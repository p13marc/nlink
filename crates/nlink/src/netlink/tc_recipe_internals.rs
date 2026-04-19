//! Internal scaffolding for TC-recipe `reconcile()` flows.
//!
//! Both [`PerPeerImpairer`] and [`PerHostLimiter`] build trees of the
//! shape:
//!
//! ```text
//! root HTB qdisc (1:)
//!   └── parent class 1:1
//!         ├── per-rule class 1:N → leaf qdisc (kind varies) [+ flower filter]
//!         └── default class      → leaf qdisc
//! ```
//!
//! [`LiveTree`] is the reconciliation-time snapshot of that shape, built
//! from three RTNETLINK dumps: qdiscs, classes, and filters at the root
//! parent. The diff logic itself lives in each helper (the recipes
//! disagree on rule shape and leaf kind), but the dump and the equality
//! primitives are shared here.
//!
//! [`PerPeerImpairer`]: super::impair::PerPeerImpairer
//! [`PerHostLimiter`]: super::ratelimit::PerHostLimiter

use std::collections::BTreeMap;

use super::{
    Connection,
    error::Result,
    messages::TcMessage,
    protocol::Route,
    tc::NetemConfig,
    tc_handle::TcHandle,
    tc_options::{HtbClassOptions, HtbOptions, QdiscOptions, parse_htb_class_options},
};

/// Snapshot of one device's TC tree at the moment `reconcile()` ran.
///
/// Populated via [`dump_live_tree()`].
#[derive(Debug, Default)]
pub(crate) struct LiveTree {
    /// The qdisc whose parent is `TcHandle::ROOT` (if any).
    pub(crate) root_qdisc: Option<TcMessage>,
    /// Every class on the device, keyed by its handle.
    pub(crate) classes: BTreeMap<TcHandle, TcMessage>,
    /// Every non-root qdisc on the device, keyed by its parent (the
    /// class that owns it). Each rule's leaf qdisc lives here.
    pub(crate) leaf_qdiscs: BTreeMap<TcHandle, TcMessage>,
    /// Filters whose parent is the root qdisc handle (`1:`), keyed by
    /// `(priority, classid)`. Recipe filters land here.
    pub(crate) root_filters: Vec<TcMessage>,
}

impl LiveTree {
    /// Look up a class by its handle.
    pub(crate) fn class(&self, handle: TcHandle) -> Option<&TcMessage> {
        self.classes.get(&handle)
    }

    /// Look up the leaf qdisc whose parent is `class_handle`.
    pub(crate) fn leaf_for(&self, class_handle: TcHandle) -> Option<&TcMessage> {
        self.leaf_qdiscs.get(&class_handle)
    }

    /// Look up a filter at the root parent by priority.
    pub(crate) fn filter_at_priority(&self, priority: u16) -> Option<&TcMessage> {
        self.root_filters.iter().find(|f| f.priority() == priority)
    }
}

/// Dump the qdiscs, classes, and root-parent filters for `ifindex`.
///
/// The resulting tree is the input to each recipe's diff function. We
/// do not dump filters at every parent — recipe helpers only ever
/// install filters at the root HTB qdisc parent (`1:`).
pub(crate) async fn dump_live_tree(conn: &Connection<Route>, ifindex: u32) -> Result<LiveTree> {
    let mut tree = LiveTree::default();

    // Qdiscs: split into root + leaves keyed by parent.
    let qdiscs = conn.get_qdiscs_by_index(ifindex).await?;
    for q in qdiscs {
        if q.parent().is_root() {
            tree.root_qdisc = Some(q);
        } else {
            tree.leaf_qdiscs.insert(q.parent(), q);
        }
    }

    // Classes keyed by handle.
    let classes = conn.get_classes_by_index(ifindex).await?;
    for c in classes {
        tree.classes.insert(c.handle(), c);
    }

    // Filters at the root HTB parent (`1:`). Both helpers install at
    // this parent; if no root HTB exists this returns an empty list.
    let root_parent = TcHandle::major_only(1);
    tree.root_filters = conn
        .get_filters_by_parent_index(ifindex, root_parent)
        .await?;

    Ok(tree)
}

/// Get the parsed HTB qdisc options from a live root qdisc, if present.
pub(crate) fn root_htb_options(tree: &LiveTree) -> Option<HtbOptions> {
    let root = tree.root_qdisc.as_ref()?;
    if root.kind()? != "htb" {
        return None;
    }
    match root.options()? {
        QdiscOptions::Htb(opts) => Some(opts),
        _ => None,
    }
}

/// Get parsed HTB class options for a live class message.
pub(crate) fn htb_class_options(class: &TcMessage) -> Option<HtbClassOptions> {
    if class.kind()? != "htb" {
        return None;
    }
    let raw = class.raw_options()?;
    parse_htb_class_options(raw)
}

/// Compare a desired [`NetemConfig`] against a live netem leaf qdisc.
///
/// Returns `true` when every field that `NetemConfig::write_options`
/// would emit matches the kernel's parsed view of the live qdisc. This
/// is the gate that decides "leave this leaf alone" vs "rewrite it".
pub(crate) fn netem_matches(desired: &NetemConfig, live: &TcMessage) -> bool {
    if live.kind() != Some("netem") {
        return false;
    }
    let Some(QdiscOptions::Netem(live_opts)) = live.options() else {
        return false;
    };

    // Delay / jitter — `delay()` returns Some only when ns > 0.
    if desired.delay != live_opts.delay() {
        return false;
    }
    if desired.jitter != live_opts.jitter() {
        return false;
    }

    // Percentages — desired stores Percent (always present, ZERO meaning
    // "off"); live exposes Option<f64>. Compare via the kernel-side
    // probability so we ignore floating-point representation drift.
    let percent_matches = |desired: crate::util::Percent, live: Option<f64>| -> bool {
        let live_value = live.unwrap_or(0.0);
        let live_kernel = crate::util::Percent::new(live_value).as_kernel_probability();
        desired.as_kernel_probability() == live_kernel
    };

    if !percent_matches(desired.loss, live_opts.loss()) {
        return false;
    }
    if !percent_matches(desired.duplicate, live_opts.duplicate()) {
        return false;
    }
    if !percent_matches(desired.corrupt, live_opts.corrupt()) {
        return false;
    }
    if !percent_matches(desired.reorder, live_opts.reorder()) {
        return false;
    }

    // Reorder gap. NetemConfig::write_options forces gap=1 when
    // reorder is set with no explicit gap — match that quirk.
    let effective_gap = if !desired.reorder.is_zero() && desired.gap == 0 {
        1
    } else {
        desired.gap
    };
    if effective_gap != live_opts.gap {
        return false;
    }

    // Rate (bytes/sec). Desired's `rate` is Option<Rate>; live's is u64
    // (0 == unset).
    let desired_rate = desired.rate.map(|r| r.as_bytes_per_sec()).unwrap_or(0);
    if desired_rate != live_opts.rate {
        return false;
    }

    // Queue limit. NetemConfig::new() defaults to 1000; live qopt.limit
    // is the same field and is always echoed.
    if desired.limit != live_opts.limit {
        return false;
    }

    true
}

/// Compare a desired target latency (used by `PerHostLimiter`'s
/// fq_codel leaves) against a live fq_codel qdisc.
///
/// `PerHostLimiter` only ever sets `target`; the rest of the
/// `FqCodelConfig` is left at the kernel default. We therefore accept
/// any kernel-chosen value for the unset fields and only enforce the
/// `target` field when the recipe sets one.
pub(crate) fn fq_codel_target_matches(desired_target_us: Option<u32>, live: &TcMessage) -> bool {
    if live.kind() != Some("fq_codel") {
        return false;
    }
    let Some(QdiscOptions::FqCodel(opts)) = live.options() else {
        return false;
    };
    match desired_target_us {
        // Recipe didn't set a target: any live value is acceptable.
        None => true,
        // Recipe set a target: live target_us must match (rounded —
        // the wire format is microseconds, no precision loss).
        Some(want) => opts.target_us == want,
    }
}

/// Extract the classid attribute (`TCA_FLOWER_CLASSID`) from a parsed
/// flower filter, if present. Returns the typed [`TcHandle`].
pub(crate) fn flower_classid(filter: &TcMessage) -> Option<TcHandle> {
    use super::types::tc::filter::flower::TCA_FLOWER_CLASSID;

    if filter.kind() != Some("flower") {
        return None;
    }
    let mut input = filter.raw_options()?;

    while input.len() >= 4 {
        let len = u16::from_ne_bytes(input[..2].try_into().ok()?) as usize;
        let attr_type = u16::from_ne_bytes(input[2..4].try_into().ok()?);

        if len < 4 || input.len() < len {
            break;
        }
        let payload = &input[4..len];

        if (attr_type & 0x3FFF) == TCA_FLOWER_CLASSID && payload.len() >= 4 {
            let raw = u32::from_ne_bytes(payload[..4].try_into().ok()?);
            return Some(TcHandle::from_raw(raw));
        }

        let aligned = (len + 3) & !3;
        if input.len() <= aligned {
            break;
        }
        input = &input[aligned..];
    }
    None
}

/// Compare desired (rate, ceil) against a live HTB class.
///
/// Compares only the fields the recipes set today; deeper attributes
/// (burst, prio, quantum) are tracked by the kernel but are derived
/// inside [`HtbClassConfig::write_options`] from rate and the default
/// MTU when not explicitly set. Two classes that round-trip through
/// the recipe's defaults will match here even when the kernel has
/// filled in derived burst/cburst values.
pub(crate) fn htb_class_rates_match(
    class: &TcMessage,
    desired_rate_bps: u64,
    desired_ceil_bps: u64,
) -> bool {
    let Some(opts) = htb_class_options(class) else {
        return false;
    };
    opts.rate == desired_rate_bps && opts.ceil == desired_ceil_bps
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::netlink::tc::QdiscConfig;
    use crate::util::{Percent, Rate};

    /// Build a `TcMessage` with `kind = "netem"` and an `options` blob
    /// produced by [`NetemConfig::write_options`]. This mirrors what
    /// the kernel echoes back on a qdisc dump.
    fn make_netem_msg(cfg: NetemConfig) -> TcMessage {
        let mut builder = crate::netlink::builder::MessageBuilder::new(0, 0);
        let start = builder.len();
        cfg.write_options(&mut builder).expect("write options");
        let end = builder.len();
        let blob = builder.as_bytes()[start..end].to_vec();

        TcMessage {
            kind: Some("netem".to_string()),
            options: Some(blob),
            ..TcMessage::default()
        }
    }

    #[test]
    fn netem_matches_round_trips_delay_only() {
        let desired = NetemConfig::new().delay(Duration::from_millis(50)).build();
        let live = make_netem_msg(desired.clone());
        assert!(netem_matches(&desired, &live));
    }

    #[test]
    fn netem_matches_rejects_different_delay() {
        let desired = NetemConfig::new().delay(Duration::from_millis(50)).build();
        let other = NetemConfig::new().delay(Duration::from_millis(60)).build();
        let live = make_netem_msg(other);
        assert!(!netem_matches(&desired, &live));
    }

    #[test]
    fn netem_matches_rejects_different_loss() {
        let desired = NetemConfig::new()
            .delay(Duration::from_millis(50))
            .loss(Percent::new(1.0))
            .build();
        let other = NetemConfig::new()
            .delay(Duration::from_millis(50))
            .loss(Percent::new(2.0))
            .build();
        let live = make_netem_msg(other);
        assert!(!netem_matches(&desired, &live));
    }

    #[test]
    fn netem_matches_round_trips_complex_config() {
        let cfg = NetemConfig::new()
            .delay(Duration::from_millis(40))
            .jitter(Duration::from_millis(5))
            .loss(Percent::new(0.5))
            .duplicate(Percent::new(0.1))
            .rate(Rate::mbit(100))
            .build();
        let live = make_netem_msg(cfg.clone());
        assert!(netem_matches(&cfg, &live));
    }

    #[test]
    fn netem_matches_handles_reorder_gap_default() {
        // When reorder is set without an explicit gap, the writer emits
        // gap=1; the comparison must use the same effective value.
        let cfg = NetemConfig::new()
            .delay(Duration::from_millis(20))
            .reorder(Percent::new(2.0))
            .build();
        let live = make_netem_msg(cfg.clone());
        assert!(netem_matches(&cfg, &live));
    }

    #[test]
    fn netem_matches_rejects_non_netem_kind() {
        let desired = NetemConfig::new().delay(Duration::from_millis(50)).build();
        let live = TcMessage::default();
        assert!(!netem_matches(&desired, &live));
    }
}
