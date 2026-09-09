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

/// Minor of the recipe's default class, and of its leaf qdisc's major.
///
/// **Deliberately not derived from the rule count.** It used to be
/// `n + 2`, one past the last rule's class, which meant editing the
/// rule list moved the default class — and the HTB `default` naming it
/// had to move with it. `htb` has no `.change` operation at all:
///
/// ```text
/// # tc qdisc change dev d0 root handle 1: htb default 3
/// Error: Change operation not supported by specified qdisc.
/// ```
///
/// so `reconcile()` could not follow. Adding or removing a rule made it
/// fail outright with `EINVAL`, which is the one thing reconcile exists
/// to handle. Pinning the default out of the rules' range means the
/// `defcls` written at creation stays correct for the tree's whole life
/// (#269, #291).
///
/// Rule classes occupy `1:2 ..= 1:n+1`, so `0xFFFF` cannot collide
/// unless someone configures 65533 rules.
pub(crate) const DEFAULT_CLASS_MINOR: u16 = 0xFFFF;

/// Major of the default class's leaf qdisc, on the same principle.
pub(crate) const DEFAULT_LEAF_MAJOR: u16 = 0xFFFF;

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

    /// The root qdisc, if one was *configured* rather than implied.
    ///
    /// Every interface always has a root qdisc: the kernel installs
    /// `noqueue`, `pfifo_fast`, `net.core.default_qdisc` or `mq`
    /// implicitly. Those carry **handle 0** — `qdisc_create` only calls
    /// `qdisc_alloc_handle()` for a qdisc someone asked for. Reading
    /// `root_qdisc` directly made the recipes' "nothing installed yet"
    /// arm unreachable, so `reconcile()` could never bootstrap and
    /// always demanded `with_fallback_to_apply(true)` (#287).
    pub(crate) fn configured_root_qdisc(&self) -> Option<&TcMessage> {
        self.root_qdisc.as_ref().filter(|q| q.handle_raw() != 0)
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
        // Recipe set a target: compare in the kernel's own units.
        Some(want) => codel_round_trip_us(want) == opts.target_us,
    }
}

/// Microseconds as they come back out of a `codel` time field.
///
/// The wire format is microseconds, but codel stores time in units of
/// 2^-10 seconds:
///
/// ```c
/// #define CODEL_SHIFT 10
/// static inline codel_time_t us_to_codel_time(u64 us)
/// { return (codel_time_t)((us * NSEC_PER_USEC) >> CODEL_SHIFT); }
/// static inline u32 codel_time_to_us(codel_time_t val)
/// { u64 valns = ((u64)val << CODEL_SHIFT); do_div(valns, NSEC_PER_USEC); return valns; }
/// ```
///
/// Both conversions truncate, so most values do not survive the round
/// trip: a 20 ms target is echoed back as 19999 µs. Comparing the
/// requested value against the echo therefore always disagreed, and
/// `reconcile()` rewrote every fq_codel leaf on every pass — an
/// idempotence break of the same shape as the psched-tick one
/// (#191-#194), and for the same reason: comparing a request against a
/// kernel-quantised readback.
pub(crate) fn codel_round_trip_us(us: u32) -> u32 {
    const CODEL_SHIFT: u32 = 10;
    const NSEC_PER_USEC: u64 = 1_000;
    let ticks = (us as u64 * NSEC_PER_USEC) >> CODEL_SHIFT;
    ((ticks << CODEL_SHIFT) / NSEC_PER_USEC) as u32
}

/// Split a netlink attribute blob into `(type, payload)` pairs.
///
/// Shares the walk guards of the crate's other chain walkers: an entry
/// shorter than its header, or one that would run past the end, stops
/// the walk instead of panicking.
fn split_attrs(mut input: &[u8]) -> BTreeMap<u16, &[u8]> {
    let mut out = BTreeMap::new();
    while input.len() >= 4 {
        let Ok(len_bytes) = input[..2].try_into() else {
            break;
        };
        let Ok(type_bytes) = input[2..4].try_into() else {
            break;
        };
        let len = u16::from_ne_bytes(len_bytes) as usize;
        let attr_type = u16::from_ne_bytes(type_bytes) & 0x3FFF;
        if len < 4 || input.len() < len {
            break;
        }
        out.insert(attr_type, &input[4..len]);
        let aligned = (len + 3) & !3;
        if input.len() <= aligned {
            break;
        }
        input = &input[aligned..];
    }
    out
}

/// The flower match *values* the recipe helpers can select on.
///
/// Used to decide whether a live filter matches on something the
/// desired one does not — i.e. whether a rule was *narrowed*.
///
/// Two deliberate exclusions. It is not "all `TCA_FLOWER_KEY_*`",
/// because the kernel echoes attributes nobody wrote
/// (`TCA_FLOWER_KEY_ETH_TYPE` derived from the filter's protocol,
/// `TCA_FLOWER_FLAGS`, `TCA_FLOWER_IN_HW_COUNT`) and treating those as
/// a mismatch would rewrite the filter on every reconcile pass. And it
/// carries no `_MASK` ids: `fl_set_key_val` fills an absent mask with
/// all-ones and dumps it back, so a port rule — where nlink sends the
/// value and no mask — would otherwise always look narrowed. A mask
/// never appears without its value here, so checking the values is
/// enough.
const RECIPE_FLOWER_VALUE_KEYS: &[u16] = {
    use super::types::tc::filter::flower::*;
    &[
        TCA_FLOWER_KEY_IP_PROTO,
        TCA_FLOWER_KEY_IPV4_SRC,
        TCA_FLOWER_KEY_IPV4_DST,
        TCA_FLOWER_KEY_IPV6_SRC,
        TCA_FLOWER_KEY_IPV6_DST,
        TCA_FLOWER_KEY_TCP_SRC,
        TCA_FLOWER_KEY_TCP_DST,
        TCA_FLOWER_KEY_UDP_SRC,
        TCA_FLOWER_KEY_UDP_DST,
    ]
};

/// Compare a desired flower filter against a live one, **match keys
/// included**.
///
/// The recipes previously accepted any live filter at the right
/// priority whose kind was `flower` and whose `TCA_FLOWER_CLASSID`
/// pointed at the right class. Since both the priority and the classid
/// are derived from the rule's *index*, editing a rule in place — a
/// different address, a different port, v4 to v6 — changed neither.
/// `reconcile()` reported "no changes" and left the old filter
/// classifying traffic by the old criteria, forever.
///
/// Returns `true` only when
///
/// * the live filter is a flower filter,
/// * its ethertype (`tcm_info`'s protocol) is the desired one,
/// * every attribute the desired filter emits — `TCA_FLOWER_CLASSID`
///   included — is present with a byte-identical payload, and
/// * the live filter selects on no *extra* recipe-vocabulary value.
pub(crate) fn flower_matches(
    desired: &super::filter::FlowerFilter,
    desired_protocol: u16,
    live: &TcMessage,
) -> bool {
    use super::filter::FilterConfig;

    if live.kind() != Some("flower") {
        return false;
    }
    if live.protocol() != desired_protocol {
        return false;
    }

    let Some(live_raw) = live.raw_options() else {
        return false;
    };
    let live_attrs = split_attrs(live_raw);

    // Serialize the desired filter through the same writer that would
    // install it, so this comparison cannot drift from what we send.
    let mut builder = crate::netlink::builder::MessageBuilder::new(0, 0);
    let start = builder.len();
    if desired.write_options(&mut builder).is_err() {
        return false;
    }
    let end = builder.len();
    let desired_blob = builder.as_bytes()[start..end].to_vec();
    let desired_attrs = split_attrs(&desired_blob);

    // Every attribute we would write must be there, byte for byte.
    for (id, want) in &desired_attrs {
        match live_attrs.get(id) {
            Some(have) if have == want => {}
            _ => return false,
        }
    }
    // …and the live filter must not match on anything more than we
    // asked for.
    for id in RECIPE_FLOWER_VALUE_KEYS {
        if live_attrs.contains_key(id) && !desired_attrs.contains_key(id) {
            return false;
        }
    }

    true
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
    fn codel_round_trip_matches_the_kernels_truncation() {
        // us_to_codel_time(20000) = (20000 * 1000) >> 10 = 19531,
        // codel_time_to_us(19531) = (19531 << 10) / 1000 = 19999.
        assert_eq!(codel_round_trip_us(20000), 19999);
        assert_eq!(codel_round_trip_us(0), 0);
        // Both conversions truncate, so the echo is never larger than
        // what was asked for — and, because it is not idempotent, this
        // must be applied to the *desired* value exactly once, never to
        // the value already read back.
        for us in [1u32, 999, 5_000, 20_000, 100_000, 1_000_000] {
            assert!(codel_round_trip_us(us) <= us, "round trip grew {us}");
        }
        assert_eq!(codel_round_trip_us(1_048_576), 1_048_576);
    }

    #[test]
    fn fq_codel_target_matches_accepts_the_kernels_echo() {
        // The leaf `reconcile()` reads back after asking for 20 ms.
        let live = TcMessage {
            kind: Some("fq_codel".to_string()),
            options: Some(fq_codel_options(19999)),
            ..TcMessage::default()
        };
        assert!(fq_codel_target_matches(Some(20_000), &live));
        // A genuinely different target still registers as drift.
        assert!(!fq_codel_target_matches(Some(50_000), &live));
        // No target asked for: anything goes.
        assert!(fq_codel_target_matches(None, &live));
    }

    /// A `TCA_FQ_CODEL_TARGET`-only options blob.
    fn fq_codel_options(target_us: u32) -> Vec<u8> {
        const TCA_FQ_CODEL_TARGET: u16 = 1;
        let mut out = Vec::new();
        out.extend_from_slice(&8u16.to_ne_bytes());
        out.extend_from_slice(&TCA_FQ_CODEL_TARGET.to_ne_bytes());
        out.extend_from_slice(&target_us.to_ne_bytes());
        out
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

// ========================================================================
// #270 — flower match-key comparison
// ========================================================================

/// Render a `FlowerFilter` the way the kernel would echo it back on a
/// dump: kind `"flower"`, the writer's own option blob, and `tcm_info`
/// carrying the ethertype in network order.
fn live_flower(filter: &crate::netlink::filter::FlowerFilter, protocol: u16) -> TcMessage {
    use crate::netlink::filter::FilterConfig;

    let mut builder = crate::netlink::builder::MessageBuilder::new(0, 0);
    let start = builder.len();
    filter.write_options(&mut builder).expect("write options");
    let end = builder.len();
    let blob = builder.as_bytes()[start..end].to_vec();

    let mut msg = TcMessage {
        kind: Some("flower".to_string()),
        options: Some(blob),
        ..TcMessage::default()
    };
    msg.header.tcm_info = protocol.to_be() as u32;
    msg
}

const ETH_P_IP: u16 = 0x0800;
const ETH_P_IPV6: u16 = 0x86DD;

fn dst_v4(addr: &str, prefix: u8, classid: TcHandle) -> crate::netlink::filter::FlowerFilter {
    crate::netlink::filter::FlowerFilter::new()
        .classid(classid)
        .priority(1)
        .dst_ipv4(addr.parse().unwrap(), prefix)
        .build()
}

#[test]
fn flower_matches_accepts_an_identical_filter() {
    let cid = TcHandle::new(1, 2);
    let f = dst_v4("10.0.0.1", 32, cid);
    assert!(flower_matches(&f, ETH_P_IP, &live_flower(&f, ETH_P_IP)));
}

#[test]
fn flower_matches_rejects_a_different_address() {
    // The bug: same rule index -> same priority and same classid, so
    // the old kind+classid check called this "unchanged".
    let cid = TcHandle::new(1, 2);
    let live = live_flower(&dst_v4("10.0.0.1", 32, cid), ETH_P_IP);
    assert!(!flower_matches(&dst_v4("10.0.0.2", 32, cid), ETH_P_IP, &live));
}

#[test]
fn flower_matches_rejects_a_different_prefix() {
    let cid = TcHandle::new(1, 2);
    let live = live_flower(&dst_v4("10.0.0.0", 24, cid), ETH_P_IP);
    assert!(!flower_matches(&dst_v4("10.0.0.0", 16, cid), ETH_P_IP, &live));
}

#[test]
fn flower_matches_rejects_src_where_dst_was_asked_for() {
    let cid = TcHandle::new(1, 2);
    let live = live_flower(
        &crate::netlink::filter::FlowerFilter::new()
            .classid(cid)
            .priority(1)
            .src_ipv4("10.0.0.1".parse().unwrap(), 32)
            .build(),
        ETH_P_IP,
    );
    assert!(!flower_matches(&dst_v4("10.0.0.1", 32, cid), ETH_P_IP, &live));
}

#[test]
fn flower_matches_rejects_a_v4_rule_turned_v6() {
    let cid = TcHandle::new(1, 2);
    let live = live_flower(&dst_v4("10.0.0.1", 32, cid), ETH_P_IP);
    let want = crate::netlink::filter::FlowerFilter::new()
        .classid(cid)
        .priority(1)
        .dst_ipv6("fd00::1".parse().unwrap(), 128)
        .build();
    assert!(!flower_matches(&want, ETH_P_IPV6, &live));
}

#[test]
fn flower_matches_rejects_a_different_classid() {
    let live = live_flower(&dst_v4("10.0.0.1", 32, TcHandle::new(1, 2)), ETH_P_IP);
    let want = dst_v4("10.0.0.1", 32, TcHandle::new(1, 3));
    assert!(!flower_matches(&want, ETH_P_IP, &live));
}

#[test]
fn flower_matches_rejects_a_live_filter_that_matches_on_more() {
    // Narrowing: the rule used to be "dst 10.0.0.1 tcp/443", it is now
    // just "dst 10.0.0.1". Every attribute the desired filter emits is
    // still present in the live one, so a desired-subset-of-live test
    // alone would wrongly pass.
    let cid = TcHandle::new(1, 2);
    let live = live_flower(
        &crate::netlink::filter::FlowerFilter::new()
            .classid(cid)
            .priority(1)
            .dst_ipv4("10.0.0.1".parse().unwrap(), 32)
            .ipv4()
            .ip_proto_tcp()
            .dst_port(443)
            .build(),
        ETH_P_IP,
    );
    assert!(!flower_matches(&dst_v4("10.0.0.1", 32, cid), ETH_P_IP, &live));
}

#[test]
fn flower_matches_rejects_a_different_port() {
    let cid = TcHandle::new(1, 2);
    let mk = |port: u16| {
        crate::netlink::filter::FlowerFilter::new()
            .classid(cid)
            .priority(1)
            .ipv4()
            .ip_proto_tcp()
            .dst_port(port)
            .build()
    };
    let live = live_flower(&mk(443), ETH_P_IP);
    assert!(flower_matches(&mk(443), ETH_P_IP, &live));
    assert!(!flower_matches(&mk(8443), ETH_P_IP, &live));
}

#[test]
fn flower_matches_rejects_tcp_where_udp_was_asked_for() {
    let cid = TcHandle::new(1, 2);
    let tcp = crate::netlink::filter::FlowerFilter::new()
        .classid(cid)
        .priority(1)
        .ipv4()
        .ip_proto_tcp()
        .dst_port(53)
        .build();
    let udp = crate::netlink::filter::FlowerFilter::new()
        .classid(cid)
        .priority(1)
        .ipv4()
        .ip_proto_udp()
        .dst_port(53)
        .build();
    assert!(!flower_matches(&udp, ETH_P_IP, &live_flower(&tcp, ETH_P_IP)));
}

#[test]
fn flower_matches_rejects_a_non_flower_filter() {
    let cid = TcHandle::new(1, 2);
    let mut live = live_flower(&dst_v4("10.0.0.1", 32, cid), ETH_P_IP);
    live.kind = Some("u32".to_string());
    assert!(!flower_matches(&dst_v4("10.0.0.1", 32, cid), ETH_P_IP, &live));
}

#[test]
fn split_attrs_stops_on_a_pathological_length() {
    // Rule 2 of the parser-robustness policy: a zero or sub-header
    // length must end the walk, not spin or index out of bounds.
    assert!(split_attrs(&[0, 0, 0, 0]).is_empty());
    assert!(split_attrs(&[2, 0, 1, 0]).is_empty());
    // A length past the end of the buffer is not readable.
    assert!(split_attrs(&[0xFF, 0xFF, 1, 0, 9, 9]).is_empty());
}
}
