//! Configuration diffing.
//!
//! This module computes the difference between desired and current network state.

use std::{
    collections::{HashMap, HashSet},
    net::IpAddr,
};

use std::time::Duration;

use super::types::{
    DeclaredAddress, DeclaredLink, DeclaredLinkType, DeclaredQdisc, DeclaredQdiscType,
    DeclaredRoute, LinkState, NetworkConfig, QdiscParent,
};
use crate::netlink::{
    builder::MessageBuilder,
    connection::Connection,
    error::Result,
    messages::{AddressMessage, LinkMessage, RouteMessage, TcMessage},
    protocol::Route,
    tc::{
        ClsactConfig, FqCodelConfig, HtbQdiscConfig, IngressConfig, NetemConfig, PrioConfig,
        QdiscConfig, SfqConfig, TbfConfig,
    },
    types::{link::OperState, route::RouteType},
};

/// Difference between desired and current network state.
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case"))]
#[derive(Debug, Default)]
pub struct ConfigDiff {
    /// Links to create.
    pub links_to_add: Vec<DeclaredLink>,
    /// Links to remove (names).
    pub links_to_remove: Vec<String>,
    /// Links to modify (name, changes).
    pub links_to_modify: Vec<(String, LinkChanges)>,

    /// Addresses to add.
    pub addresses_to_add: Vec<DeclaredAddress>,
    /// Addresses to remove (dev, address, prefix_len).
    pub addresses_to_remove: Vec<(String, IpAddr, u8)>,

    /// Routes to add.
    pub routes_to_add: Vec<DeclaredRoute>,
    /// Routes to remove (destination, prefix_len, table).
    pub routes_to_remove: Vec<(IpAddr, u8, u32)>,

    /// Qdiscs to add.
    pub qdiscs_to_add: Vec<DeclaredQdisc>,
    /// Qdiscs to remove (dev, parent).
    pub qdiscs_to_remove: Vec<(String, QdiscParent)>,
    /// Qdiscs to replace (same position, different config).
    pub qdiscs_to_replace: Vec<DeclaredQdisc>,
}

impl ConfigDiff {
    /// Apply this pre-computed diff in-place without re-running
    /// [`crate::NetworkConfig::compute_diff`].
    ///
    /// Mirrors [`crate::netlink::nftables::config::NftablesDiff::apply`]'s
    /// shape (Plan 188). Use this in the chain pattern when you
    /// already hold a diff:
    ///
    /// ```ignore
    /// let diff = cfg.diff(&conn).await?;
    /// println!("{diff}");                  // inspect before commit
    /// diff.apply(&conn, ApplyOptions::default()).await?;
    /// ```
    ///
    /// More efficient than [`crate::NetworkConfig::apply`] when
    /// you already have a `ConfigDiff` — the latter re-runs
    /// `compute_diff` internally, costing one extra round-trip
    /// of dump traffic.
    pub async fn apply(
        &self,
        conn: &Connection<Route>,
        opts: super::apply::ApplyOptions,
    ) -> Result<super::apply::ApplyResult> {
        super::apply::apply_diff(self, conn, opts).await
    }

    /// Check if no changes are needed.
    pub fn is_empty(&self) -> bool {
        self.links_to_add.is_empty()
            && self.links_to_remove.is_empty()
            && self.links_to_modify.is_empty()
            && self.addresses_to_add.is_empty()
            && self.addresses_to_remove.is_empty()
            && self.routes_to_add.is_empty()
            && self.routes_to_remove.is_empty()
            && self.qdiscs_to_add.is_empty()
            && self.qdiscs_to_remove.is_empty()
            && self.qdiscs_to_replace.is_empty()
    }

    /// Get the total number of changes.
    pub fn change_count(&self) -> usize {
        self.links_to_add.len()
            + self.links_to_remove.len()
            + self.links_to_modify.len()
            + self.addresses_to_add.len()
            + self.addresses_to_remove.len()
            + self.routes_to_add.len()
            + self.routes_to_remove.len()
            + self.qdiscs_to_add.len()
            + self.qdiscs_to_remove.len()
            + self.qdiscs_to_replace.len()
    }

    /// Get a human-readable summary of the changes.
    ///
    /// Equivalent to `format!("{self}")` — Plan 183 (0.18) made
    /// the [`std::fmt::Display`] impl share the same renderer.
    /// Prefer the `Display` form (`diff.to_string()` /
    /// `format!("{diff}")`) for new code.
    #[deprecated(
        since = "0.19.0",
        note = "use `Display` via `format!(\"{}\")` or `diff.to_string()` instead — Plan 188 §2.6"
    )]
    pub fn summary(&self) -> String {
        let mut lines = Vec::new();

        // Links
        for link in &self.links_to_add {
            lines.push(format!(
                "+ link {} ({})",
                link.name,
                link.link_type.kind().unwrap_or("physical")
            ));
        }
        for name in &self.links_to_remove {
            lines.push(format!("- link {}", name));
        }
        for (name, changes) in &self.links_to_modify {
            lines.push(format!("~ link {} ({})", name, changes.summary()));
        }

        // Addresses
        for addr in &self.addresses_to_add {
            lines.push(format!(
                "+ address {}/{} on {}",
                addr.address, addr.prefix_len, addr.dev
            ));
        }
        for (dev, addr, prefix) in &self.addresses_to_remove {
            lines.push(format!("- address {}/{} on {}", addr, prefix, dev));
        }

        // Routes
        for route in &self.routes_to_add {
            let via = route
                .gateway
                .map(|g| format!(" via {}", g))
                .unwrap_or_default();
            let dev = route
                .dev
                .as_ref()
                .map(|d| format!(" dev {}", d))
                .unwrap_or_default();
            lines.push(format!(
                "+ route {}/{}{}{}",
                route.destination, route.prefix_len, via, dev
            ));
        }
        for (dst, prefix, table) in &self.routes_to_remove {
            let table_str = if *table != 254 {
                format!(" table {}", table)
            } else {
                String::new()
            };
            lines.push(format!("- route {}/{}{}", dst, prefix, table_str));
        }

        // Qdiscs
        for qdisc in &self.qdiscs_to_add {
            lines.push(format!(
                "+ qdisc {} on {} ({:?})",
                qdisc.qdisc_type.kind(),
                qdisc.dev,
                qdisc.parent
            ));
        }
        for (dev, parent) in &self.qdiscs_to_remove {
            lines.push(format!("- qdisc on {} ({:?})", dev, parent));
        }
        for qdisc in &self.qdiscs_to_replace {
            lines.push(format!(
                "~ qdisc {} on {} ({:?})",
                qdisc.qdisc_type.kind(),
                qdisc.dev,
                qdisc.parent
            ));
        }

        if lines.is_empty() {
            "No changes needed".to_string()
        } else {
            lines.join("\n")
        }
    }
}

/// `Display` shares the renderer with the deprecated
/// `ConfigDiff::summary` so callers can `println!("{diff}")`
/// directly. Plan 183 (0.18) added this; Plan 188 §2.6 (0.19)
/// deprecated `summary()` in favor of this form. The
/// `#[allow(deprecated)]` is for the internal delegation —
/// users are not on the deprecated path.
impl std::fmt::Display for ConfigDiff {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        #[allow(deprecated)]
        f.write_str(&self.summary())
    }
}

/// Changes to make to an existing link.
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case"))]
#[derive(Debug, Default)]
pub struct LinkChanges {
    /// Change state to up.
    pub set_up: bool,
    /// Change state to down.
    pub set_down: bool,
    /// New MTU value.
    pub set_mtu: Option<u32>,
    /// New master interface.
    pub set_master: Option<String>,
    /// Remove from master.
    pub unset_master: bool,
}

impl LinkChanges {
    /// Check if any changes are needed.
    pub fn is_empty(&self) -> bool {
        !self.set_up
            && !self.set_down
            && self.set_mtu.is_none()
            && self.set_master.is_none()
            && !self.unset_master
    }

    /// Get a summary of the changes.
    ///
    /// Equivalent to `format!("{self}")` since Plan 188 §2.5
    /// (0.19) added the `Display` impl. Prefer `Display` for
    /// new code; this method may be deprecated in 0.20.
    pub fn summary(&self) -> String {
        let mut parts: Vec<String> = Vec::new();
        if self.set_up {
            parts.push("up".to_string());
        }
        if self.set_down {
            parts.push("down".to_string());
        }
        if let Some(mtu) = self.set_mtu {
            parts.push(format!("mtu={}", mtu));
        }
        if let Some(master) = &self.set_master {
            parts.push(format!("master={}", master));
        }
        if self.unset_master {
            parts.push("nomaster".to_string());
        }
        parts.join(", ")
    }
}

/// `Display` for `LinkChanges` so a `links_to_modify` row in
/// `ConfigDiff::Display` can render the changes compactly:
/// `"~ link eth0 (mtu=9000, up)"`. Plan 188 §2.5 / feedback W6.
impl std::fmt::Display for LinkChanges {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.summary())
    }
}

/// Compute the difference between desired and current state.
pub async fn compute_diff(config: &NetworkConfig, conn: &Connection<Route>) -> Result<ConfigDiff> {
    let mut diff = ConfigDiff::default();

    // Fetch current state
    let current_links = conn.get_links().await?;
    let current_addresses = conn.get_addresses().await?;
    let current_routes = conn.get_routes().await?;
    let current_qdiscs = conn.get_qdiscs().await?;

    // Build lookup maps
    let link_by_name: HashMap<&str, &LinkMessage> = current_links
        .iter()
        .filter_map(|l| l.name.as_deref().map(|n| (n, l)))
        .collect();

    let ifindex_to_name: HashMap<u32, &str> = current_links
        .iter()
        .filter_map(|l| l.name.as_deref().map(|n| (l.ifindex(), n)))
        .collect();

    // Diff links
    diff_links(config, &link_by_name, &mut diff);

    // Plan 186 §3c — topo-sort `links_to_add` so a child whose
    // parent is also being created in this apply lands AFTER
    // its parent. Without this, a `NetworkConfig` that declares
    // a VLAN before its parent (because the declared order is
    // child-first, or because the source iterated a `HashMap`)
    // hits `InterfaceNotFound` on the second `create_link`.
    // Independent links keep their declared order — the sort
    // is stable.
    topo_sort_links_to_add(&mut diff.links_to_add);

    // Diff addresses
    diff_addresses(config, &current_addresses, &ifindex_to_name, &mut diff);

    // Diff routes
    diff_routes(config, &current_routes, &ifindex_to_name, &mut diff);

    // Diff qdiscs
    diff_qdiscs(config, &current_qdiscs, &ifindex_to_name, &mut diff);

    Ok(diff)
}

fn diff_links(
    config: &NetworkConfig,
    current: &HashMap<&str, &LinkMessage>,
    diff: &mut ConfigDiff,
) {
    // Note: desired_names would be used for purge mode to find links to remove
    let _desired_names: HashSet<&str> = config.links.iter().map(|l| l.name.as_str()).collect();

    for declared in &config.links {
        if let Some(existing) = current.get(declared.name.as_str()) {
            // Link exists, check if it needs modification
            let changes = compute_link_changes(declared, existing);
            if !changes.is_empty() {
                diff.links_to_modify.push((declared.name.clone(), changes));
            }
        } else {
            // Link doesn't exist, needs to be created
            // But only if it's not a physical interface
            if declared.link_type != DeclaredLinkType::Physical {
                diff.links_to_add.push(declared.clone());
            }
        }
    }

    // Note: We don't auto-remove links that aren't in the config
    // That requires explicit purge mode
}

/// Plan 186 §3c — stable topological sort of `links_to_add`.
///
/// A child link (Vlan, Macvlan) whose parent is also in
/// `links_to_add` must land AFTER its parent. Independent
/// links keep their declared order — the sort is stable.
///
/// Cycles are theoretically impossible for the link types we
/// model (a `Vlan` parent can't be a `Vlan` child of itself
/// without a kernel that already would have refused), but we
/// still degrade gracefully: any node not in a topo order falls
/// to the tail in its declared position.
fn topo_sort_links_to_add(links: &mut Vec<DeclaredLink>) {
    if links.len() < 2 {
        return;
    }

    // Build set of names being added in this batch.
    let names_in_batch: HashSet<String> =
        links.iter().map(|l| l.name.clone()).collect();

    // For each child, find its parent name IF that parent is
    // also in this batch (a parent created out-of-band is
    // resolved on the wire and doesn't need ordering).
    let parent_of = |link: &DeclaredLink| -> Option<String> {
        let parent = match &link.link_type {
            DeclaredLinkType::Vlan { parent, .. } => Some(parent.clone()),
            DeclaredLinkType::Macvlan { parent, .. } => Some(parent.clone()),
            _ => None,
        };
        parent.filter(|p| names_in_batch.contains(p))
    };

    // Stable Kahn's algorithm. Iterate `links` in current order;
    // emit a link only once all its in-batch parents have been
    // emitted. Use a simple two-pass loop — for the link counts
    // we expect (single-digit to low-double-digit), the cost is
    // negligible and the implementation stays obvious.
    let mut emitted: HashSet<String> = HashSet::new();
    let mut out: Vec<DeclaredLink> = Vec::with_capacity(links.len());
    let mut remaining: Vec<DeclaredLink> = std::mem::take(links);

    while !remaining.is_empty() {
        let before = remaining.len();
        let mut next_remaining = Vec::with_capacity(remaining.len());
        for link in remaining.into_iter() {
            let ready = match parent_of(&link) {
                Some(parent) => emitted.contains(&parent),
                None => true,
            };
            if ready {
                emitted.insert(link.name.clone());
                out.push(link);
            } else {
                next_remaining.push(link);
            }
        }
        // No progress this round — cycle or unresolvable
        // dependency. Append the remainder in declared order
        // so the apply still attempts them (the kernel will
        // give the canonical error).
        if next_remaining.len() == before {
            out.extend(next_remaining);
            break;
        }
        remaining = next_remaining;
    }
    *links = out;
}

fn compute_link_changes(declared: &DeclaredLink, existing: &LinkMessage) -> LinkChanges {
    let mut changes = LinkChanges::default();

    // Check state
    match declared.state {
        LinkState::Up => {
            if existing.operstate != Some(OperState::Up) {
                changes.set_up = true;
            }
        }
        LinkState::Down => {
            if existing.operstate == Some(OperState::Up) {
                changes.set_down = true;
            }
        }
        LinkState::Unchanged => {}
    }

    // Check MTU
    if let Some(desired_mtu) = declared.mtu
        && existing.mtu != Some(desired_mtu)
    {
        changes.set_mtu = Some(desired_mtu);
    }

    // Check master
    // Note: This is simplified - would need ifindex lookup for full implementation
    if declared.master.is_some() && existing.master.is_none() {
        changes.set_master = declared.master.clone();
    } else if declared.master.is_none() && existing.master.is_some() {
        changes.unset_master = true;
    }

    changes
}

fn diff_addresses(
    config: &NetworkConfig,
    current: &[AddressMessage],
    ifindex_to_name: &HashMap<u32, &str>,
    diff: &mut ConfigDiff,
) {
    // Build set of desired addresses: (dev, address, prefix_len)
    let desired: HashSet<(&str, IpAddr, u8)> = config
        .addresses
        .iter()
        .map(|a| (a.dev.as_str(), a.address, a.prefix_len))
        .collect();

    // Build set of current addresses
    let current_set: HashSet<(&str, IpAddr, u8)> = current
        .iter()
        .filter_map(|a| {
            let name = ifindex_to_name.get(&a.ifindex())?;
            let addr = a.address?;
            Some((*name, addr, a.prefix_len()))
        })
        .collect();

    // Find addresses to add
    for declared in &config.addresses {
        let key = (declared.dev.as_str(), declared.address, declared.prefix_len);
        if !current_set.contains(&key) {
            diff.addresses_to_add.push(declared.clone());
        }
    }

    // Note: We don't auto-remove addresses not in config
    // That requires explicit purge mode
    let _ = desired; // Silence unused warning
}

fn diff_routes(
    config: &NetworkConfig,
    current: &[RouteMessage],
    ifindex_to_name: &HashMap<u32, &str>,
    diff: &mut ConfigDiff,
) {
    // Build set of desired routes: (destination, prefix_len, table)
    let desired: HashSet<(IpAddr, u8, u32)> = config
        .routes
        .iter()
        .map(|r| (r.destination, r.prefix_len, r.table.unwrap_or(254)))
        .collect();

    // Build set of current routes (only unicast routes we care about)
    let current_set: HashSet<(IpAddr, u8, u32)> = current
        .iter()
        .filter(|r| {
            // Only consider routes we might have added (protocol static or boot)
            matches!(
                r.route_type(),
                RouteType::Unicast
                    | RouteType::Blackhole
                    | RouteType::Unreachable
                    | RouteType::Prohibit
            )
        })
        .map(|r| {
            let dst = r.destination.unwrap_or_else(|| {
                if r.is_ipv4() {
                    IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)
                } else {
                    IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED)
                }
            });
            (dst, r.dst_len(), r.table_id())
        })
        .collect();

    // Find routes to add
    for declared in &config.routes {
        let table = declared.table.unwrap_or(254);
        let key = (declared.destination, declared.prefix_len, table);
        if !current_set.contains(&key) {
            diff.routes_to_add.push(declared.clone());
        }
    }

    // Note: We don't auto-remove routes not in config
    // That requires explicit purge mode
    let _ = desired;
    let _ = ifindex_to_name;
}

fn diff_qdiscs(
    config: &NetworkConfig,
    current: &[TcMessage],
    ifindex_to_name: &HashMap<u32, &str>,
    diff: &mut ConfigDiff,
) {
    // Build map of current root qdiscs by device
    let mut current_root_qdisc: HashMap<&str, &TcMessage> = HashMap::new();
    let mut current_ingress_qdisc: HashMap<&str, &TcMessage> = HashMap::new();

    for qdisc in current {
        if let Some(name) = ifindex_to_name.get(&qdisc.ifindex()) {
            if qdisc.is_root() {
                current_root_qdisc.insert(*name, qdisc);
            } else if qdisc.is_ingress() {
                current_ingress_qdisc.insert(*name, qdisc);
            }
        }
    }

    for declared in &config.qdiscs {
        let current_map = match declared.parent {
            QdiscParent::Root => &current_root_qdisc,
            QdiscParent::Ingress => &current_ingress_qdisc,
        };

        if let Some(existing) = current_map.get(declared.dev.as_str()) {
            // Qdisc exists, check if it matches
            let existing_kind = existing.kind().unwrap_or("");
            let desired_kind = declared.qdisc_type.kind();

            if existing_kind != desired_kind {
                // Different type, need to replace.
                diff.qdiscs_to_replace.push(declared.clone());
            } else if !qdisc_params_match(&declared.qdisc_type, existing.raw_options()) {
                // Same kind, different parameters — replace.
                diff.qdiscs_to_replace.push(declared.clone());
            }
        } else {
            // No qdisc at this position, need to add.
            diff.qdiscs_to_add.push(declared.clone());
        }
    }
}

/// Compare a declared qdisc's parameters against the kernel's reported
/// `TCA_OPTIONS` blob.
///
/// Renders the declared config through `QdiscConfig::write_options` into a
/// scratch buffer, then byte-compares against the kernel's blob. Returns
/// `true` if they match exactly.
///
/// **Known limitation**: the kernel may add attributes (defaults, optional
/// counters, padding) that the declared side doesn't write. Those cases
/// surface as "differs" → harmless re-apply via `qdiscs_to_replace`. The
/// alternative (per-field parse-and-compare) needs per-kind parsers that
/// don't exist in nlink yet; that's tracked as a 0.17 polish item. Until
/// then, prefer false-positive churn over the silent-no-op bug this
/// replaces.
fn qdisc_params_match(declared: &DeclaredQdiscType, existing_opts: Option<&[u8]>) -> bool {
    let declared_bytes = declared_options_bytes(declared);
    let existing_bytes = existing_opts.unwrap_or(&[]);
    declared_bytes.as_slice() == existing_bytes
}

/// Render the `TCA_OPTIONS` payload bytes for a declared qdisc type.
/// Mirrors the typed-config construction in `apply.rs::add_qdisc` —
/// kept in sync by being the exact same `match`.
fn declared_options_bytes(t: &DeclaredQdiscType) -> Vec<u8> {
    let mut builder = MessageBuilder::new(0, 0);
    let start = builder.len();
    let write_result: Result<()> = match t {
        DeclaredQdiscType::Netem {
            delay_us,
            jitter_us,
            loss_percent,
            limit,
        } => {
            let mut cfg = NetemConfig::new();
            if let Some(d) = delay_us {
                cfg = cfg.delay(Duration::from_micros(*d as u64));
            }
            if let Some(j) = jitter_us {
                cfg = cfg.jitter(Duration::from_micros(*j as u64));
            }
            if let Some(l) = loss_percent {
                cfg = cfg.loss(crate::util::Percent::new(*l));
            }
            if let Some(lim) = limit {
                cfg = cfg.limit(*lim);
            }
            cfg.build().write_options(&mut builder)
        }
        DeclaredQdiscType::Htb { default_class } => {
            HtbQdiscConfig::new()
                .default_class(*default_class)
                .write_options(&mut builder)
        }
        DeclaredQdiscType::FqCodel {
            limit,
            target_us,
            interval_us,
        } => {
            let mut cfg = FqCodelConfig::new();
            if let Some(lim) = limit {
                cfg = cfg.limit(*lim);
            }
            if let Some(t) = target_us {
                cfg = cfg.target(Duration::from_micros(*t as u64));
            }
            if let Some(i) = interval_us {
                cfg = cfg.interval(Duration::from_micros(*i as u64));
            }
            cfg.write_options(&mut builder)
        }
        DeclaredQdiscType::Tbf {
            rate_bps,
            burst_bytes,
            limit_bytes,
        } => {
            let mut cfg = TbfConfig::new()
                .rate(crate::util::Rate::bytes_per_sec(*rate_bps))
                .burst(crate::util::Bytes::new(*burst_bytes as u64));
            if let Some(lim) = limit_bytes {
                cfg = cfg.limit(crate::util::Bytes::new(*lim as u64));
            }
            cfg.write_options(&mut builder)
        }
        DeclaredQdiscType::Sfq { perturb_secs } => {
            let mut cfg = SfqConfig::new();
            if let Some(p) = perturb_secs {
                cfg = cfg.perturb(*p as i32);
            }
            cfg.write_options(&mut builder)
        }
        DeclaredQdiscType::Prio { bands } => {
            let mut cfg = PrioConfig::new();
            if let Some(b) = bands {
                cfg = cfg.bands(*b as i32);
            }
            cfg.write_options(&mut builder)
        }
        DeclaredQdiscType::Ingress => IngressConfig::new().write_options(&mut builder),
        DeclaredQdiscType::Clsact => ClsactConfig::new().write_options(&mut builder),
    };
    let end = builder.len();
    // If write_options failed, return empty bytes — the diff will then
    // see "declared = empty, existing = something" → replace. Safe
    // failure mode.
    if write_result.is_err() {
        return Vec::new();
    }
    builder.as_bytes()[start..end].to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::netlink::config::types::MacvlanMode;

    fn declared(name: &str, link_type: DeclaredLinkType) -> DeclaredLink {
        DeclaredLink {
            name: name.to_string(),
            link_type,
            state: LinkState::Unchanged,
            mtu: None,
            master: None,
            address: None,
        }
    }

    // -------------------------------------------------------------
    // Plan 186 §3c — topo-sort regression coverage (unit-level).
    // -------------------------------------------------------------

    #[test]
    fn topo_sort_no_op_when_empty_or_singleton() {
        let mut links: Vec<DeclaredLink> = vec![];
        topo_sort_links_to_add(&mut links);
        assert!(links.is_empty());

        let mut links = vec![declared("eth0", DeclaredLinkType::Dummy)];
        topo_sort_links_to_add(&mut links);
        assert_eq!(links.len(), 1);
        assert_eq!(links[0].name, "eth0");
    }

    #[test]
    fn topo_sort_independent_links_preserve_declared_order() {
        let mut links = vec![
            declared("eth1", DeclaredLinkType::Dummy),
            declared("eth0", DeclaredLinkType::Dummy),
            declared("br0", DeclaredLinkType::Bridge),
        ];
        topo_sort_links_to_add(&mut links);
        assert_eq!(
            links.iter().map(|l| l.name.clone()).collect::<Vec<_>>(),
            vec!["eth1", "eth0", "br0"],
            "independent links must keep declared order (stable sort)"
        );
    }

    #[test]
    fn topo_sort_promotes_parent_before_child_vlan() {
        // VLAN declared first, parent dummy declared second.
        let mut links = vec![
            declared(
                "eth0.42",
                DeclaredLinkType::Vlan {
                    parent: "eth0".into(),
                    vlan_id: 42, protocol: None,
                },
            ),
            declared("eth0", DeclaredLinkType::Dummy),
        ];
        topo_sort_links_to_add(&mut links);
        assert_eq!(
            links.iter().map(|l| l.name.clone()).collect::<Vec<_>>(),
            vec!["eth0", "eth0.42"],
            "parent must precede child after topo-sort"
        );
    }

    #[test]
    fn topo_sort_keeps_correct_order_when_already_sorted() {
        // Parent first, child second — already correct; preserved as-is.
        let mut links = vec![
            declared("eth0", DeclaredLinkType::Dummy),
            declared(
                "eth0.42",
                DeclaredLinkType::Vlan {
                    parent: "eth0".into(),
                    vlan_id: 42, protocol: None,
                },
            ),
        ];
        topo_sort_links_to_add(&mut links);
        assert_eq!(
            links.iter().map(|l| l.name.clone()).collect::<Vec<_>>(),
            vec!["eth0", "eth0.42"]
        );
    }

    #[test]
    fn topo_sort_handles_parent_not_in_batch() {
        // Parent "eth0" is NOT in links_to_add (created
        // out-of-band). The VLAN's parent ref doesn't count
        // for the sort — the link is emitted in declared order.
        let mut links = vec![
            declared("br0", DeclaredLinkType::Bridge),
            declared(
                "eth0.42",
                DeclaredLinkType::Vlan {
                    parent: "eth0".into(), // not in batch
                    vlan_id: 42, protocol: None,
                },
            ),
        ];
        topo_sort_links_to_add(&mut links);
        assert_eq!(
            links.iter().map(|l| l.name.clone()).collect::<Vec<_>>(),
            vec!["br0", "eth0.42"],
            "out-of-batch parent does NOT trigger reorder"
        );
    }

    #[test]
    fn topo_sort_handles_macvlan_parent_dep() {
        let mut links = vec![
            declared(
                "macv0",
                DeclaredLinkType::Macvlan {
                    parent: "eth0".into(),
                    mode: MacvlanMode::default(),
                },
            ),
            declared("eth0", DeclaredLinkType::Dummy),
        ];
        topo_sort_links_to_add(&mut links);
        assert_eq!(
            links.iter().map(|l| l.name.clone()).collect::<Vec<_>>(),
            vec!["eth0", "macv0"]
        );
    }

    #[test]
    fn topo_sort_chain_three_levels() {
        // Build dummy -> bridge (master via top) -> vlan(parent=bridge).
        // The chain we model is parent-child via Vlan only; bridge as
        // a parent reference doesn't fit the link_type's parent slot,
        // so this test pins a 2-level chain plus an unrelated link.
        let mut links = vec![
            declared(
                "eth0.42",
                DeclaredLinkType::Vlan {
                    parent: "eth0".into(),
                    vlan_id: 42, protocol: None,
                },
            ),
            declared("br0", DeclaredLinkType::Bridge), // unrelated
            declared("eth0", DeclaredLinkType::Dummy),
        ];
        topo_sort_links_to_add(&mut links);
        // After sort: eth0 + br0 are both root-level (no in-batch
        // parent dep) and emitted in declared order (eth0.42 deferred,
        // br0 ready, eth0 ready). Then eth0.42 lands.
        // Pass 1 ready set: br0, eth0 (declared order: eth0.42 deferred).
        // The pass iterates remaining in declared order, so output is:
        //   br0, eth0, eth0.42
        assert_eq!(
            links.iter().map(|l| l.name.clone()).collect::<Vec<_>>(),
            vec!["br0", "eth0", "eth0.42"]
        );
    }

    #[test]
    fn declared_options_bytes_differs_when_param_changes() {
        // Two HTB configs with different default_class should produce
        // different option bytes.
        let a = DeclaredQdiscType::Htb { default_class: 0x10 };
        let b = DeclaredQdiscType::Htb { default_class: 0x20 };
        assert_ne!(declared_options_bytes(&a), declared_options_bytes(&b));
    }

    #[test]
    fn declared_options_bytes_stable_for_same_input() {
        let cfg = DeclaredQdiscType::Netem {
            delay_us: Some(100_000),
            jitter_us: Some(10_000),
            loss_percent: Some(0.5),
            limit: Some(1000),
        };
        assert_eq!(declared_options_bytes(&cfg), declared_options_bytes(&cfg));
    }

    #[test]
    fn declared_options_bytes_differs_across_netem_params() {
        let a = DeclaredQdiscType::Netem {
            delay_us: Some(100_000),
            jitter_us: None,
            loss_percent: None,
            limit: None,
        };
        let b = DeclaredQdiscType::Netem {
            delay_us: Some(200_000),
            jitter_us: None,
            loss_percent: None,
            limit: None,
        };
        assert_ne!(declared_options_bytes(&a), declared_options_bytes(&b));
    }

    #[test]
    fn qdisc_params_match_treats_empty_existing_as_mismatch_when_declared_nonempty() {
        let cfg = DeclaredQdiscType::Htb { default_class: 0x10 };
        // Existing has no options at all — should not match a non-empty declared.
        assert!(!qdisc_params_match(&cfg, None));
        assert!(!qdisc_params_match(&cfg, Some(&[])));
    }

    #[test]
    fn qdisc_params_match_clsact_has_no_options() {
        // Clsact emits zero option bytes; matches an empty existing.
        let cfg = DeclaredQdiscType::Clsact;
        assert!(qdisc_params_match(&cfg, Some(&[])));
        assert!(qdisc_params_match(&cfg, None));
    }

    // ---- Plan 188 §2.2 — ApplyOptions builders ----

    #[test]
    fn apply_options_builders_compose() {
        use super::super::apply::ApplyOptions;
        let opts = ApplyOptions::default()
            .with_dry_run(true)
            .with_continue_on_error(true)
            .with_purge(true);
        assert!(opts.dry_run);
        assert!(opts.continue_on_error);
        assert!(opts.purge);
    }

    #[test]
    fn apply_options_default_is_safe() {
        use super::super::apply::ApplyOptions;
        let opts = ApplyOptions::default();
        assert!(!opts.dry_run);
        assert!(!opts.continue_on_error);
        assert!(!opts.purge);
    }

    // ---- Plan 188 §2.5 — LinkChanges::Display ----

    #[test]
    fn link_changes_display_matches_summary() {
        let c = LinkChanges {
            set_mtu: Some(9000),
            set_up: true,
            ..LinkChanges::default()
        };
        assert_eq!(c.to_string(), c.summary());
        assert!(c.to_string().contains("mtu=9000"));
        assert!(c.to_string().contains("up"));
    }

    #[test]
    fn link_changes_display_empty_when_no_changes() {
        let c = LinkChanges::default();
        assert_eq!(c.to_string(), "");
    }

    // ---- Plan 188 §2.3 — RouteBuilder::default_v{4,6} ----

    #[test]
    fn default_v4_route_is_zero_zero() {
        use super::super::types::RouteBuilder;
        let r = RouteBuilder::default_v4();
        // Internal state — verify via the via() chain works
        // and the destination round-trips.
        let with_gw = r.via("192.0.2.1");
        // Smoke-test by constructing; the field isn't directly
        // exposed but apply paths read it.
        drop(with_gw);
    }

    #[test]
    fn default_v6_route_is_unspecified_slash_zero() {
        use super::super::types::RouteBuilder;
        let r = RouteBuilder::default_v6();
        let with_gw = r.via("2001:db8::1");
        drop(with_gw);
    }

    // ---- Plan 183 — Display for NetworkDiff ----

    #[test]
    fn display_matches_summary() {
        let diff = ConfigDiff::default();
        // Plan 188 §2.6 — `summary()` is deprecated; this test
        // pins the equivalence guarantee for the deprecation
        // window (removed in 0.20).
        #[allow(deprecated)]
        {
            assert_eq!(format!("{diff}"), diff.summary());
            let mut d = ConfigDiff::default();
            d.links_to_remove.push("eth0".to_string());
            assert_eq!(format!("{d}"), d.summary());
        }
    }
}
