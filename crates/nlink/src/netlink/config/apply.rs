//! Configuration application logic.
//!
//! This module applies the computed diff to achieve the desired network state.

use std::{net::IpAddr, time::Duration};

use super::{
    diff::{ConfigDiff, LinkChanges, compute_diff},
    types::{
        BondMode, DeclaredAddress, DeclaredLink, DeclaredLinkType, DeclaredQdisc,
        DeclaredQdiscType, DeclaredRoute, DeclaredRouteType, MacvlanMode, NetworkConfig,
        QdiscParent,
    },
};
use crate::netlink::{
    addr::{Ipv4Address, Ipv6Address},
    connection::Connection,
    error::{Error, Result},
    link::{BondLink, BridgeLink, DummyLink, IfbLink, MacvlanLink, VethLink, VlanLink, VxlanLink},
    protocol::Route,
    route::{Ipv4Route, Ipv6Route},
    tc::{
        ClsactConfig, FqCodelConfig, HtbQdiscConfig, IngressConfig, NetemConfig, PrioConfig,
        SfqConfig, TbfConfig,
    },
};

/// Options for applying configuration.
///
/// Construct via `Default::default()` + the `with_*` builder
/// methods, NOT via struct-literal syntax:
///
/// ```ignore
/// use nlink::netlink::config::ApplyOptions;
/// let opts = ApplyOptions::default()
///     .with_dry_run(true)
///     .with_continue_on_error(false);
/// ```
///
/// # Default semantics
///
/// `ApplyOptions::default()` produces conservative defaults:
///
/// - `dry_run: false` — operations actually run against the
///   kernel.
/// - `continue_on_error: false` — the first error propagates
///   as `Err`, halting further ops. Partially-applied state
///   is left in the kernel.
///
/// This is the right default; opt in to each surface
/// individually via the builders.
///
/// Plan 188 §2.2 made this `#[non_exhaustive]` so we can grow
/// the option set in future minors without semver breakage —
/// the trade-off is that struct-literal construction is no
/// longer allowed by downstream code. Mirrors `ReconcileOptions`
/// (Plan 163).
///
/// **Plan 205 (0.19) breaking change**: the `purge` flag and
/// `with_purge(bool)` builder were removed because the feature
/// was non-functional in 0.18 (silent no-op — the `*_to_remove`
/// collections were never populated by the diff phase). Code
/// that called `.with_purge(true)` thinking removal would
/// happen needs to switch to the imperative API
/// (`Connection::del_link` / `del_address` / `del_route` /
/// `del_qdisc`) to delete kernel resources, since
/// `NetworkConfig` no longer offers a purge knob. A full
/// re-wired purge with a kernel-managed-resource exclusion
/// list (IPv6 link-local, multicast, `lo`, link-local prefix
/// routes) is queued for 0.20.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct ApplyOptions {
    /// Don't actually make changes, just compute what would be done.
    pub dry_run: bool,
    /// Continue applying changes even if some operations fail.
    pub continue_on_error: bool,
}

impl ApplyOptions {
    /// Toggle dry-run mode. With dry-run on, no kernel
    /// mutations occur — every operation just records what
    /// it WOULD do in `ApplyResult::summary`.
    pub fn with_dry_run(mut self, on: bool) -> Self {
        self.dry_run = on;
        self
    }

    /// Toggle continue-on-error. With this on, the first
    /// per-op failure records into `ApplyResult::errors`
    /// instead of halting `apply`. The remaining operations
    /// still run. Useful for "best-effort" reconciliation
    /// where partial progress is preferable to no progress.
    pub fn with_continue_on_error(mut self, on: bool) -> Self {
        self.continue_on_error = on;
        self
    }
}

/// Result of applying configuration.
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case"))]
#[derive(Debug, Default)]
#[must_use = "Inspect `.is_success()`, `.errors`, or `.summary_text()` to learn the outcome"]
pub struct ApplyResult {
    /// Number of changes made (or that would be made in dry-run mode).
    pub changes_made: usize,
    /// Errors that occurred during application (when continue_on_error is true).
    pub errors: Vec<ApplyError>,
    /// Summary of what was done.
    pub summary: Vec<String>,
}

impl ApplyResult {
    /// Check if the application was fully successful.
    pub fn is_success(&self) -> bool {
        self.errors.is_empty()
    }

    /// Get a human-readable summary.
    pub fn summary_text(&self) -> String {
        if self.summary.is_empty() {
            "No changes made".to_string()
        } else {
            self.summary.join("\n")
        }
    }
}

/// An error that occurred during configuration application.
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case"))]
#[derive(Debug)]
pub struct ApplyError {
    /// What operation was being performed.
    pub operation: String,
    /// The underlying error. Plan 189: serialized as the
    /// `Display` string rather than the structural enum
    /// (the `Error` type is internally varied and not
    /// shape-stable).
    #[cfg_attr(feature = "serde", serde(serialize_with = "serialize_error_as_display"))]
    pub error: Error,
}

#[cfg(feature = "serde")]
fn serialize_error_as_display<S>(err: &Error, ser: S) -> std::result::Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    use serde::Serialize as _;
    err.to_string().serialize(ser)
}

impl std::fmt::Display for ApplyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.operation, self.error)
    }
}

/// Apply configuration to achieve desired state.
pub async fn apply_config(
    config: &NetworkConfig,
    conn: &Connection<Route>,
    options: ApplyOptions,
) -> Result<ApplyResult> {
    let diff = compute_diff(config, conn).await?;
    apply_diff(&diff, conn, options).await
}

/// Apply a pre-computed diff.
pub async fn apply_diff(
    diff: &ConfigDiff,
    conn: &Connection<Route>,
    options: ApplyOptions,
) -> Result<ApplyResult> {
    let mut result = ApplyResult::default();

    // If no changes needed, return early
    if diff.is_empty() {
        return Ok(result);
    }

    // Apply changes in the correct order:
    // 1. Create new links (so they exist for addresses/routes)
    // 2. Modify existing links (state, MTU, master)
    // 3. Add addresses
    // 4. Add routes
    // 5. Configure qdiscs
    // 6. Remove old resources (if purge enabled)

    // 1. Create new links
    for link in &diff.links_to_add {
        let op = format!("create link {}", link.name);
        if options.dry_run {
            result.summary.push(format!("Would {}", op));
            result.changes_made += 1;
        } else {
            match create_link(conn, link).await {
                Ok(()) => {
                    result.summary.push(format!("Created link {}", link.name));
                    result.changes_made += 1;
                }
                Err(e) => {
                    if options.continue_on_error {
                        result.errors.push(ApplyError {
                            operation: op,
                            error: e,
                        });
                    } else {
                        return Err(e);
                    }
                }
            }
        }
    }

    // 2. Modify existing links
    for (name, changes) in &diff.links_to_modify {
        let op = format!("modify link {} ({})", name, changes.summary());
        if options.dry_run {
            result.summary.push(format!("Would {}", op));
            result.changes_made += 1;
        } else {
            match modify_link(conn, name, changes).await {
                Ok(()) => {
                    result
                        .summary
                        .push(format!("Modified link {} ({})", name, changes.summary()));
                    result.changes_made += 1;
                }
                Err(e) => {
                    if options.continue_on_error {
                        result.errors.push(ApplyError {
                            operation: op,
                            error: e,
                        });
                    } else {
                        return Err(e);
                    }
                }
            }
        }
    }

    // 3. Add addresses
    for addr in &diff.addresses_to_add {
        let op = format!(
            "add address {}/{} on {}",
            addr.address, addr.prefix_len, addr.dev
        );
        if options.dry_run {
            result.summary.push(format!("Would {}", op));
            result.changes_made += 1;
        } else {
            match add_address(conn, addr).await {
                Ok(()) => {
                    result.summary.push(format!(
                        "Added address {}/{} on {}",
                        addr.address, addr.prefix_len, addr.dev
                    ));
                    result.changes_made += 1;
                }
                Err(e) => {
                    if options.continue_on_error {
                        result.errors.push(ApplyError {
                            operation: op,
                            error: e,
                        });
                    } else {
                        return Err(e);
                    }
                }
            }
        }
    }

    // 4. Add routes
    for route in &diff.routes_to_add {
        let op = format!("add route {}/{}", route.destination, route.prefix_len);
        if options.dry_run {
            result.summary.push(format!("Would {}", op));
            result.changes_made += 1;
        } else {
            match add_route(conn, route).await {
                Ok(()) => {
                    result.summary.push(format!(
                        "Added route {}/{}",
                        route.destination, route.prefix_len
                    ));
                    result.changes_made += 1;
                }
                Err(e) => {
                    if options.continue_on_error {
                        result.errors.push(ApplyError {
                            operation: op,
                            error: e,
                        });
                    } else {
                        return Err(e);
                    }
                }
            }
        }
    }

    // 5a. Replace qdiscs (remove and re-add with new config)
    for qdisc in &diff.qdiscs_to_replace {
        let op = format!("replace qdisc {} on {}", qdisc.qdisc_type.kind(), qdisc.dev);
        if options.dry_run {
            result.summary.push(format!("Would {}", op));
            result.changes_made += 1;
        } else {
            match replace_qdisc(conn, qdisc).await {
                Ok(()) => {
                    result.summary.push(format!(
                        "Replaced qdisc {} on {}",
                        qdisc.qdisc_type.kind(),
                        qdisc.dev
                    ));
                    result.changes_made += 1;
                }
                Err(e) => {
                    if options.continue_on_error {
                        result.errors.push(ApplyError {
                            operation: op,
                            error: e,
                        });
                    } else {
                        return Err(e);
                    }
                }
            }
        }
    }

    // 5b. Add new qdiscs
    for qdisc in &diff.qdiscs_to_add {
        let op = format!("add qdisc {} on {}", qdisc.qdisc_type.kind(), qdisc.dev);
        if options.dry_run {
            result.summary.push(format!("Would {}", op));
            result.changes_made += 1;
        } else {
            match add_qdisc(conn, qdisc).await {
                Ok(()) => {
                    result.summary.push(format!(
                        "Added qdisc {} on {}",
                        qdisc.qdisc_type.kind(),
                        qdisc.dev
                    ));
                    result.changes_made += 1;
                }
                Err(e) => {
                    if options.continue_on_error {
                        result.errors.push(ApplyError {
                            operation: op,
                            error: e,
                        });
                    } else {
                        return Err(e);
                    }
                }
            }
        }
    }

    // Plan 205 (0.19) — `purge` was removed because the
    // `*_to_remove` collections were never populated by the diff
    // phase, so the apply-side branch was dead code that lied
    // about what it did. Pre-0.19 `ApplyOptions::with_purge(true)`
    // silently no-op'd; users believed kernel state was being
    // reconciled when it wasn't. For the "remove undeclared
    // resources" use case, the imperative API
    // (`Connection::del_link` / `del_address` / `del_route` /
    // `del_qdisc`) is the canonical 0.19 channel. A fully wired
    // purge with a kernel-managed-resource exclusion list
    // (IPv6 link-local, multicast, `lo`, link-local prefix
    // routes) is queued for 0.20.

    Ok(result)
}

// ============================================================================
// Helper functions for applying individual changes
// ============================================================================

async fn create_link(conn: &Connection<Route>, link: &DeclaredLink) -> Result<()> {
    match &link.link_type {
        DeclaredLinkType::Dummy => {
            let mut config = DummyLink::new(&link.name);
            if let Some(mtu) = link.mtu {
                config = config.mtu(mtu);
            }
            if let Some(addr) = link.address {
                config = config.address(addr);
            }
            conn.add_link(config).await?;
        }
        DeclaredLinkType::Veth { peer } => {
            let mut config = VethLink::new(&link.name, peer);
            if let Some(mtu) = link.mtu {
                config = config.mtu(mtu);
            }
            if let Some(addr) = link.address {
                config = config.address(addr);
            }
            conn.add_link(config).await?;
        }
        DeclaredLinkType::Bridge => {
            let mut config = BridgeLink::new(&link.name);
            if let Some(mtu) = link.mtu {
                config = config.mtu(mtu);
            }
            if let Some(addr) = link.address {
                config = config.address(addr);
            }
            conn.add_link(config).await?;
        }
        DeclaredLinkType::Vlan {
            parent,
            vlan_id,
            protocol,
        } => {
            let mut config = VlanLink::new(&link.name, parent, *vlan_id);
            if let Some(mtu) = link.mtu {
                config = config.mtu(mtu);
            }
            if let Some(p) = protocol {
                config = config.protocol(*p);
            }
            conn.add_link(config).await?;
        }
        DeclaredLinkType::Vxlan {
            vni,
            remote,
            local,
            port,
            underlay_dev,
        } => {
            let mut config = VxlanLink::new(&link.name, *vni);
            if let Some(IpAddr::V4(remote_v4)) = remote {
                config = config.remote(*remote_v4);
            }
            // Plan 190 §2.1 — local/port/underlay are v4-only
            // at the imperative VxlanLink layer today (IPv6
            // tunnel source not yet plumbed); IPv6 local
            // values are silently dropped, matching the
            // existing IPv4-only `remote` handling.
            if let Some(IpAddr::V4(local_v4)) = local {
                config = config.local(*local_v4);
            }
            if let Some(p) = port {
                config = config.port(*p);
            }
            if let Some(dev) = underlay_dev {
                config = config.dev(dev);
            }
            conn.add_link(config).await?;
        }
        DeclaredLinkType::Macvlan { parent, mode } => {
            let mut config = MacvlanLink::new(&link.name, parent);
            config = config.mode(convert_macvlan_mode(*mode));
            if let Some(addr) = link.address {
                config = config.address(addr);
            }
            conn.add_link(config).await?;
        }
        DeclaredLinkType::Bond {
            mode,
            miimon,
            xmit_hash_policy,
            min_links,
            ad_select,
            lacp_rate,
            downdelay,
            updelay,
            resend_igmp,
        } => {
            let mut config = BondLink::new(&link.name).mode(convert_bond_mode(*mode));
            if let Some(ms) = miimon {
                config = config.miimon(*ms);
            }
            if let Some(policy) = xmit_hash_policy
                && let Ok(p) = crate::netlink::link::XmitHashPolicy::try_from(*policy)
            {
                config = config.xmit_hash_policy(p);
            }
            if let Some(count) = min_links {
                config = config.min_links(*count);
            }
            if let Some(sel) = ad_select {
                config = config.ad_select(*sel);
            }
            if let Some(rate) = lacp_rate {
                config = config.lacp_rate(*rate);
            }
            if let Some(ms) = downdelay {
                config = config.downdelay(*ms);
            }
            if let Some(ms) = updelay {
                config = config.updelay(*ms);
            }
            if let Some(count) = resend_igmp {
                config = config.resend_igmp(*count);
            }
            if let Some(mtu) = link.mtu {
                config = config.mtu(mtu);
            }
            if let Some(addr) = link.address {
                config = config.address(addr);
            }
            conn.add_link(config).await?;
        }
        DeclaredLinkType::Ifb => {
            let config = IfbLink::new(&link.name);
            conn.add_link(config).await?;
        }
        DeclaredLinkType::Vrf { table } => {
            let mut config = crate::netlink::link::VrfLink::new(&link.name, *table);
            if let Some(mtu) = link.mtu {
                config = config.mtu(mtu);
            }
            conn.add_link(config).await?;
        }
        DeclaredLinkType::Ovpn => {
            let mut config = crate::netlink::link::OvpnLink::new(&link.name);
            if let Some(mtu) = link.mtu {
                config = config.mtu(mtu);
            }
            conn.add_link(config).await?;
        }
        DeclaredLinkType::Netkit {
            peer,
            mode,
            primary_policy,
            peer_policy,
            scrub,
            peer_scrub,
        } => {
            let mut config = crate::netlink::link::NetkitLink::new(&link.name, peer);
            if let Some(m) = mode {
                config = config.mode(*m);
            }
            if let Some(p) = primary_policy {
                config = config.policy(*p);
            }
            if let Some(p) = peer_policy {
                config = config.peer_policy(*p);
            }
            if let Some(s) = scrub {
                config = config.scrub(*s);
            }
            if let Some(s) = peer_scrub {
                config = config.peer_scrub(*s);
            }
            if let Some(mtu) = link.mtu {
                config = config.mtu(mtu);
            }
            conn.add_link(config).await?;
        }
        DeclaredLinkType::Physical => {
            // Physical interfaces can't be created, only configured
            // This should not be reached
        }
    }

    // Set interface up if requested
    if link.state == super::types::LinkState::Up {
        conn.set_link_up(&link.name).await?;
    }

    // Set master if requested
    if let Some(master) = &link.master {
        conn.set_link_master(&link.name, master).await?;
    }

    Ok(())
}

async fn modify_link(conn: &Connection<Route>, name: &str, changes: &LinkChanges) -> Result<()> {
    if changes.set_up {
        conn.set_link_up(name).await?;
    }
    if changes.set_down {
        conn.set_link_down(name).await?;
    }
    if let Some(mtu) = changes.set_mtu {
        conn.set_link_mtu(name, mtu).await?;
    }
    if let Some(master) = &changes.set_master {
        conn.set_link_master(name, master).await?;
    }
    if changes.unset_master {
        conn.set_link_nomaster(name).await?;
    }
    Ok(())
}

async fn add_address(conn: &Connection<Route>, addr: &DeclaredAddress) -> Result<()> {
    match addr.address {
        IpAddr::V4(v4) => {
            let config = Ipv4Address::new(&addr.dev, v4, addr.prefix_len);
            conn.add_address(config).await
        }
        IpAddr::V6(v6) => {
            let config = Ipv6Address::new(&addr.dev, v6, addr.prefix_len);
            conn.add_address(config).await
        }
    }
}

async fn add_route(conn: &Connection<Route>, route: &DeclaredRoute) -> Result<()> {
    match route.destination {
        IpAddr::V4(dst) => {
            let mut config = Ipv4Route::from_addr(dst, route.prefix_len);

            // Set gateway
            if let Some(IpAddr::V4(gw)) = route.gateway {
                config = config.gateway(gw);
            }

            // Set device
            if let Some(dev) = &route.dev {
                config = config.dev(dev);
            }

            // Set metric
            if let Some(metric) = route.metric {
                config = config.metric(metric);
            }

            // Set table
            if let Some(table) = route.table {
                config = config.table(table);
            }

            // Set route type
            config = match route.route_type {
                DeclaredRouteType::Unicast => config,
                DeclaredRouteType::Blackhole => {
                    config.route_type(crate::netlink::types::route::RouteType::Blackhole)
                }
                DeclaredRouteType::Unreachable => {
                    config.route_type(crate::netlink::types::route::RouteType::Unreachable)
                }
                DeclaredRouteType::Prohibit => {
                    config.route_type(crate::netlink::types::route::RouteType::Prohibit)
                }
            };

            // Plan 207d H3 — use NLM_F_REPLACE so a change to
            // gateway/dev/metric on the same `(dst, prefix, table)`
            // atomically swaps the existing route instead of
            // failing with EEXIST (and silently no-op'ing because
            // the pre-0.19 diff didn't notice the gateway change
            // at all). New routes are also accepted by replace.
            conn.replace_route(config).await
        }
        IpAddr::V6(dst) => {
            let mut config = Ipv6Route::from_addr(dst, route.prefix_len);

            if let Some(IpAddr::V6(gw)) = route.gateway {
                config = config.gateway(gw);
            }

            if let Some(dev) = &route.dev {
                config = config.dev(dev);
            }

            if let Some(metric) = route.metric {
                config = config.metric(metric);
            }

            if let Some(table) = route.table {
                config = config.table(table);
            }

            config = match route.route_type {
                DeclaredRouteType::Unicast => config,
                DeclaredRouteType::Blackhole => {
                    config.route_type(crate::netlink::types::route::RouteType::Blackhole)
                }
                DeclaredRouteType::Unreachable => {
                    config.route_type(crate::netlink::types::route::RouteType::Unreachable)
                }
                DeclaredRouteType::Prohibit => {
                    config.route_type(crate::netlink::types::route::RouteType::Prohibit)
                }
            };

            // Plan 207d H3 — use NLM_F_REPLACE so a change to
            // gateway/dev/metric on the same `(dst, prefix, table)`
            // atomically swaps the existing route instead of
            // failing with EEXIST (and silently no-op'ing because
            // the pre-0.19 diff didn't notice the gateway change
            // at all). New routes are also accepted by replace.
            conn.replace_route(config).await
        }
    }
}

async fn add_qdisc(conn: &Connection<Route>, qdisc: &DeclaredQdisc) -> Result<()> {
    match &qdisc.qdisc_type {
        DeclaredQdiscType::Netem {
            delay_us,
            jitter_us,
            loss_percent,
            limit,
            duplicate_percent,
            corrupt_percent,
            reorder_percent,
            loss_correlation,
            delay_correlation,
        } => {
            let mut config = NetemConfig::new();
            if let Some(delay) = delay_us {
                config = config.delay(Duration::from_micros(*delay as u64));
            }
            if let Some(jitter) = jitter_us {
                config = config.jitter(Duration::from_micros(*jitter as u64));
            }
            if let Some(loss) = loss_percent {
                config = config.loss(crate::util::Percent::new(*loss));
            }
            if let Some(lim) = limit {
                config = config.limit(*lim);
            }
            if let Some(d) = duplicate_percent {
                config = config.duplicate(crate::util::Percent::new(*d));
            }
            if let Some(c) = corrupt_percent {
                config = config.corrupt(crate::util::Percent::new(*c));
            }
            if let Some(r) = reorder_percent {
                config = config.reorder(crate::util::Percent::new(*r));
            }
            if let Some(corr) = loss_correlation {
                config = config.loss_correlation(crate::util::Percent::new(*corr));
            }
            if let Some(corr) = delay_correlation {
                config = config.delay_correlation(crate::util::Percent::new(*corr));
            }
            conn.add_qdisc(&qdisc.dev, config.build()).await
        }
        DeclaredQdiscType::Htb { default_class } => {
            let config = HtbQdiscConfig::new().default_class(*default_class);
            conn.add_qdisc_full(
                &qdisc.dev,
                crate::TcHandle::ROOT,
                Some(crate::TcHandle::major_only(1)),
                config,
            )
            .await
        }
        DeclaredQdiscType::FqCodel {
            limit,
            target_us,
            interval_us,
        } => {
            let mut config = FqCodelConfig::new();
            if let Some(lim) = limit {
                config = config.limit(*lim);
            }
            if let Some(target) = target_us {
                config = config.target(Duration::from_micros(*target as u64));
            }
            if let Some(interval) = interval_us {
                config = config.interval(Duration::from_micros(*interval as u64));
            }
            conn.add_qdisc(&qdisc.dev, config).await
        }
        DeclaredQdiscType::Tbf {
            rate_bps,
            burst_bytes,
            limit_bytes,
        } => {
            let mut config = TbfConfig::new()
                .rate(crate::util::Rate::bytes_per_sec(*rate_bps))
                .burst(crate::util::Bytes::new(*burst_bytes as u64));
            if let Some(limit) = limit_bytes {
                config = config.limit(crate::util::Bytes::new(*limit as u64));
            }
            conn.add_qdisc(&qdisc.dev, config).await
        }
        DeclaredQdiscType::Sfq { perturb_secs } => {
            let mut config = SfqConfig::new();
            if let Some(perturb) = perturb_secs {
                config = config.perturb(*perturb as i32);
            }
            conn.add_qdisc(&qdisc.dev, config).await
        }
        DeclaredQdiscType::Prio { bands } => {
            let mut config = PrioConfig::new();
            if let Some(b) = bands {
                config = config.bands(*b as i32);
            }
            conn.add_qdisc(&qdisc.dev, config).await
        }
        DeclaredQdiscType::Ingress => conn.add_qdisc(&qdisc.dev, IngressConfig::new()).await,
        DeclaredQdiscType::Clsact => conn.add_qdisc(&qdisc.dev, ClsactConfig::new()).await,
    }
}

async fn replace_qdisc(conn: &Connection<Route>, qdisc: &DeclaredQdisc) -> Result<()> {
    // Plan 207f M18 — use atomic `RTM_NEWQDISC` with `NLM_F_REPLACE`
    // (`Connection::replace_qdisc*`) instead of the pre-0.19
    // del-then-add sequence. The old sequence had a transient
    // window between `del_qdisc` (which restored the default
    // `pfifo_fast`/`mq`) and `add_qdisc` (which installed the
    // new declared kind). If `add_qdisc` failed mid-window the
    // interface kept the kernel-default qdisc, NOT the previous
    // declared one — visible state divergence on apply failure.
    //
    // The atomic form is unsupported on a small set of qdiscs
    // (`Ingress`, `Clsact`) where the kernel rejects REPLACE
    // semantically; for those we fall back to del+add since the
    // kind is parent-fixed (ingress / clsact slots).
    match &qdisc.qdisc_type {
        DeclaredQdiscType::Ingress | DeclaredQdiscType::Clsact => {
            // Kernel does not accept NLM_F_REPLACE on these
            // pseudo-qdiscs (the kind IS the slot). Use del+add.
            let parent_handle = match qdisc.parent {
                QdiscParent::Root => crate::TcHandle::ROOT,
                QdiscParent::Ingress => crate::TcHandle::INGRESS,
            };
            match conn.del_qdisc(&qdisc.dev, parent_handle).await {
                Ok(()) => {}
                Err(e) if e.is_not_found() => {}
                Err(e) => return Err(e),
            }
            return add_qdisc(conn, qdisc).await;
        }
        _ => {}
    }

    // Atomic replace via NLM_F_REPLACE on RTM_NEWQDISC.
    match &qdisc.qdisc_type {
        DeclaredQdiscType::Netem {
            delay_us,
            jitter_us,
            loss_percent,
            limit,
            duplicate_percent,
            corrupt_percent,
            reorder_percent,
            loss_correlation,
            delay_correlation,
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
            if let Some(d) = duplicate_percent {
                cfg = cfg.duplicate(crate::util::Percent::new(*d));
            }
            if let Some(c) = corrupt_percent {
                cfg = cfg.corrupt(crate::util::Percent::new(*c));
            }
            if let Some(r) = reorder_percent {
                cfg = cfg.reorder(crate::util::Percent::new(*r));
            }
            if let Some(corr) = loss_correlation {
                cfg = cfg.loss_correlation(crate::util::Percent::new(*corr));
            }
            if let Some(corr) = delay_correlation {
                cfg = cfg.delay_correlation(crate::util::Percent::new(*corr));
            }
            conn.replace_qdisc(&qdisc.dev, cfg.build()).await
        }
        DeclaredQdiscType::Htb { default_class } => {
            let cfg = HtbQdiscConfig::new().default_class(*default_class);
            conn.replace_qdisc_full(
                &qdisc.dev,
                crate::TcHandle::ROOT,
                Some(crate::TcHandle::major_only(1)),
                cfg,
            )
            .await
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
            conn.replace_qdisc(&qdisc.dev, cfg).await
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
            conn.replace_qdisc(&qdisc.dev, cfg).await
        }
        DeclaredQdiscType::Sfq { perturb_secs } => {
            let mut cfg = SfqConfig::new();
            if let Some(p) = perturb_secs {
                cfg = cfg.perturb(*p as i32);
            }
            conn.replace_qdisc(&qdisc.dev, cfg).await
        }
        DeclaredQdiscType::Prio { bands } => {
            let mut cfg = PrioConfig::new();
            if let Some(b) = bands {
                cfg = cfg.bands(*b as i32);
            }
            conn.replace_qdisc(&qdisc.dev, cfg).await
        }
        // Ingress/Clsact already handled above.
        DeclaredQdiscType::Ingress | DeclaredQdiscType::Clsact => unreachable!(),
    }
}

fn convert_macvlan_mode(mode: MacvlanMode) -> crate::netlink::link::MacvlanMode {
    match mode {
        MacvlanMode::Private => crate::netlink::link::MacvlanMode::Private,
        MacvlanMode::Vepa => crate::netlink::link::MacvlanMode::Vepa,
        MacvlanMode::Bridge => crate::netlink::link::MacvlanMode::Bridge,
        MacvlanMode::Passthru => crate::netlink::link::MacvlanMode::Passthru,
        MacvlanMode::Source => crate::netlink::link::MacvlanMode::Source,
    }
}

fn convert_bond_mode(mode: BondMode) -> crate::netlink::link::BondMode {
    match mode {
        BondMode::BalanceRr => crate::netlink::link::BondMode::BalanceRr,
        BondMode::ActiveBackup => crate::netlink::link::BondMode::ActiveBackup,
        BondMode::BalanceXor => crate::netlink::link::BondMode::BalanceXor,
        BondMode::Broadcast => crate::netlink::link::BondMode::Broadcast,
        BondMode::Ieee802_3ad => crate::netlink::link::BondMode::Lacp,
        BondMode::BalanceTlb => crate::netlink::link::BondMode::BalanceTlb,
        BondMode::BalanceAlb => crate::netlink::link::BondMode::BalanceAlb,
    }
}
