//! Configuration application logic.
//!
//! This module applies the computed diff to achieve the desired network state.

use std::net::IpAddr;
use std::time::Duration;

use super::diff::{ConfigDiff, LinkChanges, compute_diff};
use super::types::{
    DeclaredAddress, DeclaredLink, DeclaredLinkType, DeclaredQdisc, DeclaredQdiscType,
    DeclaredRoute, DeclaredRouteType, MacvlanMode, NetworkConfig, QdiscParent,
};
use crate::netlink::addr::{Ipv4Address, Ipv6Address};
use crate::netlink::connection::Connection;
use crate::netlink::error::{Error, Result};
use crate::netlink::link::{
    BridgeLink, DummyLink, IfbLink, MacvlanLink, VethLink, VlanLink, VxlanLink,
};
use crate::netlink::protocol::Route;
use crate::netlink::route::{Ipv4Route, Ipv6Route};
use crate::netlink::tc::{
    ClsactConfig, FqCodelConfig, HtbQdiscConfig, IngressConfig, NetemConfig, PrioConfig, SfqConfig,
    TbfConfig,
};

/// Options for applying configuration.
#[derive(Debug, Clone, Default)]
pub struct ApplyOptions {
    /// Don't actually make changes, just compute what would be done.
    pub dry_run: bool,
    /// Continue applying changes even if some operations fail.
    pub continue_on_error: bool,
    /// Remove resources that are not in the configuration.
    ///
    /// When enabled, interfaces, addresses, and routes that exist
    /// but are not declared in the config will be removed.
    ///
    /// **Warning**: Use with caution! This can remove important
    /// system interfaces if they're not in your config.
    pub purge: bool,
}

/// Result of applying configuration.
#[derive(Debug, Default)]
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
#[derive(Debug)]
pub struct ApplyError {
    /// What operation was being performed.
    pub operation: String,
    /// The underlying error.
    pub error: Error,
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

    // 6. Remove old resources (if purge enabled)
    if options.purge {
        // Remove qdiscs
        for (dev, parent) in &diff.qdiscs_to_remove {
            let op = format!("remove qdisc on {} ({:?})", dev, parent);
            if options.dry_run {
                result.summary.push(format!("Would {}", op));
                result.changes_made += 1;
            } else {
                let parent_str = match parent {
                    QdiscParent::Root => "root",
                    QdiscParent::Ingress => "ingress",
                };
                match conn.del_qdisc(dev, parent_str).await {
                    Ok(()) => {
                        result.summary.push(format!("Removed qdisc on {}", dev));
                        result.changes_made += 1;
                    }
                    Err(e) if e.is_not_found() => {
                        // Already gone, that's fine
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

        // Remove routes
        for (dst, prefix_len, table) in &diff.routes_to_remove {
            let op = format!("remove route {}/{}", dst, prefix_len);
            if options.dry_run {
                result.summary.push(format!("Would {}", op));
                result.changes_made += 1;
            } else {
                match remove_route(conn, *dst, *prefix_len, *table).await {
                    Ok(()) => {
                        result
                            .summary
                            .push(format!("Removed route {}/{}", dst, prefix_len));
                        result.changes_made += 1;
                    }
                    Err(e) if e.is_not_found() => {
                        // Already gone
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

        // Remove addresses
        for (dev, addr, prefix_len) in &diff.addresses_to_remove {
            let op = format!("remove address {}/{} from {}", addr, prefix_len, dev);
            if options.dry_run {
                result.summary.push(format!("Would {}", op));
                result.changes_made += 1;
            } else {
                match remove_address(conn, dev, *addr, *prefix_len).await {
                    Ok(()) => {
                        result.summary.push(format!(
                            "Removed address {}/{} from {}",
                            addr, prefix_len, dev
                        ));
                        result.changes_made += 1;
                    }
                    Err(e) if e.is_not_found() => {
                        // Already gone
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

        // Remove links (in reverse order of creation)
        for name in &diff.links_to_remove {
            let op = format!("remove link {}", name);
            if options.dry_run {
                result.summary.push(format!("Would {}", op));
                result.changes_made += 1;
            } else {
                match conn.del_link(name).await {
                    Ok(()) => {
                        result.summary.push(format!("Removed link {}", name));
                        result.changes_made += 1;
                    }
                    Err(e) if e.is_not_found() => {
                        // Already gone
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
    }

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
        DeclaredLinkType::Vlan { parent, vlan_id } => {
            let mut config = VlanLink::new(&link.name, parent, *vlan_id);
            if let Some(mtu) = link.mtu {
                config = config.mtu(mtu);
            }
            conn.add_link(config).await?;
        }
        DeclaredLinkType::Vxlan { vni, remote } => {
            let mut config = VxlanLink::new(&link.name, *vni);
            if let Some(IpAddr::V4(remote_v4)) = remote {
                config = config.remote(*remote_v4);
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
        DeclaredLinkType::Bond { mode: _ } => {
            // Bond creation requires additional work - for now just create basic bond
            // TODO: Implement full bond support
            return Err(Error::NotSupported(
                "Bond creation not yet implemented in declarative config".to_string(),
            ));
        }
        DeclaredLinkType::Ifb => {
            let config = IfbLink::new(&link.name);
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

async fn remove_address(
    conn: &Connection<Route>,
    dev: &str,
    addr: IpAddr,
    prefix_len: u8,
) -> Result<()> {
    conn.del_address(dev, addr, prefix_len).await
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

            conn.add_route(config).await
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

            conn.add_route(config).await
        }
    }
}

async fn remove_route(
    conn: &Connection<Route>,
    dst: IpAddr,
    prefix_len: u8,
    _table: u32,
) -> Result<()> {
    match dst {
        IpAddr::V4(v4) => {
            let route = Ipv4Route::from_addr(v4, prefix_len);
            conn.del_route(route).await
        }
        IpAddr::V6(v6) => {
            let route = Ipv6Route::from_addr(v6, prefix_len);
            conn.del_route(route).await
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
        } => {
            let mut config = NetemConfig::new();
            if let Some(delay) = delay_us {
                config = config.delay(Duration::from_micros(*delay as u64));
            }
            if let Some(jitter) = jitter_us {
                config = config.jitter(Duration::from_micros(*jitter as u64));
            }
            if let Some(loss) = loss_percent {
                config = config.loss(*loss);
            }
            if let Some(lim) = limit {
                config = config.limit(*lim);
            }
            conn.add_qdisc(&qdisc.dev, config.build()).await
        }
        DeclaredQdiscType::Htb { default_class } => {
            let config = HtbQdiscConfig::new().default_class(*default_class);
            conn.add_qdisc_full(&qdisc.dev, "root", Some("1:"), config)
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
            let mut config = TbfConfig::new().rate(*rate_bps).burst(*burst_bytes);
            if let Some(limit) = limit_bytes {
                config = config.limit(*limit);
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
    // First try to delete the existing qdisc
    let parent_str = match qdisc.parent {
        QdiscParent::Root => "root",
        QdiscParent::Ingress => "ingress",
    };

    // Ignore not found errors when deleting
    match conn.del_qdisc(&qdisc.dev, parent_str).await {
        Ok(()) => {}
        Err(e) if e.is_not_found() => {}
        Err(e) => return Err(e),
    }

    // Then add the new one
    add_qdisc(conn, qdisc).await
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
