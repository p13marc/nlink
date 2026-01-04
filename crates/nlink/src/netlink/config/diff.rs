//! Configuration diffing.
//!
//! This module computes the difference between desired and current network state.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

use super::types::{
    DeclaredAddress, DeclaredLink, DeclaredLinkType, DeclaredQdisc, DeclaredRoute, LinkState,
    NetworkConfig, QdiscParent,
};
use crate::netlink::connection::Connection;
use crate::netlink::error::Result;
use crate::netlink::messages::{AddressMessage, LinkMessage, RouteMessage, TcMessage};
use crate::netlink::protocol::Route;
use crate::netlink::types::link::OperState;
use crate::netlink::types::route::RouteType;

/// Difference between desired and current network state.
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

/// Changes to make to an existing link.
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
                // Different type, need to replace
                diff.qdiscs_to_replace.push(declared.clone());
            }
            // TODO: Could check detailed parameters here
        } else {
            // No qdisc at this position, need to add
            diff.qdiscs_to_add.push(declared.clone());
        }
    }
}
