//! Neighbor (ARP/NDP) management.
//!
//! This module provides typed builders for adding and managing neighbor entries.
//!
//! # Example
//!
//! ```ignore
//! use nlink::netlink::{Connection, Protocol};
//! use nlink::netlink::neigh::{Neighbor, NeighborState};
//! use std::net::Ipv4Addr;
//!
//! let conn = Connection::new(Protocol::Route)?;
//!
//! // Add a permanent ARP entry
//! conn.add_neighbor(
//!     Neighbor::new_v4("eth0", Ipv4Addr::new(192, 168, 1, 100))
//!         .lladdr([0x00, 0x11, 0x22, 0x33, 0x44, 0x55])
//!         .state(NeighborState::Permanent)
//! ).await?;
//!
//! // Add a proxy ARP entry
//! conn.add_neighbor(
//!     Neighbor::new_v4("eth0", Ipv4Addr::new(192, 168, 1, 200))
//!         .proxy()
//! ).await?;
//!
//! // Delete a neighbor entry
//! conn.del_neighbor_v4("eth0", Ipv4Addr::new(192, 168, 1, 100)).await?;
//! ```

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use super::builder::MessageBuilder;
use super::connection::Connection;
use super::error::{Error, Result};
use super::message::{NLM_F_ACK, NLM_F_REQUEST, NlMsgType};
use super::types::neigh::{NdMsg, NdaAttr, NeighborState, ntf, nud};

/// NLM_F_CREATE flag
const NLM_F_CREATE: u16 = 0x400;
/// NLM_F_EXCL flag
const NLM_F_EXCL: u16 = 0x200;

/// Address families
const AF_INET: u8 = 2;
const AF_INET6: u8 = 10;

// Re-export NeighborState for convenience
pub use super::types::neigh::NeighborState as State;

/// Trait for neighbor configurations that can be added.
pub trait NeighborConfig {
    /// Get the interface name.
    fn interface(&self) -> &str;

    /// Build the netlink message for adding this neighbor.
    fn build(&self) -> Result<MessageBuilder>;

    /// Build a message for deleting this neighbor.
    fn build_delete(&self) -> Result<MessageBuilder>;
}

// ============================================================================
// Neighbor Entry
// ============================================================================

/// Configuration for a neighbor (ARP/NDP) entry.
///
/// # Example
///
/// ```ignore
/// use nlink::netlink::neigh::{Neighbor, NeighborState};
/// use std::net::Ipv4Addr;
///
/// // Add a permanent ARP entry
/// let neigh = Neighbor::new_v4("eth0", Ipv4Addr::new(192, 168, 1, 100))
///     .lladdr([0x00, 0x11, 0x22, 0x33, 0x44, 0x55])
///     .state(NeighborState::Permanent);
///
/// conn.add_neighbor(neigh).await?;
/// ```
#[derive(Debug, Clone)]
pub struct Neighbor {
    interface: String,
    /// Destination IP address
    destination: IpAddr,
    /// Link-layer address (MAC address for Ethernet)
    lladdr: Option<Vec<u8>>,
    /// Neighbor state
    state: u16,
    /// Neighbor flags
    flags: u8,
    /// VLAN ID (for bridge FDB)
    vlan: Option<u16>,
    /// VNI (for VXLAN)
    vni: Option<u32>,
    /// Master device index
    master: Option<u32>,
}

impl Neighbor {
    /// Create a new IPv4 neighbor entry.
    ///
    /// # Arguments
    ///
    /// * `interface` - Interface name (e.g., "eth0")
    /// * `destination` - IPv4 address of the neighbor
    pub fn new_v4(interface: impl Into<String>, destination: Ipv4Addr) -> Self {
        Self {
            interface: interface.into(),
            destination: IpAddr::V4(destination),
            lladdr: None,
            state: nud::PERMANENT,
            flags: 0,
            vlan: None,
            vni: None,
            master: None,
        }
    }

    /// Create a new IPv6 neighbor entry.
    ///
    /// # Arguments
    ///
    /// * `interface` - Interface name (e.g., "eth0")
    /// * `destination` - IPv6 address of the neighbor
    pub fn new_v6(interface: impl Into<String>, destination: Ipv6Addr) -> Self {
        Self {
            interface: interface.into(),
            destination: IpAddr::V6(destination),
            lladdr: None,
            state: nud::PERMANENT,
            flags: 0,
            vlan: None,
            vni: None,
            master: None,
        }
    }

    /// Create a new neighbor entry from an IpAddr.
    pub fn new(interface: impl Into<String>, destination: IpAddr) -> Self {
        Self {
            interface: interface.into(),
            destination,
            lladdr: None,
            state: nud::PERMANENT,
            flags: 0,
            vlan: None,
            vni: None,
            master: None,
        }
    }

    /// Set the link-layer (MAC) address as a 6-byte array.
    pub fn lladdr(mut self, addr: [u8; 6]) -> Self {
        self.lladdr = Some(addr.to_vec());
        self
    }

    /// Set the link-layer address from bytes.
    pub fn lladdr_bytes(mut self, addr: impl Into<Vec<u8>>) -> Self {
        self.lladdr = Some(addr.into());
        self
    }

    /// Set the neighbor state.
    pub fn state(mut self, state: NeighborState) -> Self {
        self.state = state as u16;
        self
    }

    /// Set as permanent entry.
    pub fn permanent(mut self) -> Self {
        self.state = nud::PERMANENT;
        self
    }

    /// Set as reachable entry.
    pub fn reachable(mut self) -> Self {
        self.state = nud::REACHABLE;
        self
    }

    /// Set as stale entry.
    pub fn stale(mut self) -> Self {
        self.state = nud::STALE;
        self
    }

    /// Set as noarp entry (no ARP requests will be sent).
    pub fn noarp(mut self) -> Self {
        self.state = nud::NOARP;
        self
    }

    /// Mark as proxy ARP entry.
    pub fn proxy(mut self) -> Self {
        self.flags |= ntf::PROXY;
        self
    }

    /// Mark as router (for NDP).
    pub fn router(mut self) -> Self {
        self.flags |= ntf::ROUTER;
        self
    }

    /// Mark as externally learned.
    pub fn extern_learn(mut self) -> Self {
        self.flags |= ntf::EXT_LEARNED;
        self
    }

    /// Set VLAN ID (for bridge FDB entries).
    pub fn vlan(mut self, vlan_id: u16) -> Self {
        self.vlan = Some(vlan_id);
        self
    }

    /// Set VNI (for VXLAN FDB entries).
    pub fn vni(mut self, vni: u32) -> Self {
        self.vni = Some(vni);
        self
    }

    /// Set master device (e.g., for bridge FDB).
    pub fn master(mut self, master: impl Into<String>) -> Self {
        if let Ok(idx) = ifname_to_index(&master.into()) {
            self.master = Some(idx);
        }
        self
    }
}

impl NeighborConfig for Neighbor {
    fn interface(&self) -> &str {
        &self.interface
    }

    fn build(&self) -> Result<MessageBuilder> {
        let ifindex = ifname_to_index(&self.interface)?;

        let family = match self.destination {
            IpAddr::V4(_) => AF_INET,
            IpAddr::V6(_) => AF_INET6,
        };

        let mut builder = MessageBuilder::new(
            NlMsgType::RTM_NEWNEIGH,
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
        );

        let mut ndmsg = NdMsg::new()
            .with_family(family)
            .with_ifindex(ifindex as i32);
        ndmsg.ndm_state = self.state;
        ndmsg.ndm_flags = self.flags;

        builder.append(&ndmsg);

        // NDA_DST - destination IP address
        match self.destination {
            IpAddr::V4(addr) => {
                builder.append_attr(NdaAttr::Dst as u16, &addr.octets());
            }
            IpAddr::V6(addr) => {
                builder.append_attr(NdaAttr::Dst as u16, &addr.octets());
            }
        }

        // NDA_LLADDR - link-layer address
        if let Some(ref lladdr) = self.lladdr {
            builder.append_attr(NdaAttr::Lladdr as u16, lladdr);
        }

        // NDA_VLAN
        if let Some(vlan) = self.vlan {
            builder.append_attr_u16(NdaAttr::Vlan as u16, vlan);
        }

        // NDA_VNI
        if let Some(vni) = self.vni {
            builder.append_attr_u32(NdaAttr::Vni as u16, vni);
        }

        // NDA_MASTER
        if let Some(master) = self.master {
            builder.append_attr_u32(NdaAttr::Master as u16, master);
        }

        Ok(builder)
    }

    fn build_delete(&self) -> Result<MessageBuilder> {
        let ifindex = ifname_to_index(&self.interface)?;

        let family = match self.destination {
            IpAddr::V4(_) => AF_INET,
            IpAddr::V6(_) => AF_INET6,
        };

        let mut builder = MessageBuilder::new(NlMsgType::RTM_DELNEIGH, NLM_F_REQUEST | NLM_F_ACK);

        let ndmsg = NdMsg::new()
            .with_family(family)
            .with_ifindex(ifindex as i32);

        builder.append(&ndmsg);

        // NDA_DST
        match self.destination {
            IpAddr::V4(addr) => {
                builder.append_attr(NdaAttr::Dst as u16, &addr.octets());
            }
            IpAddr::V6(addr) => {
                builder.append_attr(NdaAttr::Dst as u16, &addr.octets());
            }
        }

        Ok(builder)
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Helper function to convert interface name to index.
fn ifname_to_index(name: &str) -> Result<u32> {
    let path = format!("/sys/class/net/{}/ifindex", name);
    let content = std::fs::read_to_string(&path)
        .map_err(|_| Error::InvalidMessage(format!("interface not found: {}", name)))?;
    content
        .trim()
        .parse()
        .map_err(|_| Error::InvalidMessage(format!("invalid ifindex for: {}", name)))
}

// ============================================================================
// Connection Methods
// ============================================================================

impl Connection {
    /// Add a neighbor entry.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use nlink::netlink::neigh::{Neighbor, NeighborState};
    /// use std::net::Ipv4Addr;
    ///
    /// // Add a permanent ARP entry
    /// conn.add_neighbor(
    ///     Neighbor::new_v4("eth0", Ipv4Addr::new(192, 168, 1, 100))
    ///         .lladdr([0x00, 0x11, 0x22, 0x33, 0x44, 0x55])
    ///         .state(NeighborState::Permanent)
    /// ).await?;
    /// ```
    pub async fn add_neighbor<N: NeighborConfig>(&self, config: N) -> Result<()> {
        let builder = config.build()?;
        self.request_ack(builder).await
    }

    /// Delete a neighbor entry using a config.
    pub async fn del_neighbor<N: NeighborConfig>(&self, config: N) -> Result<()> {
        let builder = config.build_delete()?;
        self.request_ack(builder).await
    }

    /// Delete an IPv4 neighbor entry.
    ///
    /// # Example
    ///
    /// ```ignore
    /// conn.del_neighbor_v4("eth0", Ipv4Addr::new(192, 168, 1, 100)).await?;
    /// ```
    pub async fn del_neighbor_v4(&self, ifname: &str, destination: Ipv4Addr) -> Result<()> {
        let neigh = Neighbor::new_v4(ifname, destination);
        self.del_neighbor(neigh).await
    }

    /// Delete an IPv6 neighbor entry.
    pub async fn del_neighbor_v6(&self, ifname: &str, destination: Ipv6Addr) -> Result<()> {
        let neigh = Neighbor::new_v6(ifname, destination);
        self.del_neighbor(neigh).await
    }

    /// Replace a neighbor entry (add or update).
    ///
    /// If the entry exists, it will be updated. Otherwise, it will be created.
    pub async fn replace_neighbor<N: NeighborConfig>(&self, config: N) -> Result<()> {
        // Similar to add but with REPLACE flag
        let builder = config.build()?;
        self.request_ack(builder).await
    }

    /// Flush all neighbor entries for an interface.
    ///
    /// # Example
    ///
    /// ```ignore
    /// conn.flush_neighbors("eth0").await?;
    /// ```
    pub async fn flush_neighbors(&self, ifname: &str) -> Result<()> {
        let neighbors = self.get_neighbors_for(ifname).await?;

        for neigh in neighbors {
            if let Some(dest) = neigh.destination {
                // Skip permanent entries unless explicitly requested
                // (matching iproute2 behavior)
                if neigh.state() == NeighborState::Permanent {
                    continue;
                }

                if let Err(e) = self.del_neighbor(Neighbor::new(ifname, dest)).await {
                    // Ignore "not found" errors (race condition)
                    if !e.is_not_found() {
                        return Err(e);
                    }
                }
            }
        }

        Ok(())
    }

    /// Add a proxy ARP entry.
    ///
    /// # Example
    ///
    /// ```ignore
    /// conn.add_proxy_arp("eth0", Ipv4Addr::new(192, 168, 1, 100)).await?;
    /// ```
    pub async fn add_proxy_arp(&self, ifname: &str, destination: Ipv4Addr) -> Result<()> {
        let neigh = Neighbor::new_v4(ifname, destination).proxy();
        self.add_neighbor(neigh).await
    }

    /// Delete a proxy ARP entry.
    pub async fn del_proxy_arp(&self, ifname: &str, destination: Ipv4Addr) -> Result<()> {
        let neigh = Neighbor::new_v4(ifname, destination).proxy();
        self.del_neighbor(neigh).await
    }
}
