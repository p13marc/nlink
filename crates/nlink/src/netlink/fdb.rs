//! Bridge Forwarding Database (FDB) management.
//!
//! This module provides typed builders for managing bridge FDB entries,
//! which are used for MAC address learning and forwarding in Linux bridges.
//!
//! # Example
//!
//! ```ignore
//! use nlink::netlink::{Connection, Route};
//! use nlink::netlink::fdb::FdbEntryBuilder;
//!
//! let conn = Connection::<Route>::new()?;
//!
//! // List FDB entries for a bridge
//! let entries = conn.get_fdb("br0").await?;
//! for entry in &entries {
//!     println!("{} vlan={:?}", entry.mac_str(), entry.vlan);
//! }
//!
//! // Add a static FDB entry
//! let mac = FdbEntryBuilder::parse_mac("aa:bb:cc:dd:ee:ff")?;
//! conn.add_fdb(
//!     FdbEntryBuilder::new(mac)
//!         .dev("veth0")
//!         .master("br0")
//!         .permanent()
//! ).await?;
//!
//! // Add VXLAN FDB entry (remote VTEP)
//! use std::net::Ipv4Addr;
//! conn.add_fdb(
//!     FdbEntryBuilder::new([0x00; 6])  // all-zeros for BUM traffic
//!         .dev("vxlan0")
//!         .dst(Ipv4Addr::new(192, 168, 1, 100).into())
//! ).await?;
//!
//! // Delete an entry
//! conn.del_fdb("veth0", mac, None).await?;
//! ```

use std::net::IpAddr;

use super::builder::MessageBuilder;
use super::connection::Connection;
use super::error::{Error, Result};
use super::interface_ref::InterfaceRef;
use super::message::{NLM_F_ACK, NLM_F_DUMP, NLM_F_REQUEST, NlMsgType};
use super::messages::NeighborMessage;
use super::protocol::Route;
use super::types::neigh::{NdMsg, NdaAttr, NeighborState};

/// NLM_F_CREATE flag
const NLM_F_CREATE: u16 = 0x400;
/// NLM_F_EXCL flag - fail if entry exists
const NLM_F_EXCL: u16 = 0x200;
/// NLM_F_REPLACE flag - replace existing entry
const NLM_F_REPLACE: u16 = 0x100;

/// AF_BRIDGE constant
const AF_BRIDGE: u8 = 7;

/// Neighbor flags for FDB entries.
mod ntf {
    /// Entry for the interface itself
    pub const SELF: u8 = 0x02;
    /// Entry for the master bridge
    pub const MASTER: u8 = 0x04;
    /// Externally learned entry
    pub const EXT_LEARNED: u8 = 0x10;
}

/// Neighbor states
mod nud {
    /// Permanent (static) entry
    pub const PERMANENT: u16 = 0x80;
    /// Reachable (dynamic) entry
    pub const REACHABLE: u16 = 0x02;
}

/// FDB entry information.
///
/// Represents a bridge forwarding database entry, containing MAC address
/// to port mappings, optional VLAN information, and VXLAN remote endpoint
/// data.
#[derive(Debug, Clone)]
pub struct FdbEntry {
    /// Interface index (bridge port)
    pub ifindex: u32,
    /// MAC address (6 bytes)
    pub mac: [u8; 6],
    /// VLAN ID (if VLAN filtering is enabled)
    pub vlan: Option<u16>,
    /// Destination IP (for VXLAN remote VTEP)
    pub dst: Option<IpAddr>,
    /// VNI (for VXLAN)
    pub vni: Option<u32>,
    /// Entry state (permanent, reachable, etc.)
    pub state: NeighborState,
    /// Entry flags (NTF_SELF, NTF_MASTER, etc.)
    pub flags: u8,
    /// Master device index (bridge interface)
    pub master: Option<u32>,
}

impl FdbEntry {
    /// Create from a NeighborMessage.
    ///
    /// Returns `None` if the message doesn't have a valid MAC address.
    pub fn from_neighbor(msg: &NeighborMessage) -> Option<Self> {
        let lladdr = msg.lladdr()?;
        if lladdr.len() != 6 {
            return None;
        }

        let mut mac = [0u8; 6];
        mac.copy_from_slice(lladdr);

        Some(Self {
            ifindex: msg.ifindex(),
            mac,
            vlan: msg.vlan(),
            dst: msg.destination().cloned(),
            vni: msg.vni(),
            state: msg.state(),
            flags: msg.flags(),
            master: msg.master(),
        })
    }

    /// Check if this is a permanent (static) entry.
    pub fn is_permanent(&self) -> bool {
        self.state == NeighborState::Permanent
    }

    /// Check if this is a dynamic (learned) entry.
    pub fn is_dynamic(&self) -> bool {
        !self.is_permanent()
    }

    /// Check if entry is for the interface itself (NTF_SELF).
    pub fn is_self(&self) -> bool {
        self.flags & ntf::SELF != 0
    }

    /// Check if entry is for the master bridge (NTF_MASTER).
    pub fn is_master(&self) -> bool {
        self.flags & ntf::MASTER != 0
    }

    /// Check if entry was externally learned (NTF_EXT_LEARNED).
    pub fn is_extern_learn(&self) -> bool {
        self.flags & ntf::EXT_LEARNED != 0
    }

    /// Format MAC address as a colon-separated hex string.
    pub fn mac_str(&self) -> String {
        format!(
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.mac[0], self.mac[1], self.mac[2], self.mac[3], self.mac[4], self.mac[5]
        )
    }
}

/// Builder for FDB entries.
///
/// # Example
///
/// ```ignore
/// use nlink::netlink::fdb::FdbEntryBuilder;
/// use std::net::Ipv4Addr;
///
/// // Static entry on a bridge port
/// let entry = FdbEntryBuilder::new([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff])
///     .dev("veth0")
///     .master("br0")
///     .vlan(100)
///     .permanent();
///
/// // VXLAN remote VTEP entry
/// let vxlan_entry = FdbEntryBuilder::new([0x00; 6])
///     .dev("vxlan0")
///     .dst(Ipv4Addr::new(192, 168, 1, 100).into());
/// ```
#[derive(Debug, Clone, Default)]
pub struct FdbEntryBuilder {
    mac: [u8; 6],
    dev: Option<InterfaceRef>,
    vlan: Option<u16>,
    dst: Option<IpAddr>,
    vni: Option<u32>,
    master: Option<InterfaceRef>,
    permanent: bool,
    self_flag: bool,
}

impl FdbEntryBuilder {
    /// Create a new FDB entry builder with the given MAC address.
    ///
    /// By default, the entry is marked as permanent (static).
    pub fn new(mac: [u8; 6]) -> Self {
        Self {
            mac,
            permanent: true,
            ..Default::default()
        }
    }

    /// Parse a MAC address from a colon-separated hex string.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let mac = FdbEntryBuilder::parse_mac("aa:bb:cc:dd:ee:ff")?;
    /// ```
    pub fn parse_mac(mac_str: &str) -> Result<[u8; 6]> {
        crate::util::addr::parse_mac(mac_str)
            .map_err(|e| Error::InvalidMessage(format!("invalid MAC: {}", e)))
    }

    /// Set the device name (bridge port interface).
    pub fn dev(mut self, dev: impl Into<String>) -> Self {
        self.dev = Some(InterfaceRef::Name(dev.into()));
        self
    }

    /// Set the interface index directly (namespace-safe).
    ///
    /// Use this instead of `dev()` when operating in a network namespace
    /// to avoid reading `/sys/class/net/` from the wrong namespace.
    pub fn ifindex(mut self, ifindex: u32) -> Self {
        self.dev = Some(InterfaceRef::Index(ifindex));
        self
    }

    /// Get the device reference.
    pub fn device_ref(&self) -> Option<&InterfaceRef> {
        self.dev.as_ref()
    }

    /// Set the VLAN ID.
    ///
    /// Only relevant for bridges with VLAN filtering enabled.
    pub fn vlan(mut self, vlan: u16) -> Self {
        self.vlan = Some(vlan);
        self
    }

    /// Set the destination IP address (for VXLAN FDB entries).
    ///
    /// This specifies the remote VTEP IP address for VXLAN tunneling.
    pub fn dst(mut self, dst: IpAddr) -> Self {
        self.dst = Some(dst);
        self
    }

    /// Set the VNI (for VXLAN FDB entries).
    pub fn vni(mut self, vni: u32) -> Self {
        self.vni = Some(vni);
        self
    }

    /// Set the master bridge device by name.
    pub fn master(mut self, master: impl Into<String>) -> Self {
        self.master = Some(InterfaceRef::Name(master.into()));
        self
    }

    /// Set the master bridge device by interface index (namespace-safe).
    pub fn master_ifindex(mut self, ifindex: u32) -> Self {
        self.master = Some(InterfaceRef::Index(ifindex));
        self
    }

    /// Get the master device reference.
    pub fn master_ref(&self) -> Option<&InterfaceRef> {
        self.master.as_ref()
    }

    /// Mark entry as permanent (static). This is the default.
    pub fn permanent(mut self) -> Self {
        self.permanent = true;
        self
    }

    /// Mark entry as dynamic (will age out).
    pub fn dynamic(mut self) -> Self {
        self.permanent = false;
        self
    }

    /// Add to interface's own FDB (sets NTF_SELF flag).
    ///
    /// This is typically used for entries on the bridge port itself
    /// rather than entries forwarded to the master bridge.
    pub fn self_(mut self) -> Self {
        self.self_flag = true;
        self
    }

    /// Write the add message to the builder with resolved interface indices.
    pub(crate) fn write_add(
        &self,
        builder: &mut MessageBuilder,
        ifindex: u32,
        master_idx: Option<u32>,
    ) {
        let state = if self.permanent {
            nud::PERMANENT
        } else {
            nud::REACHABLE
        };

        let mut ntf_flags: u8 = 0;
        if self.self_flag {
            ntf_flags |= ntf::SELF;
        }

        let ndmsg = NdMsg::new()
            .with_family(AF_BRIDGE)
            .with_ifindex(ifindex as i32)
            .with_state(state)
            .with_flags(ntf_flags);

        builder.append(&ndmsg);

        // NDA_LLADDR - MAC address (required)
        builder.append_attr(NdaAttr::Lladdr as u16, &self.mac);

        // NDA_MASTER - bridge interface
        if let Some(master) = master_idx {
            builder.append_attr_u32(NdaAttr::Master as u16, master);
        }

        // NDA_VLAN
        if let Some(vlan) = self.vlan {
            builder.append_attr_u16(NdaAttr::Vlan as u16, vlan);
        }

        // NDA_DST - remote IP for VXLAN
        if let Some(ref dst) = self.dst {
            match dst {
                IpAddr::V4(v4) => {
                    builder.append_attr(NdaAttr::Dst as u16, &v4.octets());
                }
                IpAddr::V6(v6) => {
                    builder.append_attr(NdaAttr::Dst as u16, &v6.octets());
                }
            }
        }

        // NDA_VNI
        if let Some(vni) = self.vni {
            builder.append_attr_u32(NdaAttr::Vni as u16, vni);
        }
    }

    /// Write the delete message to the builder with resolved interface index.
    pub(crate) fn write_delete(&self, builder: &mut MessageBuilder, ifindex: u32) {
        let ndmsg = NdMsg::new()
            .with_family(AF_BRIDGE)
            .with_ifindex(ifindex as i32);

        builder.append(&ndmsg);

        // NDA_LLADDR - MAC address (required for delete)
        builder.append_attr(NdaAttr::Lladdr as u16, &self.mac);

        // NDA_VLAN - needed if VLAN filtering is enabled
        if let Some(vlan) = self.vlan {
            builder.append_attr_u16(NdaAttr::Vlan as u16, vlan);
        }
    }
}

// ============================================================================
// Connection Methods
// ============================================================================

impl Connection<Route> {
    /// Get all FDB entries for a bridge.
    ///
    /// Returns entries where the master device matches the specified bridge,
    /// or entries directly on the bridge interface itself.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let entries = conn.get_fdb("br0").await?;
    /// for entry in &entries {
    ///     println!("{} on ifindex {} vlan={:?}",
    ///         entry.mac_str(), entry.ifindex, entry.vlan);
    /// }
    /// ```
    pub async fn get_fdb(&self, bridge: &str) -> Result<Vec<FdbEntry>> {
        let bridge_idx = self
            .resolve_interface(&InterfaceRef::Name(bridge.to_string()))
            .await?;
        self.get_fdb_by_index(bridge_idx).await
    }

    /// Get all FDB entries for a bridge by interface index.
    ///
    /// Use this method when operating in a network namespace to avoid
    /// reading `/sys/class/net/` from the wrong namespace.
    pub async fn get_fdb_by_index(&self, bridge_idx: u32) -> Result<Vec<FdbEntry>> {
        // Query neighbors with AF_BRIDGE family to get FDB entries
        let neighbors = self.get_bridge_neighbors().await?;

        Ok(neighbors
            .iter()
            .filter(|n| n.master() == Some(bridge_idx) || n.ifindex() == bridge_idx)
            .filter_map(FdbEntry::from_neighbor)
            .collect())
    }

    /// Get all bridge neighbor entries (AF_BRIDGE FDB dump).
    async fn get_bridge_neighbors(&self) -> Result<Vec<NeighborMessage>> {
        use super::message::NLMSG_HDRLEN;
        use super::parse::FromNetlink;

        let ndmsg = NdMsg::new().with_family(AF_BRIDGE);
        let mut builder = MessageBuilder::new(NlMsgType::RTM_GETNEIGH, NLM_F_REQUEST | NLM_F_DUMP);
        builder.append(&ndmsg);

        let responses = self.send_dump(builder).await?;

        let mut parsed = Vec::new();
        for response in responses {
            if response.len() < NLMSG_HDRLEN {
                continue;
            }
            let payload = &response[NLMSG_HDRLEN..];
            if let Ok(msg) = NeighborMessage::from_bytes(payload) {
                parsed.push(msg);
            }
        }
        Ok(parsed)
    }

    /// Get FDB entries for a specific bridge port.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let entries = conn.get_fdb_for_port("br0", "veth0").await?;
    /// ```
    pub async fn get_fdb_for_port(&self, bridge: &str, port: &str) -> Result<Vec<FdbEntry>> {
        let bridge_idx = self
            .resolve_interface(&InterfaceRef::Name(bridge.to_string()))
            .await?;
        let port_idx = self
            .resolve_interface(&InterfaceRef::Name(port.to_string()))
            .await?;

        let neighbors = self.get_bridge_neighbors().await?;

        Ok(neighbors
            .iter()
            .filter(|n| n.ifindex() == port_idx)
            .filter(|n| n.master() == Some(bridge_idx))
            .filter_map(FdbEntry::from_neighbor)
            .collect())
    }

    /// Resolve FDB entry interface references.
    async fn resolve_fdb_interfaces(&self, entry: &FdbEntryBuilder) -> Result<(u32, Option<u32>)> {
        let ifindex = match entry.device_ref() {
            Some(iface) => self.resolve_interface(iface).await?,
            None => {
                return Err(Error::InvalidMessage(
                    "device name or ifindex required".into(),
                ));
            }
        };

        let master_idx = match entry.master_ref() {
            Some(iface) => Some(self.resolve_interface(iface).await?),
            None => None,
        };

        Ok((ifindex, master_idx))
    }

    /// Add an FDB entry.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use nlink::netlink::fdb::FdbEntryBuilder;
    ///
    /// let mac = FdbEntryBuilder::parse_mac("aa:bb:cc:dd:ee:ff")?;
    /// conn.add_fdb(
    ///     FdbEntryBuilder::new(mac)
    ///         .dev("veth0")
    ///         .master("br0")
    ///         .vlan(100)
    /// ).await?;
    ///
    /// // Namespace-safe version using interface index
    /// conn.add_fdb(
    ///     FdbEntryBuilder::new(mac)
    ///         .ifindex(5)
    ///         .master_ifindex(3)
    /// ).await?;
    /// ```
    pub async fn add_fdb(&self, entry: FdbEntryBuilder) -> Result<()> {
        let (ifindex, master_idx) = self.resolve_fdb_interfaces(&entry).await?;
        let mut builder = MessageBuilder::new(
            NlMsgType::RTM_NEWNEIGH,
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
        );
        entry.write_add(&mut builder, ifindex, master_idx);
        self.send_ack(builder).await
    }

    /// Replace an FDB entry (add or update).
    ///
    /// If the entry exists, it will be updated. Otherwise, it will be created.
    pub async fn replace_fdb(&self, entry: FdbEntryBuilder) -> Result<()> {
        let (ifindex, master_idx) = self.resolve_fdb_interfaces(&entry).await?;
        let mut builder = MessageBuilder::new(
            NlMsgType::RTM_NEWNEIGH,
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE,
        );
        entry.write_add(&mut builder, ifindex, master_idx);
        self.send_ack(builder).await
    }

    /// Delete an FDB entry by device name, MAC address, and optional VLAN.
    ///
    /// # Example
    ///
    /// ```ignore
    /// // Delete entry without VLAN
    /// conn.del_fdb("veth0", [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff], None).await?;
    ///
    /// // Delete entry with specific VLAN
    /// conn.del_fdb("veth0", [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff], Some(100)).await?;
    /// ```
    pub async fn del_fdb(&self, dev: &str, mac: [u8; 6], vlan: Option<u16>) -> Result<()> {
        let ifindex = self
            .resolve_interface(&InterfaceRef::Name(dev.to_string()))
            .await?;
        self.del_fdb_by_index(ifindex, mac, vlan).await
    }

    /// Delete an FDB entry by interface index, MAC address, and optional VLAN.
    ///
    /// Use this method when operating in a network namespace.
    pub async fn del_fdb_by_index(
        &self,
        ifindex: u32,
        mac: [u8; 6],
        vlan: Option<u16>,
    ) -> Result<()> {
        let mut entry = FdbEntryBuilder::new(mac).ifindex(ifindex);
        if let Some(v) = vlan {
            entry = entry.vlan(v);
        }
        let mut builder = MessageBuilder::new(NlMsgType::RTM_DELNEIGH, NLM_F_REQUEST | NLM_F_ACK);
        entry.write_delete(&mut builder, ifindex);
        self.send_ack(builder).await
    }

    /// Flush all dynamic FDB entries for a bridge.
    ///
    /// Permanent (static) entries are not removed.
    ///
    /// # Example
    ///
    /// ```ignore
    /// conn.flush_fdb("br0").await?;
    /// ```
    pub async fn flush_fdb(&self, bridge: &str) -> Result<()> {
        let entries = self.get_fdb(bridge).await?;

        for entry in entries {
            // Only flush dynamic entries
            if entry.is_dynamic()
                && let Err(e) = self
                    .del_fdb_by_index(entry.ifindex, entry.mac, entry.vlan)
                    .await
            {
                // Ignore "not found" errors (race condition with aging)
                if !e.is_not_found() {
                    return Err(e);
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_mac() {
        let mac = FdbEntryBuilder::parse_mac("aa:bb:cc:dd:ee:ff").unwrap();
        assert_eq!(mac, [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
    }

    #[test]
    fn test_parse_mac_uppercase() {
        let mac = FdbEntryBuilder::parse_mac("AA:BB:CC:DD:EE:FF").unwrap();
        assert_eq!(mac, [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
    }

    #[test]
    fn test_parse_mac_invalid() {
        assert!(FdbEntryBuilder::parse_mac("invalid").is_err());
        assert!(FdbEntryBuilder::parse_mac("aa:bb:cc:dd:ee").is_err());
        assert!(FdbEntryBuilder::parse_mac("aa:bb:cc:dd:ee:ff:gg").is_err());
    }

    #[test]
    fn test_fdb_entry_mac_str() {
        let entry = FdbEntry {
            ifindex: 1,
            mac: [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            vlan: None,
            dst: None,
            vni: None,
            state: NeighborState::Permanent,
            flags: 0,
            master: None,
        };
        assert_eq!(entry.mac_str(), "00:11:22:33:44:55");
    }

    #[test]
    fn test_fdb_entry_flags() {
        let entry = FdbEntry {
            ifindex: 1,
            mac: [0; 6],
            vlan: None,
            dst: None,
            vni: None,
            state: NeighborState::Permanent,
            flags: ntf::SELF | ntf::MASTER,
            master: None,
        };
        assert!(entry.is_self());
        assert!(entry.is_master());
        assert!(!entry.is_extern_learn());
    }

    #[test]
    fn test_fdb_entry_permanent() {
        let permanent = FdbEntry {
            ifindex: 1,
            mac: [0; 6],
            vlan: None,
            dst: None,
            vni: None,
            state: NeighborState::Permanent,
            flags: 0,
            master: None,
        };
        assert!(permanent.is_permanent());
        assert!(!permanent.is_dynamic());

        let dynamic = FdbEntry {
            ifindex: 1,
            mac: [0; 6],
            vlan: None,
            dst: None,
            vni: None,
            state: NeighborState::Reachable,
            flags: 0,
            master: None,
        };
        assert!(!dynamic.is_permanent());
        assert!(dynamic.is_dynamic());
    }

    #[test]
    fn test_builder_default() {
        let builder = FdbEntryBuilder::new([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        assert!(builder.permanent); // default is permanent
        assert!(!builder.self_flag);
    }

    #[test]
    fn test_builder_chain() {
        let builder = FdbEntryBuilder::new([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff])
            .dev("veth0")
            .master("br0")
            .vlan(100)
            .dynamic()
            .self_();

        assert_eq!(builder.dev, Some(InterfaceRef::Name("veth0".to_string())));
        assert_eq!(builder.master, Some(InterfaceRef::Name("br0".to_string())));
        assert_eq!(builder.vlan, Some(100));
        assert!(!builder.permanent);
        assert!(builder.self_flag);
    }

    #[test]
    fn test_builder_ifindex() {
        let builder = FdbEntryBuilder::new([0; 6]).ifindex(5).master_ifindex(3);

        assert_eq!(builder.dev, Some(InterfaceRef::Index(5)));
        assert_eq!(builder.master, Some(InterfaceRef::Index(3)));
    }
}
