//! Bridge VLAN filtering configuration.
//!
//! This module provides API for managing per-port VLAN configuration on Linux
//! bridges with VLAN filtering enabled. It allows assigning VLANs to bridge
//! ports, setting PVID (Port VLAN ID), and configuring tagged/untagged modes.
//!
//! # Example
//!
//! ```ignore
//! use nlink::netlink::{Connection, Route};
//! use nlink::netlink::bridge_vlan::BridgeVlanBuilder;
//!
//! let conn = Connection::<Route>::new()?;
//!
//! // Add VLAN 100 as PVID and untagged (native VLAN)
//! conn.add_bridge_vlan(
//!     BridgeVlanBuilder::new(100)
//!         .dev("eth0")
//!         .pvid()
//!         .untagged()
//! ).await?;
//!
//! // Add VLANs 200-210 as tagged
//! conn.add_bridge_vlan(
//!     BridgeVlanBuilder::new(200)
//!         .dev("eth0")
//!         .range(210)
//! ).await?;
//!
//! // Query VLANs
//! let vlans = conn.get_bridge_vlans("eth0").await?;
//! for vlan in &vlans {
//!     println!("VLAN {}: pvid={} untagged={}",
//!         vlan.vid, vlan.flags.pvid, vlan.flags.untagged);
//! }
//!
//! // Delete VLAN
//! conn.del_bridge_vlan("eth0", 100).await?;
//! ```

use super::attr::AttrIter;
use super::builder::MessageBuilder;
use super::connection::Connection;
use super::error::{Error, Result};
use super::message::{MessageIter, NLM_F_ACK, NLM_F_DUMP, NLM_F_REQUEST, NlMsgType};
use super::protocol::Route;
use super::types::link::{
    BridgeVlanInfo, IfInfoMsg, IflaAttr, bridge_af, bridge_vlan_flags, rtext_filter,
};

/// VLAN flags for bridge port configuration.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BridgeVlanFlags {
    /// This is the PVID (Port VLAN ID) - untagged ingress default
    pub pvid: bool,
    /// Egress untagged - remove VLAN tag on egress
    pub untagged: bool,
}

impl BridgeVlanFlags {
    /// Create from raw kernel flags.
    pub fn from_raw(flags: u16) -> Self {
        Self {
            pvid: flags & bridge_vlan_flags::PVID != 0,
            untagged: flags & bridge_vlan_flags::UNTAGGED != 0,
        }
    }
}

/// Bridge VLAN entry information.
#[derive(Debug, Clone)]
pub struct BridgeVlanEntry {
    /// Interface index (bridge port or bridge itself)
    pub ifindex: u32,
    /// VLAN ID (1-4094)
    pub vid: u16,
    /// VLAN flags
    pub flags: BridgeVlanFlags,
}

impl BridgeVlanEntry {
    /// Check if this is the PVID for this port.
    pub fn is_pvid(&self) -> bool {
        self.flags.pvid
    }

    /// Check if egress is untagged.
    pub fn is_untagged(&self) -> bool {
        self.flags.untagged
    }
}

/// Builder for bridge VLAN operations.
///
/// # Example
///
/// ```ignore
/// use nlink::netlink::bridge_vlan::BridgeVlanBuilder;
///
/// // Add VLAN 100 as PVID and untagged
/// let config = BridgeVlanBuilder::new(100)
///     .dev("eth0")
///     .pvid()
///     .untagged();
///
/// // Add VLAN range 200-210 as tagged
/// let range_config = BridgeVlanBuilder::new(200)
///     .dev("eth0")
///     .range(210);
/// ```
#[derive(Debug, Clone, Default)]
pub struct BridgeVlanBuilder {
    dev: Option<String>,
    ifindex: Option<u32>,
    vid: u16,
    vid_end: Option<u16>,
    pvid: bool,
    untagged: bool,
    master: bool,
}

impl BridgeVlanBuilder {
    /// Create a new VLAN builder for a single VID.
    ///
    /// VID must be in range 1-4094.
    pub fn new(vid: u16) -> Self {
        Self {
            vid,
            ..Default::default()
        }
    }

    /// Set device name.
    pub fn dev(mut self, dev: impl Into<String>) -> Self {
        self.dev = Some(dev.into());
        self
    }

    /// Set interface index directly.
    ///
    /// Use this instead of `dev()` when operating in a network namespace
    /// to avoid reading `/sys/class/net/` from the wrong namespace.
    pub fn ifindex(mut self, ifindex: u32) -> Self {
        self.ifindex = Some(ifindex);
        self
    }

    /// Set VLAN range end (for bulk operations).
    ///
    /// When set, VLANs from `vid` to `vid_end` (inclusive) will be added/deleted.
    pub fn range(mut self, vid_end: u16) -> Self {
        self.vid_end = Some(vid_end);
        self
    }

    /// Mark as PVID (ingress untagged default).
    ///
    /// Untagged frames arriving on this port will be assigned this VLAN.
    /// Only one VLAN per port can be the PVID.
    pub fn pvid(mut self) -> Self {
        self.pvid = true;
        self
    }

    /// Mark as untagged (strip tag on egress).
    ///
    /// Frames with this VLAN leaving this port will have their tag removed.
    pub fn untagged(mut self) -> Self {
        self.untagged = true;
        self
    }

    /// Apply to bridge device itself (global VLAN entry).
    ///
    /// This creates a global VLAN entry on the bridge rather than a port-specific one.
    pub fn master(mut self) -> Self {
        self.master = true;
        self
    }

    /// Resolve interface name to index.
    fn resolve_ifindex(&self) -> Result<i32> {
        if let Some(idx) = self.ifindex {
            Ok(idx as i32)
        } else if let Some(ref dev) = self.dev {
            crate::util::get_ifindex(dev)
                .map(|idx| idx as i32)
                .map_err(Error::InvalidMessage)
        } else {
            Err(Error::InvalidMessage(
                "device name or ifindex required".into(),
            ))
        }
    }

    /// Build the raw flags value.
    fn build_flags(&self) -> u16 {
        let mut flags = 0u16;
        if self.pvid {
            flags |= bridge_vlan_flags::PVID;
        }
        if self.untagged {
            flags |= bridge_vlan_flags::UNTAGGED;
        }
        if self.master {
            flags |= bridge_vlan_flags::MASTER;
        }
        flags
    }

    /// Build netlink message for adding VLAN.
    pub(crate) fn build_add(&self) -> Result<MessageBuilder> {
        self.build_message(NlMsgType::RTM_SETLINK)
    }

    /// Build netlink message for deleting VLAN.
    pub(crate) fn build_del(&self) -> Result<MessageBuilder> {
        self.build_message(NlMsgType::RTM_DELLINK)
    }

    fn build_message(&self, msg_type: u16) -> Result<MessageBuilder> {
        let ifindex = self.resolve_ifindex()?;

        let mut builder = MessageBuilder::new(msg_type, NLM_F_REQUEST | NLM_F_ACK);

        // Use AF_BRIDGE family
        let ifinfo = IfInfoMsg::new()
            .with_family(libc::AF_BRIDGE as u8)
            .with_index(ifindex);
        builder.append(&ifinfo);

        // IFLA_AF_SPEC containing VLAN info
        let af_spec = builder.nest_start(IflaAttr::AfSpec as u16);

        if let Some(vid_end) = self.vid_end {
            // Range operation: two entries with RANGE_BEGIN and RANGE_END flags
            let mut begin_flags = self.build_flags();
            begin_flags |= bridge_vlan_flags::RANGE_BEGIN;

            let vlan_begin = BridgeVlanInfo::new(self.vid).with_flags(begin_flags);
            builder.append_attr(bridge_af::IFLA_BRIDGE_VLAN_INFO, vlan_begin.as_bytes());

            let mut end_flags = self.build_flags();
            end_flags |= bridge_vlan_flags::RANGE_END;

            let vlan_end = BridgeVlanInfo::new(vid_end).with_flags(end_flags);
            builder.append_attr(bridge_af::IFLA_BRIDGE_VLAN_INFO, vlan_end.as_bytes());
        } else {
            // Single VLAN
            let flags = self.build_flags();
            let vlan_info = BridgeVlanInfo::new(self.vid).with_flags(flags);
            builder.append_attr(bridge_af::IFLA_BRIDGE_VLAN_INFO, vlan_info.as_bytes());
        }

        builder.nest_end(af_spec);

        Ok(builder)
    }
}

// ============================================================================
// Connection Methods
// ============================================================================

impl Connection<Route> {
    /// Get VLAN configuration for a bridge port.
    ///
    /// Returns all VLANs configured on the specified interface.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let vlans = conn.get_bridge_vlans("eth0").await?;
    /// for vlan in &vlans {
    ///     println!("VLAN {}: pvid={} untagged={}",
    ///         vlan.vid, vlan.flags.pvid, vlan.flags.untagged);
    /// }
    /// ```
    pub async fn get_bridge_vlans(&self, dev: &str) -> Result<Vec<BridgeVlanEntry>> {
        let ifindex = crate::util::get_ifindex(dev).map_err(Error::InvalidMessage)? as u32;
        self.get_bridge_vlans_by_index(ifindex).await
    }

    /// Get VLAN configuration for a bridge port by interface index.
    ///
    /// Use this method when operating in a network namespace.
    pub async fn get_bridge_vlans_by_index(&self, ifindex: u32) -> Result<Vec<BridgeVlanEntry>> {
        // Request link with BRVLAN filter
        let mut builder = MessageBuilder::new(NlMsgType::RTM_GETLINK, NLM_F_REQUEST);

        let ifinfo = IfInfoMsg::new()
            .with_family(libc::AF_BRIDGE as u8)
            .with_index(ifindex as i32);
        builder.append(&ifinfo);
        builder.append_attr_u32(IflaAttr::ExtMask as u16, rtext_filter::BRVLAN);

        let response = self.send_request(builder).await?;
        parse_vlan_entries(&response, ifindex)
    }

    /// Get VLAN configuration for all ports of a bridge.
    ///
    /// Returns VLANs for all interfaces that are part of the bridge.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let vlans = conn.get_bridge_vlans_all("br0").await?;
    /// for vlan in &vlans {
    ///     println!("ifindex {}: VLAN {}", vlan.ifindex, vlan.vid);
    /// }
    /// ```
    pub async fn get_bridge_vlans_all(&self, bridge: &str) -> Result<Vec<BridgeVlanEntry>> {
        let bridge_idx = crate::util::get_ifindex(bridge).map_err(Error::InvalidMessage)? as u32;
        self.get_bridge_vlans_all_by_index(bridge_idx).await
    }

    /// Get VLAN configuration for all ports of a bridge by interface index.
    pub async fn get_bridge_vlans_all_by_index(
        &self,
        bridge_idx: u32,
    ) -> Result<Vec<BridgeVlanEntry>> {
        // Dump all links with BRVLAN filter
        let mut builder = MessageBuilder::new(NlMsgType::RTM_GETLINK, NLM_F_REQUEST | NLM_F_DUMP);

        let ifinfo = IfInfoMsg::new().with_family(libc::AF_BRIDGE as u8);
        builder.append(&ifinfo);
        builder.append_attr_u32(IflaAttr::ExtMask as u16, rtext_filter::BRVLAN);

        let responses = self.send_dump(builder).await?;

        let mut entries = Vec::new();
        for response in responses {
            // Parse each response for VLAN entries
            if let Ok(msg_entries) = parse_vlan_entries_from_dump(&response) {
                // Filter to ports that belong to this bridge
                for entry in msg_entries {
                    // Include if it's the bridge itself or has master == bridge_idx
                    if entry.ifindex == bridge_idx {
                        entries.push(entry);
                    }
                    // Note: We'd need to check IFLA_MASTER to filter properly,
                    // but for now include all entries from the dump
                }
            }
        }

        // Re-fetch with proper filtering by checking masters
        let links = self.get_links().await?;
        let port_indices: Vec<u32> = links
            .iter()
            .filter(|l| l.master == Some(bridge_idx))
            .map(|l| l.ifindex())
            .collect();

        // Include bridge itself and its ports
        let mut filtered = Vec::new();
        for entry in entries {
            if entry.ifindex == bridge_idx || port_indices.contains(&entry.ifindex) {
                filtered.push(entry);
            }
        }

        Ok(filtered)
    }

    /// Add VLAN to a bridge port.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use nlink::netlink::bridge_vlan::BridgeVlanBuilder;
    ///
    /// // Add VLAN 100 as PVID and untagged (native VLAN)
    /// conn.add_bridge_vlan(
    ///     BridgeVlanBuilder::new(100)
    ///         .dev("eth0")
    ///         .pvid()
    ///         .untagged()
    /// ).await?;
    ///
    /// // Add VLAN range 200-210 as tagged
    /// conn.add_bridge_vlan(
    ///     BridgeVlanBuilder::new(200)
    ///         .dev("eth0")
    ///         .range(210)
    /// ).await?;
    /// ```
    pub async fn add_bridge_vlan(&self, config: BridgeVlanBuilder) -> Result<()> {
        let builder = config.build_add()?;
        self.send_ack(builder).await
    }

    /// Delete VLAN from a bridge port.
    ///
    /// # Example
    ///
    /// ```ignore
    /// conn.del_bridge_vlan("eth0", 100).await?;
    /// ```
    pub async fn del_bridge_vlan(&self, dev: &str, vid: u16) -> Result<()> {
        let builder = BridgeVlanBuilder::new(vid).dev(dev).build_del()?;
        self.send_ack(builder).await
    }

    /// Delete VLAN from a bridge port by interface index.
    pub async fn del_bridge_vlan_by_index(&self, ifindex: u32, vid: u16) -> Result<()> {
        let builder = BridgeVlanBuilder::new(vid).ifindex(ifindex).build_del()?;
        self.send_ack(builder).await
    }

    /// Delete a range of VLANs from a bridge port.
    ///
    /// # Example
    ///
    /// ```ignore
    /// conn.del_bridge_vlan_range("eth0", 200, 210).await?;
    /// ```
    pub async fn del_bridge_vlan_range(
        &self,
        dev: &str,
        vid_start: u16,
        vid_end: u16,
    ) -> Result<()> {
        let builder = BridgeVlanBuilder::new(vid_start)
            .dev(dev)
            .range(vid_end)
            .build_del()?;
        self.send_ack(builder).await
    }

    /// Set PVID for a bridge port.
    ///
    /// This adds the VLAN as PVID and untagged, which is the typical
    /// configuration for a native VLAN.
    ///
    /// # Example
    ///
    /// ```ignore
    /// conn.set_bridge_pvid("eth0", 100).await?;
    /// ```
    pub async fn set_bridge_pvid(&self, dev: &str, vid: u16) -> Result<()> {
        self.add_bridge_vlan(BridgeVlanBuilder::new(vid).dev(dev).pvid().untagged())
            .await
    }

    /// Set PVID for a bridge port by interface index.
    pub async fn set_bridge_pvid_by_index(&self, ifindex: u32, vid: u16) -> Result<()> {
        self.add_bridge_vlan(
            BridgeVlanBuilder::new(vid)
                .ifindex(ifindex)
                .pvid()
                .untagged(),
        )
        .await
    }

    /// Add a tagged VLAN to a bridge port.
    ///
    /// This is a convenience method for adding a VLAN without PVID or untagged flags.
    ///
    /// # Example
    ///
    /// ```ignore
    /// conn.add_bridge_vlan_tagged("eth0", 200).await?;
    /// ```
    pub async fn add_bridge_vlan_tagged(&self, dev: &str, vid: u16) -> Result<()> {
        self.add_bridge_vlan(BridgeVlanBuilder::new(vid).dev(dev))
            .await
    }

    /// Add a range of tagged VLANs to a bridge port.
    ///
    /// # Example
    ///
    /// ```ignore
    /// conn.add_bridge_vlan_range("eth0", 200, 210).await?;
    /// ```
    pub async fn add_bridge_vlan_range(
        &self,
        dev: &str,
        vid_start: u16,
        vid_end: u16,
    ) -> Result<()> {
        self.add_bridge_vlan(BridgeVlanBuilder::new(vid_start).dev(dev).range(vid_end))
            .await
    }
}

// ============================================================================
// Parsing Helpers
// ============================================================================

/// Parse VLAN entries from a single netlink response.
fn parse_vlan_entries(data: &[u8], ifindex: u32) -> Result<Vec<BridgeVlanEntry>> {
    let mut entries = Vec::new();

    // Skip ifinfomsg header
    if data.len() < IfInfoMsg::SIZE {
        return Ok(entries);
    }
    let attrs_data = &data[IfInfoMsg::SIZE..];

    // Look for IFLA_AF_SPEC
    for (attr_type, payload) in AttrIter::new(attrs_data) {
        if attr_type == IflaAttr::AfSpec as u16 {
            // Parse nested attributes inside AF_SPEC
            parse_af_spec_vlans(payload, ifindex, &mut entries);
        }
    }

    Ok(entries)
}

/// Parse VLAN entries from a dump response (may contain multiple messages).
fn parse_vlan_entries_from_dump(data: &[u8]) -> Result<Vec<BridgeVlanEntry>> {
    let mut entries = Vec::new();

    for msg_result in MessageIter::new(data) {
        let (_header, payload) = match msg_result {
            Ok(msg) => msg,
            Err(_) => continue,
        };

        // Skip if too short for ifinfomsg
        if payload.len() < IfInfoMsg::SIZE {
            continue;
        }

        // Parse ifinfomsg to get ifindex
        if let Ok(ifinfo) = IfInfoMsg::from_bytes(payload) {
            let ifindex = ifinfo.ifi_index as u32;
            let attrs_data = &payload[IfInfoMsg::SIZE..];

            // Look for IFLA_AF_SPEC
            for (attr_type, attr_payload) in AttrIter::new(attrs_data) {
                if attr_type == IflaAttr::AfSpec as u16 {
                    parse_af_spec_vlans(attr_payload, ifindex, &mut entries);
                }
            }
        }
    }

    Ok(entries)
}

/// Parse VLAN info from IFLA_AF_SPEC payload.
fn parse_af_spec_vlans(data: &[u8], ifindex: u32, entries: &mut Vec<BridgeVlanEntry>) {
    let mut range_start: Option<(u16, u16)> = None; // (vid, flags)

    for (attr_type, payload) in AttrIter::new(data) {
        if attr_type == bridge_af::IFLA_BRIDGE_VLAN_INFO
            && let Some(vlan_info) = BridgeVlanInfo::from_bytes(payload)
        {
            let flags = BridgeVlanFlags::from_raw(vlan_info.flags);

            if vlan_info.is_range_begin() {
                // Start of range - remember it
                range_start = Some((vlan_info.vid, vlan_info.flags));
            } else if vlan_info.is_range_end() {
                // End of range - emit all VLANs in range
                if let Some((start_vid, start_flags)) = range_start.take() {
                    let range_flags = BridgeVlanFlags::from_raw(start_flags);
                    for vid in start_vid..=vlan_info.vid {
                        entries.push(BridgeVlanEntry {
                            ifindex,
                            vid,
                            flags: range_flags,
                        });
                    }
                }
            } else {
                // Single VLAN entry
                entries.push(BridgeVlanEntry {
                    ifindex,
                    vid: vlan_info.vid,
                    flags,
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bridge_vlan_flags_from_raw() {
        let flags =
            BridgeVlanFlags::from_raw(bridge_vlan_flags::PVID | bridge_vlan_flags::UNTAGGED);
        assert!(flags.pvid);
        assert!(flags.untagged);

        let flags = BridgeVlanFlags::from_raw(0);
        assert!(!flags.pvid);
        assert!(!flags.untagged);

        let flags = BridgeVlanFlags::from_raw(bridge_vlan_flags::PVID);
        assert!(flags.pvid);
        assert!(!flags.untagged);
    }

    #[test]
    fn test_bridge_vlan_entry_helpers() {
        let entry = BridgeVlanEntry {
            ifindex: 1,
            vid: 100,
            flags: BridgeVlanFlags {
                pvid: true,
                untagged: true,
            },
        };
        assert!(entry.is_pvid());
        assert!(entry.is_untagged());

        let entry = BridgeVlanEntry {
            ifindex: 1,
            vid: 200,
            flags: BridgeVlanFlags::default(),
        };
        assert!(!entry.is_pvid());
        assert!(!entry.is_untagged());
    }

    #[test]
    fn test_builder_default() {
        let builder = BridgeVlanBuilder::new(100);
        assert_eq!(builder.vid, 100);
        assert!(!builder.pvid);
        assert!(!builder.untagged);
        assert!(!builder.master);
        assert!(builder.vid_end.is_none());
    }

    #[test]
    fn test_builder_chain() {
        let builder = BridgeVlanBuilder::new(100)
            .dev("eth0")
            .pvid()
            .untagged()
            .master();

        assert_eq!(builder.dev, Some("eth0".to_string()));
        assert!(builder.pvid);
        assert!(builder.untagged);
        assert!(builder.master);
    }

    #[test]
    fn test_builder_range() {
        let builder = BridgeVlanBuilder::new(100).dev("eth0").range(110);

        assert_eq!(builder.vid, 100);
        assert_eq!(builder.vid_end, Some(110));
    }

    #[test]
    fn test_builder_ifindex() {
        let builder = BridgeVlanBuilder::new(100).ifindex(5);
        assert_eq!(builder.ifindex, Some(5));
    }

    #[test]
    fn test_build_flags() {
        let builder = BridgeVlanBuilder::new(100).pvid().untagged();
        let flags = builder.build_flags();
        assert_eq!(flags, bridge_vlan_flags::PVID | bridge_vlan_flags::UNTAGGED);

        let builder = BridgeVlanBuilder::new(100).master();
        let flags = builder.build_flags();
        assert_eq!(flags, bridge_vlan_flags::MASTER);
    }
}
