//! TC filter builders and configuration.
//!
//! This module provides strongly-typed configuration for TC filters including
//! u32, flower, matchall, and bpf filters.
//!
//! # Example
//!
//! ```ignore
//! use nlink::netlink::{Connection, Protocol};
//! use nlink::netlink::filter::{U32Filter, FlowerFilter, MatchallFilter};
//! use std::net::Ipv4Addr;
//!
//! let conn = Connection::new(Protocol::Route)?;
//!
//! // Add a u32 filter to match destination port 80
//! let filter = U32Filter::new()
//!     .classid("1:10")
//!     .match_dst_port(80)
//!     .build();
//! conn.add_filter("eth0", "1:", filter).await?;
//!
//! // Add a flower filter to match TCP traffic to 10.0.0.0/8
//! let filter = FlowerFilter::new()
//!     .classid("1:20")
//!     .ip_proto_tcp()
//!     .dst_ipv4(Ipv4Addr::new(10, 0, 0, 0), 8)
//!     .build();
//! conn.add_filter("eth0", "1:", filter).await?;
//!
//! // Add a matchall filter with an action
//! let filter = MatchallFilter::new()
//!     .classid("1:30")
//!     .build();
//! conn.add_filter("eth0", "1:", filter).await?;
//! ```

use std::net::{Ipv4Addr, Ipv6Addr};

use super::Connection;
use super::builder::MessageBuilder;
use super::connection::create_request;
use super::error::{Error, Result};
use super::message::NlMsgType;
use super::types::tc::filter::{basic, bpf, flower, fw, matchall, u32 as u32_mod};
use super::types::tc::{TcMsg, TcaAttr, tc_handle};

// ============================================================================
// FilterConfig trait
// ============================================================================

/// Trait for filter configurations that can be applied.
pub trait FilterConfig: Send + Sync {
    /// Get the filter kind (e.g., "u32", "flower", "matchall").
    fn kind(&self) -> &'static str;

    /// Write the filter options to a message builder.
    fn write_options(&self, builder: &mut MessageBuilder) -> Result<()>;

    /// Get the classid if set.
    fn classid(&self) -> Option<u32>;
}

// ============================================================================
// U32Filter
// ============================================================================

/// U32 filter configuration.
///
/// The u32 filter is a versatile classifier that matches packets based on
/// arbitrary fields in the packet header using a set of keys (value/mask pairs).
///
/// # Example
///
/// ```ignore
/// use nlink::netlink::filter::U32Filter;
///
/// // Match destination port 80 (HTTP)
/// let filter = U32Filter::new()
///     .classid("1:10")
///     .match_dst_port(80)
///     .build();
///
/// // Match source IP 192.168.1.0/24
/// let filter = U32Filter::new()
///     .classid("1:20")
///     .match_src_ipv4("192.168.1.0".parse().unwrap(), 24)
///     .build();
/// ```
#[derive(Debug, Clone, Default)]
pub struct U32Filter {
    /// Target class ID.
    classid: Option<u32>,
    /// Selector keys.
    keys: Vec<u32_mod::TcU32Key>,
    /// Hash table link.
    link: Option<u32>,
    /// Hash divisor (for creating hash tables).
    divisor: Option<u32>,
    /// Match mark value/mask.
    mark: Option<(u32, u32)>,
    /// Priority.
    priority: u16,
    /// Protocol (default: ETH_P_IP).
    protocol: u16,
}

impl U32Filter {
    /// Create a new u32 filter builder.
    pub fn new() -> Self {
        Self {
            protocol: 0x0800, // ETH_P_IP
            priority: 0,
            ..Default::default()
        }
    }

    /// Set the target class ID (e.g., "1:10").
    pub fn classid(mut self, classid: &str) -> Self {
        self.classid = tc_handle::parse(classid);
        self
    }

    /// Set the target class ID from raw value.
    pub fn classid_raw(mut self, classid: u32) -> Self {
        self.classid = Some(classid);
        self
    }

    /// Set the priority (lower = higher priority).
    pub fn priority(mut self, prio: u16) -> Self {
        self.priority = prio;
        self
    }

    /// Set the protocol (default: ETH_P_IP = 0x0800).
    pub fn protocol(mut self, proto: u16) -> Self {
        self.protocol = proto;
        self
    }

    /// Add a raw 32-bit key.
    pub fn add_key(mut self, val: u32, mask: u32, off: i32) -> Self {
        self.keys.push(u32_mod::pack_key32(val, mask, off));
        self
    }

    /// Match source IPv4 address with prefix length.
    pub fn match_src_ipv4(mut self, addr: Ipv4Addr, prefix_len: u8) -> Self {
        let mask = if prefix_len >= 32 {
            0xFFFFFFFF
        } else {
            !((1u32 << (32 - prefix_len)) - 1)
        };
        let val = u32::from_be_bytes(addr.octets());
        // IP source address is at offset 12 in IP header
        self.keys.push(u32_mod::pack_key32(val, mask, 12));
        self
    }

    /// Match destination IPv4 address with prefix length.
    pub fn match_dst_ipv4(mut self, addr: Ipv4Addr, prefix_len: u8) -> Self {
        let mask = if prefix_len >= 32 {
            0xFFFFFFFF
        } else {
            !((1u32 << (32 - prefix_len)) - 1)
        };
        let val = u32::from_be_bytes(addr.octets());
        // IP destination address is at offset 16 in IP header
        self.keys.push(u32_mod::pack_key32(val, mask, 16));
        self
    }

    /// Match IP protocol (e.g., 6 for TCP, 17 for UDP).
    pub fn match_ip_proto(mut self, proto: u8) -> Self {
        // IP protocol is at offset 9, single byte
        self.keys.push(u32_mod::pack_key8(proto, 0xFF, 9));
        self
    }

    /// Match source port (requires nexthdr offset).
    pub fn match_src_port(mut self, port: u16) -> Self {
        // Source port is at nexthdr+0
        let key = u32_mod::TcU32Key::with_nexthdr((port as u32) << 16, 0xFFFF0000, 0);
        self.keys.push(key);
        self
    }

    /// Match destination port (requires nexthdr offset).
    pub fn match_dst_port(mut self, port: u16) -> Self {
        // Destination port is at nexthdr+2
        let key = u32_mod::TcU32Key::with_nexthdr(port as u32, 0x0000FFFF, 0);
        self.keys.push(key);
        self
    }

    /// Match IP TOS/DSCP field.
    pub fn match_tos(mut self, tos: u8, mask: u8) -> Self {
        // TOS is at offset 1
        self.keys.push(u32_mod::pack_key8(tos, mask, 1));
        self
    }

    /// Set hash table divisor (for creating a hash table).
    pub fn divisor(mut self, div: u32) -> Self {
        self.divisor = Some(div);
        self
    }

    /// Link to a hash table.
    pub fn link(mut self, link: u32) -> Self {
        self.link = Some(link);
        self
    }

    /// Match firewall mark.
    pub fn match_mark(mut self, val: u32, mask: u32) -> Self {
        self.mark = Some((val, mask));
        self
    }

    /// Build the filter configuration.
    pub fn build(self) -> Self {
        self
    }
}

impl FilterConfig for U32Filter {
    fn kind(&self) -> &'static str {
        "u32"
    }

    fn classid(&self) -> Option<u32> {
        self.classid
    }

    fn write_options(&self, builder: &mut MessageBuilder) -> Result<()> {
        // Add classid if set
        if let Some(classid) = self.classid {
            builder.append_attr_u32(u32_mod::TCA_U32_CLASSID, classid);
        }

        // Add divisor if creating hash table
        if let Some(div) = self.divisor {
            builder.append_attr_u32(u32_mod::TCA_U32_DIVISOR, div);
        }

        // Add link if set
        if let Some(link) = self.link {
            builder.append_attr_u32(u32_mod::TCA_U32_LINK, link);
        }

        // Add mark if set
        if let Some((val, mask)) = self.mark {
            let mark = u32_mod::TcU32Mark::new(val, mask);
            builder.append_attr(u32_mod::TCA_U32_MARK, mark.as_bytes());
        }

        // Build and add selector if we have keys
        if !self.keys.is_empty() {
            let mut sel = u32_mod::TcU32Sel::new();
            sel.set_terminal();
            for key in &self.keys {
                sel.add_key(*key);
            }
            builder.append_attr(u32_mod::TCA_U32_SEL, &sel.to_bytes());
        }

        Ok(())
    }
}

// ============================================================================
// FlowerFilter
// ============================================================================

/// Flower filter configuration.
///
/// The flower filter provides a more user-friendly way to match packets
/// based on various header fields including L2/L3/L4 headers.
///
/// # Example
///
/// ```ignore
/// use nlink::netlink::filter::FlowerFilter;
/// use std::net::Ipv4Addr;
///
/// // Match TCP traffic to 10.0.0.0/8 on port 80
/// let filter = FlowerFilter::new()
///     .classid("1:10")
///     .ip_proto_tcp()
///     .dst_ipv4(Ipv4Addr::new(10, 0, 0, 0), 8)
///     .dst_port(80)
///     .build();
/// ```
#[derive(Debug, Clone, Default)]
pub struct FlowerFilter {
    /// Target class ID.
    classid: Option<u32>,
    /// Ethernet type (e.g., 0x0800 for IPv4).
    eth_type: Option<u16>,
    /// IP protocol.
    ip_proto: Option<u8>,
    /// Source IPv4 address and prefix length.
    src_ipv4: Option<(Ipv4Addr, u8)>,
    /// Destination IPv4 address and prefix length.
    dst_ipv4: Option<(Ipv4Addr, u8)>,
    /// Source IPv6 address and prefix length.
    src_ipv6: Option<(Ipv6Addr, u8)>,
    /// Destination IPv6 address and prefix length.
    dst_ipv6: Option<(Ipv6Addr, u8)>,
    /// Source port.
    src_port: Option<u16>,
    /// Destination port.
    dst_port: Option<u16>,
    /// Source MAC address.
    src_mac: Option<[u8; 6]>,
    /// Destination MAC address.
    dst_mac: Option<[u8; 6]>,
    /// VLAN ID.
    vlan_id: Option<u16>,
    /// VLAN priority.
    vlan_prio: Option<u8>,
    /// IP TOS.
    ip_tos: Option<(u8, u8)>,
    /// IP TTL.
    ip_ttl: Option<(u8, u8)>,
    /// TCP flags.
    tcp_flags: Option<(u16, u16)>,
    /// Filter flags (skip_hw, skip_sw, etc.).
    flags: u32,
    /// Priority.
    priority: u16,
    /// Protocol (default: ETH_P_ALL).
    protocol: u16,
}

impl FlowerFilter {
    /// Create a new flower filter builder.
    pub fn new() -> Self {
        Self {
            protocol: 0x0003, // ETH_P_ALL
            ..Default::default()
        }
    }

    /// Set the target class ID (e.g., "1:10").
    pub fn classid(mut self, classid: &str) -> Self {
        self.classid = tc_handle::parse(classid);
        self
    }

    /// Set the target class ID from raw value.
    pub fn classid_raw(mut self, classid: u32) -> Self {
        self.classid = Some(classid);
        self
    }

    /// Set the priority.
    pub fn priority(mut self, prio: u16) -> Self {
        self.priority = prio;
        self
    }

    /// Set the protocol.
    pub fn protocol(mut self, proto: u16) -> Self {
        self.protocol = proto;
        self
    }

    /// Match IPv4 packets.
    pub fn ipv4(mut self) -> Self {
        self.eth_type = Some(0x0800);
        self
    }

    /// Match IPv6 packets.
    pub fn ipv6(mut self) -> Self {
        self.eth_type = Some(0x86DD);
        self
    }

    /// Match ARP packets.
    pub fn arp(mut self) -> Self {
        self.eth_type = Some(0x0806);
        self
    }

    /// Set IP protocol.
    pub fn ip_proto(mut self, proto: u8) -> Self {
        self.ip_proto = Some(proto);
        self
    }

    /// Match TCP packets.
    pub fn ip_proto_tcp(mut self) -> Self {
        self.ip_proto = Some(flower::IPPROTO_TCP);
        self
    }

    /// Match UDP packets.
    pub fn ip_proto_udp(mut self) -> Self {
        self.ip_proto = Some(flower::IPPROTO_UDP);
        self
    }

    /// Match ICMP packets.
    pub fn ip_proto_icmp(mut self) -> Self {
        self.ip_proto = Some(flower::IPPROTO_ICMP);
        self
    }

    /// Match ICMPv6 packets.
    pub fn ip_proto_icmpv6(mut self) -> Self {
        self.ip_proto = Some(flower::IPPROTO_ICMPV6);
        self
    }

    /// Match source IPv4 address with prefix length.
    pub fn src_ipv4(mut self, addr: Ipv4Addr, prefix_len: u8) -> Self {
        if self.eth_type.is_none() {
            self.eth_type = Some(0x0800);
        }
        self.src_ipv4 = Some((addr, prefix_len));
        self
    }

    /// Match destination IPv4 address with prefix length.
    pub fn dst_ipv4(mut self, addr: Ipv4Addr, prefix_len: u8) -> Self {
        if self.eth_type.is_none() {
            self.eth_type = Some(0x0800);
        }
        self.dst_ipv4 = Some((addr, prefix_len));
        self
    }

    /// Match source IPv6 address with prefix length.
    pub fn src_ipv6(mut self, addr: Ipv6Addr, prefix_len: u8) -> Self {
        if self.eth_type.is_none() {
            self.eth_type = Some(0x86DD);
        }
        self.src_ipv6 = Some((addr, prefix_len));
        self
    }

    /// Match destination IPv6 address with prefix length.
    pub fn dst_ipv6(mut self, addr: Ipv6Addr, prefix_len: u8) -> Self {
        if self.eth_type.is_none() {
            self.eth_type = Some(0x86DD);
        }
        self.dst_ipv6 = Some((addr, prefix_len));
        self
    }

    /// Match source port.
    pub fn src_port(mut self, port: u16) -> Self {
        self.src_port = Some(port);
        self
    }

    /// Match destination port.
    pub fn dst_port(mut self, port: u16) -> Self {
        self.dst_port = Some(port);
        self
    }

    /// Match source MAC address.
    pub fn src_mac(mut self, mac: [u8; 6]) -> Self {
        self.src_mac = Some(mac);
        self
    }

    /// Match destination MAC address.
    pub fn dst_mac(mut self, mac: [u8; 6]) -> Self {
        self.dst_mac = Some(mac);
        self
    }

    /// Match VLAN ID.
    pub fn vlan_id(mut self, id: u16) -> Self {
        self.vlan_id = Some(id);
        self
    }

    /// Match VLAN priority.
    pub fn vlan_prio(mut self, prio: u8) -> Self {
        self.vlan_prio = Some(prio);
        self
    }

    /// Match IP TOS with mask.
    pub fn ip_tos(mut self, tos: u8, mask: u8) -> Self {
        self.ip_tos = Some((tos, mask));
        self
    }

    /// Match IP TTL with mask.
    pub fn ip_ttl(mut self, ttl: u8, mask: u8) -> Self {
        self.ip_ttl = Some((ttl, mask));
        self
    }

    /// Match TCP flags with mask.
    pub fn tcp_flags(mut self, flags: u16, mask: u16) -> Self {
        self.tcp_flags = Some((flags, mask));
        self
    }

    /// Skip hardware offload.
    pub fn skip_hw(mut self) -> Self {
        self.flags |= flower::TCA_CLS_FLAGS_SKIP_HW;
        self
    }

    /// Skip software processing.
    pub fn skip_sw(mut self) -> Self {
        self.flags |= flower::TCA_CLS_FLAGS_SKIP_SW;
        self
    }

    /// Build the filter configuration.
    pub fn build(self) -> Self {
        self
    }
}

/// Helper to create an IPv4 mask from prefix length.
fn ipv4_mask(prefix_len: u8) -> Ipv4Addr {
    if prefix_len >= 32 {
        Ipv4Addr::new(255, 255, 255, 255)
    } else if prefix_len == 0 {
        Ipv4Addr::new(0, 0, 0, 0)
    } else {
        let mask = !((1u32 << (32 - prefix_len)) - 1);
        Ipv4Addr::from(mask.to_be_bytes())
    }
}

/// Helper to create an IPv6 mask from prefix length.
fn ipv6_mask(prefix_len: u8) -> Ipv6Addr {
    if prefix_len >= 128 {
        Ipv6Addr::from([0xFFu8; 16])
    } else if prefix_len == 0 {
        Ipv6Addr::from([0u8; 16])
    } else {
        let mut bytes = [0u8; 16];
        let full_bytes = (prefix_len / 8) as usize;
        let remaining_bits = prefix_len % 8;

        for byte in bytes.iter_mut().take(full_bytes) {
            *byte = 0xFF;
        }
        if full_bytes < 16 && remaining_bits > 0 {
            bytes[full_bytes] = !((1u8 << (8 - remaining_bits)) - 1);
        }
        Ipv6Addr::from(bytes)
    }
}

impl FilterConfig for FlowerFilter {
    fn kind(&self) -> &'static str {
        "flower"
    }

    fn classid(&self) -> Option<u32> {
        self.classid
    }

    fn write_options(&self, builder: &mut MessageBuilder) -> Result<()> {
        // Add classid
        if let Some(classid) = self.classid {
            builder.append_attr_u32(flower::TCA_FLOWER_CLASSID, classid);
        }

        // Add flags
        if self.flags != 0 {
            builder.append_attr_u32(flower::TCA_FLOWER_FLAGS, self.flags);
        }

        // Add ethernet type
        if let Some(eth_type) = self.eth_type {
            builder.append_attr(flower::TCA_FLOWER_KEY_ETH_TYPE, &eth_type.to_be_bytes());
        }

        // Add IP protocol
        if let Some(proto) = self.ip_proto {
            builder.append_attr(flower::TCA_FLOWER_KEY_IP_PROTO, &[proto]);
        }

        // Add source IPv4
        if let Some((addr, prefix_len)) = self.src_ipv4 {
            builder.append_attr(flower::TCA_FLOWER_KEY_IPV4_SRC, &addr.octets());
            let mask = ipv4_mask(prefix_len);
            builder.append_attr(flower::TCA_FLOWER_KEY_IPV4_SRC_MASK, &mask.octets());
        }

        // Add destination IPv4
        if let Some((addr, prefix_len)) = self.dst_ipv4 {
            builder.append_attr(flower::TCA_FLOWER_KEY_IPV4_DST, &addr.octets());
            let mask = ipv4_mask(prefix_len);
            builder.append_attr(flower::TCA_FLOWER_KEY_IPV4_DST_MASK, &mask.octets());
        }

        // Add source IPv6
        if let Some((addr, prefix_len)) = self.src_ipv6 {
            builder.append_attr(flower::TCA_FLOWER_KEY_IPV6_SRC, &addr.octets());
            let mask = ipv6_mask(prefix_len);
            builder.append_attr(flower::TCA_FLOWER_KEY_IPV6_SRC_MASK, &mask.octets());
        }

        // Add destination IPv6
        if let Some((addr, prefix_len)) = self.dst_ipv6 {
            builder.append_attr(flower::TCA_FLOWER_KEY_IPV6_DST, &addr.octets());
            let mask = ipv6_mask(prefix_len);
            builder.append_attr(flower::TCA_FLOWER_KEY_IPV6_DST_MASK, &mask.octets());
        }

        // Add ports
        if let Some(port) = self.src_port {
            if self.ip_proto == Some(flower::IPPROTO_TCP) {
                builder.append_attr(flower::TCA_FLOWER_KEY_TCP_SRC, &port.to_be_bytes());
            } else if self.ip_proto == Some(flower::IPPROTO_UDP) {
                builder.append_attr(flower::TCA_FLOWER_KEY_UDP_SRC, &port.to_be_bytes());
            }
        }

        if let Some(port) = self.dst_port {
            if self.ip_proto == Some(flower::IPPROTO_TCP) {
                builder.append_attr(flower::TCA_FLOWER_KEY_TCP_DST, &port.to_be_bytes());
            } else if self.ip_proto == Some(flower::IPPROTO_UDP) {
                builder.append_attr(flower::TCA_FLOWER_KEY_UDP_DST, &port.to_be_bytes());
            }
        }

        // Add MAC addresses
        if let Some(mac) = self.src_mac {
            builder.append_attr(flower::TCA_FLOWER_KEY_ETH_SRC, &mac);
            builder.append_attr(flower::TCA_FLOWER_KEY_ETH_SRC_MASK, &[0xFF; 6]);
        }

        if let Some(mac) = self.dst_mac {
            builder.append_attr(flower::TCA_FLOWER_KEY_ETH_DST, &mac);
            builder.append_attr(flower::TCA_FLOWER_KEY_ETH_DST_MASK, &[0xFF; 6]);
        }

        // Add VLAN
        if let Some(id) = self.vlan_id {
            builder.append_attr(flower::TCA_FLOWER_KEY_VLAN_ID, &id.to_ne_bytes());
        }

        if let Some(prio) = self.vlan_prio {
            builder.append_attr(flower::TCA_FLOWER_KEY_VLAN_PRIO, &[prio]);
        }

        // Add IP TOS
        if let Some((tos, mask)) = self.ip_tos {
            builder.append_attr(flower::TCA_FLOWER_KEY_IP_TOS, &[tos]);
            builder.append_attr(flower::TCA_FLOWER_KEY_IP_TOS_MASK, &[mask]);
        }

        // Add IP TTL
        if let Some((ttl, mask)) = self.ip_ttl {
            builder.append_attr(flower::TCA_FLOWER_KEY_IP_TTL, &[ttl]);
            builder.append_attr(flower::TCA_FLOWER_KEY_IP_TTL_MASK, &[mask]);
        }

        // Add TCP flags
        if let Some((flags, mask)) = self.tcp_flags {
            builder.append_attr(flower::TCA_FLOWER_KEY_TCP_FLAGS, &flags.to_be_bytes());
            builder.append_attr(flower::TCA_FLOWER_KEY_TCP_FLAGS_MASK, &mask.to_be_bytes());
        }

        Ok(())
    }
}

// ============================================================================
// MatchallFilter
// ============================================================================

/// Matchall filter configuration.
///
/// The matchall filter matches all packets and is typically used with actions.
///
/// # Example
///
/// ```ignore
/// use nlink::netlink::filter::MatchallFilter;
///
/// let filter = MatchallFilter::new()
///     .classid("1:10")
///     .build();
/// ```
#[derive(Debug, Clone, Default)]
pub struct MatchallFilter {
    /// Target class ID.
    classid: Option<u32>,
    /// Filter flags.
    flags: u32,
    /// Priority.
    priority: u16,
    /// Protocol.
    protocol: u16,
}

impl MatchallFilter {
    /// Create a new matchall filter builder.
    pub fn new() -> Self {
        Self {
            protocol: 0x0003, // ETH_P_ALL
            ..Default::default()
        }
    }

    /// Set the target class ID.
    pub fn classid(mut self, classid: &str) -> Self {
        self.classid = tc_handle::parse(classid);
        self
    }

    /// Set the target class ID from raw value.
    pub fn classid_raw(mut self, classid: u32) -> Self {
        self.classid = Some(classid);
        self
    }

    /// Set the priority.
    pub fn priority(mut self, prio: u16) -> Self {
        self.priority = prio;
        self
    }

    /// Set the protocol.
    pub fn protocol(mut self, proto: u16) -> Self {
        self.protocol = proto;
        self
    }

    /// Skip hardware offload.
    pub fn skip_hw(mut self) -> Self {
        self.flags |= flower::TCA_CLS_FLAGS_SKIP_HW;
        self
    }

    /// Skip software processing.
    pub fn skip_sw(mut self) -> Self {
        self.flags |= flower::TCA_CLS_FLAGS_SKIP_SW;
        self
    }

    /// Build the filter configuration.
    pub fn build(self) -> Self {
        self
    }
}

impl FilterConfig for MatchallFilter {
    fn kind(&self) -> &'static str {
        "matchall"
    }

    fn classid(&self) -> Option<u32> {
        self.classid
    }

    fn write_options(&self, builder: &mut MessageBuilder) -> Result<()> {
        if let Some(classid) = self.classid {
            builder.append_attr_u32(matchall::TCA_MATCHALL_CLASSID, classid);
        }

        if self.flags != 0 {
            builder.append_attr_u32(matchall::TCA_MATCHALL_FLAGS, self.flags);
        }

        Ok(())
    }
}

// ============================================================================
// FwFilter
// ============================================================================

/// Firewall mark (fw) filter configuration.
///
/// The fw filter matches packets based on the firewall mark (fwmark) set by iptables.
///
/// # Example
///
/// ```ignore
/// use nlink::netlink::filter::FwFilter;
///
/// // Match packets with fwmark 10
/// let filter = FwFilter::new(10)
///     .classid("1:10")
///     .build();
/// ```
#[derive(Debug, Clone)]
pub struct FwFilter {
    /// Mask for the mark.
    mask: u32,
    /// Target class ID.
    classid: Option<u32>,
}

impl FwFilter {
    /// Create a new fw filter builder.
    ///
    /// Note: The firewall mark is specified as the filter handle when calling
    /// `add_filter_full()`. Use handle format like "10" for fwmark 10.
    pub fn new() -> Self {
        Self {
            mask: 0xFFFFFFFF,
            classid: None,
        }
    }

    /// Set the mask for the mark.
    pub fn mask(mut self, mask: u32) -> Self {
        self.mask = mask;
        self
    }

    /// Set the target class ID.
    pub fn classid(mut self, classid: &str) -> Self {
        self.classid = tc_handle::parse(classid);
        self
    }

    /// Set the target class ID from raw value.
    pub fn classid_raw(mut self, classid: u32) -> Self {
        self.classid = Some(classid);
        self
    }

    /// Build the filter configuration.
    pub fn build(self) -> Self {
        self
    }
}

impl Default for FwFilter {
    fn default() -> Self {
        Self::new()
    }
}

impl FilterConfig for FwFilter {
    fn kind(&self) -> &'static str {
        "fw"
    }

    fn classid(&self) -> Option<u32> {
        self.classid
    }

    fn write_options(&self, builder: &mut MessageBuilder) -> Result<()> {
        if let Some(classid) = self.classid {
            builder.append_attr_u32(fw::TCA_FW_CLASSID, classid);
        }

        if self.mask != 0xFFFFFFFF {
            builder.append_attr_u32(fw::TCA_FW_MASK, self.mask);
        }

        Ok(())
    }
}

// ============================================================================
// BpfFilter
// ============================================================================

/// BPF filter configuration.
///
/// The BPF filter allows using eBPF programs for packet classification.
///
/// # Example
///
/// ```ignore
/// use nlink::netlink::filter::BpfFilter;
/// use std::os::fd::RawFd;
///
/// // Attach a BPF program by file descriptor
/// let filter = BpfFilter::new(bpf_fd)
///     .name("my_classifier")
///     .direct_action()
///     .build();
/// ```
#[derive(Debug, Clone)]
pub struct BpfFilter {
    /// BPF program file descriptor.
    fd: i32,
    /// Program name.
    name: Option<String>,
    /// Use direct action mode.
    direct_action: bool,
    /// Target class ID (for non-direct-action mode).
    classid: Option<u32>,
    /// Priority.
    priority: u16,
    /// Protocol.
    protocol: u16,
}

impl BpfFilter {
    /// Create a new BPF filter with the given program file descriptor.
    pub fn new(fd: i32) -> Self {
        Self {
            fd,
            name: None,
            direct_action: false,
            classid: None,
            priority: 0,
            protocol: 0x0003, // ETH_P_ALL
        }
    }

    /// Set the program name.
    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Enable direct action mode.
    ///
    /// In direct action mode, the BPF program returns the action directly
    /// (TC_ACT_OK, TC_ACT_SHOT, etc.) instead of a classid.
    pub fn direct_action(mut self) -> Self {
        self.direct_action = true;
        self
    }

    /// Set the target class ID (for non-direct-action mode).
    pub fn classid(mut self, classid: &str) -> Self {
        self.classid = tc_handle::parse(classid);
        self
    }

    /// Set the priority.
    pub fn priority(mut self, prio: u16) -> Self {
        self.priority = prio;
        self
    }

    /// Set the protocol.
    pub fn protocol(mut self, proto: u16) -> Self {
        self.protocol = proto;
        self
    }

    /// Build the filter configuration.
    pub fn build(self) -> Self {
        self
    }
}

impl FilterConfig for BpfFilter {
    fn kind(&self) -> &'static str {
        "bpf"
    }

    fn classid(&self) -> Option<u32> {
        self.classid
    }

    fn write_options(&self, builder: &mut MessageBuilder) -> Result<()> {
        // Add file descriptor
        builder.append_attr_u32(bpf::TCA_BPF_FD, self.fd as u32);

        // Add name if set
        if let Some(ref name) = self.name {
            builder.append_attr_str(bpf::TCA_BPF_NAME, name);
        }

        // Add flags
        let mut flags = 0u32;
        if self.direct_action {
            flags |= bpf::TCA_BPF_FLAG_ACT_DIRECT;
        }
        if flags != 0 {
            builder.append_attr_u32(bpf::TCA_BPF_FLAGS, flags);
        }

        // Add classid if not using direct action
        if let Some(classid) = self.classid {
            builder.append_attr_u32(bpf::TCA_BPF_CLASSID, classid);
        }

        Ok(())
    }
}

// ============================================================================
// BasicFilter
// ============================================================================

/// Basic filter configuration.
///
/// The basic filter is a simple classifier that can use ematch expressions.
///
/// # Example
///
/// ```ignore
/// use nlink::netlink::filter::BasicFilter;
///
/// let filter = BasicFilter::new()
///     .classid("1:10")
///     .build();
/// ```
#[derive(Debug, Clone, Default)]
pub struct BasicFilter {
    /// Target class ID.
    classid: Option<u32>,
    /// Priority.
    priority: u16,
    /// Protocol.
    protocol: u16,
}

impl BasicFilter {
    /// Create a new basic filter builder.
    pub fn new() -> Self {
        Self {
            protocol: 0x0003, // ETH_P_ALL
            ..Default::default()
        }
    }

    /// Set the target class ID.
    pub fn classid(mut self, classid: &str) -> Self {
        self.classid = tc_handle::parse(classid);
        self
    }

    /// Set the target class ID from raw value.
    pub fn classid_raw(mut self, classid: u32) -> Self {
        self.classid = Some(classid);
        self
    }

    /// Set the priority.
    pub fn priority(mut self, prio: u16) -> Self {
        self.priority = prio;
        self
    }

    /// Set the protocol.
    pub fn protocol(mut self, proto: u16) -> Self {
        self.protocol = proto;
        self
    }

    /// Build the filter configuration.
    pub fn build(self) -> Self {
        self
    }
}

impl FilterConfig for BasicFilter {
    fn kind(&self) -> &'static str {
        "basic"
    }

    fn classid(&self) -> Option<u32> {
        self.classid
    }

    fn write_options(&self, builder: &mut MessageBuilder) -> Result<()> {
        if let Some(classid) = self.classid {
            builder.append_attr_u32(basic::TCA_BASIC_CLASSID, classid);
        }
        Ok(())
    }
}

// ============================================================================
// Helper functions
// ============================================================================

/// Convert interface name to index.
fn get_ifindex(name: &str) -> Result<i32> {
    let path = format!("/sys/class/net/{}/ifindex", name);
    let content = std::fs::read_to_string(&path)
        .map_err(|_| Error::InvalidMessage(format!("interface not found: {}", name)))?;
    content
        .trim()
        .parse()
        .map_err(|_| Error::InvalidMessage(format!("invalid ifindex for: {}", name)))
}

/// Parse a handle string like "1:0" or "root".
fn parse_handle(s: &str) -> Result<u32> {
    tc_handle::parse(s).ok_or_else(|| Error::InvalidMessage(format!("invalid handle: {}", s)))
}

// ============================================================================
// Connection extension methods for filters
// ============================================================================

impl Connection {
    /// Add a filter to an interface.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use nlink::netlink::filter::FlowerFilter;
    ///
    /// let filter = FlowerFilter::new()
    ///     .classid("1:10")
    ///     .ip_proto_tcp()
    ///     .dst_port(80)
    ///     .build();
    ///
    /// conn.add_filter("eth0", "1:", filter).await?;
    /// ```
    pub async fn add_filter(
        &self,
        dev: &str,
        parent: &str,
        config: impl FilterConfig,
    ) -> Result<()> {
        self.add_filter_full(dev, parent, None, 0x0800, 0, config)
            .await
    }

    /// Add a filter with explicit parameters.
    ///
    /// # Arguments
    /// * `dev` - Interface name
    /// * `parent` - Parent qdisc handle (e.g., "1:")
    /// * `handle` - Filter handle (optional)
    /// * `protocol` - Ethernet protocol (e.g., 0x0800 for IPv4)
    /// * `priority` - Filter priority (lower = higher priority)
    /// * `config` - Filter configuration
    pub async fn add_filter_full(
        &self,
        dev: &str,
        parent: &str,
        handle: Option<&str>,
        protocol: u16,
        priority: u16,
        config: impl FilterConfig,
    ) -> Result<()> {
        let ifindex = get_ifindex(dev)?;
        self.add_filter_by_index_full(ifindex, parent, handle, protocol, priority, config)
            .await
    }

    /// Add a filter by interface index.
    pub async fn add_filter_by_index(
        &self,
        ifindex: i32,
        parent: &str,
        config: impl FilterConfig,
    ) -> Result<()> {
        self.add_filter_by_index_full(ifindex, parent, None, 0x0800, 0, config)
            .await
    }

    /// Add a filter by interface index with explicit parameters.
    pub async fn add_filter_by_index_full(
        &self,
        ifindex: i32,
        parent: &str,
        handle: Option<&str>,
        protocol: u16,
        priority: u16,
        config: impl FilterConfig,
    ) -> Result<()> {
        let parent_handle = parse_handle(parent)?;
        let filter_handle = handle.map(parse_handle).transpose()?.unwrap_or(0);

        // tcm_info = (protocol << 16) | priority
        let info = ((protocol as u32) << 16) | (priority as u32);

        let tcmsg = TcMsg::new()
            .with_ifindex(ifindex)
            .with_parent(parent_handle)
            .with_handle(filter_handle)
            .with_info(info);

        let mut builder = create_request(NlMsgType::RTM_NEWTFILTER);
        builder.append(&tcmsg);

        builder.append_attr_str(TcaAttr::Kind as u16, config.kind());

        let options_token = builder.nest_start(TcaAttr::Options as u16);
        config.write_options(&mut builder)?;
        builder.nest_end(options_token);

        self.request_ack(builder).await
    }

    /// Delete a filter from an interface.
    ///
    /// # Example
    ///
    /// ```ignore
    /// conn.del_filter("eth0", "1:", 0x0800, 100).await?;
    /// ```
    pub async fn del_filter(
        &self,
        dev: &str,
        parent: &str,
        protocol: u16,
        priority: u16,
    ) -> Result<()> {
        let ifindex = get_ifindex(dev)?;
        self.del_filter_by_index(ifindex, parent, protocol, priority)
            .await
    }

    /// Delete a filter by interface index.
    pub async fn del_filter_by_index(
        &self,
        ifindex: i32,
        parent: &str,
        protocol: u16,
        priority: u16,
    ) -> Result<()> {
        let parent_handle = parse_handle(parent)?;
        let info = ((protocol as u32) << 16) | (priority as u32);

        let tcmsg = TcMsg::new()
            .with_ifindex(ifindex)
            .with_parent(parent_handle)
            .with_info(info);

        let mut builder = create_request(NlMsgType::RTM_DELTFILTER);
        builder.append(&tcmsg);

        self.request_ack(builder).await
    }

    /// Delete all filters from a parent qdisc.
    pub async fn flush_filters(&self, dev: &str, parent: &str) -> Result<()> {
        let ifindex = get_ifindex(dev)?;
        self.flush_filters_by_index(ifindex, parent).await
    }

    /// Delete all filters from a parent qdisc by interface index.
    pub async fn flush_filters_by_index(&self, ifindex: i32, parent: &str) -> Result<()> {
        // Get all filters
        let filters = self.get_filters().await?;
        let parent_handle = parse_handle(parent)?;

        // Delete each filter that matches the parent and interface
        for filter in filters {
            if filter.ifindex() == ifindex && filter.parent() == parent_handle {
                let protocol = filter.protocol();
                let priority = filter.priority();
                if let Err(e) = self
                    .del_filter_by_index(ifindex, parent, protocol, priority)
                    .await
                {
                    // Ignore not found errors
                    if !e.is_not_found() {
                        return Err(e);
                    }
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
    fn test_u32_filter_builder() {
        let filter = U32Filter::new()
            .classid("1:10")
            .match_dst_ipv4(Ipv4Addr::new(192, 168, 1, 0), 24)
            .priority(100)
            .build();

        assert_eq!(filter.classid, Some(tc_handle::make(1, 0x10)));
        assert_eq!(filter.priority, 100);
        assert_eq!(filter.keys.len(), 1);
    }

    #[test]
    fn test_flower_filter_builder() {
        let filter = FlowerFilter::new()
            .classid("1:20")
            .ip_proto_tcp()
            .dst_ipv4(Ipv4Addr::new(10, 0, 0, 0), 8)
            .dst_port(80)
            .build();

        assert_eq!(filter.classid, Some(tc_handle::make(1, 0x20)));
        assert_eq!(filter.ip_proto, Some(flower::IPPROTO_TCP));
        assert_eq!(filter.dst_ipv4, Some((Ipv4Addr::new(10, 0, 0, 0), 8)));
        assert_eq!(filter.dst_port, Some(80));
        assert_eq!(filter.eth_type, Some(0x0800));
    }

    #[test]
    fn test_matchall_filter_builder() {
        let filter = MatchallFilter::new().classid("1:30").skip_hw().build();

        assert_eq!(filter.classid, Some(tc_handle::make(1, 0x30)));
        assert!(filter.flags & flower::TCA_CLS_FLAGS_SKIP_HW != 0);
    }

    #[test]
    fn test_fw_filter_builder() {
        let filter = FwFilter::new(10).classid("1:10").mask(0xFF).build();

        assert_eq!(filter.mark, 10);
        assert_eq!(filter.mask, 0xFF);
        assert_eq!(filter.classid, Some(tc_handle::make(1, 0x10)));
    }

    #[test]
    fn test_ipv4_mask() {
        assert_eq!(ipv4_mask(32), Ipv4Addr::new(255, 255, 255, 255));
        assert_eq!(ipv4_mask(24), Ipv4Addr::new(255, 255, 255, 0));
        assert_eq!(ipv4_mask(16), Ipv4Addr::new(255, 255, 0, 0));
        assert_eq!(ipv4_mask(8), Ipv4Addr::new(255, 0, 0, 0));
        assert_eq!(ipv4_mask(0), Ipv4Addr::new(0, 0, 0, 0));
    }

    #[test]
    fn test_ipv6_mask() {
        let full = ipv6_mask(128);
        assert_eq!(full.octets(), [0xFF; 16]);

        let zero = ipv6_mask(0);
        assert_eq!(zero.octets(), [0; 16]);

        let half = ipv6_mask(64);
        assert_eq!(
            half.octets(),
            [
                0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0, 0, 0, 0, 0, 0, 0, 0
            ]
        );
    }
}
