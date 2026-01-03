//! Strongly-typed routing rule message.

use std::net::IpAddr;

use winnow::binary::le_u16;
use winnow::prelude::*;
use winnow::token::take;
use zerocopy::FromBytes;

use crate::netlink::parse::{FromNetlink, PResult, parse_ip_addr};
use crate::netlink::types::rule::{FibRuleAction, FibRuleHdr, FibRulePortRange, FibRuleUidRange};

/// Attribute IDs for FRA_* constants.
mod attr_ids {
    pub const FRA_DST: u16 = 1;
    pub const FRA_SRC: u16 = 2;
    pub const FRA_IIFNAME: u16 = 3;
    pub const FRA_GOTO: u16 = 4;
    pub const FRA_PRIORITY: u16 = 6;
    pub const FRA_FWMARK: u16 = 10;
    pub const FRA_FLOW: u16 = 11;
    pub const FRA_TUN_ID: u16 = 12;
    pub const FRA_SUPPRESS_IFGROUP: u16 = 13;
    pub const FRA_SUPPRESS_PREFIXLEN: u16 = 14;
    pub const FRA_TABLE: u16 = 15;
    pub const FRA_FWMASK: u16 = 16;
    pub const FRA_OIFNAME: u16 = 17;
    pub const FRA_L3MDEV: u16 = 19;
    pub const FRA_UID_RANGE: u16 = 20;
    pub const FRA_PROTOCOL: u16 = 21;
    pub const FRA_IP_PROTO: u16 = 22;
    pub const FRA_SPORT_RANGE: u16 = 23;
    pub const FRA_DPORT_RANGE: u16 = 24;
}

/// Strongly-typed routing rule message with all attributes parsed.
#[derive(Debug, Clone, Default)]
pub struct RuleMessage {
    /// Fixed-size header.
    pub header: FibRuleHdr,
    /// Rule priority (FRA_PRIORITY).
    pub priority: u32,
    /// Source address (FRA_SRC).
    pub source: Option<IpAddr>,
    /// Destination address (FRA_DST).
    pub destination: Option<IpAddr>,
    /// Input interface name (FRA_IIFNAME).
    pub iifname: Option<String>,
    /// Output interface name (FRA_OIFNAME).
    pub oifname: Option<String>,
    /// Firewall mark (FRA_FWMARK).
    pub fwmark: Option<u32>,
    /// Firewall mark mask (FRA_FWMASK).
    pub fwmask: Option<u32>,
    /// Routing table ID (FRA_TABLE, overrides header.table).
    pub table: u32,
    /// Goto target rule priority (FRA_GOTO).
    pub goto: Option<u32>,
    /// Flow classification ID (FRA_FLOW).
    pub flow: Option<u32>,
    /// Tunnel ID (FRA_TUN_ID).
    pub tun_id: Option<u64>,
    /// Suppress interface group (FRA_SUPPRESS_IFGROUP).
    pub suppress_ifgroup: Option<u32>,
    /// Suppress prefix length (FRA_SUPPRESS_PREFIXLEN).
    pub suppress_prefixlen: Option<u32>,
    /// L3 master device (FRA_L3MDEV).
    pub l3mdev: Option<u8>,
    /// UID range (FRA_UID_RANGE).
    pub uid_range: Option<FibRuleUidRange>,
    /// Rule protocol (FRA_PROTOCOL).
    pub protocol: Option<u8>,
    /// IP protocol for port matching (FRA_IP_PROTO).
    pub ip_proto: Option<u8>,
    /// Source port range (FRA_SPORT_RANGE).
    pub sport_range: Option<FibRulePortRange>,
    /// Destination port range (FRA_DPORT_RANGE).
    pub dport_range: Option<FibRulePortRange>,
}

impl RuleMessage {
    /// Create a new empty rule message.
    pub fn new() -> Self {
        Self::default()
    }

    /// Get the address family.
    pub fn family(&self) -> u8 {
        self.header.family
    }

    /// Check if this is an IPv4 rule.
    pub fn is_ipv4(&self) -> bool {
        self.header.family == libc::AF_INET as u8
    }

    /// Check if this is an IPv6 rule.
    pub fn is_ipv6(&self) -> bool {
        self.header.family == libc::AF_INET6 as u8
    }

    /// Get the source prefix length.
    pub fn src_len(&self) -> u8 {
        self.header.src_len
    }

    /// Get the destination prefix length.
    pub fn dst_len(&self) -> u8 {
        self.header.dst_len
    }

    /// Get the rule action.
    pub fn action(&self) -> FibRuleAction {
        FibRuleAction::from(self.header.action)
    }

    /// Check if this is a table lookup rule.
    pub fn is_lookup(&self) -> bool {
        self.action() == FibRuleAction::ToTbl
    }

    /// Check if this is a blackhole rule.
    pub fn is_blackhole(&self) -> bool {
        self.action() == FibRuleAction::Blackhole
    }

    /// Check if this is an unreachable rule.
    pub fn is_unreachable(&self) -> bool {
        self.action() == FibRuleAction::Unreachable
    }

    /// Check if this is a prohibit rule.
    pub fn is_prohibit(&self) -> bool {
        self.action() == FibRuleAction::Prohibit
    }

    /// Get the routing table ID.
    pub fn table_id(&self) -> u32 {
        self.table
    }

    /// Check if this is a default rule (priority 0, 32766, or 32767).
    pub fn is_default(&self) -> bool {
        self.priority == 0 || self.priority == 32766 || self.priority == 32767
    }
}

impl FromNetlink for RuleMessage {
    fn write_dump_header(buf: &mut Vec<u8>) {
        // RTM_GETRULE requires a FibRuleHdr header
        let header = FibRuleHdr::new();
        buf.extend_from_slice(header.as_bytes());
    }

    fn parse(input: &mut &[u8]) -> PResult<Self> {
        // Parse the fixed header
        let header_bytes: &[u8] = take(FibRuleHdr::SIZE).parse_next(input)?;
        let header = *FibRuleHdr::ref_from_bytes(header_bytes)
            .map_err(|_| winnow::error::ErrMode::Cut(winnow::error::ContextError::new()))?;

        let mut msg = RuleMessage {
            table: header.table as u32,
            header,
            ..Default::default()
        };

        // Parse attributes
        while input.len() >= 4 {
            let attr_len: u16 = le_u16.parse_next(input)?;
            let attr_type: u16 = le_u16.parse_next(input)?;

            if attr_len < 4 {
                break;
            }

            let data_len = (attr_len as usize).saturating_sub(4);
            if input.len() < data_len {
                break;
            }

            let attr_data: &[u8] = take(data_len).parse_next(input)?;

            // Skip to alignment
            let padding = (4 - (attr_len as usize % 4)) % 4;
            if input.len() >= padding {
                let _ = take(padding).parse_next(input)?;
            }

            // Mask off NLA_F_NESTED and other flags
            let attr_type_masked = attr_type & 0x7fff;

            match attr_type_masked {
                attr_ids::FRA_PRIORITY => {
                    if attr_data.len() >= 4 {
                        msg.priority = u32::from_ne_bytes(attr_data[..4].try_into().unwrap());
                    }
                }
                attr_ids::FRA_SRC => {
                    if let Ok(addr) = parse_ip_addr(attr_data, msg.header.family) {
                        msg.source = Some(addr);
                    }
                }
                attr_ids::FRA_DST => {
                    if let Ok(addr) = parse_ip_addr(attr_data, msg.header.family) {
                        msg.destination = Some(addr);
                    }
                }
                attr_ids::FRA_IIFNAME => {
                    msg.iifname = parse_string(attr_data);
                }
                attr_ids::FRA_OIFNAME => {
                    msg.oifname = parse_string(attr_data);
                }
                attr_ids::FRA_FWMARK => {
                    if attr_data.len() >= 4 {
                        msg.fwmark = Some(u32::from_ne_bytes(attr_data[..4].try_into().unwrap()));
                    }
                }
                attr_ids::FRA_FWMASK => {
                    if attr_data.len() >= 4 {
                        msg.fwmask = Some(u32::from_ne_bytes(attr_data[..4].try_into().unwrap()));
                    }
                }
                attr_ids::FRA_TABLE => {
                    if attr_data.len() >= 4 {
                        msg.table = u32::from_ne_bytes(attr_data[..4].try_into().unwrap());
                    }
                }
                attr_ids::FRA_GOTO => {
                    if attr_data.len() >= 4 {
                        msg.goto = Some(u32::from_ne_bytes(attr_data[..4].try_into().unwrap()));
                    }
                }
                attr_ids::FRA_FLOW => {
                    if attr_data.len() >= 4 {
                        msg.flow = Some(u32::from_ne_bytes(attr_data[..4].try_into().unwrap()));
                    }
                }
                attr_ids::FRA_TUN_ID => {
                    if attr_data.len() >= 8 {
                        msg.tun_id = Some(u64::from_be_bytes(attr_data[..8].try_into().unwrap()));
                    }
                }
                attr_ids::FRA_SUPPRESS_IFGROUP => {
                    if attr_data.len() >= 4 {
                        msg.suppress_ifgroup =
                            Some(u32::from_ne_bytes(attr_data[..4].try_into().unwrap()));
                    }
                }
                attr_ids::FRA_SUPPRESS_PREFIXLEN => {
                    if attr_data.len() >= 4 {
                        msg.suppress_prefixlen =
                            Some(u32::from_ne_bytes(attr_data[..4].try_into().unwrap()));
                    }
                }
                attr_ids::FRA_L3MDEV => {
                    if !attr_data.is_empty() {
                        msg.l3mdev = Some(attr_data[0]);
                    }
                }
                attr_ids::FRA_UID_RANGE => {
                    if let Some(range) = FibRuleUidRange::from_bytes(attr_data) {
                        msg.uid_range = Some(*range);
                    }
                }
                attr_ids::FRA_PROTOCOL => {
                    if !attr_data.is_empty() {
                        msg.protocol = Some(attr_data[0]);
                    }
                }
                attr_ids::FRA_IP_PROTO => {
                    if !attr_data.is_empty() {
                        msg.ip_proto = Some(attr_data[0]);
                    }
                }
                attr_ids::FRA_SPORT_RANGE => {
                    if let Some(range) = FibRulePortRange::from_bytes(attr_data) {
                        msg.sport_range = Some(*range);
                    }
                }
                attr_ids::FRA_DPORT_RANGE => {
                    if let Some(range) = FibRulePortRange::from_bytes(attr_data) {
                        msg.dport_range = Some(*range);
                    }
                }
                _ => {}
            }
        }

        Ok(msg)
    }
}

/// Parse a null-terminated string from attribute data.
fn parse_string(data: &[u8]) -> Option<String> {
    // Find null terminator
    let end = data.iter().position(|&b| b == 0).unwrap_or(data.len());
    std::str::from_utf8(&data[..end]).ok().map(String::from)
}
