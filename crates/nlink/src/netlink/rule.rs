//! Routing rule management.
//!
//! This module provides a builder for creating and deleting routing rules.
//!
//! # Example
//!
//! ```ignore
//! use nlink::netlink::{Connection, Route};
//! use nlink::netlink::rule::RuleBuilder;
//!
//! let conn = Connection::<Route>::new()?;
//!
//! // Add a rule to lookup table 100 for traffic from 10.0.0.0/8
//! conn.add_rule(
//!     RuleBuilder::v4()
//!         .priority(100)
//!         .from_prefix("10.0.0.0", 8)
//!         .table(100)
//! ).await?;
//!
//! // Add a rule to blackhole traffic to 192.168.99.0/24
//! conn.add_rule(
//!     RuleBuilder::v4()
//!         .priority(200)
//!         .to_prefix("192.168.99.0", 24)
//!         .blackhole()
//! ).await?;
//!
//! // Delete a rule by priority
//! conn.del_rule(
//!     RuleBuilder::v4()
//!         .priority(100)
//! ).await?;
//! ```

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use super::builder::MessageBuilder;
use super::error::Result;
use super::message::{NLM_F_ACK, NLM_F_CREATE, NLM_F_EXCL, NLM_F_REQUEST, NlMsgType};
use super::types::rule::{FibRuleAction, FibRuleHdr, FraAttr};

/// Address family constants.
const AF_INET: u8 = 2;
const AF_INET6: u8 = 10;

/// Builder for routing rules.
#[derive(Debug, Clone)]
pub struct RuleBuilder {
    family: u8,
    priority: Option<u32>,
    src: Option<IpAddr>,
    src_len: u8,
    dst: Option<IpAddr>,
    dst_len: u8,
    iif: Option<String>,
    oif: Option<String>,
    fwmark: Option<u32>,
    fwmask: Option<u32>,
    table: u32,
    action: FibRuleAction,
    ipproto: Option<u8>,
    sport: Option<(u16, u16)>,
    dport: Option<(u16, u16)>,
}

impl RuleBuilder {
    /// Create a new rule builder for the given address family.
    pub fn new(family: u8) -> Self {
        Self {
            family,
            priority: None,
            src: None,
            src_len: 0,
            dst: None,
            dst_len: 0,
            iif: None,
            oif: None,
            fwmark: None,
            fwmask: None,
            table: 254, // main
            action: FibRuleAction::ToTbl,
            ipproto: None,
            sport: None,
            dport: None,
        }
    }

    /// Create a new IPv4 rule builder.
    pub fn v4() -> Self {
        Self::new(AF_INET)
    }

    /// Create a new IPv6 rule builder.
    pub fn v6() -> Self {
        Self::new(AF_INET6)
    }

    /// Set the rule priority.
    pub fn priority(mut self, priority: u32) -> Self {
        self.priority = Some(priority);
        self
    }

    /// Set the source prefix using an IP address and prefix length.
    pub fn from_addr(mut self, addr: IpAddr, prefix_len: u8) -> Self {
        self.src = Some(addr);
        self.src_len = prefix_len;
        self
    }

    /// Set the source prefix from a string address and prefix length.
    pub fn from_prefix(self, addr: &str, prefix_len: u8) -> Self {
        if let Ok(ip) = addr.parse::<IpAddr>() {
            self.from_addr(ip, prefix_len)
        } else {
            self
        }
    }

    /// Set the IPv4 source prefix.
    pub fn from_v4(mut self, addr: Ipv4Addr, prefix_len: u8) -> Self {
        self.src = Some(IpAddr::V4(addr));
        self.src_len = prefix_len;
        self
    }

    /// Set the IPv6 source prefix.
    pub fn from_v6(mut self, addr: Ipv6Addr, prefix_len: u8) -> Self {
        self.src = Some(IpAddr::V6(addr));
        self.src_len = prefix_len;
        self
    }

    /// Set the destination prefix using an IP address and prefix length.
    pub fn to_addr(mut self, addr: IpAddr, prefix_len: u8) -> Self {
        self.dst = Some(addr);
        self.dst_len = prefix_len;
        self
    }

    /// Set the destination prefix from a string address and prefix length.
    pub fn to_prefix(self, addr: &str, prefix_len: u8) -> Self {
        if let Ok(ip) = addr.parse::<IpAddr>() {
            self.to_addr(ip, prefix_len)
        } else {
            self
        }
    }

    /// Set the IPv4 destination prefix.
    pub fn to_v4(mut self, addr: Ipv4Addr, prefix_len: u8) -> Self {
        self.dst = Some(IpAddr::V4(addr));
        self.dst_len = prefix_len;
        self
    }

    /// Set the IPv6 destination prefix.
    pub fn to_v6(mut self, addr: Ipv6Addr, prefix_len: u8) -> Self {
        self.dst = Some(IpAddr::V6(addr));
        self.dst_len = prefix_len;
        self
    }

    /// Set the input interface name.
    pub fn iif(mut self, name: &str) -> Self {
        self.iif = Some(name.to_string());
        self
    }

    /// Set the output interface name.
    pub fn oif(mut self, name: &str) -> Self {
        self.oif = Some(name.to_string());
        self
    }

    /// Set the fwmark to match.
    pub fn fwmark(mut self, mark: u32) -> Self {
        self.fwmark = Some(mark);
        self
    }

    /// Set the fwmark and mask to match.
    pub fn fwmark_mask(mut self, mark: u32, mask: u32) -> Self {
        self.fwmark = Some(mark);
        self.fwmask = Some(mask);
        self
    }

    /// Set the routing table to lookup.
    pub fn table(mut self, table: u32) -> Self {
        self.table = table;
        self.action = FibRuleAction::ToTbl;
        self
    }

    /// Set the action to blackhole (drop packets silently).
    pub fn blackhole(mut self) -> Self {
        self.action = FibRuleAction::Blackhole;
        self
    }

    /// Set the action to unreachable (return ICMP unreachable).
    pub fn unreachable(mut self) -> Self {
        self.action = FibRuleAction::Unreachable;
        self
    }

    /// Set the action to prohibit (return ICMP prohibited).
    pub fn prohibit(mut self) -> Self {
        self.action = FibRuleAction::Prohibit;
        self
    }

    /// Set the IP protocol to match (6=TCP, 17=UDP, etc.).
    pub fn ipproto(mut self, proto: u8) -> Self {
        self.ipproto = Some(proto);
        self
    }

    /// Match TCP traffic.
    pub fn tcp(self) -> Self {
        self.ipproto(6)
    }

    /// Match UDP traffic.
    pub fn udp(self) -> Self {
        self.ipproto(17)
    }

    /// Set the source port range to match.
    pub fn sport(mut self, start: u16, end: u16) -> Self {
        self.sport = Some((start, end));
        self
    }

    /// Set a single source port to match.
    pub fn sport_eq(self, port: u16) -> Self {
        self.sport(port, port)
    }

    /// Set the destination port range to match.
    pub fn dport(mut self, start: u16, end: u16) -> Self {
        self.dport = Some((start, end));
        self
    }

    /// Set a single destination port to match.
    pub fn dport_eq(self, port: u16) -> Self {
        self.dport(port, port)
    }

    /// Build the netlink message for adding this rule.
    pub fn build(&self) -> Result<MessageBuilder> {
        self.build_internal(NlMsgType::RTM_NEWRULE, true)
    }

    /// Build the netlink message for deleting this rule.
    pub fn build_delete(&self) -> Result<MessageBuilder> {
        self.build_internal(NlMsgType::RTM_DELRULE, false)
    }

    fn build_internal(&self, msg_type: u16, create: bool) -> Result<MessageBuilder> {
        let mut flags = NLM_F_REQUEST | NLM_F_ACK;
        if create {
            flags |= NLM_F_CREATE | NLM_F_EXCL;
        }

        let mut builder = MessageBuilder::new(msg_type, flags);

        // Build header
        let mut hdr = FibRuleHdr::new().with_family(self.family);
        hdr.src_len = self.src_len;
        hdr.dst_len = self.dst_len;
        hdr.action = self.action as u8;
        hdr.table = if self.table <= 255 {
            self.table as u8
        } else {
            0
        };

        builder.append(&hdr);

        // Add priority
        if let Some(prio) = self.priority {
            builder.append_attr_u32(FraAttr::Priority as u16, prio);
        }

        // Add source
        if let Some(addr) = self.src {
            match addr {
                IpAddr::V4(v4) => {
                    builder.append_attr(FraAttr::Src as u16, &v4.octets());
                }
                IpAddr::V6(v6) => {
                    builder.append_attr(FraAttr::Src as u16, &v6.octets());
                }
            }
        }

        // Add destination
        if let Some(addr) = self.dst {
            match addr {
                IpAddr::V4(v4) => {
                    builder.append_attr(FraAttr::Dst as u16, &v4.octets());
                }
                IpAddr::V6(v6) => {
                    builder.append_attr(FraAttr::Dst as u16, &v6.octets());
                }
            }
        }

        // Add input interface
        if let Some(ref iif) = self.iif {
            builder.append_attr_str(FraAttr::Iifname as u16, iif);
        }

        // Add output interface
        if let Some(ref oif) = self.oif {
            builder.append_attr_str(FraAttr::Oifname as u16, oif);
        }

        // Add fwmark
        if let Some(mark) = self.fwmark {
            builder.append_attr_u32(FraAttr::Fwmark as u16, mark);
            if let Some(mask) = self.fwmask {
                builder.append_attr_u32(FraAttr::Fwmask as u16, mask);
            }
        }

        // Add table if > 255
        if self.table > 255 {
            builder.append_attr_u32(FraAttr::Table as u16, self.table);
        }

        // Add IP protocol
        if let Some(proto) = self.ipproto {
            builder.append_attr(FraAttr::IpProto as u16, &[proto]);
        }

        // Add sport
        if let Some((start, end)) = self.sport {
            let range_bytes = [
                (start & 0xff) as u8,
                ((start >> 8) & 0xff) as u8,
                (end & 0xff) as u8,
                ((end >> 8) & 0xff) as u8,
            ];
            builder.append_attr(FraAttr::Sport as u16, &range_bytes);
        }

        // Add dport
        if let Some((start, end)) = self.dport {
            let range_bytes = [
                (start & 0xff) as u8,
                ((start >> 8) & 0xff) as u8,
                (end & 0xff) as u8,
                ((end >> 8) & 0xff) as u8,
            ];
            builder.append_attr(FraAttr::Dport as u16, &range_bytes);
        }

        Ok(builder)
    }
}
