//! Strongly-typed route message.

use std::net::IpAddr;

use winnow::binary::le_u16;
use winnow::prelude::*;
use winnow::token::take;

use crate::error::Result;
use crate::parse::{FromNetlink, PResult, ToNetlink, parse_ip_addr};
use crate::types::route::{RouteProtocol, RouteScope, RouteType, RtMsg};

/// Attribute IDs for RTA_* constants.
mod attr_ids {
    pub const RTA_DST: u16 = 1;
    pub const RTA_SRC: u16 = 2;
    pub const RTA_IIF: u16 = 3;
    pub const RTA_OIF: u16 = 4;
    pub const RTA_GATEWAY: u16 = 5;
    pub const RTA_PRIORITY: u16 = 6;
    pub const RTA_PREFSRC: u16 = 7;
    pub const RTA_METRICS: u16 = 8;
    pub const RTA_TABLE: u16 = 15;
    pub const RTA_PREF: u16 = 20;
    pub const RTA_EXPIRES: u16 = 23;
}

/// Strongly-typed route message with all attributes parsed.
#[derive(Debug, Clone, Default)]
pub struct RouteMessage {
    /// Fixed-size header.
    pub header: RtMsg,
    /// Destination address (RTA_DST).
    pub destination: Option<IpAddr>,
    /// Source address (RTA_SRC).
    pub source: Option<IpAddr>,
    /// Input interface index (RTA_IIF).
    pub iif: Option<u32>,
    /// Output interface index (RTA_OIF).
    pub oif: Option<u32>,
    /// Gateway address (RTA_GATEWAY).
    pub gateway: Option<IpAddr>,
    /// Priority/metric (RTA_PRIORITY).
    pub priority: Option<u32>,
    /// Preferred source address (RTA_PREFSRC).
    pub prefsrc: Option<IpAddr>,
    /// Routing table ID (RTA_TABLE).
    pub table: Option<u32>,
    /// Route preference (RTA_PREF).
    pub pref: Option<u8>,
    /// Expiration time (RTA_EXPIRES).
    pub expires: Option<u32>,
}

impl RouteMessage {
    /// Create a new empty route message.
    pub fn new() -> Self {
        Self::default()
    }

    /// Get the address family.
    pub fn family(&self) -> u8 {
        self.header.rtm_family
    }

    /// Check if this is an IPv4 route.
    pub fn is_ipv4(&self) -> bool {
        self.header.rtm_family == libc::AF_INET as u8
    }

    /// Check if this is an IPv6 route.
    pub fn is_ipv6(&self) -> bool {
        self.header.rtm_family == libc::AF_INET6 as u8
    }

    /// Get the destination prefix length.
    pub fn dst_len(&self) -> u8 {
        self.header.rtm_dst_len
    }

    /// Get the source prefix length.
    pub fn src_len(&self) -> u8 {
        self.header.rtm_src_len
    }

    /// Get the route type.
    pub fn route_type(&self) -> RouteType {
        RouteType::from(self.header.rtm_type)
    }

    /// Get the route protocol (who installed it).
    pub fn protocol(&self) -> RouteProtocol {
        RouteProtocol::from(self.header.rtm_protocol)
    }

    /// Get the route scope.
    pub fn scope(&self) -> RouteScope {
        RouteScope::from(self.header.rtm_scope)
    }

    /// Get the routing table ID.
    pub fn table_id(&self) -> u32 {
        self.table.unwrap_or(self.header.rtm_table as u32)
    }

    /// Check if this is a default route (0.0.0.0/0 or ::/0).
    pub fn is_default(&self) -> bool {
        self.header.rtm_dst_len == 0 && self.destination.is_none()
    }

    /// Check if this is a host route (/32 or /128).
    pub fn is_host(&self) -> bool {
        match self.header.rtm_family as i32 {
            libc::AF_INET => self.header.rtm_dst_len == 32,
            libc::AF_INET6 => self.header.rtm_dst_len == 128,
            _ => false,
        }
    }

    /// Check if this route has a gateway.
    pub fn has_gateway(&self) -> bool {
        self.gateway.is_some()
    }
}

impl FromNetlink for RouteMessage {
    fn write_dump_header(buf: &mut Vec<u8>) {
        // RTM_GETROUTE requires an RtMsg header
        let header = RtMsg::new();
        buf.extend_from_slice(header.as_bytes());
    }

    fn parse(input: &mut &[u8]) -> PResult<Self> {
        // Parse fixed header (12 bytes)
        if input.len() < RtMsg::SIZE {
            return Err(winnow::error::ErrMode::Cut(
                winnow::error::ContextError::new(),
            ));
        }

        let header_bytes: &[u8] = take(RtMsg::SIZE).parse_next(input)?;
        let header = *RtMsg::from_bytes(header_bytes)
            .map_err(|_| winnow::error::ErrMode::Cut(winnow::error::ContextError::new()))?;

        let mut msg = RouteMessage {
            header,
            ..Default::default()
        };

        // Parse attributes
        while !input.is_empty() && input.len() >= 4 {
            let len = le_u16.parse_next(input)? as usize;
            let attr_type = le_u16.parse_next(input)?;

            if len < 4 {
                break;
            }

            let payload_len = len.saturating_sub(4);
            if input.len() < payload_len {
                break;
            }

            let attr_data: &[u8] = take(payload_len).parse_next(input)?;

            // Align to 4 bytes
            let aligned = (len + 3) & !3;
            let padding = aligned.saturating_sub(len);
            if input.len() >= padding {
                let _: &[u8] = take(padding).parse_next(input)?;
            }

            // Match attribute type
            match attr_type & 0x3FFF {
                attr_ids::RTA_DST => {
                    if let Ok(addr) = parse_ip_addr(attr_data, header.rtm_family) {
                        msg.destination = Some(addr);
                    }
                }
                attr_ids::RTA_SRC => {
                    if let Ok(addr) = parse_ip_addr(attr_data, header.rtm_family) {
                        msg.source = Some(addr);
                    }
                }
                attr_ids::RTA_IIF => {
                    if attr_data.len() >= 4 {
                        msg.iif = Some(u32::from_ne_bytes(attr_data[..4].try_into().unwrap()));
                    }
                }
                attr_ids::RTA_OIF => {
                    if attr_data.len() >= 4 {
                        msg.oif = Some(u32::from_ne_bytes(attr_data[..4].try_into().unwrap()));
                    }
                }
                attr_ids::RTA_GATEWAY => {
                    if let Ok(addr) = parse_ip_addr(attr_data, header.rtm_family) {
                        msg.gateway = Some(addr);
                    }
                }
                attr_ids::RTA_PRIORITY => {
                    if attr_data.len() >= 4 {
                        msg.priority = Some(u32::from_ne_bytes(attr_data[..4].try_into().unwrap()));
                    }
                }
                attr_ids::RTA_PREFSRC => {
                    if let Ok(addr) = parse_ip_addr(attr_data, header.rtm_family) {
                        msg.prefsrc = Some(addr);
                    }
                }
                attr_ids::RTA_TABLE => {
                    if attr_data.len() >= 4 {
                        msg.table = Some(u32::from_ne_bytes(attr_data[..4].try_into().unwrap()));
                    }
                }
                attr_ids::RTA_PREF => {
                    if !attr_data.is_empty() {
                        msg.pref = Some(attr_data[0]);
                    }
                }
                attr_ids::RTA_EXPIRES => {
                    if attr_data.len() >= 4 {
                        msg.expires = Some(u32::from_ne_bytes(attr_data[..4].try_into().unwrap()));
                    }
                }
                _ => {} // Ignore unknown attributes
            }
        }

        Ok(msg)
    }
}

impl ToNetlink for RouteMessage {
    fn netlink_len(&self) -> usize {
        let mut len = RtMsg::SIZE;

        if self.destination.is_some() {
            len += nla_size(if self.is_ipv4() { 4 } else { 16 });
        }
        if self.gateway.is_some() {
            len += nla_size(if self.is_ipv4() { 4 } else { 16 });
        }
        if self.oif.is_some() {
            len += nla_size(4);
        }
        if self.priority.is_some() {
            len += nla_size(4);
        }
        if self.prefsrc.is_some() {
            len += nla_size(if self.is_ipv4() { 4 } else { 16 });
        }
        if self.table.is_some() {
            len += nla_size(4);
        }

        len
    }

    fn write_to(&self, buf: &mut Vec<u8>) -> Result<usize> {
        let start = buf.len();

        // Write header
        buf.extend_from_slice(self.header.as_bytes());

        // Write attributes
        if let Some(ref dst) = self.destination {
            write_attr_ip(buf, attr_ids::RTA_DST, dst);
        }
        if let Some(ref gw) = self.gateway {
            write_attr_ip(buf, attr_ids::RTA_GATEWAY, gw);
        }
        if let Some(oif) = self.oif {
            write_attr_u32(buf, attr_ids::RTA_OIF, oif);
        }
        if let Some(priority) = self.priority {
            write_attr_u32(buf, attr_ids::RTA_PRIORITY, priority);
        }
        if let Some(ref prefsrc) = self.prefsrc {
            write_attr_ip(buf, attr_ids::RTA_PREFSRC, prefsrc);
        }
        if let Some(table) = self.table {
            write_attr_u32(buf, attr_ids::RTA_TABLE, table);
        }

        Ok(buf.len() - start)
    }
}

/// Calculate aligned attribute size.
fn nla_size(payload_len: usize) -> usize {
    (4 + payload_len + 3) & !3
}

fn write_attr_u32(buf: &mut Vec<u8>, attr_type: u16, value: u32) {
    let len: u16 = 8;
    buf.extend_from_slice(&len.to_ne_bytes());
    buf.extend_from_slice(&attr_type.to_ne_bytes());
    buf.extend_from_slice(&value.to_ne_bytes());
}

fn write_attr_ip(buf: &mut Vec<u8>, attr_type: u16, addr: &IpAddr) {
    let octets = match addr {
        IpAddr::V4(v4) => v4.octets().to_vec(),
        IpAddr::V6(v6) => v6.octets().to_vec(),
    };
    let len = 4 + octets.len();
    buf.extend_from_slice(&(len as u16).to_ne_bytes());
    buf.extend_from_slice(&attr_type.to_ne_bytes());
    buf.extend_from_slice(&octets);
    // Padding
    let aligned = (len + 3) & !3;
    for _ in 0..(aligned - len) {
        buf.push(0);
    }
}

/// Builder for constructing RouteMessage.
#[derive(Debug, Clone, Default)]
pub struct RouteMessageBuilder {
    msg: RouteMessage,
}

impl RouteMessageBuilder {
    /// Create a new builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the address family to IPv4.
    pub fn ipv4(mut self) -> Self {
        self.msg.header.rtm_family = libc::AF_INET as u8;
        self
    }

    /// Set the address family to IPv6.
    pub fn ipv6(mut self) -> Self {
        self.msg.header.rtm_family = libc::AF_INET6 as u8;
        self
    }

    /// Set the destination with prefix length.
    pub fn destination(mut self, addr: IpAddr, prefix_len: u8) -> Self {
        match addr {
            IpAddr::V4(_) => self.msg.header.rtm_family = libc::AF_INET as u8,
            IpAddr::V6(_) => self.msg.header.rtm_family = libc::AF_INET6 as u8,
        }
        self.msg.header.rtm_dst_len = prefix_len;
        self.msg.destination = Some(addr);
        self
    }

    /// Set the gateway.
    pub fn gateway(mut self, addr: IpAddr) -> Self {
        self.msg.gateway = Some(addr);
        self
    }

    /// Set the output interface.
    pub fn oif(mut self, ifindex: u32) -> Self {
        self.msg.oif = Some(ifindex);
        self
    }

    /// Set the route priority/metric.
    pub fn priority(mut self, priority: u32) -> Self {
        self.msg.priority = Some(priority);
        self
    }

    /// Set the preferred source address.
    pub fn prefsrc(mut self, addr: IpAddr) -> Self {
        self.msg.prefsrc = Some(addr);
        self
    }

    /// Set the routing table.
    pub fn table(mut self, table: u32) -> Self {
        self.msg.table = Some(table);
        if table < 256 {
            self.msg.header.rtm_table = table as u8;
        } else {
            self.msg.header.rtm_table = 252; // RT_TABLE_COMPAT
        }
        self
    }

    /// Set the route type.
    pub fn route_type(mut self, rt_type: RouteType) -> Self {
        self.msg.header.rtm_type = rt_type as u8;
        self
    }

    /// Set the route protocol (who installed it).
    pub fn protocol(mut self, protocol: RouteProtocol) -> Self {
        self.msg.header.rtm_protocol = protocol as u8;
        self
    }

    /// Set the route scope.
    pub fn scope(mut self, scope: RouteScope) -> Self {
        self.msg.header.rtm_scope = scope as u8;
        self
    }

    /// Build the message.
    pub fn build(self) -> RouteMessage {
        self.msg
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_builder() {
        let msg = RouteMessageBuilder::new()
            .destination(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)), 8)
            .gateway(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)))
            .oif(2)
            .table(254)
            .build();

        assert!(msg.is_ipv4());
        assert_eq!(msg.dst_len(), 8);
        assert!(msg.has_gateway());
        assert_eq!(msg.oif, Some(2));
    }

    #[test]
    fn test_default_route() {
        let msg = RouteMessageBuilder::new()
            .ipv4()
            .gateway(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)))
            .build();

        assert!(msg.is_default());
    }
}
