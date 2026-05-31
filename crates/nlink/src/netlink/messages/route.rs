//! Strongly-typed route message.

use std::net::IpAddr;

use winnow::{prelude::*, token::take};

use crate::netlink::{
    error::Result,
    parse::{FromNetlink, PResult, ToNetlink, parse_ip_addr},
    types::route::{RouteProtocol, RouteScope, RouteType, RtMsg},
};

/// Attribute IDs for RTA_* constants.
mod attr_ids {
    pub const RTA_DST: u16 = 1;
    pub const RTA_SRC: u16 = 2;
    pub const RTA_IIF: u16 = 3;
    pub const RTA_OIF: u16 = 4;
    pub const RTA_GATEWAY: u16 = 5;
    pub const RTA_PRIORITY: u16 = 6;
    pub const RTA_PREFSRC: u16 = 7;
    /// Plan 202 — multipath nexthop chain (`RTA_MULTIPATH`).
    pub const RTA_MULTIPATH: u16 = 9;
    pub const RTA_TABLE: u16 = 15;
    pub const RTA_PREF: u16 = 20;
    pub const RTA_EXPIRES: u16 = 23;
}

/// Header size of `struct rtnexthop`
/// (`include/uapi/linux/rtnetlink.h`): `rtnh_len(u16) +
/// rtnh_flags(u8) + rtnh_hops(u8) + rtnh_ifindex(u32)` = 8.
const RTNH_HDRLEN: usize = 8;

/// Strongly-typed route message with all attributes parsed.
#[derive(Debug, Clone, Default)]
pub struct RouteMessage {
    /// Fixed-size header.
    pub(crate) header: RtMsg,
    /// Destination address (RTA_DST).
    pub(crate) destination: Option<IpAddr>,
    /// Source address (RTA_SRC).
    pub(crate) source: Option<IpAddr>,
    /// Input interface index (RTA_IIF).
    pub(crate) iif: Option<u32>,
    /// Output interface index (RTA_OIF).
    pub(crate) oif: Option<u32>,
    /// Gateway address (RTA_GATEWAY).
    pub(crate) gateway: Option<IpAddr>,
    /// Priority/metric (RTA_PRIORITY).
    pub(crate) priority: Option<u32>,
    /// Preferred source address (RTA_PREFSRC).
    pub(crate) prefsrc: Option<IpAddr>,
    /// Routing table ID (RTA_TABLE).
    pub(crate) table: Option<u32>,
    /// Route preference (RTA_PREF).
    pub(crate) pref: Option<u8>,
    /// Expiration time (RTA_EXPIRES).
    pub(crate) expires: Option<u32>,
    /// Multipath nexthops (`RTA_MULTIPATH`). Plan 202.
    /// `None` if the route is single-path; `Some(vec)` with the
    /// parsed nexthop chain otherwise.
    pub(crate) multipath: Option<Vec<ParsedNextHop>>,
}

/// One nexthop parsed from an `RTA_MULTIPATH` chain. Plan 202.
///
/// Mirrors the kernel's `struct rtnexthop` plus the nested
/// per-nexthop attributes (`RTA_GATEWAY` at minimum). The
/// `weight` field is derived from the kernel's `rtnh_hops`
/// (which counts from 0; nlink's `NextHop::weight` counts from
/// 1, matching `ip route` syntax).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedNextHop {
    /// Output interface index (`rtnh_ifindex`).
    pub ifindex: u32,
    /// Nexthop weight (1-based). Kernel stores as `rtnh_hops`
    /// (0-based); we add 1 on parse to match nlink's
    /// imperative `NextHop::weight` convention + `ip route`.
    pub weight: u8,
    /// Kernel `rtnh_flags` byte.
    pub flags: u8,
    /// Nexthop gateway (`RTA_GATEWAY` nested within the
    /// `rtnexthop` block), if present.
    pub gateway: Option<IpAddr>,
}

impl RouteMessage {
    /// Create a new empty route message.
    pub fn new() -> Self {
        Self::default()
    }

    // =========================================================================
    // Accessor methods
    // =========================================================================

    /// Get the address family.
    pub fn family(&self) -> u8 {
        self.header.rtm_family
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

    /// Get the destination address.
    pub fn destination(&self) -> Option<&IpAddr> {
        self.destination.as_ref()
    }

    /// Get the source address.
    pub fn source(&self) -> Option<&IpAddr> {
        self.source.as_ref()
    }

    /// Get the input interface index.
    pub fn iif(&self) -> Option<u32> {
        self.iif
    }

    /// Get the output interface index.
    pub fn oif(&self) -> Option<u32> {
        self.oif
    }

    /// Get the gateway address.
    pub fn gateway(&self) -> Option<&IpAddr> {
        self.gateway.as_ref()
    }

    /// Get the priority/metric.
    pub fn priority(&self) -> Option<u32> {
        self.priority
    }

    /// Get the preferred source address.
    pub fn prefsrc(&self) -> Option<&IpAddr> {
        self.prefsrc.as_ref()
    }

    /// Get the route preference.
    pub fn pref(&self) -> Option<u8> {
        self.pref
    }

    /// Get the expiration time.
    pub fn expires(&self) -> Option<u32> {
        self.expires
    }

    /// Get the multipath nexthop list parsed from
    /// `RTA_MULTIPATH`. Plan 202.
    ///
    /// `None` for single-path routes (where `gateway()` /
    /// `oif()` carry the egress). `Some(&[..])` for ECMP /
    /// weighted-multipath routes.
    pub fn multipath(&self) -> Option<&[ParsedNextHop]> {
        self.multipath.as_deref()
    }

    // =========================================================================
    // Boolean checks
    // =========================================================================

    /// Check if this is an IPv4 route.
    pub fn is_ipv4(&self) -> bool {
        self.header.rtm_family == libc::AF_INET as u8
    }

    /// Check if this is an IPv6 route.
    pub fn is_ipv6(&self) -> bool {
        self.header.rtm_family == libc::AF_INET6 as u8
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

    // =========================================================================
    // Route classification helpers
    // =========================================================================

    /// Check if this is a system-generated route (local, broadcast, multicast).
    ///
    /// These routes are automatically created by the kernel and should
    /// generally not be captured in configuration snapshots.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let routes = conn.get_routes().await?;
    /// let user_routes: Vec<_> = routes.iter()
    ///     .filter(|r| !r.is_system_generated())
    ///     .collect();
    /// ```
    pub fn is_system_generated(&self) -> bool {
        matches!(
            self.route_type(),
            RouteType::Local | RouteType::Broadcast | RouteType::Multicast
        )
    }

    /// Check if this is a static user-configured route.
    ///
    /// Returns true for routes installed by static configuration (boot or admin).
    /// This excludes kernel-generated routes and routes from routing protocols.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let routes = conn.get_routes().await?;
    /// for route in routes.iter().filter(|r| r.is_static()) {
    ///     println!("Static route: {:?}", route.destination());
    /// }
    /// ```
    pub fn is_static(&self) -> bool {
        matches!(self.protocol(), RouteProtocol::Static | RouteProtocol::Boot)
    }

    /// Check if this route was installed by a routing daemon/protocol.
    ///
    /// Returns true for routes from BGP, OSPF, RIP, etc.
    pub fn is_dynamic(&self) -> bool {
        !matches!(
            self.protocol(),
            RouteProtocol::Unspec
                | RouteProtocol::Redirect
                | RouteProtocol::Kernel
                | RouteProtocol::Boot
                | RouteProtocol::Static
        )
    }

    /// Check if this is a connected/direct route (via link).
    pub fn is_connected(&self) -> bool {
        self.protocol() == RouteProtocol::Kernel && self.scope() == RouteScope::Link
    }

    /// Get the device name using an interface name map.
    ///
    /// This is a convenience method for display purposes.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let names = conn.get_interface_names().await?;
    /// let routes = conn.get_routes().await?;
    /// for route in &routes {
    ///     println!("{:?} via {}", route.destination(), route.device_name(&names));
    /// }
    /// ```
    pub fn device_name(&self, names: &std::collections::HashMap<u32, String>) -> String {
        self.oif
            .and_then(|idx| names.get(&idx))
            .cloned()
            .unwrap_or_else(|| "-".to_string())
    }

    /// Get the device name or a default value.
    pub fn device_name_or(
        &self,
        names: &std::collections::HashMap<u32, String>,
        default: &str,
    ) -> String {
        self.oif
            .and_then(|idx| names.get(&idx))
            .cloned()
            .unwrap_or_else(|| default.to_string())
    }

    /// Format the destination as a CIDR string (e.g., "10.0.0.0/8" or "default").
    pub fn destination_str(&self) -> String {
        if self.is_default() {
            "default".to_string()
        } else if let Some(dst) = &self.destination {
            format!("{}/{}", dst, self.dst_len())
        } else {
            format!("0.0.0.0/{}", self.dst_len())
        }
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
            // 0.19 N9 — nla_len/nla_type are host-order, not LE.
            let len_bytes: &[u8] = take(2usize).parse_next(input)?;
            let type_bytes: &[u8] = take(2usize).parse_next(input)?;
            let len = u16::from_ne_bytes(len_bytes.try_into().unwrap()) as usize;
            let attr_type = u16::from_ne_bytes(type_bytes.try_into().unwrap());

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
                attr_ids::RTA_IIF if attr_data.len() >= 4 => {
                    msg.iif = Some(u32::from_ne_bytes(attr_data[..4].try_into().unwrap()));
                }
                attr_ids::RTA_OIF if attr_data.len() >= 4 => {
                    msg.oif = Some(u32::from_ne_bytes(attr_data[..4].try_into().unwrap()));
                }
                attr_ids::RTA_GATEWAY => {
                    if let Ok(addr) = parse_ip_addr(attr_data, header.rtm_family) {
                        msg.gateway = Some(addr);
                    }
                }
                attr_ids::RTA_PRIORITY if attr_data.len() >= 4 => {
                    msg.priority = Some(u32::from_ne_bytes(attr_data[..4].try_into().unwrap()));
                }
                attr_ids::RTA_PREFSRC => {
                    if let Ok(addr) = parse_ip_addr(attr_data, header.rtm_family) {
                        msg.prefsrc = Some(addr);
                    }
                }
                attr_ids::RTA_TABLE if attr_data.len() >= 4 => {
                    msg.table = Some(u32::from_ne_bytes(attr_data[..4].try_into().unwrap()));
                }
                attr_ids::RTA_PREF if !attr_data.is_empty() => {
                    msg.pref = Some(attr_data[0]);
                }
                attr_ids::RTA_EXPIRES if attr_data.len() >= 4 => {
                    msg.expires = Some(u32::from_ne_bytes(attr_data[..4].try_into().unwrap()));
                }
                attr_ids::RTA_MULTIPATH => {
                    // Plan 202 — parse the nexthop chain.
                    // Defensive guards live inside the helper:
                    // rtnh_len < HDRLEN OR > remaining bytes
                    // aborts the walk (Plan 193 §2.2; tracks
                    // netlink-packet-route #152).
                    let nexthops = parse_multipath(attr_data, header.rtm_family);
                    if !nexthops.is_empty() {
                        msg.multipath = Some(nexthops);
                    }
                }
                _ => {} // Ignore unknown attributes
            }
        }

        Ok(msg)
    }
}

/// Walk an `RTA_MULTIPATH` payload (`data`) and parse each
/// `rtnexthop` block into a [`ParsedNextHop`]. Plan 202.
///
/// `family` is `AF_INET` (2) or `AF_INET6` (10) — passed in so
/// the nested `RTA_GATEWAY` attr is decoded with the correct
/// address width.
///
/// Defensive guards (Plan 193 §2.2 + CLAUDE.md §"Parser
/// robustness" rule 2):
///
/// - `rtnh_len < RTNH_HDRLEN` aborts the walk (entry header
///   too short to be valid).
/// - `offset + rtnh_len > data.len()` aborts the walk
///   (truncated chain).
/// - `rtnh_len == 0` aborts the walk (would cause infinite
///   loop on `offset` not advancing). Tracks
///   netlink-packet-route #152.
fn parse_multipath(data: &[u8], family: u8) -> Vec<ParsedNextHop> {
    let mut out = Vec::new();
    let mut offset = 0;

    while offset + RTNH_HDRLEN <= data.len() {
        // Read the rtnexthop header: rtnh_len (u16) +
        // rtnh_flags (u8) + rtnh_hops (u8) + rtnh_ifindex (u32).
        let rtnh_len = u16::from_ne_bytes([data[offset], data[offset + 1]]) as usize;
        let flags = data[offset + 2];
        let hops = data[offset + 3];
        let ifindex = u32::from_ne_bytes([
            data[offset + 4],
            data[offset + 5],
            data[offset + 6],
            data[offset + 7],
        ]);

        // Defensive guards — see fn-level docstring.
        if rtnh_len < RTNH_HDRLEN || offset + rtnh_len > data.len() {
            break;
        }

        // Nested attributes after the rtnexthop header.
        let nested_start = offset + RTNH_HDRLEN;
        let nested_end = offset + rtnh_len;
        let mut gateway = None;
        let mut nested = nested_start;
        while nested + 4 <= nested_end {
            let nla_len =
                u16::from_ne_bytes([data[nested], data[nested + 1]]) as usize;
            let nla_type =
                u16::from_ne_bytes([data[nested + 2], data[nested + 3]]);
            if nla_len < 4 || nested + nla_len > nested_end {
                break;
            }
            let payload = &data[nested + 4..nested + nla_len];
            if (nla_type & 0x3FFF) == attr_ids::RTA_GATEWAY
                && let Ok(addr) = parse_ip_addr(payload, family)
            {
                gateway = Some(addr);
            }
            // Align to 4 bytes for the next nested attr.
            let aligned = (nla_len + 3) & !3;
            nested += aligned.max(4); // never let `nested` stall
        }

        out.push(ParsedNextHop {
            ifindex,
            weight: hops.saturating_add(1),
            flags,
            gateway,
        });

        // Align to 4 bytes for the next nexthop entry.
        let aligned = (rtnh_len + 3) & !3;
        offset += aligned.max(RTNH_HDRLEN); // never stall
    }

    out
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
        // 0.19 N4 — RTA_SRC + RTA_IIF + RTA_PREF + RTA_EXPIRES +
        // RTA_MULTIPATH were parsed but never emitted, silently
        // dropping these fields on `get → mutate → set` roundtrips.
        if let Some(ref src) = self.source {
            write_attr_ip(buf, attr_ids::RTA_SRC, src);
        }
        if let Some(iif) = self.iif {
            write_attr_u32(buf, attr_ids::RTA_IIF, iif);
        }
        if let Some(pref) = self.pref {
            write_attr_u8_padded(buf, attr_ids::RTA_PREF, pref);
        }
        if let Some(expires) = self.expires {
            write_attr_u32(buf, attr_ids::RTA_EXPIRES, expires);
        }
        if let Some(ref nexthops) = self.multipath {
            write_attr_multipath(buf, attr_ids::RTA_MULTIPATH, nexthops);
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

/// Write a u8-valued attribute (payload padded to 4 bytes).
/// 0.19 N4 — used for `RTA_PREF` (RFC 4191 router preference).
fn write_attr_u8_padded(buf: &mut Vec<u8>, attr_type: u16, value: u8) {
    let len: u16 = 5;
    buf.extend_from_slice(&len.to_ne_bytes());
    buf.extend_from_slice(&attr_type.to_ne_bytes());
    buf.push(value);
    // Pad to 4-byte alignment: 5 bytes → 8.
    buf.extend_from_slice(&[0u8; 3]);
}

/// Write an `RTA_MULTIPATH` chain — one nested `struct rtnexthop`
/// per `ParsedNextHop`, each followed by an optional nested
/// `RTA_GATEWAY` attribute. 0.19 N4.
///
/// Wire format (mirrors the parse side at
/// `parse_multipath`): nla_len(u16) + nla_type(u16) | for each nh:
/// `rtnh_len`(u16) + `rtnh_flags`(u8) + `rtnh_hops`(u8) +
/// `rtnh_ifindex`(u32) + nested attrs | per-nh 4-byte align +
/// outer 4-byte align.
fn write_attr_multipath(buf: &mut Vec<u8>, attr_type: u16, nexthops: &[ParsedNextHop]) {
    let attr_header_offset = buf.len();
    // Placeholder for nla_len; backfilled below.
    buf.extend_from_slice(&0u16.to_ne_bytes());
    buf.extend_from_slice(&attr_type.to_ne_bytes());
    let body_start = buf.len();

    for nh in nexthops {
        let nh_start = buf.len();
        // Placeholder for rtnh_len.
        buf.extend_from_slice(&0u16.to_ne_bytes());
        // Convert nlink's 1-based weight to kernel's 0-based
        // `rtnh_hops`.
        buf.push(nh.flags);
        buf.push(nh.weight.saturating_sub(1));
        buf.extend_from_slice(&nh.ifindex.to_ne_bytes());

        if let Some(ref gw) = nh.gateway {
            write_attr_ip(buf, attr_ids::RTA_GATEWAY, gw);
        }

        // Backfill rtnh_len.
        let rtnh_len = (buf.len() - nh_start) as u16;
        buf[nh_start..nh_start + 2].copy_from_slice(&rtnh_len.to_ne_bytes());

        // Pad to 4-byte alignment.
        let pad = (4 - ((buf.len() - nh_start) & 3)) & 3;
        for _ in 0..pad {
            buf.push(0);
        }
    }

    // Backfill nla_len.
    let nla_len = (buf.len() - attr_header_offset) as u16;
    buf[attr_header_offset..attr_header_offset + 2].copy_from_slice(&nla_len.to_ne_bytes());

    // Outer 4-byte alignment.
    let total = buf.len() - attr_header_offset;
    let pad = (4 - (total & 3)) & 3;
    for _ in 0..pad {
        buf.push(0);
    }
    let _ = body_start;
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

    /// Set the source address with prefix length (`RTA_SRC`).
    /// 0.19 N4 — closes the `get → mutate → set` write-parse
    /// asymmetry where `source` was parsed but never emitted.
    pub fn source(mut self, addr: IpAddr, prefix_len: u8) -> Self {
        match addr {
            IpAddr::V4(_) => self.msg.header.rtm_family = libc::AF_INET as u8,
            IpAddr::V6(_) => self.msg.header.rtm_family = libc::AF_INET6 as u8,
        }
        self.msg.header.rtm_src_len = prefix_len;
        self.msg.source = Some(addr);
        self
    }

    /// Set the input interface index (`RTA_IIF`). 0.19 N4.
    pub fn iif(mut self, ifindex: u32) -> Self {
        self.msg.iif = Some(ifindex);
        self
    }

    /// Set the route preference (`RTA_PREF`, RFC 4191 router
    /// preference). 0.19 N4.
    pub fn pref(mut self, pref: u8) -> Self {
        self.msg.pref = Some(pref);
        self
    }

    /// Set the route expiry in seconds (`RTA_EXPIRES`). 0.19 N4.
    pub fn expires(mut self, seconds: u32) -> Self {
        self.msg.expires = Some(seconds);
        self
    }

    /// Set the multipath nexthop chain (`RTA_MULTIPATH`). 0.19 N4.
    ///
    /// Uses [`ParsedNextHop`] (the round-trip type) — the imperative
    /// [`crate::netlink::route::NextHop`] carries an unresolved
    /// `InterfaceRef` and is not appropriate for replaying a
    /// previously-dumped route.
    pub fn multipath(mut self, nexthops: Vec<ParsedNextHop>) -> Self {
        self.msg.multipath = Some(nexthops);
        self
    }

    /// Build the message.
    pub fn build(self) -> RouteMessage {
        self.msg
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

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

    /// 0.19 N4 — verify every emitted attribute survives a
    /// `write_to → parse` round-trip. Pre-fix, `source`, `iif`,
    /// `pref`, `expires`, and `multipath` were silently dropped
    /// on the write side (parsed-only).
    #[test]
    fn write_to_preserves_all_attrs_roundtrip() {
        let nexthops = vec![
            ParsedNextHop {
                ifindex: 7,
                weight: 1,
                flags: 0,
                gateway: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
            },
            ParsedNextHop {
                ifindex: 9,
                weight: 2,
                flags: 0,
                gateway: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1))),
            },
        ];
        let original = RouteMessageBuilder::new()
            .destination(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)), 8)
            .source(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 0)), 24)
            .iif(3)
            .oif(7)
            .priority(100)
            .pref(0)
            .expires(3600)
            .multipath(nexthops.clone())
            .build();

        let mut buf = Vec::new();
        original.write_to(&mut buf).unwrap();

        let parsed = RouteMessage::parse(&mut buf.as_slice()).unwrap();

        assert_eq!(parsed.source, Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 0))));
        assert_eq!(parsed.iif, Some(3));
        assert_eq!(parsed.pref, Some(0));
        assert_eq!(parsed.expires, Some(3600));
        assert_eq!(parsed.multipath, Some(nexthops));
        // Spot-check the pre-existing fields too.
        assert_eq!(parsed.destination, Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0))));
        assert_eq!(parsed.oif, Some(7));
        assert_eq!(parsed.priority, Some(100));
    }

    // --------- Plan 202 — parse_multipath ---------

    /// Helper: build one IPv4 rtnexthop entry — 8-byte header
    /// plus 8-byte nested RTA_GATEWAY (4-byte address + 4-byte
    /// attr header).
    fn rtnh_v4(weight: u8, ifindex: u32, gw: Option<[u8; 4]>) -> Vec<u8> {
        let nested_len = gw.map(|_| 4 + 4).unwrap_or(0);
        let total_len = (RTNH_HDRLEN + nested_len) as u16;
        let mut e = Vec::with_capacity(total_len as usize);
        e.extend_from_slice(&total_len.to_ne_bytes());
        e.push(0); // rtnh_flags
        e.push(weight.saturating_sub(1)); // rtnh_hops
        e.extend_from_slice(&ifindex.to_ne_bytes());
        if let Some(addr) = gw {
            e.extend_from_slice(&(8u16).to_ne_bytes()); // nla_len
            e.extend_from_slice(&attr_ids::RTA_GATEWAY.to_ne_bytes());
            e.extend_from_slice(&addr);
        }
        e
    }

    #[test]
    fn parse_multipath_walks_normal_v4_chain() {
        let mut buf = Vec::new();
        buf.extend(rtnh_v4(1, 7, Some([10, 0, 0, 1])));
        buf.extend(rtnh_v4(2, 9, Some([10, 0, 1, 1])));
        let parsed = parse_multipath(&buf, /* AF_INET = */ 2);
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].ifindex, 7);
        assert_eq!(parsed[0].weight, 1);
        assert_eq!(
            parsed[0].gateway,
            Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)))
        );
        assert_eq!(parsed[1].ifindex, 9);
        assert_eq!(parsed[1].weight, 2);
    }

    #[test]
    fn parse_multipath_handles_empty_buffer() {
        let parsed = parse_multipath(&[], 2);
        assert!(parsed.is_empty());
    }

    #[test]
    fn parse_multipath_handles_zero_length_rtnh_without_loop() {
        // rtnh_len = 0 — degenerate. Plan 193 §2.2 + rule 2:
        // the walker must abort, not spin.
        let buf = vec![0u8; 8];
        let start = std::time::Instant::now();
        let parsed = parse_multipath(&buf, 2);
        assert!(start.elapsed() < std::time::Duration::from_millis(100));
        assert!(parsed.is_empty());
    }

    #[test]
    fn parse_multipath_handles_undersized_rtnh_header() {
        // rtnh_len = 1 — less than the 8-byte header.
        let mut buf = vec![0u8; 8];
        buf[0] = 1;
        buf[1] = 0;
        let parsed = parse_multipath(&buf, 2);
        assert!(parsed.is_empty(), "undersized rtnh_len must abort walk");
    }

    #[test]
    fn parse_multipath_handles_truncated_chain() {
        // First entry claims 100 bytes total; buffer carries
        // only 16. Walker must NOT walk past the buffer.
        let mut buf = vec![0u8; 16];
        let claimed_len = 100u16;
        buf[0..2].copy_from_slice(&claimed_len.to_ne_bytes());
        let parsed = parse_multipath(&buf, 2);
        assert!(parsed.is_empty(), "truncated chain must abort walk");
    }

    #[test]
    fn parse_multipath_ignores_garbage_nested_attrs() {
        // Header advertises 16-byte entry (8 hdr + 8 nested);
        // nested attr is well-formed but has unknown nla_type
        // (0x55). Walker emits the nexthop with gateway=None.
        let mut buf = Vec::new();
        buf.extend_from_slice(&16u16.to_ne_bytes());
        buf.push(0); // flags
        buf.push(0); // hops
        buf.extend_from_slice(&3u32.to_ne_bytes()); // ifindex
        buf.extend_from_slice(&8u16.to_ne_bytes()); // nla_len
        buf.extend_from_slice(&0x55u16.to_ne_bytes()); // garbage nla_type
        buf.extend_from_slice(&[0, 0, 0, 0]); // payload

        let parsed = parse_multipath(&buf, 2);
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].ifindex, 3);
        assert!(parsed[0].gateway.is_none());
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
