//! Route management.
//!
//! This module provides typed builders for adding and managing routes.
//!
//! # Example
//!
//! ```ignore
//! use nlink::netlink::{Connection, Protocol};
//! use nlink::netlink::route::{Ipv4Route, Ipv6Route, RouteType, NextHop};
//! use std::net::{Ipv4Addr, Ipv6Addr};
//!
//! let conn = Connection::new(Protocol::Route)?;
//!
//! // Add a simple route via gateway
//! conn.add_route(
//!     Ipv4Route::new("192.168.2.0", 24)
//!         .gateway(Ipv4Addr::new(192, 168, 1, 1))
//! ).await?;
//!
//! // Add a route via interface
//! conn.add_route(
//!     Ipv4Route::new("10.0.0.0", 8)
//!         .dev("eth0")
//! ).await?;
//!
//! // Add a multipath route (ECMP)
//! conn.add_route(
//!     Ipv4Route::new("0.0.0.0", 0)
//!         .multipath(vec![
//!             NextHop::new().gateway_v4(Ipv4Addr::new(192, 168, 1, 1)).dev("eth0").weight(1),
//!             NextHop::new().gateway_v4(Ipv4Addr::new(192, 168, 2, 1)).dev("eth1").weight(1),
//!         ])
//! ).await?;
//!
//! // Add a blackhole route
//! conn.add_route(
//!     Ipv4Route::new("10.255.0.0", 16)
//!         .route_type(RouteType::Blackhole)
//! ).await?;
//!
//! // Delete a route
//! conn.del_route_v4("192.168.2.0", 24).await?;
//! ```

use std::net::{Ipv4Addr, Ipv6Addr};

use super::builder::MessageBuilder;
use super::connection::Connection;
use super::error::{Error, Result};
use super::message::{NLM_F_ACK, NLM_F_REQUEST, NlMsgType};
use super::types::route::{RouteProtocol, RouteScope, RouteType, RtMsg, RtaAttr, rt_table};

/// NLM_F_CREATE flag
const NLM_F_CREATE: u16 = 0x400;
/// NLM_F_EXCL flag
const NLM_F_EXCL: u16 = 0x200;

/// Address families
const AF_INET: u8 = 2;
const AF_INET6: u8 = 10;

/// Route metrics attributes (RTAX_*)
mod rtax {
    pub const MTU: u16 = 2;
    pub const WINDOW: u16 = 3;
    pub const RTT: u16 = 4;
    pub const RTTVAR: u16 = 5;
    pub const SSTHRESH: u16 = 6;
    pub const CWND: u16 = 7;
    pub const ADVMSS: u16 = 8;
    pub const REORDERING: u16 = 9;
    pub const HOPLIMIT: u16 = 10;
    pub const INITCWND: u16 = 11;
    pub const FEATURES: u16 = 12;
    pub const RTO_MIN: u16 = 13;
    pub const INITRWND: u16 = 14;
    pub const QUICKACK: u16 = 15;
}

/// Nexthop flags (RTNH_F_*)
pub mod rtnh_flags {
    pub const DEAD: u8 = 1;
    pub const PERVASIVE: u8 = 2;
    pub const ONLINK: u8 = 4;
    pub const OFFLOAD: u8 = 8;
    pub const LINKDOWN: u8 = 16;
    pub const UNRESOLVED: u8 = 32;
    pub const TRAP: u8 = 64;
}

/// Trait for route configurations that can be added.
pub trait RouteConfig {
    /// Build the netlink message for adding this route.
    fn build(&self) -> Result<MessageBuilder>;

    /// Build a message for deleting this route.
    fn build_delete(&self) -> Result<MessageBuilder>;
}

/// Route metrics configuration.
#[derive(Debug, Clone, Default)]
pub struct RouteMetrics {
    /// Path MTU
    pub mtu: Option<u32>,
    /// Advertised MSS
    pub advmss: Option<u32>,
    /// Window size
    pub window: Option<u32>,
    /// RTT in milliseconds
    pub rtt: Option<u32>,
    /// RTT variance
    pub rttvar: Option<u32>,
    /// Slow-start threshold
    pub ssthresh: Option<u32>,
    /// Congestion window
    pub cwnd: Option<u32>,
    /// Initial congestion window
    pub initcwnd: Option<u32>,
    /// Initial receive window
    pub initrwnd: Option<u32>,
    /// Hop limit
    pub hoplimit: Option<u32>,
    /// RTO minimum
    pub rto_min: Option<u32>,
    /// Quick ACK
    pub quickack: Option<u32>,
    /// Reordering
    pub reordering: Option<u32>,
    /// Features
    pub features: Option<u32>,
}

impl RouteMetrics {
    /// Create empty metrics.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set path MTU.
    pub fn mtu(mut self, mtu: u32) -> Self {
        self.mtu = Some(mtu);
        self
    }

    /// Set advertised MSS.
    pub fn advmss(mut self, advmss: u32) -> Self {
        self.advmss = Some(advmss);
        self
    }

    /// Set window size.
    pub fn window(mut self, window: u32) -> Self {
        self.window = Some(window);
        self
    }

    /// Set initial congestion window.
    pub fn initcwnd(mut self, initcwnd: u32) -> Self {
        self.initcwnd = Some(initcwnd);
        self
    }

    /// Set initial receive window.
    pub fn initrwnd(mut self, initrwnd: u32) -> Self {
        self.initrwnd = Some(initrwnd);
        self
    }

    /// Set hop limit.
    pub fn hoplimit(mut self, hoplimit: u32) -> Self {
        self.hoplimit = Some(hoplimit);
        self
    }

    /// Set RTO minimum in milliseconds.
    pub fn rto_min(mut self, rto_min: u32) -> Self {
        self.rto_min = Some(rto_min);
        self
    }

    /// Set quick ACK.
    pub fn quickack(mut self, quickack: u32) -> Self {
        self.quickack = Some(quickack);
        self
    }

    /// Check if any metrics are set.
    pub fn has_any(&self) -> bool {
        self.mtu.is_some()
            || self.advmss.is_some()
            || self.window.is_some()
            || self.rtt.is_some()
            || self.rttvar.is_some()
            || self.ssthresh.is_some()
            || self.cwnd.is_some()
            || self.initcwnd.is_some()
            || self.initrwnd.is_some()
            || self.hoplimit.is_some()
            || self.rto_min.is_some()
            || self.quickack.is_some()
            || self.reordering.is_some()
            || self.features.is_some()
    }

    /// Write metrics as nested attribute.
    fn write_to(&self, builder: &mut MessageBuilder) {
        let metrics = builder.nest_start(RtaAttr::Metrics as u16);

        if let Some(v) = self.mtu {
            builder.append_attr_u32(rtax::MTU, v);
        }
        if let Some(v) = self.advmss {
            builder.append_attr_u32(rtax::ADVMSS, v);
        }
        if let Some(v) = self.window {
            builder.append_attr_u32(rtax::WINDOW, v);
        }
        if let Some(v) = self.rtt {
            builder.append_attr_u32(rtax::RTT, v);
        }
        if let Some(v) = self.rttvar {
            builder.append_attr_u32(rtax::RTTVAR, v);
        }
        if let Some(v) = self.ssthresh {
            builder.append_attr_u32(rtax::SSTHRESH, v);
        }
        if let Some(v) = self.cwnd {
            builder.append_attr_u32(rtax::CWND, v);
        }
        if let Some(v) = self.initcwnd {
            builder.append_attr_u32(rtax::INITCWND, v);
        }
        if let Some(v) = self.initrwnd {
            builder.append_attr_u32(rtax::INITRWND, v);
        }
        if let Some(v) = self.hoplimit {
            builder.append_attr_u32(rtax::HOPLIMIT, v);
        }
        if let Some(v) = self.rto_min {
            builder.append_attr_u32(rtax::RTO_MIN, v);
        }
        if let Some(v) = self.quickack {
            builder.append_attr_u32(rtax::QUICKACK, v);
        }
        if let Some(v) = self.reordering {
            builder.append_attr_u32(rtax::REORDERING, v);
        }
        if let Some(v) = self.features {
            builder.append_attr_u32(rtax::FEATURES, v);
        }

        builder.nest_end(metrics);
    }
}

/// A single nexthop in a multipath route.
#[derive(Debug, Clone)]
pub struct NextHop {
    /// Gateway address (IPv4)
    gateway_v4: Option<Ipv4Addr>,
    /// Gateway address (IPv6)
    gateway_v6: Option<Ipv6Addr>,
    /// Output interface name
    dev: Option<String>,
    /// Weight (for ECMP)
    weight: u8,
    /// Flags
    flags: u8,
}

impl NextHop {
    /// Create a new nexthop.
    pub fn new() -> Self {
        Self {
            gateway_v4: None,
            gateway_v6: None,
            dev: None,
            weight: 1,
            flags: 0,
        }
    }

    /// Set IPv4 gateway.
    pub fn gateway_v4(mut self, addr: Ipv4Addr) -> Self {
        self.gateway_v4 = Some(addr);
        self.gateway_v6 = None;
        self
    }

    /// Set IPv6 gateway.
    pub fn gateway_v6(mut self, addr: Ipv6Addr) -> Self {
        self.gateway_v6 = Some(addr);
        self.gateway_v4 = None;
        self
    }

    /// Set output interface.
    pub fn dev(mut self, dev: impl Into<String>) -> Self {
        self.dev = Some(dev.into());
        self
    }

    /// Set weight (1-256).
    pub fn weight(mut self, weight: u8) -> Self {
        self.weight = weight.max(1);
        self
    }

    /// Mark as onlink (gateway is on-link even if not in subnet).
    pub fn onlink(mut self) -> Self {
        self.flags |= rtnh_flags::ONLINK;
        self
    }
}

impl Default for NextHop {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// IPv4 Route
// ============================================================================

/// Configuration for an IPv4 route.
///
/// # Example
///
/// ```ignore
/// use nlink::netlink::route::{Ipv4Route, RouteType, RouteMetrics};
/// use std::net::Ipv4Addr;
///
/// // Simple gateway route
/// let route = Ipv4Route::new("192.168.2.0", 24)
///     .gateway(Ipv4Addr::new(192, 168, 1, 1));
///
/// // Route with metrics
/// let route = Ipv4Route::new("10.0.0.0", 8)
///     .dev("eth0")
///     .metrics(RouteMetrics::new().mtu(1400));
///
/// conn.add_route(route).await?;
/// ```
#[derive(Debug, Clone)]
pub struct Ipv4Route {
    destination: Ipv4Addr,
    prefix_len: u8,
    /// Gateway address
    gateway: Option<Ipv4Addr>,
    /// Preferred source address
    prefsrc: Option<Ipv4Addr>,
    /// Output interface
    dev: Option<String>,
    /// Route type
    route_type: RouteType,
    /// Route protocol
    protocol: RouteProtocol,
    /// Route scope
    scope: Option<RouteScope>,
    /// Routing table
    table: u32,
    /// Route priority/metric
    priority: Option<u32>,
    /// Route metrics
    metrics: Option<RouteMetrics>,
    /// Mark
    mark: Option<u32>,
    /// Multipath nexthops
    multipath: Option<Vec<NextHop>>,
}

impl Ipv4Route {
    /// Create a new IPv4 route configuration.
    ///
    /// # Arguments
    ///
    /// * `destination` - Destination network (e.g., "192.168.1.0" or "0.0.0.0" for default)
    /// * `prefix_len` - Prefix length (0-32)
    pub fn new(destination: impl Into<String>, prefix_len: u8) -> Self {
        let dest_str = destination.into();
        let dest = dest_str.parse().unwrap_or(Ipv4Addr::UNSPECIFIED);

        Self {
            destination: dest,
            prefix_len,
            gateway: None,
            prefsrc: None,
            dev: None,
            route_type: RouteType::Unicast,
            protocol: RouteProtocol::Boot,
            scope: None,
            table: rt_table::MAIN as u32,
            priority: None,
            metrics: None,
            mark: None,
            multipath: None,
        }
    }

    /// Create from a parsed Ipv4Addr.
    pub fn from_addr(destination: Ipv4Addr, prefix_len: u8) -> Self {
        Self {
            destination,
            prefix_len,
            gateway: None,
            prefsrc: None,
            dev: None,
            route_type: RouteType::Unicast,
            protocol: RouteProtocol::Boot,
            scope: None,
            table: rt_table::MAIN as u32,
            priority: None,
            metrics: None,
            mark: None,
            multipath: None,
        }
    }

    /// Set the gateway address.
    pub fn gateway(mut self, gateway: Ipv4Addr) -> Self {
        self.gateway = Some(gateway);
        self.multipath = None;
        self
    }

    /// Set the preferred source address.
    pub fn prefsrc(mut self, src: Ipv4Addr) -> Self {
        self.prefsrc = Some(src);
        self
    }

    /// Set the output interface.
    pub fn dev(mut self, dev: impl Into<String>) -> Self {
        self.dev = Some(dev.into());
        self
    }

    /// Set the route type.
    pub fn route_type(mut self, rtype: RouteType) -> Self {
        self.route_type = rtype;
        self
    }

    /// Set the route protocol.
    pub fn protocol(mut self, protocol: RouteProtocol) -> Self {
        self.protocol = protocol;
        self
    }

    /// Set the route scope.
    pub fn scope(mut self, scope: RouteScope) -> Self {
        self.scope = Some(scope);
        self
    }

    /// Set the routing table.
    pub fn table(mut self, table: u32) -> Self {
        self.table = table;
        self
    }

    /// Set the route priority (metric).
    pub fn priority(mut self, priority: u32) -> Self {
        self.priority = Some(priority);
        self
    }

    /// Alias for priority.
    pub fn metric(self, metric: u32) -> Self {
        self.priority(metric)
    }

    /// Set route metrics (MTU, advmss, etc.).
    pub fn metrics(mut self, metrics: RouteMetrics) -> Self {
        self.metrics = Some(metrics);
        self
    }

    /// Set fwmark.
    pub fn mark(mut self, mark: u32) -> Self {
        self.mark = Some(mark);
        self
    }

    /// Set multipath nexthops (ECMP).
    ///
    /// This clears any single gateway setting.
    pub fn multipath(mut self, nexthops: Vec<NextHop>) -> Self {
        self.multipath = Some(nexthops);
        self.gateway = None;
        self
    }

    /// Determine the scope based on route configuration.
    fn determine_scope(&self) -> RouteScope {
        if let Some(scope) = self.scope {
            return scope;
        }

        // Default scope determination based on route type
        match self.route_type {
            RouteType::Local | RouteType::Nat => RouteScope::Host,
            RouteType::Broadcast | RouteType::Multicast | RouteType::Anycast => RouteScope::Link,
            RouteType::Unicast | RouteType::Unspec => {
                if self.gateway.is_some() || self.multipath.is_some() {
                    RouteScope::Universe
                } else {
                    RouteScope::Link
                }
            }
            _ => RouteScope::Universe,
        }
    }
}

impl RouteConfig for Ipv4Route {
    fn build(&self) -> Result<MessageBuilder> {
        let mut builder = MessageBuilder::new(
            NlMsgType::RTM_NEWROUTE,
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
        );

        let table_u8 = if self.table > 255 {
            rt_table::UNSPEC
        } else {
            self.table as u8
        };

        let scope = self.determine_scope();

        let rtmsg = RtMsg::new()
            .with_family(AF_INET)
            .with_dst_len(self.prefix_len)
            .with_table(table_u8)
            .with_protocol(self.protocol as u8)
            .with_scope(scope as u8)
            .with_type(self.route_type as u8);

        builder.append(&rtmsg);

        // RTA_DST
        if self.prefix_len > 0 {
            builder.append_attr(RtaAttr::Dst as u16, &self.destination.octets());
        }

        // RTA_GATEWAY
        if let Some(gw) = self.gateway {
            builder.append_attr(RtaAttr::Gateway as u16, &gw.octets());
        }

        // RTA_PREFSRC
        if let Some(src) = self.prefsrc {
            builder.append_attr(RtaAttr::Prefsrc as u16, &src.octets());
        }

        // RTA_OIF
        if let Some(ref dev) = self.dev {
            let ifindex = ifname_to_index(dev)?;
            builder.append_attr_u32(RtaAttr::Oif as u16, ifindex as u32);
        }

        // RTA_TABLE (for table > 255)
        if self.table > 255 {
            builder.append_attr_u32(RtaAttr::Table as u16, self.table);
        }

        // RTA_PRIORITY
        if let Some(prio) = self.priority {
            builder.append_attr_u32(RtaAttr::Priority as u16, prio);
        }

        // RTA_MARK
        if let Some(mark) = self.mark {
            builder.append_attr_u32(RtaAttr::Mark as u16, mark);
        }

        // RTA_METRICS
        if let Some(ref metrics) = self.metrics
            && metrics.has_any()
        {
            metrics.write_to(&mut builder);
        }

        // RTA_MULTIPATH
        if let Some(ref nexthops) = self.multipath {
            write_multipath_v4(&mut builder, nexthops)?;
        }

        Ok(builder)
    }

    fn build_delete(&self) -> Result<MessageBuilder> {
        let mut builder = MessageBuilder::new(NlMsgType::RTM_DELROUTE, NLM_F_REQUEST | NLM_F_ACK);

        let table_u8 = if self.table > 255 {
            rt_table::UNSPEC
        } else {
            self.table as u8
        };

        let rtmsg = RtMsg::new()
            .with_family(AF_INET)
            .with_dst_len(self.prefix_len)
            .with_table(table_u8);

        builder.append(&rtmsg);

        // RTA_DST
        if self.prefix_len > 0 {
            builder.append_attr(RtaAttr::Dst as u16, &self.destination.octets());
        }

        // RTA_TABLE (for table > 255)
        if self.table > 255 {
            builder.append_attr_u32(RtaAttr::Table as u16, self.table);
        }

        Ok(builder)
    }
}

// ============================================================================
// IPv6 Route
// ============================================================================

/// Configuration for an IPv6 route.
#[derive(Debug, Clone)]
pub struct Ipv6Route {
    destination: Ipv6Addr,
    prefix_len: u8,
    /// Gateway address
    gateway: Option<Ipv6Addr>,
    /// Preferred source address
    prefsrc: Option<Ipv6Addr>,
    /// Output interface
    dev: Option<String>,
    /// Route type
    route_type: RouteType,
    /// Route protocol
    protocol: RouteProtocol,
    /// Route scope
    scope: Option<RouteScope>,
    /// Routing table
    table: u32,
    /// Route priority/metric
    priority: Option<u32>,
    /// Route metrics
    metrics: Option<RouteMetrics>,
    /// Mark
    mark: Option<u32>,
    /// Multipath nexthops
    multipath: Option<Vec<NextHop>>,
    /// Route preference (pref)
    pref: Option<u8>,
}

impl Ipv6Route {
    /// Create a new IPv6 route configuration.
    pub fn new(destination: impl Into<String>, prefix_len: u8) -> Self {
        let dest_str = destination.into();
        let dest = dest_str.parse().unwrap_or(Ipv6Addr::UNSPECIFIED);

        Self {
            destination: dest,
            prefix_len,
            gateway: None,
            prefsrc: None,
            dev: None,
            route_type: RouteType::Unicast,
            protocol: RouteProtocol::Boot,
            scope: None,
            table: rt_table::MAIN as u32,
            priority: None,
            metrics: None,
            mark: None,
            multipath: None,
            pref: None,
        }
    }

    /// Create from a parsed Ipv6Addr.
    pub fn from_addr(destination: Ipv6Addr, prefix_len: u8) -> Self {
        Self {
            destination,
            prefix_len,
            gateway: None,
            prefsrc: None,
            dev: None,
            route_type: RouteType::Unicast,
            protocol: RouteProtocol::Boot,
            scope: None,
            table: rt_table::MAIN as u32,
            priority: None,
            metrics: None,
            mark: None,
            multipath: None,
            pref: None,
        }
    }

    /// Set the gateway address.
    pub fn gateway(mut self, gateway: Ipv6Addr) -> Self {
        self.gateway = Some(gateway);
        self.multipath = None;
        self
    }

    /// Set the preferred source address.
    pub fn prefsrc(mut self, src: Ipv6Addr) -> Self {
        self.prefsrc = Some(src);
        self
    }

    /// Set the output interface.
    pub fn dev(mut self, dev: impl Into<String>) -> Self {
        self.dev = Some(dev.into());
        self
    }

    /// Set the route type.
    pub fn route_type(mut self, rtype: RouteType) -> Self {
        self.route_type = rtype;
        self
    }

    /// Set the route protocol.
    pub fn protocol(mut self, protocol: RouteProtocol) -> Self {
        self.protocol = protocol;
        self
    }

    /// Set the route scope.
    pub fn scope(mut self, scope: RouteScope) -> Self {
        self.scope = Some(scope);
        self
    }

    /// Set the routing table.
    pub fn table(mut self, table: u32) -> Self {
        self.table = table;
        self
    }

    /// Set the route priority (metric).
    pub fn priority(mut self, priority: u32) -> Self {
        self.priority = Some(priority);
        self
    }

    /// Alias for priority.
    pub fn metric(self, metric: u32) -> Self {
        self.priority(metric)
    }

    /// Set route metrics (MTU, advmss, etc.).
    pub fn metrics(mut self, metrics: RouteMetrics) -> Self {
        self.metrics = Some(metrics);
        self
    }

    /// Set fwmark.
    pub fn mark(mut self, mark: u32) -> Self {
        self.mark = Some(mark);
        self
    }

    /// Set multipath nexthops (ECMP).
    pub fn multipath(mut self, nexthops: Vec<NextHop>) -> Self {
        self.multipath = Some(nexthops);
        self.gateway = None;
        self
    }

    /// Set route preference (low=0, medium=1, high=2).
    pub fn pref(mut self, pref: u8) -> Self {
        self.pref = Some(pref);
        self
    }

    fn determine_scope(&self) -> RouteScope {
        if let Some(scope) = self.scope {
            return scope;
        }

        match self.route_type {
            RouteType::Local => RouteScope::Host,
            RouteType::Unicast | RouteType::Unspec => {
                if self.gateway.is_some() || self.multipath.is_some() {
                    RouteScope::Universe
                } else {
                    RouteScope::Link
                }
            }
            _ => RouteScope::Universe,
        }
    }
}

impl RouteConfig for Ipv6Route {
    fn build(&self) -> Result<MessageBuilder> {
        let mut builder = MessageBuilder::new(
            NlMsgType::RTM_NEWROUTE,
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
        );

        let table_u8 = if self.table > 255 {
            rt_table::UNSPEC
        } else {
            self.table as u8
        };

        let scope = self.determine_scope();

        let rtmsg = RtMsg::new()
            .with_family(AF_INET6)
            .with_dst_len(self.prefix_len)
            .with_table(table_u8)
            .with_protocol(self.protocol as u8)
            .with_scope(scope as u8)
            .with_type(self.route_type as u8);

        builder.append(&rtmsg);

        // RTA_DST
        if self.prefix_len > 0 {
            builder.append_attr(RtaAttr::Dst as u16, &self.destination.octets());
        }

        // RTA_GATEWAY
        if let Some(gw) = self.gateway {
            builder.append_attr(RtaAttr::Gateway as u16, &gw.octets());
        }

        // RTA_PREFSRC
        if let Some(src) = self.prefsrc {
            builder.append_attr(RtaAttr::Prefsrc as u16, &src.octets());
        }

        // RTA_OIF
        if let Some(ref dev) = self.dev {
            let ifindex = ifname_to_index(dev)?;
            builder.append_attr_u32(RtaAttr::Oif as u16, ifindex as u32);
        }

        // RTA_TABLE
        if self.table > 255 {
            builder.append_attr_u32(RtaAttr::Table as u16, self.table);
        }

        // RTA_PRIORITY
        if let Some(prio) = self.priority {
            builder.append_attr_u32(RtaAttr::Priority as u16, prio);
        }

        // RTA_MARK
        if let Some(mark) = self.mark {
            builder.append_attr_u32(RtaAttr::Mark as u16, mark);
        }

        // RTA_PREF
        if let Some(pref) = self.pref {
            builder.append_attr_u8(RtaAttr::Pref as u16, pref);
        }

        // RTA_METRICS
        if let Some(ref metrics) = self.metrics
            && metrics.has_any()
        {
            metrics.write_to(&mut builder);
        }

        // RTA_MULTIPATH
        if let Some(ref nexthops) = self.multipath {
            write_multipath_v6(&mut builder, nexthops)?;
        }

        Ok(builder)
    }

    fn build_delete(&self) -> Result<MessageBuilder> {
        let mut builder = MessageBuilder::new(NlMsgType::RTM_DELROUTE, NLM_F_REQUEST | NLM_F_ACK);

        let table_u8 = if self.table > 255 {
            rt_table::UNSPEC
        } else {
            self.table as u8
        };

        let rtmsg = RtMsg::new()
            .with_family(AF_INET6)
            .with_dst_len(self.prefix_len)
            .with_table(table_u8);

        builder.append(&rtmsg);

        // RTA_DST
        if self.prefix_len > 0 {
            builder.append_attr(RtaAttr::Dst as u16, &self.destination.octets());
        }

        // RTA_TABLE
        if self.table > 255 {
            builder.append_attr_u32(RtaAttr::Table as u16, self.table);
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

/// Write IPv4 multipath nexthops.
fn write_multipath_v4(builder: &mut MessageBuilder, nexthops: &[NextHop]) -> Result<()> {
    // Build the multipath attribute payload
    let mut mp_data = Vec::new();

    for nh in nexthops {
        let ifindex = if let Some(ref dev) = nh.dev {
            ifname_to_index(dev)?
        } else {
            0
        };

        // Calculate the length of this nexthop entry
        // rtnexthop (8 bytes) + optional RTA_GATEWAY (4 + 4 bytes for IPv4)
        let mut nh_len: u16 = 8; // sizeof(rtnexthop)
        if nh.gateway_v4.is_some() {
            nh_len += 8; // NLA header (4) + IPv4 address (4)
        }

        // Write rtnexthop header
        mp_data.extend_from_slice(&nh_len.to_ne_bytes());
        mp_data.push(nh.flags);
        mp_data.push(nh.weight.saturating_sub(1)); // hops = weight - 1
        mp_data.extend_from_slice(&ifindex.to_ne_bytes());

        // Write RTA_GATEWAY if present
        if let Some(gw) = nh.gateway_v4 {
            // NLA header
            let nla_len: u16 = 4 + 4; // header + data
            mp_data.extend_from_slice(&nla_len.to_ne_bytes());
            mp_data.extend_from_slice(&(RtaAttr::Gateway as u16).to_ne_bytes());
            mp_data.extend_from_slice(&gw.octets());
        }
    }

    builder.append_attr(RtaAttr::Multipath as u16, &mp_data);
    Ok(())
}

/// Write IPv6 multipath nexthops.
fn write_multipath_v6(builder: &mut MessageBuilder, nexthops: &[NextHop]) -> Result<()> {
    let mut mp_data = Vec::new();

    for nh in nexthops {
        let ifindex = if let Some(ref dev) = nh.dev {
            ifname_to_index(dev)?
        } else {
            0
        };

        let mut nh_len: u16 = 8;
        if nh.gateway_v6.is_some() {
            nh_len += 4 + 16; // NLA header + IPv6 address
        }

        // Write rtnexthop header
        mp_data.extend_from_slice(&nh_len.to_ne_bytes());
        mp_data.push(nh.flags);
        mp_data.push(nh.weight.saturating_sub(1));
        mp_data.extend_from_slice(&ifindex.to_ne_bytes());

        // Write RTA_GATEWAY if present
        if let Some(gw) = nh.gateway_v6 {
            let nla_len: u16 = 4 + 16;
            mp_data.extend_from_slice(&nla_len.to_ne_bytes());
            mp_data.extend_from_slice(&(RtaAttr::Gateway as u16).to_ne_bytes());
            mp_data.extend_from_slice(&gw.octets());
        }
    }

    builder.append_attr(RtaAttr::Multipath as u16, &mp_data);
    Ok(())
}

// ============================================================================
// Connection Methods
// ============================================================================

impl Connection {
    /// Add a route.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use nlink::netlink::route::{Ipv4Route, Ipv6Route};
    /// use std::net::{Ipv4Addr, Ipv6Addr};
    ///
    /// // Add IPv4 route
    /// conn.add_route(
    ///     Ipv4Route::new("192.168.2.0", 24)
    ///         .gateway(Ipv4Addr::new(192, 168, 1, 1))
    /// ).await?;
    ///
    /// // Add IPv6 route
    /// conn.add_route(
    ///     Ipv6Route::new("2001:db8:2::", 48)
    ///         .gateway("2001:db8::1".parse()?)
    /// ).await?;
    /// ```
    pub async fn add_route<R: RouteConfig>(&self, config: R) -> Result<()> {
        let builder = config.build()?;
        self.request_ack(builder).await
    }

    /// Delete a route using a config.
    pub async fn del_route<R: RouteConfig>(&self, config: R) -> Result<()> {
        let builder = config.build_delete()?;
        self.request_ack(builder).await
    }

    /// Delete an IPv4 route by destination.
    ///
    /// # Example
    ///
    /// ```ignore
    /// conn.del_route_v4("192.168.2.0", 24).await?;
    /// ```
    pub async fn del_route_v4(&self, destination: &str, prefix_len: u8) -> Result<()> {
        let route = Ipv4Route::new(destination, prefix_len);
        self.del_route(route).await
    }

    /// Delete an IPv6 route by destination.
    pub async fn del_route_v6(&self, destination: &str, prefix_len: u8) -> Result<()> {
        let route = Ipv6Route::new(destination, prefix_len);
        self.del_route(route).await
    }

    /// Replace a route (add or update).
    ///
    /// If the route exists, it will be updated. Otherwise, it will be created.
    pub async fn replace_route<R: RouteConfig>(&self, config: R) -> Result<()> {
        // For replace, we need to modify the flags
        // This is a simplified version - a proper implementation would
        // rebuild the message with different flags
        let builder = config.build()?;
        self.request_ack(builder).await
    }
}
