//! High-level rate limiting API.
//!
//! This module provides a simplified API for common rate limiting use cases,
//! abstracting away the complexity of TC (Traffic Control) configuration.
//!
//! # Overview
//!
//! The rate limiting API provides two main types:
//!
//! - [`RateLimiter`]: Simple interface-wide rate limiting for egress and ingress traffic
//! - [`PerHostLimiter`]: Per-IP or per-subnet rate limiting with customizable rules
//!
//! # Example
//!
//! ```ignore
//! use nlink::netlink::{Connection, Route};
//! use nlink::netlink::ratelimit::RateLimiter;
//! use std::time::Duration;
//!
//! let conn = Connection::<Route>::new()?;
//!
//! // Simple rate limiting
//! RateLimiter::new("eth0")
//!     .egress("100mbit")?
//!     .ingress("1gbit")?
//!     .burst_to("150mbit")?
//!     .latency(Duration::from_millis(20))
//!     .apply(&conn)
//!     .await?;
//!
//! // Remove limits
//! RateLimiter::new("eth0")
//!     .remove(&conn)
//!     .await?;
//! ```
//!
//! # Implementation Details
//!
//! Under the hood, the rate limiter uses:
//! - **Egress**: HTB qdisc with a single class + fq_codel leaf for AQM
//! - **Ingress**: IFB device + ingress qdisc + mirred redirect + HTB on IFB
//!
//! ```text
//! Egress:
//!   eth0 -> HTB root (1:) -> HTB class (1:1, rate limited) -> fq_codel
//!
//! Ingress:
//!   eth0 ingress -> matchall filter -> mirred redirect -> ifb_eth0 -> HTB -> fq_codel
//! ```

use std::{net::IpAddr, time::Duration};

use super::{
    Connection,
    error::{Error, Result},
    link::IfbLink,
    protocol::Route,
    tc::{FqCodelConfig, HtbClassConfig, HtbQdiscConfig, IngressConfig},
    tc_handle::TcHandle,
};

// ============================================================================
// RateLimit
// ============================================================================

/// Rate limit configuration.
#[derive(Debug, Clone)]
pub struct RateLimit {
    /// Guaranteed rate.
    pub rate: crate::util::Rate,
    /// Maximum burst rate (ceiling).
    pub ceil: Option<crate::util::Rate>,
    /// Burst size.
    pub burst: Option<crate::util::Bytes>,
    /// Latency target for AQM (Active Queue Management).
    pub latency: Option<Duration>,
}

impl RateLimit {
    /// Create a new rate limit with the specified rate.
    pub fn new(rate: crate::util::Rate) -> Self {
        Self {
            rate,
            ceil: None,
            burst: None,
            latency: None,
        }
    }

    /// Set the ceiling rate (maximum burst rate).
    pub fn ceil(mut self, ceil: crate::util::Rate) -> Self {
        self.ceil = Some(ceil);
        self
    }

    /// Set the burst size.
    pub fn burst(mut self, burst: crate::util::Bytes) -> Self {
        self.burst = Some(burst);
        self
    }

    /// Set the latency target for AQM.
    pub fn latency(mut self, latency: Duration) -> Self {
        self.latency = Some(latency);
        self
    }
}

// ============================================================================
// RateLimiter
// ============================================================================

/// High-level rate limiter for an interface.
///
/// Provides a simple API for rate limiting both egress (upload) and ingress (download)
/// traffic on a network interface.
///
/// # Example
///
/// ```ignore
/// use nlink::netlink::{Connection, Route};
/// use nlink::netlink::ratelimit::RateLimiter;
///
/// let conn = Connection::<Route>::new()?;
///
/// // Limit egress to 100 Mbps, ingress to 1 Gbps
/// RateLimiter::new("eth0")
///     .egress("100mbit")?
///     .ingress("1gbit")?
///     .apply(&conn)
///     .await?;
/// ```
#[derive(Debug, Clone)]
pub struct RateLimiter {
    /// Target interface name.
    dev: String,
    /// Egress (upload) rate limit.
    egress: Option<RateLimit>,
    /// Ingress (download) rate limit.
    ingress: Option<RateLimit>,
}

impl RateLimiter {
    /// Create a new rate limiter for the specified interface.
    pub fn new(dev: &str) -> Self {
        Self {
            dev: dev.to_string(),
            egress: None,
            ingress: None,
        }
    }

    /// Set the egress (upload) rate limit.
    pub fn egress(mut self, rate: crate::util::Rate) -> Self {
        self.egress = Some(RateLimit::new(rate));
        self
    }

    /// Set the ingress (download) rate limit.
    pub fn ingress(mut self, rate: crate::util::Rate) -> Self {
        self.ingress = Some(RateLimit::new(rate));
        self
    }

    /// Set the ceiling rate for bursting (applies to both egress and ingress).
    pub fn burst_to(mut self, ceil: crate::util::Rate) -> Self {
        if let Some(ref mut egress) = self.egress {
            egress.ceil = Some(ceil);
        }
        if let Some(ref mut ingress) = self.ingress {
            ingress.ceil = Some(ceil);
        }
        self
    }

    /// Set the burst buffer size (applies to both egress and ingress).
    pub fn burst_size(mut self, size: crate::util::Bytes) -> Self {
        if let Some(ref mut egress) = self.egress {
            egress.burst = Some(size);
        }
        if let Some(ref mut ingress) = self.ingress {
            ingress.burst = Some(size);
        }
        self
    }

    /// Set the latency target for AQM (applies to both egress and ingress).
    pub fn latency(mut self, latency: Duration) -> Self {
        if let Some(ref mut egress) = self.egress {
            egress.latency = Some(latency);
        }
        if let Some(ref mut ingress) = self.ingress {
            ingress.latency = Some(latency);
        }
        self
    }

    /// Apply the rate limits.
    ///
    /// This configures the TC (Traffic Control) subsystem to enforce the
    /// specified rate limits.
    pub async fn apply(&self, conn: &Connection<Route>) -> Result<()> {
        // Apply egress rate limiting
        if let Some(ref egress) = self.egress {
            self.apply_egress(conn, egress).await?;
        }

        // Apply ingress rate limiting
        if let Some(ref ingress) = self.ingress {
            self.apply_ingress(conn, ingress).await?;
        }

        Ok(())
    }

    /// Remove all rate limits from the interface.
    pub async fn remove(&self, conn: &Connection<Route>) -> Result<()> {
        // Remove egress qdisc (this removes all egress TC config)
        let _ = conn.del_qdisc(&self.dev, TcHandle::ROOT).await;

        // Remove ingress qdisc
        let _ = conn.del_qdisc(&self.dev, TcHandle::INGRESS).await;

        // Remove IFB device if it exists
        let ifb_name = self.ifb_name();
        let _ = conn.del_link(&ifb_name).await;

        Ok(())
    }

    /// Get the IFB device name for this interface.
    fn ifb_name(&self) -> String {
        // Truncate to fit in IFNAMSIZ (16 bytes including null)
        let prefix = "ifb_";
        let max_dev_len = 15 - prefix.len();
        let dev_part = if self.dev.len() > max_dev_len {
            &self.dev[..max_dev_len]
        } else {
            &self.dev
        };
        format!("{}{}", prefix, dev_part)
    }

    /// Apply egress rate limiting using HTB.
    async fn apply_egress(&self, conn: &Connection<Route>, limit: &RateLimit) -> Result<()> {
        // Remove existing root qdisc (ignore errors if none exists)
        let _ = conn.del_qdisc(&self.dev, TcHandle::ROOT).await;

        // Add HTB qdisc at root
        let htb = HtbQdiscConfig::new()
            .default_class(0x10)
            .handle("1:")
            .build();
        conn.add_qdisc(&self.dev, htb).await?;

        // Add root class (1:1) for the rate limit
        let mut class_config = HtbClassConfig::new(limit.rate);
        if let Some(ceil) = limit.ceil {
            class_config = class_config.ceil(ceil);
        }
        if let Some(burst) = limit.burst {
            class_config = class_config.burst(burst);
        }
        conn.add_class_config(
            &self.dev,
            TcHandle::major_only(1),
            TcHandle::new(1, 1),
            class_config.build(),
        )
        .await?;

        // Add default class (1:10) under the root class
        let mut default_config = HtbClassConfig::new(limit.rate);
        if let Some(ceil) = limit.ceil {
            default_config = default_config.ceil(ceil);
        }
        if let Some(burst) = limit.burst {
            default_config = default_config.burst(burst);
        }
        conn.add_class_config(
            &self.dev,
            TcHandle::new(1, 1),
            TcHandle::new(1, 10),
            default_config.build(),
        )
        .await?;

        // Add fq_codel as leaf qdisc for AQM
        let mut fq_codel = FqCodelConfig::new().parent("1:10").handle("10:");
        if let Some(latency) = limit.latency {
            fq_codel = fq_codel.target(latency);
        }
        conn.add_qdisc_full(
            &self.dev,
            TcHandle::new(1, 10),
            Some(TcHandle::major_only(10)),
            fq_codel.build(),
        )
        .await?;

        Ok(())
    }

    /// Apply ingress rate limiting using IFB.
    async fn apply_ingress(&self, conn: &Connection<Route>, limit: &RateLimit) -> Result<()> {
        let ifb_name = self.ifb_name();

        // Create IFB device if it doesn't exist
        if conn.get_link_by_name(&ifb_name).await?.is_none() {
            conn.add_link(IfbLink::new(&ifb_name)).await?;
        }

        // Bring IFB device up
        conn.set_link_up(&ifb_name).await?;

        // Remove existing ingress qdisc on the main interface
        let _ = conn.del_qdisc(&self.dev, TcHandle::INGRESS).await;

        // Add ingress qdisc to the main interface
        conn.add_qdisc_full(&self.dev, TcHandle::INGRESS, None, IngressConfig::new())
            .await?;

        // Add filter to redirect ingress traffic to IFB
        // We need to use a filter with mirred action
        self.add_ingress_redirect(conn, &ifb_name).await?;

        // Now configure HTB on the IFB device
        // Remove existing root qdisc on IFB
        let _ = conn.del_qdisc(&ifb_name, TcHandle::ROOT).await;

        // Add HTB qdisc at root of IFB
        let htb = HtbQdiscConfig::new()
            .default_class(0x10)
            .handle("1:")
            .build();
        conn.add_qdisc(&ifb_name, htb).await?;

        // Add root class (1:1) for the rate limit
        let mut class_config = HtbClassConfig::new(limit.rate);
        if let Some(ceil) = limit.ceil {
            class_config = class_config.ceil(ceil);
        }
        if let Some(burst) = limit.burst {
            class_config = class_config.burst(burst);
        }
        conn.add_class_config(
            &ifb_name,
            TcHandle::major_only(1),
            TcHandle::new(1, 1),
            class_config.build(),
        )
        .await?;

        // Add default class (1:10) under the root class
        let mut default_config = HtbClassConfig::new(limit.rate);
        if let Some(ceil) = limit.ceil {
            default_config = default_config.ceil(ceil);
        }
        if let Some(burst) = limit.burst {
            default_config = default_config.burst(burst);
        }
        conn.add_class_config(
            &ifb_name,
            TcHandle::new(1, 1),
            TcHandle::new(1, 10),
            default_config.build(),
        )
        .await?;

        // Add fq_codel as leaf qdisc for AQM
        let mut fq_codel = FqCodelConfig::new().parent("1:10").handle("10:");
        if let Some(latency) = limit.latency {
            fq_codel = fq_codel.target(latency);
        }
        conn.add_qdisc_full(
            &ifb_name,
            TcHandle::new(1, 10),
            Some(TcHandle::major_only(10)),
            fq_codel.build(),
        )
        .await?;

        Ok(())
    }

    /// Add ingress redirect filter using u32 filter with mirred action.
    async fn add_ingress_redirect(&self, conn: &Connection<Route>, ifb_name: &str) -> Result<()> {
        // Get IFB interface index
        let ifb_link = conn
            .get_link_by_name(ifb_name)
            .await?
            .ok_or_else(|| Error::InvalidMessage(format!("IFB device not found: {}", ifb_name)))?;
        let ifb_ifindex = ifb_link.ifindex();

        // Add a u32 filter with mirred redirect action
        // We use the low-level API since matchall doesn't support arbitrary actions yet
        self.add_u32_redirect_filter(conn, ifb_ifindex).await
    }

    /// Add u32 filter with mirred redirect action.
    async fn add_u32_redirect_filter(
        &self,
        conn: &Connection<Route>,
        ifb_ifindex: u32,
    ) -> Result<()> {
        use super::{
            connection::ack_request,
            message::NlMsgType,
            types::tc::{
                TcMsg, TcaAttr,
                action::{self, mirred},
                filter::u32 as u32_mod,
                tc_handle,
            },
        };

        // Get interface index
        let link = conn
            .get_link_by_name(&self.dev)
            .await?
            .ok_or_else(|| Error::InvalidMessage(format!("interface not found: {}", self.dev)))?;
        let ifindex = link.ifindex();

        // Build the message
        let tcmsg = TcMsg::new()
            .with_ifindex(ifindex as i32)
            .with_parent(tc_handle::INGRESS)
            .with_info((0x0003u16 as u32) << 16 | 1); // ETH_P_ALL, priority 1

        let mut builder = ack_request(NlMsgType::RTM_NEWTFILTER);
        builder.append(&tcmsg);
        builder.append_attr_str(TcaAttr::Kind as u16, "u32");

        // Options
        let opt_token = builder.nest_start(TcaAttr::Options as u16);

        // Match all packets: match u32 0 0 at 0
        let sel_token = builder.nest_start(u32_mod::TCA_U32_SEL);
        // TcU32Sel header + one key (total 28 bytes)
        // Header: flags=0, offshift=0, nkeys=1, offmask=0, off=0, offoff=0, hoff=0, hmask=0
        // Key: val=0, mask=0, off=0, offmask=0 (matches everything)
        let sel_data: [u8; 28] = [
            0, 0, 1, 0, // flags, offshift, nkeys, offmask
            0, 0, 0, 0, // off, offoff (16-bit each)
            0, 0, 0, 0, // hoff, hmask (16-bit each)
            // Key starts here (16 bytes)
            0, 0, 0, 0, // val (matches anything when mask is 0)
            0, 0, 0, 0, // mask (0 = match all)
            0, 0, 0, 0, // off (offset in packet)
            0, 0, 0, 0, // offmask
        ];
        builder.append_bytes(&sel_data);
        builder.nest_end(sel_token);

        // Add mirred action
        let act_token = builder.nest_start(u32_mod::TCA_U32_ACT);

        // Action 1: mirred redirect
        let act1_token = builder.nest_start(1);
        builder.append_attr_str(action::TCA_ACT_KIND, "mirred");

        let mirred_opt_token = builder.nest_start(action::TCA_ACT_OPTIONS);
        let mirred_parms = mirred::TcMirred::new(
            mirred::TCA_INGRESS_REDIR,
            ifb_ifindex,
            action::TC_ACT_STOLEN,
        );
        builder.append_attr(mirred::TCA_MIRRED_PARMS, mirred_parms.as_bytes());
        builder.nest_end(mirred_opt_token);

        builder.nest_end(act1_token);
        builder.nest_end(act_token);

        builder.nest_end(opt_token);

        conn.send_ack(builder).await?;
        Ok(())
    }
}

// ============================================================================
// PerHostLimiter
// ============================================================================

/// Per-IP or per-subnet rate limiting.
///
/// Allows setting different rate limits for different hosts or subnets.
///
/// # Example
///
/// ```ignore
/// use nlink::netlink::{Connection, Route};
/// use nlink::netlink::ratelimit::PerHostLimiter;
///
/// let conn = Connection::<Route>::new()?;
///
/// PerHostLimiter::new("eth0", "10mbit")?
///     .limit_ip("192.168.1.100".parse()?, "100mbit")?
///     .limit_subnet("10.0.0.0/8", "50mbit")?
///     .limit_port(80, "500mbit")?
///     .apply(&conn)
///     .await?;
/// ```
#[derive(Debug, Clone)]
pub struct PerHostLimiter {
    /// Target interface name.
    dev: String,
    /// Default rate.
    default_rate: crate::util::Rate,
    /// Per-host rules.
    rules: Vec<HostRule>,
    /// Latency target for AQM.
    latency: Option<Duration>,
}

/// A rate limiting rule for a specific host or match condition.
#[derive(Debug, Clone)]
pub struct HostRule {
    /// Match condition.
    match_: HostMatch,
    /// Rate limit.
    rate: crate::util::Rate,
    /// Ceiling rate.
    ceil: Option<crate::util::Rate>,
}

/// Match condition for per-host limiting.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum HostMatch {
    /// Match a specific IP address.
    Ip(IpAddr),
    /// Match a subnet (address and prefix length).
    Subnet(IpAddr, u8),
    /// Match a destination port.
    Port(u16),
    /// Match a port range.
    PortRange(u16, u16),
    /// Match source IP address.
    SrcIp(IpAddr),
    /// Match source subnet.
    SrcSubnet(IpAddr, u8),
}

impl PerHostLimiter {
    /// Create a new per-host rate limiter with a default rate for unmatched
    /// traffic.
    pub fn new(dev: &str, default_rate: crate::util::Rate) -> Self {
        Self {
            dev: dev.to_string(),
            default_rate,
            rules: Vec::new(),
            latency: None,
        }
    }

    /// Add a rate limit for a specific IP address.
    pub fn limit_ip(mut self, ip: IpAddr, rate: crate::util::Rate) -> Self {
        self.rules.push(HostRule {
            match_: HostMatch::Ip(ip),
            rate,
            ceil: None,
        });
        self
    }

    /// Add a rate limit for a specific IP address with ceiling.
    pub fn limit_ip_with_ceil(
        mut self,
        ip: IpAddr,
        rate: crate::util::Rate,
        ceil: crate::util::Rate,
    ) -> Self {
        self.rules.push(HostRule {
            match_: HostMatch::Ip(ip),
            rate,
            ceil: Some(ceil),
        });
        self
    }

    /// Add a rate limit for a subnet.
    pub fn limit_subnet(mut self, subnet: &str, rate: crate::util::Rate) -> Result<Self> {
        let (addr, prefix) = parse_subnet(subnet)?;
        self.rules.push(HostRule {
            match_: HostMatch::Subnet(addr, prefix),
            rate,
            ceil: None,
        });
        Ok(self)
    }

    /// Add a rate limit for a source IP address.
    pub fn limit_src_ip(mut self, ip: IpAddr, rate: crate::util::Rate) -> Self {
        self.rules.push(HostRule {
            match_: HostMatch::SrcIp(ip),
            rate,
            ceil: None,
        });
        self
    }

    /// Add a rate limit for a source subnet.
    pub fn limit_src_subnet(mut self, subnet: &str, rate: crate::util::Rate) -> Result<Self> {
        let (addr, prefix) = parse_subnet(subnet)?;
        self.rules.push(HostRule {
            match_: HostMatch::SrcSubnet(addr, prefix),
            rate,
            ceil: None,
        });
        Ok(self)
    }

    /// Add a rate limit for a destination port.
    pub fn limit_port(mut self, port: u16, rate: crate::util::Rate) -> Self {
        self.rules.push(HostRule {
            match_: HostMatch::Port(port),
            rate,
            ceil: None,
        });
        self
    }

    /// Add a rate limit for a port range.
    pub fn limit_port_range(mut self, start: u16, end: u16, rate: crate::util::Rate) -> Self {
        self.rules.push(HostRule {
            match_: HostMatch::PortRange(start, end),
            rate,
            ceil: None,
        });
        self
    }

    /// Set the latency target for AQM.
    pub fn latency(mut self, latency: Duration) -> Self {
        self.latency = Some(latency);
        self
    }

    /// Apply the per-host rate limits.
    pub async fn apply(&self, conn: &Connection<Route>) -> Result<()> {
        // Remove existing root qdisc
        let _ = conn.del_qdisc(&self.dev, TcHandle::ROOT).await;

        // Add HTB qdisc at root
        // Default class will be the last one (for unmatched traffic)
        let default_classid = (self.rules.len() + 1) as u32;
        let htb = HtbQdiscConfig::new()
            .default_class(default_classid)
            .handle("1:")
            .build();
        conn.add_qdisc(&self.dev, htb).await?;

        // Add root class (1:1) with sum of all rates as ceiling
        let parent_classid = TcHandle::new(1, 1);
        let major_only_1 = TcHandle::major_only(1);
        let total_rate: crate::util::Rate =
            self.default_rate + self.rules.iter().map(|r| r.rate).sum::<crate::util::Rate>();
        let root_config = HtbClassConfig::new(total_rate).ceil(total_rate).build();
        conn.add_class_config(&self.dev, major_only_1, parent_classid, root_config)
            .await?;

        // Add classes for each rule
        for (i, rule) in self.rules.iter().enumerate() {
            let classid = TcHandle::new(1, (i + 2) as u16);
            let leaf_handle = TcHandle::major_only((i + 10) as u16);
            let class_config = HtbClassConfig::new(rule.rate).ceil(rule.ceil.unwrap_or(rule.rate));
            conn.add_class_config(&self.dev, parent_classid, classid, class_config.build())
                .await?;

            // Add fq_codel leaf qdisc
            let mut fq_codel = FqCodelConfig::new()
                .parent(classid.to_string())
                .handle(leaf_handle.to_string());
            if let Some(latency) = self.latency {
                fq_codel = fq_codel.target(latency);
            }
            conn.add_qdisc_full(&self.dev, classid, Some(leaf_handle), fq_codel.build())
                .await?;

            // Add flower filter to classify traffic to this class
            self.add_filter_for_rule(conn, i, rule).await?;
        }

        // Add default class for unmatched traffic
        let default_classid = TcHandle::new(1, (self.rules.len() + 2) as u16);
        let default_handle = TcHandle::major_only((self.rules.len() + 10) as u16);
        let default_config = HtbClassConfig::new(self.default_rate)
            .ceil(self.default_rate)
            .build();
        conn.add_class_config(&self.dev, parent_classid, default_classid, default_config)
            .await?;

        // Add fq_codel leaf for default class
        let mut fq_codel = FqCodelConfig::new()
            .parent(default_classid.to_string())
            .handle(default_handle.to_string());
        if let Some(latency) = self.latency {
            fq_codel = fq_codel.target(latency);
        }
        conn.add_qdisc_full(
            &self.dev,
            default_classid,
            Some(default_handle),
            fq_codel.build(),
        )
        .await?;

        Ok(())
    }

    /// Remove the per-host rate limits.
    pub async fn remove(&self, conn: &Connection<Route>) -> Result<()> {
        let _ = conn.del_qdisc(&self.dev, TcHandle::ROOT).await;
        Ok(())
    }

    /// Add a flower filter for a specific rule.
    async fn add_filter_for_rule(
        &self,
        conn: &Connection<Route>,
        index: usize,
        rule: &HostRule,
    ) -> Result<()> {
        use super::filter::FlowerFilter;

        // tcm_info etherproto values. The kernel walks the per-protocol
        // dispatch table before flower's own KEY_ETH_TYPE attribute is
        // consulted, so passing the wrong value here means the filter
        // never matches its intended packets.
        const ETH_P_IP: u16 = 0x0800;
        const ETH_P_IPV6: u16 = 0x86DD;

        let classid = format!("1:{:x}", index + 2);
        let priority = (index + 1) as u16;

        match &rule.match_ {
            HostMatch::Ip(ip) | HostMatch::Subnet(ip, _) => {
                let prefix = match &rule.match_ {
                    HostMatch::Subnet(_, p) => *p,
                    _ => {
                        if ip.is_ipv4() {
                            32
                        } else {
                            128
                        }
                    }
                };

                match ip {
                    IpAddr::V4(addr) => {
                        let filter = FlowerFilter::new()
                            .classid(&classid)
                            .priority(priority)
                            .dst_ipv4(*addr, prefix)
                            .build();
                        conn.add_filter_full(
                            &self.dev,
                            TcHandle::major_only(1),
                            None,
                            ETH_P_IP,
                            priority,
                            filter,
                        )
                        .await?;
                    }
                    IpAddr::V6(addr) => {
                        let filter = FlowerFilter::new()
                            .classid(&classid)
                            .priority(priority)
                            .dst_ipv6(*addr, prefix)
                            .build();
                        conn.add_filter_full(
                            &self.dev,
                            TcHandle::major_only(1),
                            None,
                            ETH_P_IPV6,
                            priority,
                            filter,
                        )
                        .await?;
                    }
                }
            }
            HostMatch::SrcIp(ip) | HostMatch::SrcSubnet(ip, _) => {
                let prefix = match &rule.match_ {
                    HostMatch::SrcSubnet(_, p) => *p,
                    _ => {
                        if ip.is_ipv4() {
                            32
                        } else {
                            128
                        }
                    }
                };

                match ip {
                    IpAddr::V4(addr) => {
                        let filter = FlowerFilter::new()
                            .classid(&classid)
                            .priority(priority)
                            .src_ipv4(*addr, prefix)
                            .build();
                        conn.add_filter_full(
                            &self.dev,
                            TcHandle::major_only(1),
                            None,
                            ETH_P_IP,
                            priority,
                            filter,
                        )
                        .await?;
                    }
                    IpAddr::V6(addr) => {
                        let filter = FlowerFilter::new()
                            .classid(&classid)
                            .priority(priority)
                            .src_ipv6(*addr, prefix)
                            .build();
                        conn.add_filter_full(
                            &self.dev,
                            TcHandle::major_only(1),
                            None,
                            ETH_P_IPV6,
                            priority,
                            filter,
                        )
                        .await?;
                    }
                }
            }
            HostMatch::Port(port) => {
                // Match both TCP and UDP. L4 port matching at the IP layer
                // dispatches under ETH_P_IP.
                let tcp_filter = FlowerFilter::new()
                    .classid(&classid)
                    .priority(priority)
                    .ip_proto_tcp()
                    .dst_port(*port)
                    .build();
                conn.add_filter_full(
                    &self.dev,
                    TcHandle::major_only(1),
                    None,
                    ETH_P_IP,
                    priority,
                    tcp_filter,
                )
                .await?;

                let udp_filter = FlowerFilter::new()
                    .classid(&classid)
                    .priority(priority + 100) // Different priority to avoid conflict
                    .ip_proto_udp()
                    .dst_port(*port)
                    .build();
                conn.add_filter_full(
                    &self.dev,
                    TcHandle::major_only(1),
                    None,
                    ETH_P_IP,
                    priority + 100,
                    udp_filter,
                )
                .await?;
            }
            HostMatch::PortRange(start, end) => {
                // For port ranges, we need to add individual filters or use u32
                // For simplicity, we'll add filters for each port in small ranges
                // or skip for large ranges
                if *end - *start <= 10 {
                    for port in *start..=*end {
                        let filter = FlowerFilter::new()
                            .classid(&classid)
                            .priority(priority)
                            .ip_proto_tcp()
                            .dst_port(port)
                            .build();
                        let _ = conn
                            .add_filter_full(
                                &self.dev,
                                TcHandle::major_only(1),
                                None,
                                ETH_P_IP,
                                priority,
                                filter,
                            )
                            .await;
                    }
                }
                // For larger ranges, we'd need u32 filter with masks
            }
        }

        Ok(())
    }
}

/// Parse a subnet string like "10.0.0.0/8" into address and prefix length.
fn parse_subnet(subnet: &str) -> Result<(IpAddr, u8)> {
    let parts: Vec<&str> = subnet.split('/').collect();
    if parts.len() != 2 {
        return Err(Error::InvalidMessage(format!(
            "invalid subnet format: {}",
            subnet
        )));
    }

    let addr: IpAddr = parts[0]
        .parse()
        .map_err(|_| Error::InvalidMessage(format!("invalid IP address: {}", parts[0])))?;

    let prefix: u8 = parts[1]
        .parse()
        .map_err(|_| Error::InvalidMessage(format!("invalid prefix length: {}", parts[1])))?;

    // Validate prefix length
    let max_prefix = if addr.is_ipv4() { 32 } else { 128 };
    if prefix > max_prefix {
        return Err(Error::InvalidMessage(format!(
            "prefix length {} exceeds maximum {} for address type",
            prefix, max_prefix
        )));
    }

    Ok((addr, prefix))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rate_limit_new() {
        use crate::util::Rate;
        let limit = RateLimit::new(Rate::bytes_per_sec(1_000_000));
        assert_eq!(limit.rate, Rate::bytes_per_sec(1_000_000));
        assert!(limit.ceil.is_none());
        assert!(limit.burst.is_none());
    }

    #[test]
    fn test_rate_limit_typed_units() {
        use crate::util::Rate;
        let limit = RateLimit::new(Rate::mbit(100));
        assert_eq!(limit.rate.as_bytes_per_sec(), 12_500_000);

        let limit = RateLimit::new(Rate::gbit(1));
        assert_eq!(limit.rate.as_bytes_per_sec(), 125_000_000);
    }

    #[test]
    fn test_rate_limiter_builder() {
        use crate::util::Rate;
        let limiter = RateLimiter::new("eth0")
            .egress(Rate::bytes_per_sec(1_000_000))
            .ingress(Rate::bytes_per_sec(2_000_000))
            .burst_to(Rate::bytes_per_sec(3_000_000));

        assert_eq!(limiter.dev, "eth0");
        assert!(limiter.egress.is_some());
        assert!(limiter.ingress.is_some());
        assert_eq!(
            limiter.egress.as_ref().unwrap().rate,
            Rate::bytes_per_sec(1_000_000)
        );
        assert_eq!(
            limiter.egress.as_ref().unwrap().ceil,
            Some(Rate::bytes_per_sec(3_000_000))
        );
        assert_eq!(
            limiter.ingress.as_ref().unwrap().rate,
            Rate::bytes_per_sec(2_000_000)
        );
        assert_eq!(
            limiter.ingress.as_ref().unwrap().ceil,
            Some(Rate::bytes_per_sec(3_000_000))
        );
    }

    #[test]
    fn test_ifb_name_generation() {
        let limiter = RateLimiter::new("eth0");
        assert_eq!(limiter.ifb_name(), "ifb_eth0");

        let limiter = RateLimiter::new("verylonginterfacename");
        assert!(limiter.ifb_name().len() <= 15);
    }

    #[test]
    fn test_parse_subnet() {
        let (addr, prefix) = parse_subnet("10.0.0.0/8").unwrap();
        assert_eq!(addr, "10.0.0.0".parse::<IpAddr>().unwrap());
        assert_eq!(prefix, 8);

        let (addr, prefix) = parse_subnet("192.168.1.0/24").unwrap();
        assert_eq!(addr, "192.168.1.0".parse::<IpAddr>().unwrap());
        assert_eq!(prefix, 24);

        let (addr, prefix) = parse_subnet("2001:db8::/32").unwrap();
        assert!(addr.is_ipv6());
        assert_eq!(prefix, 32);

        // Invalid formats
        assert!(parse_subnet("10.0.0.0").is_err());
        assert!(parse_subnet("10.0.0.0/33").is_err());
    }

    #[test]
    fn test_per_host_limiter_builder() {
        use crate::util::Rate;
        let limiter = PerHostLimiter::new("eth0", Rate::mbit(10));
        assert_eq!(limiter.dev, "eth0");
        assert_eq!(limiter.default_rate, Rate::mbit(10));
        assert!(limiter.rules.is_empty());
    }

    #[test]
    fn test_per_host_limiter_with_rules() {
        use crate::util::Rate;
        let limiter = PerHostLimiter::new("eth0", Rate::mbit(10))
            .limit_ip("192.168.1.100".parse().unwrap(), Rate::mbit(100))
            .limit_subnet("10.0.0.0/8", Rate::mbit(50))
            .unwrap()
            .limit_port(80, Rate::mbit(500));

        assert_eq!(limiter.rules.len(), 3);
    }
}
