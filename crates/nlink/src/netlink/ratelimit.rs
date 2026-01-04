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

use std::net::IpAddr;
use std::time::Duration;

use super::Connection;
use super::error::{Error, Result};
use super::link::IfbLink;
use super::protocol::Route;
use super::tc::{FqCodelConfig, HtbClassConfig, HtbQdiscConfig, IngressConfig};
use crate::util::parse::get_rate;

// ============================================================================
// RateLimit
// ============================================================================

/// Rate limit configuration.
#[derive(Debug, Clone)]
pub struct RateLimit {
    /// Guaranteed rate in bytes per second.
    pub rate: u64,
    /// Maximum burst rate in bytes per second (ceiling).
    pub ceil: Option<u64>,
    /// Burst size in bytes.
    pub burst: Option<u32>,
    /// Latency target for AQM (Active Queue Management).
    pub latency: Option<Duration>,
}

impl RateLimit {
    /// Create a new rate limit with the specified rate in bytes per second.
    pub fn new(rate: u64) -> Self {
        Self {
            rate,
            ceil: None,
            burst: None,
            latency: None,
        }
    }

    /// Create a rate limit from a rate string (e.g., "100mbit", "1gbit").
    pub fn parse(rate: &str) -> Result<Self> {
        Ok(Self::new(get_rate(rate)?))
    }

    /// Set the ceiling rate (maximum burst rate).
    pub fn ceil(mut self, ceil: u64) -> Self {
        self.ceil = Some(ceil);
        self
    }

    /// Set the burst size in bytes.
    pub fn burst(mut self, burst: u32) -> Self {
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

    /// Set the egress (upload) rate limit from a string (e.g., "100mbit").
    pub fn egress(mut self, rate: &str) -> Result<Self> {
        self.egress = Some(RateLimit::parse(rate)?);
        Ok(self)
    }

    /// Set the egress (upload) rate limit in bytes per second.
    pub fn egress_bps(mut self, rate: u64) -> Self {
        self.egress = Some(RateLimit::new(rate));
        self
    }

    /// Set the ingress (download) rate limit from a string (e.g., "1gbit").
    pub fn ingress(mut self, rate: &str) -> Result<Self> {
        self.ingress = Some(RateLimit::parse(rate)?);
        Ok(self)
    }

    /// Set the ingress (download) rate limit in bytes per second.
    pub fn ingress_bps(mut self, rate: u64) -> Self {
        self.ingress = Some(RateLimit::new(rate));
        self
    }

    /// Set the ceiling rate for bursting (applies to both egress and ingress).
    pub fn burst_to(mut self, ceil: &str) -> Result<Self> {
        let ceil_bps = get_rate(ceil)?;
        if let Some(ref mut egress) = self.egress {
            egress.ceil = Some(ceil_bps);
        }
        if let Some(ref mut ingress) = self.ingress {
            ingress.ceil = Some(ceil_bps);
        }
        Ok(self)
    }

    /// Set the ceiling rate for bursting in bytes per second.
    pub fn burst_to_bps(mut self, ceil: u64) -> Self {
        if let Some(ref mut egress) = self.egress {
            egress.ceil = Some(ceil);
        }
        if let Some(ref mut ingress) = self.ingress {
            ingress.ceil = Some(ceil);
        }
        self
    }

    /// Set the burst buffer size (applies to both egress and ingress).
    pub fn burst_size(mut self, size: &str) -> Result<Self> {
        let size_bytes = crate::util::parse::get_size(size)? as u32;
        if let Some(ref mut egress) = self.egress {
            egress.burst = Some(size_bytes);
        }
        if let Some(ref mut ingress) = self.ingress {
            ingress.burst = Some(size_bytes);
        }
        Ok(self)
    }

    /// Set the burst buffer size in bytes.
    pub fn burst_size_bytes(mut self, size: u32) -> Self {
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
        let _ = conn.del_qdisc(&self.dev, "root").await;

        // Remove ingress qdisc
        let _ = conn.del_qdisc(&self.dev, "ingress").await;

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
        let _ = conn.del_qdisc(&self.dev, "root").await;

        // Add HTB qdisc at root
        let htb = HtbQdiscConfig::new()
            .default_class(0x10)
            .handle("1:")
            .build();
        conn.add_qdisc(&self.dev, htb).await?;

        // Add root class (1:1) for the rate limit
        let mut class_config = HtbClassConfig::from_bps(limit.rate);
        if let Some(ceil) = limit.ceil {
            class_config = class_config.ceil_bps(ceil);
        }
        if let Some(burst) = limit.burst {
            class_config = class_config.burst_bytes(burst);
        }
        conn.add_class_config(&self.dev, "1:0", "1:1", class_config.build())
            .await?;

        // Add default class (1:10) under the root class
        let mut default_config = HtbClassConfig::from_bps(limit.rate);
        if let Some(ceil) = limit.ceil {
            default_config = default_config.ceil_bps(ceil);
        }
        if let Some(burst) = limit.burst {
            default_config = default_config.burst_bytes(burst);
        }
        conn.add_class_config(&self.dev, "1:1", "1:10", default_config.build())
            .await?;

        // Add fq_codel as leaf qdisc for AQM
        let mut fq_codel = FqCodelConfig::new().parent("1:10").handle("10:");
        if let Some(latency) = limit.latency {
            fq_codel = fq_codel.target(latency);
        }
        conn.add_qdisc_full(&self.dev, "1:10", Some("10:"), fq_codel.build())
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
        let _ = conn.del_qdisc(&self.dev, "ingress").await;

        // Add ingress qdisc to the main interface
        conn.add_qdisc_full(&self.dev, "ingress", None, IngressConfig::new())
            .await?;

        // Add filter to redirect ingress traffic to IFB
        // We need to use a filter with mirred action
        self.add_ingress_redirect(conn, &ifb_name).await?;

        // Now configure HTB on the IFB device
        // Remove existing root qdisc on IFB
        let _ = conn.del_qdisc(&ifb_name, "root").await;

        // Add HTB qdisc at root of IFB
        let htb = HtbQdiscConfig::new()
            .default_class(0x10)
            .handle("1:")
            .build();
        conn.add_qdisc(&ifb_name, htb).await?;

        // Add root class (1:1) for the rate limit
        let mut class_config = HtbClassConfig::from_bps(limit.rate);
        if let Some(ceil) = limit.ceil {
            class_config = class_config.ceil_bps(ceil);
        }
        if let Some(burst) = limit.burst {
            class_config = class_config.burst_bytes(burst);
        }
        conn.add_class_config(&ifb_name, "1:0", "1:1", class_config.build())
            .await?;

        // Add default class (1:10) under the root class
        let mut default_config = HtbClassConfig::from_bps(limit.rate);
        if let Some(ceil) = limit.ceil {
            default_config = default_config.ceil_bps(ceil);
        }
        if let Some(burst) = limit.burst {
            default_config = default_config.burst_bytes(burst);
        }
        conn.add_class_config(&ifb_name, "1:1", "1:10", default_config.build())
            .await?;

        // Add fq_codel as leaf qdisc for AQM
        let mut fq_codel = FqCodelConfig::new().parent("1:10").handle("10:");
        if let Some(latency) = limit.latency {
            fq_codel = fq_codel.target(latency);
        }
        conn.add_qdisc_full(&ifb_name, "1:10", Some("10:"), fq_codel.build())
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
        use super::connection::ack_request;
        use super::message::NlMsgType;
        use super::types::tc::action::{self, mirred};
        use super::types::tc::filter::u32 as u32_mod;
        use super::types::tc::{TcMsg, TcaAttr, tc_handle};

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
    /// Default rate in bytes per second.
    default_rate: u64,
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
    /// Rate limit in bytes per second.
    rate: u64,
    /// Ceiling rate in bytes per second.
    ceil: Option<u64>,
}

/// Match condition for per-host limiting.
#[derive(Debug, Clone)]
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
    /// Create a new per-host rate limiter with a default rate.
    pub fn new(dev: &str, default_rate: &str) -> Result<Self> {
        Ok(Self {
            dev: dev.to_string(),
            default_rate: get_rate(default_rate)?,
            rules: Vec::new(),
            latency: None,
        })
    }

    /// Create a new per-host rate limiter with rate in bytes per second.
    pub fn new_bps(dev: &str, default_rate: u64) -> Self {
        Self {
            dev: dev.to_string(),
            default_rate,
            rules: Vec::new(),
            latency: None,
        }
    }

    /// Add a rate limit for a specific IP address.
    pub fn limit_ip(mut self, ip: IpAddr, rate: &str) -> Result<Self> {
        self.rules.push(HostRule {
            match_: HostMatch::Ip(ip),
            rate: get_rate(rate)?,
            ceil: None,
        });
        Ok(self)
    }

    /// Add a rate limit for a specific IP address with ceiling.
    pub fn limit_ip_with_ceil(mut self, ip: IpAddr, rate: &str, ceil: &str) -> Result<Self> {
        self.rules.push(HostRule {
            match_: HostMatch::Ip(ip),
            rate: get_rate(rate)?,
            ceil: Some(get_rate(ceil)?),
        });
        Ok(self)
    }

    /// Add a rate limit for a subnet.
    pub fn limit_subnet(mut self, subnet: &str, rate: &str) -> Result<Self> {
        let (addr, prefix) = parse_subnet(subnet)?;
        self.rules.push(HostRule {
            match_: HostMatch::Subnet(addr, prefix),
            rate: get_rate(rate)?,
            ceil: None,
        });
        Ok(self)
    }

    /// Add a rate limit for a source IP address.
    pub fn limit_src_ip(mut self, ip: IpAddr, rate: &str) -> Result<Self> {
        self.rules.push(HostRule {
            match_: HostMatch::SrcIp(ip),
            rate: get_rate(rate)?,
            ceil: None,
        });
        Ok(self)
    }

    /// Add a rate limit for a source subnet.
    pub fn limit_src_subnet(mut self, subnet: &str, rate: &str) -> Result<Self> {
        let (addr, prefix) = parse_subnet(subnet)?;
        self.rules.push(HostRule {
            match_: HostMatch::SrcSubnet(addr, prefix),
            rate: get_rate(rate)?,
            ceil: None,
        });
        Ok(self)
    }

    /// Add a rate limit for a destination port.
    pub fn limit_port(mut self, port: u16, rate: &str) -> Result<Self> {
        self.rules.push(HostRule {
            match_: HostMatch::Port(port),
            rate: get_rate(rate)?,
            ceil: None,
        });
        Ok(self)
    }

    /// Add a rate limit for a port range.
    pub fn limit_port_range(mut self, start: u16, end: u16, rate: &str) -> Result<Self> {
        self.rules.push(HostRule {
            match_: HostMatch::PortRange(start, end),
            rate: get_rate(rate)?,
            ceil: None,
        });
        Ok(self)
    }

    /// Set the latency target for AQM.
    pub fn latency(mut self, latency: Duration) -> Self {
        self.latency = Some(latency);
        self
    }

    /// Apply the per-host rate limits.
    pub async fn apply(&self, conn: &Connection<Route>) -> Result<()> {
        // Remove existing root qdisc
        let _ = conn.del_qdisc(&self.dev, "root").await;

        // Add HTB qdisc at root
        // Default class will be the last one (for unmatched traffic)
        let default_classid = (self.rules.len() + 1) as u32;
        let htb = HtbQdiscConfig::new()
            .default_class(default_classid)
            .handle("1:")
            .build();
        conn.add_qdisc(&self.dev, htb).await?;

        // Add root class (1:1) with sum of all rates as ceiling
        let total_rate = self.default_rate + self.rules.iter().map(|r| r.rate).sum::<u64>();
        let root_config = HtbClassConfig::from_bps(total_rate)
            .ceil_bps(total_rate)
            .build();
        conn.add_class_config(&self.dev, "1:0", "1:1", root_config)
            .await?;

        // Add classes for each rule
        for (i, rule) in self.rules.iter().enumerate() {
            let classid = format!("1:{:x}", i + 2); // Start from 1:2
            let mut class_config = HtbClassConfig::from_bps(rule.rate);
            if let Some(ceil) = rule.ceil {
                class_config = class_config.ceil_bps(ceil);
            } else {
                class_config = class_config.ceil_bps(rule.rate);
            }
            conn.add_class_config(&self.dev, "1:1", &classid, class_config.build())
                .await?;

            // Add fq_codel leaf qdisc
            let handle = format!("{:x}:", i + 10);
            let mut fq_codel = FqCodelConfig::new().parent(&classid).handle(&handle);
            if let Some(latency) = self.latency {
                fq_codel = fq_codel.target(latency);
            }
            conn.add_qdisc_full(&self.dev, &classid, Some(&handle), fq_codel.build())
                .await?;

            // Add flower filter to classify traffic to this class
            self.add_filter_for_rule(conn, i, rule).await?;
        }

        // Add default class for unmatched traffic
        let default_classid = format!("1:{:x}", self.rules.len() + 2);
        let default_config = HtbClassConfig::from_bps(self.default_rate)
            .ceil_bps(self.default_rate)
            .build();
        conn.add_class_config(&self.dev, "1:1", &default_classid, default_config)
            .await?;

        // Add fq_codel leaf for default class
        let default_handle = format!("{:x}:", self.rules.len() + 10);
        let mut fq_codel = FqCodelConfig::new()
            .parent(&default_classid)
            .handle(&default_handle);
        if let Some(latency) = self.latency {
            fq_codel = fq_codel.target(latency);
        }
        conn.add_qdisc_full(
            &self.dev,
            &default_classid,
            Some(&default_handle),
            fq_codel.build(),
        )
        .await?;

        Ok(())
    }

    /// Remove the per-host rate limits.
    pub async fn remove(&self, conn: &Connection<Route>) -> Result<()> {
        let _ = conn.del_qdisc(&self.dev, "root").await;
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
                        conn.add_filter(&self.dev, "1:", filter).await?;
                    }
                    IpAddr::V6(addr) => {
                        let filter = FlowerFilter::new()
                            .classid(&classid)
                            .priority(priority)
                            .dst_ipv6(*addr, prefix)
                            .build();
                        conn.add_filter(&self.dev, "1:", filter).await?;
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
                        conn.add_filter(&self.dev, "1:", filter).await?;
                    }
                    IpAddr::V6(addr) => {
                        let filter = FlowerFilter::new()
                            .classid(&classid)
                            .priority(priority)
                            .src_ipv6(*addr, prefix)
                            .build();
                        conn.add_filter(&self.dev, "1:", filter).await?;
                    }
                }
            }
            HostMatch::Port(port) => {
                // Match both TCP and UDP
                let tcp_filter = FlowerFilter::new()
                    .classid(&classid)
                    .priority(priority)
                    .ip_proto_tcp()
                    .dst_port(*port)
                    .build();
                conn.add_filter(&self.dev, "1:", tcp_filter).await?;

                let udp_filter = FlowerFilter::new()
                    .classid(&classid)
                    .priority(priority + 100) // Different priority to avoid conflict
                    .ip_proto_udp()
                    .dst_port(*port)
                    .build();
                conn.add_filter(&self.dev, "1:", udp_filter).await?;
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
                        let _ = conn.add_filter(&self.dev, "1:", filter).await;
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
        let limit = RateLimit::new(1_000_000);
        assert_eq!(limit.rate, 1_000_000);
        assert!(limit.ceil.is_none());
        assert!(limit.burst.is_none());
    }

    #[test]
    fn test_rate_limit_parse() {
        let limit = RateLimit::parse("100mbit").unwrap();
        assert_eq!(limit.rate, 12_500_000); // 100 Mbps = 12.5 MB/s

        let limit = RateLimit::parse("1gbit").unwrap();
        assert_eq!(limit.rate, 125_000_000); // 1 Gbps = 125 MB/s
    }

    #[test]
    fn test_rate_limiter_builder() {
        let limiter = RateLimiter::new("eth0")
            .egress_bps(1_000_000)
            .ingress_bps(2_000_000)
            .burst_to_bps(3_000_000);

        assert_eq!(limiter.dev, "eth0");
        assert!(limiter.egress.is_some());
        assert!(limiter.ingress.is_some());
        assert_eq!(limiter.egress.as_ref().unwrap().rate, 1_000_000);
        assert_eq!(limiter.egress.as_ref().unwrap().ceil, Some(3_000_000));
        assert_eq!(limiter.ingress.as_ref().unwrap().rate, 2_000_000);
        assert_eq!(limiter.ingress.as_ref().unwrap().ceil, Some(3_000_000));
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
        let limiter = PerHostLimiter::new("eth0", "10mbit").unwrap();
        assert_eq!(limiter.dev, "eth0");
        assert_eq!(limiter.default_rate, 1_250_000); // 10 Mbps
        assert!(limiter.rules.is_empty());
    }

    #[test]
    fn test_per_host_limiter_with_rules() {
        let limiter = PerHostLimiter::new("eth0", "10mbit")
            .unwrap()
            .limit_ip("192.168.1.100".parse().unwrap(), "100mbit")
            .unwrap()
            .limit_subnet("10.0.0.0/8", "50mbit")
            .unwrap()
            .limit_port(80, "500mbit")
            .unwrap();

        assert_eq!(limiter.rules.len(), 3);
    }
}
