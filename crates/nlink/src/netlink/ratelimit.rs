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
    tc_handle::{FilterPriority, TcHandle},
    tc_recipe::{ReconcileOptions, ReconcileReport, StaleObject, UnmanagedObject},
    tc_recipe_internals::{
        LiveTree, dump_live_tree, flower_classid, fq_codel_target_matches, htb_class_rates_match,
        root_htb_options,
    },
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
    #[tracing::instrument(level = "info", skip_all, fields(dev = %self.dev, egress = self.egress.is_some(), ingress = self.ingress.is_some()))]
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
    #[tracing::instrument(level = "info", skip_all, fields(dev = %self.dev))]
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

        // Add HTB qdisc at root with handle 1:
        let htb = HtbQdiscConfig::new().default_class(0x10).build();
        conn.add_qdisc_full(
            &self.dev,
            TcHandle::ROOT,
            Some(TcHandle::major_only(1)),
            htb,
        )
        .await?;

        // Add root class (1:1) for the rate limit
        let mut class_config = HtbClassConfig::new(limit.rate);
        if let Some(ceil) = limit.ceil {
            class_config = class_config.ceil(ceil);
        }
        if let Some(burst) = limit.burst {
            class_config = class_config.burst(burst);
        }
        conn.add_class(
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
        conn.add_class(
            &self.dev,
            TcHandle::new(1, 1),
            TcHandle::new(1, 10),
            default_config.build(),
        )
        .await?;

        // Add fq_codel as leaf qdisc for AQM
        let mut fq_codel = FqCodelConfig::new();
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

        // Add HTB qdisc at root of IFB with handle 1:
        let htb = HtbQdiscConfig::new().default_class(0x10).build();
        conn.add_qdisc_full(
            &ifb_name,
            TcHandle::ROOT,
            Some(TcHandle::major_only(1)),
            htb,
        )
        .await?;

        // Add root class (1:1) for the rate limit
        let mut class_config = HtbClassConfig::new(limit.rate);
        if let Some(ceil) = limit.ceil {
            class_config = class_config.ceil(ceil);
        }
        if let Some(burst) = limit.burst {
            class_config = class_config.burst(burst);
        }
        conn.add_class(
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
        conn.add_class(
            &ifb_name,
            TcHandle::new(1, 1),
            TcHandle::new(1, 10),
            default_config.build(),
        )
        .await?;

        // Add fq_codel as leaf qdisc for AQM
        let mut fq_codel = FqCodelConfig::new();
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
    #[tracing::instrument(level = "info", skip_all, fields(dev = %self.dev, rules = self.rules.len()))]
    pub async fn apply(&self, conn: &Connection<Route>) -> Result<()> {
        // Remove existing root qdisc
        let _ = conn.del_qdisc(&self.dev, TcHandle::ROOT).await;

        // Add HTB qdisc at root with handle 1:
        // Default class will be the last one (for unmatched traffic)
        let default_classid = (self.rules.len() + 1) as u32;
        let htb = HtbQdiscConfig::new().default_class(default_classid).build();
        conn.add_qdisc_full(
            &self.dev,
            TcHandle::ROOT,
            Some(TcHandle::major_only(1)),
            htb,
        )
        .await?;

        // Add root class (1:1) with sum of all rates as ceiling
        let parent_classid = TcHandle::new(1, 1);
        let major_only_1 = TcHandle::major_only(1);
        let total_rate: crate::util::Rate =
            self.default_rate + self.rules.iter().map(|r| r.rate).sum::<crate::util::Rate>();
        let root_config = HtbClassConfig::new(total_rate).ceil(total_rate).build();
        conn.add_class(&self.dev, major_only_1, parent_classid, root_config)
            .await?;

        // Add classes for each rule
        for (i, rule) in self.rules.iter().enumerate() {
            let classid = TcHandle::new(1, (i + 2) as u16);
            let leaf_handle = TcHandle::major_only((i + 10) as u16);
            let class_config = HtbClassConfig::new(rule.rate).ceil(rule.ceil.unwrap_or(rule.rate));
            conn.add_class(&self.dev, parent_classid, classid, class_config.build())
                .await?;

            // Add fq_codel leaf qdisc
            let mut fq_codel = FqCodelConfig::new();
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
        conn.add_class(&self.dev, parent_classid, default_classid, default_config)
            .await?;

        // Add fq_codel leaf for default class
        let mut fq_codel = FqCodelConfig::new();
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
    #[tracing::instrument(level = "info", skip_all, fields(dev = %self.dev))]
    pub async fn remove(&self, conn: &Connection<Route>) -> Result<()> {
        let _ = conn.del_qdisc(&self.dev, TcHandle::ROOT).await;
        Ok(())
    }

    // ---- reconcile ----

    /// Non-destructively converge the live TC tree to match this
    /// limiter's desired state.
    ///
    /// Unlike [`apply()`], `reconcile()` dumps the existing tree, diffs
    /// it against what the helper would build, and emits the minimum
    /// set of `add_*` / `change_*` / `del_*` operations to converge.
    /// Calling `reconcile()` twice in a row with no other changes makes
    /// **zero** kernel calls on the second invocation.
    ///
    /// If the live root qdisc is the wrong kind (not HTB), reconcile
    /// returns an error by default. Pass [`ReconcileOptions::with_fallback_to_apply(true)`]
    /// to instead trigger a destructive rebuild via [`apply()`].
    ///
    /// [`apply()`]: Self::apply
    #[tracing::instrument(level = "info", skip_all, fields(dev = %self.dev, rules = self.rules.len()))]
    pub async fn reconcile(&self, conn: &Connection<Route>) -> Result<ReconcileReport> {
        self.reconcile_with_options(conn, ReconcileOptions::new())
            .await
    }

    /// Compute what [`reconcile()`] would do without making kernel calls.
    ///
    /// [`reconcile()`]: Self::reconcile
    #[tracing::instrument(level = "info", skip_all, fields(dev = %self.dev, rules = self.rules.len()))]
    pub async fn reconcile_dry_run(&self, conn: &Connection<Route>) -> Result<ReconcileReport> {
        self.reconcile_with_options(conn, ReconcileOptions::new().with_dry_run(true))
            .await
    }

    /// [`reconcile()`] with explicit [`ReconcileOptions`].
    ///
    /// [`reconcile()`]: Self::reconcile
    #[tracing::instrument(level = "info", skip_all, fields(dev = %self.dev, rules = self.rules.len(), dry_run = opts.dry_run, fallback = opts.fallback_to_apply))]
    pub async fn reconcile_with_options(
        &self,
        conn: &Connection<Route>,
        opts: ReconcileOptions,
    ) -> Result<ReconcileReport> {
        // Resolve interface for typed-by-index calls.
        let link = conn
            .get_link_by_name(&self.dev)
            .await?
            .ok_or_else(|| Error::InvalidMessage(format!("interface not found: {}", self.dev)))?;
        let ifindex = link.ifindex();
        self.reconcile_inner(conn, ifindex, opts).await
    }

    async fn reconcile_inner(
        &self,
        conn: &Connection<Route>,
        ifindex: u32,
        opts: ReconcileOptions,
    ) -> Result<ReconcileReport> {
        let mut report = ReconcileReport {
            dry_run: opts.dry_run,
            ..ReconcileReport::default()
        };

        let tree = dump_live_tree(conn, ifindex).await?;

        let n = self.rules.len();
        let parent_classid = TcHandle::new(1, 1);
        let root_handle = TcHandle::major_only(1);
        let default_minor = (n + 2) as u16;
        let default_classid = TcHandle::new(1, default_minor);
        let default_leaf_handle = TcHandle::major_only((n + 10) as u16);
        let total_rate: crate::util::Rate =
            self.default_rate + self.rules.iter().map(|r| r.rate).sum::<crate::util::Rate>();
        let target_us = self.latency.map(|d| d.as_micros() as u32);

        // 1. Root HTB qdisc.
        match tree.root_qdisc.as_ref() {
            None => {
                if !opts.dry_run {
                    let cfg = HtbQdiscConfig::new()
                        .default_class(default_minor as u32)
                        .build();
                    conn.add_qdisc_by_index_full(ifindex, TcHandle::ROOT, Some(root_handle), cfg)
                        .await
                        .map_err(|e| e.with_context("PerHostLimiter::reconcile: add HTB root"))?;
                }
                report.changes_made += 1;
                report.root_modified = true;
            }
            Some(q) => {
                let kind_ok = q.kind() == Some("htb") && q.handle() == root_handle;
                if !kind_ok {
                    if opts.fallback_to_apply {
                        if opts.dry_run {
                            report.changes_made += 1;
                            report.root_modified = true;
                            return Ok(report);
                        }
                        return self.apply_as_reconcile(conn).await;
                    }
                    return Err(Error::InvalidMessage(format!(
                        "PerHostLimiter::reconcile: root qdisc on {} is {:?} (handle {}), \
                         not HTB at 1:; pass ReconcileOptions::with_fallback_to_apply(true) \
                         to rebuild",
                        self.dev,
                        q.kind(),
                        q.handle()
                    )));
                }
                let default_ok = root_htb_options(&tree)
                    .map(|opts| opts.default_class == default_minor as u32)
                    .unwrap_or(false);
                if !default_ok {
                    if !opts.dry_run {
                        let cfg = HtbQdiscConfig::new()
                            .default_class(default_minor as u32)
                            .build();
                        conn.change_qdisc_by_index_full(
                            ifindex,
                            TcHandle::ROOT,
                            Some(root_handle),
                            cfg,
                        )
                        .await
                        .map_err(|e| {
                            e.with_context("PerHostLimiter::reconcile: update HTB root")
                        })?;
                    }
                    report.changes_made += 1;
                    report.root_modified = true;
                }
            }
        }

        // 2. Parent class 1:1 with rate=ceil=total_rate.
        let total_bps = total_rate.as_bytes_per_sec();
        match tree.class(parent_classid) {
            None => {
                if !opts.dry_run {
                    let cfg = HtbClassConfig::new(total_rate).ceil(total_rate).build();
                    conn.add_class_by_index(ifindex, root_handle, parent_classid, cfg)
                        .await
                        .map_err(|e| {
                            e.with_context("PerHostLimiter::reconcile: add parent class 1:1")
                        })?;
                }
                report.changes_made += 1;
                report.root_modified = true;
            }
            Some(c) => {
                if !htb_class_rates_match(c, total_bps, total_bps) {
                    if !opts.dry_run {
                        let cfg = HtbClassConfig::new(total_rate).ceil(total_rate).build();
                        conn.change_class_by_index(ifindex, root_handle, parent_classid, cfg)
                            .await
                            .map_err(|e| {
                                e.with_context("PerHostLimiter::reconcile: update parent class 1:1")
                            })?;
                    }
                    report.changes_made += 1;
                    report.root_modified = true;
                }
            }
        }

        // 3. Per-rule classes + fq_codel leaves + filters.
        for (i, rule) in self.rules.iter().enumerate() {
            let classid = TcHandle::new(1, (i + 2) as u16);
            let leaf_handle = TcHandle::major_only((i + 10) as u16);
            let class_rate = rule.rate;
            let class_ceil = rule.ceil.unwrap_or(rule.rate);
            let class_rate_bps = class_rate.as_bytes_per_sec();
            let class_ceil_bps = class_ceil.as_bytes_per_sec();

            let mut rule_added = false;
            let mut rule_modified = false;

            // 3a. Class.
            match tree.class(classid) {
                None => {
                    if !opts.dry_run {
                        let cfg = HtbClassConfig::new(class_rate).ceil(class_ceil).build();
                        conn.add_class_by_index(ifindex, parent_classid, classid, cfg)
                            .await
                            .map_err(|e| {
                                e.with_context(format!(
                                    "PerHostLimiter::reconcile: add class {classid}"
                                ))
                            })?;
                    }
                    report.changes_made += 1;
                    rule_added = true;
                }
                Some(c) => {
                    if !htb_class_rates_match(c, class_rate_bps, class_ceil_bps) {
                        if !opts.dry_run {
                            let cfg = HtbClassConfig::new(class_rate).ceil(class_ceil).build();
                            conn.change_class_by_index(ifindex, parent_classid, classid, cfg)
                                .await
                                .map_err(|e| {
                                    e.with_context(format!(
                                        "PerHostLimiter::reconcile: update class {classid}"
                                    ))
                                })?;
                        }
                        report.changes_made += 1;
                        rule_modified = true;
                    }
                }
            }

            // 3b. fq_codel leaf.
            match tree.leaf_for(classid) {
                None => {
                    if !opts.dry_run {
                        let mut leaf = FqCodelConfig::new();
                        if let Some(latency) = self.latency {
                            leaf = leaf.target(latency);
                        }
                        conn.add_qdisc_by_index_full(
                            ifindex,
                            classid,
                            Some(leaf_handle),
                            leaf.build(),
                        )
                        .await
                        .map_err(|e| {
                            e.with_context(format!(
                                "PerHostLimiter::reconcile: add fq_codel leaf at {classid}"
                            ))
                        })?;
                    }
                    report.changes_made += 1;
                    if !rule_added {
                        rule_modified = true;
                    }
                }
                Some(q) => {
                    if !fq_codel_target_matches(target_us, q) {
                        if !opts.dry_run {
                            let mut leaf = FqCodelConfig::new();
                            if let Some(latency) = self.latency {
                                leaf = leaf.target(latency);
                            }
                            conn.replace_qdisc_by_index_full(
                                ifindex,
                                classid,
                                Some(leaf_handle),
                                leaf.build(),
                            )
                            .await
                            .map_err(|e| {
                                e.with_context(format!(
                                    "PerHostLimiter::reconcile: update fq_codel leaf at \
                                     {classid}"
                                ))
                            })?;
                        }
                        report.changes_made += 1;
                        if !rule_added {
                            rule_modified = true;
                        }
                    }
                }
            }

            // 3c. Filter(s) at root parent. Plain matches use one
            // priority (i+1); Port matches use two (i+1 and i+1+100).
            self.reconcile_filter_for_rule(
                conn,
                ifindex,
                &tree,
                i,
                rule,
                classid,
                opts,
                &mut rule_added,
                &mut rule_modified,
                &mut report,
            )
            .await?;

            if rule_added {
                report.rules_added += 1;
            } else if rule_modified {
                report.rules_modified += 1;
            }
        }

        // 4. Default class — always present in the desired tree.
        let default_bps = self.default_rate.as_bytes_per_sec();
        match tree.class(default_classid) {
            None => {
                if !opts.dry_run {
                    let cfg = HtbClassConfig::new(self.default_rate)
                        .ceil(self.default_rate)
                        .build();
                    conn.add_class_by_index(ifindex, parent_classid, default_classid, cfg)
                        .await
                        .map_err(|e| {
                            e.with_context("PerHostLimiter::reconcile: add default class")
                        })?;
                }
                report.changes_made += 1;
                report.default_modified = true;
            }
            Some(c) => {
                if !htb_class_rates_match(c, default_bps, default_bps) {
                    if !opts.dry_run {
                        let cfg = HtbClassConfig::new(self.default_rate)
                            .ceil(self.default_rate)
                            .build();
                        conn.change_class_by_index(ifindex, parent_classid, default_classid, cfg)
                            .await
                            .map_err(|e| {
                                e.with_context("PerHostLimiter::reconcile: update default class")
                            })?;
                    }
                    report.changes_made += 1;
                    report.default_modified = true;
                }
            }
        }

        // 4b. Default fq_codel leaf — always present.
        match tree.leaf_for(default_classid) {
            None => {
                if !opts.dry_run {
                    let mut leaf = FqCodelConfig::new();
                    if let Some(latency) = self.latency {
                        leaf = leaf.target(latency);
                    }
                    conn.add_qdisc_by_index_full(
                        ifindex,
                        default_classid,
                        Some(default_leaf_handle),
                        leaf.build(),
                    )
                    .await
                    .map_err(|e| {
                        e.with_context("PerHostLimiter::reconcile: add default fq_codel leaf")
                    })?;
                }
                report.changes_made += 1;
                report.default_modified = true;
            }
            Some(q) => {
                if !fq_codel_target_matches(target_us, q) {
                    if !opts.dry_run {
                        let mut leaf = FqCodelConfig::new();
                        if let Some(latency) = self.latency {
                            leaf = leaf.target(latency);
                        }
                        conn.replace_qdisc_by_index_full(
                            ifindex,
                            default_classid,
                            Some(default_leaf_handle),
                            leaf.build(),
                        )
                        .await
                        .map_err(|e| {
                            e.with_context(
                                "PerHostLimiter::reconcile: update default fq_codel leaf",
                            )
                        })?;
                    }
                    report.changes_made += 1;
                    report.default_modified = true;
                }
            }
        }

        // 5. Stale removal.
        self.collect_stale_and_unmanaged(&tree, &mut report, conn, ifindex, opts)
            .await?;

        Ok(report)
    }

    #[allow(clippy::too_many_arguments)]
    async fn reconcile_filter_for_rule(
        &self,
        conn: &Connection<Route>,
        ifindex: u32,
        tree: &LiveTree,
        index: usize,
        rule: &HostRule,
        classid: TcHandle,
        opts: ReconcileOptions,
        rule_added: &mut bool,
        rule_modified: &mut bool,
        report: &mut ReconcileReport,
    ) -> Result<()> {
        use super::filter::FlowerFilter;

        const ETH_P_IP: u16 = 0x0800;
        const ETH_P_IPV6: u16 = 0x86DD;

        let priority = (index + 1) as u16;
        let root_handle = TcHandle::major_only(1);

        // For each filter we want to install for this rule, check vs
        // the live tree at that priority.
        let want: Vec<(u16, u16, FlowerFilter)> = match &rule.match_ {
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
                    IpAddr::V4(addr) => vec![(
                        ETH_P_IP,
                        priority,
                        FlowerFilter::new()
                            .classid(classid)
                            .priority(priority)
                            .dst_ipv4(*addr, prefix)
                            .build(),
                    )],
                    IpAddr::V6(addr) => vec![(
                        ETH_P_IPV6,
                        priority,
                        FlowerFilter::new()
                            .classid(classid)
                            .priority(priority)
                            .dst_ipv6(*addr, prefix)
                            .build(),
                    )],
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
                    IpAddr::V4(addr) => vec![(
                        ETH_P_IP,
                        priority,
                        FlowerFilter::new()
                            .classid(classid)
                            .priority(priority)
                            .src_ipv4(*addr, prefix)
                            .build(),
                    )],
                    IpAddr::V6(addr) => vec![(
                        ETH_P_IPV6,
                        priority,
                        FlowerFilter::new()
                            .classid(classid)
                            .priority(priority)
                            .src_ipv6(*addr, prefix)
                            .build(),
                    )],
                }
            }
            HostMatch::Port(port) => vec![
                (
                    ETH_P_IP,
                    priority,
                    FlowerFilter::new()
                        .classid(classid)
                        .priority(priority)
                        .ip_proto_tcp()
                        .dst_port(*port)
                        .build(),
                ),
                (
                    ETH_P_IP,
                    priority + 100,
                    FlowerFilter::new()
                        .classid(classid)
                        .priority(priority + 100)
                        .ip_proto_udp()
                        .dst_port(*port)
                        .build(),
                ),
            ],
            HostMatch::PortRange(_, _) => {
                // Port ranges are intentionally complex (multiple
                // filters); skip incremental reconcile for them and
                // require apply() instead. A full reconcile of these
                // rules is a follow-up.
                Vec::new()
            }
        };

        for (proto, prio, filter) in want {
            let live = tree.filter_at_priority(prio);
            let ok = live
                .map(|f| f.kind() == Some("flower") && flower_classid(f) == Some(classid))
                .unwrap_or(false);
            if !ok {
                if !opts.dry_run {
                    if let Some(stale) = live {
                        let _ = conn
                            .del_filter_by_index(ifindex, root_handle, stale.protocol(), prio)
                            .await;
                    }
                    conn.add_filter_by_index_full(ifindex, root_handle, None, proto, prio, filter)
                        .await
                        .map_err(|e| {
                            e.with_context(format!(
                                "PerHostLimiter::reconcile: add filter prio={prio} \
                             classid={classid}"
                            ))
                        })?;
                }
                report.changes_made += 1;
                if !*rule_added {
                    *rule_modified = true;
                }
            }
        }
        Ok(())
    }

    async fn apply_as_reconcile(&self, conn: &Connection<Route>) -> Result<ReconcileReport> {
        self.apply(conn).await?;
        let n = self.rules.len();
        Ok(ReconcileReport {
            // 1 root + 1 parent + 3 per rule (class+leaf+filter, +1 for
            // Port matches' UDP companion) + 1 default class + 1 default
            // leaf. Estimate; off-by-one for Port matches is ok.
            changes_made: 2 + 3 * n + 2,
            rules_added: n,
            root_modified: true,
            default_modified: true,
            ..ReconcileReport::default()
        })
    }

    async fn collect_stale_and_unmanaged(
        &self,
        tree: &LiveTree,
        report: &mut ReconcileReport,
        conn: &Connection<Route>,
        ifindex: u32,
        opts: ReconcileOptions,
    ) -> Result<()> {
        let n = self.rules.len();
        let parent_classid = TcHandle::new(1, 1);
        let root_handle = TcHandle::major_only(1);
        let max_minor = (n + 2) as u16;

        // Stale classes in major 1:.
        let mut stale_classes: Vec<TcHandle> = Vec::new();
        for (handle, _class) in tree.classes.iter() {
            if handle.major() != 1 {
                continue;
            }
            let minor = handle.minor();
            if minor == 0 || minor == 1 {
                continue;
            }
            if minor >= 2 && minor <= max_minor {
                continue;
            }
            stale_classes.push(*handle);
        }
        for handle in &stale_classes {
            if let Some(q) = tree.leaf_for(*handle) {
                let leaf_handle = q.handle();
                if !opts.dry_run {
                    let _ = conn
                        .del_qdisc_by_index_full(ifindex, *handle, Some(leaf_handle))
                        .await;
                }
            }
            if !opts.dry_run
                && let Err(e) = conn
                    .del_class_by_index(ifindex, parent_classid, *handle)
                    .await
                && !e.is_not_found()
            {
                return Err(e.with_context(format!(
                    "PerHostLimiter::reconcile: remove stale class {handle}"
                )));
            }
            report.changes_made += 1;
            report.rules_removed += 1;
            report.stale_removed.push(StaleObject {
                kind: "class",
                handle: *handle,
                priority: None,
            });
        }

        // Stale filters at root parent. PerHostLimiter installs in the
        // operator band (priority i+1, i in 0..n) and recipe-band
        // companions (priority i+1+100 for Port matches). To stay
        // conservative, only treat priority `1..=n` and `101..=100+n`
        // as managed; anything else is unmanaged.
        let mut stale_filters: Vec<(u16, u16, TcHandle)> = Vec::new();
        for f in &tree.root_filters {
            let prio = f.priority();
            // Managed bands.
            let in_low = prio >= 1 && (prio as usize) <= n;
            let in_high = prio >= 101 && (prio as usize) <= 100 + n;
            // Out-of-band entries are unmanaged (left alone).
            if !in_low && !in_high {
                report.unmanaged.push(UnmanagedObject {
                    kind: "filter",
                    handle: f.parent(),
                    priority: Some(FilterPriority::new(prio)),
                });
                continue;
            }
            // In a managed band but no desired rule maps here? The
            // simplest rule: every prio in [1, n] should map to a rule;
            // every prio in [101, 100+n] only exists when that rule's
            // match_ is `Port`. We can't easily tell here without
            // knowing the rule's match shape, so we *only* delete a
            // high-band entry that has no rule index assigned — i.e.
            // (prio - 100 - 1) > n. The same for low-band.
            let i_low = (prio as usize).checked_sub(1);
            let i_high = (prio as usize).checked_sub(101);
            let mapped_index = i_high.filter(|&i| i < n).or(i_low.filter(|&i| i < n));
            if mapped_index.is_none() {
                stale_filters.push((prio, f.protocol(), f.parent()));
            }
        }
        for (prio, proto, parent) in stale_filters {
            if !opts.dry_run {
                let _ = conn
                    .del_filter_by_index(ifindex, root_handle, proto, prio)
                    .await;
            }
            report.changes_made += 1;
            report.stale_removed.push(StaleObject {
                kind: "filter",
                handle: parent,
                priority: Some(FilterPriority::new(prio)),
            });
        }
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

        let classid = TcHandle::new(1, (index + 2) as u16);
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
                            .classid(classid)
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
                            .classid(classid)
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
                            .classid(classid)
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
                            .classid(classid)
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
                    .classid(classid)
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
                    .classid(classid)
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
                            .classid(classid)
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
