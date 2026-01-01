//! Typed TC (Traffic Control) configuration and builders.
//!
//! This module provides strongly-typed configuration for qdiscs with builder patterns.
//!
//! # Example
//!
//! ```ignore
//! use rip_netlink::tc::{NetemConfig, QdiscConfig};
//! use std::time::Duration;
//!
//! // Create a netem configuration with delay and loss
//! let netem = NetemConfig::new()
//!     .delay(Duration::from_millis(100))
//!     .jitter(Duration::from_millis(10))
//!     .delay_correlation(25.0)
//!     .loss(1.0)
//!     .loss_correlation(25.0)
//!     .build();
//!
//! // Add the qdisc
//! conn.add_qdisc("eth0", netem).await?;
//!
//! // Later, modify it
//! let updated = NetemConfig::new()
//!     .delay(Duration::from_millis(50))
//!     .build();
//! conn.change_qdisc("eth0", "root", updated).await?;
//!
//! // Delete it
//! conn.del_qdisc("eth0", "root").await?;
//! ```

use std::time::Duration;

use super::Connection;
use super::builder::MessageBuilder;
use super::connection::{ack_request, create_request, replace_request};
use super::error::{Error, Result};
use super::message::NlMsgType;
use super::types::tc::qdisc::netem::*;
use super::types::tc::qdisc::{TcRateSpec, fq_codel, htb, prio, sfq, tbf};
use super::types::tc::{TcMsg, TcaAttr, tc_handle};

// ============================================================================
// QdiscConfig trait
// ============================================================================

/// Trait for qdisc configurations that can be applied.
pub trait QdiscConfig: Send + Sync {
    /// Get the qdisc kind (e.g., "netem", "htb", "fq_codel").
    fn kind(&self) -> &'static str;

    /// Write the qdisc options to a message builder.
    fn write_options(&self, builder: &mut MessageBuilder) -> Result<()>;

    /// Get the default handle for this qdisc type, if any.
    fn default_handle(&self) -> Option<u32> {
        None
    }
}

// ============================================================================
// NetemConfig
// ============================================================================

/// Network emulator (netem) qdisc configuration.
///
/// Netem allows adding delay, packet loss, duplication, corruption, and reordering
/// to outgoing packets on an interface.
///
/// # Example
///
/// ```ignore
/// use rip_netlink::tc::NetemConfig;
/// use std::time::Duration;
///
/// // Simulate a lossy satellite link
/// let config = NetemConfig::new()
///     .delay(Duration::from_millis(500))
///     .jitter(Duration::from_millis(50))
///     .loss(0.1)  // 0.1% packet loss
///     .limit(10000)
///     .build();
///
/// conn.add_qdisc("eth0", config).await?;
/// ```
#[derive(Debug, Clone, Default)]
pub struct NetemConfig {
    /// Added delay.
    pub delay: Option<Duration>,
    /// Delay jitter (variation).
    pub jitter: Option<Duration>,
    /// Delay correlation (0-100%).
    pub delay_correlation: f64,
    /// Packet loss percentage (0-100%).
    pub loss: f64,
    /// Loss correlation (0-100%).
    pub loss_correlation: f64,
    /// Packet duplication percentage (0-100%).
    pub duplicate: f64,
    /// Duplication correlation (0-100%).
    pub duplicate_correlation: f64,
    /// Packet corruption percentage (0-100%).
    pub corrupt: f64,
    /// Corruption correlation (0-100%).
    pub corrupt_correlation: f64,
    /// Packet reordering percentage (0-100%).
    pub reorder: f64,
    /// Reordering correlation (0-100%).
    pub reorder_correlation: f64,
    /// Reorder gap.
    pub gap: u32,
    /// Rate limit in bytes/sec.
    pub rate: Option<u64>,
    /// Queue limit in packets.
    pub limit: u32,
    /// Parent handle.
    pub parent: String,
    /// Qdisc handle.
    pub handle: Option<String>,
}

impl NetemConfig {
    /// Create a new netem configuration builder.
    pub fn new() -> Self {
        Self {
            limit: 1000, // Default limit
            parent: "root".to_string(),
            ..Default::default()
        }
    }

    /// Set the parent handle (default: "root").
    pub fn parent(mut self, parent: impl Into<String>) -> Self {
        self.parent = parent.into();
        self
    }

    /// Set the qdisc handle.
    pub fn handle(mut self, handle: impl Into<String>) -> Self {
        self.handle = Some(handle.into());
        self
    }

    /// Set the added delay.
    pub fn delay(mut self, delay: Duration) -> Self {
        self.delay = Some(delay);
        self
    }

    /// Set the delay jitter (variation).
    pub fn jitter(mut self, jitter: Duration) -> Self {
        self.jitter = Some(jitter);
        self
    }

    /// Set the delay correlation (0-100%).
    pub fn delay_correlation(mut self, corr: f64) -> Self {
        self.delay_correlation = corr.clamp(0.0, 100.0);
        self
    }

    /// Set the packet loss percentage (0-100%).
    pub fn loss(mut self, percent: f64) -> Self {
        self.loss = percent.clamp(0.0, 100.0);
        self
    }

    /// Set the loss correlation (0-100%).
    pub fn loss_correlation(mut self, corr: f64) -> Self {
        self.loss_correlation = corr.clamp(0.0, 100.0);
        self
    }

    /// Set the packet duplication percentage (0-100%).
    pub fn duplicate(mut self, percent: f64) -> Self {
        self.duplicate = percent.clamp(0.0, 100.0);
        self
    }

    /// Set the duplication correlation (0-100%).
    pub fn duplicate_correlation(mut self, corr: f64) -> Self {
        self.duplicate_correlation = corr.clamp(0.0, 100.0);
        self
    }

    /// Set the packet corruption percentage (0-100%).
    pub fn corrupt(mut self, percent: f64) -> Self {
        self.corrupt = percent.clamp(0.0, 100.0);
        self
    }

    /// Set the corruption correlation (0-100%).
    pub fn corrupt_correlation(mut self, corr: f64) -> Self {
        self.corrupt_correlation = corr.clamp(0.0, 100.0);
        self
    }

    /// Set the packet reordering percentage (0-100%).
    ///
    /// Note: Reordering requires delay to be set.
    pub fn reorder(mut self, percent: f64) -> Self {
        self.reorder = percent.clamp(0.0, 100.0);
        self
    }

    /// Set the reordering correlation (0-100%).
    pub fn reorder_correlation(mut self, corr: f64) -> Self {
        self.reorder_correlation = corr.clamp(0.0, 100.0);
        self
    }

    /// Set the reorder gap.
    pub fn gap(mut self, gap: u32) -> Self {
        self.gap = gap;
        self
    }

    /// Set the rate limit in bytes per second.
    pub fn rate(mut self, bytes_per_sec: u64) -> Self {
        self.rate = Some(bytes_per_sec);
        self
    }

    /// Set the rate limit from a bit rate (e.g., 1_000_000 for 1 Mbps).
    pub fn rate_bps(mut self, bits_per_sec: u64) -> Self {
        self.rate = Some(bits_per_sec / 8);
        self
    }

    /// Set the queue limit in packets.
    pub fn limit(mut self, packets: u32) -> Self {
        self.limit = packets;
        self
    }

    /// Build the configuration (returns self, for API consistency).
    pub fn build(self) -> Self {
        self
    }
}

impl QdiscConfig for NetemConfig {
    fn kind(&self) -> &'static str {
        "netem"
    }

    fn write_options(&self, builder: &mut MessageBuilder) -> Result<()> {
        // Validate: reorder requires delay
        if self.reorder > 0.0 && self.delay.is_none() {
            return Err(Error::InvalidMessage(
                "netem: reorder requires delay to be set".into(),
            ));
        }

        // Build TcNetemQopt
        let mut qopt = TcNetemQopt::new();
        qopt.limit = self.limit;

        if let Some(delay) = self.delay {
            // Use microseconds for the basic qopt (legacy)
            qopt.latency = delay.as_micros() as u32;
        }
        if let Some(jitter) = self.jitter {
            qopt.jitter = jitter.as_micros() as u32;
        }
        if self.loss > 0.0 {
            qopt.loss = percent_to_prob(self.loss);
        }
        if self.duplicate > 0.0 {
            qopt.duplicate = percent_to_prob(self.duplicate);
        }
        if self.reorder > 0.0 && self.gap == 0 {
            qopt.gap = 1; // Default gap if reorder is set
        } else {
            qopt.gap = self.gap;
        }

        // Write the base options
        builder.append(&qopt);

        // Add 64-bit latency for precision (nanoseconds)
        if let Some(delay) = self.delay {
            let latency_ns = delay.as_nanos() as i64;
            builder.append_attr(TCA_NETEM_LATENCY64, &latency_ns.to_ne_bytes());
        }

        // Add 64-bit jitter for precision (nanoseconds)
        if let Some(jitter) = self.jitter {
            let jitter_ns = jitter.as_nanos() as i64;
            builder.append_attr(TCA_NETEM_JITTER64, &jitter_ns.to_ne_bytes());
        }

        // Add correlation if any set
        if self.delay_correlation > 0.0
            || self.loss_correlation > 0.0
            || self.duplicate_correlation > 0.0
        {
            let corr = TcNetemCorr {
                delay_corr: percent_to_prob(self.delay_correlation),
                loss_corr: percent_to_prob(self.loss_correlation),
                dup_corr: percent_to_prob(self.duplicate_correlation),
            };
            builder.append_attr(TCA_NETEM_CORR, corr.as_bytes());
        }

        // Add reorder if set
        if self.reorder > 0.0 {
            let reorder = TcNetemReorder {
                probability: percent_to_prob(self.reorder),
                correlation: percent_to_prob(self.reorder_correlation),
            };
            builder.append_attr(TCA_NETEM_REORDER, reorder.as_bytes());
        }

        // Add corrupt if set
        if self.corrupt > 0.0 {
            let corrupt = TcNetemCorrupt {
                probability: percent_to_prob(self.corrupt),
                correlation: percent_to_prob(self.corrupt_correlation),
            };
            builder.append_attr(TCA_NETEM_CORRUPT, corrupt.as_bytes());
        }

        // Add rate limit if set
        if let Some(rate) = self.rate {
            let mut rate_struct = TcNetemRate::default();
            if rate > u32::MAX as u64 {
                rate_struct.rate = u32::MAX;
                builder.append_attr(TCA_NETEM_RATE, rate_struct.as_bytes());
                builder.append_attr(TCA_NETEM_RATE64, &rate.to_ne_bytes());
            } else {
                rate_struct.rate = rate as u32;
                builder.append_attr(TCA_NETEM_RATE, rate_struct.as_bytes());
            }
        }

        Ok(())
    }
}

// ============================================================================
// FqCodelConfig
// ============================================================================

/// Fair Queue CoDel (fq_codel) qdisc configuration.
///
/// FQ-CoDel combines fair queuing with the CoDel AQM algorithm to provide
/// good latency under load while maintaining fairness between flows.
///
/// # Example
///
/// ```ignore
/// use rip_netlink::tc::FqCodelConfig;
/// use std::time::Duration;
///
/// let config = FqCodelConfig::new()
///     .target(Duration::from_millis(5))
///     .interval(Duration::from_millis(100))
///     .limit(10000)
///     .flows(1024)
///     .ecn(true)
///     .build();
///
/// conn.add_qdisc("eth0", config).await?;
/// ```
#[derive(Debug, Clone)]
pub struct FqCodelConfig {
    /// Target delay.
    pub target: Option<Duration>,
    /// Interval for CoDel algorithm.
    pub interval: Option<Duration>,
    /// Queue limit in packets.
    pub limit: Option<u32>,
    /// Number of flows.
    pub flows: Option<u32>,
    /// Quantum (bytes per round).
    pub quantum: Option<u32>,
    /// Enable ECN marking.
    pub ecn: bool,
    /// CE threshold.
    pub ce_threshold: Option<Duration>,
    /// Memory limit in bytes.
    pub memory_limit: Option<u32>,
    /// Parent handle.
    pub parent: String,
    /// Qdisc handle.
    pub handle: Option<String>,
}

impl Default for FqCodelConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl FqCodelConfig {
    /// Create a new fq_codel configuration builder.
    pub fn new() -> Self {
        Self {
            target: None,
            interval: None,
            limit: None,
            flows: None,
            quantum: None,
            ecn: false,
            ce_threshold: None,
            memory_limit: None,
            parent: "root".to_string(),
            handle: None,
        }
    }

    /// Set the parent handle.
    pub fn parent(mut self, parent: impl Into<String>) -> Self {
        self.parent = parent.into();
        self
    }

    /// Set the qdisc handle.
    pub fn handle(mut self, handle: impl Into<String>) -> Self {
        self.handle = Some(handle.into());
        self
    }

    /// Set the target delay (default: 5ms).
    pub fn target(mut self, target: Duration) -> Self {
        self.target = Some(target);
        self
    }

    /// Set the interval (default: 100ms).
    pub fn interval(mut self, interval: Duration) -> Self {
        self.interval = Some(interval);
        self
    }

    /// Set the queue limit in packets.
    pub fn limit(mut self, packets: u32) -> Self {
        self.limit = Some(packets);
        self
    }

    /// Set the number of flows.
    pub fn flows(mut self, flows: u32) -> Self {
        self.flows = Some(flows);
        self
    }

    /// Set the quantum (bytes per round).
    pub fn quantum(mut self, bytes: u32) -> Self {
        self.quantum = Some(bytes);
        self
    }

    /// Enable or disable ECN marking.
    pub fn ecn(mut self, enable: bool) -> Self {
        self.ecn = enable;
        self
    }

    /// Set the CE threshold for ECN marking.
    pub fn ce_threshold(mut self, threshold: Duration) -> Self {
        self.ce_threshold = Some(threshold);
        self
    }

    /// Set the memory limit in bytes.
    pub fn memory_limit(mut self, bytes: u32) -> Self {
        self.memory_limit = Some(bytes);
        self
    }

    /// Build the configuration.
    pub fn build(self) -> Self {
        self
    }
}

impl QdiscConfig for FqCodelConfig {
    fn kind(&self) -> &'static str {
        "fq_codel"
    }

    fn write_options(&self, builder: &mut MessageBuilder) -> Result<()> {
        if let Some(target) = self.target {
            builder.append_attr_u32(fq_codel::TCA_FQ_CODEL_TARGET, target.as_micros() as u32);
        }
        if let Some(interval) = self.interval {
            builder.append_attr_u32(fq_codel::TCA_FQ_CODEL_INTERVAL, interval.as_micros() as u32);
        }
        if let Some(limit) = self.limit {
            builder.append_attr_u32(fq_codel::TCA_FQ_CODEL_LIMIT, limit);
        }
        if let Some(flows) = self.flows {
            builder.append_attr_u32(fq_codel::TCA_FQ_CODEL_FLOWS, flows);
        }
        if let Some(quantum) = self.quantum {
            builder.append_attr_u32(fq_codel::TCA_FQ_CODEL_QUANTUM, quantum);
        }
        if self.ecn {
            builder.append_attr_u32(fq_codel::TCA_FQ_CODEL_ECN, 1);
        }
        if let Some(ce) = self.ce_threshold {
            builder.append_attr_u32(fq_codel::TCA_FQ_CODEL_CE_THRESHOLD, ce.as_micros() as u32);
        }
        if let Some(mem) = self.memory_limit {
            builder.append_attr_u32(fq_codel::TCA_FQ_CODEL_MEMORY_LIMIT, mem);
        }
        Ok(())
    }
}

// ============================================================================
// TbfConfig
// ============================================================================

/// Token Bucket Filter (tbf) qdisc configuration.
///
/// TBF is a simple rate limiter that allows bursts up to a configured size.
///
/// # Example
///
/// ```ignore
/// use rip_netlink::tc::TbfConfig;
///
/// let config = TbfConfig::new()
///     .rate(1_000_000)  // 1 MB/s
///     .burst(32 * 1024)  // 32 KB burst
///     .limit(100 * 1024) // 100 KB buffer
///     .build();
///
/// conn.add_qdisc("eth0", config).await?;
/// ```
#[derive(Debug, Clone)]
pub struct TbfConfig {
    /// Rate in bytes/sec.
    pub rate: u64,
    /// Peak rate in bytes/sec (optional).
    pub peakrate: Option<u64>,
    /// Burst size in bytes.
    pub burst: u32,
    /// MTU / peak burst.
    pub mtu: u32,
    /// Buffer limit in bytes.
    pub limit: u32,
    /// Parent handle.
    pub parent: String,
    /// Qdisc handle.
    pub handle: Option<String>,
}

impl Default for TbfConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl TbfConfig {
    /// Create a new tbf configuration builder.
    pub fn new() -> Self {
        Self {
            rate: 0,
            peakrate: None,
            burst: 0,
            mtu: 1514,
            limit: 0,
            parent: "root".to_string(),
            handle: None,
        }
    }

    /// Set the parent handle.
    pub fn parent(mut self, parent: impl Into<String>) -> Self {
        self.parent = parent.into();
        self
    }

    /// Set the qdisc handle.
    pub fn handle(mut self, handle: impl Into<String>) -> Self {
        self.handle = Some(handle.into());
        self
    }

    /// Set the rate in bytes per second.
    pub fn rate(mut self, bytes_per_sec: u64) -> Self {
        self.rate = bytes_per_sec;
        self
    }

    /// Set the rate in bits per second.
    pub fn rate_bps(mut self, bits_per_sec: u64) -> Self {
        self.rate = bits_per_sec / 8;
        self
    }

    /// Set the peak rate in bytes per second.
    pub fn peakrate(mut self, bytes_per_sec: u64) -> Self {
        self.peakrate = Some(bytes_per_sec);
        self
    }

    /// Set the burst size in bytes.
    pub fn burst(mut self, bytes: u32) -> Self {
        self.burst = bytes;
        self
    }

    /// Set the MTU.
    pub fn mtu(mut self, mtu: u32) -> Self {
        self.mtu = mtu;
        self
    }

    /// Set the buffer limit in bytes.
    pub fn limit(mut self, bytes: u32) -> Self {
        self.limit = bytes;
        self
    }

    /// Build the configuration.
    pub fn build(self) -> Self {
        self
    }
}

impl QdiscConfig for TbfConfig {
    fn kind(&self) -> &'static str {
        "tbf"
    }

    fn write_options(&self, builder: &mut MessageBuilder) -> Result<()> {
        // Build TcTbfQopt
        let qopt = tbf::TcTbfQopt {
            rate: TcRateSpec::new(self.rate.min(u32::MAX as u64) as u32),
            peakrate: self
                .peakrate
                .map(|pr| TcRateSpec::new(pr.min(u32::MAX as u64) as u32))
                .unwrap_or_default(),
            limit: self.limit,
            buffer: self.burst,
            mtu: self.mtu,
        };

        builder.append_attr(tbf::TCA_TBF_PARMS, qopt.as_bytes());

        // Add 64-bit rate if needed
        if self.rate > u32::MAX as u64 {
            builder.append_attr(tbf::TCA_TBF_RATE64, &self.rate.to_ne_bytes());
        }
        if let Some(pr) = self.peakrate
            && pr > u32::MAX as u64
        {
            builder.append_attr(tbf::TCA_TBF_PRATE64, &pr.to_ne_bytes());
        }

        Ok(())
    }
}

// ============================================================================
// HtbConfig (qdisc level)
// ============================================================================

/// HTB (Hierarchical Token Bucket) qdisc configuration.
///
/// HTB is used for hierarchical bandwidth shaping with classes.
///
/// # Example
///
/// ```ignore
/// use rip_netlink::tc::HtbQdiscConfig;
///
/// let config = HtbQdiscConfig::new()
///     .default_class(0x10)
///     .r2q(10)
///     .build();
///
/// conn.add_qdisc("eth0", config).await?;
/// ```
#[derive(Debug, Clone)]
pub struct HtbQdiscConfig {
    /// Default class ID for unclassified traffic.
    pub default_class: u32,
    /// Rate to quantum divisor.
    pub r2q: u32,
    /// Direct queue length.
    pub direct_qlen: Option<u32>,
    /// Parent handle.
    pub parent: String,
    /// Qdisc handle.
    pub handle: Option<String>,
}

impl Default for HtbQdiscConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl HtbQdiscConfig {
    /// Create a new HTB qdisc configuration builder.
    pub fn new() -> Self {
        Self {
            default_class: 0,
            r2q: 10,
            direct_qlen: None,
            parent: "root".to_string(),
            handle: None,
        }
    }

    /// Set the parent handle.
    pub fn parent(mut self, parent: impl Into<String>) -> Self {
        self.parent = parent.into();
        self
    }

    /// Set the qdisc handle.
    pub fn handle(mut self, handle: impl Into<String>) -> Self {
        self.handle = Some(handle.into());
        self
    }

    /// Set the default class ID.
    pub fn default_class(mut self, classid: u32) -> Self {
        self.default_class = classid;
        self
    }

    /// Set the rate to quantum divisor.
    pub fn r2q(mut self, r2q: u32) -> Self {
        self.r2q = r2q;
        self
    }

    /// Set the direct queue length.
    pub fn direct_qlen(mut self, qlen: u32) -> Self {
        self.direct_qlen = Some(qlen);
        self
    }

    /// Build the configuration.
    pub fn build(self) -> Self {
        self
    }
}

impl QdiscConfig for HtbQdiscConfig {
    fn kind(&self) -> &'static str {
        "htb"
    }

    fn write_options(&self, builder: &mut MessageBuilder) -> Result<()> {
        let glob = htb::TcHtbGlob::new().with_default(self.default_class);
        builder.append_attr(htb::TCA_HTB_INIT, glob.as_bytes());

        if let Some(qlen) = self.direct_qlen {
            builder.append_attr_u32(htb::TCA_HTB_DIRECT_QLEN, qlen);
        }

        Ok(())
    }
}

// ============================================================================
// PrioConfig
// ============================================================================

/// Priority (prio) qdisc configuration.
///
/// # Example
///
/// ```ignore
/// use rip_netlink::tc::PrioConfig;
///
/// let config = PrioConfig::new()
///     .bands(3)
///     .build();
///
/// conn.add_qdisc("eth0", config).await?;
/// ```
#[derive(Debug, Clone)]
pub struct PrioConfig {
    /// Number of priority bands.
    pub bands: i32,
    /// Priority map (16 entries).
    pub priomap: [u8; 16],
    /// Parent handle.
    pub parent: String,
    /// Qdisc handle.
    pub handle: Option<String>,
}

impl Default for PrioConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl PrioConfig {
    /// Create a new prio configuration builder with defaults.
    pub fn new() -> Self {
        Self {
            bands: 3,
            priomap: [1, 2, 2, 2, 1, 2, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1],
            parent: "root".to_string(),
            handle: None,
        }
    }

    /// Set the parent handle.
    pub fn parent(mut self, parent: impl Into<String>) -> Self {
        self.parent = parent.into();
        self
    }

    /// Set the qdisc handle.
    pub fn handle(mut self, handle: impl Into<String>) -> Self {
        self.handle = Some(handle.into());
        self
    }

    /// Set the number of bands.
    pub fn bands(mut self, bands: i32) -> Self {
        self.bands = bands;
        self
    }

    /// Set the priority map.
    pub fn priomap(mut self, map: [u8; 16]) -> Self {
        self.priomap = map;
        self
    }

    /// Build the configuration.
    pub fn build(self) -> Self {
        self
    }
}

impl QdiscConfig for PrioConfig {
    fn kind(&self) -> &'static str {
        "prio"
    }

    fn write_options(&self, builder: &mut MessageBuilder) -> Result<()> {
        let qopt = prio::TcPrioQopt {
            bands: self.bands,
            priomap: self.priomap,
        };
        builder.append(&qopt);
        Ok(())
    }
}

// ============================================================================
// SfqConfig
// ============================================================================

/// Stochastic Fairness Queuing (sfq) qdisc configuration.
///
/// # Example
///
/// ```ignore
/// use rip_netlink::tc::SfqConfig;
///
/// let config = SfqConfig::new()
///     .perturb(10)
///     .limit(127)
///     .build();
///
/// conn.add_qdisc("eth0", config).await?;
/// ```
#[derive(Debug, Clone)]
pub struct SfqConfig {
    /// Perturbation period in seconds.
    pub perturb: i32,
    /// Queue limit.
    pub limit: u32,
    /// Quantum (bytes per round).
    pub quantum: u32,
    /// Parent handle.
    pub parent: String,
    /// Qdisc handle.
    pub handle: Option<String>,
}

impl Default for SfqConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl SfqConfig {
    /// Create a new sfq configuration builder.
    pub fn new() -> Self {
        Self {
            perturb: 0,
            limit: 127,
            quantum: 0,
            parent: "root".to_string(),
            handle: None,
        }
    }

    /// Set the parent handle.
    pub fn parent(mut self, parent: impl Into<String>) -> Self {
        self.parent = parent.into();
        self
    }

    /// Set the qdisc handle.
    pub fn handle(mut self, handle: impl Into<String>) -> Self {
        self.handle = Some(handle.into());
        self
    }

    /// Set the perturbation period in seconds.
    pub fn perturb(mut self, seconds: i32) -> Self {
        self.perturb = seconds;
        self
    }

    /// Set the queue limit.
    pub fn limit(mut self, limit: u32) -> Self {
        self.limit = limit;
        self
    }

    /// Set the quantum (bytes per round).
    pub fn quantum(mut self, bytes: u32) -> Self {
        self.quantum = bytes;
        self
    }

    /// Build the configuration.
    pub fn build(self) -> Self {
        self
    }
}

impl QdiscConfig for SfqConfig {
    fn kind(&self) -> &'static str {
        "sfq"
    }

    fn write_options(&self, builder: &mut MessageBuilder) -> Result<()> {
        let qopt = sfq::TcSfqQopt {
            quantum: self.quantum,
            perturb_period: self.perturb,
            limit: self.limit,
            divisor: 0,
            flows: 0,
        };
        builder.append(&qopt);
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
// Connection extension methods
// ============================================================================

impl Connection {
    /// Add a qdisc to an interface.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use rip_netlink::tc::NetemConfig;
    /// use std::time::Duration;
    ///
    /// let netem = NetemConfig::new()
    ///     .delay(Duration::from_millis(100))
    ///     .loss(1.0)
    ///     .build();
    ///
    /// conn.add_qdisc("eth0", netem).await?;
    /// ```
    pub async fn add_qdisc(&self, dev: &str, config: impl QdiscConfig) -> Result<()> {
        self.add_qdisc_full(dev, "root", None, config).await
    }

    /// Add a qdisc with explicit parent and handle.
    pub async fn add_qdisc_full(
        &self,
        dev: &str,
        parent: &str,
        handle: Option<&str>,
        config: impl QdiscConfig,
    ) -> Result<()> {
        let ifindex = get_ifindex(dev)?;
        let parent_handle = parse_handle(parent)?;
        let qdisc_handle = handle.map(parse_handle).transpose()?.unwrap_or(0);

        let tcmsg = TcMsg::new()
            .with_ifindex(ifindex)
            .with_parent(parent_handle)
            .with_handle(qdisc_handle);

        let mut builder = create_request(NlMsgType::RTM_NEWQDISC);
        builder.append(&tcmsg);
        builder.append_attr_str(TcaAttr::Kind as u16, config.kind());

        let options_token = builder.nest_start(TcaAttr::Options as u16);
        config.write_options(&mut builder)?;
        builder.nest_end(options_token);

        self.request_ack(builder).await
    }

    /// Delete a qdisc from an interface.
    ///
    /// # Example
    ///
    /// ```ignore
    /// conn.del_qdisc("eth0", "root").await?;
    /// ```
    pub async fn del_qdisc(&self, dev: &str, parent: &str) -> Result<()> {
        self.del_qdisc_full(dev, parent, None).await
    }

    /// Delete a qdisc with explicit handle.
    pub async fn del_qdisc_full(
        &self,
        dev: &str,
        parent: &str,
        handle: Option<&str>,
    ) -> Result<()> {
        let ifindex = get_ifindex(dev)?;
        let parent_handle = parse_handle(parent)?;
        let qdisc_handle = handle.map(parse_handle).transpose()?.unwrap_or(0);

        let tcmsg = TcMsg::new()
            .with_ifindex(ifindex)
            .with_parent(parent_handle)
            .with_handle(qdisc_handle);

        let mut builder = ack_request(NlMsgType::RTM_DELQDISC);
        builder.append(&tcmsg);

        self.request_ack(builder).await
    }

    /// Replace a qdisc (add or update).
    ///
    /// # Example
    ///
    /// ```ignore
    /// let netem = NetemConfig::new()
    ///     .delay(Duration::from_millis(50))
    ///     .build();
    ///
    /// conn.replace_qdisc("eth0", netem).await?;
    /// ```
    pub async fn replace_qdisc(&self, dev: &str, config: impl QdiscConfig) -> Result<()> {
        self.replace_qdisc_full(dev, "root", None, config).await
    }

    /// Replace a qdisc with explicit parent and handle.
    pub async fn replace_qdisc_full(
        &self,
        dev: &str,
        parent: &str,
        handle: Option<&str>,
        config: impl QdiscConfig,
    ) -> Result<()> {
        let ifindex = get_ifindex(dev)?;
        let parent_handle = parse_handle(parent)?;
        let qdisc_handle = handle.map(parse_handle).transpose()?.unwrap_or(0);

        let tcmsg = TcMsg::new()
            .with_ifindex(ifindex)
            .with_parent(parent_handle)
            .with_handle(qdisc_handle);

        let mut builder = replace_request(NlMsgType::RTM_NEWQDISC);
        builder.append(&tcmsg);
        builder.append_attr_str(TcaAttr::Kind as u16, config.kind());

        let options_token = builder.nest_start(TcaAttr::Options as u16);
        config.write_options(&mut builder)?;
        builder.nest_end(options_token);

        self.request_ack(builder).await
    }

    /// Change a qdisc's parameters.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let netem = NetemConfig::new()
    ///     .delay(Duration::from_millis(200))
    ///     .build();
    ///
    /// conn.change_qdisc("eth0", "root", netem).await?;
    /// ```
    pub async fn change_qdisc(
        &self,
        dev: &str,
        parent: &str,
        config: impl QdiscConfig,
    ) -> Result<()> {
        self.change_qdisc_full(dev, parent, None, config).await
    }

    /// Change a qdisc with explicit handle.
    pub async fn change_qdisc_full(
        &self,
        dev: &str,
        parent: &str,
        handle: Option<&str>,
        config: impl QdiscConfig,
    ) -> Result<()> {
        let ifindex = get_ifindex(dev)?;
        let parent_handle = parse_handle(parent)?;
        let qdisc_handle = handle.map(parse_handle).transpose()?.unwrap_or(0);

        let tcmsg = TcMsg::new()
            .with_ifindex(ifindex)
            .with_parent(parent_handle)
            .with_handle(qdisc_handle);

        let mut builder = ack_request(NlMsgType::RTM_NEWQDISC);
        builder.append(&tcmsg);
        builder.append_attr_str(TcaAttr::Kind as u16, config.kind());

        let options_token = builder.nest_start(TcaAttr::Options as u16);
        config.write_options(&mut builder)?;
        builder.nest_end(options_token);

        self.request_ack(builder).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_netem_builder() {
        let config = NetemConfig::new()
            .delay(Duration::from_millis(100))
            .jitter(Duration::from_millis(10))
            .delay_correlation(25.0)
            .loss(1.0)
            .build();

        assert_eq!(config.delay, Some(Duration::from_millis(100)));
        assert_eq!(config.jitter, Some(Duration::from_millis(10)));
        assert_eq!(config.delay_correlation, 25.0);
        assert_eq!(config.loss, 1.0);
        assert_eq!(config.kind(), "netem");
    }

    #[test]
    fn test_fq_codel_builder() {
        let config = FqCodelConfig::new()
            .target(Duration::from_millis(5))
            .interval(Duration::from_millis(100))
            .limit(10000)
            .ecn(true)
            .build();

        assert_eq!(config.target, Some(Duration::from_millis(5)));
        assert_eq!(config.interval, Some(Duration::from_millis(100)));
        assert_eq!(config.limit, Some(10000));
        assert!(config.ecn);
        assert_eq!(config.kind(), "fq_codel");
    }

    #[test]
    fn test_tbf_builder() {
        let config = TbfConfig::new()
            .rate(1_000_000)
            .burst(32 * 1024)
            .limit(100 * 1024)
            .build();

        assert_eq!(config.rate, 1_000_000);
        assert_eq!(config.burst, 32 * 1024);
        assert_eq!(config.limit, 100 * 1024);
        assert_eq!(config.kind(), "tbf");
    }

    #[test]
    fn test_netem_clamp() {
        let config = NetemConfig::new()
            .loss(150.0) // Should clamp to 100
            .delay_correlation(-10.0) // Should clamp to 0
            .build();

        assert_eq!(config.loss, 100.0);
        assert_eq!(config.delay_correlation, 0.0);
    }
}
