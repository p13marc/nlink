//! Typed TC (Traffic Control) configuration and builders.
//!
//! This module provides strongly-typed configuration for qdiscs with builder patterns.
//!
//! # Example
//!
//! ```ignore
//! use nlink::netlink::tc::{NetemConfig, QdiscConfig};
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

// Re-export for convenience
pub use super::types::tc::qdisc::hfsc::TcServiceCurve;
pub use super::types::tc::qdisc::taprio::TaprioSchedEntry;

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
/// use nlink::netlink::tc::NetemConfig;
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
/// use nlink::netlink::tc::FqCodelConfig;
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
/// use nlink::netlink::tc::TbfConfig;
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
/// use nlink::netlink::tc::HtbQdiscConfig;
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
/// use nlink::netlink::tc::PrioConfig;
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
/// use nlink::netlink::tc::SfqConfig;
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
// RedConfig
// ============================================================================

/// RED (Random Early Detection) qdisc configuration.
///
/// RED is an Active Queue Management (AQM) algorithm that probabilistically
/// drops packets before the queue is full to signal congestion.
///
/// # Example
///
/// ```ignore
/// use nlink::netlink::tc::RedConfig;
///
/// let config = RedConfig::new()
///     .limit(100 * 1024)    // 100KB limit
///     .min(30 * 1024)       // 30KB min threshold
///     .max(90 * 1024)       // 90KB max threshold
///     .ecn(true)            // Enable ECN marking
///     .build();
///
/// conn.add_qdisc("eth0", config).await?;
/// ```
#[derive(Debug, Clone)]
pub struct RedConfig {
    /// Queue limit in bytes.
    pub limit: u32,
    /// Minimum threshold in bytes.
    pub min: u32,
    /// Maximum threshold in bytes.
    pub max: u32,
    /// Maximum probability (0-255, default ~2%).
    pub max_p: u8,
    /// Enable ECN marking.
    pub ecn: bool,
    /// Enable hard drop (drop all above max).
    pub harddrop: bool,
    /// Enable adaptive RED.
    pub adaptive: bool,
    /// Parent handle.
    pub parent: String,
    /// Qdisc handle.
    pub handle: Option<String>,
}

impl Default for RedConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl RedConfig {
    /// Create a new RED configuration builder.
    pub fn new() -> Self {
        Self {
            limit: 0,
            min: 0,
            max: 0,
            max_p: 5, // ~2% probability
            ecn: false,
            harddrop: false,
            adaptive: false,
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

    /// Set the queue limit in bytes.
    pub fn limit(mut self, bytes: u32) -> Self {
        self.limit = bytes;
        self
    }

    /// Set the minimum threshold in bytes.
    pub fn min(mut self, bytes: u32) -> Self {
        self.min = bytes;
        self
    }

    /// Set the maximum threshold in bytes.
    pub fn max(mut self, bytes: u32) -> Self {
        self.max = bytes;
        self
    }

    /// Set the maximum probability (0-100%).
    pub fn max_probability(mut self, percent: f64) -> Self {
        // Convert percentage to 0-255 scale
        self.max_p = ((percent / 100.0) * 255.0).clamp(0.0, 255.0) as u8;
        self
    }

    /// Enable or disable ECN marking.
    pub fn ecn(mut self, enable: bool) -> Self {
        self.ecn = enable;
        self
    }

    /// Enable or disable hard drop.
    pub fn harddrop(mut self, enable: bool) -> Self {
        self.harddrop = enable;
        self
    }

    /// Enable or disable adaptive RED.
    pub fn adaptive(mut self, enable: bool) -> Self {
        self.adaptive = enable;
        self
    }

    /// Build the configuration.
    pub fn build(self) -> Self {
        self
    }
}

impl QdiscConfig for RedConfig {
    fn kind(&self) -> &'static str {
        "red"
    }

    fn write_options(&self, builder: &mut MessageBuilder) -> Result<()> {
        use super::types::tc::qdisc::red;

        let mut flags: u8 = 0;
        if self.ecn {
            flags |= red::TC_RED_ECN as u8;
        }
        if self.harddrop {
            flags |= red::TC_RED_HARDDROP as u8;
        }
        if self.adaptive {
            flags |= red::TC_RED_ADAPTATIVE as u8;
        }

        let qopt = red::TcRedQopt {
            limit: self.limit,
            qth_min: self.min,
            qth_max: self.max,
            wlog: 9,      // Weight log (default)
            plog: 13,     // Probability log (default)
            scell_log: 0, // Cell size log
            flags,
        };

        builder.append_attr(red::TCA_RED_PARMS, qopt.as_bytes());

        // Add max probability
        let max_p = (self.max_p as u32) << 24;
        builder.append_attr_u32(red::TCA_RED_MAX_P, max_p);

        Ok(())
    }
}

// ============================================================================
// PieConfig
// ============================================================================

/// PIE (Proportional Integral controller-Enhanced) qdisc configuration.
///
/// PIE is an AQM algorithm that achieves low latency and high throughput.
///
/// # Example
///
/// ```ignore
/// use nlink::netlink::tc::PieConfig;
/// use std::time::Duration;
///
/// let config = PieConfig::new()
///     .target(Duration::from_millis(15))
///     .limit(1000)
///     .ecn(true)
///     .build();
///
/// conn.add_qdisc("eth0", config).await?;
/// ```
#[derive(Debug, Clone)]
pub struct PieConfig {
    /// Target delay.
    pub target: Option<Duration>,
    /// Queue limit in packets.
    pub limit: Option<u32>,
    /// Probability update interval.
    pub tupdate: Option<Duration>,
    /// Alpha parameter (P controller).
    pub alpha: Option<u32>,
    /// Beta parameter (I controller).
    pub beta: Option<u32>,
    /// Enable ECN marking.
    pub ecn: bool,
    /// Use byte mode instead of packet mode.
    pub bytemode: bool,
    /// Parent handle.
    pub parent: String,
    /// Qdisc handle.
    pub handle: Option<String>,
}

impl Default for PieConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl PieConfig {
    /// Create a new PIE configuration builder.
    pub fn new() -> Self {
        Self {
            target: None,
            limit: None,
            tupdate: None,
            alpha: None,
            beta: None,
            ecn: false,
            bytemode: false,
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

    /// Set the target delay (default: 15ms).
    pub fn target(mut self, target: Duration) -> Self {
        self.target = Some(target);
        self
    }

    /// Set the queue limit in packets.
    pub fn limit(mut self, packets: u32) -> Self {
        self.limit = Some(packets);
        self
    }

    /// Set the probability update interval.
    pub fn tupdate(mut self, interval: Duration) -> Self {
        self.tupdate = Some(interval);
        self
    }

    /// Set the alpha parameter.
    pub fn alpha(mut self, alpha: u32) -> Self {
        self.alpha = Some(alpha);
        self
    }

    /// Set the beta parameter.
    pub fn beta(mut self, beta: u32) -> Self {
        self.beta = Some(beta);
        self
    }

    /// Enable or disable ECN marking.
    pub fn ecn(mut self, enable: bool) -> Self {
        self.ecn = enable;
        self
    }

    /// Enable or disable byte mode.
    pub fn bytemode(mut self, enable: bool) -> Self {
        self.bytemode = enable;
        self
    }

    /// Build the configuration.
    pub fn build(self) -> Self {
        self
    }
}

impl QdiscConfig for PieConfig {
    fn kind(&self) -> &'static str {
        "pie"
    }

    fn write_options(&self, builder: &mut MessageBuilder) -> Result<()> {
        use super::types::tc::qdisc::pie;

        if let Some(target) = self.target {
            builder.append_attr_u32(pie::TCA_PIE_TARGET, target.as_micros() as u32);
        }
        if let Some(limit) = self.limit {
            builder.append_attr_u32(pie::TCA_PIE_LIMIT, limit);
        }
        if let Some(tupdate) = self.tupdate {
            builder.append_attr_u32(pie::TCA_PIE_TUPDATE, tupdate.as_micros() as u32);
        }
        if let Some(alpha) = self.alpha {
            builder.append_attr_u32(pie::TCA_PIE_ALPHA, alpha);
        }
        if let Some(beta) = self.beta {
            builder.append_attr_u32(pie::TCA_PIE_BETA, beta);
        }
        if self.ecn {
            builder.append_attr_u32(pie::TCA_PIE_ECN, 1);
        }
        if self.bytemode {
            builder.append_attr_u32(pie::TCA_PIE_BYTEMODE, 1);
        }

        Ok(())
    }
}

// ============================================================================
// IngressConfig
// ============================================================================

/// Ingress qdisc configuration.
///
/// The ingress qdisc is used for ingress traffic processing and filtering.
/// It's typically used with filters to classify/police incoming traffic.
///
/// # Example
///
/// ```ignore
/// use nlink::netlink::tc::IngressConfig;
///
/// // Add ingress qdisc for filtering incoming traffic
/// conn.add_qdisc_full("eth0", "ingress", None, IngressConfig::new()).await?;
/// ```
#[derive(Debug, Clone, Default)]
pub struct IngressConfig;

impl IngressConfig {
    /// Create a new ingress configuration.
    pub fn new() -> Self {
        Self
    }
}

impl QdiscConfig for IngressConfig {
    fn kind(&self) -> &'static str {
        "ingress"
    }

    fn write_options(&self, _builder: &mut MessageBuilder) -> Result<()> {
        // Ingress qdisc has no options
        Ok(())
    }
}

// ============================================================================
// ClsactConfig
// ============================================================================

/// Clsact qdisc configuration.
///
/// The clsact qdisc is similar to ingress but provides both ingress and
/// egress traffic processing. It's commonly used with BPF programs.
///
/// # Example
///
/// ```ignore
/// use nlink::netlink::tc::ClsactConfig;
///
/// // Add clsact qdisc for BPF program attachment
/// conn.add_qdisc_full("eth0", "clsact", None, ClsactConfig::new()).await?;
/// ```
#[derive(Debug, Clone, Default)]
pub struct ClsactConfig;

impl ClsactConfig {
    /// Create a new clsact configuration.
    pub fn new() -> Self {
        Self
    }
}

impl QdiscConfig for ClsactConfig {
    fn kind(&self) -> &'static str {
        "clsact"
    }

    fn write_options(&self, _builder: &mut MessageBuilder) -> Result<()> {
        // Clsact qdisc has no options
        Ok(())
    }
}

// ============================================================================
// PfifoConfig
// ============================================================================

/// Pfifo (packet FIFO) qdisc configuration.
///
/// Simple FIFO queueing with a packet-based limit.
///
/// # Example
///
/// ```ignore
/// use nlink::netlink::tc::PfifoConfig;
///
/// let config = PfifoConfig::new()
///     .limit(1000)  // 1000 packets
///     .build();
///
/// conn.add_qdisc("eth0", config).await?;
/// ```
#[derive(Debug, Clone)]
pub struct PfifoConfig {
    /// Queue limit in packets.
    pub limit: u32,
    /// Parent handle.
    pub parent: String,
    /// Qdisc handle.
    pub handle: Option<String>,
}

impl Default for PfifoConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl PfifoConfig {
    /// Create a new pfifo configuration builder.
    pub fn new() -> Self {
        Self {
            limit: 1000,
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

    /// Set the queue limit in packets.
    pub fn limit(mut self, packets: u32) -> Self {
        self.limit = packets;
        self
    }

    /// Build the configuration.
    pub fn build(self) -> Self {
        self
    }
}

impl QdiscConfig for PfifoConfig {
    fn kind(&self) -> &'static str {
        "pfifo"
    }

    fn write_options(&self, builder: &mut MessageBuilder) -> Result<()> {
        use super::types::tc::qdisc::fifo::TcFifoQopt;

        let qopt = TcFifoQopt::new(self.limit);
        builder.append(&qopt);
        Ok(())
    }
}

// ============================================================================
// BfifoConfig
// ============================================================================

/// Bfifo (byte FIFO) qdisc configuration.
///
/// Simple FIFO queueing with a byte-based limit.
///
/// # Example
///
/// ```ignore
/// use nlink::netlink::tc::BfifoConfig;
///
/// let config = BfifoConfig::new()
///     .limit(100 * 1024)  // 100KB
///     .build();
///
/// conn.add_qdisc("eth0", config).await?;
/// ```
#[derive(Debug, Clone)]
pub struct BfifoConfig {
    /// Queue limit in bytes.
    pub limit: u32,
    /// Parent handle.
    pub parent: String,
    /// Qdisc handle.
    pub handle: Option<String>,
}

impl Default for BfifoConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl BfifoConfig {
    /// Create a new bfifo configuration builder.
    pub fn new() -> Self {
        Self {
            limit: 100 * 1024, // 100KB default
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

    /// Set the queue limit in bytes.
    pub fn limit(mut self, bytes: u32) -> Self {
        self.limit = bytes;
        self
    }

    /// Build the configuration.
    pub fn build(self) -> Self {
        self
    }
}

impl QdiscConfig for BfifoConfig {
    fn kind(&self) -> &'static str {
        "bfifo"
    }

    fn write_options(&self, builder: &mut MessageBuilder) -> Result<()> {
        use super::types::tc::qdisc::fifo::TcFifoQopt;

        let qopt = TcFifoQopt::new(self.limit);
        builder.append(&qopt);
        Ok(())
    }
}

// ============================================================================
// DrrConfig (Deficit Round Robin)
// ============================================================================

/// DRR (Deficit Round Robin) qdisc configuration.
///
/// DRR is a classful qdisc that implements the Deficit Round Robin algorithm
/// for fair bandwidth distribution among classes. Each class gets a quantum
/// of bytes to send per round.
///
/// # Example
///
/// ```ignore
/// use nlink::netlink::tc::DrrConfig;
///
/// // Create DRR qdisc
/// let config = DrrConfig::new()
///     .handle("1:")
///     .build();
///
/// conn.add_qdisc("eth0", config).await?;
/// ```
#[derive(Debug, Clone)]
pub struct DrrConfig {
    /// Parent handle.
    pub parent: String,
    /// Qdisc handle.
    pub handle: Option<String>,
}

impl Default for DrrConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl DrrConfig {
    /// Create a new DRR configuration builder.
    pub fn new() -> Self {
        Self {
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

    /// Build the configuration.
    pub fn build(self) -> Self {
        self
    }
}

impl QdiscConfig for DrrConfig {
    fn kind(&self) -> &'static str {
        "drr"
    }

    fn write_options(&self, _builder: &mut MessageBuilder) -> Result<()> {
        // DRR qdisc has no options, only classes have options
        Ok(())
    }
}

// ============================================================================
// QfqConfig (Quick Fair Queueing)
// ============================================================================

/// QFQ (Quick Fair Queueing) qdisc configuration.
///
/// QFQ is a classful qdisc that provides O(1) fair scheduling with weights.
/// It is faster than DRR for large numbers of classes.
///
/// # Example
///
/// ```ignore
/// use nlink::netlink::tc::QfqConfig;
///
/// // Create QFQ qdisc
/// let config = QfqConfig::new()
///     .handle("1:")
///     .build();
///
/// conn.add_qdisc("eth0", config).await?;
/// ```
#[derive(Debug, Clone)]
pub struct QfqConfig {
    /// Parent handle.
    pub parent: String,
    /// Qdisc handle.
    pub handle: Option<String>,
}

impl Default for QfqConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl QfqConfig {
    /// Create a new QFQ configuration builder.
    pub fn new() -> Self {
        Self {
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

    /// Build the configuration.
    pub fn build(self) -> Self {
        self
    }
}

impl QdiscConfig for QfqConfig {
    fn kind(&self) -> &'static str {
        "qfq"
    }

    fn write_options(&self, _builder: &mut MessageBuilder) -> Result<()> {
        // QFQ qdisc has no options, only classes have options
        Ok(())
    }
}

// ============================================================================
// PlugConfig (Plug/Unplug qdisc)
// ============================================================================

/// Plug qdisc configuration.
///
/// The plug qdisc allows buffering packets and releasing them on demand.
/// This is useful for checkpoint/restore, debugging, or controlled packet release.
///
/// # Example
///
/// ```ignore
/// use nlink::netlink::tc::PlugConfig;
///
/// // Create plug qdisc with 10000 byte limit
/// let config = PlugConfig::new()
///     .limit(10000)
///     .build();
///
/// conn.add_qdisc("eth0", config).await?;
///
/// // Buffer packets
/// conn.plug_buffer("eth0").await?;
///
/// // Release all buffered packets
/// conn.plug_release_one("eth0").await?;
/// ```
#[derive(Debug, Clone)]
pub struct PlugConfig {
    /// Initial limit in bytes.
    pub limit: Option<u32>,
    /// Parent handle.
    pub parent: String,
    /// Qdisc handle.
    pub handle: Option<String>,
}

impl Default for PlugConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl PlugConfig {
    /// Create a new plug configuration builder.
    pub fn new() -> Self {
        Self {
            limit: None,
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

    /// Set the queue limit in bytes.
    pub fn limit(mut self, bytes: u32) -> Self {
        self.limit = Some(bytes);
        self
    }

    /// Build the configuration.
    pub fn build(self) -> Self {
        self
    }
}

impl QdiscConfig for PlugConfig {
    fn kind(&self) -> &'static str {
        "plug"
    }

    fn write_options(&self, builder: &mut MessageBuilder) -> Result<()> {
        use super::types::tc::qdisc::plug::TcPlugQopt;

        if let Some(limit) = self.limit {
            let qopt = TcPlugQopt::limit(limit);
            builder.append(&qopt);
        }
        Ok(())
    }
}

// ============================================================================
// MqprioConfig (Multi-Queue Priority)
// ============================================================================

/// MQPRIO (Multi-Queue Priority) qdisc configuration.
///
/// MQPRIO is a qdisc for multi-queue network devices that maps traffic classes
/// to hardware queues. It supports hardware offload for NICs that support it.
///
/// # Example
///
/// ```ignore
/// use nlink::netlink::tc::MqprioConfig;
///
/// // Create mqprio with 4 traffic classes and hardware offload
/// let config = MqprioConfig::new()
///     .num_tc(4)
///     .map(&[0, 1, 2, 3, 0, 1, 2, 3, 0, 1, 2, 3, 0, 1, 2, 3])
///     .hw_offload(true)
///     .build();
///
/// conn.add_qdisc("eth0", config).await?;
/// ```
#[derive(Debug, Clone)]
pub struct MqprioConfig {
    /// Number of traffic classes.
    pub num_tc: u8,
    /// Priority to traffic class mapping.
    pub prio_tc_map: [u8; 16],
    /// Enable hardware offload.
    pub hw: bool,
    /// Queue count for each traffic class.
    pub count: [u16; 16],
    /// Queue offset for each traffic class.
    pub offset: [u16; 16],
    /// Parent handle.
    pub parent: String,
    /// Qdisc handle.
    pub handle: Option<String>,
}

impl Default for MqprioConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl MqprioConfig {
    /// Create a new mqprio configuration builder.
    pub fn new() -> Self {
        Self {
            num_tc: 8,
            prio_tc_map: [0, 1, 2, 3, 4, 5, 6, 7, 0, 1, 1, 1, 3, 3, 3, 3],
            hw: true,
            count: [0; 16],
            offset: [0; 16],
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

    /// Set the number of traffic classes (1-16).
    pub fn num_tc(mut self, num_tc: u8) -> Self {
        self.num_tc = num_tc.min(16);
        self
    }

    /// Set the priority to traffic class mapping.
    ///
    /// The array maps Linux priority (0-15) to traffic class (0-num_tc-1).
    pub fn map(mut self, map: &[u8]) -> Self {
        for (i, &tc) in map.iter().enumerate().take(16) {
            self.prio_tc_map[i] = tc;
        }
        self
    }

    /// Enable or disable hardware offload.
    pub fn hw_offload(mut self, enable: bool) -> Self {
        self.hw = enable;
        self
    }

    /// Set queue configuration for traffic classes.
    ///
    /// Each entry is (count, offset) specifying number of queues and starting queue.
    pub fn queues(mut self, queues: &[(u16, u16)]) -> Self {
        for (i, &(c, o)) in queues.iter().enumerate().take(16) {
            self.count[i] = c;
            self.offset[i] = o;
        }
        self
    }

    /// Build the configuration.
    pub fn build(self) -> Self {
        self
    }
}

impl QdiscConfig for MqprioConfig {
    fn kind(&self) -> &'static str {
        "mqprio"
    }

    fn write_options(&self, builder: &mut MessageBuilder) -> Result<()> {
        use super::types::tc::qdisc::mqprio::TcMqprioQopt;

        let mut qopt = TcMqprioQopt::new()
            .with_num_tc(self.num_tc)
            .with_hw(self.hw);

        qopt.prio_tc_map = self.prio_tc_map;
        qopt.count = self.count;
        qopt.offset = self.offset;

        builder.append(&qopt);
        Ok(())
    }
}

// ============================================================================
// TaprioConfig (Time Aware Priority)
// ============================================================================

/// TAPRIO (Time Aware Priority) qdisc configuration.
///
/// TAPRIO implements IEEE 802.1Qbv Time-Aware Shaping for Time-Sensitive
/// Networking (TSN). It uses a time-based gate control list to schedule
/// traffic classes.
///
/// # Example
///
/// ```ignore
/// use nlink::netlink::tc::{TaprioConfig, TaprioSchedEntry};
///
/// // Create TAPRIO with a simple schedule
/// let config = TaprioConfig::new()
///     .num_tc(2)
///     .map(&[0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
///     .queues(&[(1, 0), (1, 1)])
///     .clockid(libc::CLOCK_TAI)
///     .base_time(0)
///     .cycle_time(1_000_000) // 1ms cycle
///     .entry(TaprioSchedEntry::set_gates(0x1, 500_000))  // TC0 open 500us
///     .entry(TaprioSchedEntry::set_gates(0x2, 500_000))  // TC1 open 500us
///     .build();
///
/// conn.add_qdisc("eth0", config).await?;
/// ```
#[derive(Debug, Clone)]
pub struct TaprioConfig {
    /// Number of traffic classes.
    pub num_tc: u8,
    /// Priority to traffic class mapping.
    pub prio_tc_map: [u8; 16],
    /// Queue count for each traffic class.
    pub count: [u16; 16],
    /// Queue offset for each traffic class.
    pub offset: [u16; 16],
    /// Clock ID (e.g., CLOCK_TAI).
    pub clockid: i32,
    /// Base time for schedule (nanoseconds since epoch).
    pub base_time: i64,
    /// Cycle time in nanoseconds.
    pub cycle_time: i64,
    /// Cycle time extension in nanoseconds.
    pub cycle_time_extension: i64,
    /// Schedule entries.
    pub entries: Vec<super::types::tc::qdisc::taprio::TaprioSchedEntry>,
    /// Flags (TXTIME_ASSIST, FULL_OFFLOAD).
    pub flags: u32,
    /// TX time delay in nanoseconds.
    pub txtime_delay: u32,
    /// Parent handle.
    pub parent: String,
    /// Qdisc handle.
    pub handle: Option<String>,
}

impl Default for TaprioConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl TaprioConfig {
    /// Create a new TAPRIO configuration builder.
    pub fn new() -> Self {
        Self {
            num_tc: 0,
            prio_tc_map: [0; 16],
            count: [0; 16],
            offset: [0; 16],
            clockid: -1,
            base_time: 0,
            cycle_time: 0,
            cycle_time_extension: 0,
            entries: Vec::new(),
            flags: 0,
            txtime_delay: 0,
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

    /// Set the number of traffic classes.
    pub fn num_tc(mut self, num_tc: u8) -> Self {
        self.num_tc = num_tc.min(16);
        self
    }

    /// Set the priority to traffic class mapping.
    pub fn map(mut self, map: &[u8]) -> Self {
        for (i, &tc) in map.iter().enumerate().take(16) {
            self.prio_tc_map[i] = tc;
        }
        self
    }

    /// Set queue configuration for traffic classes.
    pub fn queues(mut self, queues: &[(u16, u16)]) -> Self {
        for (i, &(c, o)) in queues.iter().enumerate().take(16) {
            self.count[i] = c;
            self.offset[i] = o;
        }
        self
    }

    /// Set the clock ID (e.g., libc::CLOCK_TAI).
    pub fn clockid(mut self, clockid: i32) -> Self {
        self.clockid = clockid;
        self
    }

    /// Set the base time in nanoseconds since epoch.
    pub fn base_time(mut self, base_time: i64) -> Self {
        self.base_time = base_time;
        self
    }

    /// Set the cycle time in nanoseconds.
    pub fn cycle_time(mut self, cycle_time: i64) -> Self {
        self.cycle_time = cycle_time;
        self
    }

    /// Set the cycle time extension in nanoseconds.
    pub fn cycle_time_extension(mut self, extension: i64) -> Self {
        self.cycle_time_extension = extension;
        self
    }

    /// Add a schedule entry.
    pub fn entry(mut self, entry: super::types::tc::qdisc::taprio::TaprioSchedEntry) -> Self {
        self.entries.push(entry);
        self
    }

    /// Enable TXTIME assist mode.
    pub fn txtime_assist(mut self, enable: bool) -> Self {
        use super::types::tc::qdisc::taprio::TAPRIO_ATTR_FLAG_TXTIME_ASSIST;
        if enable {
            self.flags |= TAPRIO_ATTR_FLAG_TXTIME_ASSIST;
        } else {
            self.flags &= !TAPRIO_ATTR_FLAG_TXTIME_ASSIST;
        }
        self
    }

    /// Enable full offload mode.
    pub fn full_offload(mut self, enable: bool) -> Self {
        use super::types::tc::qdisc::taprio::TAPRIO_ATTR_FLAG_FULL_OFFLOAD;
        if enable {
            self.flags |= TAPRIO_ATTR_FLAG_FULL_OFFLOAD;
        } else {
            self.flags &= !TAPRIO_ATTR_FLAG_FULL_OFFLOAD;
        }
        self
    }

    /// Set the TX time delay in nanoseconds.
    pub fn txtime_delay(mut self, delay: u32) -> Self {
        self.txtime_delay = delay;
        self
    }

    /// Build the configuration.
    pub fn build(self) -> Self {
        self
    }
}

impl QdiscConfig for TaprioConfig {
    fn kind(&self) -> &'static str {
        "taprio"
    }

    fn write_options(&self, builder: &mut MessageBuilder) -> Result<()> {
        use super::types::tc::qdisc::mqprio::TcMqprioQopt;
        use super::types::tc::qdisc::taprio::*;

        // Write the mqprio-style priomap
        let mut qopt = TcMqprioQopt::new().with_num_tc(self.num_tc).with_hw(false);
        qopt.prio_tc_map = self.prio_tc_map;
        qopt.count = self.count;
        qopt.offset = self.offset;
        builder.append_attr(TCA_TAPRIO_ATTR_PRIOMAP, qopt.as_bytes());

        // Clock ID
        if self.clockid >= 0 {
            builder.append_attr(TCA_TAPRIO_ATTR_SCHED_CLOCKID, &self.clockid.to_ne_bytes());
        }

        // Base time
        if self.base_time != 0 {
            builder.append_attr(
                TCA_TAPRIO_ATTR_SCHED_BASE_TIME,
                &self.base_time.to_ne_bytes(),
            );
        }

        // Cycle time
        if self.cycle_time != 0 {
            builder.append_attr(
                TCA_TAPRIO_ATTR_SCHED_CYCLE_TIME,
                &self.cycle_time.to_ne_bytes(),
            );
        }

        // Cycle time extension
        if self.cycle_time_extension != 0 {
            builder.append_attr(
                TCA_TAPRIO_ATTR_SCHED_CYCLE_TIME_EXTENSION,
                &self.cycle_time_extension.to_ne_bytes(),
            );
        }

        // Flags
        if self.flags != 0 {
            builder.append_attr(TCA_TAPRIO_ATTR_FLAGS, &self.flags.to_ne_bytes());
        }

        // TX time delay
        if self.txtime_delay != 0 {
            builder.append_attr(
                TCA_TAPRIO_ATTR_TXTIME_DELAY,
                &self.txtime_delay.to_ne_bytes(),
            );
        }

        // Schedule entries
        if !self.entries.is_empty() {
            let list_token = builder.nest_start(TCA_TAPRIO_ATTR_SCHED_ENTRY_LIST);
            for (idx, entry) in self.entries.iter().enumerate() {
                let entry_token = builder.nest_start(TCA_TAPRIO_ATTR_SCHED_SINGLE_ENTRY);
                builder.append_attr(TCA_TAPRIO_SCHED_ENTRY_INDEX, &(idx as u32).to_ne_bytes());
                builder.append_attr(TCA_TAPRIO_SCHED_ENTRY_CMD, &[entry.cmd]);
                builder.append_attr(
                    TCA_TAPRIO_SCHED_ENTRY_GATE_MASK,
                    &entry.gate_mask.to_ne_bytes(),
                );
                builder.append_attr(
                    TCA_TAPRIO_SCHED_ENTRY_INTERVAL,
                    &entry.interval.to_ne_bytes(),
                );
                builder.nest_end(entry_token);
            }
            builder.nest_end(list_token);
        }

        Ok(())
    }
}

// ============================================================================
// HfscConfig (Hierarchical Fair Service Curve)
// ============================================================================

/// HFSC (Hierarchical Fair Service Curve) qdisc configuration.
///
/// HFSC is a hierarchical packet scheduler that provides guaranteed bandwidth
/// and delay bounds. It uses service curves to define bandwidth allocations.
///
/// # Example
///
/// ```ignore
/// use nlink::netlink::tc::HfscConfig;
///
/// // Create HFSC qdisc with default class 0x10
/// let config = HfscConfig::new()
///     .default_class(0x10)
///     .build();
///
/// conn.add_qdisc("eth0", config).await?;
/// ```
#[derive(Debug, Clone)]
pub struct HfscConfig {
    /// Default class for unclassified packets.
    pub default_class: u16,
    /// Parent handle.
    pub parent: String,
    /// Qdisc handle.
    pub handle: Option<String>,
}

impl Default for HfscConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl HfscConfig {
    /// Create a new HFSC configuration builder.
    pub fn new() -> Self {
        Self {
            default_class: 0,
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

    /// Set the default class for unclassified packets.
    pub fn default_class(mut self, classid: u16) -> Self {
        self.default_class = classid;
        self
    }

    /// Build the configuration.
    pub fn build(self) -> Self {
        self
    }
}

impl QdiscConfig for HfscConfig {
    fn kind(&self) -> &'static str {
        "hfsc"
    }

    fn write_options(&self, builder: &mut MessageBuilder) -> Result<()> {
        use super::types::tc::qdisc::hfsc::TcHfscQopt;

        let qopt = TcHfscQopt::new(self.default_class);
        builder.append(&qopt);
        Ok(())
    }
}

// ============================================================================
// EtfConfig (Earliest TxTime First)
// ============================================================================

/// ETF (Earliest TxTime First) qdisc configuration.
///
/// ETF is a qdisc for time-based transmission scheduling. Packets are
/// transmitted at the exact time specified in the SO_TXTIME socket option.
/// This is useful for Time-Sensitive Networking (TSN) applications.
///
/// # Example
///
/// ```ignore
/// use nlink::netlink::tc::EtfConfig;
///
/// // Create ETF with CLOCK_TAI and hardware offload
/// let config = EtfConfig::new()
///     .clockid(libc::CLOCK_TAI)
///     .delta_ns(300000)  // 300us
///     .offload(true)
///     .deadline_mode(true)
///     .build();
///
/// conn.add_qdisc("eth0", config).await?;
/// ```
#[derive(Debug, Clone)]
pub struct EtfConfig {
    /// Delta time in nanoseconds.
    pub delta: i32,
    /// Clock ID (e.g., CLOCK_TAI, CLOCK_MONOTONIC).
    pub clockid: i32,
    /// Enable deadline mode.
    pub deadline_mode: bool,
    /// Enable hardware offload.
    pub offload: bool,
    /// Skip socket check.
    pub skip_sock_check: bool,
    /// Parent handle.
    pub parent: String,
    /// Qdisc handle.
    pub handle: Option<String>,
}

impl Default for EtfConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl EtfConfig {
    /// Create a new ETF configuration builder.
    pub fn new() -> Self {
        Self {
            delta: 0,
            clockid: -1, // CLOCKID_INVALID
            deadline_mode: false,
            offload: false,
            skip_sock_check: false,
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

    /// Set the clock ID (e.g., libc::CLOCK_TAI, libc::CLOCK_MONOTONIC).
    pub fn clockid(mut self, clockid: i32) -> Self {
        self.clockid = clockid;
        self
    }

    /// Set the delta time in nanoseconds.
    ///
    /// This is the time offset from the scheduled transmission time.
    pub fn delta_ns(mut self, delta: i32) -> Self {
        self.delta = delta;
        self
    }

    /// Enable or disable deadline mode.
    ///
    /// In deadline mode, the transmission time is treated as a deadline
    /// rather than an exact time.
    pub fn deadline_mode(mut self, enable: bool) -> Self {
        self.deadline_mode = enable;
        self
    }

    /// Enable or disable hardware offload.
    ///
    /// When enabled, the NIC handles the time-based transmission scheduling.
    pub fn offload(mut self, enable: bool) -> Self {
        self.offload = enable;
        self
    }

    /// Enable or disable socket capability check skip.
    pub fn skip_sock_check(mut self, enable: bool) -> Self {
        self.skip_sock_check = enable;
        self
    }

    /// Build the configuration.
    pub fn build(self) -> Self {
        self
    }
}

impl QdiscConfig for EtfConfig {
    fn kind(&self) -> &'static str {
        "etf"
    }

    fn write_options(&self, builder: &mut MessageBuilder) -> Result<()> {
        use super::types::tc::qdisc::etf::{
            TC_ETF_DEADLINE_MODE_ON, TC_ETF_OFFLOAD_ON, TC_ETF_SKIP_SOCK_CHECK, TCA_ETF_PARMS,
            TcEtfQopt,
        };

        let mut flags = 0i32;
        if self.deadline_mode {
            flags |= TC_ETF_DEADLINE_MODE_ON;
        }
        if self.offload {
            flags |= TC_ETF_OFFLOAD_ON;
        }
        if self.skip_sock_check {
            flags |= TC_ETF_SKIP_SOCK_CHECK;
        }

        let qopt = TcEtfQopt {
            delta: self.delta,
            clockid: self.clockid,
            flags,
        };

        builder.append_attr(TCA_ETF_PARMS, qopt.as_bytes());
        Ok(())
    }
}

// ============================================================================
// Helper functions
// ============================================================================

/// Convert interface name to index.
fn get_ifindex(name: &str) -> Result<u32> {
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
    /// use nlink::netlink::tc::NetemConfig;
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
        self.add_qdisc_by_index_full(ifindex, parent, handle, config)
            .await
    }

    /// Add a qdisc by interface index.
    ///
    /// This is useful for namespace-aware operations where you've already
    /// resolved the interface index via `conn.get_link_by_name()`.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use nlink::netlink::{namespace, tc::NetemConfig};
    /// use std::time::Duration;
    ///
    /// let conn = namespace::connection_for("myns")?;
    /// let link = conn.get_link_by_name("eth0").await?;
    ///
    /// let netem = NetemConfig::new()
    ///     .delay(Duration::from_millis(100))
    ///     .build();
    ///
    /// conn.add_qdisc_by_index(link.ifindex(), netem).await?;
    /// ```
    pub async fn add_qdisc_by_index(&self, ifindex: u32, config: impl QdiscConfig) -> Result<()> {
        self.add_qdisc_by_index_full(ifindex, "root", None, config)
            .await
    }

    /// Add a qdisc by interface index with explicit parent and handle.
    pub async fn add_qdisc_by_index_full(
        &self,
        ifindex: u32,
        parent: &str,
        handle: Option<&str>,
        config: impl QdiscConfig,
    ) -> Result<()> {
        let parent_handle = parse_handle(parent)?;
        let qdisc_handle = handle.map(parse_handle).transpose()?.unwrap_or(0);

        let tcmsg = TcMsg::new()
            .with_ifindex(ifindex as i32)
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
        self.del_qdisc_by_index_full(ifindex, parent, handle).await
    }

    /// Delete a qdisc by interface index.
    ///
    /// This is useful for namespace-aware operations where you've already
    /// resolved the interface index via `conn.get_link_by_name()`.
    pub async fn del_qdisc_by_index(&self, ifindex: u32, parent: &str) -> Result<()> {
        self.del_qdisc_by_index_full(ifindex, parent, None).await
    }

    /// Delete a qdisc by interface index with explicit handle.
    pub async fn del_qdisc_by_index_full(
        &self,
        ifindex: u32,
        parent: &str,
        handle: Option<&str>,
    ) -> Result<()> {
        let parent_handle = parse_handle(parent)?;
        let qdisc_handle = handle.map(parse_handle).transpose()?.unwrap_or(0);

        let tcmsg = TcMsg::new()
            .with_ifindex(ifindex as i32)
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
        self.replace_qdisc_by_index_full(ifindex, parent, handle, config)
            .await
    }

    /// Replace a qdisc by interface index (add or update).
    ///
    /// This is useful for namespace-aware operations where you've already
    /// resolved the interface index via `conn.get_link_by_name()`.
    pub async fn replace_qdisc_by_index(
        &self,
        ifindex: u32,
        config: impl QdiscConfig,
    ) -> Result<()> {
        self.replace_qdisc_by_index_full(ifindex, "root", None, config)
            .await
    }

    /// Replace a qdisc by interface index with explicit parent and handle.
    pub async fn replace_qdisc_by_index_full(
        &self,
        ifindex: u32,
        parent: &str,
        handle: Option<&str>,
        config: impl QdiscConfig,
    ) -> Result<()> {
        let parent_handle = parse_handle(parent)?;
        let qdisc_handle = handle.map(parse_handle).transpose()?.unwrap_or(0);

        let tcmsg = TcMsg::new()
            .with_ifindex(ifindex as i32)
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
        self.change_qdisc_by_index_full(ifindex, parent, handle, config)
            .await
    }

    /// Change a qdisc's parameters by interface index.
    ///
    /// This is useful for namespace-aware operations where you've already
    /// resolved the interface index via `conn.get_link_by_name()`.
    pub async fn change_qdisc_by_index(
        &self,
        ifindex: u32,
        parent: &str,
        config: impl QdiscConfig,
    ) -> Result<()> {
        self.change_qdisc_by_index_full(ifindex, parent, None, config)
            .await
    }

    /// Change a qdisc by interface index with explicit handle.
    pub async fn change_qdisc_by_index_full(
        &self,
        ifindex: u32,
        parent: &str,
        handle: Option<&str>,
        config: impl QdiscConfig,
    ) -> Result<()> {
        let parent_handle = parse_handle(parent)?;
        let qdisc_handle = handle.map(parse_handle).transpose()?.unwrap_or(0);

        let tcmsg = TcMsg::new()
            .with_ifindex(ifindex as i32)
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

    #[test]
    fn test_drr_builder() {
        let config = DrrConfig::new().handle("1:").build();

        assert_eq!(config.handle, Some("1:".to_string()));
        assert_eq!(config.parent, "root");
        assert_eq!(config.kind(), "drr");
    }

    #[test]
    fn test_qfq_builder() {
        let config = QfqConfig::new().handle("1:").parent("root").build();

        assert_eq!(config.handle, Some("1:".to_string()));
        assert_eq!(config.parent, "root");
        assert_eq!(config.kind(), "qfq");
    }

    #[test]
    fn test_plug_builder() {
        let config = PlugConfig::new().limit(10000).build();

        assert_eq!(config.limit, Some(10000));
        assert_eq!(config.kind(), "plug");
    }

    #[test]
    fn test_mqprio_builder() {
        let config = MqprioConfig::new()
            .num_tc(4)
            .map(&[0, 1, 2, 3, 0, 1, 2, 3, 0, 1, 2, 3, 0, 1, 2, 3])
            .hw_offload(true)
            .queues(&[(2, 0), (2, 2), (2, 4), (2, 6)])
            .build();

        assert_eq!(config.num_tc, 4);
        assert!(config.hw);
        assert_eq!(config.prio_tc_map[0], 0);
        assert_eq!(config.prio_tc_map[3], 3);
        assert_eq!(config.count[0], 2);
        assert_eq!(config.offset[1], 2);
        assert_eq!(config.kind(), "mqprio");
    }

    #[test]
    fn test_etf_builder() {
        let config = EtfConfig::new()
            .clockid(1) // CLOCK_MONOTONIC on most systems
            .delta_ns(300000)
            .deadline_mode(true)
            .offload(true)
            .skip_sock_check(false)
            .build();

        assert_eq!(config.clockid, 1);
        assert_eq!(config.delta, 300000);
        assert!(config.deadline_mode);
        assert!(config.offload);
        assert!(!config.skip_sock_check);
        assert_eq!(config.kind(), "etf");
    }

    #[test]
    fn test_hfsc_builder() {
        let config = HfscConfig::new().default_class(0x10).handle("1:").build();

        assert_eq!(config.default_class, 0x10);
        assert_eq!(config.handle, Some("1:".to_string()));
        assert_eq!(config.kind(), "hfsc");
    }

    #[test]
    fn test_taprio_builder() {
        let config = TaprioConfig::new()
            .num_tc(2)
            .map(&[0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
            .queues(&[(1, 0), (1, 1)])
            .clockid(11) // CLOCK_TAI
            .base_time(1000000000)
            .cycle_time(1000000)
            .entry(TaprioSchedEntry::set_gates(0x1, 500000))
            .entry(TaprioSchedEntry::set_gates(0x2, 500000))
            .full_offload(true)
            .build();

        assert_eq!(config.num_tc, 2);
        assert_eq!(config.clockid, 11);
        assert_eq!(config.base_time, 1000000000);
        assert_eq!(config.cycle_time, 1000000);
        assert_eq!(config.entries.len(), 2);
        assert_eq!(config.entries[0].gate_mask, 0x1);
        assert_eq!(config.entries[0].interval, 500000);
        assert_eq!(config.entries[1].gate_mask, 0x2);
        assert!(config.flags & 2 != 0); // FULL_OFFLOAD flag
        assert_eq!(config.kind(), "taprio");
    }
}
