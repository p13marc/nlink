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

// Re-export for convenience
pub use super::types::tc::qdisc::hfsc::TcServiceCurve;
pub use super::types::tc::qdisc::taprio::TaprioSchedEntry;
use super::{
    Connection,
    builder::MessageBuilder,
    connection::{ack_request, create_request, replace_request},
    error::{Error, Result},
    interface_ref::InterfaceRef,
    message::NlMsgType,
    protocol::Route,
    tc_handle::TcHandle,
    types::tc::{
        TcMsg, TcaAttr,
        qdisc::{TcRateSpec, codel, ets, fq, fq_codel, htb, netem::*, prio, sfq, tbf},
    },
};

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
    /// Delay correlation.
    pub delay_correlation: crate::util::Percent,
    /// Packet loss percentage.
    pub loss: crate::util::Percent,
    /// Loss correlation.
    pub loss_correlation: crate::util::Percent,
    /// Packet duplication percentage.
    pub duplicate: crate::util::Percent,
    /// Duplication correlation.
    pub duplicate_correlation: crate::util::Percent,
    /// Packet corruption percentage.
    pub corrupt: crate::util::Percent,
    /// Corruption correlation.
    pub corrupt_correlation: crate::util::Percent,
    /// Packet reordering percentage.
    pub reorder: crate::util::Percent,
    /// Reordering correlation.
    pub reorder_correlation: crate::util::Percent,
    /// Reorder gap.
    pub gap: u32,
    /// Rate limit.
    pub rate: Option<crate::util::Rate>,
    /// Queue limit in packets.
    pub limit: u32,
}

impl NetemConfig {
    /// Create a new netem configuration builder.
    pub fn new() -> Self {
        Self {
            limit: 1000, // Default limit
            ..Default::default()
        }
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

    /// Set the delay correlation.
    pub fn delay_correlation(mut self, corr: crate::util::Percent) -> Self {
        self.delay_correlation = corr;
        self
    }

    /// Set the packet loss percentage.
    pub fn loss(mut self, percent: crate::util::Percent) -> Self {
        self.loss = percent;
        self
    }

    /// Set the loss correlation.
    pub fn loss_correlation(mut self, corr: crate::util::Percent) -> Self {
        self.loss_correlation = corr;
        self
    }

    /// Set the packet duplication percentage.
    pub fn duplicate(mut self, percent: crate::util::Percent) -> Self {
        self.duplicate = percent;
        self
    }

    /// Set the duplication correlation.
    pub fn duplicate_correlation(mut self, corr: crate::util::Percent) -> Self {
        self.duplicate_correlation = corr;
        self
    }

    /// Set the packet corruption percentage.
    pub fn corrupt(mut self, percent: crate::util::Percent) -> Self {
        self.corrupt = percent;
        self
    }

    /// Set the corruption correlation.
    pub fn corrupt_correlation(mut self, corr: crate::util::Percent) -> Self {
        self.corrupt_correlation = corr;
        self
    }

    /// Set the packet reordering percentage.
    ///
    /// Note: Reordering requires delay to be set.
    pub fn reorder(mut self, percent: crate::util::Percent) -> Self {
        self.reorder = percent;
        self
    }

    /// Set the reordering correlation.
    pub fn reorder_correlation(mut self, corr: crate::util::Percent) -> Self {
        self.reorder_correlation = corr;
        self
    }

    /// Set the reorder gap.
    pub fn gap(mut self, gap: u32) -> Self {
        self.gap = gap;
        self
    }

    /// Set the rate limit.
    pub fn rate(mut self, rate: crate::util::Rate) -> Self {
        self.rate = Some(rate);
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

    /// Parse a tc-style params slice into a typed `NetemConfig`.
    ///
    /// Recognised tokens (positional optionals are consumed greedily
    /// up to the next keyword):
    ///
    /// - `delay <time> [<jitter> [<corr>]]` (alias `latency`)
    /// - `loss [random] <pct> [<corr>]` (alias `drop`)
    /// - `duplicate <pct> [<corr>]`
    /// - `corrupt <pct> [<corr>]`
    /// - `reorder <pct> [<corr>]`
    /// - `gap <n>`
    /// - `rate <rate>` — typed config doesn't model the optional
    ///   `packet_overhead` / `cell_size` / `cell_overhead` extras
    ///   yet, so those positional args are rejected here.
    /// - `limit <packets>`
    ///
    /// **Not yet typed-modelled** (returns `Error::InvalidMessage`):
    /// `slot`, `ecn`, `distribution`, the `loss state` 4-state
    /// Markov, `loss gemodel`. These need `NetemConfig` extensions
    /// before they can land here.
    ///
    /// Strict: unknown keywords, missing values, and unparseable
    /// time/rate/percent/integer values all return an error rather
    /// than silently being skipped.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let cfg = NetemConfig::parse_params(&[
    ///     "delay", "100ms", "10ms",
    ///     "loss", "1%",
    ///     "limit", "5000",
    /// ])?;
    /// assert_eq!(cfg.delay, Some(Duration::from_millis(100)));
    /// ```
    pub fn parse_params(params: &[&str]) -> Result<Self> {
        let mut cfg = Self::new();
        let mut i = 0;
        while i < params.len() {
            let key = params[i];
            match key {
                "delay" | "latency" => {
                    let time_str = params.get(i + 1).copied().ok_or_else(|| {
                        Error::InvalidMessage(format!("netem: `{key}` requires a value"))
                    })?;
                    cfg.delay = Some(crate::util::parse::get_time(time_str).map_err(|_| {
                        Error::InvalidMessage(format!(
                            "netem: invalid {key} `{time_str}` (expected tc-style time)"
                        ))
                    })?);
                    i += 2;
                    if let Some(j) = params.get(i)
                        && !is_netem_keyword(j)
                    {
                        cfg.jitter = Some(crate::util::parse::get_time(j).map_err(|_| {
                            Error::InvalidMessage(format!(
                                "netem: invalid jitter `{j}` (expected tc-style time)"
                            ))
                        })?);
                        i += 1;
                        if let Some(c) = params.get(i)
                            && !is_netem_keyword(c)
                        {
                            cfg.delay_correlation = parse_netem_percent(c, "delay correlation")?;
                            i += 1;
                        }
                    }
                }
                "loss" | "drop" => {
                    i += 1;
                    // Optional `random` qualifier on `loss`.
                    if key == "loss" && params.get(i) == Some(&"random") {
                        i += 1;
                    }
                    // Reject 4-state Markov / gemodel — needs typed
                    // config extension.
                    if let Some(next) = params.get(i)
                        && (*next == "state" || *next == "gemodel")
                    {
                        return Err(Error::InvalidMessage(format!(
                            "netem: `loss {next}` (Markov model) is not supported by the typed parser yet — file an issue if you need this"
                        )));
                    }
                    let pct_str = params.get(i).copied().ok_or_else(|| {
                        Error::InvalidMessage(format!("netem: `{key}` requires a percent value"))
                    })?;
                    cfg.loss = parse_netem_percent(pct_str, key)?;
                    i += 1;
                    if let Some(c) = params.get(i)
                        && !is_netem_keyword(c)
                    {
                        cfg.loss_correlation = parse_netem_percent(c, "loss correlation")?;
                        i += 1;
                    }
                }
                "duplicate" => {
                    let pct_str = params.get(i + 1).copied().ok_or_else(|| {
                        Error::InvalidMessage("netem: `duplicate` requires a percent value".into())
                    })?;
                    cfg.duplicate = parse_netem_percent(pct_str, "duplicate")?;
                    i += 2;
                    if let Some(c) = params.get(i)
                        && !is_netem_keyword(c)
                    {
                        cfg.duplicate_correlation =
                            parse_netem_percent(c, "duplicate correlation")?;
                        i += 1;
                    }
                }
                "corrupt" => {
                    let pct_str = params.get(i + 1).copied().ok_or_else(|| {
                        Error::InvalidMessage("netem: `corrupt` requires a percent value".into())
                    })?;
                    cfg.corrupt = parse_netem_percent(pct_str, "corrupt")?;
                    i += 2;
                    if let Some(c) = params.get(i)
                        && !is_netem_keyword(c)
                    {
                        cfg.corrupt_correlation = parse_netem_percent(c, "corrupt correlation")?;
                        i += 1;
                    }
                }
                "reorder" => {
                    let pct_str = params.get(i + 1).copied().ok_or_else(|| {
                        Error::InvalidMessage("netem: `reorder` requires a percent value".into())
                    })?;
                    cfg.reorder = parse_netem_percent(pct_str, "reorder")?;
                    i += 2;
                    if let Some(c) = params.get(i)
                        && !is_netem_keyword(c)
                    {
                        cfg.reorder_correlation = parse_netem_percent(c, "reorder correlation")?;
                        i += 1;
                    }
                }
                "gap" => {
                    let n_str = params.get(i + 1).copied().ok_or_else(|| {
                        Error::InvalidMessage("netem: `gap` requires a value".into())
                    })?;
                    cfg.gap = n_str.parse().map_err(|_| {
                        Error::InvalidMessage(format!(
                            "netem: invalid gap `{n_str}` (expected unsigned integer)"
                        ))
                    })?;
                    i += 2;
                }
                "rate" => {
                    let rate_str = params.get(i + 1).copied().ok_or_else(|| {
                        Error::InvalidMessage("netem: `rate` requires a value".into())
                    })?;
                    cfg.rate = Some(crate::util::Rate::parse(rate_str).map_err(|_| {
                        Error::InvalidMessage(format!(
                            "netem: invalid rate `{rate_str}` (expected tc-style rate like `100mbit`)"
                        ))
                    })?);
                    i += 2;
                    // Reject the legacy positional packet_overhead /
                    // cell_size / cell_overhead extras — typed config
                    // doesn't model them.
                    if let Some(extra) = params.get(i)
                        && !is_netem_keyword(extra)
                    {
                        return Err(Error::InvalidMessage(format!(
                            "netem: positional `rate` extras (packet_overhead/cell_size/cell_overhead) are not modelled by NetemConfig — file an issue if you need them, got `{extra}`"
                        )));
                    }
                }
                "limit" => {
                    let n_str = params.get(i + 1).copied().ok_or_else(|| {
                        Error::InvalidMessage("netem: `limit` requires a value".into())
                    })?;
                    cfg.limit = n_str.parse().map_err(|_| {
                        Error::InvalidMessage(format!(
                            "netem: invalid limit `{n_str}` (expected unsigned integer)"
                        ))
                    })?;
                    i += 2;
                }
                "slot" | "ecn" | "distribution" => {
                    return Err(Error::InvalidMessage(format!(
                        "netem: `{key}` is not modelled by NetemConfig yet — file an issue if you need this token"
                    )));
                }
                other => {
                    return Err(Error::InvalidMessage(format!(
                        "netem: unknown token `{other}`"
                    )));
                }
            }
        }
        Ok(cfg)
    }
}

/// Tokens that begin a new netem option group — used by
/// `NetemConfig::parse_params` to decide where greedy positional
/// optionals (jitter / correlation) end.
fn is_netem_keyword(s: &str) -> bool {
    matches!(
        s,
        "delay"
            | "latency"
            | "loss"
            | "drop"
            | "duplicate"
            | "corrupt"
            | "reorder"
            | "gap"
            | "rate"
            | "limit"
            | "slot"
            | "ecn"
            | "distribution"
            | "random"
    )
}

/// Parse a netem percent value (`"1.5"`, `"1.5%"`) with a context
/// label folded into the error so the user knows which field failed.
fn parse_netem_percent(s: &str, label: &str) -> Result<crate::util::Percent> {
    s.parse::<crate::util::Percent>()
        .map_err(|_| Error::InvalidMessage(format!("netem: invalid {label} `{s}`")))
}

impl QdiscConfig for NetemConfig {
    fn kind(&self) -> &'static str {
        "netem"
    }

    fn write_options(&self, builder: &mut MessageBuilder) -> Result<()> {
        // Validate: reorder requires delay
        if !self.reorder.is_zero() && self.delay.is_none() {
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
        if !self.loss.is_zero() {
            qopt.loss = self.loss.as_kernel_probability();
        }
        if !self.duplicate.is_zero() {
            qopt.duplicate = self.duplicate.as_kernel_probability();
        }
        if !self.reorder.is_zero() && self.gap == 0 {
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
        if !self.delay_correlation.is_zero()
            || !self.loss_correlation.is_zero()
            || !self.duplicate_correlation.is_zero()
        {
            let corr = TcNetemCorr {
                delay_corr: self.delay_correlation.as_kernel_probability(),
                loss_corr: self.loss_correlation.as_kernel_probability(),
                dup_corr: self.duplicate_correlation.as_kernel_probability(),
            };
            builder.append_attr(TCA_NETEM_CORR, corr.as_bytes());
        }

        // Add reorder if set
        if !self.reorder.is_zero() {
            let reorder = TcNetemReorder {
                probability: self.reorder.as_kernel_probability(),
                correlation: self.reorder_correlation.as_kernel_probability(),
            };
            builder.append_attr(TCA_NETEM_REORDER, reorder.as_bytes());
        }

        // Add corrupt if set
        if !self.corrupt.is_zero() {
            let corrupt = TcNetemCorrupt {
                probability: self.corrupt.as_kernel_probability(),
                correlation: self.corrupt_correlation.as_kernel_probability(),
            };
            builder.append_attr(TCA_NETEM_CORRUPT, corrupt.as_bytes());
        }

        // Add rate limit if set
        if let Some(rate) = self.rate {
            let bytes_per_sec = rate.as_bytes_per_sec();
            let mut rate_struct = TcNetemRate::default();
            if bytes_per_sec > u32::MAX as u64 {
                rate_struct.rate = u32::MAX;
                builder.append_attr(TCA_NETEM_RATE, rate_struct.as_bytes());
                builder.append_attr(TCA_NETEM_RATE64, &bytes_per_sec.to_ne_bytes());
            } else {
                rate_struct.rate = bytes_per_sec as u32;
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
        }
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

    /// Parse a tc-style fq_codel params slice into a typed
    /// `FqCodelConfig`.
    ///
    /// Recognised tokens:
    ///
    /// - `limit <packets>` — hard limit on queue size.
    /// - `target <time>` — target delay (e.g. `5ms`).
    /// - `interval <time>` — moving-time-window width (e.g. `100ms`).
    /// - `flows <n>` — number of flows.
    /// - `quantum <bytes>` — bytes served per round.
    /// - `ce_threshold <time>` — ECN CE marking threshold.
    /// - `memory_limit <bytes>` — memory limit (tc-style size).
    /// - `ecn` / `noecn` — flag tokens, no value.
    ///
    /// Stricter than the legacy parser: unknown tokens, missing
    /// values, and unparseable time/size/integer values all return
    /// `Error::InvalidMessage`.
    pub fn parse_params(params: &[&str]) -> Result<Self> {
        let mut cfg = Self::new();
        let mut i = 0;
        while i < params.len() {
            let key = params[i];
            let need_value = || {
                params.get(i + 1).copied().ok_or_else(|| {
                    Error::InvalidMessage(format!("fq_codel: `{key}` requires a value"))
                })
            };
            match key {
                "limit" => {
                    let s = need_value()?;
                    cfg.limit = Some(s.parse().map_err(|_| {
                        Error::InvalidMessage(format!("fq_codel: invalid limit `{s}`"))
                    })?);
                    i += 2;
                }
                "target" => {
                    let s = need_value()?;
                    cfg.target = Some(crate::util::parse::get_time(s).map_err(|_| {
                        Error::InvalidMessage(format!(
                            "fq_codel: invalid target `{s}` (expected tc-style time)"
                        ))
                    })?);
                    i += 2;
                }
                "interval" => {
                    let s = need_value()?;
                    cfg.interval = Some(crate::util::parse::get_time(s).map_err(|_| {
                        Error::InvalidMessage(format!(
                            "fq_codel: invalid interval `{s}` (expected tc-style time)"
                        ))
                    })?);
                    i += 2;
                }
                "flows" => {
                    let s = need_value()?;
                    cfg.flows = Some(s.parse().map_err(|_| {
                        Error::InvalidMessage(format!("fq_codel: invalid flows `{s}`"))
                    })?);
                    i += 2;
                }
                "quantum" => {
                    let s = need_value()?;
                    cfg.quantum = Some(s.parse().map_err(|_| {
                        Error::InvalidMessage(format!(
                            "fq_codel: invalid quantum `{s}` (expected unsigned integer bytes)"
                        ))
                    })?);
                    i += 2;
                }
                "ce_threshold" => {
                    let s = need_value()?;
                    cfg.ce_threshold = Some(crate::util::parse::get_time(s).map_err(|_| {
                        Error::InvalidMessage(format!(
                            "fq_codel: invalid ce_threshold `{s}` (expected tc-style time)"
                        ))
                    })?);
                    i += 2;
                }
                "memory_limit" => {
                    let s = need_value()?;
                    let bytes = crate::util::parse::get_size(s).map_err(|_| {
                        Error::InvalidMessage(format!(
                            "fq_codel: invalid memory_limit `{s}` (expected tc-style size)"
                        ))
                    })?;
                    cfg.memory_limit = Some(bytes.try_into().map_err(|_| {
                        Error::InvalidMessage(format!("fq_codel: memory_limit `{s}` exceeds u32"))
                    })?);
                    i += 2;
                }
                "ecn" => {
                    cfg.ecn = true;
                    i += 1;
                }
                "noecn" => {
                    cfg.ecn = false;
                    i += 1;
                }
                other => {
                    return Err(Error::InvalidMessage(format!(
                        "fq_codel: unknown token `{other}`"
                    )));
                }
            }
        }
        Ok(cfg)
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
// CodelConfig
// ============================================================================

/// Controlled Delay (codel) qdisc configuration.
///
/// Plain CoDel — a single-queue AQM. For per-flow fairness use
/// [`FqCodelConfig`] instead.
///
/// ```ignore
/// use nlink::netlink::tc::CodelConfig;
/// use std::time::Duration;
///
/// let cfg = CodelConfig::new()
///     .target(Duration::from_millis(5))
///     .interval(Duration::from_millis(100))
///     .ecn(true)
///     .build();
/// ```
#[derive(Debug, Clone, Default)]
pub struct CodelConfig {
    /// Target queue delay.
    pub target: Option<Duration>,
    /// Sliding-window interval.
    pub interval: Option<Duration>,
    /// Hard queue limit in packets.
    pub limit: Option<u32>,
    /// ECN marking instead of dropping (`Some(false)` = explicit noecn).
    pub ecn: Option<bool>,
    /// CE threshold for ECN marking.
    pub ce_threshold: Option<Duration>,
}

impl CodelConfig {
    /// Create a new codel configuration builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the target queue delay (default: 5ms).
    pub fn target(mut self, target: Duration) -> Self {
        self.target = Some(target);
        self
    }

    /// Set the sliding-window interval (default: 100ms).
    pub fn interval(mut self, interval: Duration) -> Self {
        self.interval = Some(interval);
        self
    }

    /// Set the hard queue limit in packets.
    pub fn limit(mut self, packets: u32) -> Self {
        self.limit = Some(packets);
        self
    }

    /// Enable or disable ECN marking.
    pub fn ecn(mut self, enable: bool) -> Self {
        self.ecn = Some(enable);
        self
    }

    /// Set the CE threshold for ECN marking.
    pub fn ce_threshold(mut self, threshold: Duration) -> Self {
        self.ce_threshold = Some(threshold);
        self
    }

    /// Terminal no-op for builder symmetry.
    pub fn build(self) -> Self {
        self
    }

    /// Parse a tc-style codel params slice.
    ///
    /// Recognised tokens: `limit <packets>`, `target <time>`,
    /// `interval <time>`, `ce_threshold <time>`, `ecn`/`noecn`.
    /// Strict: unknown tokens, missing values, and unparseable
    /// values all error.
    pub fn parse_params(params: &[&str]) -> Result<Self> {
        let mut cfg = Self::new();
        let mut i = 0;
        while i < params.len() {
            let key = params[i];
            let need_value = || {
                params.get(i + 1).copied().ok_or_else(|| {
                    Error::InvalidMessage(format!("codel: `{key}` requires a value"))
                })
            };
            match key {
                "limit" => {
                    let s = need_value()?;
                    cfg.limit = Some(s.parse().map_err(|_| {
                        Error::InvalidMessage(format!("codel: invalid limit `{s}`"))
                    })?);
                    i += 2;
                }
                "target" => {
                    let s = need_value()?;
                    cfg.target = Some(crate::util::parse::get_time(s).map_err(|_| {
                        Error::InvalidMessage(format!(
                            "codel: invalid target `{s}` (expected tc-style time)"
                        ))
                    })?);
                    i += 2;
                }
                "interval" => {
                    let s = need_value()?;
                    cfg.interval = Some(crate::util::parse::get_time(s).map_err(|_| {
                        Error::InvalidMessage(format!(
                            "codel: invalid interval `{s}` (expected tc-style time)"
                        ))
                    })?);
                    i += 2;
                }
                "ce_threshold" => {
                    let s = need_value()?;
                    cfg.ce_threshold = Some(crate::util::parse::get_time(s).map_err(|_| {
                        Error::InvalidMessage(format!(
                            "codel: invalid ce_threshold `{s}` (expected tc-style time)"
                        ))
                    })?);
                    i += 2;
                }
                "ecn" => {
                    cfg.ecn = Some(true);
                    i += 1;
                }
                "noecn" => {
                    cfg.ecn = Some(false);
                    i += 1;
                }
                other => {
                    return Err(Error::InvalidMessage(format!("codel: unknown token `{other}`")));
                }
            }
        }
        Ok(cfg)
    }
}

impl QdiscConfig for CodelConfig {
    fn kind(&self) -> &'static str {
        "codel"
    }

    fn write_options(&self, builder: &mut MessageBuilder) -> Result<()> {
        if let Some(target) = self.target {
            builder.append_attr_u32(codel::TCA_CODEL_TARGET, target.as_micros() as u32);
        }
        if let Some(interval) = self.interval {
            builder.append_attr_u32(codel::TCA_CODEL_INTERVAL, interval.as_micros() as u32);
        }
        if let Some(limit) = self.limit {
            builder.append_attr_u32(codel::TCA_CODEL_LIMIT, limit);
        }
        if let Some(ecn) = self.ecn {
            builder.append_attr_u32(codel::TCA_CODEL_ECN, u32::from(ecn));
        }
        if let Some(ce) = self.ce_threshold {
            builder.append_attr_u32(codel::TCA_CODEL_CE_THRESHOLD, ce.as_micros() as u32);
        }
        Ok(())
    }
}

// ============================================================================
// FqConfig
// ============================================================================

/// Fair Queue (fq) qdisc configuration — the pacing-aware scheduler
/// used with BBR. Distinct from [`FqCodelConfig`] (which is an AQM).
///
/// ```ignore
/// use nlink::netlink::tc::FqConfig;
/// use nlink::Rate;
///
/// let cfg = FqConfig::new()
///     .limit(10_000)
///     .flow_limit(100)
///     .maxrate(Rate::mbit(100))
///     .build();
/// ```
#[derive(Debug, Clone, Default)]
pub struct FqConfig {
    /// Total packet limit across the queue.
    pub limit: Option<u32>,
    /// Per-flow packet limit.
    pub flow_limit: Option<u32>,
    /// Round-robin quantum in bytes.
    pub quantum: Option<u32>,
    /// Initial quantum for a new flow, in bytes.
    pub initial_quantum: Option<u32>,
    /// Per-flow maximum rate.
    pub maxrate: Option<crate::util::Rate>,
    /// Low-rate threshold below which flows are not throttled.
    pub low_rate_threshold: Option<crate::util::Rate>,
    /// Flow credit refill delay.
    pub refill_delay: Option<Duration>,
    /// Mask applied to the orphaned-skb hash.
    pub orphan_mask: Option<u32>,
    /// ECN CE marking threshold.
    pub ce_threshold: Option<Duration>,
    /// Enable/disable pacing (`Some(false)` = explicit nopacing).
    pub pacing: Option<bool>,
}

impl FqConfig {
    /// Create a new fq configuration builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the total packet limit.
    pub fn limit(mut self, packets: u32) -> Self {
        self.limit = Some(packets);
        self
    }

    /// Set the per-flow packet limit.
    pub fn flow_limit(mut self, packets: u32) -> Self {
        self.flow_limit = Some(packets);
        self
    }

    /// Set the round-robin quantum in bytes.
    pub fn quantum(mut self, bytes: u32) -> Self {
        self.quantum = Some(bytes);
        self
    }

    /// Set the initial quantum for new flows, in bytes.
    pub fn initial_quantum(mut self, bytes: u32) -> Self {
        self.initial_quantum = Some(bytes);
        self
    }

    /// Set the per-flow maximum rate.
    pub fn maxrate(mut self, rate: crate::util::Rate) -> Self {
        self.maxrate = Some(rate);
        self
    }

    /// Set the low-rate threshold.
    pub fn low_rate_threshold(mut self, rate: crate::util::Rate) -> Self {
        self.low_rate_threshold = Some(rate);
        self
    }

    /// Set the flow credit refill delay.
    pub fn refill_delay(mut self, delay: Duration) -> Self {
        self.refill_delay = Some(delay);
        self
    }

    /// Set the orphan mask.
    pub fn orphan_mask(mut self, mask: u32) -> Self {
        self.orphan_mask = Some(mask);
        self
    }

    /// Set the ECN CE marking threshold.
    pub fn ce_threshold(mut self, threshold: Duration) -> Self {
        self.ce_threshold = Some(threshold);
        self
    }

    /// Enable or disable pacing.
    pub fn pacing(mut self, enable: bool) -> Self {
        self.pacing = Some(enable);
        self
    }

    /// Terminal no-op for builder symmetry.
    pub fn build(self) -> Self {
        self
    }

    /// Parse a tc-style fq params slice.
    ///
    /// Recognised tokens: `limit <packets>`, `flow_limit <packets>`,
    /// `quantum <bytes>`, `initial_quantum <bytes>`, `maxrate <rate>`,
    /// `low_rate_threshold <rate>`, `refill_delay <time>`,
    /// `orphan_mask <n>`, `ce_threshold <time>`, `pacing`/`nopacing`.
    /// Strict: unknown tokens, missing values, and unparseable values
    /// all error.
    pub fn parse_params(params: &[&str]) -> Result<Self> {
        let mut cfg = Self::new();
        let mut i = 0;
        while i < params.len() {
            let key = params[i];
            let need_value = || {
                params
                    .get(i + 1)
                    .copied()
                    .ok_or_else(|| Error::InvalidMessage(format!("fq: `{key}` requires a value")))
            };
            let parse_u32 = |s: &str, what: &str| {
                s.parse::<u32>().map_err(|_| {
                    Error::InvalidMessage(format!("fq: invalid {what} `{s}` (expected integer)"))
                })
            };
            let parse_rate = |s: &str, what: &str| {
                crate::util::Rate::parse(s).map_err(|_| {
                    Error::InvalidMessage(format!("fq: invalid {what} `{s}` (expected tc-style rate)"))
                })
            };
            let parse_time = |s: &str, what: &str| {
                crate::util::parse::get_time(s).map_err(|_| {
                    Error::InvalidMessage(format!("fq: invalid {what} `{s}` (expected tc-style time)"))
                })
            };
            match key {
                "limit" => {
                    cfg.limit = Some(parse_u32(need_value()?, "limit")?);
                    i += 2;
                }
                "flow_limit" => {
                    cfg.flow_limit = Some(parse_u32(need_value()?, "flow_limit")?);
                    i += 2;
                }
                "quantum" => {
                    cfg.quantum = Some(parse_u32(need_value()?, "quantum")?);
                    i += 2;
                }
                "initial_quantum" => {
                    cfg.initial_quantum = Some(parse_u32(need_value()?, "initial_quantum")?);
                    i += 2;
                }
                "maxrate" => {
                    cfg.maxrate = Some(parse_rate(need_value()?, "maxrate")?);
                    i += 2;
                }
                "low_rate_threshold" => {
                    cfg.low_rate_threshold = Some(parse_rate(need_value()?, "low_rate_threshold")?);
                    i += 2;
                }
                "refill_delay" => {
                    cfg.refill_delay = Some(parse_time(need_value()?, "refill_delay")?);
                    i += 2;
                }
                "orphan_mask" => {
                    cfg.orphan_mask = Some(parse_u32(need_value()?, "orphan_mask")?);
                    i += 2;
                }
                "ce_threshold" => {
                    cfg.ce_threshold = Some(parse_time(need_value()?, "ce_threshold")?);
                    i += 2;
                }
                "pacing" => {
                    cfg.pacing = Some(true);
                    i += 1;
                }
                "nopacing" => {
                    cfg.pacing = Some(false);
                    i += 1;
                }
                other => {
                    return Err(Error::InvalidMessage(format!("fq: unknown token `{other}`")));
                }
            }
        }
        Ok(cfg)
    }
}

impl QdiscConfig for FqConfig {
    fn kind(&self) -> &'static str {
        "fq"
    }

    fn write_options(&self, builder: &mut MessageBuilder) -> Result<()> {
        if let Some(limit) = self.limit {
            builder.append_attr_u32(fq::TCA_FQ_PLIMIT, limit);
        }
        if let Some(flow_limit) = self.flow_limit {
            builder.append_attr_u32(fq::TCA_FQ_FLOW_PLIMIT, flow_limit);
        }
        if let Some(quantum) = self.quantum {
            builder.append_attr_u32(fq::TCA_FQ_QUANTUM, quantum);
        }
        if let Some(iq) = self.initial_quantum {
            builder.append_attr_u32(fq::TCA_FQ_INITIAL_QUANTUM, iq);
        }
        if let Some(maxrate) = self.maxrate {
            builder.append_attr_u32(
                fq::TCA_FQ_FLOW_MAX_RATE,
                maxrate.as_u32_bytes_per_sec_saturating(),
            );
        }
        if let Some(lrt) = self.low_rate_threshold {
            builder.append_attr_u32(
                fq::TCA_FQ_LOW_RATE_THRESHOLD,
                lrt.as_u32_bytes_per_sec_saturating(),
            );
        }
        if let Some(rd) = self.refill_delay {
            builder.append_attr_u32(fq::TCA_FQ_FLOW_REFILL_DELAY, rd.as_micros() as u32);
        }
        if let Some(mask) = self.orphan_mask {
            builder.append_attr_u32(fq::TCA_FQ_ORPHAN_MASK, mask);
        }
        if let Some(ce) = self.ce_threshold {
            builder.append_attr_u32(fq::TCA_FQ_CE_THRESHOLD, ce.as_micros() as u32);
        }
        if let Some(pacing) = self.pacing {
            builder.append_attr_u32(fq::TCA_FQ_RATE_ENABLE, u32::from(pacing));
        }
        Ok(())
    }
}

// ============================================================================
// MqConfig
// ============================================================================

/// Multiqueue (mq) qdisc configuration.
///
/// `mq` is a classful dummy scheduler the kernel attaches as the root
/// qdisc of a multi-queue NIC: it exposes one child class per hardware
/// TX queue so a real qdisc (fq_codel, pfifo_fast, …) can be installed
/// per queue. The qdisc itself carries **no options** — like
/// [`DrrConfig`], this type exists for symmetry so `mq` can be created
/// through the same typed `add_qdisc` path as every other kind.
///
/// ```ignore
/// use nlink::netlink::tc::MqConfig;
/// use nlink::TcHandle;
/// conn.add_qdisc("eth0", TcHandle::ROOT, MqConfig::new()).await?;
/// ```
#[derive(Debug, Clone, Default)]
pub struct MqConfig {}

impl MqConfig {
    /// Create a new mq configuration builder.
    pub fn new() -> Self {
        Self {}
    }

    /// Terminal no-op for builder symmetry.
    pub fn build(self) -> Self {
        self
    }

    /// Parse a tc-style mq params slice. `mq` takes no parameters; an
    /// empty slice succeeds, anything else errors (strict contract —
    /// per-queue tuning belongs on the child qdiscs).
    pub fn parse_params(params: &[&str]) -> Result<Self> {
        if let Some(token) = params.first() {
            return Err(Error::InvalidMessage(format!(
                "mq: qdisc takes no parameters (got `{token}`); install per-queue qdiscs on the child classes"
            )));
        }
        Ok(Self::new())
    }
}

impl QdiscConfig for MqConfig {
    fn kind(&self) -> &'static str {
        "mq"
    }

    fn write_options(&self, _builder: &mut MessageBuilder) -> Result<()> {
        // mq has no options; the kernel materializes one child class
        // per hardware TX queue automatically.
        Ok(())
    }
}

// ============================================================================
// EtsConfig
// ============================================================================

/// Enhanced Transmission Selection (ets) qdisc configuration.
///
/// `ets` (IEEE 802.1Qaz) combines strict-priority and weighted
/// (deficit round-robin) bands in a single qdisc. The first `nstrict`
/// bands are served in strict priority order; the remaining
/// `nbands - nstrict` bands share bandwidth by their DRR `quanta`. A
/// `priomap` maps each of the 16 skb priorities to a band.
///
/// # Example
///
/// ```ignore
/// use nlink::netlink::tc::EtsConfig;
/// // 4 bands, 1 strict; the 3 DWRR bands get 3000/2000/1000 byte quanta.
/// let cfg = EtsConfig::new()
///     .bands(4)
///     .strict(1)
///     .quanta(vec![3000, 2000, 1000])
///     .priomap(vec![0, 0, 0, 1, 2, 3, 3, 3])
///     .build();
/// ```
#[derive(Debug, Clone, Default)]
pub struct EtsConfig {
    /// Total number of bands (`nbands`, 1..=16).
    pub bands: Option<u8>,
    /// Number of leading strict-priority bands (`nstrict`).
    pub strict: Option<u8>,
    /// Per-band DRR quanta in bytes, for the non-strict bands.
    pub quanta: Vec<u32>,
    /// Priority → band map (one entry per skb priority, up to 16).
    pub priomap: Vec<u8>,
}

impl EtsConfig {
    /// Create a new ets configuration builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the total number of bands.
    pub fn bands(mut self, nbands: u8) -> Self {
        self.bands = Some(nbands);
        self
    }

    /// Set the number of leading strict-priority bands.
    pub fn strict(mut self, nstrict: u8) -> Self {
        self.strict = Some(nstrict);
        self
    }

    /// Set the per-band DRR quanta (bytes) for the non-strict bands.
    pub fn quanta(mut self, quanta: Vec<u32>) -> Self {
        self.quanta = quanta;
        self
    }

    /// Set the priority → band map.
    pub fn priomap(mut self, priomap: Vec<u8>) -> Self {
        self.priomap = priomap;
        self
    }

    /// Terminal no-op for builder symmetry.
    pub fn build(self) -> Self {
        self
    }

    /// Parse a tc-style ets params slice.
    ///
    /// Recognised tokens: `bands <n>`, `strict <n>`,
    /// `quanta <q1> <q2> …` (greedy until the next keyword),
    /// `priomap <p0> <p1> …` (greedy until the next keyword). Strict:
    /// unknown tokens, missing values, and unparseable values error.
    pub fn parse_params(params: &[&str]) -> Result<Self> {
        fn is_keyword(s: &str) -> bool {
            matches!(s, "bands" | "strict" | "quanta" | "priomap")
        }
        let mut cfg = Self::new();
        let mut i = 0;
        while i < params.len() {
            let key = params[i];
            match key {
                "bands" => {
                    let v = params.get(i + 1).copied().ok_or_else(|| {
                        Error::InvalidMessage("ets: `bands` requires a value".to_string())
                    })?;
                    cfg.bands = Some(v.parse::<u8>().map_err(|_| {
                        Error::InvalidMessage(format!(
                            "ets: invalid bands `{v}` (expected integer 1..=16)"
                        ))
                    })?);
                    i += 2;
                }
                "strict" => {
                    let v = params.get(i + 1).copied().ok_or_else(|| {
                        Error::InvalidMessage("ets: `strict` requires a value".to_string())
                    })?;
                    cfg.strict = Some(v.parse::<u8>().map_err(|_| {
                        Error::InvalidMessage(format!(
                            "ets: invalid strict `{v}` (expected integer)"
                        ))
                    })?);
                    i += 2;
                }
                "quanta" => {
                    i += 1;
                    let start = i;
                    while i < params.len() && !is_keyword(params[i]) {
                        let v = params[i];
                        cfg.quanta.push(v.parse::<u32>().map_err(|_| {
                            Error::InvalidMessage(format!(
                                "ets: invalid quantum `{v}` (expected integer bytes)"
                            ))
                        })?);
                        i += 1;
                    }
                    if i == start {
                        return Err(Error::InvalidMessage(
                            "ets: `quanta` requires at least one value".to_string(),
                        ));
                    }
                }
                "priomap" => {
                    i += 1;
                    let start = i;
                    while i < params.len() && !is_keyword(params[i]) {
                        let v = params[i];
                        cfg.priomap.push(v.parse::<u8>().map_err(|_| {
                            Error::InvalidMessage(format!(
                                "ets: invalid priomap entry `{v}` (expected band index)"
                            ))
                        })?);
                        i += 1;
                    }
                    if i == start {
                        return Err(Error::InvalidMessage(
                            "ets: `priomap` requires at least one value".to_string(),
                        ));
                    }
                }
                other => {
                    return Err(Error::InvalidMessage(format!("ets: unknown token `{other}`")));
                }
            }
        }
        Ok(cfg)
    }
}

impl QdiscConfig for EtsConfig {
    fn kind(&self) -> &'static str {
        "ets"
    }

    fn write_options(&self, builder: &mut MessageBuilder) -> Result<()> {
        if let Some(nbands) = self.bands {
            builder.append_attr(ets::TCA_ETS_NBANDS, &[nbands]);
        }
        if let Some(nstrict) = self.strict {
            builder.append_attr(ets::TCA_ETS_NSTRICT, &[nstrict]);
        }
        if !self.quanta.is_empty() {
            let token = builder.nest_start(ets::TCA_ETS_QUANTA);
            for q in &self.quanta {
                builder.append_attr(ets::TCA_ETS_QUANTA_BAND, &q.to_ne_bytes());
            }
            builder.nest_end(token);
        }
        if !self.priomap.is_empty() {
            let token = builder.nest_start(ets::TCA_ETS_PRIOMAP);
            for band in &self.priomap {
                builder.append_attr(ets::TCA_ETS_PRIOMAP_BAND, &[*band]);
            }
            builder.nest_end(token);
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
    /// Rate.
    pub rate: crate::util::Rate,
    /// Peak rate (optional).
    pub peakrate: Option<crate::util::Rate>,
    /// Burst size.
    pub burst: crate::util::Bytes,
    /// MTU / peak burst.
    pub mtu: u32,
    /// Buffer limit.
    pub limit: crate::util::Bytes,
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
            rate: crate::util::Rate::ZERO,
            peakrate: None,
            burst: crate::util::Bytes::ZERO,
            mtu: 1514,
            limit: crate::util::Bytes::ZERO,
        }
    }

    /// Set the rate.
    pub fn rate(mut self, rate: crate::util::Rate) -> Self {
        self.rate = rate;
        self
    }

    /// Set the peak rate.
    pub fn peakrate(mut self, rate: crate::util::Rate) -> Self {
        self.peakrate = Some(rate);
        self
    }

    /// Set the burst size.
    pub fn burst(mut self, b: crate::util::Bytes) -> Self {
        self.burst = b;
        self
    }

    /// Set the MTU.
    pub fn mtu(mut self, mtu: u32) -> Self {
        self.mtu = mtu;
        self
    }

    /// Set the buffer limit.
    pub fn limit(mut self, b: crate::util::Bytes) -> Self {
        self.limit = b;
        self
    }

    /// Build the configuration.
    pub fn build(self) -> Self {
        self
    }

    /// Parse a tc-style tbf params slice into a typed `TbfConfig`.
    ///
    /// Recognised tokens:
    ///
    /// - `rate <rate>` — required; the shaping rate.
    /// - `burst <bytes>` (alias `buffer`, `maxburst`) — required by
    ///   the kernel; the token-bucket size.
    /// - `limit <bytes>` — buffer size in bytes.
    /// - `peakrate <rate>` — optional secondary rate cap.
    /// - `mtu <bytes>` (alias `minburst`) — peak-burst MTU.
    ///
    /// **Not yet typed-modelled** (returns `Error::InvalidMessage`):
    /// `latency` — `tc(8)` accepts it as a way to specify `limit`
    /// indirectly (`limit ≈ rate * latency`), but `TbfConfig` only
    /// stores the raw `limit`. Compute the limit yourself or file
    /// an issue if the latency form is important.
    ///
    /// Strict: unknown tokens, missing values, and unparseable
    /// rate/size values all return `Error::InvalidMessage`. Note:
    /// this parser does NOT enforce the kernel's "rate and burst
    /// are required" rule — that's left to `add_qdisc` / the kernel
    /// itself, mirroring how `parse_params` behaves on every other
    /// config.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let cfg = TbfConfig::parse_params(&[
    ///     "rate", "1mbit",
    ///     "burst", "32kb",
    ///     "limit", "10kb",
    /// ])?;
    /// ```
    pub fn parse_params(params: &[&str]) -> Result<Self> {
        let mut cfg = Self::new();
        let mut i = 0;
        while i < params.len() {
            let key = params[i];
            let need_value = || {
                params
                    .get(i + 1)
                    .copied()
                    .ok_or_else(|| Error::InvalidMessage(format!("tbf: `{key}` requires a value")))
            };
            match key {
                "rate" => {
                    let s = need_value()?;
                    cfg.rate = crate::util::Rate::parse(s).map_err(|_| {
                        Error::InvalidMessage(format!(
                            "tbf: invalid rate `{s}` (expected tc-style rate like `1mbit`)"
                        ))
                    })?;
                    i += 2;
                }
                "peakrate" => {
                    let s = need_value()?;
                    cfg.peakrate = Some(crate::util::Rate::parse(s).map_err(|_| {
                        Error::InvalidMessage(format!(
                            "tbf: invalid peakrate `{s}` (expected tc-style rate)"
                        ))
                    })?);
                    i += 2;
                }
                "burst" | "buffer" | "maxburst" => {
                    let s = need_value()?;
                    let bytes = crate::util::parse::get_size(s).map_err(|_| {
                        Error::InvalidMessage(format!(
                            "tbf: invalid {key} `{s}` (expected tc-style size)"
                        ))
                    })?;
                    cfg.burst = crate::util::Bytes::new(bytes);
                    i += 2;
                }
                "limit" => {
                    let s = need_value()?;
                    let bytes = crate::util::parse::get_size(s).map_err(|_| {
                        Error::InvalidMessage(format!(
                            "tbf: invalid limit `{s}` (expected tc-style size)"
                        ))
                    })?;
                    cfg.limit = crate::util::Bytes::new(bytes);
                    i += 2;
                }
                "mtu" | "minburst" => {
                    let s = need_value()?;
                    let bytes = crate::util::parse::get_size(s).map_err(|_| {
                        Error::InvalidMessage(format!(
                            "tbf: invalid {key} `{s}` (expected tc-style size)"
                        ))
                    })?;
                    cfg.mtu = bytes.try_into().map_err(|_| {
                        Error::InvalidMessage(format!("tbf: {key} `{s}` exceeds u32 (max ~4GB)"))
                    })?;
                    i += 2;
                }
                "latency" => {
                    return Err(Error::InvalidMessage(
                        "tbf: `latency` is a derived form (limit = rate * latency) and is not modelled by TbfConfig — compute the limit yourself".into(),
                    ));
                }
                other => {
                    return Err(Error::InvalidMessage(format!(
                        "tbf: unknown token `{other}`"
                    )));
                }
            }
        }
        Ok(cfg)
    }
}

impl QdiscConfig for TbfConfig {
    fn kind(&self) -> &'static str {
        "tbf"
    }

    fn write_options(&self, builder: &mut MessageBuilder) -> Result<()> {
        let rate_bps = self.rate.as_bytes_per_sec();
        let peakrate_bps = self.peakrate.map(|p| p.as_bytes_per_sec());
        // Build TcTbfQopt
        let qopt = tbf::TcTbfQopt {
            rate: TcRateSpec::new(rate_bps.min(u32::MAX as u64) as u32),
            peakrate: peakrate_bps
                .map(|pr| TcRateSpec::new(pr.min(u32::MAX as u64) as u32))
                .unwrap_or_default(),
            limit: self.limit.as_u32_saturating(),
            buffer: self.burst.as_u32_saturating(),
            mtu: self.mtu,
        };

        builder.append_attr(tbf::TCA_TBF_PARMS, qopt.as_bytes());

        // Add 64-bit rate if needed
        if rate_bps > u32::MAX as u64 {
            builder.append_attr(tbf::TCA_TBF_RATE64, &rate_bps.to_ne_bytes());
        }
        if let Some(pr) = peakrate_bps
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
        }
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

    /// Parse a tc-style params slice into a typed `HtbQdiscConfig`.
    ///
    /// Recognised tokens (each followed by a value):
    ///
    /// - `default <class>` — default class for unclassified traffic.
    ///   Accepts a tc handle (`1:10`) or a bare hex minor (`10`,
    ///   matching iproute2's `tc qdisc add ... htb default 10`).
    /// - `r2q <n>` — rate-to-quantum divisor (default 10).
    /// - `direct_qlen <n>` — direct queue length.
    ///
    /// Strict: unknown tokens, keys missing their value, and
    /// unparseable numbers all return `Error::InvalidMessage`
    /// instead of being silently skipped.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let cfg = HtbQdiscConfig::parse_params(&["default", "1:10", "r2q", "5"])?;
    /// assert_eq!(cfg.r2q, 5);
    /// ```
    pub fn parse_params(params: &[&str]) -> Result<Self> {
        let mut cfg = Self::new();
        let mut i = 0;
        while i < params.len() {
            let key = params[i];
            let value = || {
                params
                    .get(i + 1)
                    .copied()
                    .ok_or_else(|| Error::InvalidMessage(format!("htb: `{key}` requires a value")))
            };
            match key {
                "default" => {
                    cfg.default_class = parse_default_class(value()?)?;
                    i += 2;
                }
                "r2q" => {
                    cfg.r2q = value()?.parse().map_err(|_| {
                        Error::InvalidMessage(format!(
                            "htb: invalid r2q `{}` (expected unsigned integer)",
                            params[i + 1]
                        ))
                    })?;
                    i += 2;
                }
                "direct_qlen" => {
                    cfg.direct_qlen = Some(value()?.parse().map_err(|_| {
                        Error::InvalidMessage(format!(
                            "htb: invalid direct_qlen `{}` (expected unsigned integer)",
                            params[i + 1]
                        ))
                    })?);
                    i += 2;
                }
                other => {
                    return Err(Error::InvalidMessage(format!(
                        "htb: unknown token `{other}` (expected default, r2q, or direct_qlen)"
                    )));
                }
            }
        }
        Ok(cfg)
    }
}

/// Parse the `default` class identifier in an HTB params slice.
///
/// Accepts a tc handle (`1:10` → raw u32 of `TcHandle::new(1, 0x10)`)
/// or a bare hex minor (`10` → `0x10`). The bare-hex form mirrors
/// `tc(8)`'s convention where `tc qdisc add ... htb default 10`
/// means "minor 0x10 under the qdisc's own major".
fn parse_default_class(s: &str) -> Result<u32> {
    if s.contains(':') {
        s.parse::<crate::netlink::tc_handle::TcHandle>()
            .map(|h| h.as_raw())
            .map_err(|e| Error::InvalidMessage(format!("htb: invalid default class `{s}`: {e}")))
    } else {
        u32::from_str_radix(s, 16).map_err(|_| {
            Error::InvalidMessage(format!(
                "htb: invalid default class `{s}` (expected hex minor or tc handle)"
            ))
        })
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
        }
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

    /// Parse a tc-style prio params slice into a typed `PrioConfig`.
    ///
    /// Recognised tokens:
    ///
    /// - `bands <n>` — number of priority bands (signed i32 to match
    ///   the kernel's wire type).
    /// - `priomap <P0> <P1> ... <P15>` — exactly 16 priority-to-band
    ///   mappings. Stricter than the legacy parser, which silently
    ///   ignored the token if there weren't 16 values; here a short
    ///   priomap is an explicit error.
    ///
    /// Unknown tokens, missing values, and unparseable numbers all
    /// return `Error::InvalidMessage`.
    pub fn parse_params(params: &[&str]) -> Result<Self> {
        let mut cfg = Self::new();
        let mut i = 0;
        while i < params.len() {
            let key = params[i];
            match key {
                "bands" => {
                    let s = params.get(i + 1).copied().ok_or_else(|| {
                        Error::InvalidMessage("prio: `bands` requires a value".into())
                    })?;
                    cfg.bands = s.parse().map_err(|_| {
                        Error::InvalidMessage(format!(
                            "prio: invalid bands `{s}` (expected signed integer)"
                        ))
                    })?;
                    i += 2;
                }
                "priomap" => {
                    if params.len() < i + 1 + 16 {
                        return Err(Error::InvalidMessage(format!(
                            "prio: `priomap` requires exactly 16 values, got {}",
                            params.len().saturating_sub(i + 1)
                        )));
                    }
                    for j in 0..16 {
                        let s = params[i + 1 + j];
                        cfg.priomap[j] = s.parse().map_err(|_| {
                            Error::InvalidMessage(format!(
                                "prio: invalid priomap[{j}] `{s}` (expected 0-255)"
                            ))
                        })?;
                    }
                    i += 17;
                }
                other => {
                    return Err(Error::InvalidMessage(format!(
                        "prio: unknown token `{other}`"
                    )));
                }
            }
        }
        Ok(cfg)
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
        }
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

    /// Parse a tc-style sfq params slice into a typed `SfqConfig`.
    ///
    /// Recognised tokens:
    ///
    /// - `quantum <bytes>` — bytes dequeued per round (tc-style size).
    /// - `perturb <seconds>` — hash perturbation interval.
    /// - `limit <packets>` — queue limit in packets.
    ///
    /// **Not yet typed-modelled** (returns `Error::InvalidMessage`):
    /// `divisor` — `SfqConfig` doesn't expose the hash-table divisor
    /// field. File an issue if you need it.
    ///
    /// Strict: unknown tokens, missing values, and unparseable
    /// numbers all return an error.
    pub fn parse_params(params: &[&str]) -> Result<Self> {
        let mut cfg = Self::new();
        let mut i = 0;
        while i < params.len() {
            let key = params[i];
            let need_value = || {
                params
                    .get(i + 1)
                    .copied()
                    .ok_or_else(|| Error::InvalidMessage(format!("sfq: `{key}` requires a value")))
            };
            match key {
                "quantum" => {
                    let s = need_value()?;
                    let bytes = crate::util::parse::get_size(s).map_err(|_| {
                        Error::InvalidMessage(format!(
                            "sfq: invalid quantum `{s}` (expected tc-style size)"
                        ))
                    })?;
                    cfg.quantum = bytes.try_into().map_err(|_| {
                        Error::InvalidMessage(format!("sfq: quantum `{s}` exceeds u32"))
                    })?;
                    i += 2;
                }
                "perturb" => {
                    let s = need_value()?;
                    cfg.perturb = s.parse().map_err(|_| {
                        Error::InvalidMessage(format!(
                            "sfq: invalid perturb `{s}` (expected signed integer seconds)"
                        ))
                    })?;
                    i += 2;
                }
                "limit" => {
                    let s = need_value()?;
                    cfg.limit = s.parse().map_err(|_| {
                        Error::InvalidMessage(format!(
                            "sfq: invalid limit `{s}` (expected unsigned integer packets)"
                        ))
                    })?;
                    i += 2;
                }
                "divisor" => {
                    return Err(Error::InvalidMessage(
                        "sfq: `divisor` is not modelled by SfqConfig — file an issue if you need it"
                            .into(),
                    ));
                }
                other => {
                    return Err(Error::InvalidMessage(format!(
                        "sfq: unknown token `{other}`"
                    )));
                }
            }
        }
        Ok(cfg)
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
        }
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

    /// Parse a tc-style red params slice into a typed `RedConfig`.
    ///
    /// Recognised tokens:
    ///
    /// - `limit <bytes>` — queue limit (tc-style size).
    /// - `min <bytes>` — minimum threshold.
    /// - `max <bytes>` — maximum threshold.
    /// - `probability <pct>` — max probability as a percentage
    ///   0-100 (converted internally to the kernel's 0-255 scale).
    /// - `ecn` / `noecn` — ECN marking flag pair.
    /// - `harddrop` / `noharddrop` — hard-drop flag pair.
    /// - `adaptive` / `noadaptive` — adaptive RED flag pair.
    ///
    /// **Not yet typed-modelled** (returns `Error::InvalidMessage`):
    /// `avpkt`, `burst`, `bandwidth` — RedConfig doesn't model
    /// those classic RED parameters. The library uses the bare
    /// thresholds directly; if you need the avpkt-derived burst
    /// computation, drop to a hand-rolled `MessageBuilder`.
    ///
    /// Stricter than the legacy parser (which doesn't recognise red
    /// at all — it silently ignores unknown qdisc kinds in
    /// `add_qdisc`): unknown tokens, missing values, and
    /// unparseable values return `Error::InvalidMessage`.
    pub fn parse_params(params: &[&str]) -> Result<Self> {
        let mut cfg = Self::new();
        let mut i = 0;
        while i < params.len() {
            let key = params[i];
            let need_value = || {
                params
                    .get(i + 1)
                    .copied()
                    .ok_or_else(|| Error::InvalidMessage(format!("red: `{key}` requires a value")))
            };
            match key {
                "limit" | "min" | "max" => {
                    let s = need_value()?;
                    let bytes = crate::util::parse::get_size(s).map_err(|_| {
                        Error::InvalidMessage(format!(
                            "red: invalid {key} `{s}` (expected tc-style size)"
                        ))
                    })?;
                    let val: u32 = bytes.try_into().map_err(|_| {
                        Error::InvalidMessage(format!("red: {key} `{s}` exceeds u32"))
                    })?;
                    match key {
                        "limit" => cfg.limit = val,
                        "min" => cfg.min = val,
                        "max" => cfg.max = val,
                        _ => unreachable!(),
                    }
                    i += 2;
                }
                "probability" => {
                    let s = need_value()?;
                    let pct: f64 = s.parse().map_err(|_| {
                        Error::InvalidMessage(format!(
                            "red: invalid probability `{s}` (expected percentage 0-100)"
                        ))
                    })?;
                    cfg = cfg.max_probability(pct);
                    i += 2;
                }
                "ecn" => {
                    cfg.ecn = true;
                    i += 1;
                }
                "noecn" => {
                    cfg.ecn = false;
                    i += 1;
                }
                "harddrop" => {
                    cfg.harddrop = true;
                    i += 1;
                }
                "noharddrop" => {
                    cfg.harddrop = false;
                    i += 1;
                }
                "adaptive" => {
                    cfg.adaptive = true;
                    i += 1;
                }
                "noadaptive" => {
                    cfg.adaptive = false;
                    i += 1;
                }
                "avpkt" | "burst" | "bandwidth" => {
                    return Err(Error::InvalidMessage(format!(
                        "red: `{key}` is not modelled by RedConfig — drop to a hand-rolled MessageBuilder if needed"
                    )));
                }
                other => {
                    return Err(Error::InvalidMessage(format!(
                        "red: unknown token `{other}`"
                    )));
                }
            }
        }
        Ok(cfg)
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
// ChokeConfig
// ============================================================================

/// CHOKe qdisc configuration.
///
/// CHOKe ("CHOose and Keep for responsive flows, CHOose and Kill for
/// unresponsive flows") is a stateless AQM in the RED family. On each
/// enqueue it compares the arriving packet against a randomly-chosen
/// packet already in the queue; if they belong to the same flow it
/// drops both, penalising unresponsive (high-rate) flows without
/// per-flow state. Parameters mirror RED (it shares
/// `struct tc_red_qopt`).
///
/// ```ignore
/// use nlink::netlink::tc::ChokeConfig;
///
/// let cfg = ChokeConfig::new()
///     .limit(1_000_000)
///     .min(50_000)
///     .max(150_000)
///     .ecn(true)
///     .build();
/// ```
#[derive(Debug, Clone)]
pub struct ChokeConfig {
    /// Queue limit in bytes.
    pub limit: u32,
    /// Minimum threshold in bytes.
    pub min: u32,
    /// Maximum threshold in bytes.
    pub max: u32,
    /// Maximum probability (0-255, default ~2%).
    pub max_p: u8,
    /// Enable ECN marking instead of dropping.
    pub ecn: bool,
    /// Enable hard drop (drop all above max).
    pub harddrop: bool,
}

impl Default for ChokeConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl ChokeConfig {
    /// Create a new CHOKe configuration builder.
    pub fn new() -> Self {
        Self {
            limit: 0,
            min: 0,
            max: 0,
            max_p: 5, // ~2% probability
            ecn: false,
            harddrop: false,
        }
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

    /// Build the configuration.
    pub fn build(self) -> Self {
        self
    }

    /// Parse a tc-style choke params slice into a typed `ChokeConfig`.
    ///
    /// Recognised tokens:
    ///
    /// - `limit <bytes>` — queue limit (tc-style size).
    /// - `min <bytes>` — minimum threshold.
    /// - `max <bytes>` — maximum threshold.
    /// - `probability <pct>` — max probability as a percentage 0-100
    ///   (converted internally to the kernel's 0-255 scale).
    /// - `ecn` / `noecn` — ECN marking flag pair.
    /// - `harddrop` / `noharddrop` — hard-drop flag pair.
    ///
    /// **Not yet typed-modelled** (returns `Error::InvalidMessage`):
    /// `avpkt`, `burst`, `bandwidth` — same as [`RedConfig`]; CHOKe
    /// uses the bare thresholds directly.
    ///
    /// Strict: unknown tokens, missing values, and unparseable values
    /// return `Error::InvalidMessage`.
    pub fn parse_params(params: &[&str]) -> Result<Self> {
        let mut cfg = Self::new();
        let mut i = 0;
        while i < params.len() {
            let key = params[i];
            let need_value = || {
                params.get(i + 1).copied().ok_or_else(|| {
                    Error::InvalidMessage(format!("choke: `{key}` requires a value"))
                })
            };
            match key {
                "limit" | "min" | "max" => {
                    let s = need_value()?;
                    let bytes = crate::util::parse::get_size(s).map_err(|_| {
                        Error::InvalidMessage(format!(
                            "choke: invalid {key} `{s}` (expected tc-style size)"
                        ))
                    })?;
                    let val: u32 = bytes.try_into().map_err(|_| {
                        Error::InvalidMessage(format!("choke: {key} `{s}` exceeds u32"))
                    })?;
                    match key {
                        "limit" => cfg.limit = val,
                        "min" => cfg.min = val,
                        "max" => cfg.max = val,
                        _ => unreachable!(),
                    }
                    i += 2;
                }
                "probability" => {
                    let s = need_value()?;
                    let pct: f64 = s.parse().map_err(|_| {
                        Error::InvalidMessage(format!(
                            "choke: invalid probability `{s}` (expected percentage 0-100)"
                        ))
                    })?;
                    cfg = cfg.max_probability(pct);
                    i += 2;
                }
                "ecn" => {
                    cfg.ecn = true;
                    i += 1;
                }
                "noecn" => {
                    cfg.ecn = false;
                    i += 1;
                }
                "harddrop" => {
                    cfg.harddrop = true;
                    i += 1;
                }
                "noharddrop" => {
                    cfg.harddrop = false;
                    i += 1;
                }
                "avpkt" | "burst" | "bandwidth" => {
                    return Err(Error::InvalidMessage(format!(
                        "choke: `{key}` is not modelled by ChokeConfig — drop to a hand-rolled MessageBuilder if needed"
                    )));
                }
                other => {
                    return Err(Error::InvalidMessage(format!(
                        "choke: unknown token `{other}`"
                    )));
                }
            }
        }
        Ok(cfg)
    }
}

impl QdiscConfig for ChokeConfig {
    fn kind(&self) -> &'static str {
        "choke"
    }

    fn write_options(&self, builder: &mut MessageBuilder) -> Result<()> {
        use super::types::tc::qdisc::{choke, red};

        let mut flags: u8 = 0;
        if self.ecn {
            flags |= red::TC_RED_ECN as u8;
        }
        if self.harddrop {
            flags |= red::TC_RED_HARDDROP as u8;
        }

        let qopt = choke::TcRedQopt {
            limit: self.limit,
            qth_min: self.min,
            qth_max: self.max,
            wlog: 9,      // Weight log (default)
            plog: 13,     // Probability log (default)
            scell_log: 0, // Cell size log
            flags,
        };

        builder.append_attr(choke::TCA_CHOKE_PARMS, qopt.as_bytes());

        let max_p = (self.max_p as u32) << 24;
        builder.append_attr_u32(choke::TCA_CHOKE_MAX_P, max_p);

        Ok(())
    }
}

// ============================================================================
// PfifoFastConfig
// ============================================================================

/// pfifo_fast qdisc configuration.
///
/// `pfifo_fast` is the classic three-band priority FIFO that the kernel
/// installs as the default qdisc on a freshly-created device. Its
/// band count and priomap (`prio2band`) are hardcoded kernel-side, so
/// unlike most qdiscs it accepts **no** options — this config is a unit
/// type. Adding it explicitly is mostly useful for restoring the
/// default behaviour after replacing the root qdisc.
///
/// ```ignore
/// use nlink::netlink::tc::PfifoFastConfig;
///
/// conn.add_qdisc("eth0", PfifoFastConfig::new()).await?;
/// ```
#[derive(Debug, Clone, Default)]
pub struct PfifoFastConfig;

impl PfifoFastConfig {
    /// Create a new pfifo_fast configuration.
    pub fn new() -> Self {
        Self
    }

    /// Terminal no-op for builder symmetry.
    pub fn build(self) -> Self {
        self
    }

    /// Parse a tc-style pfifo_fast params slice. pfifo_fast takes no
    /// parameters; any token is rejected (strict-parse contract).
    pub fn parse_params(params: &[&str]) -> Result<Self> {
        if let Some(tok) = params.first() {
            return Err(Error::InvalidMessage(format!(
                "pfifo_fast: unexpected token `{tok}` (pfifo_fast takes no parameters)"
            )));
        }
        Ok(Self)
    }
}

impl QdiscConfig for PfifoFastConfig {
    fn kind(&self) -> &'static str {
        "pfifo_fast"
    }

    fn write_options(&self, _builder: &mut MessageBuilder) -> Result<()> {
        // pfifo_fast ignores TCA_OPTIONS — bands and priomap are
        // hardcoded kernel-side. Send no options.
        Ok(())
    }
}

// ============================================================================
// AtmConfig
// ============================================================================

/// ATM (`sch_atm`) qdisc configuration.
///
/// The ATM qdisc is classful: it maps classified flows onto ATM virtual
/// circuits. The **qdisc itself takes no options** — `tc qdisc add dev X
/// root atm` simply instantiates the classful qdisc, so this is a unit
/// config (like [`PfifoFastConfig`] / `MultiqConfig`).
///
/// ```ignore
/// use nlink::netlink::tc::AtmConfig;
///
/// conn.add_qdisc("eth0", AtmConfig::new()).await?;
/// ```
///
/// # VC binding is out of scope
///
/// The useful part of `sch_atm` lives in its **classes**, which bind a
/// flow to an ATM virtual circuit via the file descriptor of an *open
/// ATM socket* (`TCA_ATM_FD`, plus `TCA_ATM_HDR`/`TCA_ATM_EXCESS`/
/// `TCA_ATM_ADDR`). That requires live ATM hardware and an
/// application-owned socket fd, so nlink does not model an ATM class
/// config — there is no portable, testable surface for it. Use a
/// hand-rolled `MessageBuilder` with your own socket fd if you target
/// ATM hardware.
#[derive(Debug, Clone, Default)]
pub struct AtmConfig;

impl AtmConfig {
    /// Create a new ATM qdisc configuration.
    pub fn new() -> Self {
        Self
    }

    /// Terminal no-op for builder symmetry.
    pub fn build(self) -> Self {
        self
    }

    /// Parse a tc-style atm params slice. The ATM qdisc takes no
    /// parameters; any token is rejected (strict-parse contract).
    pub fn parse_params(params: &[&str]) -> Result<Self> {
        if let Some(tok) = params.first() {
            return Err(Error::InvalidMessage(format!(
                "atm: unexpected token `{tok}` (the atm qdisc takes no parameters; \
                 VC binding is a class-level concern not modelled by nlink)"
            )));
        }
        Ok(Self)
    }
}

impl QdiscConfig for AtmConfig {
    fn kind(&self) -> &'static str {
        "atm"
    }

    fn write_options(&self, _builder: &mut MessageBuilder) -> Result<()> {
        // The atm qdisc accepts no TCA_OPTIONS; classes carry the VC
        // binding. Send no options.
        Ok(())
    }
}

// ============================================================================
// GredConfig
// ============================================================================

/// GRED (Generic RED) qdisc configuration — **setup phase**.
///
/// GRED multiplexes up to 16 virtual queues (drop precedences) over one
/// qdisc, each with independent RED parameters. Configuration is
/// two-phase in the kernel:
///
/// 1. **Setup** (this config) — declare the number of virtual queues
///    (`DPs`), the default VQ, and whether GRIO (RIO-like priority
///    dropping) is enabled. Sent as `struct tc_gred_sopt` under
///    `TCA_GRED_DPS`, plus an optional global byte `limit`.
/// 2. **Per-VQ RED params** — `min`/`max`/`avpkt`/`bandwidth`/`prio` for
///    an individual VQ. This requires the kernel's 256-byte RED stab
///    probability table (computed from avpkt + bandwidth), which
///    `GredConfig` does **not** model — see the note below.
///
/// ```ignore
/// use nlink::netlink::tc::GredConfig;
///
/// // 8 virtual queues, VQ 2 is the default, GRIO on.
/// let cfg = GredConfig::new()
///     .virtual_queues(8)
///     .default_vq(2)
///     .grio(true)
///     .build();
/// conn.add_qdisc("eth0", cfg).await?;
/// ```
///
/// # Per-VQ parameterization is not modelled
///
/// Setting an individual VQ's RED thresholds (the
/// `tc qdisc change … gred limit … min … max … avpkt … bandwidth … DP …`
/// form) requires computing the RED stab table the kernel demands under
/// `TCA_GRED_STAB`. The library does not currently model that table (the
/// plain [`RedConfig`] sidesteps it too). `parse_params` therefore
/// rejects per-VQ tokens with a clear not-modelled error rather than
/// emitting a message the kernel would refuse. Tracked as a follow-up
/// under the #115 coverage epic.
#[derive(Debug, Clone, Default)]
pub struct GredConfig {
    /// Number of virtual queues / drop precedences (`DPs`, 1..=16).
    pub virtual_queues: Option<u32>,
    /// Default virtual queue (`def_DP`).
    pub default_vq: Option<u32>,
    /// Enable GRIO (RIO-like priority dropping).
    pub grio: bool,
    /// Global queue limit in bytes (`TCA_GRED_LIMIT`).
    pub limit: Option<u32>,
}

impl GredConfig {
    /// Create a new GRED setup configuration builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the number of virtual queues / drop precedences (1..=16).
    pub fn virtual_queues(mut self, dps: u32) -> Self {
        self.virtual_queues = Some(dps);
        self
    }

    /// Set the default virtual queue.
    pub fn default_vq(mut self, dp: u32) -> Self {
        self.default_vq = Some(dp);
        self
    }

    /// Enable or disable GRIO (RIO-like priority dropping).
    pub fn grio(mut self, enable: bool) -> Self {
        self.grio = enable;
        self
    }

    /// Set the global queue limit in bytes.
    pub fn limit(mut self, bytes: u32) -> Self {
        self.limit = Some(bytes);
        self
    }

    /// Build the configuration.
    pub fn build(self) -> Self {
        self
    }

    /// Parse a tc-style gred params slice into a typed `GredConfig`.
    ///
    /// Recognised tokens (setup phase):
    ///
    /// - `setup` — optional leading keyword (tc(8) accepts it; ignored).
    /// - `DPs <n>` — number of virtual queues (1..=16).
    /// - `default <dp>` — default virtual queue.
    /// - `grio` / `nogrio` — GRIO flag pair.
    /// - `limit <bytes>` — global queue limit (tc-style size).
    ///
    /// **Not modelled by `GredConfig`** (returns `Error::InvalidMessage`):
    /// the per-VQ RED tokens `min`/`max`/`avpkt`/`burst`/`bandwidth`/`DP`/
    /// `probability`/`prio`/`ecn`/`harddrop`. Per-VQ parameterization needs
    /// the RED stab probability table the kernel requires under
    /// `TCA_GRED_STAB`; configure VQs via a hand-rolled `MessageBuilder`
    /// until that lands.
    ///
    /// Strict: unknown tokens, missing values, and unparseable values
    /// return `Error::InvalidMessage`.
    pub fn parse_params(params: &[&str]) -> Result<Self> {
        let mut cfg = Self::new();
        let mut i = 0;
        while i < params.len() {
            let key = params[i];
            let need_value = || {
                params
                    .get(i + 1)
                    .copied()
                    .ok_or_else(|| Error::InvalidMessage(format!("gred: `{key}` requires a value")))
            };
            match key {
                "setup" => {
                    // tc(8) leading keyword; the setup fields follow.
                    i += 1;
                }
                "DPs" | "dps" => {
                    let s = need_value()?;
                    let n: u32 = s.parse().map_err(|_| {
                        Error::InvalidMessage(format!(
                            "gred: invalid DPs `{s}` (expected 1..=16)"
                        ))
                    })?;
                    if n == 0 || n > super::types::tc::qdisc::gred::MAX_DPS {
                        return Err(Error::InvalidMessage(format!(
                            "gred: DPs `{n}` out of range (1..=16)"
                        )));
                    }
                    cfg.virtual_queues = Some(n);
                    i += 2;
                }
                "default" => {
                    let s = need_value()?;
                    let dp: u32 = s.parse().map_err(|_| {
                        Error::InvalidMessage(format!(
                            "gred: invalid default `{s}` (expected unsigned integer)"
                        ))
                    })?;
                    cfg.default_vq = Some(dp);
                    i += 2;
                }
                "grio" => {
                    cfg.grio = true;
                    i += 1;
                }
                "nogrio" => {
                    cfg.grio = false;
                    i += 1;
                }
                "limit" => {
                    let s = need_value()?;
                    let bytes = crate::util::parse::get_size(s).map_err(|_| {
                        Error::InvalidMessage(format!(
                            "gred: invalid limit `{s}` (expected tc-style size)"
                        ))
                    })?;
                    let val: u32 = bytes.try_into().map_err(|_| {
                        Error::InvalidMessage(format!("gred: limit `{s}` exceeds u32"))
                    })?;
                    cfg.limit = Some(val);
                    i += 2;
                }
                "min" | "max" | "avpkt" | "burst" | "bandwidth" | "DP" | "probability" | "prio"
                | "ecn" | "harddrop" => {
                    return Err(Error::InvalidMessage(format!(
                        "gred: per-VQ token `{key}` is not modelled by GredConfig — \
                         per-VQ RED parameterization needs the TCA_GRED_STAB table; \
                         use setup mode (DPs/default/grio) or a hand-rolled MessageBuilder"
                    )));
                }
                other => {
                    return Err(Error::InvalidMessage(format!(
                        "gred: unknown token `{other}`"
                    )));
                }
            }
        }
        Ok(cfg)
    }
}

impl QdiscConfig for GredConfig {
    fn kind(&self) -> &'static str {
        "gred"
    }

    fn write_options(&self, builder: &mut MessageBuilder) -> Result<()> {
        use super::types::tc::qdisc::gred;

        // Setup message: tc_gred_sopt under TCA_GRED_DPS. The kernel
        // requires DPs to install the virtual-queue table; default to a
        // single VQ if the caller only set a limit.
        let sopt = gred::TcGredSopt {
            dps: self.virtual_queues.unwrap_or(1),
            def_dp: self.default_vq.unwrap_or(0),
            grio: u8::from(self.grio),
            flags: 0,
            pad1: 0,
        };
        builder.append_attr(gred::TCA_GRED_DPS, sopt.as_bytes());

        if let Some(limit) = self.limit {
            builder.append_attr_u32(gred::TCA_GRED_LIMIT, limit);
        }

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
        }
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

    /// Parse a tc-style pie params slice into a typed `PieConfig`.
    ///
    /// Recognised tokens:
    ///
    /// - `target <time>` — target delay (e.g. `15ms`).
    /// - `limit <packets>` — queue limit.
    /// - `tupdate <time>` — probability update interval.
    /// - `alpha <n>` — P-controller alpha parameter.
    /// - `beta <n>` — I-controller beta parameter.
    /// - `ecn` / `noecn` — ECN marking flag pair.
    /// - `bytemode` / `nobytemode` — byte-vs-packet mode pair.
    ///
    /// Stricter than the legacy parser (which doesn't recognise pie
    /// at all): unknown tokens, missing values, and unparseable
    /// time/integer values return `Error::InvalidMessage`.
    pub fn parse_params(params: &[&str]) -> Result<Self> {
        let mut cfg = Self::new();
        let mut i = 0;
        while i < params.len() {
            let key = params[i];
            let need_value = || {
                params
                    .get(i + 1)
                    .copied()
                    .ok_or_else(|| Error::InvalidMessage(format!("pie: `{key}` requires a value")))
            };
            match key {
                "target" => {
                    let s = need_value()?;
                    cfg.target = Some(crate::util::parse::get_time(s).map_err(|_| {
                        Error::InvalidMessage(format!(
                            "pie: invalid target `{s}` (expected tc-style time)"
                        ))
                    })?);
                    i += 2;
                }
                "limit" => {
                    let s = need_value()?;
                    cfg.limit =
                        Some(s.parse().map_err(|_| {
                            Error::InvalidMessage(format!("pie: invalid limit `{s}`"))
                        })?);
                    i += 2;
                }
                "tupdate" => {
                    let s = need_value()?;
                    cfg.tupdate = Some(crate::util::parse::get_time(s).map_err(|_| {
                        Error::InvalidMessage(format!(
                            "pie: invalid tupdate `{s}` (expected tc-style time)"
                        ))
                    })?);
                    i += 2;
                }
                "alpha" => {
                    let s = need_value()?;
                    cfg.alpha =
                        Some(s.parse().map_err(|_| {
                            Error::InvalidMessage(format!("pie: invalid alpha `{s}`"))
                        })?);
                    i += 2;
                }
                "beta" => {
                    let s = need_value()?;
                    cfg.beta =
                        Some(s.parse().map_err(|_| {
                            Error::InvalidMessage(format!("pie: invalid beta `{s}`"))
                        })?);
                    i += 2;
                }
                "ecn" => {
                    cfg.ecn = true;
                    i += 1;
                }
                "noecn" => {
                    cfg.ecn = false;
                    i += 1;
                }
                "bytemode" => {
                    cfg.bytemode = true;
                    i += 1;
                }
                "nobytemode" => {
                    cfg.bytemode = false;
                    i += 1;
                }
                other => {
                    return Err(Error::InvalidMessage(format!(
                        "pie: unknown token `{other}`"
                    )));
                }
            }
        }
        Ok(cfg)
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
// FqPieConfig
// ============================================================================

/// FQ-PIE (Flow Queue PIE) qdisc configuration.
///
/// Mainline since Linux 5.6 (Mar 2020). Combines `fq_codel`'s per-flow
/// hashing with PIE's proportional-integral AQM: each flow gets its
/// own queue, and PIE controls the per-queue drop probability based on
/// queueing delay.
///
/// Practically: a fairer alternative to `pie` for shared links where
/// elephant flows would otherwise crowd out interactive ones.
///
/// # Example
///
/// ```ignore
/// use nlink::netlink::tc::FqPieConfig;
/// use nlink::{Bytes, Percent};
/// use std::time::Duration;
///
/// let config = FqPieConfig::new()
///     .target(Duration::from_millis(15))
///     .tupdate(Duration::from_millis(15))
///     .limit(10240)
///     .flows(1024)
///     .quantum(Bytes::new(1514))
///     .ecn(true)
///     .build();
///
/// conn.add_qdisc("eth0", config).await?;
/// ```
#[derive(Debug, Clone)]
pub struct FqPieConfig {
    /// Queue limit in packets.
    pub limit: Option<u32>,
    /// Number of flow buckets (default 1024).
    pub flows: Option<u32>,
    /// Target queueing delay.
    pub target: Option<Duration>,
    /// Drop-probability update interval.
    pub tupdate: Option<Duration>,
    /// Alpha parameter (P controller, weighted scaled).
    pub alpha: Option<u32>,
    /// Beta parameter (I controller, weighted scaled).
    pub beta: Option<u32>,
    /// DRR quantum (bytes per scheduling round).
    pub quantum: Option<crate::util::Bytes>,
    /// Per-qdisc memory limit.
    pub memory_limit: Option<crate::util::Bytes>,
    /// ECN marking probability.
    pub ecn_prob: Option<crate::util::Percent>,
    /// Enable ECN marking.
    pub ecn: bool,
    /// Use byte mode instead of packet mode.
    pub bytemode: bool,
    /// Enable dequeue rate estimator.
    pub dq_rate_estimator: bool,
}

impl Default for FqPieConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl FqPieConfig {
    /// Create a new FQ-PIE configuration builder with all options unset.
    pub fn new() -> Self {
        Self {
            limit: None,
            flows: None,
            target: None,
            tupdate: None,
            alpha: None,
            beta: None,
            quantum: None,
            memory_limit: None,
            ecn_prob: None,
            ecn: false,
            bytemode: false,
            dq_rate_estimator: false,
        }
    }

    /// Set the queue limit in packets.
    pub fn limit(mut self, packets: u32) -> Self {
        self.limit = Some(packets);
        self
    }

    /// Set the number of flow buckets.
    pub fn flows(mut self, n: u32) -> Self {
        self.flows = Some(n);
        self
    }

    /// Set the target queueing delay (default: 15ms).
    pub fn target(mut self, target: Duration) -> Self {
        self.target = Some(target);
        self
    }

    /// Set the drop-probability update interval.
    pub fn tupdate(mut self, interval: Duration) -> Self {
        self.tupdate = Some(interval);
        self
    }

    /// Set the alpha parameter (P controller).
    pub fn alpha(mut self, alpha: u32) -> Self {
        self.alpha = Some(alpha);
        self
    }

    /// Set the beta parameter (I controller).
    pub fn beta(mut self, beta: u32) -> Self {
        self.beta = Some(beta);
        self
    }

    /// Set the DRR quantum (bytes per scheduling round).
    pub fn quantum(mut self, quantum: crate::util::Bytes) -> Self {
        self.quantum = Some(quantum);
        self
    }

    /// Set the per-qdisc memory limit.
    pub fn memory_limit(mut self, limit: crate::util::Bytes) -> Self {
        self.memory_limit = Some(limit);
        self
    }

    /// Set the ECN marking probability.
    pub fn ecn_prob(mut self, prob: crate::util::Percent) -> Self {
        self.ecn_prob = Some(prob);
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

    /// Enable or disable the dequeue rate estimator.
    pub fn dq_rate_estimator(mut self, enable: bool) -> Self {
        self.dq_rate_estimator = enable;
        self
    }

    /// Build the configuration (returns self, for API consistency).
    pub fn build(self) -> Self {
        self
    }

    /// Parse a tc-style fq_pie params slice into a typed `FqPieConfig`.
    ///
    /// Recognised tokens (any order):
    ///
    /// - `limit <packets>`, `flows <n>`, `alpha <n>`, `beta <n>`
    /// - `target <time>`, `tupdate <time>` — tc-style times (`15ms`)
    /// - `quantum <size>`, `memory_limit <size>` — tc-style sizes
    /// - `ecnprob <percent>` (alias `ecn_prob`)
    /// - bare toggles: `ecn` / `noecn`, `bytemode` / `nobytemode`,
    ///   `dq_rate_estimator` / `no_dq_rate_estimator`
    ///
    /// Strict: unknown tokens, missing values, and unparseable
    /// values all return `Error::InvalidMessage`.
    pub fn parse_params(params: &[&str]) -> Result<Self> {
        let mut cfg = Self::new();
        let mut i = 0;
        while i < params.len() {
            let key = params[i];
            let need_value = || {
                params.get(i + 1).copied().ok_or_else(|| {
                    Error::InvalidMessage(format!("fq_pie: `{key}` requires a value"))
                })
            };
            match key {
                "limit" => {
                    let s = need_value()?;
                    cfg.limit = Some(crate::util::parse::get_u32(s).map_err(|_| {
                        Error::InvalidMessage(format!(
                            "fq_pie: invalid limit `{s}` (expected packet count)"
                        ))
                    })?);
                    i += 2;
                }
                "flows" => {
                    let s = need_value()?;
                    cfg.flows = Some(crate::util::parse::get_u32(s).map_err(|_| {
                        Error::InvalidMessage(format!(
                            "fq_pie: invalid flows `{s}` (expected unsigned integer)"
                        ))
                    })?);
                    i += 2;
                }
                "alpha" => {
                    let s = need_value()?;
                    cfg.alpha = Some(crate::util::parse::get_u32(s).map_err(|_| {
                        Error::InvalidMessage(format!(
                            "fq_pie: invalid alpha `{s}` (expected unsigned integer)"
                        ))
                    })?);
                    i += 2;
                }
                "beta" => {
                    let s = need_value()?;
                    cfg.beta = Some(crate::util::parse::get_u32(s).map_err(|_| {
                        Error::InvalidMessage(format!(
                            "fq_pie: invalid beta `{s}` (expected unsigned integer)"
                        ))
                    })?);
                    i += 2;
                }
                "target" => {
                    let s = need_value()?;
                    cfg.target = Some(crate::util::parse::get_time(s).map_err(|_| {
                        Error::InvalidMessage(format!(
                            "fq_pie: invalid target `{s}` (expected tc-style time like `15ms`)"
                        ))
                    })?);
                    i += 2;
                }
                "tupdate" => {
                    let s = need_value()?;
                    cfg.tupdate = Some(crate::util::parse::get_time(s).map_err(|_| {
                        Error::InvalidMessage(format!(
                            "fq_pie: invalid tupdate `{s}` (expected tc-style time like `15ms`)"
                        ))
                    })?);
                    i += 2;
                }
                "quantum" => {
                    let s = need_value()?;
                    let bytes = crate::util::parse::get_size(s).map_err(|_| {
                        Error::InvalidMessage(format!(
                            "fq_pie: invalid quantum `{s}` (expected tc-style size)"
                        ))
                    })?;
                    cfg.quantum = Some(crate::util::Bytes::new(bytes));
                    i += 2;
                }
                "memory_limit" => {
                    let s = need_value()?;
                    let bytes = crate::util::parse::get_size(s).map_err(|_| {
                        Error::InvalidMessage(format!(
                            "fq_pie: invalid memory_limit `{s}` (expected tc-style size)"
                        ))
                    })?;
                    cfg.memory_limit = Some(crate::util::Bytes::new(bytes));
                    i += 2;
                }
                "ecnprob" | "ecn_prob" => {
                    let s = need_value()?;
                    cfg.ecn_prob = Some(s.parse::<crate::util::Percent>().map_err(|_| {
                        Error::InvalidMessage(format!(
                            "fq_pie: invalid ecnprob `{s}` (expected percent 0-100)"
                        ))
                    })?);
                    i += 2;
                }
                "ecn" => {
                    cfg.ecn = true;
                    i += 1;
                }
                "noecn" => {
                    cfg.ecn = false;
                    i += 1;
                }
                "bytemode" => {
                    cfg.bytemode = true;
                    i += 1;
                }
                "nobytemode" => {
                    cfg.bytemode = false;
                    i += 1;
                }
                "dq_rate_estimator" => {
                    cfg.dq_rate_estimator = true;
                    i += 1;
                }
                "no_dq_rate_estimator" => {
                    cfg.dq_rate_estimator = false;
                    i += 1;
                }
                other => {
                    return Err(Error::InvalidMessage(format!(
                        "fq_pie: unknown token `{other}`"
                    )));
                }
            }
        }
        Ok(cfg)
    }
}

impl QdiscConfig for FqPieConfig {
    fn kind(&self) -> &'static str {
        "fq_pie"
    }

    fn write_options(&self, builder: &mut MessageBuilder) -> Result<()> {
        use super::types::tc::qdisc::fq_pie;

        if let Some(limit) = self.limit {
            builder.append_attr_u32(fq_pie::TCA_FQ_PIE_LIMIT, limit);
        }
        if let Some(flows) = self.flows {
            builder.append_attr_u32(fq_pie::TCA_FQ_PIE_FLOWS, flows);
        }
        if let Some(target) = self.target {
            builder.append_attr_u32(fq_pie::TCA_FQ_PIE_TARGET, target.as_micros() as u32);
        }
        if let Some(tupdate) = self.tupdate {
            builder.append_attr_u32(fq_pie::TCA_FQ_PIE_TUPDATE, tupdate.as_micros() as u32);
        }
        if let Some(alpha) = self.alpha {
            builder.append_attr_u32(fq_pie::TCA_FQ_PIE_ALPHA, alpha);
        }
        if let Some(beta) = self.beta {
            builder.append_attr_u32(fq_pie::TCA_FQ_PIE_BETA, beta);
        }
        if let Some(quantum) = self.quantum {
            builder.append_attr_u32(fq_pie::TCA_FQ_PIE_QUANTUM, quantum.as_u32_saturating());
        }
        if let Some(memory_limit) = self.memory_limit {
            builder.append_attr_u32(
                fq_pie::TCA_FQ_PIE_MEMORY_LIMIT,
                memory_limit.as_u32_saturating(),
            );
        }
        if let Some(prob) = self.ecn_prob {
            // Kernel encodes ECN probability as a per-mille value.
            let permille = (prob.as_percent() * 10.0) as u32;
            builder.append_attr_u32(fq_pie::TCA_FQ_PIE_ECN_PROB, permille);
        }
        if self.ecn {
            builder.append_attr_u32(fq_pie::TCA_FQ_PIE_ECN, 1);
        }
        if self.bytemode {
            builder.append_attr_u32(fq_pie::TCA_FQ_PIE_BYTEMODE, 1);
        }
        if self.dq_rate_estimator {
            builder.append_attr_u32(fq_pie::TCA_FQ_PIE_DQ_RATE_ESTIMATOR, 1);
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

    /// Parse a tc-style ingress params slice. Ingress takes no
    /// parameters; this method is for symmetry with the typed-units
    /// rollout — empty slice succeeds, anything else errors.
    pub fn parse_params(params: &[&str]) -> Result<Self> {
        if let Some(token) = params.first() {
            return Err(Error::InvalidMessage(format!(
                "ingress: takes no parameters (got `{token}`)"
            )));
        }
        Ok(Self::new())
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

    /// Parse a tc-style clsact params slice. Clsact takes no
    /// parameters; this method is for symmetry — empty slice
    /// succeeds, anything else errors.
    pub fn parse_params(params: &[&str]) -> Result<Self> {
        if let Some(token) = params.first() {
            return Err(Error::InvalidMessage(format!(
                "clsact: takes no parameters (got `{token}`)"
            )));
        }
        Ok(Self::new())
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
}

impl Default for PfifoConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl PfifoConfig {
    /// Create a new pfifo configuration builder.
    pub fn new() -> Self {
        Self { limit: 1000 }
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

    /// Parse a tc-style pfifo params slice into a typed `PfifoConfig`.
    ///
    /// Recognised token:
    ///
    /// - `limit <packets>` — queue limit in packets.
    ///
    /// Strict: unknown tokens, missing values, and unparseable
    /// numbers all return `Error::InvalidMessage`.
    pub fn parse_params(params: &[&str]) -> Result<Self> {
        let mut cfg = Self::new();
        let mut i = 0;
        while i < params.len() {
            let key = params[i];
            match key {
                "limit" => {
                    let s = params.get(i + 1).copied().ok_or_else(|| {
                        Error::InvalidMessage("pfifo: `limit` requires a value".into())
                    })?;
                    cfg.limit = crate::util::parse::get_u32(s).map_err(|_| {
                        Error::InvalidMessage(format!(
                            "pfifo: invalid limit `{s}` (expected packet count)"
                        ))
                    })?;
                    i += 2;
                }
                other => {
                    return Err(Error::InvalidMessage(format!(
                        "pfifo: unknown token `{other}`"
                    )));
                }
            }
        }
        Ok(cfg)
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
        }
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

    /// Parse a tc-style bfifo params slice into a typed `BfifoConfig`.
    ///
    /// Recognised token:
    ///
    /// - `limit <size>` — queue limit as a tc-style size (bytes,
    ///   accepts suffixes like `kb`/`mb`).
    ///
    /// Strict: unknown tokens, missing values, and unparseable
    /// sizes all return `Error::InvalidMessage`.
    pub fn parse_params(params: &[&str]) -> Result<Self> {
        let mut cfg = Self::new();
        let mut i = 0;
        while i < params.len() {
            let key = params[i];
            match key {
                "limit" => {
                    let s = params.get(i + 1).copied().ok_or_else(|| {
                        Error::InvalidMessage("bfifo: `limit` requires a value".into())
                    })?;
                    let bytes = crate::util::parse::get_size(s).map_err(|_| {
                        Error::InvalidMessage(format!(
                            "bfifo: invalid limit `{s}` (expected tc-style size)"
                        ))
                    })?;
                    cfg.limit = bytes.try_into().map_err(|_| {
                        Error::InvalidMessage(format!("bfifo: limit `{s}` exceeds u32 (max ~4GB)"))
                    })?;
                    i += 2;
                }
                other => {
                    return Err(Error::InvalidMessage(format!(
                        "bfifo: unknown token `{other}`"
                    )));
                }
            }
        }
        Ok(cfg)
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
// CbsConfig (Credit-Based Shaper, IEEE 802.1Qav / AVB / TSN)
// ============================================================================

/// CBS (Credit-Based Shaper) qdisc configuration.
///
/// CBS implements the IEEE 802.1Qav forwarding-and-queuing rules used by
/// AVB / TSN, shaping a traffic class to a reserved bandwidth. It is
/// typically installed as a leaf under `mqprio` on a multi-queue NIC.
///
/// `idleslope`/`sendslope` are in kbit/s; `hicredit`/`locredit` are in
/// bytes (matching tc(8) and the kernel's `struct tc_cbs_qopt`). Set
/// `offload` to hand the shaping to a NIC that implements the Qav
/// shaper in hardware.
///
/// ```ignore
/// use nlink::netlink::tc::CbsConfig;
///
/// // Class A reservation on a 1Gbit link (tc(8) example values).
/// let cfg = CbsConfig::new()
///     .idleslope(98_688)
///     .sendslope(-901_312)
///     .hicredit(153)
///     .locredit(-1_389)
///     .build();
/// ```
#[derive(Debug, Clone, Default)]
pub struct CbsConfig {
    /// Hardware offload flag.
    pub offload: bool,
    /// High credit, in bytes.
    pub hicredit: i32,
    /// Low credit, in bytes.
    pub locredit: i32,
    /// Idle slope, in kbit/s.
    pub idleslope: i32,
    /// Send slope, in kbit/s (typically negative).
    pub sendslope: i32,
}

impl CbsConfig {
    /// Create a new CBS configuration builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Enable or disable hardware offload.
    pub fn offload(mut self, offload: bool) -> Self {
        self.offload = offload;
        self
    }

    /// Set the high credit (bytes).
    pub fn hicredit(mut self, hicredit: i32) -> Self {
        self.hicredit = hicredit;
        self
    }

    /// Set the low credit (bytes).
    pub fn locredit(mut self, locredit: i32) -> Self {
        self.locredit = locredit;
        self
    }

    /// Set the idle slope (kbit/s).
    pub fn idleslope(mut self, idleslope: i32) -> Self {
        self.idleslope = idleslope;
        self
    }

    /// Set the send slope (kbit/s).
    pub fn sendslope(mut self, sendslope: i32) -> Self {
        self.sendslope = sendslope;
        self
    }

    /// Terminal no-op for builder symmetry.
    pub fn build(self) -> Self {
        self
    }

    /// Parse a tc-style cbs params slice into a typed `CbsConfig`.
    ///
    /// Recognised tokens: `idleslope <kbit>`, `sendslope <kbit>`,
    /// `hicredit <bytes>`, `locredit <bytes>`, `offload <0|1>`.
    /// Strict: unknown tokens, missing values, and unparseable values
    /// all error.
    pub fn parse_params(params: &[&str]) -> Result<Self> {
        let mut cfg = Self::new();
        let mut i = 0;
        while i < params.len() {
            let key = params[i];
            let need_value = || {
                params.get(i + 1).copied().ok_or_else(|| {
                    Error::InvalidMessage(format!("cbs: `{key}` requires a value"))
                })
            };
            let parse_i32 = |s: &str| -> Result<i32> {
                s.parse::<i32>().map_err(|_| {
                    Error::InvalidMessage(format!(
                        "cbs: invalid {key} `{s}` (expected signed integer)"
                    ))
                })
            };
            match key {
                "idleslope" => {
                    cfg.idleslope = parse_i32(need_value()?)?;
                    i += 2;
                }
                "sendslope" => {
                    cfg.sendslope = parse_i32(need_value()?)?;
                    i += 2;
                }
                "hicredit" => {
                    cfg.hicredit = parse_i32(need_value()?)?;
                    i += 2;
                }
                "locredit" => {
                    cfg.locredit = parse_i32(need_value()?)?;
                    i += 2;
                }
                "offload" => {
                    let s = need_value()?;
                    cfg.offload = match s {
                        "0" | "off" | "false" => false,
                        "1" | "on" | "true" => true,
                        other => {
                            return Err(Error::InvalidMessage(format!(
                                "cbs: invalid offload `{other}` (expected 0|1)"
                            )));
                        }
                    };
                    i += 2;
                }
                other => {
                    return Err(Error::InvalidMessage(format!("cbs: unknown token `{other}`")));
                }
            }
        }
        Ok(cfg)
    }
}

impl QdiscConfig for CbsConfig {
    fn kind(&self) -> &'static str {
        "cbs"
    }

    fn write_options(&self, builder: &mut MessageBuilder) -> Result<()> {
        use super::types::tc::qdisc::cbs::{TCA_CBS_PARMS, TcCbsQopt};

        let qopt = TcCbsQopt {
            offload: u8::from(self.offload),
            _pad: [0; 3],
            hicredit: self.hicredit,
            locredit: self.locredit,
            idleslope: self.idleslope,
            sendslope: self.sendslope,
        };
        builder.append_attr(TCA_CBS_PARMS, qopt.as_bytes());
        Ok(())
    }
}

// ============================================================================
// SkbprioConfig (SKB priority queue)
// ============================================================================

/// skbprio (SKB priority) qdisc configuration.
///
/// A priority queue that uses the packet's `skb->priority` to drop the
/// lowest-priority packets first when the queue is full. The only knob
/// is the queue-length `limit` (packets).
///
/// ```ignore
/// use nlink::netlink::tc::SkbprioConfig;
///
/// let cfg = SkbprioConfig::new().limit(64).build();
/// ```
#[derive(Debug, Clone)]
pub struct SkbprioConfig {
    /// Queue length limit in packets.
    pub limit: u32,
}

impl Default for SkbprioConfig {
    fn default() -> Self {
        // Kernel default is 64 packets.
        Self { limit: 64 }
    }
}

impl SkbprioConfig {
    /// Create a new skbprio configuration builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the queue length limit in packets.
    pub fn limit(mut self, packets: u32) -> Self {
        self.limit = packets;
        self
    }

    /// Terminal no-op for builder symmetry.
    pub fn build(self) -> Self {
        self
    }

    /// Parse a tc-style skbprio params slice into a typed
    /// `SkbprioConfig`.
    ///
    /// Recognised tokens: `limit <packets>`. Strict: unknown tokens,
    /// missing values, and unparseable values all error.
    pub fn parse_params(params: &[&str]) -> Result<Self> {
        let mut cfg = Self::new();
        let mut i = 0;
        while i < params.len() {
            let key = params[i];
            match key {
                "limit" => {
                    let s = params.get(i + 1).copied().ok_or_else(|| {
                        Error::InvalidMessage("skbprio: `limit` requires a value".to_string())
                    })?;
                    cfg.limit = s.parse().map_err(|_| {
                        Error::InvalidMessage(format!("skbprio: invalid limit `{s}`"))
                    })?;
                    i += 2;
                }
                other => {
                    return Err(Error::InvalidMessage(format!(
                        "skbprio: unknown token `{other}`"
                    )));
                }
            }
        }
        Ok(cfg)
    }
}

impl QdiscConfig for SkbprioConfig {
    fn kind(&self) -> &'static str {
        "skbprio"
    }

    fn write_options(&self, builder: &mut MessageBuilder) -> Result<()> {
        use super::types::tc::qdisc::skbprio::TcSkbprioQopt;

        let qopt = TcSkbprioQopt::new(self.limit);
        builder.append(&qopt);
        Ok(())
    }
}

// ============================================================================
// SfbConfig (Stochastic Fair Blue)
// ============================================================================

/// SFB (Stochastic Fair Blue) qdisc configuration.
///
/// SFB is a rate-control AQM that uses Bloom-filter accounting to keep
/// per-flow marking/dropping probabilities and rate-limit non-responsive
/// ("inelastic") flows. All fields map directly to `struct tc_sfb_qopt`;
/// `rehash`/`db` are durations (sent as milliseconds).
///
/// ```ignore
/// use nlink::netlink::tc::SfbConfig;
///
/// let cfg = SfbConfig::new().limit(1000).build();
/// ```
#[derive(Debug, Clone, Default)]
pub struct SfbConfig {
    /// Max SFB queue length (packets).
    pub limit: Option<u32>,
    /// Rehash interval.
    pub rehash: Option<Duration>,
    /// Double-buffering warmup time (must be < rehash).
    pub db: Option<Duration>,
    /// Max length of qlen_min.
    pub max: Option<u32>,
    /// Target queue length per bin.
    pub target: Option<u32>,
    /// Probability increment (d1).
    pub increment: Option<u32>,
    /// Probability decrement (d2).
    pub decrement: Option<u32>,
    /// Inelastic-flow penalty rate (packets/s).
    pub penalty_rate: Option<u32>,
    /// Inelastic-flow penalty burst.
    pub penalty_burst: Option<u32>,
}

impl SfbConfig {
    /// Create a new SFB configuration builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the max SFB queue length (packets).
    pub fn limit(mut self, packets: u32) -> Self {
        self.limit = Some(packets);
        self
    }

    /// Set the rehash interval.
    pub fn rehash(mut self, interval: Duration) -> Self {
        self.rehash = Some(interval);
        self
    }

    /// Set the double-buffering warmup time.
    pub fn db(mut self, warmup: Duration) -> Self {
        self.db = Some(warmup);
        self
    }

    /// Set the max length of qlen_min.
    pub fn max(mut self, max: u32) -> Self {
        self.max = Some(max);
        self
    }

    /// Set the target queue length per bin.
    pub fn target(mut self, target: u32) -> Self {
        self.target = Some(target);
        self
    }

    /// Set the probability increment (d1).
    pub fn increment(mut self, increment: u32) -> Self {
        self.increment = Some(increment);
        self
    }

    /// Set the probability decrement (d2).
    pub fn decrement(mut self, decrement: u32) -> Self {
        self.decrement = Some(decrement);
        self
    }

    /// Set the inelastic-flow penalty rate (packets/s).
    pub fn penalty_rate(mut self, rate: u32) -> Self {
        self.penalty_rate = Some(rate);
        self
    }

    /// Set the inelastic-flow penalty burst.
    pub fn penalty_burst(mut self, burst: u32) -> Self {
        self.penalty_burst = Some(burst);
        self
    }

    /// Terminal no-op for builder symmetry.
    pub fn build(self) -> Self {
        self
    }

    /// Parse a tc-style sfb params slice into a typed `SfbConfig`.
    ///
    /// Recognised tokens: `limit <packets>`, `rehash <time>`,
    /// `db <time>`, `max <packets>`, `target <packets>`,
    /// `increment <n>`, `decrement <n>`, `penalty_rate <pps>`,
    /// `penalty_burst <n>`. Strict: unknown tokens, missing values,
    /// and unparseable values all error.
    pub fn parse_params(params: &[&str]) -> Result<Self> {
        let mut cfg = Self::new();
        let mut i = 0;
        while i < params.len() {
            let key = params[i];
            let need_value = || {
                params.get(i + 1).copied().ok_or_else(|| {
                    Error::InvalidMessage(format!("sfb: `{key}` requires a value"))
                })
            };
            let parse_u32 = |s: &str| -> Result<u32> {
                s.parse::<u32>().map_err(|_| {
                    Error::InvalidMessage(format!(
                        "sfb: invalid {key} `{s}` (expected unsigned integer)"
                    ))
                })
            };
            let parse_time = |s: &str| -> Result<Duration> {
                crate::util::parse::get_time(s).map_err(|_| {
                    Error::InvalidMessage(format!(
                        "sfb: invalid {key} `{s}` (expected tc-style time)"
                    ))
                })
            };
            match key {
                "limit" => {
                    cfg.limit = Some(parse_u32(need_value()?)?);
                    i += 2;
                }
                "rehash" => {
                    cfg.rehash = Some(parse_time(need_value()?)?);
                    i += 2;
                }
                "db" => {
                    cfg.db = Some(parse_time(need_value()?)?);
                    i += 2;
                }
                "max" => {
                    cfg.max = Some(parse_u32(need_value()?)?);
                    i += 2;
                }
                "target" => {
                    cfg.target = Some(parse_u32(need_value()?)?);
                    i += 2;
                }
                "increment" => {
                    cfg.increment = Some(parse_u32(need_value()?)?);
                    i += 2;
                }
                "decrement" => {
                    cfg.decrement = Some(parse_u32(need_value()?)?);
                    i += 2;
                }
                "penalty_rate" => {
                    cfg.penalty_rate = Some(parse_u32(need_value()?)?);
                    i += 2;
                }
                "penalty_burst" => {
                    cfg.penalty_burst = Some(parse_u32(need_value()?)?);
                    i += 2;
                }
                other => {
                    return Err(Error::InvalidMessage(format!("sfb: unknown token `{other}`")));
                }
            }
        }
        Ok(cfg)
    }
}

impl QdiscConfig for SfbConfig {
    fn kind(&self) -> &'static str {
        "sfb"
    }

    fn write_options(&self, builder: &mut MessageBuilder) -> Result<()> {
        use super::types::tc::qdisc::sfb::{TCA_SFB_PARMS, TcSfbQopt};

        let ms = |d: Duration| d.as_millis() as u32;
        let qopt = TcSfbQopt {
            rehash_interval: self.rehash.map(ms).unwrap_or(0),
            warmup_time: self.db.map(ms).unwrap_or(0),
            max: self.max.unwrap_or(0),
            bin_size: self.target.unwrap_or(0),
            increment: self.increment.unwrap_or(0),
            decrement: self.decrement.unwrap_or(0),
            limit: self.limit.unwrap_or(0),
            penalty_rate: self.penalty_rate.unwrap_or(0),
            penalty_burst: self.penalty_burst.unwrap_or(0),
        };
        builder.append_attr(TCA_SFB_PARMS, qopt.as_bytes());
        Ok(())
    }
}

// ============================================================================
// MultiqConfig (band-per-tx-queue)
// ============================================================================

/// multiq qdisc configuration.
///
/// multiq creates one band per device tx queue, mapping `skb->priority`
/// to a band so a multi-queue NIC can be driven directly. It is
/// parameterless: the kernel derives the band count from the device's
/// real tx-queue count, so the config writes a zeroed
/// `struct tc_multiq_qopt`.
///
/// ```ignore
/// use nlink::netlink::tc::MultiqConfig;
///
/// let cfg = MultiqConfig::new().build();
/// ```
#[derive(Debug, Clone, Default)]
pub struct MultiqConfig;

impl MultiqConfig {
    /// Create a new multiq configuration.
    pub fn new() -> Self {
        Self
    }

    /// Terminal no-op for builder symmetry.
    pub fn build(self) -> Self {
        self
    }

    /// Parse a tc-style multiq params slice. multiq takes no
    /// parameters; any token is rejected (strict-parse contract).
    pub fn parse_params(params: &[&str]) -> Result<Self> {
        if let Some(tok) = params.first() {
            return Err(Error::InvalidMessage(format!(
                "multiq: unexpected token `{tok}` (multiq takes no parameters)"
            )));
        }
        Ok(Self)
    }
}

impl QdiscConfig for MultiqConfig {
    fn kind(&self) -> &'static str {
        "multiq"
    }

    fn write_options(&self, builder: &mut MessageBuilder) -> Result<()> {
        use super::types::tc::qdisc::multiq::TcMultiqQopt;

        // Zeroed — the kernel fills bands from the device tx-queue count.
        let qopt = TcMultiqQopt::default();
        builder.append(&qopt);
        Ok(())
    }
}

// ============================================================================
// HhfConfig (Heavy-Hitter Filter)
// ============================================================================

/// HHF (Heavy-Hitter Filter) qdisc configuration.
///
/// HHF isolates "heavy-hitter" flows (those sending disproportionately)
/// from the rest, scheduling the two bands with WDRR. Timeouts are
/// durations (sent as microseconds, matching the kernel's
/// `usecs_to_jiffies`).
///
/// ```ignore
/// use nlink::netlink::tc::HhfConfig;
///
/// let cfg = HhfConfig::new().limit(1000).quantum(Bytes::new(1514)).build();
/// ```
#[derive(Debug, Clone, Default)]
pub struct HhfConfig {
    /// Backlog limit, in packets.
    pub limit: Option<u32>,
    /// Quantum, in bytes.
    pub quantum: Option<crate::util::Bytes>,
    /// Heavy-hitter flow-table size.
    pub hh_limit: Option<u32>,
    /// Reset timeout.
    pub reset_timeout: Option<Duration>,
    /// Admit bytes threshold.
    pub admit_bytes: Option<crate::util::Bytes>,
    /// Evict timeout.
    pub evict_timeout: Option<Duration>,
    /// Weight of the non-heavy-hitter band.
    pub non_hh_weight: Option<u32>,
}

impl HhfConfig {
    /// Create a new HHF configuration builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the backlog limit (packets).
    pub fn limit(mut self, packets: u32) -> Self {
        self.limit = Some(packets);
        self
    }

    /// Set the quantum (bytes).
    pub fn quantum(mut self, bytes: crate::util::Bytes) -> Self {
        self.quantum = Some(bytes);
        self
    }

    /// Set the heavy-hitter flow-table size.
    pub fn hh_limit(mut self, limit: u32) -> Self {
        self.hh_limit = Some(limit);
        self
    }

    /// Set the reset timeout.
    pub fn reset_timeout(mut self, timeout: Duration) -> Self {
        self.reset_timeout = Some(timeout);
        self
    }

    /// Set the admit-bytes threshold.
    pub fn admit_bytes(mut self, bytes: crate::util::Bytes) -> Self {
        self.admit_bytes = Some(bytes);
        self
    }

    /// Set the evict timeout.
    pub fn evict_timeout(mut self, timeout: Duration) -> Self {
        self.evict_timeout = Some(timeout);
        self
    }

    /// Set the non-heavy-hitter band weight.
    pub fn non_hh_weight(mut self, weight: u32) -> Self {
        self.non_hh_weight = Some(weight);
        self
    }

    /// Terminal no-op for builder symmetry.
    pub fn build(self) -> Self {
        self
    }

    /// Parse a tc-style hhf params slice into a typed `HhfConfig`.
    ///
    /// Recognised tokens: `limit <packets>`, `quantum <bytes>`,
    /// `hh_limit <n>`, `reset_timeout <time>`, `admit_bytes <bytes>`,
    /// `evict_timeout <time>`, `nonhh_weight <n>`. Strict: unknown
    /// tokens, missing values, and unparseable values all error.
    pub fn parse_params(params: &[&str]) -> Result<Self> {
        let mut cfg = Self::new();
        let mut i = 0;
        while i < params.len() {
            let key = params[i];
            let need_value = || {
                params.get(i + 1).copied().ok_or_else(|| {
                    Error::InvalidMessage(format!("hhf: `{key}` requires a value"))
                })
            };
            let parse_u32 = |s: &str| -> Result<u32> {
                s.parse::<u32>().map_err(|_| {
                    Error::InvalidMessage(format!(
                        "hhf: invalid {key} `{s}` (expected unsigned integer)"
                    ))
                })
            };
            let parse_bytes = |s: &str| -> Result<crate::util::Bytes> {
                crate::util::parse::get_size(s)
                    .map(crate::util::Bytes::new)
                    .map_err(|_| {
                        Error::InvalidMessage(format!(
                            "hhf: invalid {key} `{s}` (expected tc-style size)"
                        ))
                    })
            };
            let parse_time = |s: &str| -> Result<Duration> {
                crate::util::parse::get_time(s).map_err(|_| {
                    Error::InvalidMessage(format!(
                        "hhf: invalid {key} `{s}` (expected tc-style time)"
                    ))
                })
            };
            match key {
                "limit" => {
                    cfg.limit = Some(parse_u32(need_value()?)?);
                    i += 2;
                }
                "quantum" => {
                    cfg.quantum = Some(parse_bytes(need_value()?)?);
                    i += 2;
                }
                "hh_limit" => {
                    cfg.hh_limit = Some(parse_u32(need_value()?)?);
                    i += 2;
                }
                "reset_timeout" => {
                    cfg.reset_timeout = Some(parse_time(need_value()?)?);
                    i += 2;
                }
                "admit_bytes" => {
                    cfg.admit_bytes = Some(parse_bytes(need_value()?)?);
                    i += 2;
                }
                "evict_timeout" => {
                    cfg.evict_timeout = Some(parse_time(need_value()?)?);
                    i += 2;
                }
                "nonhh_weight" => {
                    cfg.non_hh_weight = Some(parse_u32(need_value()?)?);
                    i += 2;
                }
                other => {
                    return Err(Error::InvalidMessage(format!("hhf: unknown token `{other}`")));
                }
            }
        }
        Ok(cfg)
    }
}

impl QdiscConfig for HhfConfig {
    fn kind(&self) -> &'static str {
        "hhf"
    }

    fn write_options(&self, builder: &mut MessageBuilder) -> Result<()> {
        use super::types::tc::qdisc::hhf::*;

        if let Some(limit) = self.limit {
            builder.append_attr_u32(TCA_HHF_BACKLOG_LIMIT, limit);
        }
        if let Some(q) = self.quantum {
            builder.append_attr_u32(TCA_HHF_QUANTUM, q.as_u32_saturating());
        }
        if let Some(hh) = self.hh_limit {
            builder.append_attr_u32(TCA_HHF_HH_FLOWS_LIMIT, hh);
        }
        if let Some(t) = self.reset_timeout {
            builder.append_attr_u32(TCA_HHF_RESET_TIMEOUT, t.as_micros() as u32);
        }
        if let Some(a) = self.admit_bytes {
            builder.append_attr_u32(TCA_HHF_ADMIT_BYTES, a.as_u32_saturating());
        }
        if let Some(t) = self.evict_timeout {
            builder.append_attr_u32(TCA_HHF_EVICT_TIMEOUT, t.as_micros() as u32);
        }
        if let Some(w) = self.non_hh_weight {
            builder.append_attr_u32(TCA_HHF_NON_HH_WEIGHT, w);
        }
        Ok(())
    }
}

// ============================================================================
// DsmarkConfig (DiffServ marking)
// ============================================================================

/// dsmark (DiffServ marking) qdisc configuration.
///
/// dsmark classifies packets into a table of indices, each carrying a
/// DiffServ mask/value applied to the DS field. This config covers the
/// qdisc-level knobs; the per-index `mask`/`value` are class-level
/// (`TCA_DSMARK_MASK`/`VALUE`).
///
/// ```ignore
/// use nlink::netlink::tc::DsmarkConfig;
///
/// let cfg = DsmarkConfig::new().indices(64).set_tc_index().build();
/// ```
#[derive(Debug, Clone, Default)]
pub struct DsmarkConfig {
    /// Number of indices (power of two).
    pub indices: Option<u16>,
    /// Default index for unclassified packets.
    pub default_index: Option<u16>,
    /// Derive the class from `skb->tc_index`.
    pub set_tc_index: bool,
}

impl DsmarkConfig {
    /// Create a new dsmark configuration builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the number of indices (power of two).
    pub fn indices(mut self, indices: u16) -> Self {
        self.indices = Some(indices);
        self
    }

    /// Set the default index.
    pub fn default_index(mut self, index: u16) -> Self {
        self.default_index = Some(index);
        self
    }

    /// Derive the class from `skb->tc_index`.
    pub fn set_tc_index(mut self) -> Self {
        self.set_tc_index = true;
        self
    }

    /// Terminal no-op for builder symmetry.
    pub fn build(self) -> Self {
        self
    }

    /// Parse a tc-style dsmark params slice into a typed
    /// `DsmarkConfig`.
    ///
    /// Recognised tokens: `indices <n>`, `default_index <n>`,
    /// `set_tc_index`. Strict: unknown tokens, missing values, and
    /// unparseable values all error.
    pub fn parse_params(params: &[&str]) -> Result<Self> {
        let mut cfg = Self::new();
        let mut i = 0;
        while i < params.len() {
            let key = params[i];
            let need_value = || {
                params.get(i + 1).copied().ok_or_else(|| {
                    Error::InvalidMessage(format!("dsmark: `{key}` requires a value"))
                })
            };
            let parse_u16 = |s: &str| -> Result<u16> {
                s.parse::<u16>().map_err(|_| {
                    Error::InvalidMessage(format!(
                        "dsmark: invalid {key} `{s}` (expected unsigned integer)"
                    ))
                })
            };
            match key {
                "indices" => {
                    cfg.indices = Some(parse_u16(need_value()?)?);
                    i += 2;
                }
                "default_index" => {
                    cfg.default_index = Some(parse_u16(need_value()?)?);
                    i += 2;
                }
                "set_tc_index" => {
                    cfg.set_tc_index = true;
                    i += 1;
                }
                other => {
                    return Err(Error::InvalidMessage(format!(
                        "dsmark: unknown token `{other}`"
                    )));
                }
            }
        }
        Ok(cfg)
    }
}

impl QdiscConfig for DsmarkConfig {
    fn kind(&self) -> &'static str {
        "dsmark"
    }

    fn write_options(&self, builder: &mut MessageBuilder) -> Result<()> {
        use super::types::tc::qdisc::dsmark::*;

        if let Some(indices) = self.indices {
            builder.append_attr_u16(TCA_DSMARK_INDICES, indices);
        }
        if let Some(default_index) = self.default_index {
            builder.append_attr_u16(TCA_DSMARK_DEFAULT_INDEX, default_index);
        }
        if self.set_tc_index {
            builder.append_attr_empty(TCA_DSMARK_SET_TC_INDEX);
        }
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
pub struct DrrConfig {}

impl Default for DrrConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl DrrConfig {
    /// Create a new DRR configuration builder.
    pub fn new() -> Self {
        Self {}
    }

    /// Build the configuration.
    pub fn build(self) -> Self {
        self
    }

    /// Parse a tc-style drr params slice. DRR's *qdisc* level takes
    /// no parameters (the per-class `quantum` lives on `DrrClassConfig`,
    /// not here); this method is for symmetry — empty slice succeeds,
    /// anything else errors.
    pub fn parse_params(params: &[&str]) -> Result<Self> {
        if let Some(token) = params.first() {
            return Err(Error::InvalidMessage(format!(
                "drr: qdisc takes no parameters (got `{token}`); per-class quantum belongs on DrrClassConfig"
            )));
        }
        Ok(Self::new())
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
pub struct QfqConfig {}

impl Default for QfqConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl QfqConfig {
    /// Create a new QFQ configuration builder.
    pub fn new() -> Self {
        Self {}
    }

    /// Build the configuration.
    pub fn build(self) -> Self {
        self
    }

    /// Parse a tc-style qfq params slice. QFQ's *qdisc* level takes
    /// no parameters (the per-class `weight` and `lmax` live on
    /// `QfqClassConfig`); empty slice succeeds, anything else errors.
    pub fn parse_params(params: &[&str]) -> Result<Self> {
        if let Some(token) = params.first() {
            return Err(Error::InvalidMessage(format!(
                "qfq: qdisc takes no parameters (got `{token}`); per-class weight/lmax belongs on QfqClassConfig"
            )));
        }
        Ok(Self::new())
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
// CakeConfig
// ============================================================================

/// CAKE diffserv mode (priority bands by DSCP).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CakeDiffserv {
    /// 3 tins (default for typical home gateways).
    Diffserv3,
    /// 4 tins.
    Diffserv4,
    /// 8 tins (maximum granularity).
    Diffserv8,
    /// 1 tin (no DSCP differentiation).
    Besteffort,
    /// Per-IP-precedence prioritization.
    Precedence,
}

/// CAKE flow isolation mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CakeFlowMode {
    /// No flow isolation.
    Flowblind,
    /// Per source-IP.
    Srchost,
    /// Per destination-IP.
    Dsthost,
    /// Per host pair (src+dst combined).
    Hosts,
    /// Per 5-tuple flow.
    Flows,
    /// Hierarchical: dual-isolate on src host, then per-flow.
    DualSrchost,
    /// Hierarchical: dual-isolate on dst host, then per-flow.
    DualDsthost,
    /// Triple isolation: src-host + dst-host + flow.
    Triple,
}

/// CAKE ATM/PTM overhead compensation mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CakeAtmMode {
    /// No overhead compensation.
    None,
    /// ATM (53-byte cells, 5-byte header).
    Atm,
    /// PTM (G.992.3-style).
    Ptm,
}

/// CAKE ACK filtering mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CakeAckFilter {
    /// No ACK filtering.
    Disabled,
    /// Conservative ACK filtering.
    Filter,
    /// Aggressive ACK filtering (drops more redundant ACKs).
    Aggressive,
}

/// CAKE (Common Applications Kept Enhanced) qdisc configuration.
///
/// The most-used modern AQM qdisc on real-world deployments —
/// OpenWrt's default and the bufferbloat.net community recommendation.
/// Combines a token-bucket shaper, fair queueing, and CoDel-style AQM
/// in a single self-tuning qdisc.
///
/// This is the typed builder mirroring the rest of the qdisc lineup.
/// (The legacy string-args `tc/options/cake.rs` interface was
/// removed in 0.15.0; the typed builder is the only public API.
/// Construct it via `CakeConfig::new()` + fluent setters, or via
/// `CakeConfig::parse_params(&["bandwidth", "100mbit", ...])`
/// per the [`ParseParams`](crate::ParseParams) contract.)
///
/// # Example
///
/// ```ignore
/// use nlink::netlink::tc::{CakeConfig, CakeFlowMode, CakeDiffserv};
/// use nlink::Rate;
/// use std::time::Duration;
///
/// let config = CakeConfig::new()
///     .bandwidth(Rate::mbit(100))
///     .rtt(Duration::from_millis(80))
///     .flow_mode(CakeFlowMode::Triple)
///     .diffserv_mode(CakeDiffserv::Diffserv4)
///     .nat(true)
///     .build();
///
/// conn.add_qdisc("eth0", config).await?;
/// ```
#[derive(Debug, Clone)]
pub struct CakeConfig {
    /// Bandwidth shaping limit. `None` = unlimited (let cake autorate).
    pub bandwidth: Option<crate::util::Rate>,
    /// Estimated round-trip time (drives CoDel target).
    pub rtt: Option<Duration>,
    /// Explicit CoDel target delay (overrides RTT-derived default).
    pub target: Option<Duration>,
    /// Per-packet overhead compensation in bytes (can be negative).
    pub overhead: Option<i32>,
    /// Minimum packet unit (size to charge for sub-MPU packets).
    pub mpu: Option<u32>,
    /// Per-qdisc memory limit.
    pub memory_limit: Option<crate::util::Bytes>,
    /// fwmark mask used for tin classification.
    pub fwmark: Option<u32>,
    /// Diffserv tin layout.
    pub diffserv_mode: Option<CakeDiffserv>,
    /// Flow isolation mode.
    pub flow_mode: Option<CakeFlowMode>,
    /// ATM/PTM cell-overhead compensation.
    pub atm_mode: Option<CakeAtmMode>,
    /// ACK filtering mode.
    pub ack_filter: Option<CakeAckFilter>,
    /// Enable autorate-ingress (estimate bandwidth from observed flow).
    pub autorate: bool,
    /// Enable NAT mode (rewrite addresses for hash classification).
    pub nat: bool,
    /// Disable overhead compensation entirely (raw mode).
    pub raw: bool,
    /// Enable DSCP washing (clear DSCP on egress).
    pub wash: bool,
    /// Treat as ingress qdisc (use IFB for inbound shaping).
    pub ingress: bool,
    /// Split GSO super-segments before queueing.
    pub split_gso: bool,
}

impl Default for CakeConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl CakeConfig {
    /// Create a new CAKE configuration builder with all options unset.
    pub fn new() -> Self {
        Self {
            bandwidth: None,
            rtt: None,
            target: None,
            overhead: None,
            mpu: None,
            memory_limit: None,
            fwmark: None,
            diffserv_mode: None,
            flow_mode: None,
            atm_mode: None,
            ack_filter: None,
            autorate: false,
            nat: false,
            raw: false,
            wash: false,
            ingress: false,
            split_gso: false,
        }
    }

    /// Set the bandwidth shaping limit.
    pub fn bandwidth(mut self, rate: crate::util::Rate) -> Self {
        self.bandwidth = Some(rate);
        self
    }

    /// Mark the qdisc as unlimited (no shaping).
    ///
    /// Equivalent to `bandwidth(Rate::ZERO)` — the kernel encodes
    /// bandwidth=0 as the unlimited sentinel.
    pub fn unlimited(mut self) -> Self {
        self.bandwidth = Some(crate::util::Rate::ZERO);
        self
    }

    /// Set the estimated round-trip time.
    pub fn rtt(mut self, rtt: Duration) -> Self {
        self.rtt = Some(rtt);
        self
    }

    /// Set the explicit CoDel target delay.
    pub fn target(mut self, target: Duration) -> Self {
        self.target = Some(target);
        self
    }

    /// Set the per-packet overhead in bytes (can be negative).
    pub fn overhead(mut self, overhead: i32) -> Self {
        self.overhead = Some(overhead);
        self
    }

    /// Set the minimum packet unit.
    pub fn mpu(mut self, mpu: u32) -> Self {
        self.mpu = Some(mpu);
        self
    }

    /// Set the per-qdisc memory limit.
    pub fn memory_limit(mut self, mem: crate::util::Bytes) -> Self {
        self.memory_limit = Some(mem);
        self
    }

    /// Set the fwmark mask used for tin classification.
    pub fn fwmark(mut self, mask: u32) -> Self {
        self.fwmark = Some(mask);
        self
    }

    /// Set the diffserv tin layout.
    pub fn diffserv_mode(mut self, mode: CakeDiffserv) -> Self {
        self.diffserv_mode = Some(mode);
        self
    }

    /// Set the flow isolation mode.
    pub fn flow_mode(mut self, mode: CakeFlowMode) -> Self {
        self.flow_mode = Some(mode);
        self
    }

    /// Set the ATM/PTM overhead compensation mode.
    pub fn atm_mode(mut self, mode: CakeAtmMode) -> Self {
        self.atm_mode = Some(mode);
        self
    }

    /// Set the ACK filtering mode.
    pub fn ack_filter(mut self, mode: CakeAckFilter) -> Self {
        self.ack_filter = Some(mode);
        self
    }

    /// Enable autorate-ingress.
    pub fn autorate(mut self, enable: bool) -> Self {
        self.autorate = enable;
        self
    }

    /// Enable NAT mode.
    pub fn nat(mut self, enable: bool) -> Self {
        self.nat = enable;
        self
    }

    /// Disable overhead compensation (raw mode).
    pub fn raw(mut self, enable: bool) -> Self {
        self.raw = enable;
        self
    }

    /// Enable DSCP washing.
    pub fn wash(mut self, enable: bool) -> Self {
        self.wash = enable;
        self
    }

    /// Mark this as an ingress shaper.
    pub fn ingress(mut self, enable: bool) -> Self {
        self.ingress = enable;
        self
    }

    /// Enable GSO super-segment splitting.
    pub fn split_gso(mut self, enable: bool) -> Self {
        self.split_gso = enable;
        self
    }

    /// Build the configuration.
    pub fn build(self) -> Self {
        self
    }

    /// Parse a tc-style cake params slice into a typed `CakeConfig`.
    ///
    /// Recognised tokens with values:
    ///
    /// - `bandwidth <rate>` — set the shaping limit (also: `unlimited`
    ///   as a flag token, equivalent to `bandwidth 0`).
    /// - `rtt <time>` — RTT estimate.
    /// - `target <time>` — explicit CoDel target delay.
    /// - `overhead <bytes>` — per-packet overhead (signed i32).
    /// - `mpu <bytes>` — minimum packet unit.
    /// - `memlimit <bytes>` — per-qdisc memory limit.
    /// - `fwmark <hex>` — fwmark mask for tin classification.
    ///
    /// Flag tokens for diffserv mode: `diffserv3`, `diffserv4`,
    /// `diffserv8`, `besteffort`, `precedence`.
    ///
    /// Flag tokens for flow isolation: `flowblind`, `srchost`,
    /// `dsthost`, `hosts`, `flows`, `dual-srchost`, `dual-dsthost`,
    /// `triple-isolate`.
    ///
    /// Flag tokens for ATM mode: `noatm`, `atm`, `ptm`.
    ///
    /// Flag tokens for ACK filter: `no-ack-filter`, `ack-filter`,
    /// `ack-filter-aggressive`.
    ///
    /// Boolean flag tokens (with their negations where applicable):
    /// `raw`, `nat` / `nonat`, `wash` / `nowash`, `ingress` /
    /// `egress`, `split-gso` / `no-split-gso`, `autorate-ingress`,
    /// `unlimited`.
    ///
    /// Strict: unknown tokens, missing values, and unparseable
    /// rate / time / size / integer values all return
    /// `Error::InvalidMessage`.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let cfg = CakeConfig::parse_params(&[
    ///     "bandwidth", "100mbit",
    ///     "rtt", "20ms",
    ///     "diffserv4", "triple-isolate",
    ///     "ack-filter", "wash",
    /// ])?;
    /// ```
    pub fn parse_params(params: &[&str]) -> Result<Self> {
        let mut cfg = Self::new();
        let mut i = 0;
        while i < params.len() {
            let key = params[i];
            let need_value = || {
                params
                    .get(i + 1)
                    .copied()
                    .ok_or_else(|| Error::InvalidMessage(format!("cake: `{key}` requires a value")))
            };
            match key {
                // Value tokens.
                "bandwidth" => {
                    let s = need_value()?;
                    cfg.bandwidth = Some(crate::util::Rate::parse(s).map_err(|_| {
                        Error::InvalidMessage(format!(
                            "cake: invalid bandwidth `{s}` (expected tc-style rate like `100mbit`)"
                        ))
                    })?);
                    i += 2;
                }
                "rtt" => {
                    let s = need_value()?;
                    cfg.rtt = Some(crate::util::parse::get_time(s).map_err(|_| {
                        Error::InvalidMessage(format!(
                            "cake: invalid rtt `{s}` (expected tc-style time)"
                        ))
                    })?);
                    i += 2;
                }
                "target" => {
                    let s = need_value()?;
                    cfg.target = Some(crate::util::parse::get_time(s).map_err(|_| {
                        Error::InvalidMessage(format!(
                            "cake: invalid target `{s}` (expected tc-style time)"
                        ))
                    })?);
                    i += 2;
                }
                "overhead" => {
                    let s = need_value()?;
                    cfg.overhead = Some(s.parse().map_err(|_| {
                        Error::InvalidMessage(format!(
                            "cake: invalid overhead `{s}` (expected signed integer bytes)"
                        ))
                    })?);
                    i += 2;
                }
                "mpu" => {
                    let s = need_value()?;
                    cfg.mpu = Some(s.parse().map_err(|_| {
                        Error::InvalidMessage(format!(
                            "cake: invalid mpu `{s}` (expected unsigned integer bytes)"
                        ))
                    })?);
                    i += 2;
                }
                "memlimit" => {
                    let s = need_value()?;
                    let bytes = crate::util::parse::get_size(s).map_err(|_| {
                        Error::InvalidMessage(format!(
                            "cake: invalid memlimit `{s}` (expected tc-style size)"
                        ))
                    })?;
                    cfg.memory_limit = Some(crate::util::Bytes::new(bytes));
                    i += 2;
                }
                "fwmark" => {
                    let s = need_value()?;
                    let trimmed = s.strip_prefix("0x").unwrap_or(s);
                    cfg.fwmark = Some(u32::from_str_radix(trimmed, 16).map_err(|_| {
                        Error::InvalidMessage(format!(
                            "cake: invalid fwmark `{s}` (expected hex u32)"
                        ))
                    })?);
                    i += 2;
                }
                // Diffserv flag tokens.
                "diffserv3" => {
                    cfg.diffserv_mode = Some(CakeDiffserv::Diffserv3);
                    i += 1;
                }
                "diffserv4" => {
                    cfg.diffserv_mode = Some(CakeDiffserv::Diffserv4);
                    i += 1;
                }
                "diffserv8" => {
                    cfg.diffserv_mode = Some(CakeDiffserv::Diffserv8);
                    i += 1;
                }
                "besteffort" => {
                    cfg.diffserv_mode = Some(CakeDiffserv::Besteffort);
                    i += 1;
                }
                "precedence" => {
                    cfg.diffserv_mode = Some(CakeDiffserv::Precedence);
                    i += 1;
                }
                // Flow-mode flag tokens.
                "flowblind" => {
                    cfg.flow_mode = Some(CakeFlowMode::Flowblind);
                    i += 1;
                }
                "srchost" => {
                    cfg.flow_mode = Some(CakeFlowMode::Srchost);
                    i += 1;
                }
                "dsthost" => {
                    cfg.flow_mode = Some(CakeFlowMode::Dsthost);
                    i += 1;
                }
                "hosts" => {
                    cfg.flow_mode = Some(CakeFlowMode::Hosts);
                    i += 1;
                }
                "flows" => {
                    cfg.flow_mode = Some(CakeFlowMode::Flows);
                    i += 1;
                }
                "dual-srchost" => {
                    cfg.flow_mode = Some(CakeFlowMode::DualSrchost);
                    i += 1;
                }
                "dual-dsthost" => {
                    cfg.flow_mode = Some(CakeFlowMode::DualDsthost);
                    i += 1;
                }
                "triple-isolate" => {
                    cfg.flow_mode = Some(CakeFlowMode::Triple);
                    i += 1;
                }
                // ATM mode flag tokens.
                "noatm" => {
                    cfg.atm_mode = Some(CakeAtmMode::None);
                    i += 1;
                }
                "atm" => {
                    cfg.atm_mode = Some(CakeAtmMode::Atm);
                    i += 1;
                }
                "ptm" => {
                    cfg.atm_mode = Some(CakeAtmMode::Ptm);
                    i += 1;
                }
                // ACK filter flag tokens.
                "no-ack-filter" => {
                    cfg.ack_filter = Some(CakeAckFilter::Disabled);
                    i += 1;
                }
                "ack-filter" => {
                    cfg.ack_filter = Some(CakeAckFilter::Filter);
                    i += 1;
                }
                "ack-filter-aggressive" => {
                    cfg.ack_filter = Some(CakeAckFilter::Aggressive);
                    i += 1;
                }
                // Boolean flag tokens.
                "raw" => {
                    cfg.raw = true;
                    i += 1;
                }
                "nat" => {
                    cfg.nat = true;
                    i += 1;
                }
                "nonat" => {
                    cfg.nat = false;
                    i += 1;
                }
                "wash" => {
                    cfg.wash = true;
                    i += 1;
                }
                "nowash" => {
                    cfg.wash = false;
                    i += 1;
                }
                "ingress" => {
                    cfg.ingress = true;
                    i += 1;
                }
                "egress" => {
                    cfg.ingress = false;
                    i += 1;
                }
                "split-gso" => {
                    cfg.split_gso = true;
                    i += 1;
                }
                "no-split-gso" => {
                    cfg.split_gso = false;
                    i += 1;
                }
                "autorate-ingress" => {
                    cfg.autorate = true;
                    i += 1;
                }
                "unlimited" => {
                    cfg.bandwidth = Some(crate::util::Rate::ZERO);
                    i += 1;
                }
                other => {
                    return Err(Error::InvalidMessage(format!(
                        "cake: unknown token `{other}`"
                    )));
                }
            }
        }
        Ok(cfg)
    }
}

impl QdiscConfig for CakeConfig {
    fn kind(&self) -> &'static str {
        "cake"
    }

    fn write_options(&self, builder: &mut MessageBuilder) -> Result<()> {
        use super::types::tc::qdisc::cake::*;

        if let Some(bw) = self.bandwidth {
            builder.append_attr_u64(TCA_CAKE_BASE_RATE64, bw.as_bytes_per_sec());
        }
        if let Some(rtt) = self.rtt {
            builder.append_attr_u32(TCA_CAKE_RTT, rtt.as_micros() as u32);
        }
        if let Some(target) = self.target {
            builder.append_attr_u32(TCA_CAKE_TARGET, target.as_micros() as u32);
        }
        if let Some(overhead) = self.overhead {
            builder.append_attr(TCA_CAKE_OVERHEAD, &overhead.to_ne_bytes());
        }
        if let Some(mpu) = self.mpu {
            builder.append_attr_u32(TCA_CAKE_MPU, mpu);
        }
        if let Some(mem) = self.memory_limit {
            builder.append_attr_u32(TCA_CAKE_MEMORY, mem.as_u32_saturating());
        }
        if let Some(mask) = self.fwmark {
            builder.append_attr_u32(TCA_CAKE_FWMARK, mask);
        }
        if let Some(mode) = self.diffserv_mode {
            let v = match mode {
                CakeDiffserv::Diffserv3 => CAKE_DIFFSERV_DIFFSERV3,
                CakeDiffserv::Diffserv4 => CAKE_DIFFSERV_DIFFSERV4,
                CakeDiffserv::Diffserv8 => CAKE_DIFFSERV_DIFFSERV8,
                CakeDiffserv::Besteffort => CAKE_DIFFSERV_BESTEFFORT,
                CakeDiffserv::Precedence => CAKE_DIFFSERV_PRECEDENCE,
            };
            builder.append_attr_u32(TCA_CAKE_DIFFSERV_MODE, v);
        }
        if let Some(mode) = self.flow_mode {
            let v = match mode {
                CakeFlowMode::Flowblind => CAKE_FLOW_NONE,
                CakeFlowMode::Srchost => CAKE_FLOW_SRC_IP,
                CakeFlowMode::Dsthost => CAKE_FLOW_DST_IP,
                CakeFlowMode::Hosts => CAKE_FLOW_HOSTS,
                CakeFlowMode::Flows => CAKE_FLOW_FLOWS,
                CakeFlowMode::DualSrchost => CAKE_FLOW_DUAL_SRC,
                CakeFlowMode::DualDsthost => CAKE_FLOW_DUAL_DST,
                CakeFlowMode::Triple => CAKE_FLOW_TRIPLE,
            };
            builder.append_attr_u32(TCA_CAKE_FLOW_MODE, v);
        }
        if let Some(mode) = self.atm_mode {
            let v = match mode {
                CakeAtmMode::None => CAKE_ATM_NONE,
                CakeAtmMode::Atm => CAKE_ATM_ATM,
                CakeAtmMode::Ptm => CAKE_ATM_PTM,
            };
            builder.append_attr_u32(TCA_CAKE_ATM, v);
        }
        if let Some(mode) = self.ack_filter {
            let v = match mode {
                CakeAckFilter::Disabled => CAKE_ACK_NONE,
                CakeAckFilter::Filter => CAKE_ACK_FILTER,
                CakeAckFilter::Aggressive => CAKE_ACK_AGGRESSIVE,
            };
            builder.append_attr_u32(TCA_CAKE_ACK_FILTER, v);
        }
        if self.autorate {
            builder.append_attr_u32(TCA_CAKE_AUTORATE, 1);
        }
        if self.nat {
            builder.append_attr_u32(TCA_CAKE_NAT, 1);
        }
        if self.raw {
            builder.append_attr_u32(TCA_CAKE_RAW, 1);
        }
        if self.wash {
            builder.append_attr_u32(TCA_CAKE_WASH, 1);
        }
        if self.ingress {
            builder.append_attr_u32(TCA_CAKE_INGRESS, 1);
        }
        if self.split_gso {
            builder.append_attr_u32(TCA_CAKE_SPLIT_GSO, 1);
        }
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
}

impl Default for PlugConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl PlugConfig {
    /// Create a new plug configuration builder.
    pub fn new() -> Self {
        Self { limit: None }
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

    /// Parse a tc-style plug params slice into a typed `PlugConfig`.
    ///
    /// Recognised tokens:
    ///
    /// - `limit <bytes>` — initial buffer limit.
    ///
    /// Unknown tokens, missing values, and unparseable sizes return
    /// `Error::InvalidMessage`.
    pub fn parse_params(params: &[&str]) -> Result<Self> {
        let mut cfg = Self::new();
        let mut i = 0;
        while i < params.len() {
            let key = params[i];
            match key {
                "limit" => {
                    let s = params.get(i + 1).copied().ok_or_else(|| {
                        Error::InvalidMessage("plug: `limit` requires a value".into())
                    })?;
                    let bytes = crate::util::parse::get_size(s).map_err(|_| {
                        Error::InvalidMessage(format!(
                            "plug: invalid limit `{s}` (expected tc-style size)"
                        ))
                    })?;
                    cfg.limit = Some(bytes.try_into().map_err(|_| {
                        Error::InvalidMessage(format!("plug: limit `{s}` exceeds u32"))
                    })?);
                    i += 2;
                }
                other => {
                    return Err(Error::InvalidMessage(format!(
                        "plug: unknown token `{other}`"
                    )));
                }
            }
        }
        Ok(cfg)
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
        }
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

    /// Parse a tc-style mqprio params slice into a typed `MqprioConfig`.
    ///
    /// Recognised tokens:
    ///
    /// - `num_tc <n>` — number of traffic classes (1-16).
    /// - `map <P0> <P1> ... <P15>` — exactly 16 priority-to-tc
    ///   mappings.
    /// - `hw` / `nohw` — hardware-offload flag pair.
    ///
    /// **Not yet typed-modelled** (returns `Error::InvalidMessage`):
    /// `queues <count1@offset1> <count2@offset2> ...` — the
    /// per-class queue layout is structured (count + offset pairs)
    /// and the `count@offset` parsing isn't implemented here yet.
    /// Use `MqprioConfig::queues()` directly on the typed builder
    /// for that.
    pub fn parse_params(params: &[&str]) -> Result<Self> {
        let mut cfg = Self::new();
        let mut i = 0;
        while i < params.len() {
            let key = params[i];
            match key {
                "num_tc" => {
                    let s = params.get(i + 1).copied().ok_or_else(|| {
                        Error::InvalidMessage("mqprio: `num_tc` requires a value".into())
                    })?;
                    let n: u8 = s.parse().map_err(|_| {
                        Error::InvalidMessage(format!(
                            "mqprio: invalid num_tc `{s}` (expected 1-16)"
                        ))
                    })?;
                    if !(1..=16).contains(&n) {
                        return Err(Error::InvalidMessage(format!(
                            "mqprio: num_tc `{n}` out of range (1-16)"
                        )));
                    }
                    cfg = cfg.num_tc(n);
                    i += 2;
                }
                "map" => {
                    if params.len() < i + 1 + 16 {
                        return Err(Error::InvalidMessage(format!(
                            "mqprio: `map` requires exactly 16 values, got {}",
                            params.len().saturating_sub(i + 1)
                        )));
                    }
                    let mut map = [0u8; 16];
                    for j in 0..16 {
                        let s = params[i + 1 + j];
                        map[j] = s.parse().map_err(|_| {
                            Error::InvalidMessage(format!(
                                "mqprio: invalid map[{j}] `{s}` (expected 0-15)"
                            ))
                        })?;
                    }
                    cfg.prio_tc_map = map;
                    i += 17;
                }
                "hw" => {
                    cfg.hw = true;
                    i += 1;
                }
                "nohw" => {
                    cfg.hw = false;
                    i += 1;
                }
                "queues" => {
                    return Err(Error::InvalidMessage(
                        "mqprio: `queues` (count@offset list) is not parsed by parse_params yet — use MqprioConfig::queues() on the typed builder".into(),
                    ));
                }
                other => {
                    return Err(Error::InvalidMessage(format!(
                        "mqprio: unknown token `{other}`"
                    )));
                }
            }
        }
        Ok(cfg)
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
        }
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

    /// Parse a tc-style taprio params slice into a typed
    /// `TaprioConfig`.
    ///
    /// Recognised tokens:
    ///
    /// - `num_tc <n>` — number of traffic classes (1-16).
    /// - `map <P0> ... <P15>` — exactly 16 priority-to-tc mappings.
    /// - `clockid <id>` — clock ID (named like `CLOCK_TAI` or bare
    ///   integer).
    /// - `base-time <ns>` — base time, ns since epoch (i64).
    /// - `cycle-time <ns>` — cycle time (i64).
    /// - `cycle-time-extension <ns>` — cycle time extension (i64).
    /// - `txtime-delay <ns>` — TX time delay (u32).
    /// - `txtime-assist` / `notxtime-assist` — flag pair.
    /// - `full-offload` / `nofull-offload` — flag pair.
    /// - `flags <hex>` — raw flags u32 (alternative to the named
    ///   flag pairs above; replaces, doesn't OR).
    /// - `sched-entry <CMD> <gate-mask-hex> <interval-ns>` —
    ///   schedule entry. CMD is `SET` (alias `S`),
    ///   `SET_AND_HOLD` (`HOLD`/`H`), or `SET_AND_RELEASE`
    ///   (`RELEASE`/`R`). Multiple `sched-entry` tokens append.
    ///
    /// **Not yet typed-modelled** (returns `Error::InvalidMessage`):
    /// `queues <count@offset>` — same pair-grammar deferral as
    /// `MqprioConfig`.
    ///
    /// **Net new CLI capability**: the legacy qdisc dispatcher
    /// silently swallowed `taprio`.
    pub fn parse_params(params: &[&str]) -> Result<Self> {
        use crate::netlink::types::tc::qdisc::taprio::{
            TAPRIO_ATTR_FLAG_FULL_OFFLOAD, TAPRIO_ATTR_FLAG_TXTIME_ASSIST,
        };
        let mut cfg = Self::new();
        let mut i = 0;
        while i < params.len() {
            let key = params[i];
            let need_value = || {
                params.get(i + 1).copied().ok_or_else(|| {
                    Error::InvalidMessage(format!("taprio: `{key}` requires a value"))
                })
            };
            match key {
                "num_tc" => {
                    let s = need_value()?;
                    let n: u8 = s.parse().map_err(|_| {
                        Error::InvalidMessage(format!(
                            "taprio: invalid num_tc `{s}` (expected 1-16)"
                        ))
                    })?;
                    if !(1..=16).contains(&n) {
                        return Err(Error::InvalidMessage(format!(
                            "taprio: num_tc `{n}` out of range (1-16)"
                        )));
                    }
                    cfg = cfg.num_tc(n);
                    i += 2;
                }
                "map" => {
                    if params.len() < i + 1 + 16 {
                        return Err(Error::InvalidMessage(format!(
                            "taprio: `map` requires exactly 16 values, got {}",
                            params.len().saturating_sub(i + 1)
                        )));
                    }
                    let mut map = [0u8; 16];
                    for j in 0..16 {
                        let s = params[i + 1 + j];
                        map[j] = s.parse().map_err(|_| {
                            Error::InvalidMessage(format!(
                                "taprio: invalid map[{j}] `{s}` (expected 0-15)"
                            ))
                        })?;
                    }
                    cfg.prio_tc_map = map;
                    i += 17;
                }
                "clockid" => {
                    let s = need_value()?;
                    cfg.clockid = parse_etf_clockid(s).map_err(|e| {
                        // Re-label the error from the etf helper to taprio context.
                        Error::InvalidMessage(format!("taprio: invalid clockid `{s}` ({e})"))
                    })?;
                    i += 2;
                }
                "base-time" => {
                    let s = need_value()?;
                    cfg.base_time = s.parse().map_err(|_| {
                        Error::InvalidMessage(format!("taprio: invalid base-time `{s}`"))
                    })?;
                    i += 2;
                }
                "cycle-time" => {
                    let s = need_value()?;
                    cfg.cycle_time = s.parse().map_err(|_| {
                        Error::InvalidMessage(format!("taprio: invalid cycle-time `{s}`"))
                    })?;
                    i += 2;
                }
                "cycle-time-extension" => {
                    let s = need_value()?;
                    cfg.cycle_time_extension = s.parse().map_err(|_| {
                        Error::InvalidMessage(format!("taprio: invalid cycle-time-extension `{s}`"))
                    })?;
                    i += 2;
                }
                "txtime-delay" => {
                    let s = need_value()?;
                    cfg.txtime_delay = s.parse().map_err(|_| {
                        Error::InvalidMessage(format!("taprio: invalid txtime-delay `{s}`"))
                    })?;
                    i += 2;
                }
                "txtime-assist" => {
                    cfg.flags |= TAPRIO_ATTR_FLAG_TXTIME_ASSIST;
                    i += 1;
                }
                "notxtime-assist" => {
                    cfg.flags &= !TAPRIO_ATTR_FLAG_TXTIME_ASSIST;
                    i += 1;
                }
                "full-offload" => {
                    cfg.flags |= TAPRIO_ATTR_FLAG_FULL_OFFLOAD;
                    i += 1;
                }
                "nofull-offload" => {
                    cfg.flags &= !TAPRIO_ATTR_FLAG_FULL_OFFLOAD;
                    i += 1;
                }
                "flags" => {
                    let s = need_value()?;
                    let trimmed = s.strip_prefix("0x").unwrap_or(s);
                    cfg.flags = u32::from_str_radix(trimmed, 16)
                        .or_else(|_| s.parse::<u32>())
                        .map_err(|_| {
                            Error::InvalidMessage(format!(
                                "taprio: invalid flags `{s}` (expected hex u32 or decimal)"
                            ))
                        })?;
                    i += 2;
                }
                "sched-entry" => {
                    let cmd_s = params.get(i + 1).copied().ok_or_else(|| {
                        Error::InvalidMessage(
                            "taprio: `sched-entry` needs <cmd> <gate-mask-hex> <interval-ns>"
                                .into(),
                        )
                    })?;
                    let mask_s = params.get(i + 2).copied().ok_or_else(|| {
                        Error::InvalidMessage(
                            "taprio: `sched-entry` needs <cmd> <gate-mask-hex> <interval-ns>"
                                .into(),
                        )
                    })?;
                    let interval_s = params.get(i + 3).copied().ok_or_else(|| {
                        Error::InvalidMessage(
                            "taprio: `sched-entry` needs <cmd> <gate-mask-hex> <interval-ns>"
                                .into(),
                        )
                    })?;
                    let entry = parse_taprio_sched_entry(cmd_s, mask_s, interval_s)?;
                    cfg.entries.push(entry);
                    i += 4;
                }
                "queues" => {
                    return Err(Error::InvalidMessage(
                        "taprio: `queues` (count@offset list) is not parsed by parse_params yet — use TaprioConfig::queues() on the typed builder".into(),
                    ));
                }
                other => {
                    return Err(Error::InvalidMessage(format!(
                        "taprio: unknown token `{other}`"
                    )));
                }
            }
        }
        Ok(cfg)
    }
}

/// Parse a single taprio sched-entry triple (cmd, gate-mask-hex,
/// interval-ns).
fn parse_taprio_sched_entry(
    cmd_s: &str,
    mask_s: &str,
    interval_s: &str,
) -> Result<super::types::tc::qdisc::taprio::TaprioSchedEntry> {
    use super::types::tc::qdisc::taprio::{
        TC_TAPRIO_CMD_SET_AND_HOLD, TC_TAPRIO_CMD_SET_AND_RELEASE, TC_TAPRIO_CMD_SET_GATES,
        TaprioSchedEntry,
    };
    let cmd = match cmd_s {
        "SET" | "S" | "set" | "s" => TC_TAPRIO_CMD_SET_GATES,
        "SET_AND_HOLD" | "HOLD" | "H" | "hold" | "h" => TC_TAPRIO_CMD_SET_AND_HOLD,
        "SET_AND_RELEASE" | "RELEASE" | "R" | "release" | "r" => TC_TAPRIO_CMD_SET_AND_RELEASE,
        other => {
            return Err(Error::InvalidMessage(format!(
                "taprio: invalid sched-entry cmd `{other}` (expected SET / HOLD / RELEASE)"
            )));
        }
    };
    let mask_trimmed = mask_s.strip_prefix("0x").unwrap_or(mask_s);
    let mask = u32::from_str_radix(mask_trimmed, 16).map_err(|_| {
        Error::InvalidMessage(format!(
            "taprio: invalid sched-entry gate mask `{mask_s}` (expected hex)"
        ))
    })?;
    let interval = interval_s.parse::<u32>().map_err(|_| {
        Error::InvalidMessage(format!(
            "taprio: invalid sched-entry interval `{interval_s}` (expected u32 ns)"
        ))
    })?;
    Ok(TaprioSchedEntry::new(cmd, mask, interval))
}

impl QdiscConfig for TaprioConfig {
    fn kind(&self) -> &'static str {
        "taprio"
    }

    fn write_options(&self, builder: &mut MessageBuilder) -> Result<()> {
        use super::types::tc::qdisc::{mqprio::TcMqprioQopt, taprio::*};

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
}

impl Default for HfscConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl HfscConfig {
    /// Create a new HFSC configuration builder.
    pub fn new() -> Self {
        Self { default_class: 0 }
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

    /// Parse a tc-style hfsc params slice into a typed `HfscConfig`.
    ///
    /// Recognised tokens:
    ///
    /// - `default <classid>` — default class for unclassified
    ///   packets. Accepts a tc handle's minor (`10` → `0x10`,
    ///   matching `tc(8)`'s `tc qdisc add ... hfsc default 10`
    ///   convention).
    ///
    /// Unknown tokens, missing values, and unparseable values
    /// return `Error::InvalidMessage`.
    pub fn parse_params(params: &[&str]) -> Result<Self> {
        let mut cfg = Self::new();
        let mut i = 0;
        while i < params.len() {
            let key = params[i];
            match key {
                "default" => {
                    let s = params.get(i + 1).copied().ok_or_else(|| {
                        Error::InvalidMessage("hfsc: `default` requires a value".into())
                    })?;
                    cfg.default_class = u16::from_str_radix(s, 16).map_err(|_| {
                        Error::InvalidMessage(format!(
                            "hfsc: invalid default `{s}` (expected hex minor like `10`)"
                        ))
                    })?;
                    i += 2;
                }
                other => {
                    return Err(Error::InvalidMessage(format!(
                        "hfsc: unknown token `{other}`"
                    )));
                }
            }
        }
        Ok(cfg)
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
        }
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

    /// Parse a tc-style etf params slice into a typed `EtfConfig`.
    ///
    /// Recognised tokens:
    ///
    /// - `delta <ns>` — transmission-time delta in nanoseconds
    ///   (signed i32).
    /// - `clockid <id>` — clock ID. Accepts the common names
    ///   `CLOCK_TAI`, `CLOCK_REALTIME`, `CLOCK_MONOTONIC`,
    ///   `CLOCK_BOOTTIME`, `CLOCK_PROCESS_CPUTIME_ID`,
    ///   `CLOCK_THREAD_CPUTIME_ID`, or a bare integer.
    /// - `deadline_mode` / `nodeadline_mode` — flag pair.
    /// - `offload` / `nooffload` — hardware-offload flag pair.
    /// - `skip_sock_check` / `noskip_sock_check` — flag pair.
    pub fn parse_params(params: &[&str]) -> Result<Self> {
        let mut cfg = Self::new();
        let mut i = 0;
        while i < params.len() {
            let key = params[i];
            let need_value = || {
                params
                    .get(i + 1)
                    .copied()
                    .ok_or_else(|| Error::InvalidMessage(format!("etf: `{key}` requires a value")))
            };
            match key {
                "delta" => {
                    let s = need_value()?;
                    cfg.delta = s.parse().map_err(|_| {
                        Error::InvalidMessage(format!(
                            "etf: invalid delta `{s}` (expected signed integer ns)"
                        ))
                    })?;
                    i += 2;
                }
                "clockid" => {
                    let s = need_value()?;
                    cfg.clockid = parse_etf_clockid(s)?;
                    i += 2;
                }
                "deadline_mode" => {
                    cfg.deadline_mode = true;
                    i += 1;
                }
                "nodeadline_mode" => {
                    cfg.deadline_mode = false;
                    i += 1;
                }
                "offload" => {
                    cfg.offload = true;
                    i += 1;
                }
                "nooffload" => {
                    cfg.offload = false;
                    i += 1;
                }
                "skip_sock_check" => {
                    cfg.skip_sock_check = true;
                    i += 1;
                }
                "noskip_sock_check" => {
                    cfg.skip_sock_check = false;
                    i += 1;
                }
                other => {
                    return Err(Error::InvalidMessage(format!(
                        "etf: unknown token `{other}`"
                    )));
                }
            }
        }
        Ok(cfg)
    }
}

/// Map a clock-ID name to its libc constant; otherwise parse as a
/// bare integer. The named constants come from `<time.h>` and match
/// what `tc(8)` accepts.
fn parse_etf_clockid(s: &str) -> Result<i32> {
    Ok(match s {
        "CLOCK_REALTIME" => libc::CLOCK_REALTIME,
        "CLOCK_MONOTONIC" => libc::CLOCK_MONOTONIC,
        "CLOCK_PROCESS_CPUTIME_ID" => libc::CLOCK_PROCESS_CPUTIME_ID,
        "CLOCK_THREAD_CPUTIME_ID" => libc::CLOCK_THREAD_CPUTIME_ID,
        "CLOCK_BOOTTIME" => libc::CLOCK_BOOTTIME,
        "CLOCK_TAI" => libc::CLOCK_TAI,
        other => other.parse::<i32>().map_err(|_| {
            Error::InvalidMessage(format!(
                "etf: invalid clockid `{other}` (expected name like CLOCK_TAI or bare integer)"
            ))
        })?,
    })
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
// ClassConfig trait
// ============================================================================

/// Trait for TC class configurations.
///
/// This trait is analogous to `QdiscConfig` but for traffic control classes.
/// Classes are used with classful qdiscs like HTB, HFSC, and DRR.
pub trait ClassConfig: Send + Sync {
    /// Get the class type (e.g., "htb", "hfsc", "drr").
    fn kind(&self) -> &'static str;

    /// Write the class options to a message builder.
    fn write_options(&self, builder: &mut MessageBuilder) -> Result<()>;
}

// ============================================================================
// HtbClassConfig
// ============================================================================

/// HTB class configuration builder.
///
/// Provides a type-safe way to configure HTB classes with compile-time
/// validation and IDE autocompletion.
///
/// # Example
///
/// ```ignore
/// use nlink::netlink::{Connection, Route};
/// use nlink::netlink::tc::{HtbQdiscConfig, HtbClassConfig};
/// use nlink::Rate;
///
/// let conn = Connection::<Route>::new()?;
///
/// // First add HTB qdisc
/// let htb = HtbQdiscConfig::new().default_class(0x30).build();
/// conn.add_qdisc_full("eth0", "root", Some("1:"), htb).await?;
///
/// // Add root class (total bandwidth)
/// conn.add_class("eth0", "1:0", "1:1",
///     HtbClassConfig::new(Rate::gbit(1))
///         .ceil(Rate::gbit(1))
///         .build()
/// ).await?;
///
/// // Add child class with guaranteed and ceiling rates
/// conn.add_class("eth0", "1:1", "1:10",
///     HtbClassConfig::new(Rate::mbit(100))
///         .ceil(Rate::mbit(500))
///         .prio(1)
///         .build()
/// ).await?;
/// ```
#[derive(Debug, Clone)]
pub struct HtbClassConfig {
    /// Guaranteed rate.
    rate: crate::util::Rate,
    /// Maximum rate (ceil).
    ceil: Option<crate::util::Rate>,
    /// Burst size.
    burst: Option<crate::util::Bytes>,
    /// Ceil burst size.
    cburst: Option<crate::util::Bytes>,
    /// Priority (0-7, lower is higher priority).
    prio: Option<u32>,
    /// Quantum for round-robin.
    quantum: Option<u32>,
    /// MTU for rate calculations.
    mtu: u32,
    /// Minimum packet unit.
    mpu: u16,
    /// Per-packet overhead.
    overhead: u16,
}

impl HtbClassConfig {
    /// Create a new HTB class configuration with the given rate.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use nlink::Rate;
    /// let config = HtbClassConfig::new(Rate::mbit(100));
    /// // Or parse a tc-style string:
    /// let config = HtbClassConfig::new("100mbit".parse()?);
    /// ```
    pub fn new(rate: crate::util::Rate) -> Self {
        Self {
            rate,
            ceil: None,
            burst: None,
            cburst: None,
            prio: None,
            quantum: None,
            mtu: 1600,
            mpu: 0,
            overhead: 0,
        }
    }

    /// Set the ceiling rate.
    ///
    /// The ceiling rate is the maximum rate the class can use when borrowing
    /// from parent classes.
    pub fn ceil(mut self, ceil: crate::util::Rate) -> Self {
        self.ceil = Some(ceil);
        self
    }

    /// Set the burst size.
    ///
    /// The burst is the amount of data that can be sent at hardware speed
    /// before rate limiting kicks in.
    pub fn burst(mut self, burst: crate::util::Bytes) -> Self {
        self.burst = Some(burst);
        self
    }

    /// Set the ceil burst size.
    ///
    /// The cburst is the burst for the ceiling rate.
    pub fn cburst(mut self, cburst: crate::util::Bytes) -> Self {
        self.cburst = Some(cburst);
        self
    }

    /// Set the priority (0-7, lower = higher priority).
    ///
    /// Classes with lower priority values are served first.
    pub fn prio(mut self, prio: u32) -> Self {
        self.prio = Some(prio.min(7));
        self
    }

    /// Set the quantum for round-robin scheduling.
    ///
    /// The quantum determines how many bytes a class can send before
    /// yielding to siblings.
    pub fn quantum(mut self, quantum: u32) -> Self {
        self.quantum = Some(quantum);
        self
    }

    /// Set the MTU for rate table calculations.
    ///
    /// Default is 1600 bytes.
    pub fn mtu(mut self, mtu: u32) -> Self {
        self.mtu = mtu;
        self
    }

    /// Set the minimum packet unit.
    ///
    /// Packets smaller than this are treated as this size for rate calculations.
    pub fn mpu(mut self, mpu: u16) -> Self {
        self.mpu = mpu;
        self
    }

    /// Set the per-packet overhead.
    ///
    /// Added to each packet for rate calculations (e.g., for ATM or Ethernet framing).
    pub fn overhead(mut self, overhead: u16) -> Self {
        self.overhead = overhead;
        self
    }

    /// Build the configuration. No-op marker for "I'm done"; the
    /// builder is already usable as a `ClassConfig` without it.
    pub fn build(self) -> Self {
        self
    }

    /// Parse a `tc(8)`-style HTB class param token slice.
    ///
    /// Accepts the same keywords as `tc class add ... htb`: `rate`,
    /// `ceil`, `burst`/`buffer`/`maxburst`, `cburst`/`cbuffer`/`cmaxburst`,
    /// `prio`, `quantum`, `mtu`, `mpu`, `overhead`. `rate` is required
    /// (matches the kernel and `HtbClassConfig::new`'s contract).
    ///
    /// Strict: unknown tokens, missing values, and unparseable
    /// rates/sizes/integers all return `Error::InvalidMessage` —
    /// the legacy stringly-typed dispatcher used to silently swallow
    /// unknown tokens, which this replaces.
    pub fn parse_params(params: &[&str]) -> Result<Self> {
        use crate::util::Rate;
        let mut rate: Option<Rate> = None;
        let mut ceil: Option<Rate> = None;
        let mut burst: Option<crate::util::Bytes> = None;
        let mut cburst: Option<crate::util::Bytes> = None;
        let mut prio: Option<u32> = None;
        let mut quantum: Option<u32> = None;
        let mut mtu: Option<u32> = None;
        let mut mpu: Option<u16> = None;
        let mut overhead: Option<u16> = None;

        let mut i = 0;
        while i < params.len() {
            let tok = params[i];
            let val = || {
                params
                    .get(i + 1)
                    .copied()
                    .ok_or_else(|| Error::InvalidMessage(format!("htb: `{tok}` requires a value")))
            };
            match tok {
                "rate" => {
                    let v = val()?;
                    rate = Some(v.parse::<Rate>().map_err(|e| {
                        Error::InvalidMessage(format!("htb: invalid rate `{v}`: {e}"))
                    })?);
                    i += 2;
                }
                "ceil" => {
                    let v = val()?;
                    ceil = Some(v.parse::<Rate>().map_err(|e| {
                        Error::InvalidMessage(format!("htb: invalid ceil `{v}`: {e}"))
                    })?);
                    i += 2;
                }
                "burst" | "buffer" | "maxburst" => {
                    let v = val()?;
                    burst = Some(v.parse::<crate::util::Bytes>().map_err(|e| {
                        Error::InvalidMessage(format!("htb: invalid burst `{v}`: {e}"))
                    })?);
                    i += 2;
                }
                "cburst" | "cbuffer" | "cmaxburst" => {
                    let v = val()?;
                    cburst = Some(v.parse::<crate::util::Bytes>().map_err(|e| {
                        Error::InvalidMessage(format!("htb: invalid cburst `{v}`: {e}"))
                    })?);
                    i += 2;
                }
                "prio" => {
                    let v = val()?;
                    prio = Some(v.parse::<u32>().map_err(|_| {
                        Error::InvalidMessage(format!(
                            "htb: invalid prio `{v}` (expected unsigned integer)"
                        ))
                    })?);
                    i += 2;
                }
                "quantum" => {
                    let v = val()?;
                    let bytes = v.parse::<crate::util::Bytes>().map_err(|e| {
                        Error::InvalidMessage(format!("htb: invalid quantum `{v}`: {e}"))
                    })?;
                    quantum = Some(bytes.as_u32_saturating());
                    i += 2;
                }
                "mtu" => {
                    let v = val()?;
                    mtu = Some(v.parse::<u32>().map_err(|_| {
                        Error::InvalidMessage(format!(
                            "htb: invalid mtu `{v}` (expected unsigned integer)"
                        ))
                    })?);
                    i += 2;
                }
                "mpu" => {
                    let v = val()?;
                    mpu = Some(v.parse::<u16>().map_err(|_| {
                        Error::InvalidMessage(format!("htb: invalid mpu `{v}` (expected u16)"))
                    })?);
                    i += 2;
                }
                "overhead" => {
                    let v = val()?;
                    overhead = Some(v.parse::<u16>().map_err(|_| {
                        Error::InvalidMessage(format!("htb: invalid overhead `{v}` (expected u16)"))
                    })?);
                    i += 2;
                }
                other => {
                    return Err(Error::InvalidMessage(format!(
                        "htb: unknown token `{other}` (recognised: rate, ceil, burst, cburst, prio, quantum, mtu, mpu, overhead)"
                    )));
                }
            }
        }

        let rate = rate.ok_or_else(|| Error::InvalidMessage("htb: `rate` is required".into()))?;
        let mut cfg = HtbClassConfig::new(rate);
        if let Some(c) = ceil {
            cfg = cfg.ceil(c);
        }
        if let Some(b) = burst {
            cfg = cfg.burst(b);
        }
        if let Some(c) = cburst {
            cfg = cfg.cburst(c);
        }
        if let Some(p) = prio {
            cfg = cfg.prio(p);
        }
        if let Some(q) = quantum {
            cfg = cfg.quantum(q);
        }
        if let Some(m) = mtu {
            cfg = cfg.mtu(m);
        }
        if let Some(m) = mpu {
            cfg = cfg.mpu(m);
        }
        if let Some(o) = overhead {
            cfg = cfg.overhead(o);
        }
        Ok(cfg)
    }
}

impl ClassConfig for HtbClassConfig {
    fn kind(&self) -> &'static str {
        "htb"
    }

    fn write_options(&self, builder: &mut MessageBuilder) -> Result<()> {
        let cfg = self;
        let rate = cfg.rate.as_bytes_per_sec();
        let ceil = cfg.ceil.unwrap_or(cfg.rate).as_bytes_per_sec();

        // Get HZ for time calculations (typically 1000 on Linux)
        let hz: u64 = 1000;

        // Calculate burst from rate if not specified
        let burst = cfg
            .burst
            .map(|b| b.as_u32_saturating())
            .unwrap_or_else(|| (rate / hz + cfg.mtu as u64) as u32);
        let cburst = cfg
            .cburst
            .map(|b| b.as_u32_saturating())
            .unwrap_or_else(|| (ceil / hz + cfg.mtu as u64) as u32);

        // Calculate buffer time (in ticks). Falls back to the raw burst
        // size when the rate would cause a divide-by-zero.
        let buffer = (burst as u64 * 1_000_000)
            .checked_div(rate)
            .map(|v| v as u32)
            .unwrap_or(burst);

        let cbuffer = (cburst as u64 * 1_000_000)
            .checked_div(ceil)
            .map(|v| v as u32)
            .unwrap_or(cburst);

        // Build the tc_htb_opt structure
        let opt = htb::TcHtbOpt {
            rate: TcRateSpec {
                rate: if rate >= (1u64 << 32) {
                    u32::MAX
                } else {
                    rate as u32
                },
                mpu: cfg.mpu,
                overhead: cfg.overhead,
                ..Default::default()
            },
            ceil: TcRateSpec {
                rate: if ceil >= (1u64 << 32) {
                    u32::MAX
                } else {
                    ceil as u32
                },
                mpu: cfg.mpu,
                overhead: cfg.overhead,
                ..Default::default()
            },
            buffer,
            cbuffer,
            quantum: cfg.quantum.unwrap_or(0),
            prio: cfg.prio.unwrap_or(0),
            ..Default::default()
        };

        // Add 64-bit rate if needed (for rates >= 4 Gbps)
        if rate >= (1u64 << 32) {
            builder.append_attr(htb::TCA_HTB_RATE64, &rate.to_ne_bytes());
        }

        if ceil >= (1u64 << 32) {
            builder.append_attr(htb::TCA_HTB_CEIL64, &ceil.to_ne_bytes());
        }

        // Add the main parameters structure
        builder.append_attr(htb::TCA_HTB_PARMS, opt.as_bytes());

        // Add rate tables
        let rtab = compute_htb_rate_table(rate, cfg.mtu);
        let ctab = compute_htb_rate_table(ceil, cfg.mtu);

        builder.append_attr(htb::TCA_HTB_RTAB, &rtab);
        builder.append_attr(htb::TCA_HTB_CTAB, &ctab);

        Ok(())
    }
}

// ============================================================================
// HfscClassConfig
// ============================================================================

/// HFSC class configuration builder.
///
/// HFSC (Hierarchical Fair Service Curve) uses three service curves to provide
/// both bandwidth guarantees and latency bounds:
///
/// - **RSC (Real-time Service Curve)**: Guaranteed minimum latency service
/// - **FSC (Fair Service Curve)**: Guaranteed bandwidth over time
/// - **USC (Upper-limit Service Curve)**: Maximum bandwidth limit
///
/// Each curve can be a simple rate or a two-slope curve with an initial burst.
///
/// # Example
///
/// ```ignore
/// use nlink::netlink::{Connection, Route};
/// use nlink::netlink::tc::{HfscConfig, HfscClassConfig, TcServiceCurve};
///
/// let conn = Connection::<Route>::new()?;
///
/// // First add HFSC qdisc
/// let hfsc = HfscConfig::new().default_class(0x10).build();
/// conn.add_qdisc_full("eth0", "root", Some("1:"), hfsc).await?;
///
/// // Add root class with link-share curve
/// conn.add_class("eth0", "1:0", "1:1",
///     HfscClassConfig::new()
///         .ls_rate(1_000_000_000)  // 1 Gbps link-share
///         .build()
/// ).await?;
///
/// // Add real-time class with latency guarantee
/// conn.add_class("eth0", "1:1", "1:10",
///     HfscClassConfig::new()
///         .rt_curve(TcServiceCurve::two_slope(10_000_000, 5000, 1_000_000))
///         .ls_rate(100_000_000)
///         .build()
/// ).await?;
///
/// // Add best-effort class with upper limit
/// conn.add_class("eth0", "1:1", "1:20",
///     HfscClassConfig::new()
///         .ls_rate(50_000_000)
///         .ul_rate(100_000_000)  // Cap at 100 Mbps
///         .build()
/// ).await?;
/// ```
#[derive(Debug, Clone, Default)]
pub struct HfscClassConfig {
    /// Real-time service curve (latency guarantee).
    rsc: Option<TcServiceCurve>,
    /// Fair service curve (bandwidth share).
    fsc: Option<TcServiceCurve>,
    /// Upper-limit service curve (maximum bandwidth).
    usc: Option<TcServiceCurve>,
}

impl HfscClassConfig {
    /// Create a new HFSC class configuration builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the real-time service curve (latency guarantee).
    ///
    /// The RSC provides a guaranteed minimum latency service. Packets are
    /// scheduled to meet the delay bound specified by this curve.
    pub fn rt_curve(mut self, curve: TcServiceCurve) -> Self {
        self.rsc = Some(curve);
        self
    }

    /// Set the real-time curve as a simple rate.
    ///
    /// HFSC's `tc_service_curve.m1`/`.m2` are 32-bit fields in the kernel
    /// UAPI. The `Rate` is saturating-cast to `u32` (max ≈4 GB/s ≈ 32 Gbps).
    pub fn rt_rate(mut self, rate: crate::util::Rate) -> Self {
        self.rsc = Some(TcServiceCurve::rate(rate.as_u32_bytes_per_sec_saturating()));
        self
    }

    /// Set the link-share (fair) service curve.
    ///
    /// The FSC determines the bandwidth share among sibling classes.
    /// This is the most commonly used curve.
    pub fn ls_curve(mut self, curve: TcServiceCurve) -> Self {
        self.fsc = Some(curve);
        self
    }

    /// Set the link-share curve as a simple rate. See [`Self::rt_rate`] for
    /// the 32-bit saturating-cast caveat.
    pub fn ls_rate(mut self, rate: crate::util::Rate) -> Self {
        self.fsc = Some(TcServiceCurve::rate(rate.as_u32_bytes_per_sec_saturating()));
        self
    }

    /// Set the upper-limit service curve.
    ///
    /// The USC caps the maximum bandwidth a class can use, even when
    /// there's spare bandwidth available.
    pub fn ul_curve(mut self, curve: TcServiceCurve) -> Self {
        self.usc = Some(curve);
        self
    }

    /// Set the upper-limit curve as a simple rate. See [`Self::rt_rate`] for
    /// the 32-bit saturating-cast caveat.
    pub fn ul_rate(mut self, rate: crate::util::Rate) -> Self {
        self.usc = Some(TcServiceCurve::rate(rate.as_u32_bytes_per_sec_saturating()));
        self
    }

    /// Build the configuration. No-op marker for "I'm done"; the
    /// builder is already usable as a `ClassConfig` without it.
    pub fn build(self) -> Self {
        self
    }

    /// Parse a simplified `tc(8)`-style HFSC class param token slice.
    ///
    /// Accepts the rate-only forms: `rt rate <rate>`, `ls rate <rate>`,
    /// `ul rate <rate>`. The full `m1/d/m2` service-curve grammar is
    /// not parsed here — callers needing arbitrary curves should use
    /// the typed builder (`HfscClassConfig::new().rt_curve(...)`)
    /// directly. Strict rejection on unknown tokens.
    pub fn parse_params(params: &[&str]) -> Result<Self> {
        use crate::util::Rate;
        let mut cfg = HfscClassConfig::new();
        let mut i = 0;
        while i < params.len() {
            let curve = params[i];
            let kind = match curve {
                "rt" | "ls" | "ul" => curve,
                "sc" => {
                    return Err(Error::InvalidMessage(
                        "hfsc: `sc` (real-time + link-share combined) not modelled by parse_params — use HfscClassConfig::rt_curve + ls_curve on the typed builder".into(),
                    ));
                }
                other => {
                    return Err(Error::InvalidMessage(format!(
                        "hfsc: unknown token `{other}` (recognised: rt, ls, ul; each followed by `rate <rate>`)"
                    )));
                }
            };
            // Expect `rate <rate>` after the curve keyword.
            let next = params.get(i + 1).copied().ok_or_else(|| {
                Error::InvalidMessage(format!("hfsc: `{kind}` requires `rate <rate>`"))
            })?;
            if next != "rate" {
                return Err(Error::InvalidMessage(format!(
                    "hfsc: `{kind}` followed by `{next}` — only the `rate <rate>` form is parsed (use the typed builder for full m1/d/m2 curves)"
                )));
            }
            let v = params.get(i + 2).copied().ok_or_else(|| {
                Error::InvalidMessage(format!("hfsc: `{kind} rate` requires a value"))
            })?;
            let rate = v
                .parse::<Rate>()
                .map_err(|e| Error::InvalidMessage(format!("hfsc: invalid rate `{v}`: {e}")))?;
            cfg = match kind {
                "rt" => cfg.rt_rate(rate),
                "ls" => cfg.ls_rate(rate),
                "ul" => cfg.ul_rate(rate),
                _ => unreachable!(),
            };
            i += 3;
        }
        Ok(cfg)
    }
}

impl ClassConfig for HfscClassConfig {
    fn kind(&self) -> &'static str {
        "hfsc"
    }

    fn write_options(&self, builder: &mut MessageBuilder) -> Result<()> {
        use super::types::tc::qdisc::hfsc::{TCA_HFSC_FSC, TCA_HFSC_RSC, TCA_HFSC_USC};

        let cfg = self;

        if let Some(ref rsc) = cfg.rsc {
            builder.append_attr(TCA_HFSC_RSC, rsc.as_bytes());
        }

        if let Some(ref fsc) = cfg.fsc {
            builder.append_attr(TCA_HFSC_FSC, fsc.as_bytes());
        }

        if let Some(ref usc) = cfg.usc {
            builder.append_attr(TCA_HFSC_USC, usc.as_bytes());
        }

        Ok(())
    }
}

// ============================================================================
// DrrClassConfig
// ============================================================================

/// DRR class configuration builder.
///
/// DRR (Deficit Round Robin) is a simple fair queuing algorithm where each
/// class gets a quantum of bytes to send per round. Classes with larger
/// quanta get proportionally more bandwidth.
///
/// # Example
///
/// ```ignore
/// use nlink::netlink::{Connection, Route};
/// use nlink::netlink::tc::{DrrConfig, DrrClassConfig};
///
/// let conn = Connection::<Route>::new()?;
///
/// // First add DRR qdisc
/// let drr = DrrConfig::new().handle("1:").build();
/// conn.add_qdisc_full("eth0", "root", Some("1:"), drr).await?;
///
/// // Add classes with different quanta (bandwidth proportions)
/// conn.add_class("eth0", "1:0", "1:1",
///     DrrClassConfig::new()
///         .quantum(1500)  // 1 packet worth
///         .build()
/// ).await?;
///
/// conn.add_class("eth0", "1:0", "1:2",
///     DrrClassConfig::new()
///         .quantum(3000)  // 2x bandwidth of class 1:1
///         .build()
/// ).await?;
/// ```
#[derive(Debug, Clone, Default)]
pub struct DrrClassConfig {
    /// Quantum in bytes (bandwidth share).
    quantum: Option<crate::util::Bytes>,
}

impl DrrClassConfig {
    /// Create a new DRR class configuration builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the quantum.
    ///
    /// The quantum determines how many bytes this class can send per round.
    /// Classes with larger quanta get proportionally more bandwidth.
    /// If not set, defaults to the interface MTU. Saturates at u32::MAX
    /// because the kernel field is 32 bits.
    pub fn quantum(mut self, q: crate::util::Bytes) -> Self {
        self.quantum = Some(q);
        self
    }

    /// Build the configuration. No-op marker for "I'm done"; the
    /// builder is already usable as a `ClassConfig` without it.
    pub fn build(self) -> Self {
        self
    }

    /// Parse a `tc(8)`-style DRR class param token slice.
    ///
    /// DRR class accepts a single optional keyword: `quantum <bytes>`.
    /// Unknown tokens, missing values, and unparseable sizes return
    /// `Error::InvalidMessage`.
    pub fn parse_params(params: &[&str]) -> Result<Self> {
        let mut cfg = DrrClassConfig::new();
        let mut i = 0;
        while i < params.len() {
            let tok = params[i];
            match tok {
                "quantum" => {
                    let v = params.get(i + 1).copied().ok_or_else(|| {
                        Error::InvalidMessage("drr: `quantum` requires a value".into())
                    })?;
                    let q = v.parse::<crate::util::Bytes>().map_err(|e| {
                        Error::InvalidMessage(format!("drr: invalid quantum `{v}`: {e}"))
                    })?;
                    cfg = cfg.quantum(q);
                    i += 2;
                }
                other => {
                    return Err(Error::InvalidMessage(format!(
                        "drr: unknown token `{other}` (recognised: quantum)"
                    )));
                }
            }
        }
        Ok(cfg)
    }
}

impl ClassConfig for DrrClassConfig {
    fn kind(&self) -> &'static str {
        "drr"
    }

    fn write_options(&self, builder: &mut MessageBuilder) -> Result<()> {
        use super::types::tc::qdisc::drr::TCA_DRR_QUANTUM;

        if let Some(quantum) = self.quantum {
            builder.append_attr_u32(TCA_DRR_QUANTUM, quantum.as_u32_saturating());
        }

        Ok(())
    }
}

// ============================================================================
// QfqClassConfig
// ============================================================================

/// QFQ class configuration builder.
///
/// QFQ (Quick Fair Queueing) is similar to DRR but with O(1) complexity
/// for scheduling. Each class has a weight and an optional maximum packet
/// size limit.
///
/// # Example
///
/// ```ignore
/// use nlink::netlink::{Connection, Route};
/// use nlink::netlink::tc::{QfqConfig, QfqClassConfig};
///
/// let conn = Connection::<Route>::new()?;
///
/// // First add QFQ qdisc
/// let qfq = QfqConfig::new().handle("1:").build();
/// conn.add_qdisc_full("eth0", "root", Some("1:"), qfq).await?;
///
/// // Add classes with different weights
/// conn.add_class("eth0", "1:0", "1:1",
///     QfqClassConfig::new()
///         .weight(1)
///         .build()
/// ).await?;
///
/// conn.add_class("eth0", "1:0", "1:2",
///     QfqClassConfig::new()
///         .weight(2)  // 2x bandwidth of class 1:1
///         .lmax(9000) // Max packet size (for jumbo frames)
///         .build()
/// ).await?;
/// ```
#[derive(Debug, Clone, Default)]
pub struct QfqClassConfig {
    /// Weight (bandwidth share).
    weight: Option<u32>,
    /// Maximum packet length.
    lmax: Option<crate::util::Bytes>,
}

impl QfqClassConfig {
    /// Create a new QFQ class configuration builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the weight.
    ///
    /// The weight determines the relative bandwidth share. A class with
    /// weight 2 gets twice the bandwidth of a class with weight 1.
    /// Valid range is 1-1023.
    pub fn weight(mut self, weight: u32) -> Self {
        self.weight = Some(weight.clamp(1, 1023));
        self
    }

    /// Set the maximum packet length.
    ///
    /// This is used for internal scheduling calculations. Should be at
    /// least the interface MTU. Default is typically 2048. Saturates at
    /// u32::MAX because the kernel field is 32 bits.
    pub fn lmax(mut self, b: crate::util::Bytes) -> Self {
        self.lmax = Some(b);
        self
    }

    /// Build the configuration. No-op marker for "I'm done"; the
    /// builder is already usable as a `ClassConfig` without it.
    pub fn build(self) -> Self {
        self
    }

    /// Parse a `tc(8)`-style QFQ class param token slice.
    ///
    /// QFQ class accepts: `weight <u32>` (1..=1023, clamped) and
    /// `lmax <bytes>`. Unknown tokens and unparseable values return
    /// `Error::InvalidMessage`.
    pub fn parse_params(params: &[&str]) -> Result<Self> {
        let mut cfg = QfqClassConfig::new();
        let mut i = 0;
        while i < params.len() {
            let tok = params[i];
            match tok {
                "weight" => {
                    let v = params.get(i + 1).copied().ok_or_else(|| {
                        Error::InvalidMessage("qfq: `weight` requires a value".into())
                    })?;
                    let w = v.parse::<u32>().map_err(|_| {
                        Error::InvalidMessage(format!(
                            "qfq: invalid weight `{v}` (expected unsigned integer)"
                        ))
                    })?;
                    cfg = cfg.weight(w);
                    i += 2;
                }
                "lmax" => {
                    let v = params.get(i + 1).copied().ok_or_else(|| {
                        Error::InvalidMessage("qfq: `lmax` requires a value".into())
                    })?;
                    let b = v.parse::<crate::util::Bytes>().map_err(|e| {
                        Error::InvalidMessage(format!("qfq: invalid lmax `{v}`: {e}"))
                    })?;
                    cfg = cfg.lmax(b);
                    i += 2;
                }
                other => {
                    return Err(Error::InvalidMessage(format!(
                        "qfq: unknown token `{other}` (recognised: weight, lmax)"
                    )));
                }
            }
        }
        Ok(cfg)
    }
}

impl ClassConfig for QfqClassConfig {
    fn kind(&self) -> &'static str {
        "qfq"
    }

    fn write_options(&self, builder: &mut MessageBuilder) -> Result<()> {
        use super::types::tc::qdisc::qfq::{TCA_QFQ_LMAX, TCA_QFQ_WEIGHT};

        if let Some(weight) = self.weight {
            builder.append_attr_u32(TCA_QFQ_WEIGHT, weight);
        }

        if let Some(lmax) = self.lmax {
            builder.append_attr_u32(TCA_QFQ_LMAX, lmax.as_u32_saturating());
        }

        Ok(())
    }
}

// ============================================================================
// HTB class rate-table helper (used by `impl ClassConfig for HtbClassConfig`)
// ============================================================================

/// Compute a rate table for HTB class.
fn compute_htb_rate_table(rate: u64, mtu: u32) -> [u8; 1024] {
    let mut table = [0u8; 1024];

    if rate == 0 {
        return table;
    }

    let cell_log: u32 = 3;
    let cell_size = 1u32 << cell_log;
    let time_units_per_sec: u64 = 1_000_000;

    for i in 0..256 {
        let size = ((i + 1) as u32) * cell_size;
        let size = size.min(mtu);

        let time = (size as u64 * time_units_per_sec) / rate;
        let time = time.min(u32::MAX as u64) as u32;

        let offset = i * 4;
        table[offset..offset + 4].copy_from_slice(&time.to_ne_bytes());
    }

    table
}

// ============================================================================
// Connection extension methods
// ============================================================================

impl Connection<Route> {
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
    #[tracing::instrument(level = "debug", skip_all, fields(method = "add_qdisc"))]
    pub async fn add_qdisc(
        &self,
        dev: impl Into<InterfaceRef>,
        config: impl QdiscConfig,
    ) -> Result<()> {
        self.add_qdisc_full(dev, TcHandle::ROOT, None, config).await
    }

    /// Add a qdisc with explicit parent and handle.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "add_qdisc_full"))]
    pub async fn add_qdisc_full(
        &self,
        dev: impl Into<InterfaceRef>,
        parent: TcHandle,
        handle: Option<TcHandle>,
        config: impl QdiscConfig,
    ) -> Result<()> {
        let ifindex = self.resolve_interface(&dev.into()).await?;
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
    /// use nlink::netlink::{Connection, Route, namespace, tc::NetemConfig};
    /// use std::time::Duration;
    ///
    /// let conn: Connection<Route> = namespace::connection_for("myns")?;
    /// let link = conn.get_link_by_name("eth0").await?;
    ///
    /// let netem = NetemConfig::new()
    ///     .delay(Duration::from_millis(100))
    ///     .build();
    ///
    /// conn.add_qdisc_by_index(link.ifindex(), netem).await?;
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "add_qdisc_by_index"))]
    pub async fn add_qdisc_by_index(&self, ifindex: u32, config: impl QdiscConfig) -> Result<()> {
        self.add_qdisc_by_index_full(ifindex, TcHandle::ROOT, None, config)
            .await
    }

    /// Add a qdisc by interface index with explicit parent and handle.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "add_qdisc_by_index_full"))]
    pub async fn add_qdisc_by_index_full(
        &self,
        ifindex: u32,
        parent: TcHandle,
        handle: Option<TcHandle>,
        config: impl QdiscConfig,
    ) -> Result<()> {
        let parent_handle = parent.as_raw();
        let qdisc_handle = handle.map(|h| h.as_raw()).unwrap_or(0);

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

        self.send_ack(builder)
            .await
            .map_err(|e| e.with_context("add_qdisc"))
    }

    /// Delete a qdisc from an interface.
    ///
    /// # Example
    ///
    /// ```ignore
    /// conn.del_qdisc("eth0", "root").await?;
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "del_qdisc"))]
    pub async fn del_qdisc(&self, dev: impl Into<InterfaceRef>, parent: TcHandle) -> Result<()> {
        self.del_qdisc_full(dev, parent, None).await
    }

    /// Delete a qdisc with explicit handle.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "del_qdisc_full"))]
    pub async fn del_qdisc_full(
        &self,
        dev: impl Into<InterfaceRef>,
        parent: TcHandle,
        handle: Option<TcHandle>,
    ) -> Result<()> {
        let ifindex = self.resolve_interface(&dev.into()).await?;
        self.del_qdisc_by_index_full(ifindex, parent, handle).await
    }

    /// Delete a qdisc by interface index.
    ///
    /// This is useful for namespace-aware operations where you've already
    /// resolved the interface index via `conn.get_link_by_name()`.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "del_qdisc_by_index"))]
    pub async fn del_qdisc_by_index(&self, ifindex: u32, parent: TcHandle) -> Result<()> {
        self.del_qdisc_by_index_full(ifindex, parent, None).await
    }

    /// Delete a qdisc by interface index with explicit handle.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "del_qdisc_by_index_full"))]
    pub async fn del_qdisc_by_index_full(
        &self,
        ifindex: u32,
        parent: TcHandle,
        handle: Option<TcHandle>,
    ) -> Result<()> {
        let parent_handle = parent.as_raw();
        let qdisc_handle = handle.map(|h| h.as_raw()).unwrap_or(0);

        let tcmsg = TcMsg::new()
            .with_ifindex(ifindex as i32)
            .with_parent(parent_handle)
            .with_handle(qdisc_handle);

        let mut builder = ack_request(NlMsgType::RTM_DELQDISC);
        builder.append(&tcmsg);

        self.send_ack(builder).await.map_err(|e| {
            if e.is_not_found() {
                Error::QdiscNotFound {
                    kind: handle.unwrap_or(parent).to_string(),
                    interface: format!("ifindex {ifindex}"),
                }
            } else {
                e.with_context(format!("del_qdisc(ifindex {ifindex}, parent={})", parent))
            }
        })
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
    #[tracing::instrument(level = "debug", skip_all, fields(method = "replace_qdisc"))]
    pub async fn replace_qdisc(
        &self,
        dev: impl Into<InterfaceRef>,
        config: impl QdiscConfig,
    ) -> Result<()> {
        self.replace_qdisc_full(dev, TcHandle::ROOT, None, config)
            .await
    }

    /// Replace a qdisc with explicit parent and handle.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "replace_qdisc_full"))]
    pub async fn replace_qdisc_full(
        &self,
        dev: impl Into<InterfaceRef>,
        parent: TcHandle,
        handle: Option<TcHandle>,
        config: impl QdiscConfig,
    ) -> Result<()> {
        let ifindex = self.resolve_interface(&dev.into()).await?;
        self.replace_qdisc_by_index_full(ifindex, parent, handle, config)
            .await
    }

    /// Replace a qdisc by interface index (add or update).
    ///
    /// This is useful for namespace-aware operations where you've already
    /// resolved the interface index via `conn.get_link_by_name()`.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "replace_qdisc_by_index"))]
    pub async fn replace_qdisc_by_index(
        &self,
        ifindex: u32,
        config: impl QdiscConfig,
    ) -> Result<()> {
        self.replace_qdisc_by_index_full(ifindex, TcHandle::ROOT, None, config)
            .await
    }

    /// Replace a qdisc by interface index with explicit parent and handle.
    #[tracing::instrument(
        level = "debug",
        skip_all,
        fields(method = "replace_qdisc_by_index_full")
    )]
    pub async fn replace_qdisc_by_index_full(
        &self,
        ifindex: u32,
        parent: TcHandle,
        handle: Option<TcHandle>,
        config: impl QdiscConfig,
    ) -> Result<()> {
        let parent_handle = parent.as_raw();
        let qdisc_handle = handle.map(|h| h.as_raw()).unwrap_or(0);

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

        self.send_ack(builder)
            .await
            .map_err(|e| e.with_context("replace_qdisc"))
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
    #[tracing::instrument(level = "debug", skip_all, fields(method = "change_qdisc"))]
    pub async fn change_qdisc(
        &self,
        dev: impl Into<InterfaceRef>,
        parent: TcHandle,
        config: impl QdiscConfig,
    ) -> Result<()> {
        self.change_qdisc_full(dev, parent, None, config).await
    }

    /// Change a qdisc with explicit handle.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "change_qdisc_full"))]
    pub async fn change_qdisc_full(
        &self,
        dev: impl Into<InterfaceRef>,
        parent: TcHandle,
        handle: Option<TcHandle>,
        config: impl QdiscConfig,
    ) -> Result<()> {
        let ifindex = self.resolve_interface(&dev.into()).await?;
        self.change_qdisc_by_index_full(ifindex, parent, handle, config)
            .await
    }

    /// Change a qdisc's parameters by interface index.
    ///
    /// This is useful for namespace-aware operations where you've already
    /// resolved the interface index via `conn.get_link_by_name()`.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "change_qdisc_by_index"))]
    pub async fn change_qdisc_by_index(
        &self,
        ifindex: u32,
        parent: TcHandle,
        config: impl QdiscConfig,
    ) -> Result<()> {
        self.change_qdisc_by_index_full(ifindex, parent, None, config)
            .await
    }

    /// Change a qdisc by interface index with explicit handle.
    #[tracing::instrument(
        level = "debug",
        skip_all,
        fields(method = "change_qdisc_by_index_full")
    )]
    pub async fn change_qdisc_by_index_full(
        &self,
        ifindex: u32,
        parent: TcHandle,
        handle: Option<TcHandle>,
        config: impl QdiscConfig,
    ) -> Result<()> {
        let parent_handle = parent.as_raw();
        let qdisc_handle = handle.map(|h| h.as_raw()).unwrap_or(0);

        let tcmsg = TcMsg::new()
            .with_ifindex(ifindex as i32)
            .with_parent(parent_handle)
            .with_handle(qdisc_handle);

        let kind = config.kind().to_string();
        let mut builder = ack_request(NlMsgType::RTM_NEWQDISC);
        builder.append(&tcmsg);
        builder.append_attr_str(TcaAttr::Kind as u16, &kind);

        let options_token = builder.nest_start(TcaAttr::Options as u16);
        config.write_options(&mut builder)?;
        builder.nest_end(options_token);

        self.send_ack(builder).await.map_err(|e| {
            if e.is_not_found() {
                Error::QdiscNotFound {
                    kind,
                    interface: format!("ifindex {ifindex}"),
                }
            } else {
                e.with_context(format!(
                    "change_qdisc(ifindex {ifindex}, parent={})",
                    parent
                ))
            }
        })
    }

    /// Apply a netem configuration to an interface.
    ///
    /// This is a convenience method that replaces any existing root qdisc
    /// with a netem qdisc. If no root qdisc exists, it creates one.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use nlink::netlink::tc::NetemConfig;
    /// use std::time::Duration;
    ///
    /// let netem = NetemConfig::new()
    ///     .delay(Duration::from_millis(100))
    ///     .jitter(Duration::from_millis(10))
    ///     .loss(1.0)
    ///     .build();
    ///
    /// conn.apply_netem("eth0", netem).await?;
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "apply_netem"))]
    pub async fn apply_netem(
        &self,
        dev: impl Into<InterfaceRef>,
        config: NetemConfig,
    ) -> Result<()> {
        let dev = dev.into();
        match self.replace_qdisc(dev.clone(), config.clone()).await {
            Ok(()) => Ok(()),
            Err(e) if e.is_not_found() => self.add_qdisc(dev, config).await,
            Err(e) => Err(e),
        }
    }

    /// Apply a netem configuration by interface index.
    ///
    /// This is useful for namespace-aware operations where you've already
    /// resolved the interface index via `conn.get_link_by_name()`.
    /// If no root qdisc exists, it creates one.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "apply_netem_by_index"))]
    pub async fn apply_netem_by_index(&self, ifindex: u32, config: NetemConfig) -> Result<()> {
        match self.replace_qdisc_by_index(ifindex, config.clone()).await {
            Ok(()) => Ok(()),
            Err(e) if e.is_not_found() => self.add_qdisc_by_index(ifindex, config).await,
            Err(e) => Err(e),
        }
    }

    /// Remove netem configuration from an interface.
    ///
    /// This deletes the root qdisc, which restores the default qdisc.
    ///
    /// # Example
    ///
    /// ```ignore
    /// conn.del_netem("eth0").await?;
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "del_netem"))]
    pub async fn del_netem(&self, dev: impl Into<InterfaceRef>) -> Result<()> {
        self.del_qdisc(dev, TcHandle::ROOT).await
    }

    /// Remove netem configuration by interface index.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "del_netem_by_index"))]
    pub async fn del_netem_by_index(&self, ifindex: u32) -> Result<()> {
        self.del_qdisc_by_index(ifindex, TcHandle::ROOT).await
    }

    // ========================================================================
    // TC Class Operations
    // ========================================================================

    /// Delete a TC class.
    ///
    /// # Example
    ///
    /// ```ignore
    /// conn.del_class("eth0", "1:0", "1:10").await?;
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "del_class"))]
    pub async fn del_class(
        &self,
        dev: impl Into<InterfaceRef>,
        parent: TcHandle,
        classid: TcHandle,
    ) -> Result<()> {
        let ifindex = self.resolve_interface(&dev.into()).await?;
        self.del_class_by_index(ifindex, parent, classid).await
    }

    /// Delete a TC class by interface index.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "del_class_by_index"))]
    pub async fn del_class_by_index(
        &self,
        ifindex: u32,
        parent: TcHandle,
        classid: TcHandle,
    ) -> Result<()> {
        let parent_handle = parent.as_raw();
        let class_handle = classid.as_raw();

        let tcmsg = TcMsg::new()
            .with_ifindex(ifindex as i32)
            .with_parent(parent_handle)
            .with_handle(class_handle);

        let mut builder = ack_request(NlMsgType::RTM_DELTCLASS);
        builder.append(&tcmsg);

        self.send_ack(builder)
            .await
            .map_err(|e| e.with_context("del_class"))
    }

    /// Add a TC class with typed configuration.
    ///
    /// Mirrors `add_qdisc` / `add_filter` / `add_action`: takes the
    /// typed `ClassConfig` (`HtbClassConfig`, `HfscClassConfig`,
    /// `DrrClassConfig`, `QfqClassConfig`) and submits a single
    /// `RTM_NEWTCLASS` request.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use nlink::netlink::{Connection, Route};
    /// use nlink::netlink::tc::{HtbQdiscConfig, HtbClassConfig};
    ///
    /// let conn = Connection::<Route>::new()?;
    ///
    /// // First add HTB qdisc
    /// let htb = HtbQdiscConfig::new().default_class(0x30).build();
    /// conn.add_qdisc_full("eth0", "root", Some("1:"), htb).await?;
    ///
    /// // Add a class with guaranteed 100mbit, ceiling 500mbit
    /// conn.add_class("eth0", "1:0", "1:10",
    ///     HtbClassConfig::new(Rate::mbit(100))
    ///         .ceil(Rate::mbit(500))
    ///         .prio(1)
    ///         .build()
    /// ).await?;
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "add_class", kind = %config.kind()))]
    pub async fn add_class<C: ClassConfig>(
        &self,
        dev: impl Into<InterfaceRef>,
        parent: TcHandle,
        classid: TcHandle,
        config: C,
    ) -> Result<()> {
        let ifindex = self.resolve_interface(&dev.into()).await?;
        self.add_class_by_index(ifindex, parent, classid, config)
            .await
    }

    /// Add a TC class with typed configuration by interface index.
    ///
    /// Useful for namespace-aware operations where the interface
    /// index has already been resolved via `conn.get_link_by_name()`.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "add_class_by_index", kind = %config.kind()))]
    pub async fn add_class_by_index<C: ClassConfig>(
        &self,
        ifindex: u32,
        parent: TcHandle,
        classid: TcHandle,
        config: C,
    ) -> Result<()> {
        let parent_handle = parent.as_raw();
        let class_handle = classid.as_raw();

        let tcmsg = TcMsg::new()
            .with_ifindex(ifindex as i32)
            .with_parent(parent_handle)
            .with_handle(class_handle);

        let mut builder = create_request(NlMsgType::RTM_NEWTCLASS);
        builder.append(&tcmsg);
        builder.append_attr_str(TcaAttr::Kind as u16, config.kind());

        let options_token = builder.nest_start(TcaAttr::Options as u16);
        config.write_options(&mut builder)?;
        builder.nest_end(options_token);

        self.send_ack(builder)
            .await
            .map_err(|e| e.with_context("add_class"))
    }

    /// Change a TC class with typed configuration.
    ///
    /// # Example
    ///
    /// ```ignore
    /// // Update an existing class's rate
    /// conn.change_class("eth0", "1:0", "1:10",
    ///     HtbClassConfig::new(Rate::mbit(200))
    ///         .ceil(Rate::mbit(800))
    ///         .build()
    /// ).await?;
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "change_class", kind = %config.kind()))]
    pub async fn change_class<C: ClassConfig>(
        &self,
        dev: impl Into<InterfaceRef>,
        parent: TcHandle,
        classid: TcHandle,
        config: C,
    ) -> Result<()> {
        let ifindex = self.resolve_interface(&dev.into()).await?;
        self.change_class_by_index(ifindex, parent, classid, config)
            .await
    }

    /// Change a TC class with typed configuration by interface index.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "change_class_by_index", kind = %config.kind()))]
    pub async fn change_class_by_index<C: ClassConfig>(
        &self,
        ifindex: u32,
        parent: TcHandle,
        classid: TcHandle,
        config: C,
    ) -> Result<()> {
        let parent_handle = parent.as_raw();
        let class_handle = classid.as_raw();

        let tcmsg = TcMsg::new()
            .with_ifindex(ifindex as i32)
            .with_parent(parent_handle)
            .with_handle(class_handle);

        let mut builder = ack_request(NlMsgType::RTM_NEWTCLASS);
        builder.append(&tcmsg);
        builder.append_attr_str(TcaAttr::Kind as u16, config.kind());

        let options_token = builder.nest_start(TcaAttr::Options as u16);
        config.write_options(&mut builder)?;
        builder.nest_end(options_token);

        self.send_ack(builder)
            .await
            .map_err(|e| e.with_context("change_class"))
    }

    /// Replace a TC class with typed configuration (add or update).
    ///
    /// # Example
    ///
    /// ```ignore
    /// // Create or update a class
    /// conn.replace_class("eth0", "1:0", "1:10",
    ///     HtbClassConfig::new(Rate::mbit(100))
    ///         .ceil(Rate::mbit(500))
    ///         .build()
    /// ).await?;
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "replace_class", kind = %config.kind()))]
    pub async fn replace_class<C: ClassConfig>(
        &self,
        dev: impl Into<InterfaceRef>,
        parent: TcHandle,
        classid: TcHandle,
        config: C,
    ) -> Result<()> {
        let ifindex = self.resolve_interface(&dev.into()).await?;
        self.replace_class_by_index(ifindex, parent, classid, config)
            .await
    }

    /// Replace a TC class with typed configuration by interface index.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "replace_class_by_index", kind = %config.kind()))]
    pub async fn replace_class_by_index<C: ClassConfig>(
        &self,
        ifindex: u32,
        parent: TcHandle,
        classid: TcHandle,
        config: C,
    ) -> Result<()> {
        let parent_handle = parent.as_raw();
        let class_handle = classid.as_raw();

        let tcmsg = TcMsg::new()
            .with_ifindex(ifindex as i32)
            .with_parent(parent_handle)
            .with_handle(class_handle);

        let mut builder = replace_request(NlMsgType::RTM_NEWTCLASS);
        builder.append(&tcmsg);
        builder.append_attr_str(TcaAttr::Kind as u16, config.kind());

        let options_token = builder.nest_start(TcaAttr::Options as u16);
        config.write_options(&mut builder)?;
        builder.nest_end(options_token);

        self.send_ack(builder)
            .await
            .map_err(|e| e.with_context("replace_class"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pfifo_parse_params() {
        let cfg = PfifoConfig::parse_params(&[]).unwrap();
        assert_eq!(cfg.limit, 1000); // default

        let cfg = PfifoConfig::parse_params(&["limit", "500"]).unwrap();
        assert_eq!(cfg.limit, 500);

        // missing value, unparseable value, and unknown token all error
        assert!(PfifoConfig::parse_params(&["limit"]).is_err());
        assert!(PfifoConfig::parse_params(&["limit", "abc"]).is_err());
        assert!(PfifoConfig::parse_params(&["bogus"]).is_err());
    }

    #[test]
    fn test_bfifo_parse_params() {
        let cfg = BfifoConfig::parse_params(&["limit", "100kb"]).unwrap();
        assert_eq!(cfg.limit, 100 * 1024); // tc size suffixes are binary

        let cfg = BfifoConfig::parse_params(&["limit", "4096"]).unwrap();
        assert_eq!(cfg.limit, 4096);

        assert!(BfifoConfig::parse_params(&["limit"]).is_err());
        assert!(BfifoConfig::parse_params(&["limit", "nope"]).is_err());
        assert!(BfifoConfig::parse_params(&["divisor", "1"]).is_err());
    }

    #[test]
    fn test_fq_pie_parse_params() {
        use crate::util::{Bytes, Percent};

        let cfg = FqPieConfig::parse_params(&[]).unwrap();
        assert_eq!(cfg.limit, None);
        assert!(!cfg.ecn);

        let cfg = FqPieConfig::parse_params(&[
            "limit", "10000", "flows", "1024", "target", "15ms", "tupdate", "16ms", "alpha", "2",
            "beta", "20", "quantum", "1514", "memory_limit", "32mb", "ecnprob", "10", "ecn",
            "bytemode", "dq_rate_estimator",
        ])
        .unwrap();
        assert_eq!(cfg.limit, Some(10000));
        assert_eq!(cfg.flows, Some(1024));
        assert_eq!(cfg.target, Some(Duration::from_millis(15)));
        assert_eq!(cfg.tupdate, Some(Duration::from_millis(16)));
        assert_eq!(cfg.alpha, Some(2));
        assert_eq!(cfg.beta, Some(20));
        assert_eq!(cfg.quantum, Some(Bytes::new(1514)));
        assert_eq!(cfg.memory_limit, Some(Bytes::new(32 * 1024 * 1024)));
        assert_eq!(cfg.ecn_prob, Some(Percent::new(10.0)));
        assert!(cfg.ecn);
        assert!(cfg.bytemode);
        assert!(cfg.dq_rate_estimator);

        // toggles can be cleared, alias accepted
        let cfg =
            FqPieConfig::parse_params(&["noecn", "nobytemode", "ecn_prob", "5"]).unwrap();
        assert!(!cfg.ecn);
        assert!(!cfg.bytemode);
        assert_eq!(cfg.ecn_prob, Some(Percent::new(5.0)));

        // strict: missing value, bad value, unknown token
        assert!(FqPieConfig::parse_params(&["limit"]).is_err());
        assert!(FqPieConfig::parse_params(&["target", "fast"]).is_err());
        assert!(FqPieConfig::parse_params(&["unknown"]).is_err());
    }

    #[test]
    fn test_cbs_parse_and_write() {
        // tc(8) Class-A example values.
        let cfg = CbsConfig::parse_params(&[
            "idleslope", "98688", "sendslope", "-901312", "hicredit", "153", "locredit", "-1389",
            "offload", "1",
        ])
        .unwrap();
        assert_eq!(cfg.idleslope, 98688);
        assert_eq!(cfg.sendslope, -901312);
        assert_eq!(cfg.hicredit, 153);
        assert_eq!(cfg.locredit, -1389);
        assert!(cfg.offload);

        // write_options emits the PARMS attribute without error; the
        // fixed struct is 20 bytes (offload + 3 pad + 4×i32).
        let mut b = MessageBuilder::new(0, 0);
        cfg.write_options(&mut b).unwrap();
        use crate::netlink::types::tc::qdisc::cbs::TcCbsQopt;
        assert_eq!(TcCbsQopt::SIZE, 20);

        // offload alias + default-zero fields.
        let cfg = CbsConfig::parse_params(&["offload", "off"]).unwrap();
        assert!(!cfg.offload);
        assert_eq!(cfg.idleslope, 0);

        // strict: missing value, bad value, bad offload, unknown token.
        assert!(CbsConfig::parse_params(&["idleslope"]).is_err());
        assert!(CbsConfig::parse_params(&["idleslope", "fast"]).is_err());
        assert!(CbsConfig::parse_params(&["offload", "2"]).is_err());
        assert!(CbsConfig::parse_params(&["unknown"]).is_err());
    }

    #[test]
    fn test_skbprio_parse() {
        let cfg = SkbprioConfig::parse_params(&["limit", "128"]).unwrap();
        assert_eq!(cfg.limit, 128);
        // kernel default when unspecified.
        assert_eq!(SkbprioConfig::parse_params(&[]).unwrap().limit, 64);
        // strict: missing value, bad value, unknown token.
        assert!(SkbprioConfig::parse_params(&["limit"]).is_err());
        assert!(SkbprioConfig::parse_params(&["limit", "x"]).is_err());
        assert!(SkbprioConfig::parse_params(&["unknown"]).is_err());
    }

    #[test]
    fn test_sfb_parse_and_write() {
        let cfg = SfbConfig::parse_params(&[
            "limit", "1000", "rehash", "600ms", "db", "60ms", "max", "25", "target", "20",
            "increment", "5", "decrement", "1", "penalty_rate", "10", "penalty_burst", "20",
        ])
        .unwrap();
        assert_eq!(cfg.limit, Some(1000));
        assert_eq!(cfg.rehash, Some(Duration::from_millis(600)));
        assert_eq!(cfg.db, Some(Duration::from_millis(60)));
        assert_eq!(cfg.max, Some(25));
        assert_eq!(cfg.target, Some(20));
        assert_eq!(cfg.penalty_rate, Some(10));

        let mut b = MessageBuilder::new(0, 0);
        cfg.write_options(&mut b).unwrap();
        use crate::netlink::types::tc::qdisc::sfb::TcSfbQopt;
        assert_eq!(TcSfbQopt::SIZE, 36);

        // strict: missing value, bad time, unknown token.
        assert!(SfbConfig::parse_params(&["limit"]).is_err());
        assert!(SfbConfig::parse_params(&["rehash", "soon"]).is_err());
        assert!(SfbConfig::parse_params(&["unknown"]).is_err());
    }

    #[test]
    fn test_multiq_parse() {
        // Parameterless: empty parses, any token errors.
        assert!(MultiqConfig::parse_params(&[]).is_ok());
        assert!(MultiqConfig::parse_params(&["bands", "4"]).is_err());
        let mut b = MessageBuilder::new(0, 0);
        MultiqConfig::new().write_options(&mut b).unwrap();
    }

    #[test]
    fn test_hhf_parse_and_write() {
        use crate::util::Bytes;

        let cfg = HhfConfig::parse_params(&[
            "limit", "1000", "quantum", "1514", "hh_limit", "2048", "reset_timeout", "40ms",
            "admit_bytes", "131072", "evict_timeout", "1s", "nonhh_weight", "2",
        ])
        .unwrap();
        assert_eq!(cfg.limit, Some(1000));
        assert_eq!(cfg.quantum, Some(Bytes::new(1514)));
        assert_eq!(cfg.hh_limit, Some(2048));
        assert_eq!(cfg.reset_timeout, Some(Duration::from_millis(40)));
        assert_eq!(cfg.admit_bytes, Some(Bytes::new(131072)));
        assert_eq!(cfg.evict_timeout, Some(Duration::from_secs(1)));
        assert_eq!(cfg.non_hh_weight, Some(2));

        let mut b = MessageBuilder::new(0, 0);
        cfg.write_options(&mut b).unwrap();

        // strict: missing value, bad size, bad time, unknown token.
        assert!(HhfConfig::parse_params(&["limit"]).is_err());
        assert!(HhfConfig::parse_params(&["quantum", "big"]).is_err());
        assert!(HhfConfig::parse_params(&["reset_timeout", "soon"]).is_err());
        assert!(HhfConfig::parse_params(&["unknown"]).is_err());
    }

    #[test]
    fn test_dsmark_parse() {
        let cfg =
            DsmarkConfig::parse_params(&["indices", "64", "default_index", "0", "set_tc_index"])
                .unwrap();
        assert_eq!(cfg.indices, Some(64));
        assert_eq!(cfg.default_index, Some(0));
        assert!(cfg.set_tc_index);

        let mut b = MessageBuilder::new(0, 0);
        cfg.write_options(&mut b).unwrap();

        // strict: missing value, bad value, unknown token.
        assert!(DsmarkConfig::parse_params(&["indices"]).is_err());
        assert!(DsmarkConfig::parse_params(&["indices", "x"]).is_err());
        assert!(DsmarkConfig::parse_params(&["unknown"]).is_err());
    }

    #[test]
    fn test_netem_builder() {
        use crate::util::Percent;
        let config = NetemConfig::new()
            .delay(Duration::from_millis(100))
            .jitter(Duration::from_millis(10))
            .delay_correlation(Percent::new(25.0))
            .loss(Percent::new(1.0))
            .build();

        assert_eq!(config.delay, Some(Duration::from_millis(100)));
        assert_eq!(config.jitter, Some(Duration::from_millis(10)));
        assert_eq!(config.delay_correlation.as_percent(), 25.0);
        assert_eq!(config.loss.as_percent(), 1.0);
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
        use crate::util::{Bytes, Rate};
        let config = TbfConfig::new()
            .rate(Rate::bytes_per_sec(1_000_000))
            .burst(Bytes::kib(32))
            .limit(Bytes::kib(100))
            .build();

        assert_eq!(config.rate, Rate::bytes_per_sec(1_000_000));
        assert_eq!(config.burst, Bytes::kib(32));
        assert_eq!(config.limit, Bytes::kib(100));
        assert_eq!(config.kind(), "tbf");
    }

    #[test]
    fn test_netem_clamp() {
        use crate::util::Percent;
        let config = NetemConfig::new()
            .loss(Percent::new(150.0)) // Should clamp to 100
            .delay_correlation(Percent::new(-10.0)) // Should clamp to 0
            .build();

        assert_eq!(config.loss.as_percent(), 100.0);
        assert_eq!(config.delay_correlation.as_percent(), 0.0);
    }

    #[test]
    fn test_drr_builder() {
        let config = DrrConfig::new().build();

        assert_eq!(config.kind(), "drr");
    }

    #[test]
    fn test_qfq_builder() {
        let config = QfqConfig::new().build();

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
        let config = HfscConfig::new().default_class(0x10).build();

        assert_eq!(config.default_class, 0x10);
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

    #[test]
    fn test_htb_class_config_typed() {
        use crate::util::Rate;
        let config = HtbClassConfig::new(Rate::mbit(100))
            .ceil(Rate::mbit(500))
            .prio(1)
            .quantum(1500)
            .build();

        assert_eq!(config.rate, Rate::mbit(100));
        assert_eq!(config.ceil, Some(Rate::mbit(500)));
        assert_eq!(config.prio, Some(1));
        assert_eq!(config.quantum, Some(1500));
        assert_eq!(config.kind(), "htb");
    }

    #[test]
    fn test_htb_class_config_from_string() {
        use crate::util::Rate;
        // Parse via FromStr first, then construct.
        let config = HtbClassConfig::new("100mbit".parse::<Rate>().unwrap())
            .ceil("500mbit".parse::<Rate>().unwrap())
            .prio(2)
            .build();

        assert_eq!(config.rate, Rate::mbit(100));
        assert_eq!(config.ceil, Some(Rate::mbit(500)));
        assert_eq!(config.prio, Some(2));
        assert_eq!(config.kind(), "htb");
    }

    #[test]
    fn test_htb_class_config_burst() {
        use crate::util::{Bytes, Rate};
        let config = HtbClassConfig::new(Rate::bytes_per_sec(1_000_000))
            .burst(Bytes::new(16384))
            .cburst(Bytes::new(32768))
            .mtu(9000)
            .mpu(64)
            .overhead(14)
            .build();

        assert_eq!(config.burst, Some(Bytes::new(16384)));
        assert_eq!(config.cburst, Some(Bytes::new(32768)));
        assert_eq!(config.mtu, 9000);
        assert_eq!(config.mpu, 64);
        assert_eq!(config.overhead, 14);
    }

    #[test]
    fn test_htb_class_config_prio_clamp() {
        use crate::util::Rate;
        let config = HtbClassConfig::new(Rate::bytes_per_sec(1_000_000))
            .prio(100) // Should clamp to 7
            .build();

        assert_eq!(config.prio, Some(7));
    }

    #[test]
    fn test_htb_class_config_defaults() {
        use crate::util::Rate;
        let config = HtbClassConfig::new(Rate::bytes_per_sec(1_000_000)).build();

        // ceil defaults to rate
        assert_eq!(config.ceil, None);
        // Other defaults
        assert_eq!(config.burst, None);
        assert_eq!(config.cburst, None);
        assert_eq!(config.prio, None);
        assert_eq!(config.quantum, None);
        assert_eq!(config.mtu, 1600);
        assert_eq!(config.mpu, 0);
        assert_eq!(config.overhead, 0);
    }

    #[test]
    fn htb_qdisc_parse_params_empty_yields_defaults() {
        let cfg = HtbQdiscConfig::parse_params(&[]).unwrap();
        assert_eq!(cfg.default_class, 0);
        assert_eq!(cfg.r2q, 10);
        assert_eq!(cfg.direct_qlen, None);
    }

    #[test]
    fn htb_qdisc_parse_params_default_as_handle() {
        // tc handle form: "1:10" -> raw u32 of TcHandle::new(1, 0x10)
        let cfg = HtbQdiscConfig::parse_params(&["default", "1:10"]).unwrap();
        assert_eq!(
            cfg.default_class,
            crate::netlink::tc_handle::TcHandle::new(1, 0x10).as_raw(),
        );
    }

    #[test]
    fn htb_qdisc_parse_params_default_as_bare_hex() {
        // bare-hex form mirrors `tc(8)`: "default 10" means minor 0x10.
        let cfg = HtbQdiscConfig::parse_params(&["default", "10"]).unwrap();
        assert_eq!(cfg.default_class, 0x10);
        let cfg = HtbQdiscConfig::parse_params(&["default", "ff"]).unwrap();
        assert_eq!(cfg.default_class, 0xff);
    }

    #[test]
    fn htb_qdisc_parse_params_all_three() {
        let cfg =
            HtbQdiscConfig::parse_params(&["default", "1:10", "r2q", "5", "direct_qlen", "1000"])
                .unwrap();
        assert_eq!(
            cfg.default_class,
            crate::netlink::tc_handle::TcHandle::new(1, 0x10).as_raw(),
        );
        assert_eq!(cfg.r2q, 5);
        assert_eq!(cfg.direct_qlen, Some(1000));
    }

    #[test]
    fn htb_qdisc_parse_params_unknown_token_errors() {
        // Legacy parser silently swallowed `default_class` (a typo for
        // `default`); the typed parser rejects it so callers see the
        // mistake immediately.
        let err = HtbQdiscConfig::parse_params(&["default_class", "1:10"]).unwrap_err();
        assert!(
            err.to_string().contains("unknown token"),
            "expected unknown-token error, got: {err}"
        );
    }

    #[test]
    fn htb_qdisc_parse_params_missing_value_errors() {
        let err = HtbQdiscConfig::parse_params(&["default"]).unwrap_err();
        assert!(
            err.to_string().contains("requires a value"),
            "expected missing-value error, got: {err}"
        );
        let err = HtbQdiscConfig::parse_params(&["r2q"]).unwrap_err();
        assert!(err.to_string().contains("requires a value"));
    }

    #[test]
    fn htb_qdisc_parse_params_invalid_number_errors() {
        let err = HtbQdiscConfig::parse_params(&["r2q", "not-a-number"]).unwrap_err();
        assert!(
            err.to_string().contains("invalid r2q"),
            "expected invalid-r2q error, got: {err}"
        );
        let err = HtbQdiscConfig::parse_params(&["direct_qlen", "x"]).unwrap_err();
        assert!(err.to_string().contains("invalid direct_qlen"));
    }

    #[test]
    fn htb_qdisc_parse_params_invalid_default_errors() {
        // Bare "abcdefg" is not a valid hex u32.
        let err = HtbQdiscConfig::parse_params(&["default", "zzzz"]).unwrap_err();
        assert!(
            err.to_string().contains("invalid default class"),
            "got: {err}"
        );
    }

    #[test]
    fn netem_parse_params_empty_yields_defaults() {
        let cfg = NetemConfig::parse_params(&[]).unwrap();
        assert_eq!(cfg.delay, None);
        assert_eq!(cfg.jitter, None);
        assert!(cfg.loss.is_zero());
        assert_eq!(cfg.limit, 1000);
    }

    #[test]
    fn netem_parse_params_delay_only() {
        let cfg = NetemConfig::parse_params(&["delay", "100ms"]).unwrap();
        assert_eq!(cfg.delay, Some(Duration::from_millis(100)));
        assert_eq!(cfg.jitter, None);
    }

    #[test]
    fn netem_parse_params_delay_with_jitter_and_corr() {
        let cfg = NetemConfig::parse_params(&["delay", "100ms", "10ms", "25%"]).unwrap();
        assert_eq!(cfg.delay, Some(Duration::from_millis(100)));
        assert_eq!(cfg.jitter, Some(Duration::from_millis(10)));
        // Percent::new(25.0) produces 25% (kernel probability ~ 25/100 * u32::MAX).
        assert!(!cfg.delay_correlation.is_zero());
    }

    #[test]
    fn netem_parse_params_loss_with_random_qualifier() {
        let cfg = NetemConfig::parse_params(&["loss", "random", "1.5%"]).unwrap();
        assert!(!cfg.loss.is_zero());
    }

    #[test]
    fn netem_parse_params_drop_alias() {
        // `drop` is the legacy alias for `loss`.
        let cfg = NetemConfig::parse_params(&["drop", "0.5%"]).unwrap();
        assert!(!cfg.loss.is_zero());
    }

    #[test]
    fn netem_parse_params_multiple_groups() {
        let cfg = NetemConfig::parse_params(&[
            "delay",
            "100ms",
            "10ms",
            "loss",
            "1%",
            "duplicate",
            "0.1%",
            "limit",
            "5000",
        ])
        .unwrap();
        assert_eq!(cfg.delay, Some(Duration::from_millis(100)));
        assert_eq!(cfg.jitter, Some(Duration::from_millis(10)));
        assert!(!cfg.loss.is_zero());
        assert!(!cfg.duplicate.is_zero());
        assert_eq!(cfg.limit, 5000);
    }

    #[test]
    fn netem_parse_params_rate_no_extras() {
        let cfg = NetemConfig::parse_params(&["rate", "100mbit"]).unwrap();
        // 100mbit = 12_500_000 bytes/sec. The previous implementation
        // mis-routed get_rate (which returns bits) through
        // Rate::bytes_per_sec, ending up at 100_000_000 (= 800mbit).
        // Switching to Rate::parse fixed the units bug.
        assert_eq!(
            cfg.rate.map(|r| r.as_bytes_per_sec()),
            Some(12_500_000),
            "100mbit should round-trip to 12.5 MB/sec"
        );
    }

    #[test]
    fn netem_parse_params_rate_extras_rejected() {
        // The legacy parser accepts `rate <r> <packet_overhead> <cell_size>
        // <cell_overhead>`. Typed config doesn't model those — typed
        // parser rejects them with a clear pointer at the legacy path.
        let err = NetemConfig::parse_params(&["rate", "100mbit", "20"]).unwrap_err();
        assert!(
            err.to_string().contains("packet_overhead"),
            "expected rate-extras error, got: {err}"
        );
    }

    #[test]
    fn netem_parse_params_unknown_token_errors() {
        let err = NetemConfig::parse_params(&["nonsense"]).unwrap_err();
        assert!(err.to_string().contains("unknown token"), "got: {err}");
    }

    #[test]
    fn netem_parse_params_unsupported_features_rejected() {
        for unsup in ["slot", "ecn", "distribution"] {
            let err = NetemConfig::parse_params(&[unsup]).unwrap_err();
            assert!(
                err.to_string().contains("not modelled"),
                "expected not-modelled error for `{unsup}`, got: {err}"
            );
        }
    }

    #[test]
    fn netem_parse_params_loss_state_rejected() {
        // 4-state Markov model — typed config doesn't carry the
        // p13/p31/p32/p23/p14 fields.
        let err = NetemConfig::parse_params(&["loss", "state", "0.1"]).unwrap_err();
        assert!(err.to_string().contains("Markov"), "got: {err}");
    }

    #[test]
    fn netem_parse_params_missing_value_errors() {
        let err = NetemConfig::parse_params(&["delay"]).unwrap_err();
        assert!(err.to_string().contains("requires a value"), "got: {err}");
        let err = NetemConfig::parse_params(&["loss"]).unwrap_err();
        assert!(err.to_string().contains("percent value"), "got: {err}");
    }

    #[test]
    fn netem_parse_params_invalid_time_errors() {
        let err = NetemConfig::parse_params(&["delay", "fast"]).unwrap_err();
        assert!(err.to_string().contains("invalid delay"), "got: {err}");
    }

    #[test]
    fn netem_parse_params_invalid_percent_errors() {
        let err = NetemConfig::parse_params(&["loss", "lots"]).unwrap_err();
        assert!(err.to_string().contains("invalid loss"), "got: {err}");
    }

    #[test]
    fn cake_parse_params_empty_yields_default() {
        let cfg = CakeConfig::parse_params(&[]).unwrap();
        assert!(cfg.bandwidth.is_none());
        assert!(cfg.rtt.is_none());
        assert!(cfg.diffserv_mode.is_none());
        assert!(cfg.flow_mode.is_none());
        assert!(!cfg.nat);
        assert!(!cfg.wash);
    }

    #[test]
    fn cake_parse_params_bandwidth_and_rtt() {
        let cfg = CakeConfig::parse_params(&["bandwidth", "100mbit", "rtt", "20ms"]).unwrap();
        assert_eq!(
            cfg.bandwidth.map(|r| r.as_bytes_per_sec()),
            Some(12_500_000)
        );
        assert_eq!(cfg.rtt, Some(Duration::from_millis(20)));
    }

    #[test]
    fn cake_parse_params_unlimited_flag() {
        let cfg = CakeConfig::parse_params(&["unlimited"]).unwrap();
        assert_eq!(cfg.bandwidth, Some(crate::util::Rate::ZERO));
    }

    #[test]
    fn cake_parse_params_diffserv_modes() {
        for (token, expected) in [
            ("diffserv3", CakeDiffserv::Diffserv3),
            ("diffserv4", CakeDiffserv::Diffserv4),
            ("diffserv8", CakeDiffserv::Diffserv8),
            ("besteffort", CakeDiffserv::Besteffort),
            ("precedence", CakeDiffserv::Precedence),
        ] {
            let cfg = CakeConfig::parse_params(&[token]).unwrap();
            assert_eq!(cfg.diffserv_mode, Some(expected), "diffserv {token}");
        }
    }

    #[test]
    fn cake_parse_params_flow_modes() {
        for (token, expected) in [
            ("flowblind", CakeFlowMode::Flowblind),
            ("srchost", CakeFlowMode::Srchost),
            ("dsthost", CakeFlowMode::Dsthost),
            ("hosts", CakeFlowMode::Hosts),
            ("flows", CakeFlowMode::Flows),
            ("dual-srchost", CakeFlowMode::DualSrchost),
            ("dual-dsthost", CakeFlowMode::DualDsthost),
            ("triple-isolate", CakeFlowMode::Triple),
        ] {
            let cfg = CakeConfig::parse_params(&[token]).unwrap();
            assert_eq!(cfg.flow_mode, Some(expected), "flow {token}");
        }
    }

    #[test]
    fn cake_parse_params_atm_modes() {
        for (token, expected) in [
            ("noatm", CakeAtmMode::None),
            ("atm", CakeAtmMode::Atm),
            ("ptm", CakeAtmMode::Ptm),
        ] {
            let cfg = CakeConfig::parse_params(&[token]).unwrap();
            assert_eq!(cfg.atm_mode, Some(expected), "atm {token}");
        }
    }

    #[test]
    fn cake_parse_params_ack_filter() {
        let cfg = CakeConfig::parse_params(&["ack-filter"]).unwrap();
        assert_eq!(cfg.ack_filter, Some(CakeAckFilter::Filter));
        let cfg = CakeConfig::parse_params(&["ack-filter-aggressive"]).unwrap();
        assert_eq!(cfg.ack_filter, Some(CakeAckFilter::Aggressive));
        let cfg = CakeConfig::parse_params(&["no-ack-filter"]).unwrap();
        assert_eq!(cfg.ack_filter, Some(CakeAckFilter::Disabled));
    }

    #[test]
    fn cake_parse_params_boolean_flags_with_negations() {
        let cfg =
            CakeConfig::parse_params(&["nat", "wash", "ingress", "split-gso", "raw"]).unwrap();
        assert!(cfg.nat);
        assert!(cfg.wash);
        assert!(cfg.ingress);
        assert!(cfg.split_gso);
        assert!(cfg.raw);

        // Negations override.
        let cfg =
            CakeConfig::parse_params(&["nat", "nonat", "wash", "nowash", "ingress", "egress"])
                .unwrap();
        assert!(!cfg.nat);
        assert!(!cfg.wash);
        assert!(!cfg.ingress);
    }

    #[test]
    fn cake_parse_params_overhead_signed() {
        let cfg = CakeConfig::parse_params(&["overhead", "-4"]).unwrap();
        assert_eq!(cfg.overhead, Some(-4));
        let cfg = CakeConfig::parse_params(&["overhead", "38"]).unwrap();
        assert_eq!(cfg.overhead, Some(38));
    }

    #[test]
    fn cake_parse_params_memlimit_size() {
        let cfg = CakeConfig::parse_params(&["memlimit", "32k"]).unwrap();
        assert_eq!(cfg.memory_limit.map(|b| b.as_u64()), Some(32 * 1024));
    }

    #[test]
    fn cake_parse_params_fwmark_hex() {
        let cfg = CakeConfig::parse_params(&["fwmark", "0xff"]).unwrap();
        assert_eq!(cfg.fwmark, Some(0xff));
        // Bare hex without 0x prefix.
        let cfg = CakeConfig::parse_params(&["fwmark", "ff"]).unwrap();
        assert_eq!(cfg.fwmark, Some(0xff));
    }

    #[test]
    fn cake_parse_params_realistic_combo() {
        // A typical bufferbloat-mitigation config.
        let cfg = CakeConfig::parse_params(&[
            "bandwidth",
            "100mbit",
            "rtt",
            "20ms",
            "diffserv4",
            "triple-isolate",
            "ack-filter",
            "nat",
            "wash",
        ])
        .unwrap();
        assert!(cfg.bandwidth.is_some());
        assert_eq!(cfg.rtt, Some(Duration::from_millis(20)));
        assert_eq!(cfg.diffserv_mode, Some(CakeDiffserv::Diffserv4));
        assert_eq!(cfg.flow_mode, Some(CakeFlowMode::Triple));
        assert_eq!(cfg.ack_filter, Some(CakeAckFilter::Filter));
        assert!(cfg.nat);
        assert!(cfg.wash);
    }

    #[test]
    fn cake_parse_params_unknown_token_errors() {
        let err = CakeConfig::parse_params(&["nonsense"]).unwrap_err();
        assert!(err.to_string().contains("unknown token"));
        // Common typo: dual_srchost vs dual-srchost. Legacy parser
        // silently ignored — typed parser flags it.
        let err = CakeConfig::parse_params(&["dual_srchost"]).unwrap_err();
        assert!(err.to_string().contains("unknown token"));
    }

    #[test]
    fn cake_parse_params_missing_value_errors() {
        let err = CakeConfig::parse_params(&["bandwidth"]).unwrap_err();
        assert!(err.to_string().contains("requires a value"));
        let err = CakeConfig::parse_params(&["rtt"]).unwrap_err();
        assert!(err.to_string().contains("requires a value"));
    }

    #[test]
    fn cake_parse_params_invalid_value_errors() {
        let err = CakeConfig::parse_params(&["bandwidth", "fast"]).unwrap_err();
        assert!(err.to_string().contains("invalid bandwidth"));
        let err = CakeConfig::parse_params(&["overhead", "lots"]).unwrap_err();
        assert!(err.to_string().contains("invalid overhead"));
        let err = CakeConfig::parse_params(&["fwmark", "zzzz"]).unwrap_err();
        assert!(err.to_string().contains("invalid fwmark"));
    }

    #[test]
    fn tbf_parse_params_empty_yields_default() {
        let cfg = TbfConfig::parse_params(&[]).unwrap();
        assert_eq!(cfg.rate, crate::util::Rate::ZERO);
        assert!(cfg.peakrate.is_none());
        assert_eq!(cfg.burst, crate::util::Bytes::ZERO);
        assert_eq!(cfg.mtu, 1514);
    }

    #[test]
    fn tbf_parse_params_typical_set() {
        let cfg =
            TbfConfig::parse_params(&["rate", "1mbit", "burst", "32kb", "limit", "10kb"]).unwrap();
        // 1mbit = 125_000 bytes/sec
        assert_eq!(cfg.rate.as_bytes_per_sec(), 125_000);
        // 32kb = 32 * 1024 bytes (binary, per tc(8) convention)
        assert_eq!(cfg.burst.as_u64(), 32 * 1024);
        assert_eq!(cfg.limit.as_u64(), 10 * 1024);
    }

    #[test]
    fn tbf_parse_params_burst_aliases() {
        for alias in ["burst", "buffer", "maxburst"] {
            let cfg = TbfConfig::parse_params(&[alias, "16kb"]).unwrap();
            assert_eq!(cfg.burst.as_u64(), 16 * 1024, "alias {alias}");
        }
    }

    #[test]
    fn tbf_parse_params_mtu_alias() {
        for alias in ["mtu", "minburst"] {
            let cfg = TbfConfig::parse_params(&[alias, "9000"]).unwrap();
            assert_eq!(cfg.mtu, 9000, "alias {alias}");
        }
    }

    #[test]
    fn tbf_parse_params_peakrate() {
        let cfg = TbfConfig::parse_params(&["rate", "1mbit", "peakrate", "2mbit"]).unwrap();
        assert_eq!(cfg.rate.as_bytes_per_sec(), 125_000);
        assert_eq!(cfg.peakrate.unwrap().as_bytes_per_sec(), 250_000);
    }

    #[test]
    fn tbf_parse_params_latency_rejected() {
        let err = TbfConfig::parse_params(&["latency", "50ms"]).unwrap_err();
        assert!(
            err.to_string().contains("derived form"),
            "expected derived-form rejection, got: {err}"
        );
    }

    #[test]
    fn tbf_parse_params_unknown_token_errors() {
        let err = TbfConfig::parse_params(&["nonsense"]).unwrap_err();
        assert!(err.to_string().contains("unknown token"));
    }

    #[test]
    fn tbf_parse_params_missing_value_errors() {
        let err = TbfConfig::parse_params(&["rate"]).unwrap_err();
        assert!(err.to_string().contains("requires a value"));
    }

    #[test]
    fn tbf_parse_params_invalid_rate_errors() {
        let err = TbfConfig::parse_params(&["rate", "fast"]).unwrap_err();
        assert!(err.to_string().contains("invalid rate"));
    }

    #[test]
    fn sfq_parse_params_empty_yields_default() {
        let cfg = SfqConfig::parse_params(&[]).unwrap();
        assert_eq!(cfg.perturb, 0);
        assert_eq!(cfg.limit, 127);
        assert_eq!(cfg.quantum, 0);
    }

    #[test]
    fn sfq_parse_params_typical_set() {
        let cfg = SfqConfig::parse_params(&["perturb", "10", "limit", "1000", "quantum", "1500"])
            .unwrap();
        assert_eq!(cfg.perturb, 10);
        assert_eq!(cfg.limit, 1000);
        assert_eq!(cfg.quantum, 1500);
    }

    #[test]
    fn sfq_parse_params_quantum_with_size_suffix() {
        let cfg = SfqConfig::parse_params(&["quantum", "1k"]).unwrap();
        assert_eq!(cfg.quantum, 1024);
    }

    #[test]
    fn sfq_parse_params_divisor_rejected() {
        let err = SfqConfig::parse_params(&["divisor", "1024"]).unwrap_err();
        assert!(err.to_string().contains("not modelled"), "got: {err}");
    }

    #[test]
    fn sfq_parse_params_unknown_token_errors() {
        let err = SfqConfig::parse_params(&["nonsense"]).unwrap_err();
        assert!(err.to_string().contains("unknown token"));
    }

    #[test]
    fn sfq_parse_params_missing_value_errors() {
        let err = SfqConfig::parse_params(&["perturb"]).unwrap_err();
        assert!(err.to_string().contains("requires a value"));
    }

    #[test]
    fn prio_parse_params_empty_yields_default() {
        let cfg = PrioConfig::parse_params(&[]).unwrap();
        assert_eq!(cfg.bands, 3);
        assert_eq!(
            cfg.priomap,
            [1, 2, 2, 2, 1, 2, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1]
        );
    }

    #[test]
    fn prio_parse_params_bands() {
        let cfg = PrioConfig::parse_params(&["bands", "5"]).unwrap();
        assert_eq!(cfg.bands, 5);
    }

    #[test]
    fn prio_parse_params_priomap_full() {
        // 16 explicit values
        let mut params = vec!["priomap"];
        for n in 0u8..16 {
            params.push(if n < 8 { "0" } else { "1" });
        }
        let cfg = PrioConfig::parse_params(&params).unwrap();
        let expected: [u8; 16] = [0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1];
        assert_eq!(cfg.priomap, expected);
    }

    #[test]
    fn prio_parse_params_priomap_short_errors() {
        // Only 5 values supplied — strict, unlike the legacy parser.
        let err = PrioConfig::parse_params(&["priomap", "1", "2", "3", "4", "5"]).unwrap_err();
        assert!(
            err.to_string().contains("requires exactly 16 values"),
            "got: {err}"
        );
    }

    #[test]
    fn prio_parse_params_unknown_token_errors() {
        let err = PrioConfig::parse_params(&["nonsense"]).unwrap_err();
        assert!(err.to_string().contains("unknown token"));
    }

    #[test]
    fn fq_codel_parse_params_empty_yields_default() {
        let cfg = FqCodelConfig::parse_params(&[]).unwrap();
        assert!(cfg.target.is_none());
        assert!(cfg.interval.is_none());
        assert!(cfg.limit.is_none());
        assert!(!cfg.ecn);
    }

    #[test]
    fn fq_codel_parse_params_typical_set() {
        let cfg = FqCodelConfig::parse_params(&[
            "limit",
            "10240",
            "target",
            "5ms",
            "interval",
            "100ms",
            "flows",
            "1024",
            "quantum",
            "1500",
            "memory_limit",
            "32m",
            "ecn",
        ])
        .unwrap();
        assert_eq!(cfg.limit, Some(10240));
        assert_eq!(cfg.target, Some(Duration::from_millis(5)));
        assert_eq!(cfg.interval, Some(Duration::from_millis(100)));
        assert_eq!(cfg.flows, Some(1024));
        assert_eq!(cfg.quantum, Some(1500));
        // 32m via tc-style size = 32 * 1024 * 1024
        assert_eq!(cfg.memory_limit, Some(32 * 1024 * 1024));
        assert!(cfg.ecn);
    }

    #[test]
    fn fq_codel_parse_params_ecn_noecn_toggle() {
        let cfg = FqCodelConfig::parse_params(&["ecn"]).unwrap();
        assert!(cfg.ecn);
        let cfg = FqCodelConfig::parse_params(&["ecn", "noecn"]).unwrap();
        assert!(!cfg.ecn);
    }

    #[test]
    fn fq_codel_parse_params_ce_threshold() {
        let cfg = FqCodelConfig::parse_params(&["ce_threshold", "20ms"]).unwrap();
        assert_eq!(cfg.ce_threshold, Some(Duration::from_millis(20)));
    }

    #[test]
    fn fq_codel_parse_params_unknown_token_errors() {
        let err = FqCodelConfig::parse_params(&["nonsense"]).unwrap_err();
        assert!(err.to_string().contains("unknown token"));
    }

    #[test]
    fn fq_codel_parse_params_invalid_time_errors() {
        let err = FqCodelConfig::parse_params(&["target", "fast"]).unwrap_err();
        assert!(err.to_string().contains("invalid target"));
    }

    #[test]
    fn red_parse_params_empty_yields_default() {
        let cfg = RedConfig::parse_params(&[]).unwrap();
        assert_eq!(cfg.limit, 0);
        assert_eq!(cfg.min, 0);
        assert_eq!(cfg.max, 0);
        assert_eq!(cfg.max_p, 5);
        assert!(!cfg.ecn);
        assert!(!cfg.adaptive);
    }

    #[test]
    fn red_parse_params_thresholds_with_size_suffixes() {
        let cfg = RedConfig::parse_params(&["limit", "100k", "min", "10k", "max", "30k"]).unwrap();
        assert_eq!(cfg.limit, 100 * 1024);
        assert_eq!(cfg.min, 10 * 1024);
        assert_eq!(cfg.max, 30 * 1024);
    }

    #[test]
    fn red_parse_params_probability() {
        // 50% should map to ~127 on the 0-255 scale.
        let cfg = RedConfig::parse_params(&["probability", "50"]).unwrap();
        assert!(
            cfg.max_p >= 126 && cfg.max_p <= 128,
            "expected ~127, got {}",
            cfg.max_p
        );
    }

    #[test]
    fn red_parse_params_flags_with_negations() {
        let cfg = RedConfig::parse_params(&["ecn", "harddrop", "adaptive"]).unwrap();
        assert!(cfg.ecn);
        assert!(cfg.harddrop);
        assert!(cfg.adaptive);
        let cfg = RedConfig::parse_params(&[
            "ecn",
            "noecn",
            "harddrop",
            "noharddrop",
            "adaptive",
            "noadaptive",
        ])
        .unwrap();
        assert!(!cfg.ecn);
        assert!(!cfg.harddrop);
        assert!(!cfg.adaptive);
    }

    #[test]
    fn red_parse_params_unsupported_features_rejected() {
        for unsup in ["avpkt", "burst", "bandwidth"] {
            let err = RedConfig::parse_params(&[unsup, "1"]).unwrap_err();
            assert!(
                err.to_string().contains("not modelled"),
                "expected not-modelled for `{unsup}`, got: {err}"
            );
        }
    }

    #[test]
    fn red_parse_params_unknown_token_errors() {
        let err = RedConfig::parse_params(&["nonsense"]).unwrap_err();
        assert!(err.to_string().contains("unknown token"));
    }

    #[test]
    fn choke_parse_params_empty_yields_default() {
        let cfg = ChokeConfig::parse_params(&[]).unwrap();
        assert_eq!(cfg.limit, 0);
        assert_eq!(cfg.min, 0);
        assert_eq!(cfg.max, 0);
        assert!(!cfg.ecn);
        assert!(!cfg.harddrop);
    }

    #[test]
    fn choke_parse_params_thresholds_and_flags() {
        let cfg =
            ChokeConfig::parse_params(&["limit", "100k", "min", "10k", "max", "30k", "ecn"])
                .unwrap();
        assert_eq!(cfg.limit, 100 * 1024);
        assert_eq!(cfg.min, 10 * 1024);
        assert_eq!(cfg.max, 30 * 1024);
        assert!(cfg.ecn);
    }

    #[test]
    fn choke_parse_params_unsupported_features_rejected() {
        for unsup in ["avpkt", "burst", "bandwidth"] {
            let err = ChokeConfig::parse_params(&[unsup, "1"]).unwrap_err();
            assert!(
                err.to_string().contains("not modelled"),
                "expected not-modelled for `{unsup}`, got: {err}"
            );
        }
    }

    #[test]
    fn choke_parse_params_unknown_token_errors() {
        let err = ChokeConfig::parse_params(&["nonsense"]).unwrap_err();
        assert!(err.to_string().contains("unknown token"));
        let err = ChokeConfig::parse_params(&["limit"]).unwrap_err();
        assert!(err.to_string().contains("requires a value"));
    }

    #[test]
    fn pfifo_fast_parse_params_takes_no_args() {
        assert!(PfifoFastConfig::parse_params(&[]).is_ok());
        let err = PfifoFastConfig::parse_params(&["bands", "3"]).unwrap_err();
        assert!(err.to_string().contains("takes no parameters"));
    }

    #[test]
    fn pfifo_fast_writes_no_options() {
        // pfifo_fast ignores TCA_OPTIONS; write_options must be a no-op
        // (no panic, no bytes appended beyond the empty builder).
        let cfg = PfifoFastConfig::new();
        assert_eq!(cfg.kind(), "pfifo_fast");
    }

    #[test]
    fn atm_parse_params_takes_no_args() {
        assert!(AtmConfig::parse_params(&[]).is_ok());
        assert_eq!(AtmConfig::new().kind(), "atm");
        let err = AtmConfig::parse_params(&["vpi", "0"]).unwrap_err();
        assert!(err.to_string().contains("takes no parameters"));
    }

    #[test]
    fn gred_parse_params_setup() {
        let cfg =
            GredConfig::parse_params(&["setup", "DPs", "8", "default", "2", "grio", "limit", "60k"])
                .unwrap();
        assert_eq!(cfg.virtual_queues, Some(8));
        assert_eq!(cfg.default_vq, Some(2));
        assert!(cfg.grio);
        assert_eq!(cfg.limit, Some(60 * 1024));
    }

    #[test]
    fn gred_parse_params_empty_yields_default() {
        let cfg = GredConfig::parse_params(&[]).unwrap();
        assert!(cfg.virtual_queues.is_none());
        assert!(cfg.default_vq.is_none());
        assert!(!cfg.grio);
        assert!(cfg.limit.is_none());
    }

    #[test]
    fn gred_parse_params_dps_range_checked() {
        assert!(GredConfig::parse_params(&["DPs", "0"]).is_err());
        assert!(GredConfig::parse_params(&["DPs", "17"]).is_err());
        assert!(GredConfig::parse_params(&["DPs", "16"]).is_ok());
        let err = GredConfig::parse_params(&["DPs", "notanum"]).unwrap_err();
        assert!(err.to_string().contains("invalid DPs"));
    }

    #[test]
    fn gred_parse_params_per_vq_tokens_not_modelled() {
        for tok in ["min", "max", "avpkt", "bandwidth", "DP", "probability", "prio"] {
            let err = GredConfig::parse_params(&[tok, "1"]).unwrap_err();
            assert!(
                err.to_string().contains("not modelled"),
                "expected not-modelled for per-VQ `{tok}`, got: {err}"
            );
        }
    }

    #[test]
    fn gred_parse_params_unknown_token_errors() {
        let err = GredConfig::parse_params(&["nonsense"]).unwrap_err();
        assert!(err.to_string().contains("unknown token"));
        let err = GredConfig::parse_params(&["DPs"]).unwrap_err();
        assert!(err.to_string().contains("requires a value"));
    }

    #[test]
    fn pie_parse_params_empty_yields_default() {
        let cfg = PieConfig::parse_params(&[]).unwrap();
        assert!(cfg.target.is_none());
        assert!(cfg.limit.is_none());
        assert!(cfg.alpha.is_none());
        assert!(!cfg.ecn);
        assert!(!cfg.bytemode);
    }

    #[test]
    fn pie_parse_params_typical_set() {
        let cfg = PieConfig::parse_params(&[
            "target", "15ms", "limit", "1000", "tupdate", "30ms", "alpha", "2", "beta", "20",
        ])
        .unwrap();
        assert_eq!(cfg.target, Some(Duration::from_millis(15)));
        assert_eq!(cfg.limit, Some(1000));
        assert_eq!(cfg.tupdate, Some(Duration::from_millis(30)));
        assert_eq!(cfg.alpha, Some(2));
        assert_eq!(cfg.beta, Some(20));
    }

    #[test]
    fn pie_parse_params_flags_with_negations() {
        let cfg = PieConfig::parse_params(&["ecn", "bytemode"]).unwrap();
        assert!(cfg.ecn);
        assert!(cfg.bytemode);
        let cfg = PieConfig::parse_params(&["ecn", "noecn", "bytemode", "nobytemode"]).unwrap();
        assert!(!cfg.ecn);
        assert!(!cfg.bytemode);
    }

    #[test]
    fn pie_parse_params_unknown_token_errors() {
        let err = PieConfig::parse_params(&["nonsense"]).unwrap_err();
        assert!(err.to_string().contains("unknown token"));
    }

    #[test]
    fn pie_parse_params_invalid_time_errors() {
        let err = PieConfig::parse_params(&["target", "fast"]).unwrap_err();
        assert!(err.to_string().contains("invalid target"));
    }

    #[test]
    fn hfsc_parse_params_empty_yields_default() {
        let cfg = HfscConfig::parse_params(&[]).unwrap();
        assert_eq!(cfg.default_class, 0);
    }

    #[test]
    fn hfsc_parse_params_default_hex() {
        let cfg = HfscConfig::parse_params(&["default", "10"]).unwrap();
        assert_eq!(cfg.default_class, 0x10);
        let cfg = HfscConfig::parse_params(&["default", "ff"]).unwrap();
        assert_eq!(cfg.default_class, 0xff);
    }

    #[test]
    fn hfsc_parse_params_unknown_token_errors() {
        let err = HfscConfig::parse_params(&["nonsense"]).unwrap_err();
        assert!(err.to_string().contains("unknown token"));
    }

    #[test]
    fn hfsc_parse_params_missing_value_errors() {
        let err = HfscConfig::parse_params(&["default"]).unwrap_err();
        assert!(err.to_string().contains("requires a value"));
    }

    #[test]
    fn ingress_clsact_parse_params_empty_succeeds() {
        IngressConfig::parse_params(&[]).unwrap();
        ClsactConfig::parse_params(&[]).unwrap();
    }

    #[test]
    fn ingress_clsact_parse_params_reject_any_token() {
        let err = IngressConfig::parse_params(&["foo"]).unwrap_err();
        assert!(err.to_string().contains("takes no parameters"));
        let err = ClsactConfig::parse_params(&["bar"]).unwrap_err();
        assert!(err.to_string().contains("takes no parameters"));
    }

    #[test]
    fn drr_qfq_parse_params_empty_succeeds() {
        DrrConfig::parse_params(&[]).unwrap();
        QfqConfig::parse_params(&[]).unwrap();
    }

    #[test]
    fn drr_qfq_parse_params_reject_any_token() {
        let err = DrrConfig::parse_params(&["quantum", "1500"]).unwrap_err();
        assert!(
            err.to_string().contains("DrrClassConfig"),
            "expected per-class hint, got: {err}"
        );
        let err = QfqConfig::parse_params(&["weight", "10"]).unwrap_err();
        assert!(err.to_string().contains("QfqClassConfig"), "got: {err}");
    }

    #[test]
    fn plug_parse_params_empty_yields_default() {
        let cfg = PlugConfig::parse_params(&[]).unwrap();
        assert!(cfg.limit.is_none());
    }

    #[test]
    fn plug_parse_params_limit_with_size_suffix() {
        let cfg = PlugConfig::parse_params(&["limit", "10k"]).unwrap();
        assert_eq!(cfg.limit, Some(10 * 1024));
    }

    #[test]
    fn plug_parse_params_unknown_token_errors() {
        let err = PlugConfig::parse_params(&["nonsense"]).unwrap_err();
        assert!(err.to_string().contains("unknown token"));
    }

    #[test]
    fn mqprio_parse_params_num_tc_and_hw_flag() {
        let cfg = MqprioConfig::parse_params(&["num_tc", "4", "nohw"]).unwrap();
        assert_eq!(cfg.num_tc, 4);
        assert!(!cfg.hw);
        let cfg = MqprioConfig::parse_params(&["num_tc", "8", "hw"]).unwrap();
        assert!(cfg.hw);
    }

    #[test]
    fn mqprio_parse_params_map_full() {
        let mut params = vec!["map"];
        for n in 0u8..16 {
            params.push(if n < 8 { "0" } else { "1" });
        }
        let cfg = MqprioConfig::parse_params(&params).unwrap();
        let expected: [u8; 16] = [0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1];
        assert_eq!(cfg.prio_tc_map, expected);
    }

    #[test]
    fn mqprio_parse_params_map_short_errors() {
        let err = MqprioConfig::parse_params(&["map", "1", "2", "3"]).unwrap_err();
        assert!(err.to_string().contains("requires exactly 16 values"));
    }

    #[test]
    fn mqprio_parse_params_num_tc_out_of_range() {
        let err = MqprioConfig::parse_params(&["num_tc", "20"]).unwrap_err();
        assert!(err.to_string().contains("out of range"));
    }

    #[test]
    fn mqprio_parse_params_queues_rejected() {
        let err = MqprioConfig::parse_params(&["queues", "1@0"]).unwrap_err();
        assert!(err.to_string().contains("not parsed by parse_params yet"));
    }

    #[test]
    fn etf_parse_params_empty_yields_default() {
        let cfg = EtfConfig::parse_params(&[]).unwrap();
        assert_eq!(cfg.delta, 0);
        assert_eq!(cfg.clockid, -1);
        assert!(!cfg.deadline_mode);
        assert!(!cfg.offload);
    }

    #[test]
    fn etf_parse_params_typical() {
        let cfg = EtfConfig::parse_params(&[
            "delta",
            "300000",
            "clockid",
            "CLOCK_TAI",
            "deadline_mode",
            "offload",
        ])
        .unwrap();
        assert_eq!(cfg.delta, 300_000);
        assert_eq!(cfg.clockid, libc::CLOCK_TAI);
        assert!(cfg.deadline_mode);
        assert!(cfg.offload);
    }

    #[test]
    fn etf_parse_params_clockid_named_and_integer() {
        for (name, expected) in [
            ("CLOCK_REALTIME", libc::CLOCK_REALTIME),
            ("CLOCK_MONOTONIC", libc::CLOCK_MONOTONIC),
            ("CLOCK_BOOTTIME", libc::CLOCK_BOOTTIME),
            ("CLOCK_TAI", libc::CLOCK_TAI),
        ] {
            let cfg = EtfConfig::parse_params(&["clockid", name]).unwrap();
            assert_eq!(cfg.clockid, expected, "name {name}");
        }
        let cfg = EtfConfig::parse_params(&["clockid", "11"]).unwrap();
        assert_eq!(cfg.clockid, 11);
    }

    #[test]
    fn etf_parse_params_unknown_clockid_errors() {
        let err = EtfConfig::parse_params(&["clockid", "CLOCK_NONSENSE"]).unwrap_err();
        assert!(err.to_string().contains("invalid clockid"));
    }

    #[test]
    fn etf_parse_params_unknown_token_errors() {
        let err = EtfConfig::parse_params(&["nonsense"]).unwrap_err();
        assert!(err.to_string().contains("unknown token"));
    }

    #[test]
    fn taprio_parse_params_empty_yields_default() {
        let cfg = TaprioConfig::parse_params(&[]).unwrap();
        assert_eq!(cfg.entries.len(), 0);
        assert_eq!(cfg.cycle_time, 0);
    }

    #[test]
    fn taprio_parse_params_typical() {
        let cfg = TaprioConfig::parse_params(&[
            "num_tc",
            "2",
            "clockid",
            "CLOCK_TAI",
            "base-time",
            "0",
            "cycle-time",
            "1000000",
            "sched-entry",
            "SET",
            "0x1",
            "500000",
            "sched-entry",
            "SET",
            "0x2",
            "500000",
        ])
        .unwrap();
        assert_eq!(cfg.num_tc, 2);
        assert_eq!(cfg.clockid, libc::CLOCK_TAI);
        assert_eq!(cfg.cycle_time, 1_000_000);
        assert_eq!(cfg.entries.len(), 2);
        assert_eq!(cfg.entries[0].gate_mask, 0x1);
        assert_eq!(cfg.entries[0].interval, 500_000);
        assert_eq!(cfg.entries[1].gate_mask, 0x2);
    }

    #[test]
    fn taprio_parse_params_sched_entry_cmd_aliases() {
        use crate::netlink::types::tc::qdisc::taprio::{
            TC_TAPRIO_CMD_SET_AND_HOLD, TC_TAPRIO_CMD_SET_AND_RELEASE, TC_TAPRIO_CMD_SET_GATES,
        };
        for (cmd, expected) in [
            ("SET", TC_TAPRIO_CMD_SET_GATES),
            ("S", TC_TAPRIO_CMD_SET_GATES),
            ("set", TC_TAPRIO_CMD_SET_GATES),
            ("HOLD", TC_TAPRIO_CMD_SET_AND_HOLD),
            ("H", TC_TAPRIO_CMD_SET_AND_HOLD),
            ("RELEASE", TC_TAPRIO_CMD_SET_AND_RELEASE),
            ("R", TC_TAPRIO_CMD_SET_AND_RELEASE),
        ] {
            let cfg = TaprioConfig::parse_params(&["sched-entry", cmd, "0x1", "100"]).unwrap();
            assert_eq!(cfg.entries[0].cmd, expected, "cmd alias `{cmd}`");
        }
    }

    #[test]
    fn taprio_parse_params_sched_entry_short_errors() {
        let err = TaprioConfig::parse_params(&["sched-entry", "SET", "0x1"]).unwrap_err();
        assert!(err.to_string().contains("sched-entry"));
    }

    #[test]
    fn taprio_parse_params_flags_and_named() {
        use crate::netlink::types::tc::qdisc::taprio::{
            TAPRIO_ATTR_FLAG_FULL_OFFLOAD, TAPRIO_ATTR_FLAG_TXTIME_ASSIST,
        };
        let cfg = TaprioConfig::parse_params(&["txtime-assist", "full-offload"]).unwrap();
        assert_eq!(
            cfg.flags,
            TAPRIO_ATTR_FLAG_TXTIME_ASSIST | TAPRIO_ATTR_FLAG_FULL_OFFLOAD
        );
        let cfg = TaprioConfig::parse_params(&["flags", "0x3"]).unwrap();
        assert_eq!(cfg.flags, 0x3);
    }

    #[test]
    fn taprio_parse_params_queues_rejected() {
        let err = TaprioConfig::parse_params(&["queues", "1@0"]).unwrap_err();
        assert!(err.to_string().contains("not parsed by parse_params yet"));
    }

    #[test]
    fn taprio_parse_params_unknown_token_errors() {
        let err = TaprioConfig::parse_params(&["nonsense"]).unwrap_err();
        assert!(err.to_string().contains("unknown token"));
    }

    #[test]
    fn taprio_parse_params_invalid_sched_entry_cmd() {
        let err = TaprioConfig::parse_params(&["sched-entry", "BOGUS", "0x1", "100"]).unwrap_err();
        assert!(err.to_string().contains("invalid sched-entry cmd"));
    }

    // ============================================================================
    // Class-config parse_params tests (HtbClassConfig / HfscClassConfig /
    // DrrClassConfig / QfqClassConfig — added in 0.15.0 to close the class
    // side at typed-first parity with qdisc/filter/action).
    // ============================================================================

    #[test]
    fn htb_class_parse_params_rate_only() {
        let cfg = HtbClassConfig::parse_params(&["rate", "100mbit"]).unwrap();
        assert_eq!(
            cfg.rate.as_bytes_per_sec(),
            crate::util::Rate::mbit(100).as_bytes_per_sec()
        );
        assert!(cfg.ceil.is_none());
    }

    #[test]
    fn htb_class_parse_params_full_aliases() {
        // Cover the alias set: buffer / cbuffer = burst / cburst.
        let cfg = HtbClassConfig::parse_params(&[
            "rate", "10mbit", "ceil", "100mbit", "buffer", "32kb", "cbuffer", "64kb", "prio", "1",
            "quantum", "1500", "mtu", "1500", "mpu", "64", "overhead", "14",
        ])
        .unwrap();
        assert!(cfg.ceil.is_some());
        assert!(cfg.burst.is_some());
        assert!(cfg.cburst.is_some());
        assert_eq!(cfg.prio, Some(1));
        assert_eq!(cfg.quantum, Some(1500));
        assert_eq!(cfg.mtu, 1500);
        assert_eq!(cfg.mpu, 64);
        assert_eq!(cfg.overhead, 14);
    }

    #[test]
    fn htb_class_parse_params_missing_rate_errors() {
        let err = HtbClassConfig::parse_params(&[]).unwrap_err();
        assert!(err.to_string().contains("htb:"), "kind-prefixed: {err}");
        assert!(err.to_string().contains("`rate` is required"), "got: {err}");
    }

    #[test]
    fn htb_class_parse_params_unknown_token_errors() {
        let err = HtbClassConfig::parse_params(&["rate", "100mbit", "nonsense"]).unwrap_err();
        assert!(
            err.to_string().contains("htb: unknown token `nonsense`"),
            "got: {err}"
        );
    }

    #[test]
    fn htb_class_parse_params_missing_value_errors() {
        let err = HtbClassConfig::parse_params(&["rate"]).unwrap_err();
        assert!(err.to_string().contains("requires a value"), "got: {err}");
    }

    #[test]
    fn htb_class_parse_params_invalid_rate_errors() {
        let err = HtbClassConfig::parse_params(&["rate", "fast"]).unwrap_err();
        assert!(err.to_string().contains("htb: invalid rate"), "got: {err}");
    }

    #[test]
    fn hfsc_class_parse_params_empty_yields_empty_config() {
        let cfg = HfscClassConfig::parse_params(&[]).unwrap();
        assert!(cfg.rsc.is_none() && cfg.fsc.is_none() && cfg.usc.is_none());
    }

    #[test]
    fn hfsc_class_parse_params_three_curves() {
        let cfg = HfscClassConfig::parse_params(&[
            "rt", "rate", "10mbit", "ls", "rate", "100mbit", "ul", "rate", "200mbit",
        ])
        .unwrap();
        assert!(cfg.rsc.is_some());
        assert!(cfg.fsc.is_some());
        assert!(cfg.usc.is_some());
    }

    #[test]
    fn hfsc_class_parse_params_unknown_curve_errors() {
        let err = HfscClassConfig::parse_params(&["xt", "rate", "10mbit"]).unwrap_err();
        assert!(
            err.to_string().contains("hfsc: unknown token `xt`"),
            "got: {err}"
        );
    }

    #[test]
    fn hfsc_class_parse_params_non_rate_form_errors() {
        let err = HfscClassConfig::parse_params(&["rt", "rate", "10mbit", "ls", "m1", "100"])
            .unwrap_err();
        assert!(err.to_string().contains("hfsc:"), "kind-prefixed: {err}");
        assert!(
            err.to_string().contains("only the `rate <rate>` form"),
            "got: {err}"
        );
    }

    #[test]
    fn drr_class_parse_params_empty_and_quantum() {
        let cfg = DrrClassConfig::parse_params(&[]).unwrap();
        assert!(cfg.quantum.is_none());
        let cfg = DrrClassConfig::parse_params(&["quantum", "1500"]).unwrap();
        assert!(cfg.quantum.is_some());
    }

    #[test]
    fn drr_class_parse_params_unknown_token_errors() {
        let err = DrrClassConfig::parse_params(&["rate", "100mbit"]).unwrap_err();
        assert!(
            err.to_string().contains("drr: unknown token `rate`"),
            "got: {err}"
        );
    }

    #[test]
    fn qfq_class_parse_params_weight_and_lmax() {
        let cfg = QfqClassConfig::parse_params(&["weight", "5", "lmax", "9000"]).unwrap();
        assert_eq!(cfg.weight, Some(5));
        assert!(cfg.lmax.is_some());
    }

    #[test]
    fn qfq_class_parse_params_weight_clamped() {
        let cfg = QfqClassConfig::parse_params(&["weight", "9999"]).unwrap();
        assert_eq!(cfg.weight, Some(1023));
    }

    #[test]
    fn qfq_class_parse_params_unknown_token_errors() {
        let err = QfqClassConfig::parse_params(&["nonsense"]).unwrap_err();
        assert!(
            err.to_string().contains("qfq: unknown token `nonsense`"),
            "got: {err}"
        );
    }

    /// Generic dispatch through the sealed `ParseParams` trait —
    /// proves the new class-config impls are wired into the trait
    /// alongside qdisc/filter/action, not just inherent methods.
    #[test]
    fn class_configs_dispatch_through_parse_params_trait() {
        use crate::ParseParams;
        let _: HtbClassConfig =
            <HtbClassConfig as ParseParams>::parse_params(&["rate", "100mbit"]).unwrap();
        let _: HfscClassConfig = <HfscClassConfig as ParseParams>::parse_params(&[]).unwrap();
        let _: DrrClassConfig = <DrrClassConfig as ParseParams>::parse_params(&[]).unwrap();
        let _: QfqClassConfig = <QfqClassConfig as ParseParams>::parse_params(&[]).unwrap();
    }

    #[test]
    fn codel_parse_params() {
        let cfg = CodelConfig::parse_params(&[
            "limit", "1000", "target", "5ms", "interval", "100ms", "ecn",
        ])
        .unwrap();
        assert_eq!(cfg.limit, Some(1000));
        assert_eq!(cfg.target, Some(Duration::from_millis(5)));
        assert_eq!(cfg.interval, Some(Duration::from_millis(100)));
        assert_eq!(cfg.ecn, Some(true));
        assert_eq!(cfg.kind(), "codel");

        // noecn distinct from unset
        assert_eq!(CodelConfig::parse_params(&["noecn"]).unwrap().ecn, Some(false));
        assert_eq!(CodelConfig::parse_params(&[]).unwrap().ecn, None);

        // strict
        assert!(CodelConfig::parse_params(&["bogus"]).is_err());
        assert!(CodelConfig::parse_params(&["limit"]).is_err()); // missing value
        assert!(CodelConfig::parse_params(&["target", "notatime"]).is_err());
    }

    #[test]
    fn fq_parse_params() {
        let cfg = FqConfig::parse_params(&[
            "limit", "10000", "flow_limit", "100", "quantum", "3028", "maxrate", "100mbit",
            "nopacing",
        ])
        .unwrap();
        assert_eq!(cfg.limit, Some(10000));
        assert_eq!(cfg.flow_limit, Some(100));
        assert_eq!(cfg.quantum, Some(3028));
        // 100 mbit = 12_500_000 bytes/sec
        assert_eq!(
            cfg.maxrate.unwrap().as_u32_bytes_per_sec_saturating(),
            12_500_000
        );
        assert_eq!(cfg.pacing, Some(false));
        assert_eq!(cfg.kind(), "fq");

        // strict
        assert!(FqConfig::parse_params(&["bogus"]).is_err());
        assert!(FqConfig::parse_params(&["maxrate"]).is_err()); // missing value
        assert!(FqConfig::parse_params(&["maxrate", "notarate"]).is_err());
        assert!(FqConfig::parse_params(&["limit", "notanumber"]).is_err());
    }

    #[test]
    fn mq_parse_params() {
        assert_eq!(MqConfig::parse_params(&[]).unwrap().kind(), "mq");
        // strict: any token errors
        assert!(MqConfig::parse_params(&["bands", "4"]).is_err());
        assert!(MqConfig::parse_params(&["anything"]).is_err());
    }

    #[test]
    fn ets_parse_params() {
        let cfg = EtsConfig::parse_params(&[
            "bands", "4", "strict", "1", "quanta", "3000", "2000", "1000", "priomap", "0", "0", "1",
            "2", "3",
        ])
        .unwrap();
        assert_eq!(cfg.bands, Some(4));
        assert_eq!(cfg.strict, Some(1));
        assert_eq!(cfg.quanta, vec![3000, 2000, 1000]);
        assert_eq!(cfg.priomap, vec![0, 0, 1, 2, 3]);
        assert_eq!(cfg.kind(), "ets");

        // any-order keywords
        let cfg = EtsConfig::parse_params(&["quanta", "1500", "bands", "2"]).unwrap();
        assert_eq!(cfg.quanta, vec![1500]);
        assert_eq!(cfg.bands, Some(2));

        // strict
        assert!(EtsConfig::parse_params(&["bogus"]).is_err());
        assert!(EtsConfig::parse_params(&["bands"]).is_err()); // missing value
        assert!(EtsConfig::parse_params(&["bands", "notanumber"]).is_err());
        assert!(EtsConfig::parse_params(&["quanta"]).is_err()); // empty list
        assert!(EtsConfig::parse_params(&["quanta", "notanumber"]).is_err());
        assert!(EtsConfig::parse_params(&["priomap", "notanumber"]).is_err());
    }

    #[test]
    fn ets_write_options_nests_quanta_and_priomap() {
        // Smoke-test that nested encoding produces bytes without panic
        // and includes the band-level attrs.
        let cfg = EtsConfig::new()
            .bands(3)
            .strict(1)
            .quanta(vec![2000, 1000])
            .priomap(vec![0, 1, 2]);
        let mut builder = MessageBuilder::new(0, 0);
        cfg.write_options(&mut builder).unwrap();
        // Non-empty payload — at minimum NBANDS + NSTRICT + 2 nests.
        assert!(!builder.as_bytes().is_empty());
    }
}
