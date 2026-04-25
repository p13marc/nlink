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
        qdisc::{TcRateSpec, fq_codel, htb, netem::*, prio, sfq, tbf},
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
    ///   `packet_overhead` / `cell_size` / `cell_overhead` extras yet,
    ///   so those positional args are rejected here. Drop to
    ///   `tc::options::netem::build` for them.
    /// - `limit <packets>`
    ///
    /// **Not yet typed-modelled** (returns `Error::InvalidMessage`
    /// pointing at the legacy parser): `slot`, `ecn`, `distribution`,
    /// the `loss state` 4-state Markov, `loss gemodel`. These need
    /// `NetemConfig` extensions before they can land here.
    ///
    /// Stricter than the legacy `tc::options::netem::build`: unknown
    /// keywords, missing values, and unparseable
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
                            "netem: `loss {next}` (Markov model) is not supported by the typed parser yet — use tc::options::netem::build"
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
                            "netem: positional `rate` extras (packet_overhead/cell_size/cell_overhead) are not modelled by NetemConfig — use tc::options::netem::build, got `{extra}`"
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
                        "netem: `{key}` is not modelled by NetemConfig yet — use tc::options::netem::build for this kind"
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
    /// **Not yet typed-modelled** (returns `Error::InvalidMessage`
    /// pointing at the legacy parser): `latency` — `tc(8)` accepts it
    /// as a way to specify `limit` indirectly (`limit ≈ rate *
    /// latency`), but `TbfConfig` only stores the raw `limit`. Drop
    /// to `tc::options::tbf::build` if you need the latency form.
    ///
    /// Stricter than the legacy `tc::options::tbf::build`: unknown
    /// tokens, missing values, and unparseable rate/size values all
    /// return `Error::InvalidMessage`. Note: this parser does NOT
    /// enforce the kernel's "rate and burst are required" rule —
    /// that's left to `add_qdisc` / the kernel itself, mirroring how
    /// `parse_params` behaves on every other config.
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
                        "tbf: `latency` is a derived form (limit = rate * latency) and is not modelled by TbfConfig — compute the limit yourself or use tc::options::tbf::build".into(),
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
    /// Stricter than the legacy `tc::options::htb::build`: unknown
    /// tokens, keys missing their value, and unparseable numbers all
    /// return `Error::InvalidMessage` instead of being silently
    /// skipped (which used to mask typos like `default_class` —
    /// that token has no effect on the legacy parser).
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
    /// field. Drop to `tc::options::sfq::build` if you need it.
    ///
    /// Stricter than the legacy parser: unknown tokens, missing
    /// values, and unparseable numbers all return an error.
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
                        "sfq: `divisor` is not modelled by SfqConfig — use tc::options::sfq::build"
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
/// The legacy string-args interface in `tc/options/cake.rs` remains
/// for `Connection::add_qdisc("eth0", "cake", &["bandwidth", ...])`
/// callers, but the typed builder is preferred for new code.
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
    /// Stricter than the legacy `tc::options::cake::build`: unknown
    /// tokens, missing values, and unparseable rate / time / size /
    /// integer values all return `Error::InvalidMessage`. The legacy
    /// parser silently skips unknown tokens, which masks typos like
    /// `bandwidth_limit` (no effect) or `dual_srchost` with an
    /// underscore instead of a hyphen.
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
/// conn.add_class_config("eth0", "1:0", "1:1",
///     HtbClassConfig::new(Rate::gbit(1))
///         .ceil(Rate::gbit(1))
///         .build()
/// ).await?;
///
/// // Add child class with guaranteed and ceiling rates
/// conn.add_class_config("eth0", "1:1", "1:10",
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
/// conn.add_class_config("eth0", "1:0", "1:1",
///     HfscClassConfig::new()
///         .ls_rate(1_000_000_000)  // 1 Gbps link-share
///         .build()
/// ).await?;
///
/// // Add real-time class with latency guarantee
/// conn.add_class_config("eth0", "1:1", "1:10",
///     HfscClassConfig::new()
///         .rt_curve(TcServiceCurve::two_slope(10_000_000, 5000, 1_000_000))
///         .ls_rate(100_000_000)
///         .build()
/// ).await?;
///
/// // Add best-effort class with upper limit
/// conn.add_class_config("eth0", "1:1", "1:20",
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
/// conn.add_class_config("eth0", "1:0", "1:1",
///     DrrClassConfig::new()
///         .quantum(1500)  // 1 packet worth
///         .build()
/// ).await?;
///
/// conn.add_class_config("eth0", "1:0", "1:2",
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
/// conn.add_class_config("eth0", "1:0", "1:1",
///     QfqClassConfig::new()
///         .weight(1)
///         .build()
/// ).await?;
///
/// conn.add_class_config("eth0", "1:0", "1:2",
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
// Class option helpers
// ============================================================================

/// Add class-specific options to the message builder.
fn add_class_options(builder: &mut MessageBuilder, kind: &str, params: &[String]) -> Result<()> {
    if params.is_empty() {
        return Ok(());
    }

    let options_token = builder.nest_start(TcaAttr::Options as u16);

    match kind {
        "htb" => add_htb_class_options(builder, params)?,
        _ => {
            // Unknown class type - just ignore parameters
        }
    }

    builder.nest_end(options_token);
    Ok(())
}

/// Add HTB class options.
fn add_htb_class_options(builder: &mut MessageBuilder, params: &[String]) -> Result<()> {
    use crate::util::parse::{get_rate, get_size};

    let mut rate64: u64 = 0;
    let mut ceil64: u64 = 0;
    let mut burst: u32 = 0;
    let mut cburst: u32 = 0;
    let mut prio: u32 = 0;
    let mut quantum: u32 = 0;
    let mut mtu: u32 = 1600;
    let mut mpu: u16 = 0;
    let mut overhead: u16 = 0;

    let mut i = 0;
    while i < params.len() {
        match params[i].as_str() {
            "rate" if i + 1 < params.len() => {
                rate64 = get_rate(&params[i + 1])
                    .map_err(|_| Error::InvalidMessage("invalid rate".into()))?;
                i += 2;
            }
            "ceil" if i + 1 < params.len() => {
                ceil64 = get_rate(&params[i + 1])
                    .map_err(|_| Error::InvalidMessage("invalid ceil".into()))?;
                i += 2;
            }
            "burst" | "buffer" | "maxburst" if i + 1 < params.len() => {
                burst = get_size(&params[i + 1])
                    .map_err(|_| Error::InvalidMessage("invalid burst".into()))?
                    as u32;
                i += 2;
            }
            "cburst" | "cbuffer" | "cmaxburst" if i + 1 < params.len() => {
                cburst = get_size(&params[i + 1])
                    .map_err(|_| Error::InvalidMessage("invalid cburst".into()))?
                    as u32;
                i += 2;
            }
            "prio" if i + 1 < params.len() => {
                prio = params[i + 1]
                    .parse()
                    .map_err(|_| Error::InvalidMessage("invalid prio".into()))?;
                i += 2;
            }
            "quantum" if i + 1 < params.len() => {
                quantum = get_size(&params[i + 1])
                    .map_err(|_| Error::InvalidMessage("invalid quantum".into()))?
                    as u32;
                i += 2;
            }
            "mtu" if i + 1 < params.len() => {
                mtu = params[i + 1]
                    .parse()
                    .map_err(|_| Error::InvalidMessage("invalid mtu".into()))?;
                i += 2;
            }
            "mpu" if i + 1 < params.len() => {
                mpu = params[i + 1]
                    .parse()
                    .map_err(|_| Error::InvalidMessage("invalid mpu".into()))?;
                i += 2;
            }
            "overhead" if i + 1 < params.len() => {
                overhead = params[i + 1]
                    .parse()
                    .map_err(|_| Error::InvalidMessage("invalid overhead".into()))?;
                i += 2;
            }
            _ => i += 1,
        }
    }

    // Rate is required
    if rate64 == 0 {
        return Err(Error::InvalidMessage("htb class: rate is required".into()));
    }

    // Default ceil to rate if not specified
    if ceil64 == 0 {
        ceil64 = rate64;
    }

    // Get HZ for time calculations (typically 100 or 1000 on Linux)
    let hz: u64 = 1000;

    // Compute burst from rate if not specified
    if burst == 0 {
        burst = (rate64 / hz + mtu as u64) as u32;
    }

    // Compute cburst from ceil if not specified
    if cburst == 0 {
        cburst = (ceil64 / hz + mtu as u64) as u32;
    }

    // Calculate buffer time (in ticks). Falls back to the raw burst size
    // when the rate would cause a divide-by-zero.
    let buffer = (burst as u64 * 1_000_000)
        .checked_div(rate64)
        .map(|v| v as u32)
        .unwrap_or(burst);

    let cbuffer = (cburst as u64 * 1_000_000)
        .checked_div(ceil64)
        .map(|v| v as u32)
        .unwrap_or(cburst);

    // Build the tc_htb_opt structure
    let opt = htb::TcHtbOpt {
        rate: TcRateSpec {
            rate: if rate64 >= (1u64 << 32) {
                u32::MAX
            } else {
                rate64 as u32
            },
            mpu,
            overhead,
            ..Default::default()
        },
        ceil: TcRateSpec {
            rate: if ceil64 >= (1u64 << 32) {
                u32::MAX
            } else {
                ceil64 as u32
            },
            mpu,
            overhead,
            ..Default::default()
        },
        buffer,
        cbuffer,
        quantum,
        prio,
        ..Default::default()
    };

    // Add 64-bit rate if needed
    if rate64 >= (1u64 << 32) {
        builder.append_attr(htb::TCA_HTB_RATE64, &rate64.to_ne_bytes());
    }

    if ceil64 >= (1u64 << 32) {
        builder.append_attr(htb::TCA_HTB_CEIL64, &ceil64.to_ne_bytes());
    }

    // Add the main parameters structure
    builder.append_attr(htb::TCA_HTB_PARMS, opt.as_bytes());

    // Add rate tables
    let rtab = compute_htb_rate_table(rate64, mtu);
    let ctab = compute_htb_rate_table(ceil64, mtu);

    builder.append_attr(htb::TCA_HTB_RTAB, &rtab);
    builder.append_attr(htb::TCA_HTB_CTAB, &ctab);

    Ok(())
}

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

    /// Add a TC class.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use nlink::netlink::{Connection, Route};
    /// use nlink::netlink::tc::HtbQdiscConfig;
    ///
    /// let conn = Connection::<Route>::new()?;
    ///
    /// // First add an HTB qdisc
    /// let htb = HtbQdiscConfig::new().default_class(0x10).build();
    /// conn.add_qdisc_full("eth0", "root", Some("1:"), htb).await?;
    ///
    /// // Then add a class with rate 10mbit, ceil 100mbit
    /// conn.add_class("eth0", "1:0", "1:10", "htb",
    ///     &["rate", "10mbit", "ceil", "100mbit"]).await?;
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "add_class"))]
    pub async fn add_class(
        &self,
        dev: impl Into<InterfaceRef>,
        parent: TcHandle,
        classid: TcHandle,
        kind: &str,
        params: &[&str],
    ) -> Result<()> {
        let ifindex = self.resolve_interface(&dev.into()).await?;
        self.add_class_by_index(ifindex, parent, classid, kind, params)
            .await
    }

    /// Add a TC class by interface index.
    ///
    /// This is useful for namespace-aware operations where you've already
    /// resolved the interface index via `conn.get_link_by_name()`.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "add_class_by_index"))]
    pub async fn add_class_by_index(
        &self,
        ifindex: u32,
        parent: TcHandle,
        classid: TcHandle,
        kind: &str,
        params: &[&str],
    ) -> Result<()> {
        let parent_handle = parent.as_raw();
        let class_handle = classid.as_raw();

        let tcmsg = TcMsg::new()
            .with_ifindex(ifindex as i32)
            .with_parent(parent_handle)
            .with_handle(class_handle);

        let mut builder = create_request(NlMsgType::RTM_NEWTCLASS);
        builder.append(&tcmsg);
        builder.append_attr_str(TcaAttr::Kind as u16, kind);

        let params: Vec<String> = params.iter().map(|s| s.to_string()).collect();
        add_class_options(&mut builder, kind, &params)?;

        self.send_ack(builder)
            .await
            .map_err(|e| e.with_context("add_class"))
    }

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

    /// Change a TC class's parameters.
    ///
    /// # Example
    ///
    /// ```ignore
    /// conn.change_class("eth0", "1:0", "1:10", "htb",
    ///     &["rate", "20mbit", "ceil", "100mbit"]).await?;
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "change_class"))]
    pub async fn change_class(
        &self,
        dev: impl Into<InterfaceRef>,
        parent: TcHandle,
        classid: TcHandle,
        kind: &str,
        params: &[&str],
    ) -> Result<()> {
        let ifindex = self.resolve_interface(&dev.into()).await?;
        self.change_class_by_index(ifindex, parent, classid, kind, params)
            .await
    }

    /// Change a TC class by interface index.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "change_class_by_index"))]
    pub async fn change_class_by_index(
        &self,
        ifindex: u32,
        parent: TcHandle,
        classid: TcHandle,
        kind: &str,
        params: &[&str],
    ) -> Result<()> {
        let parent_handle = parent.as_raw();
        let class_handle = classid.as_raw();

        let tcmsg = TcMsg::new()
            .with_ifindex(ifindex as i32)
            .with_parent(parent_handle)
            .with_handle(class_handle);

        let mut builder = ack_request(NlMsgType::RTM_NEWTCLASS);
        builder.append(&tcmsg);
        builder.append_attr_str(TcaAttr::Kind as u16, kind);

        let params: Vec<String> = params.iter().map(|s| s.to_string()).collect();
        add_class_options(&mut builder, kind, &params)?;

        self.send_ack(builder)
            .await
            .map_err(|e| e.with_context("change_class"))
    }

    /// Replace a TC class (add or update).
    ///
    /// # Example
    ///
    /// ```ignore
    /// conn.replace_class("eth0", "1:0", "1:10", "htb",
    ///     &["rate", "10mbit", "ceil", "100mbit"]).await?;
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "replace_class"))]
    pub async fn replace_class(
        &self,
        dev: impl Into<InterfaceRef>,
        parent: TcHandle,
        classid: TcHandle,
        kind: &str,
        params: &[&str],
    ) -> Result<()> {
        let ifindex = self.resolve_interface(&dev.into()).await?;
        self.replace_class_by_index(ifindex, parent, classid, kind, params)
            .await
    }

    /// Replace a TC class by interface index.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "replace_class_by_index"))]
    pub async fn replace_class_by_index(
        &self,
        ifindex: u32,
        parent: TcHandle,
        classid: TcHandle,
        kind: &str,
        params: &[&str],
    ) -> Result<()> {
        let parent_handle = parent.as_raw();
        let class_handle = classid.as_raw();

        let tcmsg = TcMsg::new()
            .with_ifindex(ifindex as i32)
            .with_parent(parent_handle)
            .with_handle(class_handle);

        let mut builder = replace_request(NlMsgType::RTM_NEWTCLASS);
        builder.append(&tcmsg);
        builder.append_attr_str(TcaAttr::Kind as u16, kind);

        let params: Vec<String> = params.iter().map(|s| s.to_string()).collect();
        add_class_options(&mut builder, kind, &params)?;

        self.send_ack(builder)
            .await
            .map_err(|e| e.with_context("replace_class"))
    }

    // ========================================================================
    // Typed Class Config Operations
    // ========================================================================

    /// Add a TC class with typed configuration.
    ///
    /// This method provides a type-safe way to add classes, as an alternative
    /// to the string-based `add_class` method.
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
    /// conn.add_class_config("eth0", "1:0", "1:10",
    ///     HtbClassConfig::new(Rate::mbit(100))
    ///         .ceil(Rate::mbit(500))
    ///         .prio(1)
    ///         .build()
    /// ).await?;
    /// ```
    pub async fn add_class_config<C: ClassConfig>(
        &self,
        dev: impl Into<InterfaceRef>,
        parent: TcHandle,
        classid: TcHandle,
        config: C,
    ) -> Result<()> {
        let ifindex = self.resolve_interface(&dev.into()).await?;
        self.add_class_config_by_index(ifindex, parent, classid, config)
            .await
    }

    /// Add a TC class with typed configuration by interface index.
    ///
    /// This is useful for namespace-aware operations where you've already
    /// resolved the interface index via `conn.get_link_by_name()`.
    pub async fn add_class_config_by_index<C: ClassConfig>(
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
    /// conn.change_class_config("eth0", "1:0", "1:10",
    ///     HtbClassConfig::new(Rate::mbit(200))
    ///         .ceil(Rate::mbit(800))
    ///         .build()
    /// ).await?;
    /// ```
    pub async fn change_class_config<C: ClassConfig>(
        &self,
        dev: impl Into<InterfaceRef>,
        parent: TcHandle,
        classid: TcHandle,
        config: C,
    ) -> Result<()> {
        let ifindex = self.resolve_interface(&dev.into()).await?;
        self.change_class_config_by_index(ifindex, parent, classid, config)
            .await
    }

    /// Change a TC class with typed configuration by interface index.
    pub async fn change_class_config_by_index<C: ClassConfig>(
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
    /// conn.replace_class_config("eth0", "1:0", "1:10",
    ///     HtbClassConfig::new(Rate::mbit(100))
    ///         .ceil(Rate::mbit(500))
    ///         .build()
    /// ).await?;
    /// ```
    pub async fn replace_class_config<C: ClassConfig>(
        &self,
        dev: impl Into<InterfaceRef>,
        parent: TcHandle,
        classid: TcHandle,
        config: C,
    ) -> Result<()> {
        let ifindex = self.resolve_interface(&dev.into()).await?;
        self.replace_class_config_by_index(ifindex, parent, classid, config)
            .await
    }

    /// Replace a TC class with typed configuration by interface index.
    pub async fn replace_class_config_by_index<C: ClassConfig>(
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
}
