//! Typed TC options parsing.
//!
//! This module provides strongly-typed access to qdisc-specific options
//! that are stored in the raw `TcMessage.options` field.
//!
//! # Example
//!
//! ```ignore
//! use rip_netlink::tc_options::{QdiscOptions, parse_qdisc_options};
//!
//! let qdiscs = conn.get_qdiscs().await?;
//! for qdisc in &qdiscs {
//!     if let Some(opts) = parse_qdisc_options(qdisc) {
//!         match opts {
//!             QdiscOptions::FqCodel(fq) => {
//!                 println!("fq_codel: target={}us, interval={}us, limit={}",
//!                     fq.target_us, fq.interval_us, fq.limit);
//!             }
//!             QdiscOptions::Htb(htb) => {
//!                 println!("htb: default={:x}", htb.default_class);
//!             }
//!             // ... handle other types
//!             _ => {}
//!         }
//!     }
//! }
//! ```

use super::messages::TcMessage;

/// Parsed qdisc options, strongly typed by qdisc kind.
#[derive(Debug, Clone)]
pub enum QdiscOptions {
    /// fq_codel - Fair Queue Controlled Delay
    FqCodel(FqCodelOptions),
    /// htb - Hierarchical Token Bucket
    Htb(HtbOptions),
    /// tbf - Token Bucket Filter
    Tbf(TbfOptions),
    /// netem - Network Emulator
    Netem(NetemOptions),
    /// prio - Priority Scheduler
    Prio(PrioOptions),
    /// sfq - Stochastic Fairness Queuing
    Sfq(SfqOptions),
    /// Unknown qdisc type (contains raw options)
    Unknown(Vec<u8>),
}

/// fq_codel qdisc options.
#[derive(Debug, Clone, Default)]
pub struct FqCodelOptions {
    /// Target delay in microseconds.
    pub target_us: u32,
    /// Interval in microseconds.
    pub interval_us: u32,
    /// Queue limit in packets.
    pub limit: u32,
    /// Number of flows.
    pub flows: u32,
    /// Quantum (bytes to dequeue per round).
    pub quantum: u32,
    /// ECN marking enabled.
    pub ecn: bool,
    /// CE threshold in microseconds.
    pub ce_threshold_us: Option<u32>,
    /// Memory limit in bytes.
    pub memory_limit: Option<u32>,
    /// Drop batch size.
    pub drop_batch_size: Option<u32>,
}

/// htb qdisc options.
#[derive(Debug, Clone, Default)]
pub struct HtbOptions {
    /// Default class ID.
    pub default_class: u32,
    /// Rate to quantum divisor.
    pub rate2quantum: u32,
    /// Direct queue length.
    pub direct_qlen: Option<u32>,
    /// HTB version.
    pub version: u32,
}

/// tbf qdisc options.
#[derive(Debug, Clone, Default)]
pub struct TbfOptions {
    /// Rate in bytes/sec.
    pub rate: u64,
    /// Peak rate in bytes/sec (0 if not set).
    pub peakrate: u64,
    /// Bucket size (burst) in bytes.
    pub burst: u32,
    /// Maximum packet size (MTU).
    pub mtu: u32,
    /// Queue limit in bytes.
    pub limit: u32,
}

/// netem qdisc options.
#[derive(Debug, Clone, Default)]
pub struct NetemOptions {
    /// Added delay in nanoseconds. Use `delay()` to get as Duration.
    /// This field uses 64-bit precision when TCA_NETEM_LATENCY64 is present.
    pub delay_ns: u64,
    /// Delay jitter in nanoseconds. Use `jitter()` to get as Duration.
    /// This field uses 64-bit precision when TCA_NETEM_JITTER64 is present.
    pub jitter_ns: u64,
    /// Delay correlation (0-100%).
    pub delay_corr: f64,
    /// Packet loss probability (0-100%).
    pub loss_percent: f64,
    /// Loss correlation (0-100%).
    pub loss_corr: f64,
    /// Duplicate probability (0-100%).
    pub duplicate_percent: f64,
    /// Duplicate correlation (0-100%).
    pub duplicate_corr: f64,
    /// Reorder probability (0-100%).
    pub reorder_percent: f64,
    /// Reorder correlation (0-100%).
    pub reorder_corr: f64,
    /// Corruption probability (0-100%).
    pub corrupt_percent: f64,
    /// Corruption correlation (0-100%).
    pub corrupt_corr: f64,
    /// Rate limit in bytes/sec (0 if not set).
    pub rate: u64,
    /// Per-packet overhead in bytes for rate limiting.
    pub packet_overhead: i32,
    /// ATM cell size for rate limiting overhead calculation.
    pub cell_size: u32,
    /// Per-cell overhead for rate limiting.
    pub cell_overhead: i32,
    /// Queue limit in packets.
    pub limit: u32,
    /// Reorder gap.
    pub gap: u32,
    /// ECN marking enabled.
    pub ecn: bool,
    /// Slot-based transmission configuration (if present).
    pub slot: Option<NetemSlotOptions>,
    /// Loss model (if using state-based loss instead of random).
    pub loss_model: Option<NetemLossModel>,
}

/// Netem loss model configuration.
#[derive(Debug, Clone, Copy)]
pub enum NetemLossModel {
    /// Gilbert-Intuitive 4-state loss model.
    ///
    /// States: Good (1), Bad Burst (2), Bad Gap (3), Loss (4)
    GilbertIntuitive {
        /// Probability of transitioning from Good to Bad Burst (p13).
        p13: f64,
        /// Probability of transitioning from Bad Burst to Good (p31).
        p31: f64,
        /// Probability of transitioning from Bad Burst to Bad Gap (p32).
        p32: f64,
        /// Probability of transitioning from Good to Loss (p14).
        p14: f64,
        /// Probability of transitioning from Bad Gap to Bad Burst (p23).
        p23: f64,
    },
    /// Gilbert-Elliot 2-state loss model.
    ///
    /// States: Good, Bad with different loss probabilities.
    GilbertElliot {
        /// Probability of transitioning from Good to Bad (p).
        p: f64,
        /// Probability of transitioning from Bad to Good (r).
        r: f64,
        /// Loss probability in Bad state (h), 1-h in Good state (1-k).
        h: f64,
        /// Loss probability in Good state (1-k).
        k1: f64,
    },
}

/// Netem slot-based transmission options.
#[derive(Debug, Clone, Copy, Default)]
pub struct NetemSlotOptions {
    /// Minimum delay between packets in nanoseconds.
    pub min_delay_ns: i64,
    /// Maximum delay between packets in nanoseconds.
    pub max_delay_ns: i64,
    /// Maximum packets per slot (0 = unlimited).
    pub max_packets: i32,
    /// Maximum bytes per slot (0 = unlimited).
    pub max_bytes: i32,
    /// Distribution delay in nanoseconds.
    pub dist_delay_ns: i64,
    /// Distribution jitter in nanoseconds.
    pub dist_jitter_ns: i64,
}

impl NetemOptions {
    /// Get the configured delay as a Duration.
    #[inline]
    pub fn delay(&self) -> std::time::Duration {
        std::time::Duration::from_nanos(self.delay_ns)
    }

    /// Get the configured jitter as a Duration.
    #[inline]
    pub fn jitter(&self) -> std::time::Duration {
        std::time::Duration::from_nanos(self.jitter_ns)
    }
}

/// prio qdisc options.
#[derive(Debug, Clone)]
pub struct PrioOptions {
    /// Number of priority bands.
    pub bands: i32,
    /// Priority map (16 entries, maps TOS to band).
    pub priomap: [u8; 16],
}

impl Default for PrioOptions {
    fn default() -> Self {
        Self {
            bands: 3,
            priomap: [1, 2, 2, 2, 1, 2, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1],
        }
    }
}

/// sfq qdisc options.
#[derive(Debug, Clone, Default)]
pub struct SfqOptions {
    /// Quantum (bytes to send per round).
    pub quantum: u32,
    /// Perturbation period in seconds.
    pub perturb_period: i32,
    /// Queue limit.
    pub limit: u32,
    /// Number of hash buckets.
    pub divisor: u32,
    /// Number of flows.
    pub flows: u32,
    /// Depth (packets per flow).
    pub depth: Option<u32>,
    /// Enable head drop.
    pub headdrop: Option<bool>,
}

/// Parse qdisc options from a TcMessage.
///
/// Returns `None` if the message has no kind or no options.
pub fn parse_qdisc_options(msg: &TcMessage) -> Option<QdiscOptions> {
    let kind = msg.kind()?;
    let data = msg.options.as_ref()?;

    Some(match kind {
        "fq_codel" => QdiscOptions::FqCodel(parse_fq_codel_options(data)),
        "htb" => QdiscOptions::Htb(parse_htb_options(data)),
        "tbf" => QdiscOptions::Tbf(parse_tbf_options(data)),
        "netem" => QdiscOptions::Netem(parse_netem_options(data)),
        "prio" => QdiscOptions::Prio(parse_prio_options(data)),
        "sfq" => QdiscOptions::Sfq(parse_sfq_options(data)),
        _ => QdiscOptions::Unknown(data.clone()),
    })
}

/// HTB class options.
#[derive(Debug, Clone, Default)]
pub struct HtbClassOptions {
    /// Guaranteed rate in bytes/sec.
    pub rate: u64,
    /// Ceiling rate in bytes/sec.
    pub ceil: u64,
    /// Burst size in bytes.
    pub burst: u32,
    /// Ceil burst size in bytes.
    pub cburst: u32,
    /// Priority (lower = higher priority).
    pub priority: u32,
    /// Quantum for borrowing.
    pub quantum: u32,
    /// Class level in hierarchy.
    pub level: u32,
}

/// Parse HTB class options from TcMessage options data.
pub fn parse_htb_class_options(data: &[u8]) -> Option<HtbClassOptions> {
    use super::types::tc::qdisc::htb::*;

    let mut opts = HtbClassOptions::default();
    let mut rate64: Option<u64> = None;
    let mut ceil64: Option<u64> = None;
    let mut input = data;

    while input.len() >= 4 {
        let len = u16::from_ne_bytes(input[..2].try_into().ok()?) as usize;
        let attr_type = u16::from_ne_bytes(input[2..4].try_into().ok()?);

        if len < 4 || input.len() < len {
            break;
        }

        let payload = &input[4..len];

        match attr_type & 0x3FFF {
            TCA_HTB_PARMS => {
                if payload.len() >= std::mem::size_of::<TcHtbOpt>() {
                    // Parse TcHtbOpt structure
                    // Rate spec starts at offset 0, ceil at offset 12
                    let rate = u32::from_ne_bytes(payload[8..12].try_into().ok()?);
                    let ceil = u32::from_ne_bytes(payload[20..24].try_into().ok()?);
                    opts.rate = rate as u64;
                    opts.ceil = ceil as u64;

                    if payload.len() >= 44 {
                        opts.burst = u32::from_ne_bytes(payload[24..28].try_into().ok()?);
                        opts.cburst = u32::from_ne_bytes(payload[28..32].try_into().ok()?);
                        opts.quantum = u32::from_ne_bytes(payload[32..36].try_into().ok()?);
                        opts.level = u32::from_ne_bytes(payload[36..40].try_into().ok()?);
                        opts.priority = u32::from_ne_bytes(payload[40..44].try_into().ok()?);
                    }
                }
            }
            TCA_HTB_RATE64 => {
                if payload.len() >= 8 {
                    rate64 = Some(u64::from_ne_bytes(payload[..8].try_into().ok()?));
                }
            }
            TCA_HTB_CEIL64 => {
                if payload.len() >= 8 {
                    ceil64 = Some(u64::from_ne_bytes(payload[..8].try_into().ok()?));
                }
            }
            _ => {}
        }

        let aligned = (len + 3) & !3;
        if input.len() <= aligned {
            break;
        }
        input = &input[aligned..];
    }

    // Use 64-bit rates if available
    if let Some(r) = rate64 {
        opts.rate = r;
    }
    if let Some(c) = ceil64 {
        opts.ceil = c;
    }

    Some(opts)
}

// ============================================================================
// Internal parsing functions
// ============================================================================

/// fq_codel attribute constants.
mod fq_codel_attrs {
    pub const TCA_FQ_CODEL_TARGET: u16 = 1;
    pub const TCA_FQ_CODEL_LIMIT: u16 = 2;
    pub const TCA_FQ_CODEL_INTERVAL: u16 = 3;
    pub const TCA_FQ_CODEL_ECN: u16 = 4;
    pub const TCA_FQ_CODEL_FLOWS: u16 = 5;
    pub const TCA_FQ_CODEL_QUANTUM: u16 = 6;
    pub const TCA_FQ_CODEL_CE_THRESHOLD: u16 = 7;
    pub const TCA_FQ_CODEL_DROP_BATCH_SIZE: u16 = 8;
    pub const TCA_FQ_CODEL_MEMORY_LIMIT: u16 = 9;
}

fn parse_fq_codel_options(data: &[u8]) -> FqCodelOptions {
    use fq_codel_attrs::*;

    let mut opts = FqCodelOptions::default();
    let mut input = data;

    while input.len() >= 4 {
        let Some(len) = input
            .get(..2)
            .and_then(|b| b.try_into().ok())
            .map(u16::from_ne_bytes)
        else {
            break;
        };
        let len = len as usize;
        let Some(attr_type) = input
            .get(2..4)
            .and_then(|b| b.try_into().ok())
            .map(u16::from_ne_bytes)
        else {
            break;
        };

        if len < 4 || input.len() < len {
            break;
        }

        let payload = &input[4..len];

        match attr_type & 0x3FFF {
            TCA_FQ_CODEL_TARGET => {
                if payload.len() >= 4 {
                    opts.target_us = u32::from_ne_bytes(payload[..4].try_into().unwrap());
                }
            }
            TCA_FQ_CODEL_LIMIT => {
                if payload.len() >= 4 {
                    opts.limit = u32::from_ne_bytes(payload[..4].try_into().unwrap());
                }
            }
            TCA_FQ_CODEL_INTERVAL => {
                if payload.len() >= 4 {
                    opts.interval_us = u32::from_ne_bytes(payload[..4].try_into().unwrap());
                }
            }
            TCA_FQ_CODEL_ECN => {
                if payload.len() >= 4 {
                    opts.ecn = u32::from_ne_bytes(payload[..4].try_into().unwrap()) != 0;
                }
            }
            TCA_FQ_CODEL_FLOWS => {
                if payload.len() >= 4 {
                    opts.flows = u32::from_ne_bytes(payload[..4].try_into().unwrap());
                }
            }
            TCA_FQ_CODEL_QUANTUM => {
                if payload.len() >= 4 {
                    opts.quantum = u32::from_ne_bytes(payload[..4].try_into().unwrap());
                }
            }
            TCA_FQ_CODEL_CE_THRESHOLD => {
                if payload.len() >= 4 {
                    opts.ce_threshold_us =
                        Some(u32::from_ne_bytes(payload[..4].try_into().unwrap()));
                }
            }
            TCA_FQ_CODEL_DROP_BATCH_SIZE => {
                if payload.len() >= 4 {
                    opts.drop_batch_size =
                        Some(u32::from_ne_bytes(payload[..4].try_into().unwrap()));
                }
            }
            TCA_FQ_CODEL_MEMORY_LIMIT => {
                if payload.len() >= 4 {
                    opts.memory_limit = Some(u32::from_ne_bytes(payload[..4].try_into().unwrap()));
                }
            }
            _ => {}
        }

        let aligned = (len + 3) & !3;
        if input.len() <= aligned {
            break;
        }
        input = &input[aligned..];
    }

    opts
}

fn parse_htb_options(data: &[u8]) -> HtbOptions {
    use super::types::tc::qdisc::htb::*;

    let mut opts = HtbOptions::default();
    let mut input = data;

    while input.len() >= 4 {
        let Some(len) = input
            .get(..2)
            .and_then(|b| b.try_into().ok())
            .map(u16::from_ne_bytes)
        else {
            break;
        };
        let len = len as usize;
        let Some(attr_type) = input
            .get(2..4)
            .and_then(|b| b.try_into().ok())
            .map(u16::from_ne_bytes)
        else {
            break;
        };

        if len < 4 || input.len() < len {
            break;
        }

        let payload = &input[4..len];

        match attr_type & 0x3FFF {
            TCA_HTB_INIT => {
                if payload.len() >= TcHtbGlob::SIZE {
                    opts.version = u32::from_ne_bytes(payload[0..4].try_into().unwrap());
                    opts.rate2quantum = u32::from_ne_bytes(payload[4..8].try_into().unwrap());
                    opts.default_class = u32::from_ne_bytes(payload[8..12].try_into().unwrap());
                }
            }
            TCA_HTB_DIRECT_QLEN => {
                if payload.len() >= 4 {
                    opts.direct_qlen = Some(u32::from_ne_bytes(payload[..4].try_into().unwrap()));
                }
            }
            _ => {}
        }

        let aligned = (len + 3) & !3;
        if input.len() <= aligned {
            break;
        }
        input = &input[aligned..];
    }

    opts
}

fn parse_tbf_options(data: &[u8]) -> TbfOptions {
    use super::types::tc::qdisc::tbf::*;

    let mut opts = TbfOptions::default();
    let mut rate64: Option<u64> = None;
    let mut prate64: Option<u64> = None;
    let mut input = data;

    while input.len() >= 4 {
        let Some(len) = input
            .get(..2)
            .and_then(|b| b.try_into().ok())
            .map(u16::from_ne_bytes)
        else {
            break;
        };
        let len = len as usize;
        let Some(attr_type) = input
            .get(2..4)
            .and_then(|b| b.try_into().ok())
            .map(u16::from_ne_bytes)
        else {
            break;
        };

        if len < 4 || input.len() < len {
            break;
        }

        let payload = &input[4..len];

        match attr_type & 0x3FFF {
            TCA_TBF_PARMS => {
                // TcTbfQopt: rate (TcRateSpec), peakrate (TcRateSpec), limit, buffer, mtu
                // TcRateSpec is 12 bytes
                if payload.len() >= 36 {
                    // rate.rate is at offset 8
                    opts.rate = u32::from_ne_bytes(payload[8..12].try_into().unwrap()) as u64;
                    // peakrate.rate is at offset 20
                    opts.peakrate = u32::from_ne_bytes(payload[20..24].try_into().unwrap()) as u64;
                    // limit at offset 24
                    opts.limit = u32::from_ne_bytes(payload[24..28].try_into().unwrap());
                    // buffer at offset 28
                    opts.burst = u32::from_ne_bytes(payload[28..32].try_into().unwrap());
                    // mtu at offset 32
                    opts.mtu = u32::from_ne_bytes(payload[32..36].try_into().unwrap());
                }
            }
            TCA_TBF_RATE64 => {
                if payload.len() >= 8 {
                    rate64 = Some(u64::from_ne_bytes(payload[..8].try_into().unwrap()));
                }
            }
            TCA_TBF_PRATE64 => {
                if payload.len() >= 8 {
                    prate64 = Some(u64::from_ne_bytes(payload[..8].try_into().unwrap()));
                }
            }
            TCA_TBF_BURST => {
                if payload.len() >= 4 {
                    opts.burst = u32::from_ne_bytes(payload[..4].try_into().unwrap());
                }
            }
            _ => {}
        }

        let aligned = (len + 3) & !3;
        if input.len() <= aligned {
            break;
        }
        input = &input[aligned..];
    }

    // Use 64-bit rates if available
    if let Some(r) = rate64 {
        opts.rate = r;
    }
    if let Some(r) = prate64 {
        opts.peakrate = r;
    }

    opts
}

fn parse_netem_options(data: &[u8]) -> NetemOptions {
    use super::types::tc::qdisc::netem::*;

    let mut opts = NetemOptions::default();

    // First 24 bytes are TcNetemQopt
    if data.len() >= TcNetemQopt::SIZE {
        // Parse delay/jitter as microseconds, convert to nanoseconds
        let delay_us = u32::from_ne_bytes(data[0..4].try_into().unwrap());
        opts.delay_ns = delay_us as u64 * 1000;
        opts.limit = u32::from_ne_bytes(data[4..8].try_into().unwrap());
        let loss_raw = u32::from_ne_bytes(data[8..12].try_into().unwrap());
        opts.loss_percent = prob_to_percent(loss_raw);
        opts.gap = u32::from_ne_bytes(data[12..16].try_into().unwrap());
        let dup_raw = u32::from_ne_bytes(data[16..20].try_into().unwrap());
        opts.duplicate_percent = prob_to_percent(dup_raw);
        let jitter_us = u32::from_ne_bytes(data[20..24].try_into().unwrap());
        opts.jitter_ns = jitter_us as u64 * 1000;
    }

    // Parse nested attributes after TcNetemQopt
    let mut input = if data.len() > TcNetemQopt::SIZE {
        &data[TcNetemQopt::SIZE..]
    } else {
        return opts;
    };

    while input.len() >= 4 {
        let Some(len) = input
            .get(..2)
            .and_then(|b| b.try_into().ok())
            .map(u16::from_ne_bytes)
        else {
            break;
        };
        let len = len as usize;
        let Some(attr_type) = input
            .get(2..4)
            .and_then(|b| b.try_into().ok())
            .map(u16::from_ne_bytes)
        else {
            break;
        };

        if len < 4 || input.len() < len {
            break;
        }

        let payload = &input[4..len];

        match attr_type & 0x3FFF {
            TCA_NETEM_CORR => {
                if payload.len() >= TcNetemCorr::SIZE {
                    let delay_corr = u32::from_ne_bytes(payload[0..4].try_into().unwrap());
                    let loss_corr = u32::from_ne_bytes(payload[4..8].try_into().unwrap());
                    let dup_corr = u32::from_ne_bytes(payload[8..12].try_into().unwrap());
                    opts.delay_corr = prob_to_percent(delay_corr);
                    opts.loss_corr = prob_to_percent(loss_corr);
                    opts.duplicate_corr = prob_to_percent(dup_corr);
                }
            }
            TCA_NETEM_REORDER => {
                if payload.len() >= TcNetemReorder::SIZE {
                    let prob = u32::from_ne_bytes(payload[0..4].try_into().unwrap());
                    let corr = u32::from_ne_bytes(payload[4..8].try_into().unwrap());
                    opts.reorder_percent = prob_to_percent(prob);
                    opts.reorder_corr = prob_to_percent(corr);
                }
            }
            TCA_NETEM_CORRUPT => {
                if payload.len() >= TcNetemCorrupt::SIZE {
                    let prob = u32::from_ne_bytes(payload[0..4].try_into().unwrap());
                    let corr = u32::from_ne_bytes(payload[4..8].try_into().unwrap());
                    opts.corrupt_percent = prob_to_percent(prob);
                    opts.corrupt_corr = prob_to_percent(corr);
                }
            }
            TCA_NETEM_RATE => {
                // TcNetemRate: rate (u32), packet_overhead (i32), cell_size (u32), cell_overhead (i32)
                if payload.len() >= 4 {
                    opts.rate = u32::from_ne_bytes(payload[0..4].try_into().unwrap()) as u64;
                }
                if payload.len() >= TcNetemRate::SIZE {
                    opts.packet_overhead = i32::from_ne_bytes(payload[4..8].try_into().unwrap());
                    opts.cell_size = u32::from_ne_bytes(payload[8..12].try_into().unwrap());
                    opts.cell_overhead = i32::from_ne_bytes(payload[12..16].try_into().unwrap());
                }
            }
            TCA_NETEM_RATE64 => {
                if payload.len() >= 8 {
                    opts.rate = u64::from_ne_bytes(payload[..8].try_into().unwrap());
                }
            }
            TCA_NETEM_ECN => {
                // ECN is a flag attribute (presence means enabled)
                // Some kernels send a u32 value, others just the attribute
                opts.ecn = true;
            }
            TCA_NETEM_LATENCY64 => {
                // 64-bit latency in nanoseconds
                if payload.len() >= 8 {
                    opts.delay_ns = u64::from_ne_bytes(payload[..8].try_into().unwrap());
                }
            }
            TCA_NETEM_JITTER64 => {
                // 64-bit jitter in nanoseconds
                if payload.len() >= 8 {
                    opts.jitter_ns = u64::from_ne_bytes(payload[..8].try_into().unwrap());
                }
            }
            TCA_NETEM_SLOT => {
                // TcNetemSlot structure
                if payload.len() >= TcNetemSlot::SIZE {
                    opts.slot = Some(NetemSlotOptions {
                        min_delay_ns: i64::from_ne_bytes(payload[0..8].try_into().unwrap()),
                        max_delay_ns: i64::from_ne_bytes(payload[8..16].try_into().unwrap()),
                        max_packets: i32::from_ne_bytes(payload[16..20].try_into().unwrap()),
                        max_bytes: i32::from_ne_bytes(payload[20..24].try_into().unwrap()),
                        dist_delay_ns: i64::from_ne_bytes(payload[24..32].try_into().unwrap()),
                        dist_jitter_ns: i64::from_ne_bytes(payload[32..40].try_into().unwrap()),
                    });
                }
            }
            TCA_NETEM_LOSS => {
                // Loss model is a nested attribute containing the model type and parameters
                parse_netem_loss_model(payload, &mut opts);
            }
            _ => {}
        }

        let aligned = (len + 3) & !3;
        if input.len() <= aligned {
            break;
        }
        input = &input[aligned..];
    }

    opts
}

/// Parse TCA_NETEM_LOSS nested attribute for loss model.
fn parse_netem_loss_model(data: &[u8], opts: &mut NetemOptions) {
    use super::types::tc::qdisc::netem::*;

    let mut input = data;

    while input.len() >= 4 {
        let Some(len) = input
            .get(..2)
            .and_then(|b| b.try_into().ok())
            .map(u16::from_ne_bytes)
        else {
            break;
        };
        let len = len as usize;
        let Some(attr_type) = input
            .get(2..4)
            .and_then(|b| b.try_into().ok())
            .map(u16::from_ne_bytes)
        else {
            break;
        };

        if len < 4 || input.len() < len {
            break;
        }

        let payload = &input[4..len];

        match attr_type & 0x3FFF {
            NETEM_LOSS_GI => {
                // Gilbert-Intuitive 4-state model
                if payload.len() >= TcNetemGiModel::SIZE {
                    let p13 = u32::from_ne_bytes(payload[0..4].try_into().unwrap());
                    let p31 = u32::from_ne_bytes(payload[4..8].try_into().unwrap());
                    let p32 = u32::from_ne_bytes(payload[8..12].try_into().unwrap());
                    let p14 = u32::from_ne_bytes(payload[12..16].try_into().unwrap());
                    let p23 = u32::from_ne_bytes(payload[16..20].try_into().unwrap());
                    opts.loss_model = Some(NetemLossModel::GilbertIntuitive {
                        p13: prob_to_percent(p13),
                        p31: prob_to_percent(p31),
                        p32: prob_to_percent(p32),
                        p14: prob_to_percent(p14),
                        p23: prob_to_percent(p23),
                    });
                }
            }
            NETEM_LOSS_GE => {
                // Gilbert-Elliot 2-state model
                if payload.len() >= TcNetemGeModel::SIZE {
                    let p = u32::from_ne_bytes(payload[0..4].try_into().unwrap());
                    let r = u32::from_ne_bytes(payload[4..8].try_into().unwrap());
                    let h = u32::from_ne_bytes(payload[8..12].try_into().unwrap());
                    let k1 = u32::from_ne_bytes(payload[12..16].try_into().unwrap());
                    opts.loss_model = Some(NetemLossModel::GilbertElliot {
                        p: prob_to_percent(p),
                        r: prob_to_percent(r),
                        h: prob_to_percent(h),
                        k1: prob_to_percent(k1),
                    });
                }
            }
            _ => {}
        }

        let aligned = (len + 3) & !3;
        if input.len() <= aligned {
            break;
        }
        input = &input[aligned..];
    }
}

fn parse_prio_options(data: &[u8]) -> PrioOptions {
    // TcPrioQopt: i32 bands + [u8; 16] priomap = 20 bytes
    if data.len() >= 20 {
        let bands = i32::from_ne_bytes(data[0..4].try_into().unwrap());
        let mut priomap = [0u8; 16];
        priomap.copy_from_slice(&data[4..20]);
        PrioOptions { bands, priomap }
    } else {
        PrioOptions::default()
    }
}

fn parse_sfq_options(data: &[u8]) -> SfqOptions {
    // TcSfqQopt: quantum (4), perturb_period (4), limit (4), divisor (4), flows (4) = 20 bytes
    if data.len() >= 20 {
        let quantum = u32::from_ne_bytes(data[0..4].try_into().unwrap());
        let perturb_period = i32::from_ne_bytes(data[4..8].try_into().unwrap());
        let limit = u32::from_ne_bytes(data[8..12].try_into().unwrap());
        let divisor = u32::from_ne_bytes(data[12..16].try_into().unwrap());
        let flows = u32::from_ne_bytes(data[16..20].try_into().unwrap());

        let mut opts = SfqOptions {
            quantum,
            perturb_period,
            limit,
            divisor,
            flows,
            ..Default::default()
        };

        // Check for extended SFQ options (TcSfqQoptV1)
        if data.len() >= 32 {
            opts.depth = Some(u32::from_ne_bytes(data[20..24].try_into().unwrap()));
            let headdrop = u32::from_ne_bytes(data[24..28].try_into().unwrap());
            opts.headdrop = Some(headdrop != 0);
        }

        opts
    } else {
        SfqOptions::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fq_codel_defaults() {
        let opts = FqCodelOptions::default();
        assert_eq!(opts.target_us, 0);
        assert_eq!(opts.interval_us, 0);
        assert!(!opts.ecn);
    }

    #[test]
    fn test_prio_defaults() {
        let opts = PrioOptions::default();
        assert_eq!(opts.bands, 3);
        assert_eq!(opts.priomap[0], 1);
        assert_eq!(opts.priomap[6], 0);
    }

    #[test]
    fn test_netem_defaults() {
        use std::time::Duration;
        let opts = NetemOptions::default();
        assert_eq!(opts.delay_ns, 0);
        assert_eq!(opts.delay(), Duration::ZERO);
        assert_eq!(opts.jitter_ns, 0);
        assert_eq!(opts.jitter(), Duration::ZERO);
        assert_eq!(opts.loss_percent, 0.0);
        assert_eq!(opts.duplicate_percent, 0.0);
        assert_eq!(opts.reorder_percent, 0.0);
        assert_eq!(opts.corrupt_percent, 0.0);
        assert_eq!(opts.rate, 0);
        assert_eq!(opts.limit, 0);
        assert_eq!(opts.gap, 0);
        assert!(!opts.ecn);
        assert!(opts.slot.is_none());
    }

    #[test]
    fn test_netem_parse_basic() {
        use super::super::types::tc::qdisc::netem::*;

        // Build TcNetemQopt with 100ms delay, 1000 packet limit, 1% loss
        let mut qopt = TcNetemQopt::new();
        qopt.latency = 100_000; // 100ms in microseconds
        qopt.limit = 1000;
        qopt.loss = percent_to_prob(1.0); // 1% loss
        qopt.gap = 0;
        qopt.duplicate = 0;
        qopt.jitter = 10_000; // 10ms jitter

        let data = qopt.as_bytes().to_vec();
        let opts = parse_netem_options(&data);

        assert_eq!(opts.delay().as_micros(), 100_000);
        assert_eq!(opts.jitter().as_micros(), 10_000);
        assert_eq!(opts.limit, 1000);
        assert!((opts.loss_percent - 1.0).abs() < 0.01);
        assert_eq!(opts.duplicate_percent, 0.0);
        assert_eq!(opts.gap, 0);
    }

    #[test]
    fn test_netem_parse_with_correlation() {
        use super::super::types::tc::qdisc::netem::*;

        // Build base options
        let mut qopt = TcNetemQopt::new();
        qopt.latency = 50_000; // 50ms
        qopt.limit = 1000;
        qopt.loss = percent_to_prob(5.0); // 5% loss
        qopt.duplicate = percent_to_prob(2.0); // 2% duplicate
        qopt.jitter = 5_000; // 5ms jitter

        // Build correlation attributes
        let corr = TcNetemCorr {
            delay_corr: percent_to_prob(25.0),
            loss_corr: percent_to_prob(50.0),
            dup_corr: percent_to_prob(10.0),
        };

        // Construct full data with nested attribute
        let mut data = qopt.as_bytes().to_vec();

        // Add TCA_NETEM_CORR attribute (type 1)
        let corr_bytes = corr.as_bytes();
        let attr_len = 4 + corr_bytes.len(); // header + payload
        data.extend_from_slice(&(attr_len as u16).to_ne_bytes());
        data.extend_from_slice(&TCA_NETEM_CORR.to_ne_bytes());
        data.extend_from_slice(corr_bytes);

        let opts = parse_netem_options(&data);

        assert_eq!(opts.delay().as_micros(), 50_000);
        assert_eq!(opts.jitter().as_micros(), 5_000);
        assert!((opts.loss_percent - 5.0).abs() < 0.1);
        assert!((opts.duplicate_percent - 2.0).abs() < 0.1);
        assert!((opts.delay_corr - 25.0).abs() < 0.1);
        assert!((opts.loss_corr - 50.0).abs() < 0.1);
        assert!((opts.duplicate_corr - 10.0).abs() < 0.1);
    }

    #[test]
    fn test_netem_parse_with_reorder() {
        use super::super::types::tc::qdisc::netem::*;

        let mut qopt = TcNetemQopt::new();
        qopt.latency = 100_000;
        qopt.limit = 1000;
        qopt.gap = 5; // reorder gap

        let reorder = TcNetemReorder {
            probability: percent_to_prob(10.0),
            correlation: percent_to_prob(25.0),
        };

        let mut data = qopt.as_bytes().to_vec();

        // Add TCA_NETEM_REORDER attribute (type 3)
        let reorder_bytes = reorder.as_bytes();
        let attr_len = 4 + reorder_bytes.len();
        data.extend_from_slice(&(attr_len as u16).to_ne_bytes());
        data.extend_from_slice(&TCA_NETEM_REORDER.to_ne_bytes());
        data.extend_from_slice(reorder_bytes);

        let opts = parse_netem_options(&data);

        assert_eq!(opts.gap, 5);
        assert!((opts.reorder_percent - 10.0).abs() < 0.1);
        assert!((opts.reorder_corr - 25.0).abs() < 0.1);
    }

    #[test]
    fn test_netem_parse_with_corrupt() {
        use super::super::types::tc::qdisc::netem::*;

        let mut qopt = TcNetemQopt::new();
        qopt.latency = 0;
        qopt.limit = 1000;

        let corrupt = TcNetemCorrupt {
            probability: percent_to_prob(0.5),
            correlation: percent_to_prob(10.0),
        };

        let mut data = qopt.as_bytes().to_vec();

        // Add TCA_NETEM_CORRUPT attribute (type 4)
        let corrupt_bytes = corrupt.as_bytes();
        let attr_len = 4 + corrupt_bytes.len();
        data.extend_from_slice(&(attr_len as u16).to_ne_bytes());
        data.extend_from_slice(&TCA_NETEM_CORRUPT.to_ne_bytes());
        data.extend_from_slice(corrupt_bytes);

        let opts = parse_netem_options(&data);

        assert!((opts.corrupt_percent - 0.5).abs() < 0.1);
        assert!((opts.corrupt_corr - 10.0).abs() < 0.1);
    }

    #[test]
    fn test_netem_parse_with_rate() {
        use super::super::types::tc::qdisc::netem::*;

        let mut qopt = TcNetemQopt::new();
        qopt.limit = 1000;

        let rate = TcNetemRate {
            rate: 1_000_000, // 1 MB/s
            ..Default::default()
        };

        let mut data = qopt.as_bytes().to_vec();

        // Add TCA_NETEM_RATE attribute (type 6)
        let rate_bytes = rate.as_bytes();
        let attr_len = 4 + rate_bytes.len();
        data.extend_from_slice(&(attr_len as u16).to_ne_bytes());
        data.extend_from_slice(&TCA_NETEM_RATE.to_ne_bytes());
        data.extend_from_slice(rate_bytes);

        let opts = parse_netem_options(&data);

        assert_eq!(opts.rate, 1_000_000);
    }

    #[test]
    fn test_netem_parse_with_rate64() {
        use super::super::types::tc::qdisc::netem::*;

        let mut qopt = TcNetemQopt::new();
        qopt.limit = 1000;

        // Use a rate larger than u32::MAX
        let rate64: u64 = 10_000_000_000; // 10 GB/s

        let mut data = qopt.as_bytes().to_vec();

        // Add TCA_NETEM_RATE64 attribute (type 8)
        let attr_len = 4 + 8; // header + u64
        data.extend_from_slice(&(attr_len as u16).to_ne_bytes());
        data.extend_from_slice(&TCA_NETEM_RATE64.to_ne_bytes());
        data.extend_from_slice(&rate64.to_ne_bytes());

        let opts = parse_netem_options(&data);

        assert_eq!(opts.rate, 10_000_000_000);
    }

    #[test]
    fn test_netem_parse_multiple_attrs() {
        use super::super::types::tc::qdisc::netem::*;

        // Build a complete netem config with multiple attributes
        let mut qopt = TcNetemQopt::new();
        qopt.latency = 100_000; // 100ms
        qopt.limit = 1000;
        qopt.loss = percent_to_prob(1.0);
        qopt.jitter = 10_000;

        let corr = TcNetemCorr {
            delay_corr: percent_to_prob(25.0),
            loss_corr: percent_to_prob(50.0),
            ..Default::default()
        };

        let corrupt = TcNetemCorrupt {
            probability: percent_to_prob(0.1),
            ..Default::default()
        };

        let mut data = qopt.as_bytes().to_vec();

        // Add correlation (with padding to 4-byte alignment)
        let corr_bytes = corr.as_bytes();
        let attr_len = 4 + corr_bytes.len();
        let aligned_len = (attr_len + 3) & !3;
        data.extend_from_slice(&(attr_len as u16).to_ne_bytes());
        data.extend_from_slice(&TCA_NETEM_CORR.to_ne_bytes());
        data.extend_from_slice(corr_bytes);
        // Add padding if needed
        data.resize(data.len() + aligned_len - attr_len, 0);

        // Add corruption
        let corrupt_bytes = corrupt.as_bytes();
        let attr_len = 4 + corrupt_bytes.len();
        data.extend_from_slice(&(attr_len as u16).to_ne_bytes());
        data.extend_from_slice(&TCA_NETEM_CORRUPT.to_ne_bytes());
        data.extend_from_slice(corrupt_bytes);

        let opts = parse_netem_options(&data);

        assert_eq!(opts.delay().as_micros(), 100_000);
        assert_eq!(opts.jitter().as_micros(), 10_000);
        assert!((opts.loss_percent - 1.0).abs() < 0.1);
        assert!((opts.delay_corr - 25.0).abs() < 0.1);
        assert!((opts.loss_corr - 50.0).abs() < 0.1);
        assert!((opts.corrupt_percent - 0.1).abs() < 0.1);
    }

    #[test]
    fn test_netem_parse_with_64bit_delay() {
        use super::super::types::tc::qdisc::netem::*;

        let mut qopt = TcNetemQopt::new();
        qopt.latency = 100_000; // Will be overridden by 64-bit value
        qopt.limit = 1000;

        // 5 seconds in nanoseconds (exceeds u32 microseconds)
        let delay64_ns: u64 = 5_000_000_000;
        let jitter64_ns: u64 = 500_000_000; // 0.5 seconds

        let mut data = qopt.as_bytes().to_vec();

        // Add TCA_NETEM_LATENCY64 attribute
        let attr_len = 4 + 8;
        let aligned_len = (attr_len + 3) & !3;
        data.extend_from_slice(&(attr_len as u16).to_ne_bytes());
        data.extend_from_slice(&TCA_NETEM_LATENCY64.to_ne_bytes());
        data.extend_from_slice(&delay64_ns.to_ne_bytes());
        data.resize(data.len() + aligned_len - attr_len, 0);

        // Add TCA_NETEM_JITTER64 attribute
        data.extend_from_slice(&(attr_len as u16).to_ne_bytes());
        data.extend_from_slice(&TCA_NETEM_JITTER64.to_ne_bytes());
        data.extend_from_slice(&jitter64_ns.to_ne_bytes());

        let opts = parse_netem_options(&data);

        assert_eq!(opts.delay_ns, 5_000_000_000);
        assert_eq!(opts.jitter_ns, 500_000_000);
        assert_eq!(opts.delay().as_millis(), 5000);
        assert_eq!(opts.jitter().as_millis(), 500);
    }

    #[test]
    fn test_netem_parse_with_ecn() {
        use super::super::types::tc::qdisc::netem::*;

        let mut qopt = TcNetemQopt::new();
        qopt.limit = 1000;

        let mut data = qopt.as_bytes().to_vec();

        // Add TCA_NETEM_ECN attribute (flag, just presence matters)
        let attr_len = 4 + 4; // header + u32 (some kernels send a value)
        data.extend_from_slice(&(attr_len as u16).to_ne_bytes());
        data.extend_from_slice(&TCA_NETEM_ECN.to_ne_bytes());
        data.extend_from_slice(&1u32.to_ne_bytes());

        let opts = parse_netem_options(&data);

        assert!(opts.ecn);
    }

    #[test]
    fn test_netem_parse_with_slot() {
        use super::super::types::tc::qdisc::netem::*;

        let mut qopt = TcNetemQopt::new();
        qopt.limit = 1000;

        let slot = TcNetemSlot {
            min_delay: 1_000_000,  // 1ms in ns
            max_delay: 10_000_000, // 10ms in ns
            max_packets: 10,
            max_bytes: 15000,
            dist_delay: 0,
            dist_jitter: 0,
        };

        let mut data = qopt.as_bytes().to_vec();

        // Add TCA_NETEM_SLOT attribute
        let slot_bytes = slot.as_bytes();
        let attr_len = 4 + slot_bytes.len();
        data.extend_from_slice(&(attr_len as u16).to_ne_bytes());
        data.extend_from_slice(&TCA_NETEM_SLOT.to_ne_bytes());
        data.extend_from_slice(slot_bytes);

        let opts = parse_netem_options(&data);

        assert!(opts.slot.is_some());
        let slot_opts = opts.slot.unwrap();
        assert_eq!(slot_opts.min_delay_ns, 1_000_000);
        assert_eq!(slot_opts.max_delay_ns, 10_000_000);
        assert_eq!(slot_opts.max_packets, 10);
        assert_eq!(slot_opts.max_bytes, 15000);
    }

    #[test]
    fn test_netem_parse_with_rate_overhead() {
        use super::super::types::tc::qdisc::netem::*;

        let mut qopt = TcNetemQopt::new();
        qopt.limit = 1000;

        let rate = TcNetemRate {
            rate: 1_000_000,     // 1 MB/s
            packet_overhead: 14, // Ethernet header
            cell_size: 53,       // ATM cell size
            cell_overhead: 5,    // ATM cell overhead
        };

        let mut data = qopt.as_bytes().to_vec();

        let rate_bytes = rate.as_bytes();
        let attr_len = 4 + rate_bytes.len();
        data.extend_from_slice(&(attr_len as u16).to_ne_bytes());
        data.extend_from_slice(&TCA_NETEM_RATE.to_ne_bytes());
        data.extend_from_slice(rate_bytes);

        let opts = parse_netem_options(&data);

        assert_eq!(opts.rate, 1_000_000);
        assert_eq!(opts.packet_overhead, 14);
        assert_eq!(opts.cell_size, 53);
        assert_eq!(opts.cell_overhead, 5);
    }

    #[test]
    fn test_netem_prob_conversion_roundtrip() {
        use super::super::types::tc::qdisc::netem::*;

        // Test that percent -> prob -> percent roundtrips correctly
        let test_values = [0.0, 0.1, 1.0, 10.0, 50.0, 99.9, 100.0];

        for &percent in &test_values {
            let prob = percent_to_prob(percent);
            let back = prob_to_percent(prob);
            assert!(
                (percent - back).abs() < 0.01,
                "Roundtrip failed for {}: got {}",
                percent,
                back
            );
        }
    }

    #[test]
    fn test_netem_parse_with_loss_model_gi() {
        use super::super::types::tc::qdisc::netem::*;

        let mut qopt = TcNetemQopt::new();
        qopt.limit = 1000;

        // Gilbert-Intuitive model
        let gi_model = TcNetemGiModel {
            p13: percent_to_prob(5.0),
            p31: percent_to_prob(95.0),
            p32: percent_to_prob(3.0),
            p14: percent_to_prob(1.0),
            p23: percent_to_prob(10.0),
        };

        let mut data = qopt.as_bytes().to_vec();

        // Add TCA_NETEM_LOSS attribute (nested)
        // First the outer TCA_NETEM_LOSS, then nested NETEM_LOSS_GI
        let gi_bytes = gi_model.as_bytes();
        let inner_len = 4 + gi_bytes.len();
        let inner_aligned = (inner_len + 3) & !3;

        // Build nested attribute
        let mut nested = Vec::new();
        nested.extend_from_slice(&(inner_len as u16).to_ne_bytes());
        nested.extend_from_slice(&NETEM_LOSS_GI.to_ne_bytes());
        nested.extend_from_slice(gi_bytes);
        nested.resize(nested.len() + inner_aligned - inner_len, 0);

        let outer_len = 4 + nested.len();
        data.extend_from_slice(&(outer_len as u16).to_ne_bytes());
        data.extend_from_slice(&TCA_NETEM_LOSS.to_ne_bytes());
        data.extend_from_slice(&nested);

        let opts = parse_netem_options(&data);

        assert!(opts.loss_model.is_some());
        match opts.loss_model.unwrap() {
            NetemLossModel::GilbertIntuitive {
                p13,
                p31,
                p32,
                p14,
                p23,
            } => {
                assert!((p13 - 5.0).abs() < 0.1);
                assert!((p31 - 95.0).abs() < 0.1);
                assert!((p32 - 3.0).abs() < 0.1);
                assert!((p14 - 1.0).abs() < 0.1);
                assert!((p23 - 10.0).abs() < 0.1);
            }
            _ => panic!("Expected GilbertIntuitive model"),
        }
    }

    #[test]
    fn test_netem_parse_with_loss_model_ge() {
        use super::super::types::tc::qdisc::netem::*;

        let mut qopt = TcNetemQopt::new();
        qopt.limit = 1000;

        // Gilbert-Elliot model
        let ge_model = TcNetemGeModel {
            p: percent_to_prob(1.0),
            r: percent_to_prob(10.0),
            h: percent_to_prob(50.0),
            k1: percent_to_prob(0.0),
        };

        let mut data = qopt.as_bytes().to_vec();

        // Build nested attribute
        let ge_bytes = ge_model.as_bytes();
        let inner_len = 4 + ge_bytes.len();
        let inner_aligned = (inner_len + 3) & !3;

        let mut nested = Vec::new();
        nested.extend_from_slice(&(inner_len as u16).to_ne_bytes());
        nested.extend_from_slice(&NETEM_LOSS_GE.to_ne_bytes());
        nested.extend_from_slice(ge_bytes);
        nested.resize(nested.len() + inner_aligned - inner_len, 0);

        let outer_len = 4 + nested.len();
        data.extend_from_slice(&(outer_len as u16).to_ne_bytes());
        data.extend_from_slice(&TCA_NETEM_LOSS.to_ne_bytes());
        data.extend_from_slice(&nested);

        let opts = parse_netem_options(&data);

        assert!(opts.loss_model.is_some());
        match opts.loss_model.unwrap() {
            NetemLossModel::GilbertElliot { p, r, h, k1 } => {
                assert!((p - 1.0).abs() < 0.1);
                assert!((r - 10.0).abs() < 0.1);
                assert!((h - 50.0).abs() < 0.1);
                assert!((k1 - 0.0).abs() < 0.1);
            }
            _ => panic!("Expected GilbertElliot model"),
        }
    }
}
