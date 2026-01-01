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
    /// Added delay in microseconds.
    pub delay_us: u32,
    /// Delay jitter in microseconds.
    pub jitter_us: u32,
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
    /// Queue limit in packets.
    pub limit: u32,
    /// Reorder gap.
    pub gap: u32,
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
        opts.delay_us = u32::from_ne_bytes(data[0..4].try_into().unwrap());
        opts.limit = u32::from_ne_bytes(data[4..8].try_into().unwrap());
        let loss_raw = u32::from_ne_bytes(data[8..12].try_into().unwrap());
        opts.loss_percent = prob_to_percent(loss_raw);
        opts.gap = u32::from_ne_bytes(data[12..16].try_into().unwrap());
        let dup_raw = u32::from_ne_bytes(data[16..20].try_into().unwrap());
        opts.duplicate_percent = prob_to_percent(dup_raw);
        opts.jitter_us = u32::from_ne_bytes(data[20..24].try_into().unwrap());
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
                if payload.len() >= 4 {
                    opts.rate = u32::from_ne_bytes(payload[0..4].try_into().unwrap()) as u64;
                }
            }
            TCA_NETEM_RATE64 => {
                if payload.len() >= 8 {
                    opts.rate = u64::from_ne_bytes(payload[..8].try_into().unwrap());
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
}
