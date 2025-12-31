//! Netem (Network Emulator) qdisc options.

use rip_netlink::types::tc::qdisc::netem::*;
use rip_netlink::{Error, MessageBuilder, Result};

/// Build netem qdisc options from parameters.
///
/// Supported parameters:
/// - `delay TIME [JITTER [CORRELATION]]` - Add delay
/// - `loss PERCENT [CORRELATION]` - Random packet loss
/// - `duplicate PERCENT [CORRELATION]` - Duplicate packets
/// - `corrupt PERCENT [CORRELATION]` - Corrupt packets
/// - `reorder PERCENT [CORRELATION]` - Reorder packets (requires delay)
/// - `gap DISTANCE` - Reorder gap
/// - `rate RATE [PACKETOVERHEAD [CELLSIZE [CELLOVERHEAD]]]` - Rate limit
/// - `limit PACKETS` - Queue limit
/// - `slot MIN_DELAY [MAX_DELAY] [packets N] [bytes N]` - Slot-based transmission
/// - `ecn` - Enable ECN marking
pub fn build(builder: &mut MessageBuilder, params: &[String]) -> Result<()> {
    let mut qopt = TcNetemQopt::new();
    let mut corr = TcNetemCorr::default();
    let mut reorder = TcNetemReorder::default();
    let mut corrupt = TcNetemCorrupt::default();
    let mut rate = TcNetemRate::default();
    let mut slot = TcNetemSlot::default();

    let mut has_corr = false;
    let mut has_reorder = false;
    let mut has_corrupt = false;
    let mut has_rate = false;
    let mut has_slot = false;
    let mut has_ecn = false;
    let mut latency64: Option<i64> = None;
    let mut jitter64: Option<i64> = None;
    let mut rate64: Option<u64> = None;

    let mut i = 0;
    while i < params.len() {
        match params[i].as_str() {
            "limit" if i + 1 < params.len() => {
                qopt.limit = params[i + 1]
                    .parse()
                    .map_err(|_| Error::InvalidMessage("invalid limit".into()))?;
                i += 2;
            }
            "delay" | "latency" if i + 1 < params.len() => {
                // delay TIME [JITTER [CORRELATION]]
                let delay = rip_lib::parse::get_time(&params[i + 1])
                    .map_err(|_| Error::InvalidMessage("invalid delay".into()))?;
                latency64 = Some(delay.as_nanos() as i64);
                i += 2;

                // Check for jitter
                if i < params.len() && !is_keyword(&params[i]) {
                    let jitter = rip_lib::parse::get_time(&params[i])
                        .map_err(|_| Error::InvalidMessage("invalid jitter".into()))?;
                    jitter64 = Some(jitter.as_nanos() as i64);
                    i += 1;

                    // Check for correlation
                    if i < params.len() && !is_keyword(&params[i]) {
                        corr.delay_corr = parse_percent(&params[i])?;
                        has_corr = true;
                        i += 1;
                    }
                }
            }
            "loss" if i + 1 < params.len() => {
                // loss [random] PERCENT [CORRELATION]
                i += 1;
                // Skip optional "random" keyword
                if params[i] == "random" && i + 1 < params.len() {
                    i += 1;
                }
                qopt.loss = parse_percent(&params[i])?;
                i += 1;

                // Check for correlation
                if i < params.len() && !is_keyword(&params[i]) {
                    corr.loss_corr = parse_percent(&params[i])?;
                    has_corr = true;
                    i += 1;
                }
            }
            "drop" if i + 1 < params.len() => {
                // Alias for loss
                i += 1;
                qopt.loss = parse_percent(&params[i])?;
                i += 1;
                if i < params.len() && !is_keyword(&params[i]) {
                    corr.loss_corr = parse_percent(&params[i])?;
                    has_corr = true;
                    i += 1;
                }
            }
            "duplicate" if i + 1 < params.len() => {
                // duplicate PERCENT [CORRELATION]
                i += 1;
                qopt.duplicate = parse_percent(&params[i])?;
                i += 1;

                // Check for correlation
                if i < params.len() && !is_keyword(&params[i]) {
                    corr.dup_corr = parse_percent(&params[i])?;
                    has_corr = true;
                    i += 1;
                }
            }
            "corrupt" if i + 1 < params.len() => {
                // corrupt PERCENT [CORRELATION]
                i += 1;
                corrupt.probability = parse_percent(&params[i])?;
                has_corrupt = true;
                i += 1;

                // Check for correlation
                if i < params.len() && !is_keyword(&params[i]) {
                    corrupt.correlation = parse_percent(&params[i])?;
                    i += 1;
                }
            }
            "reorder" if i + 1 < params.len() => {
                // reorder PERCENT [CORRELATION]
                i += 1;
                reorder.probability = parse_percent(&params[i])?;
                has_reorder = true;
                i += 1;

                // Check for correlation
                if i < params.len() && !is_keyword(&params[i]) {
                    reorder.correlation = parse_percent(&params[i])?;
                    i += 1;
                }
            }
            "gap" if i + 1 < params.len() => {
                qopt.gap = params[i + 1]
                    .parse()
                    .map_err(|_| Error::InvalidMessage("invalid gap".into()))?;
                i += 2;
            }
            "rate" if i + 1 < params.len() => {
                // rate RATE [PACKETOVERHEAD [CELLSIZE [CELLOVERHEAD]]]
                i += 1;
                let r = rip_lib::parse::get_rate(&params[i])
                    .map_err(|_| Error::InvalidMessage("invalid rate".into()))?;
                if r > u32::MAX as u64 {
                    rate64 = Some(r);
                    rate.rate = u32::MAX;
                } else {
                    rate.rate = r as u32;
                }
                has_rate = true;
                i += 1;

                // Packet overhead
                if i < params.len() && !is_keyword(&params[i]) {
                    rate.packet_overhead = params[i]
                        .parse()
                        .map_err(|_| Error::InvalidMessage("invalid packet overhead".into()))?;
                    i += 1;

                    // Cell size
                    if i < params.len() && !is_keyword(&params[i]) {
                        rate.cell_size = params[i]
                            .parse()
                            .map_err(|_| Error::InvalidMessage("invalid cell size".into()))?;
                        i += 1;

                        // Cell overhead
                        if i < params.len() && !is_keyword(&params[i]) {
                            rate.cell_overhead = params[i].parse().map_err(|_| {
                                Error::InvalidMessage("invalid cell overhead".into())
                            })?;
                            i += 1;
                        }
                    }
                }
            }
            "slot" if i + 1 < params.len() => {
                // slot MIN_DELAY [MAX_DELAY] [packets MAX_PACKETS] [bytes MAX_BYTES]
                i += 1;
                let min = rip_lib::parse::get_time(&params[i])
                    .map_err(|_| Error::InvalidMessage("invalid slot min_delay".into()))?;
                slot.min_delay = min.as_nanos() as i64;
                has_slot = true;
                i += 1;

                // Check for max delay
                if i < params.len() && !is_keyword(&params[i]) {
                    let max = rip_lib::parse::get_time(&params[i])
                        .map_err(|_| Error::InvalidMessage("invalid slot max_delay".into()))?;
                    slot.max_delay = max.as_nanos() as i64;
                    i += 1;
                } else {
                    slot.max_delay = slot.min_delay;
                }

                // Check for packets/bytes options
                while i + 1 < params.len() {
                    match params[i].as_str() {
                        "packets" => {
                            slot.max_packets = params[i + 1].parse().map_err(|_| {
                                Error::InvalidMessage("invalid slot packets".into())
                            })?;
                            i += 2;
                        }
                        "bytes" => {
                            slot.max_bytes = rip_lib::parse::get_size(&params[i + 1])
                                .map_err(|_| Error::InvalidMessage("invalid slot bytes".into()))?
                                as i32;
                            i += 2;
                        }
                        _ => break,
                    }
                }
            }
            "ecn" => {
                has_ecn = true;
                i += 1;
            }
            _ => i += 1,
        }
    }

    // Validate: reorder requires delay
    if has_reorder && latency64.is_none() {
        return Err(Error::InvalidMessage(
            "netem: reorder requires delay to be specified".into(),
        ));
    }

    // If reorder is set but no gap, default gap to 1
    if has_reorder && qopt.gap == 0 {
        qopt.gap = 1;
    }

    // Validate: ECN requires loss
    if has_ecn && qopt.loss == 0 {
        return Err(Error::InvalidMessage(
            "netem: ecn requires loss to be specified".into(),
        ));
    }

    // Build the message - netem options go directly after TCA_OPTIONS start
    builder.append(&qopt);

    // Add 64-bit latency if set
    if let Some(lat) = latency64 {
        builder.append_attr(TCA_NETEM_LATENCY64, &lat.to_ne_bytes());
    }

    // Add 64-bit jitter if set
    if let Some(jit) = jitter64 {
        builder.append_attr(TCA_NETEM_JITTER64, &jit.to_ne_bytes());
    }

    // Add correlation if any were set
    if has_corr {
        builder.append_attr(TCA_NETEM_CORR, corr.as_bytes());
    }

    // Add reorder if set
    if has_reorder {
        builder.append_attr(TCA_NETEM_REORDER, reorder.as_bytes());
    }

    // Add corrupt if set
    if has_corrupt {
        builder.append_attr(TCA_NETEM_CORRUPT, corrupt.as_bytes());
    }

    // Add rate if set
    if has_rate {
        builder.append_attr(TCA_NETEM_RATE, rate.as_bytes());
        if let Some(r64) = rate64 {
            builder.append_attr(TCA_NETEM_RATE64, &r64.to_ne_bytes());
        }
    }

    // Add slot if set
    if has_slot {
        builder.append_attr(TCA_NETEM_SLOT, slot.as_bytes());
    }

    // Add ECN if set
    if has_ecn {
        builder.append_attr_u32(TCA_NETEM_ECN, 1);
    }

    Ok(())
}

/// Parse a percentage string like "10%" or "0.5%" into a netem probability.
fn parse_percent(s: &str) -> Result<u32> {
    let s = s.trim_end_matches('%');
    let percent: f64 = s
        .parse()
        .map_err(|_| Error::InvalidMessage("invalid percentage".into()))?;
    Ok(percent_to_prob(percent))
}

/// Check if a string is a netem keyword.
fn is_keyword(s: &str) -> bool {
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
            | "state"
            | "gemodel"
            | "packets"
            | "bytes"
    )
}
