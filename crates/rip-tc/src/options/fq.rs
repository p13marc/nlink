//! FQ (Fair Queue) qdisc options.

use rip_netlink::types::tc::qdisc::fq::*;
use rip_netlink::{Error, MessageBuilder, Result};

/// Build FQ qdisc options from parameters.
///
/// Supported parameters:
/// - `limit PACKETS` - Total packet limit
/// - `flow_limit PACKETS` - Per-flow packet limit
/// - `quantum BYTES` - Quantum per round
/// - `initial_quantum BYTES` - Initial quantum for new flows
/// - `maxrate RATE` - Maximum rate per flow (e.g., "1mbit")
/// - `buckets NUMBER` - Number of buckets (log2)
/// - `orphan_mask MASK` - Orphan mask
/// - `pacing` / `nopacing` - Enable/disable pacing
/// - `ce_threshold TIME` - ECN CE threshold
/// - `horizon TIME` - Horizon time
/// - `horizon_drop` / `horizon_cap` - Drop or cap packets beyond horizon
pub fn build(builder: &mut MessageBuilder, params: &[String]) -> Result<()> {
    let mut i = 0;
    while i < params.len() {
        match params[i].as_str() {
            "limit" if i + 1 < params.len() => {
                let limit: u32 = params[i + 1]
                    .parse()
                    .map_err(|_| Error::InvalidMessage("invalid limit".into()))?;
                builder.append_attr_u32(TCA_FQ_PLIMIT, limit);
                i += 2;
            }
            "flow_limit" if i + 1 < params.len() => {
                let limit: u32 = params[i + 1]
                    .parse()
                    .map_err(|_| Error::InvalidMessage("invalid flow_limit".into()))?;
                builder.append_attr_u32(TCA_FQ_FLOW_PLIMIT, limit);
                i += 2;
            }
            "quantum" if i + 1 < params.len() => {
                let quantum: u32 = params[i + 1]
                    .parse()
                    .map_err(|_| Error::InvalidMessage("invalid quantum".into()))?;
                builder.append_attr_u32(TCA_FQ_QUANTUM, quantum);
                i += 2;
            }
            "initial_quantum" if i + 1 < params.len() => {
                let quantum: u32 = params[i + 1]
                    .parse()
                    .map_err(|_| Error::InvalidMessage("invalid initial_quantum".into()))?;
                builder.append_attr_u32(TCA_FQ_INITIAL_QUANTUM, quantum);
                i += 2;
            }
            "maxrate" if i + 1 < params.len() => {
                let rate = rip_lib::parse::get_rate(&params[i + 1])
                    .map_err(|_| Error::InvalidMessage("invalid maxrate".into()))?;
                builder.append_attr_u32(TCA_FQ_FLOW_MAX_RATE, rate as u32);
                i += 2;
            }
            "buckets" if i + 1 < params.len() => {
                let buckets: u32 = params[i + 1]
                    .parse()
                    .map_err(|_| Error::InvalidMessage("invalid buckets".into()))?;
                // Convert to log2
                let log2 = (buckets as f64).log2() as u32;
                builder.append_attr_u32(TCA_FQ_BUCKETS_LOG, log2);
                i += 2;
            }
            "orphan_mask" if i + 1 < params.len() => {
                let mask: u32 = params[i + 1]
                    .parse()
                    .map_err(|_| Error::InvalidMessage("invalid orphan_mask".into()))?;
                builder.append_attr_u32(TCA_FQ_ORPHAN_MASK, mask);
                i += 2;
            }
            "refill_delay" if i + 1 < params.len() => {
                let delay = rip_lib::parse::get_time(&params[i + 1])
                    .map_err(|_| Error::InvalidMessage("invalid refill_delay".into()))?;
                builder.append_attr_u32(TCA_FQ_FLOW_REFILL_DELAY, delay.as_micros() as u32);
                i += 2;
            }
            "low_rate_threshold" if i + 1 < params.len() => {
                let rate = rip_lib::parse::get_rate(&params[i + 1])
                    .map_err(|_| Error::InvalidMessage("invalid low_rate_threshold".into()))?;
                builder.append_attr_u32(TCA_FQ_LOW_RATE_THRESHOLD, rate as u32);
                i += 2;
            }
            "ce_threshold" if i + 1 < params.len() => {
                let ce = rip_lib::parse::get_time(&params[i + 1])
                    .map_err(|_| Error::InvalidMessage("invalid ce_threshold".into()))?;
                builder.append_attr_u32(TCA_FQ_CE_THRESHOLD, ce.as_micros() as u32);
                i += 2;
            }
            "horizon" if i + 1 < params.len() => {
                let horizon = rip_lib::parse::get_time(&params[i + 1])
                    .map_err(|_| Error::InvalidMessage("invalid horizon".into()))?;
                builder.append_attr_u32(TCA_FQ_HORIZON, horizon.as_micros() as u32);
                i += 2;
            }
            "pacing" => {
                builder.append_attr_u32(TCA_FQ_RATE_ENABLE, 1);
                i += 1;
            }
            "nopacing" => {
                builder.append_attr_u32(TCA_FQ_RATE_ENABLE, 0);
                i += 1;
            }
            "horizon_drop" => {
                builder.append_attr_u8(TCA_FQ_HORIZON_DROP, 1);
                i += 1;
            }
            "horizon_cap" => {
                builder.append_attr_u8(TCA_FQ_HORIZON_DROP, 0);
                i += 1;
            }
            _ => i += 1,
        }
    }
    Ok(())
}
