//! FQ_CoDel qdisc options.

use rip_netlink::types::tc::qdisc::fq_codel::*;
use rip_netlink::{Error, MessageBuilder, Result};

/// Build FQ_CoDel qdisc options from parameters.
///
/// Supported parameters:
/// - `limit PACKETS` - Hard limit on queue size
/// - `target TIME` - Target delay (e.g., "5ms")
/// - `interval TIME` - Width of moving time window (e.g., "100ms")
/// - `flows NUMBER` - Number of flows
/// - `quantum BYTES` - Quantum of bytes to serve per round
/// - `ce_threshold TIME` - ECN CE marking threshold
/// - `memory_limit BYTES` - Memory limit
/// - `ecn` / `noecn` - Enable/disable ECN
pub fn build(builder: &mut MessageBuilder, params: &[String]) -> Result<()> {
    let mut i = 0;
    while i < params.len() {
        match params[i].as_str() {
            "limit" if i + 1 < params.len() => {
                let limit: u32 = params[i + 1]
                    .parse()
                    .map_err(|_| Error::InvalidMessage("invalid limit".into()))?;
                builder.append_attr_u32(TCA_FQ_CODEL_LIMIT, limit);
                i += 2;
            }
            "target" if i + 1 < params.len() => {
                let target = rip_lib::parse::get_time(&params[i + 1])
                    .map_err(|_| Error::InvalidMessage("invalid target".into()))?;
                builder.append_attr_u32(TCA_FQ_CODEL_TARGET, target.as_micros() as u32);
                i += 2;
            }
            "interval" if i + 1 < params.len() => {
                let interval = rip_lib::parse::get_time(&params[i + 1])
                    .map_err(|_| Error::InvalidMessage("invalid interval".into()))?;
                builder.append_attr_u32(TCA_FQ_CODEL_INTERVAL, interval.as_micros() as u32);
                i += 2;
            }
            "flows" if i + 1 < params.len() => {
                let flows: u32 = params[i + 1]
                    .parse()
                    .map_err(|_| Error::InvalidMessage("invalid flows".into()))?;
                builder.append_attr_u32(TCA_FQ_CODEL_FLOWS, flows);
                i += 2;
            }
            "quantum" if i + 1 < params.len() => {
                let quantum: u32 = params[i + 1]
                    .parse()
                    .map_err(|_| Error::InvalidMessage("invalid quantum".into()))?;
                builder.append_attr_u32(TCA_FQ_CODEL_QUANTUM, quantum);
                i += 2;
            }
            "ce_threshold" if i + 1 < params.len() => {
                let ce = rip_lib::parse::get_time(&params[i + 1])
                    .map_err(|_| Error::InvalidMessage("invalid ce_threshold".into()))?;
                builder.append_attr_u32(TCA_FQ_CODEL_CE_THRESHOLD, ce.as_micros() as u32);
                i += 2;
            }
            "memory_limit" if i + 1 < params.len() => {
                let mem = rip_lib::parse::get_size(&params[i + 1])
                    .map_err(|_| Error::InvalidMessage("invalid memory_limit".into()))?;
                builder.append_attr_u32(TCA_FQ_CODEL_MEMORY_LIMIT, mem as u32);
                i += 2;
            }
            "ecn" => {
                builder.append_attr_u32(TCA_FQ_CODEL_ECN, 1);
                i += 1;
            }
            "noecn" => {
                builder.append_attr_u32(TCA_FQ_CODEL_ECN, 0);
                i += 1;
            }
            _ => i += 1,
        }
    }
    Ok(())
}
