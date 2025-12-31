//! SFQ (Stochastic Fairness Queueing) qdisc options.

use rip_netlink::types::tc::qdisc::sfq::*;
use rip_netlink::{Error, MessageBuilder, Result};

/// Build SFQ qdisc options from parameters.
///
/// Supported parameters:
/// - `quantum BYTES` - Amount of bytes to dequeue per round
/// - `perturb SECONDS` - Interval for hash perturbation
/// - `limit PACKETS` - Queue limit in packets
/// - `divisor NUMBER` - Hash table divisor
pub fn build(builder: &mut MessageBuilder, params: &[String]) -> Result<()> {
    let mut qopt = TcSfqQopt {
        quantum: 0, // Let kernel calculate default
        perturb_period: 0,
        limit: 127,
        ..Default::default()
    };

    let mut i = 0;
    while i < params.len() {
        match params[i].as_str() {
            "quantum" if i + 1 < params.len() => {
                qopt.quantum = rip_lib::parse::get_size(&params[i + 1])
                    .map_err(|_| Error::InvalidMessage("invalid quantum".into()))?
                    as u32;
                i += 2;
            }
            "perturb" if i + 1 < params.len() => {
                qopt.perturb_period = params[i + 1]
                    .parse()
                    .map_err(|_| Error::InvalidMessage("invalid perturb".into()))?;
                i += 2;
            }
            "limit" if i + 1 < params.len() => {
                qopt.limit = params[i + 1]
                    .parse()
                    .map_err(|_| Error::InvalidMessage("invalid limit".into()))?;
                i += 2;
            }
            "divisor" if i + 1 < params.len() => {
                qopt.divisor = params[i + 1]
                    .parse()
                    .map_err(|_| Error::InvalidMessage("invalid divisor".into()))?;
                i += 2;
            }
            _ => i += 1,
        }
    }

    builder.append(&qopt);

    Ok(())
}
