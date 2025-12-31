//! PRIO qdisc options.

use rip_netlink::types::tc::qdisc::prio::*;
use rip_netlink::{Error, MessageBuilder, Result};

/// Build PRIO qdisc options from parameters.
///
/// Supported parameters:
/// - `bands NUMBER` - Number of bands (default: 3)
/// - `priomap P0 P1 ... P15` - Priority to band mapping (16 values)
pub fn build(builder: &mut MessageBuilder, params: &[String]) -> Result<()> {
    let mut bands: i32 = 3;
    let mut priomap = [1u8, 2, 2, 2, 1, 2, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1];

    let mut i = 0;
    while i < params.len() {
        match params[i].as_str() {
            "bands" if i + 1 < params.len() => {
                bands = params[i + 1]
                    .parse()
                    .map_err(|_| Error::InvalidMessage("invalid bands".into()))?;
                i += 2;
            }
            "priomap" if i + 16 < params.len() => {
                for j in 0..16 {
                    priomap[j] = params[i + 1 + j]
                        .parse()
                        .map_err(|_| Error::InvalidMessage("invalid priomap value".into()))?;
                }
                i += 17;
            }
            _ => i += 1,
        }
    }

    let qopt = TcPrioQopt { bands, priomap };

    // PRIO options are sent directly, not as a nested attribute
    builder.append(&qopt);

    Ok(())
}
