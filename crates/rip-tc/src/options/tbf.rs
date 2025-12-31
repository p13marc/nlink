//! TBF (Token Bucket Filter) qdisc options.

use rip_netlink::types::tc::qdisc::tbf::*;
use rip_netlink::types::tc::qdisc::TcRateSpec;
use rip_netlink::{Error, MessageBuilder, Result};

/// Build TBF qdisc options from parameters.
///
/// Supported parameters:
/// - `rate RATE` - Rate limit (required, e.g., "1mbit")
/// - `burst BYTES` - Burst size (required, e.g., "32kb")
/// - `limit BYTES` - Queue limit in bytes
/// - `latency TIME` - Maximum latency (alternative to limit)
/// - `peakrate RATE` - Peak rate limit
/// - `mtu BYTES` - MTU for peakrate bucket
pub fn build(builder: &mut MessageBuilder, params: &[String]) -> Result<()> {
    let mut rate: u64 = 0;
    let mut burst: u32 = 0;
    let mut limit: u32 = 0;
    let mut latency: Option<u32> = None;
    let mut peakrate: u64 = 0;
    let mut mtu: u32 = 0;

    let mut i = 0;
    while i < params.len() {
        match params[i].as_str() {
            "rate" if i + 1 < params.len() => {
                rate = rip_lib::parse::get_rate(&params[i + 1])
                    .map_err(|_| Error::InvalidMessage("invalid rate".into()))?;
                i += 2;
            }
            "burst" | "buffer" | "maxburst" if i + 1 < params.len() => {
                burst = rip_lib::parse::get_size(&params[i + 1])
                    .map_err(|_| Error::InvalidMessage("invalid burst".into()))?
                    as u32;
                i += 2;
            }
            "limit" if i + 1 < params.len() => {
                limit = rip_lib::parse::get_size(&params[i + 1])
                    .map_err(|_| Error::InvalidMessage("invalid limit".into()))?
                    as u32;
                i += 2;
            }
            "latency" if i + 1 < params.len() => {
                let lat = rip_lib::parse::get_time(&params[i + 1])
                    .map_err(|_| Error::InvalidMessage("invalid latency".into()))?;
                latency = Some(lat.as_micros() as u32);
                i += 2;
            }
            "peakrate" if i + 1 < params.len() => {
                peakrate = rip_lib::parse::get_rate(&params[i + 1])
                    .map_err(|_| Error::InvalidMessage("invalid peakrate".into()))?;
                i += 2;
            }
            "mtu" | "minburst" if i + 1 < params.len() => {
                mtu = rip_lib::parse::get_size(&params[i + 1])
                    .map_err(|_| Error::InvalidMessage("invalid mtu".into()))?
                    as u32;
                i += 2;
            }
            _ => i += 1,
        }
    }

    if rate == 0 {
        return Err(Error::InvalidMessage("tbf: rate is required".into()));
    }
    if burst == 0 {
        return Err(Error::InvalidMessage("tbf: burst is required".into()));
    }

    // Calculate limit from latency if not specified
    if limit == 0 {
        if let Some(lat_us) = latency {
            // limit = rate * latency + burst
            limit = ((rate * lat_us as u64) / 1_000_000 + burst as u64) as u32;
        } else {
            return Err(Error::InvalidMessage(
                "tbf: either limit or latency is required".into(),
            ));
        }
    }

    // Calculate buffer time (in ticks)
    let buffer = if rate > 0 {
        (burst as u64 * 1_000_000 / rate) as u32
    } else {
        burst
    };

    // Build the tc_tbf_qopt structure
    let qopt = TcTbfQopt {
        rate: TcRateSpec::new(rate as u32),
        peakrate: if peakrate > 0 {
            TcRateSpec::new(peakrate as u32)
        } else {
            TcRateSpec::default()
        },
        limit,
        buffer,
        mtu,
    };

    builder.append_attr(TCA_TBF_PARMS, qopt.as_bytes());

    // For rates > 4Gbps, use 64-bit rate attributes
    if rate > u32::MAX as u64 {
        builder.append_attr(TCA_TBF_RATE64, &rate.to_ne_bytes());
    }
    if peakrate > u32::MAX as u64 {
        builder.append_attr(TCA_TBF_PRATE64, &peakrate.to_ne_bytes());
    }

    // Add burst attribute (kernel expects it separately too)
    builder.append_attr_u32(TCA_TBF_BURST, burst);

    Ok(())
}
