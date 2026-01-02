//! HTB (Hierarchical Token Bucket) qdisc options.

use crate::netlink::types::tc::qdisc::htb::*;
use crate::netlink::{Error, MessageBuilder, Result};
use crate::tc::handle::parse_handle;

/// Build HTB qdisc options from parameters.
///
/// Supported parameters:
/// - `default CLASS` - Default class for unclassified traffic
/// - `r2q NUMBER` - Rate to quantum ratio
/// - `direct_qlen NUMBER` - Direct queue length
pub fn build(builder: &mut MessageBuilder, params: &[String]) -> Result<()> {
    let mut default_class: u32 = 0;
    let mut r2q: u32 = 10;
    let mut direct_qlen: Option<u32> = None;

    let mut i = 0;
    while i < params.len() {
        match params[i].as_str() {
            "default" if i + 1 < params.len() => {
                // Parse as hex handle (e.g., "10" or "1:10")
                let s = &params[i + 1];
                default_class = if s.contains(':') {
                    parse_handle(s)
                        .ok_or_else(|| Error::InvalidMessage("invalid default class".into()))?
                } else {
                    u32::from_str_radix(s, 16)
                        .map_err(|_| Error::InvalidMessage("invalid default class".into()))?
                };
                i += 2;
            }
            "r2q" if i + 1 < params.len() => {
                r2q = params[i + 1]
                    .parse()
                    .map_err(|_| Error::InvalidMessage("invalid r2q".into()))?;
                i += 2;
            }
            "direct_qlen" if i + 1 < params.len() => {
                direct_qlen = Some(
                    params[i + 1]
                        .parse()
                        .map_err(|_| Error::InvalidMessage("invalid direct_qlen".into()))?,
                );
                i += 2;
            }
            _ => i += 1,
        }
    }

    // Build HTB global init structure
    let mut glob = TcHtbGlob::new().with_default(default_class);
    glob.rate2quantum = r2q;

    builder.append_attr(TCA_HTB_INIT, glob.as_bytes());

    if let Some(qlen) = direct_qlen {
        builder.append_attr_u32(TCA_HTB_DIRECT_QLEN, qlen);
    }

    Ok(())
}
