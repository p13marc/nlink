//! CAKE qdisc options.

use rip_netlink::types::tc::qdisc::cake::*;
use rip_netlink::{Error, MessageBuilder, Result};

/// Build CAKE qdisc options from parameters.
///
/// Supported parameters:
/// - `bandwidth RATE` - Bandwidth limit (e.g., "100mbit")
/// - `rtt TIME` - RTT estimate (e.g., "100ms")
/// - `target TIME` - Target delay
/// - `overhead BYTES` - Per-packet overhead (can be negative)
/// - `mpu BYTES` - Minimum packet unit
/// - `diffserv3` / `diffserv4` / `diffserv8` / `besteffort` / `precedence` - Diffserv mode
/// - `flowblind` / `srchost` / `dsthost` / `hosts` / `flows` / `dual-srchost` /
///   `dual-dsthost` / `triple-isolate` - Flow isolation mode
/// - `noatm` / `atm` / `ptm` - ATM/PTM mode
/// - `raw` - Disable overhead compensation
/// - `nat` / `nonat` - Enable/disable NAT mode
/// - `wash` / `nowash` - Enable/disable DSCP washing
/// - `ingress` / `egress` - Ingress/egress mode
/// - `ack-filter` / `ack-filter-aggressive` / `no-ack-filter` - ACK filtering mode
/// - `split-gso` / `no-split-gso` - GSO splitting
/// - `memlimit SIZE` - Memory limit
/// - `fwmark MASK` - fwmark mask for flow classification
/// - `autorate-ingress` - Enable autorate
pub fn build(builder: &mut MessageBuilder, params: &[String]) -> Result<()> {
    let mut i = 0;
    while i < params.len() {
        match params[i].as_str() {
            "bandwidth" if i + 1 < params.len() => {
                let rate = rip_lib::parse::get_rate(&params[i + 1])
                    .map_err(|_| Error::InvalidMessage("invalid bandwidth".into()))?;
                builder.append_attr_u64(TCA_CAKE_BASE_RATE64, rate);
                i += 2;
            }
            "unlimited" => {
                builder.append_attr_u64(TCA_CAKE_BASE_RATE64, 0);
                i += 1;
            }
            "rtt" if i + 1 < params.len() => {
                let rtt = rip_lib::parse::get_time(&params[i + 1])
                    .map_err(|_| Error::InvalidMessage("invalid rtt".into()))?;
                builder.append_attr_u32(TCA_CAKE_RTT, rtt.as_micros() as u32);
                i += 2;
            }
            "target" if i + 1 < params.len() => {
                let target = rip_lib::parse::get_time(&params[i + 1])
                    .map_err(|_| Error::InvalidMessage("invalid target".into()))?;
                builder.append_attr_u32(TCA_CAKE_TARGET, target.as_micros() as u32);
                i += 2;
            }
            "overhead" if i + 1 < params.len() => {
                let overhead: i32 = params[i + 1]
                    .parse()
                    .map_err(|_| Error::InvalidMessage("invalid overhead".into()))?;
                builder.append_attr(TCA_CAKE_OVERHEAD, &overhead.to_ne_bytes());
                i += 2;
            }
            "mpu" if i + 1 < params.len() => {
                let mpu: u32 = params[i + 1]
                    .parse()
                    .map_err(|_| Error::InvalidMessage("invalid mpu".into()))?;
                builder.append_attr_u32(TCA_CAKE_MPU, mpu);
                i += 2;
            }
            "memlimit" if i + 1 < params.len() => {
                let mem = rip_lib::parse::get_size(&params[i + 1])
                    .map_err(|_| Error::InvalidMessage("invalid memlimit".into()))?;
                builder.append_attr_u32(TCA_CAKE_MEMORY, mem as u32);
                i += 2;
            }
            "fwmark" if i + 1 < params.len() => {
                let mask: u32 = params[i + 1]
                    .parse()
                    .map_err(|_| Error::InvalidMessage("invalid fwmark".into()))?;
                builder.append_attr_u32(TCA_CAKE_FWMARK, mask);
                i += 2;
            }
            // Diffserv modes
            "diffserv3" => {
                builder.append_attr_u32(TCA_CAKE_DIFFSERV_MODE, CAKE_DIFFSERV_DIFFSERV3);
                i += 1;
            }
            "diffserv4" => {
                builder.append_attr_u32(TCA_CAKE_DIFFSERV_MODE, CAKE_DIFFSERV_DIFFSERV4);
                i += 1;
            }
            "diffserv8" => {
                builder.append_attr_u32(TCA_CAKE_DIFFSERV_MODE, CAKE_DIFFSERV_DIFFSERV8);
                i += 1;
            }
            "besteffort" => {
                builder.append_attr_u32(TCA_CAKE_DIFFSERV_MODE, CAKE_DIFFSERV_BESTEFFORT);
                i += 1;
            }
            "precedence" => {
                builder.append_attr_u32(TCA_CAKE_DIFFSERV_MODE, CAKE_DIFFSERV_PRECEDENCE);
                i += 1;
            }
            // Flow modes
            "flowblind" => {
                builder.append_attr_u32(TCA_CAKE_FLOW_MODE, CAKE_FLOW_NONE);
                i += 1;
            }
            "srchost" => {
                builder.append_attr_u32(TCA_CAKE_FLOW_MODE, CAKE_FLOW_SRC_IP);
                i += 1;
            }
            "dsthost" => {
                builder.append_attr_u32(TCA_CAKE_FLOW_MODE, CAKE_FLOW_DST_IP);
                i += 1;
            }
            "hosts" => {
                builder.append_attr_u32(TCA_CAKE_FLOW_MODE, CAKE_FLOW_HOSTS);
                i += 1;
            }
            "flows" => {
                builder.append_attr_u32(TCA_CAKE_FLOW_MODE, CAKE_FLOW_FLOWS);
                i += 1;
            }
            "dual-srchost" => {
                builder.append_attr_u32(TCA_CAKE_FLOW_MODE, CAKE_FLOW_DUAL_SRC);
                i += 1;
            }
            "dual-dsthost" => {
                builder.append_attr_u32(TCA_CAKE_FLOW_MODE, CAKE_FLOW_DUAL_DST);
                i += 1;
            }
            "triple-isolate" => {
                builder.append_attr_u32(TCA_CAKE_FLOW_MODE, CAKE_FLOW_TRIPLE);
                i += 1;
            }
            // ATM modes
            "noatm" => {
                builder.append_attr_u32(TCA_CAKE_ATM, CAKE_ATM_NONE);
                i += 1;
            }
            "atm" => {
                builder.append_attr_u32(TCA_CAKE_ATM, CAKE_ATM_ATM);
                i += 1;
            }
            "ptm" => {
                builder.append_attr_u32(TCA_CAKE_ATM, CAKE_ATM_PTM);
                i += 1;
            }
            // Other options
            "raw" => {
                builder.append_attr_u32(TCA_CAKE_RAW, 1);
                i += 1;
            }
            "nat" => {
                builder.append_attr_u32(TCA_CAKE_NAT, 1);
                i += 1;
            }
            "nonat" => {
                builder.append_attr_u32(TCA_CAKE_NAT, 0);
                i += 1;
            }
            "wash" => {
                builder.append_attr_u32(TCA_CAKE_WASH, 1);
                i += 1;
            }
            "nowash" => {
                builder.append_attr_u32(TCA_CAKE_WASH, 0);
                i += 1;
            }
            "ingress" => {
                builder.append_attr_u32(TCA_CAKE_INGRESS, 1);
                i += 1;
            }
            "egress" => {
                builder.append_attr_u32(TCA_CAKE_INGRESS, 0);
                i += 1;
            }
            "ack-filter" => {
                builder.append_attr_u32(TCA_CAKE_ACK_FILTER, CAKE_ACK_FILTER);
                i += 1;
            }
            "ack-filter-aggressive" => {
                builder.append_attr_u32(TCA_CAKE_ACK_FILTER, CAKE_ACK_AGGRESSIVE);
                i += 1;
            }
            "no-ack-filter" => {
                builder.append_attr_u32(TCA_CAKE_ACK_FILTER, CAKE_ACK_NONE);
                i += 1;
            }
            "split-gso" => {
                builder.append_attr_u32(TCA_CAKE_SPLIT_GSO, 1);
                i += 1;
            }
            "no-split-gso" => {
                builder.append_attr_u32(TCA_CAKE_SPLIT_GSO, 0);
                i += 1;
            }
            "autorate-ingress" => {
                builder.append_attr_u32(TCA_CAKE_AUTORATE, 1);
                i += 1;
            }
            _ => i += 1,
        }
    }
    Ok(())
}
