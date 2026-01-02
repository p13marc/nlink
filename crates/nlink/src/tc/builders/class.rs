//! Class message builders.
//!
//! This module provides high-level builders for creating class netlink messages.

use crate::netlink::connection::{ack_request, create_request, replace_request};
use crate::netlink::message::NlMsgType;
use crate::netlink::types::tc::{TcMsg, TcaAttr, tc_handle};
use crate::netlink::{Connection, MessageBuilder, Result};

/// Build a TcMsg with common fields for class operations.
fn build_tcmsg(dev: &str, parent: &str, classid: &str) -> Result<TcMsg> {
    let ifindex = crate::util::get_ifindex(dev).map_err(crate::netlink::Error::InvalidMessage)?;

    let parent_handle = tc_handle::parse(parent).ok_or_else(|| {
        crate::netlink::Error::InvalidMessage(format!("invalid parent handle: {}", parent))
    })?;

    let class_handle = tc_handle::parse(classid).ok_or_else(|| {
        crate::netlink::Error::InvalidMessage(format!("invalid classid: {}", classid))
    })?;

    Ok(TcMsg::new()
        .with_ifindex(ifindex as i32)
        .with_parent(parent_handle)
        .with_handle(class_handle))
}

/// Add class-specific options to the message builder.
pub fn add_options(builder: &mut MessageBuilder, kind: &str, params: &[String]) -> Result<()> {
    if params.is_empty() {
        return Ok(());
    }

    let options_token = builder.nest_start(TcaAttr::Options as u16);

    match kind {
        "htb" => add_htb_options(builder, params)?,
        _ => {
            // Unknown class type - just ignore parameters
        }
    }

    builder.nest_end(options_token);
    Ok(())
}

/// Add a new class.
///
/// # Arguments
/// * `conn` - The netlink connection
/// * `dev` - Device name
/// * `parent` - Parent handle (e.g., "1:0")
/// * `classid` - Class ID (e.g., "1:1")
/// * `kind` - Class type (e.g., "htb")
/// * `params` - Type-specific parameters
pub async fn add(
    conn: &Connection,
    dev: &str,
    parent: &str,
    classid: &str,
    kind: &str,
    params: &[String],
) -> Result<()> {
    let tcmsg = build_tcmsg(dev, parent, classid)?;

    let mut builder = create_request(NlMsgType::RTM_NEWTCLASS);
    builder.append(&tcmsg);
    builder.append_attr_str(TcaAttr::Kind as u16, kind);

    add_options(&mut builder, kind, params)?;

    conn.request_ack(builder).await?;
    Ok(())
}

/// Delete a class.
///
/// # Arguments
/// * `conn` - The netlink connection
/// * `dev` - Device name
/// * `parent` - Parent handle
/// * `classid` - Class ID to delete
pub async fn del(conn: &Connection, dev: &str, parent: &str, classid: &str) -> Result<()> {
    let tcmsg = build_tcmsg(dev, parent, classid)?;

    let mut builder = ack_request(NlMsgType::RTM_DELTCLASS);
    builder.append(&tcmsg);

    conn.request_ack(builder).await?;
    Ok(())
}

/// Change a class's parameters.
///
/// # Arguments
/// * `conn` - The netlink connection
/// * `dev` - Device name
/// * `parent` - Parent handle
/// * `classid` - Class ID
/// * `kind` - Class type
/// * `params` - Type-specific parameters
pub async fn change(
    conn: &Connection,
    dev: &str,
    parent: &str,
    classid: &str,
    kind: &str,
    params: &[String],
) -> Result<()> {
    let tcmsg = build_tcmsg(dev, parent, classid)?;

    let mut builder = ack_request(NlMsgType::RTM_NEWTCLASS);
    builder.append(&tcmsg);
    builder.append_attr_str(TcaAttr::Kind as u16, kind);

    add_options(&mut builder, kind, params)?;

    conn.request_ack(builder).await?;
    Ok(())
}

/// Replace a class (add or update).
///
/// # Arguments
/// * `conn` - The netlink connection
/// * `dev` - Device name
/// * `parent` - Parent handle
/// * `classid` - Class ID
/// * `kind` - Class type
/// * `params` - Type-specific parameters
pub async fn replace(
    conn: &Connection,
    dev: &str,
    parent: &str,
    classid: &str,
    kind: &str,
    params: &[String],
) -> Result<()> {
    let tcmsg = build_tcmsg(dev, parent, classid)?;

    let mut builder = replace_request(NlMsgType::RTM_NEWTCLASS);
    builder.append(&tcmsg);
    builder.append_attr_str(TcaAttr::Kind as u16, kind);

    add_options(&mut builder, kind, params)?;

    conn.request_ack(builder).await?;
    Ok(())
}

/// Add HTB class options.
fn add_htb_options(builder: &mut MessageBuilder, params: &[String]) -> Result<()> {
    use crate::netlink::types::tc::qdisc::TcRateSpec;
    use crate::netlink::types::tc::qdisc::htb::*;

    let mut rate64: u64 = 0;
    let mut ceil64: u64 = 0;
    let mut burst: u32 = 0;
    let mut cburst: u32 = 0;
    let mut prio: u32 = 0;
    let mut quantum: u32 = 0;
    let mut mtu: u32 = 1600;
    let mut mpu: u16 = 0;
    let mut overhead: u16 = 0;

    let mut i = 0;
    while i < params.len() {
        match params[i].as_str() {
            "rate" if i + 1 < params.len() => {
                rate64 = crate::util::parse::get_rate(&params[i + 1])
                    .map_err(|_| crate::netlink::Error::InvalidMessage("invalid rate".into()))?;
                i += 2;
            }
            "ceil" if i + 1 < params.len() => {
                ceil64 = crate::util::parse::get_rate(&params[i + 1])
                    .map_err(|_| crate::netlink::Error::InvalidMessage("invalid ceil".into()))?;
                i += 2;
            }
            "burst" | "buffer" | "maxburst" if i + 1 < params.len() => {
                burst = crate::util::parse::get_size(&params[i + 1])
                    .map_err(|_| crate::netlink::Error::InvalidMessage("invalid burst".into()))?
                    as u32;
                i += 2;
            }
            "cburst" | "cbuffer" | "cmaxburst" if i + 1 < params.len() => {
                cburst = crate::util::parse::get_size(&params[i + 1])
                    .map_err(|_| crate::netlink::Error::InvalidMessage("invalid cburst".into()))?
                    as u32;
                i += 2;
            }
            "prio" if i + 1 < params.len() => {
                prio = params[i + 1]
                    .parse()
                    .map_err(|_| crate::netlink::Error::InvalidMessage("invalid prio".into()))?;
                i += 2;
            }
            "quantum" if i + 1 < params.len() => {
                quantum = crate::util::parse::get_size(&params[i + 1])
                    .map_err(|_| crate::netlink::Error::InvalidMessage("invalid quantum".into()))?
                    as u32;
                i += 2;
            }
            "mtu" if i + 1 < params.len() => {
                mtu = params[i + 1]
                    .parse()
                    .map_err(|_| crate::netlink::Error::InvalidMessage("invalid mtu".into()))?;
                i += 2;
            }
            "mpu" if i + 1 < params.len() => {
                mpu = params[i + 1]
                    .parse()
                    .map_err(|_| crate::netlink::Error::InvalidMessage("invalid mpu".into()))?;
                i += 2;
            }
            "overhead" if i + 1 < params.len() => {
                overhead = params[i + 1].parse().map_err(|_| {
                    crate::netlink::Error::InvalidMessage("invalid overhead".into())
                })?;
                i += 2;
            }
            _ => i += 1,
        }
    }

    // Rate is required
    if rate64 == 0 {
        return Err(crate::netlink::Error::InvalidMessage(
            "htb class: rate is required".into(),
        ));
    }

    // Default ceil to rate if not specified
    if ceil64 == 0 {
        ceil64 = rate64;
    }

    // Get HZ for time calculations (typically 100 or 1000 on Linux)
    let hz: u64 = 1000;

    // Compute burst from rate if not specified
    if burst == 0 {
        burst = (rate64 / hz + mtu as u64) as u32;
    }

    // Compute cburst from ceil if not specified
    if cburst == 0 {
        cburst = (ceil64 / hz + mtu as u64) as u32;
    }

    // Calculate buffer time (in ticks)
    let buffer = if rate64 > 0 {
        ((burst as u64 * 1_000_000) / rate64) as u32
    } else {
        burst
    };

    let cbuffer = if ceil64 > 0 {
        ((cburst as u64 * 1_000_000) / ceil64) as u32
    } else {
        cburst
    };

    // Build the tc_htb_opt structure
    let opt = TcHtbOpt {
        rate: TcRateSpec {
            rate: if rate64 >= (1u64 << 32) {
                u32::MAX
            } else {
                rate64 as u32
            },
            mpu,
            overhead,
            ..Default::default()
        },
        ceil: TcRateSpec {
            rate: if ceil64 >= (1u64 << 32) {
                u32::MAX
            } else {
                ceil64 as u32
            },
            mpu,
            overhead,
            ..Default::default()
        },
        buffer,
        cbuffer,
        quantum,
        prio,
        ..Default::default()
    };

    // Add 64-bit rate if needed
    if rate64 >= (1u64 << 32) {
        builder.append_attr(TCA_HTB_RATE64, &rate64.to_ne_bytes());
    }

    if ceil64 >= (1u64 << 32) {
        builder.append_attr(TCA_HTB_CEIL64, &ceil64.to_ne_bytes());
    }

    // Add the main parameters structure
    builder.append_attr(TCA_HTB_PARMS, opt.as_bytes());

    // Add rate tables
    let rtab = compute_rate_table(rate64, mtu);
    let ctab = compute_rate_table(ceil64, mtu);

    builder.append_attr(TCA_HTB_RTAB, &rtab);
    builder.append_attr(TCA_HTB_CTAB, &ctab);

    Ok(())
}

/// Compute a rate table for HTB.
fn compute_rate_table(rate: u64, mtu: u32) -> [u8; 1024] {
    let mut table = [0u8; 1024];

    if rate == 0 {
        return table;
    }

    let cell_log: u32 = 3;
    let cell_size = 1u32 << cell_log;
    let time_units_per_sec: u64 = 1_000_000;

    for i in 0..256 {
        let size = ((i + 1) as u32) * cell_size;
        let size = size.min(mtu);

        let time = (size as u64 * time_units_per_sec) / rate;
        let time = time.min(u32::MAX as u64) as u32;

        let offset = i * 4;
        table[offset..offset + 4].copy_from_slice(&time.to_ne_bytes());
    }

    table
}
