//! Qdisc message builders.
//!
//! This module provides high-level builders for creating qdisc netlink messages.

use rip_netlink::connection::{ack_request, create_request, replace_request};
use rip_netlink::message::NlMsgType;
use rip_netlink::types::tc::{TcMsg, TcaAttr, tc_handle};
use rip_netlink::{Connection, MessageBuilder, Result};

use crate::options::{fq_codel, htb, netem, prio, sfq, tbf};

/// Build a TcMsg with common fields for qdisc operations.
fn build_tcmsg(dev: &str, parent: &str, handle: Option<&str>) -> Result<TcMsg> {
    let ifindex = rip_lib::get_ifindex(dev).map_err(rip_netlink::Error::InvalidMessage)?;

    let parent_handle = tc_handle::parse(parent).ok_or_else(|| {
        rip_netlink::Error::InvalidMessage(format!("invalid parent handle: {}", parent))
    })?;

    let qdisc_handle = if let Some(h) = handle {
        tc_handle::parse(h)
            .ok_or_else(|| rip_netlink::Error::InvalidMessage(format!("invalid handle: {}", h)))?
    } else {
        0
    };

    Ok(TcMsg::new()
        .with_ifindex(ifindex as i32)
        .with_parent(parent_handle)
        .with_handle(qdisc_handle))
}

/// Add qdisc-specific options to the message builder.
pub fn add_options(builder: &mut MessageBuilder, kind: &str, params: &[String]) -> Result<()> {
    if params.is_empty() {
        return Ok(());
    }

    let options_token = builder.nest_start(TcaAttr::Options as u16);

    match kind {
        "fq_codel" => fq_codel::build(builder, params)?,
        "tbf" => tbf::build(builder, params)?,
        "htb" => htb::build(builder, params)?,
        "prio" => prio::build(builder, params)?,
        "sfq" => sfq::build(builder, params)?,
        "netem" => netem::build(builder, params)?,
        "noqueue" | "pfifo_fast" | "mq" | "ingress" | "clsact" => {
            // These don't take parameters
        }
        _ => {
            // Unknown qdisc type - just ignore parameters for now
        }
    }

    builder.nest_end(options_token);
    Ok(())
}

/// Add a new qdisc.
///
/// # Arguments
/// * `conn` - The netlink connection
/// * `dev` - Device name
/// * `parent` - Parent handle (e.g., "root", "ingress", or "1:0")
/// * `handle` - Optional handle for this qdisc
/// * `kind` - Qdisc type (e.g., "htb", "fq_codel", "prio")
/// * `params` - Type-specific parameters
pub async fn add(
    conn: &Connection,
    dev: &str,
    parent: &str,
    handle: Option<&str>,
    kind: &str,
    params: &[String],
) -> Result<()> {
    let tcmsg = build_tcmsg(dev, parent, handle)?;

    let mut builder = create_request(NlMsgType::RTM_NEWQDISC);
    builder.append(&tcmsg);
    builder.append_attr_str(TcaAttr::Kind as u16, kind);

    add_options(&mut builder, kind, params)?;

    conn.request_ack(builder).await?;
    Ok(())
}

/// Delete a qdisc.
///
/// # Arguments
/// * `conn` - The netlink connection
/// * `dev` - Device name
/// * `parent` - Parent handle
/// * `handle` - Optional handle to delete
pub async fn del(conn: &Connection, dev: &str, parent: &str, handle: Option<&str>) -> Result<()> {
    let tcmsg = build_tcmsg(dev, parent, handle)?;

    let mut builder = ack_request(NlMsgType::RTM_DELQDISC);
    builder.append(&tcmsg);

    conn.request_ack(builder).await?;
    Ok(())
}

/// Replace a qdisc (add or update).
///
/// # Arguments
/// * `conn` - The netlink connection
/// * `dev` - Device name
/// * `parent` - Parent handle
/// * `handle` - Optional handle for this qdisc
/// * `kind` - Qdisc type
/// * `params` - Type-specific parameters
pub async fn replace(
    conn: &Connection,
    dev: &str,
    parent: &str,
    handle: Option<&str>,
    kind: &str,
    params: &[String],
) -> Result<()> {
    let tcmsg = build_tcmsg(dev, parent, handle)?;

    let mut builder = replace_request(NlMsgType::RTM_NEWQDISC);
    builder.append(&tcmsg);
    builder.append_attr_str(TcaAttr::Kind as u16, kind);

    add_options(&mut builder, kind, params)?;

    conn.request_ack(builder).await?;
    Ok(())
}

/// Change a qdisc's parameters.
///
/// # Arguments
/// * `conn` - The netlink connection
/// * `dev` - Device name
/// * `parent` - Parent handle
/// * `handle` - Optional handle for this qdisc
/// * `kind` - Qdisc type
/// * `params` - Type-specific parameters
pub async fn change(
    conn: &Connection,
    dev: &str,
    parent: &str,
    handle: Option<&str>,
    kind: &str,
    params: &[String],
) -> Result<()> {
    let tcmsg = build_tcmsg(dev, parent, handle)?;

    let mut builder = ack_request(NlMsgType::RTM_NEWQDISC);
    builder.append(&tcmsg);
    builder.append_attr_str(TcaAttr::Kind as u16, kind);

    add_options(&mut builder, kind, params)?;

    conn.request_ack(builder).await?;
    Ok(())
}
