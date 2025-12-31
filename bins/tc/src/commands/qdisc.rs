//! tc qdisc command implementation.

use clap::{Args, Subcommand};
use rip_netlink::message::NlMsgType;
use rip_netlink::messages::TcMessage;
use rip_netlink::types::tc::{TcMsg, TcaAttr, tc_handle};
use rip_netlink::{Connection, Result};
use rip_output::{OutputFormat, OutputOptions, print_items};
use rip_tclib::options::{fq_codel, htb, netem, prio, sfq, tbf};
use std::io::{self, Write};

#[derive(Args)]
pub struct QdiscCmd {
    #[command(subcommand)]
    action: Option<QdiscAction>,
}

#[derive(Subcommand)]
enum QdiscAction {
    /// Show qdiscs.
    Show {
        /// Device name (use "dev <name>" or just "<name>").
        #[arg(value_name = "DEV")]
        dev: Option<String>,

        /// Show invisible qdiscs.
        #[arg(long)]
        invisible: bool,
    },

    /// List qdiscs (alias for show).
    #[command(visible_alias = "ls")]
    List {
        /// Device name.
        #[arg(value_name = "DEV")]
        dev: Option<String>,
    },

    /// Add a qdisc.
    Add {
        /// Device name.
        #[arg(value_name = "DEV")]
        dev: String,

        /// Parent handle (root, ingress, or handle).
        #[arg(long, default_value = "root")]
        parent: String,

        /// Handle for this qdisc.
        #[arg(long)]
        handle: Option<String>,

        /// Qdisc type (htb, fq_codel, prio, tbf, etc.).
        #[arg(name = "TYPE")]
        kind: String,

        /// Type-specific parameters.
        #[arg(trailing_var_arg = true)]
        params: Vec<String>,
    },

    /// Delete a qdisc.
    Del {
        /// Device name.
        dev: String,

        /// Parent handle.
        #[arg(long, default_value = "root")]
        parent: String,

        /// Handle to delete.
        #[arg(long)]
        handle: Option<String>,
    },

    /// Replace a qdisc.
    Replace {
        /// Device name.
        dev: String,

        /// Parent handle.
        #[arg(long, default_value = "root")]
        parent: String,

        /// Handle for this qdisc.
        #[arg(long)]
        handle: Option<String>,

        /// Qdisc type.
        #[arg(name = "TYPE")]
        kind: String,

        /// Type-specific parameters.
        #[arg(trailing_var_arg = true)]
        params: Vec<String>,
    },

    /// Change a qdisc.
    Change {
        /// Device name.
        dev: String,

        /// Parent handle.
        #[arg(long, default_value = "root")]
        parent: String,

        /// Handle for this qdisc.
        #[arg(long)]
        handle: Option<String>,

        /// Qdisc type.
        #[arg(name = "TYPE")]
        kind: String,

        /// Type-specific parameters.
        #[arg(trailing_var_arg = true)]
        params: Vec<String>,
    },
}

impl QdiscCmd {
    pub async fn run(
        self,
        conn: &Connection,
        format: OutputFormat,
        opts: &OutputOptions,
    ) -> Result<()> {
        match self.action.unwrap_or(QdiscAction::Show {
            dev: None,
            invisible: false,
        }) {
            QdiscAction::Show { dev, invisible } => {
                Self::show(conn, dev.as_deref(), invisible, format, opts).await
            }
            QdiscAction::List { dev } => {
                Self::show(conn, dev.as_deref(), false, format, opts).await
            }
            QdiscAction::Add {
                dev,
                parent,
                handle,
                kind,
                params,
            } => Self::add(conn, &dev, &parent, handle.as_deref(), &kind, &params).await,
            QdiscAction::Del {
                dev,
                parent,
                handle,
            } => Self::del(conn, &dev, &parent, handle.as_deref()).await,
            QdiscAction::Replace {
                dev,
                parent,
                handle,
                kind,
                params,
            } => Self::replace(conn, &dev, &parent, handle.as_deref(), &kind, &params).await,
            QdiscAction::Change {
                dev,
                parent,
                handle,
                kind,
                params,
            } => Self::change(conn, &dev, &parent, handle.as_deref(), &kind, &params).await,
        }
    }

    async fn show(
        conn: &Connection,
        dev: Option<&str>,
        _invisible: bool,
        format: OutputFormat,
        opts: &OutputOptions,
    ) -> Result<()> {
        // Get interface index if filtering
        let filter_index =
            rip_lib::get_ifindex_opt(dev).map_err(rip_netlink::Error::InvalidMessage)?;

        // Fetch all qdiscs using typed API
        let all_qdiscs: Vec<TcMessage> = conn.dump_typed(NlMsgType::RTM_GETQDISC).await?;

        // Filter by device if specified
        let qdiscs: Vec<_> = all_qdiscs
            .into_iter()
            .filter(|q| {
                if let Some(idx) = filter_index {
                    q.ifindex() == idx
                } else {
                    true
                }
            })
            .collect();

        print_items(&qdiscs, format, opts, qdisc_to_json, print_qdisc_text)?;

        Ok(())
    }

    async fn add(
        conn: &Connection,
        dev: &str,
        parent: &str,
        handle: Option<&str>,
        kind: &str,
        params: &[String],
    ) -> Result<()> {
        use rip_netlink::connection::create_request;

        let ifindex = rip_lib::get_ifindex(dev).map_err(rip_netlink::Error::InvalidMessage)?;

        let parent_handle = tc_handle::parse(parent).ok_or_else(|| {
            rip_netlink::Error::InvalidMessage(format!("invalid parent handle: {}", parent))
        })?;

        let qdisc_handle = if let Some(h) = handle {
            tc_handle::parse(h).ok_or_else(|| {
                rip_netlink::Error::InvalidMessage(format!("invalid handle: {}", h))
            })?
        } else {
            0
        };

        let tcmsg = TcMsg::new()
            .with_ifindex(ifindex as i32)
            .with_parent(parent_handle)
            .with_handle(qdisc_handle);

        let mut builder = create_request(NlMsgType::RTM_NEWQDISC);
        builder.append(&tcmsg);

        // Add kind attribute
        builder.append_attr_str(TcaAttr::Kind as u16, kind);

        // Add qdisc-specific options
        if !params.is_empty() {
            let options_token = builder.nest_start(TcaAttr::Options as u16);
            add_qdisc_options(&mut builder, kind, params)?;
            builder.nest_end(options_token);
        }

        conn.request_ack(builder).await?;

        Ok(())
    }

    async fn del(conn: &Connection, dev: &str, parent: &str, handle: Option<&str>) -> Result<()> {
        use rip_netlink::connection::ack_request;

        let ifindex = rip_lib::get_ifindex(dev).map_err(rip_netlink::Error::InvalidMessage)?;

        let parent_handle = tc_handle::parse(parent).ok_or_else(|| {
            rip_netlink::Error::InvalidMessage(format!("invalid parent handle: {}", parent))
        })?;

        let qdisc_handle = if let Some(h) = handle {
            tc_handle::parse(h).ok_or_else(|| {
                rip_netlink::Error::InvalidMessage(format!("invalid handle: {}", h))
            })?
        } else {
            0
        };

        let tcmsg = TcMsg::new()
            .with_ifindex(ifindex as i32)
            .with_parent(parent_handle)
            .with_handle(qdisc_handle);

        let mut builder = ack_request(NlMsgType::RTM_DELQDISC);
        builder.append(&tcmsg);

        conn.request_ack(builder).await?;

        Ok(())
    }

    async fn replace(
        conn: &Connection,
        dev: &str,
        parent: &str,
        handle: Option<&str>,
        kind: &str,
        params: &[String],
    ) -> Result<()> {
        use rip_netlink::connection::replace_request;

        let ifindex = rip_lib::get_ifindex(dev).map_err(rip_netlink::Error::InvalidMessage)?;

        let parent_handle = tc_handle::parse(parent).ok_or_else(|| {
            rip_netlink::Error::InvalidMessage(format!("invalid parent handle: {}", parent))
        })?;

        let qdisc_handle = if let Some(h) = handle {
            tc_handle::parse(h).ok_or_else(|| {
                rip_netlink::Error::InvalidMessage(format!("invalid handle: {}", h))
            })?
        } else {
            0
        };

        let tcmsg = TcMsg::new()
            .with_ifindex(ifindex as i32)
            .with_parent(parent_handle)
            .with_handle(qdisc_handle);

        let mut builder = replace_request(NlMsgType::RTM_NEWQDISC);
        builder.append(&tcmsg);

        // Add kind attribute
        builder.append_attr_str(TcaAttr::Kind as u16, kind);

        // Add qdisc-specific options
        if !params.is_empty() {
            let options_token = builder.nest_start(TcaAttr::Options as u16);
            add_qdisc_options(&mut builder, kind, params)?;
            builder.nest_end(options_token);
        }

        conn.request_ack(builder).await?;

        Ok(())
    }

    async fn change(
        conn: &Connection,
        dev: &str,
        parent: &str,
        handle: Option<&str>,
        kind: &str,
        params: &[String],
    ) -> Result<()> {
        use rip_netlink::connection::ack_request;

        let ifindex = rip_lib::get_ifindex(dev).map_err(rip_netlink::Error::InvalidMessage)?;

        let parent_handle = tc_handle::parse(parent).ok_or_else(|| {
            rip_netlink::Error::InvalidMessage(format!("invalid parent handle: {}", parent))
        })?;

        let qdisc_handle = if let Some(h) = handle {
            tc_handle::parse(h).ok_or_else(|| {
                rip_netlink::Error::InvalidMessage(format!("invalid handle: {}", h))
            })?
        } else {
            0
        };

        let tcmsg = TcMsg::new()
            .with_ifindex(ifindex as i32)
            .with_parent(parent_handle)
            .with_handle(qdisc_handle);

        let mut builder = ack_request(NlMsgType::RTM_NEWQDISC);
        builder.append(&tcmsg);

        // Add kind attribute
        builder.append_attr_str(TcaAttr::Kind as u16, kind);

        // Add qdisc-specific options
        if !params.is_empty() {
            let options_token = builder.nest_start(TcaAttr::Options as u16);
            add_qdisc_options(&mut builder, kind, params)?;
            builder.nest_end(options_token);
        }

        conn.request_ack(builder).await?;

        Ok(())
    }
}

/// Convert a TcMessage to JSON representation.
fn qdisc_to_json(qdisc: &TcMessage) -> serde_json::Value {
    let dev = rip_lib::get_ifname_or_index(qdisc.ifindex());

    serde_json::json!({
        "dev": dev,
        "kind": qdisc.kind().unwrap_or(""),
        "handle": tc_handle::format(qdisc.handle()),
        "parent": tc_handle::format(qdisc.parent()),
        "bytes": qdisc.bytes(),
        "packets": qdisc.packets(),
        "drops": qdisc.drops(),
        "overlimits": qdisc.overlimits(),
        "requeues": qdisc.requeues(),
        "qlen": qdisc.qlen(),
        "backlog": qdisc.backlog(),
    })
}

/// Print qdisc in text format.
fn print_qdisc_text(
    w: &mut io::StdoutLock<'_>,
    qdisc: &TcMessage,
    opts: &OutputOptions,
) -> io::Result<()> {
    let dev = rip_lib::get_ifname_or_index(qdisc.ifindex());

    write!(
        w,
        "qdisc {} {} dev {} ",
        qdisc.kind().unwrap_or(""),
        tc_handle::format(qdisc.handle()),
        dev
    )?;

    if qdisc.parent() == tc_handle::ROOT {
        write!(w, "root ")?;
    } else if qdisc.parent() == tc_handle::INGRESS {
        write!(w, "ingress ")?;
    } else if qdisc.parent() != 0 {
        write!(w, "parent {} ", tc_handle::format(qdisc.parent()))?;
    }

    write!(w, "refcnt 2")?; // placeholder

    writeln!(w)?;

    if opts.stats {
        writeln!(
            w,
            " Sent {} bytes {} pkt (dropped {}, overlimits {} requeues {})",
            qdisc.bytes(),
            qdisc.packets(),
            qdisc.drops(),
            qdisc.overlimits(),
            qdisc.requeues()
        )?;
        writeln!(w, " backlog {}b {}p", qdisc.backlog(), qdisc.qlen())?;
    }

    Ok(())
}

/// Add qdisc-specific options to the message.
fn add_qdisc_options(
    builder: &mut rip_netlink::MessageBuilder,
    kind: &str,
    params: &[String],
) -> Result<()> {
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

    Ok(())
}
