//! tc qdisc command implementation.

use clap::{Args, Subcommand};
use rip_netlink::message::NlMsgType;
use rip_netlink::messages::TcMessage;
use rip_netlink::types::tc::{TcMsg, TcaAttr, tc_handle};
use rip_netlink::{Connection, Result};
use rip_output::{OutputFormat, OutputOptions};
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
        let filter_index = if let Some(dev_name) = dev {
            Some(rip_lib::ifname::name_to_index(dev_name).map_err(|e| {
                rip_netlink::Error::InvalidMessage(format!("interface not found: {}", e))
            })? as i32)
        } else {
            None
        };

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

        let mut stdout = io::stdout().lock();

        match format {
            OutputFormat::Text => {
                for qdisc in &qdiscs {
                    print_qdisc_text(&mut stdout, qdisc, opts)?;
                }
            }
            OutputFormat::Json => {
                let json: Vec<_> = qdiscs.iter().map(qdisc_to_json).collect();
                if opts.pretty {
                    serde_json::to_writer_pretty(&mut stdout, &json)?;
                } else {
                    serde_json::to_writer(&mut stdout, &json)?;
                }
                writeln!(stdout)?;
            }
        }

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

        let ifindex = rip_lib::ifname::name_to_index(dev).map_err(|e| {
            rip_netlink::Error::InvalidMessage(format!("interface not found: {}", e))
        })?;

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

        let ifindex = rip_lib::ifname::name_to_index(dev).map_err(|e| {
            rip_netlink::Error::InvalidMessage(format!("interface not found: {}", e))
        })?;

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

        let ifindex = rip_lib::ifname::name_to_index(dev).map_err(|e| {
            rip_netlink::Error::InvalidMessage(format!("interface not found: {}", e))
        })?;

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

        let ifindex = rip_lib::ifname::name_to_index(dev).map_err(|e| {
            rip_netlink::Error::InvalidMessage(format!("interface not found: {}", e))
        })?;

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
    let dev = rip_lib::ifname::index_to_name(qdisc.ifindex() as u32)
        .unwrap_or_else(|_| format!("if{}", qdisc.ifindex()));

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
fn print_qdisc_text<W: Write>(
    w: &mut W,
    qdisc: &TcMessage,
    opts: &OutputOptions,
) -> io::Result<()> {
    let dev = rip_lib::ifname::index_to_name(qdisc.ifindex() as u32)
        .unwrap_or_else(|_| format!("if{}", qdisc.ifindex()));

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
        "fq_codel" => add_fq_codel_options(builder, params)?,
        "tbf" => add_tbf_options(builder, params)?,
        "htb" => add_htb_options(builder, params)?,
        "prio" => add_prio_options(builder, params)?,
        "sfq" => add_sfq_options(builder, params)?,
        "netem" => add_netem_options(builder, params)?,
        "noqueue" | "pfifo_fast" | "mq" | "ingress" | "clsact" => {
            // These don't take parameters
        }
        _ => {
            // Unknown qdisc type - just ignore parameters for now
        }
    }

    Ok(())
}

/// Add fq_codel qdisc options.
fn add_fq_codel_options(
    builder: &mut rip_netlink::MessageBuilder,
    params: &[String],
) -> Result<()> {
    use rip_netlink::types::tc::qdisc::fq_codel::*;

    let mut i = 0;
    while i < params.len() {
        match params[i].as_str() {
            "limit" if i + 1 < params.len() => {
                let limit: u32 = params[i + 1]
                    .parse()
                    .map_err(|_| rip_netlink::Error::InvalidMessage("invalid limit".into()))?;
                builder.append_attr_u32(TCA_FQ_CODEL_LIMIT, limit);
                i += 2;
            }
            "target" if i + 1 < params.len() => {
                let target = rip_lib::parse::get_time(&params[i + 1])
                    .map_err(|_| rip_netlink::Error::InvalidMessage("invalid target".into()))?;
                builder.append_attr_u32(TCA_FQ_CODEL_TARGET, target.as_micros() as u32);
                i += 2;
            }
            "interval" if i + 1 < params.len() => {
                let interval = rip_lib::parse::get_time(&params[i + 1])
                    .map_err(|_| rip_netlink::Error::InvalidMessage("invalid interval".into()))?;
                builder.append_attr_u32(TCA_FQ_CODEL_INTERVAL, interval.as_micros() as u32);
                i += 2;
            }
            "flows" if i + 1 < params.len() => {
                let flows: u32 = params[i + 1]
                    .parse()
                    .map_err(|_| rip_netlink::Error::InvalidMessage("invalid flows".into()))?;
                builder.append_attr_u32(TCA_FQ_CODEL_FLOWS, flows);
                i += 2;
            }
            "quantum" if i + 1 < params.len() => {
                let quantum: u32 = params[i + 1]
                    .parse()
                    .map_err(|_| rip_netlink::Error::InvalidMessage("invalid quantum".into()))?;
                builder.append_attr_u32(TCA_FQ_CODEL_QUANTUM, quantum);
                i += 2;
            }
            "ce_threshold" if i + 1 < params.len() => {
                let ce = rip_lib::parse::get_time(&params[i + 1]).map_err(|_| {
                    rip_netlink::Error::InvalidMessage("invalid ce_threshold".into())
                })?;
                builder.append_attr_u32(TCA_FQ_CODEL_CE_THRESHOLD, ce.as_micros() as u32);
                i += 2;
            }
            "memory_limit" if i + 1 < params.len() => {
                let mem = rip_lib::parse::get_size(&params[i + 1]).map_err(|_| {
                    rip_netlink::Error::InvalidMessage("invalid memory_limit".into())
                })?;
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

/// Add tbf qdisc options.
fn add_tbf_options(builder: &mut rip_netlink::MessageBuilder, params: &[String]) -> Result<()> {
    use rip_netlink::types::tc::qdisc::TcRateSpec;
    use rip_netlink::types::tc::qdisc::tbf::*;

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
                    .map_err(|_| rip_netlink::Error::InvalidMessage("invalid rate".into()))?;
                i += 2;
            }
            "burst" | "buffer" | "maxburst" if i + 1 < params.len() => {
                burst = rip_lib::parse::get_size(&params[i + 1])
                    .map_err(|_| rip_netlink::Error::InvalidMessage("invalid burst".into()))?
                    as u32;
                i += 2;
            }
            "limit" if i + 1 < params.len() => {
                limit = rip_lib::parse::get_size(&params[i + 1])
                    .map_err(|_| rip_netlink::Error::InvalidMessage("invalid limit".into()))?
                    as u32;
                i += 2;
            }
            "latency" if i + 1 < params.len() => {
                let lat = rip_lib::parse::get_time(&params[i + 1])
                    .map_err(|_| rip_netlink::Error::InvalidMessage("invalid latency".into()))?;
                latency = Some(lat.as_micros() as u32);
                i += 2;
            }
            "peakrate" if i + 1 < params.len() => {
                peakrate = rip_lib::parse::get_rate(&params[i + 1])
                    .map_err(|_| rip_netlink::Error::InvalidMessage("invalid peakrate".into()))?;
                i += 2;
            }
            "mtu" | "minburst" if i + 1 < params.len() => {
                mtu = rip_lib::parse::get_size(&params[i + 1])
                    .map_err(|_| rip_netlink::Error::InvalidMessage("invalid mtu".into()))?
                    as u32;
                i += 2;
            }
            _ => i += 1,
        }
    }

    if rate == 0 {
        return Err(rip_netlink::Error::InvalidMessage(
            "tbf: rate is required".into(),
        ));
    }
    if burst == 0 {
        return Err(rip_netlink::Error::InvalidMessage(
            "tbf: burst is required".into(),
        ));
    }

    // Calculate limit from latency if not specified
    if limit == 0 {
        if let Some(lat_us) = latency {
            // limit = rate * latency + burst
            limit = ((rate * lat_us as u64) / 1_000_000 + burst as u64) as u32;
        } else {
            return Err(rip_netlink::Error::InvalidMessage(
                "tbf: either limit or latency is required".into(),
            ));
        }
    }

    // Calculate buffer time (in ticks)
    // buffer = burst * TIME_UNITS_PER_SEC / rate (simplified)
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

/// Add htb qdisc options (for root qdisc only).
fn add_htb_options(builder: &mut rip_netlink::MessageBuilder, params: &[String]) -> Result<()> {
    use rip_netlink::types::tc::qdisc::htb::*;

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
                    rip_netlink::types::tc::tc_handle::parse(s).ok_or_else(|| {
                        rip_netlink::Error::InvalidMessage("invalid default class".into())
                    })?
                } else {
                    u32::from_str_radix(s, 16).map_err(|_| {
                        rip_netlink::Error::InvalidMessage("invalid default class".into())
                    })?
                };
                i += 2;
            }
            "r2q" if i + 1 < params.len() => {
                r2q = params[i + 1]
                    .parse()
                    .map_err(|_| rip_netlink::Error::InvalidMessage("invalid r2q".into()))?;
                i += 2;
            }
            "direct_qlen" if i + 1 < params.len() => {
                direct_qlen = Some(params[i + 1].parse().map_err(|_| {
                    rip_netlink::Error::InvalidMessage("invalid direct_qlen".into())
                })?);
                i += 2;
            }
            _ => i += 1,
        }
    }

    // Build HTB global init structure
    let glob = TcHtbGlob::new().with_default(default_class);
    let mut glob_data = glob;
    glob_data.rate2quantum = r2q;

    builder.append_attr(TCA_HTB_INIT, glob_data.as_bytes());

    if let Some(qlen) = direct_qlen {
        builder.append_attr_u32(TCA_HTB_DIRECT_QLEN, qlen);
    }

    Ok(())
}

/// Add prio qdisc options.
fn add_prio_options(builder: &mut rip_netlink::MessageBuilder, params: &[String]) -> Result<()> {
    use rip_netlink::types::tc::qdisc::prio::*;

    let mut bands: i32 = 3;
    let mut priomap = [1u8, 2, 2, 2, 1, 2, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1];

    let mut i = 0;
    while i < params.len() {
        match params[i].as_str() {
            "bands" if i + 1 < params.len() => {
                bands = params[i + 1]
                    .parse()
                    .map_err(|_| rip_netlink::Error::InvalidMessage("invalid bands".into()))?;
                i += 2;
            }
            "priomap" if i + 16 < params.len() => {
                for j in 0..16 {
                    priomap[j] = params[i + 1 + j].parse().map_err(|_| {
                        rip_netlink::Error::InvalidMessage("invalid priomap value".into())
                    })?;
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

/// Add sfq qdisc options.
fn add_sfq_options(builder: &mut rip_netlink::MessageBuilder, params: &[String]) -> Result<()> {
    use rip_netlink::types::tc::qdisc::sfq::*;

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
                    .map_err(|_| rip_netlink::Error::InvalidMessage("invalid quantum".into()))?
                    as u32;
                i += 2;
            }
            "perturb" if i + 1 < params.len() => {
                qopt.perturb_period = params[i + 1]
                    .parse()
                    .map_err(|_| rip_netlink::Error::InvalidMessage("invalid perturb".into()))?;
                i += 2;
            }
            "limit" if i + 1 < params.len() => {
                qopt.limit = params[i + 1]
                    .parse()
                    .map_err(|_| rip_netlink::Error::InvalidMessage("invalid limit".into()))?;
                i += 2;
            }
            "divisor" if i + 1 < params.len() => {
                qopt.divisor = params[i + 1]
                    .parse()
                    .map_err(|_| rip_netlink::Error::InvalidMessage("invalid divisor".into()))?;
                i += 2;
            }
            _ => i += 1,
        }
    }

    builder.append(&qopt);

    Ok(())
}

/// Add netem qdisc options.
///
/// Supports:
/// - delay TIME [JITTER [CORRELATION]]
/// - loss PERCENT [CORRELATION]
/// - loss random PERCENT [CORRELATION]
/// - duplicate PERCENT [CORRELATION]
/// - corrupt PERCENT [CORRELATION]
/// - reorder PERCENT [CORRELATION] [gap DISTANCE]
/// - rate RATE [PACKETOVERHEAD [CELLSIZE [CELLOVERHEAD]]]
/// - limit PACKETS
/// - ecn
/// - slot MIN_DELAY [MAX_DELAY]
fn add_netem_options(builder: &mut rip_netlink::MessageBuilder, params: &[String]) -> Result<()> {
    use rip_netlink::types::tc::qdisc::netem::*;

    let mut qopt = TcNetemQopt::new();
    let mut corr = TcNetemCorr::default();
    let mut reorder = TcNetemReorder::default();
    let mut corrupt = TcNetemCorrupt::default();
    let mut rate = TcNetemRate::default();
    let mut slot = TcNetemSlot::default();

    let mut has_corr = false;
    let mut has_reorder = false;
    let mut has_corrupt = false;
    let mut has_rate = false;
    let mut has_slot = false;
    let mut has_ecn = false;
    let mut latency64: Option<i64> = None;
    let mut jitter64: Option<i64> = None;
    let mut rate64: Option<u64> = None;

    /// Parse a percentage string like "10%" or "0.5%" into a netem probability.
    fn parse_percent(s: &str) -> std::result::Result<u32, rip_netlink::Error> {
        let s = s.trim_end_matches('%');
        let percent: f64 = s
            .parse()
            .map_err(|_| rip_netlink::Error::InvalidMessage("invalid percentage".into()))?;
        Ok(percent_to_prob(percent))
    }

    let mut i = 0;
    while i < params.len() {
        match params[i].as_str() {
            "limit" if i + 1 < params.len() => {
                qopt.limit = params[i + 1]
                    .parse()
                    .map_err(|_| rip_netlink::Error::InvalidMessage("invalid limit".into()))?;
                i += 2;
            }
            "delay" | "latency" if i + 1 < params.len() => {
                // delay TIME [JITTER [CORRELATION]]
                let delay = rip_lib::parse::get_time(&params[i + 1])
                    .map_err(|_| rip_netlink::Error::InvalidMessage("invalid delay".into()))?;
                // Use 64-bit latency (nanoseconds)
                latency64 = Some(delay.as_nanos() as i64);
                i += 2;

                // Check for jitter
                if i < params.len() && !is_keyword(&params[i]) {
                    let jitter = rip_lib::parse::get_time(&params[i])
                        .map_err(|_| rip_netlink::Error::InvalidMessage("invalid jitter".into()))?;
                    jitter64 = Some(jitter.as_nanos() as i64);
                    i += 1;

                    // Check for correlation
                    if i < params.len() && !is_keyword(&params[i]) {
                        corr.delay_corr = parse_percent(&params[i])?;
                        has_corr = true;
                        i += 1;
                    }
                }
            }
            "loss" if i + 1 < params.len() => {
                // loss [random] PERCENT [CORRELATION]
                i += 1;
                // Skip optional "random" keyword
                if params[i] == "random" && i + 1 < params.len() {
                    i += 1;
                }
                qopt.loss = parse_percent(&params[i])?;
                i += 1;

                // Check for correlation
                if i < params.len() && !is_keyword(&params[i]) {
                    corr.loss_corr = parse_percent(&params[i])?;
                    has_corr = true;
                    i += 1;
                }
            }
            "drop" if i + 1 < params.len() => {
                // Alias for loss
                i += 1;
                qopt.loss = parse_percent(&params[i])?;
                i += 1;
                if i < params.len() && !is_keyword(&params[i]) {
                    corr.loss_corr = parse_percent(&params[i])?;
                    has_corr = true;
                    i += 1;
                }
            }
            "duplicate" if i + 1 < params.len() => {
                // duplicate PERCENT [CORRELATION]
                i += 1;
                qopt.duplicate = parse_percent(&params[i])?;
                i += 1;

                // Check for correlation
                if i < params.len() && !is_keyword(&params[i]) {
                    corr.dup_corr = parse_percent(&params[i])?;
                    has_corr = true;
                    i += 1;
                }
            }
            "corrupt" if i + 1 < params.len() => {
                // corrupt PERCENT [CORRELATION]
                i += 1;
                corrupt.probability = parse_percent(&params[i])?;
                has_corrupt = true;
                i += 1;

                // Check for correlation
                if i < params.len() && !is_keyword(&params[i]) {
                    corrupt.correlation = parse_percent(&params[i])?;
                    i += 1;
                }
            }
            "reorder" if i + 1 < params.len() => {
                // reorder PERCENT [CORRELATION] [gap DISTANCE]
                i += 1;
                reorder.probability = parse_percent(&params[i])?;
                has_reorder = true;
                i += 1;

                // Check for correlation
                if i < params.len() && !is_keyword(&params[i]) {
                    reorder.correlation = parse_percent(&params[i])?;
                    i += 1;
                }
            }
            "gap" if i + 1 < params.len() => {
                qopt.gap = params[i + 1]
                    .parse()
                    .map_err(|_| rip_netlink::Error::InvalidMessage("invalid gap".into()))?;
                i += 2;
            }
            "rate" if i + 1 < params.len() => {
                // rate RATE [PACKETOVERHEAD [CELLSIZE [CELLOVERHEAD]]]
                i += 1;
                let r = rip_lib::parse::get_rate(&params[i])
                    .map_err(|_| rip_netlink::Error::InvalidMessage("invalid rate".into()))?;
                if r > u32::MAX as u64 {
                    rate64 = Some(r);
                    rate.rate = u32::MAX; // Marker for 64-bit rate
                } else {
                    rate.rate = r as u32;
                }
                has_rate = true;
                i += 1;

                // Packet overhead
                if i < params.len() && !is_keyword(&params[i]) {
                    rate.packet_overhead = params[i].parse().map_err(|_| {
                        rip_netlink::Error::InvalidMessage("invalid packet overhead".into())
                    })?;
                    i += 1;

                    // Cell size
                    if i < params.len() && !is_keyword(&params[i]) {
                        rate.cell_size = params[i].parse().map_err(|_| {
                            rip_netlink::Error::InvalidMessage("invalid cell size".into())
                        })?;
                        i += 1;

                        // Cell overhead
                        if i < params.len() && !is_keyword(&params[i]) {
                            rate.cell_overhead = params[i].parse().map_err(|_| {
                                rip_netlink::Error::InvalidMessage("invalid cell overhead".into())
                            })?;
                            i += 1;
                        }
                    }
                }
            }
            "slot" if i + 1 < params.len() => {
                // slot MIN_DELAY [MAX_DELAY] [packets MAX_PACKETS] [bytes MAX_BYTES]
                i += 1;
                let min = rip_lib::parse::get_time(&params[i]).map_err(|_| {
                    rip_netlink::Error::InvalidMessage("invalid slot min_delay".into())
                })?;
                slot.min_delay = min.as_nanos() as i64;
                has_slot = true;
                i += 1;

                // Check for max delay
                if i < params.len() && !is_keyword(&params[i]) {
                    let max = rip_lib::parse::get_time(&params[i]).map_err(|_| {
                        rip_netlink::Error::InvalidMessage("invalid slot max_delay".into())
                    })?;
                    slot.max_delay = max.as_nanos() as i64;
                    i += 1;
                } else {
                    slot.max_delay = slot.min_delay;
                }

                // Check for packets/bytes options
                while i + 1 < params.len() {
                    match params[i].as_str() {
                        "packets" => {
                            slot.max_packets = params[i + 1].parse().map_err(|_| {
                                rip_netlink::Error::InvalidMessage("invalid slot packets".into())
                            })?;
                            i += 2;
                        }
                        "bytes" => {
                            slot.max_bytes =
                                rip_lib::parse::get_size(&params[i + 1]).map_err(|_| {
                                    rip_netlink::Error::InvalidMessage("invalid slot bytes".into())
                                })? as i32;
                            i += 2;
                        }
                        _ => break,
                    }
                }
            }
            "ecn" => {
                has_ecn = true;
                i += 1;
            }
            _ => i += 1,
        }
    }

    // Validate: reorder requires delay
    if has_reorder && latency64.is_none() {
        return Err(rip_netlink::Error::InvalidMessage(
            "netem: reorder requires delay to be specified".into(),
        ));
    }

    // If reorder is set but no gap, default gap to 1
    if has_reorder && qopt.gap == 0 {
        qopt.gap = 1;
    }

    // Validate: ECN requires loss
    if has_ecn && qopt.loss == 0 {
        return Err(rip_netlink::Error::InvalidMessage(
            "netem: ecn requires loss to be specified".into(),
        ));
    }

    // Build the message - netem options go directly after TCA_OPTIONS start
    // The base qopt is appended as raw data (not as an attribute)
    builder.append(&qopt);

    // Add 64-bit latency if set
    if let Some(lat) = latency64 {
        builder.append_attr(TCA_NETEM_LATENCY64, &lat.to_ne_bytes());
    }

    // Add 64-bit jitter if set
    if let Some(jit) = jitter64 {
        builder.append_attr(TCA_NETEM_JITTER64, &jit.to_ne_bytes());
    }

    // Add correlation if any were set
    if has_corr {
        builder.append_attr(TCA_NETEM_CORR, corr.as_bytes());
    }

    // Add reorder if set
    if has_reorder {
        builder.append_attr(TCA_NETEM_REORDER, reorder.as_bytes());
    }

    // Add corrupt if set
    if has_corrupt {
        builder.append_attr(TCA_NETEM_CORRUPT, corrupt.as_bytes());
    }

    // Add rate if set
    if has_rate {
        builder.append_attr(TCA_NETEM_RATE, rate.as_bytes());
        if let Some(r64) = rate64 {
            builder.append_attr(TCA_NETEM_RATE64, &r64.to_ne_bytes());
        }
    }

    // Add slot if set
    if has_slot {
        builder.append_attr(TCA_NETEM_SLOT, slot.as_bytes());
    }

    // Add ECN if set
    if has_ecn {
        builder.append_attr_u32(TCA_NETEM_ECN, 1);
    }

    Ok(())
}

/// Check if a string is a netem keyword (to determine if it's a new option or a value).
fn is_keyword(s: &str) -> bool {
    matches!(
        s,
        "delay"
            | "latency"
            | "loss"
            | "drop"
            | "duplicate"
            | "corrupt"
            | "reorder"
            | "gap"
            | "rate"
            | "limit"
            | "slot"
            | "ecn"
            | "distribution"
            | "random"
            | "state"
            | "gemodel"
            | "packets"
            | "bytes"
    )
}
