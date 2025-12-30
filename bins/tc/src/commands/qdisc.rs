//! tc qdisc command implementation.

use clap::{Args, Subcommand};
use rip_netlink::attr::{AttrIter, get};
use rip_netlink::connection::dump_request;
use rip_netlink::message::{NLMSG_HDRLEN, NlMsgHdr, NlMsgType};
use rip_netlink::types::tc::{TcMsg, TcaAttr, TcaStats, tc_handle};
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

        // Build request
        let mut builder = dump_request(NlMsgType::RTM_GETQDISC);
        let tcmsg = TcMsg::new();
        builder.append(&tcmsg);

        // Send and receive
        let responses = conn.dump(builder).await?;

        let mut stdout = io::stdout().lock();
        let mut qdiscs = Vec::new();

        for response in &responses {
            if let Some(qdisc) = parse_qdisc_message(response)? {
                // Filter by device if specified
                if let Some(idx) = filter_index {
                    if qdisc.ifindex != idx {
                        continue;
                    }
                }
                qdiscs.push(qdisc);
            }
        }

        match format {
            OutputFormat::Text => {
                for qdisc in &qdiscs {
                    print_qdisc_text(&mut stdout, qdisc, opts)?;
                }
            }
            OutputFormat::Json => {
                let json: Vec<_> = qdiscs.iter().map(|q| q.to_json()).collect();
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

/// Parsed qdisc information.
#[derive(Debug)]
struct QdiscInfo {
    ifindex: i32,
    handle: u32,
    parent: u32,
    kind: String,
    bytes: u64,
    packets: u32,
    drops: u32,
    overlimits: u32,
    requeues: u32,
    qlen: u32,
    backlog: u32,
}

impl QdiscInfo {
    fn to_json(&self) -> serde_json::Value {
        let dev = rip_lib::ifname::index_to_name(self.ifindex as u32)
            .unwrap_or_else(|_| format!("if{}", self.ifindex));

        serde_json::json!({
            "dev": dev,
            "kind": self.kind,
            "handle": tc_handle::format(self.handle),
            "parent": tc_handle::format(self.parent),
            "bytes": self.bytes,
            "packets": self.packets,
            "drops": self.drops,
            "overlimits": self.overlimits,
            "requeues": self.requeues,
            "qlen": self.qlen,
            "backlog": self.backlog,
        })
    }
}

fn parse_qdisc_message(data: &[u8]) -> Result<Option<QdiscInfo>> {
    if data.len() < NLMSG_HDRLEN + TcMsg::SIZE {
        return Ok(None);
    }

    let header = NlMsgHdr::from_bytes(data)?;

    // Skip non-qdisc messages
    if header.nlmsg_type != NlMsgType::RTM_NEWQDISC {
        return Ok(None);
    }

    let payload = &data[NLMSG_HDRLEN..];
    let tcmsg = TcMsg::from_bytes(payload)?;
    let attrs_data = &payload[TcMsg::SIZE..];

    let mut kind = String::new();
    let mut bytes = 0u64;
    let mut packets = 0u32;
    let mut drops = 0u32;
    let mut overlimits = 0u32;
    let mut requeues = 0u32;
    let mut qlen = 0u32;
    let mut backlog = 0u32;

    for (attr_type, attr_data) in AttrIter::new(attrs_data) {
        match TcaAttr::from(attr_type) {
            TcaAttr::Kind => {
                kind = get::string(attr_data).unwrap_or("").to_string();
            }
            TcaAttr::Stats2 => {
                // Parse nested stats
                for (stat_type, stat_data) in AttrIter::new(attr_data) {
                    match TcaStats::from(stat_type) {
                        TcaStats::Basic => {
                            if stat_data.len() >= 12 {
                                bytes = u64::from_ne_bytes([
                                    stat_data[0],
                                    stat_data[1],
                                    stat_data[2],
                                    stat_data[3],
                                    stat_data[4],
                                    stat_data[5],
                                    stat_data[6],
                                    stat_data[7],
                                ]);
                                packets = u32::from_ne_bytes([
                                    stat_data[8],
                                    stat_data[9],
                                    stat_data[10],
                                    stat_data[11],
                                ]);
                            }
                        }
                        TcaStats::Queue => {
                            if stat_data.len() >= 20 {
                                qlen = u32::from_ne_bytes([
                                    stat_data[0],
                                    stat_data[1],
                                    stat_data[2],
                                    stat_data[3],
                                ]);
                                backlog = u32::from_ne_bytes([
                                    stat_data[4],
                                    stat_data[5],
                                    stat_data[6],
                                    stat_data[7],
                                ]);
                                drops = u32::from_ne_bytes([
                                    stat_data[8],
                                    stat_data[9],
                                    stat_data[10],
                                    stat_data[11],
                                ]);
                                requeues = u32::from_ne_bytes([
                                    stat_data[12],
                                    stat_data[13],
                                    stat_data[14],
                                    stat_data[15],
                                ]);
                                overlimits = u32::from_ne_bytes([
                                    stat_data[16],
                                    stat_data[17],
                                    stat_data[18],
                                    stat_data[19],
                                ]);
                            }
                        }
                        _ => {}
                    }
                }
            }
            _ => {}
        }
    }

    Ok(Some(QdiscInfo {
        ifindex: tcmsg.tcm_ifindex,
        handle: tcmsg.tcm_handle,
        parent: tcmsg.tcm_parent,
        kind,
        bytes,
        packets,
        drops,
        overlimits,
        requeues,
        qlen,
        backlog,
    }))
}

fn print_qdisc_text<W: Write>(
    w: &mut W,
    qdisc: &QdiscInfo,
    opts: &OutputOptions,
) -> io::Result<()> {
    let dev = rip_lib::ifname::index_to_name(qdisc.ifindex as u32)
        .unwrap_or_else(|_| format!("if{}", qdisc.ifindex));

    write!(
        w,
        "qdisc {} {} dev {} ",
        qdisc.kind,
        tc_handle::format(qdisc.handle),
        dev
    )?;

    if qdisc.parent == tc_handle::ROOT {
        write!(w, "root ")?;
    } else if qdisc.parent == tc_handle::INGRESS {
        write!(w, "ingress ")?;
    } else if qdisc.parent != 0 {
        write!(w, "parent {} ", tc_handle::format(qdisc.parent))?;
    }

    write!(w, "refcnt 2")?; // placeholder

    writeln!(w)?;

    if opts.stats {
        writeln!(
            w,
            " Sent {} bytes {} pkt (dropped {}, overlimits {} requeues {})",
            qdisc.bytes, qdisc.packets, qdisc.drops, qdisc.overlimits, qdisc.requeues
        )?;
        writeln!(w, " backlog {}b {}p", qdisc.backlog, qdisc.qlen)?;
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
    let mut qopt = TcTbfQopt::default();
    qopt.rate = TcRateSpec::new(rate as u32);
    qopt.limit = limit;
    qopt.buffer = buffer;
    qopt.mtu = mtu;

    if peakrate > 0 {
        qopt.peakrate = TcRateSpec::new(peakrate as u32);
    }

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

    let mut qopt = TcSfqQopt::default();
    qopt.quantum = 0; // Let kernel calculate default
    qopt.perturb_period = 0;
    qopt.limit = 127;

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
