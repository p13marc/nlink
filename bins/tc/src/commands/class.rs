//! tc class command implementation.

use clap::{Args, Subcommand};
use rip_netlink::message::NlMsgType;
use rip_netlink::messages::TcMessage;
use rip_netlink::types::tc::{TcMsg, TcaAttr, tc_handle};
use rip_netlink::{Connection, Result};
use rip_output::{OutputFormat, OutputOptions};
use std::io::{self, Write};

#[derive(Args)]
pub struct ClassCmd {
    #[command(subcommand)]
    action: Option<ClassAction>,
}

#[derive(Subcommand)]
enum ClassAction {
    /// Show classes.
    Show {
        /// Device name.
        dev: String,

        /// Qdisc type to filter.
        #[arg(long)]
        kind: Option<String>,

        /// Parent handle.
        #[arg(long)]
        parent: Option<String>,

        /// Specific classid.
        #[arg(long)]
        classid: Option<String>,
    },

    /// List classes (alias for show).
    #[command(visible_alias = "ls")]
    List {
        /// Device name.
        dev: String,
    },

    /// Add a class.
    Add {
        /// Device name.
        dev: String,

        /// Parent handle.
        #[arg(long)]
        parent: String,

        /// Class ID.
        #[arg(long)]
        classid: String,

        /// Class type (htb, etc.).
        #[arg(name = "TYPE")]
        kind: String,

        /// Type-specific parameters.
        #[arg(trailing_var_arg = true)]
        params: Vec<String>,
    },

    /// Delete a class.
    Del {
        /// Device name.
        dev: String,

        /// Parent handle.
        #[arg(long)]
        parent: String,

        /// Class ID to delete.
        #[arg(long)]
        classid: String,
    },

    /// Change a class.
    Change {
        /// Device name.
        dev: String,

        /// Parent handle.
        #[arg(long)]
        parent: String,

        /// Class ID.
        #[arg(long)]
        classid: String,

        /// Class type.
        #[arg(name = "TYPE")]
        kind: String,

        /// Type-specific parameters.
        #[arg(trailing_var_arg = true)]
        params: Vec<String>,
    },

    /// Replace a class.
    Replace {
        /// Device name.
        dev: String,

        /// Parent handle.
        #[arg(long)]
        parent: String,

        /// Class ID.
        #[arg(long)]
        classid: String,

        /// Class type.
        #[arg(name = "TYPE")]
        kind: String,

        /// Type-specific parameters.
        #[arg(trailing_var_arg = true)]
        params: Vec<String>,
    },
}

impl ClassCmd {
    pub async fn run(
        self,
        conn: &Connection,
        format: OutputFormat,
        opts: &OutputOptions,
    ) -> Result<()> {
        match self
            .action
            .unwrap_or(ClassAction::List { dev: String::new() })
        {
            ClassAction::Show {
                dev,
                kind,
                parent,
                classid,
            } => {
                Self::show(
                    conn,
                    &dev,
                    kind.as_deref(),
                    parent.as_deref(),
                    classid.as_deref(),
                    format,
                    opts,
                )
                .await
            }
            ClassAction::List { dev } => {
                Self::show(conn, &dev, None, None, None, format, opts).await
            }
            ClassAction::Add {
                dev,
                parent,
                classid,
                kind,
                params,
            } => Self::add(conn, &dev, &parent, &classid, &kind, &params).await,
            ClassAction::Del {
                dev,
                parent,
                classid,
            } => Self::del(conn, &dev, &parent, &classid).await,
            ClassAction::Change {
                dev,
                parent,
                classid,
                kind,
                params,
            } => Self::change(conn, &dev, &parent, &classid, &kind, &params).await,
            ClassAction::Replace {
                dev,
                parent,
                classid,
                kind,
                params,
            } => Self::replace(conn, &dev, &parent, &classid, &kind, &params).await,
        }
    }

    async fn show(
        conn: &Connection,
        dev: &str,
        kind_filter: Option<&str>,
        parent: Option<&str>,
        classid: Option<&str>,
        format: OutputFormat,
        opts: &OutputOptions,
    ) -> Result<()> {
        if dev.is_empty() {
            return Err(rip_netlink::Error::InvalidMessage(
                "device name required".into(),
            ));
        }

        let ifindex = rip_lib::ifname::name_to_index(dev).map_err(|e| {
            rip_netlink::Error::InvalidMessage(format!("interface not found: {}", e))
        })? as i32;

        let parent_filter = parent.and_then(tc_handle::parse);
        let classid_filter = classid.and_then(tc_handle::parse);

        // Fetch all classes using typed API
        let all_classes: Vec<TcMessage> = conn.dump_typed(NlMsgType::RTM_GETTCLASS).await?;

        // Filter classes
        let classes: Vec<_> = all_classes
            .into_iter()
            .filter(|c| {
                // Filter by interface
                if c.ifindex() != ifindex {
                    return false;
                }
                // Filter by kind if specified
                if let Some(k) = kind_filter
                    && c.kind() != Some(k)
                {
                    return false;
                }
                // Filter by parent if specified
                if let Some(p) = parent_filter
                    && c.parent() != p
                {
                    return false;
                }
                // Filter by classid if specified
                if let Some(cid) = classid_filter
                    && c.handle() != cid
                {
                    return false;
                }
                true
            })
            .collect();

        let mut stdout = io::stdout().lock();

        match format {
            OutputFormat::Text => {
                for class in &classes {
                    print_class_text(&mut stdout, class, opts)?;
                }
            }
            OutputFormat::Json => {
                let json: Vec<_> = classes.iter().map(class_to_json).collect();
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
        classid: &str,
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

        let class_handle = tc_handle::parse(classid).ok_or_else(|| {
            rip_netlink::Error::InvalidMessage(format!("invalid classid: {}", classid))
        })?;

        let tcmsg = TcMsg::new()
            .with_ifindex(ifindex as i32)
            .with_parent(parent_handle)
            .with_handle(class_handle);

        let mut builder = create_request(NlMsgType::RTM_NEWTCLASS);
        builder.append(&tcmsg);

        // Add kind attribute
        builder.append_attr_str(TcaAttr::Kind as u16, kind);

        // Add class-specific options
        if !params.is_empty() {
            let options_token = builder.nest_start(TcaAttr::Options as u16);
            add_class_options(&mut builder, kind, params)?;
            builder.nest_end(options_token);
        }

        conn.request_ack(builder).await?;

        Ok(())
    }

    async fn del(conn: &Connection, dev: &str, parent: &str, classid: &str) -> Result<()> {
        use rip_netlink::connection::ack_request;

        let ifindex = rip_lib::ifname::name_to_index(dev).map_err(|e| {
            rip_netlink::Error::InvalidMessage(format!("interface not found: {}", e))
        })?;

        let parent_handle = tc_handle::parse(parent).ok_or_else(|| {
            rip_netlink::Error::InvalidMessage(format!("invalid parent handle: {}", parent))
        })?;

        let class_handle = tc_handle::parse(classid).ok_or_else(|| {
            rip_netlink::Error::InvalidMessage(format!("invalid classid: {}", classid))
        })?;

        let tcmsg = TcMsg::new()
            .with_ifindex(ifindex as i32)
            .with_parent(parent_handle)
            .with_handle(class_handle);

        let mut builder = ack_request(NlMsgType::RTM_DELTCLASS);
        builder.append(&tcmsg);

        conn.request_ack(builder).await?;

        Ok(())
    }

    async fn change(
        conn: &Connection,
        dev: &str,
        parent: &str,
        classid: &str,
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

        let class_handle = tc_handle::parse(classid).ok_or_else(|| {
            rip_netlink::Error::InvalidMessage(format!("invalid classid: {}", classid))
        })?;

        let tcmsg = TcMsg::new()
            .with_ifindex(ifindex as i32)
            .with_parent(parent_handle)
            .with_handle(class_handle);

        let mut builder = ack_request(NlMsgType::RTM_NEWTCLASS);
        builder.append(&tcmsg);

        // Add kind attribute
        builder.append_attr_str(TcaAttr::Kind as u16, kind);

        // Add class-specific options
        if !params.is_empty() {
            let options_token = builder.nest_start(TcaAttr::Options as u16);
            add_class_options(&mut builder, kind, params)?;
            builder.nest_end(options_token);
        }

        conn.request_ack(builder).await?;

        Ok(())
    }

    async fn replace(
        conn: &Connection,
        dev: &str,
        parent: &str,
        classid: &str,
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

        let class_handle = tc_handle::parse(classid).ok_or_else(|| {
            rip_netlink::Error::InvalidMessage(format!("invalid classid: {}", classid))
        })?;

        let tcmsg = TcMsg::new()
            .with_ifindex(ifindex as i32)
            .with_parent(parent_handle)
            .with_handle(class_handle);

        let mut builder = replace_request(NlMsgType::RTM_NEWTCLASS);
        builder.append(&tcmsg);

        // Add kind attribute
        builder.append_attr_str(TcaAttr::Kind as u16, kind);

        // Add class-specific options
        if !params.is_empty() {
            let options_token = builder.nest_start(TcaAttr::Options as u16);
            add_class_options(&mut builder, kind, params)?;
            builder.nest_end(options_token);
        }

        conn.request_ack(builder).await?;

        Ok(())
    }
}

/// Convert a TcMessage to JSON representation for class.
fn class_to_json(class: &TcMessage) -> serde_json::Value {
    let dev = rip_lib::ifname::index_to_name(class.ifindex() as u32)
        .unwrap_or_else(|_| format!("if{}", class.ifindex()));

    serde_json::json!({
        "dev": dev,
        "kind": class.kind().unwrap_or(""),
        "class": tc_handle::format(class.handle()),
        "parent": tc_handle::format(class.parent()),
        "bytes": class.bytes(),
        "packets": class.packets(),
        "drops": class.drops(),
        "overlimits": class.overlimits(),
        "qlen": class.qlen(),
        "backlog": class.backlog(),
    })
}

/// Print class in text format.
fn print_class_text<W: Write>(
    w: &mut W,
    class: &TcMessage,
    opts: &OutputOptions,
) -> io::Result<()> {
    let dev = rip_lib::ifname::index_to_name(class.ifindex() as u32)
        .unwrap_or_else(|_| format!("if{}", class.ifindex()));

    write!(
        w,
        "class {} {} dev {} ",
        class.kind().unwrap_or(""),
        tc_handle::format(class.handle()),
        dev
    )?;

    if class.parent() == tc_handle::ROOT {
        write!(w, "root ")?;
    } else if class.parent() != 0 {
        write!(w, "parent {} ", tc_handle::format(class.parent()))?;
    }

    writeln!(w)?;

    if opts.stats {
        writeln!(
            w,
            " Sent {} bytes {} pkt (dropped {}, overlimits {})",
            class.bytes(),
            class.packets(),
            class.drops(),
            class.overlimits()
        )?;
        writeln!(w, " backlog {}b {}p", class.backlog(), class.qlen())?;
    }

    Ok(())
}

/// Add class-specific options to the message.
fn add_class_options(
    builder: &mut rip_netlink::MessageBuilder,
    kind: &str,
    params: &[String],
) -> Result<()> {
    match kind {
        "htb" => add_htb_class_options(builder, params)?,
        _ => {
            // Unknown class type - just ignore parameters
        }
    }

    Ok(())
}

/// Add HTB class options.
///
/// Supports:
/// - rate RATE (required) - guaranteed rate
/// - ceil RATE - maximum rate (defaults to rate)
/// - burst SIZE - burst size (computed if not specified)
/// - cburst SIZE - ceil burst size (computed if not specified)
/// - prio N - priority (0-7, lower = higher priority)
/// - quantum SIZE - quantum for DRR (computed from r2q if not specified)
/// - mtu SIZE - MTU for rate calculations (default 1600)
/// - mpu SIZE - minimum packet unit
/// - overhead SIZE - per-packet overhead
fn add_htb_class_options(
    builder: &mut rip_netlink::MessageBuilder,
    params: &[String],
) -> Result<()> {
    use rip_netlink::types::tc::qdisc::TcRateSpec;
    use rip_netlink::types::tc::qdisc::htb::*;

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
                rate64 = rip_lib::parse::get_rate(&params[i + 1])
                    .map_err(|_| rip_netlink::Error::InvalidMessage("invalid rate".into()))?;
                i += 2;
            }
            "ceil" if i + 1 < params.len() => {
                ceil64 = rip_lib::parse::get_rate(&params[i + 1])
                    .map_err(|_| rip_netlink::Error::InvalidMessage("invalid ceil".into()))?;
                i += 2;
            }
            "burst" | "buffer" | "maxburst" if i + 1 < params.len() => {
                burst = rip_lib::parse::get_size(&params[i + 1])
                    .map_err(|_| rip_netlink::Error::InvalidMessage("invalid burst".into()))?
                    as u32;
                i += 2;
            }
            "cburst" | "cbuffer" | "cmaxburst" if i + 1 < params.len() => {
                cburst = rip_lib::parse::get_size(&params[i + 1])
                    .map_err(|_| rip_netlink::Error::InvalidMessage("invalid cburst".into()))?
                    as u32;
                i += 2;
            }
            "prio" if i + 1 < params.len() => {
                prio = params[i + 1]
                    .parse()
                    .map_err(|_| rip_netlink::Error::InvalidMessage("invalid prio".into()))?;
                i += 2;
            }
            "quantum" if i + 1 < params.len() => {
                quantum = rip_lib::parse::get_size(&params[i + 1])
                    .map_err(|_| rip_netlink::Error::InvalidMessage("invalid quantum".into()))?
                    as u32;
                i += 2;
            }
            "mtu" if i + 1 < params.len() => {
                mtu = params[i + 1]
                    .parse()
                    .map_err(|_| rip_netlink::Error::InvalidMessage("invalid mtu".into()))?;
                i += 2;
            }
            "mpu" if i + 1 < params.len() => {
                mpu = params[i + 1]
                    .parse()
                    .map_err(|_| rip_netlink::Error::InvalidMessage("invalid mpu".into()))?;
                i += 2;
            }
            "overhead" if i + 1 < params.len() => {
                overhead = params[i + 1]
                    .parse()
                    .map_err(|_| rip_netlink::Error::InvalidMessage("invalid overhead".into()))?;
                i += 2;
            }
            _ => i += 1,
        }
    }

    // Rate is required
    if rate64 == 0 {
        return Err(rip_netlink::Error::InvalidMessage(
            "htb class: rate is required".into(),
        ));
    }

    // Default ceil to rate if not specified
    if ceil64 == 0 {
        ceil64 = rate64;
    }

    // Get HZ for time calculations (typically 100 or 1000 on Linux)
    // We use 1000 as a reasonable default
    let hz: u64 = 1000;

    // Compute burst from rate if not specified
    // burst = rate / hz + mtu (ensures at least one packet can be sent)
    if burst == 0 {
        burst = (rate64 / hz + mtu as u64) as u32;
    }

    // Compute cburst from ceil if not specified
    if cburst == 0 {
        cburst = (ceil64 / hz + mtu as u64) as u32;
    }

    // Calculate buffer time (in ticks): buffer = burst * TIME_UNITS_PER_SEC / rate
    // TIME_UNITS_PER_SEC is typically 1,000,000 (microseconds)
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
        // level is set by kernel
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

    // Add rate tables (rtab and ctab)
    // These are 256-entry tables for fast rate calculations
    // Each entry is the time to transmit a packet of that size
    // For simplicity, we compute basic linear tables
    let rtab = compute_rate_table(rate64, mtu);
    let ctab = compute_rate_table(ceil64, mtu);

    builder.append_attr(TCA_HTB_RTAB, &rtab);
    builder.append_attr(TCA_HTB_CTAB, &ctab);

    Ok(())
}

/// Compute a rate table for HTB.
///
/// The rate table contains 256 entries, each representing the time (in ticks)
/// to transmit a packet of a given size. The size is determined by cell_log.
fn compute_rate_table(rate: u64, mtu: u32) -> [u8; 1024] {
    let mut table = [0u8; 1024];

    if rate == 0 {
        return table;
    }

    // Compute cell_log - log2 of cell size
    // cell_log determines how we map packet sizes to table entries
    // For simplicity, use cell_log = 3 (cell size = 8 bytes)
    let cell_log: u32 = 3;
    let cell_size = 1u32 << cell_log;

    // TIME_UNITS_PER_SEC is 1,000,000 (microseconds)
    let time_units_per_sec: u64 = 1_000_000;

    for i in 0..256 {
        // Size for this entry
        let size = ((i + 1) as u32) * cell_size;
        let size = size.min(mtu);

        // Time to transmit this size at the given rate
        // time = size * TIME_UNITS_PER_SEC / rate
        let time = (size as u64 * time_units_per_sec) / rate;
        let time = time.min(u32::MAX as u64) as u32;

        // Store as little-endian u32
        let offset = i * 4;
        table[offset..offset + 4].copy_from_slice(&time.to_ne_bytes());
    }

    table
}
