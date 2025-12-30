//! tc class command implementation.

use clap::{Args, Subcommand};
use rip_netlink::attr::{AttrIter, get};
use rip_netlink::connection::dump_request;
use rip_netlink::message::{NLMSG_HDRLEN, NlMsgHdr, NlMsgType};
use rip_netlink::types::tc::{TcMsg, TcaAttr, TcaStats, tc_handle};
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
        _kind: Option<&str>,
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

        // Build request
        let mut builder = dump_request(NlMsgType::RTM_GETTCLASS);
        let tcmsg = TcMsg::new().with_ifindex(ifindex);
        builder.append(&tcmsg);

        // Send and receive
        let responses = conn.dump(builder).await?;

        let mut stdout = io::stdout().lock();
        let mut classes = Vec::new();

        for response in &responses {
            if let Some(class) = parse_class_message(response)? {
                // Filter by parent if specified
                if let Some(p) = parent_filter {
                    if class.parent != p {
                        continue;
                    }
                }
                // Filter by classid if specified
                if let Some(c) = classid_filter {
                    if class.handle != c {
                        continue;
                    }
                }
                classes.push(class);
            }
        }

        match format {
            OutputFormat::Text => {
                for class in &classes {
                    print_class_text(&mut stdout, class, opts)?;
                }
            }
            OutputFormat::Json => {
                let json: Vec<_> = classes.iter().map(|c| c.to_json()).collect();
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

/// Parsed class information.
#[derive(Debug)]
struct ClassInfo {
    ifindex: i32,
    handle: u32,
    parent: u32,
    kind: String,
    bytes: u64,
    packets: u32,
    drops: u32,
    overlimits: u32,
    qlen: u32,
    backlog: u32,
}

impl ClassInfo {
    fn to_json(&self) -> serde_json::Value {
        let dev = rip_lib::ifname::index_to_name(self.ifindex as u32)
            .unwrap_or_else(|_| format!("if{}", self.ifindex));

        serde_json::json!({
            "dev": dev,
            "kind": self.kind,
            "class": tc_handle::format(self.handle),
            "parent": tc_handle::format(self.parent),
            "bytes": self.bytes,
            "packets": self.packets,
            "drops": self.drops,
            "overlimits": self.overlimits,
            "qlen": self.qlen,
            "backlog": self.backlog,
        })
    }
}

fn parse_class_message(data: &[u8]) -> Result<Option<ClassInfo>> {
    if data.len() < NLMSG_HDRLEN + TcMsg::SIZE {
        return Ok(None);
    }

    let header = NlMsgHdr::from_bytes(data)?;

    // Skip non-class messages
    if header.nlmsg_type != NlMsgType::RTM_NEWTCLASS {
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

    Ok(Some(ClassInfo {
        ifindex: tcmsg.tcm_ifindex,
        handle: tcmsg.tcm_handle,
        parent: tcmsg.tcm_parent,
        kind,
        bytes,
        packets,
        drops,
        overlimits,
        qlen,
        backlog,
    }))
}

fn print_class_text<W: Write>(
    w: &mut W,
    class: &ClassInfo,
    opts: &OutputOptions,
) -> io::Result<()> {
    let dev = rip_lib::ifname::index_to_name(class.ifindex as u32)
        .unwrap_or_else(|_| format!("if{}", class.ifindex));

    write!(
        w,
        "class {} {} dev {} ",
        class.kind,
        tc_handle::format(class.handle),
        dev
    )?;

    if class.parent == tc_handle::ROOT {
        write!(w, "root ")?;
    } else if class.parent != 0 {
        write!(w, "parent {} ", tc_handle::format(class.parent))?;
    }

    writeln!(w)?;

    if opts.stats {
        writeln!(
            w,
            " Sent {} bytes {} pkt (dropped {}, overlimits {})",
            class.bytes, class.packets, class.drops, class.overlimits
        )?;
        writeln!(w, " backlog {}b {}p", class.backlog, class.qlen)?;
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
        "htb" => {
            // HTB class requires rate parameter
            // This is complex because it needs tc_htb_opt structure
            // For now, just acknowledge the params exist
            let _ = (builder, params);
        }
        _ => {
            // Unknown class type
            let _ = (builder, params);
        }
    }

    Ok(())
}
