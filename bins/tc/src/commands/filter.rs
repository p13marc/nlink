//! tc filter command implementation.

use clap::{Args, Subcommand};
use rip_netlink::attr::{AttrIter, get};
use rip_netlink::connection::dump_request;
use rip_netlink::message::{NLMSG_HDRLEN, NlMsgHdr, NlMsgType};
use rip_netlink::types::tc::{TcMsg, TcaAttr, tc_handle};
use rip_netlink::{Connection, Result};
use rip_output::{OutputFormat, OutputOptions};
use std::io::{self, Write};

#[derive(Args)]
pub struct FilterCmd {
    #[command(subcommand)]
    action: Option<FilterAction>,
}

#[derive(Subcommand)]
enum FilterAction {
    /// Show filters.
    Show {
        /// Device name.
        dev: String,

        /// Parent qdisc/class.
        #[arg(long, default_value = "root")]
        parent: String,

        /// Protocol (ip, ipv6, all, etc.).
        #[arg(long)]
        protocol: Option<String>,

        /// Priority/preference.
        #[arg(long)]
        prio: Option<u16>,
    },

    /// List filters (alias for show).
    #[command(visible_alias = "ls")]
    List {
        /// Device name.
        dev: String,
    },

    /// Add a filter.
    Add {
        /// Device name.
        dev: String,

        /// Parent qdisc/class.
        #[arg(long, default_value = "root")]
        parent: String,

        /// Protocol.
        #[arg(long, default_value = "ip")]
        protocol: String,

        /// Priority.
        #[arg(long)]
        prio: Option<u16>,

        /// Filter type (u32, flower, basic, etc.).
        #[arg(name = "TYPE")]
        kind: String,

        /// Type-specific parameters.
        #[arg(trailing_var_arg = true)]
        params: Vec<String>,
    },

    /// Delete a filter.
    Del {
        /// Device name.
        dev: String,

        /// Parent qdisc/class.
        #[arg(long, default_value = "root")]
        parent: String,

        /// Protocol.
        #[arg(long)]
        protocol: Option<String>,

        /// Priority.
        #[arg(long)]
        prio: Option<u16>,

        /// Filter type.
        #[arg(name = "TYPE")]
        kind: Option<String>,
    },

    /// Replace a filter.
    Replace {
        /// Device name.
        dev: String,

        /// Parent qdisc/class.
        #[arg(long, default_value = "root")]
        parent: String,

        /// Protocol.
        #[arg(long, default_value = "ip")]
        protocol: String,

        /// Priority.
        #[arg(long)]
        prio: Option<u16>,

        /// Filter type.
        #[arg(name = "TYPE")]
        kind: String,

        /// Type-specific parameters.
        #[arg(trailing_var_arg = true)]
        params: Vec<String>,
    },

    /// Change a filter.
    Change {
        /// Device name.
        dev: String,

        /// Parent qdisc/class.
        #[arg(long, default_value = "root")]
        parent: String,

        /// Protocol.
        #[arg(long, default_value = "ip")]
        protocol: String,

        /// Priority.
        #[arg(long)]
        prio: Option<u16>,

        /// Filter type.
        #[arg(name = "TYPE")]
        kind: String,

        /// Type-specific parameters.
        #[arg(trailing_var_arg = true)]
        params: Vec<String>,
    },
}

impl FilterCmd {
    pub async fn run(
        self,
        conn: &Connection,
        format: OutputFormat,
        opts: &OutputOptions,
    ) -> Result<()> {
        match self
            .action
            .unwrap_or(FilterAction::List { dev: String::new() })
        {
            FilterAction::Show {
                dev,
                parent,
                protocol,
                prio,
            } => Self::show(conn, &dev, &parent, protocol.as_deref(), prio, format, opts).await,
            FilterAction::List { dev } => {
                Self::show(conn, &dev, "root", None, None, format, opts).await
            }
            FilterAction::Add {
                dev,
                parent,
                protocol,
                prio,
                kind,
                params,
            } => Self::add(conn, &dev, &parent, &protocol, prio, &kind, &params).await,
            FilterAction::Del {
                dev,
                parent,
                protocol,
                prio,
                kind,
            } => {
                Self::del(
                    conn,
                    &dev,
                    &parent,
                    protocol.as_deref(),
                    prio,
                    kind.as_deref(),
                )
                .await
            }
            FilterAction::Replace {
                dev,
                parent,
                protocol,
                prio,
                kind,
                params,
            } => Self::replace(conn, &dev, &parent, &protocol, prio, &kind, &params).await,
            FilterAction::Change {
                dev,
                parent,
                protocol,
                prio,
                kind,
                params,
            } => Self::change(conn, &dev, &parent, &protocol, prio, &kind, &params).await,
        }
    }

    async fn show(
        conn: &Connection,
        dev: &str,
        parent: &str,
        _protocol: Option<&str>,
        _prio: Option<u16>,
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

        let parent_handle = tc_handle::parse(parent).ok_or_else(|| {
            rip_netlink::Error::InvalidMessage(format!("invalid parent: {}", parent))
        })?;

        // Build request
        let mut builder = dump_request(NlMsgType::RTM_GETTFILTER);
        let tcmsg = TcMsg::new()
            .with_ifindex(ifindex)
            .with_parent(parent_handle);
        builder.append(&tcmsg);

        // Send and receive
        let responses = conn.dump(builder).await?;

        let mut stdout = io::stdout().lock();
        let mut filters = Vec::new();

        for response in &responses {
            if let Some(filter) = parse_filter_message(response)? {
                filters.push(filter);
            }
        }

        match format {
            OutputFormat::Text => {
                for filter in &filters {
                    print_filter_text(&mut stdout, filter, opts)?;
                }
            }
            OutputFormat::Json => {
                let json: Vec<_> = filters.iter().map(|f| f.to_json()).collect();
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
        protocol: &str,
        prio: Option<u16>,
        kind: &str,
        params: &[String],
    ) -> Result<()> {
        use rip_netlink::connection::create_request;

        let ifindex = rip_lib::ifname::name_to_index(dev).map_err(|e| {
            rip_netlink::Error::InvalidMessage(format!("interface not found: {}", e))
        })?;

        let parent_handle = tc_handle::parse(parent).ok_or_else(|| {
            rip_netlink::Error::InvalidMessage(format!("invalid parent: {}", parent))
        })?;

        let proto = parse_protocol(protocol)?;
        let priority = prio.unwrap_or(0);

        // tcm_info contains protocol (upper 16 bits) and priority (lower 16 bits)
        let info = ((proto as u32) << 16) | (priority as u32);

        let tcmsg = TcMsg {
            tcm_family: 0,
            tcm__pad1: 0,
            tcm__pad2: 0,
            tcm_ifindex: ifindex as i32,
            tcm_handle: 0,
            tcm_parent: parent_handle,
            tcm_info: info,
        };

        let mut builder = create_request(NlMsgType::RTM_NEWTFILTER);
        builder.append(&tcmsg);

        // Add kind attribute
        builder.append_attr_str(TcaAttr::Kind as u16, kind);

        // Add filter-specific options
        if !params.is_empty() {
            let options_token = builder.nest_start(TcaAttr::Options as u16);
            add_filter_options(&mut builder, kind, params)?;
            builder.nest_end(options_token);
        }

        conn.request_ack(builder).await?;

        Ok(())
    }

    async fn del(
        conn: &Connection,
        dev: &str,
        parent: &str,
        protocol: Option<&str>,
        prio: Option<u16>,
        kind: Option<&str>,
    ) -> Result<()> {
        use rip_netlink::connection::ack_request;

        let ifindex = rip_lib::ifname::name_to_index(dev).map_err(|e| {
            rip_netlink::Error::InvalidMessage(format!("interface not found: {}", e))
        })?;

        let parent_handle = tc_handle::parse(parent).ok_or_else(|| {
            rip_netlink::Error::InvalidMessage(format!("invalid parent: {}", parent))
        })?;

        let proto = if let Some(p) = protocol {
            parse_protocol(p)?
        } else {
            0
        };
        let priority = prio.unwrap_or(0);
        let info = ((proto as u32) << 16) | (priority as u32);

        let tcmsg = TcMsg {
            tcm_family: 0,
            tcm__pad1: 0,
            tcm__pad2: 0,
            tcm_ifindex: ifindex as i32,
            tcm_handle: 0,
            tcm_parent: parent_handle,
            tcm_info: info,
        };

        let mut builder = ack_request(NlMsgType::RTM_DELTFILTER);
        builder.append(&tcmsg);

        if let Some(k) = kind {
            builder.append_attr_str(TcaAttr::Kind as u16, k);
        }

        conn.request_ack(builder).await?;

        Ok(())
    }

    async fn replace(
        conn: &Connection,
        dev: &str,
        parent: &str,
        protocol: &str,
        prio: Option<u16>,
        kind: &str,
        params: &[String],
    ) -> Result<()> {
        use rip_netlink::connection::replace_request;

        let ifindex = rip_lib::ifname::name_to_index(dev).map_err(|e| {
            rip_netlink::Error::InvalidMessage(format!("interface not found: {}", e))
        })?;

        let parent_handle = tc_handle::parse(parent).ok_or_else(|| {
            rip_netlink::Error::InvalidMessage(format!("invalid parent: {}", parent))
        })?;

        let proto = parse_protocol(protocol)?;
        let priority = prio.unwrap_or(0);
        let info = ((proto as u32) << 16) | (priority as u32);

        let tcmsg = TcMsg {
            tcm_family: 0,
            tcm__pad1: 0,
            tcm__pad2: 0,
            tcm_ifindex: ifindex as i32,
            tcm_handle: 0,
            tcm_parent: parent_handle,
            tcm_info: info,
        };

        let mut builder = replace_request(NlMsgType::RTM_NEWTFILTER);
        builder.append(&tcmsg);

        // Add kind attribute
        builder.append_attr_str(TcaAttr::Kind as u16, kind);

        // Add filter-specific options
        if !params.is_empty() {
            let options_token = builder.nest_start(TcaAttr::Options as u16);
            add_filter_options(&mut builder, kind, params)?;
            builder.nest_end(options_token);
        }

        conn.request_ack(builder).await?;

        Ok(())
    }

    async fn change(
        conn: &Connection,
        dev: &str,
        parent: &str,
        protocol: &str,
        prio: Option<u16>,
        kind: &str,
        params: &[String],
    ) -> Result<()> {
        use rip_netlink::connection::ack_request;

        let ifindex = rip_lib::ifname::name_to_index(dev).map_err(|e| {
            rip_netlink::Error::InvalidMessage(format!("interface not found: {}", e))
        })?;

        let parent_handle = tc_handle::parse(parent).ok_or_else(|| {
            rip_netlink::Error::InvalidMessage(format!("invalid parent: {}", parent))
        })?;

        let proto = parse_protocol(protocol)?;
        let priority = prio.unwrap_or(0);
        let info = ((proto as u32) << 16) | (priority as u32);

        let tcmsg = TcMsg {
            tcm_family: 0,
            tcm__pad1: 0,
            tcm__pad2: 0,
            tcm_ifindex: ifindex as i32,
            tcm_handle: 0,
            tcm_parent: parent_handle,
            tcm_info: info,
        };

        let mut builder = ack_request(NlMsgType::RTM_NEWTFILTER);
        builder.append(&tcmsg);

        // Add kind attribute
        builder.append_attr_str(TcaAttr::Kind as u16, kind);

        // Add filter-specific options
        if !params.is_empty() {
            let options_token = builder.nest_start(TcaAttr::Options as u16);
            add_filter_options(&mut builder, kind, params)?;
            builder.nest_end(options_token);
        }

        conn.request_ack(builder).await?;

        Ok(())
    }
}

/// Parsed filter information.
#[derive(Debug)]
struct FilterInfo {
    ifindex: i32,
    handle: u32,
    parent: u32,
    protocol: u16,
    priority: u16,
    kind: String,
    chain: Option<u32>,
}

impl FilterInfo {
    fn to_json(&self) -> serde_json::Value {
        let dev = rip_lib::ifname::index_to_name(self.ifindex as u32)
            .unwrap_or_else(|_| format!("if{}", self.ifindex));

        let mut obj = serde_json::json!({
            "dev": dev,
            "kind": self.kind,
            "parent": tc_handle::format(self.parent),
            "protocol": format_protocol(self.protocol),
            "pref": self.priority,
        });

        if self.handle != 0 {
            obj["handle"] = serde_json::json!(format!("{:x}", self.handle));
        }

        if let Some(chain) = self.chain {
            obj["chain"] = serde_json::json!(chain);
        }

        obj
    }
}

fn parse_filter_message(data: &[u8]) -> Result<Option<FilterInfo>> {
    if data.len() < NLMSG_HDRLEN + TcMsg::SIZE {
        return Ok(None);
    }

    let header = NlMsgHdr::from_bytes(data)?;

    // Skip non-filter messages
    if header.nlmsg_type != NlMsgType::RTM_NEWTFILTER {
        return Ok(None);
    }

    let payload = &data[NLMSG_HDRLEN..];
    let tcmsg = TcMsg::from_bytes(payload)?;
    let attrs_data = &payload[TcMsg::SIZE..];

    // Extract protocol and priority from tcm_info
    let protocol = (tcmsg.tcm_info >> 16) as u16;
    let priority = (tcmsg.tcm_info & 0xFFFF) as u16;

    let mut kind = String::new();
    let mut chain = None;

    for (attr_type, attr_data) in AttrIter::new(attrs_data) {
        match TcaAttr::from(attr_type) {
            TcaAttr::Kind => {
                kind = get::string(attr_data).unwrap_or("").to_string();
            }
            TcaAttr::Chain => {
                chain = Some(get::u32_ne(attr_data).unwrap_or(0));
            }
            _ => {}
        }
    }

    Ok(Some(FilterInfo {
        ifindex: tcmsg.tcm_ifindex,
        handle: tcmsg.tcm_handle,
        parent: tcmsg.tcm_parent,
        protocol,
        priority,
        kind,
        chain,
    }))
}

fn print_filter_text<W: Write>(
    w: &mut W,
    filter: &FilterInfo,
    _opts: &OutputOptions,
) -> io::Result<()> {
    let dev = rip_lib::ifname::index_to_name(filter.ifindex as u32)
        .unwrap_or_else(|_| format!("if{}", filter.ifindex));

    write!(
        w,
        "filter parent {} protocol {} pref {} {} ",
        tc_handle::format(filter.parent),
        format_protocol(filter.protocol),
        filter.priority,
        filter.kind
    )?;

    if let Some(chain) = filter.chain {
        write!(w, "chain {} ", chain)?;
    }

    if filter.handle != 0 {
        write!(w, "handle {:x} ", filter.handle)?;
    }

    write!(w, "dev {}", dev)?;

    writeln!(w)?;

    Ok(())
}

/// Parse protocol name to number.
fn parse_protocol(name: &str) -> Result<u16> {
    Ok(match name.to_lowercase().as_str() {
        "all" => 0x0003,             // ETH_P_ALL
        "ip" => 0x0800,              // ETH_P_IP
        "ipv6" => 0x86DD,            // ETH_P_IPV6
        "arp" => 0x0806,             // ETH_P_ARP
        "802.1q" | "vlan" => 0x8100, // ETH_P_8021Q
        "802.1ad" => 0x88A8,         // ETH_P_8021AD
        "mpls_uc" => 0x8847,         // ETH_P_MPLS_UC
        "mpls_mc" => 0x8848,         // ETH_P_MPLS_MC
        _ => {
            // Try parsing as hex number
            if let Some(hex) = name.strip_prefix("0x") {
                u16::from_str_radix(hex, 16).map_err(|_| {
                    rip_netlink::Error::InvalidMessage(format!("invalid protocol: {}", name))
                })?
            } else {
                name.parse().map_err(|_| {
                    rip_netlink::Error::InvalidMessage(format!("unknown protocol: {}", name))
                })?
            }
        }
    })
}

/// Format protocol number to name.
fn format_protocol(proto: u16) -> String {
    match proto {
        0x0003 => "all".to_string(),
        0x0800 => "ip".to_string(),
        0x86DD => "ipv6".to_string(),
        0x0806 => "arp".to_string(),
        0x8100 => "802.1Q".to_string(),
        0x88A8 => "802.1ad".to_string(),
        0x8847 => "mpls_uc".to_string(),
        0x8848 => "mpls_mc".to_string(),
        _ => format!("0x{:04x}", proto),
    }
}

/// Add filter-specific options to the message.
fn add_filter_options(
    builder: &mut rip_netlink::MessageBuilder,
    kind: &str,
    params: &[String],
) -> Result<()> {
    use rip_netlink::types::tc::filter::*;

    match kind {
        "u32" => {
            let mut i = 0;
            while i < params.len() {
                match params[i].as_str() {
                    "classid" | "flowid" if i + 1 < params.len() => {
                        let classid = tc_handle::parse(&params[i + 1]).ok_or_else(|| {
                            rip_netlink::Error::InvalidMessage("invalid classid".into())
                        })?;
                        builder.append_attr_u32(u32::TCA_U32_CLASSID, classid);
                        i += 2;
                    }
                    "match" if i + 4 < params.len() => {
                        // Simple match parsing - skip for now, complex structure
                        i += 5;
                    }
                    _ => i += 1,
                }
            }
        }
        "flower" => {
            let mut i = 0;
            while i < params.len() {
                match params[i].as_str() {
                    "classid" | "flowid" if i + 1 < params.len() => {
                        let classid = tc_handle::parse(&params[i + 1]).ok_or_else(|| {
                            rip_netlink::Error::InvalidMessage("invalid classid".into())
                        })?;
                        builder.append_attr_u32(flower::TCA_FLOWER_CLASSID, classid);
                        i += 2;
                    }
                    "ip_proto" if i + 1 < params.len() => {
                        let proto = match params[i + 1].as_str() {
                            "tcp" => 6u8,
                            "udp" => 17u8,
                            "icmp" => 1u8,
                            "icmpv6" => 58u8,
                            _ => params[i + 1].parse().unwrap_or(0),
                        };
                        builder.append_attr_u8(flower::TCA_FLOWER_KEY_IP_PROTO, proto);
                        i += 2;
                    }
                    "dst_port" if i + 1 < params.len() => {
                        let port: u16 = params[i + 1].parse().map_err(|_| {
                            rip_netlink::Error::InvalidMessage("invalid port".into())
                        })?;
                        // Use TCP dest port by default
                        builder.append_attr_u16_be(flower::TCA_FLOWER_KEY_TCP_DST, port);
                        i += 2;
                    }
                    "src_port" if i + 1 < params.len() => {
                        let port: u16 = params[i + 1].parse().map_err(|_| {
                            rip_netlink::Error::InvalidMessage("invalid port".into())
                        })?;
                        builder.append_attr_u16_be(flower::TCA_FLOWER_KEY_TCP_SRC, port);
                        i += 2;
                    }
                    _ => i += 1,
                }
            }
        }
        "basic" | "matchall" => {
            // These filters use actions primarily
            let _ = (builder, params);
        }
        _ => {
            // Unknown filter type
            let _ = (builder, params);
        }
    }

    Ok(())
}
