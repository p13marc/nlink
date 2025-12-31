//! tc filter command implementation.

use clap::{Args, Subcommand};
use rip_netlink::message::NlMsgType;
use rip_netlink::messages::TcMessage;
use rip_netlink::types::tc::{TcMsg, TcaAttr, tc_handle};
use rip_netlink::{Connection, Result};
use rip_output::{OutputFormat, OutputOptions, print_items};
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
        protocol_filter: Option<&str>,
        prio_filter: Option<u16>,
        format: OutputFormat,
        opts: &OutputOptions,
    ) -> Result<()> {
        if dev.is_empty() {
            return Err(rip_netlink::Error::InvalidMessage(
                "device name required".into(),
            ));
        }

        let ifindex = rip_lib::get_ifindex(dev).map_err(rip_netlink::Error::InvalidMessage)?;

        let parent_handle = tc_handle::parse(parent).ok_or_else(|| {
            rip_netlink::Error::InvalidMessage(format!("invalid parent: {}", parent))
        })?;

        let proto_filter = protocol_filter.map(parse_protocol).transpose()?;

        // Fetch all filters using typed API
        let all_filters: Vec<TcMessage> = conn.dump_typed(NlMsgType::RTM_GETTFILTER).await?;

        // Filter results
        let filters: Vec<_> = all_filters
            .into_iter()
            .filter(|f| {
                // Filter by interface
                if f.ifindex() != ifindex {
                    return false;
                }
                // Filter by parent
                if f.parent() != parent_handle {
                    return false;
                }
                // Filter by protocol if specified
                if let Some(proto) = proto_filter
                    && f.protocol() != proto
                {
                    return false;
                }
                // Filter by priority if specified
                if let Some(prio) = prio_filter
                    && f.priority() != prio
                {
                    return false;
                }
                true
            })
            .collect();

        print_items(&filters, format, opts, filter_to_json, print_filter_text)?;

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

        let ifindex = rip_lib::get_ifindex(dev).map_err(rip_netlink::Error::InvalidMessage)?;

        let parent_handle = tc_handle::parse(parent).ok_or_else(|| {
            rip_netlink::Error::InvalidMessage(format!("invalid parent: {}", parent))
        })?;

        let proto = parse_protocol(protocol)?;
        let priority = prio.unwrap_or(0);

        // tcm_info contains protocol (upper 16 bits) and priority (lower 16 bits)
        let info = ((proto as u32) << 16) | (priority as u32);

        let tcmsg = TcMsg {
            tcm_family: 0,
            tcm_pad1: 0,
            tcm_pad2: 0,
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

        let ifindex = rip_lib::get_ifindex(dev).map_err(rip_netlink::Error::InvalidMessage)?;

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
            tcm_pad1: 0,
            tcm_pad2: 0,
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

        let ifindex = rip_lib::get_ifindex(dev).map_err(rip_netlink::Error::InvalidMessage)?;

        let parent_handle = tc_handle::parse(parent).ok_or_else(|| {
            rip_netlink::Error::InvalidMessage(format!("invalid parent: {}", parent))
        })?;

        let proto = parse_protocol(protocol)?;
        let priority = prio.unwrap_or(0);
        let info = ((proto as u32) << 16) | (priority as u32);

        let tcmsg = TcMsg {
            tcm_family: 0,
            tcm_pad1: 0,
            tcm_pad2: 0,
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

        let ifindex = rip_lib::get_ifindex(dev).map_err(rip_netlink::Error::InvalidMessage)?;

        let parent_handle = tc_handle::parse(parent).ok_or_else(|| {
            rip_netlink::Error::InvalidMessage(format!("invalid parent: {}", parent))
        })?;

        let proto = parse_protocol(protocol)?;
        let priority = prio.unwrap_or(0);
        let info = ((proto as u32) << 16) | (priority as u32);

        let tcmsg = TcMsg {
            tcm_family: 0,
            tcm_pad1: 0,
            tcm_pad2: 0,
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

/// Convert a TcMessage to JSON representation for filter.
fn filter_to_json(filter: &TcMessage) -> serde_json::Value {
    let dev = rip_lib::get_ifname_or_index(filter.ifindex());

    let mut obj = serde_json::json!({
        "dev": dev,
        "kind": filter.kind().unwrap_or(""),
        "parent": tc_handle::format(filter.parent()),
        "protocol": format_protocol(filter.protocol()),
        "pref": filter.priority(),
    });

    if filter.handle() != 0 {
        obj["handle"] = serde_json::json!(format!("{:x}", filter.handle()));
    }

    if let Some(chain) = filter.chain {
        obj["chain"] = serde_json::json!(chain);
    }

    obj
}

/// Print filter in text format.
fn print_filter_text(
    w: &mut io::StdoutLock<'_>,
    filter: &TcMessage,
    _opts: &OutputOptions,
) -> io::Result<()> {
    let dev = rip_lib::get_ifname_or_index(filter.ifindex());

    write!(
        w,
        "filter parent {} protocol {} pref {} {} ",
        tc_handle::format(filter.parent()),
        format_protocol(filter.protocol()),
        filter.priority(),
        filter.kind().unwrap_or("")
    )?;

    if let Some(chain) = filter.chain {
        write!(w, "chain {} ", chain)?;
    }

    if filter.handle() != 0 {
        write!(w, "handle {:x} ", filter.handle())?;
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
    match kind {
        "u32" => add_u32_filter_options(builder, params)?,
        "flower" => add_flower_filter_options(builder, params)?,
        "basic" | "matchall" => {
            // These filters use actions primarily - classid only
            add_basic_filter_options(builder, params)?;
        }
        "fw" => add_fw_filter_options(builder, params)?,
        _ => {
            // Unknown filter type
        }
    }

    Ok(())
}

/// Add u32 filter options.
///
/// Supports:
/// - match ip src ADDR - match source IP
/// - match ip dst ADDR - match destination IP
/// - match ip sport PORT - match source port
/// - match ip dport PORT - match destination port
/// - match ip protocol N - match IP protocol
/// - match u32 VAL MASK at OFF - match 32-bit value
/// - match u16 VAL MASK at OFF - match 16-bit value
/// - match u8 VAL MASK at OFF - match 8-bit value
/// - classid/flowid HANDLE - target class
fn add_u32_filter_options(
    builder: &mut rip_netlink::MessageBuilder,
    params: &[String],
) -> Result<()> {
    use rip_netlink::types::tc::filter::u32::*;

    let mut sel = TcU32Sel::new();
    let mut has_classid = false;

    let mut i = 0;
    while i < params.len() {
        match params[i].as_str() {
            "classid" | "flowid" if i + 1 < params.len() => {
                let classid = tc_handle::parse(&params[i + 1])
                    .ok_or_else(|| rip_netlink::Error::InvalidMessage("invalid classid".into()))?;
                builder.append_attr_u32(TCA_U32_CLASSID, classid);
                sel.set_terminal();
                has_classid = true;
                i += 2;
            }
            "match" if i + 1 < params.len() => {
                i += 1;
                // Parse match type
                match params[i].as_str() {
                    "ip" if i + 2 < params.len() => {
                        i += 1;
                        i = parse_ip_match(&mut sel, params, i)?;
                    }
                    "ip6" if i + 2 < params.len() => {
                        i += 1;
                        i = parse_ip6_match(&mut sel, params, i)?;
                    }
                    "tcp" | "udp" if i + 2 < params.len() => {
                        let proto = params[i].as_str();
                        i += 1;
                        i = parse_l4_match(&mut sel, params, i, proto)?;
                    }
                    "u32" if i + 3 < params.len() => {
                        i += 1;
                        let val = parse_hex_or_dec(&params[i])?;
                        i += 1;
                        let mask = parse_hex_or_dec(&params[i])?;
                        i += 1;
                        let off = parse_offset(params, &mut i)?;
                        sel.add_key(pack_key32(val, mask, off));
                    }
                    "u16" if i + 3 < params.len() => {
                        i += 1;
                        let val = parse_hex_or_dec(&params[i])? as u16;
                        i += 1;
                        let mask = parse_hex_or_dec(&params[i])? as u16;
                        i += 1;
                        let off = parse_offset(params, &mut i)?;
                        sel.add_key(pack_key16(val, mask, off));
                    }
                    "u8" if i + 3 < params.len() => {
                        i += 1;
                        let val = parse_hex_or_dec(&params[i])? as u8;
                        i += 1;
                        let mask = parse_hex_or_dec(&params[i])? as u8;
                        i += 1;
                        let off = parse_offset(params, &mut i)?;
                        sel.add_key(pack_key8(val, mask, off));
                    }
                    _ => {
                        return Err(rip_netlink::Error::InvalidMessage(format!(
                            "unknown match type: {}",
                            params[i]
                        )));
                    }
                }
            }
            "divisor" if i + 1 < params.len() => {
                let divisor: u32 = params[i + 1]
                    .parse()
                    .map_err(|_| rip_netlink::Error::InvalidMessage("invalid divisor".into()))?;
                builder.append_attr_u32(TCA_U32_DIVISOR, divisor);
                i += 2;
            }
            "link" if i + 1 < params.len() => {
                let link = parse_u32_handle(&params[i + 1])?;
                builder.append_attr_u32(TCA_U32_LINK, link);
                i += 2;
            }
            "ht" if i + 1 < params.len() => {
                let ht = parse_u32_handle(&params[i + 1])?;
                builder.append_attr_u32(TCA_U32_HASH, ht);
                i += 2;
            }
            _ => i += 1,
        }
    }

    // Add selector if we have any keys
    if sel.hdr.nkeys > 0 || has_classid {
        builder.append_attr(TCA_U32_SEL, &sel.to_bytes());
    }

    Ok(())
}

/// Parse an IP match (src, dst, sport, dport, protocol, tos).
fn parse_ip_match(
    sel: &mut rip_netlink::types::tc::filter::u32::TcU32Sel,
    params: &[String],
    mut i: usize,
) -> Result<usize> {
    use rip_netlink::types::tc::filter::u32::*;

    match params[i].as_str() {
        "src" if i + 1 < params.len() => {
            i += 1;
            let (addr, mask) = parse_ip_prefix(&params[i])?;
            sel.add_key(TcU32Key::new(addr.to_be(), mask.to_be(), 12));
            i += 1;
        }
        "dst" if i + 1 < params.len() => {
            i += 1;
            let (addr, mask) = parse_ip_prefix(&params[i])?;
            sel.add_key(TcU32Key::new(addr.to_be(), mask.to_be(), 16));
            i += 1;
        }
        "sport" if i + 1 < params.len() => {
            i += 1;
            let port: u16 = params[i]
                .parse()
                .map_err(|_| rip_netlink::Error::InvalidMessage("invalid port".into()))?;
            sel.add_key(pack_key16(port, 0xffff, 20));
            i += 1;
        }
        "dport" if i + 1 < params.len() => {
            i += 1;
            let port: u16 = params[i]
                .parse()
                .map_err(|_| rip_netlink::Error::InvalidMessage("invalid port".into()))?;
            sel.add_key(pack_key16(port, 0xffff, 22));
            i += 1;
        }
        "protocol" if i + 1 < params.len() => {
            i += 1;
            let proto: u8 = match params[i].as_str() {
                "tcp" => 6,
                "udp" => 17,
                "icmp" => 1,
                "gre" => 47,
                _ => params[i]
                    .parse()
                    .map_err(|_| rip_netlink::Error::InvalidMessage("invalid protocol".into()))?,
            };
            sel.add_key(pack_key8(proto, 0xff, 9));
            i += 1;
        }
        "tos" | "dsfield" if i + 1 < params.len() => {
            i += 1;
            let tos = parse_hex_or_dec(&params[i])? as u8;
            i += 1;
            let mask = if i < params.len() && !is_u32_keyword(&params[i]) {
                let m = parse_hex_or_dec(&params[i])? as u8;
                i += 1;
                m
            } else {
                0xff
            };
            sel.add_key(pack_key8(tos, mask, 1));
        }
        _ => {
            return Err(rip_netlink::Error::InvalidMessage(format!(
                "unknown ip match: {}",
                params[i]
            )));
        }
    }
    Ok(i)
}

/// Parse an IPv6 match.
fn parse_ip6_match(
    sel: &mut rip_netlink::types::tc::filter::u32::TcU32Sel,
    params: &[String],
    mut i: usize,
) -> Result<usize> {
    use rip_netlink::types::tc::filter::u32::*;

    match params[i].as_str() {
        "src" if i + 1 < params.len() => {
            i += 1;
            let keys = parse_ipv6_prefix(&params[i], 8)?;
            for key in keys {
                sel.add_key(key);
            }
            i += 1;
        }
        "dst" if i + 1 < params.len() => {
            i += 1;
            let keys = parse_ipv6_prefix(&params[i], 24)?;
            for key in keys {
                sel.add_key(key);
            }
            i += 1;
        }
        "sport" if i + 1 < params.len() => {
            i += 1;
            let port: u16 = params[i]
                .parse()
                .map_err(|_| rip_netlink::Error::InvalidMessage("invalid port".into()))?;
            sel.add_key(pack_key16(port, 0xffff, 40));
            i += 1;
        }
        "dport" if i + 1 < params.len() => {
            i += 1;
            let port: u16 = params[i]
                .parse()
                .map_err(|_| rip_netlink::Error::InvalidMessage("invalid port".into()))?;
            sel.add_key(pack_key16(port, 0xffff, 42));
            i += 1;
        }
        _ => {
            return Err(rip_netlink::Error::InvalidMessage(format!(
                "unknown ip6 match: {}",
                params[i]
            )));
        }
    }
    Ok(i)
}

/// Parse a TCP/UDP match (src, dst ports relative to L4 header).
fn parse_l4_match(
    sel: &mut rip_netlink::types::tc::filter::u32::TcU32Sel,
    params: &[String],
    mut i: usize,
    _proto: &str,
) -> Result<usize> {
    use rip_netlink::types::tc::filter::u32::*;

    match params[i].as_str() {
        "src" if i + 1 < params.len() => {
            i += 1;
            let port: u16 = params[i]
                .parse()
                .map_err(|_| rip_netlink::Error::InvalidMessage("invalid port".into()))?;
            // Use nexthdr+ offset for L4 matching
            sel.add_key(TcU32Key::with_nexthdr(
                ((port as u32) << 16).to_be(),
                0xffff0000u32.to_be(),
                0,
            ));
            i += 1;
        }
        "dst" if i + 1 < params.len() => {
            i += 1;
            let port: u16 = params[i]
                .parse()
                .map_err(|_| rip_netlink::Error::InvalidMessage("invalid port".into()))?;
            sel.add_key(TcU32Key::with_nexthdr(
                (port as u32).to_be(),
                0x0000ffffu32.to_be(),
                0,
            ));
            i += 1;
        }
        _ => {
            return Err(rip_netlink::Error::InvalidMessage(format!(
                "unknown tcp/udp match: {}",
                params[i]
            )));
        }
    }
    Ok(i)
}

/// Parse hex or decimal number.
fn parse_hex_or_dec(s: &str) -> Result<u32> {
    if let Some(hex) = s.strip_prefix("0x") {
        u32::from_str_radix(hex, 16)
    } else if let Some(hex) = s.strip_prefix("0X") {
        u32::from_str_radix(hex, 16)
    } else {
        s.parse()
    }
    .map_err(|_| rip_netlink::Error::InvalidMessage(format!("invalid number: {}", s)))
}

/// Parse "at OFFSET" from params.
fn parse_offset(params: &[String], i: &mut usize) -> Result<i32> {
    if *i < params.len() && params[*i] == "at" {
        *i += 1;
        if *i < params.len() {
            let off: i32 = params[*i]
                .parse()
                .map_err(|_| rip_netlink::Error::InvalidMessage("invalid offset".into()))?;
            *i += 1;
            return Ok(off);
        }
    }
    Err(rip_netlink::Error::InvalidMessage(
        "expected 'at OFFSET'".into(),
    ))
}

/// Parse u32 filter handle (htid:hash:node format).
fn parse_u32_handle(s: &str) -> Result<u32> {
    if let Some(hex) = s.strip_prefix("0x") {
        return u32::from_str_radix(hex, 16)
            .map_err(|_| rip_netlink::Error::InvalidMessage("invalid handle".into()));
    }

    let parts: Vec<&str> = s.split(':').collect();
    match parts.len() {
        1 => {
            let htid = u32::from_str_radix(parts[0], 16)
                .map_err(|_| rip_netlink::Error::InvalidMessage("invalid handle".into()))?;
            Ok(htid << 20)
        }
        2 => {
            let htid = if parts[0].is_empty() {
                0
            } else {
                u32::from_str_radix(parts[0], 16)
                    .map_err(|_| rip_netlink::Error::InvalidMessage("invalid handle".into()))?
            };
            let hash = if parts[1].is_empty() {
                0
            } else {
                u32::from_str_radix(parts[1], 16)
                    .map_err(|_| rip_netlink::Error::InvalidMessage("invalid handle".into()))?
            };
            Ok((htid << 20) | (hash << 12))
        }
        3 => {
            let htid = if parts[0].is_empty() {
                0
            } else {
                u32::from_str_radix(parts[0], 16)
                    .map_err(|_| rip_netlink::Error::InvalidMessage("invalid handle".into()))?
            };
            let hash = if parts[1].is_empty() {
                0
            } else {
                u32::from_str_radix(parts[1], 16)
                    .map_err(|_| rip_netlink::Error::InvalidMessage("invalid handle".into()))?
            };
            let node = if parts[2].is_empty() {
                0
            } else {
                u32::from_str_radix(parts[2], 16)
                    .map_err(|_| rip_netlink::Error::InvalidMessage("invalid handle".into()))?
            };
            Ok((htid << 20) | (hash << 12) | node)
        }
        _ => Err(rip_netlink::Error::InvalidMessage(
            "invalid handle format".into(),
        )),
    }
}

/// Parse IP address with optional prefix length.
fn parse_ip_prefix(s: &str) -> Result<(u32, u32)> {
    let (addr_str, prefix_len) = if let Some((a, p)) = s.split_once('/') {
        let plen: u8 = p
            .parse()
            .map_err(|_| rip_netlink::Error::InvalidMessage("invalid prefix length".into()))?;
        (a, plen)
    } else {
        (s, 32)
    };

    let addr: std::net::Ipv4Addr = addr_str
        .parse()
        .map_err(|_| rip_netlink::Error::InvalidMessage("invalid IP address".into()))?;

    let mask = if prefix_len == 0 {
        0
    } else {
        0xffffffffu32 << (32 - prefix_len)
    };

    Ok((u32::from(addr), mask))
}

/// Parse IPv6 address with prefix, returns multiple keys.
fn parse_ipv6_prefix(
    s: &str,
    base_off: i32,
) -> Result<Vec<rip_netlink::types::tc::filter::u32::TcU32Key>> {
    use rip_netlink::types::tc::filter::u32::TcU32Key;

    let (addr_str, prefix_len) = if let Some((a, p)) = s.split_once('/') {
        let plen: u8 = p
            .parse()
            .map_err(|_| rip_netlink::Error::InvalidMessage("invalid prefix length".into()))?;
        (a, plen as u32)
    } else {
        (s, 128)
    };

    let addr: std::net::Ipv6Addr = addr_str
        .parse()
        .map_err(|_| rip_netlink::Error::InvalidMessage("invalid IPv6 address".into()))?;

    let octets = addr.octets();
    let mut keys = Vec::new();

    let mut remaining = prefix_len;
    for i in 0..4 {
        if remaining == 0 {
            break;
        }
        let word_offset = base_off + (i * 4) as i32;
        let word = u32::from_be_bytes([
            octets[i * 4],
            octets[i * 4 + 1],
            octets[i * 4 + 2],
            octets[i * 4 + 3],
        ]);

        let bits = remaining.min(32);
        let mask = if bits == 32 {
            0xffffffff
        } else {
            0xffffffffu32 << (32 - bits)
        };

        keys.push(TcU32Key::new(word.to_be(), mask.to_be(), word_offset));
        remaining = remaining.saturating_sub(32);
    }

    Ok(keys)
}

/// Check if string is a u32 keyword.
fn is_u32_keyword(s: &str) -> bool {
    matches!(
        s,
        "match" | "classid" | "flowid" | "divisor" | "link" | "ht" | "at"
    )
}

/// Add flower filter options.
fn add_flower_filter_options(
    builder: &mut rip_netlink::MessageBuilder,
    params: &[String],
) -> Result<()> {
    use rip_netlink::types::tc::filter::flower::*;

    let mut i = 0;
    while i < params.len() {
        match params[i].as_str() {
            "classid" | "flowid" if i + 1 < params.len() => {
                let classid = tc_handle::parse(&params[i + 1])
                    .ok_or_else(|| rip_netlink::Error::InvalidMessage("invalid classid".into()))?;
                builder.append_attr_u32(TCA_FLOWER_CLASSID, classid);
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
                builder.append_attr_u8(TCA_FLOWER_KEY_IP_PROTO, proto);
                i += 2;
            }
            "dst_port" if i + 1 < params.len() => {
                let port: u16 = params[i + 1]
                    .parse()
                    .map_err(|_| rip_netlink::Error::InvalidMessage("invalid port".into()))?;
                builder.append_attr_u16_be(TCA_FLOWER_KEY_TCP_DST, port);
                i += 2;
            }
            "src_port" if i + 1 < params.len() => {
                let port: u16 = params[i + 1]
                    .parse()
                    .map_err(|_| rip_netlink::Error::InvalidMessage("invalid port".into()))?;
                builder.append_attr_u16_be(TCA_FLOWER_KEY_TCP_SRC, port);
                i += 2;
            }
            "dst_ip" if i + 1 < params.len() => {
                let (addr, mask) = parse_ip_prefix(&params[i + 1])?;
                builder.append_attr(TCA_FLOWER_KEY_IPV4_DST, &addr.to_be_bytes());
                builder.append_attr(TCA_FLOWER_KEY_IPV4_DST_MASK, &mask.to_be_bytes());
                i += 2;
            }
            "src_ip" if i + 1 < params.len() => {
                let (addr, mask) = parse_ip_prefix(&params[i + 1])?;
                builder.append_attr(TCA_FLOWER_KEY_IPV4_SRC, &addr.to_be_bytes());
                builder.append_attr(TCA_FLOWER_KEY_IPV4_SRC_MASK, &mask.to_be_bytes());
                i += 2;
            }
            "eth_type" if i + 1 < params.len() => {
                let eth_type: u16 = match params[i + 1].as_str() {
                    "ip" | "ipv4" => 0x0800,
                    "ipv6" => 0x86dd,
                    "arp" => 0x0806,
                    _ => parse_hex_or_dec(&params[i + 1])? as u16,
                };
                builder.append_attr_u16_be(TCA_FLOWER_KEY_ETH_TYPE, eth_type);
                i += 2;
            }
            _ => i += 1,
        }
    }

    Ok(())
}

/// Add basic/matchall filter options.
fn add_basic_filter_options(
    builder: &mut rip_netlink::MessageBuilder,
    params: &[String],
) -> Result<()> {
    // Basic filter primarily uses classid
    let mut i = 0;
    while i < params.len() {
        match params[i].as_str() {
            "classid" | "flowid" if i + 1 < params.len() => {
                let classid = tc_handle::parse(&params[i + 1])
                    .ok_or_else(|| rip_netlink::Error::InvalidMessage("invalid classid".into()))?;
                // Basic filter uses a different attribute
                builder.append_attr_u32(1, classid); // TCA_BASIC_CLASSID
                i += 2;
            }
            _ => i += 1,
        }
    }
    Ok(())
}

/// Add fw (firewall mark) filter options.
fn add_fw_filter_options(
    builder: &mut rip_netlink::MessageBuilder,
    params: &[String],
) -> Result<()> {
    // fw filter matches on fwmark set by iptables/nftables
    let mut i = 0;
    while i < params.len() {
        match params[i].as_str() {
            "classid" | "flowid" if i + 1 < params.len() => {
                let classid = tc_handle::parse(&params[i + 1])
                    .ok_or_else(|| rip_netlink::Error::InvalidMessage("invalid classid".into()))?;
                builder.append_attr_u32(1, classid); // TCA_FW_CLASSID
                i += 2;
            }
            "mask" if i + 1 < params.len() => {
                let mask = parse_hex_or_dec(&params[i + 1])?;
                builder.append_attr_u32(2, mask); // TCA_FW_MASK
                i += 2;
            }
            _ => i += 1,
        }
    }
    Ok(())
}
