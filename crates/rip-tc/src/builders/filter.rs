//! Filter message builders.
//!
//! This module provides high-level builders for creating filter netlink messages.

use rip_netlink::connection::{ack_request, create_request, replace_request};
use rip_netlink::message::NlMsgType;
use rip_netlink::types::tc::{TcMsg, TcaAttr, tc_handle};
use rip_netlink::{Connection, MessageBuilder, Result};

/// Build a TcMsg with common fields for filter operations.
fn build_tcmsg(dev: &str, parent: &str, protocol: u16, priority: u16) -> Result<TcMsg> {
    let ifindex = rip_lib::get_ifindex(dev).map_err(rip_netlink::Error::InvalidMessage)?;

    let parent_handle = tc_handle::parse(parent).ok_or_else(|| {
        rip_netlink::Error::InvalidMessage(format!("invalid parent handle: {}", parent))
    })?;

    // tcm_info contains protocol (upper 16 bits) and priority (lower 16 bits)
    let info = ((protocol as u32) << 16) | (priority as u32);

    Ok(TcMsg {
        tcm_family: 0,
        tcm_pad1: 0,
        tcm_pad2: 0,
        tcm_ifindex: ifindex as i32,
        tcm_handle: 0,
        tcm_parent: parent_handle,
        tcm_info: info,
    })
}

/// Parse protocol name to number.
pub fn parse_protocol(name: &str) -> Result<u16> {
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
pub fn format_protocol(proto: u16) -> String {
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
pub fn add_options(builder: &mut MessageBuilder, kind: &str, params: &[String]) -> Result<()> {
    if params.is_empty() {
        return Ok(());
    }

    let options_token = builder.nest_start(TcaAttr::Options as u16);

    match kind {
        "u32" => add_u32_options(builder, params)?,
        "flower" => add_flower_options(builder, params)?,
        "basic" | "matchall" => add_basic_options(builder, params)?,
        "fw" => add_fw_options(builder, params)?,
        _ => {
            // Unknown filter type
        }
    }

    builder.nest_end(options_token);
    Ok(())
}

/// Add a new filter.
///
/// # Arguments
/// * `conn` - The netlink connection
/// * `dev` - Device name
/// * `parent` - Parent handle (e.g., "root", "1:0")
/// * `protocol` - Protocol name (e.g., "ip", "all")
/// * `prio` - Optional priority
/// * `kind` - Filter type (e.g., "u32", "flower")
/// * `params` - Type-specific parameters
pub async fn add(
    conn: &Connection,
    dev: &str,
    parent: &str,
    protocol: &str,
    prio: Option<u16>,
    kind: &str,
    params: &[String],
) -> Result<()> {
    let proto = parse_protocol(protocol)?;
    let priority = prio.unwrap_or(0);
    let tcmsg = build_tcmsg(dev, parent, proto, priority)?;

    let mut builder = create_request(NlMsgType::RTM_NEWTFILTER);
    builder.append(&tcmsg);
    builder.append_attr_str(TcaAttr::Kind as u16, kind);

    add_options(&mut builder, kind, params)?;

    conn.request_ack(builder).await?;
    Ok(())
}

/// Delete a filter.
///
/// # Arguments
/// * `conn` - The netlink connection
/// * `dev` - Device name
/// * `parent` - Parent handle
/// * `protocol` - Optional protocol name
/// * `prio` - Optional priority
/// * `kind` - Optional filter type
pub async fn del(
    conn: &Connection,
    dev: &str,
    parent: &str,
    protocol: Option<&str>,
    prio: Option<u16>,
    kind: Option<&str>,
) -> Result<()> {
    let proto = if let Some(p) = protocol {
        parse_protocol(p)?
    } else {
        0
    };
    let priority = prio.unwrap_or(0);
    let tcmsg = build_tcmsg(dev, parent, proto, priority)?;

    let mut builder = ack_request(NlMsgType::RTM_DELTFILTER);
    builder.append(&tcmsg);

    if let Some(k) = kind {
        builder.append_attr_str(TcaAttr::Kind as u16, k);
    }

    conn.request_ack(builder).await?;
    Ok(())
}

/// Replace a filter (add or update).
///
/// # Arguments
/// * `conn` - The netlink connection
/// * `dev` - Device name
/// * `parent` - Parent handle
/// * `protocol` - Protocol name
/// * `prio` - Optional priority
/// * `kind` - Filter type
/// * `params` - Type-specific parameters
pub async fn replace(
    conn: &Connection,
    dev: &str,
    parent: &str,
    protocol: &str,
    prio: Option<u16>,
    kind: &str,
    params: &[String],
) -> Result<()> {
    let proto = parse_protocol(protocol)?;
    let priority = prio.unwrap_or(0);
    let tcmsg = build_tcmsg(dev, parent, proto, priority)?;

    let mut builder = replace_request(NlMsgType::RTM_NEWTFILTER);
    builder.append(&tcmsg);
    builder.append_attr_str(TcaAttr::Kind as u16, kind);

    add_options(&mut builder, kind, params)?;

    conn.request_ack(builder).await?;
    Ok(())
}

/// Change a filter's parameters.
///
/// # Arguments
/// * `conn` - The netlink connection
/// * `dev` - Device name
/// * `parent` - Parent handle
/// * `protocol` - Protocol name
/// * `prio` - Optional priority
/// * `kind` - Filter type
/// * `params` - Type-specific parameters
pub async fn change(
    conn: &Connection,
    dev: &str,
    parent: &str,
    protocol: &str,
    prio: Option<u16>,
    kind: &str,
    params: &[String],
) -> Result<()> {
    let proto = parse_protocol(protocol)?;
    let priority = prio.unwrap_or(0);
    let tcmsg = build_tcmsg(dev, parent, proto, priority)?;

    let mut builder = ack_request(NlMsgType::RTM_NEWTFILTER);
    builder.append(&tcmsg);
    builder.append_attr_str(TcaAttr::Kind as u16, kind);

    add_options(&mut builder, kind, params)?;

    conn.request_ack(builder).await?;
    Ok(())
}

// ============================================================================
// U32 Filter Options
// ============================================================================

/// Add u32 filter options.
fn add_u32_options(builder: &mut MessageBuilder, params: &[String]) -> Result<()> {
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
            sel.add_key(rip_netlink::types::tc::filter::u32::pack_key16(
                port, 0xffff, 40,
            ));
            i += 1;
        }
        "dport" if i + 1 < params.len() => {
            i += 1;
            let port: u16 = params[i]
                .parse()
                .map_err(|_| rip_netlink::Error::InvalidMessage("invalid port".into()))?;
            sel.add_key(rip_netlink::types::tc::filter::u32::pack_key16(
                port, 0xffff, 42,
            ));
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

/// Parse a TCP/UDP match.
fn parse_l4_match(
    sel: &mut rip_netlink::types::tc::filter::u32::TcU32Sel,
    params: &[String],
    mut i: usize,
    _proto: &str,
) -> Result<usize> {
    use rip_netlink::types::tc::filter::u32::TcU32Key;

    match params[i].as_str() {
        "src" if i + 1 < params.len() => {
            i += 1;
            let port: u16 = params[i]
                .parse()
                .map_err(|_| rip_netlink::Error::InvalidMessage("invalid port".into()))?;
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

// ============================================================================
// Flower Filter Options
// ============================================================================

/// Add flower filter options.
///
/// Supported parameters:
/// - classid/flowid HANDLE: Target class
/// - ip_proto tcp|udp|icmp|sctp|N: IP protocol
/// - src_ip ADDR[/PREFIX]: Source IPv4/IPv6 address
/// - dst_ip ADDR[/PREFIX]: Destination IPv4/IPv6 address
/// - src_port PORT: Source port (TCP/UDP/SCTP)
/// - dst_port PORT: Destination port (TCP/UDP/SCTP)
/// - src_mac MAC: Source MAC address
/// - dst_mac MAC: Destination MAC address
/// - eth_type ip|ipv6|arp|N: Ethernet type
/// - vlan_id N: VLAN ID (1-4094)
/// - vlan_prio N: VLAN priority (0-7)
/// - ip_tos N[/MASK]: IP TOS/DSCP
/// - ip_ttl N[/MASK]: IP TTL
/// - tcp_flags FLAGS[/MASK]: TCP flags (syn,ack,fin,rst,psh,urg)
/// - ct_state STATE: Connection tracking state (new,established,related,tracked,invalid,reply)
/// - ct_zone N: Connection tracking zone
/// - ct_mark N[/MASK]: Connection tracking mark
/// - enc_key_id N: Tunnel key ID (VNI)
/// - enc_dst_ip ADDR: Tunnel destination IP
/// - enc_src_ip ADDR: Tunnel source IP
/// - enc_dst_port PORT: Tunnel destination port
/// - skip_hw: Don't offload to hardware
/// - skip_sw: Don't process in software
/// - action ACTION...: Attach action(s)
fn add_flower_options(builder: &mut MessageBuilder, params: &[String]) -> Result<()> {
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
                let proto = parse_ip_proto(&params[i + 1]).ok_or_else(|| {
                    rip_netlink::Error::InvalidMessage(format!(
                        "invalid ip_proto: {}",
                        params[i + 1]
                    ))
                })?;
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
                i += 1;
                if params[i].contains(':') {
                    // IPv6
                    let (addr, mask) = parse_ipv6_prefix_flower(&params[i])?;
                    builder.append_attr(TCA_FLOWER_KEY_IPV6_DST, &addr);
                    builder.append_attr(TCA_FLOWER_KEY_IPV6_DST_MASK, &mask);
                } else {
                    // IPv4
                    let (addr, mask) = parse_ip_prefix(&params[i])?;
                    builder.append_attr(TCA_FLOWER_KEY_IPV4_DST, &addr.to_be_bytes());
                    builder.append_attr(TCA_FLOWER_KEY_IPV4_DST_MASK, &mask.to_be_bytes());
                }
                i += 1;
            }
            "src_ip" if i + 1 < params.len() => {
                i += 1;
                if params[i].contains(':') {
                    // IPv6
                    let (addr, mask) = parse_ipv6_prefix_flower(&params[i])?;
                    builder.append_attr(TCA_FLOWER_KEY_IPV6_SRC, &addr);
                    builder.append_attr(TCA_FLOWER_KEY_IPV6_SRC_MASK, &mask);
                } else {
                    // IPv4
                    let (addr, mask) = parse_ip_prefix(&params[i])?;
                    builder.append_attr(TCA_FLOWER_KEY_IPV4_SRC, &addr.to_be_bytes());
                    builder.append_attr(TCA_FLOWER_KEY_IPV4_SRC_MASK, &mask.to_be_bytes());
                }
                i += 1;
            }
            "dst_mac" if i + 1 < params.len() => {
                let mac = parse_mac_addr(&params[i + 1])?;
                builder.append_attr(TCA_FLOWER_KEY_ETH_DST, &mac);
                builder.append_attr(TCA_FLOWER_KEY_ETH_DST_MASK, &[0xff; 6]);
                i += 2;
            }
            "src_mac" if i + 1 < params.len() => {
                let mac = parse_mac_addr(&params[i + 1])?;
                builder.append_attr(TCA_FLOWER_KEY_ETH_SRC, &mac);
                builder.append_attr(TCA_FLOWER_KEY_ETH_SRC_MASK, &[0xff; 6]);
                i += 2;
            }
            "eth_type" if i + 1 < params.len() => {
                let eth_type: u16 = match params[i + 1].as_str() {
                    "ip" | "ipv4" => 0x0800,
                    "ipv6" => 0x86dd,
                    "arp" => 0x0806,
                    "vlan" | "802.1q" => 0x8100,
                    "802.1ad" => 0x88a8,
                    _ => parse_hex_or_dec(&params[i + 1])? as u16,
                };
                builder.append_attr_u16_be(TCA_FLOWER_KEY_ETH_TYPE, eth_type);
                i += 2;
            }
            "vlan_id" if i + 1 < params.len() => {
                let id: u16 = params[i + 1]
                    .parse()
                    .map_err(|_| rip_netlink::Error::InvalidMessage("invalid vlan_id".into()))?;
                if id == 0 || id > 4094 {
                    return Err(rip_netlink::Error::InvalidMessage(
                        "vlan_id must be 1-4094".into(),
                    ));
                }
                builder.append_attr_u16(TCA_FLOWER_KEY_VLAN_ID, id);
                i += 2;
            }
            "vlan_prio" if i + 1 < params.len() => {
                let prio: u8 = params[i + 1]
                    .parse()
                    .map_err(|_| rip_netlink::Error::InvalidMessage("invalid vlan_prio".into()))?;
                if prio > 7 {
                    return Err(rip_netlink::Error::InvalidMessage(
                        "vlan_prio must be 0-7".into(),
                    ));
                }
                builder.append_attr_u8(TCA_FLOWER_KEY_VLAN_PRIO, prio);
                i += 2;
            }
            "ip_tos" if i + 1 < params.len() => {
                let (val, mask) = parse_value_mask_u8(&params[i + 1])?;
                builder.append_attr_u8(TCA_FLOWER_KEY_IP_TOS, val);
                builder.append_attr_u8(TCA_FLOWER_KEY_IP_TOS_MASK, mask);
                i += 2;
            }
            "ip_ttl" if i + 1 < params.len() => {
                let (val, mask) = parse_value_mask_u8(&params[i + 1])?;
                builder.append_attr_u8(TCA_FLOWER_KEY_IP_TTL, val);
                builder.append_attr_u8(TCA_FLOWER_KEY_IP_TTL_MASK, mask);
                i += 2;
            }
            "tcp_flags" if i + 1 < params.len() => {
                let (flags, mask) = parse_tcp_flags(&params[i + 1])?;
                builder.append_attr_u16_be(TCA_FLOWER_KEY_TCP_FLAGS, flags);
                builder.append_attr_u16_be(TCA_FLOWER_KEY_TCP_FLAGS_MASK, mask);
                i += 2;
            }
            "ct_state" if i + 1 < params.len() => {
                let state = parse_ct_state(&params[i + 1])?;
                builder.append_attr_u16(TCA_FLOWER_KEY_CT_STATE, state);
                builder.append_attr_u16(TCA_FLOWER_KEY_CT_STATE_MASK, state);
                i += 2;
            }
            "ct_zone" if i + 1 < params.len() => {
                let zone: u16 = params[i + 1]
                    .parse()
                    .map_err(|_| rip_netlink::Error::InvalidMessage("invalid ct_zone".into()))?;
                builder.append_attr_u16(TCA_FLOWER_KEY_CT_ZONE, zone);
                builder.append_attr_u16(TCA_FLOWER_KEY_CT_ZONE_MASK, 0xffff);
                i += 2;
            }
            "ct_mark" if i + 1 < params.len() => {
                let (val, mask) = parse_value_mask_u32(&params[i + 1])?;
                builder.append_attr_u32(TCA_FLOWER_KEY_CT_MARK, val);
                builder.append_attr_u32(TCA_FLOWER_KEY_CT_MARK_MASK, mask);
                i += 2;
            }
            "enc_key_id" if i + 1 < params.len() => {
                let id: u32 = params[i + 1]
                    .parse()
                    .map_err(|_| rip_netlink::Error::InvalidMessage("invalid enc_key_id".into()))?;
                builder.append_attr_u32(TCA_FLOWER_KEY_ENC_KEY_ID, id.to_be());
                i += 2;
            }
            "enc_dst_ip" if i + 1 < params.len() => {
                i += 1;
                if params[i].contains(':') {
                    let (addr, mask) = parse_ipv6_prefix_flower(&params[i])?;
                    builder.append_attr(TCA_FLOWER_KEY_ENC_IPV6_DST, &addr);
                    builder.append_attr(TCA_FLOWER_KEY_ENC_IPV6_DST_MASK, &mask);
                } else {
                    let (addr, mask) = parse_ip_prefix(&params[i])?;
                    builder.append_attr(TCA_FLOWER_KEY_ENC_IPV4_DST, &addr.to_be_bytes());
                    builder.append_attr(TCA_FLOWER_KEY_ENC_IPV4_DST_MASK, &mask.to_be_bytes());
                }
                i += 1;
            }
            "enc_src_ip" if i + 1 < params.len() => {
                i += 1;
                if params[i].contains(':') {
                    let (addr, mask) = parse_ipv6_prefix_flower(&params[i])?;
                    builder.append_attr(TCA_FLOWER_KEY_ENC_IPV6_SRC, &addr);
                    builder.append_attr(TCA_FLOWER_KEY_ENC_IPV6_SRC_MASK, &mask);
                } else {
                    let (addr, mask) = parse_ip_prefix(&params[i])?;
                    builder.append_attr(TCA_FLOWER_KEY_ENC_IPV4_SRC, &addr.to_be_bytes());
                    builder.append_attr(TCA_FLOWER_KEY_ENC_IPV4_SRC_MASK, &mask.to_be_bytes());
                }
                i += 1;
            }
            "enc_dst_port" if i + 1 < params.len() => {
                let port: u16 = params[i + 1].parse().map_err(|_| {
                    rip_netlink::Error::InvalidMessage("invalid enc_dst_port".into())
                })?;
                builder.append_attr_u16_be(TCA_FLOWER_KEY_ENC_UDP_DST_PORT, port);
                i += 2;
            }
            "skip_hw" => {
                builder.append_attr_u32(TCA_FLOWER_FLAGS, TCA_CLS_FLAGS_SKIP_HW);
                i += 1;
            }
            "skip_sw" => {
                builder.append_attr_u32(TCA_FLOWER_FLAGS, TCA_CLS_FLAGS_SKIP_SW);
                i += 1;
            }
            "indev" if i + 1 < params.len() => {
                builder.append_attr_str(TCA_FLOWER_INDEV, &params[i + 1]);
                i += 2;
            }
            _ => i += 1,
        }
    }

    Ok(())
}

/// Parse MAC address (xx:xx:xx:xx:xx:xx format).
fn parse_mac_addr(s: &str) -> Result<[u8; 6]> {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 6 {
        return Err(rip_netlink::Error::InvalidMessage(format!(
            "invalid MAC address: {}",
            s
        )));
    }
    let mut mac = [0u8; 6];
    for (i, part) in parts.iter().enumerate() {
        mac[i] = u8::from_str_radix(part, 16).map_err(|_| {
            rip_netlink::Error::InvalidMessage(format!("invalid MAC address: {}", s))
        })?;
    }
    Ok(mac)
}

/// Parse IPv6 address with prefix for flower filter.
fn parse_ipv6_prefix_flower(s: &str) -> Result<([u8; 16], [u8; 16])> {
    let (addr_str, prefix_len) = if let Some((a, p)) = s.split_once('/') {
        let plen: u8 = p
            .parse()
            .map_err(|_| rip_netlink::Error::InvalidMessage("invalid prefix length".into()))?;
        (a, plen)
    } else {
        (s, 128)
    };

    let addr: std::net::Ipv6Addr = addr_str
        .parse()
        .map_err(|_| rip_netlink::Error::InvalidMessage("invalid IPv6 address".into()))?;

    let mut mask = [0u8; 16];
    for i in 0..16 {
        let bits = if (i * 8) < prefix_len as usize {
            let remaining = prefix_len as usize - (i * 8);
            if remaining >= 8 { 8 } else { remaining }
        } else {
            0
        };
        mask[i] = if bits == 8 { 0xff } else { 0xff << (8 - bits) };
    }

    Ok((addr.octets(), mask))
}

/// Parse value/mask format for u8 (e.g., "0x10/0xff").
fn parse_value_mask_u8(s: &str) -> Result<(u8, u8)> {
    if let Some((val, mask)) = s.split_once('/') {
        let v = parse_hex_or_dec(val)? as u8;
        let m = parse_hex_or_dec(mask)? as u8;
        Ok((v, m))
    } else {
        let v = parse_hex_or_dec(s)? as u8;
        Ok((v, 0xff))
    }
}

/// Parse value/mask format for u32 (e.g., "0x100/0xfff").
fn parse_value_mask_u32(s: &str) -> Result<(u32, u32)> {
    if let Some((val, mask)) = s.split_once('/') {
        let v = parse_hex_or_dec(val)?;
        let m = parse_hex_or_dec(mask)?;
        Ok((v, m))
    } else {
        let v = parse_hex_or_dec(s)?;
        Ok((v, 0xffffffff))
    }
}

/// Parse TCP flags (syn,ack,fin,rst,psh,urg).
fn parse_tcp_flags(s: &str) -> Result<(u16, u16)> {
    let (flags_str, mask_str) = if let Some((f, m)) = s.split_once('/') {
        (f, Some(m))
    } else {
        (s, None)
    };

    let mut flags: u16 = 0;
    for flag in flags_str.split('+') {
        flags |= match flag.to_lowercase().as_str() {
            "fin" => 0x01,
            "syn" => 0x02,
            "rst" => 0x04,
            "psh" => 0x08,
            "ack" => 0x10,
            "urg" => 0x20,
            "ece" => 0x40,
            "cwr" => 0x80,
            _ => parse_hex_or_dec(flag)? as u16,
        };
    }

    let mask = if let Some(m) = mask_str {
        let mut mask: u16 = 0;
        for flag in m.split('+') {
            mask |= match flag.to_lowercase().as_str() {
                "fin" => 0x01,
                "syn" => 0x02,
                "rst" => 0x04,
                "psh" => 0x08,
                "ack" => 0x10,
                "urg" => 0x20,
                "ece" => 0x40,
                "cwr" => 0x80,
                _ => parse_hex_or_dec(flag)? as u16,
            };
        }
        mask
    } else {
        flags
    };

    Ok((flags, mask))
}

/// Parse connection tracking state.
fn parse_ct_state(s: &str) -> Result<u16> {
    use rip_netlink::types::tc::filter::flower::*;

    let mut state: u16 = 0;
    for part in s.split('+') {
        state |= match part.to_lowercase().as_str() {
            "new" => TCA_FLOWER_KEY_CT_FLAGS_NEW,
            "established" | "est" => TCA_FLOWER_KEY_CT_FLAGS_ESTABLISHED,
            "related" | "rel" => TCA_FLOWER_KEY_CT_FLAGS_RELATED,
            "tracked" | "trk" => TCA_FLOWER_KEY_CT_FLAGS_TRACKED,
            "invalid" | "inv" => TCA_FLOWER_KEY_CT_FLAGS_INVALID,
            "reply" | "rpl" => TCA_FLOWER_KEY_CT_FLAGS_REPLY,
            _ => {
                return Err(rip_netlink::Error::InvalidMessage(format!(
                    "unknown ct_state: {}",
                    part
                )));
            }
        };
    }
    Ok(state)
}

// ============================================================================
// Basic/Matchall Filter Options
// ============================================================================

/// Add basic/matchall filter options.
fn add_basic_options(builder: &mut MessageBuilder, params: &[String]) -> Result<()> {
    let mut i = 0;
    while i < params.len() {
        match params[i].as_str() {
            "classid" | "flowid" if i + 1 < params.len() => {
                let classid = tc_handle::parse(&params[i + 1])
                    .ok_or_else(|| rip_netlink::Error::InvalidMessage("invalid classid".into()))?;
                builder.append_attr_u32(1, classid); // TCA_BASIC_CLASSID
                i += 2;
            }
            _ => i += 1,
        }
    }
    Ok(())
}

// ============================================================================
// FW (Firewall Mark) Filter Options
// ============================================================================

/// Add fw filter options.
fn add_fw_options(builder: &mut MessageBuilder, params: &[String]) -> Result<()> {
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
