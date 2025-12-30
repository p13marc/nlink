//! ip monitor - watch for netlink events.

use clap::{Args, ValueEnum};
use rip_netlink::attr::{AttrIter, get};
use rip_netlink::message::{MessageIter, NlMsgType};
use rip_netlink::rtnetlink_groups::*;
use rip_netlink::types::addr::{IfAddrMsg, IfaAttr};
use rip_netlink::types::link::{IfInfoMsg, IflaAttr, iff};
use rip_netlink::types::neigh::{NdMsg, NdaAttr, nud_state_name};
use rip_netlink::types::route::{RtMsg, RtaAttr};
use rip_netlink::{Connection, Protocol, Result};
use rip_output::{OutputFormat, OutputOptions};
use std::io::{self, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Event types that can be monitored.
#[derive(Debug, Clone, Copy, ValueEnum, PartialEq, Eq)]
pub enum EventType {
    /// Link state changes (interfaces up/down, created, deleted).
    Link,
    /// Address changes (added, removed, modified).
    Address,
    /// Routing table changes.
    Route,
    /// Neighbor (ARP/NDP) cache changes.
    Neigh,
    /// All event types.
    All,
}

#[derive(Args)]
pub struct MonitorCmd {
    /// Event types to monitor.
    #[arg(default_value = "all")]
    objects: Vec<EventType>,

    /// Label output lines with event timestamps.
    #[arg(short = 't', long)]
    timestamp: bool,
}

impl MonitorCmd {
    pub async fn run(&self, format: OutputFormat, opts: &OutputOptions) -> Result<()> {
        let mut conn = Connection::new(Protocol::Route)?;

        // Determine which groups to subscribe to
        let monitor_link = self
            .objects
            .iter()
            .any(|o| matches!(o, EventType::Link | EventType::All));
        let monitor_addr = self
            .objects
            .iter()
            .any(|o| matches!(o, EventType::Address | EventType::All));
        let monitor_route = self
            .objects
            .iter()
            .any(|o| matches!(o, EventType::Route | EventType::All));
        let monitor_neigh = self
            .objects
            .iter()
            .any(|o| matches!(o, EventType::Neigh | EventType::All));

        // Subscribe to multicast groups
        if monitor_link {
            conn.subscribe(RTNLGRP_LINK)?;
        }
        if monitor_addr {
            conn.subscribe(RTNLGRP_IPV4_IFADDR)?;
            conn.subscribe(RTNLGRP_IPV6_IFADDR)?;
        }
        if monitor_route {
            conn.subscribe(RTNLGRP_IPV4_ROUTE)?;
            conn.subscribe(RTNLGRP_IPV6_ROUTE)?;
        }
        if monitor_neigh {
            conn.subscribe(RTNLGRP_NEIGH)?;
        }

        let mut stdout = io::stdout().lock();

        if format == OutputFormat::Text {
            writeln!(stdout, "Monitoring netlink events (Ctrl+C to stop)...")?;
        }

        // Event loop
        loop {
            let data = conn.recv_event().await?;

            for result in MessageIter::new(&data) {
                let (header, payload) = result?;

                // Skip error/done/noop messages
                if header.is_error() || header.is_done() || header.nlmsg_type == NlMsgType::NOOP {
                    continue;
                }

                if self.timestamp {
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default();
                    write!(stdout, "[{}.{:03}] ", now.as_secs(), now.subsec_millis())?;
                }

                match format {
                    OutputFormat::Text => {
                        self.print_event_text(&mut stdout, header.nlmsg_type, payload, opts)?;
                    }
                    OutputFormat::Json => {
                        self.print_event_json(&mut stdout, header.nlmsg_type, payload)?;
                    }
                }
            }
        }
    }

    fn print_event_text(
        &self,
        out: &mut impl Write,
        msg_type: u16,
        payload: &[u8],
        _opts: &OutputOptions,
    ) -> Result<()> {
        match msg_type {
            NlMsgType::RTM_NEWLINK | NlMsgType::RTM_DELLINK => {
                self.print_link_event(out, msg_type, payload)?;
            }
            NlMsgType::RTM_NEWADDR | NlMsgType::RTM_DELADDR => {
                self.print_addr_event(out, msg_type, payload)?;
            }
            NlMsgType::RTM_NEWROUTE | NlMsgType::RTM_DELROUTE => {
                self.print_route_event(out, msg_type, payload)?;
            }
            NlMsgType::RTM_NEWNEIGH | NlMsgType::RTM_DELNEIGH => {
                self.print_neigh_event(out, msg_type, payload)?;
            }
            _ => {
                writeln!(out, "EVENT: type={}", msg_type)?;
            }
        }
        out.flush()?;
        Ok(())
    }

    fn print_link_event(&self, out: &mut impl Write, msg_type: u16, payload: &[u8]) -> Result<()> {
        let ifinfo = IfInfoMsg::from_bytes(payload)?;
        let attrs_data = &payload[IfInfoMsg::SIZE..];

        let mut name = String::new();
        for (attr_type, attr_data) in AttrIter::new(attrs_data) {
            if IflaAttr::from(attr_type) == IflaAttr::Ifname {
                name = get::string(attr_data).unwrap_or("").to_string();
                break;
            }
        }

        let action = if msg_type == NlMsgType::RTM_NEWLINK {
            "LINK"
        } else {
            "LINK DEL"
        };

        let state = if ifinfo.ifi_flags & iff::UP != 0 {
            "UP"
        } else {
            "DOWN"
        };

        writeln!(
            out,
            "{}: {} index {} state {}",
            action, name, ifinfo.ifi_index, state
        )?;
        Ok(())
    }

    fn print_addr_event(&self, out: &mut impl Write, msg_type: u16, payload: &[u8]) -> Result<()> {
        let addr_msg = IfAddrMsg::from_bytes(payload)?;
        let attrs_data = &payload[IfAddrMsg::SIZE..];

        let mut address: Option<IpAddr> = None;
        for (attr_type, attr_data) in AttrIter::new(attrs_data) {
            match IfaAttr::from(attr_type) {
                IfaAttr::Address | IfaAttr::Local => {
                    address = parse_ip_addr(addr_msg.ifa_family, attr_data);
                    if address.is_some() {
                        break;
                    }
                }
                _ => {}
            }
        }

        let action = if msg_type == NlMsgType::RTM_NEWADDR {
            "ADDR"
        } else {
            "ADDR DEL"
        };

        if let Some(addr) = address {
            let ifname = rip_lib::ifname::index_to_name(addr_msg.ifa_index)
                .unwrap_or_else(|_| format!("if{}", addr_msg.ifa_index));
            writeln!(
                out,
                "{}: {}/{} dev {}",
                action, addr, addr_msg.ifa_prefixlen, ifname
            )?;
        }
        Ok(())
    }

    fn print_route_event(&self, out: &mut impl Write, msg_type: u16, payload: &[u8]) -> Result<()> {
        let rt = RtMsg::from_bytes(payload)?;
        let attrs_data = &payload[RtMsg::SIZE..];

        let mut dst: Option<IpAddr> = None;
        let mut gateway: Option<IpAddr> = None;
        let mut oif: Option<u32> = None;

        for (attr_type, attr_data) in AttrIter::new(attrs_data) {
            match RtaAttr::from(attr_type) {
                RtaAttr::Dst => {
                    dst = parse_ip_addr(rt.rtm_family, attr_data);
                }
                RtaAttr::Gateway => {
                    gateway = parse_ip_addr(rt.rtm_family, attr_data);
                }
                RtaAttr::Oif => {
                    oif = get::u32_ne(attr_data).ok();
                }
                _ => {}
            }
        }

        let action = if msg_type == NlMsgType::RTM_NEWROUTE {
            "ROUTE"
        } else {
            "ROUTE DEL"
        };

        let dst_str = dst
            .map(|d| format!("{}/{}", d, rt.rtm_dst_len))
            .unwrap_or_else(|| "default".to_string());

        write!(out, "{}: {}", action, dst_str)?;

        if let Some(gw) = gateway {
            write!(out, " via {}", gw)?;
        }

        if let Some(idx) = oif {
            if let Ok(name) = rip_lib::ifname::index_to_name(idx) {
                write!(out, " dev {}", name)?;
            }
        }

        writeln!(out)?;
        Ok(())
    }

    fn print_neigh_event(&self, out: &mut impl Write, msg_type: u16, payload: &[u8]) -> Result<()> {
        let neigh = NdMsg::from_bytes(payload)?;
        let attrs_data = &payload[NdMsg::SIZE..];

        let mut dst: Option<IpAddr> = None;
        let mut lladdr: Option<String> = None;

        for (attr_type, attr_data) in AttrIter::new(attrs_data) {
            match NdaAttr::from(attr_type) {
                NdaAttr::Dst => {
                    dst = parse_ip_addr(neigh.ndm_family, attr_data);
                }
                NdaAttr::Lladdr => {
                    lladdr = Some(rip_lib::addr::format_mac(attr_data));
                }
                _ => {}
            }
        }

        let action = if msg_type == NlMsgType::RTM_NEWNEIGH {
            "NEIGH"
        } else {
            "NEIGH DEL"
        };

        if let Some(ip) = dst {
            let ifname = rip_lib::ifname::index_to_name(neigh.ndm_ifindex as u32)
                .unwrap_or_else(|_| format!("if{}", neigh.ndm_ifindex));

            write!(out, "{}: {} dev {}", action, ip, ifname)?;

            if let Some(ll) = lladdr {
                write!(out, " lladdr {}", ll)?;
            }

            write!(out, " {}", nud_state_name(neigh.ndm_state))?;
            writeln!(out)?;
        }
        Ok(())
    }

    fn print_event_json(&self, out: &mut impl Write, msg_type: u16, payload: &[u8]) -> Result<()> {
        let event = match msg_type {
            NlMsgType::RTM_NEWLINK | NlMsgType::RTM_DELLINK => {
                self.link_event_json(msg_type, payload)?
            }
            NlMsgType::RTM_NEWADDR | NlMsgType::RTM_DELADDR => {
                self.addr_event_json(msg_type, payload)?
            }
            NlMsgType::RTM_NEWROUTE | NlMsgType::RTM_DELROUTE => {
                self.route_event_json(msg_type, payload)?
            }
            NlMsgType::RTM_NEWNEIGH | NlMsgType::RTM_DELNEIGH => {
                self.neigh_event_json(msg_type, payload)?
            }
            _ => Some(serde_json::json!({
                "event": "unknown",
                "type": msg_type,
            })),
        };

        if let Some(e) = event {
            writeln!(out, "{}", serde_json::to_string(&e)?)?;
            out.flush()?;
        }
        Ok(())
    }

    fn link_event_json(&self, msg_type: u16, payload: &[u8]) -> Result<Option<serde_json::Value>> {
        let ifinfo = IfInfoMsg::from_bytes(payload)?;
        let attrs_data = &payload[IfInfoMsg::SIZE..];

        let mut name = String::new();
        for (attr_type, attr_data) in AttrIter::new(attrs_data) {
            if IflaAttr::from(attr_type) == IflaAttr::Ifname {
                name = get::string(attr_data).unwrap_or("").to_string();
                break;
            }
        }

        let action = if msg_type == NlMsgType::RTM_NEWLINK {
            "new"
        } else {
            "del"
        };

        Ok(Some(serde_json::json!({
            "event": "link",
            "action": action,
            "ifname": name,
            "ifindex": ifinfo.ifi_index,
            "flags": ifinfo.ifi_flags,
            "up": ifinfo.ifi_flags & iff::UP != 0,
        })))
    }

    fn addr_event_json(&self, msg_type: u16, payload: &[u8]) -> Result<Option<serde_json::Value>> {
        let addr_msg = IfAddrMsg::from_bytes(payload)?;
        let attrs_data = &payload[IfAddrMsg::SIZE..];

        let mut address: Option<IpAddr> = None;
        for (attr_type, attr_data) in AttrIter::new(attrs_data) {
            match IfaAttr::from(attr_type) {
                IfaAttr::Address | IfaAttr::Local => {
                    address = parse_ip_addr(addr_msg.ifa_family, attr_data);
                    if address.is_some() {
                        break;
                    }
                }
                _ => {}
            }
        }

        let action = if msg_type == NlMsgType::RTM_NEWADDR {
            "new"
        } else {
            "del"
        };

        if let Some(addr) = address {
            Ok(Some(serde_json::json!({
                "event": "address",
                "action": action,
                "address": addr.to_string(),
                "prefixlen": addr_msg.ifa_prefixlen,
                "ifindex": addr_msg.ifa_index,
                "family": addr_msg.ifa_family,
                "scope": addr_msg.ifa_scope,
            })))
        } else {
            Ok(None)
        }
    }

    fn route_event_json(&self, msg_type: u16, payload: &[u8]) -> Result<Option<serde_json::Value>> {
        let rt = RtMsg::from_bytes(payload)?;
        let attrs_data = &payload[RtMsg::SIZE..];

        let mut dst: Option<IpAddr> = None;
        let mut gateway: Option<IpAddr> = None;
        let mut oif: Option<u32> = None;

        for (attr_type, attr_data) in AttrIter::new(attrs_data) {
            match RtaAttr::from(attr_type) {
                RtaAttr::Dst => {
                    dst = parse_ip_addr(rt.rtm_family, attr_data);
                }
                RtaAttr::Gateway => {
                    gateway = parse_ip_addr(rt.rtm_family, attr_data);
                }
                RtaAttr::Oif => {
                    oif = get::u32_ne(attr_data).ok();
                }
                _ => {}
            }
        }

        let action = if msg_type == NlMsgType::RTM_NEWROUTE {
            "new"
        } else {
            "del"
        };

        Ok(Some(serde_json::json!({
            "event": "route",
            "action": action,
            "dst": dst.map(|d| d.to_string()),
            "dst_len": rt.rtm_dst_len,
            "gateway": gateway.map(|g| g.to_string()),
            "oif": oif,
            "table": rt.rtm_table,
            "protocol": rt.rtm_protocol,
        })))
    }

    fn neigh_event_json(&self, msg_type: u16, payload: &[u8]) -> Result<Option<serde_json::Value>> {
        let neigh = NdMsg::from_bytes(payload)?;
        let attrs_data = &payload[NdMsg::SIZE..];

        let mut dst: Option<IpAddr> = None;
        let mut lladdr: Option<String> = None;

        for (attr_type, attr_data) in AttrIter::new(attrs_data) {
            match NdaAttr::from(attr_type) {
                NdaAttr::Dst => {
                    dst = parse_ip_addr(neigh.ndm_family, attr_data);
                }
                NdaAttr::Lladdr => {
                    lladdr = Some(rip_lib::addr::format_mac(attr_data));
                }
                _ => {}
            }
        }

        let action = if msg_type == NlMsgType::RTM_NEWNEIGH {
            "new"
        } else {
            "del"
        };

        if let Some(ip) = dst {
            Ok(Some(serde_json::json!({
                "event": "neigh",
                "action": action,
                "dst": ip.to_string(),
                "lladdr": lladdr,
                "ifindex": neigh.ndm_ifindex,
                "state": nud_state_name(neigh.ndm_state),
            })))
        } else {
            Ok(None)
        }
    }
}

/// Parse an IP address from raw bytes based on address family.
fn parse_ip_addr(family: u8, data: &[u8]) -> Option<IpAddr> {
    match family {
        2 => {
            // AF_INET
            if data.len() >= 4 {
                Some(IpAddr::V4(Ipv4Addr::new(
                    data[0], data[1], data[2], data[3],
                )))
            } else {
                None
            }
        }
        10 => {
            // AF_INET6
            if data.len() >= 16 {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&data[..16]);
                Some(IpAddr::V6(Ipv6Addr::from(octets)))
            } else {
                None
            }
        }
        _ => None,
    }
}
