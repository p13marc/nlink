//! ip monitor - watch for netlink events.
//!
//! This module uses the strongly-typed message API from rip-netlink.

use clap::{Args, ValueEnum};
use rip_netlink::message::{MessageIter, NlMsgType};
use rip_netlink::messages::{AddressMessage, LinkMessage, NeighborMessage, RouteMessage};
use rip_netlink::parse::FromNetlink;
use rip_netlink::rtnetlink_groups::*;
use rip_netlink::types::link::iff;
use rip_netlink::types::neigh::nud_state_name;
use rip_netlink::{Connection, Protocol, Result};
use rip_output::{OutputFormat, OutputOptions};
use std::io::{self, Write};

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
                if let Ok(link) = LinkMessage::from_bytes(payload) {
                    let action = if msg_type == NlMsgType::RTM_NEWLINK {
                        "LINK"
                    } else {
                        "LINK DEL"
                    };
                    let name = link.name.as_deref().unwrap_or("?");
                    let state = if link.is_up() { "UP" } else { "DOWN" };
                    writeln!(
                        out,
                        "{}: {} index {} state {}",
                        action,
                        name,
                        link.ifindex(),
                        state
                    )?;
                }
            }
            NlMsgType::RTM_NEWADDR | NlMsgType::RTM_DELADDR => {
                if let Ok(addr) = AddressMessage::from_bytes(payload) {
                    let action = if msg_type == NlMsgType::RTM_NEWADDR {
                        "ADDR"
                    } else {
                        "ADDR DEL"
                    };
                    if let Some(address) = addr.primary_address() {
                        let ifname = rip_lib::ifname::index_to_name(addr.ifindex())
                            .unwrap_or_else(|_| format!("if{}", addr.ifindex()));
                        writeln!(
                            out,
                            "{}: {}/{} dev {}",
                            action,
                            address,
                            addr.prefix_len(),
                            ifname
                        )?;
                    }
                }
            }
            NlMsgType::RTM_NEWROUTE | NlMsgType::RTM_DELROUTE => {
                if let Ok(route) = RouteMessage::from_bytes(payload) {
                    let action = if msg_type == NlMsgType::RTM_NEWROUTE {
                        "ROUTE"
                    } else {
                        "ROUTE DEL"
                    };
                    let dst_str = route
                        .destination
                        .as_ref()
                        .map(|d| format!("{}/{}", d, route.dst_len()))
                        .unwrap_or_else(|| "default".to_string());

                    write!(out, "{}: {}", action, dst_str)?;

                    if let Some(ref gw) = route.gateway {
                        write!(out, " via {}", gw)?;
                    }

                    if let Some(oif) = route.oif {
                        if let Ok(name) = rip_lib::ifname::index_to_name(oif) {
                            write!(out, " dev {}", name)?;
                        }
                    }

                    writeln!(out)?;
                }
            }
            NlMsgType::RTM_NEWNEIGH | NlMsgType::RTM_DELNEIGH => {
                if let Ok(neigh) = NeighborMessage::from_bytes(payload) {
                    let action = if msg_type == NlMsgType::RTM_NEWNEIGH {
                        "NEIGH"
                    } else {
                        "NEIGH DEL"
                    };

                    if let Some(ref dst) = neigh.destination {
                        let ifname = rip_lib::ifname::index_to_name(neigh.ifindex())
                            .unwrap_or_else(|_| format!("if{}", neigh.ifindex()));

                        write!(out, "{}: {} dev {}", action, dst, ifname)?;

                        if let Some(ref mac) = neigh.mac_address() {
                            write!(out, " lladdr {}", mac)?;
                        }

                        write!(out, " {}", nud_state_name(neigh.header.ndm_state))?;
                        writeln!(out)?;
                    }
                }
            }
            _ => {
                writeln!(out, "EVENT: type={}", msg_type)?;
            }
        }
        out.flush()?;
        Ok(())
    }

    fn print_event_json(&self, out: &mut impl Write, msg_type: u16, payload: &[u8]) -> Result<()> {
        let event = match msg_type {
            NlMsgType::RTM_NEWLINK | NlMsgType::RTM_DELLINK => {
                LinkMessage::from_bytes(payload).ok().map(|link| {
                    let action = if msg_type == NlMsgType::RTM_NEWLINK {
                        "new"
                    } else {
                        "del"
                    };
                    serde_json::json!({
                        "event": "link",
                        "action": action,
                        "ifname": link.name.as_deref().unwrap_or(""),
                        "ifindex": link.ifindex(),
                        "flags": link.flags(),
                        "up": link.flags() & iff::UP != 0,
                        "mtu": link.mtu,
                        "operstate": link.operstate.map(|s| s.name()),
                    })
                })
            }
            NlMsgType::RTM_NEWADDR | NlMsgType::RTM_DELADDR => {
                AddressMessage::from_bytes(payload).ok().and_then(|addr| {
                    let action = if msg_type == NlMsgType::RTM_NEWADDR {
                        "new"
                    } else {
                        "del"
                    };
                    addr.primary_address().map(|address| {
                        serde_json::json!({
                            "event": "address",
                            "action": action,
                            "address": address.to_string(),
                            "prefixlen": addr.prefix_len(),
                            "ifindex": addr.ifindex(),
                            "family": addr.family(),
                            "scope": addr.scope().name(),
                            "label": addr.label,
                        })
                    })
                })
            }
            NlMsgType::RTM_NEWROUTE | NlMsgType::RTM_DELROUTE => {
                RouteMessage::from_bytes(payload).ok().map(|route| {
                    let action = if msg_type == NlMsgType::RTM_NEWROUTE {
                        "new"
                    } else {
                        "del"
                    };
                    serde_json::json!({
                        "event": "route",
                        "action": action,
                        "dst": route.destination.as_ref().map(|d| d.to_string()),
                        "dst_len": route.dst_len(),
                        "gateway": route.gateway.as_ref().map(|g| g.to_string()),
                        "oif": route.oif,
                        "table": route.table_id(),
                        "protocol": route.protocol().name(),
                        "scope": route.scope().name(),
                        "type": route.route_type().name(),
                    })
                })
            }
            NlMsgType::RTM_NEWNEIGH | NlMsgType::RTM_DELNEIGH => {
                NeighborMessage::from_bytes(payload).ok().and_then(|neigh| {
                    let action = if msg_type == NlMsgType::RTM_NEWNEIGH {
                        "new"
                    } else {
                        "del"
                    };
                    neigh.destination.as_ref().map(|dst| {
                        serde_json::json!({
                            "event": "neigh",
                            "action": action,
                            "dst": dst.to_string(),
                            "lladdr": neigh.mac_address(),
                            "ifindex": neigh.ifindex(),
                            "state": nud_state_name(neigh.header.ndm_state),
                            "router": neigh.is_router(),
                        })
                    })
                })
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
}
