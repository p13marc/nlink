//! ip monitor - watch for netlink events.
//!
//! This module uses the strongly-typed message API from rip-netlink
//! and the generic monitor infrastructure from rip-output.

use clap::{Args, ValueEnum};
use rip::netlink::message::NlMsgType;
use rip::netlink::messages::{AddressMessage, LinkMessage, NeighborMessage, RouteMessage};
use rip::netlink::parse::FromNetlink;
use rip::netlink::rtnetlink_groups::*;
use rip::netlink::types::link::iff;
use rip::netlink::types::neigh::nud_state_name;
use rip::netlink::{Connection, Protocol, Result};
use rip::output::{
    AddressEvent, IpEvent, LinkEvent, MonitorConfig, NeighborEvent, OutputFormat, OutputOptions,
    RouteEvent, print_monitor_start, run_monitor_loop,
};

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

        // Build monitor config
        let config = MonitorConfig::new()
            .with_timestamp(self.timestamp)
            .with_format(format)
            .with_opts(*opts);

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

        let mut stdout = std::io::stdout().lock();
        print_monitor_start(
            &mut stdout,
            &config,
            "Monitoring netlink events (Ctrl+C to stop)...",
        )?;
        drop(stdout);

        // Run the monitor loop with event handler
        run_monitor_loop(&conn, &config, |msg_type, payload| {
            parse_ip_event(
                msg_type,
                payload,
                monitor_link,
                monitor_addr,
                monitor_route,
                monitor_neigh,
            )
        })
        .await
    }
}

/// Parse a netlink message into an IP event.
fn parse_ip_event(
    msg_type: u16,
    payload: &[u8],
    monitor_link: bool,
    monitor_addr: bool,
    monitor_route: bool,
    monitor_neigh: bool,
) -> Option<IpEvent> {
    match msg_type {
        NlMsgType::RTM_NEWLINK | NlMsgType::RTM_DELLINK if monitor_link => {
            LinkMessage::from_bytes(payload).ok().map(|link| {
                let action = if msg_type == NlMsgType::RTM_NEWLINK {
                    "new"
                } else {
                    "del"
                };
                IpEvent::Link(LinkEvent {
                    action,
                    ifindex: link.ifindex(),
                    name: link.name.clone().unwrap_or_default(),
                    flags: link.flags(),
                    up: link.flags() & iff::UP != 0,
                    mtu: link.mtu,
                    operstate: link.operstate.map(|s| s.name()),
                })
            })
        }
        NlMsgType::RTM_NEWADDR | NlMsgType::RTM_DELADDR if monitor_addr => {
            AddressMessage::from_bytes(payload).ok().and_then(|addr| {
                let action = if msg_type == NlMsgType::RTM_NEWADDR {
                    "new"
                } else {
                    "del"
                };
                addr.primary_address().map(|address| {
                    IpEvent::Address(AddressEvent {
                        action,
                        address: address.to_string(),
                        prefix_len: addr.prefix_len(),
                        ifindex: addr.ifindex() as i32,
                        family: addr.family(),
                        scope: addr.scope().name(),
                        label: addr.label.clone(),
                    })
                })
            })
        }
        NlMsgType::RTM_NEWROUTE | NlMsgType::RTM_DELROUTE if monitor_route => {
            RouteMessage::from_bytes(payload).ok().map(|route| {
                let action = if msg_type == NlMsgType::RTM_NEWROUTE {
                    "new"
                } else {
                    "del"
                };
                IpEvent::Route(RouteEvent {
                    action,
                    destination: route.destination.as_ref().map(|d| d.to_string()),
                    dst_len: route.dst_len(),
                    gateway: route.gateway.as_ref().map(|g| g.to_string()),
                    oif: route.oif,
                    table: route.table_id(),
                    protocol: route.protocol().name(),
                    scope: route.scope().name(),
                    route_type: route.route_type().name(),
                })
            })
        }
        NlMsgType::RTM_NEWNEIGH | NlMsgType::RTM_DELNEIGH if monitor_neigh => {
            NeighborMessage::from_bytes(payload).ok().and_then(|neigh| {
                let action = if msg_type == NlMsgType::RTM_NEWNEIGH {
                    "new"
                } else {
                    "del"
                };
                neigh.destination.as_ref().map(|dst| {
                    IpEvent::Neighbor(NeighborEvent {
                        action,
                        destination: dst.to_string(),
                        lladdr: neigh.mac_address(),
                        ifindex: neigh.ifindex() as i32,
                        state: nud_state_name(neigh.header.ndm_state),
                        router: neigh.is_router(),
                    })
                })
            })
        }
        _ => None,
    }
}
