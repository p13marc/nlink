//! ip monitor - watch for netlink events.
//!
//! This module uses the EventStream API from nlink for high-level
//! event monitoring with Stream trait support.

use clap::{Args, ValueEnum};
use nlink::netlink::Result;
use nlink::netlink::events::{EventStream, NetworkEvent};
use nlink::netlink::types::link::iff;
use nlink::netlink::types::neigh::nud_state_name;
use nlink::output::{
    AddressEvent, IpEvent, LinkEvent, MonitorConfig, NeighborEvent, OutputFormat, OutputOptions,
    RouteEvent, print_event, print_monitor_start,
};
use tokio_stream::StreamExt;

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
        // Build monitor config
        let config = MonitorConfig::new()
            .with_timestamp(self.timestamp)
            .with_format(format)
            .with_opts(*opts);

        // Determine which event types to monitor
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

        // Build EventStream with selected event types
        let mut stream = EventStream::builder()
            .links(monitor_link)
            .addresses(monitor_addr)
            .routes(monitor_route)
            .neighbors(monitor_neigh)
            .build()?;

        let mut stdout = std::io::stdout().lock();
        print_monitor_start(
            &mut stdout,
            &config,
            "Monitoring netlink events (Ctrl+C to stop)...",
        )?;

        // Use try_next() for idiomatic async iteration with ? operator
        while let Some(event) = stream.try_next().await? {
            if let Some(ip_event) = convert_event(event) {
                print_event(&mut stdout, &ip_event, &config)?;
            }
        }

        Ok(())
    }
}

/// Convert a NetworkEvent to an IpEvent for output formatting.
fn convert_event(event: NetworkEvent) -> Option<IpEvent> {
    match event {
        NetworkEvent::NewLink(link) => Some(IpEvent::Link(LinkEvent {
            action: "new",
            ifindex: link.ifindex(),
            name: link.name.clone().unwrap_or_default(),
            flags: link.flags(),
            up: link.flags() & iff::UP != 0,
            mtu: link.mtu,
            operstate: link.operstate.map(|s| s.name()),
        })),
        NetworkEvent::DelLink(link) => Some(IpEvent::Link(LinkEvent {
            action: "del",
            ifindex: link.ifindex(),
            name: link.name.clone().unwrap_or_default(),
            flags: link.flags(),
            up: link.flags() & iff::UP != 0,
            mtu: link.mtu,
            operstate: link.operstate.map(|s| s.name()),
        })),
        NetworkEvent::NewAddress(addr) => addr.primary_address().map(|address| {
            IpEvent::Address(AddressEvent {
                action: "new",
                address: address.to_string(),
                prefix_len: addr.prefix_len(),
                ifindex: addr.ifindex(),
                family: addr.family(),
                scope: addr.scope().name(),
                label: addr.label.clone(),
            })
        }),
        NetworkEvent::DelAddress(addr) => addr.primary_address().map(|address| {
            IpEvent::Address(AddressEvent {
                action: "del",
                address: address.to_string(),
                prefix_len: addr.prefix_len(),
                ifindex: addr.ifindex(),
                family: addr.family(),
                scope: addr.scope().name(),
                label: addr.label.clone(),
            })
        }),
        NetworkEvent::NewRoute(route) => Some(IpEvent::Route(RouteEvent {
            action: "new",
            destination: route.destination.as_ref().map(|d| d.to_string()),
            dst_len: route.dst_len(),
            gateway: route.gateway.as_ref().map(|g| g.to_string()),
            oif: route.oif,
            table: route.table_id(),
            protocol: route.protocol().name(),
            scope: route.scope().name(),
            route_type: route.route_type().name(),
        })),
        NetworkEvent::DelRoute(route) => Some(IpEvent::Route(RouteEvent {
            action: "del",
            destination: route.destination.as_ref().map(|d| d.to_string()),
            dst_len: route.dst_len(),
            gateway: route.gateway.as_ref().map(|g| g.to_string()),
            oif: route.oif,
            table: route.table_id(),
            protocol: route.protocol().name(),
            scope: route.scope().name(),
            route_type: route.route_type().name(),
        })),
        NetworkEvent::NewNeighbor(neigh) => neigh.destination.as_ref().map(|dst| {
            IpEvent::Neighbor(NeighborEvent {
                action: "new",
                destination: dst.to_string(),
                lladdr: neigh.mac_address(),
                ifindex: neigh.ifindex(),
                state: nud_state_name(neigh.header.ndm_state),
                router: neigh.is_router(),
            })
        }),
        NetworkEvent::DelNeighbor(neigh) => neigh.destination.as_ref().map(|dst| {
            IpEvent::Neighbor(NeighborEvent {
                action: "del",
                destination: dst.to_string(),
                lladdr: neigh.mac_address(),
                ifindex: neigh.ifindex(),
                state: nud_state_name(neigh.header.ndm_state),
                router: neigh.is_router(),
            })
        }),
        // TC events are not handled by ip monitor
        _ => None,
    }
}
