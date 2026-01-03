//! ip monitor - watch for netlink events.
//!
//! This module uses the Connection events() API from nlink for high-level
//! event monitoring with Stream trait support.

use clap::{Args, ValueEnum};
use nlink::netlink::types::link::iff;
use nlink::netlink::types::neigh::nud_state_name;
use nlink::netlink::{Connection, NetworkEvent, Result, Route, RouteGroup};
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

impl EventType {
    /// Convert to RouteGroup slices for subscription.
    fn to_groups(types: &[EventType]) -> Vec<RouteGroup> {
        let mut groups = Vec::new();
        for t in types {
            match t {
                EventType::Link => groups.push(RouteGroup::Link),
                EventType::Address => {
                    groups.push(RouteGroup::Ipv4Addr);
                    groups.push(RouteGroup::Ipv6Addr);
                }
                EventType::Route => {
                    groups.push(RouteGroup::Ipv4Route);
                    groups.push(RouteGroup::Ipv6Route);
                }
                EventType::Neigh => groups.push(RouteGroup::Neigh),
                EventType::All => {
                    groups.push(RouteGroup::Link);
                    groups.push(RouteGroup::Ipv4Addr);
                    groups.push(RouteGroup::Ipv6Addr);
                    groups.push(RouteGroup::Ipv4Route);
                    groups.push(RouteGroup::Ipv6Route);
                    groups.push(RouteGroup::Neigh);
                }
            }
        }
        groups
    }
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

        // Convert CLI event types to RouteGroups
        let groups = EventType::to_groups(&self.objects);

        // Create connection and subscribe
        let mut conn = Connection::<Route>::new()?;
        conn.subscribe(&groups)?;

        let mut stdout = std::io::stdout().lock();
        print_monitor_start(
            &mut stdout,
            &config,
            "Monitoring netlink events (Ctrl+C to stop)...",
        )?;

        let mut events = conn.events();

        while let Some(result) = events.next().await {
            let event = result?;
            if let Some(ip_event) = convert_event(event) {
                print_event(&mut stdout, &ip_event, &config)?;
            }
        }

        Ok(())
    }
}

/// Convert a NetworkEvent to an IpEvent for output formatting.
fn convert_event(event: NetworkEvent) -> Option<IpEvent> {
    let action = event.action();

    if let Some(link) = event.as_link() {
        return Some(IpEvent::Link(LinkEvent {
            action,
            ifindex: link.ifindex(),
            name: link.name.clone().unwrap_or_default(),
            flags: link.flags(),
            up: link.flags() & iff::UP != 0,
            mtu: link.mtu,
            operstate: link.operstate.map(|s| s.name()),
        }));
    }

    if let Some(addr) = event.as_address() {
        return addr.primary_address().map(|address| {
            IpEvent::Address(AddressEvent {
                action,
                address: address.to_string(),
                prefix_len: addr.prefix_len(),
                ifindex: addr.ifindex(),
                family: addr.family(),
                scope: addr.scope().name(),
                label: addr.label.clone(),
            })
        });
    }

    if let Some(route) = event.as_route() {
        return Some(IpEvent::Route(RouteEvent {
            action,
            destination: route.destination.as_ref().map(|d| d.to_string()),
            dst_len: route.dst_len(),
            gateway: route.gateway.as_ref().map(|g| g.to_string()),
            oif: route.oif,
            table: route.table_id(),
            protocol: route.protocol().name(),
            scope: route.scope().name(),
            route_type: route.route_type().name(),
        }));
    }

    if let Some(neigh) = event.as_neighbor() {
        return neigh.destination.as_ref().map(|dst| {
            IpEvent::Neighbor(NeighborEvent {
                action,
                destination: dst.to_string(),
                lladdr: neigh.mac_address(),
                ifindex: neigh.ifindex(),
                state: nud_state_name(neigh.header.ndm_state),
                router: neigh.is_router(),
            })
        });
    }

    // TC events are not handled by ip monitor
    None
}
