//! Monitor network events using the Stream API.
//!
//! This example demonstrates how to use Connection<Route>::events()
//! to monitor network changes in real-time.
//!
//! Run with: cargo run -p nlink --example events_monitor
//!
//! Then in another terminal, try:
//!   ip link add dummy test0 type dummy
//!   ip addr add 10.0.0.1/24 dev test0
//!   ip link set test0 up
//!   ip link del test0

use nlink::netlink::{Connection, NetworkEvent, Route, RouteGroup};
use tokio_stream::StreamExt;

#[tokio::main]
async fn main() -> nlink::netlink::Result<()> {
    println!("Monitoring network events (Ctrl+C to stop)...\n");

    let mut conn = Connection::<Route>::new()?;
    conn.subscribe(&[
        RouteGroup::Link,
        RouteGroup::Ipv4Addr,
        RouteGroup::Ipv6Addr,
        RouteGroup::Ipv4Route,
        RouteGroup::Ipv6Route,
        RouteGroup::Neigh,
    ])?;

    let mut events = conn.events();

    while let Some(result) = events.next().await {
        let event = result?;
        match event {
            // Link events
            NetworkEvent::NewLink(link) => {
                println!(
                    "[LINK+] {} (index={}, mtu={:?}, up={})",
                    link.name_or("?"),
                    link.ifindex(),
                    link.mtu,
                    link.is_up()
                );
            }
            NetworkEvent::DelLink(link) => {
                println!("[LINK-] {} (index={})", link.name_or("?"), link.ifindex());
            }

            // Address events
            NetworkEvent::NewAddress(addr) => {
                let ip = addr
                    .address
                    .as_ref()
                    .or(addr.local.as_ref())
                    .map(|a| a.to_string())
                    .unwrap_or_else(|| "?".into());
                println!(
                    "[ADDR+] {}/{} on ifindex={}",
                    ip,
                    addr.prefix_len(),
                    addr.ifindex()
                );
            }
            NetworkEvent::DelAddress(addr) => {
                let ip = addr
                    .address
                    .as_ref()
                    .or(addr.local.as_ref())
                    .map(|a| a.to_string())
                    .unwrap_or_else(|| "?".into());
                println!(
                    "[ADDR-] {}/{} on ifindex={}",
                    ip,
                    addr.prefix_len(),
                    addr.ifindex()
                );
            }

            // Route events
            NetworkEvent::NewRoute(route) => {
                let dst = route
                    .destination
                    .as_ref()
                    .map(|a| format!("{}/{}", a, route.dst_len()))
                    .unwrap_or_else(|| "default".into());
                let via = route
                    .gateway
                    .as_ref()
                    .map(|a| format!(" via {}", a))
                    .unwrap_or_default();
                println!("[ROUTE+] {}{}", dst, via);
            }
            NetworkEvent::DelRoute(route) => {
                let dst = route
                    .destination
                    .as_ref()
                    .map(|a| format!("{}/{}", a, route.dst_len()))
                    .unwrap_or_else(|| "default".into());
                println!("[ROUTE-] {}", dst);
            }

            // Neighbor events
            NetworkEvent::NewNeighbor(neigh) => {
                let ip = neigh
                    .destination
                    .as_ref()
                    .map(|a| a.to_string())
                    .unwrap_or_else(|| "?".into());
                let mac = neigh
                    .lladdr
                    .as_ref()
                    .map(|m| {
                        format!(
                            " lladdr {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                            m[0], m[1], m[2], m[3], m[4], m[5]
                        )
                    })
                    .unwrap_or_default();
                println!("[NEIGH+] {}{} on ifindex={}", ip, mac, neigh.ifindex());
            }
            NetworkEvent::DelNeighbor(neigh) => {
                let ip = neigh
                    .destination
                    .as_ref()
                    .map(|a| a.to_string())
                    .unwrap_or_else(|| "?".into());
                println!("[NEIGH-] {} on ifindex={}", ip, neigh.ifindex());
            }

            // TC events
            NetworkEvent::NewQdisc(tc) => {
                println!(
                    "[QDISC+] {} on ifindex={}",
                    tc.kind().unwrap_or("?"),
                    tc.ifindex()
                );
            }
            NetworkEvent::DelQdisc(tc) => {
                println!(
                    "[QDISC-] {} on ifindex={}",
                    tc.kind().unwrap_or("?"),
                    tc.ifindex()
                );
            }
            NetworkEvent::NewClass(tc) => {
                println!(
                    "[CLASS+] {} on ifindex={}",
                    tc.kind().unwrap_or("?"),
                    tc.ifindex()
                );
            }
            NetworkEvent::DelClass(tc) => {
                println!(
                    "[CLASS-] {} on ifindex={}",
                    tc.kind().unwrap_or("?"),
                    tc.ifindex()
                );
            }

            // Filter and action events
            NetworkEvent::NewFilter(tc) => {
                println!(
                    "[FILTER+] {} on ifindex={}",
                    tc.kind().unwrap_or("?"),
                    tc.ifindex()
                );
            }
            NetworkEvent::DelFilter(tc) => {
                println!(
                    "[FILTER-] {} on ifindex={}",
                    tc.kind().unwrap_or("?"),
                    tc.ifindex()
                );
            }
            NetworkEvent::NewAction(tc) => {
                println!(
                    "[ACTION+] {} on ifindex={}",
                    tc.kind().unwrap_or("?"),
                    tc.ifindex()
                );
            }
            NetworkEvent::DelAction(tc) => {
                println!(
                    "[ACTION-] {} on ifindex={}",
                    tc.kind().unwrap_or("?"),
                    tc.ifindex()
                );
            }
        }
    }

    Ok(())
}
