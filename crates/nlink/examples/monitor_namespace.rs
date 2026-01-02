//! Monitor events in a specific network namespace.
//!
//! This example demonstrates namespace-aware event monitoring
//! using EventStream with namespace options.
//!
//! Run with: cargo run -p nlink --example monitor_namespace -- myns
//!
//! First create a namespace: sudo ip netns add myns
//! Then make changes: sudo ip netns exec myns ip link add dummy0 type dummy

use std::env;

use nlink::netlink::events::{EventStream, NetworkEvent};

#[tokio::main]
async fn main() -> nlink::netlink::Result<()> {
    let args: Vec<String> = env::args().collect();

    let mut builder = EventStream::builder()
        .links(true)
        .addresses(true)
        .routes(true);

    match args.get(1).map(|s| s.as_str()) {
        Some("--pid") => {
            let pid: u32 = args
                .get(2)
                .expect("usage: --pid <pid>")
                .parse()
                .expect("invalid PID");
            builder = builder.namespace_pid(pid);
            println!("Monitoring events in namespace of PID {}...", pid);
        }
        Some("--path") => {
            let path = args.get(2).expect("usage: --path <path>");
            builder = builder.namespace_path(path);
            println!("Monitoring events in namespace at {}...", path);
        }
        Some(ns_name) => {
            builder = builder.namespace(ns_name);
            println!("Monitoring events in namespace '{}'...", ns_name);
        }
        None => {
            println!("Monitoring events in default namespace...");
            println!();
            println!("Tip: Specify a namespace:");
            println!("  --pid <pid>   - Monitor by process ID");
            println!("  --path <path> - Monitor by namespace path");
            println!("  <name>        - Monitor named namespace");
        }
    }

    println!("{}", "-".repeat(50));

    let mut stream = builder.build()?;

    while let Some(event) = stream.next().await? {
        match event {
            NetworkEvent::NewLink(link) => {
                println!(
                    "[LINK+] {} idx={} mtu={:?}",
                    link.name_or("?"),
                    link.ifindex(),
                    link.mtu
                );
            }
            NetworkEvent::DelLink(link) => {
                println!(
                    "[LINK-] {} idx={}",
                    link.name_or("?"),
                    link.ifindex()
                );
            }
            NetworkEvent::NewAddress(addr) => {
                let ip = addr
                    .address
                    .as_ref()
                    .or(addr.local.as_ref())
                    .map(|a| format!("{}/{}", a, addr.prefix_len()))
                    .unwrap_or_else(|| "?".into());
                println!("[ADDR+] {} on idx={}", ip, addr.ifindex());
            }
            NetworkEvent::DelAddress(addr) => {
                let ip = addr
                    .address
                    .as_ref()
                    .or(addr.local.as_ref())
                    .map(|a| a.to_string())
                    .unwrap_or_else(|| "?".into());
                println!("[ADDR-] {} on idx={}", ip, addr.ifindex());
            }
            NetworkEvent::NewRoute(route) => {
                let dst = route
                    .destination
                    .as_ref()
                    .map(|a| format!("{}/{}", a, route.dst_len()))
                    .unwrap_or_else(|| "default".into());
                println!("[ROUTE+] {}", dst);
            }
            NetworkEvent::DelRoute(route) => {
                let dst = route
                    .destination
                    .as_ref()
                    .map(|a| format!("{}/{}", a, route.dst_len()))
                    .unwrap_or_else(|| "default".into());
                println!("[ROUTE-] {}", dst);
            }
            _ => {}
        }
    }

    Ok(())
}
