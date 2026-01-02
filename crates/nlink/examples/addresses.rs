//! List and manage IP addresses.
//!
//! This example demonstrates how to query, add, and delete IP addresses
//! using the high-level Connection API.
//!
//! Run with: cargo run -p nlink --example addresses
//!
//! To add/delete addresses (requires root):
//!   cargo run -p nlink --example addresses -- add 10.0.0.1/24 eth0
//!   cargo run -p nlink --example addresses -- del 10.0.0.1/24 eth0

use std::env;
use std::net::IpAddr;

use nlink::netlink::addr::{Ipv4Address, Ipv6Address};
use nlink::netlink::types::addr::Scope;
use nlink::netlink::{Connection, Protocol};

#[tokio::main]
async fn main() -> nlink::netlink::Result<()> {
    let conn = Connection::new(Protocol::Route)?;
    let args: Vec<String> = env::args().collect();

    match args.get(1).map(|s| s.as_str()) {
        Some("add") => {
            let (addr, prefix) =
                parse_addr_prefix(args.get(2).expect("usage: add <ip/prefix> <dev>"))?;
            let dev = args.get(3).expect("usage: add <ip/prefix> <dev>");

            match addr {
                IpAddr::V4(ip) => {
                    let config = Ipv4Address::new(dev, ip, prefix);
                    conn.add_address(config).await?;
                }
                IpAddr::V6(ip) => {
                    let config = Ipv6Address::new(dev, ip, prefix);
                    conn.add_address(config).await?;
                }
            }
            println!("Added {}/{} to {}", addr, prefix, dev);
        }
        Some("del") => {
            let (addr, prefix) =
                parse_addr_prefix(args.get(2).expect("usage: del <ip/prefix> <dev>"))?;
            let dev = args.get(3).expect("usage: del <ip/prefix> <dev>");

            conn.del_address(dev, addr, prefix).await?;
            println!("Deleted {}/{} from {}", addr, prefix, dev);
        }
        _ => {
            // List all addresses
            list_addresses(&conn).await?;
        }
    }

    Ok(())
}

async fn list_addresses(conn: &Connection) -> nlink::netlink::Result<()> {
    let links = conn.get_links().await?;
    let addrs = conn.get_addresses().await?;

    // Build ifindex -> name map (ifindex is i32 for links)
    let names: std::collections::HashMap<i32, String> = links
        .iter()
        .filter_map(|l| l.name.clone().map(|n| (l.ifindex(), n)))
        .collect();

    println!(
        "{:<4} {:<16} {:<8} {:<40}",
        "IDX", "INTERFACE", "FAMILY", "ADDRESS"
    );
    println!("{}", "-".repeat(72));

    for addr in addrs {
        // addr.ifindex() returns u32, names keys are i32
        let ifname = names
            .get(&(addr.ifindex() as i32))
            .map(|s| s.as_str())
            .unwrap_or("?");

        let family = if addr.is_ipv4() { "inet" } else { "inet6" };

        let ip = addr
            .address
            .as_ref()
            .or(addr.local.as_ref())
            .map(|a| format!("{}/{}", a, addr.prefix_len()))
            .unwrap_or_else(|| "?".into());

        let scope = match addr.scope() {
            Scope::Universe => "",
            Scope::Link => " link",
            Scope::Host => " host",
            Scope::Site => " site",
            Scope::Nowhere => " nowhere",
        };

        println!(
            "{:<4} {:<16} {:<8} {}{}",
            addr.ifindex(),
            ifname,
            family,
            ip,
            scope
        );
    }

    Ok(())
}

fn parse_addr_prefix(s: &str) -> nlink::netlink::Result<(IpAddr, u8)> {
    let parts: Vec<&str> = s.split('/').collect();
    if parts.len() != 2 {
        return Err(nlink::netlink::Error::InvalidMessage(
            "expected format: ip/prefix".into(),
        ));
    }

    let addr: IpAddr = parts[0]
        .parse()
        .map_err(|e| nlink::netlink::Error::InvalidMessage(format!("invalid IP: {}", e)))?;

    let prefix: u8 = parts[1]
        .parse()
        .map_err(|e| nlink::netlink::Error::InvalidMessage(format!("invalid prefix: {}", e)))?;

    Ok((addr, prefix))
}
