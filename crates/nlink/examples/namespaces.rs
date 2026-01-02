//! Work with network namespaces.
//!
//! This example demonstrates how to list namespaces and query
//! interfaces within a specific namespace.
//!
//! Run with: cargo run -p nlink --example namespaces
//!
//! Query a specific namespace:
//!   cargo run -p nlink --example namespaces -- myns
//!
//! First create a namespace with: sudo ip netns add myns

use std::env;

use nlink::netlink::Connection;
use nlink::netlink::namespace;

#[tokio::main]
async fn main() -> nlink::netlink::Result<()> {
    let args: Vec<String> = env::args().collect();

    match args.get(1).map(|s| s.as_str()) {
        Some("--pid") => {
            // Query namespace by PID
            let pid: u32 = args
                .get(2)
                .expect("usage: --pid <pid>")
                .parse()
                .expect("invalid PID");

            query_namespace_by_pid(pid).await?;
        }
        Some(ns_name) => {
            // Query a specific namespace
            query_namespace(ns_name).await?;
        }
        None => {
            // List all namespaces
            list_namespaces()?;
        }
    }

    Ok(())
}

fn list_namespaces() -> nlink::netlink::Result<()> {
    println!("Network namespaces:");
    println!("{}", "-".repeat(40));

    match namespace::list() {
        Ok(namespaces) => {
            if namespaces.is_empty() {
                println!("(none found in /var/run/netns/)");
            } else {
                for ns in namespaces {
                    println!("  {}", ns);
                }
            }
        }
        Err(e) if e.is_not_found() => {
            println!("(no namespaces - /var/run/netns/ does not exist)");
        }
        Err(e) => return Err(e),
    }

    Ok(())
}

async fn query_namespace(name: &str) -> nlink::netlink::Result<()> {
    println!("Interfaces in namespace '{}':", name);
    println!("{}", "-".repeat(50));

    let conn = match namespace::connection_for(name) {
        Ok(c) => c,
        Err(e) if e.is_not_found() => {
            eprintln!("Namespace '{}' not found", name);
            eprintln!("Create it with: sudo ip netns add {}", name);
            return Err(e);
        }
        Err(e) => return Err(e),
    };

    print_interfaces(&conn).await
}

async fn query_namespace_by_pid(pid: u32) -> nlink::netlink::Result<()> {
    println!("Interfaces in namespace of PID {}:", pid);
    println!("{}", "-".repeat(50));

    let conn = match namespace::connection_for_pid(pid) {
        Ok(c) => c,
        Err(e) if e.is_not_found() => {
            eprintln!("Process {} not found or no access to its namespace", pid);
            return Err(e);
        }
        Err(e) => return Err(e),
    };

    print_interfaces(&conn).await
}

async fn print_interfaces(conn: &Connection) -> nlink::netlink::Result<()> {
    let links = conn.get_links().await?;
    let addrs = conn.get_addresses().await?;

    println!(
        "{:<4} {:<16} {:<6} {:<40}",
        "IDX", "NAME", "STATE", "ADDRESSES"
    );

    for link in &links {
        let name = link.name_or("?");
        let state = if link.is_up() { "UP" } else { "DOWN" };

        // Collect addresses for this interface
        let link_addrs: Vec<String> = addrs
            .iter()
            .filter(|a| a.ifindex() == link.ifindex())
            .filter_map(|a| {
                a.address
                    .as_ref()
                    .or(a.local.as_ref())
                    .map(|ip| format!("{}/{}", ip, a.prefix_len()))
            })
            .collect();

        let addr_str = if link_addrs.is_empty() {
            "-".to_string()
        } else {
            link_addrs.join(", ")
        };

        println!(
            "{:<4} {:<16} {:<6} {:<40}",
            link.ifindex(),
            name,
            state,
            addr_str
        );
    }

    Ok(())
}
