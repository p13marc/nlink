//! List routes.
//!
//! This example demonstrates how to query routes
//! using the high-level Connection API.
//!
//! Run with: cargo run -p nlink --example routes
//!
//! Filter by address family:
//!   cargo run -p nlink --example routes -- v4
//!   cargo run -p nlink --example routes -- v6

use std::env;

use nlink::netlink::{Connection, Protocol};

#[tokio::main]
async fn main() -> nlink::netlink::Result<()> {
    let conn = Connection::new(Protocol::Route)?;
    let args: Vec<String> = env::args().collect();

    match args.get(1).map(|s| s.as_str()) {
        Some("v4") => {
            list_routes(&conn, Some(true)).await?;
        }
        Some("v6") => {
            list_routes(&conn, Some(false)).await?;
        }
        _ => {
            list_routes(&conn, None).await?;
        }
    }

    Ok(())
}

async fn list_routes(conn: &Connection, ipv4_only: Option<bool>) -> nlink::netlink::Result<()> {
    let links = conn.get_links().await?;
    let routes = conn.get_routes().await?;

    // Build ifindex -> name map (link ifindex is i32)
    let names: std::collections::HashMap<i32, String> = links
        .iter()
        .filter_map(|l| l.name.clone().map(|n| (l.ifindex(), n)))
        .collect();

    println!(
        "{:<6} {:<24} {:<20} {:<16} {:>8}",
        "TABLE", "DESTINATION", "GATEWAY", "DEV", "METRIC"
    );
    println!("{}", "-".repeat(80));

    for route in routes {
        // Filter by address family if requested
        if let Some(v4) = ipv4_only
            && v4 != route.is_ipv4()
        {
            continue;
        }

        let table = match route.table {
            Some(254) => "main".to_string(),
            Some(255) => "local".to_string(),
            Some(253) => "default".to_string(),
            Some(0) | None => "unspec".to_string(),
            Some(t) => t.to_string(),
        };

        let dst = route
            .destination
            .as_ref()
            .map(|a| format!("{}/{}", a, route.dst_len()))
            .unwrap_or_else(|| "default".into());

        let gw = route
            .gateway
            .as_ref()
            .map(|a| a.to_string())
            .unwrap_or_else(|| "-".into());

        let dev = route
            .oif
            .and_then(|idx| names.get(&(idx as i32)))
            .map(|s| s.as_str())
            .unwrap_or("-");

        let metric = route
            .priority
            .map(|m| m.to_string())
            .unwrap_or_else(|| "-".into());

        println!(
            "{:<6} {:<24} {:<20} {:<16} {:>8}",
            table, dst, gw, dev, metric
        );
    }

    Ok(())
}
