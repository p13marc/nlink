//! Connectivity Check Example
//!
//! Demonstrates how to check network connectivity to a destination
//! and diagnose routing issues.
//!
//! Run: cargo run -p nlink --example diagnostics_connectivity

use nlink::netlink::diagnostics::{Diagnostics, Severity};
use nlink::netlink::{Connection, Route};
use std::env;
use std::net::IpAddr;

#[tokio::main]
async fn main() -> nlink::Result<()> {
    // Get destination from command line or use default
    let dest: IpAddr = env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| "8.8.8.8".parse().unwrap());

    println!("=== Connectivity Check: {} ===\n", dest);

    let conn = Connection::<Route>::new()?;
    let diag = Diagnostics::new(conn);

    let report = diag.check_connectivity(dest).await?;

    // Route information
    if let Some(route) = &report.route {
        println!("Route found:");
        if let Some(dev) = &route.dev {
            println!("  Device: {}", dev);
        }
        if let Some(gateway) = &report.gateway {
            println!("  Gateway: {}", gateway);
        }
        if let Some(src) = &route.src {
            println!("  Source: {}", src);
        }
        println!();
    } else {
        println!("No route found to {}\n", dest);
    }

    // Gateway reachability
    if let Some(reachable) = report.gateway_reachable {
        if reachable {
            println!("Gateway is reachable (found in neighbor cache)");
        } else {
            println!("Gateway may be unreachable (not in neighbor cache)");
        }
        println!();
    }

    // Issues
    if !report.issues.is_empty() {
        println!("Issues detected:");
        for issue in &report.issues {
            let icon = match issue.severity {
                Severity::Critical => "!!",
                Severity::Error => "!",
                Severity::Warning => "?",
                Severity::Info => "i",
            };
            println!("  [{}] {}: {}", icon, issue.category, issue.message);
            if let Some(details) = &issue.details {
                println!("      {}", details);
            }
        }
    } else {
        println!("Connectivity looks good!");
    }

    println!("\n=== Usage ===\n");
    println!("Check connectivity to a specific IP:");
    println!("  cargo run -p nlink --example diagnostics_connectivity 1.1.1.1");
    println!("  cargo run -p nlink --example diagnostics_connectivity 2001:4860:4860::8888");

    Ok(())
}
