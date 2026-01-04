//! Network Diagnostics Example
//!
//! Demonstrates how to scan network interfaces for issues,
//! check connectivity, and find bottlenecks.
//!
//! Run: cargo run -p nlink --example diagnostics_scan

use nlink::netlink::diagnostics::{Diagnostics, DiagnosticsConfig, Severity};
use nlink::netlink::{Connection, Route};

#[tokio::main]
async fn main() -> nlink::Result<()> {
    let conn = Connection::<Route>::new()?;
    let diag = Diagnostics::new(conn);

    println!("=== Network Diagnostics Scan ===\n");

    // Run a full diagnostic scan
    let report = diag.scan().await?;

    println!("Scan completed at {:?}\n", report.timestamp);

    // Interface diagnostics
    println!("--- Interfaces ({}) ---\n", report.interfaces.len());

    for iface in &report.interfaces {
        print!("{}: ", iface.name);

        // Show state
        if iface.up {
            print!("UP ");
        } else {
            print!("DOWN ");
        }
        if iface.carrier {
            print!("CARRIER ");
        }
        if let Some(mtu) = iface.mtu {
            print!("mtu {} ", mtu);
        }
        println!();

        // Show statistics
        if let Some(stats) = &iface.stats {
            println!(
                "  RX: {} packets, {} bytes",
                stats.rx_packets, stats.rx_bytes
            );
            println!(
                "  TX: {} packets, {} bytes",
                stats.tx_packets, stats.tx_bytes
            );
            if stats.rx_errors > 0 || stats.tx_errors > 0 {
                println!("  Errors: RX {} TX {}", stats.rx_errors, stats.tx_errors);
            }
            if stats.rx_dropped > 0 || stats.tx_dropped > 0 {
                println!("  Dropped: RX {} TX {}", stats.rx_dropped, stats.tx_dropped);
            }
        }

        // Show rates if available
        if let Some(rates) = &iface.rates {
            if rates.total_bps() > 0 {
                println!(
                    "  Rate: {:.2} Mbps ({:.0} pps)",
                    rates.total_bps() as f64 / 1_000_000.0,
                    rates.total_pps()
                );
            }
        }

        // Show TC info
        if let Some(tc) = &iface.tc {
            print!("  TC: {} qdisc", tc.qdisc);
            if tc.drops > 0 {
                print!(", {} drops", tc.drops);
            }
            if tc.overlimits > 0 {
                print!(", {} overlimits", tc.overlimits);
            }
            println!();
        }

        // Show issues
        if !iface.issues.is_empty() {
            for issue in &iface.issues {
                let severity_str = match issue.severity {
                    Severity::Critical => "CRITICAL",
                    Severity::Error => "ERROR",
                    Severity::Warning => "WARN",
                    Severity::Info => "INFO",
                };
                println!("  [{}] {}: {}", severity_str, issue.category, issue.message);
            }
        }

        println!();
    }

    // Route diagnostics
    println!("--- Routes ---\n");
    println!("  IPv4 routes: {}", report.routes.ipv4_route_count);
    println!("  IPv6 routes: {}", report.routes.ipv6_route_count);
    println!(
        "  Default IPv4: {}",
        if report.routes.has_default_v4 {
            "yes"
        } else {
            "no"
        }
    );
    println!(
        "  Default IPv6: {}",
        if report.routes.has_default_v6 {
            "yes"
        } else {
            "no"
        }
    );
    if !report.routes.gateways.is_empty() {
        println!("  Gateways: {:?}", report.routes.gateways);
    }
    println!();

    // Global issues
    if !report.issues.is_empty() {
        println!("--- Issues Found ({}) ---\n", report.issues.len());
        for issue in &report.issues {
            let severity_str = match issue.severity {
                Severity::Critical => "CRITICAL",
                Severity::Error => "ERROR",
                Severity::Warning => "WARN",
                Severity::Info => "INFO",
            };
            print!("[{}] {}", severity_str, issue.message);
            if let Some(iface) = &issue.interface {
                print!(" ({})", iface);
            }
            println!();
            if let Some(details) = &issue.details {
                println!("      {}", details);
            }
        }
    } else {
        println!("No issues detected.");
    }

    Ok(())
}
