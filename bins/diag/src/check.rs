//! Check command - check connectivity to a destination.

use clap::Args;
use nlink::netlink::diagnostics::Diagnostics;
use nlink::netlink::{Connection, Result, Route};
use std::net::IpAddr;

#[derive(Args)]
pub struct CheckArgs {
    /// Destination IP address
    pub destination: IpAddr,
}

pub async fn run(args: CheckArgs, json: bool) -> Result<()> {
    let conn = Connection::<Route>::new()?;
    let diag = Diagnostics::new(conn);

    let report = diag.check_connectivity(args.destination).await?;

    if json {
        let output = serde_json::json!({
            "destination": report.destination.to_string(),
            "route": report.route.as_ref().map(|r| {
                serde_json::json!({
                    "destination": r.destination,
                    "prefix_len": r.prefix_len,
                    "gateway": r.gateway.map(|g| g.to_string()),
                    "metric": r.metric,
                })
            }),
            "output_interface": report.output_interface,
            "gateway": report.gateway.map(|g| g.to_string()),
            "gateway_reachable": report.gateway_reachable,
            "issues": report.issues.iter().map(|i| {
                serde_json::json!({
                    "severity": format!("{:?}", i.severity),
                    "category": format!("{:?}", i.category),
                    "message": i.message,
                    "details": i.details,
                })
            }).collect::<Vec<_>>(),
        });
        println!("{}", serde_json::to_string_pretty(&output).unwrap());
    } else {
        println!("Connectivity Check: {}", report.destination);
        println!();

        if let Some(ref route) = report.route {
            println!("Route:");
            println!("  Destination: {}/{}", route.destination, route.prefix_len);
            if let Some(gateway) = route.gateway {
                println!("  Gateway: {}", gateway);
            }
            if let Some(metric) = route.metric {
                println!("  Metric: {}", metric);
            }
        } else {
            println!("Route: none found");
        }

        if let Some(ref iface) = report.output_interface {
            println!("  Output interface: {}", iface);
        }

        println!();

        if let Some(gateway) = report.gateway {
            let status = if report.gateway_reachable {
                "reachable"
            } else {
                "unreachable/unknown"
            };
            println!("Gateway: {} ({})", gateway, status);
        } else {
            println!("Gateway: direct route (no gateway)");
        }

        println!();

        if report.issues.is_empty() {
            println!("Status: OK - No connectivity issues detected");
        } else {
            println!("Issues:");
            for issue in &report.issues {
                let icon = match issue.severity {
                    nlink::netlink::diagnostics::Severity::Info => "[INFO]",
                    nlink::netlink::diagnostics::Severity::Warning => "[WARN]",
                    nlink::netlink::diagnostics::Severity::Error => "[ERROR]",
                    nlink::netlink::diagnostics::Severity::Critical => "[CRIT]",
                };
                println!("  {} {}", icon, issue.message);
                if let Some(ref details) = issue.details {
                    println!("      {}", details);
                }
            }
        }
    }

    Ok(())
}
