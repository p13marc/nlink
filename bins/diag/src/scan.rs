//! Scan command - full system diagnostics scan.

use clap::Args;
use nlink::netlink::{
    Connection, Result, Route,
    diagnostics::{Diagnostics, DiagnosticsConfig, Issue, Severity},
};

#[derive(Args)]
pub struct ScanArgs {
    /// Include down interfaces
    #[arg(long)]
    include_down: bool,

    /// Include loopback interfaces
    #[arg(long)]
    include_loopback: bool,

    /// Only show issues of this severity or higher
    #[arg(long, value_parser = parse_severity)]
    min_severity: Option<Severity>,

    /// Find and report the worst bottleneck
    #[arg(long)]
    bottleneck: bool,
}

fn parse_severity(s: &str) -> std::result::Result<Severity, String> {
    match s.to_lowercase().as_str() {
        "info" => Ok(Severity::Info),
        "warning" | "warn" => Ok(Severity::Warning),
        "error" => Ok(Severity::Error),
        "critical" => Ok(Severity::Critical),
        _ => Err(format!("Unknown severity: {}", s)),
    }
}

pub async fn run(args: ScanArgs, json: bool, verbose: bool) -> Result<()> {
    let conn = Connection::<Route>::new()?;

    let config = DiagnosticsConfig {
        skip_loopback: !args.include_loopback,
        skip_down: !args.include_down,
        ..Default::default()
    };

    let diag = Diagnostics::with_config(conn, config);

    if verbose {
        eprintln!("Running diagnostic scan...");
    }

    let report = diag.scan().await?;

    // --min-severity gates *every* surface (per-interface issues, the
    // top-level issue list, text and JSON alike) — not just the text
    // summary. Defaults to Info (show everything).
    let min_severity = args.min_severity.unwrap_or(Severity::Info);
    let keep = |i: &&Issue| i.severity >= min_severity;

    // --bottleneck is honored in both output modes (was text-only).
    let bottleneck = if args.bottleneck {
        diag.find_bottleneck().await?
    } else {
        None
    };

    if json {
        // Build JSON output. Enum-typed fields serialize via their
        // stable Display impls, never Debug — Debug names drift with
        // refactors and would silently break JSON consumers.
        let output = serde_json::json!({
            "interfaces": report.interfaces.iter().map(|iface| {
                serde_json::json!({
                    "name": iface.name,
                    "ifindex": iface.ifindex,
                    "state": oper_state_str(iface.state),
                    "mtu": iface.mtu,
                    "stats": {
                        "rx_bytes": iface.stats.rx_bytes(),
                        "tx_bytes": iface.stats.tx_bytes(),
                        "rx_packets": iface.stats.rx_packets(),
                        "tx_packets": iface.stats.tx_packets(),
                        "rx_errors": iface.stats.rx_errors(),
                        "tx_errors": iface.stats.tx_errors(),
                        "rx_dropped": iface.stats.rx_dropped(),
                        "tx_dropped": iface.stats.tx_dropped(),
                    },
                    "rates": {
                        "rx_bps": iface.rates.rx_bps,
                        "tx_bps": iface.rates.tx_bps,
                        "rx_pps": iface.rates.rx_pps,
                        "tx_pps": iface.rates.tx_pps,
                    },
                    "tc": iface.tc.as_ref().map(|tc| {
                        serde_json::json!({
                            "qdisc": tc.qdisc,
                            "handle": tc.handle,
                            "drops": tc.drops,
                            "backlog": tc.backlog,
                            "qlen": tc.qlen,
                            "rate_bps": tc.rate_bps,
                        })
                    }),
                    "issues": iface.issues.iter().filter(keep).map(issue_to_json).collect::<Vec<_>>(),
                })
            }).collect::<Vec<_>>(),
            "routes": {
                "ipv4_count": report.routes.ipv4_route_count,
                "ipv6_count": report.routes.ipv6_route_count,
                "has_default_ipv4": report.routes.has_default_ipv4,
                "has_default_ipv6": report.routes.has_default_ipv6,
                "default_gateway_v4": report.routes.default_gateway_v4.map(|g| g.to_string()),
                "default_gateway_v6": report.routes.default_gateway_v6.map(|g| g.to_string()),
            },
            "issues": report.issues.iter().filter(keep).map(issue_to_json).collect::<Vec<_>>(),
            "bottleneck": bottleneck.as_ref().map(|b| serde_json::json!({
                "location": b.location,
                "type": b.bottleneck_type.to_string(),
                "drop_rate": b.drop_rate,
                "total_drops": b.total_drops,
                "recommendation": b.recommendation,
            })),
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&output).expect("JSON serialization")
        );
    } else {
        // Text output
        println!("Network Diagnostic Report");
        println!("=========================");
        println!();

        // Routes summary
        println!("Routes:");
        println!(
            "  IPv4: {} routes, default: {}",
            report.routes.ipv4_route_count,
            if report.routes.has_default_ipv4 {
                report
                    .routes
                    .default_gateway_v4
                    .map(|g| g.to_string())
                    .unwrap_or_else(|| "yes".to_string())
            } else {
                "none".to_string()
            }
        );
        println!(
            "  IPv6: {} routes, default: {}",
            report.routes.ipv6_route_count,
            if report.routes.has_default_ipv6 {
                report
                    .routes
                    .default_gateway_v6
                    .map(|g| g.to_string())
                    .unwrap_or_else(|| "yes".to_string())
            } else {
                "none".to_string()
            }
        );
        println!();

        // Interfaces
        println!("Interfaces:");
        for iface in &report.interfaces {
            let state_icon = match iface.state {
                nlink::netlink::types::link::OperState::Up => "UP",
                nlink::netlink::types::link::OperState::Down => "DOWN",
                _ => "?",
            };

            println!(
                "  {} [{}] mtu={} rx={} tx={}",
                iface.name,
                state_icon,
                iface.mtu.unwrap_or(0),
                format_bytes(iface.stats.rx_bytes()),
                format_bytes(iface.stats.tx_bytes()),
            );

            if let Some(ref tc) = iface.tc {
                println!(
                    "    TC: {} drops={} backlog={} qlen={}",
                    tc.qdisc, tc.drops, tc.backlog, tc.qlen
                );
            }

            for issue in iface.issues.iter().filter(keep) {
                println!("    {} {}", severity_icon(issue.severity), issue.message);
            }
        }
        println!();

        // Issues summary
        let filtered_issues: Vec<_> = report.issues.iter().filter(keep).collect();

        if filtered_issues.is_empty() {
            println!("No issues detected.");
        } else {
            println!("Issues ({}):", filtered_issues.len());
            for issue in filtered_issues {
                print_issue(issue);
            }
        }

        // Bottleneck detection
        if args.bottleneck {
            println!();
            if let Some(ref bottleneck) = bottleneck {
                println!("Bottleneck Detected:");
                println!("  Location: {}", bottleneck.location);
                println!("  Type: {}", bottleneck.bottleneck_type);
                println!("  Drop rate: {:.2}%", bottleneck.drop_rate * 100.0);
                println!("  Total drops: {}", bottleneck.total_drops);
                println!("  Recommendation: {}", bottleneck.recommendation);
            } else {
                println!("No significant bottleneck detected.");
            }
        }
    }

    Ok(())
}

fn issue_to_json(issue: &Issue) -> serde_json::Value {
    // Display (not Debug) — stable, refactor-proof enum strings.
    serde_json::json!({
        "severity": issue.severity.to_string(),
        "category": issue.category.to_string(),
        "message": issue.message,
        "details": issue.details,
        "interface": issue.interface,
    })
}

/// Stable string for an interface oper-state in JSON output.
fn oper_state_str(state: nlink::netlink::types::link::OperState) -> &'static str {
    use nlink::netlink::types::link::OperState;
    match state {
        OperState::Up => "up",
        OperState::Down => "down",
        OperState::Dormant => "dormant",
        OperState::NotPresent => "not-present",
        OperState::LowerLayerDown => "lower-layer-down",
        OperState::Testing => "testing",
        OperState::Unknown => "unknown",
        _ => "unknown",
    }
}

fn severity_icon(severity: Severity) -> &'static str {
    match severity {
        Severity::Info => "[INFO]",
        Severity::Warning => "[WARN]",
        Severity::Error => "[ERROR]",
        Severity::Critical => "[CRIT]",
        _ => "[????]",
    }
}

fn print_issue(issue: &Issue) {
    let iface = issue
        .interface
        .as_ref()
        .map(|s| format!("[{}] ", s))
        .unwrap_or_default();
    println!(
        "  {} {}{}",
        severity_icon(issue.severity),
        iface,
        issue.message
    );
    if let Some(ref details) = issue.details {
        println!("      {}", details);
    }
}

fn format_bytes(bytes: u64) -> String {
    const KIB: u64 = 1024;
    const MIB: u64 = KIB * 1024;
    const GIB: u64 = MIB * 1024;

    if bytes >= GIB {
        format!("{:.1}G", bytes as f64 / GIB as f64)
    } else if bytes >= MIB {
        format!("{:.1}M", bytes as f64 / MIB as f64)
    } else if bytes >= KIB {
        format!("{:.1}K", bytes as f64 / KIB as f64)
    } else {
        format!("{}B", bytes)
    }
}

#[cfg(test)]
mod tests {
    use nlink::netlink::types::link::OperState;

    use super::*;

    #[test]
    fn parse_severity_accepts_known_and_aliases() {
        assert_eq!(parse_severity("info").unwrap(), Severity::Info);
        assert_eq!(parse_severity("WARN").unwrap(), Severity::Warning);
        assert_eq!(parse_severity("warning").unwrap(), Severity::Warning);
        assert_eq!(parse_severity("Error").unwrap(), Severity::Error);
        assert_eq!(parse_severity("critical").unwrap(), Severity::Critical);
    }

    #[test]
    fn parse_severity_rejects_unknown() {
        let e = parse_severity("fatal").unwrap_err();
        assert!(e.contains("Unknown severity: fatal"), "{e}");
    }

    #[test]
    fn severity_ordering_gates_min_severity() {
        // The `issue.severity >= min_severity` filter relies on this order.
        assert!(Severity::Critical > Severity::Error);
        assert!(Severity::Error > Severity::Warning);
        assert!(Severity::Warning > Severity::Info);
    }

    #[test]
    fn oper_state_str_maps_states() {
        assert_eq!(oper_state_str(OperState::Up), "up");
        assert_eq!(oper_state_str(OperState::Down), "down");
        assert_eq!(oper_state_str(OperState::LowerLayerDown), "lower-layer-down");
    }

    #[test]
    fn severity_icon_renders() {
        assert_eq!(severity_icon(Severity::Info), "[INFO]");
        assert_eq!(severity_icon(Severity::Critical), "[CRIT]");
    }

    #[test]
    fn format_bytes_scales_units() {
        assert_eq!(format_bytes(512), "512B");
        assert_eq!(format_bytes(1024), "1.0K");
        assert_eq!(format_bytes(1024 * 1024), "1.0M");
        assert_eq!(format_bytes(3 * 1024 * 1024 * 1024), "3.0G");
    }
}
