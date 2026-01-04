//! Scan command - full system diagnostics scan.

use clap::Args;
use nlink::netlink::diagnostics::{Diagnostics, DiagnosticsConfig, Issue, Severity};
use nlink::netlink::{Connection, Result, Route};

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

    if json {
        // Build JSON output
        let output = serde_json::json!({
            "interfaces": report.interfaces.iter().map(|iface| {
                serde_json::json!({
                    "name": iface.name,
                    "ifindex": iface.ifindex,
                    "state": format!("{:?}", iface.state),
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
                    "issues": iface.issues.iter().map(issue_to_json).collect::<Vec<_>>(),
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
            "issues": report.issues.iter().map(issue_to_json).collect::<Vec<_>>(),
        });
        println!("{}", serde_json::to_string_pretty(&output).unwrap());
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

            for issue in &iface.issues {
                println!("    {} {}", severity_icon(issue.severity), issue.message);
            }
        }
        println!();

        // Issues summary
        let min_severity = args.min_severity.unwrap_or(Severity::Info);
        let filtered_issues: Vec<_> = report
            .issues
            .iter()
            .filter(|i| i.severity >= min_severity)
            .collect();

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
            if let Some(bottleneck) = diag.find_bottleneck().await? {
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
    serde_json::json!({
        "severity": format!("{:?}", issue.severity),
        "category": format!("{:?}", issue.category),
        "message": issue.message,
        "details": issue.details,
        "interface": issue.interface,
    })
}

fn severity_icon(severity: Severity) -> &'static str {
    match severity {
        Severity::Info => "[INFO]",
        Severity::Warning => "[WARN]",
        Severity::Error => "[ERROR]",
        Severity::Critical => "[CRIT]",
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
