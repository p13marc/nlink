//! Interface command - diagnose a specific interface.

use clap::Args;
use nlink::netlink::diagnostics::{Diagnostics, Severity};
use nlink::netlink::{Connection, Result, Route};
use std::time::Duration;

#[derive(Args)]
pub struct InterfaceArgs {
    /// Interface name
    pub interface: String,

    /// Watch mode (continuous updates)
    #[arg(short, long)]
    pub watch: bool,

    /// Watch interval in seconds
    #[arg(short, long, default_value = "1")]
    pub interval: u64,

    /// Include TC statistics
    #[arg(long)]
    pub tc: bool,
}

pub async fn run(args: InterfaceArgs, json: bool) -> Result<()> {
    let conn = Connection::<Route>::new()?;
    let diag = Diagnostics::new(conn);

    loop {
        let iface = diag.scan_interface(&args.interface).await?;

        if json {
            let output = serde_json::json!({
                "name": iface.name,
                "ifindex": iface.ifindex,
                "state": format!("{:?}", iface.state),
                "flags": iface.flags,
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
                    "sample_duration_ms": iface.rates.sample_duration_ms,
                },
                "tc": iface.tc.as_ref().map(|tc| {
                    serde_json::json!({
                        "qdisc": tc.qdisc,
                        "handle": tc.handle,
                        "drops": tc.drops,
                        "overlimits": tc.overlimits,
                        "backlog": tc.backlog,
                        "qlen": tc.qlen,
                        "rate_bps": tc.rate_bps,
                        "rate_pps": tc.rate_pps,
                        "bytes": tc.bytes,
                        "packets": tc.packets,
                    })
                }),
                "issues": iface.issues.iter().map(|i| {
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
            if args.watch {
                // Clear screen for watch mode
                print!("\x1B[2J\x1B[1;1H");
            }

            println!("Interface: {} (index {})", iface.name, iface.ifindex);
            println!(
                "State: {:?}  MTU: {}  Flags: 0x{:x}",
                iface.state,
                iface.mtu.unwrap_or(0),
                iface.flags
            );
            println!();

            println!("Statistics:");
            println!(
                "  RX: {} packets, {} bytes",
                iface.stats.rx_packets(),
                format_bytes(iface.stats.rx_bytes())
            );
            println!(
                "  TX: {} packets, {} bytes",
                iface.stats.tx_packets(),
                format_bytes(iface.stats.tx_bytes())
            );
            println!(
                "  Errors: {} RX, {} TX",
                iface.stats.rx_errors(),
                iface.stats.tx_errors()
            );
            println!(
                "  Dropped: {} RX, {} TX",
                iface.stats.rx_dropped(),
                iface.stats.tx_dropped()
            );
            println!();

            if iface.rates.sample_duration_ms > 0 {
                println!("Rates ({}ms sample):", iface.rates.sample_duration_ms);
                println!(
                    "  RX: {} ({} pps)",
                    format_rate(iface.rates.rx_bps),
                    iface.rates.rx_pps
                );
                println!(
                    "  TX: {} ({} pps)",
                    format_rate(iface.rates.tx_bps),
                    iface.rates.tx_pps
                );
                println!();
            }

            if args.tc {
                if let Some(ref tc) = iface.tc {
                    println!("Traffic Control ({}):", tc.qdisc);
                    println!("  Handle: {}", tc.handle);
                    println!(
                        "  Processed: {} packets, {} bytes",
                        tc.packets,
                        format_bytes(tc.bytes)
                    );
                    println!("  Drops: {}, Overlimits: {}", tc.drops, tc.overlimits);
                    println!(
                        "  Queue: {} packets, {} bytes backlog",
                        tc.qlen, tc.backlog
                    );
                    println!(
                        "  Rate: {} ({} pps)",
                        format_rate(tc.rate_bps),
                        tc.rate_pps
                    );
                    println!();
                } else {
                    println!("Traffic Control: none");
                    println!();
                }
            }

            if !iface.issues.is_empty() {
                println!("Issues:");
                for issue in &iface.issues {
                    let icon = match issue.severity {
                        Severity::Info => "[INFO]",
                        Severity::Warning => "[WARN]",
                        Severity::Error => "[ERROR]",
                        Severity::Critical => "[CRIT]",
                    };
                    println!("  {} {}", icon, issue.message);
                    if let Some(ref details) = issue.details {
                        println!("      {}", details);
                    }
                }
            } else {
                println!("No issues detected.");
            }
        }

        if !args.watch {
            break;
        }

        tokio::time::sleep(Duration::from_secs(args.interval)).await;
    }

    Ok(())
}

fn format_bytes(bytes: u64) -> String {
    const KIB: u64 = 1024;
    const MIB: u64 = KIB * 1024;
    const GIB: u64 = MIB * 1024;

    if bytes >= GIB {
        format!("{:.2} GiB", bytes as f64 / GIB as f64)
    } else if bytes >= MIB {
        format!("{:.2} MiB", bytes as f64 / MIB as f64)
    } else if bytes >= KIB {
        format!("{:.2} KiB", bytes as f64 / KIB as f64)
    } else {
        format!("{} B", bytes)
    }
}

fn format_rate(bps: u64) -> String {
    const KBPS: u64 = 1000;
    const MBPS: u64 = KBPS * 1000;
    const GBPS: u64 = MBPS * 1000;

    if bps >= GBPS {
        format!("{:.2} Gbps", (bps * 8) as f64 / GBPS as f64)
    } else if bps >= MBPS {
        format!("{:.2} Mbps", (bps * 8) as f64 / MBPS as f64)
    } else if bps >= KBPS {
        format!("{:.2} Kbps", (bps * 8) as f64 / KBPS as f64)
    } else {
        format!("{} bps", bps * 8)
    }
}
