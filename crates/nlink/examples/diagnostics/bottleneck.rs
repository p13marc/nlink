//! Bottleneck Detection Example
//!
//! Demonstrates how to find network bottlenecks by analyzing
//! interface and qdisc statistics.
//!
//! Run: cargo run -p nlink --example diagnostics_bottleneck

use nlink::netlink::diagnostics::Diagnostics;
use nlink::netlink::{Connection, Route};

#[tokio::main]
async fn main() -> nlink::Result<()> {
    println!("=== Network Bottleneck Detection ===\n");

    let conn = Connection::<Route>::new()?;
    let diag = Diagnostics::new(conn);

    match diag.find_bottleneck().await? {
        Some(bottleneck) => {
            println!("Bottleneck detected!");
            println!();
            println!("  Location: {}", bottleneck.location);
            println!("  Type: {}", bottleneck.bottleneck_type);
            println!("  Score: {:.2}%", bottleneck.score * 100.0);
            println!();
            println!("  Recommendation: {}", bottleneck.recommendation);
        }
        None => {
            println!("No bottlenecks detected.");
            println!();
            println!("The system appears to be running without significant");
            println!("packet drops or queue overflows.");
        }
    }

    println!("\n=== How Bottleneck Detection Works ===\n");

    println!("The diagnostics module analyzes:");
    println!("  1. Interface statistics (drops, errors)");
    println!("  2. Qdisc statistics (drops, overlimits, backlog)");
    println!("  3. Rate estimator data (bps, pps)");
    println!();
    println!("Bottleneck types:");
    println!("  - QdiscDrops: TC qdisc is dropping packets");
    println!("  - InterfaceDrops: Interface RX/TX drops");
    println!("  - BufferFull: Queue backlog is high");
    println!("  - RateLimited: Hitting rate limit (overlimits)");
    println!("  - HardwareErrors: Interface errors");
    println!();

    println!("=== Example: Monitor for Bottlenecks ===\n");

    println!(
        r#"
    use nlink::netlink::diagnostics::Diagnostics;
    use std::time::Duration;

    let conn = Connection::<Route>::new()?;
    let diag = Diagnostics::new(conn);

    loop {
        if let Some(bottleneck) = diag.find_bottleneck().await? {
            println!("Bottleneck: {} - {}",
                bottleneck.location,
                bottleneck.recommendation);
        }
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
"#
    );

    println!("=== Custom Thresholds ===\n");

    println!(
        r#"
    use nlink::netlink::diagnostics::DiagnosticsConfig;

    // Configure stricter thresholds
    let config = DiagnosticsConfig {
        packet_loss_threshold: 0.001,    // 0.1% loss triggers warning
        error_rate_threshold: 0.0001,    // 0.01% error rate
        qdisc_drop_threshold: 0.001,     // 0.1% qdisc drops
        backlog_threshold: 50_000,       // 50KB backlog
        qlen_threshold: 500,             // 500 packets queued
        skip_loopback: true,
        skip_down: true,
        min_bytes_for_rate: 1000,
    };

    let diag = Diagnostics::with_config(conn, config);
"#
    );

    Ok(())
}
