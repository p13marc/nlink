//! Simple Rate Limiting Example
//!
//! Demonstrates the high-level rate limiting API that abstracts
//! away TC complexity for common bandwidth management use cases.
//!
//! Run: cargo run -p nlink --example ratelimit_simple

use nlink::netlink::{Connection, Route};

#[tokio::main]
async fn main() -> nlink::Result<()> {
    println!("=== Rate Limiting API ===\n");

    // Show current TC configuration
    let conn = Connection::<Route>::new()?;
    let links = conn.get_links().await?;

    println!("Current Traffic Control Configuration:\n");

    for link in links.iter().filter(|l| !l.is_loopback()) {
        let name = link.name_or("?");
        let qdiscs = conn.get_qdiscs_for(name).await?;

        if !qdiscs.is_empty() {
            println!("Interface: {}", name);
            for qdisc in &qdiscs {
                let parent = if qdisc.is_root() {
                    "root".to_string()
                } else if qdisc.is_ingress() {
                    "ingress".to_string()
                } else {
                    qdisc.parent_str()
                };
                println!(
                    "  {} qdisc {}: {} bps, {} pps",
                    parent,
                    qdisc.kind().unwrap_or("?"),
                    qdisc.bps(),
                    qdisc.pps()
                );
            }
            println!();
        }
    }

    // Example rate limiting configurations
    println!("=== Rate Limiting Examples ===\n");

    println!("--- RateLimiter (interface-wide) ---");
    println!(
        r#"
    use nlink::netlink::ratelimit::{{RateLimiter, RateLimit}};

    let conn = Connection::<Route>::new()?;

    // Simple egress rate limiting
    let limiter = RateLimiter::new("eth0")
        .egress("100mbit");  // Limit outgoing to 100 Mbps

    limiter.apply(&conn).await?;

    // Egress and ingress limiting
    let limiter = RateLimiter::new("eth0")
        .egress("100mbit")
        .ingress("50mbit");  // Also limit incoming

    limiter.apply(&conn).await?;

    // With burst allowance
    let limiter = RateLimiter::new("eth0")
        .egress("100mbit")
        .ingress("50mbit")
        .burst_to("200mbit");  // Allow bursts up to 200 Mbps

    limiter.apply(&conn).await?;
"#
    );

    println!("--- Using RateLimit builder ---");
    println!(
        r#"
    use nlink::netlink::ratelimit::RateLimit;

    // Parse rate from string
    let limit = RateLimit::parse("100mbit")?;
    assert_eq!(limit.rate, 100_000_000);  // bits/sec

    // Build with options
    let limit = RateLimit::new(100_000_000)  // 100 Mbps
        .ceil(200_000_000)      // Burst up to 200 Mbps
        .burst(32000);          // 32KB burst bucket

    // Use with RateLimiter
    let limiter = RateLimiter::new("eth0")
        .egress_limit(limit);
"#
    );

    println!("--- Remove rate limits ---");
    println!(
        r#"
    let limiter = RateLimiter::new("eth0");
    limiter.remove(&conn).await?;
"#
    );

    println!("--- Namespace-aware rate limiting ---");
    println!(
        r#"
    use nlink::netlink::namespace;

    // Apply rate limit in a namespace
    let ns_conn = namespace::connection_for("myns")?;
    let limiter = RateLimiter::new("eth0")
        .egress("10mbit");
    limiter.apply(&ns_conn).await?;
"#
    );

    println!("=== PerHostLimiter (per-IP limiting) ===\n");

    println!(
        r#"
    use nlink::netlink::ratelimit::PerHostLimiter;

    // Limit each IP to 10 Mbps by default
    let limiter = PerHostLimiter::new("eth0", "10mbit")?;
    limiter.apply(&conn).await?;

    // With custom rules for specific IPs/subnets
    let limiter = PerHostLimiter::new("eth0", "10mbit")?
        .limit_ip("192.168.1.100".parse()?, "100mbit")?  // VIP client
        .limit_subnet("10.0.0.0/8", "50mbit")?           // Internal
        .limit_port(80, "500mbit")?;                     // HTTP traffic
    limiter.apply(&conn).await?;

    // Remove per-host limits
    limiter.remove(&conn).await?;
"#
    );

    println!("=== How It Works ===\n");
    println!("RateLimiter uses TC under the hood:");
    println!("- Egress: HTB qdisc with rate class");
    println!("- Ingress: IFB device + redirect + HTB");
    println!();
    println!("PerHostLimiter creates:");
    println!("- HTB qdisc with default class");
    println!("- Hash table for per-IP classification");
    println!("- Flower filters for custom rules");
    println!();

    println!("=== Rate String Formats ===\n");
    println!("Supported formats:");
    println!("  100mbit, 100mbps  - 100 megabits/sec");
    println!("  1gbit, 1gbps      - 1 gigabit/sec");
    println!("  10kbit, 10kbps    - 10 kilobits/sec");
    println!("  1024mibit         - 1024 mebibits/sec (binary)");
    println!();

    Ok(())
}
