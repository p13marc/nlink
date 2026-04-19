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
        let qdiscs = conn.get_qdiscs_by_name(name).await?;

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
    use nlink::Rate;
    use nlink::netlink::ratelimit::{{RateLimiter, RateLimit}};

    let conn = Connection::<Route>::new()?;

    // Simple egress rate limiting (typed Rate — no unit confusion)
    let limiter = RateLimiter::new("eth0")
        .egress(Rate::mbit(100));  // Limit outgoing to 100 Mbps

    limiter.apply(&conn).await?;

    // Egress and ingress limiting
    let limiter = RateLimiter::new("eth0")
        .egress(Rate::mbit(100))
        .ingress(Rate::mbit(50));  // Also limit incoming

    limiter.apply(&conn).await?;

    // With burst allowance
    let limiter = RateLimiter::new("eth0")
        .egress(Rate::mbit(100))
        .ingress(Rate::mbit(50))
        .burst_to(Rate::mbit(200));  // Allow bursts up to 200 Mbps

    limiter.apply(&conn).await?;
"#
    );

    println!("--- Using RateLimit builder ---");
    println!(
        r#"
    use nlink::{{Bytes, Rate}};
    use nlink::netlink::ratelimit::RateLimit;

    // Construct from any unit; storage is bytes/sec internally.
    let limit = RateLimit::new(Rate::mbit(100));
    assert_eq!(limit.rate.as_bytes_per_sec(), 12_500_000);

    // Or via FromStr (tc-style strings)
    let limit = RateLimit::new("100mbit".parse()?);

    // With ceiling and burst
    let limit = RateLimit::new(Rate::mbit(100))   // 100 Mbps
        .ceil(Rate::mbit(200))                    // Burst up to 200 Mbps
        .burst(Bytes::kib(32));                   // 32 KiB burst bucket
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
    use nlink::Rate;
    use nlink::netlink::namespace;

    // Apply rate limit in a namespace
    let ns_conn = namespace::connection_for("myns")?;
    let limiter = RateLimiter::new("eth0")
        .egress(Rate::mbit(10));
    limiter.apply(&ns_conn).await?;
"#
    );

    println!("=== PerHostLimiter (per-IP limiting) ===\n");

    println!(
        r#"
    use nlink::Rate;
    use nlink::netlink::ratelimit::PerHostLimiter;

    // Limit each IP to 10 Mbps by default
    let limiter = PerHostLimiter::new("eth0", Rate::mbit(10));
    limiter.apply(&conn).await?;

    // With custom rules for specific IPs/subnets
    let limiter = PerHostLimiter::new("eth0", Rate::mbit(10))
        .limit_ip("192.168.1.100".parse()?, Rate::mbit(100))      // VIP client
        .limit_subnet("10.0.0.0/8", Rate::mbit(50))?              // Internal
        .limit_port(80, Rate::mbit(500));                          // HTTP traffic
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
