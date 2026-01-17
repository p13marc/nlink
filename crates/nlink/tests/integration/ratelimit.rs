//! Integration tests for the rate limiting DSL.
//!
//! These tests require root privileges and network namespace support.

use std::time::Duration;

use nlink::netlink::ratelimit::{PerHostLimiter, RateLimit, RateLimiter};

use crate::common::TestNamespace;

// ============================================================================
// Unit tests (no root required)
// ============================================================================

#[test]
fn test_rate_limit_new() {
    let limit = RateLimit::new(1_000_000);
    assert_eq!(limit.rate, 1_000_000);
    assert!(limit.ceil.is_none());
    assert!(limit.burst.is_none());
    assert!(limit.latency.is_none());
}

#[test]
fn test_rate_limit_parse() {
    let limit = RateLimit::parse("100mbit").unwrap();
    assert_eq!(limit.rate, 100_000_000); // 100 Mbps in bits/sec

    let limit = RateLimit::parse("1gbit").unwrap();
    assert_eq!(limit.rate, 1_000_000_000); // 1 Gbps in bits/sec

    let limit = RateLimit::parse("10mbps").unwrap();
    assert_eq!(limit.rate, 10_000_000); // 10 Mbps in bits/sec
}

#[test]
fn test_rate_limit_with_options() {
    let limit = RateLimit::new(1_000_000)
        .ceil(2_000_000)
        .burst(32000)
        .latency(Duration::from_millis(20));

    assert_eq!(limit.rate, 1_000_000);
    assert_eq!(limit.ceil, Some(2_000_000));
    assert_eq!(limit.burst, Some(32000));
    assert_eq!(limit.latency, Some(Duration::from_millis(20)));
}

#[test]
fn test_rate_limiter_builder() {
    // Just verify builder pattern works without errors
    let _limiter = RateLimiter::new("eth0")
        .egress_bps(1_000_000)
        .ingress_bps(2_000_000)
        .burst_to_bps(3_000_000)
        .latency(Duration::from_millis(20));
}

#[test]
fn test_rate_limiter_with_string_rates() {
    // Verify string rate parsing works
    let _limiter = RateLimiter::new("eth0")
        .egress("100mbit")
        .unwrap()
        .ingress("1gbit")
        .unwrap()
        .burst_to("150mbit")
        .unwrap();
}

#[test]
fn test_per_host_limiter_builder() {
    // Verify builder works
    let _limiter = PerHostLimiter::new("eth0", "10mbit").unwrap();
}

#[test]
fn test_per_host_limiter_with_rules() {
    // Verify rule building works
    let _limiter = PerHostLimiter::new("eth0", "10mbit")
        .unwrap()
        .limit_ip("192.168.1.100".parse().unwrap(), "100mbit")
        .unwrap()
        .limit_subnet("10.0.0.0/8", "50mbit")
        .unwrap()
        .limit_port(80, "500mbit")
        .unwrap()
        .latency(Duration::from_millis(5));
}

// ============================================================================
// Integration tests (require root)
// ============================================================================

#[tokio::test]
async fn test_egress_rate_limiting() -> nlink::Result<()> {
    require_root!();

    let ns = TestNamespace::new("rl_egress")?;
    let conn = ns.connection()?;

    // Create a dummy interface
    conn.add_link(nlink::netlink::link::DummyLink::new("test0"))
        .await?;
    conn.set_link_up("test0").await?;

    // Apply egress rate limiting
    RateLimiter::new("test0")
        .egress_bps(1_000_000) // 1 MB/s
        .latency(Duration::from_millis(20))
        .apply(&conn)
        .await?;

    // Verify HTB qdisc was created
    let qdiscs = conn.get_qdiscs_by_name("test0").await?;
    let htb_qdisc = qdiscs.iter().find(|q| q.kind() == Some("htb"));
    assert!(htb_qdisc.is_some(), "HTB qdisc should exist");

    // Verify fq_codel leaf qdisc
    let fq_codel = qdiscs.iter().find(|q| q.kind() == Some("fq_codel"));
    assert!(fq_codel.is_some(), "fq_codel leaf qdisc should exist");

    // Remove rate limiting
    RateLimiter::new("test0").remove(&conn).await?;

    // Verify qdisc was removed
    let qdiscs = conn.get_qdiscs_by_name("test0").await?;
    let htb_qdisc = qdiscs.iter().find(|q| q.kind() == Some("htb"));
    assert!(htb_qdisc.is_none(), "HTB qdisc should be removed");

    Ok(())
}

#[tokio::test]
async fn test_ingress_rate_limiting() -> nlink::Result<()> {
    require_root!();

    let ns = TestNamespace::new("rl_ingress")?;
    let conn = ns.connection()?;

    // Create a dummy interface
    conn.add_link(nlink::netlink::link::DummyLink::new("test0"))
        .await?;
    conn.set_link_up("test0").await?;

    // Apply ingress rate limiting
    RateLimiter::new("test0")
        .ingress_bps(2_000_000) // 2 MB/s
        .latency(Duration::from_millis(10))
        .apply(&conn)
        .await?;

    // Verify IFB device was created
    let ifb_link = conn.get_link_by_name("ifb_test0").await?;
    assert!(ifb_link.is_some(), "IFB device should be created");

    // Verify ingress qdisc on main interface
    let qdiscs = conn.get_qdiscs_by_name("test0").await?;
    let ingress = qdiscs.iter().find(|q| q.is_ingress());
    assert!(
        ingress.is_some(),
        "Ingress qdisc should exist on main interface"
    );

    // Verify HTB on IFB device
    let ifb_qdiscs = conn.get_qdiscs_by_name("ifb_test0").await?;
    let htb = ifb_qdiscs.iter().find(|q| q.kind() == Some("htb"));
    assert!(htb.is_some(), "HTB qdisc should exist on IFB device");

    // Remove rate limiting
    RateLimiter::new("test0").remove(&conn).await?;

    // Verify cleanup
    let ifb_link = conn.get_link_by_name("ifb_test0").await?;
    assert!(ifb_link.is_none(), "IFB device should be removed");

    Ok(())
}

#[tokio::test]
async fn test_bidirectional_rate_limiting() -> nlink::Result<()> {
    require_root!();

    let ns = TestNamespace::new("rl_bidir")?;
    let conn = ns.connection()?;

    // Create a dummy interface
    conn.add_link(nlink::netlink::link::DummyLink::new("test0"))
        .await?;
    conn.set_link_up("test0").await?;

    // Apply both egress and ingress rate limiting
    RateLimiter::new("test0")
        .egress("100mbit")?
        .ingress("1gbit")?
        .burst_to("150mbit")?
        .latency(Duration::from_millis(20))
        .apply(&conn)
        .await?;

    // Verify egress HTB
    let qdiscs = conn.get_qdiscs_by_name("test0").await?;
    let htb = qdiscs.iter().find(|q| q.kind() == Some("htb"));
    assert!(htb.is_some(), "Egress HTB should exist");

    // Verify ingress setup
    let ingress = qdiscs.iter().find(|q| q.is_ingress());
    assert!(ingress.is_some(), "Ingress qdisc should exist");

    // Verify IFB device and its HTB
    let ifb_qdiscs = conn.get_qdiscs_by_name("ifb_test0").await?;
    let ifb_htb = ifb_qdiscs.iter().find(|q| q.kind() == Some("htb"));
    assert!(ifb_htb.is_some(), "HTB on IFB should exist");

    // Cleanup
    RateLimiter::new("test0").remove(&conn).await?;

    Ok(())
}

#[tokio::test]
async fn test_per_host_rate_limiting() -> nlink::Result<()> {
    require_root!();

    let ns = TestNamespace::new("rl_perhost")?;
    let conn = ns.connection()?;

    // Create a dummy interface
    conn.add_link(nlink::netlink::link::DummyLink::new("test0"))
        .await?;
    conn.set_link_up("test0").await?;

    // Apply per-host rate limiting
    PerHostLimiter::new("test0", "10mbit")?
        .limit_ip("192.168.1.100".parse().unwrap(), "100mbit")?
        .limit_subnet("10.0.0.0/8", "50mbit")?
        .latency(Duration::from_millis(5))
        .apply(&conn)
        .await?;

    // Verify HTB qdisc was created
    let qdiscs = conn.get_qdiscs_by_name("test0").await?;
    let htb = qdiscs.iter().find(|q| q.kind() == Some("htb"));
    assert!(htb.is_some(), "HTB qdisc should exist");

    // Verify multiple fq_codel leaf qdiscs (one per class)
    let fq_codel_count = qdiscs
        .iter()
        .filter(|q| q.kind() == Some("fq_codel"))
        .count();
    assert!(
        fq_codel_count >= 3,
        "Should have at least 3 fq_codel qdiscs (2 rules + default)"
    );

    // Verify flower filters were created
    let filters = conn.get_filters_by_name("test0").await?;
    assert!(!filters.is_empty(), "Flower filters should exist");

    // Cleanup
    PerHostLimiter::new("test0", "10mbit")?
        .remove(&conn)
        .await?;

    Ok(())
}

#[tokio::test]
async fn test_rate_limiter_idempotency() -> nlink::Result<()> {
    require_root!();

    let ns = TestNamespace::new("rl_idemp")?;
    let conn = ns.connection()?;

    // Create a dummy interface
    conn.add_link(nlink::netlink::link::DummyLink::new("test0"))
        .await?;
    conn.set_link_up("test0").await?;

    let limiter = RateLimiter::new("test0").egress_bps(1_000_000);

    // Apply multiple times - should not error
    limiter.apply(&conn).await?;
    limiter.apply(&conn).await?;
    limiter.apply(&conn).await?;

    // Verify config is still correct
    let qdiscs = conn.get_qdiscs_by_name("test0").await?;
    let htb_count = qdiscs.iter().filter(|q| q.kind() == Some("htb")).count();
    assert_eq!(htb_count, 1, "Should have exactly one HTB qdisc");

    Ok(())
}

#[tokio::test]
async fn test_rate_limiter_remove_nonexistent() -> nlink::Result<()> {
    require_root!();

    let ns = TestNamespace::new("rl_remove")?;
    let conn = ns.connection()?;

    // Create a dummy interface
    conn.add_link(nlink::netlink::link::DummyLink::new("test0"))
        .await?;
    conn.set_link_up("test0").await?;

    // Remove should not error even if no rate limiting is configured
    RateLimiter::new("test0").remove(&conn).await?;

    Ok(())
}
