//! Integration tests for the rate limiting DSL.
//!
//! These tests require root privileges and network namespace support.

use std::time::Duration;

use nlink::{
    Bytes, Rate,
    netlink::ratelimit::{PerHostLimiter, RateLimit, RateLimiter},
};

use crate::common::TestNamespace;

// ============================================================================
// Unit tests (no root required)
// ============================================================================

#[test]
fn test_rate_limit_new() {
    let limit = RateLimit::new(Rate::bytes_per_sec(1_000_000));
    assert_eq!(limit.rate, Rate::bytes_per_sec(1_000_000));
    assert!(limit.ceil.is_none());
    assert!(limit.burst.is_none());
    assert!(limit.latency.is_none());
}

#[test]
fn test_rate_limit_typed_units() {
    // 100 Mbps -> 12.5 MB/s, 1 Gbps -> 125 MB/s.
    let limit = RateLimit::new(Rate::mbit(100));
    assert_eq!(limit.rate.as_bytes_per_sec(), 12_500_000);

    let limit = RateLimit::new(Rate::gbit(1));
    assert_eq!(limit.rate.as_bytes_per_sec(), 125_000_000);

    let limit = RateLimit::new(Rate::mbit(10));
    assert_eq!(limit.rate.as_bytes_per_sec(), 1_250_000);
}

#[test]
fn test_rate_limit_with_options() {
    let limit = RateLimit::new(Rate::bytes_per_sec(1_000_000))
        .ceil(Rate::bytes_per_sec(2_000_000))
        .burst(Bytes::new(32000))
        .latency(Duration::from_millis(20));

    assert_eq!(limit.rate, Rate::bytes_per_sec(1_000_000));
    assert_eq!(limit.ceil, Some(Rate::bytes_per_sec(2_000_000)));
    assert_eq!(limit.burst, Some(Bytes::new(32000)));
    assert_eq!(limit.latency, Some(Duration::from_millis(20)));
}

#[test]
fn test_rate_limiter_builder() {
    // Just verify builder pattern works without errors
    let _limiter = RateLimiter::new("eth0")
        .egress(Rate::bytes_per_sec(1_000_000))
        .ingress(Rate::bytes_per_sec(2_000_000))
        .burst_to(Rate::bytes_per_sec(3_000_000))
        .latency(Duration::from_millis(20));
}

#[test]
fn test_rate_limiter_with_typed_rates() {
    let _limiter = RateLimiter::new("eth0")
        .egress(Rate::mbit(100))
        .ingress(Rate::gbit(1))
        .burst_to(Rate::mbit(150));
}

#[test]
fn test_per_host_limiter_builder() {
    let _limiter = PerHostLimiter::new("eth0", Rate::mbit(10));
}

#[test]
fn test_per_host_limiter_with_rules() {
    let _limiter = PerHostLimiter::new("eth0", Rate::mbit(10))
        .limit_ip("192.168.1.100".parse().unwrap(), Rate::mbit(100))
        .limit_subnet("10.0.0.0/8", Rate::mbit(50))
        .unwrap()
        .limit_port(80, Rate::mbit(500))
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

    conn.add_link(nlink::netlink::link::DummyLink::new("test0"))
        .await?;
    conn.set_link_up("test0").await?;

    RateLimiter::new("test0")
        .egress(Rate::bytes_per_sec(1_000_000))
        .latency(Duration::from_millis(20))
        .apply(&conn)
        .await?;

    let qdiscs = conn.get_qdiscs_by_name("test0").await?;
    let htb_qdisc = qdiscs.iter().find(|q| q.kind() == Some("htb"));
    assert!(htb_qdisc.is_some(), "HTB qdisc should exist");

    let fq_codel = qdiscs.iter().find(|q| q.kind() == Some("fq_codel"));
    assert!(fq_codel.is_some(), "fq_codel leaf qdisc should exist");

    RateLimiter::new("test0").remove(&conn).await?;

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

    conn.add_link(nlink::netlink::link::DummyLink::new("test0"))
        .await?;
    conn.set_link_up("test0").await?;

    RateLimiter::new("test0")
        .ingress(Rate::bytes_per_sec(2_000_000))
        .latency(Duration::from_millis(10))
        .apply(&conn)
        .await?;

    let ifb_link = conn.get_link_by_name("ifb_test0").await?;
    assert!(ifb_link.is_some(), "IFB device should be created");

    let qdiscs = conn.get_qdiscs_by_name("test0").await?;
    let ingress = qdiscs.iter().find(|q| q.is_ingress());
    assert!(
        ingress.is_some(),
        "Ingress qdisc should exist on main interface"
    );

    let ifb_qdiscs = conn.get_qdiscs_by_name("ifb_test0").await?;
    let htb = ifb_qdiscs.iter().find(|q| q.kind() == Some("htb"));
    assert!(htb.is_some(), "HTB qdisc should exist on IFB device");

    RateLimiter::new("test0").remove(&conn).await?;

    let ifb_link = conn.get_link_by_name("ifb_test0").await?;
    assert!(ifb_link.is_none(), "IFB device should be removed");

    Ok(())
}

#[tokio::test]
async fn test_bidirectional_rate_limiting() -> nlink::Result<()> {
    require_root!();

    let ns = TestNamespace::new("rl_bidir")?;
    let conn = ns.connection()?;

    conn.add_link(nlink::netlink::link::DummyLink::new("test0"))
        .await?;
    conn.set_link_up("test0").await?;

    RateLimiter::new("test0")
        .egress(Rate::mbit(100))
        .ingress(Rate::gbit(1))
        .burst_to(Rate::mbit(150))
        .latency(Duration::from_millis(20))
        .apply(&conn)
        .await?;

    let qdiscs = conn.get_qdiscs_by_name("test0").await?;
    let htb = qdiscs.iter().find(|q| q.kind() == Some("htb"));
    assert!(htb.is_some(), "Egress HTB should exist");

    let ingress = qdiscs.iter().find(|q| q.is_ingress());
    assert!(ingress.is_some(), "Ingress qdisc should exist");

    let ifb_qdiscs = conn.get_qdiscs_by_name("ifb_test0").await?;
    let ifb_htb = ifb_qdiscs.iter().find(|q| q.kind() == Some("htb"));
    assert!(ifb_htb.is_some(), "HTB on IFB should exist");

    RateLimiter::new("test0").remove(&conn).await?;

    Ok(())
}

#[tokio::test]
async fn test_per_host_rate_limiting() -> nlink::Result<()> {
    require_root!();

    let ns = TestNamespace::new("rl_perhost")?;
    let conn = ns.connection()?;

    conn.add_link(nlink::netlink::link::DummyLink::new("test0"))
        .await?;
    conn.set_link_up("test0").await?;

    PerHostLimiter::new("test0", Rate::mbit(10))
        .limit_ip("192.168.1.100".parse().unwrap(), Rate::mbit(100))
        .limit_subnet("10.0.0.0/8", Rate::mbit(50))?
        .latency(Duration::from_millis(5))
        .apply(&conn)
        .await?;

    let qdiscs = conn.get_qdiscs_by_name("test0").await?;
    let htb = qdiscs.iter().find(|q| q.kind() == Some("htb"));
    assert!(htb.is_some(), "HTB qdisc should exist");

    let fq_codel_count = qdiscs
        .iter()
        .filter(|q| q.kind() == Some("fq_codel"))
        .count();
    assert!(
        fq_codel_count >= 3,
        "Should have at least 3 fq_codel qdiscs (2 rules + default)"
    );

    let filters = conn.get_filters_by_name("test0").await?;
    assert!(!filters.is_empty(), "Flower filters should exist");

    PerHostLimiter::new("test0", Rate::mbit(10))
        .remove(&conn)
        .await?;

    Ok(())
}

#[tokio::test]
async fn test_rate_limiter_idempotency() -> nlink::Result<()> {
    require_root!();

    let ns = TestNamespace::new("rl_idemp")?;
    let conn = ns.connection()?;

    conn.add_link(nlink::netlink::link::DummyLink::new("test0"))
        .await?;
    conn.set_link_up("test0").await?;

    let limiter = RateLimiter::new("test0").egress(Rate::bytes_per_sec(1_000_000));

    limiter.apply(&conn).await?;
    limiter.apply(&conn).await?;
    limiter.apply(&conn).await?;

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

    conn.add_link(nlink::netlink::link::DummyLink::new("test0"))
        .await?;
    conn.set_link_up("test0").await?;

    RateLimiter::new("test0").remove(&conn).await?;

    Ok(())
}

// ============================================================================
// Reconcile tests
// ============================================================================

#[tokio::test]
async fn test_per_host_reconcile_first_call_creates_tree() -> nlink::Result<()> {
    require_root!();

    let ns = TestNamespace::new("rl_reconcile_first")?;
    let conn = ns.connection()?;

    conn.add_link(nlink::netlink::link::DummyLink::new("test0"))
        .await?;
    conn.set_link_up("test0").await?;

    let report = PerHostLimiter::new("test0", Rate::mbit(10))
        .limit_ip("10.0.0.1".parse().unwrap(), Rate::mbit(100))
        .limit_ip("10.0.0.2".parse().unwrap(), Rate::mbit(50))
        .reconcile(&conn)
        .await?;

    assert!(report.changes_made > 0);
    assert_eq!(report.rules_added, 2);
    assert!(report.root_modified);

    let qdiscs = conn.get_qdiscs_by_name("test0").await?;
    assert!(
        qdiscs
            .iter()
            .any(|q| q.kind() == Some("htb") && q.is_root())
    );
    Ok(())
}

#[tokio::test]
async fn test_per_host_reconcile_idempotent() -> nlink::Result<()> {
    require_root!();

    let ns = TestNamespace::new("rl_reconcile_idem")?;
    let conn = ns.connection()?;

    conn.add_link(nlink::netlink::link::DummyLink::new("test0"))
        .await?;
    conn.set_link_up("test0").await?;

    let limiter = PerHostLimiter::new("test0", Rate::mbit(10))
        .limit_ip("10.0.0.1".parse().unwrap(), Rate::mbit(100));

    let r1 = limiter.reconcile(&conn).await?;
    assert!(r1.changes_made > 0);
    let r2 = limiter.reconcile(&conn).await?;
    assert!(
        r2.is_noop(),
        "second reconcile should be a no-op (got {} changes)",
        r2.changes_made,
    );
    Ok(())
}

#[tokio::test]
async fn test_per_host_reconcile_dry_run() -> nlink::Result<()> {
    require_root!();

    let ns = TestNamespace::new("rl_reconcile_dry")?;
    let conn = ns.connection()?;

    conn.add_link(nlink::netlink::link::DummyLink::new("test0"))
        .await?;
    conn.set_link_up("test0").await?;

    let report = PerHostLimiter::new("test0", Rate::mbit(10))
        .limit_ip("10.0.0.1".parse().unwrap(), Rate::mbit(100))
        .reconcile_dry_run(&conn)
        .await?;

    assert!(report.dry_run);
    assert!(report.changes_made > 0);

    // Nothing actually installed.
    let qdiscs = conn.get_qdiscs_by_name("test0").await?;
    assert!(qdiscs.iter().all(|q| q.kind() != Some("htb")));
    Ok(())
}
