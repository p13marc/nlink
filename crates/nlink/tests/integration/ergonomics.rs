//! Plan 148 ergonomics — `wait_link_up` + `get_link_stats`.
//!
//! Mirrors §5.1 of `plans/166-0.17-integration-test-backfill-plan.md`.
//! Each test gates on root + the `dummy` module; on a regular-user
//! invocation `require_root!()` early-returns so the suite is no-op.

use std::time::Duration;

use nlink::netlink::link::DummyLink;

use crate::common::TestNamespace;

#[tokio::test]
async fn wait_link_up_returns_when_link_comes_up() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("dummy");

    let ns = TestNamespace::new("wait-link-up")?;
    let conn = ns.connection()?;
    conn.add_link(DummyLink::new("d0")).await?;

    // Stagger: spawn the wait, then bring up after 100ms. The wait
    // should observe operstate change within its 5s deadline.
    let ns_name = ns.name().to_string();
    let wait_task = tokio::spawn(async move {
        let conn = nlink::netlink::namespace::connection_for::<nlink::Route>(&ns_name)?;
        conn.wait_link_up("d0", Duration::from_secs(5)).await
    });
    tokio::time::sleep(Duration::from_millis(100)).await;
    conn.set_link_up("d0").await?;

    wait_task
        .await
        .expect("wait task must complete")
        .expect("wait_link_up must return Ok when the link comes up");
    Ok(())
}

#[tokio::test]
async fn wait_link_up_times_out_when_link_stays_down() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("dummy");

    let ns = TestNamespace::new("wait-link-timeout")?;
    let conn = ns.connection()?;
    conn.add_link(DummyLink::new("d0")).await?;

    let result = conn
        .wait_link_up("d0", Duration::from_millis(200))
        .await;
    let err = result.expect_err("wait_link_up must time out when link stays down");
    assert!(err.is_timeout(), "expected timeout, got {err:?}");
    Ok(())
}

#[tokio::test]
async fn get_link_stats_returns_zero_on_unused_dummy() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("dummy");

    let ns = TestNamespace::new("link-stats")?;
    let conn = ns.connection()?;
    conn.add_link(DummyLink::new("d0")).await?;

    let stats = conn.get_link_stats("d0").await?;
    assert_eq!(stats.tx_packets(), 0, "fresh dummy has no tx traffic");
    assert_eq!(stats.rx_packets(), 0, "fresh dummy has no rx traffic");
    Ok(())
}

// ============================================================================
// #169 — del_*_if_exists family + WireGuard device bootstrap
// ============================================================================

#[tokio::test]
async fn del_if_exists_family_swallows_absence_and_reports_deletion() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("dummy", "sch_htb");

    let ns = TestNamespace::new("if-exists")?;
    let conn = ns.connection()?;

    // Absent everything → Ok(false), never an error.
    assert!(!conn.del_link_if_exists("ghost0").await?);
    assert!(!conn.del_route_v4_if_exists("10.99.99.0", 24).await?);
    assert!(
        !conn
            .del_address_if_exists("lo", "10.99.99.1".parse().unwrap(), 32)
            .await?
    );
    assert!(
        !conn
            .del_qdisc_if_exists("lo", nlink::TcHandle::ROOT)
            .await?
    );
    assert!(
        !conn
            .del_filter_if_exists("lo", nlink::TcHandle::ROOT, 0x0800, 100)
            .await?
    );

    // Present → deleted, Ok(true); second call → Ok(false).
    conn.add_link(DummyLink::new("d0")).await?;
    assert!(conn.del_link_if_exists("d0").await?);
    assert!(!conn.del_link_if_exists("d0").await?);

    Ok(())
}

#[tokio::test]
async fn wireguard_diff_reports_missing_device_and_ensure_creates_it() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("wireguard");

    use nlink::netlink::genl::wireguard::WireguardConfig;

    let ns = TestNamespace::new("wg-bootstrap")?;
    let conn = ns.connection()?;
    let wg: nlink::Connection<nlink::Wireguard> =
        nlink::netlink::namespace::connection_for_async(ns.name()).await?;

    let cfg = WireguardConfig::new().device("wg-boot0", |d| d.listen_port(51999));

    // Absent device → devices_to_add, not an error (#169).
    let diff = cfg.diff(&wg).await?;
    assert_eq!(diff.devices_to_add, vec!["wg-boot0".to_string()]);
    assert!(!diff.is_empty());
    assert!(diff.change_count() >= 1);

    // apply() refuses with a descriptive error while missing.
    let err = cfg.apply(&wg).await.expect_err("apply must name the missing device");
    assert!(err.to_string().contains("wg-boot0"), "got: {err}");

    // ensure_devices creates it; idempotent second run creates none.
    let created = cfg.ensure_devices(&conn).await?;
    assert_eq!(created, vec!["wg-boot0".to_string()]);
    assert!(cfg.ensure_devices(&conn).await?.is_empty());

    // Now the config applies cleanly end-to-end.
    let report = cfg.apply(&wg).await?;
    assert!(report.total_writes() >= 1, "apply configured the fresh device");
    let dev = wg.get_device_by_name("wg-boot0").await?;
    assert_eq!(dev.listen_port, Some(51999));

    Ok(())
}
