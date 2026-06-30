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
