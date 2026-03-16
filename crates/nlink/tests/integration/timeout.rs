//! Integration tests for operation timeouts (Plan 032).

use nlink::netlink::Connection;
use nlink::Route;
use std::time::Duration;

#[tokio::test]
async fn test_no_timeout_default() {
    let conn = Connection::<Route>::new().unwrap();
    assert_eq!(conn.get_timeout(), None);
}

#[tokio::test]
async fn test_timeout_is_chainable() {
    let conn = Connection::<Route>::new()
        .unwrap()
        .timeout(Duration::from_secs(5));
    assert_eq!(conn.get_timeout(), Some(Duration::from_secs(5)));

    let conn = conn.no_timeout();
    assert_eq!(conn.get_timeout(), None);
}

#[tokio::test]
async fn test_timeout_operations_succeed() -> nlink::Result<()> {
    require_root!();

    // 10 seconds is generous — kernel responds in microseconds
    let conn = Connection::<Route>::new()?.timeout(Duration::from_secs(10));

    let links = conn.get_links().await?;
    assert!(!links.is_empty(), "should have at least loopback");

    Ok(())
}

#[tokio::test]
async fn test_very_short_timeout() -> nlink::Result<()> {
    require_root!();

    // 1 nanosecond — should almost certainly time out
    let conn = Connection::<Route>::new()?.timeout(Duration::from_nanos(1));

    let result = conn.get_links().await;
    // May succeed on very fast systems, but if it fails it must be a timeout
    if let Err(e) = result {
        assert!(e.is_timeout(), "expected timeout, got: {e}");
    }

    Ok(())
}

#[tokio::test]
async fn test_no_timeout_works() -> nlink::Result<()> {
    require_root!();

    // Default no-timeout should work fine
    let conn = Connection::<Route>::new()?;
    let links = conn.get_links().await?;
    assert!(!links.is_empty());

    Ok(())
}
