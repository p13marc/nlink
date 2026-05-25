//! Plan 159 `ConnectionPool<P>` + Plan 162 `invalidate(self)` —
//! end-to-end behaviour of the bounded mpsc-channel-backed pool.
//!
//! Mirrors §5.6 of `plans/166-0.17-integration-test-backfill-plan.md`
//! (5 scenarios) plus a Plan 162 sanity check that the consume-self
//! `invalidate(self)` shape is honoured at runtime (the rustdoc
//! `compile_fail` block in `pooled.rs` already enforces it at
//! compile time).

use std::{sync::Arc, time::Duration};

use nlink::netlink::link::DummyLink;
use nlink::{ConnectionPool, ConnectionPoolBuilder, Route};

use crate::common::TestNamespace;

#[tokio::test]
async fn pool_parallel_fanout_across_threads() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("dummy");

    let ns = TestNamespace::new("pool-fanout")?;
    let conn = ns.connection()?;
    for i in 0..3 {
        conn.add_link(DummyLink::new(format!("d{i}"))).await?;
    }

    let pool: Arc<ConnectionPool<Route>> = Arc::new(
        ConnectionPoolBuilder::<Route>::new()
            .namespace(ns.name())
            .size(4)
            .build()
            .await?,
    );

    // Spawn 8 acquires in parallel against a pool of 4 — second
    // wave must wait then succeed.
    let mut handles = Vec::new();
    for _ in 0..8 {
        let p = Arc::clone(&pool);
        handles.push(tokio::spawn(async move {
            let guard = p.acquire().await?;
            let _ = guard.get_links().await?;
            Ok::<_, nlink::Error>(())
        }));
    }
    for h in handles {
        h.await.expect("task must not panic")?;
    }
    Ok(())
}

#[tokio::test]
async fn pool_acquire_times_out_when_exhausted() -> nlink::Result<()> {
    require_root!();

    let ns = TestNamespace::new("pool-exhausted")?;
    let pool = ConnectionPoolBuilder::<Route>::new()
        .namespace(ns.name())
        .size(1)
        .acquire_timeout(Duration::from_millis(100))
        .build()
        .await?;

    // Hold the one connection, then race a second acquire.
    let _held = pool.acquire().await?;
    match pool.acquire().await {
        Ok(_) => panic!("second acquire must NOT succeed while the pool is held"),
        Err(nlink::Error::PoolExhausted { .. }) => Ok(()),
        Err(other) => panic!("expected PoolExhausted; got {other:?}"),
    }
}

#[tokio::test]
async fn pool_acquire_blocks_then_succeeds_after_release() -> nlink::Result<()> {
    require_root!();

    let ns = TestNamespace::new("pool-block-release")?;
    let pool = Arc::new(
        ConnectionPoolBuilder::<Route>::new()
            .namespace(ns.name())
            .size(1)
            .acquire_timeout(Duration::from_secs(5))
            .build()
            .await?,
    );

    let held = pool.acquire().await?;

    // Spawn a waiter — it should block until we drop `held`. The
    // spawned task takes its own Arc clone and drops the guard
    // inside the task so the guard's borrow lifetime stays local.
    let waiter = {
        let p = Arc::clone(&pool);
        tokio::spawn(async move {
            let g = p.acquire().await?;
            drop(g);
            Ok::<_, nlink::Error>(())
        })
    };
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(!waiter.is_finished(), "waiter must still be blocked");

    drop(held);
    waiter
        .await
        .expect("waiter must not panic")
        .expect("waiter must acquire once we release");
    Ok(())
}

#[tokio::test]
async fn pool_invalidate_drops_connection_and_pool_keeps_working() -> nlink::Result<()> {
    require_root!();

    let ns = TestNamespace::new("pool-invalidate")?;
    let pool = ConnectionPoolBuilder::<Route>::new()
        .namespace(ns.name())
        .size(2)
        .acquire_timeout(Duration::from_secs(2))
        .build()
        .await?;

    // Acquire + invalidate (Plan 162 consume-self).
    let guard = pool.acquire().await?;
    guard.invalidate();

    // The remaining pooled connection is still usable.
    let other = pool.acquire().await?;
    let _ = other.get_links().await?;
    Ok(())
}

#[tokio::test]
async fn pool_for_namespace_isolates_per_netns() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("dummy");

    let ns_a = TestNamespace::new("pool-iso-a")?;
    let ns_b = TestNamespace::new("pool-iso-b")?;

    // Put a unique dummy in each namespace.
    ns_a.connection()?
        .add_link(DummyLink::new("uniq_a"))
        .await?;
    ns_b.connection()?
        .add_link(DummyLink::new("uniq_b"))
        .await?;

    let pool_a = ConnectionPool::<Route>::for_namespace(ns_a.name().to_string(), 2).await?;
    let pool_b = ConnectionPool::<Route>::for_namespace(ns_b.name().to_string(), 2).await?;

    let conn_a = pool_a.acquire().await?;
    let conn_b = pool_b.acquire().await?;

    let names_a: Vec<_> = conn_a
        .get_links()
        .await?
        .iter()
        .filter_map(|l| l.name().map(str::to_owned))
        .collect();
    let names_b: Vec<_> = conn_b
        .get_links()
        .await?
        .iter()
        .filter_map(|l| l.name().map(str::to_owned))
        .collect();

    assert!(
        names_a.iter().any(|n| n == "uniq_a"),
        "pool A must see ns A's link"
    );
    assert!(
        !names_a.iter().any(|n| n == "uniq_b"),
        "pool A must NOT see ns B's link"
    );
    assert!(
        names_b.iter().any(|n| n == "uniq_b"),
        "pool B must see ns B's link"
    );
    assert!(
        !names_b.iter().any(|n| n == "uniq_a"),
        "pool B must NOT see ns A's link"
    );
    Ok(())
}
