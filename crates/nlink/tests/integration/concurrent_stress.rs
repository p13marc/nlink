//! Plan 194 — concurrent stress + interleaved-request
//! regression coverage. 0.19 F1 fix extended.
//!
//! Three bug-shapes audited by the 0.19 consolidation-pass
//! research agent against the Rust netlink ecosystem
//! (`rtnetlink` issues #131 + #132):
//!
//! 1. **Sequence-number routing failure** — two simultaneously
//!    outstanding requests on the same socket getting each
//!    other's replies (rtnetlink #131). nlink's defense in
//!    0.19: the F1 fix added `request_lock` on `Connection<P>`
//!    so concurrent shared-`Arc<Connection>` callers serialize
//!    cleanly. This test spawns 16 concurrent dumps on a
//!    shared `Arc<Connection>` and verifies each sees the
//!    expected dummy link in its own result set.
//!
//! 2. **Concurrent namespace creation race** — `setns(2)` +
//!    bind-mount sequence non-atomic under parallel
//!    invocation (rtnetlink #132). nlink's defense: every
//!    `LabNamespace::new` is hermetic. This test spawns 16
//!    concurrent namespaces, each with a uniquely-named
//!    dummy, and verifies each namespace's dump returns
//!    only its own dummy.
//!
//! 3. **ACK-style concurrent requests** — the F1 fix is
//!    symmetric across dumps and ack-only requests but the
//!    failure shape is different (ACKs are tiny so the
//!    cross-task consumption window is narrow). This test
//!    spawns 16 concurrent `add_link` calls and asserts all
//!    succeed and the final dump sees all dummies.

use std::sync::Arc;

use nlink::Result;
use nlink::netlink::{
    Route,
    link::DummyLink,
    namespace,
};

use crate::common::TestNamespace;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_dumps_on_shared_connection_route_correctly() -> Result<()> {
    nlink::require_root!();

    let ns = TestNamespace::new("seq-routing")?;
    let conn = Arc::new(namespace::connection_for::<Route>(ns.name())?);

    // Pre-create a known dummy so each dump returns at least
    // one link.
    conn.add_link(DummyLink::new("dummy0")).await?;

    // Spawn 16 concurrent get_links calls. If seq routing is
    // broken, some tasks see other tasks' responses (wrong
    // link names, mismatched ordering, partial dumps).
    let mut handles = Vec::with_capacity(16);
    for _ in 0..16 {
        let c = conn.clone();
        handles.push(tokio::spawn(async move { c.get_links().await }));
    }

    for h in handles {
        let links = h.await.expect("task panicked")?;
        assert!(
            links.iter().any(|l| l.name() == Some("dummy0")),
            "every concurrent dump must see dummy0 (seq routing)"
        );
    }

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_namespaces_dont_corrupt_each_other() -> Result<()> {
    nlink::require_root!();

    let count = 16;
    let mut handles = Vec::with_capacity(count);
    for i in 0..count {
        handles.push(tokio::spawn(async move {
            let ns_name = format!("stress-{i}");
            let ns = TestNamespace::new(&ns_name)?;
            let conn = namespace::connection_for::<Route>(ns.name())?;
            let iface_name = format!("d{i}");
            conn.add_link(DummyLink::new(&iface_name)).await?;
            let links = conn.get_links().await?;
            // Filter to our test-iface naming convention — `d<N>`
            // for an unsigned <N>. Loopback (`lo`) is excluded.
            let ours: Vec<String> = links
                .iter()
                .filter_map(|l| l.name().map(|s| s.to_string()))
                .filter(|n| n.starts_with('d') && n[1..].chars().all(|c| c.is_ascii_digit()))
                .collect();
            assert_eq!(
                ours.len(),
                1,
                "ns {i} must see only its own dummy; saw {ours:?}",
            );
            assert_eq!(ours[0], iface_name);
            // Keep the LabNamespace alive until the join_all
            // resolves so concurrent operations can't see each
            // other's torn-down state.
            Ok::<TestNamespace, nlink::Error>(ns)
        }));
    }

    // Join all 16 — surface the first error (task panic OR
    // assertion OR nlink error).
    for h in handles {
        h.await.expect("task panicked")?;
    }

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_ack_requests_on_shared_connection_succeed() -> Result<()> {
    nlink::require_root!();

    // F1 fix coverage — ack-style request path. Even though
    // ACK responses are tiny (16 bytes header + 4 bytes errno),
    // concurrent senders on a shared connection without the
    // request lock would still race: task A's recv could
    // consume task B's ACK, leaving B blocked until the 30s
    // operation timeout (Plan 171) fires.
    let ns = TestNamespace::new("ack-routing")?;
    let conn = Arc::new(namespace::connection_for::<Route>(ns.name())?);

    // Spawn 16 concurrent add_link calls — each creates a
    // uniquely-named dummy and waits for the kernel's ACK.
    let mut handles = Vec::with_capacity(16);
    for i in 0..16 {
        let c = conn.clone();
        handles.push(tokio::spawn(async move {
            c.add_link(DummyLink::new(format!("ack{i}"))).await
        }));
    }

    for h in handles {
        h.await.expect("task panicked")?;
    }

    // Confirm all 16 dummies are visible — proves every ACK
    // landed without misrouting (a misrouted ACK would leave
    // either the create or the subsequent dump stuck).
    let links = conn.get_links().await?;
    for i in 0..16 {
        let name = format!("ack{i}");
        assert!(
            links.iter().any(|l| l.name() == Some(&name)),
            "expected dummy {name} to exist after concurrent add_link"
        );
    }

    Ok(())
}
