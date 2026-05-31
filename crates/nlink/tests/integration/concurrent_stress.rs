//! Plan 194 — concurrent stress + interleaved-request
//! regression coverage.
//!
//! Two bug-shapes audited by the 0.19 consolidation-pass
//! research agent against the Rust netlink ecosystem
//! (`rtnetlink` issues #131 + #132):
//!
//! 1. **Sequence-number routing failure** — two simultaneously
//!    outstanding requests on the same socket getting each
//!    other's replies (rtnetlink #131). nlink's defense:
//!    Plan 170's seq-filter + Plan 172's recv-loop audit
//!    require every recv-loop to `if header.nlmsg_seq != seq
//!    { continue; }` before any other check. This test
//!    spawns 16 concurrent dumps on a shared `Arc<Connection>`
//!    and verifies each sees the expected dummy link in its
//!    own result set.
//!
//! 2. **Concurrent namespace creation race** — `setns(2)` +
//!    bind-mount sequence non-atomic under parallel
//!    invocation (rtnetlink #132). nlink's defense: every
//!    `LabNamespace::new` is hermetic. This test spawns 16
//!    concurrent namespaces, each with a uniquely-named
//!    dummy, and verifies each namespace's dump returns
//!    only its own dummy.
//!
//! Both tests are root-gated and meant to GO GREEN — if
//! either turns red, the bug has propagated to nlink and a
//! follow-up fix is in scope per Plan 194 §3.2 / §3.3.

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
