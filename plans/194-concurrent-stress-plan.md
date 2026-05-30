---
to: nlink maintainers
from: 0.19 consolidation-pass research agent (2026-05-30) — adjacent-crate bug audit
subject: concurrent namespace stress + interleaved-request seq-routing regression test
status: queued for 0.19 — medium (defensive — preempt classes other crates hit)
target version: 0.19.0
parent: (none — single-deliverable defensive plan)
source: kernel-research agent findings on rtnetlink #131 (seq routing) + #132 (concurrent ns race)
created: 2026-05-30
---

# Plan 194 — Concurrent stress + seq-routing regression

## 1. Why this plan exists

Two bug-shapes from the `rtnetlink` Rust crate's recent issue
tracker that nlink should explicitly verify it doesn't have:

| Bug-shape | Source | nlink exposure |
|---|---|---|
| Replies to a request on one handle delivered to a *different* request's receiver — sequence-number routing failure | [rtnetlink #131](https://github.com/rust-netlink/rtnetlink/issues/131) (Nov 2025) | Plan 170 + 172 specifically address this; we *should* be safe. Need a regression test pinning the behavior. |
| Race in `child_process_create_ns` under concurrent namespace creation — multiple namespaces created in parallel corrupt each other's mount state | [rtnetlink #132](https://github.com/rust-netlink/rtnetlink/issues/132) | `lab::LabNamespace::new` + `namespace::connection_for_async` are the analogous surfaces. No stress test today. |

This plan ships the regression tests. If they go red, the
fixes are in scope of this plan; if green, the tests are
permanent guards.

## 2. Investigation phase

### 2.1 Interleaved-request seq-routing test

Plan 170 (0.17) fixed the `send_batch` seq-filter bug; Plan
172 audited every recv-loop in the lib. The fix template
("filter by nlmsg_seq before any other check") is in
CLAUDE.md and applied across 9 loops.

The remaining risk is: do two **simultaneously outstanding**
requests on the same socket get their responses correctly
routed? rtnetlink #131's bug was that handle A's request
sometimes got handle B's reply.

The defense in nlink is single-flight discipline:
`send_ack_inner` and `send_dump_inner` are `&self` methods
that complete before returning, and the borrow-checker
prevents two concurrent calls on a single `&Connection`
(no two `&self.socket.send(...)` can race without holding
the same `&Connection` simultaneously). But:

- `Connection` is `Send + Sync` (it's `Arc<NetlinkSocket>`
  internally? — verify), which means two tasks COULD share
  it.
- The `AsyncFd` wraps a single underlying socket; concurrent
  writes ARE serialized at the kernel level, but the
  recv-loop in nlink is racy if two tasks both call
  `recv_msg().await` on the same socket simultaneously.

**Action**:
1. Audit whether nlink's `Connection<P>` is structurally
   single-flight (read-only `&self` methods + an internal
   mutex on the recv-loop, or `&mut self` everywhere).
2. Write an integration test that intentionally violates
   the discipline: spawn two tasks both calling
   `conn.get_links()` on a shared `&Connection`. Either:
   - Both succeed with correctly-routed responses (we're
     safe; ship the test as a regression guard).
   - One returns the other's reply (we have the bug; fix
     before 0.19 cuts).

### 2.2 Concurrent namespace creation stress

`lab::LabNamespace::new` + `namespace::connection_for` go
through `setns(2)` + per-namespace mount points. The
rtnetlink #132 bug was that the syscall sequence is
non-atomic; under concurrent invocation, mount-namespace
state could leak between namespaces.

**Action**: write a stress test that spawns 16-32
concurrent `LabNamespace::new` calls, each creating a
distinct named namespace with a distinct dummy interface,
and verify after completion:

- Each namespace exists (`/var/run/netns/<name>` present).
- Each contains exactly its expected dummy.
- No dummy bleeds across namespaces (the ifindex space is
  per-namespace; we verify by enumerating from inside each
  netns and comparing names).
- Cleanup on drop works (each namespace is removed when its
  `LabNamespace` drops).

## 3. The change shape

### 3.1 If both tests go GREEN (the expected case)

Ship the tests as permanent regression guards. ~150 LOC of
integration test + ~30 LOC of CHANGELOG note pointing at the
rtnetlink issue URLs as the precedent.

### 3.2 If the seq-routing test goes RED

Likely root cause: the `&self`-method recv-loop pattern lets
two `recv_msg().await`s race on the same socket. Fix shape:
internalize an `Arc<Mutex<()>>` recv-side serializer or
require `&mut self` for any method that does recv. The
latter is cleaner and matches the kernel's actual constraint
(one consumer per fd at a time).

This would be a real semver break (every `Connection`
method that does recv becomes `&mut self`). Estimate ~half a
day of refactoring plus migration guide. Land as a separate
follow-up to this plan if it turns out to be needed.

### 3.3 If the concurrent-namespace test goes RED

Likely root cause: `setns(2)` is not thread-safe in the way
we assume, OR the `/proc/self/ns/net` bind-mount path has a
race. Fix shape: serialize namespace creation via a
process-wide `Mutex` in `namespace.rs`. ~20 LOC. Performance
impact only on the ns-creation path, which is rare.

## 4. Tests

### 4.1 Integration — interleaved request seq routing

```rust
// crates/nlink/tests/integration/seq_routing.rs (new file)

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_concurrent_dumps_on_shared_connection_route_correctly()
    -> nlink::Result<()>
{
    require_root!();

    let ns = TestNamespace::new("seq-routing")?;
    let conn = std::sync::Arc::new(
        namespace::connection_for::<Route>(ns.name())?
    );

    // Pre-create a known dummy so each dump returns at least
    // one link.
    conn.add_link(DummyLink::new("dummy0")).await?;

    // Spawn 16 concurrent get_links calls. If seq routing is
    // broken, some tasks see other tasks' responses (wrong
    // link names, mismatched lengths, etc.).
    let mut handles = vec![];
    for _ in 0..16 {
        let c = conn.clone();
        handles.push(tokio::spawn(async move {
            c.get_links().await
        }));
    }

    for h in handles {
        let links = h.await.unwrap()?;
        assert!(
            links.iter().any(|l| l.name.as_deref() == Some("dummy0")),
            "every concurrent dump must see dummy0 (seq routing)"
        );
    }

    Ok(())
}
```

If `Connection<P>` is `!Sync` (no shared-ref multi-task
usage allowed), this test won't compile — the type system
prevents the bug. Document that as the actual defense.

### 4.2 Integration — concurrent namespace creation stress

```rust
// crates/nlink/tests/integration/lab_concurrent.rs (new file)

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sixteen_concurrent_namespaces_dont_corrupt_each_other()
    -> nlink::Result<()>
{
    require_root!();

    let count = 16;
    let mut handles = Vec::with_capacity(count);
    for i in 0..count {
        handles.push(tokio::spawn(async move {
            let ns_name = format!("stress-{i}");
            let ns = TestNamespace::new(&ns_name)?;
            let conn = namespace::connection_for::<Route>(ns.name())?;
            let iface_name = format!("d{i}");
            conn.add_link(DummyLink::new(&iface_name)).await?;
            // Verify only OUR dummy is visible from THIS ns.
            let links = conn.get_links().await?;
            let ours: Vec<_> = links.iter()
                .filter_map(|l| l.name.as_deref())
                .filter(|n| n.starts_with('d'))
                .collect();
            assert_eq!(ours.len(), 1, "ns {i} must see only its own dummy; saw {ours:?}");
            assert_eq!(ours[0], iface_name);
            Ok::<_, nlink::Error>(ns)  // hold ns until end
        }));
    }

    let _namespaces: Vec<_> = futures::future::try_join_all(handles)
        .await
        .map_err(|e| nlink::Error::Other(e.to_string()))?
        .into_iter()
        .collect::<Result<Vec<_>, _>>()?;

    // All 16 namespaces drop here; verify cleanup.

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn rapid_namespace_create_delete_doesnt_leak() -> nlink::Result<()> {
    require_root!();

    // Aggressively create + drop 32 namespaces sequentially.
    // Verifies the Drop impl doesn't leak procfs handles or
    // /var/run/netns entries.
    for i in 0..32 {
        let ns_name = format!("churn-{i}");
        let ns = TestNamespace::new(&ns_name)?;
        // do something with it
        let _ = namespace::connection_for::<Route>(ns.name())?;
        drop(ns);
    }
    Ok(())
}
```

### 4.3 Unit — `Connection<P>` send/sync trait bounds

```rust
#[test]
fn connection_route_is_send_but_check_sync_status() {
    fn assert_send<T: Send>() {}
    assert_send::<nlink::Connection<nlink::Route>>();
    // If Connection is Sync, document it explicitly + verify
    // the seq-routing integration test compiles.
    // If !Sync, the type system already prevents the bug.
}
```

## 5. Acceptance criteria

- [ ] `tests/integration/seq_routing.rs` with the 16-task
      concurrent dump test (root-gated).
- [ ] `tests/integration/lab_concurrent.rs` with the 16-task
      concurrent ns creation test + the 32-iteration churn
      test (root-gated).
- [ ] Trait-bound assertion test for `Connection<P>` (any
      target compile gate).
- [ ] CHANGELOG `### Fixed` (if a bug is found) or `### Added`
      (regression tests only).
- [ ] If green: link to rtnetlink #131 / #132 in CHANGELOG
      as the precedent.
- [ ] If red: ship the matching fix + migration guide entry.

## 6. Effort estimate

| Phase | Effort |
|---|---|
| Phase 1: trait-bound audit + tests | ~1 h |
| Phase 2: seq-routing integration test | ~1 h |
| Phase 3: concurrent ns stress test | ~2 h |
| Phase 4 (conditional): fixes if red | up to 1 day |
| CHANGELOG + migration guide | ~30 min |
| **Total (green path)** | **~4.5 h** |
| **Total (red path)** | **~1.5 days** |

## 7. Risks

- **rtnetlink #131 might not apply at all** — their
  architecture has multiple receivers on one socket via an
  `mpsc` channel demultiplexed by seq. nlink's
  `Connection<P>` is single-receiver per fd. The bug class
  is structurally absent if the audit confirms single-flight
  discipline; the test just pins it.
- **Concurrent ns creation might genuinely be racy** because
  it touches `/var/run/netns/` (file-system shared state) +
  `setns(2)` (per-process). If red, the fix is a global
  mutex around the create critical section. Performance
  impact only on ns creation, which is rare.
- **Tests need 4 worker threads** — single-threaded tokio
  runtime would serialize the spawn'd tasks and miss the
  race. Configure `worker_threads = 4`.

## 8. Out-of-scope follow-ups

- **Stress testing nftables Transaction commit concurrency**
  — if multiple writers commit to the same table from
  different connections, do batches see consistent state?
  Different bug class; defer.
- **`ConnectionPool` under high churn** — Plan 159
  delivered the pool; high-churn behavior wasn't part of
  Plan 162's invalidate test. Could be a follow-up.

## 9. Cross-cutting artifacts

| Artifact | Action | Notes |
|---|---|---|
| `CHANGELOG.md` `## [Unreleased]` | **add** `### Added` (regression tests) and IF the tests go red, also `### Fixed` (the concrete bug + fix description) | Link to rtnetlink #131 + #132 as precedent. |
| `docs/migration_guide/0.18.0-to-0.19.0.md` | **append** `### Plan 194` — usually a no-op section ("regression tests added; no consumer action required") unless a fix surfaces a Send/Sync change | If a fix lands that changes `Connection<P>` trait bounds (e.g. requires `&mut self`), document the migration. |
| `CLAUDE.md` | **append** a "## Single-flight discipline" sub-section in the existing recv-loop / connection-lifetime area documenting that `Connection<P>` methods are NOT safe to call concurrently from multiple tasks on a shared `&Connection` reference (or the test demonstrates they ARE — update wording based on §3.1's audit outcome) | Future contributors writing new `Connection` methods inherit the right invariant. |
| `crates/nlink/tests/integration/seq_routing.rs` (**new**) | already in §4.1 of this plan | Root-gated. |
| `crates/nlink/tests/integration/lab_concurrent.rs` (**new**) | already in §4.2 of this plan | Root-gated. |
| `docs/recipes/` | **no new recipes** — these are regression tests, not user-facing patterns | |

End of plan.
