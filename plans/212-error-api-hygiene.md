---
to: nlink maintainers
from: 0.19 second deep-audit
subject: Plan 212 — Error API hygiene (M9, M15, M16, M17)
status: queued for 0.19 — MEDIUM (asymmetry + docstring gaps)
target version: 0.19.0
parent: [203](203-0.19-second-batch-master.md)
source: docs/AUDIT_REPORT_2026_05_31.md §M9, M15, M16, M17
created: 2026-05-31
---

# Plan 212 — Error API hygiene

## 1. Why this plan exists

Four MEDIUM findings around the Error API and Connection<P>
semantics:

- **M9** `Error::is_not_found` doesn't route through `errno()` —
  misses `Error::Io(io_err with ENOENT)`. Asymmetric with
  `is_permission_denied`, `is_already_exists`, `is_busy` which
  Plan 187 §2.5 explicitly fixed.
- **M15** `Connection<P>: Sync` compiles but concurrent use loses
  responses (F1 finding from first audit). Not UB; semantically
  misleading. Needs docstring warning at minimum.
- **M16** `send_ack_inner` silently re-reads on matching-seq
  non-error frame. Bounded by the 30s timeout but unexpected.
- **M17** `RwLock::read/write().unwrap()` on family cache panics
  on poison. Currently unreachable but brittle.

This plan ships small fixes for each. No new types; purely
hardening existing code.

## 2. Phase 1 — M9 `is_not_found` Io coverage

**File:** `crates/nlink/src/netlink/error.rs:506-519`

Replace:
```rust
pub fn is_not_found(&self) -> bool {
    match self {
        Self::Kernel { errno, .. } | Self::KernelWithContext { errno, .. } => {
            matches!(*errno, 2 | 19) // ENOENT=2, ENODEV=19
        }
        Self::Interface(IfError::NotFound(_)) => true,
        Self::InterfaceNotFound { .. }
        | Self::NamespaceNotFound { .. }
        | Self::QdiscNotFound { .. }
        | Self::FamilyNotFound { .. } => true,
        _ => false,
    }
}
```

With (matches the Plan 187 §2.5 pattern):
```rust
pub fn is_not_found(&self) -> bool {
    // Errno-based check (covers Kernel, KernelWithContext, AND
    // Io variants — `self.errno()` already merges these per Plan
    // 187 §2.5).
    if matches!(self.errno(), Some(libc::ENOENT) | Some(libc::ENODEV)) {
        return true;
    }
    // Typed not-found variants.
    matches!(
        self,
        Self::Interface(IfError::NotFound(_))
        | Self::InterfaceNotFound { .. }
        | Self::NamespaceNotFound { .. }
        | Self::QdiscNotFound { .. }
        | Self::FamilyNotFound { .. }
    )
}
```

Add regression tests:
```rust
#[test]
fn is_not_found_catches_io_enoent() {
    let io = io::Error::from_raw_os_error(libc::ENOENT);
    let err: Error = io.into();
    assert!(err.is_not_found(),
        "is_not_found must match Io(ENOENT) per Plan 187 symmetry");
}
#[test]
fn is_not_found_catches_io_enodev() {
    let io = io::Error::from_raw_os_error(libc::ENODEV);
    let err: Error = io.into();
    assert!(err.is_not_found());
}
```

## 3. Phase 2 — M15 Connection<P> Sync docstring

**File:** `crates/nlink/src/netlink/connection.rs` (top of
`Connection<P>` impl docs).

Add a prominent caveat:

```rust
/// # Concurrency caveat
///
/// `Connection<P>` implements `Send + Sync` so it can be shared
/// across tokio tasks via `Arc<Connection<P>>`. **However**, the
/// underlying netlink socket is single-flight: concurrent
/// `.await`-ed calls on the same connection can race on the
/// recv side. The seq filter in `send_request_inner` protects
/// against stale-frame corruption but does NOT prevent task A
/// from consuming task B's response in flight.
///
/// **What can happen**: two tasks both call `.add_link()`
/// simultaneously. Task A's `recv_msg().await` polls before
/// task B's; the kernel delivers task B's response first; A
/// sees seq=B and skips it (correct), then polls again and
/// blocks indefinitely (or hits timeout) because B's response
/// was consumed and discarded; B in turn blocks because A's
/// response now sits in the kernel buffer with no waiter.
/// Both tasks return `Error::Timeout` after the 30s budget.
///
/// **Recommended usage**:
///
/// - One `Connection<P>` per task.
/// - To fan out concurrent work across many tasks, use
///   `nlink::netlink::ConnectionPool<P>` — each task acquires
///   a connection from the pool, uses it serially, returns it.
/// - `Connection<P>` shared across tasks is OK if the tasks
///   guarantee they don't concurrently `.await` on the same
///   connection (e.g. a Mutex<Connection> wrapping all
///   methods).
///
/// See `nlink::netlink::pool::ConnectionPool` for the canonical
/// fan-out pattern.
pub struct Connection<P> { /* ... */ }
```

Also add to the `Connection::new` rustdoc a one-line link to
this section.

## 4. Phase 3 — M16 `send_ack_inner` defensive Err on unexpected frame

**File:** `crates/nlink/src/netlink/connection.rs:420-450`

Current behavior: on `nlmsg_seq == expected_seq` AND
`!header.is_error()`, the inner for loop falls through; outer
loop reads another frame.

Replace:
```rust
if header.is_error() {
    let err = NlMsgError::from_bytes(payload)?;
    if !err.is_ack() {
        warn!(errno = err.error, "kernel returned error for ack");
        return Err(err.into_error(payload));
    }
    return Ok(());
}
// implicit fall-through to outer loop on non-error matching-seq
```

With:
```rust
if header.is_error() {
    let err = NlMsgError::from_bytes(payload)?;
    if !err.is_ack() {
        warn!(errno = err.error, "kernel returned error for ack");
        return Err(err.into_error(payload));
    }
    return Ok(());
}
// Matching seq + non-error response on an ack-only operation
// is unexpected (kernel returned data on what nlink considered
// a SET-style request). Surface explicitly rather than
// silently waiting for a possible ACK that may never come.
return Err(Error::InvalidMessage(format!(
    "send_ack: expected ACK or error for seq {}, got nlmsg_type {} \
     (data response on ack-only request)",
    seq, header.nlmsg_type
)));
```

Test:
```rust
#[test]
fn send_ack_returns_err_on_unexpected_data_response() {
    // Synthesize: ack request with seq=42; response frame
    // is RTM_NEWLINK with seq=42 (not error, not ack).
    // Verify Error::InvalidMessage with the "data response"
    // text.
}
```

## 5. Phase 4 — M17 RwLock poison policy

**File:** `crates/nlink/src/netlink/connection.rs:2295, 2312, 2332`
and `protocol.rs:190, 449`.

Replace each `self.state.cache.read().unwrap()` and
`.write().unwrap()` with:

```rust
let cache = self.state.cache.read()
    .unwrap_or_else(|p| p.into_inner());
```

This recovers from poisoning (treating the lock as if poisoning
never happened) instead of panicking. Combined with the existing
no-panic-in-locked-region guarantee, this is the right policy.

Alternative (more invasive): switch to `parking_lot::RwLock`
which doesn't poison at all. Faster, but adds a dep. Save for
0.20.

## 6. Tests

(Per-phase, already inline above.)

## 7. CHANGELOG entry

```markdown
### Fixed

- **`Error::is_not_found` now matches `Error::Io(ENOENT)` and
  `Error::Io(ENODEV)`** (M9). Brings the predicate into
  symmetry with `is_busy`, `is_permission_denied`, and
  `is_already_exists` which Plan 187 §2.5 already routed
  through `errno()`. Code calling `e.is_not_found()` on an
  `Error::Io` carrying ENOENT now correctly returns true.

- **`Connection::send_ack_inner` surfaces an explicit error on
  unexpected matching-seq data response** (M16) instead of
  silently looping for the next frame (which would hit the
  30s timeout). Defense-in-depth against kernel behavior
  divergence.

- **`Connection::cache` RwLock poison handling**: previously
  `read/write().unwrap()` would panic on poisoning; now
  recovers via `unwrap_or_else(into_inner)`. Hardens against
  future panics inside the locked region (currently
  unreachable; this is defense-in-depth).

### Documentation

- **`Connection<P>` doc-comment now describes the concurrent-
  use caveat** (M15). `Sync` impl compiles but concurrent
  `.await`-ed calls on a shared connection can race on recv
  and produce dual `Error::Timeout`. Use
  `ConnectionPool<P>` for fan-out. The architectural fix
  (NlRouter-style dispatch) is documented as out-of-scope for
  0.19.
```

## 8. Acceptance criteria

- [ ] `is_not_found` updated + 2 regression tests
- [ ] `Connection<P>` docstring concurrency caveat
- [ ] `send_ack_inner` explicit Err + 1 test
- [ ] RwLock poison-tolerant unwrap (5 sites)
- [ ] CHANGELOG entries

## 9. Effort estimate

| Phase | Time |
|---|---|
| M9 is_not_found fix + tests | 30 min |
| M15 docstring | 30 min |
| M16 send_ack_inner + test | 1 h |
| M17 RwLock poison | 30 min |
| CHANGELOG | 30 min |
| **Total** | **~3 h** |

## 10. Cross-cutting artifacts

| Artifact | Action |
|---|---|
| `CHANGELOG.md` | 3 fixed + 1 documentation entry |
| `crates/nlink/src/netlink/error.rs` | is_not_found + 2 tests |
| `crates/nlink/src/netlink/connection.rs` | docstring + send_ack_inner + 5 RwLock sites + 1 test |
| `crates/nlink/src/netlink/protocol.rs` | 2 RwLock sites |

End of plan.
