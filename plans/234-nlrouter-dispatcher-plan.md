---
to: nlink maintainers
from: 0.20 cycle pre-work — deep audit derivation
subject: F1 follow-on — per-seq response dispatcher (NlRouter-style)
status: planning — discretionary; cycle ships without it if other plans crowd
target version: 0.20.0 (or 0.21.0)
parent: [Plan 220 master](220-0.20-master-plan.md)
source: [plans/INDEX.md](INDEX.md) `## 0.20 cycle seed` F1 follow-on row; CHANGELOG `## [0.19.0]` Plan 194 entry
created: 2026-06-04
---

# Plan 234 — F1 follow-on: per-seq response dispatcher

## 1. Why this plan exists

0.19 Plan 194 closed F1 (correctness): `Connection<P>` became
`Send + Sync` via a `tokio::sync::Mutex` that every
`send_request`-shape method acquires for the duration of the
send+recv pair. That made `Arc<Connection<P>>` safe to share
across tokio tasks; concurrent callers serialize cleanly.

The correctness fix has a performance ceiling. Two specific
shapes hit it hard:

1. **Long-lived stream APIs hold the lock for their lifetime.**
   `conn.events().await`, `conn.into_events().await`,
   `conn.dump_stream::<T>(...).await?`, and the
   `*_with_resync` constructors all acquire the request lock
   when constructed and don't release it until the stream is
   dropped. A program that subscribes to events on one
   `Arc<Connection>` and then tries to issue a request on the
   same connection from another task waits indefinitely.
   Today's recommendation is "use a second Connection or
   `ConnectionPool` for the parallel path" — that works but
   asks the user to know about a footgun.

2. **Mutex-serialized requests can't pipeline.** A small
   `get_link_by_index()` issued while a 1M-route `dump_routes()`
   is in flight on the same Connection waits for the dump's full
   lifetime. The kernel can interleave responses by `nlmsg_seq`,
   but the lock prevents the client from issuing the small
   request until the dump finishes.

The cure is the design pattern neli's [`NlRouter`](https://docs.rs/neli/0.7.0-rc3/neli/router/asynchronous/struct.NlRouter.html)
uses: a dispatcher task owns the file descriptor; per-pending-seq
oneshot channels demux replies; multicast subscriptions get
bounded broadcast channels. F1's correctness wins are preserved
(the dispatcher owns the fd, so no two tasks ever recv-race) and
the performance ceiling lifts (per-seq fan-out is parallel).

This plan is **discretionary** for 0.20. The 13 deterministic
plans (Plan 221-233) take precedence; if the cycle is on track
when those finish, this lands. If not, it slides to 0.21. The
audit report says as much (`AUDIT_REPORT.md` lists plans 234-235
under "discretionary"); the cycle exit criteria don't gate on
this plan.

## 2. The design

A `Dispatcher<P>` task spawns from `Connection::new()` and owns
the `AsyncFd<Socket>`. Public methods on `Connection<P>` become
"register-and-await" wrappers:

```rust
struct Connection<P: ProtocolState> {
    cmd_tx: mpsc::Sender<DispatcherCmd>,
    next_seq: AtomicU32,
    _state: PhantomData<P>,
}

enum DispatcherCmd {
    Request {
        seq: u32,
        bytes: Vec<u8>,
        reply: oneshot::Sender<Result<Vec<u8>>>,
    },
    Dump {
        seq: u32,
        bytes: Vec<u8>,
        chunks: mpsc::Sender<Result<Vec<Vec<u8>>>>,
    },
    Subscribe {
        groups: Vec<u32>,
        ack: oneshot::Sender<Result<broadcast::Receiver<Result<Vec<u8>>>>>,
    },
    Shutdown,
}
```

The dispatcher task's main loop:

```rust
loop {
    tokio::select! {
        biased;
        Some(cmd) = cmd_rx.recv() => handle_cmd(cmd).await,
        recv = socket.recv() => handle_recv(recv).await,
        else => break,
    }
}
```

`handle_recv` parses each `MessageIter` frame, looks up the
seq in `pending: HashMap<u32, ReplySink>`, and dispatches:

- Unicast response with known seq: deliver to the right
  oneshot / mpsc, terminate on `NLMSG_DONE` / ACK.
- Multicast frame (seq == 0, or PORTID == 0 — depends on the
  family): fan-out to all matching broadcast channels.
- Unknown seq: `tracing::warn!` and drop (the F1 mutex era
  silently consumed these; the dispatcher makes them visible).

`handle_cmd` sends the request bytes to the kernel and registers
the reply sink in the `pending` map.

`Connection<P>` is `Send + Sync` because `mpsc::Sender` is. The
F1 `Mutex` is removed — the dispatcher is the sole synchronization
point.

## 3. Multicast handling

Multicast subscriptions today live in a separate code path
(`EventSubscription` etc.). They need to coexist with the per-seq
unicast dispatcher because the kernel delivers both classes of
frames on the same fd.

Design:

- A `Subscribe` command adds the requested group to the
  socket's multicast membership and creates a new
  `broadcast::Sender` keyed by `(family, group)`.
- The dispatcher's recv loop checks each frame's
  `(nlmsg_pid, nlmsg_seq)` — for multicast frames both are 0.
  Multicast frames fan out to every matching subscriber.
- The broadcast channel has a configurable bounded capacity
  (default 1024). Slow subscribers see broadcasts dropped from
  their channel; the dispatcher synthesizes a
  `ResyncMarker::ResyncStart` event into their channel and the
  caller's `*_with_resync` wrapper kicks in (Plan 151).

The per-broadcast-channel cap means a slow subscriber can't
back-pressure the dispatcher's recv loop. The dispatcher always
makes forward progress.

## 4. ENOBUFS interaction with Plan 151

When the kernel-side multicast buffer overflows, the kernel
delivers an `ENOBUFS` socket error to the next `recv`. The
dispatcher catches this at the recv-loop level (it's the only
recv-er) and fans out a `ResyncMarker::ResyncStart` into every
active multicast `broadcast::Sender`. The user-facing
`subscribe_*_with_resync` wrappers (Plan 151) already handle the
marker by re-issuing the appropriate dump request and stitching
the result.

The pre-dispatcher behavior was that `ENOBUFS` surfaced into
whichever caller happened to be in `recv_msg` at the time — often
a request, not the multicast subscriber that should care. The
dispatcher centralizes the handling and routes it correctly.

`scripts/audit-recv-loop-error-handling.sh` and Plan 172's recv-
loop template stay authoritative; the dispatcher's recv loop is
the canonical implementation of the template.

### 4.1 Deliberate divergence from neli

Cross-checked against neli's reference implementation at
`neli/src/router/asynchronous.rs` (verified during the
consolidation review). **neli does NOT special-case ENOBUFS**
— when the kernel emits an ENOBUFS error into a subscriber's
queue, neli treats it the same as any other parse failure and
the subscriber may quietly drop frames.

This plan's ENOBUFS-to-`ResyncMarker::ResyncStart` routing is a
deliberate improvement. neli's behavior is silent data loss;
ours is "loud" data loss (the marker fires, the subscriber
knows, the Plan 151 wrapper re-syncs). The cost is the marker
type's existence and the wrapper's complexity — both shipped
in 0.19 specifically to make this routing possible.

This is also a divergence from `rtnetlink`-the-crate (which
doesn't have a dispatcher at all) and from the bare `netlink-sys`
crate (which leaves recv-loop handling entirely to the caller).
nlink's dispatcher closes the gap.

Worth highlighting in the eventual 0.20 CHANGELOG entry:
*"Plan 234's dispatcher routes ENOBUFS specifically to multicast
subscribers via `ResyncMarker::ResyncStart`, deliberately
diverging from neli's behavior. neli silently drops frames on
ENOBUFS; nlink surfaces the marker so the Plan 151 resync
wrapper recovers."*

## 5. API surface stability

**No public API changes.** The full `Connection<P>` method
signatures are preserved:

- `send_request_and_wait(bytes) -> impl Future<Output = Result<Vec<u8>>>`
- `send_dump(bytes) -> impl Future<Output = Result<Vec<Vec<u8>>>>`
- `dump_stream::<T>(msg_type) -> impl Future<Output = Result<DumpStream<T>>>`
- `subscribe_*() -> impl Future<Output = Result<EventSubscription>>`
- `events() / into_events() / *_with_resync()`

The implementation routes through the dispatcher; the caller
sees no shape change. F1's `Connection<P>: Send + Sync` is
preserved (via the channel-only state).

The `ConnectionPool<P>` (Plan 159) is unchanged. Each pooled
connection has its own dispatcher; pool-level fan-out is over
many dispatchers, single-Connection fan-out is over many
oneshots into one dispatcher. The pool is still the right
abstraction for many-fd parallelism (multiple kernel-side socket
queues); the dispatcher is the right abstraction for one-fd
many-request pipelining.

The F1 era required users to choose between "share an `Arc<Conn>`
and serialize" or "use a pool". Post-dispatcher, the choice is
between "share an `Arc<Conn>` and pipeline through one fd" or
"use a pool for many-fd parallelism". The latter still wins on
large dump fan-out where the kernel-side processing parallelizes;
the former wins on workloads where requests are cheap and
fd-overhead matters.

## 6. Test plan

Three classes of test.

### 6.1 Correctness

- Existing `cargo test -p nlink --lib` must pass unchanged. The
  dispatcher is wire-compatible with the F1 mutex's behavior for
  all single-request and single-dump shapes.
- Existing integration tests (with `nlink::require_root!()`)
  must pass — the dispatcher must not regress any wire-format
  test.

### 6.1.1 Per-family integration tests

If Plan 235 (GENL command unification) ships in the same cycle,
its per-family migration tests cover the dispatcher's correctness
across every GENL family. If Plan 235 doesn't ship, Plan 234
**must** ship the equivalent coverage itself — otherwise the
dispatcher is exercised against only `Connection<Route>` paths
and the GENL families (which have their own command-recv loops
the dispatcher now unifies) are untested through the new path.

Per-family tests required (all `require_root!()` + appropriate
module gating):

| Family | Test gist | Module gate |
|---|---|---|
| Wireguard | `set_device` + `get_device` round-trip via dispatcher | `wireguard` |
| Macsec | `add_link` + `del_link` for a macsec device | `macsec` |
| MPTCP | `get_limits` + `set_limits` round-trip | `mptcp_pm` |
| Ethtool | `get_link_info` for a dummy device | `dummy` (eth driver always present) |
| Nl80211 | `get_interface` (returns empty list on no-wifi hosts; that's the test) | n/a (kernel always has wireless infra) |
| Devlink | `device_dump` (returns empty list on no-devlink hosts; that's the test) | n/a |
| DPLL | `pin_dump` round-trip | `dpll` (per Plan 226 §5.4) |
| net_shaper | `caps_get` for a dummy device | `dummy` |

Each test runs 100 commands while a multicast stream is open
on the same `Arc<Connection>`. Assert: the multicast stream
delivers events only from its subscribed group (no stale
unicast responses crossover); the request task gets all 100
responses with no `FamilyNotFound` (a pre-dispatcher stale-frame
race for wg_command); request p99 latency stays bounded.

### 6.2 Performance / non-regression

- Stress test (`stress_n_requests_with_long_dump`): on one
  `Arc<Connection>`, spawn 32 tasks issuing `get_link_by_index`
  concurrently with one task running `dump_routes` (synthetic
  10k-route table via `lab` namespace). Assert the latency
  distribution of the small requests is **not** bimodal — they
  should complete in roughly equal time whether the dump is in
  flight or not. The F1-mutex baseline shows a clear bimodality
  (small requests block until the dump finishes).
- Stress test (`stress_subscriber_while_requesting`): one task
  subscribes to all RTMGRP groups; in parallel another task
  issues 1000 `get_link_by_name` calls. Assert no head-of-line
  blocking on either side; the F1-mutex baseline shows the
  subscriber blocks on every request.

### 6.3 ENOBUFS recovery

- Synthetic test (`enobufs_fans_out_resync_marker`): inject an
  `ENOBUFS` via a mock socket; assert every active multicast
  `broadcast::Receiver` sees a `ResyncMarker::ResyncStart` and
  the wrapped `*_with_resync` stream re-issues the dump.

The stress tests can live under `crates/nlink/tests/stress/`
gated `#[ignore]` (long-running) plus a CI knob to run them
under the privileged-CI workflow.

## 7. Risks

- **Dispatcher task panics**. The dispatcher is the sole owner
  of the fd; if it panics, every pending request hangs forever
  (oneshot senders dropped → receivers see `RecvError`). The
  recovery design:
  - All sources of panic in the dispatcher must be lifted to
    `Result` (no `expect`, no `unwrap`). The recv path follows
    the established robustness rules (Plan 193); the
    `pending`-map management is straightforward `HashMap`
    operations that don't panic.
  - On dispatcher exit (graceful or otherwise) the dispatcher
    drops the command receiver; every subsequent `cmd_tx.send`
    returns `Err`, surfacing as
    `Error::ConnectionClosed { reason }` to the caller.
  - The `Connection<P>::is_closed()` predicate (already exists)
    becomes a strong signal — pre-dispatcher it was set only on
    explicit close; post-dispatcher it fires on any dispatcher
    exit.

- **Channel capacity surprises**. The cmd channel is bounded
  (default 256); a burst of requests can fill it, causing
  `cmd_tx.send().await` to wait. This is fine in normal use
  (it's back-pressure) but a stuck dispatcher (deadlock from a
  bug) shows up as a request hang. Mitigation: every public
  method already runs under the 30s default Connection timeout
  (Plan 171); a deadlocked dispatcher surfaces as
  `Error::Timeout`. Plan 171's safety net catches dispatcher
  bugs.

- **Memory usage from the pending map**. Cancelled futures
  leave their `oneshot::Sender` dropped; the dispatcher's recv
  path sees the channel as closed when it tries to deliver and
  removes the entry. Net: bounded by in-flight request count,
  cleaned up automatically. The `Connection::drain()` helper
  proposed in B12's notes (see Plan 232) becomes unnecessary
  because the dispatcher actively drains its socket.

- **The migration story**. F1 shipped in 0.19 and changed user-
  facing concurrency semantics; the dispatcher changes them
  again but more subtly. CHANGELOG entry must call out: "the
  per-Connection mutex from F1 is replaced by an internal
  dispatcher task; shared `Arc<Connection>` requests no longer
  serialize, they pipeline. Behavioral compatibility for
  single-request callers is preserved." Plus a migration-guide
  entry pointing at the performance improvement.

- **Discretionary status**. Risk: the maintainer rolls into
  0.20 mid-cycle and the work doesn't finish, leaving a
  half-landed dispatcher PR. Mitigation: this plan is gate-
  checked at the cycle's mid-point (Plan 220's weekly check-in).
  If the work hasn't started by then, it's explicitly deferred
  to 0.21 in the cycle-cut commit.

## 8. Acceptance

The dispatcher lands when:

- `cargo test -p nlink --lib` is green; all existing tests pass.
- The F1 `tokio::sync::Mutex` is removed from
  `Connection<P>`.
- The two stress tests in §6.2 pass with the dispatcher and
  fail (bimodal latency / head-of-line blocking) when reverted
  to the F1 mutex implementation.
- ENOBUFS recovery test in §6.3 passes.
- CHANGELOG `## [Unreleased]` calls out the change; migration
  guide entry written.
- Plan 159 (`ConnectionPool`) doc-comment is updated to
  contrast the dispatcher's per-Connection pipelining vs the
  pool's per-Connection parallelism (with the right framing for
  when to use which).

## 9. Cross-references

- [Plan 194](194-mutex-serialization-plan.md) (0.19) — the
  F1 fix this builds on. Plan 194's "follow-on" callout is
  the source of this plan.
- [Plan 159](159-connection-pool-plan.md) (0.16) — the
  pool abstraction. Stays compatible with the dispatcher.
- [Plan 151](151-enobufs-resync-plan.md) (0.16) — the
  `ResyncMarker` / `ResyncedEvent` types the dispatcher emits.
- [Plan 171](171-default-timeout-plan.md) (0.17) — the
  default 30s safety net that backstops dispatcher bugs.
- [Plan 172](172-recv-loop-audit-plan.md) (0.17) — the
  canonical recv-loop template the dispatcher's recv path
  implements.
- [Plan 208](208-recv-loop-completion-plan.md) (0.19) +
  [Plan 235](235-genl-command-unification-plan.md) — the
  GENL recv-loop unification; the dispatcher subsumes most of
  Plan 235's surface area if it lands first.
- neli's [`NlRouter`](https://docs.rs/neli/0.7.0-rc3/neli/router/asynchronous/struct.NlRouter.html)
  documentation — design reference.
- `docs/migration_guide/0.18.0-to-0.19.0.md` §"Plan 194" — the
  F1 era's stated follow-on intent.
