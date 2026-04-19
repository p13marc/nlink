---
to: nlink maintainers
from: nlink maintainers
subject: tracing instrumentation for nlink — make the unused dep useful
target version: 0.13.0
date: 2026-04-19
status: draft, awaiting review
---

# Tracing Instrumentation Plan

## 0. Summary

`tracing` is in `crates/nlink/Cargo.toml` (workspace dep) but **zero
call sites**. `cargo machete` flags it on every check. Either delete
the dep or actually use it.

We use it. Adding tracing is high-leverage:

- **Library users debugging real network setups** today get one line
  per error and no operational visibility. With tracing they get
  structured spans showing the request flow.
- **Reconcile-loop consumers** (Plan 131) need to see *which* recipe
  call did *what* against the kernel.
- **Cost is near-zero**: the `tracing` macros expand to a single
  relaxed atomic load when no subscriber is attached. Universally
  used in modern async Rust libraries.

Decisions:

- **Always-on, not feature-gated.** Matches `tokio`, `hyper`,
  `quinn`, `rustls` conventions. Gating tracing creates friction
  for downstream subscribers.
- **`#[instrument]` on public async methods**, with `skip_all` and
  explicit `fields(...)` to control payload.
- **Span-level convention**: `INFO` for connection lifecycle, `DEBUG`
  for public API entry/exit, `TRACE` for per-message send/recv,
  `WARN`/`ERROR` for kernel errors and unexpected attributes.
- **Structured fields, not formatted strings.**

This is additive — no BC break. ~300-500 LOC of attribute
sprinkling + a small "logging guide" doc section.

---

## 1. Goals & non-goals

### Goals

1. Every public Connection method has an `#[instrument]` span.
2. Every netlink request → response cycle is observable at TRACE level
   (request kind, sequence number, success/error, timing).
3. Errors carry context via existing `Error::with_context` _and_ a
   tracing `error!` event for visibility without parsing the error
   string.
4. Multicast event delivery has a span per event class, with
   per-event metadata (link name, address family, ifindex).
5. Recipe helpers (`PerHostLimiter::apply`, `PerPeerImpairer::apply`,
   `PerPeerImpairer::reconcile`, etc.) have one INFO-level span per
   call summarizing the high-level operation.
6. The instrumentation costs nothing when no subscriber is attached.

### Non-goals

1. Building a default subscriber. Library users wire `tracing-subscriber`
   themselves.
2. Metrics emission. Spans are an in-band structured log; metrics
   (counters/histograms) are out of scope.
3. Distributed tracing context propagation. There's no upstream
   "request" in a netlink library; nothing to propagate.
4. Per-attribute trace events. TCA_KIND/TCA_OPTIONS get logged once
   per netlink message, not per attribute.

---

## 2. Conventions

### 2.1. Levels

| Level | What goes here |
|---|---|
| `ERROR` | Unrecoverable: socket closed unexpectedly, OOM in serialization. Almost never. |
| `WARN` | Kernel returned an unexpected attribute we ignored; multicast event dropped (ENOBUFS); deprecated path used. |
| `INFO` | Connection opened/closed; namespace switch; multicast group subscription; recipe `apply`/`reconcile` start/end. |
| `DEBUG` | Public API entry/exit; family ID resolution; batch boundaries. |
| `TRACE` | Each netlink message sent/received; attribute parsing; retries. |

### 2.2. Span names

Use `crate::module::operation` form. Examples:

- `nlink::connection::send_ack`
- `nlink::connection::dump`
- `nlink::route::add_qdisc`
- `nlink::route::get_links`
- `nlink::genl::resolve_family`
- `nlink::impair::apply`
- `nlink::impair::reconcile`

This matches `tokio`/`hyper` convention and lets users filter by
prefix (`RUST_LOG=nlink::route=debug`).

### 2.3. Field selection

Each span carries the minimum fields needed to correlate:

- **Always**: the operation kind (often the span name).
- **For interface-targeted ops**: `ifindex` if known, `dev` if name.
- **For dumps**: `family` (e.g., AF_NETLINK protocol number).
- **For errors**: `errno` and the `op` context string.
- **Avoid**: full message bodies, full attribute trees, raw bytes.

```rust
// Good
#[instrument(level = "debug", skip_all, fields(ifindex = ifindex, parent = %parent))]
pub async fn add_qdisc_by_index_full(...) -> Result<()> { ... }

// Bad
#[instrument(level = "debug")]  // captures all args including config — too verbose
```

### 2.4. Error handling

Today: errors propagate via `Result<T, Error>`. Add tracing without
duplicating context:

```rust
async fn send_ack(&self, builder: MessageBuilder) -> Result<()> {
    let span = tracing::trace_span!("nlink::connection::send_ack",
        seq = builder.seq(),
    );
    let _enter = span.enter();
    // ... send / recv ...
    match result {
        Ok(()) => Ok(()),
        Err(e) => {
            tracing::warn!(errno = ?e.errno(), "kernel returned error");
            Err(e)
        }
    }
}
```

Or use `Result::inspect_err`:

```rust
result.inspect_err(|e| {
    tracing::warn!(errno = ?e.errno(), op = %op_name, "kernel returned error");
})
```

Don't `error!` for routine errors (file-not-found is common); reserve
`error!` for "this should never happen."

---

## 3. Where the spans go

### 3.1. Connection lifecycle (INFO)

```rust
// crates/nlink/src/netlink/connection.rs

#[instrument(level = "info", skip_all, fields(protocol = std::any::type_name::<P>()))]
pub fn new() -> Result<Self> { ... }

#[instrument(level = "info", skip_all, fields(ns = %ns_name))]
pub fn new_in_namespace(ns_name: &str) -> Result<Self> { ... }

#[instrument(level = "info", skip_all, fields(groups = ?groups))]
pub fn subscribe(&mut self, groups: &[RtnetlinkGroup]) -> Result<()> { ... }
```

### 3.2. Public API methods (DEBUG)

```rust
// crates/nlink/src/netlink/tc.rs

#[instrument(level = "debug", skip_all, fields(ifindex, parent = %parent))]
pub async fn add_qdisc_by_index_full(
    &self, ifindex: u32, parent: &str, ...
) -> Result<()> { ... }
```

For each public Connection method (~80 of them), add `#[instrument]`
with appropriate skip + fields. Mostly mechanical.

### 3.3. send/recv (TRACE)

```rust
// crates/nlink/src/netlink/connection.rs

async fn send_ack_inner(&self, builder: MessageBuilder) -> Result<()> {
    tracing::trace!(
        seq = builder.seq(),
        msg_type = ?builder.msg_type(),
        len = builder.len(),
        "sending netlink request",
    );
    // ... send ...
    let resp = self.recv().await?;
    tracing::trace!(seq = resp.seq(), "received ack");
    Ok(())
}
```

### 3.4. Multicast events (DEBUG/TRACE)

```rust
// crates/nlink/src/netlink/events.rs

impl Stream for EventSubscription<'_, P> {
    fn poll_next(...) -> Poll<...> {
        // when an event is yielded:
        tracing::trace!(
            event = ?event_kind(&ev),
            "delivering multicast event"
        );
    }
}
```

### 3.5. Recipe helpers (INFO)

```rust
// crates/nlink/src/netlink/impair.rs

#[instrument(level = "info", skip_all, fields(target = %self.target, rules = self.rule_count()))]
pub async fn apply(&self, conn: &Connection<Route>) -> Result<()> { ... }

#[instrument(level = "info", skip_all, fields(target = %self.target))]
pub async fn reconcile(&self, conn: &Connection<Route>) -> Result<ReconcileReport> {
    let report = ...;
    tracing::info!(
        changes = report.changes_made,
        added = report.rules_added,
        modified = report.rules_modified,
        removed = report.rules_removed,
        "reconcile complete",
    );
    Ok(report)
}
```

### 3.6. GENL family resolution (INFO once per family)

```rust
// crates/nlink/src/netlink/genl/connection.rs

#[instrument(level = "info", skip_all, fields(family = %name))]
pub async fn get_family(&self, name: &str) -> Result<u16> { ... }
```

### 3.7. Batch operations (DEBUG)

```rust
// crates/nlink/src/netlink/batch.rs

#[instrument(level = "debug", skip_all, fields(batch_size = self.ops.len()))]
pub async fn execute(&self) -> Result<BatchResults> { ... }
```

---

## 4. Files touched

| Path | Change | Approx LOC |
|---|---|---|
| `crates/nlink/src/netlink/connection.rs` | `#[instrument]` on ~30 methods + send/recv internals | ~120 |
| `crates/nlink/src/netlink/tc.rs` | `#[instrument]` on ~15 methods | ~50 |
| `crates/nlink/src/netlink/filter.rs` | `#[instrument]` on filter add/del/dump | ~20 |
| `crates/nlink/src/netlink/impair.rs` | INFO spans on apply/reconcile/clear | ~10 |
| `crates/nlink/src/netlink/ratelimit.rs` | Same on PerHostLimiter | ~10 |
| `crates/nlink/src/netlink/genl/**/connection.rs` | `#[instrument]` on family resolution + per-family methods | ~80 |
| `crates/nlink/src/netlink/events.rs` | TRACE event delivery | ~10 |
| `crates/nlink/src/netlink/batch.rs` | `#[instrument]` on execute | ~5 |
| `crates/nlink/src/netlink/namespace.rs` | INFO on namespace operations | ~15 |
| `docs/observability.md` | New: subscriber setup, level conventions, common queries | ~150 |
| `CLAUDE.md` | Mention tracing under "Debugging" section | ~30 |
| `CHANGELOG.md` | Entry | ~10 |
| `crates/nlink/tests/integration/observability.rs` | New: smoke test that spans appear | ~80 |

Total ~600 LOC. Most is `#[instrument]` annotation lines + 1-2-line
events; doc is the only multi-line content.

---

## 5. Tests

### 5.1. Smoke test (no root)

Use `tracing-subscriber` with a `Targets`+`Layer` that writes spans
to a `Vec<SpanRecord>`. Call a few public APIs and assert spans appear.

```rust
// tests/integration/observability.rs

#[tokio::test]
async fn lib_tests_emit_expected_spans() {
    use tracing_subscriber::prelude::*;
    let captured = Arc::new(Mutex::new(Vec::new()));
    let subscriber = tracing_subscriber::registry()
        .with(CapturingLayer::new(captured.clone()));

    tracing::subscriber::with_default(subscriber, || {
        let conn = Connection::<Route>::new().unwrap();
        // call something that doesn't need root
        let _ = conn.get_link_by_name("lo");
    });

    let spans = captured.lock().unwrap();
    assert!(spans.iter().any(|s| s.name == "nlink::connection::new"));
    // etc.
}
```

### 5.2. Tracing dependency removed from cargo machete

`cargo machete` should stop reporting `tracing` as unused.

### 5.3. No subscriber attached → no overhead

Benchmark: 10K `add_qdisc` calls with and without a subscriber.
Expect within ±5% (subscriber-attached overhead is the real cost,
not the macro expansion).

---

## 6. Documentation

`docs/observability.md` (new):

```markdown
# Observability with tracing

nlink instruments its public API with the `tracing` crate. To see
events, attach a subscriber:

```rust
use tracing_subscriber::EnvFilter;

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();
    // ... your nlink code ...
}
```

Then run with `RUST_LOG=nlink=debug` or more granular filters:

- `RUST_LOG=nlink::connection=info,nlink::route=debug`
- `RUST_LOG=nlink::impair=info` (just recipe operations)
- `RUST_LOG=nlink=trace` (every netlink message — verbose!)

## Span hierarchy

- INFO: connection lifecycle, recipe `apply`/`reconcile` start
- DEBUG: each public API call entry/exit
- TRACE: per-netlink-message send/recv

## Recommended minimum for production

```sh
RUST_LOG=nlink=info,my_app=info
```

Catches connection issues, recipe operations, namespace switches,
and errors without flooding logs with per-message detail.
```

`CLAUDE.md` addition: a "Debugging" section pointing at the doc.

CHANGELOG:

```markdown
### Added

- Public API is now instrumented with the `tracing` crate. Attach
  a subscriber and filter via `RUST_LOG`. See [docs/observability.md].
  Spans are emitted at INFO (lifecycle), DEBUG (per-call), and
  TRACE (per-message) levels with structured fields.
```

---

## 7. Open questions

1. **`tracing-subscriber` as a dev-dep for tests.** Yes, add to
   `[dev-dependencies]`.
2. **Default level for TRACE per-message spans.** TRACE is the right
   level (consumes ~1 event per netlink call). But this means
   `RUST_LOG=nlink=trace` is firehose. Acceptable; users opt in.
3. **Span timing.** `#[instrument]` adds an automatic enter/exit
   span; users with the `fmt` subscriber see duration on close.
   No extra work needed.
4. **Should we capture the request body size?** Yes, useful for
   "why is this dump slow" debugging. Adds one field per send
   span.
5. **Async-trait + instrument interaction.** `#[instrument]` works
   with native async fns (Rust 1.75+). We're already on edition 2024
   so this is fine.

---

## 8. Phasing

Single PR. ~600 LOC, mechanical attribute-sprinkling. Split if
needed:

- PR A: Connection-level (`connection.rs`, `genl/`) — 250 LOC
- PR B: TC + filter modules — 80 LOC
- PR C: Recipes + namespace + batch + events — 70 LOC
- PR D: Docs + tests — 200 LOC

Same release cycle. Ordering within the cycle doesn't matter.

---

## 9. Risk register

| Risk | Likelihood | Mitigation |
|---|---|---|
| Tracing macros expand to noticeable overhead under heavy load | Low | Benchmark; if real, make critical-path TRACE spans use `Span::current().is_disabled()` short-circuit |
| Span field captures expensive (e.g., formatting `&[u8]`) | Medium | Use `skip_all` + explicit fields; never include raw byte arrays |
| `RUST_LOG=trace` floods user terminal | Certain (intended) | Document the level conventions; INFO is the production default |
| Adding `#[instrument]` to async methods causes future-size bloat | Low | Modern compilers handle this; benchmark to confirm |

---

## 10. What we are NOT doing

- **No metrics.** Counters/histograms via `metrics` crate are out of
  scope.
- **No distributed tracing.** No upstream context to propagate.
- **No required subscriber setup.** Users wire it themselves.
- **No `tracing` feature flag.** Always on.

---

## 11. Definition of done

- [ ] All public Connection methods (~30) have `#[instrument]` spans
- [ ] Recipe helpers (`apply`/`reconcile`/`clear`) have INFO spans
- [ ] Namespace operations (`create`/`delete`/`spawn`) have INFO spans
- [ ] Multicast event delivery has TRACE spans
- [ ] `cargo machete` no longer flags `tracing` as unused
- [ ] `docs/observability.md` exists with subscriber setup guide
- [ ] CLAUDE.md mentions tracing under debugging
- [ ] Smoke test confirms spans are emitted
- [ ] No-subscriber benchmark within ±5% of pre-instrumentation baseline
- [ ] CHANGELOG entry written

---

End of plan.
