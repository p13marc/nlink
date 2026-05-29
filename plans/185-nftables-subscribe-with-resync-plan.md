---
to: nlink maintainers
from: nlink-lab upstream-asks report (2026-05-27) §Wishlist 2 + Plan 185 implementation scope finding (2026-05-29) + ecosystem research (2026-05-30) + backcompat-freedom revision (2026-05-30)
subject: `Connection<Nftables>::{into_events_with_resync, subscribe_all_with_resync}(factory)` — kube-rs-shaped watcher with built-in ENOBUFS recovery, both owned + borrowed forms
status: **revised again 2026-05-30** — maintainer authorized breaking changes; lifetime-generic `events_with_resync` refactor + bundled `NftablesEvent::NewSet` parsing now in scope
target version: 0.18.0
parent: (none — single-deliverable plan)
source: nlink-lab maintainer report §Wishlist 2; ecosystem audit; maintainer backcompat-freedom directive
created: 2026-05-27 (rewritten 2026-05-30; expanded 2026-05-30)
---

# Plan 185 — `into_events_with_resync` for nftables

## 1. Why this plan exists

`events_with_resync(stream, snapshot_fn)` already exists at
`nlink::events_with_resync` (Plan 151 closeout, 0.16). It
takes a `Stream<Item = Result<T>>` and a snapshot closure,
handles `ENOBUFS` recovery, returns
`Stream<Item = Result<ResyncedEvent<T>>>`.

The snapshot closure is the boilerplate. For nftables, every
caller writes substantially the same code: dump tables → for
each table dump chains/rules/flowtables → synthesize
`NewTable/NewChain/NewRule/NewFlowtable` events.

nlink-lab specifically wants this for Plan 158d's per-namespace
nftables watch (ENOBUFS-resilient firewall-change monitoring).
The original report estimated ~60 LOC per namespace shrinking
to ~5 with a bundled API; any controller doing "watch nftables
across many namespaces" wants the same.

## 2. What the first-cut implementation revealed

Started implementing `subscribe_all_with_resync(&mut self)`
per the original plan and hit a fundamental constraint:

- `Connection<P>::events()` returns `EventSubscription<'_, P>` —
  borrows `&self`.
- `events_with_resync<S, T, F>` requires
  `F: FnMut() -> Pin<Box<dyn Future<Output = Result<Vec<T>>> + Send>> + Unpin`
  — the `dyn Future + Send` defaults to `'static`, so the
  closure can't capture borrows of self.
- The borrowed event stream and the `'static`-requiring resync
  closure don't compose without one of:
  - **(A)** Refactoring `events_with_resync` to be lifetime-
    generic — `Pin<Box<dyn Future + Send + 'a>>` + an `'a`
    parameter threaded through the wrapper.
  - **(B)** Consuming self via `into_events()` (already exists,
    returns `'static + Send`) and providing a factory closure
    for snapshot connections.
  - **(C)** Reimplementing the resync state machine inline
    inside `subscribe_all_with_resync`, bypassing
    `events_with_resync` entirely.

## 3. Research — what the ecosystem does

Audited the canonical Rust + Linux precedents for "watch a
stream + on overflow do full re-sync":

### kube-rs `watcher` — exact-shape match

```rust
pub fn watcher<K: ... + 'static>(api: Api<K>, cfg: Config)
    -> impl Stream<Item = Result<Event<K>>> + Send
```

Three relevant decisions:

1. **`Api<K>` consumed by value, not borrowed.** Returned
   stream is `'static + Send`. `Api<K>` is `Clone` (an
   `Arc<Client>` under the hood); the "factory" is just
   `api.clone()` captured in the relist closure. The borrowed-
   `&Api` shape was tried early and rejected — it doesn't
   compose with `tokio::spawn`, `StreamMap::merge`, the
   reflector store, or controllers.
2. **Relist is built into the watcher state machine, not a
   separate combinator.** Users never wire a snapshot closure
   themselves. They receive `Event::Init` / `Event::InitApply(K)`
   / `Event::InitDone` markers — literally the same shape as
   nlink's `ResyncMarker::ResyncStart` / `Resynced(T)` /
   `ResyncEnd`. We're already aligned.
3. **History — `Event::Restarted(Vec<K>)` got refactored to the
   streaming `Init/InitApply/InitDone` form** that nlink
   already shipped via Plan 151's `Vec<T>`-then-marker design.
   Same conclusion, independently reached.

### `into_*` consumption pattern across the ecosystem

`tokio::net::UnixListener::into_std`,
`hyper::Body::into_data_stream`,
`reqwest::Response::bytes_stream` (consuming `self`),
every type in `tokio_stream::wrappers` — all primary forms
take by value when a long-lived async pipeline is the intent.
Borrowed-`&self` views exist for quick-poll convenience. The
existing `nlink::Connection::into_events()` already follows
this; the resync wrapper should sit beside `into_events`, not
`events`.

### libnl / libmnl / nft monitor — kernel-side precedent

The C side (libnl-3, libnftnl, nftables `src/monitor.c`)
unanimously opens a **separate socket** for the post-ENOBUFS
re-dump, never the multicast socket. Reusing the event socket
for the snapshot interleaves multicast frames into your dump
— the same subscribe + unicast race Plan 178 fixed in the lib.
The factory-closure shape isn't just convenient; it's the only
correct shape under the kernel's behavior.

### Factory-closure patterns

bb8 / deadpool / r2d2 use a `ManageConnection` trait with
`async fn connect`. That's overkill for a single-use snapshot
factory. For a single closure inside one stream, the
idiomatic minimal form (used internally by kube-rs's `Api`
re-list path) is:

```rust
Arc<dyn Fn() -> BoxFuture<'static, Result<Connection<P>>> + Send + Sync>
```

`Arc` gives cheap clones across closure re-invocations.

## 4. The change — Option B, kube-rs-shaped

### 4.1 Public type alias

```rust
// crates/nlink/src/netlink/nftables/resync.rs (new file)

use futures::future::BoxFuture;
use std::sync::Arc;

/// A factory that opens fresh `Connection<P>` on demand. Used
/// by [`Connection::into_events_with_resync`] to materialize a
/// snapshot connection during `ENOBUFS` recovery without racing
/// the multicast event socket (see Plan 178 — kernel
/// interleaves multicast frames into a unicast dump on a
/// subscribed socket).
///
/// `Arc`-wrapped for cheap cloning across closure
/// re-invocations on every resync event.
pub type ConnectionFactory<P> =
    Arc<
        dyn Fn() -> BoxFuture<'static, Result<Connection<P>>>
            + Send
            + Sync,
    >;
```

### 4.2 Public snapshot helper

```rust
// crates/nlink/src/netlink/nftables/resync.rs

/// Walk the entire nftables state on a fresh `Connection<Nftables>`,
/// emitting one `NftablesEvent::New*` per existing entity in
/// canonical create-order:
/// `NewTable` → (per-table) `NewChain` → `NewRule` →
/// `NewFlowtable`.
///
/// Sets are not currently surfaced — see the in-tree
/// `nftables/events.rs` parser, which drops `NFT_MSG_NEWSET`
/// from the live multicast stream. Adding `NewSet(SetInfo)` is
/// a follow-up; the snapshot must mirror the live-event shape
/// exactly so consumers can't tell a "Resynced" entity apart
/// from a real "Event".
///
/// Used internally by [`Connection::into_events_with_resync`];
/// exposed as `pub` so callers writing their own
/// `events_with_resync` wrappers can re-use it.
pub async fn nftables_snapshot(
    conn: &Connection<Nftables>,
) -> Result<Vec<NftablesEvent>> {
    let mut out = Vec::new();
    let tables = conn.list_tables().await?;
    for t in &tables {
        out.push(NftablesEvent::NewTable(t.clone()));
        for chain in conn.list_chains_in(&t.name, t.family).await? {
            out.push(NftablesEvent::NewChain(chain));
        }
        for rule in conn.list_rules(&t.name, t.family).await? {
            out.push(NftablesEvent::NewRule(rule));
        }
        for ft in conn.list_flowtables_in(&t.name, t.family).await? {
            out.push(NftablesEvent::NewFlowtable(ft));
        }
    }
    Ok(out)
}
```

### 4.3 The primary form — `into_events_with_resync`

```rust
impl Connection<Nftables> {
    /// Consume `self`, subscribe to the nftables multicast
    /// group, and return a stream that auto-recovers from
    /// `ENOBUFS` overflow by re-dumping current state from a
    /// freshly-opened connection.
    ///
    /// `factory` is called on every overflow to open a new
    /// `Connection<Nftables>` for the snapshot dump. **Must NOT
    /// return the same socket as the multicast stream** —
    /// reusing the event socket interleaves multicast frames
    /// into the dump (Plan 178 race). Typically:
    ///
    /// ```ignore
    /// use std::sync::Arc;
    /// use nlink::netlink::{Connection, Nftables};
    /// use nlink::netlink::namespace;
    ///
    /// let ns_name = "ns-foo".to_string();
    /// let factory = Arc::new(move || {
    ///     let n = ns_name.clone();
    ///     Box::pin(async move {
    ///         namespace::connection_for_async::<Nftables>(&n).await
    ///     }) as _
    /// });
    ///
    /// let event_conn = namespace::connection_for_async::<Nftables>(&ns_name).await?;
    /// let stream = event_conn.into_events_with_resync(factory)?;
    /// while let Some(evt) = stream.next().await {
    ///     // ResyncedEvent::Event(NftablesEvent::NewTable(...))
    ///     // ResyncedEvent::Marker(ResyncMarker::ResyncStart)
    ///     // ResyncedEvent::Resynced(NftablesEvent::NewTable(...))
    ///     // ResyncedEvent::Marker(ResyncMarker::ResyncEnd)
    ///     // ResyncedEvent::Event(...)  ← live again
    /// }
    /// ```
    ///
    /// The returned stream is `Send + 'static` — directly
    /// `tokio::spawn`-able, mergeable in a `StreamMap` for
    /// multi-namespace fan-out, etc. (this is why we consume
    /// `self`: a borrowed-stream form does not compose with
    /// `spawn`).
    ///
    /// Mirrors the kube-rs `watcher(api, cfg) -> Stream<Event<K>>`
    /// shape — `Api<K>` consumed by value, relist-on-failure
    /// internal.
    pub fn into_events_with_resync(
        mut self,
        factory: ConnectionFactory<Nftables>,
    ) -> Result<
        impl Stream<Item = Result<ResyncedEvent<NftablesEvent>>>
            + Send
            + 'static,
    > {
        self.subscribe_all()?;
        let events = self.into_events();
        Ok(events_with_resync(events, move || {
            let f = factory.clone();
            Box::pin(async move {
                let conn = f().await?;
                nftables_snapshot(&conn).await
            })
        }))
    }
}
```

### 4.4 The borrowed-convenience form — `subscribe_all_with_resync`

For quick demos / one-shot scripts that don't need
`tokio::spawn`:

```rust
impl Connection<Nftables> {
    /// Borrowed-stream variant of
    /// [`Self::into_events_with_resync`]. Returns a stream
    /// scoped to `&mut self`'s borrow — **not**
    /// `tokio::spawn`-able. For long-lived per-namespace
    /// watches use `into_events_with_resync` instead.
    ///
    /// Convenient for quick interactive scripts where you
    /// want to subscribe + re-query the same connection later
    /// (e.g. for unicast queries) — though see Plan 178: the
    /// subscribe+unicast race makes that pattern fragile.
    pub fn subscribe_all_with_resync<'a>(
        &'a mut self,
        factory: ConnectionFactory<Nftables>,
    ) -> Result<
        impl Stream<Item = Result<ResyncedEvent<NftablesEvent>>>
            + Send
            + 'a,
    > {
        self.subscribe_all()?;
        let events = self.events();
        // Same factory pattern; the only difference is the
        // returned stream's lifetime.
        Ok(events_with_resync(events, move || {
            let f = factory.clone();
            Box::pin(async move {
                let conn = f().await?;
                nftables_snapshot(&conn).await
            })
        }))
    }
}
```

⚠ The borrowed form requires `events_with_resync` to be
lifetime-generic. If that refactor is too invasive (see §5),
ship `into_events_with_resync` only and document the borrowed
form as the explicit deferred follow-up. nlink-lab's per-
namespace fan-out is the actual use case, and that needs
`'static` anyway.

## 5. Sub-decision: lifetime-generic refactor — now in scope

**Revised 2026-05-30**: maintainer authorized breaking
changes for 0.18. The lifetime-generic refactor that was
previously "invasive and out-of-scope" is now a clean,
cheap internal change.

The bound on `events_with_resync`'s resync closure changes
from:

```rust
F: FnMut() -> Pin<Box<dyn Future<Output = ...> + Send>> + Unpin
//                                              ↑ implicitly 'static
```

…to:

```rust
F: FnMut() -> Pin<Box<dyn Future<Output = ...> + Send + 'a>> + Unpin
//                                              ↑ explicit 'a
```

Existing callers (using `'static` futures) keep compiling
because `'static: 'a` for any `'a`. The semver gate stays
shut for 99% of downstream code; the explicit lifetime is
visible only to callers who want the borrowed form.

**Both forms now ship**:
- `into_events_with_resync(self, factory) -> impl Stream + Send + 'static`
  — primary, spawn-able + `StreamMap`-mergeable.
- `subscribe_all_with_resync(&mut self, factory) -> impl Stream + Send + '_`
  — borrowed convenience for quick demos. Not spawn-able,
  but useful for in-task watch loops where the connection is
  also doing unicast queries (with the Plan 178 race risk
  understood).

Why ship both: zero-marginal-cost once the refactor lands;
the kube-rs precedent rejected the borrowed form as
*primary*, not as a secondary option. Some consumers will
want the borrowed form for short-lived interactive scripts.

## 6. Tests

### 6.1 Unit — snapshot canonical order

In `crates/nlink/src/netlink/nftables/resync.rs`:

```rust
// Using a mock Connection or hitting a namespace (this test
// won't be unit-pure if it needs root).
#[test]
fn nftables_snapshot_order_is_table_chain_rule_flowtable() {
    // Build a known config, dump it, assert event ordering.
}
```

### 6.2 Integration — root-gated ENOBUFS recovery

```rust
#[tokio::test(flavor = "multi_thread")]
async fn into_events_with_resync_recovers_from_enobufs() {
    nlink::require_root!();
    nlink::require_modules!("nf_tables");

    let ns = TestNamespace::new("resync-enobufs")?;

    // 1. Set up a known nft config: 1 table + 1 chain + N rules.
    // 2. Open `event_conn = namespace::connection_for_async(ns)`.
    // 3. Build factory: `Arc::new(move || ... open new conn in same ns)`.
    // 4. `stream = event_conn.into_events_with_resync(factory)?;`
    // 5. Force ENOBUFS: from a *different* connection, flood the
    //    kernel with rule add/delete in a tight loop while the
    //    consumer is slow.
    // 6. Assert the stream sees:
    //    - Some Event(_) frames (live events from before overflow)
    //    - Marker(ResyncStart)
    //    - One Resynced(_) per entity (table, chain, rules,
    //      flowtables) in canonical create-order
    //    - Marker(ResyncEnd)
    //    - Live events resume
    // 7. Assert idempotence: no NewTable for the same table
    //    appears twice in the Resynced section.
}
```

The "force ENOBUFS reliably" technique is the same as the
existing `resync::tests::*` from Plan 151. Cross-reference.

### 6.3 Unit — factory closure clone semantics

```rust
#[test]
fn factory_arc_clones_on_each_resync_call() {
    // Build a factory backed by an AtomicUsize counter.
    // Wire it through into_events_with_resync (with a mock
    // event stream that emits ENOBUFS twice).
    // Assert the counter is == 2 (factory was invoked exactly
    // once per ENOBUFS).
}
```

## 7. Acceptance criteria

- [ ] `ConnectionFactory<P>` type alias exists at the crate
      root + re-exported from `nlink::netlink::nftables`.
- [ ] `pub async fn nftables_snapshot(&Connection<Nftables>)
      -> Result<Vec<NftablesEvent>>` exists in the new
      `nftables/resync.rs` module + re-exported.
- [ ] `Connection<Nftables>::into_events_with_resync(self,
      factory) -> impl Stream<...> + Send + 'static` exists.
- [ ] Returned stream is `tokio::spawn`-able (compile-test
      `tokio::spawn(stream.for_each(...))`).
- [ ] Integration test exercises ENOBUFS recovery under root.
- [ ] Recipe at `docs/recipes/nftables-watch-with-resync.md`
      walks a downstream consumer through the per-namespace
      pattern (literal kube-rs `watcher` shape recap so users
      coming from k8s immediately recognize it).
- [ ] CHANGELOG `### Added` entry.

## 8. Effort estimate (revised 2026-05-30)

| Phase | Effort |
|---|---|
| Refactor `events_with_resync` to lifetime-generic `'a` | ~45 min |
| `nftables/resync.rs` module + `nftables_snapshot` + `ConnectionFactory` | ~45 min |
| `into_events_with_resync` impl | ~30 min |
| `subscribe_all_with_resync` impl (borrowed form) | ~30 min |
| Add `NftablesEvent::{NewSet, DelSet}` + parser wiring | ~45 min |
| Unit tests (factory clone semantics, snapshot ordering) | ~45 min |
| Integration test (ENOBUFS recovery — both forms) | ~2 h |
| Recipe + CHANGELOG | ~30 min |
| **Total** | **~5 – 5.5 h** |

Up from ~3.5 h to absorb the lifetime-generic refactor + the
NEWSET parsing bundle + the borrowed form. Trade-off:
slightly higher up-front cost, but downstream consumers get
a complete API surface in one cycle instead of three.

## 9. Risks

- **`NftablesEvent::NewSet` parsing — now bundled into this
  plan (2026-05-30 revision).** Previously deferred to avoid
  asymmetry between snapshot and live stream. With backcompat
  freedom for 0.18, NEWSET + DELSET parsing on the live side
  is in scope too:
  - Add `NewSet(SetInfo)` + `DelSet(SetInfo)` to
    `NftablesEvent` enum.
  - Wire `NFT_MSG_NEWSET` / `NFT_MSG_DELSET` handling in
    `nftables/events.rs::parse_nftables_event`.
  - Snapshot emits `NewSet(...)` per `list_sets_in(table, family)`
    result during the snapshot walk (Plan 181 prereq is
    satisfied).
  - Removes the asymmetry; consumers see a symmetric snapshot/
    live shape across all 5 entity kinds.

- **ENOBUFS integration test is timing-sensitive across kernel
  versions** — same risk Plan 151's existing tests already
  manage. Cross-reference their flood-loop technique.

- **Factory-closure ergonomics for cross-namespace use**:
  callers who watch many namespaces want one factory per
  watcher. The `Arc<dyn Fn ...>` shape is fine but verbose.
  Consider shipping a convenience `Connection::resync_factory(ns_name)`
  builder in a follow-up — out of scope for 0.18.0.

## 10. Out-of-scope follow-ups

- **Same pattern for `Connection<Netfilter>` (conntrack)** —
  add `conntrack_snapshot` + `into_events_with_resync` on
  `Connection<Netfilter>`. Trivial port once the nftables
  shape is shipped.
- **Same pattern for `Connection<Route>`** — link/addr/route/
  qdisc snapshot is more involved (many entity kinds, ordering
  matters: link before addr before route). Separate plan.
- **`SnapshotResync` trait on `Connection<P>` for any P** —
  factor out once 3+ protocols have concrete implementations.
  Trait shape only becomes clear with 3 data points.
- **Convenience `Connection::resync_factory(ns_name)`
  builder** — reduces the `Arc<dyn Fn ...>` ceremony for the
  common per-namespace case. Defer until ergonomic pain is
  measured in practice.

## 11. Why this design is the right call

The decision matrix from the research, condensed:

| Approach | tokio::spawn | StreamMap merge | Lifetime puzzle | Implementation cost | Ecosystem precedent |
|---|:-:|:-:|:-:|:-:|:-:|
| **B — `into_events_with_resync` (this plan)** | ✅ | ✅ | sidestepped | low | **kube-rs `watcher` exact match** |
| A — lifetime-generic `events_with_resync` | ✅ (after refactor) | ✅ (after refactor) | solved by deep refactor | high (touches shipped API) | none |
| C — inline state machine | ✅ | ✅ | sidestepped | medium-high | none (every protocol re-implements) |

Plus: B honors the kernel's "fresh socket for snapshot" rule
structurally (the factory closure literally cannot reuse the
event socket — it has to open a new connection). A and C
require runtime discipline to avoid the Plan 178 race.

References:
- [kube-runtime `watcher`](https://docs.rs/kube-runtime/latest/kube_runtime/watcher/fn.watcher.html)
- [kube-runtime `Event` enum](https://docs.rs/kube-runtime/latest/kube_runtime/watcher/enum.Event.html)
- [`tokio_stream::wrappers`](https://docs.rs/tokio-stream/latest/tokio_stream/wrappers/index.html)
  — convention for "wrap-by-value" stream adapters
- nftables `src/monitor.c` — kernel-side ENOBUFS-on-multicast
  precedent (separate socket for redump)

End of plan.
