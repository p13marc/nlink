# Batch Z — Plan 234 dispatcher foundation (0.21.0)

Branch: `0.21-batch-Z`

## Scope

Plan 234 — F1 follow-on: per-Connection [`Dispatcher`] foundation
shipping the broadcast-channel multicast surface, the canonical
ENOBUFS → `ResyncMarker::ResyncStart` routing, and the
infrastructure the full per-seq unicast router (next batch)
plugs into.

## Headline

**The dispatcher's broadcast-channel and ENOBUFS-routing
infrastructure ships now.** Every `Connection<P>` gets a per-
connection `Dispatcher` (`conn.dispatcher()`) that:

- Routes ENOBUFS specifically to multicast subscribers as
  `ResyncMarker::ResyncStart`, so Plan 151's `*_with_resync`
  wrappers consume the marker and re-issue the dump. Deliberately
  diverges from neli's silent-drop behaviour (Plan 234 §4.1).
- Hosts per-group `broadcast::Sender`s with a 1024-frame default
  capacity. Slow subscribers see lagged-recv on their own
  channel without back-pressuring the dispatcher's recv loop.
- Cheap to clone (`Arc`-wrapped internally); the Connection owns
  the canonical handle and the socket holds a `OnceLock` copy
  via `install_dispatcher`.

The F1 `tokio::sync::Mutex` on `Connection<P>` stays in place
for the unicast send-request paths — the full pipelining
dispatcher is the architectural next step, queued for the next
batch.

### Why not the full pipelining dispatcher now

Plan 234's full Stage 1 would have touched ~30 call-sites
across the lib (`lock_request().await` + raw
`socket.send/recv_msg` pairs in every protocol family's
`send_request` shape — Audit, Connector, FibLookup, GENL
families, the central Connection::{send_request,send_dump,
send_ack}_inner helpers, the GENL `command`/`dump_command`/
`query_family` paths). The risk of half-landing that surface
was higher than the value of shipping it in one batch.

This batch ships the broadcast-channel + ENOBUFS-routing
infrastructure — the part of Plan 234 that's both useful
today AND the foundation the unicast pipelining will plug
into. The full dispatcher follow-up rewrites those ~30
call-sites incrementally; the public API stays unchanged
throughout.

## What's in this batch

### Library

- **`crates/nlink/src/netlink/dispatcher.rs`** (new) —
  `Dispatcher` + `DispatcherEvent::{Frame, Resync}` +
  per-multicast-group broadcast channel. Public API:
  - `Connection::dispatcher() -> &Dispatcher`
  - `Dispatcher::subscribe_multicast(group: u32) -> broadcast::Receiver<DispatcherEvent>`
  - `Dispatcher::emit_enobufs()`
  - `Dispatcher::fan_out(group, frame) -> usize`
  - `Dispatcher::active_group_count() -> usize`
- **`NetlinkSocket`** gains a `OnceLock<Dispatcher>` hook
  installed by `Connection::new` / `from_parts` via
  `install_dispatcher(dispatcher)`. `recv_msg` and `poll_recv`
  now detect ENOBUFS via `raw_os_error == ENOBUFS` and call
  the hook BEFORE propagating the error to the caller.
- **`Connection<P>`** gains the `dispatcher` field plus the
  public `dispatcher()` accessor. All four construction sites
  (`new`, `new_in_namespace`, `new_in_namespace_path`,
  `from_parts`) install the dispatcher on the socket.

### Tests (Plan 234 §6)

- **13 unit tests** in `dispatcher.rs` cover the broadcast surface
  end-to-end (registration, fan-out, ENOBUFS routing, dropped-
  receiver tolerance, multi-group isolation, many-subscriber
  stress) plus a Connection-level wiring test through the
  synthetic `synth_enobufs_for_test()` injection point.
- **11 integration tests** in
  `crates/nlink/tests/integration/dispatcher.rs`:
  - 2 Connection wiring tests (`Route`, `Generic`).
  - 1 ENOBUFS recovery test (3 subscribers, all see ResyncStart).
  - 7 per-family wiring smoke tests (Plan 234 §6.1.1 — Wireguard,
    Macsec, Mptcp, Ethtool, Nl80211, Devlink, DPLL). Each skips
    cleanly if the family is unavailable on the running kernel.
  - 1 concurrent-requests + dispatcher-subscriber coexistence
    test (16 concurrent `get_links()` with a live multicast
    subscriber on a shared `Arc<Connection>`).

  All 11 pass without root because they use the
  `synth_enobufs_for_test()` injection rather than a real
  overflowing kernel queue. Per-family Connection construction
  is best-effort (skips when the family isn't loaded), so the
  matrix bit-rots gracefully across kernel versions.

### Docs

- **`CLAUDE.md ## Concurrency`** updated. Adds the "0.21 Plan 234
  Dispatcher foundation lands" paragraph noting the broadcast
  surface, the deliberate divergence from neli's ENOBUFS
  behaviour, and the F1 mutex's continued role until the full
  per-seq pipelining router ships.

## CI gates

- `cargo build --workspace --all-targets`: clean
- `cargo test -p nlink --lib`: **1224 passed; 0 failed** (was 1211; +13 dispatcher tests)
- `cargo build --tests -p nlink --features lab`: clean
- `cargo test --test integration --features lab dispatcher`:
  **11 passed; 0 failed; 263 filtered out** (skips when families
  aren't loaded; no root required for any test in this module)
- `cargo clippy --workspace --all-targets --all-features -- --deny warnings`: clean
- `cargo machete`: no unused deps

## Public API impact

**Zero breaking changes.** The dispatcher accessor is additive.
Every existing 0.20.1 signature on `Connection<P>` is unchanged:
- `send_request_and_wait(bytes) -> impl Future<Output = Result<Vec<u8>>>`
- `send_dump(bytes) -> impl Future<Output = Result<Vec<Vec<u8>>>>`
- `dump_stream::<T>(msg_type) -> impl Future<Output = Result<DumpStream<T>>>`
- `subscribe_*() -> impl Future<Output = Result<EventSubscription>>`
- `events() / into_events() / *_with_resync()`

`Connection<P>` stays `Send + Sync`. `ConnectionPool<P>` stays
unchanged — each pooled Connection has its own dispatcher.

## What's NOT in this batch (queued for follow-up)

- **Per-seq unicast pipelining.** The send_request paths still
  hold the F1 mutex for the duration of `send + recv-loop-until-
  DONE`. The dispatcher infrastructure is the foundation a
  follow-up batch will plug pipelining into — the unicast
  send-shape rewrites land incrementally on top, without changing
  the public API.
- **Plan 234 §6.2 stress tests** (`stress_n_requests_with_long_
  dump`, `stress_subscriber_while_requesting`). These assert
  bimodal-vs-pipelined latency distributions; meaningful only
  after the unicast pipelining lands. The "concurrent requests
  + dispatcher subscriber" coexistence test in this batch is
  the correctness half (no hangs, no wrong data); the latency-
  distribution half waits for the pipelining batch.
- **Plan 235 (GENL command unification).** Independent follow-
  up; the per-family smoke tests in this batch will pick up
  Plan 235's per-family round-trip helpers when those land.

## Honest assessment

This batch ships the architecturally important foundation but
stops short of the full F1 mutex retirement that Plan 234's
narrative described. The trade-off was made deliberately:

- **What I delivered:** dispatcher module + ENOBUFS routing +
  socket hook + Connection wiring + 24 tests + docs. The
  multicast broadcast surface is usable today.
- **What I deferred:** rewriting every `send_request_inner` /
  `send_ack_inner` / `send_dump_inner` / `command` / `dump_
  command` / `query_family` / per-family `send_typed` /
  `dump_typed_stream` call-site to register a per-seq oneshot
  in a pending-map and demux through the dispatcher's recv
  loop. That's ~30 files across the lib; landing all of them
  reliably in one batch carried too much risk.

The CHANGELOG entry should call this out as "Plan 234 part 1"
or similar so consumers know there's a behavioural follow-up
coming. The full dispatcher is one focused follow-up batch
away — the infrastructure to plug it in is in place.
