# Events with ENOBUFS resync

How to consume multicast netlink events without losing track of
state when the kernel drops events under load.

## When to use this

- You're consuming a high-volume multicast group (link/addr/route
  events on a hyper-active host, conntrack events on a busy
  gateway, nftables-table events on a control-plane host).
- Your consumer maintains incremental state (a routing-table
  shadow, a connection-tracker mirror, a stats aggregator).
- You need that state to stay correct across periods when the
  kernel might out-pace your consumer.

If you're polling rather than subscribing, or your consumer is
stateless (just forwards events to another system), this recipe
is overkill — a plain `events.next().await` loop is enough.

## The problem

When a multicast subscriber falls behind the kernel's event
production rate, the kernel's per-socket buffer fills. On the
next `recvmsg`, the kernel returns **`ENOBUFS`** to signal "I
dropped events while you were behind — your view is now stale."

Naive responses:

- **Ignore it**: the consumer's state silently drifts from
  kernel state, often forever. The bug manifests later as
  inconsistent reporting or wrong decisions.
- **Re-subscribe**: re-subscription gives a fresh socket but no
  way to know what was missed. Same drift, just deferred.
- **Resort to polling**: defeats the point of subscription.

The correct recovery (per kernel maintainers' guidance):

1. **Re-dump current state** via the matching `get_*` method.
2. **Resume the multicast stream** from where it left off.

The re-dump is the consumer's authority — anything in the dump is
guaranteed to reflect current kernel state; anything *not* in the
dump has been deleted.

## The shape

nlink ships the types that make this pattern explicit
(`crate::netlink::resync`):

- [`ResyncedEvent<T>`][rs-event] — sum type yielded by your
  consumer's loop:
  - `Event(T)` — a real-time multicast event
  - `Resynced(T)` — a snapshot item from the post-`ENOBUFS`
    redump
  - `Marker(ResyncMarker::ResyncStart)` — cue to invalidate
    incremental state (it's now stale)
  - `Marker(ResyncMarker::ResyncEnd)` — cue that the replay is
    complete; subsequent events are real-time deltas again
- [`ResyncMarker`][rs-marker] — the two boundary variants above

**Two ways to consume the stream:**

1. **`events_with_resync(stream, snapshot_fn)` (recommended)** —
   the pre-baked wrapper that drives the state machine internally
   and yields `Result<ResyncedEvent<T>>`. Caller writes a plain
   `while let Some(item) = stream.next().await` loop. See the
   [§ "Using `events_with_resync`"](#using-events_with_resync)
   section below.
2. **Hand-rolled loop** — the explicit pattern shown immediately
   below. Useful when you want full control of the snapshot's
   lifetime / cancellation, or when the snapshot involves work
   the wrapper can't represent (multi-source fan-in, derived
   state). The wrapper internally does exactly what this loop
   does.

[rs-event]: https://docs.rs/nlink/latest/nlink/struct.ResyncedEvent.html
[rs-marker]: https://docs.rs/nlink/latest/nlink/enum.ResyncMarker.html

## Canonical loop

```rust,no_run
use nlink::{Connection, Route, ResyncedEvent, ResyncMarker};
use nlink::netlink::messages::LinkMessage;
use nlink::netlink::stream::EventSubscription;
use tokio_stream::StreamExt;

# async fn consume(
#     mut events: EventSubscription<'_, Route>,
#     dump_conn: &Connection<Route>,
# ) -> nlink::Result<()> {
let mut state: std::collections::HashMap<u32, String> = Default::default();

loop {
    match events.next().await {
        // Real-time event: apply incrementally.
        Some(Ok(ev)) => apply(&mut state, ResyncedEvent::Event(ev)),

        // ENOBUFS: kernel dropped events; re-dump.
        Some(Err(e)) if e.is_no_buffer_space() => {
            tracing::warn!("multicast overflow; resyncing");
            apply(&mut state, ResyncedEvent::Marker(ResyncMarker::ResyncStart));

            // Invalidate any state we'd accumulated — the resync
            // is now authoritative.
            state.clear();

            // Dump current kernel state through a SECOND
            // connection (the events connection is mid-stream).
            // The dump connection can come from a ConnectionPool
            // (Plan 159) so we don't have to manage a second
            // socket by hand.
            for link in dump_conn.get_links().await? {
                apply(&mut state, ResyncedEvent::Resynced(link));
            }

            apply(&mut state, ResyncedEvent::Marker(ResyncMarker::ResyncEnd));
            tracing::info!("resync complete; resuming");
        }

        // Real error: propagate.
        Some(Err(other)) => return Err(other),

        // Stream ended (Connection dropped, etc.).
        None => return Ok(()),
    }
}

# fn apply(s: &mut std::collections::HashMap<u32, String>, ev: ResyncedEvent<nlink::netlink::link::LinkMessage>) { let _ = (s, ev); }
# }
```

The `apply` function processes one item; it dispatches on
`ResyncedEvent` variants so the consumer can distinguish replay
items from real-time deltas if it cares (sometimes the
distinction matters for downstream metrics).

## Using `events_with_resync`

The pre-baked wrapper produces the same `ResyncedEvent<T>` stream
the hand-rolled loop above synthesizes, but drives the state
machine inside a `Stream` impl so your consumer is a plain
`while let Some(item) = stream.next().await` loop.

```rust,no_run
use std::pin::Pin;
use std::sync::Arc;
use nlink::netlink::resync::events_with_resync;
use nlink::{ConnectionPool, Connection, Route, ResyncedEvent, ResyncMarker};
use nlink::netlink::messages::LinkMessage;
use tokio_stream::StreamExt;

# async fn run() -> nlink::Result<()> {
let events_conn: Connection<Route> = Connection::<Route>::new()?;
let dump_pool: Arc<ConnectionPool<Route>> =
    Arc::new(ConnectionPool::<Route>::for_namespace("myns", 2).await?);

let live = events_conn.subscribe_links().await?;

let snapshot_pool = Arc::clone(&dump_pool);
let stream = events_with_resync(live, move || {
    let pool = Arc::clone(&snapshot_pool);
    Box::pin(async move {
        let conn = pool.acquire().await?;
        conn.get_links().await
    }) as Pin<Box<_>>
});
tokio::pin!(stream);

while let Some(item) = stream.next().await {
    match item? {
        ResyncedEvent::Event(_)    => { /* live event */ }
        ResyncedEvent::Resynced(_) => { /* replayed from snapshot */ }
        ResyncedEvent::Marker(ResyncMarker::ResyncStart) => { /* invalidate state */ }
        ResyncedEvent::Marker(ResyncMarker::ResyncEnd)   => { /* state rebuilt */ }
    }
}
# Ok(()) }
```

Notes:

- The snapshot future is built fresh on every ENOBUFS — supply a
  closure that calls `pool.acquire().await?` (not a captured
  guard) so each resync gets a clean connection.
- The wrapper fuses the stream on snapshot failure or non-ENOBUFS
  error; downstream `next()` calls return `None` after the
  fault. This matches the hand-rolled loop's behaviour.
- Use the hand-rolled loop when the snapshot's lifecycle needs
  extra control (cancellation, multi-source fan-in, derived
  state); the wrapper covers the common case.

## Using `ConnectionPool` for the dump connection

The dump connection needs to be **separate** from the events
connection — the latter is mid-stream and can't service a dump
request without races. The canonical source of a clean dump
connection is the per-namespace pool from
[`connection-pool.md`](connection-pool.md):

```rust,no_run
use std::sync::Arc;
use nlink::{ConnectionPool, Route};

# async fn run() -> nlink::Result<()> {
let pool: Arc<ConnectionPool<Route>> = Arc::new(
    ConnectionPool::<Route>::for_namespace("myns", 2).await?
);

// Events connection — bound to the same netns.
let events_conn: nlink::Connection<Route> =
    nlink::netlink::namespace::connection_for("myns")?;
// ... subscribe ...

// Dump connection from the pool — taken fresh on each resync.
// The lifetime is just for the duration of the resync; drop
// returns to the pool.
let dump_conn = pool.acquire().await?;
// ... call dump_conn.get_links() inside the resync arm ...
# Ok(())
# }
```

The pool also lets you parallelize the dump if it's slow on
1M-route hosts (one pool acquire per dump task).

## Sizing the kernel-side buffer

The most reliable way to make ENOBUFS rare is to **make the
kernel socket buffer bigger** so transient bursts don't overflow:

```rust,no_run
# fn run() -> nlink::Result<()> {
// On supported kernels (most): sysctl net.core.rmem_max controls
// the upper bound. Set the per-socket buffer at construction or
// via the existing socket APIs:
//
// SO_RCVBUF      — clamped to rmem_max
// SO_RCVBUFFORCE — bypasses the clamp; needs CAP_NET_ADMIN
//
// nlink doesn't expose these directly yet; if you need them, drop
// to libc::setsockopt against conn.socket().as_raw_fd().
# Ok(())
# }
```

A typical telco / hyperscale shape is `SO_RCVBUF = 16 MiB` so a
multi-second consumer hiccup doesn't drop events.

## When NOT to use this

- Low-volume event consumers (link state on a single-interface
  host, sporadic conntrack on a quiet edge box) can treat
  `ENOBUFS` as a hard error and bubble up. The kernel will only
  return ENOBUFS if you've actually fallen behind; in steady
  state it's rare.
- Stateless consumers that just shove events into a queue for
  someone else don't need resync — the downstream system has
  its own truth.

## See also

- [`connection-pool.md`](connection-pool.md) — `dump_conn` for
  the resync arm
- [`error-handling-patterns.md`](error-handling-patterns.md) —
  the broader `is_no_buffer_space` / `is_try_again` predicate
  story
- [`crate::netlink::resync`][resync-mod] — module docs
- [Plan 151][plan-151] — design history; the pre-baked wrapper
  shipped in the 2026-05-25 pre-cut audit window

[resync-mod]: https://docs.rs/nlink/latest/nlink/netlink/resync/index.html
[plan-151]: ../../plans/151-0.16-enobufs-resync-plan.md
