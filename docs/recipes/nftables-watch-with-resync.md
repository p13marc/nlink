# Watching nftables changes with ENOBUFS resilience

This recipe shows how to subscribe to nftables ruleset mutations
on the `NFNLGRP_NFTABLES` multicast group and survive `ENOBUFS`
without dropping state.

When a subscriber falls behind the kernel's event production
rate, the kernel drops messages and returns `ENOBUFS` on the
next `recvmsg`. The subscriber's incremental state is now
stale. The correct recovery is:

1. Open a *fresh* second connection (the subscribe socket has
   pending traffic that would race the snapshot — Plan 178's
   "subscribe + unicast on one socket" gotcha).
2. Re-dump the current ruleset via that connection.
3. Resume the multicast stream.

`Connection<Nftables>::into_events_with_resync(factory)` does
all of this for you. The wrapper mirrors `kube_rs::watcher` —
hand it a closure that knows how to open a fresh connection +
get an ENOBUFS-resilient `Stream<Item = Result<ResyncedEvent<NftablesEvent>>>`.

## API at a glance

```rust
use std::sync::Arc;
use nlink::netlink::{Connection, Nftables};
use nlink::netlink::nftables::NftablesEvent;
use nlink::netlink::resync::{ConnectionFactory, ResyncedEvent, ResyncMarker};
use tokio_stream::StreamExt;

#[tokio::main]
async fn main() -> nlink::Result<()> {
    // Factory: how to build a fresh Connection<Nftables>.
    // The wrapper invokes this each time it needs to re-dump.
    let factory: ConnectionFactory<Nftables> = Arc::new(|| {
        Box::pin(async { Connection::<Nftables>::new() })
    });

    // Subscribe on the subscribe socket; pass the factory for resyncs.
    let conn = Connection::<Nftables>::new()?;
    let mut events = conn.into_events_with_resync(factory)?;

    while let Some(item) = events.next().await {
        match item? {
            ResyncedEvent::Event(NftablesEvent::NewTable(t)) => {
                println!("+ table {} ({})", t.name, t.family);
            }
            ResyncedEvent::Event(NftablesEvent::DelTable(t)) => {
                println!("- table {}", t.name);
            }
            ResyncedEvent::Event(NftablesEvent::NewRule(r)) => {
                println!("+ rule in {}/{}", r.table, r.chain);
            }
            ResyncedEvent::Marker(ResyncMarker::ResyncStart) => {
                println!("== resync start ==");
                // invalidate any incremental state you've been tracking
            }
            ResyncedEvent::Resynced(ev) => {
                println!("?? snapshot: {ev:?}");
                // rebuild state from the snapshot
            }
            ResyncedEvent::Marker(ResyncMarker::ResyncEnd) => {
                println!("== resync end ==");
                // state is now consistent with kernel reality
            }
            _ => {}
        }
    }
    Ok(())
}
```

## Borrowed form when you still need the connection

`into_events_with_resync` consumes `self` — once the stream is
running, the connection is owned by it. If you need to keep the
connection around for queries (e.g. running `list_tables` ad-hoc
from the same task), use the borrowed sibling:

```rust
let mut conn = Connection::<Nftables>::new()?;
let mut events = conn.subscribe_all_with_resync(factory)?;
// `conn` is borrowed by `events` for its lifetime; drop the stream
// to recover access. The stream is NOT 'static, so it can't be
// `tokio::spawn`-ed — that's the trade-off.
```

## Namespace-aware factory

In a multi-tenant manager / CNI plugin, the factory should open
the new connection inside the same netns as the original
subscribe socket:

```rust
let netns_name = "tenant-a".to_string();
let factory: ConnectionFactory<Nftables> = Arc::new(move || {
    let ns = netns_name.clone();
    Box::pin(async move {
        nlink::netlink::namespace::connection_for(&ns)
    })
});
```

## Why a factory closure?

The wrapper needs to open a fresh socket every time it recovers
— it can't reuse the subscribe socket (pending traffic races the
snapshot read) and it can't be handed a pre-built second
connection (consumed after the first ENOBUFS, then what?).
A factory closure captures everything the wrapper needs to
re-open the connection on demand, while staying `Send + Sync +
'static` so the resulting stream spawns cleanly.

## What the snapshot enumerates

`nftables_snapshot(&conn)` walks every entity the multicast
stream emits as `NewX(...)`:

1. **Tables** — `list_tables()`
2. Per table:
   - **Chains** — `list_chains_in(&table, family)`
   - **Flowtables** — `list_flowtables_in(&table, family)`
   - **Sets** — `list_sets_in(&table, family)`
   - **Rules** — `list_rules(&table, family)`

Set elements (`NFT_MSG_NEWSETELEM`) and generation announcements
(`NFT_MSG_NEWGEN`) are out-of-scope today. Open an issue if you
need them — the wire path is straightforward, we just haven't
seen a downstream ask.

## See also

- [`events-with-resync.md`](events-with-resync.md) — the lower-level
  `events_with_resync` wrapper this recipe wraps. Useful when you
  want the same shape for non-nftables protocols (links, routes,
  conntrack, etc.).
- [`nftables-stateful-fw.md`](nftables-stateful-fw.md) — table /
  chain / rule plumbing the snapshot enumerates.
- [`nftables-declarative-config.md`](nftables-declarative-config.md) —
  declarative `NftablesConfig` + `diff` + `apply_reconcile`.
  Pairs well with this recipe: use this to watch external drift,
  use `apply_reconcile` to converge state back.
