# Multi-Namespace Event Monitoring

How to watch link / address / route / TC events across N network
namespaces concurrently, with each event tagged by its source
namespace.

## When to use this

Use this pattern when you have an agent or operator that needs to
observe activity in more than one namespace — container-host control
planes, lab orchestrators, multi-tenant observability daemons.

Don't use it when:

- A single namespace is enough — one `Connection::events()` subscription
  is simpler.
- You only need a point-in-time view — run `conn.get_links()` /
  `get_addresses()` etc. in each namespace instead of subscribing to
  multicast.

## High-level approach

`Connection::<Route>::subscribe(...)` registers interest in specific
rtnetlink multicast groups. `Connection::into_events()` hands back an
`OwnedEventStream<Route>` that implements `Stream`.
[`tokio_stream::StreamMap`][streammap] merges multiple named streams
into a single `Stream<Item = (K, Self::Item)>` where `K` is your
chosen key — here, the namespace name.

[streammap]: https://docs.rs/tokio-stream/latest/tokio_stream/struct.StreamMap.html

```text
    ┌──────────────────┐      ┌──────────────────┐      ┌──────────────────┐
    │ ns: default       │      │ ns: tenant-a     │      │ ns: tenant-b     │
    │ Connection<Route> │      │ Connection<Route>│      │ Connection<Route>│
    │ .subscribe_all()  │      │ .subscribe_all() │      │ .subscribe_all() │
    │ .into_events()    │      │ .into_events()   │      │ .into_events()   │
    └────────┬──────────┘      └────────┬─────────┘      └────────┬─────────┘
             │                          │                         │
             └──────────┬───────────────┴─────────────────────────┘
                        │
                        ▼
                 ┌────────────────┐
                 │   StreamMap    │
                 │   keyed by     │
                 │   namespace    │
                 └────────┬───────┘
                          │ while let Some((ns, evt)) = streams.next().await { ... }
                          ▼
                   (your event loop)
```

## Code

```no_run
# async fn demo() -> nlink::Result<()> {
use nlink::netlink::{
    Connection, NetworkEvent, Route, RtnetlinkGroup, namespace,
};
use tokio_stream::{StreamExt, StreamMap};

// Open one subscribed connection per namespace. Each connection lives
// in its own FD so they don't share a socket buffer.
let mut streams = StreamMap::new();

// Default (host) namespace.
let mut host = Connection::<Route>::new()?;
host.subscribe_all()?;
streams.insert("default".to_string(), host.into_events());

// Two named namespaces (assumed to exist — `ip netns add tenant-a / tenant-b`).
for ns in ["tenant-a", "tenant-b"] {
    let mut conn: Connection<Route> = namespace::connection_for(ns)?;
    conn.subscribe(&[
        RtnetlinkGroup::Link,
        RtnetlinkGroup::Ipv4Addr,
        RtnetlinkGroup::Ipv6Addr,
        RtnetlinkGroup::Ipv4Route,
        RtnetlinkGroup::Ipv6Route,
        RtnetlinkGroup::Tc,
    ])?;
    streams.insert(ns.to_string(), conn.into_events());
}

// Fan-in: each event comes with its namespace key.
while let Some((ns, result)) = streams.next().await {
    let event = result?;
    match event {
        NetworkEvent::NewLink(link) => {
            println!("[{ns}] link up: {}", link.name_or("?"));
        }
        NetworkEvent::DelLink(link) => {
            println!("[{ns}] link gone: {}", link.name_or("?"));
        }
        NetworkEvent::NewAddress(addr) => {
            println!("[{ns}] addr added on ifindex {}: {:?}", addr.ifindex, addr.address);
        }
        NetworkEvent::NewQdisc(tc) => {
            println!("[{ns}] qdisc: {} on ifindex {}", tc.kind().unwrap_or("?"), tc.ifindex());
        }
        _ => {}
    }
}
# Ok(())
# }
```

## Subscribing to specific groups only

`subscribe_all()` is a convenience that opts into every common
rtnetlink group. For production agents it's often cleaner to name the
specific groups you care about so the kernel doesn't wake you on
unrelated events. The `RtnetlinkGroup` enum covers:

- `Link` — interface state changes (new/del/up/down)
- `Ipv4Addr` / `Ipv6Addr` — address changes
- `Ipv4Route` / `Ipv6Route` — routing table changes
- `Neigh` — ARP / NDP / FDB changes
- `Tc` — qdisc / class / filter changes
- `NsId` — namespace-ID assignments
- `Ipv4Rule` / `Ipv6Rule` — policy routing rule changes

Address-family rules are split across two groups, so a tool that only
cares about routing changes can skip `Link` + `Neigh` + `Tc`:

```rust,ignore
conn.subscribe(&[
    RtnetlinkGroup::Ipv4Route,
    RtnetlinkGroup::Ipv6Route,
    RtnetlinkGroup::Ipv4Rule,
    RtnetlinkGroup::Ipv6Rule,
])?;
```

## Adding / removing namespaces at runtime

`StreamMap` accepts `insert`/`remove` at any time — you can discover
namespaces lazily and wire them in without rebuilding the loop.

Pair this with the [`NamespaceWatcher`][nswatch] (behind the
`namespace_watcher` feature) to auto-subscribe when a new `ip netns`
appears:

[nswatch]: https://docs.rs/nlink/latest/nlink/netlink/struct.NamespaceWatcher.html

```no_run
# async fn demo() -> nlink::Result<()> {
# use nlink::netlink::{Connection, NetworkEvent, Route, namespace, NamespaceEvent, NamespaceWatcher};
# use tokio_stream::{StreamExt, StreamMap};
# let mut streams: StreamMap<String, nlink::OwnedEventStream<Route>> = StreamMap::new();
let mut ns_watcher = NamespaceWatcher::new().await?;

loop {
    tokio::select! {
        Some(ns_event) = async { ns_watcher.recv().await.transpose() } => {
            match ns_event? {
                NamespaceEvent::Created { name } => {
                    let mut conn: Connection<Route> = namespace::connection_for(&name)?;
                    conn.subscribe_all()?;
                    streams.insert(name, conn.into_events());
                }
                NamespaceEvent::Deleted { name } => {
                    streams.remove(&name);
                }
                _ => {}
            }
        }
        Some((ns, Ok(event))) = streams.next() => {
            // ... handle event ...
            let _ = (ns, event);
        }
    }
}
# }
```

## Caveats

- Each subscribed connection keeps a netlink socket with a kernel-side
  receive buffer. Kernels drop multicast messages on buffer overrun —
  a slow consumer will lose events. Read the stream promptly; don't
  `await` on heavy work without draining it.
- `NetworkEvent::New*` and `Del*` are the delivery semantics, but the
  kernel also sends `RTM_NEW*` for state changes (e.g., link going
  up is an `RTM_NEWLINK` with the `IFF_UP` bit set, not `RTM_DELLINK`).
  Consumers that care about transitions should track state themselves.
- Namespaces live in the file descriptor — `namespace::connection_for`
  opens an FD that stays valid across the connection's lifetime. When
  you remove the connection from the `StreamMap`, the FD closes
  automatically.
- `Ipv4Addr` + `Ipv6Addr` are separate groups: you need both if you
  want all address events regardless of family.

## Hand-rolled equivalent

`StreamMap` is the ergonomic path; the underlying primitive is
`Stream`. You can also use `tokio::select!` over a fixed set of
streams, or `futures::stream::select_all` for a dynamic set that you
re-pin manually. Both work; `StreamMap` wins on readability for the
"keyed fan-in" case documented above.

## See also

- [`Connection::events`](https://docs.rs/nlink/latest/nlink/netlink/struct.Connection.html#method.events)
- [`RtnetlinkGroup`](https://docs.rs/nlink/latest/nlink/netlink/enum.RtnetlinkGroup.html)
- [`NetworkEvent`](https://docs.rs/nlink/latest/nlink/enum.NetworkEvent.html)
- [Per-peer impairment recipe](./per-peer-impairment.md) — companion
  TC-side recipe for the "per-namespace orchestration" use case.
- Kernel docs: `man 7 rtnetlink`
