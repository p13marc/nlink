# Netdev lifecycle: joining uevents with rtnetlink

How to get one typed stream — and one watch-cache — describing
network devices with *both* their rtnetlink attributes and their
driver/sysfs context.

## When to use this

- You are writing a CNI plugin, a NIC inventory agent, a
  multi-tenant network manager, or anything that wants to answer
  "which driver is behind ifindex 7?" without shelling out.
- You need to react to a driver binding or unbinding, which
  rtnetlink cannot tell you about at all.
- You want a cache of devices that stays fresh without polling.

If you only need link attributes, use `Connection<Route>` and
`RtnetlinkGroup::Link` directly — this recipe adds a second socket
and a join, and that only pays for itself if you want the second
half.

## The problem

Two sockets, two partial views:

| | rtnetlink (`RTM_NEWLINK`) | uevent (`add@…`) |
|---|---|---|
| ifindex | ✅ | ✅ (`IFINDEX=`) |
| name | ✅ | ✅ (`INTERFACE=`) |
| MTU, flags, master, kind | ✅ | ✗ |
| driver | ✗ | ✅ (`DRIVER=`) |
| sysfs devpath, bus parent | ✗ | ✅ (`DEVPATH=`) |
| driver bind / unbind | ✗ | ✅ |
| dump to resync from | ✅ | ✗ |

Nothing orders the two against each other. Either can arrive
first, and for a device that existed before you subscribed,
neither will arrive at all until something changes.

## The shape

```rust
use nlink::netlink::{
    Connection, KobjectUevent, Route, RtnetlinkGroup,
    netdev::{NetdevEvent, NetdevInfo, NetdevLifecycle},
    reflector::Store,
    uevent_filter::UeventFilter,
};
use tokio_stream::StreamExt;

let links = Connection::<Route>::new()?;
links.subscribe(&[RtnetlinkGroup::Link])?;

let uevents = Connection::<KobjectUevent>::new()?;
// Drop every non-net uevent in the kernel rather than parsing and
// discarding it here.
uevents.attach_filter(&UeventFilter::new().subsystem("net").build())?;

let store: Store<u32, NetdevInfo> = Store::new();
let mut lifecycle = NetdevLifecycle::new(links.events().await, uevents.events().await)
    .with_store(store.clone());

while let Some(event) = lifecycle.next().await {
    match event? {
        NetdevEvent::Added(info) => { /* device exists */ }
        NetdevEvent::Changed(info) => { /* attributes or annotation updated */ }
        NetdevEvent::DriverBound { ifindex, annotation } => { /* uevent-only */ }
        NetdevEvent::DriverUnbound { ifindex, annotation } => { /* uevent-only */ }
        NetdevEvent::Removed { ifindex, name } => { /* gone */ }
        _ => {}
    }
}
```

`Store` is cheap to clone and shares its backing map, so hand
clones to as many readers as you like while one task drives the
stream.

## Four things worth understanding before you rely on it

### rtnetlink decides what exists; uevents only annotate

`Added` fires when rtnetlink says a device exists — with whatever
annotation had already arrived, possibly none. When the uevent
half lands afterwards it surfaces as a `Changed` carrying the
enriched `NetdevInfo`.

So a consumer must be ready for a device to show up
un-annotated and be filled in a moment later. The alternative —
buffering until both halves arrive — needs a latency knob *and* a
"the partner never came" timeout, and the partner genuinely may
never come.

`DriverBound` / `DriverUnbound` are the exception: they have no
rtnetlink counterpart, so they can arrive for an ifindex that no
`Added` was emitted for. Read them as statements about a driver,
never about whether the device exists.

### ifindex reuse is handled, but you should know how

Kernel ifindexes are recycled. Two things stop a stale uevent
being attributed to the device that inherits an index:

1. `Removed` drops the annotation along with the device.
2. Net uevents carry `INTERFACE=`, so an annotation held for an
   index that turns up as a *new* device under a different name
   is discarded.

The name check runs only on the `Added` transition, because a
rename emits an `RTM_NEWLINK` and a `move` uevent in no fixed
order — enforcing it on every event would discard good
annotations mid-rename. During that window
`NetdevInfo::is_fully_attributed()` returns `false`, so a strict
consumer can wait it out:

```rust
if info.is_fully_attributed() {
    // rtnetlink and the uevent agree on the name; the annotation
    // is describing this device and not its predecessor.
}
```

### The devpath is a string, and stays one

`DEVPATH=` names a path in sysfs. sysfs resolves in your **mount**
namespace; the ifindex resolves in the connection's **network**
namespace. They are not the same namespace, so `NetdevAnnotation`
carries the devpath verbatim and nothing in `netlink/` ever opens
it. Resolving it is your call, under your namespace assumptions —
`nlink::util::uevent_trigger` is where nlink's own sysfs access
lives, and the `scripts/audit-sysfs-in-lib.sh` CI gate keeps it
that way.

### Inside a namespace, you see net uevents and nothing else

Net-device uevents go to the network namespace of the listening
socket:

```rust
let uevents = Connection::<KobjectUevent>::in_namespace("tenant-a")?;
```

Uevents for every *other* subsystem go only to the initial
namespace. So the join works cleanly in a netns — but the
PCI-parent uevent of a device passed into that namespace will
never arrive there.

## Frame loss

The uevent side can overflow under a coldplug storm, and it has
no dump to resync from — see
[`uevent re-enumeration`](../../crates/nlink/src/util/uevent_trigger.rs)
and issue #252. Two mitigations, both already wired in above:

- `Connection::<KobjectUevent>::new()` sizes the receive buffer up
  from the ~208 KiB system default.
- `attach_filter` sheds non-net traffic in the kernel, so the
  buffer only holds events you asked for.

What that means for the cache: the *set of devices* comes from
rtnetlink, which has a real dump, so it is sound. *Annotations*
come from uevents, so a device can sit in the store
un-annotated indefinitely. `is_fully_attributed()` distinguishes
them; do not treat a missing annotation as a missing device.

## Running it

```bash
cargo run -p nlink --example uevent_netdev_lifecycle

# in another terminal
sudo ip link add dummy0 type dummy
sudo ip link set dummy0 up
sudo ip link del dummy0
```

## See also

- [`events-with-resync`](events-with-resync.md) — the resync
  machinery this deliberately does *not* use on the uevent side.
- [`multi-namespace-events`](multi-namespace-events.md) — fanning
  the same idea across N namespaces with `StreamMap`.
- `crates/nlink/examples/uevent/` — `filtered_monitor.rs`,
  `resync_monitor.rs`, `netdev_lifecycle.rs`.
