# Event API Consolidation Report

## Status: IMPLEMENTED

This document describes the event API consolidation that was completed. The changes simplify the event monitoring API by removing redundant abstractions and adding strongly-typed multicast group subscription.

---

## Changes Made

### 1. Removed `EventStream` and `EventStreamBuilder`

**Rationale:**
- They duplicated what `Connection<Route>::events()` provides
- The builder pattern added unnecessary complexity
- Users lost access to the connection for queries

**Migration:**

Before:
```rust
let mut stream = EventStream::builder()
    .links(true)
    .tc(true)
    .namespace("myns")
    .build()?;
```

After:
```rust
let mut conn = Connection::<Route>::new_in_namespace("myns")?;
conn.subscribe(&[RtnetlinkGroup::Link, RtnetlinkGroup::Tc])?;
let mut events = conn.events();
```

### 2. Removed `MultiNamespaceEventStream`

**Rationale:**
- It was a trivial wrapper over `StreamMap`
- Users can use `StreamMap` directly with better control
- The `NamespacedEvent` wrapper just added the namespace name

**Migration:**

Before:
```rust
let mut multi = MultiNamespaceEventStream::new();
multi.add("ns1", EventStream::builder().namespace("ns1").all().build()?);
```

After:
```rust
use tokio_stream::StreamMap;

let mut streams = StreamMap::new();

let mut conn1 = Connection::<Route>::new_in_namespace("ns1")?;
conn1.subscribe_all()?;
streams.insert("ns1", conn1.into_event_stream());

// StreamMap yields (key, event) pairs
while let Some((ns, result)) = streams.next().await {
    let event = result?;
    println!("[{}] {:?}", ns, event);
}
```

### 3. Added `RtnetlinkGroup` Enum

Strongly-typed multicast group subscription replaces raw `u32` group numbers:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RtnetlinkGroup {
    Link,       // Interface state changes
    Ipv4Addr,   // IPv4 address changes
    Ipv6Addr,   // IPv6 address changes
    Ipv4Route,  // IPv4 routing table changes
    Ipv6Route,  // IPv6 routing table changes
    Neigh,      // Neighbor (ARP/NDP) changes
    Tc,         // Traffic control changes
    NsId,       // Namespace ID changes
    Ipv4Rule,   // IPv4 policy routing rules
    Ipv6Rule,   // IPv6 policy routing rules
}
```

### 4. Added `subscribe()` and `subscribe_all()` Methods

```rust
impl Connection<Route> {
    /// Subscribe to specific multicast groups.
    pub fn subscribe(&mut self, groups: &[RtnetlinkGroup]) -> Result<()>;
    
    /// Subscribe to all commonly-used event groups.
    pub fn subscribe_all(&mut self) -> Result<()>;
}
```

---

## New API

### Basic Event Monitoring

```rust
use nlink::netlink::{Connection, Route, RtnetlinkGroup, NetworkEvent};
use tokio_stream::StreamExt;

let mut conn = Connection::<Route>::new()?;
conn.subscribe(&[RtnetlinkGroup::Link, RtnetlinkGroup::Tc])?;

let mut events = conn.events();
while let Some(result) = events.next().await {
    let event = result?;
    match event {
        NetworkEvent::NewLink(link) => println!("Link: {}", link.name_or("?")),
        NetworkEvent::NewQdisc(tc) => println!("Qdisc: {}", tc.kind().unwrap_or("?")),
        _ => {}
    }
}
```

### Subscribe to All Common Groups

```rust
let mut conn = Connection::<Route>::new()?;
conn.subscribe_all()?;  // Link, Ipv4Addr, Ipv6Addr, Ipv4Route, Ipv6Route, Neigh, Tc
let mut events = conn.events();
```

### Multi-Namespace Monitoring

```rust
use nlink::netlink::{Connection, Route, RtnetlinkGroup, namespace};
use tokio_stream::{StreamExt, StreamMap};

let mut streams = StreamMap::new();

// Default namespace
let mut conn = Connection::<Route>::new()?;
conn.subscribe_all()?;
streams.insert("default", conn.into_event_stream());

// Named namespace
let mut conn_ns1 = namespace::connection_for("ns1")?;
conn_ns1.subscribe_all()?;
streams.insert("ns1", conn_ns1.into_event_stream());

while let Some((ns, result)) = streams.next().await {
    let event = result?;
    println!("[{}] {:?}", ns, event);
}
```

---

## Items Kept

| Item | Status | Notes |
|------|--------|-------|
| `NetworkEvent` | **Kept** | Used by `EventSource` impl for Route |
| `EventSource` trait | **Kept** | Unified API for all protocols |
| `EventSubscription` | **Kept** | Borrowed stream from `conn.events()` |
| `OwnedEventStream` | **Kept** | Owned stream from `conn.into_event_stream()` |
| `NamespaceEventSubscriber` | **Kept** | NSID events (can be migrated later) |
| `NamespaceWatcher` | **Kept** | inotify-based, different mechanism |

---

## Files Modified

| File | Changes |
|------|---------|
| `crates/nlink/src/netlink/connection.rs` | Added `RtnetlinkGroup` enum, `subscribe()`, `subscribe_all()` |
| `crates/nlink/src/netlink/events.rs` | Removed `EventStream`, `EventStreamBuilder`, `MultiNamespaceEventStream`, kept `NetworkEvent` |
| `crates/nlink/src/netlink/mod.rs` | Updated exports |
| `crates/nlink/src/lib.rs` | Updated re-exports |
| `crates/nlink/src/output/monitor.rs` | Removed `run_monitor_loop` (no longer compatible) |
| `crates/nlink/examples/events/monitor.rs` | Updated to new API |
| `crates/nlink/examples/events/monitor_namespace.rs` | Updated to new API |
| `bins/ip/src/commands/monitor.rs` | Updated to new API |
| `bins/tc/src/commands/monitor.rs` | Updated to new API |
| `CLAUDE.md` | Updated documentation |

---

## Protocol-specific Behavior

| Protocol | Subscription | Notes |
|----------|--------------|-------|
| `Route` | Manual via `subscribe()` | Multiple groups available |
| `KobjectUevent` | Automatic in `new()` | Single group (KOBJECT_UEVENT) |
| `Connector` | Automatic in `new().await` | Registration handshake |
| `SELinux` | Automatic in `new()` | Single group (SELNLGRP_AVC) |
| `Audit` | Manual | Query-response, not events |
| `Netfilter` | TBD | Conntrack events possible |
