# Unified Async API Design Report

## Executive Summary

**Problem**: The nlink codebase has inconsistent initialization patterns (sync vs async) and event-capable protocols don't implement `Stream`, making them incompatible with async ecosystem combinators.

**Question**: Can we design a unified API that:
1. Works for all protocols
2. Implements `Stream` trait without losing ownership
3. Handles both sync and async initialization

**Recommendation**: Implement a **reference-based event subscription** pattern where `Connection<P>` provides a `subscribe()` method returning a `Stream` that borrows the connection.

---

## Current State Analysis

### Why Some Sockets Are "Sync"

All `NetlinkSocket` instances are async (using `tokio::io::unix::AsyncFd`). The "sync" vs "async" distinction is about **initialization**, not I/O:

| Protocol | Initialization | Reason |
|----------|---------------|--------|
| Route | Sync `new()` | No kernel negotiation needed |
| SockDiag | Sync `new()` | No kernel negotiation needed |
| KobjectUevent | Sync `new()` | Just subscribes to multicast group |
| SELinux | Sync `new()` | Just subscribes to multicast group |
| Netfilter | Sync `new()` | Query-only, no subscription |
| **Wireguard** | **Async** `new_async()` | Must resolve GENL family ID |
| **Connector** | **Async** `new()` | Must register with kernel |

### Current API Inconsistencies

```rust
// Inconsistent constructors
let route = Connection::<Route>::new()?;                    // sync
let wg = Connection::<Wireguard>::new_async().await?;       // async
let proc = Connection::<Connector>::new().await?;           // async (different name!)

// Only EventStream implements Stream
let stream = EventStream::builder().links(true).build()?;   // ✓ Stream
let event = uevent_conn.recv().await?;                      // ✗ No Stream
let event = selinux_conn.recv().await?;                     // ✗ No Stream
```

### Current EventStream Pattern

`EventStream` **owns** the connection:

```rust
pub struct EventStream {
    conn: Connection<Route>,  // Owned!
    buffer: Vec<u8>,
    pending_events: Vec<NetworkEvent>,
}

impl Stream for EventStream {
    type Item = Result<NetworkEvent>;
    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        // Uses self.conn internally
    }
}
```

**Problem**: Once you create an `EventStream`, you can't use the `Connection<Route>` for queries anymore.

---

## External Pattern Analysis

### rtnetlink: Handle Pattern

rtnetlink uses a cloneable `Handle` wrapping `Arc<Connection>`:

```rust
pub struct Handle {
    inner: Arc<Connection>,
}

impl Clone for Handle { /* cheap clone */ }

impl Handle {
    pub fn link(&self) -> LinkHandle { LinkHandle::new(self.clone()) }
    pub fn address(&self) -> AddressHandle { AddressHandle::new(self.clone()) }
    // Multiple handles can coexist
}
```

**Pros**: Multiple concurrent operations, cloneable
**Cons**: Arc overhead, less direct API, can't move connection out

### sipper: Progress + Output Pattern

sipper provides a combined Future+Stream for operations with progress:

```rust
pub trait Sipper<Output, Progress = Output> {
    // Streams Progress values, then resolves to Output
}

fn download(url: &str) -> impl Sipper<File, Progress> {
    sipper(async move |mut sender| {
        sender.send(Progress(50)).await;
        File::new()  // Final output
    })
}
```

**Pros**: Type-safe progress tracking, clean separation of concerns
**Cons**: Not applicable to event monitoring (no "final output")

---

## Proposed Solution: Reference-Based Event Subscription

### Core Design: `subscribe()` Method

Instead of consuming the connection, provide a method that returns a `Stream` borrowing it:

```rust
impl<P: ProtocolState + EventSource> Connection<P> {
    /// Subscribe to events from this connection.
    /// 
    /// Returns a Stream that borrows the connection.
    /// The connection can still be used for queries while the subscription is active.
    pub fn subscribe(&self) -> EventSubscription<'_, P> {
        EventSubscription {
            conn: self,
            buffer: Vec::new(),
        }
    }
}

pub struct EventSubscription<'a, P: ProtocolState + EventSource> {
    conn: &'a Connection<P>,
    buffer: Vec<u8>,
}

impl<P: ProtocolState + EventSource> Stream for EventSubscription<'_, P> {
    type Item = Result<P::Event>;
    
    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        // Poll conn.socket().poll_recv() and parse events
    }
}
```

### EventSource Trait

Define which protocols support event monitoring:

```rust
/// Sealed trait for protocols that can produce events.
pub trait EventSource: private::Sealed {
    /// The event type produced by this protocol.
    type Event: Send + 'static;
    
    /// Parse an event from raw netlink message data.
    fn parse_event(data: &[u8]) -> Option<Self::Event>;
}

impl EventSource for Route {
    type Event = NetworkEvent;
    fn parse_event(data: &[u8]) -> Option<NetworkEvent> { /* ... */ }
}

impl EventSource for KobjectUevent {
    type Event = Uevent;
    fn parse_event(data: &[u8]) -> Option<Uevent> { Uevent::parse(data) }
}

impl EventSource for Connector {
    type Event = ProcEvent;
    fn parse_event(data: &[u8]) -> Option<ProcEvent> { /* ... */ }
}

impl EventSource for SELinux {
    type Event = SELinuxEvent;
    fn parse_event(data: &[u8]) -> Option<SELinuxEvent> { /* ... */ }
}
```

### Usage Example

```rust
use nlink::netlink::{Connection, KobjectUevent, SELinux};
use tokio_stream::StreamExt;

// Connection stays owned, subscription borrows it
let conn = Connection::<KobjectUevent>::new()?;

// Can still use conn for other operations if needed
// ...

// Subscribe to events (borrows conn)
let mut events = conn.subscribe();
while let Some(event) = events.try_next().await? {
    println!("[{}] {}", event.action, event.devpath);
}

// After subscription ends, conn is still usable
drop(events);
// conn.some_query().await?;  // Still works!
```

### Combining Multiple Event Sources

```rust
use tokio_stream::{StreamExt, StreamMap};
use std::pin::pin;

let uevent_conn = Connection::<KobjectUevent>::new()?;
let selinux_conn = Connection::<SELinux>::new()?;
let route_conn = Connection::<Route>::new()?;

// Each subscription borrows its connection
let mut uevent_sub = pin!(uevent_conn.subscribe());
let mut selinux_sub = pin!(selinux_conn.subscribe());
let mut route_sub = pin!(route_conn.subscribe());

loop {
    tokio::select! {
        Some(event) = uevent_sub.next() => {
            println!("[device] {:?}", event?);
        }
        Some(event) = selinux_sub.next() => {
            println!("[selinux] {:?}", event?);
        }
        Some(event) = route_sub.next() => {
            println!("[network] {:?}", event?);
        }
    }
}
```

---

## Alternative: Owned Stream with `into_stream()`

For cases where owning is preferred (simpler lifetime management):

```rust
impl<P: ProtocolState + EventSource> Connection<P> {
    /// Convert this connection into an event stream.
    /// 
    /// This consumes the connection. Use `subscribe()` if you need
    /// to keep using the connection for queries.
    pub fn into_stream(self) -> OwnedEventStream<P> {
        OwnedEventStream {
            conn: self,
            buffer: Vec::new(),
        }
    }
}

pub struct OwnedEventStream<P: ProtocolState + EventSource> {
    conn: Connection<P>,
    buffer: Vec<u8>,
}

impl<P: ProtocolState + EventSource> OwnedEventStream<P> {
    /// Get a reference to the underlying connection.
    pub fn connection(&self) -> &Connection<P> {
        &self.conn
    }
    
    /// Recover the connection, consuming this stream.
    pub fn into_connection(self) -> Connection<P> {
        self.conn
    }
}

impl<P: ProtocolState + EventSource> Stream for OwnedEventStream<P> {
    type Item = Result<P::Event>;
    // ...
}
```

---

## Unified Initialization

### Builder Pattern for All Protocols

```rust
/// Builder for creating connections with optional namespace support.
pub struct ConnectionBuilder<P: ProtocolState> {
    namespace: Option<NamespaceConfig>,
    _marker: PhantomData<P>,
}

impl<P: ProtocolState> ConnectionBuilder<P> {
    pub fn new() -> Self {
        Self { namespace: None, _marker: PhantomData }
    }
    
    pub fn namespace(mut self, ns: impl Into<NamespaceConfig>) -> Self {
        self.namespace = Some(ns.into());
        self
    }
}

// Sync build for protocols that don't need negotiation
impl<P: ProtocolState + SyncInit> ConnectionBuilder<P> {
    pub fn build(self) -> Result<Connection<P>> {
        let socket = match self.namespace {
            Some(ns) => NetlinkSocket::new_in_namespace(P::PROTOCOL, ns)?,
            None => NetlinkSocket::new(P::PROTOCOL)?,
        };
        Ok(Connection::from_parts(socket, P::default()))
    }
}

// Async build for protocols that need kernel negotiation
impl ConnectionBuilder<Wireguard> {
    pub async fn build(self) -> Result<Connection<Wireguard>> {
        let socket = match self.namespace {
            Some(ns) => NetlinkSocket::new_in_namespace(Wireguard::PROTOCOL, ns)?,
            None => NetlinkSocket::new(Wireguard::PROTOCOL)?,
        };
        let family_id = resolve_wireguard_family(&socket).await?;
        Ok(Connection::from_parts(socket, Wireguard { family_id }))
    }
}

impl ConnectionBuilder<Connector> {
    pub async fn build(self) -> Result<Connection<Connector>> {
        let socket = /* ... */;
        register_proc_events(&socket).await?;
        Ok(Connection::from_parts(socket, Connector))
    }
}
```

### Usage

```rust
// Sync protocols
let conn = Connection::<Route>::builder().build()?;
let conn = Connection::<Route>::builder().namespace("myns").build()?;

// Async protocols  
let conn = Connection::<Wireguard>::builder().build().await?;
let conn = Connection::<Wireguard>::builder().namespace("myns").build().await?;

// Shorthand (keep existing API)
let conn = Connection::<Route>::new()?;  // Still works
let conn = Connection::<Wireguard>::new_async().await?;  // Still works
```

---

## Implementation Plan

### Phase 1: EventSource Trait

1. Define `EventSource` trait in `protocol.rs`
2. Implement for Route (using existing NetworkEvent parsing)
3. Implement for KobjectUevent, Connector, SELinux

### Phase 2: Reference-Based Subscription

1. Add `subscribe()` method to `Connection<P: EventSource>`
2. Create `EventSubscription<'a, P>` struct
3. Implement `Stream` for `EventSubscription`
4. Add `poll_recv` to base `Connection` if not present

### Phase 3: Owned Stream Alternative

1. Add `into_stream()` method
2. Create `OwnedEventStream<P>` struct
3. Add `connection()` and `into_connection()` methods

### Phase 4: Builder Pattern

1. Create `ConnectionBuilder<P>`
2. Add sync `build()` for `SyncInit` protocols
3. Add async `build()` for Wireguard and Connector
4. Integrate namespace support

### Phase 5: Migration

1. Keep existing `EventStream` for backward compatibility
2. Deprecate `recv()` methods in favor of `subscribe()`
3. Update examples and documentation

---

## API Comparison

### Before (Current)

```rust
// Inconsistent constructors
let route = Connection::<Route>::new()?;
let wg = Connection::<Wireguard>::new_async().await?;
let proc = Connection::<Connector>::new().await?;

// Only Route has Stream via EventStream
let stream = EventStream::builder().links(true).build()?;

// Others use recv() loop
loop {
    let event = uevent_conn.recv().await?;
}
```

### After (Proposed)

```rust
// Consistent builder pattern
let route = Connection::<Route>::builder().build()?;
let wg = Connection::<Wireguard>::builder().build().await?;
let proc = Connection::<Connector>::builder().build().await?;

// Or keep shorthand
let route = Connection::<Route>::new()?;

// All event sources support Stream via subscribe()
let mut events = route.subscribe();
while let Some(e) = events.next().await { }

let mut events = uevent_conn.subscribe();
while let Some(e) = events.next().await { }

// Or use into_stream() if ownership is okay
let stream = selinux_conn.into_stream();
```

---

## Comparison with Alternatives

| Approach | Ownership | Composability | Complexity |
|----------|-----------|---------------|------------|
| Current `recv()` loop | Retained | Poor (no Stream) | Low |
| Owned Stream (current EventStream) | Lost | Good | Medium |
| **Reference-based subscribe()** | **Retained** | **Good** | Medium |
| rtnetlink Handle (Arc) | Shared | Good | High |
| sipper | N/A (wrong pattern) | N/A | N/A |

---

## Conclusion

The recommended approach is:

1. **Keep existing `Connection::new()` pattern** for backward compatibility
2. **Add `EventSource` trait** to mark event-capable protocols
3. **Add `subscribe()` method** returning borrowed Stream
4. **Optionally add `into_stream()`** for owned Stream
5. **Add `ConnectionBuilder`** for unified namespace support

This provides:
- ✅ Stream trait for all event protocols
- ✅ No ownership loss (via `subscribe()`)
- ✅ Ecosystem compatibility (tokio_stream combinators)
- ✅ Backward compatible
- ✅ Handles both sync and async initialization
