# EventStreamBuilder Generalization Analysis

## Executive Summary

**Question**: Should `EventStreamBuilder` be generalized beyond `Connection<Route>` to support other protocols?

**Short Answer**: No for the **builder**, but **yes** for implementing `tokio_stream::Stream` on event-capable protocols.

**Recommendation**: 
1. Keep `EventStreamBuilder` as Route-specific (builder pattern not needed for simple protocols)
2. **Add `Stream` trait implementations** to `Connection<KobjectUevent>`, `Connection<Connector>`, and `Connection<SELinux>` for ecosystem compatibility

---

## Current State

### EventStream (Route) - Implements Stream

The `EventStream` in `crates/nlink/src/netlink/events.rs` implements `tokio_stream::Stream`:

```rust
impl Stream for EventStream {
    type Item = Result<NetworkEvent>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        // ... polling implementation
    }
}
```

This enables powerful stream combinators:

```rust
use tokio_stream::StreamExt;

let mut stream = EventStream::builder().links(true).build()?;

// Stream combinators work
while let Some(event) = stream.try_next().await? {
    // ...
}

// Can use filter, map, timeout, etc.
let filtered = stream.filter(|e| matches!(e, Ok(NetworkEvent::NewLink(_))));
```

### Other Protocols - Only Have `recv()` Methods

| Protocol | Current API | Stream Implementation |
|----------|-------------|----------------------|
| Route | `EventStream` | **Yes** - full `Stream` impl |
| KobjectUevent | `conn.recv().await` | **No** |
| Connector | `conn.recv().await` | **No** |
| SELinux | `conn.recv().await` | **No** |
| NamespaceWatcher | `watcher.recv().await` | **No** |
| NamespaceEventSubscriber | `sub.recv().await` | **No** |

---

## The Case for Stream Trait Implementation

### Benefits of Implementing Stream

1. **Ecosystem Compatibility**: Works with `tokio_stream` combinators (filter, map, timeout, take, merge)
2. **StreamMap Support**: Can combine multiple event sources
3. **Familiar API**: Users expect `Stream` for async iterators
4. **Select! Compatibility**: Works with `tokio::select!` via `StreamExt::next()`

### Current Pain Point

Users wanting to combine events from multiple protocols must manually poll:

```rust
// Current: Manual polling required
loop {
    tokio::select! {
        event = uevent_conn.recv() => { /* handle */ }
        event = selinux_conn.recv() => { /* handle */ }
        event = proc_conn.recv() => { /* handle */ }
    }
}
```

With `Stream` implementations:

```rust
// Better: Use StreamMap
use tokio_stream::{StreamExt, StreamMap};

let mut streams = StreamMap::new();
streams.insert("uevent", uevent_stream);
streams.insert("selinux", selinux_stream);
streams.insert("proc", proc_stream);

while let Some((source, event)) = streams.next().await {
    match source {
        "uevent" => { /* handle */ }
        "selinux" => { /* handle */ }
        "proc" => { /* handle */ }
        _ => {}
    }
}
```

---

## Proposed Design: Stream Wrappers

### Option A: Stream Wrapper Types (Recommended)

Create dedicated stream types that wrap `Connection<P>`:

```rust
// crates/nlink/src/netlink/uevent.rs

/// Stream of device hotplug events.
pub struct UeventStream {
    conn: Connection<KobjectUevent>,
}

impl UeventStream {
    /// Create a new uevent stream.
    pub fn new() -> Result<Self> {
        Ok(Self {
            conn: Connection::<KobjectUevent>::new()?,
        })
    }
}

impl Stream for UeventStream {
    type Item = Result<Uevent>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        
        // Use poll_recv_msg from the socket
        match this.conn.socket().poll_recv(cx) {
            Poll::Ready(Ok(data)) => {
                if let Some(event) = Uevent::parse(&data) {
                    Poll::Ready(Some(Ok(event)))
                } else {
                    // Invalid message, wake to retry
                    cx.waker().wake_by_ref();
                    Poll::Pending
                }
            }
            Poll::Ready(Err(e)) => Poll::Ready(Some(Err(e))),
            Poll::Pending => Poll::Pending,
        }
    }
}
```

Similar implementations for:
- `ProcEventStream` wrapping `Connection<Connector>`
- `SELinuxEventStream` wrapping `Connection<SELinux>`

### Option B: Implement Stream on Connection Directly

Less code but requires `Connection` to be `!Unpin`:

```rust
impl Stream for Connection<KobjectUevent> {
    type Item = Result<Uevent>;
    
    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        // ...
    }
}
```

**Drawback**: Connection is typically used for request/response too, not just events. Making it a Stream changes its semantics.

### Option C: IntoStream Trait

```rust
pub trait IntoEventStream: Sized {
    type Event;
    type Stream: Stream<Item = Result<Self::Event>>;
    
    fn into_stream(self) -> Self::Stream;
}

impl IntoEventStream for Connection<KobjectUevent> {
    type Event = Uevent;
    type Stream = UeventStream;
    
    fn into_stream(self) -> UeventStream {
        UeventStream { conn: self }
    }
}
```

---

## Implementation Comparison

| Approach | Pros | Cons |
|----------|------|------|
| **Wrapper types (A)** | Clear semantics, Connection still usable for queries | More types to maintain |
| **Direct impl (B)** | Less code | Connection can't be used for other operations |
| **IntoStream (C)** | Conversion is explicit | Extra trait, more complex |

**Recommendation: Option A** - Wrapper types provide the clearest API.

---

## Proposed Stream Types

### 1. UeventStream

```rust
pub struct UeventStream {
    conn: Connection<KobjectUevent>,
}

impl UeventStream {
    pub fn new() -> Result<Self>;
}

impl Stream for UeventStream {
    type Item = Result<Uevent>;
}

// Usage
let mut stream = UeventStream::new()?;
while let Some(event) = stream.try_next().await? {
    println!("[{}] {}", event.action, event.devpath);
}
```

### 2. ProcEventStream

```rust
pub struct ProcEventStream {
    conn: Connection<Connector>,
}

impl ProcEventStream {
    pub async fn new() -> Result<Self>; // async due to registration
}

impl Stream for ProcEventStream {
    type Item = Result<ProcEvent>;
}

// Usage
let mut stream = ProcEventStream::new().await?;
while let Some(event) = stream.try_next().await? {
    match event {
        ProcEvent::Fork { parent_pid, child_pid, .. } => {}
        ProcEvent::Exec { pid, .. } => {}
        _ => {}
    }
}
```

### 3. SELinuxEventStream

```rust
pub struct SELinuxEventStream {
    conn: Connection<SELinux>,
}

impl SELinuxEventStream {
    pub fn new() -> Result<Self>;
    pub fn is_available() -> bool;
}

impl Stream for SELinuxEventStream {
    type Item = Result<SELinuxEvent>;
}

// Usage
let mut stream = SELinuxEventStream::new()?;
while let Some(event) = stream.try_next().await? {
    match event {
        SELinuxEvent::SetEnforce { enforcing } => {}
        SELinuxEvent::PolicyLoad { seqno } => {}
    }
}
```

---

## Multi-Source Event Monitoring

With Stream implementations, users can combine sources:

```rust
use tokio_stream::{StreamExt, StreamMap};

// Unified event enum (user-defined)
enum SystemEvent {
    Device(Uevent),
    Process(ProcEvent),
    SELinux(SELinuxEvent),
    Network(NetworkEvent),
}

let mut streams: StreamMap<&str, Pin<Box<dyn Stream<Item = Result<SystemEvent>>>>> = StreamMap::new();

streams.insert("device", Box::pin(UeventStream::new()?.map(|r| r.map(SystemEvent::Device))));
streams.insert("proc", Box::pin(ProcEventStream::new().await?.map(|r| r.map(SystemEvent::Process))));
streams.insert("selinux", Box::pin(SELinuxEventStream::new()?.map(|r| r.map(SystemEvent::SELinux))));
streams.insert("network", Box::pin(EventStream::builder().all().build()?.map(|r| r.map(SystemEvent::Network))));

while let Some((source, event)) = streams.next().await {
    match event? {
        SystemEvent::Device(e) => println!("[device] {}", e.action),
        SystemEvent::Process(e) => println!("[proc] {:?}", e),
        SystemEvent::SELinux(e) => println!("[selinux] {:?}", e),
        SystemEvent::Network(e) => println!("[network] {:?}", e),
    }
}
```

---

## Why NOT Generalize the Builder

The builder pattern is unnecessary for simple protocols:

| Protocol | Subscription Options | Builder Value |
|----------|---------------------|---------------|
| Route | 7+ independent groups | **High** - user selects which events |
| KobjectUevent | 1 group (all devices) | **None** - no options |
| Connector | 1 group (all processes) | **None** - no options |
| SELinux | 1 group (all events) | **None** - no options |

A generic `EventStreamBuilder<P>` would add complexity without benefit for simple protocols:

```rust
// Bad: Unnecessary builder for simple protocols
let stream = EventStreamBuilder::<KobjectUevent>::new()
    .build()?;  // No configuration options!

// Good: Direct constructor
let stream = UeventStream::new()?;
```

---

## Required Socket Changes

To implement `Stream`, we need `poll_recv` on `NetlinkSocket`:

```rust
// Already exists in socket.rs:
impl NetlinkSocket {
    /// Poll for incoming data (for Stream implementations).
    pub fn poll_recv(&self, cx: &mut Context<'_>) -> Poll<Result<Vec<u8>>> {
        // Implementation using AsyncFd::poll_read_ready
    }
}
```

This is already used by `EventStream` for Route.

---

## Implementation Plan

### Phase 1: Core Infrastructure
1. Ensure `NetlinkSocket::poll_recv` is public (already is)
2. Add `poll_recv` helper to `Connection<P>` if needed

### Phase 2: Stream Wrappers
1. Add `UeventStream` to `uevent.rs`
2. Add `ProcEventStream` to `connector.rs`
3. Add `SELinuxEventStream` to `selinux.rs`

### Phase 3: Documentation & Examples
1. Update examples to show Stream usage
2. Document StreamMap patterns for multi-source monitoring
3. Update CLAUDE.md with Stream examples

### Phase 4: Optional Enhancements
1. Add `NamespaceEventStream` for namespace ID events
2. Consider `AuditEventStream` if audit event monitoring is added

---

## Conclusion

| Question | Answer |
|----------|--------|
| Generalize `EventStreamBuilder`? | **No** - Route's complexity justifies its builder; others don't need it |
| Implement `Stream` trait? | **Yes** - Provides ecosystem compatibility and composability |
| How to implement? | **Wrapper types** (UeventStream, ProcEventStream, SELinuxEventStream) |
| Keep `recv()` methods? | **Yes** - Some users prefer the simpler async method |

### Summary of Recommendations

1. **Keep `EventStreamBuilder` Route-specific** - Its complexity is warranted by Route's 7+ event types
2. **Add Stream wrapper types** for KobjectUevent, Connector, and SELinux
3. **Keep `recv()` methods** as alternative API
4. **Document multi-source patterns** using `StreamMap`

The key insight is that **Stream trait implementation** is the right abstraction to generalize, not the **builder pattern**. The builder is about configuration complexity (which varies by protocol), while Stream is about async iteration (which is common to all event sources).
