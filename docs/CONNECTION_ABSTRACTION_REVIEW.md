# Connection Abstraction Review

This document analyzes whether `Connection` is the right abstraction for the nlink crate and evaluates type-safety concerns.

## Executive Summary

The current `Connection` type is a **runtime-polymorphic** abstraction over multiple netlink protocols. While convenient for implementation, it lacks **compile-time protocol enforcement**, allowing users to call methods on connections that don't support them. This leads to runtime errors instead of compile-time feedback.

**Recommendation**: Introduce phantom type parameters or protocol-specific newtypes to provide compile-time safety while preserving API ergonomics.

---

## 1. Current Design

### Protocol Enum

```rust
pub enum Protocol {
    Route,           // NETLINK_ROUTE - interfaces, addresses, routes, TC, neighbors
    Generic,         // NETLINK_GENERIC - family-based protocols (WireGuard, etc.)
    Netfilter,       // NETLINK_NETFILTER - packet filtering
    Connector,       // NETLINK_CONNECTOR - kernel connector
    KobjectUevent,   // NETLINK_KOBJECT_UEVENT - kernel uevents
}
```

### Connection Structure

```rust
pub struct Connection {
    socket: NetlinkSocket,  // Contains Protocol internally, but private
}

impl Connection {
    pub fn new(protocol: Protocol) -> Result<Self> { ... }
    // Protocol is erased after construction
}
```

---

## 2. Method-Protocol Matrix

### Methods Available on `Connection`

| Method Category | Methods | Required Protocol | Compile-Time Check |
|-----------------|---------|-------------------|-------------------|
| **Core (All)** | `request()`, `request_ack()`, `dump()`, `dump_typed()`, `subscribe()`, `recv_event()` | Any | N/A |
| **Link Mgmt** | `add_link()`, `del_link()`, `set_link_up/down()`, `set_link_mtu()`, `get_links()`, etc. | Route | **No** |
| **Address Mgmt** | `add_address()`, `del_address()`, `get_addresses()`, etc. | Route | **No** |
| **Route Mgmt** | `add_route()`, `del_route()`, `replace_route()`, `get_routes()`, etc. | Route | **No** |
| **Neighbor Mgmt** | `add_neighbor()`, `del_neighbor()`, `get_neighbors()`, etc. | Route | **No** |
| **Traffic Control** | `add_qdisc()`, `del_qdisc()`, `apply_netem()`, `get_qdiscs()`, `add_filter()`, etc. | Route | **No** |
| **Namespace ID** | `get_nsid()`, `get_nsid_for_pid()` | Route | **No** |

### Separate Type: `GenlConnection`

| Method | Required Protocol |
|--------|-------------------|
| `get_family()`, `get_family_id()` | Generic |
| `get_device()` (WireGuard) | Generic |
| `set_device()`, `set_peer()`, `remove_peer()` | Generic |

---

## 3. Type-Safety Issues

### Issue 1: Protocol Mismatch Compiles

```rust
// This compiles but fails at runtime!
let conn = Connection::new(Protocol::Generic)?;
conn.add_qdisc("eth0", netem).await?;  // Wrong protocol!
```

**Expected**: Compile-time error  
**Actual**: Runtime error from kernel rejecting invalid message type

### Issue 2: No Protocol Constraint in Function Signatures

```rust
// Library code cannot express "needs Route protocol"
async fn configure_tc(conn: &Connection) -> Result<()> {
    conn.add_qdisc("eth0", netem).await?;  // What if conn is Generic?
}
```

### Issue 3: Methods Silently Assume Route Protocol

All high-level methods (link, address, route, TC, neighbor) internally assume `Protocol::Route` without validation:

```rust
// In link.rs
impl Connection {
    pub async fn get_links(&self) -> Result<Vec<LinkMessage>> {
        // No check that self.socket.protocol() == Protocol::Route
        let mut builder = dump_request(NlMsgType::RTM_GETLINK);
        // ...
    }
}
```

### Issue 4: Generic Protocol Requires Separate Type

Users working with WireGuard must use `GenlConnection`, a completely separate type:

```rust
// Route operations
let route_conn = Connection::new(Protocol::Route)?;
route_conn.get_links().await?;

// Generic operations - different type!
let genl_conn = GenlConnection::new().await?;
genl_conn.get_device("wg0").await?;
```

This creates friction for code that needs both capabilities.

---

## 4. Misuse Scenarios

| Scenario | Risk Level | Consequence |
|----------|------------|-------------|
| Create `Protocol::Generic`; call TC methods | High | Runtime error from kernel |
| Create `Protocol::Netfilter`; call link methods | High | Runtime error, possibly undefined behavior |
| Library takes `&Connection` parameter | Medium | No way to enforce Route protocol |
| Multi-protocol application | Medium | Code duplication, separate connection management |
| Refactoring protocol usage | Low | No compiler assistance to find affected code |

---

## 5. Proposed Solution: Stateful Protocol Types

The key insight is that different protocols need **different state**, not just different methods:
- `Generic` needs a family ID cache
- `Route` needs nothing extra (stateless)
- Future protocols might need other state

Instead of phantom types or separate newtypes, we use **generic with stateful protocol structs**:

```rust
/// Trait for protocol-specific state and behavior
pub trait ProtocolState: private::Sealed + Default {
    const PROTOCOL: Protocol;
}

/// Route protocol - no extra state needed
#[derive(Default)]
pub struct Route;

impl ProtocolState for Route {
    const PROTOCOL: Protocol = Protocol::Route;
}

/// Generic protocol - needs family ID cache
pub struct Generic {
    cache: RwLock<HashMap<String, FamilyInfo>>,
}

impl Default for Generic {
    fn default() -> Self {
        Self { cache: RwLock::new(HashMap::new()) }
    }
}

impl ProtocolState for Generic {
    const PROTOCOL: Protocol = Protocol::Generic;
}

/// Connection parameterized by protocol state
pub struct Connection<P: ProtocolState> {
    socket: NetlinkSocket,
    state: P,  // Actual state, not PhantomData!
}
```

### Construction

```rust
impl<P: ProtocolState> Connection<P> {
    pub fn new() -> Result<Self> {
        Ok(Self {
            socket: NetlinkSocket::new(P::PROTOCOL)?,
            state: P::default(),
        })
    }
    
    pub fn new_in_namespace(ns_fd: RawFd) -> Result<Self> {
        Ok(Self {
            socket: NetlinkSocket::new_in_namespace(P::PROTOCOL, ns_fd)?,
            state: P::default(),
        })
    }
}
```

### Protocol-Specific Methods

```rust
// Route-specific methods
impl Connection<Route> {
    pub async fn get_links(&self) -> Result<Vec<LinkMessage>> { ... }
    pub async fn add_qdisc<Q: QdiscConfig>(&self, dev: &str, config: Q) -> Result<()> { ... }
    // ... all RTNetlink methods
}

// Generic-specific methods (can access self.state.cache)
impl Connection<Generic> {
    pub async fn get_family(&self, name: &str) -> Result<FamilyInfo> {
        // Check cache first
        if let Some(info) = self.state.cache.read().unwrap().get(name) {
            return Ok(info.clone());
        }
        // Query kernel, update cache...
        let info = self.query_family(name).await?;
        self.state.cache.write().unwrap().insert(name.to_string(), info.clone());
        Ok(info)
    }
    
    pub fn clear_cache(&self) {
        self.state.cache.write().unwrap().clear();
    }
}
```

### Usage

```rust
// Explicit protocol
let route = Connection::<Route>::new()?;
route.add_qdisc("eth0", netem).await?;  // OK

let genl = Connection::<Generic>::new()?;
genl.get_family("wireguard").await?;    // OK, uses cached family IDs

// Compile errors for wrong protocol
route.get_family("wireguard").await?;   // Error: method not found
genl.add_qdisc("eth0", netem).await?;   // Error: method not found

// Type aliases for convenience
pub type RouteConnection = Connection<Route>;
pub type GenlConnection = Connection<Generic>;
```

### Advantages Over Pure Phantom Types (Option A)

| Aspect | PhantomData | Stateful Protocol |
|--------|-------------|-------------------|
| Protocol state | Can't store per-protocol data | Each protocol has its own state |
| Family cache | Would need `Arc<RwLock<...>>` field anyway | Naturally part of `Generic` |
| Zero-size optimization | `Route` is zero-sized, no overhead | Same - `Route` is zero-sized |
| Future extensibility | Add fields = break the pattern | Add state to protocol struct |

### Advantages Over Separate Newtypes (Option B)

| Aspect | Newtypes | Stateful Protocol |
|--------|----------|-------------------|
| Code sharing | Need `ConnectionCore` or duplication | Single generic impl block |
| Namespace methods | Duplicate in each type | Single `impl<P>` block |
| Adding protocols | New struct + all method impls | New state struct + specific methods |
| Type relationships | Unrelated types | All are `Connection<P>` |

---

## 6. Removing Weakly-Typed `request()` Methods

The current API exposes low-level methods that bypass type safety:

```rust
// Current API - weakly typed
impl Connection {
    pub async fn request(&self, builder: MessageBuilder) -> Result<Vec<u8>> { ... }
    pub async fn dump(&self, builder: MessageBuilder) -> Result<Vec<Vec<u8>>> { ... }
}
```

**Problem**: A user can build any message type and send it on any connection:

```rust
let conn = Connection::<Generic>::new()?;
// Build a Route message and send on Generic socket - compiles!
let builder = dump_request(NlMsgType::RTM_GETLINK);
conn.dump(builder).await?;  // Runtime error
```

### Solution: Make Low-Level Methods Private or Protocol-Specific

**Option 1: Internal only (recommended for library use)**

```rust
impl<P: ProtocolState> Connection<P> {
    // Private - only used by high-level methods
    async fn send_request(&self, builder: MessageBuilder) -> Result<Vec<u8>> { ... }
    async fn send_dump(&self, builder: MessageBuilder) -> Result<Vec<Vec<u8>>> { ... }
}
```

Users must use typed methods like `get_links()`, `add_qdisc()`, `get_family()`.

**Option 2: Typed request builders per protocol**

```rust
// Route-specific request types
pub struct LinkDumpRequest { /* private */ }
pub struct QdiscAddRequest { config: Box<dyn QdiscConfig> }

impl Connection<Route> {
    pub async fn execute(&self, req: impl RouteRequest) -> Result<...> { ... }
}

// Generic-specific request types  
pub struct FamilyGetRequest { name: String }

impl Connection<Generic> {
    pub async fn execute(&self, req: impl GenlRequest) -> Result<...> { ... }
}
```

**Option 3: Keep for power users, document clearly**

```rust
impl<P: ProtocolState> Connection<P> {
    /// Low-level request method. Prefer typed methods like `get_links()`.
    /// 
    /// # Safety (logical)
    /// The message type must match this connection's protocol.
    pub async fn request_raw(&self, builder: MessageBuilder) -> Result<Vec<u8>> { ... }
}
```

### Recommendation

For a library-first design, **Option 1** is best:
- High-level typed methods are the public API
- Low-level methods are `pub(crate)` for internal use
- Power users can use `MessageBuilder` + `socket()` directly if needed

```rust
impl<P: ProtocolState> Connection<P> {
    /// Access the underlying socket for advanced use cases.
    pub fn socket(&self) -> &NetlinkSocket { &self.socket }
}

// Power users who need raw access:
let conn = Connection::<Route>::new()?;
let builder = dump_request(NlMsgType::RTM_GETLINK);
conn.socket().send(&builder.finish()).await?;
```

---

## 7. Historical Context: Code Duplication

The concern about "code duplication" with separate newtypes refers to **shared low-level methods** that exist in both `Connection` and `GenlConnection` today:

### Currently Duplicated Code

| Method | `Connection` | `GenlConnection` | Lines |
|--------|--------------|------------------|-------|
| `new()` | ✓ | ✓ | ~10 each |
| `new_in_namespace()` | ✓ | ✗ | ~15 |
| `new_in_namespace_path()` | ✓ | ✗ | ~10 |
| `socket()` accessor | ✓ | ✓ | 3 each |
| `request()` | ✓ | Similar (`command()`) | ~20 each |
| `dump()` | ✓ | Similar (`dump_command()`) | ~35 each |
| `process_response()` | ✓ | ✓ | ~15 each |
| `subscribe()` | ✓ | ✗ | 3 |
| `recv_event()` | ✓ | ✗ | 3 |

**Total duplicated low-level code: ~80-100 lines**

### The Duplication Is Already There

Looking at the current code, `GenlConnection` already duplicates much of `Connection`:

```rust
// In connection.rs (Connection)
pub async fn dump(&self, mut builder: MessageBuilder) -> Result<Vec<Vec<u8>>> {
    let seq = self.socket.next_seq();
    builder.set_seq(seq);
    builder.set_pid(self.socket.pid());
    let msg = builder.finish();
    self.socket.send(&msg).await?;
    // ... 30 more lines of response handling
}

// In genl/connection.rs (GenlConnection) 
pub async fn dump_command(&self, ...) -> Result<Vec<Vec<u8>>> {
    // ... GENL header setup ...
    let seq = self.socket.next_seq();
    builder.set_seq(seq);
    builder.set_pid(self.socket.pid());
    let msg = builder.finish();
    self.socket.send(&msg).await?;
    // ... 30 more lines of nearly identical response handling
}
```

### Solutions to Avoid Duplication

#### Solution 1: Extract to Free Functions (Simplest)

```rust
// In netlink/core.rs
pub(crate) async fn send_and_recv(
    socket: &NetlinkSocket,
    builder: MessageBuilder,
) -> Result<Vec<u8>> {
    let seq = socket.next_seq();
    // ... shared implementation
}

pub(crate) async fn send_and_dump(
    socket: &NetlinkSocket, 
    builder: MessageBuilder,
) -> Result<Vec<Vec<u8>>> {
    // ... shared implementation
}

// In RouteConnection
impl RouteConnection {
    pub async fn dump(&self, builder: MessageBuilder) -> Result<Vec<Vec<u8>>> {
        core::send_and_dump(&self.socket, builder).await
    }
}

// In GenlConnection  
impl GenlConnection {
    pub async fn dump_command(&self, ...) -> Result<Vec<Vec<u8>>> {
        let builder = self.build_genl_request(...);
        core::send_and_dump(&self.socket, builder).await
    }
}
```

**Lines of shared code: ~50 in `core.rs`**
**Lines per connection type: ~5 wrapper methods**

#### Solution 2: Composition with Inner Type

```rust
/// Shared netlink connection internals
pub(crate) struct ConnectionCore {
    socket: NetlinkSocket,
}

impl ConnectionCore {
    pub fn new(protocol: Protocol) -> Result<Self> { ... }
    pub fn new_in_namespace(protocol: Protocol, ns_fd: RawFd) -> Result<Self> { ... }
    pub async fn request(&self, builder: MessageBuilder) -> Result<Vec<u8>> { ... }
    pub async fn dump(&self, builder: MessageBuilder) -> Result<Vec<Vec<u8>>> { ... }
    pub fn subscribe(&mut self, group: u32) -> Result<()> { ... }
    pub async fn recv_event(&self) -> Result<Vec<u8>> { ... }
}

/// Route protocol connection
pub struct RouteConnection {
    core: ConnectionCore,
}

impl RouteConnection {
    pub fn new() -> Result<Self> {
        Ok(Self { core: ConnectionCore::new(Protocol::Route)? })
    }
    
    // Delegate to core
    pub async fn request(&self, builder: MessageBuilder) -> Result<Vec<u8>> {
        self.core.request(builder).await
    }
    
    // Route-specific methods
    pub async fn get_links(&self) -> Result<Vec<LinkMessage>> { ... }
    pub async fn add_qdisc(...) -> Result<()> { ... }
}

/// Generic netlink connection
pub struct GenlConnection {
    core: ConnectionCore,
    cache: Arc<RwLock<FamilyCache>>,  // GENL-specific state
}

impl GenlConnection {
    pub fn new() -> Result<Self> {
        Ok(Self { 
            core: ConnectionCore::new(Protocol::Generic)?,
            cache: Arc::new(RwLock::new(FamilyCache::default())),
        })
    }
    
    // GENL-specific methods
    pub async fn get_family(&self, name: &str) -> Result<FamilyInfo> { ... }
}
```

#### Solution 3: Deref to Shared Base (Not Recommended)

```rust
impl Deref for RouteConnection {
    type Target = ConnectionCore;
    fn deref(&self) -> &Self::Target { &self.core }
}
```

This exposes internal methods and creates a confusing API surface. **Not recommended.**

### Recommendation: Solution 2 (Composition)

Composition with `ConnectionCore` provides:

1. **Zero duplication** of low-level socket operations
2. **Type-specific state** (e.g., `GenlConnection` has cache, `RouteConnection` doesn't)
3. **Clear separation** between protocol-agnostic and protocol-specific code
4. **Explicit API** - users see only the methods relevant to their connection type
5. **Easy to extend** - adding `NetfilterConnection` just wraps `ConnectionCore`

### Why This Is No Longer a Concern

With the stateful protocol approach from Section 5, we get:
- Single `impl<P: ProtocolState> Connection<P>` block for shared methods
- Protocol-specific `impl Connection<Route>` and `impl Connection<Generic>` blocks
- No duplication, no `ConnectionCore` needed

---

## 8. Alternative: Runtime Validation (Minimal Change)

```rust
impl Connection {
    fn require_route(&self) -> Result<()> {
        if self.socket.protocol() != Protocol::Route {
            return Err(Error::protocol_mismatch("Route", self.socket.protocol()));
        }
        Ok(())
    }

    pub async fn add_qdisc<Q: QdiscConfig>(&self, dev: &str, config: Q) -> Result<()> {
        self.require_route()?;
        // ... implementation
    }
}
```

**Pros:**
- Minimal code changes
- Clear error messages
- No API changes

**Cons:**
- Still runtime error, not compile-time
- Slight performance overhead
- Doesn't help with IDE autocomplete

**Verdict:** Not recommended. If we're making changes, do it properly with compile-time safety.

---

## 9. Migration Strategy

Since backward compatibility is not a concern, the migration is straightforward:

### Step 1: Define Protocol State Types

```rust
// In netlink/protocol.rs
pub trait ProtocolState: private::Sealed + Default {
    const PROTOCOL: Protocol;
}

#[derive(Default)]
pub struct Route;
impl ProtocolState for Route {
    const PROTOCOL: Protocol = Protocol::Route;
}

pub struct Generic {
    cache: RwLock<HashMap<String, FamilyInfo>>,
}
impl Default for Generic { ... }
impl ProtocolState for Generic {
    const PROTOCOL: Protocol = Protocol::Generic;
}
```

### Step 2: Refactor Connection

```rust
// In netlink/connection.rs
pub struct Connection<P: ProtocolState> {
    socket: NetlinkSocket,
    state: P,
}

// Shared methods
impl<P: ProtocolState> Connection<P> {
    pub fn new() -> Result<Self> { ... }
    pub fn new_in_namespace(ns_fd: RawFd) -> Result<Self> { ... }
    pub fn new_in_namespace_path<T: AsRef<Path>>(path: T) -> Result<Self> { ... }
    pub fn socket(&self) -> &NetlinkSocket { ... }
    
    // Internal only
    async fn send_request(&self, builder: MessageBuilder) -> Result<Vec<u8>> { ... }
    async fn send_dump(&self, builder: MessageBuilder) -> Result<Vec<Vec<u8>>> { ... }
}
```

### Step 3: Move Methods to Protocol-Specific Impls

```rust
// Route-specific (was in connection.rs, link.rs, addr.rs, route.rs, tc.rs, neigh.rs)
impl Connection<Route> {
    pub async fn get_links(&self) -> Result<Vec<LinkMessage>> { ... }
    pub async fn add_qdisc<Q: QdiscConfig>(&self, dev: &str, config: Q) -> Result<()> { ... }
    // ... all RTNetlink methods
}

// Generic-specific (was in genl/connection.rs)
impl Connection<Generic> {
    pub async fn get_family(&self, name: &str) -> Result<FamilyInfo> { ... }
    pub async fn get_device(&self, name: &str) -> Result<WgDevice> { ... }
    // ... all GENL methods
}
```

### Step 4: Add Type Aliases

```rust
// In lib.rs - for discoverability
pub type RouteConnection = Connection<Route>;
pub type GenlConnection = Connection<Generic>;
```

### Step 5: Delete Old Code

- Remove `genl/connection.rs` (merged into `Connection<Generic>`)
- Remove `Protocol` parameter from constructors (inferred from `P::PROTOCOL`)

---

## 10. Comparison with Other Crates

| Crate | Approach | Type Safety |
|-------|----------|-------------|
| **nlink** (current) | Single `Connection` type | None |
| **rtnetlink** | Protocol-specific types (`Handle`, `RouteHandle`) | Partial |
| **netlink-packet-route** | Message types only, no connection | N/A |
| **neli** | Generic over socket type | Partial |

---

## 11. Example: Refactored API

```rust
use nlink::{Connection, Route, Generic, Result};
use nlink::{RouteConnection, GenlConnection};  // Type aliases

// Route protocol connection
let route = Connection::<Route>::new()?;
// Or using the alias:
let route = RouteConnection::new()?;

route.add_link(VethLink::new("veth0", "veth1")).await?;
route.apply_netem("veth0", netem).await?;
route.get_links().await?;

// Generic netlink connection  
let genl = Connection::<Generic>::new()?;
genl.get_family("wireguard").await?;  // Uses internal cache
genl.get_device("wg0").await?;

// Namespace-aware connections (both use same generic impl)
let route_ns = Connection::<Route>::new_in_namespace(ns_fd)?;
let genl_ns = Connection::<Generic>::new_in_namespace(ns_fd)?;

// Function that requires Route protocol
async fn setup_tc(conn: &Connection<Route>) -> Result<()> {
    conn.add_qdisc("eth0", FqCodelConfig::new()).await
}

// Function that requires Generic protocol
async fn get_wg_device(conn: &Connection<Generic>, name: &str) -> Result<WgDevice> {
    conn.get_device(name).await
}

// Compile-time errors for wrong protocol:
// route.get_family("wg");      // Error: method not found in Connection<Route>
// genl.add_qdisc("eth0", q);   // Error: method not found in Connection<Generic>
```

---

## 12. Conclusion

The current `Connection` abstraction has two type-safety issues:

1. **Protocol mismatch** - Can call Route methods on Generic connections
2. **Weak `request()`** - Can send any `MessageBuilder` on any connection

**Recommended approach**: Stateful protocol types with internal request methods:

| Benefit | Implementation |
|---------|----------------|
| **Compile-time protocol safety** | `Connection<P: ProtocolState>` with protocol-specific impls |
| **Per-protocol state** | `Generic` has cache, `Route` is zero-sized |
| **No code duplication** | Single `impl<P>` for shared methods |
| **No weak `request()`** | Make `send_request()` internal, expose typed methods only |
| **Namespace support for all** | Single `new_in_namespace()` in generic impl |
| **Easy extensibility** | Add `Netfilter` struct + `impl Connection<Netfilter>` |

This is a clean break from the current API, but since backward compatibility is not required, we get a properly typed API from the start.
