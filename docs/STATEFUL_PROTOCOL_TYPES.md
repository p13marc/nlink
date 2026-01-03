# Stateful Protocol Types for Connection

This document describes the refactoring of the `Connection` type to use stateful protocol types, providing compile-time safety for protocol-specific operations.

## Overview

The `Connection` struct has been refactored from a single type that accepts any `Protocol` argument to a generic `Connection<P: ProtocolState>` that provides compile-time guarantees about which methods are available.

### Before

```rust
// Single Connection type with runtime protocol selection
let conn = Connection::new(Protocol::Route)?;
conn.get_links().await?;  // Works, but...
conn.get_family("wireguard").await?;  // Runtime error - wrong protocol!

// Separate GenlConnection with duplicated socket handling
let genl = GenlConnection::new()?;
genl.get_family("wireguard").await?;
```

### After

```rust
// Protocol is encoded in the type
let route = Connection::<Route>::new()?;
route.get_links().await?;  // Compile-time guaranteed to work

let genl = Connection::<Generic>::new()?;
genl.get_family("wireguard").await?;  // Only available on Generic
```

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Connection<P>                             │
│  ┌─────────────────────────────────────────────────────────┐│
│  │ impl<P: ProtocolState> Connection<P>                    ││
│  │   - new() / new_in_namespace() / new_in_namespace_path()││
│  │   - socket() / state()                                  ││
│  │   - send_request() / send_ack() / send_dump()           ││
│  └─────────────────────────────────────────────────────────┘│
│                           │                                  │
│           ┌───────────────┴───────────────┐                  │
│           ▼                               ▼                  │
│  ┌─────────────────────┐      ┌─────────────────────┐       │
│  │ impl Connection<    │      │ impl Connection<    │       │
│  │      Route>         │      │      Generic>       │       │
│  │                     │      │                     │       │
│  │ - get_links()       │      │ - get_family()      │       │
│  │ - get_addresses()   │      │ - get_family_id()   │       │
│  │ - get_routes()      │      │ - clear_cache()     │       │
│  │ - add_qdisc()       │      │ - command()         │       │
│  │ - subscribe()       │      │ - dump_command()    │       │
│  │ - recv_event()      │      │                     │       │
│  │ - ...               │      │                     │       │
│  └─────────────────────┘      └─────────────────────┘       │
└─────────────────────────────────────────────────────────────┘
```

## Protocol State Types

### Route (Zero-Sized)

The `Route` type is used for RTNetlink operations (interfaces, addresses, routes, neighbors, traffic control). It carries no state.

```rust
#[derive(Debug, Default, Clone, Copy)]
pub struct Route;

impl ProtocolState for Route {
    const PROTOCOL: Protocol = Protocol::Route;
}
```

### Generic (Stateful)

The `Generic` type is used for Generic Netlink operations (WireGuard, MACsec, etc.). It carries a cache of resolved family IDs.

```rust
pub struct Generic {
    pub(crate) cache: RwLock<HashMap<String, FamilyInfo>>,
}

impl ProtocolState for Generic {
    const PROTOCOL: Protocol = Protocol::Generic;
}
```

The cache eliminates repeated kernel queries for family IDs, improving performance when making multiple requests to the same family.

## Files Modified

### Core Changes

| File | Changes |
|------|---------|
| `netlink/protocol.rs` | **NEW**: `ProtocolState` trait, `Route`, `Generic` types |
| `netlink/connection.rs` | Refactored to `Connection<P>`, added `impl Connection<Generic>` |
| `netlink/mod.rs` | Added exports for protocol types |
| `lib.rs` | Re-exported `Route`, `Generic` |

### Extension Files

All extension impl blocks changed from `impl Connection` to `impl Connection<Route>`:

- `netlink/link.rs`
- `netlink/addr.rs`
- `netlink/route.rs`
- `netlink/neigh.rs`
- `netlink/tc.rs`
- `netlink/filter.rs`

### Consumer Updates

| File | Changes |
|------|---------|
| `netlink/events.rs` | `EventStream` uses `Connection<Route>` |
| `netlink/namespace.rs` | Functions return `Connection<Route>` |
| `netlink/genl/connection.rs` | Reduced to only `FamilyInfo` definition |
| `netlink/genl/wireguard/connection.rs` | Uses `Connection<Generic>` |

### Binaries and Examples

All binaries (`ip`, `tc`) and examples updated to use:
- `Connection::<Route>::new()` instead of `Connection::new(Protocol::Route)`
- `Connection<Route>` in function signatures

## Breaking Changes

| Before | After |
|--------|-------|
| `Connection::new(Protocol::Route)` | `Connection::<Route>::new()` |
| `Connection::new(Protocol::Generic)` | `Connection::<Generic>::new()` |
| `GenlConnection::new()` (struct) | `Connection::<Generic>::new()` |
| `conn.request(builder)` | `conn.send_request(builder)` |
| `conn.request_ack(builder)` | `conn.send_ack(builder)` |
| `conn.dump(builder)` | `conn.send_dump(builder)` |

### Migration Guide

**Creating connections:**
```rust
// Before
let conn = Connection::new(Protocol::Route)?;

// After
let conn = Connection::<Route>::new()?;
```

**Function signatures:**
```rust
// Before
async fn do_something(conn: &Connection) -> Result<()>

// After
async fn do_something(conn: &Connection<Route>) -> Result<()>
```

**Generic netlink:**
```rust
// Before
let genl = GenlConnection::new()?;

// After
let genl = Connection::<Generic>::new()?;
```

## Benefits

1. **Compile-Time Safety**: Route methods only available on `Connection<Route>`, Generic methods only on `Connection<Generic>`. Misuse is a compile error, not a runtime error.

2. **Stateful Caching**: The `Generic` type carries the family ID cache directly, eliminating the need for a separate wrapper struct with duplicated socket handling code.

3. **No Code Duplication**: Shared logic (socket operations, namespace handling) is in the generic `impl<P>` block, while protocol-specific methods are in specialized impl blocks.

4. **Clear API**: Type parameters make it explicit which protocol a connection uses.

5. **Sealed Trait**: The `ProtocolState` trait is sealed, preventing external implementations and ensuring only supported protocols can be used.

## Low-Level API

The low-level methods `send_request()`, `send_ack()`, and `send_dump()` are still public but documented as low-level. Prefer using typed methods when available:

```rust
// Preferred: typed high-level API
let links = conn.get_links().await?;
conn.add_route(route).await?;

// Low-level: only when no typed method exists
let response = conn.send_request(builder).await?;
```

## Future Considerations

- Additional protocol types could be added (e.g., `SockDiag` for socket diagnostics) following the same pattern
- The `ProtocolState` trait could be extended with associated types for protocol-specific error handling
- Method-level feature flags could hide certain methods based on compile-time features
