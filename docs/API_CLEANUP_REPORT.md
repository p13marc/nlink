# API Cleanup and Refactoring Report

## Overview

This document summarizes the API cleanup refactoring performed on the nlink library, covering the removal of low-level APIs from public visibility, type alias cleanup, and binary command refactoring.

## Changes Made

### 1. Low-Level API Visibility Change

**Change**: Made `send_request()`, `send_ack()`, and `send_dump()` methods `pub(crate)` instead of `pub`.

**Files Modified**:
- `crates/nlink/src/netlink/connection.rs`

**Rationale**: These low-level methods bypass type safety and allow users to send arbitrary netlink messages. Making them internal-only enforces use of the typed, safe high-level APIs.

### 2. Type Aliases Removed

**Change**: Removed `RouteConnection` and `GenlConnection` type aliases.

**Files Modified**:
- `crates/nlink/src/netlink/mod.rs`
- `crates/nlink/src/lib.rs`

**Rationale**: These aliases added indirection without value. Users should use explicit `Connection<Route>` and `Connection<Generic>` types for clarity.

### 3. Examples Reorganization

**Change**: Reorganized examples into protocol-based subdirectories.

**New Structure**:
```
examples/
├── route/           # Route protocol examples
│   ├── tc/          # Traffic control examples
│   └── ...
├── events/          # Event monitoring examples
└── namespace/       # Namespace examples
```

### 4. New High-Level APIs Added

**RuleBuilder** (`crates/nlink/src/netlink/rule.rs`):
- `RuleBuilder::new(family)` - Create routing rules
- `conn.get_rules()` - Get all routing rules
- `conn.get_rules_for_family(family)` - Get rules for specific address family
- `conn.add_rule(builder)` - Add a routing rule
- `conn.del_rule(builder)` - Delete a routing rule
- `conn.flush_rules(family)` - Flush all rules for a family

### 5. Binary Command Refactoring

All binary commands were refactored to use high-level APIs instead of low-level `send_*` methods.

| File | Changes |
|------|---------|
| `bins/ip/src/commands/address.rs` | Uses `conn.add_address()`, `conn.del_address()` |
| `bins/ip/src/commands/link.rs` | Uses `conn.set_link_up()`, `conn.set_link_down()`, `conn.set_link_mtu()` |
| `bins/ip/src/commands/link_add.rs` | Uses `conn.add_link()` with typed builders |
| `bins/ip/src/commands/neighbor.rs` | Uses `conn.get_neighbors()`, `conn.add_neighbor()`, `conn.del_neighbor()` |
| `bins/ip/src/commands/route.rs` | Uses `conn.get_routes()`, `conn.add_route()`, `conn.del_route()` |
| `bins/ip/src/commands/rule.rs` | Uses new `RuleBuilder` API |
| `bins/ip/src/commands/tunnel.rs` | Uses typed link builders (`GreLink`, `IpipLink`, etc.) |
| `bins/ip/src/commands/vrf.rs` | Uses `conn.get_links()` with filtering |
| `bins/tc/src/commands/action.rs` | Uses `conn.get_actions()` |

---

## Issues Discovered During Refactoring

### 1. Missing `get_route()` Method

**Problem**: No single-route lookup method exists.

**Workaround Used**: 
```rust
let routes = conn.get_routes().await?;
let matching: Vec<_> = routes
    .into_iter()
    .filter(|r| r.destination == Some(dst_addr) && r.dst_len() == prefix_len)
    .collect();
```

**Recommendation**: Add `get_route(destination, prefix_len)` method that uses `RTM_GETROUTE` with `NLM_F_REQUEST` (not dump) to get a specific route efficiently.

### 2. No `change_link()` Method for Tunnels

**Problem**: Tunnel parameters cannot be modified in-place.

**Current Behavior**: Returns error suggesting delete/recreate.

**Recommendation**: Either implement `change_link()` for tunnel types that support it, or document this limitation clearly in the API.

### 3. IpvlanLink Cannot Set MAC Address

**Problem**: Code attempted to call `.address()` on `IpvlanLink`, but ipvlan interfaces inherit their MAC from the parent device.

**Resolution**: Removed the call and added a comment explaining the limitation.

**Recommendation**: Consider making this a compile-time constraint by not implementing a trait or method for link types that don't support address setting.

### 4. Inconsistent Field Access Patterns

**Problem**: Some message types use methods (`family()`, `dst_len()`), while others use direct field access (`priority`, `table`).

**Examples**:
- `RuleMessage.family()` - method
- `RuleMessage.priority` - field
- `RouteMessage.dst_len()` - method
- `RouteMessage.destination` - field

**Recommendation**: Standardize on one approach. Methods provide better encapsulation and allow future changes without breaking API.

### 5. Type Alias Location in Module

**Problem**: Clippy warned about items after test module.

**Resolution**: Moved `QdiscMessage`, `ClassMessage`, `FilterMessage` type aliases before the `#[cfg(test)]` module.

**Recommendation**: Establish a module structure convention:
1. Imports
2. Constants
3. Types/Structs
4. Implementations
5. Type aliases
6. Tests (always last)

---

## API Gaps Identified

### High Priority

| Missing API | Current Workaround | Suggested Method |
|-------------|-------------------|------------------|
| Get single route | Filter `get_routes()` result | `get_route(dst, prefix_len)` |
| Modify tunnel | Delete + recreate | `change_link()` or document limitation |

### Medium Priority

| Missing API | Description |
|-------------|-------------|
| `get_link_by_index(ifindex)` | Get link by index instead of name |
| `get_address_by_ip(addr)` | Find address entry by IP |
| Batch operations | Add/delete multiple routes/rules atomically |

### Low Priority

| Missing API | Description |
|-------------|-------------|
| `get_routes_for_device(dev)` | Filter routes by output interface |
| `get_neighbors_for_device(dev)` | Filter neighbors by interface |

---

## Code Quality Observations

### Positive Patterns

1. **Builder pattern** - Consistent use across link types, routes, rules
2. **Type safety** - `Connection<Route>` vs `Connection<Generic>` prevents misuse
3. **Error handling** - Semantic error methods (`is_not_found()`, `is_permission_denied()`)
4. **Zero-copy parsing** - Efficient use of `zerocopy` crate

### Areas for Improvement

1. **Documentation consistency** - Some methods lack examples
2. **Error messages** - Could include more context (e.g., which interface failed)
3. **Validation** - Some builders don't validate parameters until netlink call fails
4. **Testing** - Integration tests require root/netns, making CI difficult

---

## Lessons Learned

### 1. API Design

- **Make low-level APIs private by default** - Exposing internals creates maintenance burden
- **Prefer methods over field access** - Allows internal representation changes
- **Type aliases aid discoverability** - `QdiscMessage` is easier to find than knowing `TcMessage` works for qdiscs

### 2. Refactoring Process

- **Compile after each change** - Catches cascading errors early
- **Use clippy --fix** - Automates simple fixes
- **Check all binaries** - Library changes can break downstream code in unexpected ways

### 3. Netlink Specifics

- **Some operations aren't supported** - e.g., changing tunnel parameters requires delete/recreate
- **Interface types have different capabilities** - Not all link types support all operations (e.g., ipvlan can't set MAC)
- **Filtering is often client-side** - Netlink dumps everything; filtering happens in userspace

---

## Recommendations for Future Work

### Short Term

1. Add `get_route()` method for single-route lookup
2. Document tunnel modification limitations
3. Add validation to builders before netlink calls
4. Standardize field access (all methods or all public fields)

### Medium Term

1. Add batch operation support (multiple routes/rules in one call)
2. Improve error messages with context
3. Add more integration test coverage using network namespaces
4. Consider builder validation traits

### Long Term

1. Explore compile-time constraints for link type capabilities
2. Consider async stream APIs for large dumps
3. Add tracing/logging support for debugging
4. Performance benchmarks against iproute2

---

## Files Changed Summary

| Category | Files |
|----------|-------|
| Library core | 3 files |
| New modules | 1 file (`rule.rs`) |
| Binary commands | 8 files |
| Examples | 16 files (reorganized) |
| Documentation | 1 file (this report) |

**Total lines changed**: ~500 (excluding moves/reorganization)

---

## Conclusion

The refactoring successfully:
- Hid low-level APIs from public use
- Removed unnecessary type aliases
- Refactored all binaries to use high-level APIs
- Added new `RuleBuilder` API
- Identified several areas for future improvement

The codebase is now cleaner with a more consistent API surface. The identified gaps and recommendations provide a roadmap for continued improvement.
