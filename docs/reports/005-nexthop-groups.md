# Plan 005: Nexthop Groups Implementation Report

## Summary

Implemented Linux nexthop objects and nexthop groups (Linux 5.3+) as specified in the plan. This provides a modern, efficient way to configure ECMP and weighted multipath routing.

## Implementation Details

### Files Created

1. **`crates/nlink/src/netlink/types/nexthop.rs`** (~200 lines)
   - Kernel structures for nexthop operations using zerocopy
   - `NhMsg` - nexthop message header (8 bytes)
   - `NexthopGrp` - group member entry (8 bytes)
   - Attribute constants: `nha::*`, `nhg_type::*`, `nhf::*`
   - Resilient group attributes: `nha_res_group::*`, `nha_res_bucket::*`

2. **`crates/nlink/src/netlink/nexthop.rs`** (~820 lines)
   - High-level types and builders:
     - `NexthopGroupType` enum (Multipath, Resilient)
     - `ResilientParams` struct for parsed resilient group parameters
     - `NexthopGroupMember` struct for group members
     - `Nexthop` struct with comprehensive parsing
     - `NexthopBuilder` for individual nexthops
     - `NexthopGroupBuilder` for nexthop groups
   - Connection methods for `Connection<Route>`

### Files Modified

1. **`crates/nlink/src/netlink/message.rs`**
   - Added nexthop message types: `RTM_NEWNEXTHOP` (104), `RTM_DELNEXTHOP` (105), `RTM_GETNEXTHOP` (106)

2. **`crates/nlink/src/netlink/types/mod.rs`**
   - Added `pub mod nexthop;`

3. **`crates/nlink/src/netlink/mod.rs`**
   - Added `pub mod nexthop;`

4. **`crates/nlink/src/netlink/route.rs`**
   - Added `nexthop_id` field to `Ipv4Route` and `Ipv6Route`
   - Added `nexthop_group()` method to both route builders
   - Updated `determine_scope()` to handle nexthop references
   - Updated `build()` to emit `RTA_NH_ID` attribute

5. **`CLAUDE.md`**
   - Added nexthop module to the module listing
   - Added comprehensive usage examples for nexthop operations

## API Surface

### NexthopBuilder

```rust
NexthopBuilder::new(id)
    .gateway(IpAddr)           // Gateway address (IPv4 or IPv6)
    .dev("eth0")               // Output interface by name
    .ifindex(5)                // Output interface by index
    .onlink()                  // Treat gateway as on-link
    .blackhole()               // Create blackhole nexthop
    .fdb()                     // Use for FDB lookups
    .protocol(proto)           // Routing protocol
    .build(msg_type, flags)    // Build the message
```

### NexthopGroupBuilder

```rust
NexthopGroupBuilder::new(id)
    .member(nh_id, weight)     // Add member with weight
    .resilient()               // Use resilient hashing
    .buckets(128)              // Bucket count (resilient)
    .idle_timer(120)           // Idle timer in seconds
    .unbalanced_timer(60)      // Unbalanced timer in seconds
    .build(msg_type, flags)    // Build the message
```

### Connection Methods

```rust
// Query operations
conn.get_nexthops().await?;           // All nexthops
conn.get_nexthop(id).await?;          // Single nexthop
conn.get_nexthop_groups().await?;     // Only groups

// Nexthop CRUD
conn.add_nexthop(builder).await?;
conn.replace_nexthop(builder).await?;
conn.del_nexthop(id).await?;

// Group CRUD
conn.add_nexthop_group(builder).await?;
conn.replace_nexthop_group(builder).await?;
conn.del_nexthop_group(id).await?;
```

### Route Integration

```rust
// Use nexthop group in routes
Ipv4Route::new("10.0.0.0", 8)
    .nexthop_group(100)  // Reference group ID 100

Ipv6Route::new("2001:db8::", 32)
    .nexthop_group(100)
```

## Testing

- All 212 existing tests pass
- Added new unit tests:
  - `test_nexthop_builder` - Basic builder functionality
  - `test_nexthop_builder_blackhole` - Blackhole nexthop
  - `test_nexthop_group_builder` - Group builder with members
  - `test_group_type_conversion` - GroupType enum roundtrip
- Clippy passes with no warnings

## Benefits Over Legacy RTA_MULTIPATH

1. **Efficiency**: Nexthops are shared objects, reducing memory usage
2. **Atomic updates**: Modify nexthop once, all referencing routes update
3. **Resilient hashing**: Flow affinity maintained during member changes
4. **Better ECMP**: More control over load balancing behavior
5. **Cleaner API**: Separate nexthop and route management

## Linux Kernel Requirements

- Linux 5.3+ for basic nexthop support
- Linux 5.11+ for resilient nexthop groups

## Notes

- Nexthop IDs and group IDs share the same namespace
- Deleting a nexthop/group in use by routes will fail
- The `RTA_NH_ID` attribute (value 30) was already defined in the codebase
