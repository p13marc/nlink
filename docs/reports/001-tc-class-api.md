# Report: TC Class API on Connection

**Plan:** [001-tc-class-api.md](../plans/001-tc-class-api.md)  
**Branch:** `feature/plan-001-tc-class-api`  
**Date:** 2026-01-04  
**Status:** Completed

## Summary

Exposed TC class management operations as methods on `Connection<Route>`, providing a consistent API alongside existing qdisc and filter operations. Users can now add, delete, change, and replace TC classes directly through the Connection API.

## Changes Made

### `crates/nlink/src/netlink/tc.rs`

Added 8 new methods to `impl Connection<Route>`:

**Primary methods (by device name):**
- `add_class(dev, parent, classid, kind, params)` - Add a new TC class
- `del_class(dev, parent, classid)` - Delete a TC class
- `change_class(dev, parent, classid, kind, params)` - Change class parameters
- `replace_class(dev, parent, classid, kind, params)` - Add or update a class

**By-index variants (for namespace operations):**
- `add_class_by_index(ifindex, parent, classid, kind, params)`
- `del_class_by_index(ifindex, parent, classid)`
- `change_class_by_index(ifindex, parent, classid, kind, params)`
- `replace_class_by_index(ifindex, parent, classid, kind, params)`

**Helper functions added:**
- `add_class_options(builder, kind, params)` - Add class-specific options to message builder
- `add_htb_class_options(builder, params)` - Build HTB class options (rate, ceil, burst, etc.)
- `compute_htb_rate_table(rate, mtu)` - Compute rate table for HTB class

### `CLAUDE.md`

Added "TC class management" section with comprehensive examples showing:
- Adding HTB qdisc and classes
- Querying classes
- Changing and replacing class parameters
- Deleting classes
- Using `*_by_index` variants for namespace operations

## API Design

The class methods follow the same pattern as existing qdisc methods:

```rust
// Add a class
conn.add_class("eth0", "1:0", "1:10", "htb", 
    &["rate", "10mbit", "ceil", "100mbit"]).await?;

// Delete a class
conn.del_class("eth0", "1:0", "1:10").await?;

// Change class parameters
conn.change_class("eth0", "1:0", "1:10", "htb",
    &["rate", "20mbit"]).await?;

// Replace (add or update)
conn.replace_class("eth0", "1:0", "1:10", "htb",
    &["rate", "15mbit"]).await?;
```

### HTB Class Parameters

The following parameters are supported for HTB classes:

| Parameter | Description |
|-----------|-------------|
| `rate` | Guaranteed bandwidth (e.g., "10mbit", "1gbit") |
| `ceil` | Maximum bandwidth (defaults to rate) |
| `burst` / `buffer` | Burst size in bytes |
| `cburst` / `cbuffer` | Ceil burst size |
| `prio` | Priority (0-7) |
| `quantum` | Quantum for round-robin |
| `mtu` | MTU for rate calculations (default: 1600) |
| `mpu` | Minimum packet unit |
| `overhead` | Per-packet overhead |

## Implementation Notes

1. **No feature gate dependency**: The class methods are implemented directly in `netlink/tc.rs` without depending on the feature-gated `tc` module. The HTB options building logic was moved inline.

2. **Consistent with existing patterns**: The API matches the style of `add_qdisc`, `del_qdisc`, etc.

3. **Namespace support**: All methods have `*_by_index` variants for namespace-aware operations.

4. **Rate tables**: HTB classes require rate tables for scheduling. The implementation computes these automatically based on the specified rate and MTU.

## Verification

| Check | Result |
|-------|--------|
| `cargo build -p nlink` | Pass |
| `cargo test -p nlink` | 183 tests pass |
| `cargo clippy -p nlink --all-targets -- -D warnings` | Pass (no warnings) |

## Files Changed

```
 CLAUDE.md                              |  35 ++++-
 crates/nlink/src/netlink/tc.rs         | 403 ++++++++++++++++++++++++++++++++
 2 files changed, 438 insertions(+)
```

## Future Work

- [Plan 004: HTB Class Typed Builder](../plans/004-htb-class-builder.md) will provide a type-safe builder API instead of string parameters:

```rust
// Future typed API
let class = HtbClassConfig::new()
    .rate(Rate::mbit(10))
    .ceil(Rate::mbit(100))
    .prio(1)
    .build();
conn.add_class("eth0", "1:0", "1:10", class).await?;
```
