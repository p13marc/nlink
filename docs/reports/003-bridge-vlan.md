# Report: Plan 003 - Bridge VLAN Filtering

## Summary

Implemented API for managing per-port VLAN configuration on Linux bridges with VLAN filtering enabled. This enables adding, deleting, and querying VLANs on bridge ports, setting PVID, and configuring tagged/untagged modes.

## Changes Made

### New Files

| File | Description |
|------|-------------|
| `crates/nlink/src/netlink/bridge_vlan.rs` | Bridge VLAN types and Connection methods (~600 lines) |

### Modified Files

| File | Change |
|------|--------|
| `crates/nlink/src/netlink/types/link.rs` | Added `bridge_af`, `bridge_vlan_flags`, `BridgeVlanInfo`, `rtext_filter` modules |
| `crates/nlink/src/netlink/mod.rs` | Added `pub mod bridge_vlan;` export |
| `crates/nlink/src/lib.rs` | Re-exported `BridgeVlanBuilder`, `BridgeVlanEntry`, `BridgeVlanFlags` at crate root |
| `CLAUDE.md` | Added Bridge VLAN filtering documentation |

## API Added

### Types

- **`BridgeVlanFlags`**: VLAN flags with fields:
  - `pvid: bool` - Is this the Port VLAN ID
  - `untagged: bool` - Strip VLAN tag on egress
  - Method: `from_raw(u16)`

- **`BridgeVlanEntry`**: Parsed VLAN entry with fields:
  - `ifindex: u32` - Interface index
  - `vid: u16` - VLAN ID (1-4094)
  - `flags: BridgeVlanFlags` - VLAN flags
  - Methods: `is_pvid()`, `is_untagged()`

- **`BridgeVlanBuilder`**: Builder for VLAN operations
  - `new(vid: u16)` - Create for single VID
  - `dev()` / `ifindex()` - Set device
  - `range(vid_end)` - Set range end for bulk operations
  - `pvid()` - Mark as PVID
  - `untagged()` - Mark as untagged
  - `master()` - Apply to bridge device

### Kernel Types Added

- **`BridgeVlanInfo`**: Kernel struct `bridge_vlan_info` (4 bytes)
  - `flags: u16` - BRIDGE_VLAN_INFO_* flags
  - `vid: u16` - VLAN ID
  - Methods: `is_pvid()`, `is_untagged()`, `is_range_begin()`, `is_range_end()`

- **`bridge_af`**: IFLA_BRIDGE_* constants
- **`bridge_vlan_flags`**: BRIDGE_VLAN_INFO_* constants
- **`rtext_filter`**: RTEXT_FILTER_* constants for extended link info

### Connection Methods

| Method | Description |
|--------|-------------|
| `get_bridge_vlans(dev)` | Get VLANs for a port |
| `get_bridge_vlans_by_index(idx)` | Get VLANs by interface index |
| `get_bridge_vlans_all(bridge)` | Get VLANs for all ports of a bridge |
| `get_bridge_vlans_all_by_index(idx)` | Get all VLANs by bridge index |
| `add_bridge_vlan(builder)` | Add VLAN(s) to a port |
| `del_bridge_vlan(dev, vid)` | Delete single VLAN |
| `del_bridge_vlan_by_index(idx, vid)` | Delete by interface index |
| `del_bridge_vlan_range(dev, start, end)` | Delete VLAN range |
| `set_bridge_pvid(dev, vid)` | Set PVID (adds as pvid+untagged) |
| `set_bridge_pvid_by_index(idx, vid)` | Set PVID by index |
| `add_bridge_vlan_tagged(dev, vid)` | Add tagged VLAN (convenience) |
| `add_bridge_vlan_range(dev, start, end)` | Add VLAN range (convenience) |

## Implementation Notes

1. **RTM_SETLINK with AF_BRIDGE**: Bridge VLAN configuration uses `RTM_SETLINK` with `AF_BRIDGE` family and `IFLA_AF_SPEC` containing `IFLA_BRIDGE_VLAN_INFO` attributes.

2. **Range support**: VLAN ranges are encoded as two `bridge_vlan_info` entries with `RANGE_BEGIN` and `RANGE_END` flags.

3. **Query with RTEXT_FILTER_BRVLAN**: To get VLAN info, we request links with `IFLA_EXT_MASK` set to `RTEXT_FILTER_BRVLAN`.

4. **Namespace-aware design**: All methods have `*_by_index` variants for network namespace operations.

## Testing

- All 199 tests pass (7 new for bridge_vlan)
- New unit tests:
  - `test_bridge_vlan_flags_from_raw` - Flag parsing
  - `test_bridge_vlan_entry_helpers` - Entry helper methods
  - `test_builder_default` - Default builder state
  - `test_builder_chain` - Method chaining
  - `test_builder_range` - Range configuration
  - `test_builder_ifindex` - Index-based configuration
  - `test_build_flags` - Flag building

## Clippy

All clippy warnings resolved (used `if let` chain pattern).

## Usage Example

```rust
use nlink::netlink::{Connection, Route};
use nlink::netlink::bridge_vlan::BridgeVlanBuilder;

let conn = Connection::<Route>::new()?;

// Query VLANs
let vlans = conn.get_bridge_vlans("eth0").await?;
for vlan in &vlans {
    println!("VLAN {}: pvid={} untagged={}",
        vlan.vid, vlan.flags.pvid, vlan.flags.untagged);
}

// Set PVID (native VLAN)
conn.set_bridge_pvid("eth0", 100).await?;

// Add tagged VLAN range
conn.add_bridge_vlan_range("eth0", 200, 210).await?;

// Delete VLAN
conn.del_bridge_vlan("eth0", 100).await?;
```

## Future Work

- Bridge VLAN tunneling (VLAN-to-VNI mapping for VXLAN)
- Per-VLAN STP state
- VLAN statistics
