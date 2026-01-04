# Report: Plan 002 - Bridge FDB Management

## Summary

Implemented high-level API for managing bridge Forwarding Database (FDB) entries, enabling adding, deleting, and querying MAC address entries in Linux bridges and VXLAN devices.

## Changes Made

### New Files

| File | Description |
|------|-------------|
| `crates/nlink/src/netlink/fdb.rs` | FDB types and Connection methods (~550 lines) |

### Modified Files

| File | Change |
|------|--------|
| `crates/nlink/src/netlink/mod.rs` | Added `pub mod fdb;` export |
| `crates/nlink/src/netlink/types/neigh.rs` | Added `with_state()` and `with_flags()` builder methods to `NdMsg` |
| `crates/nlink/src/lib.rs` | Re-exported `FdbEntry` and `FdbEntryBuilder` at crate root |
| `CLAUDE.md` | Added Bridge FDB management documentation |

## API Added

### Types

- **`FdbEntry`**: Parsed FDB entry with fields:
  - `ifindex: u32` - Interface index (bridge port)
  - `mac: [u8; 6]` - MAC address
  - `vlan: Option<u16>` - VLAN ID
  - `dst: Option<IpAddr>` - Destination IP (for VXLAN)
  - `vni: Option<u32>` - VNI (for VXLAN)
  - `state: NeighborState` - Entry state
  - `flags: u8` - NTF_* flags
  - `master: Option<u32>` - Master bridge index
  - Methods: `is_permanent()`, `is_dynamic()`, `is_self()`, `is_master()`, `is_extern_learn()`, `mac_str()`

- **`FdbEntryBuilder`**: Builder for creating FDB entries
  - `new(mac: [u8; 6])` - Create with MAC address
  - `parse_mac(str)` - Parse MAC from string
  - `dev()` / `ifindex()` - Set device
  - `master()` / `master_ifindex()` - Set bridge
  - `vlan()` - Set VLAN ID
  - `dst()` - Set remote IP (VXLAN)
  - `vni()` - Set VNI (VXLAN)
  - `permanent()` / `dynamic()` - Set state
  - `self_()` - Set NTF_SELF flag

### Connection Methods

| Method | Description |
|--------|-------------|
| `get_fdb(bridge)` | Get all FDB entries for a bridge |
| `get_fdb_by_index(idx)` | Get FDB entries by bridge index |
| `get_fdb_for_port(bridge, port)` | Get FDB entries for a specific port |
| `add_fdb(builder)` | Add an FDB entry |
| `replace_fdb(builder)` | Replace/update an FDB entry |
| `del_fdb(dev, mac, vlan)` | Delete by device name |
| `del_fdb_by_index(idx, mac, vlan)` | Delete by interface index |
| `flush_fdb(bridge)` | Flush all dynamic entries |

## Implementation Notes

1. **Reused existing infrastructure**: FDB entries use the neighbor (RTM_NEWNEIGH/RTM_DELNEIGH) message types with AF_BRIDGE family. The existing `NeighborMessage` parsing handles all required attributes (NDA_LLADDR, NDA_VLAN, NDA_VNI, NDA_DST, NDA_MASTER).

2. **Added missing NdMsg builder methods**: The `with_state()` and `with_flags()` methods were added to `NdMsg` to support FDB entry creation.

3. **Namespace-aware design**: All methods have `*_by_index` variants to avoid reading `/sys/class/net/` from the wrong namespace when operating in network namespaces.

4. **VXLAN support**: The builder supports setting `dst` (remote VTEP IP) and `vni` for VXLAN FDB entries.

## Testing

- All 192 existing tests pass
- Added 9 new unit tests for FDB functionality:
  - `test_parse_mac` - MAC address parsing
  - `test_parse_mac_uppercase` - Case-insensitive parsing
  - `test_parse_mac_invalid` - Invalid MAC rejection
  - `test_fdb_entry_mac_str` - MAC formatting
  - `test_fdb_entry_flags` - Flag checking
  - `test_fdb_entry_permanent` - State checking
  - `test_builder_default` - Default builder state
  - `test_builder_chain` - Method chaining
  - `test_builder_ifindex` - Index-based configuration

## Clippy

All clippy warnings resolved:
- Removed unnecessary `as u32` casts (get_ifindex already returns u32)
- Used `if let` chain pattern for collapsible if statements

## Usage Example

```rust
use nlink::netlink::{Connection, Route};
use nlink::netlink::fdb::FdbEntryBuilder;

let conn = Connection::<Route>::new()?;

// Query FDB
let entries = conn.get_fdb("br0").await?;
for entry in &entries {
    println!("{} vlan={:?}", entry.mac_str(), entry.vlan);
}

// Add static entry
let mac = FdbEntryBuilder::parse_mac("aa:bb:cc:dd:ee:ff")?;
conn.add_fdb(
    FdbEntryBuilder::new(mac)
        .dev("veth0")
        .master("br0")
        .permanent()
).await?;

// Add VXLAN FDB entry
use std::net::Ipv4Addr;
conn.add_fdb(
    FdbEntryBuilder::new([0x00; 6])
        .dev("vxlan0")
        .dst(Ipv4Addr::new(192, 168, 1, 100).into())
).await?;

// Delete entry
conn.del_fdb("veth0", mac, None).await?;
```

## Future Work

- Add FDB event monitoring (RTM_NEWNEIGH/RTM_DELNEIGH with AF_BRIDGE)
- Support for FDB nexthop groups (modern Linux kernels)
