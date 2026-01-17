# Response: Namespace Interface Resolution - Fixed in 0.8.0

Thank you for the detailed bug report. This issue has been fully addressed in **nlink 0.8.0**.

## Summary of Fix

The namespace interface resolution bug has been fixed through a comprehensive architectural refactor. All operations that previously used sysfs-based `ifname_to_index()` now use netlink-based resolution via `Connection::resolve_interface()`, ensuring operations work correctly in any network namespace.

## What Changed in 0.8.0

### 1. New `InterfaceRef` Type

A new enum allows referencing interfaces by name or index:

```rust
pub enum InterfaceRef {
    Name(String),
    Index(u32),
}
```

### 2. Namespace-Safe Resolution

The connection now resolves interface names via netlink (RTM_GETLINK), not sysfs:

```rust
impl Connection<Route> {
    pub async fn resolve_interface(&self, iface: &InterfaceRef) -> Result<u32> {
        match iface {
            InterfaceRef::Index(idx) => Ok(*idx),
            InterfaceRef::Name(name) => {
                self.get_link_by_name(name).await?
                    .map(|l| l.ifindex())
                    .ok_or_else(|| Error::interface_not_found(name))
            }
        }
    }
}
```

### 3. Builder Refactoring

All builders (Address, Neighbor, Route, Link types) now store `InterfaceRef` internally and resolve names at operation time using the connection's namespace context.

### 4. New `_by_index` Convenience Methods

For users who already have interface indices, new methods avoid any name resolution:

```rust
// Address operations
conn.add_address_by_index(ifindex, addr, prefix_len).await?;
conn.replace_address_by_index(ifindex, addr, prefix_len).await?;

// Neighbor operations
conn.add_neighbor_v4_by_index(ifindex, dest, lladdr).await?;
conn.add_neighbor_v6_by_index(ifindex, dest, lladdr).await?;
conn.replace_neighbor_v4_by_index(ifindex, dest, lladdr).await?;
conn.replace_neighbor_v6_by_index(ifindex, dest, lladdr).await?;
```

---

## Migration Guide

### For Most Users: No Changes Required

If you use the high-level API with interface names, your code continues to work and is now namespace-safe:

```rust
// This now works correctly in namespaces (was broken in 0.7.x)
let conn: Connection<Route> = namespace::connection_for("myns")?;
conn.add_address(Ipv4Address::new("veth0", addr, 24)).await?;
conn.set_link_up("veth0").await?;
```

### Breaking Changes

#### 1. Method Renaming: `*_for()` to `*_by_name()`

Methods that query by interface name have been renamed for clarity:

| Old (0.7.x) | New (0.8.0) |
|-------------|-------------|
| `get_addresses_for("eth0")` | `get_addresses_by_name("eth0")` |
| `get_qdiscs_for("eth0")` | `get_qdiscs_by_name("eth0")` |
| `get_classes_for("eth0")` | `get_classes_by_name("eth0")` |
| `get_filters_for("eth0")` | `get_filters_by_name("eth0")` |
| `get_fdb_for_port("br0", "veth0")` | `get_fdb_by_port_name("br0", "veth0")` |

**Migration**: Find and replace in your codebase.

#### 2. Link Modification Methods Accept `InterfaceRef`

Methods like `set_link_master()` now accept `impl Into<InterfaceRef>`:

```rust
// Still works with strings
conn.set_link_master("veth0", "br0").await?;

// Now also works with indices (useful in namespaces)
conn.set_link_master(InterfaceRef::Index(5), InterfaceRef::Index(3)).await?;
```

#### 3. Builder `with_index()` Constructors

Builders now have index-based constructors:

```rust
// By name (resolves via netlink in the connection's namespace)
let addr = Ipv4Address::new("eth0", ip, 24);

// By index (no resolution needed)
let addr = Ipv4Address::with_index(5, ip, 24);
```

---

## Your Original Code - Now Works

The code from your bug report now works correctly:

```rust
use nlink::netlink::{namespace, Connection, Route};
use nlink::netlink::addr::Ipv4Address;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let conn: Connection<Route> = namespace::connection_for("myns")?;
    
    // This works - uses netlink for resolution
    let links = conn.get_links().await?;
    for link in &links {
        println!("Found interface: {} (index {})", 
            link.name().unwrap_or("?"), link.ifindex());
    }
    
    // This NOW WORKS - resolution happens via netlink in myns
    conn.add_address(Ipv4Address::new("veth0", "10.1.0.1".parse()?, 24)).await?;
    
    Ok(())
}
```

---

## Recommended Pattern for Namespace Operations

For best performance in namespace operations, resolve the interface index once and reuse it:

```rust
use nlink::netlink::{namespace, Connection, Route, InterfaceRef};
use nlink::netlink::addr::Ipv4Address;

let conn: Connection<Route> = namespace::connection_for("myns")?;

// Get interface index once
let link = conn.get_link_by_name("veth0").await?
    .ok_or("interface not found")?;
let ifindex = link.ifindex();

// Use index for all operations (avoids repeated lookups)
conn.add_address_by_index(ifindex, "10.1.0.1".parse()?, 24).await?;
conn.add_address_by_index(ifindex, "10.1.0.2".parse()?, 24).await?;
conn.set_link_up(InterfaceRef::Index(ifindex)).await?;

// TC operations also support by_index
conn.add_qdisc_by_index(ifindex, netem_config).await?;
```

---

## Changelog Entry

From CHANGELOG.md:

```markdown
## [0.8.0] - 2025-01-17

### Fixed
- **Namespace interface resolution**: All operations now use netlink-based 
  interface resolution instead of sysfs, fixing `namespace::connection_for()` 
  for operations like `add_address`, `set_link_up`, `add_qdisc`, etc.

### Added
- `InterfaceRef` enum for referencing interfaces by name or index
- `Connection::resolve_interface()` for namespace-safe name resolution
- Address operations: `add_address_by_index`, `replace_address_by_index`
- Neighbor operations: `add_neighbor_v4_by_index`, `add_neighbor_v6_by_index`,
  `replace_neighbor_v4_by_index`, `replace_neighbor_v6_by_index`
- Builder `with_index()` constructors for all affected types

### Changed (Breaking)
- Renamed `*_for()` query methods to `*_by_name()` for clarity
- `set_link_*` methods now accept `impl Into<InterfaceRef>`
```

---

## Upgrade Instructions

1. Update your `Cargo.toml`:
   ```toml
   nlink = "0.8"
   ```

2. Fix renamed methods (compile errors will guide you):
   - `get_addresses_for` -> `get_addresses_by_name`
   - `get_qdiscs_for` -> `get_qdiscs_by_name`
   - etc.

3. No other changes required for basic usage.

---

Thank you again for the detailed report. The fix ensures `namespace::connection_for()` is now fully functional for all operations.
