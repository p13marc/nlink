# Plan 009: MPTCP (Multipath TCP) Endpoints Implementation Report

## Summary

Implemented MPTCP endpoint configuration via Generic Netlink, enabling management of additional addresses/interfaces for multipath TCP connections. This allows bandwidth aggregation across multiple paths and seamless failover between networks.

## Implementation Details

### Files Created

1. **`crates/nlink/src/netlink/types/mptcp.rs`** (~110 lines)
   - Kernel constants for MPTCP Path Manager GENL interface:
     - `mptcp_pm_cmd::*` - GENL commands (ADD_ADDR, DEL_ADDR, GET_ADDR, etc.)
     - `mptcp_pm_attr::*` - Top-level attributes (ADDR, SUBFLOWS, RCV_ADD_ADDRS)
     - `mptcp_pm_addr_attr::*` - Address attributes (ID, ADDR4, ADDR6, PORT, FLAGS, IF_IDX)
     - `mptcp_pm_flags::*` - Endpoint flags (SIGNAL, SUBFLOW, BACKUP, FULLMESH)

2. **`crates/nlink/src/netlink/genl/mptcp/mod.rs`** (~45 lines)
   - Module entry point with exports
   - Constants: `MPTCP_PM_GENL_NAME`, `MPTCP_PM_GENL_VERSION`

3. **`crates/nlink/src/netlink/genl/mptcp/types.rs`** (~320 lines)
   - Type definitions:
     - `MptcpFlags` - signal, subflow, backup, fullmesh flags with raw conversion
     - `MptcpEndpoint` - Parsed endpoint info (id, address, port, ifindex, flags)
     - `MptcpEndpointBuilder` - Builder for endpoint configuration
     - `MptcpLimits` - Limits configuration (subflows, add_addr_accepted)

4. **`crates/nlink/src/netlink/genl/mptcp/connection.rs`** (~510 lines)
   - `Connection<Mptcp>` implementation:
     - `new_async()` - Async constructor with GENL family resolution
     - `family_id()` - Access resolved family ID
     - `get_endpoints()` - List all configured endpoints
     - `add_endpoint()` - Add a new endpoint
     - `del_endpoint()` - Delete endpoint by ID
     - `flush_endpoints()` - Remove all endpoints
     - `get_limits()` - Query current limits
     - `set_limits()` - Set subflow and address limits
     - `set_endpoint_flags()` - Update endpoint flags

### Files Modified

1. **`crates/nlink/src/netlink/protocol.rs`**
   - Added `Mptcp` protocol state type with `family_id: u16`
   - Implemented `private::Sealed` and `ProtocolState` traits
   - Updated tests

2. **`crates/nlink/src/netlink/mod.rs`**
   - Added `Mptcp` to protocol re-exports

3. **`crates/nlink/src/netlink/types/mod.rs`**
   - Added `pub mod mptcp;`

4. **`crates/nlink/src/netlink/genl/mod.rs`**
   - Added `pub mod mptcp;`

5. **`CLAUDE.md`**
   - Added mptcp module to architecture section
   - Added comprehensive MPTCP usage examples

## API Surface

### MptcpFlags

```rust
pub struct MptcpFlags {
    pub signal: bool,    // Announce to peers via ADD_ADDR
    pub subflow: bool,   // Use for creating new subflows
    pub backup: bool,    // Mark as backup path (lower priority)
    pub fullmesh: bool,  // Create subflows to all peer addresses
}
```

### MptcpEndpointBuilder

```rust
MptcpEndpointBuilder::new(address)
    .id(1)              // Endpoint ID (0-255, optional)
    .port(8080)         // Optional port
    .dev("eth1")        // Device by name
    .ifindex(3)         // Or by interface index
    .signal()           // Set signal flag
    .subflow()          // Set subflow flag
    .backup()           // Set backup flag
    .fullmesh()         // Set fullmesh flag
```

### MptcpLimits

```rust
MptcpLimits::new()
    .subflows(4)           // Max subflows per connection
    .add_addr_accepted(4)  // Max addresses to accept from peers
```

### MptcpEndpoint

```rust
pub struct MptcpEndpoint {
    pub id: u8,
    pub address: IpAddr,
    pub port: Option<u16>,
    pub ifindex: Option<u32>,
    pub flags: MptcpFlags,
}
```

### Connection Methods

```rust
// Async connection constructor
Connection::<Mptcp>::new_async().await?;

// Endpoint management
conn.get_endpoints().await?;
conn.add_endpoint(builder).await?;
conn.del_endpoint(id).await?;
conn.flush_endpoints().await?;
conn.set_endpoint_flags(id, flags).await?;

// Limits management
conn.get_limits().await?;
conn.set_limits(limits).await?;
```

## MPTCP Concepts

### Endpoint Flags

| Flag | Description |
|------|-------------|
| `signal` | Announce address to peers via ADD_ADDR option |
| `subflow` | Use this address to initiate new subflows |
| `backup` | Mark as backup path (used only when primary fails) |
| `fullmesh` | Create subflows to all peer addresses |

### Common Use Cases

1. **Bandwidth Aggregation**: Use multiple interfaces simultaneously
   - Add endpoints with `signal()` and `subflow()` flags

2. **Failover**: Seamless switch between networks
   - Primary: `subflow()` + `signal()`
   - Backup: `backup()` + `signal()`

3. **Mobile Devices**: WiFi/cellular handoff
   - WiFi endpoint as primary
   - Cellular as backup

## Testing

- All 273 unit tests pass
- Clippy passes with no warnings
- Added unit tests for:
  - `MptcpFlags` raw conversion and roundtrip
  - `MptcpEndpointBuilder` construction (IPv4 and IPv6)
  - `MptcpLimits` builder
  - `MptcpEndpoint` helper methods
  - Response parsing edge cases

## Linux Kernel Requirements

- Linux 5.6+ for MPTCP support
- Linux 5.9+ for full path manager API
- Kernel config: `CONFIG_MPTCP=y`

### Prerequisites

```bash
# Check if MPTCP is enabled
cat /proc/sys/net/mptcp/enabled

# Enable MPTCP
sudo sysctl -w net.mptcp.enabled=1

# Check path manager
ip mptcp endpoint show
```

## Example Usage

```rust
use nlink::netlink::{Connection, Mptcp};
use nlink::netlink::genl::mptcp::{MptcpEndpointBuilder, MptcpLimits};

// Create MPTCP connection
let conn = Connection::<Mptcp>::new_async().await?;

// Add primary endpoint (signal + subflow)
conn.add_endpoint(
    MptcpEndpointBuilder::new("192.168.1.10".parse()?)
        .id(1)
        .dev("eth0")
        .signal()
        .subflow()
).await?;

// Add backup endpoint
conn.add_endpoint(
    MptcpEndpointBuilder::new("10.0.0.10".parse()?)
        .id(2)
        .dev("wlan0")
        .signal()
        .backup()
).await?;

// Configure limits
conn.set_limits(
    MptcpLimits::new()
        .subflows(4)
        .add_addr_accepted(4)
).await?;

// List endpoints
for ep in conn.get_endpoints().await? {
    println!("Endpoint {}: {} (signal={}, subflow={}, backup={})",
        ep.id, ep.address, ep.flags.signal, ep.flags.subflow, ep.flags.backup);
}

// Clean up
conn.flush_endpoints().await?;
```

## Future Work

- Per-connection endpoint management via token
- Subflow create/destroy operations
- MPTCP socket statistics integration with sockdiag
- Event monitoring for path changes
