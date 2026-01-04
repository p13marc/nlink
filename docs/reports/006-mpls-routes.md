# Plan 006: MPLS Routes Implementation Report

## Summary

Implemented MPLS (Multi-Protocol Label Switching) route support as specified in the plan. This enables label-based forwarding for carrier-grade networking scenarios, including label push/pop/swap operations and MPLS encapsulation for IP routes.

## Implementation Details

### Files Created

1. **`crates/nlink/src/netlink/types/mpls.rs`** (~220 lines)
   - Kernel structures for MPLS operations using zerocopy
   - `MplsLabelEntry` - 4-byte big-endian label encoding (label|TC|BOS|TTL)
   - `RtVia` - structure for RTA_VIA attribute (address family + address)
   - Constants: `mpls_tunnel::*`, `lwtunnel_encap::*`, `mpls_label::*`

2. **`crates/nlink/src/netlink/mpls.rs`** (~600 lines)
   - High-level types and builders:
     - `MplsLabel` - typed wrapper with special label constants
     - `MplsEncap` - builder for MPLS encapsulation on IP routes
     - `MplsAction` enum (Pop, Swap)
     - `MplsRoute` - parsed MPLS route representation
     - `MplsRouteBuilder` - builder for MPLS forwarding entries
   - Connection methods for `Connection<Route>`

### Files Modified

1. **`crates/nlink/src/netlink/types/mod.rs`**
   - Added `pub mod mpls;`

2. **`crates/nlink/src/netlink/mod.rs`**
   - Added `pub mod mpls;`

3. **`crates/nlink/src/netlink/route.rs`**
   - Added `mpls_encap` field to `Ipv4Route` and `Ipv6Route`
   - Added `mpls_encap()` method to both route builders
   - Updated `build()` to emit RTA_ENCAP_TYPE and RTA_ENCAP attributes

4. **`CLAUDE.md`**
   - Added mpls module to the module listing
   - Added comprehensive usage examples for MPLS operations

## API Surface

### MplsLabel

```rust
pub struct MplsLabel(pub u32);

impl MplsLabel {
    pub const IMPLICIT_NULL: Self = Self(3);   // PHP (Penultimate Hop Pop)
    pub const EXPLICIT_NULL_V4: Self = Self(0);
    pub const EXPLICIT_NULL_V6: Self = Self(2);
    pub const ROUTER_ALERT: Self = Self(1);
    pub const GAL: Self = Self(13);            // Generic Associated Label
    pub const OAM_ALERT: Self = Self(14);
    pub const EXTENSION: Self = Self(15);
    
    pub fn is_reserved(&self) -> bool;
    pub fn is_valid(&self) -> bool;            // 16-1048575
}
```

### MplsEncap (for IP routes)

```rust
MplsEncap::new()
    .label(100)              // Add single label
    .labels(&[100, 200])     // Add label stack
    .ttl(64)                 // Set TTL for all labels
    .build()
```

### MplsRouteBuilder (for MPLS forwarding)

```rust
// Pop operation (PHP)
MplsRouteBuilder::pop(100)
    .dev("eth0")

// Swap to single label
MplsRouteBuilder::swap(100, 200)
    .dev("eth0")
    .via(IpAddr::V4(gateway))

// Swap to label stack
MplsRouteBuilder::swap_stack(100, &[200, 300])
    .dev("eth0")
    .via(IpAddr::V4(gateway))
```

### Connection Methods

```rust
// Query MPLS routes
conn.get_mpls_routes().await?;

// Add/replace/delete MPLS routes
conn.add_mpls_route(builder).await?;
conn.replace_mpls_route(builder).await?;
conn.del_mpls_route(100).await?;  // By in-label
```

### Route Integration

```rust
// Push MPLS label(s) onto IP routes
Ipv4Route::new("10.0.0.0", 8)
    .gateway("192.168.1.1".parse()?)
    .mpls_encap(MplsEncap::new().label(100).ttl(64).build())

// Push label stack
Ipv6Route::new("2001:db8::", 32)
    .gateway("2001:db8::1".parse()?)
    .mpls_encap(MplsEncap::new().labels(&[100, 200, 300]).build())
```

## MPLS Label Encoding

MPLS labels are encoded as 32-bit big-endian values:

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                Label                  | TC  |S|       TTL     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

- **Label** (20 bits): The label value (0-1048575)
- **TC** (3 bits): Traffic class (formerly EXP)
- **S** (1 bit): Bottom of Stack (1 for last label)
- **TTL** (8 bits): Time to Live

## Testing

- All existing tests pass
- Clippy passes with no warnings

## Key Implementation Notes

1. **AF_MPLS Family**: MPLS routes use address family 28 (AF_MPLS), separate from AF_INET/AF_INET6

2. **RTA_DST for MPLS**: Contains `MplsLabelEntry` array (typically single entry for in-label)

3. **RTA_NEWDST**: Used for swap operations to specify outgoing label stack

4. **RTA_VIA**: Encodes next-hop with address family prefix (e.g., AF_INET + 4-byte IPv4)

5. **RTA_ENCAP/RTA_ENCAP_TYPE**: Used to add MPLS encapsulation to IP routes
   - `RTA_ENCAP_TYPE` = `LWTUNNEL_ENCAP_MPLS` (1)
   - `RTA_ENCAP` contains nested `MPLS_IPTUNNEL_DST` and optional `MPLS_IPTUNNEL_TTL`

6. **BOS Bit**: Only the last label in a stack has BOS=1; the implementation handles this automatically

## Linux Kernel Requirements

- MPLS kernel modules: `mpls_router`, `mpls_iptunnel`
- MPLS must be enabled on interfaces: `sysctl net.mpls.conf.eth0.input=1`
- Platform label space: `sysctl net.mpls.platform_labels=1048575`

## Example Usage

```bash
# Enable MPLS on kernel
modprobe mpls_router
modprobe mpls_iptunnel
sysctl -w net.mpls.platform_labels=1048575
sysctl -w net.mpls.conf.eth0.input=1
```

```rust
use nlink::{Connection, Protocol};
use nlink::netlink::mpls::{MplsRouteBuilder, MplsEncap};
use std::net::Ipv4Addr;

let conn = Connection::new(Protocol::Route)?;

// Add MPLS pop route (PHP)
let pop = MplsRouteBuilder::pop(100).dev("eth0");
conn.add_mpls_route(pop).await?;

// Add MPLS swap route
let swap = MplsRouteBuilder::swap(200, 300)
    .dev("eth0")
    .via(Ipv4Addr::new(192, 168, 1, 1).into());
conn.add_mpls_route(swap).await?;

// Add IP route with MPLS encapsulation
let encap = MplsEncap::new().label(100).ttl(64).build();
let route = Ipv4Route::new("10.0.0.0", 8)
    .gateway("192.168.1.1".parse()?)
    .mpls_encap(encap);
conn.add_route(route).await?;
```
