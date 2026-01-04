# Plan 006: MPLS Routes

## Overview

Add support for MPLS (Multi-Protocol Label Switching) routes, including label operations (push, pop, swap) and MPLS encapsulation for IP routes.

## Motivation

MPLS is widely used in service provider networks for:

1. **Traffic engineering**: Path-constrained routing
2. **VPN services**: L2VPN and L3VPN
3. **Fast reroute**: Pre-computed backup paths
4. **Segment routing**: Modern MPLS control plane

This requires:
- MPLS encapsulation on IP routes (push labels)
- MPLS forwarding entries (swap/pop labels)
- Label stack operations

## Design

### API Design

```rust
/// MPLS label (20-bit value).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MplsLabel(pub u32);

impl MplsLabel {
    /// Create from raw value (0-1048575).
    pub fn new(label: u32) -> Option<Self>;
    
    /// Implicit null label (3) - pop and forward as IP.
    pub const IMPLICIT_NULL: Self = Self(3);
    
    /// Explicit null IPv4 (0).
    pub const EXPLICIT_NULL_V4: Self = Self(0);
    
    /// Explicit null IPv6 (2).
    pub const EXPLICIT_NULL_V6: Self = Self(2);
    
    /// Router alert (1).
    pub const ROUTER_ALERT: Self = Self(1);
}

/// MPLS encapsulation for IP routes.
#[derive(Debug, Clone)]
pub struct MplsEncap {
    /// Label stack (outer to inner)
    labels: Vec<MplsLabel>,
    /// TTL propagation mode
    ttl: Option<u8>,
}

impl MplsEncap {
    pub fn new() -> Self;
    pub fn label(self, label: u32) -> Self;
    pub fn labels(self, labels: &[u32]) -> Self;
    pub fn ttl(self, ttl: u8) -> Self;
}

/// MPLS route (label forwarding entry).
#[derive(Debug, Clone)]
pub struct MplsRoute {
    /// Incoming label
    label: MplsLabel,
    /// Action: pop, swap, or push
    action: MplsAction,
    /// Output interface
    dev: Option<String>,
    /// Next hop for swap/push
    via: Option<IpAddr>,
    /// Outgoing labels for swap/push
    out_labels: Vec<MplsLabel>,
}

/// MPLS forwarding actions.
#[derive(Debug, Clone)]
pub enum MplsAction {
    /// Pop label and forward as IP
    Pop,
    /// Swap with new label(s)
    Swap(Vec<MplsLabel>),
    /// Push additional labels
    Push(Vec<MplsLabel>),
}

/// Builder for MPLS routes.
#[derive(Debug, Clone)]
pub struct MplsRouteBuilder {
    label: u32,
    action: MplsAction,
    dev: Option<String>,
    via: Option<IpAddr>,
}

impl MplsRouteBuilder {
    /// Create a pop route (label -> IP).
    pub fn pop(label: u32) -> Self;
    
    /// Create a swap route (label -> label).
    pub fn swap(in_label: u32, out_label: u32) -> Self;
    
    /// Create a swap route with label stack.
    pub fn swap_stack(in_label: u32, out_labels: &[u32]) -> Self;
    
    /// Set output device.
    pub fn dev(self, dev: impl Into<String>) -> Self;
    
    /// Set nexthop address.
    pub fn via(self, via: IpAddr) -> Self;
}

impl Connection<Route> {
    // MPLS routes
    pub async fn get_mpls_routes(&self) -> Result<Vec<MplsRoute>>;
    pub async fn add_mpls_route(&self, builder: MplsRouteBuilder) -> Result<()>;
    pub async fn del_mpls_route(&self, label: u32) -> Result<()>;
    
    // IP routes with MPLS encap (existing Ipv4Route/Ipv6Route)
    // Use: Ipv4Route::new(...).encap(MplsEncap::new().label(100))
}

// Extend existing route builders
impl Ipv4Route {
    /// Add MPLS encapsulation (push labels).
    pub fn mpls_encap(self, encap: MplsEncap) -> Self;
}

impl Ipv6Route {
    /// Add MPLS encapsulation (push labels).
    pub fn mpls_encap(self, encap: MplsEncap) -> Self;
}
```

### Usage Example

```rust
use nlink::netlink::{Connection, Route};
use nlink::netlink::mpls::{MplsEncap, MplsRouteBuilder};
use nlink::netlink::route::Ipv4Route;

let conn = Connection::<Route>::new()?;

// IP route with MPLS encapsulation (push labels)
conn.add_route(
    Ipv4Route::new("10.0.0.0", 8)
        .gateway("192.168.1.1".parse()?)
        .dev("eth0")
        .mpls_encap(MplsEncap::new().labels(&[100, 200]))  // Push stack
).await?;

// MPLS pop route (decapsulate at egress PE)
conn.add_mpls_route(
    MplsRouteBuilder::pop(100)
        .dev("eth0")
).await?;

// MPLS swap route (transit LSR)
conn.add_mpls_route(
    MplsRouteBuilder::swap(100, 200)
        .via("192.168.2.1".parse()?)
        .dev("eth1")
).await?;

// MPLS swap with label stack (for label stacking)
conn.add_mpls_route(
    MplsRouteBuilder::swap_stack(100, &[200, 300])
        .via("192.168.2.1".parse()?)
        .dev("eth1")
).await?;

// Query MPLS routes
let routes = conn.get_mpls_routes().await?;
for route in &routes {
    println!("Label {}: {:?}", route.label.0, route.action);
}
```

### Implementation Details

**MPLS family:**
The MPLS address family is `AF_MPLS` (28).

**Route encapsulation (RTA_ENCAP):**
For IP routes with MPLS encapsulation:
```
RTM_NEWROUTE
  rtmsg { family: AF_INET, ... }
  RTA_DST: 10.0.0.0
  RTA_GATEWAY: 192.168.1.1
  RTA_ENCAP_TYPE: LWTUNNEL_ENCAP_MPLS (1)
  RTA_ENCAP (nested):
    MPLS_IPTUNNEL_DST: label stack
    MPLS_IPTUNNEL_TTL: ttl (optional)
```

**MPLS route (label forwarding):**
```
RTM_NEWROUTE
  rtmsg { family: AF_MPLS, ... }
  RTA_DST: incoming label (encoded as mpls_label)
  RTA_NEWDST: outgoing labels (for swap)
  RTA_VIA: { family, addr } next hop
  RTA_OIF: output interface
```

**Label encoding:**
MPLS labels in netlink are encoded as `struct mpls_label`:
```c
struct mpls_label {
    __be32 entry;  // label(20) | TC(3) | S(1) | TTL(8)
};
```

For the destination (incoming label), only the label bits matter. For outgoing labels, the full stack is encoded with proper S bit (bottom-of-stack).

### File Changes

| File | Change |
|------|--------|
| `crates/nlink/src/netlink/mpls.rs` | New file: MPLS types and builders |
| `crates/nlink/src/netlink/route.rs` | Add mpls_encap() to route builders |
| `crates/nlink/src/netlink/connection.rs` | Add MPLS route methods |
| `crates/nlink/src/netlink/types/mpls.rs` | MPLS structures |
| `crates/nlink/src/netlink/types/route.rs` | Add RTA_ENCAP constants |
| `crates/nlink/src/netlink/mod.rs` | Export mpls module |

## Implementation Steps

### Step 1: Add MPLS types

```rust
// crates/nlink/src/netlink/types/mpls.rs

use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

/// MPLS label encoding
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct MplsLabelEntry {
    /// Big-endian: label(20) | TC(3) | S(1) | TTL(8)
    pub entry: u32,
}

impl MplsLabelEntry {
    /// Create with label, TC=0, S=0 (not bottom), TTL=0
    pub fn new(label: u32) -> Self {
        Self { entry: (label << 12).to_be() }
    }
    
    /// Create bottom-of-stack entry
    pub fn bottom(label: u32, ttl: u8) -> Self {
        let entry = (label << 12) | (1 << 8) | (ttl as u32);
        Self { entry: entry.to_be() }
    }
    
    /// Get label value
    pub fn label(&self) -> u32 {
        (u32::from_be(self.entry) >> 12) & 0xFFFFF
    }
}

/// MPLS tunnel attributes
pub mod mpls_tunnel {
    pub const UNSPEC: u16 = 0;
    pub const DST: u16 = 1;
    pub const TTL: u16 = 2;
}

/// Encap types
pub mod lwtunnel_encap {
    pub const NONE: u16 = 0;
    pub const MPLS: u16 = 1;
    pub const IP: u16 = 2;
    pub const ILA: u16 = 3;
    pub const IP6: u16 = 4;
    pub const SEG6: u16 = 5;
    pub const BPF: u16 = 6;
    pub const SEG6_LOCAL: u16 = 7;
    pub const RPL: u16 = 8;
    pub const IOAM6: u16 = 9;
    pub const XFRM: u16 = 10;
}
```

### Step 2: Add route encapsulation support

```rust
// In route.rs, add RTA_ENCAP handling

/// Route encapsulation attributes
mod rta_encap {
    pub const ENCAP_TYPE: u16 = 21;
    pub const ENCAP: u16 = 22;
}

impl Ipv4Route {
    /// Add MPLS encapsulation.
    pub fn mpls_encap(mut self, encap: MplsEncap) -> Self {
        self.encap = Some(RouteEncap::Mpls(encap));
        self
    }
}

// In build():
if let Some(RouteEncap::Mpls(ref encap)) = self.encap {
    builder.append_attr_u16(rta_encap::ENCAP_TYPE, lwtunnel_encap::MPLS);
    
    let encap_nest = builder.nest_start(rta_encap::ENCAP);
    
    // Encode label stack
    let mut label_data = Vec::new();
    for (i, &label) in encap.labels.iter().enumerate() {
        let is_bottom = i == encap.labels.len() - 1;
        let entry = if is_bottom {
            MplsLabelEntry::bottom(label.0, encap.ttl.unwrap_or(255))
        } else {
            MplsLabelEntry::new(label.0)
        };
        label_data.extend_from_slice(entry.as_bytes());
    }
    builder.append_attr(mpls_tunnel::DST, &label_data);
    
    if let Some(ttl) = encap.ttl {
        builder.append_attr_u8(mpls_tunnel::TTL, ttl);
    }
    
    builder.nest_end(encap_nest);
}
```

### Step 3: Create mpls.rs module

Implement `MplsEncap`, `MplsRouteBuilder`, and parsing.

### Step 4: Add Connection methods

```rust
impl Connection<Route> {
    /// Get all MPLS routes.
    pub async fn get_mpls_routes(&self) -> Result<Vec<MplsRoute>> {
        let mut builder = MessageBuilder::new(
            NlMsgType::RTM_GETROUTE,
            NLM_F_REQUEST | NLM_F_DUMP,
        );
        
        let rtmsg = RtMsg::new().with_family(libc::AF_MPLS as u8);
        builder.append(&rtmsg);
        
        let responses = self.send_dump(builder).await?;
        // Parse MPLS routes...
    }
    
    /// Add an MPLS route.
    pub async fn add_mpls_route(&self, config: MplsRouteBuilder) -> Result<()> {
        let builder = config.build()?;
        self.send_ack(builder).await
    }
    
    /// Delete an MPLS route.
    pub async fn del_mpls_route(&self, label: u32) -> Result<()> {
        let mut builder = MessageBuilder::new(
            NlMsgType::RTM_DELROUTE,
            NLM_F_REQUEST | NLM_F_ACK,
        );
        
        let rtmsg = RtMsg::new()
            .with_family(libc::AF_MPLS as u8)
            .with_dst_len(20);  // MPLS label is 20 bits
        builder.append(&rtmsg);
        
        // RTA_DST with label
        let label_entry = MplsLabelEntry::new(label);
        builder.append_attr(RtaAttr::Dst as u16, label_entry.as_bytes());
        
        self.send_ack(builder).await
    }
}
```

## Testing

### Prerequisites

```bash
# Enable MPLS modules
sudo modprobe mpls_router
sudo modprobe mpls_iptunnel

# Enable MPLS on interface
sudo sysctl -w net.mpls.platform_labels=1048575
sudo sysctl -w net.mpls.conf.lo.input=1
```

### Example

```rust
//! Example: MPLS routing

use nlink::netlink::{Connection, Route};
use nlink::netlink::mpls::{MplsEncap, MplsRouteBuilder};
use nlink::netlink::route::Ipv4Route;

#[tokio::main]
async fn main() -> nlink::netlink::Result<()> {
    let conn = Connection::<Route>::new()?;
    
    // IP route with MPLS push
    conn.add_route(
        Ipv4Route::new("10.0.0.0", 8)
            .dev("lo")
            .mpls_encap(MplsEncap::new().label(100))
    ).await?;
    
    // MPLS swap route
    conn.add_mpls_route(
        MplsRouteBuilder::swap(100, 200)
            .dev("lo")
    ).await?;
    
    // List MPLS routes
    for route in conn.get_mpls_routes().await? {
        println!("{:?}", route);
    }
    
    // Cleanup
    conn.del_mpls_route(100).await.ok();
    conn.del_route_v4("10.0.0.0", 8).await.ok();
    
    Ok(())
}
```

## Documentation

Add MPLS section to CLAUDE.md.

## Effort Estimate

- Implementation: ~10 hours
- Testing: ~2 hours
- Documentation: ~1 hour
- **Total: ~13 hours**

## Future Work

- MPLS over UDP encapsulation
- SR-MPLS (Segment Routing with MPLS data plane)
- MPLS VPN label handling
- MPLS OAM (BFD)
