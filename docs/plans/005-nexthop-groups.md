# Plan 005: Nexthop Groups

## Overview

Add support for Linux nexthop objects and nexthop groups (introduced in Linux 5.3). This provides a modern, efficient way to configure ECMP and weighted multipath routing.

## Motivation

Nexthop groups offer several advantages over legacy RTA_MULTIPATH:

1. **Efficiency**: Nexthops are shared objects, reducing memory when the same nexthop is used in multiple routes
2. **Atomic updates**: Change nexthop once, all routes using it are updated atomically
3. **Resilient hashing**: Optional resilient group type maintains flow affinity during nexthop changes
4. **Better ECMP**: More control over load balancing behavior
5. **FDB integration**: Nexthop groups can be used with bridge FDB entries

This is the modern way to configure ECMP in Linux and is required for advanced routing use cases.

## Design

### API Design

```rust
/// Nexthop entry information.
#[derive(Debug, Clone)]
pub struct Nexthop {
    /// Nexthop ID
    pub id: u32,
    /// Gateway address
    pub gateway: Option<IpAddr>,
    /// Output interface index
    pub ifindex: Option<u32>,
    /// Encapsulation type
    pub encap_type: Option<u16>,
    /// Flags
    pub flags: u32,
    /// Group ID (if this nexthop is part of a group)
    pub group: Option<u32>,
}

/// Nexthop group types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NexthopGroupType {
    /// Multipath group with hash-threshold algorithm (default)
    Multipath,
    /// Resilient group that maintains flow affinity
    Resilient,
}

/// Nexthop group entry.
#[derive(Debug, Clone)]
pub struct NexthopGroupEntry {
    /// Nexthop ID
    pub id: u32,
    /// Weight (1-256)
    pub weight: u8,
}

/// Nexthop group information.
#[derive(Debug, Clone)]
pub struct NexthopGroup {
    /// Group ID
    pub id: u32,
    /// Group type
    pub group_type: NexthopGroupType,
    /// Member nexthops with weights
    pub members: Vec<NexthopGroupEntry>,
    /// Resilient group parameters
    pub resilient: Option<ResilientParams>,
}

/// Resilient group parameters.
#[derive(Debug, Clone)]
pub struct ResilientParams {
    /// Number of hash buckets
    pub buckets: u32,
    /// Idle timer in seconds
    pub idle_timer: u32,
    /// Unbalanced timer in seconds
    pub unbalanced_timer: u32,
}

/// Builder for nexthop objects.
#[derive(Debug, Clone)]
pub struct NexthopBuilder {
    id: u32,
    gateway: Option<IpAddr>,
    dev: Option<String>,
    ifindex: Option<u32>,
    blackhole: bool,
    onlink: bool,
    fdb: bool,  // For use with bridge FDB
}

impl NexthopBuilder {
    pub fn new(id: u32) -> Self;
    pub fn gateway(self, gw: IpAddr) -> Self;
    pub fn dev(self, dev: impl Into<String>) -> Self;
    pub fn ifindex(self, ifindex: u32) -> Self;
    pub fn blackhole(self) -> Self;
    pub fn onlink(self) -> Self;
    pub fn fdb(self) -> Self;
}

/// Builder for nexthop groups.
#[derive(Debug, Clone)]
pub struct NexthopGroupBuilder {
    id: u32,
    group_type: NexthopGroupType,
    members: Vec<(u32, u8)>,  // (nexthop_id, weight)
    resilient: Option<ResilientParams>,
}

impl NexthopGroupBuilder {
    pub fn new(id: u32) -> Self;
    pub fn multipath(self) -> Self;
    pub fn resilient(self) -> Self;
    pub fn member(self, nexthop_id: u32, weight: u8) -> Self;
    pub fn buckets(self, buckets: u32) -> Self;
    pub fn idle_timer(self, seconds: u32) -> Self;
    pub fn unbalanced_timer(self, seconds: u32) -> Self;
}

impl Connection<Route> {
    // Nexthop operations
    pub async fn get_nexthops(&self) -> Result<Vec<Nexthop>>;
    pub async fn get_nexthop(&self, id: u32) -> Result<Option<Nexthop>>;
    pub async fn add_nexthop(&self, builder: NexthopBuilder) -> Result<()>;
    pub async fn del_nexthop(&self, id: u32) -> Result<()>;
    pub async fn replace_nexthop(&self, builder: NexthopBuilder) -> Result<()>;
    
    // Nexthop group operations
    pub async fn get_nexthop_groups(&self) -> Result<Vec<NexthopGroup>>;
    pub async fn add_nexthop_group(&self, builder: NexthopGroupBuilder) -> Result<()>;
    pub async fn del_nexthop_group(&self, id: u32) -> Result<()>;
    pub async fn replace_nexthop_group(&self, builder: NexthopGroupBuilder) -> Result<()>;
}
```

### Usage Example

```rust
use nlink::netlink::{Connection, Route};
use nlink::netlink::nexthop::{NexthopBuilder, NexthopGroupBuilder, NexthopGroupType};
use nlink::netlink::route::Ipv4Route;

let conn = Connection::<Route>::new()?;

// Create individual nexthops
conn.add_nexthop(
    NexthopBuilder::new(1)
        .gateway("192.168.1.1".parse()?)
        .dev("eth0")
).await?;

conn.add_nexthop(
    NexthopBuilder::new(2)
        .gateway("192.168.2.1".parse()?)
        .dev("eth1")
).await?;

// Create ECMP group
conn.add_nexthop_group(
    NexthopGroupBuilder::new(100)
        .multipath()
        .member(1, 1)  // nexthop 1, weight 1
        .member(2, 1)  // nexthop 2, weight 1
).await?;

// Create resilient group (maintains flow affinity)
conn.add_nexthop_group(
    NexthopGroupBuilder::new(101)
        .resilient()
        .member(1, 1)
        .member(2, 1)
        .buckets(128)
        .idle_timer(120)
).await?;

// Add route using nexthop group
conn.add_route(
    Ipv4Route::new("10.0.0.0", 8)
        .nexthop_group(100)
).await?;

// Update nexthop (all routes using it are updated atomically)
conn.replace_nexthop(
    NexthopBuilder::new(1)
        .gateway("192.168.1.254".parse()?)
        .dev("eth0")
).await?;

// Query nexthops
let nexthops = conn.get_nexthops().await?;
for nh in &nexthops {
    println!("NH {}: {:?} via {:?}", nh.id, nh.gateway, nh.ifindex);
}
```

### Implementation Details

Nexthop objects use dedicated message types:

**Message types:**
- `RTM_NEWNEXTHOP` (104): Add nexthop
- `RTM_DELNEXTHOP` (105): Delete nexthop
- `RTM_GETNEXTHOP` (106): Query nexthops

**Kernel structure:**
```c
struct nhmsg {
    unsigned char nh_family;
    unsigned char nh_scope;
    unsigned char nh_protocol;
    unsigned char resvd;
    unsigned int  nh_flags;
};
```

**Nexthop attributes (NHA_*):**
```c
enum {
    NHA_UNSPEC,
    NHA_ID,           // u32: nexthop ID
    NHA_GROUP,        // array of nexthop_grp
    NHA_GROUP_TYPE,   // u16: NEXTHOP_GRP_TYPE_*
    NHA_BLACKHOLE,    // flag
    NHA_OIF,          // u32: output interface
    NHA_GATEWAY,      // IP address
    NHA_ENCAP_TYPE,   // u16: encap type
    NHA_ENCAP,        // nested: encap data
    NHA_GROUPS,       // flag: return groups only
    NHA_MASTER,       // u32: master device
    NHA_FDB,          // flag: for FDB nexthops
    NHA_RES_GROUP,    // nested: resilient group params
    NHA_RES_BUCKET,   // nested: resilient bucket info
};

struct nexthop_grp {
    __u32 id;
    __u8  weight;
    __u8  resvd1;
    __u16 resvd2;
};
```

**Route integration:**
Routes reference nexthops via `RTA_NH_ID` attribute instead of `RTA_GATEWAY`/`RTA_MULTIPATH`.

### File Changes

| File | Change |
|------|--------|
| `crates/nlink/src/netlink/nexthop.rs` | New file: nexthop types and builders |
| `crates/nlink/src/netlink/connection.rs` | Add nexthop methods |
| `crates/nlink/src/netlink/message.rs` | Add RTM_*NEXTHOP message types |
| `crates/nlink/src/netlink/types/nexthop.rs` | Kernel structures |
| `crates/nlink/src/netlink/route.rs` | Add nexthop_group() to route builders |
| `crates/nlink/src/netlink/mod.rs` | Export nexthop module |

## Implementation Steps

### Step 1: Add message types

```rust
// In message.rs
pub enum NlMsgType {
    // ... existing types
    RTM_NEWNEXTHOP = 104,
    RTM_DELNEXTHOP = 105,
    RTM_GETNEXTHOP = 106,
}
```

### Step 2: Add kernel structures

```rust
// crates/nlink/src/netlink/types/nexthop.rs

use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

/// nhmsg structure
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct NhMsg {
    pub nh_family: u8,
    pub nh_scope: u8,
    pub nh_protocol: u8,
    pub resvd: u8,
    pub nh_flags: u32,
}

/// nexthop_grp structure
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct NexthopGrp {
    pub id: u32,
    pub weight: u8,
    pub resvd1: u8,
    pub resvd2: u16,
}

/// Nexthop attributes
pub mod nha {
    pub const UNSPEC: u16 = 0;
    pub const ID: u16 = 1;
    pub const GROUP: u16 = 2;
    pub const GROUP_TYPE: u16 = 3;
    pub const BLACKHOLE: u16 = 4;
    pub const OIF: u16 = 5;
    pub const GATEWAY: u16 = 6;
    pub const ENCAP_TYPE: u16 = 7;
    pub const ENCAP: u16 = 8;
    pub const GROUPS: u16 = 9;
    pub const MASTER: u16 = 10;
    pub const FDB: u16 = 11;
    pub const RES_GROUP: u16 = 12;
    pub const RES_BUCKET: u16 = 13;
}

/// Nexthop group types
pub mod nhg_type {
    pub const MPATH: u16 = 0;
    pub const RES: u16 = 1;
}

/// Nexthop flags
pub mod nhf {
    pub const ONLINK: u32 = 1;
    pub const DEAD: u32 = 2;
    pub const LINKDOWN: u32 = 4;
}
```

### Step 3: Create nexthop.rs module

```rust
// crates/nlink/src/netlink/nexthop.rs

use std::net::IpAddr;
use super::builder::MessageBuilder;
use super::connection::Connection;
use super::error::{Error, Result};
use super::message::{NLM_F_ACK, NLM_F_CREATE, NLM_F_DUMP, NLM_F_REPLACE, NLM_F_REQUEST, NlMsgType};
use super::protocol::Route;
use super::types::nexthop::{NhMsg, NexthopGrp, nha, nhg_type, nhf};

// ... implement types and builders as shown in API design
```

### Step 4: Update route builders

Add `nexthop_group()` method to `Ipv4Route` and `Ipv6Route`:

```rust
impl Ipv4Route {
    /// Use a nexthop group instead of direct gateway.
    pub fn nexthop_group(mut self, group_id: u32) -> Self {
        self.nexthop_id = Some(group_id);
        self.gateway = None;
        self.multipath = None;
        self
    }
}
```

And update `build()` to include `RTA_NH_ID` attribute:

```rust
// In RouteConfig::build()
if let Some(nh_id) = self.nexthop_id {
    builder.append_attr_u32(RtaAttr::NhId as u16, nh_id);
}
```

### Step 5: Add Connection methods

Implement all the nexthop CRUD operations.

## Testing

### Manual Testing

```bash
# Requires Linux 5.3+
# Check kernel support
cat /proc/version

# Run example
sudo cargo run --example nexthop_groups

# Verify with iproute2
ip nexthop show
ip nexthop show id 1
ip route show | grep "nhid"
```

### Example

```rust
//! Example: Nexthop groups for ECMP

use nlink::netlink::{Connection, Route};
use nlink::netlink::nexthop::{NexthopBuilder, NexthopGroupBuilder};
use nlink::netlink::route::Ipv4Route;

#[tokio::main]
async fn main() -> nlink::netlink::Result<()> {
    let conn = Connection::<Route>::new()?;
    
    // Create nexthops
    conn.add_nexthop(
        NexthopBuilder::new(1)
            .gateway("192.168.1.1".parse()?)
            .dev("lo")
    ).await?;
    
    conn.add_nexthop(
        NexthopBuilder::new(2)
            .gateway("192.168.2.1".parse()?)
            .dev("lo")
    ).await?;
    
    // Create group
    conn.add_nexthop_group(
        NexthopGroupBuilder::new(100)
            .member(1, 1)
            .member(2, 2)  // weight 2 = gets ~2x traffic
    ).await?;
    
    // Add route using group
    conn.add_route(
        Ipv4Route::new("10.0.0.0", 8)
            .nexthop_group(100)
    ).await?;
    
    // List nexthops
    for nh in conn.get_nexthops().await? {
        println!("NH {}: {:?}", nh.id, nh.gateway);
    }
    
    // Cleanup
    conn.del_route_v4("10.0.0.0", 8).await.ok();
    conn.del_nexthop_group(100).await.ok();
    conn.del_nexthop(1).await.ok();
    conn.del_nexthop(2).await.ok();
    
    Ok(())
}
```

## Documentation

Add nexthop group documentation to CLAUDE.md.

## Effort Estimate

- Implementation: ~8 hours
- Testing: ~2 hours
- Documentation: ~1 hour
- **Total: ~11 hours**

## Future Work

- Nexthop event monitoring (RTM_NEWNEXTHOP/RTM_DELNEXTHOP)
- Resilient bucket inspection
- MPLS nexthops with encapsulation
- FDB nexthop groups for EVPN
