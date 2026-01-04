# Plan 003: Bridge VLAN Filtering

## Overview

Add API for managing per-port VLAN configuration on Linux bridges with VLAN filtering enabled. This allows assigning VLANs to bridge ports, setting PVID, and configuring tagged/untagged modes.

## Motivation

Bridge VLAN filtering is essential for:
- Multi-tenant container networking
- VLAN-aware switching in software bridges
- Network segmentation without multiple bridges
- Integration with VXLAN for overlay networks

Currently, nlink can create bridges with `vlan_filtering(true)` but cannot configure per-port VLANs.

## Design

### API Design

```rust
/// VLAN flags for bridge port configuration.
#[derive(Debug, Clone, Copy, Default)]
pub struct BridgeVlanFlags {
    /// This is the PVID (Port VLAN ID) - untagged ingress default
    pub pvid: bool,
    /// Egress untagged - remove VLAN tag on egress
    pub untagged: bool,
}

/// VLAN range for bulk operations.
#[derive(Debug, Clone)]
pub struct VlanRange {
    pub start: u16,
    pub end: u16,
    pub flags: BridgeVlanFlags,
}

/// Bridge VLAN entry information.
#[derive(Debug, Clone)]
pub struct BridgeVlanEntry {
    pub ifindex: u32,
    pub vid: u16,
    pub flags: BridgeVlanFlags,
}

/// Builder for bridge VLAN operations.
#[derive(Debug, Clone)]
pub struct BridgeVlanBuilder {
    dev: Option<String>,
    ifindex: Option<u32>,
    vid: u16,
    vid_end: Option<u16>,  // For range operations
    pvid: bool,
    untagged: bool,
}

impl BridgeVlanBuilder {
    pub fn new(vid: u16) -> Self;
    pub fn dev(self, dev: impl Into<String>) -> Self;
    pub fn ifindex(self, ifindex: u32) -> Self;
    pub fn range(self, vid_end: u16) -> Self;
    pub fn pvid(self) -> Self;
    pub fn untagged(self) -> Self;
}

impl Connection<Route> {
    /// Get VLAN configuration for a bridge port.
    pub async fn get_bridge_vlans(&self, dev: &str) -> Result<Vec<BridgeVlanEntry>>;
    
    /// Get VLAN configuration for all ports of a bridge.
    pub async fn get_bridge_vlans_all(&self, bridge: &str) -> Result<Vec<BridgeVlanEntry>>;
    
    /// Add VLAN to a bridge port.
    pub async fn add_bridge_vlan(&self, config: BridgeVlanBuilder) -> Result<()>;
    
    /// Delete VLAN from a bridge port.
    pub async fn del_bridge_vlan(&self, dev: &str, vid: u16) -> Result<()>;
    
    /// Set PVID for a bridge port.
    pub async fn set_bridge_pvid(&self, dev: &str, vid: u16) -> Result<()>;
}
```

### Implementation Details

Bridge VLAN configuration uses `RTM_SETLINK` with `IFLA_AF_SPEC` containing `AF_BRIDGE` attributes:

**Message structure:**
```
RTM_SETLINK
  ifinfomsg { family: AF_BRIDGE, index: port_ifindex }
  IFLA_AF_SPEC (nested)
    IFLA_BRIDGE_VLAN_INFO (struct bridge_vlan_info)
```

**Kernel structures:**
```c
struct bridge_vlan_info {
    __u16 flags;  // BRIDGE_VLAN_INFO_*
    __u16 vid;
};

// Flags
#define BRIDGE_VLAN_INFO_MASTER      (1 << 0)  // Operate on bridge device
#define BRIDGE_VLAN_INFO_PVID        (1 << 1)  // PVID entry
#define BRIDGE_VLAN_INFO_UNTAGGED    (1 << 2)  // Egress untagged
#define BRIDGE_VLAN_INFO_RANGE_BEGIN (1 << 3)  // Start of VLAN range
#define BRIDGE_VLAN_INFO_RANGE_END   (1 << 4)  // End of VLAN range
#define BRIDGE_VLAN_INFO_BRENTRY     (1 << 5)  // Global bridge VLAN entry
```

**For querying VLANs:**
Use `RTM_GETLINK` with `IFLA_EXT_MASK` set to `RTEXT_FILTER_BRVLAN`.

### File Changes

| File | Change |
|------|--------|
| `crates/nlink/src/netlink/bridge_vlan.rs` | New file: VLAN types and builders |
| `crates/nlink/src/netlink/connection.rs` | Add VLAN methods to Connection<Route> |
| `crates/nlink/src/netlink/types/link.rs` | Add IFLA_AF_SPEC constants |
| `crates/nlink/src/netlink/mod.rs` | Export bridge_vlan module |

## Implementation Steps

### Step 1: Add constants to types/link.rs

```rust
/// IFLA_AF_SPEC attribute types for AF_BRIDGE
pub mod bridge_af {
    pub const IFLA_BRIDGE_FLAGS: u16 = 0;
    pub const IFLA_BRIDGE_MODE: u16 = 1;
    pub const IFLA_BRIDGE_VLAN_INFO: u16 = 2;
    pub const IFLA_BRIDGE_VLAN_TUNNEL_INFO: u16 = 3;
}

/// Bridge VLAN info flags
pub mod bridge_vlan_flags {
    pub const MASTER: u16 = 1 << 0;
    pub const PVID: u16 = 1 << 1;
    pub const UNTAGGED: u16 = 1 << 2;
    pub const RANGE_BEGIN: u16 = 1 << 3;
    pub const RANGE_END: u16 = 1 << 4;
    pub const BRENTRY: u16 = 1 << 5;
}

/// bridge_vlan_info structure
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct BridgeVlanInfo {
    pub flags: u16,
    pub vid: u16,
}
```

### Step 2: Create bridge_vlan.rs module

```rust
// crates/nlink/src/netlink/bridge_vlan.rs

use super::builder::MessageBuilder;
use super::connection::Connection;
use super::error::{Error, Result};
use super::message::{NLM_F_ACK, NLM_F_REQUEST, NlMsgType};
use super::protocol::Route;
use super::types::link::{
    BridgeVlanInfo, IfInfoMsg, IflaAttr,
    bridge_af, bridge_vlan_flags,
};

/// VLAN flags for bridge port configuration.
#[derive(Debug, Clone, Copy, Default)]
pub struct BridgeVlanFlags {
    /// This is the PVID (Port VLAN ID)
    pub pvid: bool,
    /// Egress untagged
    pub untagged: bool,
}

/// Bridge VLAN entry information.
#[derive(Debug, Clone)]
pub struct BridgeVlanEntry {
    /// Interface index
    pub ifindex: u32,
    /// VLAN ID
    pub vid: u16,
    /// VLAN flags
    pub flags: BridgeVlanFlags,
}

/// Builder for bridge VLAN operations.
#[derive(Debug, Clone)]
pub struct BridgeVlanBuilder {
    dev: Option<String>,
    ifindex: Option<u32>,
    vid: u16,
    vid_end: Option<u16>,
    pvid: bool,
    untagged: bool,
    master: bool,  // Apply to bridge device, not port
}

impl BridgeVlanBuilder {
    /// Create a new VLAN builder for a single VID.
    pub fn new(vid: u16) -> Self {
        Self {
            dev: None,
            ifindex: None,
            vid,
            vid_end: None,
            pvid: false,
            untagged: false,
            master: false,
        }
    }
    
    /// Set device name.
    pub fn dev(mut self, dev: impl Into<String>) -> Self {
        self.dev = Some(dev.into());
        self
    }
    
    /// Set interface index directly.
    pub fn ifindex(mut self, ifindex: u32) -> Self {
        self.ifindex = Some(ifindex);
        self
    }
    
    /// Set VLAN range end (for bulk operations).
    pub fn range(mut self, vid_end: u16) -> Self {
        self.vid_end = Some(vid_end);
        self
    }
    
    /// Mark as PVID (ingress untagged default).
    pub fn pvid(mut self) -> Self {
        self.pvid = true;
        self
    }
    
    /// Mark as untagged (strip tag on egress).
    pub fn untagged(mut self) -> Self {
        self.untagged = true;
        self
    }
    
    /// Apply to bridge device (for global VLAN entry).
    pub fn master(mut self) -> Self {
        self.master = true;
        self
    }
    
    /// Build the netlink message for adding VLAN.
    pub(crate) fn build_add(&self) -> Result<MessageBuilder> {
        self.build_message(NlMsgType::RTM_SETLINK)
    }
    
    /// Build the netlink message for deleting VLAN.
    pub(crate) fn build_del(&self) -> Result<MessageBuilder> {
        self.build_message(NlMsgType::RTM_DELLINK)
    }
    
    fn build_message(&self, msg_type: NlMsgType) -> Result<MessageBuilder> {
        let ifindex = if let Some(idx) = self.ifindex {
            idx as i32
        } else if let Some(ref dev) = self.dev {
            crate::util::get_ifindex(dev)
                .map_err(Error::InvalidMessage)?
        } else {
            return Err(Error::InvalidMessage("device required".into()));
        };
        
        let mut builder = MessageBuilder::new(msg_type, NLM_F_REQUEST | NLM_F_ACK);
        
        // Use AF_BRIDGE family
        let ifinfo = IfInfoMsg::new()
            .with_family(libc::AF_BRIDGE as u8)
            .with_index(ifindex);
        builder.append(&ifinfo);
        
        // IFLA_AF_SPEC containing VLAN info
        let af_spec = builder.nest_start(IflaAttr::AfSpec as u16);
        
        if let Some(vid_end) = self.vid_end {
            // Range operation: two entries with RANGE_BEGIN and RANGE_END flags
            let mut flags = self.build_flags();
            flags |= bridge_vlan_flags::RANGE_BEGIN;
            
            let vlan_info = BridgeVlanInfo { flags, vid: self.vid };
            builder.append_attr(bridge_af::IFLA_BRIDGE_VLAN_INFO, vlan_info.as_bytes());
            
            let mut end_flags = self.build_flags();
            end_flags |= bridge_vlan_flags::RANGE_END;
            
            let vlan_info_end = BridgeVlanInfo { flags: end_flags, vid: vid_end };
            builder.append_attr(bridge_af::IFLA_BRIDGE_VLAN_INFO, vlan_info_end.as_bytes());
        } else {
            // Single VLAN
            let flags = self.build_flags();
            let vlan_info = BridgeVlanInfo { flags, vid: self.vid };
            builder.append_attr(bridge_af::IFLA_BRIDGE_VLAN_INFO, vlan_info.as_bytes());
        }
        
        builder.nest_end(af_spec);
        
        Ok(builder)
    }
    
    fn build_flags(&self) -> u16 {
        let mut flags = 0u16;
        if self.pvid {
            flags |= bridge_vlan_flags::PVID;
        }
        if self.untagged {
            flags |= bridge_vlan_flags::UNTAGGED;
        }
        if self.master {
            flags |= bridge_vlan_flags::MASTER;
        }
        flags
    }
}
```

### Step 3: Add Connection methods

```rust
impl Connection<Route> {
    /// Add VLAN to a bridge port.
    ///
    /// # Example
    /// ```ignore
    /// // Add VLAN 100 as PVID and untagged
    /// conn.add_bridge_vlan(
    ///     BridgeVlanBuilder::new(100)
    ///         .dev("eth0")
    ///         .pvid()
    ///         .untagged()
    /// ).await?;
    /// 
    /// // Add VLAN range 200-210 as tagged
    /// conn.add_bridge_vlan(
    ///     BridgeVlanBuilder::new(200)
    ///         .dev("eth0")
    ///         .range(210)
    /// ).await?;
    /// ```
    pub async fn add_bridge_vlan(&self, config: BridgeVlanBuilder) -> Result<()> {
        let builder = config.build_add()?;
        self.send_ack(builder).await
    }
    
    /// Delete VLAN from a bridge port.
    pub async fn del_bridge_vlan(&self, dev: &str, vid: u16) -> Result<()> {
        let builder = BridgeVlanBuilder::new(vid)
            .dev(dev)
            .build_del()?;
        self.send_ack(builder).await
    }
    
    /// Set PVID for a bridge port.
    ///
    /// This adds the VLAN as PVID and untagged, which is the typical
    /// configuration for a native VLAN.
    pub async fn set_bridge_pvid(&self, dev: &str, vid: u16) -> Result<()> {
        self.add_bridge_vlan(
            BridgeVlanBuilder::new(vid)
                .dev(dev)
                .pvid()
                .untagged()
        ).await
    }
}
```

### Step 4: Add VLAN querying

For querying VLANs, we need to request link info with the BRVLAN filter:

```rust
/// Extended filter mask for VLAN info
const RTEXT_FILTER_BRVLAN: u32 = 1 << 1;

impl Connection<Route> {
    /// Get VLAN configuration for a bridge port.
    pub async fn get_bridge_vlans(&self, dev: &str) -> Result<Vec<BridgeVlanEntry>> {
        let ifindex = crate::util::get_ifindex(dev)
            .map_err(Error::InvalidMessage)?;
        
        // Request link with BRVLAN filter
        let mut builder = MessageBuilder::new(
            NlMsgType::RTM_GETLINK,
            NLM_F_REQUEST,
        );
        
        let ifinfo = IfInfoMsg::new()
            .with_family(libc::AF_BRIDGE as u8)
            .with_index(ifindex);
        builder.append(&ifinfo);
        builder.append_attr_u32(IflaAttr::ExtMask as u16, RTEXT_FILTER_BRVLAN);
        
        let response = self.send_request(builder).await?;
        
        // Parse IFLA_AF_SPEC -> IFLA_BRIDGE_VLAN_INFO entries
        self.parse_vlan_entries(&response, ifindex as u32)
    }
}
```

## Testing

### Manual Testing

```bash
# Setup
sudo ip link add br0 type bridge vlan_filtering 1
sudo ip link add veth0 type veth peer name veth1
sudo ip link set veth0 master br0
sudo ip link set br0 up
sudo ip link set veth0 up

# Run example
sudo cargo run --example bridge_vlan

# Verify with iproute2
bridge vlan show

# Cleanup
sudo ip link del br0
```

### Example

```rust
//! Example: Bridge VLAN configuration

use nlink::netlink::{Connection, Route};
use nlink::netlink::bridge_vlan::BridgeVlanBuilder;

#[tokio::main]
async fn main() -> nlink::netlink::Result<()> {
    let conn = Connection::<Route>::new()?;
    
    // Add VLAN 100 as PVID and untagged (native VLAN)
    conn.add_bridge_vlan(
        BridgeVlanBuilder::new(100)
            .dev("veth0")
            .pvid()
            .untagged()
    ).await?;
    
    // Add VLANs 200-210 as tagged
    conn.add_bridge_vlan(
        BridgeVlanBuilder::new(200)
            .dev("veth0")
            .range(210)
    ).await?;
    
    // Query VLANs
    let vlans = conn.get_bridge_vlans("veth0").await?;
    for vlan in &vlans {
        println!("VLAN {}: pvid={} untagged={}", 
            vlan.vid, vlan.flags.pvid, vlan.flags.untagged);
    }
    
    // Delete VLAN
    conn.del_bridge_vlan("veth0", 100).await?;
    
    Ok(())
}
```

## Documentation

Update CLAUDE.md with bridge VLAN section.

## Effort Estimate

- Implementation: ~4 hours
- Testing: ~1 hour  
- Documentation: ~30 minutes
- **Total: ~5-6 hours**

## Future Work

- Bridge VLAN tunneling (VLAN-to-VNI mapping)
- Per-VLAN STP state
- VLAN statistics
