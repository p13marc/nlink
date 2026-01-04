# Plan 002: Bridge FDB Management

## Overview

Add high-level API for managing bridge Forwarding Database (FDB) entries. This enables adding, deleting, and querying MAC address entries in Linux bridges.

## Motivation

Bridge FDB management is essential for:
- Container networking (adding static MAC entries)
- VXLAN overlay networks (remote VTEP MAC/IP mappings)
- Software-defined networking
- Network virtualization

Currently, nlink parses NDA_* attributes in `messages/neighbor.rs` but doesn't provide a dedicated FDB API. Users need this for container networking and overlay networks.

## Design

### API Design

```rust
/// FDB entry information.
#[derive(Debug, Clone)]
pub struct FdbEntry {
    /// Interface index
    pub ifindex: u32,
    /// MAC address
    pub mac: [u8; 6],
    /// VLAN ID (if VLAN filtering enabled)
    pub vlan: Option<u16>,
    /// Destination IP (for VXLAN)
    pub dst: Option<IpAddr>,
    /// VNI (for VXLAN)
    pub vni: Option<u32>,
    /// Entry state (permanent, reachable, etc.)
    pub state: NeighborState,
    /// Entry flags
    pub flags: u8,
    /// Master device index (bridge)
    pub master: Option<u32>,
}

/// FDB entry builder for adding entries.
#[derive(Debug, Clone)]
pub struct FdbEntryBuilder {
    mac: [u8; 6],
    dev: Option<String>,
    ifindex: Option<u32>,
    vlan: Option<u16>,
    dst: Option<IpAddr>,
    vni: Option<u32>,
    master: Option<String>,
    permanent: bool,
    self_: bool,  // NTF_SELF flag
}

impl FdbEntryBuilder {
    pub fn new(mac: [u8; 6]) -> Self;
    pub fn dev(self, dev: impl Into<String>) -> Self;
    pub fn ifindex(self, ifindex: u32) -> Self;
    pub fn vlan(self, vlan: u16) -> Self;
    pub fn dst(self, dst: IpAddr) -> Self;
    pub fn vni(self, vni: u32) -> Self;
    pub fn master(self, master: impl Into<String>) -> Self;
    pub fn permanent(self) -> Self;
    pub fn self_(self) -> Self;  // Add to interface's own FDB
}

impl Connection<Route> {
    /// Get all FDB entries for a bridge.
    pub async fn get_fdb(&self, bridge: &str) -> Result<Vec<FdbEntry>>;
    
    /// Get FDB entries for a specific bridge port.
    pub async fn get_fdb_for_port(&self, bridge: &str, port: &str) -> Result<Vec<FdbEntry>>;
    
    /// Add an FDB entry.
    pub async fn add_fdb(&self, entry: FdbEntryBuilder) -> Result<()>;
    
    /// Delete an FDB entry.
    pub async fn del_fdb(&self, dev: &str, mac: [u8; 6], vlan: Option<u16>) -> Result<()>;
    
    /// Replace an FDB entry (add or update).
    pub async fn replace_fdb(&self, entry: FdbEntryBuilder) -> Result<()>;
    
    /// Flush all dynamic FDB entries for a bridge.
    pub async fn flush_fdb(&self, bridge: &str) -> Result<()>;
}
```

### Implementation Details

FDB entries use the neighbor (RTM_NEWNEIGH/RTM_DELNEIGH) message types with specific attributes:

**Required netlink attributes:**
- `NDA_LLADDR` (2): MAC address
- `NDA_MASTER` (9): Bridge interface index
- `NDA_VLAN` (5): VLAN ID (optional)
- `NDA_DST` (1): Remote IP for VXLAN
- `NDA_VNI` (7): VNI for VXLAN

**Neighbor flags for FDB:**
- `NTF_SELF` (0x02): Entry for the interface itself
- `NTF_MASTER` (0x04): Entry for the master bridge
- `NTF_EXT_LEARNED` (0x10): Externally learned

**Neighbor states:**
- `NUD_PERMANENT` (0x80): Static entry
- `NUD_NOARP` (0x40): Don't use ARP
- `NUD_REACHABLE` (0x02): Dynamic entry

### File Changes

| File | Change |
|------|--------|
| `crates/nlink/src/netlink/fdb.rs` | New file: FDB types and builders |
| `crates/nlink/src/netlink/connection.rs` | Add FDB methods to Connection<Route> |
| `crates/nlink/src/netlink/mod.rs` | Export fdb module |
| `crates/nlink/src/lib.rs` | Re-export FdbEntry, FdbEntryBuilder |

## Implementation Steps

### Step 1: Create fdb.rs module

```rust
// crates/nlink/src/netlink/fdb.rs

use std::net::IpAddr;
use super::builder::MessageBuilder;
use super::connection::Connection;
use super::error::{Error, Result};
use super::message::{NLM_F_ACK, NLM_F_CREATE, NLM_F_EXCL, NLM_F_REQUEST, NlMsgType};
use super::messages::NeighborMessage;
use super::protocol::Route;
use super::types::neigh::{NdMsg, NdaAttr, NeighborState};

/// Neighbor flags
mod ntf {
    pub const SELF: u8 = 0x02;
    pub const MASTER: u8 = 0x04;
    pub const EXT_LEARNED: u8 = 0x10;
}

/// FDB entry information.
#[derive(Debug, Clone)]
pub struct FdbEntry {
    pub ifindex: u32,
    pub mac: [u8; 6],
    pub vlan: Option<u16>,
    pub dst: Option<IpAddr>,
    pub vni: Option<u32>,
    pub state: NeighborState,
    pub flags: u8,
    pub master: Option<u32>,
}

impl FdbEntry {
    /// Create from a NeighborMessage.
    pub fn from_neighbor(msg: &NeighborMessage) -> Option<Self> {
        let mac = msg.lladdr()?;
        if mac.len() != 6 {
            return None;
        }
        
        Some(Self {
            ifindex: msg.ifindex(),
            mac: mac.try_into().ok()?,
            vlan: msg.vlan(),
            dst: msg.destination().cloned(),
            vni: msg.vni(),
            state: msg.state(),
            flags: msg.flags(),
            master: msg.master(),
        })
    }
    
    /// Check if this is a permanent (static) entry.
    pub fn is_permanent(&self) -> bool {
        self.state == NeighborState::Permanent
    }
    
    /// Check if this is a dynamic entry.
    pub fn is_dynamic(&self) -> bool {
        !self.is_permanent()
    }
    
    /// Format MAC address as string.
    pub fn mac_str(&self) -> String {
        format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.mac[0], self.mac[1], self.mac[2],
            self.mac[3], self.mac[4], self.mac[5])
    }
}

/// Builder for FDB entries.
#[derive(Debug, Clone, Default)]
pub struct FdbEntryBuilder {
    mac: [u8; 6],
    dev: Option<String>,
    ifindex: Option<u32>,
    vlan: Option<u16>,
    dst: Option<IpAddr>,
    vni: Option<u32>,
    master: Option<String>,
    permanent: bool,
    self_: bool,
}

impl FdbEntryBuilder {
    /// Create a new FDB entry builder.
    pub fn new(mac: [u8; 6]) -> Self {
        Self {
            mac,
            permanent: true,  // Default to permanent
            ..Default::default()
        }
    }
    
    /// Parse MAC from string.
    pub fn parse_mac(mac_str: &str) -> Result<[u8; 6]> {
        crate::util::addr::parse_mac(mac_str)
            .map_err(|e| Error::InvalidMessage(format!("invalid MAC: {}", e)))
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
    
    /// Set VLAN ID.
    pub fn vlan(mut self, vlan: u16) -> Self {
        self.vlan = Some(vlan);
        self
    }
    
    /// Set destination IP (for VXLAN FDB).
    pub fn dst(mut self, dst: IpAddr) -> Self {
        self.dst = Some(dst);
        self
    }
    
    /// Set VNI (for VXLAN FDB).
    pub fn vni(mut self, vni: u32) -> Self {
        self.vni = Some(vni);
        self
    }
    
    /// Set master bridge device.
    pub fn master(mut self, master: impl Into<String>) -> Self {
        self.master = Some(master.into());
        self
    }
    
    /// Make entry permanent (static). This is the default.
    pub fn permanent(mut self) -> Self {
        self.permanent = true;
        self
    }
    
    /// Make entry dynamic.
    pub fn dynamic(mut self) -> Self {
        self.permanent = false;
        self
    }
    
    /// Add to interface's own FDB (NTF_SELF).
    pub fn self_(mut self) -> Self {
        self.self_ = true;
        self
    }
    
    /// Build the netlink message.
    pub(crate) fn build(&self) -> Result<(MessageBuilder, u32)> {
        let ifindex = if let Some(idx) = self.ifindex {
            idx
        } else if let Some(ref dev) = self.dev {
            crate::util::get_ifindex(dev)
                .map_err(Error::InvalidMessage)? as u32
        } else {
            return Err(Error::InvalidMessage("device required".into()));
        };
        
        let family = match self.dst {
            Some(IpAddr::V6(_)) => libc::AF_INET6 as u8,
            _ => libc::AF_BRIDGE as u8,
        };
        
        let state = if self.permanent {
            NeighborState::Permanent as u16
        } else {
            NeighborState::Reachable as u16
        };
        
        let mut flags: u8 = 0;
        if self.self_ {
            flags |= ntf::SELF;
        }
        
        let ndmsg = NdMsg::new()
            .with_family(family)
            .with_ifindex(ifindex as i32)
            .with_state(state)
            .with_flags(flags);
        
        let mut builder = MessageBuilder::new(
            NlMsgType::RTM_NEWNEIGH,
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
        );
        
        builder.append(&ndmsg);
        
        // NDA_LLADDR - MAC address
        builder.append_attr(NdaAttr::Lladdr as u16, &self.mac);
        
        // NDA_MASTER - bridge interface
        if let Some(ref master) = self.master {
            let master_idx = crate::util::get_ifindex(master)
                .map_err(Error::InvalidMessage)?;
            builder.append_attr_u32(NdaAttr::Master as u16, master_idx as u32);
        }
        
        // NDA_VLAN
        if let Some(vlan) = self.vlan {
            builder.append_attr_u16(NdaAttr::Vlan as u16, vlan);
        }
        
        // NDA_DST - remote IP for VXLAN
        if let Some(ref dst) = self.dst {
            match dst {
                IpAddr::V4(v4) => {
                    builder.append_attr(NdaAttr::Dst as u16, &v4.octets());
                }
                IpAddr::V6(v6) => {
                    builder.append_attr(NdaAttr::Dst as u16, &v6.octets());
                }
            }
        }
        
        // NDA_VNI
        if let Some(vni) = self.vni {
            builder.append_attr_u32(NdaAttr::Vni as u16, vni);
        }
        
        Ok((builder, ifindex))
    }
}
```

### Step 2: Add Connection methods

In `connection.rs`, add to `impl Connection<Route>`:

```rust
// ============================================================================
// FDB (Forwarding Database) Operations
// ============================================================================

/// Get all FDB entries for a bridge.
pub async fn get_fdb(&self, bridge: &str) -> Result<Vec<FdbEntry>> {
    let bridge_idx = crate::util::get_ifindex(bridge)
        .map_err(Error::InvalidMessage)?;
    
    // Get all neighbors for AF_BRIDGE family
    let neighbors = self.get_neighbors_family(libc::AF_BRIDGE as u8).await?;
    
    Ok(neighbors
        .iter()
        .filter(|n| n.master() == Some(bridge_idx as u32) || n.ifindex() == bridge_idx as u32)
        .filter_map(FdbEntry::from_neighbor)
        .collect())
}

/// Add an FDB entry.
pub async fn add_fdb(&self, entry: FdbEntryBuilder) -> Result<()> {
    let (builder, _) = entry.build()?;
    self.send_ack(builder).await
}

/// Delete an FDB entry.
pub async fn del_fdb(&self, dev: &str, mac: [u8; 6], vlan: Option<u16>) -> Result<()> {
    let ifindex = crate::util::get_ifindex(dev)
        .map_err(Error::InvalidMessage)?;
    
    let ndmsg = NdMsg::new()
        .with_family(libc::AF_BRIDGE as u8)
        .with_ifindex(ifindex as i32);
    
    let mut builder = MessageBuilder::new(
        NlMsgType::RTM_DELNEIGH,
        NLM_F_REQUEST | NLM_F_ACK,
    );
    
    builder.append(&ndmsg);
    builder.append_attr(NdaAttr::Lladdr as u16, &mac);
    
    if let Some(vlan) = vlan {
        builder.append_attr_u16(NdaAttr::Vlan as u16, vlan);
    }
    
    self.send_ack(builder).await
}
```

### Step 3: Add module exports

In `netlink/mod.rs`:
```rust
pub mod fdb;
pub use fdb::{FdbEntry, FdbEntryBuilder};
```

In `lib.rs`:
```rust
pub use netlink::fdb::{FdbEntry, FdbEntryBuilder};
```

### Step 4: Add example

Create `examples/route/bridge_fdb.rs`:

```rust
//! Example: Bridge FDB management

use nlink::netlink::{Connection, Route};
use nlink::netlink::fdb::FdbEntryBuilder;

#[tokio::main]
async fn main() -> nlink::netlink::Result<()> {
    let conn = Connection::<Route>::new()?;
    
    // List FDB entries for br0
    println!("FDB entries for br0:");
    let entries = conn.get_fdb("br0").await?;
    for entry in &entries {
        println!("  {} vlan={:?} dst={:?}", 
            entry.mac_str(), entry.vlan, entry.dst);
    }
    
    // Add a static FDB entry
    let mac = FdbEntryBuilder::parse_mac("aa:bb:cc:dd:ee:ff")?;
    conn.add_fdb(
        FdbEntryBuilder::new(mac)
            .dev("veth0")
            .master("br0")
            .vlan(100)
            .permanent()
    ).await?;
    
    // Delete the entry
    conn.del_fdb("veth0", mac, Some(100)).await?;
    
    Ok(())
}
```

## Testing

### Manual Testing

```bash
# Setup test environment
sudo ip link add br0 type bridge
sudo ip link add veth0 type veth peer name veth1
sudo ip link set veth0 master br0
sudo ip link set br0 up
sudo ip link set veth0 up

# Run example
sudo cargo run --example bridge_fdb

# Verify with iproute2
bridge fdb show br br0

# Cleanup
sudo ip link del br0
```

### Unit Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_parse_mac() {
        let mac = FdbEntryBuilder::parse_mac("aa:bb:cc:dd:ee:ff").unwrap();
        assert_eq!(mac, [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
    }
    
    #[test]
    fn test_fdb_entry_mac_str() {
        let entry = FdbEntry {
            ifindex: 1,
            mac: [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            vlan: None,
            dst: None,
            vni: None,
            state: NeighborState::Permanent,
            flags: 0,
            master: None,
        };
        assert_eq!(entry.mac_str(), "00:11:22:33:44:55");
    }
}
```

## Documentation

Update CLAUDE.md:

```markdown
**Bridge FDB management:**
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

// Add VXLAN FDB entry (remote VTEP)
conn.add_fdb(
    FdbEntryBuilder::new([0x00; 6])  // all-zeros for BUM traffic
        .dev("vxlan0")
        .dst("192.168.1.100".parse()?)
).await?;

// Delete entry
conn.del_fdb("veth0", mac, None).await?;
```
```

## Effort Estimate

- Implementation: ~3 hours
- Testing: ~1 hour
- Documentation: ~30 minutes
- **Total: ~4-5 hours**

## Future Work

- Add `flush_fdb()` to clear all dynamic entries
- Add FDB event monitoring (RTM_NEWNEIGH/RTM_DELNEIGH with AF_BRIDGE)
- Support for FDB nexthop groups (modern Linux)
