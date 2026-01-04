# Plan 009: MPTCP Endpoints

## Overview

Add support for MPTCP (Multipath TCP) endpoint configuration via Generic Netlink, allowing management of additional addresses/interfaces for multipath connections.

## Motivation

MPTCP enables:
- Bandwidth aggregation across multiple paths
- Seamless failover between networks (WiFi/cellular)
- Load balancing across interfaces
- Improved reliability for mobile devices

Currently, nlink can query MPTCP sockets via sockdiag but cannot configure endpoints.

## Design

### API Design

```rust
/// MPTCP endpoint flags.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MptcpFlags {
    /// Announce this endpoint to peers
    pub signal: bool,
    /// Use for subflow creation
    pub subflow: bool,
    /// Use as backup path
    pub backup: bool,
    /// Fully establish before using
    pub fullmesh: bool,
}

/// MPTCP endpoint builder.
#[derive(Debug, Clone)]
pub struct MptcpEndpointBuilder {
    id: Option<u8>,
    address: IpAddr,
    port: Option<u16>,
    dev: Option<String>,
    ifindex: Option<u32>,
    flags: MptcpFlags,
}

impl MptcpEndpointBuilder {
    pub fn new(address: IpAddr) -> Self;
    pub fn id(self, id: u8) -> Self;
    pub fn port(self, port: u16) -> Self;
    pub fn dev(self, dev: impl Into<String>) -> Self;
    pub fn ifindex(self, ifindex: u32) -> Self;
    pub fn signal(self) -> Self;
    pub fn subflow(self) -> Self;
    pub fn backup(self) -> Self;
    pub fn fullmesh(self) -> Self;
}

/// Parsed MPTCP endpoint information.
#[derive(Debug, Clone)]
pub struct MptcpEndpoint {
    pub id: u8,
    pub address: IpAddr,
    pub port: Option<u16>,
    pub ifindex: Option<u32>,
    pub flags: MptcpFlags,
}

/// MPTCP limits configuration.
#[derive(Debug, Clone, Default)]
pub struct MptcpLimits {
    /// Maximum subflows per connection
    pub subflows: Option<u8>,
    /// Maximum additional addresses to advertise
    pub add_addr_accepted: Option<u8>,
}

impl MptcpLimits {
    pub fn new() -> Self;
    pub fn subflows(self, max: u8) -> Self;
    pub fn add_addr_accepted(self, max: u8) -> Self;
}

impl Connection<Mptcp> {
    // Async constructor (resolves GENL family)
    pub async fn new_async() -> Result<Self>;
    
    // Endpoint operations
    pub async fn get_endpoints(&self) -> Result<Vec<MptcpEndpoint>>;
    pub async fn add_endpoint(&self, endpoint: MptcpEndpointBuilder) -> Result<()>;
    pub async fn del_endpoint(&self, id: u8) -> Result<()>;
    pub async fn flush_endpoints(&self) -> Result<()>;
    
    // Limits
    pub async fn get_limits(&self) -> Result<MptcpLimits>;
    pub async fn set_limits(&self, limits: MptcpLimits) -> Result<()>;
}
```

### Usage Example

```rust
use nlink::netlink::{Connection, Mptcp};
use nlink::netlink::genl::mptcp::{MptcpEndpointBuilder, MptcpLimits};

// Create MPTCP connection (async for GENL family resolution)
let conn = Connection::<Mptcp>::new_async().await?;

// Add endpoint for second interface
conn.add_endpoint(
    MptcpEndpointBuilder::new("192.168.2.1".parse()?)
        .id(1)
        .dev("eth1")
        .subflow()
        .signal()
).await?;

// Add backup endpoint
conn.add_endpoint(
    MptcpEndpointBuilder::new("10.0.0.1".parse()?)
        .id(2)
        .dev("wlan0")
        .backup()
        .signal()
).await?;

// Set limits
conn.set_limits(
    MptcpLimits::new()
        .subflows(4)
        .add_addr_accepted(4)
).await?;

// List endpoints
for ep in conn.get_endpoints().await? {
    println!("Endpoint {}: {} flags={:?}", ep.id, ep.address, ep.flags);
}

// Delete endpoint
conn.del_endpoint(1).await?;
```

### Implementation Details

#### Kernel Constants

```rust
// crates/nlink/src/netlink/types/mptcp.rs

/// MPTCP Path Manager GENL commands
pub mod mptcp_pm_cmd {
    pub const ADD_ADDR: u8 = 1;
    pub const DEL_ADDR: u8 = 2;
    pub const GET_ADDR: u8 = 3;
    pub const FLUSH_ADDRS: u8 = 4;
    pub const SET_LIMITS: u8 = 5;
    pub const GET_LIMITS: u8 = 6;
    pub const SET_FLAGS: u8 = 7;
    pub const ANNOUNCE: u8 = 8;
    pub const REMOVE: u8 = 9;
    pub const SUBFLOW_CREATE: u8 = 10;
    pub const SUBFLOW_DESTROY: u8 = 11;
}

/// MPTCP PM attributes
pub mod mptcp_pm_attr {
    pub const UNSPEC: u16 = 0;
    pub const ADDR: u16 = 1;
    pub const RCV_ADD_ADDRS: u16 = 2;
    pub const SUBFLOWS: u16 = 3;
    pub const TOKEN: u16 = 4;
    pub const LOC_ID: u16 = 5;
    pub const ADDR_REMOTE: u16 = 6;
}

/// MPTCP address attributes
pub mod mptcp_pm_addr_attr {
    pub const UNSPEC: u16 = 0;
    pub const FAMILY: u16 = 1;
    pub const ID: u16 = 2;
    pub const ADDR4: u16 = 3;
    pub const ADDR6: u16 = 4;
    pub const PORT: u16 = 5;
    pub const FLAGS: u16 = 6;
    pub const IF_IDX: u16 = 7;
}

/// MPTCP endpoint flags
pub mod mptcp_pm_flags {
    pub const SIGNAL: u32 = 1 << 0;
    pub const SUBFLOW: u32 = 1 << 1;
    pub const BACKUP: u32 = 1 << 2;
    pub const FULLMESH: u32 = 1 << 3;
    pub const IMPLICIT: u32 = 1 << 4;
}
```

#### Message Parsing (winnow)

```rust
// crates/nlink/src/netlink/genl/mptcp/types.rs

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use winnow::binary::{le_u8, le_u16, le_u32};
use winnow::prelude::*;
use winnow::token::take;

use crate::netlink::parse::{FromNetlink, PResult};
use crate::netlink::types::mptcp::*;

impl FromNetlink for MptcpEndpoint {
    fn parse(input: &mut &[u8]) -> PResult<Self> {
        let mut endpoint = MptcpEndpoint {
            id: 0,
            address: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            port: None,
            ifindex: None,
            flags: MptcpFlags::default(),
        };
        
        // Parse nested MPTCP_PM_ATTR_ADDR attributes
        while !input.is_empty() && input.len() >= 4 {
            let len = le_u16.parse_next(input)? as usize;
            let attr_type = le_u16.parse_next(input)? & 0x3FFF;
            
            if len < 4 { break; }
            let payload_len = len.saturating_sub(4);
            if input.len() < payload_len { break; }
            
            let attr_data: &[u8] = take(payload_len).parse_next(input)?;
            
            match attr_type {
                mptcp_pm_addr_attr::ID => {
                    if !attr_data.is_empty() {
                        endpoint.id = attr_data[0];
                    }
                }
                mptcp_pm_addr_attr::FAMILY => {
                    // Address family indicator
                }
                mptcp_pm_addr_attr::ADDR4 => {
                    if attr_data.len() >= 4 {
                        let octets: [u8; 4] = attr_data[..4].try_into().unwrap();
                        endpoint.address = IpAddr::V4(Ipv4Addr::from(octets));
                    }
                }
                mptcp_pm_addr_attr::ADDR6 => {
                    if attr_data.len() >= 16 {
                        let octets: [u8; 16] = attr_data[..16].try_into().unwrap();
                        endpoint.address = IpAddr::V6(Ipv6Addr::from(octets));
                    }
                }
                mptcp_pm_addr_attr::PORT => {
                    if attr_data.len() >= 2 {
                        endpoint.port = Some(u16::from_be_bytes(
                            attr_data[..2].try_into().unwrap()
                        ));
                    }
                }
                mptcp_pm_addr_attr::FLAGS => {
                    if attr_data.len() >= 4 {
                        let flags = u32::from_ne_bytes(
                            attr_data[..4].try_into().unwrap()
                        );
                        endpoint.flags = MptcpFlags {
                            signal: flags & mptcp_pm_flags::SIGNAL != 0,
                            subflow: flags & mptcp_pm_flags::SUBFLOW != 0,
                            backup: flags & mptcp_pm_flags::BACKUP != 0,
                            fullmesh: flags & mptcp_pm_flags::FULLMESH != 0,
                        };
                    }
                }
                mptcp_pm_addr_attr::IF_IDX => {
                    if attr_data.len() >= 4 {
                        endpoint.ifindex = Some(u32::from_ne_bytes(
                            attr_data[..4].try_into().unwrap()
                        ));
                    }
                }
                _ => {}
            }
            
            // Align to 4 bytes
            let aligned = (len + 3) & !3;
            let padding = aligned.saturating_sub(len);
            if input.len() >= padding {
                let _: &[u8] = take(padding).parse_next(input)?;
            }
        }
        
        Ok(endpoint)
    }
}

impl FromNetlink for MptcpLimits {
    fn parse(input: &mut &[u8]) -> PResult<Self> {
        let mut limits = MptcpLimits::default();
        
        while !input.is_empty() && input.len() >= 4 {
            let len = le_u16.parse_next(input)? as usize;
            let attr_type = le_u16.parse_next(input)? & 0x3FFF;
            
            if len < 4 { break; }
            let payload_len = len.saturating_sub(4);
            if input.len() < payload_len { break; }
            
            let attr_data: &[u8] = take(payload_len).parse_next(input)?;
            
            match attr_type {
                mptcp_pm_attr::RCV_ADD_ADDRS => {
                    if attr_data.len() >= 4 {
                        limits.add_addr_accepted = Some(
                            u32::from_ne_bytes(attr_data[..4].try_into().unwrap()) as u8
                        );
                    }
                }
                mptcp_pm_attr::SUBFLOWS => {
                    if attr_data.len() >= 4 {
                        limits.subflows = Some(
                            u32::from_ne_bytes(attr_data[..4].try_into().unwrap()) as u8
                        );
                    }
                }
                _ => {}
            }
            
            let aligned = (len + 3) & !3;
            let padding = aligned.saturating_sub(len);
            if input.len() >= padding {
                let _: &[u8] = take(padding).parse_next(input)?;
            }
        }
        
        Ok(limits)
    }
}
```

### File Changes

| File | Change |
|------|--------|
| `crates/nlink/src/netlink/genl/mptcp/mod.rs` | Module entry |
| `crates/nlink/src/netlink/genl/mptcp/types.rs` | MptcpEndpoint, builders, FromNetlink |
| `crates/nlink/src/netlink/genl/mptcp/connection.rs` | Connection<Mptcp> implementation |
| `crates/nlink/src/netlink/types/mptcp.rs` | Kernel constants |
| `crates/nlink/src/netlink/protocol.rs` | Add Mptcp protocol state |
| `crates/nlink/src/netlink/genl/mod.rs` | Export mptcp module |

## Implementation Steps

1. Add `Mptcp` protocol state type
2. Define kernel constants in `types/mptcp.rs`
3. Create `genl/mptcp/` module structure
4. Implement `MptcpEndpoint` with `FromNetlink` parsing
5. Implement `MptcpLimits` with `FromNetlink` parsing
6. Implement builders for configuration
7. Add `Connection<Mptcp>` methods
8. Add example and tests

## Effort Estimate

- Implementation: ~6 hours
- Testing: ~2 hours
- Documentation: ~1 hour
- **Total: ~9 hours**
