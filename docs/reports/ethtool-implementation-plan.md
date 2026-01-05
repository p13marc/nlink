# Ethtool Implementation Plan for nlink

This document outlines what would be needed to implement ethtool support in nlink.

## Overview

Ethtool is a Linux utility for querying and controlling network driver and hardware settings. Since Linux 5.6, a netlink-based interface has been available alongside the legacy ioctl interface, providing better extensibility, notifications, and error reporting.

## Current State

| Project | Ethtool Support |
|---------|-----------------|
| iproute2 | Full (via `ethtool` command) |
| rust-netlink/ethtool | Partial (v0.2.9) |
| nlink | Not implemented |

### rust-netlink/ethtool Coverage

The existing Rust crate implements only GET operations for a subset of features:

| Feature | GET | SET |
|---------|:---:|:---:|
| Channels | Yes | Yes |
| Coalesce | Yes | No |
| Features | Yes | No |
| FEC | Yes | No |
| Link modes | Yes | No |
| Pause | Yes | No |
| Rings | Yes | No |
| Timestamp info | Yes | No |

Missing: Link info, link state, debug, WoL, private flags, EEE, tunnel info, module EEPROM, stats, PHC vclocks, module params, PSE, RSS, PLCA, MAC merge, PHY, cable test, and more.

## Ethtool Netlink Protocol

### Protocol Characteristics

- **Family**: Generic Netlink (GENL), family name `"ethtool"`
- **Header**: Standard GENL header (no family-specific header)
- **Multicast group**: `"monitor"` for notifications
- **Capabilities required**: `CAP_NET_ADMIN` for SET/ACT operations

### Message Types

The protocol defines three categories of commands:

| Suffix | Purpose | Privilege |
|--------|---------|-----------|
| `_GET` | Query information | Usually none (some need CAP_NET_ADMIN) |
| `_SET` | Modify parameters | CAP_NET_ADMIN |
| `_ACT` | Perform actions | CAP_NET_ADMIN |

### Complete Command List (Linux 6.x)

#### Information Retrieval (GET)

| Command | Description | Use Case |
|---------|-------------|----------|
| `STRSET_GET` | Get string sets | Enumerate available options |
| `LINKINFO_GET` | Link settings | Port type, MDI-X, transceiver |
| `LINKMODES_GET` | Link modes | Speed, duplex, autoneg, advertised modes |
| `LINKSTATE_GET` | Link state | Carrier, SQI, ext. state |
| `DEBUG_GET` | Debug settings | Message levels |
| `WOL_GET` | Wake-on-LAN | WoL modes, SecureOn password |
| `FEATURES_GET` | Device features | Offloads, checksumming |
| `PRIVFLAGS_GET` | Private flags | Driver-specific flags |
| `RINGS_GET` | Ring sizes | RX/TX ring buffer sizes |
| `CHANNELS_GET` | Channel counts | RX/TX/combined queues |
| `COALESCE_GET` | Coalescing params | Interrupt coalescing |
| `PAUSE_GET` | Pause/flow control | TX/RX pause, auto-neg |
| `EEE_GET` | Energy Efficient Ethernet | EEE modes, timers |
| `TSINFO_GET` | Timestamping info | HW/SW timestamp capabilities |
| `TUNNEL_INFO_GET` | Tunnel offload info | Encap offload capabilities |
| `FEC_GET` | Forward Error Correction | FEC modes, stats |
| `MODULE_EEPROM_GET` | SFP module EEPROM | Transceiver info (SFF-8472, etc.) |
| `STATS_GET` | Standard statistics | MAC, PHY, RMON stats |
| `PHC_VCLOCKS_GET` | PHC virtual clocks | PTP virtual clocks |
| `MODULE_GET` | Transceiver module params | Power mode, reset |
| `PSE_GET` | Power Sourcing Equipment | PoE status |
| `RSS_GET` | Receive Side Scaling | Hash key, indirection table |
| `PLCA_GET_CFG` | PLCA RS config | 10BASE-T1S parameters |
| `PLCA_GET_STATUS` | PLCA RS status | 10BASE-T1S state |
| `MM_GET` | MAC Merge layer | 802.3br preemption state |
| `PHY_GET` | PHY information | PHY device details |
| `TSCONFIG_GET` | HW timestamp config | Current TS configuration |
| `MSE_GET` | Mean Square Error | Signal quality diagnostic |

#### Configuration (SET)

| Command | Description |
|---------|-------------|
| `LINKINFO_SET` | Modify port type, MDI-X |
| `LINKMODES_SET` | Set speed, duplex, autoneg |
| `DEBUG_SET` | Set message levels |
| `WOL_SET` | Configure Wake-on-LAN |
| `FEATURES_SET` | Enable/disable features |
| `PRIVFLAGS_SET` | Set private flags |
| `RINGS_SET` | Configure ring sizes |
| `CHANNELS_SET` | Configure queue counts |
| `COALESCE_SET` | Set coalescing params |
| `PAUSE_SET` | Configure flow control |
| `EEE_SET` | Configure EEE |
| `FEC_SET` | Configure FEC |
| `MODULE_SET` | Configure transceiver |
| `PSE_SET` | Configure PoE |
| `RSS_SET` | Configure RSS |
| `PLCA_SET_CFG` | Configure PLCA |
| `MM_SET` | Configure MAC Merge |
| `TSCONFIG_SET` | Configure HW timestamps |

#### Actions (ACT)

| Command | Description |
|---------|-------------|
| `CABLE_TEST_ACT` | Start cable test |
| `CABLE_TEST_TDR_ACT` | Start TDR cable test |
| `MODULE_FW_FLASH_ACT` | Flash transceiver firmware |
| `RSS_CREATE_ACT` | Create RSS context |
| `RSS_DELETE_ACT` | Delete RSS context |

### Request Header

All requests include a common header with:

```
ETHTOOL_A_HEADER_DEV_INDEX  - Interface index (u32)
ETHTOOL_A_HEADER_DEV_NAME   - Interface name (string)
ETHTOOL_A_HEADER_FLAGS      - Request flags (u32)
ETHTOOL_A_HEADER_PHY_INDEX  - PHY device index (u32, optional)
```

Flags:
- `ETHTOOL_FLAG_COMPACT_BITSETS` - Use compact bitset format
- `ETHTOOL_FLAG_OMIT_REPLY` - Don't send reply (for SET)
- `ETHTOOL_FLAG_STATS` - Include statistics in reply

### Bitset Handling

Ethtool uses a special bitset format for feature flags and link modes:

1. **Compact format**: Two bitmaps (values + mask)
2. **Bit-by-bit format**: List of (index, name) pairs

This is more complex than typical netlink attributes and requires dedicated parsing.

## Implementation Plan for nlink

### Phase 1: Core Infrastructure

Create the basic GENL ethtool module:

```
crates/nlink/src/netlink/genl/ethtool/
├── mod.rs           # Constants, commands, attributes enums
├── types.rs         # Response structs (EthtoolDevice, LinkModes, etc.)
├── connection.rs    # Connection<Ethtool> implementation
├── bitset.rs        # Bitset parsing/building helpers
└── stringset.rs     # String set handling
```

Key components:

1. **Protocol constants** (`mod.rs`):
   ```rust
   pub const ETHTOOL_GENL_NAME: &str = "ethtool";
   pub const ETHTOOL_GENL_VERSION: u8 = 1;
   
   #[repr(u8)]
   pub enum EthtoolCmd {
       StrsetGet = 1,
       LinkinfoGet = 2,
       LinkinfoSet = 3,
       // ... all commands
   }
   
   #[repr(u16)]
   pub enum EthtoolHeaderAttr {
       Unspec = 0,
       DevIndex = 1,
       DevName = 2,
       Flags = 3,
       PhyIndex = 4,
   }
   ```

2. **Bitset handling** (`bitset.rs`):
   ```rust
   pub struct EthtoolBitset {
       pub values: Vec<bool>,
       pub names: Vec<String>,
   }
   
   impl EthtoolBitset {
       pub fn parse(data: &[u8], compact: bool) -> Result<Self>;
       pub fn build(&self, builder: &mut MessageBuilder, compact: bool);
   }
   ```

3. **Connection implementation** (`connection.rs`):
   ```rust
   impl Connection<Ethtool> {
       pub async fn new_async() -> Result<Self>;
       
       // String sets (needed for name resolution)
       pub async fn get_stringset(&self, set_id: u32) -> Result<Vec<String>>;
       
       // Core queries
       pub async fn get_link_info(&self, ifname: &str) -> Result<LinkInfo>;
       pub async fn get_link_modes(&self, ifname: &str) -> Result<LinkModes>;
       pub async fn get_link_state(&self, ifname: &str) -> Result<LinkState>;
       // ...
   }
   ```

### Phase 2: Priority Features

Based on common use cases, implement in this order:

| Priority | Feature | Rationale |
|----------|---------|-----------|
| 1 | Link state | Most common query (link up/down) |
| 2 | Link modes | Speed/duplex configuration |
| 3 | Link info | Port type, transceiver |
| 4 | Features | Offload configuration |
| 5 | Rings | Performance tuning |
| 6 | Channels | Multi-queue configuration |
| 7 | Coalesce | Interrupt tuning |
| 8 | Pause | Flow control |
| 9 | Statistics | Performance monitoring |
| 10 | Module EEPROM | SFP/QSFP diagnostics |

### Phase 3: Advanced Features

Lower priority but useful:

- EEE (Energy Efficient Ethernet)
- FEC (Forward Error Correction)
- WoL (Wake-on-LAN)
- Cable testing
- RSS configuration
- PHY-specific operations
- Timestamping configuration

### Phase 4: Event Monitoring

Subscribe to the `"monitor"` multicast group:

```rust
impl Connection<Ethtool> {
    pub fn subscribe_monitor(&mut self) -> Result<()>;
    
    pub fn events(&self) -> impl Stream<Item = Result<EthtoolEvent>>;
}

pub enum EthtoolEvent {
    LinkInfoChanged(LinkInfo),
    LinkModesChanged(LinkModes),
    FeaturesChanged(Features),
    // ...
}
```

## API Design

### Following nlink Patterns

The implementation should follow existing nlink GENL patterns (WireGuard, MACsec, MPTCP):

```rust
use nlink::netlink::{Connection, Ethtool};

// Create connection (resolves family ID)
let conn = Connection::<Ethtool>::new_async().await?;

// Query link state
let state = conn.get_link_state("eth0").await?;
println!("Link: {}", if state.link { "up" } else { "down" });
println!("Speed: {:?}", state.speed);

// Query link modes
let modes = conn.get_link_modes("eth0").await?;
println!("Autoneg: {}", modes.autoneg);
println!("Advertised: {:?}", modes.advertised);

// Set link modes
conn.set_link_modes("eth0", |m| {
    m.autoneg(true)
     .advertise(&["1000baseT/Full", "100baseT/Full"])
}).await?;

// Query features
let features = conn.get_features("eth0").await?;
println!("TSO: {}", features.is_enabled("tx-tcp-segmentation"));

// Modify features
conn.set_features("eth0", |f| {
    f.enable("tx-checksumming")
     .disable("rx-gro")
}).await?;

// Monitor events
conn.subscribe_monitor()?;
let mut events = conn.events();
while let Some(event) = events.next().await {
    match event? {
        EthtoolEvent::LinkModesChanged(modes) => {
            println!("Speed changed to: {:?}", modes.speed);
        }
        _ => {}
    }
}
```

### Response Types

Design clear, documented response types:

```rust
/// Link state information
#[derive(Debug, Clone)]
pub struct LinkState {
    /// Interface is up (has carrier)
    pub link: bool,
    /// Signal Quality Index (0-100, if supported)
    pub sqi: Option<u32>,
    /// Maximum SQI value supported
    pub sqi_max: Option<u32>,
    /// Extended link state
    pub ext_state: Option<LinkExtState>,
    /// Extended link substate
    pub ext_substate: Option<u32>,
}

/// Link modes configuration
#[derive(Debug, Clone)]
pub struct LinkModes {
    /// Autonegotiation enabled
    pub autoneg: bool,
    /// Current speed in Mbps
    pub speed: Option<u32>,
    /// Duplex mode
    pub duplex: Option<Duplex>,
    /// Lanes count (for multi-lane links)
    pub lanes: Option<u32>,
    /// Advertised link modes
    pub advertised: Vec<String>,
    /// Supported link modes
    pub supported: Vec<String>,
    /// Peer's advertised modes
    pub peer: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Duplex {
    Half,
    Full,
    Unknown,
}
```

## Estimated Effort

| Phase | Scope | Effort |
|-------|-------|--------|
| 1 | Core infrastructure | 2-3 days |
| 2 | Priority features (10) | 5-7 days |
| 3 | Advanced features | 3-5 days |
| 4 | Event monitoring | 1-2 days |
| **Total** | | **11-17 days** |

## File Structure

```
crates/nlink/src/netlink/genl/ethtool/
├── mod.rs              # Module exports, constants
├── commands.rs         # EthtoolCmd enum (all ~35 commands)
├── attrs.rs            # Attribute enums for each command
├── types.rs            # Response structs
├── connection.rs       # Connection<Ethtool> implementation
├── bitset.rs           # Bitset parsing/building
├── stringset.rs        # String set handling
└── tests.rs            # Unit tests

crates/nlink/src/netlink/types/ethtool.rs  # Low-level kernel structures
```

## Testing Strategy

1. **Unit tests**: Parse known-good netlink responses
2. **Integration tests**: Require physical NIC or dummy interface
3. **Mock tests**: Simulate kernel responses for edge cases

Example integration test:

```rust
#[tokio::test]
#[ignore] // Requires CAP_NET_ADMIN
async fn test_get_link_state() {
    let conn = Connection::<Ethtool>::new_async().await.unwrap();
    
    // lo always exists and is always up
    let state = conn.get_link_state("lo").await.unwrap();
    assert!(state.link);
}
```

## Comparison with rust-netlink/ethtool

| Aspect | rust-netlink/ethtool | nlink (proposed) |
|--------|---------------------|------------------|
| Architecture | Multi-crate | Single crate with feature |
| Commands | ~8 GET only | All 35+ commands |
| SET operations | Only channels | Full coverage |
| ACT operations | None | Cable test, RSS, firmware |
| Event monitoring | No | Yes |
| Bitset handling | Partial | Full (compact + verbose) |
| Documentation | 2% | Target 80%+ |
| API style | Request/Handle pattern | Connection<P> pattern |

## Dependencies

No new dependencies required. Reuses existing:
- `zerocopy` for struct serialization
- `winnow` for TLV attribute parsing
- `tokio` for async
- `thiserror` for error types
- Existing GENL infrastructure

## Implementation Guidelines Compliance

Per [GUIDELINES.md](../plans/GUIDELINES.md), the implementation must:

| Requirement | How to Comply |
|-------------|---------------|
| **Zerocopy for kernel structs** | No fixed-size ethtool headers (uses standard GENL header) |
| **Winnow for TLV parsing** | Parse ethtool attributes, especially bitsets |
| **Strongly typed** | Use enums for commands, attributes, duplex modes, link states |
| **High-level API** | `Connection<Ethtool>` with typed builders |
| **Async (Tokio)** | All methods returning `Result` must be `async` |
| **thiserror** | Create `EthtoolError` enum with informative messages |

### Error Types

```rust
use thiserror::Error;

#[derive(Debug, Error)]
pub enum EthtoolError {
    #[error("device not found: {0}")]
    DeviceNotFound(String),
    
    #[error("feature not supported by device: {0}")]
    FeatureNotSupported(String),
    
    #[error("invalid speed: {0} Mbps")]
    InvalidSpeed(u32),
    
    #[error("invalid bitset format")]
    InvalidBitset,
    
    #[error("string set {0} not found")]
    StringSetNotFound(u32),
    
    #[error("netlink error: {0}")]
    Netlink(#[from] crate::netlink::Error),
}
```

## Phase 5: Binary and Examples

After the library implementation is complete, create:

### Proof-of-Concept Binary

Create `bins/ethtool/` as a thin wrapper demonstrating the library:

```
bins/ethtool/
├── Cargo.toml
└── src/
    └── main.rs
```

**Cargo.toml:**
```toml
[package]
name = "nlink-ethtool"
version.workspace = true
edition.workspace = true
publish = false

[dependencies]
nlink = { path = "../../crates/nlink", features = ["output"] }
clap = { version = "4", features = ["derive"] }
tokio = { version = "1", features = ["rt-multi-thread", "macros"] }
```

**Supported subcommands** (matching standard ethtool):

| Subcommand | Description | Library Method |
|------------|-------------|----------------|
| `<devname>` | Show device settings | `get_link_info()`, `get_link_modes()` |
| `-i <devname>` | Show driver info | `get_driver_info()` |
| `-S <devname>` | Show statistics | `get_stats()` |
| `-k <devname>` | Show features | `get_features()` |
| `-K <devname>` | Set features | `set_features()` |
| `-g <devname>` | Show ring sizes | `get_rings()` |
| `-G <devname>` | Set ring sizes | `set_rings()` |
| `-l <devname>` | Show channels | `get_channels()` |
| `-L <devname>` | Set channels | `set_channels()` |
| `-c <devname>` | Show coalesce | `get_coalesce()` |
| `-C <devname>` | Set coalesce | `set_coalesce()` |
| `-a <devname>` | Show pause | `get_pause()` |
| `-A <devname>` | Set pause | `set_pause()` |
| `-m <devname>` | Show module EEPROM | `get_module_eeprom()` |
| `-s <devname>` | Set speed/duplex | `set_link_modes()` |
| `--monitor` | Monitor events | `events()` stream |

### Library Examples

Create examples in `crates/nlink/examples/genl/ethtool/`:

```
crates/nlink/examples/genl/
├── ethtool_link_state.rs      # Query link up/down, speed
├── ethtool_features.rs        # List and toggle offloads
├── ethtool_rings.rs           # Query and set ring buffer sizes
├── ethtool_monitor.rs         # Monitor ethtool events
└── ethtool_module_eeprom.rs   # Read SFP/QSFP info
```

**Example: ethtool_link_state.rs**
```rust
//! Query link state and speed for a network interface.
//!
//! Usage: cargo run --example ethtool_link_state -- eth0

use nlink::netlink::{Connection, Ethtool};

#[tokio::main]
async fn main() -> nlink::Result<()> {
    let ifname = std::env::args().nth(1).unwrap_or_else(|| "eth0".into());
    
    let conn = Connection::<Ethtool>::new_async().await?;
    
    // Get link state
    let state = conn.get_link_state(&ifname).await?;
    println!("Link detected: {}", if state.link { "yes" } else { "no" });
    
    if let Some(sqi) = state.sqi {
        println!("Signal Quality: {}/{}", sqi, state.sqi_max.unwrap_or(100));
    }
    
    // Get link modes
    let modes = conn.get_link_modes(&ifname).await?;
    if let Some(speed) = modes.speed {
        println!("Speed: {} Mb/s", speed);
    }
    if let Some(duplex) = modes.duplex {
        println!("Duplex: {:?}", duplex);
    }
    println!("Auto-negotiation: {}", if modes.autoneg { "on" } else { "off" });
    
    Ok(())
}
```

**Example: ethtool_features.rs**
```rust
//! List and modify device features (offloads).
//!
//! Usage:
//!   cargo run --example ethtool_features -- eth0
//!   cargo run --example ethtool_features -- eth0 --disable rx-gro

use nlink::netlink::{Connection, Ethtool};

#[tokio::main]
async fn main() -> nlink::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let ifname = args.get(1).map(|s| s.as_str()).unwrap_or("eth0");
    
    let conn = Connection::<Ethtool>::new_async().await?;
    let features = conn.get_features(ifname).await?;
    
    println!("Features for {}:", ifname);
    for (name, enabled) in features.iter() {
        let status = if enabled { "on" } else { "off" };
        println!("  {}: {}", name, status);
    }
    
    Ok(())
}
```

**Example: ethtool_monitor.rs**
```rust
//! Monitor ethtool events in real-time.
//!
//! Usage: cargo run --example ethtool_monitor

use nlink::netlink::{Connection, Ethtool};
use tokio_stream::StreamExt;

#[tokio::main]
async fn main() -> nlink::Result<()> {
    let mut conn = Connection::<Ethtool>::new_async().await?;
    conn.subscribe_monitor()?;
    
    println!("Monitoring ethtool events (Ctrl+C to stop)...");
    
    let mut events = conn.events();
    while let Some(event) = events.next().await {
        match event? {
            EthtoolEvent::LinkModesChanged { ifname, modes } => {
                println!("[{}] speed changed to {:?}", ifname, modes.speed);
            }
            EthtoolEvent::FeaturesChanged { ifname, .. } => {
                println!("[{}] features changed", ifname);
            }
            _ => {}
        }
    }
    
    Ok(())
}
```

### Updated Effort Estimate

| Phase | Scope | Effort |
|-------|-------|--------|
| 1 | Core infrastructure | 2-3 days |
| 2 | Priority features (10) | 5-7 days |
| 3 | Advanced features | 3-5 days |
| 4 | Event monitoring | 1-2 days |
| 5 | Binary + examples | 2-3 days |
| **Total** | | **13-20 days** |

### Cargo.toml Updates

Add example entries to `crates/nlink/Cargo.toml`:

```toml
# Ethtool examples
[[example]]
name = "ethtool_link_state"
path = "examples/genl/ethtool_link_state.rs"

[[example]]
name = "ethtool_features"
path = "examples/genl/ethtool_features.rs"

[[example]]
name = "ethtool_rings"
path = "examples/genl/ethtool_rings.rs"

[[example]]
name = "ethtool_monitor"
path = "examples/genl/ethtool_monitor.rs"

[[example]]
name = "ethtool_module_eeprom"
path = "examples/genl/ethtool_module_eeprom.rs"
```

## Sources

- [Netlink interface for ethtool - Linux Kernel Documentation](https://docs.kernel.org/networking/ethtool-netlink.html)
- [linux/include/uapi/linux/ethtool_netlink.h](https://github.com/torvalds/linux/blob/master/include/uapi/linux/ethtool_netlink.h)
- [rust-netlink/ethtool - GitHub](https://github.com/rust-netlink/ethtool)
- [ethtool netlink interface, part 1 - LWN.net](https://lwn.net/Articles/808028/)
