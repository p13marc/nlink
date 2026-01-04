# Plan 008: MACsec Configuration

## Overview

Add support for MACsec (IEEE 802.1AE) configuration via Generic Netlink, similar to the existing WireGuard support.

## Motivation

MACsec provides Layer 2 encryption for:
- Datacenter interconnects
- Campus networks with security requirements
- Point-to-point secure links
- Compliance requirements (PCI-DSS, HIPAA)

## Design

### API Design

```rust
/// MACsec cipher suite.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MacsecCipherSuite {
    /// GCM-AES-128
    GcmAes128,
    /// GCM-AES-256
    GcmAes256,
    /// GCM-AES-XPN-128 (extended packet numbering)
    GcmAesXpn128,
    /// GCM-AES-XPN-256
    GcmAesXpn256,
}

/// MACsec validation mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MacsecValidate {
    Disabled,
    Check,
    Strict,
}

/// MACsec device configuration builder.
#[derive(Debug, Clone)]
pub struct MacsecConfigBuilder {
    parent: String,
    sci: Option<u64>,
    cipher: MacsecCipherSuite,
    icv_len: u8,
    encrypt: bool,
    replay_protect: bool,
    replay_window: u32,
    validate: MacsecValidate,
}

impl MacsecConfigBuilder {
    pub fn new(parent: impl Into<String>) -> Self;
    pub fn sci(self, sci: u64) -> Self;
    pub fn cipher(self, cipher: MacsecCipherSuite) -> Self;
    pub fn icv_len(self, len: u8) -> Self;
    pub fn encrypt(self, encrypt: bool) -> Self;
    pub fn replay_protect(self, protect: bool) -> Self;
    pub fn replay_window(self, window: u32) -> Self;
    pub fn validate(self, mode: MacsecValidate) -> Self;
}

/// MACsec TX/RX SA (Security Association) builder.
#[derive(Debug, Clone)]
pub struct MacsecSaBuilder {
    an: u8,
    key: Vec<u8>,
    pn: u64,
    active: bool,
}

impl MacsecSaBuilder {
    pub fn new(an: u8, key: &[u8]) -> Self;
    pub fn packet_number(self, pn: u64) -> Self;
    pub fn active(self, active: bool) -> Self;
}

/// Parsed MACsec device information.
#[derive(Debug, Clone)]
pub struct MacsecDevice {
    pub ifindex: u32,
    pub sci: u64,
    pub cipher: MacsecCipherSuite,
    pub icv_len: u8,
    pub encrypt: bool,
    pub replay_protect: bool,
    pub replay_window: u32,
    pub validate: MacsecValidate,
    pub tx_sc: Option<MacsecTxSc>,
    pub rx_scs: Vec<MacsecRxSc>,
}

impl Connection<Macsec> {
    // Async connection constructor (resolves GENL family)
    pub async fn new_async() -> Result<Self>;
    
    // Device operations
    pub async fn get_device(&self, dev: &str) -> Result<MacsecDevice>;
    pub async fn set_device(&self, dev: &str, config: MacsecConfigBuilder) -> Result<()>;
    
    // TX SA operations
    pub async fn add_tx_sa(&self, dev: &str, sa: MacsecSaBuilder) -> Result<()>;
    pub async fn del_tx_sa(&self, dev: &str, an: u8) -> Result<()>;
    
    // RX SC/SA operations
    pub async fn add_rx_sc(&self, dev: &str, sci: u64) -> Result<()>;
    pub async fn del_rx_sc(&self, dev: &str, sci: u64) -> Result<()>;
    pub async fn add_rx_sa(&self, dev: &str, sci: u64, sa: MacsecSaBuilder) -> Result<()>;
    pub async fn del_rx_sa(&self, dev: &str, sci: u64, an: u8) -> Result<()>;
}
```

### Usage Example

```rust
use nlink::netlink::{Connection, Macsec};
use nlink::netlink::genl::macsec::{MacsecConfigBuilder, MacsecCipherSuite, MacsecSaBuilder};

// Create MACsec connection (async for GENL family resolution)
let conn = Connection::<Macsec>::new_async().await?;

// Configure MACsec device
conn.set_device("macsec0",
    MacsecConfigBuilder::new("eth0")
        .cipher(MacsecCipherSuite::GcmAes256)
        .encrypt(true)
        .replay_protect(true)
        .replay_window(32)
).await?;

// Add TX SA
let key = [0u8; 32];  // 256-bit key
conn.add_tx_sa("macsec0", 
    MacsecSaBuilder::new(0, &key)
        .packet_number(1)
        .active(true)
).await?;

// Add RX SC and SA
let peer_sci: u64 = 0x001122334455_0001;
conn.add_rx_sc("macsec0", peer_sci).await?;
conn.add_rx_sa("macsec0", peer_sci,
    MacsecSaBuilder::new(0, &key)
        .packet_number(1)
).await?;

// Query device
let device = conn.get_device("macsec0").await?;
println!("SCI: {:016x}, cipher: {:?}", device.sci, device.cipher);
```

### Implementation Details

#### Kernel Structures (zerocopy)

```rust
// crates/nlink/src/netlink/types/macsec.rs

use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

/// MACsec GENL commands
pub mod macsec_cmd {
    pub const GET_TXSC: u8 = 0;
    pub const ADD_RXSC: u8 = 1;
    pub const DEL_RXSC: u8 = 2;
    pub const UPD_RXSC: u8 = 3;
    pub const ADD_TXSA: u8 = 4;
    pub const DEL_TXSA: u8 = 5;
    pub const ADD_RXSA: u8 = 6;
    pub const DEL_RXSA: u8 = 7;
    pub const GET_RXSC: u8 = 8;
    pub const GET_TXSA: u8 = 9;
    pub const GET_RXSA: u8 = 10;
    pub const UPD_TXSA: u8 = 11;
    pub const UPD_RXSA: u8 = 12;
    pub const UPD_OFFLOAD: u8 = 13;
}

/// MACsec GENL attributes
pub mod macsec_attr {
    pub const UNSPEC: u16 = 0;
    pub const IFINDEX: u16 = 1;
    pub const RXSC_CONFIG: u16 = 2;
    pub const RXSC_STATS: u16 = 3;
    pub const SA_CONFIG: u16 = 4;
    pub const SA_STATS: u16 = 5;
    pub const SECY_CONFIG: u16 = 6;
    pub const SECY_STATS: u16 = 7;
    pub const TXSC_STATS: u16 = 8;
    pub const RXSC_LIST: u16 = 9;
    pub const TXSA_LIST: u16 = 10;
    pub const OFFLOAD: u16 = 11;
}

/// SA configuration attributes
pub mod macsec_sa_attr {
    pub const UNSPEC: u16 = 0;
    pub const AN: u16 = 1;
    pub const ACTIVE: u16 = 2;
    pub const PN: u16 = 3;
    pub const KEY: u16 = 4;
    pub const KEYID: u16 = 5;
}

/// Cipher suite IDs
pub mod macsec_cipher {
    pub const GCM_AES_128: u64 = 0x0080020001000001;
    pub const GCM_AES_256: u64 = 0x0080C20001000001;
    pub const GCM_AES_XPN_128: u64 = 0x0080C20001000002;
    pub const GCM_AES_XPN_256: u64 = 0x0080C20001000003;
}
```

#### Message Parsing (winnow)

```rust
// crates/nlink/src/netlink/genl/macsec/types.rs

use winnow::binary::{le_u8, le_u16, le_u32, le_u64};
use winnow::prelude::*;
use winnow::token::take;

use crate::netlink::parse::{FromNetlink, PResult};

impl FromNetlink for MacsecDevice {
    fn parse(input: &mut &[u8]) -> PResult<Self> {
        let mut device = MacsecDevice::default();
        
        // Parse nested attributes
        while !input.is_empty() && input.len() >= 4 {
            let len = le_u16.parse_next(input)? as usize;
            let attr_type = le_u16.parse_next(input)? & 0x3FFF;
            
            if len < 4 { break; }
            let payload_len = len.saturating_sub(4);
            if input.len() < payload_len { break; }
            
            let attr_data: &[u8] = take(payload_len).parse_next(input)?;
            
            match attr_type {
                macsec_attr::IFINDEX => {
                    if attr_data.len() >= 4 {
                        device.ifindex = u32::from_ne_bytes(
                            attr_data[..4].try_into().unwrap()
                        );
                    }
                }
                macsec_attr::SECY_CONFIG => {
                    // Parse nested secy config
                    device.parse_secy_config(attr_data)?;
                }
                macsec_attr::RXSC_LIST => {
                    // Parse RX SC list
                    device.parse_rxsc_list(attr_data)?;
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
        
        Ok(device)
    }
}
```

### File Changes

| File | Change |
|------|--------|
| `crates/nlink/src/netlink/genl/macsec/mod.rs` | Module entry, constants |
| `crates/nlink/src/netlink/genl/macsec/types.rs` | MacsecDevice, builders, FromNetlink impl |
| `crates/nlink/src/netlink/genl/macsec/connection.rs` | Connection<Macsec> implementation |
| `crates/nlink/src/netlink/types/macsec.rs` | Kernel structure constants |
| `crates/nlink/src/netlink/protocol.rs` | Add Macsec protocol state |
| `crates/nlink/src/netlink/genl/mod.rs` | Export macsec module |

## Implementation Steps

1. Add `Macsec` protocol state type (like `Wireguard`)
2. Define kernel constants in `types/macsec.rs`
3. Create `genl/macsec/` module structure
4. Implement `MacsecDevice` with `FromNetlink` parsing
5. Implement builders for configuration
6. Add `Connection<Macsec>` methods
7. Add example and tests

## Effort Estimate

- Implementation: ~8 hours
- Testing: ~2 hours
- Documentation: ~1 hour
- **Total: ~11 hours**
