# Plan 008: MACsec (IEEE 802.1AE) Implementation Report

## Summary

Implemented MACsec (IEEE 802.1AE) configuration via Generic Netlink, following the existing WireGuard pattern. This enables Layer 2 encryption for secure network links.

## Implementation Details

### Files Created

1. **`crates/nlink/src/netlink/types/macsec.rs`** (~230 lines)
   - Kernel constants for MACsec GENL interface:
     - `macsec_cmd::*` - GENL commands (GET_TXSC, ADD_RXSC, ADD_TXSA, etc.)
     - `macsec_attr::*` - Top-level attributes
     - `macsec_rxsc_attr::*` - RX SC attributes
     - `macsec_sa_attr::*` - SA attributes
     - `macsec_secy_attr::*` - SecY configuration attributes
     - `macsec_secy_stats_attr::*`, `macsec_txsc_stats_attr::*`, `macsec_rxsc_stats_attr::*` - Statistics
     - `macsec_offload_attr::*`, `macsec_offload::*` - Offload configuration
     - `macsec_validate::*` - Validation modes
     - `macsec_cipher::*` - Cipher suite IDs

2. **`crates/nlink/src/netlink/genl/macsec/mod.rs`** (~40 lines)
   - Module entry point with exports
   - Constants: `MACSEC_GENL_NAME`, `MACSEC_GENL_VERSION`

3. **`crates/nlink/src/netlink/genl/macsec/types.rs`** (~320 lines)
   - High-level types:
     - `MacsecCipherSuite` - GcmAes128, GcmAes256, GcmAesXpn128, GcmAesXpn256
     - `MacsecValidate` - Disabled, Check, Strict
     - `MacsecOffload` - Off, Phy, Mac
     - `MacsecDevice` - Parsed device info with TX SC and RX SCs
     - `MacsecTxSc`, `MacsecTxSa` - TX SC and SA info
     - `MacsecRxSc`, `MacsecRxSa` - RX SC and SA info
     - `MacsecSaBuilder` - Builder for SA configuration

4. **`crates/nlink/src/netlink/genl/macsec/connection.rs`** (~520 lines)
   - `Connection<Macsec>` implementation:
     - `new_async()` - Async constructor with GENL family resolution
     - `family_id()` - Access resolved family ID
     - `get_device()` - Query device info
     - `add_tx_sa()`, `del_tx_sa()`, `update_tx_sa()` - TX SA management
     - `add_rx_sc()`, `del_rx_sc()` - RX SC management
     - `add_rx_sa()`, `del_rx_sa()`, `update_rx_sa()` - RX SA management
   - Helper functions for parsing GENL responses

### Files Modified

1. **`crates/nlink/src/netlink/protocol.rs`**
   - Added `Macsec` protocol state type with `family_id: u16`
   - Implemented `private::Sealed` and `ProtocolState` traits
   - Updated tests

2. **`crates/nlink/src/netlink/mod.rs`**
   - Added `Macsec` to protocol re-exports

3. **`crates/nlink/src/netlink/types/mod.rs`**
   - Added `pub mod macsec;`

4. **`crates/nlink/src/netlink/genl/mod.rs`**
   - Added `pub mod macsec;`

5. **`CLAUDE.md`**
   - Added macsec module to architecture section
   - Added comprehensive MACsec usage examples

## API Surface

### MacsecCipherSuite

```rust
pub enum MacsecCipherSuite {
    GcmAes128,      // 128-bit AES-GCM
    GcmAes256,      // 256-bit AES-GCM
    GcmAesXpn128,   // 128-bit with extended packet numbering
    GcmAesXpn256,   // 256-bit with extended packet numbering
}
```

### MacsecValidate

```rust
pub enum MacsecValidate {
    Disabled,  // No validation
    Check,     // Validate but don't drop invalid
    Strict,    // Validate and drop invalid
}
```

### MacsecSaBuilder

```rust
MacsecSaBuilder::new(an)     // AN: 0-3
    .key(&key)               // 16 or 32 bytes for AES-128/256
    .pn(packet_number)       // Initial packet number
    .pn64(packet_number)     // 64-bit PN for XPN mode
    .active(bool)            // Enable/disable SA
```

### MacsecDevice

```rust
pub struct MacsecDevice {
    pub ifindex: u32,
    pub sci: u64,                          // Secure Channel Identifier
    pub cipher_suite: MacsecCipherSuite,
    pub icv_len: u8,                       // Integrity check value length
    pub encoding_sa: u8,                   // Current TX SA (AN)
    pub encrypt: bool,
    pub protect: bool,
    pub replay_protect: bool,
    pub replay_window: u32,
    pub validate: MacsecValidate,
    pub include_sci: bool,
    pub es: bool,                          // End station
    pub scb: bool,                         // Single copy broadcast
    pub tx_sc: MacsecTxSc,                 // TX secure channel
    pub rx_scs: Vec<MacsecRxSc>,           // RX secure channels
}
```

### Connection Methods

```rust
// Async connection constructor
Connection::<Macsec>::new_async().await?;

// Query device
conn.get_device("macsec0").await?;

// TX SA management
conn.add_tx_sa("macsec0", sa_builder).await?;
conn.del_tx_sa("macsec0", an).await?;
conn.update_tx_sa("macsec0", sa_builder).await?;

// RX SC management
conn.add_rx_sc("macsec0", sci).await?;
conn.del_rx_sc("macsec0", sci).await?;

// RX SA management
conn.add_rx_sa("macsec0", sci, sa_builder).await?;
conn.del_rx_sa("macsec0", sci, an).await?;
conn.update_rx_sa("macsec0", sci, sa_builder).await?;
```

## MACsec Concepts

### Secure Channel Identifier (SCI)

The SCI is a 64-bit identifier combining:
- MAC address (48 bits)
- Port identifier (16 bits)

```rust
let sci = 0x001122334455_0001u64;  // MAC 00:11:22:33:44:55, port 1
```

### Security Associations (SA)

Each SC can have up to 4 SAs (numbered 0-3) for key rollover:
- Only one SA is active at a time
- AN (Association Number) identifies which SA is in use
- Packet numbers prevent replay attacks

### XPN Mode

Extended Packet Numbering uses 64-bit packet numbers instead of 32-bit:
- Prevents wrap-around on high-speed links
- Requires `GcmAesXpn128` or `GcmAesXpn256` cipher suite

## Testing

- All 262 unit tests pass
- Clippy passes with no warnings
- Added unit tests for:
  - `MacsecCipherSuite` conversion
  - `MacsecValidate` conversion
  - `MacsecOffload` conversion
  - `MacsecSaBuilder` construction
  - Invalid AN panics (0-3 only)

## Linux Kernel Requirements

- Linux 4.6+ for MACsec support
- Linux 5.4+ for XPN mode
- Linux 5.12+ for MAC offload

### Prerequisites

```bash
# Create MACsec device
ip link add macsec0 link eth0 type macsec encrypt on

# Set device up
ip link set macsec0 up
```

## Example Usage

```rust
use nlink::netlink::{Connection, Macsec};
use nlink::netlink::genl::macsec::MacsecSaBuilder;

// Create MACsec connection
let conn = Connection::<Macsec>::new_async().await?;

// Query device
let device = conn.get_device("macsec0").await?;
println!("SCI: {:016x}", device.sci);
println!("Cipher: {:?}", device.cipher_suite);
println!("Encoding SA: {}", device.encoding_sa);

// Add TX SA with 128-bit key
let key = [0u8; 16];
conn.add_tx_sa("macsec0",
    MacsecSaBuilder::new(0)
        .key(&key)
        .pn(1)
        .active(true)
).await?;

// Add RX SC for peer
let peer_sci = 0x001122334455_0001u64;
conn.add_rx_sc("macsec0", peer_sci).await?;

// Add RX SA for peer
conn.add_rx_sa("macsec0", peer_sci,
    MacsecSaBuilder::new(0)
        .key(&key)
        .pn(1)
        .active(true)
).await?;

// Key rollover: add new SA, then switch
conn.add_tx_sa("macsec0",
    MacsecSaBuilder::new(1)
        .key(&new_key)
        .pn(1)
        .active(true)
).await?;
conn.update_tx_sa("macsec0",
    MacsecSaBuilder::new(0)
        .active(false)
).await?;
```

## Future Work

- Device creation/deletion via rtnetlink (IFLA_INFO_KIND "macsec")
- SecY configuration updates (cipher suite, validation mode)
- Statistics retrieval (TX/RX packet counts, SA stats)
- Hardware offload configuration
- MKA (MACsec Key Agreement) integration
