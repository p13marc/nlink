# Plan 025: Add `ip macsec` Command

## Overview

Add MACsec device information display to the `ip` binary. Full MACsec management is in the `nlink-wg`-style `nlink-macsec` binary (future), but basic show functionality belongs in `ip`.

## Current State

- Library: Full MACsec support in `netlink/genl/macsec/`
- Binary: No macsec command exists
- iproute2 equivalent: `ip macsec`

## Target Commands

```bash
# Show all MACsec devices
ip macsec show
ip macsec

# Show specific device
ip macsec show macsec0

# Show with offload info
ip macsec show macsec0 offload
```

Note: For full MACsec management (adding/deleting SAs, RX SCs), we'll create a separate `nlink-macsec` binary similar to how WireGuard has `wg`.

## Implementation

### Files to Create/Modify

1. **Create `bins/ip/src/macsec.rs`**
   - `MacsecArgs` struct
   - `run_macsec()` async function

2. **Modify `bins/ip/src/main.rs`**
   - Add `macsec` to Command enum

### Command Structure

```rust
#[derive(Parser)]
pub struct MacsecArgs {
    #[command(subcommand)]
    pub command: Option<MacsecCommand>,
}

#[derive(Subcommand)]
pub enum MacsecCommand {
    /// Show MACsec devices
    Show {
        /// Device name
        device: Option<String>,
        
        /// Show offload information
        #[arg(long)]
        offload: bool,
    },
}

pub async fn run_macsec(args: MacsecArgs, json: bool) -> Result<()> {
    let macsec = Connection::<Macsec>::new_async().await?;
    let route = Connection::<Route>::new()?;
    
    // Find MACsec interfaces
    let links = route.get_links().await?;
    let macsec_links: Vec<_> = links.iter()
        .filter(|l| l.link_info().map(|i| i.kind()) == Some(Some("macsec")))
        .collect();
    
    match args.command {
        None | Some(MacsecCommand::Show { device: None, .. }) => {
            for link in macsec_links {
                let name = link.name_or("?");
                let device = macsec.get_device(name).await?;
                print_device(&device, json);
            }
        }
        Some(MacsecCommand::Show { device: Some(name), offload }) => {
            let device = macsec.get_device(&name).await?;
            print_device(&device, json);
        }
    }
    
    Ok(())
}
```

## Output Format

### Text Output

```
macsec0: protect on validate strict sc off sa off encrypt on send_sci on end_station off scb off replay off
    cipher suite: GCM-AES-128, using ICV length 16
    TXSC: 001122334455:0001 on SA 0
        0: PN 12345, state on
    RXSC: aabbccddeeff:0001
        0: PN 54321, state on
```

### JSON Output

```json
{
  "name": "macsec0",
  "sci": "001122334455:0001",
  "protect": true,
  "validate": "strict",
  "encrypt": true,
  "cipher_suite": "GCM-AES-128",
  "icv_len": 16,
  "encoding_sa": 0,
  "tx_sc": {
    "sci": "001122334455:0001",
    "sas": [
      {"an": 0, "pn": 12345, "active": true}
    ]
  },
  "rx_scs": [
    {
      "sci": "aabbccddeeff:0001",
      "sas": [
        {"an": 0, "pn": 54321, "active": true}
      ]
    }
  ]
}
```

## Testing

```bash
# Create MACsec interface
sudo ip link add macsec0 link eth0 type macsec sci 1 encrypt on

# Show MACsec devices
./target/release/ip macsec show
./target/release/ip macsec show macsec0 --json

# Cleanup
sudo ip link del macsec0
```

## Estimated Effort

- Implementation: 2-3 hours
- Testing: 1 hour
- Total: Half day

## Dependencies

- `nlink::netlink::Connection::<Macsec>::new_async()`
- `nlink::netlink::genl::macsec::MacsecDevice`

## Future: Full `nlink-macsec` Binary

For complete MACsec management, create a dedicated binary:

```bash
# TX SA management
macsec txsa add macsec0 0 pn 1 on key 01234567...
macsec txsa set macsec0 0 off
macsec txsa del macsec0 0

# RX SC management
macsec rxsc add macsec0 aabbccddeeff:0001
macsec rxsc del macsec0 aabbccddeeff:0001

# RX SA management  
macsec rxsa add macsec0 aabbccddeeff:0001 0 pn 1 on key 01234567...
macsec rxsa set macsec0 aabbccddeeff:0001 0 off
macsec rxsa del macsec0 aabbccddeeff:0001 0
```

This would be Plan 026 if we decide to implement it.
