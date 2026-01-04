# Plan 018: Add `ip mptcp` Command

## Overview

Add MPTCP path manager configuration to the `ip` binary, exposing the MPTCP API from Plan 009.

## Current State

- Library: Full MPTCP support in `netlink/genl/mptcp/` 
- Binary: No mptcp command exists
- iproute2 equivalent: `ip mptcp`

## Target Commands

```bash
# List endpoints
ip mptcp endpoint
ip mptcp endpoint show

# Add endpoint
ip mptcp endpoint add 192.168.1.100 dev eth0 signal subflow
ip mptcp endpoint add 10.0.0.1 dev wlan0 backup signal
ip mptcp endpoint add 192.168.2.1 id 5 dev eth1 subflow

# Delete endpoint
ip mptcp endpoint del id 1
ip mptcp endpoint delete id 1

# Flush all endpoints
ip mptcp endpoint flush

# Show limits
ip mptcp limits
ip mptcp limits show

# Set limits
ip mptcp limits set subflows 4 add_addr_accepted 4

# Monitor events (future)
ip mptcp monitor
```

## Implementation

### Files to Create/Modify

1. **Create `bins/ip/src/mptcp.rs`**
   - `MptcpArgs` struct with clap derive
   - `MptcpCommand` enum (Endpoint, Limits, Monitor)
   - `EndpointCommand` enum (Show, Add, Del, Flush)
   - `LimitsCommand` enum (Show, Set)
   - `run_mptcp()` async function

2. **Modify `bins/ip/src/main.rs`**
   - Add `mptcp` to Command enum
   - Add match arm for mptcp command

### Command Structure

```rust
#[derive(Parser)]
pub struct MptcpArgs {
    #[command(subcommand)]
    pub command: MptcpCommand,
}

#[derive(Subcommand)]
pub enum MptcpCommand {
    /// Manage MPTCP endpoints
    Endpoint {
        #[command(subcommand)]
        command: Option<EndpointCommand>,
    },
    /// Manage MPTCP limits
    Limits {
        #[command(subcommand)]
        command: Option<LimitsCommand>,
    },
    /// Monitor MPTCP events
    Monitor,
}

#[derive(Subcommand)]
pub enum EndpointCommand {
    /// Show endpoints
    Show,
    /// Add an endpoint
    Add {
        /// IP address
        address: IpAddr,
        /// Endpoint ID
        #[arg(long)]
        id: Option<u8>,
        /// Network device
        #[arg(long)]
        dev: Option<String>,
        /// Port (optional)
        #[arg(long)]
        port: Option<u16>,
        /// Signal this address to peer
        #[arg(long)]
        signal: bool,
        /// Create subflows to this address
        #[arg(long)]
        subflow: bool,
        /// Use as backup path
        #[arg(long)]
        backup: bool,
        /// Enable fullmesh mode
        #[arg(long)]
        fullmesh: bool,
    },
    /// Delete an endpoint
    #[command(alias = "delete")]
    Del {
        /// Endpoint ID
        #[arg(long)]
        id: u8,
    },
    /// Flush all endpoints
    Flush,
}

#[derive(Subcommand)]
pub enum LimitsCommand {
    /// Show current limits
    Show,
    /// Set limits
    Set {
        /// Maximum subflows per connection
        #[arg(long)]
        subflows: Option<u32>,
        /// Maximum ADD_ADDR accepted
        #[arg(long)]
        add_addr_accepted: Option<u32>,
    },
}
```

### Output Format

```
# ip mptcp endpoint show
1: 192.168.1.100 dev eth0 flags signal,subflow
2: 10.0.0.1 dev wlan0 flags backup,signal
5: 192.168.2.1 dev eth1 flags subflow

# ip mptcp limits show
subflows 2 add_addr_accepted 2
```

JSON output:
```json
{
  "endpoints": [
    {"id": 1, "address": "192.168.1.100", "dev": "eth0", "flags": ["signal", "subflow"]},
    {"id": 2, "address": "10.0.0.1", "dev": "wlan0", "flags": ["backup", "signal"]}
  ]
}
```

## Testing

```bash
# Manual testing (requires MPTCP-enabled kernel)
sudo ./target/release/ip mptcp endpoint add 192.168.1.100 dev eth0 signal subflow
sudo ./target/release/ip mptcp endpoint show
sudo ./target/release/ip mptcp limits show
sudo ./target/release/ip mptcp limits set subflows 4
sudo ./target/release/ip mptcp endpoint del id 1
sudo ./target/release/ip mptcp endpoint flush
```

## Estimated Effort

- Implementation: 3-4 hours
- Testing: 1 hour
- Total: Half day

## Dependencies

- `nlink::netlink::Connection::<Mptcp>::new_async()`
- `nlink::netlink::genl::mptcp::{MptcpEndpointBuilder, MptcpLimits}`

## Notes

- MPTCP uses Generic Netlink, so we need `Connection::<Mptcp>::new_async().await?`
- The kernel must have MPTCP support enabled (most modern kernels do)
