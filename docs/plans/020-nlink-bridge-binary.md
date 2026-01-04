# Plan 020: Create `nlink-bridge` Binary

## Overview

Create a new binary for bridge management, exposing FDB (Plan 002) and VLAN (Plan 003) functionality.

## Current State

- Library: Full FDB support in `netlink/fdb.rs` (670 lines)
- Library: Full VLAN support in `netlink/bridge_vlan.rs` (674 lines)
- Binary: None exists
- iproute2 equivalent: `bridge`

## Target Commands

### FDB Commands

```bash
# Show FDB entries
bridge fdb show
bridge fdb show br0
bridge fdb show dev veth0

# Add FDB entry
bridge fdb add aa:bb:cc:dd:ee:ff dev veth0 master br0
bridge fdb add aa:bb:cc:dd:ee:ff dev veth0 master br0 permanent
bridge fdb add aa:bb:cc:dd:ee:ff dev veth0 master br0 vlan 100
bridge fdb add 00:00:00:00:00:00 dev vxlan0 dst 192.168.1.100  # VXLAN VTEP

# Replace FDB entry
bridge fdb replace aa:bb:cc:dd:ee:ff dev veth0 master br0

# Delete FDB entry
bridge fdb del aa:bb:cc:dd:ee:ff dev veth0
bridge fdb del aa:bb:cc:dd:ee:ff dev veth0 vlan 100

# Flush dynamic entries
bridge fdb flush dev br0
```

### VLAN Commands

```bash
# Show VLANs
bridge vlan show
bridge vlan show dev eth0

# Add VLAN
bridge vlan add vid 100 dev eth0
bridge vlan add vid 100 dev eth0 pvid untagged
bridge vlan add vid 200 dev eth0  # tagged
bridge vlan add vid 300-310 dev eth0  # range

# Delete VLAN
bridge vlan del vid 100 dev eth0
bridge vlan del vid 300-310 dev eth0

# Set PVID (convenience)
bridge vlan set pvid 100 dev eth0
```

### Link Commands (Bridge Port Settings)

```bash
# Show bridge ports
bridge link show
bridge link show dev veth0

# Set port options
bridge link set dev veth0 learning on
bridge link set dev veth0 flood off
bridge link set dev veth0 state forwarding
bridge link set dev veth0 cost 100
bridge link set dev veth0 priority 32
```

### Monitor

```bash
# Monitor bridge events
bridge monitor
bridge monitor fdb
bridge monitor vlan
bridge monitor link
```

## Project Structure

```
bins/bridge/
├── Cargo.toml
└── src/
    ├── main.rs
    ├── fdb.rs
    ├── vlan.rs
    ├── link.rs
    ├── monitor.rs
    └── output.rs
```

### Cargo.toml

```toml
[package]
name = "nlink-bridge"
version.workspace = true
edition.workspace = true

[[bin]]
name = "bridge"
path = "src/main.rs"

[dependencies]
nlink = { path = "../../crates/nlink", features = ["output"] }
clap = { workspace = true }
tokio = { workspace = true }
serde_json = { workspace = true }
```

## Implementation Details

### main.rs

```rust
use clap::{Parser, Subcommand};

mod fdb;
mod vlan;
mod link;
mod monitor;
mod output;

#[derive(Parser)]
#[command(name = "bridge", about = "Bridge management utility")]
struct Cli {
    /// Output JSON
    #[arg(short, long, global = true)]
    json: bool,
    
    /// Pretty print JSON
    #[arg(short, long, global = true)]
    pretty: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Manage forwarding database
    Fdb(fdb::FdbArgs),
    /// Manage VLAN filter
    Vlan(vlan::VlanArgs),
    /// Manage bridge ports
    Link(link::LinkArgs),
    /// Monitor bridge events
    Monitor(monitor::MonitorArgs),
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    
    match cli.command {
        Command::Fdb(args) => fdb::run(args, cli.json, cli.pretty).await,
        Command::Vlan(args) => vlan::run(args, cli.json, cli.pretty).await,
        Command::Link(args) => link::run(args, cli.json, cli.pretty).await,
        Command::Monitor(args) => monitor::run(args).await,
    }
}
```

### fdb.rs

```rust
use clap::{Args, Subcommand};
use nlink::netlink::{Connection, Route};
use nlink::netlink::fdb::FdbEntryBuilder;

#[derive(Args)]
pub struct FdbArgs {
    #[command(subcommand)]
    command: Option<FdbCommand>,
}

#[derive(Subcommand)]
pub enum FdbCommand {
    /// Show FDB entries
    Show {
        /// Bridge or port device
        dev: Option<String>,
    },
    /// Add FDB entry
    Add {
        /// MAC address
        mac: String,
        /// Port device
        #[arg(long)]
        dev: String,
        /// Bridge device
        #[arg(long)]
        master: Option<String>,
        /// VLAN ID
        #[arg(long)]
        vlan: Option<u16>,
        /// Remote VTEP (for VXLAN)
        #[arg(long)]
        dst: Option<IpAddr>,
        /// Permanent entry
        #[arg(long)]
        permanent: bool,
        /// Static entry
        #[arg(long, name = "static")]
        static_entry: bool,
    },
    /// Replace FDB entry
    Replace { /* same as Add */ },
    /// Delete FDB entry
    Del {
        /// MAC address
        mac: String,
        /// Port device
        #[arg(long)]
        dev: String,
        /// VLAN ID
        #[arg(long)]
        vlan: Option<u16>,
    },
    /// Flush dynamic entries
    Flush {
        /// Bridge device
        dev: String,
    },
}
```

### vlan.rs

```rust
use clap::{Args, Subcommand};
use nlink::netlink::{Connection, Route};
use nlink::netlink::bridge_vlan::BridgeVlanBuilder;

#[derive(Args)]
pub struct VlanArgs {
    #[command(subcommand)]
    command: Option<VlanCommand>,
}

#[derive(Subcommand)]
pub enum VlanCommand {
    /// Show VLAN configuration
    Show {
        /// Port device
        #[arg(long)]
        dev: Option<String>,
    },
    /// Add VLAN to port
    Add {
        /// VLAN ID or range (e.g., 100 or 100-110)
        #[arg(long)]
        vid: String,
        /// Port device
        #[arg(long)]
        dev: String,
        /// Set as PVID (native VLAN)
        #[arg(long)]
        pvid: bool,
        /// Egress untagged
        #[arg(long)]
        untagged: bool,
    },
    /// Delete VLAN from port
    Del {
        /// VLAN ID or range
        #[arg(long)]
        vid: String,
        /// Port device
        #[arg(long)]
        dev: String,
    },
    /// Set PVID (convenience command)
    Set {
        /// Set PVID
        #[arg(long)]
        pvid: u16,
        /// Port device
        #[arg(long)]
        dev: String,
    },
}
```

## Output Formats

### FDB Text Output

```
aa:bb:cc:dd:ee:ff dev veth0 master br0 permanent
11:22:33:44:55:66 dev veth0 master br0 vlan 100
00:00:00:00:00:00 dev vxlan0 dst 192.168.1.100 self permanent
```

### FDB JSON Output

```json
[
  {
    "mac": "aa:bb:cc:dd:ee:ff",
    "dev": "veth0",
    "master": "br0",
    "state": "permanent",
    "flags": ["self"]
  }
]
```

### VLAN Text Output

```
port    vlan-id
veth0   1 PVID Egress Untagged
        100
        200
veth1   1 PVID Egress Untagged
        100
```

### VLAN JSON Output

```json
[
  {
    "dev": "veth0",
    "vlans": [
      {"vid": 1, "pvid": true, "untagged": true},
      {"vid": 100, "pvid": false, "untagged": false},
      {"vid": 200, "pvid": false, "untagged": false}
    ]
  }
]
```

## Testing

```bash
# Setup test environment
sudo ip link add br0 type bridge vlan_filtering 1
sudo ip link add veth0 type veth peer name veth1
sudo ip link set veth0 master br0
sudo ip link set br0 up
sudo ip link set veth0 up

# Test FDB commands
sudo ./target/release/bridge fdb show br0
sudo ./target/release/bridge fdb add aa:bb:cc:dd:ee:ff dev veth0 master br0 permanent
sudo ./target/release/bridge fdb show
sudo ./target/release/bridge fdb del aa:bb:cc:dd:ee:ff dev veth0

# Test VLAN commands
sudo ./target/release/bridge vlan show
sudo ./target/release/bridge vlan add vid 100 dev veth0 pvid untagged
sudo ./target/release/bridge vlan add vid 200 dev veth0
sudo ./target/release/bridge vlan show dev veth0
sudo ./target/release/bridge vlan del vid 200 dev veth0

# Cleanup
sudo ip link del br0
```

## Estimated Effort

- Project setup: 1 hour
- FDB commands: 3-4 hours
- VLAN commands: 2-3 hours
- Link commands: 2-3 hours
- Monitor: 1-2 hours
- Testing: 2 hours
- Total: 2-3 days

## Dependencies

- `nlink::netlink::fdb::{FdbEntry, FdbEntryBuilder}`
- `nlink::netlink::bridge_vlan::{BridgeVlanBuilder, BridgeVlanEntry}`
- `nlink::netlink::Connection::<Route>::{get_fdb, add_fdb, del_fdb, flush_fdb, ...}`
- `nlink::netlink::Connection::<Route>::{get_bridge_vlans, add_bridge_vlan, del_bridge_vlan, ...}`

## Future Enhancements

- MDB (multicast database) support - requires library implementation
- Bridge port STP state management
- Bridge global options (ageing_time, forward_delay, etc.)
