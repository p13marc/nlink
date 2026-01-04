# Plan 017: Add `ip nexthop` Command

## Overview

Add nexthop object management to the `ip` binary, exposing the nexthop API from Plan 005.

## Current State

- Library: Full nexthop support in `netlink/nexthop.rs` (878 lines)
- Binary: No nexthop command exists
- iproute2 equivalent: `ip nexthop`

## Target Commands

```bash
# List all nexthops
ip nexthop
ip nexthop show
ip nh show

# Show specific nexthop
ip nexthop show id 1

# Show only groups
ip nexthop show group

# Add a nexthop
ip nexthop add id 1 via 192.168.1.1 dev eth0
ip nexthop add id 2 via 192.168.2.1 dev eth1
ip nexthop add id 3 blackhole

# Add a nexthop group (ECMP)
ip nexthop add id 100 group 1/2
ip nexthop add id 101 group 1,2/2,1  # weighted

# Add resilient group
ip nexthop add id 102 group 1/2 type resilient buckets 128 idle_timer 120

# Replace nexthop
ip nexthop replace id 1 via 192.168.1.254 dev eth0

# Delete nexthop
ip nexthop del id 1
ip nexthop del id 100

# Flush all nexthops
ip nexthop flush
```

## Implementation

### Files to Create/Modify

1. **Create `bins/ip/src/nexthop.rs`**
   - `NexthopArgs` struct with clap derive
   - `NexthopCommand` enum (Show, Add, Replace, Del, Flush)
   - `run_nexthop()` async function

2. **Modify `bins/ip/src/main.rs`**
   - Add `nexthop` (alias `nh`) to Command enum
   - Add match arm for nexthop command

### Command Structure

```rust
#[derive(Parser)]
pub struct NexthopArgs {
    #[command(subcommand)]
    pub command: Option<NexthopCommand>,
}

#[derive(Subcommand)]
pub enum NexthopCommand {
    /// Show nexthops
    Show {
        /// Show specific nexthop ID
        #[arg(long)]
        id: Option<u32>,
        /// Show only groups
        #[arg(long)]
        group: bool,
    },
    /// Add a nexthop
    Add {
        /// Nexthop ID
        #[arg(long)]
        id: u32,
        /// Gateway address
        #[arg(long)]
        via: Option<IpAddr>,
        /// Output device
        #[arg(long)]
        dev: Option<String>,
        /// Create blackhole
        #[arg(long)]
        blackhole: bool,
        /// Group members (id,weight/id,weight/...)
        #[arg(long)]
        group: Option<String>,
        /// Group type (resilient)
        #[arg(long, name = "type")]
        group_type: Option<String>,
        /// Resilient buckets
        #[arg(long)]
        buckets: Option<u16>,
        /// Resilient idle timer
        #[arg(long)]
        idle_timer: Option<u32>,
    },
    /// Replace a nexthop
    Replace { /* same as Add */ },
    /// Delete a nexthop
    Del {
        /// Nexthop ID
        #[arg(long)]
        id: u32,
    },
    /// Flush all nexthops
    Flush,
}
```

### Output Format

```
id 1 via 192.168.1.1 dev eth0 scope link
id 2 via 192.168.2.1 dev eth1 scope link
id 100 group 1/2 type mpath
id 101 group 1,2/2,1 type mpath
id 102 group 1/2 type resilient buckets 128 idle_timer 120
```

JSON output:
```json
[
  {"id": 1, "gateway": "192.168.1.1", "dev": "eth0", "scope": "link"},
  {"id": 100, "group": [{"id": 1, "weight": 1}, {"id": 2, "weight": 1}], "type": "mpath"}
]
```

## Testing

```bash
# Manual testing
sudo ./target/release/ip nexthop add id 1 via 192.168.1.1 dev eth0
sudo ./target/release/ip nexthop show
sudo ./target/release/ip nexthop show id 1
sudo ./target/release/ip nexthop add id 100 group 1/2
sudo ./target/release/ip nexthop del id 100
sudo ./target/release/ip nexthop del id 1
```

## Estimated Effort

- Implementation: 3-4 hours
- Testing: 1 hour
- Total: Half day

## Dependencies

- `nlink::netlink::nexthop::{NexthopBuilder, NexthopGroupBuilder}`
- `nlink::netlink::Connection::<Route>::{get_nexthops, add_nexthop, del_nexthop, ...}`
