# Plan 019: Add `tc chain` Command

## Overview

Add filter chain management to the `tc` binary, exposing the chain API from Plan 010.

## Current State

- Library: Full chain support in `netlink/tc.rs` (add_tc_chain, del_tc_chain, get_tc_chains)
- Binary: No chain command exists
- iproute2 equivalent: `tc chain`

## Target Commands

```bash
# List chains
tc chain show dev eth0
tc chain show dev eth0 ingress
tc chain show dev eth0 parent 1:

# Add chain
tc chain add dev eth0 ingress chain 0
tc chain add dev eth0 ingress chain 100
tc chain add dev eth0 parent 1: chain 10

# Delete chain
tc chain del dev eth0 ingress chain 100
tc chain del dev eth0 parent 1: chain 10
```

## Implementation

### Files to Create/Modify

1. **Create `bins/tc/src/chain.rs`**
   - `ChainArgs` struct with clap derive
   - `ChainCommand` enum (Show, Add, Del)
   - `run_chain()` async function

2. **Modify `bins/tc/src/main.rs`**
   - Add `chain` to Command enum
   - Add match arm for chain command

### Command Structure

```rust
#[derive(Parser)]
pub struct ChainArgs {
    #[command(subcommand)]
    pub command: Option<ChainCommand>,
}

#[derive(Subcommand)]
pub enum ChainCommand {
    /// Show filter chains
    #[command(alias = "list", alias = "ls")]
    Show {
        /// Network device
        #[arg(long, short)]
        dev: String,
        /// Parent qdisc (root, ingress, or handle like 1:)
        #[arg(long, default_value = "root")]
        parent: String,
    },
    /// Add a filter chain
    Add {
        /// Network device
        #[arg(long, short)]
        dev: String,
        /// Parent qdisc
        #[arg(long, default_value = "root")]
        parent: String,
        /// Chain index
        #[arg(long)]
        chain: u32,
    },
    /// Delete a filter chain
    Del {
        /// Network device
        #[arg(long, short)]
        dev: String,
        /// Parent qdisc
        #[arg(long, default_value = "root")]
        parent: String,
        /// Chain index
        #[arg(long)]
        chain: u32,
    },
}
```

### Alternative Positional Syntax

To match iproute2 more closely:

```rust
#[derive(Parser)]
pub struct ChainArgs {
    #[command(subcommand)]
    pub command: Option<ChainCommand>,
}

#[derive(Subcommand)]
pub enum ChainCommand {
    /// Show filter chains
    Show(ChainShowArgs),
    /// Add a filter chain
    Add(ChainAddArgs),
    /// Delete a filter chain
    Del(ChainDelArgs),
}

#[derive(Args)]
pub struct ChainShowArgs {
    /// Device name
    dev: String,
    /// Parent (ingress, root, or handle)
    #[arg(default_value = "root")]
    parent: String,
}

#[derive(Args)]
pub struct ChainAddArgs {
    /// Device name
    dev: String,
    /// Parent (ingress, root, or handle)
    parent: String,
    /// Chain index
    chain: u32,
}
```

### Output Format

```
# tc chain show dev eth0 ingress
chain 0
chain 100

# tc chain show dev eth0 parent 1:
chain 0
chain 10
chain 20
```

JSON output:
```json
{
  "dev": "eth0",
  "parent": "ingress",
  "chains": [0, 100]
}
```

## Filter Integration

Also update filter commands to support chain parameter:

```bash
# Add filter to specific chain
tc filter add dev eth0 ingress chain 100 flower dst_port 80 action drop

# Show filters in chain
tc filter show dev eth0 ingress chain 100
```

Update `bins/tc/src/filter.rs`:
- Add `--chain` option to FilterShowArgs, FilterAddArgs, etc.

## Testing

```bash
# Manual testing
sudo ./target/release/tc qdisc add dev eth0 ingress
sudo ./target/release/tc chain add dev eth0 ingress chain 0
sudo ./target/release/tc chain add dev eth0 ingress chain 100
sudo ./target/release/tc chain show dev eth0 ingress
sudo ./target/release/tc chain del dev eth0 ingress chain 100
sudo ./target/release/tc qdisc del dev eth0 ingress
```

## Estimated Effort

- Implementation: 2-3 hours
- Testing: 1 hour
- Total: Half day

## Dependencies

- `nlink::netlink::Connection::<Route>::{add_tc_chain, del_tc_chain, get_tc_chains}`

## Notes

- Chains are typically used with ingress/clsact qdiscs for complex filtering pipelines
- Chain 0 is the default chain
- Filters can use `goto_chain` action to jump between chains
