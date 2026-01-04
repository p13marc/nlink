# Plan 010: TC Filter Chains

## Overview

Add support for TC filter chains, allowing organization of filters into numbered chains for better performance and management.

## Motivation

Filter chains (introduced in Linux 4.1) provide:
- Logical grouping of filters
- Better performance via chain-based lookup
- Required for some hardware offload scenarios
- Used by nftables-style TC configuration

## Design

### API Design

```rust
impl Connection<Route> {
    /// Get all chains for a qdisc.
    pub async fn get_tc_chains(&self, dev: &str, parent: &str) -> Result<Vec<u32>>;
    
    /// Add a filter chain.
    pub async fn add_tc_chain(&self, dev: &str, parent: &str, chain: u32) -> Result<()>;
    
    /// Delete a filter chain.
    pub async fn del_tc_chain(&self, dev: &str, parent: &str, chain: u32) -> Result<()>;
}

// Extend filter builders
impl FlowerFilter {
    /// Set chain for this filter.
    pub fn chain(self, chain: u32) -> Self;
    
    /// Jump to another chain on match.
    pub fn goto_chain(self, chain: u32) -> Self;
}
```

### Usage Example

```rust
use nlink::netlink::{Connection, Route};
use nlink::netlink::filter::FlowerFilter;

let conn = Connection::<Route>::new()?;

// Add ingress qdisc
conn.add_qdisc("eth0", IngressConfig::new()).await?;

// Create chains
conn.add_tc_chain("eth0", "ingress", 0).await?;
conn.add_tc_chain("eth0", "ingress", 100).await?;

// Add filter in chain 0 that jumps to chain 100
conn.add_filter("eth0", "ingress",
    FlowerFilter::new()
        .chain(0)
        .ip_proto_tcp()
        .goto_chain(100)
        .build()
).await?;

// Add filter in chain 100
conn.add_filter("eth0", "ingress",
    FlowerFilter::new()
        .chain(100)
        .dst_port(80)
        .action(GactAction::drop())
        .build()
).await?;
```

### Implementation Details

Chain operations use `RTM_NEWCHAIN`, `RTM_DELCHAIN`, `RTM_GETCHAIN` message types with `TCA_CHAIN` attribute.

### File Changes

| File | Change |
|------|--------|
| `crates/nlink/src/netlink/connection.rs` | Add chain methods |
| `crates/nlink/src/netlink/filter.rs` | Add chain/goto_chain to builders |
| `crates/nlink/src/netlink/message.rs` | Add RTM_*CHAIN types |

## Effort Estimate

- Implementation: ~3 hours
- Testing: ~1 hour
- Documentation: ~30 minutes
- **Total: ~4-5 hours**
