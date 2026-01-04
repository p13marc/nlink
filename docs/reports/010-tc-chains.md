# Report: Plan 010 - TC Filter Chains

## Summary

Implemented TC filter chains support, allowing filters to be organized into numbered chains for better performance and management. This feature was introduced in Linux 4.1.

## Changes Made

### Message Types (message.rs)
- Added `RTM_NEWCHAIN` (100), `RTM_DELCHAIN` (101), `RTM_GETCHAIN` (102) message types

### Action Constants (types/tc.rs)
- Added `TC_ACT_JUMP` and `TC_ACT_GOTO_CHAIN` constants
- Added helper functions:
  - `tc_act_goto_chain(chain: u32) -> i32` - encode goto_chain action
  - `tc_act_chain(action: i32) -> u32` - decode chain from action
  - `is_goto_chain(action: i32) -> bool` - check if action is goto_chain

### Filter Builders (filter.rs)
Added `chain` field and `chain()` method to all filter types:
- `U32Filter`
- `FlowerFilter`
- `MatchallFilter`
- `FwFilter`
- `BpfFilter`
- `BasicFilter`
- `CgroupFilter`
- `RouteFilter`
- `FlowFilter`

Added `goto_chain()` method to filters that support actions:
- `FlowerFilter`
- `MatchallFilter`

Updated `FilterConfig` trait with `chain()` method.

### GactAction (action.rs)
- Added `GactAction::goto_chain(chain: u32)` constructor

### Connection Methods (connection.rs)
Added chain management methods:
- `get_tc_chains(dev, parent)` / `get_tc_chains_by_index(ifindex, parent)`
- `add_tc_chain(dev, parent, chain)` / `add_tc_chain_by_index(ifindex, parent, chain)`
- `del_tc_chain(dev, parent, chain)` / `del_tc_chain_by_index(ifindex, parent, chain)`

### Documentation (CLAUDE.md)
- Added "TC filter chains (Linux 4.1+)" section with usage examples

## API Usage

```rust
use nlink::netlink::{Connection, Route};
use nlink::netlink::filter::FlowerFilter;
use nlink::netlink::tc::IngressConfig;

let conn = Connection::<Route>::new()?;

// Add ingress qdisc
conn.add_qdisc("eth0", IngressConfig::new()).await?;

// Create chains
conn.add_tc_chain("eth0", "ingress", 0).await?;
conn.add_tc_chain("eth0", "ingress", 100).await?;

// Add filter in chain 0 that jumps to chain 100
let filter = FlowerFilter::new()
    .chain(0)
    .ip_proto_tcp()
    .goto_chain(100)
    .build();
conn.add_filter("eth0", "ingress", filter).await?;

// Add filter in chain 100
let filter = FlowerFilter::new()
    .chain(100)
    .dst_port(80)
    .build();
conn.add_filter("eth0", "ingress", filter).await?;

// List chains
let chains = conn.get_tc_chains("eth0", "ingress").await?;

// Delete chain
conn.del_tc_chain("eth0", "ingress", 100).await?;
```

## Testing

- All 261 tests pass
- Clippy clean with no warnings

## Files Changed

| File | Changes |
|------|---------|
| `crates/nlink/src/netlink/message.rs` | Added RTM_*CHAIN message types |
| `crates/nlink/src/netlink/types/tc.rs` | Added goto_chain constants and helpers |
| `crates/nlink/src/netlink/filter.rs` | Added chain support to all filter builders |
| `crates/nlink/src/netlink/action.rs` | Added GactAction::goto_chain() |
| `crates/nlink/src/netlink/connection.rs` | Added chain management methods |
| `CLAUDE.md` | Added TC chains documentation |
