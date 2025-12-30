# rip - Rust IP utilities

A modern Rust implementation of Linux network management tools, providing both library crates and CLI binaries.

## Overview

rip is a from-scratch implementation of Linux netlink-based network management. The primary goal is to provide high-quality Rust libraries for programmatic network configuration, with CLI tools serving as proof-of-concept binaries.

**Key design principles:**

- **Library-first**: Core functionality lives in reusable crates
- **Async/tokio-native**: Built for async Rust from the ground up
- **Custom netlink**: No dependency on rtnetlink or netlink-packet-* crates
- **Type-safe**: Leverage Rust's type system for correctness
- **Modern CLI**: Not a drop-in replacement for iproute2 - free to improve

## Crates

### rip-netlink

Core async netlink implementation. Provides:

- `NetlinkSocket` - Low-level async socket wrapper
- `Connection` - High-level request/response handling with dump support
- `MessageBuilder` - Zero-copy message construction with nested attribute support
- `AttrIter` - Attribute parsing iterator
- Protocol types for link, address, route, neighbor, and traffic control

```rust
use rip_netlink::{Connection, Protocol, MessageBuilder};
use rip_netlink::types::link::{RtmType, IflaAttr};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let conn = Connection::new(Protocol::Route).await?;
    
    // Dump all links
    let mut builder = MessageBuilder::new(RtmType::GetLink as u16, NLM_F_REQUEST | NLM_F_DUMP);
    builder.append(&IfInfoMsg::default());
    
    let responses = conn.dump(builder.finish()).await?;
    // Parse responses...
    Ok(())
}
```

### rip-lib

Shared utilities for parsing and formatting:

- Argument parsing (`get_u8`, `get_u16`, `get_u32`, `get_rate`, `get_size`)
- Address utilities (parse/format IP addresses and prefixes)
- Name resolution (protocol names, scope names, table names)
- Interface name/index mapping

### rip-output

Output formatting for CLI tools:

- Text and JSON output modes
- `Printable` trait for consistent formatting
- Configurable options (stats, details, color, numeric)

## Binaries

### ip

Network interface and routing management:

```bash
# List interfaces
ip link show

# Show addresses
ip addr show

# Show routes
ip route show

# Show neighbors
ip neigh show
```

### tc

Traffic control (qdisc, class, filter):

```bash
# List qdiscs
tc qdisc show

# List classes
tc class show

# List filters
tc filter show
```

## Building

Requires Rust 1.85+ (edition 2024).

```bash
# Build all crates and binaries
cargo build --release

# Run ip command
cargo run --release -p ip -- link show

# Run tc command
cargo run --release -p tc -- qdisc show
```

## Project Status

This is an early-stage project. Currently implemented:

- [x] Core netlink socket and connection handling
- [x] Message building with nested attributes
- [x] Link operations (show)
- [x] Address operations (show)
- [x] Route operations (show)
- [x] Neighbor operations (show)
- [x] TC qdisc/class/filter operations (show, add, del)

Planned:

- [ ] Link add/del/set operations
- [ ] Address add/del operations
- [ ] Route add/del operations
- [ ] Link type plugins (vlan, bridge, bond, vxlan, etc.)
- [ ] Full TC qdisc implementations (htb, fq_codel, cake, etc.)
- [ ] Network namespace support
- [ ] Event monitoring

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.
