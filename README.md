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

# Create interfaces (each type is a subcommand with specific options)
ip link add dummy test0
ip link add veth veth0 --peer veth1
ip link add bridge br0 --stp --vlan-filtering
ip link add bond bond0 --mode 802.3ad --miimon 100
ip link add vlan eth0.100 --link eth0 --id 100
ip link add vxlan vxlan0 --vni 100 --remote 10.0.0.1 --dstport 4789

# Delete interfaces
ip link del test0

# Modify interfaces
ip link set eth0 --up --mtu 9000

# Show addresses
ip addr show

# Add/remove addresses
ip addr add 192.168.1.1/24 -d eth0
ip addr del 192.168.1.1/24 -d eth0

# Show routes
ip route show

# Add/remove routes
ip route add 10.0.0.0/8 --via 192.168.1.1
ip route del 10.0.0.0/8

# Show neighbors
ip neigh show

# Add/remove neighbors
ip neigh add 192.168.1.2 --lladdr 00:11:22:33:44:55 -d eth0
ip neigh del 192.168.1.2 -d eth0
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
- [x] Link operations (show, add, del, set)
- [x] Link types: dummy, veth, bridge, bond, vlan, vxlan, macvlan, ipvlan, vrf, gre, ipip, sit, wireguard
- [x] Address operations (show, add, del)
- [x] Route operations (show, add, del, replace)
- [x] Neighbor operations (show, add, del, replace)
- [x] TC qdisc/class/filter operations (show, add, del)

Planned:

- [ ] Full TC qdisc implementations (htb, fq_codel, cake, etc.)
- [ ] Network namespace support
- [ ] Event monitoring (ip monitor)
- [ ] Policy routing rules (ip rule)

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.
