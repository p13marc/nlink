# nlink - Rust IP utilities

A modern Rust implementation of Linux network management tools, providing both a library crate and CLI binaries.

## Overview

nlink is a from-scratch implementation of Linux netlink-based network management. The primary goal is to provide a high-quality Rust library for programmatic network configuration, with CLI tools serving as proof-of-concept binaries.

**Key design principles:**

- **Library-first**: Core functionality lives in a single, well-designed crate
- **Async/tokio-native**: Built for async Rust from the ground up
- **Custom netlink**: No dependency on rtnetlink or netlink-packet-* crates
- **Type-safe**: Leverage Rust's type system for correctness

## Installation

```toml
# Core netlink functionality
nlink = "0.1"

# With additional features
nlink = { version = "0.1", features = ["sockdiag", "tuntap", "tc", "output"] }

# All features
nlink = { version = "0.1", features = ["full"] }
```

### Features

| Feature | Description |
|---------|-------------|
| `sockdiag` | Socket diagnostics via NETLINK_SOCK_DIAG |
| `tuntap` | TUN/TAP device management |
| `tc` | Traffic control utilities |
| `output` | JSON/text output formatting |
| `namespace_watcher` | Namespace watching via inotify |
| `full` | All features enabled |

## Quick Start

```rust
use nlink::netlink::{Connection, Route, RtnetlinkGroup, NetworkEvent};
use tokio_stream::StreamExt;

#[tokio::main]
async fn main() -> nlink::Result<()> {
    let mut conn = Connection::<Route>::new()?;
    
    // Query interfaces
    let links = conn.get_links().await?;
    for link in &links {
        println!("{}: {} (up={})", 
            link.ifindex(), 
            link.name_or("?"),  // Convenience helper
            link.is_up());
    }
    
    // Build ifindex -> name map for resolving routes/addresses
    let names = conn.get_interface_names().await?;
    
    // Modify interface state
    conn.set_link_up("eth0").await?;
    conn.set_link_mtu("eth0", 9000).await?;
    
    // Monitor events
    conn.subscribe(&[RtnetlinkGroup::Link, RtnetlinkGroup::Ipv4Addr])?;
    let mut events = conn.events();
    
    while let Some(result) = events.next().await {
        match result? {
            NetworkEvent::NewLink(link) => println!("Link: {}", link.name_or("?")),
            _ => {}
        }
    }
    
    Ok(())
}
```

## Documentation

- **[Library Usage](docs/library.md)** - Detailed library examples: namespaces, TC, WireGuard, error handling
- **[CLI Tools](docs/cli.md)** - ip and tc command reference

## Library Modules

| Module | Description |
|--------|-------------|
| `nlink::netlink` | Core netlink: `Connection<Route>`, EventStream, namespace, TC |
| `nlink::netlink::genl` | Generic Netlink: `Connection<Generic>`, `Connection<Wireguard>` |
| `nlink::netlink::uevent` | Device hotplug events: `Connection<KobjectUevent>` |
| `nlink::netlink::connector` | Process lifecycle events: `Connection<Connector>` |
| `nlink::netlink::netfilter` | Connection tracking: `Connection<Netfilter>` |
| `nlink::netlink::xfrm` | IPsec SA/SP management: `Connection<Xfrm>` |
| `nlink::netlink::fib_lookup` | FIB route lookups: `Connection<FibLookup>` |
| `nlink::netlink::audit` | Linux Audit subsystem: `Connection<Audit>` |
| `nlink::netlink::selinux` | SELinux events: `Connection<SELinux>` |
| `nlink::sockdiag` | Socket diagnostics: `Connection<SockDiag>` (feature: `sockdiag`) |
| `nlink::util` | Parsing utilities, address helpers, name resolution |
| `nlink::tuntap` | TUN/TAP devices (feature: `tuntap`) |

## Project Status

The library API is production-ready for network monitoring and querying.

**Implemented:**

- Core netlink socket and connection handling
- Link operations (show, add, del, set) with 20+ link types
- Address, route, neighbor, and rule operations
- Event monitoring (link, address, route, neighbor, TC)
- TC qdisc operations with 19 qdisc types
- TC class, filter (9 types), and action (12 types) support
- Network namespace support
- Tunnel management (GRE, IPIP, SIT, VTI)
- WireGuard configuration via Generic Netlink
- VRF and XFRM/IPSec support

## Building

Requires Rust 1.85+ (edition 2024).

```bash
cargo build --release
cargo run --release -p ip -- link show
cargo run --release -p tc -- qdisc show
```

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.
