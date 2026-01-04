# nlink - Rust IP utilities

[![Crates.io](https://img.shields.io/crates/v/nlink.svg)](https://crates.io/crates/nlink)
[![Documentation](https://docs.rs/nlink/badge.svg)](https://docs.rs/nlink)
[![License](https://img.shields.io/crates/l/nlink.svg)](https://github.com/p13marc/nlink#license)

A modern Rust implementation of Linux network management tools, providing both a library crate and CLI binaries.

## Overview

nlink is a from-scratch implementation of Linux netlink-based network management. The primary goal is to provide a high-quality Rust library for programmatic network configuration, with CLI tools serving as proof-of-concept binaries.

**Key design principles:**

- **Library-first**: Core functionality lives in a single, well-designed crate
- **Async/tokio-native**: Built for async Rust from the ground up
- **Custom netlink**: No dependency on rtnetlink or netlink-packet-* crates
- **Type-safe**: Leverage Rust's type system for correctness
- **High-level APIs**: Declarative configuration, rate limiting DSL, diagnostics

## Installation

```toml
# Core netlink functionality
nlink = "0.6"

# With additional features
nlink = { version = "0.6", features = ["sockdiag", "tuntap", "tc", "output"] }

# All features
nlink = { version = "0.6", features = ["full"] }
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
            link.name_or("?"),
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

## High-Level APIs

### Declarative Network Configuration

Define desired network state and let nlink compute and apply changes:

```rust
use nlink::netlink::config::{NetworkConfig, LinkConfig, LinkType, AddressConfig};

let config = NetworkConfig::new()
    .link(LinkConfig::new("br0").link_type(LinkType::Bridge).up())
    .link(LinkConfig::new("dummy0").link_type(LinkType::Dummy).mtu(9000).up())
    .address(AddressConfig::new("br0", "192.168.100.1/24"));

// Compute diff and apply (idempotent)
config.apply(&conn).await?;
```

### Rate Limiting DSL

Simple bandwidth management without TC complexity:

```rust
use nlink::netlink::ratelimit::{RateLimiter, PerHostLimiter};

// Interface-wide rate limiting
let limiter = RateLimiter::new("eth0")
    .egress("100mbit")
    .ingress("50mbit");
limiter.apply(&conn).await?;

// Per-IP rate limiting
let limiter = PerHostLimiter::new("eth0", "10mbit")?
    .limit_ip("192.168.1.100".parse()?, "100mbit")?;
limiter.apply(&conn).await?;
```

### Network Diagnostics

Scan for issues, check connectivity, find bottlenecks:

```rust
use nlink::netlink::diagnostics::Diagnostics;

let diag = Diagnostics::new(conn);

// Full diagnostic scan
let report = diag.scan().await?;
for issue in &report.issues {
    println!("[{:?}] {}", issue.severity, issue.message);
}

// Check connectivity to destination
let report = diag.check_connectivity("8.8.8.8".parse()?).await?;

// Find bottlenecks
if let Some(bottleneck) = diag.find_bottleneck().await? {
    println!("{}: {}", bottleneck.location, bottleneck.recommendation);
}
```

## Documentation

- **[Library Usage](docs/library.md)** - Detailed library examples: namespaces, TC, WireGuard, error handling
- **[CLI Tools](docs/cli.md)** - ip and tc command reference
- **[Examples](crates/nlink/examples/README.md)** - 40+ runnable examples

## Library Modules

| Module | Description |
|--------|-------------|
| `nlink::netlink` | Core netlink: `Connection<Route>`, EventStream, namespace, TC |
| `nlink::netlink::config` | Declarative network configuration |
| `nlink::netlink::ratelimit` | High-level rate limiting API |
| `nlink::netlink::diagnostics` | Network diagnostics and issue detection |
| `nlink::netlink::genl` | Generic Netlink: WireGuard, MACsec, MPTCP |
| `nlink::netlink::nexthop` | Nexthop objects and ECMP groups (Linux 5.3+) |
| `nlink::netlink::mpls` | MPLS routes and encapsulation |
| `nlink::netlink::srv6` | SRv6 segment routing |
| `nlink::netlink::fdb` | Bridge FDB management |
| `nlink::netlink::bridge_vlan` | Bridge VLAN filtering |
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

The library API is production-ready for network monitoring and configuration.

**Implemented:**

- Core netlink socket and connection handling
- Link operations (show, add, del, set) with 20+ link types
- Address, route, neighbor, and rule operations
- Event monitoring (link, address, route, neighbor, TC)
- TC qdisc operations with 19 qdisc types
- TC class management with typed builders (HTB, HFSC, DRR, QFQ)
- TC filter (9 types) and action (12 types) support
- TC filter chains for complex classification
- Network namespace support
- Tunnel management (GRE, IPIP, SIT, VTI, VXLAN, Geneve)
- WireGuard, MACsec, MPTCP configuration via Generic Netlink
- Nexthop objects and ECMP groups (Linux 5.3+)
- MPLS routes and encapsulation
- SRv6 segment routing and local SIDs
- Bridge FDB and VLAN filtering
- Declarative network configuration
- Rate limiting DSL
- Network diagnostics
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
