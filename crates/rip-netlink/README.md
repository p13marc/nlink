# rip-netlink

Async netlink protocol implementation for Linux network management.

## Overview

`rip-netlink` provides a complete, strongly-typed netlink implementation for Rust, supporting:

- **Interface management** - List, create, modify, delete network interfaces
- **IP addresses** - Manage IPv4 and IPv6 addresses
- **Routing** - Query and modify routing tables
- **Neighbors** - ARP/NDP cache management
- **Traffic Control** - Qdiscs, classes, filters, and actions
- **Event monitoring** - Real-time network change notifications

## Features

- **Async/await native** - Built on tokio with `AsyncFd`
- **Strongly typed** - All messages parsed into Rust types
- **Zero-copy parsing** - Efficient attribute iteration
- **High-level API** - Convenience methods for common operations
- **Low-level access** - Direct message building when needed

## Quick Start

### Querying Network State

```rust
use rip_netlink::{Connection, Protocol};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let conn = Connection::new(Protocol::Route)?;
    
    // Get all interfaces
    let links = conn.get_links().await?;
    for link in &links {
        println!("{}: {} (up={})", 
            link.ifindex(),
            link.name.as_deref().unwrap_or("?"),
            link.is_up());
    }
    
    // Get addresses for a specific interface
    let addrs = conn.get_addresses_for("eth0").await?;
    for addr in &addrs {
        println!("  {:?}/{}", addr.address, addr.prefix_len());
    }
    
    // Get all qdiscs
    let qdiscs = conn.get_qdiscs().await?;
    for qdisc in &qdiscs {
        println!("qdisc {} on idx {}", 
            qdisc.kind().unwrap_or("?"), 
            qdisc.ifindex());
    }
    
    Ok(())
}
```

### Monitoring Network Events

```rust
use rip_netlink::events::{EventStream, NetworkEvent};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut stream = EventStream::builder()
        .links(true)
        .addresses(true)
        .routes(true)
        .tc(true)
        .build()?;
    
    println!("Monitoring network events...");
    
    while let Some(event) = stream.next().await? {
        match event {
            NetworkEvent::NewLink(link) => {
                println!("[LINK+] {}", link.name.as_deref().unwrap_or("?"));
            }
            NetworkEvent::DelLink(link) => {
                println!("[LINK-] {}", link.name.as_deref().unwrap_or("?"));
            }
            NetworkEvent::NewAddress(addr) => {
                println!("[ADDR+] {:?}/{}", addr.address, addr.prefix_len());
            }
            NetworkEvent::DelAddress(addr) => {
                println!("[ADDR-] {:?}/{}", addr.address, addr.prefix_len());
            }
            NetworkEvent::NewRoute(route) => {
                println!("[ROUTE+] {:?}/{}", route.destination(), route.dst_len());
            }
            NetworkEvent::NewQdisc(tc) => {
                println!("[QDISC+] {} on idx {}", 
                    tc.kind().unwrap_or("?"), tc.ifindex());
            }
            _ => {}
        }
    }
    
    Ok(())
}
```

### Parsing TC Options

```rust
use rip_netlink::tc_options::{parse_qdisc_options, QdiscOptions};

let qdiscs = conn.get_qdiscs().await?;

for qdisc in &qdiscs {
    if let Some(opts) = parse_qdisc_options(qdisc) {
        match opts {
            QdiscOptions::FqCodel(fq) => {
                println!("fq_codel: target={}us interval={}us limit={} ecn={}",
                    fq.target_us, fq.interval_us, fq.limit, fq.ecn);
            }
            QdiscOptions::Htb(htb) => {
                println!("htb: default={:x} r2q={}", 
                    htb.default_class, htb.rate2quantum);
            }
            QdiscOptions::Tbf(tbf) => {
                println!("tbf: rate={} burst={} limit={}", 
                    tbf.rate, tbf.burst, tbf.limit);
            }
            QdiscOptions::Netem(netem) => {
                println!("netem: delay={}us jitter={}us loss={:.2}%",
                    netem.delay_us, netem.jitter_us, netem.loss_percent);
            }
            _ => {}
        }
    }
}
```

### Tracking Statistics Over Time

```rust
use rip_netlink::stats::{StatsSnapshot, StatsTracker};
use std::time::Duration;

let mut tracker = StatsTracker::new();

loop {
    let links = conn.get_links().await?;
    let snapshot = StatsSnapshot::from_links(&links);
    
    if let Some(rates) = tracker.update(snapshot) {
        for (ifindex, link_rates) in &rates.links {
            if link_rates.total_bytes_per_sec() > 0.0 {
                println!("Interface {}: {:.2} Mbps RX, {:.2} Mbps TX",
                    ifindex,
                    link_rates.rx_bps() / 1_000_000.0,
                    link_rates.tx_bps() / 1_000_000.0);
            }
        }
    }
    
    tokio::time::sleep(Duration::from_secs(1)).await;
}
```

## Modules

| Module | Description |
|--------|-------------|
| `connection` | High-level `Connection` type with query methods |
| `events` | `EventStream` for monitoring network changes |
| `messages` | Strongly-typed message types (`LinkMessage`, `AddressMessage`, etc.) |
| `tc_options` | Typed parsing of qdisc options (fq_codel, htb, tbf, netem, etc.) |
| `stats` | Statistics tracking and rate calculation |
| `types` | Low-level netlink structures and constants |
| `builder` | `MessageBuilder` for constructing netlink messages |
| `attr` | Attribute parsing utilities |

## Message Types

### LinkMessage

Network interface information:
- `ifindex()`, `name`, `flags`, `mtu`
- `is_up()`, `is_running()`, `has_carrier()`
- `mac_address()`, `operstate`
- `stats` - RX/TX bytes, packets, errors, drops
- `link_info` - Type (vlan, bridge, bond, etc.)

### AddressMessage

IP address information:
- `address` - `IpAddr` (v4 or v6)
- `prefix_len()`, `ifindex()`, `scope()`
- `is_ipv4()`, `is_ipv6()`
- `is_permanent()`, `is_deprecated()`, `is_tentative()`

### RouteMessage

Routing entry:
- `destination()`, `dst_len()`
- `gateway()`, `oif()` (output interface)
- `table_id()`, `protocol()`, `scope()`
- `prefsrc()` - Preferred source address

### NeighborMessage

ARP/NDP cache entry:
- `destination` - IP address
- `lladdr` - Link-layer (MAC) address
- `ifindex()`, `state()`

### TcMessage

Traffic control (qdisc/class/filter):
- `ifindex()`, `handle()`, `parent()`
- `kind()` - "htb", "fq_codel", etc.
- `bytes()`, `packets()`, `drops()`, `qlen()`
- `options` - Raw options (use `tc_options::parse_qdisc_options()` for typed access)

## License

Licensed under either of Apache License, Version 2.0 or MIT license at your option.
