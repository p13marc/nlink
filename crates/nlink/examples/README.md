# nlink Examples

This directory contains examples demonstrating the nlink library's capabilities for Linux network configuration via netlink.

## Directory Structure

```
examples/
├── README.md
├── route/              # Route protocol (RTNetlink) examples
│   ├── addresses.rs
│   ├── error_handling.rs
│   ├── link_create.rs
│   ├── list_interfaces.rs
│   ├── namespaces.rs
│   ├── neighbors.rs
│   ├── routes.rs
│   ├── stats.rs
│   └── tc/             # Traffic control examples
│       ├── htb.rs
│       ├── netem.rs
│       └── stats.rs
├── events/             # Event monitoring examples
│   ├── monitor.rs
│   ├── monitor_namespace.rs
│   └── multi_source.rs
├── namespace/          # Namespace management examples
│   ├── events.rs
│   └── watch.rs
├── genl/               # Generic Netlink examples
│   └── wireguard.rs
├── sockdiag/           # Socket diagnostics examples
│   ├── list_sockets.rs
│   ├── tcp_connections.rs
│   └── unix_sockets.rs
├── uevent/             # Kernel uevent examples
│   ├── device_monitor.rs
│   └── device_monitor_stream.rs
├── connector/          # Kernel connector examples
│   ├── process_monitor.rs
│   └── process_monitor_stream.rs
├── netfilter/          # Netfilter examples
│   └── conntrack.rs
├── xfrm/               # XFRM (IPsec) examples
│   └── ipsec_monitor.rs
├── fib_lookup/         # FIB lookup examples
│   └── route_lookup.rs
├── audit/              # Linux Audit examples
│   └── audit_status.rs
└── selinux/            # SELinux examples
    ├── selinux_monitor.rs
    └── selinux_monitor_stream.rs
```

## Running Examples

Examples can be run with:

```bash
cargo run -p nlink --example <example_name>
```

Some examples require specific features or root privileges. See the individual example descriptions below.

## Route Protocol Examples

### Basic Network Information

| Example | Description | Command |
|---------|-------------|---------|
| `route_list_interfaces` | List all network interfaces with state, MAC, and MTU | `cargo run -p nlink --example route_list_interfaces` |
| `route_addresses` | List, add, or delete IP addresses | `cargo run -p nlink --example route_addresses` |
| `route_routes` | List routes (optionally filter by IPv4/IPv6) | `cargo run -p nlink --example route_routes` |
| `route_neighbors` | List ARP/NDP neighbor entries | `cargo run -p nlink --example route_neighbors` |
| `route_stats` | Monitor interface statistics in real-time | `cargo run -p nlink --example route_stats` |

### Link Management

| Example | Description | Command |
|---------|-------------|---------|
| `route_link_create` | Create virtual interfaces (dummy, veth, bridge) | `sudo cargo run -p nlink --example route_link_create` |

### Traffic Control (TC)

| Example | Description | Command |
|---------|-------------|---------|
| `route_tc_netem` | Network emulation (delay, loss, corruption) | `cargo run -p nlink --example route_tc_netem` |
| `route_tc_htb` | HTB qdisc and class inspection | `cargo run -p nlink --example route_tc_htb` |
| `route_tc_stats` | Real-time TC qdisc statistics monitoring | `cargo run -p nlink --example route_tc_stats` |

### Namespaces

| Example | Description | Command |
|---------|-------------|---------|
| `route_namespaces` | List namespaces and query interfaces in each | `cargo run -p nlink --example route_namespaces` |

### Error Handling

| Example | Description | Command |
|---------|-------------|---------|
| `route_error_handling` | Demonstrate error handling patterns | `cargo run -p nlink --example route_error_handling` |

## Event Monitoring Examples

| Example | Description | Command |
|---------|-------------|---------|
| `events_monitor` | Monitor network events (link, address, route changes) | `cargo run -p nlink --example events_monitor` |
| `events_monitor_namespace` | Monitor events in a specific namespace | `cargo run -p nlink --example events_monitor_namespace -- <ns_name>` |

## Namespace Examples

| Example | Description | Command |
|---------|-------------|---------|
| `namespace_events` | Monitor NSID netlink events | `cargo run -p nlink --example namespace_events` |
| `namespace_watch` | Watch namespace creation/deletion (inotify) | `cargo run -p nlink --features namespace_watcher --example namespace_watch` |

## Generic Netlink Examples

| Example | Description | Command |
|---------|-------------|---------|
| `genl_wireguard` | Query WireGuard device configuration | `cargo run -p nlink --example genl_wireguard` |

## Socket Diagnostics Examples

| Example | Description | Command |
|---------|-------------|---------|
| `sockdiag_list_sockets` | List all sockets (TCP, UDP, Unix) | `cargo run -p nlink --features sockdiag --example sockdiag_list_sockets` |
| `sockdiag_tcp_connections` | List TCP connections with state | `cargo run -p nlink --features sockdiag --example sockdiag_tcp_connections` |
| `sockdiag_unix_sockets` | List Unix domain sockets | `cargo run -p nlink --features sockdiag --example sockdiag_unix_sockets` |

## Uevent Examples (Device Hotplug)

| Example | Description | Command |
|---------|-------------|---------|
| `uevent_device_monitor` | Monitor device hotplug events (like udev) | `cargo run -p nlink --example uevent_device_monitor` |
| `uevent_device_monitor_stream` | Same using Stream API with `conn.events()` | `cargo run -p nlink --example uevent_device_monitor_stream` |

## Connector Examples (Process Events)

| Example | Description | Command |
|---------|-------------|---------|
| `connector_process_monitor` | Monitor process fork/exec/exit events | `sudo cargo run -p nlink --example connector_process_monitor` |
| `connector_process_monitor_stream` | Same using Stream API with `conn.events()` | `sudo cargo run -p nlink --example connector_process_monitor_stream` |

## Netfilter Examples (Connection Tracking)

| Example | Description | Command |
|---------|-------------|---------|
| `netfilter_conntrack` | List connection tracking entries | `cargo run -p nlink --example netfilter_conntrack` |

## XFRM Examples (IPsec)

| Example | Description | Command |
|---------|-------------|---------|
| `xfrm_ipsec_monitor` | List IPsec Security Associations and Policies | `cargo run -p nlink --example xfrm_ipsec_monitor` |

## FIB Lookup Examples

| Example | Description | Command |
|---------|-------------|---------|
| `fib_lookup_route_lookup` | Perform FIB route lookups for IP addresses | `cargo run -p nlink --example fib_lookup_route_lookup` |

## Audit Examples (Linux Audit Subsystem)

| Example | Description | Command |
|---------|-------------|---------|
| `audit_status` | Display audit daemon status, TTY auditing, and features | `cargo run -p nlink --example audit_status` |

## SELinux Examples

| Example | Description | Command |
|---------|-------------|---------|
| `selinux_monitor` | Monitor SELinux enforcement mode changes and policy loads | `cargo run -p nlink --example selinux_monitor` |
| `selinux_monitor_stream` | Same using Stream API with `conn.events()` | `cargo run -p nlink --example selinux_monitor_stream` |

## Multi-Source Event Monitoring

| Example | Description | Command |
|---------|-------------|---------|
| `events_multi_source` | Combine multiple event sources with `tokio::select!` | `sudo cargo run -p nlink --example events_multi_source` |

## Example Usage Patterns

### Using `get_interface_names()` helper

Build an ifindex-to-name map efficiently:

```rust
let conn = Connection::<Route>::new()?;
let names = conn.get_interface_names().await?;

// Now use names.get(&ifindex) to resolve interface names
let routes = conn.get_routes().await?;
for route in routes {
    let dev = route.oif
        .and_then(|idx| names.get(&idx))
        .map(|s| s.as_str())
        .unwrap_or("-");
    println!("Route via {}", dev);
}
```

### Using `LinkMessage::name_or()` helper

Get interface name with a default value:

```rust
let links = conn.get_links().await?;
for link in links {
    println!("Interface: {}", link.name_or("?"));
}
```

### Using the Stream API with `conn.events()`

Protocols implementing `EventSource` can use the unified Stream API:

```rust
use nlink::netlink::{Connection, KobjectUevent, Connector, SELinux};
use tokio_stream::StreamExt;

// Device hotplug events
let conn = Connection::<KobjectUevent>::new()?;
let mut events = conn.events();  // Borrows connection
while let Some(event) = events.next().await {
    println!("{:?}", event?);
}

// Process events (requires root)
let conn = Connection::<Connector>::new().await?;
let mut events = conn.events();
while let Some(event) = events.next().await {
    println!("{:?}", event?);
}

// SELinux events
let conn = Connection::<SELinux>::new()?;
let mut events = conn.events();
while let Some(event) = events.next().await {
    println!("{:?}", event?);
}
```

### Combining multiple event sources

```rust
use nlink::netlink::{Connection, KobjectUevent, Connector};
use std::pin::pin;
use tokio_stream::StreamExt;

let uevent_conn = Connection::<KobjectUevent>::new()?;
let proc_conn = Connection::<Connector>::new().await?;

let mut uevent_events = pin!(uevent_conn.events());
let mut proc_events = pin!(proc_conn.events());

loop {
    tokio::select! {
        Some(result) = uevent_events.next() => {
            println!("[device] {:?}", result?);
        }
        Some(result) = proc_events.next() => {
            println!("[proc] {:?}", result?);
        }
    }
}
```

### Error handling with semantic checks

```rust
match conn.del_qdisc("eth0", "root").await {
    Ok(()) => println!("Deleted"),
    Err(e) if e.is_not_found() => println!("Nothing to delete"),
    Err(e) if e.is_permission_denied() => println!("Need root"),
    Err(e) => return Err(e),
}
```

## Root Privileges

Some operations require root privileges:
- Creating/deleting interfaces (`route_link_create`)
- Adding/deleting addresses (`route_addresses -- add/del`)
- Modifying TC configuration
- Accessing other network namespaces

Run with `sudo` when needed:

```bash
sudo cargo run -p nlink --example route_link_create
```

## Features

Some examples require specific features:

| Feature | Examples |
|---------|----------|
| `namespace_watcher` | `namespace_watch` |

Enable features with `--features`:

```bash
cargo run -p nlink --features namespace_watcher --example namespace_watch
```
