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
│   └── monitor_namespace.rs
└── namespace/          # Namespace management examples
    ├── events.rs
    └── watch.rs
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
    // Instead of: link.name.as_deref().unwrap_or("?")
    println!("Interface: {}", link.name_or("?"));
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
