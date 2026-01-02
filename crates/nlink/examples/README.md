# nlink Examples

This directory contains examples demonstrating the nlink library's capabilities for Linux network configuration via netlink.

## Running Examples

Most examples can be run with:

```bash
cargo run -p nlink --example <example_name>
```

Some examples require specific features or root privileges. See the individual example descriptions below.

## Examples

### Basic Network Information

| Example | Description | Command |
|---------|-------------|---------|
| `list_interfaces` | List all network interfaces with state, MAC, and MTU | `cargo run -p nlink --example list_interfaces` |
| `addresses` | List, add, or delete IP addresses | `cargo run -p nlink --example addresses` |
| `routes` | List routes (optionally filter by IPv4/IPv6) | `cargo run -p nlink --example routes` |
| `neighbors` | List ARP/NDP neighbor entries | `cargo run -p nlink --example neighbors` |
| `stats` | Monitor interface statistics in real-time | `cargo run -p nlink --example stats` |

### Link Management

| Example | Description | Command |
|---------|-------------|---------|
| `link_create` | Create virtual interfaces (dummy, veth, bridge) | `sudo cargo run -p nlink --example link_create` |

### Traffic Control (TC)

These examples require the `tc` feature:

| Example | Description | Command |
|---------|-------------|---------|
| `tc_netem` | Network emulation (delay, loss, corruption) | `cargo run -p nlink --features tc --example tc_netem` |
| `tc_htb` | HTB qdisc and class inspection | `cargo run -p nlink --features tc --example tc_htb` |
| `tc_stats` | Real-time TC qdisc statistics monitoring | `cargo run -p nlink --features tc --example tc_stats` |

### Network Namespaces

| Example | Description | Command |
|---------|-------------|---------|
| `namespaces` | List namespaces and query interfaces in each | `cargo run -p nlink --example namespaces` |
| `namespace_watch` | Watch namespace creation/deletion (inotify) | `cargo run -p nlink --features namespace_watcher --example namespace_watch` |
| `namespace_events` | Monitor NSID netlink events | `cargo run -p nlink --example namespace_events` |
| `monitor_namespace` | Monitor network events in a specific namespace | `cargo run -p nlink --example monitor_namespace` |

### Event Monitoring

| Example | Description | Command |
|---------|-------------|---------|
| `monitor` | Monitor network events (link, address, route changes) | `cargo run -p nlink --example monitor` |
| `monitor_namespace` | Monitor events in a specific namespace | `cargo run -p nlink --example monitor_namespace -- <ns_name>` |

### Error Handling

| Example | Description | Command |
|---------|-------------|---------|
| `error_handling` | Demonstrate error handling patterns | `cargo run -p nlink --example error_handling` |

## Example Usage Patterns

### Using `get_interface_names()` helper

Build an ifindex-to-name map efficiently:

```rust
let conn = Connection::new(Protocol::Route)?;
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
- Creating/deleting interfaces (`link_create`)
- Adding/deleting addresses (`addresses -- add/del`)
- Modifying TC configuration
- Accessing other network namespaces

Run with `sudo` when needed:

```bash
sudo cargo run -p nlink --example link_create
```

## Features

Some examples require specific features:

| Feature | Examples |
|---------|----------|
| `tc` | `tc_netem`, `tc_htb`, `tc_stats` |
| `namespace_watcher` | `namespace_watch` |

Enable features with `--features`:

```bash
cargo run -p nlink --features tc --example tc_stats
cargo run -p nlink --features namespace_watcher --example namespace_watch
```
