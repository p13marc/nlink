# nlink: Interface name resolution fails in network namespaces

## Summary

When using `namespace::connection_for()` to create a connection in a network namespace, operations that require interface name resolution (like `add_address`, `set_link_up`, `add_qdisc`) fail with "interface not found" even though the interface exists in that namespace.

## Root Cause

The `ifname_to_index()` function in `src/netlink/addr.rs` uses sysfs to resolve interface names:

```rust
fn ifname_to_index(name: &str) -> Result<u32> {
    let path = format!("/sys/class/net/{}/ifindex", name);
    let content = std::fs::read_to_string(&path)
        .map_err(|_| Error::InvalidMessage(format!("interface not found: {}", name)))?;
    // ...
}
```

This reads from `/sys/class/net/{name}/ifindex` which is in the **host's** sysfs, not the target namespace's sysfs. The netlink socket created by `namespace::connection_for()` correctly operates in the target namespace, but the interface name resolution happens in the host namespace.

## Reproduction

```rust
use nlink::netlink::{namespace, Connection, Route};
use nlink::netlink::addr::Ipv4Address;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Assume namespace "myns" exists with interface "veth0" inside it
    // (veth0 is NOT in the host namespace)
    
    let conn: Connection<Route> = namespace::connection_for("myns")?;
    
    // This works - get_links uses netlink, not sysfs
    let links = conn.get_links().await?;
    for link in &links {
        println!("Found interface: {} (index {})", link.name().unwrap_or("?"), link.ifindex());
    }
    // Output: Found interface: veth0 (index 28)
    
    // This fails - add_address uses sysfs to resolve "veth0"
    conn.add_address(Ipv4Address::new("veth0", "10.1.0.1".parse()?, 24)).await?;
    // Error: interface not found: veth0
    
    Ok(())
}
```

## Affected Functions

Any function that calls `ifname_to_index()` internally:
- `add_address()` / `replace_address()` / `del_address()`
- `set_link_up()` / `set_link_down()`
- `add_qdisc()` / `del_qdisc()`
- Any other function that resolves interface name to index via sysfs

## Current Workaround

Enter the namespace with `setns()` before creating the connection, so sysfs is also in the correct namespace:

```rust
use nix::sched::{setns, CloneFlags};
use std::fs::File;
use std::os::fd::AsFd;

// Enter the namespace first
let ns_file = File::open("/var/run/netns/myns")?;
setns(ns_file.as_fd(), CloneFlags::CLONE_NEWNET)?;

// Now sysfs lookups will work correctly
let conn = Connection::<Route>::new()?;
conn.add_address(Ipv4Address::new("veth0", "10.1.0.1".parse()?, 24)).await?;
```

This defeats the purpose of `namespace::connection_for()` which is supposed to allow operations in a namespace without changing the current process's namespace.

## Suggested Fix

Replace sysfs-based interface resolution with netlink-based resolution.

### Recommended: Use RTM_GETLINK with IFLA_IFNAME filter

Query the interface index via netlink using the same connection. This ensures the lookup happens in the correct namespace since it uses the netlink socket.

The `ifname_to_index()` function should be changed from:

```rust
// Current implementation (broken for namespaces)
fn ifname_to_index(name: &str) -> Result<u32> {
    let path = format!("/sys/class/net/{}/ifindex", name);
    let content = std::fs::read_to_string(&path)
        .map_err(|_| Error::InvalidMessage(format!("interface not found: {}", name)))?;
    content.trim().parse()
        .map_err(|_| Error::InvalidMessage(format!("invalid ifindex for: {}", name)))
}
```

To something like:

```rust
// Fixed implementation using netlink
async fn ifname_to_index_netlink(conn: &Connection<Route>, name: &str) -> Result<u32> {
    // Use get_link_by_name or similar to resolve via netlink
    let link = conn.get_link_by_name(name).await?
        .ok_or_else(|| Error::InvalidMessage(format!("interface not found: {}", name)))?;
    Ok(link.ifindex())
}
```

### Alternative: Add `_by_index` variants for address operations

nlink already has `_by_index` methods for many operations:
- `set_link_up_by_index()`
- `add_qdisc_by_index()`
- `del_qdisc_by_index()`

Adding similar methods for address operations would allow users to work around the issue:
- `add_address_by_index(ifindex: u32, address: IpAddr, prefix_len: u8)`
- `del_address_by_index(ifindex: u32, address: IpAddr, prefix_len: u8)`

### Functions affected

The `ifname_to_index()` helper is used in `src/netlink/addr.rs` for:
- `Ipv4Address::build()`
- `Ipv4Address::build_replace()`
- `Ipv4Address::build_delete()`
- `Ipv6Address::build()`
- `Ipv6Address::build_replace()`
- `Ipv6Address::build_delete()`

And likely in other places for tc/qdisc operations that take interface names.

## Environment

- nlink version: 0.7.0
- Linux kernel: 6.17.9
- Rust: 1.85+

## Impact

This bug makes `namespace::connection_for()` unusable for most practical namespace operations. Users must fall back to `setns()` which changes the process's namespace context.
