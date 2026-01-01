# nlink - Rust IP utilities

A modern Rust implementation of Linux network management tools, providing both a library crate and CLI binaries.

## Overview

nlink is a from-scratch implementation of Linux netlink-based network management. The primary goal is to provide a high-quality Rust library for programmatic network configuration, with CLI tools serving as proof-of-concept binaries.

**Key design principles:**

- **Library-first**: Core functionality lives in a single, well-designed crate
- **Async/tokio-native**: Built for async Rust from the ground up
- **Custom netlink**: No dependency on rtnetlink or netlink-packet-* crates
- **Type-safe**: Leverage Rust's type system for correctness
- **Modern CLI**: Not a drop-in replacement for iproute2 - free to improve

## Installation

Add to your `Cargo.toml`:

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
| `full` | All features enabled |

## Using as a Library

```rust
use nlink::netlink::{Connection, Protocol};
use nlink::netlink::events::{EventStream, NetworkEvent};

#[tokio::main]
async fn main() -> nlink::Result<()> {
    let conn = Connection::new(Protocol::Route)?;
    
    // Query network state with convenience methods
    let links = conn.get_links().await?;
    for link in &links {
        println!("{}: {} (up={})", 
            link.ifindex(), 
            link.name.as_deref().unwrap_or("?"),
            link.is_up());
    }
    
    // Get addresses for a specific interface
    let addrs = conn.get_addresses_for("eth0").await?;
    
    // Get TC qdiscs
    let qdiscs = conn.get_qdiscs().await?;
    
    // Monitor network events
    let mut stream = EventStream::builder()
        .links(true)
        .addresses(true)
        .tc(true)
        .build()?;
    
    while let Some(event) = stream.next().await? {
        match event {
            NetworkEvent::NewLink(link) => println!("Link added: {:?}", link.name),
            NetworkEvent::NewAddress(addr) => println!("Address added: {:?}", addr.address),
            _ => {}
        }
    }
    
    Ok(())
}
```

## Library Modules

### `nlink::netlink` - Core netlink functionality

- **High-level API**: `Connection` with convenience query methods (`get_links()`, `get_addresses()`, etc.)
- **Event monitoring**: `EventStream` for real-time network change notifications
- **Strongly-typed messages**: `LinkMessage`, `AddressMessage`, `RouteMessage`, `TcMessage`
- **TC options parsing**: Typed access to qdisc parameters (fq_codel, htb, tbf, netem, etc.)
- **Statistics tracking**: `StatsSnapshot` and `StatsTracker` for rate calculation
- **Low-level access**: `MessageBuilder` for custom netlink messages

### `nlink::util` - Shared utilities

- Argument parsing (`get_u8`, `get_u16`, `get_u32`, `get_rate`, `get_size`)
- Address utilities (parse/format IP addresses and prefixes)
- Name resolution (protocol names, scope names, table names)
- Interface name/index mapping

### `nlink::sockdiag` - Socket diagnostics (feature: `sockdiag`)

- Query TCP, UDP, Unix, and other socket types
- Filter by state, port, address, and other criteria
- Retrieve detailed socket information (memory, TCP info, etc.)

### `nlink::tuntap` - TUN/TAP devices (feature: `tuntap`)

- Create and manage TUN/TAP virtual network devices
- Set device ownership and permissions
- Async read/write support

### `nlink::tc` - Traffic control (feature: `tc`)

- Qdisc option builders for htb, fq_codel, tbf, netem, etc.
- Handle parsing and formatting
- Class and filter builders

### `nlink::output` - Output formatting (feature: `output`)

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

# Show policy routing rules
ip rule show

# Add/remove rules
ip rule add --from 10.0.0.0/8 --table 100 --priority 1000
ip rule add --fwmark 0x100 --table 200
ip rule del --priority 1000

# Query route for a destination
ip route get 8.8.8.8

# Flush neighbor entries
ip neigh flush dev eth0

# Monitor netlink events (link, address, route, neighbor changes)
ip monitor all
ip monitor link address --timestamp
ip monitor -j  # JSON output

# Multicast addresses
ip maddress show
ip maddress show dev eth0

# VRF (Virtual Routing and Forwarding)
ip vrf show
ip vrf exec vrf0 ping 10.0.0.1
ip vrf identify $$
ip vrf pids vrf0

# XFRM (IPSec)
ip xfrm state show
ip xfrm state count
ip xfrm policy show
ip xfrm policy count

# Network namespaces
ip netns list
ip netns add myns
ip netns exec myns ip link show
ip netns del myns
ip netns identify $$  # Identify namespace of a PID
ip netns pids myns    # List PIDs in a namespace
ip netns monitor      # Watch namespace creation/deletion

# Tunnels (GRE, IPIP, SIT, VTI)
ip tunnel show
ip tunnel add gre1 --mode gre --remote 10.0.0.1 --local 10.0.0.2 --ttl 64
ip tunnel add tun0 --mode ipip --remote 192.168.1.1 --local 192.168.1.2
ip tunnel change gre1 --remote 10.0.0.3
ip tunnel del gre1
```

### tc

Traffic control (qdisc, class, filter):

```bash
# List qdiscs
tc qdisc show
tc qdisc show dev eth0

# Add qdiscs with type-specific options
tc qdisc add dev eth0 --parent root htb default 10 r2q 10
tc qdisc add dev eth0 --parent root fq_codel limit 10000 target 5ms interval 100ms ecn
tc qdisc add dev eth0 --parent root tbf rate 1mbit burst 32kb limit 100kb
tc qdisc add dev eth0 --parent root prio bands 3
tc qdisc add dev eth0 --parent root sfq perturb 10 limit 127

# Replace/change qdiscs
tc qdisc replace dev eth0 --parent root fq_codel limit 5000
tc qdisc change dev eth0 --parent root fq_codel target 10ms

# Netem - network emulation (delay, loss, reorder, corrupt, duplicate)
tc qdisc add dev eth0 --parent root netem delay 100ms 10ms 25%
tc qdisc add dev eth0 --parent root netem loss 1% 25%
tc qdisc add dev eth0 --parent root netem duplicate 1%
tc qdisc add dev eth0 --parent root netem corrupt 0.1%
tc qdisc add dev eth0 --parent root netem reorder 25% 50% gap 5
tc qdisc add dev eth0 --parent root netem rate 1mbit
tc qdisc add dev eth0 --parent root netem delay 100ms loss 1% duplicate 0.5%

# Delete qdiscs
tc qdisc del dev eth0 --parent root

# List classes
tc class show
tc class show dev eth0

# Add HTB classes with rate limiting
tc class add dev eth0 --parent 1: --classid 1:10 htb rate 10mbit ceil 100mbit prio 1
tc class add dev eth0 --parent 1: --classid 1:20 htb rate 5mbit ceil 50mbit burst 15k

# Monitor TC events
tc monitor all
tc monitor qdisc class --timestamp
tc monitor -j  # JSON output

# List filters
tc filter show
tc filter show dev eth0
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

The library API is production-ready for network monitoring and querying. Currently implemented:

- [x] Core netlink socket and connection handling
- [x] Message building with nested attributes
- [x] Link operations (show, add, del, set)
- [x] Link types: dummy, veth, bridge, bond, vlan, vxlan, macvlan, ipvlan, vrf, gre, ipip, sit, wireguard
- [x] Address operations (show, add, del)
- [x] Route operations (show, add, del, replace)
- [x] Neighbor operations (show, add, del, replace)
- [x] Policy routing rules (ip rule show, add, del, flush)
- [x] Event monitoring (ip monitor) for link, address, route, neighbor changes
- [x] TC qdisc operations (show, add, del, replace, change)
- [x] TC qdisc types: fq_codel, htb, tbf, prio, sfq, netem (with full parameter support)
- [x] TC netem qdisc (delay, loss, reorder, corrupt, duplicate, rate limiting)
- [x] TC class operations with HTB parameters (rate, ceil, burst, prio, quantum)
- [x] TC monitor for qdisc/class/filter events
- [x] TC filter operations (show, add, del)
- [x] TC filter types: u32 (match ip/ip6/tcp/udp/icmp), flower, basic, fw
- [x] TC actions: gact (pass/drop/pipe), mirred (mirror/redirect), police (rate limiting)

- [x] Network namespace support (ip netns list, add, del, exec, identify, pids, monitor, set, attach)
- [x] Tunnel management (ip tunnel show, add, del, change) for GRE, IPIP, SIT, VTI
- [x] Route lookup (ip route get)
- [x] Neighbor flush (ip neigh flush)
- [x] Multicast addresses (ip maddress show)
- [x] VRF management (ip vrf show, exec, identify, pids)
- [x] XFRM/IPSec framework (ip xfrm state/policy show, count)

**Library features:**

- [x] High-level event stream API (`EventStream`, `NetworkEvent`)
- [x] Convenience query methods (`get_links()`, `get_addresses()`, `get_qdiscs()`, etc.)
- [x] Typed TC options parsing (fq_codel, htb, tbf, netem, prio, sfq)
- [x] Statistics helpers with rate calculation (`StatsSnapshot`, `StatsTracker`)

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.
