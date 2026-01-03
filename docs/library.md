# nlink Library Usage

This document covers library usage patterns for the nlink crate.

## Quick Start

```rust
use nlink::netlink::{Connection, Route};

#[tokio::main]
async fn main() -> nlink::Result<()> {
    let conn = Connection::<Route>::new()?;
    
    // Query interfaces
    let links = conn.get_links().await?;
    for link in &links {
        println!("{}: {} (up={})", 
            link.ifindex(), 
            link.name_or("?"),
            link.is_up());
    }
    
    // Modify interface state
    conn.set_link_up("eth0").await?;
    conn.set_link_mtu("eth0", 9000).await?;
    
    Ok(())
}
```

## Network Namespaces

```rust
use nlink::netlink::{Connection, Route, Generic};
use nlink::netlink::namespace;

// Connect to a named namespace (created via `ip netns add myns`)
// Functions are generic over protocol type
let conn: Connection<Route> = namespace::connection_for("myns")?;
let links = conn.get_links().await?;

// Connect by PID (e.g., container process)
let conn: Connection<Route> = namespace::connection_for_pid(1234)?;

// Connect by path
let conn: Connection<Route> = namespace::connection_for_path("/proc/1234/ns/net")?;

// Generic connections work too (e.g., for WireGuard in a namespace)
let genl: Connection<Generic> = namespace::connection_for("myns")?;

// List available namespaces
for ns in namespace::list()? {
    println!("Namespace: {}", ns);
}
```

## Event Monitoring

### Basic Event Stream

```rust
use nlink::netlink::{Connection, Route, RtnetlinkGroup, NetworkEvent};
use tokio_stream::StreamExt;

let mut conn = Connection::<Route>::new()?;
conn.subscribe(&[RtnetlinkGroup::Link, RtnetlinkGroup::Ipv4Addr, RtnetlinkGroup::Tc])?;

let mut events = conn.events();
while let Some(result) = events.next().await {
    match result? {
        NetworkEvent::NewLink(link) => println!("Link added: {}", link.name_or("?")),
        NetworkEvent::NewAddress(addr) => println!("Address added: {:?}", addr.address()),
        _ => {}
    }
}
```

### Namespace-aware Monitoring

```rust
use nlink::netlink::{Connection, Route, RtnetlinkGroup, namespace};
use tokio_stream::StreamExt;

// Monitor events in a named namespace
let mut conn = namespace::connection_for("myns")?;
conn.subscribe(&[RtnetlinkGroup::Link, RtnetlinkGroup::Tc])?;
let mut events = conn.events();

// Or by PID
let mut conn = namespace::connection_for_pid(1234)?;
conn.subscribe(&[RtnetlinkGroup::Link])?;

// Or by path
let mut conn = Connection::<Route>::new_in_namespace_path("/proc/1234/ns/net")?;
conn.subscribe_all()?;
```

## Watching Namespace Changes

Two complementary approaches for monitoring network namespace lifecycle:

```rust
use nlink::netlink::{NamespaceWatcher, NamespaceEvent};
use nlink::netlink::{NamespaceEventSubscriber, NamespaceNetlinkEvent};

// Option 1: Filesystem-based watching (feature: namespace_watcher)
// Watches /var/run/netns/ for named namespace creation/deletion
let mut watcher = NamespaceWatcher::new().await?;

while let Some(event) = watcher.recv().await? {
    match event {
        NamespaceEvent::Created { name } => println!("Created: {}", name),
        NamespaceEvent::Deleted { name } => println!("Deleted: {}", name),
        _ => {}
    }
}

// Atomically list existing + watch for changes (no race condition)
let (existing, mut watcher) = NamespaceWatcher::list_and_watch().await?;
println!("Existing: {:?}", existing);

// Option 2: Netlink-based events (always available)
// Receives RTM_NEWNSID/RTM_DELNSID kernel events
let mut sub = NamespaceEventSubscriber::new().await?;

while let Some(event) = sub.recv().await? {
    match event {
        NamespaceNetlinkEvent::NewNsId { nsid, pid, fd } => {
            println!("New NSID {}: pid={:?}", nsid, pid);
        }
        NamespaceNetlinkEvent::DelNsId { nsid } => {
            println!("Deleted NSID {}", nsid);
        }
    }
}
```

## Traffic Control (TC)

### Adding Qdiscs

```rust
use nlink::netlink::{Connection, Route, namespace};
use nlink::netlink::tc::NetemConfig;
use std::time::Duration;

let conn: Connection<Route> = namespace::connection_for("myns")?;

// Get interface index via netlink (namespace-aware)
let link = conn.get_link_by_name("eth0").await?;

let netem = NetemConfig::new()
    .delay(Duration::from_millis(100))
    .loss(1.0)
    .build();

// Use ifindex for namespace-aware operations
conn.add_qdisc_by_index(link.ifindex(), netem).await?;

// All TC methods have *_by_index variants:
// - add_qdisc_by_index / add_qdisc_by_index_full
// - del_qdisc_by_index / del_qdisc_by_index_full  
// - replace_qdisc_by_index / replace_qdisc_by_index_full
// - change_qdisc_by_index / change_qdisc_by_index_full
```

### Reading Existing TC Configurations

```rust
use nlink::netlink::{Connection, Route};
use nlink::netlink::tc_options::QdiscOptions;

let conn = Connection::<Route>::new()?;
let qdiscs = conn.get_qdiscs_for("eth0").await?;

for qdisc in &qdiscs {
    // Quick type checks
    if qdisc.is_netem() && qdisc.is_root() {
        println!("Found root netem qdisc");
    }
    
    // Use options() for all qdisc types - returns parsed QdiscOptions enum
    match qdisc.options() {
        Some(QdiscOptions::Netem(netem)) => {
            println!("delay: {:?}, jitter: {:?}", netem.delay(), netem.jitter());
            println!("loss: {}%, duplicate: {}%", netem.loss_percent, netem.duplicate_percent);
            
            if netem.rate > 0 {
                println!("rate: {} bytes/sec", netem.rate);
            }
            
            // Loss models (Gilbert-Intuitive or Gilbert-Elliot)
            if let Some(loss_model) = &netem.loss_model {
                use nlink::netlink::tc_options::NetemLossModel;
                match loss_model {
                    NetemLossModel::GilbertIntuitive { p13, p31, .. } => {
                        println!("4-state loss model: p13={:.2}%, p31={:.2}%", p13, p31);
                    }
                    NetemLossModel::GilbertElliot { p, r, h, .. } => {
                        println!("2-state loss model: p={:.2}%, r={:.2}%, h={:.2}%", p, r, h);
                    }
                }
            }
        }
        Some(QdiscOptions::FqCodel(fq)) => {
            println!("fq_codel: target={}us, interval={}us", fq.target_us, fq.interval_us);
        }
        Some(QdiscOptions::Htb(htb)) => {
            println!("htb: default class={:#x}", htb.default_class);
        }
        Some(QdiscOptions::Tbf(tbf)) => {
            println!("tbf: rate={} bytes/sec", tbf.rate);
        }
        _ => {}
    }
}
```

### Monitoring TC Statistics

```rust
use nlink::netlink::{Connection, Route};
use std::time::Duration;

let conn = Connection::<Route>::new()?;
let mut prev_stats = None;

loop {
    let qdiscs = conn.get_qdiscs_for("eth0").await?;
    
    for qdisc in &qdiscs {
        // Real-time rate from kernel's rate estimator
        println!("Rate: {} bps, {} pps", qdisc.bps(), qdisc.pps());
        
        // Calculate deltas from previous sample
        if let (Some(curr), Some(prev)) = (&qdisc.stats_basic, &prev_stats) {
            let delta = curr.delta(prev);
            println!("Delta: {} bytes, {} packets", delta.bytes, delta.packets);
        }
        
        prev_stats = qdisc.stats_basic;
    }
    
    tokio::time::sleep(Duration::from_secs(1)).await;
}
```

## Tunnel Management

### Creating Tunnels

```rust
use nlink::netlink::{Connection, Route};
use nlink::netlink::link::{GreLink, VxlanLink, VtiLink};
use std::net::Ipv4Addr;

let conn = Connection::<Route>::new()?;

// GRE tunnel
conn.add_link(GreLink::new("gre1")
    .local(Ipv4Addr::new(192, 168, 1, 1))
    .remote(Ipv4Addr::new(192, 168, 1, 2))
    .ttl(64)
    .key(100)
).await?;

// VXLAN tunnel
conn.add_link(VxlanLink::new("vxlan0", 100)  // VNI = 100
    .local(Ipv4Addr::new(10, 0, 0, 1))
    .remote(Ipv4Addr::new(10, 0, 0, 2))
    .port(4789)
    .learning(true)
).await?;

// VTI for IPsec
conn.add_link(VtiLink::new("vti0")
    .local(Ipv4Addr::new(192, 168, 1, 1))
    .remote(Ipv4Addr::new(192, 168, 1, 2))
    .ikey(100)
    .okey(100)
).await?;
```

### Tunnel Modification Limitations

**Important:** Tunnel parameters are immutable after creation. This is a Linux kernel limitation.

**What CAN be changed:**
- Interface state (up/down)
- MTU
- Interface name
- MAC address
- Master device (bridge membership)
- Network namespace

**What CANNOT be changed (requires delete + recreate):**
- Tunnel endpoints (local/remote IP)
- Tunnel keys
- TTL, TOS, encapsulation flags
- VXLAN VNI, port settings
- Any `IFLA_LINKINFO_DATA` parameter

### Safe Tunnel Replacement

```rust
use nlink::netlink::{Connection, Route};
use nlink::netlink::link::GreLink;
use std::net::Ipv4Addr;

let conn = Connection::<Route>::new()?;

// To change tunnel parameters, delete and recreate:
conn.del_link("gre1").await?;
conn.add_link(GreLink::new("gre1")
    .local(Ipv4Addr::new(192, 168, 1, 1))
    .remote(Ipv4Addr::new(10, 0, 0, 1))  // New remote
    .ttl(128)  // New TTL
).await?;
```

For zero-downtime changes, create a new tunnel with a temporary name, migrate traffic, then rename:

```rust
// 1. Create new tunnel with temp name
conn.add_link(GreLink::new("gre1_new")
    .remote(new_remote)
    .local(local)
).await?;

// 2. Update routing to use new tunnel
// ... (application-specific)

// 3. Delete old tunnel and rename new one
conn.del_link("gre1").await?;
conn.set_link_name("gre1_new", "gre1").await?;
```

## WireGuard via Generic Netlink

```rust
use nlink::netlink::{Connection, Wireguard};
use nlink::netlink::genl::wireguard::AllowedIp;
use std::net::{Ipv4Addr, SocketAddrV4};

let wg = Connection::<Wireguard>::new_async().await?;

// Get device information
let device = wg.get_device("wg0").await?;
println!("Public key: {:?}", device.public_key);
println!("Listen port: {:?}", device.listen_port);

for peer in &device.peers {
    println!("Peer: {:?}", peer.public_key);
    println!("  Endpoint: {:?}", peer.endpoint);
    println!("  RX: {} bytes, TX: {} bytes", peer.rx_bytes, peer.tx_bytes);
}

// Configure device (requires root)
let private_key = [0u8; 32]; // Your private key
wg.set_device("wg0", |dev| {
    dev.private_key(private_key)
       .listen_port(51820)
}).await?;

// Add a peer
let peer_pubkey = [0u8; 32];
wg.set_peer("wg0", peer_pubkey, |peer| {
    peer.endpoint(SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 1), 51820).into())
        .persistent_keepalive(25)
        .allowed_ip(AllowedIp::v4(Ipv4Addr::new(10, 0, 0, 0), 24))
        .replace_allowed_ips()
}).await?;

// Remove a peer
wg.remove_peer("wg0", peer_pubkey).await?;
```

## Error Handling

```rust
use nlink::netlink::{Connection, Route, Error};
use nlink::netlink::error::ValidationErrorInfo;

let conn = Connection::<Route>::new()?;

// Check error types for recovery logic
match conn.del_qdisc("eth0", "root").await {
    Ok(()) => println!("Qdisc deleted"),
    Err(e) if e.is_not_found() => println!("No qdisc to delete"),
    Err(e) if e.is_permission_denied() => println!("Need root privileges"),
    Err(e) if e.is_busy() => println!("Device is busy"),
    Err(e) => return Err(e),
}

// Semantic error types provide clear messages
// Error::InterfaceNotFound { name: "eth99" } -> "interface not found: eth99"
// Error::NamespaceNotFound { name: "myns" } -> "namespace not found: myns"

// Automatic error conversion from util types
use nlink::util::parse::get_rate;
let rate = get_rate("1mbit")?;  // ParseError converts to Error automatically

// Structured validation errors
let err = Error::validation(vec![
    ValidationErrorInfo::new("name", "cannot be empty"),
    ValidationErrorInfo::new("vlan_id", "must be 1-4094"),
]);
```

## Module Reference

| Module | Description |
|--------|-------------|
| `nlink::netlink` | Core netlink: Connection, EventStream, namespace, TC |
| `nlink::util` | Parsing utilities, address helpers, name resolution |
| `nlink::sockdiag` | Socket diagnostics (feature: `sockdiag`) |
| `nlink::tuntap` | TUN/TAP devices (feature: `tuntap`) |
| `nlink::netlink::genl` | Generic Netlink, WireGuard |
| `nlink::tc` | TC utilities (feature: `tc`) |
| `nlink::output` | Output formatting (feature: `output`) |
