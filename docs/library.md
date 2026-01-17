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
let qdiscs = conn.get_qdiscs_by_name("eth0").await?;

for qdisc in &qdiscs {
    // Quick type checks
    if qdisc.is_netem() && qdisc.is_root() {
        println!("Found root netem qdisc");
    }
    
    // Use options() for all qdisc types - returns parsed QdiscOptions enum
    match qdisc.options() {
        Some(QdiscOptions::Netem(netem)) => {
            println!("delay: {:?}, jitter: {:?}", netem.delay(), netem.jitter());
            println!("loss: {:?}, duplicate: {:?}", netem.loss(), netem.duplicate());
            
            if let Some(rate) = netem.rate_bps() {
                println!("rate: {} bytes/sec", rate);
            }
            
            // Loss models (Gilbert-Intuitive or Gilbert-Elliot)
            if let Some(loss_model) = netem.loss_model() {
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
            println!("fq_codel: target={:?}, interval={:?}", fq.target(), fq.interval());
        }
        Some(QdiscOptions::Htb(htb)) => {
            println!("htb: default class={:?}", htb.default_class());
        }
        Some(QdiscOptions::Tbf(tbf)) => {
            println!("tbf: rate={:?}", tbf.rate());
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
    let qdiscs = conn.get_qdiscs_by_name("eth0").await?;
    
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

## Declarative Network Configuration

Infrastructure-as-code approach for network state management:

```rust
use nlink::netlink::{Connection, Route};
use nlink::netlink::config::{NetworkConfig, ConfigDiff};

let conn = Connection::<Route>::new()?;

// Capture current network state
let current = NetworkConfig::capture(&conn).await?;

// Load desired configuration from YAML/JSON
let desired: NetworkConfig = serde_yaml::from_str(r#"
links:
  - name: veth0
    kind: veth
    peer: veth1
  - name: br0
    kind: bridge

addresses:
  - dev: veth0
    address: 10.0.0.1/24

routes:
  - destination: 10.1.0.0/16
    gateway: 10.0.0.254
    dev: veth0
"#)?;

// Compare configurations
let diff = current.diff(&desired);
println!("Changes: {} additions, {} removals", 
    diff.additions().len(), 
    diff.removals().len());

// Apply changes (dry-run first)
diff.apply_dry_run(&conn).await?;  // Preview only
diff.apply(&conn).await?;           // Actually apply
```

## Rate Limiting DSL

High-level rate limiting with minimal configuration:

```rust
use nlink::netlink::{Connection, Route};
use nlink::netlink::ratelimit::{RateLimiter, PerHostLimiter, RateLimit};
use std::time::Duration;

let conn = Connection::<Route>::new()?;

// Simple interface-level rate limiting
RateLimiter::new("eth0")
    .egress(RateLimit::parse("100mbit")?)
    .ingress(RateLimit::parse("50mbit")?)
    .burst("256kb")?
    .apply(&conn).await?;

// Rate limit with network emulation
RateLimiter::new("eth0")
    .egress(RateLimit::parse("10mbit")?)
    .with_netem(|n| n
        .delay(Duration::from_millis(50))
        .loss(0.1))
    .apply(&conn).await?;

// Per-source rate limiting (limits each source IP independently)
PerHostLimiter::new("eth0")
    .per_source()
    .rate(RateLimit::parse("1mbit")?)
    .apply(&conn).await?;

// Per-destination rate limiting
PerHostLimiter::new("eth0")
    .per_destination()
    .rate(RateLimit::parse("10mbit")?)
    .burst("64kb")?
    .apply(&conn).await?;
```

## Network Diagnostics

High-level diagnostic tools for troubleshooting:

```rust
use nlink::netlink::diagnostics::{
    NetworkScanner, ConnectivityChecker, BottleneckDetector,
    ScanOptions, ConnectivityMethod
};
use std::net::IpAddr;

// Scan a subnet for active hosts
let scanner = NetworkScanner::new();
let results = scanner.scan("192.168.1.0/24", ScanOptions {
    timeout_ms: 1000,
    concurrent: 50,
    resolve_hostnames: true,
    check_ports: vec![22, 80, 443],
}).await?;

for host in &results {
    println!("{}: latency={:?}, hostname={:?}", 
        host.ip, host.latency, host.hostname);
    for port in &host.open_ports {
        println!("  port {} open", port);
    }
}

// Check connectivity to a destination
let checker = ConnectivityChecker::new();
let result = checker.check(
    "8.8.8.8".parse()?,
    ConnectivityMethod::Icmp,
).await?;
println!("Reachable: {}, latency: {:?}, hops: {:?}", 
    result.reachable, result.latency, result.hops);

// Detect bottlenecks on a path
let detector = BottleneckDetector::new();
let report = detector.detect("10.0.0.1".parse()?).await?;
for issue in &report.issues {
    println!("[{:?}] {}: {}", issue.severity, issue.location, issue.description);
    for rec in &issue.recommendations {
        println!("  - {}", rec);
    }
}
```

## TC Classes and Filters

### HTB Class Configuration

```rust
use nlink::netlink::{Connection, Route};
use nlink::netlink::tc::{HtbQdiscConfig, HtbClassConfig};

let conn = Connection::<Route>::new()?;

// Add HTB qdisc
let htb = HtbQdiscConfig::new().default_class(0x30).build();
conn.add_qdisc_full("eth0", "root", Some("1:"), htb).await?;

// Add root class (total bandwidth)
conn.add_class_config("eth0", "1:0", "1:1",
    HtbClassConfig::new("1gbit")?
        .ceil("1gbit")?
        .build()
).await?;

// Add child classes with priorities
conn.add_class_config("eth0", "1:1", "1:10",
    HtbClassConfig::new("100mbit")?
        .ceil("500mbit")?
        .prio(1)  // High priority
        .build()
).await?;

conn.add_class_config("eth0", "1:1", "1:20",
    HtbClassConfig::new("50mbit")?
        .ceil("200mbit")?
        .prio(2)  // Lower priority
        .build()
).await?;
```

### TC Filters

```rust
use nlink::netlink::{Connection, Route};
use nlink::netlink::filter::{U32Filter, FlowerFilter, MatchallFilter};
use nlink::netlink::action::{GactAction, MirredAction, PoliceAction};
use std::net::Ipv4Addr;

let conn = Connection::<Route>::new()?;

// U32 filter to match destination port
let filter = U32Filter::new()
    .classid("1:10")
    .match_dst_port(80)
    .build();
conn.add_filter("eth0", "1:", filter).await?;

// Flower filter for TCP traffic to subnet
let filter = FlowerFilter::new()
    .classid("1:20")
    .ip_proto_tcp()
    .dst_ipv4(Ipv4Addr::new(10, 0, 0, 0), 8)
    .build();
conn.add_filter("eth0", "1:", filter).await?;

// Filter with police action (rate limit)
let police = PoliceAction::new()
    .rate(1_000_000)
    .burst(10000)
    .exceed_drop()
    .build();

let filter = MatchallFilter::new()
    .action(police)
    .build();
conn.add_filter("eth0", "ingress", filter).await?;

// Mirror traffic to another interface
let mirror = MirredAction::mirror_egress("eth1");
let filter = FlowerFilter::new()
    .ip_proto_tcp()
    .dst_port(443)
    .action(mirror)
    .build();
conn.add_filter("eth0", "ingress", filter).await?;
```

### TC Filter Chains

```rust
use nlink::netlink::{Connection, Route};
use nlink::netlink::filter::FlowerFilter;
use nlink::netlink::action::GactAction;
use nlink::netlink::tc::IngressConfig;

let conn = Connection::<Route>::new()?;

// Add ingress qdisc
conn.add_qdisc("eth0", IngressConfig::new()).await?;

// Create filter chains
conn.add_tc_chain("eth0", "ingress", 0).await?;
conn.add_tc_chain("eth0", "ingress", 100).await?;

// Add filter in chain 0 that jumps to chain 100 for TCP
let filter = FlowerFilter::new()
    .chain(0)
    .ip_proto_tcp()
    .goto_chain(100)
    .build();
conn.add_filter("eth0", "ingress", filter).await?;

// Add filter in chain 100 to drop port 80
let filter = FlowerFilter::new()
    .chain(100)
    .ip_proto_tcp()
    .dst_port(80)
    .action(GactAction::drop())
    .build();
conn.add_filter("eth0", "ingress", filter).await?;

// List chains
for chain in conn.get_tc_chains("eth0", "ingress").await? {
    println!("Chain: {}", chain);
}
```

## Bridge FDB and VLAN

### FDB Management

```rust
use nlink::netlink::{Connection, Route};
use nlink::netlink::fdb::FdbEntryBuilder;
use std::net::Ipv4Addr;

let conn = Connection::<Route>::new()?;

// Query FDB entries
let entries = conn.get_fdb("br0").await?;
for entry in &entries {
    println!("{} vlan={:?} state={:?}", 
        entry.mac_str(), entry.vlan, entry.state);
}

// Add static FDB entry
let mac = FdbEntryBuilder::parse_mac("aa:bb:cc:dd:ee:ff")?;
conn.add_fdb(
    FdbEntryBuilder::new(mac)
        .dev("veth0")
        .master("br0")
        .vlan(100)
        .permanent()
).await?;

// VXLAN FDB for remote VTEP
conn.add_fdb(
    FdbEntryBuilder::new([0x00; 6])  // All-zeros for BUM traffic
        .dev("vxlan0")
        .dst(Ipv4Addr::new(192, 168, 1, 100).into())
).await?;

// Flush dynamic entries
conn.flush_fdb("br0").await?;
```

### VLAN Filtering

```rust
use nlink::netlink::{Connection, Route};
use nlink::netlink::bridge_vlan::BridgeVlanBuilder;

let conn = Connection::<Route>::new()?;

// Query VLANs on a port
let vlans = conn.get_bridge_vlans("eth0").await?;
for vlan in &vlans {
    println!("VLAN {}: pvid={} untagged={}", 
        vlan.vid, vlan.flags.pvid, vlan.flags.untagged);
}

// Set native VLAN (PVID + untagged)
conn.set_bridge_pvid("eth0", 100).await?;

// Add tagged VLAN
conn.add_bridge_vlan_tagged("eth0", 200).await?;

// Add VLAN range
conn.add_bridge_vlan_range("eth0", 300, 310).await?;

// Delete VLANs
conn.del_bridge_vlan("eth0", 200).await?;
conn.del_bridge_vlan_range("eth0", 300, 310).await?;
```

## Nexthop Objects and ECMP

```rust
use nlink::netlink::{Connection, Route};
use nlink::netlink::nexthop::{NexthopBuilder, NexthopGroupBuilder};
use nlink::netlink::route::Ipv4Route;
use std::net::Ipv4Addr;

let conn = Connection::<Route>::new()?;

// Create individual nexthops
conn.add_nexthop(
    NexthopBuilder::new(1)
        .gateway(Ipv4Addr::new(192, 168, 1, 1).into())
        .dev("eth0")
).await?;

conn.add_nexthop(
    NexthopBuilder::new(2)
        .gateway(Ipv4Addr::new(192, 168, 2, 1).into())
        .dev("eth1")
).await?;

// Create ECMP group with equal weights
conn.add_nexthop_group(
    NexthopGroupBuilder::new(100)
        .member(1, 1)
        .member(2, 1)
).await?;

// Create weighted group (2:1 ratio)
conn.add_nexthop_group(
    NexthopGroupBuilder::new(101)
        .member(1, 2)
        .member(2, 1)
).await?;

// Create resilient group (maintains flow affinity)
conn.add_nexthop_group(
    NexthopGroupBuilder::new(102)
        .resilient()
        .member(1, 1)
        .member(2, 1)
        .buckets(128)
        .idle_timer(120)
).await?;

// Use nexthop group in route
conn.add_route(
    Ipv4Route::new("10.0.0.0", 8)
        .nexthop_group(100)
).await?;

// Query nexthops
for nh in conn.get_nexthops().await? {
    if nh.is_group() {
        println!("Group {}: {:?}", nh.id, nh.group);
    } else {
        println!("NH {}: gateway={:?}", nh.id, nh.gateway);
    }
}
```

## MPLS Routes

```rust
use nlink::netlink::{Connection, Route};
use nlink::netlink::mpls::{MplsEncap, MplsRouteBuilder};
use nlink::netlink::route::Ipv4Route;
use std::net::Ipv4Addr;

let conn = Connection::<Route>::new()?;

// IP route with MPLS encapsulation (push label)
conn.add_route(
    Ipv4Route::new("10.0.0.0", 8)
        .gateway(Ipv4Addr::new(192, 168, 1, 1))
        .dev("eth0")
        .mpls_encap(MplsEncap::new().label(100))
).await?;

// Push label stack (outer to inner)
conn.add_route(
    Ipv4Route::new("10.1.0.0", 16)
        .gateway(Ipv4Addr::new(192, 168, 1, 1))
        .mpls_encap(MplsEncap::new().labels(&[100, 200, 300]).ttl(64))
).await?;

// MPLS pop route (at egress PE)
conn.add_mpls_route(
    MplsRouteBuilder::pop(100)
        .dev("eth0")
).await?;

// MPLS swap route (at transit LSR)
conn.add_mpls_route(
    MplsRouteBuilder::swap(100, 200)
        .via("192.168.2.1".parse()?)
        .dev("eth1")
).await?;

// Query MPLS routes
for route in conn.get_mpls_routes().await? {
    println!("Label {}: {:?}", route.label.0, route.action);
}
```

## SRv6 Segment Routing

```rust
use nlink::netlink::{Connection, Route};
use nlink::netlink::srv6::{Srv6Encap, Srv6LocalBuilder};
use nlink::netlink::route::{Ipv4Route, Ipv6Route};
use std::net::Ipv6Addr;

let conn = Connection::<Route>::new()?;

// IPv4 route with SRv6 encapsulation
conn.add_route(
    Ipv4Route::new("10.0.0.0", 8)
        .dev("eth0")
        .srv6_encap(
            Srv6Encap::encap()
                .segment("fc00:1::1".parse()?)
        )
).await?;

// SRv6 with segment list
conn.add_route(
    Ipv4Route::new("10.1.0.0", 16)
        .dev("eth0")
        .srv6_encap(
            Srv6Encap::encap()
                .segments(&[
                    "fc00:1::1".parse()?,
                    "fc00:2::1".parse()?,
                ])
        )
).await?;

// SRv6 End local SID (simple transit)
conn.add_srv6_local(
    Srv6LocalBuilder::end("fc00:1::1".parse()?)
        .dev("eth0")
).await?;

// SRv6 End.DT4 (decap and lookup in VRF)
conn.add_srv6_local(
    Srv6LocalBuilder::end_dt4("fc00:1::100".parse()?, 100)
        .dev("eth0")
).await?;
```

## MACsec Configuration

```rust
use nlink::netlink::{Connection, Macsec};
use nlink::netlink::genl::macsec::MacsecSaBuilder;

let conn = Connection::<Macsec>::new_async().await?;

// Get device information (name resolved via netlink)
let device = conn.get_device("macsec0").await?;
println!("SCI: {:016x}, cipher: {:?}", device.sci, device.cipher_suite);

// Add TX SA
let key = [0u8; 16]; // 128-bit key
conn.add_tx_sa("macsec0",
    MacsecSaBuilder::new(0)
        .key(&key)
        .pn(1)
        .active(true)
).await?;

// Add RX SC and SA for a peer
let peer_sci = 0x001122334455_0001u64;
conn.add_rx_sc("macsec0", peer_sci).await?;
conn.add_rx_sa("macsec0", peer_sci,
    MacsecSaBuilder::new(0)
        .key(&key)
        .pn(1)
        .active(true)
).await?;
```

## MPTCP Path Manager

```rust
use nlink::netlink::{Connection, Mptcp};
use nlink::netlink::genl::mptcp::{MptcpEndpointBuilder, MptcpLimits};

let conn = Connection::<Mptcp>::new_async().await?;

// List endpoints
for ep in conn.get_endpoints().await? {
    println!("Endpoint {}: {} flags={:?}", ep.id, ep.address, ep.flags);
}

// Add endpoint for second interface
conn.add_endpoint(
    MptcpEndpointBuilder::new("192.168.2.1".parse()?)
        .id(1)
        .dev("eth1")
        .subflow()
        .signal()
).await?;

// Add backup endpoint
conn.add_endpoint(
    MptcpEndpointBuilder::new("10.0.0.1".parse()?)
        .id(2)
        .dev("wlan0")
        .backup()
        .signal()
).await?;

// Set connection limits
conn.set_limits(
    MptcpLimits::new()
        .subflows(4)
        .add_addr_accepted(4)
).await?;
```

## Module Reference

| Module | Description |
|--------|-------------|
| `nlink::netlink` | Core netlink: Connection, EventStream, namespace, TC |
| `nlink::netlink::config` | Declarative network configuration |
| `nlink::netlink::ratelimit` | Rate limiting DSL |
| `nlink::netlink::diagnostics` | Network diagnostics (scanner, connectivity, bottleneck) |
| `nlink::netlink::tc` | TC builders (netem, htb, fq_codel, etc.) |
| `nlink::netlink::filter` | TC filter builders (u32, flower, matchall, etc.) |
| `nlink::netlink::action` | TC action builders (gact, mirred, police, etc.) |
| `nlink::netlink::fdb` | Bridge FDB management |
| `nlink::netlink::bridge_vlan` | Bridge VLAN filtering |
| `nlink::netlink::nexthop` | Nexthop objects and ECMP groups |
| `nlink::netlink::mpls` | MPLS routes and encapsulation |
| `nlink::netlink::srv6` | SRv6 segment routing |
| `nlink::netlink::genl` | Generic Netlink (WireGuard, MACsec, MPTCP) |
| `nlink::util` | Parsing utilities, address helpers, name resolution |
| `nlink::sockdiag` | Socket diagnostics (feature: `sockdiag`) |
| `nlink::tuntap` | TUN/TAP devices (feature: `tuntap`) |
| `nlink::tc` | TC utilities (feature: `tc`) |
| `nlink::output` | Output formatting (feature: `output`) |
