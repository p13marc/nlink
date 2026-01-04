# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Nlink is a Rust library for Linux network configuration via netlink. The primary goal is to provide a well-designed Rust crate for programmatic network management. The binaries (`ip`, `tc`, `ss`) serve as proof-of-concept demonstrations.

**Key design decisions:**
- Custom netlink implementation - no dependency on rtnetlink/netlink-packet-* crates
- Async/tokio native using AsyncFd
- Library-first architecture - binaries are thin wrappers
- Single publishable crate with feature flags
- Rust edition 2024

## Build Commands

```bash
cargo build                    # Build all crates and binaries
cargo build -p nlink           # Build the library
cargo build -p nlink-ip        # Build ip binary
cargo test                     # Run all tests
cargo test -p nlink            # Test the library
```

## Integration Tests

The library includes comprehensive integration tests that use network namespaces
for isolated testing. These tests require root privileges and a Linux kernel with
network namespace support.

```bash
# Build the integration tests
cargo test --test integration --no-run

# Run integration tests (requires root and CAP_SYS_ADMIN)
sudo ./target/debug/deps/integration-* --test-threads=1

# Run a specific test
sudo ./target/debug/deps/integration-* test_create_dummy_interface --test-threads=1
```

**Test categories:**
- `link::*` - Interface creation (dummy, veth, bridge, vlan, macvlan, etc.)
- `address::*` - IPv4/IPv6 address management
- `route::*` - Routing table manipulation
- `tc::*` - Traffic control (qdiscs, classes, filters)
- `events::*` - Netlink event monitoring

**Requirements:**
- Root privileges (or CAP_NET_ADMIN + CAP_SYS_ADMIN)
- Linux kernel with network namespace support
- The `ip` command available in PATH (for namespace setup)

Tests use `--test-threads=1` to avoid namespace name collisions. Each test
creates a unique namespace that is automatically cleaned up on completion.

## Architecture

### Library Crate

**nlink** (`crates/nlink/`) - Single publishable crate with feature-gated modules:

```
crates/nlink/src/
  lib.rs              # Main entry point, re-exports
  netlink/            # Core netlink (always available)
    connection.rs     # High-level request/response/dump handling
    socket.rs         # Low-level async socket using netlink-sys + tokio AsyncFd
    builder.rs        # Message construction with MessageBuilder
    message.rs        # Netlink header parsing, MessageIter
    attr.rs           # Attribute (TLV) parsing with AttrIter
    error.rs          # Error types with semantic checks (is_not_found, etc.)
    events.rs         # NetworkEvent enum for typed event handling
    namespace.rs      # Network namespace utilities
    stats.rs          # Statistics tracking (StatsSnapshot, StatsTracker)
    tc.rs             # TC typed builders (NetemConfig, FqCodelConfig, HtbConfig, TbfConfig, PrioConfig, SfqConfig, RedConfig, PieConfig, DrrConfig, QfqConfig, HfscConfig, MqprioConfig, TaprioConfig, EtfConfig, PlugConfig, etc.)
    tc_options.rs     # TC options parsing (netem loss models, etc.)
    filter.rs         # TC filter builders (U32Filter, FlowerFilter, MatchallFilter, FwFilter, BpfFilter, BasicFilter, CgroupFilter, RouteFilter, FlowFilter)
    action.rs         # TC action builders (GactAction, MirredAction, PoliceAction, VlanAction, SkbeditAction, NatAction, TunnelKeyAction, ConnmarkAction, CsumAction, SampleAction, CtAction, PeditAction, ActionList)
    link.rs           # Link type builders (DummyLink, VethLink, BridgeLink, VlanLink, VxlanLink, MacvlanLink, MacvtapLink, IpvlanLink, IfbLink, GeneveLink, BareudpLink, NetkitLink, NlmonLink, VirtWifiLink, VtiLink, Vti6Link, Ip6GreLink, Ip6GretapLink)
    rule.rs           # Routing rule builder (RuleBuilder)
    nexthop.rs        # Nexthop objects and groups (NexthopBuilder, NexthopGroupBuilder) - Linux 5.3+
    mpls.rs           # MPLS routes and encapsulation (MplsEncap, MplsRouteBuilder)
    srv6.rs           # SRv6 routes and encapsulation (Srv6Encap, Srv6LocalBuilder)
    uevent.rs         # KobjectUevent (device hotplug events)
    connector.rs      # Connector (process lifecycle events)
    netfilter.rs      # Netfilter (connection tracking)
    xfrm.rs           # XFRM (IPsec SA/SP management)
    fib_lookup.rs     # FIB route lookups
    audit.rs          # Linux Audit subsystem
    selinux.rs        # SELinux event notifications
    config/           # Declarative network configuration (NetworkConfig, diff, apply)
    ratelimit.rs      # High-level rate limiting DSL (RateLimiter, PerHostLimiter)
    diagnostics.rs    # Network diagnostics (Diagnostics, DiagnosticReport, Issue, Bottleneck)
    genl/             # Generic Netlink (GENL) support
      mod.rs          # GENL module entry, control family constants
      header.rs       # GenlMsgHdr (4-byte GENL header)
      connection.rs   # Connection<Generic> with family ID resolution
      wireguard/      # WireGuard GENL configuration
        mod.rs        # WireGuard constants and attribute types
        types.rs      # WgDevice, WgPeer, AllowedIp, builders
        connection.rs # Connection<Wireguard> API
      macsec/         # MACsec (IEEE 802.1AE) GENL configuration
        mod.rs        # MACsec constants and attribute types
        types.rs      # MacsecDevice, MacsecTxSc, MacsecRxSc, MacsecSaBuilder
        connection.rs # Connection<Macsec> API
      mptcp/          # MPTCP (Multipath TCP) GENL configuration
        mod.rs        # MPTCP PM constants
        types.rs      # MptcpEndpoint, MptcpLimits, MptcpFlags, MptcpEndpointBuilder
        connection.rs # Connection<Mptcp> API
    messages/         # Strongly-typed message structs
    types/            # RTNetlink message structures (link, addr, route, neigh, rule, tc)
  util/               # Shared utilities (always available)
    addr.rs           # IP/MAC address parsing and formatting
    ifname.rs         # Interface name/index conversion
    names.rs          # Protocol/scope/table name resolution
    parse.rs          # Rate/size/time string parsing
  sockdiag/           # Socket diagnostics (feature: sockdiag)
  tuntap/             # TUN/TAP device management (feature: tuntap)
  tc/                 # Traffic control utilities (feature: tc)
  output/             # Output formatting (feature: output)
```

### Feature Flags

| Feature | Description |
|---------|-------------|
| `sockdiag` | Socket diagnostics via NETLINK_SOCK_DIAG |
| `tuntap` | TUN/TAP device management |
| `tc` | Traffic control utilities (qdisc builders, handle parsing) |
| `output` | JSON/text output formatting |
| `namespace_watcher` | Filesystem-based namespace watching via inotify |
| `full` | All features enabled |

### Binaries

- `bins/ip/` - Network configuration (depends on `nlink` with `output` feature)
- `bins/tc/` - Traffic control (depends on `nlink` with `tc`, `output` features)
- `bins/ss/` - Socket statistics (depends on `nlink` with `sockdiag`, `output` features)

## Crate Root Re-exports

Common types are re-exported at the crate root for convenience:

```rust
// Instead of:
use nlink::netlink::{Connection, Error, Protocol, Result, RtnetlinkGroup};
use nlink::netlink::events::NetworkEvent;
use nlink::netlink::stream::{EventSource, EventSubscription, OwnedEventStream};
use nlink::netlink::messages::TcMessage;

// You can use:
use nlink::{Connection, Error, Protocol, Result, RtnetlinkGroup};
use nlink::NetworkEvent;
use nlink::{EventSource, EventSubscription, OwnedEventStream};
use nlink::{TcMessage, QdiscMessage, ClassMessage, FilterMessage};
```

Type aliases for TC messages improve discoverability:
- `QdiscMessage` = `TcMessage`
- `ClassMessage` = `TcMessage`  
- `FilterMessage` = `TcMessage`

Stream types for event monitoring:
- `EventSource` - Trait for protocols that emit events
- `EventSubscription<'a, P>` - Borrowed stream from `conn.events()`
- `OwnedEventStream<P>` - Owned stream from `conn.into_events()`

Multicast group subscription:
- `RtnetlinkGroup` - Strongly-typed enum for rtnetlink multicast groups

## Key Patterns

**High-level queries (preferred for library use):**
```rust
use nlink::netlink::{Connection, Protocol};

let conn = Connection::new(Protocol::Route)?;

// Query interfaces
let links = conn.get_links().await?;
let eth0 = conn.get_link_by_name("eth0").await?;

// Use name_or() helper for cleaner interface name access
for link in &links {
    println!("{}: {}", link.ifindex(), link.name_or("?"));
}

// Build ifindex -> name map for resolving routes/addresses/neighbors
let names = conn.get_interface_names().await?;

// Query addresses
let addrs = conn.get_addresses().await?;
let eth0_addrs = conn.get_addresses_for("eth0").await?;

// Query routes and resolve interface names
let routes = conn.get_routes().await?;
for route in &routes {
    let dev = route.oif
        .and_then(|idx| names.get(&idx))
        .map(|s| s.as_str())
        .unwrap_or("-");
    println!("{:?} via {}", route.destination, dev);
}

// Query TC
let qdiscs = conn.get_qdiscs().await?;
let classes = conn.get_classes_for("eth0").await?;

// Query routing rules
let rules = conn.get_rules().await?;
let ipv4_rules = conn.get_rules_for_family(libc::AF_INET as u8).await?;
```

**Link state management:**
```rust
use nlink::netlink::{Connection, Protocol};

let conn = Connection::new(Protocol::Route)?;

// Bring interface up/down
conn.set_link_up("eth0").await?;
conn.set_link_down("eth0").await?;

// Set MTU
conn.set_link_mtu("eth0", 9000).await?;

// Delete a virtual interface
conn.del_link("veth0").await?;
```

**Declarative network configuration:**
```rust
use nlink::netlink::{Connection, Route};
use nlink::netlink::config::{NetworkConfig, ApplyOptions};

let conn = Connection::<Route>::new()?;

// Define desired network state declaratively
let config = NetworkConfig::new()
    // Add interfaces with optional configuration
    .link("br0", |l| l.bridge())
    .link("veth0", |l| l.veth("veth1").master("br0").up())
    .link("dummy0", |l| l.dummy().mtu(9000))
    
    // Add addresses
    .address("br0", "192.168.1.1/24")?
    .address("br0", "2001:db8::1/64")?
    
    // Add routes
    .route("10.0.0.0/8", |r| r.via("192.168.1.254").dev("br0"))?
    .route("default", |r| r.via("192.168.1.1"))?
    
    // Add qdiscs
    .qdisc("veth0", |q| q.netem().delay_ms(100).loss_percent(1.0));

// Compute diff between current and desired state
let diff = config.diff(&conn).await?;
println!("Links to add: {:?}", diff.links_to_add);
println!("Addresses to add: {:?}", diff.addresses_to_add);

// Apply configuration (creates, modifies, or removes as needed)
let result = config.apply(&conn).await?;
println!("Changes made: {}", result.changes_made);

// Dry-run mode to preview changes without applying
let result = config.apply_with_options(&conn, ApplyOptions {
    dry_run: true,
    ..Default::default()
}).await?;
for line in result.summary() {
    println!("{}", line);
}

// The apply is idempotent - running again produces no changes
let result = config.apply(&conn).await?;
assert_eq!(result.changes_made, 0);
```

**Declarative config link types:**
```rust
use nlink::netlink::config::NetworkConfig;

let config = NetworkConfig::new()
    // Bridge with VLAN filtering
    .link("br0", |l| l.bridge().vlan_filtering(true))
    
    // Veth pair
    .link("veth0", |l| l.veth("veth1"))
    
    // VLAN on parent interface
    .link("eth0.100", |l| l.vlan("eth0", 100))
    
    // VXLAN tunnel
    .link("vxlan0", |l| l.vxlan(100).local("10.0.0.1".parse()?).dstport(4789))
    
    // Bond with mode and options
    .link("bond0", |l| l.bond().mode(BondMode::ActiveBackup))
    
    // Macvlan
    .link("macvlan0", |l| l.macvlan("eth0").mode(MacvlanMode::Bridge));
```

**Declarative config qdisc types:**
```rust
use nlink::netlink::config::NetworkConfig;

let config = NetworkConfig::new()
    // Netem for network emulation
    .qdisc("eth0", |q| q
        .netem()
        .delay_ms(100)
        .jitter_ms(10)
        .loss_percent(0.5)
        .duplicate_percent(0.1)
        .reorder_percent(1.0))
    
    // HTB for hierarchical traffic shaping
    .qdisc("eth0", |q| q.htb().default_class(0x10))
    
    // FQ_Codel for fair queueing
    .qdisc("eth0", |q| q.fq_codel().target_us(5000).interval_us(100000))
    
    // TBF for token bucket rate limiting
    .qdisc("eth0", |q| q.tbf().rate(1_000_000).burst(32000))
    
    // Prio for priority queueing
    .qdisc("eth0", |q| q.prio().bands(3))
    
    // SFQ for stochastic fair queueing
    .qdisc("eth0", |q| q.sfq().perturb(10));
```

**High-level rate limiting (RateLimiter):**
```rust
use nlink::netlink::{Connection, Route};
use nlink::netlink::ratelimit::RateLimiter;
use std::time::Duration;

let conn = Connection::<Route>::new()?;

// Simple rate limiting - egress and ingress
RateLimiter::new("eth0")
    .egress("100mbit")?       // Limit upload to 100 Mbps
    .ingress("1gbit")?        // Limit download to 1 Gbps
    .burst_to("150mbit")?     // Allow bursting to 150 Mbps
    .latency(Duration::from_millis(20))  // AQM latency target
    .apply(&conn)
    .await?;

// Egress only with bytes-per-second values
RateLimiter::new("eth0")
    .egress_bps(12_500_000)   // 100 Mbps = 12.5 MB/s
    .burst_size("64kb")?      // 64 KB burst buffer
    .apply(&conn)
    .await?;

// Remove all rate limits
RateLimiter::new("eth0")
    .remove(&conn)
    .await?;
```

**Per-host rate limiting (PerHostLimiter):**
```rust
use nlink::netlink::{Connection, Route};
use nlink::netlink::ratelimit::PerHostLimiter;
use std::time::Duration;

let conn = Connection::<Route>::new()?;

// Per-IP and per-subnet rate limiting
PerHostLimiter::new("eth0", "10mbit")?  // Default rate for unmatched traffic
    .limit_ip("192.168.1.100".parse()?, "100mbit")?  // VIP client
    .limit_subnet("10.0.0.0/8", "50mbit")?           // Internal network
    .limit_port(80, "500mbit")?                       // HTTP traffic
    .latency(Duration::from_millis(5))
    .apply(&conn)
    .await?;

// Remove per-host limits
PerHostLimiter::new("eth0", "10mbit")?
    .remove(&conn)
    .await?;
```

**Network diagnostics (Diagnostics):**
```rust
use nlink::netlink::{Connection, Route};
use nlink::netlink::diagnostics::{Diagnostics, DiagnosticsConfig, Severity, IssueCategory};

let conn = Connection::<Route>::new()?;
let diag = Diagnostics::new(conn);

// Full diagnostic scan of all interfaces
let report = diag.scan().await?;
for iface in &report.interfaces {
    println!("{}: {} bps, {} drops", 
        iface.name, iface.rates.tx_bps, iface.stats.tx_dropped());
    if let Some(tc) = &iface.tc {
        println!("  TC: {} ({} drops)", tc.qdisc, tc.drops);
    }
}

// Print all detected issues
for issue in &report.issues {
    println!("[{:?}] {}: {}", issue.severity, issue.category, issue.message);
}

// Scan specific interface
let eth0 = diag.scan_interface("eth0").await?;
println!("eth0 MTU: {:?}", eth0.mtu);

// Check connectivity to a destination
let report = diag.check_connectivity("8.8.8.8".parse()?).await?;
if !report.issues.is_empty() {
    println!("Connectivity issues:");
    for issue in &report.issues {
        println!("  - {}", issue.message);
    }
}
if let Some(route) = &report.route {
    println!("Route: {} via {:?}", route.destination, report.gateway);
}

// Find bottleneck in the system
if let Some(bottleneck) = diag.find_bottleneck().await? {
    println!("Bottleneck: {} ({:?})", bottleneck.location, bottleneck.bottleneck_type);
    println!("  Drop rate: {:.2}%", bottleneck.drop_rate * 100.0);
    println!("  Recommendation: {}", bottleneck.recommendation);
}

// Custom configuration for stricter thresholds
let config = DiagnosticsConfig {
    packet_loss_threshold: 0.001,  // 0.1% packet loss triggers warning
    error_rate_threshold: 0.0001,  // 0.01% error rate triggers warning
    qdisc_drop_threshold: 0.001,   // 0.1% qdisc drop rate triggers warning
    skip_loopback: true,           // Skip lo interface
    skip_down: false,              // Include down interfaces
    ..Default::default()
};
let diag = Diagnostics::with_config(conn, config);

// Real-time issue monitoring
use tokio_stream::StreamExt;
let mut issues = diag.watch().await?;
while let Some(issue) = issues.next().await {
    let issue = issue?;
    println!("[{:?}] {}", issue.severity, issue.message);
}
```

**Network namespace operations:**
```rust
use nlink::netlink::{Connection, Route, Generic};
use nlink::netlink::namespace;

// Connect to a named namespace (created via `ip netns add myns`)
// Functions are generic over protocol type
let conn: Connection<Route> = namespace::connection_for("myns")?;
let links = conn.get_links().await?;

// Connect to a container's namespace by PID
let conn: Connection<Route> = namespace::connection_for_pid(container_pid)?;

// Or use a path directly
let conn: Connection<Route> = namespace::connection_for_path("/proc/1234/ns/net")?;

// Generic connections work too (e.g., for WireGuard in a namespace)
let genl: Connection<Generic> = namespace::connection_for("myns")?;

// List available namespaces
for ns in namespace::list()? {
    println!("Namespace: {}", ns);
}
```

**Parsing TC options:**
```rust
use nlink::netlink::tc_options::{parse_qdisc_options, QdiscOptions};

for qdisc in &qdiscs {
    if let Some(opts) = parse_qdisc_options(qdisc) {
        match opts {
            QdiscOptions::FqCodel(fq) => println!("target={}us", fq.target_us),
            QdiscOptions::Htb(htb) => println!("default={:x}", htb.default_class),
            _ => {}
        }
    }
}
```

**Reading netem configuration (detecting existing TC settings):**
```rust
use nlink::netlink::{Connection, Protocol};
use nlink::netlink::tc_options::QdiscOptions;

let conn = Connection::new(Protocol::Route)?;
let qdiscs = conn.get_qdiscs_for("eth0").await?;

for qdisc in &qdiscs {
    // Quick checks using convenience methods
    if qdisc.is_netem() && qdisc.is_root() {
        println!("Found root netem qdisc");
    }

    // Get netem options with full details
    if let Some(netem) = qdisc.netem_options() {
        // Time values as Option<Duration>
        if let Some(delay) = netem.delay() {
            print!("delay={:?}", delay);
            if let Some(jitter) = netem.jitter() {
                print!(" +/- {:?}", jitter);
            }
            println!();
        }
        
        // Percentages as Option<f64>
        if let Some(loss) = netem.loss() {
            println!("loss={:.2}%", loss);
        }
        if let Some(dup) = netem.duplicate() {
            println!("duplicate={:.2}%", dup);
        }
        if let Some(reorder) = netem.reorder() {
            println!("reorder={:.2}%, gap={}", reorder, netem.gap);
        }
        if let Some(corrupt) = netem.corrupt() {
            println!("corrupt={:.2}%", corrupt);
        }
        
        // Rate limiting as Option<u64>
        if let Some(rate) = netem.rate_bps() {
            println!("rate={} bytes/sec", rate);
            println!("packet_overhead={}, cell_size={}", netem.packet_overhead(), netem.cell_size());
        }
        
        // ECN and slot-based transmission
        println!("ecn={}", netem.ecn());
        if let Some(slot) = netem.slot() {
            println!("slot: min={}ns, max={}ns", slot.min_delay_ns, slot.max_delay_ns);
        }
        
        // Loss models (Gilbert-Intuitive or Gilbert-Elliot)
        if let Some(loss_model) = netem.loss_model() {
            use nlink::netlink::tc_options::NetemLossModel;
            match loss_model {
                NetemLossModel::GilbertIntuitive { p13, p31, p32, p14, p23 } => {
                    println!("4-state loss model: p13={}, p31={}", p13, p31);
                }
                NetemLossModel::GilbertElliot { p, r, h, k1 } => {
                    println!("2-state loss model: p={}, r={}, h={}", p, r, h);
                }
            }
        }
    }

}
```

**Applying netem configuration (convenience methods):**
```rust
use nlink::netlink::{Connection, Protocol};
use nlink::netlink::tc::NetemConfig;
use std::time::Duration;

let conn = Connection::new(Protocol::Route)?;

// Apply netem to an interface (replaces any existing root qdisc)
let netem = NetemConfig::new()
    .delay(Duration::from_millis(100))
    .jitter(Duration::from_millis(10))
    .loss(1.0)
    .build();
conn.apply_netem("eth0", netem).await?;

// Or by interface index (for namespace operations)
conn.apply_netem_by_index(ifindex, netem).await?;

// Remove netem (restores default qdisc)
conn.remove_netem("eth0").await?;
conn.remove_netem_by_index(ifindex).await?;

// Look up a qdisc by handle
if let Some(qdisc) = conn.get_qdisc_by_handle("eth0", "1:").await? {
    println!("Found qdisc: {}", qdisc.kind().unwrap_or("?"));
}
```

**TC statistics and rate monitoring:**
```rust
use nlink::netlink::{Connection, Protocol};

let conn = Connection::new(Protocol::Route)?;
let qdiscs = conn.get_qdiscs_for("eth0").await?;

for qdisc in &qdiscs {
    // Real-time rate from kernel's rate estimator
    println!("Rate: {} bps, {} pps", qdisc.bps(), qdisc.pps());
    
    // Queue statistics
    println!("Queue: {} packets, {} bytes backlog", qdisc.qlen(), qdisc.backlog());
    println!("Drops: {}, overlimits: {}", qdisc.drops(), qdisc.overlimits());
}

// Calculate deltas between samples
let prev = qdiscs[0].stats_basic.unwrap();
// ... wait ...
let curr = conn.get_qdiscs_for("eth0").await?[0].stats_basic.unwrap();
let delta = curr.delta(&prev);
println!("Transferred: {} bytes, {} packets", delta.bytes, delta.packets);
```

**TC class management:**
```rust
use nlink::netlink::{Connection, Route};
use nlink::netlink::tc::HtbQdiscConfig;

let conn = Connection::<Route>::new()?;

// First add an HTB qdisc
let htb = HtbQdiscConfig::new().default_class(0x10).build();
conn.add_qdisc_full("eth0", "root", Some("1:"), htb).await?;

// Add classes with rate limiting
conn.add_class("eth0", "1:0", "1:1", "htb", 
    &["rate", "100mbit", "ceil", "1gbit"]).await?;
conn.add_class("eth0", "1:1", "1:10", "htb", 
    &["rate", "10mbit", "ceil", "100mbit"]).await?;

// Query classes
let classes = conn.get_classes_for("eth0").await?;
for class in &classes {
    println!("Class {:x}: {} bytes, {} packets", 
        class.handle(), class.bytes(), class.packets());
}

// Change class parameters
conn.change_class("eth0", "1:0", "1:10", "htb",
    &["rate", "20mbit", "ceil", "100mbit"]).await?;

// Replace class (add or update)
conn.replace_class("eth0", "1:0", "1:10", "htb",
    &["rate", "15mbit", "ceil", "100mbit"]).await?;

// Delete class
conn.del_class("eth0", "1:0", "1:10").await?;

// Namespace-aware operations use *_by_index variants
let link = conn.get_link_by_name("eth0").await?;
conn.add_class_by_index(link.ifindex(), "1:0", "1:20", "htb",
    &["rate", "5mbit"]).await?;
```

**Typed HTB class configuration (preferred):**
```rust
use nlink::netlink::{Connection, Route};
use nlink::netlink::tc::{HtbQdiscConfig, HtbClassConfig};

let conn = Connection::<Route>::new()?;

// First add HTB qdisc
let htb = HtbQdiscConfig::new().default_class(0x30).build();
conn.add_qdisc_full("eth0", "root", Some("1:"), htb).await?;

// Add root class (total bandwidth) - typed builder
conn.add_class_config("eth0", "1:0", "1:1",
    HtbClassConfig::new("1gbit")?
        .ceil("1gbit")?
        .build()
).await?;

// Add child classes with priorities
conn.add_class_config("eth0", "1:1", "1:10",
    HtbClassConfig::new("100mbit")?
        .ceil("500mbit")?
        .prio(1)              // High priority
        .build()
).await?;

conn.add_class_config("eth0", "1:1", "1:20",
    HtbClassConfig::new("200mbit")?
        .ceil("800mbit")?
        .prio(2)
        .build()
).await?;

// Best effort class
conn.add_class_config("eth0", "1:1", "1:30",
    HtbClassConfig::new("50mbit")?
        .prio(3)
        .build()
).await?;

// Alternative: from_bps for programmatic rate values
let rate_bps = 125_000_000; // 1 Gbps in bits/sec
conn.add_class_config("eth0", "1:1", "1:40",
    HtbClassConfig::from_bps(rate_bps)
        .ceil_bps(rate_bps * 2)
        .burst_bytes(64 * 1024)  // 64KB burst
        .quantum(1500)
        .mtu(9000)               // Jumbo frames
        .build()
).await?;

// Change/replace also have typed variants
conn.change_class_config("eth0", "1:1", "1:10",
    HtbClassConfig::new("150mbit")?
        .ceil("600mbit")?
        .build()
).await?;

conn.replace_class_config("eth0", "1:1", "1:10",
    HtbClassConfig::new("200mbit")?
        .ceil("800mbit")?
        .build()
).await?;

// Namespace-aware with *_by_index variants
let link = conn.get_link_by_name("eth0").await?;
conn.add_class_config_by_index(link.ifindex(), "1:1", "1:50",
    HtbClassConfig::new("10mbit")?.build()
).await?;
```

**Link statistics tracking:**
```rust
use nlink::netlink::stats::{StatsSnapshot, StatsTracker};

let mut tracker = StatsTracker::new();
loop {
    let links = conn.get_links().await?;
    let snapshot = StatsSnapshot::from_links(&links);
    if let Some(rates) = tracker.update(snapshot) {
        for (idx, r) in &rates.links {
            println!("idx {}: {:.2} Mbps", idx, r.total_bps() / 1_000_000.0);
        }
    }
    tokio::time::sleep(Duration::from_secs(1)).await;
}
```

**Monitoring events (Stream API):**

The `Connection` type implements `EventSource` trait, providing `events()` and
`into_events()` methods that return `Stream` implementations compatible
with `tokio-stream` combinators and `StreamMap` for multi-namespace monitoring.

```rust
use nlink::netlink::{Connection, Route, RtnetlinkGroup, NetworkEvent};
use tokio_stream::StreamExt;

// Create connection and subscribe to multicast groups
let mut conn = Connection::<Route>::new()?;
conn.subscribe(&[RtnetlinkGroup::Link, RtnetlinkGroup::Ipv4Addr, RtnetlinkGroup::Tc])?;

// Or subscribe to all common groups at once
conn.subscribe_all()?;

// Get event stream (borrowed)
let mut events = conn.events();

while let Some(result) = events.next().await {
    let event = result?;
    match event {
        NetworkEvent::NewLink(link) => println!("Link: {}", link.name.unwrap_or_default()),
        NetworkEvent::NewAddress(addr) => println!("Addr: {:?}", addr.address),
        NetworkEvent::NewQdisc(tc) => println!("Qdisc: {}", tc.kind().unwrap_or("?")),
        _ => {}
    }
}
```

**RtnetlinkGroup enum for type-safe subscription:**
```rust
use nlink::netlink::RtnetlinkGroup;

// Available groups:
// RtnetlinkGroup::Link       - Interface state changes
// RtnetlinkGroup::Ipv4Addr   - IPv4 address changes
// RtnetlinkGroup::Ipv6Addr   - IPv6 address changes
// RtnetlinkGroup::Ipv4Route  - IPv4 routing table changes
// RtnetlinkGroup::Ipv6Route  - IPv6 routing table changes
// RtnetlinkGroup::Neigh      - Neighbor (ARP/NDP) cache changes
// RtnetlinkGroup::Tc         - Traffic control changes
// RtnetlinkGroup::NsId       - Namespace ID changes
// RtnetlinkGroup::Ipv4Rule   - IPv4 policy routing rules
// RtnetlinkGroup::Ipv6Rule   - IPv6 policy routing rules
```

**Multi-namespace event monitoring:**
```rust
use nlink::netlink::{Connection, Route, RtnetlinkGroup, namespace};
use tokio_stream::{StreamExt, StreamMap};

let mut streams = StreamMap::new();

// Monitor default namespace
let mut conn = Connection::<Route>::new()?;
conn.subscribe_all()?;
streams.insert("default", conn.into_events());

// Monitor named namespaces
let mut conn_ns1 = namespace::connection_for("ns1")?;
conn_ns1.subscribe_all()?;
streams.insert("ns1", conn_ns1.into_events());

// Events include namespace key
while let Some((ns, result)) = streams.next().await {
    let event = result?;
    println!("[{}] {:?}", ns, event);
}
```

**Namespace-aware event monitoring (single namespace):**
```rust
use nlink::netlink::{Connection, Route, RtnetlinkGroup, namespace};
use tokio_stream::StreamExt;

// Monitor events in a named namespace
let mut conn = namespace::connection_for("myns")?;
conn.subscribe(&[RtnetlinkGroup::Link, RtnetlinkGroup::Tc])?;
let mut events = conn.events();

// Or by PID (e.g., container process)
let mut conn = namespace::connection_for_pid(container_pid)?;
conn.subscribe(&[RtnetlinkGroup::Link])?;

// Or by path
let mut conn = Connection::<Route>::new_in_namespace_path("/proc/1234/ns/net")?;
conn.subscribe_all()?;

while let Some(result) = events.next().await {
    let event = result?;
    println!("{:?}", event);
}
```

**Watching namespace creation/deletion (inotify-based, feature: namespace_watcher):**
```rust
use nlink::netlink::{NamespaceWatcher, NamespaceEvent};

// Watch for namespace changes in /var/run/netns/
let mut watcher = NamespaceWatcher::new().await?;

while let Some(event) = watcher.recv().await? {
    match event {
        NamespaceEvent::Created { name } => println!("Namespace created: {}", name),
        NamespaceEvent::Deleted { name } => println!("Namespace deleted: {}", name),
        NamespaceEvent::DirectoryCreated => println!("/var/run/netns created"),
        NamespaceEvent::DirectoryDeleted => println!("/var/run/netns deleted"),
    }
}
```

**Atomically list and watch namespaces (no race condition):**
```rust
use nlink::netlink::{NamespaceWatcher, NamespaceEvent};

// Get current namespaces and start watching in one operation
let (existing, mut watcher) = NamespaceWatcher::list_and_watch().await?;
println!("Existing namespaces: {:?}", existing);

// Now receive only new events (no duplicates of existing namespaces)
while let Some(event) = watcher.recv().await? {
    println!("{:?}", event);
}
```

**Watching namespace ID events (netlink-based, always available):**
```rust
use nlink::netlink::{NamespaceEventSubscriber, NamespaceNetlinkEvent};

// Subscribe to RTM_NEWNSID/RTM_DELNSID kernel events
let mut sub = NamespaceEventSubscriber::new().await?;

while let Some(event) = sub.recv().await? {
    match event {
        NamespaceNetlinkEvent::NewNsId { nsid, pid, fd } => {
            println!("New NSID {}: pid={:?}, fd={:?}", nsid, pid, fd);
        }
        NamespaceNetlinkEvent::DelNsId { nsid } => {
            println!("Deleted NSID {}", nsid);
        }
    }
}
```

**Query namespace ID:**
```rust
use nlink::netlink::{Connection, Protocol};
use std::os::fd::AsRawFd;

let conn = Connection::new(Protocol::Route)?;

// Get NSID for a namespace by file descriptor
let ns_file = std::fs::File::open("/var/run/netns/myns")?;
let nsid = conn.get_nsid(ns_file.as_raw_fd()).await?;
println!("NSID: {}", nsid);

// Or get NSID for a process's namespace
let nsid = conn.get_nsid_for_pid(1234).await?;
```

**EventSource trait (unified Stream API for all protocols):**

Protocols that support event monitoring implement the `EventSource` trait,
providing a unified Stream-based API via `events()` (borrowed) and
`into_events()` (owned).

```rust
use nlink::netlink::{Connection, KobjectUevent, Connector, SELinux};
use tokio_stream::StreamExt;

// Device hotplug events
let conn = Connection::<KobjectUevent>::new()?;
let mut events = conn.events();  // Borrows connection
while let Some(event) = events.next().await {
    let uevent = event?;
    println!("[{}] {}", uevent.action, uevent.devpath);
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

// Owned stream (consumes connection)
let conn = Connection::<KobjectUevent>::new()?;
let mut stream = conn.into_events();
while let Some(event) = stream.next().await {
    println!("{:?}", event?);
}
// Recover connection if needed
let conn = stream.into_connection();
```

**Combining multiple event sources with tokio::select!:**
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

**Namespace-aware TC operations (using ifindex):**
```rust
use nlink::netlink::{Connection, Route, namespace, tc::NetemConfig};
use std::time::Duration;

// For namespace operations, use *_by_index methods to avoid
// reading /sys/class/net/ from the host namespace
let conn: Connection<Route> = namespace::connection_for("myns")?;
let link = conn.get_link_by_name("eth0").await?;

let netem = NetemConfig::new()
    .delay(Duration::from_millis(100))
    .jitter(Duration::from_millis(10))
    .loss(1.0)
    .build();

// Use ifindex instead of device name
conn.add_qdisc_by_index(link.ifindex(), netem).await?;

// All TC methods have *_by_index variants:
// - add_qdisc_by_index / add_qdisc_by_index_full
// - del_qdisc_by_index / del_qdisc_by_index_full
// - replace_qdisc_by_index / replace_qdisc_by_index_full
// - change_qdisc_by_index / change_qdisc_by_index_full
```

**Adding TC filters:**
```rust
use nlink::netlink::{Connection, Protocol};
use nlink::netlink::filter::{U32Filter, FlowerFilter, MatchallFilter};
use std::net::Ipv4Addr;

let conn = Connection::new(Protocol::Route)?;

// U32 filter to match destination port 80
let filter = U32Filter::new()
    .classid("1:10")
    .match_dst_port(80)
    .build();
conn.add_filter("eth0", "1:", filter).await?;

// Flower filter to match TCP traffic to 10.0.0.0/8
let filter = FlowerFilter::new()
    .classid("1:20")
    .ip_proto_tcp()
    .dst_ipv4(Ipv4Addr::new(10, 0, 0, 0), 8)
    .build();
conn.add_filter("eth0", "1:", filter).await?;

// Matchall filter for all traffic
let filter = MatchallFilter::new()
    .classid("1:30")
    .build();
conn.add_filter("eth0", "1:", filter).await?;

// Replace a filter (create or update)
conn.replace_filter("eth0", "1:", filter).await?;

// Change an existing filter (fails if not exists)
conn.change_filter("eth0", "1:", 0x0800, 100, filter).await?;

// Delete/flush filters
conn.del_filter("eth0", "1:", 0x0800, 100).await?;
conn.flush_filters("eth0", "1:").await?;
```

**Additional filter types (cgroup, route, flow):**
```rust
use nlink::netlink::filter::{CgroupFilter, RouteFilter, FlowFilter, FlowKey};
use nlink::netlink::action::{GactAction, ActionList};

// Cgroup filter - matches based on cgroup membership
let cgroup = CgroupFilter::new()
    .with_action(GactAction::drop());
conn.add_filter("eth0", "1:", cgroup).await?;

// Route filter - classifies based on routing realm
let route = RouteFilter::new()
    .to_realm(10)
    .from_realm(5)
    .classid(0x10010);  // 1:10
conn.add_filter("eth0", "1:", route).await?;

// Flow filter - multi-key hashing for load balancing
let flow = FlowFilter::new()
    .key(FlowKey::Src)              // Source IP
    .key(FlowKey::Dst)              // Destination IP
    .key(FlowKey::Proto)            // Protocol
    .key(FlowKey::NfctSrc)          // Conntrack original source
    .divisor(256)                    // Hash table size
    .baseclass(0x10001);            // Base class 1:1
conn.add_filter("eth0", "1:", flow).await?;

// Flow keys available: Src, Dst, Proto, ProtoSrc, ProtoDst, Iif,
// Priority, Mark, NfctSrc, NfctDst, NfctProtoSrc, NfctProtoDst,
// RtClassId, SkUid, SkGid, VlanTag, RxHash
```

**TC filter chains (Linux 4.1+):**
```rust
use nlink::netlink::{Connection, Route};
use nlink::netlink::filter::{FlowerFilter, MatchallFilter};
use nlink::netlink::action::GactAction;
use nlink::netlink::tc::IngressConfig;

let conn = Connection::<Route>::new()?;

// Add ingress qdisc
conn.add_qdisc("eth0", IngressConfig::new()).await?;

// Create filter chains for organizing filters
conn.add_tc_chain("eth0", "ingress", 0).await?;
conn.add_tc_chain("eth0", "ingress", 100).await?;

// Add filter in chain 0 that jumps to chain 100 for TCP traffic
let filter = FlowerFilter::new()
    .chain(0)
    .ip_proto_tcp()
    .goto_chain(100)
    .build();
conn.add_filter("eth0", "ingress", filter).await?;

// Add filter in chain 100 to drop traffic to port 80
let filter = FlowerFilter::new()
    .chain(100)
    .ip_proto_tcp()
    .dst_port(80)
    .build();
conn.add_filter("eth0", "ingress", filter).await?;

// List chains
let chains = conn.get_tc_chains("eth0", "ingress").await?;
for chain in chains {
    println!("Chain: {}", chain);
}

// Delete a chain (filters must be removed first)
conn.del_tc_chain("eth0", "ingress", 100).await?;

// Goto chain action can also be used with GactAction
let goto = GactAction::goto_chain(100);
```

**Adding TC actions:**
```rust
use nlink::netlink::{Connection, Protocol};
use nlink::netlink::action::{GactAction, MirredAction, PoliceAction, ActionList};
use nlink::netlink::filter::MatchallFilter;

let conn = Connection::new(Protocol::Route)?;

// Drop action
let drop = GactAction::drop();

// Mirror/redirect to another interface
let mirror = MirredAction::mirror_egress("eth1");
let redirect = MirredAction::redirect_egress("eth1");

// Police action for rate limiting
let police = PoliceAction::new()
    .rate(1_000_000)  // 1 Mbps
    .burst(10000)
    .exceed_drop()
    .build();

// Combine multiple actions in an ActionList
let actions = ActionList::new()
    .with(police)
    .with(GactAction::pass());

// Attach actions to a filter
let filter = MatchallFilter::new()
    .actions(actions)
    .build();
conn.add_filter("eth0", "ingress", filter).await?;
```

**Creating link types:**
```rust
use nlink::netlink::{Connection, Protocol};
use nlink::netlink::link::{
    DummyLink, VethLink, BridgeLink, VlanLink, VxlanLink, 
    MacvlanLink, MacvtapLink, IpvlanLink, IfbLink, GeneveLink, 
    BareudpLink, NetkitLink, MacvlanMode, NetkitMode, NetkitPolicy,
};
use std::net::Ipv4Addr;

let conn = Connection::new(Protocol::Route)?;

// Dummy interface
conn.add_link(DummyLink::new("dummy0")).await?;

// Veth pair
conn.add_link(VethLink::new("veth0", "veth1")).await?;

// IFB (Intermediate Functional Block) for ingress shaping
conn.add_link(IfbLink::new("ifb0")).await?;

// Macvtap for VM networking
conn.add_link(
    MacvtapLink::new("macvtap0", "eth0")
        .mode(MacvlanMode::Bridge)
).await?;

// Geneve tunnel
conn.add_link(
    GeneveLink::new("geneve0", 100)
        .remote(Ipv4Addr::new(192, 168, 1, 100))
        .port(6081)
        .ttl(64)
).await?;

// Bareudp for MPLS encapsulation
conn.add_link(
    BareudpLink::new("bareudp0", 6635, 0x8847)  // MPLS unicast
).await?;

// Netkit (BPF-optimized veth)
conn.add_link(
    NetkitLink::new("nk0", "nk1")
        .mode(NetkitMode::L3)
        .policy(NetkitPolicy::Forward)
).await?;

// Nlmon (Netlink monitor interface for debugging)
conn.add_link(NlmonLink::new("nlmon0")).await?;

// VirtWifi (Virtual WiFi on top of Ethernet)
conn.add_link(VirtWifiLink::new("vwifi0", "eth0")).await?;

// VTI (Virtual Tunnel Interface for route-based IPsec)
conn.add_link(
    VtiLink::new("vti0")
        .local(Ipv4Addr::new(10, 0, 0, 1))
        .remote(Ipv4Addr::new(10, 0, 0, 2))
        .ikey(100)
        .okey(100)
).await?;

// VTI6 (IPv6 Virtual Tunnel Interface)
use std::net::Ipv6Addr;
conn.add_link(
    Vti6Link::new("vti6_0")
        .local("2001:db8::1".parse()?)
        .remote("2001:db8::2".parse()?)
).await?;

// IP6GRE (IPv6 GRE tunnel)
conn.add_link(
    Ip6GreLink::new("ip6gre0")
        .local("2001:db8::1".parse()?)
        .remote("2001:db8::2".parse()?)
        .ttl(64)
).await?;

// IP6GRETAP (Layer 2 IPv6 GRE tunnel for bridging)
conn.add_link(
    Ip6GretapLink::new("ip6gretap0")
        .local("2001:db8::1".parse()?)
        .remote("2001:db8::2".parse()?)
).await?;
```

**NAT and tunnel_key actions:**
```rust
use nlink::netlink::action::{NatAction, TunnelKeyAction, ActionList};
use nlink::netlink::filter::MatchallFilter;
use std::net::Ipv4Addr;

// Source NAT: translate 10.0.0.0/8 to 192.168.1.1
let snat = NatAction::snat(
    Ipv4Addr::new(10, 0, 0, 0),
    Ipv4Addr::new(192, 168, 1, 1),
).prefix(8);

// Destination NAT
let dnat = NatAction::dnat(
    Ipv4Addr::new(192, 168, 1, 1),
    Ipv4Addr::new(10, 0, 0, 1),
);

// Tunnel key set (for VXLAN/Geneve hardware offload)
let tunnel_set = TunnelKeyAction::set()
    .src(Ipv4Addr::new(192, 168, 1, 1))
    .dst(Ipv4Addr::new(192, 168, 1, 2))
    .key_id(100)  // VNI
    .dst_port(4789)
    .ttl(64)
    .no_csum()
    .build();

// Tunnel key release (after decapsulation)
let tunnel_release = TunnelKeyAction::release();

// Attach to a filter
let filter = MatchallFilter::new()
    .actions(ActionList::new().with(snat))
    .build();
conn.add_filter("eth0", "egress", filter).await?;
```

**Extended TC actions (connmark, csum, sample, ct, pedit):**
```rust
use nlink::netlink::action::{
    ConnmarkAction, CsumAction, SampleAction, CtAction, PeditAction,
    ActionList,
};
use nlink::netlink::filter::MatchallFilter;
use std::net::Ipv4Addr;

// Connmark action - save/restore connection marks
let save_mark = ConnmarkAction::save().zone(1);
let restore_mark = ConnmarkAction::restore().zone(1);

// Csum action - recalculate checksums after packet modification
let csum = CsumAction::new()
    .iph()   // IP header checksum
    .tcp()   // TCP checksum
    .udp();  // UDP checksum

// Sample action - sample packets for monitoring (e.g., sFlow)
let sample = SampleAction::new()
    .rate(100)      // Sample 1 in 100 packets
    .group(5)       // PSAMPLE group ID
    .trunc(128);    // Truncate to 128 bytes

// CT action - connection tracking with NAT
let ct = CtAction::commit()
    .zone(1)
    .mark(0x100)
    .nat_src(Ipv4Addr::new(192, 168, 1, 1))  // SNAT to specific IP
    .nat_src_port_range(1024, 65535);        // With port range

// CT with destination NAT
let dnat_ct = CtAction::commit()
    .zone(1)
    .nat_dst(Ipv4Addr::new(10, 0, 0, 1))
    .nat_dst_port(8080);

// Pedit action - edit packet headers
let pedit = PeditAction::new()
    .set_ipv4_src(Ipv4Addr::new(10, 0, 0, 1))
    .set_ipv4_dst(Ipv4Addr::new(10, 0, 0, 2))
    .set_tcp_sport(8080)
    .set_tcp_dport(80)
    .set_eth_src([0x00, 0x11, 0x22, 0x33, 0x44, 0x55])
    .set_eth_dst([0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb]);

// Combine with other actions
let filter = MatchallFilter::new()
    .actions(ActionList::new()
        .with(ct)
        .with(csum))
    .build();
```

**Additional qdisc types:**
```rust
use nlink::netlink::{Connection, Protocol};
use nlink::netlink::tc::{
    RedConfig, PieConfig, IngressConfig, ClsactConfig, PfifoConfig, BfifoConfig,
    DrrConfig, QfqConfig, HfscConfig, MqprioConfig, TaprioConfig, EtfConfig, PlugConfig,
    TaprioSchedEntry,
};
use std::time::Duration;

let conn = Connection::new(Protocol::Route)?;

// RED (Random Early Detection) qdisc
let red = RedConfig::new()
    .limit(100000)
    .min(10000)
    .max(50000)
    .avpkt(1500)
    .ecn()
    .build();
conn.add_qdisc("eth0", red).await?;

// PIE (Proportional Integral controller Enhanced) qdisc
let pie = PieConfig::new()
    .target_ms(15)
    .tupdate_ms(15)
    .alpha(2)
    .beta(20)
    .ecn()
    .build();
conn.add_qdisc("eth0", pie).await?;

// Ingress qdisc (for ingress filtering)
let ingress = IngressConfig::new();
conn.add_qdisc("eth0", ingress).await?;

// Clsact qdisc (for BPF programs, both ingress and egress)
let clsact = ClsactConfig::new();
conn.add_qdisc("eth0", clsact).await?;

// Simple FIFO qdiscs
let pfifo = PfifoConfig::new().limit(1000);
let bfifo = BfifoConfig::new().limit(100000);

// DRR (Deficit Round Robin) classful qdisc
let drr = DrrConfig::new();
conn.add_qdisc_full("eth0", "root", "1:", drr).await?;

// QFQ (Quick Fair Queueing) classful qdisc
let qfq = QfqConfig::new();
conn.add_qdisc_full("eth0", "root", "1:", qfq).await?;

// HFSC (Hierarchical Fair Service Curve) classful qdisc
let hfsc = HfscConfig::new().default_class(0x10);
conn.add_qdisc_full("eth0", "root", "1:", hfsc).await?;

// MQPrio (Multi-Queue Priority) for hardware offload
let mqprio = MqprioConfig::new()
    .num_tc(4)
    .hw_offload(true)
    .map([0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 3, 3, 3, 3, 3, 3])
    .queues([(1, 0), (1, 1), (1, 2), (1, 3)]);
conn.add_qdisc("eth0", mqprio).await?;

// TAPRIO (Time-Aware Priority) for IEEE 802.1Qbv scheduling
let taprio = TaprioConfig::new()
    .num_tc(4)
    .map([0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 3, 3, 3, 3, 3, 3])
    .queues([(1, 0), (1, 1), (1, 2), (1, 3)])
    .base_time(0)
    .sched_entry(TaprioSchedEntry::set_gate(0x1, 250_000))  // TC0 for 250us
    .sched_entry(TaprioSchedEntry::set_gate(0x2, 250_000))  // TC1 for 250us
    .sched_entry(TaprioSchedEntry::set_gate(0x4, 250_000))  // TC2 for 250us
    .sched_entry(TaprioSchedEntry::set_gate(0x8, 250_000)); // TC3 for 250us
conn.add_qdisc("eth0", taprio).await?;

// ETF (Earliest TxTime First) for SO_TXTIME socket option
let etf = EtfConfig::new()
    .clockid_tai()      // Use TAI clock
    .delta_ns(500_000)  // 500us delta
    .deadline_mode()    // Enable deadline mode
    .offload();         // Enable hardware offload
conn.add_qdisc_full("eth0", "1:1", "10:", etf).await?;

// Plug qdisc for packet buffering
let plug = PlugConfig::new().limit(10000);
conn.add_qdisc("eth0", plug).await?;
// Control buffering: conn.plug_buffer(), conn.plug_release_one(), conn.plug_release_indefinite()
```

**Building requests (low-level):**
```rust
use nlink::netlink::{MessageBuilder, Connection};
use nlink::netlink::message::NlMsgType;
use nlink::netlink::types::link::IfInfoMsg;

let mut builder = dump_request(NlMsgType::RTM_GETLINK);
builder.append(&IfInfoMsg::new());
let responses = conn.dump(builder).await?;
```

**Adding TC qdisc with options:**
```rust
use nlink::netlink::types::tc::qdisc::htb::*;
use nlink::netlink::types::tc::{TcMsg, TcaAttr, tc_handle};

let tcmsg = TcMsg::new()
    .with_ifindex(ifindex)
    .with_parent(tc_handle::ROOT)
    .with_handle(tc_handle::make(1, 0));

let mut builder = create_request(NlMsgType::RTM_NEWQDISC);
builder.append(&tcmsg);
builder.append_attr_str(TcaAttr::Kind as u16, "htb");

let options_token = builder.nest_start(TcaAttr::Options as u16);
let glob = TcHtbGlob::new().with_default(0x10);
builder.append_attr(TCA_HTB_INIT, glob.as_bytes());
builder.nest_end(options_token);

conn.request_ack(builder).await?;
```

**Routing rules:**
```rust
use nlink::netlink::{Connection, Protocol};
use nlink::netlink::rule::RuleBuilder;

let conn = Connection::new(Protocol::Route)?;

// Add a routing rule (IPv4, lookup table 100 for traffic from 10.0.0.0/8)
let rule = RuleBuilder::new(libc::AF_INET as u8)
    .table(100)
    .src_prefix("10.0.0.0".parse()?, 8)
    .priority(1000);
conn.add_rule(rule).await?;

// Delete a rule
let rule = RuleBuilder::new(libc::AF_INET as u8)
    .table(100)
    .priority(1000);
conn.del_rule(rule).await?;

// Flush all IPv4 rules (except protected ones)
conn.flush_rules(libc::AF_INET as u8).await?;
```

**Nexthop objects and groups (Linux 5.3+):**
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
        .member(1, 1)  // nexthop 1, weight 1
        .member(2, 1)  // nexthop 2, weight 1
).await?;

// Create weighted multipath (2:1 ratio)
conn.add_nexthop_group(
    NexthopGroupBuilder::new(101)
        .member(1, 2)  // weight 2
        .member(2, 1)  // weight 1
).await?;

// Create resilient group (maintains flow affinity during changes)
conn.add_nexthop_group(
    NexthopGroupBuilder::new(102)
        .resilient()
        .member(1, 1)
        .member(2, 1)
        .buckets(128)
        .idle_timer(120)
).await?;

// Use nexthop group in a route
conn.add_route(
    Ipv4Route::new("10.0.0.0", 8)
        .nexthop_group(100)  // Reference nexthop group ID 100
).await?;

// Query nexthops
let nexthops = conn.get_nexthops().await?;
for nh in &nexthops {
    if nh.is_group() {
        println!("Group {}: {:?}", nh.id, nh.group);
    } else {
        println!("NH {}: gateway={:?} ifindex={:?}", nh.id, nh.gateway, nh.ifindex);
    }
}

// Query only groups
let groups = conn.get_nexthop_groups().await?;

// Get specific nexthop
if let Some(nh) = conn.get_nexthop(1).await? {
    println!("Nexthop 1: {:?}", nh);
}

// Replace a nexthop (update or create)
conn.replace_nexthop(
    NexthopBuilder::new(1)
        .gateway(Ipv4Addr::new(192, 168, 1, 254).into())
        .dev("eth0")
).await?;

// Cleanup
conn.del_nexthop_group(100).await?;
conn.del_nexthop(1).await?;
conn.del_nexthop(2).await?;
```

**MPLS routes and encapsulation:**
```rust
use nlink::netlink::{Connection, Route};
use nlink::netlink::mpls::{MplsEncap, MplsLabel, MplsRouteBuilder};
use nlink::netlink::route::Ipv4Route;
use std::net::Ipv4Addr;

let conn = Connection::<Route>::new()?;

// IP route with MPLS encapsulation (push labels)
conn.add_route(
    Ipv4Route::new("10.0.0.0", 8)
        .gateway(Ipv4Addr::new(192, 168, 1, 1))
        .dev("eth0")
        .mpls_encap(MplsEncap::new().label(100))
).await?;

// IP route with label stack (outer to inner)
conn.add_route(
    Ipv4Route::new("10.1.0.0", 16)
        .gateway(Ipv4Addr::new(192, 168, 1, 1))
        .mpls_encap(MplsEncap::new().labels(&[100, 200, 300]).ttl(64))
).await?;

// MPLS pop route (label -> IP, at egress PE)
conn.add_mpls_route(
    MplsRouteBuilder::pop(100)
        .dev("eth0")
).await?;

// MPLS swap route (label -> label, at transit LSR)
conn.add_mpls_route(
    MplsRouteBuilder::swap(100, 200)
        .via("192.168.2.1".parse()?)
        .dev("eth1")
).await?;

// MPLS swap with label stack
conn.add_mpls_route(
    MplsRouteBuilder::swap_stack(100, &[200, 300])
        .via("192.168.2.1".parse()?)
        .dev("eth1")
).await?;

// Query MPLS routes
let routes = conn.get_mpls_routes().await?;
for route in &routes {
    println!("Label {}: {:?}", route.label.0, route.action);
}

// Delete MPLS route
conn.del_mpls_route(100).await?;

// Special label constants
let implicit_null = MplsLabel::IMPLICIT_NULL;  // 3 - penultimate hop popping
let explicit_null_v4 = MplsLabel::EXPLICIT_NULL_V4;  // 0
let explicit_null_v6 = MplsLabel::EXPLICIT_NULL_V6;  // 2
```

**SRv6 (Segment Routing over IPv6) routes and encapsulation:**
```rust
use nlink::netlink::{Connection, Route};
use nlink::netlink::srv6::{Srv6Encap, Srv6LocalBuilder, Srv6Mode};
use nlink::netlink::route::{Ipv4Route, Ipv6Route};
use std::net::Ipv6Addr;

let conn = Connection::<Route>::new()?;

// IPv4 route with SRv6 encapsulation (IPv4oIPv6)
conn.add_route(
    Ipv4Route::new("10.0.0.0", 8)
        .dev("eth0")
        .srv6_encap(
            Srv6Encap::encap()
                .segment("fc00:1::1".parse()?)
        )
).await?;

// IPv4 route with SRv6 segment list
conn.add_route(
    Ipv4Route::new("10.1.0.0", 16)
        .dev("eth0")
        .srv6_encap(
            Srv6Encap::encap()
                .segments(&[
                    "fc00:1::1".parse()?,  // First segment (final destination)
                    "fc00:2::1".parse()?,  // Intermediate segment
                ])
        )
).await?;

// IPv6 route with SRv6 inline mode (insert SRH into IPv6 packet)
conn.add_route(
    Ipv6Route::new("2001:db8::", 32)
        .dev("eth0")
        .srv6_encap(
            Srv6Encap::inline()
                .segment("fc00:1::1".parse()?)
        )
).await?;

// SRv6 End local SID (simple transit)
conn.add_srv6_local(
    Srv6LocalBuilder::end("fc00:1::1".parse()?)
        .dev("eth0")
).await?;

// SRv6 End.X local SID (pop and forward to nexthop)
conn.add_srv6_local(
    Srv6LocalBuilder::end_x("fc00:1::1".parse()?, "fe80::1".parse()?)
        .dev("eth0")
).await?;

// SRv6 End.DT4 local SID (decap and lookup IPv4 in VRF)
conn.add_srv6_local(
    Srv6LocalBuilder::end_dt4("fc00:1::100".parse()?, 100)  // table 100
        .dev("eth0")
).await?;

// SRv6 End.DT6 local SID (decap and lookup IPv6 in VRF)
conn.add_srv6_local(
    Srv6LocalBuilder::end_dt6("fc00:1::200".parse()?, 100)
        .dev("eth0")
).await?;

// SRv6 End.B6.Encaps local SID (encap with new SRH)
conn.add_srv6_local(
    Srv6LocalBuilder::end_b6_encaps(
        "fc00:1::300".parse()?,
        &["fc00:2::1".parse()?, "fc00:3::1".parse()?]
    ).dev("eth0")
).await?;

// Query SRv6 local routes
let routes = conn.get_srv6_local_routes().await?;
for route in &routes {
    println!("SID {:?}: {}", route.sid, route.action.name());
}

// Delete SRv6 local route
conn.del_srv6_local("fc00:1::100".parse()?).await?;
```

**Bridge FDB management:**
```rust
use nlink::netlink::{Connection, Route};
use nlink::netlink::fdb::FdbEntryBuilder;

let conn = Connection::<Route>::new()?;

// Query FDB entries for a bridge
let entries = conn.get_fdb("br0").await?;
for entry in &entries {
    println!("{} vlan={:?} dst={:?}", entry.mac_str(), entry.vlan, entry.dst);
}

// Query FDB for a specific port
let port_entries = conn.get_fdb_for_port("br0", "veth0").await?;

// Add a static FDB entry
let mac = FdbEntryBuilder::parse_mac("aa:bb:cc:dd:ee:ff")?;
conn.add_fdb(
    FdbEntryBuilder::new(mac)
        .dev("veth0")
        .master("br0")
        .vlan(100)
        .permanent()
).await?;

// Add VXLAN FDB entry (remote VTEP)
use std::net::Ipv4Addr;
conn.add_fdb(
    FdbEntryBuilder::new([0x00; 6])  // all-zeros for BUM traffic
        .dev("vxlan0")
        .dst(Ipv4Addr::new(192, 168, 1, 100).into())
).await?;

// Replace entry (add or update)
conn.replace_fdb(
    FdbEntryBuilder::new(mac)
        .dev("veth0")
        .master("br0")
).await?;

// Delete entry
conn.del_fdb("veth0", mac, None).await?;

// Delete entry with VLAN
conn.del_fdb("veth0", mac, Some(100)).await?;

// Flush all dynamic entries (keeps permanent entries)
conn.flush_fdb("br0").await?;

// Namespace-aware operations (use ifindex to avoid /sys reads)
let link = conn.get_link_by_name("veth0").await?.unwrap();
conn.del_fdb_by_index(link.ifindex(), mac, None).await?;
```

**Bridge VLAN filtering:**
```rust
use nlink::netlink::{Connection, Route};
use nlink::netlink::bridge_vlan::BridgeVlanBuilder;

let conn = Connection::<Route>::new()?;

// Query VLAN configuration for a port
let vlans = conn.get_bridge_vlans("eth0").await?;
for vlan in &vlans {
    println!("VLAN {}: pvid={} untagged={}",
        vlan.vid, vlan.flags.pvid, vlan.flags.untagged);
}

// Query VLANs for all ports of a bridge
let all_vlans = conn.get_bridge_vlans_all("br0").await?;

// Add VLAN 100 as PVID and untagged (native VLAN)
conn.add_bridge_vlan(
    BridgeVlanBuilder::new(100)
        .dev("eth0")
        .pvid()
        .untagged()
).await?;

// Convenience method for setting PVID
conn.set_bridge_pvid("eth0", 100).await?;

// Add a tagged VLAN
conn.add_bridge_vlan_tagged("eth0", 200).await?;

// Add VLAN range 300-310 as tagged
conn.add_bridge_vlan_range("eth0", 300, 310).await?;

// Delete a single VLAN
conn.del_bridge_vlan("eth0", 100).await?;

// Delete a VLAN range
conn.del_bridge_vlan_range("eth0", 300, 310).await?;

// Namespace-aware operations (use ifindex)
let link = conn.get_link_by_name("eth0").await?.unwrap();
conn.get_bridge_vlans_by_index(link.ifindex()).await?;
conn.set_bridge_pvid_by_index(link.ifindex(), 100).await?;
```

**Error handling:**
```rust
use nlink::netlink::{Connection, Protocol, Error};
use nlink::util::parse::get_rate;

let conn = Connection::new(Protocol::Route)?;

// Check error types for recovery logic
match conn.del_qdisc("eth0", "root").await {
    Ok(()) => println!("Deleted"),
    Err(e) if e.is_not_found() => println!("Nothing to delete"),
    Err(e) if e.is_permission_denied() => println!("Need root"),
    Err(e) if e.is_already_exists() => println!("Already exists"),
    Err(e) if e.is_busy() => println!("Device busy"),
    Err(e) if e.is_invalid_argument() => println!("Invalid argument"),
    Err(e) if e.is_no_device() => println!("Device not found"),
    Err(e) if e.is_not_supported() => println!("Operation not supported"),
    Err(e) if e.is_network_unreachable() => println!("Network unreachable"),
    Err(e) if e.is_timeout() => println!("Operation timed out"),
    Err(e) => return Err(e),
}

// Get errno for detailed handling
if let Some(errno) = err.errno() {
    println!("System error: {}", errno);
}

// Automatic error conversion from util types (ParseError, AddrError, IfError)
let rate = get_rate("1mbit")?;  // ParseError automatically converts to Error

// Structured validation errors
use nlink::netlink::error::ValidationErrorInfo;
let err = Error::validation(vec![
    ValidationErrorInfo::new("name", "cannot be empty"),
    ValidationErrorInfo::new("vlan_id", "must be 1-4094"),
]);
// Displays as: "validation failed: name: cannot be empty; vlan_id: must be 1-4094"
```

**WireGuard configuration via Generic Netlink:**
```rust
use nlink::netlink::{Connection, Wireguard};
use nlink::netlink::genl::wireguard::AllowedIp;
use std::net::{Ipv4Addr, SocketAddrV4};

// Create a WireGuard connection (async due to GENL family resolution)
let conn = Connection::<Wireguard>::new_async().await?;

// Get device information
let device = conn.get_device("wg0").await?;
println!("Public key: {:?}", device.public_key);
println!("Listen port: {:?}", device.listen_port);

// List peers
for peer in &device.peers {
    println!("Peer: {:?}", peer.public_key);
    println!("  Endpoint: {:?}", peer.endpoint);
    println!("  RX: {} bytes, TX: {} bytes", peer.rx_bytes, peer.tx_bytes);
    println!("  Allowed IPs: {:?}", peer.allowed_ips);
}

// Configure device (requires root)
let private_key = [0u8; 32]; // Your private key
conn.set_device("wg0", |dev| {
    dev.private_key(private_key)
       .listen_port(51820)
}).await?;

// Add a peer
let peer_pubkey = [0u8; 32]; // Peer's public key
conn.set_peer("wg0", peer_pubkey, |peer| {
    peer.endpoint(SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 1), 51820).into())
        .persistent_keepalive(25)
        .allowed_ip(AllowedIp::v4(Ipv4Addr::new(10, 0, 0, 0), 24))
        .replace_allowed_ips()
}).await?;

// Remove a peer
conn.remove_peer("wg0", peer_pubkey).await?;

// Access the resolved GENL family ID if needed
println!("WireGuard family ID: {}", conn.family_id());
```

**MACsec (IEEE 802.1AE) configuration via Generic Netlink:**
```rust
use nlink::netlink::{Connection, Macsec};
use nlink::netlink::genl::macsec::{MacsecSaBuilder, MacsecCipherSuite};

// Create a MACsec connection (async due to GENL family resolution)
let conn = Connection::<Macsec>::new_async().await?;

// Get device information
let device = conn.get_device("macsec0").await?;
println!("SCI: {:016x}", device.sci);
println!("Cipher: {:?}", device.cipher_suite);
println!("Encoding SA: {}", device.encoding_sa);

// List TX SAs
for sa in &device.tx_sc.sas {
    println!("TX SA {}: active={}, pn={}", sa.an, sa.active, sa.next_pn);
}

// List RX SCs and their SAs
for rxsc in &device.rx_scs {
    println!("RX SC {:016x}:", rxsc.sci);
    for sa in &rxsc.sas {
        println!("  SA {}: active={}", sa.an, sa.active);
    }
}

// Add a TX SA (requires root)
let key = [0u8; 16]; // 128-bit key for GCM-AES-128
conn.add_tx_sa("macsec0",
    MacsecSaBuilder::new(0)  // AN 0-3
        .key(&key)
        .pn(1)
        .active(true)
).await?;

// Update TX SA (activate/deactivate or update PN)
conn.update_tx_sa("macsec0",
    MacsecSaBuilder::new(0)
        .active(false)
).await?;

// Delete TX SA
conn.del_tx_sa("macsec0", 0).await?;

// Add RX SC (peer's SCI)
let peer_sci = 0x001122334455_0001u64;  // MAC + port
conn.add_rx_sc("macsec0", peer_sci).await?;

// Add RX SA for a peer
conn.add_rx_sa("macsec0", peer_sci,
    MacsecSaBuilder::new(0)
        .key(&key)
        .pn(1)
        .active(true)
).await?;

// Delete RX SA and SC
conn.del_rx_sa("macsec0", peer_sci, 0).await?;
conn.del_rx_sc("macsec0", peer_sci).await?;

// Access the resolved GENL family ID if needed
println!("MACsec family ID: {}", conn.family_id());
```

**MPTCP (Multipath TCP) endpoint configuration via Generic Netlink:**
```rust
use nlink::netlink::{Connection, Mptcp};
use nlink::netlink::genl::mptcp::{MptcpEndpointBuilder, MptcpLimits, MptcpFlags};

// Create MPTCP connection (async for GENL family resolution)
let conn = Connection::<Mptcp>::new_async().await?;

// List configured endpoints
for ep in conn.get_endpoints().await? {
    println!("Endpoint {}: {} flags={:?}", ep.id, ep.address, ep.flags);
}

// Add endpoint for second interface (signal + subflow)
conn.add_endpoint(
    MptcpEndpointBuilder::new("192.168.2.1".parse()?)
        .id(1)
        .dev("eth1")
        .subflow()
        .signal()
).await?;

// Add backup endpoint (used when primary fails)
conn.add_endpoint(
    MptcpEndpointBuilder::new("10.0.0.1".parse()?)
        .id(2)
        .dev("wlan0")
        .backup()
        .signal()
).await?;

// Set MPTCP limits
conn.set_limits(
    MptcpLimits::new()
        .subflows(4)           // Max subflows per connection
        .add_addr_accepted(4)  // Max addresses to accept from peers
).await?;

// Get current limits
let limits = conn.get_limits().await?;
println!("Max subflows: {:?}", limits.subflows);

// Update endpoint flags
conn.set_endpoint_flags(1, MptcpFlags { backup: true, ..Default::default() }).await?;

// Delete endpoint
conn.del_endpoint(1).await?;

// Flush all endpoints
conn.flush_endpoints().await?;
```

**Device hotplug events (udev-style) via KobjectUevent:**
```rust
use nlink::netlink::{Connection, KobjectUevent};

// Subscribe to kernel uevents
let conn = Connection::<KobjectUevent>::new()?;

loop {
    let event = conn.recv().await?;
    println!("[{}] {} ({})", event.action, event.devpath, event.subsystem);
    
    // Access device properties
    if let Some(devname) = event.devname() {
        println!("  Device: /dev/{}", devname);
    }
    if event.is_add() {
        println!("  New device added!");
    }
}
```

**Process lifecycle events via Connector:**
```rust
use nlink::netlink::{Connection, Connector};
use nlink::netlink::connector::ProcEvent;

// Subscribe to process events (requires CAP_NET_ADMIN)
let conn = Connection::<Connector>::new().await?;

loop {
    match conn.recv().await? {
        ProcEvent::Fork { parent_pid, child_pid, .. } => {
            println!("fork: {} -> {}", parent_pid, child_pid);
        }
        ProcEvent::Exec { pid, .. } => {
            println!("exec: {}", pid);
        }
        ProcEvent::Exit { pid, exit_code, .. } => {
            println!("exit: {} (code {})", pid, exit_code);
        }
        _ => {}
    }
}
```

**Connection tracking (conntrack) via Netfilter:**
```rust
use nlink::netlink::{Connection, Netfilter};
use nlink::netlink::netfilter::IpProtocol;

let conn = Connection::<Netfilter>::new()?;

// Query IPv4 connection tracking entries
let entries = conn.get_conntrack().await?;
for entry in &entries {
    println!("{:?} {}:{} -> {}:{}",
        entry.proto,
        entry.orig.src_ip.unwrap_or_default(),
        entry.orig.src_port.unwrap_or(0),
        entry.orig.dst_ip.unwrap_or_default(),
        entry.orig.dst_port.unwrap_or(0));
}

// Query IPv6 entries
let entries_v6 = conn.get_conntrack_v6().await?;
```

**IPsec SA/SP management via XFRM:**
```rust
use nlink::netlink::{Connection, Xfrm};

let conn = Connection::<Xfrm>::new()?;

// List Security Associations (SAs)
let sas = conn.get_security_associations().await?;
for sa in &sas {
    println!("SA: {:?} -> {:?} proto={:?} mode={:?}",
        sa.src, sa.dst, sa.protocol, sa.mode);
    println!("  SPI: 0x{:08x}, reqid: {}", sa.spi, sa.reqid);
}

// List Security Policies (SPs)
let sps = conn.get_security_policies().await?;
for sp in &sps {
    println!("SP: {:?} dir={:?} action={:?}",
        sp.selector, sp.direction, sp.action);
}
```

**FIB route lookups:**
```rust
use nlink::netlink::{Connection, FibLookup};
use std::net::Ipv4Addr;

let conn = Connection::<FibLookup>::new()?;

// Simple route lookup
let result = conn.lookup(Ipv4Addr::new(8, 8, 8, 8).into()).await?;
println!("Route type: {:?}, scope: {:?}", result.route_type, result.scope);
println!("Table: {}, prefix_len: {}", result.table, result.prefix_len);

// Lookup in specific table with fwmark
let result = conn.lookup_with_options(
    Ipv4Addr::new(10, 0, 0, 1).into(),
    Some(100),  // table
    Some(0x42), // fwmark
).await?;
```

**Linux Audit subsystem:**
```rust
use nlink::netlink::{Connection, Audit};

let conn = Connection::<Audit>::new()?;

// Get audit daemon status
let status = conn.get_status().await?;
println!("Audit enabled: {}", status.is_enabled());
println!("Audit locked: {}", status.is_locked());
println!("Failure mode: {:?}", status.failure_mode());
println!("Backlog: {}/{}", status.backlog, status.backlog_limit);
println!("Lost messages: {}", status.lost);

// Get TTY auditing status
let tty = conn.get_tty_status().await?;
println!("TTY auditing: {}", tty.enabled != 0);

// Get audit features
let features = conn.get_features().await?;
println!("Audit version: {}", features.vers);
```

**SELinux event notifications:**
```rust
use nlink::netlink::{Connection, SELinux};
use nlink::netlink::selinux::SELinuxEvent;

// Check if SELinux is available
if !Connection::<SELinux>::is_available() {
    println!("SELinux not available");
    return Ok(());
}

// Get current enforcement mode
let enforcing = Connection::<SELinux>::get_enforce()?;
println!("Current mode: {}", if enforcing { "enforcing" } else { "permissive" });

// Monitor SELinux events
let conn = Connection::<SELinux>::new()?;
loop {
    match conn.recv().await? {
        SELinuxEvent::SetEnforce { enforcing } => {
            println!("Mode changed: {}", if enforcing { "enforcing" } else { "permissive" });
        }
        SELinuxEvent::PolicyLoad { seqno } => {
            println!("Policy loaded (seqno: {})", seqno);
        }
    }
}
```

## Netlink Message Flow

1. Create `Connection` for `Protocol::Route`
2. Build request with `MessageBuilder::new(msg_type, flags)`
3. Append message struct (e.g., `IfInfoMsg`) with `builder.append(&msg)`
4. Add attributes with `builder.append_attr*()` methods
5. For nested attributes: `nest_start()` / `nest_end()`
6. Send via `conn.dump()` (for GET) or `conn.request_ack()` (for ADD/DEL)
7. Parse responses with `MessageIter` and `AttrIter`

## Internal Design: Zero-Copy Serialization

The `types/` module uses the `zerocopy` crate for safe, zero-copy serialization of netlink structures. All `#[repr(C)]` structs derive zerocopy traits instead of using unsafe pointer casts:

```rust
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

#[repr(C)]
#[derive(Debug, Clone, Copy, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct SomeNetlinkStruct {
    pub field1: u32,
    pub field2: u16,
    pub _pad: u16,  // Explicit padding for alignment
}

impl SomeNetlinkStruct {
    // Safe serialization
    pub fn as_bytes(&self) -> &[u8] {
        <Self as IntoBytes>::as_bytes(self)
    }

    // Safe deserialization
    pub fn from_bytes(data: &[u8]) -> Option<&Self> {
        Self::ref_from_prefix(data).map(|(r, _)| r).ok()
    }
}
```

**Key points:**
- Use `IntoBytes` + `Immutable` + `KnownLayout` for serialization (`as_bytes()`)
- Use `FromBytes` + `Immutable` + `KnownLayout` for deserialization (`from_bytes()`)
- Add explicit `_pad` fields to satisfy zerocopy's padding requirements
- No unsafe code in the types module

## Generic Netlink Message Flow

1. Create `GenlConnection::new()` for `Protocol::Generic`
2. Resolve family ID with `conn.get_family("wireguard").await?`
3. Build GENL message with `GenlMsgHdr` after `NlMsgHdr`
4. Use `conn.command()` or `conn.dump_command()` with family ID
5. Parse responses starting after the GENL header (4 bytes)

## Publishing

The `nlink` crate is the only publishable crate. All binaries have `publish = false`.

```bash
cargo publish -p nlink
```
