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
    events.rs         # High-level event monitoring (EventStream, NetworkEvent)
    namespace.rs      # Network namespace utilities
    stats.rs          # Statistics tracking (StatsSnapshot, StatsTracker)
    tc.rs             # TC typed builders (NetemConfig, FqCodelConfig, HtbConfig, TbfConfig, PrioConfig, SfqConfig, RedConfig, PieConfig, DrrConfig, QfqConfig, HfscConfig, MqprioConfig, TaprioConfig, EtfConfig, PlugConfig, etc.)
    tc_options.rs     # TC options parsing (netem loss models, etc.)
    filter.rs         # TC filter builders (U32Filter, FlowerFilter, MatchallFilter, FwFilter, BpfFilter, BasicFilter, CgroupFilter, RouteFilter, FlowFilter)
    action.rs         # TC action builders (GactAction, MirredAction, PoliceAction, VlanAction, SkbeditAction, NatAction, TunnelKeyAction, ConnmarkAction, CsumAction, SampleAction, CtAction, PeditAction, ActionList)
    link.rs           # Link type builders (DummyLink, VethLink, BridgeLink, VlanLink, VxlanLink, MacvlanLink, MacvtapLink, IpvlanLink, IfbLink, GeneveLink, BareudpLink, NetkitLink, NlmonLink, VirtWifiLink, VtiLink, Vti6Link, Ip6GreLink, Ip6GretapLink)
    genl/             # Generic Netlink (GENL) support
      mod.rs          # GENL module entry, control family constants
      header.rs       # GenlMsgHdr (4-byte GENL header)
      connection.rs   # GenlConnection with family ID resolution and caching
      wireguard/      # WireGuard GENL configuration
        mod.rs        # WireGuard constants and attribute types
        types.rs      # WgDevice, WgPeer, AllowedIp, builders
        connection.rs # WireguardConnection API
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

## Key Patterns

**High-level queries (preferred for library use):**
```rust
use nlink::netlink::{Connection, Protocol};

let conn = Connection::new(Protocol::Route)?;

// Query interfaces
let links = conn.get_links().await?;
let eth0 = conn.get_link_by_name("eth0").await?;

// Query addresses
let addrs = conn.get_addresses().await?;
let eth0_addrs = conn.get_addresses_for("eth0").await?;

// Query routes
let routes = conn.get_routes().await?;

// Query TC
let qdiscs = conn.get_qdiscs().await?;
let classes = conn.get_classes_for("eth0").await?;
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

**Network namespace operations:**
```rust
use nlink::netlink::{Connection, Protocol};
use nlink::netlink::namespace;

// Connect to a named namespace (created via `ip netns add myns`)
let conn = namespace::connection_for("myns")?;
let links = conn.get_links().await?;

// Connect to a container's namespace by PID
let conn = namespace::connection_for_pid(container_pid)?;

// Or use a path directly
let conn = Connection::new_in_namespace_path(
    Protocol::Route,
    "/proc/1234/ns/net"
)?;

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
        // Time values in nanoseconds (with convenience methods)
        println!("delay={:?}, jitter={:?}", netem.delay(), netem.jitter());
        
        // Percentages
        println!("loss={}%, correlation={}%", netem.loss_percent, netem.loss_corr);
        println!("duplicate={}%", netem.duplicate_percent);
        println!("reorder={}%, gap={}", netem.reorder_percent, netem.gap);
        println!("corrupt={}%", netem.corrupt_percent);
        
        // Rate limiting with overhead params
        if netem.rate > 0 {
            println!("rate={} bytes/sec", netem.rate);
            println!("packet_overhead={}, cell_size={}", netem.packet_overhead, netem.cell_size);
        }
        
        // ECN and slot-based transmission
        println!("ecn={}", netem.ecn);
        if let Some(slot) = &netem.slot {
            println!("slot: min={}ns, max={}ns", slot.min_delay_ns, slot.max_delay_ns);
        }
        
        // Loss models (Gilbert-Intuitive or Gilbert-Elliot)
        if let Some(loss_model) = &netem.loss_model {
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

    // Option 2: Use parsed_options() for all qdisc types
    if let Some(QdiscOptions::Netem(netem)) = qdisc.parsed_options() {
        // Same fields available
    }
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

**HTB class statistics:**
```rust
// Get all classes for an interface
let classes = conn.get_classes_for("eth0").await?;
for class in &classes {
    println!("Class {:x}: {} bytes, {} packets", 
        class.handle(), class.bytes(), class.packets());
}
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

**Monitoring events (high-level API - preferred):**
```rust
use nlink::netlink::events::{EventStream, NetworkEvent};

let mut stream = EventStream::builder()
    .links(true)
    .addresses(true)
    .tc(true)
    .build()?;

while let Some(event) = stream.next().await? {
    match event {
        NetworkEvent::NewLink(link) => println!("Link: {}", link.name.unwrap_or_default()),
        NetworkEvent::NewAddress(addr) => println!("Addr: {:?}", addr.address),
        NetworkEvent::NewQdisc(tc) => println!("Qdisc: {}", tc.kind().unwrap_or("?")),
        _ => {}
    }
}
```

**Namespace-aware event monitoring:**
```rust
use nlink::netlink::events::{EventStream, NetworkEvent};

// Monitor events in a named namespace
let mut stream = EventStream::builder()
    .namespace("myns")
    .links(true)
    .tc(true)
    .build()?;

// Or by PID (e.g., container process)
let mut stream = EventStream::builder()
    .namespace_pid(container_pid)
    .links(true)
    .build()?;

// Or by path
let mut stream = EventStream::builder()
    .namespace_path("/proc/1234/ns/net")
    .all()
    .build()?;
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

**Namespace-aware TC operations (using ifindex):**
```rust
use nlink::netlink::{namespace, tc::NetemConfig};
use std::time::Duration;

// For namespace operations, use *_by_index methods to avoid
// reading /sys/class/net/ from the host namespace
let conn = namespace::connection_for("myns")?;
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

// Delete/flush filters
conn.del_filter("eth0", "1:", "u32").await?;
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

**Error handling:**
```rust
use nlink::netlink::{Connection, Protocol, Error};

let conn = Connection::new(Protocol::Route)?;

// Check error types for recovery logic
match conn.del_qdisc("eth0", "root").await {
    Ok(()) => println!("Deleted"),
    Err(e) if e.is_not_found() => println!("Nothing to delete"),
    Err(e) if e.is_permission_denied() => println!("Need root"),
    Err(e) if e.is_already_exists() => println!("Already exists"),
    Err(e) if e.is_busy() => println!("Device busy"),
    Err(e) => return Err(e),
}

// Get errno for detailed handling
if let Some(errno) = err.errno() {
    println!("System error: {}", errno);
}
```

**WireGuard configuration via Generic Netlink:**
```rust
use nlink::netlink::genl::wireguard::{WireguardConnection, AllowedIp};
use std::net::{Ipv4Addr, SocketAddrV4};

// Create a WireGuard GENL connection
let wg = WireguardConnection::new().await?;

// Get device information
let device = wg.get_device("wg0").await?;
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
wg.set_device("wg0", |dev| {
    dev.private_key(private_key)
       .listen_port(51820)
}).await?;

// Add a peer
let peer_pubkey = [0u8; 32]; // Peer's public key
wg.set_peer("wg0", peer_pubkey, |peer| {
    peer.endpoint(SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 1), 51820).into())
        .persistent_keepalive(25)
        .allowed_ip(AllowedIp::v4(Ipv4Addr::new(10, 0, 0, 0), 24))
        .replace_allowed_ips()
}).await?;

// Remove a peer
wg.remove_peer("wg0", peer_pubkey).await?;
```

## Netlink Message Flow

1. Create `Connection` for `Protocol::Route`
2. Build request with `MessageBuilder::new(msg_type, flags)`
3. Append message struct (e.g., `IfInfoMsg`) with `builder.append(&msg)`
4. Add attributes with `builder.append_attr*()` methods
5. For nested attributes: `nest_start()` / `nest_end()`
6. Send via `conn.dump()` (for GET) or `conn.request_ack()` (for ADD/DEL)
7. Parse responses with `MessageIter` and `AttrIter`

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
