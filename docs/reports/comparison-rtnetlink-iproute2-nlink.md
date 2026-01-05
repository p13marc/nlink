# Comparison: rtnetlink vs iproute2 vs nlink

This document compares three Linux network configuration approaches:

- **iproute2** - The standard C userspace utility suite for Linux networking
- **rtnetlink** - A Rust crate from the rust-netlink ecosystem
- **nlink** - This project's custom Rust netlink implementation

## Overview

| Aspect | iproute2 | rtnetlink | nlink |
|--------|----------|-----------|-------|
| **Language** | C | Rust | Rust |
| **Type** | CLI tools | Library | Library (with proof-of-concept binaries) |
| **License** | GPL-2.0 | MIT | MIT |
| **Approach** | Feature-complete reference | Rust bindings over netlink-packet-* | Custom from-scratch implementation |
| **Async Runtime** | N/A (synchronous) | Tokio | Tokio |
| **Dependencies** | libc, kernel headers | netlink-packet-route, netlink-sys, futures | netlink-sys, tokio, zerocopy |

## Feature Comparison Matrix

### Core RTNetlink Features

| Feature | iproute2 | rtnetlink | nlink |
|---------|:--------:|:---------:|:-----:|
| **Link Management** |
| List interfaces | Yes | Yes | Yes |
| Create/delete interfaces | Yes | Yes | Yes |
| Set MTU/state/name | Yes | Yes | Yes |
| **Virtual Link Types** |
| dummy | Yes | Yes | Yes |
| veth | Yes | Yes | Yes |
| bridge | Yes | Yes | Yes |
| bond | Yes | Yes | Yes |
| vlan | Yes | Yes | Yes |
| vxlan | Yes | Yes | Yes |
| macvlan/macvtap | Yes | Yes | Yes |
| ipvlan | Yes | Yes | Yes |
| vrf | Yes | Yes | Yes |
| gre/gretap | Yes | Yes | Yes |
| ip6gre/ip6gretap | Yes | Partial | Yes |
| ipip | Yes | Yes | Yes |
| sit | Yes | Yes | Yes |
| vti/vti6 | Yes | Partial | Yes |
| geneve | Yes | Partial | Yes |
| bareudp | Yes | No | Yes |
| netkit | Yes | No | Yes |
| nlmon | Yes | No | Yes |
| virtwifi | Yes | No | Yes |
| ifb | Yes | Partial | Yes |
| wireguard | Yes | Yes | Yes |
| **Address Management** |
| IPv4 addresses | Yes | Yes | Yes |
| IPv6 addresses | Yes | Yes | Yes |
| Address labels | Yes | Yes | Yes |
| **Route Management** |
| IPv4/IPv6 routes | Yes | Yes | Yes |
| Multipath (ECMP) | Yes | Yes | Yes |
| Policy routing | Yes | Yes | Yes |
| VRF routing | Yes | Yes | Yes |
| Nexthop objects (Linux 5.3+) | Yes | Partial | Yes |
| MPLS routes | Yes | No | Yes |
| SRv6 routes | Yes | No | Yes |
| **Neighbor Management** |
| ARP/NDP cache | Yes | Yes | Yes |
| Static neighbors | Yes | Yes | Yes |
| **Routing Rules** |
| Add/delete rules | Yes | Yes | Yes |
| Priority/table/fwmark | Yes | Yes | Yes |

### Traffic Control (tc)

| Feature | iproute2 | rtnetlink | nlink |
|---------|:--------:|:---------:|:-----:|
| **Qdiscs** |
| netem | Yes | Partial | Yes (full options) |
| htb | Yes | Partial | Yes |
| tbf | Yes | Partial | Yes |
| fq_codel | Yes | Partial | Yes |
| fq | Yes | No | Yes |
| sfq | Yes | No | Yes |
| prio | Yes | Partial | Yes |
| red | Yes | No | Yes |
| pie | Yes | No | Yes |
| cake | Yes | No | Yes |
| drr | Yes | No | Yes |
| qfq | Yes | No | Yes |
| hfsc | Yes | No | Yes |
| mqprio | Yes | No | Yes |
| taprio | Yes | No | Yes |
| etf | Yes | No | Yes |
| plug | Yes | No | Yes |
| ingress/clsact | Yes | Partial | Yes |
| **Classes** |
| HTB classes | Yes | Partial | Yes |
| HFSC classes | Yes | No | Yes |
| DRR classes | Yes | No | Yes |
| QFQ classes | Yes | No | Yes |
| **Filters** |
| u32 | Yes | Partial | Yes |
| flower | Yes | Partial | Yes |
| matchall | Yes | Partial | Yes |
| fw | Yes | No | Yes |
| basic | Yes | No | Yes |
| cgroup | Yes | No | Yes |
| route | Yes | No | Yes |
| flow | Yes | No | Yes |
| bpf | Yes | Partial | Yes |
| **Actions** |
| gact (pass/drop/goto) | Yes | Partial | Yes |
| mirred | Yes | Partial | Yes |
| police | Yes | Partial | Yes |
| vlan | Yes | No | Yes |
| skbedit | Yes | No | Yes |
| nat | Yes | No | Yes |
| tunnel_key | Yes | No | Yes |
| connmark | Yes | No | Yes |
| csum | Yes | No | Yes |
| sample | Yes | No | Yes |
| ct | Yes | No | Yes |
| pedit | Yes | No | Yes |
| **TC Chains** | Yes | No | Yes |
| **Statistics** | Yes | Partial | Yes |

### Bridge Features

| Feature | iproute2 | rtnetlink | nlink |
|---------|:--------:|:---------:|:-----:|
| FDB management | Yes | Partial | Yes |
| VLAN filtering | Yes | Partial | Yes |
| VLAN-to-VNI tunneling | Yes | No | Yes |
| MDB (multicast) | Yes | Partial | No |

### Generic Netlink (GENL)

| Feature | iproute2 | rtnetlink | nlink |
|---------|:--------:|:---------:|:-----:|
| WireGuard | Yes (wg tool) | Via separate crate | Yes |
| MACsec | Yes | No | Yes |
| MPTCP | Yes | Via separate crate | Yes |
| ethtool | Yes | Via separate crate | No |
| nl80211 (WiFi) | Yes (iw tool) | Via separate crate | No |

### Other Netlink Protocols

| Feature | iproute2 | rtnetlink | nlink |
|---------|:--------:|:---------:|:-----:|
| Socket diagnostics (ss) | Yes | No | Yes |
| Connection tracking | Yes (conntrack tool) | No | Yes |
| XFRM (IPsec) | Yes | No | Yes |
| FIB lookup | Yes | No | Yes |
| Audit | Yes (auditd) | Via separate crate | Yes |
| SELinux events | N/A | No | Yes |
| Kobject uevents | N/A | No | Yes |
| Process connector | N/A | No | Yes |

### Event Monitoring

| Feature | iproute2 | rtnetlink | nlink |
|---------|:--------:|:---------:|:-----:|
| Link events | Yes (`ip monitor`) | Yes | Yes |
| Address events | Yes | Yes | Yes |
| Route events | Yes | Yes | Yes |
| Neighbor events | Yes | Yes | Yes |
| TC events | Yes | No | Yes |
| FDB events | Yes | No | Yes |
| Rule events | Yes | No | Yes |
| Namespace ID events | Yes | No | Yes |
| Stream API | N/A | Yes | Yes (tokio-stream) |
| Multi-namespace monitoring | N/A | No | Yes (StreamMap) |

### Network Namespaces

| Feature | iproute2 | rtnetlink | nlink |
|---------|:--------:|:---------:|:-----:|
| Connect to namespace | Yes | Via netns-rs | Yes |
| Create/delete namespace | Yes | No | Yes |
| Execute in namespace | Yes | No | Yes |
| Namespace listing | Yes | No | Yes |
| Namespace watching (inotify) | No | No | Yes |

### High-Level APIs

| Feature | iproute2 | rtnetlink | nlink |
|---------|:--------:|:---------:|:-----:|
| Declarative config | No | No | Yes (NetworkConfig) |
| Config diffing | No | No | Yes |
| Idempotent apply | No | No | Yes |
| Dry-run mode | No | No | Yes |
| Rate limiting DSL | No | No | Yes (RateLimiter) |
| Per-host rate limits | No | No | Yes (PerHostLimiter) |
| Network diagnostics | No | No | Yes (Diagnostics) |
| Bottleneck detection | No | No | Yes |

## Architecture Comparison

### iproute2

```
+------------------------------------------+
|         CLI Tools (ip, tc, ss)           |
+------------------------------------------+
|         libnetlink (C library)           |
+------------------------------------------+
|         Netlink Socket (AF_NETLINK)      |
+------------------------------------------+
```

- Monolithic C codebase
- Direct kernel header usage
- Feature-complete reference implementation
- Maintained by kernel developers

### rtnetlink (rust-netlink ecosystem)

```
+------------------------------------------+
|              rtnetlink                   |
|         (High-level async API)           |
+------------------------------------------+
|          netlink-packet-route            |
|         (Message serialization)          |
+------------------------------------------+
|          netlink-packet-core             |
|         (Core netlink types)             |
+------------------------------------------+
|             netlink-sys                  |
|           (Socket wrapper)               |
+------------------------------------------+
```

- Modular multi-crate design
- Separate crates for each protocol (audit, genetlink, ethtool, mptcp-pm, wl-nl80211)
- Community-maintained

### nlink

```
+------------------------------------------+
|           High-Level APIs                |
|  (NetworkConfig, RateLimiter, Diag)      |
+------------------------------------------+
|         Connection<Protocol>             |
|    (Typed async API per protocol)        |
+------------------------------------------+
|         Custom Message Building          |
|     (zerocopy, zero-alloc parsing)       |
+------------------------------------------+
|             netlink-sys                  |
|           (Socket wrapper)               |
+------------------------------------------+
```

- Single-crate design with feature flags
- Protocol-generic `Connection<P>` type
- Zero-copy serialization with zerocopy crate
- Library-first with proof-of-concept binaries

## API Style Comparison

### Query Interfaces

**iproute2 (CLI)**:
```bash
ip link show
```

**rtnetlink (Rust)**:
```rust
let (connection, handle, _) = new_connection()?;
tokio::spawn(connection);
let mut links = handle.link().get().execute();
while let Some(link) = links.try_next().await? {
    println!("{:?}", link);
}
```

**nlink (Rust)**:
```rust
let conn = Connection::<Route>::new()?;
let links = conn.get_links().await?;
for link in &links {
    println!("{}: {}", link.ifindex(), link.name_or("?"));
}
```

### Add a Qdisc

**iproute2 (CLI)**:
```bash
tc qdisc add dev eth0 root netem delay 100ms loss 1%
```

**rtnetlink (Rust)**:
```rust
// TC support is partial - requires manual message building for most qdiscs
```

**nlink (Rust)**:
```rust
let netem = NetemConfig::new()
    .delay(Duration::from_millis(100))
    .loss(1.0)
    .build();
conn.add_qdisc("eth0", netem).await?;
```

### Event Monitoring

**iproute2 (CLI)**:
```bash
ip monitor all
```

**rtnetlink (Rust)**:
```rust
let (mut connection, _, messages) = new_connection()?;
let mgroup_flags = RTNLGRP_LINK | RTNLGRP_IPV4_ADDR;
let addr = SocketAddr::new(0, mgroup_flags);
connection.socket_mut().socket_mut().bind(&addr)?;
// Process messages...
```

**nlink (Rust)**:
```rust
let mut conn = Connection::<Route>::new()?;
conn.subscribe(&[RtnetlinkGroup::Link, RtnetlinkGroup::Ipv4Addr])?;
let mut events = conn.events();
while let Some(event) = events.next().await {
    match event? {
        NetworkEvent::NewLink(link) => println!("New: {:?}", link.name),
        _ => {}
    }
}
```

## Dependency Comparison

### rtnetlink

```toml
[dependencies]
futures = "0.3"
netlink-packet-core = "0.7"
netlink-packet-route = "0.21"
netlink-packet-utils = "0.5"
netlink-proto = "0.11"
netlink-sys = "0.8"
thiserror = "2"
tokio = { version = "1", features = ["rt"] }
log = "0.4"
```

### nlink

```toml
[dependencies]
tokio = "1"
netlink-sys = "0.8"
thiserror = "2"
tracing = "0.1"
bytes = "1"
libc = "0.2"
winnow = "0.7"
serde_json = "1"
zerocopy = "0.8"
tokio-stream = "0.1"
```

## Summary

| Criterion | iproute2 | rtnetlink | nlink |
|-----------|----------|-----------|-------|
| **Best for** | Direct CLI usage, scripts | Basic Rust netlink needs | Full-featured Rust library |
| **TC support** | Complete | Minimal | Comprehensive |
| **GENL support** | Via tools | Separate crates | Integrated |
| **Namespace ops** | Complete | Via external crate | Integrated |
| **High-level APIs** | No | No | Yes |
| **Learning curve** | CLI knowledge | Rust + basic netlink | Rust + idiomatic API |
| **Maintenance** | Kernel team | Community | Project-specific |

### When to Use Each

**Use iproute2 when:**
- Writing shell scripts
- Need all features immediately
- Prototyping network configurations
- Standard system administration

**Use rtnetlink when:**
- Need basic link/address/route operations in Rust
- Want a well-established community crate
- Don't need advanced TC, GENL, or namespaces

**Use nlink when:**
- Need comprehensive TC (traffic control) support
- Want integrated GENL (WireGuard, MACsec, MPTCP)
- Need declarative/idempotent configuration
- Building network automation/orchestration tools
- Need high-level abstractions (rate limiting, diagnostics)
- Want namespace-aware operations

## Sources

- [iproute2 - Linux Foundation Wiki](https://wiki.linuxfoundation.org/networking/iproute2)
- [iproute2 - Wikipedia](https://en.wikipedia.org/wiki/Iproute2)
- [rust-netlink/rtnetlink - GitHub](https://github.com/rust-netlink/rtnetlink)
- [rtnetlink - crates.io](https://crates.io/crates/rtnetlink)
- [netlink-packet-route - GitHub](https://github.com/rust-netlink/netlink-packet-route)
