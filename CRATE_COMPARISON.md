# Rust Netlink Crate Comparison: nlink vs rtnetlink vs iproute2

This document compares **nlink** with the existing Rust ecosystem (**rtnetlink**) and the C reference implementation (**iproute2**).

## Executive Summary

| Aspect | iproute2 (C) | rtnetlink (Rust) | nlink (Rust) |
|--------|:------------:|:----------------:|:------------:|
| Architecture | Synchronous | Async (tokio) | Async (tokio) |
| Netlink implementation | Custom | netlink-packet-* | Custom |
| Dependencies | libc only | ~15 crates | ~5 crates |
| API style | CLI-focused | Low-level builders | High-level + builders |
| Link types | 31+ | 16 | 12 |
| TC qdiscs (build) | 31 | 2 | 12 |
| TC filters (build) | 9 | 3 | 6 |
| TC actions (build) | 19 | 3 | 5 |
| Documentation | Man pages | Minimal | Comprehensive |

### Key Differentiators

| Feature | rtnetlink | nlink |
|---------|:---------:|:-----:|
| High-level query API (`get_links()`, etc.) | No | Yes |
| Event streaming (`EventStream`) | No | Yes |
| Statistics tracking (`StatsTracker`) | No | Yes |
| Namespace watching (inotify) | No | Yes |
| TC options parsing (typed) | Partial | Yes |
| Semantic error types | No | Yes |
| Custom netlink (no dependencies) | No | Yes |

---

## 1. Link Types Comparison

| Link Type | iproute2 | rtnetlink | nlink | Notes |
|-----------|:--------:|:---------:|:-----:|-------|
| dummy | Yes | Yes | Yes | |
| veth | Yes | Yes | Yes | |
| bridge | Yes | Yes | Yes | |
| bond | Yes | Yes | Yes | |
| vlan | Yes | Yes | Yes | |
| vxlan | Yes | Yes | Yes | |
| macvlan | Yes | Yes | Yes | |
| macvtap | Yes | Yes | No | nlink: not implemented |
| ipvlan | Yes | No | Yes | rtnetlink: missing |
| ipvtap | Yes | No | No | |
| vrf | Yes | Yes | Yes | |
| wireguard | Yes | Yes | No | nlink: not implemented |
| macsec | Yes | Yes | No | nlink: not implemented |
| gre/gretap | Yes | No | Yes | rtnetlink: missing |
| ip6gre/ip6gretap | Yes | No | No | |
| ipip/sit/ip6tnl | Yes | No | Yes | rtnetlink: missing |
| vti/vti6 | Yes | No | No | |
| xfrm | Yes | Yes | No | |
| netkit | Yes | Yes | No | |
| geneve | Yes | No | No | |
| bareudp | Yes | No | No | |
| team | Yes | No | No | |
| ifb | Yes | No | No | |
| can/vcan/vxcan | Yes | No | No | |
| TUN/TAP | Yes | No | Yes | nlink: feature-gated module |

**Summary:**
- **rtnetlink**: 16 link types
- **nlink**: 12 link types
- **nlink advantages**: ipvlan, gre, ipip/sit tunnels, TUN/TAP
- **rtnetlink advantages**: wireguard, macsec, macvtap, xfrm, netkit

---

## 2. Address Management

| Feature | iproute2 | rtnetlink | nlink |
|---------|:--------:|:---------:|:-----:|
| Add address | Yes | Yes | Yes |
| Delete address | Yes | Yes | Yes |
| List addresses | Yes | Yes | Yes |
| Filter by interface | Yes | Yes | Yes |
| Label support | Yes | No | Yes |
| Lifetime (valid/preferred) | Yes | No | Yes |
| Scope | Yes | Yes | Yes |
| Flags (IFA_F_*) | Yes | Yes | Yes |
| Replace existing | Yes | Yes | No |
| Broadcast address | Yes | Yes | Yes |

**nlink advantages**: Label support, address lifetimes
**rtnetlink advantages**: Replace operation

---

## 3. Route Management

| Feature | iproute2 | rtnetlink | nlink |
|---------|:--------:|:---------:|:-----:|
| Add route | Yes | Yes | Yes |
| Delete route | Yes | Yes | Yes |
| List routes | Yes | Yes | Yes |
| Replace route | Yes | Yes | Yes |
| Route get (lookup) | Yes | No | Yes |
| Multipath/ECMP | Yes | Yes | Yes |
| Route metrics | Yes | Yes | Yes |
| Via gateway | Yes | Yes | Yes |
| Device-only route | Yes | Yes | Yes |
| Source address | Yes | Yes | Yes |
| Table selection | Yes | Yes | Yes |
| Protocol | Yes | Yes | Yes |
| Scope | Yes | Yes | Yes |
| Nexthop objects | Yes | No | No |

**nlink advantages**: Route lookup (`ip route get`)
**Both support**: Core routing operations equally

---

## 4. Neighbor (ARP) Management

| Feature | iproute2 | rtnetlink | nlink |
|---------|:--------:|:---------:|:-----:|
| Add neighbor | Yes | Yes | Yes |
| Delete neighbor | Yes | Yes | Yes |
| List neighbors | Yes | Yes | Yes |
| Replace neighbor | Yes | Yes | Yes |
| Proxy ARP | Yes | Yes | No |
| Flush | Yes | No | Yes |
| State filtering | Yes | Yes | Yes |

**nlink advantages**: Flush operation
**rtnetlink advantages**: Proxy ARP

---

## 5. Policy Rules

| Feature | iproute2 | rtnetlink | nlink |
|---------|:--------:|:---------:|:-----:|
| Add rule | Yes | Yes | Yes |
| Delete rule | Yes | Yes | Yes |
| List rules | Yes | Yes | Yes |
| From/to prefix | Yes | Yes | Yes |
| Fwmark | Yes | Yes | Yes |
| Table selection | Yes | Yes | Yes |
| Priority | Yes | Yes | Yes |
| IIF/OIF | Yes | Yes | Yes |
| UID range | Yes | No | No |
| IP protocol | Yes | No | Yes |
| Sport/dport range | Yes | No | No |

**nlink advantages**: IP protocol matching
**Neither supports**: UID range, port ranges

---

## 6. Traffic Control - Queue Disciplines

| Qdisc | iproute2 | rtnetlink | nlink | Notes |
|-------|:--------:|:---------:|:-----:|-------|
| **Basic qdiscs** |
| pfifo/bfifo | Yes | No | Yes | nlink: PfifoConfig, BfifoConfig |
| prio | Yes | No | Yes | nlink: PrioConfig |
| **Scheduling** |
| htb | Yes | No | Yes | nlink: HtbConfig |
| tbf | Yes | No | Yes | nlink: TbfConfig |
| sfq | Yes | No | Yes | nlink: SfqConfig |
| drr | Yes | No | No | |
| qfq | Yes | No | No | |
| ets | Yes | No | No | |
| hfsc | Yes | No | No | |
| cbq | Yes | No | No | |
| **AQM (Active Queue Management)** |
| fq_codel | Yes | Yes | Yes | Both support |
| codel | Yes | No | Yes | nlink: CodelConfig |
| fq | Yes | No | Yes | nlink: FqConfig |
| red | Yes | No | Yes | nlink: RedConfig |
| pie | Yes | No | Yes | nlink: PieConfig |
| cake | Yes | No | Yes | nlink: CakeConfig (parse only) |
| gred | Yes | No | No | |
| choke | Yes | No | No | |
| fq_pie | Yes | No | No | |
| sfb | Yes | No | No | |
| hhf | Yes | No | No | |
| **Emulation** |
| netem | Yes | No | Yes | nlink: full support |
| **Ingress/Classification** |
| ingress | Yes | Yes | Yes | Both support |
| clsact | Yes | No | Yes | nlink: ClsactConfig |
| **Time-based** |
| etf | Yes | No | No | |
| taprio | Yes | No | No | |
| **Other** |
| mqprio | Yes | No | No | |
| multiq | Yes | No | No | |
| plug | Yes | No | No | |

**Summary:**
- **iproute2**: 31 qdiscs
- **rtnetlink**: 2 qdiscs (fq_codel, ingress)
- **nlink**: 12 qdiscs

**nlink has significant advantages in TC qdisc support.**

---

## 7. Traffic Control - Filters

| Filter | iproute2 | rtnetlink | nlink | Notes |
|--------|:--------:|:---------:|:-----:|-------|
| u32 | Yes | Yes | Yes | Both support |
| flower | Yes | Yes | Yes | Both support |
| matchall | Yes | Yes | Yes | Both support |
| basic | Yes | No | Yes | nlink only |
| fw | Yes | No | Yes | nlink only |
| bpf | Yes | No | Yes | nlink only |
| cgroup | Yes | No | No | |
| flow | Yes | No | No | |
| route | Yes | No | No | |

**Summary:**
- **iproute2**: 9 filters
- **rtnetlink**: 3 filters (u32, flower, matchall)
- **nlink**: 6 filters

**nlink has more filter support.**

---

## 8. Traffic Control - Actions

| Action | iproute2 | rtnetlink | nlink | Notes |
|--------|:--------:|:---------:|:-----:|-------|
| gact | Yes | No | Yes | nlink: pass/drop/pipe |
| mirred | Yes | Yes | Yes | Both support |
| police | Yes | No | Yes | nlink only |
| vlan | Yes | No | Yes | nlink: push/pop/modify |
| skbedit | Yes | No | Yes | nlink: mark/priority/queue |
| nat | Yes | Yes | No | rtnetlink only |
| tunnel_key | Yes | Yes | No | rtnetlink only |
| pedit | Yes | No | No | |
| mpls | Yes | No | No | |
| bpf | Yes | No | No | |
| connmark | Yes | No | No | |
| ct | Yes | No | No | |
| ctinfo | Yes | No | No | |
| csum | Yes | No | No | |
| skbmod | Yes | No | No | |
| ife | Yes | No | No | |
| gate | Yes | No | No | |
| sample | Yes | No | No | |

**Summary:**
- **iproute2**: 19 actions
- **rtnetlink**: 3 actions (mirred, nat, tunnel_key)
- **nlink**: 5 actions (gact, mirred, police, vlan, skbedit)

**nlink and rtnetlink have different action coverage.**

---

## 9. Event Monitoring

| Feature | iproute2 | rtnetlink | nlink |
|---------|:--------:|:---------:|:-----:|
| Link events | Yes | Yes* | Yes |
| Address events | Yes | Yes* | Yes |
| Route events | Yes | Yes* | Yes |
| Neighbor events | Yes | Yes* | Yes |
| TC events | Yes | Yes* | Yes |
| High-level API | No | No | Yes (`EventStream`) |
| Event types enum | No | No | Yes (`NetworkEvent`) |
| Namespace-aware | Yes | No | Yes |

*rtnetlink provides multicast group subscription but no high-level API.

**nlink advantages**: `EventStream`, `NetworkEvent` enum, namespace-aware monitoring

---

## 10. Namespace Support

| Feature | iproute2 | rtnetlink | nlink |
|---------|:--------:|:---------:|:-----:|
| Named namespaces | Yes | No | Yes |
| Namespace by PID | Yes | No | Yes |
| Namespace by path | Yes | No | Yes |
| Namespace watching (inotify) | No | No | Yes |
| Namespace netlink events | Yes | No | Yes |
| `ip netns exec` equivalent | Yes | No | Yes |

**nlink has comprehensive namespace support that rtnetlink lacks.**

---

## 11. API Design Comparison

### rtnetlink Style
```rust
use rtnetlink::new_connection;

let (connection, handle, _) = new_connection().unwrap();
tokio::spawn(connection);

// Low-level: must construct messages manually
let mut links = handle.link().get().execute();
while let Some(msg) = links.try_next().await? {
    // Parse LinkMessage manually
}

// Adding a link requires builder chain
handle.link().add()
    .veth("veth0".into(), "veth1".into())
    .execute().await?;
```

### nlink Style
```rust
use nlink::netlink::{Connection, Protocol};

let conn = Connection::new(Protocol::Route)?;

// High-level: typed responses
let links = conn.get_links().await?;
for link in &links {
    println!("{}: up={}", link.name.as_deref().unwrap_or("?"), link.is_up());
}

// Typed builders with full options
let veth = VethLink::new("veth0", "veth1").mtu(9000);
conn.add_link(veth).await?;

// Event streaming
let mut stream = EventStream::builder().links(true).build()?;
while let Some(event) = stream.next().await? {
    match event {
        NetworkEvent::NewLink(link) => println!("New: {}", link.name.unwrap()),
        _ => {}
    }
}
```

---

## 12. Dependency Comparison

### rtnetlink Dependencies
```
rtnetlink
├── netlink-packet-route (TC, link, addr, route parsing)
│   └── netlink-packet-core
│       └── netlink-packet-utils
├── netlink-proto (async connection)
│   └── netlink-packet-core
├── netlink-sys (socket handling)
├── tokio
├── futures
├── thiserror
└── log
```

### nlink Dependencies
```
nlink
├── netlink-sys (socket only)
├── tokio (async runtime)
├── thiserror (errors)
├── inotify (optional: namespace_watcher)
└── nix (optional: tuntap)
```

**nlink**: Custom netlink implementation, fewer dependencies
**rtnetlink**: Uses netlink-packet-* ecosystem (more code reuse but more deps)

---

## 13. Priority Improvements for nlink

Based on this comparison, nlink should prioritize:

### High Priority (Parity with rtnetlink)

1. **Wireguard link type** - Popular VPN, rtnetlink supports it
2. **MACsec link type** - Network encryption, rtnetlink supports it
3. **Address replace operation** - rtnetlink has it
4. **NAT action** - rtnetlink has it
5. **tunnel_key action** - rtnetlink has it

### Medium Priority (Unique nlink advantages to maintain)

6. **More qdisc types** - nlink already leads, continue
7. **More filter types** - nlink already leads, continue
8. **Event streaming polish** - Unique to nlink
9. **Statistics tracking** - Unique to nlink

### Lower Priority

10. **xfrm link type** - Specialized use case
11. **netkit link type** - Container networking
12. **macvtap link type** - Virtualization

---

## 14. Feature Matrix Summary

```
                        iproute2    rtnetlink    nlink
                        --------    ---------    -----
Link Types:                31+          16         12
  - nlink missing:                   wireguard, macsec, macvtap, xfrm, netkit
  
Address Operations:        Full        Full      Full
  - nlink has:                                   labels, lifetimes
  
Route Operations:          Full        Full      Full
  - nlink has:                                   route lookup

Neighbor Operations:       Full        Full      Good
  - rtnetlink has:                    proxy ARP
  
TC Qdiscs (build):          31           2         12
  - nlink leads significantly
  
TC Filters (build):          9           3          6
  - nlink leads
  
TC Actions (build):         19           3          5
  - Different coverage, nlink has gact/police/vlan/skbedit
  - rtnetlink has nat/tunnel_key

High-level API:             No          No        Yes
Event Streaming:            No          No        Yes
Namespace Watching:         No          No        Yes
Statistics Tracking:        No          No        Yes
```

---

## Conclusion

**nlink** has significant advantages over **rtnetlink** in:
- High-level API design (`get_links()`, `EventStream`, etc.)
- TC support (qdiscs, filters, actions)
- Namespace support
- Custom lightweight netlink implementation
- Documentation

**rtnetlink** has advantages in:
- Some link types (wireguard, macsec, macvtap, xfrm, netkit)
- NAT and tunnel_key actions
- Mature ecosystem (netlink-packet-* crates)

**Recommendation**: nlink should add wireguard and macsec link types to achieve near-parity with rtnetlink, while maintaining its API design advantages.
