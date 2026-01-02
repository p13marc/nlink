# Nlink vs iproute2 Feature Comparison

This document compares the nlink Rust library with the iproute2 reference implementation to identify feature gaps and implementation priorities.

## Executive Summary

**nlink** is a Rust library focused on providing a well-designed API for programmatic network management. The binaries (`ip`, `tc`, `ss`) serve as proof-of-concept demonstrations.

**iproute2** is the comprehensive C reference implementation containing 10+ utilities covering nearly every aspect of Linux networking.

| Aspect | iproute2 | nlink |
|--------|----------|-------|
| Primary utilities | 10+ (ip, tc, ss, bridge, devlink, dcb, tipc, vdpa, dpll, rdma) | 3 (ip, tc, ss) |
| IP commands | 25+ | ~10 |
| TC qdiscs | 31 | 9 |
| TC filters | 9 | 0 (library only) |
| TC actions | 19 | 0 (library only) |
| Link types | 31+ | ~5 |
| Architecture | Synchronous C | Async Rust (tokio) |

---

## 1. IP Command Comparison

### Commands Supported

| Command | iproute2 | nlink | Notes |
|---------|:--------:|:-----:|-------|
| `ip link` | Full | Partial | nlink: show, add, del, set (up/down/mtu/name) |
| `ip address` | Full | Partial | nlink: show, add, del, flush |
| `ip route` | Full | Partial | nlink: show, add, del, get |
| `ip neighbor` | Full | Partial | nlink: show (basic) |
| `ip rule` | Full | Partial | nlink: show (basic) |
| `ip netns` | Full | Good | nlink: namespace-aware connections |
| `ip monitor` | Full | Good | nlink: EventStream API |
| `ip tunnel` | Full | Minimal | nlink: basic tunnel support |
| `ip tuntap` | Full | Good | nlink: TUN/TAP module (feature-gated) |
| `ip vrf` | Full | Minimal | |
| `ip xfrm` | Full | Minimal | nlink: placeholder only |
| `ip maddress` | Full | Minimal | |
| `ip addrlabel` | Full | None | |
| `ip token` | Full | None | |
| `ip tcpmetrics` | Full | None | |
| `ip l2tp` | Full | None | |
| `ip fou` | Full | None | |
| `ip ila` | Full | None | |
| `ip macsec` | Full | None | |
| `ip mroute` | Full | None | |
| `ip mrule` | Full | None | |
| `ip netconf` | Full | None | |
| `ip sr` (seg6) | Full | None | |
| `ip nexthop` | Full | None | |
| `ip mptcp` | Full | None | |
| `ip ioam` | Full | None | |
| `ip stats` | Full | None | |
| `ip ntable` | Full | None | |

### Link Types Supported

| Type | iproute2 | nlink | Notes |
|------|:--------:|:-----:|-------|
| Physical (eth, etc.) | Yes | Yes | Query/state management |
| dummy | Yes | No | |
| ifb | Yes | No | |
| veth | Yes | No | |
| vlan | Yes | No | |
| vxlan | Yes | No | |
| bridge | Yes | No | |
| bond | Yes | No | |
| macvlan/macvtap | Yes | No | |
| ipvlan/ipvtap | Yes | No | |
| gre/gretap | Yes | No | |
| ip6gre/ip6gretap | Yes | No | |
| ipip/sit/ip6tnl | Yes | No | |
| vti/vti6 | Yes | No | |
| geneve | Yes | No | |
| bareudp | Yes | No | |
| team | Yes | No | |
| vrf | Yes | No | |
| macsec | Yes | No | |
| can/vcan/vxcan | Yes | No | |
| gtp | Yes | No | |
| hsr | Yes | No | |
| ipoib | Yes | No | |
| netkit | Yes | No | |
| nlmon | Yes | No | |
| netdevsim | Yes | No | |
| amt | Yes | No | |
| erspan/ip6erspan | Yes | No | |
| wwan | Yes | No | |
| dsa | Yes | No | |
| TUN/TAP | Yes | Yes | nlink has tuntap module |

---

## 2. TC Command Comparison

### Queue Disciplines (Qdiscs)

| Qdisc | iproute2 | nlink Parse | nlink Build | Notes |
|-------|:--------:|:-----------:|:-----------:|-------|
| netem | Yes | Yes | Yes | Network emulation - fully supported |
| htb | Yes | Yes | Partial | Hierarchical Token Bucket |
| tbf | Yes | Yes | Partial | Token Bucket Filter |
| fq_codel | Yes | Yes | Partial | Fair Queue CoDel |
| fq | Yes | Yes | Partial | Fair Queue |
| codel | Yes | Yes | Partial | Controlled Delay |
| prio | Yes | Yes | Partial | Priority scheduling |
| sfq | Yes | Yes | Partial | Stochastic Fairness Queueing |
| cake | Yes | Yes | Partial | CAKE (Common Applications Kept Enhanced) |
| fifo | Yes | Partial | No | pfifo/bfifo |
| red | Yes | No | No | Random Early Detection |
| gred | Yes | No | No | Generic RED |
| choke | Yes | No | No | CHOKe |
| pie | Yes | No | No | PIE AQM |
| fq_pie | Yes | No | No | FQ + PIE |
| sfb | Yes | No | No | Stochastic Fair Blue |
| drr | Yes | No | No | Deficit Round Robin |
| qfq | Yes | No | No | Quick Fair Queueing |
| ets | Yes | No | No | Enhanced Transmission Selection |
| hfsc | Yes | No | No | Hierarchical Fair Service Curve |
| cbq | Yes | No | No | Class-Based Queueing |
| multiq | Yes | No | No | Multi-queue |
| skbprio | Yes | No | No | SKB Priority |
| hhf | Yes | No | No | Heavy-Hitter Filter |
| etf | Yes | No | No | Earliest TxTime First |
| taprio | Yes | No | No | Time-Aware Priority |
| mqprio | Yes | No | No | Multi-queue Priority |
| cbs | Yes | No | No | Credit-Based Shaper |
| plug | Yes | No | No | Plug/unplug traffic |
| dualpi2 | Yes | No | No | Dual PI2 |
| ingress | Yes | Partial | No | Ingress qdisc |
| clsact | Yes | Partial | No | Ingress+egress |

**Summary:** nlink supports 9 of 31 qdiscs for parsing/building.

### Filters

| Filter | iproute2 | nlink |
|--------|:--------:|:-----:|
| u32 | Yes | No |
| flower | Yes | No |
| bpf | Yes | No |
| basic | Yes | No |
| cgroup | Yes | No |
| flow | Yes | No |
| fw | Yes | No |
| matchall | Yes | No |
| route | Yes | No |

**Summary:** nlink has no filter building support (library can query but not create).

### Actions

| Action | iproute2 | nlink |
|--------|:--------:|:-----:|
| gact | Yes | No |
| mirred | Yes | No |
| police | Yes | No |
| pedit | Yes | No |
| vlan | Yes | No |
| mpls | Yes | No |
| nat | Yes | No |
| bpf | Yes | No |
| connmark | Yes | No |
| ct | Yes | No |
| ctinfo | Yes | No |
| csum | Yes | No |
| skbedit | Yes | No |
| skbmod | Yes | No |
| tunnel_key | Yes | No |
| ife | Yes | No |
| gate | Yes | No |
| sample | Yes | No |
| simple | Yes | No |

**Summary:** nlink has no action support.

### Ematch Types

| Ematch | iproute2 | nlink |
|--------|:--------:|:-----:|
| canid | Yes | No |
| cmp | Yes | No |
| ipset | Yes | No |
| ipt | Yes | No |
| meta | Yes | No |
| nbyte | Yes | No |
| u32 | Yes | No |
| bpf | Yes | No |

---

## 3. SS Command Comparison

| Feature | iproute2 | nlink |
|---------|:--------:|:-----:|
| TCP sockets | Yes | Yes |
| UDP sockets | Yes | Yes |
| Unix sockets | Yes | Yes |
| RAW sockets | Yes | Partial |
| SCTP sockets | Yes | No |
| DCCP sockets | Yes | No |
| VSOCK sockets | Yes | No |
| MPTCP sockets | Yes | No |
| Packet sockets | Yes | No |
| XDP sockets | Yes | No |
| TiPC sockets | Yes | No |
| Socket filtering | Yes | Partial |
| Timer information | Yes | Partial |
| Memory information | Yes | Partial |
| Extended TCP info | Yes | Yes |
| BPF info | Yes | No |
| cgroup info | Yes | No |

---

## 4. Missing Utilities (Not in nlink)

| Utility | Purpose | Priority |
|---------|---------|----------|
| `bridge` | Bridge VLAN/FDB/MDB management | Medium |
| `devlink` | Device abstraction/eSwitch | Low |
| `dcb` | Data Center Bridging | Low |
| `tipc` | TIPC protocol | Low |
| `vdpa` | vDPA devices | Low |
| `dpll` | DPLL management | Low |
| `rdma` | RDMA subsystem | Low |
| `genl` | Generic netlink | Low |
| `netshaper` | Network shaping | Low |

---

## 5. Library API Comparison

### Netlink Connection

| Feature | iproute2 (libnetlink) | nlink |
|---------|:---------------------:|:-----:|
| Async I/O | No (blocking) | Yes (tokio AsyncFd) |
| Request/Response | Yes | Yes |
| Dump operations | Yes | Yes |
| Multicast groups | Yes | Yes |
| Namespace support | Yes | Yes |
| Error handling | errno-based | Semantic error types |
| Builder pattern | No | Yes (MessageBuilder) |

### High-Level APIs

| Feature | iproute2 | nlink |
|---------|:--------:|:-----:|
| `get_links()` | Manual | Yes |
| `get_addresses()` | Manual | Yes |
| `get_routes()` | Manual | Yes |
| `get_neighbors()` | Manual | Yes |
| `get_qdiscs()` | Manual | Yes |
| `get_classes()` | Manual | Yes |
| `get_filters()` | Manual | Yes |
| Link state management | Manual | `set_link_up/down/mtu` |
| Event streaming | `rtnl_listen()` | `EventStream` |
| Stats tracking | Manual | `StatsSnapshot`/`StatsTracker` |
| Namespace watching | Manual | `NamespaceWatcher` (inotify) |

### nlink Unique Features

- **Async-first design**: All operations are async/await compatible
- **Strongly-typed messages**: `LinkMessage`, `AddressMessage`, `TcMessage`, etc.
- **Statistics tracking**: Built-in rate calculation across samples
- **Event streaming**: High-level `NetworkEvent` enum
- **Namespace watching**: inotify-based namespace creation/deletion events
- **TC option parsing**: Structured parsing of netem, HTB, FQ-CoDel options
- **Error semantics**: `is_not_found()`, `is_permission_denied()`, etc.

---

## 6. Implementation Priority Recommendations

### High Priority (Core Functionality)

1. **Link type creation** (veth, bridge, vlan, bond, vxlan)
   - Essential for container/network virtualization
   - Missing: `ip link add type X`

2. **Address management improvements**
   - Add: label support, valid/preferred lifetimes
   - Add: secondary address handling

3. **Route management improvements**
   - Add: multipath routes, ECMP
   - Add: route metrics (mtu, advmss, etc.)
   - Add: nexthop objects

4. **Neighbor management**
   - Add: add/del/change operations
   - Add: proxy ARP support

### Medium Priority (TC Enhancements)

5. **Filter support**
   - Priority: u32, flower, bpf
   - These are essential for packet classification

6. **Action support**
   - Priority: mirred, gact, police
   - Essential for traffic steering

7. **Additional qdiscs**
   - Priority: red, pie, ingress/clsact
   - Useful for advanced QoS

### Lower Priority (Extended Features)

8. **Tunnel creation**
   - gre, vxlan, geneve tunnels
   - ip6 variants

9. **XFrm (IPsec)**
   - SA/SP management
   - Crypto algorithm configuration

10. **Bridge utility equivalent**
    - FDB management
    - VLAN filtering

11. **Additional socket types for ss**
    - SCTP, DCCP, VSOCK

---

## 7. Code Statistics

### iproute2

| Component | Files | Lines (approx) |
|-----------|-------|----------------|
| ip/ | 50+ .c files | ~120,000 |
| tc/ | 80+ .c files | ~100,000 |
| lib/ | 33 .c files | ~20,000 |
| bridge/ | 10 .c files | ~8,000 |
| ss/ | 2 .c files | ~5,000 |
| Other utilities | 30+ .c files | ~40,000 |
| **Total** | **~200+ .c files** | **~300,000 lines** |

### nlink

| Component | Files | Lines (approx) |
|-----------|-------|----------------|
| crates/nlink/src/ | ~40 .rs files | ~15,000 |
| bins/ip/ | ~15 .rs files | ~3,000 |
| bins/tc/ | ~10 .rs files | ~2,000 |
| bins/ss/ | ~5 .rs files | ~1,000 |
| **Total** | **~70 .rs files** | **~21,000 lines** |

**Ratio**: iproute2 is approximately **14x larger** in code volume.

---

## 8. Feature Matrix Summary

```
                    iproute2    nlink
                    --------    -----
IP Commands:           25+        ~10  (40%)
Link Types:            31+         ~5  (16%)
TC Qdiscs:              31          9  (29%)
TC Filters:              9          0   (0%)
TC Actions:             19          0   (0%)
Socket Types:           11          4  (36%)
Separate Utilities:     10          3  (30%)
```

---

## Appendix A: iproute2 Link Types (Complete List)

1. amt
2. bareudp
3. bond, bond_slave
4. bridge, bridge_slave
5. can, vcan, vxcan
6. dsa
7. dummy
8. erspan, ip6erspan
9. geneve
10. gre, gretap, ip6gre, ip6gretap
11. gtp
12. hsr
13. ifb
14. ipoib
15. ipip, sit, ip6tnl
16. ipvlan, ipvtap
17. macvlan, macvtap
18. macsec
19. netdevsim
20. netkit
21. nlmon
22. rmnet
23. team, team_slave
24. veth
25. virt_wifi
26. vlan
27. vrf
28. vti, vti6
29. vxlan
30. wwan
31. xdp, xstats

## Appendix B: iproute2 TC Qdiscs (Complete List)

1. cake
2. cbs
3. choke
4. clsact
5. codel
6. drr
7. dualpi2
8. etf
9. ets
10. fifo (pfifo, bfifo)
11. fq
12. fq_codel
13. fq_pie
14. gred
15. hfsc
16. hhf
17. htb
18. ingress
19. mqprio
20. multiq
21. netem
22. pie
23. plug
24. prio
25. qfq
26. red
27. sfb
28. sfq
29. skbprio
30. taprio
31. tbf
