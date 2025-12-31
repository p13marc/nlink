# Feature Comparison: rip vs iproute2

## Summary

| Category | iproute2 | rip | Coverage |
|----------|----------|-----|----------|
| ip subcommands | 25+ | 11 | ~44% |
| Link types | 40+ | 15 | ~38% |
| tc qdiscs | 30+ | 7 | ~23% |
| tc filters | 8 | 0 | 0% |
| tc actions | 18 | 0 | 0% |

---

## IP Command

### Subcommands

| Subcommand | iproute2 | rip | Notes |
|------------|----------|-----|-------|
| `ip link` | ✅ | ✅ | show, add, del, set |
| `ip address` | ✅ | ✅ | show, add, del, flush |
| `ip route` | ✅ | ✅ | show, add, del, replace, get |
| `ip neighbor` | ✅ | ✅ | show, add, del, flush |
| `ip rule` | ✅ | ✅ | show, add, del |
| `ip netns` | ✅ | ✅ | show, add, del, exec |
| `ip monitor` | ✅ | ✅ | link, address, route, tc |
| `ip tunnel` | ✅ | ✅ | show, add, del |
| `ip maddress` | ✅ | ✅ | show |
| `ip vrf` | ✅ | ✅ | show, exec |
| `ip xfrm` | ✅ | 🔶 | Basic only |
| `ip addrlabel` | ✅ | ❌ | Address labels for IPv6 |
| `ip fou` | ✅ | ❌ | Foo-over-UDP |
| `ip ila` | ✅ | ❌ | Identifier-Locator Addressing |
| `ip ioam` | ✅ | ❌ | In-situ OAM |
| `ip l2tp` | ✅ | ❌ | L2TP tunnels |
| `ip macsec` | ✅ | ❌ | MACsec |
| `ip mptcp` | ✅ | ❌ | Multipath TCP |
| `ip mroute` | ✅ | ❌ | Multicast routing |
| `ip netconf` | ✅ | ❌ | Network configuration |
| `ip nexthop` | ✅ | ❌ | Nexthop objects |
| `ip ntable` | ✅ | ❌ | Neighbor table params |
| `ip stats` | ✅ | ❌ | Interface statistics |
| `ip tcp_metrics` | ✅ | ❌ | TCP metrics cache |
| `ip token` | ✅ | ❌ | IPv6 tokenized IIDs |
| `ip tuntap` | ✅ | ❌ | TUN/TAP devices |

### Link Types Supported

| Type | iproute2 | rip | Notes |
|------|----------|-----|-------|
| dummy | ✅ | ✅ | |
| veth | ✅ | ✅ | |
| bridge | ✅ | ✅ | STP, VLAN filtering |
| bond | ✅ | ✅ | All modes, miimon, hash policy |
| vlan | ✅ | ✅ | 802.1q/802.1ad |
| vxlan | ✅ | ✅ | VNI, remote, local, learning |
| macvlan | ✅ | ✅ | All modes |
| macvtap | ✅ | ✅ | All modes |
| ipvlan | ✅ | ✅ | l2, l3, l3s |
| vrf | ✅ | ✅ | |
| gre | ✅ | ✅ | |
| gretap | ✅ | ✅ | |
| ipip | ✅ | ✅ | |
| sit | ✅ | ✅ | IPv6-in-IPv4 |
| wireguard | ✅ | ✅ | Create only (config via wg tool) |
| amt | ✅ | ❌ | Automatic Multicast Tunneling |
| bareudp | ✅ | ❌ | Bare UDP encapsulation |
| batadv | ✅ | ❌ | B.A.T.M.A.N. Advanced |
| can | ✅ | ❌ | CAN bus |
| dsa | ✅ | ❌ | Distributed Switch Architecture |
| geneve | ✅ | ❌ | Generic Network Virtualization |
| gtp | ✅ | ❌ | GPRS Tunneling Protocol |
| hsr | ✅ | ❌ | High-availability Seamless Redundancy |
| ifb | ✅ | ❌ | Intermediate Functional Block |
| ipoib | ✅ | ❌ | IP over InfiniBand |
| ip6gre | ✅ | ❌ | IPv6 GRE |
| ip6gretap | ✅ | ❌ | IPv6 GRE TAP |
| ip6tnl | ✅ | ❌ | IPv6 tunnels |
| netdevsim | ✅ | ❌ | Network device simulator |
| netkit | ✅ | ❌ | BPF network kit |
| nlmon | ✅ | ❌ | Netlink monitor |
| rmnet | ✅ | ❌ | Qualcomm rmnet |
| team | ✅ | ❌ | Network team device |
| vcan | ✅ | ❌ | Virtual CAN |
| virt_wifi | ✅ | ❌ | Virtual WiFi |
| vti | ✅ | ❌ | Virtual Tunnel Interface |
| vti6 | ✅ | ❌ | IPv6 VTI |
| vxcan | ✅ | ❌ | Virtual CAN tunnel |
| wwan | ✅ | ❌ | WWAN devices |
| xfrm | ✅ | ❌ | XFRM interface |

---

## TC Command

### Qdiscs (Queuing Disciplines)

| Qdisc | iproute2 | rip | Notes |
|-------|----------|-----|-------|
| fq_codel | ✅ | ✅ | Fair Queue CoDel |
| htb | ✅ | ✅ | Hierarchical Token Bucket |
| tbf | ✅ | ✅ | Token Bucket Filter |
| netem | ✅ | ✅ | Network Emulator |
| prio | ✅ | ✅ | Priority scheduler |
| sfq | ✅ | ✅ | Stochastic Fairness Queuing |
| ingress | ✅ | ✅ | Ingress qdisc |
| clsact | ✅ | 🔶 | Partial (via ingress) |
| cake | ✅ | ❌ | Common Applications Kept Enhanced |
| cbs | ✅ | ❌ | Credit Based Shaper |
| choke | ✅ | ❌ | CHOKe packet scheduler |
| codel | ✅ | ❌ | Controlled Delay |
| drr | ✅ | ❌ | Deficit Round Robin |
| dualpi2 | ✅ | ❌ | Dual PI2 |
| etf | ✅ | ❌ | Earliest TxTime First |
| ets | ✅ | ❌ | Enhanced Transmission Selection |
| fifo | ✅ | ❌ | FIFO (pfifo, bfifo) |
| fq | ✅ | ❌ | Fair Queue |
| fq_pie | ✅ | ❌ | FQ with PIE AQM |
| gred | ✅ | ❌ | Generic RED |
| hfsc | ✅ | ❌ | Hierarchical Fair Service Curve |
| hhf | ✅ | ❌ | Heavy-Hitter Filter |
| mqprio | ✅ | ❌ | Multiqueue Priority |
| multiq | ✅ | ❌ | Multiqueue scheduler |
| pie | ✅ | ❌ | Proportional Integral controller-Enhanced |
| plug | ✅ | ❌ | Plug/unplug traffic |
| qfq | ✅ | ❌ | Quick Fair Queuing |
| red | ✅ | ❌ | Random Early Detection |
| sfb | ✅ | ❌ | Stochastic Fair Blue |
| skbprio | ✅ | ❌ | SKB priority scheduler |
| taprio | ✅ | ❌ | Time Aware Priority |

### Classes

| Class | iproute2 | rip | Notes |
|-------|----------|-----|-------|
| htb class | ✅ | ✅ | rate, ceil, burst, prio |
| hfsc class | ✅ | ❌ | |
| drr class | ✅ | ❌ | |
| qfq class | ✅ | ❌ | |
| cbs class | ✅ | ❌ | |

### Filters

| Filter | iproute2 | rip | Notes |
|--------|----------|-----|-------|
| u32 | ✅ | ❌ | Universal 32-bit match |
| flower | ✅ | ❌ | Flow-based classification |
| bpf | ✅ | ❌ | BPF programs |
| basic | ✅ | ❌ | Basic ematch |
| cgroup | ✅ | ❌ | Cgroup classification |
| flow | ✅ | ❌ | Flow classification |
| fw | ✅ | ❌ | Firewall mark |
| matchall | ✅ | ❌ | Match all packets |
| route | ✅ | ❌ | Route-based classification |

### Actions

| Action | iproute2 | rip | Notes |
|--------|----------|-----|-------|
| gact | ✅ | ❌ | Generic action (drop, pass, etc.) |
| mirred | ✅ | ❌ | Mirror/redirect |
| police | ✅ | ❌ | Rate policing |
| pedit | ✅ | ❌ | Packet editing |
| nat | ✅ | ❌ | NAT action |
| bpf | ✅ | ❌ | BPF action |
| connmark | ✅ | ❌ | Connection tracking mark |
| csum | ✅ | ❌ | Checksum update |
| ct | ✅ | ❌ | Connection tracking |
| ctinfo | ✅ | ❌ | CT info restoration |
| gate | ✅ | ❌ | Gate scheduling |
| ife | ✅ | ❌ | Inter-FE encapsulation |
| mpls | ✅ | ❌ | MPLS actions |
| sample | ✅ | ❌ | Packet sampling |
| simple | ✅ | ❌ | Simple action |
| skbedit | ✅ | ❌ | SKB editing |
| skbmod | ✅ | ❌ | SKB modification |
| tunnel_key | ✅ | ❌ | Tunnel key manipulation |
| vlan | ✅ | ❌ | VLAN actions |

---

## Other Tools

| Tool | iproute2 | rip | Notes |
|------|----------|-----|-------|
| bridge | ✅ | ❌ | Bridge management |
| ss | ✅ | ❌ | Socket statistics |
| devlink | ✅ | ❌ | Device link management |
| dcb | ✅ | ❌ | Data Center Bridging |
| rdma | ✅ | ❌ | RDMA configuration |
| tipc | ✅ | ❌ | TIPC configuration |
| vdpa | ✅ | ❌ | vDPA configuration |
| netshaper | ✅ | ❌ | Network shaper |
| genl | ✅ | ❌ | Generic netlink tool |
| dpll | ✅ | ❌ | DPLL configuration |

---

## Feature Priority Recommendations

### High Priority (Common Use Cases)

1. **tc filters** - u32 and flower are essential for traffic classification
2. **tc actions** - gact (drop/pass), mirred (redirect), police (rate limiting)
3. **ip tuntap** - TUN/TAP device management (VPNs, containers)
4. **ip nexthop** - Modern routing uses nexthop objects
5. **More qdiscs** - cake, fq, codel are popular

### Medium Priority

6. **ip l2tp** - L2TP tunnels for VPNs
7. **ip mroute** - Multicast routing
8. **bridge command** - Bridge VLAN, FDB management
9. **tc bpf** - eBPF support for programmable networking
10. **Link types** - geneve, team, ifb

### Lower Priority (Specialized)

11. **ss command** - Socket statistics
12. **ip macsec** - Layer 2 encryption
13. **ip mptcp** - Multipath TCP
14. **Other link types** - CAN, WWAN, etc.

---

## Typed API Coverage

rip provides typed builder APIs for:
- ✅ NetemConfig (delay, jitter, loss, duplicate, corrupt, reorder, rate)
- ✅ FqCodelConfig (target, interval, limit, flows, quantum, ecn)
- ✅ TbfConfig (rate, burst, limit, mtu, peakrate)
- ✅ HtbQdiscConfig (default_class, r2q, direct_qlen)
- ✅ PrioConfig (bands, priomap)
- ✅ SfqConfig (perturb, limit, quantum)

Missing typed APIs:
- ❌ HtbClassConfig (rate, ceil, burst, cburst, prio)
- ❌ Filter configurations
- ❌ Action configurations
