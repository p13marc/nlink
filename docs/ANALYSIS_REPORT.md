# nlink Project Analysis Report

*Analysis Date: January 2026*

## Executive Summary

**nlink** is a modern, from-scratch Rust implementation of Linux network management via netlink. The project provides both a library crate and CLI binaries (`ip`, `tc`, `ss`) that serve as proof-of-concept demonstrations. This report analyzes the project's architecture, compares it to alternatives (iproute2, rtnetlink crate), and identifies areas for improvement.

**Overall Assessment: 9/10** - Excellent foundation with comprehensive coverage of core networking features, exceptional code quality, and minor gaps in advanced functionality.

---

## Table of Contents

1. [Architecture Overview](#1-architecture-overview)
2. [Feature Coverage](#2-feature-coverage)
3. [Comparison with rtnetlink Crate](#3-comparison-with-rtnetlink-crate)
4. [Comparison with iproute2](#4-comparison-with-iproute2)
5. [Code Quality Analysis](#5-code-quality-analysis)
6. [Missing Features](#6-missing-features)
7. [Improvement Recommendations](#7-improvement-recommendations)
8. [Feature Ideas](#8-feature-ideas)

---

## 1. Architecture Overview

### Design Philosophy

nlink follows a **library-first architecture** with several key design decisions:

| Decision | Rationale |
|----------|-----------|
| Custom netlink implementation | Full control, no dependency on rtnetlink/netlink-packet-* ecosystem |
| Protocol-typed connections | Type safety via `Connection<Route>`, `Connection<Generic>`, etc. |
| Zero-copy serialization | Uses `zerocopy` crate for safe, efficient message handling |
| Async/tokio native | Modern async patterns with `AsyncFd` for netlink sockets |
| Single publishable crate | Feature flags control what's included (`sockdiag`, `tc`, `output`) |

### Crate Structure

```
crates/nlink/src/
  lib.rs              # Main entry point, re-exports
  netlink/            # Core netlink (~28,000 lines)
    connection.rs     # High-level request/response/dump handling
    socket.rs         # Low-level async socket
    builder.rs        # Message construction
    message.rs        # Netlink header parsing
    attr.rs           # Attribute (TLV) parsing
    error.rs          # Rich error types with semantic checks
    events.rs         # NetworkEvent enum for typed events
    stream.rs         # EventSource trait, Stream implementations
    types/            # Zero-copy message structures
    messages/         # Strongly-typed parsed messages
    genl/             # Generic Netlink (GENL) support
    tc.rs             # TC typed builders (19+ qdisc types)
    filter.rs         # TC filter builders (9 types)
    action.rs         # TC action builders (12 types)
    link.rs           # Link type builders (30+ types)
    route.rs          # Route management with ECMP
    ...
  sockdiag/           # Socket diagnostics (feature: sockdiag)
  tuntap/             # TUN/TAP management (feature: tuntap)
  tc/                 # TC utilities (feature: tc)
  output/             # JSON/text formatting (feature: output)
  util/               # Address parsing, rate parsing, etc.
```

### Supported Netlink Protocols

| Protocol | State Type | Purpose | Status |
|----------|------------|---------|--------|
| RTNetlink | `Route` | Links, addresses, routes, neighbors, TC | Complete |
| SOCK_DIAG | `SockDiag` | Socket diagnostics (TCP, UDP, Unix) | Complete |
| Generic Netlink | `Generic` | WireGuard, future GENL families | Complete |
| Kobject UEvent | `KobjectUevent` | Device hotplug events | Complete |
| Connector | `Connector` | Process lifecycle events | Complete |
| Netfilter | `Netfilter` | Connection tracking | Complete |
| XFRM | `Xfrm` | IPsec SA/SP management | Complete |
| FIB Lookup | `FibLookup` | FIB route lookups | Complete |
| SELinux | `SELinux` | SELinux event notifications | Complete |
| Audit | `Audit` | Linux Audit subsystem | Complete |

---

## 2. Feature Coverage

### Traffic Control (TC)

**Qdisc Types (19+ implemented):**

| Qdisc | Builder | Parsing | Notes |
|-------|---------|---------|-------|
| netem | `NetemConfig` | `NetemOptions` | Full support including loss models |
| fq_codel | `FqCodelConfig` | `FqCodelOptions` | Complete |
| htb | `HtbQdiscConfig` | `HtbOptions` | Qdisc only, class via `tc/builders/class.rs` |
| tbf | `TbfConfig` | `TbfOptions` | Complete |
| prio | `PrioConfig` | Parsing | Complete |
| sfq | `SfqConfig` | Parsing | Complete |
| red | `RedConfig` | - | Builder only |
| pie | `PieConfig` | - | Builder only |
| ingress | `IngressConfig` | - | Complete |
| clsact | `ClsactConfig` | - | For BPF programs |
| pfifo/bfifo | `PfifoConfig`/`BfifoConfig` | - | Complete |
| drr | `DrrConfig` | - | Classful |
| qfq | `QfqConfig` | - | Classful |
| hfsc | `HfscConfig` | - | Classful |
| mqprio | `MqprioConfig` | - | Hardware offload |
| taprio | `TaprioConfig` | - | IEEE 802.1Qbv |
| etf | `EtfConfig` | - | SO_TXTIME |
| plug | `PlugConfig` | - | Buffering |
| cake | - | `CakeOptions` | Parsing only |
| fq | - | `FqOptions` | Parsing only |
| codel | - | `CodelOptions` | Parsing only |

**Filter Types (9 implemented):**

| Filter | Builder | Notes |
|--------|---------|-------|
| u32 | `U32Filter` | Arbitrary header matching |
| flower | `FlowerFilter` | L2/L3/L4 matching |
| matchall | `MatchallFilter` | Match all packets |
| fw | `FwFilter` | Firewall mark classification |
| bpf | `BpfFilter` | eBPF program classification |
| basic | `BasicFilter` | Simple with ematch |
| cgroup | `CgroupFilter` | Cgroup-based |
| route | `RouteFilter` | Routing realm-based |
| flow | `FlowFilter` | Multi-key hashing |

**Action Types (12 implemented):**

| Action | Builder | Notes |
|--------|---------|-------|
| gact | `GactAction` | Drop, pass, pipe, reclassify |
| mirred | `MirredAction` | Redirect/mirror |
| police | `PoliceAction` | Rate limiting |
| vlan | `VlanAction` | VLAN manipulation |
| skbedit | `SkbeditAction` | SKB metadata |
| nat | `NatAction` | Stateless NAT |
| tunnel_key | `TunnelKeyAction` | Tunnel metadata |
| connmark | `ConnmarkAction` | Connection mark |
| csum | `CsumAction` | Checksum recalc |
| sample | `SampleAction` | Packet sampling |
| ct | `CtAction` | Connection tracking |
| pedit | `PeditAction` | Packet header editing |

### Link Types (30+ implemented)

**Virtual Interfaces:**
- DummyLink, VethLink, BridgeLink, BondLink, VlanLink
- MacvlanLink, MacvtapLink, IpvlanLink, IfbLink
- NetkitLink (BPF-optimized), NlmonLink (debug), VirtWifiLink

**Tunnels:**
- VxlanLink, GeneveLink, BareudpLink
- GreLink, GretapLink, IpipLink, SitLink
- VtiLink, Vti6Link, Ip6GreLink, Ip6GretapLink

**Special:**
- VrfLink (Virtual Routing and Forwarding)
- WireguardLink (via GENL)

### Other Features

- **Route management**: IPv4/IPv6 routes with ECMP/multipath support
- **Address management**: Full CRUD operations
- **Neighbor management**: ARP/NDP cache with FDB attributes
- **Routing rules**: Policy-based routing
- **Network namespaces**: Create, delete, list, exec, watch
- **Event monitoring**: Stream-based API with `tokio-stream` compatibility
- **Statistics tracking**: Link/TC stats with rate calculation

---

## 3. Comparison with rtnetlink Crate

### Overview

The [rust-netlink/rtnetlink](https://github.com/rust-netlink/rtnetlink) crate (v0.20.0) is the primary alternative in the Rust ecosystem. It's part of the rust-netlink organization (formerly netlink-rs).

### Architecture Comparison

| Aspect | nlink | rtnetlink |
|--------|-------|-----------|
| **Dependencies** | Minimal (zerocopy, winnow, tokio) | Heavy (netlink-packet-*, netlink-proto, netlink-sys) |
| **Netlink parsing** | Custom zero-copy implementation | netlink-packet-* crates |
| **Async support** | Tokio-native | Tokio via netlink-proto |
| **Type safety** | Protocol-typed connections | Request/handle types |
| **Documentation** | Comprehensive (library.md, examples) | 19.85% documented |
| **Maturity** | Newer (v0.5.1) | Mature (v0.20.0, 265 commits) |

### Feature Comparison

| Feature | nlink | rtnetlink |
|---------|-------|-----------|
| Link management | Complete | Complete |
| Address management | Complete | Complete |
| Route management | Complete with ECMP | Complete |
| Neighbor management | Complete | Complete |
| TC (qdisc/class/filter) | 19 qdiscs, 9 filters, 12 actions | Basic (5-6 qdiscs) |
| WireGuard | Complete via GENL | Separate crate |
| Socket diagnostics | Complete | Separate crate |
| Namespace support | Complete with watcher | Basic |
| Event monitoring | Stream API with multi-source | Basic |
| Generic Netlink | Full family resolution | Separate crate |
| Process events | Connector protocol | Not available |
| Device events | KobjectUevent | Not available |
| IPsec (XFRM) | Complete | Not available |
| Connection tracking | Netfilter protocol | Separate crate |
| SELinux events | Complete | Not available |
| Audit | Complete | Not available |

### Advantages of nlink

1. **Comprehensive TC support**: Far more qdisc types, filters, and actions
2. **Unified crate**: Single crate with feature flags vs. fragmented ecosystem
3. **Protocol coverage**: 11 netlink protocols vs. primarily RTNetlink
4. **Zero-copy**: More efficient message handling
5. **Stream API**: Modern async patterns with multi-namespace monitoring
6. **Documentation**: Better documented with 32 examples

### Advantages of rtnetlink

1. **Maturity**: More production usage and community testing
2. **Ecosystem**: Part of established rust-netlink organization
3. **Stability**: More stable API with semantic versioning history

---

## 4. Comparison with iproute2

### Command Coverage

| iproute2 Command | nlink CLI | Library Support | Notes |
|------------------|-----------|-----------------|-------|
| `ip link` | `ip link` | Complete | 30+ link types |
| `ip address` | `ip address` | Complete | Full CRUD |
| `ip route` | `ip route` | Complete | ECMP, metrics |
| `ip neighbor` | `ip neighbor` | Complete | ARP/NDP |
| `ip rule` | `ip rule` | Complete | Policy routing |
| `ip netns` | `ip netns` | Complete | With watcher |
| `ip monitor` | `ip monitor` | Complete | Stream API |
| `ip tunnel` | `ip tunnel` | Complete | GRE, IPIP, SIT, VTI |
| `ip vrf` | `ip vrf` | Complete | VRF management |
| `ip xfrm` | `ip xfrm` | Complete | IPsec SA/SP |
| `ip maddress` | `ip maddress` | Partial | Query only |
| `ip bridge` | - | Partial | No FDB/VLAN mgmt |
| `ip nexthop` | - | Missing | Nexthop groups |
| `ip mroute` | - | Missing | Multicast routing |
| `ip macsec` | - | Missing | MACsec config |
| `ip mptcp` | - | Missing | MPTCP endpoints |
| `ip sr` | - | Missing | Segment routing |
| `ip fou` | - | Missing | Foo-over-UDP |
| `ip addrlabel` | - | Missing | IPv6 addr labels |
| `ip tcp_metrics` | - | Missing | TCP metrics |
| `tc qdisc` | `tc qdisc` | Complete | 19+ types |
| `tc class` | `tc class` | Complete | HTB builder |
| `tc filter` | `tc filter` | Complete | 9 types |
| `tc action` | `tc action` | Complete | 12 types |
| `tc monitor` | `tc monitor` | Complete | Stream API |
| `tc chain` | - | Missing | Filter chains |
| `ss` | `ss` | Complete | TCP/UDP/Unix/MPTCP |

### Feature Gap Analysis

**Major Gaps:**

1. **MPLS Support**
   - iproute2: `ip route add ... encap mpls 100/200`
   - nlink: No RTA_ENCAP/RTA_ENCAP_TYPE handling
   - Impact: Cannot configure MPLS label stacks

2. **Segment Routing (SRv6)**
   - iproute2: `ip route add ... encap seg6 mode encap segs ...`
   - nlink: No seg6 encapsulation support
   - Impact: Cannot configure SRv6 tunnels

3. **Nexthop Groups**
   - iproute2: `ip nexthop add id 1 group 2/3`
   - nlink: No RTM_NEWNEXTHOP message support
   - Impact: Cannot use modern ECMP management (Linux 5.3+)

4. **Bridge FDB Management**
   - iproute2: `bridge fdb add/del/show`
   - nlink: Has NDA_* attributes but no dedicated API
   - Impact: Cannot manage bridge forwarding database

5. **Bridge VLAN Filtering**
   - iproute2: `bridge vlan add vid 100 dev eth0`
   - nlink: Bridge creation with vlan_filtering, but no per-port VLAN config
   - Impact: Cannot configure per-port VLANs

6. **MPTCP Configuration**
   - iproute2: `ip mptcp endpoint add ...`
   - nlink: Can query MPTCP sockets via sockdiag, no endpoint config
   - Impact: Cannot configure MPTCP endpoints

**Minor Gaps:**

- MACsec configuration (via GENL)
- IPv6 address labels
- TCP metrics management
- Multicast routing tables
- TC filter chains

---

## 5. Code Quality Analysis

### Strengths

**Type Safety:**
- Protocol-typed connections prevent misuse
- Sealed trait pattern for protocol types
- Builder patterns for all complex configurations
- Zero unsafe code in types module (uses zerocopy)

**Error Handling:**
```rust
// Rich semantic error checks
match conn.del_qdisc("eth0", "root").await {
    Err(e) if e.is_not_found() => { /* expected */ }
    Err(e) if e.is_permission_denied() => { /* need root */ }
    Err(e) if e.is_busy() => { /* retry later */ }
    Err(e) if e.is_invalid_argument() => { /* bad params */ }
    ...
}
```

**Documentation:**
- Comprehensive CLAUDE.md (800+ lines)
- docs/library.md with usage patterns
- 32 working examples across 14 categories
- Module-level docs with code examples

**Testing:**
- Unit tests in 19+ files
- Test fixtures for message parsing
- CLI parsing tests
- No TODOs/FIXMEs in codebase

### Areas for Improvement

**Test Coverage:**
- Estimated 15-20% unit test coverage
- Missing integration tests (require root/namespace)
- No fuzzing for netlink message parsing
- No benchmarks

**API Consistency:**
- TC class management exists in `tc/builders/class.rs` but not exposed on `Connection<Route>`
- Some operations have both `*_by_name()` and `*_by_index()` variants, others don't

---

## 6. Missing Features

### Priority 1: High Impact, Commonly Used

| Feature | Effort | Description |
|---------|--------|-------------|
| Bridge FDB API | Medium | `add_fdb()`, `del_fdb()`, `get_fdb()` methods |
| Bridge VLAN API | Medium | Per-port VLAN configuration |
| Expose TC class on Connection | Low | Add `add_class()`, `del_class()` to `Connection<Route>` |
| Nexthop Groups | High | RTM_NEWNEXTHOP/DELNEXTHOP support |

### Priority 2: Medium Impact

| Feature | Effort | Description |
|---------|--------|-------------|
| MPLS Routes | High | RTA_ENCAP handling, label stack support |
| Segment Routing (SRv6) | High | seg6 encapsulation |
| MACsec | Medium | GENL-based MACsec configuration |
| MPTCP Configuration | Medium | Endpoint management |
| TC Filter Chains | Low | Chain management for complex filtering |

### Priority 3: Niche Features

| Feature | Effort | Description |
|---------|--------|-------------|
| Foo-over-UDP (FOU) | Medium | UDP encapsulation |
| IPv6 Address Labels | Low | Prefix policy table |
| TCP Metrics | Low | Per-destination metrics |
| Multicast Routing | Medium | MROUTE protocol |

---

## 7. Improvement Recommendations

### Short Term (Low Effort, High Value)

1. **Expose TC class management on Connection**
   ```rust
   // Already exists in tc/builders/class.rs, just needs exposure
   impl Connection<Route> {
       pub async fn add_class(&self, dev: &str, parent: &str, 
                              classid: &str, config: impl ClassConfig) -> Result<()>;
       pub async fn del_class(&self, dev: &str, classid: &str) -> Result<()>;
   }
   ```

2. **Add convenience methods for bridge FDB**
   - The NDA_* attributes are already parsed in messages/neighbor.rs
   - Need high-level API: `get_fdb("br0")`, `add_fdb("br0", mac, vlan)`

3. **Create typed HtbClassConfig builder**
   ```rust
   let class = HtbClassConfig::new()
       .rate("10mbit")
       .ceil("100mbit")
       .burst("15k")
       .build();
   conn.add_class("eth0", "1:0", "1:10", class).await?;
   ```

### Medium Term

4. **Add integration test infrastructure**
   - Use network namespaces for isolated testing
   - Add CI support with namespace-based tests
   - Implement test fixtures for common scenarios

5. **MPLS route support**
   - Parse RTA_ENCAP and RTA_ENCAP_TYPE
   - Add `MplsRoute` builder with label stack
   - Requires ~400 lines

6. **Nexthop group support**
   - Add RTM_NEWNEXTHOP/DELNEXTHOP message types
   - Implement `NexthopGroup` builder
   - Integrate with route multipath

### Long Term

7. **Segment Routing (SRv6)**
   - seg6_local and seg6_iptunnel support
   - Requires kernel interface research

8. **MACsec via Generic Netlink**
   - Family resolution like WireGuard
   - Full cipher suite configuration

---

## 8. Feature Ideas

### Cool Features to Add

1. **Network Diagnostics Tool**
   - Combine link stats, TC stats, and route lookups
   - Real-time bandwidth monitoring per-interface
   - Detect packet drops and identify bottleneck qdiscs

2. **Configuration Diffing**
   - Compare current state vs. desired state
   - Generate minimal set of changes needed
   - Useful for infrastructure-as-code

3. **Declarative Network Config**
   ```rust
   let config = NetworkConfig::new()
       .link("eth0", |l| l.mtu(9000).up())
       .address("eth0", "192.168.1.1/24")
       .route("10.0.0.0/8", |r| r.via("192.168.1.254"))
       .qdisc("eth0", |q| q.htb().default_class("1:10"));
   
   config.apply(&conn).await?;
   ```

4. **Network Topology Discovery**
   - Scan neighbors, routes, bridge FDBs
   - Build graph of connected devices
   - Export as DOT/GraphViz

5. **Event Replay/Recording**
   - Record network events to file
   - Replay for testing/debugging
   - Useful for reproducing issues

6. **eBPF Integration**
   - Load and attach BPF programs to TC
   - Query BPF map contents
   - Integrate with libbpf-rs

7. **Rate Limiting DSL**
   ```rust
   // High-level rate limiting API
   conn.limit("eth0")
       .ingress("1gbit")
       .egress("100mbit")
       .with_burst("15kb")
       .apply().await?;
   ```

8. **Network Namespace Orchestration**
   - Create complex namespace topologies
   - Connect with veth pairs automatically
   - Useful for testing network applications

9. **Prometheus Metrics Exporter**
   - Export link/TC stats as Prometheus metrics
   - Real-time counters and gauges
   - Could be a separate crate using nlink

10. **Container Network Plugin**
    - CNI-compatible plugin using nlink
    - Demonstrate library capabilities
    - Alternative to shell-based plugins

---

## Conclusion

nlink is an exceptionally well-designed Rust library for Linux network management. Its custom netlink implementation, comprehensive TC support, and clean async API make it a strong alternative to the rtnetlink ecosystem. The main areas for improvement are:

1. **Bridge FDB/VLAN management** - commonly needed for container networking
2. **MPLS/SRv6 support** - required for modern service provider networks
3. **Nexthop groups** - the modern way to configure ECMP (Linux 5.3+)
4. **Test coverage** - integration tests with namespaces

The library is production-ready for:
- Network monitoring and queries
- Basic link/address/route management
- Traffic control with netem, HTB, fq_codel
- Event streaming and multi-namespace monitoring
- WireGuard and IPsec configuration

The architecture is solid and extensible, making it straightforward to add the missing features over time.

---

## Sources

- [rtnetlink crate documentation](https://docs.rs/rtnetlink/latest/rtnetlink/)
- [rust-netlink/rtnetlink GitHub](https://github.com/rust-netlink/rtnetlink)
- [iproute2 man pages](https://manpages.debian.org/testing/iproute2/)
- [ip-nexthop man page](https://man7.org/linux/man-pages/man8/ip-nexthop.8.html)
- [iproute2 task-centered guide](https://baturin.org/docs/iproute2/)
