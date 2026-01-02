# nlink Roadmap: Surpassing rtnetlink

This document outlines a detailed plan to make **nlink** better than **rtnetlink** in every aspect, organized into phases with specific implementation tasks.

---

## Current Status

| Category | rtnetlink | nlink | Gap |
|----------|:---------:|:-----:|:---:|
| Link Types | 16 | **17** | **+1** ✅ |
| Address Ops | Full | **Full** | **0** ✅ (labels/lifetimes/replace) |
| Route Ops | Full | Full | 0 (nlink has route get) |
| Neighbor Ops | Full | **Full** | **0** ✅ (proxy ARP complete) |
| TC Qdiscs | 2 | 12 | +10 |
| TC Filters | 3 | **8** | **+5** ✅ |
| TC Actions | 3 | **10** | **+7** ✅ |
| High-level API | No | Yes | +1 |
| Namespaces | No | Yes | +1 |

**Progress**: Phases 1-3 complete, Phase 4 partial (3/5 actions), Phase 5 partial (2/3 filters).

**Next Goal**: Continue with Phase 6 qdiscs or complete remaining complex items.

---

## Implementation Notes from iproute2 Analysis

### Key Findings

1. **WireGuard** uses **Generic Netlink (GENL)**, not RTNetlink - requires separate protocol handling
2. **MACsec** also uses **Generic Netlink** for SA/SC management (complex)
3. **MACsec link creation** uses standard RTNetlink but configuration uses GENL
4. **NAT action** and **tunnel_key action** are straightforward RTNetlink TC actions
5. **Simple link types** (ifb, macvtap, geneve, bareudp) are trivial to implement

### Netlink Message Pattern (from iproute2)
```c
// Add attribute with data
addattr_l(n, MAX_MSG, type, data, len);
// Start nested attribute
tail = addattr_nest(n, MAX_MSG, type);
// End nested attribute
addattr_nest_end(n, tail);
```

This maps directly to nlink's `MessageBuilder`:
```rust
builder.append_attr(type, data);
let token = builder.nest_start(type);
builder.nest_end(token);
```

---

## Phase 1: Easy Wins - Simple Link Types (Priority: High)

These link types use standard RTNetlink and are trivial to implement.

### 1.1 IFB (Intermediate Functional Block)
**Effort**: Trivial | **Value**: Medium (traffic redirection)

```rust
// Target API - identical to dummy, no options
let ifb = IfbLink::new("ifb0");
conn.add_link(ifb).await?;
```

**Implementation**: Copy DummyLink pattern, change kind to "ifb"

### 1.2 macvtap Link Type
**Effort**: Trivial | **Value**: Medium (virtualization)

```rust
// Target API - identical to macvlan
let macvtap = MacvtapLink::new("macvtap0", "eth0")
    .mode(MacvlanMode::Bridge);
conn.add_link(macvtap).await?;
```

**Implementation**: Copy MacvlanLink, change kind to "macvtap"

### 1.3 geneve Link Type
**Effort**: Low | **Value**: Medium (overlay networking)

```rust
// Target API
let geneve = GeneveLink::new("geneve0", 100)  // VNI
    .remote("10.0.0.1".parse()?)
    .remote6("2001:db8::1".parse()?)
    .ttl(64)
    .tos(0)
    .df(DfMode::Set)
    .port(6081)
    .label(0)
    .udp_csum(true)
    .udp6_zero_csum_tx(false)
    .collect_metadata(false);
conn.add_link(geneve).await?;
```

**Attributes (from iplink_geneve.c)**:
- IFLA_GENEVE_ID (u32) - VNI
- IFLA_GENEVE_REMOTE (be32) / IFLA_GENEVE_REMOTE6 (in6_addr)
- IFLA_GENEVE_TTL (u8), IFLA_GENEVE_TOS (u8)
- IFLA_GENEVE_DF (u8) - 0=unset, 1=set, 2=inherit
- IFLA_GENEVE_PORT (be16)
- IFLA_GENEVE_LABEL (be32)
- IFLA_GENEVE_UDP_CSUM (u8)
- IFLA_GENEVE_UDP_ZERO_CSUM6_TX/RX (u8)
- IFLA_GENEVE_COLLECT_METADATA (flag)
- IFLA_GENEVE_INNER_PROTO_INHERIT (flag)
- IFLA_GENEVE_TTL_INHERIT (flag)

### 1.4 bareudp Link Type
**Effort**: Low | **Value**: Low (MPLS/IP encap)

```rust
// Target API
let bareudp = BareudpLink::new("bareudp0")
    .port(6635)
    .ethertype(0x6558)   // MPLS unicast
    .srcport_min(true)
    .multiproto(false);
conn.add_link(bareudp).await?;
```

**Attributes (from iplink_bareudp.c)**:
- IFLA_BAREUDP_PORT (be16)
- IFLA_BAREUDP_ETHERTYPE (be16)
- IFLA_BAREUDP_SRCPORT_MIN (flag)
- IFLA_BAREUDP_MULTIPROTO_MODE (flag)

### 1.5 netkit Link Type
**Effort**: Low | **Value**: Medium (container networking)

```rust
// Target API
let netkit = NetkitLink::new("nk0")
    .mode(NetkitMode::L2)  // or L3
    .policy(NetkitPolicy::Forward)  // or Blackhole
    .peer_policy(NetkitPolicy::Forward)
    .peer("nk1");
conn.add_link(netkit).await?;
```

**Attributes (from iplink_netkit.c)**:
- IFLA_NETKIT_MODE (u32) - 0=L3, 1=L2
- IFLA_NETKIT_POLICY (u32) - default action
- IFLA_NETKIT_PEER_POLICY (u32) - peer default action
- IFLA_NETKIT_PEER_INFO (nested) - peer ifinfomsg + attrs

### Phase 1 Deliverables
- [x] IfbLink (trivial) ✅ **DONE**
- [x] MacvtapLink (trivial) ✅ **DONE**
- [x] GeneveLink (low effort) ✅ **DONE**
- [x] BareudpLink (low effort) ✅ **DONE**
- [x] NetkitLink (low effort) ✅ **DONE**

**Phase 1 COMPLETE: nlink has 17 link types vs rtnetlink's 16** ✓

---

## Phase 2: TC Actions Parity (Priority: High)

Close the gap on the 2 actions rtnetlink has that nlink doesn't.

### 2.1 NAT Action
**Effort**: Low | **Value**: Medium

**From m_nat.c**:
```c
struct tc_nat {
    tc_gen;              // index, capab, action, refcnt, bindcnt
    __be32 old_addr;     // Original IP
    __be32 new_addr;     // Replacement IP
    __be32 mask;         // Network mask
    __u32 flags;         // TCA_NAT_FLAG_EGRESS or 0 (ingress)
};
```

```rust
// Target API
use nlink::netlink::action::NatAction;

// Ingress NAT: rewrite destination
let nat = NatAction::ingress("192.168.1.0/24".parse()?, "10.0.0.0/24".parse()?);

// Egress NAT: rewrite source
let nat = NatAction::egress("192.168.1.0/24".parse()?, "10.0.0.0/24".parse()?);

// Full builder
let nat = NatAction::new()
    .old_addr(Ipv4Addr::new(192, 168, 1, 0))
    .new_addr(Ipv4Addr::new(10, 0, 0, 0))
    .mask(Ipv4Addr::new(255, 255, 255, 0))
    .egress()  // or .ingress()
    .action(TcActionControl::Pipe);
```

**Attributes**:
- TCA_NAT_PARMS - struct tc_nat
- TCA_NAT_TM - timing info (optional)

### 2.2 tunnel_key Action
**Effort**: Medium | **Value**: Medium (tunnel encapsulation)

**From m_tunnel_key.c**:
```c
struct tc_tunnel_key {
    tc_gen;
    int t_action;   // TCA_TUNNEL_KEY_ACT_SET or ACT_RELEASE
};
```

```rust
// Target API
use nlink::netlink::action::TunnelKeyAction;

// Set tunnel metadata
let set_key = TunnelKeyAction::set()
    .id(100)                              // Tunnel ID
    .src_ip("10.0.0.1".parse()?)          // IPv4 or IPv6
    .dst_ip("10.0.0.2".parse()?)
    .dst_port(4789)                       // UDP port
    .tos(0)
    .ttl(64)
    .no_csum()                            // Disable checksum
    .no_frag();                           // No fragmentation

// With GENEVE options
let set_key = TunnelKeyAction::set()
    .id(100)
    .src_ip("10.0.0.1".parse()?)
    .dst_ip("10.0.0.2".parse()?)
    .geneve_opt(0x0102, 0x80, &[0x01, 0x02, 0x03, 0x04]);

// With VXLAN GBP
let set_key = TunnelKeyAction::set()
    .vxlan_gbp(0x100);

// Unset tunnel metadata
let unset_key = TunnelKeyAction::unset();
```

**Attributes**:
- TCA_TUNNEL_KEY_PARMS - struct tc_tunnel_key
- TCA_TUNNEL_KEY_ENC_IPV4_SRC/DST (be32)
- TCA_TUNNEL_KEY_ENC_IPV6_SRC/DST (in6_addr)
- TCA_TUNNEL_KEY_ENC_KEY_ID (be32)
- TCA_TUNNEL_KEY_ENC_DST_PORT (be16)
- TCA_TUNNEL_KEY_ENC_TOS (u8)
- TCA_TUNNEL_KEY_ENC_TTL (u8)
- TCA_TUNNEL_KEY_NO_CSUM (u8)
- TCA_TUNNEL_KEY_NO_FRAG (flag)
- TCA_TUNNEL_KEY_ENC_OPTS (nested) - GENEVE/VXLAN/ERSPAN options

### Phase 2 Deliverables
- [x] NatAction ✅ **DONE**
- [x] TunnelKeyAction ✅ **DONE**

**Phase 2 COMPLETE: nlink has 7 actions vs rtnetlink's 3** ✓

---

## Phase 3: Neighbor Parity (Priority: Medium)

### 3.1 Proxy ARP Support
**Effort**: Low | **Value**: Medium

```rust
// Target API
conn.add_neighbor_proxy("eth0", "192.168.1.100".parse()?).await?;
conn.del_neighbor_proxy("eth0", "192.168.1.100".parse()?).await?;
let proxies = conn.get_neighbor_proxies().await?;
```

**Implementation**:
- Add `NTF_PROXY` flag (0x08) to neighbor flags
- Filter by proxy flag in queries

### 3.2 Address Replace Operation
**Effort**: Low | **Value**: Low

```rust
// Target API
conn.replace_address(addr_config).await?;
```

**Implementation**:
- Add `NLM_F_REPLACE` (0x100) flag support
- Create `replace_address()` method

### Phase 3 Deliverables
- [x] Proxy ARP support ✅ **DONE** (already existed: `add_proxy_arp`, `del_proxy_arp`)
- [x] Address replace operation ✅ **DONE** (`build_replace()` with `NLM_F_REPLACE`)

**Phase 3 COMPLETE: Full parity on neighbor/address operations** ✓

---

## Phase 4: Extended TC Actions (Priority: Medium)

Go beyond rtnetlink with more TC actions.

### 4.1 connmark Action
**Effort**: Low | **Value**: Medium

```rust
let connmark = ConnmarkAction::new()
    .zone(1)
    .save();   // or .restore()
```

### 4.2 csum Action (Checksum Recalculation)
**Effort**: Low | **Value**: Low

```rust
let csum = CsumAction::new()
    .iph()     // Recalculate IP header checksum
    .tcp()     // Recalculate TCP checksum
    .udp()     // Recalculate UDP checksum
    .icmp()    // Recalculate ICMP checksum
    .igmp()    // Recalculate IGMP checksum
    .udplite() // Recalculate UDP-Lite checksum
    .sctp();   // Recalculate SCTP checksum
```

### 4.3 ct Action (Connection Tracking)
**Effort**: Medium | **Value**: High

```rust
let ct = CtAction::commit()
    .zone(1)
    .mark(0x100)
    .mark_mask(0xffffffff)
    .nat_src("10.0.0.1".parse()?, 1024..=65535)  // SNAT with port range
    .nat_dst("192.168.1.1".parse()?, 80..=80);   // DNAT
```

### 4.4 pedit Action (Packet Edit)
**Effort**: High | **Value**: High

```rust
let pedit = PeditAction::new()
    .set_ipv4_src("10.0.0.1".parse()?)
    .set_ipv4_dst("10.0.0.2".parse()?)
    .set_tcp_dport(8080)
    .set_eth_src([0x00, 0x11, 0x22, 0x33, 0x44, 0x55])
    .add_u32_at_offset(12, 0x12345678);  // Raw edit
```

### 4.5 sample Action
**Effort**: Low | **Value**: Low

```rust
let sample = SampleAction::new()
    .rate(100)       // Sample 1 in 100 packets
    .group(5)        // PSAMPLE group
    .trunc(128);     // Truncate to 128 bytes
```

### Phase 4 Deliverables
- [x] ConnmarkAction ✅ **DONE**
- [x] CsumAction ✅ **DONE**
- [ ] CtAction (complex - NAT with port ranges, labels, helpers)
- [ ] PeditAction (complex - raw packet editing)
- [x] SampleAction ✅ **DONE**

**Phase 4 Progress: 3/5 actions done. nlink now has 10 actions vs rtnetlink's 3**

---

## Phase 5: Extended TC Filters (Priority: Medium)

Achieve full iproute2 filter parity.

### 5.1 cgroup Filter
**Effort**: Low | **Value**: Medium

```rust
let filter = CgroupFilter::new()
    .with_action(GactAction::drop());
```

### 5.2 flow Filter
**Effort**: Medium | **Value**: Low

```rust
let filter = FlowFilter::new()
    .keys(&[FlowKey::Src, FlowKey::Dst, FlowKey::Proto])
    .mode(FlowMode::Hash)
    .divisor(256);
```

### 5.3 route Filter
**Effort**: Low | **Value**: Low

```rust
let filter = RouteFilter::new()
    .to_realm(10)
    .from_realm(5)
    .classid("1:10");
```

### Phase 5 Deliverables
- [x] CgroupFilter ✅ **DONE**
- [ ] FlowFilter (complex - multi-key hashing)
- [x] RouteFilter ✅ **DONE**

**Phase 5 Progress: 2/3 filters done. nlink now has 8 filters vs rtnetlink's 3**

---

## Phase 6: Extended TC Qdiscs (Priority: Low)

Continue extending nlink's qdisc lead.

### 6.1 drr (Deficit Round Robin)
```rust
let drr = DrrConfig::new();
let class = DrrClass::new().quantum(1500);
```

### 6.2 qfq (Quick Fair Queueing)
```rust
let qfq = QfqConfig::new();
let class = QfqClass::new().weight(10).maxpkt(1500);
```

### 6.3 hfsc (Hierarchical Fair Service Curve)
```rust
let hfsc = HfscConfig::new().default_class(0x10);
let class = HfscClass::new()
    .sc(ServiceCurve::new().m1(1000000).d(100).m2(500000))
    .rt(ServiceCurve::new().m2(1000000));  // Real-time curve
```

### 6.4 mqprio (Multi-queue Priority)
```rust
let mqprio = MqprioConfig::new()
    .num_tc(4)
    .hw_offload(true)
    .map(&[0, 1, 2, 3, 0, 1, 2, 3, 0, 1, 2, 3, 0, 1, 2, 3]);
```

### 6.5 taprio (Time-Aware Priority)
```rust
let taprio = TaprioConfig::new()
    .num_tc(4)
    .base_time(0)
    .cycle_time(1_000_000)  // 1ms cycle
    .add_entry(TaprioEntry::set_gates(0x1, 250_000))   // TC0 for 250us
    .add_entry(TaprioEntry::set_gates(0x2, 250_000))   // TC1 for 250us
    .add_entry(TaprioEntry::set_gates(0x4, 250_000))   // TC2 for 250us
    .add_entry(TaprioEntry::set_gates(0x8, 250_000));  // TC3 for 250us
```

### 6.6 etf (Earliest TxTime First)
```rust
let etf = EtfConfig::new()
    .delta(500_000)         // 500us
    .clockid(ClockId::Tai)
    .deadline_mode()
    .offload();
```

### 6.7 plug
```rust
let plug = PlugConfig::new().limit(10000);
conn.add_qdisc("eth0", plug).await?;
// Buffer packets
conn.plug_buffer("eth0").await?;
// Release all buffered
conn.plug_release_one("eth0").await?;
// Release indefinitely
conn.plug_release_indefinite("eth0").await?;
```

### Phase 6 Deliverables
- [ ] DrrConfig + DrrClass
- [ ] QfqConfig + QfqClass
- [ ] HfscConfig + HfscClass
- [ ] MqprioConfig
- [ ] TaprioConfig
- [ ] EtfConfig
- [ ] PlugConfig

**After Phase 6: nlink has 19 qdiscs vs rtnetlink's 2**

---

## Phase 7: Complex Link Types (Priority: Low)

These require Generic Netlink (GENL) support.

### 7.1 WireGuard Configuration
**Effort**: High | **Value**: High

WireGuard link creation uses standard RTNetlink, but configuration (peers, keys) uses GENL.

```rust
// Link creation (standard RTNetlink)
let wg = WireguardLink::new("wg0");
conn.add_link(wg).await?;

// Configuration (requires GENL)
let wg_conn = WireguardConnection::new()?;
wg_conn.set_device("wg0", WgDevice::new()
    .private_key(key)
    .listen_port(51820)
    .fwmark(0x100)
).await?;

wg_conn.add_peer("wg0", WgPeer::new(pubkey)
    .endpoint("1.2.3.4:51820".parse()?)
    .allowed_ips(&["10.0.0.0/24".parse()?])
    .persistent_keepalive(25)
).await?;

let device = wg_conn.get_device("wg0").await?;
for peer in device.peers() {
    println!("Peer: {} endpoint: {:?}", peer.public_key(), peer.endpoint());
}
```

**Implementation requires**:
- [ ] Generic Netlink socket support
- [ ] WG_CMD_SET_DEVICE, WG_CMD_GET_DEVICE
- [ ] WGDEVICE_A_* attributes
- [ ] WGPEER_A_* attributes
- [ ] WGALLOWEDIP_A_* attributes

### 7.2 MACsec Configuration
**Effort**: High | **Value**: Medium

Similar to WireGuard - link creation is RTNetlink, SA/SC management is GENL.

```rust
// Link creation (standard RTNetlink)
let macsec = MacsecLink::new("macsec0", "eth0")
    .port(1)
    .sci(0x0011223344550001)
    .cipher(MacsecCipher::GcmAes128)
    .icv_len(16)
    .encrypt(true);
conn.add_link(macsec).await?;

// SA management (requires GENL)
let macsec_conn = MacsecConnection::new()?;
macsec_conn.add_tx_sa("macsec0", TxSa::new()
    .an(0)
    .pn(1)
    .key(&[0u8; 16])
    .active(true)
).await?;

macsec_conn.add_rx_sc("macsec0", RxSc::new()
    .sci(0x0011223344550002)
    .active(true)
).await?;
```

### 7.3 team Link Type
**Effort**: Medium | **Value**: Low

Team uses libteam/teamd - complex userspace component.

### Phase 7 Deliverables
- [ ] Generic Netlink socket support
- [ ] WireguardLink (basic creation)
- [ ] WireguardConnection (GENL configuration)
- [ ] MacsecLink (with IFLA_MACSEC_* attributes)
- [ ] MacsecConnection (GENL SA/SC management) - optional

---

## Phase 8: Additional Link Types (Priority: Low)

More link types beyond rtnetlink.

### 8.1 vti/vti6 (Virtual Tunnel Interface)
```rust
let vti = VtiLink::new("vti0")
    .local("10.0.0.1".parse()?)
    .remote("10.0.0.2".parse()?)
    .ikey(100)
    .okey(100);
```

### 8.2 ip6gre/ip6gretap
```rust
let ip6gre = Ip6GreLink::new("ip6gre0")
    .local("2001:db8::1".parse()?)
    .remote("2001:db8::2".parse()?)
    .ttl(64);
```

### 8.3 nlmon (Netlink Monitor)
```rust
// Trivial - no options
let nlmon = NlmonLink::new("nlmon0");
```

### 8.4 virt_wifi
```rust
let virt_wifi = VirtWifiLink::new("vwifi0", "wlan0");
```

### Phase 8 Deliverables
- [ ] VtiLink / Vti6Link
- [ ] Ip6GreLink / Ip6GretapLink
- [ ] NlmonLink
- [ ] VirtWifiLink

---

## Phase 9: API Enhancements (Priority: Ongoing)

### 9.1 Batch Operations
```rust
conn.batch()
    .add_link(veth)
    .add_address(addr)
    .add_route(route)
    .execute().await?;
```

### 9.2 Configuration Diff
```rust
let before = conn.snapshot().await?;
// ... changes ...
let after = conn.snapshot().await?;
let diff = before.diff(&after);
```

### 9.3 Builder Validation
```rust
let veth = VethLink::new("veth0", "veth1");
veth.validate()?;  // Check before sending
```

---

## Implementation Priority Order

| Priority | Phase | Items | Effort |
|----------|-------|-------|--------|
| 1 | Phase 1 | 5 easy link types | Low |
| 2 | Phase 2 | 2 TC actions (parity) | Low-Medium |
| 3 | Phase 3 | Neighbor/address parity | Low |
| 4 | Phase 4 | 5 extended TC actions | Medium |
| 5 | Phase 5 | 3 TC filters | Low-Medium |
| 6 | Phase 6 | 7 TC qdiscs | Medium |
| 7 | Phase 7 | WireGuard/MACsec (GENL) | High |
| 8 | Phase 8 | 4 more link types | Low |

**Minimum viable superiority: Complete Phases 1-3**

---

## Final Feature Matrix

```
                        iproute2    rtnetlink    nlink (current)    nlink (after Phase 3)
                        --------    ---------    ---------------    ---------------------
Link Types:                31+          16              12                   17+
TC Qdiscs:                 31           2              12                   12
TC Filters:                 9           3               6                    6
TC Actions:                19           3               5                    7
Neighbor Ops:             Full        Full            Good                 Full
High-level API:            No          No             Yes                  Yes
```

**After Phase 6:**
```
                        iproute2    rtnetlink    nlink (planned)
                        --------    ---------    ---------------
Link Types:                31+          16              21+
TC Qdiscs:                 31           2              19
TC Filters:                 9           3               9
TC Actions:                19           3              12
```
