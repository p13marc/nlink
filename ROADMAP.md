# nlink Roadmap: Surpassing rtnetlink

This document outlines a detailed plan to make **nlink** better than **rtnetlink** in every aspect, organized into phases with specific implementation tasks.

---

## Current Status

| Category | rtnetlink | nlink | Gap |
|----------|:---------:|:-----:|:---:|
| Link Types | 16 | 12 | -4 |
| Address Ops | Full | Full | 0 (nlink has labels/lifetimes) |
| Route Ops | Full | Full | 0 (nlink has route get) |
| Neighbor Ops | Full | Good | -1 (proxy ARP) |
| TC Qdiscs | 2 | 12 | +10 |
| TC Filters | 3 | 6 | +3 |
| TC Actions | 3 | 5 | +2 |
| High-level API | No | Yes | +1 |
| Namespaces | No | Yes | +1 |

**Goal**: Close all gaps where rtnetlink leads, while maintaining and extending nlink's advantages.

---

## Phase 1: Link Type Parity (Priority: Critical)

Close the gap on the 5 link types rtnetlink has that nlink doesn't.

### 1.1 WireGuard Link Type
**Effort**: Medium | **Value**: High (very popular VPN)

```rust
// Target API
let wg = WireguardLink::new("wg0")
    .private_key(key)
    .listen_port(51820)
    .fwmark(0x100);
conn.add_link(wg).await?;

// Peer management
conn.add_wireguard_peer("wg0", WgPeer::new(pubkey)
    .endpoint("1.2.3.4:51820")
    .allowed_ips(&["10.0.0.0/24"])
    .persistent_keepalive(25)
).await?;
```

**Implementation tasks:**
- [ ] Add `WireguardLink` struct in `link.rs`
- [ ] Define IFLA_WG_* constants
- [ ] Implement `WgPeer` configuration
- [ ] Add peer add/del/list methods
- [ ] Add `get_wireguard_config()` method for reading config
- [ ] Parse WG-specific link info in `LinkMessage`

**Files to modify:**
- `crates/nlink/src/netlink/link.rs` - Add WireguardLink
- `crates/nlink/src/netlink/types/link.rs` - Add WG attributes

### 1.2 MACsec Link Type
**Effort**: Medium | **Value**: Medium (network encryption)

```rust
// Target API
let macsec = MacsecLink::new("macsec0", "eth0")
    .sci(0x0011223344550001)
    .cipher_suite(CipherSuite::GcmAes128)
    .icv_length(16)
    .encrypt(true)
    .protect(true);
conn.add_link(macsec).await?;
```

**Implementation tasks:**
- [ ] Add `MacsecLink` struct
- [ ] Define IFLA_MACSEC_* constants
- [ ] Implement cipher suite enum
- [ ] Add SA (Security Association) management
- [ ] Parse MACsec-specific link info

**Files to modify:**
- `crates/nlink/src/netlink/link.rs`
- `crates/nlink/src/netlink/types/link.rs`

### 1.3 macvtap Link Type
**Effort**: Low | **Value**: Medium (virtualization)

```rust
// Target API - similar to macvlan but creates tap device
let macvtap = MacvtapLink::new("macvtap0", "eth0")
    .mode(MacvlanMode::Bridge);
conn.add_link(macvtap).await?;
```

**Implementation tasks:**
- [ ] Add `MacvtapLink` struct (similar to MacvlanLink)
- [ ] Kind = "macvtap" instead of "macvlan"

**Files to modify:**
- `crates/nlink/src/netlink/link.rs`

### 1.4 xfrm Link Type
**Effort**: Medium | **Value**: Low (IPsec tunnels)

```rust
// Target API
let xfrm = XfrmLink::new("xfrm0")
    .dev("eth0")
    .if_id(100);
conn.add_link(xfrm).await?;
```

**Implementation tasks:**
- [ ] Add `XfrmLink` struct
- [ ] Define IFLA_XFRM_* constants
- [ ] Implement if_id support

**Files to modify:**
- `crates/nlink/src/netlink/link.rs`

### 1.5 netkit Link Type
**Effort**: Low | **Value**: Medium (container networking)

```rust
// Target API
let netkit = NetkitLink::new("nk0")
    .mode(NetkitMode::L2)
    .peer("nk1");
conn.add_link(netkit).await?;
```

**Implementation tasks:**
- [ ] Add `NetkitLink` struct
- [ ] Define IFLA_NETKIT_* constants
- [ ] Implement peer configuration

**Files to modify:**
- `crates/nlink/src/netlink/link.rs`

### Phase 1 Deliverables
- [ ] 5 new link types implemented
- [ ] Tests for each link type
- [ ] Documentation updated

**After Phase 1: nlink has 17 link types vs rtnetlink's 16**

---

## Phase 2: Neighbor & Address Parity (Priority: High)

### 2.1 Proxy ARP Support
**Effort**: Low | **Value**: Medium

```rust
// Target API
conn.add_neighbor_proxy("eth0", IpAddr::from([192, 168, 1, 100])).await?;
conn.del_neighbor_proxy("eth0", IpAddr::from([192, 168, 1, 100])).await?;
conn.get_neighbor_proxies("eth0").await?;
```

**Implementation tasks:**
- [ ] Add `NTF_PROXY` flag support
- [ ] Add `add_neighbor_proxy()` method
- [ ] Add `del_neighbor_proxy()` method
- [ ] Add `get_neighbor_proxies()` method
- [ ] Filter neighbors by proxy flag in queries

**Files to modify:**
- `crates/nlink/src/netlink/neigh.rs`
- `crates/nlink/src/netlink/connection.rs`

### 2.2 Address Replace Operation
**Effort**: Low | **Value**: Medium

```rust
// Target API
conn.replace_address(addr_config).await?;
```

**Implementation tasks:**
- [ ] Add `NLM_F_REPLACE` flag support in address operations
- [ ] Add `replace_address()` method

**Files to modify:**
- `crates/nlink/src/netlink/addr.rs`

### Phase 2 Deliverables
- [ ] Proxy ARP support
- [ ] Address replace operation
- [ ] Full neighbor operation parity

**After Phase 2: Full parity on address and neighbor operations**

---

## Phase 3: TC Actions Parity (Priority: High)

Close the gap on the 2 actions rtnetlink has that nlink doesn't.

### 3.1 NAT Action
**Effort**: Medium | **Value**: Medium

```rust
// Target API
use nlink::netlink::action::NatAction;

let nat = NatAction::new()
    .old_addr("192.168.1.0/24".parse()?)
    .new_addr("10.0.0.0/24".parse()?)
    .direction(NatDirection::Egress);

let filter = MatchallFilter::new()
    .actions(ActionList::new().with(nat))
    .build();
```

**Implementation tasks:**
- [ ] Add `NatAction` struct
- [ ] Define TCA_NAT_* constants
- [ ] Implement old_addr/new_addr configuration
- [ ] Support both ingress and egress NAT

**Files to modify:**
- `crates/nlink/src/netlink/action.rs`

### 3.2 tunnel_key Action
**Effort**: Medium | **Value**: Medium (tunnel encapsulation)

```rust
// Target API
use nlink::netlink::action::TunnelKeyAction;

// Set tunnel metadata
let set_key = TunnelKeyAction::set()
    .id(100)
    .src("10.0.0.1".parse()?)
    .dst("10.0.0.2".parse()?)
    .dst_port(4789);

// Unset tunnel metadata
let unset_key = TunnelKeyAction::unset();
```

**Implementation tasks:**
- [ ] Add `TunnelKeyAction` struct
- [ ] Define TCA_TUNNEL_KEY_* constants
- [ ] Implement set/unset modes
- [ ] Support tunnel ID, src/dst addresses, ports

**Files to modify:**
- `crates/nlink/src/netlink/action.rs`

### 3.3 Additional Actions (Beyond rtnetlink)
Extend nlink's lead in TC actions.

#### 3.3.1 bpf Action
**Effort**: Medium | **Value**: High (eBPF integration)

```rust
let bpf = BpfAction::new(fd)
    .name("my_prog")
    .direct_action();
```

#### 3.3.2 connmark Action
**Effort**: Low | **Value**: Medium

```rust
let connmark = ConnmarkAction::new()
    .zone(1)
    .restore();
```

#### 3.3.3 ct Action (Connection Tracking)
**Effort**: Medium | **Value**: High

```rust
let ct = CtAction::new()
    .commit()
    .zone(1)
    .mark(0x100);
```

#### 3.3.4 csum Action (Checksum)
**Effort**: Low | **Value**: Low

```rust
let csum = CsumAction::new()
    .iph()
    .tcp()
    .udp();
```

#### 3.3.5 pedit Action (Packet Edit)
**Effort**: High | **Value**: High

```rust
let pedit = PeditAction::new()
    .add_key(PeditKey::ipv4_src().set(addr))
    .add_key(PeditKey::tcp_dport().set(80));
```

### Phase 3 Deliverables
- [ ] NAT action (parity)
- [ ] tunnel_key action (parity)
- [ ] bpf action (beyond rtnetlink)
- [ ] connmark action (beyond rtnetlink)
- [ ] ct action (beyond rtnetlink)
- [ ] csum action (beyond rtnetlink)
- [ ] pedit action (beyond rtnetlink)

**After Phase 3: nlink has 12 actions vs rtnetlink's 3**

---

## Phase 4: TC Filters Enhancement (Priority: Medium)

Extend nlink's filter lead.

### 4.1 cgroup Filter
**Effort**: Low | **Value**: Medium

```rust
let filter = CgroupFilter::new()
    .classid("1:10")
    .ematch(/* ... */);
```

### 4.2 flow Filter
**Effort**: Medium | **Value**: Low

```rust
let filter = FlowFilter::new()
    .keys(&[FlowKey::Src, FlowKey::Dst])
    .mode(FlowMode::Hash);
```

### 4.3 route Filter
**Effort**: Low | **Value**: Low

```rust
let filter = RouteFilter::new()
    .from("eth0")
    .to("1:10");
```

### Phase 4 Deliverables
- [ ] cgroup filter
- [ ] flow filter
- [ ] route filter

**After Phase 4: nlink has 9 filters vs rtnetlink's 3 (full iproute2 parity)**

---

## Phase 5: TC Qdiscs Enhancement (Priority: Medium)

Extend nlink's qdisc lead further.

### 5.1 Scheduling Qdiscs

#### drr (Deficit Round Robin)
```rust
let drr = DrrConfig::new().quantum(1500);
```

#### qfq (Quick Fair Queueing)
```rust
let qfq = QfqConfig::new();
```

#### hfsc (Hierarchical Fair Service Curve)
```rust
let hfsc = HfscConfig::new()
    .default_class(0x10);
```

### 5.2 Time-based Qdiscs

#### etf (Earliest TxTime First)
```rust
let etf = EtfConfig::new()
    .delta(500_000)  // ns
    .clockid(ClockId::Tai)
    .deadline_mode();
```

#### taprio (Time-Aware Priority)
```rust
let taprio = TaprioConfig::new()
    .num_tc(4)
    .add_entry(TaprioEntry::new().command(SetGates).gate_mask(0x1).interval(100_000))
    .base_time(0);
```

### 5.3 Other Qdiscs

#### mqprio (Multi-queue Priority)
```rust
let mqprio = MqprioConfig::new()
    .num_tc(4)
    .hw_offload(true);
```

#### plug
```rust
let plug = PlugConfig::new();
conn.add_qdisc("eth0", plug).await?;
conn.plug_buffer("eth0").await?;   // Stop releasing
conn.plug_release("eth0").await?;  // Release all
```

### Phase 5 Deliverables
- [ ] drr qdisc
- [ ] qfq qdisc
- [ ] hfsc qdisc
- [ ] etf qdisc
- [ ] taprio qdisc
- [ ] mqprio qdisc
- [ ] plug qdisc

**After Phase 5: nlink has 19 qdiscs vs rtnetlink's 2**

---

## Phase 6: Additional Link Types (Priority: Low)

Go beyond both rtnetlink and achieve broader iproute2 parity.

### 6.1 geneve
```rust
let geneve = GeneveLink::new("geneve0", 100)  // VNI
    .remote("10.0.0.1".parse()?)
    .ttl(64);
```

### 6.2 bareudp
```rust
let bareudp = BareudpLink::new("bareudp0")
    .port(6635)
    .ethertype(0x6558);  // MPLS
```

### 6.3 ifb (Intermediate Functional Block)
```rust
let ifb = IfbLink::new("ifb0");
```

### 6.4 team
```rust
let team = TeamLink::new("team0")
    .mode(TeamMode::RoundRobin)
    .ports(&["eth0", "eth1"]);
```

### 6.5 ipvtap
```rust
let ipvtap = IpvtapLink::new("ipvtap0", "eth0")
    .mode(IpvlanMode::L3);
```

### 6.6 vti/vti6 (Virtual Tunnel Interface)
```rust
let vti = VtiLink::new("vti0")
    .local("10.0.0.1".parse()?)
    .remote("10.0.0.2".parse()?)
    .ikey(100)
    .okey(100);
```

### Phase 6 Deliverables
- [ ] geneve link
- [ ] bareudp link
- [ ] ifb link
- [ ] team link
- [ ] ipvtap link
- [ ] vti/vti6 link

**After Phase 6: nlink has 23 link types vs rtnetlink's 16**

---

## Phase 7: API Enhancements (Priority: Ongoing)

Maintain and extend nlink's API advantages.

### 7.1 Batch Operations
```rust
// Execute multiple operations atomically
conn.batch()
    .add_link(veth)
    .add_address(addr)
    .add_route(route)
    .execute().await?;
```

### 7.2 Transaction Support
```rust
// Rollback on failure
let txn = conn.transaction();
txn.add_link(veth).await?;
txn.add_address(addr).await?;
txn.commit().await?;  // or txn.rollback()
```

### 7.3 Change Detection
```rust
// Detect configuration drift
let expected = conn.get_links().await?;
// ... time passes ...
let current = conn.get_links().await?;
let changes = expected.diff(&current);
```

### 7.4 Configuration Snapshots
```rust
// Save/restore network configuration
let snapshot = conn.snapshot().await?;
// ... make changes ...
conn.restore(snapshot).await?;
```

### 7.5 Builder Validation
```rust
// Validate configuration before sending
let veth = VethLink::new("veth0", "veth1");
veth.validate()?;  // Check for errors before execute
```

---

## Phase 8: Documentation & Testing (Priority: High)

### 8.1 API Documentation
- [ ] Document every public type
- [ ] Add examples for every builder
- [ ] Add module-level documentation
- [ ] Create cookbook with common recipes

### 8.2 Integration Tests
- [ ] Test each link type creation/deletion
- [ ] Test each TC qdisc
- [ ] Test each TC filter
- [ ] Test each TC action
- [ ] Test namespace operations
- [ ] Test event streaming

### 8.3 Benchmarks
- [ ] Connection creation overhead
- [ ] Message throughput
- [ ] Event processing latency
- [ ] Comparison with rtnetlink

---

## Implementation Timeline

| Phase | Description | Tasks | Priority |
|-------|-------------|-------|----------|
| 1 | Link Type Parity | 5 link types | Critical |
| 2 | Neighbor/Address Parity | 2 features | High |
| 3 | TC Actions Parity + Beyond | 7 actions | High |
| 4 | TC Filters Enhancement | 3 filters | Medium |
| 5 | TC Qdiscs Enhancement | 7 qdiscs | Medium |
| 6 | Additional Link Types | 6 link types | Low |
| 7 | API Enhancements | 5 features | Ongoing |
| 8 | Documentation & Testing | Comprehensive | High |

---

## Final Feature Matrix (After All Phases)

```
                        iproute2    rtnetlink    nlink (current)    nlink (planned)
                        --------    ---------    ---------------    ---------------
Link Types:                31+          16              12                 23+
Address Operations:       Full        Full            Full               Full
Route Operations:         Full        Full            Full               Full  
Neighbor Operations:      Full        Full            Good               Full
TC Qdiscs:                 31           2              12                 19+
TC Filters:                 9           3               6                  9
TC Actions:                19           3               5                 12+
High-level API:            No          No             Yes                Yes+
Event Streaming:           No          No             Yes                Yes
Namespace Support:         No          No             Yes                Yes
Batch Operations:          No          No              No                Yes
Transactions:              No          No              No                Yes
```

---

## Success Criteria

nlink will be considered superior to rtnetlink when:

1. **Link Types**: nlink ≥ rtnetlink (17+ vs 16) ✓ after Phase 1
2. **Address Ops**: nlink = rtnetlink + labels/lifetimes ✓ already
3. **Route Ops**: nlink = rtnetlink + route get ✓ already
4. **Neighbor Ops**: nlink = rtnetlink ✓ after Phase 2
5. **TC Qdiscs**: nlink >> rtnetlink (12+ vs 2) ✓ already
6. **TC Filters**: nlink > rtnetlink (6 vs 3) ✓ already
7. **TC Actions**: nlink ≥ rtnetlink (7+ vs 3) ✓ after Phase 3
8. **High-level API**: nlink has, rtnetlink doesn't ✓ already
9. **Namespaces**: nlink has, rtnetlink doesn't ✓ already
10. **Documentation**: Comprehensive ✓ after Phase 8

**Minimum viable superiority: Complete Phases 1-3**
