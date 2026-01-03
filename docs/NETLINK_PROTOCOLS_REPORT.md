# Netlink Protocol Support Report

This report analyzes Linux netlink protocol families and their implementation status in nlink.

## Current Architecture

The library uses two different patterns for netlink protocols:

1. **`Connection<P: ProtocolState>`** - The main typed connection pattern
   - `Connection<Route>` - RTNetlink (interfaces, routes, TC, etc.)
   - `Connection<Generic>` - Generic Netlink (WireGuard, etc.)
   - Methods are added via `impl Connection<Route>` blocks in different modules

2. **Separate module** - `sockdiag` module has its own `SockDiag` struct
   - Does NOT use `ProtocolState` trait
   - Completely independent implementation

**Note**: `impl Connection<Route>` appears in 7 files because methods are organized by domain:
- `connection.rs` - Core queries (get_links, get_routes, etc.)
- `addr.rs` - Address management
- `link.rs` - Link creation/modification
- `route.rs` - Route management
- `neigh.rs` - Neighbor/ARP table
- `tc.rs` - Traffic control
- `filter.rs` - TC filters

## Current Implementation Status

### Fully Implemented

| Protocol | ID | Description | Implementation |
|----------|-----|-------------|----------------|
| `NETLINK_ROUTE` | 0 | Routing, interfaces, addresses, TC, rules, neighbors | `Connection<Route>` - comprehensive |
| `NETLINK_SOCK_DIAG` | 4 | Socket monitoring (ss-like queries) | `SockDiag` struct (separate module, feature-gated) |
| `NETLINK_GENERIC` | 16 | Generic netlink (extensible subsystem) | `Connection<Generic>` with WireGuard support |

### Partially Implemented (Protocol Enum Only)

| Protocol | ID | Description | Status |
|----------|-----|-------------|--------|
| `NETLINK_NETFILTER` | 12 | Netfilter subsystem | `Protocol::Netfilter` enum variant exists, no API |
| `NETLINK_CONNECTOR` | 11 | Kernel connector | `Protocol::Connector` enum variant exists, no API |
| `NETLINK_KOBJECT_UEVENT` | 15 | Kernel uevents (udev) | `Protocol::KobjectUevent` enum variant exists, no API |

### Not Implemented

| Protocol | ID | Description | Priority | Notes |
|----------|-----|-------------|----------|-------|
| `NETLINK_XFRM` | 6 | IPsec/XFRM | **High** | VPN, security policies |
| `NETLINK_AUDIT` | 9 | Linux audit | Medium | Security auditing |
| `NETLINK_FIB_LOOKUP` | 10 | FIB lookup | Low | Specialized routing queries |
| `NETLINK_SELINUX` | 7 | SELinux notifications | Low | Security module events |
| `NETLINK_ISCSI` | 8 | Open-iSCSI | Low | Storage networking |
| `NETLINK_SCSITRANSPORT` | 18 | SCSI transport | Low | Storage |
| `NETLINK_RDMA` | 20 | RDMA/InfiniBand | Low | HPC networking |
| `NETLINK_CRYPTO` | 21 | Crypto layer | Low | Kernel crypto API |
| `NETLINK_SMC` | 22 | SMC monitoring | Low | IBM SMC sockets |
| `NETLINK_ECRYPTFS` | 19 | eCryptfs | Very Low | Deprecated filesystem |
| `NETLINK_NFLOG` | 5 | Netfilter logging | Very Low | Legacy, use NETFILTER |
| `NETLINK_DNRTMSG` | 14 | DECnet routing | None | Obsolete |
| `NETLINK_IP6_FW` | 13 | IPv6 firewall | None | Unused |
| `NETLINK_FIREWALL` | 3 | ip_queue | None | Removed from kernel |
| `NETLINK_USERSOCK` | 2 | User protocols | None | Reserved for users |

---

## Priority Analysis

### High Priority: NETLINK_XFRM (IPsec)

**Why**: Essential for VPN and security infrastructure.

**Use cases**:
- IPsec SA (Security Association) management
- IPsec policy management
- VPN tunnel setup (IKE daemons like strongSwan, libreswan)
- Network security policy enforcement

**Complexity**: High - Complex message types, multiple operations

**Estimated effort**: 2-3 weeks

**Example API**:
```rust
let conn = Connection::<Xfrm>::new()?;

// Add a security policy
conn.add_policy(XfrmPolicy::new()
    .selector(Selector::new()
        .src("10.0.0.0/24".parse()?)
        .dst("192.168.0.0/24".parse()?))
    .direction(Direction::Out)
    .action(Action::Ipsec)
    .template(Template::new()
        .proto(IpsecProto::Esp)
        .mode(Mode::Tunnel)
        .remote("vpn.example.com".parse()?))
).await?;

// Add a security association
conn.add_sa(XfrmSa::new()
    .src("10.0.0.1".parse()?)
    .dst("192.168.1.1".parse()?)
    .proto(IpsecProto::Esp)
    .spi(0x12345678)
    .auth_algo("hmac(sha256)", &auth_key)
    .enc_algo("cbc(aes)", &enc_key)
).await?;
```

---

### Medium Priority: NETLINK_AUDIT

**Why**: Important for security-focused systems and compliance.

**Use cases**:
- System call auditing
- Security event logging
- Compliance monitoring (PCI-DSS, HIPAA)
- Intrusion detection

**Complexity**: Medium - Well-documented, many message types

**Estimated effort**: 1-2 weeks

**Example API**:
```rust
let conn = Connection::<Audit>::new()?;

// Add an audit rule
conn.add_rule(AuditRule::new()
    .syscall(Syscall::Open)
    .field(Field::Uid, Op::Eq, 0)  // root only
    .key("root-file-access")
).await?;

// Get audit status
let status = conn.get_status().await?;
println!("Audit enabled: {}", status.enabled);
```

---

### Medium Priority: NETLINK_NETFILTER (Full Implementation)

**Why**: Currently only has socket enum. Full implementation enables firewall management.

**Use cases**:
- nftables configuration
- Connection tracking (conntrack)
- NAT management
- Packet filtering rules

**Complexity**: Very High - nftables has complex expression language

**Estimated effort**: 4-6 weeks for comprehensive support

**Note**: Consider using existing `nftables` crate or implementing incrementally (conntrack first).

**Example API**:
```rust
let conn = Connection::<Netfilter>::new()?;

// Query connection tracking table
let conns = conn.get_conntrack().await?;
for ct in conns {
    println!("{} -> {} ({})", ct.src, ct.dst, ct.proto);
}

// Flush conntrack entries
conn.flush_conntrack().await?;
```

---

### Low Priority: NETLINK_FIB_LOOKUP

**Why**: Specialized use case for routing decisions.

**Use cases**:
- Route lookup without modifying routing table
- Testing routing configuration
- Network diagnostics

**Complexity**: Low - Simple request/response

**Estimated effort**: 2-3 days

**Example API**:
```rust
let conn = Connection::<FibLookup>::new()?;

// Look up route for destination
let result = conn.lookup("8.8.8.8".parse()?).await?;
println!("Route via: {:?}, dev: {}", result.gateway, result.oif);
```

---

### Low Priority: NETLINK_RDMA

**Why**: Niche use case for HPC and data centers.

**Use cases**:
- InfiniBand device management
- RDMA over Converged Ethernet (RoCE)
- High-performance computing networks

**Complexity**: Medium - Specialized domain knowledge required

**Estimated effort**: 1-2 weeks

---

### Low Priority: NETLINK_CRYPTO

**Why**: Specialized kernel crypto configuration.

**Use cases**:
- Query available crypto algorithms
- Crypto algorithm registration
- Hardware crypto offload management

**Complexity**: Medium

**Estimated effort**: 1 week

---

### Very Low Priority

| Protocol | Reason |
|----------|--------|
| `NETLINK_SELINUX` | Very specialized, SELinux-specific systems only |
| `NETLINK_ISCSI` | Storage networking, specialized use case |
| `NETLINK_SCSITRANSPORT` | Storage, specialized use case |
| `NETLINK_SMC` | IBM-specific, rare outside mainframe |
| `NETLINK_ECRYPTFS` | Deprecated filesystem |

---

## Generic Netlink Subsystems (via NETLINK_GENERIC)

Generic netlink is extensible. Current and potential subsystems:

### Implemented

| Family | Description | Status |
|--------|-------------|--------|
| `wireguard` | WireGuard VPN | Fully implemented |

### Not Implemented

| Family | Priority | Description | Notes |
|--------|----------|-------------|-------|
| `nl80211` | **High** | WiFi configuration | iwconfig/iw replacement |
| `devlink` | **High** | Device management | Modern NIC configuration |
| `ethtool` | **High** | Ethernet tool | Link settings, offloads |
| `macsec` | Medium | MACsec encryption | Layer 2 security |
| `team` | Medium | NIC teaming | Link aggregation |
| `l2tp` | Medium | L2TP tunnels | VPN tunneling |
| `gtp` | Low | GTP tunnels | Mobile core networks |
| `ila` | Low | Identifier Locator Addressing | Experimental |
| `seg6` | Low | Segment Routing v6 | Advanced routing |
| `mptcp` | Low | Multipath TCP | Connection management |

---

## Recommended Implementation Order

### Phase 1: Core Networking (High Value)
1. **nl80211** (via Generic) - WiFi is ubiquitous
2. **devlink** (via Generic) - Modern device management
3. **ethtool** (via Generic) - Essential for NIC configuration

### Phase 2: Security
4. **NETLINK_XFRM** - IPsec/VPN support
5. **NETLINK_AUDIT** - Security auditing

### Phase 3: Advanced Features
6. **NETLINK_NETFILTER** (full) - Firewall/nftables
7. **macsec** (via Generic) - Layer 2 encryption
8. **team** (via Generic) - NIC bonding

### Phase 4: Specialized
9. **NETLINK_FIB_LOOKUP** - Routing diagnostics
10. **NETLINK_RDMA** - HPC networking
11. **NETLINK_CRYPTO** - Kernel crypto

---

## Architecture Considerations

### Adding New Protocol Types

The current architecture uses a sealed `ProtocolState` trait. To add a new protocol:

1. Add variant to `Protocol` enum in `socket.rs`
2. Create state type (e.g., `Xfrm`) in `protocol.rs`
3. Implement `ProtocolState` for the new type
4. Add protocol-specific methods to `Connection<NewType>`

Example for XFRM:
```rust
// In protocol.rs
#[derive(Debug, Default, Clone, Copy)]
pub struct Xfrm;

impl private::Sealed for Xfrm {}

impl ProtocolState for Xfrm {
    const PROTOCOL: Protocol = Protocol::Xfrm;
}

// In a new xfrm.rs module
impl Connection<Xfrm> {
    pub async fn get_policies(&self) -> Result<Vec<XfrmPolicy>> { ... }
    pub async fn add_policy(&self, policy: XfrmPolicy) -> Result<()> { ... }
    pub async fn get_sas(&self) -> Result<Vec<XfrmSa>> { ... }
    pub async fn add_sa(&self, sa: XfrmSa) -> Result<()> { ... }
}
```

### Adding Generic Netlink Families

For new GENL families (like nl80211):

1. Create module under `netlink/genl/` (e.g., `genl/nl80211/`)
2. Define message types and attributes
3. Implement query/set operations
4. Optionally create wrapper connection type

---

## Summary

| Category | Count | Examples |
|----------|-------|----------|
| Fully Implemented | 3 | Route, SockDiag, Generic |
| High Priority Missing | 4 | XFRM, nl80211, devlink, ethtool |
| Medium Priority Missing | 4 | Audit, Netfilter, macsec, team |
| Low Priority Missing | 6 | FIB, RDMA, Crypto, etc. |
| Not Worth Implementing | 5 | Obsolete/deprecated protocols |

The library covers the most common use cases well. The main gaps are:
- **WiFi configuration** (nl80211) - very common need
- **IPsec/VPN** (XFRM) - important for security
- **Modern NIC management** (devlink, ethtool) - hardware configuration
