# Implementation Plan: High & Medium Priority Features

## Design Principles

All implementations follow these core principles:

1. **Library-first**: Every feature is a reusable library with the binary as a thin CLI wrapper
2. **Strongly-typed**: Use Rust's type system to prevent invalid states at compile time
3. **High-level API**: Builder patterns, ergonomic methods, sensible defaults
4. **Rust idiomatic**: Result types, iterators, traits, no raw pointers in public API
5. **Async**: All I/O operations are async (tokio)
6. **Well-documented**: Doc comments with examples, module-level documentation

---

## Architecture Overview

```
rip/
├── crates/
│   ├── rip-netlink/          # Core netlink (existing)
│   ├── rip-lib/              # Utilities (existing)
│   ├── rip-output/           # Formatting (existing)
│   ├── rip-tc/               # TC utilities (existing)
│   ├── rip-filter/           # NEW: TC filters (u32, flower, etc.)
│   ├── rip-action/           # NEW: TC actions (gact, mirred, etc.)
│   ├── rip-sockdiag/         # NEW: Socket diagnostics (ss)
│   └── rip-tuntap/           # NEW: TUN/TAP management
└── bins/
    ├── ip/                   # ip command (existing)
    ├── tc/                   # tc command (existing)
    └── ss/                   # NEW: ss command
```

---

## Phase 1: TC Filters (High Priority)

### Crate: `rip-filter`

TC filters are essential for traffic classification. We implement u32 and flower as the most important filters.

### 1.1 Core Types

```rust
// crates/rip-filter/src/lib.rs

/// Filter handle (32-bit identifier)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FilterHandle(pub u32);

/// Filter priority (lower = higher priority)
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Priority(pub u16);

/// Ethernet protocol type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    All,      // ETH_P_ALL (0x0003)
    Ip,       // ETH_P_IP (0x0800)
    Ipv6,     // ETH_P_IPV6 (0x86dd)
    Arp,      // ETH_P_ARP (0x0806)
    Vlan,     // ETH_P_8021Q (0x8100)
    Custom(u16),
}

/// Where to attach the filter
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilterParent {
    /// Root qdisc
    Root,
    /// Ingress hook (clsact)
    Ingress,
    /// Egress hook (clsact)  
    Egress,
    /// Specific qdisc class
    Class { major: u16, minor: u16 },
}

/// Hardware offload control
#[derive(Debug, Clone, Copy, Default)]
pub struct OffloadFlags {
    pub skip_hw: bool,
    pub skip_sw: bool,
}

/// A TC filter
pub enum Filter {
    U32(U32Filter),
    Flower(FlowerFilter),
    Basic(BasicFilter),
    Matchall(MatchallFilter),
}

/// Common filter trait
pub trait FilterConfig: Send + Sync {
    fn kind(&self) -> &'static str;
    fn write_options(&self, builder: &mut MessageBuilder) -> Result<()>;
}
```

### 1.2 U32 Filter

```rust
// crates/rip-filter/src/u32.rs

/// U32 filter handle format: htid:hash:nodeid
#[derive(Debug, Clone, Copy)]
pub struct U32Handle {
    pub htid: u16,    // Hash table ID (12 bits)
    pub hash: u8,     // Hash bucket (8 bits)
    pub nodeid: u16,  // Node ID (12 bits)
}

/// A single match key
#[derive(Debug, Clone)]
pub struct U32Key {
    pub mask: u32,
    pub value: u32,
    pub offset: i32,
    pub offset_mask: i32,
}

/// U32 selector flags
bitflags! {
    pub struct U32Flags: u8 {
        const TERMINAL = 0x01;
        const OFFSET = 0x02;
        const VAROFFSET = 0x04;
        const EAT = 0x08;
    }
}

/// U32 filter configuration
#[derive(Debug, Clone)]
pub struct U32Filter {
    keys: Vec<U32Key>,
    classid: Option<u32>,
    link: Option<u32>,
    divisor: Option<u32>,
    mark: Option<(u32, u32)>,  // (value, mask)
    flags: U32Flags,
    actions: Vec<Action>,
    offload: OffloadFlags,
}

impl U32Filter {
    pub fn new() -> Self { ... }
    
    /// Match IP source address
    pub fn match_ip_src(mut self, addr: Ipv4Addr, mask: Ipv4Addr) -> Self { ... }
    
    /// Match IP destination address  
    pub fn match_ip_dst(mut self, addr: Ipv4Addr, mask: Ipv4Addr) -> Self { ... }
    
    /// Match IP protocol
    pub fn match_ip_protocol(mut self, proto: u8) -> Self { ... }
    
    /// Match TCP/UDP source port
    pub fn match_sport(mut self, port: u16) -> Self { ... }
    
    /// Match TCP/UDP destination port
    pub fn match_dport(mut self, port: u16) -> Self { ... }
    
    /// Match firewall mark
    pub fn match_mark(mut self, value: u32, mask: u32) -> Self { ... }
    
    /// Add raw 32-bit key match
    pub fn match_u32(mut self, offset: i32, value: u32, mask: u32) -> Self { ... }
    
    /// Set target class
    pub fn classid(mut self, major: u16, minor: u16) -> Self { ... }
    
    /// Add action
    pub fn action(mut self, action: Action) -> Self { ... }
    
    /// Build the filter
    pub fn build(self) -> Result<Filter> { ... }
}

// Helper macros for common matches
impl U32Filter {
    /// Match at IP header offset
    pub fn match_ip(mut self, offset: u8, value: u32, mask: u32) -> Self {
        self.keys.push(U32Key {
            offset: offset as i32,
            value: value & mask,
            mask,
            offset_mask: 0,
        });
        self
    }
}
```

### 1.3 Flower Filter

```rust
// crates/rip-filter/src/flower.rs

/// Flower filter - flow-based classification
#[derive(Debug, Clone, Default)]
pub struct FlowerFilter {
    // L2 matching
    eth_dst: Option<(MacAddr, MacAddr)>,  // (value, mask)
    eth_src: Option<(MacAddr, MacAddr)>,
    eth_type: Option<u16>,
    vlan_id: Option<u16>,
    vlan_prio: Option<u8>,
    vlan_ethtype: Option<u16>,
    cvlan_id: Option<u16>,  // Customer VLAN (QinQ)
    
    // L3 matching
    ip_proto: Option<u8>,
    ipv4_src: Option<(Ipv4Addr, u8)>,  // (addr, prefix_len)
    ipv4_dst: Option<(Ipv4Addr, u8)>,
    ipv6_src: Option<(Ipv6Addr, u8)>,
    ipv6_dst: Option<(Ipv6Addr, u8)>,
    ip_tos: Option<(u8, u8)>,  // (value, mask)
    ip_ttl: Option<(u8, u8)>,
    
    // L4 matching
    tcp_src: Option<PortRange>,
    tcp_dst: Option<PortRange>,
    udp_src: Option<PortRange>,
    udp_dst: Option<PortRange>,
    tcp_flags: Option<(u16, u16)>,
    
    // ICMP
    icmp_type: Option<u8>,
    icmp_code: Option<u8>,
    
    // Connection tracking
    ct_state: Option<CtState>,
    ct_zone: Option<u16>,
    ct_mark: Option<(u32, u32)>,
    
    // Tunnel encapsulation
    enc_key_id: Option<u32>,  // VNI/tunnel ID
    enc_dst_ip: Option<IpAddr>,
    enc_src_ip: Option<IpAddr>,
    enc_dst_port: Option<u16>,
    
    // Classification
    classid: Option<u32>,
    actions: Vec<Action>,
    offload: OffloadFlags,
}

/// Port or port range
#[derive(Debug, Clone, Copy)]
pub enum PortRange {
    Single(u16),
    Range { min: u16, max: u16 },
}

/// Connection tracking state flags
bitflags! {
    pub struct CtState: u16 {
        const NEW = 1 << 0;
        const ESTABLISHED = 1 << 1;
        const RELATED = 1 << 2;
        const TRACKED = 1 << 3;
        const INVALID = 1 << 4;
        const REPLY = 1 << 5;
    }
}

impl FlowerFilter {
    pub fn new() -> Self { ... }
    
    // L2 matching
    pub fn eth_dst(mut self, addr: MacAddr) -> Self { ... }
    pub fn eth_dst_masked(mut self, addr: MacAddr, mask: MacAddr) -> Self { ... }
    pub fn eth_src(mut self, addr: MacAddr) -> Self { ... }
    pub fn vlan(mut self, id: u16) -> Self { ... }
    pub fn vlan_prio(mut self, prio: u8) -> Self { ... }
    
    // L3 matching
    pub fn ip_proto(mut self, proto: IpProtocol) -> Self { ... }
    pub fn ipv4_src(mut self, prefix: Ipv4Net) -> Self { ... }
    pub fn ipv4_dst(mut self, prefix: Ipv4Net) -> Self { ... }
    pub fn ipv6_src(mut self, prefix: Ipv6Net) -> Self { ... }
    pub fn ipv6_dst(mut self, prefix: Ipv6Net) -> Self { ... }
    pub fn ip_tos(mut self, value: u8, mask: u8) -> Self { ... }
    pub fn ip_ttl(mut self, value: u8) -> Self { ... }
    
    // L4 matching  
    pub fn tcp_src(mut self, port: u16) -> Self { ... }
    pub fn tcp_src_range(mut self, min: u16, max: u16) -> Self { ... }
    pub fn tcp_dst(mut self, port: u16) -> Self { ... }
    pub fn tcp_dst_range(mut self, min: u16, max: u16) -> Self { ... }
    pub fn tcp_flags(mut self, flags: TcpFlags, mask: TcpFlags) -> Self { ... }
    pub fn udp_src(mut self, port: u16) -> Self { ... }
    pub fn udp_dst(mut self, port: u16) -> Self { ... }
    
    // Connection tracking
    pub fn ct_state(mut self, state: CtState) -> Self { ... }
    pub fn ct_zone(mut self, zone: u16) -> Self { ... }
    pub fn ct_mark(mut self, value: u32, mask: u32) -> Self { ... }
    
    // Tunnel matching
    pub fn tunnel_id(mut self, id: u32) -> Self { ... }
    pub fn tunnel_dst(mut self, addr: IpAddr) -> Self { ... }
    
    // Actions
    pub fn classid(mut self, major: u16, minor: u16) -> Self { ... }
    pub fn action(mut self, action: Action) -> Self { ... }
    
    pub fn build(self) -> Result<Filter> { ... }
}
```

### 1.4 High-Level Connection API

```rust
// crates/rip-netlink/src/connection.rs (additions)

impl Connection {
    /// Add a filter to a qdisc
    pub async fn add_filter(
        &self,
        dev: &str,
        parent: FilterParent,
        priority: Priority,
        protocol: Protocol,
        filter: impl FilterConfig,
    ) -> Result<()> { ... }
    
    /// Delete a filter
    pub async fn del_filter(
        &self,
        dev: &str,
        parent: FilterParent,
        priority: Priority,
        protocol: Protocol,
        handle: Option<FilterHandle>,
    ) -> Result<()> { ... }
    
    /// List all filters on a qdisc
    pub async fn get_filters(
        &self,
        dev: &str,
        parent: FilterParent,
    ) -> Result<Vec<FilterMessage>> { ... }
}
```

### 1.5 Files to Create

```
crates/rip-filter/
├── Cargo.toml
└── src/
    ├── lib.rs          # Module exports, FilterConfig trait
    ├── types.rs        # FilterHandle, Priority, Protocol, FilterParent
    ├── u32.rs          # U32Filter builder
    ├── flower.rs       # FlowerFilter builder
    ├── basic.rs        # BasicFilter
    ├── matchall.rs     # MatchallFilter
    ├── builder.rs      # Netlink message building
    └── parse.rs        # Response parsing
```

### 1.6 CLI Integration

```rust
// bins/tc/src/commands/filter.rs

#[derive(Parser)]
pub struct FilterCmd {
    #[command(subcommand)]
    action: FilterAction,
}

#[derive(Subcommand)]
enum FilterAction {
    Add(FilterAddArgs),
    Del(FilterDelArgs),
    Show(FilterShowArgs),
    Replace(FilterAddArgs),
}

#[derive(Args)]
struct FilterAddArgs {
    /// Device name
    dev: String,
    /// Parent qdisc (ingress, egress, or handle like 1:0)
    #[arg(long, default_value = "root")]
    parent: String,
    /// Filter priority
    #[arg(long, short)]
    prio: Option<u16>,
    /// Protocol (ip, ipv6, all, 0x800, etc.)
    #[arg(long, default_value = "ip")]
    protocol: String,
    /// Filter kind (u32, flower, basic, etc.)
    kind: String,
    /// Filter-specific arguments
    #[arg(trailing_var_arg = true)]
    args: Vec<String>,
}
```

---

## Phase 2: TC Actions (High Priority)

### Crate: `rip-action`

Actions define what to do with matched packets.

### 2.1 Core Types

```rust
// crates/rip-action/src/lib.rs

/// Action control - what to do after this action
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActionControl {
    Ok,           // TC_ACT_OK - pass packet
    Shot,         // TC_ACT_SHOT - drop packet  
    Pipe,         // TC_ACT_PIPE - continue to next action
    Stolen,       // TC_ACT_STOLEN - consumed
    Reclassify,   // TC_ACT_RECLASSIFY - restart classification
    Redirect,     // TC_ACT_REDIRECT - redirect
    Jump(u32),    // TC_ACT_JUMP - jump N actions
    Goto(u32),    // TC_ACT_GOTO_CHAIN - go to chain N
}

/// Action instance index
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ActionIndex(pub u32);

/// A TC action
#[derive(Debug, Clone)]
pub enum Action {
    Gact(GactAction),
    Mirred(MirredAction),
    Police(PoliceAction),
    Vlan(VlanAction),
    Skbedit(SkbeditAction),
    Pedit(PeditAction),
    TunnelKey(TunnelKeyAction),
}

/// Common action trait
pub trait ActionConfig: Send + Sync {
    fn kind(&self) -> &'static str;
    fn write_options(&self, builder: &mut MessageBuilder) -> Result<()>;
}
```

### 2.2 Gact (Generic Action)

```rust
// crates/rip-action/src/gact.rs

/// Generic action - simple pass/drop/etc.
#[derive(Debug, Clone)]
pub struct GactAction {
    control: ActionControl,
    prob: Option<GactProbability>,
    index: Option<ActionIndex>,
}

/// Probabilistic action
#[derive(Debug, Clone)]
pub struct GactProbability {
    pub ptype: ProbType,
    pub value: u16,        // 0-10000 (0.01% granularity)
    pub action: ActionControl,
}

#[derive(Debug, Clone, Copy)]
pub enum ProbType {
    None,
    Random,
    Deterministic,
}

impl GactAction {
    /// Drop packet
    pub fn drop() -> Self {
        Self { control: ActionControl::Shot, prob: None, index: None }
    }
    
    /// Pass packet
    pub fn pass() -> Self {
        Self { control: ActionControl::Ok, prob: None, index: None }
    }
    
    /// Continue to next action
    pub fn pipe() -> Self {
        Self { control: ActionControl::Pipe, prob: None, index: None }
    }
    
    /// Reclassify packet
    pub fn reclassify() -> Self {
        Self { control: ActionControl::Reclassify, prob: None, index: None }
    }
    
    /// Jump to chain
    pub fn goto_chain(chain: u32) -> Self {
        Self { control: ActionControl::Goto(chain), prob: None, index: None }
    }
    
    /// Add probabilistic behavior
    pub fn with_probability(mut self, prob: f32, action: ActionControl) -> Self {
        self.prob = Some(GactProbability {
            ptype: ProbType::Random,
            value: (prob * 10000.0) as u16,
            action,
        });
        self
    }
    
    pub fn build(self) -> Action { Action::Gact(self) }
}
```

### 2.3 Mirred (Mirror/Redirect)

```rust
// crates/rip-action/src/mirred.rs

/// Mirror/redirect action
#[derive(Debug, Clone)]
pub struct MirredAction {
    direction: MirredDirection,
    mode: MirredMode,
    ifindex: i32,
    index: Option<ActionIndex>,
}

#[derive(Debug, Clone, Copy)]
pub enum MirredDirection {
    Egress,
    Ingress,
}

#[derive(Debug, Clone, Copy)]
pub enum MirredMode {
    Mirror,    // Copy packet
    Redirect,  // Move packet
}

impl MirredAction {
    /// Redirect packet to egress of another interface
    pub fn redirect_egress(ifindex: i32) -> Self {
        Self {
            direction: MirredDirection::Egress,
            mode: MirredMode::Redirect,
            ifindex,
            index: None,
        }
    }
    
    /// Mirror packet to egress of another interface
    pub fn mirror_egress(ifindex: i32) -> Self {
        Self {
            direction: MirredDirection::Egress,
            mode: MirredMode::Mirror,
            ifindex,
            index: None,
        }
    }
    
    /// Redirect packet to ingress of another interface
    pub fn redirect_ingress(ifindex: i32) -> Self {
        Self {
            direction: MirredDirection::Ingress,
            mode: MirredMode::Redirect,
            ifindex,
            index: None,
        }
    }
    
    /// Mirror packet to ingress of another interface
    pub fn mirror_ingress(ifindex: i32) -> Self {
        Self {
            direction: MirredDirection::Ingress,
            mode: MirredMode::Mirror,
            ifindex,
            index: None,
        }
    }
    
    pub fn build(self) -> Action { Action::Mirred(self) }
}
```

### 2.4 Police (Rate Limiting)

```rust
// crates/rip-action/src/police.rs

/// Rate limiting/policing action
#[derive(Debug, Clone)]
pub struct PoliceAction {
    rate: u64,             // bytes/sec
    burst: u32,            // bytes
    mtu: Option<u32>,
    peakrate: Option<u64>, // bytes/sec
    overhead: Option<u16>,
    linklayer: Option<LinkLayer>,
    
    // Packet-based policing
    pkt_rate: Option<u64>,    // packets/sec
    pkt_burst: Option<u64>,   // packets
    
    // Actions
    conform_action: ActionControl,
    exceed_action: ActionControl,
    
    index: Option<ActionIndex>,
}

#[derive(Debug, Clone, Copy)]
pub enum LinkLayer {
    Ethernet,
    Atm,
}

impl PoliceAction {
    /// Create a new police action with rate limit
    pub fn new(rate: u64, burst: u32) -> Self {
        Self {
            rate,
            burst,
            mtu: None,
            peakrate: None,
            overhead: None,
            linklayer: None,
            pkt_rate: None,
            pkt_burst: None,
            conform_action: ActionControl::Ok,
            exceed_action: ActionControl::Shot,
            index: None,
        }
    }
    
    /// Set peak rate (for two-rate three-color)
    pub fn peakrate(mut self, rate: u64) -> Self {
        self.peakrate = Some(rate);
        self
    }
    
    /// Set MTU
    pub fn mtu(mut self, mtu: u32) -> Self {
        self.mtu = Some(mtu);
        self
    }
    
    /// Set overhead per packet
    pub fn overhead(mut self, overhead: u16) -> Self {
        self.overhead = Some(overhead);
        self
    }
    
    /// Set packet-based rate limiting
    pub fn pkt_rate(mut self, rate: u64, burst: u64) -> Self {
        self.pkt_rate = Some(rate);
        self.pkt_burst = Some(burst);
        self
    }
    
    /// Set action when conforming
    pub fn conform(mut self, action: ActionControl) -> Self {
        self.conform_action = action;
        self
    }
    
    /// Set action when exceeding
    pub fn exceed(mut self, action: ActionControl) -> Self {
        self.exceed_action = action;
        self
    }
    
    pub fn build(self) -> Action { Action::Police(self) }
}
```

### 2.5 Vlan Action

```rust
// crates/rip-action/src/vlan.rs

/// VLAN tag manipulation action
#[derive(Debug, Clone)]
pub enum VlanAction {
    Pop,
    Push {
        id: u16,
        protocol: VlanProtocol,
        priority: Option<u8>,
    },
    Modify {
        id: Option<u16>,
        priority: Option<u8>,
    },
}

#[derive(Debug, Clone, Copy)]
pub enum VlanProtocol {
    Q8021Q,    // 0x8100
    Q8021AD,   // 0x88a8 (QinQ)
}

impl VlanAction {
    /// Pop VLAN tag
    pub fn pop() -> Self { VlanAction::Pop }
    
    /// Push VLAN tag
    pub fn push(id: u16) -> Self {
        VlanAction::Push { id, protocol: VlanProtocol::Q8021Q, priority: None }
    }
    
    /// Push 802.1ad (QinQ) tag
    pub fn push_qinq(id: u16) -> Self {
        VlanAction::Push { id, protocol: VlanProtocol::Q8021AD, priority: None }
    }
    
    /// Modify VLAN ID
    pub fn modify_id(id: u16) -> Self {
        VlanAction::Modify { id: Some(id), priority: None }
    }
    
    /// Modify VLAN priority
    pub fn modify_priority(priority: u8) -> Self {
        VlanAction::Modify { id: None, priority: Some(priority) }
    }
    
    pub fn build(self) -> Action { Action::Vlan(self) }
}
```

### 2.6 Skbedit Action

```rust
// crates/rip-action/src/skbedit.rs

/// SKB field editing action
#[derive(Debug, Clone, Default)]
pub struct SkbeditAction {
    priority: Option<u32>,
    queue_mapping: Option<u16>,
    mark: Option<(u32, Option<u32>)>,  // (value, mask)
    ptype: Option<PacketType>,
}

#[derive(Debug, Clone, Copy)]
pub enum PacketType {
    Host,
    Broadcast,
    Multicast,
    OtherHost,
    Outgoing,
    Loopback,
}

impl SkbeditAction {
    pub fn new() -> Self { Self::default() }
    
    /// Set packet priority (classid)
    pub fn priority(mut self, prio: u32) -> Self {
        self.priority = Some(prio);
        self
    }
    
    /// Set TX queue mapping
    pub fn queue(mut self, queue: u16) -> Self {
        self.queue_mapping = Some(queue);
        self
    }
    
    /// Set firewall mark
    pub fn mark(mut self, value: u32) -> Self {
        self.mark = Some((value, None));
        self
    }
    
    /// Set firewall mark with mask
    pub fn mark_masked(mut self, value: u32, mask: u32) -> Self {
        self.mark = Some((value, Some(mask)));
        self
    }
    
    /// Set packet type
    pub fn ptype(mut self, ptype: PacketType) -> Self {
        self.ptype = Some(ptype);
        self
    }
    
    pub fn build(self) -> Action { Action::Skbedit(self) }
}
```

### 2.7 Files to Create

```
crates/rip-action/
├── Cargo.toml
└── src/
    ├── lib.rs          # Module exports, Action enum, ActionConfig trait
    ├── types.rs        # ActionControl, ActionIndex
    ├── gact.rs         # GactAction
    ├── mirred.rs       # MirredAction
    ├── police.rs       # PoliceAction
    ├── vlan.rs         # VlanAction
    ├── skbedit.rs      # SkbeditAction
    ├── pedit.rs        # PeditAction (packet editing)
    ├── tunnel_key.rs   # TunnelKeyAction
    ├── builder.rs      # Netlink message building
    └── parse.rs        # Response parsing
```

---

## Phase 3: Socket Diagnostics - `ss` Command (High Priority)

### Crate: `rip-sockdiag`

A library for querying socket information via NETLINK_SOCK_DIAG.

### 3.1 Core Types

```rust
// crates/rip-sockdiag/src/lib.rs

/// Socket diagnostics connection
pub struct SockDiag {
    socket: NetlinkSocket,
}

impl SockDiag {
    /// Create a new socket diagnostics connection
    pub async fn new() -> Result<Self> { ... }
    
    /// Query TCP sockets
    pub async fn tcp_sockets(&self, filter: &SocketFilter) -> Result<Vec<TcpSocket>> { ... }
    
    /// Query UDP sockets
    pub async fn udp_sockets(&self, filter: &SocketFilter) -> Result<Vec<UdpSocket>> { ... }
    
    /// Query Unix sockets
    pub async fn unix_sockets(&self, filter: &SocketFilter) -> Result<Vec<UnixSocket>> { ... }
    
    /// Query raw sockets
    pub async fn raw_sockets(&self, filter: &SocketFilter) -> Result<Vec<RawSocket>> { ... }
    
    /// Query all sockets matching filter
    pub async fn all_sockets(&self, filter: &SocketFilter) -> Result<SocketList> { ... }
    
    /// Kill sockets matching filter (requires CAP_NET_ADMIN)
    pub async fn kill_sockets(&self, filter: &SocketFilter) -> Result<u32> { ... }
}
```

### 3.2 Socket Filter

```rust
// crates/rip-sockdiag/src/filter.rs

/// Filter for socket queries
#[derive(Debug, Clone, Default)]
pub struct SocketFilter {
    /// Socket families to include
    families: SocketFamilies,
    /// Socket states to include
    states: SocketStates,
    /// Source address filter
    src: Option<AddrFilter>,
    /// Destination address filter
    dst: Option<AddrFilter>,
    /// Source port filter
    sport: Option<PortFilter>,
    /// Destination port filter
    dport: Option<PortFilter>,
    /// Interface filter
    dev: Option<String>,
    /// User filter
    user: Option<u32>,
    /// Cgroup filter
    cgroup: Option<u64>,
}

bitflags! {
    pub struct SocketFamilies: u32 {
        const INET = 1 << 0;    // AF_INET
        const INET6 = 1 << 1;   // AF_INET6
        const UNIX = 1 << 2;    // AF_UNIX
        const NETLINK = 1 << 3; // AF_NETLINK
        const PACKET = 1 << 4;  // AF_PACKET
        const VSOCK = 1 << 5;   // AF_VSOCK
        const XDP = 1 << 6;     // AF_XDP
        const TIPC = 1 << 7;    // AF_TIPC
        
        const ALL_INET = Self::INET.bits() | Self::INET6.bits();
        const ALL = 0xFFFFFFFF;
    }
}

bitflags! {
    pub struct SocketStates: u32 {
        const ESTABLISHED = 1 << 0;
        const SYN_SENT = 1 << 1;
        const SYN_RECV = 1 << 2;
        const FIN_WAIT1 = 1 << 3;
        const FIN_WAIT2 = 1 << 4;
        const TIME_WAIT = 1 << 5;
        const CLOSE = 1 << 6;
        const CLOSE_WAIT = 1 << 7;
        const LAST_ACK = 1 << 8;
        const LISTEN = 1 << 9;
        const CLOSING = 1 << 10;
        
        const CONNECTED = Self::ESTABLISHED.bits() | Self::SYN_SENT.bits() | 
                         Self::SYN_RECV.bits() | Self::FIN_WAIT1.bits() |
                         Self::FIN_WAIT2.bits() | Self::CLOSE_WAIT.bits() |
                         Self::LAST_ACK.bits() | Self::CLOSING.bits();
        const ALL = 0xFFFFFFFF;
    }
}

#[derive(Debug, Clone)]
pub enum AddrFilter {
    Exact(IpAddr),
    Prefix(IpAddr, u8),
}

#[derive(Debug, Clone)]
pub enum PortFilter {
    Exact(u16),
    Range { min: u16, max: u16 },
    Not(u16),
}

impl SocketFilter {
    pub fn new() -> Self { Self::default() }
    
    /// Filter by address family
    pub fn family(mut self, families: SocketFamilies) -> Self { ... }
    
    /// Filter TCP sockets only
    pub fn tcp(mut self) -> Self { ... }
    
    /// Filter UDP sockets only
    pub fn udp(mut self) -> Self { ... }
    
    /// Filter Unix sockets only
    pub fn unix(mut self) -> Self { ... }
    
    /// Filter by socket state
    pub fn state(mut self, states: SocketStates) -> Self { ... }
    
    /// Filter listening sockets
    pub fn listening(mut self) -> Self { ... }
    
    /// Filter established connections
    pub fn established(mut self) -> Self { ... }
    
    /// Filter by source address
    pub fn src(mut self, addr: IpAddr) -> Self { ... }
    
    /// Filter by source prefix
    pub fn src_prefix(mut self, prefix: IpAddr, len: u8) -> Self { ... }
    
    /// Filter by destination address
    pub fn dst(mut self, addr: IpAddr) -> Self { ... }
    
    /// Filter by source port
    pub fn sport(mut self, port: u16) -> Self { ... }
    
    /// Filter by destination port
    pub fn dport(mut self, port: u16) -> Self { ... }
    
    /// Filter by port range
    pub fn dport_range(mut self, min: u16, max: u16) -> Self { ... }
    
    /// Compile filter to BPF bytecode
    fn to_bytecode(&self) -> Vec<u8> { ... }
}
```

### 3.3 TCP Socket Information

```rust
// crates/rip-sockdiag/src/tcp.rs

/// TCP socket information
#[derive(Debug, Clone)]
pub struct TcpSocket {
    /// Socket state
    pub state: TcpState,
    /// Local address
    pub local: SocketAddr,
    /// Remote address (for connected sockets)
    pub remote: Option<SocketAddr>,
    /// Receive queue length
    pub recv_q: u32,
    /// Send queue length
    pub send_q: u32,
    /// User ID
    pub uid: u32,
    /// Inode number
    pub inode: u64,
    /// Interface index
    pub ifindex: Option<u32>,
    /// Timer information
    pub timer: Option<TimerInfo>,
    /// TCP-specific info
    pub info: Option<TcpInfo>,
    /// Memory info
    pub meminfo: Option<SocketMemInfo>,
    /// Congestion control algorithm
    pub cong: Option<String>,
}

/// TCP state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpState {
    Established,
    SynSent,
    SynRecv,
    FinWait1,
    FinWait2,
    TimeWait,
    Close,
    CloseWait,
    LastAck,
    Listen,
    Closing,
    NewSynRecv,
    BoundInactive,
}

/// Detailed TCP information (from struct tcp_info)
#[derive(Debug, Clone)]
pub struct TcpInfo {
    /// Congestion avoidance state
    pub ca_state: CongestionState,
    /// Retransmit timeout (us)
    pub rto: u32,
    /// ACK timeout (us)
    pub ato: u32,
    /// Send MSS
    pub snd_mss: u32,
    /// Receive MSS
    pub rcv_mss: u32,
    /// Unacked packets
    pub unacked: u32,
    /// SACKed packets
    pub sacked: u32,
    /// Lost packets
    pub lost: u32,
    /// Retransmitted packets
    pub retrans: u32,
    /// RTT (us)
    pub rtt: u32,
    /// RTT variance (us)
    pub rttvar: u32,
    /// Send slow-start threshold
    pub snd_ssthresh: u32,
    /// Send congestion window
    pub snd_cwnd: u32,
    /// Pacing rate (bytes/sec)
    pub pacing_rate: u64,
    /// Delivery rate (bytes/sec)
    pub delivery_rate: u64,
    /// Bytes acked
    pub bytes_acked: u64,
    /// Bytes received
    pub bytes_received: u64,
    /// Segments out
    pub segs_out: u32,
    /// Segments in
    pub segs_in: u32,
    /// Minimum RTT (us)
    pub min_rtt: u32,
    /// Busy time (us)
    pub busy_time: u64,
    /// Options (timestamps, sack, wscale, ecn)
    pub options: TcpOptions,
}

bitflags! {
    pub struct TcpOptions: u8 {
        const TIMESTAMPS = 1 << 0;
        const SACK = 1 << 1;
        const WSCALE = 1 << 2;
        const ECN = 1 << 3;
        const ECN_SEEN = 1 << 4;
        const SYN_DATA = 1 << 5;  // TCP Fast Open
    }
}

#[derive(Debug, Clone, Copy)]
pub enum CongestionState {
    Open,
    Disorder,
    Cwr,
    Recovery,
    Loss,
}
```

### 3.4 Unix Socket Information

```rust
// crates/rip-sockdiag/src/unix.rs

/// Unix socket information
#[derive(Debug, Clone)]
pub struct UnixSocket {
    /// Socket type
    pub sock_type: UnixType,
    /// Socket state
    pub state: UnixState,
    /// Socket path (for bound sockets)
    pub path: Option<PathBuf>,
    /// Inode number
    pub inode: u64,
    /// Peer inode (for connected sockets)
    pub peer: Option<u64>,
    /// Receive queue length
    pub recv_q: u32,
    /// Send queue length
    pub send_q: u32,
    /// User ID
    pub uid: Option<u32>,
    /// VFS info
    pub vfs: Option<VfsInfo>,
    /// Pending connections (for listening sockets)
    pub pending: Option<Vec<u64>>,
}

#[derive(Debug, Clone, Copy)]
pub enum UnixType {
    Stream,
    Dgram,
    SeqPacket,
}

#[derive(Debug, Clone, Copy)]
pub enum UnixState {
    Unconnected,
    Listening,
    Connected,
}

#[derive(Debug, Clone)]
pub struct VfsInfo {
    pub dev: u64,
    pub ino: u64,
}
```

### 3.5 Memory Information

```rust
// crates/rip-sockdiag/src/meminfo.rs

/// Socket memory information
#[derive(Debug, Clone)]
pub struct SocketMemInfo {
    /// Receive buffer allocated
    pub rmem_alloc: u32,
    /// Receive buffer size
    pub rcvbuf: u32,
    /// Write buffer allocated
    pub wmem_alloc: u32,
    /// Send buffer size
    pub sndbuf: u32,
    /// Forward alloc
    pub fwd_alloc: u32,
    /// Write buffer queued
    pub wmem_queued: u32,
    /// Option memory
    pub optmem: u32,
    /// Backlog
    pub backlog: u32,
    /// Drops
    pub drops: u32,
}
```

### 3.6 Files to Create

```
crates/rip-sockdiag/
├── Cargo.toml
└── src/
    ├── lib.rs          # SockDiag struct, main API
    ├── filter.rs       # SocketFilter builder
    ├── bytecode.rs     # BPF bytecode compiler for filtering
    ├── tcp.rs          # TcpSocket, TcpInfo, TcpState
    ├── udp.rs          # UdpSocket
    ├── unix.rs         # UnixSocket
    ├── raw.rs          # RawSocket
    ├── netlink.rs      # NetlinkSocket info
    ├── packet.rs       # PacketSocket info
    ├── vsock.rs        # VsockSocket info
    ├── meminfo.rs      # SocketMemInfo
    ├── request.rs      # Request builders
    └── parse.rs        # Response parsing

bins/ss/
├── Cargo.toml
└── src/
    ├── main.rs
    └── output.rs       # Formatting (mimics ss output)
```

### 3.7 CLI (`bins/ss`)

```rust
// bins/ss/src/main.rs

#[derive(Parser)]
#[command(name = "ss")]
#[command(about = "Socket statistics - investigate sockets")]
struct Cli {
    /// Show TCP sockets
    #[arg(short = 't', long)]
    tcp: bool,
    
    /// Show UDP sockets
    #[arg(short = 'u', long)]
    udp: bool,
    
    /// Show Unix sockets
    #[arg(short = 'x', long)]
    unix: bool,
    
    /// Show raw sockets
    #[arg(short = 'w', long)]
    raw: bool,
    
    /// Show all sockets
    #[arg(short = 'a', long)]
    all: bool,
    
    /// Show listening sockets
    #[arg(short = 'l', long)]
    listening: bool,
    
    /// Show processes using socket
    #[arg(short = 'p', long)]
    processes: bool,
    
    /// Extended info
    #[arg(short = 'e', long)]
    extended: bool,
    
    /// Show internal TCP info
    #[arg(short = 'i', long)]
    info: bool,
    
    /// Show memory info
    #[arg(short = 'm', long)]
    memory: bool,
    
    /// Show timer info
    #[arg(short = 'o', long)]
    options: bool,
    
    /// Don't resolve service names
    #[arg(short = 'n', long)]
    numeric: bool,
    
    /// Don't resolve host names
    #[arg(short = 'r', long)]
    resolve: bool,
    
    /// Show IPv4 sockets only
    #[arg(short = '4', long)]
    ipv4: bool,
    
    /// Show IPv6 sockets only
    #[arg(short = '6', long)]
    ipv6: bool,
    
    /// Kill matching sockets
    #[arg(short = 'K', long)]
    kill: bool,
    
    /// Output format
    #[arg(short = 'j', long)]
    json: bool,
    
    /// State filter (established, listening, etc.)
    #[arg(long)]
    state: Option<String>,
    
    /// Filter expression (sport, dport, src, dst)
    filter: Vec<String>,
}
```

---

## Phase 4: TUN/TAP Management (High Priority)

### Location: `crates/rip-tuntap/`

TUN/TAP device management for VPNs and containers.

### 4.1 Core API

```rust
// crates/rip-tuntap/src/lib.rs

/// TUN/TAP device modes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunTapMode {
    Tun,  // Layer 3
    Tap,  // Layer 2
}

/// TUN/TAP device configuration
#[derive(Debug, Clone)]
pub struct TunTapConfig {
    mode: TunTapMode,
    name: Option<String>,
    multi_queue: bool,
    packet_info: bool,  // Include packet info header
    vnet_hdr: bool,     // Include virtio-net header
    persist: bool,
    owner: Option<u32>,
    group: Option<u32>,
}

impl TunTapConfig {
    pub fn tun() -> Self { ... }
    pub fn tap() -> Self { ... }
    
    /// Set device name (or use system-assigned)
    pub fn name(mut self, name: impl Into<String>) -> Self { ... }
    
    /// Enable multi-queue mode
    pub fn multi_queue(mut self) -> Self { ... }
    
    /// Include packet info header
    pub fn packet_info(mut self, enabled: bool) -> Self { ... }
    
    /// Include virtio-net header
    pub fn vnet_hdr(mut self) -> Self { ... }
    
    /// Make device persistent
    pub fn persist(mut self) -> Self { ... }
    
    /// Set owner UID
    pub fn owner(mut self, uid: u32) -> Self { ... }
    
    /// Set group GID
    pub fn group(mut self, gid: u32) -> Self { ... }
    
    /// Create the device
    pub fn create(self) -> Result<TunTapDevice> { ... }
}

/// A TUN/TAP device handle
pub struct TunTapDevice {
    fd: OwnedFd,
    name: String,
    mode: TunTapMode,
}

impl TunTapDevice {
    /// Get the device name
    pub fn name(&self) -> &str { ... }
    
    /// Get the file descriptor
    pub fn as_raw_fd(&self) -> RawFd { ... }
    
    /// Read a packet
    pub async fn read(&self, buf: &mut [u8]) -> Result<usize> { ... }
    
    /// Write a packet
    pub async fn write(&self, buf: &[u8]) -> Result<usize> { ... }
    
    /// Make the device persistent
    pub fn set_persist(&self, persist: bool) -> Result<()> { ... }
    
    /// Set owner/group
    pub fn set_owner(&self, uid: u32, gid: u32) -> Result<()> { ... }
}

/// List existing TUN/TAP devices
pub async fn list_tuntap() -> Result<Vec<TunTapInfo>> { ... }

/// TUN/TAP device information
#[derive(Debug, Clone)]
pub struct TunTapInfo {
    pub name: String,
    pub mode: TunTapMode,
    pub flags: TunTapFlags,
    pub owner: Option<u32>,
    pub group: Option<u32>,
    pub attached_fds: u32,
}

bitflags! {
    pub struct TunTapFlags: u16 {
        const MULTI_QUEUE = 1 << 0;
        const PERSIST = 1 << 1;
        const VNET_HDR = 1 << 2;
        const NO_PI = 1 << 3;
    }
}
```

### 4.2 CLI Integration

```rust
// bins/ip/src/commands/tuntap.rs

#[derive(Parser)]
pub struct TuntapCmd {
    #[command(subcommand)]
    action: TuntapAction,
}

#[derive(Subcommand)]
enum TuntapAction {
    Add {
        /// Device name
        #[arg(long)]
        name: String,
        /// Device mode
        #[arg(long, value_parser = ["tun", "tap"])]
        mode: String,
        /// User ID
        #[arg(long)]
        user: Option<String>,
        /// Group ID
        #[arg(long)]
        group: Option<String>,
        /// Multi-queue mode
        #[arg(long)]
        multi_queue: bool,
    },
    Del {
        /// Device name
        #[arg(long)]
        name: String,
    },
    Show,
}
```

### 4.3 Files to Create

```
crates/rip-tuntap/
├── Cargo.toml
└── src/
    ├── lib.rs          # Public API
    ├── config.rs       # TunTapConfig builder
    ├── device.rs       # TunTapDevice handle
    ├── ioctl.rs        # ioctl wrappers
    └── list.rs         # List existing devices
```

---

## Phase 5: Additional Qdiscs (High Priority)

### Add to existing `rip-tc` crate:

### 5.1 CAKE (Common Applications Kept Enhanced)

```rust
// crates/rip-tc/src/options/cake.rs

/// CAKE qdisc configuration
#[derive(Debug, Clone)]
pub struct CakeConfig {
    bandwidth: Option<u64>,       // bytes/sec
    rtt: Option<Duration>,        // Base RTT
    overhead: Option<i32>,        // Per-packet overhead
    mpu: Option<u32>,             // Minimum packet unit
    
    // Shaping mode
    autorate_ingress: bool,
    
    // Fairness mode
    flow_mode: CakeFlowMode,
    
    // Priority mode
    diffserv: CakeDiffserv,
    
    // NAT mode
    nat: bool,
    
    // ACK filter
    ack_filter: CakeAckFilter,
    
    // Split GSO
    split_gso: bool,
    
    // Memlimit
    memlimit: Option<u64>,
    
    // Wash
    wash: bool,
}

#[derive(Debug, Clone, Copy, Default)]
pub enum CakeFlowMode {
    #[default]
    Triple,    // Host fairness with flow fairness
    Dual,      // Host fairness only (src or dst)
    Single,    // Flow-based only
    Flows,     // Per-flow fairness
    SrcHost,   // Source host fairness
    DstHost,   // Destination host fairness
    Hosts,     // Host fairness both directions
}

#[derive(Debug, Clone, Copy, Default)]
pub enum CakeDiffserv {
    #[default]
    Diffserv4, // 4-class model (voice, video, best-effort, background)
    Diffserv3, // 3-class model
    Precedence, // 8-class precedence
    Besteffort, // Single class
}

#[derive(Debug, Clone, Copy, Default)]
pub enum CakeAckFilter {
    #[default]
    No,        // No ACK filtering
    Yes,       // ACK filtering enabled
    Aggressive, // Aggressive ACK filtering
}

impl CakeConfig {
    pub fn new() -> Self { Self::default() }
    
    /// Set bandwidth limit
    pub fn bandwidth(mut self, rate: u64) -> Self { ... }
    
    /// Set base RTT
    pub fn rtt(mut self, rtt: Duration) -> Self { ... }
    
    /// Set overhead
    pub fn overhead(mut self, overhead: i32) -> Self { ... }
    
    /// Enable autorate for ingress
    pub fn autorate_ingress(mut self) -> Self { ... }
    
    /// Set flow isolation mode
    pub fn flow_mode(mut self, mode: CakeFlowMode) -> Self { ... }
    
    /// Set diffserv mode
    pub fn diffserv(mut self, mode: CakeDiffserv) -> Self { ... }
    
    /// Enable NAT mode
    pub fn nat(mut self) -> Self { ... }
    
    /// Enable ACK filtering
    pub fn ack_filter(mut self, mode: CakeAckFilter) -> Self { ... }
    
    /// Set memory limit
    pub fn memlimit(mut self, bytes: u64) -> Self { ... }
}

impl QdiscConfig for CakeConfig { ... }
```

### 5.2 FQ (Fair Queue)

```rust
// crates/rip-tc/src/options/fq.rs

/// Fair Queue qdisc configuration
#[derive(Debug, Clone)]
pub struct FqConfig {
    plimit: Option<u32>,       // Max packets in queue
    flow_plimit: Option<u32>,  // Per-flow packet limit
    quantum: Option<u32>,      // Quantum (MTU)
    initial_quantum: Option<u32>,
    rate: Option<u64>,         // Pacing rate
    defrate: Option<u64>,      // Default flow rate
    refill_delay: Option<Duration>,
    orphan_mask: Option<u32>,
    ce_threshold: Option<Duration>,
    timer_slack: Option<Duration>,
    horizon: Option<Duration>,
    horizon_drop: bool,
    priomap: Option<[u8; 16]>,
    weights: Option<[u8; 3]>,
}

impl FqConfig {
    pub fn new() -> Self { Self::default() }
    
    /// Set packet limit
    pub fn limit(mut self, packets: u32) -> Self { ... }
    
    /// Set per-flow packet limit
    pub fn flow_limit(mut self, packets: u32) -> Self { ... }
    
    /// Set quantum
    pub fn quantum(mut self, bytes: u32) -> Self { ... }
    
    /// Set pacing rate
    pub fn rate(mut self, rate: u64) -> Self { ... }
    
    /// Set default flow rate
    pub fn defrate(mut self, rate: u64) -> Self { ... }
    
    /// Set CE threshold for ECN
    pub fn ce_threshold(mut self, threshold: Duration) -> Self { ... }
}

impl QdiscConfig for FqConfig { ... }
```

### 5.3 Codel (Controlled Delay)

```rust
// crates/rip-tc/src/options/codel.rs

/// CoDel qdisc configuration  
#[derive(Debug, Clone)]
pub struct CodelConfig {
    limit: Option<u32>,        // Max queue size (packets)
    target: Option<Duration>,  // Target delay
    interval: Option<Duration>, // Measurement interval
    ecn: bool,                 // Use ECN instead of drop
    ce_threshold: Option<Duration>,
}

impl CodelConfig {
    pub fn new() -> Self { Self::default() }
    
    /// Set queue limit
    pub fn limit(mut self, packets: u32) -> Self { ... }
    
    /// Set target delay
    pub fn target(mut self, target: Duration) -> Self { ... }
    
    /// Set measurement interval
    pub fn interval(mut self, interval: Duration) -> Self { ... }
    
    /// Enable ECN marking
    pub fn ecn(mut self) -> Self { ... }
}

impl QdiscConfig for CodelConfig { ... }
```

---

## Phase 6: Nexthop Objects (Medium Priority)

### Add to `rip-netlink`:

### 6.1 Core Types

```rust
// crates/rip-netlink/src/types/nexthop.rs

/// Nexthop object ID
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NexthopId(pub u32);

/// Nexthop group ID
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NexthopGroupId(pub u32);

/// A nexthop object
#[derive(Debug, Clone)]
pub struct Nexthop {
    pub id: NexthopId,
    pub gateway: Option<IpAddr>,
    pub ifindex: Option<i32>,
    pub flags: NexthopFlags,
    pub scope: u8,
    pub protocol: u8,
    pub encap: Option<NexthopEncap>,
}

bitflags! {
    pub struct NexthopFlags: u32 {
        const ONLINK = 1 << 0;
        const PERVASIVE = 1 << 1;
        const OFFLOAD = 1 << 2;
        const TRAP = 1 << 3;
    }
}

/// Nexthop encapsulation
#[derive(Debug, Clone)]
pub enum NexthopEncap {
    Mpls { labels: Vec<u32> },
    Seg6 { segments: Vec<Ipv6Addr>, mode: Seg6Mode },
    Seg6Local { action: Seg6LocalAction },
}

/// Nexthop group
#[derive(Debug, Clone)]
pub struct NexthopGroup {
    pub id: NexthopGroupId,
    pub group_type: NexthopGroupType,
    pub nexthops: Vec<NexthopGroupEntry>,
}

#[derive(Debug, Clone, Copy)]
pub enum NexthopGroupType {
    Mpath,       // Multipath (ECMP)
    Resilient,   // Resilient hashing
}

#[derive(Debug, Clone)]
pub struct NexthopGroupEntry {
    pub id: NexthopId,
    pub weight: u8,
}
```

### 6.2 Connection API

```rust
// crates/rip-netlink/src/connection.rs (additions)

impl Connection {
    /// Add a nexthop object
    pub async fn add_nexthop(&self, nh: &Nexthop) -> Result<NexthopId> { ... }
    
    /// Delete a nexthop object
    pub async fn del_nexthop(&self, id: NexthopId) -> Result<()> { ... }
    
    /// Get a nexthop object
    pub async fn get_nexthop(&self, id: NexthopId) -> Result<Nexthop> { ... }
    
    /// List all nexthop objects
    pub async fn get_nexthops(&self) -> Result<Vec<Nexthop>> { ... }
    
    /// Add a nexthop group
    pub async fn add_nexthop_group(&self, group: &NexthopGroup) -> Result<NexthopGroupId> { ... }
    
    /// Delete a nexthop group
    pub async fn del_nexthop_group(&self, id: NexthopGroupId) -> Result<()> { ... }
    
    /// List all nexthop groups
    pub async fn get_nexthop_groups(&self) -> Result<Vec<NexthopGroup>> { ... }
}
```

### 6.3 CLI Integration

```rust
// bins/ip/src/commands/nexthop.rs

#[derive(Parser)]
pub struct NexthopCmd {
    #[command(subcommand)]
    action: NexthopAction,
}

#[derive(Subcommand)]
enum NexthopAction {
    Add {
        /// Nexthop ID
        #[arg(long)]
        id: u32,
        /// Gateway address
        #[arg(long)]
        via: Option<String>,
        /// Output interface
        #[arg(long)]
        dev: Option<String>,
        /// Onlink flag
        #[arg(long)]
        onlink: bool,
    },
    Del {
        #[arg(long)]
        id: u32,
    },
    Show,
    Replace {
        #[arg(long)]
        id: u32,
        #[arg(long)]
        via: Option<String>,
        #[arg(long)]
        dev: Option<String>,
    },
    Group {
        #[command(subcommand)]
        action: GroupAction,
    },
}
```

---

## Phase 7: L2TP Tunnels (Medium Priority)

### Location: Enhancement to `rip-netlink`

### 7.1 Core Types

```rust
// crates/rip-netlink/src/types/l2tp.rs

/// L2TP tunnel configuration
#[derive(Debug, Clone)]
pub struct L2tpTunnel {
    pub tunnel_id: u32,
    pub peer_tunnel_id: u32,
    pub local: SocketAddr,
    pub remote: SocketAddr,
    pub encap: L2tpEncap,
    pub udp_csum: bool,
    pub udp_csum6: bool,
}

#[derive(Debug, Clone, Copy)]
pub enum L2tpEncap {
    Udp,
    Ip,
}

/// L2TP session configuration
#[derive(Debug, Clone)]
pub struct L2tpSession {
    pub tunnel_id: u32,
    pub session_id: u32,
    pub peer_session_id: u32,
    pub ifname: Option<String>,
    pub cookie: Option<Vec<u8>>,
    pub peer_cookie: Option<Vec<u8>>,
    pub l2spec_type: L2SpecType,
    pub seq: bool,
}

#[derive(Debug, Clone, Copy)]
pub enum L2SpecType {
    None,
    Default,
}
```

### 7.2 Generic Netlink Interface

L2TP uses Generic Netlink (GENL), not RTNetlink:

```rust
// crates/rip-netlink/src/genl/l2tp.rs

pub struct L2tpConnection {
    socket: GenericNetlinkSocket,
    family_id: u16,
}

impl L2tpConnection {
    pub async fn new() -> Result<Self> { ... }
    
    /// Create a tunnel
    pub async fn create_tunnel(&self, tunnel: &L2tpTunnel) -> Result<()> { ... }
    
    /// Delete a tunnel
    pub async fn delete_tunnel(&self, tunnel_id: u32) -> Result<()> { ... }
    
    /// Create a session
    pub async fn create_session(&self, session: &L2tpSession) -> Result<()> { ... }
    
    /// Delete a session
    pub async fn delete_session(&self, tunnel_id: u32, session_id: u32) -> Result<()> { ... }
    
    /// List tunnels
    pub async fn list_tunnels(&self) -> Result<Vec<L2tpTunnel>> { ... }
    
    /// List sessions
    pub async fn list_sessions(&self, tunnel_id: Option<u32>) -> Result<Vec<L2tpSession>> { ... }
}
```

---

## Phase 8: Multicast Routing (Medium Priority)

### Add to `rip-netlink`:

### 8.1 Core Types

```rust
// crates/rip-netlink/src/types/mroute.rs

/// Multicast route entry
#[derive(Debug, Clone)]
pub struct MrouteEntry {
    pub source: IpAddr,
    pub group: IpAddr,
    pub iif: i32,
    pub oifs: Vec<MrouteOif>,
    pub packets: u64,
    pub bytes: u64,
    pub wrong_if: u64,
}

#[derive(Debug, Clone)]
pub struct MrouteOif {
    pub ifindex: i32,
    pub ttl: u8,
}

/// Multicast interface
#[derive(Debug, Clone)]
pub struct MrouteIface {
    pub ifindex: i32,
    pub vif: u32,
    pub flags: MrouteIfFlags,
}

bitflags! {
    pub struct MrouteIfFlags: u32 {
        const REGISTER = 1 << 0;
        const USE_IFINDEX = 1 << 1;
    }
}
```

### 8.2 Connection API

```rust
impl Connection {
    /// List multicast routes
    pub async fn get_mroutes(&self) -> Result<Vec<MrouteEntry>> { ... }
    
    /// Add multicast route
    pub async fn add_mroute(&self, route: &MrouteEntry) -> Result<()> { ... }
    
    /// Delete multicast route
    pub async fn del_mroute(&self, source: IpAddr, group: IpAddr) -> Result<()> { ... }
}
```

---

## Implementation Timeline

### Priority Order

1. **Phase 1: TC Filters** - Essential for traffic classification
2. **Phase 2: TC Actions** - Required by filters
3. **Phase 3: Socket Diagnostics (ss)** - High user demand
4. **Phase 4: TUN/TAP** - Important for VPN/container use cases
5. **Phase 5: Additional Qdiscs** - Complete TC support
6. **Phase 6: Nexthop Objects** - Modern routing
7. **Phase 7: L2TP** - VPN support
8. **Phase 8: Multicast Routing** - Specialized use case

### Estimated Scope

| Phase | New Files | New Lines | Complexity |
|-------|-----------|-----------|------------|
| 1 | 10 | ~2000 | High |
| 2 | 12 | ~1800 | High |
| 3 | 15 | ~3000 | High |
| 4 | 5 | ~800 | Medium |
| 5 | 3 | ~600 | Low |
| 6 | 3 | ~500 | Medium |
| 7 | 4 | ~600 | Medium |
| 8 | 2 | ~400 | Low |
| **Total** | **54** | **~9700** | - |

---

## Testing Strategy

### Unit Tests
- Builder pattern validation
- Netlink message serialization/deserialization
- Filter bytecode compilation (for ss)

### Integration Tests
- All operations in network namespaces
- Feature-gated with `#[cfg(feature = "integration")]`
- Run with `sudo unshare -n cargo test --features integration`

### Functional Tests
- Shell scripts comparing output with iproute2
- Located in `tests/` directory

---

## Documentation Requirements

Each new crate must include:

1. **Crate-level documentation** with:
   - Purpose and scope
   - Quick start example
   - API overview

2. **Type documentation**:
   - All public types documented
   - Examples for builders
   - Links to related types

3. **README.md** with:
   - Installation
   - Basic usage
   - Feature flags

4. **Examples** in `examples/` directory:
   - Basic usage
   - Advanced patterns
   - Integration with other crates
