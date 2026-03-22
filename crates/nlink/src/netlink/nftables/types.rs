//! nftables data types: Family, Hook, Chain, Rule, Table, etc.

use std::net::Ipv4Addr;

/// nftables address family.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Family {
    /// IPv4 only.
    Ip = 2,
    /// IPv6 only.
    Ip6 = 10,
    /// Dual-stack (IPv4 + IPv6).
    Inet = 1,
    /// ARP.
    Arp = 3,
    /// Bridge.
    Bridge = 7,
    /// Netdev (ingress).
    Netdev = 5,
}

impl Family {
    pub fn from_u8(val: u8) -> Option<Self> {
        match val {
            2 => Some(Self::Ip),
            10 => Some(Self::Ip6),
            1 => Some(Self::Inet),
            3 => Some(Self::Arp),
            7 => Some(Self::Bridge),
            5 => Some(Self::Netdev),
            _ => None,
        }
    }
}

/// Netfilter hook point.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Hook {
    Prerouting,
    Input,
    Forward,
    Output,
    Postrouting,
    Ingress,
}

impl Hook {
    pub fn to_u32(self) -> u32 {
        match self {
            Self::Prerouting => 0,
            Self::Input => 1,
            Self::Forward => 2,
            Self::Output => 3,
            Self::Postrouting => 4,
            Self::Ingress => 0,
        }
    }
}

/// Chain type string for the kernel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainType {
    Filter,
    Nat,
    Route,
}

impl ChainType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Filter => "filter",
            Self::Nat => "nat",
            Self::Route => "route",
        }
    }
}

/// Chain priority (determines ordering).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Priority {
    Raw,
    Mangle,
    DstNat,
    Filter,
    Security,
    SrcNat,
    Custom(i32),
}

impl Priority {
    pub fn to_i32(self) -> i32 {
        match self {
            Self::Raw => -300,
            Self::Mangle => -150,
            Self::DstNat => -100,
            Self::Filter => 0,
            Self::Security => 50,
            Self::SrcNat => 100,
            Self::Custom(v) => v,
        }
    }
}

/// Default policy for a base chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Policy {
    Accept,
    Drop,
}

impl Policy {
    pub fn to_u32(self) -> u32 {
        match self {
            Self::Accept => 1,
            Self::Drop => 0,
        }
    }
}

/// Rule verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    Accept,
    Drop,
    Continue,
    Return,
    Jump(String),
    Goto(String),
}

/// Connection tracking state flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CtState(pub u32);

impl CtState {
    pub const INVALID: Self = Self(1);
    pub const ESTABLISHED: Self = Self(2);
    pub const RELATED: Self = Self(4);
    pub const NEW: Self = Self(8);
    pub const UNTRACKED: Self = Self(64);

    /// Create an empty state with no flags set.
    pub const fn empty() -> Self {
        Self(0)
    }

    pub fn bits(self) -> u32 {
        self.0
    }
}

impl Default for CtState {
    fn default() -> Self {
        Self::empty()
    }
}

impl std::ops::BitOr for CtState {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

impl std::ops::BitOrAssign for CtState {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

/// Rate limit unit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LimitUnit {
    Second,
    Minute,
    Hour,
    Day,
}

impl LimitUnit {
    pub fn to_u64(self) -> u64 {
        match self {
            Self::Second => 1,
            Self::Minute => 60,
            Self::Hour => 3600,
            Self::Day => 86400,
        }
    }
}

/// nftables register (internal).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Register {
    Verdict = 0,
    R0 = 8,
    R1 = 9,
    R2 = 10,
    R3 = 11,
}

/// Comparison operator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CmpOp {
    Eq = 0,
    Neq = 1,
    Lt = 2,
    Lte = 3,
    Gt = 4,
    Gte = 5,
}

/// Payload base header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayloadBase {
    LinkLayer = 0,
    Network = 1,
    Transport = 2,
}

/// Meta key for loading metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MetaKey {
    Len = 0,
    Protocol = 1,
    Mark = 3,
    Iif = 4,
    Oif = 5,
    IifName = 6,
    OifName = 7,
    SkUid = 10,
    SkGid = 11,
    NfProto = 15,
    L4Proto = 16,
    CGroup = 23,
}

/// Conntrack key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CtKey {
    State = 0,
    Direction = 1,
    Status = 2,
    Mark = 3,
    Expiration = 7,
}

/// NAT type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NatType {
    Snat = 0,
    Dnat = 1,
}

/// NAT expression data.
#[derive(Debug, Clone)]
pub struct NatExpr {
    pub nat_type: NatType,
    pub family: Family,
    /// IPv4 address to NAT to (loaded into register before nat expr).
    pub addr: Option<Ipv4Addr>,
    /// Port to NAT to.
    pub port: Option<u16>,
}

impl NatExpr {
    /// Create a SNAT expression.
    pub fn snat(family: Family) -> Self {
        Self {
            nat_type: NatType::Snat,
            family,
            addr: None,
            port: None,
        }
    }

    /// Create a DNAT expression.
    pub fn dnat(family: Family) -> Self {
        Self {
            nat_type: NatType::Dnat,
            family,
            addr: None,
            port: None,
        }
    }

    /// Set the NAT destination address.
    pub fn addr(mut self, addr: Ipv4Addr) -> Self {
        self.addr = Some(addr);
        self
    }

    /// Set the NAT destination port.
    pub fn port(mut self, port: u16) -> Self {
        self.port = Some(port);
        self
    }
}

// =============================================================================
// Table (parsed from dump)
// =============================================================================

/// An nftables table.
#[derive(Debug, Clone)]
pub struct Table {
    /// Table name.
    pub name: String,
    /// Address family.
    pub family: Family,
    /// Flags.
    pub flags: u32,
    /// Number of chains using this table.
    pub use_count: u32,
    /// Kernel handle.
    pub handle: u64,
}

// =============================================================================
// Chain builder
// =============================================================================

/// Chain configuration builder.
#[derive(Debug, Clone)]
pub struct Chain {
    pub(crate) table: String,
    pub(crate) name: String,
    pub(crate) family: Family,
    pub(crate) hook: Option<Hook>,
    pub(crate) priority: Option<Priority>,
    pub(crate) chain_type: Option<ChainType>,
    pub(crate) policy: Option<Policy>,
}

impl Chain {
    /// Create a new chain builder.
    pub fn new(table: &str, name: &str) -> Self {
        Self {
            table: table.to_string(),
            name: name.to_string(),
            family: Family::Inet,
            hook: None,
            priority: None,
            chain_type: None,
            policy: None,
        }
    }

    /// Set the address family.
    pub fn family(mut self, family: Family) -> Self {
        self.family = family;
        self
    }

    /// Set the hook point (makes this a base chain).
    pub fn hook(mut self, hook: Hook) -> Self {
        self.hook = Some(hook);
        self
    }

    /// Set the chain priority.
    pub fn priority(mut self, priority: Priority) -> Self {
        self.priority = Some(priority);
        self
    }

    /// Set the chain type.
    pub fn chain_type(mut self, chain_type: ChainType) -> Self {
        self.chain_type = Some(chain_type);
        self
    }

    /// Set the default policy.
    pub fn policy(mut self, policy: Policy) -> Self {
        self.policy = Some(policy);
        self
    }
}

/// Chain info parsed from a dump.
#[derive(Debug, Clone)]
pub struct ChainInfo {
    /// Table name.
    pub table: String,
    /// Chain name.
    pub name: String,
    /// Address family.
    pub family: Family,
    /// Hook point (None for regular chains).
    pub hook: Option<u32>,
    /// Priority (for base chains).
    pub priority: Option<i32>,
    /// Chain type.
    pub chain_type: Option<String>,
    /// Default policy.
    pub policy: Option<u32>,
    /// Kernel handle.
    pub handle: u64,
}

// =============================================================================
// Rule builder
// =============================================================================

/// Rule configuration builder.
///
/// The builder automatically generates nftables expression sequences
/// from high-level match/action methods.
#[derive(Debug, Clone)]
pub struct Rule {
    pub(crate) table: String,
    pub(crate) chain: String,
    pub(crate) family: Family,
    pub(crate) exprs: Vec<super::expr::Expr>,
    pub(crate) position: Option<u64>,
}

impl Rule {
    /// Create a new rule builder.
    pub fn new(table: &str, chain: &str) -> Self {
        Self {
            table: table.to_string(),
            chain: chain.to_string(),
            family: Family::Inet,
            exprs: Vec::new(),
            position: None,
        }
    }

    /// Set the address family.
    pub fn family(mut self, family: Family) -> Self {
        self.family = family;
        self
    }

    /// Insert at a specific position (before the rule with this handle).
    pub fn position(mut self, pos: u64) -> Self {
        self.position = Some(pos);
        self
    }

    /// Match TCP destination port.
    ///
    /// Generates: meta(L4PROTO) + cmp(==TCP) + payload(dport) + cmp(==port)
    pub fn match_tcp_dport(mut self, port: u16) -> Self {
        use super::expr::Expr;
        self.exprs.push(Expr::Meta {
            dreg: Register::R0,
            key: MetaKey::L4Proto,
        });
        self.exprs.push(Expr::Cmp {
            sreg: Register::R0,
            op: CmpOp::Eq,
            data: vec![6u8], // IPPROTO_TCP
        });
        self.exprs.push(Expr::Payload {
            dreg: Register::R0,
            base: PayloadBase::Transport,
            offset: 2,
            len: 2,
        });
        self.exprs.push(Expr::Cmp {
            sreg: Register::R0,
            op: CmpOp::Eq,
            data: port.to_be_bytes().to_vec(),
        });
        self
    }

    /// Match UDP destination port.
    pub fn match_udp_dport(mut self, port: u16) -> Self {
        use super::expr::Expr;
        self.exprs.push(Expr::Meta {
            dreg: Register::R0,
            key: MetaKey::L4Proto,
        });
        self.exprs.push(Expr::Cmp {
            sreg: Register::R0,
            op: CmpOp::Eq,
            data: vec![17u8], // IPPROTO_UDP
        });
        self.exprs.push(Expr::Payload {
            dreg: Register::R0,
            base: PayloadBase::Transport,
            offset: 2,
            len: 2,
        });
        self.exprs.push(Expr::Cmp {
            sreg: Register::R0,
            op: CmpOp::Eq,
            data: port.to_be_bytes().to_vec(),
        });
        self
    }

    /// Match source IPv4 address with prefix length.
    pub fn match_saddr_v4(mut self, addr: Ipv4Addr, prefix: u8) -> Self {
        use super::expr::Expr;
        // Load source IP (offset 12 in IPv4 header)
        self.exprs.push(Expr::Payload {
            dreg: Register::R0,
            base: PayloadBase::Network,
            offset: 12,
            len: 4,
        });
        if prefix == 32 {
            self.exprs.push(Expr::Cmp {
                sreg: Register::R0,
                op: CmpOp::Eq,
                data: addr.octets().to_vec(),
            });
        } else {
            let mask = prefix_to_mask_v4(prefix);
            self.exprs.push(Expr::Bitwise {
                sreg: Register::R0,
                dreg: Register::R0,
                len: 4,
                mask: mask.to_vec(),
                xor: vec![0; 4],
            });
            let masked_addr: Vec<u8> = addr
                .octets()
                .iter()
                .zip(mask.iter())
                .map(|(a, m)| a & m)
                .collect();
            self.exprs.push(Expr::Cmp {
                sreg: Register::R0,
                op: CmpOp::Eq,
                data: masked_addr,
            });
        }
        self
    }

    /// Match destination IPv4 address with prefix length.
    pub fn match_daddr_v4(mut self, addr: Ipv4Addr, prefix: u8) -> Self {
        use super::expr::Expr;
        // Load destination IP (offset 16 in IPv4 header)
        self.exprs.push(Expr::Payload {
            dreg: Register::R0,
            base: PayloadBase::Network,
            offset: 16,
            len: 4,
        });
        if prefix == 32 {
            self.exprs.push(Expr::Cmp {
                sreg: Register::R0,
                op: CmpOp::Eq,
                data: addr.octets().to_vec(),
            });
        } else {
            let mask = prefix_to_mask_v4(prefix);
            self.exprs.push(Expr::Bitwise {
                sreg: Register::R0,
                dreg: Register::R0,
                len: 4,
                mask: mask.to_vec(),
                xor: vec![0; 4],
            });
            let masked_addr: Vec<u8> = addr
                .octets()
                .iter()
                .zip(mask.iter())
                .map(|(a, m)| a & m)
                .collect();
            self.exprs.push(Expr::Cmp {
                sreg: Register::R0,
                op: CmpOp::Eq,
                data: masked_addr,
            });
        }
        self
    }

    /// Match input interface by name.
    pub fn match_iif(mut self, name: &str) -> Self {
        use super::expr::Expr;
        self.exprs.push(Expr::Meta {
            dreg: Register::R0,
            key: MetaKey::IifName,
        });
        let mut data = name.as_bytes().to_vec();
        data.push(0); // null-terminate
        // Pad to 16 bytes (IFNAMSIZ)
        data.resize(16, 0);
        self.exprs.push(Expr::Cmp {
            sreg: Register::R0,
            op: CmpOp::Eq,
            data,
        });
        self
    }

    /// Match output interface by name.
    pub fn match_oif(mut self, name: &str) -> Self {
        use super::expr::Expr;
        self.exprs.push(Expr::Meta {
            dreg: Register::R0,
            key: MetaKey::OifName,
        });
        let mut data = name.as_bytes().to_vec();
        data.push(0);
        data.resize(16, 0);
        self.exprs.push(Expr::Cmp {
            sreg: Register::R0,
            op: CmpOp::Eq,
            data,
        });
        self
    }

    /// Match connection tracking state.
    pub fn match_ct_state(mut self, state: CtState) -> Self {
        use super::expr::Expr;
        self.exprs.push(Expr::Ct {
            dreg: Register::R0,
            key: CtKey::State,
        });
        // Bitwise AND with state mask
        self.exprs.push(Expr::Bitwise {
            sreg: Register::R0,
            dreg: Register::R0,
            len: 4,
            mask: state.bits().to_ne_bytes().to_vec(),
            xor: vec![0; 4],
        });
        // Compare != 0
        self.exprs.push(Expr::Cmp {
            sreg: Register::R0,
            op: CmpOp::Neq,
            data: vec![0; 4],
        });
        self
    }

    /// Accept the packet.
    pub fn accept(mut self) -> Self {
        self.exprs
            .push(super::expr::Expr::Verdict(Verdict::Accept));
        self
    }

    /// Drop the packet.
    pub fn drop(mut self) -> Self {
        self.exprs.push(super::expr::Expr::Verdict(Verdict::Drop));
        self
    }

    /// Jump to another chain.
    pub fn jump(mut self, chain: &str) -> Self {
        self.exprs
            .push(super::expr::Expr::Verdict(Verdict::Jump(
                chain.to_string(),
            )));
        self
    }

    /// Goto another chain (no return).
    pub fn goto(mut self, chain: &str) -> Self {
        self.exprs
            .push(super::expr::Expr::Verdict(Verdict::Goto(
                chain.to_string(),
            )));
        self
    }

    /// Add a packet/byte counter.
    pub fn counter(mut self) -> Self {
        self.exprs.push(super::expr::Expr::Counter);
        self
    }

    /// Rate limit.
    pub fn limit(mut self, rate: u64, unit: LimitUnit) -> Self {
        self.exprs.push(super::expr::Expr::Limit {
            rate,
            unit,
            burst: 5,
        });
        self
    }

    /// Masquerade (source NAT using outgoing interface address).
    pub fn masquerade(mut self) -> Self {
        self.exprs.push(super::expr::Expr::Masquerade);
        self
    }

    /// Source NAT to an address (and optional port).
    pub fn snat(mut self, addr: Ipv4Addr, port: Option<u16>) -> Self {
        use super::expr::Expr;
        // Load address into R0
        self.exprs.push(Expr::Immediate {
            dreg: Register::R0,
            data: addr.octets().to_vec(),
        });
        // Load port into R1 if specified
        if let Some(p) = port {
            self.exprs.push(Expr::Immediate {
                dreg: Register::R1,
                data: p.to_be_bytes().to_vec(),
            });
        }
        self.exprs.push(Expr::Nat(NatExpr {
            nat_type: NatType::Snat,
            family: self.family,
            addr: Some(addr),
            port,
        }));
        self
    }

    /// Destination NAT to an address (and optional port).
    pub fn dnat(mut self, addr: Ipv4Addr, port: Option<u16>) -> Self {
        use super::expr::Expr;
        // Load address into R0
        self.exprs.push(Expr::Immediate {
            dreg: Register::R0,
            data: addr.octets().to_vec(),
        });
        // Load port into R1 if specified
        if let Some(p) = port {
            self.exprs.push(Expr::Immediate {
                dreg: Register::R1,
                data: p.to_be_bytes().to_vec(),
            });
        }
        self.exprs.push(Expr::Nat(NatExpr {
            nat_type: NatType::Dnat,
            family: self.family,
            addr: Some(addr),
            port,
        }));
        self
    }

    /// Redirect to a local port (DNAT to localhost).
    pub fn redirect(mut self, port: Option<u16>) -> Self {
        use super::expr::Expr;
        if let Some(p) = port {
            self.exprs.push(Expr::Immediate {
                dreg: Register::R0,
                data: p.to_be_bytes().to_vec(),
            });
        }
        self.exprs.push(Expr::Redirect { port });
        self
    }

    /// Log packet with optional prefix.
    pub fn log(mut self, prefix: Option<&str>) -> Self {
        self.exprs.push(super::expr::Expr::Log {
            prefix: prefix.map(String::from),
            group: None,
        });
        self
    }

    /// Match source IPv4 address against a named set.
    pub fn match_saddr_in_set(mut self, set: &str) -> Self {
        use super::expr::Expr;
        // Load source IP from network header offset 12
        self.exprs.push(Expr::Payload {
            dreg: Register::R0,
            base: PayloadBase::Network,
            offset: 12,
            len: 4,
        });
        self.exprs.push(Expr::Lookup {
            set: set.to_string(),
            sreg: Register::R0,
        });
        self
    }

    /// Match destination IPv4 address against a named set.
    pub fn match_daddr_in_set(mut self, set: &str) -> Self {
        use super::expr::Expr;
        // Load destination IP from network header offset 16
        self.exprs.push(Expr::Payload {
            dreg: Register::R0,
            base: PayloadBase::Network,
            offset: 16,
            len: 4,
        });
        self.exprs.push(Expr::Lookup {
            set: set.to_string(),
            sreg: Register::R0,
        });
        self
    }

    /// Use raw expressions (advanced).
    pub fn expressions(mut self, exprs: Vec<super::expr::Expr>) -> Self {
        self.exprs = exprs;
        self
    }
}

/// Rule info parsed from a dump.
#[derive(Debug, Clone)]
pub struct RuleInfo {
    /// Table name.
    pub table: String,
    /// Chain name.
    pub chain: String,
    /// Address family.
    pub family: Family,
    /// Kernel handle.
    pub handle: u64,
    /// Position in chain.
    pub position: Option<u64>,
}

// =============================================================================
// Set types
// =============================================================================

/// Key type for nftables sets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetKeyType {
    /// IPv4 address (4 bytes).
    Ipv4Addr,
    /// IPv6 address (16 bytes).
    Ipv6Addr,
    /// Ethernet address (6 bytes, padded to 8).
    EtherAddr,
    /// Port number (2 bytes).
    InetService,
    /// Interface index (4 bytes).
    IfIndex,
    /// Mark value (4 bytes).
    Mark,
}

impl SetKeyType {
    /// Kernel type ID (from nf_tables.h NFT_DATA_*).
    pub fn type_id(self) -> u32 {
        match self {
            Self::Ipv4Addr => 7,    // ipv4_addr
            Self::Ipv6Addr => 8,    // ipv6_addr
            Self::EtherAddr => 9,   // ether_addr
            Self::InetService => 13, // inet_service
            Self::IfIndex => 15,    // ifindex (meta)
            Self::Mark => 12,       // mark
        }
    }

    /// Key length in bytes.
    pub fn len(self) -> u32 {
        match self {
            Self::Ipv4Addr => 4,
            Self::Ipv6Addr => 16,
            Self::EtherAddr => 8, // padded to 8
            Self::InetService => 2,
            Self::IfIndex => 4,
            Self::Mark => 4,
        }
    }
}

/// Set builder.
#[derive(Debug, Clone)]
pub struct Set {
    pub(crate) table: String,
    pub(crate) name: String,
    pub(crate) family: Family,
    pub(crate) key_type: SetKeyType,
    pub(crate) flags: u32,
}

impl Set {
    /// Create a new named set.
    pub fn new(table: &str, name: &str) -> Self {
        Self {
            table: table.to_string(),
            name: name.to_string(),
            family: Family::Inet,
            key_type: SetKeyType::Ipv4Addr,
            flags: 0,
        }
    }

    /// Set the address family.
    pub fn family(mut self, family: Family) -> Self {
        self.family = family;
        self
    }

    /// Set the key type.
    pub fn key_type(mut self, key_type: SetKeyType) -> Self {
        self.key_type = key_type;
        self
    }

    /// Mark as constant (immutable after creation).
    pub fn constant(mut self) -> Self {
        self.flags |= super::NFT_SET_CONSTANT;
        self
    }
}

/// A set element (key + optional data).
#[derive(Debug, Clone)]
pub struct SetElement {
    /// Element key data.
    pub key: Vec<u8>,
}

impl SetElement {
    /// Create from raw bytes.
    pub fn new(key: Vec<u8>) -> Self {
        Self { key }
    }

    /// Create an IPv4 address element.
    pub fn ipv4(addr: Ipv4Addr) -> Self {
        Self {
            key: addr.octets().to_vec(),
        }
    }

    /// Create an IPv6 address element.
    pub fn ipv6(addr: std::net::Ipv6Addr) -> Self {
        Self {
            key: addr.octets().to_vec(),
        }
    }

    /// Create a port number element.
    pub fn port(port: u16) -> Self {
        Self {
            key: port.to_be_bytes().to_vec(),
        }
    }
}

/// Set info parsed from a dump.
#[derive(Debug, Clone)]
pub struct SetInfo {
    /// Table name.
    pub table: String,
    /// Set name.
    pub name: String,
    /// Address family.
    pub family: Family,
    /// Flags.
    pub flags: u32,
    /// Key type ID.
    pub key_type: u32,
    /// Key length.
    pub key_len: u32,
    /// Kernel handle.
    pub handle: u64,
}

/// Convert a prefix length to a network mask (4 bytes).
fn prefix_to_mask_v4(prefix: u8) -> [u8; 4] {
    if prefix == 0 {
        return [0; 4];
    }
    let mask = !0u32 << (32 - prefix.min(32));
    mask.to_be_bytes()
}
