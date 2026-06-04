//! nftables data types: Family, Hook, Chain, Rule, Table, etc.

use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};

use super::expr::Expr;
use crate::netlink::error::{Error, Result};

/// nftables address family.
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
#[non_exhaustive]
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
///
/// **Plan 211 M1 (0.19) breaking change**: `Ingress` was split into
/// `NetdevIngress` and `InetIngress` because the kernel hook
/// numbers differ by family. Pre-0.19 the singular `Ingress`
/// always encoded `0`, which was correct only for
/// `Family::Netdev` / `Family::Bridge` (`NF_NETDEV_INGRESS = 0`).
/// On `Family::Inet`/`Ipv4`/`Ipv6`, ingress is
/// `NF_INET_INGRESS = 5`, so the old encoding installed the
/// chain on `Prerouting` instead — silent wrong-hook attachment.
///
/// `NetdevEgress` is also new (`NF_NETDEV_EGRESS = 1`).
///
/// Migration: callers must pick the variant matching the chain's
/// family. Use [`Hook::is_valid_for_family`] to validate at
/// build time.
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Hook {
    Prerouting,
    Input,
    Forward,
    Output,
    Postrouting,
    /// Ingress hook for `Family::Netdev` / `Family::Bridge`.
    /// Encodes `NF_NETDEV_INGRESS = 0`.
    NetdevIngress,
    /// Ingress hook for `Family::Inet` / `Family::Ipv4` /
    /// `Family::Ipv6`. Encodes `NF_INET_INGRESS = 5`. Available
    /// since kernel 5.10.
    InetIngress,
    /// Egress hook for `Family::Netdev`. Encodes
    /// `NF_NETDEV_EGRESS = 1`. Available since kernel 5.16.
    NetdevEgress,
}

impl Hook {
    /// Returns the kernel hook number. Verified against
    /// `include/uapi/linux/netfilter.h` (`enum nf_inet_hooks`) and
    /// `include/uapi/linux/netfilter_netdev.h`
    /// (`enum nf_dev_hooks`).
    pub fn to_u32(self) -> u32 {
        match self {
            Self::Prerouting => 0,    // NF_INET_PRE_ROUTING
            Self::Input => 1,         // NF_INET_LOCAL_IN
            Self::Forward => 2,       // NF_INET_FORWARD
            Self::Output => 3,        // NF_INET_LOCAL_OUT
            Self::Postrouting => 4,   // NF_INET_POST_ROUTING
            Self::InetIngress => 5,   // NF_INET_INGRESS
            Self::NetdevIngress => 0, // NF_NETDEV_INGRESS
            Self::NetdevEgress => 1,  // NF_NETDEV_EGRESS
        }
    }

    /// Returns `true` if this hook is valid for the given family.
    /// Useful for validating chain definitions at build time before
    /// the kernel rejects them with EINVAL.
    pub fn is_valid_for_family(self, family: Family) -> bool {
        match (self, family) {
            // Netdev hooks need Netdev family.
            (Self::NetdevIngress | Self::NetdevEgress, Family::Netdev) => true,
            // NetdevIngress is also valid on Bridge family.
            (Self::NetdevIngress, Family::Bridge) => true,
            // InetIngress needs an Inet/Ipv4/Ipv6 family.
            (Self::InetIngress, Family::Inet | Family::Ip | Family::Ip6) => true,
            // Standard L3 hooks valid on Inet/Ip/Ip6/Bridge/Arp.
            (
                Self::Prerouting
                | Self::Input
                | Self::Forward
                | Self::Output
                | Self::Postrouting,
                Family::Inet | Family::Ip | Family::Ip6 | Family::Bridge | Family::Arp,
            ) => true,
            _ => false,
        }
    }
}

/// Chain type string for the kernel.
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
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

    /// Parse a kernel-side chain-type string (`"filter"`, `"nat"`,
    /// `"route"`) into the typed enum. Returns `None` for any
    /// other string — the kernel can grow new chain types
    /// (`"netdev"` etc.), and an unrecognised value should not
    /// silently collapse to one of the known variants.
    pub fn from_kernel_string(s: &str) -> Option<Self> {
        match s {
            "filter" => Some(Self::Filter),
            "nat" => Some(Self::Nat),
            "route" => Some(Self::Route),
            _ => None,
        }
    }
}

/// Chain priority (determines ordering).
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
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
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
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

/// A validated nftables chain name.
///
/// Chain identity in nftables is a `(family, table_name, chain_name)`
/// triple, all case-sensitive. The kernel enforces
/// `NFT_NAME_MAXLEN = 256` (per
/// `include/uapi/linux/netfilter/nf_tables.h`) and rejects interior
/// NULs (the attribute is a NUL-terminated C string at the wire layer).
///
/// Construction validates:
/// - Non-empty.
/// - No interior NUL bytes (`\0`).
/// - At most 255 bytes (one byte reserved for the NUL terminator).
///
/// Round-trip note: `ChainName` is `Display` for natural use in
/// log messages and `AsRef<str>` so it slots into existing
/// `&str`-shaped APIs.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ChainName(String);

impl ChainName {
    /// Maximum chain-name length on the wire, in bytes.
    /// Matches kernel `NFT_NAME_MAXLEN - 1` (the kernel slot is
    /// 256 bytes including the trailing NUL).
    pub const MAX_LEN: usize = 255;

    /// Construct a chain name, validating against the kernel contract.
    pub fn new(s: impl Into<String>) -> Result<Self> {
        let s = s.into();
        if s.is_empty() {
            return Err(Error::InvalidMessage(
                "ChainName: empty chain names are rejected by nftables".into(),
            ));
        }
        if s.len() > Self::MAX_LEN {
            return Err(Error::InvalidMessage(format!(
                "ChainName: {} bytes exceeds NFT_NAME_MAXLEN-1 ({} bytes)",
                s.len(),
                Self::MAX_LEN,
            )));
        }
        if s.contains('\0') {
            return Err(Error::InvalidMessage(
                "ChainName: interior NUL bytes are rejected — nftables wire format is a \
                 NUL-terminated C string"
                    .into(),
            ));
        }
        Ok(Self(s))
    }

    /// View as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for ChainName {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ChainName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl TryFrom<&str> for ChainName {
    type Error = Error;
    fn try_from(s: &str) -> Result<Self> {
        Self::new(s)
    }
}

impl TryFrom<String> for ChainName {
    type Error = Error;
    fn try_from(s: String) -> Result<Self> {
        Self::new(s)
    }
}

/// Rule verdict.
///
/// `#[non_exhaustive]` so new variants can be added additively.
/// The 0.20.1 cycle deprecates [`Verdict::Jump`] and [`Verdict::Goto`]
/// in favour of [`Verdict::JumpTo`] / [`Verdict::GotoTo`], which carry
/// a validated [`ChainName`] instead of a bare `String`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Verdict {
    Accept,
    Drop,
    Continue,
    Return,
    /// Jump to a named chain (push-and-continue).
    ///
    /// **Deprecated** in 0.20.1: use [`Verdict::JumpTo`] with
    /// [`ChainName::new`]. The bare-`String` form lets interior NULs
    /// and overlong names through to a kernel rejection at apply time;
    /// the typed sibling surfaces those at construction.
    #[deprecated(
        since = "0.20.1",
        note = "use Verdict::JumpTo(ChainName::new(...)?) — validates the chain name \
                and rejects interior NULs"
    )]
    Jump(String),
    /// Goto a named chain (tail-call).
    ///
    /// **Deprecated** in 0.20.1: use [`Verdict::GotoTo`] with
    /// [`ChainName::new`].
    #[deprecated(
        since = "0.20.1",
        note = "use Verdict::GotoTo(ChainName::new(...)?) — validates the chain name \
                and rejects interior NULs"
    )]
    Goto(String),
    /// Jump to a named chain (push-and-continue). Validated against
    /// the kernel chain-name contract at construction.
    JumpTo(ChainName),
    /// Goto a named chain (tail-call). Validated against the kernel
    /// chain-name contract at construction.
    GotoTo(ChainName),
}

#[cfg(test)]
mod chainname_tests {
    use super::*;

    #[test]
    fn chainname_accepts_short_ascii() {
        assert!(ChainName::new("foo").is_ok());
    }

    #[test]
    fn chainname_rejects_empty() {
        assert!(ChainName::new("").is_err());
    }

    #[test]
    fn chainname_rejects_interior_nul() {
        assert!(ChainName::new("foo\0bar").is_err());
    }

    #[test]
    fn chainname_rejects_overlong() {
        let s = "a".repeat(256); // 256 bytes > 255 max
        assert!(ChainName::new(s).is_err());
    }

    #[test]
    fn chainname_accepts_at_max_len() {
        let s = "a".repeat(ChainName::MAX_LEN);
        assert!(ChainName::new(s).is_ok());
    }

    #[test]
    fn chainname_display_matches_str() {
        let c = ChainName::new("filter_input").unwrap();
        assert_eq!(c.to_string(), "filter_input");
        assert_eq!(c.as_str(), "filter_input");
        let s: &str = c.as_ref();
        assert_eq!(s, "filter_input");
    }

    #[test]
    fn chainname_tryfrom_str() {
        let c: ChainName = "input".try_into().unwrap();
        assert_eq!(c.as_str(), "input");
        let r: Result<ChainName> = "".try_into();
        assert!(r.is_err());
    }
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
#[non_exhaustive]
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

/// nftables register, encoding the kernel UAPI register IDs from
/// `include/uapi/linux/netfilter/nf_tables.h`.
///
/// The discriminants are the wire-format values; `as u32` produces
/// the bytes the kernel stores and dumps. `#[repr(u32)]` locks the
/// memory layout so the cast is well-defined and the size doesn't
/// shift if the compiler changes its discriminant-sizing heuristics.
///
/// `R0..=R3` map to `NFT_REG_1..=NFT_REG_4` (16-byte registers).
/// Earlier nlink used `NFT_REG32_00..=NFT_REG32_03` (`8..=11`,
/// 4-byte registers); the kernel canonicalizes a 4-byte transfer
/// through either form to the 16-byte register's first 4 bytes,
/// so the stored/dumped register ID is always the `NFT_REG_x`
/// form. Submitting in the canonical form keeps
/// `NftablesConfig::diff` from flagging unchanged rules as
/// `to_replace` purely on register-ID divergence. Plan 178.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
#[non_exhaustive]
pub enum Register {
    /// `NFT_REG_VERDICT`. The dedicated verdict register.
    Verdict = 0,
    /// `NFT_REG_1`. First 16-byte data register.
    R0 = 1,
    /// `NFT_REG_2`. Second 16-byte data register.
    R1 = 2,
    /// `NFT_REG_3`. Third 16-byte data register.
    R2 = 3,
    /// `NFT_REG_4`. Fourth 16-byte data register.
    R3 = 4,
}

/// `meta nfproto` L3-protocol values, used as the guard prepended to
/// the address matchers (see [`Rule::match_saddr_v4`] / `_v6`).
pub(crate) const NFPROTO_IPV4: u8 = 2;
pub(crate) const NFPROTO_IPV6: u8 = 10;

/// `meta l4proto` values, used as the guard prepended by the
/// transport-layer matchers.
const IPPROTO_ICMP: u8 = 1;
const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;
const IPPROTO_ICMPV6: u8 = 58;

/// Comparison operator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
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
#[non_exhaustive]
pub enum PayloadBase {
    LinkLayer = 0,
    Network = 1,
    Transport = 2,
}

/// Meta key for loading metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
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
/// Conntrack key — matches `enum nft_ct_keys` in the kernel UAPI
/// (`include/uapi/linux/netfilter/nf_tables.h`).
///
/// Plan 221: `Expiration` was hardcoded to `7`, which is
/// `NFT_CT_L3PROTOCOL`. Every rule using `Expr::Ct { key:
/// CtKey::Expiration }` was reading the conntrack L3 protocol byte
/// instead of the expiration time in milliseconds — silent
/// type+value mismatch. Corrected to `5`, and the variants `Secmark`,
/// `Helper`, `L3Protocol` were added so the previously-shadowed
/// kernel values are reachable through the typed enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CtKey {
    State = 0,
    Direction = 1,
    Status = 2,
    Mark = 3,
    Secmark = 4,
    Expiration = 5,
    Helper = 6,
    L3Protocol = 7,
}

/// NAT type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum NatType {
    Snat = 0,
    Dnat = 1,
}

/// Whether (and how) a NAT expression's address register (`R0`) is in use.
///
/// The encoder emits `NFTA_NAT_REG_ADDR_MIN` for every variant except
/// [`None`](Self::None). Modeling "register in use" and "the IPv4 address to
/// record" as one enum makes the illegal `(addr recorded, register not in
/// use)` state unrepresentable — a v6 NAT loads its 16-byte address into `R0`
/// but has no `Ipv4Addr` to carry, which [`Reg`](Self::Reg) expresses directly.
///
/// Invariant: any variant other than `None` means an [`Expr::Immediate`]
/// loading the address into `R0` **must** precede this expr in the rule.
/// Constructing this without the matching load makes the encoder reference an
/// empty register (`EINVAL` from the kernel). The `Rule::{snat,dnat,snat_v6,
/// dnat_v6}` builders maintain this for you.
///
/// [`Expr::Immediate`]: super::expr::Expr::Immediate
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum NatAddr {
    /// No address register; the NAT expr rewrites only the port (or nothing).
    #[default]
    None,
    /// An IPv4 address loaded into `R0`. Recorded for a future dump/decode
    /// path; no decoder currently reads it back.
    V4(Ipv4Addr),
    /// An address (e.g. IPv6) loaded into `R0` with no `Ipv4Addr` to record.
    Reg,
}

impl NatAddr {
    /// Whether `R0` holds an address — i.e. the encoder must emit
    /// `NFTA_NAT_REG_ADDR_MIN`.
    pub fn reg_in_use(&self) -> bool {
        !matches!(self, NatAddr::None)
    }
}

/// NAT expression data.
#[derive(Debug, Clone)]
pub struct NatExpr {
    pub nat_type: NatType,
    pub family: Family,
    /// The NAT destination address register state. See [`NatAddr`].
    pub addr: NatAddr,
    /// Port to NAT to.
    pub port: Option<u16>,
}

impl NatExpr {
    /// Create a SNAT expression.
    ///
    /// `family` must be [`Family::Ip`] or [`Family::Ip6`] — the kernel rejects
    /// `Family::Inet` with `EAFNOSUPPORT`. Use the concrete family matching
    /// the address type being NAT'd.
    pub fn snat(family: Family) -> Self {
        Self {
            nat_type: NatType::Snat,
            family,
            addr: NatAddr::None,
            port: None,
        }
    }

    /// Create a DNAT expression.
    ///
    /// `family` must be [`Family::Ip`] or [`Family::Ip6`] — the kernel rejects
    /// `Family::Inet` with `EAFNOSUPPORT`. Use the concrete family matching
    /// the address type being NAT'd.
    pub fn dnat(family: Family) -> Self {
        Self {
            nat_type: NatType::Dnat,
            family,
            addr: NatAddr::None,
            port: None,
        }
    }

    /// Set the NAT destination address.
    pub fn addr(mut self, addr: Ipv4Addr) -> Self {
        self.addr = NatAddr::V4(addr);
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

/// An nftables flowtable.
///
/// Per-table object that caches established conntrack flows, letting
/// the kernel bypass the full nftables rule traversal for matching
/// packets. On capable NICs the flow path can be hardware-offloaded
/// via `NFT_FLOWTABLE_HW_OFFLOAD`.
///
/// Construct via [`Self::new`] + fluent setters; install via
/// `Connection::<Nftables>::add_flowtable`. List via `get_flowtables`.
///
/// # Example
///
/// ```ignore
/// use nlink::netlink::nftables::{Flowtable, Family};
///
/// let ft = Flowtable::new(Family::Inet, "filter", "ft")
///     .device("eth0")
///     .device("eth1")
///     .priority(0)
///     .hw_offload(true);
/// conn.add_flowtable(&ft).await?;
/// ```
#[derive(Debug, Clone)]
pub struct Flowtable {
    /// Owning table family (typically `Inet`, `Ip`, `Ip6`).
    pub family: Family,
    /// Owning table name.
    pub table: String,
    /// Flowtable name (unique within the table).
    pub name: String,
    /// Device names to attach the ingress hook to. Empty = no
    /// devices (the kernel accepts the add but the flowtable does
    /// nothing until devices are added in a follow-up update).
    pub devs: Vec<String>,
    /// Hook priority. Default 0; `-300` for early ingress.
    pub priority: i32,
    /// Flags bitmap. Combine `NFT_FLOWTABLE_HW_OFFLOAD` and
    /// `NFT_FLOWTABLE_COUNTER` from
    /// [`crate::netlink::nftables`].
    pub flags: u32,
    /// Use-count reported by the kernel (read-only; populated by
    /// `get_flowtables` parse, ignored on add).
    pub use_count: u32,
    /// Kernel-assigned handle (read-only; same as `use_count`).
    pub handle: u64,
}

impl Flowtable {
    /// New builder for a flowtable in the named table.
    pub fn new(
        family: Family,
        table: impl Into<String>,
        name: impl Into<String>,
    ) -> Self {
        Self {
            family,
            table: table.into(),
            name: name.into(),
            devs: Vec::new(),
            priority: 0,
            flags: 0,
            use_count: 0,
            handle: 0,
        }
    }

    /// Attach the flowtable's ingress hook to a device. Call
    /// multiple times to attach to several devices (e.g. both ends
    /// of a bridge).
    pub fn device(mut self, dev: impl Into<String>) -> Self {
        self.devs.push(dev.into());
        self
    }

    /// Set the ingress hook priority. Default is 0.
    pub fn priority(mut self, p: i32) -> Self {
        self.priority = p;
        self
    }

    /// Request hardware offload (`NFT_FLOWTABLE_HW_OFFLOAD`).
    ///
    /// Requires a NIC with flow-table offload support (mlx5, hns3,
    /// etc.) and a kernel built with `CONFIG_NF_FLOW_TABLE_HW`.
    /// If the NIC doesn't support offload the kernel accepts the
    /// add and silently falls back to software — there's no in-band
    /// signal. Check `ethtool -k <dev> | grep hw-tc-offload` or
    /// inspect per-flow counters to confirm offload engaged.
    pub fn hw_offload(mut self, on: bool) -> Self {
        if on {
            self.flags |= super::NFT_FLOWTABLE_HW_OFFLOAD;
        } else {
            self.flags &= !super::NFT_FLOWTABLE_HW_OFFLOAD;
        }
        self
    }

    /// Request per-flow counter tracking
    /// (`NFT_FLOWTABLE_COUNTER`). Adds overhead.
    pub fn counter(mut self, on: bool) -> Self {
        if on {
            self.flags |= super::NFT_FLOWTABLE_COUNTER;
        } else {
            self.flags &= !super::NFT_FLOWTABLE_COUNTER;
        }
        self
    }
}

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
#[must_use = "builders do nothing unless used"]
pub struct Chain {
    pub(crate) table: String,
    pub(crate) name: String,
    pub(crate) family: Family,
    pub(crate) hook: Option<Hook>,
    pub(crate) priority: Option<Priority>,
    pub(crate) chain_type: Option<ChainType>,
    pub(crate) policy: Option<Policy>,
    pub(crate) device: Option<String>,
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
            device: None,
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

    /// Bind a `Family::Netdev` base chain to a specific
    /// interface (`type filter hook ingress device eth0
    /// priority -150`). **Required** for netdev hooks
    /// (`Hook::Ingress`/`Egress` with `Family::Netdev`) —
    /// without this the kernel rejects the chain. Ignored on
    /// non-netdev families.
    pub fn device(mut self, dev: impl Into<String>) -> Self {
        self.device = Some(dev.into());
        self
    }
}

/// Chain info parsed from a dump.
#[derive(Debug, Clone)]
#[non_exhaustive]
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
    /// Chain type, parsed from the kernel's `NFTA_CHAIN_TYPE`
    /// string. `None` if the chain is regular (no hook) or the
    /// kernel emitted an unrecognised value — Plan 180 picked
    /// the typed form deliberately so callers can pattern-match
    /// without holding a stringly table.
    pub chain_type: Option<ChainType>,
    /// Bound device name for netdev base chains. `None` on
    /// other families or when the chain wasn't dump-included
    /// by the kernel (older kernels omit it for non-netdev).
    pub device: Option<String>,
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
#[must_use = "builders do nothing unless used"]
pub struct Rule {
    pub(crate) table: String,
    pub(crate) chain: String,
    pub(crate) family: Family,
    pub(crate) exprs: Vec<super::expr::Expr>,
    pub(crate) position: Option<u64>,
    pub(crate) comment: Option<String>,
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
            comment: None,
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

    /// Attach a comment to this rule. Encoded as
    /// `NFTA_RULE_USERDATA` (libnftnl-compatible TLV); shows up
    /// in `nft list ruleset` output as inline `comment "..."`.
    ///
    /// The declarative-config diff layer uses comments matching
    /// `nlink:<key>` as the rule's reconciliation identity (Plan
    /// 157b v2 — analogous to `LinkConfig::name`). Max 122 chars
    /// for the user-supplied portion (128-byte libnftnl
    /// `NFTNL_UDATA_COMMENT_MAXLEN` minus the `nlink:` prefix +
    /// trailing NUL).
    pub fn comment(mut self, comment: &str) -> Self {
        self.comment = Some(comment.to_string());
        self
    }

    /// Borrow the rule's comment, if any.
    pub fn comment_ref(&self) -> Option<&str> {
        self.comment.as_deref()
    }

    /// Match TCP destination port.
    ///
    /// Generates: meta(L4PROTO) + cmp(==TCP) + payload(dport) + cmp(==port)
    pub fn match_tcp_dport(mut self, port: u16) -> Self {
        use super::expr::Expr;
        self.push_meta_eq(MetaKey::L4Proto, IPPROTO_TCP);
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
        self.push_meta_eq(MetaKey::L4Proto, IPPROTO_UDP);
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

    /// Emit `Payload(Network) [+ Bitwise mask] + Cmp(op)` for an
    /// address match. Used by the v4/v6 `match_{s,d}addr*` helpers.
    /// When `prefix >= full_prefix` the bitwise mask is skipped
    /// (exact-match fast path); otherwise a network mask is applied
    /// to the loaded bytes and compared against the masked address.
    fn push_addr_match(
        &mut self,
        octets: &[u8],
        offset: u32,
        prefix: u8,
        full_prefix: u8,
        op: CmpOp,
    ) {
        let len = octets.len() as u32;
        self.exprs.push(Expr::Payload {
            dreg: Register::R0,
            base: PayloadBase::Network,
            offset,
            len,
        });
        if prefix >= full_prefix {
            self.exprs.push(Expr::Cmp {
                sreg: Register::R0,
                op,
                data: octets.to_vec(),
            });
            return;
        }
        let mask = prefix_to_mask(octets.len(), prefix);
        let masked: Vec<u8> = octets.iter().zip(&mask).map(|(a, m)| a & m).collect();
        self.exprs.push(Expr::Bitwise {
            sreg: Register::R0,
            dreg: Register::R0,
            len,
            mask,
            xor: vec![0; octets.len()],
        });
        self.exprs.push(Expr::Cmp {
            sreg: Register::R0,
            op,
            data: masked,
        });
    }

    /// Push `meta <key> == <value>` (a 1-byte metadata load + Eq compare
    /// in `R0`) — the shared shape of the nfproto/l4proto matcher guards.
    fn push_meta_eq(&mut self, key: MetaKey, value: u8) {
        self.exprs.push(Expr::Meta {
            dreg: Register::R0,
            key,
        });
        self.exprs.push(Expr::Cmp {
            sreg: Register::R0,
            op: CmpOp::Eq,
            data: vec![value],
        });
    }

    /// Prepend the `meta nfproto == ip{v4,v6}` L3 guard `nft` inserts
    /// before every `ip`/`ip6 saddr/daddr` match. Without it the address
    /// load is ambiguous in an `inet` chain, and the declarative diff
    /// phantom-diffs (the kernel stores the guard; nlink must too).
    fn push_nfproto_ipv6(&mut self) {
        self.push_meta_eq(MetaKey::NfProto, NFPROTO_IPV6);
    }

    fn push_nfproto_ipv4(&mut self) {
        self.push_meta_eq(MetaKey::NfProto, NFPROTO_IPV4);
    }

    /// Match source IPv4 address with prefix length. Operates on the
    /// IP header (`PayloadBase::Network`), so use only on chains that
    /// see IPv4 traffic (`ip`/`inet`/`netdev` family).
    pub fn match_saddr_v4(mut self, addr: Ipv4Addr, prefix: u8) -> Self {
        // Source IP at offset 12 in the IPv4 header.
        self.push_nfproto_ipv4();
        self.push_addr_match(&addr.octets(), 12, prefix, 32, CmpOp::Eq);
        self
    }

    /// Match source IPv6 address with prefix length. Operates on the
    /// IP header, so use only on chains that see IPv6 traffic
    /// (`ip6`/`inet`/`netdev` family).
    pub fn match_saddr_v6(mut self, addr: Ipv6Addr, prefix: u8) -> Self {
        // Source IP at offset 8 in the IPv6 header.
        self.push_nfproto_ipv6();
        self.push_addr_match(&addr.octets(), 8, prefix, 128, CmpOp::Eq);
        self
    }

    /// Match destination IPv4 address with prefix length. Operates on
    /// the IP header, so use only on chains that see IPv4 traffic.
    pub fn match_daddr_v4(mut self, addr: Ipv4Addr, prefix: u8) -> Self {
        // Destination IP at offset 16 in the IPv4 header.
        self.push_nfproto_ipv4();
        self.push_addr_match(&addr.octets(), 16, prefix, 32, CmpOp::Eq);
        self
    }

    /// Match destination IPv6 address with prefix length. Operates on
    /// the IP header, so use only on chains that see IPv6 traffic.
    pub fn match_daddr_v6(mut self, addr: Ipv6Addr, prefix: u8) -> Self {
        // Destination IP at offset 24 in the IPv6 header.
        self.push_nfproto_ipv6();
        self.push_addr_match(&addr.octets(), 24, prefix, 128, CmpOp::Eq);
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
        self.exprs.push(super::expr::Expr::Verdict(Verdict::Accept));
        self
    }

    /// Drop the packet.
    pub fn drop(mut self) -> Self {
        self.exprs.push(super::expr::Expr::Verdict(Verdict::Drop));
        self
    }

    /// Jump to another chain.
    ///
    /// Infallible-by-API; if the name violates the kernel chain-name
    /// contract (interior NUL, empty, or `len > 255`) the kernel will
    /// reject the rule at apply time. For early validation, construct
    /// a [`ChainName`] explicitly and use [`Self::jump_to`].
    pub fn jump(mut self, chain: &str) -> Self {
        // Prefer the typed variant when the contract is satisfied;
        // fall back to the deprecated String form so the infallible
        // public signature is preserved.
        let verdict = match ChainName::new(chain) {
            Ok(name) => Verdict::JumpTo(name),
            #[allow(deprecated)]
            Err(_) => Verdict::Jump(chain.to_string()),
        };
        self.exprs.push(super::expr::Expr::Verdict(verdict));
        self
    }

    /// Jump to another chain, typed.
    ///
    /// The chain name is validated at construction via
    /// [`ChainName::new`] — surfaces interior-NUL / overlong / empty
    /// names at the input boundary instead of as a kernel rejection
    /// at apply time.
    pub fn jump_to(mut self, chain: ChainName) -> Self {
        self.exprs
            .push(super::expr::Expr::Verdict(Verdict::JumpTo(chain)));
        self
    }

    /// Goto another chain (no return).
    ///
    /// Infallible-by-API; if the name violates the kernel chain-name
    /// contract the kernel will reject the rule at apply time. For
    /// early validation, construct a [`ChainName`] explicitly and use
    /// [`Self::goto_to`].
    pub fn goto(mut self, chain: &str) -> Self {
        let verdict = match ChainName::new(chain) {
            Ok(name) => Verdict::GotoTo(name),
            #[allow(deprecated)]
            Err(_) => Verdict::Goto(chain.to_string()),
        };
        self.exprs.push(super::expr::Expr::Verdict(verdict));
        self
    }

    /// Goto another chain (no return), typed.
    pub fn goto_to(mut self, chain: ChainName) -> Self {
        self.exprs
            .push(super::expr::Expr::Verdict(Verdict::GotoTo(chain)));
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

    /// Push a NAT expression preceded by the register loads it references.
    ///
    /// `addr_bytes` is the wire-form destination address (4 bytes for v4, 16
    /// for v6); it is loaded into `R0`. `addr` is the matching [`NatAddr`]
    /// recorded on the expr — any variant other than [`NatAddr::None`] makes
    /// the encoder emit `NFTA_NAT_REG_ADDR_MIN` referencing that load. The
    /// optional port is loaded into `R1`. Keeping the `R0` load and the
    /// `NatAddr` in one place is what upholds the [`NatAddr`] invariant that a
    /// register-in-use variant always has a real `R0` load preceding it.
    fn push_nat(
        &mut self,
        nat_type: NatType,
        family: Family,
        addr_bytes: Vec<u8>,
        addr: NatAddr,
        port: Option<u16>,
    ) {
        use super::expr::Expr;
        debug_assert!(
            addr.reg_in_use(),
            "push_nat always loads R0; addr must be a register-in-use variant"
        );
        self.exprs.push(Expr::Immediate {
            dreg: Register::R0,
            data: addr_bytes,
        });
        if let Some(p) = port {
            self.exprs.push(Expr::Immediate {
                dreg: Register::R1,
                data: p.to_be_bytes().to_vec(),
            });
        }
        self.exprs.push(Expr::Nat(NatExpr {
            nat_type,
            family,
            addr,
            port,
        }));
    }

    /// Source NAT to an address (and optional port).
    pub fn snat(mut self, addr: Ipv4Addr, port: Option<u16>) -> Self {
        self.push_nat(NatType::Snat, Family::Ip, addr.octets().to_vec(), NatAddr::V4(addr), port);
        self
    }

    /// Destination NAT to an address (and optional port).
    pub fn dnat(mut self, addr: Ipv4Addr, port: Option<u16>) -> Self {
        self.push_nat(NatType::Dnat, Family::Ip, addr.octets().to_vec(), NatAddr::V4(addr), port);
        self
    }

    /// Source NAT to an IPv6 address (and optional port).
    ///
    /// Use on an `ip6` (or `inet`) NAT chain. The NAT expr's family must match
    /// the address family, so this emits `Family::Ip6` (not the chain's
    /// `Family::Inet`). The 16-byte address is loaded into `R0`; the optional
    /// port into `R1`.
    pub fn snat_v6(mut self, addr: Ipv6Addr, port: Option<u16>) -> Self {
        self.push_nat(NatType::Snat, Family::Ip6, addr.octets().to_vec(), NatAddr::Reg, port);
        self
    }

    /// Destination NAT to an IPv6 address (and optional port).
    ///
    /// Use on an `ip6` (or `inet`) NAT chain. The NAT expr's family must match
    /// the address family, so this emits `Family::Ip6` (not the chain's
    /// `Family::Inet`). The 16-byte address is loaded into `R0`; the optional
    /// port into `R1`.
    pub fn dnat_v6(mut self, addr: Ipv6Addr, port: Option<u16>) -> Self {
        self.push_nat(NatType::Dnat, Family::Ip6, addr.octets().to_vec(), NatAddr::Reg, port);
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

    /// Match layer-4 protocol (e.g., TCP=6, UDP=17, ICMP=1).
    ///
    /// # Example
    ///
    /// ```ignore
    /// // Match ICMP traffic
    /// rule.match_l4proto(1)
    /// // Match TCP traffic
    /// rule.match_l4proto(6)
    /// ```
    pub fn match_l4proto(mut self, proto: u8) -> Self {
        self.push_meta_eq(MetaKey::L4Proto, proto);
        self
    }

    /// Match TCP source port.
    pub fn match_tcp_sport(mut self, port: u16) -> Self {
        use super::expr::Expr;
        self.push_meta_eq(MetaKey::L4Proto, IPPROTO_TCP);
        self.exprs.push(Expr::Payload {
            dreg: Register::R0,
            base: PayloadBase::Transport,
            offset: 0, // source port is at offset 0
            len: 2,
        });
        self.exprs.push(Expr::Cmp {
            sreg: Register::R0,
            op: CmpOp::Eq,
            data: port.to_be_bytes().to_vec(),
        });
        self
    }

    /// Match UDP source port.
    pub fn match_udp_sport(mut self, port: u16) -> Self {
        use super::expr::Expr;
        self.push_meta_eq(MetaKey::L4Proto, IPPROTO_UDP);
        self.exprs.push(Expr::Payload {
            dreg: Register::R0,
            base: PayloadBase::Transport,
            offset: 0,
            len: 2,
        });
        self.exprs.push(Expr::Cmp {
            sreg: Register::R0,
            op: CmpOp::Eq,
            data: port.to_be_bytes().to_vec(),
        });
        self
    }

    /// Match ICMP type (IPv4).
    ///
    /// Common types: echo-reply=0, echo-request=8, dest-unreachable=3,
    /// time-exceeded=11, redirect=5.
    pub fn match_icmp_type(mut self, icmp_type: u8) -> Self {
        use super::expr::Expr;
        // ICMP is IPv4-only; in an `inet` chain `nft` prepends the
        // `meta nfproto ipv4` guard, same as the v4 address matchers.
        self.push_nfproto_ipv4();
        self.push_meta_eq(MetaKey::L4Proto, IPPROTO_ICMP);
        // Load ICMP type (first byte of transport header)
        self.exprs.push(Expr::Payload {
            dreg: Register::R0,
            base: PayloadBase::Transport,
            offset: 0,
            len: 1,
        });
        self.exprs.push(Expr::Cmp {
            sreg: Register::R0,
            op: CmpOp::Eq,
            data: vec![icmp_type],
        });
        self
    }

    /// Match ICMPv6 type.
    ///
    /// Common types: echo-request=128, echo-reply=129, neighbor-solicitation=135,
    /// neighbor-advertisement=136, router-solicitation=133, router-advertisement=134.
    pub fn match_icmpv6_type(mut self, icmp_type: u8) -> Self {
        use super::expr::Expr;
        // ICMPv6 is IPv6-only; in an `inet` chain `nft` prepends the
        // `meta nfproto ipv6` guard, same as the v6 address matchers.
        self.push_nfproto_ipv6();
        self.push_meta_eq(MetaKey::L4Proto, IPPROTO_ICMPV6);
        self.exprs.push(Expr::Payload {
            dreg: Register::R0,
            base: PayloadBase::Transport,
            offset: 0,
            len: 1,
        });
        self.exprs.push(Expr::Cmp {
            sreg: Register::R0,
            op: CmpOp::Eq,
            data: vec![icmp_type],
        });
        self
    }

    /// Match source IPv4 address not in the given address/prefix.
    /// For prefixes shorter than 32, "not equal" means "outside the
    /// subnet" — the load is masked before comparison.
    pub fn match_saddr_v4_not(mut self, addr: Ipv4Addr, prefix: u8) -> Self {
        self.push_nfproto_ipv4();
        self.push_addr_match(&addr.octets(), 12, prefix, 32, CmpOp::Neq);
        self
    }

    /// Match source IPv6 address not in the given address/prefix.
    /// For prefixes shorter than 128, "not equal" means "outside the
    /// subnet" — the load is masked before comparison.
    pub fn match_saddr_v6_not(mut self, addr: Ipv6Addr, prefix: u8) -> Self {
        self.push_nfproto_ipv6();
        self.push_addr_match(&addr.octets(), 8, prefix, 128, CmpOp::Neq);
        self
    }

    /// Match destination IPv4 address not in the given address/prefix.
    /// For prefixes shorter than 32, "not equal" means "outside the
    /// subnet" — the load is masked before comparison.
    pub fn match_daddr_v4_not(mut self, addr: Ipv4Addr, prefix: u8) -> Self {
        self.push_nfproto_ipv4();
        self.push_addr_match(&addr.octets(), 16, prefix, 32, CmpOp::Neq);
        self
    }

    /// Match destination IPv6 address not in the given address/prefix.
    /// For prefixes shorter than 128, "not equal" means "outside the
    /// subnet" — the load is masked before comparison.
    pub fn match_daddr_v6_not(mut self, addr: Ipv6Addr, prefix: u8) -> Self {
        self.push_nfproto_ipv6();
        self.push_addr_match(&addr.octets(), 24, prefix, 128, CmpOp::Neq);
        self
    }

    /// Match TCP destination port not equal to the given port.
    pub fn match_tcp_dport_not(mut self, port: u16) -> Self {
        use super::expr::Expr;
        self.push_meta_eq(MetaKey::L4Proto, IPPROTO_TCP);
        self.exprs.push(Expr::Payload {
            dreg: Register::R0,
            base: PayloadBase::Transport,
            offset: 2,
            len: 2,
        });
        self.exprs.push(Expr::Cmp {
            sreg: Register::R0,
            op: CmpOp::Neq,
            data: port.to_be_bytes().to_vec(),
        });
        self
    }

    /// Match UDP destination port not equal to the given port.
    pub fn match_udp_dport_not(mut self, port: u16) -> Self {
        use super::expr::Expr;
        self.push_meta_eq(MetaKey::L4Proto, IPPROTO_UDP);
        self.exprs.push(Expr::Payload {
            dreg: Register::R0,
            base: PayloadBase::Transport,
            offset: 2,
            len: 2,
        });
        self.exprs.push(Expr::Cmp {
            sreg: Register::R0,
            op: CmpOp::Neq,
            data: port.to_be_bytes().to_vec(),
        });
        self
    }

    /// Match packet mark (nfmark/fwmark).
    pub fn match_mark(mut self, mark: u32) -> Self {
        use super::expr::Expr;
        self.exprs.push(Expr::Meta {
            dreg: Register::R0,
            key: MetaKey::Mark,
        });
        self.exprs.push(Expr::Cmp {
            sreg: Register::R0,
            op: CmpOp::Eq,
            data: mark.to_ne_bytes().to_vec(),
        });
        self
    }

    /// Reject the packet (send ICMP unreachable / TCP RST).
    pub fn reject(mut self) -> Self {
        self.exprs.push(super::expr::Expr::Verdict(Verdict::Drop));
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
#[non_exhaustive]
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
    /// `nlink:<key>` comment extracted from `NFTA_RULE_USERDATA`,
    /// if any. `Some(key)` when this rule was created by nlink
    /// (and carries an `nlink:`-prefixed comment); `None` when
    /// the rule has no comment or a foreign-prefixed one. Plan
    /// 157b v2 — drives per-rule reconciliation identity.
    pub comment: Option<String>,
    /// Raw `NFTA_RULE_USERDATA` payload, preserved verbatim. Lets
    /// callers round-trip foreign comments (set by `iptables-nft`,
    /// `nft -f` users, or other tools) without dropping them, even
    /// though nlink's diff doesn't manage them.
    pub userdata_raw: Option<Vec<u8>>,
    /// Raw `NFTA_RULE_EXPRESSIONS` payload, preserved for the
    /// body-equivalence check in `NftablesDiff::diff` (Plan 157b
    /// v2). Empty when the rule has no expressions (degenerate).
    pub expression_bytes: Vec<u8>,
}

// =============================================================================
// Set types
// =============================================================================

/// Key type for nftables sets.
///
/// Plan 198 §2.1 added `InetProto` (single u8 protocol — e.g.
/// `tcp`, `udp`, `icmp`) and `Concat(Vec<_>)` (composite key
/// used in rules like `ip saddr . tcp dport`).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
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
    /// IP protocol number — single u8 padded to 4 bytes
    /// (`tcp` = 6, `udp` = 17, `icmp` = 1). Plan 198 §2.1.
    InetProto,
    /// Concatenated key — packs multiple component keys
    /// end-to-end with 4-byte alignment between. Common in
    /// rules like `ip saddr . tcp dport`. Plan 198 §2.1.
    ///
    /// The vector MUST be non-empty (a single-component concat
    /// is degenerate but accepted — the kernel treats it as a
    /// normal key).
    Concat(Vec<SetKeyType>),
}

impl SetKeyType {
    /// Kernel type ID (from nf_tables.h NFT_DATA_*).
    ///
    /// `Concat` builds a per-component type list packed as
    /// `u32`s into a single u64 wire value: shift each
    /// component's `type_id()` by `i * 6` bits and OR. This
    /// matches the kernel's `nft_set_ext_concat` layout
    /// (each type packed into 6-bit slots).
    pub fn type_id(&self) -> u32 {
        match self {
            Self::Ipv4Addr => 7,     // ipv4_addr
            Self::Ipv6Addr => 8,     // ipv6_addr
            Self::EtherAddr => 9,    // ether_addr
            Self::InetService => 13, // inet_service
            Self::IfIndex => 15,     // ifindex (meta)
            Self::Mark => 12,        // mark
            Self::InetProto => 14,   // inet_proto
            Self::Concat(parts) => {
                // Pack each component's 6-bit type-id into
                // sequential slots. Per nf_tables.h
                // CONCAT_TYPE_BITS = 6. Truncates beyond u32
                // (>5 components in the list packs partially
                // — the kernel UAPI documents up to 16
                // components; nlink reports the lower-32-bit
                // window which covers single-stack
                // 4-component concats).
                parts
                    .iter()
                    .enumerate()
                    .fold(0u32, |acc, (i, t)| acc | ((t.type_id() & 0x3F) << (i * 6)))
            }
        }
    }

    /// Key length in bytes (always non-zero for all variants).
    /// For `Concat`, the sum of each component's length
    /// padded to 4-byte alignment.
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> u32 {
        match self {
            Self::Ipv4Addr => 4,
            Self::Ipv6Addr => 16,
            Self::EtherAddr => 8, // padded to 8
            Self::InetService => 2,
            Self::IfIndex => 4,
            Self::Mark => 4,
            Self::InetProto => 1,
            Self::Concat(parts) => {
                // Each component is padded to 4-byte
                // alignment before the next starts (per kernel
                // `nft_set_ext_concat` layout).
                parts.iter().map(|t| (t.len() + 3) & !3).sum()
            }
        }
    }
}

/// Set builder.
#[derive(Debug, Clone)]
#[must_use = "builders do nothing unless used"]
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

/// Convert a prefix length to a network mask of `width` bytes.
/// `prefix` is clamped to `width * 8`.
fn prefix_to_mask(width: usize, prefix: u8) -> Vec<u8> {
    let prefix = (prefix as usize).min(width * 8);
    let full_bytes = prefix / 8;
    let remainder = prefix % 8;
    let mut mask = vec![0u8; width];
    for byte in mask.iter_mut().take(full_bytes) {
        *byte = 0xff;
    }
    if remainder != 0 && full_bytes < width {
        mask[full_bytes] = 0xff << (8 - remainder);
    }
    mask
}

#[cfg(test)]
mod tests {
    use super::*;

    // -------- Plan 198 §2.1 — SetKeyType extensions --------

    #[test]
    fn set_key_type_inet_proto_wire_constants() {
        // NFT_DATA_INET_PROTO = 14, 1 byte. Plan 198 §2.1.
        assert_eq!(SetKeyType::InetProto.type_id(), 14);
        assert_eq!(SetKeyType::InetProto.len(), 1);
    }

    #[test]
    fn set_key_type_concat_len_pads_each_component() {
        // ip saddr (4B) . tcp dport (2B → 4B after pad) = 8B.
        let k = SetKeyType::Concat(vec![
            SetKeyType::Ipv4Addr,
            SetKeyType::InetService,
        ]);
        assert_eq!(k.len(), 8);
    }

    #[test]
    fn set_key_type_concat_packs_six_bit_type_ids() {
        // Plan 198 §2.1 pack contract:
        //   slot 0 = component[0].type_id() & 0x3F
        //   slot 1 = component[1].type_id() << 6
        // Ipv4Addr(7) + InetService(13) → 7 | (13 << 6) = 7 | 832 = 839.
        let k = SetKeyType::Concat(vec![
            SetKeyType::Ipv4Addr,
            SetKeyType::InetService,
        ]);
        assert_eq!(k.type_id(), 7 | (13 << 6));
    }

    #[test]
    fn set_key_type_concat_single_component_degenerate() {
        // One-component concat reports the wrapped type's
        // own type_id (no second slot). Kernel treats this as
        // a normal key.
        let k = SetKeyType::Concat(vec![SetKeyType::Ipv4Addr]);
        assert_eq!(k.type_id(), 7);
        assert_eq!(k.len(), 4);
    }

    #[test]
    fn set_key_type_concat_three_components_padding_round_trip() {
        // ether_addr (8B padded) . ip saddr (4B) . inet_service (4B padded) = 16B.
        let k = SetKeyType::Concat(vec![
            SetKeyType::EtherAddr,
            SetKeyType::Ipv4Addr,
            SetKeyType::InetService,
        ]);
        assert_eq!(k.len(), 16);
        // type_id slot composition: EtherAddr(9), Ipv4Addr(7), InetService(13).
        assert_eq!(k.type_id(), 9 | (7 << 6) | (13 << 12));
    }

    // -------- end Plan 198 §2.1 --------

    fn find_nat_expr(rule: &Rule) -> Option<&NatExpr> {
        rule.exprs.iter().find_map(|e| match e {
            super::super::expr::Expr::Nat(n) => Some(n),
            _ => None,
        })
    }

    #[test]
    fn dnat_inet_table_uses_ip_family() {
        let rule = Rule::new("nat", "prerouting")
            .family(Family::Inet)
            .dnat("10.0.0.1".parse().unwrap(), Some(8080));
        let nat = find_nat_expr(&rule).expect("should have NAT expr");
        assert_eq!(nat.family, Family::Ip);
        assert_eq!(nat.nat_type, NatType::Dnat);
    }

    #[test]
    fn snat_inet_table_uses_ip_family() {
        let rule = Rule::new("nat", "postrouting")
            .family(Family::Inet)
            .snat("10.0.0.1".parse().unwrap(), None);
        let nat = find_nat_expr(&rule).expect("should have NAT expr");
        assert_eq!(nat.family, Family::Ip);
        assert_eq!(nat.nat_type, NatType::Snat);
    }

    #[test]
    fn dnat_ip_table_uses_ip_family() {
        let rule = Rule::new("nat", "prerouting")
            .family(Family::Ip)
            .dnat("192.168.1.1".parse().unwrap(), Some(80));
        let nat = find_nat_expr(&rule).expect("should have NAT expr");
        assert_eq!(nat.family, Family::Ip);
    }

    #[test]
    fn snat_with_port() {
        let rule = Rule::new("nat", "postrouting")
            .family(Family::Inet)
            .snat("192.168.1.1".parse().unwrap(), Some(1024));
        let nat = find_nat_expr(&rule).expect("should have NAT expr");
        assert_eq!(nat.family, Family::Ip);
        assert_eq!(nat.port, Some(1024));
        assert_eq!(nat.addr, NatAddr::V4("192.168.1.1".parse().unwrap()));
    }

    #[test]
    fn dnat_v6_loads_address_and_marks_register() {
        let target: Ipv6Addr = "fd30::2".parse().unwrap();
        let rule = Rule::new("t", "c")
            .family(Family::Ip6)
            .match_daddr_v6(Ipv6Addr::LOCALHOST, 128)
            .match_tcp_dport(80)
            .dnat_v6(target, None);

        // The 16-byte target address is loaded into R0 immediately before the
        // NAT expr (after the match exprs).
        let imm_r0: Vec<&Vec<u8>> = rule
            .exprs
            .iter()
            .filter_map(|e| match e {
                super::super::expr::Expr::Immediate {
                    dreg: Register::R0,
                    data,
                } => Some(data),
                _ => None,
            })
            .collect();
        assert!(
            imm_r0.iter().any(|d| d.as_slice() == target.octets()),
            "expected a 16-byte Immediate of the target address into R0"
        );

        let nat = find_nat_expr(&rule).expect("should have NAT expr");
        assert_eq!(nat.nat_type, NatType::Dnat);
        assert_eq!(nat.family, Family::Ip6);
        assert_eq!(nat.addr, NatAddr::Reg, "v6 NAT marks the register, carries no Ipv4Addr");
        assert!(nat.addr.reg_in_use(), "address register must be marked in use");
        assert_eq!(nat.port, None);
    }

    #[test]
    fn dnat_v6_with_port_loads_proto_register() {
        let target: Ipv6Addr = "fd30::2".parse().unwrap();
        let rule = Rule::new("t", "c")
            .family(Family::Ip6)
            .dnat_v6(target, Some(8080));
        let nat = find_nat_expr(&rule).expect("should have NAT expr");
        assert_eq!(nat.addr, NatAddr::Reg);
        assert_eq!(nat.port, Some(8080));
        // Port loaded into R1.
        let imm_r1 = rule.exprs.iter().any(|e| {
            matches!(
                e,
                super::super::expr::Expr::Immediate {
                    dreg: Register::R1,
                    data,
                } if data.as_slice() == 8080u16.to_be_bytes()
            )
        });
        assert!(imm_r1, "expected port loaded into R1");
    }

    #[test]
    fn snat_v6_loads_address_and_marks_register() {
        let target: Ipv6Addr = "fd30::1".parse().unwrap();
        let rule = Rule::new("t", "c")
            .family(Family::Ip6)
            .snat_v6(target, None);

        let imm_r0 = rule.exprs.iter().any(|e| {
            matches!(
                e,
                super::super::expr::Expr::Immediate {
                    dreg: Register::R0,
                    data,
                } if data.as_slice() == target.octets()
            )
        });
        assert!(imm_r0, "expected a 16-byte Immediate of the target into R0");

        let nat = find_nat_expr(&rule).expect("should have NAT expr");
        assert_eq!(nat.nat_type, NatType::Snat);
        assert_eq!(nat.family, Family::Ip6);
        assert_eq!(nat.addr, NatAddr::Reg, "v6 NAT marks the register, carries no Ipv4Addr");
        assert!(nat.addr.reg_in_use(), "address register must be marked in use");
    }

    // ------------------------------------------------------------
    // IPv6 match helpers
    // ------------------------------------------------------------

    use super::super::expr::Expr;

    fn payload_exprs(rule: &Rule) -> Vec<(PayloadBase, u32, u32)> {
        rule.exprs
            .iter()
            .filter_map(|e| match e {
                Expr::Payload {
                    base, offset, len, ..
                } => Some((*base, *offset, *len)),
                _ => None,
            })
            .collect()
    }

    /// `Cmp` exprs with the leading nfproto guard stripped by position,
    /// so address-match assertions see only the address comparison.
    fn cmp_exprs(rule: &Rule) -> Vec<(CmpOp, Vec<u8>)> {
        strip_nfproto_guard(&rule.exprs)
            .iter()
            .filter_map(|e| match e {
                Expr::Cmp { op, data, .. } => Some((*op, data.clone())),
                _ => None,
            })
            .collect()
    }

    /// The expression slice with a leading `Meta{NfProto} + Cmp{Eq}`
    /// guard pair removed, if present.
    fn strip_nfproto_guard(exprs: &[Expr]) -> &[Expr] {
        match exprs {
            [
                Expr::Meta { key: MetaKey::NfProto, .. },
                Expr::Cmp { op: CmpOp::Eq, .. },
                rest @ ..,
            ] => rest,
            _ => exprs,
        }
    }

    /// True if `rule` opens with `meta nfproto == <proto>` (Meta at
    /// index 0, its Eq Cmp at index 1).
    fn has_nfproto_guard(rule: &Rule, proto: u8) -> bool {
        matches!(
            rule.exprs.as_slice(),
            [
                Expr::Meta { key: MetaKey::NfProto, .. },
                Expr::Cmp { op: CmpOp::Eq, data, .. },
                ..,
            ] if data.as_slice() == [proto]
        )
    }

    fn bitwise_exprs(rule: &Rule) -> Vec<Vec<u8>> {
        rule.exprs
            .iter()
            .filter_map(|e| match e {
                Expr::Bitwise { mask, .. } => Some(mask.clone()),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn match_saddr_v6_exact() {
        let addr: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let rule = Rule::new("filter", "input").match_saddr_v6(addr, 128);
        let payloads = payload_exprs(&rule);
        let cmps = cmp_exprs(&rule);
        assert_eq!(payloads, vec![(PayloadBase::Network, 8, 16)]);
        assert_eq!(cmps.len(), 1);
        assert_eq!(cmps[0].0, CmpOp::Eq);
        assert_eq!(cmps[0].1, addr.octets().to_vec());
        assert!(bitwise_exprs(&rule).is_empty(), "no mask for /128");
    }

    #[test]
    fn match_saddr_v6_with_prefix() {
        let addr: Ipv6Addr = "2001:db8:cafe::beef".parse().unwrap();
        let rule = Rule::new("filter", "input").match_saddr_v6(addr, 64);
        let payloads = payload_exprs(&rule);
        let cmps = cmp_exprs(&rule);
        let masks = bitwise_exprs(&rule);
        assert_eq!(payloads, vec![(PayloadBase::Network, 8, 16)]);
        assert_eq!(masks.len(), 1);
        assert_eq!(masks[0], prefix_to_mask(16, 64));
        assert_eq!(cmps.len(), 1);
        assert_eq!(cmps[0].0, CmpOp::Eq);
        let expected: Vec<u8> = addr
            .octets()
            .iter()
            .zip(prefix_to_mask(16, 64).iter())
            .map(|(a, m)| a & m)
            .collect();
        assert_eq!(cmps[0].1, expected);
    }

    #[test]
    fn match_saddr_v6_overlong_prefix_takes_fast_path() {
        // prefix > 128 is clamped to exact-match: no Bitwise emitted.
        let addr: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let rule = Rule::new("filter", "input").match_saddr_v6(addr, 200);
        assert!(bitwise_exprs(&rule).is_empty());
        let cmps = cmp_exprs(&rule);
        assert_eq!(cmps.len(), 1);
        assert_eq!(cmps[0].1, addr.octets().to_vec());
    }

    #[test]
    fn match_daddr_v6_uses_offset_24() {
        let addr: Ipv6Addr = "fd00::1".parse().unwrap();
        let rule = Rule::new("filter", "output").match_daddr_v6(addr, 128);
        let payloads = payload_exprs(&rule);
        assert_eq!(payloads, vec![(PayloadBase::Network, 24, 16)]);
    }

    #[test]
    fn match_saddr_v6_not_flips_op_to_neq() {
        let addr: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let rule = Rule::new("filter", "input").match_saddr_v6_not(addr, 128);
        let cmps = cmp_exprs(&rule);
        assert_eq!(cmps.len(), 1);
        assert_eq!(cmps[0].0, CmpOp::Neq);
    }

    #[test]
    fn match_daddr_v6_not_uses_offset_24_and_neq() {
        let addr: Ipv6Addr = "2001:db8::abcd".parse().unwrap();
        let rule = Rule::new("filter", "output").match_daddr_v6_not(addr, 64);
        let payloads = payload_exprs(&rule);
        let cmps = cmp_exprs(&rule);
        assert_eq!(payloads, vec![(PayloadBase::Network, 24, 16)]);
        assert_eq!(cmps.len(), 1);
        assert_eq!(cmps[0].0, CmpOp::Neq);
    }

    #[test]
    fn addr_matchers_prepend_nfproto_guard() {
        // Every address matcher opens with the two-expr nfproto guard
        // (Meta@0, Eq Cmp@1), with the address Payload immediately after.
        let v4: Ipv4Addr = "10.0.0.1".parse().unwrap();
        let v6: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let cases = [
            (Rule::new("f", "input").match_saddr_v4(v4, 24), NFPROTO_IPV4),
            (Rule::new("f", "output").match_daddr_v4(v4, 24), NFPROTO_IPV4),
            (Rule::new("f", "input").match_saddr_v4_not(v4, 24), NFPROTO_IPV4),
            (Rule::new("f", "output").match_daddr_v4_not(v4, 24), NFPROTO_IPV4),
            (Rule::new("f", "input").match_saddr_v6(v6, 64), NFPROTO_IPV6),
            (Rule::new("f", "output").match_daddr_v6(v6, 64), NFPROTO_IPV6),
            (Rule::new("f", "input").match_saddr_v6_not(v6, 64), NFPROTO_IPV6),
            (Rule::new("f", "output").match_daddr_v6_not(v6, 64), NFPROTO_IPV6),
        ];
        for (rule, proto) in cases {
            assert!(
                has_nfproto_guard(&rule, proto),
                "matcher must open with meta nfproto == {proto}: {:?}",
                rule.exprs,
            );
            assert!(
                matches!(rule.exprs.get(2), Some(Expr::Payload { .. })),
                "address payload must immediately follow the 2-expr guard: {:?}",
                rule.exprs,
            );
        }
    }

    #[test]
    fn icmp_matchers_prepend_nfproto_guard() {
        // ICMP/ICMPv6 are L3-version-specific, so the matchers open with
        // the nfproto guard (Meta@0, Eq Cmp@1) ahead of the l4proto
        // meta+cmp pair — the same `nft`-in-inet behavior as addr matchers.
        let v4 = Rule::new("f", "input").match_icmp_type(8);
        assert!(
            has_nfproto_guard(&v4, NFPROTO_IPV4),
            "match_icmp_type must open with meta nfproto == ipv4: {:?}",
            v4.exprs,
        );
        let v6 = Rule::new("f", "input").match_icmpv6_type(128);
        assert!(
            has_nfproto_guard(&v6, NFPROTO_IPV6),
            "match_icmpv6_type must open with meta nfproto == ipv6: {:?}",
            v6.exprs,
        );
    }

    #[test]
    fn prefix_to_mask_boundaries() {
        // v4 widths
        assert_eq!(prefix_to_mask(4, 0), vec![0u8; 4]);
        assert_eq!(prefix_to_mask(4, 32), vec![0xff; 4]);
        assert_eq!(prefix_to_mask(4, 24), vec![0xff, 0xff, 0xff, 0x00]);
        // v6 widths
        assert_eq!(prefix_to_mask(16, 0), vec![0u8; 16]);
        assert_eq!(prefix_to_mask(16, 128), vec![0xff; 16]);
        let mut sixty_four = vec![0u8; 16];
        for byte in sixty_four.iter_mut().take(8) {
            *byte = 0xff;
        }
        assert_eq!(prefix_to_mask(16, 64), sixty_four);
        // Cross-byte boundary: /68 → 8 bytes 0xff, then 0xf0, then 7 zeros.
        let mut sixty_eight = vec![0u8; 16];
        for byte in sixty_eight.iter_mut().take(8) {
            *byte = 0xff;
        }
        sixty_eight[8] = 0xf0;
        assert_eq!(prefix_to_mask(16, 68), sixty_eight);
        // Clamp: out-of-range prefix saturates to all-ones.
        assert_eq!(prefix_to_mask(16, 200), vec![0xff; 16]);
    }
}
