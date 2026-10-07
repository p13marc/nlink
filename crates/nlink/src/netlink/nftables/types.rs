//! nftables data types: Family, Hook, Chain, Rule, Table, etc.

use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};

use super::expr::Expr;
use crate::netlink::error::{Error, Result};
use crate::netlink::tc_handle::TcHandle;

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

/// Unwrap to the owned name. Lossless; the inbound direction stays
/// validating ([`TryFrom<&str>`]/[`ChainName::new`]).
impl From<ChainName> for String {
    #[inline]
    fn from(name: ChainName) -> Self {
        name.0
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

impl std::str::FromStr for ChainName {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self> {
        Self::new(s)
    }
}

/// A validated nftables table name.
///
/// Mirrors [`ChainName`]: the kernel rejects empty / overlong /
/// interior-NUL names, so this newtype enforces the same contract at
/// the API boundary and — crucially — makes the
/// `Chain::new(table, name)` argument order a compile-time concern
/// rather than two interchangeable `&str`s. Construct via
/// [`TableName::new`], `"filter".parse()`, or `TryFrom`; it is
/// `Display` + `AsRef<str>` for natural use in messages and
/// `&str`-shaped APIs.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TableName(String);

impl TableName {
    /// Maximum table-name length on the wire, in bytes
    /// (kernel `NFT_NAME_MAXLEN - 1`).
    pub const MAX_LEN: usize = 255;

    /// Construct a table name, validating against the kernel contract.
    pub fn new(s: impl Into<String>) -> Result<Self> {
        let s = s.into();
        if s.is_empty() {
            return Err(Error::InvalidMessage(
                "TableName: empty table names are rejected by nftables".into(),
            ));
        }
        if s.len() > Self::MAX_LEN {
            return Err(Error::InvalidMessage(format!(
                "TableName: {} bytes exceeds NFT_NAME_MAXLEN-1 ({} bytes)",
                s.len(),
                Self::MAX_LEN,
            )));
        }
        if s.contains('\0') {
            return Err(Error::InvalidMessage(
                "TableName: interior NUL bytes are rejected — nftables wire format is a \
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

impl AsRef<str> for TableName {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for TableName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Unwrap to the owned name. Lossless; the inbound direction stays
/// validating ([`TryFrom<&str>`]/[`TableName::new`]).
impl From<TableName> for String {
    #[inline]
    fn from(name: TableName) -> Self {
        name.0
    }
}

impl TryFrom<&str> for TableName {
    type Error = Error;
    fn try_from(s: &str) -> Result<Self> {
        Self::new(s)
    }
}

impl TryFrom<String> for TableName {
    type Error = Error;
    fn try_from(s: String) -> Result<Self> {
        Self::new(s)
    }
}

impl std::str::FromStr for TableName {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self> {
        Self::new(s)
    }
}

/// Rule verdict.
///
/// `#[non_exhaustive]` so new variants can be added additively.
/// [`Verdict::JumpTo`] and [`Verdict::GotoTo`] carry a validated
/// [`ChainName`] — interior NULs / overlong / empty names are
/// rejected at construction rather than at kernel apply time.
///
/// (The 0.20.1 `Verdict::Jump(String)` / `Verdict::Goto(String)`
/// variants were removed in 0.21.)
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Verdict {
    Accept,
    Drop,
    Continue,
    Return,
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

impl Register {
    /// Reverse mapping for the expression decoder (#164). `None` for
    /// values outside the 16-byte register set (the kernel also has
    /// 4-byte `NFT_REG32_*` numbers 8..=20, which the write path never
    /// emits — decodes of such rules demote to `RuleExpr::Unknown`).
    pub(crate) fn from_u32(v: u32) -> Option<Self> {
        match v {
            0 => Some(Self::Verdict),
            1 => Some(Self::R0),
            2 => Some(Self::R1),
            3 => Some(Self::R2),
            4 => Some(Self::R3),
            _ => None,
        }
    }
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

/// TCP header flags — the flags byte at offset 13 of the TCP header, for
/// [`Rule::match_tcp_flags`].
///
/// A newtype rather than bare `TCP_FLAG_*` constants: `linux/tcp.h` already
/// defines `TCP_FLAG_SYN` & co., as big-endian masks over the whole fourth
/// header word (`TCP_FLAG_SYN == htonl(0x00020000)`). Same names, different
/// values, different width — and the UAPI audit cannot see the clash, because
/// it cannot evaluate `__constant_cpu_to_be32`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TcpFlags(pub u8);

impl TcpFlags {
    pub const FIN: Self = Self(0x01);
    pub const SYN: Self = Self(0x02);
    pub const RST: Self = Self(0x04);
    pub const PSH: Self = Self(0x08);
    pub const ACK: Self = Self(0x10);
    pub const URG: Self = Self(0x20);
    pub const ECE: Self = Self(0x40);
    pub const CWR: Self = Self(0x80);

    /// No flags set.
    pub const fn empty() -> Self {
        Self(0)
    }

    pub fn bits(self) -> u8 {
        self.0
    }
}

impl Default for TcpFlags {
    fn default() -> Self {
        Self::empty()
    }
}

impl std::ops::BitOr for TcpFlags {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

impl std::ops::BitOrAssign for TcpFlags {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

/// TCP option kind of the maximum segment size (`TCPOPT_MAXSEG` in glibc's
/// `<netinet/tcp.h>`; the kernel's private name is `TCPOPT_MSS`).
pub const TCPOPT_MAXSEG: u8 = 2;

/// Comparison operator — `enum nft_cmp_ops`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
#[non_exhaustive]
pub enum CmpOp {
    Eq = 0,
    Neq = 1,
    Lt = 2,
    Lte = 3,
    Gt = 4,
    Gte = 5,
}

impl CmpOp {
    /// Reverse mapping for the expression decoder (#164).
    pub(crate) fn from_u32(v: u32) -> Option<Self> {
        match v {
            0 => Some(Self::Eq),
            1 => Some(Self::Neq),
            2 => Some(Self::Lt),
            3 => Some(Self::Lte),
            4 => Some(Self::Gt),
            5 => Some(Self::Gte),
            _ => None,
        }
    }
}

/// Payload base header — `enum nft_payload_bases`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
#[non_exhaustive]
pub enum PayloadBase {
    LinkLayer = 0,
    Network = 1,
    Transport = 2,
}

impl PayloadBase {
    /// Reverse mapping for the expression decoder (#164).
    pub(crate) fn from_u32(v: u32) -> Option<Self> {
        match v {
            0 => Some(Self::LinkLayer),
            1 => Some(Self::Network),
            2 => Some(Self::Transport),
            _ => None,
        }
    }
}

/// Which header family an `exthdr` expression addresses — `enum
/// nft_exthdr_op` in the kernel UAPI.
///
/// Only [`TcpOpt`](Self::TcpOpt) can be written
/// ([`Expr::ExthdrSet`]); every op can be
/// loaded, but see [`Dccp`](Self::Dccp).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
#[non_exhaustive]
pub enum ExthdrOp {
    /// IPv6 extension header (`exthdr`).
    Ipv6 = 0,
    /// TCP option (`tcp option`).
    TcpOpt = 1,
    /// IPv4 option (`ip option`), kernel 5.3+. Not valid in an `ip6` table.
    Ipv4 = 2,
    /// SCTP chunk (`sctp chunk`), kernel 5.14+.
    Sctp = 3,
    /// DCCP option (`dccp option`), kernel 6.5+. The kernel only accepts
    /// it as an existence test (`NFT_EXTHDR_F_PRESENT`), which
    /// [`Expr::Exthdr`] does not model, so a
    /// load built from it is rejected. Upstream has scheduled DCCP option
    /// matching for removal in 2027.
    Dccp = 4,
}

impl ExthdrOp {
    /// Reverse mapping for the expression decoder. `None` for ops the
    /// typed enum doesn't model yet.
    pub(crate) fn from_u32(v: u32) -> Option<Self> {
        match v {
            0 => Some(Self::Ipv6),
            1 => Some(Self::TcpOpt),
            2 => Some(Self::Ipv4),
            3 => Some(Self::Sctp),
            4 => Some(Self::Dccp),
            _ => None,
        }
    }
}

/// Meta key — `enum nft_meta_keys`. Loaded by [`Expr::Meta`]; the keys
/// the kernel lets a rule write (`Mark`, `Priority`) are set with
/// [`Expr::MetaSet`].
///
/// [`Expr::Meta`]: super::expr::Expr::Meta
/// [`Expr::MetaSet`]: super::expr::Expr::MetaSet
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
#[non_exhaustive]
pub enum MetaKey {
    Len = 0,
    Protocol = 1,
    /// `skb->priority` — a TC classid (`major:minor`) that HTB and prio
    /// classify on directly; see [`Rule::set_priority`].
    Priority = 2,
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

impl MetaKey {
    /// Reverse mapping for the expression decoder (#164). `None` for
    /// kernel meta keys the typed enum doesn't model yet — such
    /// expressions decode as `RuleExpr::Unknown`.
    pub(crate) fn from_u32(v: u32) -> Option<Self> {
        match v {
            0 => Some(Self::Len),
            1 => Some(Self::Protocol),
            2 => Some(Self::Priority),
            3 => Some(Self::Mark),
            4 => Some(Self::Iif),
            5 => Some(Self::Oif),
            6 => Some(Self::IifName),
            7 => Some(Self::OifName),
            10 => Some(Self::SkUid),
            11 => Some(Self::SkGid),
            15 => Some(Self::NfProto),
            16 => Some(Self::L4Proto),
            23 => Some(Self::CGroup),
            _ => None,
        }
    }
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
#[repr(u32)]
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

impl CtKey {
    /// Reverse mapping for the expression decoder. `None` for conntrack
    /// keys the typed enum doesn't model — such expressions decode as
    /// `RuleExpr::Unknown`.
    pub(crate) fn from_u32(v: u32) -> Option<Self> {
        match v {
            0 => Some(Self::State),
            1 => Some(Self::Direction),
            2 => Some(Self::Status),
            3 => Some(Self::Mark),
            4 => Some(Self::Secmark),
            5 => Some(Self::Expiration),
            6 => Some(Self::Helper),
            7 => Some(Self::L3Protocol),
            _ => None,
        }
    }
}

/// Route key for [`Expr::Rt`] — `enum nft_rt_keys`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
#[non_exhaustive]
pub enum RtKey {
    /// Realm of the packet's route (`skb->dst->tclassid`).
    Classid = 0,
    /// IPv4 next hop.
    Nexthop4 = 1,
    /// IPv6 next hop.
    Nexthop6 = 2,
    /// TCP MSS the path allows: the smaller of the route's and the reverse
    /// route's MTU, less the IP and TCP headers. A **host-order** `u16` —
    /// convert with [`Expr::Byteorder`]
    /// before writing it into a TCP option. Only in the `forward`,
    /// `output` and `postrouting` hooks (`nft_rt_validate`).
    TcpMss = 3,
    /// Whether the route goes through an xfrm (IPsec) transform.
    Xfrm = 4,
}

impl RtKey {
    /// Reverse mapping for the expression decoder.
    pub(crate) fn from_u32(v: u32) -> Option<Self> {
        match v {
            0 => Some(Self::Classid),
            1 => Some(Self::Nexthop4),
            2 => Some(Self::Nexthop6),
            3 => Some(Self::TcpMss),
            4 => Some(Self::Xfrm),
            _ => None,
        }
    }
}

/// Direction of a [`Expr::Byteorder`]
/// conversion — `enum nft_byteorder_ops`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
#[non_exhaustive]
pub enum ByteorderOp {
    /// Network to host order.
    Ntoh = 0,
    /// Host to network order.
    Hton = 1,
}

impl ByteorderOp {
    /// Reverse mapping for the expression decoder.
    pub(crate) fn from_u32(v: u32) -> Option<Self> {
        match v {
            0 => Some(Self::Ntoh),
            1 => Some(Self::Hton),
            _ => None,
        }
    }
}

/// NAT type — `enum nft_nat_types`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
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
/// ```no_run
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// # let conn = nlink::Connection::<nlink::netlink::Nftables>::new()?;
/// use nlink::netlink::nftables::{Flowtable, Family};
///
/// let ft = Flowtable::new(Family::Inet, "filter", "ft")
///     .device("eth0")
///     .device("eth1")
///     .priority(0)
///     .hw_offload(true);
/// conn.add_flowtable(&ft).await?;
/// # Ok(())
/// # }
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
    pub(crate) table: TableName,
    pub(crate) name: ChainName,
    pub(crate) family: Family,
    pub(crate) hook: Option<Hook>,
    pub(crate) priority: Option<Priority>,
    pub(crate) chain_type: Option<ChainType>,
    pub(crate) policy: Option<Policy>,
    pub(crate) device: Option<String>,
}

impl Chain {
    /// Create a new chain builder.
    ///
    /// `table` / `name` accept anything convertible to a validated
    /// [`TableName`] / [`ChainName`] — a `&str` or `String` (validated
    /// here, so an empty / overlong / NUL-bearing name is an early
    /// `Err`) or an already-typed value (infallible). The distinct
    /// types make the `(table, name)` argument order a compile-time
    /// concern rather than two interchangeable strings.
    pub fn new<T, N>(table: T, name: N) -> Result<Self>
    where
        T: TryInto<TableName>,
        T::Error: Into<Error>,
        N: TryInto<ChainName>,
        N::Error: Into<Error>,
    {
        Ok(Self {
            table: table.try_into().map_err(Into::into)?,
            name: name.try_into().map_err(Into::into)?,
            family: Family::Inet,
            hook: None,
            priority: None,
            chain_type: None,
            policy: None,
            device: None,
        })
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

    /// Place the rule right **after** the rule with kernel handle `pos`
    /// (nft's `add rule ... position <handle>`).
    ///
    /// `add_rule` always sends `NLM_F_APPEND` — without it the kernel
    /// prepends, and rules land in reverse order (#195) — and with it the
    /// kernel links a positioned rule after the one named. This said
    /// "before" until 0.30, which was true only before #195.
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
    /// Pre-validated form — pass a constructed [`ChainName`] when you
    /// already hold one. For the `&str` form that validates the name
    /// at construction, see [`Self::try_jump`].
    pub fn jump(mut self, chain: ChainName) -> Self {
        self.exprs
            .push(super::expr::Expr::Verdict(Verdict::JumpTo(chain)));
        self
    }

    /// Jump to another chain, validating the name at construction.
    ///
    /// Returns `Err` if the name violates the kernel chain-name
    /// contract (empty, interior NUL, or `len > 255`). The fallible
    /// signature surfaces the validation at the input boundary
    /// instead of as a kernel rejection at apply time.
    ///
    /// (Renamed from the 0.20.1 infallible `jump(&str)` shim in 0.21.
    /// The deprecated `Verdict::Jump(String)` fallback path is gone;
    /// the kernel-name contract is enforced at construction.)
    pub fn try_jump(mut self, chain: &str) -> Result<Self> {
        let name = ChainName::new(chain)?;
        self.exprs
            .push(super::expr::Expr::Verdict(Verdict::JumpTo(name)));
        Ok(self)
    }

    /// Goto another chain (no return).
    ///
    /// Pre-validated form — pass a constructed [`ChainName`]. For
    /// the `&str` form that validates at construction, see
    /// [`Self::try_goto`].
    pub fn goto(mut self, chain: ChainName) -> Self {
        self.exprs
            .push(super::expr::Expr::Verdict(Verdict::GotoTo(chain)));
        self
    }

    /// Goto another chain (no return), validating the name at
    /// construction. Returns `Err` if the name violates the kernel
    /// chain-name contract.
    pub fn try_goto(mut self, chain: &str) -> Result<Self> {
        let name = ChainName::new(chain)?;
        self.exprs
            .push(super::expr::Expr::Verdict(Verdict::GotoTo(name)));
        Ok(self)
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

    /// Match source IPv4 address against a named set (`ip saddr @set`).
    ///
    /// Prepends the `meta nfproto ipv4` guard the address matchers carry:
    /// without it, in an `inet` chain an IPv6 packet had bytes 4..8 of its
    /// source address looked up as if they were an IPv4 address.
    pub fn match_saddr_in_set(mut self, set: &str) -> Self {
        use super::expr::Expr;
        self.push_nfproto_ipv4();
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

    /// Match destination IPv4 address against a named set
    /// (`ip daddr @set`), behind the same `meta nfproto ipv4` guard as
    /// [`match_saddr_in_set`](Self::match_saddr_in_set).
    pub fn match_daddr_in_set(mut self, set: &str) -> Self {
        use super::expr::Expr;
        self.push_nfproto_ipv4();
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
    /// ```no_run
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # use nlink::netlink::nftables::Rule;
    /// // Match ICMP traffic
    /// let icmp = Rule::new("filter", "input").match_l4proto(1);
    /// // Match TCP traffic
    /// let tcp = Rule::new("filter", "input").match_l4proto(6);
    /// # Ok(())
    /// # }
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

    /// Set the packet mark (nfmark/fwmark): `meta mark set <mark>`.
    ///
    /// A statement, not a match: place it after the rule's matches. The
    /// mark is what `tc` `fw` filters and `ip rule fwmark` act on.
    ///
    /// This replaces all 32 bits. On a host where other software uses its
    /// own mark bits (kube-proxy, CNI plugins, VPN policy routing), use
    /// [`set_mark_masked`](Self::set_mark_masked).
    pub fn set_mark(mut self, mark: u32) -> Self {
        use super::expr::Expr;
        self.exprs.push(Expr::Immediate {
            dreg: Register::R0,
            data: mark.to_ne_bytes().to_vec(),
        });
        self.exprs.push(Expr::MetaSet {
            key: MetaKey::Mark,
            sreg: Register::R0,
        });
        self
    }

    /// Set only the mark bits under `mask` to `value`, keeping the rest:
    /// `meta mark set mark and ~<mask> or <value>` — iptables
    /// `MARK --set-mark value/mask`.
    ///
    /// Bits of `value` outside `mask` are ignored. Pairs with
    /// [`match_mark_masked`](Self::match_mark_masked) and a `tc` `fw`
    /// filter's mask.
    pub fn set_mark_masked(mut self, value: u32, mask: u32) -> Self {
        self.exprs.push(Expr::Meta {
            dreg: Register::R0,
            key: MetaKey::Mark,
        });
        // (mark & !mask) ^ (value & mask): the masked bits are zero after
        // the AND, so the XOR sets them.
        self.exprs.push(Expr::Bitwise {
            sreg: Register::R0,
            dreg: Register::R0,
            len: 4,
            mask: (!mask).to_ne_bytes().to_vec(),
            xor: (value & mask).to_ne_bytes().to_vec(),
        });
        self.exprs.push(Expr::MetaSet {
            key: MetaKey::Mark,
            sreg: Register::R0,
        });
        self
    }

    /// Match the mark bits under `mask`: `meta mark and <mask> == <value>`.
    ///
    /// Bits of `value` outside `mask` are ignored.
    pub fn match_mark_masked(mut self, value: u32, mask: u32) -> Self {
        self.exprs.push(Expr::Meta {
            dreg: Register::R0,
            key: MetaKey::Mark,
        });
        self.exprs.push(Expr::Bitwise {
            sreg: Register::R0,
            dreg: Register::R0,
            len: 4,
            mask: mask.to_ne_bytes().to_vec(),
            xor: vec![0; 4],
        });
        self.exprs.push(Expr::Cmp {
            sreg: Register::R0,
            op: CmpOp::Eq,
            data: (value & mask).to_ne_bytes().to_vec(),
        });
        self
    }

    /// Set the packet's TC priority to a class: `meta priority set
    /// <major>:<minor>`.
    ///
    /// `skb->priority` is a classid. An HTB qdisc whose handle is `major:`
    /// sends the packet straight to leaf class `major:minor` without
    /// running any filter (`htb_classify`); an inner class runs its own
    /// filters; no such class falls through to the filters and then the
    /// default class. A `prio` qdisc `major:` picks band `minor - 1`. So a
    /// firewall rule can classify into a shaper with no `tc` filter at
    /// all.
    ///
    /// Set it in an `output`, `forward` or `postrouting` chain: for
    /// forwarded IPv4 traffic the kernel overwrites `skb->priority` from
    /// the TOS before the `forward` hook (`net.ipv4.ip_forward_update_priority`,
    /// on by default), so a value set in `prerouting` is lost.
    pub fn set_priority(mut self, class: TcHandle) -> Self {
        self.exprs.push(Expr::Immediate {
            dreg: Register::R0,
            data: u32::from(class).to_ne_bytes().to_vec(),
        });
        self.exprs.push(Expr::MetaSet {
            key: MetaKey::Priority,
            sreg: Register::R0,
        });
        self
    }

    /// Set the connection's mark: `ct mark set <mark>`.
    ///
    /// The conntrack mark lives with the flow rather than the packet, so
    /// one rule can classify a whole connection: set it once, then copy it
    /// onto every packet with [`restore_mark_from_ct`](Self::restore_mark_from_ct).
    /// Needs the `nft_ct` module.
    pub fn set_ct_mark(mut self, mark: u32) -> Self {
        self.exprs.push(Expr::Immediate {
            dreg: Register::R0,
            data: mark.to_ne_bytes().to_vec(),
        });
        self.exprs.push(Expr::CtSet {
            key: CtKey::Mark,
            sreg: Register::R0,
        });
        self
    }

    /// Match the connection's mark: `ct mark <mark>`.
    pub fn match_ct_mark(mut self, mark: u32) -> Self {
        self.exprs.push(Expr::Ct {
            dreg: Register::R0,
            key: CtKey::Mark,
        });
        self.exprs.push(Expr::Cmp {
            sreg: Register::R0,
            op: CmpOp::Eq,
            data: mark.to_ne_bytes().to_vec(),
        });
        self
    }

    /// Copy the packet mark to the connection: `ct mark set mark` —
    /// iptables `CONNMARK --save-mark`.
    pub fn save_mark_to_ct(mut self) -> Self {
        self.exprs.push(Expr::Meta {
            dreg: Register::R0,
            key: MetaKey::Mark,
        });
        self.exprs.push(Expr::CtSet {
            key: CtKey::Mark,
            sreg: Register::R0,
        });
        self
    }

    /// Copy the connection mark to the packet: `meta mark set ct mark` —
    /// iptables `CONNMARK --restore-mark`.
    pub fn restore_mark_from_ct(mut self) -> Self {
        self.exprs.push(Expr::Ct {
            dreg: Register::R0,
            key: CtKey::Mark,
        });
        self.exprs.push(Expr::MetaSet {
            key: MetaKey::Mark,
            sreg: Register::R0,
        });
        self
    }

    /// Match TCP header flags: `tcp flags & <mask> == <flags>`.
    ///
    /// A connection opening (`tcp flags syn / syn,rst`) is
    /// `match_tcp_flags(TcpFlags::SYN, TcpFlags::SYN | TcpFlags::RST)`.
    /// Bits of `flags` outside `mask` are ignored.
    pub fn match_tcp_flags(mut self, flags: TcpFlags, mask: TcpFlags) -> Self {
        use super::expr::Expr;
        self.push_meta_eq(MetaKey::L4Proto, IPPROTO_TCP);
        // Flags byte at offset 13 of the TCP header.
        self.exprs.push(Expr::Payload {
            dreg: Register::R0,
            base: PayloadBase::Transport,
            offset: 13,
            len: 1,
        });
        self.exprs.push(Expr::Bitwise {
            sreg: Register::R0,
            dreg: Register::R0,
            len: 1,
            mask: vec![mask.bits()],
            xor: vec![0],
        });
        self.exprs.push(Expr::Cmp {
            sreg: Register::R0,
            op: CmpOp::Eq,
            data: vec![flags.bits() & mask.bits()],
        });
        self
    }

    /// Clamp the TCP MSS option to `mss`: `tcp option maxseg size set <mss>`.
    ///
    /// The MSS is only ever lowered, as with iptables `TCPMSS --set-mss`:
    /// the kernel itself refuses to raise it (`nft_exthdr_tcp_set_eval`,
    /// since 4.14 — "increase can cause connection to stall"), so a SYN
    /// already at or below `mss` passes unchanged. A segment without an
    /// MSS option is also left alone; unlike `TCPMSS`, nftables cannot
    /// insert one.
    ///
    /// A statement, not a match: whatever follows it in the rule still
    /// runs for every TCP packet. Emits what `nft` does — an immediate and
    /// an `exthdr` write — behind the `meta l4proto tcp` guard, because on
    /// a non-TCP packet the write ends rule evaluation. Usually combined
    /// with a SYN match ([`match_tcp_flags`](Self::match_tcp_flags)) in a
    /// `forward` or `postrouting` chain.
    pub fn clamp_tcp_mss(mut self, mss: u16) -> Self {
        use super::expr::Expr;
        self.push_meta_eq(MetaKey::L4Proto, IPPROTO_TCP);
        self.exprs.push(Expr::Immediate {
            dreg: Register::R0,
            data: mss.to_be_bytes().to_vec(),
        });
        self.push_tcp_mss_write();
        self
    }

    /// Clamp the TCP MSS option to what the path allows: `tcp option
    /// maxseg size set rt mtu` — iptables `TCPMSS --clamp-mss-to-pmtu`.
    ///
    /// The route lookup's MSS (the smaller of the route's and the reverse
    /// route's MTU, less the IP and TCP headers) is converted to network
    /// byte order and written, exactly as `nft` linearizes it. As with
    /// [`clamp_tcp_mss`](Self::clamp_tcp_mss) the MSS is only ever lowered,
    /// and a segment without the option is left alone.
    ///
    /// The kernel only allows `rt` in `ip`, `ip6` and `inet` tables, and the
    /// path MSS only in the `forward`, `output` and `postrouting` hooks —
    /// anywhere else the rule is rejected. Usually combined with a SYN
    /// match in `forward`, where a tunnel or PPPoE uplink narrows the path.
    pub fn clamp_tcp_mss_to_pmtu(mut self) -> Self {
        self.push_meta_eq(MetaKey::L4Proto, IPPROTO_TCP);
        self.exprs.push(Expr::Rt {
            dreg: Register::R0,
            key: RtKey::TcpMss,
        });
        // `rt tcpmss` stores a host-order u16; the option wants it in
        // network order.
        self.exprs.push(Expr::Byteorder {
            sreg: Register::R0,
            dreg: Register::R0,
            op: ByteorderOp::Hton,
            len: 2,
            size: 2,
        });
        self.push_tcp_mss_write();
        self
    }

    /// Push the `exthdr` write of the TCP MSS option from `R0`: the 2-byte
    /// value at offset 2 of the option (kind, length, value), network
    /// byte order.
    fn push_tcp_mss_write(&mut self) {
        self.exprs.push(Expr::ExthdrSet {
            sreg: Register::R0,
            op: ExthdrOp::TcpOpt,
            exthdr_type: TCPOPT_MAXSEG,
            offset: 2,
            len: 2,
        });
    }

    /// Reject the packet: send an ICMP port-unreachable, then drop.
    ///
    /// The client fails fast with "connection refused" instead of hanging to
    /// its TCP timeout. For a black hole (no ICMP, no RST), use
    /// [`drop`](Self::drop) instead.
    ///
    /// Uses `ICMPX` (family-independent) so the same rule is valid in an
    /// `inet` or `bridge` chain, where the family is not known at rule-load
    /// time. For a TCP RST, or a specific ICMP code, use
    /// [`reject_with`](Self::reject_with).
    ///
    /// Until 0.25 this pushed a bare `NF_DROP` verdict — the doc promised
    /// reject semantics and the code delivered a silent drop, so clients hung
    /// until timeout (#205).
    pub fn reject(self) -> Self {
        // NFT_REJECT_ICMPX_PORT_UNREACH = 1.
        self.reject_with(super::NFT_REJECT_ICMPX_UNREACH, 1)
    }

    /// Reject the packet with an explicit reject type and ICMP code.
    ///
    /// `reject_type` is one of [`NFT_REJECT_ICMP_UNREACH`],
    /// [`NFT_REJECT_TCP_RST`] or [`NFT_REJECT_ICMPX_UNREACH`]. `icmp_code` is
    /// ignored for a TCP reset.
    ///
    /// [`NFT_REJECT_ICMP_UNREACH`]: super::NFT_REJECT_ICMP_UNREACH
    /// [`NFT_REJECT_TCP_RST`]: super::NFT_REJECT_TCP_RST
    /// [`NFT_REJECT_ICMPX_UNREACH`]: super::NFT_REJECT_ICMPX_UNREACH
    pub fn reject_with(mut self, reject_type: u32, icmp_code: u8) -> Self {
        self.exprs.push(super::expr::Expr::Reject {
            reject_type,
            icmp_code,
        });
        self
    }

    /// Offload the matched flow to the named flowtable: `flow add @<name>`.
    ///
    /// Follow-on packets of the flow then bypass the ruleset on the
    /// flowtable's fast path. Valid in a `forward` chain only, and the
    /// flowtable must live in the rule's table (see
    /// [`Flowtable`]); usually preceded by
    /// `match_ct_state(CtState::ESTABLISHED)`.
    pub fn flow_offload(mut self, flowtable: &str) -> Self {
        self.exprs.push(super::expr::Expr::FlowOffload {
            table: flowtable.to_string(),
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
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
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
    /// Number of bits each component occupies in a `Concat` type word.
    /// nft's `TYPE_BITS`.
    const CONCAT_TYPE_BITS: u32 = 6;

    /// The **nftables userspace datatype id** carried in `NFTA_SET_KEY_TYPE`
    /// (nft's `enum datatypes`, `include/datatype.h`).
    ///
    /// The kernel only checks `NFT_DATA_RESERVED_MASK` and stores this value
    /// opaquely, so a wrong id still *creates* the set — it is `nft list
    /// ruleset` that then renders the wrong type, and nft cannot parse or
    /// round-trip the set. Three of these were wrong until 0.25 (#207):
    /// `InetProto` was 14 (which is `icmp_type`), `Mark` was 12 (which is
    /// `inet_protocol`), and `IfIndex` was 15 (which is `tcp_flag`).
    pub fn type_id(&self) -> u32 {
        match self {
            Self::Ipv4Addr => 7,      // TYPE_IPADDR
            Self::Ipv6Addr => 8,      // TYPE_IP6ADDR
            Self::EtherAddr => 9,     // TYPE_ETHERADDR
            Self::InetProto => 12,    // TYPE_INET_PROTOCOL
            Self::InetService => 13,  // TYPE_INET_SERVICE
            Self::Mark => 19,         // TYPE_MARK
            Self::IfIndex => 20,      // TYPE_IFINDEX
            Self::Concat(parts) => {
                // nft's `concat_subtype_add(type, sub) = type << TYPE_BITS | sub`,
                // applied left-to-right across the component list. That puts
                // component 0 in the **high** bits.
                //
                // nlink used to fold the other way (`acc | (id << (i * 6))`),
                // putting component 0 in the *low* bits — the reverse of what
                // nft builds and parses (#207).
                //
                // 6 bits per component in a u32 means at most 5 components fit;
                // beyond that the earliest components shift out the top. The
                // builder caps the list, so this cannot silently truncate.
                parts.iter().fold(0u32, |acc, t| {
                    (acc << Self::CONCAT_TYPE_BITS) | (t.type_id() & 0x3F)
                })
            }
        }
    }

    /// Key length in bytes, for `NFTA_SET_KEY_LEN`.
    ///
    /// For `Concat`, the sum of each component's length padded to 4-byte
    /// alignment (the kernel's `nft_set_ext_concat` layout).
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> u32 {
        match self {
            Self::Ipv4Addr => 4,
            Self::Ipv6Addr => 16,
            // A MAC address is 6 bytes and nft sends klen = 6. It used to say
            // 8 ("padded to 8"), but that padding belongs to the *concat*
            // layout, not to a standalone key — and a klen of 8 makes a 6-byte
            // `sreg` load fail `nft_lookup_init` validation with EINVAL (#207).
            Self::EtherAddr => 6,
            Self::InetService => 2,
            Self::IfIndex => 4,
            Self::Mark => 4,
            Self::InetProto => 1,
            Self::Concat(parts) => {
                // Each component is padded to 4-byte alignment before the next
                // starts. This is where EtherAddr's 6 bytes become 8.
                parts.iter().map(|t| t.len().next_multiple_of(4)).sum()
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
    pub(crate) size: Option<u32>,
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
            size: None,
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

    /// Maximum number of elements (`nft add set ... { size N; }`).
    ///
    /// Adding an element to a full set fails with `ENFILE`
    /// (`err.errno() == Some(libc::ENFILE)`). Without a size the set is
    /// unbounded. The size also steers the kernel's backend choice: a sized
    /// set without the timeout or interval flags gets the fixed-bucket
    /// `nft_hash` instead of the resizable `nft_rhash`.
    pub fn size(mut self, size: u32) -> Self {
        self.size = Some(size);
        self
    }

    /// Set the flags bitmask directly (`NFT_SET_*` constants).
    /// Overwrites any previously set flags (including
    /// [`Self::constant`]); combine bits yourself if you need
    /// several.
    pub fn flags(mut self, flags: u32) -> Self {
        self.flags = flags;
        self
    }
}

/// A set element (key + optional data).
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
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
///
/// `#[non_exhaustive]` since 0.30: the kernel keeps adding set attributes
/// worth reading back, and each one used to be a breaking change here.
#[derive(Debug, Clone)]
#[non_exhaustive]
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
    /// Maximum element count (`NFTA_SET_DESC_SIZE`), if the set has one.
    /// The kernel can report one nobody declared: a set a `dynset`
    /// expression writes to is given 65535.
    pub size: Option<u32>,
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

    // -------- TableName newtype --------

    #[test]
    fn table_name_validates_like_kernel() {
        assert!(TableName::new("filter").is_ok());
        assert!("filter".parse::<TableName>().is_ok());
        // Empty / interior-NUL / overlong are rejected.
        assert!(TableName::new("").is_err());
        assert!(TableName::new("a\0b").is_err());
        assert!(TableName::new("x".repeat(TableName::MAX_LEN + 1)).is_err());
        // Round-trips through Display / as_str.
        let t = TableName::new("inet-fw").unwrap();
        assert_eq!(t.as_str(), "inet-fw");
        assert_eq!(t.to_string(), "inet-fw");
    }

    #[test]
    fn table_and_chain_name_into_string() {
        let t = TableName::new("filter").unwrap();
        let s: String = t.into();
        assert_eq!(s, "filter");
        let c = ChainName::new("input").unwrap();
        let s: String = c.into();
        assert_eq!(s, "input");
    }

    #[test]
    fn chain_new_accepts_str_and_typed_and_validates() {
        // &str path (validated, fallible).
        let c = Chain::new("filter", "input").unwrap();
        assert_eq!(c.table.as_str(), "filter");
        assert_eq!(c.name.as_str(), "input");
        // Already-typed path (infallible conversion via the
        // Infallible→Error bridge).
        let table = TableName::new("nat").unwrap();
        let name = ChainName::new("postrouting").unwrap();
        let c = Chain::new(table, name).unwrap();
        assert_eq!(c.table.as_str(), "nat");
        // Invalid name surfaces as Err rather than a bad wire frame.
        assert!(Chain::new("", "input").is_err());
        assert!(Chain::new("filter", "a\0b").is_err());
    }

    // -------- SetKeyType wire contract (#207) --------

    /// The scalar datatype ids, against nft's `enum datatypes`
    /// (include/datatype.h). Three of these were wrong, and this test used to
    /// pin one of the wrong ones (`InetProto == 14`, which is actually
    /// `icmp_type`).
    #[test]
    fn set_key_type_scalar_datatype_ids() {
        assert_eq!(SetKeyType::Ipv4Addr.type_id(), 7); // TYPE_IPADDR
        assert_eq!(SetKeyType::Ipv6Addr.type_id(), 8); // TYPE_IP6ADDR
        assert_eq!(SetKeyType::EtherAddr.type_id(), 9); // TYPE_ETHERADDR
        assert_eq!(SetKeyType::InetProto.type_id(), 12); // TYPE_INET_PROTOCOL
        assert_eq!(SetKeyType::InetService.type_id(), 13); // TYPE_INET_SERVICE
        assert_eq!(SetKeyType::Mark.type_id(), 19); // TYPE_MARK
        assert_eq!(SetKeyType::IfIndex.type_id(), 20); // TYPE_IFINDEX

        // The three that were wrong pointed at real-but-different types:
        // 14 = icmp_type, 12 = inet_protocol, 15 = tcp_flag.
        assert_ne!(SetKeyType::InetProto.type_id(), 14);
        assert_ne!(SetKeyType::Mark.type_id(), 12);
        assert_ne!(SetKeyType::IfIndex.type_id(), 15);
    }

    /// A MAC key is 6 bytes on the wire. It used to claim 8 — and a klen of 8
    /// makes a 6-byte `sreg` load fail `nft_lookup_init` with EINVAL. The
    /// padding to 8 belongs to the concat layout, not to a standalone key.
    #[test]
    fn set_key_type_ether_addr_klen_is_six() {
        assert_eq!(SetKeyType::EtherAddr.len(), 6);
        assert_eq!(SetKeyType::InetProto.len(), 1);
        assert_eq!(SetKeyType::InetService.len(), 2);
    }

    #[test]
    fn set_key_type_concat_len_pads_each_component() {
        // ip saddr (4B) . tcp dport (2B → 4B after pad) = 8B.
        let k = SetKeyType::Concat(vec![SetKeyType::Ipv4Addr, SetKeyType::InetService]);
        assert_eq!(k.len(), 8);
    }

    /// nft builds a concat type with
    /// `concat_subtype_add(t, n) = (t << TYPE_BITS) | n`, applied left-to-right
    /// — so component 0 lands in the **high** bits.
    ///
    /// nlink folded the other way, putting component 0 in the *low* bits: the
    /// exact reverse of what nft builds and parses. This test used to pin the
    /// reversed order (#207).
    #[test]
    fn set_key_type_concat_packs_component_zero_in_the_high_bits() {
        // ipv4_addr(7) . inet_service(13)  ->  7 << 6 | 13
        let k = SetKeyType::Concat(vec![SetKeyType::Ipv4Addr, SetKeyType::InetService]);
        assert_eq!(k.type_id(), (7 << 6) | 13);
        assert_ne!(k.type_id(), 7 | (13 << 6), "regression: packing is reversed");
    }

    #[test]
    fn set_key_type_concat_single_component_degenerate() {
        // One-component concat reports the wrapped type's own type_id (no
        // shift). The kernel treats this as a normal key.
        let k = SetKeyType::Concat(vec![SetKeyType::Ipv4Addr]);
        assert_eq!(k.type_id(), 7);
        assert_eq!(k.len(), 4);
    }

    #[test]
    fn set_key_type_concat_three_components_padding_round_trip() {
        // ether_addr (6B → 8B after pad) . ip saddr (4B) . inet_service (2B → 4B) = 16B.
        let k = SetKeyType::Concat(vec![
            SetKeyType::EtherAddr,
            SetKeyType::Ipv4Addr,
            SetKeyType::InetService,
        ]);
        assert_eq!(k.len(), 16);
        // ether_addr(9) . ipv4_addr(7) . inet_service(13), component 0 highest.
        assert_eq!(k.type_id(), (9 << 12) | (7 << 6) | 13);
    }

    // -------- end SetKeyType wire contract --------

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
