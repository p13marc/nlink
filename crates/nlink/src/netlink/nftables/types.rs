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
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "serde", serde(transparent))]
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
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
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
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
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
/// The data area is 16 32-bit words. `R0..=R3` (`NFT_REG_1..=NFT_REG_4`)
/// name it in 16-byte steps; `Reg32_00..=Reg32_15` (`NFT_REG32_00..=15`)
/// name each word, which is what a concatenation needs: `ip saddr . tcp
/// dport` loads the address into word 0 and the port into word 1.
///
/// A word that starts a 16-byte register has two names — `Reg32_04` is
/// `R1` — and the kernel dumps the 16-byte one. nlink writes that form too
/// ([`Self::wire`]), so a rule built with either name reads back as it was
/// written and `NftablesConfig::diff` does not see a change that is only a
/// register's spelling (Plan 178).
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
    /// `NFT_REG32_00`, word 0 — the first word of `R0`.
    Reg32_00 = 8,
    /// `NFT_REG32_01`, word 1.
    Reg32_01 = 9,
    /// `NFT_REG32_02`, word 2.
    Reg32_02 = 10,
    /// `NFT_REG32_03`, word 3.
    Reg32_03 = 11,
    /// `NFT_REG32_04`, word 4 — the first word of `R1`.
    Reg32_04 = 12,
    /// `NFT_REG32_05`, word 5.
    Reg32_05 = 13,
    /// `NFT_REG32_06`, word 6.
    Reg32_06 = 14,
    /// `NFT_REG32_07`, word 7.
    Reg32_07 = 15,
    /// `NFT_REG32_08`, word 8 — the first word of `R2`.
    Reg32_08 = 16,
    /// `NFT_REG32_09`, word 9.
    Reg32_09 = 17,
    /// `NFT_REG32_10`, word 10.
    Reg32_10 = 18,
    /// `NFT_REG32_11`, word 11.
    Reg32_11 = 19,
    /// `NFT_REG32_12`, word 12 — the first word of `R3`.
    Reg32_12 = 20,
    /// `NFT_REG32_13`, word 13.
    Reg32_13 = 21,
    /// `NFT_REG32_14`, word 14.
    Reg32_14 = 22,
    /// `NFT_REG32_15`, word 15 — the last.
    Reg32_15 = 23,
}

impl Register {
    const WORDS: [Self; 16] = [
        Self::Reg32_00,
        Self::Reg32_01,
        Self::Reg32_02,
        Self::Reg32_03,
        Self::Reg32_04,
        Self::Reg32_05,
        Self::Reg32_06,
        Self::Reg32_07,
        Self::Reg32_08,
        Self::Reg32_09,
        Self::Reg32_10,
        Self::Reg32_11,
        Self::Reg32_12,
        Self::Reg32_13,
        Self::Reg32_14,
        Self::Reg32_15,
    ];

    /// The register starting at 32-bit word `word` of the data area, in
    /// the form the kernel dumps: `R0` for word 0, `Reg32_01` for word 1,
    /// `R1` for word 4. `None` past word 15.
    pub fn word(word: usize) -> Option<Self> {
        Self::WORDS.get(word).map(|r| r.canonical())
    }

    /// The kernel's spelling of this register: a word that starts a
    /// 16-byte register is named by that register.
    pub fn canonical(self) -> Self {
        match self {
            Self::Reg32_00 => Self::R0,
            Self::Reg32_04 => Self::R1,
            Self::Reg32_08 => Self::R2,
            Self::Reg32_12 => Self::R3,
            other => other,
        }
    }

    /// The register number nlink writes: [`Self::canonical`]'s.
    pub fn wire(self) -> u32 {
        self.canonical() as u32
    }

    /// Reverse mapping for the expression decoder (#164). `None` for a
    /// number that is not a register.
    pub(crate) fn from_u32(v: u32) -> Option<Self> {
        match v {
            0 => Some(Self::Verdict),
            1 => Some(Self::R0),
            2 => Some(Self::R1),
            3 => Some(Self::R2),
            4 => Some(Self::R3),
            8..=23 => Self::WORDS.get((v - 8) as usize).copied(),
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
#[non_exhaustive]
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
#[non_exhaustive]
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
#[non_exhaustive]
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
    /// The declarative identity (`nlink:<key>`), set by `NftablesDiff::apply`
    /// from the declared rule's key. Imperative rules have none.
    pub(crate) key: Option<String>,
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
            key: None,
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

    /// Attach a human comment to this rule, shown by `nft list ruleset` as
    /// `comment "..."` (`NFTA_RULE_USERDATA`, libnftnl's TLV). At most 127
    /// bytes.
    ///
    /// Written verbatim. In a declarative `NftablesConfig` the rule's key
    /// goes in front of it — `nlink:<key> <comment>` — and the two share
    /// those 127 bytes; installing a longer one is an error, not a silent
    /// drop.
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

    /// Rate limit: `limit rate <rate>/<unit>` (burst 5). For a burst or
    /// `over`, push a [`LimitExpr`](super::expr::LimitExpr) with
    /// [`expr`](Self::expr).
    pub fn limit(mut self, rate: u64, unit: LimitUnit) -> Self {
        self.exprs
            .push(super::expr::LimitExpr::packets(rate, unit).into());
        self
    }

    /// Masquerade (source NAT using outgoing interface address).
    pub fn masquerade(mut self) -> Self {
        self.exprs.push(super::expr::MasqExpr::new().into());
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
        self.exprs.push(Expr::Redirect(super::expr::RedirExpr { port }));
        self
    }

    /// Log packet with optional prefix. For an `nflog` group, push a
    /// [`LogExpr`](super::expr::LogExpr) with [`expr`](Self::expr).
    pub fn log(mut self, prefix: Option<&str>) -> Self {
        let mut log = super::expr::LogExpr::new();
        if let Some(prefix) = prefix {
            log = log.prefix(prefix);
        }
        self.exprs.push(log.into());
        self
    }

    /// Match source IPv4 address against a named set (`ip saddr @set`).
    /// Same as `match_in_set(PacketField::Ip4Saddr, set)`.
    ///
    /// Behind the `meta nfproto ipv4` guard the address matchers carry:
    /// without it, in an `inet` chain an IPv6 packet had bytes 4..8 of its
    /// source address looked up as if they were an IPv4 address.
    pub fn match_saddr_in_set(self, set: &str) -> Self {
        self.match_in_set(PacketField::Ip4Saddr, set)
    }

    /// Match destination IPv4 address against a named set
    /// (`ip daddr @set`). Same as `match_in_set(PacketField::Ip4Daddr, set)`.
    pub fn match_daddr_in_set(self, set: &str) -> Self {
        self.match_in_set(PacketField::Ip4Daddr, set)
    }

    /// Match `field` against a named set: `<field> @<set>` — `ip6 saddr @s`,
    /// `tcp dport @ports`, `meta mark @marks`, … The set's key type must be
    /// `field.key_type()`.
    pub fn match_in_set(mut self, field: PacketField, set: &str) -> Self {
        self.push_field_load(field);
        self.exprs
            .push(super::expr::LookupExpr::new(set, Register::R0).into());
        self
    }

    /// Match `field` when it is *not* in a named set: `<field> != @<set>` —
    /// iptables `-m set ! --match-set`. Packets that fail the field's
    /// protocol guard (an IPv6 packet, for an IPv4 field) do not match.
    pub fn match_not_in_set(mut self, field: PacketField, set: &str) -> Self {
        self.push_field_load(field);
        self.exprs.push(
            super::expr::LookupExpr::new(set, Register::R0)
                .invert()
                .into(),
        );
        self
    }

    /// Match a concatenation of fields against a set of concatenated keys:
    /// `ip daddr . udp dport @s` — ipset `hash:ip,port`, and with an
    /// interval set `hash:net,port`. The set's key type must be
    /// `SetKeyType::Concat` of the fields' [`PacketField::key_type`]s, in
    /// the same order.
    ///
    /// Each field's protocol guard comes first, once, then each field is
    /// loaded into the 32-bit word after the previous one, as `nft` lays a
    /// concatenation out. The data area holds 16 words (64 bytes — four
    /// IPv6 addresses); a longer concatenation is refused by the kernel.
    pub fn match_concat_in_set(mut self, fields: &[PacketField], set: &str) -> Self {
        self.push_concat_load(fields);
        self.exprs
            .push(super::expr::LookupExpr::new(set, Register::R0).into());
        self
    }

    /// Match a concatenation of fields when it is *not* in a set:
    /// `ip saddr . tcp dport != @s`.
    pub fn match_concat_not_in_set(mut self, fields: &[PacketField], set: &str) -> Self {
        self.push_concat_load(fields);
        self.exprs.push(
            super::expr::LookupExpr::new(set, Register::R0)
                .invert()
                .into(),
        );
        self
    }

    /// `<field> vmap @<map>`: the verdict the map holds for `field` decides
    /// the packet — accept, drop, or jump to a chain ([`Set::vmap`]). A
    /// packet whose field is not in the map goes on to the next rule.
    pub fn vmap(mut self, field: PacketField, map: &str) -> Self {
        self.push_field_load(field);
        self.push_map_lookup(map, Register::Verdict);
        self
    }

    /// `<field> . <field> vmap @<map>`: [`vmap`](Self::vmap) on a
    /// concatenation, laid out as [`match_concat_in_set`](Self::match_concat_in_set)
    /// does.
    pub fn vmap_concat(mut self, fields: &[PacketField], map: &str) -> Self {
        self.push_concat_load(fields);
        self.push_map_lookup(map, Register::Verdict);
        self
    }

    /// `meta mark set <field> map @<map>`: set the packet mark to the value
    /// the map holds for `field` — a map of [`SetKeyType::Mark`] values. A
    /// packet whose field is not in the map stops at this rule, unmarked.
    pub fn set_mark_from_map(self, field: PacketField, map: &str) -> Self {
        self.set_meta_from_map(MetaKey::Mark, field, map)
    }

    /// `meta priority set <field> map @<map>`: the TC class the map holds
    /// for `field` — a map of [`SetKeyType::ClassId`] values
    /// ([`SetElement::classid`]). HTB sends the packet straight to that
    /// class, as with [`set_priority`](Self::set_priority).
    pub fn set_priority_from_map(self, field: PacketField, map: &str) -> Self {
        self.set_meta_from_map(MetaKey::Priority, field, map)
    }

    fn set_meta_from_map(mut self, key: MetaKey, field: PacketField, map: &str) -> Self {
        self.push_field_load(field);
        self.push_map_lookup(map, Register::R0);
        self.exprs.push(Expr::MetaSet {
            key,
            sreg: Register::R0,
        });
        self
    }

    /// Count with, or check against, the named object of `object_type` —
    /// `counter name "web"`, `quota name "q"`, `limit name "l"`. Created
    /// with [`Connection::add_object`](crate::netlink::Connection::add_object)
    /// or declared on the table.
    pub fn objref(mut self, object_type: super::object::ObjectType, name: &str) -> Self {
        self.exprs.push(
            super::expr::ObjrefExpr::Named {
                object_type,
                name: name.to_string(),
            }
            .into(),
        );
        self
    }

    /// `counter name "<name>"`: count into a named counter, shared by every
    /// rule that names it.
    pub fn counter_named(self, name: &str) -> Self {
        self.objref(super::object::ObjectType::Counter, name)
    }

    /// `quota name "<name>"`: match against a named quota.
    pub fn quota_named(self, name: &str) -> Self {
        self.objref(super::object::ObjectType::Quota, name)
    }

    /// `limit name "<name>"`: match against a named limit.
    pub fn limit_named(self, name: &str) -> Self {
        self.objref(super::object::ObjectType::Limit, name)
    }

    /// `counter name <field> map @<map>` (and the same for quotas and
    /// limits): use the object the object map holds for `field` — one
    /// counter per address, ipset's per-element `counters`. A packet whose
    /// field is not in the map stops at this rule.
    pub fn objref_from_map(mut self, field: PacketField, map: &str) -> Self {
        self.push_field_load(field);
        self.exprs.push(
            super::expr::ObjrefExpr::Map {
                sreg: Register::R0,
                map: map.to_string(),
            }
            .into(),
        );
        self
    }

    /// `quota until <bytes> bytes`: match until the rule has passed `bytes`
    /// bytes. The quota is the rule's own; share one with
    /// [`quota_named`](Self::quota_named).
    pub fn quota_until(mut self, bytes: u64) -> Self {
        self.exprs.push(super::expr::QuotaExpr::new(bytes).into());
        self
    }

    /// `quota over <bytes> bytes`: match once the rule has passed `bytes`.
    pub fn quota_over(mut self, bytes: u64) -> Self {
        self.exprs.push(super::expr::QuotaExpr::new(bytes).over().into());
        self
    }

    /// Look the key in `R0` up in `map`, loading what it maps to into `dreg`.
    fn push_map_lookup(&mut self, map: &str, dreg: Register) {
        self.exprs.push(
            super::expr::LookupExpr::new(map, Register::R0)
                .dreg(dreg)
                .into(),
        );
    }

    /// Add `field` to a set from the packet path: `add @<set> { <field>
    /// [timeout T] }` — ipset `SET --add-set`. An element already there is
    /// left alone (its timeout keeps running). `timeout` overrides the
    /// set's default; the set must be [`Set::dynamic`], and have timeouts
    /// for a timeout. See [`DynsetExpr`](super::expr::DynsetExpr).
    pub fn add_to_set(
        self,
        field: PacketField,
        set: &str,
        timeout: Option<std::time::Duration>,
    ) -> Self {
        self.push_dynset(super::expr::DynsetOp::Add, field, set, timeout)
    }

    /// Add `field` to a set, or restart its timeout if it is there:
    /// `update @<set> { <field> [timeout T] }` — "seen in the last T".
    pub fn update_in_set(
        self,
        field: PacketField,
        set: &str,
        timeout: Option<std::time::Duration>,
    ) -> Self {
        self.push_dynset(super::expr::DynsetOp::Update, field, set, timeout)
    }

    /// Remove `field` from a set: `delete @<set> { <field> }` — ipset
    /// `SET --del-set`. Kernel 5.4+.
    pub fn delete_from_set(self, field: PacketField, set: &str) -> Self {
        self.push_dynset(super::expr::DynsetOp::Delete, field, set, None)
    }

    fn push_dynset(
        mut self,
        op: super::expr::DynsetOp,
        field: PacketField,
        set: &str,
        timeout: Option<std::time::Duration>,
    ) -> Self {
        self.push_field_load(field);
        let mut dynset = super::expr::DynsetExpr::new(op, set, Register::R0);
        if let Some(timeout) = timeout {
            dynset = dynset.timeout(timeout);
        }
        self.exprs.push(dynset.into());
        self
    }

    /// Load `field` into `R0` behind the protocol guard `nft` emits for it.
    pub(crate) fn push_field_load(&mut self, field: PacketField) {
        self.push_field_guard(field);
        self.exprs.push(field.load(Register::R0));
    }

    /// Load `fields` into consecutive 32-bit words from `R0`, behind their
    /// guards — each distinct guard once, all before the first load, since
    /// a guard compares in `R0` too.
    fn push_concat_load(&mut self, fields: &[PacketField]) {
        let mut guarded = Vec::new();
        for field in fields {
            let guard = field.guard();
            if guard.is_some() && !guarded.contains(&guard) {
                guarded.push(guard);
                self.push_field_guard(*field);
            }
        }
        let mut word = 0;
        for field in fields {
            // Past the last word, ask for the last one: the kernel then
            // refuses the load as out of range rather than nlink building a
            // rule that matches something else.
            let dreg = Register::word(word).unwrap_or(Register::Reg32_15);
            self.exprs.push(field.load(dreg));
            word += field.len().div_ceil(4) as usize;
        }
    }

    /// The protocol guard `nft` puts in front of `field`.
    fn push_field_guard(&mut self, field: PacketField) {
        if let Some((key, value)) = field.guard() {
            self.push_meta_eq(key, value);
        }
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
            flowtable: flowtable.to_string(),
        });
        self
    }

    /// Append one expression: a payload struct such as
    /// [`LookupExpr`](super::expr::LookupExpr) or
    /// [`LimitExpr`](super::expr::LimitExpr), or any [`Expr`].
    pub fn expr(mut self, expr: impl Into<Expr>) -> Self {
        self.exprs.push(expr.into());
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
    /// The declarative identity nlink stored in the rule's comment
    /// (`nlink:<key>`), if this rule was installed by nlink. Drives the
    /// per-rule reconciliation of `NftablesConfig`.
    pub key: Option<String>,
    /// The rule's comment exactly as `nft list ruleset` shows it, whoever
    /// set it (nlink's `nlink:<key>` included).
    pub comment_text: Option<String>,
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
    /// A TC class id, `major:minor` (4 bytes, host order) — what
    /// `meta priority` holds. A value type for priority maps
    /// ([`Rule::set_priority_from_map`]).
    ClassId,
    /// Mark value (4 bytes).
    Mark,
    /// IP protocol number — single u8 padded to 4 bytes
    /// (`tcp` = 6, `udp` = 17, `icmp` = 1). Plan 198 §2.1.
    InetProto,
    /// Concatenated key — packs multiple component keys
    /// end-to-end with 4-byte alignment between. Common in
    /// rules like `ip saddr . tcp dport`. Plan 198 §2.1.
    /// Build elements with [`SetElement::concat`] and match with
    /// [`Rule::match_concat_in_set`].
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
            Self::ClassId => 23,      // TYPE_CLASSID
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

    /// Whether keys of this type are stored in host byte order (a mark, an
    /// ifindex), so their bytes do not compare as numbers. For a
    /// concatenation: whether any of its fields is.
    pub fn is_host_order(&self) -> bool {
        match self {
            Self::Mark | Self::IfIndex | Self::ClassId => true,
            Self::Concat(parts) => parts.iter().any(Self::is_host_order),
            _ => false,
        }
    }

    /// The fields of a concatenation of two or more keys; `None` for any
    /// other key type (a one-field `Concat` is that field).
    pub(crate) fn concat_fields(&self) -> Option<&[SetKeyType]> {
        match self {
            Self::Concat(parts) if parts.len() > 1 => Some(parts),
            _ => None,
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
            Self::ClassId => 4,
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

/// A packet field a rule can look up in a set, map or verdict map — with
/// the protocol guard `nft` puts in front of it, and the [`SetKeyType`] a
/// set must have to hold it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum PacketField {
    /// `ip saddr` (behind `meta nfproto ipv4`).
    Ip4Saddr,
    /// `ip daddr`.
    Ip4Daddr,
    /// `ip6 saddr` (behind `meta nfproto ipv6`).
    Ip6Saddr,
    /// `ip6 daddr`.
    Ip6Daddr,
    /// `tcp sport` (behind `meta l4proto tcp`).
    TcpSport,
    /// `tcp dport`.
    TcpDport,
    /// `udp sport` (behind `meta l4proto udp`).
    UdpSport,
    /// `udp dport`.
    UdpDport,
    /// `meta mark`.
    Mark,
    /// `meta iif` — an interface index, resolved in the rule's netns.
    Iif,
    /// `meta oif`.
    Oif,
    /// `meta l4proto`.
    L4Proto,
}

impl PacketField {
    /// The `meta` comparison `nft` guards this field with: `meta nfproto`
    /// for an address, `meta l4proto` for a port.
    fn guard(self) -> Option<(MetaKey, u8)> {
        match self {
            Self::Ip4Saddr | Self::Ip4Daddr => Some((MetaKey::NfProto, NFPROTO_IPV4)),
            Self::Ip6Saddr | Self::Ip6Daddr => Some((MetaKey::NfProto, NFPROTO_IPV6)),
            Self::TcpSport | Self::TcpDport => Some((MetaKey::L4Proto, IPPROTO_TCP)),
            Self::UdpSport | Self::UdpDport => Some((MetaKey::L4Proto, IPPROTO_UDP)),
            Self::Mark | Self::Iif | Self::Oif | Self::L4Proto => None,
        }
    }

    /// The expression loading this field into `dreg`.
    fn load(self, dreg: Register) -> Expr {
        let payload = |base, offset, len| Expr::Payload {
            dreg,
            base,
            offset,
            len,
        };
        let meta = |key| Expr::Meta { dreg, key };
        match self {
            Self::Ip4Saddr => payload(PayloadBase::Network, 12, 4),
            Self::Ip4Daddr => payload(PayloadBase::Network, 16, 4),
            Self::Ip6Saddr => payload(PayloadBase::Network, 8, 16),
            Self::Ip6Daddr => payload(PayloadBase::Network, 24, 16),
            Self::TcpSport | Self::UdpSport => payload(PayloadBase::Transport, 0, 2),
            Self::TcpDport | Self::UdpDport => payload(PayloadBase::Transport, 2, 2),
            Self::Mark => meta(MetaKey::Mark),
            Self::Iif => meta(MetaKey::Iif),
            Self::Oif => meta(MetaKey::Oif),
            Self::L4Proto => meta(MetaKey::L4Proto),
        }
    }

    /// The key type a set must have to hold this field.
    pub fn key_type(self) -> SetKeyType {
        match self {
            Self::Ip4Saddr | Self::Ip4Daddr => SetKeyType::Ipv4Addr,
            Self::Ip6Saddr | Self::Ip6Daddr => SetKeyType::Ipv6Addr,
            Self::TcpSport | Self::TcpDport | Self::UdpSport | Self::UdpDport => {
                SetKeyType::InetService
            }
            Self::Mark => SetKeyType::Mark,
            Self::Iif | Self::Oif => SetKeyType::IfIndex,
            Self::L4Proto => SetKeyType::InetProto,
        }
    }

    /// Bytes the field occupies in a register.
    #[allow(clippy::len_without_is_empty)]
    pub fn len(self) -> u32 {
        self.key_type().len()
    }
}

/// Set flags — `NFTA_SET_FLAGS`, the `NFT_SET_*` bits, in the shape of
/// [`CtState`] and [`TcpFlags`]. Combine with `|`.
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct SetFlags(pub u32);

impl SetFlags {
    pub const ANONYMOUS: Self = Self(super::NFT_SET_ANONYMOUS);
    pub const CONSTANT: Self = Self(super::NFT_SET_CONSTANT);
    pub const INTERVAL: Self = Self(super::NFT_SET_INTERVAL);
    pub const MAP: Self = Self(super::NFT_SET_MAP);
    pub const TIMEOUT: Self = Self(super::NFT_SET_TIMEOUT);
    pub const EVAL: Self = Self(super::NFT_SET_EVAL);
    pub const OBJECT: Self = Self(super::NFT_SET_OBJECT);
    pub const CONCAT: Self = Self(super::NFT_SET_CONCAT);
    pub const EXPR: Self = Self(super::NFT_SET_EXPR);

    /// No flags.
    pub const fn empty() -> Self {
        Self(0)
    }

    pub fn bits(self) -> u32 {
        self.0
    }

    /// Whether every bit of `other` is set.
    pub fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }
}

impl std::ops::BitOr for SetFlags {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

impl std::ops::BitOrAssign for SetFlags {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

/// What a map maps its keys to.
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SetDataType {
    /// A verdict: a verdict map (`vmap`), whose lookup decides the packet
    /// or jumps to a chain.
    Verdict,
    /// A value of this type: a mark, a class id, an address, …
    Value(SetKeyType),
    /// A named stateful object of this type: an object map, whose elements
    /// name counters, quotas or limits ([`SetElement::object`]).
    Object(super::object::ObjectType),
}

impl SetDataType {
    /// `NFTA_SET_DATA_TYPE`: `NFT_DATA_VERDICT` for a verdict map, else the
    /// value type's nft datatype id (the kernel stores it opaquely).
    /// An object map has no data type; it is `NFT_SET_OBJECT` with
    /// `NFTA_SET_OBJ_TYPE` instead.
    pub(crate) fn type_id(&self) -> Option<u32> {
        match self {
            Self::Verdict => Some(super::NFT_DATA_VERDICT),
            Self::Value(value) => Some(value.type_id()),
            Self::Object(_) => None,
        }
    }

    /// `NFTA_SET_DATA_LEN`, for a value map. The kernel sizes a verdict
    /// itself.
    pub(crate) fn len(&self) -> Option<u32> {
        match self {
            Self::Verdict | Self::Object(_) => None,
            Self::Value(value) => Some(value.len()),
        }
    }

    /// The flag that makes a set this kind of map.
    pub(crate) fn flag(&self) -> SetFlags {
        match self {
            Self::Object(_) => SetFlags::OBJECT,
            _ => SetFlags::MAP,
        }
    }
}

/// Set builder.
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[derive(Debug, Clone)]
#[must_use = "builders do nothing unless used"]
pub struct Set {
    pub(crate) table: String,
    pub(crate) name: String,
    pub(crate) family: Family,
    pub(crate) key_type: SetKeyType,
    pub(crate) flags: SetFlags,
    pub(crate) size: Option<u32>,
    pub(crate) timeout: Option<std::time::Duration>,
    pub(crate) gc_interval: Option<std::time::Duration>,
    pub(crate) data_type: Option<SetDataType>,
}

impl Set {
    /// Create a new named set.
    pub fn new(table: &str, name: &str) -> Self {
        Self {
            table: table.to_string(),
            name: name.to_string(),
            family: Family::Inet,
            key_type: SetKeyType::Ipv4Addr,
            flags: SetFlags::empty(),
            size: None,
            timeout: None,
            gc_interval: None,
            data_type: None,
        }
    }

    /// Make this a map (`NFT_SET_MAP`, or `NFT_SET_OBJECT` for an object
    /// map): each element maps its key to `data` — [`SetElement::value`],
    /// [`SetElement::verdict`] or [`SetElement::object`]. Read it with
    /// [`Rule::set_mark_from_map`], [`Rule::vmap`],
    /// [`Rule::objref_from_map`] and the like.
    pub fn map(mut self, data: SetDataType) -> Self {
        self.flags |= data.flag();
        self.data_type = Some(data);
        self
    }

    /// A verdict map (`vmap`): `map(SetDataType::Verdict)`.
    pub fn vmap(self) -> Self {
        self.map(SetDataType::Verdict)
    }

    /// Let rules add, refresh and delete elements from the packet path
    /// ([`DynsetExpr`](super::expr::DynsetExpr), `Rule::add_to_set` …):
    /// `NFT_SET_EVAL`, nft's `flags dynamic`. It selects the resizable
    /// hash backend, the one that supports updates — without it a sized
    /// set gets a fixed hash, and a rule updating it fails `EOPNOTSUPP`.
    pub fn dynamic(mut self) -> Self {
        self.flags |= SetFlags::EVAL;
        self
    }

    /// Give elements a default timeout (`timeout 60s`): an element expires
    /// this long after it was added, unless it carries its own. Sets
    /// `NFT_SET_TIMEOUT`. The kernel keeps it in jiffies, so it reads back
    /// rounded down to one; sub-millisecond parts are dropped.
    pub fn timeout(mut self, timeout: std::time::Duration) -> Self {
        self.flags |= SetFlags::TIMEOUT;
        self.timeout = Some(timeout);
        self
    }

    /// Let elements carry their own timeouts, without a default (`flags
    /// timeout`): `NFT_SET_TIMEOUT`.
    pub fn per_element_timeouts(mut self) -> Self {
        self.flags |= SetFlags::TIMEOUT;
        self
    }

    /// How often the kernel sweeps expired elements out (`gc-interval`).
    /// Expired elements stop matching and stop being listed at once; this
    /// only bounds the memory they hold. Sets `NFT_SET_TIMEOUT`, which the
    /// kernel requires with it.
    pub fn gc_interval(mut self, interval: std::time::Duration) -> Self {
        self.flags |= SetFlags::TIMEOUT;
        self.gc_interval = Some(interval);
        self
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
        self.flags |= SetFlags::CONSTANT;
        self
    }

    /// Make this an interval set (`NFT_SET_INTERVAL`), holding ranges and
    /// prefixes — ipset `hash:net`. Its key type must be one whose bytes
    /// compare as numbers: addresses, ports, protocols. A mark or ifindex
    /// key is host-order (`nft` byte-swaps it first), which nlink does not
    /// model, so their elements are refused.
    ///
    /// With a [`SetKeyType::Concat`] key every field is a range of its own
    /// — `10.0.0.0/24 . 1000-2000`, ipset `hash:net,port` — and the set is
    /// also flagged `NFT_SET_CONCAT` with its field lengths, which is what
    /// selects the kernel's `pipapo` backend.
    pub fn interval(mut self) -> Self {
        self.flags |= SetFlags::INTERVAL;
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

    /// Owning table.
    pub fn table(&self) -> &str {
        &self.table
    }

    /// Set name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Set the flags directly. Overwrites any previously set flags
    /// (including [`Self::constant`]); combine them with `|` if you need
    /// several.
    pub fn flags(mut self, flags: SetFlags) -> Self {
        self.flags = flags;
        self
    }

    /// The flags as written; see [`wire_flags`]. A set with a data type is
    /// a map, whatever its flags say.
    pub(crate) fn wire_flags(&self) -> SetFlags {
        let flags = wire_flags(&self.key_type, self.flags);
        match &self.data_type {
            Some(data) => flags | data.flag(),
            None => flags,
        }
    }

    /// See [`ranges_per_field`].
    pub(crate) fn ranges_per_field(&self) -> bool {
        ranges_per_field(&self.key_type, self.flags)
    }
}

/// Whether a set holds ranges as a start and an inclusive end in one
/// element (`NFTA_SET_ELEM_KEY_END`) — an interval set of concatenated keys
/// — rather than as a start and an end-plus-one element.
pub(crate) fn ranges_per_field(key_type: &SetKeyType, flags: SetFlags) -> bool {
    flags.contains(SetFlags::INTERVAL) && key_type.concat_fields().is_some()
}

/// A set's flags as written: an interval set of concatenated keys also
/// carries `NFT_SET_CONCAT`, which the kernel requires alongside the field
/// lengths, and reports back.
pub(crate) fn wire_flags(key_type: &SetKeyType, flags: SetFlags) -> SetFlags {
    if ranges_per_field(key_type, flags) {
        flags | SetFlags::CONCAT
    } else {
        flags
    }
}

/// A set element: a key, or a range of keys, with what goes with it.
///
/// The fields are private so an element can grow — a range end, map data,
/// a timeout — without a breaking change; build one with the constructors
/// and read it back with the accessors. How an element is written depends
/// on the set it goes into (an interval set stores a range as two wire
/// elements, for one), which is why the element operations take the
/// [`Set`] rather than its name.
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SetElement {
    key: Vec<u8>,
    /// Inclusive end of a range element.
    key_end: Option<Vec<u8>>,
    data: Option<SetElementData>,
    timeout: Option<std::time::Duration>,
    /// Time left before the element expires, as the kernel reports it.
    expiration: Option<std::time::Duration>,
    /// `NFTA_SET_ELEM_FLAGS` as read back (`NFT_SET_ELEM_*`).
    flags: u32,
}

/// What a map element maps its key to.
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SetElementData {
    /// A value, in the map's data type (`NFTA_DATA_VALUE`).
    Value(Vec<u8>),
    /// A verdict, in a verdict map (`NFTA_DATA_VERDICT`).
    Verdict(Verdict),
    /// The name of a stateful object, in an object map.
    Object(String),
}

impl SetElement {
    /// Create from raw key bytes, in the set's key layout.
    pub fn new(key: Vec<u8>) -> Self {
        Self {
            key,
            key_end: None,
            data: None,
            timeout: None,
            expiration: None,
            flags: 0,
        }
    }

    /// An IPv4 address element.
    pub fn ipv4(addr: Ipv4Addr) -> Self {
        Self::new(addr.octets().to_vec())
    }

    /// An IPv6 address element.
    pub fn ipv6(addr: std::net::Ipv6Addr) -> Self {
        Self::new(addr.octets().to_vec())
    }

    /// A port element (`inet_service`, network byte order).
    pub fn port(port: u16) -> Self {
        Self::new(port.to_be_bytes().to_vec())
    }

    /// A mark element (host byte order, like `meta mark`).
    pub fn mark(mark: u32) -> Self {
        Self::new(mark.to_ne_bytes().to_vec())
    }

    /// An interface-index element (host byte order, like `meta iif`).
    pub fn ifindex(ifindex: u32) -> Self {
        Self::new(ifindex.to_ne_bytes().to_vec())
    }

    /// An IP protocol element (`inet_proto`, e.g. 6 for TCP).
    pub fn inet_proto(proto: u8) -> Self {
        Self::new(vec![proto])
    }

    /// An Ethernet address element.
    pub fn ether(addr: [u8; 6]) -> Self {
        Self::new(addr.to_vec())
    }

    /// A range `[start, end]`, both inclusive, as raw keys in the set's key
    /// layout. Only an interval set ([`Set::interval`]) takes ranges.
    pub fn range(start: Vec<u8>, end_inclusive: Vec<u8>) -> Self {
        Self {
            key_end: Some(end_inclusive),
            ..Self::new(start)
        }
    }

    /// An IPv4 address range, inclusive.
    pub fn ipv4_range(start: Ipv4Addr, end: Ipv4Addr) -> Self {
        Self::range(start.octets().to_vec(), end.octets().to_vec())
    }

    /// An IPv6 address range, inclusive.
    pub fn ipv6_range(start: std::net::Ipv6Addr, end: std::net::Ipv6Addr) -> Self {
        Self::range(start.octets().to_vec(), end.octets().to_vec())
    }

    /// A port range, inclusive (`1000-2000`).
    pub fn port_range(start: u16, end: u16) -> Self {
        Self::range(start.to_be_bytes().to_vec(), end.to_be_bytes().to_vec())
    }

    /// An IPv4 prefix (`10.0.0.0/8`) as the range it covers. Host bits in
    /// `addr` are masked off, as `nft` does; a prefix length over 32 is an
    /// error.
    pub fn ipv4_prefix(addr: Ipv4Addr, prefix: u8) -> Result<Self> {
        let (start, end) = prefix_range(&addr.octets(), prefix)?;
        Ok(Self::range(start, end))
    }

    /// An IPv6 prefix (`2001:db8::/32`) as the range it covers. Host bits
    /// are masked off; a prefix length over 128 is an error.
    pub fn ipv6_prefix(addr: std::net::Ipv6Addr, prefix: u8) -> Result<Self> {
        let (start, end) = prefix_range(&addr.octets(), prefix)?;
        Ok(Self::range(start, end))
    }

    /// An element of a set of concatenated keys ([`SetKeyType::Concat`]):
    /// one element per field, in the key's order — `10.0.0.1 . 443` is
    /// `concat([SetElement::ipv4(a), SetElement::port(443)])`. Each field is
    /// padded to 4 bytes, as the kernel lays the fields out in registers.
    ///
    /// In an interval set ([`Set::interval`]) a field can be a range or a
    /// prefix of its own: `concat([SetElement::ipv4_prefix(net, 24)?,
    /// SetElement::port_range(1000, 2000)])` is `10.0.0.0/24 . 1000-2000`.
    /// Only the parts' keys and range ends are used.
    pub fn concat(parts: impl IntoIterator<Item = SetElement>) -> Self {
        let parts: Vec<SetElement> = parts.into_iter().collect();
        let padded = |bytes: &[u8]| {
            let mut field = bytes.to_vec();
            field.resize(bytes.len().next_multiple_of(4), 0);
            field
        };
        let key: Vec<u8> = parts.iter().flat_map(|p| padded(&p.key)).collect();
        let key_end: Vec<u8> = parts
            .iter()
            .flat_map(|p| padded(p.key_end.as_deref().unwrap_or(&p.key)))
            .collect();
        // Ranges that are each one value make a single key.
        Self {
            key_end: (key_end != key).then_some(key_end),
            ..Self::new(key)
        }
    }

    /// The key bytes (the range start, for a range).
    pub fn key(&self) -> &[u8] {
        &self.key
    }

    /// The inclusive end of a range element.
    pub fn key_end(&self) -> Option<&[u8]> {
        self.key_end.as_deref()
    }

    /// Whether this element is a range.
    pub fn is_range(&self) -> bool {
        self.key_end.is_some()
    }

    /// Map this element's key to a value, in a map of values
    /// ([`Set::map`]): built like a key — `SetElement::ipv4(a)
    /// .value(SetElement::mark(0x10))`. Only the value's key bytes are used.
    pub fn value(mut self, value: SetElement) -> Self {
        self.data = Some(SetElementData::Value(value.key));
        self
    }

    /// Map this element's key to a verdict, in a verdict map
    /// ([`Set::vmap`]): `SetElement::port(22).verdict(Verdict::Accept)`.
    pub fn verdict(mut self, verdict: Verdict) -> Self {
        self.data = Some(SetElementData::Verdict(verdict));
        self
    }

    /// Map this element's key to the stateful object `name`, in an object
    /// map: `SetElement::ipv4(a).object("web")`.
    pub fn object(mut self, name: &str) -> Self {
        self.data = Some(SetElementData::Object(name.to_string()));
        self
    }

    /// A class id element (`meta priority`), as [`Rule::set_priority`]
    /// writes it: host order.
    pub fn classid(class: crate::TcHandle) -> Self {
        Self::new(u32::from(class).to_ne_bytes().to_vec())
    }

    /// Give this element its own timeout. The set needs timeouts
    /// ([`Set::timeout`] or [`Set::per_element_timeouts`]).
    ///
    /// The declarative diff does not compare it: a declared element that is
    /// present is left to run out its time, and added again once it has
    /// expired.
    pub fn with_timeout(mut self, timeout: std::time::Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// The data a map element maps to.
    pub fn data(&self) -> Option<&SetElementData> {
        self.data.as_ref()
    }

    /// The element's own timeout, if it has one. Read back from the kernel,
    /// only a timeout that differs from the set's default is reported.
    pub fn timeout(&self) -> Option<std::time::Duration> {
        self.timeout
    }

    /// Time left before the element expires, as read back from the kernel.
    pub fn expiration(&self) -> Option<std::time::Duration> {
        self.expiration
    }

    /// Whether this is a raw interval-end marker (`NFT_SET_ELEM_INTERVAL_END`),
    /// as an element event reports it.
    pub fn is_interval_end(&self) -> bool {
        self.flags & super::NFT_SET_ELEM_INTERVAL_END != 0
    }

    /// Whether this is the catch-all element (`NFT_SET_ELEM_CATCHALL`).
    pub fn is_catchall(&self) -> bool {
        self.flags & super::NFT_SET_ELEM_CATCHALL != 0
    }

    /// What the declarative diff compares: the key, the range end and
    /// catch-all-ness — never live state such as the expiration. A range
    /// `[k, k]` is the key `k`: that is how it is written, and read back.
    pub(crate) fn identity(&self) -> (&[u8], Option<&[u8]>, bool) {
        let end = self.key_end.as_deref().filter(|end| *end != self.key);
        (&self.key, end, self.is_catchall())
    }

    /// Validate this element against the set it is written to. Only what
    /// the writer can encode passes; anything else is an error rather
    /// than something silently dropped.
    /// A `deleting` element is named by its key alone: what it maps to and
    /// its timeout are not checked, and not sent.
    pub(crate) fn check_for(&self, set: &Set, deleting: bool) -> Result<()> {
        let want = set.key_type.len() as usize;
        if self.key.len() != want {
            return Err(Error::InvalidMessage(format!(
                "set {}: element key is {} bytes, but key type {:?} is {want}",
                set.name,
                self.key.len(),
                set.key_type,
            )));
        }
        if let Some(end) = &self.key_end {
            if !set.flags.contains(SetFlags::INTERVAL) {
                return Err(Error::InvalidMessage(format!(
                    "set {}: a range element needs an interval set (`Set::interval`)",
                    set.name
                )));
            }
            // A concatenation is a range per field, so each field's end
            // must be at or after its start; the key as a whole proves
            // nothing (`10.0.0.9 . 100` to `10.0.0.10 . 50` sorts fine).
            let widths: Vec<usize> = match set.key_type.concat_fields() {
                Some(fields) => fields.iter().map(|f| f.len().next_multiple_of(4) as usize).collect(),
                None => vec![self.key.len()],
            };
            let mut at = 0;
            for width in widths {
                let field = at..at + width;
                at += width;
                if end.len() != self.key.len() || end[field.clone()] < self.key[field] {
                    return Err(Error::InvalidMessage(format!(
                        "set {}: range end {end:02x?} is not at or after its start {:02x?}",
                        set.name, self.key
                    )));
                }
            }
        }
        if deleting {
            return Ok(());
        }
        match (&set.data_type, &self.data) {
            (None, None) => {}
            (None, Some(_)) => {
                return Err(Error::InvalidMessage(format!(
                    "set {}: element data needs a map (`Set::map`)",
                    set.name
                )));
            }
            (Some(_), None) => {
                return Err(Error::InvalidMessage(format!(
                    "set {}: an element of a map needs data (`SetElement::value` or `::verdict`)",
                    set.name
                )));
            }
            (Some(SetDataType::Verdict), Some(SetElementData::Verdict(_)))
            | (Some(SetDataType::Object(_)), Some(SetElementData::Object(_))) => {}
            (Some(SetDataType::Value(ty)), Some(SetElementData::Value(value)))
                if value.len() == ty.len() as usize => {}
            (Some(want), Some(got)) => {
                return Err(Error::InvalidMessage(format!(
                    "set {}: element data {got:?} does not fit the map's {want:?}",
                    set.name
                )));
            }
        }
        if self.timeout.is_some() && !set.flags.contains(SetFlags::TIMEOUT) {
            return Err(Error::InvalidMessage(format!(
                "set {}: an element timeout needs a set with timeouts \
                 (`Set::timeout` or `Set::per_element_timeouts`)",
                set.name
            )));
        }
        Ok(())
    }

    /// An element as read back from the kernel.
    pub(crate) fn from_wire(key: Vec<u8>, flags: u32) -> Self {
        Self {
            flags,
            ..Self::new(key)
        }
    }

    /// This start element as a range ending at `end` (inclusive).
    pub(crate) fn ending_at(mut self, end: Vec<u8>) -> Self {
        self.key_end = Some(end);
        self
    }

    /// With the map data read back.
    pub(crate) fn with_data(mut self, data: Option<SetElementData>) -> Self {
        self.data = data;
        self
    }

    /// With the timeout and time left read back.
    pub(crate) fn with_timers(
        mut self,
        timeout: Option<std::time::Duration>,
        expiration: Option<std::time::Duration>,
    ) -> Self {
        self.timeout = timeout;
        self.expiration = expiration;
        self
    }

    /// With the range end read back (`NFTA_SET_ELEM_KEY_END`). An end equal
    /// to the key is a single key — what `nft` writes for one — so it reads
    /// back as one.
    pub(crate) fn with_key_end(mut self, key_end: Option<Vec<u8>>) -> Self {
        self.key_end = key_end.filter(|end| *end != self.key);
        self
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
    pub flags: SetFlags,
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
    /// Default element timeout (`NFTA_SET_TIMEOUT`), if the set has one —
    /// in whole jiffies, so possibly a little under what was written.
    pub timeout: Option<std::time::Duration>,
    /// Garbage-collection interval (`NFTA_SET_GC_INTERVAL`), if set.
    pub gc_interval: Option<std::time::Duration>,
    /// A map's data type (`NFTA_SET_DATA_TYPE`): `NFT_DATA_VERDICT` for a
    /// verdict map, else an nft datatype id.
    pub data_type: Option<u32>,
    /// A map's data length in bytes (`NFTA_SET_DATA_LEN`).
    pub data_len: Option<u32>,
    /// An object map's object type (`NFTA_SET_OBJ_TYPE`, `NFT_OBJECT_*`).
    pub object_type: Option<u32>,
}

/// The inclusive range a prefix covers: `addr` with its host bits cleared,
/// and with them set.
fn prefix_range(addr: &[u8], prefix: u8) -> Result<(Vec<u8>, Vec<u8>)> {
    let bits = addr.len() * 8;
    if usize::from(prefix) > bits {
        return Err(Error::InvalidMessage(format!(
            "prefix length {prefix} is longer than the {bits}-bit address"
        )));
    }
    let mask = prefix_to_mask(addr.len(), prefix);
    let start = addr.iter().zip(&mask).map(|(a, m)| a & m).collect();
    let end = addr.iter().zip(&mask).map(|(a, m)| a | !m).collect();
    Ok((start, end))
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

    // -------- Registers and concatenations --------

    #[test]
    fn a_word_that_starts_a_16_byte_register_is_written_as_that_register() {
        assert_eq!(Register::Reg32_00.wire(), 1); // NFT_REG_1
        assert_eq!(Register::Reg32_04.wire(), 2); // NFT_REG_2
        assert_eq!(Register::Reg32_01.wire(), 9); // NFT_REG32_01
        assert_eq!(Register::word(0), Some(Register::R0));
        assert_eq!(Register::word(1), Some(Register::Reg32_01));
        assert_eq!(Register::word(4), Some(Register::R1));
        assert_eq!(Register::word(15), Some(Register::Reg32_15));
        assert_eq!(Register::word(16), None);
        for v in 8..=23 {
            assert_eq!(Register::from_u32(v).map(|r| r as u32), Some(v));
        }
        assert_eq!(Register::from_u32(5), None);
        assert_eq!(Register::from_u32(24), None);
    }

    #[test]
    fn concatenated_elements_pad_each_field_to_a_register_word() {
        let e = SetElement::concat([
            SetElement::ipv4(Ipv4Addr::new(10, 0, 0, 1)),
            SetElement::port(443),
        ]);
        assert_eq!(e.key(), [10, 0, 0, 1, 0x01, 0xbb, 0, 0]);
        assert!(!e.is_range());
        // One ranged field makes the element a range; the single field's
        // end is its key.
        let e = SetElement::concat([
            SetElement::ipv4(Ipv4Addr::new(10, 0, 0, 1)),
            SetElement::port_range(80, 90),
        ]);
        assert_eq!(e.key(), [10, 0, 0, 1, 0, 80, 0, 0]);
        assert_eq!(e.key_end(), Some(&[10, 0, 0, 1, 0, 90, 0, 0][..]));
        // Ranges of one value each are a single key.
        let e = SetElement::concat([
            SetElement::ipv4_range(Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 1)),
            SetElement::port_range(80, 80),
        ]);
        assert!(!e.is_range());
        assert_eq!(
            SetElement::range(vec![1], vec![1]).identity(),
            SetElement::new(vec![1]).identity()
        );
        // A MAC is 6 bytes, padded to 8 in a concatenation.
        let e = SetElement::concat([SetElement::ether([1, 2, 3, 4, 5, 6]), SetElement::inet_proto(6)]);
        assert_eq!(e.key(), [1, 2, 3, 4, 5, 6, 0, 0, 6, 0, 0, 0]);
        let key = SetKeyType::Concat(vec![SetKeyType::EtherAddr, SetKeyType::InetProto]);
        assert_eq!(e.key().len(), key.len() as usize);
    }

    #[test]
    fn map_lookups_load_into_the_verdict_or_a_data_register() {
        use super::super::expr::LookupExpr;
        let vmap = Rule::new("t", "c").vmap(PacketField::TcpDport, "vm");
        let last = format!("{:?}", vmap.exprs.last().unwrap());
        let want = LookupExpr::new("vm", Register::R0).dreg(Register::Verdict);
        assert_eq!(last, format!("{:?}", Expr::from(want)));

        let mark = Rule::new("t", "c").set_mark_from_map(PacketField::Ip4Saddr, "m");
        let tail: Vec<String> = mark.exprs[mark.exprs.len() - 2..]
            .iter()
            .map(|e| format!("{e:?}"))
            .collect();
        let lookup = LookupExpr::new("m", Register::R0).dreg(Register::R0);
        let set = Expr::MetaSet {
            key: MetaKey::Mark,
            sreg: Register::R0,
        };
        assert_eq!(tail, [format!("{:?}", Expr::from(lookup)), format!("{set:?}")]);
    }

    #[test]
    fn a_concat_lookup_guards_first_then_loads_word_by_word() {
        use super::super::expr::{Expr, LookupExpr};
        let rule = Rule::new("t", "c").match_concat_in_set(
            &[PacketField::Ip6Saddr, PacketField::TcpDport, PacketField::TcpSport],
            "s",
        );
        let guard = |key, value| {
            [
                Expr::Meta {
                    dreg: Register::R0,
                    key,
                },
                Expr::Cmp {
                    sreg: Register::R0,
                    op: CmpOp::Eq,
                    data: vec![value],
                },
            ]
        };
        let load = |dreg, base, offset, len| Expr::Payload {
            dreg,
            base,
            offset,
            len,
        };
        let mut want: Vec<Expr> = Vec::new();
        want.extend(guard(MetaKey::NfProto, NFPROTO_IPV6));
        // One l4proto guard for both TCP ports.
        want.extend(guard(MetaKey::L4Proto, IPPROTO_TCP));
        // 16 bytes in words 0-3, then a port in word 4 (`R1`, as the kernel
        // dumps it) and one in word 5.
        want.push(load(Register::R0, PayloadBase::Network, 8, 16));
        want.push(load(Register::R1, PayloadBase::Transport, 2, 2));
        want.push(load(Register::Reg32_05, PayloadBase::Transport, 0, 2));
        want.push(LookupExpr::new("s", Register::R0).into());
        // `Expr` has no `PartialEq`; its `Debug` form names every field.
        assert_eq!(format!("{:?}", rule.exprs), format!("{want:?}"));
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
