//! Netfilter implementation for `Connection<Netfilter>`.
//!
//! This module provides methods for querying and managing connection tracking
//! entries via the NETLINK_NETFILTER protocol.
//!
//! # Example
//!
//! ```ignore
//! use nlink::netlink::{Connection, Netfilter};
//!
//! let conn = Connection::<Netfilter>::new()?;
//!
//! // List all connection tracking entries
//! let entries = conn.get_conntrack().await?;
//! for entry in &entries {
//!     println!("{:?} {}:{} -> {}:{}",
//!         entry.proto,
//!         entry.orig.src_ip,
//!         entry.orig.src_port.unwrap_or(0),
//!         entry.orig.dst_ip,
//!         entry.orig.dst_port.unwrap_or(0));
//! }
//! ```

use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    time::Duration,
};

use winnow::{binary::be_u16, prelude::*};

use super::{
    builder::MessageBuilder,
    connection::Connection,
    error::Result,
    message::{NLM_F_ACK, NLM_F_CREATE, NLM_F_EXCL, NLM_F_REPLACE, NLM_F_REQUEST as NLMF_REQUEST},
    parse::PResult,
    protocol::Netfilter,
};

// Netlink constants
const NLMSG_DONE: u16 = 3;
const NLMSG_ERROR: u16 = 2;
const NLM_F_REQUEST: u16 = 0x01;
const NLM_F_DUMP: u16 = 0x300;

// Netfilter subsystem IDs
const NFNL_SUBSYS_CTNETLINK: u8 = 1;

// Conntrack message types
const IPCTNL_MSG_CT_NEW: u8 = 0;
const IPCTNL_MSG_CT_GET: u8 = 1;
const IPCTNL_MSG_CT_DELETE: u8 = 2;

// Conntrack attributes
const CTA_TUPLE_ORIG: u16 = 1;
const CTA_TUPLE_REPLY: u16 = 2;
const CTA_STATUS: u16 = 3;
const CTA_PROTOINFO: u16 = 4;
const CTA_TIMEOUT: u16 = 7;
const CTA_MARK: u16 = 8;
const CTA_COUNTERS_ORIG: u16 = 9;
const CTA_COUNTERS_REPLY: u16 = 10;
const CTA_ID: u16 = 12;
const CTA_ZONE: u16 = 18;

// Tuple attributes
const CTA_TUPLE_IP: u16 = 1;
const CTA_TUPLE_PROTO: u16 = 2;

// IP attributes
const CTA_IP_V4_SRC: u16 = 1;
const CTA_IP_V4_DST: u16 = 2;
const CTA_IP_V6_SRC: u16 = 3;
const CTA_IP_V6_DST: u16 = 4;

// Proto attributes
const CTA_PROTO_NUM: u16 = 1;
const CTA_PROTO_SRC_PORT: u16 = 2;
const CTA_PROTO_DST_PORT: u16 = 3;
const CTA_PROTO_ICMP_ID: u16 = 4;
const CTA_PROTO_ICMP_TYPE: u16 = 5;
const CTA_PROTO_ICMP_CODE: u16 = 6;

// Protoinfo attributes
const CTA_PROTOINFO_TCP: u16 = 1;
const CTA_PROTOINFO_TCP_STATE: u16 = 1;

// Counter attributes
const CTA_COUNTERS_PACKETS: u16 = 1;
const CTA_COUNTERS_BYTES: u16 = 2;

// Netlink header size
const NLMSG_HDRLEN: usize = 16;

/// IP protocol numbers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum IpProtocol {
    /// TCP (6)
    Tcp,
    /// UDP (17)
    Udp,
    /// ICMP (1)
    Icmp,
    /// ICMPv6 (58)
    Icmpv6,
    /// Other protocol
    Other(u8),
}

impl IpProtocol {
    fn from_u8(val: u8) -> Self {
        match val {
            1 => Self::Icmp,
            6 => Self::Tcp,
            17 => Self::Udp,
            58 => Self::Icmpv6,
            other => Self::Other(other),
        }
    }

    /// Get the protocol number.
    pub fn number(&self) -> u8 {
        match self {
            Self::Icmp => 1,
            Self::Tcp => 6,
            Self::Udp => 17,
            Self::Icmpv6 => 58,
            Self::Other(n) => *n,
        }
    }
}

/// TCP connection tracking state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum TcpConntrackState {
    None,
    SynSent,
    SynRecv,
    Established,
    FinWait,
    CloseWait,
    LastAck,
    TimeWait,
    Close,
    Listen,
    SynSent2,
    Max,
    Ignore,
    Retrans,
    Unack,
    Unknown(u8),
}

impl TcpConntrackState {
    fn from_u8(val: u8) -> Self {
        match val {
            0 => Self::None,
            1 => Self::SynSent,
            2 => Self::SynRecv,
            3 => Self::Established,
            4 => Self::FinWait,
            5 => Self::CloseWait,
            6 => Self::LastAck,
            7 => Self::TimeWait,
            8 => Self::Close,
            9 => Self::Listen,
            10 => Self::SynSent2,
            11 => Self::Max,
            12 => Self::Ignore,
            13 => Self::Retrans,
            14 => Self::Unack,
            other => Self::Unknown(other),
        }
    }
}

/// A connection tracking tuple (source/destination).
#[derive(Debug, Clone, Default)]
pub struct ConntrackTuple {
    /// Source IP address.
    pub src_ip: Option<IpAddr>,
    /// Destination IP address.
    pub dst_ip: Option<IpAddr>,
    /// Source port (TCP/UDP).
    pub src_port: Option<u16>,
    /// Destination port (TCP/UDP).
    pub dst_port: Option<u16>,
    /// ICMP ID.
    pub icmp_id: Option<u16>,
    /// ICMP type.
    pub icmp_type: Option<u8>,
    /// ICMP code.
    pub icmp_code: Option<u8>,
}

impl ConntrackTuple {
    /// IPv4 tuple with source + destination addresses (no L4 ports yet).
    pub fn v4(src: Ipv4Addr, dst: Ipv4Addr) -> Self {
        Self {
            src_ip: Some(IpAddr::V4(src)),
            dst_ip: Some(IpAddr::V4(dst)),
            ..Default::default()
        }
    }

    /// IPv6 tuple with source + destination addresses (no L4 ports yet).
    pub fn v6(src: Ipv6Addr, dst: Ipv6Addr) -> Self {
        Self {
            src_ip: Some(IpAddr::V6(src)),
            dst_ip: Some(IpAddr::V6(dst)),
            ..Default::default()
        }
    }

    /// Set TCP/UDP source + destination ports.
    pub fn ports(mut self, src: u16, dst: u16) -> Self {
        self.src_port = Some(src);
        self.dst_port = Some(dst);
        self
    }

    /// Set ICMP type / code / id (for ICMP / ICMPv6 tuples).
    pub fn icmp(mut self, icmp_type: u8, code: u8, id: u16) -> Self {
        self.icmp_type = Some(icmp_type);
        self.icmp_code = Some(code);
        self.icmp_id = Some(id);
        self
    }

    /// Return the mirrored tuple — src/dst swapped, ports swapped. Useful
    /// for synthesising the reply tuple of a NAT-less injection.
    pub fn mirror(&self) -> Self {
        Self {
            src_ip: self.dst_ip,
            dst_ip: self.src_ip,
            src_port: self.dst_port,
            dst_port: self.src_port,
            icmp_id: self.icmp_id,
            icmp_type: self.icmp_type,
            icmp_code: self.icmp_code,
        }
    }
}

/// Connection-tracking status flags. Mirrors the kernel's
/// `enum ip_conntrack_status` (IPS_*).
///
/// At least `CONFIRMED` is required for `add_conntrack` — the kernel
/// rejects unconfirmed entries on the netlink path with `-EINVAL`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ConntrackStatus(u32);

impl ConntrackStatus {
    pub const EXPECTED: Self = Self(0x0001);
    pub const SEEN_REPLY: Self = Self(0x0002);
    pub const ASSURED: Self = Self(0x0004);
    pub const CONFIRMED: Self = Self(0x0008);
    pub const SRC_NAT: Self = Self(0x0010);
    pub const DST_NAT: Self = Self(0x0020);
    pub const SEQ_ADJUST: Self = Self(0x0040);
    pub const SRC_NAT_DONE: Self = Self(0x0080);
    pub const DST_NAT_DONE: Self = Self(0x0100);
    pub const DYING: Self = Self(0x0200);
    pub const FIXED_TIMEOUT: Self = Self(0x0400);
    pub const TEMPLATE: Self = Self(0x0800);
    pub const NAT_CLASH: Self = Self(0x1000);
    pub const HELPER: Self = Self(0x2000);
    pub const OFFLOAD: Self = Self(0x4000);
    pub const HW_OFFLOAD: Self = Self(0x8000);

    pub const fn empty() -> Self {
        Self(0)
    }
    pub const fn bits(self) -> u32 {
        self.0
    }
    pub const fn from_bits(bits: u32) -> Self {
        Self(bits)
    }
    pub const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }
}

impl std::ops::BitOr for ConntrackStatus {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

impl std::ops::BitOrAssign for ConntrackStatus {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

impl TcpConntrackState {
    /// Encode as the wire byte the kernel expects in
    /// `CTA_PROTOINFO_TCP_STATE`.
    fn to_u8(self) -> u8 {
        match self {
            Self::None => 0,
            Self::SynSent => 1,
            Self::SynRecv => 2,
            Self::Established => 3,
            Self::FinWait => 4,
            Self::CloseWait => 5,
            Self::LastAck => 6,
            Self::TimeWait => 7,
            Self::Close => 8,
            Self::Listen => 9,
            Self::SynSent2 => 10,
            Self::Max => 11,
            Self::Ignore => 12,
            Self::Retrans => 13,
            Self::Unack => 14,
            Self::Unknown(v) => v,
        }
    }
}

/// Packet/byte counters.
#[derive(Debug, Clone, Default)]
pub struct ConntrackCounters {
    /// Number of packets.
    pub packets: u64,
    /// Number of bytes.
    pub bytes: u64,
}

/// A connection tracking entry.
#[derive(Debug, Clone)]
pub struct ConntrackEntry {
    /// IP protocol (TCP, UDP, ICMP, etc.).
    pub proto: IpProtocol,
    /// Original direction tuple.
    pub orig: ConntrackTuple,
    /// Reply direction tuple.
    pub reply: ConntrackTuple,
    /// TCP connection state (if TCP).
    pub tcp_state: Option<TcpConntrackState>,
    /// Timeout in seconds.
    pub timeout: Option<u32>,
    /// Connection mark.
    pub mark: Option<u32>,
    /// Connection status flags.
    pub status: Option<u32>,
    /// Connection ID.
    pub id: Option<u32>,
    /// Original direction counters.
    pub counters_orig: Option<ConntrackCounters>,
    /// Reply direction counters.
    pub counters_reply: Option<ConntrackCounters>,
}

impl Default for ConntrackEntry {
    fn default() -> Self {
        Self {
            proto: IpProtocol::Other(0),
            orig: ConntrackTuple::default(),
            reply: ConntrackTuple::default(),
            tcp_state: None,
            timeout: None,
            mark: None,
            status: None,
            id: None,
            counters_orig: None,
            counters_reply: None,
        }
    }
}

/// Builder for a conntrack entry — used by `add_conntrack`,
/// `update_conntrack`, and `del_conntrack`.
///
/// Address family is fixed at construction (`new_v4` / `new_v6`); the
/// builder validates that any IP supplied matches that family.
///
/// For `add_conntrack` the kernel requires a non-empty `orig` tuple
/// with src + dst + proto fields, plus `status(ConntrackStatus::CONFIRMED)`
/// — without it the kernel will reject the message with `-EINVAL`.
/// `del_conntrack` only needs enough of the tuple to identify the entry
/// (or use `del_conntrack_by_id`).
#[derive(Debug, Clone)]
#[must_use = "builders do nothing unless submitted to the connection"]
pub struct ConntrackBuilder {
    family: u8,
    proto: IpProtocol,
    orig: ConntrackTuple,
    reply: Option<ConntrackTuple>,
    status: Option<ConntrackStatus>,
    timeout: Option<Duration>,
    mark: Option<u32>,
    tcp_state: Option<TcpConntrackState>,
    id: Option<u32>,
    zone: Option<u16>,
}

impl ConntrackBuilder {
    /// IPv4 conntrack entry for the given L4 protocol.
    pub fn new_v4(proto: IpProtocol) -> Self {
        Self {
            family: libc::AF_INET as u8,
            proto,
            orig: ConntrackTuple::default(),
            reply: None,
            status: None,
            timeout: None,
            mark: None,
            tcp_state: None,
            id: None,
            zone: None,
        }
    }

    /// IPv6 conntrack entry for the given L4 protocol.
    pub fn new_v6(proto: IpProtocol) -> Self {
        Self {
            family: libc::AF_INET6 as u8,
            proto,
            ..Self::new_v4(proto)
        }
    }

    /// The address family of this entry (`AF_INET` / `AF_INET6`).
    pub fn family(&self) -> u8 {
        self.family
    }

    /// Set the original-direction tuple (client → server).
    pub fn orig(mut self, tuple: ConntrackTuple) -> Self {
        self.orig = tuple;
        self
    }

    /// Set the reply-direction tuple. If omitted, `add_conntrack`
    /// auto-mirrors `orig` (which is correct for symmetric flows
    /// without NAT).
    pub fn reply(mut self, tuple: ConntrackTuple) -> Self {
        self.reply = Some(tuple);
        self
    }

    /// Set the status flag bitmask. `ConntrackStatus::CONFIRMED` is the
    /// minimum the kernel accepts; for an entry the firewall should
    /// short-circuit, also include `SEEN_REPLY`.
    pub fn status(mut self, s: ConntrackStatus) -> Self {
        self.status = Some(s);
        self
    }

    /// Set the entry timeout.
    ///
    /// **Required for TCP injections that also set
    /// [`tcp_state`](Self::tcp_state).** The kernel's TCP state machine
    /// won't accept an entry without a timeout — `add_conntrack`
    /// returns `Error::InvalidArgument` (EINVAL). For UDP / ICMP it's
    /// optional but recommended (kernel defaults are protocol-specific
    /// and surprisingly long, e.g. 30 s for unreplied UDP).
    pub fn timeout(mut self, d: Duration) -> Self {
        self.timeout = Some(d);
        self
    }

    /// Set the connection mark.
    pub fn mark(mut self, mark: u32) -> Self {
        self.mark = Some(mark);
        self
    }

    /// Set the TCP state (encoded under `CTA_PROTOINFO/CTA_PROTOINFO_TCP`).
    /// Only meaningful when `proto = IpProtocol::Tcp`.
    ///
    /// **Pair with [`timeout`](Self::timeout)** — the kernel rejects a
    /// TCP add that has `tcp_state` set but no timeout (EINVAL). The
    /// state machine needs the timeout for its bookkeeping.
    pub fn tcp_state(mut self, state: TcpConntrackState) -> Self {
        self.tcp_state = Some(state);
        self
    }

    /// Set the conntrack ID. Used by `del_conntrack` when identifying
    /// by ID rather than tuple.
    pub fn id(mut self, id: u32) -> Self {
        self.id = Some(id);
        self
    }

    /// Set the conntrack zone (default 0).
    pub fn zone(mut self, zone: u16) -> Self {
        self.zone = Some(zone);
        self
    }

    /// Emit this entry's attributes into a request `MessageBuilder`
    /// after the nfgenmsg header has been appended.
    ///
    /// `for_delete = true` skips fields the kernel ignores on
    /// `IPCTNL_MSG_CT_DELETE` (status / timeout / protoinfo / mark).
    /// `mirror_reply = true` synthesises a reply tuple from `orig` if
    /// the builder has none — handy for `add_conntrack` of symmetric
    /// flows without explicit NAT.
    fn append_attrs(&self, b: &mut MessageBuilder, for_delete: bool, mirror_reply: bool) {
        if !self.orig.is_empty() {
            append_tuple(b, CTA_TUPLE_ORIG, self.proto, &self.orig);
        }

        let mirrored;
        let reply: Option<&ConntrackTuple> = match (&self.reply, mirror_reply) {
            (Some(r), _) => Some(r),
            (None, true) if !self.orig.is_empty() => {
                mirrored = self.orig.mirror();
                Some(&mirrored)
            }
            _ => None,
        };
        if let Some(r) = reply {
            append_tuple(b, CTA_TUPLE_REPLY, self.proto, r);
        }

        if for_delete {
            // For DELETE, only the tuple (or ID) and zone matter.
            if let Some(z) = self.zone {
                b.append_attr_u16_be(CTA_ZONE, z);
            }
            if let Some(id) = self.id {
                b.append_attr_u32_be(CTA_ID, id);
            }
            return;
        }

        if let Some(s) = self.status {
            b.append_attr_u32_be(CTA_STATUS, s.bits());
        }
        if let Some(t) = self.timeout {
            b.append_attr_u32_be(CTA_TIMEOUT, t.as_secs() as u32);
        }
        if let Some(m) = self.mark {
            b.append_attr_u32_be(CTA_MARK, m);
        }
        if let Some(state) = self.tcp_state
            && self.proto == IpProtocol::Tcp
        {
            let outer = b.nest_start(CTA_PROTOINFO);
            let tcp = b.nest_start(CTA_PROTOINFO_TCP);
            b.append_attr_u8(CTA_PROTOINFO_TCP_STATE, state.to_u8());
            b.nest_end(tcp);
            b.nest_end(outer);
        }
        if let Some(z) = self.zone {
            b.append_attr_u16_be(CTA_ZONE, z);
        }
        if let Some(id) = self.id {
            b.append_attr_u32_be(CTA_ID, id);
        }
    }
}

impl ConntrackTuple {
    /// True iff every Option field is `None` — used to detect a
    /// builder that hasn't had its `orig` set.
    fn is_empty(&self) -> bool {
        self.src_ip.is_none()
            && self.dst_ip.is_none()
            && self.src_port.is_none()
            && self.dst_port.is_none()
            && self.icmp_id.is_none()
            && self.icmp_type.is_none()
            && self.icmp_code.is_none()
    }
}

/// Append the 4-byte nfgenmsg header onto a request builder.
fn append_nfgenmsg(b: &mut MessageBuilder, family: u8) {
    b.append_bytes(&[family, 0, 0, 0]); // family, version=NFNETLINK_V0, res_id=0
}

/// Append a `CTA_TUPLE_*` nested attribute (one of `CTA_TUPLE_ORIG` /
/// `CTA_TUPLE_REPLY`). Emits IP and proto sub-trees from `tuple`.
fn append_tuple(b: &mut MessageBuilder, attr_type: u16, proto: IpProtocol, tuple: &ConntrackTuple) {
    let outer = b.nest_start(attr_type);

    // IP sub-tree
    let ip = b.nest_start(CTA_TUPLE_IP);
    if let Some(IpAddr::V4(addr)) = tuple.src_ip {
        b.append_attr(CTA_IP_V4_SRC, &addr.octets());
    }
    if let Some(IpAddr::V4(addr)) = tuple.dst_ip {
        b.append_attr(CTA_IP_V4_DST, &addr.octets());
    }
    if let Some(IpAddr::V6(addr)) = tuple.src_ip {
        b.append_attr(CTA_IP_V6_SRC, &addr.octets());
    }
    if let Some(IpAddr::V6(addr)) = tuple.dst_ip {
        b.append_attr(CTA_IP_V6_DST, &addr.octets());
    }
    b.nest_end(ip);

    // PROTO sub-tree
    let p = b.nest_start(CTA_TUPLE_PROTO);
    b.append_attr_u8(CTA_PROTO_NUM, proto.number());
    if let Some(port) = tuple.src_port {
        b.append_attr_u16_be(CTA_PROTO_SRC_PORT, port);
    }
    if let Some(port) = tuple.dst_port {
        b.append_attr_u16_be(CTA_PROTO_DST_PORT, port);
    }
    if let Some(id) = tuple.icmp_id {
        b.append_attr_u16_be(CTA_PROTO_ICMP_ID, id);
    }
    if let Some(t) = tuple.icmp_type {
        b.append_attr_u8(CTA_PROTO_ICMP_TYPE, t);
    }
    if let Some(c) = tuple.icmp_code {
        b.append_attr_u8(CTA_PROTO_ICMP_CODE, c);
    }
    b.nest_end(p);

    b.nest_end(outer);
}

/// Build the netlink message-type word for a ctnetlink op.
const fn ctnl_msg_type(msg: u8) -> u16 {
    ((NFNL_SUBSYS_CTNETLINK as u16) << 8) | (msg as u16)
}

/// nfgenmsg header (4 bytes).
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
struct NfGenMsg {
    family: u8,
    version: u8,
    res_id: u16,
}

impl NfGenMsg {
    fn parse(input: &mut &[u8]) -> PResult<Self> {
        let family = winnow::binary::le_u8.parse_next(input)?;
        let version = winnow::binary::le_u8.parse_next(input)?;
        let res_id = be_u16.parse_next(input)?;
        Ok(Self {
            family,
            version,
            res_id,
        })
    }
}

impl Connection<Netfilter> {
    /// Get all connection tracking entries.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use nlink::netlink::{Connection, Netfilter};
    ///
    /// let conn = Connection::<Netfilter>::new()?;
    /// let entries = conn.get_conntrack().await?;
    ///
    /// for entry in &entries {
    ///     println!("{:?}: {:?} -> {:?}",
    ///         entry.proto,
    ///         entry.orig.src_ip,
    ///         entry.orig.dst_ip);
    /// }
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_conntrack"))]
    pub async fn get_conntrack(&self) -> Result<Vec<ConntrackEntry>> {
        self.get_conntrack_family(libc::AF_INET as u8).await
    }

    /// Get connection tracking entries for IPv6.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_conntrack_v6"))]
    pub async fn get_conntrack_v6(&self) -> Result<Vec<ConntrackEntry>> {
        self.get_conntrack_family(libc::AF_INET6 as u8).await
    }

    /// Inject a new conntrack entry.
    ///
    /// The kernel requires `status(ConntrackStatus::CONFIRMED)` plus a
    /// non-empty `orig` tuple — the call returns `Error::InvalidArgument`
    /// from the kernel otherwise. If `reply` is unset, the original
    /// tuple is mirrored automatically (correct for symmetric flows
    /// without NAT).
    ///
    /// # Errors
    /// - `EINVAL` — missing `CONFIRMED` status, missing tuple fields,
    ///   or proto/family mismatch.
    /// - `EEXIST` — an entry with that tuple already exists.
    /// - `ENOENT` — `nf_conntrack_netlink` module not loaded.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "add_conntrack"))]
    pub async fn add_conntrack(&self, entry: ConntrackBuilder) -> Result<()> {
        let mut b = MessageBuilder::new(
            ctnl_msg_type(IPCTNL_MSG_CT_NEW),
            NLMF_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
        );
        append_nfgenmsg(&mut b, entry.family);
        entry.append_attrs(&mut b, false, true);
        self.send_ack(b).await
    }

    /// Replace an existing conntrack entry — same wire shape as
    /// `add_conntrack` but with `NLM_F_CREATE | NLM_F_REPLACE`, so the
    /// kernel updates a matching entry in place. Useful for nudging
    /// timeout / mark / TCP state without a delete-then-add.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "update_conntrack"))]
    pub async fn update_conntrack(&self, entry: ConntrackBuilder) -> Result<()> {
        let mut b = MessageBuilder::new(
            ctnl_msg_type(IPCTNL_MSG_CT_NEW),
            NLMF_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE,
        );
        append_nfgenmsg(&mut b, entry.family);
        entry.append_attrs(&mut b, false, false);
        self.send_ack(b).await
    }

    /// Delete a conntrack entry identified by tuple.
    ///
    /// The orig tuple plus `family` are enough; reply / status / mark
    /// are ignored by the kernel for delete.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "del_conntrack"))]
    pub async fn del_conntrack(&self, entry: ConntrackBuilder) -> Result<()> {
        let mut b = MessageBuilder::new(
            ctnl_msg_type(IPCTNL_MSG_CT_DELETE),
            NLMF_REQUEST | NLM_F_ACK,
        );
        append_nfgenmsg(&mut b, entry.family);
        entry.append_attrs(&mut b, true, false);
        self.send_ack(b).await
    }

    /// Delete a conntrack entry by its kernel-assigned ID (the
    /// `id` field on a [`ConntrackEntry`] returned from
    /// [`Self::get_conntrack`]).
    #[tracing::instrument(level = "debug", skip_all, fields(method = "del_conntrack_by_id"))]
    pub async fn del_conntrack_by_id(&self, id: u32) -> Result<()> {
        let mut b = MessageBuilder::new(
            ctnl_msg_type(IPCTNL_MSG_CT_DELETE),
            NLMF_REQUEST | NLM_F_ACK,
        );
        append_nfgenmsg(&mut b, libc::AF_UNSPEC as u8);
        b.append_attr_u32_be(CTA_ID, id);
        self.send_ack(b).await
    }

    /// Flush every IPv4 conntrack entry. Equivalent to
    /// `conntrack -F` for the v4 table.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "flush_conntrack"))]
    pub async fn flush_conntrack(&self) -> Result<()> {
        self.flush_conntrack_family(libc::AF_INET as u8).await
    }

    /// Flush every IPv6 conntrack entry.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "flush_conntrack_v6"))]
    pub async fn flush_conntrack_v6(&self) -> Result<()> {
        self.flush_conntrack_family(libc::AF_INET6 as u8).await
    }

    async fn flush_conntrack_family(&self, family: u8) -> Result<()> {
        let mut b = MessageBuilder::new(
            ctnl_msg_type(IPCTNL_MSG_CT_DELETE),
            NLMF_REQUEST | NLM_F_ACK,
        );
        append_nfgenmsg(&mut b, family);
        self.send_ack(b).await
    }

    /// Get connection tracking entries for a specific address family.
    async fn get_conntrack_family(&self, family: u8) -> Result<Vec<ConntrackEntry>> {
        let seq = self.socket().next_seq();
        let pid = self.socket().pid();

        // Build request
        let mut buf = Vec::with_capacity(64);

        // Netlink header (16 bytes)
        // Message type: (NFNL_SUBSYS_CTNETLINK << 8) | IPCTNL_MSG_CT_GET
        let msg_type = ((NFNL_SUBSYS_CTNETLINK as u16) << 8) | (IPCTNL_MSG_CT_GET as u16);

        buf.extend_from_slice(&0u32.to_ne_bytes()); // nlmsg_len (fill later)
        buf.extend_from_slice(&msg_type.to_ne_bytes()); // nlmsg_type
        buf.extend_from_slice(&(NLM_F_REQUEST | NLM_F_DUMP).to_ne_bytes()); // nlmsg_flags
        buf.extend_from_slice(&seq.to_ne_bytes()); // nlmsg_seq
        buf.extend_from_slice(&pid.to_ne_bytes()); // nlmsg_pid

        // nfgenmsg (4 bytes)
        buf.push(family); // nfgen_family
        buf.push(0); // version (NFNETLINK_V0)
        buf.extend_from_slice(&0u16.to_be_bytes()); // res_id

        // Update length
        let len = buf.len() as u32;
        buf[0..4].copy_from_slice(&len.to_ne_bytes());

        // Send request
        self.socket().send(&buf).await?;

        // Receive responses
        let mut entries = Vec::new();

        loop {
            let data = self.socket().recv_msg().await?;

            let mut offset = 0;
            while offset + 16 <= data.len() {
                let nlmsg_len = u32::from_ne_bytes([
                    data[offset],
                    data[offset + 1],
                    data[offset + 2],
                    data[offset + 3],
                ]) as usize;

                let nlmsg_type = u16::from_ne_bytes([data[offset + 4], data[offset + 5]]);

                if nlmsg_len < 16 || offset + nlmsg_len > data.len() {
                    break;
                }

                match nlmsg_type {
                    NLMSG_DONE => return Ok(entries),
                    NLMSG_ERROR => {
                        if nlmsg_len >= 20 {
                            let errno = i32::from_ne_bytes([
                                data[offset + 16],
                                data[offset + 17],
                                data[offset + 18],
                                data[offset + 19],
                            ]);
                            if errno != 0 {
                                return Err(super::error::Error::from_errno(-errno));
                            }
                        }
                    }
                    _ => {
                        // Check if it's a conntrack message
                        let subsys = (nlmsg_type >> 8) as u8;
                        if subsys == NFNL_SUBSYS_CTNETLINK
                            && let Some(entry) =
                                self.parse_conntrack(&data[offset..offset + nlmsg_len])
                        {
                            entries.push(entry);
                        }
                    }
                }

                // Align to 4 bytes
                offset += (nlmsg_len + 3) & !3;
            }
        }
    }

    /// Parse a conntrack message using winnow.
    fn parse_conntrack(&self, data: &[u8]) -> Option<ConntrackEntry> {
        // Skip netlink header (16 bytes)
        if data.len() < NLMSG_HDRLEN + 4 {
            return None;
        }

        let mut input = &data[NLMSG_HDRLEN..];

        // Parse nfgenmsg header
        let _nfmsg = NfGenMsg::parse(&mut input).ok()?;

        // Parse attributes
        let mut entry = ConntrackEntry::default();

        while input.len() >= 4 {
            let (attr_type, attr_data) = parse_nla(&mut input)?;

            match attr_type & 0x7FFF {
                // Remove NLA_F_NESTED flag
                CTA_TUPLE_ORIG => {
                    if let Some((tuple, proto)) = parse_tuple(attr_data) {
                        entry.orig = tuple;
                        entry.proto = proto;
                    }
                }
                CTA_TUPLE_REPLY => {
                    if let Some((tuple, _)) = parse_tuple(attr_data) {
                        entry.reply = tuple;
                    }
                }
                CTA_STATUS if attr_data.len() >= 4 => {
                    entry.status = Some(u32::from_be_bytes([
                        attr_data[0],
                        attr_data[1],
                        attr_data[2],
                        attr_data[3],
                    ]));
                }
                CTA_TIMEOUT if attr_data.len() >= 4 => {
                    entry.timeout = Some(u32::from_be_bytes([
                        attr_data[0],
                        attr_data[1],
                        attr_data[2],
                        attr_data[3],
                    ]));
                }
                CTA_MARK if attr_data.len() >= 4 => {
                    entry.mark = Some(u32::from_be_bytes([
                        attr_data[0],
                        attr_data[1],
                        attr_data[2],
                        attr_data[3],
                    ]));
                }
                CTA_ID if attr_data.len() >= 4 => {
                    entry.id = Some(u32::from_be_bytes([
                        attr_data[0],
                        attr_data[1],
                        attr_data[2],
                        attr_data[3],
                    ]));
                }
                CTA_PROTOINFO => {
                    entry.tcp_state = parse_protoinfo(attr_data);
                }
                CTA_COUNTERS_ORIG => {
                    entry.counters_orig = parse_counters(attr_data);
                }
                CTA_COUNTERS_REPLY => {
                    entry.counters_reply = parse_counters(attr_data);
                }
                _ => {}
            }
        }

        Some(entry)
    }
}

/// Parse a netlink attribute.
fn parse_nla<'a>(input: &mut &'a [u8]) -> Option<(u16, &'a [u8])> {
    if input.len() < 4 {
        return None;
    }

    // Parse length and type from first 4 bytes
    let len = u16::from_le_bytes([input[0], input[1]]) as usize;
    let attr_type = u16::from_le_bytes([input[2], input[3]]);
    *input = &input[4..];

    if len < 4 {
        return None;
    }

    let payload_len = len.saturating_sub(4);
    if input.len() < payload_len {
        return None;
    }

    let payload = &input[..payload_len];
    *input = &input[payload_len..];

    // Align to 4 bytes
    let aligned = (len + 3) & !3;
    let padding = aligned.saturating_sub(len);
    if input.len() >= padding {
        *input = &input[padding..];
    }

    Some((attr_type, payload))
}

/// Parse a conntrack tuple.
fn parse_tuple(data: &[u8]) -> Option<(ConntrackTuple, IpProtocol)> {
    let mut input = data;
    let mut tuple = ConntrackTuple::default();
    let mut proto = IpProtocol::Other(0);

    while input.len() >= 4 {
        let (attr_type, attr_data) = parse_nla(&mut input)?;

        match attr_type & 0x7FFF {
            CTA_TUPLE_IP => {
                parse_tuple_ip(attr_data, &mut tuple);
            }
            CTA_TUPLE_PROTO => {
                proto = parse_tuple_proto(attr_data, &mut tuple);
            }
            _ => {}
        }
    }

    Some((tuple, proto))
}

/// Parse IP addresses from tuple.
fn parse_tuple_ip(data: &[u8], tuple: &mut ConntrackTuple) {
    let mut input = data;

    while input.len() >= 4 {
        if let Some((attr_type, attr_data)) = parse_nla(&mut input) {
            match attr_type {
                CTA_IP_V4_SRC if attr_data.len() >= 4 => {
                    tuple.src_ip = Some(IpAddr::V4(Ipv4Addr::new(
                        attr_data[0],
                        attr_data[1],
                        attr_data[2],
                        attr_data[3],
                    )));
                }
                CTA_IP_V4_DST if attr_data.len() >= 4 => {
                    tuple.dst_ip = Some(IpAddr::V4(Ipv4Addr::new(
                        attr_data[0],
                        attr_data[1],
                        attr_data[2],
                        attr_data[3],
                    )));
                }
                CTA_IP_V6_SRC if attr_data.len() >= 16 => {
                    let mut octets = [0u8; 16];
                    octets.copy_from_slice(&attr_data[..16]);
                    tuple.src_ip = Some(IpAddr::V6(Ipv6Addr::from(octets)));
                }
                CTA_IP_V6_DST if attr_data.len() >= 16 => {
                    let mut octets = [0u8; 16];
                    octets.copy_from_slice(&attr_data[..16]);
                    tuple.dst_ip = Some(IpAddr::V6(Ipv6Addr::from(octets)));
                }
                _ => {}
            }
        } else {
            break;
        }
    }
}

/// Parse protocol info from tuple.
fn parse_tuple_proto(data: &[u8], tuple: &mut ConntrackTuple) -> IpProtocol {
    let mut input = data;
    let mut proto = IpProtocol::Other(0);

    while input.len() >= 4 {
        if let Some((attr_type, attr_data)) = parse_nla(&mut input) {
            match attr_type {
                CTA_PROTO_NUM if !attr_data.is_empty() => {
                    proto = IpProtocol::from_u8(attr_data[0]);
                }
                CTA_PROTO_SRC_PORT if attr_data.len() >= 2 => {
                    tuple.src_port = Some(u16::from_be_bytes([attr_data[0], attr_data[1]]));
                }
                CTA_PROTO_DST_PORT if attr_data.len() >= 2 => {
                    tuple.dst_port = Some(u16::from_be_bytes([attr_data[0], attr_data[1]]));
                }
                CTA_PROTO_ICMP_ID if attr_data.len() >= 2 => {
                    tuple.icmp_id = Some(u16::from_be_bytes([attr_data[0], attr_data[1]]));
                }
                CTA_PROTO_ICMP_TYPE if !attr_data.is_empty() => {
                    tuple.icmp_type = Some(attr_data[0]);
                }
                CTA_PROTO_ICMP_CODE if !attr_data.is_empty() => {
                    tuple.icmp_code = Some(attr_data[0]);
                }
                _ => {}
            }
        } else {
            break;
        }
    }

    proto
}

/// Parse protoinfo for TCP state.
fn parse_protoinfo(data: &[u8]) -> Option<TcpConntrackState> {
    let mut input = data;

    while input.len() >= 4 {
        let (attr_type, attr_data) = parse_nla(&mut input)?;

        if (attr_type & 0x7FFF) == CTA_PROTOINFO_TCP {
            // Parse TCP protoinfo
            let mut tcp_input = attr_data;
            while tcp_input.len() >= 4 {
                if let Some((tcp_attr, tcp_data)) = parse_nla(&mut tcp_input) {
                    if tcp_attr == CTA_PROTOINFO_TCP_STATE && !tcp_data.is_empty() {
                        return Some(TcpConntrackState::from_u8(tcp_data[0]));
                    }
                } else {
                    break;
                }
            }
        }
    }

    None
}

/// Parse counters.
fn parse_counters(data: &[u8]) -> Option<ConntrackCounters> {
    let mut input = data;
    let mut counters = ConntrackCounters::default();

    while input.len() >= 4 {
        if let Some((attr_type, attr_data)) = parse_nla(&mut input) {
            match attr_type {
                CTA_COUNTERS_PACKETS if attr_data.len() >= 8 => {
                    counters.packets = u64::from_be_bytes([
                        attr_data[0],
                        attr_data[1],
                        attr_data[2],
                        attr_data[3],
                        attr_data[4],
                        attr_data[5],
                        attr_data[6],
                        attr_data[7],
                    ]);
                }
                CTA_COUNTERS_BYTES if attr_data.len() >= 8 => {
                    counters.bytes = u64::from_be_bytes([
                        attr_data[0],
                        attr_data[1],
                        attr_data[2],
                        attr_data[3],
                        attr_data[4],
                        attr_data[5],
                        attr_data[6],
                        attr_data[7],
                    ]);
                }
                _ => {}
            }
        } else {
            break;
        }
    }

    Some(counters)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::netlink::message::NlMsgHdr;

    #[test]
    fn ip_protocol_roundtrip() {
        assert_eq!(IpProtocol::Tcp.number(), 6);
        assert_eq!(IpProtocol::from_u8(6), IpProtocol::Tcp);

        assert_eq!(IpProtocol::Udp.number(), 17);
        assert_eq!(IpProtocol::from_u8(17), IpProtocol::Udp);
    }

    #[test]
    fn tcp_state_from_u8() {
        assert_eq!(
            TcpConntrackState::from_u8(3),
            TcpConntrackState::Established
        );
        assert_eq!(TcpConntrackState::from_u8(7), TcpConntrackState::TimeWait);
    }

    #[test]
    fn tcp_state_roundtrip() {
        for s in [
            TcpConntrackState::SynSent,
            TcpConntrackState::Established,
            TcpConntrackState::TimeWait,
            TcpConntrackState::Close,
            TcpConntrackState::Unknown(99),
        ] {
            assert_eq!(TcpConntrackState::from_u8(s.to_u8()), s);
        }
    }

    #[test]
    fn status_flags_bitor() {
        let s = ConntrackStatus::CONFIRMED | ConntrackStatus::SEEN_REPLY;
        assert!(s.contains(ConntrackStatus::CONFIRMED));
        assert!(s.contains(ConntrackStatus::SEEN_REPLY));
        assert!(!s.contains(ConntrackStatus::ASSURED));
        assert_eq!(s.bits(), 0x000A);
    }

    #[test]
    fn tuple_mirror_swaps_src_dst() {
        let orig = ConntrackTuple::v4(Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 2))
            .ports(1234, 80);
        let r = orig.mirror();
        assert_eq!(r.src_ip, Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))));
        assert_eq!(r.dst_ip, Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
        assert_eq!(r.src_port, Some(80));
        assert_eq!(r.dst_port, Some(1234));
    }

    /// Parse a conntrack mutation request the same way the kernel
    /// would: skip nlmsghdr + nfgenmsg, run the existing dump-side
    /// parser. Returns the round-tripped `ConntrackEntry`.
    fn roundtrip(buf: &[u8]) -> ConntrackEntry {
        let hdr = NlMsgHdr::from_bytes(buf).expect("nlmsghdr");
        // Body: after nlmsghdr, then nfgenmsg (4 bytes).
        let body = &buf[16..hdr.nlmsg_len as usize];
        let mut input = body;
        let _ = NfGenMsg::parse(&mut input).expect("nfgenmsg");
        let mut entry = ConntrackEntry::default();
        while input.len() >= 4 {
            let Some((attr_type, attr_data)) = parse_nla(&mut input) else {
                break;
            };
            match attr_type & 0x7FFF {
                CTA_TUPLE_ORIG => {
                    if let Some((t, p)) = parse_tuple(attr_data) {
                        entry.orig = t;
                        entry.proto = p;
                    }
                }
                CTA_TUPLE_REPLY => {
                    if let Some((t, _)) = parse_tuple(attr_data) {
                        entry.reply = t;
                    }
                }
                CTA_STATUS if attr_data.len() >= 4 => {
                    entry.status = Some(u32::from_be_bytes(attr_data[..4].try_into().unwrap()));
                }
                CTA_TIMEOUT if attr_data.len() >= 4 => {
                    entry.timeout = Some(u32::from_be_bytes(attr_data[..4].try_into().unwrap()));
                }
                CTA_MARK if attr_data.len() >= 4 => {
                    entry.mark = Some(u32::from_be_bytes(attr_data[..4].try_into().unwrap()));
                }
                CTA_ID if attr_data.len() >= 4 => {
                    entry.id = Some(u32::from_be_bytes(attr_data[..4].try_into().unwrap()));
                }
                CTA_PROTOINFO => {
                    entry.tcp_state = parse_protoinfo(attr_data);
                }
                _ => {}
            }
        }
        entry
    }

    #[test]
    fn add_conntrack_v4_tcp_wire_roundtrip() {
        let mut b = MessageBuilder::new(
            ctnl_msg_type(IPCTNL_MSG_CT_NEW),
            NLMF_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
        );
        append_nfgenmsg(&mut b, libc::AF_INET as u8);
        ConntrackBuilder::new_v4(IpProtocol::Tcp)
            .orig(
                ConntrackTuple::v4(Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 2))
                    .ports(40000, 80),
            )
            .status(ConntrackStatus::CONFIRMED | ConntrackStatus::SEEN_REPLY)
            .timeout(Duration::from_secs(120))
            .mark(0x42)
            .tcp_state(TcpConntrackState::Established)
            .append_attrs(&mut b, false, true);
        let buf = b.finish();

        let entry = roundtrip(&buf);
        assert_eq!(entry.proto, IpProtocol::Tcp);
        assert_eq!(
            entry.orig.src_ip,
            Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)))
        );
        assert_eq!(
            entry.orig.dst_ip,
            Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)))
        );
        assert_eq!(entry.orig.src_port, Some(40000));
        assert_eq!(entry.orig.dst_port, Some(80));
        // Reply tuple was auto-mirrored.
        assert_eq!(
            entry.reply.src_ip,
            Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)))
        );
        assert_eq!(
            entry.reply.dst_ip,
            Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)))
        );
        assert_eq!(entry.reply.src_port, Some(80));
        assert_eq!(entry.reply.dst_port, Some(40000));
        assert_eq!(entry.status, Some(0x000A));
        assert_eq!(entry.timeout, Some(120));
        assert_eq!(entry.mark, Some(0x42));
        assert_eq!(entry.tcp_state, Some(TcpConntrackState::Established));
    }

    #[test]
    fn add_conntrack_v6_udp_wire_roundtrip() {
        let mut b = MessageBuilder::new(
            ctnl_msg_type(IPCTNL_MSG_CT_NEW),
            NLMF_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
        );
        append_nfgenmsg(&mut b, libc::AF_INET6 as u8);
        let src: Ipv6Addr = "fe80::1".parse().unwrap();
        let dst: Ipv6Addr = "fe80::2".parse().unwrap();
        ConntrackBuilder::new_v6(IpProtocol::Udp)
            .orig(ConntrackTuple::v6(src, dst).ports(5000, 5001))
            .status(ConntrackStatus::CONFIRMED)
            .append_attrs(&mut b, false, true);
        let buf = b.finish();

        let entry = roundtrip(&buf);
        assert_eq!(entry.proto, IpProtocol::Udp);
        assert_eq!(entry.orig.src_ip, Some(IpAddr::V6(src)));
        assert_eq!(entry.orig.dst_ip, Some(IpAddr::V6(dst)));
        assert_eq!(entry.orig.src_port, Some(5000));
        assert_eq!(entry.orig.dst_port, Some(5001));
        assert_eq!(entry.reply.src_ip, Some(IpAddr::V6(dst)));
        assert_eq!(entry.reply.dst_ip, Some(IpAddr::V6(src)));
    }

    #[test]
    fn del_conntrack_skips_status_and_timeout() {
        let mut b = MessageBuilder::new(
            ctnl_msg_type(IPCTNL_MSG_CT_DELETE),
            NLMF_REQUEST | NLM_F_ACK,
        );
        append_nfgenmsg(&mut b, libc::AF_INET as u8);
        ConntrackBuilder::new_v4(IpProtocol::Tcp)
            .orig(
                ConntrackTuple::v4(Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 2))
                    .ports(40000, 80),
            )
            // These should be elided on the delete path.
            .status(ConntrackStatus::CONFIRMED)
            .timeout(Duration::from_secs(120))
            .mark(0x42)
            .id(0xdead_beef)
            .append_attrs(&mut b, true, false);
        let buf = b.finish();

        let entry = roundtrip(&buf);
        assert_eq!(entry.status, None);
        assert_eq!(entry.timeout, None);
        assert_eq!(entry.mark, None);
        assert_eq!(entry.id, Some(0xdead_beef));
    }

    #[test]
    fn ctnl_msg_type_layout() {
        // Subsystem in high byte, message type in low byte.
        assert_eq!(ctnl_msg_type(IPCTNL_MSG_CT_NEW), 0x0100);
        assert_eq!(ctnl_msg_type(IPCTNL_MSG_CT_GET), 0x0101);
        assert_eq!(ctnl_msg_type(IPCTNL_MSG_CT_DELETE), 0x0102);
    }
}
