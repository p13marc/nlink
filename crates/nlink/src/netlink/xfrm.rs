//! XFRM implementation for `Connection<Xfrm>`.
//!
//! This module provides methods for querying and managing IPsec Security
//! Associations (SAs) and Security Policies (SPs) via the NETLINK_XFRM protocol.
//!
//! # Example
//!
//! ```ignore
//! use nlink::netlink::{Connection, Xfrm};
//!
//! let conn = Connection::<Xfrm>::new()?;
//!
//! // List all Security Associations
//! let sas = conn.get_security_associations().await?;
//! for sa in &sas {
//!     println!("{:?} -> {:?} SPI={:08x}",
//!         sa.src_addr, sa.dst_addr, sa.spi);
//! }
//!
//! // List all Security Policies
//! let policies = conn.get_security_policies().await?;
//! for pol in &policies {
//!     println!("{:?} dir={:?} action={:?}",
//!         pol.selector, pol.direction, pol.action);
//! }
//! ```

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

use super::connection::Connection;
use super::error::Result;
use super::protocol::{ProtocolState, Xfrm};
use super::socket::NetlinkSocket;

// Netlink constants
const NLMSG_DONE: u16 = 3;
const NLMSG_ERROR: u16 = 2;
const NLM_F_REQUEST: u16 = 0x01;
const NLM_F_DUMP: u16 = 0x300;

// XFRM message types (from linux/xfrm.h)
const XFRM_MSG_GETSA: u16 = 0x12;
const XFRM_MSG_GETPOLICY: u16 = 0x15;

// XFRM attribute types
const XFRMA_ALG_AUTH: u16 = 1;
const XFRMA_ALG_CRYPT: u16 = 2;
const XFRMA_ALG_COMP: u16 = 3;
const XFRMA_ENCAP: u16 = 4;
const XFRMA_ALG_AEAD: u16 = 18;
const XFRMA_ALG_AUTH_TRUNC: u16 = 20;
const XFRMA_MARK: u16 = 21;
const XFRMA_IF_ID: u16 = 31;

// XFRM modes
const XFRM_MODE_TRANSPORT: u8 = 0;
const XFRM_MODE_TUNNEL: u8 = 1;
const XFRM_MODE_BEET: u8 = 4;

// XFRM protocols
const IPPROTO_ESP: u8 = 50;
const IPPROTO_AH: u8 = 51;
const IPPROTO_COMP: u8 = 108;

// Policy directions
const XFRM_POLICY_IN: u8 = 0;
const XFRM_POLICY_OUT: u8 = 1;
const XFRM_POLICY_FWD: u8 = 2;

// Policy actions
const XFRM_POLICY_ALLOW: u8 = 0;
const XFRM_POLICY_BLOCK: u8 = 1;

// Netlink header size
const NLMSG_HDRLEN: usize = 16;

/// XFRM address (16 bytes, can hold IPv4 or IPv6).
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct XfrmAddress {
    /// Raw address bytes (4 bytes for IPv4, 16 for IPv6).
    pub bytes: [u8; 16],
}

impl XfrmAddress {
    /// Create from an IPv4 address.
    pub fn from_v4(addr: Ipv4Addr) -> Self {
        let mut bytes = [0u8; 16];
        bytes[..4].copy_from_slice(&addr.octets());
        Self { bytes }
    }

    /// Create from an IPv6 address.
    pub fn from_v6(addr: Ipv6Addr) -> Self {
        Self {
            bytes: addr.octets(),
        }
    }

    /// Convert to an IP address based on the address family.
    pub fn to_ip(&self, family: u16) -> Option<IpAddr> {
        match family {
            2 => {
                // AF_INET
                Some(IpAddr::V4(Ipv4Addr::new(
                    self.bytes[0],
                    self.bytes[1],
                    self.bytes[2],
                    self.bytes[3],
                )))
            }
            10 => {
                // AF_INET6
                Some(IpAddr::V6(Ipv6Addr::from(self.bytes)))
            }
            _ => None,
        }
    }
}

/// XFRM ID (identifies an SA by destination, SPI, and protocol).
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct XfrmId {
    /// Destination address.
    pub daddr: XfrmAddress,
    /// Security Parameter Index (network byte order).
    pub spi: u32,
    /// IPsec protocol (ESP, AH, COMP).
    pub proto: u8,
    /// Padding.
    pub _pad: [u8; 3],
}

/// XFRM selector (traffic selector for policies/SAs).
#[repr(C, packed)]
#[derive(Debug, Clone, Copy, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct XfrmSelector {
    /// Destination address.
    pub daddr: XfrmAddress,
    /// Source address.
    pub saddr: XfrmAddress,
    /// Destination port (network byte order).
    pub dport: u16,
    /// Destination port mask.
    pub dport_mask: u16,
    /// Source port (network byte order).
    pub sport: u16,
    /// Source port mask.
    pub sport_mask: u16,
    /// Address family.
    pub family: u16,
    /// Destination prefix length.
    pub prefixlen_d: u8,
    /// Source prefix length.
    pub prefixlen_s: u8,
    /// IP protocol.
    pub proto: u8,
    /// Padding to align ifindex to 4 bytes.
    pub _pad1: [u8; 3],
    /// Interface index.
    pub ifindex: i32,
    /// User ID.
    pub user: u32,
}

/// XFRM lifetime configuration.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct XfrmLifetimeCfg {
    /// Soft byte limit.
    pub soft_byte_limit: u64,
    /// Hard byte limit.
    pub hard_byte_limit: u64,
    /// Soft packet limit.
    pub soft_packet_limit: u64,
    /// Hard packet limit.
    pub hard_packet_limit: u64,
    /// Soft add expiry (seconds).
    pub soft_add_expires_seconds: u64,
    /// Hard add expiry (seconds).
    pub hard_add_expires_seconds: u64,
    /// Soft use expiry (seconds).
    pub soft_use_expires_seconds: u64,
    /// Hard use expiry (seconds).
    pub hard_use_expires_seconds: u64,
}

/// XFRM lifetime current values.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct XfrmLifetimeCur {
    /// Bytes processed.
    pub bytes: u64,
    /// Packets processed.
    pub packets: u64,
    /// Time added.
    pub add_time: u64,
    /// Time last used.
    pub use_time: u64,
}

/// XFRM statistics.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct XfrmStats {
    /// Replay window.
    pub replay_window: u32,
    /// Replay count.
    pub replay: u32,
    /// Integrity check failures.
    pub integrity_failed: u32,
}

/// XFRM usersa_info (main SA structure).
#[repr(C, packed)]
#[derive(Debug, Clone, Copy, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct XfrmUsersaInfo {
    /// Traffic selector.
    pub sel: XfrmSelector,
    /// SA identifier.
    pub id: XfrmId,
    /// Source address.
    pub saddr: XfrmAddress,
    /// Lifetime configuration.
    pub lft: XfrmLifetimeCfg,
    /// Current lifetime values.
    pub curlft: XfrmLifetimeCur,
    /// Statistics.
    pub stats: XfrmStats,
    /// Sequence number.
    pub seq: u32,
    /// Request ID.
    pub reqid: u32,
    /// Address family.
    pub family: u16,
    /// Mode (transport/tunnel/beet).
    pub mode: u8,
    /// Replay window size.
    pub replay_window: u8,
    /// Flags.
    pub flags: u8,
    /// Padding to align to 8 bytes.
    pub _pad: [u8; 7],
}

/// XFRM userpolicy_info (main policy structure).
#[repr(C, packed)]
#[derive(Debug, Clone, Copy, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct XfrmUserpolicyInfo {
    /// Traffic selector.
    pub sel: XfrmSelector,
    /// Lifetime configuration.
    pub lft: XfrmLifetimeCfg,
    /// Current lifetime values.
    pub curlft: XfrmLifetimeCur,
    /// Priority.
    pub priority: u32,
    /// Policy index.
    pub index: u32,
    /// Direction (in/out/fwd).
    pub dir: u8,
    /// Action (allow/block).
    pub action: u8,
    /// Flags.
    pub flags: u8,
    /// Share mode.
    pub share: u8,
}

/// XFRM algorithm.
#[derive(Debug, Clone)]
pub struct XfrmAlgorithm {
    /// Algorithm name.
    pub name: String,
    /// Key length in bits.
    pub key_len: u32,
    /// Key data.
    pub key: Vec<u8>,
}

/// XFRM AEAD algorithm.
#[derive(Debug, Clone)]
pub struct XfrmAlgorithmAead {
    /// Algorithm name.
    pub name: String,
    /// Key length in bits.
    pub key_len: u32,
    /// ICV length in bits.
    pub icv_len: u32,
    /// Key data.
    pub key: Vec<u8>,
}

/// XFRM authentication algorithm with truncation.
#[derive(Debug, Clone)]
pub struct XfrmAlgorithmAuthTrunc {
    /// Algorithm name.
    pub name: String,
    /// Key length in bits.
    pub key_len: u32,
    /// Truncation length in bits.
    pub trunc_len: u32,
    /// Key data.
    pub key: Vec<u8>,
}

/// XFRM encapsulation template.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct XfrmEncapTmpl {
    /// Encapsulation type.
    pub encap_type: u16,
    /// Source port (network byte order).
    pub encap_sport: u16,
    /// Destination port (network byte order).
    pub encap_dport: u16,
    /// Padding.
    pub _pad: u16,
    /// Original address.
    pub encap_oa: XfrmAddress,
}

/// XFRM mark.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct XfrmMark {
    /// Mark value.
    pub v: u32,
    /// Mark mask.
    pub m: u32,
}

/// IPsec protocol type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpsecProtocol {
    /// Encapsulating Security Payload.
    Esp,
    /// Authentication Header.
    Ah,
    /// IP Compression.
    Comp,
    /// Other protocol.
    Other(u8),
}

impl IpsecProtocol {
    fn from_u8(val: u8) -> Self {
        match val {
            IPPROTO_ESP => Self::Esp,
            IPPROTO_AH => Self::Ah,
            IPPROTO_COMP => Self::Comp,
            other => Self::Other(other),
        }
    }

    /// Get the protocol number.
    pub fn number(&self) -> u8 {
        match self {
            Self::Esp => IPPROTO_ESP,
            Self::Ah => IPPROTO_AH,
            Self::Comp => IPPROTO_COMP,
            Self::Other(n) => *n,
        }
    }
}

/// XFRM mode (transport, tunnel, etc.).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XfrmMode {
    /// Transport mode.
    Transport,
    /// Tunnel mode.
    Tunnel,
    /// BEET mode.
    Beet,
    /// Other mode.
    Other(u8),
}

impl XfrmMode {
    fn from_u8(val: u8) -> Self {
        match val {
            XFRM_MODE_TRANSPORT => Self::Transport,
            XFRM_MODE_TUNNEL => Self::Tunnel,
            XFRM_MODE_BEET => Self::Beet,
            other => Self::Other(other),
        }
    }
}

/// Policy direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyDirection {
    /// Incoming traffic.
    In,
    /// Outgoing traffic.
    Out,
    /// Forwarded traffic.
    Forward,
    /// Unknown direction.
    Unknown(u8),
}

impl PolicyDirection {
    fn from_u8(val: u8) -> Self {
        match val {
            XFRM_POLICY_IN => Self::In,
            XFRM_POLICY_OUT => Self::Out,
            XFRM_POLICY_FWD => Self::Forward,
            other => Self::Unknown(other),
        }
    }
}

/// Policy action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyAction {
    /// Allow traffic.
    Allow,
    /// Block traffic.
    Block,
    /// Unknown action.
    Unknown(u8),
}

impl PolicyAction {
    fn from_u8(val: u8) -> Self {
        match val {
            XFRM_POLICY_ALLOW => Self::Allow,
            XFRM_POLICY_BLOCK => Self::Block,
            other => Self::Unknown(other),
        }
    }
}

/// A traffic selector.
#[derive(Debug, Clone)]
pub struct TrafficSelector {
    /// Source address.
    pub src_addr: Option<IpAddr>,
    /// Destination address.
    pub dst_addr: Option<IpAddr>,
    /// Source prefix length.
    pub src_prefix_len: u8,
    /// Destination prefix length.
    pub dst_prefix_len: u8,
    /// Source port.
    pub src_port: Option<u16>,
    /// Destination port.
    pub dst_port: Option<u16>,
    /// IP protocol.
    pub proto: u8,
}

impl TrafficSelector {
    fn from_selector(sel: XfrmSelector) -> Self {
        Self {
            src_addr: sel.saddr.to_ip(sel.family),
            dst_addr: sel.daddr.to_ip(sel.family),
            src_prefix_len: sel.prefixlen_s,
            dst_prefix_len: sel.prefixlen_d,
            src_port: if sel.sport != 0 {
                Some(u16::from_be(sel.sport))
            } else {
                None
            },
            dst_port: if sel.dport != 0 {
                Some(u16::from_be(sel.dport))
            } else {
                None
            },
            proto: sel.proto,
        }
    }
}

/// A Security Association (SA).
#[derive(Debug, Clone)]
pub struct SecurityAssociation {
    /// Source address.
    pub src_addr: Option<IpAddr>,
    /// Destination address.
    pub dst_addr: Option<IpAddr>,
    /// Security Parameter Index.
    pub spi: u32,
    /// IPsec protocol.
    pub protocol: IpsecProtocol,
    /// Mode (transport/tunnel).
    pub mode: XfrmMode,
    /// Request ID.
    pub reqid: u32,
    /// Traffic selector.
    pub selector: TrafficSelector,
    /// Encryption algorithm.
    pub enc_alg: Option<XfrmAlgorithm>,
    /// Authentication algorithm.
    pub auth_alg: Option<XfrmAlgorithm>,
    /// AEAD algorithm.
    pub aead_alg: Option<XfrmAlgorithmAead>,
    /// Authentication algorithm with truncation.
    pub auth_trunc_alg: Option<XfrmAlgorithmAuthTrunc>,
    /// Compression algorithm.
    pub comp_alg: Option<XfrmAlgorithm>,
    /// Encapsulation template (UDP encap).
    pub encap: Option<XfrmEncapTmpl>,
    /// Mark.
    pub mark: Option<XfrmMark>,
    /// Interface ID.
    pub if_id: Option<u32>,
    /// Bytes processed.
    pub bytes: u64,
    /// Packets processed.
    pub packets: u64,
    /// Replay window size.
    pub replay_window: u8,
    /// Flags.
    pub flags: u8,
}

/// A Security Policy (SP).
#[derive(Debug, Clone)]
pub struct SecurityPolicy {
    /// Traffic selector.
    pub selector: TrafficSelector,
    /// Policy direction.
    pub direction: PolicyDirection,
    /// Policy action.
    pub action: PolicyAction,
    /// Priority.
    pub priority: u32,
    /// Policy index.
    pub index: u32,
    /// Flags.
    pub flags: u8,
    /// Mark.
    pub mark: Option<XfrmMark>,
    /// Interface ID.
    pub if_id: Option<u32>,
}

impl Connection<Xfrm> {
    /// Create a new XFRM connection.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use nlink::netlink::{Connection, Xfrm};
    ///
    /// let conn = Connection::<Xfrm>::new()?;
    /// ```
    pub fn new() -> Result<Self> {
        let socket = NetlinkSocket::new(Xfrm::PROTOCOL)?;
        Ok(Self::from_parts(socket, Xfrm))
    }

    /// Get all Security Associations.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use nlink::netlink::{Connection, Xfrm};
    ///
    /// let conn = Connection::<Xfrm>::new()?;
    /// let sas = conn.get_security_associations().await?;
    ///
    /// for sa in &sas {
    ///     println!("{:?} -> {:?} SPI={:08x} proto={:?}",
    ///         sa.src_addr, sa.dst_addr, sa.spi, sa.protocol);
    /// }
    /// ```
    pub async fn get_security_associations(&self) -> Result<Vec<SecurityAssociation>> {
        let seq = self.socket().next_seq();
        let pid = self.socket().pid();

        // Build request message
        let mut buf = Vec::with_capacity(64);

        // Netlink header (16 bytes)
        buf.extend_from_slice(&0u32.to_ne_bytes()); // nlmsg_len (fill later)
        buf.extend_from_slice(&XFRM_MSG_GETSA.to_ne_bytes()); // nlmsg_type
        buf.extend_from_slice(&(NLM_F_REQUEST | NLM_F_DUMP).to_ne_bytes()); // nlmsg_flags
        buf.extend_from_slice(&seq.to_ne_bytes()); // nlmsg_seq
        buf.extend_from_slice(&pid.to_ne_bytes()); // nlmsg_pid

        // xfrm_usersa_info (filled with zeros for dump)
        let sa_info = XfrmUsersaInfo::default();
        buf.extend_from_slice(sa_info.as_bytes());

        // Update length
        let len = buf.len() as u32;
        buf[0..4].copy_from_slice(&len.to_ne_bytes());

        // Send request
        self.socket().send(&buf).await?;

        // Receive responses
        let mut sas = Vec::new();

        loop {
            let data = self.socket().recv_msg().await?;

            let mut offset = 0;
            while offset + NLMSG_HDRLEN <= data.len() {
                let nlmsg_len = u32::from_ne_bytes([
                    data[offset],
                    data[offset + 1],
                    data[offset + 2],
                    data[offset + 3],
                ]) as usize;

                let nlmsg_type = u16::from_ne_bytes([data[offset + 4], data[offset + 5]]);

                if nlmsg_len < NLMSG_HDRLEN || offset + nlmsg_len > data.len() {
                    break;
                }

                match nlmsg_type {
                    NLMSG_DONE => return Ok(sas),
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
                        if let Some(sa) = self.parse_sa(&data[offset..offset + nlmsg_len]) {
                            sas.push(sa);
                        }
                    }
                }

                // Align to 4 bytes
                offset += (nlmsg_len + 3) & !3;
            }
        }
    }

    /// Get all Security Policies.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use nlink::netlink::{Connection, Xfrm};
    ///
    /// let conn = Connection::<Xfrm>::new()?;
    /// let policies = conn.get_security_policies().await?;
    ///
    /// for pol in &policies {
    ///     println!("dir={:?} action={:?} priority={}",
    ///         pol.direction, pol.action, pol.priority);
    /// }
    /// ```
    pub async fn get_security_policies(&self) -> Result<Vec<SecurityPolicy>> {
        let seq = self.socket().next_seq();
        let pid = self.socket().pid();

        // Build request message
        let mut buf = Vec::with_capacity(64);

        // Netlink header (16 bytes)
        buf.extend_from_slice(&0u32.to_ne_bytes()); // nlmsg_len (fill later)
        buf.extend_from_slice(&XFRM_MSG_GETPOLICY.to_ne_bytes()); // nlmsg_type
        buf.extend_from_slice(&(NLM_F_REQUEST | NLM_F_DUMP).to_ne_bytes()); // nlmsg_flags
        buf.extend_from_slice(&seq.to_ne_bytes()); // nlmsg_seq
        buf.extend_from_slice(&pid.to_ne_bytes()); // nlmsg_pid

        // xfrm_userpolicy_info (filled with zeros for dump)
        let pol_info = XfrmUserpolicyInfo::default();
        buf.extend_from_slice(pol_info.as_bytes());

        // Update length
        let len = buf.len() as u32;
        buf[0..4].copy_from_slice(&len.to_ne_bytes());

        // Send request
        self.socket().send(&buf).await?;

        // Receive responses
        let mut policies = Vec::new();

        loop {
            let data = self.socket().recv_msg().await?;

            let mut offset = 0;
            while offset + NLMSG_HDRLEN <= data.len() {
                let nlmsg_len = u32::from_ne_bytes([
                    data[offset],
                    data[offset + 1],
                    data[offset + 2],
                    data[offset + 3],
                ]) as usize;

                let nlmsg_type = u16::from_ne_bytes([data[offset + 4], data[offset + 5]]);

                if nlmsg_len < NLMSG_HDRLEN || offset + nlmsg_len > data.len() {
                    break;
                }

                match nlmsg_type {
                    NLMSG_DONE => return Ok(policies),
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
                        if let Some(pol) = self.parse_policy(&data[offset..offset + nlmsg_len]) {
                            policies.push(pol);
                        }
                    }
                }

                // Align to 4 bytes
                offset += (nlmsg_len + 3) & !3;
            }
        }
    }

    /// Parse a Security Association from a netlink message.
    fn parse_sa(&self, data: &[u8]) -> Option<SecurityAssociation> {
        if data.len() < NLMSG_HDRLEN + std::mem::size_of::<XfrmUsersaInfo>() {
            return None;
        }

        let msg_data = &data[NLMSG_HDRLEN..];
        let (info, _) = XfrmUsersaInfo::ref_from_prefix(msg_data).ok()?;

        let mut sa = SecurityAssociation {
            src_addr: info.saddr.to_ip(info.family),
            dst_addr: info.id.daddr.to_ip(info.family),
            spi: u32::from_be(info.id.spi),
            protocol: IpsecProtocol::from_u8(info.id.proto),
            mode: XfrmMode::from_u8(info.mode),
            reqid: info.reqid,
            selector: TrafficSelector::from_selector(info.sel),
            enc_alg: None,
            auth_alg: None,
            aead_alg: None,
            auth_trunc_alg: None,
            comp_alg: None,
            encap: None,
            mark: None,
            if_id: None,
            bytes: info.curlft.bytes,
            packets: info.curlft.packets,
            replay_window: info.replay_window,
            flags: info.flags,
        };

        // Parse attributes
        let attr_start = NLMSG_HDRLEN + std::mem::size_of::<XfrmUsersaInfo>();
        if data.len() > attr_start {
            let mut input = &data[attr_start..];
            while let Some((attr_type, attr_data)) = parse_nla(&mut input) {
                match attr_type {
                    XFRMA_ALG_CRYPT => {
                        sa.enc_alg = parse_algorithm(attr_data);
                    }
                    XFRMA_ALG_AUTH => {
                        sa.auth_alg = parse_algorithm(attr_data);
                    }
                    XFRMA_ALG_AEAD => {
                        sa.aead_alg = parse_aead_algorithm(attr_data);
                    }
                    XFRMA_ALG_AUTH_TRUNC => {
                        sa.auth_trunc_alg = parse_auth_trunc_algorithm(attr_data);
                    }
                    XFRMA_ALG_COMP => {
                        sa.comp_alg = parse_algorithm(attr_data);
                    }
                    XFRMA_ENCAP => {
                        if attr_data.len() >= std::mem::size_of::<XfrmEncapTmpl>()
                            && let Ok((encap, _)) = XfrmEncapTmpl::ref_from_prefix(attr_data)
                        {
                            sa.encap = Some(*encap);
                        }
                    }
                    XFRMA_MARK => {
                        if attr_data.len() >= std::mem::size_of::<XfrmMark>()
                            && let Ok((mark, _)) = XfrmMark::ref_from_prefix(attr_data)
                        {
                            sa.mark = Some(*mark);
                        }
                    }
                    XFRMA_IF_ID => {
                        if attr_data.len() >= 4 {
                            sa.if_id = Some(u32::from_ne_bytes([
                                attr_data[0],
                                attr_data[1],
                                attr_data[2],
                                attr_data[3],
                            ]));
                        }
                    }
                    _ => {}
                }
            }
        }

        Some(sa)
    }

    /// Parse a Security Policy from a netlink message.
    fn parse_policy(&self, data: &[u8]) -> Option<SecurityPolicy> {
        if data.len() < NLMSG_HDRLEN + std::mem::size_of::<XfrmUserpolicyInfo>() {
            return None;
        }

        let msg_data = &data[NLMSG_HDRLEN..];
        let (info, _) = XfrmUserpolicyInfo::ref_from_prefix(msg_data).ok()?;

        let mut policy = SecurityPolicy {
            selector: TrafficSelector::from_selector(info.sel),
            direction: PolicyDirection::from_u8(info.dir),
            action: PolicyAction::from_u8(info.action),
            priority: info.priority,
            index: info.index,
            flags: info.flags,
            mark: None,
            if_id: None,
        };

        // Parse attributes
        let attr_start = NLMSG_HDRLEN + std::mem::size_of::<XfrmUserpolicyInfo>();
        if data.len() > attr_start {
            let mut input = &data[attr_start..];
            while let Some((attr_type, attr_data)) = parse_nla(&mut input) {
                match attr_type {
                    XFRMA_MARK => {
                        if attr_data.len() >= std::mem::size_of::<XfrmMark>()
                            && let Ok((mark, _)) = XfrmMark::ref_from_prefix(attr_data)
                        {
                            policy.mark = Some(*mark);
                        }
                    }
                    XFRMA_IF_ID => {
                        if attr_data.len() >= 4 {
                            policy.if_id = Some(u32::from_ne_bytes([
                                attr_data[0],
                                attr_data[1],
                                attr_data[2],
                                attr_data[3],
                            ]));
                        }
                    }
                    _ => {}
                }
            }
        }

        Some(policy)
    }
}

/// Parse a netlink attribute.
fn parse_nla<'a>(input: &mut &'a [u8]) -> Option<(u16, &'a [u8])> {
    if input.len() < 4 {
        return None;
    }

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

/// Parse an XFRM algorithm.
fn parse_algorithm(data: &[u8]) -> Option<XfrmAlgorithm> {
    // Algorithm structure: 64-byte name + 4-byte key_len + key data
    if data.len() < 68 {
        return None;
    }

    let name = parse_cstring(&data[..64]);
    let key_len = u32::from_le_bytes([data[64], data[65], data[66], data[67]]);
    let key_bytes = (key_len as usize).div_ceil(8);
    let key = if data.len() >= 68 + key_bytes {
        data[68..68 + key_bytes].to_vec()
    } else {
        Vec::new()
    };

    Some(XfrmAlgorithm { name, key_len, key })
}

/// Parse an XFRM AEAD algorithm.
fn parse_aead_algorithm(data: &[u8]) -> Option<XfrmAlgorithmAead> {
    // AEAD structure: 64-byte name + 4-byte key_len + 4-byte icv_len + key data
    if data.len() < 72 {
        return None;
    }

    let name = parse_cstring(&data[..64]);
    let key_len = u32::from_le_bytes([data[64], data[65], data[66], data[67]]);
    let icv_len = u32::from_le_bytes([data[68], data[69], data[70], data[71]]);
    let key_bytes = (key_len as usize).div_ceil(8);
    let key = if data.len() >= 72 + key_bytes {
        data[72..72 + key_bytes].to_vec()
    } else {
        Vec::new()
    };

    Some(XfrmAlgorithmAead {
        name,
        key_len,
        icv_len,
        key,
    })
}

/// Parse an XFRM authentication algorithm with truncation.
fn parse_auth_trunc_algorithm(data: &[u8]) -> Option<XfrmAlgorithmAuthTrunc> {
    // Auth trunc structure: 64-byte name + 4-byte key_len + 4-byte trunc_len + key data
    if data.len() < 72 {
        return None;
    }

    let name = parse_cstring(&data[..64]);
    let key_len = u32::from_le_bytes([data[64], data[65], data[66], data[67]]);
    let trunc_len = u32::from_le_bytes([data[68], data[69], data[70], data[71]]);
    let key_bytes = (key_len as usize).div_ceil(8);
    let key = if data.len() >= 72 + key_bytes {
        data[72..72 + key_bytes].to_vec()
    } else {
        Vec::new()
    };

    Some(XfrmAlgorithmAuthTrunc {
        name,
        key_len,
        trunc_len,
        key,
    })
}

/// Parse a C string from a fixed-size buffer.
fn parse_cstring(data: &[u8]) -> String {
    let end = data.iter().position(|&b| b == 0).unwrap_or(data.len());
    String::from_utf8_lossy(&data[..end]).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xfrm_address_ipv4() {
        let addr = XfrmAddress::from_v4(Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(
            addr.to_ip(2),
            Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)))
        );
    }

    #[test]
    fn xfrm_address_ipv6() {
        let addr = XfrmAddress::from_v6(Ipv6Addr::LOCALHOST);
        assert_eq!(addr.to_ip(10), Some(IpAddr::V6(Ipv6Addr::LOCALHOST)));
    }

    #[test]
    fn ipsec_protocol_roundtrip() {
        assert_eq!(IpsecProtocol::Esp.number(), 50);
        assert_eq!(IpsecProtocol::from_u8(50), IpsecProtocol::Esp);

        assert_eq!(IpsecProtocol::Ah.number(), 51);
        assert_eq!(IpsecProtocol::from_u8(51), IpsecProtocol::Ah);
    }

    #[test]
    fn xfrm_mode_from_u8() {
        assert_eq!(XfrmMode::from_u8(0), XfrmMode::Transport);
        assert_eq!(XfrmMode::from_u8(1), XfrmMode::Tunnel);
        assert_eq!(XfrmMode::from_u8(4), XfrmMode::Beet);
    }

    #[test]
    fn policy_direction_from_u8() {
        assert_eq!(PolicyDirection::from_u8(0), PolicyDirection::In);
        assert_eq!(PolicyDirection::from_u8(1), PolicyDirection::Out);
        assert_eq!(PolicyDirection::from_u8(2), PolicyDirection::Forward);
    }

    #[test]
    fn zerocopy_sizes() {
        assert_eq!(std::mem::size_of::<XfrmAddress>(), 16);
        assert_eq!(std::mem::size_of::<XfrmId>(), 24);
        assert_eq!(std::mem::size_of::<XfrmMark>(), 8);
    }
}
