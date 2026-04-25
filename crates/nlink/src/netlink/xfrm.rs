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

use super::{
    builder::MessageBuilder,
    connection::Connection,
    error::Result,
    protocol::{ProtocolState, Xfrm},
    socket::NetlinkSocket,
};

// Netlink constants
const NLMSG_DONE: u16 = 3;
const NLMSG_ERROR: u16 = 2;
const NLM_F_REQUEST: u16 = 0x01;
const NLM_F_ACK: u16 = 0x04;
const NLM_F_DUMP: u16 = 0x300;
const NLM_F_CREATE: u16 = 0x400;
const NLM_F_EXCL: u16 = 0x200;
const NLM_F_REPLACE: u16 = 0x100;

// XFRM message types (from linux/xfrm.h)
const XFRM_MSG_NEWSA: u16 = 16;
const XFRM_MSG_DELSA: u16 = 17;
const XFRM_MSG_GETSA: u16 = 18;
const XFRM_MSG_NEWPOLICY: u16 = 19;
const XFRM_MSG_DELPOLICY: u16 = 20;
const XFRM_MSG_GETPOLICY: u16 = 21;
const XFRM_MSG_FLUSHSA: u16 = 25;
const XFRM_MSG_FLUSHPOLICY: u16 = 28;

// XFRM attribute types
const XFRMA_ALG_AUTH: u16 = 1;
const XFRMA_ALG_CRYPT: u16 = 2;
const XFRMA_ALG_COMP: u16 = 3;
const XFRMA_ENCAP: u16 = 4;
const XFRMA_TMPL: u16 = 5;
const XFRMA_SRCADDR: u16 = 9;
#[allow(dead_code)] // for the future "main vs sub" policy-type slice
const XFRMA_POLICY_TYPE: u16 = 16;
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

/// `xfrm_usersa_id` — body of `XFRM_MSG_DELSA` / `GETSA` requests.
/// 24 bytes (16 daddr + 4 spi + 2 family + 1 proto + 1 align).
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct XfrmUsersaId {
    pub daddr: XfrmAddress,
    pub spi: u32,
    pub family: u16,
    pub proto: u8,
    pub _pad: u8,
}

/// `xfrm_usersa_flush` — body of `XFRM_MSG_FLUSHSA`. Just the
/// `proto` byte (0 = IPSEC_PROTO_ANY → flush everything); padded
/// to 8 bytes for the kernel's `sizeof`-rounded read.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct XfrmUsersaFlush {
    pub proto: u8,
    pub _pad: [u8; 7],
}

/// `xfrm_userpolicy_id` — body of `XFRM_MSG_DELPOLICY` /
/// `GETPOLICY` requests. Selector + index + direction byte.
#[repr(C, packed)]
#[derive(Debug, Clone, Copy, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct XfrmUserpolicyId {
    pub sel: XfrmSelector,
    pub index: u32,
    pub dir: u8,
    pub _pad: [u8; 7],
}

/// `xfrm_user_tmpl` — one entry in an SP's `XFRMA_TMPL` array.
/// Tells the kernel which SA(s) to look up to satisfy the policy:
/// the (daddr, spi, proto) triple plus mode/reqid + algorithm
/// bitmasks (typically 0xFFFFFFFF = "any algorithm").
#[repr(C, packed)]
#[derive(Debug, Clone, Copy, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct XfrmUserTmpl {
    pub id: XfrmId,
    pub family: u16,
    pub saddr: XfrmAddress,
    pub reqid: u32,
    pub mode: u8,
    pub share: u8,
    pub optional: u8,
    pub _pad: u8,
    pub aalgos: u32,
    pub ealgos: u32,
    pub calgos: u32,
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
#[non_exhaustive]
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
#[non_exhaustive]
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

    /// Convert back to the wire-format `u8`.
    pub fn number(&self) -> u8 {
        match self {
            Self::Transport => XFRM_MODE_TRANSPORT,
            Self::Tunnel => XFRM_MODE_TUNNEL,
            Self::Beet => XFRM_MODE_BEET,
            Self::Other(n) => *n,
        }
    }
}

/// Policy direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
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

    /// Convert back to the wire-format `u8`.
    pub fn number(&self) -> u8 {
        match self {
            Self::In => XFRM_POLICY_IN,
            Self::Out => XFRM_POLICY_OUT,
            Self::Forward => XFRM_POLICY_FWD,
            Self::Unknown(n) => *n,
        }
    }
}

/// Policy action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
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

    /// Convert back to the wire-format `u8`.
    pub fn number(&self) -> u8 {
        match self {
            Self::Allow => XFRM_POLICY_ALLOW,
            Self::Block => XFRM_POLICY_BLOCK,
            Self::Unknown(n) => *n,
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

// ============================================================================
// Write-path builder (Plan 141 PR A, Plan 142 Phase 2)
// ============================================================================

/// Authentication algorithm spec for an [`XfrmSaBuilder`].
///
/// `name` is a kernel algorithm string like `"hmac(sha256)"`; the
/// kernel's crypto subsystem decides which combinations are valid.
/// `key` is the raw key bytes; `key_len_bits` is set automatically
/// from `key.len() * 8` by the helper constructors.
#[derive(Debug, Clone)]
pub struct XfrmAlgoAuth {
    pub name: String,
    pub key: Vec<u8>,
}

/// Encryption algorithm spec.
#[derive(Debug, Clone)]
pub struct XfrmAlgoEncr {
    pub name: String,
    pub key: Vec<u8>,
}

/// AEAD algorithm spec (combined auth + encrypt with ICV).
///
/// `icv_truncbits` is the ICV length in bits (e.g. 128 for
/// AES-GCM-128).
#[derive(Debug, Clone)]
pub struct XfrmAlgoAead {
    pub name: String,
    pub key: Vec<u8>,
    pub icv_truncbits: u32,
}

/// Builder for a Security Association write request.
///
/// Construct via [`XfrmSaBuilder::new`], chain the relevant setters,
/// and pass to [`Connection::add_sa`]. The kernel validates the
/// combination of `proto` / `mode` / algorithm specs; mismatches
/// surface as `EINVAL` from `add_sa`.
///
/// # Example
///
/// ```no_run
/// # async fn example() -> nlink::Result<()> {
/// use nlink::netlink::{Connection, Xfrm};
/// use nlink::netlink::xfrm::{XfrmSaBuilder, XfrmMode, IpsecProtocol};
///
/// let conn = Connection::<Xfrm>::new()?;
/// let sa = XfrmSaBuilder::new(
///     "10.0.0.1".parse().unwrap(),
///     "10.0.0.2".parse().unwrap(),
///     0xdead_beef,
///     IpsecProtocol::Esp,
/// )
/// .mode(XfrmMode::Tunnel)
/// .reqid(42)
/// .auth_hmac_sha256(&[0u8; 32])
/// .encr_aes_cbc(&[0u8; 16]);
/// conn.add_sa(sa).await?;
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone)]
#[must_use = "builders do nothing unless submitted to the connection"]
pub struct XfrmSaBuilder {
    src: IpAddr,
    dst: IpAddr,
    spi: u32,
    proto: IpsecProtocol,
    mode: XfrmMode,
    reqid: u32,
    flags: u8,
    replay_window: u8,
    auth: Option<XfrmAlgoAuth>,
    encr: Option<XfrmAlgoEncr>,
    aead: Option<XfrmAlgoAead>,
    encap: Option<XfrmEncapTmpl>,
    mark: Option<(u32, u32)>,
    if_id: Option<u32>,
}

impl XfrmSaBuilder {
    /// Create a new SA builder for the given (src, dst, spi, proto)
    /// tuple. Defaults to transport mode, reqid 0, replay window 32.
    pub fn new(src: IpAddr, dst: IpAddr, spi: u32, proto: IpsecProtocol) -> Self {
        Self {
            src,
            dst,
            spi,
            proto,
            mode: XfrmMode::Transport,
            reqid: 0,
            flags: 0,
            // Default replay window — kernel default is 0 (replay
            // protection disabled), which surprises users; pick 32
            // packets like iproute2 does for `ip xfrm`.
            replay_window: 32,
            auth: None,
            encr: None,
            aead: None,
            encap: None,
            mark: None,
            if_id: None,
        }
    }

    pub fn mode(mut self, mode: XfrmMode) -> Self {
        self.mode = mode;
        self
    }

    pub fn reqid(mut self, id: u32) -> Self {
        self.reqid = id;
        self
    }

    pub fn replay_window(mut self, w: u8) -> Self {
        self.replay_window = w;
        self
    }

    /// Set the auth algorithm by name + raw key bytes. Most users
    /// want one of the named helpers ([`Self::auth_hmac_sha256`]).
    pub fn auth(mut self, name: impl Into<String>, key: &[u8]) -> Self {
        self.auth = Some(XfrmAlgoAuth {
            name: name.into(),
            key: key.to_vec(),
        });
        self
    }

    /// Convenience: HMAC-SHA256. Key must be 32 bytes.
    pub fn auth_hmac_sha256(self, key: &[u8]) -> Self {
        self.auth("hmac(sha256)", key)
    }

    /// Set the encryption algorithm by name + raw key bytes.
    pub fn encr(mut self, name: impl Into<String>, key: &[u8]) -> Self {
        self.encr = Some(XfrmAlgoEncr {
            name: name.into(),
            key: key.to_vec(),
        });
        self
    }

    /// Convenience: AES-CBC. Key length determines variant
    /// (16 → AES-128, 24 → AES-192, 32 → AES-256).
    pub fn encr_aes_cbc(self, key: &[u8]) -> Self {
        self.encr("cbc(aes)", key)
    }

    /// Set the AEAD algorithm. Pass `icv_truncbits` in BITS
    /// (e.g. 128 for the standard AES-GCM-128 ICV).
    pub fn aead(mut self, name: impl Into<String>, key: &[u8], icv_truncbits: u32) -> Self {
        self.aead = Some(XfrmAlgoAead {
            name: name.into(),
            key: key.to_vec(),
            icv_truncbits,
        });
        self
    }

    /// Convenience: AES-GCM (RFC 4106). Key includes the 4-byte
    /// salt suffix per RFC; pass `icv_truncbits` 128 for the
    /// standard ICV length.
    pub fn aead_aes_gcm(self, key: &[u8], icv_truncbits: u32) -> Self {
        self.aead("rfc4106(gcm(aes))", key, icv_truncbits)
    }

    /// Configure NAT-T UDP encapsulation. Picks the encap type
    /// based on `dport` (4500 → IKE-compatible variant, anything
    /// else → non-IKE).
    pub fn nat_t_udp_encap(mut self, sport: u16, dport: u16) -> Self {
        // UDP_ENCAP_ESPINUDP_NON_IKE = 1, UDP_ENCAP_ESPINUDP = 2
        // (from include/uapi/linux/udp.h)
        let encap_type: u16 = if dport == 4500 { 2 } else { 1 };
        self.encap = Some(XfrmEncapTmpl {
            encap_type,
            encap_sport: sport.to_be(),
            encap_dport: dport.to_be(),
            _pad: 0,
            encap_oa: XfrmAddress::default(),
        });
        self
    }

    /// Filter which policies/SAs apply by skb mark.
    pub fn mark(mut self, mark: u32, mask: u32) -> Self {
        self.mark = Some((mark, mask));
        self
    }

    /// XFRM interface ID (XFRMA_IF_ID).
    pub fn if_id(mut self, id: u32) -> Self {
        self.if_id = Some(id);
        self
    }

    /// Address family inferred from `src`/`dst` (must match).
    fn family(&self) -> u16 {
        family_for_pair(self.src, self.dst)
    }

    /// Populate the request's `xfrm_usersa_info` header bytes.
    fn build_usersa_info(&self) -> XfrmUsersaInfo {
        let saddr = ip_to_xfrm_addr(self.src);
        let daddr = ip_to_xfrm_addr(self.dst);
        let family = self.family();
        XfrmUsersaInfo {
            sel: XfrmSelector {
                family,
                ..Default::default()
            },
            id: XfrmId {
                daddr,
                spi: self.spi.to_be(),
                proto: self.proto.number(),
                _pad: [0; 3],
            },
            saddr,
            lft: XfrmLifetimeCfg {
                soft_byte_limit: u64::MAX,
                hard_byte_limit: u64::MAX,
                soft_packet_limit: u64::MAX,
                hard_packet_limit: u64::MAX,
                soft_add_expires_seconds: 0,
                hard_add_expires_seconds: 0,
                soft_use_expires_seconds: 0,
                hard_use_expires_seconds: 0,
            },
            curlft: XfrmLifetimeCur::default(),
            stats: XfrmStats::default(),
            seq: 0,
            reqid: self.reqid,
            family,
            mode: self.mode.number(),
            replay_window: self.replay_window,
            flags: self.flags,
            _pad: [0; 7],
        }
    }

    /// Append the SA to a [`MessageBuilder`]: header bytes followed
    /// by algorithm + encap + mark + if_id attributes.
    fn write_into(&self, b: &mut MessageBuilder) {
        let info = self.build_usersa_info();
        b.append_bytes(info.as_bytes());

        if let Some(a) = &self.auth {
            let bytes = encode_xfrm_algo(&a.name, &a.key);
            b.append_attr(XFRMA_ALG_AUTH, &bytes);
        }
        if let Some(e) = &self.encr {
            let bytes = encode_xfrm_algo(&e.name, &e.key);
            b.append_attr(XFRMA_ALG_CRYPT, &bytes);
        }
        if let Some(a) = &self.aead {
            let bytes = encode_xfrm_algo_aead(&a.name, &a.key, a.icv_truncbits);
            b.append_attr(XFRMA_ALG_AEAD, &bytes);
        }
        if let Some(encap) = &self.encap {
            b.append_attr(XFRMA_ENCAP, encap.as_bytes());
        }
        if let Some((mark, mask)) = self.mark {
            let m = XfrmMark { v: mark, m: mask };
            b.append_attr(XFRMA_MARK, m.as_bytes());
        }
        if let Some(id) = self.if_id {
            b.append_attr_u32(XFRMA_IF_ID, id);
        }
    }
}

/// Encode the `xfrm_algo` wire layout: 64-byte zero-padded name
/// + 4-byte key_len (BITS) + key bytes.
fn encode_xfrm_algo(name: &str, key: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(68 + key.len());
    let mut name_field = [0u8; 64];
    let n = name.len().min(63);
    name_field[..n].copy_from_slice(&name.as_bytes()[..n]);
    buf.extend_from_slice(&name_field);
    let key_len_bits = (key.len() * 8) as u32;
    buf.extend_from_slice(&key_len_bits.to_le_bytes());
    buf.extend_from_slice(key);
    buf
}

/// Encode `xfrm_algo_aead`: 64-byte name + 4-byte key_len (BITS)
/// + 4-byte icv_len (BITS) + key bytes.
fn encode_xfrm_algo_aead(name: &str, key: &[u8], icv_truncbits: u32) -> Vec<u8> {
    let mut buf = Vec::with_capacity(72 + key.len());
    let mut name_field = [0u8; 64];
    let n = name.len().min(63);
    name_field[..n].copy_from_slice(&name.as_bytes()[..n]);
    buf.extend_from_slice(&name_field);
    let key_len_bits = (key.len() * 8) as u32;
    buf.extend_from_slice(&key_len_bits.to_le_bytes());
    buf.extend_from_slice(&icv_truncbits.to_le_bytes());
    buf.extend_from_slice(key);
    buf
}

/// Convert a Rust `IpAddr` into the kernel's 16-byte
/// `xfrm_address_t` (IPv4 in the first 4 bytes, network order).
fn ip_to_xfrm_addr(ip: IpAddr) -> XfrmAddress {
    match ip {
        IpAddr::V4(v4) => XfrmAddress::from_v4(v4),
        IpAddr::V6(v6) => XfrmAddress::from_v6(v6),
    }
}

/// Address family for a `(src, dst)` pair. Mismatched families
/// return 0 — the kernel will reject the request with EINVAL.
fn family_for_pair(src: IpAddr, dst: IpAddr) -> u16 {
    match (src, dst) {
        (IpAddr::V4(_), IpAddr::V4(_)) => libc::AF_INET as u16,
        (IpAddr::V6(_), IpAddr::V6(_)) => libc::AF_INET6 as u16,
        _ => 0,
    }
}

impl XfrmUsersaId {
    fn as_bytes(&self) -> &[u8] {
        <Self as IntoBytes>::as_bytes(self)
    }
}

impl XfrmUsersaFlush {
    fn as_bytes(&self) -> &[u8] {
        <Self as IntoBytes>::as_bytes(self)
    }
}

impl XfrmUserpolicyId {
    fn as_bytes(&self) -> &[u8] {
        <Self as IntoBytes>::as_bytes(self)
    }
}

impl XfrmUserTmpl {
    fn as_bytes(&self) -> &[u8] {
        <Self as IntoBytes>::as_bytes(self)
    }

    /// Build a typical "match-any-algo" template: forward to a
    /// specific destination via `proto`/`mode`, no SPI constraint.
    pub fn match_any(
        src: IpAddr,
        dst: IpAddr,
        proto: IpsecProtocol,
        mode: XfrmMode,
        reqid: u32,
    ) -> Self {
        Self {
            id: XfrmId {
                daddr: ip_to_xfrm_addr(dst),
                spi: 0,
                proto: proto.number(),
                _pad: [0; 3],
            },
            family: family_for_pair(src, dst),
            saddr: ip_to_xfrm_addr(src),
            reqid,
            mode: mode.number(),
            share: 0,
            optional: 0,
            _pad: 0,
            // Default: any algorithm acceptable (kernel matches any
            // SA whose algorithms intersect this bitmask).
            aalgos: u32::MAX,
            ealgos: u32::MAX,
            calgos: u32::MAX,
        }
    }
}

// ============================================================================
// Security Policy write-path builder (Plan 141 PR B)
// ============================================================================

/// Builder for a Security Policy write request.
///
/// SPs steer traffic into / out of the IPsec subsystem: each
/// matching packet is checked against the policy's templates and
/// either encrypted/decrypted via the resolved SA, blocked, or
/// passed through. Construct via [`XfrmSpBuilder::new`], chain
/// the relevant setters (and any number of [`Self::template`]
/// calls), and pass to [`Connection::add_sp`].
///
/// # Example
///
/// ```no_run
/// # async fn example() -> nlink::Result<()> {
/// use nlink::netlink::{Connection, Xfrm};
/// use nlink::netlink::xfrm::{
///     XfrmSpBuilder, XfrmSelector, XfrmUserTmpl, IpsecProtocol,
///     PolicyDirection, XfrmMode,
/// };
///
/// let conn = Connection::<Xfrm>::new()?;
/// let sel = XfrmSelector { family: libc::AF_INET as u16, ..Default::default() };
/// let tmpl = XfrmUserTmpl::match_any(
///     "10.0.0.1".parse().unwrap(),
///     "10.0.0.2".parse().unwrap(),
///     IpsecProtocol::Esp, XfrmMode::Tunnel, 42,
/// );
/// let sp = XfrmSpBuilder::new(sel, PolicyDirection::Out)
///     .priority(100)
///     .template(tmpl);
/// conn.add_sp(sp).await?;
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone)]
#[must_use = "builders do nothing unless submitted to the connection"]
pub struct XfrmSpBuilder {
    sel: XfrmSelector,
    direction: PolicyDirection,
    action: PolicyAction,
    priority: u32,
    index: u32,
    flags: u8,
    share: u8,
    tmpls: Vec<XfrmUserTmpl>,
    mark: Option<(u32, u32)>,
    if_id: Option<u32>,
}

impl XfrmSpBuilder {
    /// New SP for the given selector + direction. Defaults to
    /// `Allow` action, priority 0, kernel-assigned index.
    pub fn new(sel: XfrmSelector, direction: PolicyDirection) -> Self {
        Self {
            sel,
            direction,
            action: PolicyAction::Allow,
            priority: 0,
            index: 0,
            flags: 0,
            share: 0,
            tmpls: Vec::new(),
            mark: None,
            if_id: None,
        }
    }

    /// Set action to `Allow` (default).
    pub fn allow(mut self) -> Self {
        self.action = PolicyAction::Allow;
        self
    }

    /// Set action to `Block` — packets matching this selector are
    /// dropped.
    pub fn block(mut self) -> Self {
        self.action = PolicyAction::Block;
        self
    }

    pub fn priority(mut self, p: u32) -> Self {
        self.priority = p;
        self
    }

    /// Pre-pin a policy index. Default 0 = kernel assigns one.
    pub fn index(mut self, idx: u32) -> Self {
        self.index = idx;
        self
    }

    /// Append a template to the policy. Each template references
    /// an SA the kernel must look up to satisfy the policy. Order
    /// matters for nested transforms (e.g. AH inside ESP).
    pub fn template(mut self, tmpl: XfrmUserTmpl) -> Self {
        self.tmpls.push(tmpl);
        self
    }

    /// Filter which policies apply by skb mark.
    pub fn mark(mut self, mark: u32, mask: u32) -> Self {
        self.mark = Some((mark, mask));
        self
    }

    /// XFRM interface ID (XFRMA_IF_ID).
    pub fn if_id(mut self, id: u32) -> Self {
        self.if_id = Some(id);
        self
    }

    fn build_userpolicy_info(&self) -> XfrmUserpolicyInfo {
        XfrmUserpolicyInfo {
            sel: self.sel,
            lft: XfrmLifetimeCfg {
                soft_byte_limit: u64::MAX,
                hard_byte_limit: u64::MAX,
                soft_packet_limit: u64::MAX,
                hard_packet_limit: u64::MAX,
                soft_add_expires_seconds: 0,
                hard_add_expires_seconds: 0,
                soft_use_expires_seconds: 0,
                hard_use_expires_seconds: 0,
            },
            curlft: XfrmLifetimeCur::default(),
            priority: self.priority,
            index: self.index,
            dir: self.direction.number(),
            action: self.action.number(),
            flags: self.flags,
            share: self.share,
        }
    }

    fn write_into(&self, b: &mut MessageBuilder) {
        let info = self.build_userpolicy_info();
        b.append_bytes(info.as_bytes());

        if !self.tmpls.is_empty() {
            // XFRMA_TMPL is a single attribute carrying a packed
            // array of xfrm_user_tmpl entries (no per-entry
            // attribute header — just the structs back-to-back).
            let mut payload =
                Vec::with_capacity(self.tmpls.len() * std::mem::size_of::<XfrmUserTmpl>());
            for t in &self.tmpls {
                payload.extend_from_slice(t.as_bytes());
            }
            b.append_attr(XFRMA_TMPL, &payload);
        }
        if let Some((mark, mask)) = self.mark {
            let m = XfrmMark { v: mark, m: mask };
            b.append_attr(XFRMA_MARK, m.as_bytes());
        }
        if let Some(id) = self.if_id {
            b.append_attr_u32(XFRMA_IF_ID, id);
        }
    }
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

    /// Create a Security Association.
    ///
    /// Sends `XFRM_MSG_NEWSA` with `NLM_F_CREATE | NLM_F_EXCL`.
    /// Returns `Err` (`EEXIST`) if an SA with the same
    /// (dst, spi, proto) already exists; use [`Self::update_sa`]
    /// (lands in a follow-up slice) to replace in place.
    ///
    /// Common failure modes:
    /// - `EINVAL` — algorithm/key length mismatch, or src/dst
    ///   address-family mismatch.
    /// - `EEXIST` — SA tuple already present.
    /// - `EPROTONOSUPPORT` — kernel lacks the requested algorithm.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "add_sa"))]
    pub async fn add_sa(&self, sa: XfrmSaBuilder) -> Result<()> {
        let mut b = MessageBuilder::new(
            XFRM_MSG_NEWSA,
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
        );
        sa.write_into(&mut b);
        self.send_ack(b).await
    }

    /// Delete a Security Association identified by its tuple.
    ///
    /// Sends `XFRM_MSG_DELSA`. The kernel matches on
    /// (`daddr`, `spi`, `proto`, `family`); the source address is
    /// not part of the lookup key.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "del_sa"))]
    pub async fn del_sa(
        &self,
        src: IpAddr,
        dst: IpAddr,
        spi: u32,
        proto: IpsecProtocol,
    ) -> Result<()> {
        let mut b = MessageBuilder::new(XFRM_MSG_DELSA, NLM_F_REQUEST | NLM_F_ACK);

        // xfrm_usersa_id { daddr, spi, family, proto, _pad }
        let id = XfrmUsersaId {
            daddr: ip_to_xfrm_addr(dst),
            spi: spi.to_be(),
            family: family_for_pair(src, dst),
            proto: proto.number(),
            _pad: 0,
        };
        b.append_bytes(id.as_bytes());

        // Optional XFRMA_SRCADDR — kernel doesn't require it for
        // the lookup but iproute2 includes it for clarity.
        let saddr = ip_to_xfrm_addr(src);
        b.append_attr(XFRMA_SRCADDR, &saddr.bytes);

        self.send_ack(b).await
    }

    /// Replace an existing Security Association in place — same
    /// wire shape as [`Self::add_sa`] but with
    /// `NLM_F_CREATE | NLM_F_REPLACE`. The kernel matches on the
    /// (`daddr`, `spi`, `proto`, `family`) tuple from the body and
    /// updates the matching SA's algorithms / encap / mark / etc.
    /// Useful for rotating keys or nudging an SA's mark without a
    /// delete-then-add (which would briefly leave traffic
    /// unprotected).
    #[tracing::instrument(level = "debug", skip_all, fields(method = "update_sa"))]
    pub async fn update_sa(&self, sa: XfrmSaBuilder) -> Result<()> {
        let mut b = MessageBuilder::new(
            XFRM_MSG_NEWSA,
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE,
        );
        sa.write_into(&mut b);
        self.send_ack(b).await
    }

    /// Flush every Security Association in the kernel's database.
    ///
    /// Sends `XFRM_MSG_FLUSHSA` with `proto = 0` (which the kernel
    /// reads as IPSEC_PROTO_ANY → all protocols).
    #[tracing::instrument(level = "debug", skip_all, fields(method = "flush_sa"))]
    pub async fn flush_sa(&self) -> Result<()> {
        self.flush_sa_inner(0).await
    }

    /// Flush every Security Association of a specific protocol
    /// (e.g. ESP only). Useful for narrow cleanup that leaves
    /// other-protocol SAs in place.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "flush_sa_proto"))]
    pub async fn flush_sa_proto(&self, proto: IpsecProtocol) -> Result<()> {
        self.flush_sa_inner(proto.number()).await
    }

    async fn flush_sa_inner(&self, proto: u8) -> Result<()> {
        let mut b = MessageBuilder::new(XFRM_MSG_FLUSHSA, NLM_F_REQUEST | NLM_F_ACK);
        let body = XfrmUsersaFlush { proto, _pad: [0; 7] };
        b.append_bytes(body.as_bytes());
        self.send_ack(b).await
    }

    /// Fetch a single Security Association by its tuple. Returns
    /// `Ok(None)` if no SA matches (kernel returns ENOENT).
    ///
    /// Sends `XFRM_MSG_GETSA` with an `XfrmUsersaId` body — same
    /// shape as [`Self::del_sa`]'s lookup key. The response is a
    /// single `XFRM_MSG_NEWSA`-style message carrying the SA, or a
    /// `NLMSG_ERROR` with `errno=ENOENT` when nothing matches.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_sa"))]
    pub async fn get_sa(
        &self,
        src: IpAddr,
        dst: IpAddr,
        spi: u32,
        proto: IpsecProtocol,
    ) -> Result<Option<SecurityAssociation>> {
        let mut b = MessageBuilder::new(XFRM_MSG_GETSA, NLM_F_REQUEST);
        let id = XfrmUsersaId {
            daddr: ip_to_xfrm_addr(dst),
            spi: spi.to_be(),
            family: family_for_pair(src, dst),
            proto: proto.number(),
            _pad: 0,
        };
        b.append_bytes(id.as_bytes());
        let saddr = ip_to_xfrm_addr(src);
        b.append_attr(XFRMA_SRCADDR, &saddr.bytes);

        match self.send_request(b).await {
            Ok(response) => Ok(Self::parse_sa_msg(&response)),
            Err(e) if e.is_not_found() => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Create a Security Policy.
    ///
    /// Sends `XFRM_MSG_NEWPOLICY` with `NLM_F_CREATE | NLM_F_EXCL`.
    /// Returns `EEXIST` if a policy with the same (selector, dir,
    /// index) already exists; use [`Self::update_sp`] to replace.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "add_sp"))]
    pub async fn add_sp(&self, sp: XfrmSpBuilder) -> Result<()> {
        let mut b = MessageBuilder::new(
            XFRM_MSG_NEWPOLICY,
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
        );
        sp.write_into(&mut b);
        self.send_ack(b).await
    }

    /// Replace an existing Security Policy in place — same wire
    /// shape as [`Self::add_sp`] but with
    /// `NLM_F_CREATE | NLM_F_REPLACE`. Match key is the
    /// `(selector, dir)` from the body.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "update_sp"))]
    pub async fn update_sp(&self, sp: XfrmSpBuilder) -> Result<()> {
        let mut b = MessageBuilder::new(
            XFRM_MSG_NEWPOLICY,
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE,
        );
        sp.write_into(&mut b);
        self.send_ack(b).await
    }

    /// Delete a Security Policy by `(selector, direction)`.
    /// Sends `XFRM_MSG_DELPOLICY` with an `XfrmUserpolicyId` body.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "del_sp"))]
    pub async fn del_sp(&self, sel: XfrmSelector, direction: PolicyDirection) -> Result<()> {
        let mut b = MessageBuilder::new(XFRM_MSG_DELPOLICY, NLM_F_REQUEST | NLM_F_ACK);
        let id = XfrmUserpolicyId {
            sel,
            index: 0,
            dir: direction.number(),
            _pad: [0; 7],
        };
        b.append_bytes(id.as_bytes());
        self.send_ack(b).await
    }

    /// Flush every Security Policy in the kernel's database.
    /// Sends `XFRM_MSG_FLUSHPOLICY`.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "flush_sp"))]
    pub async fn flush_sp(&self) -> Result<()> {
        let b = MessageBuilder::new(XFRM_MSG_FLUSHPOLICY, NLM_F_REQUEST | NLM_F_ACK);
        self.send_ack(b).await
    }

    /// Fetch a single Security Policy by `(selector, direction)`.
    /// Returns `Ok(None)` if no policy matches.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_sp"))]
    pub async fn get_sp(
        &self,
        sel: XfrmSelector,
        direction: PolicyDirection,
    ) -> Result<Option<SecurityPolicy>> {
        let mut b = MessageBuilder::new(XFRM_MSG_GETPOLICY, NLM_F_REQUEST);
        let id = XfrmUserpolicyId {
            sel,
            index: 0,
            dir: direction.number(),
            _pad: [0; 7],
        };
        b.append_bytes(id.as_bytes());

        match self.send_request(b).await {
            Ok(response) => Ok(Self::parse_policy_msg(&response)),
            Err(e) if e.is_not_found() => Ok(None),
            Err(e) => Err(e),
        }
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
    #[tracing::instrument(
        level = "debug",
        skip_all,
        fields(method = "get_security_associations")
    )]
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
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_security_policies"))]
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
        Self::parse_sa_msg(data)
    }

    /// Parse a Security Association from a netlink message buffer
    /// (`nlmsghdr` + `xfrm_usersa_info` + attributes). Associated
    /// function (no `&self`) so unit tests can call it via
    /// `Connection::<Xfrm>::parse_sa_msg(...)` without needing a
    /// live socket.
    fn parse_sa_msg(data: &[u8]) -> Option<SecurityAssociation> {
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
                    XFRMA_IF_ID if attr_data.len() >= 4 => {
                        sa.if_id = Some(u32::from_ne_bytes([
                            attr_data[0],
                            attr_data[1],
                            attr_data[2],
                            attr_data[3],
                        ]));
                    }
                    _ => {}
                }
            }
        }

        Some(sa)
    }

    /// Parse a Security Policy from a netlink message.
    fn parse_policy(&self, data: &[u8]) -> Option<SecurityPolicy> {
        Self::parse_policy_msg(data)
    }

    /// Parse a Security Policy from a netlink message buffer.
    /// Associated function so unit tests can call it via
    /// `Connection::<Xfrm>::parse_policy_msg(...)` without a live
    /// socket.
    fn parse_policy_msg(data: &[u8]) -> Option<SecurityPolicy> {
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
                    XFRMA_IF_ID if attr_data.len() >= 4 => {
                        policy.if_id = Some(u32::from_ne_bytes([
                            attr_data[0],
                            attr_data[1],
                            attr_data[2],
                            attr_data[3],
                        ]));
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
        // New write-path structs:
        assert_eq!(std::mem::size_of::<XfrmUsersaId>(), 24);
        assert_eq!(std::mem::size_of::<XfrmUsersaFlush>(), 8);
    }

    // ==========================================================
    // XfrmSaBuilder — Plan 141 PR A wire-format round-trip tests
    // ==========================================================

    use super::Connection;
    use super::Xfrm;

    /// Build an `add_sa` request via XfrmSaBuilder + MessageBuilder
    /// and return the full netlink frame (header + body + attrs).
    fn build_add_sa_frame(sa: XfrmSaBuilder) -> Vec<u8> {
        let mut b = MessageBuilder::new(
            XFRM_MSG_NEWSA,
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
        );
        sa.write_into(&mut b);
        b.finish()
    }

    #[test]
    fn xfrm_sa_v4_esp_separate_auth_encr_roundtrips_through_parse_sa() {
        let sa = XfrmSaBuilder::new(
            "10.0.0.1".parse().unwrap(),
            "10.0.0.2".parse().unwrap(),
            0xdead_beef,
            IpsecProtocol::Esp,
        )
        .mode(XfrmMode::Tunnel)
        .reqid(42)
        .auth_hmac_sha256(&[0u8; 32])
        .encr_aes_cbc(&[0u8; 16]);

        let frame = build_add_sa_frame(sa);
        let parsed = Connection::<Xfrm>::parse_sa_msg(&frame)
            .expect("parse_sa must round-trip XfrmSaBuilder output");

        assert_eq!(
            parsed.src_addr,
            Some(IpAddr::V4("10.0.0.1".parse().unwrap()))
        );
        assert_eq!(
            parsed.dst_addr,
            Some(IpAddr::V4("10.0.0.2".parse().unwrap()))
        );
        assert_eq!(parsed.spi, 0xdead_beef);
        assert_eq!(parsed.protocol, IpsecProtocol::Esp);
        assert_eq!(parsed.mode, XfrmMode::Tunnel);
        assert_eq!(parsed.reqid, 42);
        assert_eq!(parsed.replay_window, 32, "default replay window");

        let auth = parsed.auth_alg.expect("auth alg present");
        assert_eq!(auth.name, "hmac(sha256)");
        assert_eq!(auth.key_len, 32 * 8, "key_len_bits");
        assert_eq!(auth.key.len(), 32);

        let encr = parsed.enc_alg.expect("encr alg present");
        assert_eq!(encr.name, "cbc(aes)");
        assert_eq!(encr.key_len, 16 * 8);
        assert_eq!(encr.key.len(), 16);
    }

    #[test]
    fn xfrm_sa_v4_esp_aead_aes_gcm_roundtrips() {
        // AEAD AES-GCM-128: 16-byte key + 4-byte salt = 20 bytes;
        // ICV truncbits = 128.
        let key = [0xAAu8; 20];
        let sa = XfrmSaBuilder::new(
            "192.0.2.1".parse().unwrap(),
            "192.0.2.2".parse().unwrap(),
            0x12345678,
            IpsecProtocol::Esp,
        )
        .mode(XfrmMode::Transport)
        .reqid(7)
        .aead_aes_gcm(&key, 128);

        let frame = build_add_sa_frame(sa);
        let parsed = Connection::<Xfrm>::parse_sa_msg(&frame)
            .expect("parse_sa must round-trip AEAD SA");

        assert_eq!(parsed.spi, 0x12345678);
        assert_eq!(parsed.mode, XfrmMode::Transport);
        let aead = parsed.aead_alg.expect("aead alg present");
        assert_eq!(aead.name, "rfc4106(gcm(aes))");
        assert_eq!(aead.key_len, key.len() as u32 * 8);
        assert_eq!(aead.icv_len, 128);
        assert_eq!(aead.key.len(), 20);
        assert!(parsed.auth_alg.is_none());
        assert!(parsed.enc_alg.is_none());
    }

    #[test]
    fn xfrm_sa_v6_separate_auth_encr_roundtrips() {
        let sa = XfrmSaBuilder::new(
            "2001:db8::1".parse().unwrap(),
            "2001:db8::2".parse().unwrap(),
            0xCAFEBABE,
            IpsecProtocol::Esp,
        )
        .mode(XfrmMode::Tunnel)
        .reqid(99)
        .auth_hmac_sha256(&[0xBBu8; 32])
        .encr_aes_cbc(&[0xCCu8; 32]); // AES-256

        let frame = build_add_sa_frame(sa);
        let parsed = Connection::<Xfrm>::parse_sa_msg(&frame)
            .expect("parse_sa must round-trip v6 SA");

        assert_eq!(
            parsed.src_addr,
            Some(IpAddr::V6("2001:db8::1".parse().unwrap()))
        );
        assert_eq!(
            parsed.dst_addr,
            Some(IpAddr::V6("2001:db8::2".parse().unwrap()))
        );
        assert_eq!(parsed.spi, 0xCAFEBABE);
        let encr = parsed.enc_alg.unwrap();
        assert_eq!(encr.key_len, 256, "AES-256 key length in bits");
    }

    #[test]
    fn xfrm_sa_nat_t_udp_encap_roundtrips() {
        let sa = XfrmSaBuilder::new(
            "10.0.0.1".parse().unwrap(),
            "10.0.0.2".parse().unwrap(),
            0x1000,
            IpsecProtocol::Esp,
        )
        .nat_t_udp_encap(4500, 4500) // both 4500 → IKE-compatible
        .auth_hmac_sha256(&[0u8; 32])
        .encr_aes_cbc(&[0u8; 16]);

        let frame = build_add_sa_frame(sa);
        let parsed = Connection::<Xfrm>::parse_sa_msg(&frame)
            .expect("parse_sa must round-trip NAT-T SA");

        let encap = parsed.encap.expect("XFRMA_ENCAP must be present");
        // sport/dport are stored network-byte-order on the wire; the
        // parser doesn't byte-swap them. Compare the wire form.
        assert_eq!(encap.encap_sport, 4500u16.to_be());
        assert_eq!(encap.encap_dport, 4500u16.to_be());
        assert_eq!(encap.encap_type, 2, "dport=4500 → ESPINUDP (IKE)");
    }

    #[test]
    fn xfrm_del_sa_emits_correct_tuple() {
        let mut b = MessageBuilder::new(XFRM_MSG_DELSA, NLM_F_REQUEST | NLM_F_ACK);
        let id = XfrmUsersaId {
            daddr: ip_to_xfrm_addr("10.0.0.2".parse().unwrap()),
            spi: 0xdead_beef_u32.to_be(),
            family: libc::AF_INET as u16,
            proto: IpsecProtocol::Esp.number(),
            _pad: 0,
        };
        b.append_bytes(id.as_bytes());
        let frame = b.finish();

        // Frame layout: 16-byte nlmsghdr + 24-byte XfrmUsersaId.
        assert!(frame.len() >= 16 + 24);
        let id_bytes = &frame[16..16 + 24];
        let (got, _) = XfrmUsersaId::ref_from_prefix(id_bytes).unwrap();
        assert_eq!(got.daddr.to_ip(libc::AF_INET as u16),
                   Some(IpAddr::V4("10.0.0.2".parse().unwrap())));
        assert_eq!(u32::from_be(got.spi), 0xdead_beef);
        assert_eq!(got.family, libc::AF_INET as u16);
        assert_eq!(got.proto, IpsecProtocol::Esp.number());
    }

    #[test]
    fn xfrm_flush_sa_proto_zero_means_all() {
        let mut b = MessageBuilder::new(XFRM_MSG_FLUSHSA, NLM_F_REQUEST | NLM_F_ACK);
        let body = XfrmUsersaFlush { proto: 0, _pad: [0; 7] };
        b.append_bytes(body.as_bytes());
        let frame = b.finish();

        assert!(frame.len() >= 16 + 8);
        assert_eq!(frame[16], 0, "proto=0 = IPSEC_PROTO_ANY");
    }

    #[test]
    fn xfrm_sa_default_replay_window_is_32() {
        // The kernel's default of 0 disables replay protection,
        // which is a footgun. Builder defaults to 32 like iproute2.
        let sa = XfrmSaBuilder::new(
            "10.0.0.1".parse().unwrap(),
            "10.0.0.2".parse().unwrap(),
            1,
            IpsecProtocol::Esp,
        );
        let info = sa.build_usersa_info();
        assert_eq!(info.replay_window, 32);
    }

    // ==========================================================
    // Slice 2 — update_sa, flush_sa_proto, get_sa
    // ==========================================================

    fn build_update_sa_frame(sa: XfrmSaBuilder) -> Vec<u8> {
        let mut b = MessageBuilder::new(
            XFRM_MSG_NEWSA,
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE,
        );
        sa.write_into(&mut b);
        b.finish()
    }

    #[test]
    fn xfrm_update_sa_uses_create_and_replace_flags_not_excl() {
        let sa = XfrmSaBuilder::new(
            "10.0.0.1".parse().unwrap(),
            "10.0.0.2".parse().unwrap(),
            0xdead_beef,
            IpsecProtocol::Esp,
        )
        .auth_hmac_sha256(&[0u8; 32])
        .encr_aes_cbc(&[0u8; 16]);

        let frame = build_update_sa_frame(sa);

        // nlmsghdr.flags is at offset 6..8 (after len + type).
        let flags = u16::from_le_bytes([frame[6], frame[7]]);
        let want = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE;
        assert_eq!(flags, want, "update_sa must set CREATE+REPLACE, not EXCL");
        assert_eq!(flags & NLM_F_EXCL, 0, "EXCL must NOT be set");
    }

    #[test]
    fn xfrm_update_sa_body_round_trips_like_add_sa() {
        // The body bytes are identical to add_sa — only nlmsghdr
        // flags differ. Verify the SA payload still parses.
        let sa = XfrmSaBuilder::new(
            "10.0.0.1".parse().unwrap(),
            "10.0.0.2".parse().unwrap(),
            0xCAFE,
            IpsecProtocol::Esp,
        )
        .reqid(11)
        .aead_aes_gcm(&[0xAAu8; 20], 128);

        let frame = build_update_sa_frame(sa);
        let parsed = Connection::<Xfrm>::parse_sa_msg(&frame)
            .expect("parse_sa must round-trip update_sa body");
        assert_eq!(parsed.spi, 0xCAFE);
        assert_eq!(parsed.reqid, 11);
        assert!(parsed.aead_alg.is_some());
    }

    #[test]
    fn xfrm_flush_sa_proto_writes_specific_proto_byte() {
        // Frame layout: 16-byte nlmsghdr + 8-byte XfrmUsersaFlush;
        // the proto byte sits at offset 16.
        let mut b = MessageBuilder::new(XFRM_MSG_FLUSHSA, NLM_F_REQUEST | NLM_F_ACK);
        let body = XfrmUsersaFlush {
            proto: IpsecProtocol::Esp.number(),
            _pad: [0; 7],
        };
        b.append_bytes(body.as_bytes());
        let frame = b.finish();

        assert!(frame.len() >= 16 + 8);
        assert_eq!(frame[16], 50, "proto=ESP=50");
        // Padding bytes stay zero.
        for &b in &frame[17..24] {
            assert_eq!(b, 0, "flush body padding must be zero");
        }
    }

    // ==========================================================
    // XfrmSpBuilder — Plan 141 PR B SP CRUD wire-format tests
    // ==========================================================

    fn ipv4_subnet_selector(family: u16) -> XfrmSelector {
        XfrmSelector {
            family,
            ..Default::default()
        }
    }

    fn build_add_sp_frame(sp: XfrmSpBuilder) -> Vec<u8> {
        let mut b = MessageBuilder::new(
            XFRM_MSG_NEWPOLICY,
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
        );
        sp.write_into(&mut b);
        b.finish()
    }

    #[test]
    fn xfrm_sp_out_with_one_tmpl_roundtrips() {
        let sel = ipv4_subnet_selector(libc::AF_INET as u16);
        let tmpl = XfrmUserTmpl::match_any(
            "10.0.0.1".parse().unwrap(),
            "10.0.0.2".parse().unwrap(),
            IpsecProtocol::Esp,
            XfrmMode::Tunnel,
            42,
        );
        let sp = XfrmSpBuilder::new(sel, PolicyDirection::Out)
            .priority(100)
            .template(tmpl);

        let frame = build_add_sp_frame(sp);
        let parsed = Connection::<Xfrm>::parse_policy_msg(&frame)
            .expect("parse_policy must round-trip XfrmSpBuilder output");

        assert_eq!(parsed.direction, PolicyDirection::Out);
        assert_eq!(parsed.action, PolicyAction::Allow, "default action");
        assert_eq!(parsed.priority, 100);
    }

    #[test]
    fn xfrm_sp_in_with_two_tmpls_packs_array() {
        // Inbound chain: ESP outer + AH inner.
        let sel = ipv4_subnet_selector(libc::AF_INET as u16);
        let esp = XfrmUserTmpl::match_any(
            "10.0.0.1".parse().unwrap(),
            "10.0.0.2".parse().unwrap(),
            IpsecProtocol::Esp,
            XfrmMode::Tunnel,
            1,
        );
        let ah = XfrmUserTmpl::match_any(
            "10.0.0.1".parse().unwrap(),
            "10.0.0.2".parse().unwrap(),
            IpsecProtocol::Ah,
            XfrmMode::Tunnel,
            2,
        );
        let sp = XfrmSpBuilder::new(sel, PolicyDirection::In)
            .template(esp)
            .template(ah);

        let frame = build_add_sp_frame(sp);
        let parsed = Connection::<Xfrm>::parse_policy_msg(&frame)
            .expect("parse_policy must round-trip nested-tmpl SP");

        assert_eq!(parsed.direction, PolicyDirection::In);
        // The current parse_policy doesn't expose the templates list,
        // but we can verify XFRMA_TMPL is present in the wire bytes
        // and that it carries 2 * size_of::<XfrmUserTmpl>() bytes.
        let tmpl_size = std::mem::size_of::<XfrmUserTmpl>();
        let want_attr_payload_len = 2 * tmpl_size;
        let attr_present = frame.windows(2).any(|w| {
            // Look for the XFRMA_TMPL nlattr type byte. nlattr is
            // {len: u16, type: u16}; type is at +2.
            u16::from_le_bytes([w[0], w[1]]) == want_attr_payload_len as u16 + 4
        });
        assert!(
            attr_present,
            "XFRMA_TMPL attr should carry 2*sizeof(XfrmUserTmpl) bytes"
        );
    }

    #[test]
    fn xfrm_sp_block_action_no_templates() {
        let sel = ipv4_subnet_selector(libc::AF_INET as u16);
        let sp = XfrmSpBuilder::new(sel, PolicyDirection::Out).block();

        let frame = build_add_sp_frame(sp);
        let parsed = Connection::<Xfrm>::parse_policy_msg(&frame)
            .expect("parse_policy must round-trip block SP");
        assert_eq!(parsed.action, PolicyAction::Block);
    }

    #[test]
    fn xfrm_del_sp_emits_selector_plus_dir() {
        let sel = ipv4_subnet_selector(libc::AF_INET as u16);
        let mut b = MessageBuilder::new(XFRM_MSG_DELPOLICY, NLM_F_REQUEST | NLM_F_ACK);
        let id = XfrmUserpolicyId {
            sel,
            index: 0,
            dir: PolicyDirection::Out.number(),
            _pad: [0; 7],
        };
        b.append_bytes(id.as_bytes());
        let frame = b.finish();

        // nlmsg_type = DELPOLICY (offset 4..6)
        assert_eq!(
            u16::from_le_bytes([frame[4], frame[5]]),
            XFRM_MSG_DELPOLICY
        );

        // XfrmUserpolicyId starts at offset 16. Direction byte
        // sits at offset 16 + size_of::<XfrmSelector>() + 4 (index).
        let sel_size = std::mem::size_of::<XfrmSelector>();
        let dir_off = 16 + sel_size + 4;
        assert_eq!(frame[dir_off], XFRM_POLICY_OUT);
    }

    #[test]
    fn xfrm_get_sp_request_uses_request_only_flags() {
        let sel = ipv4_subnet_selector(libc::AF_INET as u16);
        let mut b = MessageBuilder::new(XFRM_MSG_GETPOLICY, NLM_F_REQUEST);
        let id = XfrmUserpolicyId {
            sel,
            index: 0,
            dir: PolicyDirection::In.number(),
            _pad: [0; 7],
        };
        b.append_bytes(id.as_bytes());
        let frame = b.finish();

        let nlmsg_type = u16::from_le_bytes([frame[4], frame[5]]);
        assert_eq!(nlmsg_type, XFRM_MSG_GETPOLICY);
        let flags = u16::from_le_bytes([frame[6], frame[7]]);
        assert_eq!(flags & NLM_F_DUMP, 0, "get_sp must NOT use DUMP");
        assert_eq!(flags & NLM_F_ACK, 0, "get_sp must NOT use ACK");
        assert!(flags & NLM_F_REQUEST != 0);
    }

    #[test]
    fn xfrm_flush_sp_has_no_body() {
        let b = MessageBuilder::new(XFRM_MSG_FLUSHPOLICY, NLM_F_REQUEST | NLM_F_ACK);
        let frame = b.finish();
        // Just the 16-byte nlmsghdr — no XfrmUserpolicyId body.
        assert_eq!(frame.len(), 16);
        assert_eq!(
            u16::from_le_bytes([frame[4], frame[5]]),
            XFRM_MSG_FLUSHPOLICY
        );
    }

    #[test]
    fn xfrm_user_tmpl_sets_default_algo_bitmasks_to_max() {
        // The "any algorithm" default is u32::MAX on all three
        // bitmasks — the kernel matches any SA whose algorithms
        // intersect this mask.
        let t = XfrmUserTmpl::match_any(
            "10.0.0.1".parse().unwrap(),
            "10.0.0.2".parse().unwrap(),
            IpsecProtocol::Esp,
            XfrmMode::Tunnel,
            0,
        );
        let aalgos = t.aalgos;
        let ealgos = t.ealgos;
        let calgos = t.calgos;
        assert_eq!(aalgos, u32::MAX);
        assert_eq!(ealgos, u32::MAX);
        assert_eq!(calgos, u32::MAX);
    }

    #[test]
    fn policy_direction_to_u8_round_trips() {
        for dir in [PolicyDirection::In, PolicyDirection::Out, PolicyDirection::Forward] {
            assert_eq!(PolicyDirection::from_u8(dir.number()), dir);
        }
    }

    #[test]
    fn xfrm_get_sa_request_carries_lookup_tuple() {
        // get_sa builds the same XfrmUsersaId body as del_sa, but
        // with XFRM_MSG_GETSA + NLM_F_REQUEST (no DUMP, no ACK).
        let mut b = MessageBuilder::new(XFRM_MSG_GETSA, NLM_F_REQUEST);
        let id = XfrmUsersaId {
            daddr: ip_to_xfrm_addr("192.0.2.10".parse().unwrap()),
            spi: 0x1234_5678_u32.to_be(),
            family: libc::AF_INET as u16,
            proto: IpsecProtocol::Ah.number(),
            _pad: 0,
        };
        b.append_bytes(id.as_bytes());
        let saddr = ip_to_xfrm_addr("192.0.2.1".parse().unwrap());
        b.append_attr(XFRMA_SRCADDR, &saddr.bytes);
        let frame = b.finish();

        // nlmsg_type at offset 4..6
        let nlmsg_type = u16::from_le_bytes([frame[4], frame[5]]);
        assert_eq!(nlmsg_type, XFRM_MSG_GETSA);

        // nlmsg_flags at offset 6..8 — REQUEST only, no DUMP / ACK.
        let flags = u16::from_le_bytes([frame[6], frame[7]]);
        assert_eq!(flags & NLM_F_DUMP, 0, "get_sa must NOT use DUMP");
        assert_eq!(flags & NLM_F_ACK, 0, "get_sa must NOT use ACK");
        assert!(flags & NLM_F_REQUEST != 0);

        // XfrmUsersaId at offset 16..40
        let (got, _) = XfrmUsersaId::ref_from_prefix(&frame[16..16 + 24]).unwrap();
        assert_eq!(u32::from_be(got.spi), 0x1234_5678);
        assert_eq!(got.proto, IpsecProtocol::Ah.number());
    }
}
