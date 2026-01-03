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

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use winnow::binary::be_u16;
use winnow::prelude::*;

use super::connection::Connection;
use super::error::Result;
use super::parse::PResult;
use super::protocol::{Netfilter, ProtocolState};
use super::socket::NetlinkSocket;

// Netlink constants
const NLMSG_DONE: u16 = 3;
const NLMSG_ERROR: u16 = 2;
const NLM_F_REQUEST: u16 = 0x01;
const NLM_F_DUMP: u16 = 0x300;

// Netfilter subsystem IDs
const NFNL_SUBSYS_CTNETLINK: u8 = 1;

// Conntrack message types
const IPCTNL_MSG_CT_GET: u8 = 1;

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
    /// Create a new netfilter connection.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use nlink::netlink::{Connection, Netfilter};
    ///
    /// let conn = Connection::<Netfilter>::new()?;
    /// ```
    pub fn new() -> Result<Self> {
        let socket = NetlinkSocket::new(Netfilter::PROTOCOL)?;
        Ok(Self::from_parts(socket, Netfilter))
    }

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
    pub async fn get_conntrack(&self) -> Result<Vec<ConntrackEntry>> {
        self.get_conntrack_family(libc::AF_INET as u8).await
    }

    /// Get connection tracking entries for IPv6.
    pub async fn get_conntrack_v6(&self) -> Result<Vec<ConntrackEntry>> {
        self.get_conntrack_family(libc::AF_INET6 as u8).await
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
                CTA_STATUS => {
                    if attr_data.len() >= 4 {
                        entry.status = Some(u32::from_be_bytes([
                            attr_data[0],
                            attr_data[1],
                            attr_data[2],
                            attr_data[3],
                        ]));
                    }
                }
                CTA_TIMEOUT => {
                    if attr_data.len() >= 4 {
                        entry.timeout = Some(u32::from_be_bytes([
                            attr_data[0],
                            attr_data[1],
                            attr_data[2],
                            attr_data[3],
                        ]));
                    }
                }
                CTA_MARK => {
                    if attr_data.len() >= 4 {
                        entry.mark = Some(u32::from_be_bytes([
                            attr_data[0],
                            attr_data[1],
                            attr_data[2],
                            attr_data[3],
                        ]));
                    }
                }
                CTA_ID => {
                    if attr_data.len() >= 4 {
                        entry.id = Some(u32::from_be_bytes([
                            attr_data[0],
                            attr_data[1],
                            attr_data[2],
                            attr_data[3],
                        ]));
                    }
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
                CTA_IP_V4_SRC => {
                    if attr_data.len() >= 4 {
                        tuple.src_ip = Some(IpAddr::V4(Ipv4Addr::new(
                            attr_data[0],
                            attr_data[1],
                            attr_data[2],
                            attr_data[3],
                        )));
                    }
                }
                CTA_IP_V4_DST => {
                    if attr_data.len() >= 4 {
                        tuple.dst_ip = Some(IpAddr::V4(Ipv4Addr::new(
                            attr_data[0],
                            attr_data[1],
                            attr_data[2],
                            attr_data[3],
                        )));
                    }
                }
                CTA_IP_V6_SRC => {
                    if attr_data.len() >= 16 {
                        let mut octets = [0u8; 16];
                        octets.copy_from_slice(&attr_data[..16]);
                        tuple.src_ip = Some(IpAddr::V6(Ipv6Addr::from(octets)));
                    }
                }
                CTA_IP_V6_DST => {
                    if attr_data.len() >= 16 {
                        let mut octets = [0u8; 16];
                        octets.copy_from_slice(&attr_data[..16]);
                        tuple.dst_ip = Some(IpAddr::V6(Ipv6Addr::from(octets)));
                    }
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
                CTA_PROTO_NUM => {
                    if !attr_data.is_empty() {
                        proto = IpProtocol::from_u8(attr_data[0]);
                    }
                }
                CTA_PROTO_SRC_PORT => {
                    if attr_data.len() >= 2 {
                        tuple.src_port = Some(u16::from_be_bytes([attr_data[0], attr_data[1]]));
                    }
                }
                CTA_PROTO_DST_PORT => {
                    if attr_data.len() >= 2 {
                        tuple.dst_port = Some(u16::from_be_bytes([attr_data[0], attr_data[1]]));
                    }
                }
                CTA_PROTO_ICMP_ID => {
                    if attr_data.len() >= 2 {
                        tuple.icmp_id = Some(u16::from_be_bytes([attr_data[0], attr_data[1]]));
                    }
                }
                CTA_PROTO_ICMP_TYPE => {
                    if !attr_data.is_empty() {
                        tuple.icmp_type = Some(attr_data[0]);
                    }
                }
                CTA_PROTO_ICMP_CODE => {
                    if !attr_data.is_empty() {
                        tuple.icmp_code = Some(attr_data[0]);
                    }
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
                CTA_COUNTERS_PACKETS => {
                    if attr_data.len() >= 8 {
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
                }
                CTA_COUNTERS_BYTES => {
                    if attr_data.len() >= 8 {
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
}
