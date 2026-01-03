//! Socket diagnostics implementation for `Connection<SockDiag>`.
//!
//! This module provides methods for querying socket information via the
//! NETLINK_SOCK_DIAG protocol, integrated into the Connection pattern.
//!
//! # Example
//!
//! ```ignore
//! use nlink::netlink::{Connection, SockDiag};
//! use nlink::sockdiag::{SocketFilter, TcpState};
//!
//! let conn = Connection::<SockDiag>::new()?;
//!
//! // Query all TCP sockets
//! let sockets = conn.query_tcp().await?;
//!
//! // Query with filter
//! let filter = SocketFilter::tcp()
//!     .listening()
//!     .with_tcp_info()
//!     .build();
//! let sockets = conn.query(&filter).await?;
//! ```

use std::net::{IpAddr, SocketAddr};

use super::connection::Connection;
use super::error::Result;
use super::protocol::SockDiag;

// Re-export sockdiag types that are needed for the API
pub use crate::sockdiag::filter::{
    FilterKind, InetFilter, NetlinkFilter, PacketFilter, SocketFilter, UnixFilter,
};
pub use crate::sockdiag::socket::{InetSocket, SocketInfo, UnixSocket, UnixType};
pub use crate::sockdiag::types::{
    AddressFamily, MemInfo, Protocol as InetProtocol, SocketState, TcpInfo, TcpState, Timer,
};

// Netlink constants
const NLMSG_DONE: u16 = 3;
const NLMSG_ERROR: u16 = 2;
const NLM_F_REQUEST: u16 = 0x01;
const NLM_F_ROOT: u16 = 0x100;
const NLM_F_MATCH: u16 = 0x200;
const NLM_F_DUMP: u16 = NLM_F_ROOT | NLM_F_MATCH;

// Socket diagnostics constants
const SOCK_DIAG_BY_FAMILY: u16 = 20;
const TCPDIAG_GETSOCK: u16 = 18;

// Inet diag extensions
const INET_DIAG_MEMINFO: u16 = 1;
const INET_DIAG_INFO: u16 = 2;
const INET_DIAG_CONG: u16 = 4;
const INET_DIAG_TOS: u16 = 5;
const INET_DIAG_TCLASS: u16 = 6;
const INET_DIAG_SKMEMINFO: u16 = 7;
const INET_DIAG_SHUTDOWN: u16 = 8;
const INET_DIAG_MARK: u16 = 15;
const INET_DIAG_CGROUP_ID: u16 = 21;
const INET_DIAG_SKV6ONLY: u16 = 11;

// Unix diag attributes
const UNIX_DIAG_NAME: u16 = 0;
const UNIX_DIAG_VFS: u16 = 1;
const UNIX_DIAG_PEER: u16 = 2;
const UNIX_DIAG_ICONS: u16 = 3;
const UNIX_DIAG_RQLEN: u16 = 4;
const UNIX_DIAG_MEMINFO: u16 = 5;
const UNIX_DIAG_SHUTDOWN: u16 = 6;
const UNIX_DIAG_UID: u16 = 7;

impl Connection<SockDiag> {
    /// Query sockets matching the given filter.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use nlink::netlink::{Connection, SockDiag};
    /// use nlink::sockdiag::SocketFilter;
    ///
    /// let conn = Connection::<SockDiag>::new()?;
    /// let filter = SocketFilter::tcp().listening().build();
    /// let sockets = conn.query(&filter).await?;
    /// ```
    pub async fn query(&self, filter: &SocketFilter) -> Result<Vec<SocketInfo>> {
        match &filter.kind {
            FilterKind::Inet(f) => self.query_inet(f).await,
            FilterKind::Unix(f) => self.query_unix(f).await,
            FilterKind::Netlink(f) => self.query_netlink(f).await,
            FilterKind::Packet(f) => self.query_packet(f).await,
        }
    }

    /// Query TCP sockets with default filter.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use nlink::netlink::{Connection, SockDiag};
    ///
    /// let conn = Connection::<SockDiag>::new()?;
    /// let sockets = conn.query_tcp().await?;
    /// for sock in sockets {
    ///     println!("{} -> {}", sock.local, sock.remote);
    /// }
    /// ```
    pub async fn query_tcp(&self) -> Result<Vec<InetSocket>> {
        let filter = InetFilter {
            protocol: InetProtocol::Tcp,
            ..Default::default()
        };
        self.query_inet_typed(&filter).await
    }

    /// Query UDP sockets with default filter.
    pub async fn query_udp(&self) -> Result<Vec<InetSocket>> {
        let filter = InetFilter {
            protocol: InetProtocol::Udp,
            ..Default::default()
        };
        self.query_inet_typed(&filter).await
    }

    /// Query Unix sockets with default filter.
    pub async fn query_unix_sockets(&self) -> Result<Vec<UnixSocket>> {
        let filter = UnixFilter::default();
        self.query_unix_typed(&filter).await
    }

    async fn query_inet(&self, filter: &InetFilter) -> Result<Vec<SocketInfo>> {
        let sockets = self.query_inet_typed(filter).await?;
        Ok(sockets
            .into_iter()
            .map(|s| SocketInfo::Inet(Box::new(s)))
            .collect())
    }

    async fn query_inet_typed(&self, filter: &InetFilter) -> Result<Vec<InetSocket>> {
        let mut results = Vec::new();

        // Query IPv4 if not filtering to IPv6 only
        if filter.family.is_none() || filter.family == Some(AddressFamily::Inet) {
            let sockets = self.query_inet_family(filter, AddressFamily::Inet).await?;
            results.extend(sockets);
        }

        // Query IPv6 if not filtering to IPv4 only
        if filter.family.is_none() || filter.family == Some(AddressFamily::Inet6) {
            let sockets = self.query_inet_family(filter, AddressFamily::Inet6).await?;
            results.extend(sockets);
        }

        Ok(results)
    }

    async fn query_inet_family(
        &self,
        filter: &InetFilter,
        family: AddressFamily,
    ) -> Result<Vec<InetSocket>> {
        let seq = self.socket().next_seq();
        let pid = self.socket().pid();

        // Build request
        let mut buf = Vec::with_capacity(256);

        // Netlink header (16 bytes)
        let msg_type = SOCK_DIAG_BY_FAMILY;

        // Will fill in length later
        buf.extend_from_slice(&0u32.to_ne_bytes()); // nlmsg_len
        buf.extend_from_slice(&msg_type.to_ne_bytes()); // nlmsg_type
        buf.extend_from_slice(&(NLM_F_REQUEST | NLM_F_DUMP).to_ne_bytes()); // nlmsg_flags
        buf.extend_from_slice(&seq.to_ne_bytes()); // nlmsg_seq
        buf.extend_from_slice(&pid.to_ne_bytes()); // nlmsg_pid

        // inet_diag_req_v2 structure (56 bytes)
        buf.push(family as u8); // sdiag_family
        buf.push(filter.protocol.number()); // sdiag_protocol
        buf.push(filter.extensions); // idiag_ext
        buf.push(0); // pad
        buf.extend_from_slice(&filter.states.to_ne_bytes()); // idiag_states

        // inet_diag_sockid (48 bytes)
        buf.extend_from_slice(&0u16.to_be_bytes()); // idiag_sport
        buf.extend_from_slice(&0u16.to_be_bytes()); // idiag_dport
        buf.extend_from_slice(&[0u8; 16]); // idiag_src
        buf.extend_from_slice(&[0u8; 16]); // idiag_dst
        buf.extend_from_slice(&0u32.to_ne_bytes()); // idiag_if
        buf.extend_from_slice(&[0u8; 8]); // idiag_cookie

        // Update length
        let len = buf.len() as u32;
        buf[0..4].copy_from_slice(&len.to_ne_bytes());

        // Send request
        self.socket().send(&buf).await?;

        // Receive responses
        let mut sockets = Vec::new();

        loop {
            let data: Vec<u8> = self.socket().recv_msg().await?;

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
                    NLMSG_DONE => return Ok(sockets),
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
                    SOCK_DIAG_BY_FAMILY | TCPDIAG_GETSOCK => {
                        if let Some(sock) =
                            parse_inet_msg(&data[offset..offset + nlmsg_len], filter.protocol)
                        {
                            sockets.push(sock);
                        }
                    }
                    _ => {}
                }

                // Align to 4 bytes
                offset += (nlmsg_len + 3) & !3;
            }
        }
    }

    async fn query_unix(&self, filter: &UnixFilter) -> Result<Vec<SocketInfo>> {
        let sockets = self.query_unix_typed(filter).await?;
        Ok(sockets.into_iter().map(SocketInfo::Unix).collect())
    }

    async fn query_unix_typed(&self, filter: &UnixFilter) -> Result<Vec<UnixSocket>> {
        let seq = self.socket().next_seq();
        let pid = self.socket().pid();

        // Build request
        let mut buf = Vec::with_capacity(64);

        // Netlink header (16 bytes)
        buf.extend_from_slice(&0u32.to_ne_bytes()); // nlmsg_len (fill later)
        buf.extend_from_slice(&SOCK_DIAG_BY_FAMILY.to_ne_bytes()); // nlmsg_type
        buf.extend_from_slice(&(NLM_F_REQUEST | NLM_F_DUMP).to_ne_bytes()); // nlmsg_flags
        buf.extend_from_slice(&seq.to_ne_bytes()); // nlmsg_seq
        buf.extend_from_slice(&pid.to_ne_bytes()); // nlmsg_pid

        // unix_diag_req structure (20 bytes)
        buf.push(libc::AF_UNIX as u8); // sdiag_family
        buf.push(0); // sdiag_protocol
        buf.extend_from_slice(&0u16.to_ne_bytes()); // pad
        buf.extend_from_slice(&filter.states.to_ne_bytes()); // udiag_states
        buf.extend_from_slice(&filter.inode.unwrap_or(0).to_ne_bytes()); // udiag_ino
        buf.extend_from_slice(&filter.show.to_ne_bytes()); // udiag_show
        buf.extend_from_slice(&[0u8; 8]); // udiag_cookie

        // Update length
        let len = buf.len() as u32;
        buf[0..4].copy_from_slice(&len.to_ne_bytes());

        // Send request
        self.socket().send(&buf).await?;

        // Receive responses
        let mut sockets = Vec::new();

        loop {
            let data: Vec<u8> = self.socket().recv_msg().await?;

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
                    NLMSG_DONE => return Ok(sockets),
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
                    SOCK_DIAG_BY_FAMILY => {
                        if let Some(sock) = parse_unix_msg(&data[offset..offset + nlmsg_len]) {
                            sockets.push(sock);
                        }
                    }
                    _ => {}
                }

                offset += (nlmsg_len + 3) & !3;
            }
        }
    }

    async fn query_netlink(&self, _filter: &NetlinkFilter) -> Result<Vec<SocketInfo>> {
        // Netlink socket diagnostics - simplified for now
        Ok(Vec::new())
    }

    async fn query_packet(&self, _filter: &PacketFilter) -> Result<Vec<SocketInfo>> {
        // Packet socket diagnostics - simplified for now
        Ok(Vec::new())
    }
}

// Helper functions for parsing

fn parse_ipv4(data: &[u8]) -> std::net::Ipv4Addr {
    if data.len() >= 4 {
        std::net::Ipv4Addr::new(data[0], data[1], data[2], data[3])
    } else {
        std::net::Ipv4Addr::UNSPECIFIED
    }
}

fn parse_ipv6(data: &[u8]) -> std::net::Ipv6Addr {
    if data.len() >= 16 {
        let mut octets = [0u8; 16];
        octets.copy_from_slice(&data[..16]);
        std::net::Ipv6Addr::from(octets)
    } else {
        std::net::Ipv6Addr::UNSPECIFIED
    }
}

fn parse_port(data: &[u8]) -> u16 {
    if data.len() >= 2 {
        u16::from_be_bytes([data[0], data[1]])
    } else {
        0
    }
}

fn parse_inet_msg(data: &[u8], protocol: InetProtocol) -> Option<InetSocket> {
    // Skip netlink header (16 bytes)
    if data.len() < 16 + 72 {
        return None;
    }

    let payload = &data[16..];

    // inet_diag_msg structure
    let family = AddressFamily::from_u8(payload[0])?;
    let state = TcpState::from_u8(payload[1]);
    let timer = payload[2];
    let retrans = payload[3];

    // inet_diag_sockid at offset 4
    let sport = parse_port(&payload[4..6]);
    let dport = parse_port(&payload[6..8]);

    let (src_ip, dst_ip) = match family {
        AddressFamily::Inet => {
            let src = IpAddr::V4(parse_ipv4(&payload[8..12]));
            let dst = IpAddr::V4(parse_ipv4(&payload[24..28]));
            (src, dst)
        }
        AddressFamily::Inet6 => {
            let src = IpAddr::V6(parse_ipv6(&payload[8..24]));
            let dst = IpAddr::V6(parse_ipv6(&payload[24..40]));
            (src, dst)
        }
        _ => return None,
    };

    let interface = u32::from_ne_bytes([payload[40], payload[41], payload[42], payload[43]]);
    let cookie = u64::from_ne_bytes([
        payload[44],
        payload[45],
        payload[46],
        payload[47],
        payload[48],
        payload[49],
        payload[50],
        payload[51],
    ]);

    // After sockid: expires, rqueue, wqueue, uid, inode
    let expires = u32::from_ne_bytes([payload[52], payload[53], payload[54], payload[55]]);
    let rqueue = u32::from_ne_bytes([payload[56], payload[57], payload[58], payload[59]]);
    let wqueue = u32::from_ne_bytes([payload[60], payload[61], payload[62], payload[63]]);
    let uid = u32::from_ne_bytes([payload[64], payload[65], payload[66], payload[67]]);
    let inode = u32::from_ne_bytes([payload[68], payload[69], payload[70], payload[71]]);

    let mut sock = InetSocket {
        family,
        protocol,
        state: SocketState::Tcp(state),
        local: SocketAddr::new(src_ip, sport),
        remote: SocketAddr::new(dst_ip, dport),
        interface,
        cookie,
        timer: Timer::from_raw(timer, expires, retrans),
        recv_q: rqueue,
        send_q: wqueue,
        uid,
        inode,
        refcnt: 0,
        mark: None,
        cgroup_id: None,
        tcp_info: None,
        mem_info: None,
        congestion: None,
        tos: None,
        tclass: None,
        shutdown: None,
        v6only: None,
    };

    // Parse attributes
    let mut attr_offset = 16 + 72;
    while attr_offset + 4 <= data.len() {
        let attr_len = u16::from_ne_bytes([data[attr_offset], data[attr_offset + 1]]) as usize;
        let attr_type = u16::from_ne_bytes([data[attr_offset + 2], data[attr_offset + 3]]);

        if attr_len < 4 || attr_offset + attr_len > data.len() {
            break;
        }

        let attr_data = &data[attr_offset + 4..attr_offset + attr_len];

        match attr_type {
            INET_DIAG_MEMINFO => {
                if attr_data.len() >= 16 {
                    sock.mem_info = Some(MemInfo {
                        rmem_alloc: u32::from_ne_bytes([
                            attr_data[0],
                            attr_data[1],
                            attr_data[2],
                            attr_data[3],
                        ]),
                        wmem_alloc: u32::from_ne_bytes([
                            attr_data[4],
                            attr_data[5],
                            attr_data[6],
                            attr_data[7],
                        ]),
                        fwd_alloc: u32::from_ne_bytes([
                            attr_data[8],
                            attr_data[9],
                            attr_data[10],
                            attr_data[11],
                        ]),
                        wmem_queued: u32::from_ne_bytes([
                            attr_data[12],
                            attr_data[13],
                            attr_data[14],
                            attr_data[15],
                        ]),
                        ..Default::default()
                    });
                }
            }
            INET_DIAG_INFO => {
                sock.tcp_info = Some(parse_tcp_info(attr_data));
            }
            INET_DIAG_CONG => {
                if let Ok(s) = std::str::from_utf8(attr_data) {
                    sock.congestion = Some(s.trim_end_matches('\0').to_string());
                }
            }
            INET_DIAG_TOS => {
                if !attr_data.is_empty() {
                    sock.tos = Some(attr_data[0]);
                }
            }
            INET_DIAG_TCLASS => {
                if !attr_data.is_empty() {
                    sock.tclass = Some(attr_data[0]);
                }
            }
            INET_DIAG_SKMEMINFO => {
                if attr_data.len() >= 36 {
                    sock.mem_info = Some(MemInfo {
                        rmem_alloc: u32::from_ne_bytes([
                            attr_data[0],
                            attr_data[1],
                            attr_data[2],
                            attr_data[3],
                        ]),
                        rcvbuf: u32::from_ne_bytes([
                            attr_data[4],
                            attr_data[5],
                            attr_data[6],
                            attr_data[7],
                        ]),
                        wmem_alloc: u32::from_ne_bytes([
                            attr_data[8],
                            attr_data[9],
                            attr_data[10],
                            attr_data[11],
                        ]),
                        sndbuf: u32::from_ne_bytes([
                            attr_data[12],
                            attr_data[13],
                            attr_data[14],
                            attr_data[15],
                        ]),
                        fwd_alloc: u32::from_ne_bytes([
                            attr_data[16],
                            attr_data[17],
                            attr_data[18],
                            attr_data[19],
                        ]),
                        wmem_queued: u32::from_ne_bytes([
                            attr_data[20],
                            attr_data[21],
                            attr_data[22],
                            attr_data[23],
                        ]),
                        optmem: u32::from_ne_bytes([
                            attr_data[24],
                            attr_data[25],
                            attr_data[26],
                            attr_data[27],
                        ]),
                        backlog: u32::from_ne_bytes([
                            attr_data[28],
                            attr_data[29],
                            attr_data[30],
                            attr_data[31],
                        ]),
                        drops: u32::from_ne_bytes([
                            attr_data[32],
                            attr_data[33],
                            attr_data[34],
                            attr_data[35],
                        ]),
                    });
                }
            }
            INET_DIAG_SHUTDOWN => {
                if !attr_data.is_empty() {
                    sock.shutdown = Some(attr_data[0]);
                }
            }
            INET_DIAG_MARK => {
                if attr_data.len() >= 4 {
                    sock.mark = Some(u32::from_ne_bytes([
                        attr_data[0],
                        attr_data[1],
                        attr_data[2],
                        attr_data[3],
                    ]));
                }
            }
            INET_DIAG_CGROUP_ID => {
                if attr_data.len() >= 8 {
                    sock.cgroup_id = Some(u64::from_ne_bytes([
                        attr_data[0],
                        attr_data[1],
                        attr_data[2],
                        attr_data[3],
                        attr_data[4],
                        attr_data[5],
                        attr_data[6],
                        attr_data[7],
                    ]));
                }
            }
            INET_DIAG_SKV6ONLY => {
                if !attr_data.is_empty() {
                    sock.v6only = Some(attr_data[0] != 0);
                }
            }
            _ => {}
        }

        // Align to 4 bytes
        attr_offset += (attr_len + 3) & !3;
    }

    Some(sock)
}

fn parse_tcp_info(data: &[u8]) -> TcpInfo {
    let mut info = TcpInfo::default();

    if data.len() < 104 {
        return info;
    }

    info.state = data[0];
    info.ca_state = data[1];
    info.retransmits = data[2];
    info.probes = data[3];
    info.backoff = data[4];
    info.options = data[5];
    info.wscale = data[6];
    info.delivery_rate_app_limited = data[7] != 0;

    info.rto = u32::from_ne_bytes([data[8], data[9], data[10], data[11]]);
    // ATO at 12-15 (skip)
    info.snd_mss = u32::from_ne_bytes([data[16], data[17], data[18], data[19]]);
    info.rcv_mss = u32::from_ne_bytes([data[20], data[21], data[22], data[23]]);

    info.unacked = u32::from_ne_bytes([data[24], data[25], data[26], data[27]]);
    info.sacked = u32::from_ne_bytes([data[28], data[29], data[30], data[31]]);
    info.lost = u32::from_ne_bytes([data[32], data[33], data[34], data[35]]);
    info.retrans = u32::from_ne_bytes([data[36], data[37], data[38], data[39]]);
    info.fackets = u32::from_ne_bytes([data[40], data[41], data[42], data[43]]);

    info.last_data_sent = u32::from_ne_bytes([data[44], data[45], data[46], data[47]]);
    info.last_ack_sent = u32::from_ne_bytes([data[48], data[49], data[50], data[51]]);
    info.last_data_recv = u32::from_ne_bytes([data[52], data[53], data[54], data[55]]);
    info.last_ack_recv = u32::from_ne_bytes([data[56], data[57], data[58], data[59]]);

    info.pmtu = u32::from_ne_bytes([data[60], data[61], data[62], data[63]]);
    info.rcv_ssthresh = u32::from_ne_bytes([data[64], data[65], data[66], data[67]]);
    info.rtt = u32::from_ne_bytes([data[68], data[69], data[70], data[71]]);
    info.rttvar = u32::from_ne_bytes([data[72], data[73], data[74], data[75]]);
    info.snd_ssthresh = u32::from_ne_bytes([data[76], data[77], data[78], data[79]]);
    info.snd_cwnd = u32::from_ne_bytes([data[80], data[81], data[82], data[83]]);
    info.advmss = u32::from_ne_bytes([data[84], data[85], data[86], data[87]]);
    info.reordering = u32::from_ne_bytes([data[88], data[89], data[90], data[91]]);

    info.rcv_rtt = u32::from_ne_bytes([data[92], data[93], data[94], data[95]]);
    info.rcv_space = u32::from_ne_bytes([data[96], data[97], data[98], data[99]]);

    info.total_retrans = u32::from_ne_bytes([data[100], data[101], data[102], data[103]]);

    // Extended fields if available
    if data.len() >= 160 {
        info.pacing_rate = u64::from_ne_bytes([
            data[104], data[105], data[106], data[107], data[108], data[109], data[110], data[111],
        ]);
        info.max_pacing_rate = u64::from_ne_bytes([
            data[112], data[113], data[114], data[115], data[116], data[117], data[118], data[119],
        ]);
        info.bytes_acked = u64::from_ne_bytes([
            data[120], data[121], data[122], data[123], data[124], data[125], data[126], data[127],
        ]);
        info.bytes_received = u64::from_ne_bytes([
            data[128], data[129], data[130], data[131], data[132], data[133], data[134], data[135],
        ]);
        info.segs_out = u32::from_ne_bytes([data[136], data[137], data[138], data[139]]);
        info.segs_in = u32::from_ne_bytes([data[140], data[141], data[142], data[143]]);
        info.notsent_bytes = u32::from_ne_bytes([data[144], data[145], data[146], data[147]]);
        info.min_rtt = u32::from_ne_bytes([data[148], data[149], data[150], data[151]]);
        info.data_segs_in = u32::from_ne_bytes([data[152], data[153], data[154], data[155]]);
        info.data_segs_out = u32::from_ne_bytes([data[156], data[157], data[158], data[159]]);
    }

    if data.len() >= 168 {
        info.delivery_rate = u64::from_ne_bytes([
            data[160], data[161], data[162], data[163], data[164], data[165], data[166], data[167],
        ]);
    }

    info
}

fn parse_unix_msg(data: &[u8]) -> Option<UnixSocket> {
    // Skip netlink header (16 bytes)
    if data.len() < 16 + 16 {
        return None;
    }

    let payload = &data[16..];

    // unix_diag_msg structure
    let family = payload[0];
    if family != libc::AF_UNIX as u8 {
        return None;
    }

    let socket_type = UnixType::from_u8(payload[1])?;
    let state_raw = payload[2];
    // pad at 3

    let inode = u32::from_ne_bytes([payload[4], payload[5], payload[6], payload[7]]);
    let cookie = u64::from_ne_bytes([
        payload[8],
        payload[9],
        payload[10],
        payload[11],
        payload[12],
        payload[13],
        payload[14],
        payload[15],
    ]);

    let state = match state_raw {
        1 => SocketState::Established,
        10 => SocketState::Listen,
        _ => SocketState::Close,
    };

    let mut sock = UnixSocket {
        socket_type,
        state,
        path: None,
        abstract_name: None,
        inode,
        cookie,
        peer_inode: None,
        vfs_dev: None,
        vfs_inode: None,
        recv_q: None,
        send_q: None,
        pending_connections: None,
        uid: None,
        mem_info: None,
        shutdown: None,
    };

    // Parse attributes
    let mut attr_offset = 16 + 16;
    while attr_offset + 4 <= data.len() {
        let attr_len = u16::from_ne_bytes([data[attr_offset], data[attr_offset + 1]]) as usize;
        let attr_type = u16::from_ne_bytes([data[attr_offset + 2], data[attr_offset + 3]]);

        if attr_len < 4 || attr_offset + attr_len > data.len() {
            break;
        }

        let attr_data = &data[attr_offset + 4..attr_offset + attr_len];

        match attr_type {
            UNIX_DIAG_NAME => {
                if !attr_data.is_empty() {
                    if attr_data[0] == 0 {
                        // Abstract socket
                        if let Ok(s) = std::str::from_utf8(&attr_data[1..]) {
                            sock.abstract_name = Some(s.trim_end_matches('\0').to_string());
                        }
                    } else if let Ok(s) = std::str::from_utf8(attr_data) {
                        sock.path = Some(s.trim_end_matches('\0').to_string());
                    }
                }
            }
            UNIX_DIAG_VFS => {
                if attr_data.len() >= 8 {
                    sock.vfs_inode = Some(u32::from_ne_bytes([
                        attr_data[0],
                        attr_data[1],
                        attr_data[2],
                        attr_data[3],
                    ]));
                    sock.vfs_dev = Some(u32::from_ne_bytes([
                        attr_data[4],
                        attr_data[5],
                        attr_data[6],
                        attr_data[7],
                    ]));
                }
            }
            UNIX_DIAG_PEER => {
                if attr_data.len() >= 4 {
                    sock.peer_inode = Some(u32::from_ne_bytes([
                        attr_data[0],
                        attr_data[1],
                        attr_data[2],
                        attr_data[3],
                    ]));
                }
            }
            UNIX_DIAG_ICONS => {
                let mut icons = Vec::new();
                let mut i = 0;
                while i + 4 <= attr_data.len() {
                    icons.push(u32::from_ne_bytes([
                        attr_data[i],
                        attr_data[i + 1],
                        attr_data[i + 2],
                        attr_data[i + 3],
                    ]));
                    i += 4;
                }
                if !icons.is_empty() {
                    sock.pending_connections = Some(icons);
                }
            }
            UNIX_DIAG_RQLEN => {
                if attr_data.len() >= 8 {
                    sock.recv_q = Some(u32::from_ne_bytes([
                        attr_data[0],
                        attr_data[1],
                        attr_data[2],
                        attr_data[3],
                    ]));
                    sock.send_q = Some(u32::from_ne_bytes([
                        attr_data[4],
                        attr_data[5],
                        attr_data[6],
                        attr_data[7],
                    ]));
                }
            }
            UNIX_DIAG_MEMINFO => {
                if attr_data.len() >= 36 {
                    sock.mem_info = Some(MemInfo {
                        rmem_alloc: u32::from_ne_bytes([
                            attr_data[0],
                            attr_data[1],
                            attr_data[2],
                            attr_data[3],
                        ]),
                        rcvbuf: u32::from_ne_bytes([
                            attr_data[4],
                            attr_data[5],
                            attr_data[6],
                            attr_data[7],
                        ]),
                        wmem_alloc: u32::from_ne_bytes([
                            attr_data[8],
                            attr_data[9],
                            attr_data[10],
                            attr_data[11],
                        ]),
                        sndbuf: u32::from_ne_bytes([
                            attr_data[12],
                            attr_data[13],
                            attr_data[14],
                            attr_data[15],
                        ]),
                        fwd_alloc: u32::from_ne_bytes([
                            attr_data[16],
                            attr_data[17],
                            attr_data[18],
                            attr_data[19],
                        ]),
                        wmem_queued: u32::from_ne_bytes([
                            attr_data[20],
                            attr_data[21],
                            attr_data[22],
                            attr_data[23],
                        ]),
                        optmem: u32::from_ne_bytes([
                            attr_data[24],
                            attr_data[25],
                            attr_data[26],
                            attr_data[27],
                        ]),
                        backlog: u32::from_ne_bytes([
                            attr_data[28],
                            attr_data[29],
                            attr_data[30],
                            attr_data[31],
                        ]),
                        drops: u32::from_ne_bytes([
                            attr_data[32],
                            attr_data[33],
                            attr_data[34],
                            attr_data[35],
                        ]),
                    });
                }
            }
            UNIX_DIAG_SHUTDOWN => {
                if !attr_data.is_empty() {
                    sock.shutdown = Some(attr_data[0]);
                }
            }
            UNIX_DIAG_UID => {
                if attr_data.len() >= 4 {
                    sock.uid = Some(u32::from_ne_bytes([
                        attr_data[0],
                        attr_data[1],
                        attr_data[2],
                        attr_data[3],
                    ]));
                }
            }
            _ => {}
        }

        attr_offset += (attr_len + 3) & !3;
    }

    Some(sock)
}
