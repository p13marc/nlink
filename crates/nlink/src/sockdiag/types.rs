//! Core types for socket diagnostics.
//!
//! This module provides strongly-typed representations of socket states,
//! address families, protocols, and diagnostic information.

use serde::{Deserialize, Serialize};

/// Socket address family.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum AddressFamily {
    /// Unix domain sockets.
    Unix = libc::AF_UNIX as u8,
    /// IPv4.
    Inet = libc::AF_INET as u8,
    /// IPv6.
    Inet6 = libc::AF_INET6 as u8,
    /// Netlink.
    Netlink = libc::AF_NETLINK as u8,
    /// Packet (raw).
    Packet = libc::AF_PACKET as u8,
    /// VSOCK (virtual machine sockets).
    Vsock = 40, // AF_VSOCK
    /// TIPC.
    Tipc = 30, // AF_TIPC
    /// XDP (eXpress Data Path).
    Xdp = 44, // AF_XDP
}

impl AddressFamily {
    /// Parse from a raw u8 value.
    pub fn from_u8(value: u8) -> Option<Self> {
        match value as i32 {
            libc::AF_UNIX => Some(Self::Unix),
            libc::AF_INET => Some(Self::Inet),
            libc::AF_INET6 => Some(Self::Inet6),
            libc::AF_NETLINK => Some(Self::Netlink),
            libc::AF_PACKET => Some(Self::Packet),
            40 => Some(Self::Vsock),
            30 => Some(Self::Tipc),
            44 => Some(Self::Xdp),
            _ => None,
        }
    }

    /// Get the netid string (used by ss).
    pub fn netid(&self) -> &'static str {
        match self {
            Self::Unix => "u_str",
            Self::Inet => "tcp",
            Self::Inet6 => "tcp6",
            Self::Netlink => "nl",
            Self::Packet => "p_raw",
            Self::Vsock => "v_str",
            Self::Tipc => "tipc",
            Self::Xdp => "xdp",
        }
    }
}

/// Transport protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Protocol {
    /// TCP.
    Tcp,
    /// UDP.
    Udp,
    /// SCTP.
    Sctp,
    /// DCCP.
    Dccp,
    /// MPTCP.
    Mptcp,
    /// Raw IP.
    Raw,
}

impl Protocol {
    /// Get the protocol number.
    pub fn number(&self) -> u8 {
        match self {
            Self::Tcp => libc::IPPROTO_TCP as u8,
            Self::Udp => libc::IPPROTO_UDP as u8,
            Self::Sctp => 132,
            Self::Dccp => 33,
            Self::Mptcp => 6, // Uses TCP protocol number in inet_diag
            Self::Raw => libc::IPPROTO_RAW as u8,
        }
    }

    /// Parse from a raw u8 value.
    pub fn from_u8(value: u8) -> Option<Self> {
        match value as i32 {
            libc::IPPROTO_TCP => Some(Self::Tcp),
            libc::IPPROTO_UDP => Some(Self::Udp),
            132 => Some(Self::Sctp),
            33 => Some(Self::Dccp),
            libc::IPPROTO_RAW => Some(Self::Raw),
            _ => None,
        }
    }

    /// Get the protocol name.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
            Self::Sctp => "sctp",
            Self::Dccp => "dccp",
            Self::Mptcp => "mptcp",
            Self::Raw => "raw",
        }
    }
}

/// TCP socket states.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum TcpState {
    /// Unknown state.
    Unknown = 0,
    /// Connection established.
    Established = 1,
    /// SYN sent, waiting for matching SYN.
    SynSent = 2,
    /// SYN received, waiting for ACK.
    SynRecv = 3,
    /// FIN sent, waiting for FIN or FIN-ACK.
    FinWait1 = 4,
    /// FIN received, waiting for FIN.
    FinWait2 = 5,
    /// In TIME-WAIT state.
    TimeWait = 6,
    /// Socket is closed.
    Close = 7,
    /// FIN received, close pending.
    CloseWait = 8,
    /// Close wait acknowledged, waiting for FIN.
    LastAck = 9,
    /// Socket is listening.
    Listen = 10,
    /// Both sides sent FIN simultaneously.
    Closing = 11,
    /// New SYN received (kernel only).
    NewSynRecv = 12,
    /// Bound but inactive (MPTCP).
    BoundInactive = 13,
}

impl TcpState {
    /// Parse from a raw u8 value.
    pub fn from_u8(value: u8) -> Self {
        match value {
            1 => Self::Established,
            2 => Self::SynSent,
            3 => Self::SynRecv,
            4 => Self::FinWait1,
            5 => Self::FinWait2,
            6 => Self::TimeWait,
            7 => Self::Close,
            8 => Self::CloseWait,
            9 => Self::LastAck,
            10 => Self::Listen,
            11 => Self::Closing,
            12 => Self::NewSynRecv,
            13 => Self::BoundInactive,
            _ => Self::Unknown,
        }
    }

    /// Get the state name.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Unknown => "UNKNOWN",
            Self::Established => "ESTAB",
            Self::SynSent => "SYN-SENT",
            Self::SynRecv => "SYN-RECV",
            Self::FinWait1 => "FIN-WAIT-1",
            Self::FinWait2 => "FIN-WAIT-2",
            Self::TimeWait => "TIME-WAIT",
            Self::Close => "UNCONN",
            Self::CloseWait => "CLOSE-WAIT",
            Self::LastAck => "LAST-ACK",
            Self::Listen => "LISTEN",
            Self::Closing => "CLOSING",
            Self::NewSynRecv => "NEW-SYN-RECV",
            Self::BoundInactive => "BOUND-INACTIVE",
        }
    }

    /// Create a bitmask for this state.
    pub fn mask(&self) -> u32 {
        1 << (*self as u32)
    }

    /// All connection states (excludes LISTEN, CLOSE, TIME-WAIT, SYN-RECV).
    pub fn connected_mask() -> u32 {
        Self::all_mask()
            & !(Self::Listen.mask()
                | Self::Close.mask()
                | Self::TimeWait.mask()
                | Self::SynRecv.mask())
    }

    /// All states mask.
    pub fn all_mask() -> u32 {
        (1 << 14) - 1
    }
}

/// Generic socket state (for non-TCP sockets).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SocketState {
    /// TCP state (for TCP/MPTCP/DCCP sockets).
    Tcp(TcpState),
    /// Closed (for UDP, Unix, etc.).
    Close,
    /// Established (for UDP, Unix stream).
    Established,
    /// Listening (for Unix stream/seqpacket).
    Listen,
}

impl SocketState {
    /// Get the state name.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Tcp(state) => state.name(),
            Self::Close => "UNCONN",
            Self::Established => "ESTAB",
            Self::Listen => "LISTEN",
        }
    }
}

/// Extensions to request in inet_diag query.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum InetExtension {
    /// Memory info (idiag_rmem, idiag_wmem, etc.).
    MemInfo = 1,
    /// TCP info structure.
    Info = 2,
    /// Vegas congestion info.
    VegasInfo = 3,
    /// Congestion algorithm name.
    Cong = 4,
    /// Type of service.
    Tos = 5,
    /// Traffic class (IPv6).
    TClass = 6,
    /// Socket memory info array.
    SkMemInfo = 7,
    /// Shutdown state.
    Shutdown = 8,
}

impl InetExtension {
    /// Get the bitmask for this extension.
    pub fn mask(&self) -> u8 {
        1 << (*self as u8)
    }
}

/// What to show in Unix socket queries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum UnixShow {
    /// Show socket name.
    Name = 0x00000001,
    /// Show VFS inode info.
    Vfs = 0x00000002,
    /// Show peer socket info.
    Peer = 0x00000004,
    /// Show pending connections.
    Icons = 0x00000008,
    /// Show receive queue length.
    RqLen = 0x00000010,
    /// Show memory info.
    MemInfo = 0x00000020,
    /// Show socket UID.
    Uid = 0x00000040,
}

impl UnixShow {
    /// Get the bitmask for this show option.
    pub fn mask(&self) -> u32 {
        *self as u32
    }

    /// Combine multiple show options into a bitmask.
    pub fn combine(options: &[UnixShow]) -> u32 {
        options.iter().fold(0, |acc, opt| acc | opt.mask())
    }
}

/// TCP information structure (from tcp_info).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TcpInfo {
    /// State.
    pub state: u8,
    /// CA state.
    pub ca_state: u8,
    /// Retransmits.
    pub retransmits: u8,
    /// Probes.
    pub probes: u8,
    /// Backoff.
    pub backoff: u8,
    /// Options.
    pub options: u8,
    /// Send/receive window scale.
    pub wscale: u8,
    /// Delivery rate app limited flag.
    pub delivery_rate_app_limited: bool,

    /// Retransmit timeout (usec).
    pub rto: u32,
    /// Estimated RTT (usec).
    pub rtt: u32,
    /// RTT variance (usec).
    pub rttvar: u32,
    /// Send MSS.
    pub snd_mss: u32,
    /// Receive MSS.
    pub rcv_mss: u32,

    /// Unacked packets.
    pub unacked: u32,
    /// Sacked packets.
    pub sacked: u32,
    /// Lost packets.
    pub lost: u32,
    /// Retransmitted packets.
    pub retrans: u32,
    /// Forward acknowledged packets.
    pub fackets: u32,

    /// Last data sent timestamp.
    pub last_data_sent: u32,
    /// Last ACK sent timestamp.
    pub last_ack_sent: u32,
    /// Last data received timestamp.
    pub last_data_recv: u32,
    /// Last ACK received timestamp.
    pub last_ack_recv: u32,

    /// Path MTU.
    pub pmtu: u32,
    /// Receive SSTHRESH.
    pub rcv_ssthresh: u32,
    /// Send SSTHRESH.
    pub snd_ssthresh: u32,
    /// Send CWND.
    pub snd_cwnd: u32,
    /// Advertised MSS.
    pub advmss: u32,
    /// Reordering.
    pub reordering: u32,

    /// Receive RTT (usec).
    pub rcv_rtt: u32,
    /// Receive space.
    pub rcv_space: u32,

    /// Total retransmits.
    pub total_retrans: u32,

    /// Pacing rate (bytes/sec).
    pub pacing_rate: u64,
    /// Max pacing rate (bytes/sec).
    pub max_pacing_rate: u64,
    /// Bytes ACKed.
    pub bytes_acked: u64,
    /// Bytes received.
    pub bytes_received: u64,
    /// Segments out.
    pub segs_out: u32,
    /// Segments in.
    pub segs_in: u32,

    /// Not sent bytes.
    pub notsent_bytes: u32,
    /// Minimum RTT (usec).
    pub min_rtt: u32,
    /// Data segments in.
    pub data_segs_in: u32,
    /// Data segments out.
    pub data_segs_out: u32,

    /// Delivery rate (bytes/sec).
    pub delivery_rate: u64,

    /// Busy time (usec).
    pub busy_time: u64,
    /// RWnd limited time (usec).
    pub rwnd_limited: u64,
    /// Sndbuf limited time (usec).
    pub sndbuf_limited: u64,

    /// Delivered packets.
    pub delivered: u32,
    /// Delivered with CE mark.
    pub delivered_ce: u32,

    /// Bytes sent.
    pub bytes_sent: u64,
    /// Bytes retransmitted.
    pub bytes_retrans: u64,
    /// Duplicate SACKs received.
    pub dsack_dups: u32,
    /// Reordering seen.
    pub reord_seen: u32,

    /// Receive out-of-order rate.
    pub rcv_ooopack: u32,
    /// Send window.
    pub snd_wnd: u32,
}

impl TcpInfo {
    /// Format as ss-style string with all non-zero metrics.
    ///
    /// This produces output similar to `ss -i`:
    /// ```text
    /// rtt:0.123/0.050 ato:40 mss:1448 cwnd:10 ssthresh:7 bytes_acked:12345
    /// ```
    pub fn format_ss(&self) -> String {
        let mut parts = Vec::new();

        // RTT (in milliseconds with 3 decimal places)
        if self.rtt > 0 {
            let rtt_ms = self.rtt as f64 / 1000.0;
            let rttvar_ms = self.rttvar as f64 / 1000.0;
            parts.push(format!("rtt:{:.3}/{:.3}", rtt_ms, rttvar_ms));
        }

        // RTO
        if self.rto > 0 && self.rto != 200_000 {
            // Skip default RTO
            parts.push(format!("rto:{}", self.rto / 1000));
        }

        // MSS
        if self.snd_mss > 0 {
            parts.push(format!("mss:{}", self.snd_mss));
        }

        // Congestion window
        if self.snd_cwnd > 0 {
            parts.push(format!("cwnd:{}", self.snd_cwnd));
        }

        // Slow-start threshold
        if self.snd_ssthresh > 0 && self.snd_ssthresh < u32::MAX {
            parts.push(format!("ssthresh:{}", self.snd_ssthresh));
        }

        // Bytes metrics
        if self.bytes_acked > 0 {
            parts.push(format!("bytes_acked:{}", self.bytes_acked));
        }
        if self.bytes_received > 0 {
            parts.push(format!("bytes_received:{}", self.bytes_received));
        }

        // Segments
        if self.segs_out > 0 {
            parts.push(format!("segs_out:{}", self.segs_out));
        }
        if self.segs_in > 0 {
            parts.push(format!("segs_in:{}", self.segs_in));
        }

        // Retransmissions
        if self.retrans > 0 {
            parts.push(format!("retrans:{}/{}", self.retrans, self.total_retrans));
        } else if self.total_retrans > 0 {
            parts.push(format!("retrans:0/{}", self.total_retrans));
        }

        // Delivery rate
        if self.delivery_rate > 0 {
            parts.push(format!(
                "delivery_rate:{}{}",
                format_rate_bps(self.delivery_rate * 8),
                if self.delivery_rate_app_limited {
                    "app_limited"
                } else {
                    ""
                }
            ));
        }

        // Pacing rate
        if self.pacing_rate > 0 && self.pacing_rate < u64::MAX {
            parts.push(format!(
                "pacing_rate:{}",
                format_rate_bps(self.pacing_rate * 8)
            ));
        }

        // Minimum RTT
        if self.min_rtt > 0 {
            parts.push(format!("minrtt:{:.3}", self.min_rtt as f64 / 1000.0));
        }

        // Receive window
        if self.rcv_space > 0 {
            parts.push(format!("rcv_space:{}", self.rcv_space));
        }

        parts.join(" ")
    }

    /// Format RTT as "rtt/rttvar" in milliseconds.
    pub fn rtt_str(&self) -> String {
        if self.rtt > 0 {
            format!(
                "{:.3}/{:.3}",
                self.rtt as f64 / 1000.0,
                self.rttvar as f64 / 1000.0
            )
        } else {
            String::new()
        }
    }

    /// Format congestion window.
    pub fn cwnd_str(&self) -> String {
        if self.snd_cwnd > 0 {
            format!("{}", self.snd_cwnd)
        } else {
            String::new()
        }
    }

    /// Format delivery rate as human-readable string.
    pub fn delivery_rate_str(&self) -> String {
        if self.delivery_rate > 0 {
            format_rate_bps(self.delivery_rate * 8)
        } else {
            String::new()
        }
    }

    /// Format pacing rate as human-readable string.
    pub fn pacing_rate_str(&self) -> String {
        if self.pacing_rate > 0 && self.pacing_rate < u64::MAX {
            format_rate_bps(self.pacing_rate * 8)
        } else {
            String::new()
        }
    }

    /// Get the send window scale (high nibble of wscale).
    pub fn snd_wscale(&self) -> u8 {
        self.wscale >> 4
    }

    /// Get the receive window scale (low nibble of wscale).
    pub fn rcv_wscale(&self) -> u8 {
        self.wscale & 0x0f
    }
}

/// Format bits per second as human-readable string.
fn format_rate_bps(bps: u64) -> String {
    if bps >= 1_000_000_000 {
        format!("{:.1}Gbps", bps as f64 / 1_000_000_000.0)
    } else if bps >= 1_000_000 {
        format!("{:.1}Mbps", bps as f64 / 1_000_000.0)
    } else if bps >= 1_000 {
        format!("{:.1}Kbps", bps as f64 / 1_000.0)
    } else {
        format!("{}bps", bps)
    }
}

/// Socket memory information.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MemInfo {
    /// Receive memory allocated.
    pub rmem_alloc: u32,
    /// Receive buffer size.
    pub rcvbuf: u32,
    /// Write memory allocated.
    pub wmem_alloc: u32,
    /// Send buffer size.
    pub sndbuf: u32,
    /// Forward alloc.
    pub fwd_alloc: u32,
    /// Write memory queued.
    pub wmem_queued: u32,
    /// Option memory.
    pub optmem: u32,
    /// Backlog.
    pub backlog: u32,
    /// Drops.
    pub drops: u32,
}

impl MemInfo {
    /// Format as skmem style string.
    ///
    /// This produces output like ss's skmem() format:
    /// ```text
    /// skmem:(r0,rb131072,t0,tb16384,f0,w0,o0,bl0,d0)
    /// ```
    pub fn format_skmem(&self) -> String {
        format!(
            "skmem:(r{},rb{},t{},tb{},f{},w{},o{},bl{},d{})",
            self.rmem_alloc,
            self.rcvbuf,
            self.wmem_alloc,
            self.sndbuf,
            self.fwd_alloc,
            self.wmem_queued,
            self.optmem,
            self.backlog,
            self.drops
        )
    }

    /// Format as compact skmem string (only non-zero values).
    pub fn format_skmem_compact(&self) -> String {
        let mut parts = Vec::new();

        if self.rmem_alloc > 0 {
            parts.push(format!("r{}", self.rmem_alloc));
        }
        if self.rcvbuf > 0 {
            parts.push(format!("rb{}", self.rcvbuf));
        }
        if self.wmem_alloc > 0 {
            parts.push(format!("t{}", self.wmem_alloc));
        }
        if self.sndbuf > 0 {
            parts.push(format!("tb{}", self.sndbuf));
        }
        if self.fwd_alloc > 0 {
            parts.push(format!("f{}", self.fwd_alloc));
        }
        if self.wmem_queued > 0 {
            parts.push(format!("w{}", self.wmem_queued));
        }
        if self.optmem > 0 {
            parts.push(format!("o{}", self.optmem));
        }
        if self.backlog > 0 {
            parts.push(format!("bl{}", self.backlog));
        }
        if self.drops > 0 {
            parts.push(format!("d{}", self.drops));
        }

        if parts.is_empty() {
            "skmem:()".to_string()
        } else {
            format!("skmem:({})", parts.join(","))
        }
    }

    /// Check if there are any drops.
    pub fn has_drops(&self) -> bool {
        self.drops > 0
    }

    /// Total memory in use (rmem + wmem).
    pub fn total_mem(&self) -> u64 {
        self.rmem_alloc as u64 + self.wmem_alloc as u64
    }
}

/// Timer information.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Timer {
    /// No timer active.
    Off,
    /// Retransmit timer.
    On { expires_ms: u32, retrans: u8 },
    /// Keepalive timer.
    Keepalive { expires_ms: u32, probes: u8 },
    /// TIME-WAIT timer.
    TimeWait { expires_ms: u32 },
    /// Zero window probe timer.
    Probe { expires_ms: u32, retrans: u8 },
}

impl Timer {
    /// Parse timer info from idiag_timer, idiag_expires, idiag_retrans.
    pub fn from_raw(timer: u8, expires: u32, retrans: u8) -> Self {
        match timer {
            0 => Self::Off,
            1 => Self::On {
                expires_ms: expires,
                retrans,
            },
            2 => Self::Keepalive {
                expires_ms: expires,
                probes: retrans,
            },
            3 => Self::TimeWait {
                expires_ms: expires,
            },
            4 => Self::Probe {
                expires_ms: expires,
                retrans,
            },
            _ => Self::Off,
        }
    }
}
