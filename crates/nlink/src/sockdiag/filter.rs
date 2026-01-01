//! Socket query filters.
//!
//! This module provides builder-pattern APIs for constructing socket queries
//! with various filter criteria.

use super::types::{AddressFamily, InetExtension, Protocol, TcpState, UnixShow};
use std::net::IpAddr;

/// Socket filter builder.
///
/// Use this to construct queries for different socket types.
#[derive(Debug, Clone)]
pub struct SocketFilter {
    /// The specific filter type.
    pub kind: FilterKind,
}

/// The kind of filter to apply.
#[derive(Debug, Clone)]
pub enum FilterKind {
    /// Filter for inet (TCP/UDP) sockets.
    Inet(InetFilter),
    /// Filter for Unix domain sockets.
    Unix(UnixFilter),
    /// Filter for Netlink sockets.
    Netlink(NetlinkFilter),
    /// Filter for Packet sockets.
    Packet(PacketFilter),
}

impl SocketFilter {
    /// Create a TCP socket filter.
    pub fn tcp() -> InetFilterBuilder {
        InetFilterBuilder::new(Protocol::Tcp)
    }

    /// Create a UDP socket filter.
    pub fn udp() -> InetFilterBuilder {
        InetFilterBuilder::new(Protocol::Udp)
    }

    /// Create an MPTCP socket filter.
    pub fn mptcp() -> InetFilterBuilder {
        InetFilterBuilder::new(Protocol::Mptcp)
    }

    /// Create an SCTP socket filter.
    pub fn sctp() -> InetFilterBuilder {
        InetFilterBuilder::new(Protocol::Sctp)
    }

    /// Create a DCCP socket filter.
    pub fn dccp() -> InetFilterBuilder {
        InetFilterBuilder::new(Protocol::Dccp)
    }

    /// Create a raw IP socket filter.
    pub fn raw() -> InetFilterBuilder {
        InetFilterBuilder::new(Protocol::Raw)
    }

    /// Create a Unix socket filter.
    pub fn unix() -> UnixFilterBuilder {
        UnixFilterBuilder::new()
    }

    /// Create a Netlink socket filter.
    pub fn netlink() -> NetlinkFilterBuilder {
        NetlinkFilterBuilder::new()
    }

    /// Create a Packet socket filter.
    pub fn packet() -> PacketFilterBuilder {
        PacketFilterBuilder::new()
    }
}

/// Filter for inet (TCP/UDP/SCTP) sockets.
#[derive(Debug, Clone)]
pub struct InetFilter {
    /// Address family (IPv4, IPv6, or both).
    pub family: Option<AddressFamily>,
    /// Protocol.
    pub protocol: Protocol,
    /// State bitmask.
    pub states: u32,
    /// Extensions to request.
    pub extensions: u8,
    /// Filter by local address.
    pub local_addr: Option<IpAddr>,
    /// Filter by local port.
    pub local_port: Option<u16>,
    /// Filter by remote address.
    pub remote_addr: Option<IpAddr>,
    /// Filter by remote port.
    pub remote_port: Option<u16>,
    /// Filter by interface index.
    pub interface: Option<u32>,
    /// Filter by socket mark.
    pub mark: Option<(u32, u32)>, // (value, mask)
    /// Filter by cgroup ID.
    pub cgroup_id: Option<u64>,
}

impl Default for InetFilter {
    fn default() -> Self {
        Self {
            family: None,
            protocol: Protocol::Tcp,
            states: TcpState::all_mask(),
            extensions: 0,
            local_addr: None,
            local_port: None,
            remote_addr: None,
            remote_port: None,
            interface: None,
            mark: None,
            cgroup_id: None,
        }
    }
}

/// Builder for inet socket filters.
#[derive(Debug, Clone)]
pub struct InetFilterBuilder {
    filter: InetFilter,
}

impl InetFilterBuilder {
    /// Create a new builder for the given protocol.
    pub fn new(protocol: Protocol) -> Self {
        Self {
            filter: InetFilter {
                protocol,
                ..Default::default()
            },
        }
    }

    /// Filter by address family.
    pub fn family(mut self, family: AddressFamily) -> Self {
        self.filter.family = Some(family);
        self
    }

    /// Filter by IPv4 only.
    pub fn ipv4(self) -> Self {
        self.family(AddressFamily::Inet)
    }

    /// Filter by IPv6 only.
    pub fn ipv6(self) -> Self {
        self.family(AddressFamily::Inet6)
    }

    /// Filter by socket states.
    pub fn states(mut self, states: &[TcpState]) -> Self {
        self.filter.states = states.iter().fold(0, |acc, s| acc | s.mask());
        self
    }

    /// Filter by all states.
    pub fn all_states(mut self) -> Self {
        self.filter.states = TcpState::all_mask();
        self
    }

    /// Filter by connected states only.
    pub fn connected(mut self) -> Self {
        self.filter.states = TcpState::connected_mask();
        self
    }

    /// Filter by listening state only.
    pub fn listening(mut self) -> Self {
        self.filter.states = TcpState::Listen.mask();
        self
    }

    /// Request memory info extension.
    pub fn with_mem_info(mut self) -> Self {
        self.filter.extensions |= InetExtension::MemInfo.mask();
        self
    }

    /// Request TCP info extension.
    pub fn with_tcp_info(mut self) -> Self {
        self.filter.extensions |= InetExtension::Info.mask();
        self
    }

    /// Request congestion info extension.
    pub fn with_congestion(mut self) -> Self {
        self.filter.extensions |= InetExtension::Cong.mask();
        self
    }

    /// Request TOS extension.
    pub fn with_tos(mut self) -> Self {
        self.filter.extensions |= InetExtension::Tos.mask();
        self
    }

    /// Request all extensions.
    pub fn with_all_extensions(mut self) -> Self {
        self.filter.extensions = 0xFF;
        self
    }

    /// Filter by local address.
    pub fn local_addr(mut self, addr: IpAddr) -> Self {
        self.filter.local_addr = Some(addr);
        self
    }

    /// Filter by local port.
    pub fn local_port(mut self, port: u16) -> Self {
        self.filter.local_port = Some(port);
        self
    }

    /// Filter by remote address.
    pub fn remote_addr(mut self, addr: IpAddr) -> Self {
        self.filter.remote_addr = Some(addr);
        self
    }

    /// Filter by remote port.
    pub fn remote_port(mut self, port: u16) -> Self {
        self.filter.remote_port = Some(port);
        self
    }

    /// Filter by interface index.
    pub fn interface(mut self, ifindex: u32) -> Self {
        self.filter.interface = Some(ifindex);
        self
    }

    /// Filter by socket mark.
    pub fn mark(mut self, value: u32, mask: u32) -> Self {
        self.filter.mark = Some((value, mask));
        self
    }

    /// Filter by cgroup ID.
    pub fn cgroup(mut self, cgroup_id: u64) -> Self {
        self.filter.cgroup_id = Some(cgroup_id);
        self
    }

    /// Build the filter.
    pub fn build(self) -> SocketFilter {
        SocketFilter {
            kind: FilterKind::Inet(self.filter),
        }
    }
}

/// Filter for Unix domain sockets.
#[derive(Debug, Clone)]
pub struct UnixFilter {
    /// Socket types to query.
    pub socket_types: u32,
    /// State bitmask.
    pub states: u32,
    /// What to show in response.
    pub show: u32,
    /// Filter by specific inode.
    pub inode: Option<u32>,
    /// Filter by path pattern.
    pub path_pattern: Option<String>,
}

impl Default for UnixFilter {
    fn default() -> Self {
        Self {
            socket_types: 0xFFFFFFFF,
            states: TcpState::all_mask(),
            show: UnixShow::combine(&[UnixShow::Name, UnixShow::Peer, UnixShow::RqLen]),
            inode: None,
            path_pattern: None,
        }
    }
}

/// Builder for Unix socket filters.
#[derive(Debug, Clone)]
pub struct UnixFilterBuilder {
    filter: UnixFilter,
}

impl UnixFilterBuilder {
    /// Create a new Unix filter builder.
    pub fn new() -> Self {
        Self {
            filter: UnixFilter::default(),
        }
    }

    /// Filter by stream sockets only.
    pub fn stream(mut self) -> Self {
        self.filter.socket_types = 1 << libc::SOCK_STREAM;
        self
    }

    /// Filter by datagram sockets only.
    pub fn dgram(mut self) -> Self {
        self.filter.socket_types = 1 << libc::SOCK_DGRAM;
        self
    }

    /// Filter by seqpacket sockets only.
    pub fn seqpacket(mut self) -> Self {
        self.filter.socket_types = 1 << libc::SOCK_SEQPACKET;
        self
    }

    /// Filter by states.
    pub fn states(mut self, states: &[TcpState]) -> Self {
        self.filter.states = states.iter().fold(0, |acc, s| acc | s.mask());
        self
    }

    /// Filter by listening state.
    pub fn listening(mut self) -> Self {
        self.filter.states = TcpState::Listen.mask();
        self
    }

    /// Filter by connected state.
    pub fn connected(mut self) -> Self {
        self.filter.states = TcpState::connected_mask();
        self
    }

    /// Show socket name.
    pub fn show_name(mut self) -> Self {
        self.filter.show |= UnixShow::Name.mask();
        self
    }

    /// Show VFS info.
    pub fn show_vfs(mut self) -> Self {
        self.filter.show |= UnixShow::Vfs.mask();
        self
    }

    /// Show peer info.
    pub fn show_peer(mut self) -> Self {
        self.filter.show |= UnixShow::Peer.mask();
        self
    }

    /// Show pending connections.
    pub fn show_icons(mut self) -> Self {
        self.filter.show |= UnixShow::Icons.mask();
        self
    }

    /// Show queue lengths.
    pub fn show_rqlen(mut self) -> Self {
        self.filter.show |= UnixShow::RqLen.mask();
        self
    }

    /// Show memory info.
    pub fn show_meminfo(mut self) -> Self {
        self.filter.show |= UnixShow::MemInfo.mask();
        self
    }

    /// Show UID.
    pub fn show_uid(mut self) -> Self {
        self.filter.show |= UnixShow::Uid.mask();
        self
    }

    /// Show all information.
    pub fn show_all(mut self) -> Self {
        self.filter.show = UnixShow::combine(&[
            UnixShow::Name,
            UnixShow::Vfs,
            UnixShow::Peer,
            UnixShow::Icons,
            UnixShow::RqLen,
            UnixShow::MemInfo,
            UnixShow::Uid,
        ]);
        self
    }

    /// Filter by specific inode.
    pub fn inode(mut self, inode: u32) -> Self {
        self.filter.inode = Some(inode);
        self
    }

    /// Filter by path pattern.
    pub fn path(mut self, pattern: impl Into<String>) -> Self {
        self.filter.path_pattern = Some(pattern.into());
        self
    }

    /// Build the filter.
    pub fn build(self) -> SocketFilter {
        SocketFilter {
            kind: FilterKind::Unix(self.filter),
        }
    }
}

impl Default for UnixFilterBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Filter for Netlink sockets.
#[derive(Debug, Clone)]
pub struct NetlinkFilter {
    /// Netlink protocol to filter by (None = all).
    pub protocol: Option<u8>,
    /// Show memory info.
    pub show_meminfo: bool,
    /// Show groups.
    pub show_groups: bool,
}

impl Default for NetlinkFilter {
    fn default() -> Self {
        Self {
            protocol: None,
            show_meminfo: false,
            show_groups: true,
        }
    }
}

/// Builder for Netlink socket filters.
#[derive(Debug, Clone)]
pub struct NetlinkFilterBuilder {
    filter: NetlinkFilter,
}

impl NetlinkFilterBuilder {
    /// Create a new Netlink filter builder.
    pub fn new() -> Self {
        Self {
            filter: NetlinkFilter::default(),
        }
    }

    /// Filter by protocol.
    pub fn protocol(mut self, protocol: u8) -> Self {
        self.filter.protocol = Some(protocol);
        self
    }

    /// Show memory info.
    pub fn show_meminfo(mut self) -> Self {
        self.filter.show_meminfo = true;
        self
    }

    /// Show groups.
    pub fn show_groups(mut self) -> Self {
        self.filter.show_groups = true;
        self
    }

    /// Build the filter.
    pub fn build(self) -> SocketFilter {
        SocketFilter {
            kind: FilterKind::Netlink(self.filter),
        }
    }
}

impl Default for NetlinkFilterBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Filter for Packet sockets.
#[derive(Debug, Clone)]
pub struct PacketFilter {
    /// Show memory info.
    pub show_meminfo: bool,
    /// Show info.
    pub show_info: bool,
    /// Show fanout.
    pub show_fanout: bool,
}

impl Default for PacketFilter {
    fn default() -> Self {
        Self {
            show_meminfo: false,
            show_info: true,
            show_fanout: true,
        }
    }
}

/// Builder for Packet socket filters.
#[derive(Debug, Clone)]
pub struct PacketFilterBuilder {
    filter: PacketFilter,
}

impl PacketFilterBuilder {
    /// Create a new Packet filter builder.
    pub fn new() -> Self {
        Self {
            filter: PacketFilter::default(),
        }
    }

    /// Show memory info.
    pub fn show_meminfo(mut self) -> Self {
        self.filter.show_meminfo = true;
        self
    }

    /// Show socket info.
    pub fn show_info(mut self) -> Self {
        self.filter.show_info = true;
        self
    }

    /// Show fanout info.
    pub fn show_fanout(mut self) -> Self {
        self.filter.show_fanout = true;
        self
    }

    /// Build the filter.
    pub fn build(self) -> SocketFilter {
        SocketFilter {
            kind: FilterKind::Packet(self.filter),
        }
    }
}

impl Default for PacketFilterBuilder {
    fn default() -> Self {
        Self::new()
    }
}
