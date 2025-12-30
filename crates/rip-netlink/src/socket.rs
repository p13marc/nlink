//! Low-level async netlink socket operations.

use std::os::unix::io::{AsRawFd, RawFd};
use std::sync::atomic::{AtomicU32, Ordering};

use bytes::BytesMut;
use netlink_sys::{Socket, SocketAddr, protocols};
use tokio::io::Interest;
use tokio::io::unix::AsyncFd;

use crate::error::Result;

/// Netlink protocol families.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    /// Routing/device hook (ip, tc, etc.)
    Route,
    /// Generic netlink
    Generic,
    /// Netfilter
    Netfilter,
    /// Kernel connector
    Connector,
    /// Kobject uevent
    KobjectUevent,
}

impl Protocol {
    fn as_isize(self) -> isize {
        match self {
            Protocol::Route => protocols::NETLINK_ROUTE,
            Protocol::Generic => protocols::NETLINK_GENERIC,
            Protocol::Netfilter => protocols::NETLINK_NETFILTER,
            Protocol::Connector => protocols::NETLINK_CONNECTOR,
            Protocol::KobjectUevent => protocols::NETLINK_KOBJECT_UEVENT,
        }
    }
}

/// Async netlink socket.
pub struct NetlinkSocket {
    /// The underlying async file descriptor.
    fd: AsyncFd<Socket>,
    /// Sequence number counter.
    seq: AtomicU32,
    /// Local port ID (assigned by kernel).
    pid: u32,
    /// Protocol this socket uses.
    protocol: Protocol,
}

impl NetlinkSocket {
    /// Create a new netlink socket for the given protocol.
    pub fn new(protocol: Protocol) -> Result<Self> {
        let mut socket = Socket::new(protocol.as_isize())?;
        socket.set_non_blocking(true)?;

        // Bind to get a port ID
        let mut addr = SocketAddr::new(0, 0);
        socket.bind(&addr)?;
        socket.get_address(&mut addr)?;
        let pid = addr.port_number();

        // Enable extended ACK for better error messages
        socket.set_ext_ack(true).ok(); // Ignore if not supported

        let fd = AsyncFd::new(socket)?;

        Ok(Self {
            fd,
            seq: AtomicU32::new(1),
            pid,
            protocol,
        })
    }

    /// Get the next sequence number.
    pub fn next_seq(&self) -> u32 {
        self.seq.fetch_add(1, Ordering::Relaxed)
    }

    /// Get the local port ID.
    pub fn pid(&self) -> u32 {
        self.pid
    }

    /// Get the protocol.
    pub fn protocol(&self) -> Protocol {
        self.protocol
    }

    /// Subscribe to multicast groups.
    pub fn add_membership(&mut self, group: u32) -> Result<()> {
        self.fd.get_mut().add_membership(group)?;
        Ok(())
    }

    /// Unsubscribe from multicast groups.
    pub fn drop_membership(&mut self, group: u32) -> Result<()> {
        self.fd.get_mut().drop_membership(group)?;
        Ok(())
    }

    /// Send a message.
    pub async fn send(&self, msg: &[u8]) -> Result<()> {
        loop {
            let mut guard = self.fd.ready(Interest::WRITABLE).await?;

            match guard.try_io(|inner| inner.get_ref().send(msg, 0)) {
                Ok(result) => {
                    result?;
                    return Ok(());
                }
                Err(_would_block) => continue,
            }
        }
    }

    /// Receive a message, allocating a buffer.
    pub async fn recv_msg(&self) -> Result<Vec<u8>> {
        // Allocate buffer with capacity - don't resize, let recv fill it
        let mut buf = BytesMut::with_capacity(32768);

        loop {
            let mut guard = self.fd.ready(Interest::READABLE).await?;

            match guard.try_io(|inner| inner.get_ref().recv(&mut buf, 0)) {
                Ok(result) => {
                    let _n = result?;
                    // buf has been advanced by recv, so buf[..] contains the data
                    return Ok(buf.to_vec());
                }
                Err(_would_block) => continue,
            }
        }
    }
}

impl AsRawFd for NetlinkSocket {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.get_ref().as_raw_fd()
    }
}

/// Multicast groups for NETLINK_ROUTE.
pub mod rtnetlink_groups {
    pub const RTNLGRP_LINK: u32 = 1;
    pub const RTNLGRP_NOTIFY: u32 = 2;
    pub const RTNLGRP_NEIGH: u32 = 3;
    pub const RTNLGRP_TC: u32 = 4;
    pub const RTNLGRP_IPV4_IFADDR: u32 = 5;
    pub const RTNLGRP_IPV4_MROUTE: u32 = 6;
    pub const RTNLGRP_IPV4_ROUTE: u32 = 7;
    pub const RTNLGRP_IPV4_RULE: u32 = 8;
    pub const RTNLGRP_IPV6_IFADDR: u32 = 9;
    pub const RTNLGRP_IPV6_MROUTE: u32 = 10;
    pub const RTNLGRP_IPV6_ROUTE: u32 = 11;
    pub const RTNLGRP_IPV6_IFINFO: u32 = 12;
    pub const RTNLGRP_IPV6_PREFIX: u32 = 18;
    pub const RTNLGRP_IPV6_RULE: u32 = 19;
    pub const RTNLGRP_NSID: u32 = 28;
}
