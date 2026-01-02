//! Low-level async netlink socket operations.

use std::fs::File;
use std::os::unix::io::{AsRawFd, RawFd};
use std::path::Path;
use std::sync::atomic::{AtomicU32, Ordering};
use std::task::{Context, Poll};

use bytes::BytesMut;
use netlink_sys::{Socket, SocketAddr, protocols};
use tokio::io::Interest;
use tokio::io::unix::AsyncFd;

use super::error::{Error, Result};

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
        Self::create_socket(protocol)
    }

    /// Create a netlink socket that operates in a specific network namespace.
    ///
    /// The namespace is specified by an open file descriptor to a namespace file
    /// (e.g., `/proc/<pid>/ns/net` or `/var/run/netns/<name>`).
    ///
    /// This function temporarily switches to the target namespace, creates the socket,
    /// then restores the original namespace. The socket will operate in the target
    /// namespace for all subsequent operations.
    ///
    /// # Safety
    ///
    /// This function uses `setns()` which affects the calling thread. It saves and
    /// restores the original namespace, but callers should be aware of potential
    /// issues in multi-threaded contexts if the restoration fails.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use std::fs::File;
    /// use nlink::netlink::{NetlinkSocket, Protocol};
    ///
    /// let ns_file = File::open("/var/run/netns/myns")?;
    /// let socket = NetlinkSocket::new_in_namespace(Protocol::Route, ns_file.as_raw_fd())?;
    /// ```
    pub fn new_in_namespace(protocol: Protocol, ns_fd: RawFd) -> Result<Self> {
        // Save the current namespace so we can restore it
        let current_ns = File::open("/proc/self/ns/net")
            .map_err(|e| Error::InvalidMessage(format!("cannot open current namespace: {}", e)))?;
        let current_ns_fd = current_ns.as_raw_fd();

        // Switch to the target namespace
        // SAFETY: libc::setns switches to the namespace specified by ns_fd.
        // ns_fd is a valid file descriptor to a namespace file.
        let ret = unsafe { libc::setns(ns_fd, libc::CLONE_NEWNET) };
        if ret < 0 {
            return Err(Error::Io(std::io::Error::last_os_error()));
        }

        // Create the socket in the target namespace
        let result = Self::create_socket(protocol);

        // Restore the original namespace (best effort - log but don't fail)
        // SAFETY: libc::setns restores the original namespace. current_ns_fd
        // is valid (opened from /proc/self/ns/net above).
        let restore_ret = unsafe { libc::setns(current_ns_fd, libc::CLONE_NEWNET) };
        if restore_ret < 0 {
            // We successfully created the socket but failed to restore namespace.
            // This is a serious issue, but we still return the socket.
            eprintln!(
                "warning: failed to restore original namespace: {}",
                std::io::Error::last_os_error()
            );
        }

        result
    }

    /// Create a netlink socket that operates in a network namespace specified by path.
    ///
    /// This is a convenience method that opens the namespace file and calls
    /// [`new_in_namespace`](Self::new_in_namespace).
    ///
    /// # Example
    ///
    /// ```ignore
    /// use nlink::netlink::{NetlinkSocket, Protocol};
    ///
    /// // For a named namespace
    /// let socket = NetlinkSocket::new_in_namespace_path(
    ///     Protocol::Route,
    ///     "/var/run/netns/myns"
    /// )?;
    ///
    /// // For a process namespace
    /// let socket = NetlinkSocket::new_in_namespace_path(
    ///     Protocol::Route,
    ///     "/proc/1234/ns/net"
    /// )?;
    /// ```
    pub fn new_in_namespace_path<P: AsRef<Path>>(protocol: Protocol, ns_path: P) -> Result<Self> {
        let ns_file = File::open(ns_path.as_ref()).map_err(|e| {
            Error::InvalidMessage(format!(
                "cannot open namespace '{}': {}",
                ns_path.as_ref().display(),
                e
            ))
        })?;
        Self::new_in_namespace(protocol, ns_file.as_raw_fd())
    }

    /// Internal helper to create the socket.
    fn create_socket(protocol: Protocol) -> Result<Self> {
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

    /// Poll for incoming data.
    ///
    /// This is the poll-based version of `recv_msg()` for use with `Stream` implementations.
    /// Returns `Poll::Ready(Ok(data))` when data is available.
    pub fn poll_recv(&self, cx: &mut Context<'_>) -> Poll<Result<Vec<u8>>> {
        let mut buf = BytesMut::with_capacity(32768);

        loop {
            let mut guard = match self.fd.poll_read_ready(cx) {
                Poll::Ready(Ok(guard)) => guard,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e.into())),
                Poll::Pending => return Poll::Pending,
            };

            match guard.try_io(|inner| inner.get_ref().recv(&mut buf, 0)) {
                Ok(result) => match result {
                    Ok(_n) => return Poll::Ready(Ok(buf.to_vec())),
                    Err(e) => return Poll::Ready(Err(e.into())),
                },
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
