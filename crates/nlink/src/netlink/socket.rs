//! Low-level async netlink socket operations.

use std::{
    fs::File,
    os::unix::io::{AsRawFd, RawFd},
    path::Path,
    sync::atomic::{AtomicU32, Ordering},
    task::{Context, Poll},
};

use bytes::BytesMut;
use netlink_sys::{Socket, SocketAddr, protocols};
use tokio::io::{Interest, unix::AsyncFd};

use super::error::{Error, Result};

/// Netlink protocol families.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Protocol {
    /// Routing/device hook (ip, tc, etc.)
    Route,
    /// Generic netlink
    Generic,
    /// Socket diagnostics (ss-like queries)
    SockDiag,
    /// Netfilter
    Netfilter,
    /// Kernel connector
    Connector,
    /// Kobject uevent
    KobjectUevent,
    /// XFRM (IPsec)
    Xfrm,
    /// SELinux event notifications
    SELinux,
    /// Linux Audit
    Audit,
    /// FIB lookup
    FibLookup,
}

/// NETLINK_XFRM protocol number (6).
const NETLINK_XFRM: isize = 6;

/// NETLINK_SELINUX protocol number (7).
const NETLINK_SELINUX: isize = 7;

/// NETLINK_AUDIT protocol number (9).
const NETLINK_AUDIT: isize = 9;

/// NETLINK_FIB_LOOKUP protocol number (10).
const NETLINK_FIB_LOOKUP: isize = 10;

impl Protocol {
    fn as_isize(self) -> isize {
        match self {
            Protocol::Route => protocols::NETLINK_ROUTE,
            Protocol::Generic => protocols::NETLINK_GENERIC,
            Protocol::SockDiag => protocols::NETLINK_SOCK_DIAG,
            Protocol::Netfilter => protocols::NETLINK_NETFILTER,
            Protocol::Connector => protocols::NETLINK_CONNECTOR,
            Protocol::KobjectUevent => protocols::NETLINK_KOBJECT_UEVENT,
            Protocol::Xfrm => NETLINK_XFRM,
            Protocol::SELinux => NETLINK_SELINUX,
            Protocol::Audit => NETLINK_AUDIT,
            Protocol::FibLookup => NETLINK_FIB_LOOKUP,
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
    /// restores the original namespace. If restoration fails, the function
    /// returns [`Error::NamespaceRestoreFailed`] — the socket may have been
    /// created successfully but the calling thread is now stuck in the target
    /// namespace. See the variant's documentation for recovery options.
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
        let current_ns = File::open("/proc/thread-self/ns/net")
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

        // Restore the original namespace. If this fails, the calling thread
        // is stuck in the target ns — surface as an error so callers can
        // decide whether to abort or pin work to a different thread.
        // SAFETY: libc::setns restores the original namespace. current_ns_fd
        // is valid (opened from /proc/thread-self/ns/net above).
        let restore_ret = unsafe { libc::setns(current_ns_fd, libc::CLONE_NEWNET) };
        if restore_ret < 0 {
            let source = std::io::Error::last_os_error();
            tracing::error!(
                error = %source,
                "netns restore failed after socket creation; thread stuck in target netns"
            );
            // Drop the (possibly successful) socket — the caller can't rely
            // on thread-context to use it safely.
            return Err(Error::NamespaceRestoreFailed { source });
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

    /// Toggle extended-ack reception (`NETLINK_EXT_ACK`, kernel
    /// 4.12+). Enabled by default during socket construction;
    /// rarely useful to disable. Exposed for parity with neli and
    /// for callers that want to suppress the trailing TLVs in
    /// error responses (e.g. for tighter timing-sensitive
    /// measurements).
    ///
    /// Returns `Ok(())` on pre-4.12 kernels where the sockopt is
    /// not supported (`ENOPROTOOPT`) — graceful degradation.
    pub fn set_ext_ack(&self, on: bool) -> Result<()> {
        Self::set_netlink_sockopt(self.as_raw_fd(), libc::NETLINK_EXT_ACK, on)
    }

    /// Shrink/grow the kernel-side receive buffer (`SO_RCVBUF`).
    /// `SO_RCVBUFFORCE` is used so callers with `CAP_NET_ADMIN`
    /// can drop below `net.core.rmem_min` — useful for tests
    /// that need to provoke `ENOBUFS` overflow on multicast
    /// subscribers without flooding the kernel for minutes.
    ///
    /// Plan 185 integration test depends on this — shrinking the
    /// nftables multicast subscriber to a few hundred bytes
    /// makes a handful of rule mutations overflow it
    /// deterministically. Outside that test scope this is
    /// rarely the right knob; prefer the kernel default.
    pub fn set_rcvbuf(&self, bytes: usize) -> Result<()> {
        let val = bytes as libc::c_int;
        // SAFETY: SO_RCVBUFFORCE on a valid fd; size matches int.
        let rc = unsafe {
            libc::setsockopt(
                self.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_RCVBUFFORCE,
                &val as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        if rc < 0 {
            return Err(Error::Io(std::io::Error::last_os_error()));
        }
        Ok(())
    }

    /// Enable kernel-side strict checking (`NETLINK_GET_STRICT_CHK`,
    /// kernel 5.0+). When enabled, the kernel validates dump request
    /// filters strictly and returns an error if they reference
    /// unknown attributes — useful for catching
    /// client/kernel-version mismatches early.
    ///
    /// Off by default. Returns `Ok(())` silently on pre-5.0 kernels
    /// where the sockopt is not supported (`ENOPROTOOPT`).
    pub fn set_strict_checking(&self, on: bool) -> Result<()> {
        // NETLINK_GET_STRICT_CHK = 12 per include/uapi/linux/netlink.h.
        // Not in libc as of writing; define inline.
        const NETLINK_GET_STRICT_CHK: libc::c_int = 12;
        Self::set_netlink_sockopt(self.as_raw_fd(), NETLINK_GET_STRICT_CHK, on)
    }

    /// Internal helper: setsockopt(SOL_NETLINK, optname, on as int).
    /// Treats `ENOPROTOOPT` as success (graceful degradation when
    /// the running kernel doesn't recognize the optname).
    fn set_netlink_sockopt(fd: RawFd, optname: libc::c_int, on: bool) -> Result<()> {
        let val: libc::c_int = if on { 1 } else { 0 };
        // SAFETY: setsockopt with a valid fd + SOL_NETLINK level +
        // pointer to a stack-allocated int + correct size. Returns
        // -1 on failure; we check it.
        let rc = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_NETLINK,
                optname,
                &val as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        if rc < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::ENOPROTOOPT) {
                // Kernel doesn't support this sockopt — silently
                // succeed so callers can `enable_strict_checking(true)`
                // unconditionally and it's a no-op on old kernels.
                return Ok(());
            }
            return Err(Error::Io(err));
        }
        Ok(())
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

// ============================================================================
// Batched I/O via recvmmsg(2) / sendmmsg(2)
// Plan 158 — opt-in `syscall_batch` feature flag for 0.16; default-on in 0.17.
// ============================================================================

/// Maximum number of frames batched in one `recvmmsg`/`sendmmsg`
/// syscall. Matches quinn-udp's choice; above 64 cache footprint
/// outweighs syscall amortization.
#[cfg(feature = "syscall_batch")]
pub const NL_BATCH_SIZE: usize = 32;

/// Per-slot recv buffer size. Sized to exceed any realistic
/// single netlink frame; MSG_TRUNC is a hard error rather than
/// silent truncation.
#[cfg(feature = "syscall_batch")]
pub const NL_BUF_SIZE: usize = 32 * 1024;

#[cfg(feature = "syscall_batch")]
struct BatchBufs {
    /// Owned per-slot recv storage. Allocated once; pointers
    /// reused across calls.
    storage: Vec<Vec<u8>>,
    /// iovec entries pointing into `storage`. Set up at
    /// construction; the pointers stay valid because `storage`
    /// is never resized.
    ///
    /// Held here even though we don't read the field directly —
    /// `msgs[i].msg_hdr.msg_iov` is a raw `*mut iovec` into this
    /// `Vec`, and dropping `iovecs` would dangle those pointers.
    /// Keeping ownership in the same struct guarantees the
    /// lifetime extends across `recvmmsg` calls.
    #[allow(dead_code)]
    iovecs: Vec<libc::iovec>,
    /// mmsghdr array; msg_hdr.msg_iov points into `iovecs`.
    msgs: Vec<libc::mmsghdr>,
}

#[cfg(feature = "syscall_batch")]
impl BatchBufs {
    fn new() -> Self {
        let mut storage: Vec<Vec<u8>> = (0..NL_BATCH_SIZE)
            .map(|_| vec![0u8; NL_BUF_SIZE])
            .collect();
        let mut iovecs: Vec<libc::iovec> = storage
            .iter_mut()
            .map(|buf| libc::iovec {
                iov_base: buf.as_mut_ptr() as *mut libc::c_void,
                iov_len: buf.len(),
            })
            .collect();
        let mut msgs: Vec<libc::mmsghdr> = (0..NL_BATCH_SIZE)
            .map(|_| unsafe { std::mem::zeroed() })
            .collect();
        for (i, msg) in msgs.iter_mut().enumerate() {
            msg.msg_hdr.msg_iov = &mut iovecs[i] as *mut _;
            msg.msg_hdr.msg_iovlen = 1;
            msg.msg_hdr.msg_name = std::ptr::null_mut();
            msg.msg_hdr.msg_namelen = 0;
            msg.msg_hdr.msg_control = std::ptr::null_mut();
            msg.msg_hdr.msg_controllen = 0;
            msg.msg_hdr.msg_flags = 0;
            msg.msg_len = 0;
        }
        BatchBufs {
            storage,
            iovecs,
            msgs,
        }
    }

    /// Reset per-call mutable fields on the first `n` slots. The
    /// iov_base / iov_len / msg_iov bindings stay valid.
    fn prepare(&mut self, n: usize) {
        for i in 0..n {
            self.msgs[i].msg_len = 0;
            self.msgs[i].msg_hdr.msg_flags = 0;
        }
    }
}

#[cfg(feature = "syscall_batch")]
impl NetlinkSocket {
    /// Poll-based batched recv for `Stream` implementations
    /// (`DumpStream`, multicast event streams). Same semantics as
    /// [`Self::recv_batch`] but exposes the batch via the
    /// `Poll<Result<Vec<Vec<u8>>>>` shape.
    pub fn poll_recv_batch(
        &self,
        cx: &mut Context<'_>,
        max: usize,
    ) -> Poll<Result<Vec<Vec<u8>>>> {
        let max = max.clamp(1, NL_BATCH_SIZE);
        loop {
            let mut guard = match self.fd.poll_read_ready(cx) {
                Poll::Ready(Ok(guard)) => guard,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e.into())),
                Poll::Pending => return Poll::Pending,
            };
            let result: std::result::Result<std::io::Result<Vec<Vec<u8>>>, _> =
                guard.try_io(|inner| Self::recv_batch_inner(inner.get_ref().as_raw_fd(), max));
            match result {
                Ok(Ok(frames)) => return Poll::Ready(Ok(frames)),
                Ok(Err(e)) => return Poll::Ready(Err(Error::Io(e))),
                Err(_would_block) => continue,
            }
        }
    }

    /// Receive up to `max` netlink datagrams in one `recvmmsg(2)`
    /// syscall.
    ///
    /// Pushes each successfully-received frame as an owned `Vec<u8>`
    /// onto `out` (not cleared). Returns the count received in
    /// this call. `max` is clamped to [`NL_BATCH_SIZE`].
    ///
    /// On `EAGAIN`/`EWOULDBLOCK` returns `Ok(0)` after the
    /// `AsyncFd` re-arms — caller can poll again or back off.
    /// Other syscall errors propagate. `MSG_TRUNC` on any slot is
    /// promoted to `Error::InvalidMessage` ("frame exceeded
    /// `NL_BUF_SIZE`") — the 32 KiB per-slot buffer exceeds every
    /// realistic netlink frame, so this signals a kernel ABI
    /// violation worth screaming about rather than silently
    /// dropping bytes.
    ///
    /// The per-socket buffer pool is lazily allocated on first
    /// call (`NL_BATCH_SIZE * NL_BUF_SIZE = 1 MiB`) and reused
    /// across subsequent calls.
    ///
    /// # Cancellation safety
    ///
    /// Cancellation-safe: dropping the future before the syscall
    /// completes leaves the socket state intact (AsyncFd has not
    /// consumed any data). Re-polling resumes cleanly.
    pub async fn recv_batch(&self, out: &mut Vec<Vec<u8>>, max: usize) -> Result<usize> {
        let max = max.clamp(1, NL_BATCH_SIZE);
        loop {
            let mut guard = self.fd.ready(Interest::READABLE).await?;
            // try_io expects io::Result<T> so it can spot
            // WouldBlock — we map nlink::Error back through Io to
            // satisfy that contract, then unwrap at the outer
            // layer. The Other-shaped Error::InvalidMessage stays
            // typed via the OS-error roundtrip below.
            let result: std::result::Result<std::io::Result<Vec<Vec<u8>>>, _> =
                guard.try_io(|inner| Self::recv_batch_inner(inner.get_ref().as_raw_fd(), max));
            match result {
                Ok(Ok(frames)) => {
                    let n = frames.len();
                    out.extend(frames);
                    return Ok(n);
                }
                Ok(Err(e)) => return Err(Error::Io(e)),
                Err(_would_block) => continue,
            }
        }
    }

    fn recv_batch_inner(fd: RawFd, max: usize) -> std::io::Result<Vec<Vec<u8>>> {
        // Per-call buffer pool — lazily initialized in TLS to keep
        // recv_batch &self (no Mutex contention). The cost is one
        // BatchBufs per thread that ever calls recv_batch on any
        // socket; for the per-connection single-flight pattern
        // that's exactly one.
        thread_local! {
            static BUFS: std::cell::RefCell<Option<BatchBufs>> =
                const { std::cell::RefCell::new(None) };
        }

        BUFS.with(|cell| {
            let mut borrow = cell.borrow_mut();
            let bufs = borrow.get_or_insert_with(BatchBufs::new);
            bufs.prepare(max);

            // SAFETY: `recvmmsg` requires the mmsghdr array to be
            // valid for reads and writes for `max` entries; we own
            // it via the thread-local BatchBufs and the iovec
            // pointers reference owned storage that outlives this
            // call (storage is never resized after BatchBufs::new).
            // MSG_DONTWAIT skips blocking; timeout = NULL because
            // the kernel `timeout` arg has been buggy since 2010
            // (see `man recvmmsg(2)` BUGS) — tokio::time::timeout
            // is the right tool.
            let n = unsafe {
                libc::recvmmsg(
                    fd,
                    bufs.msgs.as_mut_ptr(),
                    max as libc::c_uint,
                    libc::MSG_DONTWAIT,
                    std::ptr::null_mut(),
                )
            };
            if n < 0 {
                return Err(std::io::Error::last_os_error());
            }

            let mut frames = Vec::with_capacity(n as usize);
            for i in 0..n as usize {
                let len = bufs.msgs[i].msg_len as usize;
                let flags = bufs.msgs[i].msg_hdr.msg_flags;
                if flags & libc::MSG_TRUNC != 0 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!(
                            "netlink frame {} exceeded NL_BUF_SIZE ({} bytes > {} buffer); \
                             file an issue with the kernel version + subsystem",
                            i, len, NL_BUF_SIZE
                        ),
                    ));
                }
                frames.push(bufs.storage[i][..len].to_vec());
            }
            Ok(frames)
        })
    }

    /// Send up to `msgs.len()` netlink request frames in one
    /// `sendmmsg(2)` syscall. `msgs.len()` clamped to
    /// [`NL_BATCH_SIZE`].
    ///
    /// Returns the count successfully sent. Partial sends are
    /// possible — per `sendmmsg(2)`, if slot K errors the call
    /// returns K (the successful prefix) and the K-th error is
    /// silently dropped. Caller handles partial-send by re-calling
    /// from the returned offset; the resulting `-1` return will
    /// carry the real errno.
    ///
    /// **Important**: per-request kernel processing errors (the
    /// kernel's `NLMSG_ERROR` responses to malformed requests)
    /// are NOT surfaced here — they arrive asynchronously on the
    /// receive side, matched by `nlmsg_seq`. `send_batch` only
    /// reports syscall-level errors (`ENOBUFS`, `EMSGSIZE`, etc.).
    pub async fn send_batch(&self, msgs: &[&[u8]]) -> Result<usize> {
        if msgs.is_empty() {
            return Ok(0);
        }
        let n = msgs.len().min(NL_BATCH_SIZE);

        loop {
            let mut guard = self.fd.ready(Interest::WRITABLE).await?;
            let result: std::result::Result<std::io::Result<usize>, _> = guard.try_io(|inner| {
                Self::send_batch_inner(inner.get_ref().as_raw_fd(), &msgs[..n])
            });
            match result {
                Ok(Ok(sent)) => return Ok(sent),
                Ok(Err(e)) => return Err(Error::Io(e)),
                Err(_would_block) => continue,
            }
        }
    }

    fn send_batch_inner(fd: RawFd, msgs: &[&[u8]]) -> std::io::Result<usize> {
        let mut iovecs: Vec<libc::iovec> = msgs
            .iter()
            .map(|m| libc::iovec {
                iov_base: m.as_ptr() as *mut libc::c_void,
                iov_len: m.len(),
            })
            .collect();
        let mut mmsg: Vec<libc::mmsghdr> = (0..msgs.len())
            .map(|i| unsafe {
                let mut hdr: libc::mmsghdr = std::mem::zeroed();
                hdr.msg_hdr.msg_iov = &mut iovecs[i] as *mut _;
                hdr.msg_hdr.msg_iovlen = 1;
                hdr
            })
            .collect();

        // SAFETY: mmsghdr + iovec arrays are owned for the duration
        // of the call; pointers from `msgs.iter().as_ptr()` are
        // valid for `msg.len()` bytes (the slice's invariant).
        // MSG_DONTWAIT avoids blocking the executor thread.
        let n = unsafe {
            libc::sendmmsg(
                fd,
                mmsg.as_mut_ptr(),
                msgs.len() as libc::c_uint,
                libc::MSG_DONTWAIT,
            )
        };
        if n < 0 {
            return Err(std::io::Error::last_os_error());
        }
        // Verify each successful slot wrote the full input length;
        // partial writes shouldn't happen on netlink (datagram
        // semantics) but if they do, surface as WriteZero.
        for (i, slot) in mmsg.iter().enumerate().take(n as usize) {
            if slot.msg_len as usize != msgs[i].len() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::WriteZero,
                    format!(
                        "sendmmsg slot {i}: wrote {} of {} bytes",
                        slot.msg_len,
                        msgs[i].len()
                    ),
                ));
            }
        }
        Ok(n as usize)
    }
}

#[cfg(all(test, feature = "syscall_batch"))]
mod batch_tests {
    use super::*;

    #[test]
    fn batch_bufs_initialization_wires_iovecs() {
        let bufs = BatchBufs::new();
        assert_eq!(bufs.storage.len(), NL_BATCH_SIZE);
        assert_eq!(bufs.iovecs.len(), NL_BATCH_SIZE);
        assert_eq!(bufs.msgs.len(), NL_BATCH_SIZE);
        for i in 0..NL_BATCH_SIZE {
            assert_eq!(bufs.storage[i].len(), NL_BUF_SIZE);
            assert_eq!(bufs.iovecs[i].iov_len, NL_BUF_SIZE);
            assert_eq!(bufs.iovecs[i].iov_base as *const u8, bufs.storage[i].as_ptr());
            // msg_iov should point at the i-th iovec.
            assert_eq!(
                bufs.msgs[i].msg_hdr.msg_iov as *const libc::iovec,
                &bufs.iovecs[i] as *const libc::iovec
            );
            assert_eq!(bufs.msgs[i].msg_hdr.msg_iovlen, 1);
        }
    }

    #[test]
    fn batch_bufs_prepare_resets_mutable_fields() {
        let mut bufs = BatchBufs::new();
        // Pretend a previous recvmmsg populated these.
        bufs.msgs[0].msg_len = 1234;
        bufs.msgs[0].msg_hdr.msg_flags = libc::MSG_TRUNC;
        bufs.msgs[5].msg_len = 567;
        bufs.prepare(8);
        assert_eq!(bufs.msgs[0].msg_len, 0);
        assert_eq!(bufs.msgs[0].msg_hdr.msg_flags, 0);
        assert_eq!(bufs.msgs[5].msg_len, 0);
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
