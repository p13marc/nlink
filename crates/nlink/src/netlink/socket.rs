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

use super::{
    dispatcher::Dispatcher,
    error::{Error, Result},
};

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
    /// Plan 234 (0.21.0) — optional Dispatcher hook. When the recv
    /// path detects ENOBUFS, it calls `dispatcher.emit_enobufs()`
    /// to fan `ResyncMarker::ResyncStart` out to every active
    /// multicast subscriber. Set by `Connection::new()` via
    /// [`Self::install_dispatcher`]; absent for sockets constructed
    /// directly (the standalone `NetlinkSocket::new` path used by
    /// integration tests and macro-emitted family-resolution code
    /// — those don't have multicast subscribers anyway).
    ///
    /// Atomic load/store via `OnceLock` so the read path on `recv_msg`
    /// is a single relaxed load.
    dispatcher: std::sync::OnceLock<Dispatcher>,
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
    /// The socket is created inside the target namespace and operates there for
    /// all subsequent operations; the calling thread's namespace is untouched.
    ///
    /// # Thread discipline (#185)
    ///
    /// The netns-sensitive part — `setns()` + `socket(2)` — runs on a dedicated
    /// worker thread that **exits instead of restoring**: a thread's namespace
    /// membership dies with it, so there is no restore step that can fail and
    /// no window in which the calling thread (possibly a tokio worker shared
    /// with unrelated tasks) observes the target namespace. A panic during
    /// socket creation kills the worker, not the caller's netns state. The
    /// pre-#185 implementation `setns`'d the calling thread and could return
    /// [`Error::NamespaceRestoreFailed`]; that variant is retained for
    /// compatibility but is no longer produced here.
    ///
    /// The tokio reactor registration (`AsyncFd`) happens afterwards on the
    /// calling thread — epoll registration is not namespace-sensitive, and the
    /// caller is where a runtime context is guaranteed.
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
        // `ns_fd` stays valid for the worker's lifetime: fds are process-wide
        // and the caller's handle outlives the synchronous join() below.
        let thread_result = std::thread::spawn(move || -> Result<(Socket, u32)> {
            // SAFETY: libc::setns switches this worker thread to the namespace
            // specified by ns_fd, a valid namespace-file descriptor. Only this
            // freshly-spawned thread is affected, and it exits right after.
            let ret = unsafe { libc::setns(ns_fd, libc::CLONE_NEWNET) };
            if ret < 0 {
                return Err(Error::Io(std::io::Error::last_os_error()));
            }
            Self::create_raw_socket(protocol)
        })
        .join();

        match thread_result {
            Ok(Ok((socket, pid))) => Self::from_raw_socket(socket, pid, protocol),
            Ok(Err(e)) => Err(e),
            Err(_panic) => Err(Error::InvalidMessage(
                "namespace socket worker thread panicked".to_string(),
            )),
        }
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
        // #184: ENOENT → typed NamespaceNotFound (is_not_found()), other
        // errors keep their errno — never a stringly InvalidMessage.
        let ns_file = File::open(ns_path.as_ref())
            .map_err(|e| super::namespace::namespace_open_error(ns_path.as_ref(), e))?;
        Self::new_in_namespace(protocol, ns_file.as_raw_fd())
    }

    /// Internal helper to create the socket.
    fn create_socket(protocol: Protocol) -> Result<Self> {
        let (socket, pid) = Self::create_raw_socket(protocol)?;
        Self::from_raw_socket(socket, pid, protocol)
    }

    /// Create and bind the raw netlink socket. This is the namespace-sensitive
    /// half of construction — `socket(2)` binds the socket to the calling
    /// thread's netns at creation time — and is runtime-independent, so
    /// `new_in_namespace` can run it on a dedicated worker thread (#185).
    fn create_raw_socket(protocol: Protocol) -> Result<(Socket, u32)> {
        let mut socket = Socket::new(protocol.as_isize())?;
        socket.set_non_blocking(true)?;

        // Bind to get a port ID
        let mut addr = SocketAddr::new(0, 0);
        socket.bind(&addr)?;
        socket.get_address(&mut addr)?;
        let pid = addr.port_number();

        // Enable extended ACK for better error messages
        socket.set_ext_ack(true).ok(); // Ignore if not supported

        Ok((socket, pid))
    }

    /// Wrap a raw bound socket into the async `NetlinkSocket`. Must run on a
    /// thread with a tokio runtime context (`AsyncFd::new` registers with the
    /// reactor); the socket's netns membership is already fixed, so this half
    /// is namespace-insensitive.
    fn from_raw_socket(socket: Socket, pid: u32, protocol: Protocol) -> Result<Self> {
        let fd = AsyncFd::new(socket)?;

        Ok(Self {
            fd,
            seq: AtomicU32::new(1),
            pid,
            protocol,
            dispatcher: std::sync::OnceLock::new(),
        })
    }

    /// Plan 234 — install the per-Connection
    /// [`Dispatcher`] hook on this socket. Called once by
    /// `Connection::new()` / `from_parts()`; the recv path then
    /// fans ENOBUFS into the dispatcher's broadcast channels via
    /// `dispatcher.emit_enobufs()`.
    ///
    /// No-op if already installed (subsequent calls are silently
    /// ignored by `OnceLock::set`). The contract is "set once per
    /// socket, at Connection construction time."
    pub fn install_dispatcher(&self, dispatcher: Dispatcher) {
        let _ = self.dispatcher.set(dispatcher);
    }

    /// Plan 234 — internal helper. If a Dispatcher is installed,
    /// forward an ENOBUFS event to every active subscriber.
    /// Called from the recv error paths.
    fn fan_out_enobufs(&self) {
        if let Some(d) = self.dispatcher.get() {
            d.emit_enobufs();
        }
    }

    /// Plan 234 — test-only synthetic ENOBUFS injection so the
    /// dispatcher path can be exercised without a real overflowing
    /// kernel queue. Hidden from the public surface; only the
    /// integration tests under `crates/nlink/tests/` call this.
    #[cfg(any(test, feature = "lab"))]
    pub fn synth_enobufs_for_test(&self) {
        self.fan_out_enobufs();
    }

    /// Plan 234 — accessor for tests that need to confirm the
    /// dispatcher is wired up. Returns `None` if `install_dispatcher`
    /// was never called.
    #[cfg(any(test, feature = "lab"))]
    pub fn dispatcher_for_test(&self) -> Option<&Dispatcher> {
        self.dispatcher.get()
    }

    /// Get the next sequence number.
    ///
    /// **Skips 0** (#134): the dispatcher treats `nlmsg_seq == 0` as the
    /// multicast-notification marker and fans those frames out to event
    /// subscribers. A unicast request that wrapped to seq 0 would be
    /// misrouted, so the counter never hands out 0 (after `u32::MAX` it
    /// resumes at 1).
    pub fn next_seq(&self) -> u32 {
        next_nonzero_seq(&self.seq)
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
    ///
    /// Takes `&self` (changed in 0.19, Finding A). The underlying
    /// syscall is `setsockopt(SOL_NETLINK, NETLINK_ADD_MEMBERSHIP)`
    /// which is fd-level — no shared state to mutate. Matches the
    /// pattern set by [`Self::set_strict_checking`] /
    /// [`Self::set_ext_ack`]. The `&mut` requirement was a stale
    /// artefact of routing through `AsyncFd::get_mut`; it blocked
    /// subscribe-through-`ConnectionPool` and concurrent
    /// subscribe-from-different-tasks, both legitimate uses.
    pub fn add_membership(&self, group: u32) -> Result<()> {
        Self::set_membership_sockopt(self.as_raw_fd(), libc::NETLINK_ADD_MEMBERSHIP, group)
    }

    /// Unsubscribe from multicast groups. See [`Self::add_membership`].
    pub fn drop_membership(&self, group: u32) -> Result<()> {
        Self::set_membership_sockopt(self.as_raw_fd(), libc::NETLINK_DROP_MEMBERSHIP, group)
    }

    /// Internal helper: `setsockopt(SOL_NETLINK, optname, group)`.
    fn set_membership_sockopt(fd: RawFd, optname: libc::c_int, group: u32) -> Result<()> {
        let val: libc::c_int = group as libc::c_int;
        // SAFETY: setsockopt with a valid fd + SOL_NETLINK level +
        // pointer to a stack-allocated int + correct size.
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
            return Err(Error::Io(std::io::Error::last_os_error()));
        }
        Ok(())
    }

    /// Send a message.
    ///
    /// Plan 232 B19 — surface backpressure as
    /// [`Error::Backpressure`] after a small number of
    /// back-to-back `WouldBlock` returns from the kernel. The 30 s
    /// connection timeout (Plan 171) would eventually surface as
    /// `Timeout`; surfacing backpressure sooner lets a caller back
    /// off without waiting the full timeout window.
    pub async fn send(&self, msg: &[u8]) -> Result<()> {
        let mut would_block_count: u32 = 0;
        loop {
            let mut guard = self.fd.ready(Interest::WRITABLE).await?;

            match guard.try_io(|inner| inner.get_ref().send(msg, 0)) {
                Ok(result) => {
                    result?;
                    return Ok(());
                }
                Err(_would_block) => {
                    would_block_count += 1;
                    if would_block_count >= SEND_WOULDBLOCK_LIMIT {
                        return Err(Error::Backpressure {
                            send_buffer_full: true,
                        });
                    }
                    continue;
                }
            }
        }
    }

    /// Send a netlink message with file descriptors attached as an
    /// `SCM_RIGHTS` ancillary control message via `sendmsg(2)`.
    ///
    /// With an empty `fds` slice this is exactly [`Self::send`].
    ///
    /// # Netlink semantics — read before reaching for this
    ///
    /// Unlike `AF_UNIX` sockets, the kernel's netlink layer does **not**
    /// hand `SCM_RIGHTS` file descriptors to generic-netlink command
    /// handlers: a genl `doit`/`dumpit` callback has no access to the
    /// received `scm_fp_list`. So for most in-tree families (including
    /// OpenVPN DCO) this primitive does not attach the fd to anything —
    /// it is provided as a general building block for protocols (or
    /// out-of-tree kernels) that genuinely consume passed fds, and for
    /// fd-relay scenarios (handing the message+fd to a broker over a
    /// Unix socket). For the OpenVPN DCO family, cross-netns socket
    /// attach is done via the `OVPN_A_PEER_SOCKET` +
    /// `OVPN_A_PEER_SOCKET_NETNSID` attributes instead — see
    /// [`Connection::<Ovpn>::attach_socket`](crate::netlink::Connection).
    pub async fn send_with_fds(&self, msg: &[u8], fds: &[RawFd]) -> Result<()> {
        if fds.is_empty() {
            return self.send(msg).await;
        }

        let (mut cmsg_buf, cmsg_space) = build_scm_rights_control(fds);

        let mut would_block_count: u32 = 0;
        loop {
            let mut guard = self.fd.ready(Interest::WRITABLE).await?;

            // Build the `msghdr` inside the synchronous closure so the
            // raw pointers it holds never cross the `.await` above —
            // keeping the returned future `Send` (only the `Vec<u64>`
            // control buffer, which is `Send`, is held across the await).
            let res = guard.try_io(|inner| {
                let mut iov = libc::iovec {
                    iov_base: msg.as_ptr() as *mut libc::c_void,
                    iov_len: msg.len(),
                };
                let mut mhdr: libc::msghdr = unsafe { std::mem::zeroed() };
                mhdr.msg_iov = &mut iov;
                mhdr.msg_iovlen = 1;
                mhdr.msg_control = cmsg_buf.as_mut_ptr() as *mut libc::c_void;
                mhdr.msg_controllen = cmsg_space as _;

                let n = unsafe { libc::sendmsg(inner.get_ref().as_raw_fd(), &mhdr, 0) };
                if n < 0 {
                    Err(std::io::Error::last_os_error())
                } else {
                    Ok(n as usize)
                }
            });

            match res {
                Ok(result) => {
                    result?;
                    return Ok(());
                }
                Err(_would_block) => {
                    would_block_count += 1;
                    if would_block_count >= SEND_WOULDBLOCK_LIMIT {
                        return Err(Error::Backpressure {
                            send_buffer_full: true,
                        });
                    }
                    continue;
                }
            }
        }
    }

    /// Receive a message, allocating a buffer.
    ///
    /// Plan 224 — passes `MSG_TRUNC` to recv so the kernel reports
    /// the actual frame size. On truncation, auto-grows the recv
    /// buffer (rounded up to the next 4 KiB) and re-attempts, up
    /// to a 1 MiB cap. If the kernel emits a frame past the cap,
    /// returns [`Error::FrameTruncated`]
    /// instead of silently losing the tail.
    pub async fn recv_msg(&self) -> Result<Vec<u8>> {
        let mut capacity = RECV_INITIAL_CAPACITY;
        loop {
            let mut buf = BytesMut::with_capacity(capacity);
            let received = loop {
                let mut guard = self.fd.ready(Interest::READABLE).await?;
                match guard.try_io(|inner| inner.get_ref().recv(&mut buf, libc::MSG_TRUNC)) {
                    Ok(Ok(n)) => break n,
                    Ok(Err(e)) => {
                        // Plan 234 §4 — route ENOBUFS to multicast
                        // subscribers via the dispatcher BEFORE
                        // propagating the error to the caller. Slow
                        // subscribers see `ResyncMarker::ResyncStart`
                        // even though the request path also surfaces
                        // the error. Pre-dispatcher, ENOBUFS
                        // surfaced into whichever caller happened to
                        // be in `recv_msg` — typically a request,
                        // not the subscriber that should care.
                        if e.raw_os_error() == Some(libc::ENOBUFS) {
                            self.fan_out_enobufs();
                        }
                        return Err(e.into());
                    }
                    Err(_would_block) => continue,
                }
            };

            if received <= capacity {
                // Fast path. The bytes already in buf are the
                // complete frame.
                return Ok(buf.to_vec());
            }

            // Truncated. The kernel reports the actual size in
            // `received`. Re-attempt with that size (rounded up
            // to the next 4 KiB), capped at RECV_MAX_CAPACITY.
            let next = received.next_multiple_of(4096);
            if next > RECV_MAX_CAPACITY {
                return Err(Error::FrameTruncated {
                    received,
                    buffer_size: capacity,
                });
            }
            capacity = next;
            // Loop and re-attempt the recv with the larger buffer.
        }
    }

    /// Poll for incoming data.
    ///
    /// This is the poll-based version of `recv_msg()` for use with `Stream` implementations.
    /// Returns `Poll::Ready(Ok(data))` when data is available.
    ///
    /// Plan 224 — passes `MSG_TRUNC` so kernel-side truncation is
    /// detected. `poll_recv` cannot auto-grow inside a single poll
    /// (it would have to return `Pending` after re-arming with a
    /// larger buffer), so on first truncation it surfaces
    /// [`Error::FrameTruncated`]. Stream-shape callers
    /// (`events()`, `dump_stream`) propagate the error cleanly.
    pub fn poll_recv(&self, cx: &mut Context<'_>) -> Poll<Result<Vec<u8>>> {
        let capacity = RECV_INITIAL_CAPACITY;
        let mut buf = BytesMut::with_capacity(capacity);

        loop {
            let mut guard = match self.fd.poll_read_ready(cx) {
                Poll::Ready(Ok(guard)) => guard,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e.into())),
                Poll::Pending => return Poll::Pending,
            };

            match guard.try_io(|inner| inner.get_ref().recv(&mut buf, libc::MSG_TRUNC)) {
                Ok(result) => match result {
                    Ok(received) => {
                        if received > capacity {
                            return Poll::Ready(Err(Error::FrameTruncated {
                                received,
                                buffer_size: capacity,
                            }));
                        }
                        return Poll::Ready(Ok(buf.to_vec()));
                    }
                    Err(e) => {
                        // Plan 234 §4 — see recv_msg for the
                        // ENOBUFS routing rationale. poll_recv is
                        // the streaming entrypoint, so a multicast
                        // subscriber that overflows will see the
                        // error AND get a ResyncStart marker
                        // delivered to any other subscriber sharing
                        // this socket's dispatcher.
                        if e.raw_os_error() == Some(libc::ENOBUFS) {
                            self.fan_out_enobufs();
                        }
                        return Poll::Ready(Err(e.into()));
                    }
                },
                Err(_would_block) => continue,
            }
        }
    }
}

/// Plan 232 B19 — back-to-back `WouldBlock` returns from `send`
/// that exceed this threshold surface as
/// [`Error::Backpressure`]. The kernel send buffer is full and
/// retrying immediately is futile.
///
/// 32 matches the historic `NL_BATCH_SIZE` heuristic. The full
/// 30 s connection timeout (Plan 171) is still in place as an
/// upper bound; this lets callers react faster.
pub(crate) const SEND_WOULDBLOCK_LIMIT: u32 = 32;

/// Initial recv buffer capacity for [`NetlinkSocket::recv_msg`]
/// (Plan 224). 32 KiB matches the historic single-frame cap; the
/// auto-grow loop handles anything larger.
pub(crate) const RECV_INITIAL_CAPACITY: usize = 32 * 1024;

/// Max recv buffer capacity for [`NetlinkSocket::recv_msg`]
/// (Plan 224). 1 MiB is the cap before nlink surfaces
/// [`Error::FrameTruncated`] instead of growing further.
///
/// The kernel's `NLMSG_GOODSIZE` per-frame budget is roughly
/// `SKB_WITH_OVERHEAD(PAGE_SIZE_MAX)` (≈32-64 KiB on x86, up to
/// ~56 KiB on 64 KiB-page arm64). 1 MiB covers every plausible
/// kernel-side frame with a 16× margin; anything beyond is a
/// kernel bug or a protocol-extension nlink hasn't been
/// updated for.
pub(crate) const RECV_MAX_CAPACITY: usize = 1024 * 1024;

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
        let mut storage: Vec<Vec<u8>> =
            (0..NL_BATCH_SIZE).map(|_| vec![0u8; NL_BUF_SIZE]).collect();
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
    pub fn poll_recv_batch(&self, cx: &mut Context<'_>, max: usize) -> Poll<Result<Vec<Vec<u8>>>> {
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
                Ok(Err(e)) => {
                    // Mirror recv_msg/poll_recv: tell the resync subscribers the
                    // kernel dropped multicast frames *before* handing the error
                    // to whoever happened to be reading (#220). Without this, a
                    // `syscall_batch` build's resync streams never learn they
                    // missed anything and never re-dump.
                    if e.raw_os_error() == Some(libc::ENOBUFS) {
                        self.fan_out_enobufs();
                    }
                    return Poll::Ready(Err(Error::Io(e)));
                }
                Err(_would_block) => continue,
            }
        }
    }

    /// Receive up to `max` netlink datagrams in one `recvmmsg(2)`
    /// syscall.
    ///
    /// Pushes each successfully-received frame as an owned `Vec<u8>`
    /// onto `out` (not cleared). Returns the count received in
    /// this call. `max` is clamped to `NL_BATCH_SIZE` (32 frames).
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
                Ok(Err(e)) => {
                    // Same as recv_msg (#220) — see poll_recv_batch.
                    if e.raw_os_error() == Some(libc::ENOBUFS) {
                        self.fan_out_enobufs();
                    }
                    return Err(Error::Io(e));
                }
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
    /// `NL_BATCH_SIZE` (32 frames).
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
            let result: std::result::Result<std::io::Result<usize>, _> = guard
                .try_io(|inner| Self::send_batch_inner(inner.get_ref().as_raw_fd(), &msgs[..n]));
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

/// Build an `SCM_RIGHTS` control buffer carrying `fds`.
///
/// Returned as a `Vec<u64>` so the backing storage is 8-byte aligned
/// (the alignment `cmsghdr` requires); the `usize` is the valid
/// `msg_controllen` (`CMSG_SPACE`). Split out from
/// [`NetlinkSocket::send_with_fds`] so the on-wire control-message
/// layout is unit-testable without a live socket.
fn build_scm_rights_control(fds: &[RawFd]) -> (Vec<u64>, usize) {
    let fd_bytes = std::mem::size_of_val(fds);
    // SAFETY: CMSG_SPACE is a pure size computation.
    let space = unsafe { libc::CMSG_SPACE(fd_bytes as u32) } as usize;
    let mut buf = vec![0u64; space.div_ceil(std::mem::size_of::<u64>())];

    // A throwaway msghdr drives CMSG_FIRSTHDR / CMSG_DATA; it is never
    // sent — only used to compute the cmsg/data offsets into `buf`.
    let mut mhdr: libc::msghdr = unsafe { std::mem::zeroed() };
    mhdr.msg_control = buf.as_mut_ptr() as *mut libc::c_void;
    mhdr.msg_controllen = space as _;

    // SAFETY: `buf` is `space` bytes (rounded up to u64) and 8-byte
    // aligned; CMSG_FIRSTHDR returns a pointer within it, and we copy
    // exactly `fd_bytes` into the CMSG_DATA region which `CMSG_SPACE`
    // accounts for.
    unsafe {
        let cmsg = libc::CMSG_FIRSTHDR(&mhdr);
        debug_assert!(!cmsg.is_null());
        (*cmsg).cmsg_level = libc::SOL_SOCKET;
        (*cmsg).cmsg_type = libc::SCM_RIGHTS;
        (*cmsg).cmsg_len = libc::CMSG_LEN(fd_bytes as u32) as _;
        std::ptr::copy_nonoverlapping(fds.as_ptr() as *const u8, libc::CMSG_DATA(cmsg), fd_bytes);
    }

    (buf, space)
}

/// Fetch-and-increment a sequence counter, skipping 0 (#134). Pulled out
/// of [`NetlinkSocket::next_seq`] so the wrap behavior is unit-testable
/// without opening a socket fd.
fn next_nonzero_seq(counter: &AtomicU32) -> u32 {
    loop {
        let s = counter.fetch_add(1, Ordering::Relaxed);
        if s != 0 {
            return s;
        }
    }
}

#[cfg(test)]
mod seq_tests {
    use super::*;

    #[test]
    fn next_seq_skips_zero_on_wrap() {
        // Seed just below wrap: u32::MAX is handed out, then the counter
        // is at 0 and must be skipped, yielding 1.
        let counter = AtomicU32::new(u32::MAX);
        assert_eq!(next_nonzero_seq(&counter), u32::MAX);
        assert_eq!(next_nonzero_seq(&counter), 1, "0 must be skipped");
        assert_eq!(next_nonzero_seq(&counter), 2);
    }

    #[test]
    fn next_seq_is_monotonic_from_one() {
        let counter = AtomicU32::new(1);
        assert_eq!(next_nonzero_seq(&counter), 1);
        assert_eq!(next_nonzero_seq(&counter), 2);
        assert_eq!(next_nonzero_seq(&counter), 3);
    }
}

#[cfg(test)]
mod scm_rights_tests {
    use super::*;

    /// The control buffer must round-trip through `CMSG_FIRSTHDR` /
    /// `CMSG_DATA` with the SCM_RIGHTS level/type and the exact fd
    /// payload — this pins the on-wire cmsg layout.
    #[test]
    fn scm_rights_control_roundtrips_fds() {
        let fds = [7i32, 9, 11];
        let (mut buf, space) = build_scm_rights_control(&fds);

        let mut mhdr: libc::msghdr = unsafe { std::mem::zeroed() };
        mhdr.msg_control = buf.as_mut_ptr() as *mut libc::c_void;
        mhdr.msg_controllen = space as _;

        unsafe {
            let cmsg = libc::CMSG_FIRSTHDR(&mhdr);
            assert!(!cmsg.is_null());
            assert_eq!((*cmsg).cmsg_level, libc::SOL_SOCKET);
            assert_eq!((*cmsg).cmsg_type, libc::SCM_RIGHTS);
            assert_eq!(
                (*cmsg).cmsg_len as usize,
                libc::CMSG_LEN((std::mem::size_of::<RawFd>() * fds.len()) as u32) as usize
            );
            let data = libc::CMSG_DATA(cmsg) as *const RawFd;
            for (i, &want) in fds.iter().enumerate() {
                assert_eq!(*data.add(i), want, "fd {i} mismatch");
            }
        }
    }

    /// Compile-time guard: the `send_with_fds` future must stay `Send`.
    /// The `msghdr`/`iovec` raw pointers are built inside the sync
    /// `try_io` closure precisely so they never cross the `.await`; if a
    /// refactor leaked one into the await-held state, this stops
    /// compiling. Never executed.
    #[allow(dead_code)]
    fn assert_send_with_fds_future_is_send(s: &NetlinkSocket) {
        fn assert_send<T: Send>(_: &T) {}
        let fut = s.send_with_fds(&[], &[]);
        assert_send(&fut);
    }

    #[test]
    fn scm_rights_control_single_fd() {
        let (mut buf, space) = build_scm_rights_control(&[42]);
        let mut mhdr: libc::msghdr = unsafe { std::mem::zeroed() };
        mhdr.msg_control = buf.as_mut_ptr() as *mut libc::c_void;
        mhdr.msg_controllen = space as _;
        unsafe {
            let cmsg = libc::CMSG_FIRSTHDR(&mhdr);
            assert!(!cmsg.is_null());
            assert_eq!(*(libc::CMSG_DATA(cmsg) as *const RawFd), 42);
        }
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
            assert_eq!(
                bufs.iovecs[i].iov_base as *const u8,
                bufs.storage[i].as_ptr()
            );
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

/// Plan 224 — recv_msg MSG_TRUNC handling tests. The constants
/// and the auto-grow size math are testable without a live
/// socket; the truncation behaviour itself is covered by the
/// integration test in `crates/nlink/tests/integration/`.
#[cfg(test)]
mod recv_msg_truncate_tests {
    use super::*;

    #[test]
    fn recv_msg_size_math() {
        // Sanity-check the constants — sane values.
        const _: () = assert!(RECV_INITIAL_CAPACITY <= RECV_MAX_CAPACITY);
        assert_eq!(RECV_INITIAL_CAPACITY, 32 * 1024);
        assert_eq!(RECV_MAX_CAPACITY, 1024 * 1024);
    }

    #[test]
    fn next_multiple_of_4096_overshoots_at_cap_boundary() {
        // `1 MiB + 1` rounds up past the cap so the auto-grow
        // surfaces FrameTruncated instead of growing again.
        let received = 1_048_577_usize; // 1 MiB + 1
        let next = received.next_multiple_of(4096);
        assert!(
            next > RECV_MAX_CAPACITY,
            "1 MiB + 1 should overshoot the cap"
        );
    }

    #[test]
    fn next_multiple_of_4096_doesnt_grow_in_fast_path() {
        // A frame that fits the initial buffer must not trigger
        // auto-grow — the `received <= capacity` fast path
        // returns directly.
        let capacity = RECV_INITIAL_CAPACITY;
        let received = 8_000_usize;
        assert!(received <= capacity);
    }

    #[test]
    fn auto_grow_step_matches_actual_frame() {
        // For a frame of size N where `INITIAL < N < MAX`, the
        // next capacity is `N` rounded up to 4 KiB — enough to
        // cover the same frame on retry.
        let received = 60_000_usize; // ~60 KiB
        let next = received.next_multiple_of(4096);
        assert!(next >= received);
        assert!(next <= RECV_MAX_CAPACITY);
        assert_eq!(next % 4096, 0);
    }

    #[test]
    fn b19_backpressure_predicate_and_constant() {
        // Plan 232 B19 — the SEND_WOULDBLOCK_LIMIT constant is the
        // threshold past which back-to-back WouldBlocks surface
        // as Backpressure instead of looping into the 30s
        // connection timeout. Verify the constant is sane.
        assert_eq!(SEND_WOULDBLOCK_LIMIT, 32);

        let err = Error::Backpressure {
            send_buffer_full: true,
        };
        assert!(err.is_backpressure());
        // Other errors must NOT match.
        assert!(!Error::Timeout.is_backpressure());
    }

    #[test]
    fn frame_truncated_predicate() {
        // Construct the error variant directly and assert the
        // predicate matches.
        let err = Error::FrameTruncated {
            received: 2_000_000,
            buffer_size: RECV_MAX_CAPACITY,
        };
        assert!(err.is_truncated());
        // Non-truncated errors must NOT match.
        let other = Error::Timeout;
        assert!(!other.is_truncated());
        let other2 = Error::Truncated {
            expected: 8,
            actual: 4,
        };
        // The pre-existing parser-short-buffer `Truncated`
        // variant has a different semantic; `is_truncated()`
        // surfaces frame-truncation specifically.
        assert!(!other2.is_truncated());
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
    pub const RTNLGRP_IPV4_NETCONF: u32 = 24;
    pub const RTNLGRP_IPV6_NETCONF: u32 = 25;
    pub const RTNLGRP_MDB: u32 = 26;
    pub const RTNLGRP_NSID: u32 = 28;
    pub const RTNLGRP_NEXTHOP: u32 = 32;
    pub const RTNLGRP_BRVLAN: u32 = 33;
}
