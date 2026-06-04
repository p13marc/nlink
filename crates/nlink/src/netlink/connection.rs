//! High-level netlink connection with request/response handling.

use std::{os::unix::io::RawFd, path::Path, time::Duration};

use tracing::{instrument, warn};

use super::{
    builder::MessageBuilder,
    error::{Error, Result},
    interface_ref::InterfaceRef,
    message::{
        MessageIter, NLM_F_ACK, NLM_F_DUMP, NLM_F_REQUEST, NLMSG_HDRLEN, NlMsgError, NlMsgType,
        nlmsg_align,
    },
    parse::FromNetlink,
    protocol::{ProtocolState, Route},
    socket::NetlinkSocket,
    tc_handle::TcHandle,
};
use crate::util::AddressFamily;

/// High-level netlink connection parameterized by protocol state.
///
/// The type parameter `P` determines which protocol this connection uses
/// and which methods are available:
///
/// - [`Connection<Route>`]: RTNetlink for interfaces, addresses, routes, TC
/// - [`Connection<Generic>`]: Generic netlink for WireGuard, MACsec, etc.
///
/// # Construction
///
/// **Sync protocols** — use [`Connection::new()`]:
/// `Route`, `SockDiag`, `Generic`, `Nftables`
///
/// **GENL protocols** — use `Connection::new_async().await`:
/// `Wireguard`, `Macsec`, `Mptcp`, `Ethtool`, `Nl80211`, `Devlink`
///
/// These require async construction to resolve their Generic Netlink family ID.
/// While `Connection::new()` compiles for them (they implement `Default`), the
/// resulting connection will have an unresolved family ID and will not work.
///
/// **Other protocols** have their own constructors (e.g., `Connector`, `KobjectUevent`).
///
/// # Example
///
/// ```ignore
/// use nlink::netlink::{Connection, Route, Generic, Wireguard};
///
/// // Sync construction (Route, Generic, Nftables, SockDiag)
/// let route = Connection::<Route>::new()?;
/// let genl = Connection::<Generic>::new()?;
///
/// // Async construction (Wireguard, Macsec, Mptcp, Ethtool, Nl80211, Devlink)
/// let wg = Connection::<Wireguard>::new_async().await?;
/// ```
///
/// # Concurrency
///
/// `Connection<P>` is `Send + Sync` and safe to share across
/// tokio tasks via `Arc<Connection<P>>`. As of 0.19 (closing the
/// F1 architectural concurrency issue), each request/response
/// pair acquires an internal `tokio::sync::Mutex` so concurrent
/// callers on a shared `Arc<Connection>` serialize cleanly
/// instead of racing on the recv side.
///
/// The lock is held for one send + one drain-until-DONE/ACK
/// cycle, so concurrent dumps on a shared connection complete
/// in sequence rather than in parallel. For true parallel
/// throughput, use [`crate::netlink::pool::ConnectionPool<P>`]
/// — each task acquires its own connection (and therefore its
/// own netlink socket, which the kernel processes in parallel).
///
/// What the lock fixes — without it, two tasks calling
/// `get_links()` on a shared connection would race on `recv_msg`:
/// task A could consume task B's response from the socket
/// buffer, the seq filter would `continue` past it (correct
/// from A's view) but B then blocks forever waiting for a
/// response that's gone. The seq filter remains as a defensive
/// backstop against stale multicast/cross-process frames, but
/// no longer load-bears against multi-task races.
///
/// What the lock does **not** fix — multicast `events()` streams
/// running concurrently with requests still race the recv side
/// (event streams tap the socket directly and don't acquire the
/// request lock). The proper fix is a per-seq response router
/// (NlRouter-style dispatch task) — queued for 0.20.
pub struct Connection<P: ProtocolState> {
    socket: NetlinkSocket,
    state: P,
    timeout: Option<Duration>,
    /// Serialize concurrent request/response cycles on a shared
    /// `Arc<Connection<P>>`. Held by every higher-level method
    /// that does `socket.send(...) + recv-loop-until-DONE`.
    /// Closes the F1 concurrency bug (rtnetlink #131 shape) where
    /// task A's recv loop would consume task B's response from
    /// the socket buffer and drop it. See `Concurrency` above.
    ///
    /// `Arc<Mutex<()>>` (rather than `Mutex<()>`) so streams
    /// (`DumpStream`, `EventSubscription`) can take an
    /// [`tokio::sync::OwnedMutexGuard`] that lives independent
    /// of the Connection's borrow scope — see 0.19 Finding B.
    request_lock: std::sync::Arc<tokio::sync::Mutex<()>>,
}

/// Default operation timeout for `Connection<P>` (Plan 171).
///
/// 30 seconds — long enough that legitimate slow operations don't
/// trip it (kernel dumps on huge route tables: ~5-10s; nft batch
/// commits on thousands of rules: ~2-3s), short enough to fail
/// fast on the "hidden hang" class of bugs (kernel response
/// anomaly, missing DONE marker, etc.) that would otherwise block
/// indefinitely. Tunable via [`Connection::timeout`]; opt out via
/// [`Connection::no_timeout`].
///
/// The number aligns with the integration suite's existing 30s
/// explicit cap on root-gated tests — same budget, same intuition.
const DEFAULT_OPERATION_TIMEOUT: Duration = Duration::from_secs(30);

// ============================================================================
// Shared methods for protocol types that implement Default
// ============================================================================

impl<P> Connection<P>
where
    P: ProtocolState + Default + crate::netlink::protocol::construction::SyncConstructible,
{
    /// Create a new connection for this protocol type.
    ///
    /// Bounded `where P: SyncConstructible` so the GENL protocol
    /// markers (`Wireguard`, `Macsec`, `Mptcp`, `Ethtool`, `Nl80211`,
    /// `Devlink`) are a **compile error** here — those families need
    /// async family-ID resolution and must use `new_async().await`.
    /// Sync-constructible markers are: `Route`, `SockDiag`, `Generic`,
    /// `KobjectUevent`, `Connector`, `Netfilter`, `Xfrm`, `FibLookup`,
    /// `SELinux`, `Audit`, `Nftables`.
    ///
    /// Before 0.16.0 this method took only `P: ProtocolState + Default`,
    /// which let `Connection::<Wireguard>::new()` compile and return a
    /// connection with `family_id = 0`; the first operation then failed
    /// with a confusing kernel error. The new bound prevents that
    /// class of bug at the type level.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use nlink::netlink::{Connection, Route, Generic};
    ///
    /// let route = Connection::<Route>::new()?;
    /// let genl = Connection::<Generic>::new()?;
    /// ```
    #[instrument(level = "info", skip_all, fields(protocol = std::any::type_name::<P>()))]
    pub fn new() -> Result<Self> {
        Ok(Self {
            socket: NetlinkSocket::new(P::PROTOCOL)?,
            state: P::default(),
            timeout: Some(DEFAULT_OPERATION_TIMEOUT),
            request_lock: std::sync::Arc::new(tokio::sync::Mutex::new(())),
        })
    }

    /// Create a connection that operates in a specific network namespace.
    ///
    /// The namespace is specified by an open file descriptor to a namespace file
    /// (e.g., `/proc/<pid>/ns/net` or `/var/run/netns/<name>`).
    ///
    /// # Example
    ///
    /// ```ignore
    /// use std::fs::File;
    /// use std::os::unix::io::AsRawFd;
    /// use nlink::netlink::{Connection, Route};
    ///
    /// let ns_file = File::open("/var/run/netns/myns")?;
    /// let conn = Connection::<Route>::new_in_namespace(ns_file.as_raw_fd())?;
    ///
    /// // All operations now occur in the "myns" namespace
    /// let links = conn.get_links().await?;
    /// ```
    #[instrument(level = "info", skip_all, fields(protocol = std::any::type_name::<P>(), ns_fd))]
    pub fn new_in_namespace(ns_fd: RawFd) -> Result<Self> {
        Ok(Self {
            socket: NetlinkSocket::new_in_namespace(P::PROTOCOL, ns_fd)?,
            state: P::default(),
            timeout: Some(DEFAULT_OPERATION_TIMEOUT),
            request_lock: std::sync::Arc::new(tokio::sync::Mutex::new(())),
        })
    }

    /// Create a connection that operates in a network namespace specified by path.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use nlink::netlink::{Connection, Route};
    ///
    /// // For a named namespace (created via `ip netns add myns`)
    /// let conn = Connection::<Route>::new_in_namespace_path("/var/run/netns/myns")?;
    ///
    /// // For a container's namespace
    /// let conn = Connection::<Route>::new_in_namespace_path("/proc/1234/ns/net")?;
    ///
    /// // Query interfaces in that namespace
    /// let links = conn.get_links().await?;
    /// ```
    #[instrument(level = "info", skip_all, fields(protocol = std::any::type_name::<P>(), ns_path = %ns_path.as_ref().display()))]
    pub fn new_in_namespace_path<T: AsRef<Path>>(ns_path: T) -> Result<Self> {
        Ok(Self {
            socket: NetlinkSocket::new_in_namespace_path(P::PROTOCOL, ns_path)?,
            state: P::default(),
            timeout: Some(DEFAULT_OPERATION_TIMEOUT),
            request_lock: std::sync::Arc::new(tokio::sync::Mutex::new(())),
        })
    }
}

// ============================================================================
// Generic async constructor for GENL families
// ============================================================================
//
// `new_async()` was hand-rolled per-family in 0.15 (one inherent
// `impl Connection<Wireguard>::new_async()`, one for `Macsec`, etc.).
// 0.16's `#[genl_family(...)]` macro emits the `AsyncProtocolInit`
// impl that this generic constructor needs, so macro-defined
// families plug into the canonical API automatically. The
// hand-rolled per-family `new_async()` impls remain for backwards
// compatibility (the inherent versions take priority over this
// generic one when both apply).

impl<P> Connection<P>
where
    P: super::protocol::AsyncProtocolInit
        + super::protocol::construction::AsyncConstructible,
{
    /// Create a connection for a GENL family whose ID must be
    /// resolved at construction time.
    ///
    /// Generic over any `P: AsyncConstructible + AsyncProtocolInit`
    /// — the in-tree GENL family markers (`Wireguard`, `Macsec`,
    /// `Mptcp`, `Devlink`, `Nl80211`, `Ethtool`) and every family
    /// declared via `#[genl_family(name = ..., version = ...)]`
    /// satisfy the bound.
    ///
    /// Bounded so that sync-only markers (`Route`, `Generic`,
    /// `SockDiag`, `Netfilter`, etc.) are a **compile error** here
    /// — those don't need async setup and should call
    /// [`Self::new`].
    ///
    /// # Example
    ///
    /// ```ignore
    /// use nlink::netlink::{Connection, Wireguard};
    ///
    /// let wg = Connection::<Wireguard>::new_async().await?;
    /// ```
    #[instrument(level = "info", skip_all, fields(protocol = std::any::type_name::<P>()))]
    pub async fn new_async() -> Result<Self> {
        let socket = NetlinkSocket::new(P::PROTOCOL)?;
        let state = P::resolve_async(&socket).await?;
        Ok(Self::from_parts(socket, state))
    }
}

// ============================================================================
// Shared methods for all protocol types
// ============================================================================

impl<P: ProtocolState> Connection<P> {
    /// Get the underlying socket.
    pub fn socket(&self) -> &NetlinkSocket {
        &self.socket
    }

    /// Get the protocol state.
    pub fn state(&self) -> &P {
        &self.state
    }

    /// Override the operation timeout.
    ///
    /// Operations that exceed the configured duration return
    /// [`Error::Timeout`]. As of 0.17 (Plan 171) the **default is
    /// 30 seconds** — long enough for legitimate slow ops, short
    /// enough to fail fast on the "hidden hang" class of bugs
    /// (kernel response anomaly, missing DONE marker, etc.).
    /// Use this method to set a different bound; use
    /// [`Self::no_timeout`] to opt out entirely.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use nlink::{Connection, Route};
    /// use std::time::Duration;
    ///
    /// let conn = Connection::<Route>::new()?
    ///     .timeout(Duration::from_secs(5));
    /// ```
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// Opt out of the default operation timeout. Use sparingly —
    /// without a timeout, any kernel response anomaly hangs the
    /// call indefinitely (the failure mode that caused the 0.16
    /// cycle's `send_batch` CI hang; see Plan 170).
    pub fn no_timeout(mut self) -> Self {
        self.timeout = None;
        self
    }

    /// Get the configured timeout.
    pub fn get_timeout(&self) -> Option<Duration> {
        self.timeout
    }

    /// Enable kernel-side strict checking (`NETLINK_GET_STRICT_CHK`,
    /// kernel 5.0+). When enabled, the kernel validates dump request
    /// filters strictly and returns an error if they reference
    /// unknown attributes — useful for catching client/kernel-version
    /// mismatches early during development.
    ///
    /// Off by default for backwards compatibility with older
    /// kernels. The setsockopt is silently a no-op on pre-5.0
    /// kernels (returns `Ok(())` on `ENOPROTOOPT`), so calling
    /// `enable_strict_checking(true)` unconditionally is safe.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use nlink::{Connection, Route};
    /// let conn = Connection::<Route>::new()?;
    /// conn.enable_strict_checking(true)?;
    /// ```
    #[instrument(level = "debug", skip(self), fields(method = "enable_strict_checking"))]
    pub fn enable_strict_checking(&self, on: bool) -> Result<()> {
        self.socket.set_strict_checking(on)
    }

    /// Toggle extended-ack reception (`NETLINK_EXT_ACK`, kernel
    /// 4.12+). **Enabled by default** during socket construction —
    /// disabling is rarely useful in practice. Exposed for parity
    /// with neli's API and for callers that explicitly want to
    /// suppress the trailing TLVs in error responses.
    ///
    /// Silently a no-op on pre-4.12 kernels (returns `Ok(())` on
    /// `ENOPROTOOPT`).
    ///
    /// See [`Error::Kernel::ext_ack`] for what these TLVs contain
    /// once parsed.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use nlink::{Connection, Route};
    /// let conn = Connection::<Route>::new()?;
    /// conn.set_ext_ack(false)?;  // disable; rarely useful
    /// ```
    #[instrument(level = "debug", skip(self), fields(method = "set_ext_ack"))]
    pub fn set_ext_ack(&self, on: bool) -> Result<()> {
        self.socket.set_ext_ack(on)
    }

    /// Acquire the per-connection request lock for the duration of
    /// a `send + recv-loop` cycle.
    ///
    /// Every higher-level method that does `socket.send(...)` followed
    /// by a `recv_msg`/`recv_batch` loop MUST hold this guard for the
    /// whole flow. Otherwise concurrent callers on a shared
    /// `Arc<Connection<P>>` race on the recv side and lose frames.
    ///
    /// This closes the F1 architectural concurrency issue (rtnetlink
    /// #131 shape). See the struct-level `Concurrency` docstring.
    pub(crate) async fn lock_request(&self) -> tokio::sync::MutexGuard<'_, ()> {
        self.request_lock.lock().await
    }

    /// Acquire the request lock as an *owned* guard. 0.19 Finding B —
    /// used by stream-shape APIs (`DumpStream`, `EventSubscription`)
    /// that hold the lock for the stream's whole lifetime; the owned
    /// guard outlives the `&Connection` borrow scope so the stream
    /// can store it in its own struct.
    pub(crate) async fn lock_request_owned(&self) -> tokio::sync::OwnedMutexGuard<()> {
        self.request_lock.clone().lock_owned().await
    }

    /// Wrap a future with the configured timeout.
    ///
    /// If no timeout is set, the future runs without time limit.
    /// On timeout, returns [`Error::Timeout`].
    pub(crate) async fn with_timeout<F, T>(&self, fut: F) -> Result<T>
    where
        F: std::future::Future<Output = Result<T>>,
    {
        match self.timeout {
            Some(dur) => tokio::time::timeout(dur, fut)
                .await
                .map_err(|_| Error::Timeout)?,
            None => fut.await,
        }
    }

    /// Create a connection from its parts.
    ///
    /// This is primarily used internally for protocols that require
    /// async initialization (like WireGuard which needs family ID resolution).
    pub(crate) fn from_parts(socket: NetlinkSocket, state: P) -> Self {
        Self {
            socket,
            state,
            timeout: Some(DEFAULT_OPERATION_TIMEOUT),
            request_lock: std::sync::Arc::new(tokio::sync::Mutex::new(())),
        }
    }

    // ========================================================================
    // Internal request methods (pub(crate) - not part of public API)
    // ========================================================================

    /// Send a request and wait for a response.
    ///
    /// Respects the configured timeout. This is a low-level method.
    /// Prefer using typed methods like `get_links()`, `add_route()`, etc.
    pub(crate) async fn send_request(&self, builder: MessageBuilder) -> Result<Vec<u8>> {
        self.with_timeout(self.send_request_inner(builder)).await
    }

    /// Send a request that expects an ACK only (no data response).
    ///
    /// Respects the configured timeout. This is a low-level method.
    /// Prefer using typed methods like `add_link()`, `del_route()`, etc.
    pub(crate) async fn send_ack(&self, builder: MessageBuilder) -> Result<()> {
        self.with_timeout(self.send_ack_inner(builder)).await
    }

    /// Send a dump request and collect all responses.
    ///
    /// Respects the configured timeout. This is a low-level method.
    /// Prefer using typed methods like `get_links()`, `get_routes()`, etc.
    pub(crate) async fn send_dump(&self, builder: MessageBuilder) -> Result<Vec<Vec<u8>>> {
        self.with_timeout(self.send_dump_inner(builder)).await
    }

    #[instrument(level = "trace", skip_all, fields(seq))]
    async fn send_request_inner(&self, mut builder: MessageBuilder) -> Result<Vec<u8>> {
        // F1 fix — serialize the send + recv-loop pair so concurrent
        // tasks on a shared `Arc<Connection>` don't race on the recv
        // side. See struct-level "Concurrency" docstring.
        let _guard = self.request_lock.lock().await;

        let seq = self.socket.next_seq();
        builder.set_seq(seq);
        builder.set_pid(self.socket.pid());
        tracing::Span::current().record("seq", seq);

        let msg = builder.finish();
        self.socket.send(&msg).await?;

        // Loop until a frame containing a message with the expected
        // seq arrives. Multicast events delivered while subscribed
        // (e.g. when this `Connection` is also `subscribe()`d to a
        // group the request mutates) carry `seq=0` and would
        // otherwise be mistaken for the response. The 30s default
        // operation timeout (`with_timeout` in `send_request`)
        // bounds the loop so a never-ack'd request still surfaces
        // as `Error::Timeout` instead of hanging.
        loop {
            let response = self.socket.recv_msg().await?;
            let mut found_seq = false;
            for result in MessageIter::new(&response) {
                // 0.19 N2 — Plan 193 §2.3 rule 3 extension. When a
                // `Connection<P>` is both subscribed (multicast) and
                // performing requests, the recv loop sees BOTH our
                // unicast reply AND unrelated multicast frames. A
                // malformed multicast frame (corrupted kernel, future
                // protocol extension) used to kill the unrelated
                // request via `?`. Skip parse failures silently so
                // long-lived subscribers + requests on the same
                // socket survive a single malformed frame.
                let Ok((header, payload)) = result else {
                    tracing::trace!(
                        "send_request: skipping malformed frame in shared recv loop"
                    );
                    continue;
                };
                if header.nlmsg_seq != seq {
                    continue;
                }
                found_seq = true;
                if header.is_error() {
                    let err = NlMsgError::from_bytes(payload)?;
                    if !err.is_ack() {
                        warn!(errno = err.error, "kernel returned error for request");
                        return Err(err.into_error(payload));
                    }
                }
            }
            if found_seq {
                return Ok(response);
            }
            // No matching seq in this frame — stale multicast or
            // delayed reply for a previous request. Keep reading.
        }
    }

    #[instrument(level = "trace", skip_all, fields(seq))]
    async fn send_ack_inner(&self, mut builder: MessageBuilder) -> Result<()> {
        // F1 fix — see send_request_inner.
        let _guard = self.request_lock.lock().await;

        let seq = self.socket.next_seq();
        builder.set_seq(seq);
        builder.set_pid(self.socket.pid());
        tracing::Span::current().record("seq", seq);

        let msg = builder.finish();
        self.socket.send(&msg).await?;

        // Same shape as `send_request_inner` — loop until the ACK
        // with the expected seq lands, skipping unrelated multicast
        // frames.
        loop {
            let response = self.socket.recv_msg().await?;
            for result in MessageIter::new(&response) {
                // 0.19 N2 — see send_request_inner.
                let Ok((header, payload)) = result else {
                    tracing::trace!(
                        "send_ack: skipping malformed frame in shared recv loop"
                    );
                    continue;
                };
                if header.nlmsg_seq != seq {
                    continue;
                }
                if header.is_error() {
                    let err = NlMsgError::from_bytes(payload)?;
                    if !err.is_ack() {
                        warn!(errno = err.error, "kernel returned error for ack");
                        return Err(err.into_error(payload));
                    }
                    return Ok(());
                }
                // Matching seq + non-error response on an ack-only
                // operation is unexpected (kernel returned a data
                // message for what nlink considered a SET-style
                // request). Pre-0.19 this fell through and looped to
                // the next recv, blocking until the 30s timeout. Now
                // we surface explicitly so the caller can react
                // (Plan 212 M16).
                return Err(Error::InvalidMessage(format!(
                    "send_ack: expected ACK or error for seq {}, got nlmsg_type {} \
                     (kernel returned data on an ack-only request)",
                    seq, header.nlmsg_type
                )));
            }
        }
    }

    #[instrument(level = "trace", skip_all, fields(seq, responses))]
    async fn send_dump_inner(&self, mut builder: MessageBuilder) -> Result<Vec<Vec<u8>>> {
        // F1 fix — see send_request_inner.
        let _guard = self.request_lock.lock().await;

        let seq = self.socket.next_seq();
        builder.set_seq(seq);
        builder.set_pid(self.socket.pid());
        tracing::Span::current().record("seq", seq);

        let msg = builder.finish();
        self.socket.send(&msg).await?;

        let mut responses = Vec::new();

        // Per-batch frame buffer. When the `syscall_batch` feature
        // is on we collect up to NL_BATCH_SIZE frames per syscall
        // via recvmmsg(2); otherwise we fall back to per-frame
        // recv_msg. The frame-processing loop below is identical
        // either way — it just sees a 1-frame batch vs an N-frame
        // batch.
        #[cfg(feature = "syscall_batch")]
        let mut batch: Vec<Vec<u8>> = Vec::with_capacity(crate::netlink::socket::NL_BATCH_SIZE);

        'outer: loop {
            #[cfg(feature = "syscall_batch")]
            {
                batch.clear();
                self.socket
                    .recv_batch(&mut batch, crate::netlink::socket::NL_BATCH_SIZE)
                    .await?;
            }
            #[cfg(not(feature = "syscall_batch"))]
            let batch = {
                let data = self.socket.recv_msg().await?;
                vec![data]
            };

            for data in batch.iter() {
                // Plan 232 B9 — track msg_start with an explicit
                // counter that advances alongside `MessageIter`
                // instead of the original raw-pointer subtraction.
                // Each MessageIter step consumes `nlmsg_align(msg_len)`
                // bytes; advancing the counter in the same shape
                // keeps it within `data` by construction.
                let mut msg_start: usize = 0;
                for result in MessageIter::new(data) {
                    // 0.19 N2 — see send_request_inner.
                    let Ok((header, payload)) = result else {
                        tracing::trace!(
                            "send_dump: skipping malformed frame in shared recv loop"
                        );
                        break;
                    };

                    let msg_len = header.nlmsg_len as usize;
                    let aligned = nlmsg_align(msg_len);

                    // Check sequence number
                    if header.nlmsg_seq != seq {
                        msg_start = msg_start.saturating_add(aligned);
                        continue;
                    }

                    // Plan 193 follow-up — surface NLM_F_DUMP_INTR.
                    // The kernel sets this when the dump iterator's
                    // underlying data structure was mutated since the
                    // dump started; per kernel docs the userspace
                    // should retry. Pre-0.19 nlink silently used the
                    // inconsistent snapshot. Caller can retry via
                    // `Error::is_dump_interrupted()`.
                    if header.is_dump_interrupted() {
                        return Err(Error::DumpInterrupted);
                    }

                    if header.is_error() {
                        let err = NlMsgError::from_bytes(payload)?;
                        if !err.is_ack() {
                            return Err(err.into_error(payload));
                        }
                    }

                    if header.is_done() {
                        break 'outer;
                    }

                    // Collect the full message (header + payload).
                    if msg_start + msg_len <= data.len() {
                        responses.push(data[msg_start..msg_start + msg_len].to_vec());
                    }
                    msg_start = msg_start.saturating_add(aligned);
                    let _ = payload; // payload still flagged consumed via header check above
                }
            }
        }

        tracing::Span::current().record("responses", responses.len());
        Ok(responses)
    }

}

// ============================================================================
// Route protocol multicast groups
// ============================================================================

/// Multicast groups for Route protocol event notifications.
///
/// Use with [`Connection<Route>::subscribe`] to receive specific event types.
///
/// # Example
///
/// ```ignore
/// use nlink::netlink::{Connection, Route, RtnetlinkGroup};
///
/// let mut conn = Connection::<Route>::new()?;
/// conn.subscribe(&[RtnetlinkGroup::Link, RtnetlinkGroup::Tc])?;
/// let mut events = conn.events();
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum RtnetlinkGroup {
    /// Link (interface) state changes (RTM_NEWLINK, RTM_DELLINK).
    Link,
    /// IPv4 address changes (RTM_NEWADDR, RTM_DELADDR).
    Ipv4Addr,
    /// IPv6 address changes (RTM_NEWADDR, RTM_DELADDR).
    Ipv6Addr,
    /// IPv4 route changes (RTM_NEWROUTE, RTM_DELROUTE).
    Ipv4Route,
    /// IPv6 route changes (RTM_NEWROUTE, RTM_DELROUTE).
    Ipv6Route,
    /// Neighbor (ARP/NDP) cache changes (RTM_NEWNEIGH, RTM_DELNEIGH).
    Neigh,
    /// Traffic control changes (qdiscs, classes, filters, actions).
    Tc,
    /// Namespace ID changes (RTM_NEWNSID, RTM_DELNSID).
    NsId,
    /// IPv4 routing rule changes (RTM_NEWRULE, RTM_DELRULE).
    Ipv4Rule,
    /// IPv6 routing rule changes (RTM_NEWRULE, RTM_DELRULE).
    Ipv6Rule,
}

impl RtnetlinkGroup {
    /// Convert to the raw netlink multicast group number.
    fn to_group(self) -> u32 {
        use super::socket::rtnetlink_groups::*;
        match self {
            Self::Link => RTNLGRP_LINK,
            Self::Ipv4Addr => RTNLGRP_IPV4_IFADDR,
            Self::Ipv6Addr => RTNLGRP_IPV6_IFADDR,
            Self::Ipv4Route => RTNLGRP_IPV4_ROUTE,
            Self::Ipv6Route => RTNLGRP_IPV6_ROUTE,
            Self::Neigh => RTNLGRP_NEIGH,
            Self::Tc => RTNLGRP_TC,
            Self::NsId => RTNLGRP_NSID,
            Self::Ipv4Rule => RTNLGRP_IPV4_RULE,
            Self::Ipv6Rule => RTNLGRP_IPV6_RULE,
        }
    }
}

// ============================================================================
// Route protocol specific methods
// ============================================================================

impl Connection<Route> {
    /// Create a connection for the specified namespace.
    ///
    /// This is a convenience method that creates a Route protocol connection
    /// for any namespace specification.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use nlink::netlink::{Connection, Route};
    /// use nlink::netlink::namespace::NamespaceSpec;
    ///
    /// // For a named namespace
    /// let conn = Connection::<Route>::for_namespace(NamespaceSpec::Named("myns"))?;
    ///
    /// // For a container by PID
    /// let conn = Connection::<Route>::for_namespace(NamespaceSpec::Pid(1234))?;
    ///
    /// // For the default namespace
    /// let conn = Connection::<Route>::for_namespace(NamespaceSpec::Default)?;
    /// ```
    #[instrument(level = "info", skip_all, fields(protocol = "Route"))]
    pub fn for_namespace(spec: super::namespace::NamespaceSpec<'_>) -> Result<Self> {
        spec.connection()
    }

    /// Subscribe to multicast groups for event notifications.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use nlink::netlink::{Connection, Route, RtnetlinkGroup};
    ///
    /// let mut conn = Connection::<Route>::new()?;
    /// conn.subscribe(&[RtnetlinkGroup::Link, RtnetlinkGroup::Tc])?;
    /// ```
    #[instrument(level = "info", skip(self), fields(groups = ?groups))]
    pub fn subscribe(&self, groups: &[RtnetlinkGroup]) -> Result<()> {
        for group in groups {
            self.socket.add_membership(group.to_group())?;
        }
        Ok(())
    }

    /// Subscribe to all commonly-used event groups.
    ///
    /// Subscribes to: Link, Ipv4Addr, Ipv6Addr, Ipv4Route, Ipv6Route, Neigh, Tc.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use nlink::netlink::{Connection, Route};
    ///
    /// let mut conn = Connection::<Route>::new()?;
    /// conn.subscribe_all()?;
    /// let mut events = conn.events();
    /// ```
    #[instrument(level = "info", skip_all)]
    pub fn subscribe_all(&self) -> Result<()> {
        self.subscribe(&[
            RtnetlinkGroup::Link,
            RtnetlinkGroup::Ipv4Addr,
            RtnetlinkGroup::Ipv6Addr,
            RtnetlinkGroup::Ipv4Route,
            RtnetlinkGroup::Ipv6Route,
            RtnetlinkGroup::Neigh,
            RtnetlinkGroup::Tc,
        ])
    }

    // ========================================================================
    // Strongly-typed API for Route protocol
    // ========================================================================

    /// Send a dump request and parse all responses into typed messages.
    ///
    /// This is a convenience method that combines `dump()` with parsing.
    /// The type T must implement `FromNetlink::write_dump_header` to provide
    /// the required message header (e.g., IfInfoMsg for links, IfAddrMsg for addresses).
    ///
    /// # Example
    ///
    /// ```ignore
    /// use nlink::netlink::messages::AddressMessage;
    /// use nlink::netlink::message::NlMsgType;
    ///
    /// let addresses: Vec<AddressMessage> = conn.dump_typed(NlMsgType::RTM_GETADDR).await?;
    /// for addr in addresses {
    ///     println!("{}: {:?}", addr.ifindex(), addr.address);
    /// }
    /// ```
    #[instrument(level = "debug", skip(self), fields(method = "dump_typed", msg_type))]
    pub async fn dump_typed<T: FromNetlink>(&self, msg_type: u16) -> Result<Vec<T>> {
        let mut builder = dump_request(msg_type);

        // Get the header from the type and append it to the request
        let mut header_buf = Vec::new();
        T::write_dump_header(&mut header_buf);
        builder.append_bytes(&header_buf);

        let responses = self.send_dump(builder).await?;

        let mut parsed = Vec::with_capacity(responses.len());
        for response in responses {
            if response.len() < NLMSG_HDRLEN {
                continue;
            }
            let payload = &response[NLMSG_HDRLEN..];
            if let Ok(msg) = T::from_bytes(payload) {
                parsed.push(msg);
            }
        }

        Ok(parsed)
    }

    /// Parse a single response into a typed message.
    pub fn parse_response<T: FromNetlink>(&self, response: &[u8]) -> Result<T> {
        if response.len() < NLMSG_HDRLEN {
            return Err(Error::Truncated {
                expected: NLMSG_HDRLEN,
                actual: response.len(),
            });
        }
        let payload = &response[NLMSG_HDRLEN..];
        T::from_bytes(payload)
    }
}

/// Helper to build a dump request.
pub(crate) fn dump_request(msg_type: u16) -> MessageBuilder {
    MessageBuilder::new(msg_type, NLM_F_REQUEST | NLM_F_DUMP)
}

/// Helper to build a request expecting ACK.
pub(crate) fn ack_request(msg_type: u16) -> MessageBuilder {
    MessageBuilder::new(msg_type, NLM_F_REQUEST | NLM_F_ACK)
}

/// Helper to build a create request.
pub(crate) fn create_request(msg_type: u16) -> MessageBuilder {
    MessageBuilder::new(msg_type, NLM_F_REQUEST | NLM_F_ACK | 0x400) // NLM_F_CREATE
}

/// Helper to build a create-or-replace request.
pub(crate) fn replace_request(msg_type: u16) -> MessageBuilder {
    MessageBuilder::new(msg_type, NLM_F_REQUEST | NLM_F_ACK | 0x400 | 0x100) // NLM_F_CREATE | NLM_F_REPLACE
}

// ============================================================================
// Batch Operations
// ============================================================================

impl Connection<Route> {
    /// Create a batch for executing multiple operations in minimal syscalls.
    ///
    /// Operations are buffered and sent as concatenated messages in a single
    /// `sendmsg()`. The kernel processes them sequentially and returns one
    /// ACK per message.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use nlink::netlink::{Connection, Route};
    /// use nlink::netlink::route::Ipv4Route;
    ///
    /// let conn = Connection::<Route>::new()?;
    /// let results = conn.batch()
    ///     .add_route(Ipv4Route::new("10.0.0.0", 8).dev_index(5))
    ///     .add_route(Ipv4Route::new("10.1.0.0", 16).dev_index(5))
    ///     .execute()
    ///     .await?;
    /// ```
    pub fn batch(&self) -> super::batch::Batch<'_> {
        super::batch::Batch::new(self)
    }
}

// ============================================================================
// Convenience Query Methods
// ============================================================================

use super::messages::{
    AddressMessage, LinkMessage, NeighborMessage, RouteMessage, RuleMessage, TcMessage,
};

impl Connection<Route> {
    /// Get all network interfaces.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let links = conn.get_links().await?;
    /// for link in links {
    ///     println!("{}: {}", link.ifindex(), link.name.as_deref().unwrap_or("?"));
    /// }
    /// ```
    ///
    /// **Scale note**: this eager variant collects the full kernel
    /// response into a `Vec<LinkMessage>` before returning. For
    /// hosts with thousands of interfaces (containers, VM hosts),
    /// prefer [`Self::stream_links`] — same data, O(1) memory.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_links"))]
    pub async fn get_links(&self) -> Result<Vec<LinkMessage>> {
        self.dump_typed(NlMsgType::RTM_GETLINK).await
    }

    /// Stream a link dump frame-by-frame.
    ///
    /// O(1) memory in the number of links, vs `get_links` which
    /// buffers the full response. See [`Self::dump_stream`] for
    /// the full semantics. On hosts with thousands of interfaces
    /// (containers, VM hosts), this is the cliff-fix.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use tokio_stream::StreamExt;
    /// let mut s = conn.stream_links().await?;
    /// while let Some(link) = s.next().await {
    ///     let link = link?;
    ///     // process one link with O(1) memory
    /// }
    /// ```
    #[instrument(level = "debug", skip_all, fields(method = "stream_links"))]
    pub async fn stream_links(
        &self,
    ) -> Result<crate::netlink::dump_stream::DumpStream<'_, Route, LinkMessage>> {
        self.dump_stream::<LinkMessage>(NlMsgType::RTM_GETLINK).await
    }

    /// Stream a route dump frame-by-frame. See [`Self::stream_links`].
    #[instrument(level = "debug", skip_all, fields(method = "stream_routes"))]
    pub async fn stream_routes(
        &self,
    ) -> Result<crate::netlink::dump_stream::DumpStream<'_, Route, RouteMessage>> {
        self.dump_stream::<RouteMessage>(NlMsgType::RTM_GETROUTE)
            .await
    }

    /// Stream a neighbor-table dump frame-by-frame. See
    /// [`Self::stream_links`].
    ///
    /// Note: the kernel returns both unicast neighbors and the
    /// bridge FDB entries together when AF_BRIDGE isn't filtered;
    /// use the typed-config Connection (`stream_fdb` on
    /// `Connection<Route>` when added in 0.17) for FDB-only.
    #[instrument(level = "debug", skip_all, fields(method = "stream_neighbors"))]
    pub async fn stream_neighbors(
        &self,
    ) -> Result<crate::netlink::dump_stream::DumpStream<'_, Route, NeighborMessage>> {
        self.dump_stream::<NeighborMessage>(NlMsgType::RTM_GETNEIGH)
            .await
    }

    /// Stream an address dump frame-by-frame. See [`Self::stream_links`].
    #[instrument(level = "debug", skip_all, fields(method = "stream_addresses"))]
    pub async fn stream_addresses(
        &self,
    ) -> Result<crate::netlink::dump_stream::DumpStream<'_, Route, AddressMessage>> {
        self.dump_stream::<AddressMessage>(NlMsgType::RTM_GETADDR)
            .await
    }

    /// Get a network interface by name.
    ///
    /// Returns `None` if the interface doesn't exist.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_link_by_name"))]
    pub async fn get_link_by_name(
        &self,
        name: impl Into<InterfaceRef>,
    ) -> Result<Option<LinkMessage>> {
        let iface = name.into();
        match iface {
            InterfaceRef::Name(ref name_str) => {
                let links = self.get_links().await?;
                Ok(links
                    .into_iter()
                    .find(|l| l.name.as_deref() == Some(name_str)))
            }
            InterfaceRef::Index(idx) => self.get_link_by_index(idx).await,
        }
    }

    /// Get a network interface by index.
    ///
    /// Returns `None` if the interface doesn't exist.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_link_by_index"))]
    pub async fn get_link_by_index(&self, index: u32) -> Result<Option<LinkMessage>> {
        let links = self.get_links().await?;
        Ok(links.into_iter().find(|l| l.ifindex() == index))
    }

    /// Wait for an interface to reach the `IFF_UP` state.
    ///
    /// Polls the interface state with exponential backoff (starting
    /// at 10ms, capped at 100ms) until `IFF_UP` is observed or
    /// `timeout` elapses. The polling form is preferred over a
    /// subscription-based wait because it keeps lifetime concerns
    /// trivial — no multicast socket to manage, no event-stream
    /// drop semantics to document.
    ///
    /// Returns `Err(Timeout)` on deadline. Returns
    /// `Err(InterfaceNotFound)` if the interface is removed during
    /// the wait.
    ///
    /// # Namespace safety
    ///
    /// Takes `impl Into<InterfaceRef>`. With a `Name` variant the
    /// lookup goes via netlink (`get_link_by_name`), which queries
    /// the connection's netns — namespace-correct even from a
    /// process running in a different mount namespace.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use std::time::Duration;
    /// use nlink::{Connection, Route};
    ///
    /// let conn = Connection::<Route>::new()?;
    /// // Bring up the interface, then wait for the operstate to
    /// // reflect it (kernel may take milliseconds).
    /// conn.set_link_up_by_name("eth0").await?;
    /// conn.wait_link_up("eth0", Duration::from_secs(5)).await?;
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "wait_link_up"))]
    pub async fn wait_link_up(
        &self,
        iface: impl Into<InterfaceRef>,
        timeout: Duration,
    ) -> Result<()> {
        let iface = iface.into();
        let label = match &iface {
            InterfaceRef::Name(n) => n.clone(),
            InterfaceRef::Index(i) => i.to_string(),
        };
        let deadline = std::time::Instant::now() + timeout;
        let mut backoff = Duration::from_millis(10);
        // Resolve once to ifindex so subsequent polls are
        // namespace-correct + cheaper.
        let ifindex = self.resolve_interface(&iface).await?;

        loop {
            let link = self
                .get_link_by_index(ifindex)
                .await?
                .ok_or_else(|| Error::InterfaceNotFound {
                    name: label.clone(),
                })?;
            if link.is_up() {
                return Ok(());
            }
            if std::time::Instant::now() >= deadline {
                return Err(Error::Timeout);
            }
            tokio::time::sleep(backoff).await;
            backoff = (backoff * 2).min(Duration::from_millis(100));
        }
    }

    /// Get the kernel-reported per-link statistics for the named or
    /// indexed interface.
    ///
    /// Convenience wrapper around `get_link_by_*` + `LinkMessage::stats()`.
    /// Returns `Err(InterfaceNotFound)` if no interface matches, and
    /// `Err(InvalidMessage)` if the kernel response didn't include a
    /// stats attribute (rare — most interfaces always report stats).
    ///
    /// # Namespace safety
    ///
    /// Takes `impl Into<InterfaceRef>`. With a `Name` variant, the
    /// initial lookup reads from the namespace this connection is
    /// bound to (via netlink, not `/sys/class/net/`) — so name
    /// resolution is namespace-correct.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use nlink::{Connection, Route};
    ///
    /// let conn = Connection::<Route>::new()?;
    /// let stats = conn.get_link_stats("eth0").await?;
    /// println!("rx: {} bytes / {} packets", stats.rx_bytes, stats.rx_packets);
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_link_stats"))]
    pub async fn get_link_stats(
        &self,
        iface: impl Into<InterfaceRef>,
    ) -> Result<crate::netlink::messages::LinkStats> {
        let iface = iface.into();
        let label = match &iface {
            InterfaceRef::Name(n) => n.clone(),
            InterfaceRef::Index(i) => i.to_string(),
        };
        let link = self
            .get_link_by_name(iface)
            .await?
            .ok_or_else(|| Error::InterfaceNotFound { name: label.clone() })?;
        link.stats().copied().ok_or_else(|| {
            Error::InvalidMessage(format!(
                "interface {label} response did not include link-stats attribute"
            ))
        })
    }

    /// Resolve an interface reference to an index.
    ///
    /// This method is namespace-safe: it uses netlink to resolve interface names,
    /// which queries the namespace that this connection is bound to.
    ///
    /// - If the reference is already an index, returns it directly.
    /// - If the reference is a name, queries the kernel via netlink.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InterfaceNotFound`] if the interface name doesn't exist.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use nlink::netlink::{Connection, Route, InterfaceRef};
    ///
    /// let conn = Connection::<Route>::new()?;
    ///
    /// // Resolve a name
    /// let ifindex = conn.resolve_interface(&InterfaceRef::name("eth0")).await?;
    ///
    /// // Pass-through an index
    /// let ifindex = conn.resolve_interface(&InterfaceRef::index(2)).await?;
    /// assert_eq!(ifindex, 2);
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "resolve_interface"))]
    pub async fn resolve_interface(&self, iface: &InterfaceRef) -> Result<u32> {
        match iface {
            InterfaceRef::Index(idx) => Ok(*idx),
            InterfaceRef::Name(name) => {
                let link = self
                    .get_link_by_name(name)
                    .await?
                    .ok_or_else(|| Error::interface_not_found(name))?;
                Ok(link.ifindex())
            }
        }
    }

    /// Resolve an optional interface reference.
    ///
    /// Returns `None` if the input is `None`, otherwise resolves the reference.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "resolve_interface_opt"))]
    pub async fn resolve_interface_opt(&self, iface: Option<&InterfaceRef>) -> Result<Option<u32>> {
        match iface {
            Some(iface) => Ok(Some(self.resolve_interface(iface).await?)),
            None => Ok(None),
        }
    }

    /// Build a map of interface index to name.
    ///
    /// This is a convenience method for code that needs to look up interface
    /// names by index (e.g., when displaying addresses, routes, or TC objects).
    ///
    /// # Example
    ///
    /// ```ignore
    /// let names = conn.get_interface_names().await?;
    /// let addresses = conn.get_addresses().await?;
    /// for addr in addresses {
    ///     let name = names.get(&addr.ifindex()).map(|s| s.as_str()).unwrap_or("?");
    ///     println!("{}: {:?}", name, addr.address);
    /// }
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_interface_names"))]
    pub async fn get_interface_names(&self) -> Result<std::collections::HashMap<u32, String>> {
        let links = self.get_links().await?;
        Ok(links
            .into_iter()
            .filter_map(|l| l.name.clone().map(|n| (l.ifindex(), n)))
            .collect())
    }

    /// Get interface name by index.
    ///
    /// This is a convenience method for getting a single interface name.
    /// For looking up multiple names, prefer [`Connection::get_interface_names()`]
    /// to build a lookup map.
    ///
    /// Returns `None` if no interface with that index exists.
    ///
    /// # Example
    ///
    /// ```ignore
    /// if let Some(name) = conn.interface_name(route.oif.unwrap()).await? {
    ///     println!("Route via {}", name);
    /// }
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "interface_name"))]
    pub async fn interface_name(&self, ifindex: u32) -> Result<Option<String>> {
        let link = self.get_link_by_index(ifindex).await?;
        Ok(link.and_then(|l| l.name))
    }

    /// Get interface name by index, or return a default value.
    ///
    /// This is a convenience method for display purposes when you want
    /// a fallback value like "-" or "?" for unknown interfaces.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let dev = conn.interface_name_or(route.oif.unwrap_or(0), "-").await?;
    /// println!("Route via {}", dev);
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "interface_name_or"))]
    pub async fn interface_name_or(&self, ifindex: u32, default: &str) -> Result<String> {
        Ok(self
            .interface_name(ifindex)
            .await?
            .unwrap_or_else(|| default.to_string()))
    }

    /// Get bond information for a bond interface.
    ///
    /// Returns the bond configuration as reported by the kernel.
    ///
    /// # Errors
    ///
    /// Returns an error if the interface doesn't exist or is not a bond.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let info = conn.get_bond_info("bond0").await?;
    /// println!("Mode: {:?}, miimon: {}ms", info.bond_mode(), info.miimon);
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_bond_info"))]
    pub async fn get_bond_info(
        &self,
        iface: impl Into<InterfaceRef>,
    ) -> Result<crate::netlink::messages::BondInfo> {
        let ifindex = self.resolve_interface(&iface.into()).await?;
        let link = self
            .get_link_by_index(ifindex)
            .await?
            .ok_or_else(|| Error::InvalidMessage("interface not found".into()))?;
        link.bond_info()
            .ok_or_else(|| Error::InvalidMessage("not a bond interface".into()))
    }

    /// List all slaves of a bond interface with their status.
    ///
    /// Returns a list of `(LinkMessage, BondSlaveInfo)` pairs for each slave.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let slaves = conn.get_bond_slaves("bond0").await?;
    /// for (link, info) in &slaves {
    ///     println!("{}: state={:?}, mii={:?}",
    ///         link.name_or("?"), info.state, info.mii_status);
    /// }
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_bond_slaves"))]
    pub async fn get_bond_slaves(
        &self,
        bond: impl Into<InterfaceRef>,
    ) -> Result<Vec<(LinkMessage, crate::netlink::messages::BondSlaveInfo)>> {
        let bond_ifindex = self.resolve_interface(&bond.into()).await?;
        let all_links = self.get_links().await?;
        let mut slaves = Vec::new();

        for link in all_links {
            if link.master() == Some(bond_ifindex)
                && let Some(info) = link.bond_slave_info()
            {
                slaves.push((link, info));
            }
        }

        Ok(slaves)
    }

    /// Get all IP addresses.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let addresses = conn.get_addresses().await?;
    /// for addr in addresses {
    ///     println!("{:?}/{} on idx {}", addr.address, addr.prefix_len(), addr.ifindex());
    /// }
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_addresses"))]
    pub async fn get_addresses(&self) -> Result<Vec<AddressMessage>> {
        self.dump_typed(NlMsgType::RTM_GETADDR).await
    }

    /// Get IP addresses for a specific interface.
    ///
    /// Accepts either an interface name or index via [`InterfaceRef`].
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_addresses_by_name"))]
    pub async fn get_addresses_by_name(
        &self,
        iface: impl Into<InterfaceRef>,
    ) -> Result<Vec<AddressMessage>> {
        let ifindex = self.resolve_interface(&iface.into()).await?;
        self.get_addresses_by_index(ifindex).await
    }

    /// Get IP addresses for a specific interface by index.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_addresses_by_index"))]
    pub async fn get_addresses_by_index(&self, ifindex: u32) -> Result<Vec<AddressMessage>> {
        let addresses = self.get_addresses().await?;
        Ok(addresses
            .into_iter()
            .filter(|a| a.ifindex() == ifindex)
            .collect())
    }

    /// Get an address entry by IP address.
    ///
    /// Returns `None` if no address entry matches the given IP.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use std::net::IpAddr;
    ///
    /// let ip: IpAddr = "192.168.1.100".parse()?;
    /// if let Some(addr) = conn.get_address_by_ip(ip).await? {
    ///     println!("Found on interface index {}", addr.ifindex());
    /// }
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_address_by_ip"))]
    pub async fn get_address_by_ip(
        &self,
        addr: std::net::IpAddr,
    ) -> Result<Option<AddressMessage>> {
        let addresses = self.get_addresses().await?;
        Ok(addresses.into_iter().find(|a| a.address == Some(addr)))
    }

    /// Get all routes.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let routes = conn.get_routes().await?;
    /// for route in routes {
    ///     println!("{:?}/{}", route.destination(), route.dst_len());
    /// }
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_routes"))]
    pub async fn get_routes(&self) -> Result<Vec<RouteMessage>> {
        self.dump_typed(NlMsgType::RTM_GETROUTE).await
    }

    /// Get routes for a specific table.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_routes_for_table"))]
    pub async fn get_routes_for_table(&self, table_id: u32) -> Result<Vec<RouteMessage>> {
        let routes = self.get_routes().await?;
        Ok(routes
            .into_iter()
            .filter(|r| r.table_id() == table_id)
            .collect())
    }

    /// Get a specific IPv4 route by destination and prefix length.
    ///
    /// Uses RTM_GETROUTE without NLM_F_DUMP to query the kernel directly,
    /// which is more efficient than dumping all routes for large routing tables.
    ///
    /// Returns `None` if no matching route is found.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use std::net::Ipv4Addr;
    ///
    /// // Look up route to 10.0.0.0/8
    /// if let Some(route) = conn.get_route_v4(Ipv4Addr::new(10, 0, 0, 0), 8).await? {
    ///     println!("Gateway: {:?}", route.gateway);
    /// }
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_route_v4"))]
    pub async fn get_route_v4(
        &self,
        destination: std::net::Ipv4Addr,
        prefix_len: u8,
    ) -> Result<Option<RouteMessage>> {
        use crate::netlink::types::route::{RtMsg, RtaAttr};

        // Build RTM_GETROUTE request WITHOUT NLM_F_DUMP
        let mut builder = MessageBuilder::new(NlMsgType::RTM_GETROUTE, NLM_F_REQUEST);

        let rtmsg = RtMsg::new()
            .with_family(libc::AF_INET as u8)
            .with_dst_len(prefix_len);
        builder.append(&rtmsg);
        builder.append_attr(RtaAttr::Dst as u16, &destination.octets());

        // Send single request (not dump)
        match self.send_request(builder).await {
            Ok(response) => {
                // Parse the response - skip netlink header
                if response.len() >= NLMSG_HDRLEN {
                    let payload = &response[NLMSG_HDRLEN..];
                    if let Ok(msg) = RouteMessage::from_bytes(payload) {
                        return Ok(Some(msg));
                    }
                }
                Ok(None)
            }
            Err(e) if e.is_not_found() => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Get a specific IPv6 route by destination and prefix length.
    ///
    /// Uses RTM_GETROUTE without NLM_F_DUMP to query the kernel directly,
    /// which is more efficient than dumping all routes for large routing tables.
    ///
    /// Returns `None` if no matching route is found.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use std::net::Ipv6Addr;
    ///
    /// // Look up route to 2001:db8::/32
    /// let dest: Ipv6Addr = "2001:db8::".parse()?;
    /// if let Some(route) = conn.get_route_v6(dest, 32).await? {
    ///     println!("Gateway: {:?}", route.gateway);
    /// }
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_route_v6"))]
    pub async fn get_route_v6(
        &self,
        destination: std::net::Ipv6Addr,
        prefix_len: u8,
    ) -> Result<Option<RouteMessage>> {
        use crate::netlink::types::route::{RtMsg, RtaAttr};

        let mut builder = MessageBuilder::new(NlMsgType::RTM_GETROUTE, NLM_F_REQUEST);

        let rtmsg = RtMsg::new()
            .with_family(libc::AF_INET6 as u8)
            .with_dst_len(prefix_len);
        builder.append(&rtmsg);
        builder.append_attr(RtaAttr::Dst as u16, &destination.octets());

        match self.send_request(builder).await {
            Ok(response) => {
                if response.len() >= NLMSG_HDRLEN {
                    let payload = &response[NLMSG_HDRLEN..];
                    if let Ok(msg) = RouteMessage::from_bytes(payload) {
                        return Ok(Some(msg));
                    }
                }
                Ok(None)
            }
            Err(e) if e.is_not_found() => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Get all neighbor entries.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let neighbors = conn.get_neighbors().await?;
    /// for neigh in neighbors {
    ///     println!("{:?} -> {:?}", neigh.destination, neigh.lladdr);
    /// }
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_neighbors"))]
    pub async fn get_neighbors(&self) -> Result<Vec<NeighborMessage>> {
        self.dump_typed(NlMsgType::RTM_GETNEIGH).await
    }

    /// Get neighbor entries for a specific interface.
    ///
    /// Accepts either an interface name or index via [`InterfaceRef`].
    ///
    /// See also [`get_neighbors_by_index`](Self::get_neighbors_by_index) in the neighbor module.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_neighbors_by_name"))]
    pub async fn get_neighbors_by_name(
        &self,
        iface: impl Into<InterfaceRef>,
    ) -> Result<Vec<NeighborMessage>> {
        let ifindex = self.resolve_interface(&iface.into()).await?;
        self.get_neighbors_by_index(ifindex).await
    }

    /// Get all routing rules.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let rules = conn.get_rules().await?;
    /// for rule in rules {
    ///     println!("{}: {:?} -> table {}", rule.priority, rule.source, rule.table);
    /// }
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_rules"))]
    pub async fn get_rules(&self) -> Result<Vec<RuleMessage>> {
        self.dump_typed(NlMsgType::RTM_GETRULE).await
    }

    /// Get routing rules for a specific address family.
    ///
    /// # Arguments
    ///
    /// * `family` - Address family: `libc::AF_INET` for IPv4, `libc::AF_INET6` for IPv6
    ///
    /// **Deprecated** in 0.20.1: pass [`AddressFamily`] to
    /// [`Self::get_rules_for_family_typed`]. The raw-`u8` form silently
    /// returns an empty `Vec` for unmodelled family bytes; the typed form
    /// surfaces the same call as a type-checked constructor (`AddressFamily::v4()`).
    #[deprecated(
        since = "0.20.1",
        note = "use get_rules_for_family_typed(AddressFamily::v4()) — \
                raw u8 silently returns empty for unknown families"
    )]
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_rules_for_family"))]
    pub async fn get_rules_for_family(&self, family: u8) -> Result<Vec<RuleMessage>> {
        let rules = self.get_rules().await?;
        Ok(rules.into_iter().filter(|r| r.family() == family).collect())
    }

    /// Get routing rules for a specific address family, typed.
    ///
    /// Pass `AddressFamily::unspec()` to dump every family.
    ///
    /// This is the typed sibling of the deprecated [`Self::get_rules_for_family`].
    /// Internally delegates through the same dump path; the typed signature
    /// just constrains the input boundary.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_rules_for_family_typed"))]
    pub async fn get_rules_for_family_typed(
        &self,
        family: AddressFamily,
    ) -> Result<Vec<RuleMessage>> {
        let raw = family.as_u8();
        let rules = self.get_rules().await?;
        // AF_UNSPEC (0) is the "no filter" form: return everything.
        if raw == 0 {
            return Ok(rules);
        }
        Ok(rules.into_iter().filter(|r| r.family() == raw).collect())
    }

    /// Get IPv4 routing rules.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_rules_v4"))]
    pub async fn get_rules_v4(&self) -> Result<Vec<RuleMessage>> {
        self.get_rules_for_family_typed(AddressFamily::v4()).await
    }

    /// Get IPv6 routing rules.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_rules_v6"))]
    pub async fn get_rules_v6(&self) -> Result<Vec<RuleMessage>> {
        self.get_rules_for_family_typed(AddressFamily::v6()).await
    }

    /// Add a routing rule.
    ///
    /// Use the [`super::rule::RuleBuilder`] to construct the rule.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use nlink::netlink::rule::RuleBuilder;
    ///
    /// // Add a rule to lookup table 100 for traffic from 10.0.0.0/8
    /// conn.add_rule(
    ///     RuleBuilder::v4()
    ///         .priority(100)
    ///         .from("10.0.0.0", 8)
    ///         .table(100)
    /// ).await?;
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "add_rule"))]
    pub async fn add_rule(&self, rule: super::rule::RuleBuilder) -> Result<()> {
        let builder = rule.build()?;
        self.send_ack(builder)
            .await
            .map_err(|e| e.with_context("add_rule"))
    }

    /// Delete a routing rule.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use nlink::netlink::rule::RuleBuilder;
    ///
    /// conn.del_rule(
    ///     RuleBuilder::v4()
    ///         .priority(100)
    /// ).await?;
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "del_rule"))]
    pub async fn del_rule(&self, rule: super::rule::RuleBuilder) -> Result<()> {
        let builder = rule.build_delete()?;
        self.send_ack(builder)
            .await
            .map_err(|e| e.with_context("del_rule"))
    }

    /// Delete a rule by priority.
    ///
    /// **Deprecated** in 0.20.1: use [`Self::del_rule_by_priority_typed`]
    /// with [`AddressFamily`].
    #[deprecated(
        since = "0.20.1",
        note = "use del_rule_by_priority_typed(AddressFamily::v4(), priority) instead"
    )]
    #[tracing::instrument(level = "debug", skip_all, fields(method = "del_rule_by_priority"))]
    pub async fn del_rule_by_priority(&self, family: u8, priority: u32) -> Result<()> {
        let rule = super::rule::RuleBuilder::new(family).priority(priority);
        self.del_rule(rule).await
    }

    /// Delete a rule by priority, typed.
    ///
    /// Typed sibling of the deprecated [`Self::del_rule_by_priority`].
    /// Internally converts [`AddressFamily`] to the raw `AF_*` byte and
    /// delegates to the same `RuleBuilder` path — behaviour is identical
    /// for the modelled families; the typed boundary is the safety net.
    #[tracing::instrument(
        level = "debug",
        skip_all,
        fields(method = "del_rule_by_priority_typed")
    )]
    pub async fn del_rule_by_priority_typed(
        &self,
        family: AddressFamily,
        priority: u32,
    ) -> Result<()> {
        let rule = super::rule::RuleBuilder::new(family.as_u8()).priority(priority);
        self.del_rule(rule).await
    }

    /// Flush all non-default routing rules for a family.
    ///
    /// This deletes all rules except the default ones (priority 0, 32766, 32767).
    ///
    /// **Deprecated** in 0.20.1: use [`Self::flush_rules_typed`] with
    /// [`AddressFamily`]. The raw-`u8` form silently no-ops for unknown
    /// family bytes (the per-family filter yields zero matches).
    #[deprecated(
        since = "0.20.1",
        note = "use flush_rules_typed(AddressFamily::v4()) instead — \
                raw u8 silently no-ops for unknown families"
    )]
    #[tracing::instrument(level = "debug", skip_all, fields(method = "flush_rules"))]
    pub async fn flush_rules(&self, family: u8) -> Result<()> {
        #[allow(deprecated)]
        let rules = self.get_rules_for_family(family).await?;

        for rule in rules {
            // Skip default rules
            if rule.priority == 0 || rule.priority == 32766 || rule.priority == 32767 {
                continue;
            }

            // Delete by priority
            #[allow(deprecated)]
            let _ = self.del_rule_by_priority(family, rule.priority).await;
        }

        Ok(())
    }

    /// Flush all non-default routing rules for a family, typed.
    ///
    /// Typed sibling of the deprecated [`Self::flush_rules`]. Internally
    /// delegates through the typed dump + delete path; behaviour matches
    /// for modelled families.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "flush_rules_typed"))]
    pub async fn flush_rules_typed(&self, family: AddressFamily) -> Result<()> {
        let rules = self.get_rules_for_family_typed(family).await?;

        for rule in rules {
            // Skip default rules
            if rule.priority == 0 || rule.priority == 32766 || rule.priority == 32767 {
                continue;
            }
            let _ = self
                .del_rule_by_priority_typed(family, rule.priority)
                .await;
        }

        Ok(())
    }

    /// Get all qdiscs.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let qdiscs = conn.get_qdiscs().await?;
    /// for qdisc in qdiscs {
    ///     println!("{}: {}", qdisc.ifindex(), qdisc.kind().unwrap_or("?"));
    /// }
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_qdiscs"))]
    pub async fn get_qdiscs(&self) -> Result<Vec<TcMessage>> {
        self.dump_typed(NlMsgType::RTM_GETQDISC).await
    }

    /// Get qdiscs for a specific interface.
    ///
    /// Accepts either an interface name or index via [`InterfaceRef`].
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_qdiscs_by_name"))]
    pub async fn get_qdiscs_by_name(
        &self,
        iface: impl Into<InterfaceRef>,
    ) -> Result<Vec<TcMessage>> {
        let ifindex = self.resolve_interface(&iface.into()).await?;
        self.get_qdiscs_by_index(ifindex).await
    }

    /// Get qdiscs for a specific interface by index.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_qdiscs_by_index"))]
    pub async fn get_qdiscs_by_index(&self, ifindex: u32) -> Result<Vec<TcMessage>> {
        let qdiscs = self.get_qdiscs().await?;
        Ok(qdiscs
            .into_iter()
            .filter(|q| q.ifindex() == ifindex)
            .collect())
    }

    /// Get all TC classes.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_classes"))]
    pub async fn get_classes(&self) -> Result<Vec<TcMessage>> {
        self.dump_typed(NlMsgType::RTM_GETTCLASS).await
    }

    /// Get TC classes for a specific interface.
    ///
    /// Accepts either an interface name or index via [`InterfaceRef`].
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_classes_by_name"))]
    pub async fn get_classes_by_name(
        &self,
        iface: impl Into<InterfaceRef>,
    ) -> Result<Vec<TcMessage>> {
        let ifindex = self.resolve_interface(&iface.into()).await?;
        self.get_classes_by_index(ifindex).await
    }

    /// Get TC classes for a specific interface by index.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_classes_by_index"))]
    pub async fn get_classes_by_index(&self, ifindex: u32) -> Result<Vec<TcMessage>> {
        let classes = self.get_classes().await?;
        Ok(classes
            .into_iter()
            .filter(|c| c.ifindex() == ifindex)
            .collect())
    }

    /// Get all TC filters.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_filters"))]
    pub async fn get_filters(&self) -> Result<Vec<TcMessage>> {
        self.dump_typed(NlMsgType::RTM_GETTFILTER).await
    }

    /// Get TC filters for a specific interface.
    ///
    /// Accepts either an interface name or index via [`InterfaceRef`].
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_filters_by_name"))]
    pub async fn get_filters_by_name(
        &self,
        iface: impl Into<InterfaceRef>,
    ) -> Result<Vec<TcMessage>> {
        let ifindex = self.resolve_interface(&iface.into()).await?;
        self.get_filters_by_index(ifindex).await
    }

    /// Get TC filters for a specific interface by index.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_filters_by_index"))]
    pub async fn get_filters_by_index(&self, ifindex: u32) -> Result<Vec<TcMessage>> {
        let filters = self.get_filters().await?;
        Ok(filters
            .into_iter()
            .filter(|f| f.ifindex() == ifindex)
            .collect())
    }

    /// Stream a qdisc dump frame-by-frame.
    ///
    /// O(1) memory in the number of qdiscs, vs `get_qdiscs` which
    /// buffers the full response. See [`Self::stream_links`] for
    /// the full semantics. Right answer on hosts with many TC-heavy
    /// interfaces (BGP peers per-route TC, telecom DPDK fanout,
    /// per-pod CNI plugins).
    ///
    /// # Example
    ///
    /// ```ignore
    /// use tokio_stream::StreamExt;
    /// let mut s = conn.stream_qdiscs().await?;
    /// while let Some(q) = s.next().await {
    ///     let q = q?;
    ///     // process one qdisc with O(1) memory
    /// }
    /// ```
    #[instrument(level = "debug", skip_all, fields(method = "stream_qdiscs"))]
    pub async fn stream_qdiscs(
        &self,
    ) -> Result<crate::netlink::dump_stream::DumpStream<'_, Route, TcMessage>> {
        self.dump_stream::<TcMessage>(NlMsgType::RTM_GETQDISC).await
    }

    /// Stream a TC class dump frame-by-frame. See
    /// [`Self::stream_qdiscs`].
    #[instrument(level = "debug", skip_all, fields(method = "stream_classes"))]
    pub async fn stream_classes(
        &self,
    ) -> Result<crate::netlink::dump_stream::DumpStream<'_, Route, TcMessage>> {
        self.dump_stream::<TcMessage>(NlMsgType::RTM_GETTCLASS)
            .await
    }

    /// Stream a TC filter dump frame-by-frame. See
    /// [`Self::stream_qdiscs`].
    ///
    /// Note: the kernel returns filters for **all** interfaces
    /// (matches the eager `get_filters` semantics). Filter
    /// client-side via `.filter(|f| f.as_ref().map(|f|
    /// f.ifindex() == my_index).unwrap_or(true))` if you only
    /// care about one interface — there's no kernel-side
    /// per-ifindex `RTM_GETTFILTER` dump filter.
    #[instrument(level = "debug", skip_all, fields(method = "stream_filters"))]
    pub async fn stream_filters(
        &self,
    ) -> Result<crate::netlink::dump_stream::DumpStream<'_, Route, TcMessage>> {
        self.dump_stream::<TcMessage>(NlMsgType::RTM_GETTFILTER)
            .await
    }

    /// Get TC filters for a specific interface, filtered by parent handle.
    ///
    /// Equivalent to `get_filters_by_name(...).await?` followed by a
    /// client-side `.filter(|f| f.parent() == parsed_parent)`. Useful for
    /// reconcile-style consumers that need targeted teardown without
    /// scanning every filter on the interface.
    ///
    /// `parent` accepts the standard `tc` handle syntax: `"1:"`, `"1:5"`,
    /// `"root"`, `"ingress"`, `"clsact"`. Returns `Error::InvalidMessage`
    /// for unparseable handles.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_filters_by_parent"))]
    pub async fn get_filters_by_parent(
        &self,
        iface: impl Into<InterfaceRef>,
        parent: TcHandle,
    ) -> Result<Vec<TcMessage>> {
        let ifindex = self.resolve_interface(&iface.into()).await?;
        self.get_filters_by_parent_index(ifindex, parent).await
    }

    /// Get TC filters by interface index, filtered by parent handle.
    ///
    /// Namespace-safe variant of [`Connection::get_filters_by_parent`].
    #[tracing::instrument(
        level = "debug",
        skip_all,
        fields(method = "get_filters_by_parent_index")
    )]
    pub async fn get_filters_by_parent_index(
        &self,
        ifindex: u32,
        parent: TcHandle,
    ) -> Result<Vec<TcMessage>> {
        let filters = self.get_filters_by_index(ifindex).await?;
        Ok(filters
            .into_iter()
            .filter(|f| f.parent() == parent)
            .collect())
    }

    /// Get all TC filter chains for an interface.
    ///
    /// Filter chains provide logical grouping of filters for better
    /// performance and organization (Linux 4.1+).
    ///
    /// # Example
    ///
    /// ```ignore
    /// let chains = conn.get_tc_chains("eth0", "ingress").await?;
    /// for chain in chains {
    ///     println!("Chain: {}", chain);
    /// }
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_tc_chains"))]
    pub async fn get_tc_chains(
        &self,
        ifname: impl Into<InterfaceRef>,
        parent: TcHandle,
    ) -> Result<Vec<u32>> {
        let ifindex = self.resolve_interface(&ifname.into()).await?;
        self.get_tc_chains_by_index(ifindex, parent).await
    }

    /// Get all TC filter chains for an interface by index.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_tc_chains_by_index"))]
    pub async fn get_tc_chains_by_index(&self, ifindex: u32, parent: TcHandle) -> Result<Vec<u32>> {
        use super::types::tc::TcMsg;

        let tcmsg = TcMsg::new()
            .with_ifindex(ifindex as i32)
            .with_parent(parent.as_raw());

        let mut builder = dump_request(NlMsgType::RTM_GETCHAIN);
        builder.append(&tcmsg);

        let responses = self.send_dump(builder).await?;
        let mut chains = Vec::new();

        for response in responses {
            if response.len() < NLMSG_HDRLEN {
                continue;
            }
            let payload = &response[NLMSG_HDRLEN..];
            if let Ok(tc) = TcMessage::from_bytes(payload)
                && let Some(chain) = tc.chain()
            {
                chains.push(chain);
            }
        }

        Ok(chains)
    }

    /// Add a TC filter chain.
    ///
    /// Chains provide logical grouping of filters (Linux 4.1+).
    /// Chain 0 is created automatically when adding filters.
    ///
    /// # Example
    ///
    /// ```ignore
    /// // Create chain 100 on ingress qdisc
    /// conn.add_tc_chain("eth0", "ingress", 100).await?;
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "add_tc_chain"))]
    pub async fn add_tc_chain(
        &self,
        ifname: impl Into<InterfaceRef>,
        parent: TcHandle,
        chain: u32,
    ) -> Result<()> {
        let ifindex = self.resolve_interface(&ifname.into()).await?;
        self.add_tc_chain_by_index(ifindex, parent, chain).await
    }

    /// Add a TC filter chain by interface index.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "add_tc_chain_by_index"))]
    pub async fn add_tc_chain_by_index(
        &self,
        ifindex: u32,
        parent: TcHandle,
        chain: u32,
    ) -> Result<()> {
        use super::types::tc::{TcMsg, TcaAttr};

        let tcmsg = TcMsg::new()
            .with_ifindex(ifindex as i32)
            .with_parent(parent.as_raw());

        let mut builder = create_request(NlMsgType::RTM_NEWCHAIN);
        builder.append(&tcmsg);
        builder.append_attr_u32(TcaAttr::Chain as u16, chain);

        self.send_ack(builder)
            .await
            .map_err(|e| e.with_context("add_tc_chain"))
    }

    /// Delete a TC filter chain.
    ///
    /// All filters in the chain must be deleted before the chain can be removed.
    ///
    /// # Example
    ///
    /// ```ignore
    /// conn.del_tc_chain("eth0", "ingress", 100).await?;
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "del_tc_chain"))]
    pub async fn del_tc_chain(
        &self,
        ifname: impl Into<InterfaceRef>,
        parent: TcHandle,
        chain: u32,
    ) -> Result<()> {
        let ifindex = self.resolve_interface(&ifname.into()).await?;
        self.del_tc_chain_by_index(ifindex, parent, chain).await
    }

    /// Delete a TC filter chain by interface index.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "del_tc_chain_by_index"))]
    pub async fn del_tc_chain_by_index(
        &self,
        ifindex: u32,
        parent: TcHandle,
        chain: u32,
    ) -> Result<()> {
        use super::types::tc::{TcMsg, TcaAttr};

        let tcmsg = TcMsg::new()
            .with_ifindex(ifindex as i32)
            .with_parent(parent.as_raw());

        let mut builder = create_request(NlMsgType::RTM_DELCHAIN);
        builder.append(&tcmsg);
        builder.append_attr_u32(TcaAttr::Chain as u16, chain);

        self.send_ack(builder)
            .await
            .map_err(|e| e.with_context("del_tc_chain"))
    }

    /// Get the root qdisc for an interface (parent == ROOT).
    ///
    /// Returns `None` if no root qdisc is configured.
    ///
    /// Accepts either an interface name or index via [`InterfaceRef`].
    ///
    /// # Example
    ///
    /// ```ignore
    /// if let Some(root) = conn.get_root_qdisc_by_name("eth0").await? {
    ///     println!("Root qdisc: {}", root.kind().unwrap_or("?"));
    /// }
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_root_qdisc_by_name"))]
    pub async fn get_root_qdisc_by_name(
        &self,
        iface: impl Into<InterfaceRef>,
    ) -> Result<Option<TcMessage>> {
        let ifindex = self.resolve_interface(&iface.into()).await?;
        self.get_root_qdisc_by_index(ifindex).await
    }

    /// Get the root qdisc for an interface by index.
    ///
    /// Returns `None` if no root qdisc is configured.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_root_qdisc_by_index"))]
    pub async fn get_root_qdisc_by_index(&self, ifindex: u32) -> Result<Option<TcMessage>> {
        let qdiscs = self.get_qdiscs().await?;
        Ok(qdiscs
            .into_iter()
            .find(|q| q.ifindex() == ifindex && q.is_root()))
    }

    /// Get a qdisc by interface name and handle.
    ///
    /// # Example
    ///
    /// ```ignore
    /// // Get the qdisc with handle 1:0 on eth0
    /// if let Some(qdisc) = conn.get_qdisc_by_handle("eth0", "1:").await? {
    ///     println!("Found qdisc: {}", qdisc.kind().unwrap_or("?"));
    /// }
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_qdisc_by_handle"))]
    pub async fn get_qdisc_by_handle(
        &self,
        ifname: &str,
        handle: TcHandle,
    ) -> Result<Option<TcMessage>> {
        let ifindex = self
            .resolve_interface(&InterfaceRef::Name(ifname.to_string()))
            .await?;
        self.get_qdisc_by_handle_index(ifindex, handle).await
    }

    /// Get a qdisc by interface index and handle.
    ///
    /// # Example
    ///
    /// ```ignore
    /// // Get the qdisc with handle 1:0 on interface index 2
    /// if let Some(qdisc) = conn.get_qdisc_by_handle_index(2, TcHandle::major_only(1)).await? {
    ///     println!("Found qdisc: {}", qdisc.kind().unwrap_or("?"));
    /// }
    /// ```
    #[tracing::instrument(
        level = "debug",
        skip_all,
        fields(method = "get_qdisc_by_handle_index")
    )]
    pub async fn get_qdisc_by_handle_index(
        &self,
        ifindex: u32,
        handle: TcHandle,
    ) -> Result<Option<TcMessage>> {
        let qdiscs = self.get_qdiscs().await?;
        Ok(qdiscs
            .into_iter()
            .find(|q| q.ifindex() == ifindex && q.handle() == handle))
    }

    /// Get netem options for an interface, if a netem qdisc is configured at root.
    ///
    /// This is a convenience method that returns `Some` only if a netem qdisc
    /// is the root qdisc and its options can be parsed.
    ///
    /// Accepts either an interface name or index via [`InterfaceRef`].
    ///
    /// # Example
    ///
    /// ```ignore
    /// if let Some(netem) = conn.get_netem_by_name("eth0").await? {
    ///     if let Some(delay) = netem.delay() {
    ///         println!("Delay: {:?}", delay);
    ///     }
    ///     if let Some(loss) = netem.loss() {
    ///         println!("Loss: {:.2}%", loss);
    ///     }
    ///     if let Some(rate) = netem.rate_bps() {
    ///         println!("Rate limit: {} bytes/sec", rate);
    ///     }
    /// }
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_netem_by_name"))]
    pub async fn get_netem_by_name(
        &self,
        iface: impl Into<InterfaceRef>,
    ) -> Result<Option<super::tc_options::NetemOptions>> {
        let ifindex = self.resolve_interface(&iface.into()).await?;
        self.get_netem_by_index(ifindex).await
    }

    /// Get netem options for an interface by index.
    ///
    /// Returns `None` if no netem qdisc is configured at root.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_netem_by_index"))]
    pub async fn get_netem_by_index(
        &self,
        ifindex: u32,
    ) -> Result<Option<super::tc_options::NetemOptions>> {
        use super::tc_options::QdiscOptions;
        let root = self.get_root_qdisc_by_index(ifindex).await?;
        Ok(match root.and_then(|q| q.options()) {
            Some(QdiscOptions::Netem(opts)) => Some(opts),
            _ => None,
        })
    }
}

// ============================================================================
// Link State Management
// ============================================================================

use super::types::link::{IfInfoMsg, iff};

impl Connection<Route> {
    /// Bring a network interface up.
    ///
    /// Accepts either an interface name or index via [`InterfaceRef`].
    ///
    /// # Example
    ///
    /// ```ignore
    /// conn.set_link_up("eth0").await?;
    /// conn.set_link_up(5u32).await?;  // by index
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "set_link_up"))]
    pub async fn set_link_up(&self, iface: impl Into<InterfaceRef>) -> Result<()> {
        let ifindex = self.resolve_interface(&iface.into()).await?;
        self.set_link_up_by_index(ifindex).await
    }

    /// Bring a network interface up by index.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "set_link_up_by_index"))]
    pub async fn set_link_up_by_index(&self, ifindex: u32) -> Result<()> {
        self.set_link_state_by_index(ifindex, true).await
    }

    /// Bring a network interface down.
    ///
    /// Accepts either an interface name or index via [`InterfaceRef`].
    ///
    /// # Example
    ///
    /// ```ignore
    /// conn.set_link_down("eth0").await?;
    /// conn.set_link_down(5u32).await?;  // by index
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "set_link_down"))]
    pub async fn set_link_down(&self, iface: impl Into<InterfaceRef>) -> Result<()> {
        let ifindex = self.resolve_interface(&iface.into()).await?;
        self.set_link_down_by_index(ifindex).await
    }

    /// Bring a network interface down by index.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "set_link_down_by_index"))]
    pub async fn set_link_down_by_index(&self, ifindex: u32) -> Result<()> {
        self.set_link_state_by_index(ifindex, false).await
    }

    /// Set the state of a network interface (up or down).
    ///
    /// Accepts either an interface name or index via [`InterfaceRef`].
    ///
    /// # Arguments
    ///
    /// * `iface` - The interface name or index
    /// * `up` - `true` to bring the interface up, `false` to bring it down
    ///
    /// # Example
    ///
    /// ```ignore
    /// // Bring interface up
    /// conn.set_link_state("eth0", true).await?;
    ///
    /// // Bring interface down by index
    /// conn.set_link_state(5u32, false).await?;
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "set_link_state"))]
    pub async fn set_link_state(&self, iface: impl Into<InterfaceRef>, up: bool) -> Result<()> {
        let ifindex = self.resolve_interface(&iface.into()).await?;
        self.set_link_state_by_index(ifindex, up).await
    }

    /// Set the state of a network interface by index.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "set_link_state_by_index"))]
    pub async fn set_link_state_by_index(&self, ifindex: u32, up: bool) -> Result<()> {
        let mut ifinfo = IfInfoMsg::new().with_index(ifindex as i32);

        if up {
            ifinfo.ifi_flags = iff::UP;
            ifinfo.ifi_change = iff::UP;
        } else {
            ifinfo.ifi_flags = 0;
            ifinfo.ifi_change = iff::UP;
        }

        let mut builder = ack_request(NlMsgType::RTM_SETLINK);
        builder.append(&ifinfo);

        let state = if up { "up" } else { "down" };
        self.send_ack(builder).await.map_err(|e| {
            if e.is_not_found() {
                Error::InterfaceNotFound {
                    name: format!("ifindex {ifindex}"),
                }
            } else {
                e.with_context(format!("set_link_{state}(ifindex {ifindex})"))
            }
        })
    }

    /// Set the MTU of a network interface.
    ///
    /// Accepts either an interface name or index via [`InterfaceRef`].
    ///
    /// # Example
    ///
    /// ```ignore
    /// conn.set_link_mtu("eth0", 9000).await?;
    /// conn.set_link_mtu(5u32, 9000).await?;  // by index
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "set_link_mtu"))]
    pub async fn set_link_mtu(&self, iface: impl Into<InterfaceRef>, mtu: u32) -> Result<()> {
        let ifindex = self.resolve_interface(&iface.into()).await?;
        self.set_link_mtu_by_index(ifindex, mtu).await
    }

    /// Set the MTU of a network interface by index.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "set_link_mtu_by_index"))]
    pub async fn set_link_mtu_by_index(&self, ifindex: u32, mtu: u32) -> Result<()> {
        use super::types::link::IflaAttr;

        let ifinfo = IfInfoMsg::new().with_index(ifindex as i32);

        let mut builder = ack_request(NlMsgType::RTM_SETLINK);
        builder.append(&ifinfo);
        builder.append_attr_u32(IflaAttr::Mtu as u16, mtu);

        self.send_ack(builder)
            .await
            .map_err(|e| e.with_context("set_link_mtu"))
    }

    /// Delete a network interface.
    ///
    /// Accepts either an interface name or index via [`InterfaceRef`].
    ///
    /// # Example
    ///
    /// ```ignore
    /// conn.del_link("veth0").await?;
    /// conn.del_link(5u32).await?;  // by index
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "del_link"))]
    pub async fn del_link(&self, iface: impl Into<InterfaceRef>) -> Result<()> {
        let ifindex = self.resolve_interface(&iface.into()).await?;
        self.del_link_by_index(ifindex).await
    }

    /// Delete a network interface by index.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "del_link_by_index"))]
    pub async fn del_link_by_index(&self, ifindex: u32) -> Result<()> {
        let ifinfo = IfInfoMsg::new().with_index(ifindex as i32);

        let mut builder = ack_request(NlMsgType::RTM_DELLINK);
        builder.append(&ifinfo);

        self.send_ack(builder).await.map_err(|e| {
            if e.is_not_found() {
                Error::InterfaceNotFound {
                    name: format!("ifindex {ifindex}"),
                }
            } else {
                e.with_context(format!("del_link(ifindex {ifindex})"))
            }
        })
    }

    /// Set the TX queue length of a network interface.
    ///
    /// Accepts either an interface name or index via [`InterfaceRef`].
    ///
    /// # Example
    ///
    /// ```ignore
    /// conn.set_link_txqlen("eth0", 1000).await?;
    /// conn.set_link_txqlen(5u32, 1000).await?;  // by index
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "set_link_txqlen"))]
    pub async fn set_link_txqlen(&self, iface: impl Into<InterfaceRef>, txqlen: u32) -> Result<()> {
        let ifindex = self.resolve_interface(&iface.into()).await?;
        self.set_link_txqlen_by_index(ifindex, txqlen).await
    }

    /// Set the TX queue length of a network interface by index.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "set_link_txqlen_by_index"))]
    pub async fn set_link_txqlen_by_index(&self, ifindex: u32, txqlen: u32) -> Result<()> {
        use super::types::link::IflaAttr;

        let ifinfo = IfInfoMsg::new().with_index(ifindex as i32);

        let mut builder = ack_request(NlMsgType::RTM_SETLINK);
        builder.append(&ifinfo);
        builder.append_attr_u32(IflaAttr::TxqLen as u16, txqlen);

        self.send_ack(builder)
            .await
            .map_err(|e| e.with_context("set_link_txqlen"))
    }
}

// ============================================================================
// Namespace ID Queries
// ============================================================================

use super::{
    messages::NsIdMessage,
    types::nsid::{RTM_GETNSID, RtGenMsg, netnsa},
};

impl Connection<Route> {
    /// Get the namespace ID for a given file descriptor.
    ///
    /// The file descriptor should be an open reference to a network namespace
    /// (e.g., from opening `/proc/<pid>/ns/net`).
    ///
    /// # Errors
    ///
    /// Returns an error if the namespace ID cannot be determined.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use std::fs::File;
    /// use std::os::unix::io::AsRawFd;
    ///
    /// let ns_file = File::open("/var/run/netns/myns")?;
    /// let nsid = conn.get_nsid(ns_file.as_raw_fd()).await?;
    /// println!("Namespace ID: {}", nsid);
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_nsid"))]
    pub async fn get_nsid(&self, ns_fd: RawFd) -> Result<u32> {
        let mut builder = ack_request(RTM_GETNSID);

        // Append rtgenmsg header (1 byte + 3 padding)
        builder.append(&RtGenMsg::new());
        builder.append_bytes(&[0u8; 3]); // Padding to 4 bytes

        // Add NETNSA_FD attribute
        builder.append_attr_u32(netnsa::FD, ns_fd as u32);

        let response = self.send_request(builder).await?;

        // Parse the response
        if response.len() >= super::message::NLMSG_HDRLEN {
            let payload = &response[super::message::NLMSG_HDRLEN..];
            if let Some(nsid_msg) = NsIdMessage::parse(payload)
                && let Some(nsid) = nsid_msg.nsid
            {
                return Ok(nsid);
            }
        }

        Err(Error::InvalidMessage(
            "namespace ID not found in response".into(),
        ))
    }

    /// Get the namespace ID for a given process's network namespace.
    ///
    /// # Errors
    ///
    /// Returns an error if the namespace ID cannot be determined.
    ///
    /// # Example
    ///
    /// ```ignore
    /// // Get the namespace ID for process 1234
    /// let nsid = conn.get_nsid_for_pid(1234).await?;
    /// println!("Namespace ID for PID 1234: {}", nsid);
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_nsid_for_pid"))]
    pub async fn get_nsid_for_pid(&self, pid: u32) -> Result<u32> {
        let mut builder = ack_request(RTM_GETNSID);

        // Append rtgenmsg header (1 byte + 3 padding)
        builder.append(&RtGenMsg::new());
        builder.append_bytes(&[0u8; 3]); // Padding to 4 bytes

        // Add NETNSA_PID attribute
        builder.append_attr_u32(netnsa::PID, pid);

        let response = self.send_request(builder).await?;

        // Parse the response
        if response.len() >= super::message::NLMSG_HDRLEN {
            let payload = &response[super::message::NLMSG_HDRLEN..];
            if let Some(nsid_msg) = NsIdMessage::parse(payload)
                && let Some(nsid) = nsid_msg.nsid
            {
                return Ok(nsid);
            }
        }

        Err(Error::InvalidMessage(
            "namespace ID not found in response".into(),
        ))
    }
}

// ============================================================================
// Generic Netlink protocol methods
// ============================================================================

use std::collections::HashMap;

use super::{
    genl::{
        CtrlAttr, CtrlAttrMcastGrp, CtrlCmd, FamilyInfo, GENL_HDRLEN, GENL_ID_CTRL, GenlMsgHdr,
    },
    protocol::Generic,
};

impl Connection<Generic> {
    /// Get information about a Generic Netlink family.
    ///
    /// The result is cached, so subsequent calls for the same family
    /// do not require kernel communication.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use nlink::netlink::{Connection, Generic};
    ///
    /// let conn = Connection::<Generic>::new()?;
    /// let wg = conn.get_family("wireguard").await?;
    /// println!("WireGuard family ID: {}", wg.id);
    /// ```
    #[instrument(level = "info", skip(self), fields(family = %name, id, cached))]
    pub async fn get_family(&self, name: &str) -> Result<FamilyInfo> {
        // Check cache first. Poison-tolerant unwrap (Plan 212 M17)
        // — the locked region is panic-free, so poisoning is
        // unreachable; the `unwrap_or_else(into_inner)` recovers if
        // a future panic surfaces (hardening rather than fix).
        {
            let cache = self
                .state
                .cache
                .read()
                .unwrap_or_else(|p| p.into_inner());
            if let Some(info) = cache.get(name) {
                let span = tracing::Span::current();
                span.record("id", info.id);
                span.record("cached", true);
                return Ok(info.clone());
            }
        }

        // Query kernel for family info
        let info = self.query_family(name).await?;
        let span = tracing::Span::current();
        span.record("id", info.id);
        span.record("cached", false);

        // Cache the result
        {
            let mut cache = self
                .state
                .cache
                .write()
                .unwrap_or_else(|p| p.into_inner());
            cache.insert(name.to_string(), info.clone());
        }

        Ok(info)
    }

    /// Get the family ID for a given family name.
    ///
    /// This is a convenience method that returns just the ID.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_family_id"))]
    pub async fn get_family_id(&self, name: &str) -> Result<u16> {
        Ok(self.get_family(name).await?.id)
    }

    /// Clear the family cache.
    ///
    /// This is rarely needed, but may be useful if families are
    /// dynamically loaded/unloaded.
    pub fn clear_cache(&self) {
        let mut cache = self
            .state
            .cache
            .write()
            .unwrap_or_else(|p| p.into_inner());
        cache.clear();
    }

    /// Query the kernel for family information.
    async fn query_family(&self, name: &str) -> Result<FamilyInfo> {
        // Build CTRL_CMD_GETFAMILY request
        let mut builder = MessageBuilder::new(GENL_ID_CTRL, NLM_F_REQUEST | NLM_F_ACK);

        // Append GENL header
        let genl_hdr = GenlMsgHdr::new(CtrlCmd::GetFamily as u8, 1);
        builder.append(&genl_hdr);

        // Append family name attribute
        builder.append_attr_str(CtrlAttr::FamilyName as u16, name);

        // Plan 208 Phase 1 — wrap in with_timeout. High blast radius:
        // every hand-rolled GENL family resolution touches this
        // method. Pre-0.19 had no timeout; a dropped CTRL_CMD_GETFAMILY
        // response would hang `new_async()` indefinitely.
        //
        // Note: parse_family_response already filters by seq, but the
        // single-recv pattern means a stale frame on the socket would
        // be swallowed once and then the kernel's real reply would
        // arrive on the next recv — outside the bounds of this call.
        // The minimum-risk fix is to keep the single-recv but add the
        // timeout wrap. A full loop+seq-filter refactor (Plan 208
        // Phase 4) is queued separately because parse_family_response
        // conflates "stale frame" and "real ENOENT" into the same
        // FamilyNotFound error and disambiguating that requires
        // refactoring the parse side.
        self.with_timeout(async move {
            let seq = self.socket.next_seq();
            builder.set_seq(seq);
            builder.set_pid(self.socket.pid());

            let msg = builder.finish();
            self.socket.send(&msg).await?;

            let response = self.socket.recv_msg().await?;
            self.parse_family_response(&response, seq, name)
        })
        .await
    }

    /// Parse a CTRL_CMD_GETFAMILY response.
    fn parse_family_response(&self, data: &[u8], seq: u32, name: &str) -> Result<FamilyInfo> {
        for result in MessageIter::new(data) {
            let (header, payload) = result?;

            // Check sequence number
            if header.nlmsg_seq != seq {
                continue;
            }

            // Check for error
            if header.is_error() {
                let err = NlMsgError::from_bytes(payload)?;
                if !err.is_ack() {
                    // ENOENT means family not found
                    if err.error == -libc::ENOENT {
                        return Err(Error::FamilyNotFound {
                            name: name.to_string(),
                        });
                    }
                    return Err(err.into_error(payload));
                }
                continue;
            }

            // Skip DONE message
            if header.is_done() {
                continue;
            }

            // Parse GENL header
            if payload.len() < GENL_HDRLEN {
                return Err(Error::InvalidMessage("GENL header too short".into()));
            }

            // Parse attributes after GENL header
            let attrs_data = &payload[GENL_HDRLEN..];
            return self.parse_family_attrs(attrs_data);
        }

        Err(Error::FamilyNotFound {
            name: name.to_string(),
        })
    }

    /// Parse family attributes from a CTRL_CMD_GETFAMILY response.
    fn parse_family_attrs(&self, data: &[u8]) -> Result<FamilyInfo> {
        use super::attr::{AttrIter, get};

        let mut id: Option<u16> = None;
        let mut version: u8 = 0;
        let mut hdr_size: u32 = 0;
        let mut max_attr: u32 = 0;
        let mut mcast_groups = HashMap::new();

        for (attr_type, payload) in AttrIter::new(data) {
            match attr_type {
                t if t == CtrlAttr::FamilyId as u16 => {
                    id = Some(get::u16_ne(payload)?);
                }
                t if t == CtrlAttr::Version as u16 => {
                    version = get::u32_ne(payload)? as u8;
                }
                t if t == CtrlAttr::HdrSize as u16 => {
                    hdr_size = get::u32_ne(payload)?;
                }
                t if t == CtrlAttr::MaxAttr as u16 => {
                    max_attr = get::u32_ne(payload)?;
                }
                t if t == CtrlAttr::McastGroups as u16 => {
                    mcast_groups = self.parse_mcast_groups(payload)?;
                }
                _ => {}
            }
        }

        let id = id.ok_or_else(|| Error::InvalidMessage("missing family ID".into()))?;

        Ok(FamilyInfo {
            id,
            version,
            hdr_size,
            max_attr,
            mcast_groups,
        })
    }

    /// Parse multicast groups from CTRL_ATTR_MCAST_GROUPS.
    fn parse_mcast_groups(&self, data: &[u8]) -> Result<HashMap<String, u32>> {
        use super::attr::{AttrIter, get};

        let mut groups = HashMap::new();

        // The mcast_groups attribute contains nested arrays
        for (_group_idx, group_payload) in AttrIter::new(data) {
            let mut name: Option<String> = None;
            let mut grp_id: Option<u32> = None;

            // Parse the nested group attributes
            for (attr_type, payload) in AttrIter::new(group_payload) {
                match attr_type {
                    t if t == CtrlAttrMcastGrp::Name as u16 => {
                        name = Some(get::string(payload)?.to_string());
                    }
                    t if t == CtrlAttrMcastGrp::Id as u16 => {
                        grp_id = Some(get::u32_ne(payload)?);
                    }
                    _ => {}
                }
            }

            if let (Some(name), Some(id)) = (name, grp_id) {
                groups.insert(name, id);
            }
        }

        Ok(groups)
    }

    /// Send a GENL command and wait for a response.
    ///
    /// This is a low-level method for sending arbitrary GENL commands.
    /// Family-specific wrappers (like `Connection<Wireguard>`) should use this.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "command"))]
    pub async fn command(
        &self,
        family_id: u16,
        cmd: u8,
        version: u8,
        build_attrs: impl FnOnce(&mut MessageBuilder),
    ) -> Result<Vec<u8>> {
        let mut builder = MessageBuilder::new(family_id, NLM_F_REQUEST | NLM_F_ACK);
        let genl_hdr = GenlMsgHdr::new(cmd, version);
        builder.append(&genl_hdr);
        build_attrs(&mut builder);

        // F1 fix — these public escape hatches for custom GENL
        // commands were missed in the 0.19 lock sweep. Without this,
        // `conn.command(...)` running concurrently with `conn.get_links()`
        // on a shared `Arc<Connection>` races on the recv side
        // exactly like the pre-F1 bug. Lock acquired BEFORE
        // with_timeout so the lock spans the 30s op-timeout window.
        let _guard = self.lock_request().await;

        // Plan 208 Phase 1 — wrap in with_timeout. Pre-0.19 a kernel
        // that dropped the ACK for any custom GENL command hung
        // indefinitely. `process_genl_response` already does
        // seq-filter; the timeout closes the indefinite-hang class.
        self.with_timeout(async move {
            let seq = self.socket.next_seq();
            builder.set_seq(seq);
            builder.set_pid(self.socket.pid());

            let msg = builder.finish();
            self.socket.send(&msg).await?;

            let response = self.socket.recv_msg().await?;
            self.process_genl_response(&response, seq)?;

            Ok(response)
        })
        .await
    }

    /// Send a GENL dump command and collect all responses.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "dump_command"))]
    pub async fn dump_command(
        &self,
        family_id: u16,
        cmd: u8,
        version: u8,
        build_attrs: impl FnOnce(&mut MessageBuilder),
    ) -> Result<Vec<Vec<u8>>> {
        let mut builder = MessageBuilder::new(family_id, NLM_F_REQUEST | NLM_F_DUMP);
        let genl_hdr = GenlMsgHdr::new(cmd, version);
        builder.append(&genl_hdr);
        build_attrs(&mut builder);

        // F1 fix — see `command()` above.
        let _guard = self.lock_request().await;

        // Plan 208 Phase 1+2 — wrap in with_timeout, add
        // NLM_F_DUMP_INTR detection. Pre-0.19 every custom GENL
        // dump could hang indefinitely on a dropped response AND
        // silently use an inconsistent snapshot when the kernel
        // signaled mid-dump mutation.
        self.with_timeout(async move {
            let seq = self.socket.next_seq();
            builder.set_seq(seq);
            builder.set_pid(self.socket.pid());

            let msg = builder.finish();
            self.socket.send(&msg).await?;

            let mut responses = Vec::new();

            loop {
                let data = self.socket.recv_msg().await?;
                let mut done = false;

                for result in MessageIter::new(&data) {
                    let (header, payload) = result?;

                    if header.nlmsg_seq != seq {
                        continue;
                    }

                    if header.is_dump_interrupted() {
                        return Err(Error::DumpInterrupted);
                    }

                    if header.is_error() {
                        let err = NlMsgError::from_bytes(payload)?;
                        if !err.is_ack() {
                            return Err(err.into_error(payload));
                        }
                        continue;
                    }

                    if header.is_done() {
                        done = true;
                        break;
                    }

                    responses.push(payload.to_vec());
                }

                if done {
                    break;
                }
            }

            Ok(responses)
        })
        .await
    }

    /// Process a GENL response, checking for errors.
    fn process_genl_response(&self, data: &[u8], seq: u32) -> Result<()> {
        for result in MessageIter::new(data) {
            let (header, payload) = result?;

            if header.nlmsg_seq != seq {
                continue;
            }

            if header.is_error() {
                let err = NlMsgError::from_bytes(payload)?;
                if !err.is_ack() {
                    return Err(err.into_error(payload));
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod send_sync_tests {
    use super::*;

    fn assert_send<T: Send>() {}
    fn assert_sync<T: Sync>() {}

    #[test]
    fn connection_is_send_sync() {
        assert_send::<Connection<Route>>();
        assert_sync::<Connection<Route>>();
    }

    /// Plan 171 — every fresh Connection<P> ships with the default
    /// 30s operation timeout. Caller can override via
    /// `.timeout(d)` or opt out via `.no_timeout()`.
    #[tokio::test]
    async fn connection_default_timeout_is_30s() {
        let conn = Connection::<Route>::new().expect("socket open");
        assert_eq!(
            conn.get_timeout(),
            Some(DEFAULT_OPERATION_TIMEOUT),
            "Plan 171: fresh Connection<P> must default to 30s timeout"
        );
        assert_eq!(
            DEFAULT_OPERATION_TIMEOUT,
            Duration::from_secs(30),
            "Plan 171: documented constant value",
        );
    }

    #[tokio::test]
    async fn connection_no_timeout_clears_default() {
        let conn = Connection::<Route>::new()
            .expect("socket open")
            .no_timeout();
        assert_eq!(
            conn.get_timeout(),
            None,
            "Plan 171: .no_timeout() must opt out of the default"
        );
    }

    #[tokio::test]
    async fn connection_timeout_override_replaces_default() {
        let conn = Connection::<Route>::new()
            .expect("socket open")
            .timeout(Duration::from_secs(5));
        assert_eq!(conn.get_timeout(), Some(Duration::from_secs(5)));
    }
}
