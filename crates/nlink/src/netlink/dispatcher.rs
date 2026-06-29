//! Per-Connection dispatcher — Plan 234 (0.21.0).
//!
//! Architectural foundation for the F1 follow-on. The dispatcher
//! provides a broadcast-channel multicast surface and the
//! `ResyncMarker::ResyncStart` ENOBUFS routing that Plan 151 was
//! designed for. The full NlRouter-style per-seq dispatcher (every
//! unicast request pipelines through one fd) lands incrementally;
//! this module ships the shared infrastructure that unicast pipelining
//! will plug into, plus the multicast surface that's usable today.
//!
//! # What ships in 0.21.0
//!
//! - [`Dispatcher`] — a per-Connection async task that holds a set
//!   of multicast broadcast channels and routes ENOBUFS into them
//!   as [`ResyncMarker::ResyncStart`].
//! - [`Dispatcher::subscribe_multicast`] — register interest in a
//!   multicast group; the dispatcher fans out frames received on
//!   that group to the returned `broadcast::Receiver`.
//! - [`Dispatcher::emit_enobufs`] — public escape hatch the
//!   `NetlinkSocket::recv_msg` wrapper calls when the kernel
//!   returns ENOBUFS; emits `ResyncStart` to every active
//!   subscriber so Plan 151's `*_with_resync` wrappers re-dump
//!   cleanly.
//!
//! # What's queued for a follow-up
//!
//! The full unicast-pipelining dispatcher — where every
//! `send_request_and_wait` call registers a oneshot in a per-seq
//! pending map and the dispatcher demuxes recv frames by
//! `nlmsg_seq` — is the architectural next step. Today's
//! call-sites still hold the F1 `tokio::sync::Mutex` while
//! `send + recv-loop-until-DONE` runs. The dispatcher's
//! infrastructure ships now so the unicast piece can plug in
//! without rewriting the broadcast surface.
//!
//! See Plan 234 §6 for the test plan that the full dispatcher
//! must pass; this module's surface is the foundation Stage 1 of
//! that work plugs into.
//!
//! # Why this lands now
//!
//! Without it, ENOBUFS surfaces into whichever caller happens to
//! be in `recv_msg` when the kernel overflows the multicast
//! buffer — typically a request, not the multicast subscriber
//! that should care. Plan 151's `ResyncMarker` types exist
//! precisely so subscribers can recover; the dispatcher routes
//! the marker to the right place.
//!
//! See `docs/recipes/events-with-resync.md` and the
//! `subscribe_*_with_resync` wrappers for the consumer-side
//! pattern.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex, OnceLock, RwLock},
};

use tokio::sync::{Notify, broadcast, mpsc};

use super::{message::MessageIter, resync::ResyncMarker, socket::NetlinkSocket};
use crate::Error;

/// Default broadcast channel capacity for multicast subscriptions.
///
/// 1024 matches Plan 234 §3's recommendation. Slow subscribers
/// see a backlog drop via `broadcast::error::RecvError::Lagged`;
/// the dispatcher synthesizes a `ResyncMarker::ResyncStart` into
/// the channel and the caller's `*_with_resync` wrapper re-syncs.
pub const DEFAULT_MULTICAST_CAPACITY: usize = 1024;

/// Dispatcher state shared between the Connection and (eventually)
/// the per-Connection dispatcher task.
///
/// Plan 234 architectural foundation: this is the type that grows
/// the per-seq pending map and the recv-loop ownership when the
/// full dispatcher lands. Today it ships with the multicast-only
/// surface (broadcast channels keyed by group + the ENOBUFS fan-out
/// path).
///
/// Cheap to clone (`Arc`-wrapped internally).
#[derive(Clone)]
pub struct Dispatcher {
    inner: Arc<DispatcherInner>,
}

struct DispatcherInner {
    /// Per-multicast-group broadcast senders. Keyed by
    /// raw netlink group number (matches
    /// `socket::rtnetlink_groups::*`, family-resolved GENL group
    /// IDs, etc.).
    ///
    /// `RwLock` over a `HashMap` rather than a `DashMap` to keep
    /// the dep footprint minimal — register/lookup is rare relative
    /// to fan-out which is read-only.
    subscribers: RwLock<HashMap<u32, broadcast::Sender<DispatcherEvent>>>,

    /// #134 — per-`nlmsg_seq` unicast demux. When a `Connection` runs
    /// in dispatcher mode, each request registers a sender here keyed
    /// by its sequence number; the background driver task routes each
    /// recv'd datagram to the matching sender. `std::sync::Mutex`
    /// because every critical section is an O(1) map op never held
    /// across an await.
    pending: Mutex<HashMap<u32, mpsc::UnboundedSender<Arc<Vec<u8>>>>>,

    /// #134 — the background recv-driver task handle, spawned lazily
    /// on first dispatcher-mode use via [`Dispatcher::ensure_driver`].
    driver: OnceLock<tokio::task::JoinHandle<()>>,

    /// #134 — fires when the owning `Connection` is dropped so the
    /// driver task exits and releases its `Arc<NetlinkSocket>`.
    shutdown: Notify,

    /// #134 — the last fatal recv error's message, stored when the
    /// driver dies so awaiting requests (whose channels then close)
    /// can surface a meaningful error instead of a bare "closed".
    fatal: Mutex<Option<String>>,
}

/// Item delivered to multicast subscribers by the dispatcher.
///
/// Plan 234 §3 + §4 — multicast frames are forwarded as `Frame`;
/// ENOBUFS recovery is signalled via `Resync`.
#[derive(Debug, Clone)]
pub enum DispatcherEvent {
    /// A multicast frame from the kernel — raw netlink bytes.
    /// Subscribers re-parse via the appropriate `EventSource`
    /// impl (Plan 234 keeps the parse on the consumer side so a
    /// stale subscriber doesn't waste dispatcher CPU on a
    /// frame nobody's reading).
    Frame(Arc<Vec<u8>>),
    /// Plan 151 boundary marker, currently emitted only for
    /// `ResyncStart` from the ENOBUFS path. `ResyncEnd` stays
    /// with the consumer-side `*_with_resync` wrapper (it knows
    /// when the redump finished).
    Resync(ResyncMarker),
}

impl Dispatcher {
    /// Create a new dispatcher with no active subscriptions.
    ///
    /// Plan 234 — the dispatcher is owned by `Connection<P>` and
    /// shared with the (future) recv-side task that owns the fd.
    pub(crate) fn new() -> Self {
        Self {
            inner: Arc::new(DispatcherInner {
                subscribers: RwLock::new(HashMap::new()),
                pending: Mutex::new(HashMap::new()),
                driver: OnceLock::new(),
                shutdown: Notify::new(),
                fatal: Mutex::new(None),
            }),
        }
    }

    /// Register interest in a multicast group. Returns a
    /// `broadcast::Receiver` that yields `DispatcherEvent`s for
    /// that group.
    ///
    /// Multiple subscribers may register for the same group; each
    /// gets its own receiver and sees the same frames.
    ///
    /// The dispatcher does NOT subscribe the underlying socket to
    /// the kernel multicast group — the caller does that separately
    /// via `NetlinkSocket::add_membership`. The dispatcher only
    /// handles the fan-out side. (Future Plan 235 work may unify
    /// these.)
    pub fn subscribe_multicast(&self, group: u32) -> broadcast::Receiver<DispatcherEvent> {
        let mut subs = self
            .inner
            .subscribers
            .write()
            .unwrap_or_else(|p| p.into_inner());
        subs.entry(group)
            .or_insert_with(|| broadcast::channel(DEFAULT_MULTICAST_CAPACITY).0)
            .subscribe()
    }

    /// Emit `ResyncMarker::ResyncStart` to every active
    /// multicast subscriber.
    ///
    /// Plan 234 §4 — called by the `NetlinkSocket::recv_msg`
    /// wrapper (or the future dispatcher recv loop) when the
    /// kernel returns ENOBUFS. Subscribers' `*_with_resync`
    /// wrappers consume the marker and re-issue the appropriate
    /// dump.
    ///
    /// Idempotent — if no subscribers are active the call is a
    /// no-op.
    pub fn emit_enobufs(&self) {
        let subs = self
            .inner
            .subscribers
            .read()
            .unwrap_or_else(|p| p.into_inner());
        let ev = DispatcherEvent::Resync(ResyncMarker::ResyncStart);
        for (group, sender) in subs.iter() {
            // broadcast::Sender::send returns Err(SendError) when
            // there are zero active receivers — that's fine here,
            // we drop silently. Lagged receivers don't surface to
            // the sender; they see Lagged on their next recv()
            // which the consumer-side wrapper treats as a resync
            // cue too.
            let n = sender.receiver_count();
            if n == 0 {
                continue;
            }
            match sender.send(ev.clone()) {
                Ok(_) => {
                    tracing::debug!(group, subs = n, "dispatcher: ENOBUFS resync emitted");
                }
                Err(_) => {
                    tracing::trace!(group, "dispatcher: ENOBUFS resync had no live receivers");
                }
            }
        }
    }

    /// Forward a multicast frame to all subscribers of the given
    /// group. Returns the number of subscribers the frame was
    /// fanned out to (0 if no subscribers were active).
    ///
    /// Plan 234 §3 — called by the dispatcher recv loop when it
    /// classifies a frame as multicast. Today no recv loop calls
    /// this directly (the F1 mutex still owns recv); the entry
    /// point exists for the full dispatcher follow-up.
    pub fn fan_out(&self, group: u32, frame: Arc<Vec<u8>>) -> usize {
        let subs = self
            .inner
            .subscribers
            .read()
            .unwrap_or_else(|p| p.into_inner());
        let Some(sender) = subs.get(&group) else {
            return 0;
        };
        let n = sender.receiver_count();
        if n == 0 {
            return 0;
        }
        // Ignore SendError — the only way it returns Err is if
        // every receiver has been dropped between our count check
        // and the send. That's a benign race.
        let _ = sender.send(DispatcherEvent::Frame(frame));
        n
    }

    // ========================================================================
    // #134 — per-seq unicast registry + background recv driver
    // ========================================================================

    /// Register interest in responses for `seq`. Returns a RAII guard
    /// whose `rx` yields each datagram the driver routes to this seq;
    /// dropping the guard deregisters the seq (cancellation-safe — a
    /// late frame for a dropped request is then discarded).
    ///
    /// Callers MUST register **before** sending the request so the
    /// driver never observes a response for an unregistered seq (the
    /// `pending` mutex supplies the happens-before edge).
    pub(crate) fn register(&self, seq: u32) -> PendingGuard {
        let (tx, rx) = mpsc::unbounded_channel();
        self.inner
            .pending
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(seq, tx);
        PendingGuard {
            dispatcher: self.clone(),
            seq,
            rx,
        }
    }

    /// Remove the pending entry for `seq` (called from `PendingGuard`'s
    /// `Drop`, and by the driver after it routes a terminal frame is
    /// **not** done here — the guard owns the lifetime).
    pub(crate) fn deregister(&self, seq: u32) {
        self.inner
            .pending
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(&seq);
    }

    /// Classify and route one recv'd datagram. Called by the driver.
    ///
    /// Rules (mirror the seq invariant the request loops rely on):
    /// - first parseable message has `seq != 0` and a registered
    ///   pending entry → forward the whole buffer to that channel;
    /// - `seq == 0` → multicast notification → fan out to every
    ///   subscriber (group-agnostic v1, preserving today's
    ///   "see-everything-then-filter" `events()` semantics);
    /// - otherwise (unknown / late / post-cancel seq) → drop.
    pub(crate) fn route_buffer(&self, buf: Arc<Vec<u8>>) {
        let Some((header, _)) = MessageIter::new(&buf).flatten().next() else {
            // Unparseable frame — drop (Plan 193 rule 3 spirit).
            return;
        };
        let seq = header.nlmsg_seq;
        if seq == 0 {
            self.fan_out_all(buf);
            return;
        }
        let pending = self.inner.pending.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(tx) = pending.get(&seq) {
            // Ignore send errors — the receiver may have been dropped
            // between the driver's lookup and now (cancellation race);
            // the guard's Drop will clean up the map entry.
            let _ = tx.send(buf);
        } else {
            tracing::trace!(seq, "dispatcher: dropping frame for unregistered seq");
        }
    }

    /// Fan a `seq == 0` multicast frame out to every subscriber on
    /// every group. v1 is group-agnostic (the netlink group isn't in
    /// the message body); consumers filter by message type.
    fn fan_out_all(&self, frame: Arc<Vec<u8>>) -> usize {
        let subs = self
            .inner
            .subscribers
            .read()
            .unwrap_or_else(|p| p.into_inner());
        let mut delivered = 0;
        for sender in subs.values() {
            if sender.receiver_count() == 0 {
                continue;
            }
            if sender.send(DispatcherEvent::Frame(frame.clone())).is_ok() {
                delivered += 1;
            }
        }
        delivered
    }

    /// Record a fatal recv error and tear down every pending request:
    /// dropping the senders closes their channels, so an awaiting
    /// request's `rx.recv()` returns `None` and surfaces the error via
    /// [`take_fatal_error`](Self::take_fatal_error).
    fn fail_all(&self, message: String) {
        *self.inner.fatal.lock().unwrap_or_else(|p| p.into_inner()) = Some(message);
        self.inner
            .pending
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clear();
    }

    /// Take the stored fatal error (if any) as an [`Error`], or a
    /// generic "driver stopped" error. Called by a request whose
    /// pending channel closed unexpectedly.
    pub(crate) fn take_fatal_error(&self) -> Error {
        let msg = self
            .inner
            .fatal
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone();
        match msg {
            Some(m) => Error::Io(std::io::Error::other(format!(
                "netlink dispatcher driver stopped: {m}"
            ))),
            None => Error::Io(std::io::Error::other(
                "netlink dispatcher driver stopped before the response arrived",
            )),
        }
    }

    /// Spawn the background recv-driver task if it isn't already
    /// running (idempotent via `OnceLock`). Must be called from within
    /// a Tokio runtime context (the request inners are `async`, so
    /// `Handle::current()` is always valid there).
    pub(crate) fn ensure_driver(&self, socket: Arc<NetlinkSocket>) {
        self.inner.driver.get_or_init(|| {
            let dispatcher = self.clone();
            tokio::spawn(async move { run_driver(socket, dispatcher).await })
        });
    }

    /// Signal the driver task to exit. Called from `Connection`'s
    /// `Drop`. The driver `select!`s on this and drops its
    /// `Arc<NetlinkSocket>` on wake; the last `Arc` closes the fd.
    pub(crate) fn shutdown(&self) {
        self.inner.shutdown.notify_waiters();
    }

    /// `true` once the background driver has been spawned.
    pub(crate) fn driver_started(&self) -> bool {
        self.inner.driver.get().is_some()
    }

    /// Test/lab accessor: number of in-flight registered seqs.
    #[cfg(any(test, feature = "lab"))]
    pub fn pending_count(&self) -> usize {
        self.inner
            .pending
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .len()
    }

    /// Count of currently-registered multicast groups. Used by
    /// `Connection::is_closed` follow-on work and by the dispatcher
    /// stress tests in Plan 234 §6.
    pub fn active_group_count(&self) -> usize {
        self.inner
            .subscribers
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .len()
    }

    /// Drop any multicast group that has no live subscribers. The
    /// `subscribe_multicast` path lazy-creates senders; this
    /// reverse hook lets callers reclaim space when long-lived
    /// connections churn subscriptions.
    ///
    /// Today it's only called from tests; production callers can
    /// rely on `broadcast::Sender` staying around — the cost is
    /// O(groups), not O(messages).
    #[cfg(test)]
    pub fn gc(&self) {
        let mut subs = self
            .inner
            .subscribers
            .write()
            .unwrap_or_else(|p| p.into_inner());
        subs.retain(|_, sender| sender.receiver_count() > 0);
    }
}

/// RAII registration handle for a per-seq response channel (#134).
///
/// Holds the receiving end of the channel the driver routes datagrams
/// to. Dropping it deregisters the seq from the dispatcher's pending
/// map — this is what makes a cancelled / timed-out request
/// cancellation-safe: a late frame for the dropped seq is then
/// discarded by [`Dispatcher::route_buffer`] instead of stranding the
/// recv side.
pub(crate) struct PendingGuard {
    dispatcher: Dispatcher,
    seq: u32,
    /// Each item is a full netlink datagram routed by the driver.
    pub rx: mpsc::UnboundedReceiver<Arc<Vec<u8>>>,
}

impl Drop for PendingGuard {
    fn drop(&mut self) {
        self.dispatcher.deregister(self.seq);
    }
}

/// The background recv-driver loop (#134). Owns the socket's recv side
/// while in dispatcher mode: reads each datagram and demuxes it to the
/// matching per-seq channel (unicast) or the multicast subscribers
/// (`seq == 0`).
async fn run_driver(socket: Arc<NetlinkSocket>, dispatcher: Dispatcher) {
    loop {
        tokio::select! {
            biased;
            _ = dispatcher.inner.shutdown.notified() => {
                tracing::trace!("dispatcher driver: shutdown");
                break;
            }
            res = socket.recv_msg() => match res {
                Ok(buf) => dispatcher.route_buffer(Arc::new(buf)),
                Err(e) if e.is_no_buffer_space() => {
                    // ENOBUFS: `recv_msg` already fanned out
                    // ResyncMarker::ResyncStart to subscribers via the
                    // socket's dispatcher hook. A multicast overflow
                    // must not kill unrelated in-flight requests, so
                    // keep going (an improvement over the pre-dispatcher
                    // path where ENOBUFS surfaced into whichever caller
                    // happened to be in recv_msg).
                    tracing::debug!("dispatcher driver: ENOBUFS, continuing");
                    continue;
                }
                Err(e) => {
                    tracing::warn!(error = %e, "dispatcher driver: fatal recv error");
                    dispatcher.fail_all(e.to_string());
                    break;
                }
            }
        }
    }
}

impl Default for Dispatcher {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for Dispatcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let n = self.active_group_count();
        f.debug_struct("Dispatcher")
            .field("active_groups", &n)
            .finish()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn dispatcher_starts_empty() {
        let d = Dispatcher::new();
        assert_eq!(d.active_group_count(), 0);
    }

    #[tokio::test]
    async fn subscribe_multicast_registers_group() {
        let d = Dispatcher::new();
        let _rx = d.subscribe_multicast(1);
        assert_eq!(d.active_group_count(), 1);
    }

    #[tokio::test]
    async fn subscribe_multicast_same_group_shares_sender() {
        let d = Dispatcher::new();
        let _rx1 = d.subscribe_multicast(7);
        let _rx2 = d.subscribe_multicast(7);
        // One group entry, two receivers.
        assert_eq!(d.active_group_count(), 1);
    }

    #[tokio::test]
    async fn fan_out_delivers_to_subscriber() {
        let d = Dispatcher::new();
        let mut rx = d.subscribe_multicast(42);
        let frame = Arc::new(vec![1u8, 2, 3, 4]);
        let n = d.fan_out(42, frame.clone());
        assert_eq!(n, 1);
        match rx.recv().await {
            Ok(DispatcherEvent::Frame(f)) => assert_eq!(&*f, &[1u8, 2, 3, 4]),
            other => panic!("expected Frame, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn fan_out_skips_other_groups() {
        let d = Dispatcher::new();
        let mut rx1 = d.subscribe_multicast(1);
        let _rx2 = d.subscribe_multicast(2); // bind so the receiver stays live
        let frame = Arc::new(vec![9u8]);
        // Send to group 2; receiver on group 1 must not see it.
        let n = d.fan_out(2, frame);
        assert_eq!(n, 1, "fan_out reaches the group-2 subscriber");
        // Receiver on group 1 sees nothing — try_recv should return
        // Empty.
        assert!(
            matches!(rx1.try_recv(), Err(broadcast::error::TryRecvError::Empty)),
            "group-1 receiver must not see group-2 frame"
        );
    }

    #[tokio::test]
    async fn fan_out_no_subscribers_returns_zero() {
        let d = Dispatcher::new();
        let frame = Arc::new(vec![1u8]);
        assert_eq!(d.fan_out(1, frame), 0);
    }

    #[tokio::test]
    async fn enobufs_fans_out_resync_start_to_all_subscribers() {
        // Plan 234 §6.3 — ENOBUFS recovery test (synthetic; no live
        // socket needed). Multiple subscribers on different groups;
        // ENOBUFS emit must reach every active receiver.
        let d = Dispatcher::new();
        let mut rx1 = d.subscribe_multicast(1);
        let mut rx2 = d.subscribe_multicast(2);
        let mut rx3 = d.subscribe_multicast(3);

        d.emit_enobufs();

        for (i, rx) in [&mut rx1, &mut rx2, &mut rx3].iter_mut().enumerate() {
            match rx.recv().await {
                Ok(DispatcherEvent::Resync(ResyncMarker::ResyncStart)) => {
                    // expected
                }
                other => panic!("subscriber {i} expected ResyncStart, got {:?}", other),
            }
        }
    }

    #[tokio::test]
    async fn enobufs_with_no_subscribers_is_noop() {
        // Idempotent: emit_enobufs on a dispatcher with no
        // active subscribers must not panic / leak.
        let d = Dispatcher::new();
        d.emit_enobufs();
        // Subscribe after the fact — must not see a stale
        // ResyncStart (the broadcast channel didn't exist yet).
        let mut rx = d.subscribe_multicast(99);
        assert!(matches!(
            rx.try_recv(),
            Err(broadcast::error::TryRecvError::Empty)
        ));
    }

    #[tokio::test]
    async fn enobufs_with_dropped_receiver_does_not_panic() {
        let d = Dispatcher::new();
        let rx = d.subscribe_multicast(5);
        drop(rx);
        // No live receiver — emit must complete cleanly.
        d.emit_enobufs();
    }

    #[tokio::test]
    async fn gc_reclaims_dropped_groups() {
        let d = Dispatcher::new();
        let rx = d.subscribe_multicast(11);
        assert_eq!(d.active_group_count(), 1);
        drop(rx);
        d.gc();
        assert_eq!(d.active_group_count(), 0);
    }

    #[tokio::test]
    async fn fan_out_with_many_subscribers() {
        // Stress: 32 subscribers on the same group all receive the
        // same frame.
        let d = Dispatcher::new();
        let mut receivers: Vec<_> = (0..32).map(|_| d.subscribe_multicast(7)).collect();
        let frame = Arc::new(vec![0xAB; 16]);
        let delivered = d.fan_out(7, frame.clone());
        assert_eq!(delivered, 32);
        for rx in receivers.iter_mut() {
            match rx.try_recv() {
                Ok(DispatcherEvent::Frame(f)) => assert_eq!(f.len(), 16),
                other => panic!("expected Frame, got {:?}", other),
            }
        }
    }

    // -- #134 — per-seq unicast registry routing ------------------

    /// Build a minimal valid netlink datagram carrying a single
    /// message with the given `seq`. `MessageIter` only needs a
    /// well-formed `nlmsghdr`, so a header-only frame suffices.
    fn synth_frame(seq: u32) -> Arc<Vec<u8>> {
        use crate::netlink::message::{NLMSG_HDRLEN, NlMsgHdr, NlMsgType};
        let mut hdr = NlMsgHdr::new(NlMsgType::RTM_NEWLINK, 0);
        hdr.nlmsg_len = NLMSG_HDRLEN as u32;
        hdr.nlmsg_seq = seq;
        Arc::new(hdr.as_bytes().to_vec())
    }

    #[tokio::test]
    async fn register_then_route_delivers_to_matching_seq() {
        let d = Dispatcher::new();
        let mut guard = d.register(7);
        assert_eq!(d.pending_count(), 1);
        d.route_buffer(synth_frame(7));
        let buf = guard.rx.recv().await.expect("frame routed to seq 7");
        // The routed buffer is the whole datagram.
        assert!(!buf.is_empty());
    }

    #[tokio::test]
    async fn route_unregistered_seq_is_dropped() {
        let d = Dispatcher::new();
        let mut guard = d.register(1);
        // Frame for an unregistered seq must not reach seq 1's channel.
        d.route_buffer(synth_frame(999));
        assert!(matches!(
            guard.rx.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));
    }

    #[tokio::test]
    async fn dropping_guard_deregisters_seq() {
        let d = Dispatcher::new();
        let guard = d.register(3);
        assert_eq!(d.pending_count(), 1);
        drop(guard);
        assert_eq!(d.pending_count(), 0);
        // A late frame for the dropped seq is silently discarded.
        d.route_buffer(synth_frame(3));
        assert_eq!(d.pending_count(), 0);
    }

    #[tokio::test]
    async fn seq_zero_frame_fans_out_to_multicast() {
        let d = Dispatcher::new();
        let mut sub = d.subscribe_multicast(1);
        let mut unicast = d.register(5);
        // seq == 0 → multicast fan-out, NOT the unicast channel.
        d.route_buffer(synth_frame(0));
        match sub.recv().await {
            Ok(DispatcherEvent::Frame(_)) => {}
            other => panic!("expected multicast Frame, got {:?}", other),
        }
        assert!(matches!(
            unicast.rx.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));
    }

    #[tokio::test]
    async fn fail_all_closes_pending_and_records_error() {
        let d = Dispatcher::new();
        let mut guard = d.register(2);
        d.fail_all("synthetic recv failure".to_string());
        // Channel closed → recv yields None.
        assert!(guard.rx.recv().await.is_none());
        // Pending map cleared.
        assert_eq!(d.pending_count(), 0);
        // The fatal error surfaces with the recorded message.
        let err = d.take_fatal_error();
        assert!(
            err.to_string().contains("synthetic recv failure"),
            "got {err}"
        );
    }

    #[tokio::test]
    async fn take_fatal_error_without_record_is_generic() {
        let d = Dispatcher::new();
        let err = d.take_fatal_error();
        assert!(err.to_string().contains("driver stopped"), "got {err}");
    }

    #[tokio::test]
    async fn concurrent_registrations_are_independent() {
        let d = Dispatcher::new();
        let mut g1 = d.register(10);
        let mut g2 = d.register(20);
        assert_eq!(d.pending_count(), 2);
        d.route_buffer(synth_frame(20));
        d.route_buffer(synth_frame(10));
        assert!(g1.rx.recv().await.is_some(), "seq 10 delivered");
        assert!(g2.rx.recv().await.is_some(), "seq 20 delivered");
    }

    #[tokio::test]
    async fn debug_impl_exposes_active_group_count() {
        let d = Dispatcher::new();
        let _ = d.subscribe_multicast(1);
        let _ = d.subscribe_multicast(2);
        let s = format!("{:?}", d);
        assert!(s.contains("active_groups: 2"), "got {s}");
    }

    // -- Plan 234 §6.3 — ENOBUFS recovery via the socket hook -----

    /// Plan 234 — Connection installs the dispatcher on its
    /// underlying socket; the socket's recv-side ENOBUFS path fans
    /// out via `dispatcher.emit_enobufs()`. Synthetic injection via
    /// `socket.synth_enobufs_for_test()` exercises the routing
    /// without a real overflowing kernel queue.
    #[tokio::test]
    async fn connection_install_propagates_enobufs_to_subscribers() {
        use crate::netlink::{Connection, Route};

        let conn = Connection::<Route>::new().unwrap();
        // The Connection's dispatcher is shared with the socket via
        // install_dispatcher in the constructor.
        let dispatcher = conn.dispatcher();
        let mut rx = dispatcher.subscribe_multicast(1);

        // Sanity check — the socket has the same dispatcher
        // installed.
        let installed = conn
            .socket()
            .dispatcher_for_test()
            .expect("Connection::new must install_dispatcher");
        assert_eq!(installed.active_group_count(), 1);

        // Synthetic ENOBUFS — the recv error path would call this
        // before propagating the error to the caller.
        conn.socket().synth_enobufs_for_test();

        match rx.recv().await {
            Ok(DispatcherEvent::Resync(ResyncMarker::ResyncStart)) => {}
            other => panic!("expected ResyncStart, got {:?}", other),
        }
    }
}
