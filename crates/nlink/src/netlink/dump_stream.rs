//! Streaming dump API — yield parsed netlink dump frames one at a
//! time without buffering the full response.
//!
//! See [`Connection::dump_stream`] and the typed wrappers
//! [`Connection::stream_links`], [`Connection::stream_routes`],
//! [`Connection::stream_neighbors`], [`Connection::stream_addresses`].
//!
//! # Why
//!
//! The existing eager dump path (`get_links`, `get_routes` etc.)
//! collects the full kernel response into a `Vec<Vec<u8>>` before
//! the first row is parsed. On a BGP router with 1M routes that's
//! gigabytes of intermediate allocation before the user sees
//! anything. `dump_stream` allocates one per-frame buffer plus the
//! pre-parsed batch backlog — peak memory is bounded by what the
//! kernel writes in one socket read (typically tens of frames).
//!
//! # Design
//!
//! Hand-rolled `Stream` impl (no `async-stream` dep) following the
//! same pattern as the multicast `EventSubscription` in
//! `crate::netlink::stream`. The state machine:
//!
//! 1. `dump_stream(msg_type)` is **async** — it sends the dump
//!    request and returns the stream (the first frame may already
//!    be in the kernel socket buffer; that's fine, the next
//!    `poll_recv` will pick it up).
//! 2. `poll_next` drains any already-parsed messages from the
//!    internal `VecDeque`; when empty, it calls `socket.poll_recv`
//!    for the next batch, parses all messages in the batch
//!    matching the request's sequence number, queues them, and
//!    yields the head.
//! 3. `NLMSG_DONE` flips a `done` flag; subsequent polls return
//!    `Poll::Ready(None)`.
//! 4. `NLMSG_ERROR` is yielded as `Some(Err(...))` then the stream
//!    fuses (further polls return `None`).

use std::{
    collections::VecDeque,
    marker::PhantomData,
    pin::Pin,
    task::{Context, Poll},
};

use tokio_stream::Stream;

use super::{
    builder::MessageBuilder,
    connection::Connection,
    error::Result,
    message::{MessageIter, NLM_F_DUMP, NLM_F_REQUEST, NlMsgError},
    parse::FromNetlink,
    protocol::ProtocolState,
};

/// Streaming dump handle returned by [`Connection::dump_stream`]
/// (and its typed wrappers).
///
/// Implements [`Stream<Item = Result<T>>`][tokio_stream::Stream].
/// Each `next().await` yields one parsed message, or `None` when
/// the kernel signals `NLMSG_DONE`.
///
/// Borrows `&Connection<P>` for its lifetime. Pin via
/// `futures::pin_mut!` or store in `Box::pin` if you need to use
/// it across `await` points held by a struct field.
#[non_exhaustive]
pub struct DumpStream<'a, P: ProtocolState, T: FromNetlink + Unpin> {
    conn: &'a Connection<P>,
    expected_seq: u32,
    pending: VecDeque<Result<T>>,
    done: bool,
    errored: bool,
    /// Plan 233 (0.20.1) — opt-in: skip malformed frames instead of
    /// fusing the stream. Each skip logs at `tracing::warn!`.
    /// Default `false` preserves the snapshot-completeness contract
    /// that dump APIs imply. See
    /// [`Self::with_skip_malformed`].
    skip_malformed: bool,
    /// 0.19 Finding B — hold the Connection's request lock for the
    /// stream's lifetime so concurrent dumps / events on a shared
    /// `Arc<Connection>` don't race on `poll_recv` and steal each
    /// other's frames. Released when the stream is dropped.
    _guard: tokio::sync::OwnedMutexGuard<()>,
    _marker: PhantomData<fn() -> T>,
}

impl<'a, P: ProtocolState, T: FromNetlink + Unpin> DumpStream<'a, P, T> {
    /// Send the dump request and construct a stream ready to yield
    /// frames. Called by `Connection::dump_stream`; not part of the
    /// public API directly.
    pub(crate) async fn send(
        conn: &'a Connection<P>,
        msg_type: u16,
    ) -> Result<Self> {
        let mut header_buf = Vec::new();
        T::write_dump_header(&mut header_buf);
        Self::send_with_body_bytes(conn, msg_type, &header_buf).await
    }

    /// Same as [`send`](Self::send), but the body bytes come from
    /// the caller instead of `T::write_dump_header`. Used for
    /// families whose dump request needs a runtime-parameterized
    /// body — conntrack (`nfgenmsg.family` varies v4/v6/AF_UNSPEC)
    /// or nft rules (nfgenmsg + `NFTA_RULE_TABLE` filter).
    pub(crate) async fn send_with_body(
        conn: &'a Connection<P>,
        msg_type: u16,
        body: &[u8],
    ) -> Result<Self> {
        Self::send_with_body_bytes(conn, msg_type, body).await
    }

    async fn send_with_body_bytes(
        conn: &'a Connection<P>,
        msg_type: u16,
        body: &[u8],
    ) -> Result<Self> {
        // 0.19 Finding B — acquire the request lock BEFORE the send
        // and hold it for the stream's lifetime. Without this, two
        // concurrent DumpStreams on a shared `Arc<Connection>` would
        // both `poll_recv` and steal each other's frames; the
        // seq-filter would silently drop the foreign frames but
        // they'd never reach the right stream's pending queue.
        let guard = conn.lock_request_owned().await;

        let mut builder = MessageBuilder::new(msg_type, NLM_F_REQUEST | NLM_F_DUMP);
        if !body.is_empty() {
            builder.append_bytes(body);
        }

        let socket = conn.socket();
        let seq = socket.next_seq();
        builder.set_seq(seq);
        builder.set_pid(socket.pid());

        let msg = builder.finish();
        socket.send(&msg).await?;

        Ok(Self {
            conn,
            expected_seq: seq,
            pending: VecDeque::new(),
            done: false,
            errored: false,
            skip_malformed: false,
            _guard: guard,
            _marker: PhantomData,
        })
    }

    /// Plan 233 (0.20.1) — continue past malformed frames instead of
    /// fusing the stream. Each skip logs at `tracing::warn!` level
    /// with the parse error.
    ///
    /// Default is hard-fail (the snapshot-completeness contract that
    /// dump APIs imply). Use this when the caller would rather have
    /// a partial dump than no dump at all — e.g. exporting a
    /// best-effort metric to a dashboard.
    ///
    /// # Dump vs event policy
    ///
    /// CLAUDE.md `## Parser robustness` rule 3 (skip + log on
    /// malformed frames) applies to **event** subscribers (`events()`,
    /// `into_events()`, `subscribe_*()`), not dumps. Dump APIs
    /// intentionally fuse on malformed frames because the caller
    /// asked for the full snapshot; silently delivering a partial
    /// one would deliver wrong-data-with-no-error to a reconcile loop
    /// or audit log. This setter is the explicit opt-out for the
    /// best-effort case.
    ///
    /// Event APIs follow rule 3 unconditionally — there is no
    /// matching "fail on first bad event" opt-in because failing a
    /// long-lived multicast stream only widens the event-loss window.
    pub fn with_skip_malformed(mut self, skip: bool) -> Self {
        self.skip_malformed = skip;
        self
    }

    /// Parse `data` into per-message items and push them onto the
    /// pending queue. Sets `done` on `NLMSG_DONE`. Pushes
    /// `Err(...)` and sets `errored` on `NLMSG_ERROR`.
    ///
    /// Plan 233 (0.20.1) — when `skip_malformed` is set, malformed
    /// MessageIter frames and typed-parse failures log at WARN and
    /// continue iteration instead of fusing the stream.
    fn drain_into_pending(&mut self, data: &[u8]) {
        for result in MessageIter::new(data) {
            let (header, payload) = match result {
                Ok(p) => p,
                Err(e) => {
                    if self.skip_malformed {
                        tracing::warn!(
                            error = %e,
                            "DumpStream: skip malformed MessageIter frame (Plan 233 opt-in)"
                        );
                        // Plan 233 — MessageIter consumed the bad
                        // frame internally; continue with the next.
                        continue;
                    }
                    self.pending.push_back(Err(e));
                    self.errored = true;
                    return;
                }
            };

            if header.nlmsg_seq != self.expected_seq {
                continue;
            }

            if header.is_error() {
                match NlMsgError::from_bytes(payload) {
                    Ok(err) => {
                        if err.is_ack() {
                            // Spurious ACK during a dump — skip.
                            continue;
                        }
                        // NLMSG_ERROR is NOT a "malformed frame" —
                        // it's the kernel reporting that the request
                        // itself failed. Always fuse here regardless
                        // of skip_malformed; the caller wants to know
                        // their dump errored at the source.
                        self.pending.push_back(Err(err.into_error(payload)));
                        self.errored = true;
                        return;
                    }
                    Err(e) => {
                        if self.skip_malformed {
                            tracing::warn!(
                                error = %e,
                                "DumpStream: skip malformed NLMSG_ERROR payload (Plan 233 opt-in)"
                            );
                            continue;
                        }
                        self.pending.push_back(Err(e));
                        self.errored = true;
                        return;
                    }
                }
            }

            if header.is_done() {
                self.done = true;
                return;
            }

            // Parse the message payload into T.
            //
            // The payload Iterator gives us the body bytes (after
            // the NlMsgHdr). FromNetlink::from_bytes is the typed
            // parse step. Without Plan 233's opt-in, malformed
            // frames push Err(...) into the queue; the next poll
            // yields the error and (because the stream doesn't fuse
            // on typed-parse errors specifically) iteration
            // continues. With `skip_malformed`, the bad frame logs
            // at WARN and is dropped silently.
            let _ = header; // header is used above for seq/error/done checks
            match T::from_bytes(payload) {
                Ok(item) => self.pending.push_back(Ok(item)),
                Err(e) => {
                    if self.skip_malformed {
                        tracing::warn!(
                            error = %e,
                            "DumpStream: skip malformed typed payload (Plan 233 opt-in)"
                        );
                        continue;
                    }
                    self.pending.push_back(Err(e));
                }
            }
        }
    }
}

impl<P: ProtocolState, T: FromNetlink + Unpin> Stream for DumpStream<'_, P, T> {
    type Item = Result<T>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();

        // Yield buffered items first.
        if let Some(item) = this.pending.pop_front() {
            return Poll::Ready(Some(item));
        }
        if this.done || this.errored {
            return Poll::Ready(None);
        }

        // Drain socket batches until we have a parsed message to
        // yield, or until the socket goes pending.
        //
        // With `syscall_batch` on, one poll_recv_batch returns up
        // to NL_BATCH_SIZE frames in one syscall — drain each into
        // pending and continue. Without the feature, poll_recv
        // gives us one frame per call; drain that and loop.
        loop {
            #[cfg(feature = "syscall_batch")]
            {
                match this
                    .conn
                    .socket()
                    .poll_recv_batch(cx, crate::netlink::socket::NL_BATCH_SIZE)
                {
                    Poll::Ready(Ok(frames)) => {
                        for data in &frames {
                            this.drain_into_pending(data);
                        }
                        if let Some(item) = this.pending.pop_front() {
                            return Poll::Ready(Some(item));
                        }
                        if this.done || this.errored {
                            return Poll::Ready(None);
                        }
                        continue;
                    }
                    Poll::Ready(Err(e)) => {
                        this.errored = true;
                        return Poll::Ready(Some(Err(e)));
                    }
                    Poll::Pending => return Poll::Pending,
                }
            }
            #[cfg(not(feature = "syscall_batch"))]
            {
                match this.conn.socket().poll_recv(cx) {
                    Poll::Ready(Ok(data)) => {
                        this.drain_into_pending(&data);
                        if let Some(item) = this.pending.pop_front() {
                            return Poll::Ready(Some(item));
                        }
                        if this.done || this.errored {
                            return Poll::Ready(None);
                        }
                        continue;
                    }
                    Poll::Ready(Err(e)) => {
                        this.errored = true;
                        return Poll::Ready(Some(Err(e)));
                    }
                    Poll::Pending => return Poll::Pending,
                }
            }
        }
    }
}

impl<P: ProtocolState, T: FromNetlink + Unpin> Unpin for DumpStream<'_, P, T> {}

/// Convenience: build a dump_stream from an arbitrary message type
/// when the typed wrappers don't cover the user's case.
///
/// This is the building block; prefer the typed
/// [`Connection::stream_links`] etc. when they exist.
impl<P: ProtocolState> Connection<P> {
    /// Stream a dump response as it arrives, one typed message per
    /// `next().await`. Terminates on `NLMSG_DONE`.
    ///
    /// Compared to [`Self::dump_typed`], this method does **not**
    /// buffer the full response. On large dumps (BGP-scale route
    /// tables, conntrack tables on a busy gateway) this avoids
    /// materializing gigabytes of intermediate buffers.
    ///
    /// # Cancellation
    ///
    /// Dropping the stream is safe. The kernel terminates the
    /// dump when no more frames are read; any in-flight frames sit
    /// in the kernel socket buffer briefly until they age out. The
    /// next request on this connection has a different sequence
    /// number so stale frames are skipped.
    ///
    /// # Errors
    ///
    /// The stream yields `Err` for per-message parse failures *but
    /// keeps iterating* — kernel sometimes ships partially-parseable
    /// frames in long dumps and dropping them silently would mask
    /// real bugs. `NLMSG_ERROR` and socket-level errors terminate
    /// the stream after yielding the error.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use tokio_stream::StreamExt;
    /// use nlink::{Connection, Route};
    /// use nlink::netlink::messages::LinkMessage;
    /// use nlink::netlink::message::NlMsgType;
    ///
    /// # async fn run() -> nlink::Result<()> {
    /// let conn = Connection::<Route>::new()?;
    /// let mut stream = conn.dump_stream::<LinkMessage>(NlMsgType::RTM_GETLINK).await?;
    /// while let Some(link) = stream.next().await {
    ///     let link = link?;
    ///     println!("{}: {}", link.ifindex(), link.name_or("?"));
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub async fn dump_stream<T>(&self, msg_type: u16) -> Result<DumpStream<'_, P, T>>
    where
        T: FromNetlink + Unpin,
    {
        DumpStream::send(self, msg_type).await
    }

    /// Like [`dump_stream`](Self::dump_stream), but the caller
    /// supplies the body bytes that follow the `nlmsghdr`. Bypasses
    /// `T::write_dump_header` entirely — use this when the dump
    /// request body is runtime-parameterized (e.g.
    /// `nfgenmsg.family` for conntrack, or a fixed body + filter
    /// attribute for nft rules).
    ///
    /// `T` still parses each frame's body via
    /// [`FromNetlink::from_bytes`]; the per-frame body shape is
    /// whatever the kernel emits (independent of the request body).
    pub async fn dump_stream_with_body<T>(
        &self,
        msg_type: u16,
        body: &[u8],
    ) -> Result<DumpStream<'_, P, T>>
    where
        T: FromNetlink + Unpin,
    {
        DumpStream::send_with_body(self, msg_type, body).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::netlink::message::NLMSG_HDRLEN;

    // Verify DumpStream's send/done state machine via a tiny synth
    // test exercising drain_into_pending directly. (Full
    // integration tests need a live socket — covered manually.)

    #[derive(Debug, PartialEq)]
    struct Dummy;

    impl FromNetlink for Dummy {
        fn parse(_input: &mut &[u8]) -> super::super::parse::PResult<Self> {
            Ok(Dummy)
        }
    }

    async fn make_stream<'a>(conn: &'a Connection<crate::netlink::Route>) -> DumpStream<'a, crate::netlink::Route, Dummy> {
        let guard = conn.lock_request_owned().await;
        DumpStream {
            conn,
            expected_seq: 1,
            pending: VecDeque::new(),
            done: false,
            errored: false,
            skip_malformed: false,
            _guard: guard,
            _marker: PhantomData,
        }
    }

    // Build a synthetic NLMSG_DONE frame.
    fn synth_done_frame(seq: u32) -> Vec<u8> {
        let mut buf = vec![0u8; NLMSG_HDRLEN];
        // nlmsg_len = 16 (header only); nlmsg_type = NLMSG_DONE (3);
        // nlmsg_flags = 0; nlmsg_seq = seq; nlmsg_pid = 0.
        buf[0..4].copy_from_slice(&(NLMSG_HDRLEN as u32).to_ne_bytes());
        buf[4..6].copy_from_slice(&3u16.to_ne_bytes()); // NLMSG_DONE
        buf[6..8].copy_from_slice(&0u16.to_ne_bytes());
        buf[8..12].copy_from_slice(&seq.to_ne_bytes());
        buf[12..16].copy_from_slice(&0u32.to_ne_bytes());
        buf
    }

    #[tokio::test]
    async fn drain_recognizes_nlmsg_done() {
        let conn = Connection::<crate::netlink::Route>::new().unwrap();
        let mut stream = make_stream(&conn).await;
        let done = synth_done_frame(1);
        stream.drain_into_pending(&done);
        assert!(stream.done);
        assert!(!stream.errored);
        assert!(stream.pending.is_empty());
    }

    #[tokio::test]
    async fn drain_skips_mismatched_seq() {
        let conn = Connection::<crate::netlink::Route>::new().unwrap();
        let mut stream = make_stream(&conn).await;
        // expected_seq = 1; frame is seq = 42 — should be skipped.
        let other = synth_done_frame(42);
        stream.drain_into_pending(&other);
        assert!(!stream.done);
        assert!(!stream.errored);
        assert!(stream.pending.is_empty());
    }

    // -- Plan 233 (0.20.1) — skip_malformed opt-in -----------------

    /// Per-message payload that only parses for a body of "OK"; any
    /// other body produces a typed parse error. Used to feed
    /// drain_into_pending synthetic malformed frames.
    #[derive(Debug, PartialEq)]
    struct Strict;

    impl FromNetlink for Strict {
        fn parse(_input: &mut &[u8]) -> super::super::parse::PResult<Self> {
            // Always fail — synthesizes a typed-parse error class
            // for tests below. The point of `skip_malformed` is to
            // suppress these.
            use winnow::error::{ContextError, ErrMode};
            Err(ErrMode::Backtrack(ContextError::new()))
        }
    }

    fn synth_data_frame(seq: u32, msg_type: u16, body: &[u8]) -> Vec<u8> {
        let total = NLMSG_HDRLEN + body.len();
        // Round up to 4-byte boundary per NLMSG_ALIGN.
        let padded = (total + 3) & !3;
        let mut buf = vec![0u8; padded];
        buf[0..4].copy_from_slice(&(total as u32).to_ne_bytes());
        buf[4..6].copy_from_slice(&msg_type.to_ne_bytes());
        buf[6..8].copy_from_slice(&0u16.to_ne_bytes());
        buf[8..12].copy_from_slice(&seq.to_ne_bytes());
        buf[12..16].copy_from_slice(&0u32.to_ne_bytes());
        buf[NLMSG_HDRLEN..total].copy_from_slice(body);
        buf
    }

    async fn make_stream_strict<'a>(
        conn: &'a Connection<crate::netlink::Route>,
    ) -> DumpStream<'a, crate::netlink::Route, Strict> {
        let guard = conn.lock_request_owned().await;
        DumpStream {
            conn,
            expected_seq: 1,
            pending: VecDeque::new(),
            done: false,
            errored: false,
            skip_malformed: false,
            _guard: guard,
            _marker: PhantomData,
        }
    }

    /// Plan 233 — default behaviour: typed-parse failures push Err
    /// into pending (the existing pre-Plan-233 contract — does NOT
    /// fuse on typed-parse alone, only on MessageIter / NLMSG_ERROR).
    #[tokio::test]
    async fn plan_233_default_typed_parse_failure_pushes_err_without_fusing() {
        let conn = Connection::<crate::netlink::Route>::new().unwrap();
        let mut stream = make_stream_strict(&conn).await;

        // A valid data frame whose typed parse will fail (Strict
        // always errors).
        let bad = synth_data_frame(1, /* RTM_NEWLINK */ 16, b"x");
        stream.drain_into_pending(&bad);

        // Pre-Plan-233 contract preserved: one Err in pending,
        // stream not fused (errored stays false for typed-parse
        // failures specifically — only NLMSG_ERROR / MessageIter
        // errors fuse).
        assert_eq!(stream.pending.len(), 1);
        assert!(stream.pending.front().unwrap().is_err());
        assert!(!stream.errored);
        assert!(!stream.done);
    }

    /// Plan 233 — skip_malformed = true: typed-parse failures drop
    /// silently (and the pending queue stays empty for that frame).
    #[tokio::test]
    async fn plan_233_skip_malformed_drops_typed_parse_failure() {
        let conn = Connection::<crate::netlink::Route>::new().unwrap();
        let mut stream = make_stream_strict(&conn).await;
        stream.skip_malformed = true;

        let bad = synth_data_frame(1, /* RTM_NEWLINK */ 16, b"x");
        stream.drain_into_pending(&bad);

        assert!(
            stream.pending.is_empty(),
            "skip_malformed should drop typed-parse failures silently"
        );
        assert!(!stream.errored);
        assert!(!stream.done);
    }

    /// Plan 233 — skip_malformed = true still terminates on
    /// NLMSG_DONE (the opt-in suppresses *malformed* frames, not
    /// kernel signaling).
    #[tokio::test]
    async fn plan_233_skip_malformed_still_terminates_on_done() {
        let conn = Connection::<crate::netlink::Route>::new().unwrap();
        let mut stream = make_stream_strict(&conn).await;
        stream.skip_malformed = true;

        let done = synth_done_frame(1);
        stream.drain_into_pending(&done);

        assert!(stream.done, "NLMSG_DONE must terminate even with skip_malformed");
        assert!(stream.pending.is_empty());
    }

    #[tokio::test]
    async fn plan_233_with_skip_malformed_setter_toggles_field() {
        // Builder-style verification — the setter consumes and
        // returns Self with the field flipped.
        let conn = Connection::<crate::netlink::Route>::new().unwrap();
        let stream = make_stream(&conn).await;
        assert!(!stream.skip_malformed, "default is false");
        let stream = stream.with_skip_malformed(true);
        assert!(stream.skip_malformed);
        let stream = stream.with_skip_malformed(false);
        assert!(!stream.skip_malformed);
    }
}
