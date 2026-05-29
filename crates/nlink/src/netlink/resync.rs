//! ENOBUFS-resync helper types.
//!
//! When a multicast subscriber falls behind the kernel's event
//! production rate, the kernel drops events and returns `ENOBUFS`
//! on the next `recvmsg`. The subscriber's view of state is now
//! incomplete. The correct recovery (per kernel maintainers'
//! guidance) is:
//!
//! 1. Re-dump current state via the matching `get_*` method.
//! 2. Resume the multicast stream from where the read left off.
//!
//! Downstream consumers of this pattern keep reinventing it, often
//! badly (the well-known
//! [Cilium issue #40280](https://github.com/cilium/cilium/issues/40280)
//! is the same gap in Go). This module ships the **types** that
//! make the pattern explicit:
//!
//! - [`ResyncedEvent<T>`] — sum type yielded by a resync-aware
//!   consumer: `Event(T)` for normal events, `Resynced(T)` for
//!   replayed items, `Marker(...)` for state-machine boundaries.
//! - [`ResyncMarker`] — `ResyncStart` and `ResyncEnd` boundaries
//!   so consumers can coordinate state-rebuild logic with the
//!   replay window.
//!
//! See `docs/recipes/events-with-resync.md` for the canonical
//! event-loop pattern using these types. The [`events_with_resync`]
//! Stream wrapper (Plan 151 §4.2 — landed in 0.16 after design
//! soak) drives the state machine internally so the consumer
//! just `next().await`s `ResyncedEvent<T>` items.
//!
//! # Example loop
//!
//! ```ignore
//! use nlink::netlink::resync::{ResyncedEvent, ResyncMarker};
//! use tokio_stream::StreamExt;
//!
//! # async fn run(
//! #     mut events: nlink::netlink::stream::EventSubscription<'_, nlink::Route>,
//! #     dump_conn: &nlink::Connection<nlink::Route>,
//! #     mut handle: impl FnMut(ResyncedEvent<nlink::netlink::messages::LinkMessage>),
//! # ) -> nlink::Result<()> {
//! while let Some(item) = events.next().await {
//!     match item {
//!         Ok(ev) => handle(ResyncedEvent::Event(ev)),
//!         Err(e) if e.is_no_buffer_space() => {
//!             handle(ResyncedEvent::Marker(ResyncMarker::ResyncStart));
//!             for link in dump_conn.get_links().await? {
//!                 handle(ResyncedEvent::Resynced(link));
//!             }
//!             handle(ResyncedEvent::Marker(ResyncMarker::ResyncEnd));
//!         }
//!         Err(other) => return Err(other),
//!     }
//! }
//! # Ok(())
//! # }
//! ```

/// Boundary markers emitted around a resync window so consumers
/// can coordinate state-rebuild logic with the replay.
///
/// `ResyncStart` is the cue to invalidate any incremental state
/// the consumer has been accumulating from `Event(T)`s (it's now
/// stale).
///
/// `ResyncEnd` is the cue that the replay is complete — the
/// consumer's state now reflects current kernel state, and
/// subsequent `Event(T)`s are real-time deltas again.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ResyncMarker {
    /// Resync is starting. The next items will be
    /// [`ResyncedEvent::Resynced`] until [`Self::ResyncEnd`].
    ResyncStart,
    /// Resync is complete. Subsequent items resume as
    /// [`ResyncedEvent::Event`].
    ResyncEnd,
}

/// A stream item produced by a resync-aware event consumer.
///
/// Distinguishes multicast event deltas (`Event`) from
/// post-overflow state replay (`Resynced`), with explicit
/// boundary markers so the consumer's state-rebuild logic can
/// trigger at the right moment.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ResyncedEvent<T> {
    /// A real-time multicast event from the kernel.
    Event(T),
    /// A state-snapshot item from the post-`ENOBUFS` redump.
    Resynced(T),
    /// A boundary marker. See [`ResyncMarker`].
    Marker(ResyncMarker),
}

impl<T> ResyncedEvent<T> {
    /// Convenience: is this a `Marker(ResyncStart)`?
    pub fn is_resync_start(&self) -> bool {
        matches!(self, Self::Marker(ResyncMarker::ResyncStart))
    }

    /// Convenience: is this a `Marker(ResyncEnd)`?
    pub fn is_resync_end(&self) -> bool {
        matches!(self, Self::Marker(ResyncMarker::ResyncEnd))
    }

    /// Extract the inner `T`, regardless of whether it arrived as
    /// a real-time event or a replay item. Returns `None` for
    /// marker variants (callers usually want to handle markers
    /// separately).
    pub fn into_inner(self) -> Option<T> {
        match self {
            Self::Event(t) | Self::Resynced(t) => Some(t),
            Self::Marker(_) => None,
        }
    }

    /// Borrow the inner `T`. `None` for markers.
    pub fn as_inner(&self) -> Option<&T> {
        match self {
            Self::Event(t) | Self::Resynced(t) => Some(t),
            Self::Marker(_) => None,
        }
    }
}

// ============================================================
// Plan 151 §4.2 — `events_with_resync` Stream wrapper
// ============================================================

use std::collections::VecDeque;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use tokio_stream::Stream;

// ============================================================
// ConnectionFactory<P> — generic factory for opening fresh
// `Connection<P>` during ENOBUFS recovery. Used by protocol-
// specific resync wrappers (e.g. nftables) so the consumer
// can carry netns context / extra setup into every retry.
// ============================================================

/// Boxed future producing a fresh `Connection<P>`. Defaults to
/// `'static` so the resulting stream is spawn-friendly.
///
/// This is the building block for [`ConnectionFactory<P>`].
pub type ConnectionFuture<P> =
    Pin<Box<dyn Future<Output = crate::Result<crate::Connection<P>>> + Send + 'static>>;

/// User-supplied closure that opens a fresh `Connection<P>` each
/// time a resync wrapper needs to re-dump after an `ENOBUFS`.
///
/// Mirrors the `kube_rs::watcher(api, cfg)` pattern: the wrapper
/// captures the factory, clones it across resync invocations, and
/// invokes it to materialise a clean unicast connection (Plan
/// 178's "subscribe + unicast on one socket" race makes this the
/// only correct shape).
///
/// `Arc`-wrapped so it's cheap to clone across `poll_next` calls.
/// Most callers wrap a plain closure in `Arc::new(...)`:
///
/// ```ignore
/// use std::sync::Arc;
/// use nlink::netlink::{Connection, Nftables};
/// use nlink::netlink::resync::ConnectionFactory;
///
/// let factory: ConnectionFactory<Nftables> = Arc::new(|| {
///     Box::pin(async { Connection::<Nftables>::new() })
/// });
/// ```
///
/// Namespace-aware code substitutes
/// [`namespace::connection_for`](crate::netlink::namespace::connection_for)
/// (or `_async` for GENL families) inside the closure.
pub type ConnectionFactory<P> =
    Arc<dyn Fn() -> ConnectionFuture<P> + Send + Sync + 'static>;

/// Internal state-machine state for [`ResyncStream`].
///
/// The `'a` lifetime threads through to the boxed snapshot
/// future. Plan 185 (0.18) made `events_with_resync`
/// lifetime-generic so the snapshot closure can borrow from
/// its environment — required for the borrowed-stream
/// `Connection<P>::subscribe_all_with_resync(&mut self, ...)`
/// shape. Closures that produce `'static` futures (the prior
/// shape) still satisfy `'static: 'a` for any `'a`, so they
/// keep compiling unchanged.
enum ResyncState<'a, T> {
    /// Pulling items from the inner event stream; each item is
    /// yielded as `Event(T)` or — on ENOBUFS — kicks the state
    /// machine into `RunningSnapshot`.
    Forwarding,
    /// Snapshot future is being driven. When it resolves, we
    /// flush `Marker(ResyncStart)` + each item as `Resynced(t)` +
    /// `Marker(ResyncEnd)` via the `Replaying` state.
    RunningSnapshot(Pin<Box<dyn Future<Output = crate::Result<Vec<T>>> + Send + 'a>>),
    /// Snapshot resolved; draining the queue of yet-to-emit items.
    /// `did_emit_start` flips true after the leading marker is
    /// yielded; the trailing marker is yielded when the queue
    /// empties.
    Replaying {
        items: VecDeque<T>,
        did_emit_start: bool,
    },
    /// Stream fused after a non-recoverable error.
    Done,
    /// Phantom variant to express the `'a` parameter even when
    /// no live state holds an `'a`-bound future.
    #[doc(hidden)]
    _Phantom(std::marker::PhantomData<&'a ()>),
}

/// Stream wrapper around an inner event stream that handles
/// `ENOBUFS` (multicast overflow) transparently — yields
/// [`ResyncedEvent<T>`] items, automatically running the
/// caller-supplied snapshot closure when the kernel reports a
/// dropped-events condition.
///
/// Construct via [`events_with_resync`]. Implements
/// [`Stream<Item = Result<ResyncedEvent<T>>>`][Stream].
///
/// The state machine emitted on each ENOBUFS recovery:
///
/// 1. `Ok(Marker(ResyncMarker::ResyncStart))` — cue to invalidate
///    incremental state.
/// 2. `Ok(Resynced(item))` for each item the snapshot returned.
/// 3. `Ok(Marker(ResyncMarker::ResyncEnd))` — cue that the replay
///    is complete.
/// 4. Resume `Ok(Event(item))` for subsequent live deltas.
///
/// Non-ENOBUFS errors propagate as `Err(e)` and fuse the stream
/// (subsequent polls return `None`). The closure's own errors
/// (e.g. snapshot failed) also propagate + fuse.
#[must_use = "streams do nothing unless polled"]
#[non_exhaustive]
pub struct ResyncStream<'a, S, T, F>
where
    S: Stream<Item = crate::Result<T>>,
    F: FnMut() -> Pin<Box<dyn Future<Output = crate::Result<Vec<T>>> + Send + 'a>>,
{
    inner: S,
    resync: F,
    state: ResyncState<'a, T>,
}

impl<'a, S, T, F> Stream for ResyncStream<'a, S, T, F>
where
    S: Stream<Item = crate::Result<T>> + Unpin,
    F: FnMut() -> Pin<Box<dyn Future<Output = crate::Result<Vec<T>>> + Send + 'a>> + Unpin,
    T: Unpin,
{
    type Item = crate::Result<ResyncedEvent<T>>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        loop {
            // Take the state out so we can match-and-replace
            // without borrow-checker friction.
            let state = std::mem::replace(&mut this.state, ResyncState::Done);
            match state {
                ResyncState::Done => return Poll::Ready(None),
                // Phantom variant — never constructed; the
                // outer enum carries it only to anchor the `'a`
                // parameter. If we ever land here, treat as
                // fused.
                ResyncState::_Phantom(_) => return Poll::Ready(None),

                ResyncState::Forwarding => {
                    match Pin::new(&mut this.inner).poll_next(cx) {
                        Poll::Ready(Some(Ok(item))) => {
                            this.state = ResyncState::Forwarding;
                            return Poll::Ready(Some(Ok(ResyncedEvent::Event(item))));
                        }
                        Poll::Ready(Some(Err(e))) if e.is_no_buffer_space() => {
                            // ENOBUFS — kick off snapshot.
                            let fut = (this.resync)();
                            this.state = ResyncState::RunningSnapshot(fut);
                            // Loop around to drive the future.
                        }
                        Poll::Ready(Some(Err(e))) => {
                            this.state = ResyncState::Done;
                            return Poll::Ready(Some(Err(e)));
                        }
                        Poll::Ready(None) => {
                            this.state = ResyncState::Done;
                            return Poll::Ready(None);
                        }
                        Poll::Pending => {
                            this.state = ResyncState::Forwarding;
                            return Poll::Pending;
                        }
                    }
                }

                ResyncState::RunningSnapshot(mut fut) => {
                    match fut.as_mut().poll(cx) {
                        Poll::Ready(Ok(items)) => {
                            // Flush start marker, then drain.
                            this.state = ResyncState::Replaying {
                                items: items.into(),
                                did_emit_start: false,
                            };
                            // Loop to emit the start marker.
                        }
                        Poll::Ready(Err(e)) => {
                            // Snapshot failed — fuse.
                            this.state = ResyncState::Done;
                            return Poll::Ready(Some(Err(e)));
                        }
                        Poll::Pending => {
                            this.state = ResyncState::RunningSnapshot(fut);
                            return Poll::Pending;
                        }
                    }
                }

                ResyncState::Replaying {
                    mut items,
                    did_emit_start,
                } => {
                    if !did_emit_start {
                        this.state = ResyncState::Replaying {
                            items,
                            did_emit_start: true,
                        };
                        return Poll::Ready(Some(Ok(ResyncedEvent::Marker(
                            ResyncMarker::ResyncStart,
                        ))));
                    }
                    if let Some(item) = items.pop_front() {
                        this.state = ResyncState::Replaying {
                            items,
                            did_emit_start: true,
                        };
                        return Poll::Ready(Some(Ok(ResyncedEvent::Resynced(item))));
                    }
                    // Queue empty — emit end marker, return to Forwarding.
                    this.state = ResyncState::Forwarding;
                    return Poll::Ready(Some(Ok(ResyncedEvent::Marker(
                        ResyncMarker::ResyncEnd,
                    ))));
                }
            }
        }
    }
}

/// Wrap an event stream so ENOBUFS overflows trigger an
/// automatic snapshot + boundary-marker replay. Returns a
/// [`ResyncStream`] yielding [`ResyncedEvent<T>`] items.
///
/// The `resync` closure is invoked each time the inner stream
/// reports `ENOBUFS`. It returns a future yielding the snapshot
/// items (typically by calling the matching `get_*` method on a
/// fresh connection). Wrap the async body in `Box::pin(...)` so
/// the future is `Pin<Box<dyn Future + Send>>`.
///
/// ```ignore
/// use nlink::{Connection, Route};
/// use nlink::netlink::resync::{events_with_resync, ResyncedEvent};
/// use tokio_stream::StreamExt;
///
/// let mut events_conn = Connection::<Route>::new()?;
/// events_conn.subscribe(&[/* groups */])?;
/// let raw_events = events_conn.events();
///
/// // dump_conn is a separate connection so the resync dump
/// // doesn't interleave with the live events on the same socket.
/// let dump_conn = Connection::<Route>::new()?;
///
/// let mut stream = events_with_resync(raw_events, move || {
///     let conn = dump_conn.clone();
///     Box::pin(async move { conn.get_links().await })
/// });
///
/// while let Some(item) = stream.next().await {
///     match item? {
///         ResyncedEvent::Event(ev) => { /* live delta */ }
///         ResyncedEvent::Marker(ResyncMarker::ResyncStart) => {
///             /* invalidate incremental state */
///         }
///         ResyncedEvent::Resynced(item) => { /* replay item */ }
///         ResyncedEvent::Marker(ResyncMarker::ResyncEnd) => {
///             /* state is fully rebuilt; resume normal processing */
///         }
///     }
/// }
/// ```
pub fn events_with_resync<'a, S, T, F>(
    events: S,
    resync: F,
) -> ResyncStream<'a, S, T, F>
where
    S: Stream<Item = crate::Result<T>> + Unpin,
    F: FnMut() -> Pin<Box<dyn Future<Output = crate::Result<Vec<T>>> + Send + 'a>> + Unpin,
    T: Unpin,
{
    ResyncStream {
        inner: events,
        resync,
        state: ResyncState::Forwarding,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn marker_predicates() {
        let start: ResyncedEvent<u32> = ResyncedEvent::Marker(ResyncMarker::ResyncStart);
        let end: ResyncedEvent<u32> = ResyncedEvent::Marker(ResyncMarker::ResyncEnd);
        let event = ResyncedEvent::Event(42u32);
        let resynced = ResyncedEvent::Resynced(7u32);

        assert!(start.is_resync_start());
        assert!(!start.is_resync_end());
        assert!(end.is_resync_end());
        assert!(!end.is_resync_start());
        assert!(!event.is_resync_start());
        assert!(!resynced.is_resync_end());
    }

    #[test]
    fn inner_extraction_skips_markers() {
        let start: ResyncedEvent<u32> = ResyncedEvent::Marker(ResyncMarker::ResyncStart);
        let event = ResyncedEvent::Event(42u32);
        let resynced = ResyncedEvent::Resynced(7u32);

        assert_eq!(start.clone().into_inner(), None);
        assert_eq!(event.clone().into_inner(), Some(42));
        assert_eq!(resynced.clone().into_inner(), Some(7));

        assert_eq!(start.as_inner(), None);
        assert_eq!(event.as_inner(), Some(&42));
        assert_eq!(resynced.as_inner(), Some(&7));
    }

    // ---- Plan 151 §4.2 — `events_with_resync` Stream wrapper ----

    use tokio_stream::StreamExt;

    /// Synthetic event stream — yields a scripted sequence of
    /// `Result<u32>` items so we can drive the state machine
    /// through every branch without a kernel.
    struct ScriptedStream {
        items: VecDeque<crate::Result<u32>>,
    }

    impl Stream for ScriptedStream {
        type Item = crate::Result<u32>;
        fn poll_next(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Option<Self::Item>> {
            Poll::Ready(self.items.pop_front())
        }
    }

    fn enobufs() -> crate::Error {
        crate::Error::from_errno(-libc::ENOBUFS)
    }

    #[tokio::test]
    async fn resync_stream_passes_events_through() {
        let s = ScriptedStream {
            items: vec![Ok(1u32), Ok(2), Ok(3)].into(),
        };
        let mut stream = events_with_resync(s, || {
            Box::pin(async move { Ok::<Vec<u32>, crate::Error>(vec![]) })
        });
        let mut got = Vec::new();
        while let Some(item) = stream.next().await {
            got.push(item.unwrap());
        }
        assert_eq!(got.len(), 3);
        assert!(matches!(got[0], ResyncedEvent::Event(1)));
        assert!(matches!(got[1], ResyncedEvent::Event(2)));
        assert!(matches!(got[2], ResyncedEvent::Event(3)));
    }

    #[tokio::test]
    async fn resync_stream_handles_enobufs_with_replay() {
        let s = ScriptedStream {
            items: vec![Ok(1u32), Err(enobufs()), Ok(99)].into(),
        };
        let mut stream = events_with_resync(s, || {
            Box::pin(async move { Ok::<Vec<u32>, crate::Error>(vec![10, 20, 30]) })
        });
        let mut got = Vec::new();
        while let Some(item) = stream.next().await {
            got.push(item.unwrap());
        }
        // Expected:
        //   Event(1)
        //   Marker(ResyncStart)
        //   Resynced(10) Resynced(20) Resynced(30)
        //   Marker(ResyncEnd)
        //   Event(99)
        assert_eq!(got.len(), 7);
        assert!(matches!(got[0], ResyncedEvent::Event(1)));
        assert!(got[1].is_resync_start());
        assert!(matches!(got[2], ResyncedEvent::Resynced(10)));
        assert!(matches!(got[3], ResyncedEvent::Resynced(20)));
        assert!(matches!(got[4], ResyncedEvent::Resynced(30)));
        assert!(got[5].is_resync_end());
        assert!(matches!(got[6], ResyncedEvent::Event(99)));
    }

    #[tokio::test]
    async fn resync_stream_replay_with_empty_snapshot_still_emits_markers() {
        let s = ScriptedStream {
            items: vec![Err(enobufs()), Ok(1u32)].into(),
        };
        let mut stream = events_with_resync(s, || {
            Box::pin(async move { Ok::<Vec<u32>, crate::Error>(vec![]) })
        });
        let mut got = Vec::new();
        while let Some(item) = stream.next().await {
            got.push(item.unwrap());
        }
        // Even with empty snapshot, both markers must fire so the
        // consumer can rebuild its state-machine boundary.
        assert_eq!(got.len(), 3);
        assert!(got[0].is_resync_start());
        assert!(got[1].is_resync_end());
        assert!(matches!(got[2], ResyncedEvent::Event(1)));
    }

    #[tokio::test]
    async fn resync_stream_propagates_non_enobufs_error_and_fuses() {
        let s = ScriptedStream {
            items: vec![
                Ok(1u32),
                Err(crate::Error::from_errno(-libc::EPERM)),
                Ok(99), // should NOT be yielded
            ]
            .into(),
        };
        let mut stream = events_with_resync(s, || {
            Box::pin(async move { Ok::<Vec<u32>, crate::Error>(vec![]) })
        });
        let mut results = Vec::new();
        while let Some(item) = stream.next().await {
            results.push(item);
        }
        // Expected:
        //   Ok(Event(1))
        //   Err(EPERM)
        //   None (fused)
        assert_eq!(results.len(), 2);
        assert!(matches!(results[0].as_ref().unwrap(), ResyncedEvent::Event(1)));
        assert!(results[1].as_ref().unwrap_err().is_permission_denied());
    }

    #[tokio::test]
    async fn resync_stream_propagates_snapshot_failure_and_fuses() {
        let s = ScriptedStream {
            items: vec![Err(enobufs())].into(),
        };
        let mut stream = events_with_resync(s, || {
            Box::pin(async move {
                Err::<Vec<u32>, crate::Error>(crate::Error::from_errno(-libc::ENODEV))
            })
        });
        let mut results = Vec::new();
        while let Some(item) = stream.next().await {
            results.push(item);
        }
        // Snapshot failed → fuse with the snapshot's error.
        assert_eq!(results.len(), 1);
        assert!(results[0].as_ref().unwrap_err().errno() == Some(libc::ENODEV));
    }

    #[tokio::test]
    async fn resync_stream_handles_multiple_enobufs_recoveries() {
        let s = ScriptedStream {
            items: vec![
                Ok(1u32),
                Err(enobufs()),
                Ok(2),
                Err(enobufs()),
                Ok(3),
            ]
            .into(),
        };
        let mut call_count = 0;
        let mut stream = events_with_resync(s, move || {
            call_count += 1;
            let count = call_count;
            Box::pin(async move { Ok::<Vec<u32>, crate::Error>(vec![count * 100]) })
        });
        let mut got = Vec::new();
        while let Some(item) = stream.next().await {
            got.push(item.unwrap());
        }
        // Expected:
        //   Event(1)
        //   Start, Resynced(100), End  (first recovery)
        //   Event(2)
        //   Start, Resynced(200), End  (second recovery)
        //   Event(3)
        assert_eq!(got.len(), 9);
        assert!(matches!(got[0], ResyncedEvent::Event(1)));
        assert!(got[1].is_resync_start());
        assert!(matches!(got[2], ResyncedEvent::Resynced(100)));
        assert!(got[3].is_resync_end());
        assert!(matches!(got[4], ResyncedEvent::Event(2)));
        assert!(got[5].is_resync_start());
        assert!(matches!(got[6], ResyncedEvent::Resynced(200)));
        assert!(got[7].is_resync_end());
        assert!(matches!(got[8], ResyncedEvent::Event(3)));
    }
}
