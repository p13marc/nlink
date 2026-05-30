//! Composable combinators on top of [`ResyncStream`] —
//! kube-rs-style stream extensions.
//!
//! Plan 195 ships a small `ResyncStreamExt` trait providing
//! composable adapters mirroring `kube_rs::utils::WatchStreamExt`:
//!
//! - [`ResyncStreamExt::predicate_filter`] — drop consecutive
//!   events whose key matches the previous one. Useful when
//!   the underlying stream re-emits on unrelated changes.
//! - [`ResyncStreamExt::map_event`] — project the inner payload
//!   of `Event(T)` / `Resynced(T)` to a domain-specific type;
//!   `Marker` items pass through unchanged.
//!
//! Both combinators apply uniformly to the nftables (Plan 185)
//! and Route (Plan 191) resync streams — no per-protocol
//! duplication.
//!
//! `default_backoff()` + `StreamBackoff` are deferred to a
//! follow-up commit if a consumer needs in-stream backoff
//! (the resync wrapper handles ENOBUFS internally; most
//! consumers handle restart backoff at the spawn-loop level
//! via `tokio::time::sleep`).
//!
//! Like [`ResyncStream`](super::resync::ResyncStream) itself,
//! the adapters require `Unpin` on the inner stream — a bound
//! that holds for the watcher streams nlink ships today.
//!
//! # Example
//!
//! ```ignore
//! use nlink::netlink::resync_ext::ResyncStreamExt;
//! use tokio_stream::StreamExt;
//!
//! let mut watch = conn
//!     .into_events_with_resync(factory)?
//!     .predicate_filter(|ev| key_of(ev));
//!
//! while let Some(ev) = watch.next().await {
//!     handle(ev?);
//! }
//! ```

use std::pin::Pin;
use std::task::{Context, Poll};

use tokio_stream::Stream;

use super::resync::ResyncedEvent;

/// Extension trait providing composable combinators on top of
/// [`ResyncStream`](super::resync::ResyncStream) and any other
/// `Stream<Item = Result<ResyncedEvent<T>>>` that's also
/// `Unpin`.
///
/// Mirrors the shape of [`kube-rs`' `WatchStreamExt`][kube-watch-stream]:
/// small composable adapters that don't couple filter / map
/// policy to the underlying watcher infrastructure.
///
/// Plan 195.
///
/// [kube-watch-stream]: https://docs.rs/kube-runtime/latest/kube_runtime/utils/trait.WatchStreamExt.html
pub trait ResyncStreamExt<T>:
    Stream<Item = crate::Result<ResyncedEvent<T>>> + Sized + Unpin
{
    /// Drop consecutive `Event(T)` / `Resynced(T)` items whose
    /// key matches the previously-emitted item's key. Markers
    /// pass through unchanged.
    ///
    /// The key function picks the fields that constitute a
    /// "meaningful change". Useful when the underlying stream
    /// re-emits events on unrelated changes (e.g. a neighbor
    /// event on every neighbor-cache update).
    ///
    /// Mirrors `WatchStreamExt::predicate_filter`. Plan 195.
    fn predicate_filter<K, F>(self, key: F) -> PredicateFilter<Self, T, K, F>
    where
        K: PartialEq + Clone,
        F: FnMut(&ResyncedEvent<T>) -> K,
    {
        PredicateFilter::new(self, key)
    }

    /// Map the inner `T` of every `Event(T)` / `Resynced(T)`
    /// item via the closure. `Marker` items pass through
    /// untouched.
    ///
    /// Convenience for consumers projecting the kernel event
    /// payload to a domain-specific type once at the watcher
    /// boundary. Plan 195.
    fn map_event<U, F>(self, f: F) -> MapEvent<Self, T, U, F>
    where
        F: FnMut(T) -> U,
    {
        MapEvent::new(self, f)
    }
}

// Blanket impl over every Stream of the right shape.
impl<S, T> ResyncStreamExt<T> for S where
    S: Stream<Item = crate::Result<ResyncedEvent<T>>> + Unpin
{
}

// =============================================================
// PredicateFilter
// =============================================================

/// Stream adapter that drops `Event(T)` / `Resynced(T)` items
/// whose key matches the previously-emitted item's key.
/// Created via [`ResyncStreamExt::predicate_filter`].
pub struct PredicateFilter<S, T, K, F>
where
    S: Stream<Item = crate::Result<ResyncedEvent<T>>> + Unpin,
    K: PartialEq + Clone,
    F: FnMut(&ResyncedEvent<T>) -> K,
{
    inner: S,
    key_fn: F,
    last_key: Option<K>,
    _phantom: std::marker::PhantomData<T>,
}

impl<S, T, K, F> PredicateFilter<S, T, K, F>
where
    S: Stream<Item = crate::Result<ResyncedEvent<T>>> + Unpin,
    K: PartialEq + Clone,
    F: FnMut(&ResyncedEvent<T>) -> K,
{
    fn new(inner: S, key_fn: F) -> Self {
        Self {
            inner,
            key_fn,
            last_key: None,
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<S, T, K, F> Unpin for PredicateFilter<S, T, K, F>
where
    S: Stream<Item = crate::Result<ResyncedEvent<T>>> + Unpin,
    K: PartialEq + Clone,
    F: FnMut(&ResyncedEvent<T>) -> K,
{
}

impl<S, T, K, F> Stream for PredicateFilter<S, T, K, F>
where
    S: Stream<Item = crate::Result<ResyncedEvent<T>>> + Unpin,
    K: PartialEq + Clone,
    F: FnMut(&ResyncedEvent<T>) -> K,
{
    type Item = crate::Result<ResyncedEvent<T>>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        loop {
            match Pin::new(&mut this.inner).poll_next(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(None) => return Poll::Ready(None),
                Poll::Ready(Some(Err(e))) => return Poll::Ready(Some(Err(e))),
                Poll::Ready(Some(Ok(item))) => {
                    // Markers always pass through — they're
                    // state-machine signals, not delta payloads.
                    if matches!(item, ResyncedEvent::Marker(_)) {
                        return Poll::Ready(Some(Ok(item)));
                    }
                    let key = (this.key_fn)(&item);
                    if this.last_key.as_ref() == Some(&key) {
                        // Duplicate — silently drop, loop for next.
                        continue;
                    }
                    this.last_key = Some(key);
                    return Poll::Ready(Some(Ok(item)));
                }
            }
        }
    }
}

// =============================================================
// MapEvent
// =============================================================

/// Stream adapter that maps the inner `T` of every `Event(T)` /
/// `Resynced(T)` item via a closure. `Marker` items are passed
/// through untouched. Created via [`ResyncStreamExt::map_event`].
pub struct MapEvent<S, T, U, F>
where
    S: Stream<Item = crate::Result<ResyncedEvent<T>>> + Unpin,
    F: FnMut(T) -> U,
{
    inner: S,
    map_fn: F,
    _phantom: std::marker::PhantomData<(T, U)>,
}

impl<S, T, U, F> MapEvent<S, T, U, F>
where
    S: Stream<Item = crate::Result<ResyncedEvent<T>>> + Unpin,
    F: FnMut(T) -> U,
{
    fn new(inner: S, map_fn: F) -> Self {
        Self {
            inner,
            map_fn,
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<S, T, U, F> Unpin for MapEvent<S, T, U, F>
where
    S: Stream<Item = crate::Result<ResyncedEvent<T>>> + Unpin,
    F: FnMut(T) -> U,
{
}

impl<S, T, U, F> Stream for MapEvent<S, T, U, F>
where
    S: Stream<Item = crate::Result<ResyncedEvent<T>>> + Unpin,
    F: FnMut(T) -> U,
{
    type Item = crate::Result<ResyncedEvent<U>>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_next(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Ready(Some(Err(e))) => Poll::Ready(Some(Err(e))),
            Poll::Ready(Some(Ok(item))) => {
                let mapped = match item {
                    ResyncedEvent::Event(t) => ResyncedEvent::Event((this.map_fn)(t)),
                    ResyncedEvent::Resynced(t) => ResyncedEvent::Resynced((this.map_fn)(t)),
                    ResyncedEvent::Marker(m) => ResyncedEvent::Marker(m),
                };
                Poll::Ready(Some(Ok(mapped)))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::netlink::resync::ResyncMarker;
    use tokio_stream::StreamExt;

    fn synth_stream<T: 'static>(
        items: Vec<crate::Result<ResyncedEvent<T>>>,
    ) -> impl Stream<Item = crate::Result<ResyncedEvent<T>>> + Unpin {
        tokio_stream::iter(items)
    }

    #[tokio::test]
    async fn predicate_filter_dedupes_consecutive_equal_keys() {
        let items = vec![
            Ok(ResyncedEvent::Event(("a", 1))),
            Ok(ResyncedEvent::Event(("a", 2))), // same key, drop
            Ok(ResyncedEvent::Event(("b", 1))),
            Ok(ResyncedEvent::Event(("a", 3))), // key changed back
        ];
        let s = synth_stream(items);
        let filtered: Vec<_> = s
            .predicate_filter(|e| match e {
                ResyncedEvent::Event((k, _)) => *k,
                ResyncedEvent::Resynced((k, _)) => *k,
                _ => "",
            })
            .collect()
            .await;
        assert_eq!(filtered.len(), 3, "duplicate ('a', 2) must drop");
    }

    #[tokio::test]
    async fn predicate_filter_passes_markers_unchanged() {
        // Markers are state-machine signals — never deduped,
        // regardless of the surrounding key sequence.
        let items: Vec<crate::Result<ResyncedEvent<&'static str>>> = vec![
            Ok(ResyncedEvent::Event("a")),
            Ok(ResyncedEvent::Marker(ResyncMarker::ResyncStart)),
            Ok(ResyncedEvent::Marker(ResyncMarker::ResyncStart)), // even adjacent markers stay
            Ok(ResyncedEvent::Event("a")), // same key as first, post-marker — still drops
        ];
        let s = synth_stream(items);
        let filtered: Vec<_> = s
            .predicate_filter(|e| match e {
                ResyncedEvent::Event(s) => *s,
                ResyncedEvent::Resynced(s) => *s,
                _ => "",
            })
            .collect()
            .await;
        // First "a" + both markers survive; the trailing "a"
        // (same key as the most-recently-emitted event) drops.
        assert_eq!(filtered.len(), 3);
        assert!(matches!(
            filtered[1].as_ref().unwrap(),
            ResyncedEvent::Marker(ResyncMarker::ResyncStart)
        ));
        assert!(matches!(
            filtered[2].as_ref().unwrap(),
            ResyncedEvent::Marker(ResyncMarker::ResyncStart)
        ));
    }

    #[tokio::test]
    async fn map_event_transforms_event_and_resynced_variants() {
        let items = vec![
            Ok(ResyncedEvent::Event(5_i32)),
            Ok(ResyncedEvent::Resynced(10_i32)),
            Ok(ResyncedEvent::Marker(ResyncMarker::ResyncStart)),
        ];
        let s = synth_stream(items);
        let mapped: Vec<_> = s.map_event(|i: i32| i * 2).collect().await;
        match mapped[0].as_ref().unwrap() {
            ResyncedEvent::Event(v) => assert_eq!(*v, 10),
            other => panic!("expected Event, got {other:?}"),
        }
        match mapped[1].as_ref().unwrap() {
            ResyncedEvent::Resynced(v) => assert_eq!(*v, 20),
            other => panic!("expected Resynced, got {other:?}"),
        }
        assert!(matches!(
            mapped[2].as_ref().unwrap(),
            ResyncedEvent::Marker(ResyncMarker::ResyncStart)
        ));
    }

    #[tokio::test]
    async fn map_event_propagates_errors() {
        let items: Vec<crate::Result<ResyncedEvent<i32>>> = vec![
            Ok(ResyncedEvent::Event(1)),
            Err(crate::Error::InvalidMessage("synth".into())),
        ];
        let s = synth_stream(items);
        let mapped: Vec<_> = s.map_event(|i: i32| i + 100).collect().await;
        assert_eq!(mapped.len(), 2);
        assert!(matches!(
            mapped[0].as_ref().unwrap(),
            ResyncedEvent::Event(101)
        ));
        assert!(mapped[1].is_err());
    }
}
