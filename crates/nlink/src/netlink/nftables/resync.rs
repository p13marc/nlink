//! ENOBUFS-resilient nftables event watching.
//!
//! Wraps [`Connection<Nftables>::events`] / `into_events` with the
//! same resync state machine ENOBUFS-aware consumers must
//! otherwise hand-roll: when the kernel drops events under
//! pressure (`-ENOBUFS`), the typed wrapper transparently
//! re-dumps the current ruleset via a freshly-constructed
//! connection and emits `Resynced(...)` items between
//! [`ResyncMarker::ResyncStart`](crate::netlink::resync::ResyncMarker::ResyncStart)
//! and [`ResyncMarker::ResyncEnd`](crate::netlink::resync::ResyncMarker::ResyncEnd)
//! markers.
//!
//! The shape mirrors `kube_rs::watcher(api, cfg) -> Stream` —
//! `watcher`-style fanout has proven the right primitive for
//! "long-lived self-resyncing watcher" across multiple
//! ecosystems. The key invariant: the resync **must** dump from
//! a freshly-resolved connection so the subscribe socket's
//! pending traffic doesn't race the snapshot read (Plan 178's
//! "subscribe + unicast on one socket" gotcha).
//!
//! # Why a factory closure
//!
//! ENOBUFS can fire at any moment. The wrapper needs to be able
//! to *open a fresh* `Connection<Nftables>` each time it
//! recovers — that's why the user hands in a closure rather than
//! a pre-built second connection. The factory is `Send + Sync +
//! 'static` so the stream is spawnable.
//!
//! # Example — owned, spawn-friendly
//!
//! ```ignore
//! use std::sync::Arc;
//! use nlink::netlink::{Connection, Nftables};
//! use nlink::netlink::resync::{ConnectionFactory, ResyncedEvent, ResyncMarker};
//! use nlink::netlink::nftables::NftablesEvent;
//! use tokio_stream::StreamExt;
//!
//! let factory: ConnectionFactory<Nftables> = Arc::new(|| Box::pin(async {
//!     Connection::<Nftables>::new()
//! }));
//!
//! let mut conn = Connection::<Nftables>::new()?;
//! conn.subscribe_all()?;
//! let mut events = conn.into_events_with_resync(factory);
//!
//! while let Some(item) = events.next().await {
//!     match item? {
//!         ResyncedEvent::Event(NftablesEvent::NewTable(t)) => println!("+t {}", t.name),
//!         ResyncedEvent::Event(NftablesEvent::DelTable(t)) => println!("-t {}", t.name),
//!         ResyncedEvent::Marker(ResyncMarker::ResyncStart) => println!("== resync start =="),
//!         ResyncedEvent::Resynced(ev) => println!("?? snapshot: {ev:?}"),
//!         ResyncedEvent::Marker(ResyncMarker::ResyncEnd) => println!("== resync end =="),
//!         _ => {}
//!     }
//! }
//! # Ok::<(), nlink::Error>(())
//! ```

use std::pin::Pin;

use tokio_stream::Stream;

use super::events::NftablesEvent;
use super::types::Family;
use crate::netlink::protocol::Nftables;
use crate::netlink::resync::{ConnectionFactory, ResyncStream, events_with_resync};
use crate::netlink::stream::{EventSubscription, OwnedEventStream};
use crate::{Connection, Result};

/// Walk the full ruleset on a freshly-opened connection,
/// returning everything as `NewX(...)` events.
///
/// The walk order is: tables → chains → flowtables → sets →
/// rules per table. This matches the order the kernel itself
/// emits when something is created, so consumers replaying
/// snapshot items as "creates" stay consistent with their
/// runtime mutation handler.
///
/// Used internally by the resync wrapper; exposed here so
/// callers building bespoke ENOBUFS handling can reuse it.
pub async fn nftables_snapshot(conn: &Connection<Nftables>) -> Result<Vec<NftablesEvent>> {
    let mut out = Vec::new();

    let tables = conn.list_tables().await?;
    for t in &tables {
        out.push(NftablesEvent::NewTable(t.clone()));
    }

    // chains, flowtables, sets, rules per-table — server-side
    // family filtering is unsound on these dump types (Plan 181
    // finding), so we walk per-table by-name with client-side
    // matching via list_*_in.
    for t in &tables {
        for c in conn.list_chains_in(&t.name, t.family).await? {
            out.push(NftablesEvent::NewChain(c));
        }
        for f in conn.list_flowtables_in(&t.name, t.family).await? {
            out.push(NftablesEvent::NewFlowtable(f));
        }
        for s in conn.list_sets_in(&t.name, t.family).await? {
            out.push(NftablesEvent::NewSet(s));
        }
        // list_rules takes the table name — already family-scoped.
        let _: Family = t.family;
        for r in conn.list_rules(&t.name, t.family).await? {
            out.push(NftablesEvent::NewRule(r));
        }
    }

    Ok(out)
}

/// Boxed snapshot future — what the resync closure produces.
type SnapshotFuture =
    Pin<Box<dyn Future<Output = Result<Vec<NftablesEvent>>> + Send + 'static>>;

/// Boxed snapshot closure — what `events_with_resync` consumes.
type SnapshotFn = Box<dyn FnMut() -> SnapshotFuture + Send + Unpin + 'static>;

/// Build the resync closure passed to [`events_with_resync`].
/// Each invocation opens a fresh `Connection<Nftables>` via the
/// factory + walks the ruleset via [`nftables_snapshot`].
fn make_snapshot_fn(factory: ConnectionFactory<Nftables>) -> SnapshotFn {
    Box::new(move || {
        let factory = factory.clone();
        Box::pin(async move {
            let conn = (factory)().await?;
            nftables_snapshot(&conn).await
        }) as SnapshotFuture
    })
}

/// Resync-wrapped `OwnedEventStream<Nftables>`. Returned by
/// [`Connection::<Nftables>::into_events_with_resync`]. `'static`
/// + `Send` — spawn-friendly with `tokio::spawn`.
pub type OwnedResyncStream =
    ResyncStream<'static, OwnedEventStream<Nftables>, NftablesEvent, SnapshotFn>;

/// Resync-wrapped `EventSubscription<'a, Nftables>`. Returned by
/// [`Connection::<Nftables>::subscribe_all_with_resync`].
/// Borrows the connection for `'a`.
pub type BorrowedResyncStream<'a> =
    ResyncStream<'static, EventSubscription<'a, Nftables>, NftablesEvent, SnapshotFn>;

impl Connection<Nftables> {
    /// Subscribe to every nftables multicast group + return an
    /// ENOBUFS-resilient event stream that **owns** the connection.
    ///
    /// The factory is invoked whenever the kernel drops events
    /// under pressure (`-ENOBUFS`); the wrapper re-dumps the
    /// ruleset via a fresh connection + emits the snapshot as
    /// `Resynced(...)` items between
    /// [`ResyncMarker::ResyncStart`](crate::netlink::resync::ResyncMarker::ResyncStart)
    /// and [`ResyncMarker::ResyncEnd`](crate::netlink::resync::ResyncMarker::ResyncEnd)
    /// markers.
    ///
    /// **Important** — the fresh connection MUST be on the same
    /// netns. Use
    /// [`namespace::connection_for`](crate::netlink::namespace::connection_for)
    /// inside the factory for namespace-aware code; in the host
    /// netns plain `Connection::<Nftables>::new()` is fine.
    ///
    /// Subscribes to `NftablesGroup::All` before returning. Use
    /// [`Self::subscribe_all_with_resync`] if you need to retain
    /// borrowed access to the connection.
    #[tracing::instrument(level = "info", skip_all)]
    pub fn into_events_with_resync(
        mut self,
        factory: ConnectionFactory<Nftables>,
    ) -> Result<OwnedResyncStream> {
        self.subscribe_all()?;
        let stream = self.into_events();
        Ok(events_with_resync(stream, make_snapshot_fn(factory)))
    }

    /// Same as [`Self::into_events_with_resync`] but borrows the
    /// connection so it stays usable for queries.
    ///
    /// Returns a stream that holds `&self` for `'a`. If you need
    /// to spawn the stream onto a tokio task, prefer
    /// [`Self::into_events_with_resync`] (the owned form is
    /// `'static + Send`).
    #[tracing::instrument(level = "info", skip_all)]
    pub fn subscribe_all_with_resync(
        &mut self,
        factory: ConnectionFactory<Nftables>,
    ) -> Result<BorrowedResyncStream<'_>> {
        self.subscribe_all()?;
        let stream = self.events();
        Ok(events_with_resync(stream, make_snapshot_fn(factory)))
    }
}

// Anchor `Stream`-trait users without leaking `tokio_stream` —
// `ResyncStream` implements `Stream`; `OwnedResyncStream` /
// `BorrowedResyncStream` inherit it through the alias.
#[allow(dead_code)]
fn _streams_are_streams() {
    fn assert_stream<S: Stream + ?Sized>() {}
    assert_stream::<OwnedResyncStream>();
    assert_stream::<BorrowedResyncStream<'static>>();
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::netlink::resync::ConnectionFuture;

    #[test]
    fn factory_is_clone_and_send() {
        let factory: ConnectionFactory<Nftables> = Arc::new(|| {
            Box::pin(async { Connection::<Nftables>::new() })
                as Pin<Box<dyn Future<Output = Result<Connection<Nftables>>> + Send + 'static>>
        });
        let _f2 = factory.clone();
        // Doesn't actually open a socket — just exercises the
        // type bounds so a regression caught at compile time.
        fn assert_send_sync<T: Send + Sync>() {}
        fn assert_send<T: Send>() {}
        assert_send_sync::<ConnectionFactory<Nftables>>();
        // ConnectionFuture is `Send` (not `Sync`) — a future
        // held by a single executor doesn't need Sync.
        assert_send::<ConnectionFuture<Nftables>>();
    }
}
