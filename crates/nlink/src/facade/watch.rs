//! One-line watch wrappers — ENOBUFS-resilient event
//! subscription. Plan 200 §2.3.
//!
//! Each entry point opens a `Connection<P>` + builds the
//! `ConnectionFactory<P>` + returns the resync stream, so
//! callers don't write the same 8-line factory closure
//! every time. For the polling-based WG watcher (which has
//! no native multicast — see Plan 199's kernel research),
//! the wrapper builds a `WireguardWatcher` instead.

use std::sync::Arc;

use crate::netlink::genl::wireguard::{WireguardWatchOptions, WireguardWatcher};
use crate::netlink::namespace;
use crate::netlink::nftables::resync::OwnedResyncStream as NftablesResyncStream;
use crate::netlink::{Nftables, Route, Wireguard};
use crate::netlink::resync::ConnectionFactory;
use crate::netlink::route_resync::OwnedResyncStream as RouteResyncStream;
use crate::{Connection, Result};

// =============================================================================
// RTNETLINK — Plan 191
// =============================================================================

/// Watch RTNETLINK changes in the host's default namespace.
///
/// Returns a `ResyncStream` of `NetworkEvent`s with ENOBUFS
/// recovery built in. The factory closure (which opens a
/// fresh connection on every overflow) is constructed for
/// you.
///
/// 0.19 Finding B — now `async`.
pub async fn route_changes() -> Result<RouteResyncStream> {
    let conn = Connection::<Route>::new()?;
    let factory: ConnectionFactory<Route> =
        Arc::new(|| Box::pin(async { Connection::<Route>::new() }));
    conn.into_events_with_resync(factory).await
}

/// Watch RTNETLINK changes inside a named namespace.
///
/// 0.19 Finding B — now `async`.
pub async fn route_changes_in_namespace(ns: &str) -> Result<RouteResyncStream> {
    let conn = namespace::connection_for::<Route>(ns)?;
    let ns_owned = ns.to_string();
    let factory: ConnectionFactory<Route> = Arc::new(move || {
        let ns = ns_owned.clone();
        Box::pin(async move { namespace::connection_for::<Route>(&ns) })
    });
    conn.into_events_with_resync(factory).await
}

// =============================================================================
// nftables — Plan 185
// =============================================================================

/// Watch nftables ruleset mutations in the host's default
/// namespace.
///
/// 0.19 Finding B — now `async`.
pub async fn nftables_changes() -> Result<NftablesResyncStream> {
    let conn = Connection::<Nftables>::new()?;
    let factory: ConnectionFactory<Nftables> =
        Arc::new(|| Box::pin(async { Connection::<Nftables>::new() }));
    conn.into_events_with_resync(factory).await
}

/// Watch nftables ruleset mutations inside a named namespace.
///
/// 0.19 Finding B — now `async`.
pub async fn nftables_changes_in_namespace(ns: &str) -> Result<NftablesResyncStream> {
    let conn = namespace::connection_for::<Nftables>(ns)?;
    let ns_owned = ns.to_string();
    let factory: ConnectionFactory<Nftables> = Arc::new(move || {
        let ns = ns_owned.clone();
        Box::pin(async move { namespace::connection_for::<Nftables>(&ns) })
    });
    conn.into_events_with_resync(factory).await
}

// =============================================================================
// WireGuard — Plan 199 (polling watcher; kernel has no mcast)
// =============================================================================

/// Build a WireGuard polling watcher for the host's default
/// namespace.
///
/// **WireGuard has no native multicast** — the kernel module
/// declares `n_mcgrps = 0` (verified upstream). Every WG
/// monitoring tool polls; this wrapper opens the GENL
/// connection + returns a [`WireguardWatcher`] you drive via
/// [`WireguardWatcher::next_events`]. See Plan 199's
/// migration-guide section for the kernel-source ground
/// truth + the deferred-multicast patch history.
pub async fn wireguard_changes(opts: WireguardWatchOptions) -> Result<WireguardWatcher> {
    let conn = Connection::<Wireguard>::new_async().await?;
    WireguardWatcher::new(conn, opts)
}

/// Same as [`wireguard_changes`] inside a named namespace.
pub async fn wireguard_changes_in_namespace(
    ns: &str,
    opts: WireguardWatchOptions,
) -> Result<WireguardWatcher> {
    let conn = namespace::connection_for_async::<Wireguard>(ns).await?;
    WireguardWatcher::new(conn, opts)
}
