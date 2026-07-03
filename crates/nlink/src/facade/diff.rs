//! One-line diff wrappers. Plan 200 §2.2.
//!
//! Pair with [`super::apply`] — render the diff, decide
//! whether to apply, then commit.
//!
//! Each config type has three shapes (#169): plain (default
//! namespace), `_in_namespace(&str)` (named netns), and the
//! general `_in(NamespaceSpec)` which also covers path- and
//! PID-referenced namespaces (containers).

use crate::netlink::config::{ConfigDiff, NetworkConfig};
use crate::netlink::genl::wireguard::{WireguardConfig, WireguardConfigDiff};
use crate::netlink::namespace::NamespaceSpec;
use crate::netlink::nftables::config::{NftablesConfig, NftablesDiff};
use crate::netlink::{Nftables, Route, Wireguard};
use crate::{Connection, Result};

// =============================================================================
// NetworkConfig — RTNETLINK
// =============================================================================

/// Diff a network config against the host's default
/// namespace.
pub async fn network(cfg: &NetworkConfig) -> Result<ConfigDiff> {
    network_in(NamespaceSpec::Default, cfg).await
}

/// Diff a network config against a named namespace.
pub async fn network_in_namespace(ns: &str, cfg: &NetworkConfig) -> Result<ConfigDiff> {
    network_in(NamespaceSpec::Named(ns), cfg).await
}

/// Diff a network config against any namespace specification
/// (named, path, or PID — container support, #169).
pub async fn network_in(ns: NamespaceSpec<'_>, cfg: &NetworkConfig) -> Result<ConfigDiff> {
    let conn: Connection<Route> = ns.connection()?;
    cfg.diff(&conn).await
}

// =============================================================================
// NftablesConfig
// =============================================================================

/// Diff an nftables config against the host's default
/// namespace.
pub async fn nftables(cfg: &NftablesConfig) -> Result<NftablesDiff> {
    nftables_in(NamespaceSpec::Default, cfg).await
}

/// Diff an nftables config against a named namespace.
pub async fn nftables_in_namespace(ns: &str, cfg: &NftablesConfig) -> Result<NftablesDiff> {
    nftables_in(NamespaceSpec::Named(ns), cfg).await
}

/// Diff an nftables config against any namespace specification
/// (named, path, or PID — container support, #169).
pub async fn nftables_in(ns: NamespaceSpec<'_>, cfg: &NftablesConfig) -> Result<NftablesDiff> {
    let conn: Connection<Nftables> = ns.connection()?;
    cfg.diff(&conn).await
}

// =============================================================================
// WireguardConfig
// =============================================================================

/// Diff a WireGuard config against the host's default
/// namespace.
pub async fn wireguard(cfg: &WireguardConfig) -> Result<WireguardConfigDiff> {
    wireguard_in(NamespaceSpec::Default, cfg).await
}

/// Diff a WireGuard config against a named namespace.
pub async fn wireguard_in_namespace(
    ns: &str,
    cfg: &WireguardConfig,
) -> Result<WireguardConfigDiff> {
    wireguard_in(NamespaceSpec::Named(ns), cfg).await
}

/// Diff a WireGuard config against any namespace specification
/// (named, path, or PID — container support, #169).
pub async fn wireguard_in(
    ns: NamespaceSpec<'_>,
    cfg: &WireguardConfig,
) -> Result<WireguardConfigDiff> {
    let conn: Connection<Wireguard> = ns.connection_async().await?;
    cfg.diff(&conn).await
}
