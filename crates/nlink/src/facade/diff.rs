//! One-line diff wrappers. Plan 200 §2.2.
//!
//! Pair with [`super::apply`] — render the diff, decide
//! whether to apply, then commit.

use crate::netlink::config::{ConfigDiff, NetworkConfig};
use crate::netlink::genl::wireguard::{WireguardConfig, WireguardConfigDiff};
use crate::netlink::namespace;
use crate::netlink::nftables::config::{NftablesConfig, NftablesDiff};
use crate::netlink::{Nftables, Route, Wireguard};
use crate::{Connection, Result};

// =============================================================================
// NetworkConfig — RTNETLINK
// =============================================================================

/// Diff a network config against the host's default
/// namespace.
pub async fn network(cfg: &NetworkConfig) -> Result<ConfigDiff> {
    let conn = Connection::<Route>::new()?;
    cfg.diff(&conn).await
}

/// Diff a network config against a named namespace.
pub async fn network_in_namespace(ns: &str, cfg: &NetworkConfig) -> Result<ConfigDiff> {
    let conn = namespace::connection_for::<Route>(ns)?;
    cfg.diff(&conn).await
}

// =============================================================================
// NftablesConfig
// =============================================================================

/// Diff an nftables config against the host's default
/// namespace.
pub async fn nftables(cfg: &NftablesConfig) -> Result<NftablesDiff> {
    let conn = Connection::<Nftables>::new()?;
    cfg.diff(&conn).await
}

/// Diff an nftables config against a named namespace.
pub async fn nftables_in_namespace(ns: &str, cfg: &NftablesConfig) -> Result<NftablesDiff> {
    let conn = namespace::connection_for::<Nftables>(ns)?;
    cfg.diff(&conn).await
}

// =============================================================================
// WireguardConfig
// =============================================================================

/// Diff a WireGuard config against the host's default
/// namespace.
pub async fn wireguard(cfg: &WireguardConfig) -> Result<WireguardConfigDiff> {
    let conn = Connection::<Wireguard>::new_async().await?;
    cfg.diff(&conn).await
}

/// Diff a WireGuard config against a named namespace.
pub async fn wireguard_in_namespace(
    ns: &str,
    cfg: &WireguardConfig,
) -> Result<WireguardConfigDiff> {
    let conn = namespace::connection_for_async::<Wireguard>(ns).await?;
    cfg.diff(&conn).await
}
