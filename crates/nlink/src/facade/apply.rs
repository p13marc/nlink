//! One-line apply wrappers. Plan 200 §2.1.
//!
//! Each function opens a fresh `Connection<P>` (in the host
//! netns or a named one) and calls `cfg.apply(&conn).await`.
//! Use these for the common case; reach for the typed
//! `Connection<P>::new()?.apply(&cfg)` form when you need a
//! pre-existing connection (e.g. one shared across many
//! apply calls).

use crate::netlink::config::{ApplyResult, NetworkConfig};
use crate::netlink::genl::wireguard::WireguardConfig;
use crate::netlink::namespace;
use crate::netlink::nftables::config::NftablesConfig;
use crate::netlink::{Nftables, Route, Wireguard};
use crate::{Connection, Result};

// =============================================================================
// NetworkConfig — RTNETLINK
// =============================================================================

/// Apply a network config to the host's default namespace.
///
/// ```ignore
/// use nlink::netlink::config::NetworkConfig;
/// let cfg = NetworkConfig::new().link("eth0", |b| b.dummy());
/// nlink::facade::apply::network(&cfg).await?;
/// ```
pub async fn network(cfg: &NetworkConfig) -> Result<ApplyResult> {
    let conn = Connection::<Route>::new()?;
    cfg.apply(&conn).await
}

/// Apply a network config inside a named namespace.
///
/// Equivalent to [`network`] but opens the connection in
/// `ns` via [`namespace::connection_for`].
pub async fn network_in_namespace(ns: &str, cfg: &NetworkConfig) -> Result<ApplyResult> {
    let conn = namespace::connection_for::<Route>(ns)?;
    cfg.apply(&conn).await
}

// =============================================================================
// NftablesConfig
// =============================================================================

/// Apply an nftables config to the host's default namespace.
///
/// ```ignore
/// use nlink::netlink::nftables::config::NftablesConfig;
/// let cfg = NftablesConfig::new().table("filter", Family::Inet, |t| t);
/// nlink::facade::apply::nftables(&cfg).await?;
/// ```
pub async fn nftables(cfg: &NftablesConfig) -> Result<usize> {
    let conn = Connection::<Nftables>::new()?;
    let diff = cfg.diff(&conn).await?;
    diff.apply(&conn).await
}

/// Apply an nftables config inside a named namespace.
pub async fn nftables_in_namespace(ns: &str, cfg: &NftablesConfig) -> Result<usize> {
    let conn = namespace::connection_for::<Nftables>(ns)?;
    let diff = cfg.diff(&conn).await?;
    diff.apply(&conn).await
}

// =============================================================================
// WireguardConfig
// =============================================================================

/// Apply a WireGuard config to the host's default namespace.
///
/// Opens the WG GENL connection via the async resolver
/// (family-ID resolution requires a roundtrip to the kernel
/// genetlink controller).
pub async fn wireguard(
    cfg: &WireguardConfig,
) -> Result<crate::netlink::genl::wireguard::WireguardApplyResult> {
    let conn = Connection::<Wireguard>::new_async().await?;
    cfg.apply(&conn).await
}

/// Apply a WireGuard config inside a named namespace.
pub async fn wireguard_in_namespace(
    ns: &str,
    cfg: &WireguardConfig,
) -> Result<crate::netlink::genl::wireguard::WireguardApplyResult> {
    let conn = namespace::connection_for_async::<Wireguard>(ns).await?;
    cfg.apply(&conn).await
}
