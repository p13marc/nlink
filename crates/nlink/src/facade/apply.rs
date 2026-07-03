//! One-line apply wrappers. Plan 200 §2.1.
//!
//! Each function opens a fresh `Connection<P>` and calls
//! `cfg.apply(&conn).await`. Use these for the common case;
//! reach for the typed `Connection<P>::new()?.apply(&cfg)`
//! form when you need a pre-existing connection (e.g. one
//! shared across many apply calls).
//!
//! Each config type has three shapes (#169): plain (default
//! namespace), `_in_namespace(&str)` (named netns), and the
//! general `_in(NamespaceSpec)` which also covers path- and
//! PID-referenced namespaces (containers).

use crate::netlink::config::{ApplyResult, NetworkConfig};
use crate::netlink::genl::wireguard::WireguardConfig;
use crate::netlink::namespace::NamespaceSpec;
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
    network_in(NamespaceSpec::Default, cfg).await
}

/// Apply a network config inside a named namespace.
pub async fn network_in_namespace(ns: &str, cfg: &NetworkConfig) -> Result<ApplyResult> {
    network_in(NamespaceSpec::Named(ns), cfg).await
}

/// Apply a network config inside any namespace specification
/// (named, path, or PID — container support, #169).
pub async fn network_in(ns: NamespaceSpec<'_>, cfg: &NetworkConfig) -> Result<ApplyResult> {
    let conn: Connection<Route> = ns.connection()?;
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
    nftables_in(NamespaceSpec::Default, cfg).await
}

/// Apply an nftables config inside a named namespace.
pub async fn nftables_in_namespace(ns: &str, cfg: &NftablesConfig) -> Result<usize> {
    nftables_in(NamespaceSpec::Named(ns), cfg).await
}

/// Apply an nftables config inside any namespace specification
/// (named, path, or PID — container support, #169).
pub async fn nftables_in(ns: NamespaceSpec<'_>, cfg: &NftablesConfig) -> Result<usize> {
    let conn: Connection<Nftables> = ns.connection()?;
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
/// genetlink controller). Missing declared devices are created
/// first via [`WireguardConfig::ensure_devices`] with a Route
/// connection in the same namespace (#169).
pub async fn wireguard(
    cfg: &WireguardConfig,
) -> Result<crate::netlink::genl::wireguard::WireguardApplyResult> {
    wireguard_in(NamespaceSpec::Default, cfg).await
}

/// Apply a WireGuard config inside a named namespace.
pub async fn wireguard_in_namespace(
    ns: &str,
    cfg: &WireguardConfig,
) -> Result<crate::netlink::genl::wireguard::WireguardApplyResult> {
    wireguard_in(NamespaceSpec::Named(ns), cfg).await
}

/// Apply a WireGuard config inside any namespace specification
/// (named, path, or PID — container support, #169).
///
/// Bootstraps missing devices: declared WG links that don't exist
/// are created through a Route connection in the same namespace
/// before the GENL apply, so a bare `WireguardConfig` works
/// end-to-end without a separate `NetworkConfig` layer.
pub async fn wireguard_in(
    ns: NamespaceSpec<'_>,
    cfg: &WireguardConfig,
) -> Result<crate::netlink::genl::wireguard::WireguardApplyResult> {
    let route: Connection<Route> = ns.connection()?;
    cfg.ensure_devices(&route).await?;
    let conn: Connection<Wireguard> = ns.connection_async().await?;
    cfg.apply(&conn).await
}
