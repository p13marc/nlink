//! Unified declarative bundle covering RTNETLINK +
//! nftables + WireGuard in one type. Plan 200 §2.4.
//!
//! Lets consumers manage network + firewall + VPN from one
//! type without manually orchestrating per-protocol `apply`
//! calls in the right order. Apply order is the natural
//! dependency direction:
//!
//! 1. **RTNETLINK** (`NetworkConfig`): links, addresses,
//!    routes, qdiscs — everything else references interfaces.
//! 2. **nftables** (`NftablesConfig`): firewall rules can
//!    reference interfaces from step 1.
//! 3. **WireGuard** (`WireguardConfig`): VPN peers route
//!    through links + filter through rules from steps 1 + 2.
//!
//! Each layer is optional; `Stack` skips layers that aren't
//! set, so callers can use Stack as their one-stop
//! orchestrator without needing every layer.
//!
//! `ovpn` is intentionally absent — the kernel ovpn family
//! is bleeding-edge (6.16+) and nlink ships only the link
//! half (Plan 190 §2.3b). The full GENL-side declarative
//! `OvpnConfig` will join the Stack once Plan 197 ships
//! (deferred to a future cycle for kernel-ABI stability —
//! the ovpn UAPI is still maturing).

use crate::netlink::config::{ApplyResult as NetworkApplyResult, ConfigDiff, NetworkConfig};
use crate::netlink::genl::wireguard::{
    WireguardApplyResult, WireguardConfig, WireguardConfigDiff,
};
use crate::netlink::nftables::config::{NftablesConfig, NftablesDiff};
use crate::Result;

use super::{apply, diff};

/// Unified declarative bundle spanning RTNETLINK +
/// nftables + WireGuard. Plan 200 §2.4.
#[derive(Debug, Clone, Default)]
#[must_use = "Stack does nothing unless apply() or diff() is called"]
pub struct Stack {
    pub network: Option<NetworkConfig>,
    pub nftables: Option<NftablesConfig>,
    pub wireguard: Option<WireguardConfig>,
}

impl Stack {
    /// Build an empty Stack.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the RTNETLINK layer.
    pub fn network(mut self, cfg: NetworkConfig) -> Self {
        self.network = Some(cfg);
        self
    }

    /// Set the nftables layer.
    pub fn nftables(mut self, cfg: NftablesConfig) -> Self {
        self.nftables = Some(cfg);
        self
    }

    /// Set the WireGuard layer.
    pub fn wireguard(mut self, cfg: WireguardConfig) -> Self {
        self.wireguard = Some(cfg);
        self
    }

    /// Apply every set layer in dependency order to the
    /// host's default namespace.
    ///
    /// Order: RTNETLINK → nftables → WireGuard.
    ///
    /// **0.19 N7 — pre-flight validation.** Before mutating any
    /// layer, `apply()` calls `self.diff()` to validate every
    /// set layer against current kernel state. If any layer's
    /// diff fails (missing kernel module, invalid config,
    /// permission error, family-resolution failure, missing
    /// namespace, etc.), the whole apply bails BEFORE the first
    /// mutation. This catches the high-value failure modes
    /// that would otherwise leave the host in a partial state.
    ///
    /// **Residual race window.** Diff and apply are not atomic:
    /// a peer disappearing between validation and apply still
    /// leaves partial state. Use
    /// [`NetworkConfig::apply_reconcile`](crate::netlink::config::NetworkConfig::apply_reconcile)
    /// for the network layer if concurrent mutators are a
    /// concern; nftables already uses an atomic single-batch
    /// commit. True rollback would require a Reverse-Diff
    /// abstraction across all layers — out of scope.
    pub async fn apply(&self) -> Result<StackApplyReport> {
        // Pre-flight: validate every layer's diff succeeds
        // before any kernel mutation.
        let _validation = self.diff().await?;

        let mut report = StackApplyReport::default();
        if let Some(cfg) = &self.network {
            report.network = Some(apply::network(cfg).await?);
        }
        if let Some(cfg) = &self.nftables {
            report.nftables_change_count = Some(apply::nftables(cfg).await?);
        }
        if let Some(cfg) = &self.wireguard {
            report.wireguard = Some(apply::wireguard(cfg).await?);
        }
        Ok(report)
    }

    /// Apply every set layer in dependency order to a named
    /// namespace. See [`Self::apply`] for the pre-flight
    /// validation semantics.
    pub async fn apply_in_namespace(&self, ns: &str) -> Result<StackApplyReport> {
        // Pre-flight: same as `apply()`. Validate against the
        // target namespace before any mutation.
        let _validation = self.diff_in_namespace(ns).await?;

        let mut report = StackApplyReport::default();
        if let Some(cfg) = &self.network {
            report.network = Some(apply::network_in_namespace(ns, cfg).await?);
        }
        if let Some(cfg) = &self.nftables {
            report.nftables_change_count = Some(apply::nftables_in_namespace(ns, cfg).await?);
        }
        if let Some(cfg) = &self.wireguard {
            report.wireguard = Some(apply::wireguard_in_namespace(ns, cfg).await?);
        }
        Ok(report)
    }

    /// Diff every set layer against the host's default
    /// namespace.
    pub async fn diff(&self) -> Result<StackDiff> {
        let mut out = StackDiff::default();
        if let Some(cfg) = &self.network {
            out.network = Some(diff::network(cfg).await?);
        }
        if let Some(cfg) = &self.nftables {
            out.nftables = Some(diff::nftables(cfg).await?);
        }
        if let Some(cfg) = &self.wireguard {
            out.wireguard = Some(diff::wireguard(cfg).await?);
        }
        Ok(out)
    }

    /// Diff every set layer against a named namespace.
    pub async fn diff_in_namespace(&self, ns: &str) -> Result<StackDiff> {
        let mut out = StackDiff::default();
        if let Some(cfg) = &self.network {
            out.network = Some(diff::network_in_namespace(ns, cfg).await?);
        }
        if let Some(cfg) = &self.nftables {
            out.nftables = Some(diff::nftables_in_namespace(ns, cfg).await?);
        }
        if let Some(cfg) = &self.wireguard {
            out.wireguard = Some(diff::wireguard_in_namespace(ns, cfg).await?);
        }
        Ok(out)
    }
}

/// Aggregated apply outcome covering every layer.
#[derive(Debug, Default)]
#[must_use = "Inspect per-layer fields to learn what Stack::apply changed"]
pub struct StackApplyReport {
    pub network: Option<NetworkApplyResult>,
    pub nftables_change_count: Option<usize>,
    pub wireguard: Option<WireguardApplyResult>,
}

impl StackApplyReport {
    /// `true` if every set layer reported zero changes.
    pub fn is_noop(&self) -> bool {
        self.network.as_ref().is_none_or(|r| r.changes_made == 0)
            && self.nftables_change_count.is_none_or(|c| c == 0)
            && self.wireguard.as_ref().is_none_or(|r| r.total_writes() == 0)
    }
}

/// Aggregated drift covering every layer.
#[derive(Debug, Default)]
#[must_use = "Diffs do nothing unless inspected or passed to apply()"]
pub struct StackDiff {
    pub network: Option<ConfigDiff>,
    pub nftables: Option<NftablesDiff>,
    pub wireguard: Option<WireguardConfigDiff>,
}

impl StackDiff {
    /// `true` if every set layer reports zero changes.
    pub fn is_empty(&self) -> bool {
        self.network.as_ref().is_none_or(|d| d.is_empty())
            && self.nftables.as_ref().is_none_or(|d| d.is_empty())
            && self.wireguard.as_ref().is_none_or(|d| d.is_empty())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_stack_diff_is_empty_no_op() {
        let s = StackDiff::default();
        assert!(s.is_empty());
    }

    #[test]
    fn empty_stack_apply_is_noop() {
        let r = StackApplyReport::default();
        assert!(r.is_noop());
    }

    #[test]
    fn stack_builder_layers_optional() {
        let s = Stack::new();
        assert!(s.network.is_none());
        assert!(s.nftables.is_none());
        assert!(s.wireguard.is_none());

        let s = s.network(NetworkConfig::new());
        assert!(s.network.is_some());
    }
}
