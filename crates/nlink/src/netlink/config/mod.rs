//! Declarative network configuration.
//!
//! This module provides a declarative API for specifying desired network state
//! and computing/applying the necessary changes to achieve it.
//!
//! # Overview
//!
//! Instead of imperatively calling `add_link`, `add_address`, etc., you describe
//! the desired state and let the library figure out what changes are needed:
//!
//! ```ignore
//! use nlink::netlink::{Connection, Route};
//! use nlink::netlink::config::NetworkConfig;
//!
//! let conn = Connection::<Route>::new()?;
//!
//! // Define desired state
//! let config = NetworkConfig::new()
//!     .link("br0", |l| l.bridge().up())
//!     .link("veth0", |l| l.veth("veth1").master("br0").up())
//!     .address("br0", "192.168.100.1/24")?
//!     .route("10.0.0.0/8", |r| r.via("192.168.100.254"))?;
//!
//! // Preview changes
//! let diff = config.diff(&conn).await?;
//! println!("{}", diff.summary());
//!
//! // Apply changes
//! config.apply(&conn).await?;
//! ```
//!
//! # Benefits
//!
//! - **Idempotent**: Running the same config multiple times produces the same result
//! - **Diff-based**: Only makes necessary changes
//! - **Ordered**: Applies changes in the correct order (links before addresses, etc.)
//! - **Dry-run**: Preview changes before applying
//!
//! # Supported Resources
//!
//! - Links (interfaces): dummy, veth, bridge, vlan, vxlan, macvlan, bond
//! - Addresses: IPv4 and IPv6
//! - Routes: IPv4 and IPv6, with gateway, device, or multipath
//! - Qdiscs: netem, htb, fq_codel, tbf, etc.

mod apply;
mod diff;
mod types;

pub use apply::{ApplyOptions, ApplyResult};
pub use diff::ConfigDiff;
pub use types::*;

use super::{connection::Connection, error::Result, protocol::Route};

impl NetworkConfig {
    /// Compute the difference between desired and current state.
    ///
    /// This fetches the current network state and compares it against
    /// the desired configuration, returning a diff of what needs to change.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let diff = config.diff(&conn).await?;
    /// if !diff.is_empty() {
    ///     println!("Changes needed:\n{}", diff.summary());
    /// }
    /// ```
    pub async fn diff(&self, conn: &Connection<Route>) -> Result<ConfigDiff> {
        diff::compute_diff(self, conn).await
    }

    /// Apply the configuration to achieve the desired state.
    ///
    /// This computes the diff and applies all necessary changes.
    /// Changes are applied in the correct order:
    /// 1. Create new links
    /// 2. Modify existing links
    /// 3. Add addresses
    /// 4. Add routes
    /// 5. Configure qdiscs
    /// 6. Remove old resources (if purge is enabled)
    ///
    /// # Example
    ///
    /// ```ignore
    /// let result = config.apply(&conn).await?;
    /// println!("Made {} changes", result.changes_made);
    /// ```
    pub async fn apply(&self, conn: &Connection<Route>) -> Result<ApplyResult> {
        self.apply_with_options(conn, ApplyOptions::default()).await
    }

    /// Apply the configuration with custom options.
    ///
    /// # Options
    ///
    /// - `dry_run`: Compute diff but don't make any changes
    /// - `continue_on_error`: Keep going if some operations fail
    /// - `purge`: Remove resources not in the config
    ///
    /// # Example
    ///
    /// ```ignore
    /// // Dry run first
    /// let result = config.apply_with_options(&conn, ApplyOptions {
    ///     dry_run: true,
    ///     ..Default::default()
    /// }).await?;
    /// println!("Would make {} changes", result.changes_made);
    ///
    /// // Then apply for real
    /// config.apply(&conn).await?;
    /// ```
    pub async fn apply_with_options(
        &self,
        conn: &Connection<Route>,
        options: ApplyOptions,
    ) -> Result<ApplyResult> {
        apply::apply_config(self, conn, options).await
    }

    /// Apply the configuration with bounded retry on transient
    /// kernel errors. Mirrors
    /// [`crate::netlink::nftables::config::NftablesDiff::apply_reconcile`].
    ///
    /// Retries on [`crate::Error::is_busy`] / [`crate::Error::is_try_again`]
    /// up to `opts.max_retries` times, with exponential backoff
    /// starting at `opts.backoff` (doubling per attempt, capped
    /// at `backoff × 2^10`).
    ///
    /// For RTNETLINK the transient-error surface is smaller than
    /// nftables (no batch-end races), but VRF table allocation,
    /// neighbor-cache pressure, and similar edges can still
    /// benefit from the retry budget. Plan 187 (`Error::errno()`
    /// Io-shape fix) ensures raw `EBUSY`/`EAGAIN` from the
    /// socket layer is correctly classified.
    ///
    /// Plan 188 §2.4.
    ///
    /// **Note on `ReconcileOptions`**: this method uses
    /// [`crate::netlink::nftables::config::ReconcileOptions`]
    /// (the retry-budget shape), NOT the crate-root
    /// `ReconcileOptions` (which is the TC recipe shape with
    /// `fallback_to_apply` / `dry_run`). The two share a name
    /// for legacy reasons; the apply_reconcile retry surface
    /// uses the nftables shape.
    pub async fn apply_reconcile(
        &self,
        conn: &Connection<Route>,
        opts: crate::netlink::nftables::config::ReconcileOptions,
    ) -> Result<crate::netlink::nftables::config::ReconcileReport> {
        // Plan 207e H4 — recompute the diff at the START of each
        // attempt. Pre-0.19 this loop re-ran the same `apply`
        // against changed kernel state, causing this failure mode:
        //
        //   Attempt 1: link X added OK, address Y add fails with EBUSY
        //              (kernel netlink is_busy() triggers retry)
        //   Attempt 2: re-runs full apply → link X already exists →
        //              add_link fails with EEXIST (NOT is_busy(),
        //              NOT is_try_again()) → reconcile gives up
        //              with EEXIST, masking the original EBUSY.
        //
        // Recomputing the diff per attempt makes the second attempt
        // see "link X already in kernel state, no work needed on the
        // link side; retry only address Y" — which is what users
        // expect from a reconciler.
        //
        // Cumulative `change_count` across attempts is the sum of
        // each successful apply pass. An empty diff at start of an
        // attempt is treated as "done", short-circuiting.
        let mut attempt: usize = 0;
        let mut cumulative_changes: usize = 0;
        loop {
            // Compute fresh diff against current kernel state.
            let diff = self.diff(conn).await?;
            if diff.is_empty() {
                return Ok(crate::netlink::nftables::config::ReconcileReport {
                    attempts: attempt + 1,
                    change_count: cumulative_changes,
                });
            }

            match apply::apply_diff(&diff, conn, apply::ApplyOptions::default()).await {
                Ok(result) => {
                    cumulative_changes += result.changes_made;
                    return Ok(crate::netlink::nftables::config::ReconcileReport {
                        attempts: attempt + 1,
                        change_count: cumulative_changes,
                    });
                }
                Err(e) if (e.is_busy() || e.is_try_again()) && attempt < opts.max_retries => {
                    let backoff = opts.backoff.saturating_mul(1u32 << attempt.min(10));
                    tokio::time::sleep(backoff).await;
                    attempt += 1;
                    continue;
                }
                Err(e) => return Err(e),
            }
        }
    }
}

#[cfg(test)]
mod apply_reconcile_tests {
    //! Plan 188 §2.4 — `NetworkConfig::apply_reconcile`.
    //!
    //! These tests verify the retry classification (the
    //! NftablesConfig precedent's logic mirrored for the
    //! RTNETLINK side). The integration-test side of the
    //! happy path lives in `tests/integration/config.rs`
    //! (root-gated).

    use crate::Error;
    use std::time::Duration;

    #[test]
    fn classify_io_ebusy_as_retryable() {
        // Plan 187 §2.5 fix: Error::errno() unwraps Io via
        // raw_os_error(). is_busy(Io(EBUSY)) must be true,
        // so apply_reconcile would retry instead of bubbling.
        let io_ebusy = Error::Io(std::io::Error::from_raw_os_error(libc::EBUSY));
        assert!(io_ebusy.is_busy(), "Io(EBUSY) must trigger apply_reconcile retry");
        assert!(!io_ebusy.is_no_buffer_space(), "wrong predicate must NOT match");
    }

    #[test]
    fn classify_io_eagain_as_retryable() {
        let io_eagain = Error::Io(std::io::Error::from_raw_os_error(libc::EAGAIN));
        assert!(io_eagain.is_try_again(), "Io(EAGAIN) must trigger apply_reconcile retry");
    }

    #[test]
    fn classify_kernel_einval_as_terminal() {
        // EINVAL is NOT retryable — must propagate.
        let einval = Error::from_errno_ext_ack(libc::EINVAL, None, None);
        assert!(!einval.is_busy());
        assert!(!einval.is_try_again());
        // apply_reconcile would short-circuit on the `Err(e) => return Err(e)`
        // arm.
    }

    #[test]
    fn reconcile_options_default_caps_at_3_retries() {
        use crate::netlink::nftables::config::ReconcileOptions;
        let opts = ReconcileOptions::default();
        assert_eq!(opts.max_retries, 3);
        assert_eq!(opts.backoff, Duration::from_millis(100));
    }
}
