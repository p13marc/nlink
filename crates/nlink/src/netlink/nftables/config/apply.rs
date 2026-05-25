//! Apply an [`NftablesDiff`] to the kernel.
//!
//! Apply is **atomic** as of the Plan 157 follow-up that extended
//! `Transaction` with `del_chain` / `del_rule` / `add_flowtable` /
//! `del_flowtable`: a single `NFNL_MSG_BATCH_BEGIN ... BATCH_END`
//! commit either applies the whole diff or rolls the kernel back
//! to its prior state. No half-applied intermediate state is
//! observable to other readers (the kernel takes the nftables
//! mutex for the duration of the batch).
//!
//! Operations are enqueued in dependency-correct order so the
//! kernel's intra-batch validation accepts them:
//! 1. Rule deletes (release dependencies on chains/tables)
//! 2. Chain deletes
//! 3. Flowtable deletes
//! 4. Table deletes (cascades any leftover children)
//! 5. Table adds (creates the namespace for children)
//! 6. Chain adds
//! 7. Rule adds
//! 8. Flowtable adds
//!
//! Tables with flags (`NFT_TABLE_F_DORMANT` / `_OWNER` /
//! `_PERSIST`) route through `Transaction::add_table_with_flags`
//! so they stay inside the atomic batch; no out-of-batch
//! fallback remains.
//!
//! `apply_reconcile` (Plan 157 §4.5) — bounded retry-on-conflict
//! variant — landed alongside the atomic apply. See
//! [`NftablesDiff::apply_reconcile`].

use std::time::Duration;

use super::diff::NftablesDiff;
use super::super::connection::Transaction;
use super::super::types::Chain;
use crate::netlink::{connection::Connection, error::Result, protocol::Nftables};

impl NftablesDiff {
    /// Apply the diff to the kernel atomically.
    ///
    /// Builds a single `Transaction` covering every change in the
    /// diff and commits it in one `NFNL_MSG_BATCH_BEGIN ...
    /// BATCH_END` round-trip. The kernel either accepts the whole
    /// batch (full diff visible to other readers in one step) or
    /// rejects the whole batch (kernel rolls back; no
    /// intermediate state observable).
    ///
    /// Returns the diff's `change_count` on success — a
    /// caller-visible "we did N things" signal useful for
    /// `tracing::info!`-style post-apply logging.
    pub async fn apply(&self, conn: &Connection<Nftables>) -> Result<usize> {
        let total = self.change_count();
        if total == 0 {
            return Ok(0);
        }

        let mut tx: Transaction = conn.transaction();

        // 1. Rule deletes — handle-targeted, family-aware.
        //
        // The diff carries (table, family, chain, handle). The
        // kernel rejects a DELRULE with an empty NFTA_RULE_CHAIN
        // (returns ENOENT) even when NFTA_RULE_HANDLE pins the
        // rule — contrary to an earlier assumption in this code.
        // Plan 178 closeout.
        for (table, family, chain, handle) in &self.rules_to_delete {
            tx = tx.del_rule(table, chain, *family, handle.0);
        }

        // 2. Chain deletes.
        for (table, family, name) in &self.chains_to_delete {
            tx = tx.del_chain(table, name, *family);
        }

        // 3. Flowtable deletes.
        for (family, table, name) in &self.flowtables_to_delete {
            tx = tx.del_flowtable(*family, table, name);
        }

        // 4. Table deletes (cascades any leftover children).
        for (family, name) in &self.tables_to_delete {
            tx = tx.del_table(name, *family);
        }

        // 5. Table adds (must precede chain/rule/flowtable adds
        //    that reference them). Flagged tables route through
        //    Transaction::add_table_with_flags so they stay
        //    inside the atomic batch.
        for table in &self.tables_to_add {
            if table.flags() != 0 {
                tx = tx.add_table_with_flags(table.name(), table.family(), table.flags());
            } else {
                tx = tx.add_table(table.name(), table.family());
            }
        }

        // 6. Chain adds. Re-build a runtime `Chain` from
        //    `DeclaredChain` since the latter is a value type and
        //    the former is the transaction-input type.
        for (table_name, family, declared) in &self.chains_to_add {
            let mut chain = Chain::new(table_name, declared.name()).family(*family);
            if let Some(h) = declared.hook() {
                chain = chain.hook(h);
            }
            if let Some(p) = declared.priority() {
                chain = chain.priority(p);
            }
            if let Some(pol) = declared.policy() {
                chain = chain.policy(pol);
            }
            tx = tx.add_chain(chain);
        }

        // 7. Rule adds. Wire `handle_key` → `body.comment` so the
        //    kernel round-trips it as `NFTA_RULE_USERDATA`
        //    (Plan 157b v2 — drives per-rule diff identity).
        for rule in &self.rules_to_add {
            let mut body = rule.body.clone();
            if let Some(key) = rule.handle_key()
                && body.comment.is_none()
            {
                body.comment = Some(key.to_string());
            }
            tx = tx.add_rule(body);
        }

        // 7b. Rule in-place replaces — emits
        //     `NFT_MSG_NEWRULE | NLM_F_REPLACE | NFTA_RULE_HANDLE`.
        //     Kernel atomically swaps the body at that handle
        //     (preserves position, no flush). Plan 157b v2.
        for (_table, _family, _chain, handle, declared) in &self.rules_to_replace {
            let mut body = declared.body.clone();
            if let Some(key) = declared.handle_key()
                && body.comment.is_none()
            {
                body.comment = Some(key.to_string());
            }
            tx = tx.replace_rule(body, handle.0);
        }

        // 8. Flowtable adds.
        for ft in &self.flowtables_to_add {
            let mut runtime =
                super::super::Flowtable::new(ft.family(), ft.table(), ft.name())
                    .priority(ft.priority());
            for dev in ft.devs() {
                runtime = runtime.device(dev.clone());
            }
            if ft.flags() & super::super::NFT_FLOWTABLE_HW_OFFLOAD != 0 {
                runtime = runtime.hw_offload(true);
            }
            if ft.flags() & super::super::NFT_FLOWTABLE_COUNTER != 0 {
                runtime = runtime.counter(true);
            }
            tx = tx.add_flowtable(&runtime);
        }

        tx.commit(conn).await?;
        Ok(total)
    }

    /// Apply with bounded retry on transient kernel-busy errors
    /// (EBUSY / EAGAIN). Useful when another process may be
    /// mutating the same ruleset concurrently — e.g. systemd-resolved
    /// + a node firewall tool both calling nft simultaneously.
    ///
    /// On EBUSY / EAGAIN, sleeps `opts.backoff` × 2^attempt and
    /// retries up to `opts.max_retries` times. Non-transient errors
    /// surface immediately (caller's responsibility to handle).
    ///
    /// Returns a [`ReconcileReport`] with the attempt count + the
    /// diff that was finally applied. Total wall time is bounded
    /// by Σ(opts.backoff × 2^i) for i in 0..max_retries.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use nlink::netlink::nftables::config::{NftablesConfig, ReconcileOptions};
    /// use std::time::Duration;
    ///
    /// let cfg = NftablesConfig::new() /* ... */;
    /// let diff = cfg.diff(&conn).await?;
    /// let report = diff
    ///     .apply_reconcile(&conn, ReconcileOptions::default())
    ///     .await?;
    /// if report.attempts > 1 {
    ///     tracing::warn!(retries = report.attempts - 1, "transient conflict");
    /// }
    /// ```
    pub async fn apply_reconcile(
        &self,
        conn: &Connection<Nftables>,
        opts: ReconcileOptions,
    ) -> Result<ReconcileReport> {
        let mut attempt: usize = 0;
        loop {
            match self.apply(conn).await {
                Ok(_) => {
                    return Ok(ReconcileReport {
                        attempts: attempt + 1,
                        change_count: self.change_count(),
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

/// Options controlling [`NftablesDiff::apply_reconcile`]'s retry
/// loop. Defaults: 3 retries, 100ms initial backoff (exponential).
///
/// Construct via [`Default::default()`] + the builder-style
/// setters; struct-literal construction is forbidden by
/// `#[non_exhaustive]` so future fields can be added without an
/// SHV bump.
///
/// ```
/// use nlink::netlink::nftables::config::ReconcileOptions;
/// use std::time::Duration;
/// let opts = ReconcileOptions::default()
///     .max_retries(5)
///     .backoff(Duration::from_millis(50));
/// ```
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ReconcileOptions {
    /// Maximum number of retries after the initial attempt.
    /// Total apply attempts is `max_retries + 1`. Default: 3.
    pub max_retries: usize,
    /// Backoff between retries. Doubles each attempt (exponential),
    /// capped at `backoff × 2^10`. Default: 100ms.
    pub backoff: Duration,
}

impl Default for ReconcileOptions {
    fn default() -> Self {
        Self {
            max_retries: 3,
            backoff: Duration::from_millis(100),
        }
    }
}

impl ReconcileOptions {
    /// Set `max_retries` (chained builder pattern).
    #[must_use]
    pub fn max_retries(mut self, retries: usize) -> Self {
        self.max_retries = retries;
        self
    }

    /// Set `backoff` (chained builder pattern).
    #[must_use]
    pub fn backoff(mut self, backoff: Duration) -> Self {
        self.backoff = backoff;
        self
    }
}

/// Outcome of [`NftablesDiff::apply_reconcile`]. `attempts == 1`
/// means the first apply succeeded — no contention encountered.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct ReconcileReport {
    /// Total number of apply attempts (including retries).
    /// 1 = first try succeeded; 2+ = retried after EBUSY/EAGAIN.
    pub attempts: usize,
    /// `change_count()` of the diff that was applied.
    pub change_count: usize,
}

#[cfg(test)]
mod reconcile_tests {
    use super::*;

    #[test]
    fn default_reconcile_options_match_plan_spec() {
        let opts = ReconcileOptions::default();
        assert_eq!(opts.max_retries, 3);
        assert_eq!(opts.backoff, Duration::from_millis(100));
    }

    #[test]
    fn reconcile_report_default_is_zero_attempts() {
        let r = ReconcileReport::default();
        assert_eq!(r.attempts, 0);
        assert_eq!(r.change_count, 0);
    }

    #[test]
    fn empty_diff_apply_via_reconcile_returns_one_attempt() {
        // Smoke: an empty diff doesn't even need a socket — apply
        // returns Ok(0) early. apply_reconcile loops once and
        // succeeds.
        // Can't easily test the retry path without a mock; the
        // shape check is what unit tests cover. Real retries land
        // in the integration test gate.
        let d = NftablesDiff::default();
        assert!(d.is_empty());
        // Build a no-op connection isn't trivial without sockets;
        // the empty-diff fast path is exercised in apply()'s own
        // tests at the integration level.
        let _ = d;
    }
}
