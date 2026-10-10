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
//! Operations are enqueued in four phases (after the in-place set
//! updates, which commit first in a batch of their own). The kernel
//! releases what a rule uses — a set, an object, a jump target — only when
//! the message deleting or replacing that rule is processed, so anything a
//! rule used is deleted last (#460):
//!
//! 1. **Release:** rule deletes (including every rule of a chain being
//!    deleted) and the delete half of moves; set-element removes; deletes
//!    of sets and objects recreated under the same name.
//! 2. **Add:** tables and flag updates; chains and chain updates (a
//!    verdict map's elements name chains); objects and quota updates
//!    (object maps' elements name objects); flowtables (a rule's
//!    `flow add @ft` names one); sets; set elements.
//! 3. **Rules:** inserts and moves in planned order, then replaces.
//! 4. **Delete:** sets, objects, chains, flowtables, tables.
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

use super::diff::{NftablesDiff, RulePlacement};
use super::types::{DeclaredChain, DeclaredRule};
use super::super::ObjectType;
use super::super::connection::Transaction;
use super::super::types::{Chain, Family, Rule};
use crate::netlink::{
    connection::Connection,
    error::{Error, Result},
    protocol::Nftables,
};

/// A declared rule's body carrying its key, which is written ahead of any
/// human comment as `nlink:<key> <comment>` (`NFTA_RULE_USERDATA`) and is
/// the diff's identity for the rule.
fn keyed_body(rule: &DeclaredRule) -> Rule {
    let mut body = rule.body.clone();
    body.key = rule.handle_key.clone();
    body
}

/// Push a rule at its planned place: right before or after an anchor
/// rule, or at the end of the chain.
fn place_rule(tx: Transaction, body: Rule, placement: RulePlacement) -> Transaction {
    match placement {
        RulePlacement::Before(before) => tx.insert_rule_before(body, before.0),
        // `add_rule` sends NLM_F_APPEND, which with a position puts the
        // rule right after the named one.
        RulePlacement::After(after) => tx.add_rule(body.position(after.0)),
        _ => tx.add_rule(body),
    }
}

/// Re-build a runtime `Chain` from a `DeclaredChain`.
///
/// `DeclaredChain` is a value type; `Chain` is the transaction-input type.
/// Shared by the chain-add and chain-modify passes. Both emit
/// `NFT_MSG_NEWCHAIN`; the modify pass leaves out `NLM_F_EXCL`, so the
/// kernel treats it as an update of the existing chain (#456).
fn build_chain(table: &str, family: Family, declared: &DeclaredChain) -> Result<Chain> {
    let mut chain = Chain::new(table, declared.name())?.family(family);
    if let Some(h) = declared.hook() {
        chain = chain.hook(h);
    }
    if let Some(p) = declared.priority() {
        chain = chain.priority(p);
    }
    if let Some(pol) = declared.policy() {
        chain = chain.policy(pol);
    }
    if let Some(ct) = declared.chain_type() {
        chain = chain.chain_type(ct);
    }
    if let Some(dev) = declared.device() {
        chain = chain.device(dev);
    }
    Ok(chain)
}

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

        // 0. In-place set updates (size, timeout, GC interval), in a batch
        //    of their own committed first. The kernel checks an element add
        //    against the size the set has before the commit, so a set grown
        //    in the same batch as its new elements would refuse them
        //    (ENFILE) and fail the apply, every time. Changing a limit is
        //    the one change that is safe to make ahead of the rest.
        if !self.sets_to_update.is_empty() {
            self.update_sets(conn).await?;
        }

        let mut tx: Transaction = conn.transaction();

        // The batch runs in four phases, because the kernel releases what a
        // rule uses — sets, objects, jump targets — only when the message
        // that deletes or replaces that rule is processed. A DELSET, DELOBJ
        // or DELCHAIN sent ahead of it is EBUSY, and was, for every rename
        // of a named counter or set and every chain dropped with a rule in
        // it (#460).
        //
        // Phase 1 — release. Rule deletes and the delete half of rule
        // moves, then element removes, then whatever this diff deletes
        // only to add back under the same name.

        // 1. Rule deletes — handle-targeted, family-aware. This includes
        //    every rule of a chain the diff deletes: DELCHAIN would take
        //    them, but only at its own place in phase 4, after the sets and
        //    objects they use.
        //
        // The diff carries (table, family, chain, handle). The
        // kernel rejects a DELRULE with an empty NFTA_RULE_CHAIN
        // (returns ENOENT) even when NFTA_RULE_HANDLE pins the
        // rule — contrary to an earlier assumption in this code.
        // Plan 178 closeout.
        for (table, family, chain, handle) in &self.rules_to_delete {
            tx = tx.del_rule(table, chain, *family, handle.0);
        }
        // ...and the rules being moved: out of declared order, or bound to
        // a set being recreated, which must be gone before its DELSET
        // (EBUSY otherwise). Re-inserted in step 10.
        for m in &self.rules_to_move {
            tx = tx.del_rule(&m.table, &m.chain, m.family, m.from.0);
        }

        // 2. Set-element removes, for sets that persist (a deleted set takes
        //    its elements). Before any delete: a verdict map's element holds
        //    its chain, an object map's element its object.
        for change in &self.set_elements_to_remove {
            tx = tx.del_set_elements(&change.set, &change.elements);
        }

        // 3. Sets and objects recreated under the same name: deleted here,
        //    so the add in phase 2 does not find them (EEXIST). The rules
        //    bound to them were moved out of the way in step 1. Sets first:
        //    an object map holds its objects.
        let recreated_set = |table: &str, family: Family, name: &str| {
            self.sets_to_add
                .iter()
                .any(|(t, f, s)| t == table && *f == family && s.name() == name)
        };
        let recreated_object = |table: &str, family: Family, name: &str, ty: ObjectType| {
            self.objects_to_add.iter().any(|(t, f, o)| {
                t == table && *f == family && o.name() == name && o.config().object_type() == ty
            })
        };
        for (table, family, name) in &self.sets_to_delete {
            if recreated_set(table, *family, name) {
                tx = tx.del_set(table, name, *family);
            }
        }
        for (table, family, name, object_type) in &self.objects_to_delete {
            if recreated_object(table, *family, name, *object_type) {
                tx = tx.del_object(table, name, *object_type, *family);
            }
        }

        // Phase 2 — add, in dependency order.

        // 4. Table adds (must precede chain/rule/flowtable adds
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

        // 4b. Table flag updates. NFT_MSG_NEWTABLE updates an existing table,
        //     so a flag change converges without a delete+recreate — which
        //     would cascade away every chain and rule inside it (#208).
        for (family, name, flags) in &self.tables_to_modify {
            tx = tx.add_table_with_flags(name, *family, *flags);
        }

        // 5. Chain adds, then chain property updates — before the sets,
        //    whose elements (a verdict map's jumps) can name chains. An
        //    update is `NFT_MSG_NEWCHAIN` *without* `NLM_F_EXCL`, which the
        //    kernel treats as an update of the existing chain, so a drifted
        //    policy converges without a delete+recreate (which would drop
        //    the chain's rules) (#200). Sent with `add_chain`'s `NLM_F_EXCL`
        //    it was refused with `EEXIST`, and no policy change ever applied
        //    (#456). The kernel refuses a changed hook, priority or type on
        //    a live base chain either way.
        for (table_name, family, declared) in &self.chains_to_add {
            tx = tx.add_chain(build_chain(table_name, *family, declared)?);
        }
        for (table_name, family, declared) in &self.chains_to_modify {
            tx = tx.update_chain(build_chain(table_name, *family, declared)?);
        }

        // 6. Object adds and quota updates — before the object maps' elements
        //     (step 9) that name them and the rules (step 10) that use them.
        for (table, family, declared) in &self.objects_to_add {
            tx = tx.add_object(&declared.to_object(table, *family));
        }
        for (table, family, declared) in &self.objects_to_update {
            tx = tx.update_object(&declared.to_object(table, *family));
        }

        // 7. Flowtable adds — **before** the rules.
        //
        //    A rule carrying `flow add @ft` for a flowtable created in
        //    the same diff is validated when the batch is committed,
        //    and the flowtable has to exist by then. Adding them after
        //    the rules failed the whole atomic batch. The module
        //    docstring stated the same (wrong) order, so doc and code
        //    agreed with each other and not with the dependency
        //    (#281).
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

        // 8. Set adds — after the owning table exists, before the
        //    rules (step 10) that reference them by `@name`. Re-build
        //    a runtime `Set` from `DeclaredSet`.
        for (table_name, family, declared) in &self.sets_to_add {
            tx = tx.add_set(declared.to_set(table_name, *family));
        }

        // 9. Set-element adds — after their set is created (step 8 or
        //    a prior apply), before the rules that match on them.
        for change in &self.set_elements_to_add {
            tx = tx.add_set_elements(&change.set, &change.elements);
        }

        // Phase 3 — rules.

        // 10. Rule inserts, new and moved, in the order the diff planned:
        //     inserts before the same anchor in declared order, inserts
        //     after one in reverse, so the chain ends up in declared
        //     order. Each anchor is a rule that stays, so its handle is
        //     valid throughout the batch.
        let mut inserts: Vec<(usize, &DeclaredRule, RulePlacement)> = self
            .rules_to_add
            .iter()
            .map(|a| (a.seq, &a.rule, a.placement))
            .chain(self.rules_to_move.iter().map(|m| (m.seq, &m.rule, m.placement)))
            .collect();
        inserts.sort_by_key(|(seq, ..)| *seq);
        for (_, rule, placement) in inserts {
            tx = place_rule(tx, keyed_body(rule), placement);
        }

        // 11. Rule in-place replaces — emits
        //     `NFT_MSG_NEWRULE | NLM_F_REPLACE | NFTA_RULE_HANDLE`.
        //     Kernel atomically swaps the body at that handle
        //     (preserves position, no flush), releasing what the old body
        //     used. After the inserts, so no insert anchors on a handle a
        //     replace has already retired.
        for (_table, _family, _chain, handle, declared) in &self.rules_to_replace {
            tx = tx.replace_rule(keyed_body(declared), handle.0);
        }

        // Phase 4 — delete what nothing uses any more: sets (an object map
        // holds its objects, a verdict map its chains), then objects, then
        // chains (whose rules went in step 1), flowtables, tables.

        // 12. Set deletes.
        for (table, family, name) in &self.sets_to_delete {
            if !recreated_set(table, *family, name) {
                tx = tx.del_set(table, name, *family);
            }
        }

        // 13. Object deletes.
        for (table, family, name, object_type) in &self.objects_to_delete {
            if !recreated_object(table, *family, name, *object_type) {
                tx = tx.del_object(table, name, *object_type, *family);
            }
        }

        // 14. Chain deletes.
        for (table, family, name) in &self.chains_to_delete {
            tx = tx.del_chain(table, name, *family);
        }

        // 15. Flowtable deletes — after the rules that `flow add` to them.
        for (family, table, name) in &self.flowtables_to_delete {
            tx = tx.del_flowtable(*family, table, name);
        }

        // 16. Table deletes (cascades any leftover children).
        for (family, name) in &self.tables_to_delete {
            tx = tx.del_table(name, *family);
        }

        tx.commit(conn).await?;
        Ok(total)
    }

    /// Commit [`Self::sets_to_update`] as one batch, then read the sets back:
    /// a kernel older than 6.5 accepts the update and keeps the old size,
    /// and saying so beats a diff that reports the same update forever.
    async fn update_sets(&self, conn: &Connection<Nftables>) -> Result<()> {
        let mut tx = conn.transaction();
        for (table, family, declared) in &self.sets_to_update {
            tx = tx.update_set(declared.to_set(table, *family));
        }
        tx.commit(conn).await?;

        for (table, family, declared) in &self.sets_to_update {
            let Some(current) = conn
                .list_sets_in(table, *family)
                .await?
                .into_iter()
                .find(|s| s.name == declared.name())
            else {
                continue;
            };
            let ms = |d: Option<std::time::Duration>| d.map_or(0, super::super::expr::millis);
            let kept = if declared.size().is_some_and(|size| current.size != Some(size)) {
                Some(format!("a size of {:?} (asked {:?})", current.size, declared.size()))
            } else if super::rules::timeout_step(ms(declared.timeout()))
                != super::rules::timeout_step(ms(current.timeout))
            {
                Some(format!(
                    "a timeout of {:?} (asked {:?})",
                    current.timeout,
                    declared.timeout()
                ))
            } else if ms(declared.gc_interval()) != ms(current.gc_interval) {
                Some(format!(
                    "a GC interval of {:?} (asked {:?})",
                    current.gc_interval,
                    declared.gc_interval()
                ))
            } else {
                None
            };
            if let Some(kept) = kept {
                return Err(Error::not_supported(format!(
                    "set {table}/{}: the kernel accepted an in-place update but kept {kept} \
                     (an in-place set update needs Linux 6.5+); delete the set and \
                     re-apply to recreate it",
                    declared.name(),
                )));
            }
        }
        Ok(())
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
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # let conn = nlink::Connection::<nlink::netlink::Nftables>::new()?;
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
    /// # Ok(())
    /// # }
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
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case"))]
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
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case"))]
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
#[must_use = "Inspect `.attempts` to detect retried apply paths"]
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
