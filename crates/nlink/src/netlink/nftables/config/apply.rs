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
//! `apply_reconcile` (Plan 157 §4.5 retry-on-conflict variant)
//! remains a documented follow-up.

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
        // The diff carries (table, family, handle); chain name is
        // implicit in the handle. The kernel ignores
        // NFTA_RULE_CHAIN when a handle is supplied (per
        // `net/netfilter/nf_tables_api.c`), so chain="" is safe.
        for (table, family, handle) in &self.rules_to_delete {
            tx = tx.del_rule(table, "", *family, handle.0);
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

        // 7. Rule adds. The DeclaredRule already carries a fully-
        //    constructed Rule body; just clone and add.
        for rule in &self.rules_to_add {
            tx = tx.add_rule(rule.body.clone());
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
}
