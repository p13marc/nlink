//! Apply an [`NftablesDiff`] to the kernel.
//!
//! 0.16 implementation note: the underlying `Transaction` API
//! does not yet cover `del_chain`, `del_rule`, `add_flowtable`,
//! or `del_flowtable` (Plan 150 §9.4 coordination point). Until
//! that ships, apply uses the **imperative** path (`add_table`
//! / `del_table` / `add_chain` / `del_chain` / `add_rule` /
//! `del_rule` / `add_flowtable` / `del_flowtable` directly) and
//! gives up atomicity. The chain + rule + flowtable changes
//! happen in dependency-correct order so a partial failure
//! leaves a recoverable state — the next reapply converges.
//!
//! When Transaction grows full coverage (post-0.16), `apply`
//! flips to the atomic batched path and `apply_reconcile` (the
//! follow-up Plan 157 §4.5 method) handles concurrent-mutation
//! retry.

use super::diff::NftablesDiff;
use super::super::types::Chain;
use crate::netlink::{connection::Connection, error::Result, protocol::Nftables};

impl NftablesDiff {
    /// Apply the diff to the kernel.
    ///
    /// Operations execute in dependency-correct order:
    /// 1. Rule deletes (release dependencies on chains/tables)
    /// 2. Chain deletes
    /// 3. Flowtable deletes
    /// 4. Table deletes (cascades any leftover children)
    /// 5. Table adds (creates the namespace for children)
    /// 6. Chain adds
    /// 7. Rule adds
    /// 8. Flowtable adds
    ///
    /// Returns the diff's `change_count` on success — a
    /// caller-visible "we did N things" signal useful for
    /// `tracing::info!`-style post-apply logging.
    ///
    /// # Atomicity caveat (0.16)
    ///
    /// Apply is **not atomic** in 0.16 — see the module-level note
    /// for why and what's planned. A partial failure leaves
    /// per-table state half-applied; the next reapply converges
    /// the remainder. Document this explicitly for any operator
    /// using NftablesConfig in production.
    pub async fn apply(&self, conn: &Connection<Nftables>) -> Result<usize> {
        let total = self.change_count();
        if total == 0 {
            return Ok(0);
        }

        // 1. Rule deletes — handle-targeted, family-aware.
        for (table, family, handle) in &self.rules_to_delete {
            // The kernel needs (table, chain, family, handle) for
            // del_rule but the diff only carries (table, family,
            // handle) since the chain is implicit in the handle.
            // For 0.16 a workable shim: re-issue with chain="" —
            // the kernel ignores NFTA_RULE_CHAIN when a handle
            // is supplied, per `net/netfilter/nf_tables_api.c`.
            conn.del_rule(table, "", *family, handle.0).await?;
        }

        // 2. Chain deletes.
        for (table, family, name) in &self.chains_to_delete {
            conn.del_chain(table, name, *family).await?;
        }

        // 3. Flowtable deletes.
        for (family, table, name) in &self.flowtables_to_delete {
            conn.del_flowtable(*family, table, name).await?;
        }

        // 4. Table deletes (cascades any leftover children).
        for (family, name) in &self.tables_to_delete {
            conn.del_table(name, *family).await?;
        }

        // 5. Table adds (must precede chain/rule/flowtable adds
        //    that reference them).
        for table in &self.tables_to_add {
            if table.flags() != 0 {
                conn.add_table_with_flags(table.name(), table.family(), table.flags())
                    .await?;
            } else {
                conn.add_table(table.name(), table.family()).await?;
            }
        }

        // 6. Chain adds. Re-build a runtime `Chain` from
        //    `DeclaredChain` since the latter is a value type and
        //    the former is the connection-method input.
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
            conn.add_chain(chain).await?;
        }

        // 7. Rule adds. The DeclaredRule already carries a fully-
        //    constructed Rule body; just clone and add.
        for rule in &self.rules_to_add {
            conn.add_rule(rule.body.clone()).await?;
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
            conn.add_flowtable(&runtime).await?;
        }

        Ok(total)
    }
}
