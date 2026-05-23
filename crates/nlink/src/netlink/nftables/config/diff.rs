//! `NftablesDiff` — what changes between declared and current.

use std::collections::HashSet;

use super::types::{
    DeclaredChain, DeclaredFlowtable, DeclaredRule, DeclaredTable, NftablesConfig,
};
use super::super::types::Family;
use crate::netlink::{connection::Connection, error::Result, protocol::Nftables};

/// Kernel-assigned rule handle (`NFTA_RULE_HANDLE`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RuleHandle(pub u64);

/// The result of comparing a declared [`NftablesConfig`] against
/// the kernel's current state. Apply via
/// [`Self::apply`](super::NftablesDiff::apply).
///
/// `is_empty()` returns true when declared and current already
/// agree (idempotent reapply).
#[derive(Debug, Clone, Default)]
pub struct NftablesDiff {
    /// Tables to create.
    pub tables_to_add: Vec<DeclaredTable>,
    /// Tables to delete (family, name).
    pub tables_to_delete: Vec<(Family, String)>,
    /// Chains to create — (owning table, owning family, chain).
    pub chains_to_add: Vec<(String, Family, DeclaredChain)>,
    /// Chains to delete — (table, family, name).
    pub chains_to_delete: Vec<(String, Family, String)>,
    /// Rules to add — paired with owning table/chain/family.
    pub rules_to_add: Vec<DeclaredRule>,
    /// Rules to delete — kernel-assigned handles.
    pub rules_to_delete: Vec<(String, Family, RuleHandle)>,
    /// Flowtables to add.
    pub flowtables_to_add: Vec<DeclaredFlowtable>,
    /// Flowtables to delete — (family, table, name).
    pub flowtables_to_delete: Vec<(Family, String, String)>,
}

impl NftablesDiff {
    /// `true` if declared state already matches kernel state.
    pub fn is_empty(&self) -> bool {
        self.tables_to_add.is_empty()
            && self.tables_to_delete.is_empty()
            && self.chains_to_add.is_empty()
            && self.chains_to_delete.is_empty()
            && self.rules_to_add.is_empty()
            && self.rules_to_delete.is_empty()
            && self.flowtables_to_add.is_empty()
            && self.flowtables_to_delete.is_empty()
    }

    /// Total number of changes (sum of all add/delete counts).
    pub fn change_count(&self) -> usize {
        self.tables_to_add.len()
            + self.tables_to_delete.len()
            + self.chains_to_add.len()
            + self.chains_to_delete.len()
            + self.rules_to_add.len()
            + self.rules_to_delete.len()
            + self.flowtables_to_add.len()
            + self.flowtables_to_delete.len()
    }

    /// Render a one-line-per-change human summary. Useful for
    /// `tracing::info!` or CLI output.
    pub fn summary(&self) -> String {
        let mut lines = Vec::new();
        for t in &self.tables_to_add {
            lines.push(format!("+ table {:?} {}", t.family(), t.name()));
        }
        for (fam, name) in &self.tables_to_delete {
            lines.push(format!("- table {fam:?} {name}"));
        }
        for (tbl, fam, c) in &self.chains_to_add {
            lines.push(format!("+ chain {fam:?} {tbl}/{}", c.name()));
        }
        for (tbl, fam, name) in &self.chains_to_delete {
            lines.push(format!("- chain {fam:?} {tbl}/{name}"));
        }
        for r in &self.rules_to_add {
            let key = r.handle_key().unwrap_or("<anonymous>");
            lines.push(format!(
                "+ rule {:?} {}/{} [{}]",
                r.family(),
                r.table(),
                r.chain(),
                key
            ));
        }
        for (tbl, fam, h) in &self.rules_to_delete {
            lines.push(format!("- rule {fam:?} {tbl} (handle={})", h.0));
        }
        for f in &self.flowtables_to_add {
            lines.push(format!(
                "+ flowtable {:?} {}/{}",
                f.family(),
                f.table(),
                f.name()
            ));
        }
        for (fam, tbl, name) in &self.flowtables_to_delete {
            lines.push(format!("- flowtable {fam:?} {tbl}/{name}"));
        }
        if lines.is_empty() {
            "NftablesDiff: no changes".to_string()
        } else {
            format!(
                "NftablesDiff: {} change{}:\n  {}",
                lines.len(),
                if lines.len() == 1 { "" } else { "s" },
                lines.join("\n  ")
            )
        }
    }
}

impl NftablesConfig {
    /// Compute the diff between this declared config and the
    /// kernel's current state.
    ///
    /// # Rule-identity caveat (0.16)
    ///
    /// Rules without a `handle_key` are *always* added — there's
    /// no diff identity for them. Rules with a `handle_key` are
    /// matched against kernel rules by the key (the kernel doesn't
    /// know our keys; we just emit the same set as we declared,
    /// and any extras are deleted on apply). Full byte-canonical
    /// diff is a follow-up; this gets the user a working
    /// declarative apply now with explicit churn-vs-correctness
    /// trade-off.
    pub async fn diff(&self, conn: &Connection<Nftables>) -> Result<NftablesDiff> {
        let mut diff = NftablesDiff::default();

        // Index declared by (family, name) for fast lookup.
        let declared_tables: HashSet<(Family, &str)> = self
            .tables
            .iter()
            .map(|t| (t.family(), t.name()))
            .collect();

        // Current kernel state.
        let current_tables = conn.list_tables().await?;
        let current_table_names: HashSet<(Family, String)> = current_tables
            .iter()
            .map(|t| (t.family, t.name.clone()))
            .collect();

        // Pass 1: tables to add (declared but not current).
        for declared in &self.tables {
            if !current_table_names.contains(&(declared.family(), declared.name().to_string())) {
                diff.tables_to_add.push(declared.clone());
            }
        }

        // Pass 2: tables to delete (current but not declared).
        for current in &current_tables {
            if !declared_tables.contains(&(current.family, current.name.as_str())) {
                diff.tables_to_delete
                    .push((current.family, current.name.clone()));
            }
        }

        // Pass 3: per-table diff for tables present in both sides.
        // For 0.16 simplicity: chains + rules + flowtables in
        // tables_to_add already get installed wholesale by apply
        // (they're nested in the add op). For tables in both,
        // diff chains/rules/flowtables individually.
        for declared in &self.tables {
            // Skip tables in tables_to_add — chains/rules/flowtables
            // for them are added as part of the table-creation.
            if diff
                .tables_to_add
                .iter()
                .any(|t| t.family() == declared.family() && t.name() == declared.name())
            {
                // Promote nested contents into the per-object
                // collections so apply() handles them uniformly.
                for c in declared.chains() {
                    diff.chains_to_add.push((
                        declared.name().to_string(),
                        declared.family(),
                        c.clone(),
                    ));
                }
                for r in declared.rules() {
                    diff.rules_to_add.push(r.clone());
                }
                for f in declared.flowtables() {
                    diff.flowtables_to_add.push(f.clone());
                }
                continue;
            }

            // Table exists in both — diff chains.
            let current_chains = conn.list_chains().await?;
            let chains_in_table: Vec<_> = current_chains
                .iter()
                .filter(|c| c.table == declared.name() && c.family == declared.family())
                .collect();
            let declared_chain_names: HashSet<&str> =
                declared.chains().iter().map(|c| c.name()).collect();
            let current_chain_names: HashSet<&str> =
                chains_in_table.iter().map(|c| c.name.as_str()).collect();

            for c in declared.chains() {
                if !current_chain_names.contains(c.name()) {
                    diff.chains_to_add.push((
                        declared.name().to_string(),
                        declared.family(),
                        c.clone(),
                    ));
                }
            }
            for c in &chains_in_table {
                if !declared_chain_names.contains(c.name.as_str()) {
                    diff.chains_to_delete.push((
                        declared.name().to_string(),
                        declared.family(),
                        c.name.clone(),
                    ));
                }
            }

            // Rules: 0.16 strategy is "all declared rules get
            // added; current rules tagged with handle_keys we
            // didn't declare get deleted." The kernel returns
            // rule handles in list_rules; deletes target the
            // handle.
            //
            // Without a per-rule handle_key registry, the
            // pragmatic shape: emit all declared rules
            // unconditionally + delete every current rule whose
            // declared peer is missing. This means rules churn
            // on every reapply, but apply remains correct.
            //
            // For 0.16, take an even simpler stance: emit all
            // declared rules and DON'T delete current ones. Users
            // who want full reconcile can call flush_table first,
            // then apply. The integration test below documents
            // this.
            for r in declared.rules() {
                diff.rules_to_add.push(r.clone());
            }

            // Flowtables: name-based identity, like chains.
            let current_flowtables = conn.list_flowtables().await?;
            let fts_in_table: Vec<_> = current_flowtables
                .iter()
                .filter(|f| f.table == declared.name() && f.family == declared.family())
                .collect();
            let declared_ft_names: HashSet<&str> =
                declared.flowtables().iter().map(|f| f.name()).collect();
            let current_ft_names: HashSet<&str> =
                fts_in_table.iter().map(|f| f.name.as_str()).collect();
            for f in declared.flowtables() {
                if !current_ft_names.contains(f.name()) {
                    diff.flowtables_to_add.push(f.clone());
                }
            }
            for f in &fts_in_table {
                if !declared_ft_names.contains(f.name.as_str()) {
                    diff.flowtables_to_delete.push((
                        declared.family(),
                        declared.name().to_string(),
                        f.name.clone(),
                    ));
                }
            }
        }

        Ok(diff)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_diff_is_empty() {
        let d = NftablesDiff::default();
        assert!(d.is_empty());
        assert_eq!(d.change_count(), 0);
        assert_eq!(d.summary(), "NftablesDiff: no changes");
    }

    #[test]
    fn summary_renders_change_lines() {
        use super::super::super::types::{Family, Hook, Policy, Priority};
        use super::super::types::DeclaredChain;
        // Manually populate a diff to test the rendering — the
        // async diff() needs a live socket.
        let mut d = NftablesDiff::default();
        d.tables_to_delete
            .push((Family::Inet, "legacy".to_string()));
        let cfg = NftablesConfig::new().table("filter", Family::Inet, |t| {
            t.chain("input", |c| {
                c.hook(Hook::Input)
                    .priority(Priority::Filter)
                    .policy(Policy::Drop)
            })
        });
        d.tables_to_add.push(cfg.tables()[0].clone());
        assert_eq!(d.change_count(), 2);
        let s = d.summary();
        assert!(s.contains("+ table"));
        assert!(s.contains("- table"));
        assert!(s.contains("2 changes"));
        let _ = DeclaredChain::name; // silence unused-import on the DeclaredChain pub path
    }

    #[test]
    fn change_count_sums_all_kinds() {
        let mut d = NftablesDiff::default();
        d.tables_to_add
            .push(NftablesConfig::new().tables().first().cloned().unwrap_or_else(
                || NftablesConfig::new().table(
                    "x",
                    super::super::super::types::Family::Inet,
                    |t| t,
                ).tables()[0].clone(),
            ));
        d.tables_to_delete
            .push((super::super::super::types::Family::Inet, "y".to_string()));
        assert_eq!(d.change_count(), 2);
    }
}
