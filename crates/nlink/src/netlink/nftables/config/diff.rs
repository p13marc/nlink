//! `NftablesDiff` — what changes between declared and current.

use std::collections::HashSet;

use super::types::{
    DeclaredChain, DeclaredFlowtable, DeclaredRule, DeclaredTable, NftablesConfig,
};
use super::super::types::Family;
use crate::netlink::{
    builder::MessageBuilder, connection::Connection, error::Result, protocol::Nftables,
};

/// One-line hex dump used by the Plan 178 diagnostic trace.
/// Kept small + dependency-free.
struct HexDump<'a>(&'a [u8]);
impl std::fmt::Display for HexDump<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for b in self.0 {
            write!(f, "{:02x}", b)?;
        }
        Ok(())
    }
}
fn hex_dump(bytes: &[u8]) -> HexDump<'_> {
    HexDump(bytes)
}

/// Normalize a netlink TLV byte stream for byte-equality
/// comparison. Plan 178 fix — closes the false-positive class
/// where the lib's writer-side expression bytes diverged from
/// the kernel-echoed bytes purely on:
///
/// 1. `NLA_F_NESTED` (`0x8000`) bit: the lib's `nest_start`
///    sets it on nested attribute types; the kernel's outgoing
///    serialization of `NFTA_RULE_EXPRESSIONS` does NOT set it.
/// 2. Attribute ordering within a nest: the kernel emits inner
///    attributes in canonical (numeric) order; the lib's writer
///    emits them in source order (e.g. `NFTA_META_DREG` then
///    `NFTA_META_KEY` vs the kernel's `KEY` then `DREG`).
///
/// Strategy: walk the byte stream as TLVs, recursively. For each
/// attribute, strip the `NLA_F_NESTED` bit, treat the payload as
/// nested if and only if it parses cleanly as another TLV stream
/// (consistent lengths, no overrun, 4-byte alignment), and at
/// each level sort sibling attributes by type. Re-emit the
/// canonical form. Both declared-side and kernel-side bytes go
/// through this normalizer before the byte compare in `diff`.
///
/// Safe on garbage input: invalid TLV streams return the original
/// bytes unchanged so the comparison still produces a definitive
/// answer (different) without panicking.
pub(crate) fn normalize_tlv(bytes: &[u8]) -> Vec<u8> {
    match try_walk_tlvs(bytes) {
        Some(mut attrs) => {
            attrs.sort_by_key(|(ty, _)| *ty);
            let mut out = Vec::with_capacity(bytes.len());
            for (ty, payload) in &attrs {
                emit_tlv(&mut out, *ty, payload);
            }
            out
        }
        None => bytes.to_vec(),
    }
}

/// Walk `bytes` as a netlink TLV stream. Returns `Some(attrs)` if
/// the entire input parses cleanly (lengths consistent, no overrun
/// past EOF, 4-byte aligned, every payload ≥ 0). For each attribute
/// whose payload itself parses as TLVs, recursively normalize the
/// payload first (so siblings-at-every-depth get sorted).
///
/// Returns `None` if the input doesn't look like a TLV stream —
/// `normalize_tlv` then leaves it alone.
fn try_walk_tlvs(bytes: &[u8]) -> Option<Vec<(u16, Vec<u8>)>> {
    if bytes.is_empty() {
        return Some(Vec::new());
    }
    let mut out = Vec::new();
    let mut pos = 0;
    while pos < bytes.len() {
        if pos + 4 > bytes.len() {
            return None;
        }
        let len = u16::from_le_bytes([bytes[pos], bytes[pos + 1]]) as usize;
        if len < 4 || pos + len > bytes.len() {
            return None;
        }
        let raw_type = u16::from_le_bytes([bytes[pos + 2], bytes[pos + 3]]);
        // Strip NLA_F_NESTED (0x8000) and NLA_F_NET_BYTEORDER (0x4000)
        // hint bits — these are parser hints, not stored state, so
        // the kernel and the lib can legitimately differ on whether
        // they're set without the underlying attribute differing.
        let ty = raw_type & !0xc000;
        let payload = &bytes[pos + 4..pos + len];
        // Recursively normalize if the payload parses as TLVs.
        let normalized_payload = match try_walk_tlvs(payload) {
            Some(mut inner) => {
                inner.sort_by_key(|(t, _)| *t);
                let mut buf = Vec::with_capacity(payload.len());
                for (t, p) in &inner {
                    emit_tlv(&mut buf, *t, p);
                }
                buf
            }
            None => payload.to_vec(),
        };
        out.push((ty, normalized_payload));
        // 4-byte alignment.
        let aligned = (len + 3) & !3;
        pos += aligned;
        if pos > bytes.len() {
            return None;
        }
    }
    Some(out)
}

fn emit_tlv(out: &mut Vec<u8>, ty: u16, payload: &[u8]) {
    let len = (payload.len() + 4) as u16;
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(&ty.to_le_bytes());
    out.extend_from_slice(payload);
    while !out.len().is_multiple_of(4) {
        out.push(0);
    }
}

/// Render the declared `Rule`'s expression list to the same byte
/// shape the kernel returns in `NFTA_RULE_EXPRESSIONS` (the
/// nested elem-list inner bytes, *not* including the outer
/// attribute header). Used by the diff to byte-compare declared
/// vs kernel rule bodies. Plan 157b v2.
fn lower_to_expression_bytes(rule: &super::super::types::Rule) -> Vec<u8> {
    if rule.exprs.is_empty() {
        return Vec::new();
    }
    // Scratch builder: write the NFTA_RULE_EXPRESSIONS attribute,
    // then strip the 16-byte nlmsghdr + 4-byte attribute header
    // to get just the inner elem list (matches what the kernel
    // emits as the `NFTA_RULE_EXPRESSIONS` payload).
    let mut b = MessageBuilder::new(0, 0);
    super::super::expr::write_expressions(&mut b, &rule.exprs);
    let raw = b.finish();
    // NlMsgHdr is 16 bytes, attribute header is 4 bytes.
    if raw.len() <= 20 {
        return Vec::new();
    }
    raw[20..].to_vec()
}

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
#[non_exhaustive]
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
    /// Rules to delete — `(table, family, chain, kernel_handle)`.
    /// Chain is carried explicitly because the kernel rejects a
    /// `NFT_MSG_DELRULE` with an empty `NFTA_RULE_CHAIN` even when
    /// `NFTA_RULE_HANDLE` is supplied (returns `ENOENT`); the
    /// earlier (table, family, handle) shape relied on a kernel
    /// behavior that doesn't actually hold. Plan 178 closeout.
    pub rules_to_delete: Vec<(String, Family, String, RuleHandle)>,
    /// Rules to replace in-place. Each entry is
    /// `(table, family, chain, kernel_handle, replacement)` —
    /// emits `NFT_MSG_NEWRULE | NLM_F_REPLACE | NFTA_RULE_HANDLE`
    /// so the kernel atomically swaps the rule body at that
    /// handle (preserves position, no flush).
    ///
    /// Populated by [`NftablesConfig::diff`] when a declared
    /// keyed rule matches a kernel rule by `NFTA_RULE_USERDATA`
    /// comment but the expression bytes differ. Plan 157b v2.
    pub rules_to_replace: Vec<(String, Family, String, RuleHandle, DeclaredRule)>,
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
            && self.rules_to_replace.is_empty()
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
            + self.rules_to_replace.len()
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
        for (tbl, fam, chain, h) in &self.rules_to_delete {
            lines.push(format!("- rule {fam:?} {tbl}/{chain} (handle={})", h.0));
        }
        for (tbl, fam, chain, h, r) in &self.rules_to_replace {
            let key = r.handle_key().unwrap_or("<anonymous>");
            lines.push(format!(
                "~ rule {fam:?} {tbl}/{chain} (handle={} key={key})",
                h.0
            ));
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

        // HOIST (Plan 164): list_chains() and list_flowtables()
        // are kernel-wide dumps; calling them inside the per-table
        // loop made the diff O(N²) in declared-table count. Pull
        // them out once, index by (family, table_name) for O(1)
        // lookups inside the loop. list_rules stays inside (it's
        // server-side table-scoped — N round-trips is optimal).
        let all_chains_for_diff = conn.list_chains().await?;
        let chains_by_table: std::collections::HashMap<
            (super::super::types::Family, String),
            Vec<&super::super::types::ChainInfo>,
        > = all_chains_for_diff
            .iter()
            .fold(std::collections::HashMap::new(), |mut acc, c| {
                acc.entry((c.family, c.table.clone()))
                    .or_default()
                    .push(c);
                acc
            });
        let all_flowtables_for_diff = conn.list_flowtables().await?;
        let flowtables_by_table: std::collections::HashMap<
            (super::super::types::Family, String),
            Vec<&super::super::types::Flowtable>,
        > = all_flowtables_for_diff
            .iter()
            .fold(std::collections::HashMap::new(), |mut acc, f| {
                acc.entry((f.family, f.table.clone()))
                    .or_default()
                    .push(f);
                acc
            });

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
            // Lookup into the hoisted index (Plan 164); no per-
            // table kernel call. Empty slice if no current chains
            // match this table.
            let chains_in_table: &[&super::super::types::ChainInfo] = chains_by_table
                .get(&(declared.family(), declared.name().to_string()))
                .map(|v| v.as_slice())
                .unwrap_or(&[]);
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
            for c in chains_in_table {
                if !declared_chain_names.contains(c.name.as_str()) {
                    diff.chains_to_delete.push((
                        declared.name().to_string(),
                        declared.family(),
                        c.name.clone(),
                    ));
                }
            }

            // Rules: per-rule USERDATA-keyed identity (Plan
            // 157b v2). NetworkConfig-symmetric — each rule is an
            // individually diffable object keyed by its
            // user-supplied `handle_key`, which round-trips
            // through the kernel as
            // `NFTA_RULE_USERDATA = "nlink:<key>"`.
            //
            // Anonymous rules (no `handle_key`): always-add with a
            // tracing::warn. Documented limitation — same as a
            // `LinkConfig` without a name in `NetworkConfig`.
            let current_rules = conn
                .list_rules(declared.name(), declared.family())
                .await?;
            let rules_in_chain: Vec<&super::super::types::RuleInfo> = Vec::new();
            // Per-chain: group declared rules by chain, then
            // diff against kernel rules in the same chain.
            use std::collections::HashMap as _HashMap;
            let kernel_in_chain: _HashMap<String, Vec<&super::super::types::RuleInfo>> =
                current_rules
                    .iter()
                    .fold(_HashMap::new(), |mut acc, r| {
                        acc.entry(r.chain.clone()).or_default().push(r);
                        acc
                    });
            let _ = rules_in_chain; // silence the placeholder
            let declared_in_chain: _HashMap<&str, Vec<&DeclaredRule>> = declared
                .rules()
                .iter()
                .fold(_HashMap::new(), |mut acc, r| {
                    acc.entry(r.chain()).or_default().push(r);
                    acc
                });

            for (chain_name, declared_rules) in &declared_in_chain {
                let kernel_rules: &[&super::super::types::RuleInfo] = kernel_in_chain
                    .get(*chain_name)
                    .map(|v| v.as_slice())
                    .unwrap_or(&[]);

                // Map: key → kernel rule with that nlink:<key>
                // comment.
                let kernel_by_key: _HashMap<&str, &super::super::types::RuleInfo> = kernel_rules
                    .iter()
                    .filter_map(|r| r.comment.as_deref().map(|c| (c, *r)))
                    .collect();

                // Track which kernel keys we've claimed so we can
                // delete the rest in pass 2.
                let mut declared_keys: HashSet<&str> = HashSet::new();

                // Pass 1: declared rules.
                for declared_rule in declared_rules {
                    let Some(key) = declared_rule.handle_key() else {
                        // Anonymous → always-add. Warn so users
                        // notice the idempotency gap.
                        tracing::warn!(
                            chain = chain_name,
                            "anonymous rule in declarative config; \
                             will be added on every apply (use \
                             rule_keyed for idempotent reconcile)",
                        );
                        diff.rules_to_add.push((*declared_rule).clone());
                        continue;
                    };
                    declared_keys.insert(key);

                    match kernel_by_key.get(key) {
                        Some(kr) => {
                            // Key matches: compare expression
                            // bytes. If different → in-place
                            // replace at the kernel handle.
                            // Plan 178 — pass both sides through
                            // `normalize_tlv` first: strips the
                            // `NLA_F_NESTED` hint bit and sorts
                            // sibling attributes by type so the
                            // writer's source-order emission and
                            // the kernel's canonical-order echo
                            // compare equal when they describe
                            // the same expression list.
                            let declared_body = normalize_tlv(
                                &lower_to_expression_bytes(&declared_rule.body),
                            );
                            let kernel_body = normalize_tlv(&kr.expression_bytes);
                            if declared_body != kernel_body {
                                tracing::trace!(
                                    table = %declared.name(),
                                    chain = chain_name,
                                    key,
                                    declared_len = declared_body.len(),
                                    kernel_len = kernel_body.len(),
                                    declared_hex = %hex_dump(&declared_body),
                                    kernel_hex = %hex_dump(&kernel_body),
                                    "diff body-bytes divergence after normalize (Plan 178)"
                                );
                                diff.rules_to_replace.push((
                                    declared.name().to_string(),
                                    declared.family(),
                                    chain_name.to_string(),
                                    RuleHandle(kr.handle),
                                    (*declared_rule).clone(),
                                ));
                            }
                            // else: no-op (declared and kernel
                            // already agree byte-for-byte after
                            // normalization)
                        }
                        None => {
                            // Not in kernel: add.
                            diff.rules_to_add.push((*declared_rule).clone());
                        }
                    }
                }

                // Pass 2: kernel rules with nlink keys we didn't
                // declare → delete (they're ours, they shouldn't
                // be there). Kernel rules without an nlink-prefix
                // comment (foreign / external) are left alone.
                for kr in kernel_rules {
                    let Some(key) = kr.comment.as_deref() else { continue };
                    if !declared_keys.contains(key) {
                        diff.rules_to_delete.push((
                            declared.name().to_string(),
                            declared.family(),
                            chain_name.to_string(),
                            RuleHandle(kr.handle),
                        ));
                    }
                }
            }

            // Pass 3: declared chains with no rules in
            // declared_in_chain — those chains' kernel rules
            // (with nlink keys) need cleanup too.
            for kchain_name in kernel_in_chain.keys() {
                if declared_in_chain.contains_key(kchain_name.as_str()) {
                    continue;
                }
                // Only act on chains that are in the declared
                // chain list (or being-added). Drift in chains
                // we don't manage is left alone.
                let in_declared_chains = declared
                    .chains()
                    .iter()
                    .any(|c| c.name() == kchain_name);
                if !in_declared_chains {
                    continue;
                }
                if let Some(krs) = kernel_in_chain.get(kchain_name) {
                    for kr in krs {
                        if kr.comment.is_some() {
                            diff.rules_to_delete.push((
                                declared.name().to_string(),
                                declared.family(),
                                kchain_name.clone(),
                                RuleHandle(kr.handle),
                            ));
                        }
                    }
                }
            }

            // Flowtables: name-based identity, like chains.
            // Lookup into the hoisted index (Plan 164).
            let fts_in_table: &[&super::super::types::Flowtable] = flowtables_by_table
                .get(&(declared.family(), declared.name().to_string()))
                .map(|v| v.as_slice())
                .unwrap_or(&[]);
            let declared_ft_names: HashSet<&str> =
                declared.flowtables().iter().map(|f| f.name()).collect();
            let current_ft_names: HashSet<&str> =
                fts_in_table.iter().map(|f| f.name.as_str()).collect();
            for f in declared.flowtables() {
                if !current_ft_names.contains(f.name()) {
                    diff.flowtables_to_add.push(f.clone());
                }
            }
            for f in fts_in_table {
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

    // ---- Plan 157b v2 — per-rule USERDATA-keyed identity ----

    #[test]
    fn lower_to_expression_bytes_is_deterministic() {
        use super::super::super::types::Rule;
        let r1 = Rule::new("filter", "input").match_tcp_dport(22).accept();
        let r2 = Rule::new("filter", "input").match_tcp_dport(22).accept();
        assert_eq!(
            lower_to_expression_bytes(&r1),
            lower_to_expression_bytes(&r2),
            "identical rule builders should lower to identical bytes"
        );
        assert!(
            !lower_to_expression_bytes(&r1).is_empty(),
            "non-empty rule should have non-empty expression bytes"
        );
    }

    #[test]
    fn lower_to_expression_bytes_differs_on_value_change() {
        use super::super::super::types::Rule;
        let r1 = Rule::new("filter", "input").match_tcp_dport(22).accept();
        let r2 = Rule::new("filter", "input").match_tcp_dport(443).accept();
        assert_ne!(
            lower_to_expression_bytes(&r1),
            lower_to_expression_bytes(&r2),
            "rules matching different ports should lower differently"
        );
    }

    #[test]
    fn empty_rule_lowers_to_empty_bytes() {
        use super::super::super::types::Rule;
        let r = Rule::new("filter", "input"); // no exprs
        assert!(lower_to_expression_bytes(&r).is_empty());
    }

    #[test]
    fn summary_renders_rules_to_replace() {
        use super::super::super::types::{Family, Rule};
        use super::super::types::DeclaredRule;
        let mut d = NftablesDiff::default();
        let rule = Rule::new("filter", "input").match_tcp_dport(22).accept();
        let declared = DeclaredRule {
            table: "filter".to_string(),
            chain: "input".to_string(),
            family: Family::Inet,
            handle_key: Some("ssh".to_string()),
            body: rule,
        };
        d.rules_to_replace.push((
            "filter".to_string(),
            Family::Inet,
            "input".to_string(),
            RuleHandle(42),
            declared,
        ));
        let s = d.summary();
        assert!(s.contains("~ rule"), "summary missing replace marker: {s}");
        assert!(s.contains("handle=42"), "summary missing handle: {s}");
        assert!(s.contains("key=ssh"), "summary missing key: {s}");
        assert_eq!(d.change_count(), 1);
        assert!(!d.is_empty());
    }

    // ---- Plan 178 — TLV normalizer + register canonicalization ----

    /// Hex captured from CI on commit `a154a16` (the "Plan 178
    /// diag" test) showing what the **kernel** echoes back via
    /// `NFTA_RULE_EXPRESSIONS` for a `match_tcp_dport(1000).accept()`
    /// rule. 224 bytes. The kernel form has `NLA_F_NESTED` bits
    /// stripped, attributes sorted by type within each nest, and
    /// canonicalized `NFT_REG_1` (1) register IDs throughout.
    const PLAN178_KERNEL_HEX_FOR_PORT_1000: &str = "24000100090001006d6574610000000014000200080002000000001008000100000000012c00010008000100636d700020000200080001000000000108000200000000000c0003000500010006000000340001000c0001007061796c6f6164002400020008000100000000010800020000000002080003000000000208000400000000022c00010008000100636d700020000200080001000000000108000200000000000c0003000600010003e80000300001000e000100696d6d6564696174650000001c0002000800010000000000100002000c0002000800010000000001";

    fn hex_decode(s: &str) -> Vec<u8> {
        let mut out = Vec::with_capacity(s.len() / 2);
        let bytes = s.as_bytes();
        let mut i = 0;
        while i + 2 <= bytes.len() {
            let h = (bytes[i] as char).to_digit(16).unwrap();
            let l = (bytes[i + 1] as char).to_digit(16).unwrap();
            out.push(((h << 4) | l) as u8);
            i += 2;
        }
        out
    }

    #[test]
    fn normalize_tlv_collapses_writer_vs_kernel_to_equal() {
        // Build the same rule the kernel fixture above represents.
        use super::super::super::types::Rule;
        let r = Rule::new("filter_rec", "input")
            .match_tcp_dport(1000)
            .accept();
        let declared = lower_to_expression_bytes(&r);
        let kernel = hex_decode(PLAN178_KERNEL_HEX_FOR_PORT_1000);

        // Pre-normalize, the raw forms diverge (NLA_F_NESTED bits +
        // attribute ordering). After normalize, they must match —
        // that's the contract `NftablesConfig::diff` now relies on.
        assert_ne!(
            declared, kernel,
            "raw writer-side and kernel-side bytes should differ pre-normalize"
        );
        let n_declared = normalize_tlv(&declared);
        let n_kernel = normalize_tlv(&kernel);
        assert_eq!(
            n_declared, n_kernel,
            "normalize_tlv must canonicalize writer-side and kernel-side bytes \
             for the same logical rule to equal bytes"
        );
    }

    #[test]
    fn normalize_tlv_idempotent() {
        let kernel = hex_decode(PLAN178_KERNEL_HEX_FOR_PORT_1000);
        let once = normalize_tlv(&kernel);
        let twice = normalize_tlv(&once);
        assert_eq!(once, twice, "normalize_tlv must be idempotent");
    }

    #[test]
    fn normalize_tlv_differs_when_values_actually_differ() {
        // Two rules with different ports — must still diverge after
        // normalize, otherwise the diff would silently miss real
        // expression changes.
        use super::super::super::types::Rule;
        let r_a = Rule::new("filter_rec", "input").match_tcp_dport(1000).accept();
        let r_b = Rule::new("filter_rec", "input").match_tcp_dport(9000).accept();
        let a = normalize_tlv(&lower_to_expression_bytes(&r_a));
        let b = normalize_tlv(&lower_to_expression_bytes(&r_b));
        assert_ne!(a, b);
    }

    #[test]
    fn normalize_tlv_empty_input() {
        assert!(normalize_tlv(&[]).is_empty());
    }

    #[test]
    fn normalize_tlv_garbage_input_passes_through() {
        // Truncated TLV (claims len=100 in a 4-byte buffer) — bail
        // out and return the bytes verbatim. The diff path then
        // sees them as unequal to anything else, which is the
        // correct conservative behavior.
        let garbage = vec![0x64, 0x00, 0x01, 0x00];
        assert_eq!(normalize_tlv(&garbage), garbage);
    }
}
