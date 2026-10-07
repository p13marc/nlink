//! `NftablesDiff` — what changes between declared and current.

use std::collections::HashSet;

use super::types::{
    DeclaredChain, DeclaredFlowtable, DeclaredRule, DeclaredSet, DeclaredTable, NftablesConfig,
};
use super::super::expr::RuleExpr;
use super::super::types::{
    ChainInfo, Family, Hook, Policy, Priority, RuleInfo, Set, SetElement, SetInfo,
};
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
        // Plan 223 — netlink attribute nla_len / nla_type are kernel
        // native-endian (per `struct nlattr` in include/uapi/linux/netlink.h
        // and nlink's canonical `NlAttr` in `attr.rs` using zerocopy
        // native-endian). Was `from_le_bytes` — silently broken on
        // BE platforms.
        let len = u16::from_ne_bytes([bytes[pos], bytes[pos + 1]]) as usize;
        if len < 4 || pos + len > bytes.len() {
            return None;
        }
        let raw_type = u16::from_ne_bytes([bytes[pos + 2], bytes[pos + 3]]);
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
    // Native-endian, matching `try_walk_tlvs`'s reader above and the Plan 223
    // policy it documents. These were `to_le_bytes`, re-introducing on the
    // writer side the exact BE bug class Plan 223 closed on the reader side:
    // on a big-endian host `normalize_tlv(normalize_tlv(x)) != normalize_tlv(x)`,
    // because the second pass fails `try_walk_tlvs` and passes the LE bytes
    // through verbatim — so the idempotence test only passed by accident (#212).
    out.extend_from_slice(&len.to_ne_bytes());
    out.extend_from_slice(&ty.to_ne_bytes());
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
pub(crate) fn lower_to_expression_bytes(rule: &super::super::types::Rule) -> Vec<u8> {
    if rule.exprs.is_empty() {
        return Vec::new();
    }
    // Scratch builder: write the NFTA_RULE_EXPRESSIONS attribute,
    // then strip the 16-byte nlmsghdr + 4-byte attribute header
    // to get just the inner elem list (matches what the kernel
    // emits as the `NFTA_RULE_EXPRESSIONS` payload).
    let mut b = MessageBuilder::new(0, 0);
    super::super::expr::write_expressions_as(
        &mut b,
        &rule.exprs,
        super::super::expr::WireForm::Echo,
    );
    let raw = b.finish();
    // NlMsgHdr is 16 bytes, attribute header is 4 bytes.
    if raw.len() <= 20 {
        return Vec::new();
    }
    raw[20..].to_vec()
}

/// Kernel-assigned rule handle (`NFTA_RULE_HANDLE`).
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RuleHandle(pub u64);

/// Where an added or moved rule goes in its chain. Rule order is policy
/// (first match wins), so the diff says exactly where each rule lands.
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RulePlacement {
    /// At the end of the chain.
    Append,
    /// Immediately before the rule with this handle.
    Before(RuleHandle),
    /// Immediately after the rule with this handle.
    After(RuleHandle),
}

/// A declared rule to add, and where it goes.
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct RuleAdd {
    /// The rule.
    pub rule: DeclaredRule,
    /// Where it goes.
    pub placement: RulePlacement,
    /// Position in the order rule inserts must be sent (shared with
    /// [`RuleMove`]): inserts before the same anchor go in declared order,
    /// inserts after one in reverse.
    #[cfg_attr(feature = "serde", serde(skip))]
    pub(crate) seq: usize,
}

/// Why the diff deletes a rule and puts it back.
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum MoveReason {
    /// It references a set this diff deletes and recreates; the kernel
    /// refuses to delete a set a rule is bound to (`EBUSY`).
    BoundToRecreatedSet,
    /// It is installed out of declared order.
    Reorder,
}

/// A rule the diff deletes and re-inserts, keeping (or restoring) its place
/// in the chain.
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct RuleMove {
    /// Owning table.
    pub table: String,
    /// Owning family.
    pub family: Family,
    /// Chain.
    pub chain: String,
    /// Kernel handle of the rule being deleted.
    pub from: RuleHandle,
    /// Where the re-inserted rule goes.
    pub placement: RulePlacement,
    /// The rule to re-insert.
    pub rule: DeclaredRule,
    /// Why it moves.
    pub reason: MoveReason,
    /// See [`RuleAdd`].
    #[cfg_attr(feature = "serde", serde(skip))]
    pub(crate) seq: usize,
}

/// Elements to add to, or remove from, one set — with the [`Set`] they
/// belong to, since how an element is written depends on the set.
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct SetElementsChange {
    /// The set.
    pub set: Set,
    /// The elements.
    pub elements: Vec<SetElement>,
}

/// The result of comparing a declared [`NftablesConfig`] against
/// the kernel's current state. Apply via
/// [`Self::apply`](super::NftablesDiff::apply).
///
/// `is_empty()` returns true when declared and current already
/// agree (idempotent reapply).
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case"))]
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
#[must_use = "Diffs do nothing unless passed to `.apply()` or stringified via `Display`"]
pub struct NftablesDiff {
    /// Tables to create.
    pub tables_to_add: Vec<DeclaredTable>,
    /// Tables whose flags drifted — `(family, name, declared_flags)`. Applied
    /// as `NFT_MSG_NEWTABLE`, which the kernel treats as an update.
    ///
    /// Separate from [`Self::tables_to_add`] because every table in *that*
    /// collection has its whole contents (chains, rules, sets, flowtables)
    /// installed wholesale — routing an existing table through it would re-add
    /// everything it already has.
    ///
    /// `DeclaredTable::flags` (`.persist(true)`, `NFT_TABLE_F_DORMANT`) used to
    /// be applied only on create, so toggling a flag on an existing table
    /// produced an empty diff and a no-op apply (#208).
    pub tables_to_modify: Vec<(Family, String, u32)>,
    /// Tables to delete (family, name).
    pub tables_to_delete: Vec<(Family, String)>,
    /// Chains to create — (owning table, owning family, chain).
    pub chains_to_add: Vec<(String, Family, DeclaredChain)>,
    /// Chains whose *properties* drifted — (owning table, owning family,
    /// chain). Applied as `NFT_MSG_NEWCHAIN`, which the kernel treats as an
    /// update for an existing chain.
    ///
    /// Until 0.25 a chain's diff identity was its **name alone**: none of
    /// `hook` / `priority` / `policy` / `chain_type` / `device` were compared,
    /// even though `DeclaredChain` carries all five and `ChainInfo` parses all
    /// five back. So flipping a declared firewall from `policy(Accept)` to
    /// `policy(Drop)` produced an empty diff and a no-op apply — the operator
    /// believed the box was default-deny while it stayed default-allow (#200).
    pub chains_to_modify: Vec<(String, Family, DeclaredChain)>,
    /// Chains to delete — (table, family, name).
    pub chains_to_delete: Vec<(String, Family, String)>,
    /// Rules to add, each with its placement in the chain.
    pub rules_to_add: Vec<RuleAdd>,
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
    /// Declared rules to delete and put back in place.
    ///
    /// A set whose key type or flags changed is deleted and recreated,
    /// and the kernel refuses to delete a set a rule still references
    /// (`EBUSY`). So every keyed rule referencing it is deleted ahead of
    /// the set and re-added after the new one, immediately before the next
    /// rule in the chain that survives, so chain order — which is policy —
    /// is unchanged.
    pub rules_to_move: Vec<RuleMove>,
    /// Flowtables to add.
    pub flowtables_to_add: Vec<DeclaredFlowtable>,
    /// Flowtables to delete — (family, table, name).
    pub flowtables_to_delete: Vec<(Family, String, String)>,
    /// Sets to create — (owning table, owning family, set).
    pub sets_to_add: Vec<(String, Family, DeclaredSet)>,
    /// Sets to delete — (table, family, name).
    pub sets_to_delete: Vec<(String, Family, String)>,
    /// Sets whose declared size differs from the kernel's — (owning table,
    /// owning family, set). Applied in place (`NFT_MSG_NEWSET` without
    /// `NLM_F_EXCL`, kernel 6.5+), keeping the set's elements and the
    /// rules bound to it, in a batch [`apply`](Self::apply) commits ahead
    /// of everything else: the kernel checks element adds against the
    /// size the set has *before* the commit, so a grown set could not
    /// take its new elements in the same batch.
    pub sets_to_update: Vec<(String, Family, DeclaredSet)>,
    /// Set elements to add: the declared elements not yet in the kernel
    /// set.
    pub set_elements_to_add: Vec<SetElementsChange>,
    /// Set elements to remove: the kernel elements not declared (full
    /// element reconcile).
    pub set_elements_to_remove: Vec<SetElementsChange>,
}

impl NftablesDiff {
    /// `true` if declared state already matches kernel state.
    pub fn is_empty(&self) -> bool {
        self.tables_to_add.is_empty()
            && self.tables_to_modify.is_empty()
            && self.tables_to_delete.is_empty()
            && self.chains_to_add.is_empty()
            && self.chains_to_modify.is_empty()
            && self.chains_to_delete.is_empty()
            && self.rules_to_add.is_empty()
            && self.rules_to_delete.is_empty()
            && self.rules_to_replace.is_empty()
            && self.rules_to_move.is_empty()
            && self.flowtables_to_add.is_empty()
            && self.flowtables_to_delete.is_empty()
            && self.sets_to_add.is_empty()
            && self.sets_to_delete.is_empty()
            && self.sets_to_update.is_empty()
            && self.set_elements_to_add.is_empty()
            && self.set_elements_to_remove.is_empty()
    }

    /// Total number of changes (sum of all add/delete counts).
    pub fn change_count(&self) -> usize {
        self.tables_to_add.len()
            + self.tables_to_modify.len()
            + self.tables_to_delete.len()
            + self.chains_to_add.len()
            + self.chains_to_modify.len()
            + self.chains_to_delete.len()
            + self.rules_to_add.len()
            + self.rules_to_delete.len()
            + self.rules_to_replace.len()
            + self.rules_to_move.len()
            + self.flowtables_to_add.len()
            + self.flowtables_to_delete.len()
            + self.sets_to_add.len()
            + self.sets_to_delete.len()
            + self.sets_to_update.len()
            + self.set_elements_to_add.len()
            + self.set_elements_to_remove.len()
    }

    /// Render a one-line-per-change human summary. Useful for
    /// `tracing::info!` or CLI output.
    ///
    /// Equivalent to `format!("{self}")` — Plan 183 (0.18) made
    /// the [`std::fmt::Display`] impl share the same renderer.
    /// Prefer the `Display` form (`diff.to_string()` /
    /// `format!("{diff}")`) for new code.
    #[deprecated(
        since = "0.19.0",
        note = "use `Display` via `format!(\"{}\")` or `diff.to_string()` instead — Plan 188 §2.6"
    )]
    pub fn summary(&self) -> String {
        let mut lines = Vec::new();
        for t in &self.tables_to_add {
            lines.push(format!("+ table {:?} {}", t.family(), t.name()));
        }
        for (fam, name, flags) in &self.tables_to_modify {
            lines.push(format!("~ table {fam:?} {name} (flags={flags:#x})"));
        }
        for (fam, name) in &self.tables_to_delete {
            lines.push(format!("- table {fam:?} {name}"));
        }
        for (tbl, fam, c) in &self.chains_to_add {
            lines.push(format!("+ chain {fam:?} {tbl}/{}", c.name()));
        }
        for (tbl, fam, c) in &self.chains_to_modify {
            lines.push(format!(
                "~ chain {fam:?} {tbl}/{} (policy={:?} hook={:?} priority={:?})",
                c.name(),
                c.policy(),
                c.hook(),
                c.priority(),
            ));
        }
        for (tbl, fam, name) in &self.chains_to_delete {
            lines.push(format!("- chain {fam:?} {tbl}/{name}"));
        }
        for add in &self.rules_to_add {
            let r = &add.rule;
            let key = r.handle_key().unwrap_or("<anonymous>");
            lines.push(format!(
                "+ rule {:?} {}/{} [{}]{}",
                r.family(),
                r.table(),
                r.chain(),
                key,
                placement_suffix(add.placement),
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
        for m in &self.rules_to_move {
            let key = m.rule.handle_key().unwrap_or("<anonymous>");
            let why = match m.reason {
                MoveReason::BoundToRecreatedSet => "its set is recreated",
                MoveReason::Reorder => "out of declared order",
            };
            lines.push(format!(
                "~ rule {:?} {}/{} (handle={} key={key}, re-added: {why}){}",
                m.family,
                m.table,
                m.chain,
                m.from.0,
                placement_suffix(m.placement),
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
        for (tbl, fam, s) in &self.sets_to_add {
            lines.push(format!(
                "+ set {fam:?} {tbl}/{} ({} element{})",
                s.name(),
                s.elements().len(),
                if s.elements().len() == 1 { "" } else { "s" },
            ));
        }
        for (tbl, fam, name) in &self.sets_to_delete {
            lines.push(format!("- set {fam:?} {tbl}/{name}"));
        }
        for (tbl, fam, s) in &self.sets_to_update {
            lines.push(format!(
                "~ set {fam:?} {tbl}/{} (size={})",
                s.name(),
                s.size().map_or_else(|| "-".to_string(), |n| n.to_string()),
            ));
        }
        for c in &self.set_elements_to_add {
            lines.push(format!(
                "+ {} element{} {:?} {}/{}",
                c.elements.len(),
                if c.elements.len() == 1 { "" } else { "s" },
                c.set.family,
                c.set.table(),
                c.set.name(),
            ));
        }
        for c in &self.set_elements_to_remove {
            lines.push(format!(
                "- {} element{} {:?} {}/{}",
                c.elements.len(),
                if c.elements.len() == 1 { "" } else { "s" },
                c.set.family,
                c.set.table(),
                c.set.name(),
            ));
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

/// `Display` mirrors [`NftablesDiff::summary`] so callers can
/// `println!("{diff}")` directly. Plan 183.
impl std::fmt::Display for NftablesDiff {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Plan 188 §2.6 — `summary()` is deprecated in 0.19 in
        // favor of this Display impl. Internal delegation is
        // allowed; users are on the Display path.
        #[allow(deprecated)]
        f.write_str(&self.summary())
    }
}

/// ` (before handle=N)` / ` (after handle=N)` for a positioned rule.
fn placement_suffix(placement: RulePlacement) -> String {
    match placement {
        RulePlacement::Append => String::new(),
        RulePlacement::Before(h) => format!(" (before handle={})", h.0),
        RulePlacement::After(h) => format!(" (after handle={})", h.0),
    }
}

/// Has a declared chain's shape drifted from what the kernel holds?
///
/// Compares all five properties `DeclaredChain` carries and `ChainInfo` parses
/// back. A declared `None` means "not specified" and is not treated as drift —
/// the config is only asserting the properties it names, so a config that
/// doesn't mention a policy won't fight a policy set out-of-band.
fn chain_has_drifted(declared: &DeclaredChain, current: &ChainInfo) -> bool {
    fn drifted<T: PartialEq>(declared: Option<T>, current: Option<T>) -> bool {
        // Only a declared value can drift; an unspecified one is not a claim.
        declared.is_some_and(|d| current != Some(d))
    }

    drifted(declared.hook().map(Hook::to_u32), current.hook)
        || drifted(declared.priority().map(Priority::to_i32), current.priority)
        || drifted(declared.policy().map(Policy::to_u32), current.policy)
        || drifted(declared.chain_type(), current.chain_type)
        || drifted(declared.device(), current.device.as_deref())
}

/// Has a declared set's shape drifted from what the kernel holds?
///
/// Sets were matched by **name alone**, so changing a set's key type,
/// or adding `NFT_SET_INTERVAL`/`constant`, produced an empty diff
/// while every rule matching `@set` silently mismatched (#275). Chains
/// (#200), tables and flowtables (#208) all got this treatment; sets
/// were left out of that pass.
///
/// Unlike a chain, a set's key type and length cannot be changed in
/// place — `nf_tables_newset` returns `EEXIST` for an existing name and
/// there is no "update" — so drift means delete and recreate, which
/// also discards its elements. They are re-added from the declaration
/// in the same transaction.
fn set_has_drifted(declared: &DeclaredSet, current: &SetInfo) -> bool {
    declared.key_type().type_id() != current.key_type
        || declared.key_type().len() != current.key_len
        || declared.flags() != current.flags
}

/// Does `rule` reference the set `set`? A plain lookup decodes typed; an
/// inverted or map lookup, and a `dynset`, stay `Unknown` but carry the set
/// name as their first attribute (`NFTA_LOOKUP_SET`, `NFTA_DYNSET_SET_NAME`).
fn references_set(rule: &RuleInfo, set: &str) -> bool {
    use crate::netlink::attr::{AttrIter, get};
    rule.expressions().iter().any(|e| match e {
        RuleExpr::Lookup { set: s, .. } => s == set,
        RuleExpr::Unknown { name, data } if name == "lookup" || name == "dynset" => {
            AttrIter::new(data)
                .any(|(attr, payload)| attr == 1 && get::string(payload).ok() == Some(set))
        }
        _ => false,
    })
}

/// Does a declared rule match the kernel rule with its key? Bodies are
/// compared after `normalize_tlv` and with the live state the kernel echoes
/// (counter values, quota consumption) zeroed; the human comment — what
/// follows `nlink:<key> ` — must match too.
fn rule_matches(declared: &DeclaredRule, kernel: &RuleInfo) -> bool {
    let canon = |bytes: &[u8]| super::rules::canonicalize_for_compare(normalize_tlv(bytes));
    let declared_body = canon(&lower_to_expression_bytes(&declared.body));
    let kernel_body = canon(&kernel.expression_bytes);
    if declared_body != kernel_body {
        tracing::trace!(
            table = %declared.table(),
            chain = %declared.chain(),
            key = ?declared.handle_key(),
            declared_hex = %hex_dump(&declared_body),
            kernel_hex = %hex_dump(&kernel_body),
            "rule body differs from the kernel's after normalization",
        );
        return false;
    }
    let kernel_comment = kernel
        .comment_text
        .as_deref()
        .and_then(super::super::userdata::human_comment);
    declared.body.comment.as_deref() == kernel_comment
}

/// The elements to add to and remove from an existing set.
///
/// A plain set compares element identities (key, range end, catch-all). An
/// interval set compares ranges: if the kernel's ranges, merged where they
/// touch, are the declared ones merged the same way, nothing changes —
/// however the kernel happens to split them. Otherwise the kernel ranges
/// that are not declared go, and the declared ones the kernel does not hold
/// come — the removals are sent first, so a range that grows is replaced
/// in one batch.
fn element_changes(
    declared: &DeclaredSet,
    current: &[SetElement],
) -> (Vec<SetElement>, Vec<SetElement>) {
    use super::super::interval;
    if declared.flags().contains(super::super::SetFlags::INTERVAL) {
        let wanted: Vec<interval::Range> = declared
            .wire_elements()
            .iter()
            .map(interval::range_of)
            .collect();
        let held: Vec<interval::Range> = current.iter().map(interval::range_of).collect();
        if interval::canonicalize(held.clone()) == wanted {
            return (Vec::new(), Vec::new());
        }
        let to_add = wanted
            .iter()
            .filter(|r| !held.contains(r))
            .map(interval::element_of)
            .collect();
        let to_remove = held
            .iter()
            .filter(|r| !wanted.contains(r))
            .map(interval::element_of)
            .collect();
        return (to_add, to_remove);
    }
    let declared_ids: HashSet<_> = declared.elements().iter().map(SetElement::identity).collect();
    let current_ids: HashSet<_> = current.iter().map(SetElement::identity).collect();
    let to_add = declared
        .elements()
        .iter()
        .filter(|e| !current_ids.contains(&e.identity()))
        .cloned()
        .collect();
    let to_remove = current
        .iter()
        .filter(|e| !declared_ids.contains(&e.identity()))
        .cloned()
        .collect();
    (to_add, to_remove)
}

/// Has a declared set's size drifted? Unlike the key and flags, a size
/// can be changed in place, so this is reported separately. An
/// undeclared size is not a claim: the kernel gives every set a `dynset`
/// writes to a size of 65535, and that is not the config's business.
fn set_size_has_drifted(declared: &DeclaredSet, current: &SetInfo) -> bool {
    declared.size().is_some_and(|size| current.size != Some(size))
}

/// Options controlling [`NftablesConfig::diff_with_options`].
///
/// Mirrors [`DiffOptions`](crate::netlink::config::DiffOptions) on the
/// `NetworkConfig` side.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct NftDiffOptions {
    /// Delete tables that exist in the kernel but are not declared in this
    /// config ("full reconcile"). Default `false`.
    ///
    /// # This is extremely destructive — read before enabling
    ///
    /// `list_tables()` is unscoped: it returns **every table in every
    /// family**, with no ownership marker. `NFT_MSG_DELTABLE` cascades — all
    /// chains, rules, sets and flowtables in the table go with it.
    ///
    /// So on any host that also runs Docker, firewalld, libvirt or kube-proxy,
    /// a purging apply of a config that declares only your own table will
    /// atomically destroy `ip nat` (Docker), `inet firewalld`, `ip6 filter`,
    /// and everything else on the box — the host loses its firewall and NAT
    /// rules in a single commit.
    ///
    /// **Until 0.25 this was the unconditional default** (#190): `diff()`
    /// scheduled every foreign table for deletion and `apply()` committed it.
    /// It is now opt-in, and reachable only through the explicit
    /// `diff_with_options` → inspect the diff → `apply` flow, so you always
    /// see the `-` lines before anything is deleted.
    ///
    /// If you enable this, scope your config to a netns (`nlink::lab` does),
    /// or be certain you own every table on the host.
    pub purge_tables: bool,
    /// Enforce declared rule order. Default `true`.
    ///
    /// First match wins, so order is policy: a rule declared between two
    /// installed rules is inserted there, and installed rules found out of
    /// order are moved — as few as possible (the longest run already in
    /// order stays). Off, installed rules stay wherever they are and only
    /// new rules are placed.
    pub enforce_rule_order: bool,
}

impl Default for NftDiffOptions {
    fn default() -> Self {
        Self {
            purge_tables: false,
            enforce_rule_order: true,
        }
    }
}

impl NftDiffOptions {
    /// Enforce declared rule order (the default) or leave installed rules
    /// where they are. See [`Self::enforce_rule_order`].
    pub fn enforce_rule_order(mut self, on: bool) -> Self {
        self.enforce_rule_order = on;
        self
    }

    /// Enable/disable purging of undeclared tables. See [`Self::purge_tables`]
    /// — it is destructive and unscoped.
    pub fn purge_tables(mut self, on: bool) -> Self {
        self.purge_tables = on;
        self
    }
}

impl NftablesConfig {
    /// Compute the diff between this declared config and the
    /// kernel's current state.
    ///
    /// **Never deletes tables.** Tables present in the kernel but absent from
    /// this config are left alone. To remove them, opt in explicitly with
    /// [`diff_with_options`](Self::diff_with_options) +
    /// [`NftDiffOptions::purge_tables`] — and read that method's warning first
    /// (#190).
    ///
    /// # Rule identity and order
    ///
    /// A rule is identified by the key stored in its comment
    /// (`nlink:<key>`): the `handle_key` given to `rule_keyed`, or — for a
    /// rule declared with `rule` — a key derived from its chain, body and
    /// comment. A declared rule whose body or comment changed is replaced in
    /// place; one that is gone is deleted; rules nlink did not write are
    /// left alone unless the chain is
    /// [`exclusive`](super::DeclaredChainBuilder::exclusive). Each chain is
    /// brought to declared order with as few moves as possible
    /// ([`NftDiffOptions::enforce_rule_order`]). Live state the kernel
    /// echoes — counter values, quota consumption — is not drift.
    ///
    /// The config is [validated](Self::validate) first.
    pub async fn diff(&self, conn: &Connection<Nftables>) -> Result<NftablesDiff> {
        self.diff_with_options(conn, &NftDiffOptions::default())
            .await
    }

    /// [`diff`](Self::diff), with table purging optionally enabled.
    ///
    /// See [`NftDiffOptions::purge_tables`] — it deletes every kernel table
    /// this config does not declare, across every family, cascading to their
    /// chains, rules and sets.
    pub async fn diff_with_options(
        &self,
        conn: &Connection<Nftables>,
        options: &NftDiffOptions,
    ) -> Result<NftablesDiff> {
        self.validate()?;
        let mut diff = NftablesDiff::default();
        // Order in which rule inserts (new and moved) are sent; see
        // `RuleAdd::seq`.
        let mut seq = 0usize;

        // Index declared by (family, name) for fast lookup.
        let declared_tables: HashSet<(Family, &str)> = self
            .tables
            .iter()
            .map(|t| (t.family(), t.name()))
            .collect();

        // Current kernel state.
        let current_tables = conn.list_tables().await?;

        // Pass 1: tables to add (declared but not current), and tables whose
        // flags drifted.
        //
        // Table identity used to be (family, name) alone: `DeclaredTable::flags`
        // — set via `.persist(true)` / `NFT_TABLE_F_DORMANT` — was applied only
        // on create, even though `Table::flags` is parsed back from the dump.
        // So toggling `.persist(true)` -> `.persist(false)`, or setting DORMANT
        // to disable a table's chains without deleting it, produced an empty
        // diff and a no-op apply; the flag never changed (#208).
        //
        // NFT_MSG_NEWTABLE updates an existing table, so a flag change reuses
        // the add path rather than needing a delete+recreate (which would
        // cascade away every chain and rule inside).
        // Flag drift gets its own collection, deliberately NOT `tables_to_add`:
        // every table in `tables_to_add` has its whole contents promoted and
        // installed wholesale below, so routing an *existing* table through it
        // would re-add every chain and rule it already has.
        for declared in &self.tables {
            match current_tables
                .iter()
                .find(|t| t.family == declared.family() && t.name == declared.name())
            {
                None => diff.tables_to_add.push(declared.clone()),
                Some(current) if current.flags != declared.flags() => {
                    diff.tables_to_modify
                        .push((declared.family(), declared.name().to_string(), declared.flags()));
                }
                Some(_) => {}
            }
        }

        // Pass 2: tables to delete (current but not declared).
        //
        // Opt-in only. `current_tables` is EVERY table in EVERY family with no
        // ownership marker, and DELTABLE cascades — so doing this by default
        // meant a config declaring one table atomically wiped Docker's `ip
        // nat`, firewalld's `inet firewalld`, and every other table on the box
        // (#190).
        if options.purge_tables {
            for current in &current_tables {
                if !declared_tables.contains(&(current.family, current.name.as_str())) {
                    diff.tables_to_delete
                        .push((current.family, current.name.clone()));
                }
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
                for rule in super::rules::effective_rules(declared.rules()) {
                    diff.rules_to_add.push(RuleAdd {
                        rule,
                        placement: RulePlacement::Append,
                        seq,
                    });
                    seq += 1;
                }
                for f in declared.flowtables() {
                    diff.flowtables_to_add.push(f.clone());
                }
                for s in declared.sets() {
                    diff.sets_to_add.push((
                        declared.name().to_string(),
                        declared.family(),
                        s.clone(),
                    ));
                    if !s.elements().is_empty() {
                        diff.set_elements_to_add.push(SetElementsChange {
                            set: s.to_set(declared.name(), declared.family()),
                            elements: s.wire_elements(),
                        });
                    }
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

            for c in declared.chains() {
                match chains_in_table.iter().find(|k| k.name == c.name()) {
                    None => {
                        diff.chains_to_add.push((
                            declared.name().to_string(),
                            declared.family(),
                            c.clone(),
                        ));
                    }
                    // The chain exists. Its *properties* may still have
                    // drifted — and until 0.25 nothing compared them, so a
                    // chain's identity was its name alone. Flipping a declared
                    // firewall from policy(Accept) to policy(Drop) produced an
                    // empty diff and a no-op apply: the operator believed the
                    // box was default-deny while it stayed default-allow
                    // (#200). Same silence for a changed hook or priority.
                    Some(current) if chain_has_drifted(c, current) => {
                        diff.chains_to_modify.push((
                            declared.name().to_string(),
                            declared.family(),
                            c.clone(),
                        ));
                    }
                    Some(_) => {}
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

            // Flowtables: name-based identity, like chains.
            // Lookup into the hoisted index (Plan 164).
            let fts_in_table: &[&super::super::types::Flowtable] = flowtables_by_table
                .get(&(declared.family(), declared.name().to_string()))
                .map(|v| v.as_slice())
                .unwrap_or(&[]);
            let declared_ft_names: HashSet<&str> =
                declared.flowtables().iter().map(|f| f.name()).collect();
            for f in declared.flowtables() {
                match fts_in_table.iter().find(|k| k.name == f.name()) {
                    None => diff.flowtables_to_add.push(f.clone()),
                    // Same name-only-identity gap as chains: `Flowtable` from
                    // the dump carries devs/priority/flags and
                    // `DeclaredFlowtable` declares all three, but nothing
                    // compared them. Adding a device to a declared flowtable,
                    // or toggling hw_offload, produced an empty diff (#208).
                    //
                    // NFT_MSG_NEWFLOWTABLE updates an existing flowtable, so
                    // this reuses the add path.
                    Some(current)
                        if f.devs() != current.devs.as_slice()
                            || f.priority() != current.priority
                            || f.flags() != current.flags =>
                    {
                        diff.flowtables_to_add.push(f.clone());
                    }
                    Some(_) => {}
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

            // Sets: name-based identity, like chains/flowtables.
            // Server-side table-scoped (Plan 181), so this is one
            // round-trip per declared table — cheaper than a
            // kernel-wide GETSET dump indexed in the loop.
            let current_sets = conn
                .list_sets_in(declared.name(), declared.family())
                .await?;
            let declared_set_names: HashSet<&str> =
                declared.sets().iter().map(|s| s.name()).collect();
            let current_set_names: HashSet<&str> =
                current_sets.iter().map(|s| s.name.as_str()).collect();

            // Sets this diff deletes and recreates (key type / flags drift).
            let mut recreated: HashSet<&str> = HashSet::new();
            for s in declared.sets() {
                let current_set = current_sets.iter().find(|c| c.name == s.name());
                if let Some(current) = current_set
                    && set_has_drifted(s, current)
                {
                    recreated.insert(s.name());
                    // Recreate: delete first, then add with the
                    // declared shape and all of its elements.
                    diff.sets_to_delete.push((
                        declared.name().to_string(),
                        declared.family(),
                        s.name().to_string(),
                    ));
                    diff.sets_to_add.push((
                        declared.name().to_string(),
                        declared.family(),
                        s.clone(),
                    ));
                    if !s.elements().is_empty() {
                        diff.set_elements_to_add.push(SetElementsChange {
                            set: s.to_set(declared.name(), declared.family()),
                            elements: s.wire_elements(),
                        });
                    }
                    continue;
                }
                if let Some(current) = current_set
                    && set_size_has_drifted(s, current)
                {
                    diff.sets_to_update.push((
                        declared.name().to_string(),
                        declared.family(),
                        s.clone(),
                    ));
                }
                if current_set_names.contains(s.name()) {
                    // Set exists on both sides → element-level diff.
                    // Read the kernel's current elements and compute
                    // the symmetric difference on raw key bytes.
                    let current_elems = conn
                        .list_set_elements(declared.name(), s.name(), declared.family())
                        .await?;
                    let (to_add, to_remove) = element_changes(s, &current_elems);
                    if !to_add.is_empty() {
                        diff.set_elements_to_add.push(SetElementsChange {
                            set: s.to_set(declared.name(), declared.family()),
                            elements: to_add,
                        });
                    }

                    if !to_remove.is_empty() {
                        diff.set_elements_to_remove.push(SetElementsChange {
                            set: s.to_set(declared.name(), declared.family()),
                            elements: to_remove,
                        });
                    }
                } else {
                    // Set is new in an existing table → create it +
                    // install all declared elements.
                    diff.sets_to_add.push((
                        declared.name().to_string(),
                        declared.family(),
                        s.clone(),
                    ));
                    if !s.elements().is_empty() {
                        diff.set_elements_to_add.push(SetElementsChange {
                            set: s.to_set(declared.name(), declared.family()),
                            elements: s.wire_elements(),
                        });
                    }
                }
            }

            // Kernel sets we no longer declare → delete (full
            // reconcile, same as chains/flowtables). Sets in tables
            // we don't manage never reach here.
            for s in &current_sets {
                if !declared_set_names.contains(s.name.as_str()) {
                    diff.sets_to_delete.push((
                        declared.name().to_string(),
                        declared.family(),
                        s.name.clone(),
                    ));
                }
            }

            // Rules. Identity is the key in each rule's `nlink:<key>`
            // comment — derived from the content for a rule declared
            // without one — and declared order is enforced per chain,
            // moving as few rules as possible (`plan_chain`). After the
            // sets, because a rule bound to a set this diff recreates has
            // to move out of its way: DELSET on a bound set is EBUSY.
            let current_rules = conn
                .list_rules(declared.name(), declared.family())
                .await?;
            let effective = super::rules::effective_rules(declared.rules());
            let mut chain_names: Vec<&str> =
                declared.chains().iter().map(|c| c.name()).collect();
            for rule in &effective {
                if !chain_names.contains(&rule.chain()) {
                    chain_names.push(rule.chain());
                }
            }
            for chain_name in chain_names {
                let exclusive = declared
                    .chains()
                    .iter()
                    .any(|c| c.name() == chain_name && c.exclusive());
                let kernel_rules: Vec<&RuleInfo> = current_rules
                    .iter()
                    .filter(|r| r.chain == chain_name)
                    .collect();
                let declared_rules: Vec<&DeclaredRule> = effective
                    .iter()
                    .filter(|r| r.chain() == chain_name)
                    .collect();
                let slots: Vec<super::rules::KernelSlot> = kernel_rules
                    .iter()
                    .map(|kr| {
                        let bound = recreated.iter().any(|set| references_set(kr, set));
                        if bound && kr.key.is_none() && !exclusive {
                            // nlink cannot put it back, so the DELSET will be
                            // EBUSY. Say why before it happens.
                            tracing::warn!(
                                table = %declared.name(),
                                chain = chain_name,
                                handle = kr.handle,
                                "a rule nlink does not manage references a set this diff \
                                 recreates; the apply will fail with EBUSY until that rule \
                                 is removed",
                            );
                        }
                        super::rules::KernelSlot {
                            handle: kr.handle,
                            key: kr.key.clone(),
                            forced: bound && kr.key.is_some(),
                        }
                    })
                    .collect();
                let keys: Vec<&str> = declared_rules
                    .iter()
                    .map(|r| r.handle_key().expect("effective rules all have keys"))
                    .collect();
                let plan = super::rules::plan_chain(
                    &slots,
                    &keys,
                    |i, pos| !rule_matches(declared_rules[i], kernel_rules[pos]),
                    exclusive,
                    options.enforce_rule_order,
                );

                for handle in plan.deletes {
                    diff.rules_to_delete.push((
                        declared.name().to_string(),
                        declared.family(),
                        chain_name.to_string(),
                        RuleHandle(handle),
                    ));
                }
                for insert in plan.inserts {
                    let rule = declared_rules[insert.declared].clone();
                    match insert.from {
                        None => diff.rules_to_add.push(RuleAdd {
                            rule,
                            placement: insert.placement,
                            seq,
                        }),
                        Some(from) => diff.rules_to_move.push(RuleMove {
                            table: declared.name().to_string(),
                            family: declared.family(),
                            chain: chain_name.to_string(),
                            from: RuleHandle(from),
                            placement: insert.placement,
                            rule,
                            reason: insert.reason,
                            seq,
                        }),
                    }
                    seq += 1;
                }
                for (handle, i) in plan.replaces {
                    diff.rules_to_replace.push((
                        declared.name().to_string(),
                        declared.family(),
                        chain_name.to_string(),
                        RuleHandle(handle),
                        declared_rules[i].clone(),
                    ));
                }
            }
        }

        Ok(diff)
    }
}

#[cfg(test)]
#[allow(deprecated)] // Plan 188 §2.6 — test the deprecated `summary()` shape during its window
mod tests {
    use super::*;
    use crate::netlink::nftables::{SetFlags, SetKeyType};
    use crate::netlink::nftables::config::types::DeclaredSet;

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

    // ---- Plan 198 — declarative sets + element diff ----

    #[test]
    fn declared_set_builder_collects_key_type_flags_and_elements() {
        use super::super::super::types::SetKeyType;
        let cfg = NftablesConfig::new().table("filter", Family::Inet, |t| {
            t.set("allowed_v4", |s| {
                s.key_type(SetKeyType::Ipv4Addr)
                    .constant()
                    .ipv4(std::net::Ipv4Addr::new(10, 0, 0, 1))
                    .port(80) // (mixed key not realistic, just exercises the builder)
            })
        });
        let set = &cfg.tables()[0].sets()[0];
        assert_eq!(set.name(), "allowed_v4");
        assert_eq!(*set.key_type(), SetKeyType::Ipv4Addr);
        assert_eq!(set.flags(), SetFlags::CONSTANT, "constant() must set the flag");
        assert_eq!(set.elements().len(), 2);
    }

    #[test]
    fn set_and_element_collections_count_and_render() {
        use super::super::super::types::{SetElement, SetKeyType};
        let cfg = NftablesConfig::new().table("filter", Family::Inet, |t| {
            t.set("s", |s| s.key_type(SetKeyType::InetService))
        });
        let declared = cfg.tables()[0].sets()[0].clone();

        let mut d = NftablesDiff::default();
        d.sets_to_add
            .push(("filter".to_string(), Family::Inet, declared));
        d.sets_to_delete
            .push(("filter".to_string(), Family::Inet, "stale".to_string()));
        let set = d.sets_to_add[0].2.to_set("filter", Family::Inet);
        d.set_elements_to_add.push(SetElementsChange {
            set: set.clone(),
            elements: vec![SetElement::port(80)],
        });
        d.set_elements_to_remove.push(SetElementsChange {
            set,
            elements: vec![SetElement::port(81), SetElement::port(82)],
        });

        assert!(!d.is_empty());
        assert_eq!(d.change_count(), 4);
        let s = d.summary();
        assert!(s.contains("+ set"), "summary: {s}");
        assert!(s.contains("- set"), "summary: {s}");
        assert!(s.contains("+ 1 element"), "summary: {s}");
        assert!(s.contains("- 2 elements"), "summary: {s}");
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

    /// Walk `bytes` as a TLV stream → `(type_without_hint_bits, payload)`.
    fn walk(bytes: &[u8]) -> Vec<(u16, &[u8])> {
        let mut out = Vec::new();
        let mut pos = 0;
        while pos + 4 <= bytes.len() {
            // Plan 223 — kernel-native endian.
            let len = u16::from_ne_bytes([bytes[pos], bytes[pos + 1]]) as usize;
            let ty = u16::from_ne_bytes([bytes[pos + 2], bytes[pos + 3]]) & 0x3fff;
            if len < 4 || pos + len > bytes.len() {
                break;
            }
            out.push((ty, &bytes[pos + 4..pos + len]));
            pos += (len + 3) & !3;
        }
        out
    }

    /// True if the lowered expression list contains an expression named
    /// `expr_name` whose `NFTA_EXPR_DATA` carries inner attribute `attr`.
    fn expr_has_attr(body: &[u8], expr_name: &str, attr: u16) -> bool {
        // body = list of NFTA_LIST_ELEM (type 1), each wrapping one expr.
        walk(body).into_iter().any(|(_, elem)| {
            let mut name = None;
            let mut data = None;
            for (t, p) in walk(elem) {
                match t {
                    1 => name = Some(p.split(|&b| b == 0).next().unwrap_or(p)),
                    2 => data = Some(p),
                    _ => {}
                }
            }
            name == Some(expr_name.as_bytes())
                && data.is_some_and(|d| walk(d).iter().any(|(t, _)| *t == attr))
        })
    }

    #[test]
    fn masked_match_lowers_bitwise_op() {
        use super::super::super::NFTA_BITWISE_OP;
        use super::super::super::types::Rule;
        use std::net::Ipv4Addr;
        let v4: Ipv4Addr = "10.1.2.3".parse().unwrap();
        let masked = lower_to_expression_bytes(
            &Rule::new("f", "input").match_saddr_v4(v4, 24).accept(),
        );
        assert!(
            expr_has_attr(&masked, "bitwise", NFTA_BITWISE_OP),
            "masked match must emit NFTA_BITWISE_OP"
        );
        // Exact match has no bitwise expr at all.
        let exact = lower_to_expression_bytes(
            &Rule::new("f", "input").match_saddr_v4(v4, 32).accept(),
        );
        assert!(
            !expr_has_attr(&exact, "bitwise", NFTA_BITWISE_OP),
            "exact match should emit no bitwise expr"
        );
    }

    #[test]
    fn nat_lowers_max_regs_and_flags() {
        use super::super::super::{
            NFTA_NAT_FLAGS, NFTA_NAT_REG_ADDR_MAX, NFTA_NAT_REG_PROTO_MAX,
        };
        use super::super::super::types::Rule;
        use std::net::Ipv6Addr;
        let target: Ipv6Addr = "fd30::1".parse().unwrap();
        let body = lower_to_expression_bytes(
            &Rule::new("n", "post").snat_v6(target, Some(8080)),
        );
        assert!(expr_has_attr(&body, "nat", NFTA_NAT_REG_ADDR_MAX));
        assert!(expr_has_attr(&body, "nat", NFTA_NAT_REG_PROTO_MAX));
        assert!(expr_has_attr(&body, "nat", NFTA_NAT_FLAGS));
    }

    /// Empty-NAT case (`NatExpr::snat(family)` with no addr, no port):
    /// `nft_nat_dump` skips `NFTA_NAT_FLAGS` when `priv->flags == 0`,
    /// so we mirror that — emitting `FLAGS=0` would reintroduce a
    /// phantom diff for any rule constructed via the internal builders
    /// without the fluent `Rule::snat_*` / `Rule::dnat_*` helpers.
    #[test]
    fn empty_nat_omits_flags() {
        use super::super::super::{NFTA_NAT_FLAGS, NFTA_NAT_REG_ADDR_MAX, NFTA_NAT_REG_PROTO_MAX};
        use super::super::super::expr::Expr;
        use super::super::super::types::{Family, NatExpr, Rule};
        let mut rule = Rule::new("n", "post");
        rule.exprs.push(Expr::Nat(NatExpr::snat(Family::Ip)));
        let body = lower_to_expression_bytes(&rule);
        assert!(
            !expr_has_attr(&body, "nat", NFTA_NAT_FLAGS),
            "empty NAT must NOT emit NFTA_NAT_FLAGS (kernel dump skips it when flags==0)"
        );
        assert!(
            !expr_has_attr(&body, "nat", NFTA_NAT_REG_ADDR_MAX),
            "empty NAT must NOT emit addr-max register"
        );
        assert!(
            !expr_has_attr(&body, "nat", NFTA_NAT_REG_PROTO_MAX),
            "empty NAT must NOT emit proto-max register"
        );
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

    // ---- Plan 183 — Display for NftablesDiff ----

    #[test]
    fn display_matches_summary() {
        let diff = NftablesDiff::default();
        assert_eq!(format!("{diff}"), diff.summary());

        use super::super::super::types::Family;
        let mut d = NftablesDiff::default();
        d.tables_to_delete.push((Family::Inet, "foo".to_string()));
        assert_eq!(format!("{d}"), d.summary());
    }

    // ====================================================================
    // #275 — declared sets were matched by name alone
    // ====================================================================

    fn set_info(key_type: &SetKeyType, flags: u32) -> SetInfo {
        let flags = SetFlags(flags);
        SetInfo {
            table: "t".to_string(),
            name: "s".to_string(),
            family: Family::Inet,
            flags,
            key_type: key_type.type_id(),
            key_len: key_type.len(),
            handle: 1,
            size: None,
        }
    }

    fn declared_set(key_type: SetKeyType, flags: u32) -> DeclaredSet {
        let flags = SetFlags(flags);
        DeclaredSet {
            name: "s".to_string(),
            key_type,
            flags,
            size: None,
            elements: Vec::new(),
        }
    }

    #[test]
    fn a_declared_size_drifts_only_against_a_different_kernel_size() {
        let mut declared = declared_set(SetKeyType::Ipv4Addr, 0);
        let mut current = set_info(&SetKeyType::Ipv4Addr, 0);

        // No declared size is no claim — not even against the 65535 the
        // kernel gives a set a `dynset` writes to.
        current.size = Some(65535);
        assert!(!set_size_has_drifted(&declared, &current));

        declared.size = Some(1024);
        assert!(set_size_has_drifted(&declared, &current));
        current.size = None;
        assert!(set_size_has_drifted(&declared, &current));
        current.size = Some(1024);
        assert!(!set_size_has_drifted(&declared, &current));

        // A size is changed in place, not by recreating the set.
        current.size = Some(16);
        assert!(!set_has_drifted(&declared, &current));
    }

    fn rule_info(expression_bytes: Vec<u8>) -> RuleInfo {
        RuleInfo {
            table: "t".to_string(),
            chain: "c".to_string(),
            family: Family::Ip,
            handle: 7,
            position: None,
            key: None,
            comment_text: None,
            userdata_raw: None,
            expression_bytes,
        }
    }

    #[test]
    fn references_set_sees_plain_inverted_and_dynset_references() {
        use crate::netlink::builder::MessageBuilder;
        use crate::netlink::nftables::{
            Expr, NFTA_EXPR_DATA, NFTA_EXPR_NAME, NFTA_LIST_ELEM, NFTA_LOOKUP_FLAGS,
            NFTA_LOOKUP_SET, NFTA_LOOKUP_SREG, Register, Rule,
        };

        let plain = Rule::new("t", "c").match_daddr_in_set("s");
        let plain = rule_info(lower_to_expression_bytes(&plain));
        assert!(references_set(&plain, "s"));
        assert!(!references_set(&plain, "other"));

        // `ip daddr != @s` decodes as Unknown (an inverted lookup is not
        // `RuleExpr::Lookup`), and still pins the set.
        let mut b = MessageBuilder::new(0, 0);
        let elem = b.nest_start(NFTA_LIST_ELEM | 0x8000);
        b.append_attr_str(NFTA_EXPR_NAME, "lookup");
        let data = b.nest_start(NFTA_EXPR_DATA | 0x8000);
        b.append_attr_str(NFTA_LOOKUP_SET, "s");
        b.append_attr_u32_be(NFTA_LOOKUP_SREG, Register::R0 as u32);
        b.append_attr_u32_be(NFTA_LOOKUP_FLAGS, 1);
        b.nest_end(data);
        b.nest_end(elem);
        let inverted = rule_info(b.as_bytes()[16..].to_vec());
        assert!(references_set(&inverted, "s"));

        let unrelated = rule_info(lower_to_expression_bytes(
            &Rule::new("t", "c").expressions(vec![Expr::Counter]),
        ));
        assert!(!references_set(&unrelated, "s"));
    }

    #[test]
    fn a_resize_renders_and_counts() {
        let mut d = NftablesDiff::default();
        let mut s = declared_set(SetKeyType::Ipv4Addr, 0);
        s.size = Some(4096);
        d.sets_to_update.push(("t".to_string(), Family::Ip, s));
        assert!(!d.is_empty());
        assert_eq!(d.change_count(), 1);
        assert!(d.to_string().contains("~ set Ip t/s (size=4096)"), "{d}");
    }

    #[test]
    fn a_set_that_matches_the_kernel_is_not_drift() {
        let declared = declared_set(SetKeyType::Ipv4Addr, 0);
        let current = set_info(&SetKeyType::Ipv4Addr, 0);
        assert!(!set_has_drifted(&declared, &current));
    }

    #[test]
    fn a_changed_key_type_is_drift() {
        // Sets were matched by name only, so this produced an empty
        // diff while every rule matching `@s` silently mismatched.
        let declared = declared_set(SetKeyType::InetService, 0);
        let current = set_info(&SetKeyType::Ipv4Addr, 0);
        assert!(set_has_drifted(&declared, &current));
    }

    #[test]
    fn a_changed_key_length_alone_is_drift() {
        // Two types can share a `type_id` band but differ in length;
        // the length is what `nft_lookup_init` validates the `sreg`
        // against, so it has to be compared in its own right.
        let declared = declared_set(SetKeyType::Ipv6Addr, 0);
        let mut current = set_info(&SetKeyType::Ipv6Addr, 0);
        current.key_len = 4;
        assert!(set_has_drifted(&declared, &current));
    }

    #[test]
    fn changed_flags_are_drift() {
        let declared = declared_set(SetKeyType::Ipv4Addr, crate::netlink::nftables::NFT_SET_CONSTANT);
        let current = set_info(&SetKeyType::Ipv4Addr, 0);
        assert!(set_has_drifted(&declared, &current));
    }

    #[test]
    fn a_concat_key_is_compared_by_both_id_and_length() {
        let concat = SetKeyType::Concat(vec![SetKeyType::Ipv4Addr, SetKeyType::InetService]);
        let declared = declared_set(concat.clone(), 0);
        assert!(!set_has_drifted(&declared, &set_info(&concat, 0)));
        // Same components, different order — a different key entirely.
        let swapped = SetKeyType::Concat(vec![SetKeyType::InetService, SetKeyType::Ipv4Addr]);
        assert!(set_has_drifted(&declared, &set_info(&swapped, 0)));
    }
}
