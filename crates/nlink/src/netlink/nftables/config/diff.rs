//! `NftablesDiff` — what changes between declared and current.

use std::collections::{HashMap, HashSet};

use super::super::expr::{ElementStatement, RuleExpr};
use super::super::object::{ObjectConfig, ObjectType};
use super::super::types::{
    ChainInfo, Family, RuleInfo, Set, SetElement, SetFlags, SetInfo, Verdict,
};
use super::types::{
    DeclaredChain, DeclaredFlowtable, DeclaredObject, DeclaredRule, DeclaredSet, DeclaredTable,
    NftablesConfig, SetElementMode,
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

/// Normalize a rule's expression list (`NFTA_RULE_EXPRESSIONS`' payload)
/// for byte-equality comparison. Both the declared body and the kernel's go
/// through it before the compare in `diff`, and the derived `~` keys hash
/// its output.
///
/// What may differ between nlink's writer and the kernel's echo without the
/// rule differing (Plan 178):
///
/// 1. the `NLA_F_NESTED` / `NLA_F_NET_BYTEORDER` bits, which the kernel does
///    not set when it echoes a rule: stripped;
/// 2. the order of attributes within a nest: sorted by type, at every
///    level;
/// 3. an empty attribute: a `*_PAD` before a 64-bit value on a kernel
///    without efficient unaligned access, or an empty nest (`masq`'s
///    `NFTA_EXPR_DATA`, #362; #484): dropped.
///
/// **Which attributes are nests is a schema, not a guess (#721).** The
/// expression list is a list of `NFTA_LIST_ELEM`, each an expression's name
/// and data. Within the data, only the attributes the kernel declares as
/// `NLA_NESTED` are walked: `cmp`'s and `immediate`'s data, `range`'s
/// bounds, `bitwise`'s mask, xor and data, `dynset`'s expressions. Each of
/// those holds a value (`NFTA_DATA_VALUE`, a leaf) or a verdict (a nest of
/// leaves). Everything else is a leaf. This used to recurse into any payload
/// that happened to parse as attributes. A 4-byte value such as `04 00 05
/// 00` (`ip daddr 4.0.5.0`) parses as one empty attribute, which was then
/// dropped, so `4.0.5.0` and `4.0.6.0` compared equal and a declared change
/// between them was never applied.
///
/// Expression order is kept: it is the rule's meaning. Malformed input at
/// any level is kept as it is, so the comparison still gives a definite
/// answer.
pub(crate) fn normalize_expressions(bytes: &[u8]) -> Vec<u8> {
    use crate::netlink::nftables::NFTA_LIST_ELEM;
    let Some(attrs) = walk(bytes) else {
        return bytes.to_vec();
    };
    let mut out = Vec::with_capacity(bytes.len());
    for (ty, payload) in attrs {
        match ty {
            NFTA_LIST_ELEM => emit_tlv(&mut out, ty, &normalize_expression(payload)),
            _ => emit_tlv(&mut out, ty, payload),
        }
    }
    out
}

/// One expression: its name, and its data normalized by the name's schema.
fn normalize_expression(bytes: &[u8]) -> Vec<u8> {
    use crate::netlink::nftables::{NFTA_EXPR_DATA, NFTA_EXPR_NAME};
    let Some(mut attrs) = walk(bytes) else {
        return bytes.to_vec();
    };
    attrs.sort_by_key(|(ty, _)| *ty);
    let name = attrs
        .iter()
        .find(|(ty, _)| *ty == NFTA_EXPR_NAME)
        .map(|(_, p)| p.strip_suffix(b"\0").unwrap_or(p))
        .unwrap_or_default();
    let mut out = Vec::with_capacity(bytes.len());
    for (ty, payload) in &attrs {
        match *ty {
            NFTA_EXPR_DATA => emit_tlv(&mut out, *ty, &normalize_expression_data(name, payload)),
            _ => emit_tlv(&mut out, *ty, payload),
        }
    }
    out
}

/// An expression's `NFTA_EXPR_DATA`: its attributes sorted, and those the
/// kernel declares nested walked by kind.
fn normalize_expression_data(name: &[u8], bytes: &[u8]) -> Vec<u8> {
    use crate::netlink::nftables::{
        NFTA_BITWISE_MASK, NFTA_BITWISE_XOR, NFTA_CMP_DATA, NFTA_DYNSET_EXPR,
        NFTA_DYNSET_EXPRESSIONS, NFTA_IMMEDIATE_DATA, NFTA_RANGE_FROM_DATA, NFTA_RANGE_TO_DATA,
    };
    /// `NFTA_BITWISE_DATA`: a shift's argument, `nft_data_attributes`.
    const NFTA_BITWISE_DATA: u16 = 7;
    enum Nest {
        Data,
        Expression,
        Expressions,
    }
    let nest = |ty: u16| match (name, ty) {
        (b"cmp", NFTA_CMP_DATA)
        | (b"immediate", NFTA_IMMEDIATE_DATA)
        | (b"range", NFTA_RANGE_FROM_DATA | NFTA_RANGE_TO_DATA)
        | (b"bitwise", NFTA_BITWISE_MASK | NFTA_BITWISE_XOR | NFTA_BITWISE_DATA) => Some(Nest::Data),
        (b"dynset", NFTA_DYNSET_EXPR) => Some(Nest::Expression),
        (b"dynset", NFTA_DYNSET_EXPRESSIONS) => Some(Nest::Expressions),
        _ => None,
    };
    let Some(mut attrs) = walk(bytes) else {
        return bytes.to_vec();
    };
    attrs.sort_by_key(|(ty, _)| *ty);
    let mut out = Vec::with_capacity(bytes.len());
    for (ty, payload) in &attrs {
        let normalized = match nest(*ty) {
            Some(Nest::Data) => normalize_data(payload),
            Some(Nest::Expression) => normalize_expression(payload),
            Some(Nest::Expressions) => normalize_expressions(payload),
            None => payload.to_vec(),
        };
        emit_tlv(&mut out, *ty, &normalized);
    }
    out
}

/// `nft_data_attributes`: a value, which is a leaf, or a verdict, a nest of
/// leaves.
fn normalize_data(bytes: &[u8]) -> Vec<u8> {
    use crate::netlink::nftables::NFTA_DATA_VERDICT;
    let Some(mut attrs) = walk(bytes) else {
        return bytes.to_vec();
    };
    attrs.sort_by_key(|(ty, _)| *ty);
    let mut out = Vec::with_capacity(bytes.len());
    for (ty, payload) in &attrs {
        if *ty == NFTA_DATA_VERDICT {
            let verdict = match walk(payload) {
                Some(mut leaves) => {
                    leaves.sort_by_key(|(ty, _)| *ty);
                    let mut buf = Vec::with_capacity(payload.len());
                    for (t, p) in &leaves {
                        emit_tlv(&mut buf, *t, p);
                    }
                    buf
                }
                None => payload.to_vec(),
            };
            emit_tlv(&mut out, *ty, &verdict);
        } else {
            emit_tlv(&mut out, *ty, payload);
        }
    }
    out
}

/// One level of attributes: `(type without its flag bits, payload)`, empty
/// ones dropped. `None` if `bytes` is not a well-formed attribute stream.
fn walk(bytes: &[u8]) -> Option<Vec<(u16, &[u8])>> {
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
        // NLA_F_NESTED (0x8000) and NLA_F_NET_BYTEORDER (0x4000) are parser
        // hints, not stored state.
        let ty = u16::from_ne_bytes([bytes[pos + 2], bytes[pos + 3]]) & !0xc000;
        let payload = &bytes[pos + 4..pos + len];
        if !payload.is_empty() {
            out.push((ty, payload));
        }
        pos += (len + 3) & !3;
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
        &super::super::expr::exprs_for_family(&rule.exprs, rule.family),
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
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RuleHandle(pub u64);

/// Where an added or moved rule goes in its chain. Rule order is policy
/// (first match wins), so the diff says exactly where each rule lands.
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
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
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
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
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum MoveReason {
    /// It references a set this diff deletes and recreates; the kernel
    /// refuses to delete a set a rule is bound to (`EBUSY`).
    BoundToRecreatedSet,
    /// It uses a named object this diff deletes and recreates (a limit
    /// whose rate changed); same `EBUSY`.
    BoundToRecreatedObject,
    /// It offloads to a flowtable this diff deletes and recreates (its
    /// priority or hardware offload changed); same `EBUSY` (#479).
    BoundToRecreatedFlowtable,
    /// It is installed out of declared order.
    Reorder,
    /// Its chain is deleted and created again, because what changed — the
    /// hook, priority, type or device, or whether it is a base chain at
    /// all — cannot be changed on a live chain (#478).
    ChainRecreated,
}

/// A rule the diff deletes and re-inserts, keeping (or restoring) its place
/// in the chain.
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
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
    /// The rule the kernel has at [`from`](Self::from), as `nft -s list`
    /// prints it ([`RuleInfo::nft_syntax_stateless`]). `None` where nlink
    /// cannot print it.
    pub current: Option<String>,
    /// Why it moves.
    pub reason: MoveReason,
    /// See [`RuleAdd`].
    #[cfg_attr(feature = "serde", serde(skip))]
    pub(crate) seq: usize,
}

/// A rule in the kernel that the diff deletes.
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct RuleDelete {
    /// Owning table.
    pub table: String,
    /// Owning family.
    pub family: Family,
    /// Chain. The kernel refuses a `NFT_MSG_DELRULE` without one (`ENOENT`),
    /// even when the handle names the rule (Plan 178).
    pub chain: String,
    /// Kernel handle of the rule.
    pub handle: RuleHandle,
    /// The rule's key, when nlink wrote it.
    pub key: Option<String>,
    /// The rule as `nft -s list` prints it
    /// ([`RuleInfo::nft_syntax_stateless`]), so a log of the diff says what
    /// it removes. `None` where nlink cannot print it.
    pub current: Option<String>,
}

impl RuleDelete {
    fn of(rule: &RuleInfo) -> Self {
        Self {
            table: rule.table.clone(),
            family: rule.family,
            chain: rule.chain.clone(),
            handle: RuleHandle(rule.handle),
            key: rule.key.clone(),
            current: rule.nft_syntax_stateless(),
        }
    }
}

/// A rule replaced in place: `NFT_MSG_NEWRULE | NLM_F_REPLACE` at its
/// handle, which keeps its place in the chain.
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct RuleReplace {
    /// Owning table.
    pub table: String,
    /// Owning family.
    pub family: Family,
    /// Chain.
    pub chain: String,
    /// Kernel handle of the rule replaced.
    pub handle: RuleHandle,
    /// The rule the kernel has now, as `nft -s list` prints it
    /// ([`RuleInfo::nft_syntax_stateless`]). `None` where nlink cannot
    /// print it.
    pub current: Option<String>,
    /// The declared rule that takes its place.
    pub rule: DeclaredRule,
}

/// A flowtable changed in place: devices added and removed, flags set
/// (#479). A new priority or hardware-offload setting cannot be changed on
/// a live flowtable, so that is a delete and add instead
/// ([`NftablesDiff::flowtables_to_delete`] and
/// [`NftablesDiff::flowtables_to_add`] both name it).
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct FlowtableUpdate {
    /// The flowtable as declared.
    pub flowtable: DeclaredFlowtable,
    /// Devices to add to it.
    pub add_devs: Vec<String>,
    /// Devices to take off it.
    pub remove_devs: Vec<String>,
}

impl std::fmt::Display for FlowtableUpdate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let ft = &self.flowtable;
        write!(
            f,
            "~ flowtable {:?} {}/{} (",
            ft.family(),
            ft.table(),
            ft.name()
        )?;
        let mut parts = Vec::new();
        if !self.add_devs.is_empty() {
            parts.push(format!("+devices {}", self.add_devs.join(",")));
        }
        if !self.remove_devs.is_empty() {
            parts.push(format!("-devices {}", self.remove_devs.join(",")));
        }
        parts.push(format!("flags={:#x}", ft.flags()));
        write!(f, "{})", parts.join(" "))
    }
}

/// A chain the diff deletes and creates again, with its declared rules put
/// back in declared order (#478).
///
/// `nf_tables_updchain` refuses a different hook, priority or type, and a
/// hook on a regular chain, with `EEXIST`; and nothing turns a base chain
/// into a regular one. So these changes were sent as an update the kernel
/// always refused, and a base chain declared as a regular one stayed a base
/// chain with an empty diff. A base chain cannot be a jump target, so only
/// its own rules depend on it.
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ChainRecreate {
    /// Owning table.
    pub table: String,
    /// Owning family.
    pub family: Family,
    /// The chain as declared.
    pub chain: DeclaredChain,
    /// What changed: `hook input -> forward`, `priority 0 -> -10`, …
    pub reason: String,
    /// Rules in the chain that nlink did not write, which it could not put
    /// back. Non-empty means the apply refuses, with
    /// [`ErrorDetail::NotSupported`](crate::ErrorDetail::NotSupported), rather than
    /// delete them. An [`exclusive`](super::DeclaredChainBuilder::exclusive)
    /// chain deletes them instead.
    pub blocked_by: Vec<String>,
}

impl ChainRecreate {
    /// True when the apply will refuse this recreate (see
    /// [`blocked_by`](Self::blocked_by)).
    pub fn is_refused(&self) -> bool {
        !self.blocked_by.is_empty()
    }
}

impl std::fmt::Display for ChainRecreate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "-/+ chain {:?} {}/{} (recreate",
            self.family,
            self.table,
            self.chain.name()
        )?;
        if self.blocked_by.is_empty() {
            write!(f, ": {})", self.reason)
        } else {
            write!(
                f,
                " refused: {}; it would delete rules nlink did not write: {})",
                self.reason,
                self.blocked_by.join(", ")
            )
        }
    }
}

/// Elements to add to, or remove from, one set — with the [`Set`] they
/// belong to, since how an element is written depends on the set.
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct SetElementsChange {
    /// The set.
    pub set: Set,
    /// The elements.
    pub elements: Vec<SetElement>,
}

/// An undeclared chain, set, flowtable or object in a managed table that
/// [`NftablesDiff`] leaves in place, because a rule that stays — one nlink
/// does not manage — still uses it.
///
/// The kernel refuses to delete what a rule uses (`EBUSY`), and one refused
/// message fails the whole batch, so deleting it would fail every apply until
/// someone removed the rule by hand (#459).
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case"))]
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum KeptInUse {
    /// A chain a kept rule jumps or goes to.
    Chain {
        /// Owning table.
        table: String,
        /// Owning family.
        family: Family,
        /// Chain name.
        name: String,
    },
    /// A named set or map a kept rule looks up or updates.
    Set {
        /// Owning table.
        table: String,
        /// Owning family.
        family: Family,
        /// Set name.
        name: String,
    },
    /// A flowtable a kept rule offloads to (`flow add @ft`).
    Flowtable {
        /// Owning table.
        table: String,
        /// Owning family.
        family: Family,
        /// Flowtable name.
        name: String,
    },
    /// A named object a kept rule references.
    Object {
        /// Owning table.
        table: String,
        /// Owning family.
        family: Family,
        /// Object name.
        name: String,
        /// Object type.
        object_type: ObjectType,
    },
}

impl std::fmt::Display for KeptInUse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (kind, table, family, name) = match self {
            Self::Chain {
                table,
                family,
                name,
            } => ("chain", table, family, name),
            Self::Set {
                table,
                family,
                name,
            } => ("set", table, family, name),
            Self::Flowtable {
                table,
                family,
                name,
            } => ("flowtable", table, family, name),
            Self::Object {
                table,
                family,
                name,
                object_type,
            } => return write!(f, "object {family:?} {table}/{name} ({object_type:?})"),
        };
        write!(f, "{kind} {family:?} {table}/{name}")
    }
}

/// The result of comparing a declared [`NftablesConfig`] against
/// the kernel's current state. Apply via
/// [`Self::apply`](super::NftablesDiff::apply).
///
/// `is_empty()` returns true when declared and current already
/// agree (idempotent reapply).
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
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
    /// Table flag changes the kernel refuses on a live table — `(family,
    /// name, why)`. Only `NFT_TABLE_F_DORMANT` can change; turning persist
    /// or owner on or off needs the table deleted with everything in it,
    /// which the diff will not do. The apply fails on the first, with
    /// [`ErrorDetail::NotSupported`](crate::ErrorDetail::NotSupported) (#479).
    pub tables_refused: Vec<(Family, String, String)>,
    /// Tables deleted and created again, with everything declared in them —
    /// `(family, name, why)`: a changed comment, with
    /// [`NftDiffOptions::recreate_on_comment_change`] (#703). Each is also
    /// in [`Self::tables_to_add`].
    pub tables_to_recreate: Vec<(Family, String, String)>,
    /// Chains to create — (owning table, owning family, chain).
    pub chains_to_add: Vec<(String, Family, DeclaredChain)>,
    /// Chains whose policy drifted — (owning table, owning family, chain).
    /// Applied as `NFT_MSG_NEWCHAIN`, which the kernel treats as an update
    /// for an existing chain. What an update cannot change is in
    /// [`Self::chains_to_recreate`].
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
    /// Chains to delete and create again, with their declared rules, in
    /// [`Self::rules_to_move`] and [`Self::rules_to_add`] (#478). A refused
    /// one ([`ChainRecreate::is_refused`]) makes the apply fail instead.
    pub chains_to_recreate: Vec<ChainRecreate>,
    /// Rules to add, each with its placement in the chain.
    pub rules_to_add: Vec<RuleAdd>,
    /// Rules to delete, each with what the kernel has: its key, and the
    /// rule as `nft -s list` prints it.
    pub rules_to_delete: Vec<RuleDelete>,
    /// Rules to replace in place, each with what the kernel has now and the
    /// declared rule that takes its place. Applied as `NFT_MSG_NEWRULE |
    /// NLM_F_REPLACE | NFTA_RULE_HANDLE`: the kernel swaps the rule body at
    /// that handle atomically, keeping its position.
    ///
    /// Populated by [`NftablesConfig::diff`] when a declared
    /// keyed rule matches a kernel rule by `NFTA_RULE_USERDATA`
    /// comment but the expression bytes differ. Plan 157b v2.
    pub rules_to_replace: Vec<RuleReplace>,
    /// Declared rules to delete and put back in place.
    ///
    /// Rules installed out of declared order move to their place. And a set
    /// whose key type or flags changed is deleted and recreated, as is a
    /// limit object whose rate changed; the kernel refuses to delete either
    /// while a rule still references it (`EBUSY`). So every keyed rule
    /// referencing it is deleted ahead of it and re-added after the new
    /// one, immediately before the next rule in the chain that survives, so
    /// chain order — which is policy — is unchanged.
    pub rules_to_move: Vec<RuleMove>,
    /// Flowtables to add.
    pub flowtables_to_add: Vec<DeclaredFlowtable>,
    /// Flowtables to delete — (family, table, name). A flowtable also in
    /// [`Self::flowtables_to_add`] is recreated, its rules moved out of the
    /// way first.
    pub flowtables_to_delete: Vec<(Family, String, String)>,
    /// Flowtables whose devices or counter flag changed, updated in place
    /// (#479).
    pub flowtables_to_update: Vec<FlowtableUpdate>,
    /// Sets to create — (owning table, owning family, set).
    pub sets_to_add: Vec<(String, Family, DeclaredSet)>,
    /// Sets to delete — (table, family, name).
    pub sets_to_delete: Vec<(String, Family, String)>,
    /// Sets whose declared size, timeout or GC interval differs from the
    /// kernel's — (owning table, owning family, set). Applied in place
    /// (`NFT_MSG_NEWSET` without `NLM_F_EXCL`, kernel 6.5+), keeping the
    /// set's elements and the rules bound to it, in a batch
    /// [`apply`](Self::apply) commits ahead of everything else: the kernel
    /// checks element adds against the size the set has *before* the
    /// commit, so a grown set could not take its new elements in the same
    /// batch. An update overwrites the timeout and GC interval with what it
    /// carries, so the set here carries the kernel's where the declaration
    /// has none.
    pub sets_to_update: Vec<(String, Family, DeclaredSet)>,
    /// Set elements to add: the declared elements not yet in the kernel
    /// set.
    pub set_elements_to_add: Vec<SetElementsChange>,
    /// Set elements to remove: the kernel elements not declared (full
    /// element reconcile).
    pub set_elements_to_remove: Vec<SetElementsChange>,
    /// Stateful objects to create — (owning table, owning family, object).
    /// A changed limit is here and in `objects_to_delete`.
    pub objects_to_add: Vec<(String, Family, DeclaredObject)>,
    /// Quotas whose size or `over` changed — updated in place, keeping
    /// what they have used.
    pub objects_to_update: Vec<(String, Family, DeclaredObject)>,
    /// Stateful objects to delete — (table, family, name, type).
    pub objects_to_delete: Vec<(String, Family, String, ObjectType)>,
    /// Undeclared chains, sets, flowtables and objects the diff does **not** delete,
    /// because a rule that stays still uses them — see [`KeptInUse`]. Not a
    /// change: [`is_empty`](Self::is_empty) and
    /// [`change_count`](Self::change_count) ignore it, and nothing in it is
    /// sent to the kernel.
    pub kept_in_use: Vec<KeptInUse>,
    /// The ruleset generation the diff was taken at, if it was taken from
    /// the kernel: [`apply`](Self::apply) commits only if the ruleset is
    /// still there, and is otherwise refused with `ERESTART`
    /// ([`Error::is_restart`](crate::Error::is_restart)) (#482).
    pub generation: Option<u32>,
}

impl NftablesDiff {
    /// The JSON Schema (draft 7) of the JSON a `NftablesDiff` serializes to,
    /// pretty-printed. Requires the `schemars` feature. Publish it beside
    /// a `diff` output so a change to the diff's shape is a visible change
    /// to its schema (#531).
    #[cfg(feature = "schemars")]
    pub fn json_schema() -> String {
        crate::netlink::config::draft07_output_schema_text::<Self>()
    }

    /// [`json_schema`](Self::json_schema) as a [`schemars::Schema`].
    #[cfg(feature = "schemars")]
    pub fn json_schema_value() -> schemars::Schema {
        crate::netlink::config::draft07_output_schema::<Self>()
    }

    /// `true` if declared state already matches kernel state.
    pub fn is_empty(&self) -> bool {
        self.tables_to_add.is_empty()
            && self.tables_to_modify.is_empty()
            && self.tables_to_delete.is_empty()
            && self.tables_refused.is_empty()
            && self.tables_to_recreate.is_empty()
            && self.chains_to_add.is_empty()
            && self.chains_to_modify.is_empty()
            && self.chains_to_delete.is_empty()
            && self.chains_to_recreate.is_empty()
            && self.rules_to_add.is_empty()
            && self.rules_to_delete.is_empty()
            && self.rules_to_replace.is_empty()
            && self.rules_to_move.is_empty()
            && self.flowtables_to_add.is_empty()
            && self.flowtables_to_delete.is_empty()
            && self.flowtables_to_update.is_empty()
            && self.sets_to_add.is_empty()
            && self.sets_to_delete.is_empty()
            && self.sets_to_update.is_empty()
            && self.set_elements_to_add.is_empty()
            && self.set_elements_to_remove.is_empty()
            && self.objects_to_add.is_empty()
            && self.objects_to_update.is_empty()
            && self.objects_to_delete.is_empty()
    }

    /// Total number of changes (sum of all add/delete counts).
    pub fn change_count(&self) -> usize {
        self.tables_to_add.len()
            + self.tables_to_modify.len()
            + self.tables_to_delete.len()
            + self.tables_refused.len()
            + self.tables_to_recreate.len()
            + self.chains_to_add.len()
            + self.chains_to_modify.len()
            + self.chains_to_delete.len()
            + self.chains_to_recreate.len()
            + self.rules_to_add.len()
            + self.rules_to_delete.len()
            + self.rules_to_replace.len()
            + self.rules_to_move.len()
            + self.flowtables_to_add.len()
            + self.flowtables_to_delete.len()
            + self.flowtables_to_update.len()
            + self.sets_to_add.len()
            + self.sets_to_delete.len()
            + self.sets_to_update.len()
            + self.set_elements_to_add.len()
            + self.set_elements_to_remove.len()
            + self.objects_to_add.len()
            + self.objects_to_update.len()
            + self.objects_to_delete.len()
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
        for (fam, name, why) in &self.tables_refused {
            lines.push(format!("! table {fam:?} {name} (refused: {why})"));
        }
        for (fam, name, why) in &self.tables_to_recreate {
            lines.push(format!("~ table {fam:?} {name} (recreate: {why})"));
        }
        for (tbl, fam, c) in &self.chains_to_add {
            lines.push(format!("+ chain {fam:?} {tbl}/{}", c.name()));
        }
        for (tbl, fam, c) in &self.chains_to_modify {
            lines.push(format!(
                "~ chain {fam:?} {tbl}/{} (policy={:?} hook={:?} priority={:?} type={:?} \
                 devices={:?})",
                c.name(),
                c.policy(),
                c.hook(),
                c.priority(),
                c.chain_type(),
                c.devices(),
            ));
        }
        for (tbl, fam, name) in &self.chains_to_delete {
            lines.push(format!("- chain {fam:?} {tbl}/{name}"));
        }
        for recreate in &self.chains_to_recreate {
            lines.push(recreate.to_string());
        }
        for add in &self.rules_to_add {
            let r = &add.rule;
            let key = r.handle_key().unwrap_or("<anonymous>");
            lines.push(format!(
                "+ rule {:?} {}/{} [{}]{}{}",
                r.family(),
                r.table(),
                r.chain(),
                key,
                placement_suffix(add.placement),
                body_suffix(r),
            ));
        }
        for d in &self.rules_to_delete {
            let key = d
                .key
                .as_deref()
                .map(|k| format!(" [{k}]"))
                .unwrap_or_default();
            let body = d
                .current
                .as_deref()
                .map(|b| format!(": {b}"))
                .unwrap_or_default();
            lines.push(format!(
                "- rule {:?} {}/{}{key} (handle={}){body}",
                d.family, d.table, d.chain, d.handle.0,
            ));
        }
        for r in &self.rules_to_replace {
            let key = r.rule.handle_key().unwrap_or("<anonymous>");
            lines.push(format!(
                "~ rule {:?} {}/{} (handle={} key={key}){}",
                r.family,
                r.table,
                r.chain,
                r.handle.0,
                change_suffix(r.current.as_deref(), &r.rule),
            ));
        }
        for m in &self.rules_to_move {
            let key = m.rule.handle_key().unwrap_or("<anonymous>");
            let why = match m.reason {
                MoveReason::BoundToRecreatedSet => "its set is recreated",
                MoveReason::BoundToRecreatedObject => "its object is recreated",
                MoveReason::BoundToRecreatedFlowtable => "its flowtable is recreated",
                MoveReason::Reorder => "out of declared order",
                MoveReason::ChainRecreated => "its chain is recreated",
            };
            lines.push(format!(
                "~ rule {:?} {}/{} (handle={} key={key}, re-added: {why}){}{}",
                m.family,
                m.table,
                m.chain,
                m.from.0,
                placement_suffix(m.placement),
                change_suffix(m.current.as_deref(), &m.rule),
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
        for update in &self.flowtables_to_update {
            lines.push(update.to_string());
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
        for (tbl, fam, o) in &self.objects_to_add {
            lines.push(format!("+ object {fam:?} {tbl}/{} {:?}", o.name(), o.config()));
        }
        for (tbl, fam, o) in &self.objects_to_update {
            lines.push(format!("~ object {fam:?} {tbl}/{} {:?}", o.name(), o.config()));
        }
        for (tbl, fam, name, ty) in &self.objects_to_delete {
            lines.push(format!("- object {fam:?} {tbl}/{name} ({ty:?})"));
        }
        for (tbl, fam, s) in &self.sets_to_update {
            let mut what = format!(
                "size={}",
                s.size().map_or_else(|| "-".to_string(), |n| n.to_string())
            );
            if let Some(t) = s.timeout() {
                what.push_str(&format!(", timeout={t:?}"));
            }
            if let Some(gc) = s.gc_interval() {
                what.push_str(&format!(", gc-interval={gc:?}"));
            }
            lines.push(format!("~ set {fam:?} {tbl}/{} ({what})", s.name()));
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
        let mut out = if lines.is_empty() {
            "NftablesDiff: no changes".to_string()
        } else {
            format!(
                "NftablesDiff: {} change{}:\n  {}",
                lines.len(),
                if lines.len() == 1 { "" } else { "s" },
                lines.join("\n  ")
            )
        };
        for kept in &self.kept_in_use {
            out.push_str(&format!(
                "\n  ! {kept} kept: a rule nlink does not manage uses it"
            ));
        }
        out
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

/// `: <the rule as nft -s prints it>`, when nlink can print it (#708).
fn body_suffix(rule: &DeclaredRule) -> String {
    rule.body()
        .nft_syntax_stateless()
        .map(|body| format!(": {body}"))
        .unwrap_or_default()
}

/// `: <what the kernel has> -> <what is declared>` for a rule the diff
/// writes over, or just the declared rule when the two print the same.
fn change_suffix(current: Option<&str>, rule: &DeclaredRule) -> String {
    match (current, rule.body().nft_syntax_stateless()) {
        (Some(now), Some(to)) if now != to => format!(": {now} -> {to}"),
        (_, Some(to)) => format!(": {to}"),
        (Some(now), None) => format!(" (now: {now})"),
        (None, None) => String::new(),
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

/// What a declared chain needs to match what the kernel holds.
///
/// Compares all five properties `DeclaredChain` carries and `ChainInfo` parses
/// back. A declared `None` means "not specified" and is not treated as drift —
/// the config is only asserting the properties it names, so a config that
/// doesn't mention a policy won't fight a policy set out-of-band. The hook is
/// the exception: a chain declared without one is a regular chain, and a
/// base chain of that name is not it (#478).
fn chain_change(declared: &DeclaredChain, current: &ChainInfo, comments: bool) -> ChainChange {
    let mut why = Vec::new();
    // The kernel keeps a chain's comment as it was created (#703).
    if comments && current.comment.as_deref() != declared.comment() {
        why.push(format!("comment {:?} -> {:?}", current.comment, declared.comment()));
    }
    match (declared.hook(), current.hook) {
        (None, Some(_)) => why.push("base chain -> regular chain".to_string()),
        (Some(_), None) => why.push("regular chain -> base chain".to_string()),
        (Some(hook), Some(have)) if hook.number(current.family) != have => {
            why.push(format!("hook {have} -> {}", hook.number(current.family)));
        }
        _ => {}
    }
    // Type, priority and device belong to a base chain; on a regular one
    // they have no meaning, and the change of kind above covers it.
    if declared.hook().is_some() && current.hook.is_some() {
        if let Some(t) = declared.chain_type()
            && current.chain_type != Some(t)
        {
            let have = current.chain_type.map_or("none", |t| t.as_str());
            why.push(format!("type {have} -> {}", t.as_str()));
        }
        if let Some(p) = declared.priority()
            && current.priority != Some(p.to_i32())
        {
            let have = current
                .priority
                .map_or("none".to_string(), |p| p.to_string());
            why.push(format!("priority {have} -> {}", p.to_i32()));
        }
        // A chain bound to several devices dumps `NFTA_HOOK_DEVS` without
        // `NFTA_HOOK_DEV`. An update only adds devices, so a different set
        // is a recreate too (#484), compared as a set (#703).
        if !declared.devices().is_empty() {
            let mut have: Vec<&str> = if current.devices.is_empty() {
                current.device.as_deref().into_iter().collect()
            } else {
                current.devices.iter().map(String::as_str).collect()
            };
            let mut want: Vec<&str> = declared.devices().iter().map(String::as_str).collect();
            have.sort_unstable();
            want.sort_unstable();
            want.dedup();
            if have != want {
                let have = if have.is_empty() {
                    "none".to_string()
                } else {
                    have.join(",")
                };
                why.push(format!("device {have} -> {}", want.join(",")));
            }
        }
    }
    if !why.is_empty() {
        return ChainChange::Recreate(why.join(", "));
    }
    // Only a declared value can drift; an unspecified one is not a claim.
    match declared.policy() {
        Some(policy) if current.policy != Some(policy.to_u32()) => ChainChange::Update,
        _ => ChainChange::None,
    }
}

/// What a declared chain needs: nothing, an update in place (the policy),
/// or a recreate (anything else the kernel cannot change on a live chain).
#[derive(Debug, PartialEq, Eq)]
enum ChainChange {
    None,
    Update,
    Recreate(String),
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
        || declared.wire_flags() != current.flags
        || declared.data_type().and_then(|d| d.type_id()) != current.data_type
        || declared.data_type().and_then(|d| match d {
            super::super::SetDataType::Object(object_type) => Some(*object_type as u32),
            _ => None,
        }) != current.object_type
        // The kernel sizes a verdict itself; only a value's length is ours.
        || declared
            .data_type()
            .and_then(|d| d.len())
            .is_some_and(|len| current.data_len != Some(len))
        // Neither changes in place (#703).
        || declared.policy().is_some_and(|policy| policy != current.policy)
        || !statements_match(declared.statements(), &current.statements)
}

/// Whether a set's statements are the declared ones, as the kernel keeps
/// them. One nlink cannot read never matches.
fn statements_match(declared: &[ElementStatement], current: &[RuleExpr]) -> bool {
    declared.len() == current.len()
        && declared.iter().zip(current).all(|(declared, current)| {
            ElementStatement::from_rule_expr(current)
                .is_some_and(|current| current.kernel_form() == declared.kernel_form())
        })
}

/// Does `rule` reference the set `set`? A plain lookup decodes typed; an
/// inverted or map lookup, and a `dynset`, stay `Unknown` but carry the set
/// name as their first attribute (`NFTA_LOOKUP_SET`, `NFTA_DYNSET_SET_NAME`).
fn references_set(rule: &RuleInfo, set: &str) -> bool {
    use crate::netlink::attr::{AttrIter, get};
    rule.expressions().iter().any(|e| match e {
        RuleExpr::Lookup { set: s, .. } | RuleExpr::Dynset { set: s, .. } => s == set,
        // `counter name ip saddr map @m`: the rule is bound to the object
        // map, and a DELSET of it is EBUSY (#483).
        RuleExpr::Objref(super::super::expr::ObjrefExpr::Map { map, .. }) => map == set,
        RuleExpr::Unknown { name, data } if name == "lookup" || name == "dynset" => {
            AttrIter::new(data)
                .any(|(attr, payload)| attr == 1 && get::string(payload).ok() == Some(set))
        }
        _ => false,
    })
}

/// Does `rule` use the named object `name` of `object_type`?
fn references_object(rule: &RuleInfo, name: &str, object_type: ObjectType) -> bool {
    use super::super::expr::ObjrefExpr;
    rule.expressions().iter().any(|e| {
        matches!(
            e,
            RuleExpr::Objref(ObjrefExpr::Named { object_type: t, name: n })
                if n == name && *t == object_type
        )
    })
}

/// Move the undeclared chains, sets, flowtables and objects of `declared`'s table that a
/// staying rule uses from the diff's delete lists to `kept_in_use`.
///
/// A staying rule is one in the kernel that the diff neither deletes,
/// replaces nor moves, in a chain the diff does not delete. Sets and objects
/// recreated under the same name are declared, so they are never kept.
fn keep_what_staying_rules_use(
    diff: &mut NftablesDiff,
    declared: &DeclaredTable,
    current_rules: &[RuleInfo],
) {
    let (table, family) = (declared.name(), declared.family());
    let here = |t: &str, f: Family| t == table && f == family;
    let mut gone: HashSet<u64> = HashSet::new();
    for d in &diff.rules_to_delete {
        if here(&d.table, d.family) {
            gone.insert(d.handle.0);
        }
    }
    for r in &diff.rules_to_replace {
        if here(&r.table, r.family) {
            gone.insert(r.handle.0);
        }
    }
    for m in &diff.rules_to_move {
        if here(&m.table, m.family) {
            gone.insert(m.from.0);
        }
    }
    let recreated_sets: HashSet<String> = diff
        .sets_to_add
        .iter()
        .filter(|(t, f, _)| here(t, *f))
        .map(|(_, _, s)| s.name().to_string())
        .collect();
    let recreated_objects: Vec<(String, ObjectType)> = diff
        .objects_to_add
        .iter()
        .filter(|(t, f, _)| here(t, *f))
        .map(|(_, _, o)| (o.name().to_string(), o.config().object_type()))
        .collect();

    loop {
        let deleted_chains: HashSet<&str> = diff
            .chains_to_delete
            .iter()
            .filter(|(t, f, _)| here(t, *f))
            .map(|(_, _, name)| name.as_str())
            .collect();
        let staying: Vec<&RuleInfo> = current_rules
            .iter()
            .filter(|r| !gone.contains(&r.handle) && !deleted_chains.contains(r.chain.as_str()))
            .collect();
        let used = |pred: &dyn Fn(&RuleInfo) -> bool| staying.iter().any(|r| pred(r));
        let mut kept = Vec::new();

        diff.chains_to_delete.retain(|(t, f, name)| {
            let keep = here(t, *f) && used(&|r| references_chain(r, name));
            if keep {
                kept.push(KeptInUse::Chain {
                    table: t.clone(),
                    family: *f,
                    name: name.clone(),
                });
            }
            !keep
        });
        diff.sets_to_delete.retain(|(t, f, name)| {
            let keep =
                here(t, *f) && !recreated_sets.contains(name) && used(&|r| references_set(r, name));
            if keep {
                kept.push(KeptInUse::Set {
                    table: t.clone(),
                    family: *f,
                    name: name.clone(),
                });
            }
            !keep
        });
        diff.flowtables_to_delete.retain(|(f, t, name)| {
            let keep = here(t, *f) && used(&|r| references_flowtable(r, name));
            if keep {
                kept.push(KeptInUse::Flowtable {
                    table: t.clone(),
                    family: *f,
                    name: name.clone(),
                });
            }
            !keep
        });
        diff.objects_to_delete.retain(|(t, f, name, ty)| {
            let keep = here(t, *f)
                && !recreated_objects
                    .iter()
                    .any(|(n, rt)| n == name && rt == ty)
                && used(&|r| references_object(r, name, *ty));
            if keep {
                kept.push(KeptInUse::Object {
                    table: t.clone(),
                    family: *f,
                    name: name.clone(),
                    object_type: *ty,
                });
            }
            !keep
        });

        if kept.is_empty() {
            return;
        }
        for k in &kept {
            tracing::warn!(
                kept = %k,
                "not deleting an undeclared nftables item: a rule nlink does not manage uses it",
            );
        }
        diff.kept_in_use.extend(kept);
    }
}

/// Does `rule` offload to the flowtable `name`?
fn references_flowtable(rule: &RuleInfo, name: &str) -> bool {
    rule.expressions()
        .iter()
        .any(|e| matches!(e, RuleExpr::FlowOffload { flowtable } if flowtable == name))
}

/// Does `rule` jump or go to `chain`?
fn references_chain(rule: &RuleInfo, chain: &str) -> bool {
    rule.expressions().iter().any(|e| {
        matches!(
            e,
            RuleExpr::Verdict(Verdict::JumpTo(c) | Verdict::GotoTo(c)) if c.as_str() == chain
        )
    })
}

/// What a declared object asks the diff to do with the kernel's.
#[derive(Debug, PartialEq, Eq)]
enum ObjectChange {
    Nothing,
    /// Update in place (a quota).
    Update,
    /// Delete and create (a limit, or a state nlink cannot read).
    Recreate,
}

/// Compare a declared object's configuration with the kernel's — never its
/// live state. A limit's burst of 0 is the kernel's 5, as the writer sends
/// it.
fn object_change(declared: &ObjectConfig, current: Option<ObjectConfig>) -> ObjectChange {
    let normalize = |config: ObjectConfig| match config {
        ObjectConfig::Limit(mut limit) if limit.burst == 0 => {
            limit.burst = 5;
            ObjectConfig::Limit(limit)
        }
        other => other,
    };
    match current.map(normalize) {
        Some(current) if current == normalize(declared.clone()) => ObjectChange::Nothing,
        Some(ObjectConfig::Quota(_)) => ObjectChange::Update,
        _ => ObjectChange::Recreate,
    }
}

/// Does a declared rule match the kernel rule with its key? Bodies are
/// compared after `normalize_tlv` and with the live state the kernel echoes
/// (counter values, quota consumption) zeroed; the human comment — what
/// follows `nlink:<key> ` — must match too.
fn rule_matches(declared: &DeclaredRule, kernel: &RuleInfo) -> bool {
    let canon = super::rules::canonical_body;
    let declared_body = canon(&lower_to_expression_bytes(&declared.body), declared.body.family);
    let kernel_body = canon(&kernel.expression_bytes, kernel.family);
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
        .userdata_raw
        .as_deref()
        .and_then(super::super::userdata::human_comment_of);
    declared.body.comment == kernel_comment
}

/// The elements to add to and remove from an existing set. In
/// [`SetElementMode::Ensure`] nothing undeclared is removed; a declared map
/// element whose data changed is replaced in either mode.
///
/// A plain set compares element identities (key, range end, catch-all), and
/// so does an interval set of concatenated keys, whose elements the kernel
/// keeps as written. An interval set of single keys compares ranges: if the
/// kernel's ranges, merged where they touch, are the declared ones merged
/// the same way, nothing changes — however the kernel happens to split
/// them. Otherwise the kernel ranges that are not declared go, and the
/// declared ones the kernel does not hold come — the removals are sent
/// first, so a range that grows is replaced in one batch.
fn element_changes(
    declared: &DeclaredSet,
    current: &[SetElement],
) -> (Vec<SetElement>, Vec<SetElement>) {
    use super::super::interval;
    let ensure = declared.element_mode() == SetElementMode::Ensure;
    if declared.merges_ranges() {
        // Ranges compare as numbers: a host-order key in network order, and
        // back for the writer (#703).
        let swap = declared.key_type().is_host_order();
        let to_wire = |e: &SetElement| if swap { e.host_to_wire() } else { e.clone() };
        let to_host = |e: SetElement| if swap { e.wire_to_host() } else { e };
        let current: Vec<SetElement> = current.iter().map(to_wire).collect();
        // The declared elements, merged, with their timeouts (#483).
        let wanted_elements: Vec<SetElement> = declared.wire_elements().iter().map(to_wire).collect();
        let wanted: Vec<interval::Range> = wanted_elements.iter().map(interval::range_of).collect();
        let held: Vec<interval::Range> = current.iter().map(interval::range_of).collect();
        if interval::canonicalize(held.clone()) == interval::canonicalize(wanted.clone()) {
            return (Vec::new(), Vec::new());
        }
        let to_add: Vec<SetElement> = if ensure {
            // Ensure keeps what the kernel holds, so a declared range that
            // overlaps one added at runtime goes in as the parts it does not
            // cover: the kernel refuses an overlapping range, which made
            // every apply fail (#483).
            let held = interval::canonicalize(held.clone());
            wanted_elements
                .iter()
                .flat_map(|e| {
                    interval::subtract(&interval::range_of(e), &held)
                        .into_iter()
                        .map(|piece| {
                            let piece = interval::element_of(&piece);
                            match e.timeout() {
                                Some(t) => piece.with_timeout(t),
                                None => piece,
                            }
                        })
                })
                .collect()
        } else {
            wanted_elements
                .iter()
                .filter(|e| !held.contains(&interval::range_of(e)))
                .cloned()
                .collect()
        };
        let to_remove: Vec<SetElement> = if ensure {
            Vec::new()
        } else {
            held.iter()
                .filter(|r| !wanted.contains(r))
                .map(interval::element_of)
                .collect()
        };
        return (
            to_add.into_iter().map(to_host).collect(),
            to_remove.into_iter().map(to_host).collect(),
        );
    }
    // A map element whose data changed is removed and added again; the
    // removals go first in the batch.
    let declared_by_id: HashMap<_, _> = declared
        .elements()
        .iter()
        .map(|e| (e.identity(), e.data()))
        .collect();
    let current_by_id: HashMap<_, _> = current.iter().map(|e| (e.identity(), e.data())).collect();
    let to_add = declared
        .elements()
        .iter()
        .filter(|e| current_by_id.get(&e.identity()) != Some(&e.data()))
        .cloned()
        .collect();
    let to_remove = current
        .iter()
        .filter(|e| match declared_by_id.get(&e.identity()) {
            None => !ensure,
            Some(data) => *data != e.data(),
        })
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

/// Has a declared set's default timeout or GC interval drifted? Like the
/// size, both change in place and an undeclared one is not a claim. The
/// timeout is compared in 20 ms steps, as the kernel keeps it in jiffies
/// ([`super::rules::timeout_step`]); the GC interval it keeps as given.
fn set_timers_have_drifted(declared: &DeclaredSet, current: &SetInfo) -> bool {
    use super::rules::timeout_step;
    let ms = |d: Option<std::time::Duration>| d.map_or(0, super::super::expr::millis);
    let timeout = declared
        .timeout()
        .is_some_and(|t| timeout_step(ms(Some(t))) != timeout_step(ms(current.timeout)));
    let gc = declared
        .gc_interval()
        .is_some_and(|gc| ms(Some(gc)) != ms(current.gc_interval));
    timeout || gc
}

/// The update a drifted set gets: the declaration, with the kernel's
/// timeout and GC interval where it has none — an update overwrites both
/// with what it carries, so leaving them out would zero them.
fn set_update(declared: &DeclaredSet, current: &SetInfo) -> DeclaredSet {
    let mut update = declared.clone();
    update.timeout = update.timeout.or(current.timeout);
    update.gc_interval = update.gc_interval.or(current.gc_interval);
    update
}

/// Options controlling [`NftablesConfig::diff_with_options`].
///
/// Mirrors [`PlanOptions`](crate::netlink::config::PlanOptions) on the
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
    /// Apply a changed comment on a table, chain or set by creating it
    /// again (#703). Default `false`.
    ///
    /// The kernel keeps a comment as it was created and never updates it,
    /// so without this the diff does not compare comments. With it, a
    /// changed one recreates what carries it, with all that is in it: an
    /// owned table and everything declared in it (in one batch, so nothing
    /// is unfiltered in between, but counters and dynamic set elements
    /// start again), a chain and its rules, a set and its declared
    /// elements. A shared table keeps its comment; declared objects carry
    /// none.
    pub recreate_on_comment_change: bool,
}

impl Default for NftDiffOptions {
    fn default() -> Self {
        Self {
            purge_tables: false,
            enforce_rule_order: true,
            recreate_on_comment_change: false,
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

    /// Recreate a table, chain or set whose declared comment changed. See
    /// [`Self::recreate_on_comment_change`].
    pub fn recreate_on_comment_change(mut self, on: bool) -> Self {
        self.recreate_on_comment_change = on;
        self
    }
}

#[nlink_macros::send_futures]
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
    ///
    /// The dumps are taken between two reads of the ruleset generation and
    /// taken again if a commit landed in between; the diff records the
    /// generation, and [`NftablesDiff::apply`] commits only if the ruleset
    /// is still at it (#482).
    pub async fn diff_with_options(
        &self,
        conn: &Connection<Nftables>,
        options: &NftDiffOptions,
    ) -> Result<NftablesDiff> {
        self.validate()?;
        // A snapshot is 3 + 2N dumps, taken again if a commit landed in the
        // middle of them; if something commits in a loop the last one's
        // apply is refused (its generation is stale) rather than applied
        // against a torn view.
        let snapshot = self.snapshot(conn).await?;
        self.diff_snapshot(&snapshot, options)
    }

    /// The diff against `snapshot` (#527): what [`diff_with_options`]
    /// computes from the kernel, as a pure function of what it read — from
    /// [`snapshot`](Self::snapshot), or simulated with
    /// [`RulesetSnapshot::from_config`](super::RulesetSnapshot::from_config).
    /// It commits only at the snapshot's generation, if it has one.
    ///
    /// [`diff_with_options`]: Self::diff_with_options
    pub fn diff_snapshot(
        &self,
        snapshot: &super::RulesetSnapshot,
        options: &NftDiffOptions,
    ) -> Result<NftablesDiff> {
        self.validate()?;
        let mut diff = NftablesDiff {
            generation: snapshot.generation,
            ..Default::default()
        };
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
        let current_tables = snapshot.tables.clone();

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
                // The kernel keeps a table's comment as it was created: with
                // the option, an owned table is created again (#703). A
                // shared one holds what others put there, and keeps its.
                Some(current)
                    if options.recreate_on_comment_change
                        && declared.mode() == super::TableMode::Owned
                        && current.comment.as_deref() != declared.comment() =>
                {
                    diff.tables_to_recreate.push((
                        declared.family(),
                        declared.name().to_string(),
                        format!("comment {:?} -> {:?}", current.comment, declared.comment()),
                    ));
                    diff.tables_to_add.push(declared.clone());
                }
                Some(current) if current.flags != declared.flags() => {
                    // Only dormant changes on a live table:
                    // `nf_tables_updtable` refuses an owner or persist
                    // change with EOPNOTSUPP (#479).
                    let changed = current.flags ^ declared.flags();
                    let at = (declared.family(), declared.name().to_string());
                    if changed & !super::super::NFT_TABLE_F_DORMANT != 0 {
                        diff.tables_refused.push((
                            at.0,
                            at.1,
                            format!(
                                "flags {:#x} -> {:#x}: only dormant can change on a live table",
                                current.flags,
                                declared.flags()
                            ),
                        ));
                    } else {
                        diff.tables_to_modify.push((at.0, at.1, declared.flags()));
                    }
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
        // Tables declared absent go whenever the kernel has them (#519).
        for (family, name) in &self.absent {
            let live = current_tables
                .iter()
                .any(|t| t.family == *family && &t.name == name);
            let at = (*family, name.clone());
            if live && !diff.tables_to_delete.contains(&at) {
                diff.tables_to_delete.push(at);
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
        let all_chains_for_diff = snapshot.chains.clone();
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
        let all_flowtables_for_diff = snapshot.flowtables.clone();
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
                for o in declared.objects() {
                    diff.objects_to_add.push((
                        declared.name().to_string(),
                        declared.family(),
                        o.clone(),
                    ));
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
                    // (#200). Same silence for a changed hook or priority —
                    // which, sent as an update, the kernel refuses, so those
                    // recreate the chain (#478).
                    Some(current) => match chain_change(c, current, options.recreate_on_comment_change) {
                        ChainChange::None => {}
                        ChainChange::Update => diff.chains_to_modify.push((
                            declared.name().to_string(),
                            declared.family(),
                            c.clone(),
                        )),
                        ChainChange::Recreate(reason) => {
                            diff.chains_to_recreate.push(ChainRecreate {
                                table: declared.name().to_string(),
                                family: declared.family(),
                                chain: c.clone(),
                                reason,
                                blocked_by: Vec::new(),
                            });
                        }
                    },
                }
            }
            // In a shared table only what nlink's apply made is its to
            // delete (#527).
            let shared = declared.mode() == super::TableMode::Shared;
            for c in chains_in_table {
                if !declared_chain_names.contains(c.name.as_str()) && (!shared || c.managed) {
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
            let mut recreated_flowtables: Vec<String> = Vec::new();
            for f in declared.flowtables() {
                match fts_in_table.iter().find(|k| k.name == f.name()) {
                    None => diff.flowtables_to_add.push(f.clone()),
                    // Same name-only-identity gap as chains: `Flowtable` from
                    // the dump carries devs/priority/flags and
                    // `DeclaredFlowtable` declares all three, but nothing
                    // compared them. Adding a device to a declared flowtable,
                    // or toggling hw_offload, produced an empty diff (#208).
                    //
                    // NFT_MSG_NEWFLOWTABLE updates an existing flowtable,
                    // but sent through the add path it carried NLM_F_EXCL
                    // (EEXIST), and an update only adds devices. The
                    // devices are compared as a set: the kernel lists
                    // added ones first (#479).
                    Some(current) => {
                        let offload = super::super::NFT_FLOWTABLE_HW_OFFLOAD;
                        let want: HashSet<&str> = f.devs().iter().map(String::as_str).collect();
                        let have: HashSet<&str> = current.devs.iter().map(String::as_str).collect();
                        if f.priority() != current.priority
                            || (f.flags() ^ current.flags) & offload != 0
                        {
                            diff.flowtables_to_delete.push((
                                declared.family(),
                                declared.name().to_string(),
                                f.name().to_string(),
                            ));
                            diff.flowtables_to_add.push(f.clone());
                            recreated_flowtables.push(f.name().to_string());
                        } else if want != have || f.flags() != current.flags {
                            let mut add_devs: Vec<String> = f
                                .devs()
                                .iter()
                                .filter(|d| !have.contains(d.as_str()))
                                .cloned()
                                .collect();
                            add_devs.dedup();
                            let remove_devs: Vec<String> = current
                                .devs
                                .iter()
                                .filter(|d| !want.contains(d.as_str()))
                                .cloned()
                                .collect();
                            diff.flowtables_to_update.push(FlowtableUpdate {
                                flowtable: f.clone(),
                                add_devs,
                                remove_devs,
                            });
                        }
                    }
                }
            }
            for f in fts_in_table {
                if !declared_ft_names.contains(f.name.as_str()) && !shared {
                    diff.flowtables_to_delete.push((
                        declared.family(),
                        declared.name().to_string(),
                        f.name.clone(),
                    ));
                }
            }

            // Stateful objects: identity is (name, type). Only their
            // configuration is compared — a counter's counts and a quota's
            // consumption are live state.
            let current_objects = snapshot.objects_in(declared.name(), declared.family());
            let mut recreated_objects: Vec<(String, ObjectType)> = Vec::new();
            for o in declared.objects() {
                let ty = o.config().object_type();
                let current = current_objects
                    .iter()
                    .find(|c| c.name == o.name() && c.object_type() == Some(ty));
                let push = |list: &mut Vec<(String, Family, DeclaredObject)>| {
                    list.push((declared.name().to_string(), declared.family(), o.clone()));
                };
                match current.map(|c| object_change(o.config(), c.state.config())) {
                    None => push(&mut diff.objects_to_add),
                    Some(ObjectChange::Nothing) => {}
                    Some(ObjectChange::Update) => push(&mut diff.objects_to_update),
                    Some(ObjectChange::Recreate) => {
                        diff.objects_to_delete.push((
                            declared.name().to_string(),
                            declared.family(),
                            o.name().to_string(),
                            ty,
                        ));
                        push(&mut diff.objects_to_add);
                        recreated_objects.push((o.name().to_string(), ty));
                    }
                }
            }
            for c in &current_objects {
                let declared_here = declared
                    .objects()
                    .iter()
                    .any(|o| o.name() == c.name && Some(o.config().object_type()) == c.object_type());
                if declared_here || (shared && !c.managed) {
                    continue;
                }
                match c.object_type() {
                    Some(ty) => diff.objects_to_delete.push((
                        declared.name().to_string(),
                        declared.family(),
                        c.name.clone(),
                        ty,
                    )),
                    // A kind nlink cannot name it cannot delete either; say
                    // so rather than leave it unmentioned.
                    None => tracing::warn!(
                        table = %declared.name(),
                        object = %c.name,
                        "an object of a type nlink does not model is left in a managed table",
                    ),
                }
            }

            // Sets: name-based identity, like chains/flowtables.
            // Server-side table-scoped (Plan 181), so this is one
            // round-trip per declared table — cheaper than a
            // kernel-wide GETSET dump indexed in the loop.
            // Anonymous sets (`tcp dport { 22, 80 }`) belong to the rule that
            // created them: the kernel creates and frees them with it, `nft`
            // never lists them, and the diff must not delete one either. A
            // DELSET for one is EBUSY while its rule exists (#459).
            let current_sets: Vec<SetInfo> = snapshot
                .sets_in(declared.name(), declared.family())
                .into_iter()
                .filter(|s| !s.flags.contains(SetFlags::ANONYMOUS))
                .collect();
            let declared_set_names: HashSet<&str> =
                declared.sets().iter().map(|s| s.name()).collect();
            let current_set_names: HashSet<&str> =
                current_sets.iter().map(|s| s.name.as_str()).collect();

            // Sets this diff deletes and recreates (key type / flags drift).
            let mut recreated: HashSet<&str> = HashSet::new();
            for s in declared.sets() {
                let current_set = current_sets.iter().find(|c| c.name == s.name());
                if let Some(current) = current_set
                    && (set_has_drifted(s, current)
                        || (options.recreate_on_comment_change
                            && current.comment.as_deref() != s.comment.as_deref()))
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
                    && (set_size_has_drifted(s, current) || set_timers_have_drifted(s, current))
                {
                    diff.sets_to_update.push((
                        declared.name().to_string(),
                        declared.family(),
                        set_update(s, current),
                    ));
                }
                // An object map whose elements name an object this diff
                // recreates: the elements hold the object, and its DELOBJ is
                // EBUSY until they let go (#483).
                let holds_recreated = |e: &SetElement| match e.data() {
                    Some(super::super::types::SetElementData::Object(name)) => {
                        recreated_objects.iter().any(|(n, _)| n == name)
                    }
                    _ => false,
                };
                let object_map = matches!(
                    s.data_type(),
                    Some(super::super::types::SetDataType::Object(_))
                );
                if current_set_names.contains(s.name())
                    && s.element_mode() == SetElementMode::Ensure
                    && s.elements().is_empty()
                    && !(object_map && !recreated_objects.is_empty())
                {
                    // Nothing declared and nothing to remove: no need to
                    // read what the packet path has put there.
                } else if current_set_names.contains(s.name()) {
                    // Set exists on both sides → element-level diff.
                    // Read the kernel's current elements and compute
                    // the symmetric difference on raw key bytes.
                    let current_elems =
                        snapshot.elements_of(declared.family(), declared.name(), s.name())?;
                    let (mut to_add, mut to_remove) = element_changes(s, &current_elems);
                    // A constant set cannot take element changes while a
                    // rule is bound to it (EBUSY): recreate it, its rules
                    // moved out of the way (#483).
                    if s.wire_flags().contains(SetFlags::CONSTANT)
                        && !(to_add.is_empty() && to_remove.is_empty())
                    {
                        recreated.insert(s.name());
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
                    // Elements that hold a recreated object let go of it
                    // first and come back after it.
                    for held in current_elems.iter().filter(|e| holds_recreated(e)) {
                        let same = |e: &SetElement| e.identity() == held.identity();
                        if !to_remove.iter().any(same) {
                            to_remove.push(held.clone());
                        }
                        if !to_add.iter().any(same) {
                            let declared_one = s.elements().iter().find(|e| same(e));
                            to_add.push(declared_one.unwrap_or(held).clone());
                        }
                    }
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
                if !declared_set_names.contains(s.name.as_str()) && (!shared || s.managed) {
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
            let current_rules =
                super::rules::rekey_derived(snapshot.rules_in(declared.name(), declared.family()));
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

                // A recreated chain loses every rule. The declared ones go
                // back in declared order; one nlink did not write cannot, so
                // it refuses the recreate, unless the chain is exclusive
                // (#478).
                if let Some(recreate) = diff.chains_to_recreate.iter_mut().find(|r| {
                    r.table == declared.name()
                        && r.family == declared.family()
                        && r.chain.name() == chain_name
                }) {
                    recreate.blocked_by = kernel_rules
                        .iter()
                        .filter(|kr| kr.key.is_none() && !exclusive)
                        .map(|kr| format!("rule handle {}", kr.handle))
                        .collect();
                    if recreate.is_refused() {
                        continue;
                    }
                    let keys: HashSet<&str> = declared_rules
                        .iter()
                        .filter_map(|r| r.handle_key())
                        .collect();
                    for kr in &kernel_rules {
                        if kr.key.as_deref().is_none_or(|k| !keys.contains(k)) {
                            diff.rules_to_delete.push(RuleDelete::of(kr));
                        }
                    }
                    for rule in &declared_rules {
                        let was = kernel_rules
                            .iter()
                            .find(|kr| kr.key.as_deref() == rule.handle_key());
                        match was {
                            Some(kr) => diff.rules_to_move.push(RuleMove {
                                table: declared.name().to_string(),
                                family: declared.family(),
                                chain: chain_name.to_string(),
                                from: RuleHandle(kr.handle),
                                placement: RulePlacement::Append,
                                rule: (*rule).clone(),
                                current: kr.nft_syntax_stateless(),
                                reason: MoveReason::ChainRecreated,
                                seq,
                            }),
                            None => diff.rules_to_add.push(RuleAdd {
                                rule: (*rule).clone(),
                                placement: RulePlacement::Append,
                                seq,
                            }),
                        }
                        seq += 1;
                    }
                    continue;
                }
                let slots: Vec<super::rules::KernelSlot> = kernel_rules
                    .iter()
                    .map(|kr| {
                        let bound_set = recreated.iter().any(|set| references_set(kr, set));
                        let bound_object = recreated_objects
                            .iter()
                            .any(|(name, ty)| references_object(kr, name, *ty));
                        let bound_flowtable = recreated_flowtables
                            .iter()
                            .any(|name| references_flowtable(kr, name));
                        let bound = bound_set || bound_object || bound_flowtable;
                        if bound && kr.key.is_none() && !exclusive {
                            // nlink cannot put it back, so the DELSET will be
                            // EBUSY. Say why before it happens.
                            tracing::warn!(
                                table = %declared.name(),
                                chain = chain_name,
                                handle = kr.handle,
                                "a rule nlink does not manage references a set or object this \
                                 diff recreates; the apply will fail with EBUSY until that rule \
                                 is removed",
                            );
                        }
                        super::rules::KernelSlot {
                            handle: kr.handle,
                            key: kr.key.clone(),
                            forced: match (kr.key.is_some(), bound_set, bound_object) {
                                (false, ..) => None,
                                (true, true, _) => Some(MoveReason::BoundToRecreatedSet),
                                (true, false, true) => Some(MoveReason::BoundToRecreatedObject),
                                (true, false, false) if bound_flowtable => {
                                    Some(MoveReason::BoundToRecreatedFlowtable)
                                }
                                (true, false, false) => None,
                            },
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

                // What the kernel has at a handle the plan names. The planner
                // only names the handles it was given, but a diff that cannot
                // say what a rule was still deletes it.
                let at = |handle: u64| kernel_rules.iter().copied().find(|kr| kr.handle == handle);
                for handle in plan.deletes {
                    let rule = at(handle);
                    diff.rules_to_delete.push(RuleDelete {
                        table: declared.name().to_string(),
                        family: declared.family(),
                        chain: chain_name.to_string(),
                        handle: RuleHandle(handle),
                        key: rule.and_then(|r| r.key.clone()),
                        current: rule.and_then(RuleInfo::nft_syntax_stateless),
                    });
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
                            current: at(from).and_then(RuleInfo::nft_syntax_stateless),
                            reason: insert.reason,
                            seq,
                        }),
                    }
                    seq += 1;
                }
                for (handle, i) in plan.replaces {
                    diff.rules_to_replace.push(RuleReplace {
                        table: declared.name().to_string(),
                        family: declared.family(),
                        chain: chain_name.to_string(),
                        handle: RuleHandle(handle),
                        current: at(handle).and_then(RuleInfo::nft_syntax_stateless),
                        rule: declared_rules[i].clone(),
                    });
                }
            }

            // Undeclared chains, sets and objects that a rule which stays
            // still uses are kept, not deleted: the rule planner leaves rules
            // nlink did not write alone, and deleting what one of them uses
            // is EBUSY, failing every apply (#459). Repeated until nothing
            // changes, because a kept chain keeps its rules, which can use
            // more.
            keep_what_staying_rules_use(&mut diff, declared, &current_rules);

            // The rules of a chain this diff deletes go explicitly, in the
            // apply's first phase. DELCHAIN would take them too, but only at
            // its own place, after the deletes of the sets and objects those
            // rules use — which are then EBUSY (#460).
            for (table, family, chain) in &diff.chains_to_delete {
                if table != declared.name() || *family != declared.family() {
                    continue;
                }
                for rule in current_rules.iter().filter(|r| &r.chain == chain) {
                    diff.rules_to_delete.push(RuleDelete::of(rule));
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

    /// A policy change is an update; a hook, priority or type change, or a
    /// base chain declared as a regular one, is a recreate (#478).
    #[test]
    fn chain_changes_the_kernel_cannot_update_are_recreates() {
        let chain_change_ = |d: &DeclaredChain, c: &ChainInfo| chain_change(d, c, false);
        use crate::netlink::nftables::{BaseChain, ChainType, FilterHook, Hook, Policy, Priority};

        let declared =
            |f: fn(super::super::DeclaredChainBuilder) -> super::super::DeclaredChainBuilder| {
                NftablesConfig::new()
                    .table("t", Family::Inet, move |t| t.chain("c", f))
                    .tables()[0]
                    .chains()[0]
                    .clone()
            };
        let live = ChainInfo {
            table: "t".into(),
            name: "c".into(),
            family: Family::Inet,
            hook: Some(Hook::Input.number(Family::Inet)),
            priority: Some(0),
            chain_type: Some(ChainType::Filter),
            policy: Some(Policy::Accept.to_u32()),
            handle: 1,
            device: None,
            devices: Vec::new(),
            comment: None,
            managed: true,
        };
        fn base(c: super::super::DeclaredChainBuilder) -> super::super::DeclaredChainBuilder {
            c.base(BaseChain::filter(FilterHook::Input, Priority::Filter))
        }
        assert_eq!(chain_change_(&declared(base), &live), ChainChange::None);
        assert_eq!(
            chain_change_(&declared(|c| base(c).policy(Policy::Drop)), &live),
            ChainChange::Update
        );
        assert_eq!(
            chain_change_(
                &declared(|c| base(c).priority(Priority::Custom(-10))),
                &live
            ),
            ChainChange::Recreate("priority 0 -> -10".into())
        );
        assert_eq!(
            chain_change_(
                &declared(
                    |c| base(c).base(BaseChain::filter(FilterHook::Forward, Priority::Filter))
                ),
                &live
            ),
            ChainChange::Recreate("hook 1 -> 2".into())
        );
        assert_eq!(
            chain_change_(&declared(|c| c), &live),
            ChainChange::Recreate("base chain -> regular chain".into())
        );
        let regular = ChainInfo {
            hook: None,
            priority: None,
            chain_type: None,
            policy: None,
            ..live.clone()
        };
        assert_eq!(chain_change_(&declared(|c| c), &regular), ChainChange::None);
        assert_eq!(
            chain_change_(&declared(base), &regular),
            ChainChange::Recreate("regular chain -> base chain".into())
        );
    }

    #[test]
    fn empty_diff_is_empty() {
        let d = NftablesDiff::default();
        assert!(d.is_empty());
        assert_eq!(d.change_count(), 0);
        assert_eq!(d.summary(), "NftablesDiff: no changes");
    }

    #[test]
    fn summary_renders_change_lines() {
        use super::super::super::types::{BaseChain, Family, FilterHook, Policy, Priority};
        use super::super::types::DeclaredChain;
        // Manually populate a diff to test the rendering — the
        // async diff() needs a live socket.
        let mut d = NftablesDiff::default();
        d.tables_to_delete
            .push((Family::Inet, "legacy".to_string()));
        let cfg = NftablesConfig::new().table("filter", Family::Inet, |t| {
            t.chain("input", |c| {
                c.base(BaseChain::filter(FilterHook::Input, Priority::Filter).policy(Policy::Drop))
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
        d.rules_to_replace.push(RuleReplace {
            table: "filter".to_string(),
            family: Family::Inet,
            chain: "input".to_string(),
            handle: RuleHandle(42),
            current: Some("tcp dport 23 counter accept".to_string()),
            rule: declared,
        });
        d.rules_to_delete.push(RuleDelete {
            table: "filter".to_string(),
            family: Family::Inet,
            chain: "input".to_string(),
            handle: RuleHandle(7),
            key: None,
            current: Some("udp dport 53 accept".to_string()),
        });
        let s = d.summary();
        assert!(
            s.contains(
                "~ rule Inet filter/input (handle=42 key=ssh): \
                 tcp dport 23 counter accept -> tcp dport 22 accept"
            ),
            "a replace says what the kernel has and what replaces it: {s}"
        );
        assert!(
            s.contains("- rule Inet filter/input (handle=7): udp dport 53 accept"),
            "a delete says what it removes: {s}"
        );
        assert_eq!(d.change_count(), 2);
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
    fn normalize_expressions_collapses_writer_vs_kernel_to_equal() {
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
        let n_declared = normalize_expressions(&declared);
        let n_kernel = normalize_expressions(&kernel);
        assert_eq!(
            n_declared, n_kernel,
            "normalize_expressions must canonicalize writer-side and kernel-side bytes \
             for the same logical rule to equal bytes"
        );
    }

    /// A zero-length attribute — the `*_PAD` some architectures put ahead
    /// of a 64-bit value — does not make two rule bodies differ (#484).
    #[test]
    fn normalize_expressions_drops_zero_length_attributes() {
        let attr = |ty: u16, payload: &[u8]| {
            let mut out = Vec::new();
            emit_tlv(&mut out, ty, payload);
            out
        };
        // A counter's data: PACKETS and BYTES, with and without a PAD.
        let counter = [attr(2, &7u64.to_be_bytes()), attr(1, &9u64.to_be_bytes())].concat();
        let padded = [attr(3, &[]), counter.clone()].concat();
        let elem = |data: &[u8]| attr(1, &[attr(1, b"counter\0"), attr(2, data)].concat());
        assert_eq!(
            normalize_expressions(&elem(&padded)),
            normalize_expressions(&elem(&counter))
        );
    }

    #[test]
    fn normalize_expressions_idempotent() {
        let kernel = hex_decode(PLAN178_KERNEL_HEX_FOR_PORT_1000);
        let once = normalize_expressions(&kernel);
        let twice = normalize_expressions(&once);
        assert_eq!(once, twice, "normalize_expressions must be idempotent");
    }

    #[test]
    fn normalize_expressions_differs_when_values_actually_differ() {
        // Two rules with different ports — must still diverge after
        // normalize, otherwise the diff would silently miss real
        // expression changes.
        use super::super::super::types::Rule;
        let r_a = Rule::new("filter_rec", "input").match_tcp_dport(1000).accept();
        let r_b = Rule::new("filter_rec", "input").match_tcp_dport(9000).accept();
        let a = normalize_expressions(&lower_to_expression_bytes(&r_a));
        let b = normalize_expressions(&lower_to_expression_bytes(&r_b));
        assert_ne!(a, b);
    }

    /// #721: a value that happens to parse as an empty attribute is still a
    /// value. `04 00 05 00` (`ip daddr 4.0.5.0`, or the mark `0x00050004` on
    /// a little-endian host) used to be read as a nest and dropped, so these
    /// compared equal and a change between them was never applied.
    #[test]
    fn values_that_look_like_attributes_still_differ() {
        use super::super::super::types::Rule;
        use std::net::Ipv4Addr;
        let addr = |a| {
            normalize_expressions(&lower_to_expression_bytes(
                &Rule::new("t", "c").match_daddr_v4(a, 32).accept(),
            ))
        };
        assert_ne!(addr(Ipv4Addr::new(4, 0, 5, 0)), addr(Ipv4Addr::new(4, 0, 6, 0)));
        let mark = |m| normalize_expressions(&lower_to_expression_bytes(&Rule::new("t", "c").match_mark(m).accept()));
        assert_ne!(mark(0x0005_0004), mark(0x0006_0004));

        // And so do the keys derived for them.
        let rule = |a| DeclaredRule {
            table: "t".into(),
            chain: "c".into(),
            family: Family::Inet,
            handle_key: None,
            body: Rule::new("t", "c").match_daddr_v4(a, 32).accept(),
        };
        let keys = super::super::rules::effective_rules(&[
            rule(Ipv4Addr::new(4, 0, 5, 0)),
            rule(Ipv4Addr::new(4, 0, 6, 0)),
        ]);
        assert_ne!(keys[0].handle_key(), keys[1].handle_key());
        assert!(!keys[1].handle_key().unwrap().ends_with(".1"), "{:?}", keys[1].handle_key());
    }

    /// #721: a kernel rule's derived key is recomputed from its body, so a
    /// rule installed under another normalization still matches.
    #[test]
    fn derived_keys_are_recomputed_from_the_kernel_body() {
        use super::super::super::types::Rule;
        let body = Rule::new("t", "c").match_tcp_dport(1000).accept();
        let declared = super::super::rules::effective_rules(&[DeclaredRule {
            table: "t".into(),
            chain: "c".into(),
            family: Family::Inet,
            handle_key: None,
            body: body.clone(),
        }]);
        let mut kernel = rule_info(lower_to_expression_bytes(&body));
        kernel.chain = "c".into();
        kernel.key = Some("~0123456789abcdef".to_string());
        let rekeyed = super::super::rules::rekey_derived(vec![kernel.clone(), kernel.clone()]);
        assert_eq!(rekeyed[0].key.as_deref(), declared[0].handle_key());
        assert_eq!(
            rekeyed[1].key.as_deref(),
            Some(format!("{}.1", declared[0].handle_key().unwrap()).as_str())
        );
        // An explicit key is the user's, and stays.
        kernel.key = Some("ssh".to_string());
        assert_eq!(super::super::rules::rekey_derived(vec![kernel])[0].key.as_deref(), Some("ssh"));
    }

    #[test]
    fn normalize_expressions_empty_input() {
        assert!(normalize_expressions(&[]).is_empty());
    }

    #[test]
    fn normalize_expressions_garbage_input_passes_through() {
        // Truncated TLV (claims len=100 in a 4-byte buffer) — bail
        // out and return the bytes verbatim. The diff path then
        // sees them as unequal to anything else, which is the
        // correct conservative behavior.
        let garbage = vec![0x64, 0x00, 0x01, 0x00];
        assert_eq!(normalize_expressions(&garbage), garbage);
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
            timeout: None,
            gc_interval: None,
            data_type: None,
            data_len: None,
            object_type: None,
            comment: None,
            managed: true,
            policy: Default::default(),
            statements: Vec::new(),
        }
    }

    fn declared_set(key_type: SetKeyType, flags: u32) -> DeclaredSet {
        let flags = SetFlags(flags);
        DeclaredSet {
            name: "s".to_string(),
            key_type,
            flags,
            size: None,
            timeout: None,
            gc_interval: None,
            element_mode: None,
            data_type: None,
            elements: Vec::new(),
            comment: None,
            policy: None,
            statements: Vec::new(),
        }
    }

    #[test]
    fn a_declared_timeout_drifts_by_whole_20ms_steps_and_an_update_keeps_the_kernels() {
        use crate::netlink::nftables::NFT_SET_TIMEOUT;
        use std::time::Duration;
        let ms = Duration::from_millis;
        let mut declared = declared_set(SetKeyType::Ipv4Addr, NFT_SET_TIMEOUT);
        let mut current = set_info(&SetKeyType::Ipv4Addr, NFT_SET_TIMEOUT);
        current.timeout = Some(ms(30_000));
        current.gc_interval = Some(ms(5_000));
        // Undeclared timers are no claim.
        assert!(!set_timers_have_drifted(&declared, &current));

        // 1001 ms reads back as 1000 at HZ=250 and 1003 at HZ=300.
        declared.timeout = Some(ms(1001));
        for read_back in [1000, 1003] {
            current.timeout = Some(ms(read_back));
            assert!(!set_timers_have_drifted(&declared, &current), "{read_back}");
        }
        current.timeout = Some(ms(980));
        assert!(set_timers_have_drifted(&declared, &current));

        // A resize carries the kernel's timers where none is declared:
        // the update would zero them otherwise (B6).
        declared.timeout = None;
        declared.size = Some(10);
        current.timeout = Some(ms(30_000));
        let update = set_update(&declared, &current);
        assert_eq!(update.timeout(), Some(ms(30_000)));
        assert_eq!(update.gc_interval(), Some(ms(5_000)));
        assert_eq!(update.size(), Some(10));
    }

    #[test]
    fn a_map_element_whose_data_changed_is_replaced_and_a_data_type_change_recreates() {
        use crate::netlink::nftables::{SetDataType, Verdict};
        let a = std::net::Ipv4Addr::new(10, 0, 0, 1);
        let mut declared = declared_set(SetKeyType::Ipv4Addr, 0);
        declared.data_type = Some(SetDataType::Verdict);
        declared.flags = SetFlags::MAP;
        declared.elements = vec![SetElement::ipv4(a).verdict(Verdict::Drop)];
        let kernel = [SetElement::ipv4(a).verdict(Verdict::Accept)];
        let (add, remove) = element_changes(&declared, &kernel);
        assert_eq!((add.len(), remove.len()), (1, 1));
        assert_eq!(remove[0].data(), kernel[0].data());
        // Even in Ensure mode: the element is declared.
        declared.element_mode = Some(SetElementMode::Ensure);
        assert_eq!(element_changes(&declared, &kernel).1.len(), 1);
        // Same data: nothing to do.
        assert_eq!(element_changes(&declared, &declared.elements.clone()), (vec![], vec![]));

        let mut current = set_info(&SetKeyType::Ipv4Addr, crate::netlink::nftables::NFT_SET_MAP);
        current.data_type = Some(crate::netlink::nftables::NFT_DATA_VERDICT);
        current.data_len = Some(16);
        assert!(!set_has_drifted(&declared, &current), "the kernel sizes a verdict");
        current.data_type = Some(19);
        assert!(set_has_drifted(&declared, &current));
    }

    #[test]
    fn objects_compare_configuration_only_and_only_a_quota_updates_in_place() {
        use super::super::super::expr::{LimitExpr, QuotaExpr};
        use super::super::super::types::LimitUnit;
        let quota = |b| ObjectConfig::Quota(QuotaExpr::new(b));
        assert_eq!(object_change(&quota(10), Some(quota(10))), ObjectChange::Nothing);
        assert_eq!(object_change(&quota(10), Some(quota(20))), ObjectChange::Update);
        let limit = |r, burst| ObjectConfig::Limit(LimitExpr::packets(r, LimitUnit::Second).burst(burst));
        // Burst 0 is sent, stored and dumped as the kernel's 5.
        assert_eq!(object_change(&limit(10, 0), Some(limit(10, 5))), ObjectChange::Nothing);
        assert_eq!(object_change(&limit(10, 5), Some(limit(20, 5))), ObjectChange::Recreate);
        // A state nlink cannot read is recreated rather than trusted.
        assert_eq!(object_change(&limit(10, 5), None), ObjectChange::Recreate);
        assert_eq!(object_change(&ObjectConfig::Counter, Some(ObjectConfig::Counter)), ObjectChange::Nothing);
    }

    #[test]
    fn a_dynamic_or_timeout_set_only_ensures_its_declared_elements() {
        use crate::netlink::nftables::{NFT_SET_EVAL, NFT_SET_TIMEOUT};
        let runtime = [SetElement::ipv4(std::net::Ipv4Addr::new(10, 0, 0, 9))];
        for flags in [NFT_SET_EVAL, NFT_SET_TIMEOUT] {
            let declared = declared_set(SetKeyType::Ipv4Addr, flags);
            assert_eq!(declared.element_mode(), SetElementMode::Ensure);
            let (add, remove) = element_changes(&declared, &runtime);
            assert!(add.is_empty() && remove.is_empty(), "flags {flags:#x}");
        }
        // A plain set is exact, unless told otherwise.
        let mut declared = declared_set(SetKeyType::Ipv4Addr, 0);
        assert_eq!(declared.element_mode(), SetElementMode::Exact);
        assert_eq!(element_changes(&declared, &runtime).1.len(), 1);
        declared.element_mode = Some(SetElementMode::Ensure);
        assert!(element_changes(&declared, &runtime).1.is_empty());
        // And a dynamic set can be made exact.
        let mut declared = declared_set(SetKeyType::Ipv4Addr, NFT_SET_EVAL);
        declared.element_mode = Some(SetElementMode::Exact);
        assert_eq!(element_changes(&declared, &runtime).1.len(), 1);
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
    fn references_chain_and_flowtable_see_what_a_rule_names() {
        use crate::netlink::nftables::types::{ChainName, Rule};

        let jump = Rule::new("t", "c").jump(ChainName::new("dbg").unwrap());
        let jump = rule_info(lower_to_expression_bytes(&jump));
        assert!(references_chain(&jump, "dbg"));
        assert!(!references_chain(&jump, "other"));

        let goto = Rule::new("t", "c").goto(ChainName::new("dbg").unwrap());
        let goto = rule_info(lower_to_expression_bytes(&goto));
        assert!(references_chain(&goto, "dbg"));

        let offload = Rule::new("t", "c").flow_offload("ft");
        let offload = rule_info(lower_to_expression_bytes(&offload));
        assert!(references_flowtable(&offload, "ft"));
        assert!(!references_flowtable(&offload, "other"));
        assert!(!references_chain(&offload, "ft"));
    }

    #[test]
    fn kept_in_use_is_not_a_change_but_is_shown() {
        let mut d = NftablesDiff::default();
        d.kept_in_use.push(KeptInUse::Set {
            table: "t".into(),
            family: Family::Inet,
            name: "blocked".into(),
        });
        assert!(d.is_empty());
        assert_eq!(d.change_count(), 0);
        assert_eq!(
            d.to_string(),
            "NftablesDiff: no changes\n  ! set Inet t/blocked kept: a rule nlink does not manage uses it"
        );
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

    #[test]
    fn the_concat_flag_the_kernel_reports_for_a_concatenated_interval_set_is_not_drift() {
        use crate::netlink::nftables::{NFT_SET_CONCAT, NFT_SET_INTERVAL};
        let concat = SetKeyType::Concat(vec![SetKeyType::Ipv4Addr, SetKeyType::InetService]);
        let declared = declared_set(concat.clone(), NFT_SET_INTERVAL);
        let reported = set_info(&concat, NFT_SET_INTERVAL | NFT_SET_CONCAT);
        assert!(!set_has_drifted(&declared, &reported));
        // Without it, the set was not made with its field lengths: recreate.
        assert!(set_has_drifted(&declared, &set_info(&concat, NFT_SET_INTERVAL)));
        assert!(!declared.merges_ranges(), "each field is its own range");
    }
}
