//! Rule identity, comparison and ordering for the declarative diff.
//!
//! Three things a declared chain needs to converge:
//!
//! - **Identity.** A rule's key lives in its comment, `nlink:<key>`. A rule
//!   declared without one gets a key derived from its content
//!   ([`effective_rules`]), so it is matched rather than re-added on every
//!   apply.
//! - **Comparison.** The kernel echoes live state — a counter's packets and
//!   bytes, a quota's consumption — so bodies are compared with that state
//!   zeroed on both sides ([`canonicalize_for_compare`]).
//! - **Order.** First match wins, so declared order is enforced, moving as
//!   few rules as possible ([`plan_chain`]).

use std::collections::{HashMap, HashSet};

use super::diff::{MoveReason, RulePlacement};
use super::types::DeclaredRule;
use crate::netlink::error::{Error, Result};

/// The declared rules with every key filled in: explicit keys as given,
/// and for a rule without one, `~` + the FNV-1a-64 of its chain, its
/// expression bytes and its comment — `.N` appended to the Nth identical
/// rule in the same chain.
///
/// The hash is hand-rolled: the key is stored in the kernel, so it has to
/// be the same on every build, which `std`'s `DefaultHasher` does not
/// promise.
pub(crate) fn effective_rules(rules: &[DeclaredRule]) -> Vec<DeclaredRule> {
    let mut seen: HashMap<(String, String), usize> = HashMap::new();
    rules
        .iter()
        .map(|rule| {
            if rule.handle_key.is_some() {
                return rule.clone();
            }
            let body = super::diff::normalize_tlv(&super::diff::lower_to_expression_bytes(
                &rule.body,
            ));
            let hash = fnv1a64(&[
                rule.chain.as_bytes(),
                &body,
                rule.body.comment.as_deref().unwrap_or("").as_bytes(),
            ]);
            let base = format!("~{hash:016x}");
            let n = seen.entry((rule.chain.clone(), base.clone())).or_insert(0);
            let key = if *n == 0 {
                base
            } else {
                format!("{base}.{n}")
            };
            *n += 1;
            let mut rule = rule.clone();
            rule.handle_key = Some(key);
            rule
        })
        .collect()
}

const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

impl super::types::NftablesConfig {
    /// Check the config before any kernel round-trip; [`diff`] calls this
    /// first. Everything here would otherwise fail half-way through an
    /// apply, or — worse — install something that does not mean what was
    /// declared:
    ///
    /// - a rule key must be 1–121 bytes of printable ASCII without spaces,
    ///   not start with `~`, and be unique in its chain;
    /// - a rule's key and comment together must fit the kernel's 127-byte
    ///   comment;
    /// - a declared rule cannot carry a [`position`](crate::netlink::nftables::Rule::position):
    ///   the diff places rules in declared order;
    /// - every declared set element must fit its set.
    ///
    /// [`diff`]: Self::diff
    pub fn validate(&self) -> Result<()> {
        for table in self.tables() {
            let mut seen: HashSet<(&str, &str)> = HashSet::new();
            for rule in table.rules() {
                let chain = rule.chain();
                if rule.body.position.is_some() {
                    return Err(Error::InvalidMessage(format!(
                        "{}/{chain}: a declared rule cannot carry a position; the diff \
                         places rules in declared order",
                        table.name()
                    )));
                }
                if let Some(key) = rule.handle_key() {
                    validate_key(table.name(), chain, key)?;
                    if !seen.insert((chain, key)) {
                        return Err(Error::InvalidMessage(format!(
                            "{}/{chain}: rule key `{key}` is declared twice",
                            table.name()
                        )));
                    }
                }
            }
            for rule in effective_rules(table.rules()) {
                crate::netlink::nftables::userdata::encode_rule_userdata(
                    rule.handle_key(),
                    rule.body.comment.as_deref(),
                )
                .map_err(|e| {
                    Error::InvalidMessage(format!("{}/{}: {e}", table.name(), rule.chain()))
                })?;
            }
            for set in table.sets() {
                crate::netlink::nftables::connection::check_elements(
                    &set.to_set(table.name(), table.family()),
                    set.elements(),
                    crate::netlink::nftables::connection::ElementWrite::Add,
                )?;
            }
        }
        Ok(())
    }
}

/// FNV-1a, 64-bit, over `parts`, each followed by a `0xff` separator so
/// `["ab", "c"]` and `["a", "bc"]` differ.
fn fnv1a64(parts: &[&[u8]]) -> u64 {
    parts
        .iter()
        .fold(FNV_OFFSET, |hash, part| fnv_feed(fnv_feed(hash, part), &[0xff]))
}

/// Feed `bytes` into an FNV-1a-64 state.
fn fnv_feed(mut hash: u64, bytes: &[u8]) -> u64 {
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
}

/// Check an explicit rule key: 1–121 bytes (`nlink:<key>` and the NUL must
/// fit the kernel's 128), printable ASCII without spaces (a space separates
/// the key from a comment), and not starting with `~` (reserved for derived
/// keys).
pub(crate) fn validate_key(table: &str, chain: &str, key: &str) -> Result<()> {
    let bad = |why: &str| {
        Err(Error::InvalidMessage(format!(
            "{table}/{chain}: rule key `{key}` {why}"
        )))
    };
    if key.is_empty() {
        return bad("is empty");
    }
    if key.len() > 121 {
        return bad(&format!(
            "is {} bytes; at most 121 fit in a rule comment",
            key.len()
        ));
    }
    if !key.bytes().all(|b| b.is_ascii_graphic()) {
        return bad("must be printable ASCII without spaces");
    }
    if key.starts_with('~') {
        return bad("starts with `~`, which is reserved for derived keys");
    }
    Ok(())
}

/// Zero the live state the kernel echoes in a rule body, in place, so a
/// declared rule compares equal to its echo however much traffic it has
/// seen: a `counter`'s packets and bytes, a `quota`'s consumed bytes and
/// its depleted flag. Works on [`normalize_tlv`](super::diff::normalize_tlv)
/// output; anything that does not walk as TLVs is left as it is.
pub(crate) fn canonicalize_for_compare(mut bytes: Vec<u8>) -> Vec<u8> {
    use crate::netlink::nftables::{
        NFTA_COUNTER_BYTES, NFTA_COUNTER_PACKETS, NFTA_DYNSET_TIMEOUT, NFTA_EXPR_DATA,
        NFTA_EXPR_NAME, NFTA_LIST_ELEM, NFTA_QUOTA_CONSUMED, NFTA_QUOTA_FLAGS,
        NFT_QUOTA_F_DEPLETED,
    };
    for (ty, elem_at, elem_len) in tlvs(&bytes, 0, bytes.len()) {
        if ty != NFTA_LIST_ELEM {
            continue;
        }
        let mut name: Option<&[u8]> = None;
        let mut data: Option<(usize, usize)> = None;
        for (ty, at, len) in tlvs(&bytes, elem_at, elem_len) {
            match ty {
                NFTA_EXPR_NAME => name = Some(&bytes[at..at + len]),
                NFTA_EXPR_DATA => data = Some((at, len)),
                _ => {}
            }
        }
        let (Some(name), Some((data_at, data_len))) = (name, data) else {
            continue;
        };
        let name = name.strip_suffix(b"\0").unwrap_or(name).to_vec();
        for (ty, at, len) in tlvs(&bytes, data_at, data_len) {
            match (name.as_slice(), ty) {
                (b"counter", NFTA_COUNTER_BYTES | NFTA_COUNTER_PACKETS)
                | (b"quota", NFTA_QUOTA_CONSUMED) => bytes[at..at + len].fill(0),
                (b"quota", NFTA_QUOTA_FLAGS) if len == 4 => {
                    let flags = u32::from_be_bytes(bytes[at..at + 4].try_into().unwrap());
                    let flags = flags & !NFT_QUOTA_F_DEPLETED;
                    bytes[at..at + 4].copy_from_slice(&flags.to_be_bytes());
                }
                (b"dynset", NFTA_DYNSET_TIMEOUT) if len == 8 => {
                    let ms = u64::from_be_bytes(bytes[at..at + 8].try_into().unwrap());
                    bytes[at..at + 8].copy_from_slice(&timeout_step(ms).to_be_bytes());
                }
                _ => {}
            }
        }
    }
    bytes
}

/// A timeout in milliseconds as the kernel can read it back, at any `HZ`:
/// rounded down to a multiple of 20 ms.
///
/// The kernel keeps timeouts in jiffies, converting with
/// `nsecs_to_jiffies64` (rounding down) and back with `jiffies64_to_msecs`
/// (rounding down again), so `1001 ms` reads back as `1000 ms` at `HZ=250`
/// and `1003 ms` at `HZ=300`. 20 ms is a whole number of jiffies at every
/// `HZ` Linux offers (100, 250, 300, 1000), so a value and its read-back
/// always fall in the same 20 ms step — and nlink cannot know the kernel's
/// `HZ`.
pub(crate) fn timeout_step(ms: u64) -> u64 {
    ms - ms % 20
}

/// The attributes in `buf[at..at + len]`: `(type, payload offset, payload
/// length)`, flag bits masked off. Stops at the first malformed header.
fn tlvs(buf: &[u8], at: usize, len: usize) -> Vec<(u16, usize, usize)> {
    let end = at + len;
    let mut out = Vec::new();
    let mut pos = at;
    while pos + 4 <= end {
        let nla_len = u16::from_ne_bytes([buf[pos], buf[pos + 1]]) as usize;
        let ty = u16::from_ne_bytes([buf[pos + 2], buf[pos + 3]]) & !0xc000;
        if nla_len < 4 || pos + nla_len > end {
            break;
        }
        out.push((ty, pos + 4, nla_len - 4));
        pos += nla_len.next_multiple_of(4);
    }
    out
}

/// One kernel rule as the planner sees it.
#[derive(Debug, Clone)]
pub(crate) struct KernelSlot {
    pub(crate) handle: u64,
    /// nlink key, or `None` for a rule nlink did not write.
    pub(crate) key: Option<String>,
    /// Why it has to move whatever the order: bound to a set or object
    /// this diff recreates, so it is deleted ahead of it and put back
    /// afterwards.
    pub(crate) forced: Option<MoveReason>,
}

/// A declared rule to insert, in emission order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PlannedInsert {
    /// Index into the chain's declared rules.
    pub(crate) declared: usize,
    pub(crate) placement: RulePlacement,
    /// Kernel handle being moved, or `None` for a new rule.
    pub(crate) from: Option<u64>,
    pub(crate) reason: MoveReason,
}

/// What one chain needs.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct ChainPlan {
    /// Kernel handles to delete: nlink rules no longer declared, duplicate
    /// keys, and — in an exclusive chain — rules nlink did not write.
    pub(crate) deletes: Vec<u64>,
    /// New and moved rules, in the order they must be sent.
    pub(crate) inserts: Vec<PlannedInsert>,
    /// Rules that stay where they are but whose body or comment changed:
    /// `(handle, declared index)`.
    pub(crate) replaces: Vec<(u64, usize)>,
}

/// Plan one chain: bring the kernel's rules (`kernel`, in chain order) to
/// the declared ones (`declared_keys`, in declared order).
///
/// Rules nlink did not write are fixed points and never touched (unless the
/// chain is `exclusive`, when they are deleted). Of the declared rules
/// already installed, the longest run that is already in declared order
/// stays put; every other declared rule is inserted — or, if installed out
/// of order or `forced`, deleted and re-inserted — immediately before the
/// next staying rule, or after the last one, or at the end of the chain.
///
/// `changed(declared, kernel_pos)` says whether a staying rule's body or
/// comment differs; those are replaced in place. With `enforce_order` off,
/// every installed rule stays and only new rules are placed.
pub(crate) fn plan_chain(
    kernel: &[KernelSlot],
    declared_keys: &[&str],
    changed: impl Fn(usize, usize) -> bool,
    exclusive: bool,
    enforce_order: bool,
) -> ChainPlan {
    let mut plan = ChainPlan::default();
    let by_key: HashMap<&str, usize> = declared_keys
        .iter()
        .enumerate()
        .map(|(i, k)| (*k, i))
        .collect();

    // Match each declared rule to the first kernel rule with its key.
    let mut matched: Vec<Option<usize>> = vec![None; declared_keys.len()];
    for (pos, slot) in kernel.iter().enumerate() {
        match slot.key.as_deref() {
            Some(key) => match by_key.get(key) {
                Some(&i) if matched[i].is_none() => matched[i] = Some(pos),
                // Undeclared, or a second rule with a key already matched.
                _ => plan.deletes.push(slot.handle),
            },
            None if exclusive => plan.deletes.push(slot.handle),
            None => {}
        }
    }

    // The declared rules that may stay, in kernel order.
    let mut candidates: Vec<(usize, usize)> = matched
        .iter()
        .enumerate()
        .filter_map(|(i, pos)| pos.filter(|&p| kernel[p].forced.is_none()).map(|p| (p, i)))
        .collect();
    candidates.sort_unstable();
    let order: Vec<usize> = candidates.iter().map(|&(_, i)| i).collect();
    let staying: HashSet<usize> = if enforce_order {
        longest_increasing(&order)
    } else {
        order.iter().copied().collect()
    };
    let mut staying_sorted: Vec<usize> = staying.iter().copied().collect();
    staying_sorted.sort_unstable();
    let handle_of = |i: usize| RuleHandle(kernel[matched[i].unwrap()].handle);

    let mut before = Vec::new();
    let mut after = Vec::new();
    let mut append = Vec::new();
    for i in (0..declared_keys.len()).filter(|i| !staying.contains(i)) {
        let from = matched[i].map(|p| kernel[p].handle);
        let reason = matched[i]
            .and_then(|p| kernel[p].forced)
            .unwrap_or(MoveReason::Reorder);
        let next = staying_sorted.iter().find(|&&j| j > i);
        let prev = staying_sorted.iter().rev().find(|&&j| j < i);
        let insert = |placement| PlannedInsert {
            declared: i,
            placement,
            from,
            reason,
        };
        match (next, prev) {
            (Some(&j), _) => before.push(insert(RulePlacement::Before(handle_of(j)))),
            (None, Some(&j)) => after.push(insert(RulePlacement::After(handle_of(j)))),
            (None, None) => append.push(insert(RulePlacement::Append)),
        }
    }
    // Inserts before the same anchor go in declared order; inserts after
    // the same anchor go in reverse, each landing right after it.
    after.reverse();
    plan.inserts.extend(before);
    plan.inserts.extend(after);
    plan.inserts.extend(append);

    for &i in &staying_sorted {
        let pos = matched[i].unwrap();
        if changed(i, pos) {
            plan.replaces.push((kernel[pos].handle, i));
        }
    }
    plan
}

use super::diff::RuleHandle;

/// The positions (into `seq`) of one longest strictly increasing
/// subsequence, returned as the set of its values.
fn longest_increasing(seq: &[usize]) -> HashSet<usize> {
    // tails[k] = index into `seq` of the smallest tail of an increasing
    // run of length k + 1; prev links reconstruct the run.
    let mut tails: Vec<usize> = Vec::new();
    let mut prev: Vec<Option<usize>> = vec![None; seq.len()];
    for (i, &v) in seq.iter().enumerate() {
        let k = tails.partition_point(|&t| seq[t] < v);
        if k > 0 {
            prev[i] = Some(tails[k - 1]);
        }
        if k == tails.len() {
            tails.push(i);
        } else {
            tails[k] = i;
        }
    }
    let mut out = HashSet::new();
    let mut cur = tails.last().copied();
    while let Some(i) = cur {
        out.insert(seq[i]);
        cur = prev[i];
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_timeout_and_its_read_back_share_a_20ms_step_at_every_hz() {
        // The kernel's round trip: msecs -> jiffies (down) -> msecs (down).
        for hz in [100u64, 250, 300, 1000] {
            for ms in [1u64, 19, 20, 999, 1001, 1500, 3_600_000] {
                let jiffies = (ms * 1_000_000 / (1_000_000_000 / hz)).max(1);
                let read_back = jiffies * 1000 / hz;
                assert_eq!(timeout_step(ms), timeout_step(read_back), "HZ={hz} ms={ms}");
            }
        }
    }

    fn slots(keys: &[Option<&str>]) -> Vec<KernelSlot> {
        keys.iter()
            .enumerate()
            .map(|(i, k)| KernelSlot {
                handle: 100 + i as u64,
                key: k.map(str::to_string),
                forced: None,
            })
            .collect()
    }

    fn plan(kernel: &[KernelSlot], declared: &[&str]) -> ChainPlan {
        plan_chain(kernel, declared, |_, _| false, false, true)
    }

    #[test]
    fn an_up_to_date_chain_needs_nothing() {
        let k = slots(&[Some("a"), Some("b"), Some("c")]);
        assert_eq!(plan(&k, &["a", "b", "c"]), ChainPlan::default());
    }

    #[test]
    fn a_new_rule_goes_before_the_next_declared_one() {
        let k = slots(&[Some("a"), Some("z")]);
        let p = plan(&k, &["a", "m", "z"]);
        assert_eq!(
            p.inserts,
            [PlannedInsert {
                declared: 1,
                placement: RulePlacement::Before(RuleHandle(101)),
                from: None,
                reason: MoveReason::Reorder,
            }]
        );
        assert!(p.deletes.is_empty() && p.replaces.is_empty());
    }

    #[test]
    fn rules_after_the_last_installed_one_go_after_it_in_reverse() {
        let k = slots(&[Some("a")]);
        let p = plan(&k, &["a", "b", "c"]);
        // Each lands right after `a`, so c is sent before b.
        let order: Vec<_> = p.inserts.iter().map(|i| (i.declared, i.placement)).collect();
        assert_eq!(
            order,
            [
                (2, RulePlacement::After(RuleHandle(100))),
                (1, RulePlacement::After(RuleHandle(100))),
            ]
        );
    }

    #[test]
    fn an_empty_chain_is_filled_by_appending_in_order() {
        let p = plan(&[], &["a", "b"]);
        let order: Vec<_> = p.inserts.iter().map(|i| (i.declared, i.placement)).collect();
        assert_eq!(order, [(0, RulePlacement::Append), (1, RulePlacement::Append)]);
    }

    #[test]
    fn a_reorder_moves_only_what_is_out_of_order() {
        // [a, b, c] -> [c, a, b]: a and b stay, c moves before a.
        let k = slots(&[Some("a"), Some("b"), Some("c")]);
        let p = plan(&k, &["c", "a", "b"]);
        assert_eq!(
            p.inserts,
            [PlannedInsert {
                declared: 0,
                placement: RulePlacement::Before(RuleHandle(100)),
                from: Some(102),
                reason: MoveReason::Reorder,
            }]
        );
    }

    #[test]
    fn undeclared_and_duplicate_rules_are_deleted_and_foreign_ones_kept() {
        let k = slots(&[Some("a"), None, Some("gone"), Some("a")]);
        let p = plan(&k, &["a"]);
        assert_eq!(p.deletes, [102, 103]);
        assert!(p.inserts.is_empty());
    }

    #[test]
    fn an_exclusive_chain_deletes_foreign_rules() {
        let k = slots(&[None, Some("a")]);
        let p = plan_chain(&k, &["a"], |_, _| false, true, true);
        assert_eq!(p.deletes, [100]);
    }

    #[test]
    fn a_forced_rule_moves_back_to_its_place() {
        let mut k = slots(&[Some("a"), Some("b"), Some("c")]);
        k[1].forced = Some(MoveReason::BoundToRecreatedSet);
        let p = plan(&k, &["a", "b", "c"]);
        assert_eq!(
            p.inserts,
            [PlannedInsert {
                declared: 1,
                placement: RulePlacement::Before(RuleHandle(102)),
                from: Some(101),
                reason: MoveReason::BoundToRecreatedSet,
            }]
        );
    }

    #[test]
    fn changed_staying_rules_are_replaced_in_place() {
        let k = slots(&[Some("a"), Some("b")]);
        let p = plan_chain(&k, &["a", "b"], |i, _| i == 1, false, true);
        assert_eq!(p.replaces, [(101, 1)]);
        assert!(p.inserts.is_empty());
    }

    #[test]
    fn without_order_enforcement_installed_rules_stay() {
        let k = slots(&[Some("a"), Some("b"), Some("c")]);
        let p = plan_chain(&k, &["c", "a", "b"], |_, _| false, false, false);
        assert!(p.inserts.is_empty());
    }

    #[test]
    fn longest_increasing_keeps_the_longest_ordered_run() {
        assert_eq!(longest_increasing(&[0, 1, 2]), HashSet::from([0, 1, 2]));
        assert_eq!(longest_increasing(&[1, 2, 0]), HashSet::from([1, 2]));
        assert_eq!(longest_increasing(&[3, 0, 1, 2]), HashSet::from([0, 1, 2]));
        assert!(longest_increasing(&[]).is_empty());
    }

    #[test]
    fn fnv_is_the_standard_fnv1a_64() {
        // Reference vectors (the FNV authors' test suite). The derived keys
        // live in kernels, so the hash must never change between builds.
        assert_eq!(fnv_feed(FNV_OFFSET, b""), 0xcbf2_9ce4_8422_2325);
        assert_eq!(fnv_feed(FNV_OFFSET, b"a"), 0xaf63_dc4c_8601_ec8c);
        assert_eq!(fnv_feed(FNV_OFFSET, b"foobar"), 0x8594_4171_f739_67e8);
        assert_eq!(
            fnv1a64(&[b"a"]),
            fnv_feed(fnv_feed(FNV_OFFSET, b"a"), &[0xff])
        );
        assert_ne!(fnv1a64(&[b"ab", b"c"]), fnv1a64(&[b"a", b"bc"]));
    }

    #[test]
    fn keys_are_validated() {
        assert!(validate_key("t", "c", "ssh").is_ok());
        assert!(validate_key("t", "c", &"k".repeat(121)).is_ok());
        assert!(validate_key("t", "c", &"k".repeat(122)).is_err());
        assert!(validate_key("t", "c", "").is_err());
        assert!(validate_key("t", "c", "has space").is_err());
        assert!(validate_key("t", "c", "~derived").is_err());
    }
}
