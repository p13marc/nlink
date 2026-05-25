---
to: nlink maintainer
from: 0.16 cycle work
subject: Plan 157 §4.3 redesign — per-rule USERDATA-keyed identity (matches NetworkConfig pattern)
status: design proposal — awaiting sign-off
related: 157-0.16-nftables-declarative-config-plan.md
created: 2026-05-24
revision: v2 — switched from chain-level hashing to per-rule identity after maintainer feedback on NetworkConfig-symmetry
---

# Plan 157b — rule reconciliation redesign

## TL;DR

**Drop typed-Match canonicalization (Plan 157 §4.3).** No production
tool implements it (research summary in §3 below). The user-facing
limitation that motivated the design — "declared rule's identity
against the kernel" — is solved everywhere else with a *user-supplied
identity field* (`NFTA_RULE_USERDATA` carrying a TLV-formatted
comment, the libnftnl + Google-`nftables` pattern), not byte-level
equivalence.

**Adopt: per-rule USERDATA-keyed identity.** `DeclaredRule::handle_key`
(which already exists in nlink today but is unwired) becomes the
identity field — analogous to `Link::name`, `Route::destination`,
`Address::ip_with_prefix` in the existing `NetworkConfig`. Each
declared rule with a `handle_key` is encoded as
`NFTA_RULE_USERDATA = TLV(NFTNL_UDATA_RULE_COMMENT, "nlink:<key>")`
on apply. The kernel preserves it; we parse it back on dump. Diff
matches by key. Body changes trigger in-place rule replace via the
kernel's native `NFT_MSG_NEWRULE + NLM_F_REPLACE + handle`.

This is **the same shape** as the existing `NetworkConfig`
per-object diff: identity field → match → compare → update/add/delete.

## Why the previous v1 was wrong (chain-level hashing)

v1 proposed chain-content-hash + `flush chain` on mismatch. That
*works*, and it's exactly what kube-proxy does, but it breaks
parity with the rest of nlink's declarative-config story:

| Resource | nlink identity field | Diff granularity |
|---|---|---|
| `LinkConfig` (`NetworkConfig`) | `Link::name` | per-link |
| `RouteConfig` | (destination, table, oif) tuple | per-route |
| `AddressConfig` | (iface, ip/prefix) | per-address |
| `QdiscConfig` | (iface, handle) | per-qdisc |
| **`DeclaredRule` (v1: chain-level)** | — | **per-chain** (asymmetric) |
| **`DeclaredRule` (v2: per-rule USERDATA)** | `handle_key` → USERDATA | **per-rule** ✓ |

A user updating one rule's destination port in a 100-rule chain
should get a 1-op diff (`replace rule handle=X`), not a 101-op
diff (`flush chain ; add 100 rules`). v2 delivers that; v1 didn't.

The kube-proxy precedent is good *for kube-proxy* — they need
chain-as-unit because they regenerate the whole chain anyway when
the underlying Service changes (Service is the source of truth, not
individual rules). Our user model is different: the
`NftablesConfig` IS the source of truth and each declared rule is
a distinct intent.

## Why this matches production patterns

The research turned up that real production tooling uses
USERDATA comment tagging for rule identity, *not* canonical
equivalence:

- **Google's `nftables` Go library** has [`userdata.MakeRuleComment`](https://pkg.go.dev/github.com/google/nftables/userdata)
  + reverse parser. Used by virtually everyone building on it.
- **libnftnl** ships `nftnl_udata_parse` + `NFTNL_UDATA_RULE_COMMENT`
  type code for exactly this.
- **Cilium-iptables** (and the planned Cilium-nftables backend per
  [#4825](https://github.com/cilium/cilium/issues/4825)) uses a
  comment prefix like `cilium:<hash>` to find its own rules vs
  external rules.
- **`nft list ruleset`** renders `NFTA_RULE_USERDATA` as inline
  `comment "..."` so operators can grep / diff text-mode output.

The pattern is: **user-supplied identity key**, not
algorithm-derived canonical hash. Aligns with how every other
declarative-config system works (Kubernetes' object names, GCP
resource IDs, Terraform addresses).

## Detailed design

### 5.1 Wire-format addition — USERDATA TLV

Kernel UAPI: `NFTA_RULE_USERDATA = 7` (opaque `NLA_BINARY`,
preserved verbatim, max `NFT_USERDATA_MAXLEN = 256` bytes).

libnftnl-compatible TLV format (so `nft list ruleset` renders our
keys as inline comments):

```
+--------+--------+--------+-----+
| type=0 | length |   data        |
+--------+--------+--------+-----+
    1 byte    1 byte    N bytes
```

Where `type=0` is `NFTNL_UDATA_RULE_COMMENT`, length includes the
trailing NUL byte (libnftnl convention), and data is the comment
string. Max payload is `NFTNL_UDATA_COMMENT_MAXLEN = 128` bytes.

```rust
// crates/nlink/src/netlink/nftables/userdata.rs (new file)

pub(crate) const NFTNL_UDATA_RULE_COMMENT: u8 = 0;
pub(crate) const NFTNL_UDATA_COMMENT_MAXLEN: usize = 128;

/// Encode an `nlink:<key>` comment as libnftnl-compatible TLV
/// userdata bytes. Returns `None` if the key is too long.
pub(crate) fn encode_nlink_comment(key: &str) -> Option<Vec<u8>> {
    let body = format!("nlink:{key}\0");
    let body_bytes = body.as_bytes();
    if body_bytes.len() > NFTNL_UDATA_COMMENT_MAXLEN {
        return None;
    }
    let mut tlv = Vec::with_capacity(2 + body_bytes.len());
    tlv.push(NFTNL_UDATA_RULE_COMMENT);
    tlv.push(body_bytes.len() as u8);
    tlv.extend_from_slice(body_bytes);
    Some(tlv)
}

/// Decode a libnftnl TLV userdata payload and extract an
/// `nlink:<key>` comment. Returns `None` for foreign comments
/// (kept-as-is — we don't manage them).
pub(crate) fn parse_nlink_comment(userdata: &[u8]) -> Option<String> {
    let mut cursor = userdata;
    while cursor.len() >= 2 {
        let ty = cursor[0];
        let len = cursor[1] as usize;
        if cursor.len() < 2 + len {
            return None;
        }
        let payload = &cursor[2..2 + len];
        if ty == NFTNL_UDATA_RULE_COMMENT {
            // Strip trailing NUL.
            let s = std::str::from_utf8(payload).ok()?
                .trim_end_matches('\0');
            return s.strip_prefix("nlink:").map(str::to_string);
        }
        cursor = &cursor[2 + len..];
    }
    None
}
```

`encode_nlink_comment("input:ssh-accept")` → 23-byte TLV.

### 5.2 Rule emit + parse — USERDATA round-trip

**Apply path** (`crates/nlink/src/netlink/nftables/connection.rs`,
the existing `add_rule` builder code):

```rust
// In Transaction::serialize_add_rule (or wherever NFT_MSG_NEWRULE
// is built), after writing the expressions:
if let Some(comment) = &rule.comment {
    if let Some(udata) = userdata::encode_nlink_comment(comment) {
        builder.append_attr_bytes(NFTA_RULE_USERDATA, &udata);
    }
}
```

**Dump path** (`parse_rule` in `connection.rs`):

```rust
// After the existing attr-walk loop, also check NFTA_RULE_USERDATA:
NFTA_RULE_USERDATA => {
    rule.comment = userdata::parse_nlink_comment(payload);
    rule.userdata_raw = Some(payload.to_vec()); // preserve foreign comments
}
```

**`RuleInfo` gets two new fields:**

```rust
pub struct RuleInfo {
    // ... existing fields ...
    /// Comment extracted from `NFTA_RULE_USERDATA` when it's an
    /// `nlink:<key>` tagged comment (i.e., a rule we created).
    /// `None` for rules without userdata or with foreign comments.
    pub comment: Option<String>,
    /// Raw `NFTA_RULE_USERDATA` payload, preserved verbatim. Lets
    /// us round-trip rules with foreign comments without losing
    /// them, even though our diff doesn't manage them.
    pub userdata_raw: Option<Vec<u8>>,
    /// Raw NFTA_RULE_EXPRESSIONS payload, preserved for the
    /// body-hash diff step.
    pub expression_bytes: Vec<u8>,
}
```

The new `expression_bytes` field is what powers body-change
detection without needing typed canonicalization. We hash the
raw bytes for the *post-key-match* equivalence check (§5.4).

### 5.3 `Rule` and `DeclaredRule` API additions

```rust
impl Rule {
    /// Attach a comment to this rule. Renders as `comment "..."`
    /// in `nft list ruleset` output. Used by the declarative-
    /// config diff as the rule's identity key. Max 122 chars
    /// (128 minus the `nlink:` prefix + NUL).
    pub fn comment(mut self, comment: &str) -> Self {
        self.comment = Some(comment.to_string());
        self
    }
}

impl DeclaredRuleBuilder {
    /// Set this rule's reconciliation key. Encoded as
    /// `NFTA_RULE_USERDATA` so the kernel rounds-trip it across
    /// dumps. Two declared rules with the same `handle_key` in the
    /// same chain are an error at `apply` time (returns
    /// `Error::InvalidMessage`).
    ///
    /// Mirror of `LinkConfig::name` / `RouteConfig::destination`
    /// in the existing `NetworkConfig` — the field that gives
    /// `NftablesDiff` per-rule identity.
    pub fn key(mut self, key: &str) -> Self {
        self.handle_key = Some(key.to_string());
        self
    }
}
```

`DeclaredRule::handle_key` already exists; this just wires it
through to `Rule::comment` at apply time.

### 5.4 Diff algorithm — per-rule, NetworkConfig-symmetric

```rust
impl NftablesConfig {
    pub async fn diff(&self, conn: &Connection<Nftables>) -> Result<NftablesDiff> {
        // ... tables / chains / flowtables presence diff
        // (unchanged) ...

        // Per-chain rule diff: matches NetworkConfig's per-object
        // reconciliation shape.
        for declared in &self.tables {
            for declared_chain in declared.chains() {
                if chain_in_tables_to_add(&diff, declared) {
                    // Chain is being added; rules-to-add inherit
                    // the chain's userdata-encoded comments.
                    for rule in declared_chain.rules() {
                        diff.rules_to_add.push(rule.clone());
                    }
                    continue;
                }

                // Dump current rules in this chain.
                let kernel_rules: Vec<RuleInfo> = conn
                    .stream_rules(declared.name(), declared.family())
                    .await?
                    .try_filter(|r| std::future::ready(
                        r.chain == declared_chain.name()
                    ))
                    .try_collect()
                    .await?;

                // Build (key -> kernel rule) map for fast lookup.
                let kernel_by_key: HashMap<String, &RuleInfo> = kernel_rules
                    .iter()
                    .filter_map(|r| r.comment.as_ref().map(|c| (c.clone(), r)))
                    .collect();

                // Pass 1: declared rules.
                let mut declared_keys: HashSet<String> = HashSet::new();
                for declared_rule in declared_chain.rules() {
                    let key = match declared_rule.handle_key() {
                        Some(k) => k,
                        None => {
                            // Anonymous: always add (documented
                            // limitation — same as a Link without
                            // a name in NetworkConfig: nonsensical,
                            // so error or always-add).
                            diff.rules_to_add.push(declared_rule.clone());
                            continue;
                        }
                    };
                    declared_keys.insert(key.to_string());

                    match kernel_by_key.get(key) {
                        Some(kr) => {
                            // Key matches: compare bodies.
                            let declared_body = lower_to_expression_bytes(declared_rule);
                            if declared_body != kr.expression_bytes {
                                diff.rules_to_replace.push((
                                    declared.name().to_string(),
                                    declared.family(),
                                    declared_chain.name().to_string(),
                                    RuleHandle(kr.handle),
                                    declared_rule.clone(),
                                ));
                            }
                            // else: no-op (declared and kernel agree)
                        }
                        None => {
                            // Not in kernel: add.
                            diff.rules_to_add.push(declared_rule.clone());
                        }
                    }
                }

                // Pass 2: kernel rules NOT in declared.
                for kr in &kernel_rules {
                    // Skip rules without our prefix (foreign — not
                    // ours to manage).
                    let Some(key) = &kr.comment else { continue };
                    if !declared_keys.contains(key) {
                        diff.rules_to_delete.push((
                            declared.name().to_string(),
                            declared.family(),
                            RuleHandle(kr.handle),
                        ));
                    }
                }
            }
        }

        Ok(diff)
    }
}
```

### 5.5 Apply algorithm — adds `rules_to_replace`

```rust
pub struct NftablesDiff {
    // ... existing fields ...
    /// (table, family, chain, kernel_handle, new_rule). Emits
    /// NFT_MSG_NEWRULE + NLM_F_REPLACE + NFTA_RULE_HANDLE so the
    /// kernel does an in-place rule replace (no flush, preserves
    /// rule position).
    pub rules_to_replace: Vec<(String, Family, String, RuleHandle, DeclaredRule)>,
}
```

`Transaction::replace_rule(table, chain, family, handle, &rule)`:
emits `NFT_MSG_NEWRULE` with `NLM_F_REPLACE | NLM_F_REQUEST` set
and `NFTA_RULE_HANDLE` populated. Kernel atomically replaces the
rule at that handle with the new body. Inside the same
`NFNL_MSG_BATCH_*` commit as the other ops; whole apply stays
atomic.

### 5.6 Anonymous rules — documented limitation

Rules without a `handle_key` are always added (no identity, no
diff). The recipe documents this clearly:

> ### Rule identity
>
> `DeclaredRule` requires a `handle_key` to participate in
> reconciliation — analogous to `LinkConfig` needing a name or
> `RouteConfig` needing a destination. Without a key, a rule is
> *anonymous*: every `apply` adds it (no idempotency).
>
> ```rust
> .chain("input", |c| c
>     .rule_keyed("ssh-accept", |r| r
>         .match_tcp_dport(22).accept()))
> ```
>
> Use `.rule_keyed(key, |r| ...)` instead of `.rule(|r| ...)`
> for any rule you want to reconcile across applies. Operators
> typically derive keys from their config schema:
> `service-foo/ingress/allow`, `firewall-rule-3142`, etc.

This is **exactly** the model NetworkConfig uses — every
diffable object has a stable identity field; anonymous /
nameless objects are pathological. Easy to explain.

## Comparison: v1 vs v2

| Concern | v1 (chain-content-hash) | v2 (per-rule USERDATA) |
|---|---|---|
| NetworkConfig pattern parity | ✗ — chain-level, asymmetric | ✓ — per-rule identity |
| Diff granularity for 1 changed rule in 100-rule chain | 101 ops (flush + 100 re-adds) | 1 op (replace rule) |
| Anonymous rules | Implicit via chain hash | Explicit: always-add (documented) |
| New wire format | Chain-flush op | USERDATA TLV encode/decode |
| New `RuleInfo` fields | `expression_bytes` | `comment`, `userdata_raw`, `expression_bytes` |
| New diff variants | `chain_bodies_to_replace` | `rules_to_replace` |
| New `Transaction` method | `flush_chain` | `replace_rule` |
| Implementation cost | ~6h | ~7-8h |
| `nft list ruleset` legibility | No change | Rules show `comment "nlink:<key>"` — operators can grep |
| Production precedent | kube-proxy (chain-level reconcile) | Google `nftables` library + everyone building on it (rule-level reconcile) |

v2 wins on every axis except marginal implementation cost.

## Breaking changes

- `DeclaredRule::handle_key` semantics activate (currently a
  no-op field; now drives diff identity).
- `RuleInfo` gains three new fields (`comment`, `userdata_raw`,
  `expression_bytes`). Additive; affects `Debug` output.
- `NftablesDiff` gains `rules_to_replace: Vec<...>` collection.
  Additive; existing introspection code unaffected.
- `Rule::comment(&str)` is a new public builder method.
- Anonymous rules in declared configs now log a warning at diff
  time ("rule in chain X has no handle_key; will be added every
  apply") so users notice.

Zero changes to `Rule::match_*` builders. Zero typed-Match
layer. The `Rule.exprs: Vec<Expr>` representation stays exactly
as-is.

## Effort estimate

| Phase | Effort |
|---|---|
| `userdata.rs` — TLV encode/decode helpers + unit tests | 1h |
| Wire USERDATA into `add_rule` emit + `parse_rule` decode | 1h |
| `Rule::comment` + `DeclaredRule::handle_key` plumbing | 0.5h |
| `RuleInfo` field additions + parse-side population | 0.5h |
| `NftablesDiff::rules_to_replace` collection + `diff()` algorithm | 2h |
| `Transaction::replace_rule` + `apply()` integration | 1h |
| Recipe update + warning emission for anonymous rules | 1h |
| Tests (TLV round-trip, diff scenarios, apply round-trip) | 1.5h |
| **Total** | **~8.5 hours (1 focused session)** |

vs Plan 157 §4.3 original estimate of "4h canonicalization" which
hid the prerequisite Rule refactor (realistically 12-15h);
vs v1 chain-level hash estimate of 6h.

## Decision points

1. **Adopt v2?** y/n. If yes: implementation can start.
2. **Rule-comment prefix format.** I propose `nlink:<user-key>` —
   short, distinguishable from foreign comments. Alternatives:
   `nl:` (shorter), `nlink/` (path-like). Operators see this in
   `nft list ruleset` output.
3. **What to do with anonymous rules.** I propose: always-add +
   warning at diff time. Alternative: hard-error at config-build
   time ("must call `.key(...)` to participate in reconcile").
4. **Whether to also support foreign userdata round-trip.**
   v2's `userdata_raw` preserves foreign comments through dumps,
   so re-applying doesn't strip them. Worth keeping; tiny cost.
5. **`.rule_keyed(key, ...)` builder vs `.rule(...).key(key)`.**
   The former makes the key prominent ("of course you need an
   identity"); the latter chains naturally. I lean toward
   exposing both — `.rule_keyed` as the documented-recommended
   path, `.rule` still works but emits the anonymous-rule warning.

End of design v2.
