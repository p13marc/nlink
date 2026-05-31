---
to: nlink maintainers
from: 0.19 second deep-audit
subject: Plan 211 — nftables semantic correctness (M1, M6, M7 + Hook::Egress)
status: queued for 0.19 — MEDIUM (silent semantic bugs in declarative nftables)
target version: 0.19.0
parent: [203](203-0.19-second-batch-master.md)
source: docs/AUDIT_REPORT_2026_05_31.md §M1, M6, M7
created: 2026-05-31
---

# Plan 211 — nftables semantic correctness

## 1. Why this plan exists

Three semantic bugs in the nftables declarative path:

- **M1** `Hook::Ingress` encodes `0` regardless of family. `0` is
  correct for `Family::Netdev`/`Bridge` but `Family::Inet`'s
  ingress is `NF_INET_INGRESS = 5`. `Hook::Egress` is missing
  entirely (`NF_NETDEV_EGRESS = 1`).
- **M6** Anonymous rules (no `handle_key`) re-applied without
  bound deduplication — every reapply installs the same rule
  again; nft rule list grows unboundedly.
- **M7** Pass 3 cleanup wipes any kernel rule with **any** comment
  in declared-but-empty chains. A user-installed rule with
  comment `"my-firewall"` gets wiped by an nlink config that
  declares the chain.

All three are silent state-corruption bugs in real-world
firewalls.

## 2. Phase 1 — M1 + Hook::Egress (breaking change)

**File:** `crates/nlink/src/netlink/nftables/types.rs:56-67`

Hook encoding depends on family. Disambiguate at the type level:

```rust
// Replace:
pub enum Hook {
    Prerouting,
    Input,
    Forward,
    Output,
    Postrouting,
    Ingress,
}

// With:
pub enum Hook {
    Prerouting,
    Input,
    Forward,
    Output,
    Postrouting,
    /// Ingress hook for `Family::Netdev`/`Bridge`. Encodes
    /// `NF_NETDEV_INGRESS = 0`.
    NetdevIngress,
    /// Ingress hook for `Family::Inet`/`Ipv4`/`Ipv6`. Encodes
    /// `NF_INET_INGRESS = 5`. Available since kernel 5.10.
    InetIngress,
    /// Egress hook for `Family::Netdev`. Encodes
    /// `NF_NETDEV_EGRESS = 1`. Available since kernel 5.16.
    NetdevEgress,
}

impl Hook {
    /// Returns the kernel hook number. Now unambiguous — each
    /// variant maps to one wire value.
    pub fn to_u32(self) -> u32 {
        match self {
            Self::Prerouting    => 0,
            Self::Input         => 1,
            Self::Forward       => 2,
            Self::Output        => 3,
            Self::Postrouting   => 4,
            Self::NetdevIngress => 0,    // NF_NETDEV_INGRESS
            Self::InetIngress   => 5,    // NF_INET_INGRESS
            Self::NetdevEgress  => 1,    // NF_NETDEV_EGRESS
        }
    }

    /// Returns true if the hook is compatible with the given
    /// chain family. Useful for validation at build time.
    pub fn is_valid_for_family(self, family: Family) -> bool {
        match (self, family) {
            (Self::NetdevIngress | Self::NetdevEgress, Family::Netdev) => true,
            (Self::NetdevIngress, Family::Bridge) => true,
            (Self::InetIngress, Family::Inet | Family::Ipv4 | Family::Ipv6) => true,
            (Self::Prerouting | Self::Input | Self::Forward | Self::Output | Self::Postrouting,
                Family::Inet | Family::Ipv4 | Family::Ipv6 | Family::Bridge) => true,
            _ => false,
        }
    }
}
```

`ChainBuilder::hook(Hook::Ingress)` callers must update to the
disambiguated variant. The migration guide includes a per-family
mapping table.

## 3. Phase 2 — M6 anonymous rule churn → stable comment cookie

**File:** `crates/nlink/src/netlink/nftables/config/diff.rs:502-513`

Anonymous rules (no user-supplied `handle_key`) get a stable
auto-generated comment derived from the rule's expression hash:

```rust
fn auto_comment_for_anonymous_rule(rule: &Rule) -> String {
    use blake3::Hasher;
    let mut h = Hasher::new();
    // Hash the wire bytes of the rule's expressions. Use the
    // already-existing `to_wire_bytes` helper that the apply
    // path calls — this guarantees the hash matches what the
    // kernel stores.
    let bytes = rule.expressions_wire_bytes();
    h.update(&bytes);
    let hash = h.finalize();
    format!("nlink-anon:{}", hex::encode(&hash.as_bytes()[..8]))
}
```

`16-hex-char` prefix is short enough to fit nft's comment limit
(64 chars) and long enough to make collisions cosmic-ray rare.

Then `diff` uses this auto-cookie as identity:
```rust
let Some(key) = declared_rule.handle_key_or_anon() else {
    // declared_rule has neither user handle_key nor expressions;
    // can't be deduplicated. Error out at build time.
    return Err(...);
};
```

Where `handle_key_or_anon()` returns `Some(user_key)` if set, or
`Some(auto_cookie)` derived from the expressions otherwise.

Diff side: now anonymous rules dedupe via the cookie. Repeated
applies are idempotent.

## 4. Phase 3 — M7 nlink-managed comment prefix discrimination

**File:** `crates/nlink/src/netlink/nftables/config/diff.rs:583-609`

Tag every nlink-managed rule with a prefix:
- User-supplied: `"<user-comment>"` (no prefix)
- Auto-anonymous: `"nlink-anon:<hash>"` (Phase 2)
- User-supplied via `handle_key`: `"nlink:<user-key>"` (NEW
  — wrap user keys to disambiguate from raw user comments)

Pass 3 cleanup then filters on the `nlink-` prefix:

```rust
for kr in kernel_rules_in_chain {
    let Some(comment) = &kr.comment else { continue };
    if !(comment.starts_with("nlink:") || comment.starts_with("nlink-anon:")) {
        // Foreign rule — leave alone.
        continue;
    }
    // This is an nlink-managed rule.
    let key = extract_key(comment);
    if !declared.contains_key(&key) {
        diff.rules_to_delete.push((/* ... */));
    }
}
```

User-installed `iptables-restore`-style rules with arbitrary
comments are now safe.

**Breaking change**: existing 0.18-installed rules with
non-prefixed user keys won't match the new prefix. Migration:
either re-apply to install the new prefix, or document a
one-time `nlink-migrate-comments` helper.

## 5. Tests

### 5.1 Unit — `Hook::is_valid_for_family`

```rust
#[test]
fn hook_netdev_ingress_for_netdev_family_valid() {
    assert!(Hook::NetdevIngress.is_valid_for_family(Family::Netdev));
}
#[test]
fn hook_inet_ingress_for_inet_family_valid() {
    assert!(Hook::InetIngress.is_valid_for_family(Family::Inet));
}
#[test]
fn hook_netdev_ingress_for_inet_family_invalid() {
    assert!(!Hook::NetdevIngress.is_valid_for_family(Family::Inet));
}
#[test]
fn hook_to_u32_matches_kernel_uapi() {
    // include/uapi/linux/netfilter.h:
    //   NF_INET_PRE_ROUTING = 0, _LOCAL_IN = 1, _FORWARD = 2,
    //   _LOCAL_OUT = 3, _POST_ROUTING = 4, _INGRESS = 5
    // include/uapi/linux/netfilter_netdev.h:
    //   NF_NETDEV_INGRESS = 0, NF_NETDEV_EGRESS = 1
    assert_eq!(Hook::Prerouting.to_u32(), 0);
    assert_eq!(Hook::InetIngress.to_u32(), 5);
    assert_eq!(Hook::NetdevIngress.to_u32(), 0);
    assert_eq!(Hook::NetdevEgress.to_u32(), 1);
}
```

### 5.2 Unit — anonymous rule auto-cookie

```rust
#[test]
fn anonymous_rule_reapply_is_idempotent() {
    let rule = anon_rule_accept_tcp_22();
    let cfg = NftablesConfig::new()
        .table("filter", Family::Inet, |t| t
            .chain("input", |c| c.rule(rule.clone()))
        );
    // First apply: rule installed.
    let mut kernel = MockKernel::new();
    let diff1 = cfg.diff_against(&kernel);
    diff1.apply_to_mock(&mut kernel);
    assert_eq!(kernel.rule_count(), 1);

    // Second apply: nothing changes.
    let diff2 = cfg.diff_against(&kernel);
    assert!(diff2.is_empty());
    assert_eq!(kernel.rule_count(), 1);
}

#[test]
fn anonymous_rule_cookie_is_deterministic() {
    let rule = anon_rule_accept_tcp_22();
    let k1 = auto_comment_for_anonymous_rule(&rule);
    let k2 = auto_comment_for_anonymous_rule(&rule);
    assert_eq!(k1, k2);
}

#[test]
fn different_anonymous_rules_get_different_cookies() {
    let r1 = anon_rule_accept_tcp_22();
    let r2 = anon_rule_accept_tcp_80();
    assert_ne!(
        auto_comment_for_anonymous_rule(&r1),
        auto_comment_for_anonymous_rule(&r2)
    );
}
```

### 5.3 Unit — foreign-commented rule preserved

```rust
#[test]
fn pass3_cleanup_preserves_foreign_commented_rules() {
    let cfg = NftablesConfig::new()
        .table("filter", Family::Inet, |t| t.chain("input", |c| c));  // empty
    let mut kernel = MockKernel::new();
    kernel.add_rule_with_comment("input", "my-firewall-rule");
    kernel.add_rule_with_comment("input", "nlink:foo");

    let diff = cfg.diff_against(&kernel);
    // Should delete "nlink:foo" but NOT "my-firewall-rule".
    assert_eq!(diff.rules_to_delete.len(), 1);
}
```

### 5.4 Integration (root-gated)

```rust
#[tokio::test]
async fn nftables_inet_ingress_chain_installs_with_hook_5() -> Result<()> {
    require_root!();
    let ns = LabNamespace::new("nft-ingress")?;
    let conn = ns.connection::<Nftables>()?;

    let cfg = NftablesConfig::new()
        .table("ingress-test", Family::Inet, |t| t
            .chain("ingress", |c| c
                .chain_type(ChainType::Filter)
                .hook(Hook::InetIngress)
                .priority(0)
            )
        );

    cfg.apply(&conn).await?;
    // Verify chain installed with NF_INET_INGRESS = 5 hook number.
}

#[tokio::test]
async fn nftables_anonymous_rule_repeated_apply_is_idempotent() -> Result<()> {
    require_root!();
    // Apply config 5 times. Verify exactly 1 rule installed.
}
```

## 6. CHANGELOG entry

```markdown
### Breaking changes

- **`Hook::Ingress` split into `Hook::NetdevIngress` and
  `Hook::InetIngress`; `Hook::NetdevEgress` added** (Plan 211).
  Pre-0.19 `Hook::Ingress` encoded `0` regardless of family,
  which was correct only for `Family::Netdev`/`Bridge`. On
  `Family::Inet`, ingress is `NF_INET_INGRESS = 5`, so the old
  encoding installed the chain on `Prerouting` (also hook 0).
  Migration: replace `Hook::Ingress` with the family-appropriate
  variant.

- **nlink-managed nftables rules now carry an `nlink:` /
  `nlink-anon:` comment prefix** (Plan 211 M7). Pass 3 cleanup
  now only sweeps rules with these prefixes. User-installed
  rules with arbitrary comments are preserved. Code that
  inspects rule comments may see the prefix; strip it via
  `comment.strip_prefix("nlink:").or(comment.strip_prefix("nlink-anon:"))`.

### Fixed

- **Anonymous nftables rules dedupe via stable expression-hash
  cookie** (M6). Pre-0.19, every reapply of an anonymous rule
  installed the same rule again; the rule list grew unboundedly.
  Now `auto_comment_for_anonymous_rule(&rule)` generates a stable
  `nlink-anon:<hash>` cookie; reapplies are idempotent.

- **Pass 3 cleanup respects foreign-commented rules** (M7).
  User-installed `iptables-restore`-style rules with arbitrary
  comments are no longer wiped by nlink reconcile.
```

## 7. Acceptance criteria

- [ ] `Hook::NetdevIngress` / `Hook::InetIngress` / `Hook::NetdevEgress` shipped
- [ ] `Hook::is_valid_for_family` validator
- [ ] Anonymous rule auto-cookie helper
- [ ] `nlink:` / `nlink-anon:` prefix on all nlink-managed rules
- [ ] Pass 3 cleanup filters on prefix
- [ ] 8 unit tests pass
- [ ] 2 root-gated integration tests pass
- [ ] CHANGELOG entries
- [ ] Migration guide §"Plan 211" with `Hook::Ingress` mapping table

## 8. Effort estimate

| Phase | Time |
|---|---|
| Phase 1 — Hook enum + validator | 1 h |
| Phase 2 — anonymous cookie | 1.5 h |
| Phase 3 — Pass 3 prefix discrimination | 1.5 h |
| Tests | 1 h |
| CHANGELOG + migration guide | 30 min |
| **Total** | **~5 h** |

## 9. Cross-cutting artifacts

| Artifact | Action |
|---|---|
| `CHANGELOG.md` | 2 breaking + 2 fixed |
| `docs/migration_guide/0.18.0-to-0.19.0.md` | §"Plan 211" with Hook mapping |
| `crates/nlink/src/netlink/nftables/types.rs` | Hook enum reshape |
| `crates/nlink/src/netlink/nftables/config/diff.rs` | anon cookie + prefix logic |
| `crates/nlink/src/netlink/nftables/config/apply.rs` | prefix wrapping on emit |
| `crates/nlink/tests/integration/cycle_0_19_backfill.rs` | 2 root-gated tests |
| `Cargo.toml` | add `blake3 = "1"` + `hex = "0.4"` dep (if not already present) |

End of plan.
