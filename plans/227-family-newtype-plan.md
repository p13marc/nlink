---
to: nlink maintainers
from: 0.20 cycle pre-work — deep audit derivation
subject: Typed `AddressFamily` newtype — close the raw-u8 family footgun on rule.rs
status: planning
target version: 0.20.0
parent: [Plan 220 master](220-0.20-master-plan.md)
source: [AUDIT_API.md](../AUDIT_API.md) Finding A2
created: 2026-06-04
---

# Plan 227 — Typed `nlink::AddressFamily` newtype

## 1. Why this plan exists

Three public `Connection<Route>` methods take `family: u8`:

- `flush_rules(&self, family: u8)` —
  `crates/nlink/src/netlink/connection.rs:1604`
- `get_rules_for_family(&self, family: u8)` —
  `crates/nlink/src/netlink/connection.rs:1531`
- `del_rule_by_priority(&self, family: u8, priority: u32)` —
  `crates/nlink/src/netlink/connection.rs:1595`

The contract per the docstring is "pass `libc::AF_INET` (2) or
`libc::AF_INET6` (10) cast to `u8`." Pass `4` and you get
`Ok(vec![])` silently — no rule has family 4, so the filter at
`connection.rs:1533` (`rules.into_iter().filter(|r| r.family() ==
family)`) just yields nothing. Same for `flush_rules(4)`: zero
matches, zero deletes, returns `Ok(())`. The caller has no signal
that they passed garbage.

This is precisely the bug class that `TcHandle`, `Rate`, `Bytes`,
`Percent`, `InterfaceRef`, and `FilterPriority` exist to kill. The
typed-units convention from 0.13-0.14 explicitly identified
"function takes a raw integer that needs a kernel constant"
as the smell to eradicate. Family was missed.

Adjacent: `nftables::types::Family` already exists at
`crates/nlink/src/netlink/nftables/types.rs:33` as the **nft**
family enum. It maps to `NFPROTO_*` (NFPROTO_IPV4=2,
NFPROTO_IPV6=10, NFPROTO_INET=1, NFPROTO_NETDEV=5, …). Those
happen to overlap with libc `AF_*` for v4/v6 but the contract is
distinct — `NFPROTO_INET` (1) is a netfilter virtual family with
no libc equivalent. **We must not reuse it for `RuleMessage`,
which speaks `AF_*` directly.** The new type lives in the
crate root.

## 2. The newtype design

```rust
// crates/nlink/src/util/address_family.rs (new file)

/// IP address family for routing-policy DB rules and adjacent
/// netlink surfaces that speak `AF_*` constants directly.
///
/// Distinct from [`crate::netlink::nftables::types::Family`] —
/// that type speaks `NFPROTO_*` (NFPROTO_INET=1 has no libc
/// equivalent). Mixing the two is a wire-format error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum AddressFamily {
    /// `AF_INET` (libc value 2).
    V4,
    /// `AF_INET6` (libc value 10).
    V6,
    /// `AF_BRIDGE` (libc value 7). Used by FDB / bridge VLAN
    /// rules; included here for surface completeness.
    Bridge,
    /// `AF_PACKET` (libc value 17). Rare at the rule layer
    /// but accepted by some `RTM_*` dumps.
    Packet,
    /// `AF_MPLS` (libc value 28).
    Mpls,
    /// `AF_UNSPEC` (libc value 0). The "no filter" form —
    /// `get_rules_for_family(AddressFamily::Unspec)` is the
    /// typed equivalent of the old `get_rules()` no-arg dump.
    Unspec,
}

impl AddressFamily {
    /// Wire value as the kernel sees it (`AF_*` numeric form).
    pub const fn as_u8(self) -> u8 {
        match self {
            Self::Unspec => 0,         // AF_UNSPEC
            Self::V4 => 2,             // AF_INET
            Self::Bridge => 7,         // AF_BRIDGE
            Self::V6 => 10,            // AF_INET6
            Self::Packet => 17,        // AF_PACKET
            Self::Mpls => 28,          // AF_MPLS
        }
    }
}

impl From<AddressFamily> for u8 {
    fn from(f: AddressFamily) -> u8 { f.as_u8() }
}

// No `From<u8>` — that defeats the typed-newtype invariant
// (cf. Finding A6 on FilterPriority's blanket From<u16>).
// Add a fallible `try_from_raw` for power users:
impl AddressFamily {
    /// Parse a raw `AF_*` byte. Returns `None` for values nlink
    /// does not model — callers who genuinely need them should
    /// extend the enum (it's `#[non_exhaustive]`).
    pub const fn try_from_raw(raw: u8) -> Option<Self> {
        match raw {
            0 => Some(Self::Unspec),
            2 => Some(Self::V4),
            7 => Some(Self::Bridge),
            10 => Some(Self::V6),
            17 => Some(Self::Packet),
            28 => Some(Self::Mpls),
            _ => None,
        }
    }
}
```

Re-exported as `nlink::AddressFamily` from `crates/nlink/src/lib.rs`
alongside `Rate`, `Bytes`, `Percent`, `TcHandle`.

## 3. The deprecation cadence

Per CLAUDE.md `## Type-safe units` lineage and the user
preference recorded in `feedback_tc_api_direction.md` — "deprecate
in same release as typed replacement; delete one release later":

- **0.20.0**: ship typed siblings + `#[deprecated]` on the `u8`
  variants. Compiler warns; no behaviour change.
- **0.21.0**: delete the `u8` variants outright.

Concretely, the three sites grow typed siblings and the existing
methods get the deprecation attribute:

```rust
/// Flush all non-default routing rules for a family.
///
/// This deletes all rules except the default ones (priority 0,
/// 32766, 32767).
#[tracing::instrument(level = "debug", skip_all, fields(method = "flush_rules"))]
pub async fn flush_rules(&self, family: AddressFamily) -> Result<()> {
    let rules = self.get_rules_for_family(family).await?;
    for rule in rules {
        if rule.priority == 0 || rule.priority == 32766 || rule.priority == 32767 {
            continue;
        }
        let _ = self.del_rule_by_priority(family, rule.priority).await;
    }
    Ok(())
}

/// Flush all non-default routing rules. **Deprecated** in 0.20;
/// use [`Connection::flush_rules`] with [`AddressFamily`].
#[deprecated(
    since = "0.20.0",
    note = "use flush_rules(AddressFamily::V4 / V6) instead — \
            passing a raw u8 silently returns Ok() for unknown families"
)]
pub async fn flush_rules_raw(&self, family: u8) -> Result<()> {
    let af = AddressFamily::try_from_raw(family).ok_or_else(|| {
        Error::InvalidArgument(format!(
            "flush_rules_raw: unknown address family byte {} \
             (not in AddressFamily::try_from_raw)", family
        ))
    })?;
    self.flush_rules(af).await
}
```

Note the deprecated `*_raw` shim **errors on unknown families
instead of silently filtering to empty**. That's the headline
benefit users get from the move even before they migrate — the
0.19 silent-empty-result is gone the same release.

`get_rules_for_family` and `del_rule_by_priority` follow the
same shape: typed method takes `AddressFamily`, `*_raw` shim
takes `u8` and delegates through `try_from_raw`.

## 4. Cross-API audit — all raw-u8 family / proto sites

Pre-work for this plan: grep every `pub fn ... u8` parameter on
public modules. Audit table (annotated with disposition).

| File:line | Method | Param | Disposition |
|---|---|---|---|
| `connection.rs:1531` | `get_rules_for_family` | `family: u8` | Plan 227 — `AddressFamily` |
| `connection.rs:1595` | `del_rule_by_priority` | `family: u8` | Plan 227 — `AddressFamily` |
| `connection.rs:1604` | `flush_rules` | `family: u8` | Plan 227 — `AddressFamily` |
| `rule.rs` `RuleBuilder::new` | constructor | `family: u8` | Plan 227 — `AddressFamily` (mechanical) |
| `messages/rule.rs:89` | `RuleMessage::family()` | returns `u8` | Plan 231 — switch return to `AddressFamily` |
| `route.rs` route_proto sites | various | `proto: u8` | **defer** — `IpProto` newtype is a 0.21 candidate (RFC numbers space, kernel doesn't constrain) |
| nftables `protocol` accessors | various | `proto: u8` | **defer** — same reason |
| `connection.rs:1620+` | `get_routes_for_table` | `table: u32` | Bikeshed A21.1 — `TableId` newtype, defer to 0.21 |

The route/nft `proto: u8` sites are deliberately out of scope for
this plan. Their footgun shape is different (IPPROTO_* space is
sparse + IANA-managed; a `Other(u8)` arm is mandatory; the
ergonomic cost-benefit is weaker than `AddressFamily`). Flagged
for 0.21 in the cycle seed list at cut time.

## 5. Test plan

Three test classes:

1. **Compile-fail tests** under `crates/nlink/tests/compile_fail/`
   (trybuild). Confirm `flush_rules(4)` no longer compiles after
   the deprecation period closes; document the warning text it
   produces in 0.20.

2. **`#[deprecated]` warning is emitted under
   `--deny warnings`**. CI's clippy already runs with
   `--deny warnings`; the deprecated-path invocation in existing
   tests must be moved behind `#[allow(deprecated)]` or migrated.
   The migration is mechanical; if anything in the lib's own
   tests trips it, that's a signal we missed a callsite.

3. **Integration test** under
   `crates/nlink/tests/integration/rule_family_typed.rs` (root +
   netns gated per Plan 140 convention):

   ```rust
   nlink::require_root!();
   // Seed three v4 rules + two v6 rules in a fresh netns, then:
   let v4 = conn.get_rules_for_family(AddressFamily::V4).await?;
   assert_eq!(v4.len(), 3);
   let v6 = conn.get_rules_for_family(AddressFamily::V6).await?;
   assert_eq!(v6.len(), 2);
   // The unspec form returns everything:
   let all = conn.get_rules_for_family(AddressFamily::Unspec).await?;
   assert_eq!(all.len(), 5);
   ```

   The Unspec arm is the typed replacement for `get_rules()`. If
   the cycle has bandwidth, deprecate the no-arg form too — but
   that's a separate flip and not required by this plan.

## 6. Migration

`docs/migration_guide/0.19.0-to-0.20.0.md` gets an entry:

```markdown
### `AddressFamily` typed newtype (Plan 227)

`Connection::{get_rules_for_family, del_rule_by_priority,
flush_rules}` previously took `family: u8` and silently returned
empty results when passed an unrecognized family byte. They now
take `nlink::AddressFamily`:

- Before: `conn.flush_rules(libc::AF_INET as u8).await?`
- After:  `conn.flush_rules(AddressFamily::V4).await?`

The raw-`u8` form remains as `*_raw` shims with a
`#[deprecated]` warning for one release (deleted in 0.21). The
shims error on unknown family bytes instead of silently
returning `Ok(())`.
```

## 7. Risks

- **`From<u8>` requests will arrive**. Callers with their own
  byte-to-family logic will ask for `impl From<u8> for
  AddressFamily`. Resist for the same reasons Finding A6 calls
  out about `FilterPriority`: a blanket `From<u8>` lets bare-byte
  values silently land in the typed slot, defeating the type. The
  explicit fallible `try_from_raw` is the documented escape
  hatch.

- **Adjacent `Family` confusion**. The crate now has two family
  types (`nftables::Family` for NFPROTO_*, `AddressFamily` for
  AF_*). Document the distinction in the public rustdoc on both;
  cross-link in module-level comments. The naming asymmetry
  (`Family` vs `AddressFamily`) is the cost of avoiding a name
  collision in the same crate's public namespace.

- **`#[non_exhaustive]` lockdown bites future kernels**.
  Acceptable: the enum is `#[non_exhaustive]`, so adding new
  variants in 0.21+ is non-breaking. The known-set we ship in
  0.20 covers everything `RuleMessage` actually encounters.

## 8. Acceptance

This plan ships when:

- ✅ `nlink::AddressFamily` is re-exported from the crate root.
- ✅ Three `Connection<Route>` methods grow typed signatures;
  the `*_raw` shims emit `#[deprecated]`.
- ✅ One integration test confirms the v4/v6/unspec dispatch.
- ✅ `cargo clippy --workspace --all-targets --all-features --
  --deny warnings` passes (no callsite inside nlink itself still
  uses the deprecated path).
- ✅ The migration guide gains the §6 entry.

## 9. Cross-references

- [Plan 220 master](220-0.20-master-plan.md) §3.3 — typed-API
  tightening cluster
- [AUDIT_API.md](../AUDIT_API.md) Finding A2 (this plan's source)
  and Finding A6 (sibling argument for *not* shipping `From<u8>`)
- [Plan 231 — `RuleMessage` accessor discipline](231-message-accessor-discipline-plan.md)
  — `RuleMessage::family()` switches its return type to
  `AddressFamily` as part of the accessor sweep
- [Plan 228 — typed `Percent`](228-typed-percent-builders-plan.md)
  — sibling typed-API tightening; same deprecation cadence
- CLAUDE.md `## Type-safe units` — convention lineage
- `feedback_tc_api_direction.md` (user memory) — deprecation
  cadence the cycle is committing to
