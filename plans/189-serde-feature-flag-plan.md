---
to: nlink maintainers
from: nlink-lab feedback `nlink-feedback.md` §9 + W4 (2026-05-30)
subject: `serde` feature flag on the nlink crate — `Serialize` on the public diff + result + report types
status: queued for 0.19 — low (feature flag, opt-in)
target version: 0.19.0
parent: (none — single-deliverable plan)
source: nlink-lab `nlink-feedback.md` §9 (low feature), W4 (wishlist)
created: 2026-05-30
---

# Plan 189 — `serde` feature flag

## 1. Why this plan exists

nlink-lab Plan 158f Phase 2 shipped an `apply --check --json`
envelope that serializes a layered diff. The lab's own
`TopologyDiff` carries `#[derive(Serialize)]` and serializes
natively. The two upstream diffs (`ConfigDiff` + `NftablesDiff`)
don't — the envelope falls back to a `layered_summary: String`
field carrying the rendered `Display` output.

Any future machine-readable consumer of nlink's diffs (CI
gates, IaC tools wrapping nlink, dashboards visualising drift)
takes the same Display-string fallback today. A
`serde`-gated `Serialize` derive on the public diff types
closes this gap permanently.

## 2. The change

### 2.1 Workspace + crate-level feature

```toml
# crates/nlink/Cargo.toml
[features]
default = []
serde = ["dep:serde"]
full = [..., "serde"]

[dependencies]
serde = { version = "1", features = ["derive"], optional = true }
```

The `serde` feature is **opt-in by default**, included in
`full` for completeness. `Deserialize` is **out of scope** for
this plan — the diff types are not user-constructible
(they're products of `compute_diff`), so round-trip
deserialization adds no consumer value. Keep the surface
narrow.

### 2.2 Gated derives on every reachable type

Per the maintainer's note, the gate covers:

| Type | Module | Reachable from |
|---|---|---|
| `ConfigDiff` | `netlink/config/diff.rs` | top-level |
| `NftablesDiff` | `netlink/nftables/config/diff.rs` | top-level |
| `LinkChanges` | `netlink/config/diff.rs` | inside ConfigDiff |
| `DeclaredLink` | `netlink/config/types.rs` | inside ConfigDiff |
| `DeclaredLinkType` | `netlink/config/types.rs` | inside DeclaredLink |
| `DeclaredAddress` | `netlink/config/types.rs` | inside ConfigDiff |
| `DeclaredRoute` | `netlink/config/types.rs` | inside ConfigDiff |
| `DeclaredQdisc` | `netlink/config/types.rs` | inside ConfigDiff |
| `DeclaredTable` | `netlink/nftables/config/types.rs` | inside NftablesDiff |
| `DeclaredChain` | `netlink/nftables/config/types.rs` | inside DeclaredTable |
| `DeclaredRule` | `netlink/nftables/config/types.rs` | inside DeclaredChain |
| `DeclaredFlowtable` | `netlink/nftables/config/types.rs` | inside DeclaredTable |
| `ApplyResult` | `netlink/config/apply.rs` | top-level |
| `ApplyError` | `netlink/config/apply.rs` | inside ApplyResult |
| `ReconcileReport` | `netlink/tc_recipe.rs` | top-level |
| `StaleObject` | `netlink/tc_recipe.rs` | inside ReconcileReport |
| `UnmanagedObject` | `netlink/tc_recipe.rs` | inside ReconcileReport |

Plus leaf types these reach: `Hook`, `Policy`, `Priority`,
`ChainType`, `Family`, `Family` for TC, `BondMode`,
`VlanProtocol` (if added in Plan 190), `MacvlanMode`,
`IpAddr`-wrapped values, etc.

The derive shape:

```rust
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[derive(Debug, Clone, ...existing...)]
#[non_exhaustive]
pub struct ConfigDiff { ... }
```

Each `#[cfg_attr]` is one line per type. `cargo machete` won't
flag `serde` as unused because the `dep:serde` mapping in
`[features]` keeps it conditional-only.

### 2.3 JSON shape stability — `#[serde(rename_all = "kebab-case")]`

The default Rust field-naming (`snake_case`) maps to JSON
fields like `links_to_add`. Downstream JSON tooling expects
`links-to-add` or `linksToAdd`. Pick **kebab-case** — matches
nlink-lab's existing schema (per their docs/json-schemas path)
+ matches the iproute2 lineage:

```rust
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case"))]
pub struct ConfigDiff { ... }
```

Trade-off: kebab-case JSON field names are not valid Rust
identifiers, which means downstream `serde_json::Value`-style
consumers see `"links-to-add"` strings. Acceptable; that's the
schema. Document in the migration guide that consumers can
override with their own newtype wrapper if they want a
different shape.

### 2.4 `Serialize` for `Family`, `Hook`, `Policy` etc.

Public enums become string-tagged JSON for forward-compat:

```rust
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Family {
    Inet,    // → "inet"
    Ip,      // → "ip"
    Ip6,     // → "ip6"
    Arp,     // → "arp"
    Bridge,  // → "bridge"
    Netdev,  // → "netdev"
}
```

Default Rust would emit `{"Inet": null}` for unit variants;
the explicit `rename_all = "snake_case"` flattens to bare
string `"inet"`. Cleaner JSON.

## 3. Implementation phases

| Phase | Files | LOC |
|---|---|---|
| 1 — Cargo feature + dep | `Cargo.toml` | ~5 |
| 2 — `cfg_attr` derives on diff types | 4 files | ~20 lines |
| 3 — `cfg_attr` derives on declared types | 4 files | ~30 lines |
| 4 — `cfg_attr` derives on leaf enums | 4 files | ~25 lines |
| 5 — `cfg_attr` derives on ApplyResult/Report | 2 files | ~10 lines |
| 6 — Tests (see §4) | new `tests/serde.rs` | ~150 |
| 7 — `full` feature update | `Cargo.toml` | ~1 |
| 8 — CI workflow: run tests with `--features serde` | `.github/workflows/rust.yml` | ~3 |
| **Total** | | **~244 LOC** |

## 4. Tests

### 4.1 Unit — feature-gate compile check

In `crates/nlink/src/lib.rs`:

```rust
#[cfg(all(test, feature = "serde"))]
mod serde_tests {
    use super::*;

    #[test]
    fn config_diff_implements_serialize() {
        fn assert_serialize<T: serde::Serialize>() {}
        assert_serialize::<crate::ConfigDiff>();
        assert_serialize::<crate::NftablesDiff>();
        assert_serialize::<crate::ApplyResult>();
    }
}
```

### 4.2 Unit — JSON snapshot tests for shape stability

In `crates/nlink/tests/serde.rs` (new file):

```rust
//! Plan 189 — JSON shape stability tests for serde-gated
//! `Serialize` impls. Pinned snapshots so any field rename
//! in the diff types surfaces as a snapshot diff.

#![cfg(feature = "serde")]

use nlink::netlink::config::{ConfigDiff, ApplyResult};
use nlink::netlink::nftables::config::NftablesDiff;

#[test]
fn config_diff_empty_serializes_to_known_shape() {
    let diff = ConfigDiff::default();
    let json = serde_json::to_string_pretty(&diff).unwrap();
    insta::assert_snapshot!(json);
    // OR, if avoiding insta:
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert!(parsed["links-to-add"].is_array());
    assert!(parsed["links-to-modify"].is_array());
    assert_eq!(parsed["links-to-add"].as_array().unwrap().len(), 0);
}

#[test]
fn nftables_diff_empty_serializes_to_known_shape() {
    let diff = NftablesDiff::default();
    let json = serde_json::to_string_pretty(&diff).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert!(parsed["tables-to-add"].is_array());
    ...
}

#[test]
fn family_enum_serializes_to_lowercase_string() {
    use nlink::netlink::nftables::types::Family;
    let json = serde_json::to_string(&Family::Inet).unwrap();
    assert_eq!(json, r#""inet""#);
}

#[test]
fn config_diff_with_link_add_renders_link_payload() {
    // Construct via NetworkConfig builder for realism, then
    // diff against an empty kernel state.
    // The structural JSON should carry every field nlink-lab's
    // schema expects. This is the contract-stability test.
    ...
}
```

We **don't** want to depend on `insta` as a dev-dep just for
two snapshot tests; structural assertions on `serde_json::Value`
are sufficient.

### 4.3 Unit — kebab-case is correctly applied

```rust
#[test]
fn config_diff_field_names_are_kebab_case() {
    let diff = ConfigDiff::default();
    let json = serde_json::to_string(&diff).unwrap();
    // Spot-check several field names.
    assert!(json.contains(r#""links-to-add""#));
    assert!(json.contains(r#""addresses-to-add""#));
    assert!(!json.contains(r#""links_to_add""#));
}
```

### 4.4 CI — feature matrix

Existing CI runs `--features lab --features internal_config`.
Add a new matrix entry:

```yaml
# .github/workflows/rust.yml — add to the build + test job matrix
features-set:
  - default
  - all-features
  - serde-only  # NEW
```

Run `cargo test -p nlink --features serde` in the serde-only
gate so the gated path doesn't bit-rot.

### 4.5 No integration tests required

`serde` is a pure-Rust addition; no kernel interaction.

## 5. Acceptance criteria

- [ ] `serde` feature in `[features]`; `serde` crate dep with
      `derive` is `optional = true`.
- [ ] `Serialize` derived on every reachable public diff +
      report + supporting type.
- [ ] `rename_all = "kebab-case"` (structs) or `"snake_case"`
      (enums) for stable JSON.
- [ ] `cargo test -p nlink --features serde` green; CI runs
      it in a new matrix entry.
- [ ] 4+ JSON shape-stability tests in `tests/serde.rs`.
- [ ] CHANGELOG `### Added` entry.
- [ ] Migration guide note.

## 6. Effort estimate

| Phase | Effort |
|---|---|
| Cargo + features | ~30 min |
| Type-by-type derive additions (~17 types + ~6 enums) | ~1.5 h |
| Tests | ~1 h |
| CI matrix update | ~15 min |
| CHANGELOG + migration guide | ~15 min |
| **Total** | **~3.5 h** |

## 7. Risks

- **Adding `Serialize` is a public-API surface commitment.**
  Renaming a field on a diff type becomes a JSON breaking
  change, not just a Rust one. The kebab-case
  `rename_all` shields us partially — kebab-case is the
  schema-stable rename target — but we still need to be
  cautious about field renames going forward.
  Document in CONTRIBUTING.md (one line).
- **`Deserialize` deferred** — a downstream that wants to
  round-trip a `NftablesDiff` for "apply this canned diff"
  scenarios is out of luck. No current consumer asked;
  revisit when one does.
- **Enum variant additions on `#[non_exhaustive]` enums** —
  serde's external tagging emits the bare-string for unit
  variants, which means adding a variant changes the JSON
  enumeration. Downstream JSON consumers should treat
  variant strings as open-set; document.

## 8. Out-of-scope follow-ups

- **`Deserialize` derives** — separate plan when asked.
- **JSON Schema export** — nlink-lab generates its own schemas
  for the apply --check envelope. If we want a built-in
  `nlink::schema::config_diff()` returning a JSON Schema, that's
  its own plan (would compose with `schemars`).
- **`Serialize` for runtime parsed types** (`LinkMessage`,
  `RouteMessage`, etc.) — useful for tools dumping kernel
  state to JSON. Not in this plan; ask in a follow-up.

End of plan.
