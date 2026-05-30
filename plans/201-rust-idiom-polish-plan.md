---
to: nlink maintainers
from: 0.19 third consolidation-pass — Rust idiom audit (2026-05-30)
subject: Rust idiom polish sweep — `#[must_use]`, `From`/`Into`, `Display`, `#[inline]`, type-state builders where applicable
status: queued for 0.19 — low-medium (one-time sweep + audit gate)
target version: 0.19.0
parent: (none — cross-cutting polish that touches most plans' types)
source: third consolidation-pass review of the 14-plan cycle
created: 2026-05-30
---

# Plan 201 — Rust idiom polish sweep

## 1. Why this plan exists

Across the 14-plan cycle (and the existing 0.18 surface) we
have hundreds of public types and methods. Each plan focuses
on its slice; nothing in the plan structure forces
cross-cutting Rust-idiom consistency. The result is a
codebase where some types carry `#[must_use]` and some don't,
some have `From<&str>` impls and others want `String::from`
+ `.into()`, some accessors are `#[inline]` and some aren't.

This plan is a one-time sweep + an audit CI gate that pins
the conventions so future contributors inherit them.

The sweep is **purely additive in behavior** — every
addition is opt-in (`#[must_use]` warns, `From` impls add
conversion paths, `Display` adds a renderer, `#[inline]`
hints don't change semantics). No semver risk.

## 2. The sweep — six conventions

### 2.1 `#[must_use]` on every builder + diff type

Builders that return `Self` and diffs that the caller is
expected to `apply()` are easy to forget. Add `#[must_use]`
on every:

- `*Builder` struct
- `*Config` type whose primary use is `.diff()` or `.apply()`
- `*Diff` type whose primary use is `.apply()` or `.summary()`
- `LinkBuilder`, `RouteBuilder`, `RuleBuilder`,
  `DeclaredChainBuilder`, `DeclaredSetBuilder`, etc.

Expected coverage: ~40 types across the codebase.

```rust
#[must_use = "Builder values must be passed to apply() or otherwise consumed"]
pub struct LinkBuilder { ... }

#[must_use = "Diffs must be applied via .apply() or .summary() to be useful"]
pub struct ConfigDiff { ... }
```

### 2.2 `From`/`Into` conversion impls for common ergonomic input

Where a method takes a strict typed parameter but the caller
naturally has a different form, ship `From`/`Into` impls.

Examples to audit:

- `IpAddr` → `IpNet` (with `/32` or `/128` mask)
- `&str` → `PublicKey` (parse base64; fallible — use `FromStr`)
- `[u8; 32]` ↔ `PublicKey` (newtype wrap)
- `Ipv4Addr` ↔ `IpAddr::V4(_)` (already exists in std)
- `String` ↔ `InterfaceRef::Name(...)` (already exists)
- `u32` ↔ `InterfaceRef::Index(...)` (already exists; verify)
- `Duration` → `TimerNewtype` for the various timeout fields
- `&str` → `Family` (`"inet"` → `Family::Inet`, fallible)

Many of these likely exist for the older modules; sweep
audits coverage on the new 0.19 surface (Plans 196, 197, 198,
199).

### 2.3 `Display` on every public diff + report + summary type

Plan 183 made `Display` work for `NftablesDiff` + `ConfigDiff`.
Plan 188 adds `LinkChanges::Display`. Plan 196 adds
`WireguardDiff::Display`. Plan 197 adds `OvpnDiff::Display`.

Sweep audits coverage:
- `WireguardDeviceChanges` — likely missing
- `StackDiff` — covered by Plan 200
- `ApplyResult` / `StackApplyReport` — likely missing
- `ReconcileReport` — likely missing
- `LinkAttributes` — useful for `RUST_LOG=debug`-shaped
  prints

Add `Display` for every type a user would reasonably
`println!("{}")`.

### 2.4 `#[inline]` on tiny accessor methods

Trivial getters (`fn name(&self) -> &str { &self.name }`)
benefit from `#[inline]` so they're elided across crate
boundaries. Sweep adds `#[inline]` to:

- Every accessor method `≤ 3 lines`
- Every `pub const fn` that returns a primitive
- Every `bool`-returning predicate
- Every `Into` / `From` impl body

Estimate: ~150 methods get the annotation. Negligible binary
size impact; meaningful when consumers compile in release
mode and the borrow-checker has to inline anyway.

### 2.5 `const fn` where the body is const-evaluable

Promote any `pub fn` whose body uses only const operations
(arithmetic on primitives, struct construction with const
fields, simple matches) to `pub const fn`. Lets consumers
use these in const contexts.

Examples:
- `RtnetlinkGroup::to_kernel_group` — currently runtime match;
  could be `const fn`
- `Family::from_u8` → `const fn`
- `NetkitMode::default()` — `const fn`
- Most enum→u32 mapping functions

Estimate: ~30 functions promoted. The build doesn't change
without consumer adoption; this is forward-compat polish.

### 2.6 Iterator combinators over manual loops where natural

A targeted audit: find places where we manually push to a
`Vec` in a for loop and `.collect()` would be cleaner.

```rust
// Before
let mut out = Vec::new();
for x in iter { if pred(&x) { out.push(transform(x)); } }

// After
let out: Vec<_> = iter.filter(pred).map(transform).collect();
```

This is **only** an idiomaticity polish — not a perf change.
Stop the audit at obvious wins; don't refactor working code
just for style.

## 3. Implementation phases

| Phase | Files | LOC |
|---|---|---|
| 1 — `#[must_use]` sweep + audit script | ~40 files | ~80 (mostly attribute additions) |
| 2 — `From`/`Into` impls — 0.19 surface | ~10 files | ~150 |
| 3 — `Display` impls audit + additions | ~15 files | ~250 |
| 4 — `#[inline]` sweep | ~30 files | ~150 (attribute additions) |
| 5 — `const fn` promotions | ~15 files | ~30 (signature changes) |
| 6 — Iterator combinator polish | ~10 files | ~80 net |
| 7 — Audit scripts (3 new) | new `scripts/` entries | ~120 |
| 8 — Tests (see §4) | various | ~150 |
| **Total** | | **~1010 LOC** |

## 4. Tests

### 4.1 Audit scripts as CI gates

```bash
# scripts/audit-must-use.sh
# Fails if any `pub struct *Builder` or `pub struct *Diff`
# in crates/nlink/src/ lacks #[must_use].

# scripts/audit-public-from-impls.sh
# Fails if a public newtype lacks From impls from its
# component types (audit by convention: any `pub struct Foo(Bar);`
# with no From<Bar> for Foo).

# scripts/audit-display-on-diffs.sh
# Fails if any type whose name ends in `Diff` or `Report`
# lacks an impl of std::fmt::Display.
```

Three audit scripts; one per convention worth pinning.

### 4.2 Doctest examples

Every `From`/`Into` addition should ship with a doctest
showing the conversion:

```rust
/// ```
/// use nlink::netlink::nftables::Family;
/// let f: Family = "inet".parse().unwrap();
/// assert_eq!(f, Family::Inet);
/// ```
impl FromStr for Family { ... }
```

### 4.3 Unit — `#[must_use]` actually warns

Cargo can verify with `--deny warnings`. If a builder is
constructed and dropped, the compile fails. Add a single test
file that constructs each builder, captures it in `_`, and
documents the warning suppression — confirming the attribute
is on.

### 4.4 No new integration tests

Polish doesn't change runtime behavior; the existing
integration suite is the regression check.

## 5. Acceptance criteria

- [ ] `#[must_use]` on every public Builder + Config + Diff
      type across the codebase.
- [ ] `From`/`Into`/`FromStr` impls on the new 0.19 surface
      (WireGuard, ovpn, sets, etc.) where ergonomic.
- [ ] `Display` impls on every public Diff + Report + summary
      type.
- [ ] `#[inline]` on tiny accessors + predicates + From/Into
      bodies.
- [ ] `const fn` where the body is const-evaluable.
- [ ] Three audit scripts: `audit-must-use`,
      `audit-public-from-impls`, `audit-display-on-diffs`.
- [ ] CI workflow runs all three on every push.
- [ ] CHANGELOG `### Changed` entry; migration guide entry
      ("no consumer action required").

## 6. Effort estimate

| Phase | Effort |
|---|---|
| Code (~1010 LOC; mostly attribute additions) | ~4 h |
| Audit scripts + CI integration | ~1.5 h |
| Doctest additions | ~1 h |
| CHANGELOG + migration guide | ~30 min |
| **Total** | **~7 h** |

## 7. Risks

- **`#[must_use]` may surface latent caller code that
  constructs+drops a builder** — these were silent bugs and
  now compile-warn. Acceptable break; document in the
  migration guide.
- **`#[inline]` on widely-imported small methods may slow
  CI compile times** marginally. Profile if it surfaces.
- **`From`/`Into` conflicts** — Rust's coherence rules can
  reject `impl From<X> for Y` if a transitive impl exists.
  Each addition tested individually.

## 8. Out-of-scope follow-ups

- **Type-state builders** (`LinkBuilder<NeedsKind>` →
  `LinkBuilder<HasKind>`) — would enforce
  required-before-optional ordering at compile time. Bigger
  refactor; not worth the API churn for the existing
  builders. Could apply to specific new builders in 0.20+.
- **`#[diagnostic::on_unimplemented]`** — useful for sealed
  traits to give better error messages. Stable in 1.78+; we
  could adopt. Defer if not directly asked for.

## 9. Cross-cutting artifacts

| Artifact | Action | Notes |
|---|---|---|
| `CHANGELOG.md` `## [Unreleased]` | **add** `### Changed` entry summarizing the polish sweep | Lists the conventions pinned; no per-type entries (too many). |
| `docs/migration_guide/0.18.0-to-0.19.0.md` | **append** `### Plan 201` section: "no consumer action required, but new `#[must_use]` warnings may surface" | Lists the audit script paths + the convention table. |
| `CLAUDE.md` | **append** a "## Rust idiom conventions" section under the existing project-overview area, documenting the six conventions + how to verify locally | Future contributors inherit the conventions automatically — code review uses the same checklist. |
| `scripts/audit-must-use.sh` (**new**) | **create** ~40 lines | Per §4.1. |
| `scripts/audit-public-from-impls.sh` (**new**) | **create** ~40 lines | Per §4.1. |
| `scripts/audit-display-on-diffs.sh` (**new**) | **create** ~40 lines | Per §4.1. |
| `.github/workflows/rust.yml` | **add 3 audit jobs** | Mirror the existing audit-shape jobs. |

End of plan.
