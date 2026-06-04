---
to: nlink maintainers
from: 0.20 cycle pre-work — deep audit derivation
subject: Typed `Percent` on declarative builders — close the f64 footgun
status: planning
target version: 0.20.0
parent: [Plan 220 master](220-0.20-master-plan.md)
source: [AUDIT_API.md](../AUDIT_API.md) Finding A1 (MAJOR)
created: 2026-06-04
---

# Plan 228 — Typed `Percent` on declarative builders

## 1. Why this plan exists

Two paths to the same kernel field, two argument shapes:

```rust
// Imperative (typed, correct):
let cfg = NetemConfig::new()
    .loss(Percent::new(1.5))         // crates/nlink/src/netlink/tc.rs:156
    .build();

// Declarative (raw f64, unclamped, unchecked):
let q = QdiscBuilder::new("eth0")
    .netem()
    .loss(1.5);                       // crates/nlink/src/netlink/config/types.rs:1179
```

The declarative `.loss(1.5)` is interpreted as 1.5% and stored
verbatim. `.loss(0.015)` for "1.5% expressed as a fraction" is
0.015% loss — silent. `.loss(150.0)` produces "150% loss" with no
validation. The kernel saturates downstream (the netem qopt
encodes 32-bit u32 probability), so the user sees full packet
drop with no error.

This is the **0.14 units bug, recurring in 2026**. Same word
("loss percent"), two incompatible argument shapes in the same
crate, same exposed surface. The 0.14 lesson — and the lineage
the cycle has been investing in since (`Rate`, `Bytes`,
`Percent`, `TcHandle`, `FilterPriority`, `InterfaceRef`) — was
that this class of bug is fixable permanently at the type level.
The declarative path was missed.

The audit ranks this finding **MAJOR** (footgun that silently
produces wrong behaviour). It is the only MAJOR finding in
AUDIT_API.md.

## 2. The change — full table

Cross-walk every `f64` / raw-int setter on
`config/types.rs::QdiscBuilder` against its imperative
typed-config sibling. Builders that have no imperative twin (e.g.
`htb` defaults) are out of scope for this plan.

| Declarative method | File:line | Current sig | Imperative twin | Typed shape |
|---|---|---|---|---|
| `QdiscBuilder::loss` | `config/types.rs:1179` | `(f64)` | `NetemConfig::loss(Percent)` | `(Percent)` |
| `QdiscBuilder::duplicate` | `config/types.rs:1186`* | `(f64)` | `NetemConfig::duplicate(Percent)` | `(Percent)` |
| `QdiscBuilder::corrupt` | `config/types.rs:1192`* | `(f64)` | `NetemConfig::corruption(Percent)` | `(Percent)` |
| `QdiscBuilder::reorder` | `config/types.rs:1199`* | `(f64, f64?)` | `NetemConfig::reorder(Percent, Percent)` | `(Percent, Percent)` |
| `QdiscBuilder::loss_correlation` | tbd | `(f64)` | `NetemConfig::loss_correlation(Percent)` | `(Percent)` |
| `QdiscBuilder::delay_correlation` | tbd | `(f64)` | `NetemConfig::delay_correlation(Percent)` | `(Percent)` |

\* Line numbers reflect the audit-time tree. Pre-work pass:
re-grep `pub fn .*: f64` under `crates/nlink/src/netlink/config/`
and confirm the table. Append any setter that has an imperative
typed-Percent twin we missed; explicitly skip setters whose twin
is also `f64` (those are bandwidth / time / rate setters; covered
by `Rate` / `Duration` typed-arg paths, not this plan).

Rate-flavoured declarative setters (`tbf(rate_bps: u64, ...)`,
`htb_class(rate_bps: u64)` etc.) get the same treatment in a
**sibling plan, deferred to 0.21**. The audit's MAJOR finding is
specifically `Percent`; widening this plan to `Rate` doubles its
scope and slows the cycle. The cycle seed in 0.20's INDEX.md cut
flags `Rate` on declarative builders as the natural follow-on.

## 3. The `f64` deprecation strategy

Per the user-stated cadence — "deprecate in same release as
typed replacement; delete one release later" — we ship the
typed signature **in place** in 0.20 and keep a deprecated
`*_pct` shim as the f64 escape hatch:

```rust
// crates/nlink/src/netlink/config/types.rs

impl QdiscBuilder {
    /// Set netem packet loss percentage.
    ///
    /// Takes a [`Percent`]; construct via `Percent::new(1.5)`,
    /// `"1.5%".parse()`, `Percent::from_fraction(0.015)`, or
    /// any of the constructors at [`crate::util::Percent`].
    pub fn loss(mut self, percent: Percent) -> Self {
        if let Some(DeclaredQdiscType::Netem { loss_percent, .. }) = &mut self.qdisc_type {
            // Internal storage stays f64 (matches kernel qopt
            // and the declarative diff machinery's existing
            // PartialEq comparison); the typed sig at the
            // boundary is what kills the wrong-units footgun.
            *loss_percent = Some(percent.as_percent());
        }
        self
    }

    /// **Deprecated** in 0.20: pass a typed [`Percent`] to
    /// [`Self::loss`] instead. The raw-`f64` form silently
    /// accepts out-of-range values and conflates
    /// percent-vs-fraction.
    #[deprecated(
        since = "0.20.0",
        note = "use loss(Percent::new(x)) — raw f64 doesn't clamp"
    )]
    pub fn loss_pct(self, percent: f64) -> Self {
        self.loss(Percent::new(percent))
    }
}
```

`Percent::new` saturates at `[0, 100]` (per
`crates/nlink/src/util/percent.rs:38`). Finding A7 separately
suggests adding a fallible `try_new`; that's a sibling 0.20
finding tracked under Plan 232 (LOW-tier batch). For this plan,
`Percent::new` is what users will reach for and the saturating
behaviour is consistent with the imperative sibling.

Reciprocal sites — `duplicate`, `corrupt`, `reorder`,
`loss_correlation`, `delay_correlation` — all follow the same
shape: typed signature replaces the existing `f64`; `*_pct` shim
emits `#[deprecated]`.

## 4. Doc test alignment

Every shipped example, recipe, and doctest that uses the
declarative builder must move from `.loss(1.0)` to
`.loss(Percent::new(1.0))` (or `"1.0%".parse()?`). Audit-time
sites that will break:

- `crates/nlink/src/netlink/tc.rs:16` — module-level doc example
- `crates/nlink/src/netlink/tc.rs:5190` — `NetemConfig` rustdoc
- `crates/nlink/src/netlink/tc.rs:5530` — `add_qdisc` example
- `crates/nlink/src/netlink/mod.rs:56` — netlink module example
- `crates/nlink/src/netlink/impair.rs:54` — `PerPeerImpairer` doc
- `docs/recipes/per-peer-impairment.md` — recipe walkthrough
- examples under `crates/nlink/examples/impair/`

These are also called out under Finding A5 (doc drift). Plan 229
owns the doc-sweep CI gate that ensures none of this drifts back.
Plan 228 owns the **API** flip + the existing doctest fixups in
the same commit; Plan 229 owns the **gate** that keeps it from
recurring. Coordinate ordering — 228 lands before 229 because
229's doc-test CI gate goes red until 228's API flip is in.

## 5. Test plan

1. **Unit tests at `config/types.rs`** confirming:
   - `QdiscBuilder::new().netem().loss(Percent::new(150.0))`
     stores 100.0 (saturated).
   - `QdiscBuilder::new().netem().loss(Percent::new(-1.0))`
     stores 0.0.
   - `QdiscBuilder::new().netem().loss(Percent::from_fraction(0.015))`
     stores 1.5 — the **fraction vs percent** confusion is now
     a typed-constructor difference, not a runtime bug.

2. **Wire-shape parity test** between declarative apply and
   imperative `add_qdisc`. Both paths must emit identical
   bytes for `.loss(Percent::new(1.5))` — confirmed by encoding
   under each path and asserting `==` on the resulting frames.
   This catches future drift where one path applies the
   saturating step and the other doesn't.

3. **`#[deprecated]` warning sweep**. The lib's own tests, bins,
   and examples must all migrate. CI's
   `cargo clippy --workspace --all-targets --all-features --
   --deny warnings` catches any callsite that still uses the
   deprecated shim. If any third-party recipe code is vendored
   under `crates/nlink-examples/` or similar, sweep those too.

4. **Compile-fail check** via trybuild that `.loss(1.5)` (bare
   `f64`) is now a type error. Pin the expected error message —
   regressions in the type checker's diagnostic wording shouldn't
   fail CI, so use the message-fragment match form trybuild
   supports.

## 6. Migration

`docs/migration_guide/0.19.0-to-0.20.0.md`:

```markdown
### Declarative builders take typed `Percent` (Plan 228)

`QdiscBuilder::{loss, duplicate, corrupt, reorder,
loss_correlation, delay_correlation}` now take `Percent` instead
of `f64`. This closes a units-confusion footgun that mirrored
the 0.13/0.14 unit-confusion bug.

Before:
```rust
QdiscBuilder::new("eth0").netem().loss(1.5)
```

After (any of):
```rust
QdiscBuilder::new("eth0").netem().loss(Percent::new(1.5))
QdiscBuilder::new("eth0").netem().loss("1.5%".parse()?)
QdiscBuilder::new("eth0").netem().loss(Percent::from_fraction(0.015))
```

A deprecated `loss_pct(f64)` shim is retained for 0.20 and
deleted in 0.21. The shim's behaviour matches old `loss` (it
delegates through `Percent::new`, which saturates).
```

## 7. Risks

- **Aggressive deprecation cadence**. The user's stated
  preference (`feedback_tc_api_direction.md`) is "deprecate in
  same release as typed replacement; delete one release later."
  That makes 0.20 → 0.21 the deletion window. For a MAJOR-tier
  footgun, this is the right speed: leaving `loss(f64)` in for
  multiple cycles keeps the footgun alive for longer than the
  fix is worth, and the migration is mechanical (`s/loss(/loss(Percent::new(/`).

- **Doctests drift into 0.20.0**. If Plan 229's doc-test CI gate
  doesn't land before this plan, the doctests will silently
  rot through the cycle. Mitigation: 228 lands its own doctest
  fixups in the same commit as the API flip; 229's CI gate
  catches any *future* drift.

- **`f64::into::<Percent>` is tempting**. A blanket
  `impl From<f64> for Percent` would let `loss(1.5)` keep
  working via inference. The audit (Finding A5 suggested fix)
  considers this; this plan rejects it for the same reason
  Finding A6 rejects `From<u16> for FilterPriority` — the
  blanket conversion erases the type-level intent. Keep
  `Percent::new` as the **explicit** constructor; force the
  call site to read clearly.

- **Internal storage stays `f64`**. The `DeclaredQdiscType::Netem
  { loss_percent: Option<f64>, … }` enum keeps `f64` internally.
  Changing it to `Option<Percent>` requires editing the diff /
  reconcile machinery (which compares with `PartialEq`); that's
  noise this plan doesn't need. The boundary type at the
  fluent-setter is what kills the footgun.

## 8. Acceptance

This plan ships when:

- ✅ All 6 declarative setters in §2 take `Percent`.
- ✅ The `*_pct(f64)` shims emit `#[deprecated(since = "0.20.0")]`.
- ✅ All doctests + recipes in the §4 list compile under
  `cargo test --doc -p nlink`.
- ✅ The wire-shape parity test confirms declarative apply
  produces the same netem-qopt bytes as imperative.
- ✅ `cargo clippy --workspace --all-targets --all-features --
  --deny warnings` passes (no internal site still uses the
  deprecated shim).
- ✅ The migration guide gains the §6 entry.

## 9. Cross-references

- [Plan 220 master](220-0.20-master-plan.md) §3.3 — typed-API
  tightening
- [AUDIT_API.md](../AUDIT_API.md) Finding A1 (this plan's source,
  the only MAJOR finding) + A5 (sibling doctest drift) + A7
  (Percent::try_new sibling, deferred)
- [Plan 227 — `AddressFamily`](227-family-newtype-plan.md) —
  sibling typed-API tightening, same deprecation cadence
- [Plan 229 — doc-drift sweep](229-doc-drift-sweep-plan.md) —
  owns the CI gate that keeps the doctest fixups from rotting
- CLAUDE.md `## Type-safe units` — the convention lineage; this
  plan is its extension to the declarative path
- `feedback_tc_api_direction.md` (user memory) — deprecation
  cadence ratified
