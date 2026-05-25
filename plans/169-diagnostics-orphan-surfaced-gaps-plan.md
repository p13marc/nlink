---
to: nlink maintainers
from: Plan 168 post-execution forensic analysis (2026-05-25)
subject: Real lib-side gaps surfaced by the Plan 160 / Plan 168 orphan-example investigation
status: Phases 1 + 2 landed (2026-05-25 pre-cut window) — 4 gaps closed. Phase 3 (`Bottleneck::score`) deferred to 0.17 — design call on the combining formula.
target version: 0.16.0 (Phases 1+2) + 0.17.0 (Phase 3)
parent: 160-example-registry-audit.md + 168-orphan-examples-closeout-plan.md
source: forensic read of every orphan's phantom symbols against the actual lib API
created: 2026-05-25
---

# Plan 169 — diagnostics-layer gaps surfaced by orphan investigation

## 0. Why this plan exists

The Plan 160 + Plan 168 orphan-example closeout removed 9 broken
example files from the catalog. But the *phantom symbols* in
those examples are evidence: each one is a code path that some
author thought *should* exist. Most were just naming misses
(rename drift, abbreviated field names). But **five of them
point at real lib-side coverage gaps** worth filling.

This plan separates the noise (phantom = orphan was wrong) from
the signal (phantom = lib really is missing something) and
proposes per-gap fixes.

## 1. What the orphans actually surfaced

### 1.1 Three patterns

| Pattern | Description | Action |
|---|---|---|
| **A — rename drift** | Example was right once; the lib renamed a symbol and the orphan didn't get updated. | Fix the example (already done in Plan 168). No lib change. |
| **B — phantom API** | Author expected a symbol that never existed. Sometimes the orphan was wrong (the right name does exist with different spelling). Sometimes the *concept* is missing from the lib. | Distinguish: rename vs. coverage gap. Gap → fill. |
| **C — ahead-of-API design** | Example written against a draft API design that was later redesigned; the example was never rewritten. | Fix the example against the shipped API (Plan 168 §4.2 already rewrote `config/declarative.rs`). |

### 1.2 Per-symbol forensic verdict

| Orphan symbol | Verdict | Action |
|---|---|---|
| `LinkMessage::link_kind()` | A (rename to `.kind()`) | Examples fixed; no lib change. |
| `route.gateway` | A (rename to `.via`) | Examples fixed. |
| `nh.is_blackhole()` | A (method-to-field `nh.blackhole`) | Examples fixed. |
| `FdbEntry::is_local()` | B-noise (orphan wanted `is_self()` — kernel uses NTF_SELF terminology) | Examples fixed. No gap. |
| `RouteDiag::has_default_v4` | A (abbreviated; real is `has_default_ipv4`) | Already correct; orphan was just lazy. |
| `gateway_reachable: Option<bool>` | B-noise (orphan wanted Option; actual `bool` is right — `false` means unreachable) | No change. |
| `Srv6LocalRoute::table` | B-gap | **§3.4 — surface the kernel TABLE attr as a top-level getter.** |
| `RouteInfo::src` | B-gap | **§3.1 — RTA_PREFSRC is parsed at the RouteMessage level (`prefsrc()`) but dropped when building RouteInfo. Surface it.** |
| `RouteInfo::dev` | B-gap | **§3.2 — diagnostics already resolves the OIF→name in its scan path; just lift it onto RouteInfo for direct access.** |
| `InterfaceDiag.up: bool` | B-gap | **§3.3 — LinkMessage has `is_up()` and `has_carrier()`; InterfaceDiag drops these and forces callers to inspect `state` + `flags` themselves.** |
| `InterfaceDiag.carrier: bool` | B-gap | (same as above) |
| `Bottleneck::score: f64` | B-gap (design call) | **§3.5 — a normalized 0.0..=1.0 severity score is missing. Useful for monitoring/alerting integrations.** |
| `config::{LinkConfig,LinkType,AddressConfig,...}` | C (ahead-of-API; struct API never landed) | Example rewritten to closure-based shipped API. |

## 2. Why these matter

Each of the five real gaps shares a shape: the **lower-level**
type already carries the data, but the **higher-level**
"diagnostics" wrapper that operators actually use as a public
API drops it on the way through. That's a worse pattern than
a missing feature — the data is *there*, the parser already
read it, the public-API wrapper just throws it away. Users
hit a dead end.

The orphan examples are evidence that prior authors (or the
original API designer working from memory) reasonably expected
to find this data on the diagnostic-layer types. Closing the
gaps removes a class of "wait, this is missing?" moments.

## 3. Per-gap fix design

### 3.1 `RouteInfo::source: Option<IpAddr>` (RTA_PREFSRC)

**Current** (`crates/nlink/src/netlink/diagnostics.rs:329`):

```rust
pub struct RouteInfo {
    pub destination: String,
    pub prefix_len: u8,
    pub gateway: Option<IpAddr>,
    pub oif: Option<u32>,
    pub metric: Option<u32>,
}
```

**Builder path** (`diagnostics.rs:748`): drops `r.prefsrc()`
even though it's available on the underlying RouteMessage.

**Fix**:

1. Add field: `pub source: Option<IpAddr>`.
2. In the builder at `diagnostics.rs:748`, set
   `source: r.prefsrc().copied()`.
3. Add `#[non_exhaustive]` to the struct (matching Plan 163
   convention — this is a NEW pub field add; without
   `#[non_exhaustive]` it's mildly breaking for anyone who
   pattern-matched the struct, but RouteInfo is parser-output
   only so the risk is theoretical).
4. Wait — RouteInfo predates Plan 163's lockdown list. Adding
   a field is mildly breaking for exhaustive match. Either:
   (a) make the field add, expect breakage in 0.17 cycle, OR
   (b) add `#[non_exhaustive]` at the same time as the field
   (still adds the field; the attribute prevents future-field
   adds from breaking).

**Recommended**: (b) — `#[non_exhaustive]` + new field, as a
bundle. Mirrors Plan 163 spirit.

**Effort**: ~15 min including a unit test.

### 3.2 `RouteInfo::dev_name: Option<String>`

**Current**: `RouteInfo::oif: Option<u32>` (kernel ifindex
only). Callers wanting the name must cross-reference against
something else (a links dump, the `DiagnosticReport.interfaces`
table, `/sys/class/net/`).

**Builder path** (`diagnostics.rs:740-746`): ALREADY resolves
OIF → name via `conn.get_link_by_index(idx).await?.name()`.
The result is bound to a local `output_interface` variable +
returned alongside RouteInfo from the function — but NOT into
RouteInfo itself. Plumbing miss.

**Fix**:

1. Add field: `pub dev_name: Option<String>`.
2. In the builder, set
   `dev_name: output_interface.clone()`.

**Effort**: ~10 min.

### 3.3 `InterfaceDiag::is_up()` + `has_carrier()`

**Current** (`diagnostics.rs:95`):

```rust
pub struct InterfaceDiag {
    pub state: OperState,
    pub flags: u32,
    ...
}
```

`LinkMessage::is_up()` (`messages/link.rs:360`) and
`has_carrier()` (`:385`) exist. Users of the diagnostics layer
have to either bit-test the `flags` themselves (and remember
`IFF_UP` is `0x1`, etc.) or compare against `OperState::Up`.

**Fix**: add the same two methods on InterfaceDiag, delegating
to the well-defined predicates the lib already has:

```rust
impl InterfaceDiag {
    /// True if the IFF_UP flag is set (admin-up).
    pub fn is_up(&self) -> bool {
        self.flags & libc::IFF_UP as u32 != 0
    }

    /// True if the IFF_RUNNING flag is set (link layer detected
    /// carrier and a connected peer at L1/L2).
    pub fn has_carrier(&self) -> bool {
        self.flags & libc::IFF_RUNNING as u32 != 0
    }

    /// True if the interface is administratively up AND in
    /// OperState::Up (i.e., ready to carry traffic).
    pub fn is_operational(&self) -> bool {
        self.is_up() && self.state == OperState::Up
    }
}
```

**Effort**: ~15 min including unit tests.

### 3.4 `Srv6LocalRoute::table() -> Option<u32>`

**Current** (`srv6.rs:363`): table is embedded in action
variants:

```rust
pub enum Srv6Action {
    EndT { table: u32 },
    EndDT4 { table: u32 },
    EndDT6 { table: u32 },
    EndDT46 { table: u32 },
    // ... variants without table ...
}
```

The orphan wanted `route.table`. The kernel UAPI puts the
table attribute INSIDE the action's nested encap block, so
the variant-level placement is technically correct. But UX:
asking "what table is this SRv6 SID in?" requires:

```rust
let table = match &route.action {
    Srv6Action::EndT { table } |
    Srv6Action::EndDT4 { table } |
    Srv6Action::EndDT6 { table } |
    Srv6Action::EndDT46 { table } => Some(*table),
    _ => None,
};
```

**Fix**: add a convenience getter on `Srv6LocalRoute` that
encapsulates that match:

```rust
impl Srv6LocalRoute {
    /// The routing table this SID directs into, if the
    /// action uses one (EndT / EndDT4 / EndDT6 / EndDT46).
    /// Returns None for actions that don't have a target
    /// table (End / EndX / EndDX2 / EndDX4 / EndDX6 / etc.).
    pub fn table(&self) -> Option<u32> {
        match &self.action {
            Srv6Action::EndT { table } |
            Srv6Action::EndDT4 { table } |
            Srv6Action::EndDT6 { table } |
            Srv6Action::EndDT46 { table } => Some(*table),
            _ => None,
        }
    }
}
```

**Effort**: ~10 min.

### 3.5 `Bottleneck::score: f64` (design call)

**Current** (`diagnostics.rs:344`): Bottleneck has
`drop_rate: f64` (0.0..=1.0), `total_drops: u64`,
`current_rate: u64`, `recommendation: String`. No single
"how severe?" metric.

**The orphan's expectation**: `bottleneck.score: f64` — a
normalized 0.0..=1.0 number suitable for "alert if > 0.5"
monitoring patterns.

**Design choices**:

A. **Don't add it.** `drop_rate` is already 0..1 and is the
   most actionable single number. Users wanting more
   sophistication can combine fields themselves.
B. **Add as alias for drop_rate.** Trivial; lossy compared
   to combining signals.
C. **Add as composite metric.** Combine drop_rate + backlog
   pressure + error rate. Requires defining a formula the
   lib commits to (semver-stable).
D. **Add as Severity enum** (Info/Warn/Error/Critical, similar
   to the existing `Severity` enum). Quantized; less granular.

**Recommendation**: defer this to a design discussion. The
question "what counts as a severe bottleneck?" depends on
the use case (latency-sensitive RT workload vs. bulk
throughput). Picking a single formula now risks shipping
something users override anyway.

**If we ship in 0.17**: option C with a documented formula:

```rust
/// Normalized severity score in 0.0..=1.0.
///
/// Combines drop_rate (weight 0.6), backlog pressure
/// (weight 0.3, normalized as min(backlog_bytes / 1MB, 1.0)),
/// and error rate (weight 0.1). The weights are documented
/// rather than configurable — for use cases that need
/// different weighting, compute the score yourself from the
/// underlying fields.
pub fn score(&self) -> f64 {
    let drop_component = self.drop_rate * 0.6;
    let backlog_pressure = /* ... */;
    let error_component = /* ... */;
    (drop_component + backlog_pressure + error_component).min(1.0)
}
```

But this is "design discussion in #ops channel" territory,
not a pre-cut fix.

**Effort if shipped**: ~1h including formula validation +
unit tests + recipe note on when to override.

## 4. Phases

### Phase 1 — Lift dropped data (gaps §3.1 + §3.2)

Both touch `RouteInfo`. Bundle into one commit.

- Add `RouteInfo::source: Option<IpAddr>`.
- Add `RouteInfo::dev_name: Option<String>`.
- Mark struct `#[non_exhaustive]` (mirrors Plan 163).
- Update `build_route_diag` (only caller) to populate
  both new fields.
- 1 unit test against a synthetic route.
- CHANGELOG entry.

**Effort**: ~30 min.

### Phase 2 — Convenience predicates (gaps §3.3 + §3.4)

Both add methods to existing public types. No struct shape
changes; pure additive.

- `InterfaceDiag::is_up() / has_carrier() / is_operational()`.
- `Srv6LocalRoute::table()`.
- 2-3 unit tests.
- CHANGELOG entry.

**Effort**: ~30 min.

### Phase 3 — `Bottleneck::score` design call (DEFERRED)

Either:

- **Option A (recommended)**: skip for 0.16; capture as a
  proposed 0.17 plan that asks for use-case input first.
- **Option B**: ship the documented-formula version (§3.5
  recommendation) as part of 0.16. Adds ~1h and locks in a
  formula.

## 5. Acceptance criteria

- [ ] `RouteInfo` has `source` + `dev_name`, both populated
      by `build_route_diag`, both `#[non_exhaustive]`-protected.
- [ ] `InterfaceDiag::is_up()` / `has_carrier()` /
      `is_operational()` ship + are documented.
- [ ] `Srv6LocalRoute::table()` ships + handles every
      action variant correctly.
- [ ] Lib tests cover the new methods (at least one assertion
      each).
- [ ] `cargo clippy --workspace --all-features` clean.
- [ ] CHANGELOG entry under
      `### Added — diagnostics layer gaps closed (Plan 169)`.
- [ ] Migration guide entry if any of the additions are
      observably breaking (RouteInfo struct-literal users —
      `#[non_exhaustive]` will catch them, document the
      builder-style workaround).

## 6. Effort estimate

| Phase | Effort |
|---|---|
| 1 RouteInfo fields | ~30 min |
| 2 convenience predicates | ~30 min |
| 3 Bottleneck::score (deferred) | ~1 h if shipped, 0 if deferred |
| **Total** (Phases 1 + 2 only — recommended for 0.16) | **~1 hour** |

## 7. Why this matters (the meta-lesson)

The Plan 160 + Plan 168 closeout closed the orphan catalog,
but the *information* in the orphans was almost-discarded
along with the broken code. Each phantom symbol was a record
of "an author wanted this and didn't find it." Pattern A
phantoms (rename drift) were already-fixed bugs; Pattern B
phantoms were quietly accumulated UX papercuts.

Going forward, the `audit-example-registration` CI gate
prevents new orphans, but it doesn't surface the same kind of
"missing UX" signal. The closest substitute is to listen
when users open issues with the shape "I was looking for X
on type Y but it's not there" — those are the same evidence,
in a different channel.

## 8. Out-of-scope follow-ups

- **`Bottleneck::score`** — Plan 170 territory if the design
  discussion converges on a formula.
- **`gateway_reachable: Option<bool>`** — the orphan wanted
  Option, the lib has `bool`. The lib's `bool` is right
  (false = unreachable). No change.
- **Per-protocol prefsrc** — RouteInfo's `source` is
  `Option<IpAddr>`. The kernel-level RouteMessage exposes
  `prefsrc()` typed as `Option<&IpAddr>`. RouteInfo is the
  generic-IpAddr type, so no IPv4/IPv6 split needed.
- **Process improvement: ahead-of-API examples**: the
  `config/declarative.rs` (Pattern C) case suggests a
  CLAUDE.md convention worth recording: "examples are
  written against shipped public API only; if you're
  documenting a design before it lands, use plans/
  not examples/." Not blocking for 0.16; worth a
  half-line note in CLAUDE.md when there's a doc-polish
  commit anyway.

End of plan.
