---
to: nlink maintainers
from: nlink maintainers
subject: 0.15.0 typed-API completion — zero-legacy milestone (consolidates Plans 133 PR C, 138, 139, 140, 141)
target version: 0.15.0 (substantively shipped under `[Unreleased]`; cut-pending)
date: 2026-04-25; substantively closed 2026-04-25
status: **CLOSED — all 5 phases substantively shipped; only sudo-gated tail items remain.** **Phase 0** (`553f9dd` + `05b626d`): `nlink::lab::has_module` + `require_module!` macros + sealed `nlink::ParseParams` trait + 25 (now 41) impls + bins/tc dispatch tightened. **Phase 1** (`ae0e4ae` + `3b5cb21` + `d95a0ea` + `e2ee5d8`): Plan 138 closes (3 PRs) + Plan 133 PR C closes; filter side at 9/9 typed-first. **Phase 2** (`74a4e48` + `844a166` + `a120ee7`): Plan 141 PRs A+B close — XFRM SA + SP CRUD with 20 round-trip tests; PR C (recipe + `--apply`) is sudo-gated. **Phase 3** (`d69e10a` + `f7e4502` + `d124920` + `2764806`): Plan 139 PRs A+B close — typed standalone-action CRUD + `parse_params` on all 14 action kinds (74 tests). **Phase 4** (`b2370fd` + `0d095ae` + `56371db`): legacy-deletion milestone — `tc::builders::*` + `tc::options/*` deleted (-3940 LOC), zero `#[allow(deprecated)]` in `bins/tc`, every §6 acceptance gate met. Lib tests: 593 → 749 (+156). **Master plan closed; phase-level detail plans (133, 138, 139, 140, 141) all marked closed in their own headers.** Remaining tail (sudo-gated, ships post-cut): Plan 141 PR C recipe; Plan 140 GHA workflow YAML alongside Plan 137 integration tests un-parking. Procedural follow-up: cut 0.15.0 (bump version, rename `[Unreleased]`, publish). Migration walkthrough: [`docs/migration_guide/0.14.0-to-0.15.0.md`](docs/migration_guide/0.14.0-to-0.15.0.md).
---

# Plan 142: 0.15.0 — Typed-API completion (zero-legacy milestone)

## 0. Why this plan exists

The typed-units rollout (0.14.0, 15 slices, 25 `parse_params`,
`bins/tc` qdisc 100% typed-first) demonstrated that a coherent
typed surface is reachable. What's left to ship 0.15.0 is the
*completion* of that surface plus the *removal* of the parallel
legacy surface. Today those two outcomes are tracked across five
plans:

- **Plan 133 PR C** — `BasicFilter` ematch (last filter kind not
  typed-first)
- **Plan 138** — bins/tc u32 filter selector grammar (penultimate
  filter kind)
- **Plan 139** — typed standalone-action CRUD + **delete
  `tc::builders::{class,qdisc,filter,action}` + `tc::options/*`**
- **Plan 140** — CI integration tests harness (gating dependency
  for any new root-gated tests)
- **Plan 141** — XFRM write-path (closes Plan 135 PR B's last
  recipe)

Each of those plans stands on its own as a phase-level
implementation guide. **This plan is the master**: it states the
end-state API, sequences the phases, defines the legacy-removal
milestone unambiguously, and guarantees the doc / CHANGELOG /
CLAUDE.md updates land *as part of* the work rather than as
afterthoughts. **Plans 138/139/140/141 + Plan 133 PR C remain
authoritative for their respective wire-format / per-kind /
per-PR detail.** This plan does not duplicate that content; it
binds it.

Plans **133 PRs A/B/D, 135 PRs A + 6 of 7 B, 136, 137 PRs A+B**
are already shipped under `[Unreleased]` for 0.14.0 and out of
scope here. **Plan 137 PRs C/D/E** (`ct_expect`, nfqueue, nflog)
are demand-gated and explicitly outside the 0.15.0 milestone.

## 1. Goals & non-goals

### Goals

1. **Articulate the end-state API as a coherent surface** so
   reviewers / contributors / downstream consumers can read one
   document and understand what 0.15.0 ships.
2. **Formalize the patterns** that the 0.14.0 typed-units rollout
   established by adoption — the `parse_params` shape, the typed
   builder / fluent setters / `build()` triple, the
   `try_typed_X` dispatch macro, the typed-then-legacy-fallback
   handle parsing — into a documented contract in CLAUDE.md and
   (where it adds clarity) in code via a `ParseParams` trait.
3. **Sequence the remaining phases** so each prerequisite lands
   before its dependents, no parallel branches block on each
   other, and the legacy-removal milestone is reachable in a
   single PR rather than a long tail of "almost there" commits.
4. **Hard milestone**: at the end of Phase 4 (Plan 139 PR C), the
   workspace contains zero `#[allow(deprecated)]` directives
   targeting `tc::builders::*` or `tc::options::*`, and those
   modules are deleted from the source tree. CI enforces this:
   a `cargo clippy --workspace --all-targets -- --deny warnings`
   that touches deprecated items must fail.
5. **Documentation lands with each phase**, not deferred. Every
   phase PR ticks: CHANGELOG entry under `## [Unreleased]`,
   CLAUDE.md updated where the API surface changes, recipe /
   example cross-references updated where deferred items resolve.

### Non-goals

1. **Other-bin migrations.** The roadmap "Workspace-wide rollout
   to other bins" backlog row tracks the audit of `bins/{ip,ss,
   nft,wifi,devlink,bridge,wg,ethtool,diag,config}`. The bins
   that already use typed APIs need no migration; per-bin plans
   open opportunistically as audits surface real work. **Out of
   scope** for 0.15.0 unless a per-bin audit lands first.
2. **Plan 137 PRs C/D/E** (`ct_expect`, nfqueue, nflog).
   Demand-gated; outside the milestone.
3. **API redesign of already-shipped typed configs.** The
   18 qdisc + 7 filter typed configs that landed in 0.14.0 stay
   as-is. This plan formalizes the patterns they exemplify;
   it does not refactor them.
4. **`mqprio` / `taprio` `queues <count@offset>` pair grammar.**
   Backlog row; ~50 LOC when someone hits the deferred error.
   Not on the 0.15.0 critical path.

---

## 2. The end-state API (what 0.15.0 ships)

This section is the high-level design document. It is the
specification the phase plans implement against. It describes
**every typed surface a user sees** when they reach for nlink in
0.15.0.

### 2.1. Typed configuration objects

Every TC entity (qdisc / class / filter / action) has a typed
configuration struct in `nlink::netlink::{tc,filter,action}`:

```rust
use nlink::netlink::tc::HtbQdiscConfig;
use nlink::Rate;

let cfg = HtbQdiscConfig::new()
    .default_class(0x10)
    .r2q(10)
    .build();
```

**Conventions** (uniform across all 25+ typed configs):

- `pub struct FooConfig { ... }` — `#[derive(Debug, Clone)]` at
  minimum; `#[derive(Default)]` where every field has a sensible
  default, or a hand-rolled `Default` that delegates to `new()`.
- `impl FooConfig { pub fn new() -> Self }` — entry constructor.
- Fluent setters: `pub fn x(mut self, ...) -> Self`. Each setter
  consumes `self` and returns `Self`, so calls chain
  left-to-right with no intermediate bindings.
- `pub fn build(self) -> Self` — terminal no-op for API symmetry
  with builder patterns that *do* validate. Kept transparent
  intentionally (the kernel is the validator); reviewers should
  not introduce `Result`-returning builds without a concrete
  reason.
- Implements the relevant `QdiscConfig` / `FilterConfig` /
  `ActionConfig` trait. The trait is what `Connection<Route>`'s
  generic methods take.

### 2.2. Token-stream parsing — the `parse_params` convention

CLI consumers (chiefly `bins/tc`) need to turn an `&[String]` of
user-supplied tokens into a typed config. Every typed config
exposes:

```rust
impl FooConfig {
    pub fn parse_params(params: &[&str]) -> Result<Self> { ... }
}
```

**Conventions** (audited as uniform across every shipped parser):

- **Signature**: `&[&str]` in, `nlink::Result<Self>` out. Caller
  is responsible for `params.iter().map(String::as_str).collect()`
  if they have an `&[String]`.
- **Strictness**: unknown tokens, missing values, and unparseable
  inner values all return `Error::InvalidMessage(format!("kind: ..."))`.
  Silent skipping is a bug. The legacy `tc::options::*` parsers
  silently swallowed unknown tokens — that fossil is what the
  typed parsers explicitly fix.
- **Error message shape**: `"kind: invalid <token-name> `<value>` (<expected ...>)"`
  or `"kind: `<token>` requires a value"` or `"kind: unknown token `<token>`"`
  — all begin with the kind name to disambiguate when nested
  errors bubble up.
- **Token ordering**: any-order keyword. Positional optional args
  (e.g., `delay <time> [<jitter> [<corr>]]`) are consumed greedily
  up to the next keyword via a per-config `is_keyword` helper.
- **Aliases**: where `tc(8)` accepts multiple tokens for the same
  attribute (`classid` / `flowid`, `burst` / `buffer` / `maxburst`),
  the parser handles them at the same arm.
- **"Not modelled yet" rejections**: when the kernel accepts a
  token (`mqprio`'s `queues`, `tbf`'s `latency`, `cgroup`'s
  ematch) that the typed config doesn't carry, the parser returns
  a clear "not modelled by FooConfig — use tc::options::foo or
  hand-rolled MessageBuilder" error. **Never silently fall back.**
- **Doc string**: enumerates recognised tokens with one-line
  semantics each, plus a "**Not yet typed-modelled**" subsection
  for any rejections.

**Trait formalization** (lands in Phase 0 alongside Plan 140):

```rust
// crates/nlink/src/netlink/tc.rs (new — for QdiscConfig parsers)
// crates/nlink/src/netlink/filter.rs (new — for FilterConfig parsers)

/// Parse a tc(8)-style token slice into a typed config.
///
/// Implementations return `Err(Error::InvalidMessage(...))` for
/// unknown tokens, missing values, and unparseable inner values.
/// Silent skipping is a bug. See the parser doc-strings on
/// individual configs for the recognised token sets.
pub trait ParseParams: Sized {
    fn parse_params(params: &[&str]) -> Result<Self>;
}
```

Sealed via `private::Sealed` — no third-party impls. Every shipped
typed config gets a `impl ParseParams for FooConfig { ... }` that
forwards to its inherent `parse_params` method (so existing
inherent-method callers don't break).

The trait gives the bin's `dispatch!` macro a contract to bind to
(currently it relies on each type having an inherent
`parse_params` method, which works but isn't enforced by the type
system). It also opens the door to a generic
`Connection::parse_and_add_qdisc<C: QdiscConfig + ParseParams>(...)`
helper if a downstream consumer wants one, though this plan
doesn't ship that.

### 2.3. `Connection<P>` typed methods

Every TC operation has a typed entry point:

```rust
// Qdisc — landed in 0.14.0
conn.add_qdisc_full(dev, parent, handle, cfg).await?;
conn.del_qdisc_full(dev, parent, handle).await?;
conn.replace_qdisc_full(dev, parent, handle, cfg).await?;
conn.change_qdisc_full(dev, parent, handle, cfg).await?;

// Class — landed in 0.14.0
conn.add_class_config(dev, parent, classid, cfg).await?;
conn.del_class(dev, parent, classid).await?;
// ... etc

// Filter — landed in 0.14.0
conn.add_filter_full(dev, parent, handle, proto, prio, cfg).await?;
conn.del_filter(dev, parent, proto, prio).await?;
// ... etc

// Standalone action — NEW in 0.15.0 (Phase 3, Plan 139 PR A)
let index: u32 = conn.add_action(action).await?;
conn.add_action_with_index(action, index).await?;
conn.del_action(kind, index).await?;
let action_info: ActionMessage = conn.get_action(kind, index).await?;
let all: Vec<ActionMessage> = conn.dump_actions(kind).await?;

// XFRM — NEW in 0.15.0 (Phase 2, Plan 141)
conn.add_sa(sa).await?;
conn.del_sa(src, dst, spi, proto).await?;
conn.add_sp(sp).await?;
conn.del_sp(&sel, dir).await?;
// ... etc
```

**`*_full` vs short forms**: `add_qdisc(dev, cfg)` defaults parent
to `TcHandle::ROOT` and handle to `None`. `add_qdisc_full(dev,
parent, handle, cfg)` is the explicit form. The bin uses `_full`
because it has user-supplied parent/handle; recipes typically use
the short form. Both stay; both are tested.

### 2.4. Bin-side: `bins/tc` typed dispatch shape

The bin's qdisc / filter / action subcommands use a uniform
shape:

```rust
// bins/tc/src/commands/{qdisc,filter,action}.rs

#[allow(clippy::too_many_arguments)]
async fn try_typed_X(
    conn: &Connection<Route>,
    dev: &str,
    parent: &str,
    /* ... per-subcommand args ... */,
    kind: &str,
    params: &[String],
    verb: XVerb,
) -> Option<Result<()>> {
    if !matches!(kind, /* known kinds list */) {
        return None;
    }
    // 1. Parse positional handles via TcHandle::from_str.
    // 2. Call FooConfig::parse_params(&refs).
    // 3. Dispatch on verb.
    Some(match kind {
        "htb" => dispatch!(HtbQdiscConfig),
        "netem" => dispatch!(NetemConfig),
        // ...
        _ => unreachable!("checked by `matches!` guard above"),
    })
}
```

**End-state in 0.15.0**: every kind that has a typed config has a
`parse_params`. The `matches!` guard lists every typed kind. The
legacy fallback (`qdisc_builder::add` / `filter_builder::add` /
`action_builder::*`) is deleted because there are no kinds left
that fall through. The `#[allow(deprecated)]` directives that
guarded the legacy import lines come out with the deletion.

### 2.5. Why we don't use clap's `value_parser` for `TcHandle`

The bin parses `parent: String` from clap and converts to
`TcHandle` later in `parse_handles`. Tempting to think the parse
should land at clap-time via `#[arg(value_parser)]`, but the
typed-then-legacy fallback **requires** the string form to live
through to the dispatcher: if `parse_handles` fails, the legacy
parser (which has its own handle parser) takes over. Once the
legacy fallback is deleted (Phase 4), this constraint goes away
and the bin **could** move parsing to clap-time. **In-scope for
Phase 4 PR**: convert `parent`/`handle`/`classid` to
`TcHandle` at clap-parse-time as part of the legacy deletion.
Same for `prio: Option<FilterPriority>`.

### 2.6. Errors

All `parse_params` methods return `Result<T>` with `T` ::
`nlink::Result`, the error variant being
`nlink::Error::InvalidMessage(String)`. The string carries
context — kind name + token + expected format. **No typed parse
error variants.** The `format!`-shaped messages have proven readable
in interactive use and uniform across the 25 shipped parsers; a
typed error variant would either explode the variant count (one per
kind × token) or collapse to a stringly-typed `kind`/`token`
pair that's no better than the current free-form string.

This decision is honest, durable, and documented.

---

## 3. Rust-idiomatic patterns we honour

The 0.14.0 rollout established and validated these patterns. The
0.15.0 work continues them. Listed here so reviewers have a
single reference and contributors don't accidentally drift:

| Pattern | Where used | Why |
|---|---|---|
| `#[non_exhaustive]` on public enums (`CakeFlowMode`, `FlowKey`, `ConntrackEvent`, etc.) | Every public enum that mirrors a kernel value space | Kernel adds variants; we add them in minor releases without breaking matches. |
| Public structs *not* `#[non_exhaustive]` (`CakeConfig`, `NetemConfig`, ...) | All typed config holders | The fluent-setter API is the addition point; no need to constrain struct expression. |
| Builder methods return `Self`, not `&mut Self` | All typed builders | Allows chained `.x().y().z()` without intermediate bindings; consumes self so the builder can't be re-used after `.build()`. |
| `build() -> Self` is transparent | All typed builders | Symmetric with builder patterns that validate; the kernel is the validator. Don't introduce `Result`-returning builds without a concrete reason. |
| Sealed traits via `private::Sealed` | `ProtocolState`, `EventSource`, `ParseParams` (new) | Prevents third-party impls without being annoying for first-party code. |
| `Result<T>` everywhere; never `unwrap()` in library code | All public APIs | Self-explanatory. |
| Async methods spell `pub async fn` | All `Connection<P>` mutations | Tokio-native; no `#[tokio::main]` in library code. |
| Doc-strings cite tc(8) where syntax matches | All `parse_params` doc-strings | User reaches for tc(8) man pages; we honour their vocabulary. |
| `#[tracing::instrument]` on every public `Connection<P>` method | Every typed `add_/del_/get_/replace_/change_/flush_` | Tooling/observability. The Plan 137 work did this; new methods follow. |
| Format-string error messages over typed error variants for parse errors | All `parse_params` | See §2.6. |
| Skip-if-not-root + skip-if-modules-missing for integration tests | Lands with Plan 140 | Tests stay runnable as a regular user; CI runs them for real. |

---

## 4. Phase dependency graph

```
                  ┌──────────────────────────────────────┐
                  │ Phase 0: CI infrastructure (Plan 140)│
                  │  + ParseParams trait formalization   │
                  └────────────────┬─────────────────────┘
                                   │
                                   ▼
       ┌───────────────────────────────────────────────────────┐
       │ Phase 1: Filter side completion                       │
       │   - Plan 138 PR A (u32 raw triples + structural)     │
       │   - Plan 138 PR B (named-match shortcuts + fixtures) │
       │   - Plan 138 PR C (hash-table grammar)               │
       │   - Plan 133 PR C (BasicFilter ematch)               │
       │   - Plan 137 integration tests (un-parked by Plan 140)│
       └────────────────┬──────────────────────────────────────┘
                        │
                        ▼
                  ┌──────────────────────────────────┐
                  │ Phase 2: XFRM (Plan 141 A+B+C)   │
                  └────────────────┬─────────────────┘
                                   │
                                   ▼
                  ┌─────────────────────────────────────────────────┐
                  │ Phase 3: Action API (Plan 139 PR A + PR B)      │
                  │   - Library API: add/del/get/dump_action        │
                  │   - parse_params on every typed action kind     │
                  └────────────────┬────────────────────────────────┘
                                   │
                                   ▼
                  ┌──────────────────────────────────────────────────┐
                  │ Phase 4: LEGACY DELETION (Plan 139 PR C)         │
                  │   - bins/tc/src/commands/action.rs migrated      │
                  │   - tc::builders::{class,qdisc,filter,action}    │
                  │     and tc::options/* DELETED from source tree   │
                  │   - All #[allow(deprecated)] directives DELETED  │
                  │   - bins/tc clap value_parser conversion         │
                  │   - 0.15.0 release-cut commit                    │
                  └──────────────────────────────────────────────────┘
```

**Why this order**:

- **Phase 0 first** because Plan 140 unblocks every later phase's
  integration tests, and the `ParseParams` trait formalization is
  load-bearing for the dispatch macro contract.
- **Phase 1 second** because it's the smallest meaningful
  user-visible win and finishes the bin's filter side. With
  Plan 137 integration tests un-parked by Phase 0, they ride
  along here.
- **Phase 2 third** because XFRM is independent of the bin work
  but unblocks Plan 135 PR B's last recipe. Concurrent with
  Phase 3 if maintainer bandwidth allows.
- **Phase 3 fourth** because it's the largest single phase
  (~14 action `parse_params` + library API) and is the
  prerequisite for Phase 4.
- **Phase 4 last** and *atomic* — the deletion lands in one
  commit (the bin migration + the module deletion + the doc
  updates). Splitting risks an in-tree state where the legacy
  is half-removed.

---

## 5. Phase deliverables

### Phase 0 — Infrastructure (Plan 140 + trait formalization)

**Plan 140 details**: see `140-ci-integration-tests-plan.md`.
**Additional Phase 0 work** layered on top of Plan 140:

- Add `pub trait ParseParams: Sized` (sealed) in
  `crates/nlink/src/netlink/tc.rs` (re-exported from a shared
  location TBD during PR review — possibly `crates/nlink/src/lib.rs`
  as a top-level re-export, since both `tc::` and `filter::` configs
  implement it).
- Add `impl ParseParams for FooConfig { ... }` for every existing
  typed config that has an inherent `parse_params` (25 impls,
  each ~3 lines forwarding to the inherent method). Ship the
  trait + impls in the **same PR as Plan 140** so the bin's
  dispatch macro can switch from `Cfg::parse_params` (inherent) to
  `<Cfg as ParseParams>::parse_params` (trait) — no behaviour
  change, just a contract-binding tightening.
- Update the `try_typed_qdisc` / `try_typed_filter` macro
  callsites to bind through the trait. No-op functionally but
  clarifies the contract.

**Doc updates** (in the same PR):

- CLAUDE.md gains a new section after "Type-safe TC handles"
  titled **"TC API conventions"** that documents:
  - The `parse_params` convention (§2.2 of this plan, condensed)
  - The `ParseParams` trait
  - The typed dispatch shape in `bins/tc` (§2.4 condensed)
  - The "why no clap value_parser" rationale (§2.5 condensed)
- CHANGELOG entry under `## [Unreleased]` describing the trait
  + CI workflow + skip helpers.

**DoD**: per Plan 140 §11 + the trait formalization items above.

### Phase 1 — Filter side completion (Plan 138 + Plan 133 PR C + Plan 137 integration tests)

**Plans**: 138, 133 PR C; integration tests slot from 137.
**Deliverables** (each PR has its own DoD in the cited plan;
this plan adds doc-update requirements):

- After **Plan 138 PR A** lands: bin's filter `matches!` guard
  grows `u32`; Phase 1 tally: 8 of 9 filter kinds typed-first.
  CHANGELOG entry. CLAUDE.md "TC API conventions" gets the
  u32-shortcuts table fragment added.
- After **Plan 138 PR B** lands: named-match shortcuts work;
  golden-hex fixtures live under `crates/nlink/tests/fixtures/u32/`;
  Plan 140's CI runs them. Recipe `cgroup-classification.md`
  may now write `match cgroup ID` if Plan 133 PR C also lands.
- After **Plan 138 PR C** lands: hash-table grammar supported;
  filter side at 8 of 9.
- After **Plan 133 PR C** lands: `BasicFilter::parse_params` +
  `bins/tc/src/commands/filter.rs` known-kinds list grows
  `basic` to 9 of 9. The bin's `filter_builder` import can drop
  its `#[allow(deprecated)]` (the only legacy callers remaining
  are in the `format_protocol` / `parse_protocol` wrappers; those
  stay until Phase 4). Recipe `cgroup-classification.md` lands as
  Plan 135 PR B item 7-of-7-pending-cgroup; **Plan 135 PR B
  status bumps to 7/7 once both Plan 133 PR C AND Plan 141 land.**
- **Plan 137 integration tests** ride along here — both `--apply`
  runners' assertions lift into `#[tokio::test]` functions
  wrapped in `LabNamespace`, gated by Plan 140's
  `require_root!` + `require_module!`.

**End-of-Phase-1 metrics**:
- 9 of 9 typed filter kinds dispatched.
- 0 of 4 deprecated `tc::builders::*` modules deleted (still
  needed for Phase 3 prerequisites).
- Plan 137 integration tests passing in CI on every push.

### Phase 2 — XFRM write-path (Plan 141)

**Plan 141 details**: see `141-xfrm-write-path-plan.md`.

**Deliverables** in scope:
- After Plan 141 PR A: `Connection<Xfrm>::add_sa` + cousins.
- After Plan 141 PR B: `Connection<Xfrm>::add_sp` + cousins.
- After Plan 141 PR C: `docs/recipes/xfrm-ipsec-tunnel.md`,
  `examples/xfrm/ipsec_monitor.rs --apply`, **Plan 135 PR B
  bumps to 7/7** (assuming Phase 1's `cgroup-classification.md`
  has also landed).

**Doc updates** layered on Plan 141:
- CLAUDE.md gains a "**XFRM write-path**" section (mirror of
  the existing "Connection tracking" section style — typed
  builder example, `--apply` example pointer, recipe pointer).
- CHANGELOG entry per PR.

### Phase 3 — Action API (Plan 139 PR A + PR B)

**Plan 139 details**: see `139-typed-standalone-action-crud-plan.md`.

**Deliverables** in scope:
- Plan 139 PR A: typed `Connection<Route>::{add,del,get,dump}_action`.
  Required prerequisite: a `send_request_typed` variant on
  `Connection<P>` that captures the response payload (currently
  `send_ack` discards it). This new method is small (~30 LOC) but
  needs a unit test.
- Plan 139 PR B: `parse_params` on every typed action kind
  (~14 kinds, batched into 2-3 sub-PRs the same way slices 8-14
  split the qdisc/filter parsers). After this lands, the bin's
  action subcommand can dispatch typed.

**Doc updates** layered on Plan 139:
- CLAUDE.md: action-attachment vs standalone-action distinction
  added to the TC section.
- CHANGELOG entry per PR / sub-PR.

### Phase 4 — LEGACY DELETION (Plan 139 PR C)

**This is the milestone PR.** All previous phases are
prerequisites; this PR is what makes 0.15.0 a "zero-legacy"
release.

**Deliverables**:

1. `bins/tc/src/commands/action.rs` migrated to the typed
   dispatch shape (mirror of the qdisc and filter dispatch).
   `#[allow(deprecated)]` on the `impl ActionCmd` block deleted.
2. `bins/tc/src/commands/{class,qdisc,filter}.rs` `clap`
   conversion: `parent: String` → `parent: TcHandle` via
   `#[arg(value_parser = clap::value_parser!(TcHandle))]`.
   Same for `classid` / `handle`. `prio: Option<u16>` →
   `prio: Option<FilterPriority>`. The `parse_handles`
   helpers go away because clap does the work at parse time.
3. **Source tree deletion**:
   - `crates/nlink/src/tc/builders/{mod,class,qdisc,filter,action}.rs`
   - `crates/nlink/src/tc/options/{cake,codel,fq_codel,fq,htb,netem,prio,sfq,tbf}.rs`
     (verify each via `cargo machete` + a workspace grep that
     no in-tree code references them)
   - Any `tc::handle::parse_handle` etc. that's unreferenced
     after the deletion
4. CHANGELOG entry that **calls out the breaking removal
   explicitly** and includes a migration table:

   ```text
   ## [0.15.0] — Breaking removal of `tc::builders::*`

   The `nlink::tc::builders` and `nlink::tc::options` modules,
   deprecated since 0.14.0, are removed in 0.15.0.

   Migration table:

   | Removed | Replacement |
   |---|---|
   | `nlink::tc::builders::class::add(conn, dev, parent, classid, kind, params)` | `conn.add_class_config(dev, parent, classid, FooClassConfig::parse_params(&params)?)` |
   | `nlink::tc::builders::qdisc::add(conn, dev, parent, handle, kind, params)` | `conn.add_qdisc_full(dev, parent, handle, FooQdiscConfig::parse_params(&params)?)` |
   | `nlink::tc::builders::filter::add(...)` | `conn.add_filter_full(...)` + typed FilterConfig |
   | `nlink::tc::builders::action::add(...)` | `conn.add_action(...)` + typed ActionConfig |
   ```

5. CLAUDE.md cleanup: any remaining mention of `tc::builders` or
   the legacy parser pattern is removed. The "TC API conventions"
   section gains a closing paragraph noting that the legacy
   surface has been removed in 0.15.0 and pointing at the
   migration table.
6. The `tc::builders` deprecation note in 0.14.0's CHANGELOG is
   left untouched (historical record), but a forward-pointer
   `### Removed in 0.15.0 — see [0.15.0] entry` is added.
7. **Verification gates** that must pass before merge:
   - `cargo clippy --workspace --all-targets -- --deny warnings`
     clean (no deprecation warnings to allow because there are
     no deprecated items left).
   - `cargo machete` clean (no orphan deps from the deletion).
   - `grep -r "tc::builders" crates/ bins/ examples/ docs/`
     returns empty.
   - `grep -r "#\[allow(deprecated)\]" bins/tc/` returns empty.
   - `grep -r "#\[deprecated" crates/nlink/src/tc/` returns empty.
8. After this PR lands, **cut 0.15.0**.

---

## 6. Acceptance criteria for "zero-legacy"

A PR claiming to close Phase 4 must satisfy **every** item:

- [ ] `crates/nlink/src/tc/builders/` directory does not exist
- [ ] `crates/nlink/src/tc/options/` directory does not exist
- [ ] `bins/tc/src/commands/{class,qdisc,filter,action}.rs`
      contains no `#[allow(deprecated)]` directives
- [ ] No `use nlink::tc::builders::` anywhere in the workspace
- [ ] No `nlink::tc::options::` references anywhere in the
      workspace
- [ ] `grep -rn "tc::handle::parse_handle" crates/ bins/` is empty
      (the legacy handle parser was an internal detail)
- [ ] `cargo clippy --workspace --all-targets -- --deny warnings`
      passes
- [ ] `cargo machete` reports no new unused dependencies
- [ ] `cargo test -p nlink --lib` passes (≥593 tests, including
      the legacy-parser tests that get *deleted* with their
      source files — count drops by however many were exclusively
      in `tc::options::*::tests`, which audit shows is roughly 0
      because the legacy code was thinly tested)
- [ ] `cargo test -p nlink-tc` passes (35 tests stay; tests for
      legacy paths are removed if they exist)
- [ ] `bins/tc` interactive smoke: `tc qdisc add dummy0 --parent
      root --handle 1: htb default 10` succeeds (or fails at
      interface-not-found, same as today). One smoke test per bin
      subcommand verb (add / del / change / replace / show).
- [ ] CHANGELOG entry under `## [0.15.0]` documents the breaking
      removal with a migration table.
- [ ] CLAUDE.md is clean: no mention of `tc::builders` or
      `tc::options` outside historical-context paragraphs.
- [ ] Roadmap `128b-roadmap-overview.md` updated: this plan
      (142) and Plans 138/139/140/141 + Plan 133 PR C move from
      "Active plans" to "Shipped & ready to archive".

---

## 7. Documentation deliverables (binding)

Each phase PR must update the following — **not deferred to a
follow-up commit**:

### CHANGELOG.md

- Entry under `## [Unreleased]` (becomes `## [0.15.0]` at release
  cut) with a per-phase subsection. Pattern matches the 0.14.0
  typed-units-rollout entries.
- Phase 4's entry **must** include the migration table from §5.

### CLAUDE.md

- **Phase 0**: new section "TC API conventions" (between the
  existing "Type-safe TC handles" and "Key Patterns" sections)
  documenting the four patterns from §2.2 + §2.3 + §2.4 + §2.5
  of this plan, condensed to ~80 lines.
- **Phase 2**: new section "XFRM write-path" (under the existing
  "Connection tracking (conntrack) via Netfilter" section,
  before the "Conntrack mutation" subsection).
- **Phase 3**: action subsection added to the existing
  "Adding TC actions" section, distinguishing
  filter-attached vs standalone shared actions.
- **Phase 4**: cleanup — strip legacy mentions, add a
  closing paragraph to the "TC API conventions" section noting
  the removal.

### Recipes

- **Phase 1**: `docs/recipes/cgroup-classification.md` (new,
  Plan 135 PR B item) once Plan 133 PR C lands.
- **Phase 2**: `docs/recipes/xfrm-ipsec-tunnel.md` (new, Plan
  135 PR B item) once Plan 141 PR C lands. Plan 135 PR B status
  bumps to 7/7 here.
- Recipe README index updated for both, with the deferred items
  removed from the "Wanted" list.

### Plan files (this plan + cited plans)

- Each cited plan (133, 138, 139, 140, 141) gets a status-header
  forward-pointer at the start: "Subsumed under Plan 142 — this
  document is the phase-level detail for Plan 142 Phase X."
- Plan 142 itself gets archived after Phase 4 lands; status moves
  to "Shipped".

---

## 8. Trait formalization detail (the only new API design in this plan)

This plan ships exactly one new trait. The design:

```rust
// crates/nlink/src/netlink/parse.rs (new file)

/// Sealed module preventing third-party impls.
mod private {
    pub trait Sealed {}
}

/// Parse a tc(8)-style token slice into a typed config.
///
/// Implementations return `Err(Error::InvalidMessage(...))` for
/// unknown tokens, missing values, and unparseable inner values.
/// Silent skipping is a bug.
///
/// See per-config doc-strings for the recognised token sets.
///
/// # Example
///
/// ```ignore
/// use nlink::netlink::tc::HtbQdiscConfig;
/// use nlink::netlink::parse::ParseParams;
///
/// let cfg = HtbQdiscConfig::parse_params(&["default", "10"])?;
/// ```
pub trait ParseParams: Sized + private::Sealed {
    fn parse_params(params: &[&str]) -> Result<Self>;
}

// Sealing impls — one per shipped typed config.
impl private::Sealed for crate::netlink::tc::HtbQdiscConfig {}
// ... 24 more, all similar.

// Trait impls — forward to the existing inherent method.
impl ParseParams for crate::netlink::tc::HtbQdiscConfig {
    fn parse_params(params: &[&str]) -> Result<Self> {
        Self::parse_params(params)  // calls the inherent method
    }
}
// ... 24 more.
```

**Why sealed**: the `parse_params` contract is intentionally
narrow (kind-name-prefixed errors, strict rejections). Allowing
third-party impls invites drift. Downstream consumers who want
their own DSL implement their own trait.

**Why both inherent + trait**: existing callers of
`HtbQdiscConfig::parse_params(...)` (every test, every recipe)
keep working because the inherent method stays. The trait is for
generic dispatch (`fn foo<C: ParseParams>(params: &[&str]) ->
Result<C>`), which is what the bin's `dispatch!` macro can bind
to in 0.15.0+.

**Re-export location**: `nlink::netlink::parse::ParseParams` plus
`pub use netlink::parse::ParseParams as ParseParams` in
`crates/nlink/src/lib.rs` for top-level convenience.

This is the only new public API surface in this plan beyond what
the cited sub-plans already specify.

---

## 9. Metrics

Targets at end of Phase 4 (the 0.15.0 release-cut commit):

| Metric | 0.14.0 | 0.15.0 target |
|---|---|---|
| `parse_params` methods on typed configs | 25 | ≥39 (+14 action kinds) |
| Lib unit tests (`cargo test -p nlink --lib`) | 593 | ≥700 |
| Bin tests (`cargo test -p nlink-tc`) | 35 | ≥40 |
| `bins/tc` filter kinds dispatched typed | 7 of 9 | 9 of 9 |
| `bins/tc` qdisc kinds dispatched typed | 18 of 18 | 18 of 18 |
| `bins/tc` action subcommand on legacy path | 100% | 0% |
| `#[allow(deprecated)]` directives in `bins/tc/` | 4 | 0 |
| LOC in `crates/nlink/src/tc/{builders,options}/` | ~3580 | 0 |
| `cargo machete` clean | yes | yes |
| Workspace clippy `--deny warnings` clean | yes | yes |
| CI integration tests run on every push | no | yes |
| Recipes shipped | 6 of 7 (Plan 135 PR B) | 8 of 7 (cgroup + xfrm added; numerator > 7 because index renumbers) |

---

## 10. Risks

| Risk | Likelihood | Mitigation |
|---|---|---|
| Phase 4's atomic deletion PR is too large to review | Medium | Split into a "preparation" sub-PR (clap conversion + bin migration) and the deletion sub-PR proper. Both must land together to keep the tree valid (CI gate enforces). |
| `ParseParams` trait formalization breaks downstream consumers using inherent `parse_params` | Low | Inherent methods stay; trait is additive. Only effect: a generic call site that *already* assumed the inherent method now has a typed contract. |
| Plan 139 PR B's 14 per-action parsers take longer than estimated | Medium | Sub-PRs the same way slices 8–14 did. Each action kind is small (~50-100 LOC). |
| `send_request_typed` (Phase 3 prerequisite) destabilises existing send_ack callers | Low | New method, additive; existing `send_ack` untouched. |
| Plan 140's GHA runner kernel doesn't surface bugs that the maintainer's Linux 6.19 does | Medium | Both Linux 5.x (GHA-default LTS) and Linux 6.19 (`--apply` runners on maintainer's machine) provide coverage; the `--apply` runners stay as the local validation channel. |
| 0.15.0 release cut accidentally leaves a `#[allow(deprecated)]` somewhere in `bins/` | Medium | The Phase 4 acceptance criteria checklist is the gate; CI grep step must pass before merge. |
| Plan 141 (XFRM) interferes with maintainer's IPsec setup during interactive validation | Low | All Plan 141 `--apply` runs use `LabNamespace` isolation; never touches host XFRM tables. |

---

## 11. Open questions

1. **`build()` validation revisit.** §2.1 affirms the
   transparent-`build()` choice. Reviewers may want `build()` to
   validate (e.g. `HtbClassConfig::new(rate).build()` ensuring
   rate > 0). Decision deferred — this plan honours the existing
   choice. If a reviewer wants change, open a separate plan.
2. **Re-export location for `ParseParams`.** §8 picks
   `nlink::netlink::parse::ParseParams` + `nlink::ParseParams` at
   crate root. Could equally live at `nlink::netlink::ParseParams`.
   Final placement decided during PR review.
3. **Other-bins typed-units rollout.** Backlog row mentions an
   audit of `bins/{ip,ss,nft,wifi,devlink,bridge,wg,ethtool,diag,
   config}`. This plan declares the audit out of scope; if the
   audit turns up real work and the per-bin plan is small
   enough, it may slot into 0.15.0. Otherwise 0.16.0.
4. **`tc::handle::parse_handle` removal.** §6 acceptance says it
   goes away with Phase 4. Verify no public re-export at the
   crate root before deletion; if there is one, the removal is
   itself a breaking change that needs CHANGELOG attention.

---

## 12. After 0.15.0 cuts

- `mqprio` / `taprio` `queues <count@offset>` pair grammar lands
  if/when a user hits the deferred error.
- Plan 137 PRs C/D/E (`ct_expect`, nfqueue, nflog) ship demand-
  gated, each as their own minor release.
- Other-bin typed-units rollout (per-bin audits → per-bin plans).
- 1.0.0 considered when downstream consumption validates the
  typed surface in production. The zero-legacy state shipped here
  is a prerequisite, not a release trigger.

End of plan.
