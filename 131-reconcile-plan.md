---
to: nlink maintainers
from: nlink maintainers
subject: Reconcile pattern for ratelimit and impair recipes
target version: 0.13.0 / 1.0
date: 2026-04-19
status: draft, post-verification (2026-04-19) — QdiscOptions coverage gap noted
verified: codebase audit complete
---

# Reconcile Pattern for Recipe Helpers

## 0. Summary

`PerHostLimiter::apply()` and `PerPeerImpairer::apply()` today
**delete the device's root qdisc and re-create the entire tree on
every call**. Each `apply()` is a brief but real packet-drop window.
For consumers reapplying on a reconcile loop (k8s operators, lab
controllers), this cost compounds: a config-tick every 10s means
a hiccup every 10s, even if nothing has changed.

Add a non-destructive `reconcile()` method that:

1. Dumps the current root tree on the target interface.
2. Diffs against the desired tree the helper would build.
3. Emits the minimum set of `change_*`/`replace_*`/`add_*`/`del_*`
   operations to converge.
4. Returns a structured report of what changed.

`apply()` keeps its destructive contract (clean slate, used for
"start from scratch") but `reconcile()` becomes the primary verb for
long-running consumers.

The existing `nlink::netlink::config` module already does
diff-and-apply for declarative `NetworkConfig` graphs (1271 LOC across
diff.rs/apply.rs/types.rs). We don't reinvent that — we reuse its
diff primitives where they fit and add per-recipe diff logic where
they don't.

This is mostly **additive**: `apply()` keeps working as it does today.
The BC-breakable part is making `reconcile()` the documented default,
deprecating reapply-via-`apply()` in long-running loops.

---

## 1. Goals & non-goals

### Goals

1. `PerHostLimiter::reconcile(&conn) -> Result<ReconcileReport>` and
   `PerPeerImpairer::reconcile(&conn) -> Result<ReconcileReport>` —
   non-destructive convergence to the desired tree.
2. Idempotent: calling `reconcile()` twice in a row with no external
   changes makes zero kernel calls on the second invocation
   (reported as `ReconcileReport { changes: 0 }`).
3. Minimal change set under realistic edits:
   - Add a peer rule → one `add_class` + one `add_qdisc_full` (netem
     leaf) + one `add_filter` (3 calls).
   - Modify a peer's netem (delay, loss, etc.) → one `change_qdisc`
     on the leaf only (1 call).
   - Modify a peer's rate cap → one `change_class` (1 call).
   - Remove a peer rule → one `del_filter` + one `del_class` (the
     leaf qdisc is implicitly removed by class deletion) (2 calls).
   - Reorder peers (no semantic change) → zero calls.
4. Detect drift: report when the live tree contains classes/filters
   the helper didn't install and warn (don't mutate them).
5. Dry-run mode: `reconcile_dry_run(&conn)` returns the same
   `ReconcileReport` without making kernel calls.

### Non-goals

1. Reconciling unrelated state (interface state, addresses, routes).
   Stays in `NetworkConfig`.
2. Three-way merge (desired/current/last-applied). Two-way is enough
   for v0.13; revisit if drift detection proves insufficient.
3. Cross-interface reconcile. `reconcile` operates on one helper
   targeting one interface.
4. Generic reconcile framework. Each recipe owns its diff logic;
   shared primitives factored only after a third recipe lands.
5. Concurrent reconcile guards. Caller's responsibility (use a
   `tokio::sync::Mutex` per device).

---

## 2. Use case

```rust
loop {
    let desired = build_impairer_from_config(&latest_config);
    let report = desired.reconcile(&conn).await?;
    if report.changes_made > 0 {
        info!(
            "impair: {} added, {} modified, {} removed",
            report.rules_added, report.rules_modified, report.rules_removed,
        );
    }
    tokio::time::sleep(Duration::from_secs(10)).await;
}
```

Today this loop has a packet-drop hiccup every 10s. With `reconcile`,
zero hiccups when the config is stable; minimal-impact updates only
when something actually changed.

---

## 3. Design

### 3.1. Where the diff logic lives

Each helper (`PerHostLimiter`, `PerPeerImpairer`) owns its own
diff. The two helpers' trees are similar but not identical
(PerHostLimiter has `fq_codel` leaves; PerPeerImpairer has `netem`
leaves), and the natural diff key differs (HostMatch vs PeerMatch).

Shared internal scaffolding lives in a new module
`nlink::netlink::tc_recipe_internals` (private, `pub(crate)`):

```rust
pub(crate) struct LiveTree {
    pub root_kind: Option<&'static str>,           // "htb"
    pub root_default_class: Option<TcHandle>,
    pub classes: BTreeMap<TcHandle, ClassSnapshot>,
    pub filters: BTreeMap<(TcHandle, FilterPriority), FilterSnapshot>,
    pub leaf_qdiscs: BTreeMap<TcHandle /* parent */, LeafSnapshot>,
}

pub(crate) struct ClassSnapshot { kind: &'static str, rate: Rate, ceil: Rate }
pub(crate) struct LeafSnapshot { kind: &'static str, raw_options: Vec<u8> }
pub(crate) struct FilterSnapshot { kind: &'static str, classid: TcHandle, ... }

pub(crate) async fn dump_live_tree(
    conn: &Connection<Route>, ifindex: u32,
) -> Result<LiveTree>;

pub(crate) fn classes_equal(a: &ClassSnapshot, b: &ClassSnapshot) -> bool;
pub(crate) fn netem_equal(a: &NetemConfig, b: &[u8]) -> bool;  // parses live blob
```

This is a thin shared utility; each recipe's reconcile does its own
matching.

### 3.2. Diff strategy

Identify "what" each managed object is by **handle**, not by content:

- The helper deterministically assigns `TcHandle::new(1, i+2)` to the
  i-th rule's class, and `TcHandle::new(i+10, 0)` to its leaf qdisc.
- Filter handles are kernel-assigned, but the helper deterministically
  uses `FilterPriority::recipe(i)` for the i-th rule.

So given a desired `PerPeerImpairer` and a dumped `LiveTree`, we can:

1. Map each desired rule `i` → expected (classid, leaf_handle, prio).
2. Look up that classid in the live tree.
3. If absent → add. If present but contents differ → modify. If a
   live class is in our handle range (`1:2..1:N+2`) but no desired
   rule maps to it → remove.

### 3.3. Diff outcomes per object

For each object, decide one of: `Identical | NeedsModify | Missing | Stale`.

| Object | "Identical" check | "NeedsModify" action | "Missing" action |
|---|---|---|---|
| Root HTB qdisc | `kind == "htb"` & `default_class == expected` | `replace_qdisc` (this is rare; usually reset everything if root differs) | `add_qdisc_full(parent=ROOT, handle=1:, ...)` |
| Parent class 1:1 | `rate == expected_total` | `change_class_config` | `add_class_config` |
| Per-rule class 1:N | `rate == expected_rate` & `ceil == expected_ceil` | `change_class_config` (no del-and-readd) | `add_class_config` |
| Per-rule leaf qdisc | `kind == "netem"` & options bytes match | `change_qdisc_full` (in-place) | `add_qdisc_full` |
| Per-rule flower filter | match keys identical | `del_filter` + `add_filter_full` (no in-place change for filter content) | `add_filter_full` |
| Default class 1:N+2 | same as per-rule | `change_class_config` | `add_class_config` |
| Default leaf qdisc | same as per-rule leaf | `change_qdisc_full` or `add_qdisc_full` | `del_qdisc_full` if no longer wanted |

**"Stale" handling**: if the live tree contains classes/filters in our
handle range that no desired rule corresponds to, **remove them**.
If outside our range (operator-installed), **leave alone** but report
in `ReconcileReport.unmanaged`.

### 3.4. The "compare netem options" hard case

`change_qdisc_full` works for in-place netem updates. But to detect
"does the live netem already match what we want?", we need to parse
the kernel's netem option blob and compare against our `NetemConfig`.

**Verified state of `QdiscOptions`** (`tc_options.rs:34`): only **6
qdisc kinds** parse currently — `FqCodel`, `Htb`, `Tbf`, `Netem`,
`Prio`, `Sfq`. Anything else hits `QdiscOptions::Unknown(Vec<u8>)`.

For our recipes:
- `PerPeerImpairer` uses HTB (root + parent + per-rule classes) +
  netem leaves: **fully covered**.
- `PerHostLimiter` uses HTB + fq_codel leaves: **fully covered**.

So both helpers can compare desired vs live without first extending
`QdiscOptions`. New recipes built on cake/fq_pie/hfsc/drr/qfq would
need their option parsers added to `QdiscOptions` first — flagged as
a precondition for any future recipe using those qdiscs.

`NetemOptions` already exposes the comparable accessors — verified in
`tc_options.rs`:

- `delay() -> Option<Duration>`
- `jitter() -> Option<Duration>`
- `loss() -> Option<f64>`         ← `Some(p)` when set, `None` otherwise
- `duplicate() -> Option<f64>`
- `loss_correlation() / duplicate_correlation()`
- Plus raw `delay_ns()`, `jitter_ns()`, `loss_percent()`, `duplicate_percent()`,
  `loss_model()` for richer queries.

Use:

```rust
fn netem_equal(desired: &NetemConfig, live: &TcMessage) -> bool {
    let Some(QdiscOptions::Netem(live_opts)) = live.options() else { return false; };
    desired.delay == live_opts.delay()
        && desired.jitter == live_opts.jitter()
        && desired.loss == live_opts.loss().unwrap_or(0.0)
        && desired.duplicate == live_opts.duplicate().unwrap_or(0.0)
        && desired.corrupt == live_opts.corrupt().unwrap_or(0.0)
        && desired.reorder == live_opts.reorder().unwrap_or(0.0)
        && desired.gap == live_opts.gap
        && desired.rate == live_opts.rate_bps()
        && desired.limit == live_opts.limit
        // ...all the other netem fields
}
```

Tedious but straightforward. Encapsulate as `NetemConfig::matches(&TcMessage)`.

For HTB classes: today's `QdiscOptions::Htb` covers HTB **qdisc**
options (`r2q`, default class). Class-side rate/ceil parsing is not
yet exposed in `QdiscOptions` (since classes aren't qdiscs). **Add a
`parse_class_options() -> Option<ClassOptions>` to
`tc_options.rs`** as part of this work — required for HTB class
rate/ceil comparison.

For flower filters: there's no `parse_filter_options` today. We need
either:
- Add `parse_filter_options() -> Option<FilterOptions>` (matches the
  pattern of qdisc/class), OR
- Compare filter outcomes by handle + classid only, treating the match
  keys as opaque (the helper deterministically generates filter keys
  from `PeerMatch`, so if the handle and classid match, the key is
  trivially the same).

Recommendation: option 2 for v0.13. Filter keys are
helper-deterministic; full filter-options parsing is a deeper rabbit
hole.

### 3.5. The change emission engine

```rust
pub(crate) struct PlannedChanges {
    pub root_qdisc: ChangeOp,
    pub classes: Vec<(TcHandle, ChangeOp)>,
    pub leaf_qdiscs: Vec<(TcHandle, ChangeOp)>,
    pub filters: Vec<(FilterPriority, ChangeOp)>,
}

pub(crate) enum ChangeOp { None, Add, Modify, Delete }

impl PlannedChanges {
    pub fn is_empty(&self) -> bool { /* all None */ }

    pub async fn execute(&self, conn: &Connection<Route>, ifindex: u32, /* recipe state */) -> Result<usize> {
        // Order matters:
        // 1. Add new classes (need parent first)
        // 2. Add new leaf qdiscs (need class first)
        // 3. Add new filters (need classid to exist)
        // 4. Modify existing classes/leaves/filters
        // 5. Delete removed filters first (else they reference doomed classes)
        // 6. Delete removed leaf qdiscs
        // 7. Delete removed classes
        // Return number of kernel calls made.
    }
}
```

Filter deletes go before class deletes (filter refers to classid).
Adds go in dependency order (class → leaf → filter).

### 3.6. Public API on the recipe helpers

```rust
impl PerPeerImpairer {
    /// Apply destructively: delete root qdisc, then build the tree fresh.
    /// Brief packet-drop window. Use for "start clean".
    pub async fn apply(&self, conn: &Connection<Route>) -> Result<()>;

    /// Reconcile non-destructively: diff against the live tree and emit
    /// minimum changes. Idempotent. Preferred for reconcile loops.
    pub async fn reconcile(&self, conn: &Connection<Route>) -> Result<ReconcileReport>;

    /// Compute what `reconcile` would do, without making kernel calls.
    pub async fn reconcile_dry_run(&self, conn: &Connection<Route>) -> Result<ReconcileReport>;

    pub async fn clear(&self, conn: &Connection<Route>) -> Result<()>;
}

#[derive(Debug, Clone)]
pub struct ReconcileReport {
    pub changes_made: usize,
    pub rules_added: usize,
    pub rules_modified: usize,
    pub rules_removed: usize,
    pub default_modified: bool,
    pub root_modified: bool,
    /// Objects in our handle range that didn't exist in the desired
    /// tree and were removed.
    pub stale_removed: Vec<StaleObject>,
    /// Objects outside our handle range that we left alone.
    pub unmanaged: Vec<UnmanagedObject>,
    /// Whether this was a dry-run (no kernel calls made).
    pub dry_run: bool,
}

#[derive(Debug, Clone)]
pub struct StaleObject { pub kind: &'static str, pub handle: TcHandle }
#[derive(Debug, Clone)]
pub struct UnmanagedObject { pub kind: &'static str, pub handle: TcHandle, pub priority: Option<FilterPriority> }
```

Same for `PerHostLimiter`.

### 3.7. Behavior under "wrong root qdisc" — fall back to apply()

If the live tree's root qdisc isn't HTB (e.g., something else got
installed), `reconcile` cannot incrementally fix it. Two options:

A. Return an error and let caller decide. Conservative.
B. Auto-fall-back to `apply()` (full destructive rebuild). Pragmatic.

Recommendation: (A) by default; provide a `ReconcileOptions::
fallback_to_apply(true)` knob. Surprising auto-destruction is bad
default for a reconcile-loop verb. Caller can opt in.

```rust
pub struct ReconcileOptions {
    pub fallback_to_apply: bool,
    pub dry_run: bool,
}

pub async fn reconcile_with_options(
    &self, conn: &Connection<Route>, opts: ReconcileOptions,
) -> Result<ReconcileReport>;
```

### 3.8. Interaction with `nlink::netlink::config`

The existing `NetworkConfig::diff()`/`apply()` does
declarative-config-style reconcile for whole network state. It tracks
qdiscs but at a much coarser grain (qdisc add/remove/replace, no
per-class/per-filter diffing).

After this work lands:

- `NetworkConfig` continues to handle the broad declarative state
  (links, addresses, routes, simple qdiscs).
- For per-peer rate-limiting / impairment, callers either:
  - Build a `PerPeerImpairer` and call `reconcile()` directly, or
  - Embed the impairer into a `NetworkConfig` via a new
    `NetworkConfig::impair(...)` method that adds a "managed by
    PerPeerImpairer" entry to the config and delegates reconcile to it.

The second path is a nice-to-have follow-up; not in scope for v0.13.

---

## 4. API summary

```rust
// crates/nlink/src/netlink/impair.rs
impl PerPeerImpairer {
    // existing
    pub async fn apply(&self, conn: &Connection<Route>) -> Result<()>;
    pub async fn clear(&self, conn: &Connection<Route>) -> Result<()>;
    // new
    pub async fn reconcile(&self, conn: &Connection<Route>) -> Result<ReconcileReport>;
    pub async fn reconcile_dry_run(&self, conn: &Connection<Route>) -> Result<ReconcileReport>;
    pub async fn reconcile_with_options(&self, conn: &Connection<Route>, opts: ReconcileOptions) -> Result<ReconcileReport>;
}

// same shape on PerHostLimiter

// crates/nlink/src/netlink/tc_recipe.rs (new public module — or keep
// these types under impair/ratelimit if we don't want a new module)
pub struct ReconcileReport { ... }
pub struct ReconcileOptions { ... }
pub struct StaleObject { ... }
pub struct UnmanagedObject { ... }
```

---

## 5. Files touched

| Path | Change | Approx LOC |
|---|---|---|
| `crates/nlink/src/netlink/tc_recipe.rs` | New: shared types (`ReconcileReport`, `ReconcileOptions`) | ~120 |
| `crates/nlink/src/netlink/tc_recipe_internals.rs` | New (`pub(crate)`): `LiveTree`, dump, equality helpers | ~350 |
| `crates/nlink/src/netlink/impair.rs` | Add `reconcile`, `reconcile_dry_run`, `reconcile_with_options` | ~250 |
| `crates/nlink/src/netlink/ratelimit.rs` | Same on `PerHostLimiter` | ~250 |
| `crates/nlink/src/netlink/tc_options.rs` | Extend netem/HTB option parsing for "matches" comparisons | ~150 |
| `crates/nlink/src/netlink/mod.rs` | `pub mod tc_recipe`, `mod tc_recipe_internals` | ~3 |
| `crates/nlink/src/lib.rs` | Re-export `ReconcileReport`, `ReconcileOptions` | ~3 |
| `crates/nlink/tests/integration/impair.rs` | Add reconcile tests (5 new) | ~250 |
| `crates/nlink/tests/integration/ratelimit.rs` | Same | ~250 |
| `crates/nlink/examples/impair/per_peer.rs` | Demo `reconcile` (extend `--apply` path) | ~50 |
| `docs/recipes/per-peer-impairment.md` | Document `reconcile` and when to use vs `apply` | ~50 |
| `CLAUDE.md` | Add reconcile pattern to recipe sections | ~30 |
| `CHANGELOG.md` | Entry | ~15 |

Total ~1750 LOC. Largest single chunk is the `tc_recipe_internals` dump
+ equality engine.

---

## 6. Tests

### 6.1. Unit tests (no root)

- `ReconcileReport::is_noop()` returns true when changes_made == 0
- `ReconcileOptions::default().dry_run == false`
- Diff math: given a `LiveTree` and a `PerPeerImpairer` config, the
  computed `PlannedChanges` matches the expected operation list.
  (Mock `LiveTree`; no kernel needed.)
- `NetemConfig::matches()` round-trip: serialize a config, parse it
  back via `tc_options::parse_qdisc_options`, assert
  `desired.matches(&parsed)`.

### 6.2. Integration tests (root)

For both `PerPeerImpairer` and `PerHostLimiter`:

- `test_reconcile_first_call_creates_tree`: empty interface → reconcile
  → tree exists, report.changes_made > 0.
- `test_reconcile_idempotent`: reconcile twice; second call
  changes_made == 0.
- `test_reconcile_add_rule`: deploy 2-rule config, reconcile;
  rebuild config with 3 rules, reconcile; assert exactly the new
  class/leaf/filter were added (compare class/filter count deltas).
- `test_reconcile_modify_netem`: deploy with delay 50ms, reconcile;
  rebuild with delay 100ms, reconcile; assert leaf qdisc was
  `change_qdisc`'d (not deleted+added).
- `test_reconcile_remove_rule`: deploy 3-rule, reconcile; rebuild
  with 2-rule, reconcile; assert one filter+class removed.
- `test_reconcile_drift_detection`: deploy via reconcile; install an
  unmanaged filter at priority 50 via raw `add_filter_full`;
  reconcile; assert report.unmanaged contains the filter.
- `test_reconcile_dry_run`: deploy nothing; call `reconcile_dry_run`
  with a 3-rule config; assert report says "would add 3 classes / 3
  leaves / 3 filters" but no actual qdiscs exist.
- `test_reconcile_wrong_root_kind_errors`: install a `prio` qdisc at
  root manually; `reconcile()` returns `Err` (default options).
- `test_reconcile_with_fallback_to_apply`: same setup, opts
  `fallback_to_apply(true)`; reconcile succeeds and the tree is
  HTB-rooted.

### 6.3. Property test (no root)

Generate random sequences of "config edits" (add/modify/remove peer
rules) on a mock `LiveTree`; assert that applying the planned changes
yields a tree shape equivalent to a fresh `apply`.

---

## 7. Documentation

### 7.1. `docs/recipes/per-peer-impairment.md`

Add an "Apply vs reconcile" subsection:

> - Use **`apply()`** for "set up from scratch" — typically once per
>   interface lifetime. Brief packet-drop window.
> - Use **`reconcile()`** for "make sure the tree matches my desired
>   state" — repeated calls are cheap when nothing changed, and
>   minimal-disruption when something did. Preferred for reconcile
>   loops.

### 7.2. `CLAUDE.md`

Add a small section under the recipe patterns showing the
reconcile-loop idiom.

### 7.3. CHANGELOG

```markdown
### Added

- `PerPeerImpairer::reconcile`, `PerHostLimiter::reconcile` —
  non-destructive convergence. Diffs the live TC tree against the
  desired one and emits minimum changes. Idempotent: zero kernel
  calls when nothing changed.
- `ReconcileReport` and `ReconcileOptions` (in `nlink::netlink::tc_recipe`)
  — structured outcome and dry-run/fallback knobs.
- Companion `reconcile_dry_run` for previewing changes without
  kernel calls.
```

No BC break here — `apply()` keeps its destructive contract; recommend
new code use `reconcile()` for repeated calls.

---

## 8. Open questions

1. **Public diff types.** Should `PlannedChanges` be exposed publicly
   so callers can inspect "what reconcile would do" structurally?
   Or just the summary `ReconcileReport`? Recommendation: just the
   report — exposing the typed change list invites callers to mutate
   and re-execute, which bypasses the helper.
2. **Filter modification path.** `change_filter` exists but doesn't
   work for all filter kinds reliably. We default to "delete +
   re-add" for filter modifications. Acceptable cost? Yes — a
   filter swap is sub-millisecond; the alternative is encoding-format
   inspection which is fragile.
3. **NetworkConfig integration.** Add `NetworkConfig::impair(name,
   PerPeerImpairer)`? Out of scope for v0.13 (parking lot for v0.14).
4. **Concurrent reconcile of the same interface.** Caller must
   guard. Document. Should we add a per-`Connection` mutex? No —
   too coarse; consumers know their concurrency model better than we do.
5. **Reconcile against an interface in a different namespace than
   the helper expected.** Today, the helper holds an `InterfaceRef`
   and resolves at call time. Reconcile follows the same model.
   No change.

---

## 9. Phasing

Single PR. ~1750 LOC. No prerequisites — works on top of the
existing `apply` infrastructure.

Order of work:

1. Build `LiveTree` dumper (`tc_recipe_internals`) with unit tests
   against mock TcMessages.
2. Build `NetemConfig::matches()` and `HtbClassConfig::matches()` —
   the comparison functions that drive the diff.
3. Build `PerPeerImpairer::reconcile` — the larger of the two
   helpers, gets first-pass review.
4. Mirror to `PerHostLimiter::reconcile`.
5. Integration tests (both helpers).
6. Docs + CHANGELOG.

---

## 10. Risk register

| Risk | Likelihood | Mitigation |
|---|---|---|
| Equality functions miss a netem field, false "matches" | Medium | Property test: serialize → parse → assert matches; covers the round-trip |
| Filter delete-then-readd causes a brief miss-window | Low | Document; sub-ms in practice; acceptable for the recipe scope |
| Drift detection misses unmanaged filters with handle in our range | Low | We use deterministic ranges; collision is the operator's fault. Document the convention. |
| Reconcile is significantly slower than apply for large rule sets | Low | Benchmark; reconcile of N=100 unchanged rules = 1 dump (3 list calls). Should be faster than apply (3*N writes). |
| Wrong-root-kind handling surprises caller | Low | Default = error; fallback = opt-in. Document. |

---

## 11. What we are NOT doing

- **No three-way merge.** Two-way (desired vs live) is enough.
- **No NetworkConfig integration.** Park for v0.14.
- **No generic reconcile framework.** Each recipe owns its diff.
- **No concurrent-reconcile guards.** Caller's job.
- **No automatic root-qdisc-rebuild.** Opt-in via `fallback_to_apply`.

---

## 12. Definition of done

- [ ] `PerPeerImpairer::reconcile` exists and passes integration tests
- [ ] `PerHostLimiter::reconcile` exists and passes integration tests
- [ ] `ReconcileReport`, `ReconcileOptions`, drift detection types
      exist in `nlink::netlink::tc_recipe` (re-exported at crate root)
- [ ] Idempotent property holds: reconcile twice → 0 kernel calls
- [ ] Drift detection works: unmanaged filters reported, not touched
- [ ] Dry-run path tested
- [ ] Recipe doc updated with apply-vs-reconcile guidance
- [ ] CLAUDE.md shows a reconcile-loop snippet
- [ ] CHANGELOG entry written

---

End of plan.
