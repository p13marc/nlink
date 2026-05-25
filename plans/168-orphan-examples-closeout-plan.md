---
to: nlink maintainers
from: 0.16 post-audit verification pass (2026-05-25)
subject: Plan 160 orphan-catalog closeout — fix-or-delete all 9 entries
status: landed (2026-05-25 pre-cut window) — all 3 phases shipped in a single execution pass; Plan 160 allowlist deleted; 11 example files net change (5 fixed + registered, 3 deleted, 2 new files [1 rewrite + 1 consolidation]); 0 orphans remaining
target version: 0.16.0 (Phases 1 + 2) + 0.16.0 or 0.17.0 (Phase 3, maintainer judgement)
parent: 160-example-registry-audit.md
source: triage analysis of Plan 160's catalog after the 0.16 readiness audit (cost-vs-value grid)
created: 2026-05-25
---

# Plan 168 — orphan-example catalog closeout

## 0. Live status

| Phase | Files | Status |
|---|---|---|
| 1. Trivial fixes (R+F orphans) | `bridge/vlan.rs`, `route/mpls.rs`, `route/nexthop.rs`, `route/srv6.rs` | 🟢 shipped |
| 2. Diagnostics consolidation | `diagnostics/{bottleneck,connectivity,scan}.rs` → `diagnostics/health_check.rs` | 🟢 shipped |
| 3. Substantive rewrites | `bridge/fdb.rs` (in-place fix, less work than planned), `config/declarative.rs` (full rewrite) | 🟢 shipped |

After Phase 3, `scripts/audit-example-registration.allowlist`
is empty → delete the file itself per Plan 160 §"Acceptance
criteria" line 176.

## 1. Why this plan exists

Plan 160 (2026-05-24) catalogued **9 example files** under
`crates/nlink/examples/` that exist on disk but aren't registered
as `[[example]]` entries in `crates/nlink/Cargo.toml`, so cargo
silently skips them in `--all-targets` builds. The catalog
documented per-file failure modes and explicitly deferred the
"fix vs. delete" judgement to the maintainer.

The post-audit verification pass (2026-05-25) layered a
cost-vs-value grid on top of the catalog and recommended three
batches with very different effort profiles. This plan turns
those batches into actionable phases with per-file fix sketches.

**Outcomes**:

- Allowlist shrinks 9 → 0.
- Plan 160 closes formally.
- Every subsystem with a buildable example *has* one (no demo
  gaps for MPLS / SRv6 / nexthops / FDB / declarative
  NetworkConfig / diagnostics).
- The `scripts/audit-example-registration.sh` CI gate's
  failure shape (catches NEW orphans) is the only ongoing
  enforcement; the historical batch is closed.

## 2. Phase 1 — trivial fixes (R+F orphans)

Four files, all "right-once-drifted-on-rename" plus
raw-string-format-bug variants. Per Plan 160 §"Verdict per
file" the (R+F) ones are "trivial mechanical edits". The
(P+F) on `srv6.rs` is also mechanical because the only
phantom is `Srv6LocalRoute::table` referenced from a single
print arm — drop the print line, file works.

### 2.1 `examples/bridge/vlan.rs` (R+F)

| Edit | Line(s) | Change |
|---|---|---|
| 1 rename | search/replace | `.link_kind()` → `.kind()` (single occurrence per Plan 160) |
| 7 raw-string format bugs | scan | `println!(r#"...{}..."#)` → `println!("{}", r#"..."#)` or split the body |

**Register** in `crates/nlink/Cargo.toml`:

```toml
[[example]]
name = "bridge_vlan"
path = "examples/bridge/vlan.rs"
```

**Allowlist** — drop `examples/bridge/vlan.rs # R+F` line.

### 2.2 `examples/route/mpls.rs` (R+F)

| Edit | Line(s) | Change |
|---|---|---|
| 1 rename | scan | `route.gateway` → `route.via` (verified: `MplsRoute.via: Option<IpAddr>` exists at `mpls.rs:325`) |
| 9 raw-string format bugs | scan | same shape as 2.1 |

**Register** as `mpls`, **drop** allowlist line.

### 2.3 `examples/route/nexthop.rs` (R+F)

| Edit | Line(s) | Change |
|---|---|---|
| 1 rename | scan | `nh.is_blackhole()` → `nh.blackhole` (field, not method) |
| 8 raw-string format bugs | scan | same shape |

**Register** as `nexthop`, **drop** allowlist line.

### 2.4 `examples/route/srv6.rs` (P+F)

| Edit | Line(s) | Change |
|---|---|---|
| Phantom drop | scan for `route.table` arm | Delete the single `route.table` access. Surrounding print arms (`sid`, `prefix_len`, `action`, `oif`, `iif`, `protocol`) all exist on `Srv6LocalRoute` (per Plan 160 verified). |
| Raw-string format bugs | scan | same shape (count not given in catalog; expect 5-10) |

**Register** as `srv6`, **drop** allowlist line.

### 2.5 Verification

After all 4 fixes:

```bash
# Build all examples — the 4 fixed ones should compile now.
cargo build -p nlink --all-targets

# Re-run the registration audit — the 4 lines should be reported
# as "ALLOWLIST STALE" (the file is now registered, no longer
# orphan, so the allowlist entry is wrong).
./scripts/audit-example-registration.sh

# After dropping the 4 lines, audit re-runs clean.
./scripts/audit-example-registration.sh
```

### 2.6 Commit shape

One commit per file (4 commits) or one batch commit, maintainer's
preference. The "one batch commit" reads well as
`fix(examples): close 4 trivial orphans from Plan 160 catalog`.

**Effort estimate**: ~1.5 hours total (~20 min per file).

## 3. Phase 2 — diagnostics consolidation

Three files (`bottleneck.rs`, `connectivity.rs`, `scan.rs`), all
in `examples/diagnostics/`, all in (P) or (P+F) category. Each
demonstrates one method on the real `nlink::netlink::diagnostics::
Diagnostics` API: `find_bottleneck()`, `check_connectivity()`,
`scan()`.

### 3.1 Recommendation: replace three with one

Plan 160 §"Verdict per file" notes the three are "mostly
`println!`-of-doc-strings — arguably better replaced by the
`--apply` runner pattern". But `Diagnostics` is a real substantive
API (see `crates/nlink/src/netlink/diagnostics.rs:435` — it owns
a `Connection<Route>`, holds previous-stats state, runs full
scans). It deserves runnable demo coverage. The right shape is
**one** comprehensive example that walks the canonical
diagnostic workflow end-to-end:

1. Construct `Diagnostics::new(conn)`.
2. Call `diag.scan()` — get a `DiagnosticReport`.
3. Call `diag.find_bottleneck()` — see what (if anything) is
   the worst issue.
4. Print the report's `interfaces`, `tc`, `routes`, and
   `issues` fields.
5. Demonstrate the `--apply`-style "do something then re-scan
   to see the change" pattern (e.g., load a netem qdisc, scan
   shows the new TC entry).

### 3.2 New file: `examples/diagnostics/health_check.rs`

Shape (target ~120 LOC):

```rust
//! Network health check — runs the full Diagnostics scan and
//! prints a structured report.
//!
//! Replaces the three earlier println-driven examples
//! (bottleneck.rs, connectivity.rs, scan.rs) deleted in
//! the Plan 168 Phase 2 closeout. The substantive `Diagnostics`
//! API justifies one cohesive demo, not three single-method
//! println walkthroughs.
//!
//! Run: cargo run -p nlink --example diagnostics_health_check

use nlink::netlink::{Connection, Route, diagnostics::Diagnostics};

#[tokio::main]
async fn main() -> nlink::Result<()> {
    let conn = Connection::<Route>::new()?;
    let diag = Diagnostics::new(conn);

    let report = diag.scan().await?;
    print_report(&report);

    if let Some(bottleneck) = diag.find_bottleneck().await? {
        println!("\nWorst issue:");
        println!("  {}: {} ({})",
            bottleneck.location,
            bottleneck.bottleneck_type,
            bottleneck.recommendation);
    } else {
        println!("\nNo bottlenecks detected.");
    }
    Ok(())
}

fn print_report(r: &nlink::netlink::diagnostics::DiagnosticReport) {
    // Walk r.interfaces, r.tc, r.routes, r.issues; print a
    // human-readable table. Use the actual fields verified in
    // diagnostics.rs:82-329.
}
```

### 3.3 Per-file disposition

- `examples/diagnostics/bottleneck.rs` — **delete** (replaced by §3.2).
- `examples/diagnostics/connectivity.rs` — **delete** (covered by `scan()` output in §3.2).
- `examples/diagnostics/scan.rs` — **delete** (replaced by §3.2; the new file IS the scan demo).

After deletion, register the new file:

```toml
[[example]]
name = "diagnostics_health_check"
path = "examples/diagnostics/health_check.rs"
```

Drop **3** allowlist lines.

### 3.4 Verification

```bash
cargo build -p nlink --example diagnostics_health_check
./scripts/audit-example-registration.sh   # 3 fewer allowlist entries
```

### 3.5 Commit shape

`refactor(examples): consolidate diagnostics demos into one`
(plus a brief justification in the commit body — "Plan 160
catalogued these three as written against fields that never
existed; the substantive Diagnostics API has more value in a
single end-to-end demo than three single-method walkthroughs.").

**Effort estimate**: ~1.5 hours (45 min to write the new file
with real API surface verification + 15 min for the three
deletions + 30 min for registration + audit verification).

## 4. Phase 3 — substantive rewrites

Two files, both larger surgery, both with real demo value once
done.

### 4.1 `examples/bridge/fdb.rs` (P)

**The problem** (per Plan 160):

- `LinkMessage::link_kind()` doesn't exist; correct is `.kind()`
  (same rename as `bridge/vlan.rs` in Phase 1 §2.1).
- `FdbEntry::is_local()` doesn't exist; the type carries
  `is_self`, `is_master`, `is_extern_learn`, `is_permanent`
  (verify against `crates/nlink/src/netlink/fdb.rs`).

**Investigation step**: read the current 161-line file end to
end. Count what works vs. what phantoms. If ≥ 80% works, fix
in place. If much of the file is built on the wrong mental
model, rewrite from scratch using the canonical FDB CRUD
pattern (lift from `tests/integration/neigh.rs` shape — which
covers a similar API).

**Target shape after rewrite** (~150 LOC):

1. Enumerate bridges via `get_links()` + `kind() == "bridge"`.
2. For each bridge: `conn.get_fdb(bridge_name).await?` — list
   entries.
3. Demonstrate add/del: install a static MAC entry via
   `FdbEntryBuilder`, dump, see it, delete it, re-dump, see
   it gone.
4. Print canonical fields: `mac_str()`, `vlan`, `dst`,
   `is_self`, `is_master`, `is_permanent`.

**Register** as `bridge_fdb`. **Drop** allowlist line.

**Effort estimate**: 1-3 hours depending on investigation
outcome.

### 4.2 `examples/config/declarative.rs` (O)

**The problem** (per Plan 160): the entire file is written
against a struct-based API (`LinkConfig`, `AddressConfig`,
`RouteConfig`, `QdiscConfig`) that the `nlink::netlink::config`
module never exposed. The actual API is closure-based:
`NetworkConfig::new().link(name, |b: LinkBuilder| ...)`.

**This is a full rewrite**, but the template is already in tree:
`examples/nftables/declarative.rs` (Plan 161) demonstrates the
mirror pattern for nftables. The NetworkConfig demo follows the
same arc:

1. Build a `NetworkConfig` declaring 2-3 links + addresses +
   routes + a qdisc.
2. `cfg.diff(&conn).await?` — show the initial diff (all-adds).
3. `diff.apply(&conn).await?` — atomic apply.
4. Re-diff — should be empty (idempotent).
5. Mutate one item (change an address, add a route), re-diff,
   show the small delta, re-apply.
6. Tear down with an empty config + final diff.

**Target shape after rewrite** (~180-220 LOC, in line with
`nftables/declarative.rs`'s 102 lines but bigger because
NetworkConfig spans more resource types).

**Register** as `config_declarative`. **Drop** allowlist line.

**Effort estimate**: 3-4 hours (research the actual
`NetworkConfig` API surface; write the demo; verify it
compiles under `cargo build --example`; test the
permission-denied early-exit path for unprivileged users
following the pattern in `nftables/declarative.rs:48-54`).

### 4.3 Phase 3 disposition options

Two reasonable timings:

- **Option A — bundle into 0.16 cut.** Adds ~4-7 hours of
  focused work. Closes the catalog completely before publish;
  no orphans ever shipped under 0.16's name. Risk: the
  `config/declarative.rs` rewrite is a real design call —
  the closure-based `NetworkConfig` API has nuances the demo
  needs to teach. Better when well-rested.
- **Option B — defer Phase 3 to 0.16.1 or 0.17 cycle.**
  Phases 1 + 2 close 7 of 9 orphans pre-cut (allowlist 9 → 2).
  Phase 3 lands in a focused follow-up commit when there's
  appetite. Risk: the catalog stays partially open at cut.

**Recommendation**: Option A if there's an unhurried 4-7 hour
block. Option B if cut is time-pressured.

## 5. Cross-cutting verification (after each phase)

```bash
# Build all (registered) examples.
cargo build -p nlink --all-targets --all-features

# Run the audit script — should report 0 orphans if all
# phases have landed.
./scripts/audit-example-registration.sh

# Workspace clippy.
CARGO_INCREMENTAL=0 cargo clippy --workspace --all-targets \
    --all-features -- --deny warnings

# Lib tests + doctests — no regressions expected since
# examples don't share code with lib.
cargo test -p nlink --lib --features full
cargo test -p nlink --doc --features full
```

## 6. After all 3 phases land

- `scripts/audit-example-registration.allowlist` is empty.
- Per Plan 160 §"Acceptance criteria" line 176-177: **delete
  the allowlist file itself** ("the script no-ops when the
  allowlist file is absent").
- Update Plan 160 frontmatter status to "closed by Plan 168".
- CHANGELOG entry under
  `### Documentation` (or `### Examples` if first such entry):
  "All 9 orphan examples catalogued by Plan 160 closed —
  4 trivial fixes, 3 diagnostics consolidated into one
  end-to-end health-check, 2 substantive rewrites
  (bridge FDB CRUD, declarative NetworkConfig). Allowlist
  file deleted; the `audit-example-registration` CI gate
  now enforces zero orphans from a clean slate."

## 7. Acceptance criteria

- [ ] Phase 1: 4 trivial orphans fixed + registered; 4
      allowlist lines dropped; `cargo build --all-targets`
      green.
- [ ] Phase 2: 3 diagnostics files deleted + 1 new
      `health_check.rs` written and registered; 3 allowlist
      lines dropped.
- [ ] Phase 3: `bridge/fdb.rs` either rewritten + registered
      OR deleted; `config/declarative.rs` rewritten +
      registered; 2 allowlist lines dropped.
- [ ] `scripts/audit-example-registration.allowlist` deleted
      (empty file).
- [ ] Plan 160 frontmatter status → closed.
- [ ] CHANGELOG entry.

## 8. Effort estimate

| Phase | Effort |
|---|---|
| 1 trivial fixes (4 files) | ~1.5 h |
| 2 diagnostics consolidation | ~1.5 h |
| 3 substantive rewrites | ~4-7 h |
| Phase-trailing verification + commits | ~30 min total |
| **Total** (all phases) | **~7.5 – 10.5 h** |
| **Phases 1+2 only** (Option B above) | **~3.5 h** |

## 9. Risks

- **`config/declarative.rs` API drift during rewrite**:
  `NetworkConfig` may have edge cases not obvious from the
  module docs. Mitigation: cross-read `tests/integration/config.rs`
  for canonical-usage patterns before writing the new file.
- **`bridge/fdb.rs` deeper-than-expected rewrite**: if the
  investigation step finds < 50% of the file salvageable,
  cost balloons toward 3 hours. Mitigation: timebox to
  90 min — if still messy, **delete the file entirely**
  (drop the allowlist line as deletion-not-fix). FDB CRUD
  is also covered by `tests/integration/neigh.rs`; the
  example isn't load-bearing for downstream learners.
- **Diagnostics API surface drift**: the new
  `health_check.rs` references the canonical fields of
  `DiagnosticReport`, `InterfaceDiag`, `TcDiag`, `RouteDiag`,
  `RouteInfo`, `Bottleneck`. Each is `#[non_exhaustive]`-protected
  going forward (post Plan 163), so future field additions
  won't break the example. But current field names must be
  verified against `diagnostics.rs` at write time (not from
  the orphan files themselves — they're the source of the
  phantom-field mistakes).
- **Example bit-rot reintroduction**: the whole point of Plan
  160's CI gate is to prevent this. After Phase 3 closes,
  the gate enforces "zero new orphans from a clean slate" —
  any future bit-rot must be either a phantom-field check
  (caught by `cargo build`) or a missing registration (caught
  by the audit script).

## 10. Why this matters

The 9 orphans had no user-visible failure mode — `cargo build`
was happy, CI was green, the files just weren't included. But
they're carried in the published source-tarball and visible
when downstream consumers browse the repository. Each one is a
small credibility tax: "this project ships broken examples."
Closing them out raises the floor on what a first-time visitor
sees when they wander into `examples/`.

End of plan.
