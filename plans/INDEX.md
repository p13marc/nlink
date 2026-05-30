---
subject: nlink plan index — 0.19 cycle
status: live (update as plans land)
target version: 0.19.0
maintainer: p13marc
created: 2026-05-29 (post-0.18 cut; seven 0.19 plans seeded 2026-05-30 from nlink-feedback.md, expanded to ten plans same day during consolidation pass)
---

# Plan index — 0.19 cycle

Day-to-day tracker for nlink's 0.19 work. The 0.18 cycle
shipped 2026-05-29 (both crates on crates.io; tagged `0.18.0`
on master; GitHub release at
https://github.com/p13marc/nlink/releases/tag/0.18.0). The 0.18
cycle's narrative lives in
[`CHANGELOG.md ## [0.18.0]`](../CHANGELOG.md) +
[`docs/migration_guide/0.17.0-to-0.18.0.md`](../docs/migration_guide/0.17.0-to-0.18.0.md).

## Quick status

- **Cycle**: 0.19.0 — branched from master post-0.18 cut.
- **Branch**: all 0.19 work pushes to the `0.19` branch.
  Cycle cut → master merge happens at release time. **Do not
  push to master.**
- **Workspace version**: `0.18.0` → bump to `0.19.0` on the
  first PR whose change cargo-semver-checks flags as
  semver-major. Multiple breaking changes line up:
  Plan 187 (Error factory sign-normalization),
  Plan 188 (ApplyOptions `#[non_exhaustive]`),
  Plan 190 (DeclaredLinkType enum widening),
  Plan 191 (RouteEvent enum addition).
  Whichever lands first triggers the bump.
- **CI**: open a draft PR `0.19 → master` once the first
  commit lands so the workflow fires on every push.
- **Seed reports**:
  - [`nlink-feedback.md`](../nlink-feedback.md) (nlink-lab
    maintainer, 2026-05-30; covers the 158 arc's ~30 friction
    points)
  - 0.19 consolidation-pass bug-hunt + kernel-research agents
    (2026-05-30; surfaced 3 new plans worth of defensive
    coverage)

## Status legend

| Symbol | Meaning |
|---|---|
| ⚪ | Planned — not started |
| 🟡 | In progress — PR open or work underway |
| 🟢 | Merged to master |
| 🔵 | Cut & published |

## Sub-plan table

Ten plans this cycle. Three groups: feedback-driven (186-191
core), defensive (193-194 from ecosystem audit), kube-rs-shape
(195 stream combinators).

| Plan | Title | Effort | Order | Status | Notes |
|------|-------|--------|-------|--------|-------|
| [186](186-vlan-parent-resolution-race-plan.md) | VLAN parent ifindex race — investigation-first + topo-sort + ordering docstring (Items #1, #2, D1) | ~4-12 h | 1 | ⚪ | **HIGH** correctness. Maintainer's cache/sysfs hypotheses confirmed wrong; real cause is non-obvious from code read. Investigation phase = integration repro. |
| [187](187-error-api-hygiene-plan.md) | `Error` API hygiene — normalize factory sign, `chain_walk` helper, **Io-shape sweep across all `is_*` predicates** (expanded 2026-05-30 from bug-hunt finding) | ~5 h (was 3 h) | 2 | ⚪ | Medium footgun bundle. Single-point fix in `errno()` cascades to ~12 predicates that have the Plan 185 bug class. |
| [188](188-declarative-apply-parity-plan.md) | Declarative apply parity — `ConfigDiff::apply`, `ApplyOptions` builders, `apply_reconcile`, `default_v{4,6}`, `LinkChanges::Display`, `del_*_if_exists`, **deprecate `summary()`** (folded D6 here) | ~6.5 h (was 6 h) | 3 | ⚪ | Low-priority ergonomic bundle. `ApplyOptions` `#[non_exhaustive]` is a semver break. |
| [189](189-serde-feature-flag-plan.md) | `serde` feature flag on diff + result + report types (Item #9, W4) | ~3.5 h | 4 | ⚪ | Opt-in feature. JSON shape commits us to kebab-case schema stability. |
| [190](190-linkbuilder-gaps-plan.md) | `LinkBuilder` gaps — VXLAN local/port/underlay, VLAN protocol, VRF, **+ netkit (6.7), ovpn link half (6.16), IPv4 GSO/GRO caps (6.6)** (expanded 2026-05-30 from kernel research) | ~11.5 h (was 7 h) | 5 | ⚪ | Significantly expanded. Three new kernel link kinds + kernel ABI surface. |
| [191](191-route-events-with-resync-plan.md) | `Connection<Route>::subscribe` + `RouteEvent` + `into_events_with_resync` — RTNETLINK twin of Plan 185 (Item #15, W2) | ~9.5 h | 6 | ⚪ | **Headline** of 0.19. Mirrors the kube-rs-shaped Plan 185 watcher for RTNETLINK. |
| [192](192-docs-pass-plan.md) | Doc pass — D1, D4, D5, W7 tracing-span audit, **CLAUDE.md namespace-safety spec** (D6 moved to 188) | ~4.5 h | 7 | ⚪ | Doc + tracing-audit + new sysfs-audit CI gate. |
| **[193](193-parser-robustness-plan.md)** (**NEW** 2026-05-30) | Parser robustness — accept-larger-than-expected fixed-size structs, multipath/nexthop pathological-input guards, recoverable per-message parse skip + optional cargo-fuzz target | ~7 h | 8 | ⚪ | **Defensive**, preempting CVE-shaped issues other crates hit. References netlink-packet-route #232 + #152 + neli #305. |
| **[194](194-concurrent-stress-plan.md)** (**NEW** 2026-05-30) | Concurrent stress + seq-routing regression — 16-task interleaved dump test + 16-namespace parallel creation test | ~4.5 h (green path) | 9 | ⚪ | **Defensive**. References rtnetlink #131 (seq routing) + #132 (concurrent ns race). |
| **[195](195-stream-combinators-plan.md)** (**NEW** 2026-05-30) | `ResyncStreamExt` — `StreamBackoff`, `predicate_filter`, `map_event` mirroring kube-rs `WatchStreamExt` | ~6.5 h | 10 | ⚪ | Composes on top of Plans 185 + 191; doesn't change existing API. Applies to BOTH protocols. |

Total estimated focused-work: **~63-77 h** (depending on Plan
186's investigation outcome). Significant expansion from the
initial 38-45 h estimate after consolidation surfaced the
parser robustness + concurrent stress + stream combinator
plans.

## Cross-plan dependencies + ordering rationale

```
186 (HIGH, investigation-first)
 ├─ blocks: nothing structurally; but topo-sort docstring
 │   in 192 references it
 │
187 (Error API hygiene)
 ├─ enables 188's apply_reconcile to retry on Io-shape EAGAIN
 │
188 (Apply parity)        189 (serde)        190 (LinkBuilder gaps)
 │                          │                  │
 ├──────────┬───────────────┴──────────────────┘
 │          │
 │     193 (Parser robustness — independent, ship anytime)
 │     194 (Concurrent stress — independent, ship anytime)
 │
191 (RTNETLINK events) ─────────────┐
  │                                  │
  └──> 195 (Stream combinators ─ builds on both 185 + 191)
                                     │
192 (Docs + tracing audit) ──────────┘
```

**Recommended landing order:**
1. **193 (parser robustness)** first — if fuzz finds a panic,
   we want to know before piling other work on top.
2. **194 (concurrent stress)** second — same reason; if the
   seq-routing test goes red, the fix shape is invasive.
3. **187 (Error)** third — easy, unblocks 188's
   `apply_reconcile`.
4. **188 (apply parity)** fourth — small wins, momentum.
5. **186 (VLAN race)** fifth — investigation might take a day.
6. **190 (LinkBuilder gaps)** sixth — significant new code.
7. **189 (serde)** seventh — independent, can interleave.
8. **191 (RTNETLINK events)** eighth — the headline. Plan
   195 composes on top.
9. **195 (Stream combinators)** ninth.
10. **192 (Docs + tracing audit)** last — closes the cycle.

## Cross-plan artifact ownership

The 0.19 cycle has shared infrastructure that needs a single
owner. Most artifacts live inside an individual plan; these
are the ones that span:

| Artifact | Owning plan | Notes |
|---|---|---|
| `docs/migration_guide/0.18.0-to-0.19.0.md` | Plan 193 creates the stub (lands first) | Each subsequent plan appends its `### Plan 187`, `### Plan 188`, … section. Stub is in place; commit `b8ab3a2` + this consolidation push. |
| `docs/migration_guide/README.md` row for 0.19 | Plan 193 inserts the row | Polished at cycle cut with cycle highlights. ✓ inserted in this consolidation push. |
| `CHANGELOG.md ## [Unreleased]` | All plans append; cycle-cut script promotes to `## [0.19.0] - <date>` | Each plan's §9 "Cross-cutting artifacts" lists its specific subsections. |
| `CLAUDE.md` updates | Each plan owns its own section; no plan should ever delete or substantively rewrite another plan's section without coordination | Currently planned additions: 186 (parent topo-sort), 187 (Io-shape predicate template), 191 (Connection<Route> EventSource), 192 (util::ifname namespace policy), 193 (parser robustness policy), 194 (single-flight discipline), 195 (ResyncStreamExt). |
| `README.md` updates | Plans 189 (serde feature row), 190 (Library Modules row), 191 (High-Level APIs section), 195 (combinators sub-section) all touch README | Coordinate at PR review time; small per-plan touches. |
| `.github/workflows/rust.yml` new CI gates | Plans 189 (serde matrix), 192 (tracing + sysfs audit gates), 193 (recv-loop audit gate) | Four new gates total. |
| `.github/workflows/fuzz.yml` | Plan 193 creates | New workflow; weekly cron. |
| `scripts/` audit scripts | Plans 192 + 193 | Three new scripts: audit-tracing-instrument, audit-sysfs-in-lib, audit-recv-loop-error-handling. |
| `docs/recipes/` new recipes | Plans 186 (network-config-declarative), 189 (json-diff-export), 190 (vrf-multitenant + netkit-cilium-style), 191 (route-watch-with-resync), 195 (resync-with-backoff) | Six new recipes. Update `docs/recipes/README.md` index per plan. |
| `crates/nlink/examples/` new examples | Plans 186 (declarative_vlan_parent), 188 (existing examples updated for ApplyOptions builder), 189 (serialize_diff), 190 (vrf + netkit + vxlan_advanced + ovpn_link), 191 (route_watch_with_resync + route_subscribe), 195 (watch_with_backoff) | Nine new examples + edits to existing. Register each in `crates/nlink/Cargo.toml` per CLAUDE.md audit-example-registration convention. |

## Wishlist items NOT scoped this cycle

| Item | Why deferred |
|------|--------------|
| #11 — Bond options (ad_select, lacp_rate, etc.) | Per nlink-lab maintainer's own note: nlink-lab doesn't need them. Land when another consumer asks. |
| #13 WireGuard half — `LinkBuilder::wireguard` | Bundle with ovpn GENL family in a 0.20 plan: "GENL-side declarative families". |
| #14 — Declarative nft sets | nlink-lab doesn't use sets. No downstream signal. |
| W1 — Dump-cache invalidation hook | Moot if Plan 186's diagnosis is right (no cache exists). |
| W5 — `Connection::<P>::lazy()` deferred-socket ctor | Belongs in a per-namespace `ConnectionPool` revision; defer. |
| W9 — Macvlan Source mode | No downstream signal. |
| kube-rs `reflector` / `Store<K>` | Bigger scope; defer to 0.20+. |
| More fuzz targets beyond MessageIter | Land incrementally after the message_iter target settles. |

## Deprioritized (parked)

| Plan | Why parked |
|------|------------|
| [152](152-0.16-integration-showcases-plan.md) | `aya` co-demo + Prometheus exporter + OTel example. Carried since 0.16 without a real adopter signal. Revisit if a downstream asks for it. |

## Known maintainer-tooling bug

_None as of 0.18 cut._ The `wait_for_ci_green` stdout-vs-stderr
bug from the 0.17.0 cut was fixed in commit `6fb1c96` during the
0.18.0 cut; the script's Phase 3 capture now works. (The 0.18.0
cut still ran manually — the script's `confirm()` reads from
`/dev/tty` and can't run unattended.)

## How to update this file

When a plan moves status:

1. Edit the **Status** column emoji.
2. When a plan ships and the cycle cuts + publishes, delete the
   per-plan file (per CLAUDE.md "Publishing" / "Plan-file
   cleanup"). The durable narrative is the CHANGELOG entry +
   migration guide; plan files are working memory and shouldn't
   accumulate.
3. Rewrite this INDEX when opening a new cycle — clear the
   "Quick status" + "Sub-plan table" sections, leaving
   "Deprioritized" intact unless explicitly un-parked.
