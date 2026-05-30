---
subject: nlink plan index — 0.19 cycle
status: live (update as plans land)
target version: 0.19.0
maintainer: p13marc
created: 2026-05-29 (post-0.18 cut; seven 0.19 plans seeded 2026-05-30 from nlink-feedback.md)
---

# Plan index — 0.19 cycle

Day-to-day tracker for nlink's 0.19 work. The 0.18 cycle
shipped 2026-05-29 (both crates on crates.io; tagged `0.18.0`
on master; GitHub release at
https://github.com/p13marc/nlink/releases/tag/0.18.0). The 0.18
cycle's narrative lives in
[`CHANGELOG.md ## [0.18.0]`](../CHANGELOG.md) +
[`docs/migration_guide/0.17.0-to-0.18.0.md`](../docs/migration_guide/0.17.0-to-0.18.0.md);
per-plan scaffolding was deleted post-cut per convention.

## Quick status

- **Cycle**: 0.19.0 — branched from master post-0.18 cut.
- **Branch**: all 0.19 work pushes to the `0.19` branch.
  Cycle cut → master merge happens at release time. **Do not
  push to master.**
- **Workspace version**: `0.18.0` — bump to `0.19.0` on the
  first PR whose change cargo-semver-checks flags as semver-
  major. Plan 187's `Error` factory sign-normalization is
  technically semver-major (changes stored errno values);
  Plan 188's `ApplyOptions` `#[non_exhaustive]` flip likewise.
  Whichever lands first triggers the bump.
- **CI**: open a draft PR `0.19 → master` once the first
  commit lands so the workflow fires on every push.
- **Seed report**: [`nlink-feedback.md`](../nlink-feedback.md)
  (nlink-lab maintainer, 2026-05-30; covers the 158 arc's
  ~30 friction points).

## Status legend

| Symbol | Meaning |
|---|---|
| ⚪ | Planned — not started |
| 🟡 | In progress — PR open or work underway |
| 🟢 | Merged to master |
| 🔵 | Cut & published |

## Sub-plan table

Ordered by recommended landing sequence: investigation-first
(#1) blocks downstream design assumptions, then the small
ergonomic bundle (188) shows progress + low risk, then the
correctness fixes (187), then features in scope of
sophistication.

| Plan | Title | Effort | Order | Status | Notes |
|------|-------|--------|-------|--------|-------|
| [186](186-vlan-parent-resolution-race-plan.md) | VLAN parent ifindex race — investigation-first + topo-sort + ordering docstring (Items #1, #2, D1) | ~4-12 h | 1 | ⚪ | **HIGH** correctness. Diagnose root cause before shipping fix. Maintainer's cache/sysfs hypotheses confirmed wrong by audit; real cause is non-obvious from code read. Investigation phase = integration repro. |
| [187](187-error-api-hygiene-plan.md) | `Error` API hygiene — normalize factory sign, `chain_walk` helper, Box-source rustdoc (Items #3, #4, D2, D3) | ~3 h | 2 | ⚪ | Medium footgun bundle. Breaking change for tests asserting prior `Some(-N)` semantics. |
| [188](188-declarative-apply-parity-plan.md) | Declarative apply parity — `ConfigDiff::apply`, `ApplyOptions` builders, `apply_reconcile`, `default_v{4,6}`, `LinkChanges::Display`, `del_*_if_exists` (Items #5, #7, #8, #16, W6, W8) | ~6 h | 3 | ⚪ | Low-priority ergonomic bundle. `ApplyOptions` `#[non_exhaustive]` is a semver break. |
| [189](189-serde-feature-flag-plan.md) | `serde` feature flag on diff + result + report types (Item #9, W4) | ~3.5 h | 4 | ⚪ | Opt-in feature. JSON shape commits us to kebab-case schema stability. |
| [190](190-linkbuilder-gaps-plan.md) | `LinkBuilder` gaps — VXLAN local/port/underlay, VLAN protocol, VRF (Items #10, #12, #13-VRF half) | ~7 h | 5 | ⚪ | Predictable feature work. WireGuard half of #13 split out. |
| [191](191-route-events-with-resync-plan.md) | `Connection<Route>::subscribe` + `RouteEvent` + `into_events_with_resync` — RTNETLINK twin of Plan 185 (Item #15, W2) | ~9.5 h | 6 | ⚪ | **Headline** of 0.19. Mirrors the kube-rs-shaped Plan 185 watcher for RTNETLINK. |
| [192](192-docs-pass-plan.md) | Documentation pass — D1, D4, D5, D6, W7 tracing-span audit | ~4.5 h | 7 | ⚪ | Doc + tracing-audit bundle. Deprecates `summary()` methods in favor of `Display`. |

Total estimated focused-work: **~38-45 h** (depending on Plan
186's investigation outcome) + integration-test CI cycle time.

## Wishlist items NOT scoped this cycle

| Item | Why deferred |
|------|--------------|
| #11 — Bond options (ad_select, lacp_rate, etc.) | Per nlink-lab maintainer's own note: nlink-lab doesn't need them. Land when another consumer asks. |
| #13 WireGuard half — `LinkBuilder::wireguard` | Different shape entirely (GENL family for peers). Needs its own design plan; defer to 0.20 or later. |
| #14 — Declarative nft sets | nlink-lab doesn't use sets. No downstream signal. |
| W1 — Dump-cache invalidation hook | Moot if Plan 186's diagnosis is right (no cache exists). Revisit only if it turns out a cache is the right fix. |
| W5 — `Connection::<P>::lazy()` deferred-socket ctor | Belongs in a per-namespace `ConnectionPool` revision; defer. |
| W9 — Macvlan Source mode | No downstream signal. |
| #16 add-on — deprecating `summary()` | Folded into Plan 192. |

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
