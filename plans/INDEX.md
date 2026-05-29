---
subject: nlink plan index — 0.18 cycle
status: live (update as plans land)
target version: 0.18.0
maintainer: p13marc
created: 2026-05-26 (post-0.17 cut; 0.17 published 2026-05-26 as `0.17.0` + `v0.16.0` alias)
---

# Plan index — 0.18 cycle

Day-to-day tracker for nlink's 0.18 work. The 0.17 cycle
shipped 2026-05-26 (both crates on crates.io; tagged `0.17.0`
on master). The 0.18 cycle's seed surface is the upstream-asks
report from the nlink-lab maintainer (2026-05-27), with one
adjacent-gap finding (netdev hook `device`) bundled into the
chain-attribute pass.

## Quick status

- **Cycle**: 0.18.0 — branched from master post-0.17 cut.
- **Branch**: all 0.18 work pushes to the `0.18` branch.
  Cycle cut → master merge happens at release time. **Do not
  push to master.**
- **Workspace version**: `0.18.0` — bumped on Plan 180's CI
  iteration when `cargo-semver-checks` flagged the
  `#[non_exhaustive]` addition on `ChainInfo` as semver-major
  (same precedent as 0.17's Register discriminant change in
  Plan 178).
- **CI**: open a draft PR `0.18 → master` once the first
  commit lands so the workflow fires on every push.
- **Seed report**: [`nlink-upstream-asks.md`](../nlink-upstream-asks.md)
  (committed in repo root; nlink-lab maintainer, 2026-05-27).

## Status legend

| Symbol | Meaning |
|---|---|
| ⚪ | Planned — not started |
| 🟡 | In progress — PR open or work underway |
| 🟢 | Merged to master |
| 🔵 | Cut & published |

## Sub-plan table

Ordered by recommended landing sequence: unblocker first, then
the larger ergonomic surface, then the trivials, then the
medium-size dependent plan.

| Plan | Title | Effort | Order | Status | Notes |
|------|-------|--------|-------|--------|-------|
| [180](180-declarative-chain-type-and-device-plan.md) | `DeclaredChainBuilder::chain_type` + `Chain`/`DeclaredChain` `device` for netdev hooks | ~2.5 h | 1 | 🟢 | Shipped `aa52b09`. All 11 CI jobs green incl. integration. Unblocks nlink-lab Plan 158a. |
| [181](181-list-in-filter-family-plan.md) | `list_{tables,chains,flowtables,sets}_in(table?, family)` server-side filter family | ~2 h | 2 | 🟢 | Shipped `496378a` + defensive-filter fix `7d0a34b`. Kernel ignores `NFTA_*_TABLE` on dump (only single-get); client-side filter ensures contract holds. |
| [182](182-error-ext-ack-accessor-plan.md) | `Error::ext_ack()` + `Error::ext_ack_offset()` inherent accessors | ~30 min | 3 | 🟢 | Shipped `7fc03ce` (bundled). |
| [183](183-display-for-diff-types-plan.md) | `impl Display for NftablesDiff` + `ConfigDiff` (wraps existing `summary()`) | ~30 min | 4 | 🟢 | Shipped `7fc03ce` (bundled). Note: target was `NetworkDiff` per the report, but the actual type name is `ConfigDiff` — used that. |
| [184](184-default-route-constructors-plan.md) | `Ipv4Route::default_route()` / `Ipv6Route::default_route()` constructors | ~20 min | 5 | 🟢 | Shipped `7fc03ce` (bundled). |
| [185](185-nftables-subscribe-with-resync-plan.md) | `Connection<Nftables>::{into_events_with_resync, subscribe_all_with_resync}(factory)` — kube-rs-shaped watcher with built-in ENOBUFS recovery; both owned + borrowed forms | ~5 h | 6 | 🟢 | Shipped `adf386d`. All 12 CI gates green incl. integration (2m48s). Lifetime-generic `events_with_resync` + `NftablesEvent::{NewSet,DelSet}` + `nftables::resync` module + recipe + migration guide all bundled. Closes nlink-lab Wishlist 5. |

Total estimated focused-work: **~9.5 h** + integration-test CI
cycle time.

## Wishlist items NOT scoped this cycle

| Item | Why deferred |
|------|--------------|
| `for_each_namespace_async` (Wishlist 4) | Too opinionated for core (hardcodes thread-per-ns + current_thread runtime). Belongs in `nlink::lab` if anywhere. Defer — let consumers compose `namespace::with_namespace_async` themselves. |
| `NetworkConfig` per-object reconcile parity (Wishlist 6) | Multi-cycle scope. RTNETLINK lacks BATCH_BEGIN/END so "atomic apply" needs best-effort rollback design. Warrants a design doc before any code. Open a doc-only plan when there's bandwidth. |

## Deprioritized (parked)

| Plan | Why parked |
|------|------------|
| [152](152-0.16-integration-showcases-plan.md) | `aya` co-demo + Prometheus exporter + OTel example. Carried from 0.16 without a real adopter signal. Revisit if a downstream asks for it. |

## Known maintainer-tooling bug

- `scripts/cut-release.sh` Phase 3 captures the PR number AND the
  `gh pr checks --watch` status lines into `PR_NUMBER` (output
  capture vs. stdout). Fix: send status echoes to stderr
  (`echo ... >&2`) and emit only the bare PR number on stdout.
  Surfaced during the 0.17.0 cut; ~5-line patch on the script.
  Do this before the next cut.

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
