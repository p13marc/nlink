---
subject: nlink plan index — post-0.17 / pre-0.18
status: live (update as plans land or open)
target version: 0.18.0 (next cycle)
maintainer: p13marc
created: 2026-05-25 (post-0.17 cleanup; 0.16 + 0.17 per-plan scaffolding deleted per convention)
---

# Plan index — post-0.17 / pre-0.18

Day-to-day tracker for nlink's outstanding plan work. The 0.17
cycle's per-plan scaffolding (Plans 169-178) was deleted after
the cycle wrapped, per project convention — the durable narrative
lives in [`CHANGELOG.md`](../CHANGELOG.md) `## [0.17.0]` (once
cut; currently still under `## [Unreleased]`) and the migration
walkthrough in
[`docs/migration_guide/0.16.0-to-0.17.0.md`](../docs/migration_guide/0.16.0-to-0.17.0.md).

## Quick status

- **Last cycle**: 0.17 — code work complete 2026-05-25;
  workspace bumped to 0.17.0; CI green on every commit.
  Awaiting maintainer cut via `scripts/cut-release.sh 0.17.0`.
- **Next cycle**: 0.18.0 — branch will open from master after
  the 0.17 cut publishes. Plan 179 (below) is the only carry-
  over work currently queued.

## Status legend

| Symbol | Meaning |
|---|---|
| ⚪ | Planned — not started |
| 🟡 | In progress — PR open or work underway |
| 🟢 | Merged to master |
| 🔵 | Cut & published |

## In-flight / queued

| Plan | Title | Effort | Status | Notes |
|------|-------|--------|--------|-------|
| [179](179-diagnostics-tests-migrate-to-require-root-plan.md) | Migrate 12 `#[ignore]`'d `diagnostics.rs` tests to `nlink::require_root!()` | ~1-3 h | ⚪ | Surfaced by the 0.17 CI-observability work. Mechanical bulk pass; may surface latent test failures (these tests have never run). Pick up when 0.18 opens. |

## Deprioritized (parked)

| Plan | Why parked |
|------|------------|
| [152](152-0.16-integration-showcases-plan.md) | `aya` co-demo + Prometheus exporter + OTel example. Carried from 0.16 without a real adopter signal. Revisit if a downstream asks for it. |

## How to update this file

When a plan moves status:

1. Edit the **Status** column emoji.
2. When a plan ships and the cycle cuts + publishes, delete the
   per-plan file (per CLAUDE.md "Publishing" / "Plan-file
   cleanup"). The durable narrative is the CHANGELOG entry +
   migration guide; plan files are working memory and shouldn't
   accumulate.
3. Rewrite this INDEX when opening a new cycle — clear the
   "Quick status" + "In-flight / queued" sections, leaving
   "Deprioritized" intact unless explicitly un-parked.
