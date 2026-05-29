---
subject: nlink plan index — 0.19 cycle
status: live (update as plans land)
target version: 0.19.0
maintainer: p13marc
created: 2026-05-29 (post-0.18 cut; 0.18.0 published 2026-05-29 — both crates on crates.io, tag `0.18.0` on master)
---

# Plan index — 0.19 cycle

Day-to-day tracker for nlink's 0.19 work. The 0.18 cycle shipped
2026-05-29 (both crates on crates.io; tagged `0.18.0` on master;
GitHub release at
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
  major. Same precedent as 0.17's Register discriminant change
  (Plan 178) and 0.18's `ChainInfo` non-exhaustive addition
  (Plan 180 CI iteration).
- **CI**: open a draft PR `0.19 → master` once the first
  commit lands so the workflow fires on every push.

## Status legend

| Symbol | Meaning |
|---|---|
| ⚪ | Planned — not started |
| 🟡 | In progress — PR open or work underway |
| 🟢 | Merged to master |
| 🔵 | Cut & published |

## Sub-plan table

| Plan | Title | Effort | Order | Status | Notes |
|------|-------|--------|-------|--------|-------|
| _none yet_ | | | | | |

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
