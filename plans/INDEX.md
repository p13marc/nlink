---
subject: nlink plan index + progress tracker (0.17 cycle)
status: live (update as PRs land)
target version: 0.17.0
maintainer: p13marc
created: 2026-05-25 (rewritten from the 0.16 cycle tracker after the 0.16 cut)
---

# Plan index — 0.17 cycle

Day-to-day tracker for nlink's 0.17 cycle. The 0.16 cycle's
per-plan scaffolding (Plans 146 – 168) was deleted post-cut
per project convention (the CHANGELOG `## [0.16.0]` section
and `docs/migration_guide/0.15.1-to-0.16.0.md` carry the
durable narrative). Plan 169's Phases 1+2 shipped in 0.16;
its Phase 3 (`Bottleneck::score`) was rewritten as a slim
design plan and lives at
[`169-bottleneck-score-design.md`](169-bottleneck-score-design.md).

## Quick status

- **Cycle**: 0.17.0 — branched from master (= 0.16.0 head)
  2026-05-25; **cycle work complete 2026-05-25**, awaiting
  maintainer cut.
- **Branch**: all 0.17 work pushes to the `0.17` branch.
  Cycle cut → master merge happens at release time. **Do not
  push to master.**
- **Workspace version**: `0.17.0` — bumped on Plan 178's
  closeout (Register discriminant change + `rules_to_delete`
  tuple shape are the cycle's first semver-major API breaks;
  Plan 171's default-timeout was behavior-only, didn't trigger
  the bump).
- **Migration guide**:
  [`docs/migration_guide/0.16.0-to-0.17.0.md`](../docs/migration_guide/0.16.0-to-0.17.0.md)
  written.
- **CI**: PR #4 (draft, `0.17 → master`) — every push triggers
  the full workflow; all 11 jobs green on the cycle-close commit.
- **Cut**: run `scripts/cut-release.sh 0.17.0` when ready.

## Status legend

| Symbol | Meaning |
|---|---|
| ⚪ | Planned — not started |
| 🟡 | In progress — PR open or work underway |
| 🟢 | Merged to master |
| 🔵 | Cut & published |

## Sub-plan table

Master plan: [177](177-0.17-master-plan.md) — cycle theme,
sequencing rationale, scope boundaries.

| Plan | Title | Effort | Order | Status | PR(s) | Notes |
|------|-------|--------|-------|--------|-------|-------|
| [170](170-nft-send-batch-hang-investigation-plan.md) | `Connection::<Nftables>::send_batch` seq filter + end-seq termination — fixes the 0.16 cut's CI hang; un-ignores 7 `nftables_reconcile::*` tests | ~2.5 h | 1 | 🟢 | #4 | Shipped `dc4c103` + un-ignore `b9c8eb6`. Plan 170 un-ignored 4; remaining 3 closed by [Plan 178](178-nftables-diff-body-bytes-false-positive-plan.md). All 7 green. |
| [171](171-default-connection-timeout-plan.md) | Default 30s operation timeout on `Connection<P>` — opt-out via `.no_timeout()`; closes the "hidden hang" class that masked Plan 170 | ~3 h | 2 | 🟢 | #4 | Shipped `2a1251f`; integration timeout tests adjusted `66210c0`. |
| [172](172-recv-loop-audit-plan.md) | Audit + harden every recv-loop in the lib for the Plan 170 hang pattern — 9 loops total, 8 already structurally defensive (just need Plan 171's timeout wrap); 1 (`send_batch`) is the Plan 170 fix | ~2 h | 3 | 🟢 | #4 | Shipped `ee2a75f` — 9 recv-loops routed through `self.with_timeout`. |
| [173](173-parse-error-from-impls-plan.md) | `From<AddressParseError>` + `From<RouteParseError>` for `nlink::Error` — removes the `.map_err()` ceremony in `NetworkConfig` caller chains | ~30 min | 4 | 🟢 | #4 | Shipped `e00e365`. |
| [174](174-ci-observability-plan.md) | `tracing-subscriber` in integration test harness + `nf_flow_table` modprobe + ignored-tests catalog | ~1.5 h | 5 | 🟢 | #4 | Shipped `64bb854`. |
| [175](175-release-cut-tooling-plan.md) | `scripts/cut-release.sh` orchestrating the cut sequence + handling the `cargo publish --dry-run` inversion, CHANGELOG promotion, GitHub release length truncation | ~2 h | 6 | 🟡 | #4 | Shipped `778dcf4`; gets its real shakedown at the 0.17 cut. |
| [176](176-hardware-test-coverage-plan.md) | Hardware-only test coverage strategy doc (XFRM offload / devlink rate / net_shaper caps) — §3.3 deliverable for 0.17; §3.1 (self-hosted) and §3.2 (cloud lab) are future-plan sketches | ~1 h doc | 7 | 🟡 | #4 | §3.3 doc + CHANGELOG-annotation convention + cut-script hook landed locally; §3.1/§3.2 remain future plans. |
| [178](178-nftables-diff-body-bytes-false-positive-plan.md) | `NftablesDiff` body-bytes comparison flags unchanged rules as `to_replace`; un-ignores the 3 reconcile tests blocked by it | ~2-3 h | 8 | 🟢 | #4 | Closed via two commits: `7549039` (Register canonical values + repr(u32) + normalize_tlv) + `49455d2` (DELRULE chain fix + 0.17.0 bump). 3 reconcile tests un-ignored, all green in CI. |
| [169 Phase 3](169-bottleneck-score-design.md) | `Bottleneck::score: f64` normalized severity — combines drop_rate (weight 0.6) + backlog pressure (0.3) + error rate (0.1) | ~1 h | 9 | 🟢 | #4 | Shipped `11078c5`. |

Total 0.17 focused-work estimate: **~13 hours** + CI cycle
time + migration-guide write-up for the 0.16.0 → 0.17.0
transition.

## Post-0.17 follow-ups (queued)

| Plan | Title | Notes |
|------|-------|-------|
| [179](179-diagnostics-tests-migrate-to-require-root-plan.md) | Migrate 12 `#[ignore]`'d `diagnostics.rs` tests to `nlink::require_root!()` | Surfaced by Plan 174 §7. Mechanical bulk pass; may surface latent test failures (these tests have never run). ~1-3 h. |

## Deprioritized (parked)

| Plan | Why parked |
|------|------------|
| [152](152-0.16-integration-showcases-plan.md) | `aya` co-demo + Prometheus exporter + OTel example. Carried forward from 0.16 without a real adopter signal. Revisit if a downstream asks for it. |

## How to update this file

When a plan moves status:

1. Edit the **Status** column emoji.
2. Edit the **PR(s)** column — comma-separated list of PR
   numbers, or "—" if not yet open.
3. When a plan ships, optionally add a one-line outcome note
   to **Notes** (e.g., "shipped commit abc1234").
4. When the cycle cuts, the relevant rows become 🔵 and
   per-plan files get deleted (per the post-cut convention
   established at 0.16; substance lives in CHANGELOG +
   migration guide).
