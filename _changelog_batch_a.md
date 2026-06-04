# Batch A — `_changelog_batch_a.md`

Stubs for CHANGELOG `[Unreleased]` section. Reviewer merges with sibling batches at cut time.

## Added

- **Plan 222.2-4 — Sizeof gate broader coverage.**
  Extended the `crates/nlink/src/netlink/sys_sizeof.rs` constant-value
  gate (shipped in 0.20.0 with XFRM + nft CT phase) to cover TC
  HTB / flower keys, IFLA / RTA / ctnetlink, and DPLL / devlink /
  ethtool. Each module pins ~10-20 most-used constants against
  kernel UAPI v6.13 reference values, with a build-time test that
  fails if nlink's production constants drift. Defers exhaustive
  coverage to 0.21; documented inline with `// TODO 0.21:` markers.

- **Plan 226 — DPLL `sint` codegen runtime (additive).**
  Added `nlink-macros` runtime support for the kernel's
  variable-length signed-integer wire format (`nla_put_sint`:
  4 bytes if value fits in s32, 8 bytes otherwise). Added a NEW
  `DpllPin::fractional_frequency_offset_ppt_i64: Option<i64>`
  field that holds the full-width value; the existing
  `fractional_frequency_offset_ppt: Option<i32>` field is kept
  for backward compatibility but marked `#[deprecated(since =
  "0.20.1")]` because it silently truncates on overflow. Added
  `ffo_ppt_i64()` accessor as the recommended API. Adversarial-
  input unit tests for FFO values > `i32::MAX`.

- **Plan 233 — `DumpStream::with_skip_malformed` opt-in.**
  Default behaviour on `DumpStream` stays fuse-on-malformed
  (correctness > liveness for snapshot dumps). New
  `.with_skip_malformed(true)` setter switches to flatten-mode
  with WARN-level `tracing` per skip. Per-stream-API audit table
  + dump-vs-event policy documented inline. CLAUDE.md
  `## Parser robustness` updated with the new sub-section.

- **Plan 237 — Audit-script self-test pattern.**
  Five new `scripts/test-audit-*.sh` self-tests verify the
  failure paths of the audit-by-grep CI scripts
  (`audit-recv-loop-error-handling.sh`, `audit-sysfs-in-lib.sh`,
  `audit-example-registration.sh`, `audit-example-feature-gating.sh`).
  Each test injects a deliberately-broken fixture, runs the audit
  script, and asserts non-zero exit + message match. Closes the
  silent-broken-script class.

## Deprecated

- `DpllPin::fractional_frequency_offset_ppt: Option<i32>` —
  silently truncates kernel-supplied FFO values that don't fit in
  s32. Use the new `_i64` field or `ffo_ppt_i64()` accessor.
  Removal: 0.21.0.

## Deferred to 0.21

- `audit-bytes-le.sh` self-test (Plan 237.1 part) — depends on
  Plan 223's script existing. Will land alongside if both batches
  merge cleanly; otherwise the self-test slots into 0.21.
- Exhaustive sizeof-gate coverage of remaining UAPI families
  (`audit-uapi-constants.sh` cron + reference-kernel checkout).
- CI workflow YAML entry for the `audit-script-self-tests` job —
  may have OAuth-scope issues on the gh PR-merge path; documenting
  for the reviewer to wire manually if needed.
