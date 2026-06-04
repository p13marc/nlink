---
to: nlink maintainers
from: 0.20 consolidation review (`PLAN_REVIEW.md` §4.1)
subject: cycle-wide audit-script self-test pattern — every audit-by-grep CI gate gets a failure-path fixture
status: planning
target version: 0.20.0
parent: [Plan 220 master](220-0.20-master-plan.md) §3.2 cycle-wide rubrics
source: [PLAN_REVIEW.md](../PLAN_REVIEW.md) §4.1
created: 2026-06-04
---

# Plan 237 — Audit-script self-test pattern

## 1. Why this plan exists

The 0.20 cycle ships two new audit-by-grep CI scripts (Plan 222's
`audit-uapi-constants.sh`, Plan 223's `audit-bytes-le.sh`). Plus
the codebase already has four such scripts from prior cycles:

- `scripts/audit-recv-loop-error-handling.sh` (0.19 Plan 193)
- `scripts/audit-sysfs-in-lib.sh` (0.16+; in CLAUDE.md as gated)
- `scripts/audit-example-registration.sh` (CLAUDE.md ## Cookbook)
- `scripts/audit-example-feature-gating.sh` (0.18-era)

None of these scripts currently have **self-tests**. If a regex
typo, a missing `set -e`, or a logic error breaks the script's
failure path, the gate runs green forever while detecting
nothing. This is exactly the "audit-by-grep" failure mode the
user memory note `feedback_regression_test_first.md` warns
against — happy-path grep PASSES but the gate isn't actually
catching anything.

The consolidation review (`PLAN_REVIEW.md` §4.1) flagged this
across the cycle. This plan establishes a **self-test pattern**
that:

1. Every new audit-by-grep CI script ships with a self-test
   fixture (Plans 222, 223 — bound by this plan).
2. The existing four audit scripts get retrofitted to the same
   pattern during the cycle.
3. A new CI job runs every audit script's self-test on every
   push, gating that the script's failure-path still works.

## 2. The pattern

For each audit script `scripts/audit-<name>.sh`, create a
sibling test driver `scripts/test-audit-<name>.sh` that:

1. Creates a temporary git working tree (clone the repo head to
   a `mktemp -d`).
2. Injects a deliberately-broken fixture into the working tree
   (e.g. adds a `from_le_bytes` in a forbidden location for
   `audit-bytes-le.sh`).
3. Runs the audit script against the broken tree.
4. Asserts the script exits **non-zero** and the error message
   contains the expected pattern.
5. Cleans up the temp tree on exit.

Example shape:

```bash
#!/usr/bin/env bash
# scripts/test-audit-bytes-le.sh — self-test for audit-bytes-le.sh

set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
SCRIPT="$REPO_ROOT/scripts/audit-bytes-le.sh"

WORK_DIR="$(mktemp -d -t audit-bytes-le-test.XXXXXX)"
trap 'rm -rf "$WORK_DIR"' EXIT

# Snapshot the working tree, then inject the failure fixture.
git -C "$REPO_ROOT" archive HEAD | tar -x -C "$WORK_DIR"

# Inject the failure: add a from_le_bytes call to a file in
# crates/nlink/src/netlink/ that isn't on the allow-list.
INJECT_FILE="$WORK_DIR/crates/nlink/src/netlink/test_inject.rs"
cat > "$INJECT_FILE" <<'EOF'
// Self-test fixture for audit-bytes-le.sh — deliberately broken.
fn f(buf: &[u8]) -> u32 {
    u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]])
}
EOF

# Run the script; expect non-zero exit.
if (cd "$WORK_DIR" && "$SCRIPT") > "$WORK_DIR/out.txt" 2>&1; then
    echo "FAIL: audit-bytes-le.sh accepted a broken fixture"
    cat "$WORK_DIR/out.txt"
    exit 1
fi

# Verify the error message mentions the injected file.
if ! grep -q 'test_inject.rs' "$WORK_DIR/out.txt"; then
    echo "FAIL: audit-bytes-le.sh failure message did not mention the broken file"
    cat "$WORK_DIR/out.txt"
    exit 1
fi

echo "PASS: audit-bytes-le.sh failure path works"
```

This shape is replicable across all six scripts. The
self-tests don't need to be exhaustive of every regex branch —
one failure-path fixture per script is sufficient to prove the
script's failure path runs.

## 3. Scope — six scripts × self-test

| # | Script | Pre-existing? | What the fixture injects |
|---|---|---|---|
| S1 | `audit-bytes-le.sh` (Plan 223) | new | `from_le_bytes` in a forbidden file |
| S2 | `audit-uapi-constants.sh` (Plan 222) | new | a deliberately wrong constant value in `sys_sizeof.rs` |
| S3 | `audit-recv-loop-error-handling.sh` | existing | a `?` operator inside a `MessageIter::new(data)` walking loop in an event-parser context |
| S4 | `audit-sysfs-in-lib.sh` | existing | a `/sys/class/net/` read inside `crates/nlink/src/netlink/` outside the allowed exception list |
| S5 | `audit-example-registration.sh` | existing | a new `crates/nlink/examples/sub/orphan.rs` file with no corresponding `[[example]]` block in `Cargo.toml` |
| S6 | `audit-example-feature-gating.sh` | existing | an example that uses a feature without the `required-features` declaration |

## 4. CI integration

Add to `.github/workflows/ci.yml`:

```yaml
audit-script-self-tests:
  name: audit script self-tests
  runs-on: ubuntu-latest
  steps:
    - uses: actions/checkout@v4
    - name: Run all audit script self-tests
      run: |
        for st in scripts/test-audit-*.sh; do
          echo "== $st =="
          bash "$st"
        done
```

The job runs in parallel with the rest of CI and gates merge to
master. A failed self-test means the audit script's failure
path no longer works — must be fixed before the audit can be
trusted.

## 5. Test plan for this plan

The plan ships in two phases:

### 5.1 Phase 237.1 — Plans 222, 223 self-tests (new scripts)

Lands in the same PR as each new audit script. Plan 222 PR
includes `scripts/test-audit-uapi-constants.sh`; Plan 223 PR
includes `scripts/test-audit-bytes-le.sh`. CI workflow update
lands with either (whichever ships first; the second one
inherits the existing job).

### 5.2 Phase 237.2 — Retrofit the four existing scripts

A single PR adds self-tests for S3, S4, S5, S6. Can ship any
time in the 0.20 cycle after Phase 237.1. The retrofit is
mechanical given the pattern above; ~30 minutes per script.

### 5.3 Verification

For each self-test:

1. Run it against the head of the branch. Expect PASS (the
   audit script's failure path works for the injected fixture).
2. Temporarily break the audit script (e.g. add `exit 0` at the
   top). Re-run the self-test. Expect FAIL (the self-test
   catches the broken script).
3. Revert the temporary break. Re-run. Expect PASS.

## 6. Adversarial input coverage

Per Plan 236 §3, this plan's adversarial inputs are:

- **An empty repo** — the self-test fixture file is the only
  thing in the working tree. Audit script should still pass
  (no other files to scan); the injected fixture is the only
  failure.
- **Two injected failures in the same fixture file** — script
  should report both (or at least the first), not silently
  drop the second.
- **An injected failure inside a comment** (`// from_le_bytes` —
  the comment is text, not code). The script should NOT flag
  this; if it does, that's a false-positive bug in the script.
  The self-test for S1 should include this case to verify the
  audit script correctly distinguishes code from comments.

The comment-vs-code distinction is the highest-value
adversarial input for the grep-based scripts — it's exactly
where they're most likely to false-positive.

## 7. Risks

- **CI job becomes slow**: 6 self-tests sequentially could take
  ~30 seconds. Mitigation: run in parallel within the same
  job; or split each into its own job if CI allowance permits.
- **Self-test maintenance burden**: as audit scripts evolve,
  fixtures may drift. Mitigation: the fixtures are colocated
  with the scripts in `scripts/`; any change to the script
  forces a review of the sibling test.
- **`mktemp` + `git archive` in CI**: requires write access to
  the runner FS; should work on every GH Actions runner; not
  a real risk.

## 8. Acceptance

- All six audit scripts have a sibling `test-audit-<name>.sh`.
- CI's `audit-script-self-tests` job is green on every push.
- Each self-test verified per §5.3 (temporarily-broken-script
  catches the failure).
- Plan 222 + Plan 223 PRs include their self-tests.

## 9. Cross-references

- [`PLAN_REVIEW.md`](../PLAN_REVIEW.md) §4.1 (the systemic
  finding this plan answers).
- [`Plan 220 master`](220-0.20-master-plan.md) §3.2 cycle-wide
  rubrics.
- [Plan 222](222-sizeof-gate-constants-plan.md) — sibling
  audit script (`audit-uapi-constants.sh`).
- [Plan 223](223-bigendian-sweep-plan.md) — sibling audit
  script (`audit-bytes-le.sh`).
- User memory: `feedback_regression_test_first.md` — "trust
  adversarial inputs over audit-by-grep."
