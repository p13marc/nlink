#!/usr/bin/env bash
# Plan 237 (0.20.1) — self-test for audit-recv-loop-error-handling.sh.
#
# Verifies that the audit script's failure path actually fires by
# injecting a deliberately-bad pattern (a `?;` operator on a line
# inside a `for ... in MessageIter::new(data)` loop in stream.rs)
# and confirming the script exits non-zero with a message mentioning
# the file.
#
# If this test passes, the audit script's failure path works.
# If this test fails, the audit script has bit-rotted (regex typo,
# `set -e` removal, logic bug) and the CI gate is no longer
# catching the bug class it was designed to catch.

set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
SCRIPT="$REPO_ROOT/scripts/audit-recv-loop-error-handling.sh"

if [[ ! -f "$SCRIPT" ]]; then
    echo "FAIL: $SCRIPT not found" >&2
    exit 1
fi

WORK_DIR="$(mktemp -d -t audit-recv-loop-test.XXXXXX)"
trap 'rm -rf "$WORK_DIR"' EXIT

# Snapshot the working tree.
git -C "$REPO_ROOT" archive HEAD | tar -x -C "$WORK_DIR"

# The audit script uses `git rev-parse --show-toplevel` to find the
# repo root; init a throwaway repo so the script's `cd` step resolves.
(cd "$WORK_DIR" && git init -q && git add -A 2>/dev/null && \
    git -c user.email=test@test -c user.name=test commit -q -m fixture >/dev/null 2>&1)

# The audit script greps inside crates/nlink/src/netlink/stream.rs;
# inject a violating block at the end of the file.
STREAM_RS="$WORK_DIR/crates/nlink/src/netlink/stream.rs"
if [[ ! -f "$STREAM_RS" ]]; then
    echo "FAIL: stream.rs not present in injected tree at $STREAM_RS" >&2
    exit 1
fi

cat >> "$STREAM_RS" <<'INJECT'

// Plan 237 self-test fixture (NOT compiled — appended after the
// real file's logical end). Deliberately violates CLAUDE.md §"Parser
// robustness" rule 3 to verify audit-recv-loop-error-handling.sh
// catches the `?` operator inside a MessageIter::new walk.
#[allow(dead_code)]
fn plan_237_self_test_fixture(data: &[u8]) -> Result<()> {
    for msg in MessageIter::new(data) {
        let (header, payload) = msg?;
        let _ = (header, payload);
    }
    Ok(())
}
INJECT

# Run the script; expect non-zero exit.
set +e
output="$(cd "$WORK_DIR" && bash "$SCRIPT" 2>&1)"
rc=$?
set -e

if [[ $rc -eq 0 ]]; then
    echo "FAIL: audit-recv-loop-error-handling.sh accepted a broken fixture" >&2
    echo "Output was:" >&2
    echo "$output" >&2
    exit 1
fi

# The script should mention stream.rs in the failure output.
if ! grep -q 'stream.rs' <<<"$output"; then
    echo "FAIL: audit script failure message did not mention stream.rs" >&2
    echo "Output was:" >&2
    echo "$output" >&2
    exit 1
fi

echo "PASS: audit-recv-loop-error-handling.sh failure path works"
