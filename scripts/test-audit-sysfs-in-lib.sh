#!/usr/bin/env bash
# Plan 237 (0.20.1) — self-test for audit-sysfs-in-lib.sh.
#
# Verifies the audit script catches a /sys/class/net/ read added
# inside crates/nlink/src/netlink/ outside the ALLOWED list.
#
# Adversarial input coverage: also injects a `// /sys/class/net/`
# comment in a separate file to verify the audit script correctly
# distinguishes code from comments (the highest-value
# false-positive class for grep-based scripts — Plan 237 §6).

set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
SCRIPT="$REPO_ROOT/scripts/audit-sysfs-in-lib.sh"

if [[ ! -f "$SCRIPT" ]]; then
    echo "FAIL: $SCRIPT not found" >&2
    exit 1
fi

WORK_DIR="$(mktemp -d -t audit-sysfs-test.XXXXXX)"
trap 'rm -rf "$WORK_DIR"' EXIT

git -C "$REPO_ROOT" archive HEAD | tar -x -C "$WORK_DIR"

# Inject a deliberately-bad fixture: a /sys/class/net/ read in a
# non-allowlisted file under crates/nlink/src/netlink/.
INJECT_FILE="$WORK_DIR/crates/nlink/src/netlink/_plan_237_inject.rs"
cat > "$INJECT_FILE" <<'EOF'
// Plan 237 self-test fixture. Deliberately violates the namespace
// policy to verify audit-sysfs-in-lib.sh catches it.
#[allow(dead_code)]
fn fixture_bad() -> std::io::Result<String> {
    std::fs::read_to_string("/sys/class/net/eth0/operstate")
}
EOF

# Adversarial input #2: a separate file with the same string in a
# RUSTDOC comment. The script's comment-detection guards (// and ///)
# should skip these — if it flags them, that's a false-positive.
COMMENT_FILE="$WORK_DIR/crates/nlink/src/netlink/_plan_237_comment_only.rs"
cat > "$COMMENT_FILE" <<'EOF'
//! Plan 237 self-test fixture for comment-only sysfs mentions.
//! References /sys/class/net/ in a rustdoc — the audit script
//! must NOT flag this.
EOF

# Run the script.
set +e
output="$(cd "$WORK_DIR" && bash "$SCRIPT" 2>&1)"
rc=$?
set -e

if [[ $rc -eq 0 ]]; then
    echo "FAIL: audit-sysfs-in-lib.sh accepted a broken fixture" >&2
    echo "Output was:" >&2
    echo "$output" >&2
    exit 1
fi

# Check that the script's failure output names the injected file.
if ! grep -q '_plan_237_inject.rs' <<<"$output"; then
    echo "FAIL: failure output didn't mention the injected file" >&2
    echo "Output was:" >&2
    echo "$output" >&2
    exit 1
fi

# Comment-only file should NOT appear in violations. We allow it to
# appear in info / context lines but must NOT appear in a line
# tagged VIOLATION.
if grep -E 'VIOLATION:.*_plan_237_comment_only.rs' <<<"$output"; then
    echo "FAIL: audit-sysfs-in-lib.sh false-positive on comment-only mention" >&2
    echo "Output was:" >&2
    echo "$output" >&2
    exit 1
fi

echo "PASS: audit-sysfs-in-lib.sh failure path works (incl. comment-vs-code distinction)"
