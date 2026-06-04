#!/usr/bin/env bash
# Plan 237 (0.20.1) — self-test for audit-example-features.sh.
#
# Verifies the audit script catches an [[example]] entry that
# imports a feature-gated module without declaring the matching
# `required-features = [...]`.

set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
SCRIPT="$REPO_ROOT/scripts/audit-example-features.sh"

if [[ ! -f "$SCRIPT" ]]; then
    echo "FAIL: $SCRIPT not found" >&2
    exit 1
fi

WORK_DIR="$(mktemp -d -t audit-example-feat-test.XXXXXX)"
trap 'rm -rf "$WORK_DIR"' EXIT

git -C "$REPO_ROOT" archive HEAD | tar -x -C "$WORK_DIR"

# Inject a new example that uses `nlink::lab::*` but its
# [[example]] entry will not declare `required-features = ["lab"]`.
INJECT_FILE="$WORK_DIR/crates/nlink/examples/plan_237_lab_orphan.rs"
cat > "$INJECT_FILE" <<'EOF'
//! Plan 237 self-test fixture — uses nlink::lab without declaring
//! required-features = ["lab"] in the [[example]] entry below.
use nlink::lab::with_namespace;

fn main() {
    let _ = with_namespace;
}
EOF

# Append a deliberately-broken [[example]] entry (no required-features).
cat >> "$WORK_DIR/crates/nlink/Cargo.toml" <<'EOF'

# Plan 237 self-test fixture — deliberately missing required-features.
[[example]]
name = "plan_237_lab_orphan"
path = "examples/plan_237_lab_orphan.rs"
EOF

# Run the script; expect non-zero exit.
set +e
output="$(cd "$WORK_DIR" && bash "$SCRIPT" 2>&1)"
rc=$?
set -e

if [[ $rc -eq 0 ]]; then
    echo "FAIL: audit-example-features.sh accepted a broken fixture" >&2
    echo "Output was:" >&2
    echo "$output" >&2
    exit 1
fi

if ! grep -q 'plan_237_lab_orphan' <<<"$output"; then
    echo "FAIL: failure output didn't name the injected example" >&2
    echo "Output was:" >&2
    echo "$output" >&2
    exit 1
fi

echo "PASS: audit-example-features.sh failure path works"
