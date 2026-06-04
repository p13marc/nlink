#!/usr/bin/env bash
# Plan 237 (0.20.1) — self-test for audit-example-registration.sh.
#
# Verifies the audit script catches a NEW (un-allowlisted) example
# file in a subdirectory that lacks an [[example]] entry in
# crates/nlink/Cargo.toml.

set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
SCRIPT="$REPO_ROOT/scripts/audit-example-registration.sh"

if [[ ! -f "$SCRIPT" ]]; then
    echo "FAIL: $SCRIPT not found" >&2
    exit 1
fi

WORK_DIR="$(mktemp -d -t audit-example-reg-test.XXXXXX)"
trap 'rm -rf "$WORK_DIR"' EXIT

git -C "$REPO_ROOT" archive HEAD | tar -x -C "$WORK_DIR"

# Inject a new example in a subdirectory that's NOT registered in
# Cargo.toml and NOT on the allowlist.
INJECT_PATH="$WORK_DIR/crates/nlink/examples/_plan_237_subdir"
mkdir -p "$INJECT_PATH"
cat > "$INJECT_PATH/plan_237_orphan.rs" <<'EOF'
//! Plan 237 self-test fixture — deliberately unregistered example.
fn main() {
    println!("hello");
}
EOF

# Run the script; expect non-zero exit.
set +e
output="$(cd "$WORK_DIR" && bash "$SCRIPT" 2>&1)"
rc=$?
set -e

if [[ $rc -eq 0 ]]; then
    echo "FAIL: audit-example-registration.sh accepted an unregistered example" >&2
    echo "Output was:" >&2
    echo "$output" >&2
    exit 1
fi

if ! grep -q 'plan_237_orphan' <<<"$output"; then
    echo "FAIL: failure output didn't name the injected example" >&2
    echo "Output was:" >&2
    echo "$output" >&2
    exit 1
fi

echo "PASS: audit-example-registration.sh failure path works"
