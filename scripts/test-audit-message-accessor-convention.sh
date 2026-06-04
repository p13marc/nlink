#!/usr/bin/env bash
# Self-test for audit-message-accessor-convention.sh.
#
# Verifies the audit script catches:
#   1. A *Message struct that's missing #[non_exhaustive].
#   2. A *Message struct with bare `pub field:` declarations.
#
# Adversarial input coverage: a separate `*MessageBuilder` struct
# is added in the same fixture file to confirm the audit doesn't
# false-positive on builders / wrappers whose name starts with
# `Message`-followed-by-letters.

set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
SCRIPT="$REPO_ROOT/scripts/audit-message-accessor-convention.sh"

if [[ ! -f "$SCRIPT" ]]; then
    echo "FAIL: $SCRIPT not found" >&2
    exit 1
fi

WORK_DIR="$(mktemp -d -t audit-msg-convention-test.XXXXXX)"
trap 'rm -rf "$WORK_DIR"' EXIT

git -C "$REPO_ROOT" archive HEAD | tar -x -C "$WORK_DIR"

# Inject a deliberately-bad fixture: a *Message struct missing
# #[non_exhaustive] AND with bare pub fields.
INJECT_FILE="$WORK_DIR/crates/nlink/src/netlink/messages/_inject_bad.rs"
cat > "$INJECT_FILE" <<'EOF'
//! Self-test fixture for audit-message-accessor-convention.sh.
//! Deliberately violates the convention to verify the audit
//! catches the structural break.

/// Bad: missing #[non_exhaustive] + has bare pub fields.
#[derive(Debug, Clone, Default)]
pub struct BadInjectedMessage {
    pub family: u8,
    pub priority: u32,
}

/// Builder-style wrapper — should NOT be flagged. Names that
/// continue past `Message` (MessageBuilder, MessageEvent, …) are
/// outside the convention's scope.
pub struct BadInjectedMessageBuilder {
    pub family: u8,
}
EOF

set +e
output="$(cd "$WORK_DIR" && bash "$SCRIPT" 2>&1)"
rc=$?
set -e

if [[ $rc -eq 0 ]]; then
    echo "FAIL: audit-message-accessor-convention.sh accepted broken fixture" >&2
    echo "Output was:" >&2
    echo "$output" >&2
    exit 1
fi

if ! grep -q 'BadInjectedMessage missing #\[non_exhaustive\]' <<<"$output"; then
    echo "FAIL: failure output didn't flag the missing #[non_exhaustive]" >&2
    echo "Output was:" >&2
    echo "$output" >&2
    exit 1
fi

if ! grep -q 'BadInjectedMessage has bare pub field' <<<"$output"; then
    echo "FAIL: failure output didn't flag the bare pub fields" >&2
    echo "Output was:" >&2
    echo "$output" >&2
    exit 1
fi

# False-positive guard: the `BadInjectedMessageBuilder` line MUST
# NOT appear flagged. The regex must require `Message` followed by
# a non-word character to scope the audit correctly.
if grep -q 'BadInjectedMessageBuilder' <<<"$output"; then
    echo "FAIL: false-positive — flagged a *MessageBuilder struct" >&2
    echo "Output was:" >&2
    echo "$output" >&2
    exit 1
fi

echo "PASS: audit-message-accessor-convention.sh failure path works (incl. *MessageBuilder false-positive guard)"
