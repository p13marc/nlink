#!/usr/bin/env bash
# Plan 231 (0.21) — fail CI if any `*Message` struct in
# crates/nlink/src/netlink/messages/ has all-public fields without
# accessor methods.
#
# Rationale: every shipped `*Message` type wraps a parsed netlink
# response. The convention (see CLAUDE.md "Parser robustness" +
# Plan 231 §3) is:
#
#   1. Fields are `pub(crate)`.
#   2. The struct carries `#[non_exhaustive]`.
#   3. Each load-bearing field has a `pub fn name(&self) -> T`
#      accessor.
#
# All-pub fields leak the parser's internal layout to downstream
# code, which becomes a public-API break the moment the kernel
# adds an attribute or we re-layout the struct.
#
# The audit fires on any `pub struct *Message<...>` or
# `pub struct *Message {` that either:
#   - lacks `#[non_exhaustive]` on the preceding 5 lines, OR
#   - has bare `pub <name>:` field declarations inside the struct
#     body (delimited by the matching `{` and `}` braces).
#
# `*MessageBuilder` and other types whose name continues past
# `Message` are explicitly excluded — they're builders / wrappers,
# not the parsed messages themselves.

set -euo pipefail

MESSAGES_DIR="crates/nlink/src/netlink/messages"

if [[ ! -d "$MESSAGES_DIR" ]]; then
    echo "audit-message-accessor-convention: $MESSAGES_DIR not found" >&2
    exit 0
fi

violations=0
TMP_VIOLATIONS="$(mktemp)"
trap 'rm -f "$TMP_VIOLATIONS"' EXIT

# Strict match: `pub struct Name` where Name ENDS in `Message`
# (followed by `<`, `{`, or whitespace — not by another letter
# that would turn it into MessageBuilder, etc.).
audit_file() {
    local file="$1"
    awk -v FILE="$file" -v OUT="$TMP_VIOLATIONS" '
        function emit(msg) {
            print msg >> OUT
        }

        # Track every line for the look-back window.
        { history[NR] = $0 }

        # Match `pub struct *Message` where the name ends with
        # `Message` followed by a boundary (`<`, `{`, space, or EOL).
        match($0, /^[[:space:]]*pub struct ([A-Za-z_][A-Za-z0-9_]*Message)([^A-Za-z0-9_]|$)/, m) {
            struct_name = m[1]

            # Look back 5 lines for #[non_exhaustive] — but only
            # match a real attribute (line starts with optional
            # whitespace then `#[non_exhaustive]`), not a mention
            # inside a doc comment or string.
            non_exh = 0
            for (j = 1; j <= 5 && (NR - j) >= 1; j++) {
                if (history[NR - j] ~ /^[[:space:]]*#\[non_exhaustive\]/) {
                    non_exh = 1
                    break
                }
            }
            if (!non_exh) {
                emit("VIOLATION: " FILE ":" NR ": " struct_name " missing #[non_exhaustive]")
            }

            # Track brace depth from this line.
            depth = 0
            for (i = 1; i <= length($0); i++) {
                ch = substr($0, i, 1)
                if (ch == "{") depth++
                else if (ch == "}") depth--
            }
            in_struct = 1
            next
        }

        # Inside a struct body, check for bare `pub name:` fields.
        in_struct {
            # Skip `pub(crate)`, `pub(super)`, `pub fn`, etc.
            if ($0 ~ /^[[:space:]]+pub [a-zA-Z_][a-zA-Z0-9_]*:/) {
                emit("VIOLATION: " FILE ":" NR ": " struct_name " has bare pub field: " $0)
            }
            for (i = 1; i <= length($0); i++) {
                ch = substr($0, i, 1)
                if (ch == "{") depth++
                else if (ch == "}") depth--
            }
            if (depth <= 0) {
                in_struct = 0
            }
        }
    ' "$file"
}

for file in $(find "$MESSAGES_DIR" -name '*.rs' -type f | sort); do
    audit_file "$file"
done

# 0.21 — sibling parsed-result types outside messages/ that follow
# the same convention. These are constructed by parser code (not by
# users), so they share the convention rationale: fields hidden,
# struct non-exhaustive, accessors public.
SIBLING_AUDIT_FILES=(
    "crates/nlink/src/netlink/bridge_vlan.rs"
    "crates/nlink/src/netlink/fdb.rs"
    "crates/nlink/src/netlink/mpls.rs"
    "crates/nlink/src/netlink/nexthop.rs"
)
SIBLING_TARGETS=(
    "BridgeVlanEntry"
    "FdbEntry"
    "MplsRoute"
    "Nexthop"
)

for idx in "${!SIBLING_AUDIT_FILES[@]}"; do
    file="${SIBLING_AUDIT_FILES[$idx]}"
    target="${SIBLING_TARGETS[$idx]}"
    if [[ ! -f "$file" ]]; then
        continue
    fi
    awk -v FILE="$file" -v OUT="$TMP_VIOLATIONS" -v TGT="$target" '
        function emit(msg) {
            print msg >> OUT
        }
        { history[NR] = $0 }
        $0 ~ ("^[[:space:]]*pub struct " TGT "([^A-Za-z0-9_]|$)") {
            non_exh = 0
            for (j = 1; j <= 5 && (NR - j) >= 1; j++) {
                if (history[NR - j] ~ /^[[:space:]]*#\[non_exhaustive\]/) {
                    non_exh = 1
                    break
                }
            }
            if (!non_exh) {
                emit("VIOLATION: " FILE ":" NR ": " TGT " missing #[non_exhaustive]")
            }
            depth = 0
            for (i = 1; i <= length($0); i++) {
                ch = substr($0, i, 1)
                if (ch == "{") depth++
                else if (ch == "}") depth--
            }
            in_struct = 1
            next
        }
        in_struct {
            if ($0 ~ /^[[:space:]]+pub [a-zA-Z_][a-zA-Z0-9_]*:/) {
                emit("VIOLATION: " FILE ":" NR ": " TGT " has bare pub field: " $0)
            }
            for (i = 1; i <= length($0); i++) {
                ch = substr($0, i, 1)
                if (ch == "{") depth++
                else if (ch == "}") depth--
            }
            if (depth <= 0) {
                in_struct = 0
            }
        }
    ' "$file"
done

if [[ -s "$TMP_VIOLATIONS" ]]; then
    cat "$TMP_VIOLATIONS" >&2
    violations="$(wc -l < "$TMP_VIOLATIONS")"
    echo "" >&2
    echo "$violations message-accessor-convention violation(s) in $MESSAGES_DIR." >&2
    echo "" >&2
    echo "Convention (CLAUDE.md + Plan 231):" >&2
    echo "  - Struct has #[non_exhaustive]." >&2
    echo "  - Fields are pub(crate), not bare pub." >&2
    echo "  - Each field has a pub accessor method." >&2
    exit 1
fi

echo "audit-message-accessor-convention: $MESSAGES_DIR clean"
