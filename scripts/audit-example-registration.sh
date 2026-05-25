#!/usr/bin/env bash
# Audit: every `.rs` file under crates/nlink/examples/ MUST be
# registered as a [[example]] entry in crates/nlink/Cargo.toml,
# UNLESS it's listed in scripts/audit-example-registration.allowlist
# (a per-line list of known-orphan paths, documented in
# plans/160-example-registry-audit.md).
#
# Why this exists: Cargo only auto-discovers examples at the
# top level of `examples/` (one level deep). Files in
# subdirectories like `examples/route/mpls.rs`, `examples/bridge/
# vlan.rs`, etc. are invisible to cargo unless explicitly declared
# via [[example]] name=… path=…  in Cargo.toml. Without that
# registration, `cargo build --workspace --all-targets` never
# compiles them — they bit-rot silently against API changes for
# years.
#
# The allowlist is the bridge between "we know about these
# orphans but resolving them is a separate maintainer-judgment
# decision (see Plan 160)" and "no new orphans should sneak in".
# As Plan 160 triages each orphan, the allowlist shrinks; once
# empty it can be deleted.
#
# Per-example fix when the script flags a NEW (un-allowlisted) file:
#   - Working example → add an [[example]] block to Cargo.toml.
#   - Stale example   → update it to current API + register, OR
#                       delete it.
#   - Genuinely-orphan-intentionally → add to the allowlist with
#                       a one-line justifying comment.

set -euo pipefail

CARGO="crates/nlink/Cargo.toml"
EXAMPLES_DIR="crates/nlink/examples"
ALLOWLIST="scripts/audit-example-registration.allowlist"

if [[ ! -f "$CARGO" ]]; then
    echo "ERROR: $CARGO not found — run from repo root." >&2
    exit 2
fi

# Build the allowlist as a sorted set (skips blank lines + #-only
# lines + trailing `# ...` comments after each path; whitespace
# trimmed).
allowed=""
if [[ -f "$ALLOWLIST" ]]; then
    allowed=$(
        grep -vE '^\s*(#|$)' "$ALLOWLIST" \
            | sed -E 's/[[:space:]]*#.*$//; s/[[:space:]]+$//' \
            | sort -u || true
    )
fi

is_allowlisted() {
    local rel="$1"
    [[ -n "$allowed" ]] && grep -qxF "$rel" <<<"$allowed"
}

new_orphans=0
allowlist_seen=""

while IFS= read -r f; do
    # Path relative to crates/nlink/ since that's what
    # `path = "examples/..."` references in Cargo.toml.
    rel="${f#crates/nlink/}"
    if grep -qF "path = \"$rel\"" "$CARGO"; then
        continue  # registered — good
    fi
    if is_allowlisted "$rel"; then
        allowlist_seen="${allowlist_seen}${rel}"$'\n'
        continue  # known orphan — exempted
    fi
    # NEW orphan — fail loudly.
    echo "::error file=$f::example $rel not registered in $CARGO (and not allowlisted)"
    echo "  fix: add this block to $CARGO:"
    name=$(echo "$rel" | sed 's|^examples/||; s|\.rs$||; s|/|_|g')
    echo "    [[example]]"
    echo "    name = \"$name\""
    echo "    path = \"$rel\""
    echo
    new_orphans=$((new_orphans+1))
done < <(find "$EXAMPLES_DIR" -name '*.rs' -type f | sort)

# Detect dead allowlist entries (paths in the allowlist that no
# longer exist on disk — likely because the orphan was deleted or
# fixed but the allowlist wasn't pruned).
stale_allowlist=0
if [[ -n "$allowed" ]]; then
    while IFS= read -r rel; do
        [[ -z "$rel" ]] && continue
        if [[ ! -f "crates/nlink/$rel" ]]; then
            echo "::warning::allowlist entry $rel no longer exists on disk — prune it from $ALLOWLIST"
            stale_allowlist=$((stale_allowlist+1))
        fi
    done <<<"$allowed"
fi

if [[ $new_orphans -gt 0 ]]; then
    echo "Found $new_orphans NEW unregistered example file(s)."
    echo "See plans/160-example-registry-audit.md for context."
    exit 1
fi

if [[ $stale_allowlist -gt 0 ]]; then
    echo "Stale allowlist entries (informational, not a failure)."
fi

allowlist_count=$(grep -cvE '^\s*(#|$)' "$ALLOWLIST" 2>/dev/null || echo 0)
echo "OK: every $EXAMPLES_DIR/*.rs is registered or allowlisted"
echo "    (allowlist holds $allowlist_count known orphan(s); shrink as Plan 160 triages)"
