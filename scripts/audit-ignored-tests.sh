#!/usr/bin/env bash
# Audit: every `#[ignore]` in `crates/nlink/tests/integration/`
# MUST appear in `crates/nlink/tests/integration/IGNORED.md`.
# Closes the gap surfaced by Plan 174: `#[ignore]` is too easy to
# add and accumulates silently — IGNORED.md plus this script make
# it a managed inventory instead of a backdoor.
#
# Per-test fix when the script flags a NEW ignored function:
#   - Genuinely-ignored → add a row to
#     crates/nlink/tests/integration/IGNORED.md with the test name,
#     reason category, and tracking plan/issue.
#   - "Requires root" laziness → drop `#[ignore]` and add
#     `nlink::require_root!()` so the test runs under root in CI.
#   - One-off debug ignore → un-ignore before merging.
#
# Pure bash; no toolchain step needed.

set -euo pipefail

INTEGRATION_DIR="crates/nlink/tests/integration"
CATALOG="$INTEGRATION_DIR/IGNORED.md"

if [[ ! -f "$CATALOG" ]]; then
    echo "ERROR: $CATALOG not found — run from repo root." >&2
    exit 2
fi

# Extract every test function name following an `#[ignore]` attribute
# in the integration suite. The match requires the attribute form at
# the start of a line (optionally indented) — `#[ignore]`,
# `#[ignore = "..."]`, or the first line of a multi-line
# `#[ignore = "..."]` continuation. This rejects in-comment mentions
# like `// see #[ignore]` or `/// **#[ignore] on CI**` that would
# otherwise false-positive into the catalog audit.
ignored_tests=$(
    find "$INTEGRATION_DIR" -name '*.rs' -type f -print0 \
        | xargs -0 awk '
            /^[[:space:]]*#\[ignore(\]| = )/ { in_ignore=1; next }
            in_ignore && /^[[:space:]]*(pub[[:space:]]+)?(async[[:space:]]+)?fn[[:space:]]+/ {
                sub(/.*fn[[:space:]]+/, "")
                sub(/[(<].*$/, "")
                print
                in_ignore=0
            }
        ' \
        | sort -u
)

if [[ -z "$ignored_tests" ]]; then
    echo "OK: no #[ignore]'d tests found in $INTEGRATION_DIR (nothing to audit)"
    exit 0
fi

uncatalogued=0
while IFS= read -r name; do
    [[ -z "$name" ]] && continue
    # Match `| <name> |` (table row) or backtick-quoted in prose.
    if grep -qE "(\| \`?${name}\`? \||\`${name}\`)" "$CATALOG"; then
        continue
    fi
    echo "::error::ignored test \`$name\` not catalogued in $CATALOG"
    echo "  fix: add a row to the appropriate section of IGNORED.md, or"
    echo "       drop \`#[ignore]\` and add \`nlink::require_root!()\` if"
    echo "       it's only ignored to skip non-root environments."
    uncatalogued=$((uncatalogued+1))
done <<<"$ignored_tests"

total=$(wc -l <<<"$ignored_tests")
if [[ $uncatalogued -gt 0 ]]; then
    echo
    echo "Found $uncatalogued uncatalogued ignored test(s) out of $total total."
    echo "See CHANGELOG.md ## [0.17.0] 'CI observability' for context."
    exit 1
fi

# Reverse check: catalog entries that no longer exist on disk.
stale_entries=0
catalog_names=$(
    awk -F'|' '
        # Match table rows: `| <name> | <reason> | <tracking> |`
        # Skip header + separator rows.
        /^\| / && !/^\| ---/ && !/^\| Test \|/ {
            gsub(/`/, "", $2)
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", $2)
            if ($2 != "" && $2 !~ /^Test$/) print $2
        }
    ' "$CATALOG" | sort -u
)

while IFS= read -r name; do
    [[ -z "$name" ]] && continue
    if ! grep -qF "$name" <<<"$ignored_tests"; then
        echo "::warning::catalog entry \`$name\` no longer exists as an ignored test — prune it from $CATALOG"
        stale_entries=$((stale_entries+1))
    fi
done <<<"$catalog_names"

if [[ $stale_entries -gt 0 ]]; then
    echo "Stale catalog entries (informational, not a failure)."
fi

echo "OK: every #[ignore] in $INTEGRATION_DIR is catalogued in $CATALOG ($total total)"
