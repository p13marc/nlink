#!/usr/bin/env bash
# Audit: README.md MUST stay in sync with the workspace manifest.
#
# Why this exists: the README is hand-maintained prose, but several
# of its claims are *facts owned by Cargo.toml* — the published
# version pin, the MSRV, and the binary package names. Those drift
# silently. PR #14 had to fix a stale README; this gate stops the
# next drift from landing. The four cross-cutting binary-audit
# issues (#15, #30) name "README drifts silently — no CI gate" as
# the root cause.
#
# Checks (all derived from the workspace Cargo.toml, never
# hard-coded here):
#   1. The `nlink = "X.Y"` install pin matches the workspace
#      version's major.minor.
#   2. The `MSRV: Rust X.Y` line matches `rust-version`.
#   3. Every `-p <pkg>` referenced in a README command is a real
#      workspace package.
#
# Pure bash + standard coreutils; ~1s. No network, no cargo build.

set -euo pipefail

cd "$(dirname "$0")/.."

README="README.md"
ROOT_MANIFEST="Cargo.toml"

fail=0
err() {
    echo "check-readme: ERROR: $*" >&2
    fail=1
}

# --- 1. version pin --------------------------------------------------

# Workspace version (first `version = "..."` under [workspace.package]).
ws_version="$(grep -m1 '^version = ' "$ROOT_MANIFEST" | sed -E 's/.*"([^"]+)".*/\1/')"
if [[ -z "$ws_version" ]]; then
    err "could not read workspace version from $ROOT_MANIFEST"
fi
ws_majmin="$(echo "$ws_version" | cut -d. -f1,2)"

# README pin: `nlink = "X.Y"` or `nlink = "X.Y.Z"`.
readme_pin="$(grep -E '^nlink = "[0-9]' "$README" | head -n1 | sed -E 's/.*"([^"]+)".*/\1/' || true)"
if [[ -z "$readme_pin" ]]; then
    err "no \`nlink = \"X.Y\"\` install pin found in $README"
else
    readme_majmin="$(echo "$readme_pin" | cut -d. -f1,2)"
    if [[ "$readme_majmin" != "$ws_majmin" ]]; then
        err "README install pin \`nlink = \"$readme_pin\"\` does not match workspace version $ws_version (expected major.minor $ws_majmin)"
    fi
fi

# --- 2. MSRV --------------------------------------------------------

ws_msrv="$(grep -m1 '^rust-version = ' "$ROOT_MANIFEST" | sed -E 's/.*"([^"]+)".*/\1/')"
if [[ -n "$ws_msrv" ]]; then
    if ! grep -qE "MSRV:[[:space:]]*Rust[[:space:]]+$ws_msrv\b" "$README"; then
        err "README MSRV line does not match workspace rust-version $ws_msrv (expected \"MSRV: Rust $ws_msrv\")"
    fi
fi

# --- 3. package names in commands -----------------------------------

# Collect every workspace package name once.
mapfile -t pkgs < <(grep -rh '^name = ' bins/*/Cargo.toml crates/*/Cargo.toml | sed -E 's/.*"([^"]+)".*/\1/' | sort -u)
is_pkg() {
    local needle="$1"
    for p in "${pkgs[@]}"; do
        [[ "$p" == "$needle" ]] && return 0
    done
    return 1
}

# Every `-p <name>` token that appears in the README must resolve.
while read -r pkg; do
    [[ -z "$pkg" ]] && continue
    if ! is_pkg "$pkg"; then
        err "README references \`-p $pkg\` but no such workspace package exists"
    fi
done < <(grep -oE '\-p +[A-Za-z0-9_-]+' "$README" | sed -E 's/-p +//' | sort -u)

if [[ "$fail" -ne 0 ]]; then
    echo "check-readme: README.md is out of sync with the workspace manifest (see errors above)." >&2
    exit 1
fi

echo "check-readme: README.md is in sync (version $ws_majmin, MSRV $ws_msrv, package refs OK)."
