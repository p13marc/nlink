#!/usr/bin/env bash
# audit-example-features.sh — find [[example]] entries that import
# feature-gated modules without declaring the matching `required-features`.
#
# Background: 0.15.0 shipped with `examples/xfrm/ipsec_monitor.rs` using
# `nlink::lab::with_namespace` but its [[example]] entry didn't declare
# `required-features = ["lab"]`. Result: `cargo test --workspace`
# (default features) failed to compile the example. This script catches
# that class of regression.
#
# Usage:   scripts/audit-example-features.sh
# Exit 0:  no mismatches.
# Exit 1:  one or more mismatches found (script prints the pairs).
#
# This script is a diagnostic for contributors. The enforcement layer
# is the `build-and-test-default-features` CI job in
# `.github/workflows/rust.yml` — that job runs `cargo test --workspace`
# without features and fails loud on the same class of bug.

set -euo pipefail

CARGO_TOML="crates/nlink/Cargo.toml"
EXAMPLES_DIR="crates/nlink/examples"

if [[ ! -f "$CARGO_TOML" ]]; then
  echo "error: run this script from the workspace root (current: $(pwd))" >&2
  exit 2
fi

# Feature → module-path mapping. Extend if new optional features land.
# Format: "feature_name:rust_path_prefix"
declare -a FEATURE_MAP=(
  "lab:nlink::lab"
  "sockdiag:nlink::sockdiag"
  "tuntap:nlink::tuntap"
  "output:nlink::output"
  "namespace_watcher:nlink::namespace_watcher"
)

# Parse [[example]] entries from Cargo.toml. Each entry is a small TOML
# stanza with `name = "..."`, `path = "..."`, optional
# `required-features = [...]`. Awk pulls out (name, path, required-features)
# triples in CSV.
parse_examples() {
  awk '
    function flush() {
      if (in_example && name != "") {
        print name "|" path "|" required
      }
      name = ""; path = ""; required = ""
    }
    /^\[\[example\]\]/ {
      flush()
      in_example = 1
      next
    }
    /^\[/ && !/^\[\[example\]\]/ {
      flush()
      in_example = 0
      next
    }
    in_example && /^name = / {
      gsub(/^name = "/, "", $0); gsub(/"$/, "", $0); name = $0
    }
    in_example && /^path = / {
      gsub(/^path = "/, "", $0); gsub(/"$/, "", $0); path = $0
    }
    in_example && /^required-features = / {
      gsub(/^required-features = /, "", $0); required = $0
    }
    END { flush() }
  ' "$CARGO_TOML"
}

mismatches=0
total=0

while IFS='|' read -r name path required; do
  [[ -z "$name" ]] && continue
  total=$((total + 1))
  src="crates/nlink/$path"

  if [[ ! -f "$src" ]]; then
    echo "warn: example '$name' references missing source $src" >&2
    continue
  fi

  for entry in "${FEATURE_MAP[@]}"; do
    feature="${entry%%:*}"
    prefix="${entry##*:}"

    # Does the source import this feature-gated module?
    if grep -qE "use $prefix(::|;)|$prefix::" "$src"; then
      # Does the [[example]] entry declare this feature as required?
      if [[ "$required" != *"\"$feature\""* ]]; then
        echo "MISMATCH: example '$name'"
        echo "    path:     $path"
        echo "    imports:  $prefix"
        echo "    feature:  $feature"
        echo "    declared: ${required:-(none)}"
        echo "    fix:      add 'required-features = [\"$feature\"]' to the [[example]] entry in $CARGO_TOML"
        echo
        mismatches=$((mismatches + 1))
      fi
    fi
  done
done < <(parse_examples)

echo "audit-example-features.sh: scanned $total examples; $mismatches mismatch(es)."

if [[ $mismatches -gt 0 ]]; then
  exit 1
fi
exit 0
