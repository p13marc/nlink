#!/usr/bin/env bash
# Plan 229 (0.21) — fail CI if recipe markdown under docs/recipes/
# contains known-stale API patterns that the 0.19/0.20/0.21
# breaking-change waves rendered uncompilable.
#
# Scope: cheap grep-based audit. The 0.21 cycle's recipe-test
# harness (a synthetic compile-fixture per recipe block) is the
# durable answer for full compile validation; this script is the
# stop-gap that catches the high-frequency drift patterns.

set -euo pipefail

RECIPES_DIR="docs/recipes"
if [[ ! -d "$RECIPES_DIR" ]]; then
    echo "audit-recipe-drift: $RECIPES_DIR not found" >&2
    exit 0
fi

# Each PATTERN regex flags a known-stale shape.
# Use literal-friendly regex (POSIX ERE).
declare -a PATTERNS=(
    # 0.19 F1 async-ification: events() / into_events() must take .await
    'conn\.events\(\)[^.]'
    'conn\.into_events\(\)[^.]'
    # 0.20.1 → 0.21 typed netem (loss removed)
    '\.loss\(1\.[0-9]'
    '\.loss\([0-9]+\.0\)'
    # 0.19 Plan 211 split Hook::Ingress
    'Hook::Ingress\b'
    # 0.19 Plan 205 removed with_purge
    'with_purge'
    # 0.15 removed tc/options/*
    'tc/options/'
    # 0.21 removed Verdict::Jump(String) / Verdict::Goto(String)
    'Verdict::Jump\("'
    'Verdict::Goto\("'
    # 0.21 removed flush_rules(libc::AF_*); typed AddressFamily only
    'flush_rules\(libc::AF_'
    # WG private_key "always None" claim corrected by PR #9
    'private_key.*always.*None'
)

violations=0
for pattern in "${PATTERNS[@]}"; do
    while IFS= read -r line; do
        echo "VIOLATION: $line" >&2
        violations=$((violations + 1))
    done < <(grep -nrE "$pattern" "$RECIPES_DIR" 2>/dev/null || true)
done

if [[ "$violations" -gt 0 ]]; then
    echo "" >&2
    echo "$violations doc-drift pattern(s) in $RECIPES_DIR." >&2
    echo "" >&2
    echo "Each match is a known-stale API call from a previous breaking" >&2
    echo "wave. Update the recipe to the current API. Reference patterns:" >&2
    echo "  conn.events()       → conn.events().await" >&2
    echo "  conn.into_events()  → conn.into_events().await" >&2
    echo "  .loss(1.5)          → .loss_pct(Percent::new(1.5))" >&2
    echo "  Hook::Ingress       → Hook::NetdevIngress or Hook::InetIngress" >&2
    echo "  with_purge          → (remove; the feature was always non-functional)" >&2
    echo "  Verdict::Jump(s)    → Verdict::JumpTo(ChainName::new(s)?)" >&2
    echo "  flush_rules(libc::) → flush_rules(AddressFamily::v4())" >&2
    exit 1
fi

echo "audit-recipe-drift: $RECIPES_DIR clean"
