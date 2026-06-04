#!/usr/bin/env bash
# Plan 223 — block `from_le_bytes` re-entry in the netlink lib.
#
# NLA headers (`struct nlattr` in include/uapi/linux/netlink.h)
# and the bulk of attribute payloads the kernel emits are
# kernel-native endian. The 0.19 N3 fix swapped `from_le_bytes`
# for `from_ne_bytes` in `xfrm.rs`; the 0.20 sweep covered the
# three other sites (`netfilter.rs`, `action.rs`,
# `nftables/config/diff.rs`). This script keeps the class
# closed by failing the build if `from_le_bytes` reappears.
#
# The few documented LE-on-the-wire cases belong in ALLOWED
# with a comment explaining the kernel-side wire contract.
# Allow-list initially empty: every NLA / TC / nft / xfrm /
# conntrack TLV the kernel emits is native-endian.

set -euo pipefail

ALLOWED=(
    # (intentionally empty as of 0.20.1 — every NLA / TC / nft /
    # xfrm / conntrack TLV the kernel emits is native-endian.)
    #
    # If you legitimately need an LE-on-the-wire reader, append
    # the file path here with a comment explaining the kernel-side
    # wire contract. Reviewers will see ALLOWED additions in PR
    # diffs.
)

# Search the production lib tree. Test fixtures inside the lib
# (`#[cfg(test)] mod ...`) are also flipped to `from_ne_bytes`
# for hygiene, so the audit is uniform across the tree.
hits=$(
    grep -rn --include='*.rs' \
        'from_le_bytes' \
        crates/nlink/src/netlink/ || true
)

# Filter out ALLOWED files.
if [[ -n "$hits" ]]; then
    filtered=""
    while IFS= read -r line; do
        file="${line%%:*}"
        allowed=false
        for ok in "${ALLOWED[@]}"; do
            if [[ "$file" == "$ok" ]]; then
                allowed=true
                break
            fi
        done
        if ! $allowed; then
            # Also skip lines that are clearly comments referencing
            # the bug class historically — these are documentation,
            # not actual reads.
            rest="${line#*:}"
            content="${rest#*:}"
            trimmed="$(echo "$content" | sed -E 's/^[[:space:]]+//')"
            if [[ "$trimmed" =~ ^/// ]] || [[ "$trimmed" =~ ^//[^/!] ]] || [[ "$trimmed" =~ ^//!  ]]; then
                continue
            fi
            if [[ -n "$filtered" ]]; then
                filtered="${filtered}"$'\n'"${line}"
            else
                filtered="${line}"
            fi
        fi
    done <<< "$hits"
    hits="$filtered"
fi

if [[ -n "$hits" ]]; then
    echo "ERROR: from_le_bytes found in netlink lib outside ALLOWED:" >&2
    echo "$hits" >&2
    echo "" >&2
    echo "NLA headers and attribute payloads are kernel-native" >&2
    echo "endian. If your case is genuinely LE-on-the-wire, add" >&2
    echo "the file path to ALLOWED in scripts/audit-bytes-le.sh" >&2
    echo "with a comment explaining the kernel-side wire contract." >&2
    echo "See Plan 223 and CLAUDE.md \`## Parser robustness\`." >&2
    exit 1
fi

echo "audit-bytes-le: no native/little-endian drift in crates/nlink/src/netlink/"
