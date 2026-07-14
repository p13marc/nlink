#!/usr/bin/env bash
# Plan 192 §2.7 — fail CI if any /sys/class/net/ or /proc/sys/
# read appears in crates/nlink/src/netlink/ outside the
# explicitly-allowed files.
#
# Rationale: those paths are read in the calling process's
# mount namespace, which is the wrong namespace when the
# library is called from a thread bound to a foreign netns
# (CNI plugins, multi-tenant managers, integration-test
# harnesses). The lib uses RTNETLINK for everything else; the
# `sysctl` module is the documented exception because
# `/proc/sys/net/...` IS the kernel-blessed way to read
# sysctls from a process attached to a netns.
#
# If a new file needs to read sysfs (e.g. ethtool fallback,
# diagnostics), add it to the ALLOWED list explicitly + add a
# rustdoc note explaining why.

set -euo pipefail

ALLOWED=(
    # /proc/sys IS the namespace-correct path for sysctls.
    "crates/nlink/src/netlink/sysctl.rs"
    # /proc/net/psched carries the packet-scheduler clock constants
    # (PSCHED_SHIFT, HZ). They are compile-time kernel globals, identical
    # in every netns, so reading them through the caller's mount namespace
    # is not a namespace-correctness hazard — unlike per-netns device state
    # or sysctls. Read once per process, with the same constants as the
    # fallback. See the module header for the full rationale.
    "crates/nlink/src/netlink/psched.rs"
)

# Search the lib for literal sysfs/procfs reads. Surface anything
# outside ALLOWED.
#
# /proc/net/ (not the broader /proc/) is deliberate: the many
# /proc/<pid>/ns/net and /proc/thread-self/ns/net opens in namespace.rs
# are namespace-correct by construction and must not be swept in.
PATTERNS=(
    "/sys/class/net/"
    "/proc/sys/"
    "/proc/net/"
)

violations=0
for pattern in "${PATTERNS[@]}"; do
    while IFS= read -r line; do
        # Each line is "path:lineno:content"
        file="${line%%:*}"
        # Strip up to the content portion (after second `:`).
        rest="${line#*:}"
        content="${rest#*:}"
        # Skip rustdoc / line comments — those are policy
        # references, not actual sysfs reads.
        trimmed="$(echo "$content" | sed -E 's/^[[:space:]]+//')"
        if [[ "$trimmed" =~ ^/// ]] || [[ "$trimmed" =~ ^//[^/!] ]] || [[ "$trimmed" =~ ^//!  ]]; then
            continue
        fi
        # Skip ALLOWED files.
        allowed=false
        for ok in "${ALLOWED[@]}"; do
            if [[ "$file" == "$ok" ]]; then
                allowed=true
                break
            fi
        done
        if ! $allowed; then
            echo "VIOLATION: $line" >&2
            violations=$((violations + 1))
        fi
    done < <(grep -rn --include='*.rs' -- "$pattern" crates/nlink/src/netlink/ 2>/dev/null || true)
done

if [[ $violations -gt 0 ]]; then
    echo "" >&2
    echo "$violations namespace-unsafe sysfs/procfs read(s) in the lib." >&2
    echo "If a new read is legitimate, add the file to ALLOWED in" >&2
    echo "  scripts/audit-sysfs-in-lib.sh" >&2
    echo "and document why in a rustdoc comment." >&2
    exit 1
fi

echo "audit-sysfs-in-lib: no namespace-unsafe reads in crates/nlink/src/netlink/"
