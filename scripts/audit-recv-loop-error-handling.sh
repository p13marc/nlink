#!/usr/bin/env bash
# Audit: event-parser recv loops in stream.rs MUST silently skip
# malformed frames rather than propagating via the `?` operator.
#
# Why: long-lived multicast subscribers (Plan 185 nftables
# watcher, Plan 191 route watcher, Plan 199 wireguard watcher)
# must NOT die on one malformed frame from a future kernel.
# neli #305 tracks the bug class.
#
# Pattern we WANT inside `for ... in MessageIter::new(data)`:
#   - `.flatten()` chained on the iterator, OR
#   - `let Ok(...) = msg_result else { continue };`
#
# Pattern we REJECT:
#   - `let (header, payload) = msg_result?;` (propagates the
#     parse failure up + aborts the whole batch)
#
# This script greps for `?` operator on a line inside or right
# below a `for ... MessageIter::new` pattern in stream.rs and
# fails if any hits. CLAUDE.md §"Parser robustness" §3 pins the
# convention.

set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

STREAM_RS="crates/nlink/src/netlink/stream.rs"

if [[ ! -f "$STREAM_RS" ]]; then
    echo "ERROR: $STREAM_RS not found" >&2
    exit 1
fi

# Find every `for ... in MessageIter::new` line, then check the
# next ~5 lines for a `?` operator (the smell). False-positives
# are rare since MessageIter walks are stylized; real
# false-positives would need to be allowlisted explicitly.

violations=0

awk '
    /for.*in MessageIter::new/ {
        in_loop = 1
        loop_start = NR
        next
    }
    in_loop {
        # Lookahead window: 8 lines.
        if (NR - loop_start > 8) {
            in_loop = 0
            next
        }
        # Match `?;` at end of an unwrap-like pattern. Skip
        # `Ok(...) else { continue }` and `flatten()` patterns
        # by checking the loop start lines too.
        if ($0 ~ /\?;[[:space:]]*$/ || $0 ~ /\?\.[a-z_]/) {
            print FILENAME ":" NR ": potential `?` inside MessageIter walk"
            print "  context: " $0
            exit 1
        }
        # Detect the end of the for-loop body (heuristic: closing
        # brace at column 0 or 4 — outside the inner scope).
        if ($0 ~ /^[[:space:]]{0,8}}$/ && NR > loop_start + 1) {
            in_loop = 0
        }
    }
' "$STREAM_RS" && {
    echo "audit-recv-loop-error-handling: stream.rs clean."
    exit 0
} || {
    echo "ERROR: stream.rs has a `?` operator inside a MessageIter walk." >&2
    echo "Per CLAUDE.md §\"Parser robustness\" §3, event parsers must" >&2
    echo "silently skip parse errors via .flatten() or" >&2
    echo "\`let Ok(...) = msg_result else { continue };\` — never \`?\`." >&2
    exit 1
}
