#!/usr/bin/env bash
# #267 / #271 — every dump terminator goes through the shared classifier.
#
# `NLMSG_DONE` carries the dump's result code as an `int` payload, and
# `NLM_F_DUMP_INTR` says the snapshot is torn. Both were handled in some
# dump loops and not others, because the loop is copy-pasted across
# seven files in three shapes. The pattern was diagnostic: the two
# *older* invariants (seq filter, DONE terminator) were in every copy,
# and the two *newer* ones were in four out of nine.
#
# So the checks live in `netlink/dump_frame.rs` now, and this gate keeps
# them there. A new dump loop that hand-rolls `is_done()` — and
# therefore silently drops the result code again — fails the build.
#
# What counts as a hit:
#   is_done()            hand-rolled DONE terminator
#   NLMSG_DONE =>        the same, in a hand-decoded match
#   nlmsg_flags & 0x10   hand-rolled NLM_F_DUMP_INTR check
#
# ALLOWED holds the sites that are legitimately not dump loops. Each
# needs a reason: a bare "it's fine" entry is how the four unchecked
# loops got there in the first place.

set -euo pipefail

# path:reason
ALLOWED=(
    # The classifier itself, and its tests.
    "crates/nlink/src/netlink/dump_frame.rs:the shared classifier"

    # `is_done()` is defined here.
    "crates/nlink/src/netlink/message.rs:defines is_done()/is_dump_interrupted()"

    # Not dumps. `CTRL_CMD_GETFAMILY` is a single-message doit issued
    # during connection bootstrap; a DONE there is skipped, not a
    # terminator, and there is no dump whose result code could be lost.
    "crates/nlink/src/macros/mod.rs:CTRL_CMD_GETFAMILY bootstrap, single-message doit"
    "crates/nlink/src/netlink/connection.rs:CTRL_CMD_GETFAMILY bootstrap + migrated loops"

    # ACK waiters: these send NLM_F_ACK and wait for the ACK. A DONE is
    # the "nothing to report" answer, not a dump terminator.
    "crates/nlink/src/netlink/genl/nl80211/connection.rs:wait_ack + migrated dump loop"
    "crates/nlink/src/netlink/genl/devlink/connection.rs:wait_ack + migrated dump loops"
    "crates/nlink/src/netlink/genl/ethtool/connection.rs:doit reply reader + migrated dump loops"

    # nftables batch commits are not dumps: they terminate on the
    # BATCH_END ACK, and a DONE is deliberately an error there (#209).
    "crates/nlink/src/netlink/nftables/connection.rs:batch commit treats DONE as an error (#209)"

    # These walk hand-decoded offsets rather than MessageIter, and call
    # `done_result` at the DONE arm. Migrating them to MessageIter would
    # change their parse path (MessageIter self-exhausts where the
    # hand-walk breaks), which is a behavioural change this gate should
    # not force.
    "crates/nlink/src/netlink/sockdiag.rs:hand-decoded walk, calls done_result"
    "crates/nlink/src/netlink/netfilter.rs:hand-decoded walk, calls done_result"
    "crates/nlink/src/netlink/xfrm.rs:hand-decoded walk, calls done_result"

    # Multicast event parsers. There is no dump here: a DONE or ERROR
    # frame arriving on a subscription is skipped, per the
    # parser-robustness policy that one malformed or unexpected frame
    # must not kill a long-lived subscriber.
    "crates/nlink/src/netlink/stream.rs:multicast event parsers skip DONE, no dump"

    # Stream state machines: they drain frames incrementally into a
    # VecDeque and encode termination as flags, so there is no await
    # point to hang the async collector on. Both call `done_result` and
    # check `is_dump_interrupted` inline.
    "crates/nlink/src/netlink/dump_stream.rs:poll_next drainer, calls done_result"
    "crates/nlink/src/macros/genl_dispatch.rs:poll_next drainer, calls done_result"
)

allowed_path() {
    local file="$1" entry
    for entry in "${ALLOWED[@]}"; do
        [ "${entry%%:*}" = "$file" ] && return 0
    done
    return 1
}

hits=$(grep -rnE 'is_done\(\)|NLMSG_DONE[[:space:]]*=>|nlmsg_flags & 0x10' \
    crates/nlink/src --include='*.rs' 2>/dev/null || true)

violations=""
while IFS= read -r line; do
    [ -z "$line" ] && continue
    file="${line%%:*}"
    allowed_path "$file" || violations+="$line"$'\n'
done <<< "$hits"

if [ -n "$violations" ]; then
    echo "audit-dump-termination: hand-rolled dump termination outside the classifier."
    echo
    echo "$violations"
    echo "A dump loop must go through netlink/dump_frame.rs::classify (or, for a"
    echo "hand-decoded walker, call done_result on the NLMSG_DONE payload)."
    echo "Skipping the result code turns a failed dump into a short, successful-"
    echo "looking one; skipping NLM_F_DUMP_INTR uses a torn snapshot (#267, #271)."
    echo
    echo "If this really is not a dump, add it to ALLOWED in $0 with a reason."
    exit 1
fi

echo "audit-dump-termination: dump termination goes through the classifier."
