#!/usr/bin/env bash
# #232 — fail CI if any hand-transcribed UAPI constant in nlink disagrees with
# the kernel headers.
#
# nlink owns its wire format end to end (no rtnetlink, no netlink-packet-*),
# which is the design's whole point — and its one structural liability: every
# attribute id, message type and enum value in the crate was typed in by hand
# from a kernel header. Transcription drifts, and it drifts *silently*: the
# kernel happily accepts a well-formed message that names the wrong attribute.
#
# The 0.25.0 cycle found eight independent drifts this way. The worst
# (#196) split ETHTOOL_A_LINKMODES_OURS into two variants, so every id after it
# was one too high and **link speed read as None forever** — on the request path
# and the multicast path, with no error anywhere. Two more (#230's PAD, #229's
# PhyGet) were found only because somebody happened to be reading the header.
# The last two were found by this script on its first run.
#
# So: check them all, every push. See scripts/audit_uapi_constants.py for how,
# scripts/audit-uapi-constants.map for the enum->prefix mapping, and
# scripts/audit-uapi-constants.allowlist for the enums that genuinely have no
# kernel counterpart.

set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"

if ! command -v python3 >/dev/null 2>&1; then
    echo "SKIP: python3 not found"
    exit 0
fi

HEADERS="${NLINK_UAPI_HEADER_DIR:-/usr/include/linux}"
if [[ ! -d "$HEADERS" ]]; then
    echo "SKIP: $HEADERS not present — install the kernel headers"
    echo "      (Fedora: kernel-headers; Debian/Ubuntu: linux-libc-dev)"
    exit 0
fi

exec python3 "$REPO_ROOT/scripts/audit_uapi_constants.py"
