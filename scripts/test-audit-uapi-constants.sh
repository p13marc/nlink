#!/usr/bin/env bash
# Self-test for audit-uapi-constants.sh (#232).
#
# An audit script that cannot fail is not a gate, it is a decoration. This
# reconstructs the real drifts the 0.25.0 cycle fixed, in a throwaway copy of
# the tree, and asserts the audit catches each one — plus the two structural
# escape hatches (an unclassified enum, an invented variant).
#
# Cases:
#   1. clean tree                    -> pass
#   2. #196   LINKMODES off by one   -> caught
#   3. #227   ETH_SS missing FEATURES-> caught
#   4. #231   BssStatus starts at 1  -> caught
#   5. new enum, unclassified        -> caught (nobody is checking it)
#   6. invented variant in a UAPI enum -> caught (no such kernel constant)
#   7. older build host, vouched-for  -> skipped, not failed
#   8. older build host, UNvouched    -> still caught (the hole stays closed)

set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
SCRIPT_REL="scripts/audit-uapi-constants.sh"

if ! command -v python3 >/dev/null 2>&1 || [[ ! -d /usr/include/linux ]]; then
    echo "SKIP: needs python3 + /usr/include/linux"
    exit 0
fi

WORK_DIR="$(mktemp -d -t audit-uapi-test.XXXXXX)"
trap 'rm -rf "$WORK_DIR"' EXIT

# Copy the *working tree*, not HEAD: the point is to test the audit as it stands
# right now, including changes not yet committed.
mkdir -p "$WORK_DIR/crates/nlink"
cp -r "$REPO_ROOT/scripts" "$WORK_DIR/scripts"
cp -r "$REPO_ROOT/crates/nlink/src" "$WORK_DIR/crates/nlink/src"

# The wrapper locates the repo with `git rev-parse --show-toplevel`, and the
# fixture cases revert with `git checkout`, so the copy needs to be a git repo.
git -C "$WORK_DIR" init -q
git -C "$WORK_DIR" add -A >/dev/null
git -C "$WORK_DIR" -c user.email=t@t -c user.name=t commit -qm fixture >/dev/null

ETHTOOL="$WORK_DIR/crates/nlink/src/netlink/genl/ethtool/mod.rs"
NL80211="$WORK_DIR/crates/nlink/src/netlink/genl/nl80211/types.rs"
FAILURES=0

run_audit() {
    (cd "$WORK_DIR" && bash "$SCRIPT_REL" 2>&1)
}

expect_pass() {
    local case_name="$1"
    if run_audit >/dev/null 2>&1; then
        echo "  ok   $case_name"
    else
        echo "  FAIL $case_name: audit rejected a tree it should accept"
        run_audit | sed 's/^/       /'
        FAILURES=$((FAILURES + 1))
    fi
}

expect_fail() {
    local case_name="$1" expect_text="$2"
    local output
    if output="$(run_audit)"; then
        echo "  FAIL $case_name: audit PASSED a tree it must reject"
        FAILURES=$((FAILURES + 1))
        return
    fi
    if ! grep -qF "$expect_text" <<<"$output"; then
        echo "  FAIL $case_name: caught, but the message never mentions '$expect_text'"
        sed 's/^/       /' <<<"$output"
        FAILURES=$((FAILURES + 1))
        return
    fi
    echo "  ok   $case_name"
}

restore() {
    git -C "$WORK_DIR" checkout -q -- .
}

echo "test-audit-uapi-constants:"

# 1. The tree as committed must pass, or every other case is meaningless.
expect_pass "clean tree passes"

# 2. #196 — reintroduce the LINKMODES off-by-one: split OURS into two variants
#    so every later id shifts up by one.
python3 - "$ETHTOOL" <<'PY'
import sys, re
p = sys.argv[1]
s = open(p).read()
s = s.replace("    Ours = 3,\n    /// Peer advertised link modes (bitset).\n    Peer = 4,",
              "    Supported = 3,\n    /// Advertised.\n    Advertised = 4,\n    /// Peer advertised link modes (bitset).\n    Peer = 5,")
s = s.replace("    Speed = 5,", "    Speed = 6,")
s = s.replace("    Duplex = 6,", "    Duplex = 7,")
open(p, "w").write(s)
PY
expect_fail "#196 LINKMODES off-by-one is caught" "EthtoolLinkmodesAttr::Speed"
restore

# 3. #227 — drop ETH_SS_FEATURES so every set id from 4 up is one too low.
python3 - "$ETHTOOL" <<'PY'
import sys
p = sys.argv[1]
s = open(p).read()
s = s.replace("    /// Device feature names.\n    Features = 4,\n    /// RSS hash function names.\n    RssHashFuncs = 5,",
              "    /// RSS hash function names.\n    RssHashFuncs = 4,")
open(p, "w").write(s)
PY
expect_fail "#227 ETH_SS missing FEATURES is caught" "EthtoolStringSet::RssHashFuncs"
restore

# 4. #231 — start BssStatus at 1 instead of 0.
python3 - "$NL80211" <<'PY'
import sys
p = sys.argv[1]
s = open(p).read()
s = s.replace("    Authenticated = 0,\n    /// Associated to this BSS.\n    Associated = 1,\n    /// Joined IBSS (ad-hoc).\n    IbssJoined = 2,",
              "    Authenticated = 1,\n    /// Associated to this BSS.\n    Associated = 2,\n    /// Joined IBSS (ad-hoc).\n    IbssJoined = 3,")
open(p, "w").write(s)
PY
expect_fail "#231 BssStatus off-by-one is caught" "BssStatus::Authenticated"
restore

# 5. A brand-new UAPI enum that nobody mapped or allowlisted. This is the case
#    that keeps the gate honest as the crate grows: an unclassified enum is an
#    unchecked enum.
cat >> "$ETHTOOL" <<'EOF'

/// Fixture: a new wire enum nobody classified.
#[repr(u16)]
#[derive(Debug, Clone, Copy)]
pub enum FixtureUnclassifiedAttr {
    Unspec = 0,
    Header = 1,
}
EOF
expect_fail "an unclassified enum is caught" "FixtureUnclassifiedAttr"
restore

# 6. A variant invented inside a mapped UAPI enum — the shape of #227's
#    RssContexts, which was never a kernel string set at all.
python3 - "$ETHTOOL" <<'PY'
import sys
p = sys.argv[1]
s = open(p).read()
s = s.replace("pub enum EthtoolWolAttr {\n    Unspec = 0,",
              "pub enum EthtoolWolAttr {\n    Unspec = 0,\n    /// Fixture: no such kernel attribute.\n    Imaginary = 99,")
open(p, "w").write(s)
PY
expect_fail "an invented variant is caught" "no kernel constant named ETHTOOL_A_WOL_IMAGINARY"
restore

# 7. An OLDER build host. nlink deliberately supports kernels newer than the
#    machine compiling it, so a constant the headers have never heard of is a
#    legitimate answer — but only for one vouched for by name in the .newer file.
#    This is the exact failure that took the first CI run down: ubuntu-latest
#    ships an older linux-libc-dev than the maintainer's box.
OLD_HEADERS="$WORK_DIR/old-headers"
cp -r /usr/include/linux "$OLD_HEADERS"
# Strip the constants nlink knows but an older header set would not.
sed -i '/ETHTOOL_MSG_MODULE_FW_FLASH_ACT/d; /ETHTOOL_MSG_PHY_GET,/d; /ETHTOOL_A_HEADER_PHY_INDEX/d' \
    "$OLD_HEADERS/ethtool_netlink_generated.h"
sed -i '/ETH_SS_STATS_PHY/d; /ETH_SS_TS_FLAGS/d' "$OLD_HEADERS/ethtool.h"

if NLINK_UAPI_HEADER_DIR="$OLD_HEADERS" run_audit >/dev/null 2>&1; then
    echo "  ok   older headers: vouched-for constants are skipped, not failed"
else
    echo "  FAIL older headers: the audit rejected a tree whose only sin is being"
    echo "       newer than the build host's headers"
    NLINK_UAPI_HEADER_DIR="$OLD_HEADERS" run_audit | sed 's/^/       /'
    FAILURES=$((FAILURES + 1))
fi

# 8. ...but the vouching is what makes it safe. Un-vouch one and it must fail
#    again, exactly as an invented variant would.
grep -v ETHTOOL_A_HEADER_PHY_INDEX "$WORK_DIR/scripts/audit-uapi-constants.newer" \
    > "$WORK_DIR/scripts/.newer.tmp"
mv "$WORK_DIR/scripts/.newer.tmp" "$WORK_DIR/scripts/audit-uapi-constants.newer"

if output="$(NLINK_UAPI_HEADER_DIR="$OLD_HEADERS" run_audit)"; then
    echo "  FAIL older headers: an UNVOUCHED-FOR missing constant was waved through"
    echo "       — that is the hole an invented variant would hide in"
    FAILURES=$((FAILURES + 1))
elif grep -qF "ETHTOOL_A_HEADER_PHY_INDEX" <<<"$output"; then
    echo "  ok   older headers: an unvouched-for missing constant still fails"
else
    echo "  FAIL older headers: failed, but not about the constant we un-vouched"
    FAILURES=$((FAILURES + 1))
fi
restore

echo
if ((FAILURES > 0)); then
    echo "FAIL: $FAILURES case(s) failed"
    exit 1
fi
echo "PASS: the audit accepts the tree and catches every drift shape"
