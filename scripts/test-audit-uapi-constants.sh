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
#  14. distro-patched headers, the upstream value listed -> accepted, said so
#  15. distro-patched headers, NOT listed            -> caught
#  16. a listed constant whose nlink value drifted   -> caught

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
cp -r "$REPO_ROOT/third_party" "$WORK_DIR/third_party"

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

# 4b. #266 — the plain `pub const` pass. This is the form that carried ~30 wrong
# ids past the enum-only gate (nl80211, devlink, bridge and tc all declare their
# constants this way), so it needs its own case. Reproduce the real #259 bug:
# IFLA_BRPORT_MCAST_TO_UCAST four too low, which is IFLA_BRPORT_FLUSH — the
# value that made setting one boolean wipe the bridge port's FDB.
python3 - "$WORK_DIR/crates/nlink/src/netlink/types/link.rs" <<'PY'
import sys
p = sys.argv[1]
s = open(p).read()
s = s.replace("pub const IFLA_BRPORT_MCAST_TO_UCAST: u16 = 28;",
              "pub const IFLA_BRPORT_MCAST_TO_UCAST: u16 = 24;")
open(p, "w").write(s)
PY
expect_fail "#266 a wrong plain pub const is caught" "IFLA_BRPORT_MCAST_TO_UCAST"
restore

# 4b'. The same pass reads private constants. xfrm.rs declares its message types
# `const`, not `pub const`, and the pass read only `pub` until #167, so the
# constants of the 0.19.1 hotfix were never checked. Reproduce that bug:
# XFRM_MSG_FLUSHSA at 25, which is XFRM_MSG_UPDPOLICY.
python3 - "$WORK_DIR/crates/nlink/src/netlink/xfrm.rs" <<'PY'
import sys
p = sys.argv[1]
s = open(p).read()
assert "const XFRM_MSG_FLUSHSA: u16 = 28;" in s
s = s.replace("const XFRM_MSG_FLUSHSA: u16 = 28;", "const XFRM_MSG_FLUSHSA: u16 = 25;")
open(p, "w").write(s)
PY
expect_fail "#167 a wrong private const is caught" "XFRM_MSG_FLUSHSA"
restore

# 4c. A plain const whose name the kernel does not define must be ignored, not
# guessed at. The pass is exact-name-match only; anything looser would need a
# mapping table and would invent failures on nlink-local constants.
python3 - "$WORK_DIR/crates/nlink/src/netlink/types/link.rs" <<'PY'
import sys
p = sys.argv[1]
s = open(p).read()
s = s.replace(
    "pub const IFLA_BRPORT_MCAST_TO_UCAST: u16 = 28;",
    "pub const IFLA_BRPORT_MCAST_TO_UCAST: u16 = 28;\n"
    "    pub const NLINK_LOCAL_NOT_A_KERNEL_SYMBOL: u16 = 4242;",
)
open(p, "w").write(s)
PY
expect_pass "#266 an nlink-local plain const is ignored, not guessed at"
restore

# 4d. #260 — a mapped module (audit-uapi-constants.modmap) supplies the kernel
# prefix for constants named with the suffix only, and is checked *strictly*:
# every constant in it must resolve to a real kernel symbol. That strictness is
# the point. nlink's macsec module carried two attributes the kernel has never
# defined, and an invented attribute is invisible to a value-only check —
# there is no wrong number to notice, just a name nobody implements.
python3 - "$WORK_DIR/crates/nlink/src/netlink/types/macsec.rs" <<'PY'
import sys
p = sys.argv[1]
s = open(p).read()
s = s.replace("    /// Netlink alignment padding.\n    pub const PAD: u16 = 2;\n}",
              "    /// Netlink alignment padding.\n    pub const PAD: u16 = 2;\n"
              "    pub const INVENTED_BY_NOBODY: u16 = 3;\n}", 1)
open(p, "w").write(s)
PY
expect_fail "#260 an invented attribute in a mapped module is caught" "no kernel constant named MACSEC_OFFLOAD_ATTR_INVENTED_BY_NOBODY"
restore

# 4e. The same module, wrong value rather than invented name — the cipher-suite
# shape. These are `ULL`-suffixed #defines in the header, which the expression
# evaluator has to strip; before it did, they parsed as nothing and the whole
# cipher table was silently unchecked while GcmAes256 sent GCM-AES-128.
python3 - "$WORK_DIR/crates/nlink/src/netlink/types/macsec.rs" <<'PY'
import sys
p = sys.argv[1]
s = open(p).read()
s = s.replace("pub const GCM_AES_256: u64 = 0x0080_C200_0100_0002;",
              "pub const GCM_AES_256: u64 = 0x0080_C200_0100_0001;")
open(p, "w").write(s)
PY
expect_fail "#260 a ULL-suffixed cipher id with the wrong value is caught" "macsec_cipher::GCM_AES_256"
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

# Age the copy: delete the enumerators an older header set would not have.
#
# Which file each lives in varies by kernel version (ethtool's netlink enums
# moved into ethtool_netlink_generated.h only recently), and on a genuinely old
# host — the ubuntu-latest runner, say — several are absent to begin with. So
# grep for each constant rather than naming files, and treat "already missing"
# as success: that IS the state being simulated.
#
# The trailing comma in each pattern is load-bearing: it keeps
# `ETHTOOL_MSG_PHY_GET,` from also matching `ETHTOOL_MSG_PHY_GET_REPLY,`.
for const in 'ETHTOOL_MSG_MODULE_FW_FLASH_ACT,' 'ETHTOOL_MSG_PHY_GET,' \
             'ETHTOOL_A_HEADER_PHY_INDEX,' 'ETH_SS_STATS_PHY,' 'ETH_SS_TS_FLAGS,'; do
    while IFS= read -r f; do
        sed -i "/${const}/d" "$f"
    done < <(grep -rlF "$const" "$OLD_HEADERS" 2>/dev/null || true)
done

if NLINK_UAPI_HEADER_DIR="$OLD_HEADERS" run_audit >/dev/null 2>&1; then
    echo "  ok   older headers: vouched-for constants are skipped, not failed"
else
    echo "  FAIL older headers: the audit rejected a tree whose only sin is being"
    echo "       newer than the build host's headers"
    NLINK_UAPI_HEADER_DIR="$OLD_HEADERS" run_audit | sed 's/^/       /'
    FAILURES=$((FAILURES + 1))
fi

# 8. ...but the vouching is what makes it safe. Un-vouch one and it must fail
#    again, exactly as an invented variant would. (ETHTOOL_A_HEADER_PHY_INDEX,
#    also aged out above, needs no vouching: the ethtool spec defines it, #167.)
grep -v ETH_SS_STATS_PHY "$WORK_DIR/scripts/audit-uapi-constants.newer" \
    > "$WORK_DIR/scripts/.newer.tmp"
mv "$WORK_DIR/scripts/.newer.tmp" "$WORK_DIR/scripts/audit-uapi-constants.newer"

if output="$(NLINK_UAPI_HEADER_DIR="$OLD_HEADERS" run_audit)"; then
    echo "  FAIL older headers: an UNVOUCHED-FOR missing constant was waved through"
    echo "       — that is the hole an invented variant would hide in"
    FAILURES=$((FAILURES + 1))
elif grep -qF "ETH_SS_STATS_PHY" <<<"$output"; then
    echo "  ok   older headers: an unvouched-for missing constant still fails"
else
    echo "  FAIL older headers: failed, but not about the constant we un-vouched"
    FAILURES=$((FAILURES + 1))
fi
restore

# 9. #167 — a drift only a spec can see. ovpn (6.16) is newer than most build
#    hosts' headers, so before the spec overlay its enums were checked against
#    nothing at all.
OVPN="$WORK_DIR/crates/nlink/src/netlink/genl/ovpn/types.rs"
python3 - "$OVPN" <<'PY'
import sys
p = sys.argv[1]
s = open(p).read()
assert "    TxId = 24," in s
s = s.replace("    TxId = 24,", "    TxId = 25,")
open(p, "w").write(s)
PY
expect_fail "#167 a drift in a family the headers lack is caught by its spec" "OvpnPeerAttr::TxId"
restore

# 10. A spec and a header that disagree: either the derivation is wrong for the
#     case or the spec is, and neither is picked silently. The edit is re-hashed
#     into SOURCE so that the hash check doesn't catch it first.
python3 - "$WORK_DIR/third_party/ynl-specs" <<'PY'
import hashlib, sys
from pathlib import Path
d = Path(sys.argv[1])
spec, source = d / "wireguard.yaml", d / "SOURCE"
old = spec.read_bytes()
new = old.replace(b"      - remove-me\n      - replace-allowedips\n",
                  b"      - replace-allowedips\n      - remove-me\n")
assert new != old
spec.write_bytes(new)
source.write_text(source.read_text().replace(
    hashlib.sha256(old).hexdigest(), hashlib.sha256(new).hexdigest()))
PY
expect_fail "#167 a spec that disagrees with the headers is caught" "The spec and the header disagree"
restore

# 11. A vendored spec edited by hand: its hash no longer matches SOURCE.
echo "# edited" >> "$WORK_DIR/third_party/ynl-specs/ovpn.yaml"
expect_fail "#167 a hand-edited spec is caught" "ovpn.yaml: sha256"
restore

# 12. An unclassified enum declared through the GENL derives, the form that
#     went unchecked until #167 (all of ovpn, net_shaper and dpll).
cat >> "$OVPN" <<'EOF'

/// Fixture: a new GENL wire enum nobody classified.
#[derive(GenlAttribute, Debug, Clone, Copy)]
#[genl_attribute(repr = "u16")]
pub enum FixtureUnclassifiedGenlAttr {
    Unspec = 0,
    Ifindex = 1,
}
EOF
expect_fail "#167 an unclassified GENL-derive enum is caught" "FixtureUnclassifiedGenlAttr"
restore

# 13. No PyYAML is a failure, not a skip: the spec-only constants are vouched for
#     nowhere else. A `yaml` module that refuses to import stands in for one
#     that isn't installed.
mkdir -p "$WORK_DIR/no-yaml"
echo 'raise ImportError("simulated: PyYAML is not installed")' > "$WORK_DIR/no-yaml/yaml.py"
PYTHONPATH="$WORK_DIR/no-yaml" expect_fail "#167 a missing PyYAML fails the audit" "PyYAML is not installed"

# 14. Distro-patched headers. Ubuntu 24.04's linux-libc-dev 6.8.0 backports
#     per-CPU SAs without the two attributes upstream numbered before them, so
#     its XFRMA_SA_PCPU is 33 where upstream's is 35: the failure that took
#     down #795's audit job. Deleting those two enumerators from a copy makes
#     either kind of host look like that one.
DISTRO_HEADERS="$WORK_DIR/distro-headers"
cp -r /usr/include/linux "$DISTRO_HEADERS"
for const in 'XFRMA_SA_DIR,' 'XFRMA_NAT_KEEPALIVE_INTERVAL,'; do
    sed -i "/${const}/d" "$DISTRO_HEADERS/xfrm.h"
done
if output="$(NLINK_UAPI_HEADER_DIR="$DISTRO_HEADERS" run_audit)" && grep -qF "XFRMA_SA_PCPU: these headers say 33, upstream 35" <<<"$output"; then
    echo "  ok   distro headers: nlink's upstream value is accepted, and said so"
else
    echo "  FAIL distro headers: the listed upstream value was not accepted, or not reported"
    sed 's/^/       /' <<<"$output"
    FAILURES=$((FAILURES + 1))
fi

# 15. ...for the constant listed, and no other: unlisted, it is a mismatch.
grep -v '^XFRMA_SA_PCPU' "$WORK_DIR/scripts/audit-uapi-constants.distro" \
    > "$WORK_DIR/scripts/.distro.tmp"
mv "$WORK_DIR/scripts/.distro.tmp" "$WORK_DIR/scripts/audit-uapi-constants.distro"
if output="$(NLINK_UAPI_HEADER_DIR="$DISTRO_HEADERS" run_audit)"; then
    echo "  FAIL distro headers: an unlisted disagreement was waved through"
    FAILURES=$((FAILURES + 1))
elif grep -qF "XFRMA_SA_PCPU = 35, but XFRMA_SA_PCPU = 33" <<<"$output"; then
    echo "  ok   distro headers: an unlisted disagreement still fails"
else
    echo "  FAIL distro headers: failed, but not about XFRMA_SA_PCPU"
    FAILURES=$((FAILURES + 1))
fi
restore

# 16. The list excuses the headers, never nlink: a drifted nlink value fails
#     against distro headers and upstream ones alike.
sed -i 's/^const XFRMA_SA_PCPU: u16 = 35;/const XFRMA_SA_PCPU: u16 = 36;/' \
    "$WORK_DIR/crates/nlink/src/netlink/xfrm.rs"
NLINK_UAPI_HEADER_DIR="$DISTRO_HEADERS" expect_fail "distro headers: a drifted nlink value is caught" "XFRMA_SA_PCPU = 36"
restore

echo
if ((FAILURES > 0)); then
    echo "FAIL: $FAILURES case(s) failed"
    exit 1
fi
echo "PASS: the audit accepts the tree and catches every drift shape"
