# Wire-format audit — 0.20 cycle pre-work

**Audit performed**: 2026-06-03 against branch `0.20` head `05d388a`.
**Method**: Source-level inspection of `crates/nlink/src/netlink/`
cross-referenced against Linux kernel `v6.13` UAPI headers
(`include/uapi/linux/*.h`), `Documentation/netlink/specs/*.yaml`,
and select kernel sources (`net/xfrm/xfrm_user.c`,
`net/sched/cls_flower.c`, `drivers/dpll/dpll_netlink.c`).

## Executive summary

The audit surfaces **6 CRITICAL** wire-format defects, all in
`crates/nlink/src/netlink/xfrm.rs`, plus **2 HIGH** correctness
defects (one nftables CtKey, one DPLL FFO sint truncation), and a
handful of MEDIUM forward-compat hazards. The XFRM cluster is the
0.20 headline: the entire `update_sa` / `update_sp` / `flush_sa`
/ `flush_policy` set of public methods is broken on every kernel
since the family shipped — `XFRM_MSG_FLUSHSA` / `XFRM_MSG_FLUSHPOLICY`
are hardcoded to the wrong message-type numbers, `XFRMA_SRCADDR`
and `XFRMA_OFFLOAD_DEV` are hardcoded to the wrong attribute IDs,
and `update_*` uses `NEWSA + NLM_F_REPLACE` (XFRM ignores
`NLM_F_REPLACE`; replace requires `XFRM_MSG_UPDSA` / `_UPDPOLICY`).
None of these surfaces appear in 0.19's audit Plan 204 or its
sizeof-CI gate (Plan 213) — they're all attribute-ID and msg-type
constants the regression test doesn't cover. Plan 213's gate
needs widening to also assert kernel-side constants are correct,
not just struct sizes.

The XFRM cluster doesn't show up in nlink's
`tests/integration/` because the existing XFRM integration test
covers only `add_sa` / `del_sa` / `get_sa` / dump, which work.
The broken paths (`update_*`, `flush_*`, offload, lookup with
src-addr) bit-rot silently — most users never noticed because
they delete-then-add instead of replacing in place.

## Severity rubric
- **CRITICAL**: silently wrong bytes on the wire that the kernel
  accepts (corruption, wrong field interpreted, wrong destination …)
- **HIGH**: round-trip phantom diff, broken dump-back, missing
  required attr, EINVAL surface, broken request entirely
- **MEDIUM**: forward-compat hazard, inconsistent endianness,
  missing sizeof CI gate entry, dead-code with wrong constant
- **LOW**: cosmetic / docs / minor

## Findings

### Finding W1 — `XFRM_MSG_FLUSHSA` constant value wrong (25 → 28)
**Severity**: CRITICAL
**File**: `crates/nlink/src/netlink/xfrm.rs:51`
**Claim**: `XFRM_MSG_FLUSHSA: u16 = 25` is wrong — kernel UAPI
defines it as `28`. Value `25` is `XFRM_MSG_UPDPOLICY` (update SP).
So `Connection::<Xfrm>::flush_sa()` sends an `UPDPOLICY` message
carrying an 8-byte `xfrm_usersa_flush` body where the kernel
expects a 168-byte `xfrm_userpolicy_info` body.
**Evidence**: Kernel `include/uapi/linux/xfrm.h` (v6.13)
`enum { XFRM_MSG_BASE = 0x10, NEWSA, DELSA, GETSA, NEWPOLICY,
DELPOLICY, GETPOLICY, ALLOCSPI, ACQUIRE, EXPIRE, UPDPOLICY, UPDSA,
POLEXPIRE, FLUSHSA, FLUSHPOLICY, ... }` — counting forward from
`0x10`: FLUSHSA = 0x10 + 12 = 28. Kernel dispatcher in
`net/xfrm/xfrm_user.c` line 3257:
`[XFRM_MSG_FLUSHSA - XFRM_MSG_BASE] = { .doit = xfrm_flush_sa }`.
**Reproducer**: `conn.flush_sa().await` — on strict-checking
kernels returns `EINVAL` (body too small for UPDPOLICY). On
lenient kernels: undefined behaviour — UPDPOLICY without a
matching SP key field is likely to fail policy verification.
**Fix**: `const XFRM_MSG_FLUSHSA: u16 = 28;`
**Confidence**: very high (cross-checked against kernel
dispatcher table).

### Finding W2 — `XFRM_MSG_FLUSHPOLICY` constant value wrong (28 → 29)
**Severity**: CRITICAL
**File**: `crates/nlink/src/netlink/xfrm.rs:52`
**Claim**: `XFRM_MSG_FLUSHPOLICY: u16 = 28` is wrong — kernel UAPI
defines it as `29`. Value `28` is `XFRM_MSG_FLUSHSA`. So
`Connection::<Xfrm>::flush_policy()` actually flushes all SAs
instead of all SPs.
**Evidence**: Same enum as W1 — counting: FLUSHPOLICY = 0x10 + 13
= 29. Kernel `net/xfrm/xfrm_user.c` line 3258:
`[XFRM_MSG_FLUSHPOLICY - XFRM_MSG_BASE] = { .doit =
xfrm_flush_policy }`.
**Reproducer**: `conn.flush_policy().await` while there are SAs
+ SPs configured: SPs are left alone, all SAs are deleted.
**Fix**: `const XFRM_MSG_FLUSHPOLICY: u16 = 29;`
**Confidence**: very high.

### Finding W3 — `XFRMA_SRCADDR` attribute ID wrong (9 → 13)
**Severity**: CRITICAL
**File**: `crates/nlink/src/netlink/xfrm.rs:60`
**Claim**: `XFRMA_SRCADDR: u16 = 9` is wrong — kernel UAPI
defines it as `13`. Value `9` is `XFRMA_LTIME_VAL`. Every
`del_sa` / `get_sa` request (lines 1394, 1469) attaches a 16-byte
"src addr" attr that the kernel interprets as a 32-byte
`xfrm_lifetime_cur` lifetime structure → silent length mismatch
or wrong field interpretation.
**Evidence**: Kernel `include/uapi/linux/xfrm.h`
`enum xfrm_attr_type_t { UNSPEC, AUTH=1, CRYPT=2, COMP=3, ENCAP=4,
TMPL=5, SA=6, POLICY=7, SEC_CTX=8, LTIME_VAL=9, REPLAY_VAL=10,
REPLAY_THRESH=11, ETIMER_THRESH=12, SRCADDR=13, ... }`.
**Reproducer**: `conn.del_sa(src, dst, spi, proto)` — request
includes `nla_type=9 nla_len=20` carrying 16 byte address; kernel
parses it as truncated `xfrm_lifetime_cur` (expects 32 bytes).
Likely silently ignored on most kernels (xfrm_user.c
`xfrma_policy[XFRMA_LTIME_VAL].len = ...` checks size) — net
effect: the optional src-addr filter on the lookup is dropped.
SA delete by daddr+spi+proto still happens, masking the bug.
**Fix**: `const XFRMA_SRCADDR: u16 = 13;`
**Confidence**: very high.

### Finding W4 — `XFRMA_OFFLOAD_DEV` attribute ID wrong (26 → 28)
**Severity**: CRITICAL
**File**: `crates/nlink/src/netlink/xfrm.rs:66`
**Claim**: `XFRMA_OFFLOAD_DEV: u16 = 26` is wrong — kernel UAPI
defines it as `28`. Value `26` is `XFRMA_ADDRESS_FILTER`. Every
`XfrmSaBuilder::offload(...)` call (Plan 153.1) emits an 8-byte
`xfrm_user_offload` payload under attr ID 26, which the kernel
parses as a malformed `xfrm_address_filter` (expects 24 bytes:
`{xfrm_address_t saddr, xfrm_address_t daddr, __u16 family,
__u8 splen, __u8 dplen}`). Strict-checking kernels reject with
EINVAL; lenient kernels silently drop the offload request and
install a software-only SA.
**Evidence**: Same enum as W3 — counting: ADDRESS_FILTER=26,
PAD=27, OFFLOAD_DEV=28. Confirmed in `xfrma_policy[]` table at
`net/xfrm/xfrm_user.c` ~line 3017
(`[XFRMA_OFFLOAD_DEV] = { .len = sizeof(struct
xfrm_user_offload) }`).
**Reproducer**: `XfrmSaBuilder::new(...).offload(ifindex,
XfrmOffloadFlag::PACKET)` — kernel either rejects (strict) or
silently ignores offload (lenient). Plan 213's existing sizeof
test asserts `XfrmUserOffload` is 8 bytes — which is correct —
so the regression suite doesn't catch this.
**Fix**: `const XFRMA_OFFLOAD_DEV: u16 = 28;`
**Confidence**: very high. Also, the existing dummy assertion
`assert_eq!(XFRMA_OFFLOAD_DEV, 26)` at line 2139 of xfrm.rs
encodes the bug — that test enforces the wrong value.

### Finding W5 — `update_sa` uses wrong message type (NEWSA + REPLACE → UPDSA)
**Severity**: CRITICAL
**File**: `crates/nlink/src/netlink/xfrm.rs:1408-1415`
**Claim**: `Connection::<Xfrm>::update_sa` sends
`XFRM_MSG_NEWSA` (= 16) with `NLM_F_CREATE | NLM_F_REPLACE`. The
kernel dispatches XFRM messages by `nlmsg_type` alone:
`xfrm_user.c:917` `if (nlh->nlmsg_type == XFRM_MSG_NEWSA) err =
xfrm_state_add(x); else err = xfrm_state_update(x);`.
`NLM_F_REPLACE` is **ignored**. So `update_sa` always invokes
`xfrm_state_add` which returns `-EEXIST` when the SA tuple
already exists. Net effect: the public `update_sa` API can
never succeed when the target SA exists — its entire reason for
being.
**Evidence**: `net/xfrm/xfrm_user.c` lines 917-921 — the
`nlmsg_type == NEWSA` check; lines 3240/3255 dispatch table
entries `[XFRM_MSG_NEWSA] = { .doit = xfrm_add_sa }` and
`[XFRM_MSG_UPDSA] = { .doit = xfrm_add_sa }` (same handler,
behaviour differentiated by type).
**Reproducer**:
```rust
conn.add_sa(builder.clone()).await?;
conn.update_sa(builder.with_replay_window(64)).await?; // EEXIST
```
**Fix**: Send `XFRM_MSG_UPDSA = 26` (after fixing W1's constant
shift) without `NLM_F_REPLACE`:
```rust
let mut b = MessageBuilder::new(
    XFRM_MSG_UPDSA,
    NLM_F_REQUEST | NLM_F_ACK,
);
```
**Confidence**: very high.

### Finding W6 — `update_sp` uses wrong message type (NEWPOLICY + REPLACE → UPDPOLICY)
**Severity**: CRITICAL
**File**: `crates/nlink/src/netlink/xfrm.rs:1498-1505`
**Claim**: Identical mistake to W5 for policies.
`xfrm_user.c:1106` in `xfrm_add_policy`:
`excl = nlh->nlmsg_type == XFRM_MSG_NEWPOLICY;
err = xfrm_policy_insert(p->dir, xp, excl);`. With NEWPOLICY,
`excl=1`, kernel returns `-EEXIST` for any duplicate. The
`UPDPOLICY` flow path (`excl=0`) is the documented "replace
in place" path.
**Evidence**: `net/xfrm/xfrm_user.c` lines around 1100-1110 +
dispatch table.
**Reproducer**:
```rust
conn.add_sp(builder.clone()).await?;
conn.update_sp(builder.with_priority(200)).await?; // EEXIST
```
**Fix**: Send `XFRM_MSG_UPDPOLICY = 25` (the existing wrong
`FLUSHSA = 25` value is actually the correct value for
UPDPOLICY!). Drop `NLM_F_REPLACE`.
**Confidence**: very high.

### Finding W7 — nftables `CtKey::Expiration` wrong (7 → 5)
**Severity**: HIGH
**File**: `crates/nlink/src/netlink/nftables/types.rs:370`
**Claim**: `CtKey::Expiration = 7` is wrong — kernel UAPI
defines `NFT_CT_EXPIRATION = 5`. Value `7` is
`NFT_CT_L3PROTOCOL`. So `Expr::Ct { key: CtKey::Expiration, .. }`
loads the conntrack L3 protocol byte into the register instead
of the relative expiration time in ms — a 4-byte u32 mismatch in
both meaning and width.
**Evidence**: Kernel `include/uapi/linux/netfilter/nf_tables.h`
`enum nft_ct_keys { NFT_CT_STATE=0, DIRECTION=1, STATUS=2,
MARK=3, SECMARK=4, EXPIRATION=5, HELPER=6, L3PROTOCOL=7, ... }`.
**Reproducer**: a rule using
`Expr::Ct { dreg: R0, key: CtKey::Expiration }` followed by a
`Cmp` against a millisecond value will never match — it's
comparing the wrong field. Silent on the wire (the kernel
happily emits the L3PROTOCOL value).
**Fix**: `Expiration = 5,`
**Confidence**: very high.

### Finding W8 — DPLL `fractional_frequency_offset_ppt` (and `_ffo`) wrong type (`Option<i32>` → variable-length signed integer)
**Severity**: HIGH
**File**: `crates/nlink/src/netlink/genl/dpll/messages.rs:354`
(`fractional_frequency_offset_ppt`) and the older
`FractionalFrequencyOffset` attr (id 24) accessor.
**Claim**: The DPLL YAML spec types both `fractional-frequency-offset`
and `fractional-frequency-offset-ppt` as `sint` — kernel
`drivers/dpll/dpll_netlink.c:dpll_msg_add_ffo()` uses
`nla_put_sint(msg, ..., ffo)` where `s64 ffo`. `nla_put_sint`
emits **4 bytes if the value fits in `s32`, 8 bytes otherwise**.
nlink stores the field as `Option<i32>` with no `sint`
codepath — any FFO requiring more than 32 signed bits parses
as `None` (length mismatch) or silent truncation.
**Evidence**: kernel YAML
`Documentation/netlink/specs/dpll.yaml`:
```yaml
- name: fractional-frequency-offset
  type: sint
```
and `drivers/dpll/dpll_netlink.c` line 322:
`return nla_put_sint(msg, DPLL_A_PIN_FRACTIONAL_FREQUENCY_OFFSET,
ffo);` with `s64 ffo` declared at line 310. Plan 206 widened
`phase_offset` from `i32 → i64` for the same class of bug; FFO
was missed.
**Reproducer**: a SyncE-EthPort pin with a non-trivial FFO
(typical at link bring-up: hundreds of ppm × kernel scaling)
returns `None` from `pin.fractional_frequency_offset_ppt`.
**Fix**: widen the field to `Option<i64>`; add a `sint` parser
to the macro runtime (kernel's `nla_get_sint`: read len, switch
on 4 → `i32 as i64`, 8 → `i64`).
**Confidence**: high. The `_ppt` and `_ffo` are both affected.

### Finding W9 — `TCA_HTB_OFFLOAD` constant wrong (8 → 9)
**Severity**: MEDIUM (constant is currently dead code; would
become a CRITICAL silent wrong attribute the moment the
HTB-offload builder is wired through)
**File**: `crates/nlink/src/netlink/types/tc.rs:335`
**Claim**: `TCA_HTB_OFFLOAD: u16 = 8` is wrong — kernel UAPI has
`PAD=8, OFFLOAD=9`. Constant defined but currently never
referenced; if a user reaches into the typed module to emit
HTB offload directly, the kernel parses it as `TCA_HTB_PAD`
and silently rejects (PAD is not for use; it's an alignment
sentinel).
**Evidence**: `include/uapi/linux/pkt_sched.h`:
```
enum {
    TCA_HTB_UNSPEC,    // 0
    TCA_HTB_PARMS,     // 1
    TCA_HTB_INIT,      // 2
    TCA_HTB_CTAB,      // 3
    TCA_HTB_RTAB,      // 4
    TCA_HTB_DIRECT_QLEN, // 5
    TCA_HTB_RATE64,    // 6
    TCA_HTB_CEIL64,    // 7
    TCA_HTB_PAD,       // 8
    TCA_HTB_OFFLOAD,   // 9
};
```
**Reproducer**: none today (dead code); blocks HTB offload
work.
**Fix**: `pub const TCA_HTB_PAD: u16 = 8;
pub const TCA_HTB_OFFLOAD: u16 = 9;`
**Confidence**: very high.

### Finding W10 — `nest_start` double-OR with `0x8000` in `expr.rs`
**Severity**: LOW
**File**: `crates/nlink/src/netlink/nftables/expr.rs` (every call site)
**Claim**: `nest_start` internally ORs `NLA_F_NESTED` (0x8000)
into the attribute type; every call in `expr.rs` redundantly
ORs `0x8000` again. Idempotent (`0x8000 | 0x8000 = 0x8000`),
so the wire bytes are correct, but the code is misleading and
breaks the (sealed) invariant.
**Evidence**: `crates/nlink/src/netlink/builder.rs:132`
`let attr = NlAttr::new(attr_type | NLA_F_NESTED, 0);`.
**Fix**: drop `| 0x8000` from every `expr.rs` call site.
**Confidence**: very high.

### Finding W11 — `XfrmUserOffload::ifindex` should be `i32` not `u32`
**Severity**: LOW
**File**: `crates/nlink/src/netlink/xfrm.rs:446`
**Claim**: Kernel `struct xfrm_user_offload { int ifindex; __u8
flags; }` declares `ifindex` as `int` (signed). nlink uses `u32`.
On every real system ifindex > 0, so the high bit is unused;
the bytes are identical, only the type contract differs. Future
ifindex tables with negative sentinel values would diverge.
**Fix**: `pub ifindex: i32` (kernel-honest).
**Confidence**: medium (low impact; documentation-only).

### Finding W12 — `XfrmUsersaId._pad` width is too tight (`u8` → kernel padding semantics)
**Severity**: MEDIUM (forward-compat)
**File**: `crates/nlink/src/netlink/xfrm.rs:159`
**Claim**: `XfrmUsersaId._pad: u8` produces a 24-byte struct:
16 (daddr) + 4 (spi) + 2 (family) + 1 (proto) + 1 (pad) = 24.
Kernel `struct xfrm_usersa_id { xfrm_address_t daddr; __be32 spi;
__u16 family; __u8 proto; }` totals 23 bytes; natural alignment
rounds to 24, so the byte count matches. But the `__attribute__((packed))`
shape is not enforced — if the kernel ever adds a trailing
field (kernel 6.16+ in `xfrm_user.c` has discussed adding
`u8 dir`), nlink would silently truncate. Adding a sizeof CI
gate entry would catch this.
**Evidence**: `include/uapi/linux/xfrm.h` `struct xfrm_usersa_id`.
**Fix**: add `pub const USERSA_ID: usize = 24;` to
`sys_sizeof::xfrm` + a regression test (same shape as
USERPOLICY_ID).
**Confidence**: high.

### Finding W13 — XFRM lifetime structures lack sizeof CI gate entries for the wire-attribute payload kinds
**Severity**: MEDIUM
**File**: `crates/nlink/src/netlink/sys_sizeof.rs`
**Claim**: The 0.19 Plan 213 sizeof gate covers
`XfrmUserpolicyInfo`, `XfrmUserpolicyId`, `XfrmUsersaInfo`,
`XfrmSelector`, `XfrmLifetimeCfg`, `XfrmLifetimeCur`,
`XfrmUserTmpl` — but not `XfrmId` (24), `XfrmUsersaId` (24),
`XfrmUsersaFlush` (8), `XfrmEncapTmpl` (24), `XfrmMark` (8),
`XfrmUserOffload` (8). The missing ones are smaller but their
sizes still pin a wire-format contract; any future maintainer
who reorders fields would break the wire silently.
**Fix**: extend `sys_sizeof::xfrm` with constants + regression
tests for the six structs above.
**Confidence**: high.

### Finding W14 — sizeof CI gate doesn't cover XFRM message-type / attribute-ID constants
**Severity**: MEDIUM (this audit's findings W1-W6 are exactly
the class the gate was created to catch but the gate scope
was too narrow)
**File**: `crates/nlink/src/netlink/sys_sizeof.rs`
**Claim**: Plan 213's regression gate verifies struct sizes
match kernel UAPI. It doesn't verify constants (msg types,
attribute IDs). The four CRITICAL fixes Plan 204 shipped were
also constants (nft verdicts) — they got verified in
`sys_sizeof.rs`'s `nft_verdict` module. Same pattern was not
applied to XFRM message types / XFRMA_* attribute IDs, leaving
W1-W6 undetected.
**Fix**: add `pub mod xfrm_msg_type` and `pub mod xfrm_attr` to
`sys_sizeof.rs` with all msg-type and attribute-ID constants
asserted against the local `const` definitions. Same pattern
for any other family that hardcodes attribute IDs (TC's
HtbAttr / FlowerAttr / ActionAttr; nftables NFTA_*).
**Confidence**: high — and addressing it would be the most
durable 0.20 prevention work.

### Finding W15 — XFRMA_ALG_AUTH 64-byte name field zero-padded, not null-terminated
**Severity**: LOW
**File**: `crates/nlink/src/netlink/xfrm.rs:1078-1088` (`encode_xfrm_algo`)
**Claim**: The algorithm name is copied into a 64-byte buffer
truncated at byte 63 (which leaves position 63 always 0). For
algorithm names of exactly 63 bytes, the kernel's
`crypto_alloc_*` call relies on the trailing NUL — current code
guarantees it. For names >63 bytes the kernel sees a
non-null-terminated string and may walk past the end. nlink
caps to 63 (`name.len().min(63)`) — safe. No bug, but worth
documenting that the 64-byte name is mandatory.
**Confidence**: very high (no bug). Audited; clean.

### Finding W16 — `Connection::<Xfrm>::flush_sa_proto` regression on top of W1
**Severity**: derived from W1
**File**: `crates/nlink/src/netlink/xfrm.rs:1430-1442`
**Claim**: Same as W1 — uses the broken `XFRM_MSG_FLUSHSA = 25`
constant. Fixing W1 fixes this method too.
**Fix**: see W1.

### Finding W17 — Plan 178's register canonicalisation invariant is correct; no follow-on bug
**Severity**: confirmed clean
**Claim**: Audited `Register::R0..R3 = 1..4` against kernel
`enum nft_registers { NFT_REG_VERDICT=0, NFT_REG_1=1,
NFT_REG_2=2, NFT_REG_3=3, NFT_REG_4=4, NFT_REG_32_00=8, ... }`.
nlink's mapping is to the 16-byte registers (the canonical
kernel-stored form), matching Plan 178's design intent.
**Confidence**: very high.

### Finding W18 — flower / TC / RTA tables: spot-clean
**Severity**: confirmed clean
**Claim**: Spot-audited:
- `TCA_FLOWER_KEY_VLAN_ID` written as `to_ne_bytes` matches
  kernel `nla_get_u16` (despite the kernel header's
  `/* be16 */` comment — that comment is misleading).
  `cls_flower.c:fl_set_key_vlan` uses `nla_get_u16`.
- `TCA_FLOWER_KEY_ETH_TYPE` written as `to_be_bytes` matches
  kernel `nla_get_be16(tb)` in `cls_flower.c`.
- `TCA_HTB_RATE64`/`CEIL64` written as `to_ne_bytes` matches
  kernel `nla_get_u64` (native).
- `RTA_*` enum positions 0..30 match kernel `__RTA_MAX`.
- `IFLA_*` enum positions match kernel through 64
  (`GRO_IPV4_MAX_SIZE`); gap at 62 (`IFLA_DEVLINK_PORT`) is
  cosmetic per `#[non_exhaustive]`.
- `MetaKey::{Len=0, Protocol=1, Mark=3, Iif=4, ..., CGroup=23}`
  matches `enum nft_meta_keys`.
- nftables NFTA_FLOWTABLE_*, NFTA_CHAIN_*, NFTA_HOOK_*,
  NFTA_RULE_*, NFTA_EXPR_*, NFTA_DATA_*, NFTA_VERDICT_*
  constants verified against kernel UAPI.
- CTA_* / CTA_TUPLE_* / CTA_PROTO_* / CTA_COUNTERS_*
  conntrack constants verified.
- Port numbers in conntrack tuples written as big-endian
  (`append_attr_u16_be`) — correct.
- `Family::{Inet=1, Ip=2, Arp=3, Netdev=5, Bridge=7, Ip6=10}`
  matches `NFPROTO_*`.

## Not audited / out of scope (deferred)

Time-boxed audit; the following surfaces were not exhaustively
checked. Recommend either covering in a 0.20 follow-on or
adding fuzz coverage:

- **nl80211** — only spot-checked; the family is huge and the
  attribute landscape changes per kernel.
- **devlink rate** + **port-function-state** — Plan 153.2's
  newly added attribute IDs not cross-referenced against the
  current devlink YAML.
- **ethtool linkmodes bitset** — `bitset.rs` was not opened;
  the bitset wire format is finicky (`nla_get_bitfield32` /
  `NLA_BITFIELD32`) and is a documented competitor pain point.
- **net_shaper** — kernel-side YAML changed between 6.12 and
  6.13; deferred.
- **macsec / mptcp / wireguard** — macro-derived; the macro is
  more disciplined but the family-specific attribute tables
  (e.g. `WGDEVICE_A_*`) were not cross-checked.
- **TC pedit** — typed config carries key offsets/masks; not
  audited against kernel `pkt_cls.h`.
- **TC u32 selector** — handled byte-level (already audited per
  Plan 147); not re-examined here.
- **Bridge VLAN (`bridge_vlan.rs`) / FDB** — recent additions;
  spot-check showed no obvious drift but no deep walkthrough.
- **MPLS / SRv6 / NextHop** — typed structs not size-checked
  against kernel.
- **xfrm_replay_state_esn** + nested `XFRMA_REPLAY_ESN_VAL`
  parsing — only the write path's algorithm encoders were
  walked.
- **selinux / audit / fib_lookup** — not opened.
- **uevent / connector / namespace_watcher** — not opened (no
  wire-format risk; they consume kernel binary blobs verbatim).

The CRITICAL findings W1-W6 are sufficient justification for a
0.20.1 point release on their own; W7 (CtKey) likely belongs
in the same hotfix.
