# Deep audit — nlink 0.20 pre-work

**Reviewer**: independent deep-audit pass
**Branch**: `0.20` at `05d388a` (today, post PRs #9 + #10 merge)
**Method**: three parallel agents on disjoint surfaces (wire-format,
bug hunt, API design); reviewer personally verified all CRITICAL
wire-format findings against upstream kernel UAPI v6.13.
**Detailed reports**:
[`AUDIT_WIRE_FORMAT.md`](AUDIT_WIRE_FORMAT.md) (18 findings),
[`AUDIT_BUGS.md`](AUDIT_BUGS.md) (20 findings),
[`AUDIT_API.md`](AUDIT_API.md) (22 findings).

## TL;DR — the catastrophic finding

**`Connection::<Xfrm>::flush_policy()` doesn't flush policies. It
flushes all SAs.** And `flush_sa()` doesn't flush SAs either — it
sends `XFRM_MSG_UPDPOLICY` with a too-small body. Both methods have
been broken since the XFRM family shipped. Root cause: 4 hardcoded
kernel constants in `crates/nlink/src/netlink/xfrm.rs` are off by 1-4
because the original author counted enum positions wrong:

| Symbol | nlink has | Kernel UAPI v6.13 | What nlink actually emits |
|---|---|---|---|
| `XFRM_MSG_FLUSHSA` | `25` | `28` | `XFRM_MSG_UPDPOLICY` |
| `XFRM_MSG_FLUSHPOLICY` | `28` | `29` | `XFRM_MSG_FLUSHSA` — **flushes SAs!** |
| `XFRMA_SRCADDR` | `9` | `13` | `XFRMA_LTIME_VAL` (lifetime struct) |
| `XFRMA_OFFLOAD_DEV` | `26` | `28` | `XFRMA_ADDRESS_FILTER` (24-byte struct) |

Plus two adjacent shape errors on the same family:

| Method | Issue |
|---|---|
| `update_sa(...)` | Sends `NEWSA + NLM_F_REPLACE`; XFRM ignores `NLM_F_REPLACE` and dispatches by `nlmsg_type` alone → kernel calls `xfrm_state_add` → `-EEXIST` whenever the target SA exists. Must use `XFRM_MSG_UPDSA` instead. |
| `update_sp(...)` | Same pattern — sends `NEWPOLICY + NLM_F_REPLACE`; must use `XFRM_MSG_UPDPOLICY`. |

I verified the four constant errors directly against
`https://raw.githubusercontent.com/torvalds/linux/v6.13/include/uapi/linux/xfrm.h`
— the enum is counted correctly by the kernel and miscounted by
nlink. The `update_*` analysis was not personally verified against
the kernel handler but matches the documented XFRM dispatcher
behaviour and is consistent with everything else the audit found
in this file.

How did 0.19's Plan 213 sizeof CI gate miss these? It only verifies
struct sizes, not constant values. The Plan 204 cluster (nft
verdicts, also constants) was added via a hand-rolled `nft_verdict`
sizeof module; that pattern was never applied to XFRM. **Extending
the sizeof CI gate to assert constant values is the single
highest-leverage 0.20 prevention work.**

There's also a self-correcting irony hidden in this: the line
`update_sa` would need to emit (`XFRM_MSG_UPDSA = 26`) is exactly
the wrong value `XFRMA_OFFLOAD_DEV` currently holds — and the line
`update_sp` would need (`XFRM_MSG_UPDPOLICY = 25`) is exactly what
`XFRM_MSG_FLUSHSA` currently holds. The four off-by-one errors share
a single root miscounting.

---

## What else turned up

### Verified by reviewer against kernel UAPI
- **W7 (HIGH)** — nftables `CtKey::Expiration = 7`, kernel
  `NFT_CT_EXPIRATION = 5`. nlink's value 7 is `NFT_CT_L3PROTOCOL`.
  Every `Expr::Ct { key: CtKey::Expiration, .. }` loads the L3
  protocol byte instead of the expiration millisecond u32. Silent.
  Verified against
  `include/uapi/linux/netfilter/nf_tables.h::enum nft_ct_keys`.
- **W9 (MEDIUM, dead code)** — `TCA_HTB_OFFLOAD = 8`, kernel value
  is `9`. Currently unreferenced; blocks any future HTB-offload work.

### High-confidence agent findings (kernel cross-refs in detail report)
- **W8 (HIGH)** — DPLL `fractional_frequency_offset_ppt` typed as
  `Option<i32>`, kernel emits `sint` (variable-length, often s64).
  Same class as 0.19 Plan 206's `phase_offset` widening that was
  done for the same family — this field was missed. Affects telco/
  SyncE workloads with non-trivial FFO.

### Bug-hunt headlines
- **B1-B3 (HIGH on BE)** — `from_le_bytes` used on netlink-native
  NLA headers in **three** files: `netfilter.rs:1085`,
  `action.rs:3541`, `nftables/config/diff.rs:84,737`. The same bug
  was fixed in `xfrm.rs:1959-1960` for 0.19 N3 with an explicit
  *"Was `from_le_bytes` — silently broken on BE platforms"* comment.
  The fix was scoped to one file; the class wasn't swept. Trivially
  benign on x86/aarch64 (everything is LE); breaks every conntrack
  / TC action / nftables diff on s390x and PowerPC-BE.
- **B4 (HIGH)** — `recv_msg` silently truncates frames >32 KiB.
  No `MSG_TRUNC` check, no `MSG_TRUNC` flag passed to recv. The
  sibling `recv_batch_inner` path (Plan 158's `syscall_batch`)
  correctly bails on truncation; the single-frame fallback got
  missed. Triggers on large dump frames (nftables rulesets,
  conntrack tables with thousands of flows, ethtool message walks).
- **B5 (HIGH, verified by repro)** — WireGuard `parse_timespec`
  panics on a malformed handshake timestamp. `Duration::new(secs as
  u64, ...)` + `UNIX_EPOCH + duration` overflows when `secs` is
  negative. One bad multicast frame kills a long-lived subscriber.
  Violates CLAUDE.md Parser robustness rule 3 (recoverable
  per-message). The reviewer ran a repro at `/tmp/check_dur2.rs`.

### API headlines
- **A1 (MAJOR — pattern-match of the 0.14 units bug)** —
  declarative `QdiscBuilder::loss(f64)` is unclamped and unchecked,
  while imperative `NetemConfig::loss(Percent)` is typed. Same
  method name, two argument shapes: `loss(0.01)` interpreted as
  0.01% in one path, 1% in another. Should be `loss(Percent)` on
  both, deprecate the f64 form.
- **A2 (MID)** — `flush_rules(family: u8)`,
  `get_rules_for_family(family: u8)`, `del_rule_by_priority(family: u8, ...)`
  take raw libc family numbers. `flush_rules(4)` silently returns
  empty (kernel rejects). Should take a `nlink::Family` newtype.
- **A4/A5 (MID, doc-only)** — significant doc drift from 0.19's
  F1 async-ification: many `conn.events()` / `into_events()`
  examples shown as sync; `.loss(1.0)` examples don't compile. The
  rustdoc surface needs a sweep.
- **A8 (MID)** — nftables `Expr::Cmp { data: Vec<u8> }` takes raw
  bytes. The just-merged PR #10 added typed matchers (`match_*`)
  but the lower-level escape hatch is still untyped. Typed
  `match_ipv4 / match_u16_be` helpers exist; not all wire-shape
  primitives have them.
- **A11 (MID)** — `set_link_state(_, up: bool)` is a boolean trap.
  Should be `set_link_up(...)` / `set_link_down(...)` or take a
  `LinkState` enum.

The "Things that are designed well" section of `AUDIT_API.md`
(lines 220-231) is worth reading directly — typed-units coverage,
the `ParseParams` sealed-trait design, error-predicate I/O-shape
sweep, `#[non_exhaustive]` discipline, and the pool single-flight
design all read as load-bearing and intentional.

---

## Prioritized 0.20 action list

### P0 — hotfix candidate for 0.19.1

Ship as a point release within days, not weeks. The XFRM cluster
is silent, severe, and trivially fixable.

1. **Fix `XFRM_MSG_FLUSHSA` (25 → 28), `XFRM_MSG_FLUSHPOLICY` (28 → 29),
   `XFRMA_SRCADDR` (9 → 13), `XFRMA_OFFLOAD_DEV` (26 → 28)** —
   `crates/nlink/src/netlink/xfrm.rs:51,52,60,66`.
2. **Remove the assertion that encodes the bug**:
   `xfrm.rs:2139 assert_eq!(XFRMA_OFFLOAD_DEV, 26)` must flip to
   `28` (otherwise the unit test fails after the fix).
3. **Audit `xfrm.rs:2362 xfrm_update_sa_uses_create_and_replace_flags_not_excl`** —
   this test enforces the broken `update_sa` behaviour. Replace
   with a test that asserts `nlmsg_type == XFRM_MSG_UPDSA` and no
   `NLM_F_REPLACE`.
4. **Fix `update_sa` / `update_sp`** to send `UPDSA` / `UPDPOLICY`
   without `NLM_F_REPLACE`. `crates/nlink/src/netlink/xfrm.rs:1408,1498`.
5. **Fix `CtKey::Expiration = 7 → 5`** — nftables/types.rs:370.
6. **Add integration tests** under
   `crates/nlink/tests/integration/xfrm/` covering:
   - `flush_sa()` then `dump_sa()` returns empty
   - `flush_policy()` then `dump_sa()` returns the original SAs
     intact (would have failed pre-fix — `flush_policy` was
     deleting them)
   - `update_sa(existing)` succeeds (would have returned EEXIST
     pre-fix)
   - `update_sp(existing)` succeeds
   - SA with `offload(...)` dumps back with offload attached
     (would have shown an `address_filter` corruption pre-fix)
   - All gated with `require_root!()` + `require_modules!("xfrm")`

### P1 — 0.20 cycle plans

Open plan files now; land in 0.20.

7. **Plan X1 — Extend Plan 213 sizeof CI gate to constants**
   (`crates/nlink/src/netlink/sys_sizeof.rs` + new modules). Cover:
   - All `XFRM_MSG_*` (16 message types)
   - All `XFRMA_*` (~40 attribute IDs)
   - All `NFT_CT_*` (24 conntrack keys)
   - All `TCA_HTB_*` (10 HTB attrs — would have caught W9)
   - All `TCA_FLOWER_*` (~80 flower keys + masks — fast-growing
     kernel surface)
   This is the single biggest 0.20 prevention investment.
8. **Plan X2 — Big-endian wire-parsing sweep**
   (`from_le_bytes` → `from_ne_bytes` audit + CI gate).
   `scripts/audit-bytes-le.sh` that fails the build if `from_le_bytes`
   appears anywhere in `crates/nlink/src/netlink/` outside an
   allowed list (the documented LE-on-the-wire cases). Sweep
   landing fixes in netfilter, action, nftables/config/diff. Add
   an s390x `cargo check` job to CI (no test run; just compile
   check ensures structural correctness).
9. **Plan X3 — `recv_msg` MSG_TRUNC handling**
   (`crates/nlink/src/netlink/socket.rs:367`).
   Pass `MSG_TRUNC` flag to `recv`, check return value vs buffer
   size, escalate to a typed `Error::Truncated { received, buffer }`.
   Add an integration test that generates a large dump (5000+ flows
   or 50000 conntrack entries).
10. **Plan X4 — WireGuard `parse_timespec` robustness**
    (`crates/nlink/src/netlink/genl/wireguard/types.rs:326`).
    Wrap the `SystemTime + Duration` arithmetic in
    `checked_add(...)` + return `None` instead of panicking. Cover
    with a unit test feeding `secs = i64::MIN`.
11. **Plan X5 — DPLL `sint` codegen**
    (`crates/nlink/src/netlink/genl/dpll/messages.rs` + `nlink-macros`).
    Add a `sint` field type to the `#[derive(GenlMessage)]` macro
    runtime (reads len, dispatches 4 → `i32 as i64`, 8 → `i64`).
    Widen `fractional_frequency_offset` and `_ppt` to `Option<i64>`.
    Audit other DPLL fields against the YAML spec for the same
    class.

### P2 — 0.20 cycle plans, smaller scope

12. **Plan X6 — Typed `nlink::Family` newtype for raw `u8` API**
    (A2). Deprecate `flush_rules(u8)` etc., add typed variants.
13. **Plan X7 — Typed `Percent`/`Rate` on declarative builders**
    (A1). Flip `QdiscBuilder::loss(f64)` to `Percent`; deprecate
    the `f64` form across builders that have the same shape.
14. **Plan X8 — Doc drift sweep** (A4, A5, A18, A22). 0.19 added
    `cargo doc --deny broken-intra-doc-links` but it doesn't catch
    docs that compile-against-stale-API examples. Add a
    `cargo test --doc` gate and trace through every `loss(f64)` /
    `events().await` doc example that needs updating.
15. **Plan X9 — `Verdict::Jump(String) / Goto(String)` → typed
    chain ref** (A20). Use a `ChainName` newtype with `&str`
    accessor; helps with case-sensitivity + interior NULs.
16. **Plan X10 — `RuleMessage` convention alignment** (A3).
    Wrap pub fields with `pub(crate)` + accessors to match
    `LinkMessage` / `AddressMessage` / `RouteMessage` /
    `NeighborMessage`.

### P3 — robustness hygiene (batch into one PR)

17. **Plan X11 — Bug-hunt LOW-tier sweep** (B6, B9-B11,
    B13-B14, B16-B20). 11 small cleanups in one batch — `expect`
    calls in non-test code, `.unwrap()` after length guards (most
    are safe; convert to explicit panics with reasons or to `?`),
    redundant `from_errno(-errno)` calls, etc.
18. **Plan X12 — `DumpStream` fuse-on-error policy** (B7, B16).
    Currently fuses on one malformed frame; per CLAUDE.md Parser
    robustness rule 3 (recoverable per-message) it should `flatten()`
    and continue. Wire under the existing
    `audit-recv-loop-error-handling.sh` CI script's coverage.

---

## What the audits did NOT cover

Open issues to spawn follow-on audits or fuzz coverage for:

- **nl80211** — surface is huge and per-kernel-version churn is
  high; only spot-checked. Likely contains its own constant-drift
  bugs.
- **devlink rate + port-function-state** — newly added Plan 153.2
  attribute IDs not cross-referenced against current devlink YAML.
- **ethtool linkmodes bitset** — finicky bitfield32 wire format,
  documented competitor pain point (Cilium #40280), not opened.
- **net_shaper** — kernel-side YAML changed between 6.12 and 6.13,
  audit deferred. Newly shipped Plan 153.3 — drift-risk window
  open.
- **macsec / mptcp / wireguard** — macro-derived (lower risk) but
  the per-family attribute tables (`WGDEVICE_A_*` etc.) not
  cross-checked against kernel.
- **TC pedit / TC u32 selector** — typed configs not re-walked;
  pedit's offset-mask shape is an easy place to mis-align.
- **MPLS / SRv6 / NextHop** — typed structs not size-checked.
- **bridge_vlan / fdb** — recent additions, spot-check only.

## Verification notes

The three sub-audits used different methods. The reviewer:

- **Wire-format audit (W*)**: directly verified W1, W2, W3, W4, W7
  against upstream kernel header `v6.13/include/uapi/linux/xfrm.h`
  and `v6.13/include/uapi/linux/netfilter/nf_tables.h`. Reviewed
  the nlink source at the cited line numbers; all reproduce the
  reported constants. W5 + W6 (`update_*`) not personally verified
  against the kernel handler but the analysis matches documented
  XFRM dispatcher behaviour and the broader file's bug cluster.
  Lower-confidence findings (W11, W12, W15) reviewed inline; minor.
- **Bug hunt (B*)**: B5 was verified by repro at `/tmp/check_dur2.rs`
  (release-mode panic message reproduced). B1-B3 verified by
  reading the cited source against the xfrm.rs comment that already
  flags the bug class. B4 verified by reading
  `crates/nlink/src/netlink/socket.rs:367-383` against the
  `recv_batch_inner` sibling that handles MSG_TRUNC correctly.
  Other B-findings reviewed via cross-reference; not all
  individually repro'd.
- **API audit (A*)**: A1, A2 confirmed by reading the cited APIs
  directly. Doc-drift findings (A4, A5) tested against current
  source.

If the maintainer wants any specific finding deeply re-verified,
flag the ID and I'll write a focused proof.

---

**Bottom line**: the XFRM cluster (W1-W6) alone justifies a 0.19.1
hotfix. The remaining findings are 0.20-cycle work — the sizeof
CI gate extension (Plan X1) is the highest-leverage durable fix
since it would have caught all four constant errors at build time.
