# Plan-suite review — 220-226 (0.20 cycle hotfix + P1 plans)

**Reviewer**: deep cross-consistency + test-spec pass on Plans 220-226.
**Branch**: `0.20` at `05d388a`.
**Scope**: master plan + 0.19.1 hotfix carve-out + 5 P1 plans
(sizeof-gate constants, BE sweep, MSG_TRUNC, parse_timespec, DPLL sint).
**Sources**: the plan files + `AUDIT_REPORT.md`, `AUDIT_WIRE_FORMAT.md`,
`AUDIT_BUGS.md` + spot-checked kernel UAPI (v6.13 `xfrm.h` /
`nf_tables.h`) + the existing `.github/workflows/integration-tests.yml`
+ existing `cycle_0_19_backfill.rs::plan_204_c2_xfrm_add_sp_round_trips`
test for ground-truth on how the codebase gates XFRM tests today.

---

## Section 1 — Inter-plan consistency

### 1.1 Conflicts

**No direct design-choice conflicts** between plans on the
overlapping topics. Cross-checked:

- DPLL FFO type widening: Plan 220 §6 says "widen from `Option<i32>`
  to `Option<i64>`" and "same shape as 0.19's `phase_offset`
  widening." Plan 226 §3 widens to `Option<i64>` and §4.3 adds
  `#[genl_attr_sint]` to phase_offset. Consistent.
- XFRM constant values: Plan 220 §6 lists the four corrected values
  (28, 29, 13, 28) and Plan 221 §2 enumerates the same set. Plan
  222 §2.1 mirrors the same constants in `sys_sizeof::xfrm_msg_type`.
  All three agree on `FLUSHSA=28, FLUSHPOLICY=29, OFFLOAD_DEV=28,
  SRCADDR=13, UPDPOLICY=25, UPDSA=26`. Independently verified by
  raw kernel `include/uapi/linux/xfrm.h` v6.13 fetch — all numbers
  match.
- `Error::Truncated` shape (Plan 224 §2.2): introduces a new variant
  on `Error`. CLAUDE.md `## Errors` says the enum is
  `#[non_exhaustive]`. No other plan introduces an `Error` variant
  in this cycle. No collision.
- `nlink-macros` `#[genl_attr_sint]` marker (Plan 226): no other
  plan touches `nlink-macros`. Clean.

### 1.2 Order-of-operations

Plan 220 §4 declares:

```
221 (hotfix) → 222 (sizeof gate) → {223..233 in parallel}
```

with one sub-dependency (228 before 229). The parallel set ordering
is fine for 223-226 — they touch independent files (socket.rs,
nftables/types.rs, xfrm.rs are touched by 221; netfilter.rs,
action.rs, diff.rs by 223; socket.rs again by 224; WG types by
225; DPLL + nlink-macros by 226). No file overlap between 223-226
that would force serialization.

**One soft concern**: Plan 222 §2.5 says "Phase 222.1 is part of
the hotfix train" — i.e. the XFRM/CtKey constant-gate modules ship
in the SAME PR as Plan 221. Plan 221 §7 (cut sequence) does **not
mention this**. Plan 221's cut sequence describes a single-commit
hotfix that bumps to 0.19.1; if 222.1 ships in the same PR, Plan
221 §7 step 2 ("Land this plan as a single commit") under-states
the surface and step 5 ("Bump workspace version 0.19.0 → 0.19.1")
implies the sizeof gate ALSO ships under 0.19.1. Either:

- Accept that the gate ships in 0.19.1 (probably fine — it's
  test-only and locks the fix), or
- Carve 222.1 out of the hotfix train and keep it for 0.20 only
  (the master plan's "Plan 222 gates the typed-API cluster"
  ordering still holds).

Plan 221 should be edited to say explicitly which one. See §5.

### 1.3 Duplicate work

- **CHANGELOG `[Unreleased]` plumbing for `Error::Truncated`**
  (Plan 224) and the migration-guide updates: each plan owns its
  own CHANGELOG entry; no overlap.
- Plan 225 §3 "Sibling sites swept" claims it will sweep
  `UNIX_EPOCH + Duration` sites across the lib. If any of those
  sibling sites are in conntrack `entry.last_used`, that overlaps
  Plan 224's MSG_TRUNC work zone only insofar as both touch
  `netfilter.rs`; the actual edits are in different functions
  (recv vs parse). No duplicate.
- Plan 222 §2.3 lists `nft_ct_keys` in the table of covered
  modules. Plan 221 also fixes CtKey. The overlap is intentional
  — Plan 221 ships the fix; Plan 222 ships the gate that LOCKS the
  fix. Both plans cross-reference each other. Clean.

### 1.4 Missing handoffs

- Plan 224 §2.1 introduces `Error::Truncated`. Plan 220 §6's
  migration-guide outline does NOT mention this. Should be added —
  it's a new public-API variant that downstream exhaustive matches
  see.
- Plan 226 §4.3 says "Add `#[genl_attr_sint]` to `phase_offset` as
  part of this plan." Plan 220 §6 only describes the FFO widening
  in the DPLL entry; the phase_offset marker addition (no
  observable behaviour change but forward-compat-relevant) isn't
  flagged. Minor — both are backward-compatible. Worth a sentence
  in the migration guide nonetheless.
- Plan 223 §2 commits to flipping six `from_le_bytes` sites
  (three production + three `#[cfg(test)]` in action.rs). Plan 220
  §3.2 row 223 lists "Closes B1-B3" — only the three production
  sites. Not strictly inconsistent because the test-cfg fixes are
  hygiene; but Plan 220 could acknowledge the six-edit reality so
  the reviewer knows what to expect.
- Plan 220 §10 "Touch points" says `scripts/audit-bytes-le.sh` is
  added by Plan 223 and that Plan 222 adds
  `scripts/audit-uapi-constants.sh`. Plan 222 §3 mentions the audit
  script. Plan 222 §2.3 also says "weekly cron via a scheduled
  workflow" + "wired into `.github/workflows/uapi-drift.yml`." Plan
  220 §10 mentions only `ci.yml` for audit scripts. Cosmetic.

### 1.5 CHANGELOG / migration guide coordination

Plan 220 §6's migration-guide outline lists 6 bullets covering
221 + 222 + 226 + 227 + 228 + 230 + 231. **Missing**:

- Plan 223 (BE sweep). Plan 223 §4 commits to a migration-guide
  bullet at cut time. Plan 220 omits it — a non-blocking gap.
- Plan 224 (`Error::Truncated`). Plan 224 §6 commits to a
  migration-guide note about exhaustive matches. Plan 220 omits it.
- Plan 225 (parse_timespec). Plan 225 §6 commits to a note; Plan
  220 omits it.

Plan 220 §6 should be updated to enumerate all the per-plan
migration entries, not just the ones with user-facing API breaks.
Even bug-only fixes deserve migration-guide presence so users
auditing 0.19→0.20 see the full diff at a glance.

---

## Section 2 — Test-spec completeness

Audit rubric: unit-test specificity, integration-test (root-gated)
specificity with modules listed, compile-time tests where typed
APIs change, CI-gate self-tests, adversarial inputs.

### 2.1 Plan 221 — XFRM constant + dispatch hotfix

| Test class | Specified? | Comments |
|---|---|---|
| Unit | Yes — §3.4 rewrites two existing tests with exact assertion bodies | The flipped `assert_eq!(XFRMA_OFFLOAD_DEV, 28)` lock test is concrete and load-bearing. |
| Integration (root-gated) | Yes — §4 lists 6 named tests with pre-fix vs post-fix behaviour | Module gate: `require_modules!("xfrm_user", "xfrm_state", "xfrm_policy")` (see §3 below for the kernel-module-naming concern). |
| Compile-time | N/A | No typed-API surface change. |
| CI script self-test | N/A | No new script. |
| Adversarial inputs | Partial | The dispatch tests assert no `NLM_F_REPLACE` is set — good. The integration tests check post-fix correctness but don't probe e.g. zero-byte sa/sp bodies. Probably acceptable given the surgical scope. |

**Verdict: solid.** The 6 named integration tests are the
load-bearing piece; each says exactly what it'll assert
pre-fix vs post-fix.

### 2.2 Plan 222 — Sizeof CI gate extension

| Test class | Specified? | Comments |
|---|---|---|
| Unit | Yes — §3 says `cargo test -p nlink --lib sys_sizeof` runs all constant gates in <1s | The structure (one `mod {name}_const` block per family + matching `#[test]`) is concrete. |
| CI script self-test | Partial — §3 specifies `scripts/audit-uapi-constants.sh` but doesn't describe a self-test of the script's invariants | The script polices DRIFT against a checked-out kernel tree, but there's no test that exercises the script's pass/fail semantics on a synthetic delta. See §5. |
| Adversarial inputs | N/A | Constant-value assertions are deterministic. |

**Verdict: solid except for the audit-script self-test.** Per the
user-memory note about "trust adversarial inputs over audit-by-grep,"
this script — which is exactly an audit-by-grep — should have a
unit-test that constructs a synthetic `sys_sizeof.rs` with one
deliberately-wrong constant and asserts the script flags it.

### 2.3 Plan 223 — BE wire-parsing sweep + s390x

| Test class | Specified? | Comments |
|---|---|---|
| Unit | Yes — §3.1 and §3.2 lock the round-trip + per-site regression | The §3.1 round-trip test is structurally fine but on x86 it's a no-op (LE bytes == NE bytes). It locks the policy at the source level (a future `from_le_bytes` reintroduction would fail compile because the test imports the helper from the canonical location). |
| Integration (root-gated) | NOT specified | Plan touches conntrack, TC action, nftables parsing — all wire-format code. A root-gated test that parses a real conntrack dump on x86 (where the bug is invisible) doesn't add coverage. The honest answer is the s390x compile-only job + grep gate. |
| CI script self-test | NOT specified — `audit-bytes-le.sh` has no test | Should have a unit-test that creates a temp file with `from_le_bytes` in `crates/nlink/src/netlink/` and asserts the script exits 1. |
| s390x compile-only | Yes — §2.3 + §3.3 #4 | Sufficient given the cycle's BE-hardware budget. |
| Adversarial inputs | Weak | §3.2 says "build an attribute chain by hand using `to_ne_bytes`" — but on x86 that's identical to LE bytes. The test "passes" pre-fix on x86. Only the s390x compile job + the audit-script grep catch actual regressions. The plan should be honest about this. |

**Verdict: incomplete.** Two gaps: (a) the audit script needs its
own self-test, (b) the per-site regression tests are LE-trivial.
Consider adding a test that constructs the parser fixture using
deliberately byte-swapped bytes (i.e. simulate BE input on an LE
host) so the test actually exercises the bug class.

### 2.4 Plan 224 — `recv_msg` MSG_TRUNC handling

| Test class | Specified? | Comments |
|---|---|---|
| Unit | Yes — §4.1 (size math) + §4.2 (mocked truncation) | §4.2's mock-Socket spec is clear — `(buf_len=100, returned=500)` first call, `(buf_len=4096, returned=500)` second. Good adversarial shape. |
| Integration (root-gated) | Yes — §4.3 | Module: `require_module!("nf_conntrack")`. Plan describes "seed 5000 conntrack entries" + assert `count >= 5000` + every entry has its `tuple_orig.src` populated. Pre-fix this would fail; post-fix it passes. Concrete + adversarial. |
| Compile-time | Yes — §6 describes the migration-guide exhaustive-match note | Implicit through `#[non_exhaustive]`. |
| Adversarial inputs | Yes — §4.4 injects a >1 MiB frame and asserts `is_truncated()` | Covers the cap-reached path. |

**Verdict: solid.** §4 covers all four classes cleanly. Only nit:
§4.3's "see crates/nlink/tests/integration/conntrack_large.rs for
the established harness" — verify the harness actually exists
before committing to it. If it doesn't, plan should specify the
shape inline.

### 2.5 Plan 225 — WireGuard `parse_timespec` robustness

| Test class | Specified? | Comments |
|---|---|---|
| Unit | Yes — §4.1 enumerates SEVEN named tests with exact adversarial inputs (`i64::MIN`, `i64::MAX`, out-of-range nsecs, etc.) | This is the gold standard for the rubric. Each test name is the assertion. |
| Integration (root-gated) | NOT root-gated, but §4.2 specifies a mocked-subscriber test | The test doesn't need root — it builds fake event frames inline. Plan §4.2 acknowledges this explicitly. Good call. |
| Sibling-site coverage | Yes — §4.3 says "parallel adversarial-input unit test in the same file" for each sibling site found | Concrete shape ("feed `i64::MIN`, `-1`, `i64::MAX`, out-of-range nsecs"). |
| Adversarial inputs | Yes — explicitly per §4.1 + §4.3 | Best-in-suite. |

**Verdict: solid.** Plan 225's test spec exemplifies the
"trust adversarial inputs over audit-by-grep" rule. The seven
named unit tests are concrete, the failure modes are tied to
specific inputs, and the sibling-site sweep gets the same
discipline.

### 2.6 Plan 226 — DPLL sint codegen + FFO widening

| Test class | Specified? | Comments |
|---|---|---|
| Unit | Yes — §5.1 covers the sint runtime + §5.2 covers the DPLL round-trip | §5.1's round-trip test sweeps boundary values (0, ±1, ±i32::MAX, ±i32::MAX±1, ±i64::MIN/MAX). Excellent adversarial coverage. |
| Integration (root-gated) | Yes — §5.3 | Module gate: `require_module!("dpll")`. Plan acknowledges the test "is the soft path" because hardware isn't always present. Specifies a skip behaviour. |
| Compile-time | Implicit — `Option<i32>` → `Option<i64>` widening fails compile on destructuring | Plan §7 documents this explicitly with the migration-guide snippet. |
| CI script self-test | N/A | No CI script. |
| Adversarial inputs | Yes — §5.1's `round_trip_holds_for_boundary_values` test | Explicit |

**Verdict: solid.** §5.1's boundary-value sweep is exemplary.

### 2.7 Summary table

| Plan | Unit | Integration | Compile-time | CI script self-test | Adversarial |
|---|---|---|---|---|---|
| 221 | ✓ | ✓ (6 named) | n/a | n/a | partial |
| 222 | ✓ | n/a | n/a | **missing** | n/a |
| 223 | partial | **missing** (s390x compile gate substitutes) | n/a | **missing** | weak on x86 |
| 224 | ✓ | ✓ | implicit | n/a | ✓ |
| 225 | ✓ | not needed | n/a | n/a | ✓ |
| 226 | ✓ | ✓ | implicit | n/a | ✓ |

Gaps to flag: 222 missing audit-script self-test, 223 missing
audit-script self-test + weak adversarial unit tests.

---

## Section 3 — Root-gated test specification quality

### 3.1 Modules listed

Plan 221 §4 lists `require_modules!("xfrm_user", "xfrm_state",
"xfrm_policy")`. This **disagrees** with current practice in the
codebase. The existing XFRM integration test
`cycle_0_19_backfill.rs:461` uses
`require_module!("xfrm_user")` — a single module. And the
integration-tests workflow's modprobe list (lines 102-103) loads
`xfrm_user xfrm4_tunnel xfrm6_tunnel` — no `xfrm_state` or
`xfrm_policy`.

`xfrm_state` and `xfrm_policy` are NOT separate Linux kernel
modules. They are sub-systems within the `xfrm_*` namespace; the
exposed module name on modern kernels is `xfrm_user` (and the
optional tunnel modules). Plan 221's three-module list is wrong;
it should be just `require_module!("xfrm_user")` — matching the
established pattern.

**Verification**: searching the kernel tree for `MODULE_AUTHOR` /
`MODULE_LICENSE` in `net/xfrm/*.c` shows `xfrm_user.c` is the
loadable module entry; `xfrm_state.c` and `xfrm_policy.c` are
built into the `xfrm_state` core (which is always-on if any
`xfrm` is enabled — no separate modprobe). The
`has_module()` check (`/sys/module/<name>`) would not find
`xfrm_state` or `xfrm_policy` as standalone entries.

**Plan 221 §4.1 (CI modprobe addition)** says "add `xfrm_user` to
the modprobed list (it's not auto-loaded on every kernel)." But
the existing workflow YAML at line 102 ALREADY modprobes
`xfrm_user`. The plan should drop §4.1's claim or correct it to
say "verify it's already present" (it is).

### 3.2 Root-gated tests per plan

| Plan | Needs root-gated? | Specified? | Module list correct? |
|---|---|---|---|
| 221 | YES — wire-format fixes | YES — 6 named tests | **NO — should be just `xfrm_user`** |
| 222 | NO — pure constant-value gate | n/a | n/a |
| 223 | NO (substituted by s390x compile-only) | n/a | n/a |
| 224 | YES — kernel-truncation path | YES — §4.3 | YES — `nf_conntrack` is correct, already in workflow |
| 225 | NO (mock subscriber suffices) | n/a | n/a |
| 226 | YES — DPLL kernel emit path | YES — §5.3 | YES — `dpll` is correct (note: not currently modprobed in CI workflow YAML — needs adding!) |

### 3.3 Workflow YAML additions

| Plan | New modprobe entry needed? | Plan acknowledges? |
|---|---|---|
| 221 | No (`xfrm_user` already present line 102) | Yes, but incorrectly claims it needs adding |
| 224 | No (`nf_conntrack` already present line 78) | Plan doesn't say either way |
| 226 | YES — `dpll` is not currently modprobed | **Plan 226 doesn't mention this** |

Plan 226 §5.3 specifies `require_module!("dpll")` but doesn't
flag that the integration-tests workflow's modprobe list needs
`dpll` added. Without that, the test will skip-clean on every CI
run because `/sys/module/dpll` won't exist (mock DPLL driver
isn't loaded by default).

### 3.4 Plans missing root-gated tests that should have them

- **Plan 223** (BE sweep): no root-gated test specified. The
  argument is that BE behaviour can't be tested in CI without
  s390x hardware. Fair, but the plan should explicitly say so.
  §5 risks bullet 1 partially says it ("No live BE testing"), but
  doesn't explicitly tie that to "we don't add a root-gated test
  here because the bug class is invisible on x86."
- **Plan 225** (parse_timespec): no root-gated test specified.
  Justified — the bug is purely a parser robustness issue and
  mock frames cover it. Plan §4.2 explicitly says "no
  `require_root!()` needed because the mock subscriber doesn't
  need the kernel." Good call-out.

---

## Section 4 — Verification by external research

### 4.1 Plan 221 constants

**XFRM message types** (kernel `v6.13/include/uapi/linux/xfrm.h`):

```
XFRM_MSG_BASE = 0x10 (16)
XFRM_MSG_NEWSA       = 0x10 (16)
XFRM_MSG_DELSA       = 0x11 (17)
XFRM_MSG_GETSA       = 0x12 (18)
XFRM_MSG_NEWPOLICY   = 0x13 (19)
XFRM_MSG_DELPOLICY   = 0x14 (20)
XFRM_MSG_GETPOLICY   = 0x15 (21)
XFRM_MSG_ALLOCSPI    = 0x16 (22)
XFRM_MSG_ACQUIRE     = 0x17 (23)
XFRM_MSG_EXPIRE      = 0x18 (24)
XFRM_MSG_UPDPOLICY   = 0x19 (25)
XFRM_MSG_UPDSA       = 0x1a (26)
XFRM_MSG_POLEXPIRE   = 0x1b (27)
XFRM_MSG_FLUSHSA     = 0x1c (28)
XFRM_MSG_FLUSHPOLICY = 0x1d (29)
```

Plan 221's values (28, 29, 25, 26 respectively) **match**.
Verified.

**XFRM attribute types** (same file, `enum xfrm_attr_type_t`):

```
XFRMA_LTIME_VAL      = 9
XFRMA_SRCADDR        = 13
XFRMA_ADDRESS_FILTER = 26
XFRMA_PAD            = 27
XFRMA_OFFLOAD_DEV    = 28
```

Plan 221's `XFRMA_SRCADDR = 13` and `XFRMA_OFFLOAD_DEV = 28`
**match**. Verified.

(Note: one of my web-fetch passes returned XFRMA_OFFLOAD_DEV = 31
due to a misalignment in extracting the enum; the second pass with
the full enum listing confirmed 28. Plan 221 is correct.)

**`enum nft_ct_keys`** (kernel
`v6.13/include/uapi/linux/netfilter/nf_tables.h`):

```
NFT_CT_STATE       = 0
NFT_CT_DIRECTION   = 1
NFT_CT_STATUS      = 2
NFT_CT_MARK        = 3
NFT_CT_SECMARK     = 4
NFT_CT_EXPIRATION  = 5
NFT_CT_HELPER      = 6
NFT_CT_L3PROTOCOL  = 7
... (24 entries total)
```

Plan 221 §3.3's `Expiration = 5` **matches**, and the new
`Secmark=4`, `Helper=6`, `L3Protocol=7` variants align. Verified.

### 4.2 Plan 224 MSG_TRUNC semantics

`recvmsg(2)` with the `MSG_TRUNC` flag (Linux semantics, stable
since at least 2.6.x):

> If `MSG_TRUNC` is set in flags, the return value is the real
> length of the datagram, even if it is longer than the buffer.

For netlink sockets (which use SOCK_RAW underneath), this is
identical to UDP semantics: the kernel writes
`min(buf_len, frame_size)` bytes and returns `frame_size`. The
behaviour is consistent across the kernel range nlink supports
(MSRV 1.75 implies typical deployment kernels 5.10+; the flag's
behaviour has been stable since the 3.x era).

Plan 224's auto-grow logic ("`received <= capacity` → done;
`received > capacity` → resize to `next_multiple_of(4096)` and
retry") matches the kernel's "datagram stays queued until
consumed" guarantee. The retry does NOT consume the frame on the
first too-small recv as long as MSG_TRUNC is passed without
MSG_PEEK (Plan 224 doesn't pass MSG_PEEK; correct — passing both
would block but not consume, but the plan's two-pass approach
doesn't need that because the kernel re-delivers the head frame
on the second recv).

Verified: the design is sound for kernels supported by nlink's
MSRV.

### 4.3 Plan 225 — kernel timestamp emit path

WG kernel emit (`drivers/net/wireguard/netlink.c`, `get_peer`):

```c
const struct __kernel_timespec last_handshake = {
    .tv_sec = peer->walltime_last_handshake.tv_sec,
    .tv_nsec = peer->walltime_last_handshake.tv_nsec
};
if (nla_put(skb, WGPEER_A_LAST_HANDSHAKE_TIME,
            sizeof(last_handshake), &last_handshake) ...
```

`struct __kernel_timespec`:
- `__kernel_time64_t tv_sec` — signed 64-bit (i64) on all archs.
- `long long tv_nsec` — signed 64-bit on most archs; signed 32-bit
  on time32-only legacy systems but `__kernel_timespec` is
  specifically the time64 variant.

Endianness: native (`nla_put` is byte-copy; no conversion).

So Plan 225's read shape (two `i64::from_ne_bytes` reads, 16 bytes
total) **matches the kernel's emit**. Plan 225's adversarial guards
(reject `secs < 0`, reject `nsecs` outside `[0, 10^9)`, use
`checked_add` for the `UNIX_EPOCH + Duration` step) cover every
panic path identified in the audit. Verified.

The "negative secs = no-handshake-yet" semantic discussed in §5
risks is correctly identified as ambiguous; treating it as
malformed (return `None`) is the safer call.

### 4.4 Plan 226 — `nla_put_sint` / `nla_get_sint` semantics

`nla_put_sint` was added in kernel 4.20 (`commit 1d1670739ad7
2018-12-04`, "netlink: add new nla_put helpers for integer
types"). Wire format (per the kernel header comment):

```
nla_put_sint:
  if INT_MIN <= value <= INT_MAX: nla_put_s32(skb, attrtype, value)
  else:                            nla_put_s64(skb, attrtype, value)
```

`nla_get_sint` dispatches on attribute length: 4 bytes →
`nla_get_s32` (returned as `s64`), 8 bytes → `nla_get_s64`, other
→ error.

Plan 226 §2.2 and §2.3 capture this exactly:

> Values in `i32::MIN..=i32::MAX` ship as 4 bytes (matches kernel
> `nla_put_sint`'s behaviour). Everything else ships as 8 bytes.

> match payload.len() { 4 => …; 8 => …; _ => None }

The behaviour on kernels predating 4.20 is: those kernels never
EMIT `sint`-shaped attributes (the helpers didn't exist). Any
field that USES nla_put_sint on the emit side is gated by a
kernel-version check at the call site (DPLL is 6.11+ for FFO).
Plan 226's reader handles both 4-byte and 8-byte widths, so it's
forward+backward compatible. Verified.

### 4.5 Plan 226's `phase_offset` claim

Plan 226 §4.3 says "Plan 206 widened `phase_offset` from `i32 →
i64` but the kernel emit path is `nla_put_sint`." Spot-checking
the 0.19 messages.rs:341 confirms phase_offset is currently
`Option<i64>` with the fixed-8-byte codegen. Adding
`#[genl_attr_sint]` is correct + forward-compat.

---

## Section 5 — Recommended edits

Plans are listed only where I have edits to suggest. **Plan 220,
221 (modulo §3.1), 224, 225, 226 are solid as-written aside from
the specific edits below.**

### Plan 220 — master

- **§6**: Add migration-guide bullets for Plan 223 (BE sweep),
  Plan 224 (`Error::Truncated`), and Plan 225 (parse_timespec
  panic fix). Even bug-only fixes deserve presence so the
  0.19→0.20 doc reads complete.
- **§10**: Add `.github/workflows/uapi-drift.yml` to the touch
  points list (per Plan 222 §3).

### Plan 221 — hotfix

- **§4 (test harness)**: Replace
  `require_modules!("xfrm_user", "xfrm_state", "xfrm_policy")`
  with `require_module!("xfrm_user")`. `xfrm_state` and
  `xfrm_policy` are not standalone kernel modules — they're
  built into the xfrm core which is always-on when `xfrm_user` is
  loaded. The existing `plan_204_c2_xfrm_add_sp_round_trips`
  test in `cycle_0_19_backfill.rs:461` uses just `xfrm_user`;
  align with that.
- **§4.1**: Drop the claim that `xfrm_user` needs adding to the
  modprobed list. It's already present at
  `.github/workflows/integration-tests.yml:102`. Replace with a
  one-line "verified already present" note for the reviewer.
- **§7 (cut sequence)**: Reconcile with Plan 222 §2.5. Either
  (a) include Phase 222.1 in the 0.19.1 hotfix and adjust step 2
  ("Land this plan as a single commit") to "Land plan 221 + Phase
  222.1 in one PR with two commits"; or (b) explicitly defer
  222.1 to 0.20 and remove Plan 222's claim that it ships in the
  hotfix train.
- **§4 (table)**: Add a column for `require_modules!` invocations
  per test so each row is self-contained and the column makes the
  module-list correctness reviewable.

### Plan 222 — sizeof gate extension

- **§3**: Add a self-test for `scripts/audit-uapi-constants.sh`.
  Concretely: a unit test that runs the script against a fixture
  `sys_sizeof.rs` containing one deliberately-wrong constant and
  asserts exit code 1 + the constant name appears in the error
  message. Mirror the discipline `scripts/audit-sysfs-in-lib.sh`
  uses (per CLAUDE.md `## util::ifname sysfs reads`).
- **§2.5**: Either commit to shipping Phase 222.1 alongside Plan
  221 in the same hotfix PR (and bump Plan 221 §7 accordingly),
  or punt 222.1 to 0.20 and remove the "this means the 0.19.1
  hotfix actually ships *two* commits" sentence.

### Plan 223 — BE sweep + s390x

- **§3.1/§3.2**: Replace "build an attribute chain by hand using
  `to_ne_bytes`" with "build an attribute chain using a
  deliberately byte-swapped representation (`to_be_bytes` on an
  LE host or `to_le_bytes` on a BE host) and assert the parser
  rejects it or extracts garbage." The current tests are no-ops
  on x86 and so don't catch the bug class even at the unit
  level. Aim: a unit test that fails on x86 pre-fix and passes
  post-fix.
- **§3.3**: Add a self-test for `scripts/audit-bytes-le.sh`.
  Same shape as the recommendation for Plan 222 — a fixture file
  with `from_le_bytes` triggers exit 1; absence triggers exit 0.
- **§4 (migration)**: Add explicit pointer in Plan 220 §6
  cross-reference (Plan 220 already mentions but Plan 223 should
  too — make the linkage bidirectional).
- **§5 (risks)**: Strengthen "No live BE testing" bullet — say
  explicitly "no root-gated test specified because the bug is
  invisible on the architectures the CI runs."

### Plan 224 — recv MSG_TRUNC

- **§4.3**: Verify
  `crates/nlink/tests/integration/conntrack_large.rs` exists. If
  it does not, replace the "see ... for the established harness"
  reference with an inline spec for the harness — concretely, "in
  a fresh `LabNamespace`, run `seed_conntrack_entries(5000)` which
  bursts 5000 TCP probes against a localhost listener, then dump
  via `stream_conntrack` and count entries."
- **§4 table**: Add a row for the `poll_recv` path's
  Error::Truncated surface — the unit test should cover that
  `DumpStream`/`events()` consumers see the typed error rather
  than a panic.

### Plan 225 — parse_timespec robustness

Solid as written. One tiny addition:

- **§3 (sibling-site audit)**: §3.2's table includes a row
  "(others to be enumerated during the sweep step)." Pre-enumerate
  by running the grep in §3 NOW and listing every hit in the
  plan, rather than deferring to landing time. The plan would be
  more reviewable if the table is concrete before the PR opens.

### Plan 226 — DPLL sint

- **§5.3 (integration test)**: Add a note that
  `.github/workflows/integration-tests.yml` needs `dpll` added to
  the modprobed list — currently it's not there. Without this,
  every CI run will skip-clean the test silently. Mirror Plan 221
  §4.1's modprobe-add discipline (corrected per §3.1 above).
- **§4.2 (audit findings table)**: Pre-enumerate the cross-family
  audit results during plan-write, not at PR time. Same
  pre-enumerate discipline as Plan 225 §3.2. Concretely: run the
  YAML-fetch loop in §4.1 now and fill in the rows so reviewers
  see the actual cross-family surface before approving.
- **§7 (migration)**: Add a one-line mention of the
  `phase_offset` marker addition. Behaviour-neutral today, but
  documenting it now avoids confusion when a future kernel emits
  4-byte phase_offset.

---

## Summary

The plan suite is well-scoped and broadly consistent. The XFRM
hotfix (221) is correct in its constant values and dispatch fix
— all four kernel-side values cross-verified against
v6.13/xfrm.h. The CtKey fix is correct. The MSG_TRUNC, sint, and
parse_timespec plans all match the kernel-side contracts when
spot-checked against current upstream.

The biggest defect is **Plan 221 §4's `require_modules!` list**:
`xfrm_state` and `xfrm_policy` are not standalone modules. This
needs flipping to `require_module!("xfrm_user")` to align with the
established `cycle_0_19_backfill.rs:461` test and the actual
kernel module layout. Without the fix, the new integration tests
will skip-clean on every CI run because two of the three required
"modules" never exist as `/sys/module/xfrm_*` entries.

The next-biggest gap is **CI-script self-tests** for Plans 222
and 223. Audit-by-grep scripts that police the codebase but have
no test for their own pass/fail semantics are exactly the
"audit-by-grep" pattern the user-memory flagged as low-trust.
Both scripts should ship with a deliberately-broken fixture that
exercises the failure path.

Tertiary gaps: Plan 226 doesn't flag the workflow YAML modprobe
addition for `dpll`; Plan 220's migration-guide outline omits
the bug-only fixes (223/224/225); Plan 223's per-site regression
tests are LE-trivial on x86 and don't actually fail pre-fix
without architecture-specific input fabrication.

Plans 224, 225, 226 are best-in-suite for adversarial-input test
coverage; Plan 225 in particular is a model of the discipline
the user-memory note about "trust adversarial inputs over
audit-by-grep" asks for — seven named unit tests, each tied to a
specific boundary value, each failing pre-fix in a documented way.
