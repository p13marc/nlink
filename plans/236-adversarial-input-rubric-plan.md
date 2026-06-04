---
to: nlink maintainers
from: 0.20 consolidation review (`PLAN_REVIEW.md` §4.2)
subject: cycle-wide adversarial-input testing rubric — every plan pins specific malformed inputs
status: planning
target version: 0.20.0
parent: [Plan 220 master](220-0.20-master-plan.md) §3.2 cycle-wide rubrics
source: [PLAN_REVIEW.md](../PLAN_REVIEW.md) §4.2 + user memory note `feedback_regression_test_first.md`
created: 2026-06-04
---

# Plan 236 — Adversarial-input testing rubric

## 1. Why this plan exists

The user's feedback memory `feedback_regression_test_first.md`
says: *"Write tests against contracts even when code 'looks
clean'. Plan 193 §2.3's test-the-policy work surfaced a real
MessageIter infinite-loop bug; trust adversarial inputs over
audit-by-grep."*

The consolidation review (`PLAN_REVIEW.md` §4.2) audited every
plan in the 0.20 suite against this rule and found that the
happy-path test coverage is solid but **adversarial-input
specification is under-developed** across the typed-API + parser
plans. Of the 16 plans, only Plan 225 (WG `parse_timespec`)
specifies named adversarial inputs at the resolution the rule
requires (`secs = i64::MIN`, `secs = -1`, `nanos = -1`,
`nanos = 1_500_000_000`, etc.).

The risk: a plan ships with happy-path tests passing and the
implementation looks clean, but the bug class it was meant to
close stays open because no test exercises the actual edge
that produces the bug. The original audit found the
`MessageIter` infinite-loop bug exactly this way — through
adversarial input, not by grepping for the class.

This plan exists as a **cycle-wide rubric** that the implementer
references when writing each plan's tests. It does NOT introduce
new code; it pins specific adversarial inputs per plan in a
table that becomes the implementer's checklist.

## 2. The rubric

Every plan in the cycle MUST satisfy:

1. **Happy-path coverage** — the documented normal use case
   round-trips through the change. (Already specified in every
   plan.)
2. **Boundary coverage** — values at the edges of valid ranges
   (zero, max, max-1, min, min+1). (Already specified in most
   plans.)
3. **Adversarial input coverage** — at least one test per plan
   that feeds a deliberately-malformed input the change must
   handle without panicking or silently producing wrong output.
   The malformed input value MUST be named in the plan; "test
   with malformed inputs" is not sufficient.

The third rule is what most plans currently under-specify.
Section 3 below lists the specific adversarial inputs each plan
must pin.

## 3. Per-plan adversarial-input checklist

Implementer reads the row for the plan they're working on,
ensures the named adversarial inputs appear in the test suite
before the plan is marked complete.

### 3.1 Wire-format + parser plans

| Plan | Adversarial inputs to pin |
|---|---|
| 221 | `XFRM_MSG_NEWSA` request with a too-short `xfrm_usersa_info` body (kernel rejects EINVAL); `xfrm_usersa_id` with `daddr = ::ffff:0:0` (IPv4-mapped IPv6 — valid but unusual); `del_sa` request with no XFRMA_SRCADDR (verify post-fix code path) |
| 222 | n/a — gate is compile-time integer compare; the constants are the inputs |
| 223 | NLA header bytes `[0xFF, 0xFF, 0x00, 0x00]` (length 65535 — pathological); NLA header with `len < 4` (invalid by spec); a deliberately byte-swapped NLA header that would parse OK as LE but is actually NE (only fires on BE host — caught by s390x compile job and runtime assertion if you have BE hardware) |
| 224 | Kernel response of exactly the buffer size (boundary — no truncation but caller can't distinguish); kernel response of buffer-size + 1 (truncation by 1 byte); kernel response of 100 MiB (forces auto-grow up to and past the 1 MiB cap → `Error::Truncated`) |
| 225 | `secs = i64::MIN`; `secs = -1`; `secs = i64::MAX`; `nanos = -1`; `nanos = 1_500_000_000` (out of range); `nanos = i32::MIN`; truncated frame (only 4 bytes of the expected 16) |
| 226 | DPLL FFO of `i64::MIN`; FFO of `i32::MAX + 1` (forces 8-byte sint); FFO of `0` (pinned 4-byte path); kernel frame with `nla_len = 7` (impossible — neither 4 nor 8 nor 0); `nla_len = 0` (treated as absent) |

### 3.2 Typed-API plans

| Plan | Adversarial inputs to pin |
|---|---|
| 227 | `AddressFamily::try_from(0xFF)` (unknown libc value — must return `Err`); `AddressFamily::try_from(0)` (AF_UNSPEC — accepted but flagged); round-trip `Family::Ipv4` through wire `u8` and back |
| 228 | `Percent::new(f64::NAN)` (must clamp or reject); `Percent::new(f64::INFINITY)`; `Percent::new(-0.0)` (negative zero — clamps to 0.0); `Percent::new(-1.5)` (clamps to 0.0); `Percent::new(150.0)` (clamps to 100.0); `Percent::from_fraction(0.01)` returns 1.0 (NOT 0.01 — the unit confusion is what this plan kills) |
| 229 | A recipe file with a `loss(1.0)` example (must compile clean post-228); a recipe with a `loss(Percent::new(150.0))` example (must compile; the clamp is the test); a recipe with `conn.events()` not `.await`-ed (must fail to compile post-F1) |
| 230 | `ChainName::new("")` (must reject); `ChainName::new("foo\0bar")` (must reject interior NUL); `ChainName::new("a".repeat(256))` (must reject — > 255 bytes); `ChainName::new("foo")` round-trip; non-UTF-8 byte sequence (the existing string-based API accepted invalid UTF-8 silently; new ChainName rejects via the `String` constructor) |
| 231 | `RuleMessage` parse with `family = 0xFF` (unknown libc family — accessor returns the right Err variant, not a panic); accessor invocation on a partially-parsed message (header valid, attrs malformed); round-trip with all-zero header (impossible kernel response — accessor returns sensible defaults) |

### 3.3 Robustness plans

| Plan | Adversarial inputs to pin |
|---|---|
| 232 | Per-finding inputs — each individual finding in the LOW batch gets one adversarial input. B19: socket that returns `EWOULDBLOCK` forever (verify the retry-with-backoff terminates eventually) |
| 233 | Stream that emits 100 valid frames + 1 malformed frame + 100 more valid frames; assert non-fuse mode counts 200, fuse mode counts 100; the malformed frame's byte pattern is pinned (e.g. `[0xDE, 0xAD, 0xBE, 0xEF]` as the leading 4 bytes — a deliberately-broken NLA header that's not valid in any endianness) |
| 234 | Stress test: 16 concurrent tasks × 1000 requests + 1 long-lived multicast subscriber; the subscriber's queue fills (force ENOBUFS); assert subscriber emits `ResyncMarker::ResyncStart` and continues; assert request latency p99 stays < 50ms even with the subscriber lagging by 10000 frames |
| 235 | Each migrated family: send 100 commands while a multicast stream is active; assert no stale-frame seq from family A is delivered to family B; specifically the wireguard `wg_command` original H9 race — request seq N, get a response from seq M ≠ N first, verify it's ignored not delivered |

### 3.4 Discretionary plans

| Plan | Adversarial inputs to pin |
|---|---|
| 197 | Peer with `peer_id = u32::MAX`; key with all-zero AEAD key (kernel may accept; we should reject upstream); SCM_RIGHTS cmsg with fd that closed mid-call (race); concurrent `peer_set` from two tasks on the same peer_id (last-write-wins is correct) |

## 4. How to use this checklist

The plan implementer:

1. Locates their plan's row in the table above.
2. Adds the named adversarial inputs to the plan's `## Test plan`
   section as concrete `#[test]` names with the input values
   inlined in the test body.
3. Confirms each test fails against pre-fix code (where
   applicable) and passes against post-fix code.
4. The PR review checklist (see Plan 220 §5) includes "all
   adversarial inputs from Plan 236 §3.X are exercised."

## 5. Test plan for this plan

This plan is itself a rubric, not code. Its "test" is whether
the implementers reference it. Acceptance:

- Each plan PR in the cycle (221-235) explicitly cites Plan 236
  in the PR description and notes which adversarial inputs from
  the table are exercised.
- The 0.20 cycle exit checklist (Plan 220 §5) includes "Plan 236
  adversarial inputs covered for all merged plans."

## 6. Risks

- **Checklist becomes ceremony**: if implementers add the named
  tests mechanically without thinking about what they're
  exercising, the rubric loses its value. Mitigation: each row
  in §3 includes a brief rationale (e.g. "the unit confusion is
  what this plan kills" for 228); implementer must understand
  the rationale, not just write the test.
- **Adversarial input table drift**: as plans evolve during
  implementation, the named inputs may go stale. Mitigation:
  this plan is a working document; update §3 alongside any
  plan-body edits, then revisit in the cycle-end review.
- **Coverage gap**: §3 may miss an important adversarial input
  for some plan. Mitigation: implementer is encouraged to ADD
  rows / inputs as they go; the table is a floor, not a ceiling.

## 7. Acceptance

- Plan 236 §3 has at least one named adversarial input per
  cycle plan (221-235).
- Each plan's `## Test plan` references Plan 236 §3.X and
  includes the adversarial inputs from the table.
- The 0.20 cycle migration guide notes Plan 236 as the
  test-discipline upgrade vs prior cycles.

## 8. Cross-references

- [`PLAN_REVIEW.md`](../PLAN_REVIEW.md) §4.2 (the systemic
  finding this plan answers).
- [`Plan 220 master`](220-0.20-master-plan.md) §3.2 cycle-wide
  rubrics.
- User memory: `feedback_regression_test_first.md` — "trust
  adversarial inputs over audit-by-grep."
- Historical example: 0.19 Plan 193 §2.3 (the MessageIter
  infinite-loop bug surfaced by adversarial-input testing).
