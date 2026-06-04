# Plan-suite consolidation review

**Reviewer**: deep cross-consistency + test-spec pass on Plans 220-235 (+ 197).
**Branch**: `0.20` at `152d806` (post audit + plan suite commit).
**Method**: three parallel reviews (one per cluster) + reviewer
synthesis + external kernel-UAPI cross-checks. Per-cluster
reports retained at the repo root for traceability:
- [`PLAN_REVIEW_220_226.md`](PLAN_REVIEW_220_226.md) — master + hotfix + correctness
- [`PLAN_REVIEW_227_231.md`](PLAN_REVIEW_227_231.md) — typed-API
- [`PLAN_REVIEW_232_235_197.md`](PLAN_REVIEW_232_235_197.md) — hygiene + discretionary

## 1. TL;DR

The 16-plan suite is internally consistent and externally
verified. Five must-fix defects identified and applied at this
commit (see §3); the rest are systemic-quality improvements the
implementer should pick up as each plan lands. The biggest
deferred item is **adversarial-input specification** — most plans
specify happy-path tests but the typed-API and parser plans
should pin specific malformed inputs (NaN, interior NUL,
i64::MIN, etc.). Calling that out as a cycle-wide test rule
in §4.2 below.

## 2. Verification status

### Kernel-UAPI cross-checks (independently re-verified)

| Plan | Claim | Source | Status |
|---|---|---|---|
| 221 | XFRM_MSG_FLUSHSA=28, FLUSHPOLICY=29, UPDPOLICY=25, UPDSA=26 | `v6.13/include/uapi/linux/xfrm.h` enum | ✅ confirmed |
| 221 | XFRMA_SRCADDR=13, XFRMA_OFFLOAD_DEV=28 | same enum | ✅ confirmed |
| 221 | NFT_CT_EXPIRATION=5 (nlink had 7 = NFT_CT_L3PROTOCOL) | `v6.13/include/uapi/linux/netfilter/nf_tables.h` `enum nft_ct_keys` | ✅ confirmed |
| 224 | MSG_TRUNC semantics: return value = actual frame size when flag passed | Linux `recvfrom(2)` + `netlink(7)` | ✅ confirmed |
| 225 | WG kernel emits last-handshake timestamp as `struct __kernel_timespec` | `drivers/net/wireguard/netlink.c::wg_get_device_dumpit` | ✅ confirmed |
| 226 | `nla_put_sint` emits 4 bytes if value fits in s32, 8 bytes otherwise | `lib/nlattr.c::nla_put_sint` | ✅ confirmed |
| 226 | DPLL FFO is `sint` in YAML spec | `Documentation/netlink/specs/dpll.yaml` line 211 | ✅ confirmed |
| 227 | `fib_rule_hdr.family` is `__u8` | `v6.13/include/uapi/linux/fib_rules.h` | ✅ confirmed |
| 228 | `tc_netem_qopt.loss` is `__u32` with no kernel-side validation | `v6.13/include/uapi/linux/pkt_sched.h::tc_netem_qopt` | ✅ confirmed |
| 230 | `NFT_NAME_MAXLEN = 256` (max name = 255 bytes + NUL) | `v6.13/include/uapi/linux/netfilter/nf_tables.h` | ✅ confirmed |
| 234 | neli's NlRouter implementation pattern | `github.com/jbaublitz/neli/blob/main/src/router/asynchronous.rs` | ✅ confirmed (Plan 234's ENOBUFS routing is BETTER than neli's — see §4.3 below) |
| 197 | ovpn YAML: 8 commands + 3 notifications (NOT 11) | `Documentation/netlink/specs/ovpn.yaml` | ⚠ corrected via plan edit |

All wire-format claims verified. Plan 197's command-count error
is the only kernel-side miscount in the suite; corrected via
inline note in §3.

## 3. Must-fix defects (applied in this commit)

These edits ship in the same commit as this review:

1. **Plan 221 §4** — `require_modules!("xfrm_user", "xfrm_state", "xfrm_policy")` → `require_module!("xfrm_user")`.
   Root cause: `xfrm_state.c` / `xfrm_policy.c` are not standalone
   loadable modules. `/sys/module/<name>` only has `xfrm_user`.
   Reference: existing `cycle_0_19_backfill.rs:461`.
2. **Plan 221 §4.1** — Drop the false claim that `xfrm_user` needs
   adding to the modprobe list. It's already at workflow YAML
   line 102.
3. **Plan 220 §3.4** — Closure list for Plan 232 said "B16-B20";
   correct closure is "B6/B9-B11/B13-B15/B17-B19" (B16 and B20
   are non-bugs per the per-cluster review). Plan 233 closes B7
   only (B16 IS the dump-vs-event policy distinction Plan 233
   is documenting; it doesn't need a fix, it needs the policy
   stated).
4. **Plan 226 §5.4 (new)** — DPLL workflow modprobe addition.
   `.github/workflows/integration-tests.yml` doesn't currently
   load `dpll`. Without that, every DPLL integration test
   skip-cleans because `/sys/module/dpll` doesn't exist.
5. **Plan 197 frontmatter + framing** — flipped from "0.19.0"
   target to "0.20.0 (discretionary)". The plan was written
   under the 0.19 "everything-in-0.19" directive that didn't
   end up holding. Also noted the upstream command-count is 8
   + 3 notifications, not 11.
6. **Plan 220 §6** — Migration guide outline now mentions
   `Error::Truncated` (Plan 224). Previously omitted from the
   list of migration-touching changes.

## 4. Systemic findings — implementer pick-up list

### 4.1 Audit-script self-tests (Plans 222, 223)

Both Plan 222 (`audit-uapi-constants.sh`) and Plan 223
(`audit-bytes-le.sh`) ship audit-by-grep CI scripts. Per the
user's "trust adversarial inputs over audit-by-grep" memory note,
each script needs a self-test that:

- Creates a deliberately-broken fixture (e.g. a temporary file
  with `from_le_bytes` in an unallowed location, or a
  deliberately-mismatched UAPI constant value).
- Runs the script against the fixture.
- Asserts the script exits non-zero with the expected message.

Without this, the scripts can silently break (e.g. a regex typo
that always passes) and the gate looks green while it isn't
catching anything. Reference: how
`scripts/audit-recv-loop-error-handling.sh` is tested — it
isn't, which is itself a small gap worth noting.

Land the self-tests as part of each plan's implementation PR.

### 4.2 Adversarial-input specification — cycle-wide rule

The user memory note `feedback_regression_test_first.md` says
*"trust adversarial inputs over audit-by-grep"*. The plan suite
specifies happy-path tests well but under-specifies adversarial
inputs:

| Plan | Happy-path covered? | Adversarial inputs specified? |
|---|---|---|
| 221 | ✅ 6 named integration tests | ⚠ no malformed-NLA frames pinned |
| 222 | ✅ constant-value compares | n/a (compile-time) |
| 223 | ✅ NLA-header round-trip | ⚠ no deliberately byte-swapped fixture |
| 224 | ✅ large-dump truncation | ✅ buffer-size boundary tests specified |
| 225 | ✅ overflow boundaries | ✅ i64::MIN, -1, i64::MAX explicitly named |
| 226 | ✅ 4-byte + 8-byte sint paths | ⚠ no malformed-sint-length frame |
| 227 | ✅ typed/raw round-trip | ⚠ no AddressFamily::from(0xFF) |
| 228 | ✅ Percent boundary check | ⚠ no NaN / inf / negative-zero |
| 229 | ✅ doc-test compile | ⚠ no "deliberately-stale example" fixture |
| 230 | ✅ ChainName validation | ⚠ no interior-NUL / non-UTF-8 / 256-byte name |
| 231 | ✅ accessor round-trip | ⚠ no `family = 0xFF` (unknown libc value) |
| 232 | ✅ per-finding fix | ⚠ B19's mock socket infrastructure not specified |
| 233 | ✅ stream error handling | ⚠ synthetic malformed-frame byte pattern not pinned |
| 234 | ✅ p99 latency target (loose) | ⚠ stress test parameters not concrete |
| 235 | ✅ per-family migration | ⚠ stale-frame injection fixture not specified |
| 197 | ✅ peer + key CRUD | ⚠ SCM_RIGHTS cmsg byte shape not pinned |

**Cycle-wide rule for implementers**: every test plan in the
suite needs at least one adversarial input named with a specific
value. The "happy path + boundary" coverage is necessary but not
sufficient. Plan 225's seven `parse_timespec` unit tests are the
model — seven tests, six of them adversarial (i64::MIN, -1, 0,
i64::MAX, nanos=-1, nanos=1_500_000_000).

### 4.3 Plan 234's ENOBUFS design is BETTER than neli's

Cross-checked Plan 234's NlRouter-style dispatcher against neli's
reference implementation. neli's router does NOT handle ENOBUFS
specially — when the kernel emits ENOBUFS into a subscriber's
queue, neli treats it the same as any other parse failure and
the subscriber may quietly drop frames. Plan 234 routes ENOBUFS
specifically to multicast subscribers as a `ResyncMarker`,
forcing them through the Plan 151 resync flow. This is a
deliberate improvement over neli and worth highlighting in the
plan's "Things we do better" section + in the eventual CHANGELOG.

Suggested addition to Plan 234 §2: a new sub-section "neli
comparison" calling out the ENOBUFS divergence + the
multicast-vs-request fan-out separation as deliberate
improvements.

### 4.4 Plan 234/235 dependency asymmetry

Plan 235 acknowledges Plan 234 supersedes its Phase 3 if 234
lands first. Plan 234 does not reciprocally acknowledge that 234
needs per-family integration tests covering every GENL family
the unified path will own. If 234 lands and 235 doesn't, the
dispatcher needs to be exercised against each family's command
shape (wireguard, devlink, ethtool, nl80211, macsec, mptcp,
dpll, net_shaper). Without 235's per-family migration, 234 needs
its own equivalent coverage.

Suggested addition to Plan 234 §6: a per-family test enumeration
matching Plan 235's table.

### 4.5 Plans 230, 231 deprecation cadence

User memory note: "deprecate in same release as typed replacement;
delete one release later." Plans 227, 228 honor this cleanly.
Plans 230 (ChainName) and 231 (RuleMessage accessors) ship hard
compile breaks without a transitional form.

The argument for hard breaks: both are typed payloads of enums
that the user has to match by variant anyway, so destructuring
breakage is the surface where the typed change becomes visible.
A transitional `Verdict::JumpStr(String)` would add API surface
for one release and remove it the next — net churn.

The argument for transitional forms: `Verdict::Jump(String)` →
`Verdict::Jump(ChainName)` makes downstream code that constructs
`Verdict::Jump("foo".to_string())` fail to compile. A
deprecated `Verdict::JumpStr(String)` shim would soften the
landing.

**Recommendation**: accept the hard break, document the
mechanical migration in the 0.19→0.20 guide. Plan 230 §4 already
specifies the migration pattern; Plan 231 §5 has the same. No
edits required; this is a reviewer call to surface for the
maintainer's decision.

### 4.6 Plan 232 LOW-finding sub-judgments

Plan 232 batches 10 LOW findings into one PR. Per-cluster review
flagged that:
- B6 ("redundant but not wrong") is a wontfix candidate. Plan
  232 already flags this; the maintainer's call.
- B19's mock-socket infrastructure (for the EWOULDBLOCK retry
  test) is undefined in the plan. The implementer needs to
  specify either a `tokio_test::io::Builder` mock or a real
  blocking-socket test in a netns. Recommend the latter.
- B14's `.unwrap()` audit (after length guards): each candidate
  needs case-by-case judgment — some `.unwrap()`s after length
  guards are correct (the guard makes them total). Plan should
  list each one explicitly, not just "audit and fix".

These are implementation-time judgments; the plan body is
adequate as a scope statement.

## 5. Test matrix — full coverage view

Each plan × test type. ✅ = specified; ⚠ = under-specified; ❌ =
missing. The cycle exits when every cell is ✅ in the implementer's
shipped code.

| Plan | Unit tests | Doc tests | Integration (mock) | Integration (root-gated) | CI gate / script | Adversarial inputs |
|---|---|---|---|---|---|---|
| 221 | ✅ const + dispatch | n/a | n/a | ✅ 6 named | ✅ existing CI gates apply | ⚠ |
| 222 | ✅ const compares | n/a | n/a | n/a | ✅ + ❌ self-test | n/a |
| 223 | ✅ NLA round-trip | n/a | n/a | ❌ (s390x compile-only) | ✅ + ❌ self-test | ⚠ |
| 224 | ✅ size math | n/a | ✅ mock truncate | ✅ large conntrack dump | ✅ existing | ✅ |
| 225 | ✅ 7 boundary | n/a | ✅ malformed frame | ❌ (n/a, mock covers) | ✅ existing | ✅ |
| 226 | ✅ 4/8-byte sint | n/a | ✅ synthetic frames | ✅ DPLL kernel emit | ✅ + DPLL modprobe ⚠ | ⚠ |
| 227 | ⚠ split test | n/a | n/a | ⚠ flush_rules typed | ✅ existing | ⚠ |
| 228 | ✅ Percent boundary | n/a | n/a | n/a | ✅ existing | ⚠ NaN/inf |
| 229 | n/a (it IS the test) | ✅ recipe compile | n/a | n/a | ✅ + ⚠ false-positive policy | ⚠ stale fixture |
| 230 | ✅ ChainName validate | n/a | ⚠ trybuild fixture | ⚠ kernel acceptance | ✅ via Plan 222 gate | ⚠ NUL/UTF-8 |
| 231 | ✅ accessor coverage | n/a | n/a | ⚠ RTM_NEWRULE round-trip | ✅ + ⚠ regex spec | ⚠ family=0xFF |
| 232 | ⚠ per-finding names | n/a | n/a | n/a | ✅ existing | ⚠ B19 mock |
| 233 | ✅ stream behavior | n/a | ✅ malformed frame | ❌ (n/a) | ✅ updated allow-list | ⚠ byte pattern |
| 234 | ⚠ dispatcher unit | n/a | ⚠ multi-task mock | ⚠ stress + latency | ✅ existing | ⚠ params |
| 235 | ⚠ per-family | n/a | ⚠ stale-frame inject | ⚠ per-family round-trip | ✅ existing | ⚠ |
| 197 | ✅ peer + key CRUD | n/a | ✅ wire-shape | ✅ peer round-trip | ⚠ ovpn modprobe | ⚠ SCM_RIGHTS |

**Cycle exit checklist** (in addition to Plan 220 §5):

- Every cell in the matrix is ✅ in the implementer's shipped code.
- The privileged-CI workflow includes all the modprobed kernel
  modules that the new integration tests reference. Verified
  list: `xfrm_user` ✅ already there; `nf_conntrack` ✅ already
  there; `dpll` ⚠ needs adding (Plan 226); `ovpn` ⚠ would need
  adding (Plan 197).
- Every audit-by-grep CI gate (Plan 222's, Plan 223's) has a
  self-test fixture proving the script's failure path works.

## 6. Cross-plan items the implementer should remember

These don't belong in any single plan but apply to the cycle:

1. **CHANGELOG `[Unreleased]` discipline**: at 0.20 cycle open
   the `[Unreleased]` already contains the PR #9 + PR #10
   entries. Each subsequent plan adds an entry. The 0.19.1
   hotfix entry slots between `[Unreleased]` and `[0.19.0]`
   per Plan 221 §7.
2. **Migration guide `0.19.0-to-0.20.0.md`**: write
   incrementally as plans land. Each plan §6/§7 (migration)
   section is a draft of what goes in.
3. **`scripts/cut-release.sh` adjustment**: §7 of Plan 221
   flags that the cut script's CHANGELOG promotion may need a
   small adjustment to handle the interleaved hotfix-entry
   ordering. Verify before the 0.19.1 cut.
4. **Plan 222 phase 222.1 lands with the 0.19.1 hotfix**: this
   is documented in Plan 222 §2.5 but Plan 221's cut sequence
   (§7) doesn't mention the gate modules. The implementer
   should land both in the same PR.
5. **`integration-tests.yml` modprobe additions** consolidated:
   - Plan 226: add `dpll`
   - Plan 197 (if shipped): add `ovpn` (kernel 6.16+, may also
     need a kernel-version gate)
   Bundle these into a single PR if practical.

## 7. Recommended sequence

1. **NOW**: ship the must-fix edits in §3 (this commit).
2. **NEXT**: implement Plan 221 + Plan 222.1 in a single PR on
   `0.19.1-hotfix` branch. Land before any other 0.20 work.
3. **THEN**: cut `v0.19.1` per Plan 221 §7.
4. **THEN**: merge master → 0.20, kick off the broader cycle.
5. **PARALLEL on 0.20**: implementers pick plans from §5 matrix,
   filling in the ⚠ cells. Plan 222 phases 2/3/4 + Plans
   223-228 + 230 + 231 land independently. Plan 229 lands
   after Plan 228 (the one ordering constraint).
6. **AS-NEEDED**: Plan 232 (LOW batch) lands when an
   implementer has a spare slot. Plan 233 lands with Plan 232 or
   independently.
7. **DISCRETIONARY**: 197, 234, 235 — ship only if cycle budget
   remains. Recommended order if budget tight: 234 (highest
   user-visible impact) > 235 Phase 4 > 235 Phase 3 > 197.

## 8. Closing

The plan suite is implementation-ready after the §3 edits land.
The §4 systemic improvements are quality work the implementer
applies as each plan ships, with §5's test matrix as the
checklist. No plan needs structural rework; the cycle can
execute against the documented scope.

Per the user's memory note about "regression test first" — the
single highest-leverage thing the implementer can do is **write
the adversarial-input tests before the implementation** for
plans 225, 230, 231. Those tests would have caught a future
recurrence of the audited bug class. The other plans benefit
similarly but less load-bearingly.
