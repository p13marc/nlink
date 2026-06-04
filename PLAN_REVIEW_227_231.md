# Plan review — 227-231 typed-API tightening cluster (0.20)

Reviewer pass over the 5 plans in `/var/home/mpardo/git/rip/plans/`
for the 0.20 cycle's typed-API tightening cluster (Plan 220 §3.3 +
§3.4). Reviewed alongside the master plan (220), the XFRM hotfix
(221), `AUDIT_API.md`, and `CLAUDE.md`. External verification
against kernel UAPI v6.13 for the wire-format / constant claims.

---

## Section 1 — Inter-plan consistency

### Naming + module-placement conflicts (227 vs 230)

No direct conflict. 227 places `AddressFamily` at the crate root
(`nlink::AddressFamily`) under a new file `util/address_family.rs`;
230 places `ChainName` under `nftables::types` (or a sibling file).
The names do **not** collide. 227 §1 explicitly calls out the
risk of confusion with the existing `nftables::types::Family`
(NFPROTO_*) and resolves it by giving the new type a different
name (`AddressFamily` vs `Family`). The risk note in 227 §7 already
documents the cost of the naming asymmetry; that documentation
discipline should carry through to 230, where `ChainName` and the
deferred `TableName` (flagged for 0.21) share the same nftables
namespace.

**One latent concern**: 227 §4's audit table lists nftables
`protocol` accessors as deferred for an `IpProto` newtype in 0.21.
That deferral is consistent with 230's §3.1 deferral of `TableName`
and `SetName`. The two plans land complementary typed-name surfaces
without overlap.

### Timing — 228 → 229 ordering

The master plan §4 specifies `228 → 229`. Verified:

- 228 §4 says "Plan 229 owns the doc-sweep CI gate" and §7 risks
  notes "Coordinate ordering — 228 lands before 229 because 229's
  doc-test CI gate goes red until 228's API flip is in."
- 229 §5 confirms: "Plan 228 fixes its own doctests in the same
  commit. Plan 229's sweep then needs to confirm Plan 228 caught
  them all." And: "Ordering: 228 lands before 229's gate goes
  blocking."

The honoring is explicit and bilateral. Both plans land doctests in
228's PR; 229's *gate* lands after with a one-week non-blocking
bake. Good.

### Duplicate work / scope creep

- **231 vs 227**: 231 §4.1 specifies `RuleMessage::family()`
  returns `AddressFamily` per 227. This is a coordinated handoff,
  not a duplication — 227 defines the type; 231 consumes it. The
  cross-reference is bidirectional (227 §9 mentions 231; 231 §4.1
  and §9 mention 227).
- **231 §4.2** flags `BridgeVlanMessage`, `FdbMessage`,
  `MplsRouteMessage`, `NexthopMessage` as audit-time grep targets.
  This is correct scoping — 231 explicitly admits the audit
  hasn't been run yet, which is consistent with CLAUDE.md
  "Investigate before destroying."
- **230 vs 0.19 Plan 211 (Hook split)**: no overlap. Plan 211
  fixed wire-format encoding of `Hook::Ingress`; Plan 230 fixes
  the input-side hazard of `Verdict::Jump(String)`. Different
  surfaces, different bugs. 230's intro correctly distinguishes
  itself as "input-side mismatches" vs 211's "wire-format
  mismatches."
- **228 vs 0.13/0.14 Percent rollout**: 228 §1 explicitly frames
  itself as the declarative-builder extension of the 0.14 unit
  rollout, not a duplication. Good framing.

### Migration guide coherence

Each plan ships a §-titled markdown block destined for
`docs/migration_guide/0.19.0-to-0.20.0.md`. Cross-checking:

- 227 §6 "AddressFamily typed newtype"
- 228 §6 "Declarative builders take typed Percent"
- 230 §4 "Verdict::Jump / Verdict::Goto take typed ChainName"
- 231 §5 "RuleMessage accessor discipline"
- 229 emits CHANGELOG entries (§6) rather than migration-guide
  entries — appropriate since it's doc-only

Combined, these entries make a coherent "typed-API tightening"
section in the migration guide. No conflicts; the only suggestion
is to add a one-paragraph preamble that tells migrators they're
likely to see 3-4 of these at once (sharing the `try_into()?`
fallible-conversion idiom from 230 § with the `Percent::new(x)`
infallible idiom from 228).

### Deprecation cadence consistency

User memory: "deprecate in same release as typed replacement;
delete one release later."

- **227**: deprecate u8 in 0.20 (`*_raw` shims), delete in 0.21.
  Honored.
- **228**: deprecate `*_pct(f64)` shims in 0.20, delete in 0.21.
  Honored.
- **229**: no deprecations — doc-only plan. N/A.
- **230**: This plan does **NOT** ship a deprecation shim — it
  flips `Verdict::Jump(String)` to `Verdict::Jump(ChainName)`
  directly as a "hard compile break." This is **inconsistent**
  with the stated cadence. Per the memory note, the cadence
  applies "when there's a typed replacement"; 230's break is
  enum-variant payload change, not a method signature change, so
  a deprecation shim would require a parallel
  `Verdict::JumpString(String)` variant. The plan should either
  (a) ship a transitional `Verdict::JumpRaw(String)` deprecated
  variant or (b) explicitly justify the no-shim policy. As
  written, 230 §3 just says "hard compile break" without
  acknowledging the cadence mismatch.
- **231**: deprecation is implicit — the field-`pub` → accessor
  flip is a hard compile break for downstream destructuring. No
  shim provided. This is **also inconsistent** with the stated
  cadence. The plan's §7 risks mention "Hard compile break for
  downstream destructuring" but does not propose a transitional
  approach. Options: (a) keep `pub` fields with `#[deprecated]`
  attribute (Rust accepts this on struct fields since 1.55) for
  0.20, demote to `pub(crate)` in 0.21; (b) explicitly justify
  the no-shim policy.

Recommend Section 5 edits to 230 and 231 to either ship a
transitional form or document why the cadence is being skipped
for these two.

---

## Section 2 — Test-spec completeness

### Plan 227 (AddressFamily)

- **Unit tests**: not explicitly listed. The plan should pin
  `assert_eq!(AddressFamily::V4.as_u8(), 2)`, the round-trip
  through `try_from_raw`, and the `From<AddressFamily> for u8`
  conversion. Currently §5 lists three test classes but skips
  the constructor-contract tests entirely.
- **Compile-fail tests**: §5.1 names trybuild for `flush_rules(4)`
  no-longer-compiles. Specifies "document the warning text it
  produces in 0.20" — note that 0.20 has the deprecation, so the
  type itself still compiles via `*_raw`; the compile-fail comes
  in 0.21. This conflates two phases. Recommend pinning the
  trybuild fixture for 0.20 (asserts the `#[deprecated]` warning)
  separately from 0.21 (asserts the deletion).
- **Integration tests**: §5.3 specifies one root-gated test
  exercising v4/v6/unspec dispatch. Good shape but lacks the
  `require_modules!()` call. Routing-policy DB rules are part of
  `ip_tables`'s policy routing — actually the policy routing
  doesn't need a module (it's built into IPv4/IPv6 stack), so
  `require_modules!()` may be skippable. The plan should
  explicitly state "no module gate needed; policy routing is
  built into the IPv4/IPv6 stack." Otherwise reviewers will ask.
- **Adversarial inputs**: not specified. Per the user feedback
  note about "trust adversarial inputs over audit-by-grep," 227
  should add: `try_from_raw(255)` returns `None`,
  `try_from_raw(0)` returns `Unspec` (which is the only "valid"
  zero-value), `as_u8()` is total and never panics. Currently
  none of these are explicit.

### Plan 228 (Percent)

- **Unit tests**: §5.1 specifies three saturation cases
  (`150.0 → 100.0`, `-1.0 → 0.0`, `from_fraction(0.015) → 1.5`).
  Good.
- **Wire-shape parity test**: §5.2 specifies declarative vs
  imperative wire bytes must match. **Excellent** — this is
  exactly the test the 0.14 unit-confusion lesson would suggest.
- **Compile-fail test**: §5.4 specifies trybuild that
  `.loss(1.5)` (bare f64) is a type error. Notes the
  message-fragment-match form. Good.
- **`#[deprecated]` sweep**: §5.3 specifies clippy
  `--deny warnings` catches internal callsites. Good.
- **Adversarial inputs**: missing. Should pin
  `Percent::new(f64::NAN)`, `Percent::new(f64::INFINITY)`,
  `Percent::new(f64::NEG_INFINITY)`. These are the canonical f64
  edge cases that a typed wrapper should explicitly handle. The
  audit's Finding A7 (deferred to Plan 232) is about
  silent-vs-error clamping; 228 should at least pin the NaN
  behaviour at the unit-test level.
- **No root-gated integration test**: 228 is a builder-level
  change, no wire-format change beyond the parity test. Skipping
  the root-gated test is defensible — but the plan should say so
  explicitly. As written, §5 just lists 4 test classes and stops.

### Plan 229 (doc-drift sweep)

- **Doc-test gate exit criteria**: §3 specifies the gate is
  non-blocking for one week, then promoted. Does not specify
  what "false positives" the gate might fire on. A doctest
  failing because rustfmt formatted something unexpectedly is
  not the same as a doctest failing because the API moved. The
  plan should add a §6 entry on "expected failure modes":
  - rustfmt drift (re-run `cargo fmt` and the fence reformats)
  - kernel-side feature drift (a doctest assuming a kernel
    feature that the CI runner doesn't have)
  - flake from cold incremental cache
- **Recipe-test harness**: §4 sketches the synthesised
  `tests/recipes/main.rs`. The harness pattern is correct (see
  external verification §4 below — tokio uses the same
  `extract-from-fence-and-compile` model). But:
  - The plan does not pin **what compiles** vs **what runs**.
    Compile-only is fine for the recipe harness; the plan
    should explicitly say "we never call the `_example`
    functions; they exist to type-check."
  - The plan does not specify what happens when a recipe's
    code fence is marked `~~~rust,no_run` vs `~~~rust,ignore`.
    These should map to different harness behaviours; specify.
- **Adversarial inputs**: 229's only adversarial input class is
  "future kernel breaks the example." The plan should explicitly
  call out that the doctest gate is `_p nlink`-scoped (not
  workspace) to avoid root-gated examples failing in CI without
  CAP_NET_ADMIN. §3 mentions this but the discussion is in the
  middle of a paragraph; should be its own bullet under
  "expected non-failures."

### Plan 230 (ChainName)

- **Unit tests**: §5.1 specifies four cases (empty, NUL,
  overlong, max-len OK). Good. Missing: `ChainName::new("a")`
  (1-byte minimum positive case), Display + AsRef round-trip
  test, TryFrom test exercising both `&str` and `String` paths.
- **Round-trip identity tests**: §5.2 references the Plan 157b
  chain-identity scenarios. Good.
- **Integration test**: §5.3 specifies a root-gated test with
  `require_modules!("nf_tables")`. Module name is correct (the
  kernel module is `nf_tables`, not `nftables`). Specifies
  Verdict::Jump path. Good.
- **Compile-fail test**: NOT specified. The plan should add a
  trybuild fixture showing `Verdict::Jump("foo".to_string())`
  no longer compiles, with the expected error message fragment.
- **Adversarial inputs**: partially covered (empty, NUL,
  overlong). Missing: UTF-8 cases — does `ChainName::new("café")`
  succeed? The kernel treats names as opaque bytes (it does not
  validate UTF-8), so the answer is yes — but the plan doesn't
  pin this. Also missing: leading/trailing whitespace (kernel
  accepts these but downstream users may not expect it).

### Plan 231 (RuleMessage accessor discipline)

- **Unit tests**: §6.1 specifies an accessor return-shape test.
  Good but mechanical; the test as specified will pass even if
  the bodies are wrong (it only type-checks).
- **Trybuild compile-fail**: §6.2 specifies the destructure
  rejection test. Good.
- **Integration round-trip**: §6.3 specifies a `RuleBuilder`
  apply → dump → parse cycle, asserting accessor values match.
  Good but lacks `require_modules!()`. Like 227, may be no-op
  (built into kernel stack) — should explicitly say so.
- **Audit script**: §6.4 specifies a new
  `scripts/audit-message-accessor-convention.sh`. This is the
  durable-prevention piece. The script's pattern is left vague
  ("grep for `pub field:`"); should specify the exact regex it
  uses and what file patterns it walks. Recommend using
  ripgrep with `--type rust` on
  `crates/nlink/src/netlink/messages/` and matching
  `^\s*pub [a-z_]+:\s` excluding `pub(`.
- **Adversarial inputs**: missing. Should pin: parser handed a
  rule with an unknown family byte exposes
  `header.family != known` and `family() -> AddressFamily::Unspec`
  (per §4.1's fallback). This is the "kernel grows a new family"
  forward-compat case.

---

## Section 3 — Root-gated test specification quality

Survey of root-gated test specifications against the existing
patterns in `crates/nlink/tests/integration/`:

### Plan 227

One root-gated test (`rule_family_typed.rs`) is specified for the
v4/v6/unspec dispatch. The plan should expand to **three** tests
covering each method:

- `flush_rules_typed_v4` — seed rules in both v4 and v6, flush
  v4, assert v6 unchanged.
- `del_rule_by_priority_typed` — exercise the typed signature.
- `get_rules_for_family_unspec_returns_all` — the Unspec arm.

The existing test pattern (`require_root!()` early-return) is
honored. No `require_modules!()` needed — policy routing is
built into the IPv4/IPv6 stack — but the plan should say so
explicitly so reviewers don't ask. **Compare against
`crates/nlink/tests/integration/route.rs`** for the canonical
shape.

### Plan 230

`crates/nlink/tests/integration/nftables_reconcile.rs` already
uses `require_modules!("nf_tables")` extensively (verified — 18
sites). 230 §5.3's `require_modules!("nf_tables")` matches the
existing convention. The plan **does** specify a root-gated test
verifying kernel accepts a `Verdict::Jump(ChainName::new("foo"))`
rule. Good shape but specification is one-paragraph hand-wave;
should be expanded to an explicit table:

| Test | What it asserts |
|---|---|
| `verdict_jump_kernel_accepts_typed_chain` | apply + dump round-trip |
| `verdict_jump_invalid_target_chain_eexist` | jump to non-existent chain → expected kernel error |
| `verdict_goto_kernel_accepts_typed_chain` | same as Jump but Goto |
| `verdict_chain_byte_for_byte_roundtrip` | confirms the kernel returns the same chain name we wrote |

The last is the adversarial test that pins the wire-format
contract (i.e., catches a "kernel canonicalizes case" surprise if
it ever happened).

### Plan 231

The integration round-trip test (§6.3) is the right concept but
under-specified. The existing pattern in `route.rs` should be
followed — build a rule via `RuleBuilder`, apply, dump, and
verify each accessor matches the input. Need to enumerate **which
accessors** are exercised — `family()`, `priority()`, `source()`,
`table()` minimum; ideally all 17 accessors per a
data-driven test loop.

Like 227, no `require_modules!()` needed. The plan should clarify
this and reference the existing `route.rs` pattern.

### Plan 229

229 is doc-only; no root-gated tests. The plan's CI gate
(`cargo test --doc -p nlink`) runs without root. Correct.

### Plan 228

228 has the wire-shape parity test (§5.2) but no root-gated
integration test. Defensible — the declarative-vs-imperative
parity covers the wire-format guarantee. But the plan should
add at least one root-gated test confirming the **kernel
accepts** the netem qopt bytes the typed Percent path produces.
Without it, "they encode the same bytes" doesn't guarantee
"both work" — the existing `tc.rs` integration test should
already cover this if it does (verify).

### Module-gating audit

Reference `crates/nlink/tests/integration/` confirms the
`require_modules!()` convention is honored across existing
tests. The five plans collectively need:

- 227: no module gate (policy routing built-in)
- 228: no module gate (netem is built-in to most kernels;
  consider `require_modules!("sch_netem")` to be safe — the
  module name confirmed at
  `https://git.kernel.org/.../net/sched/sch_netem.c`)
- 229: N/A
- 230: `require_modules!("nf_tables")` — verified consistent
- 231: no module gate (policy routing built-in)

228's plan should explicitly state the sch_netem module
expectation if it ships a root-gated test.

---

## Section 4 — Verification by external research

### 227 — AddressFamily design

**Verified**: `fib_rule_hdr.family` is `__u8`
(`include/uapi/linux/fib_rules.h`, verified via
raw.githubusercontent.com fetch of v6.13 tag). The 227 plan's
list of AF_* values is correct:

- AF_UNSPEC=0, AF_INET=2, AF_BRIDGE=7, AF_INET6=10,
  AF_PACKET=17, AF_MPLS=28 — confirmed via standard libc/headers.

**Verified**: `nftables::types::Family` exists at
`crates/nlink/src/netlink/nftables/types.rs:13` (read directly).
The existing Family is `repr(u8)` with NFPROTO_* values
(Ip=2, Ip6=10, Inet=1, Arp=3, Bridge=7, Netdev=5). It is **the
NFPROTO_* enum**, not AF_*. The overlap is partial:

| Symbol | NFPROTO | AF |
|---|---|---|
| Inet | 1 | (no equivalent — AF_UNIX=1 in libc!) |
| Ip / V4 | 2 | 2 |
| Bridge | 7 | 7 |
| Ip6 / V6 | 10 | 10 |

The NFPROTO_INET=1 vs AF_UNIX=1 collision is the load-bearing
reason 227's "do not reuse Family" decision is correct.

**Plan 227's documented rationale (§1) is accurate.**

### 228 — Percent kernel range

**Verified**: `tc_netem_qopt.loss` is `__u32` with range "0=none
~0=100%" (linear interpolation between 0 and `u32::MAX`). Not a
percent value; not clamped to 0..=100. The kernel uses the full
u32 range as a probability.

Plan 228's claim — "the kernel saturates downstream (the netem
qopt encodes 32-bit u32 probability), so the user sees full
packet drop with no error" — is accurate. The math is
`(percent / 100.0) * u32::MAX as f64 as u32`. A `f64` of `1.5`
becomes ~64.4M (1.5% of u32::MAX); a `f64` of `150.0` saturates
when the multiplication exceeds u32::MAX.

**Plan 228's `Percent::new(150.0)` clamps to 100.0** (per the
audit's Finding A7) — which then encodes as u32::MAX. The
**fallible `try_new`** is in Plan 232 (deferred per 228 §3).
The plan correctly chooses Percent::new (saturating) over
try_new (fallible) for consistency with the imperative sibling.

### 229 — Doc-test gate approach

**Web search confirmed** the pattern is widely used: tokio,
axum, hyper all run `cargo test --doc` in CI. mdbook's "test"
command does exactly what 229 §4 sketches — extract `~~~rust`
fences, compile (and optionally run) each. The 229 plan's
proposed `tests/recipes/` harness is reasonable and matches the
state of the art. Recommended addition (per §5 below): cite
mdbook as the inspiration; the plan currently says "same approach
mdbook test uses" but doesn't tie the harness to its semantics
(`~~~rust,no_run` etc.).

### 230 — NFT_NAME_MAXLEN

**Verified** via raw.githubusercontent.com fetch of v6.13:

```c
#define NFT_NAME_MAXLEN     256
#define NFT_TABLE_MAXNAMELEN    NFT_NAME_MAXLEN
#define NFT_CHAIN_MAXNAMELEN    NFT_NAME_MAXLEN
```

Plan 230's `MAX_LEN = 255` (one byte reserved for NUL
terminator) is **correct**. The constant is exactly
`NFT_NAME_MAXLEN - 1`. Plan 222's UAPI-constant gate
should ingest `NFT_NAME_MAXLEN` to enforce this.

Plan 230 §6 risk note "MAX_LEN is a wire-format constant" is
correct framing per the 0.20 cycle theme.

---

## Section 5 — Recommended edits

### Plan 227 (AddressFamily)

- **§5 — Test plan**: Add unit-test list pinning
  `AddressFamily::V4.as_u8() == 2`, all six variants'
  numeric values, round-trip via `try_from_raw`, and
  `try_from_raw(255) == None`.
- **§5 — Adversarial unit tests**: Pin
  `try_from_raw(0) == Some(Unspec)` to confirm the
  zero-byte case is treated as Unspec (the AF_UNSPEC
  semantics) and not as an error.
- **§5.3 — Integration**: Split into three named tests
  (`flush_rules_typed_v4`, `del_rule_by_priority_typed`,
  `get_rules_for_family_unspec_returns_all`); add explicit
  "no `require_modules!()` needed; policy routing is built-in
  to the IPv4/IPv6 stack" with a citation to the existing
  `route.rs` test for the canonical shape.
- **§5 — Trybuild lifecycle**: Separate the 0.20-cycle
  trybuild (asserts deprecation warning emits) from the
  0.21-cycle trybuild (asserts deletion). Today's text
  conflates them.

### Plan 228 (Percent)

- **§5.1 — Adversarial inputs**: Add NaN / +inf / -inf
  cases pinning the saturating behaviour. These are the
  canonical f64-edge unit-test inputs.
- **§5.5 — Root-gated test**: Add a one-paragraph
  justification for skipping a root-gated integration
  test, citing the wire-shape parity as the load-bearing
  guarantee. If the netem-via-builder integration coverage
  already exists in `tc.rs`, cite it.
- **§5.4 — Trybuild error message**: Pin the
  expected-message fragment ("expected `Percent`, found
  `{integer}`") so future rustc-diagnostic-wording changes
  don't fire false-positives.

### Plan 229 (doc-drift sweep)

- **§3 — Expected failure modes**: Add a bullet listing
  what counts as a legitimate doctest failure vs an
  "expected non-failure" (rustfmt drift, root-required
  examples). Use the bake week to characterize the noise.
- **§4 — Recipe harness semantics**: Specify what
  `~~~rust`, `~~~rust,no_run`, `~~~rust,ignore` each
  map to in the harness. Cite mdbook's behaviour as the
  reference.
- **§3 — Harness output sample**: Include a sketch of
  what a failed-doctest CI message looks like (or
  reference the cargo upstream doc-test message format).
- **§6 — Test plan**: Add an "expected non-failure"
  test (e.g., a doctest that intentionally uses a
  root-gated path; the gate should skip / pass, not fail).

### Plan 230 (ChainName)

- **§3 — Deprecation cadence justification**: Add a
  paragraph explaining why no transitional
  `Verdict::JumpString(String)` deprecated variant is
  shipped. The current text says "hard compile break"
  without addressing the user's stated cadence
  preference. Options to consider:
  (a) ship `Verdict::JumpString(String)` for 0.20 with
  `#[deprecated]`, delete in 0.21;
  (b) document that enum-payload changes are exempt
  from the cadence and explain why.
- **§5.1 — Unit tests**: Add `ChainName::new("a")`
  positive case, Display + AsRef round-trip, UTF-8
  multi-byte test (`"café"` works), leading/trailing
  whitespace policy test.
- **§5.3 — Integration test expansion**: Specify the
  4-test table from this review's §3:
  `verdict_jump_kernel_accepts_typed_chain`,
  `verdict_jump_invalid_target_chain_eexist`,
  `verdict_goto_kernel_accepts_typed_chain`,
  `verdict_chain_byte_for_byte_roundtrip`.
- **§5 — Trybuild fixture**: Add a compile-fail test
  for `Verdict::Jump("foo".to_string())` no longer
  compiling.

### Plan 231 (RuleMessage)

- **§7 — Deprecation cadence justification**: Same
  issue as 230. Demoting fields from `pub` to
  `pub(crate)` is a hard break. Options:
  (a) ship `#[deprecated]` field attributes for one
  cycle (Rust 1.55+ supports this on struct fields),
  demote in 0.21;
  (b) document the exemption.
- **§4.2 — Adjacent-message audit**: Promote the
  pre-work audit into an explicit checklist with
  expected outcome ("if any of {BridgeVlanMessage,
  FdbMessage, MplsRouteMessage, NexthopMessage} has
  `pub` fields, include in this plan's scope").
- **§6.4 — Audit script regex**: Specify the exact
  ripgrep pattern:
  `rg --type rust '^\s*pub [a-z_][a-zA-Z0-9_]*:\s' crates/nlink/src/netlink/messages/ | grep -v 'pub('`.
  Otherwise the script's behaviour is under-specified.
- **§6.3 — Integration test**: Add explicit accessor
  enumeration. Reference `route.rs` integration test
  pattern.
- **§6 — Adversarial inputs**: Pin parser-handed
  unknown-family-byte case (`family() -> Unspec`
  fallback per §4.1).

### Master coordination edit

The 5 plans share two latent concerns the master plan (220)
doesn't currently mention:

1. **Deprecation cadence exemption**: 230 and 231 both
   skip the standard cadence. Either the master plan should
   document a cadence-exemption policy ("enum-variant
   payload changes and struct-field-visibility changes are
   exempt because they have no shim form") or the master
   should add a row to its §3.3 table reflecting that 230
   and 231 are "hard break, no shim." Currently the cadence
   inconsistency is silent across the suite.
2. **Migration-guide preamble**: §6 of 220 lists all five
   plans' migration-guide entries individually. Add a
   one-paragraph framing that tells downstreams "expect 3-5
   typed-API tightenings in this cycle; the patterns are
   `Percent::new(x)` for infallible conversions,
   `try_into()?` for fallible conversions, and accessor
   replacement for field access."

---

## Summary

The five plans are tightly coordinated and the cross-references
are consistent. 227 ↔ 231 hand off the typed-family return
cleanly; 228 ↔ 229 honor the master-plan ordering; 230 and 231
are scoped correctly without creep. Verifications against kernel
UAPI v6.13 confirm the wire-format / constant claims in 228 and
230. The doc-test gate approach in 229 is consistent with the
state of the art (tokio/axum/hyper).

**Two systematic gaps**:

1. **Deprecation cadence inconsistency** in 230 and 231 (both
   skip the user's stated "deprecate then delete" cadence without
   justification). Either ship transitional forms or document the
   exemption policy at the master-plan level.
2. **Adversarial-input under-specification** across all five
   plans. The user's memory note "trust adversarial inputs over
   audit-by-grep" is not visibly honored — each plan should
   enumerate the boundary cases (NaN, empty, max-length, unknown
   bytes) it explicitly pins.

The Section 5 edits are concrete and small; applying them tightens
each plan to "ready to land" status. None of the plans need
structural rework.

---

## File paths referenced

- `/var/home/mpardo/git/rip/plans/220-0.20-master-plan.md`
- `/var/home/mpardo/git/rip/plans/221-xfrm-constants-hotfix-plan.md`
- `/var/home/mpardo/git/rip/plans/227-family-newtype-plan.md`
- `/var/home/mpardo/git/rip/plans/228-typed-percent-builders-plan.md`
- `/var/home/mpardo/git/rip/plans/229-doc-drift-sweep-plan.md`
- `/var/home/mpardo/git/rip/plans/230-verdict-chainname-plan.md`
- `/var/home/mpardo/git/rip/plans/231-message-accessor-discipline-plan.md`
- `/var/home/mpardo/git/rip/AUDIT_API.md`
- `/var/home/mpardo/git/rip/CLAUDE.md`
- `/var/home/mpardo/git/rip/crates/nlink/src/netlink/nftables/types.rs` (verified existing `Family` at :13)
- `/var/home/mpardo/git/rip/crates/nlink/tests/integration/nftables_reconcile.rs` (verified `require_modules!("nf_tables")` pattern)
- `/var/home/mpardo/git/rip/crates/nlink/tests/integration/route.rs` (canonical pattern for non-module-gated integration tests)
- Kernel UAPI v6.13: `include/uapi/linux/fib_rules.h` (fib_rule_hdr.family is `__u8`), `include/uapi/linux/netfilter/nf_tables.h` (NFT_NAME_MAXLEN=256), `include/uapi/linux/pkt_sched.h` (tc_netem_qopt.loss is `__u32` saturating probability)

Sources:
- [Linux kernel v6.13 fib_rules.h](https://raw.githubusercontent.com/torvalds/linux/v6.13/include/uapi/linux/fib_rules.h)
- [Linux kernel v6.13 nf_tables.h](https://raw.githubusercontent.com/torvalds/linux/v6.13/include/uapi/linux/netfilter/nf_tables.h)
- [Linux kernel v6.13 pkt_sched.h](https://raw.githubusercontent.com/torvalds/linux/v6.13/include/uapi/linux/pkt_sched.h)
- [axum GitHub](https://github.com/tokio-rs/axum)
- [Rust Async in Production: Tokio, Axum, and Building High-Performance APIs in 2026](https://devstarsj.github.io/2026/03/01/rust-async-tokio-axum-production-2026/)
