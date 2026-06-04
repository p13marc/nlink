# 0.21 — Batch X handoff

Working batch for the 0.21 cycle's "remove the 5 deprecated APIs +
close audit-derived plans" sweep. Sibling batches:

- Batch Y — Plan 197 (declarative ovpn)
- Batch Z — Plan 234 (NlRouter dispatcher)
- Batch ? — Plan 235 (GENL command unification)

This batch's CHANGELOG entries to fold into `[Unreleased]` /
`[0.21.0]` at cut time. Use "### Breaking changes / Removed"
for the deprecation removals.

---

### Breaking changes / Removed

- **`DpllPin::fractional_frequency_offset_ppt` widened from
  `Option<i32>` to `Option<i64>`.** Closes the 0.20.1 deferral
  (CHANGELOG Plan 226). Pre-0.21 the field silently failed the
  whole `DpllPinReply::from_bytes` parse when the kernel emitted
  an 8-byte sint that overflowed `i32` (typical at SyncE
  bring-up); 0.21 widens the field so the full-width value
  parses cleanly. Callers using `as i32` casts or `i32`
  arithmetic on the field must widen to `i64`. The 0.20.1
  escape-hatch helper `ffo_ppt_i64_from_payload(&[u8])` stays
  for callers that hold the raw attribute bytes but not a
  parsed struct.
- **Route-rule API: `Connection::<Route>::flush_rules`,
  `get_rules_for_family`, `del_rule_by_priority` collapsed to a
  single typed form.** The raw-`u8` family signature deprecated
  in 0.20.1 is gone. The typed siblings (`*_typed`, taking
  `AddressFamily`) are renamed back to the original names —
  there's only one form now, and it's the safe one. Migration:
  `flush_rules(libc::AF_INET as u8)` → `flush_rules(AddressFamily::v4())`.
- **`QdiscBuilder::loss(f64)` removed.** Use `loss_pct(Percent)`
  with `Percent::new(1.5)` (percent value) or
  `Percent::from_fraction(0.015)` (fraction). The raw-`f64` form
  silently accepted out-of-range and NaN values; the typed form
  clamps to `[0, 100]` and surfaces the units-confusion footgun
  at the construction boundary. Plan 228 closeout.
- **`Verdict::Jump(String)` and `Verdict::Goto(String)` removed.**
  Use `Verdict::JumpTo(ChainName::new(...)?)` and
  `Verdict::GotoTo(ChainName::new(...)?)`. The `String` variants
  let interior NULs and overlong names through to a kernel
  rejection at apply time; the typed `ChainName` newtype
  validates the kernel chain-name contract at construction.
- **`RuleBuilder::jump(&str)` / `goto(&str)` reworked.** The 0.20.1
  infallible shim that fell back to the deprecated `String`
  variants on bad names is gone. The 0.21 form takes a
  pre-validated `ChainName` and stays infallible. New `try_jump`
  / `try_goto` siblings take `&str` and return `Result<Self>` —
  validation happens at construction. Migration: code calling
  `.jump("name")` becomes either `.jump(ChainName::new("name")?)`
  (if a `Result` context exists upstream) or `.try_jump("name")?`
  (one fewer line). Plan 230 closeout.
- **`*Message` fields demoted to `pub(crate)` + `#[non_exhaustive]`
  added.** Plan 231 closeout. Six message types affected:
  `AddressMessage`, `LinkMessage`, `NeighborMessage`, `NsIdMessage`,
  `RouteMessage`, `TcMessage` gain `#[non_exhaustive]`;
  `RuleMessage` and `NsIdMessage` additionally have their fields
  flipped from `pub` to `pub(crate)`. Consumers read via the
  per-field accessor methods (`rule.priority()` etc.) — the 0.20.1
  Plan 231 batch shipped the accessors additively; 0.21 closes
  the convention by hiding the fields. Direct field-access in
  downstream code must become accessor-call. A new
  `scripts/audit-message-accessor-convention.sh` CI gate keeps
  the convention closed against drift, with a sibling
  `test-audit-message-accessor-convention.sh` self-test guarding
  the audit script itself (Plan 237 pattern).

