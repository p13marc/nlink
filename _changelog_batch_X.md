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

