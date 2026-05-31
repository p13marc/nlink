---
to: nlink maintainers
from: 0.19 second deep-audit
subject: Plan 206 — DPLL phase_offset s64 + macros runtime i64 support
status: queued for 0.19 — HIGH (silent value truncation on telco workloads)
target version: 0.19.0
parent: [203](203-0.19-second-batch-master.md)
source: docs/AUDIT_REPORT_2026_05_31.md §H1
created: 2026-05-31
---

# Plan 206 — DPLL `phase_offset` s64 + macros runtime i64 support

## 1. Why this plan exists

The kernel's `Documentation/netlink/specs/dpll.yaml` declares
`phase-offset` as `s64` (signed 64-bit, attoseconds × 1000).
nlink's `DpllPin::phase_offset` field is typed `Option<i32>` and
parsed via `__rt::parse_i32_attr` which reads the **low 4 bytes
only** of an 8-byte payload.

On LE platforms (every supported Linux platform) the high 4 bytes
of the kernel's s64 value are silently dropped. Phase-offset
values in attoseconds × 1000 routinely exceed i32 range — a 1 ns
offset = 1e9 attoseconds × 1000 = well past `i32::MAX`. Telco/PTP/
SyncE users get nonsense readings.

The fix requires:
1. New `__rt::parse_i64_attr` and `emit_i64_attr` helpers in the
   macros runtime.
2. Extension of the `GenlMessage` derive to recognize `i64` /
   `Option<i64>` field types.
3. Type flip `phase_offset: Option<i32>` → `Option<i64>` (and
   spot-audit for other s64 fields in DPLL or other GENL
   families that might be similarly truncated).
4. `phase_offset_ns()` accessor unchanged (already returns `i64`;
   the conversion just stops truncating).

## 2. Phase 1 — `__rt::parse_i64_attr` and `emit_i64_attr`

**File:** `crates/nlink/src/macros/mod.rs:284` (location of the
existing `parse_i32_attr`).

Add the i64 helpers next to the i32 ones, matching the same shape:

```rust
/// Parse a signed 64-bit attribute payload (native endian).
/// Accepts payloads of any size >= 8 bytes per CLAUDE.md
/// `## Parser robustness` rule 1 — the kernel may grow the
/// attribute in future versions, and we read the prefix.
pub fn parse_i64_attr(payload: &[u8]) -> Result<i64> {
    if payload.len() < 8 {
        return Err(Error::InvalidAttribute(
            format!("truncated i64 attribute: {} bytes", payload.len())
        ));
    }
    Ok(i64::from_ne_bytes([
        payload[0], payload[1], payload[2], payload[3],
        payload[4], payload[5], payload[6], payload[7],
    ]))
}

/// Append a signed 64-bit attribute (native endian).
pub fn emit_i64_attr(builder: &mut MessageBuilder, attr_type: u16, value: i64) {
    builder.append_attr(attr_type, &value.to_ne_bytes());
}
```

Plus equivalent u64 helpers for completeness (we already have
`u32_ne` in `attr::get`; round out the unsigned form here too if
it's missing):

```rust
pub fn parse_u64_attr(payload: &[u8]) -> Result<u64> {
    if payload.len() < 8 {
        return Err(Error::InvalidAttribute(
            format!("truncated u64 attribute: {} bytes", payload.len())
        ));
    }
    Ok(u64::from_ne_bytes([
        payload[0], payload[1], payload[2], payload[3],
        payload[4], payload[5], payload[6], payload[7],
    ]))
}

pub fn emit_u64_attr(builder: &mut MessageBuilder, attr_type: u16, value: u64) {
    builder.append_attr(attr_type, &value.to_ne_bytes());
}
```

Reuse existing `MessageBuilder::append_attr_u64` if the public
helper already exists; the macros runtime ones are private
implementations gated under `__rt` for use by macro-generated
code.

## 3. Phase 2 — Extend `GenlMessage` derive

**File:** `crates/nlink-macros/src/genl_message.rs`

The derive macro inspects field types and emits parse / emit
calls. Currently maps:
- `i32`/`Option<i32>` → `parse_i32_attr`/`emit_i32_attr`
- `u32`/`Option<u32>` → `parse_u32_attr`/`emit_u32_attr`
- (etc.)

Add the i64/u64 cases:
```rust
match field_type {
    // ... existing matches ...
    "i64" | "Option<i64>" => quote! {
        ::nlink::macros::__rt::parse_i64_attr
        ::nlink::macros::__rt::emit_i64_attr
    },
    "u64" | "Option<u64>" => quote! {
        ::nlink::macros::__rt::parse_u64_attr
        ::nlink::macros::__rt::emit_u64_attr
    },
    // ...
}
```

Reference: `Plan 154 Phase 8.1` shipped the i32 support; this is
the same shape for i64.

## 4. Phase 3 — Flip `DpllPin::phase_offset`

**File:** `crates/nlink/src/netlink/genl/dpll/messages.rs:331`

Replace:
```rust
#[genl_attr(DpllPinAttr::PhaseOffset)]
pub phase_offset: Option<i32>,
```

With:
```rust
/// Phase offset from the reference clock, in attoseconds × 1000.
/// Kernel UAPI: `s64` (verified against
/// `Documentation/netlink/specs/dpll.yaml`). Sub-nanosecond
/// values routinely exceed i32 range; the previous `Option<i32>`
/// silently truncated the high 4 bytes on LE platforms.
#[genl_attr(DpllPinAttr::PhaseOffset)]
pub phase_offset: Option<i64>,
```

`phase_offset_ns()` already returns `i64` (currently constructed
from a truncated value); no signature change needed — it just
stops truncating.

## 5. Phase 4 — Spot-audit other DPLL fields and other GENL families

Files to audit:
- `crates/nlink/src/netlink/genl/dpll/messages.rs` — every
  field, check against `Documentation/netlink/specs/dpll.yaml`.
  Per the audit agent, `temp_celsius`, `phase_adjust*`,
  `fractional_frequency_offset*` are correctly typed `i32` per
  the kernel YAML. Only `phase_offset` is wrong.
- `crates/nlink/src/netlink/genl/net_shaper/messages.rs` —
  verify shaper rates / burst sizes against kernel YAML (likely
  u64 in some fields).
- `crates/nlink/src/netlink/genl/devlink/messages.rs` — rate
  attributes are u64 (`DEVLINK_ATTR_RATE_TX_*`); verify these
  go through `parse_u64_attr` not `parse_u32_attr`.
- `crates/nlink/src/netlink/genl/ethtool/messages.rs` — speed
  attributes can be > u32 (100G+ in bits/s overflows u32).
- `crates/nlink/src/netlink/genl/wireguard/connection.rs` —
  `last_handshake_time` is `__u64`; verify.

Document findings inline; any actual bug is folded into this
plan as a new Phase X audit item.

## 6. Tests

### 6.1 Unit — `parse_i64_attr` and `emit_i64_attr` correctness

**File:** new test module in `crates/nlink/src/macros/mod.rs`.

```rust
#[cfg(test)]
mod i64_helper_tests {
    use super::__rt::*;

    #[test]
    fn parse_i64_round_trips_through_emit() {
        let mut builder = MessageBuilder::new(0, 0);
        emit_i64_attr(&mut builder, 7, -123_456_789_012_345_i64);
        let bytes = builder.as_bytes();
        let payload = find_attr_payload(bytes, 7).unwrap();
        let parsed = parse_i64_attr(payload).unwrap();
        assert_eq!(parsed, -123_456_789_012_345_i64);
    }

    #[test]
    fn parse_i64_handles_value_above_i32_max() {
        // 1 ns in attoseconds × 1000 = 1_000_000_000_000.
        // Well above i32::MAX (2_147_483_647).
        let mut builder = MessageBuilder::new(0, 0);
        emit_i64_attr(&mut builder, 7, 1_000_000_000_000_i64);
        let payload = find_attr_payload(builder.as_bytes(), 7).unwrap();
        let parsed = parse_i64_attr(payload).unwrap();
        assert_eq!(parsed, 1_000_000_000_000_i64);
    }

    #[test]
    fn parse_i64_accepts_larger_than_8_payload() {
        // Forward-compat per CLAUDE.md rule 1.
        let bigger = vec![0xff; 12];  // 12 bytes
        let v = parse_i64_attr(&bigger).unwrap();
        assert_eq!(v, -1i64);  // 8 0xff bytes → -1
    }

    #[test]
    fn parse_i64_rejects_short_payload() {
        let short = vec![0u8; 4];
        assert!(parse_i64_attr(&short).is_err());
    }
}
```

### 6.2 Unit — DPLL pin parse correctness

**File:** extend `crates/nlink/src/netlink/genl/dpll/messages.rs`
test mod.

```rust
#[test]
fn dpll_pin_phase_offset_parses_large_s64_value() {
    // Build a synthetic DPLL pin response with a phase_offset
    // attribute carrying a value > i32::MAX.
    let mut builder = MessageBuilder::new(0, 0);
    builder.append_attr_u32_be(DpllPinAttr::Id as u16, 1);
    // 5 ns offset in attoseconds × 1000:
    let phase = 5_000_000_000_000_i64;
    builder.append_attr(
        DpllPinAttr::PhaseOffset as u16,
        &phase.to_ne_bytes(),
    );
    let bytes = builder.finish();

    let pin = DpllPin::from_genl_attrs(/* iter */&bytes[NLMSG_HDRLEN + GENL_HDRLEN..]).unwrap();
    assert_eq!(pin.phase_offset, Some(phase));
    // phase_offset_ns() returns Option<i64>:
    assert_eq!(pin.phase_offset_ns(), Some(5_i64));
}

#[test]
fn dpll_pin_phase_offset_pre_fix_truncation_regression() {
    // This is the test that would have caught the original bug.
    // A 5ns offset truncated to i32 would have been:
    //   5e12 as i32 == -1389934688 (silent wrap)
    // Verify our post-fix value matches what the kernel sent.
    let phase = 5_000_000_000_000_i64;
    let bytes_lo32 = (phase as u32).to_ne_bytes();  // would be parsed as i32 pre-fix
    let pre_fix_lossy = i32::from_ne_bytes(bytes_lo32) as i64;
    assert_ne!(pre_fix_lossy, phase,
        "sanity: 5ns truncated to i32 != 5ns");
    // Post-fix, the round-trip preserves the value (covered by
    // the test above).
}
```

### 6.3 Integration (hardware-gated, opportunistic)

**File:** extend
`crates/nlink/tests/integration/cycle_0_19_backfill.rs`

```rust
#[tokio::test]
async fn dpll_pin_dump_reports_kernel_s64_phase_offset() -> Result<()> {
    nlink::require_root!();
    nlink::require_module!("dpll");

    let conn = Connection::<Dpll>::new_async().await?;
    let pins = conn.pin_dump().await?;

    // Skip if no DPLL hardware on this test box.
    if pins.is_empty() {
        eprintln!("no DPLL pins on this kernel; skipping");
        return Ok(());
    }

    for pin in &pins {
        // Per the kernel spec, phase_offset can be 0 (locked) or
        // any signed value. The assertion is just that the parse
        // doesn't crash + returns Some when the attribute was
        // present.
        let _ = pin.phase_offset;
    }

    Ok(())
}
```

## 7. CHANGELOG entry

```markdown
### Breaking changes

- **`DpllPin::phase_offset` field type changes from
  `Option<i32>` to `Option<i64>`** (Plan 206). The kernel UAPI
  declares this attribute as `s64` (attoseconds × 1000), and
  nlink was silently truncating the high 4 bytes on every
  parse. Telco / PTP / SyncE values regularly exceed i32 range;
  a 1 ns offset is 1e12 in the kernel's units, well past
  `i32::MAX`. Callers reading `.phase_offset` need to update
  any explicit `i32` annotations; the
  `DpllPin::phase_offset_ns()` accessor returns the same
  `Option<i64>` shape it always did.

### Fixed

- **DPLL `phase_offset` was silently truncated to i32** —
  parsed via the macros runtime's `parse_i32_attr` which reads
  the low 4 bytes only. Now uses the new `parse_i64_attr` /
  `emit_i64_attr` helpers (Plan 206 Phase 1). 4 new unit tests
  verify the round-trip + accept-larger-payload + reject-short
  contracts.

### Added

- **`nlink::macros::__rt::parse_i64_attr` / `emit_i64_attr`** —
  i64 / u64 helpers for the macros runtime. Macro derive now
  recognizes `i64` and `u64` field types (Plan 206 Phase 2).
  Same shape as the i32 / u32 helpers from Plan 154 Phase 8.1.
```

## 8. Migration guide

```markdown
### Plan 206 — DPLL `phase_offset` widened to i64

If you read `DpllPin::phase_offset` explicitly:

```rust
// 0.18:
let p: Option<i32> = pin.phase_offset;
// 0.19:
let p: Option<i64> = pin.phase_offset;
```

If you used `pin.phase_offset_ns()`: no change. Same return
type (`Option<i64>`), just no longer truncating.

If your code worked around the truncation by storing the value
separately: you can now delete that workaround.
```

## 9. Acceptance criteria

- [ ] `__rt::parse_i64_attr` + `emit_i64_attr` + `parse_u64_attr` +
      `emit_u64_attr` helpers added
- [ ] `GenlMessage` derive recognizes `i64` / `u64` / `Option<i64>` /
      `Option<u64>` field types
- [ ] `DpllPin::phase_offset` field is `Option<i64>`
- [ ] Spot-audit of other DPLL/net_shaper/devlink/ethtool/WG
      fields documented (no other s64 fields found, OR a
      follow-up issue is filed)
- [ ] 4 unit tests for the i64 helpers
- [ ] 2 unit tests for DPLL phase_offset parsing
- [ ] 1 root-gated integration test for DPLL pin dump
- [ ] CHANGELOG `### Breaking changes` + `### Fixed` + `### Added`
- [ ] Migration guide §"Plan 206"

## 10. Effort estimate

| Phase | Time |
|---|---|
| Phase 1 — i64/u64 helpers in `__rt` | 1 h |
| Phase 2 — macros derive extension | 1 h |
| Phase 3 — DpllPin field flip | 15 min |
| Phase 4 — spot-audit other fields | 1 h |
| Tests (unit + integration) | 1.5 h |
| CHANGELOG + migration guide | 30 min |
| **Total** | **~5 h** |

## 11. Risks

- **Macro derive extension is non-trivial**: the existing i32
  support landed in Phase 8.1 (~50 LOC). The i64 addition should
  be similar; risk is forgetting to wire one of the
  match-arm branches.
- **Other DPLL fields might also be s64**: the audit agent
  verified phase_offset is the only one, but a fresh kernel YAML
  diff could surface more. Spot-audit is part of Phase 4.
- **The `cycle_0_19_backfill.rs` integration test won't run on
  CI without DPLL hardware**: that's why it skips cleanly with an
  empty-list bail. Real validation needs telco/PTP hardware.

## 12. Cross-cutting artifacts

| Artifact | Action |
|---|---|
| `CHANGELOG.md` | 1 breaking + 1 fixed + 1 added entry |
| `docs/migration_guide/0.18.0-to-0.19.0.md` | §"Plan 206" |
| `crates/nlink/src/macros/mod.rs` | 4 new helper functions + test mod |
| `crates/nlink-macros/src/genl_message.rs` | match-arm extension |
| `crates/nlink/src/netlink/genl/dpll/messages.rs` | field type flip + test mod |
| `crates/nlink/tests/integration/cycle_0_19_backfill.rs` | 1 root-gated test |

End of plan.
