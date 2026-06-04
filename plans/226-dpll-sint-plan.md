---
to: nlink maintainers
from: 0.20 cycle pre-work — deep audit finding W8 (2026-06-04)
subject: DPLL `sint` codegen + FFO widening — close the variable-length-signed-int class
status: planning
target version: 0.20.0
parent: [Plan 220 master](220-0.20-master-plan.md)
source: [AUDIT_WIRE_FORMAT.md](../AUDIT_WIRE_FORMAT.md) W8
created: 2026-06-04
---

# Plan 226 — DPLL `sint` codegen + FFO widening

## 1. Why this plan exists

DPLL `fractional_frequency_offset_ppt` at
`crates/nlink/src/netlink/genl/dpll/messages.rs:354` is typed
`Option<i32>`. The kernel YAML spec
(`Documentation/netlink/specs/dpll.yaml`) types the field as
`sint` — a **variable-length signed integer**, 4 bytes if the
value fits in `s32`, 8 bytes otherwise. The kernel emit path
in `drivers/dpll/dpll_netlink.c:dpll_msg_add_ffo()` is:

```c
// drivers/dpll/dpll_netlink.c (v6.13) — kernel emit
static int dpll_msg_add_ffo(struct sk_buff *msg, ...)
{
    s64 ffo;
    // ... compute ffo from pin state ...
    return nla_put_sint(msg, DPLL_A_PIN_FRACTIONAL_FREQUENCY_OFFSET,
                        ffo);
}
```

`nla_put_sint`'s contract is: emit the minimum-width
representation. Values that fit in `s32` ship as a 4-byte
attribute; anything that needs the extra range ships as
8-byte.

nlink's derive-macro runtime treats DPLL attributes as
fixed-width by tag. There's no `sint` field type — the macro
reads exactly 4 bytes for `i32` fields. So:

- Pin with FFO that fits in `s32`: kernel emits 4 bytes,
  nlink reads 4 bytes, value is correct.
- Pin with FFO that needs `s64` (typical at link bring-up:
  hundreds of ppm × the kernel's ppt scaling overflow s32):
  kernel emits 8 bytes, nlink's `Option<i32>` parser sees
  attribute-length 8 ≠ 4, returns `None` (or silently
  truncates depending on the parse path).

The 0.19 Plan 206 widened a sibling field (`phase_offset`)
from `i32 → i64` for the same class of bug. The widening was
field-scoped — DPLL's macro-derived field was not generalized
to handle `sint` for any future kernel-side widening.

Two pieces of work close the class for good:

1. Add an `sint` field type to the `#[derive(GenlMessage)]`
   macro runtime in `crates/nlink-macros/`. The runtime
   reads attribute length and dispatches: 4 → `i32 as i64`,
   8 → `i64`, otherwise `None`. Emit path picks the minimum
   width.
2. Widen `fractional_frequency_offset_ppt` (and any sibling
   sint-typed DPLL fields the audit finds) from `Option<i32>`
   to `Option<i64>` and route through the new `sint` codegen.

A cross-family audit (ethtool, devlink, nl80211) catches any
other `sint`-typed fields stored as fixed-width.

## 2. The macro runtime change

`nlink-macros` derives field readers/writers from a
`#[genl_attr(...)]` annotation on each struct field. The
runtime today handles `u8`, `u16`, `u32`, `u64`, `i8`, `i16`,
`i32`, `i64`, `Vec<u8>`, nested attribute groups (Plan 154
Phase 8.5), and enum-typed fields (Plan 154 Phase 8.2). No
variable-length integer type.

### 2.1 Add `Sint` to the field-type registry

```rust
// crates/nlink-macros/src/field_type.rs — new variant
//
// Plan 226 — variable-length signed integer (kernel's
// `nla_put_sint` / `nla_get_sint`). Emit minimum width: 4
// bytes if the value fits in s32, 8 bytes otherwise. Read:
// length 4 → i32 as i64, length 8 → i64, otherwise field is
// left `None` (or surfaces as a parse error in strict
// contexts).
pub enum FieldType {
    // ... existing variants ...
    Sint,                   // i64-typed; variable-length on wire
}
```

The macro infers `FieldType::Sint` from the Rust type
`Option<i64>` when the field also carries the new
`#[genl_attr_sint]` marker (so we don't break the existing
`Option<i64>` semantics for fixed-8-byte fields). Concretely:

```rust
// Field declaration in DpllPinReply (the typed message struct):
#[genl_attr(DpllPinAttr::FractionalFrequencyOffsetPpt)]
#[genl_attr_sint]
pub fractional_frequency_offset_ppt: Option<i64>,
```

The macro generates the reader/writer for this field via the
`__rt::sint` codegen path.

### 2.2 The reader

```rust
// crates/nlink/src/netlink/genl/__rt/sint.rs — new
//
// Plan 226 — runtime for the macro's `sint` field type.
// Mirrors kernel `nla_get_sint` / `nla_put_sint`.

/// Read an `sint` attribute payload as `i64`.
///
/// Returns `None` if `payload.len()` is anything other than 4
/// or 8 bytes. The kernel emits 4 bytes for values that fit
/// in `s32` and 8 bytes otherwise; future kernels may add
/// additional widths (none planned), in which case the
/// parser surfaces `None` rather than truncate.
pub fn read_sint(payload: &[u8]) -> Option<i64> {
    match payload.len() {
        4 => {
            let bytes: [u8; 4] = payload.try_into().ok()?;
            Some(i32::from_ne_bytes(bytes) as i64)
        }
        8 => {
            let bytes: [u8; 8] = payload.try_into().ok()?;
            Some(i64::from_ne_bytes(bytes))
        }
        _ => None,
    }
}
```

### 2.3 The writer

```rust
/// Write an `sint` attribute: emit minimum width.
///
/// Values in `i32::MIN..=i32::MAX` ship as 4 bytes (matches
/// kernel `nla_put_sint`'s behaviour). Everything else ships
/// as 8 bytes.
pub fn write_sint(buf: &mut Vec<u8>, attr_type: u16, value: i64) {
    if (i32::MIN as i64..=i32::MAX as i64).contains(&value) {
        let bytes = (value as i32).to_ne_bytes();
        nla::append(buf, attr_type, &bytes);
    } else {
        let bytes = value.to_ne_bytes();
        nla::append(buf, attr_type, &bytes);
    }
}
```

The `nla::append` helper already exists in
`crates/nlink/src/netlink/attr.rs` and handles header + pad.

### 2.4 Macro codegen

The `#[derive(GenlMessage)]` macro in `nlink-macros/src/lib.rs`
matches on the new `#[genl_attr_sint]` marker and emits:

```rust
// Generated reader (per-field, inside parse):
DpllPinAttr::FractionalFrequencyOffsetPpt => {
    out.fractional_frequency_offset_ppt =
        nlink::netlink::genl::__rt::sint::read_sint(payload);
}

// Generated writer (per-field, inside encode):
if let Some(value) = self.fractional_frequency_offset_ppt {
    nlink::netlink::genl::__rt::sint::write_sint(
        buf,
        DpllPinAttr::FractionalFrequencyOffsetPpt as u16,
        value,
    );
}
```

The marker is opt-in. Existing `Option<i64>` fields continue
to use the fixed-8-byte codegen unless they add the
`#[genl_attr_sint]` marker. No breakage for fields that are
genuinely fixed-width.

## 3. The DPLL field widening

```rust
// crates/nlink/src/netlink/genl/dpll/messages.rs:351-354 —
// corrected
//
// Plan 226 — widen from `Option<i32>` to `Option<i64>` and
// route through `sint` codegen. The kernel YAML types this
// field as `sint`; on pins with non-trivial FFO (telco /
// SyncE workloads at link bring-up) the kernel emits 8 bytes
// and the old fixed-4-byte reader returned `None`.

/// Fractional frequency offset in parts-per-trillion
/// (kernel 6.11+).
///
/// **Breaking change in 0.20**: widened from `Option<i32>` to
/// `Option<i64>` to match the kernel's `sint` wire shape.
/// Values that overflow `i32` (typical at SyncE link
/// bring-up) parsed as `None` in 0.19; they now parse to
/// the kernel-emitted `i64` value.
#[genl_attr(DpllPinAttr::FractionalFrequencyOffsetPpt)]
#[genl_attr_sint]
pub fractional_frequency_offset_ppt: Option<i64>,
```

The older `fractional_frequency_offset` attr (attribute id
24, `DPLL_A_PIN_FRACTIONAL_FREQUENCY_OFFSET`) is the same
class — kernel emits `sint` from `s64 ffo`. If it's currently
typed as `Option<i32>` in nlink (audit confirms during the
sweep), it gets the same widening + `#[genl_attr_sint]`
marker in the same PR.

The methods that derive from these fields
(`DpllPinReply::measured_frequency_hz` at
`messages.rs:373-380` and any FFO-derived helper) take
`Option<i64>` consistently; the existing
`Self::DPLL_PHASE_OFFSET_DIVIDER = 1000` math is already
`i64`-typed (Plan 206) and doesn't need changing.

## 4. Cross-family audit

`sint` typing isn't DPLL-specific. The kernel uses it for any
field where the natural value range is signed and the typical
case fits in `s32`. Other GENL families likely have the same
class.

### 4.1 The audit method

For each family, pull the kernel YAML and grep for `type:
sint`:

```bash
for fam in dpll ethtool devlink nl80211 net_shaper wireguard \
           macsec mptcp; do
    curl -s "https://raw.githubusercontent.com/torvalds/linux/v6.13/Documentation/netlink/specs/${fam}.yaml" \
        | grep -B 2 'type: sint' \
        | awk -v fam="$fam" '/name:/ {print fam": "$2}'
done
```

For each finding, walk to the nlink-side typed message struct
and confirm: is the field typed `Option<i32>` (or wider)?
Does it route through fixed-width codegen, or is it already
on the `sint` path (which doesn't exist yet — so: always
fixed)?

### 4.2 Expected findings table

To be filled in during the PR; structural skeleton:

| Family | Field (per YAML) | nlink site | nlink type | Action |
|---|---|---|---|---|
| dpll | `fractional-frequency-offset` (id 24) | `messages.rs` | TBD | widen + sint |
| dpll | `fractional-frequency-offset-ppt` | `messages.rs:354` | `Option<i32>` | widen + sint (this plan §3) |
| dpll | `phase-offset` (id 15) | `messages.rs:341` | already `Option<i64>` (Plan 206) | add `#[genl_attr_sint]`? — needs walk |
| ethtool | `<TBD>` | TBD | TBD | TBD |
| devlink | `<TBD>` | TBD | TBD | TBD |
| nl80211 | `<TBD>` | TBD | TBD | TBD |

The audit step lands as a single PR-prep walk; the findings
table goes into the PR description so reviewers can
cross-check. Any field marked `widen + sint` ships in the
Plan 226 PR; any field marked `confirm fixed-width` (genuinely
not `sint`) ships unchanged.

### 4.3 Phase-offset note

Plan 206 widened `phase_offset` from `i32 → i64` but the
kernel emit path is `nla_put_sint`. nlink's wire reader for
that field assumes 8 bytes — which works for `phase_offset`
because the kernel currently emits 8 bytes for any non-trivial
phase offset. But a future kernel that emits 4 bytes for
small phase offsets (legitimate per `nla_put_sint`'s
contract) would break nlink.

Add `#[genl_attr_sint]` to `phase_offset` as part of this
plan. The Rust type stays `Option<i64>`; the marker switches
the macro codegen to the variable-width reader. The bytes
nlink already accepts (8-byte) still parse cleanly; the
4-byte path becomes available without further change.

## 5. Test plan

### 5.1 Unit tests for the `sint` codegen

```rust
// crates/nlink/src/netlink/genl/__rt/sint.rs — tests

#[cfg(test)]
mod sint_tests {
    use super::*;

    #[test]
    fn read_4_byte_sint_returns_widened_i32() {
        let payload = (-1_i32).to_ne_bytes();
        assert_eq!(read_sint(&payload), Some(-1));

        let payload = (i32::MIN).to_ne_bytes();
        assert_eq!(read_sint(&payload), Some(i32::MIN as i64));

        let payload = (i32::MAX).to_ne_bytes();
        assert_eq!(read_sint(&payload), Some(i32::MAX as i64));
    }

    #[test]
    fn read_8_byte_sint_returns_full_i64() {
        let payload = (i64::MIN / 2).to_ne_bytes();
        assert_eq!(read_sint(&payload), Some(i64::MIN / 2));

        let payload = (i64::MAX).to_ne_bytes();
        assert_eq!(read_sint(&payload), Some(i64::MAX));
    }

    #[test]
    fn read_sint_rejects_unexpected_lengths() {
        assert_eq!(read_sint(&[0u8; 0]), None);
        assert_eq!(read_sint(&[0u8; 1]), None);
        assert_eq!(read_sint(&[0u8; 2]), None);
        assert_eq!(read_sint(&[0u8; 3]), None);
        assert_eq!(read_sint(&[0u8; 5]), None);
        assert_eq!(read_sint(&[0u8; 16]), None);
    }

    #[test]
    fn write_sint_picks_minimum_width() {
        let mut buf = Vec::new();
        write_sint(&mut buf, 42, 100);
        // 4-byte NLA header + 4-byte payload = 8 bytes total.
        assert_eq!(buf.len(), 8);

        let mut buf = Vec::new();
        write_sint(&mut buf, 42, i64::MAX);
        // 4-byte NLA header + 8-byte payload = 12 bytes total.
        assert_eq!(buf.len(), 12);

        let mut buf = Vec::new();
        write_sint(&mut buf, 42, i32::MIN as i64);
        // Fits in s32; ships as 4 bytes.
        assert_eq!(buf.len(), 8);
    }

    #[test]
    fn round_trip_holds_for_boundary_values() {
        for value in [
            0_i64, 1, -1,
            i32::MAX as i64,
            i32::MIN as i64,
            i32::MAX as i64 + 1,
            i32::MIN as i64 - 1,
            i64::MAX,
            i64::MIN,
        ] {
            let mut buf = Vec::new();
            write_sint(&mut buf, 42, value);
            // Skip the NLA header (4 bytes); read payload.
            let payload = &buf[4..];
            assert_eq!(
                read_sint(payload),
                Some(value),
                "round-trip failed for {value}"
            );
        }
    }
}
```

### 5.2 DPLL FFO round-trip test

```rust
// crates/nlink/src/netlink/genl/dpll/messages.rs — test
//
// Plan 226 — pre-fix this case parsed FFO as `None`.

#[test]
fn dpll_pin_reply_parses_8_byte_ffo() {
    // Build a synthetic DPLL pin reply with FFO that needs
    // s64 (i.e., > i32::MAX as i64, the typical real-world
    // case for SyncE-EthPort pins at link bring-up).
    let ffo: i64 = (i32::MAX as i64) + 1_000_000;
    let frame = build_synthetic_pin_reply_with_ffo(ffo);
    let pin = DpllPinReply::from_bytes(&frame)
        .expect("must parse");
    assert_eq!(pin.fractional_frequency_offset_ppt, Some(ffo));
}

#[test]
fn dpll_pin_reply_parses_4_byte_ffo() {
    // Backward-compat: kernel can still emit 4 bytes when
    // the value fits in s32. nlink reads either width.
    let ffo: i64 = -42;
    let frame = build_synthetic_pin_reply_with_ffo_4_byte(ffo);
    let pin = DpllPinReply::from_bytes(&frame)
        .expect("must parse");
    assert_eq!(pin.fractional_frequency_offset_ppt, Some(ffo));
}
```

### 5.3 Integration test (gated)

```rust
// crates/nlink/tests/integration/dpll_ffo.rs
nlink::require_root!();
nlink::require_module!("dpll");

#[tokio::test]
async fn dpll_pin_ffo_round_trips_through_kernel() {
    // Requires a DPLL-capable device; skip cleanly otherwise.
    // The mock dpll netlink device introduced in
    // tools/testing/ via the upstream selftest covers this
    // case if it's loaded. Document the skip path.
}
```

The integration test is the soft path — real DPLL hardware
isn't always present. The unit + synthetic-frame tests in §5.1
and §5.2 are the load-bearing coverage.

### 5.4 CI workflow modprobe addition

`.github/workflows/integration-tests.yml` does NOT currently
modprobe `dpll` (verified: the workflow loads `xfrm_user`,
`nf_conntrack`, `nf_nat`, `wireguard`, `dummy`, `veth`, but not
`dpll`). Without it, the integration test in §5.3 skips clean on
every CI run because `/sys/module/dpll` isn't present.

Add `dpll` to the modprobe list. The DPLL module is built-in on
some kernels (CONFIG_DPLL=y); the modprobe is a no-op when it's
built in, and a load when it's modular. The `require_module!`
macro checks `/sys/module/<name>`, which the kernel populates for
both cases.

## 6. Risks

- **Breaking-change axis: `Option<i32> → Option<i64>`**.
  Downstream code that destructured `let Some(ffo): Option<i32>
  = pin.fractional_frequency_offset_ppt` breaks at compile
  time. The compile error is the desired surface; document the
  migration explicitly. CLAUDE.md's "aggressive deprecation
  cadence" preference doesn't apply here — there's no useful
  alias because the type is the source of truth.

- **Macro complexity**. The `sint` codegen adds a new
  field-type path to `nlink-macros`. Risk: existing
  `Option<i64>` field semantics (fixed 8-byte) need to stay
  unchanged for fields that don't opt into the marker.
  Mitigation: the `#[genl_attr_sint]` marker is opt-in; the
  default `Option<i64>` codegen is unchanged. Unit tests in
  §5.1 cover both paths.

- **Audit-time pressure**. The cross-family audit (§4) could
  surface many `sint`-typed fields that all need widening.
  If the audit returns >5 fields outside DPLL, the cycle may
  not finish in one PR. Mitigation: prioritize DPLL (the
  triggering finding) + any field that's already known to
  cause silent data loss in production; defer the rest to a
  Plan 226-follow-on for 0.21.

- **kernel `nla_put_sint` semantics**. The kernel `sint` emit
  is documented as "minimum width" but a future kernel
  could ship 2-byte or 6-byte widths (theoretically — no
  current code path does this). Our reader returns `None` on
  any width that isn't 4 or 8. If kernel widens its sint
  alphabet, we need to extend the reader; not now.

- **Macro re-export hygiene**. The `__rt::sint` module needs
  to be `pub(crate)` exposed where derived code can reach
  it, but not part of the public surface. Mirror Plan 154
  Phase 7's re-export discipline. The `nlink::macros::__rt`
  module is the existing landing zone.

## 7. Migration

Breaking change. CHANGELOG entry under `[Unreleased]`:

```markdown
### Changed

- **`DpllPinReply::fractional_frequency_offset_ppt` widened
  from `Option<i32>` to `Option<i64>`.** The kernel emits
  this field as `sint` (variable-length: 4 bytes if it fits
  in `s32`, 8 bytes otherwise). nlink previously assumed a
  fixed 4-byte read, so pins with non-trivial FFO (typical at
  SyncE link bring-up) silently parsed as `None`. Same class
  as 0.19's `phase_offset` widening (Plan 206). Plan 226.

### Added

- `#[genl_attr_sint]` field marker for `#[derive(GenlMessage)]`.
  Annotates an `Option<i64>` field as variable-length signed
  integer; the macro emits the kernel's `nla_put_sint` /
  `nla_get_sint` codepath (minimum-width on write, accept-4-
  or-8 on read). Plan 226. Available for downstream custom
  GENL families.
```

Migration guide entry under
`docs/migration_guide/0.19.0-to-0.20.0.md`:

```markdown
### DPLL FFO type widening

`DpllPinReply::fractional_frequency_offset_ppt` changed from
`Option<i32>` to `Option<i64>`.

```rust
// Before:
let ffo: Option<i32> = pin.fractional_frequency_offset_ppt;

// After:
let ffo: Option<i64> = pin.fractional_frequency_offset_ppt;
```

If you were destructuring to a local typed binding, the new
type flows through. If you were assigning to a `Vec<i32>` or
similar collection, cast explicitly:

```rust
// If the i32 truncation is genuinely what you want, opt in:
let ffos: Vec<i32> = pins.iter()
    .filter_map(|p| p.fractional_frequency_offset_ppt)
    .map(|f| f as i32)
    .collect();
```

`fractional_frequency_offset` (the older attr) gets the
same widening; the migration path is identical.
```

## 8. Acceptance

- ✅ `nlink-macros` exposes the `#[genl_attr_sint]` marker and
  emits the `__rt::sint` codegen for marked fields.
- ✅ `__rt::sint::{read_sint, write_sint}` are in tree; unit
  tests from §5.1 pass.
- ✅ DPLL `fractional_frequency_offset_ppt` is typed
  `Option<i64>` and uses the `sint` codegen.
- ✅ DPLL `fractional_frequency_offset` (id 24) likewise.
- ✅ DPLL `phase_offset` carries `#[genl_attr_sint]` (Plan 206
  follow-up; behaviour unchanged today, forward-compat ready).
- ✅ The cross-family audit table in §4.2 is populated;
  every other `sint`-typed field outside DPLL is either fixed
  in the same PR or documented as deferred to 0.21 (with the
  trade-off explicit in the PR description).
- ✅ The unit tests in §5.1 and §5.2 pass under
  `cargo test -p nlink --lib`.
- ✅ The integration test in §5.3 is registered; it skips
  cleanly when DPLL hardware isn't present.
- ✅ `cargo +stable clippy --workspace --all-targets
  --all-features -- --deny warnings` passes.
- ✅ The migration-guide entry and CHANGELOG entries land at
  cut time.

## 9. Cross-references

- [`AUDIT_WIRE_FORMAT.md`](../AUDIT_WIRE_FORMAT.md) W8 — the
  finding, kernel-source references for `dpll_msg_add_ffo`,
  and the YAML spec citation.
- Kernel source: `drivers/dpll/dpll_netlink.c` v6.13.
- Kernel YAML:
  `https://raw.githubusercontent.com/torvalds/linux/v6.13/Documentation/netlink/specs/dpll.yaml`.
- Kernel `nla_put_sint` / `nla_get_sint`:
  `include/net/netlink.h` — the minimum-width contract.
- [Plan 206](.) (historic, shipped 0.19) — `phase_offset`
  i32→i64 widening; same class, scoped to one field.
- [Plan 154 Phase 8](.) (historic, shipped 0.16) —
  `nlink-macros` field-type extension cadence; Plan 226's
  `sint` is the next addition in the same shape.
- `crates/nlink/src/netlink/genl/dpll/messages.rs:340-358`
  — the typed message struct being modified.
- `crates/nlink-macros/src/` — the macro crate that gets the
  new field-type variant.
- [Plan 220 master](220-0.20-master-plan.md) §3 — Plan 226's
  position in the P1 defensive-correctness cluster (alongside
  223, 224, 225).
