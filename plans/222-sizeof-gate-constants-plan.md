---
to: nlink maintainers
from: 0.20 cycle pre-work — deep audit derivation
subject: extend 0.19 Plan 213 sizeof CI gate to UAPI constant values
status: planning — depends on Plan 221 landing (the bugs the gate is being designed to catch)
target version: 0.20.0
parent: [Plan 220 master](220-0.20-master-plan.md)
source: [AUDIT_REPORT.md](../AUDIT_REPORT.md) §P1 Plan X1 + [AUDIT_WIRE_FORMAT.md](../AUDIT_WIRE_FORMAT.md) W14
created: 2026-06-04
---

# Plan 222 — Extend the sizeof CI gate to UAPI constants

## 1. Why this plan exists

0.19's Plan 213 shipped a build-time CI gate at
`crates/nlink/src/netlink/sys_sizeof.rs` that asserts every
zerocopy-`#[repr(C)]` wire struct matches the kernel's
`sizeof(struct …)`. It immediately surfaced the
`XfrmUserTmpl` 62→64 sibling bug the moment it merged. It saved
the codebase from a wire-format regression class.

It does **not** verify the kernel-side constant values that nlink
hardcodes as Rust `const`s (message types, attribute IDs, flag
values). All 4 XFRM constants Plan 221 fixes were
off-by-1-to-4 because nobody counted the kernel enum and the gate
didn't catch it. The Plan 204 nft-verdict fix (`NFT_JUMP`/`NFT_GOTO`)
had the same root cause; it was patched by adding a hand-rolled
`nft_verdict` module to `sys_sizeof.rs` — but that pattern was
never generalized.

**Plan 222 closes the constant-value drift class for good.** Adding
the gate would have caught all 4 XFRM defects, the nft `CtKey`
defect, and the `TCA_HTB_OFFLOAD` dead-code drift at build time.

## 2. The gate's design

### 2.1 Mechanism (same as sizeof)

`crates/nlink/src/netlink/sys_sizeof.rs` already uses C-side
compile-time generation via the `cc` crate or a build script —
verify the actual layout in `build.rs`. Plan 222 extends the same
mechanism: write a small C program at build time that emits
`size_t` values for each `enum`/`const` we want to pin, capture
the output, and compare in a `#[test]`.

Concrete shape (matches what 213 does for sizes):

```rust
// crates/nlink/src/netlink/sys_sizeof.rs — extended

#[cfg(test)]
mod xfrm_msg_type {
    /// Kernel UAPI: include/uapi/linux/xfrm.h enum xfrm_attr_msg_type
    /// Verified via build.rs C-program output.
    pub const XFRM_MSG_NEWSA: u16 = 16;
    pub const XFRM_MSG_DELSA: u16 = 17;
    pub const XFRM_MSG_GETSA: u16 = 18;
    pub const XFRM_MSG_NEWPOLICY: u16 = 19;
    pub const XFRM_MSG_DELPOLICY: u16 = 20;
    pub const XFRM_MSG_GETPOLICY: u16 = 21;
    pub const XFRM_MSG_ALLOCSPI: u16 = 22;
    pub const XFRM_MSG_ACQUIRE: u16 = 23;
    pub const XFRM_MSG_EXPIRE: u16 = 24;
    pub const XFRM_MSG_UPDPOLICY: u16 = 25;
    pub const XFRM_MSG_UPDSA: u16 = 26;
    pub const XFRM_MSG_POLEXPIRE: u16 = 27;
    pub const XFRM_MSG_FLUSHSA: u16 = 28;
    pub const XFRM_MSG_FLUSHPOLICY: u16 = 29;
    // ... through SETDEFAULT = 0x21 ...
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::netlink::xfrm;

    #[test]
    fn xfrm_msg_types_match_kernel_uapi() {
        // The constants nlink uses in its production paths must
        // equal the kernel-validated reference values.
        assert_eq!(xfrm::XFRM_MSG_NEWSA, xfrm_msg_type::XFRM_MSG_NEWSA);
        assert_eq!(xfrm::XFRM_MSG_FLUSHSA, xfrm_msg_type::XFRM_MSG_FLUSHSA);
        assert_eq!(xfrm::XFRM_MSG_FLUSHPOLICY, xfrm_msg_type::XFRM_MSG_FLUSHPOLICY);
        assert_eq!(xfrm::XFRM_MSG_UPDSA, xfrm_msg_type::XFRM_MSG_UPDSA);
        assert_eq!(xfrm::XFRM_MSG_UPDPOLICY, xfrm_msg_type::XFRM_MSG_UPDPOLICY);
        // ... all 14 message types ...
    }
}
```

### 2.2 The kernel-reference values

For each module the gate covers, the reference values are either:

- **Hand-mirrored from kernel UAPI** — like the table above. The
  values are written into the `sys_sizeof` module by the
  maintainer at gate-creation time, after verifying against the
  kernel header. Future drift (kernel changes the value) would
  break the gate, alerting the maintainer to manually verify and
  bump.

- **Or extracted from `build.rs`** — `build.rs` invokes a small C
  program that includes the kernel header, emits each constant's
  value, captures stdout, and emits a generated Rust module. This
  is the "true" mechanism Plan 213 uses for struct sizes. Picking
  between the two:
  - **Hand-mirrored** is faster to maintain, no `build.rs`
    complexity for constants we care about; the gate fails on
    upstream drift which is exactly when we want to know.
  - **Build-time extracted** is more robust but adds C-toolchain
    requirements on the build host and complicates cross-
    compilation (s390x and aarch64 builds need their respective
    `linux/*.h` headers). For RPC libraries this is acceptable;
    for netlink libraries it's often onerous on minimal CI
    runners.

  **Decision: hand-mirrored for 0.20**, with a follow-up plan to
  reduce manual error by writing a `scripts/audit-uapi-constants.sh`
  that periodically diffs the hand-mirrored module against a
  kernel header checked out under `target/uapi-reference/`. Run
  the audit script in CI weekly via a scheduled workflow; surface
  drift as an issue, not a build break.

### 2.3 What to cover

Listed in order of impact + risk. Each module is one
`mod {name}_const { ... }` block in `sys_sizeof.rs`:

| Module | Constants | Source | Cost to mirror |
|---|---|---|---|
| `xfrm_msg_type` | ~14 (`XFRM_MSG_*`) | `include/uapi/linux/xfrm.h` | small |
| `xfrm_attr` | ~40 (`XFRMA_*`) | same | medium |
| `nft_ct_keys` | ~24 (`NFT_CT_*`) | `include/uapi/linux/netfilter/nf_tables.h` | small |
| `nft_meta_keys` | ~24 (`NFT_META_*`) | same | small |
| `nft_reg` | ~10 (`NFT_REG_*`) | same | small |
| `tca_htb_attr` | ~10 (`TCA_HTB_*`) | `include/uapi/linux/pkt_sched.h` | small |
| `tca_flower_key` | ~80 (`TCA_FLOWER_KEY_*`) | `include/uapi/linux/pkt_cls.h` | medium |
| `tca_filter_attr` | ~25 (`TCA_FILTER_*`) | same | small |
| `ifla_attr` | ~70 (`IFLA_*`) | `include/uapi/linux/if_link.h` | medium |
| `rta_attr` | ~30 (`RTA_*`) | `include/uapi/linux/rtnetlink.h` | small |
| `dpll_a` | ~30 (`DPLL_A_*`) | `Documentation/netlink/specs/dpll.yaml` | medium (YAML, not C) |
| `devlink_attr` | ~150 (`DEVLINK_ATTR_*`) | `include/uapi/linux/devlink.h` | medium |
| `ethtool_a` | ~50 (`ETHTOOL_A_*`) | `include/uapi/linux/ethtool_netlink.h` | medium |
| `ctnetlink_attr` | ~30 (`CTA_*`) | `include/uapi/linux/netfilter/nfnetlink_conntrack.h` | small |

Total: ~600 constants. At ~30 lines per module + ~20 lines per
test, that's ~3000 lines of `sys_sizeof.rs` growth. Acceptable;
it's data, not logic. CI runs them as a single test target so the
test-time impact is negligible (the assertions are integer
compares).

### 2.4 Plan ordering within the cycle

| Phase | Effort | Covers | Lands as |
|---|---|---|---|
| 222.1 | small | XFRM (msg types + attrs) + nft CT keys + meta keys | one PR |
| 222.2 | small | TC HTB + flower keys + filter attrs | one PR |
| 222.3 | medium | IFLA + RTA + ctnetlink | one PR |
| 222.4 | medium | DPLL + devlink + ethtool | one PR |

Each phase ships independently. Phase 1 unblocks Plan 221's
hotfix (the hotfix lands the constant fixes; phase 1 of this plan
locks them with the gate so they can't drift again).

### 2.5 Phase 222.1 is part of the hotfix train

Phase 222.1 — the XFRM + nft-CT modules — is the **smallest**
incremental change that prevents recurrence of Plan 221's bug
class. Land it as a follow-up to Plan 221 within the same hotfix
window. This means the 0.19.1 hotfix actually ships *two* commits:
the constant fix (Plan 221) and the gate that locks the fix
(Plan 222.1).

Both can land in the same PR.

## 3. Test plan

`cargo test -p nlink --lib sys_sizeof` runs all the constant gates
in <1s — they're pure integer compares.

CI integration: covered by the existing `cargo test` CI job. No
new CI gate needed beyond the test count growing.

For drift detection on un-mirrored sections (the IFLA_* enum is
~70 entries; we'd mirror the load-bearing ones), a separate
script `scripts/audit-uapi-constants.sh`:

```bash
#!/usr/bin/env bash
# Diff our hand-mirrored UAPI constants against a checked-out kernel
# tree. Surfaces drift as a build warning (or a weekly cron issue).
KERNEL_TAG="${KERNEL_TAG:-v6.13}"
KERNEL_PATH="${KERNEL_PATH:-/tmp/linux-${KERNEL_TAG}}"
# ... clone the kernel UAPI subset, run rust-based reference
# extractor, diff against sys_sizeof.rs ...
```

Wire into `.github/workflows/uapi-drift.yml` as a weekly schedule.

## 4. Risks

- **Hand-mirrored constants drift silently** if the maintainer
  doesn't update them when bumping kernel-UAPI awareness. Mitigation:
  `audit-uapi-constants.sh` weekly cron + alert on drift. The
  audit script and the gate together close the loop.
- **CI runs against many kernel versions** but the gate's
  reference values are pinned to one (v6.13 today). If a future
  upstream kernel renumbers an enum entry (rare; UAPI is stable),
  the gate would break. The break is the right signal — manual
  verification, then bump the reference and document.
- **Cost of writing 600 constants by hand**. ~6 hours of focused
  work. Acceptable.

## 5. Acceptance

The gate is complete when:

1. All 14 `mod {name}_const` modules in `sys_sizeof.rs` are
   written and their tests pass.
2. The corresponding nlink-production constants are referenced in
   each test (so any drift between nlink's value and the kernel
   reference fails the build).
3. `scripts/audit-uapi-constants.sh` exists, runs against a
   v6.13 kernel checkout, and reports zero diffs.
4. `.github/workflows/uapi-drift.yml` is wired and scheduled.

## 6. Out of scope

- **Automatic UAPI extraction at build time** — deferred to a
  hypothetical 0.21 plan. The build-time C-toolchain dependency
  is non-trivial for nlink's CI matrix.
- **Constants outside `crates/nlink/src/netlink/`** (the bins'
  constants are CLI-driven; not wire-format).
- **Kernel-side flag bitmasks** (`NLM_F_*`, etc.) — these are
  standard netlink core, defined once in `nlink::netlink::constants`
  and very stable. Worth covering but lower priority.

## 7. Cross-references

- Plan 213 (the 0.19 sizeof gate this extends) — durable narrative
  in `CHANGELOG.md ## [0.19.0]`.
- Plan 204 (the 0.19 nft-verdict fix that motivated the
  `nft_verdict` partial gate) — same.
- Plan 221 (the 0.19.1 hotfix this plan locks).
- [`AUDIT_WIRE_FORMAT.md`](../AUDIT_WIRE_FORMAT.md) W14 (the
  specific gap this plan closes).
