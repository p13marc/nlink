---
to: nlink maintainers
from: 0.19 second deep-audit
subject: Plan 204 — wire-format CRITICAL fixes (C1, C2, C3, C4)
status: queued for 0.19 — CRITICAL (silent wire corruption on real kernels)
target version: 0.19.0
parent: [203](203-0.19-second-batch-master.md)
source: docs/AUDIT_REPORT_2026_05_31.md §C1–C4
created: 2026-05-31
---

# Plan 204 — Four wire-format CRITICAL corrections

## 1. Why this plan exists

The second audit found four byte-level wire-format bugs that ship
today silently broken on real kernels:

1. **C1** — `NFT_JUMP` and `NFT_GOTO` constants emit the wrong
   kernel verdict codes. `Verdict::Jump(chain)` writes `-2`
   (=`NFT_BREAK`) and the kernel terminates rule evaluation instead
   of jumping.
2. **C2** — `XfrmUserpolicyInfo` body is 4 bytes shorter than the
   kernel struct. Every `add_sp` call sends an undersized message;
   kernel returns EINVAL. The `add_sp` path is entirely
   non-functional.
3. **C3** — `XfrmUserpolicyId` body is 4 bytes longer than the
   kernel struct. `del_sp`/`get_sp` work on lenient kernels by
   accident; break on strict-checking kernels (which nlink ships
   support for via Plan 155.2).
4. **C4** — `Connection<Devlink>::subscribe()` tries to bind to
   multicast group `"devlink"`. Kernel registers the group as
   `"config"`. Every devlink event subscriber fails.

All four bugs would have been caught by a single byte-level
regression test against the kernel UAPI header. Plan 213 introduces
the build-time sizeof CI gate that prevents the class from
recurring.

## 2. The changes

### 2.1 C1 — Correct NFT verdict constants

**File:** `crates/nlink/src/netlink/nftables/mod.rs:285-293`

Replace:
```rust
// Verdict codes
pub const NF_DROP: i32 = 0;
pub const NF_ACCEPT: i32 = 1;
pub const NFT_CONTINUE: i32 = -1;
pub const NFT_RETURN: i32 = -5;
pub const NFT_JUMP: i32 = -2;
pub const NFT_GOTO: i32 = -3;
```

With (matching `include/uapi/linux/netfilter/nf_tables.h` enum
`nft_verdicts`):

```rust
// Verdict codes — verified against kernel UAPI nft_verdicts enum.
// See plans/204-wire-format-critical-fixes.md for repro.
pub const NF_DROP: i32 = 0;
pub const NF_ACCEPT: i32 = 1;
pub const NFT_CONTINUE: i32 = -1;
pub const NFT_BREAK: i32 = -2;    // NEW — was missing entirely
pub const NFT_JUMP: i32 = -3;     // WAS -2
pub const NFT_GOTO: i32 = -4;     // WAS -3
pub const NFT_RETURN: i32 = -5;
```

Audit usage sites:
```bash
rg 'NFT_JUMP|NFT_GOTO|NFT_BREAK' crates/nlink/src/
```

Verify each site uses the constant (not the literal value). If any
hardcodes `-2`/`-3`/`-4`, replace with the constant.

### 2.2 C2 — Add trailing pad to `XfrmUserpolicyInfo`

**File:** `crates/nlink/src/netlink/xfrm.rs:315-336`

Replace:
```rust
#[repr(C, packed)]
#[derive(Debug, Clone, Copy, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct XfrmUserpolicyInfo {
    pub sel: XfrmSelector,
    pub lft: XfrmLifetimeCfg,
    pub curlft: XfrmLifetimeCur,
    pub priority: u32,
    pub index: u32,
    pub dir: u8,
    pub action: u8,
    pub flags: u8,
    pub share: u8,
}
```

With:
```rust
#[repr(C, packed)]
#[derive(Debug, Clone, Copy, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct XfrmUserpolicyInfo {
    pub sel: XfrmSelector,
    pub lft: XfrmLifetimeCfg,
    pub curlft: XfrmLifetimeCur,
    pub priority: u32,
    pub index: u32,
    pub dir: u8,
    pub action: u8,
    pub flags: u8,
    pub share: u8,
    /// Padding to natural u64 alignment — kernel struct uses
    /// natural alignment (no __attribute__((packed))) and pads to
    /// the next 8-byte boundary after the four trailing __u8
    /// fields. Without this nlink emits a 164-byte body and the
    /// kernel rejects `add_sp` with EINVAL.
    pub _pad: [u8; 4],
}
```

Now `size_of::<XfrmUserpolicyInfo>() == 168` matches kernel
`sizeof(struct xfrm_userpolicy_info)`.

### 2.3 C3 — Trim trailing pad on `XfrmUserpolicyId`

**File:** `crates/nlink/src/netlink/xfrm.rs:173-180`

Replace:
```rust
#[repr(C, packed)]
pub struct XfrmUserpolicyId {
    pub sel: XfrmSelector,
    pub index: u32,
    pub dir: u8,
    pub _pad: [u8; 7],
}
```

With:
```rust
#[repr(C, packed)]
pub struct XfrmUserpolicyId {
    pub sel: XfrmSelector,
    pub index: u32,
    pub dir: u8,
    /// Padding to natural u32 alignment — kernel struct
    /// has no explicit pad; natural alignment after the
    /// single `dir: u8` rounds to next __u32 boundary. The
    /// previous `[u8; 7]` produced a 68-byte body that the
    /// kernel parsed as a malformed trailing nlattr; strict-
    /// checking kernels (≥5.0 with NETLINK_GET_STRICT_CHK,
    /// which nlink can enable via Plan 155.2) reject it.
    pub _pad: [u8; 3],
}
```

Now `size_of::<XfrmUserpolicyId>() == 64` matches kernel
`sizeof(struct xfrm_userpolicy_id)`.

### 2.4 C4 — Devlink multicast group name

**File:** `crates/nlink/src/netlink/genl/devlink/mod.rs:154`

Replace:
```rust
pub const DEVLINK_MCGRP_NAME: &str = "devlink";
```

With:
```rust
/// Devlink multicast group name — matches the kernel's
/// `DEVLINK_GENL_MCGRP_CONFIG_NAME` (literally `"config"`) from
/// `include/uapi/linux/devlink.h`. The previous value `"devlink"`
/// did not exist in the kernel's CTRL_ATTR_MCAST_GROUPS table, so
/// `Connection::<Devlink>::subscribe()` returned `FamilyNotFound`
/// on every kernel.
pub const DEVLINK_MCGRP_NAME: &str = "config";
```

Audit `subscribe_group` / `subscribe` call sites in
`genl/devlink/connection.rs` to confirm they read
`DEVLINK_MCGRP_NAME` and don't hardcode a wrong literal anywhere.

## 3. Tests (per-finding)

### 3.1 C1 — `nft_verdict_codes_match_kernel_uapi`

**File:** new `crates/nlink/src/netlink/nftables/mod.rs` test
module (or extend an existing one).

```rust
#[cfg(test)]
mod verdict_const_tests {
    use super::*;

    /// Verified against `include/uapi/linux/netfilter/nf_tables.h`
    /// enum nft_verdicts (kernel 6.X).
    #[test]
    fn nft_verdict_constants_match_kernel_uapi() {
        assert_eq!(NF_DROP,    0);
        assert_eq!(NF_ACCEPT,  1);
        assert_eq!(NFT_CONTINUE, -1);
        assert_eq!(NFT_BREAK,    -2);
        assert_eq!(NFT_JUMP,     -3);
        assert_eq!(NFT_GOTO,     -4);
        assert_eq!(NFT_RETURN,   -5);
    }

    #[test]
    fn verdict_jump_emits_nft_jump_value() {
        let mut builder = MessageBuilder::new(0, 0);
        write_verdict(&mut builder, &Verdict::Jump("subchain".into()));
        let bytes = builder.as_bytes();
        // Walk to the NFTA_VERDICT_CODE attribute and verify
        // the i32 payload equals NFT_JUMP (-3, network byte
        // order in the nftables wire format).
        let code = find_attr_be_i32(bytes, NFTA_VERDICT_CODE).unwrap();
        assert_eq!(code, NFT_JUMP);
    }

    #[test]
    fn verdict_goto_emits_nft_goto_value() {
        // Same shape — assert NFT_GOTO (-4) in the bytes.
    }
}
```

### 3.2 C2 / C3 — `xfrm_struct_sizes_match_kernel_uapi`

**File:** new `crates/nlink/src/netlink/xfrm.rs` test module
extension.

```rust
#[cfg(test)]
mod wire_format_size_tests {
    use super::*;
    use std::mem::size_of;

    /// Verified against `include/uapi/linux/xfrm.h` —
    /// `struct xfrm_userpolicy_info` is 168 bytes on a 64-bit
    /// build with natural alignment. nlink uses
    /// `#[repr(C, packed)]` so we must include explicit trailing
    /// pad to hit 168.
    #[test]
    fn xfrm_userpolicy_info_is_168_bytes() {
        assert_eq!(size_of::<XfrmUserpolicyInfo>(), 168);
    }

    /// Verified against `include/uapi/linux/xfrm.h` —
    /// `struct xfrm_userpolicy_id` is 64 bytes (selector + u32
    /// index + u8 dir + 3 pad to u32 align).
    #[test]
    fn xfrm_userpolicy_id_is_64_bytes() {
        assert_eq!(size_of::<XfrmUserpolicyId>(), 64);
    }

    /// Sanity: selector itself is 56 bytes.
    #[test]
    fn xfrm_selector_is_56_bytes() {
        assert_eq!(size_of::<XfrmSelector>(), 56);
    }

    /// XfrmUsersaInfo was correct pre-Plan 204 (already had
    /// _pad[7]); pin it to prevent regression.
    #[test]
    fn xfrm_usersa_info_is_224_bytes() {
        assert_eq!(size_of::<XfrmUsersaInfo>(), 224);
    }
}
```

### 3.3 C4 — `devlink_mcast_group_name_matches_kernel`

**File:** new `crates/nlink/src/netlink/genl/devlink/mod.rs` test
extension.

```rust
#[cfg(test)]
mod mcast_group_tests {
    use super::*;

    #[test]
    fn devlink_mcast_group_name_matches_kernel_uapi() {
        // include/uapi/linux/devlink.h:
        //   #define DEVLINK_GENL_MCGRP_CONFIG_NAME "config"
        assert_eq!(DEVLINK_MCGRP_NAME, "config");
    }
}
```

### 3.4 Integration tests (root-gated)

**File:** extend `crates/nlink/tests/integration/cycle_0_19_backfill.rs`.

```rust
#[tokio::test]
async fn xfrm_add_sp_round_trips_after_pad_fix() -> nlink::Result<()> {
    nlink::require_root!();
    nlink::require_module!("xfrm_user");

    let ns = nlink::lab::LabNamespace::new("xfrm-policy-rt")?;
    let conn = ns.connection::<Xfrm>().await?;

    // Construct a minimal valid SP.
    let sp = XfrmUserpolicyInfoBuilder::new()
        .selector(/* ... */)
        .direction(XfrmDir::Out)
        .build();

    conn.add_sp(&sp).await?;     // Pre-Plan 204: EINVAL
    let dump = conn.get_security_policies().await?;
    assert_eq!(dump.len(), 1);

    conn.del_sp(/* ... */).await?;
    Ok(())
}

#[tokio::test]
async fn devlink_subscribe_resolves_config_mcast_group() -> nlink::Result<()> {
    nlink::require_root!();
    nlink::require_module!("devlink");

    let mut conn = nlink::netlink::Connection::<Devlink>::new_async().await?;
    // Pre-Plan 204: `FamilyNotFound { name: "devlink::devlink" }`.
    // Post-fix: this resolves and the subscription succeeds.
    conn.subscribe()?;

    // No assert beyond the subscribe succeeding — that's the
    // bug we're closing.
    Ok(())
}

#[tokio::test]
async fn nft_verdict_jump_actually_jumps_in_kernel() -> nlink::Result<()> {
    nlink::require_root!();

    // Build a rule that uses Verdict::Jump to a subchain that
    // sets a counter; check that the counter increments when
    // the rule fires. Pre-Plan 204 the kernel sees NFT_BREAK
    // and never enters the subchain → counter stays at 0.
    // Post-fix → counter increments.
}
```

## 4. CHANGELOG entry

```markdown
### Breaking changes

- **nftables verdict constants `NFT_JUMP`/`NFT_GOTO` change to
  match the kernel UAPI**. Pre-0.19 nlink shipped `NFT_JUMP = -2`
  and `NFT_GOTO = -3`, but the kernel's
  `enum nft_verdicts` defines them as `-3` and `-4` respectively.
  Code building `Verdict::Jump(chain)` previously wrote `-2` on
  the wire, which the kernel interpreted as `NFT_BREAK`
  (terminate rule evaluation), silently breaking every subroutine
  rule. The new `NFT_BREAK = -2` constant is added for
  completeness. Source-level no-op for users of `Verdict::Jump`
  / `Verdict::Goto`; runtime behavior changes from silently
  broken to kernel-correct. Verified against kernel
  `include/uapi/linux/netfilter/nf_tables.h`.

### Fixed

- **`XfrmUserpolicyInfo` body was 4 bytes shorter than the
  kernel struct — `add_sp` rejected with EINVAL on every kernel
  version**. The kernel's `struct xfrm_userpolicy_info` uses
  natural alignment (not packed), padding the trailing four
  `__u8` fields (`dir, action, flags, share`) to the next u64
  boundary for total size 168. nlink used `#[repr(C, packed)]`
  with no trailing pad, emitting 164 bytes. `kernel
  xfrm_add_policy()` calls `nlmsg_parse_deprecated(nlh,
  sizeof(*p), ...)` and rejects messages smaller than 168.
  The `add_sp` API has been silently non-functional on every
  kernel version since the XFRM family shipped. Fix: add
  `_pad: [u8; 4]` after `share`. New regression test
  `xfrm_userpolicy_info_is_168_bytes` plus root-gated
  integration test `xfrm_add_sp_round_trips_after_pad_fix`.

- **`XfrmUserpolicyId` body was 4 bytes longer than the kernel
  struct — `del_sp`/`get_sp` broke on strict-checking
  kernels**. nlink's `_pad: [u8; 7]` produced a 68-byte body;
  the kernel struct is 64 bytes (selector + u32 index + u8 dir
  + 3 pad). On lenient kernels the extra 4 bytes were parsed
  as a malformed trailing nlattr and silently skipped. On
  strict-checking kernels (≥5.0 with NETLINK_GET_STRICT_CHK,
  enableable via Plan 155.2's `enable_strict_checking`), the
  kernel rejected with EINVAL. Fix: trim `_pad` to `[u8; 3]`.

- **Devlink multicast subscription was broken — group name
  mismatch**. nlink looked up `"devlink"` in the kernel's
  CTRL_ATTR_MCAST_GROUPS table. The kernel registers the
  group as `"config"` (per
  `DEVLINK_GENL_MCGRP_CONFIG_NAME` in
  `include/uapi/linux/devlink.h`). Every `Connection::<Devlink>::subscribe()`
  call returned `Error::FamilyNotFound { name:
  "devlink::devlink" }`. Fix: change the constant to `"config"`.
  Plus a regression test
  `devlink_mcast_group_name_matches_kernel_uapi`.
```

## 5. Acceptance criteria

- [ ] `NFT_BREAK`, `NFT_JUMP`, `NFT_GOTO` constants updated
- [ ] No code site hardcodes the verdict literal values
- [ ] `XfrmUserpolicyInfo` is exactly 168 bytes
- [ ] `XfrmUserpolicyId` is exactly 64 bytes
- [ ] `DEVLINK_MCGRP_NAME == "config"`
- [ ] 4 unit tests pass: verdict constants, two XFRM sizes,
      devlink mcast group name
- [ ] 3 root-gated integration tests pass: add_sp round-trip,
      devlink subscribe, nft jump-actually-jumps
- [ ] CHANGELOG `### Breaking changes` entry for NFT verdicts
- [ ] CHANGELOG `### Fixed` entries for C2, C3, C4
- [ ] migration guide `0.18.0-to-0.19.0.md` includes one-paragraph
      note per breaking change

## 6. Effort estimate

| Step | Time |
|---|---|
| C1 verdict constant edit + usage audit | 30 min |
| C2 XfrmUserpolicyInfo pad addition | 15 min |
| C3 XfrmUserpolicyId pad trim | 15 min |
| C4 Devlink mcast group rename | 10 min |
| 4 unit tests | 30 min |
| 3 root-gated integration tests | 60 min |
| CHANGELOG + migration guide | 30 min |
| Verification (cargo test/clippy/machete) | 10 min |
| **Total** | **~3 h** |

## 7. Risks

- **C1 verdict constants**: changing `NFT_JUMP`/`NFT_GOTO` is a
  *behavior* break for anyone who was depending on the wrong
  values (e.g. a test that asserts `NFT_JUMP == -2`). Acceptable
  per the user's "break backward compat" authorization. Source-
  level callers using `Verdict::Jump`/`Verdict::Goto` enums see
  no break; only callers using the raw constants do.

- **C2 `add_sp` going from "rejected with EINVAL" to
  "succeeds"** may surface latent issues in downstream code that
  was working around the breakage. Document in migration guide
  that `add_sp` now actually works.

- **C4 devlink subscribe going from "always errors" to
  "succeeds"** may flood subscribers with events they weren't
  expecting. Document; the `is_dump_interrupted` retry pattern
  recipe is a good reference.

## 8. Cross-cutting artifacts

| Artifact | Action |
|---|---|
| `CHANGELOG.md ## [Unreleased]` | add 1 breaking-change + 3 fixed entries |
| `docs/migration_guide/0.18.0-to-0.19.0.md` | append §"Plan 204" with per-finding migration paragraphs |
| `crates/nlink/tests/integration/cycle_0_19_backfill.rs` | add 3 root-gated tests |
| `crates/nlink/src/netlink/nftables/mod.rs` | constant changes + verdict const test mod |
| `crates/nlink/src/netlink/xfrm.rs` | two struct pad fixes + size test mod |
| `crates/nlink/src/netlink/genl/devlink/mod.rs` | constant change + mcast name test |

End of plan.
