---
to: nlink maintainers
from: 0.19 second deep-audit
subject: Plan 213 — Wire-format build-time size assertions (CI gate)
status: queued for 0.19 — INFRA (prevents C1/C2/C3 class from recurring)
target version: 0.19.0
parent: [203](203-0.19-second-batch-master.md)
source: docs/AUDIT_REPORT_2026_05_31.md §"Recommended hardening"
created: 2026-05-31
---

# Plan 213 — Wire-format build-time size assertions

## 1. Why this plan exists

Plan 204 fixes C1 (NFT verdicts), C2 (XfrmUserpolicyInfo), C3
(XfrmUserpolicyId), C4 (Devlink mcast). Each shipped silently
wrong for many releases because no test pinned the byte-level
wire bytes to the kernel UAPI value.

This plan adds the infrastructure that **prevents the class from
recurring**:

1. Build-time `cc`-compiled C program that emits
   `sizeof(struct ...)` for every kernel UAPI struct nlink mirrors.
2. Generated constants written to an OUT_DIR Rust file.
3. Per-struct test that asserts `size_of::<MyStruct>() ==
   KERNEL_SIZEOF_MY_STRUCT`.
4. Per-constant test for verdict / hook enum values.

A breakage (e.g. a future maintainer adds a field but forgets the
explicit pad) fails `cargo test` at compile-checked test time
instead of running silently broken in production.

## 2. Architecture

### 2.1 New `nlink-sys-sizeof` build-time helper crate

`crates/nlink-sys-sizeof/build.rs` (new crate):

```rust
// build.rs
fn main() {
    let mut build = cc::Build::new();
    build.file("src/sizes.c");
    build.compile("nlink_sys_sizes");

    // Run the compiled program at build time to emit
    // generated.rs:
    let exe = std::env::var("OUT_DIR").unwrap();
    // (uses a Rust-side runner crate to invoke the binary, or
    //  embeds the C as a fn-returning-Vec<(String, usize)>
    //  via `bindgen`-style integration.)
}
```

`crates/nlink-sys-sizeof/src/sizes.c`:
```c
#include <linux/xfrm.h>
#include <linux/rtnetlink.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nf_tables.h>
#include <linux/devlink.h>
#include <linux/wireguard.h>
#include <stdio.h>

int main(void) {
    printf("XFRM_USERPOLICY_INFO=%zu\n", sizeof(struct xfrm_userpolicy_info));
    printf("XFRM_USERPOLICY_ID=%zu\n", sizeof(struct xfrm_userpolicy_id));
    printf("XFRM_USERSA_INFO=%zu\n", sizeof(struct xfrm_usersa_info));
    printf("XFRM_SELECTOR=%zu\n", sizeof(struct xfrm_selector));
    printf("XFRM_LIFETIME_CFG=%zu\n", sizeof(struct xfrm_lifetime_cfg));
    printf("XFRM_LIFETIME_CUR=%zu\n", sizeof(struct xfrm_lifetime_cur));
    printf("XFRM_USER_TMPL=%zu\n", sizeof(struct xfrm_user_tmpl));
    printf("IFINFOMSG=%zu\n", sizeof(struct ifinfomsg));
    printf("IFADDRMSG=%zu\n", sizeof(struct ifaddrmsg));
    printf("RTMSG=%zu\n", sizeof(struct rtmsg));
    printf("NDMSG=%zu\n", sizeof(struct ndmsg));
    printf("FIB_RULE_HDR=%zu\n", sizeof(struct fib_rule_hdr));
    printf("TCMSG=%zu\n", sizeof(struct tcmsg));
    printf("NFGENMSG=%zu\n", sizeof(struct nfgenmsg));
    printf("NLMSGHDR=%zu\n", sizeof(struct nlmsghdr));
    printf("NLMSGERR=%zu\n", sizeof(struct nlmsgerr));
    printf("NLATTR=%zu\n", sizeof(struct nlattr));
    // ... etc.
    return 0;
}
```

### 2.2 Alternative architecture (simpler, recommended)

Just hard-code the sizes in test constants, with documented
provenance:

```rust
// crates/nlink/src/netlink/sys_sizeof.rs (new)

//! Kernel UAPI struct sizes — verified against include/uapi/linux/*.h
//! on kernel 6.X. Each constant is paired with a regression test
//! asserting `std::mem::size_of::<NlinkType>() == KERNEL_SIZE`.
//!
//! Plan 213 — prevents Plan 204's C1/C2/C3 class from recurring.

pub mod xfrm {
    /// `sizeof(struct xfrm_userpolicy_info)` on a 64-bit build.
    /// Verified against `include/uapi/linux/xfrm.h` (kernel 6.X).
    pub const USERPOLICY_INFO: usize = 168;
    pub const USERPOLICY_ID: usize = 64;
    pub const USERSA_INFO: usize = 224;
    pub const SELECTOR: usize = 56;
    pub const LIFETIME_CFG: usize = 64;
    pub const LIFETIME_CUR: usize = 32;
    pub const USER_TMPL: usize = 64;
}

pub mod rtnetlink {
    /// `sizeof(struct ifinfomsg)`. Verified `include/uapi/linux/if_link.h`.
    pub const IFINFOMSG: usize = 16;
    pub const IFADDRMSG: usize = 8;
    pub const RTMSG: usize = 12;
    pub const NDMSG: usize = 12;
    pub const FIB_RULE_HDR: usize = 12;
    pub const TCMSG: usize = 20;
}

pub mod netfilter {
    pub const NFGENMSG: usize = 4;
}

pub mod netlink {
    pub const NLMSGHDR: usize = 16;
    pub const NLMSGERR: usize = 20;
    pub const NLATTR: usize = 4;
}

pub mod verdict {
    pub const NF_DROP: i32 = 0;
    pub const NF_ACCEPT: i32 = 1;
    pub const NFT_CONTINUE: i32 = -1;
    pub const NFT_BREAK: i32 = -2;
    pub const NFT_JUMP: i32 = -3;
    pub const NFT_GOTO: i32 = -4;
    pub const NFT_RETURN: i32 = -5;
}
```

**Recommended: Option 2 (hard-coded with provenance comments).**
Reason:
- Avoids a build-time C dependency that might fail on cross-
  compile or sandboxed CI environments.
- The kernel UAPI sizes are stable across kernel versions
  (struct ABI is treated as immutable per netlink-deprecated
  semantics + sizeof never decreases).
- One-time human verification + test-time runtime assertion is
  the simplest pattern.
- Drift surfaces immediately on a struct field change.

Option 1 (build-time `cc`) is documented as a follow-up if the
hard-coded approach proves too brittle in practice.

## 3. The regression tests

`crates/nlink/src/netlink/sys_sizeof.rs` test mod:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use std::mem::size_of;
    use crate::netlink::xfrm::{
        XfrmUserpolicyInfo, XfrmUserpolicyId, XfrmUsersaInfo,
        XfrmSelector, XfrmLifetimeCfg, XfrmLifetimeCur, XfrmUserTmpl,
    };
    use crate::netlink::types::*;
    use crate::netlink::nftables::*;

    macro_rules! assert_size_matches {
        ($t:ty, $expected:expr) => {
            assert_eq!(
                size_of::<$t>(),
                $expected,
                "size_of<{}> = {} but kernel expects {}; \
                 check struct layout against UAPI",
                stringify!($t),
                size_of::<$t>(),
                $expected,
            );
        };
    }

    #[test] fn xfrm_userpolicy_info_size_matches_kernel() {
        assert_size_matches!(XfrmUserpolicyInfo, xfrm::USERPOLICY_INFO);
    }
    #[test] fn xfrm_userpolicy_id_size_matches_kernel() {
        assert_size_matches!(XfrmUserpolicyId, xfrm::USERPOLICY_ID);
    }
    #[test] fn xfrm_usersa_info_size_matches_kernel() {
        assert_size_matches!(XfrmUsersaInfo, xfrm::USERSA_INFO);
    }
    #[test] fn xfrm_selector_size_matches_kernel() {
        assert_size_matches!(XfrmSelector, xfrm::SELECTOR);
    }
    #[test] fn xfrm_lifetime_cfg_size_matches_kernel() {
        assert_size_matches!(XfrmLifetimeCfg, xfrm::LIFETIME_CFG);
    }
    // ... and 15 more ...

    #[test] fn nft_verdict_constants_match_kernel() {
        assert_eq!(NF_DROP,      verdict::NF_DROP);
        assert_eq!(NF_ACCEPT,    verdict::NF_ACCEPT);
        assert_eq!(NFT_CONTINUE, verdict::NFT_CONTINUE);
        assert_eq!(NFT_BREAK,    verdict::NFT_BREAK);
        assert_eq!(NFT_JUMP,     verdict::NFT_JUMP);
        assert_eq!(NFT_GOTO,     verdict::NFT_GOTO);
        assert_eq!(NFT_RETURN,   verdict::NFT_RETURN);
    }

    // (Hook variants need Plan 211 to ship first.)
}
```

## 4. Phase — Bring up the gate

1. Create `crates/nlink/src/netlink/sys_sizeof.rs` with the
   pub-const tables + test mod.
2. Wire into `mod` declaration in `netlink/mod.rs`.
3. Verify all tests pass post-Plan 204 (i.e. C2 and C3 must be
   fixed first; this plan ratchets the win).
4. Update `CLAUDE.md ## Parser robustness` section adding a
   §"Wire-format byte-exact regression tests" sub-section
   pointing at this module.

## 5. CHANGELOG entry

```markdown
### Added

- **Wire-format byte-exact regression tests** (Plan 213). New
  `nlink::netlink::sys_sizeof` module hosts kernel UAPI struct
  sizes verified against the relevant `include/uapi/linux/*.h`.
  Test suite asserts `size_of::<NlinkType>() == KERNEL_SIZE`
  for every `#[repr(C)]` / `#[repr(C, packed)]` struct nlink
  emits. Catches the silent wire-format corruption class
  (Plan 204) at test time. Future maintainers adding a field
  to a kernel-facing struct see a test fail immediately if the
  layout drifts.
```

## 6. Acceptance criteria

- [ ] `sys_sizeof` module with provenance-commented constants
- [ ] ~25 size regression tests (one per UAPI struct nlink
      mirrors)
- [ ] 7 verdict constant tests
- [ ] CLAUDE.md updated with byte-exact section
- [ ] All tests pass on the post-Plan 204 codebase

## 7. Effort estimate

| Step | Time |
|---|---|
| Survey of UAPI structs nlink emits | 1 h |
| `sys_sizeof.rs` module with provenance | 1.5 h |
| 25 size regression tests | 1.5 h |
| 7 verdict tests | 30 min |
| CLAUDE.md update | 30 min |
| **Total** | **~5 h** |

## 8. Risks

- **Sizes may differ on 32-bit builds**. nlink targets only
  64-bit Linux but build correctness on 32-bit cross-compile
  may surface drift. Mitigation: gate sizes per
  `#[cfg(target_pointer_width = "64")]` initially; add 32-bit
  pointer-width tables later if cross-builds become a target.
- **Future kernel ABI changes** (rare but possible). When a
  field is added to a kernel struct, the size grows; nlink's
  struct must grow to match. Catching the drift is the whole
  point; the test then becomes a forcing function to update.

## 9. Cross-cutting artifacts

| Artifact | Action |
|---|---|
| `CHANGELOG.md` | 1 added entry |
| `crates/nlink/src/netlink/sys_sizeof.rs` (new) | module |
| `crates/nlink/src/netlink/mod.rs` | wire in |
| `CLAUDE.md` `## Parser robustness` | new sub-section |

End of plan.
