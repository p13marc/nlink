---
to: nlink maintainers
from: 0.20 cycle pre-work — deep audit findings W1-W7 (2026-06-04)
subject: 0.19.1 hotfix — XFRM constant + dispatch errors + nft CtKey constant
status: urgent — gates 0.19.1 ship; carved out of 0.20 cycle
target version: 0.19.1 (hotfix on master), then folded into 0.20
parent: [Plan 220 master](220-0.20-master-plan.md)
source: [AUDIT_WIRE_FORMAT.md](../AUDIT_WIRE_FORMAT.md) W1-W7 + [AUDIT_REPORT.md](../AUDIT_REPORT.md) §P0
created: 2026-06-04
---

# Plan 221 — XFRM constant + dispatch hotfix → 0.19.1

## 1. Why this plan exists

Six wire-format defects in `crates/nlink/src/netlink/xfrm.rs` make
the entire `update_*` / `flush_*` / `offload` surface broken since
the family shipped. The most severe is `Connection::<Xfrm>::flush_policy()`
**flushing all SAs instead of all SPs** — a user with a running
reconcile loop can silently drop their entire tunnel state. Plus
`Connection::<Xfrm>::flush_sa()` sends `XFRM_MSG_UPDPOLICY` with the
wrong body shape; on strict-checking kernels this is `EINVAL`, on
lenient kernels it's undefined.

This is too severe to bundle into the broader 0.20 cycle. The fix
is small (4 constants + 2 method bodies + ~80 lines of tests) and
needs to ship within days of the audit. Carved out as a hotfix
sequence:

1. Branch `0.19.1-hotfix` from `master` (which is at `9f6bf20` —
   the 0.19.0 ship commit).
2. Land Plan 221's surgical fixes + integration tests.
3. Cut `v0.19.1` to crates.io (nlink-macros not affected; only
   `nlink` republishes).
4. Merge master into `0.20` to pick up the hotfix into the cycle
   branch.

Cross-verified by the reviewer against
`https://raw.githubusercontent.com/torvalds/linux/v6.13/include/uapi/linux/xfrm.h`
at audit time. All 4 constant errors are confirmed off-by-1-to-4
from the upstream enum.

## 2. The constants table

Counting from the kernel UAPI enum bases:

| nlink symbol | nlink file:line | nlink has | Kernel UAPI v6.13 | What nlink emits | Symbol the value belongs to |
|---|---|---|---|---|---|
| `XFRM_MSG_FLUSHSA` | `xfrm.rs:51` | `25` | `28` | `XFRM_MSG_UPDPOLICY` | `XFRM_MSG_UPDPOLICY` |
| `XFRM_MSG_FLUSHPOLICY` | `xfrm.rs:52` | `28` | `29` | `XFRM_MSG_FLUSHSA` | **`XFRM_MSG_FLUSHSA`** — flushes SAs! |
| `XFRMA_SRCADDR` | `xfrm.rs:60` | `9` | `13` | `XFRMA_LTIME_VAL` | `XFRMA_LTIME_VAL` (lifetime struct) |
| `XFRMA_OFFLOAD_DEV` | `xfrm.rs:66` | `26` | `28` | `XFRMA_ADDRESS_FILTER` | `XFRMA_ADDRESS_FILTER` (24-byte struct) |

Plus the two dispatch errors:

| Method | nlink does | Kernel behaviour | Net effect |
|---|---|---|---|
| `update_sa` (xfrm.rs:1408) | sends `XFRM_MSG_NEWSA` + `NLM_F_CREATE \| NLM_F_REPLACE` | XFRM dispatches by `nlmsg_type` alone; ignores `NLM_F_REPLACE`; calls `xfrm_state_add` | EEXIST whenever target SA already exists — the method can never succeed at its job |
| `update_sp` (xfrm.rs:1498) | sends `XFRM_MSG_NEWPOLICY` + `NLM_F_REPLACE` | identical pattern; calls `xfrm_policy_insert` with `excl=1` | EEXIST whenever target SP already exists |

Plus one test that **encodes the bug**:

| Test | File:line | What it does |
|---|---|---|
| `assert_eq!(XFRMA_OFFLOAD_DEV, 26)` | `xfrm.rs:2139` | Locks the wrong constant. Must flip to `28` or the unit test will fail after the constant fix. |
| `xfrm_update_sa_uses_create_and_replace_flags_not_excl` | `xfrm.rs:2362` | Locks the wrong dispatch. Must be rewritten to assert `nlmsg_type == XFRM_MSG_UPDSA` and no `NLM_F_REPLACE`. |

And one nftables finding bundled into the hotfix:

| nlink symbol | nlink file:line | nlink has | Kernel UAPI v6.13 | What nlink emits |
|---|---|---|---|---|
| `CtKey::Expiration` | `nftables/types.rs:370` | `7` | `5` (NFT_CT_EXPIRATION) | `7` is `NFT_CT_L3PROTOCOL` |

The kernel side `nft_ct_keys` enum is verified at
`include/uapi/linux/netfilter/nf_tables.h` (v6.13):
`STATE=0, DIRECTION=1, STATUS=2, MARK=3, SECMARK=4, EXPIRATION=5,
HELPER=6, L3PROTOCOL=7, ...`.

## 3. The change

### 3.1 Constants

```rust
// crates/nlink/src/netlink/xfrm.rs:51-66 — corrected

// Was 25; correct value (kernel UAPI v6.13 enum position 12 from
// XFRM_MSG_BASE = 16). Plan 221 wire-format correction.
const XFRM_MSG_FLUSHSA: u16 = 28;
// Was 28; correct value 29 (enum position 13). 0.19's value silently
// matched FLUSHSA — flush_policy() was flushing all SAs.
const XFRM_MSG_FLUSHPOLICY: u16 = 29;
// Add the two we now need for the dispatch fix:
const XFRM_MSG_UPDSA: u16 = 26;
const XFRM_MSG_UPDPOLICY: u16 = 25;

// Was 9; correct value 13. 0.19's value matched XFRMA_LTIME_VAL.
const XFRMA_SRCADDR: u16 = 13;
// Was 26; correct value 28. 0.19's value matched XFRMA_ADDRESS_FILTER.
const XFRMA_OFFLOAD_DEV: u16 = 28;
```

### 3.2 `update_sa` / `update_sp` fix

```rust
// xfrm.rs:1407-1418 — corrected update_sa
#[tracing::instrument(level = "debug", skip_all, fields(method = "update_sa"))]
pub async fn update_sa(&self, sa: XfrmSaBuilder) -> Result<()> {
    // Was: MessageBuilder::new(XFRM_MSG_NEWSA, ... | NLM_F_REPLACE)
    // XFRM dispatches by nlmsg_type alone (see xfrm_user.c:917-921);
    // NLM_F_REPLACE is ignored, so NEWSA always calls xfrm_state_add
    // which returns EEXIST on every duplicate.
    let mut b = MessageBuilder::new(
        XFRM_MSG_UPDSA,
        NLM_F_REQUEST | NLM_F_ACK,
    );
    sa.encode(&mut b)?;
    self.request_with_ack(b.finish()).await
}

// xfrm.rs:1497-1508 — corrected update_sp
#[tracing::instrument(level = "debug", skip_all, fields(method = "update_sp"))]
pub async fn update_sp(&self, sp: XfrmSpBuilder) -> Result<()> {
    let mut b = MessageBuilder::new(
        XFRM_MSG_UPDPOLICY,
        NLM_F_REQUEST | NLM_F_ACK,
    );
    sp.encode(&mut b)?;
    self.request_with_ack(b.finish()).await
}
```

### 3.3 nftables CtKey

```rust
// crates/nlink/src/netlink/nftables/types.rs:363-371 — corrected

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CtKey {
    State = 0,
    Direction = 1,
    Status = 2,
    Mark = 3,
    Secmark = 4,         // NEW — was missing
    Expiration = 5,      // Was 7 (which was actually NFT_CT_L3PROTOCOL)
    Helper = 6,          // NEW — was missing
    L3Protocol = 7,      // NEW — was missing (and is what 'Expiration=7' was emitting!)
}
```

We deliberately add `Secmark`, `Helper`, `L3Protocol` as part of
the fix because they're well-known kernel constants and the public
enum is `#[non_exhaustive]` — adding variants is non-breaking.
This avoids leaving holes that downstream code might construct via
`transmute` (the `#[non_exhaustive]` doesn't prevent that). The
matching parser-side changes (if any) need to handle the new
discriminants too.

### 3.4 Bug-encoding test fixes

```rust
// xfrm.rs:2139 — flip the locked constant
#[test]
fn xfrm_offload_dev_attribute_id_matches_kernel_uapi() {
    // Was: assert_eq!(XFRMA_OFFLOAD_DEV, 26); — that locked the bug
    assert_eq!(XFRMA_OFFLOAD_DEV, 28);
    assert_eq!(XFRMA_SRCADDR, 13);
    assert_eq!(XFRM_MSG_FLUSHSA, 28);
    assert_eq!(XFRM_MSG_FLUSHPOLICY, 29);
    assert_eq!(XFRM_MSG_UPDSA, 26);
    assert_eq!(XFRM_MSG_UPDPOLICY, 25);
}

// xfrm.rs:2362 — rename + rewrite the dispatch-flags test
#[test]
fn xfrm_update_sa_uses_upds_a_message_type() {
    // Was: asserted CREATE+REPLACE flags. That asserted the BUG —
    // XFRM dispatches by type alone; NLM_F_REPLACE is no-op.
    let sa = build_test_sa();
    let frame = build_update_sa_frame(sa);
    let nlh = parse_nlmsghdr(&frame).unwrap();
    assert_eq!(nlh.nlmsg_type, XFRM_MSG_UPDSA);
    assert_eq!(
        nlh.nlmsg_flags & NLM_F_REPLACE, 0,
        "update_sa must NOT set NLM_F_REPLACE (XFRM ignores it; \
         dispatch is by nlmsg_type alone — Plan 221)"
    );
}
```

## 4. Integration tests (root + xfrm-module gated)

Six new tests under
`crates/nlink/tests/integration/xfrm_hotfix.rs`, all gated:

```rust
nlink::require_root!();
nlink::require_module!("xfrm_user");
// (Note: `xfrm_state` and `xfrm_policy` are NOT standalone modules — they're
// always-built core of `xfrm_state.c` / `xfrm_policy.c`; `xfrm_user` is the
// only loadable entry point that `/sys/module/<name>` will show. This
// matches the existing test pattern at `cycle_0_19_backfill.rs:461`.)
```

| Test | Pre-fix behaviour | Post-fix behaviour |
|---|---|---|
| `flush_sa_actually_removes_sas` | sent UPDPOLICY → EINVAL or kernel-confused | dump after flush returns empty |
| `flush_policy_does_not_touch_sas` | flushed all SAs! | dump_sa after flush_policy returns the original SAs intact |
| `update_sa_succeeds_when_existing` | always EEXIST | updates in place; replay_window etc. change applies |
| `update_sp_succeeds_when_existing` | always EEXIST | updates in place |
| `add_sa_with_offload_attaches_offload_dev` | wrote ADDRESS_FILTER under wrong attr | dump_sa shows the offload device + flags attached |
| `del_sa_with_srcaddr_uses_correct_filter` | wrote LTIME_VAL under wrong attr | kernel applies the src-addr filter (only matching SA deleted) |

The `flush_policy_does_not_touch_sas` test is the load-bearing one
— it would have **caught and failed against** the broken 0.19
behaviour from day one if it had existed.

### 4.1 CI modprobe entries

`.github/workflows/integration-tests.yml` already loads `xfrm_user`
at line 102 (alongside `xfrm4_tunnel` + `xfrm6_tunnel`). No
workflow edit needed for the XFRM tests — they'll run on every CI
push.

## 5. Migration impact

### 5.1 Behaviour changes

These are bug fixes, but the *observable behaviour* changes:

- **`flush_policy()`** previously deleted all SAs; now deletes all
  SPs (as documented). If a user wrote
  `conn.flush_policy().await?` thinking it would clean up before
  shutdown and discovered that SAs were getting flushed too, they
  may have been working around it with `flush_sa()` after — that
  second call previously failed (sent UPDPOLICY with wrong body);
  post-fix it actually flushes SAs. Net: their post-shutdown
  state is now correct.

- **`flush_sa()`** previously returned `Err(EINVAL)` on strict-
  checking kernels and was a no-op on lenient ones. Post-fix it
  actually flushes SAs. Users who relied on the no-op behaviour are
  in for a surprise.

- **`update_sa(builder)`** previously returned `EEXIST` when the
  target SA existed (i.e. always — that's the whole point of an
  update). Post-fix it succeeds.

### 5.2 CHANGELOG entry (0.19.1)

```markdown
## [0.19.1] - <date>

### Fixed

- **CRITICAL: `Connection::<Xfrm>::flush_policy()` was flushing all
  SAs instead of all SPs.** Root cause: `XFRM_MSG_FLUSHPOLICY` was
  hardcoded to `28`, which is the kernel UAPI value for
  `XFRM_MSG_FLUSHSA`. The same enum-counting error mis-coded three
  other constants, breaking `flush_sa()`, every `del_sa`/`get_sa`
  with a src-addr filter, and the Plan 153.1 XFRMA_OFFLOAD_DEV
  feature.
- **`Connection::<Xfrm>::update_sa()` and `update_sp()`** sent
  `NEWSA`/`NEWPOLICY` with `NLM_F_REPLACE`; the kernel dispatches by
  `nlmsg_type` alone and ignores `NLM_F_REPLACE`, so both methods
  returned `EEXIST` whenever the target already existed. Fixed to
  use `XFRM_MSG_UPDSA` / `XFRM_MSG_UPDPOLICY`.
- **`nftables::CtKey::Expiration` was hardcoded to `7` (kernel
  `NFT_CT_L3PROTOCOL`); correct value is `5`.** Every rule using
  `Expr::Ct { key: CtKey::Expiration }` was reading the L3
  protocol byte instead of the expiration time. Added
  `CtKey::Secmark`, `CtKey::Helper`, `CtKey::L3Protocol` for the
  variants the enum was silently shadowing.

The XFRM cluster justified a hotfix because `flush_policy()` was
the **opposite** of what it said it did — running it as a
shutdown step would silently destroy a user's entire SA table.

This is a hotfix; semver-bump is `0.19.0 → 0.19.1`. The 0.20 cycle
absorbs the fix on merge.
```

## 6. Test plan

Pre-merge gate (must all pass):
1. `cargo build --workspace --all-targets`
2. `cargo test -p nlink --lib`
3. `cargo clippy --workspace --all-targets --all-features -- --deny warnings`
4. `cargo machete`
5. `cargo +stable check --target s390x-unknown-linux-gnu -p nlink`
   (mid-cycle Plan 223 will wire this into CI; for the hotfix it's
   a manual one-time check that the constant fix doesn't introduce
   BE-only regressions).

CI gate (the standard 14 + integration-tests):
- The new `xfrm_hotfix.rs` integration tests run in the privileged
  CI job. `xfrm_user` modprobe is already in the workflow YAML
  (line 102) — no edit needed.

## 7. Cut sequence

The 0.19.1 hotfix train bundles **two plans into one PR**:
- Plan 221 (this plan — the surgical fix for the XFRM constants
  and dispatch + the CtKey constant)
- [Plan 222.1](222-sizeof-gate-constants-plan.md) §2.5 — the
  XFRM / nft CT phase of the new constant-value sizeof gate,
  which locks 221's fix so a future commit can't re-introduce
  the bug.

Cut sequence:

1. Branch `0.19.1-hotfix` from `master` head (currently `9f6bf20`).
2. Land Plan 221 + Plan 222.1 as two commits in the same PR
   (split for review readability — fix first, then gate). The
   sizeof gate's XFRM + nft CT modules MUST land in this PR; if
   they slip to 0.20, the bug class can re-recur during the
   intervening cycle.
3. PR `0.19.1-hotfix → master`, wait for 14 CI gates green.
4. Merge to master.
5. Bump workspace version `0.19.0 → 0.19.1` in `Cargo.toml`.
6. Promote CHANGELOG `[Unreleased]` → `[0.19.1] - <date>` (preserve
   the 0.20-cycle `[Unreleased]` entries currently in `master` from
   PRs #9, #10, and the follow-up commit — they ship in 0.20.0,
   not 0.19.1).

   Wait — that's a snag. The current `[Unreleased]` on `master`
   already has the PR #9 (WireGuard private-key readback) and PR #10
   (nftables canonical wire form) entries from today's merges. Those
   are 0.20 features. The 0.19.1 hotfix entry needs to slot in
   **between** `[Unreleased]` and `[0.19.0]`, with the WG + nftables
   entries staying in `[Unreleased]` for 0.20. Concretely:

   ```markdown
   ## [Unreleased]

   ### Fixed
   - [WG private-key readback]   ← 0.20
   - [nftables canonical wire]    ← 0.20

   ## [0.19.1] - <date>            ← NEW

   ### Fixed
   - [XFRM cluster]
   - [CtKey]

   ## [0.19.0] - 2026-05-31
   ...
   ```

7. `cargo publish -p nlink` (nlink-macros @ 0.19.0 unchanged; only
   nlink republishes — bump from 0.19.0 to 0.19.1).
8. Tag `v0.19.1` on master at the publish commit.
9. `gh release create v0.19.1 --notes-file <changelog 0.19.1
   section>`.
10. Merge `master → 0.20`. The cycle branch absorbs the hotfix.

## 8. Risks

- **The `XFRM_MSG_UPDSA` / `UPDPOLICY` constants weren't even
  defined**. We define them as part of this hotfix (lines 51-66 in
  the table above show 4 corrected + 2 added). If a downstream
  consumer was reaching into nlink's internal const namespace
  (unlikely; they're `const fn`-internal), they'd see new symbols
  appear — non-breaking.

- **`Secmark` / `Helper` / `L3Protocol` were not in the public
  `CtKey` enum**. Adding them in a hotfix is technically a
  feature, but they're `#[non_exhaustive]`-compatible additions
  and necessary because `Expiration = 7` was silently shadowing
  `L3Protocol`. Documenting them in the CHANGELOG calls this out.

- **The hotfix's 0.19.1 CHANGELOG vs 0.20's `[Unreleased]`
  ordering matters**. §7 step 6 walks through it. The cut script
  needs a small adjustment for this kind of interleaved hotfix —
  see `scripts/cut-release.sh` §3.2 (CHANGELOG promotion). The
  manual sequence in §7 documents what needs doing if the script
  doesn't handle it cleanly.

- **0.19.0 stays on crates.io broken**. We can't un-publish 0.19.0
  (crates.io policy). The 0.19.1 cargo metadata should `yanks`
  0.19.0 once 0.19.1 is up:
  `cargo yank --version 0.19.0 nlink`. Document the reason in the
  yank message: "yanked due to CRITICAL wire-format defect in XFRM
  (see CHANGELOG 0.19.1)". Same for 0.18.0 and earlier — every
  shipped version has the bug. Consider yanking the whole chain
  from the last unaffected release, with a single banner in the
  README pointing at 0.19.1 as the minimum-viable version. This
  call is the maintainer's; see §9 for the recommendation.

## 9. Recommendation on yanking older versions

The XFRM bug has been latent since at least 0.16.0 (the family
shipped well before that). Practical choices:

- **Yank none**: silent breakage for new users who pick up an old
  version. Worst.
- **Yank ≤0.19.0 with a banner**: forces new pulls to 0.19.1+.
  Existing lockfiles still work. Surfaces the bug to anyone
  reading crates.io. **Recommended.**
- **Yank ≤0.19.0 + open issues on every nlink-consuming repo I can
  find**: maximalist, probably noise unless the user wants to do
  outreach.

The 0.20 cut will continue forward as normal.

## 10. Acceptance

The hotfix lands when:

- All 6 integration tests pass on the privileged CI job.
- The dummy assertion `assert_eq!(XFRMA_OFFLOAD_DEV, 28)` and its
  siblings pass.
- `cargo publish -p nlink` succeeds for 0.19.1.
- `v0.19.1` tag is on master.
- `master → 0.20` merge picks up the hotfix.

Then Plan 222 onward unblocks.

## 11. Cross-references

- [`AUDIT_WIRE_FORMAT.md`](../AUDIT_WIRE_FORMAT.md) findings W1-W7
  (full kernel-source references).
- [`AUDIT_REPORT.md`](../AUDIT_REPORT.md) §P0 (action list).
- Kernel UAPI source: `https://raw.githubusercontent.com/torvalds/linux/v6.13/include/uapi/linux/xfrm.h`
  (XFRM enum) and the same path with `netfilter/nf_tables.h`
  (nft_ct_keys).
- [Plan 222](222-sizeof-gate-constants-plan.md) — the durable fix
  (sizeof CI gate extended to constant values) that prevents this
  class from recurring. Plan 221 ships the surgical fix; Plan 222
  ships the systemic prevention.
