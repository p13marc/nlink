# Review of PR #9 and PR #10 (nlink)

Independent review, 2026-06-03. Both PRs from `avionix-g` against `master`
(post-0.19.0 ship). Reviewer ran the diffs against the current tree,
cross-checked every kernel-side claim against upstream Linux source, and
adversarially looked for failure modes the author's tests don't cover.

## Executive summary

| PR | Title | Verdict | Why |
|---|---|---|---|
| **#9** | `fix(wireguard): read private key back from the kernel on get_device` | **MERGE** (optional doc tightening) | Real bug, surgical fix, kernel-claims VERIFIED, tests cover the contract. |
| **#10** | `fix(nftables): correct declarative round-trip for address, masked, and NAT rules` | **REQUEST CHANGES** (two small asks) | Real bugs (plural), kernel-claims VERIFIED, but introduces a new wire-format regression for the empty-NAT case **and** a one-time phantom-diff for existing rulesets that needs CHANGELOG mention. |

Headline ask for the author across both PRs: nothing structural. Wire
encoding, refactor shape, test coverage, and CHANGELOG entries are all
solid. Specific asks called out below.

---

## PR #9 — WireGuard `get_device` private-key readback

### What it claims to fix

`Connection::<Wireguard>::get_device*` returned `WgDevice { private_key:
None, .. }` even for privileged callers on a keyed device. The
`parse_device_attrs` match (`crates/nlink/src/netlink/genl/wireguard/connection.rs`
on master, lines 372–402) had no `WgDeviceAttr::PrivateKey` arm — the
attribute (id `3`) was silently consumed by the catch-all `_ => {}`.
The existing rustdoc said *"only set, never returned by kernel for
security"* (`types.rs:18`); that assertion was wrong.

### Kernel-side claim verification

**Claim:** `WG_CMD_GET_DEVICE` returns `WGDEVICE_A_PRIVATE_KEY` to any
caller with `CAP_NET_ADMIN` in the device's netns, omits to anyone else.

**VERIFIED** with two-source corroboration:

1. `Documentation/netlink/specs/wireguard.yaml` declares
   `flags: [uns-admin-perm]` on `get-device` — compiles to
   `GENL_UNS_ADMIN_PERM`, gating the entire op behind
   `netlink_ns_capable(skb, net->user_ns, CAP_NET_ADMIN)`. Unprivileged
   callers get `EPERM` on the whole command — not a partial reply.
2. `drivers/net/wireguard/netlink.c::wg_get_device_dumpit` emits
   `WGDEVICE_A_PRIVATE_KEY` unconditionally when
   `wg->static_identity.has_identity` is true. No second cap-check in
   the handler.

Cross-reference: the `wireguard-tools` `wg showconf` reads the private
key via this exact attribute (see
[`src/ipc-linux.h:424`](https://github.com/WireGuard/wireguard-tools/blob/a998407747005ea7e4e0258d96f105c97241e1d3/src/ipc-linux.h#L424)
linked in the PR body).

**Doc nit:** the PR's new `config.rs` rustdoc says *"the kernel returns
... to a caller holding CAP_NET_ADMIN ... and omits it otherwise — so
`WgDevice::private_key` is `None` for unprivileged callers."* In
practice an unprivileged caller hits the EPERM gate on the whole
command — they'd see `Error::Kernel { errno: EPERM }`, never
`Ok(WgDevice { private_key: None })`. The `None`-for-unprivileged
shape doesn't surface through nlink's API at all. Worth tightening to
*"is gated behind CAP_NET_ADMIN in the device's netns; unprivileged
get_device calls fail with EPERM outright."* Not blocking.

### Parsing logic

Two helpers added:

- `parse_device_attr_scalar` — free function, takes `&AttrItem` plus
  `&mut WgDevice` accumulator. Clean split: no `&self`, no duplicated
  state, directly unit-testable without a live socket. **OK.**
- `parse_key(payload: &[u8]) -> Option<[u8; 32]>` — reads first 32
  bytes, normalizes all-zeros sentinel to `None`. **OK.**

**Robustness audit** (per `CLAUDE.md ## Parser robustness`):

- Rule 1 (accept-larger-than-expected on fixed structs): VERIFIED.
  `payload.len() >= WG_KEY_LEN` guard + copy first 32; ignores trailing
  bytes. A future kernel that ships a 40-byte key field would not panic.
- Rule 2 (header-driven loops): N/A.
- Rule 3 (recoverable per-message): N/A (not an event parser).

**X25519 clamping:** VERIFIED. `drivers/net/wireguard/noise.c::wg_noise_set_static_identity_private_key`
calls `curve25519_clamp_secret()` on store — byte 0 `&= 248`, byte 31
`= (byte31 & 127) | 64`. The kernel persists and returns the *clamped*
key. The integration test
(`tests/integration/cycle_0_19_backfill.rs:1031–1038`) applies the
exact same two operations to the expected buffer before comparing.
Correct.

### Tests

Unit tests (`connection.rs:711–765`):
- present-key round-trip
- all-zeros → `None` (pins normalization independently of kernel)
- public-key symmetry
- short-payload length guard (proves `>= WG_KEY_LEN` holds)
- absent-attribute path (mirrors unprivileged wire shape)

Integration test `wg_private_key_readback_round_trips`
(`cycle_0_19_backfill.rs:996–1045`):
- `require_root!()` + `require_module!("wireguard")` gated
- creates wg0 in fresh netns, sets `[0xCD; 32]` deliberately
  non-clamped, reads back, asserts equality against the manually
  re-clamped expected key
- pre-fix would fail with `Some(expected) != None`

CI workflow change: adds `wireguard` to the modprobed-modules list so
the gate actually runs in the privileged-CI job instead of skipping.

**Gap (not blocking):** no `parse_private_key_oversize_payload` test
(kernel returns ≥33 bytes — future-grow scenario). The length guard
handles it; a test would lock it in.

### Risk

- **Breaking semantic change on `Option<[u8; 32]>`:** technically yes —
  `WgDevice::private_key` flips from "always None" to "Some on privileged
  reads". Downstream code that wrote `assert!(dev.private_key.is_none())`
  would now fire. The type didn't change; the field name didn't change.
  Per `CLAUDE.md ## Active work` (0.20 cycle is open in `[Unreleased]`),
  this is the right semantic to flip at a minor-version boundary. Worth
  a note in the 0.19→0.20 migration guide when written.
- **All-zeros-to-None masking a real bug:** marginal. A real X25519
  secret that's all zeros is computationally impossible. After clamping,
  an all-zeros *input* becomes `[0x00, 0, ..., 0, 0x40]` (bit 6 of
  byte 31 set), so the stored form isn't all-zeros anyway. Safe.
- **Non-clamped key from alternative backends:** UNVERIFIED but low
  risk. wireguard-go uses TUN, never the kernel netlink path — the
  test wouldn't apply. The wireguard-linux-compat module that predates
  upstreaming used the same `curve25519_clamp_secret`. If a future
  kernel ever ships "raw, unclamped storage", the test fails loudly,
  which is exactly what we want.
- **Concurrency interaction:** zero. The fix is pure parse-path inside
  an already-mutex'd `get_device_by_name`. No new `Connection` field,
  no new lock.

### Recommendation: MERGE

Optional follow-up: tighten the *"omits it otherwise"* wording in
`config.rs` rustdoc + CHANGELOG to mention the EPERM gate explicitly.

---

## PR #10 — nftables canonical wire form for address / bitwise / NAT

### What it claims to fix

Three classes of expressions in `NftablesConfig::diff` lowered to fewer
attributes than the kernel keeps. The kernel echoes the fuller form on
dump, so the second `cfg.diff(&nft)` after a successful `apply` was
always non-empty:

1. **Address matchers** (`match_{s,d}addr_{v4,v6}` + `_not`) emitted a
   bare `Payload(Network)` load with no L3-protocol guard.
2. **`bitwise`** (every prefix-masked match like `/24`, `/64`) omitted
   `NFTA_BITWISE_OP`.
3. **`nat`** (every `snat`/`dnat`) omitted `NFTA_NAT_REG_{ADDR,PROTO}_MAX`
   and `NFTA_NAT_FLAGS`.

The bitwise/nat gap had been **latent since the original nftables
support (0.10.0)** because the NAT round-trip tests gate on `nft_nat`
and CI never modprobed it. The CHANGELOG calls this out.

### Kernel-side claim verification

#### Claim 1 — `nft` emits `meta nfproto == ipX` before address matchers

**VERIFIED with one refinement:**

- The nftables wiki [Ruleset debug/VM code analysis](https://wiki.nftables.org/wiki-nftables/index.php/Ruleset_debug/VM_code_analysis)
  confirms a bare `ip daddr 1.2.3.4` lowers to `[ meta load nfproto =>
  reg 1 ][ cmp eq reg 1 0x00000002 ] [ payload load 4b @ network +16 =>
  reg 1 ] [ cmp eq reg 1 ... ]`.
- Kernel `net/netfilter/nft_payload.c::nft_payload_eval` does **not**
  version-check before reading `NFT_PAYLOAD_NETWORK_HEADER`. It just
  computes `offset = skb_network_offset(skb) + pkt->nhoff` and
  `skb_copy_bits(...)`. So a bare `payload @ network +12 ..4` against an
  IPv6 packet really would read into the v6 traffic class/flowlabel and
  silently misfire. The guard is **load-bearing semantics**, not just
  cosmetics.
- **Refinement:** `nft` only emits the guard in **mixed-L3 families**
  (`inet`, `bridge`, `netdev`) via `src/payload.c::payload_gen_special_dependency`,
  which keys on `ctx->pctx.family`. In single-family `ip` / `ip6` chains,
  `nft` skips it (chain family unambiguously determines L3). This PR
  emits the guard **unconditionally** at
  `crates/nlink/src/netlink/nftables/types.rs:880-908` because nlink's
  `Rule` builder doesn't know its owning chain's family. That's
  defensible — the kernel accepts the redundant `meta nfproto == ipv6`
  in an `ip6` chain (always-true cmp, stored verbatim, echoed on dump)
  so round-trip stays empty. Technically a small per-packet cost in
  single-family chains (1 register load + 1 cmp); negligible in
  practice; unmeasured by the PR (acceptable).

#### Claim 2 — `NFTA_BITWISE_OP` required for round-trip

**VERIFIED.**

- `nft_bitwise_init`: `if (tb[NFTA_BITWISE_OP]) priv->op = ntohl(...);
  else priv->op = NFT_BITWISE_MASK_XOR;` — omission is *accepted* (no
  `EINVAL`), kernel defaults to MASK_XOR (= `NFT_BITWISE_BOOL`, value
  `0`).
- `nft_bitwise_dump`: `nla_put_be32(skb, NFTA_BITWISE_OP, htonl(priv->op))`
  emitted unconditionally before the per-op dispatcher. So even when
  nlink omits OP, the kernel echoes it on dump → round-trip mismatch.
- UAPI constants `NFTA_BITWISE_OP = 6` and `NFT_BITWISE_BOOL = 0` match
  the PR's additions at `crates/nlink/src/netlink/nftables/mod.rs:227-229`.

The fix in `expr.rs:225` (`builder.append_attr_u32_be(NFTA_BITWISE_OP,
NFT_BITWISE_BOOL)`) is correct.

#### Claim 3 — `NFTA_NAT_REG_*_MAX` + `NFTA_NAT_FLAGS` required

**VERIFIED with one caveat that's a real bug.**

- `nft_nat_init`: when MAX absent and MIN set, kernel sets
  `sreg_addr_max = sreg_addr_min`. `NFTA_NAT_FLAGS` is optional and
  ORed into `priv->flags`.
- `nft_nat_dump`: MAX is emitted **whenever MIN is set**, regardless
  of whether init received MAX. So MIN-only on the wire forces a
  phantom diff on dump-back. Fix is correct.
- **CAVEAT — real new bug:** `nft_nat_dump` emits FLAGS only when
  non-zero: `if (priv->flags != 0) { nla_put_be32(skb, NFTA_NAT_FLAGS,
  ...) }`. The PR emits `NFTA_NAT_FLAGS` **unconditionally** at
  `crates/nlink/src/netlink/nftables/expr.rs:177`:

  ```rust
  let mut flags = 0u32;
  if nat.addr.reg_in_use() { ... flags |= NF_NAT_RANGE_MAP_IPS; }
  if nat.port.is_some()    { ... flags |= NF_NAT_RANGE_PROTO_SPECIFIED; }
  builder.append_attr_u32_be(NFTA_NAT_FLAGS, flags);  // <- always emits
  ```

  When **both** `addr.reg_in_use() == false` and `port.is_none()`, the
  PR emits `NFTA_NAT_FLAGS = 0`. The kernel stores 0 but doesn't echo
  it back — **re-introducing a phantom diff for the empty-NAT case**.

  Reachable via `Expr::Nat(NatExpr::snat(family))` /
  `Expr::Nat(NatExpr::dnat(family))` without `.addr(...)` or `.port(...)`.
  The public happy path (`Rule::snat_v{4,6}`, `Rule::dnat_v{4,6}`) is
  safe because `push_nat` has
  `debug_assert!(addr.reg_in_use(), ...)` at `types.rs:1041` — but
  `NatExpr` is publicly constructible, and the assert is `debug_` so
  release builds wouldn't catch it.

  **Fix:** wrap the emit in `if flags != 0 { ... }`. One-line change,
  plus a unit test for the no-addr-no-port case.

- Flag values: `NF_NAT_RANGE_MAP_IPS = (1 << 0)` and
  `NF_NAT_RANGE_PROTO_SPECIFIED = (1 << 1)` from
  `include/uapi/linux/netfilter/nf_nat.h`. Match the PR's
  `mod.rs:250-252` additions. Endianness: `append_attr_u32_be` matches
  the kernel's `nla_get_be32` on the read side. **OK.**

#### Claim 4 — inet-chain ambiguity for bare `Payload(Network)`

**VERIFIED.** Same kernel-source as Claim 1 — `nft_payload_eval` does
no version check; the rule is accepted at init and silently mismatches
v6 packets when written for v4 (or vice-versa) in an `inet` chain.

### Code correctness — other items

`crates/nlink/src/netlink/nftables/types.rs`:
- `push_meta_eq` helper (`line 853`): 1-byte `data: vec![value]` for
  both `MetaKey::NfProto` and `MetaKey::L4Proto`. Matches kernel
  `nft_meta_eval` (writes one byte for both keys). **OK.**
- `NFPROTO_IPV4 = 2`, `NFPROTO_IPV6 = 10`: match
  `include/uapi/linux/netfilter.h`. **OK.**
- `MetaKey::NfProto = 15`, `MetaKey::L4Proto = 16`: match `enum
  nft_meta_keys`. **OK.**
- All 6 address matchers + 2 ICMP matchers now prepend the family-
  correct guard. **OK.**
- L4 port matchers (`tcp_dport`, etc.) only refactored to use
  `push_meta_eq` — wire shape unchanged. No regression.

`crates/nlink/src/netlink/nftables/config/diff.rs`: purely
test-additive. Two new unit tests walk the lowered TLV byte stream and
assert specific inner attributes — independent of the existing
`normalize_tlv` logic so the tests catch regressions even if
normalization stops trimming `NLA_F_NESTED` bits. **OK.**

`crates/nlink/src/netlink/nftables/mod.rs`: 4 new pub consts, all
doc-string-linked to UAPI headers. **OK.**

5-commit walk (incremental development — `2bebf9b`, `f9feb93`,
`2372b0f`, `3ccec6f`, `c3ff401`): final tree subsumes intermediates
cleanly. No dead code, no orphaned constants.

### Tests

- Unit tests (`types.rs:1919–1964`): `addr_matchers_prepend_nfproto_guard`
  enumerates all 8 address-matcher legs (s/d × v4/v6 × eq/neq), asserts
  `Meta@0 + Cmp@1` with the right proto byte. `icmp_matchers_prepend_nfproto_guard`
  covers both ICMP type matchers. Solid.
- Diff-level unit tests (`diff.rs:765–805`): `masked_match_lowers_bitwise_op`
  asserts BITWISE_OP **only** when prefix < 32 (prefix==32 → no bitwise
  expr emitted). `nat_lowers_max_regs_and_flags` asserts MAX-ADDR,
  MAX-PROTO, FLAGS all present in a single rule body. Good.
- Integration tests
  (`tests/integration/nftables_reconcile.rs:773–884`), all
  `require_root!()` + `nlink::require_modules!("nf_tables", ...)`:
  - `inet_addr_matches_round_trip` — all four address-matcher legs (v4/v6
    × exact/prefix) in `Family::Inet`. **Critical test** — without the
    nfproto guard fix, the second `diff` is non-empty.
  - `inet_icmp_type_matches_round_trip` — both ICMP type matchers.
  - `snat_v6_addr_only_round_trips` — addr-only / `flags=MAP_IPS` leg.
    Combined with the pre-existing addr+port test (`flags=3`), covers
    the two non-trivial flag values.
- `nft_nat.ko` is genuinely a separate kernel module from `nf_tables.ko`
  (loadable, lives at `kernel/net/netfilter/nft_nat.ko`). The CI
  workflow now modprobes both `nft_nat` and `nf_nat`. **OK.**

**Gap (the request-changes item):** no test for the empty-NAT case
(`Expr::Nat(NatExpr::snat(family))` with no addr, no port). This is
exactly the case that reintroduces a phantom diff via the unconditional
FLAGS emit. Author should add it and tighten the writer.

### nlink-consistency

- All new attribute writes use `append_attr_u32_be` (matches kernel
  `nla_get_be32`). Consistent with the rest of `expr.rs`. **OK.**
- The 0.19 wire-format sizeof CI gate
  (`crates/nlink/src/netlink/sys_sizeof.rs`, Plan 213) covers verdicts/
  family/hook **constants** but not nftables expression attribute
  numbers. The PR's new constants sit outside the gate. Low drift risk
  (these UAPI numbers are decade-stable) but worth adding as a
  follow-up so the next constant drift gets caught.
- `push_meta_eq` composition traced: `match_icmp_type` calls
  `push_nfproto_ipv4()` followed by `push_meta_eq(L4Proto, IPPROTO_ICMP)`
  — two distinct meta+cmp pairs. Matches `nft`'s inet-chain emission
  for `meta l4proto icmp` (see
  [LWN on nftables implicit dependencies](https://lwn.net/Articles/872508/)).
  No redundant guards.

### Risk + backward compat

- **Headline risk — one-time phantom diff against pre-0.19 rulesets:**
  users running nlink ≤0.19 who installed `match_saddr_v{4,6}`,
  `bitwise`-emitting, or `snat`/`dnat` rules will see a non-empty diff
  against pre-existing in-kernel rules after upgrading. The first
  `cfg.diff(&nft).apply(&nft)` rewrites the affected rules; subsequent
  reconciles converge. **Not in the CHANGELOG.** This is operationally
  important for `apply_reconcile` users (long-running controllers
  watching for drift). Request-changes item.
- **Unconditional nfproto guard cost in single-family chains:** per
  packet, 1 register load + 1 cmp. Sub-ns on modern x86, dominated by
  the skb cache touch. Unmeasured by the PR; acceptable as asserted.
- **NAT flag-derivation edge case:** see Claim 3 caveat. Real bug in
  the new code.
- **No public API surface change.** Existing `Family::Ip6` tests on
  master continue to pass — kernel stores the redundant `meta nfproto
  == ipv6` guard verbatim in an `ip6` chain and echoes it on dump,
  round-trip stays empty.

### Recommendation: REQUEST CHANGES (two asks)

1. **Wrap `NFTA_NAT_FLAGS` emit in `if flags != 0`** at
   `crates/nlink/src/netlink/nftables/expr.rs:177`. Add a unit test for
   `Expr::Nat(NatExpr::snat(Family::Ip))` (no addr, no port) so the
   contract is locked.
2. **Add one CHANGELOG sentence** noting the one-time phantom diff for
   existing in-kernel rulesets: *"Existing rulesets installed by
   earlier nlink versions will diff non-empty on first post-upgrade
   reconcile; the diff converges after one apply."* Important for
   controller-style consumers.

After those two fixups this is a clear merge. The kernel-side analysis
is sound, the wire encoding is correct, the tests cover the
load-bearing claims, and the `push_meta_eq` DRY refactor is a clean
adjacent win.

---

## Combined notes

- Both PRs come with CI workflow updates that **actually exercise the
  new tests** (modprobe `wireguard`; modprobe `nft_nat` + `nf_nat`).
  This is exactly the pattern Plan 140's privileged-CI gate was built
  for — a memory I'm flagging for future review: when an integration
  test ships, the modprobe list needs to match or the gate
  silently skips. Both PRs got this right.
- Both PRs split parsing/wire-emission helpers into independently
  unit-testable free functions, matching the test-the-contract
  preference in `CLAUDE.md`. Good shape.
- Neither PR touches the 0.19 F1 concurrency story
  (`tokio::sync::Mutex` on `Connection<P>`) or any of the recv-loop
  invariants from Plan 172. No interaction risk.
- Both target `master` but land into the open `0.20` cycle's
  `[Unreleased]` once merged. Should appear in the eventual
  `docs/migration_guide/0.19.0-to-0.20.0.md` as wire-format
  corrections (PR #9 as a behaviour change on
  `WgDevice::private_key`'s `Some` semantics; PR #10 as a one-time
  rewrite-on-upgrade note).

---

**Suggested follow-up:** comment on PR #10 with the two specific asks
above (one-line fix + CHANGELOG sentence) and a clear MERGE-after-fix
green-light. PR #9 can be merged as-is, with the optional doc nit left
as a side note.
