---
to: nlink maintainers
from: nlink maintainers
subject: bins/tc u32 filter selector grammar — typed `parse_params` for `U32Filter`
target version: 0.15.0 (Phase 1 of [Plan 142](142-zero-legacy-typed-api-plan.md))
date: 2026-04-25
status: draft — phase-level detail document for **Plan 142 Phase 1**. Read Plan 142 first for the consolidated view; this plan is the per-PR / per-token / per-fixture specification.
related: Plan 142 master; Plan 133 PR C (basic filter ematch — the other half of Plan 142 Phase 1); Plan 140 (CI integration tests harness — Plan 142 Phase 0 prerequisite for the golden-hex fixtures in Phase 2 of this plan).
---

# bins/tc u32 filter selector grammar

## 0. Summary

The typed-units rollout (slices 1–15) brought `bins/tc` to typed-first
dispatch for every qdisc kind and seven of the nine filter kinds.
The remaining filter kinds are:

- **`u32`** — kernel's swiss-army-knife filter with a complex
  selector grammar. This plan.
- **`basic`** — blocked on Plan 133 PR C (`BasicFilter` ematch).

The `u32` filter doesn't fit the "small parser, one slice" pattern
the previous fifteen slices used. Its grammar is genuinely a small
DSL — `match TYPE VALUE MASK at OFFSET` repeated, plus address /
port / protocol shortcuts that desugar to `match` triples, plus hash
table support (`link`, `ht`, `divisor`, `order`). This plan stages
the work in three independently-shippable slices so the rollout
makes incremental progress without any one commit ballooning.

## 1. Goals & non-goals

### Goals

1. **Phase 1**: a `U32Filter::parse_params(&[&str])` that handles the
   raw `match u32|u16|u8 VALUE MASK at OFFSET` triples plus the
   simple structural tokens (`classid`, `flowid`, `chain`,
   `goto_chain`, `skip_hw`, `skip_sw`, `priority`).
2. **Phase 2**: named-match shortcuts — `match ip src ADDR/PREFIX`,
   `match ip dst`, `match ip protocol`, `match ip dport`, `match ip
   sport`, `match tcp dport`, `match udp dport`, `match icmp type`.
   Each desugars to a Phase-1 raw triple at the right offset.
3. **Phase 3**: hash table grammar — `link <handle>`, `ht <handle>`,
   `divisor <n>`, `order <n>`, `hashkey mask <hex> at <offset>`.
4. After Phase 3 lands, wire `bins/tc/src/commands/filter.rs`
   typed dispatch to include `u32`. The bin's filter `try_typed_filter`
   `matches!` guard grows to 8 kinds and the dispatch macro grows
   one arm. Drop `#[allow(deprecated)]` on the bin's `filter_builder`
   import once `basic` is also off the legacy path (Plan 133 PR C);
   until then it stays for the basic fallback.

### Non-goals

1. **Optimisation hints.** The `tc(8)` `u32` syntax also accepts
   per-key offset masks and shifts that the kernel uses for
   computed-offset jumps (`offset mask 0xf00 shift 6`). Add only if
   a user asks; the typed `U32Filter` doesn't currently expose
   them.
2. **Hash buckets at construction.** This plan exposes `link` /
   `ht` / `divisor` / `order` so the parser can target an existing
   bucket; creating the bucket itself stays a separate
   `add_filter_full` call.
3. **Full grammar parity with iproute2.** Some `tc(8)` shorthands
   (`match ether type`, `match ether dst`, the `u32` link/redirect
   construct used in nested hash-tables) are rare enough that
   "drop to `tc::builders::filter` for those" is the right
   answer.

## 2. Phase 1 — raw `match` triples + structural tokens

### 2.1. API sketch

```rust
// crates/nlink/src/netlink/filter.rs

impl U32Filter {
    /// Parse a tc-style u32 params slice into a typed `U32Filter`.
    ///
    /// Phase 1 surface (raw matches + structural tokens):
    ///
    /// - `match u32 <hex-value> <hex-mask> at <offset>` — append a
    ///   32-bit-wide selector key. The triple is (value, mask,
    ///   offset) all hex (offset can be a decimal integer too).
    /// - `match u16 <hex-value> <hex-mask> at <offset>`,
    ///   `match u8 <hex-value> <hex-mask> at <offset>` — narrower
    ///   widths. The kernel still uses a 32-bit-sized key on the
    ///   wire; the parser shifts/masks to put the value in the
    ///   correct quadrant.
    /// - `classid <handle>` (alias `flowid`).
    /// - `chain <n>`.
    /// - `priority <n>` — filter priority (u16 banded per
    ///   `FilterPriority`).
    /// - `skip_hw` / `skip_sw` — flag tokens.
    pub fn parse_params(params: &[&str]) -> Result<Self> { ... }
}
```

### 2.2. Wire format reminders

The `u32` filter's selector lives under `TCA_U32_SEL` and contains:

```c
struct tc_u32_sel {
    unsigned char       flags;       // TC_U32_TERMINAL, etc.
    unsigned char       offshift;
    unsigned char       nkeys;
    __be16              offmask;
    __u16               off;
    short               offoff;
    short               hoff;
    __be32              hmask;
    struct tc_u32_key   keys[0];     // packed array
};

struct tc_u32_key {
    __be32  mask;
    __be32  val;
    int     off;
    int     offmask;
};
```

For Phase 1 the `flags` / `offshift` / `offmask` / `off` /
`offoff` / `hoff` / `hmask` fields stay zero; we just append
`tc_u32_key` entries. Reference: kernel
`net/sched/cls_u32.c`.

### 2.3. Stricter than the legacy parser

The legacy `add_u32_options` in `tc::builders::filter` silently
swallows unknown tokens via the `_ => i += 1` arm (same fossil that
made every previous net-new CLI capability slice possible). Phase 1
returns `Error::InvalidMessage` for unknown tokens, missing values,
and unparseable hex.

### 2.4. Tests

Unit tests — pattern matches the existing typed-units tests:

- `u32_parse_params_empty_yields_default`
- `u32_parse_params_match_u32_triple` — single `match u32 0xCAFE 0xFFFF at 0`,
  assert one key with the right (value, mask, off).
- `u32_parse_params_match_u16_lower_half`,
  `u32_parse_params_match_u16_upper_half` — assert the value/mask
  shift goes into the correct quadrant.
- `u32_parse_params_match_u8` — same for byte-wide.
- `u32_parse_params_multiple_matches` — assert keys append in
  order.
- `u32_parse_params_classid`, `u32_parse_params_chain`,
  `u32_parse_params_skip_flags`.
- `u32_parse_params_unknown_token_errors`.
- `u32_parse_params_match_invalid_hex_errors`.
- `u32_parse_params_match_short_errors` — `match u32 0xCAFE` (no
  mask / no offset).

### 2.5. Effort

~1.5 days. Builder API + the per-key encoder + ~12 unit tests.

## 3. Phase 2 — named-match shortcuts

### 3.1. API sketch

The parser learns to desugar `match TYPE FIELD VALUE` into the
correct Phase-1 raw triple. No new public method — the existing
`U32Filter::parse_params` recognises the shortcut tokens and
internally constructs the underlying raw key.

### 3.2. Shortcuts to support

| Token | Desugars to |
|---|---|
| `match ip src <addr/prefix>` | `match u32 (addr_be & mask) mask at 12` (IPv4 src) |
| `match ip dst <addr/prefix>` | `match u32 (addr_be & mask) mask at 16` |
| `match ip protocol <proto> 0xff` | `match u8 <proto> 0xff at 9` |
| `match ip dport <port> 0xffff` | `match u16 <port> 0xffff at 22` (after IP+TCP/UDP header pun) |
| `match ip sport <port> 0xffff` | `match u16 <port> 0xffff at 20` |
| `match tcp dport / sport` | same offsets but L4 explicit |
| `match udp dport / sport` | same offsets, label explicit |
| `match icmp type` / `match icmp code` | offsets 20, 21 with u8 |

(These offsets assume IPv4 + at-offset-from-network-header. Real
`tc(8)` u32 walks a tree of `link`s for IPv6 / L2 / L3-payload
offsets; Phase 2 covers the IPv4 simple case only. IPv6 versions
of the same matches are an honest extension if a user asks, but
they need the kernel-derived `nexthdr` chain that ip6 doesn't have
at fixed offsets.)

### 3.3. Stricter than the legacy parser

Per-shortcut argument validation: `match ip src 10.0.0.0/40`
returns "IPv4 prefix out of range" rather than silently producing a
wrong-mask key.

### 3.4. Tests

- `u32_parse_params_match_ip_src_with_prefix`,
  `_match_ip_dst_full_address` (no prefix → /32).
- `u32_parse_params_match_ip_protocol_tcp` — assert proto 6 at
  offset 9, mask 0xff.
- `u32_parse_params_match_tcp_dport_80` — assert (80<<16) at offset
  20, mask 0xffff_0000 (or however the kernel packs it; verify
  against golden hex from `tc -s filter show`).
- `u32_parse_params_match_ip_src_invalid_prefix_errors`.
- `u32_parse_params_match_named_field_with_unsupported_modifier_errors` —
  e.g. `match ip src 10.0.0.0/24 fragment` → unsupported modifier.

### 3.5. Effort

~1.5 days. Parser additions + ~10 unit tests. Wire format work is
zero (Phase 1's encoder reused).

### 3.6. Validate offset constants against `tc(8)`

Because the magic offsets (12, 16, 9, 20, 22) are easy to typo,
**capture golden hex** for each shortcut once interactively under
sudo:

```text
sudo tc qdisc add dev lo root handle 1: htb default 1
sudo tc filter add dev lo parent 1: protocol ip prio 100 \
    u32 match ip src 10.0.0.0/24 classid 1:1
nlmon -i lo  # capture netlink frames
```

Decode the captured frame, write the byte sequence into a
`tests/fixtures/u32/match_ip_src_10_0_0_0_24.hex` file, and add a
test that compares Phase 2's emitted bytes against the fixture.
Same approach Plan 133 PR C calls for.

## 4. Phase 3 — hash table grammar

### 4.1. Why

Real `tc(8)` `u32` filters use hash tables to avoid linear scan when
many filters share a prefix. A user types:

```text
tc filter add dev eth0 parent 1: handle 100: protocol ip prio 1 u32 \
    divisor 256
tc filter add dev eth0 parent 1: protocol ip prio 1 u32 ht 100: \
    match ip dst 1.2.3.4 link 100:0:1 \
    classid 1:1
```

The first command creates a 256-bucket hash table at handle `100:`.
The second adds a key whose match links into bucket `100:0:1`.
Without `link` / `ht` / `divisor` support, the typed parser can't
express tree-of-hashes filters at all.

### 4.2. API sketch

Tokens to add:

- `divisor <n>` — for the hash-table-create case (`U32Filter::new()`
  flagged as a divisor-only filter, no keys).
- `ht <handle>` — set the hash table this filter belongs to.
- `link <handle>` — the next-hop hash-table handle to chase on
  match.
- `order <n>` — explicit slot within the hash bucket.
- `hashkey mask <hex> at <offset>` — additional hash-key bits used
  to compute the bucket index.

### 4.3. Wire format

These map onto existing `TCA_U32_*` attributes:

- `TCA_U32_DIVISOR` (u32)
- `TCA_U32_HASH` — packed `(ht_handle, slot_within_bucket)`
- `TCA_U32_LINK` (u32)
- `TCA_U32_HMASK` / hashkey fields inside `tc_u32_sel`

### 4.4. Tests

- `u32_parse_params_divisor_only` — assert `TCA_U32_DIVISOR` set,
  no keys, no `link`.
- `u32_parse_params_ht_link_combo` — typical "hashed chain" flow.
- `u32_parse_params_hashkey` — hashkey-mask-at-offset goes into
  `sel.hmask` / `sel.hoff`.
- Conflicting tokens (e.g. `divisor 256 match ip src ...` —
  divisors don't have keys) → clean error.

### 4.5. Effort

~2 days. Phase-3 token handling + the `tc_u32_sel` field
population + ~8 unit tests.

## 5. Bin wiring (after Phase 1 lands)

`bins/tc/src/commands/filter.rs`:

```rust
// matches! guard
"flower" | "matchall" | "fw" | "route" | "bpf" | "cgroup" | "flow" | "u32"
```

```rust
// dispatch! arm
"u32" => dispatch!(U32Filter),
```

That's the end of the typed-units rollout's filter side once Plan
133 PR C also lands. The bin's `filter_builder` import can then
have its `#[allow(deprecated)]` dropped — `basic` will be the
remaining legacy caller, gated on PR C.

## 6. Files touched (estimate)

| Path | Change | Approx LOC |
|---|---|---|
| `crates/nlink/src/netlink/filter.rs` | `U32Filter::parse_params` (3 phases) | ~400 |
| `crates/nlink/src/netlink/filter.rs::tests` | ~30 unit tests | ~250 |
| `crates/nlink/tests/fixtures/u32/*.hex` | golden frames per Phase 2 | ~10 files |
| `bins/tc/src/commands/filter.rs` | dispatch macro + `matches!` | ~10 |
| `CHANGELOG.md` | per-phase entries | per phase |

Total ~700 LOC code+tests. The fixtures are small but require
interactive capture under sudo (one-shot setup; checked in).

## 7. Phasing (which PRs, in what order)

| PR | Scope | Size | Unlocks |
|---|---|---|---|
| A | Phase 1: raw `match` triples + structural tokens | ~250 LOC | Basic typed dispatch for users who write u32 by raw offset |
| B | Phase 2: named-match shortcuts (IPv4 src/dst/proto/ports/icmp) | ~200 LOC | The common case: writing port-based / address-based u32 filters |
| C | Phase 3: hash table grammar (`divisor`, `ht`, `link`, `order`, `hashkey`) | ~250 LOC | Tree-of-hashes filters; large-fanout u32 trees |

Bin wiring lands with PR A so Phase 1 functionality is immediately
usable from the CLI; PRs B and C extend what `parse_params` can
recognise without changing the bin's dispatch shape.

## 8. Open questions

1. **IPv6 named-match shortcuts.** `match ip6 src` etc. need the
   kernel's `link`-walk through the IPv6 next-header chain. Defer
   to a phase 4 or punt indefinitely.
2. **Endianness sanity.** `tc(8)`'s `u32` selectors quote values in
   either `0x12345678` or `0x12 0x34 0x56 0x78` form depending on
   shell. We accept hex words and let the parser handle byte order
   internally. Document that the syntax matches `tc(8)` shell
   conventions.
3. **Test fixture for endianness.** Add at least one `match u32`
   golden-hex test where the byte order would be flipped under a
   wrong-endian implementation. Catches the most common encoder
   bug.

## 9. Definition of done (per phase)

### PR A — Phase 1
- [ ] `U32Filter::parse_params` recognises every Phase-1 token
- [ ] ~12 unit tests cover empty, raw matches, structural tokens,
      strict error cases
- [ ] `bins/tc/src/commands/filter.rs` typed dispatch routes
      `u32` through `parse_params`; long-tail `basic` still falls
      through to legacy
- [ ] CHANGELOG entry under `## [Unreleased]`
- [ ] Workspace `cargo clippy --all-targets -- --deny warnings`
      clean

### PR B — Phase 2
- [ ] All eight named-match shortcuts parse correctly
- [ ] Golden-hex fixtures for at least: `match ip src /24`,
      `match ip dst /32`, `match ip protocol tcp`,
      `match tcp dport 80`. Compared against the parser's emitted
      bytes in unit tests
- [ ] ~10 additional unit tests
- [ ] CHANGELOG entry

### PR C — Phase 3
- [ ] `divisor`, `ht`, `link`, `order`, `hashkey` all parse
- [ ] At least one tree-of-hashes test that constructs a 2-level
      bucket layout
- [ ] ~8 additional unit tests
- [ ] CHANGELOG entry
- [ ] **Filter-side `#[allow(deprecated)]` drop check** — once
      Plan 133 PR C also lands, the bin's `filter_builder` import
      can lose its `#[allow]`. If PR C lands first, this PR closes
      the loop; otherwise the loop closes with PR C.

## 10. Risks

| Risk | Likelihood | Mitigation |
|---|---|---|
| Endianness bug in `match u32` | Medium | Phase 2 golden-hex fixtures catch it on a known-good filter |
| Magic offsets wrong for IPv4 named matches | High | Capture golden hex from `tc(8)` for each shortcut, compare bytes in tests |
| Tree-of-hashes interactions with `link` | Medium | Phase 3 unit test that builds a 2-level tree and decodes the resulting frame |
| Scope creep into IPv6 / L2 / computed offsets | Medium | Phase boundaries explicit; defer to phase 4 with a concrete user ask |

End of plan.
