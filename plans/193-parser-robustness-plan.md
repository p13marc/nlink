---
to: nlink maintainers
from: 0.19 consolidation-pass research agent (2026-05-30) — neighboring-crate bug audit
subject: parser robustness audit — accept-larger-than-expected, zero-length pathological inputs, per-message recoverable parse failures
status: queued for 0.19 — medium (defensive — preempting CVE-shaped issues other crates hit)
target version: 0.19.0
parent: (none — single-deliverable defensive plan)
source: kernel-research agent findings on netlink-packet-route #232, #152, neli #305
created: 2026-05-30
---

# Plan 193 — Parser robustness audit

## 0. Phase 1 implementation findings (2026-05-30)

The phase-1 audit was done; the lib's defensive parsing was
better than the plan assumed. Findings:

- **§2.1 (accept-larger-than-expected size check sweep): N/A.**
  Every fixed-size struct parser in `types/` + `messages/`
  ALREADY uses `data.len() < REQUIRED_SIZE` (the defensive
  form). The `!=` exact-equality smell from
  netlink-packet-route #232 isn't present in nlink. No
  changes needed.

- **§2.2 (multipath/nexthop pathological-input guards): N/A
  here, but surfaced a real gap.** nlink doesn't currently
  PARSE multipath chains from kernel responses — only writes
  them. `write_multipath_v4`/`write_multipath_v6` exist; no
  `parse_multipath_*` symbol. Multipath routes round-tripped
  through `get_routes()` lose their nexthop list. **This is
  a real feature gap surfaced by Plan 193 §2.2; it's tracked
  separately in [Plan 202](202-rta-multipath-parsing-plan.md)
  for the 0.19 cycle.**

- **§2.3 (recoverable per-message parse failures): policy
  pinned, code already compliant.** Every event-parser
  recv-loop in `stream.rs` uses either `.flatten()` or
  `let Ok(...) = msg_result else { continue };`. The audit
  script `scripts/audit-recv-loop-error-handling.sh` ran
  green; CI gate added.

The "Plan 193 didn't find bugs" outcome is itself the
deliverable for phase 1 — the policy doc + CI gate prevent
future drift. Phases 2 (fuzz target) + phase 3 (proptest)
remain for later commits; they're defensive and don't gate
anything.

## 1. Why this plan exists

The 0.19 consolidation-pass ecosystem audit surfaced three
bug-shapes from adjacent Rust netlink crates that would apply
to nlink too, but that we haven't been bitten by yet. Fixing
them now is cheap; waiting for a downstream consumer to file
the bug is slower and embarrassing.

| Bug-shape | Source | Risk in nlink |
|---|---|---|
| Fixed-size struct exact-equality check vs newer kernel sizes | [netlink-packet-route #232](https://github.com/rust-netlink/netlink-packet-route/issues/232) — `IFLA_INET6_CONF` size mismatch ("expecting 236, got 240") | Possible in our `zerocopy` fixed-size structs in `types/` |
| Integer underflow / panic on zero-length pathological inputs | [netlink-packet-route #152](https://github.com/rust-netlink/netlink-packet-route/issues/152) — `RTA_MULTIPATH` parsing | We walk nexthop chains in `nexthop.rs` + `route.rs` with similar loop shape |
| Whole-batch abort on one malformed message | [neli #305](https://github.com/jbaublitz/neli/issues/305) | Long-lived multicast subscribers (Plan 185, Plan 191) could die on one future-kernel event variant we don't recognize |

This plan ships three audits + the matching defensive fixes
+ optional fuzz coverage.

## 2. The change

### 2.1 Accept-larger-than-expected fixed-size struct parsing

Walk every `zerocopy::FromBytes`-style fixed-size struct in
`crates/nlink/src/netlink/types/` and `messages/`. Any code
path that does `if buf.len() != EXPECTED_SIZE { error }` is
brittle against kernel ABI growth. The kernel adds fields to
struct-typed attributes (e.g. `IFLA_INET6_CONF`); a newer
kernel sending a larger payload than we expect should yield
the FIELDS WE KNOW, not a parse error.

**Policy**: `buf.len() < REQUIRED_PREFIX_SIZE` is an error;
`buf.len() > REQUIRED_PREFIX_SIZE` is fine — we slice
`&buf[..REQUIRED_PREFIX_SIZE]` and ignore trailing bytes.

Phase 1 task: grep for `len() !=` / `len() == EXPECTED` in
`types/` + `messages/` and convert each to `len() <`.

### 2.2 Pathological-length input safety for multipath/nexthop walking

`netlink/nexthop.rs` and `netlink/route.rs::parse_multipath`
walk `rtnexthop` chains:

```rust
loop {
    let len = nexthop_hdr.rtnh_len as usize;  // u16 → usize
    if offset + len > end { break; }
    process(...);
    offset += align4(len);  // ← what if len == 0?
}
```

If a malformed message has `rtnh_len == 0`, the offset
doesn't advance and the loop spins. If `rtnh_len < sizeof(rtnexthop)`,
the slice indexing panics.

**Defensive**: validate `rtnh_len >= MIN_NEXTHOP_HEADER_SIZE`
on entry; if not, log + skip the remainder of the chain.
Verify in `nexthop.rs` + `route.rs` + any other
header-driven loop.

### 2.3 Recoverable per-message parse failures

`MessageIter::new(data)` walks netlink frames. If one frame
fails to parse, current behavior in some recv-loops is to
`?` the error and abort the whole recv batch.

For long-lived multicast subscribers (Plan 185 nftables
watcher, Plan 191 route watcher), one malformed frame from a
future kernel must NOT kill the stream — log + skip + keep
reading.

Audit `parse_events` implementations in `stream.rs` (each
`impl EventSource for X`) and confirm:
- `MessageIter::new(data).flatten()` is used (silently skips
  parse errors) instead of `.collect::<Result<_, _>>()`.
- The per-message `parse_*_event` returns `Option<_>` (None
  on unrecognized type / truncated body), not Result.

Both are already the pattern. The audit confirms; the
defensive fix would only kick in if a future contributor
changes the recv shape.

Add a **CI gate** that fails on `?` operator inside a
`for ... in MessageIter::new(...)` body in
`crates/nlink/src/netlink/stream.rs` — small awk script in
the audit suite shape.

### 2.4 Optional — `cargo-fuzz` target for the parser surface

Plan 176 (0.17) shipped a hardware-test-coverage strategy
doc. A natural follow-up is fuzz coverage on the parsers:
random bytes in → no panics, no infinite loops, no memory
allocations beyond a reasonable cap. ~50 LOC per fuzz target.

Scope decision: **ship fuzz infrastructure but only one
target** in this plan (the `MessageIter` + nlmsg-header
parsing surface, which has the largest reachable surface).
Future targets can be added incrementally.

```toml
# fuzz/Cargo.toml (new directory)
[package]
name = "nlink-fuzz"
version = "0.0.0"
publish = false

[dependencies]
libfuzzer-sys = "0.4"
nlink = { path = "../crates/nlink", features = ["full"] }

[[bin]]
name = "fuzz_message_iter"
path = "fuzz_targets/fuzz_message_iter.rs"
test = false
doc = false
```

```rust
// fuzz/fuzz_targets/fuzz_message_iter.rs
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Walk every parser-reachable code path. The target
    // succeeds when the fuzz run completes without panic /
    // OOM / infinite loop.
    for msg in nlink::netlink::message::MessageIter::new(data).flatten() {
        let (_header, payload) = msg;
        // Cycle a few parsers — none should panic on garbage.
        let _ = nlink::netlink::messages::link::LinkMessage::from_bytes(payload);
        let _ = nlink::netlink::messages::route::RouteMessage::from_bytes(payload);
        let _ = nlink::netlink::messages::address::AddressMessage::from_bytes(payload);
    }
});
```

CI doesn't run fuzz tests on every push (too slow); a
weekly cron via GitHub Actions runs it for ~10 minutes per
target. Catches regressions over time without slowing the
hot path.

## 3. Implementation phases

| Phase | Files | LOC |
|---|---|---|
| 1 — Fixed-size struct size check audit | `types/`, `messages/` | ~50 (mostly `!=` → `<` flips) |
| 2 — Multipath/nexthop pathological-input guards | `nexthop.rs`, `route.rs` | ~30 |
| 3 — Recv-loop parse-error skip CI gate | new audit script | ~30 |
| 4 — `cargo-fuzz` target + workflow | `fuzz/` (new) | ~100 |
| 5 — Tests (see §4) | various | ~200 |
| **Total** | | **~410 LOC** |

## 4. Tests

### 4.1 Unit — accept-larger-than-expected

For each `from_bytes` parser in `types/` + `messages/`, add a
test that passes a buffer >= EXPECTED_SIZE and verifies
parsing succeeds:

```rust
#[test]
fn link_attribute_struct_accepts_larger_than_expected_payload() {
    // Mimic the netlink-packet-route #232 scenario:
    // kernel grew the struct from 236 to 240 bytes. Parser
    // must read the prefix and ignore the trailing bytes.
    let mut buf = vec![0u8; 236];
    // ... fill in valid prefix ...
    let parsed = LinkInet6Conf::from_bytes(&buf).expect("236 bytes valid");

    let mut buf_larger = buf.clone();
    buf_larger.extend_from_slice(&[0xFFu8; 4]);  // 4 trailing
    let parsed_larger = LinkInet6Conf::from_bytes(&buf_larger)
        .expect("240 bytes must also parse");

    assert_eq!(parsed.field_a, parsed_larger.field_a);
}
```

One test per struct, ~10 structs to audit. Reuse a generic
test fixture if possible.

### 4.2 Unit — pathological-length safety

```rust
#[test]
fn parse_multipath_handles_zero_length_nexthop_without_loop() {
    // A malformed rtnexthop with rtnh_len = 0 must not spin.
    let mut buf = vec![0u8; 8];
    // rtnh_len at offset 0 = 0  (BAD)
    buf[0] = 0; buf[1] = 0;
    let start = std::time::Instant::now();
    let result = parse_multipath_chain(&buf);
    assert!(start.elapsed() < std::time::Duration::from_millis(100));
    // Parser must surface this as an error or skip, but not hang.
    assert!(result.is_err() || result.as_ref().unwrap().is_empty());
}

#[test]
fn parse_multipath_handles_undersized_nexthop_header() {
    // rtnh_len = 1 (less than the header size) — slice index
    // would panic without the defensive check.
    let mut buf = vec![0u8; 8];
    buf[0] = 1; buf[1] = 0;
    let result = parse_multipath_chain(&buf);
    // Must not panic; either error or skip.
    let _ = result;
}

#[test]
fn parse_multipath_walks_normal_chain() {
    // Sanity that the defensive guards don't break the
    // happy path — two well-formed nexthops, both should
    // parse cleanly.
    ...
}
```

### 4.3 Unit — parse-error skip pattern in event parsers

```rust
#[test]
fn nftables_parse_events_skips_malformed_frame() {
    // Construct a buffer with two messages: one valid, one
    // truncated. parse_events must return only the valid one,
    // not error.
    let mut data = Vec::new();
    // ... append valid NEWTABLE frame ...
    // ... append truncated frame (length says 100, only 20 bytes follow) ...
    let events = Nftables::parse_events(&data);
    assert_eq!(events.len(), 1, "valid frame must survive; truncated skipped");
}

// Same for Route, NetworkEvent, Conntrack, Audit, ...
```

### 4.4 Integration — large nexthop count

```rust
#[tokio::test]
async fn parse_multipath_handles_high_nexthop_count() -> Result<()> {
    require_root!();

    // Create a multipath route with 8 nexthops and dump it.
    // Verifies the chain walker handles a non-trivial chain
    // without missing nexthops or spinning.
    ...
}
```

### 4.5 CI — fuzz target weekly cron

```yaml
# .github/workflows/fuzz.yml (new)
name: Fuzz
on:
  schedule:
    - cron: '0 3 * * 1'  # weekly Monday 03:00 UTC
  workflow_dispatch: {}
jobs:
  fuzz:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@nightly
      - run: cargo install cargo-fuzz
      - run: cd fuzz && cargo +nightly fuzz run fuzz_message_iter -- -max_total_time=600
```

## 5. Acceptance criteria

- [ ] Every fixed-size struct parser in `types/` + `messages/`
      accepts `>=` expected size (was: ==).
- [ ] Multipath/nexthop chain walking guards against
      zero-length and undersized headers.
- [ ] Audit script verifies `?` operator not used inside
      `MessageIter` walking loops in `stream.rs`.
- [ ] `cargo-fuzz` infrastructure + one target
      (`fuzz_message_iter`).
- [ ] Weekly GitHub Actions cron runs the fuzz target for
      10 minutes.
- [ ] 5+ unit tests covering the new defensive cases.
- [ ] 1+ integration test (large nexthop count).
- [ ] CHANGELOG `### Fixed` entry.

## 6. Effort estimate

| Phase | Effort |
|---|---|
| Phase 1: size check sweep | ~1.5 h |
| Phase 2: pathological-input guards | ~1 h |
| Phase 3: CI audit script | ~30 min |
| Phase 4: fuzz setup + workflow | ~1.5 h |
| Tests | ~2 h |
| CHANGELOG + migration guide | ~30 min |
| **Total** | **~7 h** |

## 7. Risks

- **Discovering a real bug during the audit phase**: if a
  fuzz target finds a panic in the first 10 minutes, that's
  a fix-and-ship situation. Estimate +2 h budget for the
  first iteration.
- **Fixed-size parser sweep might surface API drift**: if a
  struct grew between kernel versions we model, the
  internal field layout might be wrong (not just the size).
  Triage case-by-case.
- **Fuzz target is `no_main`** — needs nightly Rust. The
  weekly cron uses nightly explicitly; the main CI stays on
  stable.

## 8. In-scope expansions (consolidation pass — fuzz coverage broadened)

**Five fuzz targets total, not one** — pull in the full fuzz
coverage that was deferred:

```
fuzz/fuzz_targets/
├── fuzz_message_iter.rs       (original — top-level netlink frames)
├── fuzz_link_attrs.rs         (RTNETLINK link attribute parsing)
├── fuzz_tc_messages.rs        (TC qdisc/class/filter parsing)
├── fuzz_nftables_expr.rs      (nftables expression walking)
└── fuzz_genl_messages.rs      (genl message header + family-specific bodies)
```

Each target adds ~60 LOC + a CI workflow line. Run all five in
the weekly cron with 10 minutes per target (50 min total).

**Proptest integration** — randomized but structured. Useful
where the input space has constraints fuzz misses (valid
netlink frame headers + invalid attribute payloads). One
prop-test target per parser family. ~100 LOC.

```rust
// crates/nlink/proptest-regressions/ (new)
proptest! {
    #[test]
    fn message_iter_never_panics_on_valid_header_invalid_body(
        seq in any::<u32>(),
        ty in any::<u16>(),
        body in prop::collection::vec(any::<u8>(), 0..4096),
    ) {
        let mut frame = vec![];
        // Build valid nlmsghdr (len, type, flags, seq, pid)
        // ... then append `body` as the payload
        for msg in MessageIter::new(&frame).flatten() {
            // Must not panic regardless of body content.
            let _ = msg;
        }
    }
}
```

## 8b. Out-of-scope follow-ups

- **`miri` integration** — would catch undefined behavior in
  the `zerocopy` casts. Substantial CI cost AND `miri` doesn't
  run native syscalls so most of our code path is untestable
  under it. Genuinely out of scope; not just a "we'll get to
  it" deferral.

## 9. Cross-cutting artifacts

This plan lands FIRST per the recommended landing order, so
it owns creating the 0.18 → 0.19 migration guide file +
adding the row to the migration-guide README index.

| Artifact | Action | Notes |
|---|---|---|
| `docs/migration_guide/0.18.0-to-0.19.0.md` (**new** — Plan 193 creates the file since it lands first) | **create** with header + Plan 193's section. Subsequent plans append to it. | One-time setup. Follow the template from `0.17.0-to-0.18.0.md`. |
| `docs/migration_guide/README.md` | **add row** for `0.18.0-to-0.19.0`. | One line in the existing table. |
| `CHANGELOG.md` `## [Unreleased]` | **add** `### Fixed` (parser robustness audits) + `### Added` (fuzz infrastructure) | Note links to the three upstream issues (netlink-packet-route #232, #152, neli #305) as precedent. |
| `CLAUDE.md` | **append** a "## Parser robustness" sub-section under the existing "## Recv-loop shape" area, documenting the accept-larger-than-expected + pathological-input policy | Future contributors writing new parsers inherit the right policy. |
| `fuzz/` (**new directory**) | **create** with `Cargo.toml`, `fuzz_targets/fuzz_message_iter.rs`, README explaining nightly Rust + cargo-fuzz prerequisites | Lives at workspace root, NOT under `crates/nlink/`. |
| `.github/workflows/fuzz.yml` (**new**) | **create** | Weekly cron + manual dispatch. |
| `scripts/audit-recv-loop-error-handling.sh` (**new**) | **create** | Per §2.3. Verifies `?` isn't used inside `MessageIter` walking loops in `stream.rs`. |
| `.github/workflows/rust.yml` | **add** the recv-loop audit script as a CI gate | Mirrors the existing audit-shape jobs. |

End of plan.
