---
to: nlink maintainers
from: 0.20 cycle pre-work — deep audit finding B5 (2026-06-04)
subject: WireGuard `parse_timespec` overflow panic — close the long-lived subscriber crash class
status: planning
target version: 0.20.0
parent: [Plan 220 master](220-0.20-master-plan.md)
source: [AUDIT_BUGS.md](../AUDIT_BUGS.md) B5 (verified by reviewer repro)
created: 2026-06-04
---

# Plan 225 — WireGuard `parse_timespec` robustness

## 1. Why this plan exists

`parse_timespec` at
`crates/nlink/src/netlink/genl/wireguard/types.rs:326-344`
panics in release mode on any malformed handshake timestamp
with negative seconds:

```rust
// types.rs:326-344 — current
pub fn parse_timespec(data: &[u8]) -> Option<SystemTime> {
    if data.len() < 16 {
        return None;
    }

    let secs = i64::from_ne_bytes([
        data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
    ]);
    let nsecs = i64::from_ne_bytes([
        data[8], data[9], data[10], data[11], data[12], data[13], data[14], data[15],
    ]);

    if secs == 0 && nsecs == 0 {
        return None; // No handshake yet
    }

    let duration = Duration::new(secs as u64, nsecs as u32);
    Some(UNIX_EPOCH + duration)   // PANIC on overflow
}
```

Three problems:

1. `secs as u64` on a negative `i64` produces a huge unsigned
   value (`-1 → u64::MAX`).
2. `nsecs as u32` on a negative `i64` or a value ≥ 10⁹
   either truncates or trips `Duration::new`'s nanos
   normalization (`Duration::new` does `nanos % 1_000_000_000`,
   adding the carry to `secs` — which can itself overflow).
3. `UNIX_EPOCH + duration` panics on overflow. `SystemTime`'s
   `Add<Duration>` impl is documented as panicking on overflow;
   `checked_add` is the non-panicking variant.

Verified by repro at `/tmp/check_dur2.rs` per the audit:
release-mode `thread 'main' panicked at 'overflow when adding
duration to instant'`.

This function runs inside the WireGuard multicast event
handler. One malformed frame from the kernel kills the entire
`watch()` task plus any sibling tasks pinned to the runtime —
the long-lived subscriber dies on a single bad timestamp.

This violates CLAUDE.md `## Parser robustness` rule 3:

> **Recoverable per-message parse failures.** Event parsers
> (`impl EventSource for *`, `parse_*_event` dispatchers)
> that walk `MessageIter::new(data)` MUST silently skip parse
> errors rather than propagating via `?`. (...) One malformed
> frame from a future kernel MUST NOT kill a long-lived
> multicast subscriber.

`parse_timespec` returns `Option<SystemTime>`. Its contract is
"`None` on malformed input." The panic violates the contract.

## 2. The change

Wrap the arithmetic, validate ranges, propagate `None` on every
failure mode:

```rust
// crates/nlink/src/netlink/genl/wireguard/types.rs:326-344 —
// corrected
//
// Plan 225 — close B5. Pre-fix, a malformed kernel frame with
// negative `secs` or out-of-range `nsecs` panicked in release
// mode via `UNIX_EPOCH + Duration`. The function's documented
// contract is `None` on malformed input; the panic violated it
// and violated CLAUDE.md `## Parser robustness` rule 3
// (recoverable per-message parse failures).

pub fn parse_timespec(data: &[u8]) -> Option<SystemTime> {
    if data.len() < 16 {
        return None;
    }

    let secs = i64::from_ne_bytes([
        data[0], data[1], data[2], data[3],
        data[4], data[5], data[6], data[7],
    ]);
    let nsecs = i64::from_ne_bytes([
        data[8],  data[9],  data[10], data[11],
        data[12], data[13], data[14], data[15],
    ]);

    if secs == 0 && nsecs == 0 {
        return None; // No handshake yet — documented case.
    }

    // Reject impossible/garbage timestamps. Pre-1970 makes no
    // sense for a WireGuard last-handshake. Out-of-range nsecs
    // are kernel-side garbage; `Duration::new` would normalize
    // them but the carry can re-overflow secs.
    if secs < 0 {
        return None;
    }
    if !(0..1_000_000_000).contains(&nsecs) {
        return None;
    }

    // Safe to widen: secs is non-negative, nsecs is in
    // [0, 10^9). `Duration::new` cannot panic here.
    let duration = Duration::new(secs as u64, nsecs as u32);

    // SystemTime::checked_add returns None on overflow rather
    // than panicking — required by the function's contract.
    UNIX_EPOCH.checked_add(duration)
}
```

The function still returns `Option<SystemTime>`; the contract
is unchanged. The body is robust against every adversarial
input we can construct.

## 3. Audit of sibling sites

`parse_timespec`-like patterns elsewhere in the codebase that
construct a `SystemTime` from kernel-supplied bytes:

| Site | File:line | Audited |
|---|---|---|
| WG `parse_timespec` | `genl/wireguard/types.rs:326` | this plan |
| Conntrack `entry.last_used` | `netfilter.rs` (search `UNIX_EPOCH`) | check |
| audit `AuditStatus::lost_messages` timestamp | `audit.rs` | check (uses u32 ticks; not vulnerable) |
| ethtool stats counter timestamps | `genl/ethtool/` | check |
| DPLL `lock_status_acquired_at` | `genl/dpll/messages.rs` | check |

For the sweep, run:

```bash
grep -rn "UNIX_EPOCH" crates/nlink/src/netlink/
grep -rn "Duration::new" crates/nlink/src/netlink/
grep -rn "SystemTime" crates/nlink/src/netlink/
grep -rn "Duration::from_secs" crates/nlink/src/netlink/
```

Walk each hit. The pattern that matters is:

```rust
let x: i64 = read_from_kernel();
UNIX_EPOCH + Duration::from_secs(x as u64)  // BAD
```

or any variant where a signed kernel value is widened to
unsigned without sign-checking. The audit-checklist in §3.1
captures the conventions any new site must follow.

### 3.1 The policy for new sites

Any code constructing a `SystemTime` from kernel bytes MUST:

1. Validate `secs >= 0` before widening to `u64`.
2. Validate `nsecs` is in `[0, 1_000_000_000)` before passing
   to `Duration::new`.
3. Use `SystemTime::checked_add` (or `checked_sub`) — never
   the panicking `+` / `-` operators.

The function MUST return `Option<SystemTime>` (or `Result`
with a typed error) and propagate `None` on every malformed
case.

A short note next to CLAUDE.md `## Parser robustness` rule 3
documents this as the time-handling sub-rule. The
`audit-recv-loop-error-handling.sh` CI gate doesn't catch this
directly (it walks `?` operators in `MessageIter` loops); the
prevention is the policy doc + the unit-test discipline in §4.

### 3.2 What the audit found

A grep of `UNIX_EPOCH` + `Duration::new` in
`crates/nlink/src/netlink/` returned (results to be expanded
at landing time, but on a sampled walk):

| File:line | Pattern | Action |
|---|---|---|
| `genl/wireguard/types.rs:343` | `UNIX_EPOCH + duration` | FIX (this plan) |
| (others to be enumerated during the sweep step) | | document each finding inline in the PR; fix the ones with the same panic shape |

Each unguarded site found gets the same shape of fix in the
same PR. If a site uses `u64` kernel input (not `i64`), the
sign check is unnecessary but the `checked_add` step still
applies. If a site is `Result`-shaped (returns
`Result<SystemTime>` not `Option<SystemTime>`), the failure
mode becomes a typed `Error::InvalidMessage` instead of `None`.

## 4. Test plan

### 4.1 Unit tests for `parse_timespec`

```rust
// crates/nlink/src/netlink/genl/wireguard/types.rs — new tests
//
// Plan 225 — adversarial input cases that pre-fix would have
// panicked in release mode.

#[cfg(test)]
mod parse_timespec_tests {
    use super::*;

    fn bytes(secs: i64, nsecs: i64) -> [u8; 16] {
        let mut out = [0u8; 16];
        out[..8].copy_from_slice(&secs.to_ne_bytes());
        out[8..].copy_from_slice(&nsecs.to_ne_bytes());
        out
    }

    #[test]
    fn returns_none_on_too_short_input() {
        assert!(parse_timespec(&[0u8; 15]).is_none());
        assert!(parse_timespec(&[]).is_none());
    }

    #[test]
    fn returns_none_on_zero_zero_no_handshake_sentinel() {
        assert!(parse_timespec(&bytes(0, 0)).is_none());
    }

    #[test]
    fn returns_none_on_negative_secs() {
        // Pre-fix: `secs as u64` produces u64::MAX-ish, and
        // `UNIX_EPOCH + Duration::from_secs(huge)` panics.
        assert!(parse_timespec(&bytes(-1, 0)).is_none());
        assert!(parse_timespec(&bytes(i64::MIN, 0)).is_none());
        assert!(parse_timespec(&bytes(-1, 500_000_000)).is_none());
    }

    #[test]
    fn returns_none_on_negative_nsecs() {
        assert!(parse_timespec(&bytes(0, -1)).is_none());
        assert!(parse_timespec(&bytes(100, -1)).is_none());
    }

    #[test]
    fn returns_none_on_out_of_range_nsecs() {
        // Anything >= 1_000_000_000 is kernel-garbage.
        assert!(parse_timespec(&bytes(0, 1_000_000_000)).is_none());
        assert!(parse_timespec(&bytes(0, 1_500_000_000)).is_none());
        assert!(parse_timespec(&bytes(0, i64::MAX)).is_none());
    }

    #[test]
    fn returns_none_on_overflow_to_far_future() {
        // i64::MAX seconds + UNIX_EPOCH overflows SystemTime.
        // Pre-fix: panic. Post-fix: None via checked_add.
        assert!(parse_timespec(&bytes(i64::MAX, 0)).is_none());
    }

    #[test]
    fn returns_some_on_a_real_handshake_timestamp() {
        // 2024-01-01 00:00:00 UTC — well within range.
        let secs = 1_704_067_200_i64;
        let nsecs = 123_456_789_i64;
        let st = parse_timespec(&bytes(secs, nsecs))
            .expect("real timestamp must parse");
        let d = st.duration_since(UNIX_EPOCH).unwrap();
        assert_eq!(d.as_secs(), secs as u64);
        assert_eq!(d.subsec_nanos(), nsecs as u32);
    }
}
```

### 4.2 Subscriber-survives-bad-frame test

```rust
// crates/nlink/tests/integration/wg_subscriber_survives.rs
//
// Plan 225 — adversarial multicast frame must not kill the
// subscriber. Mirror of the parser-robustness rule 3 test
// pattern from Plan 193 §2.3.

#[tokio::test]
async fn wireguard_subscriber_survives_malformed_timestamp() {
    // Build a fake multicast event with a negative `secs` in
    // the handshake-time TLV, feed it through the event
    // parser, assert: event is dropped (or surfaced with
    // `last_handshake = None`), the parser returns to ready
    // state, the next valid event parses cleanly.

    let bad_frame = build_wg_event_with_bad_handshake_secs(-1);
    let good_frame = build_wg_event_with_handshake_secs(
        1_704_067_200,
        123_456_789,
    );
    let mut frames = [bad_frame.as_slice(), good_frame.as_slice()];
    let mut subscriber = mock_wireguard_subscriber(&mut frames);

    // The bad frame either drops or surfaces last_handshake =
    // None — either is acceptable per parser-robustness rule 3.
    let first = subscriber.next().await;
    // The good frame must come through with a valid timestamp.
    let second = subscriber.next().await.unwrap();
    assert!(second.last_handshake.is_some());
}
```

Tests live in `crates/nlink/tests/integration/`; no
`require_root!()` needed because the mock subscriber doesn't
need the kernel.

### 4.3 Sibling-site test sweep

For each sibling site fixed during §3's audit walk, a parallel
adversarial-input unit test in the same file. Same shape: feed
`i64::MIN`, `-1`, `i64::MAX`, out-of-range nsecs; assert no
panic.

## 5. Risks

- **Callers expected `parse_timespec` to never return `None`
  for non-zero input**. None of nlink's internal callers
  destructure unconditionally; they all match `Some/None`
  (verified by `grep -rn 'parse_timespec' crates/`). Downstream
  consumers using `parse_timespec` directly (it's `pub`)
  shouldn't be affected — the contract was always
  `Option<SystemTime>`, and `None` was always reachable on
  short input. Pre-fix, additional inputs panicked instead of
  returning `None`; post-fix they return `None`. That's a
  strictly broader `None` surface, not narrower.

- **The "negative secs = no-handshake-yet" semantic is
  ambiguous**. The kernel's documented sentinel is `(0, 0)`.
  Some older kernels may emit `(-1, 0)` for the same purpose
  on weird code paths; we treat that as malformed and return
  `None`. If users surface "I'm getting None on a freshly-
  connected peer," the root cause is kernel-side and a fix
  would be the right escalation path.

- **`Duration::new` normalization**. The `nanos % 10^9`
  normalization in `Duration::new` adds the carry to `secs`;
  if `secs` is close to `i64::MAX` and `nsecs` is close to
  `10^9` (which we now reject explicitly), the carry would
  overflow. Our guard `nsecs < 1_000_000_000` makes the carry
  zero, so the overflow path is unreachable post-fix.

- **Future kernel adds sub-microsecond fields**. If the kernel
  extends the timespec attribute (e.g., adds a `flags` u64),
  `data.len() > 16` is fine — the current code reads the first
  16 bytes and ignores the rest, matching CLAUDE.md `## Parser
  robustness` rule 1 (accept-larger-than-expected). No change
  needed.

## 6. Migration

Pure correctness fix. The function signature, the
`Option<SystemTime>` return type, and the documented
behaviour are unchanged. The set of inputs returning `None`
expands to cover negative `secs`, out-of-range `nsecs`, and
far-future overflow — all previously panic paths.

No downstream code needs to change. Downstream code that was
silently relying on the panic to abort processing (unlikely
to nonexistent) now sees `None` and continues.

CHANGELOG entry under `[Unreleased]`:

```markdown
### Fixed

- **`parse_timespec` panic on negative seconds.** The
  WireGuard event handler crashed in release mode on any
  malformed handshake timestamp with negative `secs` —
  `SystemTime + Duration::from_secs(huge)` overflowed and
  panicked. One bad multicast frame killed the entire
  `watch()` task and any sibling tasks on the runtime,
  violating CLAUDE.md `## Parser robustness` rule 3
  (recoverable per-message parse failures). Verified by
  reviewer repro. Fixed by sign-checking + `checked_add`.
  Plan 225.

- **Sibling sites swept**: any other `UNIX_EPOCH + Duration`
  construction in `crates/nlink/src/netlink/` is guarded the
  same way. (Per-file list in the migration guide.)
```

Migration guide note under `0.19.0-to-0.20.0.md`:

> If you destructured `Some(timestamp)` from `parse_timespec`
> unconditionally, your code already handled the documented
> `None` case (short input, zero-zero sentinel) — no change
> needed. The new `None` cases (negative `secs`, garbage
> `nsecs`, overflow) all map to "the kernel emitted a
> malformed frame," which is the same failure mode you were
> already seeing as a panic. You now get clean `None` and
> the subscriber stays alive.

## 7. Acceptance

- ✅ The `parse_timespec` body in §2 is in tree.
- ✅ The adversarial unit tests in §4.1 pass under
  `cargo test -p nlink --lib`.
- ✅ The mocked subscriber test in §4.2 passes.
- ✅ The audit sweep from §3 has enumerated every sibling
  site, and each one either matches the safe pattern or is
  fixed in the same PR.
- ✅ The CHANGELOG and migration-guide entries land at cut
  time.
- ✅ No new lint warnings from `cargo +stable clippy
  --workspace --all-targets --all-features -- --deny warnings`.

## 8. Cross-references

- [`AUDIT_BUGS.md`](../AUDIT_BUGS.md) B5 — repro at
  `/tmp/check_dur2.rs`, full panic message reproduced.
- `crates/nlink/src/netlink/genl/wireguard/types.rs:326-344`
  — the function being fixed.
- CLAUDE.md `## Parser robustness` rule 3 — the policy this
  violates and the policy the fix implements.
- [Plan 193](.) (historic, shipped 0.19) — phase 1 of the
  parser-robustness audit; Plan 225 extends the same
  discipline to time-handling.
- [Plan 220 master](220-0.20-master-plan.md) §3 — Plan 225's
  position in the P1 defensive-correctness cluster (alongside
  223, 224, 226).
- Rust `std::time::SystemTime::checked_add` —
  `https://doc.rust-lang.org/std/time/struct.SystemTime.html#method.checked_add`.
