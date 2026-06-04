---
to: nlink maintainers
from: 0.20 cycle pre-work — deep audit derivation
subject: LOW-tier bug-hunt batch — 11 small fixes from AUDIT_BUGS.md
status: planning
target version: 0.20.0
parent: [Plan 220 master](220-0.20-master-plan.md)
source: [AUDIT_BUGS.md](../AUDIT_BUGS.md) B6, B9, B10, B11, B13, B14, B15, B17, B18, B19 (B16/B20 are non-bugs — closed by the audit itself)
created: 2026-06-04
---

# Plan 232 — Bug-hunt LOW-tier batch

## 1. Why this plan exists

The 0.20 audit (`AUDIT_BUGS.md`) surfaced 20 bug-hunt findings.
The CRITICAL/HIGH ones are carved out into focused plans (Plan
221 for XFRM, Plan 223 for the BE sweep, Plan 224 for `recv_msg`
truncation, Plan 225 for `parse_timespec`). The LOW-severity
findings — 11 of them — are each one-line cleanups that don't
merit a standalone plan but DO merit a single batched PR so the
audit doesn't get closed by inactivity.

Convention from prior cycles (Plan 147 in 0.16, Plan 212 in
0.19): one PR for "robustness hygiene" with a clearly-bounded
finding table. The PR diff is wide (many files, ~250 LOC), but
each hunk is independently obvious and reviewable. The risk is
**not** that any one fix breaks something — it's that touching
11 files in one commit obscures the per-finding rationale, which
is why the table in §2 stays the source of truth.

Two of the original 11 (B16, B20) re-read as non-bugs during the
audit pass and are not in scope here. B7 and B12 are MEDIUM and
get their own plan (Plan 233 for B7; B12 is a Plan 234 surface
when the dispatcher lands or stays open otherwise — see §5).

## 2. The findings table

Ordered LOW first (per audit severity), with file:line, the fix,
and a one-line test where applicable. **B6 is wontfix-candidate**
— flagged for maintainer call.

| # | File:line | Finding | Fix | Test |
|---|---|---|---|---|
| B6 | `audit.rs:458`, `sockdiag.rs:298-300` | `Error::from_errno(-errno)` double-negates (LOW; not wrong) | **Decision needed**: leave for clarity OR replace with `from_errno_with_context(errno, "audit_set_status")` per Plan 212 M9/M16 convention | Lib test asserts the operation tag appears in `Error::Display` |
| B9 | `connection.rs:632-639` | `msg_start = ptr_arithmetic - HDRLEN` is unreviewable | Replace with `MessageIter` yielding `(header, payload, full_msg_bytes)`; remove the pointer subtraction | Existing `send_dump_inner` tests cover; no new test needed |
| B10 | `parse.rs:180-183` | `parse_string_from_bytes` swallows invalid UTF-8 → empty string | Switch to `String::from_utf8_lossy(&data[..end]).into_owned()`; events with non-UTF-8 names now log U+FFFD instead of going missing | Unit: `parse_string_from_bytes(b"foo\xff\xfebar\0")` returns `"foo\u{fffd}\u{fffd}bar"` |
| B11 | `genl/wireguard/config.rs:304,334` | `.expect("declared device must exist for entry in diff")` panic path | Return `Err(Error::InvalidMessage(format!("wireguard apply: diff references undeclared device `{ifname}`")))` instead of panicking | Unit: synthetic diff with stale device → assert `is_invalid_message()` |
| B13 | `connector.rs:506-602` | Unknown `header.what` falls through to `None`; subscriber silently drops events | Add `ProcEvent::Unknown { what: u32, raw_bytes: Vec<u8> }` variant; return it from the `_ =>` arm; matches `Event::Unknown` precedent | Unit: feed a synthetic `what = 0xDEADBEEF` event; assert it surfaces as `ProcEvent::Unknown { what: 0xDEADBEEF, .. }` |
| B14 | `nftables/connection.rs:1062-1215` | `.unwrap()` after `payload.len() >= 4` length guard; safe but inconsistent | Refactor through `attr::get::u32_be(payload)?` so guard + cast are co-located; matches conntrack/dpll parsers | Existing nftables parse tests cover the happy path; no new test |
| B15 | `audit.rs:486-510` | 32-byte short-struct fallback zeros all fields past byte 32; kernel struct between 32 and `size_of` truncates silently | Walk fields with per-offset bounds checks; tolerate any size ≥ 32 bytes per CLAUDE.md "Parser robustness rule 1" | Unit: synthetic 48-byte struct → assert middle fields parse, trailing zeros default |
| B17 | `socket.rs:367-383` | `recv_msg` allocs new 32 KiB `BytesMut` per call; recv-loops churn | Reuse via thread-local scratch matching `recv_batch_inner`; or stash a `BytesMut` on `NetlinkSocket` | None — perf only. Bench (microbench in a `#[ignore]` test) before/after if useful |
| B18 | `message.rs:15-17` | `nlmsg_align` debug-panics on `len + 3` `usize` overflow | `len.checked_add(NLMSG_ALIGNTO - 1).ok_or(Error::InvalidMessage("nlmsg_align overflow"))?` | Unit: `nlmsg_align(usize::MAX)` returns `Err`, not panic |
| B19 | `socket.rs:352-364` | `send` loops on `WouldBlock` without a cap; tight spin until 30s `Connection` timeout | After `Connection::config().backpressure_threshold` (default 32) back-to-back `WouldBlock`s, return `Error::Backpressure { send_buffer_full: true }` | Unit: mock `Socket::send` returns WouldBlock 33 times; assert `is_backpressure()` |

### 2.1 Excluded from this batch

| # | Why excluded |
|---|---|
| B7 | MEDIUM — gets Plan 233 (DumpStream fuse policy) |
| B8 | MEDIUM — `execute_in` swallow; out of scope for this batch (its own fix needs a typed `Error::NamespaceRestoreFailed` discipline pass that's bigger than a one-liner). Note in the next-cycle seed |
| B12 | LOW — stale-seq accumulation; the right fix is the dispatcher (Plan 234). Documenting on `Connection<P>` doc-comment is in scope; queue the `drain()` helper for Plan 234 |
| B16 | Re-read confirms non-bug (audit notes itself) |
| B20 | Re-read confirms non-bug (audit notes itself) |

## 3. Per-finding details

Most rows in §2 are self-contained. Three warrant more notes.

### 3.1 B6 — the wontfix question

The audit calls B6 LOW and notes it's "redundant but not wrong".
The two callsites:

```rust
// audit.rs:458
return Err(Error::from_errno(-errno));

// sockdiag.rs:298-300
return Err(Error::from_errno(-errno));
```

`Error::from_errno` does `errno.abs()` internally, so the leading
`-` is a no-op. Plan 212 M9/M16 set the convention that every
kernel-error construction site adds an operation tag via
`from_errno_with_context(errno, "<op>")`. These two sites pre-date
that convention.

**The maintainer call**: roll into this batch (cheap, aligns with
the post-0.19 convention) OR leave alone (the `-` is visible
documentation that "this errno came off the wire negative"). My
read: roll in. The convention sweep is more valuable than the
documentation hint.

### 3.2 B10 — `parse_string_from_bytes` lossy switch

The lossy switch is a behavior change visible to consumers of
`Event::LinkChanged { name, .. }` etc. For names with bytes
outside ASCII (kernel allows arbitrary content in `IFLA_IFNAME`),
the post-fix value contains U+FFFD where U+0000 would have
truncated and U+ANYTHING where the old code returned `""`.

This is strictly more information. Document in `CHANGELOG.md ##
[Unreleased]` under "Changed" so downstream code that splits on
`name.is_empty()` for "unparseable" can switch to
`name.contains(char::REPLACEMENT_CHARACTER)`.

### 3.3 B17 — scratch-buffer reuse

The implementation choice is between:

- **Thread-local scratch** — matches `recv_batch_inner`'s shape;
  no new field on `NetlinkSocket`.
- **Connection-owned scratch** — a `Mutex<BytesMut>` (or
  `parking_lot::Mutex` for lower overhead) on `NetlinkSocket`;
  guaranteed reuse across calls on the same connection.

The thread-local wins on simplicity and matches the existing
pattern. Going Connection-owned would be a larger refactor not
worth doing in a LOW-tier batch.

## 4. Test plan

Per-finding tests are in §2's table. Aggregate:

- `cargo test -p nlink --lib` — gates the per-finding unit tests
  (5 new tests: B10, B11, B13, B15, B18, B19).
- `cargo clippy --workspace --all-targets --all-features -- --deny warnings`
  — gates the style-only changes (B14, B6 if rolled in).
- No integration tests needed; all findings are unit-testable
  with synthetic inputs.

The B17 perf change is unmeasured by CI. A `#[ignore]`d microbench
under `crates/nlink/tests/perf/scratch_buffer_bench.rs` would
document the win but isn't gating.

## 5. Risks

- **Wide diff obscures intent**. Mitigation: commit per finding
  (11 commits, one PR). The reviewer can step through each. The
  CHANGELOG entry per finding stays one-liner.

- **B10 (`parse_string_from_bytes` lossy)** is a visible behavior
  change. Mitigation: CHANGELOG `## [Unreleased]` entry under
  "Changed" with the new shape explicit ("invalid UTF-8 bytes now
  surface as U+FFFD instead of truncating the name to `""`").

- **B19 (`Error::Backpressure` new variant)** is a new public
  enum variant on `Error`. Mitigation: the error enum is
  `#[non_exhaustive]` (Plan 163); adding a variant is
  non-breaking. The corresponding `is_backpressure()` predicate
  follows the existing predicate-pattern convention from CLAUDE.md
  `## Errors`.

- **B6 (`from_errno_with_context`)** changes the format of two
  error messages. Mitigation: nothing downstream parses these
  strings (they're operator-facing). Confirm with `grep -r
  is_audit_status` etc. in nlink-consumer code if any is visible.

## 6. Acceptance

The batch lands when:

- 11 (or 10 if B6 is wontfix) findings in §2 are resolved.
- 5 new unit tests pass (B10, B11, B13, B15, B18, B19).
- `cargo clippy --workspace --all-targets --all-features --
  --deny warnings` is green.
- `cargo machete` reports no new unused deps.
- CHANGELOG `## [Unreleased]` carries one bullet per finding
  under the appropriate "Fixed" / "Changed" sub-heading.
- The "B6 decision: rolled in" or "B6: wontfix per maintainer"
  line is in the PR description.

## 7. Cross-references

- [`AUDIT_BUGS.md`](../AUDIT_BUGS.md) findings B6, B9, B10, B11,
  B13, B14, B15, B17, B18, B19 (full evidence + repro notes).
- [`AUDIT_REPORT.md`](../AUDIT_REPORT.md) §P3 "Plan X11 —
  Bug-hunt LOW-tier sweep" (the prioritized entry that
  authorized this batch).
- [Plan 212](212-error-api-hygiene-plan.md) (0.19) — the prior
  hygiene-sweep precedent; convention for `from_errno_with_context`.
- [Plan 233 (DumpStream fuse policy)](233-dumpstream-fuse-policy-plan.md)
  — sibling plan covering B7 + B16.
- CLAUDE.md `## Errors` (predicate convention), `## Parser
  robustness` rule 1 (B15's "accept-larger-than-expected"
  invocation).
