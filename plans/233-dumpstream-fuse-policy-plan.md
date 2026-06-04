---
to: nlink maintainers
from: 0.20 cycle pre-work — deep audit derivation
subject: DumpStream fuse-on-malformed policy — opt-in skip mode
status: planning
target version: 0.20.0
parent: [Plan 220 master](220-0.20-master-plan.md)
source: [AUDIT_BUGS.md](../AUDIT_BUGS.md) B7 + B16; CLAUDE.md `## Parser robustness` rule 3
created: 2026-06-04
---

# Plan 233 — `DumpStream` fuse-on-error policy

## 1. Why this plan exists

`DumpStream::drain_into_pending` (`dump_stream.rs:147-156`) fuses
the stream on the first malformed frame. B7 in `AUDIT_BUGS.md`
flags this as a contradiction with CLAUDE.md "Parser robustness
rule 3": *"event parsers that walk `MessageIter::new(data)` MUST
silently skip parse errors rather than propagating via `?`"*.

The audit's reading is half-right. Rule 3 was written about
**multicast event subscribers** — where the contract is
"long-lived stream of best-effort notifications, one bad frame
must not kill the subscriber". Dumps are a different contract:
the caller asked for *the full snapshot*. Silently dropping a
frame violates correctness for the user who actually wanted
correctness, which is the whole point of calling `dump_*` over
subscribing to multicast deltas.

So the fix isn't "make `DumpStream` flatten like rule 3 says".
The fix is to:

1. **Document the dump-vs-event distinction explicitly** in
   CLAUDE.md and on `DumpStream`'s doc-comment, so the next
   audit doesn't surface this as a "violation" again.
2. **Offer an opt-in** for the dump-but-best-effort case
   (`with_skip_malformed(true)`) for callers who'd rather have
   a partial dump than no dump at all.
3. **Verify the event-stream APIs do flatten** (per rule 3) so
   the distinction holds.

B16 in the audit is structurally adjacent (typed-parse failure
behavior on the SAME stream type) — it's re-read as a non-bug,
but the policy clarification in this plan makes the contract
explicit so future readers don't re-relitigate it.

## 2. The policy

```
| API shape                      | Default     | Opt-in       |
|--------------------------------|-------------|--------------|
| Dump (full snapshot)           | hard-fail   | skip+trace   |
| Event subscription (long-lived)| skip+trace  | (none)       |
```

**Default for dumps**: parse error → `Some(Err(e))` then the
stream fuses (current behavior). The caller asked for the full
snapshot; silently delivering a partial one is the wrong default
in every case where the caller is doing something that depends
on snapshot completeness (reconciliation loops, capacity
planning, audit log generation, etc.).

**Default for events**: per-frame parse errors skip the bad
frame and log at `tracing::warn!` level. The caller can't get
"completeness" from a multicast stream by definition (it's a
moving target); the right tradeoff is liveness over correctness.

**The opt-in (`.with_skip_malformed(true)` on `DumpStream`)** is
for the niche where a caller wants "all the rows the kernel can
serve me, but don't die if one frame is corrupt". Logs every
skip at WARN. Doesn't fuse. The caller acknowledges the partial-
snapshot risk by opting in.

The policy is asymmetric on purpose: events don't get a "hard-
fail" opt-in because there's no contract where that's the right
behaviour (any malformed event still leaves the stream alive on
the multicast group; failing the stream just means the caller
re-subscribes and misses MORE events in the gap).

## 3. The opt-in design

```rust
// Add to DumpStream
impl<T: FromNetlink> DumpStream<T> {
    /// Continue past malformed frames instead of fusing the
    /// stream. Each skip logs at `tracing::warn!` level with
    /// the parse error. Default is hard-fail (snapshot
    /// completeness > liveness).
    ///
    /// Use this when the caller would rather have a partial
    /// dump than no dump at all — e.g. exporting a best-effort
    /// metric to a dashboard.
    pub fn with_skip_malformed(mut self, skip: bool) -> Self {
        self.skip_malformed = skip;
        self
    }
}
```

The field defaults to `false`. The constructor signature
(`Connection::dump_stream`) doesn't change. The opt-in is
purely a fluent setter on the returned stream.

Implementation detail in `drain_into_pending`:

```rust
fn drain_into_pending(&mut self, data: &[u8]) {
    for result in MessageIter::new(data) {
        let (header, payload) = match result {
            Ok(p) => p,
            Err(e) => {
                if self.skip_malformed {
                    tracing::warn!(error = %e, "DumpStream: skip malformed frame");
                    continue;
                }
                self.pending.push_back(Err(e));
                self.errored = true;
                return;
            }
        };
        // ...
    }
}
```

## 4. Per-stream-API audit

Walk the full list of public stream-shape APIs and document the
behaviour each will have after this plan:

| API | Path | Current | Post-plan |
|---|---|---|---|
| `Connection::dump_stream::<T>(msg_type)` | `connection.rs` | fuse-on-error | fuse (default) / skip (opt-in) |
| `Connection::stream_links()` | `connection.rs` | fuse | fuse / opt-in |
| `Connection::stream_routes()` | `connection.rs` | fuse | fuse / opt-in |
| `Connection::stream_addresses()` | `connection.rs` | fuse | fuse / opt-in |
| `Connection::stream_neighbors()` | `connection.rs` | fuse | fuse / opt-in |
| `Connection::stream_qdiscs()` / `_classes` / `_filters` | `connection.rs` | fuse | fuse / opt-in |
| `Connection::stream_sas()` / `stream_sps()` | xfrm | fuse | fuse / opt-in |
| `Connection::stream_conntrack()` | netfilter | fuse | fuse / opt-in |
| `Connection::stream_rules()` | nftables | fuse | fuse / opt-in |
| `Connection::events()` / `into_events()` | `connection.rs` | flatten (Plan 193 §2.3) | unchanged |
| `Connection::events_with_resync()` (subscribe wrappers) | stream/resync | flatten | unchanged |
| `Connection<Generic>::subscribe_*()` (dpll/nftables/wg) | per family | flatten | unchanged — verify in §6 |
| `Connection::subscribe_all()` (rtnetlink groups) | `connection.rs` | flatten | unchanged |

The dump variants are unified — they all delegate to
`DumpStream<T>` via the typed wrappers. The event variants are
heterogeneous (per-family event parsers); the audit needs to
confirm rule-3 compliance for each. `scripts/audit-recv-loop-
error-handling.sh` already greps for this in the
`MessageIter::new(...)` walking context — see §7.

## 5. CLAUDE.md update

Insert a sub-section under `## Parser robustness`:

```markdown
### Rule 3 applies to events, not dumps

Dump APIs (`DumpStream<T>`, `stream_*`, `dump_*`) intentionally
fuse on malformed frames. The caller asked for the full snapshot;
silently dropping rows would deliver wrong-data-with-no-error to
a reconcile loop or audit log. Use
`DumpStream::with_skip_malformed(true)` for the explicit "best
effort" opt-in (logged at WARN, doesn't fuse).

Event APIs (`events()`, `into_events()`, `subscribe_*()`) follow
rule 3 as written: skip malformed frames, log at TRACE, the
subscriber stays alive. There is no opt-in for "fail on first
bad event" — re-subscribing after a stream death only widens the
event-loss window.
```

## 6. Test plan

- Unit test (`dump_stream::tests::fuses_on_malformed_by_default`):
  feed a synthetic stream with two valid frames then a malformed
  one then another valid frame; assert the stream yields
  `Some(Ok(t1))`, `Some(Ok(t2))`, `Some(Err(_))`, `None`.
- Unit test (`dump_stream::tests::skip_malformed_continues`):
  same input, opt-in; assert `Some(Ok(t1))`, `Some(Ok(t2))`,
  `Some(Ok(t4))`, `None`. Verify the WARN log fires by capturing
  `tracing_subscriber::fmt::TestWriter` (or just count via a
  test-only counter).
- Audit-script update: `scripts/audit-recv-loop-error-handling.sh`
  currently checks all `MessageIter::new(...)` walkers for the
  flatten pattern. Update it to recognize `DumpStream`-context
  walks as exempt (the fuse pattern is intentional there). The
  audit table in §4 doubles as the allow-list.
- Per-family event-stream verification (§4 rows tagged
  "unchanged — verify"): grep each family's event parser for
  `?` inside a `MessageIter::new(data)` for-loop. If any are
  found, that's a separate bug; queue as a follow-up.

## 7. Risks

- **Silently changed event behaviour**. The plan claims event
  streams already flatten; if the audit step in §6 finds a
  family that doesn't, fixing it in this plan changes the
  observable behaviour for that family (one bad event → drop
  vs kill-stream). Mitigation: §6's verification step is a
  pre-merge gate; any family-stream that's NOT flattening today
  gets a callout in the PR description with the maintainer's
  judgment call on whether to flip in 0.20 or hold.

- **Opt-in is YAGNI**. There's no concrete user asking for
  `with_skip_malformed`. If no one ever uses it, it's API
  surface area for nothing. Mitigation: the opt-in is one
  method + one boolean field; the cost-to-maintain is near-zero.
  And the documentation it generates (the visible "this is
  opt-in because the default cares about correctness") is the
  real value — the method is a teaching artifact.

- **Doc drift from CLAUDE.md update**. The new rule-3 subsection
  becomes the authoritative reference; existing rustdoc on
  `DumpStream` and `MessageIter` needs to point at it.
  Mitigation: the plan ships the rustdoc + CLAUDE.md edit
  together; reviewers verify both.

- **`audit-recv-loop-error-handling.sh` regression**. The
  script's allow-list now needs to track DumpStream context.
  If the test grep loses precision (false-positives on
  unrelated code), the gate fires on every PR. Mitigation:
  the script greps for the literal string
  `MessageIter::new(data)` in files matching a path pattern;
  add a `DumpStream` exemption by path (the dump_stream.rs file)
  not by inline tag. Easy to maintain.

## 8. Migration

None for the default behaviour — it matches current behaviour
exactly. Callers who want the new opt-in add `.with_skip_malformed(true)`
to their `dump_stream::<T>(...).await?` chain.

The CHANGELOG entry under `## [Unreleased]` documents:

```markdown
### Added
- `DumpStream::with_skip_malformed(bool)` — opt-in to continue
  past malformed frames instead of fusing the stream. Defaults
  to `false` (preserves the snapshot-completeness contract that
  dumps imply). Skips log at `tracing::warn!`.

### Documentation
- CLAUDE.md `## Parser robustness` gains a sub-section
  clarifying that rule 3 (skip+log on malformed frames) applies
  to event subscribers, not dump streams. Dumps intentionally
  fuse; see `DumpStream::with_skip_malformed` for the explicit
  opt-out.
```

## 9. Acceptance

The plan lands when:

- `DumpStream::with_skip_malformed` shipped.
- 2 unit tests pass.
- §4's audit table is reflected in
  `scripts/audit-recv-loop-error-handling.sh` allow-list.
- Per-family event-stream verification done (§6); any
  flatten-violators escalated to a separate fix.
- CLAUDE.md `## Parser robustness` updated with the dump-vs-event
  sub-section.
- CHANGELOG entries written.

## 10. Cross-references

- [`AUDIT_BUGS.md`](../AUDIT_BUGS.md) findings B7 (default-fuse
  policy) + B16 (typed-parse non-bug, kept as adjacent note).
- CLAUDE.md `## Parser robustness` (rule 3 source).
- `scripts/audit-recv-loop-error-handling.sh` (the CI gate that
  enforces rule 3 today).
- [Plan 193](193-message-iter-attr-iter-tests-plan.md) (0.19) —
  the prior pass that pinned rule 3's policy and added the gate.
- [Plan 149](149-streaming-dump-plan.md) (0.16) — `DumpStream`'s
  original design plan; the original docstring at line 35-36
  encodes the fuse policy without yet contrasting it against
  events.
