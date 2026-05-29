---
to: nlink maintainers
from: nlink-lab upstream-asks report (2026-05-27) §Wishlist 1
subject: `impl Display for NftablesDiff` + `impl Display for NetworkDiff` — wraps existing `summary()` methods
status: queued for 0.18 — trivial, but the report overestimated the cost
target version: 0.18.0
parent: (none — single-deliverable plan)
source: nlink-lab maintainer report `nlink-upstream-asks.md` §Wishlist 1 (report estimated ~80 LOC; actual is ~15)
created: 2026-05-27
---

# Plan 183 — `Display` for diff types

## 1. Why this plan exists

`NftablesDiff` (`crates/nlink/src/netlink/nftables/config/diff.rs:226`)
and `NetworkDiff` (`crates/nlink/src/netlink/config/diff.rs:87`)
both already expose a `summary() -> String` method that renders
the canonical "12 changes: + table foo, ~ rule bar/baz, …"
output. But neither implements `std::fmt::Display`, so:

- `println!("{diff}")` doesn't work — caller has to write
  `println!("{}", diff.summary())`.
- `format!("apply failed: {}", diff)` doesn't work either —
  same shape.
- Logging consumers (`tracing::info!(?diff)` falls back to
  `Debug`, which is verbose and not human-friendly).

The nlink-lab maintainer asked for this and estimated ~80 LOC.
**Actual cost is ~15 LOC** because the `summary()` methods
already do the formatting work — `Display` is a thin wrapper.

## 2. The change

```rust
// crates/nlink/src/netlink/nftables/config/diff.rs (after the
// existing `impl NftablesDiff { fn summary() }` block)

impl std::fmt::Display for NftablesDiff {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.summary())
    }
}
```

Same shape for `NetworkDiff` (`crates/nlink/src/netlink/config/diff.rs`).

**Open question — does `summary()` allocate?** Yes (returns
`String`). For the high-volume logging case (a Display in
hot paths), this is a small inefficiency. Better:

```rust
impl std::fmt::Display for NftablesDiff {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Write directly to the formatter — no intermediate
        // String allocation. Mirror summary()'s line shape.
        self.write_summary(f)
    }
}
```

…and refactor `summary()` to call the same `write_summary`:

```rust
impl NftablesDiff {
    fn write_summary(&self, w: &mut impl std::fmt::Write) -> std::fmt::Result {
        // (existing summary body, but using `writeln!(w, …)`
        // instead of pushing to a String)
    }

    /// Backwards-compat: existing callers of `.summary()` keep
    /// the `String` return type.
    pub fn summary(&self) -> String {
        let mut s = String::new();
        let _ = self.write_summary(&mut s);
        s
    }
}
```

This avoids the double-allocation for `format!("{diff}")` calls
while keeping the existing `.summary()` API intact.

## 3. Tests

In the same test module that covers `summary()`:

```rust
#[test]
fn display_matches_summary() {
    let diff = NftablesDiff::default();  // empty
    assert_eq!(format!("{diff}"), diff.summary());

    let mut diff = NftablesDiff::default();
    // ... push a couple of changes ...
    assert_eq!(format!("{diff}"), diff.summary());
}

#[test]
fn display_no_alloc_no_string_intermediate() {
    // Smoke test that the Display impl works through a Formatter
    // path (no panic when fed a buffered writer).
    let diff = NftablesDiff::default();
    let mut buf = String::new();
    use std::fmt::Write;
    write!(&mut buf, "{diff}").unwrap();
    assert_eq!(buf, diff.summary());
}
```

Same shape for `NetworkDiff`. 4 tests total (2 per type).

## 4. Acceptance criteria

- [ ] `impl Display for NftablesDiff` exists; output matches
      `summary()` byte-for-byte.
- [ ] `impl Display for NetworkDiff` ditto.
- [ ] `summary()` keeps working (no caller breaks).
- [ ] If the no-alloc refactor is taken, both `summary()` and
      `Display` route through the same `write_summary` private
      helper to keep one source of truth.
- [ ] 4 unit tests.
- [ ] CHANGELOG `### Added` entry: 2-line note explaining
      `println!("{diff}")` now works.

## 5. Effort estimate

| Phase | Effort (minimal version) | Effort (no-alloc refactor) |
|---|---|---|
| Code | ~5 min | ~30 min |
| Tests (4) | ~15 min | ~15 min |
| CHANGELOG | ~5 min | ~5 min |
| **Total** | **~25 min** | **~50 min** |

Recommend the no-alloc refactor — same shipping cost, cleaner
internals, removes an allocation from a hot path that
controller dashboards will hit.

## 6. Risks — none

`Display` is additive. `summary()` keeps the same `String`
return type. No observable behaviour change for existing
callers; `format!("{diff}")` is the only new path.

## 7. Out-of-scope follow-ups

- **`{:#}` alternate form** — the report mentions a
  Debug-rich alternate form for `nft --debug=mnl`-style raw-
  attribute dump. Defer: no consumer signal yet, and the
  shape isn't obvious (raw bytes? attribute-tree? both?).
- **`Display for ReconcileReport`** — the report flags this
  too. Same one-liner shape. Bundle if free; otherwise defer.

End of plan.
