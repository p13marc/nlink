---
to: nlink maintainers
from: 0.19 consolidation-pass research agent (2026-05-30) — kube-rs ecosystem audit
subject: `StreamBackoff` + `predicate_filter` + `default_backoff()` extension trait on `ResyncStream`
status: queued for 0.19 — low (compose-on-top; doesn't change existing API)
target version: 0.19.0
parent: builds on Plans 185 (nftables) + 191 (route) watchers
source: kube-rs `WatchStreamExt` audit (https://github.com/kube-rs/kube/blob/main/kube-runtime/src/watcher.rs)
created: 2026-05-30
---

# Plan 195 — Stream combinators on `ResyncStream`

## 1. Why this plan exists

Plan 185 (0.18) shipped `Connection<Nftables>::into_events_with_resync(factory)`
mirroring `kube_rs::watcher(api, cfg)`. Plan 191 (0.19) ships
the Route twin. Both yield `Stream<Item = Result<ResyncedEvent<T>>>`.

`kube-rs` has spent two years polishing combinators that
compose on top of `watcher`. The shape is `WatchStreamExt`
— a trait providing `default_backoff()`, `predicate_filter()`,
etc. Adopting these for nlink's resync streams:

- Keeps the resync wrapper minimal (it doesn't try to handle
  backoff or filtering internally — composition over
  configuration)
- Lets consumers pick + swap policies easily
- Matches the kube-rs idiom that ~every downstream Rust
  developer doing Kubernetes work already knows

This plan ships an `nlink::stream::ResyncStreamExt` extension
trait with three combinators + a `StreamBackoff` wrapper +
documentation. Applies to BOTH the nftables and Route
watchers without per-protocol duplication.

## 2. The change — three combinators + one wrapper

### 2.1 `ResyncStreamExt::default_backoff()`

```rust
// crates/nlink/src/netlink/resync_ext.rs (new file)

use std::time::Duration;
use tokio_stream::Stream;

use super::resync::ResyncedEvent;

/// Extension trait providing composable combinators on top
/// of [`ResyncStream`] (and any equivalent
/// `Stream<Item = Result<ResyncedEvent<T>>>`).
///
/// Mirrors [`kube-rs`' `WatchStreamExt`][kube-watch-stream]
/// shape: small composable adapters that wrap the underlying
/// resync stream without coupling backoff / dedup policy to
/// the snapshot/factory mechanism.
///
/// [kube-watch-stream]: https://docs.rs/kube-runtime/latest/kube_runtime/utils/trait.WatchStreamExt.html
pub trait ResyncStreamExt<T>: Stream<Item = crate::Result<ResyncedEvent<T>>>
    + Sized
{
    /// Apply a default exponential-backoff retry policy to the
    /// stream.
    ///
    /// Defaults: min 800ms, max 30s, factor 2.0, ±10% jitter,
    /// reset window 120s. Matches kube-rs's `default_backoff()`
    /// values verbatim; the policy is well-tested across
    /// Kubernetes ecosystems and a reasonable starting point
    /// for any drift-watching consumer.
    ///
    /// For custom policies, wrap with [`StreamBackoff`] directly
    /// (see §2.4).
    fn default_backoff(self) -> StreamBackoff<Self, T> {
        StreamBackoff::new(self, BackoffPolicy::default())
    }

    /// Dedupe deltas by a key function. Useful when the
    /// underlying stream re-emits events on unrelated changes
    /// (e.g. an `Addr` event on every neighbor-cache update).
    ///
    /// The key function picks the fields that constitute a
    /// "meaningful change"; deltas matching the previous
    /// item's key are silently dropped from the stream.
    ///
    /// Mirrors `WatchStreamExt::predicate_filter`.
    fn predicate_filter<K, F>(self, key: F) -> PredicateFilter<Self, T, K, F>
    where
        K: PartialEq + Clone,
        F: FnMut(&ResyncedEvent<T>) -> K,
    {
        PredicateFilter::new(self, key)
    }

    /// Map the inner `T` of every `Event(T)` / `Resynced(T)`
    /// item via the closure. Markers pass through untouched.
    ///
    /// Convenience for consumers that want to project the
    /// event payload to a domain-specific type once at the
    /// edge.
    fn map_event<U, F>(self, f: F) -> MapEvent<Self, T, U, F>
    where
        F: FnMut(T) -> U,
    {
        MapEvent::new(self, f)
    }
}

// Blanket impl over every Stream of the right shape.
impl<S, T> ResyncStreamExt<T> for S
where
    S: Stream<Item = crate::Result<ResyncedEvent<T>>>,
{
}
```

### 2.2 `StreamBackoff<S, T>` — the wrapper

```rust
// crates/nlink/src/netlink/resync_ext.rs

/// An exponential-backoff wrapper for ENOBUFS-prone streams.
///
/// On every non-recoverable error, sleeps for `policy.next_delay()`
/// before re-polling. Resets the backoff window after
/// `policy.reset_window` of clean events.
pub struct StreamBackoff<S, T>
where
    S: Stream<Item = crate::Result<ResyncedEvent<T>>>,
{
    inner: S,
    policy: BackoffPolicy,
    state: BackoffState,
}

#[derive(Debug, Clone)]
pub struct BackoffPolicy {
    pub min: Duration,
    pub max: Duration,
    pub factor: f64,
    pub jitter: f64,        // 0.0..=1.0 fractional jitter
    pub reset_window: Duration,
}

impl Default for BackoffPolicy {
    fn default() -> Self {
        // kube-rs defaults verbatim.
        Self {
            min: Duration::from_millis(800),
            max: Duration::from_secs(30),
            factor: 2.0,
            jitter: 0.1,
            reset_window: Duration::from_secs(120),
        }
    }
}

enum BackoffState {
    Open,                        // forwarding events
    Sleeping(tokio::time::Sleep, Duration),  // current delay
}
```

### 2.3 `PredicateFilter<S, T, K, F>` + `MapEvent<S, T, U, F>`

Adapter shapes mirror `StreamExt::filter_map` /
`StreamExt::map`. Both are `~50 LOC` each, no new
infrastructure needed.

### 2.4 Re-exports + recipe

```rust
// crates/nlink/src/lib.rs (after the existing resync re-exports)

pub use netlink::resync_ext::{
    BackoffPolicy, MapEvent, PredicateFilter, ResyncStreamExt,
    StreamBackoff,
};
```

Add a docs recipe (`docs/recipes/resync-with-backoff.md`)
showing the kube-rs-style usage:

```rust
use nlink::netlink::resync_ext::ResyncStreamExt;
use tokio_stream::StreamExt;

let mut watch = conn
    .into_events_with_resync(factory)?
    .default_backoff()
    .predicate_filter(|ev| key_of(ev));

while let Some(ev) = watch.next().await {
    handle(ev?);
}
```

## 3. Implementation phases

| Phase | Files | LOC |
|---|---|---|
| 1 — `ResyncStreamExt` trait + blanket impl | new `resync_ext.rs` | ~30 |
| 2 — `StreamBackoff` + `BackoffPolicy` + Stream impl | `resync_ext.rs` | ~150 |
| 3 — `PredicateFilter` + Stream impl | `resync_ext.rs` | ~60 |
| 4 — `MapEvent` + Stream impl | `resync_ext.rs` | ~50 |
| 5 — Re-exports in `lib.rs` | `lib.rs` | ~5 |
| 6 — Recipe | new doc | ~100 |
| 7 — Tests (see §4) | various | ~250 |
| **Total** | | **~645 LOC** |

## 4. Tests

### 4.1 Unit — `BackoffPolicy::next_delay` math

```rust
#[test]
fn backoff_starts_at_min_and_doubles_within_factor() {
    let mut policy = BackoffPolicy::default();
    let mut state = BackoffState::Open;

    // Synthesize 3 consecutive failures and assert the
    // delays grow per the factor.
    let d1 = state.advance_on_error(&policy);  // ~800ms ±jitter
    let d2 = state.advance_on_error(&policy);  // ~1.6s
    let d3 = state.advance_on_error(&policy);  // ~3.2s

    assert!(d1 >= Duration::from_millis(720) && d1 <= Duration::from_millis(880));
    assert!(d2 >= Duration::from_millis(1440) && d2 <= Duration::from_millis(1760));
    assert!(d3 >= Duration::from_millis(2880) && d3 <= Duration::from_millis(3520));
}

#[test]
fn backoff_caps_at_max() {
    let policy = BackoffPolicy {
        min: Duration::from_secs(1),
        max: Duration::from_secs(5),
        factor: 10.0,
        jitter: 0.0,
        ..Default::default()
    };
    let mut state = BackoffState::Open;
    // After enough doublings, delay hits the cap.
    for _ in 0..10 {
        state.advance_on_error(&policy);
    }
    let d = state.advance_on_error(&policy);
    assert!(d <= Duration::from_secs(5), "delay must not exceed max");
}

#[test]
fn backoff_resets_after_window_of_clean_events() {
    // ...
}
```

### 4.2 Unit — `PredicateFilter` dedup

```rust
#[test]
fn predicate_filter_dedupes_consecutive_equal_keys() {
    let stream = futures::stream::iter(vec![
        Ok(ResyncedEvent::Event(("a", 1))),
        Ok(ResyncedEvent::Event(("a", 2))),  // same key, drop
        Ok(ResyncedEvent::Event(("b", 1))),
        Ok(ResyncedEvent::Event(("a", 3))),  // key changed back
    ]);
    let filtered: Vec<_> = stream.predicate_filter(|e| match e {
        ResyncedEvent::Event((k, _)) => *k,
        _ => "",
    }).collect().block_on().unwrap();
    assert_eq!(filtered.len(), 3, "duplicate ('a', 2) must be dropped");
}

#[test]
fn predicate_filter_passes_markers_unchanged() {
    // ResyncStart / ResyncEnd markers must NOT be deduped —
    // they're state-machine signals.
}
```

### 4.3 Unit — `MapEvent` transform

```rust
#[test]
fn map_event_transforms_event_and_resynced_variants() {
    let stream = futures::stream::iter(vec![
        Ok(ResyncedEvent::Event(5)),
        Ok(ResyncedEvent::Resynced(10)),
        Ok(ResyncedEvent::Marker(ResyncMarker::ResyncStart)),
    ]);
    let mapped: Vec<_> = stream.map_event(|i: i32| i * 2).collect().block_on().unwrap();
    match mapped[0].as_ref().unwrap() {
        ResyncedEvent::Event(v) => assert_eq!(*v, 10),
        _ => panic!(),
    }
    match mapped[1].as_ref().unwrap() {
        ResyncedEvent::Resynced(v) => assert_eq!(*v, 20),
        _ => panic!(),
    }
    // Marker survives untouched (no map applied)
    assert!(matches!(
        mapped[2].as_ref().unwrap(),
        ResyncedEvent::Marker(ResyncMarker::ResyncStart)
    ));
}
```

### 4.4 Integration — backoff actually delays

```rust
#[tokio::test(start_paused = true)]
async fn backoff_delays_re_poll_after_error() {
    // Use tokio's paused clock so the test is deterministic.
    // Construct a stream that yields one Err, then a Marker;
    // wrap with default_backoff; assert the gap between
    // poll(Err) and poll(Marker) ≈ 800ms ±jitter.
    let stream = futures::stream::iter(vec![
        Err(nlink::Error::Other("fake".into())),
        Ok(ResyncedEvent::Marker(ResyncMarker::ResyncStart)),
    ]);
    let mut backed_off = stream.default_backoff();

    let t0 = tokio::time::Instant::now();
    let _err = backed_off.next().await.unwrap();
    let _marker = backed_off.next().await.unwrap();
    let elapsed = tokio::time::Instant::now() - t0;

    assert!(elapsed >= Duration::from_millis(700));
    assert!(elapsed <= Duration::from_millis(900));
}
```

### 4.5 No new kernel-side integration test

The combinators are pure stream adapters — kernel events are
out of scope. The existing root-gated tests for Plan 185 +
Plan 191 already exercise the stream end-to-end; adding
combinator coverage there would just bloat already-slow tests.

## 5. Acceptance criteria

- [ ] `ResyncStreamExt` trait with blanket impl on every
      `Stream<Item = Result<ResyncedEvent<T>>>`.
- [ ] `StreamBackoff`, `BackoffPolicy` (with kube-rs default
      values), `PredicateFilter`, `MapEvent`.
- [ ] Re-exports in `lib.rs`.
- [ ] Recipe `docs/recipes/resync-with-backoff.md`.
- [ ] 8+ unit tests covering backoff math, predicate
      dedup, map projection.
- [ ] 1 integration test using `tokio::test(start_paused)`
      for deterministic timing.
- [ ] CHANGELOG `### Added` entry; cross-reference Plan 185
      and Plan 191.

## 6. Effort estimate

| Phase | Effort |
|---|---|
| Code (~645 LOC) | ~3.5 h |
| Unit tests (8+) | ~1.5 h |
| Integration test (1) | ~30 min |
| Recipe | ~1 h |
| CHANGELOG + migration guide | ~30 min |
| **Total** | **~6.5 h** |

## 7. Risks

- **`StreamBackoff` correctness under pause** — `tokio::time`
  has subtle behavior around `tokio::test(start_paused)`.
  Mirror kube-rs's test patterns for the same combinator.
- **Jitter via `rand`** — adding `rand` as a dependency.
  Acceptable trade-off; alternative is using time-based
  pseudo-jitter, which is less correct. Use `rand` with a
  carefully-scoped `optional = false`.
- **`MapEvent` doesn't compose with `predicate_filter` after
  it** — if the key function takes a `&ResyncedEvent<T>` but
  the consumer maps to `U`, the predicate must use the
  pre-map type. Document; the kube-rs equivalent has the
  same ordering constraint.

## 8. Out-of-scope follow-ups

- **`reflector` / store pattern**: kube-rs ships a
  `Store<K>` that maintains an in-memory view of the
  watched objects. Useful for higher-level abstractions but
  bigger scope. Defer to 0.20 or later.
- **Backoff with `backon` crate**: backon is the canonical
  Rust backoff library. Could re-export `BackoffPolicy` as
  a `backon::Backoff` to compose with external policy.
  Defer; our default policy is enough for now.
- **Tracing instrumentation on the combinators**: per-event
  spans would help debugging but add cost. Defer to a
  follow-up when a consumer asks.

## 9. Cross-cutting artifacts

| Artifact | Action | Notes |
|---|---|---|
| `CHANGELOG.md` `## [Unreleased]` | **add** `### Added` entry — `ResyncStreamExt` trait, `StreamBackoff`, `BackoffPolicy`, `PredicateFilter`, `MapEvent` | Cross-reference Plans 185 + 191 + kube-rs `WatchStreamExt`. |
| `docs/migration_guide/0.18.0-to-0.19.0.md` | **append** `### Plan 195 — stream combinators` section | Pure additive; no migration except "swap your hand-rolled backoff for `.default_backoff()`". |
| `docs/recipes/resync-with-backoff.md` (**new**) | **create** ~120 lines | Already noted in §2.4 of this plan. Pairs with both nftables and route watchers. |
| `docs/recipes/README.md` | **add row** for `resync-with-backoff.md` | One line. |
| `crates/nlink/examples/events/watch_with_backoff.rs` (**new**) | **create** ~70-line runnable demo: subscribe to nftables OR route, wrap with `.default_backoff().predicate_filter(...)`, drain | Showcases all three combinators in one file. Register in `Cargo.toml`. |
| `README.md` `### Features` | **no change** — combinators are part of the default surface, no opt-in feature | |
| `README.md` `## High-Level APIs` | **add a sub-section** "Stream combinators" or include in existing event-subscription sub-sections | Brief; mention `.default_backoff()` as the canonical pattern. |
| `CLAUDE.md` | **append** a paragraph in the existing resync / event-stream area noting the `ResyncStreamExt` extension trait + kube-rs `WatchStreamExt` precedent | One-paragraph addition. |

End of plan.
