---
to: nlink maintainers
from: nlink-lab feedback `nlink-feedback.md` §3 + §4 + D2 + D3 (2026-05-30) + 0.19 consolidation-pass bug-hunt (2026-05-30)
subject: `Error` API hygiene — normalize `from_errno_*` sign convention + `Error::chain_walk` helper + Io-shape sweep across `is_*` predicates + Box-source rustdoc
status: queued for 0.19 — medium (footgun bundle, expanded during consolidation)
target version: 0.19.0
parent: (none — single-deliverable plan)
source: nlink-lab `nlink-feedback.md` §3 (sign convention), §4 (Box source), D2 + D3 docs; consolidation bug-hunt surfaced 5 more predicates with the same Plan 185 `is_no_buffer_space` Io-shape bug
created: 2026-05-30 (expanded same day during consolidation pass)
---

# Plan 187 — `Error` API hygiene

## 1. Why this plan exists

Three distinct footguns from the 158b `Error::ext_ack` work +
related ergonomic gaps:

1. **`Error::from_errno_ext_ack` silently negates the input.**
   The signature reads `errno: i32` so a tester reasonably passes
   `1` for EPERM; the body computes `errno: -errno` and stores
   `-1`. Subsequent `.errno()` returns `Some(-1)`. The
   maintainer's own unit test had to assert `Some(-1)` instead
   of the natural `Some(1)`.

2. **Boxing `nlink::Error` in a `#[source]` field breaks the
   chain-walk pattern** that `Error::ext_ack`/`errno`/etc. use
   internally. `Box<nlink::Error>` as `&dyn Error` ⇒
   `downcast_ref::<nlink::Error>()` returns `None`. The
   maintainer backed out their box + crate-allowed
   `result_large_err`. Not strictly nlink's bug but the chain
   walk is nlink's contract, so the fix lives here.

3. **Five `Error::is_*` predicates have the same Io-shape gap
   that Plan 185 caught for `is_no_buffer_space`.** The bug-hunt
   pass during the 0.19 consolidation surfaced
   `is_busy`, `is_try_again`, `is_already_exists`,
   `is_permission_denied`, `is_connection_refused`,
   `is_not_found`, and the rest of the predicate family. All
   delegate to `self.errno()`, which only returns `Some(_)` for
   `Error::Kernel*` variants — never for `Error::Io(io_err)`
   carrying the same errno via `raw_os_error()`. Same-shape bug
   as 185, broader blast radius: `is_try_again` is used by
   `NftablesConfig::apply_reconcile` and a future
   `NetworkConfig::apply_reconcile` (Plan 188); a raw `EAGAIN`
   from the socket layer would silently fail the retry
   classification.

The bundle ships:
- Sign normalization on the factory (eliminates the footgun by
  construction)
- A public `Error::chain_walk` helper that knows about
  `Box<nlink::Error>` so consumers don't have to handle it
- **Refactor `Error::errno()` itself to return the
  `raw_os_error()` for `Error::Io` variants** — single change
  fixes every predicate at once + every future predicate
  inherits the right behavior
- Rustdoc additions on `Error::Kernel` warning about the
  Box-source trap, and the sign-convention factory docs

## 2. The change

### 2.1 Normalize the factory sign convention (Item #3, fix (c))

```rust
// crates/nlink/src/netlink/error.rs (existing factory at L321)

impl Error {
    /// Build a kernel error from an errno value + optional
    /// extended-ack TLVs.
    ///
    /// **Accepts either sign.** The kernel's `nlmsgerr.error`
    /// field is signed-negative (`-EEXIST = -17`); the stored
    /// `Error::Kernel.errno` is always the positive POSIX
    /// number (`17`). This factory normalizes via `.abs()` so:
    ///
    /// ```ignore
    /// // Both produce the same EEXIST error:
    /// Error::from_errno_ext_ack(-17, None, None);
    /// Error::from_errno_ext_ack(17, None, None);
    /// ```
    ///
    /// Prior to 0.19 this factory silently negated the input
    /// and a positive-passed `1` became stored `-1`.
    pub fn from_errno_ext_ack(
        errno: i32,
        ext_ack: Option<String>,
        ext_ack_offset: Option<u32>,
    ) -> Self {
        let errno = errno.abs();
        let message = std::io::Error::from_raw_os_error(errno).to_string();
        Self::Kernel {
            errno,
            message,
            ext_ack,
            ext_ack_offset,
        }
    }
}
```

Same normalization in `from_errno_with_context_ext_ack` +
`from_errno` + `from_errno_with_context` (any factory that
takes a signed `errno`).

**This is a BREAKING change.** Code that relied on the prior
"pass positive, get positive" behavior (i.e. nobody — that
behavior was the bug) continues to work; code that relied on
"pass negative, get positive" also continues to work. The only
breakage is the unit-test idiom where the tester observed and
asserted `Some(-1)`. Migration guide will note this.

### 2.2 `Error::chain_walk` helper (Item #4 / W-side)

```rust
// crates/nlink/src/netlink/error.rs

impl Error {
    /// Walk the source chain of an arbitrary error and yield
    /// every `&nlink::Error` along the way, **transparently
    /// unwrapping `Box<nlink::Error>`** at each step.
    ///
    /// Saves consumers from writing the
    /// `src.downcast_ref::<nlink::Error>()`
    /// → fallback-to-`Box<nlink::Error>` ladder by hand. The
    /// chain-walk is what `Error::ext_ack` and friends use
    /// internally; this helper exposes it for downstream
    /// consumers building their own walk-style accessors.
    ///
    /// Returns a borrowed iterator; the outermost `nlink::Error`
    /// (if any) is yielded first.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use nlink::Error;
    ///
    /// // Find the first kernel ENOBUFS anywhere in the chain.
    /// let enobufs = Error::chain_walk(&outer_err)
    ///     .find(|e| e.is_no_buffer_space());
    /// ```
    pub fn chain_walk(err: &(dyn std::error::Error + 'static))
        -> impl Iterator<Item = &Error>
    {
        ChainWalk { current: Some(err) }
    }
}

struct ChainWalk<'a> {
    current: Option<&'a (dyn std::error::Error + 'static)>,
}

impl<'a> Iterator for ChainWalk<'a> {
    type Item = &'a Error;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let err = self.current?;
            self.current = err.source();
            // Try the unboxed form first (the common shape).
            if let Some(nl) = err.downcast_ref::<Error>() {
                return Some(nl);
            }
            // Fall back to Box<nlink::Error> — the trap from
            // nlink-feedback §4.
            if let Some(boxed) = err.downcast_ref::<Box<Error>>() {
                return Some(boxed.as_ref());
            }
            // Not an nlink error at this level; advance.
        }
    }
}
```

The internal accessors (`Error::ext_ack`, `errno`,
`ext_ack_offset`) **switch to this helper** so they work
through boxed-source layers in downstream wrappers without
the rustdoc note we'd otherwise have to ship. The note still
ships as a safety net, but the helper makes the trap
non-fatal.

### 2.3 Rustdoc on `Error::Kernel` (D2)

```rust
/// A kernel netlink error response (`NLMSGERR` with `error !=
/// 0`).
///
/// ...
///
/// # Wrapping in a downstream error type
///
/// If you wrap this error in a `#[source]` field on your own
/// error enum, **prefer carrying it inline**:
///
/// ```ignore
/// #[derive(thiserror::Error, Debug)]
/// enum MyError {
///     #[error("netlink failed: {0}")]
///     Netlink(#[from] nlink::Error),  // inline — works
/// }
/// ```
///
/// Boxing breaks the [`Error::ext_ack`], [`Error::errno`], and
/// [`Error::ext_ack_offset`] chain-walk accessors because
/// `downcast_ref::<nlink::Error>()` on a `&dyn Error` backed
/// by `Box<nlink::Error>` returns `None`. As of 0.19,
/// [`Error::chain_walk`] handles both shapes transparently, so
/// if you do need to box for `result_large_err` ergonomics,
/// use `chain_walk` rather than `downcast_ref` directly.
```

Same note on `Error::KernelWithContext`.

### 2.4 Rustdoc on D3 — `from_errno_ext_ack` sign convention

Covered by §2.1's docstring rewrite. No extra entry needed.

### 2.5 Single-point Io-shape fix on `Error::errno()`

Bug-hunt finding: every `is_*` predicate today reads
`self.errno()`, which only handles `Error::Kernel*`. A raw
`Error::Io(io_err)` carries the same errno via
`raw_os_error()`, but `errno()` returns `None` for that
variant. Plan 185 fixed `is_no_buffer_space` by checking both
shapes inline; the right fix is **one level up** — let
`errno()` itself unwrap `Io`, and every predicate inherits
the correct behavior:

```rust
// crates/nlink/src/netlink/error.rs (existing errno fn)

/// Get the POSIX errno value if this error carries one.
///
/// Handles three shapes:
/// - `Error::Kernel { errno, .. }` — from `NLMSGERR`.
/// - `Error::KernelWithContext { errno, .. }` — context-wrapped.
/// - `Error::Io(io_err)` — from raw socket-layer errors;
///   reads `io_err.raw_os_error()`. This is the shape
///   `recvmsg` returns `-ENOBUFS` in (the Plan 185 bug).
///
/// Returns `None` for the other variants (Timeout, Truncated,
/// InvalidMessage, etc.) — they don't carry an errno.
pub fn errno(&self) -> Option<i32> {
    match self {
        Self::Kernel { errno, .. }
        | Self::KernelWithContext { errno, .. } => Some(*errno),
        Self::Io(io_err) => io_err.raw_os_error(),
        _ => None,
    }
}
```

The Plan 185 special-case in `is_no_buffer_space` becomes
dead code; remove it. Every other predicate (~12 of them)
inherits the fix without per-method changes.

This **subsumes** the Plan 185 `is_no_buffer_space` defensive
fix as a single-point repair. Cross-reference the 0.18
CHANGELOG entry: the 185 fix stays in place (it shipped) but
the `if let Self::Io(...)` branch in the predicate becomes
redundant.

## 3. Implementation phases

| Phase | Files | LOC |
|---|---|---|
| 1 — sign normalization on the four factories | `error.rs` | ~12 |
| 2 — `Error::chain_walk` + `ChainWalk` iterator | `error.rs` | ~50 |
| 3 — switch `ext_ack`/`errno`/`ext_ack_offset` accessors to use chain_walk internally | `error.rs` | ~10 net |
| 4 — Rustdoc on `Error::Kernel*` variants | `error.rs` | ~15 lines docs |
| 5 — `errno()` Io-shape unwrap + remove Plan 185 defensive branch from `is_no_buffer_space` | `error.rs` | ~10 net |
| 6 — Tests (see §4) | `error.rs` | ~140 (was ~80) |
| **Total** | | **~240 LOC** (was ~170) |

## 4. Tests

### 4.1 Unit — sign normalization

```rust
#[test]
fn from_errno_ext_ack_normalizes_negative_input() {
    let e = Error::from_errno_ext_ack(-libc::EEXIST, None, None);
    assert_eq!(e.errno(), Some(libc::EEXIST));
}

#[test]
fn from_errno_ext_ack_normalizes_positive_input() {
    let e = Error::from_errno_ext_ack(libc::EEXIST, None, None);
    assert_eq!(e.errno(), Some(libc::EEXIST));
}

#[test]
fn from_errno_ext_ack_zero_stays_zero() {
    let e = Error::from_errno_ext_ack(0, None, None);
    assert_eq!(e.errno(), Some(0));
}

#[test]
fn from_errno_with_context_ext_ack_normalizes_both_signs() {
    let neg = Error::from_errno_with_context_ext_ack(
        -libc::EBUSY,
        "add_link".into(),
        None, None,
    );
    let pos = Error::from_errno_with_context_ext_ack(
        libc::EBUSY,
        "add_link".into(),
        None, None,
    );
    assert_eq!(neg.errno(), pos.errno());
    assert_eq!(neg.errno(), Some(libc::EBUSY));
}
```

### 4.2 Unit — `chain_walk` covers both shapes

```rust
use std::error::Error as _;

#[derive(Debug, thiserror::Error)]
#[error("outer wrapper")]
struct InlineWrapper(#[source] nlink::Error);

#[derive(Debug, thiserror::Error)]
#[error("outer wrapper")]
struct BoxedWrapper(#[source] Box<nlink::Error>);

#[test]
fn chain_walk_finds_nlink_error_through_inline_source() {
    let inner = Error::from_errno_ext_ack(libc::EEXIST, None, None);
    let outer = InlineWrapper(inner);
    let found: Vec<_> = Error::chain_walk(&outer).collect();
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].errno(), Some(libc::EEXIST));
}

#[test]
fn chain_walk_finds_nlink_error_through_boxed_source() {
    // The trap from nlink-feedback §4 — must NOT yield None.
    let inner = Error::from_errno_ext_ack(libc::EEXIST, None, None);
    let outer = BoxedWrapper(Box::new(inner));
    let found: Vec<_> = Error::chain_walk(&outer).collect();
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].errno(), Some(libc::EEXIST));
}

#[test]
fn chain_walk_walks_deep_through_mixed_layers() {
    // Inline > Boxed > Inline > root kernel.
    let inner = Error::from_errno_ext_ack(libc::EBUSY, None, None);
    let inline2 = InlineWrapper(inner);
    // Wrap `inline2` in a Box-source layer manually (can't use
    // BoxedWrapper because it's typed to nlink::Error).
    // Use the chain via `outer.source().source()...` — the
    // walk should traverse it transparently.
    ...
}

#[test]
fn chain_walk_returns_empty_for_non_nlink_chain() {
    let plain = std::io::Error::other("no nlink here");
    let v: Vec<_> = Error::chain_walk(&plain).collect();
    assert!(v.is_empty());
}
```

### 4.3 Unit — accessors still work through boxed source

The most important regression test: the inherent accessors that
nlink-lab was reaching for *should now work* through a boxed
wrapper, post Phase 3.

```rust
#[test]
fn ext_ack_works_through_boxed_source_wrapper() {
    let inner = Error::Kernel {
        errno: libc::EINVAL,
        message: "EINVAL".into(),
        ext_ack: Some("attribute IFLA_MTU rejected".into()),
        ext_ack_offset: Some(24),
    };
    let outer = BoxedWrapper(Box::new(inner));
    // Currently this would return None for the boxed source.
    // After §2.2 switches the accessor to use chain_walk:
    let ack = Error::chain_walk(&outer)
        .find_map(|e| e.ext_ack())
        .unwrap_or("");
    assert_eq!(ack, "attribute IFLA_MTU rejected");
}
```

### 4.4 Unit — Io-shape predicate sweep

For every predicate, test BOTH shapes (kernel + Io) produce
the correct answer. This is the bug-class regression suite —
adding a new `is_*` predicate later inherits the test
template:

```rust
// Pair-test template: applied to all 12 predicates.

#[test]
fn is_busy_matches_kernel_ebusy() {
    let e = Error::from_errno_ext_ack(libc::EBUSY, None, None);
    assert!(e.is_busy(), "Kernel(EBUSY) must be is_busy");
}

#[test]
fn is_busy_matches_io_ebusy() {
    let e = Error::Io(std::io::Error::from_raw_os_error(libc::EBUSY));
    assert!(e.is_busy(), "Io(EBUSY) must be is_busy");
}

#[test]
fn is_busy_rejects_unrelated_errno() {
    let e = Error::Io(std::io::Error::from_raw_os_error(libc::ENOENT));
    assert!(!e.is_busy());
}

// Same pattern for: is_no_buffer_space, is_try_again,
// is_already_exists, is_permission_denied,
// is_connection_refused, is_not_found, is_invalid_argument,
// is_no_device, is_not_supported, is_network_unreachable,
// is_host_unreachable.
//
// = 12 predicates × 3 tests each = 36 sweep tests.
```

The shared test fixture (a helper that takes a predicate fn
pointer + an errno + tests both shapes) keeps this from
becoming 36 × N LOC:

```rust
fn assert_predicate_matches_both_shapes(
    pred: fn(&Error) -> bool,
    errno: i32,
    name: &str,
) {
    let kernel = Error::from_errno_ext_ack(errno, None, None);
    assert!(pred(&kernel), "{name}: Kernel({errno}) must match");
    let io = Error::Io(std::io::Error::from_raw_os_error(errno));
    assert!(pred(&io), "{name}: Io({errno}) must match");
}

#[test]
fn predicate_io_shape_sweep() {
    assert_predicate_matches_both_shapes(Error::is_busy, libc::EBUSY, "is_busy");
    assert_predicate_matches_both_shapes(Error::is_try_again, libc::EAGAIN, "is_try_again");
    assert_predicate_matches_both_shapes(Error::is_already_exists, libc::EEXIST, "is_already_exists");
    // ... etc. — 12 entries.
}
```

### 4.5 No integration tests required

The factory + chain-walk + predicate path has no kernel
surface to exercise. The existing root-gated integration
suite already verifies real-world chain-walk works (it's
used implicitly by every operation that produces an
`Error::Kernel` and gets surfaced through a wrapping context).

## 5. Acceptance criteria

- [ ] Four factory variants (`from_errno`, `from_errno_with_context`,
      `from_errno_ext_ack`, `from_errno_with_context_ext_ack`)
      normalize input sign.
- [ ] `Error::chain_walk(&dyn Error) -> impl Iterator<&Error>`
      handles both inline + `Box<Error>` source layers.
- [ ] `Error::ext_ack` / `errno` / `ext_ack_offset` use
      `chain_walk` internally so they work through wrapper
      layers (cleaner than the current ad-hoc `downcast_ref`).
- [ ] `Error::errno()` unwraps `Error::Io` via `raw_os_error()`;
      Plan 185's defensive branch in `is_no_buffer_space`
      removed.
- [ ] 4 sign-normalization tests + 4+ chain-walk tests + 1+
      accessor-through-box test + 36+ predicate Io-shape
      sweep tests via the shared assertion helper.
- [ ] Rustdoc note on `Error::Kernel` and
      `Error::KernelWithContext` about the boxed-source caveat
      + the `chain_walk` escape hatch.
- [ ] CHANGELOG `### Breaking changes` entry for the sign
      normalization (consumers asserting `Some(-1)` from a
      `from_errno_ext_ack(1, ...)` call break — that's the
      intent).
- [ ] CHANGELOG `### Fixed` entry for the predicate Io-shape
      sweep (the broader Plan 185 bug class).
- [ ] Migration guide `0.18.0-to-0.19.0.md` entry.

## 6. Effort estimate

| Phase | Effort |
|---|---|
| Code (factories + chain_walk + accessor refactor) | ~1 h |
| Tests (9+) | ~1 h |
| Rustdoc | ~30 min |
| CHANGELOG + migration guide | ~30 min |
| **Total** | **~3 h** |

## 7. Risks

- **`Error::chain_walk` impl returns `impl Iterator` — the
  return type is anonymous.** If we ever want to expose
  iterator helpers (`chain_walk(&err).filter_map(...)`),
  consumers can already do this. No risk per se; just
  noting.
- **Sign normalization is a real semver break** for tests that
  asserted the prior `Some(-N)`. Limited blast radius; the
  migration guide entry calls it out.

## 8. Out-of-scope follow-ups

- **`Error::chain_walk` returning `&dyn Error`** for non-nlink
  links in the chain — would let consumers inspect non-nlink
  intermediate layers. Not asked for; the current shape (only
  yield nlink errors) matches what `Error::ext_ack` needs.

## 9. Cross-cutting artifacts

| Artifact | Action | Notes |
|---|---|---|
| `CHANGELOG.md` `## [Unreleased]` | **add** `### Breaking changes` (sign normalization) + `### Fixed` (Io-shape predicate sweep) + `### Added` (`chain_walk`) | Three subsections; the predicate fix is the broadest. |
| `docs/migration_guide/0.18.0-to-0.19.0.md` | **append** `### Plan 187 — Error API` section with the sign-normalization migration ("if you asserted `Some(-1)` from `from_errno_ext_ack(1, ...)`, update to `Some(1)`") | Specific code snippets. |
| `docs/recipes/error-handling-patterns.md` (exists — Plan 148.6) | **update** with a `chain_walk` example showing it handles `Box<nlink::Error>` source layers | Adds ~30 lines of new recipe content. |
| `crates/nlink/examples/route/error_handling.rs` (exists) | **update** to demonstrate `Error::chain_walk` walking a wrapped error | The example currently shows basic predicate use; extend with chain_walk. |
| `CLAUDE.md` | **append** a sub-section under the existing "## Errors" area documenting the Io-shape predicate contract: every new `is_*` predicate must work for both `Kernel*` AND `Io` variants — the `errno()` unwrap handles this | Future contributors adding predicates inherit the right behavior automatically. |

End of plan.
