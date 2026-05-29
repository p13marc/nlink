---
to: nlink maintainers
from: nlink-lab upstream-asks report (2026-05-27) §Wishlist 3
subject: `nlink::Error::ext_ack() -> Option<&str>` + `ext_ack_offset() -> Option<u32>` inherent accessors
status: queued for 0.18 — trivial 10-LOC additive
target version: 0.18.0
parent: (none — single-deliverable plan)
source: nlink-lab maintainer report `nlink-upstream-asks.md` §Wishlist 3
created: 2026-05-27
---

# Plan 182 — `Error::ext_ack()` inherent accessors

## 1. Why this plan exists

The `ext_ack` and `ext_ack_offset` fields ship on both
`Error::Kernel` and `Error::KernelWithContext` (Plan 155.1,
0.16). Both variants are `#[non_exhaustive]` (Plan 163), so
downstream consumers can't destructure them — they have to
write a match arm with a wildcard at every call site:

```rust
let ext_ack = match &err {
    nlink::Error::Kernel { ext_ack, .. }
    | nlink::Error::KernelWithContext { ext_ack, .. } => ext_ack.as_deref(),
    _ => None,
};
```

That pattern is verbose, error-prone (two variants to keep in
sync), and forced by the `#[non_exhaustive]` decision.
Inherent accessors are the obvious fix — they already exist
for `errno() -> Option<i32>` and the predicate family
(`is_busy()`, `is_not_found()`, …) on the same `Error` type
at `error.rs:474-576`.

## 2. The change

```rust
// crates/nlink/src/netlink/error.rs

impl Error {
    /// Return the kernel's `NLMSGERR_ATTR_MSG` extended-ack
    /// string if this is a kernel error that carries one.
    /// Populated by Plan 155.1's `NETLINK_EXT_ACK` parsing.
    ///
    /// Matches the existing [`errno`](Self::errno) accessor
    /// shape — call site goes from a 5-line `match` to
    /// `err.ext_ack().unwrap_or_default()`.
    pub fn ext_ack(&self) -> Option<&str> {
        match self {
            Error::Kernel { ext_ack, .. }
            | Error::KernelWithContext { ext_ack, .. } => ext_ack.as_deref(),
            _ => None,
        }
    }

    /// Return the `NLMSGERR_ATTR_OFFS` byte offset pointing
    /// at the offending attribute in the request payload, if
    /// the kernel sent one. Less commonly useful than
    /// [`ext_ack`](Self::ext_ack) — pair with it when
    /// constructing structured error reports.
    pub fn ext_ack_offset(&self) -> Option<u32> {
        match self {
            Error::Kernel { ext_ack_offset, .. }
            | Error::KernelWithContext { ext_ack_offset, .. } => *ext_ack_offset,
            _ => None,
        }
    }
}
```

That's it. No field changes; no variant changes; no
serialization changes.

## 3. Tests

In `crates/nlink/src/netlink/error.rs` tests module
(co-located with existing `errno`/predicate tests):

```rust
#[test]
fn ext_ack_returns_some_for_kernel_with_ack() {
    let err = Error::Kernel {
        errno: 22,
        message: "EINVAL".into(),
        ext_ack: Some("attribute IFLA_MTU rejected".into()),
        ext_ack_offset: Some(24),
    };
    assert_eq!(err.ext_ack(), Some("attribute IFLA_MTU rejected"));
    assert_eq!(err.ext_ack_offset(), Some(24));
}

#[test]
fn ext_ack_returns_some_for_kernel_with_context() {
    let err = Error::KernelWithContext {
        operation: "add_link".into(),
        errno: 17,
        message: "EEXIST".into(),
        ext_ack: Some("interface 'veth0' already exists".into()),
        ext_ack_offset: None,
    };
    assert_eq!(err.ext_ack(), Some("interface 'veth0' already exists"));
    assert_eq!(err.ext_ack_offset(), None);
}

#[test]
fn ext_ack_returns_none_for_non_kernel_errors() {
    assert_eq!(Error::Timeout.ext_ack(), None);
    assert_eq!(Error::InvalidMessage("bad".into()).ext_ack(), None);
    assert_eq!(Error::Timeout.ext_ack_offset(), None);
}

#[test]
fn ext_ack_returns_none_for_kernel_without_ack() {
    let err = Error::Kernel {
        errno: 22,
        message: "EINVAL".into(),
        ext_ack: None,
        ext_ack_offset: None,
    };
    assert_eq!(err.ext_ack(), None);
    assert_eq!(err.ext_ack_offset(), None);
}
```

## 4. Acceptance criteria

- [ ] `Error::ext_ack()` + `Error::ext_ack_offset()` exist.
- [ ] 4 unit tests cover both variants × (ack-present /
      ack-absent / non-kernel).
- [ ] CHANGELOG `### Added` entry: 2-line note describing the
      accessors and noting they obviate the `match | _ =>`
      ceremony forced by `#[non_exhaustive]`.

## 5. Effort estimate

| Phase | Effort |
|---|---|
| Code | ~5 min |
| Tests (4) | ~15 min |
| CHANGELOG | ~5 min |
| **Total** | **~30 min** |

## 6. Risks — none

Pure additive on `impl Error`. No field changes, no behaviour
changes. `cargo-semver-checks` will pass cleanly.

## 7. Out-of-scope follow-ups

- **`ErrorContext` chain accessor** — if/when nlink grows a
  cause-chain pattern (currently flat), a parallel
  `cause() -> Option<&dyn Error>` accessor would fit the same
  shape. Not on the roadmap; mention for future symmetry only.

End of plan.
