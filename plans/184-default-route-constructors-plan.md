---
to: nlink maintainers
from: nlink-lab upstream-asks report (2026-05-27) §Wishlist 5
subject: `Ipv4Route::default_route()` / `Ipv6Route::default_route()` constructors
status: queued for 0.18 — trivial cosmetic
target version: 0.18.0
parent: (none — single-deliverable plan)
source: nlink-lab maintainer report `nlink-upstream-asks.md` §Wishlist 5
created: 2026-05-27
---

# Plan 184 — `default_route` constructors

## 1. Why this plan exists

Every default-route call site reads:

```rust
nlink::netlink::route::Ipv4Route::new("0.0.0.0", 0)
nlink::netlink::route::Ipv6Route::new("::", 0)
```

The `"0.0.0.0"` / `"::"` literal-string-meaning-default-route
idiom is iproute2 muscle-memory and entirely fine for someone
who lives in netlink land. For declarative call sites that
prioritize self-documentation, the construction reads better
as:

```rust
Ipv4Route::default_route()
Ipv6Route::default_route()
```

`Default::default()` is unfortunately taken by the trait;
`default_route()` is the obvious unambiguous name and is also
the natural pronunciation.

## 2. The change

```rust
// crates/nlink/src/netlink/route.rs (around the existing
// Ipv4Route::new at line 468)

impl Ipv4Route {
    /// Build a default IPv4 route (`0.0.0.0/0`). Equivalent to
    /// `Ipv4Route::new("0.0.0.0", 0)` but self-documenting.
    pub fn default_route() -> Self {
        Self::new("0.0.0.0", 0)
    }
}

impl Ipv6Route {
    /// Build a default IPv6 route (`::/0`). Equivalent to
    /// `Ipv6Route::new("::", 0)` but self-documenting.
    pub fn default_route() -> Self {
        Self::new("::", 0)
    }
}
```

That's the whole change. Both methods are zero-arg constructors
that delegate to `new()` with the convention strings.

## 3. Tests

```rust
#[test]
fn ipv4_default_route_is_unspecified_slash_zero() {
    let r = Ipv4Route::default_route();
    assert_eq!(r.destination(), "0.0.0.0");
    assert_eq!(r.prefix_len(), 0);
}

#[test]
fn ipv6_default_route_is_unspecified_slash_zero() {
    let r = Ipv6Route::default_route();
    assert_eq!(r.destination(), "::");
    assert_eq!(r.prefix_len(), 0);
}

#[test]
fn default_route_equals_explicit_new() {
    assert_eq!(
        Ipv4Route::default_route().destination(),
        Ipv4Route::new("0.0.0.0", 0).destination()
    );
    assert_eq!(
        Ipv6Route::default_route().destination(),
        Ipv6Route::new("::", 0).destination()
    );
}
```

## 4. Acceptance criteria

- [ ] `Ipv4Route::default_route()` + `Ipv6Route::default_route()`
      exist.
- [ ] 3 unit tests.
- [ ] CHANGELOG `### Added` entry: one-liner.

## 5. Effort estimate

| Phase | Effort |
|---|---|
| Code (~10 LOC) | ~5 min |
| Tests | ~10 min |
| CHANGELOG | ~2 min |
| **Total** | **~20 min** |

## 6. Risks — none

Pure additive on `impl`. No field changes; no trait changes.

## 7. Out-of-scope follow-ups

- **`Ipv4Address::loopback()` / `Ipv6Address::loopback()`** —
  same shape (self-documenting wrappers around `127.0.0.1` /
  `::1`). Add if found useful. Defer to a separate small-PR
  bundle if no immediate signal.
- **`Ipv4Address::link_local_prefix()`** — `169.254.0.0/16` for
  IPv4, `fe80::/10` for IPv6. Same pattern, more niche use.
- **Multicast prefix constants** — `224.0.0.0/4`, `ff00::/8`.
  Same shape; defer.

The pattern is "name what the literal means," and there are
~5 idiomatic addresses worth covering when there's actual
downstream pull. None of those are in this plan.

End of plan.
