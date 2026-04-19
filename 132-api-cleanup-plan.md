---
to: nlink maintainers
from: nlink maintainers
subject: API cleanup pass for nlink 1.0 — builders, naming, non_exhaustive
target version: 0.13.0 / 1.0
date: 2026-04-19
status: draft, post-verification (2026-04-19) — non_exhaustive scope corrected (was "4 marked, ~36 unmarked"; actual is 44 marked, 96 unmarked)
verified: codebase audit complete
---

# API Cleanup Pass for 1.0

## 0. Summary

Three small but pervasive cleanups, naturally grouped because they all
touch the public API contract:

1. **Builder pattern uniformity**: ~27 builder structs with three
   inconsistent shapes (`Self` vs `Built<T>` wrapper; `Result`-returning
   vs infallible setters; `.build()` mandatory vs absent).
2. **`_bps` naming**: `HtbClassConfig::from_bps` means **bytes** per
   second; `NetemConfig::rate_bps` means **bits** per second. Same
   suffix, opposite meanings. Rename so the suffix unambiguously means
   bytes per second; bits-per-second variants get an explicit
   `_bits_per_sec` suffix.
3. **`#[non_exhaustive]` audit**: **44 of 140** public enums in
   `crates/nlink/src/netlink/` have it today. The remaining 96 are
   the audit scope. Adding `non_exhaustive` post-1.0 is a BC break;
   removing it isn't. So the call is "lock down for 1.0" — apply
   broadly to the 96 unmarked enums.

Items 1 and 2 are subsumed if the Rate newtype plan
(`129-rate-bytes-percent-newtypes-plan.md`) lands (no more `_bps`
naming because no more `bps` arguments). This plan stands alone if Rate
slips, and the builder + non_exhaustive parts are useful regardless.

This is contained, mechanical work. ~600 LOC of changes, no new
dependencies, no architectural shifts.

---

## 1. Goals & non-goals

### Goals

1. Every public builder follows one shape: infallible setters return
   `Self`, `.build()` returns `Self` (not a wrapper), `String`-parsing
   variants return `Result<Self>` and live as separate methods.
2. Every public method that takes a "rate" or "size" argument has an
   unambiguous name. Either:
   - Plan 129 lands → `Rate`/`Bytes` types eliminate naming
     ambiguity entirely, OR
   - Plan 129 doesn't land → adopt one consistent suffix policy
     (`_bytes_per_sec` for bytes/sec; `_bits_per_sec` for bits/sec;
     no bare `_bps`).
3. Every public enum is reviewed for `#[non_exhaustive]` and either
   marked or annotated `// stable: enumerable` with rationale.

### Non-goals

1. Restructuring data types (no new fields, no removed methods beyond
   what naming/builder cleanup requires).
2. Performance changes.
3. Cross-crate `non_exhaustive` (workspace dep crates are out of scope).

---

## 2. Builder pattern audit

### 2.1. Today's three shapes

From the agent's audit of 27 builder structs:

**Shape A: simple `Self`-returning** (most common)
```rust
NetemConfig::new()
    .delay(Duration::from_millis(100))    // -> Self
    .loss(1.0)                            // -> Self
    .build()                              // -> Self  (.build() is a no-op)
```

**Shape B: `Built` wrapper** (`HtbClassConfig` only)
```rust
HtbClassConfig::new("100mbit")?           // -> Result<Self>
    .ceil("500mbit")?                     // -> Result<Self>
    .prio(2)                              // -> Self
    .build()                              // -> HtbClassBuilt(Self)  ← differs
```

**Shape C: parsed string variants returning `Result`** (mixed in
with shapes A/B)
```rust
RateLimiter::new("eth0")
    .egress("100mbit")?                   // -> Result<Self>
    .ingress_bps(2_000_000)               // -> Self
```

### 2.2. Decision matrix

| Concern | Decision | Rationale |
|---|---|---|
| `.build()` return type | Always `Self` (no `Built<T>` wrapper) | One pattern. `HtbClassBuilt` exists only to gate `apply()`-style operations; that's solvable with a marker trait if needed. |
| `.build()` mandatory? | Optional. Builders are usable without `.build()`; `.build()` is a no-op marker for "I'm done". | Consistent with `NetemConfig`, `FlowerFilter`, etc. Forcing `.build()` adds noise without value. |
| String-parsing setter | Always `Result<Self>`, named with bare verb | `egress("100mbit")?` not `egress_str("100mbit")?` |
| Native-typed setter | `Self`, named with `_bytes_per_sec` / `_bytes` / `_packets` suffix as appropriate | `egress_bytes_per_sec(12_500_000)` is unambiguous. |
| If Plan 129 (Rate) lands | Native-typed setter takes `Rate` and is the only setter; string parsing happens in user code via `Rate::parse()` | Single API per concept |

### 2.3. Migration plan

For 0.13 / 1.0:

- `HtbClassBuilt` → delete; `HtbClassConfig::build() -> HtbClassConfig`
  (was: `-> HtbClassBuilt(HtbClassConfig)`).
- `HfscClassBuilt`, `DrrClassBuilt`, `QfqClassBuilt` — same treatment
  (per agent's audit of class builders). Marker trait `ClassConfig`
  carries the typing.
- `HtbClassConfig::new(rate: &str) -> Result<Self>` — keep the name,
  document as the string parser. The native-typed alternative is
  `HtbClassConfig::with_rate(rate: Rate)` (or the renamed `from_bps`
  if Rate doesn't land).

---

## 3. `_bps` naming policy

### 3.1. Today's mess

| Method | Argument unit |
|---|---|
| `HtbClassConfig::from_bps(u64)` | **bytes** per second |
| `HtbClassConfig::ceil_bps(u64)` | **bytes** per second |
| `NetemConfig::rate(u64)` | **bytes** per second (no `_bps` suffix) |
| `NetemConfig::rate_bps(u64)` | **bits** per second (`_bps` here is bits) |
| `NetemConfig::rate_kbps(u64)` | kilo**bits** per second |
| `RateLimiter::egress_bps(u64)` | **bytes** per second |
| `PerHostLimiter::new_bps(dev, u64)` | **bytes** per second |
| `PerPeerImpairer::assumed_link_rate_bps(u64)` | **bytes** per second |
| `PeerImpairment::rate_cap_bps(u64)` | **bytes** per second |

So `_bps` means bytes-per-second in 6 cases and bits-per-second in
3 cases. Recipe for confusion. (See: the 8× HTB rate bug.)

### 3.2. Decision (if Plan 129 doesn't land)

`bps` is too overloaded to use unambiguously. Drop it from public API.

| Old | New |
|---|---|
| `from_bps(u64)` | `from_bytes_per_sec(u64)` |
| `ceil_bps(u64)` | `ceil_bytes_per_sec(u64)` |
| `NetemConfig::rate(u64)` | `NetemConfig::rate_bytes_per_sec(u64)` |
| `NetemConfig::rate_bps(u64)` | `NetemConfig::rate_bits_per_sec(u64)` |
| `NetemConfig::rate_kbps(u64)` | `NetemConfig::rate_kbits_per_sec(u64)` |
| `NetemConfig::rate_mbps(u64)` | `NetemConfig::rate_mbits_per_sec(u64)` |
| `RateLimiter::egress_bps(u64)` | `RateLimiter::egress_bytes_per_sec(u64)` |
| `PerPeerImpairer::assumed_link_rate_bps(u64)` | `assumed_link_rate_bytes_per_sec(u64)` |

Verbose but unambiguous. Documentation note: "Yes, the names are
long. The 8× HTB bug fixed in 0.12.x existed because the previous
short names lied."

### 3.3. Decision if Plan 129 *does* land

The `_bps`/`_bytes_per_sec`/`_bits_per_sec` distinction collapses
into `Rate`. Single setter per builder:

```rust
HtbClassConfig::with_rate(rate: Rate)
NetemConfig::with_rate(rate: Rate)
RateLimiter::egress(rate: Rate)
```

Way better. Recommend Plan 129 as the headliner; this section is the
fallback.

---

## 4. `#[non_exhaustive]` audit

### 4.1. Why this matters at 1.0

Adding `#[non_exhaustive]` to a public enum is a **breaking change**
(downstream code that exhaustively matches breaks). Removing it isn't.
So 1.0 should err on the side of marking enums non_exhaustive, except
where we're confident the variants are stable.

### 4.2. The audit

Verified counts (audit, 2026-04-19): **140 public enums total in
`crates/nlink/src/netlink/`. 44 marked, 96 unmarked.**

The 96 unmarked enums break down roughly into:

- ~50 kernel-attribute enums (`*Attr` types) where the kernel adds
  values across releases — **mark all**.
- ~20 kernel-state/type enums (`OperState`, `RouteType`,
  `RouteProtocol`, `RouteScope`, `IfaceType`, `Family`, etc.) where
  the kernel can grow the set — **mark all**.
- ~15 protocol-specific enums under `genl/{wireguard,nl80211,
  devlink,...}/` — **mark all** (these are GENL families with
  evolving attribute sets).
- ~10 truly stable / RFC-fixed enums (e.g., `Verdict::Accept|Drop`
  patterns) — **leave unmarked with rationale comment**.

So the practical work is: mark ~85 enums, comment the remaining ~10,
write a `docs/non_exhaustive_audit.md` enumerating the decisions.

Triage rule:

#### Mark `#[non_exhaustive]`:

These represent kernel-defined or evolving spaces. Mark them all:

- All `*Attr` enums (kernel attribute IDs change; we add new variants
  on every kernel update). E.g., `TcaAttr`, `IflaAttr`, `IfaAttr`,
  `RtaAttr`, ...
- All `*State` / `*Status` enums (kernel state spaces). E.g.,
  `OperState`, `NeighborState`, `TcpState`.
- All `*Type` / `*Protocol` / `*Family` enums where the kernel adds
  values. E.g., `RouteType`, `RouteProtocol`, `RouteScope`,
  `IfaceType`, `Family`.
- All event enums (`NetworkEvent`, protocol-specific events).
- Recipe match enums (`HostMatch` already marked; same for any
  follow-ons).
- Error enums (`Error` already marked via `#[non_exhaustive]` —
  verify; if not, add).

#### Leave un-marked (deliberate):

These are stable mathematical / library-defined spaces:

- Booleans-in-disguise (e.g., direction enums with exactly two
  variants, where adding a third would be a semantic break, not an
  additive change).
- `Verdict`, `Action` enums where the variant set is enumerated by
  RFC and unlikely to grow (e.g., `Verdict::Accept`/`Drop` patterns).
- Internal enums never exposed publicly.

For each of these, add a doc comment:

```rust
// stable: enumerable. The set of MPLS label semantics is fixed
// by the original RFC and won't grow.
pub enum MplsLabel { ... }
```

Documentation-as-rationale; future maintainers know the choice was
intentional.

### 4.3. Detection script

```bash
# Find all pub enums in nlink/src
rg --files-with-matches '^pub enum' crates/nlink/src/

# For each, check whether #[non_exhaustive] precedes
rg -B2 '^pub enum' crates/nlink/src/ --multiline
```

Audit walks each entry and decides mark/no-mark with a short comment.

---

## 5. Files touched

### 5.1. Builder cleanup

| Path | Change | Approx LOC |
|---|---|---|
| `crates/nlink/src/netlink/tc.rs` | Remove `HtbClassBuilt`, `HfscClassBuilt`, `DrrClassBuilt`, `QfqClassBuilt`; collapse `.build() -> Built<T>` to `.build() -> Self`; update `ClassConfig` impls | ~80 |
| `crates/nlink/src/netlink/tc.rs` (Connection methods) | Update `add_class_config` etc. signatures | ~30 |
| `crates/nlink/src/netlink/filter.rs` | No-op (already shape A) | 0 |
| `crates/nlink/src/netlink/action.rs` | Audit; expected no-op | 0 |
| Examples / recipes / docs | Drop `.build()` from chains where redundant; not strictly required | ~30 |

### 5.2. `_bps` rename (only if Plan 129 doesn't land)

| Path | Change | Approx LOC |
|---|---|---|
| `crates/nlink/src/netlink/tc.rs` | Rename ~10 methods | ~80 |
| `crates/nlink/src/netlink/ratelimit.rs` | Rename 4 methods | ~30 |
| `crates/nlink/src/netlink/impair.rs` | Rename 2 methods | ~10 |
| `crates/nlink/tests/integration/*.rs` | Update assertions/calls | ~50 |
| `crates/nlink/examples/**` | Update | ~30 |
| `bins/tc/`, `bins/ip/` | Update | ~50 |
| `docs/`, `CLAUDE.md`, `README.md` | Update | ~50 |

### 5.3. `#[non_exhaustive]` audit

| Path | Change | Approx LOC |
|---|---|---|
| `crates/nlink/src/netlink/types/{addr,link,route,rule,neigh,tc,nsid,nexthop,mpls,srv6,macsec,mptcp}.rs` | Mark ~50 enums; add rationale comments to ~10 unmarked | ~150 |
| `crates/nlink/src/netlink/genl/**/{types,mod}.rs` | Mark ~20 protocol-specific enums | ~50 |
| `crates/nlink/src/netlink/error.rs` | Verify `Error` marked (it should already be) | ~5 |
| `crates/nlink/src/netlink/events.rs` | Verify `NetworkEvent` marked | ~5 |
| `crates/nlink/src/netlink/messages/**` | Audit ~10 enums | ~30 |
| `crates/nlink/src/sockdiag/**` | Audit (when feature enabled) | ~20 |
| `docs/non_exhaustive_audit.md` | New: full enum-by-enum decision log | ~200 |

### 5.4. Total

~600-800 LOC depending on which subitems land. Mostly mechanical.

---

## 6. Tests

Builder cleanup:

- All existing builder tests still pass (the change is to
  `.build()`'s return type for class builders; assertions touching
  `HtbClassBuilt(...)` need to be `HtbClassConfig` instead).
- Compile-test that `HtbClassConfig::new("...").unwrap().build()` is
  still usable as the input to `add_class_config`.

`_bps` rename:

- All assertions on rate values still hold (units don't change, just
  names).
- Callsite migration verified by compile.

`non_exhaustive` audit:

- Add a doctest per major enum showing the wildcard arm:
  ```
  match attr {
      TcaAttr::Kind => ...,
      TcaAttr::Options => ...,
      _ => /* future variants */,
  }
  ```
- Compile-test that exhaustive matches without `_` arm fail to
  compile (negative test via `compile_fail` doctest).

---

## 7. Documentation

CHANGELOG entries (assuming both Plan 129 and this land):

```markdown
### Changed (BC break)

- **Class builder `.build()` no longer returns a wrapper type.**
  `HtbClassConfig::build()` now returns `Self` instead of
  `HtbClassBuilt(Self)`. The `HtbClassBuilt`, `HfscClassBuilt`,
  `DrrClassBuilt`, `QfqClassBuilt` types are removed. Code that
  passed `HtbClassConfig::new(...)?.build()` to
  `Connection::add_class_config` continues to work; code that
  named the `HtbClassBuilt` type explicitly needs updating.

- **Many public enums are now `#[non_exhaustive]`.** Code that
  exhaustively matches kernel-defined enums like `TcaAttr`,
  `RouteType`, `OperState`, etc. now requires a wildcard arm.
  See [the audit](docs/non_exhaustive_audit.md) for the full list.
```

`docs/non_exhaustive_audit.md` (new): the full enum list with
mark/no-mark decisions and rationale. ~100 lines.

CLAUDE.md update: small note in the patterns section about builder
shape (`.build()` is optional; rename `HtbClassBuilt` mentions).

---

## 8. Open questions

1. **`HtbClassBuilt` was probably introduced for a reason.** Check
   git blame on `crates/nlink/src/netlink/tc.rs:2654`. If the wrapper
   carries semantics (e.g., "this class is fully validated"),
   replacing with `Self` loses that. Recommendation: do the
   investigation; if it carries no validation, remove. If it does,
   keep but rename to a marker trait.
2. **`.build()` removal.** Some callers may rely on `.build()` as
   visual punctuation. Recommendation: keep `.build()` as a no-op
   `pub fn build(self) -> Self { self }`; just standardize the
   return type.
3. **Naming bikeshed: `_bytes_per_sec` vs `_Bps` vs `_byte_rate`.**
   Verbose but unambiguous wins; `_bytes_per_sec`. Plan 129's
   `Rate` type makes this moot.
4. **Enum stability call: `Verdict`?** The `Verdict` enum
   (Accept/Drop) is RFC-stable. Mark `non_exhaustive`? Lean: no
   (it's a math-stable enum; marking is overkill).
5. **Doctest for non_exhaustive negative case.** `compile_fail`
   tests are noisy in rustdoc. Worth it? Lean: yes for the
   highest-value enums (TcaAttr, NetworkEvent), no for the long
   tail.

---

## 9. Phasing

If Plan 129 (Rate) lands first:
- This plan loses the `_bps` rename section entirely.
- Builder + non_exhaustive remain (~400 LOC).

If Plan 129 doesn't land:
- All three sections in one PR.
- ~700 LOC.

Either way, single PR. Mechanical changes; reviewable.

---

## 10. Risk register

| Risk | Likelihood | Mitigation |
|---|---|---|
| Removing `HtbClassBuilt` breaks a downstream invariant | Low | git-blame check; if it's load-bearing, keep as marker |
| `_bytes_per_sec` rename is verbose enough that callers complain | Medium | Plan 129 (`Rate`) makes the names short again |
| `non_exhaustive` audit adds the marker too aggressively, breaks downstream code | Certain (intended) | Migration doc lists exactly which enums changed |
| New variants get added later that re-tempt removing `non_exhaustive` | N/A | That's the point of marking now |

---

## 11. What we are NOT doing

- **No new types** beyond what cleanup demands.
- **No method removals** other than the rename layer.
- **No `into()` blanket impls** to soften the rename (creates its own
  ambiguity).
- **No `#[non_exhaustive]` on internal enums.**

---

## 12. Definition of done

- [ ] `HtbClassBuilt` and similar removed; `.build()` returns `Self`
- [ ] `_bps` naming policy applied (or made moot by Plan 129)
- [ ] All `pub enum`s in `crates/nlink/src/` audited; ~30 marked
      `non_exhaustive`, remainder commented with rationale
- [ ] `docs/non_exhaustive_audit.md` exists
- [ ] All tests pass; clippy clean
- [ ] CHANGELOG migration table written

---

End of plan.
