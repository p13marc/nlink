---
to: nlink maintainers
from: nlink maintainers
subject: TcHandle and FilterPriority newtypes for nlink 1.0
target version: 0.13.0 / 1.0
date: 2026-04-19
status: draft, post-verification (2026-04-19) — call-site count corrected (~20 → 52)
verified: codebase audit complete; netlink-packet-route comparison from training
---

# TcHandle and FilterPriority Newtypes

## 0. Summary

Today the public TC API takes handles as `&str` (`"1:"`, `"1:5"`,
`"root"`) and parses them at every call site. Class IDs and parent
handles are passed as raw `u32` in struct fields. Filter priorities
flow as `u16`, easy to collide.

Replace with two small typed wrappers:

- **`TcHandle(u32)`** — opaque major/minor pair with constants for
  `ROOT`, `INGRESS`, `CLSACT`, `UNSPEC`. `FromStr`/`Display` round-trip
  via the existing tc-style notation. Replaces `&str` and raw `u32`
  handle args throughout the public API.
- **`FilterPriority(u16)`** — namespaced priority bands (operator,
  recipe, system) so library helpers can't accidentally collide with
  caller-installed filters.

Companion to the rate/bytes/percent newtype work
(`129-rate-bytes-percent-newtypes-plan.md`) — same motivation (kill a
bug class at the type level), independent scope.

**Ecosystem alignment**: `netlink-packet-route` 0.19+ already exposes
`TcHandle` as a struct with `major: u16` / `minor: u16` fields plus
`From<u32>`/`Into<u32>` for wire interop and `ROOT`/`INGRESS`
constants. Our type matches that shape — adopt their public field
names so users can interop with both crates. (Source: training memory,
version may have moved; verify before merging.)

---

## 1. Goals & non-goals

### Goals

1. Single canonical handle type used in every public TC API.
2. Round-trip parsing/formatting matches `tc(8)` exactly: `"root"`,
   `"ingress"`, `"clsact"`, `"1:"`, `"1:a"`, `"ffff:"`.
3. Compile-time prevention of "passed minor where major was expected"
   bugs.
4. `FilterPriority` provides a namespaced band convention library
   helpers can use to stay out of the way of operator filters.
5. Strong invariants: no public way to construct an invalid handle.

### Non-goals

1. Replacing the `tc_handle` constants module. It stays for
   internal use; the new `TcHandle` wraps it.
2. Type-distinguishing class handles from qdisc handles from filter
   handles. They're all the same kernel concept (32-bit major:minor),
   even if conventionally used differently.
3. Restricting `FilterPriority` numerically to bands at the type
   level. Bands are documented conventions, not invariants.

---

## 2. Today's pain

### 2.1. `&str` parsing tax

```rust
// Every call parses again:
conn.add_qdisc_full("eth0", "root", Some("1:"), htb).await?;
conn.add_class_config("eth0", "1:0", "1:1", cfg).await?;
conn.add_filter_full("eth0", "1:", None, 0x0800, 100, filter).await?;
```

Internally each call does `tc_handle::parse(parent).ok_or(...)?` —
allocating intermediate `String` if the caller built a handle with
`format!()`. With ~10 such calls per recipe, the parse cost is
nontrivial and the error path (invalid handle) is reachable from
every call.

### 2.2. Raw `u32` allows nonsense

```rust
// HtbQdiscConfig::default_class takes u32 — no protection
let htb = HtbQdiscConfig::new()
    .default_class(0x10010)   // is this 1:10 or 10010:0? users guess
    .build();
```

The kernel encoding is `(major << 16) | minor`. Easy to write
`0x10010` thinking "class 1:10" (correct value: `0x00010010`) or
"major 0x1001" (correct value: `0x10010000`). Reviewers can't tell
which the author meant.

### 2.3. Filter priority collisions

`PerHostLimiter` uses priority `1..N+1`. `PerPeerImpairer` uses
`100..100+N`. An operator's hand-installed `tc filter add prio 50`
sits between them. There's no convention; collisions are silent (the
filters coexist but ordering becomes implementation-dependent).

---

## 3. Design

### 3.1. `TcHandle`

```rust
// crates/nlink/src/netlink/tc_handle.rs (new top-level type;
// internal `tc_handle` module in types/tc.rs becomes a private impl detail)

/// A traffic-control handle: a packed `(major, minor)` pair plus the
/// special values `ROOT`, `INGRESS`, `CLSACT`.
///
/// Encoded as the kernel does: `(major as u32) << 16 | minor as u32`.
/// Parses and formats in `tc(8)` notation.
///
/// # Example
///
/// ```
/// use nlink::TcHandle;
///
/// assert_eq!(TcHandle::new(1, 10).to_string(), "1:a");
/// assert_eq!(TcHandle::ROOT.to_string(), "root");
/// assert_eq!("1:a".parse::<TcHandle>().unwrap(), TcHandle::new(1, 10));
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct TcHandle(u32);

impl TcHandle {
    pub const ROOT: Self    = Self(0xFFFF_FFFF);
    pub const INGRESS: Self = Self(0xFFFF_FFF1);
    pub const CLSACT: Self  = Self(0xFFFF_FFF2);
    pub const UNSPEC: Self  = Self(0);

    /// Construct from major/minor.
    pub const fn new(major: u16, minor: u16) -> Self {
        Self(((major as u32) << 16) | (minor as u32))
    }

    /// Construct a major-only handle (`"1:"`). Equivalent to
    /// `TcHandle::new(major, 0)`.
    pub const fn major_only(major: u16) -> Self {
        Self::new(major, 0)
    }

    /// Construct from the raw u32 the kernel uses.
    /// Public so consumers reading raw netlink can wrap, but kept
    /// distinct from `new()` to discourage accidental misuse.
    pub const fn from_raw(raw: u32) -> Self { Self(raw) }

    pub const fn as_raw(self) -> u32 { self.0 }

    pub const fn major(self) -> u16 { (self.0 >> 16) as u16 }
    pub const fn minor(self) -> u16 { (self.0 & 0xFFFF) as u16 }

    pub const fn is_root(self) -> bool    { self.0 == Self::ROOT.0 }
    pub const fn is_ingress(self) -> bool { self.0 == Self::INGRESS.0 }
    pub const fn is_clsact(self) -> bool  { self.0 == Self::CLSACT.0 }
    pub const fn is_unspec(self) -> bool  { self.0 == Self::UNSPEC.0 }
}

impl fmt::Display for TcHandle {
    /// `"root"`, `"ingress"`, `"clsact"`, `"none"`, `"1:"`, or `"1:a"`.
    /// Matches `tc(8)` output exactly.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result;
}

impl FromStr for TcHandle {
    type Err = TcHandleParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err>;
}

#[derive(Debug, thiserror::Error)]
pub enum TcHandleParseError {
    #[error("empty handle")]
    Empty,
    #[error("missing ':' separator in {0}")]
    MissingSep(String),
    #[error("invalid major in {0}")]
    InvalidMajor(String),
    #[error("invalid minor in {0}")]
    InvalidMinor(String),
}
```

The internal `tc_handle::parse`/`make`/`format` functions in
`crates/nlink/src/netlink/types/tc.rs` become private and the public
API stops needing them.

### 3.2. `FilterPriority`

```rust
// crates/nlink/src/netlink/filter_priority.rs (new)

/// A traffic-control filter priority.
///
/// Lower values are evaluated first. Conventional bands (documentation
/// only, not enforced):
///
/// | Range       | Use                                         |
/// |-------------|---------------------------------------------|
/// | `1..=49`    | Operator-installed filters                  |
/// | `50..=99`   | Reserved for future library use             |
/// | `100..=199` | nlink recipe helpers (`PerPeerImpairer`,    |
/// |             | `PerHostLimiter`)                           |
/// | `200..=999` | Application-specific                        |
/// | `1000..`    | System / catch-alls                         |
///
/// Helpers in this crate take values from the recipe band by default.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct FilterPriority(u16);

impl FilterPriority {
    pub const RECIPE_BAND_START: u16 = 100;
    pub const APP_BAND_START: u16 = 200;
    pub const SYSTEM_BAND_START: u16 = 1000;

    pub const fn new(value: u16) -> Self { Self(value) }
    pub const fn as_u16(self) -> u16 { self.0 }

    /// Helper: make a priority within the recipe band, given an offset
    /// from the band start. Saturates at `APP_BAND_START - 1`.
    pub const fn recipe(offset: u16) -> Self {
        let v = Self::RECIPE_BAND_START.saturating_add(offset);
        Self(if v >= Self::APP_BAND_START { Self::APP_BAND_START - 1 } else { v })
    }

    /// Same for the app band.
    pub const fn app(offset: u16) -> Self {
        let v = Self::APP_BAND_START.saturating_add(offset);
        Self(if v >= Self::SYSTEM_BAND_START { Self::SYSTEM_BAND_START - 1 } else { v })
    }
}

impl fmt::Display for FilterPriority { /* "100" */ }
impl FromStr for FilterPriority { /* "100" */ }
impl From<u16> for FilterPriority { /* opt-in lossy compat */ }
```

`FilterPriority` is opt-in via `From<u16>` to ease migration. The
recipe helpers use the typed form.

### 3.3. Where these slot in

#### Connection methods (signature changes)

```rust
// Before
pub async fn add_qdisc_full(
    &self,
    dev: impl Into<InterfaceRef>,
    parent: &str,
    handle: Option<&str>,
    config: impl QdiscConfig,
) -> Result<()>;

// After
pub async fn add_qdisc_full(
    &self,
    dev: impl Into<InterfaceRef>,
    parent: TcHandle,
    handle: Option<TcHandle>,
    config: impl QdiscConfig,
) -> Result<()>;
```

To keep the common case ergonomic, `TcHandle: From<&str>` is
**rejected** — a fallible `From` would have to panic on bad input,
which is worse than today's `Result`. Instead, callers do:

```rust
conn.add_qdisc_full("eth0", TcHandle::ROOT, Some(TcHandle::major_only(1)), htb).await?;
// or
conn.add_qdisc_full("eth0", "root".parse()?, Some("1:".parse()?), htb).await?;
```

For the ergonomic loss, a small helper on `Connection<Route>`:

```rust
/// Sugar for the most common shape: `add_qdisc_full(dev, ROOT, Some(handle), cfg)`.
pub async fn add_qdisc_at_root(
    &self,
    dev: impl Into<InterfaceRef>,
    handle: TcHandle,
    config: impl QdiscConfig,
) -> Result<()>;
```

#### Class IDs in builders

```rust
// HtbQdiscConfig
- pub fn default_class(self, classid: u32) -> Self
+ pub fn default_class(self, classid: TcHandle) -> Self

// MqprioConfig
- pub fn default_class(self, classid: u16) -> Self
+ pub fn default_class(self, classid: TcHandle) -> Self
```

`MqprioConfig` actually only takes the minor (the major is implicit
from the qdisc's own handle). To keep the type uniform: take a
`TcHandle` and assert/error if `major != 0`. Or introduce a separate
`TcMinor(u16)` type. Recommendation: use `TcHandle` and document the
convention. (One type to learn beats two.)

#### Filter builders

```rust
// FlowerFilter, U32Filter, etc.
- pub fn classid(self, classid: &str) -> Self
- pub fn classid_raw(self, classid: u32) -> Self
+ pub fn classid(self, classid: TcHandle) -> Self
// (no _raw variant; use TcHandle::from_raw if you really need it)

- pub fn priority(self, prio: u16) -> Self
+ pub fn priority(self, prio: FilterPriority) -> Self
```

#### Filter dump methods

```rust
// Connection<Route>
- pub async fn get_filters_by_parent(
-     &self, iface: impl Into<InterfaceRef>, parent: &str,
- ) -> Result<Vec<TcMessage>>
+ pub async fn get_filters_by_parent(
+     &self, iface: impl Into<InterfaceRef>, parent: TcHandle,
+ ) -> Result<Vec<TcMessage>>
```

#### Message accessors

```rust
// TcMessage
- pub fn handle(&self) -> u32
- pub fn parent(&self) -> u32
+ pub fn handle(&self) -> TcHandle
+ pub fn parent(&self) -> TcHandle

// keep handle_str() / parent_str() as Display delegators for callers
// who want the formatted string
```

---

## 4. API surface (full list of changed signatures)

Verified count from the codebase audit: **52 methods** that take
handle args, distributed as:

- **26 in `tc.rs`** — qdisc and class operations
- **16 in `filter.rs`** — filter operations
- **10 in `connection.rs`** — chains, dumps, by-handle lookups

Plus **~7 builder fields** (see §4.4) and **2 message accessors**
(see §4.5).

### 4.1. `tc.rs` — 26 qdisc/class methods (verified file:line)

```rust
// Qdisc — 12 methods
add_qdisc_full(...)                       // tc.rs:3326
add_qdisc_by_index_full(...)              // tc.rs:3364
del_qdisc(dev, parent: &str)              // tc.rs:3399
del_qdisc_full(...)                       // tc.rs:3404
del_qdisc_by_index(ifindex, parent: &str) // tc.rs:3418
del_qdisc_by_index_full(...)              // tc.rs:3423
replace_qdisc_full(...)                   // tc.rs:3472
replace_qdisc_by_index_full(...)          // tc.rs:3498
change_qdisc(dev, parent: &str, ...)      // tc.rs:3537
change_qdisc_full(...)                    // tc.rs:3547
change_qdisc_by_index(...)                // tc.rs:3563
change_qdisc_by_index_full(...)           // tc.rs:3574

// Class — 14 methods
add_class(dev, parent: &str, classid: &str, ...)         // tc.rs:3695
add_class_by_index(...)                                  // tc.rs:3712
del_class(dev, parent: &str, classid: &str)              // tc.rs:3747
del_class_by_index(...)                                  // tc.rs:3758
change_class(dev, parent: &str, classid: &str, ...)      // tc.rs:3788
change_class_by_index(...)                               // tc.rs:3802
replace_class(dev, parent: &str, classid: &str, ...)     // tc.rs:3838
replace_class_by_index(...)                              // tc.rs:3852
add_class_config<C>(dev, parent: &str, classid: &str, ...)        // tc.rs:3909
add_class_config_by_index<C>(...)                                 // tc.rs:3925
change_class_config<C>(...)                                       // tc.rs:3965
change_class_config_by_index<C>(...)                              // tc.rs:3978
replace_class_config<C>(...)                                      // tc.rs:4018
replace_class_config_by_index<C>(...)                             // tc.rs:4031
```

All take `parent: &str`, most also `classid: &str` and `handle: Option<&str>`.
Migrate to `parent: TcHandle`, `classid: TcHandle`, `handle: Option<TcHandle>`.

### 4.2. `filter.rs` — 16 filter methods (verified file:line)

```rust
add_filter(dev, parent: &str, config)                                          // filter.rs:1876
add_filter_full(dev, parent: &str, handle: Option<&str>, protocol, prio, ...)  // filter.rs:1895
add_filter_by_index(...)                                                       // filter.rs:1910
add_filter_by_index_full(...)                                                  // filter.rs:1921
replace_filter(...)                                                            // filter.rs:1975
replace_filter_full(...)                                                       // filter.rs:1987
replace_filter_by_index(...)                                                   // filter.rs:2002
replace_filter_by_index_full(...)                                              // filter.rs:2013
change_filter(dev, parent: &str, protocol, prio, ...)                          // filter.rs:2065
change_filter_full(...)                                                        // filter.rs:2079
change_filter_by_index(...)                                                    // filter.rs:2094
change_filter_by_index_full(...)                                               // filter.rs:2107
del_filter(dev, parent: &str, protocol, prio)                                  // filter.rs:2153
del_filter_by_index(...)                                                       // filter.rs:2166
flush_filters(dev, parent: &str)                                               // filter.rs:2190
flush_filters_by_index(ifindex, parent: &str)                                  // filter.rs:2196
```

`protocol: u16` stays raw (it's an etherproto/ETH_P_*); could newtype
later if there's appetite. `priority: u16` migrates to `FilterPriority`.

### 4.3. `connection.rs` — 10 chain / dump / lookup methods

```rust
get_filters_by_parent(iface, parent: &str)         // connection.rs:1229 (added in 0.12.x)
get_filters_by_parent_index(ifindex, parent: &str) // connection.rs:1241
get_tc_chains(ifname, parent: &str)                // connection.rs:1268
get_tc_chains_by_index(ifindex, parent: &str)      // connection.rs:1278
add_tc_chain(ifname, parent: &str, chain)          // connection.rs:1320
add_tc_chain_by_index(ifindex, parent: &str, chain) // connection.rs:1331
del_tc_chain(ifname, parent: &str, chain)          // connection.rs:1364
del_tc_chain_by_index(ifindex, parent: &str, chain) // connection.rs:1375
get_qdisc_by_handle(ifname: &str, handle: &str)    // connection.rs:1440
get_qdisc_by_handle_index(ifindex, handle: &str)   // connection.rs:1461
```

### 4.4. `tests/integration` and `examples/` migration scope

After signature changes:
- All ~10 integration test files under `crates/nlink/tests/integration/`
  have to switch from `"1:"`/`"1:5"` strings to `TcHandle::ROOT` /
  `TcHandle::new(1, 5)` (or `"1:".parse()?`). Migration is
  mechanical; ~80 LOC.
- `crates/nlink/examples/` has ~6 examples calling these APIs
  (route/tc/{netem,htb,bpf,classes,...}).
- `bins/tc/` and `bins/ip/`'s tc subcommand also call the methods.

### 4.5. Builder field types

```rust
HtbQdiscConfig.default_class: TcHandle
MqprioConfig.default_class: TcHandle  // or TcMinor — see §3.3
TaprioConfig.default_class: TcHandle  // ditto

FlowerFilter.classid: TcHandle
U32Filter.classid: TcHandle
MatchallFilter.classid: TcHandle
BpfFilter.classid: TcHandle
... (all filter builders)

FlowerFilter.priority: FilterPriority
... (all filter builders)
```

### 4.6. `TcMessage` accessors

```rust
- pub fn handle(&self) -> u32
- pub fn parent(&self) -> u32
+ pub fn handle(&self) -> TcHandle
+ pub fn parent(&self) -> TcHandle

// Existing convenience methods stay:
pub fn handle_str(&self) -> String   // = self.handle().to_string()
pub fn parent_str(&self) -> String   // = self.parent().to_string()
pub fn is_root(&self) -> bool        // = self.handle().is_root() etc.
```

### 4.7. Recipe helpers

`PerPeerImpairer` and `PerHostLimiter` internals already use
`TcHandle`-equivalent strings. Their public API doesn't expose handles
directly (the helpers manage the tree), so the change is internal-only.

---

## 5. Files touched

| Path | Change | Approx LOC |
|---|---|---|
| `crates/nlink/src/netlink/tc_handle.rs` | New top-level `TcHandle` type | ~200 |
| `crates/nlink/src/netlink/filter_priority.rs` | New `FilterPriority` type | ~80 |
| `crates/nlink/src/netlink/types/tc.rs` | Make `tc_handle` mod private | ~5 |
| `crates/nlink/src/netlink/tc.rs` | Migrate ~30 method signatures | ~250 |
| `crates/nlink/src/netlink/filter.rs` | Migrate ~12 method signatures | ~120 |
| `crates/nlink/src/netlink/connection.rs` | Migrate ~5 dump helpers | ~30 |
| `crates/nlink/src/netlink/messages/tc.rs` | Update accessors | ~20 |
| `crates/nlink/src/netlink/impair.rs` | Internal switch from `&str` to `TcHandle` | ~50 |
| `crates/nlink/src/netlink/ratelimit.rs` | Same | ~50 |
| `crates/nlink/src/netlink/config/{diff,apply,types}.rs` | Migrate qdisc handle fields | ~80 |
| `crates/nlink/src/lib.rs` | Re-export | ~5 |
| `crates/nlink/tests/integration/{tc,ratelimit,impair}.rs` | Update | ~100 |
| `crates/nlink/examples/**/*.rs` | Update | ~80 |
| `bins/tc/**/*.rs`, `bins/ip/**/*.rs` | Update | ~100 |
| `docs/recipes/per-peer-impairment.md` | Update code samples | ~20 |
| `CLAUDE.md`, `README.md` | Update examples | ~50 |
| `CHANGELOG.md` | Migration notes | ~25 |

Total ~1200 LOC. Mostly mechanical signature swaps.

---

## 6. Tests

### 6.1. `TcHandle` unit tests

- `TcHandle::new(1, 10).as_raw() == 0x0001_000A`
- `TcHandle::new(1, 10).major() == 1 && .minor() == 10`
- `TcHandle::major_only(1).as_raw() == 0x0001_0000`
- `TcHandle::ROOT.as_raw() == 0xFFFF_FFFF`
- `TcHandle::ROOT.is_root() == true`
- `TcHandle::ROOT.major() == 0xFFFF` (just checking encoding)
- Display: `TcHandle::new(1, 10).to_string() == "1:a"`
- Display: `TcHandle::major_only(1).to_string() == "1:"`
- Display: `TcHandle::ROOT.to_string() == "root"`
- Display: `TcHandle::INGRESS.to_string() == "ingress"`
- FromStr round-trip: `"1:a".parse::<TcHandle>().unwrap() == TcHandle::new(1, 10)`
- FromStr: `"root".parse() == Ok(TcHandle::ROOT)`
- FromStr error cases: `"".parse().is_err()`, `"1".parse().is_err()`, `"1:zzzz".parse().is_err()`
- Property test: for many `(maj, min)` pairs, `TcHandle::new(maj, min).to_string().parse() == TcHandle::new(maj, min)`

### 6.2. `FilterPriority` unit tests

- `FilterPriority::new(100).as_u16() == 100`
- `FilterPriority::recipe(0).as_u16() == 100`
- `FilterPriority::recipe(50).as_u16() == 150`
- `FilterPriority::recipe(200).as_u16() == 199` (saturates within band)
- `FilterPriority::app(0).as_u16() == 200`
- `FilterPriority::app(900).as_u16() == 999`
- `From<u16>` works as documented compat path

### 6.3. Integration tests

After migration, all existing TC/filter integration tests should still
pass with updated arguments. New checks:

- `test_tchandle_display_matches_tc_command`: deploy a 3-class HTB
  tree, dump via `get_classes_by_index`, format each class's handle
  via the new `Display`, parse with `TcHandle::FromStr`, assert
  round-trip.
- `test_filter_priority_band_helper`: install a `PerPeerImpairer` with
  3 rules, verify the resulting filters' priorities are in the recipe
  band.

---

## 7. Migration guide (CHANGELOG)

```markdown
### Changed (BC break)

- **TC handles are now strongly typed via `TcHandle`.**
  Public methods that previously took `parent: &str`, `classid: &str`,
  or `handle: Option<&str>` now take `TcHandle` (or `Option<TcHandle>`).
  Builder fields like `HtbQdiscConfig::default_class` now take
  `TcHandle` instead of raw `u32`.

  | Old                                                  | New                                                       |
  |---|---|
  | `conn.add_qdisc_full(dev, "root", Some("1:"), cfg)`  | `conn.add_qdisc_full(dev, TcHandle::ROOT, Some(TcHandle::major_only(1)), cfg)` |
  | `conn.add_qdisc_full(dev, "root", Some("1:"), cfg)`  | `conn.add_qdisc_full(dev, "root".parse()?, Some("1:".parse()?), cfg)` (string-style still works via `FromStr`) |
  | `HtbQdiscConfig::new().default_class(0x10)`          | `HtbQdiscConfig::new().default_class(TcHandle::new(1, 0x10))` (was ambiguous before) |
  | `FlowerFilter::new().classid("1:5")`                 | `FlowerFilter::new().classid(TcHandle::new(1, 5))`        |
  | `tcmsg.handle() // u32`                              | `tcmsg.handle() // TcHandle`                              |

- **Filter priorities are now `FilterPriority` instead of raw `u16`.**
  Recipe helpers (`PerPeerImpairer`, `PerHostLimiter`) install filters
  in the recipe band (`100..200`); operator filters traditionally use
  `1..50`. `FilterPriority::From<u16>` is provided for compatibility.
```

---

## 8. Open questions

1. **`TcHandle` vs separate `QdiscHandle` / `ClassHandle` / `FilterHandle`?**
   The kernel uses one type. Distinguishing would catch the rare
   "passed a class handle where a qdisc handle was expected" mistake at
   the type level, but most APIs already disambiguate by parameter
   name. Recommendation: one type. Revisit if real-world misuse shows up.
2. **`MqprioConfig::default_class` taking minor only.** The kernel
   stores it in 16 bits (the major is implicit). Either:
   - Use `TcHandle` and panic/error on `major != 0` (loose but
     consistent)
   - Add `TcMinor(u16)` (strict but more types to learn)
   Lean: `TcHandle` with a runtime assert in debug builds.
3. **`TcMessage::handle()` return-type change.** Today `u32`, proposed
   `TcHandle`. This is a breaking change to *every* TC dump consumer.
   Worth keeping a `handle_raw() -> u32` accessor for raw kernel
   access? Recommendation: yes, behind a `non_exhaustive`-friendly
   "internal kernel value" doc note.
4. **`TcHandle::From<u32>`?** Convenient, but encourages bypassing
   `from_raw` documentation. Recommendation: no — `from_raw` is one
   character longer and signals intent.
5. **`FilterPriority` band convention enforcement.** Today documentation
   only. Should `FilterPriority::recipe()` be the only constructor for
   recipe-band values, with `new()` requiring the value be outside that
   band? Lean: no — the band convention is advisory; making it
   load-bearing is rigid for negligible gain.

---

## 9. Phasing

Single PR. Same scope class as the Rate plan (~1200 LOC, mechanical).
Land in lockstep with Rate if both are happening — they touch the
same files and migrating each independently doubles the touch.

---

## 10. Risk register

| Risk | Likelihood | Mitigation |
|---|---|---|
| External callers' code breaks loudly | Certain | Migration table in CHANGELOG. `FromStr` keeps the string path working. |
| Common-case verbosity ("1:".parse() everywhere) | Medium | Add `add_qdisc_at_root(dev, handle, cfg)` sugar; document `FromStr` pattern in CLAUDE.md |
| `FilterPriority` band convention ignored | Medium | Documentation; helpers default to recipe band |
| `TcHandle::Display` differs from `tc(8)` in edge cases | Low | Property tests against `tc qdisc show` output for representative cases |
| `MqprioConfig` major-vs-minor ambiguity | Low | Document the convention; debug_assert in dev |

---

## 11. What we are NOT doing

- **No `From<&str>` for `TcHandle`** (would have to panic).
- **No separate types per handle role** (qdisc/class/filter handle).
- **No `FilterPriority` band enforcement** at the type level — bands
  are documented conventions.
- **No automatic priority allocation** ("give me an unused recipe-band
  priority"). Recipe helpers compute it themselves; complex allocation
  is the caller's job.

---

## 12. Definition of done

- [ ] `TcHandle` exists in `crates/nlink/src/netlink/tc_handle.rs` with full unit tests
- [ ] `FilterPriority` exists in `crates/nlink/src/netlink/filter_priority.rs` with full unit tests
- [ ] All Connection TC methods migrated per §4.1-§4.3
- [ ] All builder fields migrated per §4.4
- [ ] `TcMessage::handle()`/`parent()` return `TcHandle`; `_str()`
      / `_raw()` accessors documented
- [ ] `bins/`, examples, recipes, CLAUDE.md, README all updated
- [ ] All integration tests pass
- [ ] `cargo clippy --workspace --all-targets --all-features -- --deny warnings` passes
- [ ] CHANGELOG migration table written

---

End of plan.
