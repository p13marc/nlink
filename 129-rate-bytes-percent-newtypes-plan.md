---
to: nlink maintainers
from: nlink maintainers
subject: Type-safe units (Rate / Bytes / Percent) for nlink 1.0
target version: 0.13.0 (or 1.0 if we're going there)
date: 2026-04-19
status: draft, post-verification (2026-04-19) — site list expanded; HFSC asymmetry noted
related: 128-nlink-per-peer-impairer-plan.md (the unit bug that motivated this)
verified: codebase audit complete; web research denied (uom recommendation from training)
---

# Type-Safe Units for nlink — Rate, Bytes, Percent

## 0. Summary

Replace raw `u64` rates, `u64`/`u32` byte sizes, and unchecked `f64`
percentages with three small, hand-rolled newtypes:

- **`Rate`** — bandwidth, internally bytes/sec (matches kernel
  `tc_ratespec.rate`). Constructors for bits/sec, bytes/sec, kbit, mbit,
  gbit, tc-style strings (`"100mbit"`).
- **`Bytes`** — byte counts for burst sizes, queue limits, MTU
  contributions. Internally `u64`.
- **`Percent`** — clamped 0..=100 `f64` for netem loss, duplication,
  corruption, etc.

This is the headline 1.0 change: the recent 8× HTB rate bug
(`HtbClassConfig::new("100mbit")` shaped at 800 Mbps because bits/sec
got silently treated as bytes/sec) existed for ~12 months because
the type system gave no help. After this refactor, that mistake is a
compile error.

**Decision: roll our own.** External crates surveyed:

| Crate | Verdict |
|---|---|
| `uom` | Heavyweight (typenum, num-traits, generic dimensional analysis). Slow compiles. Overkill for two units. **Rejected.** |
| `dimensioned` | Older, similar, less maintained. **Rejected.** |
| `measurements` | Lighter but no `Rate` type and no tc-string parser. We'd be wrapping it. **Rejected.** |
| Hand-rolled | ~200 LOC, zero deps, full control over tc parsing quirks. **Adopt.** |

This is a substantial BC break — touches **~45 method signatures**
across the public TC API (verified count, not the rough ~30 first
estimate) — but is contained to one refactor pass.

**Verified counts** (post-audit, 2026-04-19):

- 18 rate-accepting methods across `tc.rs` (HtbClassConfig × 4,
  NetemConfig × 5, TbfConfig × 3, HfscClassConfig × 3, DrrClassConfig
  × 1 byte field, QfqClassConfig × 1 byte field, plus byte fields on
  HtbClassConfig)
- 13 rate/byte-accepting methods across `ratelimit.rs` (RateLimit ×
  3, RateLimiter × 8, PerHostLimiter × 9 already partially overlap)
- 3 rate methods on `impair.rs` (PerPeerImpairer + PeerImpairment)
- 9 percent-accepting methods on `NetemConfig`

The HFSC/DRR/QFQ subset is special: their kernel UAPI uses 32-bit
rate/size fields. The plan's `Rate` and `Bytes` types are u64
internally, which is wider than what HFSC/DRR/QFQ accept. Builders
saturating-cast at write time and emit a `debug_assert!` warning
during construction. This is a small ergonomic asymmetry callers
won't usually hit (4 GB/s = ~32 Gbps is the ceiling).

---

## 1. Goals & non-goals

### Goals

1. Eliminate bits/sec ↔ bytes/sec confusion at the type level.
2. Single canonical parser for tc-style rate strings (`"100mbit"`,
   `"1gbit"`, `"500kbps"`, `"1.5gibit"`), shared by `RateLimiter`,
   `PerHostLimiter`, `PerPeerImpairer`, `HtbClassConfig`, `TbfConfig`,
   `NetemConfig`, and any future caller.
3. `Rate`, `Bytes`, `Percent` are `Copy`, `Eq`, `Ord`, `Hash`, `Display`,
   `Debug`, `serde::Serialize` (when `serde` feature is on).
4. `Display` round-trips: `Rate::parse(r.to_string()).unwrap() == r`.
5. Arithmetic: `Rate * Duration → Bytes`, `Bytes / Duration → Rate`,
   `Rate + Rate → Rate`, `Bytes + Bytes → Bytes` (saturating).
6. Common-case ergonomics: `Rate::mbit(100)` short form for the
   90% case.

### Non-goals

1. Full SI dimensional analysis. We have three concrete types, no
   generic dimensions.
2. Floating-point rates. Internal storage is integer bytes/sec; sub-bps
   precision is unnecessary.
3. Negative rates / counts. Unsigned, saturating arithmetic.
4. `Bytes` for *file* sizes (KiB/MiB binary base) — `Bytes` here means
   network burst/buffer sizes; mostly used with the kernel which is
   decimal-base. Document this explicitly; if there's demand later, add
   `BinaryBytes` separately.

---

## 2. The bug this prevents

From `c03ba76`'s commit message:

> HTB rates parsed from strings were 8× too high. `HtbClassConfig::new(string)`
> parsed values like `"100mbit"` as bits/sec but stored them in fields
> the kernel reads as bytes/sec — so a "100mbit" rate actually shaped at
> ~800 Mbps.

The fix divided by 8 at the call site. It works, but the same bug class
can recur every time anyone touches a u64 rate field. The newtype
makes the conversion explicit:

```rust
// Before — easy to confuse:
let cfg = HtbClassConfig::from_bps(get_rate("100mbit")?);  // bug

// After — won't compile if you do the wrong thing:
let cfg = HtbClassConfig::with_rate(Rate::parse("100mbit")?);  // correct
let cfg = HtbClassConfig::with_rate(Rate::bytes_per_sec(12_500_000));  // also correct
let cfg = HtbClassConfig::with_rate(Rate::bits_per_sec(100_000_000));  // also correct
let cfg = HtbClassConfig::with_rate(12_500_000_u64);  // doesn't compile — type mismatch
```

---

## 3. Design

### 3.1. `Rate`

```rust
// crates/nlink/src/util/rate.rs (replaces today's free functions)

/// A bandwidth rate. Stored internally as **bytes per second** to match
/// the kernel's `tc_ratespec.rate` semantics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Rate(u64);

impl Rate {
    pub const ZERO: Self = Self(0);
    pub const MAX: Self = Self(u64::MAX);

    // ---- construction ----
    pub const fn bytes_per_sec(bps: u64) -> Self { Self(bps) }
    pub const fn bits_per_sec(bits_per_sec: u64) -> Self { Self(bits_per_sec / 8) }

    pub const fn kbit(n: u64) -> Self { Self::bits_per_sec(n * 1_000) }
    pub const fn mbit(n: u64) -> Self { Self::bits_per_sec(n * 1_000_000) }
    pub const fn gbit(n: u64) -> Self { Self::bits_per_sec(n * 1_000_000_000) }

    pub const fn kib_per_sec(n: u64) -> Self { Self(n * 1024) }
    pub const fn mib_per_sec(n: u64) -> Self { Self(n * 1024 * 1024) }

    /// Parse a tc-style rate string. Accepts `"100mbit"`, `"1gbit"`,
    /// `"500kbps"`, `"1.5gibit"`, `"100"` (bare bits/sec).
    pub fn parse(s: &str) -> Result<Self, RateParseError>;

    // ---- accessors ----
    pub const fn as_bytes_per_sec(self) -> u64 { self.0 }
    pub const fn as_bits_per_sec(self) -> u64 { self.0.saturating_mul(8) }

    // ---- arithmetic (saturating) ----
    pub const fn saturating_add(self, other: Rate) -> Rate { Rate(self.0.saturating_add(other.0)) }
    pub const fn saturating_sub(self, other: Rate) -> Rate { Rate(self.0.saturating_sub(other.0)) }
}

impl std::ops::Add for Rate { /* saturating */ }
impl std::ops::Sub for Rate { /* saturating */ }
impl std::ops::Mul<u64> for Rate { /* scale */ }

impl std::ops::Mul<Duration> for Rate {
    type Output = Bytes;
    fn mul(self, d: Duration) -> Bytes {
        Bytes::new((self.0 as u128 * d.as_nanos() / 1_000_000_000) as u64)
    }
}

impl std::iter::Sum for Rate { /* saturating sum */ }

impl fmt::Display for Rate {
    /// Formats as the smallest tc unit that rounds cleanly:
    /// `Rate::mbit(100).to_string() == "100mbit"`.
    /// `Rate::bytes_per_sec(1).to_string() == "8bit"`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result;
}

impl FromStr for Rate { type Err = RateParseError; /* delegates to Self::parse */ }

#[derive(Debug, thiserror::Error)]
pub enum RateParseError {
    #[error("empty rate string")]
    Empty,
    #[error("invalid number: {0}")]
    InvalidNumber(String),
    #[error("unknown unit: {0}")]
    UnknownUnit(String),
}
```

**Storage decision: bytes/sec.** Matches the kernel. Conversions to/from
bits/sec happen at construction and accessor time. No silent
unit-mismatch ever.

**Display: smallest clean tc unit.** Round-trips via `parse`. If the
rate isn't a clean multiple of any tc unit, fall back to bare bits/sec.

### 3.2. `Bytes`

```rust
// crates/nlink/src/util/bytes.rs (new)

/// A byte count. Used for burst sizes, queue limits, and other
/// kernel-side sizes that aren't rates. Decimal-base (KB = 1000) by
/// default; for binary-base see `Bytes::kib_size`/`mib_size`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Bytes(u64);

impl Bytes {
    pub const ZERO: Self = Self(0);
    pub const fn new(n: u64) -> Self { Self(n) }

    pub const fn kb(n: u64) -> Self { Self(n * 1_000) }
    pub const fn mb(n: u64) -> Self { Self(n * 1_000_000) }
    pub const fn gb(n: u64) -> Self { Self(n * 1_000_000_000) }

    pub const fn kib(n: u64) -> Self { Self(n * 1024) }
    pub const fn mib(n: u64) -> Self { Self(n * 1024 * 1024) }
    pub const fn gib(n: u64) -> Self { Self(n * 1024 * 1024 * 1024) }

    /// Parse a tc-style size string: `"32kb"`, `"1mb"`, `"64k"`.
    pub fn parse(s: &str) -> Result<Self, BytesParseError>;

    pub const fn as_u64(self) -> u64 { self.0 }
    pub fn as_u32_saturating(self) -> u32 { self.0.try_into().unwrap_or(u32::MAX) }
}

impl std::ops::Add for Bytes { /* saturating */ }
impl std::ops::Div<Duration> for Bytes {
    type Output = Rate;
    fn div(self, d: Duration) -> Rate {
        let secs = d.as_secs_f64();
        if secs > 0.0 { Rate::bytes_per_sec((self.0 as f64 / secs) as u64) } else { Rate::ZERO }
    }
}
impl std::iter::Sum for Bytes { /* saturating sum */ }

impl fmt::Display for Bytes { /* "32kb" / "1mb" / "1.5gib" */ }
impl FromStr for Bytes { /* delegates to parse */ }
```

### 3.3. `Percent`

```rust
// crates/nlink/src/util/percent.rs (new)

/// A percentage in the range 0..=100. Construction clamps; arithmetic
/// saturates.
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd, Default)]
pub struct Percent(f64);

impl Percent {
    pub const ZERO: Self = Self(0.0);
    pub const HUNDRED: Self = Self(100.0);

    pub fn new(value: f64) -> Self {
        Self(value.clamp(0.0, 100.0))
    }

    /// `Percent::from_fraction(0.5)` → `Percent(50.0)`.
    pub fn from_fraction(f: f64) -> Self {
        Self::new(f * 100.0)
    }

    pub const fn as_percent(self) -> f64 { self.0 }
    pub fn as_fraction(self) -> f64 { self.0 / 100.0 }

    /// Convert to the kernel's 32-bit probability representation
    /// (today's `percent_to_prob`).
    pub fn as_kernel_probability(self) -> u32 {
        ((self.0 / 100.0) * (u32::MAX as f64)) as u32
    }
}

impl fmt::Display for Percent { /* "12.34%" */ }
impl FromStr for Percent { /* parses "50%" or "0.5" */ }

// `Eq`/`Hash` deliberately not derived — float comparison.
```

### 3.4. Conversions and ergonomics

For the most common form (literal numbers), we get short
spellings via `const fn` constructors:

```rust
HtbClassConfig::with_rate(Rate::mbit(100))
NetemConfig::new().delay(Duration::from_millis(50)).loss(Percent::new(1.0))
```

For string parsing — common in CLIs and config files:

```rust
let r: Rate = "100mbit".parse()?;  // FromStr
let b: Bytes = "32kb".parse()?;
```

For interop with the existing `util::parse::get_rate` / `get_size`
free functions: deprecate them in favor of `Rate::parse` / `Bytes::parse`.
Keep them as `#[deprecated]` shims for one minor version (or delete in 1.0).

### 3.5. Where these slot in

The agent-scoped 27 rate sites + 12 percent sites all migrate. Selected
examples:

```rust
// Before
pub fn from_bps(rate: u64) -> Self;            // bytes/sec, ambiguous
pub fn rate_bps(self, bits_per_sec: u64) -> Self;  // bits/sec, even more ambiguous
pub fn loss(self, percent: f64) -> Self;       // clamped internally

// After
pub fn with_rate(rate: Rate) -> Self;
pub fn with_loss(self, p: Percent) -> Self;
```

The CLI bins (`bins/tc/`, `bins/ip/`) are the largest secondary
consumers; they parse `clap` strings and feed them to the API. They get
shorter:

```rust
// Before
let rate_bps = nlink::util::parse::get_rate(&args.rate)?;
let cfg = HtbClassConfig::from_bps(rate_bps / 8);  // remember to divide

// After
let cfg = HtbClassConfig::with_rate(args.rate.parse()?);  // or use clap's value_parser
```

---

## 4. API surface (changed signatures)

Full list of public-method signature changes. ~30 entries. Each is a
mechanical rewrite with one of `Rate` / `Bytes` / `Percent`. Cataloged
exhaustively to size the diff.

### 4.1. `nlink::netlink::tc`

Verified call sites from the codebase audit:

```rust
// HtbQdiscConfig — no rate fields, unchanged
// HtbClassConfig (tc.rs:2539-2579)
- pub fn new(rate: &str) -> Result<Self>
- pub fn from_bps(rate: u64) -> Self
+ pub fn new(rate: Rate) -> Self
+ // (no _bps variant; Rate handles all units)

- pub fn ceil(self, ceil: &str) -> Result<Self>
- pub fn ceil_bps(self, ceil: u64) -> Self
+ pub fn ceil(self, ceil: Rate) -> Self

- pub fn burst(self, burst: &str) -> Result<Self>
- pub fn burst_bytes(self, burst: u32) -> Self
+ pub fn burst(self, burst: Bytes) -> Self

- pub fn cburst(self, cburst: &str) -> Result<Self>
- pub fn cburst_bytes(self, cburst: u32) -> Self
+ pub fn cburst(self, cburst: Bytes) -> Self

// NetemConfig (tc.rs:225-275, 167-217)
- pub fn rate(self, bytes_per_sec: u64) -> Self
- pub fn rate_bps(self, bits_per_sec: u64) -> Self
- pub fn rate_kbps(self, kbps: u64) -> Self
- pub fn rate_mbps(self, mbps: u64) -> Self
- pub fn rate_gbps(self, gbps: u64) -> Self
+ pub fn rate(self, rate: Rate) -> Self

- pub fn loss(self, percent: f64) -> Self
- pub fn duplicate(self, percent: f64) -> Self
- pub fn corrupt(self, percent: f64) -> Self
- pub fn reorder(self, percent: f64) -> Self
- pub fn delay_correlation(self, corr: f64) -> Self
- pub fn loss_correlation(self, corr: f64) -> Self
- pub fn duplicate_correlation(self, corr: f64) -> Self
- pub fn corrupt_correlation(self, corr: f64) -> Self
- pub fn reorder_correlation(self, corr: f64) -> Self
+ pub fn loss(self, p: Percent) -> Self
+ pub fn duplicate(self, p: Percent) -> Self
+ pub fn corrupt(self, p: Percent) -> Self
+ pub fn reorder(self, p: Percent) -> Self
+ pub fn delay_correlation(self, p: Percent) -> Self
+ pub fn loss_correlation(self, p: Percent) -> Self
+ pub fn duplicate_correlation(self, p: Percent) -> Self
+ pub fn corrupt_correlation(self, p: Percent) -> Self
+ pub fn reorder_correlation(self, p: Percent) -> Self

// TbfConfig (tc.rs:634-664) — five rate/byte methods, all need migration
- pub fn rate(self, bytes_per_sec: u64) -> Self
- pub fn rate_bps(self, bits_per_sec: u64) -> Self
- pub fn peakrate(self, bytes_per_sec: u64) -> Self
- pub fn burst(self, bytes: u32) -> Self
- pub fn limit(self, bytes: u32) -> Self
+ pub fn rate(self, rate: Rate) -> Self
+ pub fn peakrate(self, rate: Rate) -> Self
+ pub fn burst(self, b: Bytes) -> Self
+ pub fn limit(self, b: Bytes) -> Self

// HfscClassConfig (tc.rs:2827-2857) — *** kernel-asymmetric: u32, not u64 ***
//
// HFSC's tc_service_curve.m1/m2 are 32-bit fields in the kernel UAPI.
// The current builder takes u32 directly. Two options:
//   (a) Have these methods take Rate and saturate-cast to u32 internally
//       (consistent ergonomics, possible silent truncation at 4 GB/s = ~32 Gbps)
//   (b) Keep them as u32 but rename to make the unit explicit
//       (rt_rate_bytes_per_sec(u32))
//
// Recommendation: (a). Add a debug_assert!(rate.as_bytes_per_sec() <= u32::MAX as u64)
// and document. Net upside: uniform Rate API across all qdiscs.
- pub fn rt_rate(self, rate_bps: u32) -> Self
- pub fn ls_rate(self, rate_bps: u32) -> Self
- pub fn ul_rate(self, rate_bps: u32) -> Self
+ pub fn rt_rate(self, rate: Rate) -> Self  // saturating-cast to u32 internally
+ pub fn ls_rate(self, rate: Rate) -> Self
+ pub fn ul_rate(self, rate: Rate) -> Self

// DrrClassConfig.quantum (tc.rs:2950) — bytes (NOT packets, plan was wrong)
- pub fn quantum(self, bytes: u32) -> Self
+ pub fn quantum(self, b: Bytes) -> Self  // saturating-cast to u32 internally

// QfqClassConfig (tc.rs:3036-3045)
- pub fn weight(self, weight: u32) -> Self  // dimensionless; stays u32
- pub fn lmax(self, bytes: u32) -> Self
+ pub fn lmax(self, b: Bytes) -> Self  // saturating-cast to u32 internally
```

### 4.2. `nlink::netlink::ratelimit`

```rust
// RateLimit
- pub fn new(rate: u64) -> Self        // ambiguous unit
- pub fn parse(rate: &str) -> Result<Self>
- pub fn ceil(self, ceil: u64) -> Self
- pub fn burst(self, burst: u32) -> Self
+ pub fn new(rate: Rate) -> Self
+ pub fn ceil(self, ceil: Rate) -> Self
+ pub fn burst(self, burst: Bytes) -> Self
// .latency(Duration) unchanged

// RateLimiter
- pub fn egress(self, rate: &str) -> Result<Self>
- pub fn egress_bps(self, rate: u64) -> Self
- pub fn ingress(self, rate: &str) -> Result<Self>
- pub fn ingress_bps(self, rate: u64) -> Self
- pub fn burst_to(self, ceil: &str) -> Result<Self>
- pub fn burst_to_bps(self, ceil: u64) -> Self
- pub fn burst_size(self, size: &str) -> Result<Self>
- pub fn burst_size_bytes(self, size: u32) -> Self
+ pub fn egress(self, rate: Rate) -> Self
+ pub fn ingress(self, rate: Rate) -> Self
+ pub fn burst_to(self, ceil: Rate) -> Self
+ pub fn burst_size(self, size: Bytes) -> Self

// PerHostLimiter
- pub fn new(dev: &str, default_rate: &str) -> Result<Self>
- pub fn new_bps(dev: &str, default_rate: u64) -> Self
- pub fn limit_ip(self, ip: IpAddr, rate: &str) -> Result<Self>
- pub fn limit_ip_with_ceil(self, ip: IpAddr, rate: &str, ceil: &str) -> Result<Self>
- pub fn limit_subnet(self, subnet: &str, rate: &str) -> Result<Self>
- pub fn limit_src_ip(self, ip: IpAddr, rate: &str) -> Result<Self>
- pub fn limit_src_subnet(self, subnet: &str, rate: &str) -> Result<Self>
- pub fn limit_port(self, port: u16, rate: &str) -> Result<Self>
- pub fn limit_port_range(self, start: u16, end: u16, rate: &str) -> Result<Self>
+ pub fn new(dev: &str, default_rate: Rate) -> Self
+ pub fn limit_ip(self, ip: IpAddr, rate: Rate) -> Self
+ pub fn limit_ip_with_ceil(self, ip: IpAddr, rate: Rate, ceil: Rate) -> Self
+ pub fn limit_subnet(self, subnet: &str, rate: Rate) -> Result<Self>  // subnet still parses
+ pub fn limit_src_ip(self, ip: IpAddr, rate: Rate) -> Self
+ pub fn limit_src_subnet(self, subnet: &str, rate: Rate) -> Result<Self>
+ pub fn limit_port(self, port: u16, rate: Rate) -> Self
+ pub fn limit_port_range(self, start: u16, end: u16, rate: Rate) -> Self
```

### 4.3. `nlink::netlink::impair`

```rust
// PeerImpairment
- pub fn rate_cap_bps(self, bytes_per_sec: u64) -> Self
- pub fn rate_cap(self, rate: &str) -> Result<Self>
+ pub fn rate_cap(self, rate: Rate) -> Self

// PerPeerImpairer
- pub fn assumed_link_rate_bps(self, bps: u64) -> Self
+ pub fn assumed_link_rate(self, rate: Rate) -> Self

// PUB const
- pub const DEFAULT_ASSUMED_LINK_RATE_BPS: u64 = 10_000_000_000
+ pub const DEFAULT_ASSUMED_LINK_RATE: Rate = Rate::bytes_per_sec(10_000_000_000)
```

### 4.4. `nlink::util::*`

```rust
// crates/nlink/src/util/parse.rs
- pub fn get_rate(s: &str) -> Result<u64>      // bits/sec — confusing
- pub fn get_size(s: &str) -> Result<u64>
+ #[deprecated(note = "use Rate::parse")] pub fn get_rate(...) -> ...   // 1 minor cycle, then delete in 1.0
+ #[deprecated(note = "use Bytes::parse")] pub fn get_size(...) -> ...

// crates/nlink/src/util/rate.rs (existing)
// Add deprecation shims OR delete the kbps_to_bytes helpers in favor of Rate::kbit etc.
```

For 1.0, just delete; document the migration in CHANGELOG. For 0.13,
deprecate-and-redirect and remove in 1.0.

---

### 4.5. Existing examples that will need updates

Audit found two examples calling string-rate APIs:

```
crates/nlink/examples/route/tc/classes.rs    HtbClassConfig::new("1gbit")?, etc. (4 sites)
crates/nlink/examples/ratelimit/simple.rs    RateLimit::parse("100mbit")? (1 site)
```

Plus `crates/nlink/examples/impair/per_peer.rs` (added in
prior work) uses `PeerImpairment::rate_cap("100mbit")?`. Migrate
all three.

---

## 5. Files touched

| Path | Change | Approx LOC |
|---|---|---|
| `crates/nlink/src/util/rate.rs` | Replace existing helpers with `Rate` newtype | ~250 |
| `crates/nlink/src/util/bytes.rs` | New | ~150 |
| `crates/nlink/src/util/percent.rs` | New | ~80 |
| `crates/nlink/src/util/mod.rs` | Re-export | ~5 |
| `crates/nlink/src/util/parse.rs` | Deprecate or delete `get_rate`/`get_size` | ±50 |
| `crates/nlink/src/netlink/tc.rs` | Migrate ~15 method signatures | ~300 |
| `crates/nlink/src/netlink/ratelimit.rs` | Migrate ~12 method signatures | ~150 |
| `crates/nlink/src/netlink/impair.rs` | Migrate 3 method signatures | ~30 |
| `crates/nlink/src/netlink/types/tc.rs` | Conversion helpers (`Rate ↔ tc_ratespec.rate`) | ~30 |
| `crates/nlink/src/lib.rs` | Re-export `Rate, Bytes, Percent` at crate root + prelude | ~10 |
| `crates/nlink/tests/integration/{tc,ratelimit,impair}.rs` | Test assertions | ~80 |
| `crates/nlink/examples/{ratelimit,impair}/*.rs` | Update example code | ~40 |
| `bins/tc/src/**/*.rs` | Migrate clap parsers | ~50 |
| `bins/ip/src/commands/tc/*.rs` | Same | ~30 |
| `docs/recipes/per-peer-impairment.md` | Update code samples | ~20 |
| `CLAUDE.md` | Update root + per-section examples | ~80 |
| `README.md` | Update one Rate-using snippet | ~5 |
| `CHANGELOG.md` | Migration notes | ~30 |

Total ~1300 LOC. Half is test/example/doc updates; the engine of the
change is in `util/` + ~30 method signatures across three modules.

---

## 6. Tests

### 6.1. `Rate` unit tests

- `Rate::mbit(100).as_bytes_per_sec() == 12_500_000`
- `Rate::bits_per_sec(100_000_000) == Rate::mbit(100)`
- `Rate::parse("100mbit").unwrap() == Rate::mbit(100)`
- `Rate::parse("12500000bps").unwrap() == Rate::bytes_per_sec(12_500_000)` (note: tc `bps` = bits/sec)
- Roundtrip: `Rate::parse(&Rate::mbit(100).to_string()).unwrap() == Rate::mbit(100)` for many rates
- `Rate::parse("garbage").is_err()`
- `Rate::ZERO + Rate::mbit(1) == Rate::mbit(1)`
- `Rate::MAX + Rate::mbit(1) == Rate::MAX` (saturating)
- `(Rate::mbit(8) * Duration::from_secs(1)).as_u64() == 1_000_000` (bytes)
- `(Bytes::mb(1) / Duration::from_secs(1)) == Rate::mbit(8)`
- `Sum<Rate>` over an iterator works and saturates

### 6.2. `Bytes` unit tests

- `Bytes::kb(1) == Bytes::new(1000)`
- `Bytes::kib(1) == Bytes::new(1024)`
- `Bytes::parse("32kb").unwrap() == Bytes::kb(32)`
- `Bytes::ZERO + Bytes::kb(1) == Bytes::kb(1)`
- `Bytes::MAX + Bytes::new(1) == Bytes::MAX` (saturating)
- `Bytes::kb(1).as_u32_saturating() == 1000`
- `Bytes::new(u64::MAX).as_u32_saturating() == u32::MAX`

### 6.3. `Percent` unit tests

- `Percent::new(50.0).as_fraction() == 0.5`
- `Percent::from_fraction(0.5).as_percent() == 50.0`
- `Percent::new(150.0).as_percent() == 100.0` (clamp)
- `Percent::new(-1.0).as_percent() == 0.0` (clamp)
- `Percent::new(50.0).as_kernel_probability() == u32::MAX / 2` (within ±1 ulp)

### 6.4. Integration tests (existing, root)

After migration, all existing TC tests should still pass with updated
arguments. Specifically verify:

- `test_apply_creates_full_tree` (impair) — assertion counts unchanged
- `test_egress_rate_limiting` (ratelimit) — bandwidth shaping verified
  via tc dump matches `Rate::mbit(N)` not `Rate::bytes_per_sec(N)`
- `test_htb_class_config_new` (tc unit) — values now in bytes/sec, no
  conversion comment needed

### 6.5. Doctest

Each newtype's rustdoc has a small runnable example showing
`from_*` + `as_*` round-trip. These are the "this is what the type
does" smoke tests.

---

## 7. Migration guide (CHANGELOG)

```markdown
### Changed (BC break)

- **TC rate, byte, and percent values are now strongly typed.**
  Replace raw `u64` rate args with `nlink::Rate`, raw byte args with
  `nlink::Bytes`, and `f64` percentages with `nlink::Percent`.

  | Old                                                | New                                                |
  |---|---|
  | `HtbClassConfig::from_bps(12_500_000)`             | `HtbClassConfig::with_rate(Rate::mbit(100))`       |
  | `HtbClassConfig::new("100mbit")?`                  | `HtbClassConfig::with_rate("100mbit".parse()?)`    |
  | `RateLimit::parse("100mbit")?`                     | `RateLimit::new("100mbit".parse()?)`               |
  | `RateLimiter::new("eth0").egress("100mbit")?`      | `RateLimiter::new("eth0").egress("100mbit".parse()?)` |
  | `NetemConfig::new().rate_mbps(100)`                | `NetemConfig::new().rate(Rate::mbit(100))`         |
  | `NetemConfig::new().loss(1.0)`                     | `NetemConfig::new().loss(Percent::new(1.0))`       |
  | `PeerImpairment::new(...).rate_cap("100mbit")?`    | `PeerImpairment::new(...).rate_cap("100mbit".parse()?)` |
  | `nlink::util::parse::get_rate("100mbit")?`         | `Rate::parse("100mbit")?`                          |

  All values are stored internally in bytes/sec (rates) or bytes
  (sizes), matching the kernel's `tc_ratespec` semantics. The 8× HTB
  rate bug fixed in 0.12.x is now impossible to reintroduce.
```

---

## 8. Open questions

1. **Re-export at crate root, in prelude, or both?** `Rate`/`Bytes`/
   `Percent` are touch-everything types. Recommendation: both crate
   root and prelude. (Differs from `PerPeerImpairer` which is in
   neither.)
2. **Operator overloading scope.** Should `Rate * f64 → Rate`? It's
   ergonomic for "80% of link rate" but introduces float arithmetic
   into an integer type. Lean: yes, with rounding documented.
3. **`serde` support.** Behind a `serde` feature? Default-on?
   Recommendation: feature-gated, not default. Most consumers don't
   need serialization.
4. **Display format for non-clean rates.** `Rate::bytes_per_sec(7)`
   isn't a clean tc unit. Display as `"56bit"` (8×7 bits/sec)?
   `"7Bps"`? `"7bps"` clashes with tc bytes-per-sec. Recommendation:
   `"56bit"` (always smallest tc-recognized unit).
5. **`Rate` vs `Bandwidth`.** Brief naming consideration. `Rate` is
   shorter and matches kernel terminology. Adopt `Rate`.
6. **Leave `RateLimit.rate` field public?** Today it's `pub rate:
   u64`. Newtype migration: `pub rate: Rate`. Or make private and add
   a getter. Recommendation: keep public (the struct is a config
   bag, not an invariant-bearing type).

---

## 9. Phasing

Single PR. ~1300 LOC, mechanical changes, contained behind one
type-system pivot. Splitting it would create ugly intermediate states
where some methods take `Rate` and others take `u64`.

Order of work inside the PR:

1. Add `Rate`/`Bytes`/`Percent` types + unit tests (compiles standalone)
2. Migrate `HtbClassConfig` and run TC tests — establishes the pattern
3. Migrate the rest of `tc.rs` (Netem, Tbf, Hfsc, Drr, Qfq)
4. Migrate `ratelimit.rs`
5. Migrate `impair.rs`
6. Migrate `bins/`
7. Update examples/recipes/CLAUDE.md/README
8. Deprecate `util::parse::get_rate`/`get_size`
9. Update CHANGELOG with the migration table

---

## 10. Risk register

| Risk | Likelihood | Mitigation |
|---|---|---|
| External callers' code breaks loudly | Certain | That's the point. Migration table in CHANGELOG. |
| Overflow in `Rate * Duration` for very long durations | Low | u128 intermediate; saturating cast |
| Float comparisons in `Percent` cause test flakiness | Medium | Test with explicit `assert!((a.as_percent() - b).abs() < 1e-6)` |
| Display format churns over time | Low | Round-trip property test pins format stability |
| `Rate::MAX * Duration` panics | Low | Saturating multiplication uses `u128` intermediate |

---

## 11. What we are NOT doing

- **No `uom`/`dimensioned` dep.** §0.
- **No generic `Quantity<D, U, V>`.** Three concrete types is enough.
- **No floating-point storage.** Integer bytes/sec everywhere.
- **No "smart" auto-conversion based on context.** Explicit constructors only.
- **No `Bytes` for *file* sizes.** Different semantic; KiB/MiB/GiB
  apply but base differs by domain.

---

## 12. Definition of done

- [ ] `Rate`, `Bytes`, `Percent` exist in `crates/nlink/src/util/` with full unit-test coverage
- [ ] All ~30 public methods listed in §4 migrated
- [ ] `bins/` migrated; all binaries still build
- [ ] All examples and recipes updated
- [ ] All integration tests pass (under `sudo`)
- [ ] `cargo clippy --workspace --all-targets --all-features -- --deny warnings` passes
- [ ] CHANGELOG migration table written
- [ ] CLAUDE.md root file's TC sections updated
- [ ] `util::parse::get_rate`/`get_size` deprecated (or deleted, depending on 0.13 vs 1.0 target)

---

End of plan.
