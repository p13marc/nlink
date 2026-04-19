---
to: nlink-lab team
from: nlink maintainers
subject: Per-peer netem impairment — implementation plan (response to 128)
nlink target version: 0.13.0
date: 2026-04-19
status: §10 answered (2026-04-19); proceeding to implementation
---

# Per-Peer Impairment Helper — Implementation Plan

## 0. Summary

We will add a `PerPeerImpairer` recipe helper to nlink, structurally
mirroring `PerHostLimiter`, in a new `nlink::netlink::impair` module.
This is pure composition over existing primitives — no new netlink
machinery — but the recipe encapsulates a few non-obvious decisions
(root choice, handle layout, default semantics) that are worth owning
in the library rather than re-deriving in every consumer.

Headline decisions:

- **HTB** at root, not PRIO. PRIO is strict-priority and would let one
  peer's traffic starve the others under load on real interfaces;
  PRIO also has no native `default_class` semantics. HTB matches
  `PerHostLimiter` exactly and trivially extends to per-peer rate +
  impair later. (See §3.1 for the analysis.)
- **cls_flower** as the only classifier. Mainline since 4.2; IPv4 and
  IPv6 in one builder; supports MAC matching natively. No u32 fallback.
- New module **`nlink::netlink::impair`** (sibling of `ratelimit`),
  rather than extending `ratelimit` whose name no longer fits.
- Helper takes the entire root qdisc on the target device. It is
  **destructive** (`del_qdisc(root)` then re-create) — same contract
  as `PerHostLimiter::apply`. Documented loudly.

We are not breaking BC for `PerHostLimiter` in this change. The user's
note that BC can break is noted but unused — we don't see a justified
reorganisation that would help users today, and the maintenance cost of
a churn-only rename outweighs the symmetry win. Revisit if a third
recipe lands.

The §5 proposal also asks for `get_filters_by_parent`. We'll add it as
a one-line client-side helper rather than a new dump path; `TcMessage`
already exposes `parent()`.

We're targeting nlink **0.13.0** (next minor). No deprecations needed.

---

## 1. Goals & non-goals

### Goals

1. Per-destination netem impairment on a single interface, configured
   once, applied atomically (cleared root → fresh tree).
2. API shape mirrors `PerHostLimiter` so users who know one know the
   other.
3. Match by destination IPv4, IPv6, IPv6 subnet, IPv4 subnet, and
   destination MAC. (Source variants deferred — see §3.4.)
4. Optional `default_impairment` for unmatched traffic.
5. Idempotent teardown via `clear()`.
6. Namespace-friendly: takes a `Connection<Route>` (already
   namespace-scoped); also offers an ifindex constructor to avoid
   `/sys` reads.
7. Recipe documentation in `docs/recipes/per-peer-impairment.md` so
   users who need a custom topology can hand-roll without reading
   the helper's source.

### Non-goals (this change)

1. Server-side filter dump filtering. Client-side `.parent() == X`
   is fine.
2. BPF-based impairment dispatch.
3. `modprobe cls_flower` from within nlink. Out of scope; document
   the EOPNOTSUPP signature.
4. Reorganising `ratelimit` into a `recipes` parent module.

---

## 2. Use case recap

A multi-namespace lab puts N namespaces on a shared L2 bridge. The
caller wants different RTT/loss between every (src, dst) pair, e.g.
satellite-link emulation:

```
hq -- alpha    delay 15ms loss 1%
hq -- bravo    delay 40ms loss 5%
alpha -- bravo delay 60ms loss 8%
```

Per-peer impairment is applied **on each bridge-port veth, egress
side**, classifying packets by destination IP. Symmetric pair
impairment requires applying on both bridge ports of the pair (see
§9 for caller responsibilities).

---

## 3. Design decisions

### 3.1. Root qdisc: HTB, not PRIO

The proposal suggests PRIO. We surveyed both. HTB wins.

**PRIO is strict priority.** Bands are dequeued in band order; band
1 must be empty before band 2 transmits, etc. If peer A is in band 1
and peer B is in band 2, then sustained traffic from A will starve B
on any link with real contention. On a memory-to-memory veth this
rarely matters in practice, but the helper is a library API — it must
behave correctly on real interfaces too. (And lab veths can be
saturated by iperf — it does happen.)

PRIO also caps at `TCQ_PRIO_BANDS = 16` and has no native
`default_class`. The "catch unmatched traffic" path requires either
(a) a custom priomap or (b) a wildcard catch-all filter at lowest
priority. Both are workable but cement PRIO as the wrong shape for
"N independent per-peer pipes that don't compete with each other".

**HTB gives us, for free:**

- `default_class(N)` for unmatched traffic.
- Per-class rate ceilings, which we fix at a generous link-rate
  placeholder (default 10 Gbps; overridable). With each class's `rate
  == ceil == placeholder`, no class throttles in practice and there is
  no fairness conflict. Borrowing within parent gives effectively
  unconstrained access.
- No band cap. (Practical limit is well above any realistic peer
  count.)
- Identical structure to `PerHostLimiter`, so the helper code is
  almost copy-paste.
- A natural extension path for combined rate + impair (just lower the
  per-class rate).

We **do not** expose a "use PRIO instead" knob on the builder. The
helper is opinionated. Users who need PRIO can compose manually using
the recipe doc.

### 3.2. Filter classifier: cls_flower

Flower has been mainline since 4.2 (Aug 2015). IPv4, IPv6, and MAC
matching live in the same builder. `PerHostLimiter` already uses it.
No fallback to `cls_u32` — the kernel matrix where flower is missing
is not in nlink's support window, and silent fallback would mask real
configuration mistakes.

If `cls_flower` is unloaded (`EOPNOTSUPP` on add_filter), surface
the kernel error plainly. Document in the helper's rustdoc:

> Requires `cls_flower` (mainline since Linux 4.2). If loading fails
> with EOPNOTSUPP, run `modprobe cls_flower` in the target namespace.

### 3.3. Default link rate placeholder

HTB requires a positive rate per class. For "no shaping" we pick a
number larger than any realistic line speed but well below `u64::MAX`
to avoid overflow in any internal arithmetic.

- Default: **`10_000_000_000` bytes/sec** (≈80 Gbps), exposed as
  `impair::DEFAULT_ASSUMED_LINK_RATE_BPS`.
- Overridable per-helper via `.assumed_link_rate_bps(u64)`.

We deliberately don't try to query the link's real speed via ethtool.
veth reports a synthetic "10000 Mbps" anyway, and querying adds an
async dependency (`Connection<Ethtool>::new_async`) for negligible
benefit. Users who want faithful shaping should use the future
combined rate-impair path.

### 3.4. Match dimensions in v0.13

Ship:

- `PeerMatch::DstIp(IpAddr)`
- `PeerMatch::DstSubnet(IpAddr, u8)`
- `PeerMatch::DstMac([u8; 6])`
- `PeerMatch::SrcIp(IpAddr)`
- `PeerMatch::SrcSubnet(IpAddr, u8)`
- `PeerMatch::SrcMac([u8; 6])`

Defer:

- Port-based. The use case is per-peer, not per-flow.

### 3.5. Module name and placement

`nlink::netlink::impair`. Re-exported at the crate root as
`nlink::PerPeerImpairer` (alongside `RateLimiter`, `PerHostLimiter`).

`ratelimit` is left alone. We considered renaming the module to
something neutral (`tc_recipes`?) and folding both helpers in, but
that's pure churn for users who already have `use
nlink::netlink::ratelimit::PerHostLimiter` working. Revisit on the
third recipe.

### 3.6. Apply contract: destructive

`apply()` does `del_qdisc(root)` then re-creates the tree. Same as
`PerHostLimiter`. Brief packet drop during reconfiguration is
expected. No diff-and-mutate.

A future `reconcile()` that produces a minimal change set could be
useful for callers who reapply on every config tick, but it's a
larger design (what counts as "equal" between two `NetemConfig`s
when one omits a field that defaults to the other's value?) and not
what the proposal asks for.

### 3.7. Namespace ergonomics

The connection is already namespace-scoped. We expose two constructors:

- `PerPeerImpairer::new(dev: &str)` — what the proposal wants, ergonomic.
- `PerPeerImpairer::new_by_index(ifindex: u32)` — avoids the
  `/sys/class/net/<dev>/ifindex` read when the caller has already
  resolved the interface (typical in deploy/reconcile loops).

Internally the helper uses ifindex for all subsequent operations to
match the `*_by_index` convention from CLAUDE.md.

### 3.8. NetemConfig is not validated

We pass through whatever `NetemConfig` the caller hands us. If they
hand us an all-defaults netem (no delay, no loss, ...), we still apply
it — it's a no-op leaf, costs a queue but does nothing. Not worth
adding a `NetemConfig::is_noop()` check just to optimise that.

---

## 4. API surface

### 4.1. Public types

```rust
// crates/nlink/src/netlink/impair.rs

use std::net::IpAddr;
use crate::netlink::{Connection, Result, Route, InterfaceRef};
use crate::netlink::tc::NetemConfig;

/// Default link-rate placeholder used to fill HTB rate/ceil when the
/// caller hasn't provided one. Large enough to avoid throttling on any
/// realistic interface; small enough to leave headroom in HTB internals.
pub const DEFAULT_ASSUMED_LINK_RATE_BPS: u64 = 10_000_000_000;

/// Per-destination netem impairment on a single interface.
///
/// Applies a classful HTB tree at the device's root qdisc and routes
/// packets to per-destination netem leaves via cls_flower filters.
/// All previous root-qdisc state on the target interface is removed
/// when [`PerPeerImpairer::apply`] is called.
///
/// The recipe is documented at `docs/recipes/per-peer-impairment.md`.
///
/// # Direction
///
/// Filters match on **destination**; this impairs egress toward the
/// matched peer. For symmetric pair impairment, apply the helper on
/// both ends of the path (typically both bridge-port veths).
///
/// # Requirements
///
/// `cls_flower` must be available in the target namespace
/// (mainline since Linux 4.2). On `EOPNOTSUPP`, `modprobe cls_flower`.
#[derive(Debug, Clone)]
pub struct PerPeerImpairer {
    target: ImpairTarget,
    rules: Vec<PeerRule>,
    default_impairment: Option<NetemConfig>,
    assumed_link_rate_bps: u64,
}

#[derive(Debug, Clone)]
enum ImpairTarget {
    Name(String),
    Index(u32),
}

#[derive(Debug, Clone)]
struct PeerRule {
    match_: PeerMatch,
    impairment: NetemConfig,
}

#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum PeerMatch {
    DstIp(IpAddr),
    DstSubnet(IpAddr, u8),
    DstMac([u8; 6]),
}

impl PerPeerImpairer {
    pub fn new(dev: impl Into<String>) -> Self;
    pub fn new_by_index(ifindex: u32) -> Self;

    /// Set impairment applied to all traffic that doesn't match a rule.
    /// Without this, unmatched traffic still flows through the default
    /// HTB class but with no netem leaf, i.e. unmodified.
    pub fn default_impairment(self, cfg: NetemConfig) -> Self;

    /// Override the link-rate placeholder used for HTB classes.
    /// Default: `DEFAULT_ASSUMED_LINK_RATE_BPS`.
    pub fn assumed_link_rate_bps(self, bps: u64) -> Self;

    pub fn impair_dst_ip(self, ip: IpAddr, cfg: NetemConfig) -> Self;
    pub fn impair_dst_subnet(self, subnet: &str, cfg: NetemConfig) -> Result<Self>;
    pub fn impair_dst_subnet_parsed(self, addr: IpAddr, prefix: u8, cfg: NetemConfig) -> Self;
    pub fn impair_dst_mac(self, mac: [u8; 6], cfg: NetemConfig) -> Self;

    pub async fn apply(&self, conn: &Connection<Route>) -> Result<()>;

    /// Remove the impairment by deleting the root qdisc on the target.
    /// Idempotent: succeeds even if no qdisc is currently installed.
    pub async fn clear(&self, conn: &Connection<Route>) -> Result<()>;
}
```

### 4.2. New convenience on `Connection<Route>`

Listed in the small-requests section of the proposal. Worth doing
alongside the helper because the helper itself doesn't strictly need
it but reconcile-style consumers do.

```rust
// crates/nlink/src/netlink/filter.rs (impl block)

impl Connection<Route> {
    /// Return only the filters whose parent matches `parent`. Equivalent
    /// to `get_filters_by_index(...).await?.into_iter().filter(...)`,
    /// kept in the API to spare callers the boilerplate.
    pub async fn get_filters_by_parent(
        &self,
        dev: impl Into<InterfaceRef>,
        parent: &str,
    ) -> Result<Vec<TcMessage>>;
}
```

`parent` accepts the standard "1:", "1:5", "ffff:" handle syntax via
the existing `tc_handle::parse(...)` (or whatever it's called
internally). On parse failure → `Error::InvalidArgument`.

### 4.3. Crate-root re-export

```rust
// crates/nlink/src/lib.rs
pub use crate::netlink::impair::{PerPeerImpairer, PeerMatch};
```

### 4.4. Prelude

Add to `nlink::prelude` if `PerHostLimiter` is in there. (Quick check
during implementation; if not, leave it out — proposal callers are
already importing from `nlink::netlink::ratelimit` explicitly.)

---

## 5. Internal recipe

Same skeleton as `PerHostLimiter::apply` (`crates/nlink/src/netlink/ratelimit.rs:650`).

```text
ifindex = resolve(target)
del_qdisc_by_index(ifindex, "root")             # idempotent: ignore errors

# Root HTB; default_class points at the catch-all class id (rules.len() + 2)
default_classid = (rules.len() + 1 + 1) as u32  # +1 for root class 1:1
add_qdisc_by_index(ifindex,
    HtbQdiscConfig::new()
        .handle("1:")
        .default_class(default_classid)
        .build())

# Root class 1:1 with rate = ceil = N * link_rate, lets children borrow.
total = (rules.len() + 1) as u64 * link_rate
add_class_config_by_index(ifindex, "1:0", "1:1",
    HtbClassConfig::from_bps(total).ceil_bps(total).build())

# One child class + netem leaf + flower filter per rule.
for (i, rule) in rules.iter().enumerate() {
    classid     = format!("1:{:x}", i + 2)        # 1:2 .. 1:(N+1)
    leaf_handle = format!("{:x}:", i + 10)        # a:, b:, c:, ...

    add_class_config_by_index(ifindex, "1:1", &classid,
        HtbClassConfig::from_bps(link_rate).ceil_bps(link_rate).build())

    add_qdisc_full_by_index(ifindex, &classid, Some(&leaf_handle),
        rule.impairment.clone())

    add_filter_by_index(ifindex, "1:",
        flower_filter_for(rule.match_, &classid, priority = 100 + i))
}

# Default class — receives anything no filter matched.
default_classid_str = format!("1:{:x}", rules.len() + 2)
default_handle      = format!("{:x}:", rules.len() + 10)

add_class_config_by_index(ifindex, "1:1", &default_classid_str,
    HtbClassConfig::from_bps(link_rate).ceil_bps(link_rate).build())

if let Some(cfg) = &default_impairment {
    add_qdisc_full_by_index(ifindex, &default_classid_str,
        Some(&default_handle), cfg.clone())
}
# else: no leaf qdisc; default class uses the implicit pfifo and is
# effectively pass-through.
```

`flower_filter_for(...)` switches on `PeerMatch`:

- `DstIp(V4)` → `dst_ipv4(addr, 32)`
- `DstIp(V6)` → `dst_ipv6(addr, 128)`
- `DstSubnet(V4, p)` → `dst_ipv4(addr, p)`
- `DstSubnet(V6, p)` → `dst_ipv6(addr, p)`
- `DstMac(m)` → `dst_mac(m)`

Priority is `100 + i` so the helper's filters sit out of the way of any
operator-installed filters (which conventionally use 1..50). Consumers
who layer their own filters above this can — though they're entering
unsupported territory because `apply()` will blow them away.

### 5.1. Why ifindex-internally

CLAUDE.md prescribes `*_by_index` for namespace-safe operations. The
existing `PerHostLimiter` uses `&self.dev` (name) and so does a
`/sys/class/net/<dev>/ifindex` read on every TC call. That's not a
correctness bug because the helper is normally used on the host, but
we're shipping `PerPeerImpairer` for namespaces specifically. Resolve
once, cache the ifindex for the duration of `apply()`.

### 5.2. Error handling

- `del_qdisc` of a missing root: ignore (matches `PerHostLimiter`).
- `add_filter` `EOPNOTSUPP` (cls_flower not loaded): wrap with a
  helpful message via `Error::with_context` ("cls_flower not loaded
  in target namespace; try `modprobe cls_flower`"). No fallback.
- Mid-tree failure: best-effort cleanup via `clear()`. Document that
  failed `apply()` may leave a partial tree and the caller should
  invoke `clear()` then retry.

---

## 6. Files touched

| Path | Change | Approx LOC |
|---|---|---|
| `crates/nlink/src/netlink/impair.rs` | New module | ~280 |
| `crates/nlink/src/netlink/mod.rs` | `pub mod impair;` | 1 |
| `crates/nlink/src/lib.rs` | Re-exports | ~3 |
| `crates/nlink/src/netlink/filter.rs` | `get_filters_by_parent` helper | ~25 |
| `crates/nlink/CLAUDE.md` | Recipe in patterns section | ~40 |
| `docs/recipes/per-peer-impairment.md` | New | ~150 |
| `crates/nlink/tests/integration/impair.rs` | New | ~250 |
| `CHANGELOG.md` | `## [0.13.0]` entry | ~10 |

Total: ~750 LOC, ~280 of which is the helper itself.

---

## 7. Tests

### 7.1. Unit tests (in `impair.rs`, no root)

- `test_builder_dst_ip_v4`
- `test_builder_dst_ip_v6`
- `test_builder_dst_subnet_parsing` (incl. invalid input)
- `test_builder_dst_mac`
- `test_default_impairment_optional`
- `test_assumed_link_rate_override`
- `test_clone_roundtrip`

### 7.2. Integration tests (`tests/integration/impair.rs`, root)

Run as part of the existing `integration` harness. Each test creates
a fresh netns, builds a small bridge with N veth members, and asserts.

- `test_apply_creates_expected_tree`: deploy 3-peer impairment,
  enumerate via `get_qdiscs_by_index`/`get_classes_by_index`/
  `get_filters_by_index`, assert handle/class/filter shape matches
  the recipe. (No timing.)
- `test_apply_idempotent`: apply twice; second apply yields the same
  tree (after the destructive teardown).
- `test_clear_removes_all`: apply, clear, assert no qdiscs at root.
- `test_default_impairment_applied_to_default_class`: apply with a
  default delay; assert the default class has a netem leaf.
- `test_no_default_means_no_default_leaf`: apply without
  default_impairment; assert the default class has no netem leaf.
- `test_partial_failure_path_is_recoverable`: induce a failure (e.g.
  invalid prefix), assert tree is recoverable via `clear()`.
- `test_v6_match`: build with IPv6 destination, verify filter dump
  shows IPv6 attrs.
- `test_dst_mac_match`: same for MAC.

We **do not** ship a ping-RTT timing test in CI. That belongs in
nlink-lab's integration suite where the deploy/measure scaffolding
already exists.

### 7.3. Doctest

The rustdoc on `PerPeerImpairer` includes a `# Example` block that
compiles with `ignore` (matches `PerHostLimiter`). Not run.

---

## 8. Documentation

### 8.1. `docs/recipes/per-peer-impairment.md`

Sections:

1. When to use this vs. per-interface netem
2. The high-level helper (link to rustdoc, code example)
3. The hand-rolled recipe (HTB + flower + netem) for users who want
   custom topology
4. Symmetric vs. asymmetric impairment, with a diagram of two veth
   bridge ports and which side carries which filter
5. Caveats:
   - Apply is destructive on the device's root qdisc
   - cls_flower must be loaded in the target namespace
   - Helper resolves ifindex once and uses it throughout `apply()`
6. Removing impairment (`clear()`)
7. Combining with rate shaping (manual recipe; lower per-class rate)

### 8.2. `crates/nlink/CLAUDE.md`

Add a short section under existing patterns, with a single example
that mirrors the proposal's use case. Link to the recipe doc for the
deeper writeup.

### 8.3. CHANGELOG

```
## [0.13.0] - 2026-04-XX

### Added
- `nlink::netlink::impair::PerPeerImpairer` — per-destination netem
  impairment recipe for shared L2 bridges.
- `Connection<Route>::get_filters_by_parent(dev, parent)` — client-side
  filter dump helper.
- `docs/recipes/per-peer-impairment.md` — recipe documentation.
```

---

## 9. Caller responsibilities (for nlink-lab)

These belong in nlink-lab, not nlink, but worth flagging here so the
plan is end-to-end.

1. **Symmetric pair impairment is two `apply()` calls.** A network
   declaration like `impair hq -- alpha { delay 15ms }` lowers to:
   - On `hq`'s bridge-port veth: `impair_dst_ip(<alpha>)` with the
     given netem.
   - On `alpha`'s bridge-port veth: `impair_dst_ip(<hq>)` with the
     given netem.

   nlink-lab's parser/lower owns this fan-out.

2. **Per-interface netem and per-peer netem are mutually exclusive on
   the same root.** If the user already declared `network { netem
   { ... } }` for the whole bridge, the per-peer block replaces it (or
   the lower errors out — design decision in nlink-lab).

3. **`cls_flower` modprobe.** If the namespace might lack the module,
   nlink-lab can `namespace::spawn` a `modprobe cls_flower` before
   calling the helper. nlink itself stays out of this.

---

## 10. Open questions for nlink-lab — RESOLVED

Answered 2026-04-19 by nlink-lab:

1. Naming → **`PerPeerImpairer`** (§4 unchanged)
2. Default impairment on default class → **(a) no leaf when unset** (§5 unchanged)
3. Source-side matching → **ship in v0.13** (§4 expanded; see §10a)
4. Combined rate + impair → **ship in v0.13** via `PeerImpairment` wrapper (§10a)
5. MAC matching → **ship in v0.13** (§4 unchanged)
6. `assumed_link_rate_bps` default → **10 GB/s** (§3.3 unchanged)
7. PR ownership → **nlink team writes; nlink-lab reviews**

### 10a. API additions from §10.3 / §10.4

Source-side `PeerMatch` variants:

```rust
pub enum PeerMatch {
    DstIp(IpAddr),
    DstSubnet(IpAddr, u8),
    DstMac([u8; 6]),
    SrcIp(IpAddr),         // new
    SrcSubnet(IpAddr, u8), // new
    SrcMac([u8; 6]),       // new
}
```

Source-side builder methods (mirror dst):

```rust
impl PerPeerImpairer {
    pub fn impair_src_ip(self, ip: IpAddr, imp: impl Into<PeerImpairment>) -> Self;
    pub fn impair_src_subnet(self, subnet: &str, imp: impl Into<PeerImpairment>) -> Result<Self>;
    pub fn impair_src_subnet_parsed(self, addr: IpAddr, prefix: u8, imp: impl Into<PeerImpairment>) -> Self;
    pub fn impair_src_mac(self, mac: [u8; 6], imp: impl Into<PeerImpairment>) -> Self;
}
```

Rate cap per rule via a small wrapper struct that pairs netem with an
optional cap:

```rust
pub struct PeerImpairment {
    netem: NetemConfig,
    rate_cap_bps: Option<u64>,
}

impl PeerImpairment {
    pub fn new(netem: NetemConfig) -> Self;
    pub fn rate_cap_bps(self, bps: u64) -> Self;
    pub fn rate_cap(self, rate: &str) -> Result<Self>;
}

impl From<NetemConfig> for PeerImpairment {
    fn from(netem: NetemConfig) -> Self;
}
```

Effect on the recipe (§5): each rule's HTB child class uses
`rate = ceil = rule.rate_cap_bps.unwrap_or(assumed_link_rate_bps)`.
The parent class 1:1 sums all per-rule caps + the default — same
total-rate accounting as `PerHostLimiter`.

All `impair_dst_*` and `impair_src_*` methods take
`impl Into<PeerImpairment>`, so the simple case stays one-line:

```rust
.impair_dst_ip(ip, NetemConfig::new().delay(...).build())
```

…and the rate-capped case is:

```rust
.impair_dst_ip(ip, PeerImpairment::new(netem).rate_cap("100mbit")?)
```

1. **Naming.** `PerPeerImpairer` (what you proposed) or `PerHostImpairer`
   (mirror `PerHostLimiter`'s "Host" wording)? We lean `PerPeerImpairer`
   because "peer" is the meaningful unit in your bridge model and
   "Impairer" already breaks the wording symmetry with "Limiter". Sound
   ok?

2. **Default impairment on the default class.** If the caller doesn't
   call `.default_impairment(...)`, do you want:
   - (a) The default class to have no netem leaf — pass-through. **Our
     preferred default.**
   - (b) The default class to have an explicit pfifo leaf — same
     observable behaviour but more explicit in the qdisc tree.
   
   We're going with (a). Speak up if you want (b).

3. **Source-side matching.** Confirm you don't need `impair_src_*`
   variants in v0.13. Our reading: no, since you'd apply on the
   opposite end's bridge port instead. If you have a use case that
   forces source matching, tell us now and we'll add the variants.

4. **Combined rate + impair.** Confirm you don't need the helper to
   expose a per-rule rate cap in v0.13. If you do, we'd add a
   `.rate_cap(bps)` per-rule modifier; the recipe extends naturally.

5. **MAC matching priority.** You mentioned `DstMac` in passing. Real
   v0.13 use case, or stub for completeness? If you don't have a
   concrete consumer, we'd defer to v0.14 and ship IP-only first.

6. **`assumed_link_rate_bps` default.** We picked 10 GB/s (≈80 Gbps)
   as the placeholder. If you regularly target 100GbE in labs, we'll
   bump it. Otherwise this is a non-issue.

7. **PR ownership.** You offered to send the PR. We're happy to write
   it ourselves to set the precedent for the recipe layout (cleaner
   for the recipe doc + CLAUDE.md update too). OK with us doing the
   first cut and you reviewing? Either way works.

---

## 11. Phasing & sequencing

All in one PR. ~750 LOC is well within review burden, and splitting
the helper from its docs/tests doesn't help anyone.

Order of work inside the PR:

1. Add `impair.rs` skeleton with `PeerMatch` enum and builder. Unit
   tests for the builder.
2. Implement `apply()` against the recipe in §5.
3. Implement `clear()`.
4. Add `Connection<Route>::get_filters_by_parent`.
5. Add `crates/nlink/src/lib.rs` re-exports and `mod.rs` declaration.
6. Integration tests (root-required, gated on the existing harness).
7. Recipe doc + CLAUDE.md update + CHANGELOG.
8. `cargo +stable clippy --all-targets --all-features -- --deny warnings`,
   `cargo machete`, `cargo nextest run -p nlink`, `taplo fmt --check`,
   `rustfmt +nightly --check`.

---

## 12. What we are NOT doing (and why)

- **No `tc_recipes` umbrella module.** Premature.
- **No PRIO backend.** §3.1.
- **No u32 fallback.** §3.2.
- **No ethtool-based link-rate detection.** §3.3.
- **No `NetemConfig::is_noop()` validator.** Cost of carrying it
  exceeds value; an empty netem leaf is harmless.
- **No `reconcile()` (diff-and-mutate) path.** Larger design; not
  asked for.
- **No `ratelimit` reorganisation despite BC freedom.** Churn-only
  change. Revisit when a third recipe lands.
- **No CLI `bins/` demo.** This is a library-level recipe; nlink-lab
  is the demo.

---

## 13. Risk register

| Risk | Likelihood | Mitigation |
|---|---|---|
| HTB `default_class` semantics differ from our reading on some kernel version | Low | Integration test asserts default-class behaviour explicitly |
| cls_flower MAC matching has surprising attribute requirements | Low | Integration test covers `DstMac` end-to-end |
| Bridge-port classful qdisc behaves oddly on ≥6.x | Very low | Test on the project's CI kernel; nlink-lab has prior in-namespace experience and hasn't hit this |
| 10 GB/s placeholder rate gets users in trouble at 100GbE | Low | Override knob shipped from day 1 |
| Filter priority `100 + i` collides with caller's existing filters | Low | Helper is destructive; caller's filters get wiped on apply. Documented. |
| Helper's `clear()` only clears the root qdisc, leaving stale ingress/clsact intact | Medium | Document — `clear()` is scoped to root egress only |

---

## 14. Definition of done

- [ ] `PerPeerImpairer` lives at `nlink::netlink::impair` with the API in §4.1
- [ ] `get_filters_by_parent` lives in `Connection<Route>`
- [ ] `docs/recipes/per-peer-impairment.md` exists
- [ ] `crates/nlink/CLAUDE.md` includes the new recipe in its patterns section
- [ ] Unit tests pass (no root)
- [ ] Integration tests pass under `sudo ./target/debug/deps/integration-* --test-threads=1`
- [ ] Lint/format clean: `clippy --all-features --deny warnings`, `taplo fmt --check`, `rustfmt --check`, `cargo machete`
- [ ] CHANGELOG updated under `## [0.13.0]`
- [ ] Open questions in §10 answered and any resulting API changes folded back in

---

End of plan. Awaiting answers to §10 before opening the PR.
