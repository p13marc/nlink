---
to: nlink maintainers
from: nlink maintainers
subject: nlink 1.0 roadmap — overview and sequencing
target version: 1.0 (or 0.13.0 → 0.14.0 → 1.0 depending on ambition)
date: 2026-04-19
status: draft, post-verification consolidation (2026-04-19)
related: plans 129-135 (the seven detailed plans this overview indexes)
---

# nlink 1.0 Roadmap — Overview

## 0. What this is

A consolidated index of the seven detailed plans drafted alongside
this document. Each plan is self-contained and reviewable in
isolation; this document gives the cross-cutting view: dependencies,
sequencing, and which combinations make sense together for which
release.

The plans came out of the discussion that followed
`128-nlink-per-peer-impairer.md` (per-peer netem helper) and the bug
class it surfaced (`HtbClassConfig::new("100mbit")` shaped at 800 Mbps
because bits/sec got silently treated as bytes/sec). The 1.0 release
is the natural moment to fix that class of issue at the type level.

---

## 1. The seven plans

| # | Plan | Tier | LOC est. | BC break | Headline |
|---|---|---|---|---|---|
| 129 | [Rate / Bytes / Percent newtypes](129-rate-bytes-percent-newtypes-plan.md) | 1 (foundation) | ~1300 | Major | Eliminates the unit-confusion bug class permanently. ~45 method signatures change. |
| 130 | [TcHandle / FilterPriority newtypes](130-tc-handle-priority-newtypes-plan.md) | 1 (foundation) | ~1200 | Major | Replaces `&str`/`u32` handles across **52 connection methods**. |
| 131 | [Reconcile pattern for recipes](131-reconcile-plan.md) | 1 (foundation) | ~1750 | Additive | Non-destructive `reconcile()` for `PerHostLimiter` and `PerPeerImpairer`. Idempotent. |
| 132 | [API cleanup (builders + non_exhaustive)](132-api-cleanup-plan.md) | 2 (polish) | ~600 | Major (small) | Locks down ~85 of 96 unmarked enums for 1.0; collapses `*Built` wrapper types. |
| 133 | [TC coverage (cake-typed + fq_pie + cls_basic ematch + act_bpf)](133-tc-coverage-plan.md) | 3 (additive) | ~1800 | Additive | Brings cake to typed-builder parity, adds fq_pie, makes cls_basic actually useful. |
| 134 | [Tracing instrumentation](134-tracing-instrumentation-plan.md) | 3 (additive) | ~600 | Additive | Wire up the unused `tracing` dep; INFO/DEBUG/TRACE convention. |
| 135 | [More recipes + public lab module](135-recipes-and-lab-helpers-plan.md) | 3 (additive) | ~2300 | Additive | 7 new recipes + promote `TestNamespace` → public `nlink::lab`. |

Total: ~9550 LOC across the seven plans. Mostly mechanical; the
substance is in the design decisions in plans 129/130/131.

---

## 2. Dependency graph

```text
                    ┌─────────────────────┐
                    │ 129 Rate/Bytes/%    │ ◄──── headline 1.0 change
                    │ (foundation)        │
                    └──────────┬──────────┘
                               │ enables typed Rate args in
                               │ qdisc/class builders
                               ▼
              ┌────────────────────────────────┐
              │ 130 TcHandle/FilterPriority    │ ◄── parallel foundation
              │ (foundation; touches same files)│     (land in same release as 129)
              └────────────────────────────────┘
                               │
                ┌──────────────┴───────────────┐
                ▼                              ▼
   ┌────────────────────────┐    ┌────────────────────────┐
   │ 132 API cleanup        │    │ 131 Reconcile pattern  │
   │ (subsumes _bps rename  │    │ (uses TcHandle for     │
   │  if 129 lands)         │    │  diff comparisons)     │
   └────────────────────────┘    └────────────────────────┘
                                              │
                                              │ tracing spans on
                                              │ recipe operations
                                              ▼
                                 ┌────────────────────────┐
                                 │ 134 Tracing            │
                                 │ (independent, useful   │
                                 │  alongside reconcile)  │
                                 └────────────────────────┘

  Independent of all the above:
  ┌────────────────────────┐    ┌────────────────────────┐
  │ 133 TC coverage gaps   │    │ 135 Recipes + lab      │
  │ (cake-typed, fq_pie,   │    │ (recipes use Plan 133's│
  │  cls_basic ematch,     │    │  cls_basic for cgroup  │
  │  act_bpf)              │    │  classification recipe)│
  └────────────────────────┘    └────────────────────────┘
```

**Hard dependencies** (must land before / together with):

- **129 ↔ 130**: same files, same release. Splitting forces an awkward
  intermediate state where some methods take `Rate` and others take `u64`.
- **132 → 129**: 132's `_bps` rename section is moot if 129 lands; the
  builder + non_exhaustive parts remain useful.
- **131 → 130**: reconcile compares handles; benefits from `TcHandle`
  but works with `&str` (just uglier).
- **135 cgroup recipe → 133 cls_basic**: the cgroup-classification
  recipe needs ematch support.

**Soft / optional**:

- **134 tracing** is independent; lands anytime.
- **135 recipes (excluding cgroup)** are independent.

---

## 3. Suggested release plan

### Option A: Single 1.0 release (ambitious)

Land all seven plans in one go. ~9500 LOC. Reviewable but heavy.
Pros: clean version story, one BC migration for downstream. Cons:
long-running branch, hard to merge.

### Option B: 0.13 → 0.14 → 1.0 staged (recommended)

**0.13.0** (the next minor; can break BC since pre-1.0):
- Plan 129: Rate / Bytes / Percent newtypes
- Plan 130: TcHandle / FilterPriority newtypes
- Plan 132: API cleanup (builder uniformity + non_exhaustive audit)
- Plan 134: Tracing instrumentation

This bundles all the BC-breaking type-level work plus the
free-standing tracing wins. Total ~3700 LOC.

**0.14.0** (additive):
- Plan 131: Reconcile pattern
- Plan 133: TC coverage gaps (cake-typed, fq_pie, cls_basic ematch,
  act_bpf, simple action)
- Plan 135: Recipes + public lab module

Total ~5800 LOC. Mostly additive; minimal further BC.

**1.0**: Whichever cycle is the right "we're done with major API
churn" moment. May be 0.14 itself if we feel solid; may be a 0.15
hardening cycle.

### Option C: Plans 129/130 only as a 1.0 cut

Minimal-scope 1.0 with just the type-safety foundations. Everything
else continues iterating in 1.x. Pros: fastest to 1.0 with the most
important fix. Cons: leaves the unused `tracing` dep and the missing
`reconcile` path on the table for "later."

**Recommendation: Option B.** 0.13 carries the headline work and is
defensible as a major version step; 0.14 stabilizes; 1.0 declares
done. Three milestones, each shippable.

---

## 4. Verification status of the seven plans

All seven plans were drafted, then audited against the codebase. Key
corrections folded in:

| Plan | Issue caught | Fixed |
|---|---|---|
| 129 | `DrrClassConfig::quantum` is bytes (not packets); HFSC rates are u32 (not u64); TBF rate methods missing from migration list | ✅ |
| 130 | "~20 connection methods" was wildly low — actual is **52** | ✅ |
| 130 | `netlink-packet-route` already has a `TcHandle` (training memory; verify) | ✅ noted |
| 131 | `QdiscOptions` only parses 6 qdiscs — fq_pie/cake/hfsc/drr/qfq are `Unknown(blob)`. Recipes that target HTB+netem (the existing two) are fully covered. | ✅ |
| 131 | No `parse_class_options` exists today — would need to add for HTB class rate/ceil reconciliation | ✅ |
| 132 | Audit count was "4 marked, ~36 unmarked" — actual is **44 marked, 96 unmarked** out of 140 enums | ✅ |
| 133 | "cake fully implemented" — half-true. Implemented in legacy `pub fn build(builder, &[String])` form only; no typed `CakeConfig`. Plan now adds the typed version. | ✅ |
| 134 | Verified: `tracing` dep at `Cargo.toml:38`, zero use sites, injection points correct | ✅ |
| 135 | Verified: `TestNamespace` at 195 LOC, all 8 methods present | ✅ |

**Items NOT verified** (web tools were denied during research):

- Current `uom` / `dimensioned` / `measurements` versions and dep
  trees — recommendation to roll our own is from training memory
- `netlink-packet-route` 0.19+ `TcHandle` field-naming — verify
  before depending on the upstream alignment claim
- Exact `TCA_CAKE_*` and `TCA_FQ_PIE_*` attribute lists from current
  kernel headers — verified count from training; spot-check
  `include/uapi/linux/pkt_sched.h` before implementation
- `cls_basic` ematch deprecation status — training says still
  supported; verify against `net/sched/cls_basic.c` recent commits

---

## 5. Cross-plan API cohesion

If 129 and 130 both land, the typed-builder shape becomes very
uniform across the TC API:

```rust
use nlink::{Connection, Route, Rate, Bytes, Percent, TcHandle, FilterPriority};
use nlink::netlink::tc::{HtbQdiscConfig, HtbClassConfig, NetemConfig};
use nlink::netlink::filter::FlowerFilter;
use std::time::Duration;

let conn = Connection::<Route>::new()?;

// HTB qdisc at root
conn.add_qdisc_full(
    "eth0",
    TcHandle::ROOT,
    Some(TcHandle::major_only(1)),
    HtbQdiscConfig::new()
        .default_class(TcHandle::new(1, 0xff))
        .build(),
).await?;

// Rate-shaped class with explicit Rate type
conn.add_class_config(
    "eth0",
    TcHandle::major_only(1),
    TcHandle::new(1, 1),
    HtbClassConfig::new(Rate::mbit(100))
        .ceil(Rate::mbit(500))
        .burst(Bytes::kib(32))
        .build(),
).await?;

// Netem leaf with typed Percent for loss
conn.add_qdisc_full(
    "eth0",
    TcHandle::new(1, 1),
    Some(TcHandle::major_only(0xa)),
    NetemConfig::new()
        .delay(Duration::from_millis(50))
        .loss(Percent::new(1.5))
        .build(),
).await?;

// Flower filter with typed FilterPriority
conn.add_filter_full(
    "eth0",
    TcHandle::major_only(1),
    None,
    0x0800,
    FilterPriority::recipe(0),
    FlowerFilter::new()
        .classid(TcHandle::new(1, 1))
        .dst_ipv4("10.0.0.1".parse()?, 32)
        .build(),
).await?;
```

Compare to today:

```rust
// Today: ambiguous units, raw u32 handles, &str parsing tax
HtbClassConfig::from_bps(get_rate("100mbit")?);  // 8x bug if you forget the / 8
add_class_config("eth0", "1:0", "1:1", cfg);     // strings parsed at every call
```

---

## 6. Open questions cutting across plans

1. **0.13 or 1.0?** Pre-1.0 BC is expected. 1.0 commits us to
   stability. Lean: 0.13 for the Tier-1 work, 0.14 for
   stabilization, 1.0 once the additive features have landed and we
   feel solid.

2. **Workspace-wide rollout.** All plans are nlink-only. The bins
   (`bins/{ip,tc,ss,nft,wifi,devlink,bridge,wg,ethtool,diag,config}`)
   need to migrate too. Plan 129 alone touches `bins/{tc,ip}`; the
   rest are mostly unaffected. Audit per-plan during implementation.

3. **`netlink-packet-route` interop.** Worth providing optional
   `From`/`Into` impls between our `TcHandle` and theirs (gated
   behind a feature flag)? Lean: yes, `nlink-interop` feature in a
   later release.

4. **GENL protocols (WireGuard, MACsec, MPTCP, Ethtool, nl80211,
   Devlink) — anything similar?** Plan 129's Rate may apply to
   WireGuard's keepalive intervals, ethtool's link rates, nl80211's
   bitrates. Each GENL family deserves a quick audit. Out of scope
   for plans 129-135; track as follow-on work.

5. **`config` module integration.** Plan 131's reconcile lives in
   the recipe helpers, not in `nlink::netlink::config::NetworkConfig`.
   Should `NetworkConfig::impair(name, PerPeerImpairer)` (or similar)
   bridge the two? Park as 1.x follow-on.

---

## 7. CHANGELOG strategy across releases

If we go with Option B (recommended):

### `## [0.13.0]` (target tag: 2026-Q3)

```markdown
### Changed (BC break)

- TC rates and sizes are now strongly typed via `Rate`, `Bytes`, `Percent`.
- TC handles are now strongly typed via `TcHandle`.
- Filter priorities are now strongly typed via `FilterPriority`.
- HTB rate parsing from strings now correctly converts bits/sec → bytes/sec
  (the 8× bug from 0.12.x is impossible to reintroduce).
- ~85 of 96 previously-unmarked public enums are now `#[non_exhaustive]`.
- Class builder `*Built` wrapper types removed; `.build()` returns Self.

### Added

- Public API instrumented with `tracing`. See `docs/observability.md`.
```

### `## [0.14.0]` (target tag: 2026-Q4)

```markdown
### Added

- `PerHostLimiter::reconcile()` and `PerPeerImpairer::reconcile()` —
  non-destructive convergence pattern.
- Typed `CakeConfig` builder + per-tin stats.
- `FqPieConfig` qdisc.
- `BasicFilter` with `ematch` (cmp/u32/meta).
- `BpfAction`, `SimpleAction`.
- `nlink::lab` module (feature `lab`) with public lab/test helpers.
- Cookbook recipes: bridge VLAN, bidir rate limit, WireGuard mesh,
  IPsec tunnel, nftables stateful firewall, cgroup classification,
  multi-namespace events, lab setup.
```

### `## [1.0.0]` (target: when stable)

```markdown
### Stable

API surface declared stable. No further BC breaks without a 2.0.
```

---

## 8. Review checklist for each PR

When reviewing any PR derived from these plans:

- [ ] Cross-checks against the relevant detailed plan
- [ ] All listed call sites migrated (no half-and-half state)
- [ ] CHANGELOG entry written under `## [Unreleased]`
- [ ] Tests updated and passing
- [ ] Examples and CLAUDE.md updated where relevant
- [ ] `cargo clippy --workspace --all-targets --all-features -- --deny warnings` passes
- [ ] `cargo machete` shows no NEW unused deps

---

End of overview. See plans 129-135 for the detailed work.
