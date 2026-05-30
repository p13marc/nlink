---
subject: nlink plan index — 0.19 cycle
status: live (update as plans land)
target version: 0.19.0
maintainer: p13marc
created: 2026-05-29 (post-0.18 cut; 7 plans seeded 2026-05-30; expanded to 10 plans during first consolidation pass; expanded to 14 plans during second consolidation pass under the "everything in 0.19" directive)
---

# Plan index — 0.19 cycle

Day-to-day tracker for nlink's 0.19 work. The 0.18 cycle
shipped 2026-05-29 (both crates on crates.io; tagged `0.18.0`
on master; GitHub release at
https://github.com/p13marc/nlink/releases/tag/0.18.0). The 0.18
cycle's narrative lives in
[`CHANGELOG.md ## [0.18.0]`](../CHANGELOG.md) +
[`docs/migration_guide/0.17.0-to-0.18.0.md`](../docs/migration_guide/0.17.0-to-0.18.0.md).

## Quick status

- **Cycle**: 0.19.0 — branched from master post-0.18 cut.
- **Branch**: all 0.19 work pushes to the `0.19` branch.
  Cycle cut → master merge happens at release time. **Do not
  push to master.**
- **Workspace version**: `0.18.0` → bump to `0.19.0` on the
  first PR whose change cargo-semver-checks flags as
  semver-major. Multiple breaking changes:
  Plan 187 (Error factory sign-normalization),
  Plan 188 (ApplyOptions `#[non_exhaustive]`),
  Plan 190 (DeclaredLinkType enum widening),
  Plan 191 (RouteEvent enum addition + deprecation of raw
  `RtnetlinkGroup` constants),
  Plan 196 (`WireguardConfig` is net-new but the existing
  imperative API stays — no break),
  Plan 198 (`SetKeyType` enum widening).
- **CI**: open a draft PR `0.19 → master` once the first
  commit lands so the workflow fires on every push.
- **Seed reports**:
  - [`nlink-feedback.md`](../nlink-feedback.md) (nlink-lab
    maintainer, 2026-05-30)
  - 0.19 first consolidation-pass bug-hunt + kernel research
    (2026-05-30)
  - 0.19 second consolidation-pass: WireGuard `wg syncconf` +
    ovpn DCO + nftables sets research (2026-05-30)

## Status legend

| Symbol | Meaning |
|---|---|
| ⚪ | Planned — not started |
| 🟡 | In progress — PR open or work underway |
| 🟢 | Merged to master |
| 🔵 | Cut & published |

## Sub-plan table

Fourteen plans this cycle. Four groups: feedback-driven
(186-191 core), defensive (193-194 from ecosystem audit),
kube-rs-shape (195 stream combinators), GENL declarative
families (196-199 from the "everything in 0.19" directive).

| Plan | Title | Effort | Order | Status | Notes |
|------|-------|--------|-------|--------|-------|
| [186](186-vlan-parent-resolution-race-plan.md) | VLAN parent ifindex race — investigation-first + topo-sort + ordering docstring | ~4-12 h | 1 | ⚪ | **HIGH** correctness. Investigation phase = integration repro. |
| [187](187-error-api-hygiene-plan.md) | `Error` API hygiene — sign normalization + `chain_walk` + Io-shape sweep across all predicates | ~5 h | 2 | 🟢 | **Complete.** Shipped `83c417c` + `750cb64`. Predicate sweep caught 3 real bugs in `is_busy`/`is_already_exists`/`is_permission_denied`. |
| [188](188-declarative-apply-parity-plan.md) | Declarative apply parity — `ConfigDiff::apply`, builders, `apply_reconcile`, `default_v{4,6}`, idempotent del_*, deprecate `summary()` | ~6.5 h | 3 | 🟡 | 6 of 7 sub-items shipped (`d50429b` + `e3c4371` + `64a7288`). Only §2.4 `apply_reconcile` remains. |
| [189](189-serde-feature-flag-plan.md) | `serde` feature flag — `Serialize` + `Deserialize` on diffs + JSON Schema via `schemars` + runtime parsed-type `Serialize` | ~5.5 h (was 3.5) | 4 | ⚪ | Opt-in feature; expanded with Deserialize + Schema + runtime types. |
| [190](190-linkbuilder-gaps-plan.md) | `LinkBuilder` gaps — VXLAN advanced + VLAN protocol + VRF + netkit + ovpn link half + IPv4 GSO/GRO caps + bond options + macvlan Source | ~13 h (was 11.5) | 5 | ⚪ | Significantly expanded; bond options + macvlan Source absorbed. |
| [191](191-route-events-with-resync-plan.md) | `Connection<Route>::subscribe` + `RouteEvent` (18 variants now including TC + Rule) + `into_events_with_resync` | ~14.5 h (was 9.5) | 6 | ⚪ | **Headline #1** of 0.19. TC + Rule event variants added. |
| [192](192-docs-pass-plan.md) | Doc pass — D1, D4, D5, W7 universal tracing audit, CLAUDE.md namespace-safety spec | ~6.5 h (was 4.5) | 7 | ⚪ | Universal tracing audit expanded beyond Connection<P>. |
| [193](193-parser-robustness-plan.md) | Parser robustness — defensive parsing + 5 `cargo-fuzz` targets + `proptest` integration | ~10 h (was 7) | 8 | 🟡 | Phase 1 (policy doc + CI gate) shipped `be52799`. §2.1 + §2.2 came back N/A (lib already compliant); §2.2's gap surfaced as new [Plan 202](202-rta-multipath-parsing-plan.md). Phase 2 (fuzz target) + phase 3 (proptest) remain. |
| [194](194-concurrent-stress-plan.md) | Concurrent stress — seq routing + namespace + nftables transaction + ConnectionPool churn | ~7 h (was 4.5) | 9 | ⚪ | Defensive; transaction + pool stress added. |
| [195](195-stream-combinators-plan.md) | `ResyncStreamExt` — backoff/filter/map + **`reflector`/`Store<K>` + `backon` integration + combinator tracing** | ~10.5 h (was 6.5) | 10 | ⚪ | `Store<K>` reflector pattern + backon + tracing added. |
| **[196](196-declarative-wireguard-plan.md)** (**NEW**) | Declarative `WireguardConfig` — diff + apply + `wg syncconf` semantics + `LinkBuilder::wireguard` | ~14 h | 11 | ⚪ | **Headline #2**. First Rust crate to ship NetworkConfig-style WG reconciliation. |
| **[197](197-declarative-ovpn-plan.md)** (**NEW**) | ovpn GENL family — imperative + declarative `OvpnConfig` (kernel 6.16+) | ~17.5 h | 12 | ⚪ | New protocol family. First Rust coverage of ovpn declarative. |
| **[198](198-declarative-nft-sets-plan.md)** (**NEW**) | Declarative nftables sets — `DeclaredTableBuilder::set` with element diff + concat keys + vmaps | ~11 h | 13 | ⚪ | Closes the last declarative-nftables gap. |
| **[199](199-wireguard-monitor-plan.md)** | `Connection<Wireguard>::subscribe` + `WireguardEvent` + `into_events_with_resync` — third member of the watcher trinity | ~10 h | 14 | ⚪ | Composes on Plan 196 + Plan 195. |
| **[200](200-high-level-facade-api-plan.md)** (**NEW** — Rust-idiomaticity audit) | `nlink::{apply,diff,watch}` modules + `nlink::Stack` unified declarative bundle + `nlink::watch::namespace` multi-protocol watcher | ~12.5 h | 15 | ⚪ | **Newcomer experience headline.** One-line entry points; Stack closes the loop on nlink-lab's TopologyDiff envelope. |
| **[201](201-rust-idiom-polish-plan.md)** (**NEW** — Rust-idiomaticity audit) | Polish sweep — `#[must_use]`, `From`/`Into`, `Display`, `#[inline]`, `const fn`, iterator combinators + 3 audit CI gates | ~7 h | 16 | ⚪ | Pins conventions; future contributors inherit. |
| **[202](202-rta-multipath-parsing-plan.md)** (**NEW** — Plan 193 phase-1 finding) | RTA_MULTIPATH parser — multipath routes round-trip through `get_routes()` + `NetworkConfig::diff` idempotence | ~7.5 h | between-189-and-190 | ⚪ | Surfaced during Plan 193 phase-1 audit: nlink can WRITE multipath but doesn't PARSE it. Real bug for ECMP consumers (silent drift). Inherits Plan 193 §"Parser robustness" rules. |

Total estimated focused-work: **~167-182 h** (was ~160-175 h
before Plan 202's +7.5h surfaced during 193's audit).
Plans 200 + 201 add the one-line user-facing entry points +
the convention pins.

## Implementation progress (live)

**Commits landed on `0.19` branch** (most recent first):

| Commit | Plan | Phase |
|---|---|---|
| `64a7288` | 188 phases 3+4 | `LinkChanges::Display` + `del_*_if_exists` |
| `e3c4371` | 188 phase 2 | `ApplyOptions` `#[non_exhaustive]` + builders |
| `d50429b` | 188 phase 1 | `ConfigDiff::apply` + `default_v{4,6}` + `summary()` deprecation |
| `750cb64` | 187 phase 2 | `Error::chain_walk` + `root_cause` + `contexts` |
| `83c417c` | 187 phase 1 | Error factory sign normalization + Io-shape predicate sweep (3 real bugs caught) |
| `be52799` | 193 phase 1 | Parser robustness policy + CI gate |

Lib test count: **992 passing** (was 980 at cycle start; +12).
Clippy `--deny warnings` clean.

**Plans complete (🟢):** 187.
**Plans partially shipped (🟡):** 188 (6 of 7), 193 (1 of 4).
**Plans not started (⚪):** 186, 189, 190, 191, 192, 194, 195,
196, 197, 198, 199, 200, 201, 202.

**Per-plan idiom additions during the audit:**
- **187** — gained `Error::root_cause()`, `Error::contexts()`,
  named `ChainWalk` iterator (vs anonymous `impl Iterator`)
- **191** — gained `Connection<Route>::watch(factory)`
  one-call shortcut; equivalent on Nftables + Wireguard
- **195** — `Store<K>` switched from `RwLock<HashMap>` to
  `DashMap` (lock-free per-key, no across-await footgun)
- **196** — gained `PublicKey` newtype with `FromStr`/`Display`
  (base64) + `WireguardConfig::client(...)` quick-start +
  `WireguardConfig::from_wg_config(&str)` parser
- **198** — gained `FromIterator<IpAddr> for DeclaredSet` +
  `SetElement::{ipv4,ipv6,ether,inet_service,...}` const
  constructors

## Cross-plan dependencies + ordering rationale

```
193 (parser robustness — sanity gate) ──┐
194 (concurrent stress — sanity gate) ──┤
                                         │
187 (Error API + Io-shape sweep) ────────┤
                                         │
188 (apply parity, including 187's      │
     errno predicate fix in retries) ───┤
                                         │
186 (VLAN race investigation) ───────────┤
                                         │
190 (LinkBuilder gaps — VRF, netkit,    │
     ovpn LINK half, bond, macvlan) ────┤
189 (serde + Deserialize + Schema) ──────┤
                                         │
191 (RTNETLINK events — headline #1) ────┤
195 (stream combinators on 185 + 191) ───┤
                                         │
196 (declarative WireguardConfig) ───────┤
197 (declarative OvpnConfig) ────────────┤
198 (declarative nft sets) ──────────────┤
199 (WireGuard monitor — uses 195) ──────┤
                                         │
192 (docs + universal tracing audit) ────┘ (cycle closer)
```

**Recommended landing order (revised for expanded cycle):**

1. **193 (parser robustness + fuzz)** — sanity gate.
2. **194 (concurrent stress)** — sanity gate.
3. **187 (Error API)** — needed for 188/196/197's
   `apply_reconcile` retry classification.
4. **188 (apply parity)** — small ergonomic wins.
5. **186 (VLAN race)** — investigation may need a day.
6. **190 (LinkBuilder gaps)** — much new code; sets up
   `LinkBuilder::ovpn` for 197.
7. **189 (serde)** — independent.
8. **191 (RTNETLINK events)** — headline #1.
9. **195 (stream combinators)** — composes on 191.
10. **198 (declarative nft sets)** — closes nftables surface.
11. **196 (declarative WireGuard)** — substantial.
12. **197 (declarative ovpn)** — substantial; depends on
    Plan 190's LinkBuilder::ovpn.
13. **199 (WireGuard monitor)** — composes on 196 + 195.
14. **192 (docs + universal tracing audit)** — closes cycle.
15. **200 (facade APIs)** — lands LAST among feature plans.
    Depends on every declarative + watcher plan above shipping
    so the facades have something to wrap. Headline "newcomer
    one-liner" win.
16. **201 (Rust idiom polish)** — final sweep. Pins the
    conventions across everything that landed.

## Wishlist items NOT scoped this cycle

| Item | Why deferred |
|------|--------------|
| _none from feedback_ | All nlink-lab feedback items are now in 0.19. |
| miri integration | Genuinely out-of-scope; miri doesn't run native syscalls. |
| Anonymous nft sets (inline rule expressions like `{22, 80, 443}`) | Different shape than named sets (rule-expr layer); future plan. |
| OvpnConfig under TLS-handshake automation | Belongs in the higher-level OpenVPN userspace control, not in the kernel data-channel layer. |

## Deprioritized (parked)

| Plan | Why parked |
|------|------------|
| [152](152-0.16-integration-showcases-plan.md) | `aya` co-demo + Prometheus exporter + OTel example. Carried since 0.16 without a real adopter signal. Revisit if a downstream asks for it. |

## Cross-plan artifact ownership

The 0.19 cycle has shared infrastructure that needs a single
owner.

| Artifact | Owning plan | Notes |
|---|---|---|
| `docs/migration_guide/0.18.0-to-0.19.0.md` | Plan 193 creates the stub (lands first) | Each plan appends its `### Plan NNN` section. Stub in place. |
| `docs/migration_guide/README.md` row for 0.19 | Plan 193 inserts the row | ✓ in place. Polished at cycle cut with full highlights. |
| `CHANGELOG.md ## [Unreleased]` | All plans append; cycle-cut script promotes to `## [0.19.0]` | Each plan §9 lists its subsections. |
| `CLAUDE.md` updates | Each plan owns its own section | 9 plans contribute sections; coordinate at PR review. |
| `README.md` updates | Plans 189, 190, 191, 195, 196, 197, 198, 199 all touch README | Small per-plan touches; resolve at PR review. |
| `.github/workflows/*` CI gates | Plans 189, 192, 193 (4 gates total) + 193 fuzz workflow | One workflow file + matrix entries. |
| `scripts/audit-*.sh` audit scripts | Plans 192 + 193 (3 scripts) | New `scripts/` entries. |
| `docs/recipes/*.md` new recipes | Plans 186, 189, 190, 191, 195, 196, 197, 198, 199 | **Nine new recipes**. Update `docs/recipes/README.md` per plan. |
| `crates/nlink/examples/*.rs` new examples | Plans 186, 188, 189, 190, 191, 195, 196, 197, 198, 199 | **Twelve new examples**. Register each in `crates/nlink/Cargo.toml`. |

## Known maintainer-tooling bug

_None as of 0.18 cut._ The `wait_for_ci_green` stdout-vs-stderr
bug was fixed in 0.18 commit `6fb1c96`.

## How to update this file

When a plan moves status:

1. Edit the **Status** column emoji.
2. When a plan ships and the cycle cuts + publishes, delete the
   per-plan file (per CLAUDE.md "Publishing" / "Plan-file
   cleanup"). The durable narrative is the CHANGELOG entry +
   migration guide; plan files are working memory and shouldn't
   accumulate.
3. Rewrite this INDEX when opening a new cycle — clear the
   "Quick status" + "Sub-plan table" sections, leaving
   "Deprioritized" intact unless explicitly un-parked.
