---
subject: nlink plan index — 0.19 cycle
status: cycle-close ready (cut pending)
target version: 0.19.0
maintainer: p13marc
last updated: 2026-05-31 (post-cycle audit + backfill)
---

# Plan index — 0.19 cycle

The 0.19 cycle's narrative lives in
[`CHANGELOG.md ## [Unreleased]`](../CHANGELOG.md) (will
become `## [0.19.0]` on cut) and the migration walkthrough
in
[`docs/migration_guide/0.18.0-to-0.19.0.md`](../docs/migration_guide/0.18.0-to-0.19.0.md).

## Quick status

- **Branch**: all 0.19 work pushes to the `0.19` branch.
- **Workspace version**: `0.18.0` — bump to `0.19.0` at cut
  time via `scripts/cut-release.sh 0.19.0`.
- **CI**: full pipeline green (lib unit + integration +
  workspace clippy + machete + 4 audit gates).
- **Lib test count**: 1080 passing as of 2026-05-31.
- **Plans shipped**: 16 of 17. Plan 197 deferred to 0.20
  with documented rationale (kernel ABI maturing).

## Status legend

| Symbol | Meaning |
|---|---|
| ✅ | Shipped (full or scoped subset) |
| 🟡 | Subset shipped; remainder deferred |
| ⛔ | Deferred to 0.20 with documented rationale |

## Sub-plan table

| Plan | Title | Status | Notes |
|------|-------|--------|-------|
| [186](186-vlan-parent-resolution-race-plan.md) | VLAN parent ifindex race — integration repro + topo-sort | ✅ | Topo-sort in `compute_diff` + 3 root-gated integration tests + 7 unit tests pin sort behavior. |
| [187](187-error-api-hygiene-plan.md) | Error API hygiene — sign normalization + chain_walk + Io-shape sweep | ✅ | Shipped pre-cycle (commits `83c417c` + `750cb64`). Caught 3 real bugs in `is_busy`/`is_already_exists`/`is_permission_denied`. |
| [188](188-declarative-apply-parity-plan.md) | Declarative apply parity — `ConfigDiff::apply`, builders, `apply_reconcile`, idempotent del_* | ✅ | All 7 sub-items shipped + 3 root-gated integration tests in `cycle_0_19_backfill.rs`. |
| [189](189-serde-feature-flag-plan.md) | `serde` feature flag — Serialize derives across 30+ types | 🟡 | Serialize-only (no Deserialize / schemars / runtime-types — documented deferrals). 5 unit tests pin kebab-case / snake_case shape. |
| [190](190-linkbuilder-gaps-plan.md) | LinkBuilder gaps — VXLAN + VLAN protocol + VRF + netkit + ovpn link + IPv4 GSO/GRO + bond | ✅ | All 6 sub-items + 2 §8 expansions. Parser-only for IPv4 GSO/GRO (declarative-write deferred). |
| [191](191-route-events-with-resync-plan.md) | `Connection<Route>::into_events_with_resync` + `rtnetlink_snapshot` | ✅ | Re-uses existing `NetworkEvent` enum (not a separate `RouteEvent`). |
| [192](192-docs-pass-plan.md) | Docs pass — D4 docstrings + W7 tracing + CLAUDE.md namespace-safety + audit script | ✅ | All 4 components shipped including §2.7 backfill (new `audit-sysfs-in-lib.sh` + CI gate). |
| [193](193-parser-robustness-plan.md) | Parser robustness — phase 1 policy + phase 2 MessageIter fix | 🟡 | Phase 1 + phase 2 + audit gate shipped. Phase 2 surfaced + fixed a REAL infinite-loop bug in `MessageIter::next`. Fuzz + proptest infrastructure deferred. |
| [194](194-concurrent-stress-plan.md) | Concurrent stress tests — seq routing + namespace isolation | ✅ | 2 root-gated integration tests (consolidated from 3 specified). |
| [195](195-stream-combinators-plan.md) | `ResyncStreamExt` combinators | 🟡 | `predicate_filter` + `map_event` shipped. `StreamBackoff` + `Store<K>` + `backon` deferred (acknowledged). |
| [196](196-declarative-wireguard-plan.md) | Declarative `WireguardConfig` — diff + apply + reconcile | ✅ | Full diff/apply/reconcile shipped + `PublicKey` newtype + `Display` for diff + integration tests. INI parser + `client()` shortcut deferred. |
| [197](197-declarative-ovpn-plan.md) | ovpn GENL family — imperative + declarative | ⛔ | Deferred to 0.20. Kernel 6.16 ovpn UAPI still maturing; the imperative `Connection<Ovpn>` family doesn't exist in nlink yet. Link half ships via Plan 190 §2.3b. |
| [198](198-declarative-nft-sets-plan.md) | Declarative nftables sets — full `DeclaredSet` + element diff | 🟡 | `SetKeyType::InetProto` + `Concat(Vec<_>)` variants shipped. Full declarative `DeclaredSet` deferred. |
| [199](199-wireguard-monitor-plan.md) | WireGuard polling watcher (kernel has no multicast) | ✅ | Redesigned after kernel research confirmed `n_mcgrps = 0`. Ships polling-based `WireguardWatcher` + 11 unit tests + integration test (gated by `require_module!("wireguard")`). |
| [200](200-high-level-facade-api-plan.md) | High-level facade — `nlink::facade::{apply,diff,watch}` + `Stack` | ✅ | 3 modules + Stack shipped + 2 root-gated integration tests. ovpn intentionally absent until Plan 197 lands. |
| [201](201-rust-idiom-polish-plan.md) | Rust idiom polish — must_use + From/Into + Display + inline | 🟡 | `#[must_use]` on 5 diff/report types shipped. Broader sweep deferred to 0.20. |
| [202](202-rta-multipath-parsing-plan.md) | RTA_MULTIPATH parser — Plan 193 §2.2 finding | ✅ | Parser + 6 defensive unit tests + root-gated round-trip integration test. |

## Headline contributions

1. **Plan 193 phase 2 found a real bug** — `MessageIter::next` returned `Err` from both bounds checks without advancing `self.data`. Plans 185 + 191 long-lived multicast subscribers would have spun on a single malformed kernel frame in production. Two-line fix, four regression tests. Bug class matches neli #305.
2. **Plan 199 redesigned after kernel research** — verified `drivers/net/wireguard/netlink.c` declares zero multicast groups (`n_mcgrps = 0`). The original spec assumed multicast events that don't exist in the kernel. Ships polling-based watcher matching what every WG monitoring tool does.
3. **Plan 200 facade ships the "newcomer one-liner" target** — `nlink::facade::apply::network(&cfg).await?` replaces 5-15 lines of typed-surface boilerplate. `Stack` bundles RTNETLINK + nftables + WG with deterministic apply order.

## CI gates (.github/workflows/)

| Workflow / Job | Purpose | Trigger |
|---|---|---|
| `rust.yml` → `build-test` | `cargo build` + `cargo test --lib` matrix + clippy + machete + workspace doc-build | push/PR to master |
| `rust.yml` → `audit-example-registration` | New `examples/**/*.rs` files must be registered in `Cargo.toml` | push/PR to master |
| `rust.yml` → `audit-recv-loop-error-handling` | Plan 193 §2.3 — event parsers walking `MessageIter` must skip per-frame, not abort | push/PR to master |
| `rust.yml` → `audit-sysfs-in-lib` | Plan 192 §2.7 — no `/sys/class/net/` or `/proc/sys/` reads in `crates/nlink/src/netlink/` outside ALLOWED | push/PR to master |
| `rust.yml` → `audit-ignored-tests` | Every `#[ignore]` catalogued in `tests/integration/IGNORED.md` | push/PR to master |
| `integration-tests.yml` | Root-gated integration suite — Debian container with `CAP_NET_ADMIN`+`CAP_SYS_ADMIN`+seccomp=unconfined. Loads kernel modules + runs `cargo test --features lab --test integration -- --test-threads=1` + lib tests + clippy + machete | push/PR to master |

## Documented 0.20 deferrals

| Plan | Why deferred |
|---|---|
| 189 — Deserialize + schemars + runtime-types Serialize | Plan 189 §8 expansions; ship Serialize-only first, expand if consumer asks |
| 193 — cargo-fuzz infrastructure | Requires nightly Rust + `fuzz/` directory; not blocking |
| 195 — StreamBackoff + Store<K> + backon | StreamBackoff needs `tokio::time::pause` integration tests; Store<K> picks dashmap |
| 196 — `WireguardConfig::client()` + `from_wg_config()` INI parser | Substantial; defer until consumer asks for the `wg-quick` shape |
| 197 — ovpn GENL family (full plan) | Kernel UAPI maturing; needs imperative `Connection<Ovpn>` first |
| 198 — Full declarative `DeclaredSet` + element diff | Substantial; ships imperative SetKeyType extensions now to unblock future declarative work |
| 201 — Broader sweep (From/Into + Display + #[inline]) | Mechanical; defer until §2.1 must_use bakes in |

## Cycle cut checklist (for `scripts/cut-release.sh 0.19.0`)

- [ ] Workspace version bumped to `0.19.0` in root + crates' `Cargo.toml`
- [ ] `CHANGELOG.md ## [Unreleased]` promoted to `## [0.19.0]` with date
- [ ] `docs/migration_guide/0.18.0-to-0.19.0.md` headline polished
- [ ] `docs/migration_guide/README.md` row inserted with cycle highlights
- [ ] `nlink-macros` published before `nlink` (path-dep version pinning)
- [ ] Per-plan files in `plans/` deleted post-cut per `CLAUDE.md ## Publishing` convention; INDEX.md rewritten for the next cycle

## Deprioritized (parked)

| Plan | Why parked |
|------|------------|
| [152](152-0.16-integration-showcases-plan.md) | `aya` co-demo + Prometheus exporter + OTel example. Carried since 0.16 without a real adopter signal. Revisit if a downstream asks. |

## How to update this file

1. When a plan ships, flip the **Status** column.
2. When the cycle cuts + publishes, delete the per-plan
   files (durable narrative lives in CHANGELOG + migration
   guide).
3. Rewrite this INDEX when opening a new cycle.
