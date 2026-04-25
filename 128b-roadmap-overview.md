---
to: nlink maintainers
from: nlink maintainers
subject: nlink roadmap — active plans only
target version: 0.14.0 and beyond
last updated: 2026-04-25 (typed-units rollout shipped — 25 parsers across 15 slices, qdisc 100%, filter 7/9; **Plan 142 is the consolidated 0.15.0 master** — read it first for the full picture; Plans 133 PR C / 138 / 139 / 140 / 141 are its phase-level details; **Phase 0 substantively shipped under `[Unreleased]`** — `lab::has_module` + `require_module!` helper, sealed `ParseParams` trait + 25 impls, bins/tc dispatch tightened — only the GHA workflow file itself remains, deferred until an in-tree test actually uses `require_module!`; Phase 1 next)
---

# nlink Roadmap

Forward-looking index of active plans. Shipped work is in
[`CHANGELOG.md`](CHANGELOG.md); detailed plans for shipped features
have been removed (their substance is in the commits + changelog).

## Active plans

**Read first:** [Plan 142 — 0.15.0 typed-API completion (zero-legacy milestone)](142-zero-legacy-typed-api-plan.md). It is the consolidated master plan for the 0.15.0 release: end-state API, phase ordering, legacy-removal acceptance criteria, doc-update requirements. Plans 133 PR C / 138 / 139 / 140 / 141 are its phase-level detail documents.

| # | Plan | Status | Headline |
|---|---|---|---|
| **142** | **[0.15.0 typed-API completion (zero-legacy milestone)](142-zero-legacy-typed-api-plan.md)** | **draft — master plan** | Consolidates Plans 133 PR C / 138 / 139 / 140 / 141 into a single 0.15.0 milestone. End-state: typed surface end-to-end, `tc::builders::*` and `tc::options::*` deleted from source tree, `bins/tc` zero `#[allow(deprecated)]`. Phases: 0 = CI infra + `ParseParams` trait; 1 = filter side completion (138 + 133 PR C + 137 integration tests); 2 = XFRM (141); 3 = action API (139 PRs A+B); 4 = LEGACY DELETION (139 PR C). |
| 133 | [TC coverage gaps](133-tc-coverage-plan.md) | **3 of 4 PRs landed** (A/B/D under `[Unreleased]`); **PR C → Plan 142 Phase 1** | Typed `CakeConfig`, `FqPieConfig`, `BpfAction`, `SimpleAction`. PR C (`BasicFilter` ematch — cmp/u32/meta) is now phase-level detail for Plan 142 Phase 1; needs golden `tc(8)` hex captures (run alongside Plan 140's CI infra). |
| 135 | [Recipes + public `nlink::lab`](135-recipes-and-lab-helpers-plan.md) | **PR A complete**; PR B partial (6 of 7) — both deferred recipes are Plan 142 phases | `nlink::lab` shipped (PR A). Six recipes shipped under `[Unreleased]`. The two deferred recipes (`xfrm-ipsec-tunnel` and `cgroup-classification`) close as Plan 142 Phase 2 (via Plan 141) and Phase 1 (via Plan 133 PR C) respectively, bumping PR B to 7/7. |
| 137 | [Netfilter expansion](137-netfilter-expansion-plan.md) | **PRs A+B kernel-validated** (under `[Unreleased]`); integration tests un-parked by Plan 142 Phase 0; C/D/E demand-gated | PRs A+B and the `conntrack-programmatic` recipe shipped. Integration tests slot into Plan 142 Phase 1. PRs C (`ct_expect`), D (nfqueue), E (nflog) **explicitly out of scope for 0.15.0** per Plan 142 §1; demand-gated. |
| 138 | [bins/tc u32 filter selector grammar](138-u32-filter-selector-grammar-plan.md) | **draft — Plan 142 Phase 1 detail** | 3-PR arc (raw triples; named-match shortcuts with golden-hex fixtures; hash-table grammar). |
| 139 | [Typed standalone-action CRUD](139-typed-standalone-action-crud-plan.md) | **draft — Plan 142 Phases 3 + 4 detail** | 3-PR arc. PR A library API; PR B per-kind `parse_params` (~14 action kinds); **PR C is the legacy-deletion milestone** (deletes `tc::builders::*` + `tc::options::*`). |
| 140 | [CI integration tests harness](140-ci-integration-tests-plan.md) | **`require_module!` helper shipped** under `[Unreleased]` (commit `553f9dd`); GHA workflow deferred until an in-tree test uses it | `nlink::lab::has_module` + `require_module!` macros landed. Workflow file itself is no-op until Phase 1 lands integration tests that actually call `require_module!` — wires up then. |
| 141 | [XFRM write-path API extension](141-xfrm-write-path-plan.md) | **draft — Plan 142 Phase 2 detail** | 3-PR arc modeled on Plan 137 PR A. Independent of Phase 1; can land in parallel. Closes Plan 135 PR B at 7/7. |

**Shipped & ready to archive:** Plan 136 (Example cleanup) — all phases plus the conntrack deferral resolved by Plan 137 PR A slice 3 (`1e9307e`). `MacsecLink` rtnetlink builder also landed as a follow-up; `examples/genl/macsec.rs` uses it directly. See CHANGELOG `## [Unreleased]` for the full slate.

## Release plan

- **0.13.0** (shipped 2026-04-19): typed `Rate` / `Bytes` / `Percent`
  newtypes, typed `TcHandle` / `FilterPriority`, API cleanup
  (builder uniformity + 95-enum `non_exhaustive` lockdown), and
  `tracing` instrumentation. See CHANGELOG `## [0.13.0]` for the
  migration tables and detailed bullets.
- **0.14.0** (in progress): reconcile pattern (shipped under
  `[Unreleased]`) + Plan 133 (except PR C) + Plan 135 PR A + 6 of 7
  PR B recipes + Plan 136 (all phases) + Plan 137 PRs A+B (typed
  ctnetlink mutation + multicast event subscription, both kernel-
  validated) + `MacsecLink` rtnetlink builder + `tc::builders::*`
  deprecation + **typed-units rollout** (15 slices, 25 typed
  `parse_params`, `bins/tc` qdisc 100% typed-first, filter 7/9).
  Mostly additive; minimal BC. Only deprecation note in the slate
  is `tc::builders::{class,qdisc,filter,action}` — actual removal
  ships under Plan 139 PR C.
- **0.15.0 work** is the [Plan 142](142-zero-legacy-typed-api-plan.md)
  phases, in order:

  | Phase | Subsumes | Outcome |
  |---|---|---|
  | 0 | Plan 140 (helper) + `ParseParams` trait formalization — **substantively shipped** under `[Unreleased]` | `nlink::lab::has_module` + `require_module!` helper; sealed `nlink::ParseParams` trait + 25 impls; bins/tc dispatch macros bind through the trait. GHA workflow deferred to land alongside the first Phase 1 integration test that needs it. |
  | 1 | Plan 138 (3 PRs) + Plan 133 PR C + Plan 137 integration tests un-parked | Filter side 9/9 typed-first; `bins/tc/src/commands/filter.rs` `#[allow(deprecated)]` reduced to the format/parse_protocol wrappers |
  | 2 | Plan 141 (3 PRs) | `Connection<Xfrm>` SA/SP CRUD; `xfrm-ipsec-tunnel` recipe; Plan 135 PR B closes at 7/7 |
  | 3 | Plan 139 PRs A + B | Typed standalone-action CRUD on `Connection<Route>` + `parse_params` on every action kind |
  | 4 | Plan 139 PR C — **legacy deletion milestone** | `tc::builders::*` + `tc::options::*` DELETED. Zero `#[allow(deprecated)]` in `bins/tc`. 0.15.0 release-cut commit. |

  **Out of scope for 0.15.0** per Plan 142 §1: Plan 137 PRs C/D/E
  (`ct_expect`, nfqueue, nflog) — demand-gated; per-bin
  typed-units rollout to `bins/{ip,ss,nft,wifi,devlink,bridge,wg,
  ethtool,diag,config}` (audit-driven, opens per-bin plans
  opportunistically); `mqprio`/`taprio` `queues <count@offset>`
  pair grammar (~50 LOC, lands when someone hits the deferred
  error).
- **1.0.0**: deferred indefinitely. Cut when downstream consumption
  validates the API, not on a calendar. The `non_exhaustive`
  lockdown and typed units already give the most important 1.0
  guarantees; rest is "let the API marinate, then bless it".

## Backlog (lower-priority, track here for later)

| Item | Priority | Notes |
|---|---|---|
| Typed-units rollout: `mqprio`/`taprio` `queues <count@offset>` pair grammar | Low | Both parsers reject the `queues` token with a "not parsed yet" hint pointing at `MqprioConfig::queues()` / `TaprioConfig::queues()` on the typed builders. Defer the parser until anyone hits the rejection — pair grammar is its own small parsing exercise (~50 LOC). Rest of the typed-units rollout is closed under Plans 138 + 139. |
| Workspace-wide rollout to **other bins** | Medium | The `bins/tc` rollout is shipping under Plans 138 + 139. The other bins (`bins/{ip,ss,nft,wifi,devlink,bridge,wg,ethtool,diag,config}`) should migrate off any remaining string/raw-u32 patterns. Audit per-bin during implementation; many already use the typed APIs since they were written after Plan 129/130 landed. Open per-bin plans only for the ones that turn up real work. |
| MACsec enhancements (stats, offload) | Medium | `MacsecLink` rtnetlink builder landed; `examples/genl/macsec.rs` now uses it directly. Follow-ons: MACsec stats parser, hardware-offload knobs (`IFLA_MACSEC_OFFLOAD`), cipher-suite + ICV-length flags on `MacsecLink`. |
| GENL Rate audit | Low | Plan 129's `Rate` may apply to WireGuard keepalive intervals, ethtool link rates, nl80211 bitrates. Each GENL family deserves a quick audit. |
| `netlink-packet-route` interop | Low | Optional `From`/`Into` impls between our `TcHandle` and theirs, gated behind an `nlink-interop` feature. |
| `NetworkConfig::impair()` | Low | Bridge Plan 131 reconcile with declarative `NetworkConfig`. Parked as 1.x follow-on. |
| SRv6 advanced features | Low | HMAC, policy, uSID, counters. |
| VRF in `NetworkConfig` | Low | Add `DeclaredLinkType::Vrf` variant. |
| `ss` binary remaining features | Low | Kill mode, expression filters, DCCP/VSOCK. |
| Additional edge-case tests | Low | Error conditions, race conditions. |

## Review checklist for PRs derived from the active plans

- [ ] Cross-checks against the relevant detailed plan
- [ ] CHANGELOG entry written under `## [Unreleased]`
- [ ] Tests updated and passing (`cargo test -p nlink --lib`)
- [ ] `cargo clippy --workspace --all-targets --all-features -- --deny warnings` clean
- [ ] `cargo machete` shows no NEW unused deps
- [ ] Examples and `CLAUDE.md` updated where relevant
- [ ] Integration tests added for namespace-gated flows (skip-if-not-root)

End of roadmap.
