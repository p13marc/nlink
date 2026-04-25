---
to: nlink maintainers
from: nlink maintainers
subject: nlink roadmap — active plans only
target version: 0.14.0 and beyond
last updated: 2026-04-25 (typed-units rollout shipped — 25 parsers across 15 slices, qdisc 100%, filter 7/9; Plans 138/139/140/141 added for the truly-blocked remainders)
---

# nlink Roadmap

Forward-looking index of active plans. Shipped work is in
[`CHANGELOG.md`](CHANGELOG.md); detailed plans for shipped features
have been removed (their substance is in the commits + changelog).

## Active plans

| # | Plan | Status | Headline |
|---|---|---|---|
| 133 | [TC coverage gaps](133-tc-coverage-plan.md) | **3 of 4 PRs landed** (A/B/D under `[Unreleased]`); **PR C deferred** | Typed `CakeConfig`, `FqPieConfig`, `BpfAction`, `SimpleAction`. `BasicFilter` ematch (cmp/u32/meta) pending — ematch wire format needs golden `tc(8)` hex before shipping. PR C unblocks the `cgroup-classification` recipe (Plan 135) and the `basic` filter dispatch (last filter kind needed alongside Plan 138). |
| 135 | [Recipes + public `nlink::lab`](135-recipes-and-lab-helpers-plan.md) | **PR A complete**; PR B partial (6 of 7) | `nlink::lab` shipped (PR A). Recipes shipped: multi-namespace-events, bridge-vlan, bidirectional-rate-limit, wireguard-mesh, nftables-stateful-fw, conntrack-programmatic (mutation + events) + index + README/CLAUDE pointers. Deferred: `xfrm-ipsec-tunnel` (now tracked under Plan 141); `cgroup-classification` (still blocked on Plan 133 PR C). Recipe smoke tests (`tests/integration/recipes.rs`) parked behind Plan 140. |
| 137 | [Netfilter expansion](137-netfilter-expansion-plan.md) | **PRs A+B both kernel-validated end-to-end** (under `[Unreleased]`); integration tests parked behind Plan 140; C/D/E pending | PR A slices 1+2+3 + the `122f60b` timeout fix; PR B types + EventSource impl + parse units + `--apply` validation. Both `--apply` runners pass on Linux 6.19. `conntrack-programmatic` recipe covers both APIs with all four caveats. PRs C (`ct_expect`), D (nfqueue), E (nflog) unstarted; D/E gated on demand. |
| 138 | [bins/tc u32 filter selector grammar](138-u32-filter-selector-grammar-plan.md) | **draft** — last typed-units rollout remainder on the filter side | 3-PR arc: Phase 1 raw `match u32/u16/u8 V M at OFF` triples + structural tokens; Phase 2 named-match shortcuts (`match ip src`, `match tcp dport`, etc.) with golden-hex fixtures; Phase 3 hash-table grammar (`divisor`/`ht`/`link`/`order`). Lands `u32` typed dispatch in `bins/tc/src/commands/filter.rs`; alongside Plan 133 PR C closes the filter side of the rollout. |
| 139 | [Typed standalone-action CRUD](139-typed-standalone-action-crud-plan.md) | **draft** — last typed-units rollout remainder for `bins/tc` action subcommand | 3-PR arc: PR A `Connection<Route>::{add,del,get,dump}_action` + wire-format tests; PR B `parse_params` on every typed action kind (~14 kinds); PR C bin migration + **delete `tc::builders::{class,qdisc,filter,action}` entirely**. Closes the workspace-wide typed-units rollout. |
| 140 | [CI integration tests harness](140-ci-integration-tests-plan.md) | **draft** — gating dependency for any new root-gated test | Privileged GitHub Actions runner runs the `lab`-feature integration tests on every push. Adds `nlink::lab::require_module(name)` skip-helper alongside the existing `require_root!`. **Unblocks**: Plan 137 integration tests, Plan 135 recipe smoke tests, Plan 138 PR B golden-hex regression, every future root-gated test. |
| 141 | [XFRM write-path API extension](141-xfrm-write-path-plan.md) | **draft** — unblocks Plan 135 PR B's last deferred recipe | 3-PR arc modeled on Plan 137 PR A: PR A SA CRUD; PR B SP CRUD; PR C `xfrm-ipsec-tunnel` recipe + `examples/xfrm/ipsec_monitor.rs --apply` promotion. Closes Plan 135 PR B (7/7 recipes). |

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
- **0.15.0 candidate work**, ranked by user-visible value vs.
  effort:
  1. **Plan 140 — CI integration tests harness.** Gating
     dependency for everything else's "integration tests" item;
     small/tractable PR; once it lands, every later plan's test
     deferral disappears. Recommended first.
  2. **Plan 138 PR A — u32 filter Phase 1.** Smallest meaningful
     bin-side win after Plan 140; raw `match u32/u16/u8` triples +
     structural tokens; opens the typed dispatch path for the most
     common u32 filter shape. Phases B/C land incrementally.
  3. **Plan 137 integration tests.** Un-parked by Plan 140.
     Templates already exist in the `--apply` runners (`bdf0f84`,
     `b2243d0`); lifting into `#[tokio::test]` is mostly mechanical.
  4. **Plan 133 PR C — `BasicFilter` ematch.** Needs golden
     `tc(8)` hex captures (capture once under sudo, check in as
     test fixtures). Unblocks the `cgroup-classification` recipe
     and the bin's `basic` filter dispatch.
  5. **Plan 141 — XFRM write-path.** Unblocks Plan 135 PR B's
     `xfrm-ipsec-tunnel` recipe (closes that plan at 7/7).
  6. **Plan 139 — Typed standalone-action CRUD.** Largest of the
     remaining plans; lands the typed action API + bin migration
     + **deletes `tc::builders::*` entirely**, ending the
     typed-units rollout.
  7. **Plan 137 PR C (`ct_expect`)** — demand-gated; only worth
     doing if concrete user ask for FTP/SIP helper testing surfaces.
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
