---
to: nlink maintainers
from: nlink maintainers
subject: nlink roadmap — active plans only
target version: 0.15.0 cut 2026-04-26 (publish-ready, all sudo-gated tail items shipped pre-publish); 0.16.0 and beyond
last updated: 2026-04-26 (post-cut tail cleared: xfrm-ipsec-tunnel + cgroup-classification recipes shipped, ipsec_monitor.rs --apply promoted, Plan 137 conntrack integration tests un-parked with 6 root-gated tests, Plan 140 GHA workflow YAML wired. Active plans table empty; 0.16.0 work opens with the other-bins typed-units rollout.)
---

# nlink Roadmap

Forward-looking index of active plans. Shipped work lives in
[`CHANGELOG.md`](CHANGELOG.md); detailed plans for shipped
features have been removed (their substance is in the commits +
changelog). For per-release upgrade notes see
[`docs/migration_guide/`](docs/migration_guide/README.md).

## Active plans

**Empty as of 2026-04-26 (post-0.15.0 cut, post-tail cleanup).**
Every row that was on this table at cut-pending time shipped
before publish — both deferred recipes, the GHA workflow YAML,
the conntrack integration tests, and the `ipsec_monitor.rs
--apply` promotion all landed under the same `## [0.15.0]`
heading. See the "Shipped & ready to archive" table for the
final per-plan status.

**0.15.0 cut on 2026-04-26.** Workspace at `0.15.0`, CHANGELOG
header is `## [0.15.0] - 2026-04-26`, migration guide in place
at [`docs/migration_guide/0.14.0-to-0.15.0.md`](docs/migration_guide/0.14.0-to-0.15.0.md).
Maintainer publishes via `cargo publish -p nlink` and tags
`v0.15.0`.

**Next-up after publish**: the other-bins typed-units rollout
(see Backlog row promoted to "Medium — next-up after 0.15.0
cut"). Other PRs/items not in this table are explicitly
demand-gated (Plan 137 PRs C/D/E for `ct_expect` / nfqueue /
nflog) — open per-PR plans only when a downstream user asks.

## Shipped & ready to archive

The typed-API completion arc closed under `[Unreleased]`. Plan
detail documents stay in tree as historical reference; their
substance is already in CHANGELOG entries and the
[migration guide](docs/migration_guide/0.14.0-to-0.15.0.md).

| Plan | Shipped | Headline |
|---|---|---|
| 133 (TC coverage gaps) | all 4 PRs | Typed `CakeConfig`, `FqPieConfig`, `BpfAction`, `SimpleAction`, `BasicFilter` ematch tree (cmp + u32; meta deferred). PR C (`e2ee5d8`) closed the filter side at 9/9 typed-first. |
| 135 (recipes + lab helpers) | PR A + PR B at 7/7 | `nlink::lab` module + 7 cookbook recipes. The two deferred recipes (`xfrm-ipsec-tunnel`, `cgroup-classification`) shipped during the post-cut tail cleanup; PR B closes at 7/7. |
| 136 (Example cleanup) | all phases | Plus the conntrack deferral resolved by Plan 137 PR A slice 3 (`1e9307e`). `MacsecLink` rtnetlink builder landed as a follow-up; `examples/genl/macsec.rs` uses it directly. |
| 137 (netfilter expansion) | PRs A+B + integration tests | PRs A+B kernel-validated under `[Unreleased]` (typed ctnetlink mutation + multicast event subscription). Integration tests un-parked post-cut: 6 root-gated `#[tokio::test]` functions in `tests/integration/conntrack.rs`. PRs C/D/E (`ct_expect`, nfqueue, nflog) demand-gated. |
| 138 (u32 filter selector grammar) | all 3 PRs (`ae0e4ae`, `3b5cb21`, `d95a0ea`) | Raw `match u32|u16|u8 VAL MASK at OFFSET` triples + named-match shortcuts + hash-table grammar. 41 unit tests. `order` deferred with explicit rejection. |
| 139 (typed standalone-action CRUD) | all 3 PRs | PR A: library typed CRUD on `Connection<Route>` (`d69e10a`). PR B: `parse_params` on all 14 action kinds, 74 tests (`f7e4502`/`d124920`/`2764806`). PR C: bin migration + **legacy deletion** (`56371db`, -3940 LOC) — the 0.15.0 release-cut commit. |
| 140 (CI integration tests harness) | helper + GHA workflow | Helper macros (`require_module!`, `has_module`) shipped in Phase 0 (`553f9dd`). GHA workflow YAML (`.github/workflows/integration-tests.yml`) wired during the post-cut tail cleanup, alongside the conntrack integration tests it validates against. |
| 141 (XFRM write path) | all 3 PRs | PRs A+B (`74a4e48`/`844a166`/`a120ee7`): typed SA + SP CRUD on `Connection<Xfrm>`, 20 wire-format round-trip tests. PR C: `xfrm-ipsec-tunnel` recipe + `examples/xfrm/ipsec_monitor.rs --apply` lifecycle runner shipped during the post-cut tail cleanup. |
| 142 (0.15.0 master) | all 5 phases substantively | Phase 0: helper + sealed `ParseParams` trait. Phase 1: filter side 9/9. Phase 2: XFRM SA + SP CRUD. Phase 3: typed action CRUD. Phase 4: legacy deletion. Every Phase 4 §6 acceptance gate met. |

## Release plan

- **0.13.0** (shipped 2026-04-19): typed `Rate` / `Bytes` /
  `Percent` newtypes, typed `TcHandle` / `FilterPriority`, API
  cleanup (builder uniformity + 95-enum `non_exhaustive`
  lockdown), `tracing` instrumentation across the public
  surface. See CHANGELOG `## [0.13.0]` and the
  [migration guide](docs/migration_guide/0.13.0-to-0.14.0.md).

- **0.15.0** (cut 2026-04-26): the typed-API completion arc —
  what would have been 0.14.0 + 0.15.0 in the original release
  plan merged into one ship. Highlights:

  - **Plan 142 Phases 0–4** all met. Typed surface end-to-end
    (41 typed configs in `nlink::ParseParams` — 18 qdisc + 9
    filter + 14 action). Legacy `tc::builders::*` and
    `tc::options/*` modules **deleted** (-3940 LOC). Zero
    `#[allow(deprecated)]` in `bins/tc`.
  - **Plan 137 PRs A+B** kernel-validated typed ctnetlink
    mutation + multicast event subscription. `MacsecLink`
    rtnetlink builder. Reconcile pattern. `nlink::lab` shipped
    publicly. 6 of 7 cookbook recipes.
  - **Plan 141 PRs A+B**: typed XFRM SA + SP CRUD on
    `Connection<Xfrm>` (was dump-only).
  - **Plan 139 PR A**: typed standalone-action CRUD on
    `Connection<Route>`.
  - Sealed `nlink::ParseParams` trait + `nlink::lab::has_module`
    + `nlink::require_module!` macro.

  Lib tests grew from 593 (post-0.13.0) to 749 (+156 net). Full
  upgrade walkthrough:
  [`docs/migration_guide/0.14.0-to-0.15.0.md`](docs/migration_guide/0.14.0-to-0.15.0.md).

  **Out of scope for 0.15.0** per Plan 142 §1 (still): Plan 137
  PRs C/D/E (`ct_expect`, nfqueue, nflog) — demand-gated;
  per-bin typed-units rollout to `bins/{ip,ss,nft,wifi,devlink,
  bridge,wg,ethtool,diag,config}` (audit-driven, opens per-bin
  plans opportunistically); `mqprio` / `taprio` `queues
  <count@offset>` pair grammar (~50 LOC, lands when someone
  hits the deferred error).

- **0.16.0** (no plan committed yet): the natural next chunk is
  the **other-bins typed-units rollout** — see Backlog. Audit
  each binary, open per-bin plans for any that turn up real
  work. Plan 137 PRs C/D/E and Plan 141 PR C tail items also
  ship in this window if they clear their gates.

- **1.0.0**: deferred indefinitely. Cut when downstream
  consumption validates the API, not on a calendar. The
  `non_exhaustive` lockdown and typed units already give the
  most important 1.0 guarantees; the rest is "let the API
  marinate, then bless it".

## Backlog (lower-priority, track here for later)

| Item | Priority | Notes |
|---|---|---|
| **Workspace-wide typed-units rollout to other bins** | **Medium — next-up after 0.15.0 cut** | The `bins/tc` rollout closed under Plan 142. Other bins (`bins/{ip,ss,nft,wifi,devlink,bridge,wg,ethtool,diag,config}`) likely have less drift since most were written after Plans 129/130 landed — audit per-bin and open small per-bin plans for any that turn up real string/raw-u32 patterns. |
| Typed-units rollout: `mqprio`/`taprio` `queues <count@offset>` pair grammar | Low | Both parsers reject the `queues` token with a "not parsed yet" hint pointing at `MqprioConfig::queues()` / `TaprioConfig::queues()` on the typed builders. Defer the parser until anyone hits the rejection — pair grammar is its own small parsing exercise (~50 LOC). |
| MACsec enhancements (stats, offload) | Medium | `MacsecLink` rtnetlink builder shipped. Follow-ons: MACsec stats parser, hardware-offload knobs (`IFLA_MACSEC_OFFLOAD`), cipher-suite + ICV-length flags on `MacsecLink`. |
| GENL Rate audit | Low | Plan 129's `Rate` may apply to WireGuard keepalive intervals, ethtool link rates, nl80211 bitrates. Each GENL family deserves a quick audit. |
| `netlink-packet-route` interop | Low | Optional `From`/`Into` impls between our `TcHandle` and theirs, gated behind an `nlink-interop` feature. |
| `NetworkConfig::impair()` | Low | Bridge Plan 131 reconcile with declarative `NetworkConfig`. Parked as 1.x follow-on. |
| SRv6 advanced features | Low | HMAC, policy, uSID, counters. |
| VRF in `NetworkConfig` | Low | Add `DeclaredLinkType::Vrf` variant. |
| `ss` binary remaining features | Low | Kill mode, expression filters, DCCP/VSOCK. |
| Pedit `parse_params` typed grammar | Low | `PeditAction::parse_params` ships as a stub in 0.15.0 (always rejects with "use the typed builder"). The full `tc(8)` pedit DSL — `munge ip src set 1.2.3.4` etc. — is non-trivial; flesh out only if a downstream user asks. |
| Additional edge-case tests | Low | Error conditions, race conditions. |

## Review checklist for PRs derived from the active plans

- [ ] Cross-checks against the relevant detailed plan
- [ ] CHANGELOG entry written under `## [Unreleased]`
- [ ] Tests updated and passing (`cargo test -p nlink --lib`)
- [ ] `cargo clippy --workspace --all-targets --all-features -- --deny warnings` clean
- [ ] `cargo machete` shows no NEW unused deps
- [ ] Examples and `CLAUDE.md` updated where relevant
- [ ] Integration tests added for namespace-gated flows (skip-if-not-root)
- [ ] On release-cut PRs: `docs/migration_guide/<from>-to-<to>.md` written and cross-linked from CHANGELOG

End of roadmap.
