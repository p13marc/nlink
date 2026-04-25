---
to: nlink maintainers
from: nlink maintainers
subject: nlink roadmap — active plans only
target version: 0.14.0 and beyond
last updated: 2026-04-25 (doc-sync after Plan 137 PRs A+B + class subcommand migration; integration-tests parked pending CI story)
---

# nlink Roadmap

Forward-looking index of active plans. Shipped work is in
[`CHANGELOG.md`](CHANGELOG.md); detailed plans for shipped features
have been removed (their substance is in the commits + changelog).

## Active plans

| # | Plan | Status | Headline |
|---|---|---|---|
| 133 | [TC coverage gaps](133-tc-coverage-plan.md) | **3 of 4 PRs landed** (A/B/D under `[Unreleased]`); **PR C deferred** | Typed `CakeConfig`, `FqPieConfig`, `BpfAction`, `SimpleAction`. `BasicFilter` ematch (cmp/u32/meta) pending — ematch wire format needs validation against golden `tc(8)` hex before shipping. |
| 135 | [Recipes + public `nlink::lab`](135-recipes-and-lab-helpers-plan.md) | **PR A complete**; PR B partial (6 of 7) | `nlink::lab` shipped (PR A). Recipes shipped: multi-namespace-events, bridge-vlan, bidirectional-rate-limit, wireguard-mesh, nftables-stateful-fw, conntrack-programmatic (mutation + events) + index + README/CLAUDE pointers. Deferred: xfrm-ipsec-tunnel (XFRM connection is dump-only — needs a Plan-137-shaped library extension first); cgroup-classification still blocked on Plan 133 PR C. Recipe smoke tests (`tests/integration/recipes.rs`) deferred. |
| 137 | [Netfilter expansion](137-netfilter-expansion-plan.md) | **PRs A+B both kernel-validated end-to-end** (under `[Unreleased]`); integration tests parked, C/D/E pending | PR A slices 1+2+3 + the `122f60b` timeout fix; PR B types + EventSource impl + parse units + `--apply` validation. Both `--apply` runners pass on Linux 6.19 with full assertion of the wire round-trip. `conntrack-programmatic` recipe covers both mutation and events with all four caveats (subscribe_all skip, New-covers-Update, two-connections-for-mutation+sub, ENOBUFS). **Integration tests parked** until the CI-with-privileged-containers backlog row lands (root-required tests bit-rot when no one runs them); the two `--apply` runners cover the wire-format regression risk on demand. PRs C (`ct_expect`), D (nfqueue), E (nflog) unstarted; D/E gated on demand. |

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
  deprecation + `bins/tc` `class` subcommand migration. Mostly
  additive; minimal BC.
- **0.15.0 candidate work, ranked by what's actually actionable
  under `cargo test` as a regular user**:
  1. **`bins/tc` qdisc/filter migration via `parse_params` on typed
     configs** (see Backlog row). Add `parse_params(&[&str]) ->
     Result<Self>` per typed config, then bin dispatches on `kind`.
     Each kind is a self-contained commit; unit-testable as user.
     Recommended start: HTB (most-used qdisc).
  2. **Plan 133 PR C** (`BasicFilter` ematch). Needs golden `tc(8)`
     hex captures — those can be generated once interactively
     under sudo and checked in as test fixtures, after which unit
     tests run as user.
  3. **Plan 135 PR B remaining recipes** (transitively blocked):
     xfrm-ipsec-tunnel needs Plan-137-style XFRM write-path extension;
     cgroup-classification needs (2).
  4. **Plan 137 PR C (`ct_expect`)** — demand-gated; only worth doing
     if a concrete user ask for FTP/SIP helper testing surfaces.

  **Parked** (root cost > value as long as `cargo test` runs as user):
  - **Plan 137 integration tests** under `lab` feature — both
    `--apply` runners (`bdf0f84`, `b2243d0`) already prove the wire
    format on demand. Lifting them into `#[tokio::test]` requires
    the `cargo test --no-run` + `sudo ./target/debug/deps/...`
    two-step, which bit-rots if not run regularly. Only worth
    landing in tandem with the **CI integration tests** backlog row
    so something actually runs them.
- **1.0.0**: deferred indefinitely. Cut when downstream consumption
  validates the API, not on a calendar. The `non_exhaustive`
  lockdown and typed units already give the most important 1.0
  guarantees; rest is "let the API marinate, then bless it".

## Backlog (lower-priority, track here for later)

| Item | Priority | Notes |
|---|---|---|
| CI integration tests | Medium | GitHub Actions with privileged containers so the root-gated integration tests in `crates/nlink/tests/` actually run in CI. **Now a gating dependency** for adding any new root-gated tests (Plan 137 integration tests, recipe smoke tests, etc.) — without CI to run them, they bit-rot. Until this lands, prefer `--apply` example runners over `#[tokio::test]`-shaped integration tests for kernel-side wire-format coverage. |
| Workspace-wide rollout of typed units | Medium | Plans 129/130 landed in nlink; the bins (`bins/{tc,ip,ss,nft,wifi,devlink,bridge,wg,ethtool,diag,config}`) should migrate off any remaining string/raw-u32 patterns. Audit per-bin during implementation. **In progress**: `tc::builders::{class,qdisc,filter,action}` marked `#[deprecated]` (0.14.0); `bins/tc`'s `class` subcommand migrated to `Connection::{add,del,change,replace}_class` (typed `TcHandle`, `#[allow(deprecated)]` dropped); **fifteen slices landed**: twenty-five `parse_params` (18 qdisc + 7 filter; 161 unit tests). Bin dispatch wiring lives in `qdisc.rs` (**18 typed qdisc kinds — 100% of the typed-config tier**: htb, netem, cake, tbf, sfq, prio, fq_codel, red, pie, hfsc, drr, qfq, ingress, clsact, plug, mqprio, etf, taprio) and `filter.rs` (7 typed filter kinds — flower, matchall, fw, route, bpf, cgroup, flow). **The qdisc side is closed** — every kind with a typed `QdiscConfig` is dispatched through the typed parser path. The filter side has only **u32** (kernel's swiss-army-knife filter with complex selector grammar — own arc) and **basic** (blocked on Plan 133 PR C ematch) remaining. Slices 10/11/12/14/15 each added net-new CLI capability for kinds the legacy CLI silently swallowed. The `CakeConfig` work also caught and fixed a bits-vs-bytes/sec units bug in `NetemConfig::parse_params`'s `rate` token. **Truly remaining (each blocked or its own arc)**: u32 (selector grammar), basic (blocked on ematch); `action` subcommand blocked on typed standalone-action CRUD on `Connection`; `mqprio`/`taprio` `queues <count@offset>` pair grammar. Rejected alternative: adding `Connection::add_qdisc_with_params(kind, &[&str])` to mirror the class shape — that shape is an incomplete-migration fossil. `action` subcommand remains blocked on typed standalone-action CRUD on `Connection`. |
| MACsec enhancements (stats, offload) | Medium | `MacsecLink` rtnetlink builder landed; `examples/genl/macsec.rs` now uses it directly (no `ip(8)` shell-out). Follow-ons: MACsec stats parser, hardware-offload knobs (`IFLA_MACSEC_OFFLOAD`), cipher-suite + ICV-length flags on `MacsecLink`. |
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
