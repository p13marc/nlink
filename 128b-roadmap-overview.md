---
to: nlink maintainers
from: nlink maintainers
subject: nlink roadmap — active plans only
target version: 0.14.0 and beyond
last updated: 2026-04-21
---

# nlink Roadmap

Forward-looking index of active plans. Shipped work is in
[`CHANGELOG.md`](CHANGELOG.md); detailed plans for shipped features
have been removed (their substance is in the commits + changelog).

## Active plans

| # | Plan | Status | Headline |
|---|---|---|---|
| 133 | [TC coverage gaps](133-tc-coverage-plan.md) | **3 of 4 PRs landed** (A/B/D under `[Unreleased]`); **PR C deferred** | Typed `CakeConfig`, `FqPieConfig`, `BpfAction`, `SimpleAction`. `BasicFilter` ematch (cmp/u32/meta) pending — ematch wire format needs validation against golden `tc(8)` hex before shipping. |
| 135 | [Recipes + public `nlink::lab`](135-recipes-and-lab-helpers-plan.md) | **PR A partially landed** (LabNamespace + with_namespace + shim); PR B not started | `nlink::lab::LabNamespace` + `with_namespace` public behind `lab` feature. `LabBridge` / `LabVeth` builders and the `examples/lab/three_namespace.rs` walk-through deferred to a follow-up. PR B: 7 recipes (bridge VLAN, bidir rate limit, WireGuard mesh, IPsec, nftables stateful firewall, cgroup classification, multi-namespace events). The cgroup-classification recipe blocks on Plan 133 PR C. |
| 136 | [Example cleanup](136-example-cleanup-plan.md) | **Phases 1 + 2 + 3 complete**; conntrack deferred | Phase 1 (htb + wireguard), Phase 2 (macsec + mptcp), and Phase 3 (ethtool_rings + devlink + nl80211) all shipped. `netfilter/conntrack.rs` deferred — nlink's Netfilter connection only dumps, so promoting the example would require a library extension that's out of scope for a test-cleanup plan. `MacsecLink` rtnetlink builder remains a medium-priority follow-up. |

## Release plan

- **0.13.0** (shipped 2026-04-19): typed `Rate` / `Bytes` / `Percent`
  newtypes, typed `TcHandle` / `FilterPriority`, API cleanup
  (builder uniformity + 95-enum `non_exhaustive` lockdown), and
  `tracing` instrumentation. See CHANGELOG `## [0.13.0]` for the
  migration tables and detailed bullets.
- **0.14.0** (in progress): reconcile pattern (shipped under
  `[Unreleased]`) + Plan 133 (except PR C) + Plan 135 + Plan 136.
  Mostly additive; minimal BC.
- **1.0.0**: deferred indefinitely. Cut when downstream consumption
  validates the API, not on a calendar. The `non_exhaustive`
  lockdown and typed units already give the most important 1.0
  guarantees; rest is "let the API marinate, then bless it".

## Backlog (lower-priority, track here for later)

| Item | Priority | Notes |
|---|---|---|
| CI integration tests | Medium | GitHub Actions with privileged containers so the root-gated integration tests in `crates/nlink/tests/` actually run in CI. |
| Workspace-wide rollout of typed units | Medium | Plans 129/130 landed in nlink; the bins (`bins/{tc,ip,ss,nft,wifi,devlink,bridge,wg,ethtool,diag,config}`) should migrate off any remaining string/raw-u32 patterns. Audit per-bin during implementation. |
| `MacsecLink` rtnetlink builder | Medium | `examples/genl/macsec.rs` currently shells out to `ip link add … type macsec` because there's no typed helper. Adding `MacsecLink::new("macsec0", parent).encrypt(true).sci(..)` lands the missing piece for end-to-end nlink-only setup. Companion: stats, hardware-offload knobs. |
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
