---
to: nlink maintainers
from: nlink maintainers
subject: nlink roadmap — active plans only
target version: 0.14.0 and beyond
last updated: 2026-04-22 (Plan 137 PR A slice 1)
---

# nlink Roadmap

Forward-looking index of active plans. Shipped work is in
[`CHANGELOG.md`](CHANGELOG.md); detailed plans for shipped features
have been removed (their substance is in the commits + changelog).

## Active plans

| # | Plan | Status | Headline |
|---|---|---|---|
| 133 | [TC coverage gaps](133-tc-coverage-plan.md) | **3 of 4 PRs landed** (A/B/D under `[Unreleased]`); **PR C deferred** | Typed `CakeConfig`, `FqPieConfig`, `BpfAction`, `SimpleAction`. `BasicFilter` ematch (cmp/u32/meta) pending — ematch wire format needs validation against golden `tc(8)` hex before shipping. |
| 135 | [Recipes + public `nlink::lab`](135-recipes-and-lab-helpers-plan.md) | **PR A complete**; PR B partial (5 of 7) | `nlink::lab` shipped (PR A). Recipes shipped: multi-namespace-events, bridge-vlan, bidirectional-rate-limit, wireguard-mesh, nftables-stateful-fw + index + README/CLAUDE pointers. Deferred: xfrm-ipsec-tunnel (XFRM connection is dump-only — needs a Plan-137-shaped library extension first); cgroup-classification still blocked on Plan 133 PR C. Recipe smoke tests (`tests/integration/recipes.rs`) deferred. |
| 136 | [Example cleanup](136-example-cleanup-plan.md) | **All phases complete**; conntrack deferral resolved by Plan 137 PR A slice 3 | Phase 1 (htb + wireguard), Phase 2 (macsec + mptcp), Phase 3 (ethtool_rings + devlink + nl80211), and the previously-deferred `netfilter/conntrack.rs` (promoted under Plan 137 PR A slice 3, once the library gained add/update/del/flush). `MacsecLink` rtnetlink builder also landed as a follow-up; macsec example uses it directly. Plan can be archived. |
| 137 | [Netfilter expansion](137-netfilter-expansion-plan.md) | **PR A nearly done** (slices 1+2+3 landed under `[Unreleased]`); B/C/D/E pending | Slice 1: `ConntrackBuilder` + add/update/del/flush + 9 wire-format unit tests. Slice 2: `docs/recipes/conntrack-programmatic.md`. Slice 3: `examples/netfilter/conntrack.rs` promoted to a `--apply` lifecycle demo + `Netfilter: Default` so namespace-scoped construction works. Remaining for PR A: root-gated integration tests under the `lab` feature. PRs B (events), C (`ct_expect`), D (nfqueue), E (nflog) still pending; recommended order A→B→C; D/E gated on demand. |

## Release plan

- **0.13.0** (shipped 2026-04-19): typed `Rate` / `Bytes` / `Percent`
  newtypes, typed `TcHandle` / `FilterPriority`, API cleanup
  (builder uniformity + 95-enum `non_exhaustive` lockdown), and
  `tracing` instrumentation. See CHANGELOG `## [0.13.0]` for the
  migration tables and detailed bullets.
- **0.14.0** (in progress): reconcile pattern (shipped under
  `[Unreleased]`) + Plan 133 (except PR C) + Plan 135 + Plan 136.
  Mostly additive; minimal BC.
- **0.15.0 candidate work**: Plan 133 PR C (pending golden-hex
  validation), Plan 135 PR B remaining recipes (xfrm-ipsec-tunnel
  needs Plan 137 first, cgroup-classification needs Plan 133 PR C),
  remaining Plan 137 PR A slices (integration tests + example
  promotion + recipe), then Plan 137 PRs B/C.
- **1.0.0**: deferred indefinitely. Cut when downstream consumption
  validates the API, not on a calendar. The `non_exhaustive`
  lockdown and typed units already give the most important 1.0
  guarantees; rest is "let the API marinate, then bless it".

## Backlog (lower-priority, track here for later)

| Item | Priority | Notes |
|---|---|---|
| CI integration tests | Medium | GitHub Actions with privileged containers so the root-gated integration tests in `crates/nlink/tests/` actually run in CI. |
| Workspace-wide rollout of typed units | Medium | Plans 129/130 landed in nlink; the bins (`bins/{tc,ip,ss,nft,wifi,devlink,bridge,wg,ethtool,diag,config}`) should migrate off any remaining string/raw-u32 patterns. Audit per-bin during implementation. |
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
