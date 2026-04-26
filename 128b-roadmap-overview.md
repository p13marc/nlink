---
to: nlink maintainers
from: nlink maintainers
subject: nlink roadmap — active plans only
target version: 0.15.0 cut 2026-04-26 (publish-ready); 0.16.0 and beyond
last updated: 2026-04-26 (post-cut tail cleared, all shipped detail
plans removed from tree — substance lives in CHANGELOG `## [0.15.0]`
and `docs/migration_guide/0.14.0-to-0.15.0.md`)
---

# nlink Roadmap

Forward-looking index of active plans. Shipped work lives in
[`CHANGELOG.md`](CHANGELOG.md); detailed plan documents for shipped
features have been removed (their substance is in the commits +
changelog). For per-release upgrade notes see
[`docs/migration_guide/`](docs/migration_guide/README.md).

## Active plans

**Empty as of 2026-04-26 (post-0.15.0 cut, post-tail cleanup).**
Every plan that was active at cut-pending time shipped before
publish — both deferred recipes, the GHA workflow YAML, the
conntrack integration tests, and the `ipsec_monitor.rs --apply`
promotion all landed under the same `## [0.15.0]` heading.

**0.15.0 cut on 2026-04-26.** Workspace at `0.15.0`, CHANGELOG
header is `## [0.15.0] - 2026-04-26`, migration guide in place
at [`docs/migration_guide/0.14.0-to-0.15.0.md`](docs/migration_guide/0.14.0-to-0.15.0.md).
Maintainer publishes via `cargo publish -p nlink` and tags
`v0.15.0`.

**Next-up after publish**: the other-bins typed-units rollout
(see Backlog row "Workspace-wide typed-units rollout to other
bins"). Other items not in the active set are explicitly
demand-gated (typed `ct_expect` / nfqueue / nflog surfaces) —
open per-PR plans only when a downstream user asks.

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

  - **Typed surface end-to-end** — 45 typed configs in
    `nlink::ParseParams` (18 qdisc + 4 class + 9 filter + 14 action).
    Sealed `ParseParams` trait formalizes the contract.
  - **Legacy deletion** — `tc::builders::*` and `tc::options/*`
    modules removed (-3940 LOC). Zero `#[deprecated]` and zero
    `#[allow(deprecated)]` in the source tree.
  - **Typed ctnetlink mutation + multicast event subscription**
    on `Connection<Netfilter>`. `MacsecLink` rtnetlink builder.
    Reconcile pattern. `nlink::lab` shipped publicly. 7 of 7
    cookbook recipes (`xfrm-ipsec-tunnel` + `cgroup-classification`
    landed in the post-cut tail).
  - **Typed XFRM SA + SP CRUD** on `Connection<Xfrm>` (was
    dump-only).
  - **Typed standalone-action CRUD** on `Connection<Route>`.
  - **`nlink::lab::has_module` + `nlink::require_module!` macro**;
    privileged GHA workflow runs the integration tests with
    these gates honoured.

  Lib tests grew from 593 (post-0.13.0) to 749 (+156 net). Full
  upgrade walkthrough:
  [`docs/migration_guide/0.14.0-to-0.15.0.md`](docs/migration_guide/0.14.0-to-0.15.0.md).
  Per-PR breakdown with commit references in CHANGELOG `##
  [0.15.0]`.

  **Out of scope for 0.15.0** (still): typed `ct_expect` / nfqueue
  / nflog surfaces — demand-gated; per-bin typed-units rollout to
  `bins/{ip,ss,nft,wifi,devlink,bridge,wg,ethtool,diag,config}`
  (audit-driven, opens per-bin plans opportunistically); `mqprio`
  / `taprio` `queues <count@offset>` pair grammar (~50 LOC, lands
  when someone hits the deferred error).

- **0.16.0** (no plan committed yet): the natural next chunk is
  the **other-bins typed-units rollout** — see Backlog. Audit
  each binary, open per-bin plans for any that turn up real
  work. The demand-gated tail items (typed `ct_expect` / nfqueue
  / nflog surfaces) also ship in this window if they clear their
  gates.

- **1.0.0**: deferred indefinitely. Cut when downstream
  consumption validates the API, not on a calendar. The
  `non_exhaustive` lockdown and typed units already give the
  most important 1.0 guarantees; the rest is "let the API
  marinate, then bless it".

## Backlog (lower-priority, track here for later)

| Item | Priority | Notes |
|---|---|---|
| **Workspace-wide typed-units rollout to other bins** | **Medium — next-up after 0.15.0 cut** | The `bins/tc` rollout closed in 0.15.0. Other bins (`bins/{ip,ss,nft,wifi,devlink,bridge,wg,ethtool,diag,config}`) likely have less drift since most were written after the typed-units convention landed — audit per-bin and open small per-bin plans for any that turn up real string/raw-u32 patterns. |
| Typed-units rollout: `mqprio`/`taprio` `queues <count@offset>` pair grammar | Low | Both parsers reject the `queues` token with a "not parsed yet" hint pointing at `MqprioConfig::queues()` / `TaprioConfig::queues()` on the typed builders. Defer the parser until anyone hits the rejection — pair grammar is its own small parsing exercise (~50 LOC). |
| Typed `ct_expect` / nfqueue / nflog surfaces | Low — demand-gated | Conntrack mutation + multicast events shipped in 0.15.0. The remaining netfilter sub-protocols (expectations, packet queueing to userspace, packet logging) are deferred — open a fresh plan when a downstream user asks. |
| MACsec enhancements (stats, offload) | Medium | `MacsecLink` rtnetlink builder shipped. Follow-ons: MACsec stats parser, hardware-offload knobs (`IFLA_MACSEC_OFFLOAD`), cipher-suite + ICV-length flags on `MacsecLink`. |
| GENL Rate audit | Low | The typed `Rate` may apply to WireGuard keepalive intervals, ethtool link rates, nl80211 bitrates. Each GENL family deserves a quick audit. |
| `netlink-packet-route` interop | Low | Optional `From`/`Into` impls between our `TcHandle` and theirs, gated behind an `nlink-interop` feature. |
| `NetworkConfig::impair()` | Low | Reconcile the impair helpers with the declarative `NetworkConfig`. Parked as 1.x follow-on. |
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
