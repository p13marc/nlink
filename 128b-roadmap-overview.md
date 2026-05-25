---
to: nlink maintainers
from: nlink maintainers
subject: nlink roadmap — active plans only
target version: 0.16.0 late-cycle, ready to cut
last updated: 2026-05-24 (0.16.0 cycle near-complete on the `0.16`
branch — 12/13 sub-plans 🟢. Migration guide written. Remaining
🟡 (Plan 151 stream wrapper) explicitly on hold for design soak;
⚪ Plan 152 (integration showcases) deprioritized by maintainer.)
---

# nlink Roadmap

Forward-looking index of active plans. Shipped work lives in
[`CHANGELOG.md`](CHANGELOG.md); detailed plan documents for shipped
features have been removed (their substance is in the commits +
changelog). For per-release upgrade notes see
[`docs/migration_guide/`](docs/migration_guide/README.md). The
detailed-plan archive for the in-flight 0.16.0 cycle lives in
[`plans/`](plans/) with [`plans/INDEX.md`](plans/INDEX.md) as the
live status tracker.

## Active plans

**0.16.0 cycle — late stage** on the long-lived `0.16` branch.
Per [`plans/INDEX.md`](plans/INDEX.md):

- **12/13 sub-plans 🟢** (147 bug fixes, 148 ergonomics, 149
  streaming dumps, 150 nftables flowtable, 153 kernel feature
  bundle, 154 nlink-macros proc-macro crate, 155 neli-parity,
  156 DPLL, 157 declarative NftablesConfig, 158 syscall
  batching, 159 ConnectionPool, 160 example-registry audit).
- **🟡 partials with documented deferrals**: Plan 151
  (ResyncedEvent + ResyncMarker types shipped; pre-baked
  Stream wrapper on hold for design soak — hand-rolled loop
  pattern documented in the recipe is the 0.16 shape).
- **⚪ deprioritized**: Plan 152 (aya/Prometheus/OTel
  showcases — both macro dogfoods now in tree as references;
  showcases can ship later).

Headlines that land in 0.16.0:

- **`nlink-macros` proc-macro crate** — define a custom Generic
  Netlink family in ~30 lines (Plan 154; validated by two
  in-tree dogfoods, DPLL and net_shaper).
- **Streaming dump API** — `Connection::stream_*` over rtnetlink
  + TC + XFRM SA/SP + conntrack + nftables rules (Plan 149).
- **DPLL family** — kernel 6.7+ clock-synchronization
  (Plan 156).
- **`net_shaper` family** — kernel 6.13+ TX hardware shaping
  (Plan 153.3).
- **Declarative `NftablesConfig`** — diff + atomic apply +
  per-rule USERDATA-keyed reconcile (Plan 157 + Plan 157b v2).
- **`ConnectionPool<P>`** — bounded fanout (Plan 159).
- **`recvmmsg`/`sendmmsg` syscall batching** behind opt-in
  `syscall_batch` feature (Plan 158).
- **Shared GENL multicast-group resolution** + ext-ack error
  TLV parsing + strict-checking sockopts (Plans 154 Phase 5 /
  155).
- **Per-release upgrade guide** — see
  [`docs/migration_guide/0.15.1-to-0.16.0.md`](docs/migration_guide/0.15.1-to-0.16.0.md).

**Cut blockers** (per [`plans/INDEX.md`](plans/INDEX.md)
acceptance gates):

- `cargo publish -p nlink-macros` then `cargo publish -p nlink`
  (publish-order matters — nlink-macros first; see
  [`crates/nlink/CLAUDE.md`](crates/nlink/CLAUDE.md) Publishing
  section).
- Final `cargo public-api diff` review against the published
  0.15.1 to confirm only the expected additions.
- Workspace already bumped to `0.16.0` mid-cycle.

**0.17 backlog** (forward-looking; no plans committed yet):

- Plan 151 pre-baked ENOBUFS-resync Stream wrapper.
- Plan 152 integration showcases (aya / Prometheus exporter /
  OTel) if user demand materializes.
- Refactor `Rule` from `Vec<Expr>` → typed `Vec<Match>` +
  lowering pass; would enable byte-canonical rule-equivalence
  diffing (currently the per-rule USERDATA-keyed identity from
  Plan 157b v2 covers the common case, but anonymous rules
  still always re-add).
- `Vec<NetlinkAttrs>` (multi-valued nested groups) + flag-attr
  typed fields in `nlink-macros` — would unlock `net_shaper`'s
  `group` command + cleaner caps reply parsing.

Demand-gated tail items remaining from 0.15.0 — typed
`ct_expect` / nfqueue / nflog surfaces, `mqprio`/`taprio`
queues-pair grammar — still parked behind "open a plan when
a downstream user asks."

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

- **0.16.0** (late-cycle on the `0.16` branch as of 2026-05-24,
  ready to cut once the maintainer runs final `cargo publish`):
  see "Active plans" above + [`plans/INDEX.md`](plans/INDEX.md)
  + [`docs/migration_guide/0.15.1-to-0.16.0.md`](docs/migration_guide/0.15.1-to-0.16.0.md)
  for the full per-feature picture. The cycle was substantial —
  estimated ~5-6 focused weeks for ~22 distinct deliverables
  across 14 sub-plans (plans 147-160).

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
