---
subject: 0.16 cycle — plan index + progress tracker
status: live (update as PRs land)
target version: 0.16.0
maintainer: p13marc
created: 2026-05-23
---

# Plan index — 0.16 cycle

Single dashboard for the 0.16 release. Update the **Status** and
**PR** columns as each sub-plan lands. The master plan
([146](146-0.16-master-plan.md)) holds the overall narrative, scope
boundaries, and "genuinely out of scope" rationale; this file is the
day-to-day tracker.

## Quick status

- **Cycle**: 0.16.0 — branched from 0.15.1
- **Workspace version**: `0.16.0` (bumped mid-cycle; publishing
  remains manual via `cargo publish -p nlink-macros` then
  `cargo publish -p nlink`)
- **Estimated length**: 5 – 6 focused weeks
- **Plans**: 1 master + 13 sub-plans (147 – 159)
- **CI**: PR [#3](https://github.com/p13marc/nlink/pull/3) (draft) is
  the long-lived 0.16 → master release-branch CI driver — GitHub
  Actions only triggers on push/PR to master, so the draft PR is
  how 0.16 work gets validated. All Rust + integration-test jobs
  pass on the latest 0.16 head as of the version bump.
- **Cut blocker**: all thirteen sub-plans + standard release prep
  (CHANGELOG, migration guide, semver-checks, public-api gate)

## Status legend

| Symbol | Meaning |
|---|---|
| ⚪ | Planned — not started |
| 🟡 | In progress — PR open or work underway |
| 🟢 | Merged to master |
| 🔵 | Cut & published |
| 🟣 | Deferred (escaped 0.16; see master plan §4) |

## Sub-plan table

| Plan | Title | Effort | Order | Status | PR(s) | Notes |
|------|-------|--------|-------|--------|-------|-------|
| [147](147-0.16-bug-fixes-plan.md) | Bug fixes (socket.rs critical, bitset perf, config-diff, route metrics, cosmetic) + audit follow-ups (parser fuzz, eprintln→tracing, unwrap audit) | ~1 day | 1 | 🟢 | – | Phases 1-4 landed locally (commits ad6b44d, f8e0b09, plus Phase 3+4 bundle). §9 audit follow-ups (parser fuzz, unwrap deep-dive) deferred — bundled into other 0.16 work or pushed to release-time polish |
| [155](155-0.16-neli-parity-features-plan.md) | ext-ack TLV parsing + `enable_strict_checking()` + `set_ext_ack()` + namespace-safety lib docs | ~1 day | 2 | 🟢 | – | All 4 phases landed locally (commits 8d60ff3 ext-ack, 60a69e7 sockopts + this commit for docs). Diagnostic surface ready for everything that follows |
| [148](148-0.16-ergonomics-plan.md) | `wait_link_up` + `get_link_stats` + re-exports + per-method namespace docs + sealed GENL constructor + error recipe + netkit test + `NFT_TABLE_F_PERSIST` + per-NAPI config | ~1.5 days | 3 | 🟢 | – | Phases §4.1-§4.8 all landed across commits f122f7a, 6f7f801, de0bfc3, plus this commit. Per-NAPI (§4.9) deferred — needs Netdev family which doesn't exist yet (would be its own plan via nlink-macros) |
| [149](149-0.16-streaming-dump-api-plan.md) | `dump_stream<T>` generic + `stream_routes/links/neighbors/fdb` + TC streams + typed config streams (XFRM SA/SP, conntrack) | ~3 days | 4 | 🟡 | – | Foundation `dump_stream<T>` + four rtnetlink wrappers (links/routes/neighbors/addresses) landed. TC wrappers (`stream_qdiscs`/`stream_classes`/`stream_filters`) landed as a follow-up. **XFRM `stream_sas`/`stream_sps` landed** — `FromNetlink` impls on `SecurityAssociation`/`SecurityPolicy` via refactored payload-only parsers. Conntrack + nft-rules streaming still deferred — they need `dump_stream` to learn to pass a caller-parameterized body prefix (conntrack: nfgenmsg.family) |
| [153](153-0.16-kernel-feature-bundle-plan.md) | XFRM IPsec offload (`XFRMA_OFFLOAD_DEV`) + Devlink rate + port-function-state + TX H/W shaping (`net_shaper` GENL) | ~5 days | 5 | 🟢 | – | **All three sub-features landed.** §4.1 XFRM offload + §4.2 Devlink rate / port-function-state shipped earlier. §4.3 net_shaper landed via the macro stack — second in-tree dogfood after DPLL, ~200 lines of macro-derived Rust for 5 commands + 22 attrs + 2 enums + 2 nested groups. End-to-end validated on kernel 6.13+. `Connection<NetShaper>` exposes get/dump/set/del/get_caps/dump_caps; the `group` command (hierarchical reparenting) is deferred — needs `Vec<NetlinkAttrs>` support in the macro stack |
| [150](150-0.16-nftables-flowtable-plan.md) | `Flowtable` builder + `add/del/get_flowtable` + `Expr::FlowOffload` + counters + multicast events for table/chain/rule/flowtable | ~3 days | 6 | 🟡 | – | Core CRUD landed (Flowtable + add/del/list + Expr::FlowOffload). §9.2 multicast events landed (`NftablesEvent` + `subscribe`/`events()` on `Connection<Nftables>` with 8 typed variants for table/chain/rule/flowtable new+del). Remaining: counters introspection (§9.1) + integration tests + recipe — pure follow-ups |
| [151](151-0.16-enobufs-resync-plan.md) | `events_with_resync()` — sum-type `ResyncedEvent<T> { Event, Resynced, Marker }`, hand-rolled state machine, recipe | ~2 days | 7 | 🟡 | – | Types (ResyncedEvent + ResyncMarker) + recipe landed. Stream wrapper that drives the state machine deferred — needs more soak; hand-rolled loop pattern documented in the recipe is the 0.16 shape |
| [158](158-0.16-syscall-batching-plan.md) | `recvmmsg`/`sendmmsg` batching behind opt-in `syscall_batch` feature; 32-frame batches; per-socket reused buffers | ~2 days | 8 | 🟢 | – | recv_batch + send_batch + poll_recv_batch landed and wired into both `send_dump_inner` (eager dumps) and `DumpStream::poll_next` (streaming dumps) under `cfg(feature = "syscall_batch")`. Criterion benches still deferred (separate infra work) — actual speedup not measured in CI yet |
| [154](154-0.16-nlink-macros-plan.md) | New `nlink-macros` proc-macro crate: `#[derive(GenlMessage/GenlCommand/GenlAttribute/GenlEnum/NetlinkAttrs)]` + `#[genl_family]` | ~7.5 days | 9 | 🟢 | – | **All 7 phases + all 5 Phase 8 sub-items done (8.1 i32 + 8.2 Option<GenlEnum> + 8.3 Vec<GenlEnum> + 8.4 bitflags + 8.5 NetlinkAttrs/nested).** 5 derive/attr macros + `GenlFamily` send-time trait + `Connection::<F: GenlFamily>::send_typed<M, R>` / `dump_typed_stream<M, R>` generic dispatch + worked example + recipe + README with publish-order docs. 36 runtime tests in nlink::macros + 14 in nlink-macros. Workspace dep on nlink-macros now carries `version = "..."` for crates.io publishability. **Publish nlink-macros first** when the cycle cuts |
| [156](156-0.16-dpll-genl-family-plan.md) | DPLL netlink family (kernel 6.7+) — first in-tree user of `nlink-macros`. ~130 lines of macro-derived declaration for the full family | ~2 days | 10 | 🟢 | – | **All 6 phases done.** Family marker + 11 typed enums + device/pin messages with 2 nested groups + Connection methods + multicast monitor (`Connection<Dpll>::subscribe_monitor()` + `DpllEvent` stream via `EventSource` impl) + runnable example + recipe. Phase 5 closeout also shipped shared GENL group-resolution infrastructure: `__rt::resolve_genl_family_with_groups` + `GenlFamily::mcast_group(name)` + `Connection<F: GenlFamily>::subscribe_group(name)`; **Devlink/Nl80211/Ethtool refactored to use it (commit 287cb62, −254 lines of duplicated wire parsing)**. 26 unit tests in `genl::dpll::*` |
| [159](159-0.16-connection-pool-plan.md) | `ConnectionPool<P>` + `PooledConnection<'p, P>` + namespace-aware builder. Bounded mpsc-channel-backed | ~2 days | 11 | 🟢 | – | Landed locally with sync + async overloads, PoolExhausted/PoolClosed Error variants, for_namespace convenience, recipe. 3 builder unit tests. Integration tests deferred (need root + tokio multi-thread runtime — covered manually for now) |
| [157](157-0.16-nftables-declarative-config-plan.md) | Declarative `NftablesConfig` — `diff + apply + reconcile` mirroring `NetworkConfig`, atomic-via-`Transaction` commit, canonicalized rule equivalence | ~3 days | 12 | 🟡 | – | Core types + diff landed. **Full atomicity landed**: Transaction extended with `add_table_with_flags` / `del_chain` / `del_rule` / `add_flowtable` / `del_flowtable`; `NftablesDiff::apply` now bundles every diff op (including flagged tables) into a single `NFNL_MSG_BATCH_BEGIN ... END` round-trip. Kernel commits or rolls back the whole batch — no half-applied state observable. Canonicalization-based rule diff + sets/maps + reconcile retry mode + recipe deferred |
| [152](152-0.16-integration-showcases-plan.md) | `aya` co-demo (TCX + nlink + nlink-macros showcase) + Prometheus exporter POC (`bins/exporter/`) + OpenTelemetry example | ~3 days | 13 | ⚪ | – | Depends on Plan 154 (aya demo uses macros). **Unblocked after Plan 154 Phase 8 closeout.** Best sequenced after Plan 156 lands so the showcase can point at DPLL as the in-tree reference. Ships last |
| [160](160-example-registry-audit.md) | Audit: every example .rs must be registered in `Cargo.toml`; CI gate to enforce + per-file resolution catalog for 9 orphans | ~0.5 day (script + catalog); per-orphan triage separate | 14 | 🟢 | – | Triggered by a code-review pass during the 0.16 cycle. Script `scripts/audit-example-registration.sh` + allowlist in tree; **wired into CI as the `audit-example-registration` job**. Allowlist exempts the 9 known orphans (catalogued with R/F/P/O categories in the plan + allowlist comments); any NEW orphan fails CI loudly with a copy-paste fix block. Convention added to CLAUDE.md. **Remaining**: maintainer triages the 9 orphans at leisure (each triage removes the corresponding allowlist line); when the allowlist empties, delete the file itself |

Total focused-work estimate: **~35 – 37 days** (5 – 6 calendar weeks
at typical maintainer cadence).

## Sequencing rationale

The order column reflects the master plan §7 — the abbreviated
reasoning per slot:

1. **147 (bugs)** — smallest, clears the critical socket.rs netns
   restore bug, builds momentum.
2. **155 (ext-ack + strict-check)** — improves error diagnostics
   for everything that ships later.
3. **148 (ergonomics)** — additive, parallelizable into several
   PRs; lands the sealed `AsyncConstructible` trait that Plans 154
   and 159 need.
4. **149 (streaming)** — touches the lower-level `send_dump`; land
   on a clean tree so reviewers focus on the architectural change.
   Plan 154 builds on `dump_stream`, so 149 ships first.
5. **153 (kernel features)** — three independent kernel features
   bundled to share the kernel-version probing + CI modprobe wave.
6. **150 (nftables flowtable)** — substantial new module; lands
   after 153 to share the modprobe-wave update. Plan 157 needs the
   `Flowtable` type in tree.
7. **151 (ENOBUFS resync)** — touches multicast subscription
   machinery; lands before 152 so its recipe can use resync.
8. **158 (syscall batching)** — touches the lowest-level socket
   code. Lands after 149 so the streaming code path automatically
   benefits when the feature flag is on. Behind `syscall_batch`
   for one release of soak; default-on in 0.17.
9. **154 (nlink-macros)** — biggest plan; lands after the lib's
   runtime surface stabilizes (147 – 151, 153, 155, 158 in tree)
   so the macro's `__rt` targets don't shift under it.
10. **156 (DPLL family)** — first nlink-macros dogfood. Lands
    immediately after 154 to validate the macro design on a real
    subsystem; surfaces any iteration needed before 152's `aya`
    demo also depends on macros.
11. **159 (ConnectionPool)** — additive; depends on 148 §4.5
    (sealed constructor sealed-trait bound). Small enough to ship
    in parallel with 156 or 157 if reviewer bandwidth allows.
12. **157 (NftablesConfig)** — biggest high-level API addition;
    depends on 150 (Flowtable). Lands late so reviewers see the
    diff against the full nftables surface.
13. **152 (integration showcases)** — `aya` co-demo uses the
    macros from 154; Prometheus exporter benefits from streaming
    from 149; OTel example is small and ships standalone.

## Cross-plan integration map

See master plan §7b for the full dependency graph + coupling-points
table. Quick reference:

```
147 ──┐
      ├──► CHANGELOG bundle: "Error variants now carry ext-ack"
155 ──┘    (147 adds NamespaceRestoreFailed; 155 adds ext_ack fields)

148 §4.5 (sealed AsyncConstructible) ──┬──► 154 (#[genl_family] auto-impls)
                                       │
                                       └──► 159 (ConnectionPoolBuilder bound)

149 (dump_stream) ──┬─► 154 (dump_typed_stream uses it)
                    │
                    └─► 151 (resync state machine borrows the patterns)

158 (recvmmsg/sendmmsg) ─── transparently speeds up 149 + 154 + 156

154 ──┬─► 156 (DPLL family — first dogfood; adds #[derive(GenlEnum)] +0.5d to 154)
      │
      └─► 152 (aya co-demo uses macros)

150 ──► 157 (uses Flowtable type + Transaction for atomic apply)

150 + 153 + 156 ──► one `bitflags = "2"` workspace dep
150 + 153 + 156 ──► one workflow modprobe-wave edit
```

## Pre-cut acceptance gates

Track here, tick as they go green:

- [ ] All thirteen sub-plans 🟢 (status above all green)
- [ ] `nlink-macros` published to crates.io (Plan 154 blocker —
      nlink depends on it; ships first)
- [ ] `cargo test -p nlink --lib` passes
- [ ] `cargo test -p nlink-macros` passes
- [ ] `cargo test --workspace` passes (example-gating regression
      guard)
- [ ] `cargo test -p nlink --features lab --test integration`
      passes in privileged container
- [ ] `cargo test -p nlink --features lab,syscall_batch --test
      integration` passes (Plan 158 parity check)
- [ ] `cargo bench -p nlink --bench dump_throughput` runs;
      results recorded in `benches/RESULTS.md` (Plan 158)
- [ ] `cargo doc -p nlink --no-deps` zero warnings
- [ ] `cargo doc -p nlink-macros --no-deps` zero warnings
- [ ] `cargo clippy --workspace --all-targets --all-features -- --deny warnings` clean
- [ ] `cargo machete` clean (no `|| true`)
- [ ] `cargo-semver-checks` passes against published 0.15.1
      (informational today; ideally `--deny=major` by release time)
- [ ] `cargo public-api -p nlink diff 0.15.1..HEAD` reviewed —
      expected additions only, no surprise removals or signature
      changes
- [ ] `cargo publish -p nlink-macros --dry-run` clean
- [ ] `cargo publish -p nlink --dry-run` clean
- [ ] Workspace version bumped to `0.16.0`
- [ ] CHANGELOG `## [0.16.0]` consolidated from `[Unreleased]`
- [ ] `docs/migration_guide/0.15.1-to-0.16.0.md` written
- [ ] Release commit + tag + push
- [ ] `cargo publish -p nlink-macros` (FIRST — nlink depends on it)
- [ ] `cargo publish -p nlink`
- [ ] `git tag 0.16.0 && git push --tags`

## Post-publish cleanup

- [ ] Update `128b-roadmap-overview.md` "Active plans" table — clear
      entries for 147 – 159
- [ ] Delete `plans/146-*.md` through `plans/159-*.md` in one
      post-publish commit (per project convention; see commits
      `b8c03fa`, `5d0ad14`)
- [ ] **Keep `plans/INDEX.md`** — overwrite it with the 0.17 cycle's
      tracking when work begins, or delete-and-recreate at that
      point. The file itself is the pattern; the 0.16 contents are
      ephemeral.
- [ ] Substance lives in `CHANGELOG.md ## [0.16.0]` + the migration
      guide; the plan files were scaffolding.

## How to update this file

When a plan moves status:

1. Edit the **Status** column emoji.
2. Edit the **PR(s)** column — comma-separated list of PR numbers,
   or "—" if not yet open.
3. If a plan slips, add a one-line note in **Notes** ("slipped to
   week 3 — kernel-source dive longer than estimated").
4. When the cycle cuts, all rows become 🔵.
5. After post-publish cleanup, this file gets rewritten for 0.17.

The dependency map + sequencing rationale are stable across the
cycle — only the status / PR / notes columns change as work moves.
