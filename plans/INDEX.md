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
- **Estimated length**: 5 – 6 focused weeks
- **Plans**: 1 master + 13 sub-plans (147 – 159)
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
| [147](147-0.16-bug-fixes-plan.md) | Bug fixes (socket.rs critical, bitset perf, config-diff, route metrics, cosmetic) + audit follow-ups (parser fuzz, eprintln→tracing, unwrap audit) | ~1 day | 1 | 🟡 | – | Phase 1 (socket.rs §4.1) done in local commit; Phases 2-4 next |
| [155](155-0.16-neli-parity-features-plan.md) | ext-ack TLV parsing + `enable_strict_checking()` + `set_ext_ack()` + namespace-safety lib docs | ~1 day | 2 | ⚪ | – | Lands early so its better diagnostics benefit every later plan |
| [148](148-0.16-ergonomics-plan.md) | `wait_link_up` + `get_link_stats` + re-exports + per-method namespace docs + sealed GENL constructor + error recipe + netkit test + `NFT_TABLE_F_PERSIST` + per-NAPI config | ~1.5 days | 3 | ⚪ | – | §4.5 sealed-constructor is the dependency Plans 154 and 159 need |
| [149](149-0.16-streaming-dump-api-plan.md) | `dump_stream<T>` generic + `stream_routes/links/neighbors/fdb` + TC streams + typed config streams (XFRM SA/SP, conntrack) | ~3 days | 4 | ⚪ | – | Foundation for Plan 154's `dump_typed_stream`; Plan 158 transparently accelerates it |
| [153](153-0.16-kernel-feature-bundle-plan.md) | XFRM IPsec offload (`XFRMA_OFFLOAD_DEV`) + Devlink rate + port-function-state + TX H/W shaping (`net_shaper` GENL) | ~5 days | 5 | ⚪ | – | Shares `bitflags` workspace dep with Plans 150 and 156 |
| [150](150-0.16-nftables-flowtable-plan.md) | `Flowtable` builder + `add/del/get_flowtable` + `Expr::FlowOffload` + counters + multicast events for table/chain/rule/flowtable | ~3 days | 6 | ⚪ | – | Bundle modprobe-wave edit with Plans 153 and 156. Required by Plan 157 |
| [151](151-0.16-enobufs-resync-plan.md) | `events_with_resync()` — sum-type `ResyncedEvent<T> { Event, Resynced, Marker }`, hand-rolled state machine, recipe | ~2 days | 7 | ⚪ | – | Cilium-issue-#40280 fix; uses Plan 149 patterns |
| [158](158-0.16-syscall-batching-plan.md) | `recvmmsg`/`sendmmsg` batching behind opt-in `syscall_batch` feature; 32-frame batches; per-socket reused buffers | ~2 days | 8 | ⚪ | – | Transparently speeds up Plans 149 + 154; default-on planned for 0.17 |
| [154](154-0.16-nlink-macros-plan.md) | New `nlink-macros` proc-macro crate: `#[derive(GenlMessage/GenlCommand/GenlAttribute/GenlEnum/NetlinkAttrs)]` + `#[genl_family]` | ~7.5 days | 9 | ⚪ | – | Single biggest plan; **publish before nlink** at release time. `GenlEnum` derive added by Plan 156's add-on (+0.5d) |
| [156](156-0.16-dpll-genl-family-plan.md) | DPLL netlink family (kernel 6.7+) — first in-tree user of `nlink-macros`. ~130 lines of macro-derived declaration for the full family | ~2 days | 10 | ⚪ | – | Validates Plan 154's design end-to-end; telco SyncE/PTP use case |
| [159](159-0.16-connection-pool-plan.md) | `ConnectionPool<P>` + `PooledConnection<'p, P>` + namespace-aware builder. Bounded mpsc-channel-backed | ~2 days | 11 | ⚪ | – | Partial alternative to deferred NlRouter dispatch; depends on Plan 148 §4.5 |
| [157](157-0.16-nftables-declarative-config-plan.md) | Declarative `NftablesConfig` — `diff + apply + reconcile` mirroring `NetworkConfig`, atomic-via-`Transaction` commit, canonicalized rule equivalence | ~3 days | 12 | ⚪ | – | Biggest high-level API addition; depends on Plan 150 (Flowtable type) |
| [152](152-0.16-integration-showcases-plan.md) | `aya` co-demo (TCX + nlink + nlink-macros showcase) + Prometheus exporter POC (`bins/exporter/`) + OpenTelemetry example | ~3 days | 13 | ⚪ | – | Depends on Plan 154 (aya demo uses macros). Ships last |

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
