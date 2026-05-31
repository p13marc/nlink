---
subject: nlink plan index — 0.19 second batch in flight
status: 0.19 second-audit batch queued (13 plans); cut blocked on these landing
last updated: 2026-05-31
---

# Plan index

Day-to-day plan tracker. Per `CLAUDE.md ## Publishing` /
`Plan-file cleanup`, plan files are working memory and get
deleted when a cycle cuts. The durable narrative lives in
`CHANGELOG.md` + `docs/migration_guide/`.

## 0.19 cycle — second batch (in flight)

The first round of 16 plans either shipped or were deferred with
documented rationale; cycle was "cut pending" — until a second
deep audit (`docs/AUDIT_REPORT_2026_05_31.md`) surfaced ~96
distinct bugs across angles the first audit didn't reach.

Five **CRITICAL** wire-format defects ship today silently broken
on real kernels (NFT verdicts, XFRM policy add/del, devlink
event subscription, NetworkConfig purge). Eleven **HIGH**
findings span library, bins, and examples. Per user
authorization (2026-05-31) the second batch is allowed to
include breaking changes.

The cycle now cuts only once the second batch lands.

### Master + sub-plans

| Plan | Subject | Severity | Effort | Breaking? |
|------|---------|----------|--------|-----------|
| [203](203-0.19-second-batch-master.md) | Master — orchestrates 12 sub-plans | — | (see below) | — |
| [204](204-wire-format-critical-fixes.md) | C1 nft verdicts + C2/C3 xfrm padding + C4 devlink mcast | CRITICAL | 3 h | Yes (verdict consts) |
| [205](205-network-config-purge-decision.md) | C5 wire up `purge` correctly OR remove the dead-code knob | CRITICAL | 6 h | Yes |
| [206](206-dpll-phase-offset-s64.md) | H1 DPLL phase_offset i32→s64 + macros runtime i64 support | HIGH | 5 h | Yes |
| [207](207-network-config-correctness-pass.md) | H2 master change + H3 route identity + H4 reconcile + M3-M5/M10/M18/M19 | HIGH | 10 h | Yes |
| [208](208-recv-loop-completion.md) | H9 — 11 remaining recv-loops + NLM_F_DUMP_INTR coverage + GENL unification | HIGH | 8 h | No |
| [209](209-bins-remediation.md) | H5 nft typo + H6 wg silent + H7 vrf exec + H8 xfrm stubs + H11 TC alignment | HIGH | 8 h | Behavior |
| [210](210-examples-remediation.md) | H10 firewall cleanup + L1-L33 doc-comment + apply convention | HIGH+LOW | 4 h | No |
| [211](211-nftables-semantic-correctness.md) | M1 Hook::Ingress family + M6 anonymous rule churn + M7 Pass 3 comment sweep | MEDIUM | 5 h | Yes (Hook) |
| [212](212-error-api-hygiene.md) | M9 is_not_found Io + M15 Sync docstring + M16/M17 hardening | MEDIUM | 3 h | No |
| [213](213-wire-format-build-time-assertions.md) | Build-time `sizeof(...)` CI gate preventing C1/C2/C3 from recurring | INFRA | 5 h | No |
| [214](214-documentation-drift-sweep.md) | M23-M30 + L34-L36 — README/CLAUDE/lib.rs/recipes brought to 0.19 state | DOCS | 3 h | No |
| [215](215-genl-family-cleanup.md) | M11 KeepaliveSecs + M12 unpadded b64 + M13 nl80211 SSID walker | MEDIUM | 4 h | Yes (KeepaliveSecs) |

**Total**: ~76 h focused work. Parallelizable across contributors
per the dependency graph in Plan 203 §4.

### Cycle cut checklist (post-second-batch)

- [ ] All 13 second-batch plans landed
- [ ] Workspace version bumped to `0.19.0`
- [ ] `CHANGELOG.md ## [Unreleased]` promoted to `## [0.19.0]`
      with date — includes the breaking-change inventory from
      Plan 203 §7
- [ ] Migration guide §"Plan 204"–§"Plan 215" sections written
- [ ] `docs/migration_guide/README.md` row inserted with 0.19
      highlights including the second-batch CRITICAL fixes
- [ ] `nlink-macros` published before `nlink` (path-dep version
      pinning)

### Headline contributions (for the release notes)

First batch (shipped `5ef0808` 2026-05-31):
1. **Plan 193 phase 2** found and fixed `MessageIter::next`
   no-progress on malformed frames.
2. **Plan 199** redesigned WireguardWatcher as polling.
3. **Plan 200** facade APIs collapsed boilerplate.
4. First post-cycle bug-hunt fixed 5 latent bugs +
   `Error::DumpInterrupted`.

Second batch (queued):
5. **Plan 204** — four CRITICAL wire-format defects fixed (nft
   verdicts wrong since enum shipped; XFRM add_sp broken on
   every kernel; XFRM del_sp brittle on strict-checking
   kernels; devlink mcast subscribe broken entirely).
6. **Plan 205** — `NetworkConfig::apply` purge wired end-to-end
   (was silently no-op pre-0.19).
7. **Plan 207** — NetworkConfig correctness pass closes 9
   silent reconcile-divergence bugs (master change, route
   gateway change, etc.).
8. **Plan 213** — build-time `sizeof(struct ...)` CI gate
   prevents wire-format drift from recurring.

## Deferred to 0.20

| Plan | Why deferred |
|------|--------------|
| [197](197-declarative-ovpn-plan.md) | Kernel 6.16+ ovpn GENL UAPI; needs imperative Connection<Ovpn> family + scoped implementation effort. Link half shipped via Plan 190 §2.3b. |

## Deprioritized (parked)

| Plan | Why parked |
|------|------------|
| [152](152-0.16-integration-showcases-plan.md) | `aya` co-demo + Prometheus exporter + OTel example. Carried since 0.16 without a real adopter signal. Revisit if a downstream asks. |

## 0.20 cycle seed

Not yet opened. Topics worth scoping when it kicks off:

| Topic | Source |
|-------|--------|
| Plan 197 — ovpn GENL family imperative + declarative | `plans/197-declarative-ovpn-plan.md` |
| F1 architectural concurrency fix — NlRouter dispatch / per-Connection Mutex | Plan 212 §3 punt + audit M15 |
| Plan 189 §8 expansions — `Deserialize` + `schemars` JSON Schema | 0.19 migration guide §"Plan 189" |
| Plan 193 phase 2-3 — `cargo-fuzz` infrastructure + `proptest` integration | 0.19 migration guide §"Plan 193" |
| Plan 195 — `StreamBackoff` + `Store<K>` reflector + `backon` | 0.19 migration guide §"Plan 195" |
| Plan 196 follow-ups — `WireguardConfig::client()` shortcut + `from_wg_config()` INI parser | 0.19 migration guide §"Plan 196" |
| Plan 198 — full declarative `DeclaredSet` + element diff | 0.19 migration guide §"Plan 198" |
| Plan 201 — broader sweep (`From`/`Into` + `Display` + `#[inline]` on builders) | 0.19 migration guide §"Plan 201" |
| Wire-format `cc`-built-time sizeof option (Plan 213 alternative) | Plan 213 §2.1 |

These don't have plan files yet; write them when the 0.20
cycle kicks off (likely after 0.19.0 publishes and a
maintainer-cadence pause).

## How to update this file

1. When a cycle opens, add the new plan rows + a "Cycle X.Y"
   section at the top.
2. When a plan ships and the cycle cuts + publishes, delete
   the per-plan file in the cut commit. The CHANGELOG entry
   + migration-guide section carry the durable narrative.
3. Keep this file slim — it's a pointer, not an archive.
