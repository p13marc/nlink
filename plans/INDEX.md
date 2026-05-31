---
subject: nlink plan index — 0.19 cycle-close ready
status: 0.19 cycle CUT-PENDING; second-batch (Plans 203-215) shipped; only Plan 210 LOW-tier remainder + maintainer cut left
last updated: 2026-05-31
---

# Plan index

Day-to-day plan tracker. Per `CLAUDE.md ## Publishing` /
`Plan-file cleanup`, plan files are working memory and get
deleted when a cycle cuts. The durable narrative lives in
`CHANGELOG.md` + `docs/migration_guide/`.

## 0.19 cycle — cut-pending

The 0.19 cycle ships **two waves**:

**Wave 1** — original 0.19 plan suite (Plans 186-202). All 16
plans either shipped or were deferred with documented rationale.
Documented in `docs/migration_guide/0.18.0-to-0.19.0.md` §"Plan
186" through §"Plan 202".

**Wave 2** — post-cycle deep audit (`docs/AUDIT_REPORT_2026_05_31.md`)
surfaced ~96 additional bugs. Plan 203 (master) orchestrated 13
sub-plans (204-215). **12 of 13 shipped pre-cut**; the 13th
(Plan 210 examples cleanup) has its HIGH-severity sub-item
(firewall cleanup leak) + the highest-impact LOW-tier doc-name
fixes shipped, with the remaining LOW-tier cleanup folded into
the cut-prep hygiene pass.

Cumulative breaking changes (full list in migration guide):

- nftables `NFT_JUMP`/`NFT_GOTO` constant values corrected
  (Plan 204 C1)
- `ApplyOptions::with_purge` + `ConfigDiff::*_to_remove`
  removed (Plan 205)
- `DpllPin::phase_offset` widened to `Option<i64>` (Plan 206)
- `Hook::Ingress` split into `NetdevIngress`/`InetIngress` +
  new `NetdevEgress` (Plan 211)
- 0.19-cycle Plans 187, 188, 190 (wave 1)

All wave-2 fixes carry adversarial-verification provenance via
the audit report; CHANGELOG entries cite the audit finding ID
for each (C1-C5, H1-H11, M1-M19).

### Cut checklist (for `scripts/cut-release.sh 0.19.0`)

- [ ] Workspace version bumped to `0.19.0`
- [ ] `CHANGELOG.md ## [Unreleased]` promoted to `## [0.19.0]`
      with date
- [ ] `docs/migration_guide/README.md` row updated with 0.19
      highlights (NFT verdicts, XFRM, DPLL i64, Hook split,
      purge removal)
- [ ] `nlink-macros` published before `nlink` (path-dep version
      pinning)

### Headline contributions (for the release notes)

Wave 1:
1. **Plan 193 phase 2** found and fixed `MessageIter::next`
   no-progress on malformed frames.
2. **Plan 199** redesigned WireguardWatcher as polling.
3. **Plan 200** facade APIs collapsed boilerplate.

Wave 2:
4. **Plan 204** — four CRITICAL wire-format defects fixed (nft
   verdicts wrong since enum shipped; XFRM `add_sp` broken on
   every kernel; XFRM `del_sp` brittle on strict-checking
   kernels; devlink mcast subscribe broken entirely).
5. **Plan 213** — build-time `sizeof(struct ...)` CI gate
   prevents wire-format drift from recurring. Surfaced a
   sibling bug (`XfrmUserTmpl` 62→64) the moment it shipped.
6. **Plan 207** — NetworkConfig correctness pass closes 7
   silent reconcile-divergence bugs (master change, route
   gateway change, IFF_UP vs OperState, atomic qdisc replace,
   etc.).
7. **Plan 206** — DPLL `phase_offset` widened to `i64`,
   closing silent value corruption for telco/PTP/SyncE workloads.

## Active plans (carrying past 0.19)

| Plan | Status | Notes |
|------|--------|-------|
| [197](197-declarative-ovpn-plan.md) | deferred to 0.20 | Kernel 6.16+ ovpn GENL UAPI; needs imperative Connection<Ovpn> family + scoped implementation effort. Link half shipped via Plan 190 §2.3b. |

## Deprioritized (parked)

| Plan | Why parked |
|------|------------|
| [152](152-0.16-integration-showcases-plan.md) | `aya` co-demo + Prometheus exporter + OTel example. Carried since 0.16 without a real adopter signal. Revisit if a downstream asks. |

## 0.20 cycle seed

Not yet opened. Topics worth scoping when it kicks off:

| Topic | Source |
|-------|--------|
| Plan 197 — ovpn GENL family imperative + declarative | `plans/197-declarative-ovpn-plan.md` |
| Plan 205 follow-on — wire purge correctly with kernel-managed-resource exclusion list | Plan 205 §10 deferral note + audit report C5 |
| F1 follow-on — full NlRouter-style dispatcher task (Mutex serialization shipped in 0.19 Plan 194; dispatcher unlocks per-request pipelining + multicast-events vs request safety) | 0.19 migration guide §"Plan 194" + audit report |
| Plan 208 Phase 3-4 — GENL command unification + family-resolution unification (15th recv-loop closeout: wg_command stale-frame race) | Plan 208 deferral note + audit report H9 |
| Plan 189 §8 expansions — `Deserialize` + `schemars` JSON Schema | 0.19 migration guide §"Plan 189" |
| Plan 193 phase 2-3 — `cargo-fuzz` infrastructure + `proptest` integration | 0.19 migration guide §"Plan 193" |
| Plan 195 — `StreamBackoff` + `Store<K>` reflector + `backon` | 0.19 migration guide §"Plan 195" |
| Plan 196 follow-ups — `WireguardConfig::client()` shortcut + `from_wg_config()` INI parser | 0.19 migration guide §"Plan 196" |
| Plan 198 — full declarative `DeclaredSet` + element diff | 0.19 migration guide §"Plan 198" |
| Plan 201 — broader sweep (`From`/`Into` + `Display` + `#[inline]` on builders) | 0.19 migration guide §"Plan 201" |
| Audit follow-ups — H7 (`ip vrf exec` real impl) + H8 (`ip xfrm` lib wire-up) | Plan 209 §4-5 + audit report H7/H8 |

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
