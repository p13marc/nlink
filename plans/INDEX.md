---
subject: nlink plan index — 0.20 cycle open (post-audit, 16-plan suite written)
status: 0.20 cycle planning complete; Plan 221 (0.19.1 hotfix) carved out as the first deliverable
last updated: 2026-06-04
---

# Plan index

Day-to-day plan tracker. Per `CLAUDE.md ## Publishing` /
`Plan-file cleanup`, plan files are working memory and get
deleted when a cycle cuts. The durable narrative lives in
`CHANGELOG.md` + `docs/migration_guide/`.

## 0.19.0 — shipped 2026-05-31

`nlink@0.19.0` + `nlink-macros@0.19.0` on crates.io; `v0.19.0`
tag + GitHub release on master. Durable narrative:

- [`CHANGELOG.md ## [0.19.0]`](../CHANGELOG.md)
- [`docs/migration_guide/0.18.0-to-0.19.0.md`](../docs/migration_guide/0.18.0-to-0.19.0.md)

## 0.20 cycle — open

Audit pass on `0.20` head `05d388a` (2026-06-04) surfaced 60
findings; 16 plans written. Cycle theme:

> *Constants are part of the wire format too.*

0.19's Plan 213 closed struct-size drift. 0.20 closes
constant-value drift (Plan 222), big-endian wire parsing
(Plan 223), recv truncation (Plan 224), and panic-on-malformed
(Plan 225). Plus the typed-API tightening and doc-drift sweep
the audit surfaced.

The XFRM cluster (Plan 221) is **carved out as a 0.19.1
hotfix** because `flush_policy()` was silently deleting all SAs
since the family shipped — too severe to wait for the cycle.

Audit artefacts at repo root (deleted at cut time per CLAUDE.md
`## Plan-file cleanup`):
- [`AUDIT_REPORT.md`](../AUDIT_REPORT.md) — consolidated executive
- [`AUDIT_WIRE_FORMAT.md`](../AUDIT_WIRE_FORMAT.md) — 18 findings
- [`AUDIT_BUGS.md`](../AUDIT_BUGS.md) — 20 findings
- [`AUDIT_API.md`](../AUDIT_API.md) — 22 findings

### Master + hotfix

| # | Plan | Status | Notes |
|---|---|---|---|
| 220 | [0.20 master](220-0.20-master-plan.md) | planning complete | Cycle scope, ordering, exit criteria |
| 221 | [XFRM constants hotfix → 0.19.1](221-xfrm-constants-hotfix-plan.md) | URGENT | Gates 0.19.1 ship; 6 CRITICAL XFRM + 1 HIGH CtKey |

### Durable prevention

| # | Plan | Severity | Notes |
|---|---|---|---|
| 222 | [Sizeof CI gate — constants extension](222-sizeof-gate-constants-plan.md) | systemic | Would have caught W1-W4 + W7 + W9 at build time |
| 223 | [BE wire-parsing sweep + s390x gate](223-bigendian-sweep-plan.md) | HIGH on BE | Closes B1-B3; sweeps the class 0.19 N3 missed |
| 224 | [`recv_msg` MSG_TRUNC handling](224-recv-msg-truncate-plan.md) | HIGH | Closes B4; mirrors `recv_batch_inner` |
| 225 | [WG `parse_timespec` robustness](225-wg-timespec-robustness-plan.md) | HIGH | Closes B5; verified by repro |
| 226 | [DPLL `sint` codegen + FFO widening](226-dpll-sint-plan.md) | HIGH | Closes W8; `nlink-macros` runtime work |

### Typed-API tightening

| # | Plan | Severity | Notes |
|---|---|---|---|
| 227 | [Typed `AddressFamily` newtype](227-family-newtype-plan.md) | MID footgun | Closes A2; raw u8 → typed |
| 228 | [Typed `Percent` on declarative builders](228-typed-percent-builders-plan.md) | MAJOR footgun | Closes A1; mirrors 0.14 units rollout |
| 230 | [`Verdict` typed `ChainName`](230-verdict-chainname-plan.md) | MID | Closes A20 |
| 231 | [`RuleMessage` accessor discipline](231-message-accessor-discipline-plan.md) | MID | Closes A3 + convention sweep |

### Robustness + docs

| # | Plan | Severity | Notes |
|---|---|---|---|
| 229 | [Doc-drift sweep + compile-tested examples](229-doc-drift-sweep-plan.md) | MID doc-only | Closes A4/A5/A18/A22 |
| 232 | [Bug-hunt LOW-tier batch](232-bug-hunt-low-tier-plan.md) | LOW | Closes B6/B9-B11/B13-B14/B17-B19 |
| 233 | [`DumpStream` fuse-on-error policy](233-dumpstream-fuse-policy-plan.md) | MEDIUM | Closes B7/B16; documents dump vs event asymmetry |

### Discretionary (cycle ships without these if budget is tight)

| # | Plan | Notes |
|---|---|---|
| 197 | [Declarative ovpn](197-declarative-ovpn-plan.md) | Carry-over; kernel 6.16+; new GENL family |
| 234 | [F1 follow-on — NlRouter dispatcher](234-nlrouter-dispatcher-plan.md) | Closes the F1 mutex hold-time perf gap |
| 235 | [Plan 208 Phase 3-4 — GENL command unification](235-genl-command-unification-plan.md) | Closes H9 (wg_command stale-frame); finishes recv-loop closeout |

### Cycle dependency graph

```
221 (hotfix) ──→ 222.1 (sizeof gate XFRM/nft phase) ──→ 0.19.1 ship
   │                       │
   │                       └──→ 222.2/3/4 (broader gate coverage)
   │
   master → 0.20 merge
   │
   └──→ {223, 224, 225, 226, 227, 228, 230, 231, 229, 232, 233}
          (12 deterministic plans; mostly independent)
   │
   └──→ {197, 234, 235} (discretionary; opt-in if cycle budget allows)
   │
   └──→ docs/migration_guide/0.19.0-to-0.20.0.md written
   │
   └──→ CHANGELOG promoted + cargo publish
```

The only deterministic ordering is **228 → 229** — the doc sweep
needs to know the final builder shape.

## 0.21 cycle seed

Punted from 0.20 at audit time; revisit at the 0.20 cut:

| Topic | Source |
|---|---|
| Full nl80211 audit + per-attribute coverage | Master plan §9 |
| ethtool linkmodes bitset (`NLA_BITFIELD32`) audit | AUDIT_WIRE_FORMAT.md "Not audited" |
| net_shaper re-audit against kernel 6.13 YAML | AUDIT_WIRE_FORMAT.md "Not audited" |
| Bridge VLAN / FDB wire-format audit | same |
| MPLS / SRv6 / NextHop struct-size audit | same |
| Audit follow-ups H7 (`ip vrf exec`) + H8 (`ip xfrm` lib wire-up) | 0.19 migration guide §"Plan 209" |
| Plan 198 — full declarative `DeclaredSet` + element diff | 0.19 migration guide §"Plan 198" |
| Plan 189 §8 — `Deserialize` + `schemars` JSON Schema | 0.19 migration guide §"Plan 189" |
| Plan 193 phase 2-3 — `cargo-fuzz` + `proptest` | 0.19 migration guide §"Plan 193" |
| Plan 195 — `StreamBackoff` + `Store<K>` reflector + `backon` | 0.19 migration guide §"Plan 195" |
| Plan 196 follow-ups — `WireguardConfig::client()` + INI parser | 0.19 migration guide §"Plan 196" |
| Plan 201 — broader `From`/`Into` + `Display` + `#[inline]` sweep | 0.19 migration guide §"Plan 201" |
| Plan 205 follow-on — wire purge correctly with kernel-managed exclusions | 0.19 CHANGELOG §"Plan 205" |
| TC pedit + u32 selector wire-format spot audit | AUDIT_WIRE_FORMAT.md §"Not audited" |
| `TableName` newtype + `Chain::new` typed args (Plan 230 adjacent) | Plan 230 §6 |
| `LinkStats` accessor-convention break | Plan 231 §6 |

These rows have no plan files yet — write them when the 0.21
cycle kicks off, at the 0.20 cut.

## How to update this file

1. When a cycle opens, add the new plan rows + a "Cycle X.Y"
   section at the top.
2. When a plan ships and the cycle cuts + publishes, delete
   the per-plan file in the cut commit. The CHANGELOG entry
   + migration-guide section carry the durable narrative.
3. Keep this file slim — it's a pointer, not an archive.
