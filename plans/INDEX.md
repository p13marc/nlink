---
subject: nlink plan index — between cycles
status: 0.19 cycle-close ready (cut pending); 0.20 not yet opened
last updated: 2026-05-31
---

# Plan index

Day-to-day plan tracker. Per `CLAUDE.md ## Publishing` /
`Plan-file cleanup`, plan files are working memory and get
deleted when a cycle cuts. The durable narrative lives in
`CHANGELOG.md` + `docs/migration_guide/`.

## 0.19 cycle — cut pending

All 16 0.19 plans either shipped or deferred with documented
rationale. The cycle's narrative is in
[`CHANGELOG.md ## [Unreleased]`](../CHANGELOG.md) (will become
`## [0.19.0]` at cut) and
[`docs/migration_guide/0.18.0-to-0.19.0.md`](../docs/migration_guide/0.18.0-to-0.19.0.md).

**Cut checklist** (for `scripts/cut-release.sh 0.19.0`):

- [ ] Workspace version bumped to `0.19.0`
- [ ] `CHANGELOG.md ## [Unreleased]` promoted to `## [0.19.0]`
      with date
- [ ] Migration guide headline polished
- [ ] `docs/migration_guide/README.md` row inserted with
      0.19 highlights
- [ ] `nlink-macros` published before `nlink` (path-dep
      version pinning)

**Headline contributions** (for the release notes):

1. **Plan 193 phase 2 found + fixed a real bug** —
   `MessageIter::next` returned `Err` from both bounds
   checks without advancing `self.data`. Plans 185 + 191
   long-lived multicast subscribers would have spun on a
   single malformed kernel frame. Two-line fix, four
   regression tests. Bug class matches neli #305.
2. **Plan 199 redesigned after kernel research** —
   `drivers/net/wireguard/netlink.c` declares zero
   multicast groups (`n_mcgrps = 0`). The original spec
   assumed multicast events that don't exist in the
   kernel. Ships polling-based `WireguardWatcher`
   matching what every WG monitoring tool does.
3. **Plan 200 facade** — `nlink::facade::apply::network(&cfg)`
   collapses 5-15 lines of typed-surface boilerplate
   into one-liners; `Stack` bundles RTNETLINK + nftables
   + WG with deterministic apply order.

## Active plans

| Plan | Status | Notes |
|------|--------|-------|
| [197](197-declarative-ovpn-plan.md) | deferred to 0.20 | Kernel 6.16 ovpn GENL UAPI maturing; needs imperative `Connection<Ovpn>` family first. Link half ships via Plan 190 §2.3b. |

## Deprioritized (parked)

| Plan | Why parked |
|------|------------|
| [152](152-0.16-integration-showcases-plan.md) | `aya` co-demo + Prometheus exporter + OTel example. Carried since 0.16 without a real adopter signal. Revisit if a downstream asks. |

## 0.20 cycle seed

Not yet opened. Topics worth scoping when it kicks off:

| Topic | Source |
|-------|--------|
| Plan 197 — ovpn GENL family imperative + declarative | `plans/197-declarative-ovpn-plan.md` carries the spec |
| Plan 189 §8 expansions — `Deserialize` + `schemars` JSON Schema + runtime-types `Serialize` | 0.19 migration guide §"Plan 189" |
| Plan 193 phase 2-3 — `cargo-fuzz` infrastructure + `proptest` integration | 0.19 migration guide §"Plan 193" |
| Plan 195 — `StreamBackoff` + `Store<K>` reflector + `backon` | 0.19 migration guide §"Plan 195" |
| Plan 196 follow-ups — `WireguardConfig::client()` shortcut + `from_wg_config()` INI parser | 0.19 migration guide §"Plan 196" |
| Plan 198 — full declarative `DeclaredSet` + element diff + `DeclaredTableBuilder::set` | 0.19 migration guide §"Plan 198" |
| Plan 201 — broader sweep (`From`/`Into` + `Display` + `#[inline]` on builders) | 0.19 migration guide §"Plan 201" |

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
