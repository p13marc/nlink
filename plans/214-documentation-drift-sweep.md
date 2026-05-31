---
to: nlink maintainers
from: 0.19 second deep-audit
subject: Plan 214 — Documentation drift sweep (M23-M30 + L34-L36)
status: queued for 0.19 — MEDIUM (visible docs are 2 cycles stale)
target version: 0.19.0
parent: [203](203-0.19-second-batch-master.md)
source: docs/AUDIT_REPORT_2026_05_31.md §Documentation drift
created: 2026-05-31
---

# Plan 214 — Documentation drift sweep

## 1. Why this plan exists

The audit's doc-drift agent found 30 doc-drift items. The dominant
pattern: **CLAUDE.md, lib.rs, and README.md all describe pre-0.18
state**. The migration guide tracks 0.19, but the always-visible
top-level docs lag by 2 cycles.

The single highest-leverage fix is **rewriting the top docs**.
Recipes and example-name drift are bundled at Plan 210.

## 2. The changes

### 2.1 README.md sweep

**File:** `README.md`

- Line 29, 32, 36: `nlink = "0.17"` → `"0.19"` in three install
  snippets.
- Lines 274-307: Replace "New in 0.17" / "Highlights from 0.16"
  with **"New in 0.19"** + **"Highlights from 0.18"** sections.
- New in 0.19 section: cover (a) `Error::DumpInterrupted` +
  `is_dump_interrupted` predicate, (b) `Connection<Route>::into_events_with_resync`,
  (c) facade APIs (Plan 200), (d) declarative WireguardConfig
  (Plan 196), (e) `apply_reconcile` retry semantics, (f)
  CRITICAL fixes from Plan 204.
- Add a row for `tuntap-async` and `serde` in the features
  table (lines 43-53).
- Highlights from 0.18: chain_type, list_*_in filters,
  Error::ext_ack(), Display for diffs, default routes,
  subscribe_all_with_resync.

### 2.2 CLAUDE.md sweep

**File:** `CLAUDE.md`

- Line 10, 66: bins list `{ip,tc,ss,nft,wifi,devlink}` →
  `{ip,tc,ss,nft,wifi,devlink,ethtool,bridge,config,diag,wg}`
  (11 total).
- Line 69: "Plans" architecture row points at `plans/INDEX.md`
  instead of stale `128b-roadmap-overview.md`.
- Lines 97-104: features table missing `tuntap-async` row.
- Line 103: `syscall_batch` "for one soak release" — drop the
  stale claim (it's been on the opt-in plan for 3 cycles).
- Lines 486-522: cookbook missing 6 recipes:
  `cgroup-classification`, `connection-pool`,
  `error-handling-patterns`, `events-with-resync`,
  `nftables-watch-with-resync`, `xfrm-ipsec-tunnel`.
- Lines 526-529: examples subdir listing missing `pool/`.
- Lines 543-560: **"Active work"** section — completely
  rewrite for 0.19 cut-pending state (per the INDEX.md).

### 2.3 lib.rs landing-page docs

**File:** `crates/nlink/src/lib.rs`

- Line 148: doctest `Connection::<Route>::new_in_namespace("ns1")?`
  → `Connection::<Route>::new()?` + use `connection_for("ns1")`
  pattern, OR cast the &str to a RawFd appropriately.
- Lines 9-14: features list — remove non-existent `tc`, add
  `namespace_watcher`, `lab`, `syscall_batch`, `serde`.
- Lines 86-90: drop the "_by_name reads /sys/class/net/" claim
  (Plan 192 D4 made it netlink-correct).
- Line 128: doctest `addr.address` → `addr.address()` (`pub(crate)`
  field has accessor).

### 2.4 error.rs doctest fix

**File:** `crates/nlink/src/netlink/error.rs:701`

`-> nlink::Result<Vec<nlink::Link>>` →
`-> nlink::Result<Vec<nlink::LinkMessage>>`.

### 2.5 Recipe drift fixes

| File | Fix |
|---|---|
| `docs/recipes/nftables-declarative-config.md:64` | `diff.summary()` → `format!("{}", diff)` (Plan 188 §2.6 deprecation) |
| `docs/recipes/events-with-resync.md` | Add §"Pre-baked RTNETLINK helper" pointing at Plan 191's `Connection<Route>::into_events_with_resync` |
| `docs/recipes/error-handling-patterns.md` | Add §"NLM_F_DUMP_INTR — retry the dump" using `is_dump_interrupted()` |
| `docs/recipes/connection-pool.md:32-33` | Drop "see master plan §4 item 6" — refers to deleted Plan 146 |

### 2.6 Migration guide README

**File:** `docs/migration_guide/README.md:54`

Update the 0.19 row from "currently 7-plan + 3 defensive
(193-195); In progress — placeholder" to the 16 shipped plans
+ this batch (203-215).

### 2.7 New recipes for 0.19 features

- `docs/recipes/wireguard-declarative.md` (new) — Plan 196
  WireguardConfig walk-through (~150 lines).
- `docs/recipes/facade-quickstart.md` (new) — Plan 200 facade
  APIs (~100 lines).

## 3. Tests

- All doctests must compile (`cargo test --doc`).
- `cargo build --workspace` succeeds.
- `scripts/audit-example-registration.sh` clean.
- (Plan 210's `audit-example-doc-names.sh` once added.)

## 4. CHANGELOG entry

```markdown
### Documentation

- **Top-level docs brought to 0.19 state** (Plan 214). README,
  CLAUDE.md, lib.rs landing-page doc-comment all updated.
  Features tables include `tuntap-async` and `serde`. Bins
  listing extended from 6 to 11. CLAUDE.md "Active work" rewritten
  for 0.19 cut-pending state.
- **Two new recipes**: `wireguard-declarative.md` (Plan 196)
  and `facade-quickstart.md` (Plan 200).
- **Recipe drift cleanup**: `nftables-declarative-config.md`
  uses `Display` instead of deprecated `.summary()`;
  `events-with-resync.md` points at the Plan 191 helper;
  `connection-pool.md` drops the deleted-Plan-146 reference.
- **`Error::is_dump_interrupted` doctest type fix**: was
  `nlink::Link` (doesn't exist), now `nlink::LinkMessage`.
```

## 5. Acceptance criteria

- [ ] README install snippets at 0.19
- [ ] README "New in 0.19" + "Highlights from 0.18" sections
- [ ] README feature table includes tuntap-async + serde
- [ ] CLAUDE.md bins list at 11, cookbook complete
- [ ] CLAUDE.md "Active work" rewritten for 0.19 state
- [ ] lib.rs doctest compiles; features list correct
- [ ] error.rs doctest references correct type
- [ ] 4 recipe drift items fixed
- [ ] 2 new recipes written
- [ ] Migration guide README row at 0.19 state

## 6. Effort estimate

| Step | Time |
|---|---|
| README sweep | 45 min |
| CLAUDE.md sweep | 45 min |
| lib.rs doctest fixes | 15 min |
| error.rs doctest fix | 5 min |
| 4 recipe drift fixes | 30 min |
| 2 new recipes | 1 h |
| Migration guide README | 15 min |
| Verify (cargo test --doc) | 30 min |
| **Total** | **~3 h** |

## 7. Risks

- **Low.** Pure doc edits. Verification via `cargo test --doc`
  + recipe code-block compilation.

## 8. Cross-cutting artifacts

| Artifact | Action |
|---|---|
| `CHANGELOG.md` | 4 documentation entries |
| `README.md` | sweep |
| `CLAUDE.md` | sweep |
| `crates/nlink/src/lib.rs` | doctest + features list |
| `crates/nlink/src/netlink/error.rs:701` | doctest type |
| `docs/recipes/*.md` | 4 fixes + 2 new |
| `docs/migration_guide/README.md` | row update |

End of plan.
