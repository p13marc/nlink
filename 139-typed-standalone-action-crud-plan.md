---
to: nlink maintainers
from: nlink maintainers
subject: typed standalone-action CRUD on `Connection<Route>` — unblocks bins/tc action subcommand migration
target version: 0.15.0 (released under `[Unreleased]`); PR C is the release-cut commit
date: 2026-04-25; closed 2026-04-25
status: **CLOSED — all 3 PRs shipped under `[Unreleased]` as Plan 142 Phases 3 + 4.** **PR A** (`d69e10a`): library typed CRUD on `Connection<Route>` — `add/del/get/dump_action` + `ActionMessage` parser, 8 wire-format tests. **PR B** (`f7e4502` + `d124920` + `2764806`): `parse_params` on all 14 action kinds (13 fully parsed + `PeditAction` stub per §10), 74 unit tests. **PR C** (`b2370fd` + `0d095ae` + `56371db`): bin migration (action.rs typed dispatch + qdisc/filter legacy-fallback removal + parse_protocol inlining) + the **legacy-deletion milestone** that closed the 0.15.0 release-cut — `tc::builders::*` + `tc::options/*` deleted entirely (-3940 LOC), zero `#[allow(deprecated)]` in `bins/tc`. Every Plan 142 §6 acceptance gate met. Historical reference; substance lives in CHANGELOG `## [Unreleased]` and [`docs/migration_guide/0.14.0-to-0.15.0.md`](docs/migration_guide/0.14.0-to-0.15.0.md). One backlog item: `PeditAction::parse_params` is a stub (always rejects per §10's "punt-eligible until a downstream user asks") — see Backlog row in `128b-roadmap-overview.md`.
related: Plan 142 master; Plans 138 + 133 PR C (filter side prerequisite — closed); Plan 140 (helper prerequisite — closed); Plan 141 (independent — closed except sudo-gated PR C).
---

# Typed standalone-action CRUD on `Connection<Route>`

## 0. Summary

Today nlink has two coexisting action surfaces:

1. **Filter-attached actions** — `FilterConfig::actions(ActionList::new().with(GactAction::drop()))`.
   Composes typed actions into a filter; emit path is the filter's
   `write_options`. **Already typed end-to-end.** Used by every
   recipe and example that needs an action.

2. **Standalone shared actions** — `tc action add gact ...` creates
   a reusable action that filters can later reference by index.
   Only the deprecated `nlink::tc::builders::action::*` free
   functions speak this surface today; `Connection<Route>` has no
   typed equivalent. The `bins/tc/src/commands/action.rs` impl
   therefore stays under `#[allow(deprecated)]` indefinitely.

This plan adds the missing typed methods on `Connection<Route>`
plus a small builder shape, so the bin's `action` subcommand can
migrate the same way `qdisc` and `filter` did in slices 6 + 7 +
later. Once the bin migrates, the four legacy
`tc::builders::{class,qdisc,filter,action}` modules can be deleted
entirely.

## 1. Goals & non-goals

### Goals

1. **Typed `Connection<Route>` methods** for the standalone-action
   lifecycle — `add_action`, `del_action`, `get_action`,
   `dump_actions`. All take typed `ActionConfig` (already exists)
   plus a typed action index where applicable.
2. **`bins/tc/src/commands/action.rs` migrated off**
   `tc::builders::action::*`. Drop the `#[allow(deprecated)]` on
   the `impl ActionCmd` block.
3. **Delete the four deprecated `tc::builders::{class,qdisc,filter,action}`
   modules.** With every bin caller migrated and the deprecation
   period through one minor release, removal is safe.
4. **Wire-format unit tests** for each typed method (round-trip
   through the existing dump-side parser, same shape as the Plan
   137 PR A unit tests).

### Non-goals

1. **Retroactive typing of action attributes the existing typed
   builders don't model.** Actions like `pedit` (per-packet header
   editing) have a complex wire format. Whatever `GactAction` /
   `MirredAction` / `PoliceAction` / `VlanAction` / `SkbeditAction`
   / etc. already model is what this plan supports; new action
   kinds are out of scope.
2. **`tc(8)`-style action index pre-allocation.** The kernel
   assigns an index on `RTM_NEWACTION` if you don't pass one.
   Don't pre-allocate; let the kernel do it. Users who need a
   specific index can supply it.
3. **Cross-namespace action sharing.** Standalone shared actions
   are per-namespace; this plan doesn't try to model shared-state
   across namespaces.

---

## 2. Wire format

`tc(8)`'s standalone-action netlink shape:

```
nlmsghdr (RTM_NEWACTION / RTM_DELACTION / RTM_GETACTION)
  tcamsg (4 bytes: tca_family, _pad1, _pad2)
  attrs:
    TCA_ACT_TAB (nested)
      [1] (one entry per action — index 1, 2, … in the table)
        TCA_ACT_KIND (string: "gact" / "mirred" / ...)
        TCA_ACT_INDEX (u32, optional on add — kernel assigns if absent)
        TCA_ACT_OPTIONS (nested, kind-specific — same shape as the
                         filter-attached version)
        TCA_ACT_STATS (nested, dump-only)
```

Two key differences from filter-attached actions:

- **Top-level `TCA_ACT_TAB`**, not nested inside a filter's
  `TCA_OPTIONS`.
- **`tcamsg` header** instead of `tcmsg` — different tail-padding
  and no `tcm_ifindex` field.

The legacy `tc::builders::action::add` already builds this shape
correctly. The typed methods reuse the existing `ActionConfig`
trait's `write_options` to emit each action's kind-specific bits;
the only new code is the framing (`tcamsg` + `TCA_ACT_TAB` nesting +
the `TCA_ACT_INDEX` injection on update/delete).

---

## 3. API sketch

### 3.1. New methods on `Connection<Route>` (`crates/nlink/src/netlink/action.rs` or a new sibling module)

```rust
impl Connection<Route> {
    /// Add a standalone shared action. Returns the kernel-assigned
    /// action index (or the index you supplied if you passed one).
    pub async fn add_action(
        &self,
        action: impl ActionConfig,
    ) -> Result<u32>;

    /// Add a shared action with a specific index (advanced; the
    /// kernel rejects with `-EEXIST` if the index is taken).
    pub async fn add_action_with_index(
        &self,
        action: impl ActionConfig,
        index: u32,
    ) -> Result<()>;

    /// Delete a shared action by kind + index.
    pub async fn del_action(&self, kind: &str, index: u32) -> Result<()>;

    /// Get a single shared action by kind + index. Returns the
    /// parsed dump representation (statistics + options).
    pub async fn get_action(
        &self,
        kind: &str,
        index: u32,
    ) -> Result<ActionMessage>;

    /// Dump all shared actions of a specific kind.
    pub async fn dump_actions(&self, kind: &str) -> Result<Vec<ActionMessage>>;
}
```

`ActionMessage` is a parsed shared-action dump entry — kind +
index + attached `TcStats` + a kind-specific options blob. (We
don't need the options to round-trip back into a typed
`impl ActionConfig` here; the dump is for inspection. If users want
to "edit" an action, they construct a fresh typed builder with the
new options and call `add_action_with_index` to overwrite — the
kernel's RTM_NEWACTION semantics are upsert-by-default.)

### 3.2. `ActionMessage` shape

```rust
#[derive(Debug, Clone)]
pub struct ActionMessage {
    pub kind: String,        // "gact", "mirred", "police", ...
    pub index: u32,          // shared-action index
    pub stats: Option<TcStats>,
    pub options_raw: Vec<u8>, // kind-specific TCA_ACT_OPTIONS payload
}
```

The raw options payload is intentional: parsing each kind back
into its typed builder is a significant per-kind effort that
duplicates `tc::options::*` work. Users who need typed access to
the options can use a per-kind decoder (separate, opportunistic
follow-up).

---

## 4. `bins/tc` migration

### 4.1. Current state (as of master)

`bins/tc/src/commands/action.rs` is the **only file** in the bin
that's still 100% on the legacy path. The `#[allow(deprecated)]`
sits at the impl-block level because the existing `Self::add`,
`Self::show_actions`, `Self::del`, `Self::get` all call
`tc::builders::action::*` directly (and so does the typed
`format_protocol` helper at file scope, on the filter side — but
that's a different `#[allow]`).

### 4.2. Migration shape

After this plan ships:

```rust
// bins/tc/src/commands/action.rs
async fn add(conn: &Connection<Route>, kind: &str, params: &[String]) -> Result<()> {
    let refs: Vec<&str> = params.iter().map(String::as_str).collect();
    // Per-kind dispatch using the same parse_params shape the
    // filter side uses. New kinds: "gact", "mirred", "police",
    // "vlan", "skbedit", "nat", "tunnel_key", "connmark", "csum",
    // "sample", "ct", "pedit", "bpf", "simple".
    let action = parse_typed_action(kind, &refs)?;
    let _index = conn.add_action(action).await?;
    Ok(())
}
```

Where `parse_typed_action` is a per-kind dispatch macro mirroring
`try_typed_qdisc` / `try_typed_filter`. **Each action kind needs a
`parse_params`** — that's the bulk of the work for the bin
migration, parallel to slices 1-15. Fortunately the action types
(`GactAction` etc.) tend to be simpler than filters or qdiscs.

### 4.3. Drop the `#[allow(deprecated)]`

Once every action kind has `parse_params` and the bin dispatches
typed for all of them, the impl-block-level `#[allow(deprecated)]`
on `bins/tc/src/commands/action.rs` is gone. **The four
`tc::builders::{class,qdisc,filter,action}` modules can then be
deleted in a single follow-up commit** — all bin call sites
migrated, no library callers, deprecation period over. That's the
end of the workspace-wide typed-units rollout.

---

## 5. Phasing

| PR | Scope | Size | Unlocks |
|---|---|---|---|
| A | `Connection<Route>::add_action` + `del_action` + `get_action` + `dump_actions` + `ActionMessage` + 6-8 unit tests for the wire format | ~600 LOC | Library-side typed standalone-action CRUD; `bins/tc` migration unblocked |
| B | `parse_params` on every typed action kind (`GactAction`, `MirredAction`, `PoliceAction`, `VlanAction`, `SkbeditAction`, `NatAction`, `TunnelKeyAction`, `ConnmarkAction`, `CsumAction`, `SampleAction`, `CtAction`, `PeditAction`, `BpfAction`, `SimpleAction`) — ~14 parsers, batched in 2-3 sub-slices | ~1500 LOC across 14 parsers + ~80 unit tests | `bins/tc` migration ready |
| C | `bins/tc/src/commands/action.rs` migration: per-kind typed dispatch, drop `#[allow(deprecated)]`. Then **delete `tc::builders::{class,qdisc,filter,action}`** entirely. | ~200 LOC migration + bulk deletion | Workspace typed-units rollout closed |

PR A and PR B can ship independently; PR C requires both.

---

## 6. Files touched (estimate)

| Path | Change | Approx LOC |
|---|---|---|
| `crates/nlink/src/netlink/action.rs` | New `Connection<Route>` impl block + `ActionMessage` parser | ~600 |
| `crates/nlink/src/netlink/action.rs::tests` | Wire-format round-trip tests | ~250 |
| `crates/nlink/src/netlink/action.rs` | `parse_params` per typed action (PR B) | ~1500 |
| `crates/nlink/src/netlink/action.rs::tests` | Per-kind unit tests | ~600 |
| `bins/tc/src/commands/action.rs` | Per-kind dispatch + drop `#[allow]` | ~200 |
| `crates/nlink/src/tc/builders/{class,qdisc,filter,action}.rs` | DELETION | -1500 |
| `crates/nlink/src/tc/builders/mod.rs` | DELETION | -50 |
| `crates/nlink/src/tc/options/{cake,codel,fq_codel,fq,htb,netem,prio,sfq,tbf}.rs` | Deletion if no other callers (verify) | -800 |
| `CHANGELOG.md` | Per-PR entries | per phase |

Net: ~+2700 LOC new, ~-2350 LOC deleted = +350 LOC. The deletion
side is significant — this is the slice that finally **removes**
the deprecated surface, not just adds parallel typed paths.

---

## 7. Tests

Unit tests, all runnable as a regular user:

- **PR A**: Build a known-input message via the new typed methods,
  parse it back via the existing `tc::builders::action::dump`
  parser (which lives in the deprecated module — keep it alive
  through PR A and B; delete with PR C). Assert round-trip.
  Same shape as Plan 137 PR A's unit tests.
- **PR B**: Per-kind `parse_params` tests, same shape as the 25
  parsers from slices 1-15.
- **PR C**: Smoke test the bin's `--apply` path inline if there's
  no kernel module gating; otherwise interactive verification
  matching the qdisc/filter slice pattern.

Integration tests under `lab` feature: defer per the standard
"root-gated tests bit-rot without CI" stance (see Plan 140 in this
plan family for the CI work).

---

## 8. Open questions

1. **`add_action` return type.** The kernel returns the assigned
   index in `TCA_ACT_INDEX` of the response message. Returning
   `Result<u32>` from `add_action` requires parsing that response —
   but `Connection::send_ack` currently throws away the response
   payload after checking the ACK. Either (a) add a
   `send_request_typed` variant that captures the response body or
   (b) require callers to follow up with `dump_actions` and pick
   the new entry. Lean (a) — the response payload is small and the
   API is much cleaner.
2. **`ActionMessage::options_raw`.** Parsing each kind back into a
   typed builder is a separate ~14-parser arc. Defer; the raw
   payload is the honest baseline. Add typed decoders only when a
   user concretely asks (likely via a query subcommand on
   `bins/tc`).
3. **Deletion of `tc::builders::{class,qdisc,filter,action}` —
   semver impact.** These are public modules, deprecated since
   0.14.0. Removal in 0.15.0 is acceptable per Rust semver
   guidance for `#[deprecated]` items, but the CHANGELOG entry
   should call it out as a breaking removal so downstream
   consumers get a clear migration window. (No known downstream
   consumer today; the deprecation note already pointed at typed
   replacements.)
4. **Unique handling for `simple` action's `sdata`.** The
   `SimpleAction::new("matched-port-80")` text payload ends up in
   `TCA_ACT_OPTIONS/TCA_ACT_SIMP_DATA`. Make sure `parse_params`
   accepts it as a quoted string (or supports `sdata <token>` for
   no-spaces).

---

## 9. Definition of done

### PR A
- [ ] `Connection<Route>::{add,del,get,dump}_action` + `ActionMessage`
- [ ] At least 6 wire-format round-trip unit tests (one per major
      action kind: gact / mirred / police / vlan / skbedit)
- [ ] CHANGELOG entry under `## [Unreleased]`
- [ ] Workspace clippy clean

### PR B
- [ ] `parse_params` on all 14 typed action kinds
- [ ] ~80 unit tests across the kinds
- [ ] Doc strings document the recognised tokens and the
      "stricter than legacy" caveats per kind
- [ ] CHANGELOG entry

### PR C
- [ ] `bins/tc/src/commands/action.rs` migrated, no
      `#[allow(deprecated)]` remaining
- [ ] `tc::builders::{class,qdisc,filter,action}` modules **deleted**
- [ ] `tc::options/<kind>.rs` deleted if not referenced
      elsewhere
- [ ] Workspace `cargo machete` clean (no orphan deps left from
      the deletion)
- [ ] CHANGELOG entry calls out the **breaking removal** with a
      pointer at the per-kind typed replacements
- [ ] Cross-check Plan 138 status — if PR C of u32 hasn't landed,
      `tc::builders::filter::add_u32_options` may need to stay
      alive longer; coordinate with Plan 138 author

---

## 10. Risks

| Risk | Likelihood | Mitigation |
|---|---|---|
| Response-payload-not-captured in `send_ack` blocks `add_action` | High | Address up front by adding `send_request_typed` (PR A item 1) before any other PR A work |
| Per-kind `parse_params` work in PR B is bigger than estimated | Medium | Each action kind ships independently; PR B can be split into 2-3 sub-slices the same way slices 8-14 split the qdisc/filter parsers |
| Deletion of `tc::builders::*` breaks downstream consumers | Low | Deprecation period through 0.14.0 + clear CHANGELOG migration table; no known downstream user today |
| `pedit` action's `parse_params` is much harder than the others | Medium | Punt: leave `pedit` on the legacy path with a tracked TODO. Bin's `action` subcommand still works for `pedit` via the legacy fallback (same shape as `basic` filter on the filter side) |

End of plan.
