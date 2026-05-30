---
to: nlink maintainers
from: nlink-lab feedback `nlink-feedback.md` D1 + D4 + D5 + W7 (2026-05-30) + 0.19 consolidation-pass (D6 moved out, CLAUDE.md namespace-safety spec added)
subject: documentation pass — VLAN-parent ordering, `InterfaceRef::Name` netns pitfall, `ApplyOptions` defaults, `Connection<P>::span()` audit, CLAUDE.md namespace-safety spec
status: queued for 0.19 — low (doc-only, except W7 audit)
target version: 0.19.0
parent: (none — bundled doc work)
source: nlink-lab `nlink-feedback.md` D1, D4, D5, W7 (D6 folded into Plan 188); 0.19 consolidation-pass bug-hunt added CLAUDE.md namespace-safety spec
created: 2026-05-30 (consolidated same day)
---

# Plan 192 — Documentation + tracing-span audit + namespace-safety spec

## 1. Why this plan exists

Four documentation-shaped asks from the 158-arc feedback,
none of which materially changes nlink's behavior but each of
which would save a downstream consumer's debug cycle. Plus a
single low-effort audit (W7 — `#[tracing::instrument]` coverage
on public methods) and a CLAUDE.md spec section (from the
0.19 bug-hunt's namespace-safety finding) that are small
enough to bundle here. Plan 165 in the 0.16 cycle was the
same shape.

Items moved out during the 0.19 consolidation pass:
- **D2 and D3** → folded into Plan 187 (Error API hygiene)
  because the rustdoc lives on `Error::Kernel` next to the
  factory + `chain_walk` code being added there.
- **D6** (deprecate `summary()`) → folded into Plan 188
  (Declarative apply parity) because the deprecation is
  applied to the same diff types Plan 188 already touches.

## 2. The changes

### 2.1 D1 — VLAN-parent ordering caveat on `NetworkConfig::link`

```rust
// crates/nlink/src/netlink/config/types.rs (NetworkConfig::link)

/// Append a link declaration to this `NetworkConfig`.
///
/// ...
///
/// # Ordering for parent-dependent kinds
///
/// `LinkBuilder` kinds with a parent dependency — VLAN
/// (parent), MACVLAN (parent), VXLAN (underlay_dev), bond
/// slaves via `.master(...)`, VRF members via `.master(...)`
/// — must be declared **after** their parents in the same
/// `NetworkConfig` when both are new.
///
/// `compute_diff` performs a topological sort over the
/// `links_to_add` set (Plan 186) so HashMap-built configs
/// that declare children before parents get reordered
/// automatically. Externally-existing parents (already in
/// the kernel) are matched by ifindex via netlink at apply
/// time and don't need to be in the config.
///
/// # Example
///
/// ```ignore
/// // Order is canonicalized by compute_diff regardless of
/// // how you declared them:
/// let cfg = NetworkConfig::new()
///     .link(|b| b.vlan("eth0.42", "eth0", 42))   // child first
///     .link(|b| b.dummy("eth0"));                // parent second
/// // Topo-sort places eth0 before eth0.42.
/// ```
pub fn link(...) -> Self { ... }
```

This is **conditional on Plan 186**'s topo-sort shipping. If
Plan 186 ends up not landing the topo-sort (e.g. the root
cause turns out to be different), reword to "must be
declared before their children" and drop the example.

### 2.2 D4 — `InterfaceRef::Name` namespace correctness

The current docstrings everywhere say `with_parent_index` is
"the namespace-safe variant that avoids reading from
/sys/class/net/." Per audit (Plan 186 §1), the name-based
variant ALSO goes through netlink (not sysfs); the sysfs
path is only in `util::ifname::name_to_index`, which is used
by the `bins/` CLI tools.

So the docstring is misleading. Two fix options:

**(a)** Reword the existing docstrings everywhere — about ~12
sites — to drop the "avoids reading from /sys/class/net/"
claim and just say "takes a kernel ifindex directly, useful
when the caller already has it (e.g. just-created link)."

**(b)** Add a single shared docstring section to the parent
`LinkBuilder` documentation explaining the
`InterfaceRef::Name` vs `Index` trade-off in one place (CLAUDE.md
already has this — port the same paragraph into the public
rustdoc).

Pick **(b)** + lightly trim (a). The 12 individual docstrings
become one-liners pointing at the shared section.

### 2.3 D5 — `ApplyOptions::default()` semantics

```rust
// crates/nlink/src/netlink/config/apply.rs (after ApplyOptions struct)

/// # Default semantics
///
/// `ApplyOptions::default()` produces conservative defaults:
///
/// - `dry_run: false` — operations actually run against the
///   kernel.
/// - `continue_on_error: false` — the first error propagates
///   as `Err`, halting further ops. Partially-applied state
///   is left in the kernel.
/// - `purge: false` — removals (links / addresses / routes
///   present in the kernel but absent from the config) are
///   skipped, not propagated as deletions.
///
/// Override individual knobs via the builder methods:
///
/// ```ignore
/// let opts = ApplyOptions::default()
///     .with_dry_run(true);
/// ```
```

Folds with Plan 188 §2.2 (the `with_*` builder additions); we
ship both together.

### 2.4 D6 — moved to Plan 188

The deprecation of `ConfigDiff::summary` / `NftablesDiff::summary`
moved to Plan 188 §2.6 during the 0.19 consolidation pass —
Plan 188 already touches these types via the new
`ConfigDiff::apply` inherent method, so bundling the
deprecation there avoids cross-plan coordination.

### 2.5 W7 — `#[tracing::instrument]` audit on public `Connection<P>` methods

Run a scripted audit:

```bash
# crates/nlink/src/netlink/connection.rs
grep -B1 "pub async fn\|pub fn" connection.rs | grep -A1 "pub" \
  | grep -B1 "fn " | awk '/tracing::instrument/{ok=1} /pub.*fn/{
      if (!ok) print NR ": " $0; ok=0
    }'
```

…or the Rust-tooling equivalent. The script lists every
`pub fn` / `pub async fn` on Connection<P> that lacks a
`#[tracing::instrument]` attribute. Walk the output, add the
attribute (with `level = "debug"` + `skip_all` + the method-
name field), commit.

Expected output: ~15-20 methods that grew without spans
across cycles. Probable suspects:
- Several `*_by_index` variants where the `_by_name` got the
  attribute but the `_by_index` didn't
- Some recently-added methods like `set_rcvbuf` (Plan 185)
- The `Connection<P>::events` / `into_events` family

The attribute is `~3 lines per method`. Total ~50 LOC.

### 2.6 D2 + D3 — folded into Plan 187

Listed for completeness; the rustdoc lives in `error.rs` next
to the `Error::Kernel` variant + the `from_errno_ext_ack`
factory. Plan 187 handles both.

### 2.7 CLAUDE.md namespace-safety spec (consolidation-pass addition)

The 0.19 bug-hunt agent surfaced that `util::ifname` reads
`/sys/class/net/` and is namespace-unsafe when called from
threads bound to a non-host netns. The risk is currently
documented per-method in `link.rs` (~12 "namespace-safe
variant" docstrings — see D4 above for the cleanup), but
there's no centralized spec.

Add a CLAUDE.md section under the existing namespace-safety
strategic section (Plan 155.4):

```markdown
### `util::ifname` sysfs reads — namespace policy

`util::ifname::{name_to_index, index_to_name, list_interfaces}`
read from `/sys/class/net/` in the **calling process's mount
namespace**. They are only used by the `bins/` CLI tools and
never by internal library paths (audit 2026-05-30, Plan 186 §1).

For library code touching foreign netns, the policy is:

1. Use `Connection::get_link_by_name` (netlink-based, ifindex
   resolved through `RTM_GETLINK`).
2. Or use the `_by_index` API variants and pre-resolve the
   ifindex via the connection.

`util::ifname` will return a Future kernel ABI change.
Internal callers that drift back to sysfs must be flagged
in code review — see `scripts/audit-sysfs-in-lib.sh`.
```

Plus ship the audit script (~30 LOC bash):

```bash
#!/usr/bin/env bash
# scripts/audit-sysfs-in-lib.sh
# Fails CI if any /sys/class/net/ or /proc/sys/ read appears
# in crates/nlink/src/netlink/ outside the explicitly-allowed
# files (sysctl.rs is the documented exception).
set -euo pipefail
ALLOWED=(crates/nlink/src/netlink/sysctl.rs)
... grep + diff ...
```

Add the script to the CI workflow as a new audit gate
matching the existing "audit example registration" shape.

## 3. Implementation phases

| Phase | Files | LOC |
|---|---|---|
| 1 — D1: NetworkConfig::link rustdoc | `config/types.rs` | ~20 lines |
| 2 — D4: shared "InterfaceRef trade-offs" doc + 12 docstring trims | `link.rs` | ~25 lines |
| 3 — D5: ApplyOptions::default semantics doc | `config/apply.rs` | ~15 lines |
| 4 — D6: `#[deprecated]` on `summary()` × 2 | 2 files | ~6 lines |
| 5 — W7: tracing-span audit + additions | `connection.rs` + per-method | ~50 lines |
| 6 — Tests (see §4) | minimal | ~30 |
| **Total** | | **~146 LOC** |

## 4. Tests

### 4.1 W7 — verify span coverage doesn't regress

The CLAUDE.md "Observability" section commits us to spans on
every Connection method. After landing W7's audit, add a CI
gate or test that asserts the coverage stays at 100%:

```bash
# scripts/audit-tracing-instrument.sh (new)
#
# Fails CI if any `pub fn` or `pub async fn` on Connection<P>
# in crates/nlink/src/netlink/ lacks #[tracing::instrument].
# Plan 192 §2.5 baseline; future additions are caught here.

set -euo pipefail
... awk-script ...
```

Wire into the existing `audit example registration` workflow
shape — one extra step.

### 4.2 D6 — `#[deprecated]` test

```rust
#[test]
#[allow(deprecated)]
fn summary_still_works_with_deprecation_warning() {
    let diff = ConfigDiff::default();
    let s = diff.summary();
    assert_eq!(s, diff.to_string());
}
```

Round-trip assertion: `summary()` still produces the same
string as `Display`. The `#[allow(deprecated)]` is the price
of testing a deprecated method.

### 4.3 No integration tests required

This is doc + tracing work, no behavioral surface.

## 5. Acceptance criteria

- [ ] D1: `NetworkConfig::link` rustdoc paragraph about
      parent ordering, cross-referencing Plan 186's topo-sort.
- [ ] D4: shared `InterfaceRef` trade-offs documentation
      section + 12 misleading docstrings trimmed.
- [ ] D5: `ApplyOptions::default()` semantics documented next
      to the struct definition.
- [ ] D6: `#[deprecated]` on `ConfigDiff::summary` +
      `NftablesDiff::summary` with `since="0.19.0"`.
- [ ] W7: `#[tracing::instrument]` added to every public
      Connection method that lacked one.
- [ ] W7 CI gate (`scripts/audit-tracing-instrument.sh`) added
      to the workflow.
- [ ] 1 deprecation-still-works unit test + 1 W7 audit.
- [ ] CHANGELOG entries; migration guide for the
      `#[deprecated]` and any reworded docstrings worth
      noting.

## 6. Effort estimate

| Phase | Effort |
|---|---|
| D1 + D4 + D5 rewords | ~1 h |
| D6 deprecation + test | ~30 min |
| W7 audit script + additions | ~2 h |
| CI gate | ~30 min |
| CHANGELOG + migration guide | ~30 min |
| **Total** | **~4.5 h** |

## 7. Risks

- **Deprecating `summary()` is a downstream signal**.
  Consumers will see compile warnings; some will migrate, some
  will sprinkle `#[allow(deprecated)]`. Both are acceptable.
  Set `since="0.19.0"` so the warning is dated.
- **W7 audit might surface methods where the
  `#[tracing::instrument]` doesn't compose with an existing
  `#[cfg_attr]` or `#[cfg(feature = ...)]`** — needs per-
  method care. Budget +1 h if the audit hits this.
- **The "shared `InterfaceRef` trade-offs" documentation
  section** has to land somewhere reachable. Put it on
  `InterfaceRef` itself (cleanest), with a one-line link from
  each `_by_name` / `_by_index` method docstring back to it.

## 8. Out-of-scope follow-ups

- **Universal `#[tracing::instrument]` on non-Connection
  types** — TC, namespace, ConnectionPool. Could be a Plan
  192b if the W7 audit's CI gate stays narrow to Connection;
  expand the gate later when there's a desire.
- **`error.rs` rustdoc additions** — folded into Plan 187,
  not duplicated here.
- **Recipe revisions** — the recipes were last sweep at 0.16;
  another sweep might be worthwhile but isn't in feedback.
  Defer to its own plan when requested.

## 9. Cross-cutting artifacts

| Artifact | Action | Notes |
|---|---|---|
| `CHANGELOG.md` `## [Unreleased]` | **add** `### Changed` (docstring sweep, W7 tracing audit) + `### Added` (namespace-safety CI gate) | Brief; this plan is doc-shaped. |
| `docs/migration_guide/0.18.0-to-0.19.0.md` | **append** `### Plan 192 — doc additions` section | Nothing user-actionable except W7 (no public API change); just lists the doc improvements. |
| `docs/observability.md` (exists) | **update** with the W7 CI gate description + the new audit script path | Plan 192 is the natural moment — the observability doc is where the tracing convention lives. |
| `CLAUDE.md` | **append** the new "## util::ifname sysfs reads — namespace policy" section under the existing namespace-safety strategic section (Plan 155.4) | Per §2.7 of this plan; ~25 lines. |
| `scripts/audit-tracing-instrument.sh` (**new**) | **create** | Per §2.5. Bash awk-script; ~30 lines. |
| `scripts/audit-sysfs-in-lib.sh` (**new**) | **create** | Per §2.7. Bash grep-script; ~25 lines. |
| `.github/workflows/rust.yml` | **add 2 jobs** — `audit tracing-instrument coverage` + `audit sysfs reads in lib` | Mirrors the existing `audit example registration` shape. |

End of plan.
