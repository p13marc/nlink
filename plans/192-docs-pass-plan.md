---
to: nlink maintainers
from: nlink-lab feedback `nlink-feedback.md` D1 + D4 + D5 + D6 + W7 (2026-05-30)
subject: documentation pass — VLAN-parent ordering, `InterfaceRef::Name` netns pitfall, `ApplyOptions` defaults, `summary()` vs `Display`, `Connection<P>::span()` audit
status: queued for 0.19 — low (doc-only, except W7 audit)
target version: 0.19.0
parent: (none — bundled doc work)
source: nlink-lab `nlink-feedback.md` D1, D4, D5, D6, W7
created: 2026-05-30
---

# Plan 192 — Documentation + tracing-span audit

## 1. Why this plan exists

Five documentation-shaped asks from the 158-arc feedback,
none of which materially changes nlink's behavior but each of
which would save a downstream consumer's debug cycle. Plus a
single low-effort audit (W7 — `#[tracing::instrument]` coverage
on public methods) that's small enough to bundle here rather
than splitting into its own plan. Plan 165 in the 0.16 cycle
was the same shape.

Items D2 and D3 are not in this plan — they're folded into
Plan 187 (Error API hygiene) because the rustdoc lives on
`Error::Kernel` next to the factory + `chain_walk` code being
added there.

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

### 2.4 D6 — `ConfigDiff::summary()` vs `Display`

Plan 183 (0.18) made `Display` wrap `summary()` byte-for-byte,
so the two are equivalent in output. But the naming asymmetry
confuses the user. Two ship-options:

**(a) Deprecate `summary()`.** Add `#[deprecated(since="0.19.0",
note="use Display via `format!(\"{diff}\")` or `diff.to_string()`")]`
on both `ConfigDiff::summary` and `NftablesDiff::summary`. Drop
in 0.20.

**(b) Keep both, document the equivalence.** One-line note on
`summary()`: "Equivalent to `format!(\"{}\", self)`; both share
the same renderer. Prefer the `Display` form for new code."

Pick **(a)** — the 0.19 cycle has backcompat-freedom, and the
`Display` shape is the canonical Rust idiom. Two-release
deprecation cycle (deprecated in 0.19, removed in 0.20).

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

End of plan.
