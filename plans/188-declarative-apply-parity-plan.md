---
to: nlink maintainers
from: nlink-lab feedback `nlink-feedback.md` §5 + §6 + §7 + §8 + §16 + W6 + W8 (2026-05-30)
subject: declarative apply API parity — `ConfigDiff::apply`, `ApplyOptions` builders, `apply_reconcile`, `RouteBuilder::default_v{4,6}`, `LinkChanges::Display`, idempotent `del_*`
status: queued for 0.19 — low-to-medium ergonomic bundle
target version: 0.19.0
parent: (none — single-deliverable plan)
source: nlink-lab `nlink-feedback.md` §5/§6/§7/§8/§16, W6, W8
created: 2026-05-30
---

# Plan 188 — Declarative apply API parity

## 1. Why this plan exists

Seven small ergonomic asymmetries between the RTNETLINK and
nftables declarative APIs (`NftablesConfig` got 0.16/0.17 polish
that `NetworkConfig` didn't get) plus two bundled paper-cuts.
Individually low priority; together they close the
"declarative path feels unfinished compared to nftables"
impression nlink-lab reported.

| Item | Severity | Surface |
|---|---|---|
| #5 | low | `ConfigDiff::apply(&conn, opts)` inherent method |
| #6 | low | re-export `apply::apply_diff` (mostly subsumed by #5) |
| #7 | low | `ApplyOptions::with_*` builders + `#[non_exhaustive]` |
| #8 | low | `RouteBuilder::default_v4()` / `default_v6()` |
| #16 | low | `NetworkConfig::apply_reconcile` parity with `NftablesConfig` |
| W6 | low | `LinkChanges::Display` for the diff row |
| W8 | low | `del_table_if_exists` / `del_chain_if_exists` / `del_rule_if_exists` |

## 2. The change — by sub-item

### 2.1 `ConfigDiff::apply` (#5)

```rust
// crates/nlink/src/netlink/config/diff.rs

impl ConfigDiff {
    /// Apply the pre-computed diff in-place without re-running
    /// [`NetworkConfig::compute_diff`].
    ///
    /// Mirrors [`NftablesDiff::apply`]'s shape. Use this in the
    /// chain pattern:
    ///
    /// ```ignore
    /// let diff = cfg.diff(&conn).await?;
    /// println!("{diff}");           // inspect before commit
    /// diff.apply(&conn, ApplyOptions::default()).await?;
    /// ```
    ///
    /// Equivalent to but more efficient than `cfg.apply(&conn)`
    /// when you already hold a `ConfigDiff` — the latter re-runs
    /// `compute_diff` internally, costing one extra round-trip
    /// of dump traffic.
    pub async fn apply(
        &self,
        conn: &Connection<Route>,
        opts: ApplyOptions,
    ) -> Result<ApplyResult> {
        apply::apply_diff(self, conn, opts).await
    }
}
```

#6 is now redundant — consumers don't need direct access to the
free `apply_diff` if the inherent method exists. We won't
re-export the free function; downstream code switches to the
inherent.

### 2.2 `ApplyOptions::with_*` + `#[non_exhaustive]` (#7)

```rust
// crates/nlink/src/netlink/config/apply.rs

/// Knobs that control the behavior of [`apply_diff`] /
/// [`ConfigDiff::apply`] / [`NetworkConfig::apply`].
///
/// Construct via `Default::default()` + builder setters:
///
/// ```ignore
/// let opts = ApplyOptions::default()
///     .with_dry_run(true)
///     .with_continue_on_error(false)
///     .with_purge(true);
/// ```
///
/// The builder shape matches [`NftablesConfig::ReconcileOptions`]
/// for cross-API consistency.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct ApplyOptions {
    pub dry_run: bool,
    pub continue_on_error: bool,
    pub purge: bool,
}

impl ApplyOptions {
    pub fn with_dry_run(mut self, on: bool) -> Self {
        self.dry_run = on;
        self
    }
    pub fn with_continue_on_error(mut self, on: bool) -> Self {
        self.continue_on_error = on;
        self
    }
    pub fn with_purge(mut self, on: bool) -> Self {
        self.purge = on;
        self
    }
}
```

**`#[non_exhaustive]` is a semver-major change** — pin-on-version
downstream code constructing `ApplyOptions { dry_run, continue_on_error, purge }`
literal-style breaks. Migration is mechanical (switch to the
builder). Same precedent as Plan 163's enum-lockdown sweep.

### 2.3 `RouteBuilder::default_v4` / `default_v6` (#8)

```rust
// crates/nlink/src/netlink/config/types.rs (RouteBuilder)

impl RouteBuilder {
    /// `RouteBuilder` whose destination is `0.0.0.0/0` —
    /// the IPv4 default route. Mirrors
    /// [`Ipv4Route::default_route`] (Plan 184) on the
    /// declarative path.
    pub fn default_v4() -> Self {
        Self::new("0.0.0.0/0")
            .expect("0.0.0.0/0 is a valid IPv4 CIDR")
    }

    /// `RouteBuilder` whose destination is `::/0` — the
    /// IPv6 default route.
    pub fn default_v6() -> Self {
        Self::new("::/0")
            .expect("::/0 is a valid IPv6 CIDR")
    }
}
```

Avoids the `"default"` magic-string family-inference question.

### 2.4 `NetworkConfig::apply_reconcile` (#16)

```rust
// crates/nlink/src/netlink/config/apply.rs

impl NetworkConfig {
    /// Apply this config with bounded retry on transient
    /// kernel errors. Mirrors
    /// [`NftablesConfig::apply_reconcile`].
    ///
    /// Retries on [`Error::is_busy`] / [`Error::is_try_again`]
    /// up to `opts.max_retries` times, with exponential backoff
    /// starting at `opts.backoff`.
    ///
    /// For RTNETLINK the transient-error surface is smaller
    /// than nftables (no batch-end races), but VRF table
    /// allocation, neighbor-cache pressure, and similar edges
    /// can still benefit from the retry budget.
    pub async fn apply_reconcile(
        &self,
        conn: &Connection<Route>,
        opts: ReconcileOptions,
    ) -> Result<ApplyResult> {
        // Mirror of nftables/config/apply.rs::apply_reconcile
        // for the ConfigDiff + apply_diff pair. ~40 LOC.
        ...
    }
}
```

`ReconcileOptions` already exists at `nlink::ReconcileOptions`
(re-exported in Plan 148.3 via `tc_recipe`). Reuse it.

### 2.5 `LinkChanges::Display` (W6)

```rust
// crates/nlink/src/netlink/config/diff.rs

impl std::fmt::Display for LinkChanges {
    /// Compact diff line: `"mtu 1500 → 9000, state down → up"`.
    /// Used by `ConfigDiff::Display` to render
    /// `links_to_modify` rows.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut first = true;
        let mut emit = |s: &str| -> std::fmt::Result {
            if !first {
                f.write_str(", ")?;
            }
            first = false;
            f.write_str(s)
        };
        if let Some((old, new)) = self.mtu {
            emit(&format!("mtu {old} → {new}"))?;
        }
        if let Some((old, new)) = self.state {
            emit(&format!("state {} → {}", old.as_str(), new.as_str()))?;
        }
        if let Some((old, new)) = &self.master {
            emit(&format!("master {old:?} → {new:?}"))?;
        }
        // ...for each field LinkChanges carries
        if first {
            f.write_str("(no changes)")?;
        }
        Ok(())
    }
}
```

Integrates with `ConfigDiff::Display` via
`writeln!(f, "  ~ {} ({})", name, changes)` instead of the
current `~ {name}` placeholder.

### 2.6 Idempotent `del_*_if_exists` (W8)

Three new methods on `Connection<Nftables>`:

```rust
// crates/nlink/src/netlink/nftables/connection.rs

impl Connection<Nftables> {
    /// Delete a table if it exists. Returns `Ok(true)` if the
    /// table was deleted, `Ok(false)` if it didn't exist.
    /// Unlike [`Self::del_table`], does NOT error on `ENOENT`.
    ///
    /// Saves the `let _ = conn.del_table(...).await;` ignore
    /// pattern that nearly all callers reach for.
    pub async fn del_table_if_exists(
        &self, name: &str, family: Family,
    ) -> Result<bool> {
        match self.del_table(name, family).await {
            Ok(()) => Ok(true),
            Err(e) if e.is_not_found() => Ok(false),
            Err(e) => Err(e),
        }
    }

    pub async fn del_chain_if_exists(
        &self, table: &str, name: &str, family: Family,
    ) -> Result<bool> { ... }

    pub async fn del_rule_if_exists(
        &self, table: &str, chain: &str, family: Family, handle: u64,
    ) -> Result<bool> { ... }
}
```

The behavioral contract is exactly "swallow ENOENT, propagate
everything else." Trivial.

## 3. Implementation phases

| Phase | Files | LOC |
|---|---|---|
| 1 — `ConfigDiff::apply` | `config/diff.rs` | ~12 |
| 2 — `ApplyOptions` builder + `#[non_exhaustive]` | `config/apply.rs` | ~20 |
| 3 — `RouteBuilder::default_v{4,6}` | `config/types.rs` | ~10 |
| 4 — `NetworkConfig::apply_reconcile` | `config/apply.rs` | ~50 |
| 5 — `LinkChanges::Display` | `config/diff.rs` | ~40 |
| 6 — `del_*_if_exists` | `nftables/connection.rs` | ~30 |
| 7 — Tests (see §4) | various | ~120 |
| **Total** | | **~280 LOC** |

## 4. Tests

### 4.1 Unit — `ConfigDiff::apply` equivalence

```rust
#[test]
fn diff_apply_routes_through_apply_diff() {
    // Type-check: confirm ConfigDiff::apply signature matches
    // the underlying apply_diff. Smoke-test via dry-run.
    let cfg = NetworkConfig::new();
    let conn = ...;  // mock or skip — see integration test
}
```

Real coverage is the integration test in §4.7.

### 4.2 Unit — `ApplyOptions` builders

```rust
#[test]
fn apply_options_builders_compose() {
    let opts = ApplyOptions::default()
        .with_dry_run(true)
        .with_continue_on_error(true)
        .with_purge(true);
    assert!(opts.dry_run);
    assert!(opts.continue_on_error);
    assert!(opts.purge);
}

#[test]
fn apply_options_default_is_safe() {
    let opts = ApplyOptions::default();
    assert!(!opts.dry_run);
    assert!(!opts.continue_on_error);
    assert!(!opts.purge);
}
```

### 4.3 Unit — `RouteBuilder::default_v{4,6}`

```rust
#[test]
fn default_v4_route_is_zero_zero() {
    let r = RouteBuilder::default_v4();
    assert_eq!(r.destination(), "0.0.0.0/0");
}

#[test]
fn default_v6_route_is_unspecified_slash_zero() {
    let r = RouteBuilder::default_v6();
    assert_eq!(r.destination(), "::/0");
}
```

### 4.4 Unit — `LinkChanges::Display`

```rust
#[test]
fn link_changes_display_emits_compact_diff_line() {
    let changes = LinkChanges {
        mtu: Some((1500, 9000)),
        state: Some((LinkState::Down, LinkState::Up)),
        ..Default::default()
    };
    assert_eq!(
        changes.to_string(),
        "mtu 1500 → 9000, state down → up"
    );
}

#[test]
fn link_changes_display_handles_empty_diff() {
    let changes = LinkChanges::default();
    assert_eq!(changes.to_string(), "(no changes)");
}

#[test]
fn link_changes_display_handles_single_field_change() {
    let changes = LinkChanges {
        mtu: Some((1500, 9000)),
        ..Default::default()
    };
    assert_eq!(changes.to_string(), "mtu 1500 → 9000");
}

#[test]
fn config_diff_display_uses_link_changes_display_for_modify_rows() {
    let mut diff = ConfigDiff::default();
    diff.links_to_modify.push((
        "eth0".into(),
        LinkChanges { mtu: Some((1500, 9000)), ..Default::default() },
    ));
    let rendered = diff.to_string();
    assert!(rendered.contains("eth0"));
    assert!(rendered.contains("mtu 1500 → 9000"));
}
```

### 4.5 Unit — `del_*_if_exists` behavior

These can't be true unit tests (need a kernel), but the
`Err.is_not_found()` predicate is the contract. The integration
tests cover it.

### 4.6 Integration — `del_*_if_exists` idempotence

In `crates/nlink/tests/integration/nftables_reconcile.rs`:

```rust
#[tokio::test]
async fn del_table_if_exists_is_idempotent() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("nf_tables");

    with_timeout(async {
        let ns = TestNamespace::new("del-idem")?;
        let nft = nft_in_ns(&ns)?;

        // Create then delete once — returns true.
        nft.add_table("toy", Family::Inet).await?;
        let deleted = nft.del_table_if_exists("toy", Family::Inet).await?;
        assert!(deleted, "first delete should return true");

        // Delete again — must NOT error, returns false.
        let again = nft.del_table_if_exists("toy", Family::Inet).await?;
        assert!(!again, "second delete must be Ok(false)");

        Ok(())
    })
    .await
}

#[tokio::test]
async fn del_chain_if_exists_is_idempotent() -> nlink::Result<()> {
    // Same shape: create chain, del once, del again, assert
    // the second is Ok(false).
    ...
}

#[tokio::test]
async fn del_rule_if_exists_handles_bad_handle() -> nlink::Result<()> {
    // del_rule_if_exists with a never-allocated handle must
    // be Ok(false), not Err.
    ...
}
```

### 4.7 Integration — `ConfigDiff::apply` + `apply_reconcile`

In `crates/nlink/tests/integration/network_config_apply.rs`
(file created in Plan 186):

```rust
#[tokio::test]
async fn config_diff_apply_avoids_re_dump() -> nlink::Result<()> {
    require_root!();

    let ns = TestNamespace::new("diff-apply")?;
    let conn = namespace::connection_for::<Route>(ns.name())?;

    let cfg = NetworkConfig::new().link(|b| b.dummy("dummy0"));
    let diff = cfg.diff(&conn).await?;
    diff.apply(&conn, ApplyOptions::default()).await?;

    let links = conn.get_links().await?;
    assert!(links.iter().any(|l| l.name.as_deref() == Some("dummy0")));
    Ok(())
}

#[tokio::test]
async fn apply_reconcile_retries_on_busy() -> nlink::Result<()> {
    // Synthetic-pressure shape: too narrow a window to make
    // EBUSY reproducible reliably. Smoke-test the happy path
    // instead; the retry surface is covered by the
    // NftablesConfig version of the same code.
    ...
}
```

## 5. Acceptance criteria

- [ ] `ConfigDiff::apply` inherent method (#5).
- [ ] `ApplyOptions` `#[non_exhaustive]` + `with_*` builders
      (#7).
- [ ] `RouteBuilder::default_v4()` / `default_v6()` (#8).
- [ ] `NetworkConfig::apply_reconcile` mirroring nftables
      (#16).
- [ ] `LinkChanges::Display` + `ConfigDiff::Display` uses it
      (W6).
- [ ] `Connection<Nftables>::{del_table,del_chain,del_rule}_if_exists`
      (W8).
- [ ] 8+ unit tests covering builders / display / accessors.
- [ ] 4+ integration tests covering apply equivalence,
      reconcile happy-path, del_*_if_exists idempotence.
- [ ] CHANGELOG `### Added` entries; `### Breaking changes`
      entry for the `ApplyOptions` `#[non_exhaustive]` flip.
- [ ] Migration guide entry for the breaking change.

## 6. Effort estimate

| Phase | Effort |
|---|---|
| Code (~280 LOC across 5 files) | ~3 h |
| Unit tests (~8) | ~1 h |
| Integration tests (~4) | ~1.5 h |
| CHANGELOG + migration guide | ~30 min |
| **Total** | **~6 h** |

## 7. Risks

- **`#[non_exhaustive]` on `ApplyOptions` is a real semver
  break.** The `result_large_err`-style ergonomic story
  (always construct via the builder) is the right one — the
  user-facing migration is a single search-and-replace from
  struct-literal to method-chain. Document in the migration
  guide.
- **`apply_reconcile` retries on `is_busy`/`is_try_again`** —
  if the underlying op isn't safe to retry (idempotence
  violation), repeated retries could compound. The nftables
  version handles this via `ReconcileOptions::max_retries`
  defaulting to 3; mirror that conservative cap.

## 8. Out-of-scope follow-ups

- **`ConfigDiff::summary()` vs `Display`** (D6 in feedback) —
  the maintainer asks when to prefer which. Since `Display`
  wraps `summary()` byte-for-byte (Plan 183 closed this),
  `Display` is the canonical surface and `summary()` is
  legacy. We could deprecate `summary()` here; defer to a
  follow-up to keep this plan additive-mostly.
- **`del_*_or_create_idempotent`** — different pattern, not
  asked for.

End of plan.
