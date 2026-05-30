---
to: nlink maintainers
from: 0.19 third consolidation-pass — Rust-idiomaticity + high-level-API audit (2026-05-30)
subject: high-level facade APIs — `nlink::watch::*`, `nlink::apply::*`, `nlink::Stack` unified declarative bundle
status: queued for 0.19 — medium (closes the "the lib lacks a one-line entry point" gap)
target version: 0.19.0
parent: composes on Plans 185, 188, 191, 196, 197, 198, 199 (all the declarative + watcher plans)
source: third consolidation-pass review of the 14-plan cycle — every plan ships a typed surface but the cross-cutting facade is missing
created: 2026-05-30
---

# Plan 200 — High-level facade APIs

## 1. Why this plan exists

The 0.19 cycle ships eight declarative or event-subscription
surfaces:

| Surface | Plan | Entry point today |
|---|---|---|
| nftables config | 157 + 180-185 | `NftablesConfig::apply(&conn)` |
| nftables events | 185 | `Connection<Nftables>::into_events_with_resync(factory)` |
| RTNETLINK config | NetworkConfig (pre-0.19) | `NetworkConfig::apply(&conn)` |
| RTNETLINK events | 191 | `Connection<Route>::into_events_with_resync(factory)` |
| WireGuard config | 196 | `WireguardConfig::apply(&conn)` |
| WireGuard events | 199 | `Connection<Wireguard>::into_events_with_resync(factory)` |
| ovpn config | 197 | `OvpnConfig::apply(&conn)` |
| nft sets | 198 | inside `NftablesConfig` |

Every entry point requires:
1. Open a `Connection<P>` (with the right protocol marker).
2. (For events) Build a factory closure.
3. (For namespaces) Wrap in `namespace::connection_for_async`.
4. Call the method.

That's 5-15 lines of boilerplate per call. The library exposes
typed primitives but doesn't expose the **canonical
one-liners** that ~90% of consumers want.

This plan adds three thin facade modules:

- `nlink::apply::*` — one-line declarative reconciliation
- `nlink::watch::*` — one-line event subscription with built-in resync
- `nlink::Stack` — unified declarative bundle covering network +
  firewall + VPN in one type

All three are pure compositional wrappers; they don't change
any existing API. They live alongside the typed surface and
give newcomers a low-friction entry point that scales to the
typed surface as needs grow.

## 2. The change

### 2.1 `nlink::apply` — one-line declarative reconciliation

```rust
// crates/nlink/src/facade/apply.rs (new)

/// Apply a network config to the host's default namespace.
///
/// One-line wrapper over
/// `Connection::<Route>::new()?.apply(cfg)`.
pub async fn network(cfg: &NetworkConfig) -> Result<ApplyResult> {
    let conn = Connection::<Route>::new()?;
    cfg.apply(&conn).await
}

/// Apply a network config to a named namespace.
pub async fn network_in_namespace(
    ns: &str,
    cfg: &NetworkConfig,
) -> Result<ApplyResult> {
    let conn = namespace::connection_for::<Route>(ns)?;
    cfg.apply(&conn).await
}

/// Apply an nftables config.
pub async fn nftables(cfg: &NftablesConfig) -> Result<()>;
pub async fn nftables_in_namespace(
    ns: &str, cfg: &NftablesConfig,
) -> Result<()>;

/// Apply a WireGuard config (kernel WG GENL family).
pub async fn wireguard(cfg: &WireguardConfig) -> Result<()>;
pub async fn wireguard_in_namespace(
    ns: &str, cfg: &WireguardConfig,
) -> Result<()>;

/// Apply an ovpn config (kernel 6.16+).
pub async fn ovpn(cfg: &OvpnConfig) -> Result<()>;
pub async fn ovpn_in_namespace(
    ns: &str, cfg: &OvpnConfig,
) -> Result<()>;
```

Each function is ~5 lines. Total ~80 LOC. Zero new types.

### 2.2 `nlink::diff` — one-line drift detection

```rust
// crates/nlink/src/facade/diff.rs (new)

pub async fn network(cfg: &NetworkConfig) -> Result<ConfigDiff>;
pub async fn network_in_namespace(ns: &str, cfg: &NetworkConfig)
    -> Result<ConfigDiff>;

pub async fn nftables(cfg: &NftablesConfig) -> Result<NftablesDiff>;
pub async fn nftables_in_namespace(ns: &str, cfg: &NftablesConfig)
    -> Result<NftablesDiff>;

pub async fn wireguard(cfg: &WireguardConfig) -> Result<WireguardDiff>;
pub async fn wireguard_in_namespace(ns: &str, cfg: &WireguardConfig)
    -> Result<WireguardDiff>;

pub async fn ovpn(cfg: &OvpnConfig) -> Result<OvpnDiff>;
pub async fn ovpn_in_namespace(ns: &str, cfg: &OvpnConfig)
    -> Result<OvpnDiff>;
```

Pair with `apply::*` — diff first, render, then apply if
non-empty.

### 2.3 `nlink::watch` — one-line event subscription with built-in resync

```rust
// crates/nlink/src/facade/watch.rs (new)

/// Watch RTNETLINK changes in the host namespace.
///
/// Returns a `Stream<Item = Result<ResyncedEvent<RouteEvent>>>`
/// with ENOBUFS recovery built in. Equivalent to:
///
/// ```ignore
/// let conn = Connection::<Route>::new()?;
/// let factory = Arc::new(|| Box::pin(async {
///     Connection::<Route>::new()
/// }) as _);
/// conn.into_events_with_resync(factory)?
/// ```
pub fn route_changes() -> Result<impl Stream<Item = Result<ResyncedEvent<RouteEvent>>>>;

/// Watch RTNETLINK changes inside a named namespace.
pub fn route_changes_in_namespace(ns: &str)
    -> Result<impl Stream<Item = Result<ResyncedEvent<RouteEvent>>>>;

/// Watch nftables ruleset mutations.
pub fn nftables_changes()
    -> Result<impl Stream<Item = Result<ResyncedEvent<NftablesEvent>>>>;
pub fn nftables_changes_in_namespace(ns: &str)
    -> Result<impl Stream<Item = Result<ResyncedEvent<NftablesEvent>>>>;

/// Watch WireGuard peer + handshake events.
pub fn wireguard_changes()
    -> Result<impl Stream<Item = Result<ResyncedEvent<WireguardEvent>>>>;
pub fn wireguard_changes_in_namespace(ns: &str)
    -> Result<impl Stream<Item = Result<ResyncedEvent<WireguardEvent>>>>;
```

Each is ~10 lines (open connection + build factory + return
the resync stream). Total ~120 LOC.

### 2.4 `nlink::Stack` — unified declarative bundle

```rust
// crates/nlink/src/facade/stack.rs (new)

/// A unified bundle of declarative configs spanning multiple
/// protocols. Lets consumers manage network + firewall + VPN
/// from one type without manually orchestrating per-protocol
/// `apply` calls in the right order.
///
/// Apply order: links + addresses + routes (NetworkConfig) →
/// firewall (NftablesConfig) → VPN (WireGuard / ovpn).
/// This is the natural dependency direction: rules reference
/// interfaces, VPN peers route through configured links.
#[derive(Debug, Clone, Default)]
pub struct Stack {
    pub network: Option<NetworkConfig>,
    pub nftables: Option<NftablesConfig>,
    pub wireguard: Option<WireguardConfig>,
    pub ovpn: Option<OvpnConfig>,
}

impl Stack {
    pub fn new() -> Self;

    pub fn network(self, cfg: NetworkConfig) -> Self;
    pub fn nftables(self, cfg: NftablesConfig) -> Self;
    pub fn wireguard(self, cfg: WireguardConfig) -> Self;
    pub fn ovpn(self, cfg: OvpnConfig) -> Self;

    /// Apply every set layer in dependency order.
    pub async fn apply(&self) -> Result<StackApplyReport>;
    pub async fn apply_in_namespace(&self, ns: &str)
        -> Result<StackApplyReport>;

    /// Diff every set layer against current kernel state.
    pub async fn diff(&self) -> Result<StackDiff>;
    pub async fn diff_in_namespace(&self, ns: &str) -> Result<StackDiff>;
}

/// Per-layer diff outcome.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct StackDiff {
    pub network: Option<ConfigDiff>,
    pub nftables: Option<NftablesDiff>,
    pub wireguard: Option<WireguardDiff>,
    pub ovpn: Option<OvpnDiff>,
}

impl StackDiff {
    pub fn is_empty(&self) -> bool;
    pub fn summary(&self) -> String;     // unified, layered
}

impl std::fmt::Display for StackDiff { ... }

/// Aggregated apply outcome — one `ApplyResult` per layer.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct StackApplyReport {
    pub network: Option<ApplyResult>,
    pub nftables: Option<()>,        // NftablesConfig::apply returns ()
    pub wireguard: Option<()>,
    pub ovpn: Option<()>,
    pub total_changes: usize,
}
```

The `Stack` shape closes the loop on nlink-lab's own
`TopologyDiff` envelope — `Stack` is the upstream version of
the same idea.

### 2.5 `nlink::watch::Multi` — namespace-wide unified watcher

Optional bonus: a single `Stream` that yields events from
ALL THREE protocols at once.

```rust
// crates/nlink/src/facade/watch.rs

#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum NamespaceEvent {
    Route(RouteEvent),
    Nftables(NftablesEvent),
    Wireguard(WireguardEvent),
}

pub fn namespace(ns: &str)
    -> Result<impl Stream<Item = Result<ResyncedEvent<NamespaceEvent>>>>;
```

Uses `StreamMap` to merge the three per-protocol streams. The
factory pattern threads through correctly: one ENOBUFS in any
of the three triggers a per-protocol resync; markers are
emitted per-protocol via the variant.

## 3. Implementation phases

| Phase | Files | LOC |
|---|---|---|
| 1 — `nlink::apply` module + 8 functions | new `facade/apply.rs` | ~80 |
| 2 — `nlink::diff` module + 8 functions | new `facade/diff.rs` | ~80 |
| 3 — `nlink::watch` module + 6 functions | new `facade/watch.rs` | ~120 |
| 4 — `Stack` + `StackDiff` + `StackApplyReport` | new `facade/stack.rs` | ~250 |
| 5 — `nlink::watch::namespace` (Multi) + `NamespaceEvent` | `facade/watch.rs` | ~150 |
| 6 — Re-exports in `lib.rs` | `lib.rs` | ~30 |
| 7 — Recipe + example | new files | ~250 |
| 8 — Tests (see §4) | various | ~300 |
| **Total** | | **~1260 LOC** |

## 4. Tests

### 4.1 Integration — `apply::network_in_namespace` round-trip

```rust
#[tokio::test]
async fn apply_network_in_namespace_creates_link() -> Result<()> {
    require_root!();
    let ns = TestNamespace::new("facade-apply")?;
    let cfg = NetworkConfig::new().link(|b| b.dummy("d0"));
    nlink::apply::network_in_namespace(ns.name(), &cfg).await?;

    // Verify via the typed surface.
    let conn = namespace::connection_for::<Route>(ns.name())?;
    let links = conn.get_links().await?;
    assert!(links.iter().any(|l| l.name.as_deref() == Some("d0")));
    Ok(())
}

#[tokio::test]
async fn apply_nftables_diff_then_apply_paths_match() -> Result<()> {
    // The diff-then-apply convenience should produce the
    // same kernel state as the direct apply.
    let cfg = NftablesConfig::new()...;
    let diff = nlink::diff::nftables_in_namespace(ns.name(), &cfg).await?;
    assert!(!diff.is_empty());
    nlink::apply::nftables_in_namespace(ns.name(), &cfg).await?;
    let diff_after = nlink::diff::nftables_in_namespace(ns.name(), &cfg).await?;
    assert!(diff_after.is_empty(), "post-apply diff must be empty");
    Ok(())
}
```

### 4.2 Integration — `Stack::apply_in_namespace` end-to-end

```rust
#[tokio::test]
async fn stack_apply_orchestrates_all_three_layers() -> Result<()> {
    require_root!();
    nlink::require_modules!("nf_tables", "wireguard");
    let ns = TestNamespace::new("stack-apply")?;

    let stack = nlink::Stack::new()
        .network(NetworkConfig::new()
            .link(|b| b.dummy("d0"))
            .link(|b| b.wireguard().name("wg0")))
        .nftables(NftablesConfig::new()
            .table("filter", Family::Inet, |t| t
                .chain("input", |c| c.hook(Hook::Input)...)))
        .wireguard(WireguardConfig::new("wg0")
            .listen_port(51820));

    let report = stack.apply_in_namespace(ns.name()).await?;
    assert!(report.network.unwrap().changes_made > 0);
    assert!(report.nftables.is_some());
    assert!(report.wireguard.is_some());

    // Re-apply must be no-op.
    let report2 = stack.apply_in_namespace(ns.name()).await?;
    assert_eq!(report2.total_changes, 0, "re-apply must be idempotent");
    Ok(())
}

#[tokio::test]
async fn stack_diff_aggregates_per_layer() -> Result<()> { ... }
```

### 4.3 Integration — `watch::namespace` unified stream

```rust
#[tokio::test(flavor = "multi_thread")]
async fn namespace_watcher_yields_events_from_all_protocols() -> Result<()> {
    require_root!();
    nlink::require_modules!("nf_tables", "wireguard");

    let ns = TestNamespace::new("multi-watch")?;
    let mut events = nlink::watch::namespace(ns.name())?;

    // Mutate from each protocol.
    tokio::spawn(async move {
        // 1. Add a dummy via RTNETLINK
        // 2. Add an nft table
        // 3. Add a WG peer
    });

    // Drain the stream; assert we see at least one event from
    // each protocol.
    let mut saw_route = false;
    let mut saw_nft = false;
    let mut saw_wg = false;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while tokio::time::Instant::now() < deadline {
        if let Some(evt) = events.next().await {
            match evt? {
                ResyncedEvent::Event(NamespaceEvent::Route(_)) => saw_route = true,
                ResyncedEvent::Event(NamespaceEvent::Nftables(_)) => saw_nft = true,
                ResyncedEvent::Event(NamespaceEvent::Wireguard(_)) => saw_wg = true,
                _ => {}
            }
        }
        if saw_route && saw_nft && saw_wg { break; }
    }
    assert!(saw_route && saw_nft && saw_wg);
    Ok(())
}
```

### 4.4 Unit — `Stack` builder + diff aggregation

```rust
#[test]
fn stack_builder_carries_each_layer() {
    let stack = nlink::Stack::new()
        .network(NetworkConfig::new())
        .nftables(NftablesConfig::new())
        .wireguard(WireguardConfig::default());
    assert!(stack.network.is_some());
    assert!(stack.nftables.is_some());
    assert!(stack.wireguard.is_some());
    assert!(stack.ovpn.is_none());
}

#[test]
fn stack_diff_is_empty_only_when_all_layers_empty() { ... }
```

## 5. Acceptance criteria

- [ ] `nlink::apply::{network, nftables, wireguard, ovpn}` +
      `*_in_namespace` variants (8 functions).
- [ ] `nlink::diff::*` mirror (8 functions).
- [ ] `nlink::watch::{route_changes, nftables_changes,
      wireguard_changes}` + `*_in_namespace` (6 functions).
- [ ] `nlink::watch::namespace` unified multi-protocol stream.
- [ ] `nlink::Stack` + `StackDiff` + `StackApplyReport` +
      `Display` impl.
- [ ] 3+ integration tests (round-trip, idempotence, unified
      watcher).
- [ ] 2+ unit tests (Stack builder + diff aggregation).
- [ ] Recipe `docs/recipes/quickstart-stack.md` — the one-pager
      newcomer recipe.
- [ ] Example `crates/nlink/examples/facade/quickstart.rs`.
- [ ] CHANGELOG `### Added` headline entry.

## 6. Effort estimate

| Phase | Effort |
|---|---|
| Code (~1260 LOC across 4 files) | ~6 h |
| Integration tests | ~3 h |
| Unit tests | ~1 h |
| Recipe + example | ~2 h |
| CHANGELOG + migration guide | ~30 min |
| **Total** | **~12.5 h** |

## 7. Risks

- **Multi-protocol watcher merge complexity**: the StreamMap
  approach is right, but per-protocol ENOBUFS handling must
  stay independent — one protocol's resync MUST NOT block
  the others. Verify the integration test covers this.
- **`Stack::apply` ordering**: the dependency order
  (network → firewall → VPN) is opinionated. Some consumers
  might want to override (e.g., create VPN tunnel before
  firewall). Add `Stack::apply_in_order(layers: &[Layer])`
  as an out-of-scope follow-up if signal surfaces.
- **`Stack::diff` partial mutations**: if `apply` errors
  midway, partial state is left in the kernel. Document
  clearly; the `StackApplyReport` records which layers
  succeeded.

## 8. Out-of-scope follow-ups

- **Per-namespace `Stack` builder** (`Stack::for_namespace(ns)`)
  — could simplify the `_in_namespace` boilerplate further.
  Defer until consumer signal.
- **`Stack::watch()`** — apply this stack + watch for drift +
  auto-reconcile. Reconciliation-loop pattern, substantial
  scope; defer to its own plan.

## 9. Cross-cutting artifacts

| Artifact | Action | Notes |
|---|---|---|
| `CHANGELOG.md` `## [Unreleased]` | **add** `### Added` headline entry for `nlink::{apply,diff,watch,Stack}` facade modules | Big newcomer-experience headline. |
| `docs/migration_guide/0.18.0-to-0.19.0.md` | **append** `### Plan 200` section | Pure additive; encourages migrating from boilerplate to facade. |
| `docs/recipes/quickstart-stack.md` (**new**) | **create** ~200 lines — the one-pager newcomer recipe | Show the `Stack` pattern as the canonical way to manage a host. |
| `docs/recipes/README.md` | **add row** for `quickstart-stack.md` AND mark it the **recommended starting point** | Promote up-front; newcomers shouldn't have to read 17 recipes. |
| `crates/nlink/examples/facade/quickstart.rs` (**new**) | **create** ~100-line demo using `Stack` + `watch::namespace` | Register in `Cargo.toml`. |
| `README.md` `## Quick Start` section | **update** to use `nlink::Stack` + `nlink::apply` shapes | Replace the existing per-API examples — facade is the new front door. |
| `README.md` `## High-Level APIs` section | **add** "Facade modules" as the FIRST sub-section | Reorder so the high-level API is what users see first. |
| `CLAUDE.md` | **append** a "## Facade modules — the one-line API" section under the existing Project Overview | Document that the typed surface stays the canonical layer; facades are convenience-only. |

End of plan.
