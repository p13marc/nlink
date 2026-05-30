---
to: nlink maintainers
from: 0.19 second consolidation-pass — "everything in 0.19" directive + WireGuard research agent (2026-05-30)
subject: declarative `WireguardConfig` mirroring `NftablesConfig` — diff + apply + `wg syncconf` semantics + `LinkBuilder::wireguard`
status: queued for 0.19 — medium (substantial; closes the WG declarative gap from nlink-lab feedback #13)
target version: 0.19.0
parent: (none — single-deliverable plan, was previously deferred to 0.20)
source: nlink-lab `nlink-feedback.md` §13 (WireGuard half); 0.19 research agent on `wg syncconf` semantics + DefGuard `wireguard-rs` ecosystem audit
created: 2026-05-30
---

# Plan 196 — Declarative `WireguardConfig`

## 1. Why this plan exists

nlink-lab feedback #13 flagged WireGuard + VRF as missing
from the declarative path. Plan 190 ships VRF (the easy
half, an RTNETLINK link kind). The WireGuard half was
initially split out to 0.20 because peer/key config goes
through the `Wireguard` GENL family — a fundamentally
different shape than RTNETLINK link creation. Under the
0.19 "everything in 0.19" directive (2026-05-30), this
plan pulls the WG declarative coverage into the same cycle.

The research-agent audit (2026-05-30) on the WG kernel UAPI
+ `wg syncconf` semantics + the DefGuard `wireguard-rs`
crate concluded:

- The kernel's `WG_CMD_SET_DEVICE` carries semantic levers
  for reconciliation: `WGDEVICE_F_REPLACE_PEERS`,
  `WGPEER_F_REPLACE_ALLOWEDIPS`, `WGPEER_F_UPDATE_ONLY`,
  `WGPEER_F_REMOVE_ME`.
- `wg syncconf` is the canonical "merge, don't replace"
  shape — preserves runtime stats + last-handshake
  timestamps. This is the right default for reconciliation
  loops.
- Peer identity is the public key. Sort + diff by pubkey.
- No Rust crate today ships `NetworkConfig`-style WG
  reconciliation. nlink shipping this is a
  first-of-its-kind in the ecosystem.

## 2. The change

### 2.1 `WireguardConfig` + `WireguardPeerConfig`

```rust
// crates/nlink/src/netlink/genl/wireguard/config/types.rs (new)

use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;

use ipnet::IpNet;

use super::keys::PublicKey;

/// Declarative WireGuard interface configuration.
///
/// Mirrors `NftablesConfig` / `NetworkConfig` shape: diff against
/// kernel state → apply with bounded retry → reconcile.
///
/// Defaults to `wg syncconf` semantics (preserve runtime stats,
/// peers absent from this config are removed via `REMOVE_ME`
/// flag, not by wiping the device).
#[derive(Debug, Clone, Default)]
pub struct WireguardConfig {
    pub ifname: String,
    pub private_key: Option<[u8; 32]>,        // None = preserve kernel state
    pub listen_port: Option<u16>,
    pub fwmark: Option<u32>,
    pub peers: BTreeMap<PublicKey, WireguardPeerConfig>,
}

#[derive(Debug, Clone, Default)]
pub struct WireguardPeerConfig {
    pub preshared_key: Option<[u8; 32]>,
    pub endpoint: Option<SocketAddr>,
    pub persistent_keepalive: Option<u16>,
    pub allowed_ips: BTreeSet<IpNet>,  // always sent with REPLACE_ALLOWEDIPS
}
```

`BTreeMap<PublicKey, _>` + `BTreeSet<IpNet>` give us
deterministic iteration order — critical for stable diff
output and snapshot-test fixtures.

### 2.2 Builder shape

```rust
impl WireguardConfig {
    pub fn new(ifname: impl Into<String>) -> Self;
    pub fn private_key(self, k: [u8; 32]) -> Self;
    pub fn listen_port(self, port: u16) -> Self;
    pub fn fwmark(self, mark: u32) -> Self;
    pub fn peer(self, pubkey: PublicKey, build: impl FnOnce(WireguardPeerConfig) -> WireguardPeerConfig) -> Self;
}

impl WireguardPeerConfig {
    pub fn endpoint(self, addr: SocketAddr) -> Self;
    pub fn allowed_ip(mut self, net: IpNet) -> Self;
    pub fn allowed_ips(self, nets: impl IntoIterator<Item = IpNet>) -> Self;
    pub fn keepalive(self, secs: u16) -> Self;
    pub fn preshared_key(self, k: [u8; 32]) -> Self;
}
```

### 2.3 `WireguardDiff` + `apply`

```rust
// crates/nlink/src/netlink/genl/wireguard/config/diff.rs (new)

#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct WireguardDiff {
    pub ifname: String,
    pub device_changes: WireguardDeviceChanges,
    pub peers_to_add_or_update: Vec<(PublicKey, WireguardPeerConfig)>,
    pub peers_to_remove: Vec<PublicKey>,
}

#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct WireguardDeviceChanges {
    pub private_key: Option<[u8; 32]>,
    pub listen_port: Option<u16>,
    pub fwmark: Option<u32>,
}

impl WireguardConfig {
    /// Diff against current kernel state. Computes
    /// `syncconf`-style merge: peers in this config become
    /// `add_or_update`, peers in the kernel but not in this
    /// config become `remove`.
    pub async fn diff(
        &self,
        conn: &Connection<Wireguard>,
    ) -> Result<WireguardDiff> {
        let current = conn.get_device(&self.ifname).await?;
        Ok(compute_diff(self, &current))
    }
}

impl WireguardDiff {
    pub fn is_empty(&self) -> bool { ... }
    /// Render summary like `NftablesDiff::summary` /
    /// `ConfigDiff::Display`.
    pub fn summary(&self) -> String { ... }
    /// Apply via a single `WG_CMD_SET_DEVICE` carrying every
    /// peer mutation as a nested attribute.
    pub async fn apply(
        &self,
        conn: &Connection<Wireguard>,
    ) -> Result<()> { ... }
}

impl WireguardConfig {
    /// Convenience: diff + apply in one call. Matches the
    /// `NftablesConfig::apply` / `NetworkConfig::apply` shape.
    pub async fn apply(&self, conn: &Connection<Wireguard>) -> Result<()> {
        let diff = self.diff(conn).await?;
        if !diff.is_empty() { diff.apply(conn).await?; }
        Ok(())
    }

    /// Apply with bounded retry on `is_busy`/`is_try_again`
    /// — mirrors NftablesConfig::apply_reconcile + the new
    /// NetworkConfig::apply_reconcile (Plan 188).
    pub async fn apply_reconcile(
        &self,
        conn: &Connection<Wireguard>,
        opts: ReconcileOptions,
    ) -> Result<()> { ... }

    /// Force a `REPLACE_PEERS` wipe-then-add (rare; for the
    /// "this is the new ground truth, discard runtime state"
    /// case). Use `apply` for normal reconciliation.
    pub async fn apply_replace(&self, conn: &Connection<Wireguard>) -> Result<()> { ... }
}
```

### 2.3b `PublicKey` newtype + parser (idiom-pass addition)

The research agent's API sketch uses `[u8; 32]` for keys.
For the public surface use a `PublicKey` newtype with
`FromStr` (base64 — matching the `wg(8)` config format) +
`Display` impl + `From<[u8; 32]>` + `AsRef<[u8]>`:

```rust
/// A WireGuard public key (32-byte Curve25519 point).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PublicKey([u8; 32]);

impl PublicKey {
    #[inline] pub const fn from_bytes(b: [u8; 32]) -> Self { Self(b) }
    #[inline] pub fn as_bytes(&self) -> &[u8; 32] { &self.0 }
}

impl From<[u8; 32]> for PublicKey { ... }
impl FromStr for PublicKey {
    type Err = WgKeyParseError;
    /// Parse a base64-encoded 32-byte key, matching the
    /// canonical `wg(8)` config format.
    fn from_str(s: &str) -> Result<Self, Self::Err> { ... }
}
impl std::fmt::Display for PublicKey {
    /// Emit the canonical base64 form, matching what `wg(8)`
    /// writes.
    fn fmt(...) { ... }
}
```

Same newtype + impls for `PresharedKey` (also `[u8; 32]`).

### 2.3c `WireguardConfig::client(remote, our_key)` shortcut (idiom-pass addition)

The common "client connecting to one server" case is verbose
in the typed API. Add a one-call shortcut for it:

```rust
impl WireguardConfig {
    /// Quick-start constructor for the single-peer client case.
    /// Equivalent to building a config with one peer + the
    /// `wg-quick`-style defaults.
    pub fn client(
        ifname: impl Into<String>,
        our_private_key: [u8; 32],
        server_pubkey: PublicKey,
        server_endpoint: SocketAddr,
        allowed_ips: impl IntoIterator<Item = IpNet>,
    ) -> Self;
}
```

Reads as a single declarative call. Most newcomers' first
WG config is this shape. Mirrors `RouteBuilder::default_v4`
in spirit.

### 2.3d `WireguardConfig::from_wg_config(&str)` parser (idiom-pass addition)

The `wg(8)` config file format is widely used; parsing it
into a `WireguardConfig` gives consumers a migration path
from existing `wg-quick` setups:

```rust
impl WireguardConfig {
    /// Parse a `wg(8)`-format config file. Mirrors what
    /// `wg setconf <file>` would accept.
    ///
    /// ```ignore
    /// let raw = std::fs::read_to_string("/etc/wireguard/wg0.conf")?;
    /// let cfg = WireguardConfig::from_wg_config(&raw)?;
    /// cfg.apply(&conn).await?;
    /// ```
    pub fn from_wg_config(s: &str) -> Result<Self, WgConfigParseError>;
}
```

~80 LOC for an INI-style parser. Closes the loop with the
existing `wg-quick` ecosystem.

### 2.4 `Display` for `WireguardDiff`

Same shape as `NftablesDiff::Display` (Plan 183) — wraps
`summary()`. Closes the symmetry across all three
declarative diffs.

### 2.5 `LinkBuilder::wireguard()` link-half integration

Already noted in Plan 190 §1 as deferred here. Add the
declarative `LinkBuilder::wireguard()` that creates a `wg`-
kind RTNETLINK link, then expects the consumer to apply a
`WireguardConfig` against `Connection<Wireguard>` separately:

```rust
// crates/nlink/src/netlink/config/types.rs

#[non_exhaustive]
pub enum DeclaredLinkType {
    ...
    Wireguard,   // link-only; peer config via WireguardConfig
}

impl LinkBuilder {
    pub fn wireguard(self) -> Self { ... }
}
```

The split is intentional: `LinkBuilder` covers RTNETLINK
links; `WireguardConfig` covers GENL peer/key state. They
compose in a higher-level orchestrator (which nlink-lab
already has).

## 3. Implementation phases

| Phase | Files | LOC |
|---|---|---|
| 1 — Config + Peer struct + builders | new `genl/wireguard/config/types.rs` | ~150 |
| 2 — `compute_diff` (BTreeMap symmetric difference) | new `genl/wireguard/config/diff.rs` | ~120 |
| 3 — `WireguardDiff::apply` (single SET_DEVICE) | `config/apply.rs` | ~100 |
| 4 — `apply_reconcile` with ReconcileOptions | `config/apply.rs` | ~50 |
| 5 — `apply_replace` (REPLACE_PEERS flag) | `config/apply.rs` | ~30 |
| 6 — `Display` for `WireguardDiff` | `config/diff.rs` | ~40 |
| 7 — `LinkBuilder::wireguard` link half | `config/types.rs` + `config/apply.rs` | ~30 |
| 8 — Exclude runtime stats from diff | `compute_diff` | ~10 |
| 9 — Re-exports in `lib.rs` | `lib.rs` | ~5 |
| 10 — Recipe + example | new files | ~250 |
| 11 — Tests (see §4) | various | ~400 |
| **Total** | | **~1185 LOC** |

## 4. Tests

### 4.1 Unit — `compute_diff` semantics

```rust
#[test]
fn diff_empty_config_against_empty_kernel_is_noop() {
    let cfg = WireguardConfig::new("wg0");
    let kernel = WgDevice { ..Default::default() };
    let diff = compute_diff(&cfg, &kernel);
    assert!(diff.is_empty());
}

#[test]
fn diff_new_peer_becomes_add_or_update() {
    let cfg = WireguardConfig::new("wg0")
        .peer(test_pubkey(1), |p| p.endpoint("10.0.0.1:51820".parse().unwrap()));
    let kernel = WgDevice { peers: vec![], ..Default::default() };
    let diff = compute_diff(&cfg, &kernel);
    assert_eq!(diff.peers_to_add_or_update.len(), 1);
    assert_eq!(diff.peers_to_remove.len(), 0);
}

#[test]
fn diff_stale_peer_in_kernel_becomes_remove() {
    let cfg = WireguardConfig::new("wg0");  // empty
    let kernel = WgDevice {
        peers: vec![WgPeer { public_key: test_pubkey(1), .. }],
        ..Default::default()
    };
    let diff = compute_diff(&cfg, &kernel);
    assert_eq!(diff.peers_to_remove.len(), 1);
    assert_eq!(diff.peers_to_remove[0], test_pubkey(1));
}

#[test]
fn diff_allowed_ips_change_becomes_replace_allowedips() {
    // A peer with the same pubkey but different allowed_ips —
    // must be in add_or_update (the apply path sends
    // REPLACE_ALLOWEDIPS for every peer in add_or_update).
}

#[test]
fn diff_does_not_drift_on_runtime_stats() {
    // Same config; kernel has different last_handshake_time,
    // rx_bytes, tx_bytes. Diff must be empty.
    let cfg = WireguardConfig::new("wg0")
        .peer(test_pubkey(1), |p| p);
    let kernel = WgDevice {
        peers: vec![WgPeer {
            public_key: test_pubkey(1),
            last_handshake_time: SystemTime::now(),
            rx_bytes: 99999,
            tx_bytes: 99999,
            ..Default::default()
        }],
        ..Default::default()
    };
    assert!(compute_diff(&cfg, &kernel).is_empty());
}

#[test]
fn diff_idempotence_via_reapply() {
    // Apply once, diff again, second diff must be empty.
    // This is the contract that drives `apply_reconcile`.
}
```

### 4.2 Wire-shape — `apply` emits correct SET_DEVICE

```rust
#[test]
fn apply_emits_single_set_device_with_replace_allowedips_per_peer() {
    let diff = WireguardDiff {
        ifname: "wg0".into(),
        device_changes: WireguardDeviceChanges::default(),
        peers_to_add_or_update: vec![(test_pubkey(1), test_peer())],
        peers_to_remove: vec![],
    };
    let bytes = build_set_device_request(&diff);
    // Assert the request carries WGDEVICE_A_PEERS nest with
    // one nested peer, and that peer has
    // WGPEER_F_REPLACE_ALLOWEDIPS set.
    ...
}

#[test]
fn apply_emits_remove_me_flag_for_peers_to_remove() {
    // peers_to_remove must show up in the SET_DEVICE peer
    // nest with WGPEER_F_REMOVE_ME, NOT separated into a
    // different request.
}

#[test]
fn apply_replace_emits_wgdevice_f_replace_peers() {
    // The WireguardConfig::apply_replace path sets the
    // device-level REPLACE_PEERS flag.
}
```

### 4.3 Integration — root-gated round-trip

```rust
// crates/nlink/tests/integration/wireguard_declarative.rs (new file)

#[tokio::test]
async fn wireguard_config_apply_creates_device_and_peers() -> Result<()> {
    require_root!();
    nlink::require_modules!("wireguard");

    let ns = TestNamespace::new("wg-decl")?;
    // Create the wg link first via NetworkConfig + LinkBuilder::wireguard.
    let route = namespace::connection_for::<Route>(ns.name())?;
    NetworkConfig::new().link(|b| b.wireguard().name("wg0"))
        .apply(&route).await?;

    let wg = namespace::connection_for_async::<Wireguard>(ns.name()).await?;

    let cfg = WireguardConfig::new("wg0")
        .listen_port(51820)
        .peer(test_pubkey(1), |p| p
            .endpoint("10.0.0.99:51820".parse().unwrap())
            .allowed_ip("10.0.0.0/24".parse().unwrap())
            .keepalive(25));

    cfg.apply(&wg).await?;

    // Verify kernel state.
    let device = wg.get_device("wg0").await?;
    assert_eq!(device.listen_port, Some(51820));
    assert_eq!(device.peers.len(), 1);
    assert_eq!(device.peers[0].public_key, test_pubkey(1));

    Ok(())
}

#[tokio::test]
async fn wireguard_config_apply_is_idempotent() -> Result<()> {
    // The headline reconciliation guarantee.
    require_root!();
    nlink::require_modules!("wireguard");

    let cfg = ...;
    cfg.apply(&conn).await?;
    // Second apply must be no-op.
    let diff2 = cfg.diff(&conn).await?;
    assert!(diff2.is_empty(), "second apply must be zero-op");
    Ok(())
}

#[tokio::test]
async fn wireguard_config_apply_preserves_runtime_stats() -> Result<()> {
    // Apply twice with the same config; verify
    // last_handshake_time + rx/tx_bytes survive the second
    // apply (syncconf semantics, not REPLACE_PEERS).
    ...
}

#[tokio::test]
async fn wireguard_apply_replace_wipes_runtime_stats() -> Result<()> {
    // Verify the opt-in REPLACE_PEERS path actually wipes.
    ...
}

#[tokio::test]
async fn wireguard_apply_remove_stale_peer() -> Result<()> {
    // Add a peer via the kernel directly, then apply a
    // WireguardConfig that doesn't include it. Verify the
    // peer is removed via REMOVE_ME.
    ...
}
```

## 5. Acceptance criteria

- [ ] `WireguardConfig` + `WireguardPeerConfig` + builders.
- [ ] `WireguardDiff` + `Display` impl.
- [ ] `compute_diff` with `syncconf` semantics (BTreeMap
      symmetric difference) + runtime-stats exclusion.
- [ ] `apply`, `apply_reconcile`, `apply_replace` all ship.
- [ ] `LinkBuilder::wireguard()` link-half integration.
- [ ] Re-exports at the crate root.
- [ ] 6+ unit tests + 3+ wire-shape tests + 5+ root-gated
      integration tests.
- [ ] Recipe `docs/recipes/wireguard-declarative.md`.
- [ ] Example `crates/nlink/examples/wireguard/declarative.rs`.
- [ ] CHANGELOG `### Added` headline entry.
- [ ] Migration guide entry — net-new feature, no migration
      needed except "switch from imperative `set_device` to
      `WireguardConfig::apply` for the idempotence win".

## 6. Effort estimate

| Phase | Effort |
|---|---|
| Code (~1185 LOC) | ~6 h |
| Unit + wire-shape tests | ~2.5 h |
| Integration tests | ~3 h |
| Recipe + example | ~2 h |
| CHANGELOG + migration guide | ~30 min |
| **Total** | **~14 h** |

## 7. Risks

- **`compute_diff` correctness under partial config**: if the
  caller provides a `WireguardConfig` with `private_key:
  None`, the diff must NOT propose changing the kernel's
  current key. Verify in unit tests; the `None` case is
  consequential.
- **`REPLACE_ALLOWEDIPS` flag semantics**: every peer in
  `peers_to_add_or_update` must carry this flag — otherwise
  the kernel UNIONs the new allowed_ips with the old. Wire-
  shape test pins this.
- **Endpoint v4 vs v6**: kernel uses different attributes
  (`WGPEER_A_ENDPOINT_V4`/`_V6`). Apply path must dispatch.

## 8. Out-of-scope follow-ups

_None — this plan is comprehensive for 0.19._

## 9. Cross-cutting artifacts

| Artifact | Action | Notes |
|---|---|---|
| `CHANGELOG.md` `## [Unreleased]` | **add** `### Added` headline entry for `WireguardConfig` declarative coverage | Cross-reference Plan 197 (ovpn — the other GENL declarative). |
| `docs/migration_guide/0.18.0-to-0.19.0.md` | **append** `### Plan 196` section: from imperative `wg.set_device` → declarative `cfg.apply(&conn)` | The migration is opt-in; imperative API keeps working. |
| `docs/recipes/wireguard-declarative.md` (**new**) | **create** ~150 lines | Mirrors `nftables-declarative-config.md`; covers the `wg syncconf` semantic choice. |
| `docs/recipes/wireguard-mesh.md` (exists — 0.16) | **update** with declarative version alongside the existing imperative example | The existing recipe shows the imperative path; show both. |
| `docs/recipes/README.md` | **add row** for `wireguard-declarative.md` | One line. |
| `crates/nlink/examples/wireguard/declarative.rs` (**new**) | **create** ~80-line demo: 3-peer config, apply, dump, re-apply (idempotence) | Register in `Cargo.toml`. |
| `README.md` `## Library Modules` table | **update** the `Connection<Wireguard>` row mention with declarative coverage | One-line update. |
| `README.md` `## High-Level APIs` | **add** "Declarative WireGuard" sub-section | Mirror the existing "Declarative Network Configuration" sub-section shape. |
| `CLAUDE.md` | **append** in the existing declarative-config section: `WireguardConfig` follows the same diff/apply/apply_reconcile shape as `NftablesConfig` + `NetworkConfig` | Sets the pattern for future GENL declarative families. |

End of plan.
