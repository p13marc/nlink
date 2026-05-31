---
to: nlink maintainers
from: 0.19 second consolidation-pass + ovpn GENL research agent (2026-05-30)
subject: ovpn GENL family — full imperative + declarative `OvpnConfig` (kernel 6.16+)
status: queued for 0.19 — medium (substantial; new GENL family + declarative wrapper)
target version: 0.19.0
parent: (none — was previously deferred to 0.20)
source: kernel 6.16 ovpn netlink spec + 0.19 research agent on OpenVPN 2.7 DCO + ovpn-dco-cli
created: 2026-05-30
---

# Plan 197 — Declarative ovpn (OpenVPN data-channel offload)

## 1. Why this plan exists

Plan 190 §2.3b shipped the ovpn LINK half (the kernel
`IFLA_INFO_KIND = "ovpn"` RTNETLINK side). The GENL family
that controls peers + cipher keys was initially deferred to
0.20. Under the 0.19 "everything in 0.19" directive
(2026-05-30), this plan pulls the full ovpn GENL coverage
into the cycle.

The research-agent audit (2026-05-30) on the kernel 6.16
ovpn netlink spec concluded:

- 11 GENL commands covering peers + keys + multicast
  notifications.
- Multi-peer (server-mode) is supported; per-peer UDP fd
  passing required.
- AEAD-only ciphers: AES-GCM + ChaCha20-Poly1305.
- TLS handshake stays in OpenVPN 2.7 userspace; the kernel
  side accepts pre-derived AEAD keys via netlink.
- No Rust crate today covers ovpn declaratively; nlink would
  be first.

## 2. The change

Two-tier scope, both in this plan:

### 2.1 Imperative `Connection<Ovpn>` (foundation)

Following the nlink-macros `#[genl_family]` pattern (Plan
154), build a full imperative wrapper for the 11 commands +
the multicast group.

```rust
// crates/nlink/src/netlink/genl/ovpn/mod.rs (new)

#[genl_family]
pub struct Ovpn;

impl Connection<Ovpn> {
    pub async fn new_iface(&self, ifname: &str, mode: OvpnMode) -> Result<()>;
    pub async fn del_iface(&self, ifname: &str) -> Result<()>;

    pub async fn peer_new(&self, ifindex: u32, peer: OvpnPeer) -> Result<()>;
    pub async fn peer_set(&self, ifindex: u32, peer: OvpnPeer) -> Result<()>;
    pub async fn peer_get(&self, ifindex: u32, peer_id: u32) -> Result<OvpnPeer>;
    pub async fn peer_dump(&self, ifindex: u32) -> Result<Vec<OvpnPeer>>;
    pub async fn peer_del(&self, ifindex: u32, peer_id: u32) -> Result<()>;

    pub async fn key_new(&self, ifindex: u32, key: OvpnKey) -> Result<()>;
    pub async fn key_get(&self, ifindex: u32, peer_id: u32, slot: OvpnKeySlot)
        -> Result<OvpnKeyMetadata>;
    pub async fn key_swap(&self, ifindex: u32, peer_id: u32) -> Result<()>;
    pub async fn key_del(&self, ifindex: u32, peer_id: u32, slot: OvpnKeySlot)
        -> Result<()>;

    /// Attach the per-peer UDP socket fd. Server mode passes
    /// one fd per peer; client mode passes one fd total.
    pub async fn attach_socket(&self, ifindex: u32, peer_id: u32, fd: RawFd)
        -> Result<()>;
}
```

Multicast group: `subscribe(&[OvpnGroup::All])` for
`PEER_DEL_NTF`, `KEY_SWAP_NTF`, `PEER_FLOAT_NTF`.

### 2.2 Declarative `OvpnConfig`

```rust
// crates/nlink/src/netlink/genl/ovpn/config/types.rs (new)

#[derive(Debug, Clone, Default)]
pub struct OvpnConfig {
    pub ifname: String,
    pub mode: OvpnMode,                              // Client or Server
    pub peers: BTreeMap<u32 /* peer_id */, OvpnPeerConfig>,
}

#[derive(Debug, Clone, Default)]
pub struct OvpnPeerConfig {
    pub remote: Option<SocketAddr>,
    pub local: Option<SocketAddr>,
    pub vpn_ipv4: Option<Ipv4Addr>,
    pub vpn_ipv6: Option<Ipv6Addr>,
    pub keepalive: Option<OvpnKeepalive>,
    pub keys: BTreeMap<OvpnKeySlot, OvpnKeyConfig>,  // Primary + Secondary
}

#[derive(Debug, Clone)]
pub struct OvpnKeyConfig {
    pub key_id: u32,
    pub cipher: OvpnCipher,                          // AesGcm | Chacha20Poly1305
    pub encrypt: OvpnKeyMaterial,                    // { cipher_key, nonce_tail }
    pub decrypt: OvpnKeyMaterial,
}
```

Peer identity is `peer_id` (u32, userspace-assigned). Diff
shape:

```rust
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct OvpnDiff {
    pub peers_to_add: Vec<(u32, OvpnPeerConfig)>,
    pub peers_to_update: Vec<(u32, OvpnPeerConfig)>,
    pub peers_to_remove: Vec<u32>,
    pub keys_to_install: Vec<(u32, OvpnKeySlot, OvpnKeyConfig)>,
    pub keys_to_swap: Vec<u32>,            // peer_id; swap primary↔secondary
    pub keys_to_delete: Vec<(u32, OvpnKeySlot)>,
}
```

### 2.3 Exclude read-only counters from diff input

Same as Plan 196 + Plan 178: drift detection must NOT trigger
on the read-only counter attributes
(`vpn-{rx,tx}-{bytes,packets}`, `link-{rx,tx}-{bytes,packets}`).

```rust
fn normalize_for_diff(peer: &OvpnPeer) -> OvpnPeerConfig {
    OvpnPeerConfig {
        remote: peer.remote,
        ...
        // Excluded: rx_bytes, tx_bytes, rx_packets, tx_packets
    }
}
```

### 2.4 `LinkBuilder::ovpn` integration

Already shipped via Plan 190 §2.3b as the link-half-only
form. Plan 197 doesn't change the LinkBuilder API; the
declarative `OvpnConfig::apply` consumes the link the
LinkBuilder created.

## 3. Implementation phases

| Phase | Files | LOC |
|---|---|---|
| 1 — `genl/ovpn/family.rs` + `#[genl_family]` declaration | new dir | ~80 |
| 2 — Command + attribute enums + GenlEnum derives | new `genl/ovpn/commands.rs` | ~150 |
| 3 — Imperative `Connection<Ovpn>` methods (11 commands) | new `genl/ovpn/connection.rs` | ~250 |
| 4 — Multicast subscribe + `OvpnEvent` (3 notification kinds) | new `genl/ovpn/events.rs` | ~100 |
| 5 — `attach_socket` helper (fd-passing) | `connection.rs` | ~60 |
| 6 — Declarative `OvpnConfig` + builders | new `genl/ovpn/config/types.rs` | ~150 |
| 7 — `compute_diff` (peer + key symmetric diff) | new `config/diff.rs` | ~150 |
| 8 — `OvpnDiff::apply` orchestrating peer + key ops | `config/apply.rs` | ~150 |
| 9 — `apply_reconcile` | `config/apply.rs` | ~40 |
| 10 — `Display` for `OvpnDiff` | `config/diff.rs` | ~50 |
| 11 — Re-exports | `lib.rs` | ~10 |
| 12 — Recipe + example | new files | ~250 |
| 13 — Tests (see §4) | various | ~450 |
| **Total** | | **~1890 LOC** |

## 4. Tests

### 4.1 Unit — `compute_diff` semantics

```rust
#[test]
fn diff_new_peer_becomes_add() {
    let cfg = OvpnConfig::new("ovpn0")
        .peer(42, |p| p.remote("10.0.0.1:1194".parse().unwrap()));
    let kernel = vec![];
    let diff = compute_diff(&cfg, &kernel);
    assert_eq!(diff.peers_to_add.len(), 1);
    assert_eq!(diff.peers_to_add[0].0, 42);
}

#[test]
fn diff_existing_peer_with_changed_endpoint_becomes_update() {
    // peer_id matches; endpoint differs.
}

#[test]
fn diff_stale_peer_becomes_remove() { ... }

#[test]
fn diff_key_install_then_re_diff_is_noop() {
    // Idempotence under apply.
}

#[test]
fn diff_does_not_drift_on_byte_counters() {
    // The Plan 178 invariant applied to ovpn.
}

#[test]
fn diff_handles_key_swap_correctly() {
    // Config wants primary=keyA; kernel has secondary=keyA + primary=keyB.
    // Diff must propose: swap (or delete+install).
}
```

### 4.2 Wire-shape

```rust
#[test]
fn peer_new_emits_correct_attributes() { ... }

#[test]
fn key_new_emits_aes_gcm_cipher_value() { ... }

#[test]
fn attach_socket_includes_scm_rights() {
    // The fd-passing path uses SCM_RIGHTS in the auxiliary
    // control message. Verify the auxiliary cmsg shape.
}
```

### 4.3 Integration — root-gated + module-gated

```rust
#[tokio::test]
async fn ovpn_config_apply_creates_peer() -> Result<()> {
    require_root!();
    nlink::require_modules!("ovpn");      // kernel 6.16+

    let ns = TestNamespace::new("ovpn-decl")?;
    let route = namespace::connection_for::<Route>(ns.name())?;
    NetworkConfig::new().link(|b| b.ovpn().name("ovpn0"))
        .apply(&route).await?;

    let ovpn = namespace::connection_for_async::<Ovpn>(ns.name()).await?;
    let cfg = OvpnConfig::new("ovpn0")
        .mode(OvpnMode::Client)
        .peer(1, |p| p
            .remote("10.0.0.99:1194".parse().unwrap())
            .keys_primary(test_key())
        );

    cfg.apply(&ovpn).await?;

    let peers = ovpn.peer_dump(...).await?;
    assert_eq!(peers.len(), 1);

    Ok(())
}

#[tokio::test]
async fn ovpn_config_apply_is_idempotent() -> Result<()> { ... }

#[tokio::test]
async fn ovpn_key_swap_through_diff() -> Result<()> {
    // Install primary + secondary. Apply a config that has
    // them swapped. Verify the diff proposes a swap (single
    // KEY_SWAP command) rather than delete+install.
}
```

## 5. Acceptance criteria

- [ ] Imperative `Connection<Ovpn>` with 11 GENL commands +
      `attach_socket` helper.
- [ ] Multicast subscribe + `OvpnEvent` (3 NTF kinds).
- [ ] Declarative `OvpnConfig` + `OvpnDiff` + `apply` +
      `apply_reconcile` + `Display` impl.
- [ ] Byte counters excluded from diff input.
- [ ] 5+ unit tests (diff semantics) + 3+ wire-shape tests
      + 3+ root-gated integration tests.
- [ ] Recipe + example.
- [ ] CHANGELOG entry; migration guide entry.

## 6. Effort estimate

| Phase | Effort |
|---|---|
| Code (~1890 LOC) | ~9 h |
| Unit + wire-shape tests | ~3 h |
| Integration tests (kernel 6.16+ required) | ~3 h |
| Recipe + example | ~2 h |
| CHANGELOG + migration guide | ~30 min |
| **Total** | **~17.5 h** |

## 7. Risks

- **Kernel 6.16+ required**. The integration tests need a
  recent enough kernel. Gate via `require_modules!("ovpn")`;
  the test skips cleanly on older systems. CI runner kernel
  version must be checked.
- **fd-passing via SCM_RIGHTS**: the `attach_socket` path is
  the most complex piece; needs careful wire-shape testing.
  Reference the existing `setns` patterns in
  `namespace.rs` if they use SCM_RIGHTS (they do for the
  netns fd).
- **Cipher key material handling**: 32-byte keys + nonce
  tails. Plumb as `[u8; 32]` + `[u8; 12]`. Document that
  callers MUST zero-on-drop their key material at the
  application level — the lib doesn't enforce this.
- **No public test vectors**: ovpn's GENL family is new
  enough that there isn't a "known correct request bytes"
  test corpus. Build our own by sniffing what the
  `ovpn-dco-cli` PSK demo emits + reproducing it.

## 8. Out-of-scope follow-ups

_None — this plan is comprehensive for 0.19._

## 9. Cross-cutting artifacts

| Artifact | Action | Notes |
|---|---|---|
| `CHANGELOG.md` `## [Unreleased]` | **add** `### Added` headline entry for ovpn GENL family + declarative `OvpnConfig` | Cross-reference Plan 190's link-half + Plan 196 WG. |
| `docs/migration_guide/0.18.0-to-0.19.0.md` | **append** `### Plan 197` section | Net-new feature; no migration needed. |
| `docs/recipes/ovpn-data-channel-offload.md` (**new**) | **create** ~180 lines | Walks setting up a 2-peer client config with AES-GCM keys. |
| `docs/recipes/README.md` | **add row** for `ovpn-data-channel-offload.md` | One line. |
| `crates/nlink/examples/ovpn/declarative.rs` (**new**) | **create** ~120-line demo | Register in `Cargo.toml`. |
| `crates/nlink/examples/ovpn/imperative.rs` (**new**) | **create** ~80-line demo of the lower-level imperative API | Pedagogical step before the declarative recipe. |
| `README.md` `## Library Modules` table | **add row** for `nlink::netlink::genl::ovpn` | New protocol family; deserves a top-level mention. |
| `README.md` `## High-Level APIs` | **add** "Declarative ovpn" sub-section alongside Declarative WireGuard | Pair with Plan 196's section. |
| `CLAUDE.md` `## Feature flags` table | **add row** if any new feature flag (probably not — uses default `genl`) | Check during implementation. |
| `CLAUDE.md` | **append** a new sub-section under the existing protocol/GENL families area documenting ovpn (kernel version + scope + cipher constraints) | Helps consumers know what's covered. |

End of plan.
