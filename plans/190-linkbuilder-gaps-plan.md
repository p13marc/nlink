---
to: nlink maintainers
from: nlink-lab feedback `nlink-feedback.md` §10 + §12 + §13-VRF (2026-05-30)
subject: `LinkBuilder` feature gaps — VXLAN local/port/underlay, VLAN protocol, VRF
status: queued for 0.19 — low (feature additions); WG split out
target version: 0.19.0
parent: (none — single-deliverable plan)
source: nlink-lab `nlink-feedback.md` §10, §12, §13 (VRF half only)
created: 2026-05-30
---

# Plan 190 — `LinkBuilder` declarative-path gaps

## 1. Why this plan exists

Three concrete declarative-vs-imperative asymmetries on
`LinkBuilder` that keep nlink-lab on the imperative path for
VXLAN, VLAN-protocol-aware setups, and VRF. All three already
have imperative coverage in `netlink/link.rs`; the missing
piece is wiring them into `LinkBuilder` so `NetworkConfig`
consumers can reach them. Predictable feature work.

WireGuard's half of feedback Item #13 is **split out to a
separate plan** (193 or similar) because it's a different
shape entirely: the link kind exists in RTNETLINK but
peer/key config goes through the `Wireguard` GENL family, so
modeling it declaratively means either a parallel
`WireguardConfig` or accepting the "RTNETLINK link only,
peers separate" pattern nlink-lab is already using. Out of
scope here.

## 2. The changes — three sub-items

### 2.1 VXLAN — `local()`, `port()`, `underlay_dev()` (#10)

Imperative `VxlanLink` already exposes:
- `.local(IpAddr)` — tunnel source IP (`IFLA_VXLAN_LOCAL` /
  `IFLA_VXLAN_LOCAL6`)
- `.port(u16)` — UDP encap port (`IFLA_VXLAN_PORT`, default
  4789)
- (implicit) `IFLA_VXLAN_LINK` — the underlay parent device

Declarative `LinkBuilder::vxlan` covers VNI only; `vxlan_remote`
covers the remote endpoint. The three missing knobs:

```rust
// crates/nlink/src/netlink/config/types.rs (DeclaredLinkType)

#[non_exhaustive]
pub enum DeclaredLinkType {
    ...
    Vxlan {
        vni: u32,
        remote: Option<IpAddr>,
        local: Option<IpAddr>,        // NEW
        port: Option<u16>,            // NEW
        underlay_dev: Option<String>, // NEW
    },
    ...
}

impl LinkBuilder {
    pub fn vxlan_local(self, addr: IpAddr) -> Self { ... }
    pub fn vxlan_port(self, port: u16) -> Self { ... }
    pub fn vxlan_underlay_dev(self, name: impl Into<String>) -> Self { ... }
}
```

Apply-path glue in `config/apply.rs`:

```rust
DeclaredLinkType::Vxlan {
    vni, remote, local, port, underlay_dev,
} => {
    let mut config = VxlanLink::new(&link.name, *vni);
    if let Some(IpAddr::V4(r)) = remote {
        config = config.remote(*r);
    } else if let Some(IpAddr::V6(r)) = remote {
        config = config.remote_v6(*r);
    }
    if let Some(IpAddr::V4(l)) = local {
        config = config.local(*l);
    } else if let Some(IpAddr::V6(l)) = local {
        config = config.local_v6(*l);
    }
    if let Some(p) = port {
        config = config.port(*p);
    }
    if let Some(dev) = underlay_dev {
        // Plan 186 §2.3 will provide a Name-as-parent path;
        // for now resolve to ifindex via the same code path
        // VlanLink uses.
        config = config.underlay_link_name(dev);
    }
    conn.add_link(config).await?;
}
```

**Idempotence implication:** since these become part of the
diff, `compute_diff` needs to compare them against kernel
state in `links_to_modify`. The maintainer notes Vxlan
re-applies are non-idempotent today — landing this fixes
that for the four new knobs.

### 2.2 VLAN — `protocol()` (#12)

```rust
// crates/nlink/src/netlink/config/types.rs

#[non_exhaustive]
pub enum DeclaredLinkType {
    ...
    Vlan {
        parent: String,
        vlan_id: u16,
        protocol: Option<VlanProtocol>,  // NEW; None == 802.1Q (kernel default)
    },
    ...
}

impl LinkBuilder {
    /// Set the VLAN tagging protocol. Defaults to 802.1Q.
    /// Use 802.1ad for Q-in-Q stacked VLAN encap.
    pub fn vlan_protocol(self, p: VlanProtocol) -> Self { ... }
}
```

`VlanProtocol` already exists in `netlink/link.rs`. Re-export at
the crate root if not already.

### 2.3 VRF — `LinkBuilder::vrf(table)` (#13 half)

```rust
// crates/nlink/src/netlink/config/types.rs

#[non_exhaustive]
pub enum DeclaredLinkType {
    ...
    Vrf {
        table: u32,
    },
    ...
}

impl LinkBuilder {
    /// Build a VRF link bound to routing-table `table`.
    /// VRF (Virtual Routing & Forwarding) groups interfaces
    /// under a per-table forwarding domain; common in
    /// multi-tenant networks. Members enslave via
    /// [`LinkBuilder::master`].
    pub fn vrf(self, table: u32) -> Self { ... }
}
```

Apply-path glue:

```rust
DeclaredLinkType::Vrf { table } => {
    let mut config = VrfLink::new(&link.name, *table);
    if let Some(mtu) = link.mtu {
        config = config.mtu(mtu);
    }
    conn.add_link(config).await?;
}
```

`VrfLink` already exists in `netlink/link.rs` (per the
maintainer's audit).

## 3. Implementation phases

| Phase | Files | LOC |
|---|---|---|
| 1 — VXLAN: enum widening + 3 builder setters | `config/types.rs` | ~30 |
| 2 — VXLAN: apply-path glue | `config/apply.rs` | ~20 |
| 3 — VLAN protocol: enum widening + builder setter | `config/types.rs` | ~10 |
| 4 — VLAN protocol: apply-path glue | `config/apply.rs` | ~5 |
| 5 — VRF: enum variant + builder + apply | `config/types.rs` + `config/apply.rs` | ~30 |
| 6 — `compute_diff` parity for new VXLAN fields (idempotence) | `config/diff.rs` | ~30 |
| 7 — Tests (see §4) | various | ~200 |
| **Total** | | **~325 LOC** |

## 4. Tests

### 4.1 Unit — builder round-trip

In `crates/nlink/src/netlink/config/types.rs` tests:

```rust
#[test]
fn vxlan_builder_carries_all_new_knobs() {
    let link = LinkBuilder::new("vx0")
        .vxlan(42)
        .vxlan_remote(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)))
        .vxlan_local(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)))
        .vxlan_port(4790)
        .vxlan_underlay_dev("eth0");
    match &link.link_type {
        DeclaredLinkType::Vxlan { vni, remote, local, port, underlay_dev } => {
            assert_eq!(*vni, 42);
            assert_eq!(*remote, Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
            assert_eq!(*local, Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))));
            assert_eq!(*port, Some(4790));
            assert_eq!(underlay_dev.as_deref(), Some("eth0"));
        }
        _ => panic!("expected DeclaredLinkType::Vxlan"),
    }
}

#[test]
fn vlan_builder_carries_protocol() {
    let link = LinkBuilder::new("vlan100")
        .vlan("eth0", 100)
        .vlan_protocol(VlanProtocol::Dot1ad);
    match &link.link_type {
        DeclaredLinkType::Vlan { protocol, .. } => {
            assert_eq!(*protocol, Some(VlanProtocol::Dot1ad));
        }
        _ => panic!("expected DeclaredLinkType::Vlan"),
    }
}

#[test]
fn vrf_builder_carries_table() {
    let link = LinkBuilder::new("vrf-red")
        .vrf(100);
    match &link.link_type {
        DeclaredLinkType::Vrf { table } => assert_eq!(*table, 100),
        _ => panic!("expected DeclaredLinkType::Vrf"),
    }
}

#[test]
fn vxlan_diff_detects_local_change() {
    // compute_diff parity: a VXLAN with local=A in config vs
    // local=B in kernel must emit a `links_to_modify` op.
    let cfg = NetworkConfig::new().link(|b| {
        b.vxlan(42)
            .vxlan_local(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)))
    });
    let kernel_state = ...; // mock VXLAN with local=10.0.0.2
    let diff = compute_diff_from_states(&cfg, kernel_state);
    assert_eq!(diff.links_to_modify.len(), 1);
}
```

### 4.2 Wire-shape — VXLAN local/port/underlay attributes

In `crates/nlink/src/netlink/link.rs` tests (existing test
module):

```rust
#[test]
fn vxlan_link_with_local_emits_ifla_vxlan_local() {
    let link = VxlanLink::new("vx0", 42)
        .local(Ipv4Addr::new(10, 0, 0, 1));
    let bytes = build_add_link_request(&link);
    let attrs = parse_ifla_info_data(&bytes);
    let local = find_nested_attr(&attrs, IFLA_VXLAN_LOCAL)
        .expect("IFLA_VXLAN_LOCAL must be present");
    assert_eq!(local, &[10, 0, 0, 1]);
}

#[test]
fn vxlan_link_with_port_emits_ifla_vxlan_port() { ... }

#[test]
fn vxlan_link_with_underlay_link_emits_ifla_vxlan_link() { ... }

#[test]
fn vlan_link_with_protocol_emits_ifla_vlan_protocol() {
    let link = VlanLink::new("v0", "eth0", 100)
        .protocol(VlanProtocol::Dot1ad);
    let bytes = build_add_link_request(&link);
    let attrs = parse_ifla_info_data(&bytes);
    let proto = find_attr(&attrs, IFLA_VLAN_PROTOCOL).unwrap();
    // 802.1ad in network byte order
    assert_eq!(proto, &[0x88, 0xA8]);
}

#[test]
fn vrf_link_emits_ifla_vrf_table() {
    let link = VrfLink::new("vrf-red", 100);
    let bytes = build_add_link_request(&link);
    let attrs = parse_ifla_info_data(&bytes);
    let table = find_attr(&attrs, IFLA_VRF_TABLE).unwrap();
    assert_eq!(u32::from_le_bytes(table.try_into().unwrap()), 100);
}
```

These reuse the helpers from Plan 181's `build_list_*_request`
test pattern.

### 4.3 Integration — kernel round-trip

In `crates/nlink/tests/integration/links.rs` (existing) or
extend with a new file. All root-gated.

```rust
#[tokio::test]
async fn vxlan_local_round_trips_through_kernel() -> Result<()> {
    require_root!();
    nlink::require_modules!("vxlan");

    let ns = TestNamespace::new("vxlan-local")?;
    let conn = namespace::connection_for::<Route>(ns.name())?;

    // Need a dummy parent + an IP on it for the local addr
    // to be valid.
    conn.add_link(DummyLink::new("eth0")).await?;
    conn.add_address("eth0", IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 24).await?;

    let vx = VxlanLink::new("vx0", 42)
        .local(Ipv4Addr::new(10, 0, 0, 2))
        .remote(Ipv4Addr::new(10, 0, 0, 99))
        .port(4790);
    conn.add_link(vx).await?;

    let links = conn.get_links().await?;
    let vxlan = links.iter()
        .find(|l| l.name.as_deref() == Some("vx0"))
        .expect("vxlan must appear in dump");
    // Parse IFLA_VXLAN_* from the kernel response + verify
    // round-trip — the local/port/remote we set comes back
    // unchanged.
    ...

    Ok(())
}

#[tokio::test]
async fn vlan_protocol_dot1ad_round_trips() -> Result<()> { ... }

#[tokio::test]
async fn vrf_link_creates_with_table_id() -> Result<()> {
    require_root!();
    nlink::require_modules!("vrf");
    ...
}

#[tokio::test]
async fn declarative_vrf_with_member_enslaves_via_master() -> Result<()> {
    // Two-link config: a VRF + a dummy `.master(vrf)` —
    // dummy must end up enslaved under the VRF.
    let cfg = NetworkConfig::new()
        .link(|b| b.dummy("eth0"))
        .link(|b| b.vrf(100).name("vrf-red"))
        .link(|b| b.dummy("eth1").master("vrf-red"));
    ...
}
```

### 4.4 Idempotence — re-apply with new VXLAN knobs is zero-op

```rust
#[tokio::test]
async fn vxlan_with_local_port_reapply_is_zero_ops() -> Result<()> {
    require_root!();
    nlink::require_modules!("vxlan");

    let ns = ...;
    let conn = ...;

    let cfg = NetworkConfig::new()
        .link(|b| b.dummy("eth0"))
        .link(|b| b.vxlan(42)
            .vxlan_remote(IpAddr::V4(...))
            .vxlan_local(IpAddr::V4(...))
            .vxlan_port(4790));

    // First apply — creates everything.
    let r1 = cfg.apply(&conn).await?;
    assert_eq!(r1.changes_made, 2);

    // Second apply — must be zero ops. Verifies
    // compute_diff sees the new knobs as in-sync.
    let r2 = cfg.apply(&conn).await?;
    assert_eq!(r2.changes_made, 0, "reapply must be idempotent");

    Ok(())
}
```

This is the nlink-lab-shaped test from the feedback. Closes
Plan 158e Slice 4's blocker (per the maintainer).

## 5. Acceptance criteria

- [ ] `LinkBuilder::vxlan_{local,port,underlay_dev}` ship + are
      reachable from `NetworkConfig`.
- [ ] `LinkBuilder::vlan_protocol` ships.
- [ ] `DeclaredLinkType::Vrf { table }` + `LinkBuilder::vrf`
      ship.
- [ ] `compute_diff` detects changes in every new field so
      re-applies are idempotent.
- [ ] 5+ unit tests covering builder round-trip + diff
      detection.
- [ ] 5+ wire-shape tests covering the new IFLA_* attribute
      emissions.
- [ ] 4+ integration tests covering kernel round-trip +
      idempotence + VRF master enslaving.
- [ ] CHANGELOG entries; migration guide notes the
      `DeclaredLinkType` enum widening (semver-major; mitigated
      by `#[non_exhaustive]`).

## 6. Effort estimate

| Phase | Effort |
|---|---|
| Code (~325 LOC across 3 files) | ~2.5 h |
| Unit tests (5+) | ~1 h |
| Wire-shape tests (5+) | ~1.5 h |
| Integration tests (4+) | ~1.5 h |
| CHANGELOG + migration guide | ~30 min |
| **Total** | **~7 h** |

## 7. Risks

- **`DeclaredLinkType::Vxlan` enum-struct widening**: today's
  shape is `Vxlan { vni, remote }`; we're growing it to carry
  three more fields. Constructors via the `LinkBuilder` are
  unaffected; downstream pattern-matching with `Vxlan { vni,
  remote, .. }` keeps working (we already wrapped the enum in
  `#[non_exhaustive]`-equivalent semantics via the variant
  constructor being inaccessible). Direct pattern-match without
  `..` would break — flag in the migration guide.
- **VRF kernel module not always loaded** — gate the
  integration tests via `require_modules!("vrf")`. Standard
  pattern.
- **VXLAN local IP semantic** — the local must be an address
  configured on the underlay interface. The test fixture has
  to set up that address; document the requirement on the
  builder.

## 8. Out-of-scope follow-ups

- **WireGuard `LinkBuilder` (other half of #13)** — split to
  its own plan. Needs design work on whether peer config goes
  through `NetworkConfig` (probably no) or via a parallel
  `WireguardConfig`.
- **Bond options sparse coverage (#11)** — defer per
  maintainer's own assessment; no downstream signal.
- **Macvlan Source mode (W9)** — defer; no downstream signal.

End of plan.
