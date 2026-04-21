# VLAN-Aware Bridge Setup

How to build a Linux bridge with 802.1Q VLAN filtering enabled, then
configure member ports as either VLAN trunks (carrying multiple tagged
VLANs) or access ports (stripping tags to expose a single VLAN to the
endpoint).

## When to use this

- A switch-like topology inside a single host: multiple VLANs sharing
  L2 infrastructure with per-VLAN isolation.
- Containers / VMs each attached to one VLAN via a veth, with a shared
  bridge carrying trunked uplinks to other hosts.

Don't use it when:

- You only need one network segment — plain `BridgeLink` without
  `vlan_filtering()` is lighter.
- You need L3 routing between VLANs — pair a VLAN-aware bridge with
  routing rules or nftables forwarding; the bridge alone is L2 only.

## High-level approach

Three pieces:

1. Create a bridge with `vlan_filtering(true)`. Without the flag the
   kernel ignores VLAN metadata at this port.
2. Enslave member interfaces. On creation a port gets VLAN 1 pvid +
   untagged by default — override that with `BridgeVlanBuilder`.
3. For each port, decide: access or trunk.
   - **Access port**: one VLAN ID, `.pvid()` and `.untagged()`. Frames
     arriving untagged get assigned that VID; egress strips the tag.
   - **Trunk port**: one or more VLANs, tagged. Frames keep their
     `.1Q` tag in both directions.

```text
                    br0 (vlan_filtering)
                ┌──────────────────────────┐
     trunk:     │  ● uplink   VLAN 10,20 (tagged)
                │  ● access-10 VLAN 10 pvid+untagged
     access:    │  ● access-20 VLAN 20 pvid+untagged
                │  ● range    VLAN 100-199 tagged
                └──────────────────────────┘
```

## Code

```no_run
# async fn demo() -> nlink::Result<()> {
use nlink::netlink::{Connection, Route};
use nlink::netlink::bridge_vlan::BridgeVlanBuilder;
use nlink::netlink::link::{BridgeLink, DummyLink};

let conn = Connection::<Route>::new()?;

// 1. Create the VLAN-aware bridge.
conn.add_link(BridgeLink::new("br0").vlan_filtering(true)).await?;
conn.set_link_up("br0").await?;

// 2. Create some ports and enslave them. (Replace DummyLink with
//    your real NICs / veths.)
for name in ["uplink", "access-10", "access-20", "range"] {
    conn.add_link(DummyLink::new(name)).await?;
    conn.enslave(name, "br0").await?;
    conn.set_link_up(name).await?;
}

// 3a. Access port on VLAN 10 — pvid + untagged.
conn.add_bridge_vlan(
    BridgeVlanBuilder::new(10).dev("access-10").pvid().untagged(),
).await?;

// 3b. Access port on VLAN 20.
conn.add_bridge_vlan(
    BridgeVlanBuilder::new(20).dev("access-20").pvid().untagged(),
).await?;

// 3c. Trunk port carrying VLAN 10 + VLAN 20 tagged. No pvid — frames
//     without a tag are dropped at ingress on a trunk.
conn.add_bridge_vlan_tagged("uplink", 10).await?;
conn.add_bridge_vlan_tagged("uplink", 20).await?;

// 3d. A range trunk for VLANs 100-199 (one netlink op).
conn.add_bridge_vlan_range("range", 100, 199).await?;

// 4. Verify: dump per-port VLAN configuration.
for port in ["uplink", "access-10", "access-20", "range"] {
    let vlans = conn.get_bridge_vlans(port).await?;
    println!("{port}:");
    for v in &vlans {
        println!(
            "  vid={} pvid={} untagged={}",
            v.vid, v.flags.pvid, v.flags.untagged,
        );
    }
}
# Ok(())
# }
```

## Removing bridge VLAN port defaults (VLAN 1)

When you enslave a port, the kernel installs VLAN 1 as `pvid +
untagged` by default. For a trunk that shouldn't carry VLAN 1, remove
that default before adding your real VLAN list:

```rust,ignore
conn.del_bridge_vlan("uplink", 1).await?;
conn.add_bridge_vlan_tagged("uplink", 10).await?;
conn.add_bridge_vlan_tagged("uplink", 20).await?;
```

Otherwise untagged ingress on the trunk gets classified to VLAN 1 and
quietly forwarded, which is rarely what you want.

## Trunk with untagged native + tagged others

Some devices expect a "native VLAN": one VLAN delivered untagged, the
rest tagged. Combine pvid/untagged on one VID with tagged on others:

```rust,ignore
// Native VLAN 1 (untagged) + tagged 10 + tagged 20.
conn.add_bridge_vlan(BridgeVlanBuilder::new(1).dev("uplink").pvid().untagged()).await?;
conn.add_bridge_vlan_tagged("uplink", 10).await?;
conn.add_bridge_vlan_tagged("uplink", 20).await?;
```

## VLAN-to-VXLAN tunnel mapping

If you're bridging into a VXLAN, map VLAN IDs to VNIs via
`add_vlan_tunnel`. See [`BridgeVlanTunnelBuilder`][tunnel].

[tunnel]: https://docs.rs/nlink/latest/nlink/netlink/bridge_vlan/struct.BridgeVlanTunnelBuilder.html

```rust,ignore
use nlink::netlink::bridge_vlan::BridgeVlanTunnelBuilder;

// VLAN 10 <-> VNI 10000 on a VXLAN port.
conn.add_vlan_tunnel(BridgeVlanTunnelBuilder::new(10, 10000).dev("vxlan0")).await?;
// Range: VLAN 100-109 <-> VNI 20000-20009
conn.add_vlan_tunnel(BridgeVlanTunnelBuilder::new(100, 20000).dev("vxlan0").range(109)).await?;
```

## Caveats

- `vlan_filtering` is a bridge-level toggle, not a port-level toggle.
  Flipping it on an existing bridge does not retroactively install per-port
  VLAN config — you still need to configure each port.
- The bridge itself is a port. To let the host reach a VLAN through
  `br0` (e.g., assign an IP on VLAN 10), run `add_bridge_vlan` with
  `.dev("br0")` — otherwise the bridge's self-port won't accept that
  VLAN's traffic upward.
- Multicast flooding rules interact with VLAN filtering; enabling
  `vlan_filtering(true)` on a bridge that was forwarding unfiltered
  traffic can drop frames your workload was silently relying on. Test
  in a lab namespace first.
- The Linux bridge is always learning — MAC-VID pairs age out like in a
  non-VLAN bridge. Monitor with `get_fdb()` (see [FDB event
  monitoring](#see-also)).

## Hand-rolled equivalent

The `BridgeVlanBuilder` wraps the `RTM_NEWLINK` + `IFLA_AF_SPEC` +
nested `AF_BRIDGE` attribute sequence. If you need unusual flag
combinations (e.g., `BRIDGE_VLAN_INFO_BRENTRY`), build the
`MessageBuilder` directly — see `crates/nlink/src/netlink/bridge_vlan.rs`
for the wire layout.

For a shell-equivalent sanity check, the `bridge(8)` tool does the
same operations:

```text
bridge vlan add dev access-10 vid 10 pvid untagged master
bridge vlan add dev uplink vid 10
bridge vlan add dev uplink vid 20
bridge vlan show
```

## See also

- [`BridgeVlanBuilder`](https://docs.rs/nlink/latest/nlink/netlink/bridge_vlan/struct.BridgeVlanBuilder.html)
- [`Connection::add_bridge_vlan_range`](https://docs.rs/nlink/latest/nlink/netlink/struct.Connection.html#method.add_bridge_vlan_range)
- [Per-peer impairment recipe](./per-peer-impairment.md) — once VLANs
  are up, apply per-port netem on the bridge side.
- [Multi-namespace events recipe](./multi-namespace-events.md) —
  subscribe to `RtnetlinkGroup::Neigh` to observe FDB / VLAN learning
  live.
- Kernel: `Documentation/networking/bridge.rst`, `man 8 bridge`.
