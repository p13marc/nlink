# WireGuard Mesh in Namespaces

How to build a 3-node WireGuard full-mesh entirely within a single
host, using three namespaces as stand-ins for three physically separate
peers. Useful for integration tests, handshake failure-mode
reproductions, and teaching.

## When to use this

- Validating WireGuard configuration logic (keys, allowed-ips,
  keepalive) without cloud infrastructure.
- Reproducing multi-peer bug reports in a self-contained harness.
- Integration-testing an orchestrator that programs wg interfaces.

Don't use it when:

- You want real-world NAT / MTU / link behavior — a single host
  can't emulate those faithfully. Use real peers behind routers.
- The transport medium matters (radio, satellite). Pair with
  [per-peer impairment](./per-peer-impairment.md) to simulate it.

## High-level approach

Three namespaces (`wga`, `wgb`, `wgc`), each holding a `wg*`
interface + a veth uplink into a shared bridge in a "transit"
namespace. Each node knows the other two peers' public keys + allowed
IPs, listens on a distinct UDP port. After handshake, traffic to a
peer's wg IP flows over the encrypted tunnel.

```text
             ┌────────────────── transit ns ──────────────────┐
             │     br0  (10.0.0.0/24 on native segment)       │
             │      ├── veth_a ── 10.0.0.1                    │
             │      ├── veth_b ── 10.0.0.2                    │
             │      └── veth_c ── 10.0.0.3                    │
             └────────┬──────────────┬─────────────────┬──────┘
                      │              │                 │
              ┌───────┴─────┐  ┌─────┴───────┐  ┌──────┴──────┐
              │ ns: wga     │  │ ns: wgb     │  │ ns: wgc     │
              │ wg0 10.66.1 │  │ wg0 10.66.2 │  │ wg0 10.66.3 │
              │ listen 51820│  │ listen 51821│  │ listen 51822│
              └─────────────┘  └─────────────┘  └─────────────┘
```

The transit ns hosts the bridge that lets the wg endpoints reach each
other. In production you'd replace that with real IP reachability.

## Code

Requires the `lab` feature for `nlink::lab::{LabNamespace, LabBridge,
LabVeth}`.

```no_run
# async fn demo() -> nlink::Result<()> {
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};

use nlink::lab::{LabBridge, LabNamespace, LabVeth};
use nlink::netlink::{Connection, Route, Wireguard};
use nlink::netlink::genl::wireguard::AllowedIp;
use nlink::netlink::link::WireguardLink;

// 1. Build the transit namespace + bridge.
let transit = LabNamespace::new("wg-transit")?;
let wga = LabNamespace::new("wga")?;
let wgb = LabNamespace::new("wgb")?;
let wgc = LabNamespace::new("wgc")?;

// 2. For each peer, veth pair: local side stays in transit, peer side
//    goes into the peer namespace.
LabVeth::new("veth_a", "uplink").peer_in(&wga).create_in(&transit).await?;
LabVeth::new("veth_b", "uplink").peer_in(&wgb).create_in(&transit).await?;
LabVeth::new("veth_c", "uplink").peer_in(&wgc).create_in(&transit).await?;

// 3. Bridge the transit-side ports.
LabBridge::new(&transit, "br0")
    .create().await?
    .add_port("veth_a").await?
    .add_port("veth_b").await?
    .add_port("veth_c").await?
    .up().await?;
transit.add_addr("br0", "10.0.0.254/24")?;
for port in ["veth_a", "veth_b", "veth_c"] {
    transit.link_up(port)?;
}

// 4. Address + up the peer-side uplinks.
for (ns, addr) in [(&wga, "10.0.0.1/24"), (&wgb, "10.0.0.2/24"), (&wgc, "10.0.0.3/24")] {
    ns.add_addr("uplink", addr)?;
    ns.link_up("uplink")?;
}

// 5. Create a WireGuard interface in each peer namespace.
for peer in [&wga, &wgb, &wgc] {
    let route: Connection<Route> = peer.connection()?;
    route.add_link(WireguardLink::new("wg0")).await?;
    route.set_link_up("wg0").await?;
}

// Real deployments generate keys with `wg genkey`. For the mesh wiring
// itself, the kernel accepts any 32-byte blob — fill these in with
// real keypairs in production code.
let (priv_a, pub_a) = ([0x11; 32], [0x21; 32]);
let (priv_b, pub_b) = ([0x12; 32], [0x22; 32]);
let (priv_c, pub_c) = ([0x13; 32], [0x23; 32]);

let transit_ep = |port: u16| SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), port));

// Helper to configure one node: own key, listen port, two peers.
async fn configure(
    ns: &LabNamespace,
    own_priv: [u8; 32],
    listen_port: u16,
    peers: [(IpAddr, SocketAddr, [u8; 32], u8); 2], // (wg_ip, endpoint, pub_key, allowed_prefix_len)
) -> nlink::Result<()> {
    let wg: Connection<Wireguard> = ns.connection_for_async().await?;
    wg.set_device("wg0", |d| d.private_key(own_priv).listen_port(listen_port)).await?;
    for (wg_ip, endpoint, pub_key, prefix) in peers {
        let allowed_v4 = match wg_ip {
            IpAddr::V4(v4) => AllowedIp::v4(v4, prefix),
            IpAddr::V6(_) => unreachable!("demo uses v4"),
        };
        wg.set_peer("wg0", pub_key, |p| {
            p.endpoint(endpoint)
             .allowed_ip(allowed_v4)
             .persistent_keepalive(15)
        }).await?;
    }
    Ok(())
}

// Wire up the mesh.
configure(&wga, priv_a, 51820, [
    (Ipv4Addr::new(10,66,1,2).into(), transit_ep(51821), pub_b, 32),
    (Ipv4Addr::new(10,66,1,3).into(), transit_ep(51822), pub_c, 32),
]).await?;

configure(&wgb, priv_b, 51821, [
    (Ipv4Addr::new(10,66,1,1).into(), transit_ep(51820), pub_a, 32),
    (Ipv4Addr::new(10,66,1,3).into(), transit_ep(51822), pub_c, 32),
]).await?;

configure(&wgc, priv_c, 51822, [
    (Ipv4Addr::new(10,66,1,1).into(), transit_ep(51820), pub_a, 32),
    (Ipv4Addr::new(10,66,1,2).into(), transit_ep(51821), pub_b, 32),
]).await?;

// 6. Address the wg0 interfaces so the allowed-ip routes resolve.
wga.add_addr("wg0", "10.66.1.1/24")?; wga.link_up("wg0")?;
wgb.add_addr("wg0", "10.66.1.2/24")?; wgb.link_up("wg0")?;
wgc.add_addr("wg0", "10.66.1.3/24")?; wgc.link_up("wg0")?;

// 7. Verify: ping across the mesh from a spawn inside wga.
let out = wga.spawn_output({
    let mut cmd = std::process::Command::new("ping");
    cmd.args(["-c", "1", "-W", "2", "10.66.1.2"]);
    cmd
})?;
println!("a -> b handshake: {}", String::from_utf8_lossy(&out.stdout));
# Ok(())
# }
```

## Observing the handshake

Each peer's `get_device` dump shows the last-handshake timestamp and
byte counters once traffic flows:

```rust,ignore
let wg: Connection<Wireguard> = wga.connection_for_async().await?;
let dev = wg.get_device("wg0").await?;
for peer in &dev.peers {
    println!(
        "peer {:?}: handshake={:?}  rx={}  tx={}",
        peer.public_key,
        peer.last_handshake,
        peer.rx_bytes,
        peer.tx_bytes,
    );
}
```

`last_handshake == None` means the peer hasn't handshaken yet
(initiator hasn't sent, or responder hasn't replied). Force a
handshake by generating traffic to that peer's allowed IP.

## Caveats

- **Real keypair generation.** Don't ship code with all-`0x11` keys;
  replace with `wg genkey` output or an in-process curve25519
  keypair generator.
- **Listen port collision across namespaces.** Each peer listens on a
  different UDP port; they can't all use 51820 because they share the
  host's `network: underlay` — well, in this recipe they each have
  their own socket table so they *could*, but running different ports
  matches real multi-host deployments more faithfully.
- **Keepalive.** `persistent_keepalive(15)` is appropriate for
  NAT-traversal scenarios. A pure lab mesh doesn't need it, but leaving
  it on keeps tests predictable.
- **Routing inside peer namespaces.** The example assumes traffic to
  `10.66.1.0/24` is routed via `wg0`. The kernel adds that route
  automatically when you add the address on `wg0`; if you disable that
  (`ip addr add … noprefixroute`), add the route manually.
- **MTU.** WireGuard encapsulates UDP with its own header; the default
  MTU is 1420. If you're tunneling inside a veth that has MTU 1500 you
  won't see fragmentation, but real-world paths with lower PMTU will.
  Set `WireguardLink::new("wg0").mtu(1380)` in constrained environments.

## Teardown

All four `LabNamespace` handles are dropped at end-of-scope, so the
namespaces delete themselves. No explicit cleanup needed.

## Hand-rolled equivalent

The wiring above is a condensed version of
`crates/nlink/examples/genl/wireguard.rs` — that example runs the full
single-peer lifecycle interactively. Use the example for end-to-end
behavior; use this recipe for the mesh topology.

## See also

- [`Connection::<Wireguard>`](https://docs.rs/nlink/latest/nlink/netlink/genl/wireguard/index.html)
- [`examples/genl/wireguard.rs`](../../crates/nlink/examples/genl/wireguard.rs)
- [`nlink::lab`](https://docs.rs/nlink/latest/nlink/lab/index.html) — the
  namespace + bridge + veth helpers used above.
- [Per-peer impairment recipe](./per-peer-impairment.md) — apply
  netem to individual veth uplinks to simulate per-link quality.
- Upstream: `man 8 wg`, [WireGuard whitepaper][wg-paper].

[wg-paper]: https://www.wireguard.com/papers/wireguard.pdf
