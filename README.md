# nlink

[![Crates.io](https://img.shields.io/crates/v/nlink.svg)](https://crates.io/crates/nlink)
[![Documentation](https://docs.rs/nlink/badge.svg)](https://docs.rs/nlink)
[![License](https://img.shields.io/crates/l/nlink.svg)](https://github.com/p13marc/nlink#license)

A Rust library for Linux network configuration via netlink. Async/tokio-native,
type-safe, owns its wire format end-to-end (no `rtnetlink` / `netlink-packet-*`
dependency). CLI binaries (`ip`, `tc`, `ss`, `nft`, `wg`, `bridge`, `devlink`,
`ethtool`, `wifi`) ship as proof-of-concept demonstrations of the library.

## Install

```toml
nlink = "0.21"
```

Feature flags: `sockdiag`, `tuntap`, `tuntap-async`, `output`, `namespace_watcher`,
`syscall_batch` (recvmmsg/sendmmsg batching), `serde`, `lab` (test harness),
`full`. Full list in the [docs.rs feature table](https://docs.rs/crate/nlink/latest/features).

MSRV: Rust 1.95, edition 2024.

## Quick start

```rust
use nlink::netlink::{Connection, Route, RtnetlinkGroup, NetworkEvent};
use tokio_stream::StreamExt;

#[tokio::main]
async fn main() -> nlink::Result<()> {
    let conn = Connection::<Route>::new()?;

    // Query
    for link in conn.get_links().await? {
        println!("{}: {} (up={})", link.ifindex(), link.name_or("?"), link.is_up());
    }

    // Modify
    conn.set_link_up("eth0").await?;
    conn.set_link_mtu("eth0", 9000).await?;

    // Observe
    conn.subscribe(&[RtnetlinkGroup::Link, RtnetlinkGroup::Ipv4Addr])?;
    let mut events = conn.events().await;
    while let Some(event) = events.try_next().await? {
        if let NetworkEvent::NewLink(link) = event {
            println!("link added: {}", link.name_or("?"));
        }
    }
    Ok(())
}
```

## What's in the box

**Networking core** — links (20+ types: dummy, veth, bridge, bond, VLAN, VXLAN,
GRE, IPIP, SIT, VTI, Geneve, netkit, IFB, VRF, MACsec, MACVLAN, IPVLAN, GTP,
tun/tap), addresses, routes, neighbors, routing rules, nexthop objects + ECMP
groups, MPLS, SRv6, bridge FDB + VLAN filtering, network namespaces.

**Traffic control** — 35 typed qdisc kinds, typed classes (HTB, HFSC, DRR, QFQ),
11 typed filter kinds, 17 typed action kinds, filter chains, BPF program attachment.
Every typed config has a `parse_params(&[&str])` so `tc` CLI syntax round-trips
through the typed API. Strongly-typed units: `Rate` (bytes/sec internally,
parses `100mbit` / `1gbit`), `Bytes`, `Percent`, `TcHandle`, `FilterPriority`.

**Generic Netlink families** — WireGuard, MACsec, MPTCP, ethtool, nl80211 (WiFi),
devlink, DPLL (clock synchronization — SyncE/PTP/GNSS, kernel 6.7+),
net_shaper (TX hardware shaping, kernel 6.13+).

**Firewall** — nftables tables/chains/rules/sets/NAT/match expressions,
flowtables (`Expr::FlowOffload`), multicast event subscription, atomic
single-batch commits via `Transaction`.

**Diagnostics & observability** — socket diagnostics (`SockDiag`),
connection tracking (`Netfilter`/ctnetlink), Linux audit, SELinux events,
FIB lookups, ethtool statistics + monitor, kobject uevent (device hotplug),
process connector lifecycle events.

**Cross-cutting** — XFRM IPsec SA/SP management + hardware offload
(`XFRMA_OFFLOAD_DEV`), 30-second default per-Connection timeout (override or
opt out), `NETLINK_EXT_ACK` TLV parsing (kernel error messages with offset +
attribute name), `NETLINK_GET_STRICT_CHK` opt-in.

## High-level APIs

The lower-level imperative API is the foundation; these declarative layers
collapse common configuration patterns.

```rust
// Declarative network state — diff against kernel, apply changes idempotently.
// With the `serde` feature it also round-trips through JSON/YAML: the typed
// config validates as it parses (CIDR addresses, MAC strings), so a bad value
// is a deserialize error, not a silently-wrong config.
use nlink::netlink::config::NetworkConfig;
NetworkConfig::new()
    .link("br0", |l| l.bridge().up())
    .link("dummy0", |l| l.dummy().mtu(9000).up().master("br0"))
    .address("br0", "192.168.100.1/24")?
    .apply(&conn).await?;
let cfg = NetworkConfig::from_json_str(r#"{ "links": [{ "name": "br0", "link-type": "bridge" }] }"#)?;

// Declarative nftables ruleset — atomic batch commit.
use nlink::netlink::nftables::config::NftablesConfig;
use nlink::netlink::nftables::types::{Family, Hook, Policy, Priority};
let cfg = NftablesConfig::new().table("filter", Family::Inet, |t| {
    t.chain("input", |c| c.hook(Hook::Input).priority(Priority::Filter).policy(Policy::Drop))
        .rule("input", |r| r.match_iif("lo").accept())
        .rule("input", |r| r.match_tcp_dport(22).accept())
});
cfg.diff(&conn).await?.apply(&conn).await?;

// Rate limiting — typed Rate, no bits-vs-bytes confusion.
use nlink::{Rate, netlink::ratelimit::RateLimiter};
RateLimiter::new("eth0").egress(Rate::mbit(100)).ingress(Rate::mbit(50))
    .apply(&conn).await?;

// Per-peer impairment — netem per destination on shared L2.
use nlink::netlink::impair::PerPeerImpairer;
PerPeerImpairer::new("vethA-br")
    .impair_dst_ip("172.100.3.18".parse()?, /* netem config */)
    .apply(&conn).await?;

// Network diagnostics — find issues, score bottlenecks.
let report = nlink::netlink::diagnostics::Diagnostics::new(conn).scan().await?;
```

## Building blocks for downstream code

- **`ConnectionPool<P>`** — bounded async pool of typed connections; each lease
  gets its own kernel-side socket, so the kernel processes them in parallel.
- **`DumpStream<T>`** — `Stream` adapter over netlink dumps; O(1) memory on
  BGP/conntrack/IPsec-scale tables instead of buffering the full response.
- **`ResyncStream<T>`** — wraps multicast subscriptions with ENOBUFS recovery
  (`ResyncedEvent::Marker(ResyncStart)` → snapshot replay → `ResyncEnd`).
- **`nlink-macros`** — declare a custom Generic Netlink family in ~30 lines via
  `#[genl_family]` + `#[derive(GenlMessage)]`; consume through
  `conn.send_typed(req).await?` / `dump_typed_stream`. The in-tree DPLL and
  net_shaper families are the canonical dogfoods.

## Documentation

- [Library guide](docs/library.md) — detailed examples: namespaces, TC, WireGuard,
  error handling, concurrency.
- [Cookbook recipes](docs/recipes/README.md) — end-to-end walkthroughs
  (per-peer impairment, VLAN-aware bridges, bidirectional rate limiting,
  WireGuard mesh in namespaces, ENOBUFS-resync loops, define-your-own-GENL-family).
- [CLI reference](docs/cli.md) — command coverage for all ten demo
  binaries (`ip`, `tc`, `ss`, `nft`, `bridge`, `wg`, `nlink-config`,
  `devlink`, `nlink-ethtool`, `wifi`).
- [Migration guides](docs/migration_guide/README.md) — per-release upgrade notes.
- [Examples](crates/nlink/examples/README.md) — 40+ runnable demos.
- [docs.rs/nlink](https://docs.rs/nlink) — full API reference.

## Project status

API stable and used in production. Wire format pinned by build-time
`sizeof(struct …)` CI gates; concurrent shared-`Arc<Connection>` use is safe
(serialized via internal mutex — use `ConnectionPool` for parallel throughput).
19 CI gates on every push (build × 2 feature sets, tests × 2, clippy
`--deny warnings`, doc with strict intra-doc links, semver-checks, public-api
diff, machete, msrv, s390x big-endian cross-check, README/manifest sync, plus
8 nlink-specific audit scripts) + a privileged integration job that runs the
root-gated kernel round-trip suite.

## Building from source

```bash
cargo build --release
cargo run --release -p nlink-ip -- link show
cargo run --release -p nlink-tc -- qdisc show
```

## License

Apache 2.0 OR MIT, at your option.
