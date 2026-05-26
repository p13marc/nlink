# nlink - Rust IP utilities

[![Crates.io](https://img.shields.io/crates/v/nlink.svg)](https://crates.io/crates/nlink)
[![Documentation](https://docs.rs/nlink/badge.svg)](https://docs.rs/nlink)
[![License](https://img.shields.io/crates/l/nlink.svg)](https://github.com/p13marc/nlink#license)

A modern Rust implementation of Linux network management tools, providing both a library crate and CLI binaries.

## Overview

nlink is a from-scratch implementation of Linux netlink-based network management. The primary goal is to provide a high-quality Rust library for programmatic network configuration, with CLI tools serving as proof-of-concept binaries.

**Key design principles:**

- **Library-first**: Core functionality lives in a single, well-designed crate
- **Async/tokio-native**: Built for async Rust from the ground up
- **Custom netlink**: No dependency on rtnetlink or netlink-packet-* crates
- **Type-safe**: Leverage Rust's type system for correctness
- **High-level APIs**: Declarative configuration, rate limiting DSL, diagnostics

## Installation

```toml
# Core netlink functionality (always built — TC, link, address,
# route, namespace, GENL families, conntrack, XFRM, nftables, etc.
# all live in always-built modules). nlink bundles a re-export of
# `nlink-macros` so downstream code that wants to define its own
# GENL family pulls in only one dep.
nlink = "0.17"

# With additional features
nlink = { version = "0.17", features = ["sockdiag", "tuntap", "output"] }

# All features (including opt-in syscall_batch — 1.5x speedup on
# dump-heavy workloads via recvmmsg/sendmmsg).
nlink = { version = "0.17", features = ["full"] }
```

> Upgrading from an earlier release? See
> [`docs/migration_guide/`](docs/migration_guide/README.md) for
> per-release upgrade notes.

### Features

| Feature | Description |
|---------|-------------|
| `sockdiag` | Socket diagnostics via NETLINK_SOCK_DIAG |
| `tuntap` | TUN/TAP device management |
| `output` | JSON/text output formatting |
| `namespace_watcher` | Namespace watching via inotify |
| `lab` | `nlink::lab` namespace + integration-test harness |
| `syscall_batch` | `recvmmsg`/`sendmmsg` batching on dumps + streams (0.16+, opt-in) |
| `full` | All features enabled |

## Quick Start

```rust
use nlink::netlink::{Connection, Route, RtnetlinkGroup, NetworkEvent};
use tokio_stream::StreamExt;

#[tokio::main]
async fn main() -> nlink::Result<()> {
    let mut conn = Connection::<Route>::new()?;
    
    // Query interfaces
    let links = conn.get_links().await?;
    for link in &links {
        println!("{}: {} (up={})", 
            link.ifindex(), 
            link.name_or("?"),
            link.is_up());
    }
    
    // Build ifindex -> name map for resolving routes/addresses
    let names = conn.get_interface_names().await?;
    
    // Modify interface state
    conn.set_link_up("eth0").await?;
    conn.set_link_mtu("eth0", 9000).await?;
    
    // Monitor events
    conn.subscribe(&[RtnetlinkGroup::Link, RtnetlinkGroup::Ipv4Addr])?;
    let mut events = conn.events();
    
    while let Some(result) = events.next().await {
        match result? {
            NetworkEvent::NewLink(link) => println!("Link: {}", link.name_or("?")),
            _ => {}
        }
    }
    
    Ok(())
}
```

## High-Level APIs

### Declarative Network Configuration

Define desired network state and let nlink compute and apply changes:

```rust
use nlink::netlink::config::{NetworkConfig, LinkConfig, LinkType, AddressConfig};

let config = NetworkConfig::new()
    .link(LinkConfig::new("br0").link_type(LinkType::Bridge).up())
    .link(LinkConfig::new("dummy0").link_type(LinkType::Dummy).mtu(9000).up())
    .address(AddressConfig::new("br0", "192.168.100.1/24"));

// Compute diff and apply (idempotent)
config.apply(&conn).await?;
```

### Rate Limiting DSL

Simple bandwidth management without TC complexity. Rates are typed
via [`Rate`](https://docs.rs/nlink/latest/nlink/struct.Rate.html) —
no more bits/sec vs bytes/sec confusion.

```rust
use nlink::Rate;
use nlink::netlink::ratelimit::{RateLimiter, PerHostLimiter};

// Interface-wide rate limiting
let limiter = RateLimiter::new("eth0")
    .egress(Rate::mbit(100))
    .ingress(Rate::mbit(50));
limiter.apply(&conn).await?;

// Per-IP rate limiting
let limiter = PerHostLimiter::new("eth0", Rate::mbit(10))
    .limit_ip("192.168.1.100".parse()?, Rate::mbit(100));
limiter.apply(&conn).await?;
```

### Per-Peer Impairment

Different netem (delay/loss) settings per destination, for emulating
shared L2 segments where each peer-to-peer path needs distinct RTT
and loss characteristics. Recipe at
[`docs/recipes/per-peer-impairment.md`](docs/recipes/per-peer-impairment.md).

```rust
use nlink::{Percent, Rate};
use nlink::netlink::impair::{PerPeerImpairer, PeerImpairment};
use nlink::netlink::tc::NetemConfig;
use std::time::Duration;

PerPeerImpairer::new("vethA-br")
    .impair_dst_ip(
        "172.100.3.18".parse()?,
        NetemConfig::new()
            .delay(Duration::from_millis(15))
            .loss(Percent::new(1.0))
            .build(),
    )
    .impair_dst_ip(
        "172.100.3.19".parse()?,
        PeerImpairment::new(
            NetemConfig::new()
                .delay(Duration::from_millis(40))
                .loss(Percent::new(5.0))
                .build(),
        )
        .rate_cap(Rate::mbit(100)),
    )
    .apply(&conn).await?;
```

### Network Diagnostics

Scan for issues, check connectivity, find bottlenecks:

```rust
use nlink::netlink::diagnostics::Diagnostics;

let diag = Diagnostics::new(conn);

// Full diagnostic scan
let report = diag.scan().await?;
for issue in &report.issues {
    println!("[{:?}] {}", issue.severity, issue.message);
}

// Check connectivity to destination
let report = diag.check_connectivity("8.8.8.8".parse()?).await?;

// Find bottlenecks
if let Some(bottleneck) = diag.find_bottleneck().await? {
    println!("{}: {}", bottleneck.location, bottleneck.recommendation);
}
```

## Documentation

- **[Library Usage](docs/library.md)** - Detailed library examples: namespaces, TC, WireGuard, error handling
- **[Cookbook Recipes](docs/recipes/README.md)** - End-to-end walkthroughs: per-peer impairment, VLAN-aware bridges, bidirectional rate limiting, WireGuard mesh in namespaces, multi-namespace event monitoring, ENOBUFS-resync event loops, connection pools, **define-your-own-GENL-family**
- **[CLI Tools](docs/cli.md)** - ip and tc command reference
- **[Migration Guides](docs/migration_guide/README.md)** - Per-release upgrade notes (what was removed / behaviour-changed / typed-replacement-of)
- **[Examples](crates/nlink/examples/README.md)** - 40+ runnable examples

## Library Modules

| Module | Description |
|--------|-------------|
| `nlink::netlink` | Core netlink: `Connection<Route>`, EventStream, namespace, TC |
| `nlink::netlink::config` | Declarative network configuration |
| `nlink::netlink::nftables::config` | Declarative `NftablesConfig` — diff + atomic apply (0.16+) |
| `nlink::netlink::ratelimit` | High-level rate limiting API |
| `nlink::netlink::diagnostics` | Network diagnostics and issue detection |
| `nlink::netlink::dump_stream` | `DumpStream<T>` — O(1)-memory iteration over large dumps (0.16+) |
| `nlink::netlink::resync` | `ResyncedEvent<T>` + `ResyncMarker` — ENOBUFS overflow recovery (0.16+) |
| `nlink::netlink::pool` | `ConnectionPool<P>` + `PooledConnection<'p, P>` (0.16+) |
| `nlink::netlink::genl` | Generic Netlink: WireGuard, MACsec, MPTCP, Ethtool, nl80211, Devlink, DPLL, net_shaper (TX HW shaping) |
| `nlink::netlink::nexthop` | Nexthop objects and ECMP groups (Linux 5.3+) |
| `nlink::netlink::mpls` | MPLS routes and encapsulation |
| `nlink::netlink::srv6` | SRv6 segment routing |
| `nlink::netlink::fdb` | Bridge FDB management |
| `nlink::netlink::bridge_vlan` | Bridge VLAN filtering |
| `nlink::netlink::uevent` | Device hotplug events: `Connection<KobjectUevent>` |
| `nlink::netlink::connector` | Process lifecycle events: `Connection<Connector>` |
| `nlink::netlink::netfilter` | Connection tracking: `Connection<Netfilter>` |
| `nlink::netlink::nftables` | nftables management + multicast events: `Connection<Nftables>` |
| `nlink::netlink::xfrm` | IPsec SA/SP management: `Connection<Xfrm>` (+ IPsec offload, 0.16+) |
| `nlink::netlink::fib_lookup` | FIB route lookups: `Connection<FibLookup>` |
| `nlink::netlink::audit` | Linux Audit subsystem: `Connection<Audit>` |
| `nlink::netlink::selinux` | SELinux events: `Connection<SELinux>` |
| `nlink::macros` | Proc-macro derives — define your own GENL family in ~30 lines (0.16+; re-exported from `nlink-macros`) |
| `nlink::sockdiag` | Socket diagnostics: `Connection<SockDiag>` (feature: `sockdiag`) |
| `nlink::util` | Parsing utilities, address helpers, name resolution |
| `nlink::tuntap` | TUN/TAP devices (feature: `tuntap`) |

## Project Status

The library API is production-ready for network monitoring and configuration.

**Implemented:**

- Core netlink socket and connection handling
- Link operations (show, add, del, set) with 20+ link types
- Address, route, neighbor, and rule operations
- Event monitoring (link, address, route, neighbor, TC)
- TC qdisc operations with 18 typed qdisc kinds (every kind has `parse_params`)
- TC class management with typed builders (HTB, HFSC, DRR, QFQ)
- TC filter (9 typed kinds, all `parse_params`-driven) and action (14 typed kinds) support
- Standalone shared-action CRUD on `Connection<Route>` (typed `add_action` / `del_action` / `get_action` / `dump_actions`)
- TC filter chains for complex classification
- Network namespace support
- Tunnel management (GRE, IPIP, SIT, VTI, VXLAN, Geneve)
- WireGuard, MACsec, MPTCP configuration via Generic Netlink
- Nexthop objects and ECMP groups (Linux 5.3+)
- MPLS routes and encapsulation
- SRv6 segment routing and local SIDs
- Bridge FDB and VLAN filtering
- Declarative network configuration
- Rate limiting DSL
- Network diagnostics
- VRF and XFRM/IPSec support
- Bond interface management with typed modes and slave info
- nftables firewall management (tables, chains, rules, sets, NAT, match expressions)
- nl80211 WiFi management (scan, connect, monitor)
- Devlink hardware device management (ports, health, firmware flash)
- BPF program attachment to TC hooks
- Socket statistics: summary mode, kill mode, expression filters
- Netlink batching for bulk operations
- Operation timeouts
- Ethtool configuration and event monitoring
- Async GENL namespace connections (WireGuard, MACsec, MPTCP, Ethtool, nl80211, Devlink)
- Interface name validation in link builders
- Typed error promotion (InterfaceNotFound, QdiscNotFound) with operation context
- Name-based address operations (add_address_by_name, replace_address_by_name)
- Bond/bridge enslavement helper (enslave/enslave_by_index)

**New in 0.17:**

- **Default 30-second operation timeout on every `Connection<P>`**
  — every netlink round-trip is wrapped in a tokio timeout so a
  kernel that never responds surfaces as `Error::Timeout`
  instead of hanging the caller forever. Override per-Connection
  with `.timeout(Duration)`; opt out with `.no_timeout()`.
- **Recv-loop audit across the lib** — every recv-loop now seq-
  filters and routes through the default-timeout, closing the
  "hidden hang" class of bugs that surfaced during the 0.16 cut.
  Canonical recv-loop shape documented in
  [`CLAUDE.md`](CLAUDE.md#recv-loop-shape-canonical).
- **`Bottleneck::score: f64`** — a 0.0..=1.0 normalized severity
  score on `Diagnostics::find_bottleneck()` results, useful for
  sorting in dashboards.
- **`?` propagation for parse errors** — `nlink::Error` now
  carries `From<AddressParseError>` + `From<RouteParseError>`,
  so `NetworkConfig` builder chains drop their `.map_err(…)`
  ceremony.
- **CI observability** — the integration test harness initializes
  a `tracing-subscriber` (via `nlink::lab::init_test_tracing`,
  auto-invoked by `require_root!()`) so the lib's
  `#[tracing::instrument]` spans surface in CI logs.
- **`scripts/cut-release.sh`** — one-shot orchestrator for a
  release cut (pre-flight → CHANGELOG promotion → CI green-gate
  → publish → GitHub release → next-cycle branch) with
  confirmations at every irreversible step.
- **Two breaking changes** in nftables — `Register`
  discriminants switched to canonical `NFT_REG_x` form (was
  `NFT_REG32_xx`), and `NftablesDiff::rules_to_delete` tuple
  now carries the chain name explicitly. See
  [`docs/migration_guide/0.16.0-to-0.17.0.md`](docs/migration_guide/0.16.0-to-0.17.0.md).

**Highlights from 0.16 (shipped 2026-05-25):**

- **`nlink-macros` proc-macro crate** — declare a custom Generic
  Netlink family + typed request/response structs in ~30 lines via
  `#[genl_family(...)]` + `#[derive(GenlMessage / GenlCommand /
  GenlAttribute / GenlEnum / NetlinkAttrs)]` and consume it through
  `Connection::<F>::send_typed(req).await?` / `dump_typed_stream`.
  See [`docs/recipes/define-your-own-genl-family.md`](docs/recipes/define-your-own-genl-family.md).
- **DPLL family** (`Connection<Dpll>`) — kernel 6.7+
  clock-synchronization hardware (SyncE, PTP, GNSS-disciplined
  oscillators). First in-tree dogfood of the nlink-macros stack:
  ~430 lines of declarative Rust for the full family vs ~600+
  lines hand-written per the WireGuard / MACsec / Devlink
  pattern. Includes push-based multicast monitor
  (`subscribe_monitor()` + `DpllEvent` stream via `EventSource`).
  Telco-RAN, time-sync, SmartNIC use case. See
  [`docs/recipes/dpll-monitor.md`](docs/recipes/dpll-monitor.md).
- **`net_shaper` family** (`Connection<NetShaper>`) — kernel 6.13+
  TX hardware shaping: per-NIC, per-queue, or intermediate-node
  bandwidth/burst/priority/weight on shaper-capable drivers
  (Intel `ice` E810/E830, Mellanox `mlx5` ConnectX-7+, Broadcom
  `bnxt`). Second in-tree macro dogfood — ~200 lines of
  declarative Rust for the full family. See
  [`docs/recipes/tx-hw-shaping.md`](docs/recipes/tx-hw-shaping.md).
- **Shared GENL multicast-group resolution** —
  `GenlFamily::mcast_group(name) -> Option<u32>` +
  `Connection::<F>::subscribe_group(name)`. `#[genl_family]`
  populates the map automatically; Devlink/Nl80211/Ethtool
  also refactored to use it (−254 lines of duplicated wire
  parsing).
- Streaming dump API (`dump_stream<T>` + typed wrappers for links/
  routes/neighbors/addresses + qdiscs/classes/filters + XFRM
  SAs/SPs) — O(1) memory iteration on BGP/conntrack/IPsec-scale
  dumps
- `ConnectionPool<P>` + `PooledConnection<'p, P>` for parallel fanout
- ENOBUFS-resync types (`ResyncedEvent<T>` + `ResyncMarker` +
  recipe) for multicast-overflow recovery
- Declarative `NftablesConfig` with atomic single-batch apply
- Nftables multicast event subscription
  (`Connection::<Nftables>::events()`)
- Generic `Connection::<P: AsyncConstructible>::new_async()` —
  collapsed six hand-rolled per-family constructors into one;
  macro-defined families plug in for free
- Devlink rate-limit objects + port-function state
- XFRM IPsec hardware offload (`XFRMA_OFFLOAD_DEV`)
- nftables flowtables + `Expr::FlowOffload`
- `recvmmsg` / `sendmmsg` syscall batching (opt-in
  `syscall_batch` feature — ≥1.5x speedup on dump-heavy
  workloads)
- ext-ack error TLVs parsed into `Error::Kernel::ext_ack`;
  `enable_strict_checking` + `set_ext_ack` sockopts

## Building

Requires Rust 1.95+ (edition 2024).

```bash
cargo build --release
cargo run --release -p ip -- link show
cargo run --release -p tc -- qdisc show
```

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.
