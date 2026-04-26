# Per-Peer Impairment

How to apply different netem (delay/loss/jitter) settings to different
destinations on a single interface.

## When to use this

Use the [`PerPeerImpairer`][impairer] helper when you have a *shared* L2
segment (a bridge, a multipoint radio fabric, a mesh) and want each
member-to-member path to behave differently — e.g. emulating a satellite
hop for one member and a fibre uplink for another, on the same bridge.

Don't use it when:

- A single uniform netem on the interface is enough — apply
  `NetemConfig` directly via `Connection::add_qdisc`.
- You need *bidirectional* impairment that's only configured on one
  side. Filters here match egress on the local interface, so symmetric
  pair impairment requires applying the helper on both ends. See
  [Symmetric vs. asymmetric](#symmetric-vs-asymmetric).

[impairer]: https://docs.rs/nlink/latest/nlink/netlink/impair/struct.PerPeerImpairer.html

## High-level API

```rust
use nlink::netlink::{Connection, Route, namespace};
use nlink::netlink::impair::{PerPeerImpairer, PeerImpairment};
use nlink::netlink::tc::NetemConfig;
use std::time::Duration;

let conn: Connection<Route> = namespace::connection_for("lab-mgmt")?;

use nlink::{Percent, Rate};

PerPeerImpairer::new("vethA-br")
    // Close peer.
    .impair_dst_ip(
        "172.100.3.18".parse()?,
        NetemConfig::new()
            .delay(Duration::from_millis(15))
            .jitter(Duration::from_millis(5))
            .loss(Percent::new(1.0))
            .build(),
    )
    // Far peer with a 100 Mbps cap.
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
    // Subnet-level fallback for the rest of the bridge.
    .default_impairment(NetemConfig::new().delay(Duration::from_millis(2)).build())
    .apply(&conn).await?;
```

`apply()` is *destructive* on the device's root qdisc — it removes any
existing root qdisc first, then installs a fresh tree. Filters and
classes added by other tools at the root will be wiped.

To remove the impairment:

```rust
PerPeerImpairer::new("vethA-br").clear(&conn).await?;
```

`clear()` is idempotent.

## What the helper builds

The recipe is a classful HTB tree with a `cls_flower` filter dispatching
each destination to its own per-peer netem leaf:

```text
vethA-br
└── 1: htb (root)
    └── 1:1 htb (parent — sum of children)
        ├── 1:2 htb -- 10: netem (peer 1)   <- flower(dst=peer1) classid=1:2 prio=100
        ├── 1:3 htb -- 11: netem (peer 2)   <- flower(dst=peer2) classid=1:3 prio=101
        ├── 1:4 htb -- 12: netem (peer 3)   <- flower(dst=peer3) classid=1:4 prio=102
        └── 1:5 htb -- 13: netem (default)  (no filter; HTB default_class=5)
```

### Why HTB and not PRIO

PRIO would be lighter, but:

- PRIO is **strict priority** — band 1 must be empty before band 2
  transmits. With one peer per band, a busy peer would starve a quiet
  one on any link with real contention.
- PRIO has no native default class — the catch-all is determined by
  the priomap and is fragile to express.
- HTB has explicit `default` semantics, no band cap, and matches the
  shape of [`PerHostLimiter`].

[`PerHostLimiter`]: https://docs.rs/nlink/latest/nlink/netlink/ratelimit/struct.PerHostLimiter.html

### Per-class HTB rates

Each class is given `rate = ceil = assumed_link_rate`
(default `DEFAULT_ASSUMED_LINK_RATE` = `Rate::bytes_per_sec(10_000_000_000)`
≈ 80 Gbps) unless the rule has a `rate_cap`. With this large default,
HTB does not throttle in practice, and per-class borrowing through the
parent class lets every peer use its full pipe.

To layer a per-peer rate cap on top of the impairment:

```rust
.impair_dst_ip(
    peer_addr,
    PeerImpairment::new(netem).rate_cap(Rate::mbit(50)),
)
```

Override the default via:

```rust
PerPeerImpairer::new("vethA-br")
    .assumed_link_rate(Rate::gbit(1000)) // 1 Tbps
```

## Symmetric vs. asymmetric

The helper installs filters on the **egress** side of one interface.
A packet from `hq` to `alpha` is impaired only by the qdisc on the
interface it's about to leave.

For symmetric pair impairment (impair the path between two peers, both
directions), apply the helper on **both** ends:

```text
hq-veth        :  PerPeerImpairer::new("hq-veth").impair_dst_ip(alpha_addr, netem)
alpha-veth     :  PerPeerImpairer::new("alpha-veth").impair_dst_ip(hq_addr, netem)
```

The fan-out is the caller's responsibility — typically a
declarative-config layer in the consumer.

## Source matching

`impair_src_ip(...)`, `impair_src_subnet(...)`, and `impair_src_mac(...)`
match on the packet's source instead of destination. Useful when you
want to impair "all traffic from peer X" on its own egress interface
(e.g. its inbound traffic on the bridge port).

## Caveats

### `cls_flower` must be loaded

The helper uses `cls_flower` for classification. It's mainline since
Linux 4.2. If the classifier module is unloaded in the target
namespace, `apply()` returns an `Error::NotSupported` with a
`modprobe cls_flower` hint. nlink does not modprobe on your behalf.

### Apply is destructive

`apply()` calls `del_qdisc(root)` before installing the new tree. Any
operator-installed qdiscs/classes/filters at the root are wiped. The
helper's filters use priorities `100..` to stay clear of the
conventional operator priority range (1..50), but coexistence is not
guaranteed.

### Use `reconcile()` for repeated calls

For long-running consumers (k8s operators, lab controllers,
config-tick loops) prefer **`reconcile()`** over re-running `apply()`.
It dumps the live tree, diffs against the desired one, and emits the
minimum set of `add_*` / `change_*` / `del_*` operations. When nothing
has changed, it makes **zero** kernel calls; when only one peer's
delay changes, it `change_qdisc`'s a single leaf.

```rust
loop {
    let desired = build_impairer_from_config(&latest_config);
    let report = desired.reconcile(&conn).await?;
    if !report.is_noop() {
        info!(
            "reconcile: +{} ~{} -{} (root_modified={}, default_modified={})",
            report.rules_added,
            report.rules_modified,
            report.rules_removed,
            report.root_modified,
            report.default_modified,
        );
        for stale in &report.stale_removed {
            info!("removed stale {}: {}", stale.kind, stale.handle);
        }
        for um in &report.unmanaged {
            warn!("unmanaged {}: {} (left alone)", um.kind, um.handle);
        }
    }
    tokio::time::sleep(Duration::from_secs(10)).await;
}
```

Key contract differences from `apply()`:

- **`apply()`**: destructive rebuild. Brief packet-drop window. Use
  for "set up from scratch", typically once per interface lifetime.
- **`reconcile()`**: non-destructive convergence. Idempotent.
  Preferred for reconcile loops.

If the live root qdisc is the wrong kind (someone else installed a
non-HTB root), `reconcile()` returns an error by default. Pass
`ReconcileOptions::with_fallback_to_apply(true)` to instead trigger a
destructive rebuild via `apply()` — opt-in because surprising
auto-destruction is a bad default for a reconcile-loop verb.

`reconcile_dry_run()` returns the same `ReconcileReport` without
making kernel calls — useful for preview/validation in CI.

### Helper resolves ifindex once

When constructed via `PerPeerImpairer::new(name)`, the interface name
is resolved exactly once at the start of `apply()`. Subsequent TC
operations use that ifindex, which is namespace-safe and avoids reading
`/sys/class/net/<name>/ifindex` repeatedly. To avoid the resolution
entirely (e.g. in a tight reconcile loop), use
`PerPeerImpairer::new_by_index(ifindex)`.

### `clear()` is scoped to root egress

It deletes the device's root qdisc only. Ingress / clsact qdiscs and
their filters are not touched.

## Hand-rolled recipe

If you need a custom topology — e.g. mixed per-peer rates and shared
parent rate caps, or BPF dispatching — here's the minimum to do the
same thing manually with nlink primitives:

```rust
use nlink::{Percent, Rate, TcHandle};
use nlink::netlink::{Connection, Route};
use nlink::netlink::filter::FlowerFilter;
use nlink::netlink::tc::{HtbClassConfig, HtbQdiscConfig, NetemConfig};
use std::net::Ipv4Addr;
use std::time::Duration;

let conn = Connection::<Route>::new()?;
let dev = "vethA-br";

// Clean slate.
let _ = conn.del_qdisc(dev, TcHandle::ROOT).await;

// Root HTB with default class id pointing at the catch-all.
conn.add_qdisc_full(dev, TcHandle::ROOT, Some(TcHandle::major_only(1)),
    HtbQdiscConfig::new().default_class(0xff).build()
).await?;

// Parent class.
let link_rate = Rate::bytes_per_sec(10_000_000_000);
conn.add_class(dev, TcHandle::major_only(1), TcHandle::new(1, 1),
    HtbClassConfig::new(link_rate).ceil(link_rate).build()
).await?;

// One peer.
conn.add_class(dev, TcHandle::new(1, 1), TcHandle::new(1, 2),
    HtbClassConfig::new(link_rate).ceil(link_rate).build()
).await?;

conn.add_qdisc_full(dev, TcHandle::new(1, 2), Some(TcHandle::major_only(0xa)),
    NetemConfig::new()
        .delay(Duration::from_millis(15))
        .loss(Percent::new(1.0))
        .build()
).await?;

conn.add_filter(dev, TcHandle::major_only(1),
    FlowerFilter::new()
        .classid(TcHandle::new(1, 2))
        .priority(100)
        .dst_ipv4(Ipv4Addr::new(172, 100, 3, 18), 32)
        .build()
).await?;

// ...repeat for additional peers, then default class 1:ff.
```

The helper exists so consumers don't have to repeat this; reach for it
unless you genuinely need the flexibility above.
