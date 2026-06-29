# Cap TX bandwidth on a specific queue (or SR-IOV VF)

Use `Connection<NetShaper>` to install hardware shapers — per
interface, per TX queue, or under an intermediate scheduler node.
Bandwidth caps, burst limits, scheduling priority, and round-robin
weights ride the same kernel-generic `net-shaper` Generic Netlink
family that telcos, hyperscalers, and SmartNIC operators use to
program in-NIC schedulers without leaving netlink for `ethtool` or
driver-private ioctls.

## When to use this

- You're rate-limiting an SR-IOV VF (multi-tenant host: cap one
  guest's TX so it can't starve the others).
- You're enforcing per-queue priority on a multi-queue NIC where
  one queue carries control plane and the rest carry bulk data.
- You're building a service-mesh sidecar or eBPF orchestrator
  that needs deterministic per-flow caps without touching `tc`.
- You're cross-checking a driver's net-shaper implementation
  against the UAPI without writing throwaway C.

If you just want to see what's wired up on the host, run the
example —
`cargo run -p nlink --example genl_net_shaper -- show <ifname>` —
and read no further.

## Kernel requirements

- **Linux 6.13+** for the family itself
  ([`include/uapi/linux/net_shaper.h`](https://elixir.bootlin.com/linux/v6.13/source/include/uapi/linux/net_shaper.h)).
- A driver that registers shaper ops with the kernel. Intel `ice`
  (E810 / E830 + recent firmware), Mellanox `mlx5` (ConnectX-7+),
  and Broadcom `bnxt` are the typical in-tree consumers. Stock
  loopback / virtio / many older drivers return `EOPNOTSUPP` on
  every `net-shaper` request — that's the signal to fall back to
  `tc` HTB or driver-private mechanisms.

## Permissions

`get` and `cap-get` are unprivileged. `set`, `delete`, and
`group` require `CAP_NET_ADMIN`. `Error::is_permission_denied()`
detects EPERM cleanly; the example shows the idiomatic handling.

## High-level approach

1. Construct `Connection::<NetShaper>::new_async().await?`.
   `Error::is_not_found()` if the kernel is too old (< 6.13) or
   the family wasn't enabled (`CONFIG_NET_SHAPER=n`).
2. **Always check caps first.** Drivers vary widely in which
   attributes they accept at each scope (some support `bw_max`
   on queues but not nodes, others reject `weight` entirely).
   Call `get_caps(ifindex, scope)` and gate your `set_shaper`
   on the returned `support_*` bools.
3. **Build the handle.** A shaper is identified by `(scope, id)`:
   `Netdev` scope (id always 0) is the per-interface root,
   `Queue` (id = TX queue index) is per-queue, `Node` is an
   intermediate scheduler node returned by `group`.
4. **`set_shaper`** with the typed builder; chain only the fields
   you want to change. The kernel preserves prior values for
   omitted attributes on an existing shaper, or applies driver
   defaults when creating one.

## Code — rate-limit one TX queue

```rust,no_run
use nlink::netlink::{
    genl::net_shaper::{
        NetShaper, NetShaperHandle, NetShaperMetric, NetShaperScope, NetShaperSetRequest,
    },
    Connection,
};

# async fn run() -> nlink::Result<()> {
let conn = match Connection::<NetShaper>::new_async().await {
    Ok(c) => c,
    Err(e) if e.is_not_found() => {
        tracing::warn!("net-shaper family not registered; kernel < 6.13");
        return Ok(());
    }
    Err(e) => return Err(e),
};

let ifindex: u32 = 5;  // resolved via Connection::<Route>::get_link_by_name

// Step 1: confirm the driver supports the attributes we're about to set.
let caps = conn.get_caps(ifindex, NetShaperScope::Queue).await?;
if !caps.support_metric_bps || !caps.support_bw_max || !caps.support_burst {
    tracing::warn!(
        "driver missing required caps: bps={} bw_max={} burst={}",
        caps.support_metric_bps, caps.support_bw_max, caps.support_burst,
    );
    return Ok(());
}

// Step 2: install a 1 Gbit/s cap on TX queue 0 with a 64 KiB burst.
let handle = NetShaperHandle::queue(0);
conn.set_shaper(
    NetShaperSetRequest::new(ifindex, handle)
        .metric(NetShaperMetric::Bps)
        .bw_max(1_000_000_000)
        .burst(1 << 16)
        .priority(0),
)
.await?;
# Ok(())
# }
```

## Code — read every shaper installed on an interface

```rust,no_run
use nlink::netlink::{
    genl::net_shaper::NetShaper, Connection,
};
use tokio_stream::StreamExt;

# async fn run(ifindex: u32) -> nlink::Result<()> {
let conn = Connection::<NetShaper>::new_async().await?;
let mut stream = conn.dump_shapers(ifindex).await?;
while let Some(shaper) = stream.next().await {
    let shaper = match shaper {
        Ok(s) => s,
        Err(e) if e.is_not_supported() => {
            // Driver doesn't implement net-shaper for this interface.
            // Fall back to tc HTB or driver-private knobs.
            break;
        }
        Err(e) => return Err(e),
    };
    tracing::info!(
        handle = ?shaper.handle,
        bw_max = ?shaper.bw_max,
        priority = ?shaper.priority,
        "shaper",
    );
}
# Ok(())
# }
```

The dump is **per-interface** — pass the same `ifindex` you'd
pass to `dump_shapers`. To enumerate across every interface, use
the `dump_links` API from `Connection<Route>` and call
`dump_shapers` once per interface.

## Code — driver capability discovery

```rust,no_run
use nlink::netlink::{
    genl::net_shaper::{NetShaper, NetShaperScope}, Connection,
};
use tokio_stream::StreamExt;

# async fn run(ifindex: u32) -> nlink::Result<()> {
let conn = Connection::<NetShaper>::new_async().await?;
let mut caps = conn.dump_caps(ifindex).await?;
while let Some(c) = caps.next().await {
    let c = c?;
    tracing::info!(
        scope = ?c.scope,
        metrics_bps = c.support_metric_bps,
        metrics_pps = c.support_metric_pps,
        nesting = c.support_nesting,
        bw_min = c.support_bw_min,
        bw_max = c.support_bw_max,
        burst = c.support_burst,
        priority = c.support_priority,
        weight = c.support_weight,
        "shaper caps",
    );
}
# Ok(())
# }
```

`dump_caps` yields one [`NetShaperCapsReply`] per scope the
driver supports. The reply's flag fields are **presence
attributes** on the wire — the kernel emits the
`NET_SHAPER_A_CAPS_SUPPORT_*` attribute with a zero-byte payload
to mean "yes," omits it to mean "no." nlink parses both shapes
into the obvious `bool`.

## Hierarchical shaping (advanced)

The `NET_SHAPER_CMD_GROUP` operation atomically creates (or updates)
a `Node`-scope shaper and attaches the listed `Queue`-scope leaf
shapers underneath it — "rate-limit this set of queues collectively
to N Gbit/s." Use [`group_shapers`][grp] with a
[`NetShaperGroupRequest`][greq] + one [`NetShaperLeaf`][leaf] per queue:

[grp]: https://docs.rs/nlink/latest/nlink/netlink/struct.Connection.html#method.group_shapers
[greq]: https://docs.rs/nlink/latest/nlink/netlink/genl/net_shaper/struct.NetShaperGroupRequest.html
[leaf]: https://docs.rs/nlink/latest/nlink/netlink/genl/net_shaper/struct.NetShaperLeaf.html

```rust,no_run
# use nlink::netlink::{genl::net_shaper::{NetShaper, NetShaperGroupRequest, NetShaperLeaf}, Connection};
# async fn run(ifindex: u32) -> nlink::Result<()> {
let conn = Connection::<NetShaper>::new_async().await?;

// Group TX queues 0..=2 under a new node, collectively capped at 1 Gbps.
// Omitting the node handle asks the kernel to allocate one and return it.
let node = conn.group_shapers(
    NetShaperGroupRequest::new(ifindex)
        .bw_max(1_000_000_000)
        .leaf(NetShaperLeaf::queue(0))
        .leaf(NetShaperLeaf::queue(1))
        .leaf(NetShaperLeaf::queue(2)),
).await?;

// `node` is the kernel-assigned Node handle — pass it to a later
// group() call (`.node(node)`) to add more leaves, or to set_shaper
// to retune the aggregate cap.
println!("created scheduler node {node:?}");
# Ok(())
# }
```

Per-leaf `priority` / `weight` ride along
(`NetShaperLeaf::queue(0).priority(1).weight(4)`). The node shaper
must be `Node` or `Netdev` scope and the driver must report
`support_nesting` at that scope (check [`get_caps`](#code--driver-capability-discovery)
first). The operation is atomic: on failure nothing is applied.

## Error handling

```rust,no_run
use nlink::netlink::{genl::net_shaper::{NetShaper, NetShaperHandle}, Connection};
# async fn run(conn: &Connection<NetShaper>, ifindex: u32) -> nlink::Result<()> {
match conn.get_shaper(ifindex, NetShaperHandle::queue(0)).await {
    Ok(s) => tracing::info!(?s, "queue 0 shaper"),
    Err(e) if e.is_not_supported() => {
        tracing::info!("driver doesn't expose shapers for this interface");
    }
    Err(e) if e.is_not_found() => {
        tracing::info!("no shaper installed on queue 0");
    }
    Err(e) if e.is_permission_denied() => {
        tracing::error!("CAP_NET_ADMIN required even for read on this kernel?");
    }
    Err(e) => return Err(e),
}
# Ok(())
# }
```

## See also

- [`crates/nlink/examples/genl/net_shaper.rs`](../../crates/nlink/examples/genl/net_shaper.rs)
  — runnable enumeration of shapers + caps on a given interface.
- [`docs/recipes/define-your-own-genl-family.md`](define-your-own-genl-family.md)
  — net_shaper is the **second** in-tree dogfood of the macro
  stack (after [DPLL](dpll-monitor.md)); both families declare
  in <250 lines of macro-derived Rust each.
- [`docs/recipes/bidirectional-rate-limit.md`](bidirectional-rate-limit.md)
  — `tc` HTB-based rate limiting (software). Use this when the
  driver doesn't ship net-shaper support.
- `CHANGELOG.md ## [0.16.0]` (`net_shaper` section) — design
  rationale + the macro-derived family declaration shape.
- Kernel docs:
  [`Documentation/netlink/specs/net_shaper.yaml`](https://docs.kernel.org/userspace-api/netlink/specs.html)
  — authoritative YNL spec.
