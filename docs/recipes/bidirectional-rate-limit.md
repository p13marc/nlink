# Bidirectional Rate Limiting

How to shape both egress (upload) and ingress (download) on a single
interface — and why ingress shaping needs an extra device (IFB).

## When to use this

- Simulating a constrained WAN link in a lab (e.g. "this veth is a
  50/10 Mbps DSL").
- Enforcing per-interface bandwidth caps on a host or VM, symmetric or
  asymmetric.
- Pairing with [`PerHostLimiter`](./per-peer-impairment.md) when you
  want both a device cap and a per-flow breakdown.

Don't use it when:

- You only need to shape egress — the `RateLimiter::new(dev).egress(rate)`
  subset is simpler.
- You want to rate-limit *per host* or *per port*, not per interface —
  reach for [`PerHostLimiter`](https://docs.rs/nlink/latest/nlink/netlink/ratelimit/struct.PerHostLimiter.html).

## Why ingress shaping needs IFB

Traffic control's natural shape is egress: packets sit in a qdisc
waiting for the driver to clock them out, and a shaper drains that
queue at a controlled rate. Ingress has no symmetric queue — packets
arrive and are processed synchronously — so there's nothing for an
egress-style shaper to drain.

The canonical workaround is an IFB (Intermediate Functional Block)
device: a virtual interface whose *egress* qdisc stands in for
*ingress* shaping on the real device. You attach an `ingress` qdisc +
`matchall` filter + `mirred` action on the real device that redirects
every ingress packet to `ifb_<dev>`, then install an HTB/fq_codel shaper
on the IFB's egress. Result: ingress packets now flow through a real
egress shaper before reaching the kernel, which is the only way to get
predictable download-side caps on Linux.

`RateLimiter::new(...).ingress(rate).apply(&conn)` wires all of this
up automatically — you never have to build the pipeline by hand unless
you need custom filter predicates.

```text
          ingress                           egress
     eth0 ─────────► root qdisc (ingress)       eth0 ◄────── root qdisc (HTB)
              └── matchall filter                   └── egress shaper +
                     └── mirred → ifb_eth0                fq_codel (AQM)
                             │
                             ▼
                    ifb_eth0 egress qdisc (HTB) ◄── actual ingress shaping
                             │
                             └── fq_codel (AQM)
                             │
                             ▼
                         (to kernel)
```

## Code: symmetric 100 Mbps

```no_run
# async fn demo() -> nlink::Result<()> {
use nlink::Rate;
use nlink::netlink::{Connection, Route};
use nlink::netlink::ratelimit::RateLimiter;
use std::time::Duration;

let conn = Connection::<Route>::new()?;

RateLimiter::new("eth0")
    .egress(Rate::mbit(100))      // upload cap
    .ingress(Rate::mbit(100))     // download cap, auto-wires IFB
    .latency(Duration::from_millis(20))
    .apply(&conn)
    .await?;
# Ok(())
# }
```

## Code: asymmetric 50/10 Mbps (DSL-style)

```rust,ignore
RateLimiter::new("eth0")
    .egress(Rate::mbit(10))
    .ingress(Rate::mbit(50))
    .burst_to(Rate::mbit(15))     // ceil for upload; download uses its own ceil
    .latency(Duration::from_millis(30))
    .apply(&conn)
    .await?;
```

`burst_to` sets the HTB `ceil` so the shaper can briefly overshoot the
committed rate before clamping — important for interactive traffic on
slow links.

## Code: teardown

```rust,ignore
// Removes root qdiscs on both eth0 *and* ifb_eth0, and deletes the IFB.
RateLimiter::new("eth0").remove(&conn).await?;
```

## Combining with per-host limits

`RateLimiter` shapes the *device* bidirectionally. For "each client IP
gets 10 Mbps but the interface overall caps at 1 Gbps", stack
`PerHostLimiter` on egress + `RateLimiter` on ingress:

```rust,ignore
use nlink::netlink::ratelimit::{PerHostLimiter, RateLimiter};
use nlink::Rate;

// Per-host egress shaping (which itself uses HTB + classful filters).
PerHostLimiter::new("eth0", Rate::mbit(10))
    .limit_ip("192.168.1.42".parse()?, Rate::mbit(100))
    .apply(&conn).await?;

// Device-level ingress cap (not amenable to per-host on download
// without matching on conntrack; keep it simple).
RateLimiter::new("eth0").ingress(Rate::mbit(1_000)).apply(&conn).await?;
```

Note: `RateLimiter::apply` is destructive on the root qdiscs of the
device and its IFB. If you've already built a custom TC tree on the
same interface, apply `RateLimiter` first and then layer custom
filters/classes on top, not the other way round.

## Verification

Dump the qdisc tree to confirm:

```rust,ignore
use nlink::TcHandle;

let qdiscs = conn.get_qdiscs_by_name("eth0").await?;
for q in &qdiscs {
    println!("eth0: {} handle={}", q.kind().unwrap_or("?"), q.handle_str());
}

let ifb_qdiscs = conn.get_qdiscs_by_name("ifb_eth0").await?;
for q in &ifb_qdiscs {
    println!("ifb_eth0: {} handle={}", q.kind().unwrap_or("?"), q.handle_str());
}
```

Expect:

- `eth0`: root qdisc `htb`, plus an `ingress` qdisc at parent
  `ffff:fff1` (the ingress hook).
- `ifb_eth0`: root qdisc `htb` with an `fq_codel` child.

Or side-by-side against iproute2:

```text
tc qdisc show dev eth0
tc qdisc show dev ifb_eth0
```

## Caveats

- The IFB device is named `ifb_<dev>` by convention in our helper. If
  the name collides with something you already have (another IFB or a
  dummy), teardown will refuse to delete an unfamiliar interface.
  Remove the collision first.
- `ingress` qdisc requires the `sch_ingress` module, and IFB requires
  `ifb.ko`. Both are typically built into mainline kernels, but stripped
  kernels (embedded, some cloud images) may be missing them.
- Ingress accounting at the qdisc level is less accurate than egress
  because `mirred` runs under `RCU` without packet-level queue
  backpressure — microbursts can briefly exceed the configured rate.
  For TCP workloads this is usually fine; for strict contract
  enforcement, measure downstream.
- Shaping operates below the socket buffer. If your tenant opens a
  10 Gbps connection and you shape them to 100 Mbps, the kernel will
  happily buffer the difference — make sure your memory limits + AQM
  latency target (`.latency(Duration)`) are tight enough that the
  queue drains fast.

## Hand-rolled equivalent

If you need non-default filters (e.g. "only shape traffic matching a
specific flow label"), skip `RateLimiter` and construct the pipeline
manually. Sketch:

```rust,ignore
use nlink::netlink::link::IfbLink;
use nlink::netlink::tc::{IngressConfig, HtbQdiscConfig, HtbClassConfig, FqCodelConfig};
use nlink::netlink::filter::MatchallFilter;
use nlink::netlink::action::MirredAction;
use nlink::{Rate, TcHandle};

// 1. Create and up the IFB.
conn.add_link(IfbLink::new("ifb_eth0")).await?;
conn.set_link_up("ifb_eth0").await?;

// 2. Egress shaping on the real device: HTB root + class.
conn.add_qdisc_full(
    "eth0", TcHandle::ROOT, Some(TcHandle::major_only(1)),
    HtbQdiscConfig::new().default_class(0x10).build(),
).await?;
conn.add_class_config(
    "eth0", TcHandle::major_only(1), TcHandle::new(1, 0x10),
    HtbClassConfig::new(Rate::mbit(10)).ceil(Rate::mbit(10)).build(),
).await?;

// 3. Ingress qdisc + mirred redirect to IFB.
conn.add_qdisc("eth0", IngressConfig::new()).await?;
conn.add_filter(
    "eth0", TcHandle::INGRESS,
    MatchallFilter::new().actions(
        nlink::netlink::action::ActionList::new()
            .with(MirredAction::redirect_egress("ifb_eth0")),
    ).build(),
).await?;

// 4. Egress shaping on the IFB — same HTB + fq_codel pattern.
// ...
```

Everything `RateLimiter` does is built from public APIs — look at
`crates/nlink/src/netlink/ratelimit.rs` for the full construction.

## See also

- [`RateLimiter`](https://docs.rs/nlink/latest/nlink/netlink/ratelimit/struct.RateLimiter.html)
- [`PerHostLimiter`](https://docs.rs/nlink/latest/nlink/netlink/ratelimit/struct.PerHostLimiter.html)
- [Per-peer impairment recipe](./per-peer-impairment.md) — stacks
  cleanly with `RateLimiter` when you want shaping *plus* emulated
  loss/delay.
- Kernel: `tc-htb(8)`, `tc-fq_codel(8)`, `tc-mirred(8)`,
  `Documentation/networking/ifb.rst`.
