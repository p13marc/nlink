# Per-cgroup traffic classification (net_cls + cls_cgroup)

Steer outbound traffic into per-cgroup HTB classes using the
`net_cls` cgroup controller and the typed `CgroupFilter` (the
`cls_cgroup` classifier). Useful for per-tenant bandwidth
shaping, per-container QoS, and traffic accounting that needs to
align with process boundaries rather than just IP/port tuples.

## When to use this

`CgroupFilter` is the right tool when:

- Process / container identity is the meaningful classification
  axis, and shaping by IP / port doesn't fit (PID-routed
  workloads, multi-tenant userspace).
- The `net_cls` cgroup v1 controller is available and you can
  arrange for processes to be added to it (containers, systemd
  slices, or direct `cgroup.procs` writes).
- Shaping is **egress** — `cls_cgroup` reads the originating
  socket's cgroup classid; on ingress that information isn't
  available.

For other classification angles see:
- IP/port: `FlowerFilter` (recipe:
  [`bidirectional-rate-limit`](bidirectional-rate-limit.md)).
- Per-destination L2: `PerPeerImpairer` (recipe:
  [`per-peer-impairment`](per-peer-impairment.md)).

> **cgroup v1 only.** `net_cls` is not exposed in cgroup v2;
> there's no v2 equivalent today. If your hosts are pure-v2
> (most modern systemd setups), you'll need a hybrid mount or
> a different classification scheme.

## High-level approach

```
┌──────────────────────────────────────────────────┐
│ /sys/fs/cgroup/net_cls/                          │
│   ├── tenant-gold/                               │
│   │     net_cls.classid = 0x00010010 (= 1:10)    │
│   │     cgroup.procs    = <PIDs>                 │
│   └── tenant-silver/                             │
│         net_cls.classid = 0x00010020 (= 1:20)    │
│         cgroup.procs    = <PIDs>                 │
└──────────────────────────────────────────────────┘
                       │
                       ▼ socket carries classid; tc reads it
┌──────────────────────────────────────────────────┐
│ tc qdisc add dev eth0 root handle 1: htb         │
│ tc class add dev eth0 parent 1: classid 1:1      │
│   htb rate 1gbit                                 │
│ tc class add dev eth0 parent 1:1 classid 1:10    │
│   htb rate 100mbit ceil 200mbit  ← gold          │
│ tc class add dev eth0 parent 1:1 classid 1:20    │
│   htb rate  10mbit ceil 100mbit  ← silver        │
│ tc filter add dev eth0 parent 1: cgroup          │
│                                                  │
│ ↑ CgroupFilter — looks up the originating        │
│   socket's net_cls.classid and uses it as the    │
│   target HTB classid. No further selectors;      │
│   the cgroup IS the selector.                    │
└──────────────────────────────────────────────────┘
```

## Code

```rust
use nlink::netlink::action::GactAction;
use nlink::netlink::filter::CgroupFilter;
use nlink::netlink::tc::{HtbClassConfig, HtbQdiscConfig};
use nlink::netlink::{Connection, Route};
use nlink::{Rate, TcHandle};

# async fn example() -> nlink::Result<()> {
let conn = Connection::<Route>::new()?;
let dev = "eth0";

// Root HTB qdisc.
conn.add_qdisc_full(
    dev,
    TcHandle::ROOT,
    Some(TcHandle::major_only(1)),
    HtbQdiscConfig::new().default_class(0xFFFF).build(),
).await?;

// Root class — total bandwidth budget.
conn.add_class_config(
    dev,
    TcHandle::major_only(1),
    TcHandle::new(1, 1),
    HtbClassConfig::new(Rate::gbit(1)).build(),
).await?;

// Gold tier.
conn.add_class_config(
    dev,
    TcHandle::new(1, 1),
    TcHandle::new(1, 0x10),
    HtbClassConfig::new(Rate::mbit(100))
        .ceil(Rate::mbit(200))
        .build(),
).await?;

// Silver tier.
conn.add_class_config(
    dev,
    TcHandle::new(1, 1),
    TcHandle::new(1, 0x20),
    HtbClassConfig::new(Rate::mbit(10))
        .ceil(Rate::mbit(100))
        .build(),
).await?;

// One CgroupFilter at the root — it reads each packet's socket
// classid and uses it as the target HTB classid directly. No
// per-tenant filter needed.
conn.add_filter_full(
    dev,
    TcHandle::major_only(1),
    None,
    0x0003,         // ETH_P_ALL
    100,            // priority
    CgroupFilter::new().build(),
).await?;
# Ok(())
# }
```

That's the entire TC-side setup. The cgroup-side wiring (mounting
`net_cls`, writing `net_cls.classid`, adding processes) is
out-of-band — usually a one-shot at host bring-up.

## Cgroup-side wiring (out-of-band)

Skip this if your container runtime already does it (Docker /
podman / k8s with the `net_cls` controller enabled write
classids for you).

```bash
# Mount net_cls (cgroup v1)
sudo mkdir -p /sys/fs/cgroup/net_cls
sudo mount -t cgroup -o net_cls none /sys/fs/cgroup/net_cls

# Define tiers
sudo mkdir /sys/fs/cgroup/net_cls/tenant-gold
sudo mkdir /sys/fs/cgroup/net_cls/tenant-silver

# Set classids — these MUST match the HTB classids exactly
echo 0x00010010 | sudo tee /sys/fs/cgroup/net_cls/tenant-gold/net_cls.classid
echo 0x00010020 | sudo tee /sys/fs/cgroup/net_cls/tenant-silver/net_cls.classid

# Add a process
echo $PID | sudo tee /sys/fs/cgroup/net_cls/tenant-gold/cgroup.procs
```

The classid format: `0xMMMMmmmm` where `MMMM` is the HTB major
(here `0x0001` = `1:`) and `mmmm` is the minor. So the gold tier
is class `1:10` (= `0x0010`), encoded as `0x00010010`.

## Verify

```bash
# What classids are configured?
$ sudo cat /sys/fs/cgroup/net_cls/tenant-gold/net_cls.classid
65552                            # 0x00010010

# What's actually classified?
$ sudo tc -s class show dev eth0
class htb 1:10 parent 1:1 rate 100Mbit ceil 200Mbit
 Sent 1234567 bytes 8901 pkt    # ← traffic from the cgroup
```

After traffic flows, the per-class byte/packet counters confirm
the cgroup classifier is steering correctly.

## Combining with ematch

`CgroupFilter` is the simplest case (one filter, kernel does the
classid→class mapping). For more complex steering — e.g. "shape
gold tenant's HTTP traffic differently from their SSH" — pair
the cgroup classid with an L4 match using `BasicFilter`'s
ematch tree:

```rust
use nlink::netlink::filter::{
    BasicFilter, CmpAlign, CmpLayer, CmpOp, Ematch, EmatchCmp,
};

// Match cgroup-classified gold-tier (classid 1:10) +
// destination port 80.
let f = BasicFilter::new()
    .classid(TcHandle::new(1, 0x100))   // direct to a sub-class
    .ematch(Ematch::cmp(EmatchCmp {
        layer: CmpLayer::Network,
        align: CmpAlign::U8,
        offset: 9,                       // IP proto byte
        mask: 0xff,
        value: 6,                        // TCP
        op: CmpOp::Eq,
        trans: false,
    }))
    .build();
```

(The cgroup match itself doesn't have a clean ematch shape today
in nlink — `cls_cgroup` is the canonical way to read the classid.
File an issue if a `meta` ematch on `skb->cgroup_classid` is
worth typing.)

## Caveats

### cgroup v2

`net_cls` doesn't exist in v2. Modern systemd defaults to v2.
Workarounds:
- Hybrid mount: keep `net_cls` mounted as v1 alongside the v2
  hierarchy. Most distros support this; check
  `/sys/fs/cgroup/cgroup.controllers` and the systemd
  `Delegate=` semantics.
- eBPF: write a `cgroup_skb/egress` program that sets the
  classid (or uses `bpf_redirect` etc.). Out of scope for this
  recipe; see the `BpfFilter` typed config + a future BPF recipe.

### classid scope

`net_cls.classid` is **inherited** at fork time. A process
re-parented after creation keeps its original cgroup's classid
unless explicitly moved. For long-running daemons this is
usually fine; for short-lived shells / containers verify before
relying on it.

### Egress only

`cls_cgroup` reads `skb->sk` — the originating socket. On the
ingress path the kernel doesn't yet know which (if any) socket
will receive the packet. Use a different classifier for ingress
shaping (or accept that ingress is a different problem).

### IFB for "ingress" shaping

The standard "shape ingress by mirroring to IFB" trick still
works; just install the cgroup filter on the IFB device's egress.
See [`bidirectional-rate-limit`](bidirectional-rate-limit.md) for
the IFB redirect pattern.

## See also

- `nlink::netlink::filter::CgroupFilter` — typed `cls_cgroup`
  wrapper (`with_action`, `chain`, `parse_params`).
- `nlink::netlink::filter::BasicFilter` — typed `cls_basic` with
  ematch tree support (`Ematch`, `EmatchCmp`, `EmatchU32`).
- `nlink::netlink::tc::HtbQdiscConfig` / `HtbClassConfig` — the
  typed HTB shaping side.
- Linux `Documentation/admin-guide/cgroup-v1/net_cls.rst` for
  the kernel-side concept.
