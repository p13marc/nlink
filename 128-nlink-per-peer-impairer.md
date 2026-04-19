---
to: nlink maintainers
from: nlink-lab team
subject: Per-peer netem impairment — proposed helper + recipe confirmation
nlink version surveyed: 0.12.2
date: 2026-04-19
---

# Per-peer impairment on shared networks — nlink proposal

## TL;DR

We were going to ask for new TC APIs to support per-destination
impairment on shared bridge networks. After surveying nlink 0.12.2 we
found that **every primitive is already there** — `add_qdisc`,
`add_class`, `add_filter`, `U32Filter`/`FlowerFilter` builders,
`PrioConfig`, `NetemConfig`, `HtbQdiscConfig`, handle parsing, and
`get_qdiscs`/`get_classes`/`get_filters` enumeration.

What we'd like from the nlink team:

1. **Primary ask:** a `PerPeerImpairer` helper in `nlink::netlink::ratelimit`
   (or a new `nlink::netlink::impair`) analogous to the existing
   `PerHostLimiter`. It's the same TC pattern (root classful qdisc +
   per-destination flower filters) with netem leaves instead of HTB rate
   shaping. Keeping this recipe as a first-class helper avoids each
   consumer re-implementing the ordering and handle-allocation details.

2. **Confirm the recipe below** — we want to make sure our plan for
   composing PRIO + netem-children + flower filters on bridge-side veth
   endpoints is what you'd recommend, and flag any gotchas.

3. **Small QoL item:** `get_filters_by_parent(dev, parent)` that filters
   the dump server-side (or at least client-side) by parent handle, so
   consumers can do idempotent re-apply and targeted teardown without
   scanning every filter on the interface. Minor — not blocking.

Rest of this doc: use case, proposed API, recipe we plan to follow, and
open questions.

---

## 1. Use case

nlink-lab runs multi-namespace labs with shared L2 bridge networks. A
single bridge can have many members (radio/satellite emulation,
multipoint fabrics). Today we can apply:

- **Per-interface netem** — impair one end of a point-to-point veth.
- **Per-link netem** — impair both sides of a point-to-point veth.

What we cannot currently express cleanly is **per source-destination
pair** on a bridge:

```
network radio {
  members [hq, alpha, bravo]
  impair hq -- alpha   { delay 15ms jitter 5ms loss 1% }  # close
  impair hq -- bravo   { delay 40ms jitter 20ms loss 5% } # far
  impair alpha -- bravo { delay 60ms jitter 30ms loss 8% } # farthest
}
```

This is the canonical realistic satellite/radio model. It's also useful
for geo-distributed WAN simulation where each pair has distinct RTT
and loss.

## 2. Why the existing nlink primitives are sufficient

We mapped the plan against nlink 0.12.2 and confirmed:

| Need | nlink 0.12.2 API | Notes |
|------|------------------|-------|
| Root classful qdisc | `PrioConfig` or `HtbQdiscConfig` | `Connection::add_qdisc` |
| Leaf netem per band/class | `NetemConfig` | `Connection::add_qdisc_full` with `parent="1:N"` |
| HTB child class | `HtbClassConfig` | `Connection::add_class_config` |
| Per-dest-IP classification (v4/v6, mask) | `U32Filter::match_dst_ipv4` / `FlowerFilter` | Already in the public API |
| Apply in a specific netns | `namespace::connection_for(&ns)` | `Connection<Route>` is namespace-scoped |
| Idempotent teardown | `del_qdisc(dev, "root")` | Cascades to classes and filters |
| Enumerate existing state | `get_qdiscs_by_index`, `get_classes_by_index`, `get_filters_by_index` | Good for diff/reconcile |

The only thing we'd be hand-rolling is handle allocation (`1:`, `1:1..N`,
`10:`, `11:`, …) and the ordering of operations — which is exactly what
`PerHostLimiter::apply` already encapsulates for rate limiting.

## 3. Proposed helper: `PerPeerImpairer`

Drop-in shape mirroring `PerHostLimiter`, under
`nlink::netlink::ratelimit` (or a new sibling module — we'd suggest
`nlink::netlink::impair` since this is no longer strictly rate
limiting).

```rust
pub struct PerPeerImpairer {
    dev: String,
    default_impairment: Option<NetemConfig>, // optional, applied to catch-all
    rules: Vec<PeerRule>,
    // Implementation detail: root qdisc choice.
    // Default: PRIO with N+1 bands (one per rule + default). HTB available
    // if user needs combined rate shaping.
}

struct PeerRule {
    match_: PeerMatch,
    impairment: NetemConfig,
}

pub enum PeerMatch {
    DstIp(IpAddr),
    DstSubnet(IpAddr, u8),
    DstMac([u8; 6]),
}

impl PerPeerImpairer {
    pub fn new(dev: &str) -> Self;
    pub fn default_impairment(mut self, cfg: NetemConfig) -> Self;
    pub fn impair_dst_ip(mut self, ip: IpAddr, cfg: NetemConfig) -> Self;
    pub fn impair_dst_subnet(mut self, subnet: &str, cfg: NetemConfig) -> Result<Self>;
    pub fn impair_dst_mac(mut self, mac: [u8; 6], cfg: NetemConfig) -> Self;
    pub async fn apply(&self, conn: &Connection<Route>) -> Result<()>;
    pub async fn clear(&self, conn: &Connection<Route>) -> Result<()>;
}
```

Example:

```rust
use nlink::netlink::{Connection, Route};
use nlink::netlink::impair::PerPeerImpairer;
use nlink::netlink::tc::NetemConfig;
use std::time::Duration;

let conn: Connection<Route> = namespace::connection_for("lab-mgmt")?;

PerPeerImpairer::new("vethA-br")
    .impair_dst_ip(
        "172.100.3.18".parse()?,
        NetemConfig::new().delay(Duration::from_millis(15)).loss_percent(1.0),
    )
    .impair_dst_ip(
        "172.100.3.19".parse()?,
        NetemConfig::new().delay(Duration::from_millis(40)).loss_percent(5.0),
    )
    .apply(&conn).await?;
```

### Why `impair_dst_*` (not `src`)

On a bridge-port veth, packets egress the port toward a specific
member. Filtering by destination IP on egress naturally pins the
per-pair impairment, assuming each member has a unique address in the
bridge's subnet. Source-IP matching would also work for symmetric
impairment applied on the opposite port — but requesting both would
double-apply the delay. We should document "apply on the egress side
toward the destination" clearly.

### Implementation sketch (what we'd do if you prefer we inline it)

```text
del_qdisc(dev, "root")                       # clean slate, idempotent
add_qdisc(dev, PrioConfig::new()             # root 1: with N+1 bands
    .handle("1:")
    .bands(N + 1)
    .build())
for (i, rule) in rules.iter().enumerate() {
    let band = i + 1;                         # 1:1 .. 1:N
    add_qdisc_full(dev,
        parent = format!("1:{}", band),
        handle = Some(&format!("{:x}:", 10 + i)),
        rule.impairment)                      # netem leaf
    add_filter(dev,
        parent = "1:",
        protocol = "ip",
        FlowerFilter::new()
            .classid(&format!("1:{}", band))
            .dst_ip_with_prefix(rule.match_)   # or U32Filter
            .priority(100 + i as u16)
            .build())
}
# band N+1 is the default (no filter → catches unmatched traffic),
# optionally with default_impairment as a netem leaf.
```

We already know this works because it's the same shape as
`PerHostLimiter::apply`, just with `NetemConfig` leaves instead of
`FqCodelConfig` under an HTB hierarchy.

## 4. Open questions for the nlink team

1. **PRIO vs HTB as root.** HTB would let a caller combine per-peer
   impairment with a per-peer rate cap. PRIO is simpler. Prefer to
   keep the helper PRIO-only and point users to a manual composition
   for rate+impair, or support both roots via a builder knob?

2. **Filter kind default.** Flower is more ergonomic and supports IPv6
   in one attr set. U32 is lighter and well-tested. Any preference?
   We'd default to flower and fall back to u32 if the kernel lacks
   cls_flower on the interface (unlikely on any kernel we care about,
   but worth asking).

3. **Netem ordering with HTB.** If HTB is ever used as root, the
   netem leaf should be under the HTB class, not the other way around.
   Would the helper enforce this, or leave it to the caller if they
   compose manually?

4. **Bridge port vs node-side veth.** We plan to attach TC on the
   mgmt-namespace bridge-port veth (egress toward the member). Is
   there a known issue with classful qdiscs on bridge ports on current
   kernels (≥6.x)? We've not seen one but want a sanity check.

5. **Naming and module placement.** `impair` as a new module, or
   extend `ratelimit` with this helper? We lean toward the former for
   discoverability, but defer to your library layout preference.

## 5. Smaller requests (independent of the helper)

These are nice-to-haves that would help us even if you decide the helper
is out of scope:

a. `get_filters_by_parent(dev, parent) -> Vec<FilterInfo>` — today we'd
   have to pull all filters on the interface and filter client-side by
   `tcm_parent`. A helper that parses out parent/prio/protocol/handle
   from the dump into a small struct would save boilerplate in several
   of our reconcile paths (not just impair).

b. **Recipe in the nlink docs**: a `docs/recipes/per-peer-impairment.md`
   (or doc-comment example on `NetemConfig`) showing the PRIO + netem
   + flower pattern. Even without the helper, pointing users at the
   canonical shape prevents bad hand-rolls (missing terminal bit on
   u32 selectors, wrong parent handle for nested netem, etc.).

c. **Error-path docs**: confirm in the `add_filter` docs that
   `EOPNOTSUPP` on `u32`/`flower` means the classifier module isn't
   loaded in the target namespace, and whether nlink could optionally
   `modprobe` it (or we should).

## 6. What we'll do on our side

Regardless of the helper decision, once we have your answers we will:

1. Implement `NetworkImpairment` type in
   `crates/nlink-lab/src/types.rs` and the `impair` block inside NLL
   `network { ... }` in the parser/lower.
2. Add Step 14b to `crates/nlink-lab/src/deploy.rs` after per-interface
   netem. It will call `PerPeerImpairer::apply` if the helper lands,
   or the hand-rolled equivalent otherwise.
3. Add integration tests under
   `crates/nlink-lab/tests/network_impairment.rs` that deploy a
   3-member radio network, measure per-pair latency with `ping`, and
   assert each pair gets its configured delay ± jitter.
4. Update `examples/multi-site.nll` with a realistic distance-based
   impairment matrix.

We're happy to contribute the helper to nlink as a PR if you'd like to
set a shape and have us implement it — just say the word.

## 7. Context pointers

- nlink primitives we surveyed:
  - `nlink::netlink::filter::{U32Filter, FlowerFilter, FilterConfig}` —
    full builder suite
  - `nlink::netlink::tc::{NetemConfig, PrioConfig, HtbQdiscConfig,
    HtbClassConfig, QdiscConfig, ClassConfig}`
  - `nlink::Connection::{add_qdisc, add_qdisc_full, add_class,
    add_class_config, add_filter, add_filter_full, del_qdisc,
    get_qdiscs_by_index, get_classes_by_index, get_filters_by_index}`
- Closest existing helper: `nlink::netlink::ratelimit::PerHostLimiter`
  (`ratelimit.rs:550`) — same structural pattern we want, with HTB +
  flower instead of PRIO + netem + flower.
- Our consumer code today:
  - `crates/nlink-lab/src/deploy.rs:1201` — current single-netem
    application point (Step 14).
  - `crates/nlink-lab/src/running.rs:497` — runtime impairment
    modification, which also uses `conn.change_qdisc` / `add_qdisc`.
