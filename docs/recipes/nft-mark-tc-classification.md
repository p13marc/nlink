# Classify into TC classes from nftables (marks, priority, connmark)

Decide *which* traffic gets shaped in the firewall — where sets,
conntrack state and interfaces are first-class — and do the shaping in
TC. nftables hands the decision over in one of two packet fields:

- **`skb->priority`**, set with `meta priority set 1:10`. It *is* a TC
  classid: an HTB qdisc `1:` sends the packet straight to leaf class
  `1:10` with no `tc` filter at all.
- **the packet mark**, set with `meta mark set`, which a `tc` `fw`
  filter maps to a class. Use it when the mark has to mean something
  else too (`ip rule fwmark` policy routing, another qdisc on another
  device), or when only some of the mark bits are yours.

And a third tool on top: the **conntrack mark** keeps the decision with
the connection, so the expensive match (a big set, a DPI verdict) runs
on the first packet only.

## When to use this

- A mobile-core UPF or a CPE throttling a set of subscriber addresses.
- Per-tenant egress shaping where tenants are known by address set or
  interface, not by cgroup (for that, see
  [`cgroup-classification`](cgroup-classification.md)).
- Anything you would have written as iptables `-t mangle -j MARK` /
  `-j CLASSIFY` / `-j CONNMARK` plus `tc filter ... fw`.

For the shaping side alone, see
[`bidirectional-rate-limit`](bidirectional-rate-limit.md).

## The TC side

One HTB tree on the egress device: a throttled class `1:10` and a
default class `1:20`.

```rust,no_run
use nlink::netlink::tc::{HtbClassConfig, HtbQdiscConfig};
use nlink::netlink::{Connection, Route};
use nlink::{Rate, TcHandle};

# async fn example() -> nlink::Result<()> {
let tc = Connection::<Route>::new()?;
let dev = "eth0";

tc.add_qdisc_full(
    dev,
    TcHandle::ROOT,
    Some(TcHandle::major_only(1)),
    HtbQdiscConfig::new().default_class(0x20).build(),
).await?;
tc.add_class(
    dev,
    TcHandle::major_only(1),
    TcHandle::new(1, 1),
    HtbClassConfig::new(Rate::gbit(1)).build(),
).await?;
// Throttled.
tc.add_class(
    dev,
    TcHandle::new(1, 1),
    TcHandle::new(1, 0x10),
    HtbClassConfig::new(Rate::mbit(1)).ceil(Rate::mbit(2)).build(),
).await?;
// Everyone else.
tc.add_class(
    dev,
    TcHandle::new(1, 1),
    TcHandle::new(1, 0x20),
    HtbClassConfig::new(Rate::mbit(500)).ceil(Rate::gbit(1)).build(),
).await?;
# Ok(())
# }
```

## Option 1 — `meta priority set`: no `tc` filter

```rust,no_run
use std::net::Ipv4Addr;

use nlink::TcHandle;
use nlink::netlink::nftables::config::NftablesConfig;
use nlink::netlink::nftables::{ChainType, Family, Hook, Priority, SetKeyType};
use nlink::netlink::{Connection, Nftables};

# async fn example() -> nlink::Result<()> {
let nft = Connection::<Nftables>::new()?;

let cfg = NftablesConfig::new().table("qos", Family::Ip, |t| {
    // A bounded set: adding past 4096 fails with ENFILE instead of
    // growing without limit. Raising the size later is applied in place.
    t.set("throttled", |s| {
        s.key_type(SetKeyType::Ipv4Addr)
            .size(4096)
            .ipv4(Ipv4Addr::new(10, 45, 0, 7))
    })
    .chain("post", |c| {
        c.hook(Hook::Postrouting)
            .priority(Priority::Mangle)
            .chain_type(ChainType::Filter)
    })
    // ip daddr @throttled meta priority set 1:10
    .rule_keyed("post", "throttle", |r| {
        r.match_daddr_in_set("throttled")
            .set_priority(TcHandle::new(1, 0x10))
    })
});
cfg.diff(&nft).await?.apply(&nft).await?;
# Ok(())
# }
```

That is the whole classifier. `htb_classify` checks `skb->priority`
before it runs any filter: a match on a **leaf** class of this qdisc
wins outright; an inner class runs its own filters; anything else falls
through to the qdisc's filters and then the default class. A `prio`
qdisc `1:` reads it the same way and picks band `minor - 1`.

**Set it in `postrouting`, `output` or `forward` — not `prerouting`.**
For forwarded IPv4 traffic the kernel rewrites `skb->priority` from the
TOS before the `forward` hook (`net.ipv4.ip_forward_update_priority`,
on by default), so a value set earlier is gone by the time the packet
reaches the qdisc.

## Option 2 — a mark and a `fw` filter

The mark is 32 bits that several tools on one host may want: kube-proxy
uses `0x4000`/`0x8000`, CNI plugins and VPN policy routing take others.
`set_mark` overwrites all 32; `set_mark_masked(value, mask)` changes
only the bits under `mask` (iptables `MARK --set-mark value/mask`).

```rust,no_run
# use nlink::netlink::nftables::config::NftablesConfig;
# use nlink::netlink::nftables::{ChainType, Family, Hook, Priority};
# use nlink::netlink::{Connection, Nftables};
use nlink::netlink::filter::FwFilter;
use nlink::netlink::Route;
use nlink::TcHandle;

# async fn example(nft: Connection<Nftables>, tc: Connection<Route>) -> nlink::Result<()> {
const QOS_MASK: u32 = 0x0000_00ff;
const THROTTLED: u32 = 0x10;

let cfg = NftablesConfig::new().table("qos", Family::Ip, |t| {
    t.chain("post", |c| {
        c.hook(Hook::Postrouting)
            .priority(Priority::Mangle)
            .chain_type(ChainType::Filter)
    })
    // ip daddr @throttled meta mark set mark and 0xffffff00 or 0x10
    .rule_keyed("post", "throttle", |r| {
        r.match_daddr_in_set("throttled")
            .set_mark_masked(THROTTLED, QOS_MASK)
    })
});
cfg.diff(&nft).await?.apply(&nft).await?;

// tc filter add dev eth0 parent 1: handle 0x10/0xff fw classid 1:10
// The mark to match is the filter *handle*; the mask goes in the builder.
tc.add_filter_full(
    "eth0",
    TcHandle::major_only(1),
    Some(TcHandle::from(THROTTLED)),
    0x0003, // ETH_P_ALL
    100,
    FwFilter::new()
        .mask(QOS_MASK)
        .classid(TcHandle::new(1, 0x10))
        .build(),
).await?;
# Ok(())
# }
```

`match_mark_masked(value, mask)` is the matching side, for later rules
that need to know what an earlier one decided.

## Option 3 — decide once per connection (connmark)

Matching every packet against a large set costs a lookup per packet.
Store the verdict on the connection instead, and copy it back onto each
packet:

```rust,no_run
# use nlink::netlink::nftables::config::NftablesConfig;
# use nlink::netlink::nftables::{ChainType, CtState, Family, Hook, Priority};
# fn cfg() -> NftablesConfig {
NftablesConfig::new().table("qos", Family::Ip, |t| {
    t.chain("post", |c| {
        c.hook(Hook::Postrouting)
            .priority(Priority::Mangle)
            .chain_type(ChainType::Filter)
    })
    // ct state new ip daddr @throttled ct mark set 0x10
    .rule_keyed("post", "classify-new", |r| {
        r.match_ct_state(CtState::NEW)
            .match_daddr_in_set("throttled")
            .set_ct_mark(0x10)
    })
    // meta mark set ct mark   (CONNMARK --restore-mark)
    .rule_keyed("post", "restore", |r| r.restore_mark_from_ct())
})
# }
```

`save_mark_to_ct()` is the other direction (`ct mark set mark`,
CONNMARK `--save-mark`), and `match_ct_mark(mark)` matches the stored
value. These need the `nft_ct` module, which the kernel loads on demand.

## Clamping the MSS on the same path

Shaping often comes with a tunnel or a PPPoE uplink whose MTU is lower
than the hosts behind it think. Clamp the TCP MSS on forwarded SYNs
while you are in the table — to a constant, or to what the route
allows:

```rust,no_run
# use nlink::netlink::nftables::config::NftablesConfig;
# use nlink::netlink::nftables::{ChainType, Family, Hook, Priority, TcpFlags};
# fn cfg() -> NftablesConfig {
NftablesConfig::new().table("qos", Family::Ip, |t| {
    t.chain("forward", |c| {
        c.hook(Hook::Forward)
            .priority(Priority::Mangle)
            .chain_type(ChainType::Filter)
    })
    // tcp flags syn / syn,rst tcp option maxseg size set rt mtu
    .rule_keyed("forward", "mss", |r| {
        r.match_tcp_flags(TcpFlags::SYN, TcpFlags::SYN | TcpFlags::RST)
            .clamp_tcp_mss_to_pmtu()
    })
})
# }
```

`clamp_tcp_mss(1360)` is the constant form. Either way the kernel only
ever *lowers* an MSS, and a SYN without the option is left alone. The
path-MTU form is only valid in `forward`, `output` and `postrouting`.

## Verify

```rust,no_run
# use nlink::netlink::nftables::Family;
# use nlink::netlink::{Connection, Nftables, Route};
# use nlink::TcHandle;
# async fn example(nft: Connection<Nftables>, tc: Connection<Route>) -> nlink::Result<()> {
// What the firewall matched (rules need a `.counter()`).
for rule in nft.list_rules("qos", Family::Ip).await? {
    println!("{:?}: {:?}", rule.comment, rule.counter());
}
// What the shaper got.
for class in tc.get_classes_by_name("eth0").await? {
    if class.handle() == TcHandle::new(1, 0x10) {
        println!("1:10 sent {} packets", class.packets());
    }
}
# Ok(())
# }
```

## Caveats

- **Hook placement.** Mark and priority must be set before the packet
  reaches the qdisc: `postrouting` is always late enough. For priority,
  `prerouting` is too early on a router (see above).
- **Ingress shaping** happens before netfilter's hooks, so a mark set
  by nftables is not there yet. Redirect to an IFB and shape on its
  egress, as [`bidirectional-rate-limit`](bidirectional-rate-limit.md)
  does.
- **`set_mark` is all 32 bits.** Prefer `set_mark_masked` on any host
  you do not own outright.

The behaviour described here is exercised end-to-end by
`crates/nlink/tests/integration/nftables_statements.rs`, which sends
packets through a namespace and reads the rule counters and HTB class
statistics.
