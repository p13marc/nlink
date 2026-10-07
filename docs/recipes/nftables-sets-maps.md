# nftables sets, maps and stateful objects

How to match packets against sets of addresses, prefixes, ports and
combinations of them, how to let rules fill sets (with timeouts), how to map
keys to verdicts, marks or TC classes, and how to give every address its own
counter or quota — imperatively, and declaratively with `NftablesConfig`.
This is the nftables side of what ipset does; the
[ipset migration table](ipset-to-nftables.md) maps one onto the other.

A runnable version of everything here, applied in a throwaway namespace:
`sudo cargo run -p nlink --example nftables_sets_maps -- --apply`.

## When to use this

- A rule should match many addresses, prefixes or ports without one rule
  each: a blocklist, an allowlist of networks, the ports a service listens
  on.
- A rule should *record* what it sees: recently-seen sources, port knocking,
  per-client state that expires.
- The decision itself is data: which chain a destination jumps to, which
  mark or TC class a source gets, which counter a packet is counted in.

## Permissions

`CAP_NET_ADMIN` in the network namespace. Listing works without it.

## Matching a field against a set

A set has a key type; a rule loads a packet field and looks it up.
`PacketField` names the fields and the key type each needs, and the
matchers put the protocol guard `nft` uses in front of the load (`meta
nfproto ipv6` for an IPv6 address, `meta l4proto tcp` for a TCP port), so a
lookup never reads the wrong header.

```rust,no_run
use nlink::netlink::nftables::types::{Family, PacketField, Rule, Set, SetElement, SetKeyType};
use nlink::netlink::{Connection, Nftables};
use std::net::Ipv6Addr;

# async fn run(conn: &Connection<Nftables>) -> nlink::Result<()> {
let blocked = Set::new("filter", "blocked6")
    .family(Family::Inet)
    .key_type(SetKeyType::Ipv6Addr);
conn.add_set(blocked.clone()).await?;
conn.add_set_elements(&blocked, &[SetElement::ipv6(Ipv6Addr::LOCALHOST)]).await?;

// ip6 saddr @blocked6 drop
conn.add_rule(
    Rule::new("filter", "input")
        .match_in_set(PacketField::Ip6Saddr, "blocked6")
        .drop(),
)
.await?;

// tcp dport != @open_ports drop   (iptables `! --match-set`)
conn.add_rule(
    Rule::new("filter", "input")
        .match_not_in_set(PacketField::TcpDport, "open_ports")
        .drop(),
)
.await?;
# Ok(())
# }
```

The element calls take the `Set`, not its name: how an element goes on the
wire depends on the set's key type and flags, and an element that does not
fit is an error before anything is sent.

## Ranges and prefixes — interval sets

`Set::interval()` makes a set of ranges (ipset `hash:net`). Elements are
prefixes or ranges; a single key is the range of one.

```rust,no_run
use nlink::netlink::nftables::types::{Set, SetElement, SetKeyType};
use std::net::Ipv4Addr;

# async fn run(conn: &nlink::Connection<nlink::netlink::Nftables>) -> nlink::Result<()> {
let nets = Set::new("filter", "allowed_nets")
    .key_type(SetKeyType::Ipv4Addr)
    .interval();
conn.add_set(nets.clone()).await?;
conn.add_set_elements(
    &nets,
    &[
        SetElement::ipv4_prefix(Ipv4Addr::new(10, 0, 0, 0), 8)?,
        SetElement::ipv4_range(Ipv4Addr::new(192, 0, 2, 10), Ipv4Addr::new(192, 0, 2, 20)),
        SetElement::ipv4(Ipv4Addr::new(198, 51, 100, 7)),
    ],
)
.await?;
# Ok(())
# }
```

The kernel stores `[a, b]` as two elements, `a` and `b + 1` flagged as an
interval end. `list_set_elements` pairs them back into ranges. Declared
ranges that overlap or touch are merged before they are written, as the
kernel's lookups would see them, so `10.0.0.0/25` + `10.0.0.128/25` is one
`/24` and converges. A mark or ifindex key is host-order and does not
compare as a number, so interval elements of those types are refused.

## Combinations — concatenated keys

`ip daddr . udp dport @services` matches the pair, not its parts (ipset
`hash:ip,port`). Each field is padded to a 4-byte register word. In an
interval set every field is a range of its own (`hash:net,port`), and the
kernel's `pipapo` backend holds each element with its inclusive end.

```rust,no_run
use nlink::netlink::nftables::types::{PacketField, Rule, Set, SetElement, SetKeyType};
use std::net::Ipv4Addr;

# async fn run(conn: &nlink::Connection<nlink::netlink::Nftables>) -> nlink::Result<()> {
let services = Set::new("filter", "services")
    .key_type(SetKeyType::Concat(vec![SetKeyType::Ipv4Addr, SetKeyType::InetService]))
    .interval();
conn.add_set(services.clone()).await?;
conn.add_set_elements(
    &services,
    &[SetElement::concat([
        SetElement::ipv4_prefix(Ipv4Addr::new(10, 0, 0, 0), 24)?,
        SetElement::port_range(8000, 8999),
    ])],
)
.await?;
conn.add_rule(
    Rule::new("filter", "input")
        .match_concat_in_set(&[PacketField::Ip4Daddr, PacketField::TcpDport], "services")
        .accept(),
)
.await?;
# Ok(())
# }
```

## Sets that rules fill — timeouts and `dynset`

A rule can add the packet's field to a set (`add`), add it or restart its
timeout (`update`), or remove it (`delete`). The set must be `dynamic()`,
which selects the backend that supports updates from the packet path. A
timeout makes its elements expire.

```rust,no_run
use nlink::netlink::nftables::types::{PacketField, Rule, Set, SetKeyType};
use std::time::Duration;

# async fn run(conn: &nlink::Connection<nlink::netlink::Nftables>) -> nlink::Result<()> {
let seen = Set::new("filter", "seen")
    .key_type(SetKeyType::Ipv4Addr)
    .dynamic()
    .timeout(Duration::from_secs(60));
conn.add_set(seen).await?;

// update @seen { ip saddr timeout 60s } — "seen in the last minute"
conn.add_rule(
    Rule::new("filter", "input").update_in_set(PacketField::Ip4Saddr, "seen", None),
)
.await?;
# Ok(())
# }
```

`list_set_elements` reports each element's own timeout (when it differs from
the set's default) and the time it has left. The kernel keeps timeouts in
jiffies, rounding down, so they read back in whole jiffies; the declarative
diff compares them in 20 ms steps, which are whole jiffies at every `HZ`.

## Maps and verdict maps

A map holds a value per key: a verdict (`vmap`), a mark, a TC class.

```rust,no_run
use nlink::TcHandle;
use nlink::netlink::nftables::types::{
    PacketField, Rule, Set, SetDataType, SetElement, SetKeyType, Verdict,
};
use std::net::Ipv4Addr;

# async fn run(conn: &nlink::Connection<nlink::netlink::Nftables>) -> nlink::Result<()> {
// tcp dport vmap { 22 : accept, 23 : drop }
let ports = Set::new("filter", "ports").key_type(SetKeyType::InetService).vmap();
conn.add_set(ports.clone()).await?;
conn.add_set_elements(
    &ports,
    &[
        SetElement::port(22).verdict(Verdict::Accept),
        SetElement::port(23).verdict(Verdict::Drop),
    ],
)
.await?;
conn.add_rule(Rule::new("filter", "input").vmap(PacketField::TcpDport, "ports"))
    .await?;

// meta priority set ip saddr map @classes — straight into an HTB class
let classes = Set::new("filter", "classes").map(SetDataType::Value(SetKeyType::ClassId));
conn.add_set(classes.clone()).await?;
conn.add_set_elements(
    &classes,
    &[SetElement::ipv4(Ipv4Addr::new(10, 0, 0, 5)).value(SetElement::classid(TcHandle::new(1, 0x10)))],
)
.await?;
conn.add_rule(
    Rule::new("filter", "output").set_priority_from_map(PacketField::Ip4Saddr, "classes"),
)
.await?;
# Ok(())
# }
```

A packet whose key is not in a verdict map goes on to the next rule; one
whose key is not in a value map stops at that rule.

## Counters, quotas and limits by name

A stateful object lives in the table under a name, and rules share it. An
object map picks one per key — ipset's per-element `counters`.

```rust,no_run
use nlink::netlink::nftables::types::{Family, PacketField, Rule, Set, SetDataType, SetElement};
use nlink::netlink::nftables::{Object, ObjectState, ObjectType, QuotaExpr};
use std::net::Ipv4Addr;

# async fn run(conn: &nlink::Connection<nlink::netlink::Nftables>) -> nlink::Result<()> {
conn.add_object(&Object::counter("filter", "client_a")).await?;
conn.add_object(&Object::quota("filter", "budget", QuotaExpr::new(10 << 30))).await?;

let per_ip = Set::new("filter", "per_ip").map(SetDataType::Object(ObjectType::Counter));
conn.add_set(per_ip.clone()).await?;
conn.add_set_elements(
    &per_ip,
    &[SetElement::ipv4(Ipv4Addr::new(10, 0, 0, 5)).object("client_a")],
)
.await?;
conn.add_rule(Rule::new("filter", "forward").objref_from_map(PacketField::Ip4Saddr, "per_ip"))
    .await?;
conn.add_rule(Rule::new("filter", "forward").quota_named("budget").accept())
    .await?;

// Read and zero a counter in one step: nothing counted in between is lost.
if let Some(before) = conn
    .reset_object("filter", "client_a", ObjectType::Counter, Family::Inet)
    .await?
    && let ObjectState::Counter { packets, bytes, .. } = before.state
{
    println!("client_a: {packets} packets, {bytes} bytes");
}
# Ok(())
# }
```

## Declaratively

Everything above has a declarative form. The diff compares configuration,
never live state, so counters keep counting, quotas keep what they have used,
and the elements rules added stay.

```rust,no_run
use nlink::netlink::nftables::config::NftablesConfig;
use nlink::netlink::nftables::types::{
    Family, Hook, PacketField, Priority, SetDataType, SetElement, SetKeyType, Verdict,
};
use nlink::netlink::nftables::{ObjectConfig, ObjectType, QuotaExpr};
use std::net::Ipv4Addr;
use std::time::Duration;

# async fn run(conn: &nlink::Connection<nlink::netlink::Nftables>) -> nlink::Result<()> {
let cfg = NftablesConfig::new().table("filter", Family::Inet, |t| {
    t.chain("input", |c| c.hook(Hook::Input).priority(Priority::Filter))
    .set("allowed_nets", |s| {
        s.key_type(SetKeyType::Ipv4Addr)
            .interval()
            .element(SetElement::ipv4_prefix(Ipv4Addr::new(10, 0, 0, 0), 8).unwrap())
    })
    .set("seen", |s| s.key_type(SetKeyType::Ipv4Addr).dynamic().timeout(Duration::from_secs(60)))
    .set("ports", |s| {
        s.key_type(SetKeyType::InetService)
            .vmap()
            .element(SetElement::port(22).verdict(Verdict::Accept))
    })
    .object("budget", ObjectConfig::Quota(QuotaExpr::new(10 << 30)))
    .object("client_a", ObjectConfig::Counter)
    .set("per_ip", |s| {
        s.map(SetDataType::Object(ObjectType::Counter))
            .element(SetElement::ipv4(Ipv4Addr::new(10, 0, 0, 5)).object("client_a"))
    })
    .rule_keyed("input", "seen", |r| r.update_in_set(PacketField::Ip4Saddr, "seen", None))
    .rule_keyed("input", "ports", |r| r.vmap(PacketField::TcpDport, "ports"))
});
cfg.diff(conn).await?.apply(conn).await?;
assert!(cfg.diff(conn).await?.is_empty());
# Ok(())
# }
```

How each piece reconciles:

| Change | What `apply` does |
|---|---|
| Elements added/removed | Only those elements, in the same batch. |
| A map element's value | That element is removed and added again. |
| A dynamic or timeout set's runtime elements | Kept: such sets default to `SetElementMode::Ensure`, which adds declared elements and removes none. Use `.element_mode(SetElementMode::Exact)` to own them. |
| Size, default timeout, GC interval | Changed in place (kernel 6.5+). |
| Key type, flags, data type | The set is recreated; rules using it move out of its way and back to their places. |
| A quota's size | Updated in place, keeping its consumption. |
| A limit's rate | Recreated (limits cannot be updated); rules using it move and come back. |

## Caveats

- **Interval sets of host-order keys** (mark, ifindex) are refused: `nft`
  byte-swaps those, nlink does not model that.
- **`list_set_elements` on an interval set** needs one extra round-trip to
  learn the set's flags.
- **Elements a rule adds** (`add @set`) are not notified as events by the
  kernel; `NftablesEvent::NewSetElements` reports elements added through
  netlink.
- **An object of a kind nlink does not model** (ct helper, synproxy, …)
  reads back as `ObjectState::Other` and is left alone by the diff.
- **The `nlink-nft` demo binary** parses intervals and `@set` lookups but not
  concatenations, maps or objects yet.

## See also

- [ipset → nftables](ipset-to-nftables.md) — the migration table.
- [nftables declarative config](nftables-declarative-config.md) — diff,
  apply, rule identity and order.
- [nftables → TC classification](nft-mark-tc-classification.md) — marks and
  `meta priority` into HTB.
