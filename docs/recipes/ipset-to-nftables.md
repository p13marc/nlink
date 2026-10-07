# ipset → nftables, with nlink

ipset keeps sets of addresses, networks and ports for iptables to match
against. nftables has sets built in, along with maps, timeouts and named
counters. This recipe maps each ipset type, option and iptables match to
the nlink call that does the same, then migrates a typical ipset + iptables
setup to one declared `NftablesConfig`. The how-to for each feature is in
[nftables sets, maps and objects](nftables-sets-maps.md).

## When to use this

- You are retiring `ipset` + `iptables` (or `iptables-nft` with
  `-m set`) and want the same behaviour from typed Rust code.
- A program shells out to `ipset add/del/test` at runtime and should call
  the kernel directly instead.

## Set types

| ipset | nlink |
|---|---|
| `hash:ip` | `Set::new(t, s).key_type(SetKeyType::Ipv4Addr)` (or `Ipv6Addr`), `SetElement::ipv4(a)` |
| `hash:net` | `.interval()`, `SetElement::ipv4_prefix(a, len)?` / `ipv4_range(a, b)` |
| `hash:ip,port` | `.key_type(SetKeyType::Concat(vec![Ipv4Addr, InetService]))`, `SetElement::concat([ipv4(a), port(p)])` |
| `hash:net,port`, `hash:ip,port,net`, … | the same concatenation, `.interval()`, with a prefix or range per field |
| `hash:mac` | `SetKeyType::EtherAddr`, `SetElement::ether(mac)` |
| `bitmap:port` | `SetKeyType::InetService`, with `.interval()` for port ranges |
| `hash:ip,iface` | concatenation with `SetKeyType::IfIndex`, matched with `PacketField::Iif` |
| `hash:net,iface` | not yet: a prefix needs an interval set, and an interval set with a host-order field (the ifindex) is refused |
| `list:set` | no single equivalent: one rule per member set, or merge the members |

`family inet6` is `SetKeyType::Ipv6Addr`. An nftables set holds one address
family; a table of family `inet` sees both IPv4 and IPv6 traffic, and the
matchers guard each lookup by protocol.

## Set options

| ipset option | nlink |
|---|---|
| `timeout N` (set default) | `Set::timeout(Duration)` |
| `timeout N` on `ipset add` | `SetElement::with_timeout(Duration)` on a set with `.timeout(..)` or `.per_element_timeouts()` |
| `maxelem N` | `Set::size(N)` |
| `counters` | an object map of counters: `Set::map(SetDataType::Object(ObjectType::Counter))` and `SetElement::object(name)`, one `Object::counter` per element |
| `comment` | not modelled on elements |
| `-exist` on `add` | `add_set_elements` is idempotent for elements already present; declaratively, only missing elements are sent |
| `ipset save` / `ipset restore` | an `NftablesConfig`: `diff` + `apply` is a restore that touches only what changed |
| `ipset swap` | not needed: `apply` changes a set's elements in one atomic batch |
| `ipset flush` | `del_set_elements` with the elements from `list_set_elements`, or declare the set empty in `SetElementMode::Exact` |

## iptables matches and targets

| iptables | nlink `Rule` |
|---|---|
| `-m set --match-set S src` | `.match_in_set(PacketField::Ip4Saddr, "S")` |
| `-m set ! --match-set S dst` | `.match_not_in_set(PacketField::Ip4Daddr, "S")` |
| `--match-set S dst,dst` on `hash:ip,port` | `.match_concat_in_set(&[PacketField::Ip4Daddr, PacketField::TcpDport], "S")` |
| `-j SET --add-set S src` | `.add_to_set(PacketField::Ip4Saddr, "S", None)` (the set must be `.dynamic()`) |
| `-j SET --add-set S src --exist --timeout 60` | `.update_in_set(PacketField::Ip4Saddr, "S", Some(Duration::from_secs(60)))` |
| `-j SET --del-set S src` | `.delete_from_set(PacketField::Ip4Saddr, "S")` |
| `-m set --match-set S src --packets-gt N` | count per element with an object map of counters, and read them with `list_objects_in` |
| many `-j MARK` rules, one per address | one `set_mark_from_map(PacketField::Ip4Saddr, "marks")` with a value map |
| many `-j ACCEPT/DROP/jump` rules, one per port | one `vmap(PacketField::TcpDport, "ports")` with a verdict map |

## Migrating a typical setup

The ipset and iptables side:

```text
ipset create trusted hash:net
ipset add trusted 10.0.0.0/8
ipset add trusted 192.168.1.0/24
ipset create web hash:ip,port
ipset add web 10.0.0.5,tcp:443
ipset create offenders hash:ip timeout 600
iptables -A INPUT -m set --match-set trusted src -j ACCEPT
iptables -A INPUT -m set --match-set web dst,dst -j ACCEPT
iptables -A INPUT -m set --match-set offenders src -j DROP
iptables -A INPUT -p tcp --dport 22 -j SET --add-set offenders src --exist
iptables -A INPUT -j DROP
```

The same as one declared ruleset:

```rust,no_run
use nlink::netlink::nftables::config::NftablesConfig;
use nlink::netlink::nftables::types::{
    Family, Hook, PacketField, Policy, Priority, SetElement, SetKeyType,
};
use std::net::Ipv4Addr;
use std::time::Duration;

# async fn run(conn: &nlink::Connection<nlink::netlink::Nftables>) -> nlink::Result<()> {
let net = |a, b, c, d, len| SetElement::ipv4_prefix(Ipv4Addr::new(a, b, c, d), len);
let trusted = vec![net(10, 0, 0, 0, 8)?, net(192, 168, 1, 0, 24)?];
let cfg = NftablesConfig::new().table("filter", Family::Ip, move |t| {
    t.chain("input", |c| {
        c.hook(Hook::Input)
            .priority(Priority::Filter)
            .policy(Policy::Drop)
    })
    .set("trusted", move |s| s.key_type(SetKeyType::Ipv4Addr).interval().elements(trusted))
    .set("web", |s| {
        s.key_type(SetKeyType::Concat(vec![SetKeyType::Ipv4Addr, SetKeyType::InetService]))
            .element(SetElement::concat([
                SetElement::ipv4(Ipv4Addr::new(10, 0, 0, 5)),
                SetElement::port(443),
            ]))
    })
    // Filled by the "ssh-knock" rule; kept across applies (Ensure mode).
    .set("offenders", |s| {
        s.key_type(SetKeyType::Ipv4Addr)
            .dynamic()
            .timeout(Duration::from_secs(600))
    })
    .rule_keyed("input", "trusted", |r| {
        r.match_in_set(PacketField::Ip4Saddr, "trusted").accept()
    })
    .rule_keyed("input", "web", |r| {
        r.match_concat_in_set(&[PacketField::Ip4Daddr, PacketField::TcpDport], "web")
            .accept()
    })
    .rule_keyed("input", "offenders", |r| {
        r.match_in_set(PacketField::Ip4Saddr, "offenders").drop()
    })
    .rule_keyed("input", "ssh-knock", |r| {
        r.match_tcp_dport(22)
            .update_in_set(PacketField::Ip4Saddr, "offenders", None)
    })
});

let diff = cfg.diff(conn).await?;
println!("{diff}");
diff.apply(conn).await?;
# Ok(())
# }
```

A few differences from the iptables version:

- The final `-j DROP` becomes the chain's `Policy::Drop`.
- `--exist` is `update_in_set`, which also restarts the element's timeout.
  `add_to_set` leaves a present element's timeout running.
- Declared rule order is enforced: `apply` puts rules in declared order, as
  iptables rule numbers would.
- Re-applying is a no-op. It does not empty `offenders`, whose elements
  came from the packet path.

## Caveats

- **Per-element comments** are not modelled.
- **`hash:net` with a `nomatch` exception** has no direct equivalent: put
  the exceptions in a second interval set and match it first with a
  `return` (or `accept`) rule.

## See also

- [nftables sets, maps and objects](nftables-sets-maps.md)
- [nftables declarative config](nftables-declarative-config.md)
- [nftables stateful firewall](nftables-stateful-fw.md)
