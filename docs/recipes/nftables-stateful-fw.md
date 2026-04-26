# Stateful Firewall with Connection Tracking

How to build a stateful firewall — accept established / related flows,
drop new connections from untrusted interfaces, allow specific services
on the trusted side — and verify it via conntrack lookups. Uses
`nlink::netlink::nftables` for the rule pipeline and
`Connection::<Netfilter>::get_conntrack` for the verification.

## When to use this

- Edge-router-style policy on a host, container, or VM that should drop
  unsolicited inbound traffic but keep outbound flows working.
- Lab fixtures that need a programmable firewall under integration
  tests — the `Transaction` API installs the entire ruleset
  atomically, so a half-applied policy never leaks.
- Replacing `iptables-legacy` shell-outs from existing tooling with
  typed nftables calls.

Don't use it when:

- You need full nftables expressiveness (named maps with verdicts,
  flowtables, vmaps, complex set element types). The typed builder
  covers the firewall sweet spot — for the long tail, drop to the
  raw `MessageBuilder` or shell out to `nft -f`.
- You need to inspect or manipulate conntrack entries themselves
  (insert / delete / mark). For that, see the
  [conntrack-programmatic](./conntrack-programmatic.md) recipe —
  this one stays focused on the rule-side firewall.

## High-level approach

A single `inet` table with three base chains plus one regular chain for
the WAN-facing input policy:

```text
                      table inet filter
        ┌──────────────────────────────────────────────────┐
        │ chain input    (hook=input,    policy=drop)      │
        │   ct state established,related accept            │
        │   iif lo accept                                   │
        │   tcp dport ssh accept                           │
        │   ct state new jump wan-in                       │
        │ chain wan-in   (regular)                          │
        │   iif eth0 ip saddr @blocklist drop              │
        │   iif eth0 ip protocol icmp accept               │
        │ chain forward  (hook=forward,  policy=drop)      │
        │   ct state established,related accept            │
        │   iif lan oif eth0 accept                        │
        │ chain output   (hook=output,   policy=accept)    │
        └──────────────────────────────────────────────────┘
```

Two stateful pillars:

1. **Drop-by-default base chains.** `policy(Policy::Drop)` on `input`
   and `forward` means anything not explicitly allowed is dropped at
   the chain's end. Safer than the iptables-legacy `-A INPUT -j DROP`
   pattern because it survives partial rule updates.
2. **Conntrack-state shortcut.** `match_ct_state(ESTABLISHED|RELATED)`
   as the first rule short-circuits 99% of packets — return traffic for
   flows the host originated, plus ICMP errors / FTP data channels
   correlated with active flows. Only `state new` packets fall through
   to the per-service rules.

## Code

```no_run
# async fn demo() -> nlink::Result<()> {
use std::net::Ipv4Addr;

use nlink::netlink::Connection;
use nlink::netlink::nftables::{
    Chain, ChainType, CtState, Family, Hook, LimitUnit, Policy, Priority, Rule,
};
use nlink::netlink::Nftables;

let conn = Connection::<Nftables>::new()?;

// One atomic transaction: table → chains → set → rules. If any step
// errors, the kernel rolls back to pre-transaction state.
conn.transaction()
    // 1. The table holds everything.
    .add_table("filter", Family::Inet)

    // 2. Three base chains hooked into netfilter.
    .add_chain(Chain::new("filter", "input")
        .family(Family::Inet)
        .hook(Hook::Input)
        .chain_type(ChainType::Filter)
        .priority(Priority::Filter)
        .policy(Policy::Drop))
    .add_chain(Chain::new("filter", "forward")
        .family(Family::Inet)
        .hook(Hook::Forward)
        .chain_type(ChainType::Filter)
        .priority(Priority::Filter)
        .policy(Policy::Drop))
    .add_chain(Chain::new("filter", "output")
        .family(Family::Inet)
        .hook(Hook::Output)
        .chain_type(ChainType::Filter)
        .priority(Priority::Filter)
        .policy(Policy::Accept))

    // 3. INPUT: stateful shortcut, loopback, then per-service allows.
    .add_rule(Rule::new("filter", "input")
        .family(Family::Inet)
        .match_ct_state(CtState::ESTABLISHED | CtState::RELATED)
        .accept())
    .add_rule(Rule::new("filter", "input")
        .family(Family::Inet)
        .match_iif("lo")
        .accept())
    .add_rule(Rule::new("filter", "input")
        .family(Family::Inet)
        .match_tcp_dport(22)
        .counter()
        .accept())
    .add_rule(Rule::new("filter", "input")
        .family(Family::Inet)
        .match_tcp_dport(443)
        .counter()
        .accept())
    .add_rule(Rule::new("filter", "input")
        .family(Family::Inet)
        .match_l4proto(1)            // ICMP
        .limit(10, LimitUnit::Second)
        .accept())

    // 4. FORWARD: only return traffic + LAN→WAN initiated flows.
    .add_rule(Rule::new("filter", "forward")
        .family(Family::Inet)
        .match_ct_state(CtState::ESTABLISHED | CtState::RELATED)
        .accept())
    .add_rule(Rule::new("filter", "forward")
        .family(Family::Inet)
        .match_iif("lan0")
        .match_oif("eth0")
        .accept())

    .commit(&conn)
    .await?;
# Ok(())
# }
```

## Block-list as a typed set

Sets give you O(1) lookup and let you mutate the membership list without
rebuilding rules. Add the set in the same transaction (or after — sets
can be added/extended live):

```no_run
# async fn demo() -> nlink::Result<()> {
# use std::net::Ipv4Addr;
# use nlink::netlink::Connection;
# use nlink::netlink::nftables::{
#     Family, Rule, Set, SetElement, SetKeyType,
# };
# use nlink::netlink::Nftables;
# let conn = Connection::<Nftables>::new()?;
conn.add_set(
    Set::new("filter", "blocklist")
        .family(Family::Inet)
        .key_type(SetKeyType::Ipv4Addr),
).await?;

conn.add_set_elements("filter", "blocklist", Family::Inet, &[
    SetElement::ipv4(Ipv4Addr::new(198, 51, 100, 7)),
    SetElement::ipv4(Ipv4Addr::new(203, 0, 113, 42)),
]).await?;

// Drop anything from a blocked source before the per-service allows.
conn.add_rule(
    Rule::new("filter", "input")
        .family(Family::Inet)
        .match_saddr_in_set("blocklist")
        .counter()
        .drop(),
).await?;
# Ok(())
# }
```

To extend the blocklist later, call `add_set_elements` again with the
new entries — duplicates are tolerated by the kernel. To remove an
entry, use `del_set_elements`.

## Verifying state via conntrack

Once traffic flows, `Connection::<Netfilter>` exposes the live conntrack
table — same source the kernel consults for the
`ct state established,related` match. Useful for asserting that a flow
landed where you expected it:

```no_run
# async fn demo() -> nlink::Result<()> {
use nlink::netlink::{Connection, Netfilter};
use nlink::netlink::netfilter::IpProtocol;

let nf = Connection::<Netfilter>::new()?;
let entries = nf.get_conntrack().await?;

let ssh_flows = entries.iter().filter(|e| {
    e.proto == IpProtocol::Tcp
        && e.orig.dst_port == Some(22)
});
for e in ssh_flows {
    println!(
        "{:?}:{:?} -> {:?}:{:?}  state={:?}  timeout={:?}",
        e.orig.src_ip, e.orig.src_port,
        e.orig.dst_ip, e.orig.dst_port,
        e.tcp_state, e.timeout,
    );
}
# Ok(())
# }
```

`tcp_state == Some(TcpConntrackState::Established)` is the canonical
"this flow has finished its 3-way handshake and the firewall is
short-circuiting it via the established/related rule."

## Lab demo: WAN / Router / LAN

To see the firewall actually drop unsolicited traffic, set up three
namespaces — a WAN side, a router (where the firewall lives), and a
LAN client — then probe across:

```no_run
# async fn demo() -> nlink::Result<()> {
use nlink::lab::{LabNamespace, LabVeth};
use nlink::netlink::Connection;
use nlink::netlink::nftables::{
    Chain, ChainType, CtState, Family, Hook, Policy, Priority, Rule,
};
use nlink::netlink::Nftables;

let wan = LabNamespace::new("fw-wan")?;
let router = LabNamespace::new("fw-router")?;
let lan = LabNamespace::new("fw-lan")?;

LabVeth::new("eth0", "wan0").peer_in(&wan).create_in(&router).await?;
LabVeth::new("lan0", "client0").peer_in(&lan).create_in(&router).await?;

router.add_addr("eth0", "203.0.113.1/24")?;     router.link_up("eth0")?;
router.add_addr("lan0", "10.0.0.1/24")?;        router.link_up("lan0")?;
wan.add_addr("wan0", "203.0.113.2/24")?;        wan.link_up("wan0")?;
lan.add_addr("client0", "10.0.0.2/24")?;        lan.link_up("client0")?;

// Enable IPv4 forwarding inside the router namespace.
nlink::netlink::namespace::set_sysctl("fw-router", "net.ipv4.ip_forward", "1")?;

// Install the firewall in the router namespace. Nftables is a sync-construct
// protocol (no GENL family-id round-trip), so use `connection_for`, not
// `connection_for_async`.
let nft: Connection<Nftables> = router.connection_for()?;
nft.transaction()
    .add_table("filter", Family::Inet)
    .add_chain(Chain::new("filter", "input")
        .family(Family::Inet)
        .hook(Hook::Input).chain_type(ChainType::Filter)
        .priority(Priority::Filter).policy(Policy::Drop))
    .add_chain(Chain::new("filter", "forward")
        .family(Family::Inet)
        .hook(Hook::Forward).chain_type(ChainType::Filter)
        .priority(Priority::Filter).policy(Policy::Drop))
    .add_rule(Rule::new("filter", "input")
        .family(Family::Inet)
        .match_ct_state(CtState::ESTABLISHED | CtState::RELATED)
        .accept())
    .add_rule(Rule::new("filter", "forward")
        .family(Family::Inet)
        .match_ct_state(CtState::ESTABLISHED | CtState::RELATED)
        .accept())
    .add_rule(Rule::new("filter", "forward")
        .family(Family::Inet)
        .match_iif("lan0").match_oif("eth0").accept())
    .commit(&nft).await?;

// LAN → WAN ping should succeed (forward + return path open).
let out = lan.spawn_output({
    let mut c = std::process::Command::new("ping");
    c.args(["-c", "1", "-W", "2", "203.0.113.2"]);
    c
})?;
assert!(out.status.success(), "LAN→WAN ping should pass");

// WAN → LAN unsolicited ping should fail (no matching established flow).
let out = wan.spawn_output({
    let mut c = std::process::Command::new("ping");
    c.args(["-c", "1", "-W", "2", "10.0.0.2"]);
    c
})?;
assert!(!out.status.success(), "WAN→LAN unsolicited should be dropped");
# Ok(())
# }
```

The asymmetric ping result is the firewall doing its job: `lan0` is
trusted (`match_iif("lan0")` rule), `eth0` is not, so only return
traffic from a flow already in conntrack survives the forward chain.

## Caveats

- **Required kernel modules.** The first rule that matches conntrack
  state autoloads `nf_conntrack`. If the module is absent and locked
  out (e.g., kmod-blocked container), `match_ct_state` rules silently
  match nothing — every flow looks like `ct state new`. Verify with
  `lsmod | grep nf_conntrack` before debugging "rules not matching".
- **`Family::Inet` vs `Family::Ip` for NAT.** Inet works for filter
  chains (it's the dual-stack family); but DNAT/SNAT rules require
  `Family::Ip` or `Family::Ip6` because the NAT expression is
  family-specific. The typed builder enforces this — `NatExpr::snat`
  rejects `Family::Inet`.
- **Default-policy gotcha.** Setting `policy(Policy::Drop)` on a chain
  takes effect *as soon as the transaction commits*, not after all your
  allow rules land. If your transaction errors halfway through, the
  partial state is rolled back — but if you split chain creation and
  rule installation into two transactions, the chain exists with its
  drop policy and zero rules in between. Always install chains + rules
  in the same `Transaction`.
- **Counter rules.** `.counter()` allocates kernel memory per rule —
  cheap, but if you're generating thousands of dynamic rules consider
  reusing a counter via the rule's `position` to insert near an
  existing counter rule instead.
- **Set elements need to match the table family.** A set declared
  `Family::Inet` only accepts `SetKeyType::Ipv4Addr` *or*
  `SetKeyType::Ipv6Addr` elements that come through an inet chain;
  IPv6 elements in an inet rule still need a separate
  `match_saddr_v6_in_set` (currently coverage-gated — drop to
  `MessageBuilder` for v6 set membership today).
- **Conntrack zones.** Multiple firewalls on a single host (e.g.,
  per-tenant CT zones) need `zone()` set on rules. Not yet exposed by
  the typed `Rule` builder — file an issue if you need it.

## Hand-rolled equivalent

The above transaction is byte-equivalent to:

```text
nft add table inet filter
nft add chain inet filter input { type filter hook input priority filter \; policy drop \; }
nft add chain inet filter forward { type filter hook forward priority filter \; policy drop \; }
nft add chain inet filter output { type filter hook output priority filter \; policy accept \; }
nft add rule inet filter input ct state established,related accept
nft add rule inet filter input iifname "lo" accept
nft add rule inet filter input tcp dport 22 counter accept
nft add rule inet filter input tcp dport 443 counter accept
nft add rule inet filter input ip protocol icmp limit rate 10/second accept
nft add rule inet filter forward ct state established,related accept
nft add rule inet filter forward iifname "lan0" oifname "eth0" accept
```

`nft -f file.nft` applies multiple rules in one transaction the same
way `Transaction::commit` does. Use `nft list ruleset` to dump the
parsed kernel state — handy for diffing against what you expected the
typed builder to emit.

## See also

- [`nlink::netlink::nftables`](https://docs.rs/nlink/latest/nlink/netlink/nftables/index.html)
  — full type list (`Chain`, `Rule`, `Set`, `Transaction`, etc.).
- [`Connection::<Netfilter>::get_conntrack`](https://docs.rs/nlink/latest/nlink/netlink/struct.Connection.html#method.get_conntrack)
  — dump the live conntrack table for verification.
- [conntrack-programmatic](./conntrack-programmatic.md) — typed
  conntrack mutation + multicast event subscription.
- Upstream: `man 8 nft`, the [nftables wiki][nft-wiki], and
  `Documentation/networking/nf_conntrack-sysctl.rst` in the kernel tree.

[nft-wiki]: https://wiki.nftables.org/wiki-nftables/index.php/Main_Page
