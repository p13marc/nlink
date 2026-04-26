# Programmatic Conntrack — Inject, Inspect, Evict

How to drive Linux's connection-tracking table directly from nlink:
inject synthetic flows, watch them appear in the dump, update timeouts
or marks, and delete by tuple or by ID. Uses
`nlink::netlink::netfilter::ConntrackBuilder` for the write side and
`Connection::<Netfilter>::get_conntrack` for the read side.

## When to use this

- **Pre-seeding flow state in tests.** A NAT integration test that
  expects an existing `ESTABLISHED` flow can inject one rather than
  generating real traffic with the right 5-tuple.
- **Load-balancer control planes.** Programs that hand off connections
  between back-ends often need to install conntrack entries so the
  kernel's stateful firewall short-circuits the new path.
- **Lab eviction.** Force-clear stuck flows by tuple or by ID without
  shelling out to `conntrack -D`.

Don't use it when:

- You only want to *observe* conntrack state — `get_conntrack` /
  `get_conntrack_v6` are dump-only and don't need any of the builder
  machinery.
- You're writing real packet-rewriting logic. Conntrack mutation is
  flow-state injection, not packet manipulation. For the latter,
  reach for nftables NAT rules or BPF.
- You need historical state — conntrack only knows what's *currently*
  tracked. For audit trails, log to nftables `log` or pipe events to
  a collector (see [Subscribing to events](#subscribing-to-events) below).

## High-level approach

Three operations:

1. **Build** a `ConntrackBuilder` with the address family, L4 protocol,
   and at least the orig tuple. For `add_conntrack`, also set
   `status(ConntrackStatus::CONFIRMED)` — the kernel rejects
   unconfirmed entries on the netlink path.
2. **Submit** via `add_conntrack` / `update_conntrack` /
   `del_conntrack` / `del_conntrack_by_id` / `flush_conntrack`. The
   first three take the same builder shape; ID-based delete and flush
   take simpler arguments.
3. **Verify** with `get_conntrack` (or `get_conntrack_v6`) and inspect
   the returned `ConntrackEntry` list — same struct returned for both
   organic kernel entries and ones you injected.

```text
   ConntrackBuilder              kernel ctnetlink             ConntrackEntry
   ┌─────────────┐  add_conntrack   ┌───────────┐  get_conntrack  ┌─────────────┐
   │ orig tuple  │ ───────────────► │  conntrack│ ──────────────► │ orig tuple  │
   │ status      │                  │   table   │                 │ reply tuple │
   │ timeout     │                  │           │ ◄────────────── │ id, mark,   │
   │ tcp_state   │  del_conntrack   └───────────┘                 │ tcp_state…  │
   └─────────────┘ ───────────────►                                └─────────────┘
```

## Code: inject, query, evict

The full lifecycle in one block. Run inside a `LabNamespace` so the
host's real conntrack table stays untouched.

```no_run
# async fn demo() -> nlink::Result<()> {
use std::net::Ipv4Addr;
use std::time::Duration;

use nlink::lab::LabNamespace;
use nlink::netlink::Connection;
use nlink::netlink::netfilter::{
    ConntrackBuilder, ConntrackStatus, ConntrackTuple, IpProtocol,
    TcpConntrackState,
};
use nlink::netlink::Netfilter;

let ns = LabNamespace::new("ct-demo")?;
let nf: Connection<Netfilter> = ns.connection_for()?;

// 1. Inject a synthetic TCP/ESTABLISHED entry. The reply tuple is
//    auto-mirrored from orig, which is correct for symmetric flows
//    without NAT.
nf.add_conntrack(
    ConntrackBuilder::new_v4(IpProtocol::Tcp)
        .orig(
            ConntrackTuple::v4(Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 2))
                .ports(40000, 80),
        )
        // The kernel requires CONFIRMED. Add SEEN_REPLY so the entry
        // looks like a flow that has finished its 3-way handshake —
        // otherwise stateful firewall rules won't short-circuit it.
        .status(ConntrackStatus::CONFIRMED | ConntrackStatus::SEEN_REPLY)
        .timeout(Duration::from_secs(120))
        .mark(0x42)
        .tcp_state(TcpConntrackState::Established),
).await?;

// 2. Read it back. The returned ConntrackEntry has the same fields as
//    a kernel-organic entry — there's no marker that says "this was
//    user-injected".
let entries = nf.get_conntrack().await?;
let injected = entries.iter().find(|e| {
    e.proto == IpProtocol::Tcp && e.orig.dst_port == Some(80)
}).expect("injected entry should appear in the dump");
println!(
    "id={:?} mark={:?} state={:?} timeout={:?}",
    injected.id, injected.mark, injected.tcp_state, injected.timeout,
);
let id = injected.id.expect("kernel always assigns an id");

// 3. Update the mark + timeout in place — same builder, different verb.
nf.update_conntrack(
    ConntrackBuilder::new_v4(IpProtocol::Tcp)
        .orig(
            ConntrackTuple::v4(Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 2))
                .ports(40000, 80),
        )
        .status(ConntrackStatus::CONFIRMED | ConntrackStatus::SEEN_REPLY)
        .timeout(Duration::from_secs(60))
        .mark(0x99),
).await?;

// 4. Delete by ID — the cheapest path when you already have one.
nf.del_conntrack_by_id(id).await?;

// 5. Or delete by tuple, which works without a prior dump.
nf.add_conntrack(
    ConntrackBuilder::new_v4(IpProtocol::Udp)
        .orig(
            ConntrackTuple::v4(Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 2))
                .ports(53000, 53),
        )
        .status(ConntrackStatus::CONFIRMED)
        .timeout(Duration::from_secs(30)),
).await?;

nf.del_conntrack(
    ConntrackBuilder::new_v4(IpProtocol::Udp)
        .orig(
            ConntrackTuple::v4(Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 2))
                .ports(53000, 53),
        ),
).await?;

// 6. Or wipe the whole v4 table.
nf.flush_conntrack().await?;
# Ok(())
# }
```

## Asymmetric flows (NAT'd entries)

When the orig and reply tuples differ — typical for SNAT/DNAT'd flows
— supply both. The builder will *not* auto-mirror when `reply` is
explicitly set:

```rust,ignore
use std::net::Ipv4Addr;

// Client 10.0.0.5:50000 → public 1.2.3.4:443, NAT'd to 192.168.1.1.
nf.add_conntrack(
    ConntrackBuilder::new_v4(IpProtocol::Tcp)
        .orig(
            ConntrackTuple::v4(
                Ipv4Addr::new(10, 0, 0, 5),
                Ipv4Addr::new(1, 2, 3, 4),
            ).ports(50000, 443),
        )
        .reply(
            ConntrackTuple::v4(
                Ipv4Addr::new(1, 2, 3, 4),
                Ipv4Addr::new(192, 168, 1, 1),  // SNAT source
            ).ports(443, 50000),
        )
        .status(
            ConntrackStatus::CONFIRMED
                | ConntrackStatus::SEEN_REPLY
                | ConntrackStatus::SRC_NAT
                | ConntrackStatus::SRC_NAT_DONE,
        )
        .tcp_state(TcpConntrackState::Established),
).await?;
```

The `SRC_NAT` / `DST_NAT` / `*_DONE` flags tell the kernel which side
was translated; they're informational on the dump path but the kernel
respects them for return-traffic matching.

## Per-zone conntrack

If you're running multi-tenant CT with `nft ... ct zone set 5`, scope
your operations with `.zone(5)` so they only touch that zone's
table:

```rust,ignore
nf.add_conntrack(
    ConntrackBuilder::new_v4(IpProtocol::Tcp)
        .zone(5)
        .orig(/* … */)
        .status(ConntrackStatus::CONFIRMED),
).await?;
```

There's no `flush_conntrack_by_zone` helper yet — file an issue
if you need a zone-scoped connection wrapper.

## Subscribing to events

`Connection::<Netfilter>` implements `EventSource`, so you can
subscribe to the conntrack multicast groups and consume `NEW` /
`DESTROY` events as a `Stream`. The same connection can't both
subscribe and submit mutations at the same time without races between
multicast deliveries and the ACK reply — open two connections, one
subscribed and one for actions.

```no_run
# async fn demo() -> nlink::Result<()> {
use std::time::Duration;

use nlink::netlink::{Connection, Netfilter};
use nlink::netlink::netfilter::{ConntrackEvent, ConntrackGroup};
use tokio_stream::StreamExt;

let mut sub = Connection::<Netfilter>::new()?;
sub.subscribe(&[ConntrackGroup::New, ConntrackGroup::Destroy])?;

let mut events = sub.events();
let deadline = tokio::time::Instant::now() + Duration::from_secs(10);

while tokio::time::Instant::now() < deadline {
    let remaining = deadline - tokio::time::Instant::now();
    match tokio::time::timeout(remaining, events.next()).await {
        Ok(Some(Ok(ConntrackEvent::New(entry)))) => {
            println!("NEW     {:?} -> {:?}", entry.orig.src_ip, entry.orig.dst_ip);
        }
        Ok(Some(Ok(ConntrackEvent::Destroy(entry)))) => {
            println!("DESTROY {:?} -> {:?}", entry.orig.src_ip, entry.orig.dst_ip);
        }
        Ok(Some(Err(e))) => return Err(e),
        Ok(None) | Err(_) => break,
    }
}
# Ok(())
# }
```

### `subscribe_all` vs targeted groups

`subscribe_all()` covers `New + Update + Destroy` — the three groups
that deliver `ConntrackEntry`-shaped messages. It skips `ExpNew` /
`ExpDestroy` because the parser doesn't yet understand the
`ct_expect` shape (Plan 137 PR C). To subscribe to those, call
`subscribe(&[ConntrackGroup::ExpNew, ConntrackGroup::ExpDestroy])`
explicitly — events will buffer in the kernel multicast queue but
won't surface as `ConntrackEvent` until the expect parser lands.

### `New` covers updates too

The kernel uses `IPCTNL_MSG_CT_NEW` for both creation *and* update
notifications. A subscriber to both `ConntrackGroup::New` and
`ConntrackGroup::Update` gets `ConntrackEvent::New` for everything —
the message itself doesn't carry "this is a true creation" vs
"this is an update" metadata that the parser can lift out without
ambiguity. To monitor only updates, subscribe to
`ConntrackGroup::Update` in isolation; every event then *is* an
update.

`ConntrackEvent::Destroy` is unambiguous — it always corresponds to
`IPCTNL_MSG_CT_DELETE`.

### Mutation + subscription on the same connection

Don't. The mutation path (`add_conntrack`, etc.) uses `send_ack`,
which expects a single ACK reply on the next `recv_msg`. If multicast
deliveries arrive on the same socket between send and recv, they'll
be consumed by `send_ack` and confuse the seq-matching. Open two
connections — one subscribed, one for mutations — and route them
through the same namespace if needed:

```rust,ignore
let ns = nlink::lab::LabNamespace::new("ct-watch")?;
let mut sub: Connection<Netfilter> = ns.connection_for()?;
sub.subscribe(&[ConntrackGroup::New, ConntrackGroup::Destroy])?;
let act: Connection<Netfilter> = ns.connection_for()?;
// ... use sub for events, act for add/del.
```

The `examples/netfilter/conntrack_events.rs --apply` runner exercises
exactly this pattern.

### Buffer overrun

If the consumer falls behind, the kernel multicast buffer eventually
fills up and drops events — the next read returns `Error::from_errno(-105)`
(ENOBUFS). nlink surfaces this rather than silently masking it. If
you can't keep up, either grow the socket's `SO_RCVBUF` (not yet
exposed by nlink — drop to a custom socket if you need it) or
process events on a dedicated task that does nothing else.

## Caveats

- **Required modules.** `add_conntrack` and friends need both
  `nf_conntrack` and `nf_conntrack_netlink` loaded. The kernel
  autoloads the netlink half on first request; the core conntrack
  module needs `modprobe nf_conntrack` if not already pulled in by
  another consumer (nftables ct rules, an IPVS director, etc.).
- **`CONFIRMED` is mandatory.** Submitting a builder without
  `status(ConntrackStatus::CONFIRMED)` returns `Error::InvalidArgument`
  from the kernel. The library doesn't pre-validate this — the kernel
  is authoritative because the exact required set varies by kernel
  version.
- **TCP `tcp_state` requires `timeout`.** A TCP `add_conntrack` that
  sets `tcp_state` but not `timeout` is rejected with EINVAL — the
  kernel's TCP state machine needs the timeout for its bookkeeping.
  Validated against Linux 6.19 (Fedora 43) by the example's `--apply`
  smoke test, where step 6 originally tripped exactly this. UDP /
  ICMP injections without `tcp_state` use protocol defaults and don't
  need explicit `timeout`, but it's still recommended for predictable
  test cleanup.
- **`add_conntrack` + `NLM_F_EXCL`.** Injecting a tuple that already
  exists fails with `Error::AlreadyExists` (`-EEXIST`). Use
  `update_conntrack` for upsert, or catch the error if you don't care
  about clobbering.
- **`update_conntrack` matches by tuple.** It doesn't take an ID;
  the kernel finds the entry by orig tuple. If you've changed the
  tuple, delete-then-add instead.
- **`del_conntrack` is forgiving.** Deleting a tuple that doesn't
  exist returns `Error::NotFound` — wrap with `.is_not_found()`
  if you want idempotent eviction.
- **Counter / timeout drift.** `update_conntrack` updates the fields
  you supplied but doesn't reset the kernel's packet/byte counters.
  Use `del` + `add` if you want a fresh entry.
- **No event subscription.** The Plan 137 PR B work hasn't shipped, so
  there's no way today to subscribe to NEW/UPDATE/DESTROY events on
  injected entries. Poll `get_conntrack` if you need
  near-real-time visibility.
- **TCP state byte values.** `tcp_state(TcpConntrackState::Established)`
  emits the correct wire byte (3) automatically; the
  `Unknown(u8)` variant is the escape hatch if you need to set a
  state value not yet enumerated.

## Lab smoke test

The recipe block above runs end-to-end against a `LabNamespace`. As a
quick sanity check that you've got the kernel modules loaded:

```text
$ sudo cargo run -p nlink --features lab --example conntrack -- --apply
```

Once `examples/netfilter/conntrack.rs` is promoted (Plan 137 PR A
follow-up), that command will exercise this recipe end-to-end. Until
then, the recipe is the runnable test plan.

## Hand-rolled equivalent

The Linux `conntrack-tools` CLI does the same operations:

```text
# Inject the entry from the recipe block.
sudo conntrack -I -p tcp -s 10.0.0.1 -d 10.0.0.2 \
    --sport 40000 --dport 80 \
    --reply-src 10.0.0.2 --reply-dst 10.0.0.1 \
    --reply-port-src 80 --reply-port-dst 40000 \
    --state ESTABLISHED --timeout 120 --mark 66 --status SEEN_REPLY,CONFIRMED

# Show the entry (matches what get_conntrack returns).
sudo conntrack -L -p tcp --dport 80

# Delete it.
sudo conntrack -D -p tcp -s 10.0.0.1 -d 10.0.0.2 --sport 40000 --dport 80

# Flush everything.
sudo conntrack -F
```

The wire format is identical — `conntrack-tools` and nlink both speak
ctnetlink. nlink's advantage is staying inside the Rust process: no
shell-out, no parsing of `conntrack -L` output, typed error variants.

## See also

- [`ConntrackBuilder`](https://docs.rs/nlink/latest/nlink/netlink/netfilter/struct.ConntrackBuilder.html)
- [`ConntrackStatus`](https://docs.rs/nlink/latest/nlink/netlink/netfilter/struct.ConntrackStatus.html) — flag constants and `bitor` syntax.
- [`ConntrackEvent`](https://docs.rs/nlink/latest/nlink/netlink/netfilter/enum.ConntrackEvent.html) and [`ConntrackGroup`](https://docs.rs/nlink/latest/nlink/netlink/netfilter/enum.ConntrackGroup.html) — multicast event types.
- [`Connection::<Netfilter>::get_conntrack`](https://docs.rs/nlink/latest/nlink/netlink/struct.Connection.html#method.get_conntrack) — dump path, returns the same `ConntrackEntry` shape that injected entries become.
- [`examples/netfilter/conntrack.rs`](../../crates/nlink/examples/netfilter/conntrack.rs) — `--apply` lifecycle demo for the mutation API.
- [`examples/netfilter/conntrack_events.rs`](../../crates/nlink/examples/netfilter/conntrack_events.rs) — `--apply` smoke test for the events API; opens two connections (sub + act) in a temp namespace, asserts NEW + DESTROY arrive.
- [Stateful firewall recipe](./nftables-stateful-fw.md) — uses
  `get_conntrack` to verify that nftables `ct state` rules match the
  flows you expect; pair with this recipe when seeding state for tests.
- Demand-gated follow-ons: `ct_expect`, nfqueue, nflog. File an
  issue if you need any of them.
- Upstream: `man 8 conntrack`, the kernel's
  `Documentation/networking/nf_conntrack-sysctl.rst`, and
  `include/uapi/linux/netfilter/nfnetlink_conntrack.h` for the
  authoritative attribute and status enum lists.
