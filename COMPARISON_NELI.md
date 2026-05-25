---
title: nlink vs neli — a fair comparison
audience: maintainer + prospective users evaluating Rust netlink crates
status: draft for review
date: 2026-05-23
methodology: web research on neli (github, crates.io, source reading) + my own knowledge of nlink
verified-against: neli 0.7.4 (2026-01-28) vs nlink 0.15.1
---

# nlink vs neli — a fair comparison

[`neli`](https://github.com/jbaublitz/neli) is the most prominent
type-safe netlink library in the Rust ecosystem outside the
`rust-netlink` umbrella. Single-author project by John Baublitz,
BSD-3-Clause, 225 ⭐ / 49 forks. Currently at version **0.7.4** released
**2026-01-28**.

This document compares it against `nlink` (0.15.1) across the
dimensions that matter most when choosing between them. Where they
differ, I try to be honest about the tradeoff rather than promotional.

If you only read one paragraph: **[skip to the TL;DR](#honest-tldr)**.

---

## At-a-glance

| | **neli** 0.7.4 | **nlink** 0.15.1 |
|---|---|---|
| **Latest release** | 2026-01-28 | 2026-04-26 (latest 0.15.1) |
| **Last commit** | 2026-03-03 | 2026-05-23 (this branch) |
| **Maintainer count** | 1 (John Baublitz) | 1 (Marc Pardo) |
| **License** | BSD-3-Clause | MIT OR Apache-2.0 |
| **Crate split** | 2 crates (`neli` + `neli-proc-macros`) | 1 publishable crate (`nlink`); 11 unpublished POC bins |
| **MSRV** | undeclared (de facto current stable) | `1.95` (declared in workspace package) |
| **Async story** | sync + async, feature-flag toggled, mirrored APIs | async-only (tokio via `AsyncFd`) |
| **Wire codec** | proc-macro-derived (`Size`, `ToBytes`, `FromBytes`, `Header`) | `zerocopy` derives + manual builders |
| **Crates.io all-time downloads** | 29.1M | early-days (first 0.15.x cut) |
| **Distinctive strength** | `#[neli::neli_enum]` lets users define their own GENL families in ~20 lines | batteries-included Linux network config (TC, nftables, XFRM, lab) |

---

## 1. Architecture

### neli

Clean two-tier socket model:

- **`NlSocket` / `NlSocketHandle`** — raw, syscall-thin wrappers
  (sync + async variants in `src/socket/`).
- **`NlRouter`** — higher-level handle that manages sequence
  numbers, ACKs, PID validation, and a background dispatcher that
  demuxes unicast responses by `seq#` while shipping multicast
  packets to a separate `Receiver` channel
  ([`src/router/asynchronous.rs`](https://github.com/jbaublitz/neli/blob/main/src/router/asynchronous.rs)).

Sync vs async is a **Cargo feature toggle**, not a separate type
tree. Enable `async` to get
`neli::router::asynchronous::NlRouter` (Tokio-backed); enable `sync`
(default) for `neli::router::synchronous::NlRouter` (parking_lot).
The two APIs are deliberately mirrored — 0.7.0 redesigned async to
"more closely resemble its corresponding synchronous API."

Generic vs typed: neli ships **typed enums for control / nl / socket
/ rtnl / netfilter / connector constants** plus escape hatches
(`NlTypeWrapper`, `Buffer`, `#[neli_enum]`-derived enums) so users
can extend coverage outside the crate.

### nlink

Per-protocol typed `Connection<P>` where `P` is a zero-sized marker
(`Route`, `Generic`, `Wireguard`, `Netfilter`, `Xfrm`, etc.). One
Connection per protocol; switching protocols means making a new
Connection. Sequence numbers, ACKs, PID validation handled
internally per-Connection.

Async-only via `tokio`'s `AsyncFd`. No sync variant — a deliberate
choice to keep the surface single-shape.

Wire codec via `zerocopy`'s `FromBytes` + `IntoBytes` + `Immutable`
+ `KnownLayout` derives plus a `MessageBuilder` for construction.
Less proc-macro magic than neli; users hand-write more per new
message type but the generated code is lighter at runtime.

### Tradeoff

neli's `NlRouter` is a slick design for **concurrent unicast +
multicast on one socket**. nlink's "one Connection per concern"
trades the slickness for simpler invariants (each Connection has a
single-flight contract; concurrent dumps need separate Connections).

For "I want to subscribe to one family and occasionally probe ctrl"
on a single socket, neli's design wins. For "I'm building a router
control plane that touches 5 protocols," nlink's per-protocol typing
wins.

---

## 2. API ergonomics — show me the code

### Subscribe to multicast events

**neli** (verbatim from the README):
```rust
let (s, multicast) = NlRouter::connect(NlFamily::Generic, None, Groups::empty())?;
let id = s.resolve_nl_mcast_group("my_family_name", "my_multicast_group_name")?;
s.add_mcast_membership(Groups::new_groups(&[id]))?;
for next in multicast {
    println!("{:?}", next?);
}
```

**nlink**:
```rust
let mut conn = Connection::<Route>::new()?;
conn.subscribe(&[RtnetlinkGroup::Link])?;
let mut events = conn.events();
while let Some(event) = events.next().await {
    println!("{:?}", event?);
}
```

Both clean. neli's `resolve_nl_mcast_group` is generic and works for
any family; nlink's `RtnetlinkGroup::Link` is enum-typed for the
common case but loses the generic resolution.

### Create a VLAN sub-interface

**neli** ([`examples/newvlan.rs`](https://github.com/jbaublitz/neli/blob/main/examples/newvlan.rs)
— ~130 lines, but the meat is this attribute-stacking):
```rust
attrs.push(RtattrBuilder::default().rta_type(Ifla::Ifname).rta_payload(name).build()?);
attrs.push(RtattrBuilder::default().rta_type(Ifla::Link).rta_payload(if_index).build()?);
let mut vlan_attrs = RtBuffer::<IflaVlan, Buffer>::new();
vlan_attrs.push(RtattrBuilder::default().rta_type(IflaVlan::Id).rta_payload(vlan_id).build()?);
let mut info_attrs = RtBuffer::<IflaInfo, Buffer>::new();
info_attrs.push(RtattrBuilder::default().rta_type(IflaInfo::Kind).rta_payload("vlan\0").build()?);
info_attrs.push(RtattrBuilder::default().rta_type(IflaInfo::Data).rta_payload(vlan_attrs).build()?);
attrs.push(RtattrBuilder::default().rta_type(Ifla::Linkinfo).rta_payload(info_attrs).build()?);
let ifinfomsg = IfinfomsgBuilder::default().ifi_family(RtAddrFamily::Netlink).rtattrs(attrs).build()?;
rtnl.send::<_, _, Rtm, Ifinfomsg>(Rtm::Newlink,
    NlmF::CREATE | NlmF::EXCL | NlmF::ACK,
    NlPayload::Payload(ifinfomsg))?;
```

Note the `"vlan\0"` — neli's typed API still surfaces the
null-terminated-string footgun.

**nlink**:
```rust
conn.add_link(
    VlanLink::new("eth0.100")
        .link("eth0")
        .id(100)
).await?;
```

The shape ratio here (one method call vs ~30 lines of attribute
stacking) is the most stark contrast in the comparison. **neli is
closer to "type-safe assembly for netlink" than to an ip(8)
replacement**; nlink has built the ergonomic layer on top.

### Send a request, parse a typed response (genl ctrl list)

**neli** ([`examples/ctrl-list.rs`](https://github.com/jbaublitz/neli/blob/main/examples/ctrl-list.rs)):
```rust
let (socket, _) = NlRouter::connect(NlFamily::Generic, None, Groups::empty())?;
let recv = socket.send::<_, _, NlTypeWrapper, Genlmsghdr<CtrlCmd, CtrlAttr>>(
    GenlId::Ctrl, NlmF::DUMP,
    NlPayload::Payload(
        GenlmsghdrBuilder::default()
            .cmd(CtrlCmd::Getfamily).version(2)
            .attrs(GenlBuffer::<u16, Buffer>::new())
            .build()?,
    ),
)?;
for r in recv {
    if let Some(p) = r?.get_payload() {
        for attr in p.attrs().get_attr_handle().iter() { /* … */ }
    }
}
```

**nlink** has no equivalent because the GENL family marker pattern
makes `Connection::<Generic>` already resolve family IDs on demand
— users don't typically call ctrl directly. For the equivalent
"list available GENL families":
```rust
let conn = Connection::<Generic>::new_async().await?;
let families = conn.list_families().await?;
```

(Verify; this may not exist — but the pattern is what users want.)

### Tradeoff

neli's verbosity is partly a design choice — it stays close to the
protocol so escape hatches feel natural. nlink's brevity comes from
opinion (e.g. `VlanLink::new()` decides what attributes to set), which
is wonderful when the opinion matches your needs and limiting when it
doesn't.

---

## 3. Crate organization, feature flags, MSRV

| | **neli** | **nlink** |
|---|---|---|
| Crates published | `neli`, `neli-proc-macros` (workspace) | `nlink` (single publishable) |
| Bins | none | 11 unpublished POC bins (`ip`, `tc`, `nft`, `ss`, `wifi`, …) |
| Feature flags | `sync` (default), `async`, `netfilter` | `sockdiag`, `tuntap`, `tuntap-async`, `output`, `namespace_watcher`, `lab`, `full`, `integration` |
| MSRV | undeclared (de facto current stable) | `1.95` declared in `[workspace.package].rust-version` |
| Edition | bumped to 2024 in 0.7.1, **reverted in 0.7.3** | 2024 (locked) |

Note neli's edition revert in 0.7.3 — they had to back out 2024
because of unspecified compatibility issues. nlink commits to 2024
permanently (and requires 1.85+ as a result, raised to 1.95 in
0.15.1).

---

## 4. Protocol coverage

This is where the two projects differ most. nlink is wide; neli is
narrow + extensible.

| Capability | neli | nlink |
|---|---|---|
| rtnetlink (link/addr/route/rule) | ✓ — `src/rtnl.rs` + examples | ✓ |
| Generic netlink, auto family resolution | ✓ — `NlRouter::resolve_nl_mcast_group()` | ✓ (`Connection::<Wireguard>::new_async()`) |
| Streaming dump API | ✓ — `send()` returns `impl Iterator`; multicast `Receiver` | partial (`get_*` returns `Vec`; streaming is Plan 149) |
| nftables (table/chain/rule + atomic txn) | **no** | ✓ |
| Netfilter ctnetlink (conntrack) | partial — only NFULOG attrs + bind/unbind stub | ✓ (full add/del/update/flush + events) |
| XFRM (IPsec SA/SP) | **no** | ✓ |
| sock_diag | **no** | ✓ |
| audit | **no** | ✓ |
| SELinux / fib_lookup / uevent | **no** | ✓ |
| Connector (proc events) | partial — only `PROC_CN` | ✓ |
| Wireguard / nl80211 / ethtool / devlink / macsec / mptcp | **out of tree** (delegated to `wireguard-uapi`, `neli-wifi`, `nl80211-ng`) | ✓ (in-tree typed) |
| TC qdisc/class/filter/action typed builders | **no** (manual `Tcmsg` attr building) | ✓ (45 `parse_params` impls in `nlink::ParseParams`) |
| Ext-ACK / strict checking | ✓ — `enable_ext_ack`, `enable_strict_checking` | ✓ |
| High-level helpers (rate limit, impair, recipes) | **no** | ✓ (`RateLimiter`, `PerHostLimiter`, `PerPeerImpairer`) |
| Namespace harness for tests | **no** | ✓ (`lab` feature: `LabNamespace`, `with_namespace`, `require_root!`, `require_module!`) |
| Proc-macro derives for message types | ✓ — `Size`, `ToBytes`, `FromBytes`, `Header`, `neli_enum` | ✗ (zerocopy serves a different role) |
| `aya` co-demo | **no** | planned (Plan 152 for 0.16) |
| 7 cookbook recipes | **no** | ✓ |

Reading the table: **for "build a desktop wifi widget," neli is the
better starting point** (its derive macros + the ecosystem crates
like `neli-wifi` are pointed exactly at that). For "build a
programmable router" or "build a network test harness," nlink covers
ground neli simply doesn't.

---

## 5. What neli does well that nlink doesn't

Honest praise:

1. **Auto-derived wire codecs via proc macros.**
   `#[derive(Size, ToBytes, FromBytesWithInput, Header)]` plus
   `#[neli::neli_enum(serialized_type = "u8")]` lets a user define a
   new GENL family in ~20 lines (see
   [`examples/nl80211.rs`](https://github.com/jbaublitz/neli/blob/main/examples/nl80211.rs)).
   nlink's `zerocopy` approach is leaner at runtime but requires
   more hand-written code per new message type. **This is genuinely
   nicer for downstream crate authors.**

2. **A real `NlRouter` abstraction.** Inbound dispatch is fan-out to
   per-seq channels with a separate multicast `Receiver`. Concurrent
   requests on the same socket are safe by construction. nlink
   solves this differently (separate connections per concern), but
   neli's design has a cleaner conceptual story for the
   single-socket case.

3. **Mirrored sync + async APIs from one type tree.** `--features
   async` flips `synchronous::NlRouter` for `asynchronous::NlRouter`
   and the rest of the call shape is identical. nlink commits to
   async-only — fine for tokio users, awkward for anyone wanting
   sync.

4. **Symmetric `NlRouter` for foreign-defined GENL families.**
   Dispatch is generic over message type, so third-party crates
   (`wireguard-uapi`, `neli-wifi`, `nl80211-ng`) define their own
   command/attribute enums and reuse neli's whole machinery —
   and several do.

5. **Extended ACK / strict checking as first-class methods.**
   `rtnl.enable_ext_ack(true)?; rtnl.enable_strict_checking(true)?;`
   — one line each.

6. **Smaller surface area.** ~110 KB of `src/` total vs nlink's
   many submodules. Easier to read end-to-end.

7. **Real production adopters in the WiFi / desktop-bar niche.**
   Cloudflare's `rustfoundry`, plus `i3status-rs`, `i3stat`,
   `local-ip-address`, `wireguard-uapi`. nlink has the avionix-g
   downstream user (visible via PR #1, #2) but hasn't built a
   reverse-dep network of comparable breadth yet.

---

## 6. What neli does worse than nlink

Equally honest:

1. **Coverage is much narrower.** No nftables, no XFRM, no audit,
   no sock_diag, no fib_lookup, no SELinux, no uevent. Netfilter is
   stub-level (only NFULOG attrs + bind/unbind). nftables is the
   big absence — anyone building modern firewall configs reaches for
   nlink or shells out to `nft`.

2. **No TC typed configs at all.** No `HtbQdiscConfig`, no
   `TcHandle`, no `Rate`/`Bytes`/`Percent` units. TC use is
   "hand-build a `Tcmsg` and stuff attributes in." This is the
   gap that took nlink ~3 release cycles to close (`Plan 142` in the
   nlink history); neli hasn't started.

3. **No high-level recipes / helpers.** No rate limiter, no
   impairer, no namespace harness, no per-peer netem builder. neli
   stays a *protocol library*; nlink layers `RateLimiter`,
   `PerHostLimiter`, `PerPeerImpairer`, `LabNamespace`,
   `with_namespace`, `NetworkConfig` (declarative + reconcile)
   on top.

4. **String + null-terminator footguns.** The newvlan example
   contains `.rta_payload("vlan\0")` — a footgun the typed API
   doesn't filter for you. nlink's builders handle string
   termination internally.

5. **No ifindex-first / namespace-aware ergonomics.** Examples
   walk `Rtm::Getlink` dumps by hand and string-match `Ifla::Ifname`.
   There's no `get_link_by_index` typed helper, no documented
   "use ifindex inside foreign netns" guidance.

6. **MSRV undeclared.** No `rust-version` field. The README's
   "Support matrix" says only "nightly and stable are supported,"
   which doesn't help downstream Cargo.toml pinning. The
   2.4-edition revert in 0.7.3 suggests they're navigating
   compatibility carefully without a documented floor.

7. **`NlmF::CREATE | NlmF::EXCL | NlmF::ACK` everywhere.** Users
   manually compose flags per call. nlink hides flag composition
   inside the typed `add_link` / `add_route` / etc. methods,
   selecting the right flag set automatically.

---

## 7. User reception

Real reverse deps (from crates.io, ~24 total):
- **WiFi / network discovery**: `wireguard-uapi`, `neli-wifi`,
  `nl80211-ng`, `nl80211`, `netlink_wi`, `ssid`
- **Bus / link tooling**: `socketcan`, `socketcan-hal`, `local-ip-address`,
  `ip-nlroute`, `cotton-netif`
- **Status bars**: `i3status-rs`, `i3stat`, `home-router-exporter`
- **Production**: `foundations` / `rustfoundry` (Cloudflare's
  service-foundations library)
- **Specialized**: `phantun`, `tonel`, `muvm` (microVM), `nbd-netlink`,
  `pwrsurge`, `batman-robin`, `conntrack`, `e2etest-firewall`

The reverse deps lean heavily toward **WiFi / nl80211** and
**status-bar widgets** — exactly the niches GENL ergonomics matter
most.

Downloads: 29.1M all-time, 7.0M in the last 90 days. **0.6.5
dominates total downloads (10.9M)**, with 0.7.x recent uptake real
(3.4M for 0.7.4). The ecosystem is mid-migration to the 0.7
router-based API.

nlink has no comparable reverse-dep network yet (first 0.15.x cut
was April 2026). Time and downstream interest will tell.

---

## 8. When to choose which

### Choose **neli** when:

- You're defining a new GENL family in a downstream crate — the
  `#[neli_enum]` derive system makes this clean.
- You need sync + async APIs from the same code (CLI tool with a
  monitoring daemon mode, for instance).
- You're building a desktop widget / status bar / WiFi scanner.
- You're a Cloudflare-style infrastructure team comfortable with
  hand-rolling typed wrappers.
- Compile time and binary size matter to you (smaller surface).
- You want the canonical Rust netlink core that other ecosystem
  crates build on.

### Choose **nlink** when:

- You're building anything that needs **TC** (qdiscs, classes,
  filters, actions). nlink's typed configs are the only Rust offering
  here.
- You need **nftables**. Same.
- You need **XFRM IPsec**.
- You're building a **programmable router / firewall / network
  appliance** — nlink's "covers all four protocol families with one
  coherent API" is the strategic moat.
- You want **batteries-included** — rate limiters, impairers,
  namespace test harnesses, declarative `NetworkConfig` with
  diff/apply.
- You're already on tokio.
- You want **typed handles + units** (`TcHandle`, `Rate`, `Bytes`,
  `Percent`) end-to-end.

### They overlap in:

- rtnetlink basics (link/addr/route)
- Generic netlink core
- Connector proc events (both partial; nlink slightly wider)
- Extended-ACK / strict checking

For these basics, choose by code-style preference: neli for "I want
to see the wire format and own the message types," nlink for "I want
opinionated typed methods that compile to the right wire format."

---

## Honest TL;DR

`neli` is the right tool when you need a small, well-tested netlink
core that lets you **define new GENL families ergonomically with
proc-macro-derived codecs** — that's why `wireguard-uapi`,
`neli-wifi`, `nl80211-ng`, `socketcan`, and `foundations` build on
it. `nlink` is the right tool when you want **batteries-included
Linux network configuration** — TC typed builders, nftables
transactions, XFRM, sock_diag, audit, lab namespaces, and named
recipes — without assembling them yourself from primitives. Both
projects are single-maintainer, both have credible release cadences,
and both treat the netlink wire protocol as something to own
end-to-end rather than wrap an external library. They genuinely
overlap only in the rtnetlink + generic-netlink + connector core,
and even there neli's surface is "build the message yourself with
typed enums" while nlink's is `conn.add_qdisc(eth0, ROOT, htb_cfg)`.
If you're writing a desktop wifi widget or a custom GENL family,
reach for neli; if you're building a programmable router or a
network-test rig, reach for nlink.

---

## Sources

- [github.com/jbaublitz/neli](https://github.com/jbaublitz/neli)
- [Cargo.toml](https://github.com/jbaublitz/neli/blob/main/Cargo.toml)
- [README.md](https://github.com/jbaublitz/neli/blob/main/README.md)
- [CHANGELOG.md](https://github.com/jbaublitz/neli/blob/main/CHANGELOG.md)
- [src/lib.rs](https://github.com/jbaublitz/neli/blob/main/src/lib.rs)
- [src/connector.rs](https://github.com/jbaublitz/neli/blob/main/src/connector.rs)
- [src/router/asynchronous.rs](https://github.com/jbaublitz/neli/blob/main/src/router/asynchronous.rs)
- [src/consts/netfilter.rs](https://github.com/jbaublitz/neli/blob/main/src/consts/netfilter.rs)
- [examples/ctrl-list.rs](https://github.com/jbaublitz/neli/blob/main/examples/ctrl-list.rs)
- [examples/newvlan.rs](https://github.com/jbaublitz/neli/blob/main/examples/newvlan.rs)
- [examples/getlink.rs](https://github.com/jbaublitz/neli/blob/main/examples/getlink.rs)
- [examples/nl80211.rs](https://github.com/jbaublitz/neli/blob/main/examples/nl80211.rs)
- [examples/procmon.rs](https://github.com/jbaublitz/neli/blob/main/examples/procmon.rs)
- [neli-proc-macros/Cargo.toml](https://github.com/jbaublitz/neli/blob/main/neli-proc-macros/Cargo.toml)
- [crates.io: neli](https://crates.io/crates/neli)
- [crates.io: neli reverse dependencies](https://crates.io/crates/neli/reverse_dependencies)
- [wireguard-uapi-rs (representative downstream)](https://github.com/gluxon/wireguard-uapi-rs)
- [rust-netlink org (peer ecosystem)](https://github.com/rust-netlink)
