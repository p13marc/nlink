# nlink Crate Feedback Report

**From:** nlink-lab project (network lab engine)
**Date:** 2026-03-28
**nlink version:** git main (commit 481a12e)
**nlink-lab context:** ~2,500 lines of nlink API usage across deploy, runtime, and diagnostics modules

---

## Executive Summary

nlink-lab is a network lab engine that creates isolated, reproducible network topologies
using Linux namespaces. It is the heaviest consumer of nlink's API surface — we use
namespaces, veth pairs, bridges, VLANs, VRFs, VXLAN, WireGuard, routes, nftables,
netem, rate limiting, diagnostics, and more, all in a single deployment pipeline.

Overall, nlink is **excellent**. The async-first design, type-safe protocol states
(`Connection<Route>`, `Connection<Nftables>`, `Connection<Wireguard>`), and the
builder patterns for link types all work very well. The diagnostics module is
particularly valuable for us.

This report documents concrete friction points, missing APIs, and feature requests
based on real production usage patterns.

---

## 1. Friction Points (things that work but are awkward)

### 1.1 The resolve-then-act pattern for addresses

Every time we add an address to an interface, we must first resolve the interface
name to an index, then call `add_address_by_index`:

```rust
// This 4-step pattern appears 4 times in our deploy.rs:
let iface_ref = nlink::netlink::InterfaceRef::Name(ep.iface.clone());
let idx = conn.resolve_interface(&iface_ref).await?;
conn.add_address_by_index(idx, ip, prefix).await?;
```

**Request:** Add `add_address_by_name(name, ip, prefix)` that resolves internally.
Same for `del_address_by_name`. The index-based API should still exist for cases
where callers already have the index.

### 1.2 Bringing up all interfaces requires full enumeration

After creating interfaces in a namespace, we bring them all up by fetching the
entire link list and iterating:

```rust
let links = conn.get_links().await?;
for link_msg in &links {
    conn.set_link_up_by_index(link_msg.ifindex()).await?;
}
```

**Request:** Either a `set_all_links_up()` convenience method, or (better) a way
to bring an interface up as part of creation. Many link builders could take an
`up: bool` parameter.

### 1.3 WireGuard connections require manual namespace entry

For Route and Nftables connections, we can use `namespace::connection_for(name)`.
For WireGuard, we must manually enter the namespace and construct a new connection:

```rust
// Route — clean one-liner:
let conn: Connection<Route> = namespace::connection_for(ns_name)?;

// WireGuard — requires namespace entry guard:
let _guard = namespace::enter(ns_name)?;
let wg_conn = Connection::<Wireguard>::new_async().await?;
```

**Request:** Add `namespace::connection_for::<P>(name)` as a generic over protocol
state, or at minimum `namespace::wireguard_connection_for(name)`.

### 1.4 Qdisc update requires try-change-then-add fallback

To update a netem qdisc at runtime, we must try `change_qdisc` first, and if it
fails (qdisc doesn't exist yet), fall back to `add_qdisc`:

```rust
match conn.change_qdisc(&ep.iface, "root", netem.clone()).await {
    Ok(()) => Ok(()),
    Err(_) => conn.add_qdisc(&ep.iface, netem).await...,
}
```

This discards the error from `change_qdisc` — we can't tell if it failed because
the qdisc doesn't exist vs. an actual error.

**Request:** Either:
- Add `upsert_qdisc(iface, config)` that does add-or-replace atomically, or
- Make the error from `change_qdisc` distinguishable (e.g., `Error::NotFound` vs
  `Error::Kernel`) so we can match on it properly, or
- Add `has_qdisc(iface, handle)` to check before acting

### 1.5 Bond enslavement is a 3-step dance

Enslaving an interface to a bond requires three separate awaits:

```rust
conn.set_link_down(member).await?;       // must be down first
conn.set_link_master(member, bond).await?; // enslave
conn.set_link_up(member).await?;           // bring back up
```

**Request:** `enslave_to_bond(member, bond)` that handles the down/master/up
sequence internally — this is always the correct sequence and never varies.

---

## 2. Missing APIs (things we need that don't exist)

### 2.1 Interface name validation

Linux interface names have strict rules: 1-15 characters, no `/` or whitespace,
not `.` or `..`. We wrote our own `validate_interface_name()` in our helpers
module. nlink should validate this at the builder level.

Currently, if you pass a 20-character name to `VethLink::new()`, nlink sends it
to the kernel and gets a cryptic `EINVAL` back. A pre-send validation with a clear
error message would prevent debugging time.

**Specific ask:** Validate interface names in all link builder constructors. Return
`Error::Interface { name, reason }` early.

### 2.2 Reading current qdisc/netem configuration

We can add, change, and delete qdiscs, but there's no convenient way to read back
the current netem parameters on an interface. `get_qdiscs_by_name()` returns raw
`TcMessage` — we'd need to parse the netem-specific attributes ourselves.

**Request:** A `get_netem_config(iface)` that returns `Option<NetemConfig>` with
the currently-applied delay/jitter/loss/rate values. This would let us implement
idempotent apply operations and diff current vs. desired state.

### 2.3 Bulk/batch operations for common patterns

Our deploy sequence makes ~40+ individual netlink calls per namespace. While each
is fast, the round-trips add up for large topologies (20+ nodes). nlink has
`batch()` for nftables, but not for Route operations.

**Request:** Extend the batch API to cover Route operations — specifically
`add_link`, `add_address`, `add_route` in a single atomic batch. Even if Linux
doesn't support true atomicity across all these, reducing round-trips would help.

### 2.4 Deleting addresses by name

We can `add_address_by_index` but there's no `del_address_by_name` — we have to
resolve the index first. Same friction as 1.1 above.

### 2.5 Checking if a namespace exists

We use `namespace::exists(name)` which nlink provides — great. But there's no
equivalent for checking if an interface exists in a namespace without creating a
full connection and calling `get_link_by_name`. A lightweight
`namespace::interface_exists(ns, iface)` would be useful for idempotency checks.

---

## 3. Diagnostics Module Feedback

The diagnostics module is **one of the best features of nlink** for us. We use it
for live monitoring, CLI dashboards, and Zenoh metric publishing.

### 3.1 What works great

- `Diagnostics::scan()` is exactly what we need — one call, full picture
- `InterfaceDiag` with pre-computed `rates` (rx_bps, tx_bps) saves us from
  tracking state ourselves
- `Issue` detection with `Severity` and `IssueCategory` is very useful
- `TcDiag` with qdisc drops, backlog, and queue length

### 3.2 Requests

- **`LinkStats` fields are private** — we access them via methods like
  `.rx_errors()`, `.tx_errors()`, which is fine, but we'd prefer public fields
  for destructuring in metric conversion code. Currently we write:
  ```rust
  rx_errors: iface.stats.rx_errors(),
  tx_errors: iface.stats.tx_errors(),
  ```
  vs. what we'd like:
  ```rust
  rx_errors: iface.stats.rx_errors,
  ```

- **`OperState` doesn't implement `Display`** — we use `format!("{:?}", state)`
  to get "Up", "Down", etc. for our metrics. A proper `Display` impl that produces
  "up", "down", "unknown" etc. would be cleaner.

- **Per-interface rate calculation depends on previous sample** — the diagnostics
  module calculates rates between scans, which is excellent. However, the first
  scan always returns zero rates. It would be nice to have an option to do a
  two-sample scan with a configurable sleep (e.g., 100ms) for one-shot rate
  measurement.

---

## 4. Feature Requests (new capabilities)

### 4.1 Interface creation with address + up in one call

The most common pattern in network lab creation is:
1. Create interface (veth/bridge/etc.)
2. Set address
3. Bring up

A builder that chains these would be significantly more ergonomic:

```rust
// Dream API:
conn.add_link(
    VethLink::new("eth0", "eth0")
        .peer_netns_fd(ns_fd)
        .address_a("10.0.0.1/24")
        .address_b("10.0.0.2/24")
        .up()
).await?;
```

### 4.2 Namespace-scoped connection pool

We create 12+ `Connection<Route>` instances per namespace during deployment (one
per operation phase). A namespace-scoped connection that can be reused would reduce
socket creation overhead:

```rust
// Current: create connection each time
let conn: Connection<Route> = namespace::connection_for(ns_name)?;

// Desired: reuse connection
let ns = namespace::scope(ns_name)?;  // holds FD
let conn = ns.connection::<Route>()?; // reuses socket
```

### 4.3 Link deletion by name in foreign namespace

`conn.del_link(name)` works when the connection is in the right namespace. But for
cleanup during topology teardown, we'd like to delete a veth pair from the host
namespace by specifying the target namespace. Currently we must create a connection
in the target namespace just to delete one interface.

### 4.4 nftables: more match expressions

Our firewall support is limited to `tcp dport`, `udp dport`, and `ct state` because
those are the only match types the nftables Rule builder supports. We'd like:

- Source/destination IP matching (`ip saddr`, `ip daddr`)
- Interface matching (`iif`, `oif`)
- Protocol matching (`meta l4proto`)
- Negation (`!=`)
- ICMP type matching
- Rate limiting (`limit rate`)
- Log action
- NAT actions (SNAT, DNAT, masquerade)

### 4.5 Route deletion by destination

We can add routes easily, but `del_route_v4`/`del_route_v6` require constructing
the full route object. A simpler `del_route_by_dest(dest, prefix)` would help for
incremental topology updates where we need to remove routes by destination.

---

## 5. Error Handling Feedback

### 5.1 What works well

- `Error::Kernel { errno, message }` is great for debugging — the errno is
  essential for understanding kernel rejections
- `#[from] nlink::Error` works perfectly with our error enum
- The error chain is clean and informative

### 5.2 Requests

- **Distinguish "not found" errors** — When `change_qdisc` fails because the qdisc
  doesn't exist, the error is a generic `Kernel { errno: -2, ... }` (ENOENT). An
  `Error::NotFound` variant for interface/qdisc/route lookups would let us write:
  ```rust
  match conn.change_qdisc(...).await {
      Ok(()) => Ok(()),
      Err(nlink::Error::NotFound { .. }) => conn.add_qdisc(...).await,
      Err(e) => Err(e),
  }
  ```

- **Include operation context in errors** — `Error::KernelWithContext` exists but
  isn't always used. When `add_link` fails, knowing it was specifically during
  "add_link for VethLink named eth0" (not just "EEXIST") would reduce wrapping:
  ```rust
  // Currently we wrap every call with context:
  conn.add_link(veth).await.map_err(|e| {
      Error::deploy_failed(format!("failed to create veth '{}': {e}", name))
  })?;
  ```
  If nlink's errors included the operation and target, we could skip ~90 of these
  `map_err` wrappers.

---

## 6. API Ergonomics — Small Improvements

| Current | Suggested | Reason |
|---------|-----------|--------|
| `InterfaceRef::Name(name.clone())` | `InterfaceRef::name(name)` | Avoid allocation for &str |
| `BridgeVlanBuilder::new(vid).dev(name)` | `conn.add_bridge_vlan(port, vid)` | Common case needs fewer steps |
| `VethLink::new(a, b).peer_netns_fd(fd.as_raw_fd())` | `.peer_netns(fd)` accepting NamespaceFd directly | Avoid raw FD exposure |
| `Connection::<Wireguard>::new_async().await` | `Connection::wireguard().await` | Turbofish is noisy |
| `namespace::connection_for(name)` returns `Result<Connection<Route>>` | Generic over protocol state | One function for all protocols |

---

## 7. Documentation Suggestions

- **Cookbook/recipes section** for common patterns (create veth pair between
  namespaces, set up bridge with VLANs, configure netem)
- **Error handling guide** showing which operations can return which error variants
- **Namespace lifecycle** guide explaining connection lifetimes, FD management,
  and when to use `connection_for` vs `enter` + `new`
- **Migration guide** between nlink versions (we track git main)

---

## 8. Summary: Priority Ranking

| # | Request | Impact | Effort |
|---|---------|--------|--------|
| 1 | `add_address_by_name` / name-based address ops | High (removes 4+ resolve steps) | Low |
| 2 | Distinguish NotFound errors from Kernel errors | High (enables idempotent ops) | Low |
| 3 | Interface name validation in builders | High (prevents cryptic EINVAL) | Low |
| 4 | `upsert_qdisc` or qdisc existence check | Medium (removes fallback hack) | Low |
| 5 | `OperState` Display impl | Medium (cleaner metrics code) | Trivial |
| 6 | Public LinkStats fields | Low (cosmetic) | Trivial |
| 7 | Namespace-generic connection_for | Medium (WireGuard ergonomics) | Medium |
| 8 | nftables match expressions (saddr, daddr, iif) | High (unblocks firewall features) | Medium |
| 9 | `enslave_to_bond` convenience method | Low (saves 3 lines) | Low |
| 10 | Batch Route operations | Medium (perf for large topologies) | High |
| 11 | `get_netem_config` to read back qdisc params | Medium (enables diff/apply) | Medium |
| 12 | VethLink builder with address + up | Low (nice-to-have) | Medium |

---

## Appendix: nlink API Surface Used by nlink-lab

| Module | APIs Used | Call Count |
|--------|-----------|------------|
| `namespace` | create, delete, exists, open, connection_for, connection_for_pid, spawn, spawn_output, enter, set_sysctls (+ path variants) | ~30 |
| `Connection<Route>` | add_link, set_link_up/down, set_link_master, set_link_mtu, del_link, get_links, resolve_interface, add_address_by_index, add_route, add_qdisc, change_qdisc, del_qdisc | ~50 |
| `Connection<Nftables>` | add_table, add_chain, add_rule | ~5 |
| `Connection<Wireguard>` | set_device (private_key, listen_port, peer) | ~4 |
| `link::*` | VethLink, BridgeLink, DummyLink, VxlanLink, BondLink, VlanLink, VrfLink, WireguardLink | 8 types |
| `route::*` | Ipv4Route, Ipv6Route (gateway, dev, metric, table) | ~10 |
| `tc::NetemConfig` | delay, jitter, loss, rate_bps, corrupt, reorder | ~6 |
| `ratelimit::RateLimiter` | new, egress, ingress, apply | ~4 |
| `bridge_vlan::BridgeVlanBuilder` | new, dev, pvid, untagged | ~5 |
| `diagnostics::Diagnostics` | new, scan | ~3 |
| **Total** | | **~125 nlink API calls** |
