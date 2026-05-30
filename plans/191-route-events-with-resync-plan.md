---
to: nlink maintainers
from: nlink-lab feedback `nlink-feedback.md` §15 + W2 (2026-05-30)
subject: `Connection<Route>::subscribe` + `RouteEvent` + `into_events_with_resync` — RTNETLINK twin of Plan 185
status: queued for 0.19 — medium (substantial; the headline feature)
target version: 0.19.0
parent: (none — headline plan of the cycle)
source: nlink-lab `nlink-feedback.md` §15 (medium feature gap), W2 (wishlist)
created: 2026-05-30
---

# Plan 191 — `Connection<Route>::subscribe` + `RouteEvent` + ENOBUFS-resilient watcher

## 1. Why this plan exists

Plan 185 (0.18) shipped `Connection<Nftables>::{into,subscribe_all}_events_with_resync`
with the kube-rs-shaped watcher pattern. nlink-lab's Plan
158d watch command consumes that for nftables drift detection.
The RTNETLINK side is currently uncovered:

- `Connection<Route>` has no `subscribe` method.
- `RtnetlinkGroup` constants exist but there's no typed enum.
- `EventSource` impl for `Route` doesn't exist; there's no
  `RouteEvent` enum carrying parsed link / addr / route /
  neighbor mutations.
- No `Connection<Route>::into_events_with_resync`.

nlink-lab's Plan 158d documented this gap and falls back to
periodic polling via `NetworkConfig::diff` for the RTNETLINK
side. This plan closes the gap by mirroring Plan 185's shape.

The infrastructure is already in place — Plan 185's
generalization made `ConnectionFactory<P>` + `events_with_resync`
work for any protocol. This plan adds the Route-specific layer.

## 2. The change — six pieces

### 2.1 `RtnetlinkGroup` enum

```rust
// crates/nlink/src/netlink/events.rs (or new netlink/route_events.rs)

/// Subscribable multicast groups on the rtnetlink socket.
///
/// Mirrors the kernel `RTNLGRP_*` constants; `All` is the
/// convenience grouping for the common "watch every mutation"
/// pattern. New variants may be added; treat the enum as
/// open-set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RtnetlinkGroup {
    Link,      // RTNLGRP_LINK
    Notify,    // RTNLGRP_NOTIFY
    Neigh,     // RTNLGRP_NEIGH
    Tc,        // RTNLGRP_TC
    Ipv4Addr,  // RTNLGRP_IPV4_IFADDR
    Ipv4Route, // RTNLGRP_IPV4_ROUTE
    Ipv4Rule,  // RTNLGRP_IPV4_RULE
    Ipv6Addr,  // RTNLGRP_IPV6_IFADDR
    Ipv6Route, // RTNLGRP_IPV6_ROUTE
    Ipv6Rule,  // RTNLGRP_IPV6_RULE
    Mpls,      // RTNLGRP_MPLS_ROUTE
    Nsid,      // RTNLGRP_NSID
    /// Convenience grouping: subscribe to Link + Notify +
    /// Neigh + Ipv4Addr + Ipv4Route + Ipv6Addr + Ipv6Route.
    /// Most drift-detection consumers want this.
    All,
}

impl RtnetlinkGroup {
    pub fn to_kernel_group(self) -> u32 { ... }
    /// Expand `All` into the underlying per-kind set; identity
    /// for other variants. Used internally by `subscribe_all`.
    pub fn expand(self) -> &'static [RtnetlinkGroup] { ... }
}
```

This DEPRECATES the existing `RtnetlinkGroup` constants (raw
u32) in favor of the typed enum. Existing call sites of
`conn.subscribe(&[RtnetlinkGroup::Link as u32])` continue to
work via a `From<RtnetlinkGroup> for u32` impl; new code uses
the enum directly. Plan 0.19 cycle is a good moment to rename
the existing usage.

### 2.2 `RouteEvent` enum

```rust
// crates/nlink/src/netlink/route_events.rs

/// A typed multicast event delivered on the rtnetlink stream.
///
/// One variant per RTNETLINK `RTM_*` mutation we model.
/// Address / route / neigh / link CRUD shapes mirror the
/// dump-side parsers — `LinkMessage`, `AddressMessage`,
/// `RouteMessage`, `NeighborMessage` (already in the lib).
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum RouteEvent {
    NewLink(LinkMessage),
    DelLink(LinkMessage),
    NewAddr(AddressMessage),
    DelAddr(AddressMessage),
    NewRoute(RouteMessage),
    DelRoute(RouteMessage),
    NewNeigh(NeighborMessage),
    DelNeigh(NeighborMessage),
    // (TC mutations, rule mutations, NSID events deferred —
    //  add when a consumer asks.)
}
```

### 2.3 `impl EventSource for Route`

```rust
// crates/nlink/src/netlink/stream.rs

impl private::Sealed for super::protocol::Route {}

impl EventSource for super::protocol::Route {
    type Event = super::route_events::RouteEvent;

    fn parse_events(data: &[u8]) -> Vec<Self::Event> {
        let mut events = Vec::new();
        for (header, payload) in MessageIter::new(data).flatten() {
            if let Some(evt) = parse_route_event(header.nlmsg_type, payload) {
                events.push(evt);
            }
        }
        events
    }
}

pub(crate) fn parse_route_event(msg_type: u16, body: &[u8])
    -> Option<RouteEvent>
{
    use super::message::NlMsgType;
    match msg_type {
        NlMsgType::RTM_NEWLINK => {
            LinkMessage::from_bytes(body).ok().map(RouteEvent::NewLink)
        }
        NlMsgType::RTM_DELLINK => {
            LinkMessage::from_bytes(body).ok().map(RouteEvent::DelLink)
        }
        NlMsgType::RTM_NEWADDR => {
            AddressMessage::from_bytes(body).ok().map(RouteEvent::NewAddr)
        }
        // ... 5 more arms ...
        _ => None,
    }
}
```

### 2.4 `Connection<Route>::subscribe` + `subscribe_all`

```rust
// crates/nlink/src/netlink/connection.rs (or route.rs)

impl Connection<Route> {
    /// Subscribe to one or more rtnetlink multicast groups.
    /// After subscribing, consume events via [`Self::events`]
    /// / [`Self::into_events`] (returning
    /// `Stream<Item = Result<RouteEvent>>`).
    ///
    /// Mirrors [`Connection::<Nftables>::subscribe`] (Plan 185
    /// in 0.18).
    pub fn subscribe(&mut self, groups: &[RtnetlinkGroup]) -> Result<()> {
        for g in groups {
            for inner in g.expand() {
                self.socket_mut().add_membership(inner.to_kernel_group())?;
            }
        }
        Ok(())
    }

    /// Subscribe to every rtnetlink multicast group via
    /// [`RtnetlinkGroup::All`].
    pub fn subscribe_all(&mut self) -> Result<()> {
        self.subscribe(&[RtnetlinkGroup::All])
    }
}
```

### 2.5 `rtnetlink_snapshot` helper

```rust
// crates/nlink/src/netlink/route_resync.rs (new file)

/// Walk the current rtnetlink state — links, addresses,
/// routes, neighbors — and return one `New*` event per
/// existing entity. Used internally by
/// `into_events_with_resync` for ENOBUFS recovery; exposed
/// publicly so callers wiring their own resync can re-use
/// it.
///
/// Walk order: links → addresses → routes → neighbors. This
/// matches the order the kernel emits when a fresh netns
/// boots, so resync consumers replaying as creates stay
/// consistent with their runtime delta handler.
pub async fn rtnetlink_snapshot(conn: &Connection<Route>)
    -> Result<Vec<RouteEvent>>
{
    let mut out = Vec::new();
    for link in conn.get_links().await? {
        out.push(RouteEvent::NewLink(link));
    }
    for addr in conn.get_addresses().await? {
        out.push(RouteEvent::NewAddr(addr));
    }
    for route in conn.get_routes().await? {
        out.push(RouteEvent::NewRoute(route));
    }
    for neigh in conn.get_neighbors().await? {
        out.push(RouteEvent::NewNeigh(neigh));
    }
    Ok(out)
}
```

### 2.6 `Connection<Route>::into_events_with_resync` + `subscribe_all_with_resync`

Mirror of Plan 185's nftables shape — uses the generic
`ConnectionFactory<Route>` + `events_with_resync` from the
shared resync infra.

```rust
// crates/nlink/src/netlink/route_resync.rs

pub type OwnedResyncStream =
    ResyncStream<'static, OwnedEventStream<Route>, RouteEvent, SnapshotFn>;
pub type BorrowedResyncStream<'a> =
    ResyncStream<'static, EventSubscription<'a, Route>, RouteEvent, SnapshotFn>;

impl Connection<Route> {
    /// Subscribe to every rtnetlink multicast group + return
    /// an ENOBUFS-resilient event stream that **owns** the
    /// connection.
    ///
    /// Mirrors [`Connection::<Nftables>::into_events_with_resync`]
    /// (Plan 185). The factory is invoked on every ENOBUFS
    /// overflow; the wrapper re-dumps state via
    /// [`rtnetlink_snapshot`] on a fresh connection and emits
    /// the snapshot as `Resynced(...)` items between
    /// `ResyncStart` / `ResyncEnd` markers.
    pub fn into_events_with_resync(
        mut self,
        factory: ConnectionFactory<Route>,
    ) -> Result<OwnedResyncStream> {
        self.subscribe_all()?;
        let stream = self.into_events();
        Ok(events_with_resync(stream, make_snapshot_fn(factory)))
    }

    /// Borrowed sibling of [`Self::into_events_with_resync`].
    pub fn subscribe_all_with_resync(
        &mut self,
        factory: ConnectionFactory<Route>,
    ) -> Result<BorrowedResyncStream<'_>> {
        self.subscribe_all()?;
        let stream = self.events();
        Ok(events_with_resync(stream, make_snapshot_fn(factory)))
    }
}

fn make_snapshot_fn(factory: ConnectionFactory<Route>) -> SnapshotFn {
    Box::new(move || {
        let factory = factory.clone();
        Box::pin(async move {
            let conn = (factory)().await?;
            rtnetlink_snapshot(&conn).await
        })
    })
}
```

## 3. Implementation phases

| Phase | Files | LOC |
|---|---|---|
| 1 — `RtnetlinkGroup` enum + kernel-id mapping + `expand` | `events.rs` or new `route_events.rs` | ~80 |
| 2 — `RouteEvent` enum + `parse_route_event` | new `route_events.rs` | ~80 |
| 3 — `impl EventSource for Route` | `stream.rs` | ~30 |
| 4 — `Connection<Route>::subscribe` + `subscribe_all` | `connection.rs` | ~30 |
| 5 — `rtnetlink_snapshot` helper | new `route_resync.rs` | ~30 |
| 6 — `into_events_with_resync` + borrowed sibling + type aliases | `route_resync.rs` | ~50 |
| 7 — Re-exports in `lib.rs` (`RouteEvent`, `RtnetlinkGroup`, snapshot) | `lib.rs` | ~5 |
| 8 — Recipe at `docs/recipes/route-watch-with-resync.md` | new file | ~120 |
| 9 — Tests (see §4) | various | ~300 |
| **Total** | | **~725 LOC** |

## 4. Tests

### 4.1 Unit — `RtnetlinkGroup::to_kernel_group` mapping

```rust
#[test]
fn rtnetlink_group_maps_to_kernel_constants() {
    assert_eq!(RtnetlinkGroup::Link.to_kernel_group(), libc::RTNLGRP_LINK);
    assert_eq!(RtnetlinkGroup::Ipv4Addr.to_kernel_group(), libc::RTNLGRP_IPV4_IFADDR);
    // ... 11 more ...
}

#[test]
fn rtnetlink_group_all_expands_to_canonical_set() {
    let expanded = RtnetlinkGroup::All.expand();
    assert!(expanded.contains(&RtnetlinkGroup::Link));
    assert!(expanded.contains(&RtnetlinkGroup::Ipv4Addr));
    assert!(expanded.contains(&RtnetlinkGroup::Ipv6Addr));
    // All variant must NOT recurse into itself.
    assert!(!expanded.contains(&RtnetlinkGroup::All));
}
```

### 4.2 Unit — `parse_route_event` dispatch

```rust
#[test]
fn parse_route_event_dispatches_newlink() {
    // Build a synthetic RTM_NEWLINK payload with a known
    // LinkMessage shape, run through parse_route_event,
    // assert NewLink(...) variant + payload preserved.
    let payload = build_newlink_payload("eth0", ifindex=2);
    let evt = parse_route_event(NlMsgType::RTM_NEWLINK, &payload).unwrap();
    match evt {
        RouteEvent::NewLink(msg) => {
            assert_eq!(msg.name.as_deref(), Some("eth0"));
            assert_eq!(msg.ifindex(), 2);
        }
        _ => panic!("expected NewLink"),
    }
}

#[test]
fn parse_route_event_rejects_unrecognized_msg_type() {
    // Some out-of-band msg type — must return None, not panic.
    let evt = parse_route_event(0xFFFF, &[]);
    assert!(evt.is_none());
}

#[test]
fn parse_route_event_rejects_truncated_payload() {
    let evt = parse_route_event(NlMsgType::RTM_NEWLINK, &[0u8; 1]);
    assert!(evt.is_none());
}
```

### 4.3 Unit — snapshot ordering

```rust
#[test]
fn snapshot_walks_in_canonical_order() {
    // Mock the dump methods (or run against a fresh netns
    // integration test — see 4.5). Assert the returned Vec
    // is in [links..., addrs..., routes..., neighs...] order.
    ...
}

#[test]
fn snapshot_factory_clones_on_each_resync_call() {
    let counter = Arc::new(AtomicUsize::new(0));
    let factory: ConnectionFactory<Route> = {
        let c = counter.clone();
        Arc::new(move || {
            c.fetch_add(1, Ordering::SeqCst);
            Box::pin(async { Connection::<Route>::new() })
        })
    };
    // Construct the snapshot fn via make_snapshot_fn; invoke
    // twice; assert counter is 2.
    let mut snap = make_snapshot_fn(factory);
    let _ = futures::executor::block_on(async {
        (snap)().await
    });
    let _ = futures::executor::block_on(async {
        (snap)().await
    });
    assert_eq!(counter.load(Ordering::SeqCst), 2);
}
```

### 4.4 Integration — basic subscribe + event arrival

In `crates/nlink/tests/integration/route_events.rs` (new file):

```rust
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn subscribe_link_sees_add_link_from_other_conn() -> Result<()> {
    require_root!();

    let ns = TestNamespace::new("route-events-link")?;
    let ns_name = ns.name().to_string();

    let mut event_conn = namespace::connection_for::<Route>(&ns_name)?;
    event_conn.subscribe(&[RtnetlinkGroup::Link])?;
    let mut events = event_conn.events();

    // From another connection in the same ns, create a dummy.
    let writer = namespace::connection_for::<Route>(&ns_name)?;
    writer.add_link(DummyLink::new("dummy0")).await?;

    // Drain the event stream with a deadline.
    let evt = tokio::time::timeout(
        Duration::from_secs(5),
        events.next(),
    )
    .await
    .map_err(|_| nlink::Error::Timeout)?
    .expect("stream must yield an event")?;

    match evt {
        RouteEvent::NewLink(msg) => {
            assert_eq!(msg.name.as_deref(), Some("dummy0"));
        }
        other => panic!("expected NewLink, got {other:?}"),
    }

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn subscribe_all_with_resync_yields_resync_markers_on_enobufs()
    -> Result<()>
{
    require_root!();

    // Mirror Plan 185's ENOBUFS integration test. Set rcvbuf
    // tiny, spawn an mutator that floods add_link/del_link
    // from another connection, drain slowly, assert
    // `Marker(ResyncStart) → Resynced(...) → Marker(ResyncEnd)`.
    //
    // Cross-references Plan 185's
    // `into_events_with_resync_recovers_from_enobufs` test.
    ...
}
```

### 4.5 Integration — snapshot walks ruleset

```rust
#[tokio::test]
async fn rtnetlink_snapshot_walks_links_addrs_routes() -> Result<()> {
    require_root!();

    let ns = TestNamespace::new("rtnl-snap")?;
    let conn = namespace::connection_for::<Route>(ns.name())?;

    conn.add_link(DummyLink::new("eth0")).await?;
    conn.add_address("eth0", IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 24).await?;

    let snapshot = nlink::netlink::route_resync::rtnetlink_snapshot(&conn).await?;

    let links: Vec<_> = snapshot.iter()
        .filter_map(|e| if let RouteEvent::NewLink(l) = e { Some(l) } else { None })
        .collect();
    assert!(links.iter().any(|l| l.name.as_deref() == Some("eth0")));
    let addrs: Vec<_> = snapshot.iter()
        .filter_map(|e| if let RouteEvent::NewAddr(a) = e { Some(a) } else { None })
        .collect();
    assert!(!addrs.is_empty(), "must include the address we set");

    Ok(())
}
```

### 4.6 Recipe — `docs/recipes/route-watch-with-resync.md`

Mirror of `nftables-watch-with-resync.md` (Plan 185). Same
shape, swap `Nftables` for `Route`. Covers:
- Plain `into_events_with_resync(factory)` usage
- Borrowed `subscribe_all_with_resync` alternative
- Namespace-aware factory
- What the snapshot enumerates (links, addrs, routes, neighs)
- Cross-references the lower-level `events_with_resync`

## 5. Acceptance criteria

- [ ] `RtnetlinkGroup` enum + kernel-id mapping + `expand`.
- [ ] `RouteEvent` enum with 8 variants
      (NewLink/DelLink/NewAddr/DelAddr/NewRoute/DelRoute/NewNeigh/DelNeigh).
- [ ] `impl EventSource for Route`.
- [ ] `Connection<Route>::{subscribe, subscribe_all}`.
- [ ] `Connection<Route>::{into,subscribe_all}_events_with_resync`.
- [ ] `rtnetlink_snapshot(&Connection<Route>)` helper.
- [ ] Re-exports at the crate root for `RouteEvent`,
      `RtnetlinkGroup`, `rtnetlink_snapshot`.
- [ ] 6+ unit tests covering group mapping, event parsing,
      snapshot ordering, factory clone semantics.
- [ ] 3+ integration tests covering subscribe arrival, full
      snapshot enumeration, ENOBUFS recovery (root-gated).
- [ ] Recipe `docs/recipes/route-watch-with-resync.md`.
- [ ] CHANGELOG `### Added` entry (substantial — the headline
      of 0.19).
- [ ] Migration guide entry; reference to Plan 185 as the
      precedent shape.

## 6. Effort estimate

| Phase | Effort |
|---|---|
| Code (~725 LOC across 5 files) | ~4 h |
| Unit tests (~6) | ~1.5 h |
| Integration tests (~3) — includes flaky ENOBUFS shaping | ~2.5 h |
| Recipe | ~1 h |
| CHANGELOG + migration guide | ~30 min |
| **Total** | **~9.5 h** |

## 7. Risks

- **The ENOBUFS integration test is timing-sensitive**, same
  caveat as Plan 185. Use the same `set_rcvbuf` /
  flood-from-second-conn pattern. The Plan 185 fix to
  `is_no_buffer_space` (catching `Io(ENOBUFS)`) is already
  in place; this test should pass on the first push (Plan
  185 spent two pushes catching that bug).
- **Existing `RtnetlinkGroup` raw constants** — we have to
  keep them working as `From<RtnetlinkGroup> for u32` or
  deprecate them carefully. Pick the deprecation path
  (`#[deprecated]` on the constants, point to the enum)
  since the 0.19 cycle is breakage-tolerant.
- **`RouteEvent` enum non-exhaustive growth** — TC mutations,
  rule changes, NSID events all live in RTNETLINK too. We
  ship only the 8 most-asked-for variants in this plan;
  callers consuming Vec<RouteEvent> via exhaustive `match`
  will break on future additions. Document that match arms
  must include `_ => ...` (the standard `#[non_exhaustive]`
  contract).

## 8. Out-of-scope follow-ups

- **TC event variants** — `NewTfilter`/`DelTfilter`/
  `NewQdisc`/`DelQdisc` etc. Useful for TC change tracking
  but no current consumer.
- **Rule event variants** — `NewRule`/`DelRule` (the
  `ip rule` lineage). Same — no consumer.
- **`Connection<Wireguard>` / `Connection<Generic>`
  equivalents** — WireGuard's monitor stream is its own
  shape; defer to a separate plan.
- **W1 (dump-cache invalidation)** — moot if Plan 186's
  diagnosis lands cleanly. If a real cache turns out to be
  needed, the resync stream itself is the natural place
  (re-dump on demand via the factory).

## 9. Cross-cutting artifacts

This is the cycle's headline; the artifact surface is the
biggest of any 0.19 plan.

| Artifact | Action | Notes |
|---|---|---|
| `CHANGELOG.md` `## [Unreleased]` | **add** `### Added` headline entry covering `Connection<Route>::subscribe` + `RouteEvent` + `into_events_with_resync` + `subscribe_all_with_resync` + `rtnetlink_snapshot` | Lead with cross-reference to Plan 185 (the nftables precedent). |
| `docs/migration_guide/0.18.0-to-0.19.0.md` | **append** `### Plan 191 — RTNETLINK events` substantial section: new `RouteEvent` enum (non-exhaustive — match arms need `_ => ...`), `RtnetlinkGroup` typed enum supersedes raw `u32` constants (deprecated), recipe link | Step-by-step migration of any existing rtnetlink subscriber. |
| `docs/recipes/route-watch-with-resync.md` (**new**) | **create** ~150 lines mirroring `nftables-watch-with-resync.md` shape | Already noted in §3 of this plan. |
| `docs/recipes/README.md` | **add row** for `route-watch-with-resync.md` | One-line entry. |
| `crates/nlink/examples/events/route_watch_with_resync.rs` (**new**) | **create** ~80-line runnable demo using `into_events_with_resync` | Mirrors the existing `examples/events/resync_loop.rs` shape (Plan 151) for the new API. Register in `Cargo.toml`. |
| `crates/nlink/examples/events/route_subscribe.rs` (**new**) | **create** ~50-line minimal subscribe demo (no resync) | Pedagogical step before the resync recipe; helps newcomers. |
| `README.md` `## Library Modules` table | **update** the `nlink::netlink` row to mention RouteEvent subscription | One-line update — matches the existing nftables row treatment. |
| `README.md` `## High-Level APIs` section | **add a sub-section** "RTNETLINK Event Subscription" mirroring the nftables event section | ~10 lines, like the existing nftables section. |
| `CLAUDE.md` | **append** in the existing protocol section: `Route` now implements `EventSource`; `Connection<Route>::subscribe` is the typed entry point; `RtnetlinkGroup::All` is the convenience grouping | Two-paragraph addition; mention Plan 185 precedent. |
| Deprecation note: existing raw `RtnetlinkGroup` `const u32` table | **mark deprecated** with `since = "0.19.0"` + point to the typed enum | Two-release cycle (removed 0.20). Document in CHANGELOG `### Deprecated`. |

End of plan.
