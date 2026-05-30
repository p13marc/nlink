---
to: nlink maintainers
from: Plan 193 §2.2 implementation finding (2026-05-30)
subject: RTA_MULTIPATH parser — make multipath routes round-trip through `get_routes()`
status: queued for 0.19 — medium (real gap surfaced during the parser-robustness audit)
target version: 0.19.0
parent: (none — surfaced by Plan 193 §2.2 implementation; ships as its own plan)
source: Plan 193 phase 1 audit (commit `be52799` discovery): nlink has `write_multipath_v4`/`v6` but no `parse_multipath_*` symbol
created: 2026-05-30
---

# Plan 202 — RTA_MULTIPATH parser

## 1. Why this plan exists

Plan 193's phase-1 audit was supposed to add pathological-
input guards to nlink's multipath/nexthop chain walker.
**No such walker exists.** nlink can WRITE multipath routes
(`write_multipath_v4`, `write_multipath_v6` at
`crates/nlink/src/netlink/route.rs:1349,1387`) but doesn't
parse them back from kernel responses. Multipath routes
round-tripped through `Connection<Route>::get_routes()` come
back without their nexthop list — `route.multipath` is empty
when the kernel-side route has multiple nexthops.

This is a real feature gap, not a bug per se:

- `Ipv4Route::multipath` / `Ipv6Route::multipath` are write-
  only fields. Their values are sent to the kernel correctly
  on `add_route` but lost on `get_routes` dump-and-parse.
- Drift detection via `NetworkConfig::diff` can't detect a
  multipath change: the config side carries the nexthop list,
  the kernel-side parse drops it, the diff says "config wants
  multipath; kernel has none" forever.
- `nlink-lab` consumers who care about ECMP cross-zone routes
  silently lose multipath state after every drift check.

## 2. The change

### 2.1 Add `parse_multipath_v4` + `parse_multipath_v6`

```rust
// crates/nlink/src/netlink/route.rs (companion to the
// existing write_multipath_*)

/// Parse an `RTA_MULTIPATH` attribute payload into a list of
/// nexthops. The payload is a chain of `rtnexthop` headers
/// each followed by zero or more attributes (`RTA_GATEWAY`
/// etc.) describing the nexthop.
///
/// Plan 193 §2.2's pathological-input guards apply here:
/// - `rtnh_len < sizeof(rtnexthop)` is end-of-chain or skip
/// - `rtnh_len == 0` is malformed; abort the walk (prevents
///   the infinite-loop scenario tracked by
///   netlink-packet-route #152)
/// - `offset + rtnh_len > payload.len()` is truncated; stop
fn parse_multipath_v4(data: &[u8]) -> Vec<NextHop> {
    let mut nexthops = Vec::new();
    let mut offset = 0;
    while offset + RTNH_HDRLEN <= data.len() {
        let hdr = match RtNextHop::from_bytes(&data[offset..]) {
            Ok(h) => h,
            Err(_) => break,
        };
        let rtnh_len = hdr.rtnh_len as usize;
        // Defensive guards (Plan 193 §2.2).
        if rtnh_len < RTNH_HDRLEN || offset + rtnh_len > data.len() {
            tracing::warn!(
                rtnh_len, offset, total = data.len(),
                "parse_multipath_v4: malformed nexthop chain, aborting walk"
            );
            break;
        }
        let attrs = &data[offset + RTNH_HDRLEN..offset + rtnh_len];
        // Parse nested attributes within the nexthop block:
        // RTA_GATEWAY, RTA_NEWDST, etc.
        let mut nh = NextHop {
            ifindex: Some(hdr.rtnh_ifindex),
            ..Default::default()
        };
        for (attr_type, payload) in AttrIter::new(attrs) {
            match attr_type {
                RtaAttr::Gateway if payload.len() >= 4 => {
                    nh.gateway = Some(IpAddr::V4(Ipv4Addr::from(
                        u32::from_ne_bytes(payload[..4].try_into().unwrap())
                    )));
                }
                // ... other attrs ...
                _ => {}
            }
        }
        nh.weight = Some(hdr.rtnh_hops + 1);  // kernel stores as hops, not weight
        nexthops.push(nh);
        // Advance by aligned length.
        offset += align4(rtnh_len);
    }
    nexthops
}
```

Same shape for `parse_multipath_v6` — different `RTA_GATEWAY`
payload size (16 bytes).

### 2.2 Wire into `Ipv4Route::from_bytes` / `Ipv6Route::from_bytes`

```rust
// crates/nlink/src/netlink/route.rs (inside the existing
// from_bytes dispatch over RTA attribute types)

RtaAttr::Multipath => {
    let nexthops = if family == AF_INET {
        parse_multipath_v4(payload)
    } else {
        parse_multipath_v6(payload)
    };
    if !nexthops.is_empty() {
        route.multipath = Some(nexthops);
    }
}
```

### 2.3 Round-trip integration test

The headline test — multipath route survives the
write → dump → parse cycle.

```rust
// crates/nlink/tests/integration/route.rs (existing file;
// new test below)

#[tokio::test]
async fn multipath_route_round_trips_through_get_routes() -> Result<()> {
    require_root!();

    let ns = TestNamespace::new("mp-roundtrip")?;
    let conn = namespace::connection_for::<Route>(ns.name())?;

    // Set up two dummies to use as nexthop egress interfaces.
    conn.add_link(DummyLink::new("eth0")).await?;
    conn.add_link(DummyLink::new("eth1")).await?;
    conn.set_link_up_by_name("eth0").await?;
    conn.set_link_up_by_name("eth1").await?;
    conn.add_address("eth0", IpAddr::V4("10.0.0.1".parse()?), 24).await?;
    conn.add_address("eth1", IpAddr::V4("10.0.1.1".parse()?), 24).await?;

    let r = Ipv4Route::new("192.0.2.0", 24)
        .multipath(vec![
            NextHop::new().gateway("10.0.0.254").dev("eth0").weight(1),
            NextHop::new().gateway("10.0.1.254").dev("eth1").weight(2),
        ]);
    conn.add_route_v4(&r).await?;

    let routes = conn.get_routes().await?;
    let dumped = routes.iter()
        .find(|r| r.destination == "192.0.2.0".parse::<Ipv4Addr>().unwrap())
        .expect("multipath route must appear in dump");

    assert!(dumped.multipath.is_some(), "multipath nexthops must survive round-trip");
    let nexthops = dumped.multipath.as_ref().unwrap();
    assert_eq!(nexthops.len(), 2);
    // Verify gateway + ifindex + weight per nexthop.
    ...

    Ok(())
}
```

### 2.4 `NetworkConfig::diff` no-op for multipath round-trip

```rust
#[tokio::test]
async fn multipath_route_in_network_config_is_idempotent() -> Result<()> {
    require_root!();

    // Apply a NetworkConfig declaring a multipath route.
    // Re-diff — must be empty (no spurious drift).
    let cfg = NetworkConfig::new()
        .link(|b| b.dummy("eth0"))
        .link(|b| b.dummy("eth1"))
        .address("eth0", "10.0.0.1/24")
        .address("eth1", "10.0.1.1/24")
        .route(|r| r.dst("192.0.2.0/24").multipath(...));

    cfg.apply(&conn).await?;
    let re = cfg.diff(&conn).await?;
    assert!(re.is_empty(), "multipath re-diff must be empty; got: {re}");

    Ok(())
}
```

This is the bug the lack of parser hides — `NetworkConfig`
consumers think their multipath routes are drifting forever.

## 3. Implementation phases

| Phase | Files | LOC |
|---|---|---|
| 1 — `RtNextHop` zerocopy struct + constants (if missing) | `route.rs` | ~40 |
| 2 — `parse_multipath_v4` + pathological guards | `route.rs` | ~80 |
| 3 — `parse_multipath_v6` (mostly v4 with 16-byte addrs) | `route.rs` | ~50 |
| 4 — Wire into `from_bytes` dispatch | `route.rs` | ~20 |
| 5 — Unit tests (chain walking, guards, byte-shape) | `route.rs` tests | ~150 |
| 6 — Integration tests (round-trip + diff-idempotence) | `tests/integration/route.rs` | ~120 |
| 7 — `compute_diff` parity for multipath field | `config/diff.rs` | ~30 |
| **Total** | | **~490 LOC** |

## 4. Tests

### 4.1 Unit — pathological-input guards (Plan 193 §2.2 applied here)

```rust
#[test]
fn parse_multipath_v4_handles_zero_length_nexthop_without_loop() {
    // rtnh_len = 0 — the infinite-loop scenario from
    // netlink-packet-route #152.
    let buf = vec![0u8; 8];  // length field = 0, junk after
    let start = std::time::Instant::now();
    let result = parse_multipath_v4(&buf);
    assert!(start.elapsed() < std::time::Duration::from_millis(100));
    assert!(result.is_empty(), "malformed chain must abort, not produce phantom nexthops");
}

#[test]
fn parse_multipath_v4_handles_undersized_header() {
    // rtnh_len = 2 (less than RTNH_HDRLEN). Slice access
    // would panic without the defensive check.
    let mut buf = vec![0u8; 8];
    buf[0] = 2; buf[1] = 0;
    let result = parse_multipath_v4(&buf);
    assert!(result.is_empty());
}

#[test]
fn parse_multipath_v4_walks_normal_two_nexthop_chain() {
    // Two well-formed nexthops, both with RTA_GATEWAY.
    let buf = build_two_nexthop_payload(
        Ipv4Addr::new(10, 0, 0, 254), 2,
        Ipv4Addr::new(10, 0, 1, 254), 3,
    );
    let nh = parse_multipath_v4(&buf);
    assert_eq!(nh.len(), 2);
    assert_eq!(nh[0].gateway, Some("10.0.0.254".parse::<IpAddr>().unwrap()));
    assert_eq!(nh[0].ifindex, Some(2));
}

#[test]
fn parse_multipath_v4_truncated_payload_stops_at_boundary() {
    // Two nexthop headers but the second is cut off mid-attribute.
    // Parser must return the first one, not panic.
}
```

### 4.2 Integration — round-trip + diff-idempotence

Per §2.3 + §2.4 above. Root-gated.

## 5. Acceptance criteria

- [ ] `parse_multipath_v4` + `parse_multipath_v6` with the
      three pathological-input guards from Plan 193 §2.2.
- [ ] `Ipv4Route::from_bytes` / `Ipv6Route::from_bytes`
      populate `route.multipath` when `RTA_MULTIPATH` is
      present.
- [ ] `compute_diff` for routes treats `multipath` as a
      stable field (Plan 178's body-bytes-style invariant
      applied to multipath nexthop lists).
- [ ] 4+ unit tests covering the pathological inputs +
      happy path.
- [ ] 2+ integration tests (round-trip + diff-idempotence).
- [ ] CHANGELOG `### Fixed` (multipath routes now survive
      `get_routes()`) + `### Added` (parser).
- [ ] Migration guide entry.

## 6. Effort estimate

| Phase | Effort |
|---|---|
| Code (~490 LOC) | ~3 h |
| Unit tests | ~2 h |
| Integration tests (kernel-required) | ~2 h |
| CHANGELOG + migration guide | ~30 min |
| **Total** | **~7.5 h** |

## 7. Risks

- **Weight encoding nuance**: kernel stores `rtnh_hops` (0-
  based) but users think in 1-based weights. Verify the
  off-by-one is handled both directions; the existing
  `write_multipath_v4` is the reference.
- **Mixed-family multipath**: in theory IPv4 routes can have
  IPv6 gateways via `RTA_VIA`. Out of scope for this plan;
  document as a known limitation.
- **`RTA_NH_ID` references vs inline multipath**: post-5.3
  kernels prefer the nexthop-object reference; multipath
  routes can be either. The parser handles both — multipath
  via `RTA_MULTIPATH` (this plan's path) OR `RTA_NH_ID`
  (already supported on the write side, parser TBD; future
  plan if needed).

## 8. Out-of-scope follow-ups

- **`RTA_NH_ID` parser** for nexthop-object references.
  Separate write+parse work for the modern (kernel 5.3+)
  nexthop API.
- **`RTA_VIA` cross-family gateways**. Document gap.

## 9. Cross-cutting artifacts

| Artifact | Action | Notes |
|---|---|---|
| `CHANGELOG.md ## [Unreleased]` | **add** `### Fixed` entry — multipath routes round-trip through `get_routes()` (previously silently lost their nexthop list) — and `### Added` entry — `parse_multipath_v{4,6}` parsers | Surfaced by Plan 193 §2.2 audit. |
| `docs/migration_guide/0.18.0-to-0.19.0.md` | **append** `### Plan 202` section | Pure additive; no migration. |
| `docs/recipes/multipath-ecmp.md` (**new**) | **create** ~120-line recipe walking the ECMP setup and verifying round-trip behavior via diff | Closes the loop — previously consumers couldn't even verify their multipath state was right. |
| `crates/nlink/examples/route/multipath.rs` (**new**) | **create** ~80-line demo with 2 dummies + multipath route + dump-and-verify | Register in `Cargo.toml`. |
| `CLAUDE.md` | **no change** — the parser inherits the Plan 193 §"Parser robustness" rules established in commit `be52799`. |

End of plan.
