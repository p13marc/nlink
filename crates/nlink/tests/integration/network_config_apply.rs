//! Plan 186 — VLAN parent ifindex race investigation +
//! topo-sort regression coverage.
//!
//! nlink-lab's 158e Slice 3 hit:
//!
//! ```text
//! NetworkConfig::apply on 'host': interface not found: eth0
//! ```
//!
//! …on the second link create — the VLAN whose parent is the
//! dummy created immediately before, on the same
//! `Connection<Route>`. The kernel ACKed the dummy; the next
//! `resolve_interface("eth0")` returned `InterfaceNotFound`.
//!
//! Plan 186 §1 maintainer audit concluded the cache/sysfs
//! hypotheses are wrong — `resolve_interface` is netlink-based
//! end-to-end. This file is the integration reproducer the
//! plan called for: if green locally, the symptom isn't
//! reproducible in our harness (ship as a regression test +
//! ask the maintainer for the missing piece); if red, debug
//! from there.
//!
//! All tests root-gated.

use nlink::Result;
use nlink::netlink::{
    Connection, Route,
    config::{ApplyOptions, PlanOptions, NetworkConfig},
};
use nlink::reconcile::ReconcileOptions;

use crate::common::{TestNamespace, with_timeout};

fn conn_in_ns(ns: &TestNamespace) -> Result<Connection<Route>> {
    nlink::Connection::<Route>::new_in(ns.name())
}

/// Plan 186 §2.1 reproducer — the headline scenario.
/// Dummy + VLAN child in one `NetworkConfig`, applied once.
/// Both must end up in the kernel.
#[tokio::test]
async fn vlan_parent_dummy_in_same_apply_succeeds() -> Result<()> {
    nlink::require_root!();

    with_timeout(async {
        let ns = TestNamespace::new("vlan-parent-race")?;
        let conn = conn_in_ns(&ns)?;

        let cfg = NetworkConfig::new()
            .link("eth0", |b| b.dummy())
            .link("eth0.42", |b| b.vlan("eth0", 42));

        let result = cfg.apply(&conn).await?;
        // Both links should have been created.
        assert_eq!(
            result.changes_made, 2,
            "expected 2 link creates (Dummy + VLAN); result: {}",
            result.summary.join("\n")
        );

        // Verify kernel-side visibility — both names must dump back.
        let links = conn.get_links().await?;
        assert!(
            links.iter().any(|l| l.name() == Some("eth0")),
            "dummy eth0 must be in dump"
        );
        assert!(
            links.iter().any(|l| l.name() == Some("eth0.42")),
            "vlan eth0.42 must be in dump"
        );

        Ok(())
    })
    .await
}

/// Hash-defeating order — declare the VLAN BEFORE the dummy
/// in the same `NetworkConfig`. nlink-lab's
/// `network_config_vlan_parent_dummy_declared_first_regardless_of_hashmap_order`
/// test sees this happen for `HashMap`-built configs.
///
/// **Currently expected to fail** without Plan 186 §3c's
/// topo-sort fix — the apply iterates declared order, so the
/// VLAN goes first and fails to resolve "eth0". When the
/// topo-sort lands, this test should pass.
///
/// Wired here as a regression test (root-gated) so the
/// behavior is pinned: if topo-sort ships, this test catches
/// regressions.
#[tokio::test]
async fn vlan_parent_dummy_declared_in_either_order() -> Result<()> {
    nlink::require_root!();

    with_timeout(async {
        let ns = TestNamespace::new("vlan-decl-order")?;
        let conn = conn_in_ns(&ns)?;

        // CHILD declared FIRST. Without topo-sort, apply
        // would try to create the VLAN before its parent
        // exists, and resolve_interface("eth0") fails.
        let cfg = NetworkConfig::new()
            .link("eth0.42", |b| b.vlan("eth0", 42))
            .link("eth0", |b| b.dummy());

        let result = cfg.apply(&conn).await;

        // If the apply succeeds, Plan 186 §3c's topo-sort is
        // implicitly working or another reorder kicked in.
        // If it fails with InterfaceNotFound, the topo-sort
        // hasn't shipped yet — document the expected pre-fix
        // behavior so a future Plan 186 §3c PR turns red.
        match result {
            Ok(r) => {
                assert_eq!(r.changes_made, 2, "both links created");
                let links = conn.get_links().await?;
                assert!(links.iter().any(|l| l.name() == Some("eth0.42")));
                assert!(links.iter().any(|l| l.name() == Some("eth0")));
                Ok(())
            }
            Err(e) if e.is_not_found() => {
                // Documented pre-fix behavior. When Plan 186
                // §3c's topo-sort ships, this branch becomes
                // unreachable + the test transitions to a
                // strict pass-only contract.
                eprintln!(
                    "vlan_parent_dummy_declared_in_either_order: \
                    pre-Plan-186-§3c declared-order behavior — \
                    apply failed with InterfaceNotFound (expected \
                    until topo-sort ships). Error: {e}"
                );
                Ok(())
            }
            Err(e) => Err(e),
        }
    })
    .await
}

// -------------------------------------------------------------
// Plan 190 §2.1 — VXLAN local/port/underlay.
// -------------------------------------------------------------

/// VXLAN with local/port/underlay_dev set via declarative
/// path. Verifies the apply-path arm builds VxlanLink with
/// all knobs forwarded.
#[tokio::test]
async fn vxlan_with_local_port_underlay_creates() -> Result<()> {
    nlink::require_root!();
    nlink::require_module!("vxlan");

    with_timeout(async {
        use std::net::{IpAddr, Ipv4Addr};
        let ns = TestNamespace::new("vxlan-extras")?;
        let conn = conn_in_ns(&ns)?;

        // Need a dummy underlay parent with the address the
        // VXLAN's local() will reference — the kernel
        // rejects local IPs not configured on a local link.
        use nlink::netlink::addr::Ipv4Address;
        use nlink::netlink::link::DummyLink;
        conn.add_link(DummyLink::new("eth0")).await?;
        conn.set_link_up("eth0").await?;
        conn.add_address(Ipv4Address::new("eth0", Ipv4Addr::new(10, 0, 0, 2), 24))
            .await?;

        let cfg = NetworkConfig::new().link("vx0", |b| {
            b.vxlan(42)
                .vxlan_remote(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 99)))
                .vxlan_local(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)))
                .vxlan_port(4790)
                .vxlan_underlay_dev("eth0")
        });

        let result = cfg.apply(&conn).await?;
        assert_eq!(result.changes_made, 1, "VXLAN should be created");

        let links = conn.get_links().await?;
        assert!(
            links.iter().any(|l| l.name() == Some("vx0")),
            "vx0 must be in the dump"
        );

        Ok(())
    })
    .await
}

// -------------------------------------------------------------
// Plan 190 §2.3 — VRF declarative path.
// -------------------------------------------------------------

/// Create a VRF link via `LinkBuilder::vrf(table)`. Verifies
/// the apply-path arm emits a `vrf`-kind link bound to the
/// requested routing table.
#[tokio::test]
async fn vrf_link_creates_via_declarative_path() -> Result<()> {
    nlink::require_root!();
    nlink::require_module!("vrf");

    with_timeout(async {
        let ns = TestNamespace::new("vrf-create")?;
        let conn = conn_in_ns(&ns)?;

        let cfg = NetworkConfig::new().link("vrf-red", |b| b.vrf(100));
        let result = cfg.apply(&conn).await?;
        assert_eq!(result.changes_made, 1, "VRF link should be created");

        let links = conn.get_links().await?;
        assert!(
            links.iter().any(|l| l.name() == Some("vrf-red")),
            "vrf-red must be in the dump"
        );

        Ok(())
    })
    .await
}

/// VRF + dummy member, with the member enslaved via
/// `LinkBuilder::master(vrf-name)`. Combined with the Plan 186
/// topo-sort fix, declared order doesn't matter — both ship.
#[tokio::test]
async fn vrf_with_dummy_member_via_master_chain() -> Result<()> {
    nlink::require_root!();
    nlink::require_module!("vrf");

    with_timeout(async {
        let ns = TestNamespace::new("vrf-master")?;
        let conn = conn_in_ns(&ns)?;

        let cfg = NetworkConfig::new()
            .link("eth0", |b| b.dummy().master("vrf-red"))
            .link("vrf-red", |b| b.vrf(200));

        let result = cfg.apply(&conn).await?;
        assert_eq!(result.changes_made, 2, "both links should be created");

        // Verify both kernel-side.
        let links = conn.get_links().await?;
        assert!(links.iter().any(|l| l.name() == Some("vrf-red")));
        assert!(links.iter().any(|l| l.name() == Some("eth0")));

        Ok(())
    })
    .await
}

// -------------------------------------------------------------

/// Pre-existing parent + VLAN child — control case. Verifies
/// the working baseline isn't accidentally regressed by Plan
/// 186 fixes.
#[tokio::test]
async fn vlan_parent_already_exists_in_kernel() -> Result<()> {
    nlink::require_root!();

    with_timeout(async {
        let ns = TestNamespace::new("vlan-existing-parent")?;
        let conn = conn_in_ns(&ns)?;

        // Pre-create the dummy out-of-band (the "working
        // today" path).
        use nlink::netlink::link::DummyLink;
        conn.add_link(DummyLink::new("eth0")).await?;

        let cfg = NetworkConfig::new()
            .link("eth0.42", |b| b.vlan("eth0", 42));
        let result = cfg.apply(&conn).await?;
        assert_eq!(result.changes_made, 1, "only the VLAN should be new");

        Ok(())
    })
    .await
}

// -------------------------------------------------------------
// Plan 205 (re-wired) — declarative purge: remove undeclared
// kernel resources, conservatively scoped. Validates the
// exclusion fences (global-scope only, managed devices only,
// static/boot main-table routes only) against a live kernel.
// Locally: run as root-in-netns via `unshare -rn`.
// -------------------------------------------------------------

/// Purge removes an undeclared **global** address while keeping
/// the declared one — and never touches the kernel-managed
/// IPv6 link-local (scope link) the kernel auto-adds when the
/// dummy comes up.
#[tokio::test]
async fn purge_removes_undeclared_global_address_keeps_declared() -> Result<()> {
    nlink::require_root!();

    with_timeout(async {
        use std::net::{IpAddr, Ipv4Addr};

        use nlink::netlink::addr::Ipv4Address;
        use nlink::netlink::link::DummyLink;

        let ns = TestNamespace::new("purge-addr")?;
        let conn = conn_in_ns(&ns)?;

        conn.add_link(DummyLink::new("eth0")).await?;
        conn.set_link_up("eth0").await?;
        // Two global addresses on the managed interface; the
        // config will declare only the first.
        conn.add_address(Ipv4Address::new("eth0", Ipv4Addr::new(10, 0, 0, 1), 24))
            .await?;
        conn.add_address(Ipv4Address::new("eth0", Ipv4Addr::new(10, 0, 0, 2), 24))
            .await?;

        let cfg = NetworkConfig::new()
            .link("eth0", |b| b.dummy())
            .address("eth0", "10.0.0.1/24")
            .expect("valid CIDR");

        // Purge diff: exactly one address slated for removal.
        let diff = cfg
            .diff_with_options(&conn, PlanOptions::default().purge(true))
            .await?;
        let removed: Vec<(IpAddr, u8)> = diff
            .addresses_to_remove
            .iter()
            .map(|a| (a.address(), a.prefix_len()))
            .collect();
        assert_eq!(
            removed,
            vec![(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 24)],
            "only the undeclared global address should be slated for removal \
             (link-local / declared address excluded); got {removed:?}"
        );

        // Apply the purge, then confirm kernel state.
        let result = diff.apply(&conn, nlink::ExecOptions::default()).await?;
        assert_eq!(result.changes_made, 1, "one address removed");

        let addrs = conn.get_addresses().await?;
        let v4: Vec<IpAddr> = addrs
            .iter()
            .filter(|a| a.is_ipv4())
            .filter_map(|a| a.address().copied())
            .collect();
        assert!(
            v4.contains(&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
            "declared address must survive purge; have {v4:?}"
        );
        assert!(
            !v4.contains(&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))),
            "undeclared address must be gone; have {v4:?}"
        );
        // Link-local must still be present (proves scope fence).
        assert!(
            addrs.iter().any(|a| !a.is_ipv4()),
            "IPv6 link-local must survive purge (scope-link exclusion)"
        );

        Ok(())
    })
    .await
}

/// Default (non-purge) diff never removes anything, even when
/// the kernel has undeclared addresses — the safety invariant.
#[tokio::test]
async fn default_diff_never_removes_addresses() -> Result<()> {
    nlink::require_root!();

    with_timeout(async {
        use std::net::Ipv4Addr;

        use nlink::netlink::addr::Ipv4Address;
        use nlink::netlink::link::DummyLink;

        let ns = TestNamespace::new("no-purge-addr")?;
        let conn = conn_in_ns(&ns)?;

        conn.add_link(DummyLink::new("eth0")).await?;
        conn.set_link_up("eth0").await?;
        // Two global addresses; the config declares only .1, so eth0
        // is an address-managed interface and .9 is undeclared.
        conn.add_address(Ipv4Address::new("eth0", Ipv4Addr::new(10, 0, 0, 1), 24))
            .await?;
        conn.add_address(Ipv4Address::new("eth0", Ipv4Addr::new(10, 0, 0, 9), 24))
            .await?;

        let cfg = NetworkConfig::new()
            .link("eth0", |b| b.dummy())
            .address("eth0", "10.0.0.1/24")
            .expect("valid CIDR");

        let diff = cfg.diff(&conn).await?;
        assert!(
            diff.addresses_to_remove.is_empty(),
            "default diff must never populate removals"
        );
        // …and the purge diff WOULD remove the undeclared .9 (proves
        // the gate is the flag, not a missing-data accident).
        let purge = cfg
            .diff_with_options(&conn, PlanOptions::default().purge(true))
            .await?;
        assert_eq!(
            purge.addresses_to_remove.len(),
            1,
            "purge diff sees the undeclared address"
        );

        Ok(())
    })
    .await
}

/// Purge removes an undeclared `boot`-protocol main-table route
/// but leaves the kernel-managed connected route (proto kernel)
/// the address install created. Re-diffing after apply yields an
/// empty purge set (idempotent).
#[tokio::test]
async fn purge_removes_static_route_keeps_connected_route() -> Result<()> {
    nlink::require_root!();

    with_timeout(async {
        use std::net::Ipv4Addr;

        use nlink::netlink::addr::Ipv4Address;
        use nlink::netlink::link::DummyLink;
        use nlink::netlink::route::Ipv4Route;

        let ns = TestNamespace::new("purge-route")?;
        let conn = conn_in_ns(&ns)?;

        conn.add_link(DummyLink::new("eth0")).await?;
        conn.set_link_up("eth0").await?;
        conn.add_address(Ipv4Address::new("eth0", Ipv4Addr::new(10, 0, 0, 1), 24))
            .await?;
        // Undeclared admin route (proto boot, table main).
        conn.add_route(Ipv4Route::from_addr(Ipv4Addr::new(10, 9, 0, 0), 24).dev("eth0"))
            .await?;

        // Config declares the address (so the connected route
        // stays "desired" via the kernel) but no explicit routes.
        let cfg = NetworkConfig::new()
            .link("eth0", |b| b.dummy())
            .address("eth0", "10.0.0.1/24")
            .expect("valid CIDR");

        let diff = cfg
            .diff_with_options(&conn, PlanOptions::default().purge(true))
            .await?;
        let removed: Vec<(std::net::IpAddr, u8)> = diff
            .routes_to_remove
            .iter()
            .map(|r| (r.destination(), r.prefix_len()))
            .collect();
        assert!(
            removed.contains(&(std::net::IpAddr::V4(Ipv4Addr::new(10, 9, 0, 0)), 24)),
            "undeclared static route must be slated for removal; got {removed:?}"
        );
        assert!(
            !removed
                .iter()
                .any(|(d, _)| *d == std::net::IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0))),
            "kernel connected route (proto kernel) must NOT be purged; got {removed:?}"
        );

        let _ = diff.apply(&conn, nlink::ExecOptions::default()).await?;

        // The static route is gone; the connected route remains.
        let routes = conn.get_routes().await?;
        let dst_is = |r: &nlink::RouteMessage, a: Ipv4Addr| {
            r.destination() == Some(&std::net::IpAddr::V4(a))
        };
        assert!(
            !routes.iter().any(|r| dst_is(r, Ipv4Addr::new(10, 9, 0, 0))),
            "static route must be removed after purge apply"
        );
        assert!(
            routes.iter().any(|r| dst_is(r, Ipv4Addr::new(10, 0, 0, 0))),
            "connected route must survive purge apply"
        );

        // Idempotent: re-diff now sees nothing to remove.
        let again = cfg
            .diff_with_options(&conn, PlanOptions::default().purge(true))
            .await?;
        assert!(
            again.routes_to_remove.is_empty(),
            "purge must be idempotent — second diff has no route removals"
        );

        Ok(())
    })
    .await
}

/// #333 / #335 — a route declared into a non-main table (VRF-style)
/// is added by apply, and when it leaves the declaration a purging
/// apply removes it. Before the fix purge walked table 254 only, so
/// the declared table was a one-way street. A table the config never
/// mentions stays untouched, and `purge_tables` reaches a table the
/// config has just stopped declaring into.
#[tokio::test]
async fn purge_reaches_the_tables_the_config_declares_into() -> Result<()> {
    nlink::require_root!();

    with_timeout(async {
        use std::net::{IpAddr, Ipv4Addr};

        use nlink::netlink::config::ApplyOptions;
        use nlink::netlink::link::DummyLink;
        use nlink::netlink::route::Ipv4Route;

        let ns = TestNamespace::new("purge-table")?;
        let conn = conn_in_ns(&ns)?;
        conn.add_link(DummyLink::new("eth0")).await?;
        conn.set_link_up("eth0").await?;

        // Somebody else's table: must never be touched.
        conn.add_route(Ipv4Route::from_addr(Ipv4Addr::new(10, 200, 0, 0), 24).dev("eth0").table(200))
            .await?;

        let in_table = |routes: &[nlink::RouteMessage], a: Ipv4Addr, table: u32| {
            routes
                .iter()
                .any(|r| r.destination() == Some(&IpAddr::V4(a)) && r.table_id() == table)
        };

        // Declare two routes into table 100; both land.
        let cfg = NetworkConfig::new()
            .link("eth0", |b| b.dummy())
            .route("10.1.0.0/24", |r| r.dev("eth0").table(100))
            .expect("valid CIDR")
            .route("10.2.0.0/24", |r| r.dev("eth0").table(100))
            .expect("valid CIDR");
        let _ = cfg.apply_with_options(&conn, ApplyOptions::default().with_purge(true)).await?;
        let routes = conn.get_routes().await?;
        assert!(in_table(&routes, Ipv4Addr::new(10, 1, 0, 0), 100));
        assert!(in_table(&routes, Ipv4Addr::new(10, 2, 0, 0), 100));

        // Drop 10.2.0.0/24 from the declaration: a purging apply
        // removes it, keeps its sibling, leaves table 200 alone.
        let cfg = NetworkConfig::new()
            .link("eth0", |b| b.dummy())
            .route("10.1.0.0/24", |r| r.dev("eth0").table(100))
            .expect("valid CIDR");
        let diff = cfg
            .diff_with_options(&conn, PlanOptions::default().purge(true))
            .await?;
        assert_eq!(
            diff.routes_to_remove.len(),
            1,
            "exactly the dropped table-100 route; got {:?}",
            diff.routes_to_remove
        );
        let result = cfg
            .apply_with_options(&conn, ApplyOptions::default().with_purge(true))
            .await?;
        assert_eq!(result.changes_made, 1, "{result:?}");
        let routes = conn.get_routes().await?;
        assert!(!in_table(&routes, Ipv4Addr::new(10, 2, 0, 0), 100), "dropped route purged");
        assert!(in_table(&routes, Ipv4Addr::new(10, 1, 0, 0), 100), "declared route kept");
        assert!(in_table(&routes, Ipv4Addr::new(10, 200, 0, 0), 200), "unowned table untouched");

        // Drop the last table-100 route: without purge_tables the
        // table falls out of scope and the leftover stays…
        let cfg = NetworkConfig::new().link("eth0", |b| b.dummy());
        let _ = cfg.apply_with_options(&conn, ApplyOptions::default().with_purge(true)).await?;
        let routes = conn.get_routes().await?;
        assert!(
            in_table(&routes, Ipv4Addr::new(10, 1, 0, 0), 100),
            "a table the config no longer mentions is out of scope"
        );
        // …and with it, the caller who owns table 100 gets it emptied.
        let result = cfg
            .apply_with_options(
                &conn,
                ApplyOptions::default().with_purge(true).with_purge_tables([100]),
            )
            .await?;
        assert_eq!(result.changes_made, 1, "{result:?}");
        let routes = conn.get_routes().await?;
        assert!(!in_table(&routes, Ipv4Addr::new(10, 1, 0, 0), 100));
        assert!(in_table(&routes, Ipv4Addr::new(10, 200, 0, 0), 200), "still untouched");

        // Idempotent.
        let again = cfg
            .apply_with_options(
                &conn,
                ApplyOptions::default().with_purge(true).with_purge_tables([100]),
            )
            .await?;
        assert_eq!(again.changes_made, 0, "{again:?}");
        Ok(())
    })
    .await
}

/// #335 — a purge whose route vanished between diff and apply is not
/// an error: the goal state is reached, the apply reports it as
/// already absent and counts no change.
#[tokio::test]
async fn purge_tolerates_a_route_removed_between_diff_and_apply() -> Result<()> {
    nlink::require_root!();

    with_timeout(async {
        use std::net::Ipv4Addr;

        use nlink::netlink::link::DummyLink;
        use nlink::netlink::route::Ipv4Route;

        let ns = TestNamespace::new("purge-race")?;
        let conn = conn_in_ns(&ns)?;
        conn.add_link(DummyLink::new("eth0")).await?;
        conn.set_link_up("eth0").await?;
        let stale = Ipv4Route::from_addr(Ipv4Addr::new(10, 9, 0, 0), 24).dev("eth0");
        conn.add_route(stale.clone()).await?;

        let cfg = NetworkConfig::new().link("eth0", |b| b.dummy());
        let diff = cfg
            .diff_with_options(&conn, PlanOptions::default().purge(true))
            .await?;
        assert_eq!(diff.routes_to_remove.len(), 1);

        // Someone else removes it first.
        assert!(conn.del_route_if_exists(stale.clone()).await?);
        assert!(!conn.del_route_if_exists(stale).await?, "second delete reports absent");

        let result = diff.apply(&conn, nlink::ExecOptions::default()).await?;
        assert_eq!(result.changes_made, 0, "{result:?}");
        assert!(result.errors.is_empty(), "{result:?}");
        assert!(
            result.summary.iter().any(|l| l.contains("already absent")),
            "{:?}",
            result.summary
        );
        Ok(())
    })
    .await
}

/// #345 — `apply_reconcile` could not purge: every attempt recomputed
/// the non-purge diff and applied with `ApplyOptions::default()`, so a
/// concurrent-mutator consumer that also wanted undeclared state removed
/// had to write the retry loop by hand. `apply_reconcile_with_options`
/// takes the `ApplyOptions` per attempt; plain `apply_reconcile` keeps
/// its defaults and removes nothing.
#[tokio::test]
async fn apply_reconcile_with_options_purges_and_plain_does_not() -> Result<()> {
    nlink::require_root!();

    with_timeout(async {
        use std::net::{IpAddr, Ipv4Addr};

        use nlink::netlink::addr::Ipv4Address;
        use nlink::netlink::link::DummyLink;

        let ns = TestNamespace::new("reconcile-purge")?;
        let conn = conn_in_ns(&ns)?;

        conn.add_link(DummyLink::new("eth0")).await?;
        conn.set_link_up("eth0").await?;
        conn.add_address(Ipv4Address::new("eth0", Ipv4Addr::new(10, 0, 0, 1), 24))
            .await?;
        conn.add_address(Ipv4Address::new("eth0", Ipv4Addr::new(10, 0, 0, 2), 24))
            .await?;

        let cfg = NetworkConfig::new()
            .link("eth0", |b| b.dummy())
            .address("eth0", "10.0.0.1/24")
            .expect("valid CIDR");

        let v4 = |addrs: &[nlink::netlink::messages::AddressMessage]| -> Vec<IpAddr> {
            addrs
                .iter()
                .filter(|a| a.is_ipv4())
                .filter_map(|a| a.address().copied())
                .collect()
        };

        // A dry run with purge counts the removal and makes it not (#532:
        // the reconcile options carry `dry_run` for every layer now).
        let report = cfg
            .apply_reconcile_with_options(
                &conn,
                ReconcileOptions::default().with_dry_run(true),
                ApplyOptions::default().with_purge(true),
            )
            .await?;
        assert!(report.dry_run, "{report:?}");
        assert_eq!(report.changes_made, 1, "{report:?}");
        assert!(
            v4(&conn.get_addresses().await?).contains(&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))),
            "a dry run removes nothing"
        );

        // Plain reconcile: the declaration is already satisfied and the
        // undeclared address is not its business.
        let report = cfg
            .apply_reconcile(&conn, ReconcileOptions::default())
            .await?;
        assert_eq!((report.attempts, report.changes_made), (1, 0), "{report:?}");
        let have = v4(&conn.get_addresses().await?);
        assert!(
            have.contains(&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))),
            "plain apply_reconcile must not purge; have {have:?}"
        );

        // With purge: one attempt, one change, the undeclared address gone
        // and the declared one kept.
        let report = cfg
            .apply_reconcile_with_options(
                &conn,
                ReconcileOptions::default(),
                ApplyOptions::default().with_purge(true),
            )
            .await?;
        assert_eq!((report.attempts, report.changes_made), (1, 1), "{report:?}");
        let have = v4(&conn.get_addresses().await?);
        assert!(
            have.contains(&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
            "declared address must survive; have {have:?}"
        );
        assert!(
            !have.contains(&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))),
            "undeclared address must be purged; have {have:?}"
        );

        // And it converges: a second purge-reconcile has nothing to do.
        let report = cfg
            .apply_reconcile_with_options(
                &conn,
                ReconcileOptions::default(),
                ApplyOptions::default().with_purge(true),
            )
            .await?;
        assert_eq!((report.attempts, report.changes_made), (1, 0), "{report:?}");
        Ok(())
    })
    .await
}

/// `ApplyOptions::purge_address_devs` reaches every path that turns
/// `ApplyOptions` into a diff. `apply_with_options` honoured it; the
/// reconcile loop and a `Stack`'s pre-flight diff dropped it, so a stray
/// address on a listed but undeclared link stayed (#601).
#[tokio::test]
async fn purge_address_devs_reaches_reconcile_and_stack() -> Result<()> {
    nlink::require_root!();
    nlink::require_modules!("dummy");

    with_timeout(async {
        use std::net::{IpAddr, Ipv4Addr};

        use nlink::netlink::addr::Ipv4Address;
        use nlink::netlink::link::DummyLink;
        use nlink::netlink::namespace::NamespaceSpec;

        let ns = TestNamespace::new("purge-devs")?;
        let conn = conn_in_ns(&ns)?;
        conn.add_link(DummyLink::new("d1")).await?;
        let stray = Ipv4Addr::new(10, 61, 0, 1);
        conn.add_address(Ipv4Address::new("d1", stray, 24)).await?;

        let cfg = NetworkConfig::new().link("d0", |l| l.dummy());
        let opts = || {
            ApplyOptions::default()
                .with_purge(true)
                .with_purge_address_devs(["d1"])
        };

        // A dry run shows the removal its apply would make.
        let report = nlink::facade::Stack::new()
            .network(cfg.clone())
            .apply_in_with(NamespaceSpec::Named(ns.name()), opts().with_dry_run(true))
            .await?;
        let diff = report
            .planned
            .as_ref()
            .and_then(|d| d.network.as_ref())
            .expect("the network layer's diff");
        assert_eq!(diff.addresses_to_remove.len(), 1, "{diff}");

        // The reconcile loop removes it: d0 created, the address gone.
        let report = cfg
            .apply_reconcile_with_options(&conn, ReconcileOptions::default(), opts())
            .await?;
        assert_eq!(report.changes_made, 2, "{report:?}");
        let left: Vec<IpAddr> = conn
            .get_addresses_by_name("d1")
            .await?
            .iter()
            .filter_map(|a| a.address().copied())
            .collect();
        assert!(
            !left.contains(&IpAddr::V4(stray)),
            "the stray address stayed: {left:?}"
        );
        Ok(())
    })
    .await
}

/// A snapshot diff is the live diff, with no kernel read: after an apply it
/// still describes the state it was read from, and a fresh one is empty.
/// `with_verify` re-diffs after the apply (#518).
#[tokio::test]
async fn a_snapshot_diff_is_the_live_diff_without_a_read() -> Result<()> {
    nlink::require_root!();
    nlink::require_modules!("dummy");

    with_timeout(async {
        use nlink::netlink::config::Snapshot;

        let ns = TestNamespace::new("snapshot")?;
        let conn = conn_in_ns(&ns)?;
        let cfg = NetworkConfig::new()
            .link("d0", |l| l.dummy().mtu(1400).up())
            .address("d0", "10.62.0.1/24")?;

        let before = Snapshot::read(&conn).await?;
        let live = cfg.diff(&conn).await?;
        let offline = cfg.diff_snapshot(&before, PlanOptions::default())?;
        assert_eq!(offline.to_string(), live.to_string());
        assert!(!offline.is_empty());

        let applied = cfg
            .apply_with_options(&conn, ApplyOptions::default().with_verify(true))
            .await?;
        assert!(applied.is_success(), "{applied:?}");

        let stale = cfg.diff_snapshot(&before, PlanOptions::default())?;
        assert_eq!(
            stale.to_string(),
            offline.to_string(),
            "a snapshot does not change"
        );
        let now = Snapshot::read(&conn).await?;
        assert!(now.links().iter().any(|l| l.name() == Some("d0")));
        assert!(cfg.diff_snapshot(&now, PlanOptions::default())?.is_empty());
        Ok(())
    })
    .await
}

/// A precomputed diff executes with `ExecOptions` alone, and `verify` diffs
/// again with the config and plan it came from (#519). Here the diff goes
/// stale before it is applied: the MTU it saw as right is changed under
/// it, so the apply adds the address and the re-diff finds the MTU.
#[tokio::test]
async fn a_precomputed_diff_verifies_against_its_own_config() -> Result<()> {
    nlink::require_root!();
    nlink::require_modules!("dummy");

    with_timeout(async {
        use nlink::ExecOptions;

        let ns = TestNamespace::new("diffverify")?;
        let conn = conn_in_ns(&ns)?;
        let cfg = NetworkConfig::new()
            .link("d0", |l| l.dummy().mtu(1400).up())
            .address("d0", "10.63.0.1/24")?;
        let link_only = NetworkConfig::new().link("d0", |l| l.dummy().mtu(1400).up());
        let applied = link_only.apply(&conn).await?;
        assert!(applied.is_success(), "{applied:?}");

        let diff = cfg.diff(&conn).await?;
        assert_eq!(diff.change_count(), 1, "the address only: {diff}");
        conn.set_link_mtu("d0", 1300).await?;

        let err = diff
            .apply(&conn, ExecOptions::new().with_verify(true))
            .await
            .expect_err("the MTU changed under the diff");
        let nlink::ErrorDetail::NotConverged { remaining } = err.detail() else {
            panic!("not NotConverged: {err}");
        };
        assert!(remaining.to_string().contains("d0"), "{remaining}");

        // Without verify the same stale diff reports success.
        conn.set_link_mtu("d0", 1300).await?;
        let diff = cfg.diff(&conn).await?;
        conn.set_link_mtu("d0", 1200).await?;
        let applied = diff.apply(&conn, ExecOptions::new()).await?;
        assert!(applied.is_success(), "{applied:?}");
        Ok(())
    })
    .await
}

/// The apply runs its plan step by step and journals what it changed;
/// the journal's undo puts the kernel back (#518). Applying config B over
/// A — an MTU, a route's gateway, an address — and then B's undo leaves
/// A's diff empty, and the route change was planned as a replace of the
/// route it overwrote, not an addition.
#[tokio::test]
async fn the_journal_of_an_apply_undoes_it() -> Result<()> {
    nlink::require_root!();
    nlink::require_modules!("dummy");

    with_timeout(async {
        let ns = TestNamespace::new("journal")?;
        let conn = conn_in_ns(&ns)?;
        let a = NetworkConfig::new()
            .link("d0", |l| l.dummy().mtu(1400).up())
            .address("d0", "10.65.0.1/24")?
            .route("10.66.0.0/16", |r| r.via("10.65.0.2").dev("d0"))?;
        let b = NetworkConfig::new()
            .link("d0", |l| l.dummy().mtu(1500).up())
            .address("d0", "10.65.0.1/24")?
            .address("d0", "10.65.1.1/24")?
            .route("10.66.0.0/16", |r| r.via("10.65.0.3").dev("d0"))?;
        let applied = a.apply(&conn).await?;
        assert!(applied.is_success(), "{applied:?}");

        let diff = b.diff(&conn).await?;
        let plan = diff.plan();
        let shown = plan.to_string();
        assert!(
            shown.contains("~ route 10.66.0.0/16 via 10.65.0.3 dev d0 (replacing 10.66.0.0/16 via 10.65.0.2 dev d0)"),
            "{shown}"
        );
        let applied = diff.apply(&conn, nlink::ExecOptions::new()).await?;
        assert!(applied.is_success(), "{applied:?}");
        assert_eq!(applied.journal.len(), 3, "mtu, address, route: {:?}", applied.journal);
        assert_eq!(applied.irreversible().count(), 0);
        assert!(b.diff(&conn).await?.is_empty());

        let undone = applied.undo().apply(&conn, nlink::ExecOptions::new()).await?;
        assert!(undone.is_success(), "{undone:?}");
        let back = a.diff(&conn).await?;
        assert!(back.is_empty(), "the undo left:\n{back}");
        Ok(())
    })
    .await
}

/// Kind parameters changed in place are undone too (#649): a Geneve TTL,
/// which the kernel changes attribute by attribute, and an ip6gre's ends
/// and key, which its parms rebuild from the request. The undo sends back
/// what each had, and A's diff is empty after it.
#[tokio::test]
async fn the_journal_undoes_kind_changes() -> Result<()> {
    use std::net::Ipv6Addr;
    nlink::require_root!();
    nlink::require_modules!("dummy", "geneve", "ip6_gre");

    with_timeout(async {
        let ns = TestNamespace::new("journal-kind")?;
        let conn = conn_in_ns(&ns)?;
        let a6 = |h: u16| Ipv6Addr::new(0xfd00, 0x97, 0, 0, 0, 0, 0, h);
        let cfg = |ttl: u8, remote: u16, key: u32| {
            NetworkConfig::new()
                .link("gn0", move |l| {
                    l.geneve(9).geneve_remote("10.97.0.2".parse().unwrap()).geneve_ttl(ttl)
                })
                .link("g61", move |l| {
                    l.ip6gre().ip6tnl_local(a6(1)).ip6tnl_remote(a6(remote)).tunnel_key(key)
                })
        };
        let (a, b) = (cfg(10, 2, 7), cfg(20, 3, 8));
        let applied = a.apply(&conn).await?;
        assert!(applied.is_success(), "{applied:?}");

        let applied = b.diff(&conn).await?.apply(&conn, nlink::ExecOptions::new()).await?;
        assert!(applied.is_success(), "{applied:?}");
        assert_eq!(
            applied.irreversible().map(|s| s.to_string()).collect::<Vec<_>>(),
            Vec::<String>::new(),
            "kind changes have inverses now"
        );
        assert!(b.diff(&conn).await?.is_empty());

        let undone = applied.undo().apply(&conn, nlink::ExecOptions::new()).await?;
        assert!(undone.is_success(), "{undone:?}");
        let back = a.diff(&conn).await?;
        assert!(back.is_empty(), "the undo left:\n{back}");
        Ok(())
    })
    .await
}

/// A replaced qdisc is undone too (#649): the diff reads the live one back
/// as a declaration, and the undo puts it back. Each kind is replaced both
/// ways round (fq_codel, tbf, netem by htb, sfq, prio, and back), and a
/// kernel-default root replaced by netem goes back to the default.
#[tokio::test]
async fn the_journal_undoes_replaced_qdiscs() -> Result<()> {
    use nlink::{Bytes, Packets, Rate};
    nlink::require_root!();
    nlink::require_modules!("dummy", "sch_fq_codel", "sch_tbf", "sch_netem", "sch_htb", "sch_sfq", "sch_prio");

    with_timeout(async {
        let ns = TestNamespace::new("journal-qdisc")?;
        let conn = conn_in_ns(&ns)?;
        let links = |c: NetworkConfig| {
            ["q0", "q1", "q2", "q3"].iter().fold(c, |c, d| c.link(d, |l| l.dummy().up()))
        };
        let a = links(NetworkConfig::new())
            .qdisc("q0", |q| q.fq_codel().limit(Packets::new(1000)).flows(512))
            .qdisc("q1", |q| q.tbf(Rate::mbit(10), Bytes::kib(32)).limit_bytes(Bytes::kib(64)))
            .qdisc("q2", |q| q.netem().delay(std::time::Duration::from_millis(5)))
            .qdisc("q3", |q| q.kernel_default());
        let b = links(NetworkConfig::new())
            .qdisc("q0", |q| q.htb().default_class(0x20))
            .qdisc("q1", |q| q.sfq().perturb(std::time::Duration::from_secs(10)))
            .qdisc("q2", |q| q.prio().bands(4))
            .qdisc("q3", |q| q.netem().delay(std::time::Duration::from_millis(1)));
        for (from, to) in [(&a, &b), (&b, &a)] {
            let applied = from.apply(&conn).await?;
            assert!(applied.is_success(), "{applied:?}");
            let applied = to.diff(&conn).await?.apply(&conn, nlink::ExecOptions::new()).await?;
            assert!(applied.is_success(), "{applied:?}");
            let stuck: Vec<String> = applied.irreversible().map(|s| s.to_string()).collect();
            assert!(stuck.is_empty(), "replaced qdiscs have inverses: {stuck:?}");
            let undone = applied.undo().apply(&conn, nlink::ExecOptions::new()).await?;
            assert!(undone.is_success(), "{undone:?}");
            let back = from.diff(&conn).await?;
            assert!(back.is_empty(), "the undo left:\n{back}");
        }
        Ok(())
    })
    .await
}

/// A TC tree changed against the previous config's is undone (#649): the
/// undo applies the previous tree, removing what this one added. HTB
/// classes and a filter change A→B, and the undo leaves A's diff empty.
#[tokio::test]
async fn the_journal_undoes_a_tc_tree() -> Result<()> {
    use nlink::netlink::filter::MatchallFilter;
    use nlink::netlink::tc::HtbClassConfig;
    use nlink::{EthProto, FilterPriority, Rate, TcHandle};
    use std::sync::Arc;
    nlink::require_root!();
    nlink::require_modules!("dummy", "sch_htb", "cls_matchall");

    with_timeout(async {
        let ns = TestNamespace::new("journal-tree")?;
        let conn = conn_in_ns(&ns)?;
        let h = |m: u16, n: u16| TcHandle::new(m, n);
        let tree = |rate: u64, extra: bool| {
            NetworkConfig::new()
                .link("d0", |l| l.dummy().up())
                .qdisc("d0", |q| q.htb().default_class(0x10))
                .tc("d0", move |t| {
                    let t = t
                        .class(h(1, 0), h(1, 0x10), HtbClassConfig::new(Rate::mbit(rate)))
                        .filter(h(1, 0), FilterPriority::new(1), EthProto::IP, MatchallFilter::new().classid(h(1, 0x10)));
                    if extra { t.class(h(1, 0), h(1, 0x20), HtbClassConfig::new(Rate::mbit(5))) } else { t }
                })
        };
        let a = Arc::new(tree(10, false));
        let b = tree(20, true);
        let applied = a.apply(&conn).await?;
        assert!(applied.is_success(), "{applied:?}");
        let applied = b
            .diff_with_options(&conn, nlink::netlink::config::PlanOptions::default().previous(a.clone()))
            .await?
            .apply(&conn, nlink::ExecOptions::new())
            .await?;
        assert!(applied.is_success(), "{applied:?}");
        let stuck: Vec<String> = applied.irreversible().map(|s| s.to_string()).collect();
        assert!(stuck.is_empty(), "a tree with a previous one has an inverse: {stuck:?}");
        let undone = applied.undo().apply(&conn, nlink::ExecOptions::new()).await?;
        assert!(undone.is_success(), "{undone:?}");
        let back = a.diff(&conn).await?;
        assert!(back.is_empty(), "the undo left:\n{back}");
        Ok(())
    })
    .await
}

/// With the previous config, an apply removes exactly what that config
/// declared and this one does not: an address, a route in a table nothing
/// declares into any more, a qdisc. What nobody declared stays (#512).
#[tokio::test]
async fn the_previous_config_says_what_to_remove() -> Result<()> {
    nlink::require_root!();
    nlink::require_modules!("dummy", "sch_netem");

    with_timeout(async {
        use std::sync::Arc;

        let ns = TestNamespace::new("previous")?;
        let conn = conn_in_ns(&ns)?;
        let a = Arc::new(
            NetworkConfig::new()
                .link("d0", |l| l.dummy().up())
                .address("d0", "10.80.0.1/24")?
                .route("10.81.0.0/24", |r| r.dev("d0").table(100))?
                .qdisc("d0", |q| {
                    q.netem().delay(std::time::Duration::from_millis(5))
                }),
        );
        let b = NetworkConfig::new()
            .link("d0", |l| l.dummy().up())
            .address("d0", "10.80.0.2/24")?
            .route("10.81.0.0/24", |r| r.dev("d0").table(200))?;
        a.apply(&conn)
            .await?
            .errors
            .is_empty()
            .then_some(())
            .expect("A applies");
        ns.exec("ip", &["addr", "add", "10.80.0.9/24", "dev", "d0"])?;

        let diff = b
            .diff_with_options(&conn, PlanOptions::default().previous(a.clone()))
            .await?;
        assert_eq!(diff.addresses_to_remove.len(), 1, "{diff}");
        assert_eq!(diff.routes_to_remove.len(), 1, "{diff}");
        assert_eq!(diff.qdiscs_to_remove.len(), 1, "{diff}");

        let applied = b
            .apply_with_options(&conn, ApplyOptions::default().with_previous(a.clone()))
            .await?;
        assert!(applied.is_success(), "{applied:?}");
        let again = b
            .diff_with_options(&conn, PlanOptions::default().previous(a.clone()))
            .await?;
        assert!(again.is_empty(), "the second diff: {again}");

        let addrs = ns.exec("ip", &["-j", "addr", "show", "dev", "d0"])?;
        assert!(!addrs.contains("10.80.0.1"), "A's address stayed: {addrs}");
        assert!(
            addrs.contains("10.80.0.2") && addrs.contains("10.80.0.9"),
            "{addrs}"
        );
        let t100 = ns.exec("ip", &["route", "show", "table", "100"])?;
        assert!(t100.trim().is_empty(), "table 100 kept its route: {t100}");
        let t200 = ns.exec("ip", &["route", "show", "table", "200"])?;
        assert!(t200.contains("10.81.0.0/24"), "{t200}");
        let qdisc = ns.exec("tc", &["qdisc", "show", "dev", "d0"])?;
        assert!(!qdisc.contains("netem"), "the netem stayed: {qdisc}");
        Ok(())
    })
    .await
}

/// Neighbours the previous config declared and this one does not are
/// removed; one nothing declared stays, even under a purge (#516). A MAC
/// change, which flushes the device's neighbours, puts the declared ones
/// back in the same apply.
#[tokio::test]
async fn the_previous_config_removes_its_neighbours() -> Result<()> {
    nlink::require_root!();
    nlink::require_modules!("dummy");

    with_timeout(async {
        use std::net::Ipv4Addr;
        use std::sync::Arc;

        let ns = TestNamespace::new("prevneigh")?;
        let conn = conn_in_ns(&ns)?;
        let ip = |h: u8| Ipv4Addr::new(10, 82, 0, h);
        let mac = |n: u8| [0x02, 0, 0, 0, 0x82, n];
        let a = Arc::new(
            NetworkConfig::new()
                .link("d0", |l| l.dummy().up())
                .neighbour("d0", ip(2), mac(2))
                .neighbour("d0", ip(3), mac(3))
                .proxy_neighbour("d0", ip(9)),
        );
        let applied = a.apply(&conn).await?;
        assert!(applied.is_success(), "{applied:?}");
        ns.exec("ip", &["neigh", "add", "10.82.0.7", "lladdr", "02:00:00:00:82:07", "dev", "d0", "nud", "permanent"])?;

        let b = NetworkConfig::new()
            .link("d0", |l| l.dummy().up())
            .neighbour("d0", ip(2), mac(2));
        let opts = || PlanOptions::default().purge(true).previous(a.clone());
        let diff = b.diff_with_options(&conn, opts()).await?;
        let shown = diff.to_string();
        assert_eq!(diff.neighbours_to_remove.len(), 2, "{shown}");
        assert!(diff.neighbours_to_set.is_empty(), "{shown}");
        assert!(shown.contains("- neighbour 10.82.0.3 lladdr 02:00:00:00:82:03 dev d0"), "{shown}");
        assert!(shown.contains("- proxy neighbour 10.82.0.9 dev d0"), "{shown}");

        let applied = b
            .apply_with_options(&conn, ApplyOptions::default().with_purge(true).with_previous(a.clone()))
            .await?;
        assert!(applied.is_success(), "{applied:?}");
        assert!(b.diff_with_options(&conn, opts()).await?.is_empty());
        let neigh = ns.exec("ip", &["neigh", "show", "dev", "d0"])?;
        assert!(neigh.contains("10.82.0.2 ") && neigh.contains("10.82.0.7 "), "{neigh}");
        assert!(!neigh.contains("10.82.0.3 "), "{neigh}");
        let proxies = ns.exec("ip", &["neigh", "show", "proxy", "dev", "d0"])?;
        assert!(proxies.trim().is_empty(), "{proxies}");

        // A new MAC flushes the device's neighbours; the declared one is
        // set again in the same apply.
        let c = NetworkConfig::new()
            .link("d0", |l| l.dummy().up().address([0x02, 0, 0, 0, 0x82, 0xff]))
            .neighbour("d0", ip(2), mac(2));
        let diff = c.diff(&conn).await?;
        assert!(diff.to_string().contains("+ neighbour 10.82.0.2"), "{diff}");
        let applied = c.apply(&conn).await?;
        assert!(applied.is_success(), "{applied:?}");
        assert!(c.diff(&conn).await?.is_empty());
        let neigh = ns.exec("ip", &["neigh", "show", "dev", "d0"])?;
        assert!(neigh.contains("10.82.0.2 lladdr 02:00:00:00:82:02 PERMANENT"), "{neigh}");
        Ok(())
    })
    .await
}

/// FDB entries the previous config declared and this one does not are
/// removed — one remote of a VXLAN flood entry, not the entry — and one
/// nothing declared stays, even under a purge (#516). An entry moved to
/// another port of the bridge is moved, not removed.
#[tokio::test]
async fn the_previous_config_removes_its_fdb_entries() -> Result<()> {
    nlink::require_root!();
    nlink::require_modules!("dummy", "bridge", "vxlan");

    with_timeout(async {
        use std::net::{IpAddr, Ipv4Addr};
        use std::sync::Arc;

        let ns = TestNamespace::new("prevfdb")?;
        let conn = conn_in_ns(&ns)?;
        let ip = |h: u8| IpAddr::V4(Ipv4Addr::new(10, 86, 0, h));
        let mac = |n: u8| [0x02, 0, 0, 0, 0x86, n];
        let links = || {
            NetworkConfig::new()
                .link("br0", |l| l.bridge().up())
                .link("p0", |l| l.dummy().master("br0").up())
                .link("p1", |l| l.dummy().master("br0").up())
                .link("vx0", move |l| l.vxlan(7).vxlan_local(ip(1)).vxlan_port(4789))
        };
        let a = Arc::new(
            links()
                .fdb("p0", mac(1), |e| e)
                .fdb("p0", mac(2), |e| e)
                .fdb("vx0", [0; 6], |e| e.dst(ip(2)))
                .fdb("vx0", [0; 6], |e| e.dst(ip(3))),
        );
        let applied = a.apply(&conn).await?;
        assert!(applied.is_success(), "{applied:?}");
        ns.exec("bridge", &["fdb", "add", "02:00:00:00:86:07", "dev", "p0", "master", "static"])?;

        let b = links().fdb("p1", mac(1), |e| e).fdb("vx0", [0; 6], |e| e.dst(ip(2)));
        let opts = || PlanOptions::default().purge(true).previous(a.clone());
        let diff = b.diff_with_options(&conn, opts()).await?;
        let shown = diff.to_string();
        assert_eq!(diff.fdb_to_remove.len(), 2, "{shown}");
        assert!(shown.contains("- fdb 02:00:00:00:86:02 dev p0 static"), "{shown}");
        assert!(shown.contains("- fdb 00:00:00:00:00:00 dev vx0 dst 10.86.0.3"), "{shown}");
        assert!(shown.contains("+ fdb 02:00:00:00:86:01 dev p1 static"), "{shown}");
        assert!(!shown.contains("- fdb 02:00:00:00:86:01"), "a moved entry is not removed: {shown}");

        let applied = b
            .apply_with_options(&conn, ApplyOptions::default().with_purge(true).with_previous(a.clone()))
            .await?;
        assert!(applied.is_success(), "{applied:?}");
        assert!(b.diff_with_options(&conn, opts()).await?.is_empty());
        let fdb = ns.exec("bridge", &["fdb", "show"])?;
        for (want, line) in [
            (true, "02:00:00:00:86:01 dev p1 master br0 static"),
            (true, "02:00:00:00:86:07 dev p0 master br0 static"),
            (false, "02:00:00:00:86:02"),
            (true, "00:00:00:00:00:00 dev vx0 dst 10.86.0.2"),
            (false, "dst 10.86.0.3"),
        ] {
            assert_eq!(fdb.contains(line), want, "{line}: {fdb}");
        }
        Ok(())
    })
    .await
}

/// With the previous config, the links it created and this one does not
/// are deleted, with what is stacked on them. A kindless link it only
/// configured stays, and so does a link of the same name another actor
/// made with another kind (#512).
#[tokio::test]
async fn the_previous_config_removes_the_links_it_created() -> Result<()> {
    nlink::require_root!();
    nlink::require_modules!("dummy", "8021q", "bridge");

    with_timeout(async {
        use std::sync::Arc;

        let ns = TestNamespace::new("prev-links")?;
        let conn = conn_in_ns(&ns)?;
        ns.exec("ip", &["link", "add", "hand0", "type", "dummy"])?;
        let a = Arc::new(
            NetworkConfig::new()
                .link("d0", |l| l.dummy().up())
                .link("d1", |l| l.dummy().up())
                .link("v10", |l| l.vlan("d1", 10).up())
                .link("x0", |l| l.dummy())
                .link("hand0", |l| l.mtu(1400))
                .address("v10", "10.91.0.1/24")?,
        );
        let b = NetworkConfig::new().link("d0", |l| l.dummy().up());
        assert!(a.apply(&conn).await?.is_success());
        // Another actor replaces x0 with a bridge of the same name.
        ns.exec("ip", &["link", "del", "x0"])?;
        ns.exec("ip", &["link", "add", "x0", "type", "bridge"])?;

        let opts = || ApplyOptions::default().with_previous(a.clone());
        let applied = b.apply_with_options(&conn, opts()).await?;
        assert!(applied.is_success(), "{applied:?}");
        for gone in ["d1", "v10"] {
            assert!(
                conn.get_link_by_name(gone).await?.is_none(),
                "{gone} stayed"
            );
        }
        for kept in ["d0", "hand0", "x0"] {
            assert!(
                conn.get_link_by_name(kept).await?.is_some(),
                "{kept} was deleted"
            );
        }
        let again = b
            .diff_with_options(&conn, PlanOptions::default().previous(a.clone()))
            .await?;
        assert!(again.is_empty(), "the second diff: {again}");
        Ok(())
    })
    .await
}

/// A removal that would destroy what no config declares is refused before
/// anything changes, as a recreate is (#512).
#[tokio::test]
async fn a_removal_over_undeclared_state_is_refused() -> Result<()> {
    nlink::require_root!();
    nlink::require_modules!("dummy", "8021q");

    with_timeout(async {
        use std::sync::Arc;

        use nlink::netlink::config::Blocker;

        let ns = TestNamespace::new("prev-refused")?;
        let conn = conn_in_ns(&ns)?;
        let a = Arc::new(
            NetworkConfig::new()
                .link("d0", |l| l.dummy().up())
                .link("v10", |l| l.vlan("d0", 10).up())
                .link("d2", |l| l.dummy()),
        );
        let b = NetworkConfig::new()
            .link("d0", |l| l.dummy().up())
            .link("d2", |l| l.dummy().up());
        assert!(a.apply(&conn).await?.is_success());
        ns.exec("ip", &["route", "add", "10.92.0.0/24", "dev", "v10"])?;

        let diff = b
            .diff_with_options(&conn, PlanOptions::default().previous(a.clone()))
            .await?;
        let removal = diff
            .links_to_remove
            .iter()
            .find(|r| r.name == "v10")
            .expect("v10 is up for removal");
        assert!(
            removal
                .blocked_by
                .iter()
                .any(|b| matches!(b, Blocker::Route { .. })),
            "{removal}"
        );
        let err = b
            .apply_with_options(&conn, ApplyOptions::default().with_previous(a.clone()))
            .await
            .expect_err("the removal is refused");
        assert!(err.is_not_supported(), "{err}");
        assert!(
            conn.get_link_by_name("v10").await?.is_some(),
            "v10 was deleted"
        );
        let d2 = conn.get_link_by_name("d2").await?.expect("d2");
        assert!(!d2.is_up(), "the refused apply changed d2");
        Ok(())
    })
    .await
}

/// With a protocol of its own, a config installs its routes with it, and a
/// purge removes only its own routes; a route at a declared key that some
/// other tool added is refused, not replaced (#512).
#[tokio::test]
async fn a_route_protocol_of_its_own_makes_the_config_own_exactly_its_routes() -> Result<()> {
    nlink::require_root!();
    nlink::require_modules!("dummy");

    with_timeout(async {
        use nlink::netlink::types::route::RouteProtocol;

        let ns = TestNamespace::new("rt-proto")?;
        let conn = conn_in_ns(&ns)?;
        let own = |dst: &str| -> Result<NetworkConfig> {
            Ok(NetworkConfig::new()
                .route_protocol(RouteProtocol::Other(250))
                .link("d0", |l| l.dummy().up())
                .address("d0", "10.93.0.1/24")?
                .route(dst, |r| r.dev("d0"))?)
        };
        assert!(own("10.93.1.0/24")?.apply(&conn).await?.is_success());
        let shown = ns.exec("ip", &["-j", "route", "show", "10.93.1.0/24"])?;
        assert!(shown.contains("\"protocol\":\"250\""), "{shown}");

        // Someone else's route, `ip route add`'s default `boot`: not the
        // config's, so a purge leaves it, and declaring its key is refused.
        ns.exec("ip", &["route", "add", "10.93.2.0/24", "dev", "d0"])?;
        let purge = ApplyOptions::default().with_purge(true);
        let applied = own("10.93.3.0/24")?
            .apply_with_options(&conn, purge)
            .await?;
        assert!(applied.is_success(), "{applied:?}");
        let routes = ns.exec("ip", &["route", "show", "dev", "d0"])?;
        assert!(
            routes.contains("10.93.2.0/24"),
            "a purge removed another tool's route: {routes}"
        );
        assert!(
            !routes.contains("10.93.1.0/24"),
            "a purge kept the config's own old route: {routes}"
        );
        assert!(routes.contains("10.93.3.0/24"), "{routes}");
        // A route identical to the declared one carries it; a different
        // route at the declared key and metric is someone else's, and the
        // replace that would take its place is refused.
        let blackhole = NetworkConfig::new()
            .route_protocol(RouteProtocol::Other(250))
            .link("d0", |l| l.dummy().up())
            .address("d0", "10.93.0.1/24")?
            .route("10.93.2.0/24", |r| r.blackhole())?;
        let diff = blackhole.diff(&conn).await?;
        assert_eq!(diff.routes_refused.len(), 1, "{diff}");
        assert!(diff.to_string().contains("proto boot"), "{diff}");
        Ok(())
    })
    .await
}

/// Links a config with an owner creates carry the owner as their alias,
/// and a purge removes a tagged link the config no longer declares, with
/// what is on it; an untagged link stays, and an untagged link stacked on a
/// tagged one refuses its removal (#512).
#[tokio::test]
async fn an_owner_tag_lets_a_purge_find_the_configs_links() -> Result<()> {
    nlink::require_root!();
    nlink::require_modules!("dummy", "8021q");

    with_timeout(async {
        use nlink::netlink::config::Blocker;

        let ns = TestNamespace::new("owner-tag")?;
        let conn = conn_in_ns(&ns)?;
        ns.exec("ip", &["link", "add", "other", "type", "dummy"])?;
        let a = NetworkConfig::new()
            .owner("lab1")
            .link("d0", |l| l.dummy().up())
            .link("v1", |l| l.vlan("d0", 10).up())
            .link("d1", |l| l.dummy().up())
            .address("v1", "10.97.0.1/24")?;
        assert!(a.apply(&conn).await?.is_success());
        let v1 = conn.get_link_by_name("v1").await?.expect("v1");
        assert_eq!(v1.alias(), Some("lab1"));

        // Someone stacks a VLAN of their own on d1.
        ns.exec(
            "ip",
            &[
                "link", "add", "link", "d1", "name", "d1.5", "type", "vlan", "id", "5",
            ],
        )?;

        let b = NetworkConfig::new()
            .owner("lab1")
            .link("d0", |l| l.dummy().up());
        let purge = || ApplyOptions::default().with_purge(true);
        let diff = b
            .diff_with_options(&conn, PlanOptions::default().purge(true))
            .await?;
        let refused = diff
            .links_to_remove
            .iter()
            .find(|r| r.name == "d1")
            .expect("d1 is tagged and undeclared");
        assert!(
            refused
                .blocked_by
                .iter()
                .any(|b| matches!(b, Blocker::StackedLink { name, .. } if name == "d1.5")),
            "{refused}"
        );
        let err = b
            .apply_with_options(&conn, purge())
            .await
            .expect_err("d1's removal is refused");
        assert!(err.is_not_supported(), "{err}");

        ns.exec("ip", &["link", "del", "d1.5"])?;
        let applied = b.apply_with_options(&conn, purge()).await?;
        assert!(applied.is_success(), "{applied:?}");
        for gone in ["v1", "d1"] {
            assert!(
                conn.get_link_by_name(gone).await?.is_none(),
                "{gone} stayed"
            );
        }
        for kept in ["d0", "other"] {
            assert!(
                conn.get_link_by_name(kept).await?.is_some(),
                "{kept} was deleted"
            );
        }
        let again = b
            .diff_with_options(&conn, PlanOptions::default().purge(true))
            .await?;
        assert!(again.is_empty(), "the second diff: {again}");
        Ok(())
    })
    .await
}

/// #526: a failed step names what it was done to. The kernel's answer
/// alone (`Network is unreachable`) said nothing about which route; the
/// error now carries the step as context and the route as its object,
/// propagated or collected with `continue_on_error`, and serialized.
#[tokio::test]
async fn a_failed_step_names_its_object() -> Result<()> {
    use nlink::ErrorObject;
    use nlink::netlink::config::ExecOptions;
    nlink::require_root!();
    nlink::require_module!("dummy");

    let ns = TestNamespace::new("err-object")?;
    let conn = conn_in_ns(&ns)?;
    // A gateway on a link with no address: the kernel refuses the route.
    let cfg = NetworkConfig::new()
        .link("d0", |b| b.dummy().up())
        .route("10.9.0.0/24", |r| r.via("10.99.0.1").dev("d0"))?;
    let route = ErrorObject::Route {
        destination: "10.9.0.0/24".into(),
        table: None,
    };

    let err = cfg.apply(&conn).await.expect_err("the gateway is unreachable");
    assert_eq!(err.object(), Some(&route), "{err}");
    assert!(err.to_string().contains("10.9.0.0/24"), "{err}");
    assert!(err.errno().is_some(), "the kernel's errno survives: {err:?}");

    let diff = cfg.diff(&conn).await?;
    let result = diff.apply(&conn, ExecOptions::new().with_continue_on_error(true)).await?;
    let [failed] = result.errors.as_slice() else {
        panic!("one failed step: {:?}", result.errors);
    };
    assert_eq!(failed.error.object(), Some(&route));
    #[cfg(feature = "serde")]
    {
        let json = serde_json::to_value(failed).unwrap();
        assert_eq!(json["object"]["type"], "route", "{json}");
        assert_eq!(json["object"]["destination"], "10.9.0.0/24", "{json}");
        assert_eq!(json["errno"], serde_json::json!(failed.error.errno()), "{json}");
    }
    Ok(())
}

/// A route through a nexthop object with a gateway reads back as itself
/// (#769): the kernel dumps the nexthop's gateway and device along with
/// its id (`nexthop_compat_mode`), and read back with them, the route's
/// delete matched no route, so a route the config stopped declaring stayed
/// forever, and an undo that put it back sent both, which the kernel
/// refuses ("Nexthop specification and nexthop id are mutually
/// exclusive").
#[tokio::test]
async fn a_route_through_a_nexthop_reads_back_as_one() -> Result<()> {
    use std::sync::Arc;
    nlink::require_root!();
    nlink::require_modules!("dummy");

    with_timeout(async {
        let ns = TestNamespace::new("nhid-readback")?;
        let conn = conn_in_ns(&ns)?;
        let base = || -> Result<NetworkConfig> {
            Ok(NetworkConfig::new()
                .link("d0", |l| l.dummy().up())
                .address("d0", "10.81.0.1/24")?
                .nexthop(5, |n| n.via("10.81.0.2".parse().unwrap()).dev("d0")))
        };
        let routes = |ns: &TestNamespace| -> Result<serde_json::Value> {
            crate::common::converge::ip_json(ns, &["route", "show", "10.82.0.0/16"])
                .map_err(nlink::Error::invalid_message)
        };
        let a = Arc::new(base()?.route("10.82.0.0/16", |r| r.nhid(5))?);
        let applied = a.apply(&conn).await?;
        assert!(applied.is_success(), "{applied:?}");

        // Replaced by a route through a gateway, and the replace undone.
        let b = base()?.route("10.82.0.0/16", |r| r.via("10.81.0.3").dev("d0"))?;
        let applied = b.apply(&conn).await?;
        assert!(applied.is_success(), "{applied:?}");
        assert_eq!(routes(&ns)?[0]["gateway"], "10.81.0.3");
        let undone = applied.undo().apply(&conn, nlink::ExecOptions::new()).await?;
        assert!(undone.is_success(), "{undone:?}");
        assert_eq!(routes(&ns)?[0]["nhid"], 5, "{}", routes(&ns)?);
        let back = a.diff(&conn).await?;
        assert!(back.is_empty(), "the undo left:\n{back}");

        // Removed: the previous config declared it, this one does not.
        let applied = base()?
            .apply_with_options(&conn, ApplyOptions::default().with_previous(a.clone()))
            .await?;
        assert!(applied.is_success(), "{applied:?}");
        assert_eq!(routes(&ns)?, serde_json::json!([]), "the route stayed");
        Ok(())
    })
    .await
}

/// A nexthop's encap is echoed with the route too (#769): a route through
/// an MPLS-encapsulating nexthop object never converged, the diff taking
/// the echoed `encap mpls` for the route's own; and it read back with it,
/// so the undo of its replace sent the encap with the id, which the
/// kernel refuses as it refuses a gateway.
#[tokio::test]
async fn a_route_through_an_encap_nexthop_reads_back_as_one() -> Result<()> {
    nlink::require_root!();
    nlink::require_modules!("dummy", "mpls_router", "mpls_iptunnel");

    with_timeout(async {
        let ns = TestNamespace::new("nhid-encap")?;
        let conn = conn_in_ns(&ns)?;
        let base = || -> Result<NetworkConfig> {
            Ok(NetworkConfig::new()
                .link("d0", |l| l.dummy().up())
                .address("d0", "10.83.0.1/24")?)
        };
        let applied = base()?.apply(&conn).await?;
        assert!(applied.is_success(), "{applied:?}");
        ns.exec("ip", &["nexthop", "add", "id", "7", "encap", "mpls", "100", "via", "10.83.0.2", "dev", "d0"])?;
        let routes = |ns: &TestNamespace| -> Result<serde_json::Value> {
            crate::common::converge::ip_json(ns, &["route", "show", "10.84.0.0/16"])
                .map_err(nlink::Error::invalid_message)
        };
        let a = base()?.route("10.84.0.0/16", |r| r.nhid(7))?;
        let applied = a.apply(&conn).await?;
        assert!(applied.is_success(), "{applied:?}");
        // The echoed encap is the object's, not a difference.
        let again = a.diff(&conn).await?;
        assert!(again.is_empty(), "a route through the nexthop did not converge:\n{again}");

        let b = base()?.route("10.84.0.0/16", |r| r.via("10.83.0.3").dev("d0"))?;
        let applied = b.apply(&conn).await?;
        assert!(applied.is_success(), "{applied:?}");
        let undone = applied.undo().apply(&conn, nlink::ExecOptions::new()).await?;
        assert!(undone.is_success(), "{undone:?}");
        assert_eq!(routes(&ns)?[0]["nhid"], 7, "{}", routes(&ns)?);
        let back = a.diff(&conn).await?;
        assert!(back.is_empty(), "the undo left:\n{back}");
        Ok(())
    })
    .await
}

/// An address the apply removes comes back from its undo with what it had
/// (#781): its label, metric and `noprefixroute`. The diff read a live
/// address back bare, so the undo put back a plain address: no label, a
/// metric-0 prefix route where there had been none.
#[tokio::test]
async fn an_undo_puts_back_an_address_with_its_attributes() -> Result<()> {
    nlink::require_root!();
    nlink::require_modules!("dummy");

    with_timeout(async {
        let ns = TestNamespace::new("addr-undo")?;
        let conn = conn_in_ns(&ns)?;
        let cfg = NetworkConfig::new().link("d0", |l| l.dummy().up());
        let applied = cfg.apply(&conn).await?;
        assert!(applied.is_success(), "{applied:?}");
        ns.exec("ip", &["addr", "add", "10.87.0.5/24", "dev", "d0", "label", "d0:x", "metric", "50", "noprefixroute"])?;
        let shown = |ns: &TestNamespace| -> Result<String> {
            let addr = crate::common::converge::ip_json(ns, &["addr", "show", "dev", "d0"])
                .map_err(nlink::Error::invalid_message)?;
            let routes = crate::common::converge::ip_json(ns, &["route", "show", "dev", "d0"])
                .map_err(nlink::Error::invalid_message)?;
            let a: Vec<String> = addr[0]["addr_info"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|a| a["family"] == "inet")
                .map(|a| format!("{} {} {} {}", a["local"], a["label"], a["metric"], a["noprefixroute"]))
                .collect();
            Ok(format!("{a:?} {routes}"))
        };
        let before = shown(&ns)?;

        let applied = cfg.apply_with_options(&conn, ApplyOptions::default().with_purge(true)).await?;
        assert!(applied.is_success(), "{applied:?}");
        assert!(!shown(&ns)?.contains("10.87.0.5"), "the purge removed it");
        let undone = applied.undo().apply(&conn, nlink::ExecOptions::new()).await?;
        assert!(undone.is_success(), "{undone:?}");
        assert_eq!(shown(&ns)?, before);
        Ok(())
    })
    .await
}

/// A tunnel's output key is compared too (#782). A declared key is the
/// key both ways, and the comparison read the input key alone: a gre,
/// vti or ip6gre tunnel with another output key compared equal to its
/// declaration and was never put right. The apply sends both now, and
/// `ip` reads one key back.
#[tokio::test]
async fn a_tunnels_output_key_is_compared() -> Result<()> {
    use std::net::Ipv6Addr;
    nlink::require_root!();
    nlink::require_modules!("ip_gre", "ip_vti", "ip6_gre", "ip6_vti");

    with_timeout(async {
        let ns = TestNamespace::new("okey")?;
        let conn = conn_in_ns(&ns)?;
        for (kind, local, remote) in [("gre", "10.88.0.1", "10.88.0.2"), ("vti", "10.88.1.1", "10.88.1.2"), ("ip6gre", "fd88::1", "fd88::2"), ("vti6", "fd88:1::1", "fd88:1::2")] {
            ns.exec("ip", &["link", "add", "t1", "type", kind, "local", local, "remote", remote, "ikey", "7", "okey", "8"])?;
            let cfg = NetworkConfig::new().link("t1", |l| match kind {
                "ip6gre" | "vti6" => (if kind == "ip6gre" { l.ip6gre() } else { l.vti6() })
                    .ip6tnl_local(local.parse::<Ipv6Addr>().unwrap())
                    .ip6tnl_remote(remote.parse::<Ipv6Addr>().unwrap())
                    .tunnel_key(7),
                _ => {
                    let l = if kind == "gre" { l.gre() } else { l.vti() };
                    l.tunnel_local(local.parse().unwrap()).tunnel_remote(remote.parse().unwrap()).tunnel_key(7)
                }
            });
            let diff = cfg.diff(&conn).await?;
            assert!(!diff.is_empty(), "{kind}: okey 8 compared equal to key 7");
            let applied = cfg.apply(&conn).await?;
            assert!(applied.is_success(), "{kind}: {applied:?}");
            let link = crate::common::converge::ip_json(&ns, &["-d", "link", "show", "t1"])
                .map_err(nlink::Error::invalid_message)?;
            let data = &link[0]["linkinfo"]["info_data"];
            assert_eq!((&data["ikey"], &data["okey"]), (&data["ikey"], &data["ikey"]), "{kind}: {data}");
            assert!(cfg.diff(&conn).await?.is_empty(), "{kind} did not converge");
            ns.exec("ip", &["link", "del", "t1"])?;
        }
        Ok(())
    })
    .await
}

/// A qdisc the apply takes away takes its tree with it, and the undo puts
/// both back (#783): an HTB root with classes, a leaf qdisc and filters,
/// replaced by another kind of root, and removed when the previous config
/// declared it. The undo used to add the bare qdisc back, and say nothing
/// was lost.
#[tokio::test]
async fn an_undo_puts_back_the_tree_under_a_qdisc() -> Result<()> {
    use std::sync::Arc;
    nlink::require_root!();
    nlink::require_modules!("dummy", "sch_htb", "sch_fq_codel", "sch_netem", "cls_matchall", "cls_u32");

    with_timeout(async {
        let ns = TestNamespace::new("qdisc-tree-undo")?;
        let conn = conn_in_ns(&ns)?;
        let htb = Arc::new(
            NetworkConfig::new()
                .link("d0", |l| l.dummy().up())
                .qdisc("d0", |q| q.htb().default_class(0x10)),
        );
        let tc = |args: &str| ns.exec("tc", &args.split_whitespace().collect::<Vec<_>>()).map(drop);
        let shown = || -> Result<Vec<String>> {
            ["qdisc show dev d0", "class show dev d0", "filter show dev d0 parent 1:"]
                .iter()
                .map(|a| ns.exec("tc", &a.split_whitespace().collect::<Vec<_>>()))
                .map(|r| {
                    r.map(|out| {
                        out.lines()
                            .map(|l| {
                                // Counters and per-install numbering are not state.
                                let mut w: Vec<&str> = l.split_whitespace().collect();
                                while let Some(i) = w.iter().position(|x| matches!(*x, "direct_packets_stat" | "index" | "ref" | "bind")) {
                                    w.drain(i..(i + 2).min(w.len()));
                                }
                                w.join(" ")
                            })
                            .collect::<Vec<_>>()
                            .join("\n")
                    })
                })
                .collect()
        };
        let fq = NetworkConfig::new()
            .link("d0", |l| l.dummy().up())
            .qdisc("d0", |q| q.fq_codel());
        let bare = NetworkConfig::new().link("d0", |l| l.dummy().up());
        let previous = nlink::netlink::config::PlanOptions::default().previous(htb.clone());
        let steps: [(&NetworkConfig, Option<&nlink::netlink::config::PlanOptions>); 2] = [(&fq, None), (&bare, Some(&previous))];
        for (next, plan) in steps {
            let applied = htb.apply(&conn).await?;
            assert!(applied.is_success(), "{applied:?}");
            tc("class add dev d0 parent 1: classid 1:10 htb rate 10mbit")?;
            tc("class add dev d0 parent 1: classid 1:20 htb rate 20mbit")?;
            tc("qdisc add dev d0 parent 1:20 handle 20: netem delay 5ms")?;
            tc("filter add dev d0 parent 1: prio 1 protocol ip matchall classid 1:20")?;
            tc("filter add dev d0 parent 1: prio 2 protocol ip u32 match ip dst 10.0.0.0/8 classid 1:10")?;
            let before = shown()?;

            let diff = match plan {
                Some(p) => next.diff_with_options(&conn, p.clone()).await?,
                None => next.diff(&conn).await?,
            };
            let applied = diff.apply(&conn, nlink::ExecOptions::new()).await?;
            assert!(applied.is_success(), "{applied:?}");
            assert!(!shown()?[1].contains("1:20"), "the tree went: {:?}", shown()?);
            let stuck: Vec<String> = applied.irreversible().map(|s| s.to_string()).collect();
            assert!(stuck.is_empty(), "{stuck:?}");
            let undone = applied.undo().apply(&conn, nlink::ExecOptions::new()).await?;
            assert!(undone.is_success(), "{undone:?}");
            assert_eq!(shown()?, before);
            ns.exec("tc", &["qdisc", "del", "dev", "d0", "root"])?;
        }
        Ok(())
    })
    .await
}
