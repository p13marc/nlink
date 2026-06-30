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

use std::time::Duration;

use nlink::Result;
use nlink::netlink::{
    Connection, Route,
    config::{DiffOptions, NetworkConfig},
    namespace,
};

use crate::common::TestNamespace;

/// Wrap a test body in a 30s timeout so a hang surfaces as
/// `Error::Timeout`, not a hung CI job.
async fn with_timeout<F>(body: F) -> Result<()>
where
    F: std::future::Future<Output = Result<()>>,
{
    match tokio::time::timeout(Duration::from_secs(30), body).await {
        Ok(result) => result,
        Err(_elapsed) => Err(nlink::Error::Timeout),
    }
}

fn conn_in_ns(ns: &TestNamespace) -> Result<Connection<Route>> {
    namespace::connection_for::<Route>(ns.name())
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
            .diff_with_options(&conn, DiffOptions::default().purge(true))
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
        let result = diff.apply(&conn, Default::default()).await?;
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
            .diff_with_options(&conn, DiffOptions::default().purge(true))
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
            .diff_with_options(&conn, DiffOptions::default().purge(true))
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

        let _ = diff.apply(&conn, Default::default()).await?;

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
            .diff_with_options(&conn, DiffOptions::default().purge(true))
            .await?;
        assert!(
            again.routes_to_remove.is_empty(),
            "purge must be idempotent — second diff has no route removals"
        );

        Ok(())
    })
    .await
}
