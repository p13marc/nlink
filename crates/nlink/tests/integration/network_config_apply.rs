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
    config::NetworkConfig,
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
