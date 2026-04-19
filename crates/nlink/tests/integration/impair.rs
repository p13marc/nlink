//! Integration tests for the per-peer impairment helper.
//!
//! These require root + a kernel with `cls_flower` and `sch_netem` loaded.

use std::{net::Ipv4Addr, time::Duration};

use nlink::netlink::{
    impair::{PeerImpairment, PerPeerImpairer},
    link::DummyLink,
    tc::NetemConfig,
};

use crate::common::TestNamespace;

fn netem_50ms() -> NetemConfig {
    NetemConfig::new().delay(Duration::from_millis(50)).build()
}

#[tokio::test]
async fn test_apply_creates_full_tree() -> nlink::Result<()> {
    require_root!();

    let ns = TestNamespace::new("impair_apply")?;
    let conn = ns.connection()?;

    conn.add_link(DummyLink::new("test0")).await?;
    conn.set_link_up("test0").await?;
    let link = conn.get_link_by_name("test0").await?.expect("dummy exists");
    let ifindex = link.ifindex();

    PerPeerImpairer::new("test0")
        .impair_dst_ip(Ipv4Addr::new(10, 0, 0, 1).into(), netem_50ms())
        .impair_dst_ip(Ipv4Addr::new(10, 0, 0, 2).into(), netem_50ms())
        .impair_dst_ip(Ipv4Addr::new(10, 0, 0, 3).into(), netem_50ms())
        .apply(&conn)
        .await?;

    // Root HTB present.
    let qdiscs = conn.get_qdiscs_by_index(ifindex).await?;
    assert!(
        qdiscs
            .iter()
            .any(|q| q.kind() == Some("htb") && q.is_root()),
        "root HTB should exist"
    );

    // 4 netem leaves: one per rule + one default (since no default
    // impairment specified, we don't add a netem leaf for the default
    // class — adjust: exactly 3 netem leaves expected)
    let netem_count = qdiscs.iter().filter(|q| q.kind() == Some("netem")).count();
    assert_eq!(
        netem_count, 3,
        "expected 3 netem leaves (one per rule, no default impairment)"
    );

    // 5 classes total: 1:1 root + 1:2..1:4 per rule + 1:5 default.
    let classes = conn.get_classes_by_index(ifindex).await?;
    let htb_classes = classes.iter().filter(|c| c.kind() == Some("htb")).count();
    assert_eq!(
        htb_classes, 5,
        "expected 5 HTB classes (1 parent + 3 rules + 1 default)"
    );

    // 3 flower filters at parent 1:.
    let filters = conn
        .get_filters_by_parent_index(ifindex, nlink::TcHandle::major_only(1))
        .await?;
    let flower_filters = filters
        .iter()
        .filter(|f| f.kind() == Some("flower"))
        .count();
    assert_eq!(flower_filters, 3, "expected 3 flower filters at parent 1:");

    Ok(())
}

#[tokio::test]
async fn test_apply_with_default_impairment_adds_default_leaf() -> nlink::Result<()> {
    require_root!();

    let ns = TestNamespace::new("impair_default")?;
    let conn = ns.connection()?;

    conn.add_link(DummyLink::new("test0")).await?;
    conn.set_link_up("test0").await?;
    let link = conn.get_link_by_name("test0").await?.expect("dummy exists");
    let ifindex = link.ifindex();

    PerPeerImpairer::new("test0")
        .impair_dst_ip(Ipv4Addr::new(10, 0, 0, 1).into(), netem_50ms())
        .default_impairment(NetemConfig::new().delay(Duration::from_millis(20)).build())
        .apply(&conn)
        .await?;

    let qdiscs = conn.get_qdiscs_by_index(ifindex).await?;
    let netem_count = qdiscs.iter().filter(|q| q.kind() == Some("netem")).count();
    assert_eq!(
        netem_count, 2,
        "expected 2 netem leaves (1 rule + 1 default impairment)"
    );

    Ok(())
}

#[tokio::test]
async fn test_apply_no_default_means_no_default_leaf() -> nlink::Result<()> {
    require_root!();

    let ns = TestNamespace::new("impair_no_default")?;
    let conn = ns.connection()?;

    conn.add_link(DummyLink::new("test0")).await?;
    conn.set_link_up("test0").await?;
    let link = conn.get_link_by_name("test0").await?.expect("dummy exists");
    let ifindex = link.ifindex();

    PerPeerImpairer::new("test0")
        .impair_dst_ip(Ipv4Addr::new(10, 0, 0, 1).into(), netem_50ms())
        .apply(&conn)
        .await?;

    let qdiscs = conn.get_qdiscs_by_index(ifindex).await?;
    let netem_count = qdiscs.iter().filter(|q| q.kind() == Some("netem")).count();
    assert_eq!(
        netem_count, 1,
        "expected 1 netem leaf (rule only, no default impairment)"
    );

    Ok(())
}

#[tokio::test]
async fn test_apply_idempotent() -> nlink::Result<()> {
    require_root!();

    let ns = TestNamespace::new("impair_idempotent")?;
    let conn = ns.connection()?;

    conn.add_link(DummyLink::new("test0")).await?;
    conn.set_link_up("test0").await?;
    let link = conn.get_link_by_name("test0").await?.expect("dummy exists");
    let ifindex = link.ifindex();

    let imp = PerPeerImpairer::new("test0")
        .impair_dst_ip(Ipv4Addr::new(10, 0, 0, 1).into(), netem_50ms())
        .impair_dst_ip(Ipv4Addr::new(10, 0, 0, 2).into(), netem_50ms());

    imp.apply(&conn).await?;
    let first_filter_count = conn
        .get_filters_by_parent_index(ifindex, nlink::TcHandle::major_only(1))
        .await?
        .iter()
        .filter(|f| f.kind() == Some("flower"))
        .count();

    // Apply again — should give the same shape.
    imp.apply(&conn).await?;
    let second_filter_count = conn
        .get_filters_by_parent_index(ifindex, nlink::TcHandle::major_only(1))
        .await?
        .iter()
        .filter(|f| f.kind() == Some("flower"))
        .count();

    assert_eq!(first_filter_count, second_filter_count);
    assert_eq!(first_filter_count, 2);

    Ok(())
}

#[tokio::test]
async fn test_clear_removes_all() -> nlink::Result<()> {
    require_root!();

    let ns = TestNamespace::new("impair_clear")?;
    let conn = ns.connection()?;

    conn.add_link(DummyLink::new("test0")).await?;
    conn.set_link_up("test0").await?;
    let link = conn.get_link_by_name("test0").await?.expect("dummy exists");
    let ifindex = link.ifindex();

    let imp = PerPeerImpairer::new("test0")
        .impair_dst_ip(Ipv4Addr::new(10, 0, 0, 1).into(), netem_50ms());

    imp.apply(&conn).await?;
    assert!(
        conn.get_qdiscs_by_index(ifindex)
            .await?
            .iter()
            .any(|q| q.kind() == Some("htb")),
        "HTB should exist after apply"
    );

    imp.clear(&conn).await?;
    assert!(
        !conn
            .get_qdiscs_by_index(ifindex)
            .await?
            .iter()
            .any(|q| q.kind() == Some("htb")),
        "HTB should be removed after clear"
    );

    // clear() is idempotent — second call is a no-op.
    imp.clear(&conn).await?;

    Ok(())
}

#[tokio::test]
async fn test_apply_with_ipv6_match() -> nlink::Result<()> {
    require_root!();

    let ns = TestNamespace::new("impair_v6")?;
    let conn = ns.connection()?;

    conn.add_link(DummyLink::new("test0")).await?;
    conn.set_link_up("test0").await?;
    let link = conn.get_link_by_name("test0").await?.expect("dummy exists");
    let ifindex = link.ifindex();

    PerPeerImpairer::new("test0")
        .impair_dst_subnet("2001:db8::/32", netem_50ms())?
        .apply(&conn)
        .await?;

    let filters = conn
        .get_filters_by_parent_index(ifindex, nlink::TcHandle::major_only(1))
        .await?;
    let flower_filters: Vec<_> = filters
        .iter()
        .filter(|f| f.kind() == Some("flower"))
        .collect();
    assert_eq!(flower_filters.len(), 1, "one flower filter expected");

    Ok(())
}

#[tokio::test]
async fn test_apply_with_dst_mac_match() -> nlink::Result<()> {
    require_root!();

    let ns = TestNamespace::new("impair_mac")?;
    let conn = ns.connection()?;

    conn.add_link(DummyLink::new("test0")).await?;
    conn.set_link_up("test0").await?;
    let link = conn.get_link_by_name("test0").await?.expect("dummy exists");
    let ifindex = link.ifindex();

    PerPeerImpairer::new("test0")
        .impair_dst_mac([0x52, 0x54, 0x00, 0x12, 0x34, 0x56], netem_50ms())
        .apply(&conn)
        .await?;

    let filters = conn
        .get_filters_by_parent_index(ifindex, nlink::TcHandle::major_only(1))
        .await?;
    assert!(
        filters.iter().any(|f| f.kind() == Some("flower")),
        "flower filter for MAC match should exist"
    );

    Ok(())
}

#[tokio::test]
async fn test_apply_by_index_constructor() -> nlink::Result<()> {
    require_root!();

    let ns = TestNamespace::new("impair_byidx")?;
    let conn = ns.connection()?;

    conn.add_link(DummyLink::new("test0")).await?;
    conn.set_link_up("test0").await?;
    let link = conn.get_link_by_name("test0").await?.expect("dummy exists");
    let ifindex = link.ifindex();

    PerPeerImpairer::new_by_index(ifindex)
        .impair_dst_ip(Ipv4Addr::new(10, 0, 0, 1).into(), netem_50ms())
        .apply(&conn)
        .await?;

    let qdiscs = conn.get_qdiscs_by_index(ifindex).await?;
    assert!(
        qdiscs.iter().any(|q| q.kind() == Some("htb")),
        "tree should be created when constructed by ifindex"
    );

    Ok(())
}

#[tokio::test]
async fn test_rate_cap_per_rule() -> nlink::Result<()> {
    require_root!();

    let ns = TestNamespace::new("impair_ratecap")?;
    let conn = ns.connection()?;

    conn.add_link(DummyLink::new("test0")).await?;
    conn.set_link_up("test0").await?;
    let link = conn.get_link_by_name("test0").await?.expect("dummy exists");
    let ifindex = link.ifindex();

    PerPeerImpairer::new("test0")
        .impair_dst_ip(
            Ipv4Addr::new(10, 0, 0, 1).into(),
            PeerImpairment::new(netem_50ms()).rate_cap(nlink::Rate::mbit(100)),
        )
        .apply(&conn)
        .await?;

    let classes = conn.get_classes_by_index(ifindex).await?;
    let htb_classes: Vec<_> = classes.iter().filter(|c| c.kind() == Some("htb")).collect();
    // 1 parent + 1 rule + 1 default = 3 HTB classes
    assert_eq!(htb_classes.len(), 3, "expected 3 HTB classes with rate cap");

    Ok(())
}

#[tokio::test]
async fn test_get_filters_by_parent_filters_correctly() -> nlink::Result<()> {
    require_root!();

    let ns = TestNamespace::new("impair_byparent")?;
    let conn = ns.connection()?;

    conn.add_link(DummyLink::new("test0")).await?;
    conn.set_link_up("test0").await?;
    let link = conn.get_link_by_name("test0").await?.expect("dummy exists");
    let ifindex = link.ifindex();

    PerPeerImpairer::new("test0")
        .impair_dst_ip(Ipv4Addr::new(10, 0, 0, 1).into(), netem_50ms())
        .impair_dst_ip(Ipv4Addr::new(10, 0, 0, 2).into(), netem_50ms())
        .apply(&conn)
        .await?;

    // All filters at parent 1: should be the helper's flower filters.
    let at_root = conn
        .get_filters_by_parent_index(ifindex, nlink::TcHandle::major_only(1))
        .await?;
    assert_eq!(at_root.len(), 2, "expected 2 filters at parent 1:");
    assert!(at_root.iter().all(|f| f.kind() == Some("flower")));

    // No filters at parent 2: (a parent that doesn't exist).
    let at_other = conn
        .get_filters_by_parent_index(ifindex, nlink::TcHandle::major_only(2))
        .await?;
    assert!(at_other.is_empty(), "no filters expected at parent 2:");

    Ok(())
}
