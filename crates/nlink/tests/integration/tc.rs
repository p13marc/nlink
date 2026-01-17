//! Traffic Control (TC) integration tests.
//!
//! Tests for qdisc, class, and filter management using network namespaces.

use nlink::netlink::filter::{FlowerFilter, MatchallFilter, U32Filter};
use nlink::netlink::link::{DummyLink, IfbLink};
use nlink::netlink::tc::{
    FqCodelConfig, HtbClassConfig, HtbQdiscConfig, IngressConfig, NetemConfig, PrioConfig,
    SfqConfig, TbfConfig,
};
use nlink::{Connection, Result, Route};
use std::time::Duration;

use crate::common::TestNamespace;

/// Set up a namespace with a dummy interface.
async fn setup_tc_ns(name: &str) -> Result<(TestNamespace, Connection<Route>)> {
    let ns = TestNamespace::new(name)?;
    let conn = ns.connection()?;

    // Create dummy interface
    conn.add_link(DummyLink::new("dummy0")).await?;
    conn.set_link_up("dummy0").await?;

    Ok((ns, conn))
}

// ============================================================================
// Qdisc Tests
// ============================================================================

#[tokio::test]
async fn test_add_netem_qdisc() -> Result<()> {
    require_root!();

    let (_ns, conn) = setup_tc_ns("netem").await?;

    // Add netem qdisc with delay
    let netem = NetemConfig::new()
        .delay(Duration::from_millis(100))
        .jitter(Duration::from_millis(10))
        .build();

    conn.add_qdisc("dummy0", netem).await?;

    // Verify
    let qdiscs = conn.get_qdiscs_by_name("dummy0").await?;
    let netem = qdiscs.iter().find(|q| q.kind() == Some("netem"));
    assert!(netem.is_some(), "netem qdisc should exist");

    Ok(())
}

#[tokio::test]
async fn test_netem_with_loss() -> Result<()> {
    require_root!();

    let (_ns, conn) = setup_tc_ns("netemloss").await?;

    // Add netem with packet loss
    let netem = NetemConfig::new().loss(1.0).build();

    conn.add_qdisc("dummy0", netem).await?;

    // Verify netem exists
    let qdiscs = conn.get_qdiscs_by_name("dummy0").await?;
    let netem = qdiscs.iter().find(|q| q.kind() == Some("netem"));
    assert!(netem.is_some());

    Ok(())
}

#[tokio::test]
async fn test_remove_netem() -> Result<()> {
    require_root!();

    let (_ns, conn) = setup_tc_ns("netemrm").await?;

    // Add netem
    let netem = NetemConfig::new().delay(Duration::from_millis(50)).build();
    conn.add_qdisc("dummy0", netem).await?;

    // Remove it
    conn.remove_netem("dummy0").await?;

    // Verify it's gone (default qdisc should be back)
    let qdiscs = conn.get_qdiscs_by_name("dummy0").await?;
    assert!(
        !qdiscs.iter().any(|q| q.kind() == Some("netem")),
        "netem should be removed"
    );

    Ok(())
}

#[tokio::test]
async fn test_add_htb_qdisc() -> Result<()> {
    require_root!();

    let (_ns, conn) = setup_tc_ns("htb").await?;

    // Add HTB qdisc
    let htb = HtbQdiscConfig::new().default_class(0x30).build();
    conn.add_qdisc_full("dummy0", "root", Some("1:"), htb)
        .await?;

    // Verify
    let qdiscs = conn.get_qdiscs_by_name("dummy0").await?;
    let htb = qdiscs.iter().find(|q| q.kind() == Some("htb"));
    assert!(htb.is_some(), "htb qdisc should exist");
    assert!(htb.unwrap().is_root());

    Ok(())
}

#[tokio::test]
async fn test_add_tbf_qdisc() -> Result<()> {
    require_root!();

    let (_ns, conn) = setup_tc_ns("tbf").await?;

    // Add TBF qdisc (token bucket filter)
    let tbf = TbfConfig::new()
        .rate(1_000_000) // 1 Mbps
        .burst(10000)
        .limit(100000)
        .build();
    conn.add_qdisc("dummy0", tbf).await?;

    // Verify
    let qdiscs = conn.get_qdiscs_by_name("dummy0").await?;
    let tbf = qdiscs.iter().find(|q| q.kind() == Some("tbf"));
    assert!(tbf.is_some(), "tbf qdisc should exist");

    Ok(())
}

#[tokio::test]
async fn test_add_fq_codel_qdisc() -> Result<()> {
    require_root!();

    let (_ns, conn) = setup_tc_ns("fqcodel").await?;

    // Add fq_codel qdisc
    let fqcodel = FqCodelConfig::new()
        .target(Duration::from_micros(5000)) // 5ms
        .interval(Duration::from_micros(100000)) // 100ms
        .limit(10240)
        .build();
    conn.add_qdisc("dummy0", fqcodel).await?;

    // Verify
    let qdiscs = conn.get_qdiscs_by_name("dummy0").await?;
    let fq = qdiscs.iter().find(|q| q.kind() == Some("fq_codel"));
    assert!(fq.is_some(), "fq_codel qdisc should exist");

    Ok(())
}

#[tokio::test]
async fn test_add_prio_qdisc() -> Result<()> {
    require_root!();

    let (_ns, conn) = setup_tc_ns("prio").await?;

    // Add prio qdisc
    let prio = PrioConfig::new().bands(3).build();
    conn.add_qdisc_full("dummy0", "root", Some("1:"), prio)
        .await?;

    // Verify
    let qdiscs = conn.get_qdiscs_by_name("dummy0").await?;
    let prio = qdiscs.iter().find(|q| q.kind() == Some("prio"));
    assert!(prio.is_some(), "prio qdisc should exist");

    Ok(())
}

#[tokio::test]
async fn test_add_sfq_qdisc() -> Result<()> {
    require_root!();

    let (_ns, conn) = setup_tc_ns("sfq").await?;

    // Add SFQ qdisc
    let sfq = SfqConfig::new().perturb(10).quantum(1500).build();
    conn.add_qdisc("dummy0", sfq).await?;

    // Verify
    let qdiscs = conn.get_qdiscs_by_name("dummy0").await?;
    let sfq = qdiscs.iter().find(|q| q.kind() == Some("sfq"));
    assert!(sfq.is_some(), "sfq qdisc should exist");

    Ok(())
}

#[tokio::test]
async fn test_add_ingress_qdisc() -> Result<()> {
    require_root!();

    let (_ns, conn) = setup_tc_ns("ingress").await?;

    // Add ingress qdisc
    conn.add_qdisc("dummy0", IngressConfig::new()).await?;

    // Verify
    let qdiscs = conn.get_qdiscs_by_name("dummy0").await?;
    let ingress = qdiscs.iter().find(|q| q.kind() == Some("ingress"));
    assert!(ingress.is_some(), "ingress qdisc should exist");

    Ok(())
}

#[tokio::test]
async fn test_delete_qdisc() -> Result<()> {
    require_root!();

    let (_ns, conn) = setup_tc_ns("qdiscdel").await?;

    // Add netem
    let netem = NetemConfig::new().delay(Duration::from_millis(10)).build();
    conn.add_qdisc("dummy0", netem).await?;

    // Delete it
    conn.del_qdisc("dummy0", "root").await?;

    // Verify
    let qdiscs = conn.get_qdiscs_by_name("dummy0").await?;
    assert!(!qdiscs.iter().any(|q| q.kind() == Some("netem")));

    Ok(())
}

#[tokio::test]
async fn test_replace_qdisc() -> Result<()> {
    require_root!();

    let (_ns, conn) = setup_tc_ns("qdiscrep").await?;

    // Add netem with 100ms delay
    let netem1 = NetemConfig::new().delay(Duration::from_millis(100)).build();
    conn.add_qdisc("dummy0", netem1).await?;

    // Replace with 50ms delay
    let netem2 = NetemConfig::new().delay(Duration::from_millis(50)).build();
    conn.replace_qdisc("dummy0", netem2).await?;

    // Verify there's still just one netem
    let qdiscs = conn.get_qdiscs_by_name("dummy0").await?;
    let netem_count = qdiscs.iter().filter(|q| q.kind() == Some("netem")).count();
    assert_eq!(netem_count, 1);

    Ok(())
}

// ============================================================================
// Class Tests
// ============================================================================

#[tokio::test]
async fn test_add_htb_class() -> Result<()> {
    require_root!();

    let (_ns, conn) = setup_tc_ns("htbclass").await?;

    // Add HTB qdisc
    let htb = HtbQdiscConfig::new().default_class(0x30).build();
    conn.add_qdisc_full("dummy0", "root", Some("1:"), htb)
        .await?;

    // Add class
    let class = HtbClassConfig::new("10mbit")?
        .ceil_bps(100_000_000) // 100 Mbps
        .build();
    conn.add_class_config("dummy0", "1:", "1:10", class).await?;

    // Verify
    let classes = conn.get_classes_by_name("dummy0").await?;
    assert!(
        !classes.is_empty(),
        "at least one class should exist (may include root)"
    );

    Ok(())
}

#[tokio::test]
async fn test_htb_class_hierarchy() -> Result<()> {
    require_root!();

    let (_ns, conn) = setup_tc_ns("htbhier").await?;

    // Add HTB qdisc
    let htb = HtbQdiscConfig::new().default_class(0x30).build();
    conn.add_qdisc_full("dummy0", "root", Some("1:"), htb)
        .await?;

    // Add root class
    let root_class = HtbClassConfig::new("100mbit")?.build();
    conn.add_class_config("dummy0", "1:", "1:1", root_class)
        .await?;

    // Add child classes
    let child1 = HtbClassConfig::new("50mbit")?.ceil_bps(100_000_000).build();
    conn.add_class_config("dummy0", "1:1", "1:10", child1)
        .await?;

    let child2 = HtbClassConfig::new("30mbit")?.ceil_bps(100_000_000).build();
    conn.add_class_config("dummy0", "1:1", "1:20", child2)
        .await?;

    // Verify
    let classes = conn.get_classes_by_name("dummy0").await?;
    assert!(classes.len() >= 3, "should have at least 3 classes");

    Ok(())
}

#[tokio::test]
async fn test_delete_class() -> Result<()> {
    require_root!();

    let (_ns, conn) = setup_tc_ns("classdel").await?;

    // Add HTB qdisc
    let htb = HtbQdiscConfig::new().default_class(0x30).build();
    conn.add_qdisc_full("dummy0", "root", Some("1:"), htb)
        .await?;

    // Add class
    let class = HtbClassConfig::new("10mbit")?.build();
    conn.add_class_config("dummy0", "1:", "1:10", class).await?;

    // Delete it
    conn.del_class("dummy0", "1:", "1:10").await?;

    // Verify
    let classes = conn.get_classes_by_name("dummy0").await?;
    // Check that class 1:10 is gone
    assert!(!classes.iter().any(|c| c.handle() == 0x10010)); // 1:10 = 0x10010

    Ok(())
}

// ============================================================================
// Filter Tests
// ============================================================================

#[tokio::test]
async fn test_add_matchall_filter() -> Result<()> {
    require_root!();

    let (_ns, conn) = setup_tc_ns("matchall").await?;

    // Add HTB qdisc first
    let htb = HtbQdiscConfig::new().default_class(0x30).build();
    conn.add_qdisc_full("dummy0", "root", Some("1:"), htb)
        .await?;

    // Add class
    let class = HtbClassConfig::new("10mbit")?.build();
    conn.add_class_config("dummy0", "1:", "1:10", class).await?;

    // Add matchall filter
    let filter = MatchallFilter::new().classid("1:10").build();
    conn.add_filter("dummy0", "1:", filter).await?;

    // Verify
    let filters = conn.get_filters_by_name("dummy0").await?;
    let matchall = filters.iter().find(|f| f.kind() == Some("matchall"));
    assert!(matchall.is_some(), "matchall filter should exist");

    Ok(())
}

#[tokio::test]
async fn test_add_u32_filter() -> Result<()> {
    require_root!();

    let (_ns, conn) = setup_tc_ns("u32").await?;

    // Add HTB qdisc
    let htb = HtbQdiscConfig::new().default_class(0x30).build();
    conn.add_qdisc_full("dummy0", "root", Some("1:"), htb)
        .await?;

    // Add class
    let class = HtbClassConfig::new("10mbit")?.build();
    conn.add_class_config("dummy0", "1:", "1:10", class).await?;

    // Add u32 filter matching destination port 80
    let filter = U32Filter::new().classid("1:10").match_dst_port(80).build();
    conn.add_filter("dummy0", "1:", filter).await?;

    // Verify
    let filters = conn.get_filters_by_name("dummy0").await?;
    let u32 = filters.iter().find(|f| f.kind() == Some("u32"));
    assert!(u32.is_some(), "u32 filter should exist");

    Ok(())
}

#[tokio::test]
async fn test_add_flower_filter() -> Result<()> {
    require_root!();

    let (_ns, conn) = setup_tc_ns("flower").await?;

    // Add HTB qdisc
    let htb = HtbQdiscConfig::new().default_class(0x30).build();
    conn.add_qdisc_full("dummy0", "root", Some("1:"), htb)
        .await?;

    // Add class
    let class = HtbClassConfig::new("10mbit")?.build();
    conn.add_class_config("dummy0", "1:", "1:10", class).await?;

    // Add flower filter
    let filter = FlowerFilter::new().classid("1:10").ip_proto_tcp().build();
    conn.add_filter("dummy0", "1:", filter).await?;

    // Verify
    let filters = conn.get_filters_by_name("dummy0").await?;
    let flower = filters.iter().find(|f| f.kind() == Some("flower"));
    assert!(flower.is_some(), "flower filter should exist");

    Ok(())
}

#[tokio::test]
async fn test_matchall_on_ingress() -> Result<()> {
    require_root!();

    let (_ns, conn) = setup_tc_ns("matchinq").await?;

    // Add ingress qdisc
    conn.add_qdisc("dummy0", IngressConfig::new()).await?;

    // Add matchall filter on ingress (without actions - just classifying)
    let filter = MatchallFilter::new().build();
    conn.add_filter("dummy0", "ingress", filter).await?;

    // Verify
    let filters = conn.get_filters_by_name("dummy0").await?;
    assert!(!filters.is_empty(), "filter should exist");

    Ok(())
}

#[tokio::test]
async fn test_matchall_goto_chain() -> Result<()> {
    require_root!();

    let (_ns, conn) = setup_tc_ns("gotoch").await?;

    // Add HTB qdisc
    let htb = HtbQdiscConfig::new().default_class(0x30).build();
    conn.add_qdisc_full("dummy0", "root", Some("1:"), htb)
        .await?;

    // Add chain 10
    conn.add_tc_chain("dummy0", "1:", 10).await?;

    // Add matchall filter with goto_chain
    let filter = MatchallFilter::new().goto_chain(10).build();
    conn.add_filter("dummy0", "1:", filter).await?;

    // Verify
    let filters = conn.get_filters_by_name("dummy0").await?;
    assert!(!filters.is_empty(), "filter should exist");

    Ok(())
}

#[tokio::test]
async fn test_filter_on_ifb() -> Result<()> {
    require_root!();

    let (_ns, conn) = setup_tc_ns("ifbfilt").await?;

    // Create IFB interface
    conn.add_link(IfbLink::new("ifb0")).await?;
    conn.set_link_up("ifb0").await?;

    // Add HTB qdisc on IFB
    let htb = HtbQdiscConfig::new().default_class(0x30).build();
    conn.add_qdisc_full("ifb0", "root", Some("1:"), htb).await?;

    // Add class
    let class = HtbClassConfig::new("10mbit")?.build();
    conn.add_class_config("ifb0", "1:", "1:10", class).await?;

    // Add matchall filter
    let filter = MatchallFilter::new().classid("1:10").build();
    conn.add_filter("ifb0", "1:", filter).await?;

    // Verify
    let filters = conn.get_filters_by_name("ifb0").await?;
    assert!(!filters.is_empty(), "filter should exist");

    Ok(())
}

#[tokio::test]
async fn test_delete_filter() -> Result<()> {
    require_root!();

    let (_ns, conn) = setup_tc_ns("filterdel").await?;

    // Add HTB qdisc
    let htb = HtbQdiscConfig::new().default_class(0x30).build();
    conn.add_qdisc_full("dummy0", "root", Some("1:"), htb)
        .await?;

    // Add class
    let class = HtbClassConfig::new("10mbit")?.build();
    conn.add_class_config("dummy0", "1:", "1:10", class).await?;

    // Add filter
    let filter = MatchallFilter::new().classid("1:10").build();
    conn.add_filter("dummy0", "1:", filter).await?;

    // Flush filters
    conn.flush_filters("dummy0", "1:").await?;

    // Verify
    let filters = conn.get_filters_by_name("dummy0").await?;
    assert!(filters.is_empty(), "filters should be deleted");

    Ok(())
}

#[tokio::test]
async fn test_replace_filter() -> Result<()> {
    require_root!();

    let (_ns, conn) = setup_tc_ns("filterrep").await?;

    // Add HTB qdisc
    let htb = HtbQdiscConfig::new().default_class(0x30).build();
    conn.add_qdisc_full("dummy0", "root", Some("1:"), htb)
        .await?;

    // Add classes
    let class1 = HtbClassConfig::new("10mbit")?.build();
    conn.add_class_config("dummy0", "1:", "1:10", class1)
        .await?;

    let class2 = HtbClassConfig::new("20mbit")?.build();
    conn.add_class_config("dummy0", "1:", "1:20", class2)
        .await?;

    // Add filter pointing to 1:10
    let filter = MatchallFilter::new().classid("1:10").build();
    conn.add_filter("dummy0", "1:", filter).await?;

    // Replace to point to 1:20
    let filter2 = MatchallFilter::new().classid("1:20").build();
    conn.replace_filter("dummy0", "1:", filter2).await?;

    // Verify there's still just one matchall filter
    let filters = conn.get_filters_by_name("dummy0").await?;
    let matchall_count = filters
        .iter()
        .filter(|f| f.kind() == Some("matchall"))
        .count();
    assert_eq!(matchall_count, 1);

    Ok(())
}

// ============================================================================
// Statistics Tests
// ============================================================================

#[tokio::test]
async fn test_qdisc_statistics() -> Result<()> {
    require_root!();

    let (_ns, conn) = setup_tc_ns("qdiscstats").await?;

    // Add netem qdisc
    let netem = NetemConfig::new().delay(Duration::from_millis(10)).build();
    conn.add_qdisc("dummy0", netem).await?;

    // Get qdiscs and check stats are available
    let qdiscs = conn.get_qdiscs_by_name("dummy0").await?;
    let netem = qdiscs.iter().find(|q| q.kind() == Some("netem")).unwrap();

    // Check convenience methods work
    let _bytes = netem.bytes();
    let _packets = netem.packets();
    let _drops = netem.drops();

    Ok(())
}

#[tokio::test]
async fn test_class_statistics() -> Result<()> {
    require_root!();

    let (_ns, conn) = setup_tc_ns("classstats").await?;

    // Add HTB qdisc and class
    let htb = HtbQdiscConfig::new().default_class(0x30).build();
    conn.add_qdisc_full("dummy0", "root", Some("1:"), htb)
        .await?;

    let class = HtbClassConfig::new("10mbit")?.build();
    conn.add_class_config("dummy0", "1:", "1:10", class).await?;

    // Get classes and check stats
    let classes = conn.get_classes_by_name("dummy0").await?;
    assert!(!classes.is_empty());

    // Check convenience methods work
    for c in &classes {
        let _bytes = c.bytes();
        let _packets = c.packets();
    }

    Ok(())
}

// ============================================================================
// Chain Tests
// ============================================================================

#[tokio::test]
async fn test_add_tc_chain() -> Result<()> {
    require_root!();

    let (_ns, conn) = setup_tc_ns("chain").await?;

    // Add HTB qdisc
    let htb = HtbQdiscConfig::new().default_class(0x30).build();
    conn.add_qdisc_full("dummy0", "root", Some("1:"), htb)
        .await?;

    // Add a chain
    conn.add_tc_chain("dummy0", "1:", 10).await?;

    // Get chains
    let chains = conn.get_tc_chains("dummy0", "1:").await?;
    assert!(chains.contains(&10), "chain 10 should exist");

    Ok(())
}

#[tokio::test]
async fn test_delete_tc_chain() -> Result<()> {
    require_root!();

    let (_ns, conn) = setup_tc_ns("chaindel").await?;

    // Add HTB qdisc
    let htb = HtbQdiscConfig::new().default_class(0x30).build();
    conn.add_qdisc_full("dummy0", "root", Some("1:"), htb)
        .await?;

    // Add and delete chain
    conn.add_tc_chain("dummy0", "1:", 20).await?;
    conn.del_tc_chain("dummy0", "1:", 20).await?;

    // Verify it's gone
    let chains = conn.get_tc_chains("dummy0", "1:").await?;
    assert!(!chains.contains(&20), "chain 20 should be deleted");

    Ok(())
}

#[tokio::test]
async fn test_filter_with_chain() -> Result<()> {
    require_root!();

    let (_ns, conn) = setup_tc_ns("fchain").await?;

    // Add HTB qdisc
    let htb = HtbQdiscConfig::new().default_class(0x30).build();
    conn.add_qdisc_full("dummy0", "root", Some("1:"), htb)
        .await?;

    // Add class
    let class = HtbClassConfig::new("10mbit")?.build();
    conn.add_class_config("dummy0", "1:", "1:10", class).await?;

    // Add chain
    conn.add_tc_chain("dummy0", "1:", 5).await?;

    // Add filter in chain 5
    let filter = MatchallFilter::new().classid("1:10").chain(5).build();
    conn.add_filter("dummy0", "1:", filter).await?;

    // Verify filter is in chain
    let filters = conn.get_filters_by_name("dummy0").await?;
    // At least one filter should exist
    assert!(!filters.is_empty());

    Ok(())
}
