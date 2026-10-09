//! Traffic Control (TC) integration tests.
//!
//! Tests for qdisc, class, and filter management using network namespaces.

use std::time::Duration;

use nlink::{
    Connection, Result, Route, TcHandle,
    netlink::{
        filter::{FlowerFilter, MatchallFilter, U32Filter},
        link::{DummyLink, IfbLink},
        tc::{
            FqCodelConfig, HtbClassConfig, HtbQdiscConfig, IngressConfig, NetemConfig,
            NetemLossModel, PlugConfig, PrioConfig, SfqConfig, TbfConfig,
        },
        tc_options::QdiscOptions,
    },
};

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
    nlink::require_modules!("sch_netem");

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

/// `PlugConfig::new().build()` — no limit — could not install a plug at
/// all: the request carried an empty `TCA_OPTIONS` nest, and `plug_init`
/// refuses one shorter than `tc_plug_qopt` with `EINVAL`. The form the
/// kernel wants for "use the device default" is *no* `TCA_OPTIONS`
/// (#327). This installs the plug as the leaf of a netem, the shape the
/// issue reproduced with, then sends traffic through it and checks the
/// property that distinguishes a working plug from a `limit(0)`
/// blackhole: packets are **held**, not dropped.
#[tokio::test]
async fn plug_without_limit_installs_and_buffers() -> Result<()> {
    require_root!();
    nlink::require_modules!("sch_netem", "sch_plug", "veth");

    let left = TestNamespace::new("plug_l")?;
    let right = TestNamespace::new("plug_r")?;
    left.connect_to(&right, "veth0", "veth1")?;
    left.add_addr("veth0", "10.27.0.1/24")?;
    left.link_up("veth0")?;
    right.add_addr("veth1", "10.27.0.2/24")?;
    right.link_up("veth1")?;

    let conn = left.connection()?;
    let ifindex = conn
        .get_link_by_name("veth0")
        .await?
        .expect("veth0 exists")
        .ifindex();

    conn.add_qdisc_by_index_full(
        ifindex,
        TcHandle::ROOT,
        Some(TcHandle::major_only(1)),
        NetemConfig::new().build(),
    )
    .await?;
    let parent = TcHandle::new(1, 1);

    // The form that returned EINVAL.
    conn.add_qdisc_by_index_full(ifindex, parent, None, PlugConfig::new().build())
        .await
        .expect("PlugConfig::new().build() must install (no TCA_OPTIONS → kernel default limit)");

    // Ping into the plug: nothing comes back (that is the point of a
    // plug), so let ping time out and look at the qdisc instead.
    left.exec_ignore("ping", &["-c", "3", "-i", "0.2", "-W", "1", "10.27.0.2"]);

    let qdiscs = conn.get_qdiscs_by_index(ifindex).await?;
    let plug = qdiscs
        .iter()
        .find(|q| q.kind() == Some("plug"))
        .expect("plug qdisc is installed");
    let stats = plug.stats_queue().expect("plug reports queue stats");
    assert!(
        stats.backlog > 0 && stats.qlen > 0,
        "a plug with the kernel-default limit must hold packets; \
         backlog {}b {}p — a zero limit would show 0b 0p and drops instead",
        stats.backlog,
        stats.qlen
    );
    assert_eq!(
        stats.drops, 0,
        "a plug with the kernel-default limit dropped {} packets — that is \
         the `limit 0` blackhole, not the default",
        stats.drops
    );

    // An explicit limit keeps working: replace with one and the qdisc
    // still stands.
    conn.replace_qdisc_by_index_full(ifindex, parent, None, PlugConfig::new().limit(65536).build())
        .await?;
    let qdiscs = conn.get_qdiscs_by_index(ifindex).await?;
    assert!(qdiscs.iter().any(|q| q.kind() == Some("plug")));

    // Let the buffered packets out so the namespace tears down cleanly.
    conn.plug_release_indefinite(ifindex, parent).await.ok();
    Ok(())
}

#[tokio::test]
async fn test_netem_with_loss() -> Result<()> {
    require_root!();
    nlink::require_modules!("sch_netem");

    let (_ns, conn) = setup_tc_ns("netemloss").await?;

    // Add netem with packet loss
    let netem = NetemConfig::new().loss(nlink::Percent::new(1.0)).build();

    conn.add_qdisc("dummy0", netem).await?;

    // Verify netem exists
    let qdiscs = conn.get_qdiscs_by_name("dummy0").await?;
    let netem = qdiscs.iter().find(|q| q.kind() == Some("netem"));
    assert!(netem.is_some());

    Ok(())
}

/// The Markov loss models go into the kernel and come back as written
/// (#368). The kernel echoes `TCA_NETEM_LOSS` only after `get_loss_clg`
/// accepted it, so a model read back is a model the kernel parsed — the
/// nested attribute, its `NLA_F_NESTED` flag and the struct layout all
/// included. A plain `loss` replace must then clear it.
#[tokio::test]
async fn netem_loss_models_round_trip_through_the_kernel() -> Result<()> {
    require_root!();
    nlink::require_modules!("sch_netem");
    use nlink::Percent;

    let (_ns, conn) = setup_tc_ns("netem-lossmodel").await?;
    let models = [
        NetemLossModel::gilbert_elliot(Percent::new(1.0))
            .r(Percent::new(30.0))
            .loss_in_bad(Percent::new(50.0))
            .loss_in_good(Percent::new(0.1)),
        NetemLossModel::gilbert_intuitive(Percent::new(1.0))
            .p31(Percent::new(2.0))
            .p32(Percent::new(3.0))
            .p23(Percent::new(4.0))
            .p14(Percent::new(5.0)),
    ];
    for model in models {
        conn.replace_qdisc("dummy0", NetemConfig::new().loss_model(model).build())
            .await?;
        let qdiscs = conn.get_qdiscs_by_name("dummy0").await?;
        let netem = qdiscs
            .iter()
            .find(|q| q.kind() == Some("netem"))
            .expect("netem installed");
        let Some(QdiscOptions::Netem(opts)) = netem.options() else {
            panic!("netem options did not parse");
        };
        let echoed = opts
            .loss_model()
            .unwrap_or_else(|| panic!("the kernel echoed no loss model for {model:?}"));
        assert_eq!(
            format!("{echoed:.3?}"),
            format!("{model:.3?}"),
            "kernel stored a different model"
        );
        assert_eq!(opts.loss(), Some(0.0), "a model must not also set random loss");
    }

    conn.replace_qdisc("dummy0", NetemConfig::new().loss(Percent::new(2.0)).build())
        .await?;
    let qdiscs = conn.get_qdiscs_by_name("dummy0").await?;
    let netem = qdiscs.iter().find(|q| q.kind() == Some("netem")).unwrap();
    let Some(QdiscOptions::Netem(opts)) = netem.options() else {
        panic!("netem options did not parse");
    };
    assert!(opts.loss_model().is_none(), "random loss must replace the model");
    Ok(())
}

/// A configured model must actually *drop* — the property nlink-lab#153
/// asks to pin, because `loss <p>% <corr>%` went quiet for a year without
/// anything noticing (#369). Deterministic models, so the counts are
/// exact: Gilbert-Elliot that never enters the bad state drops nothing;
/// one that loses everything in the good state drops every packet, and so
/// does a 4-state model with p13 = 100% (it never leaves "burst losses").
#[tokio::test]
async fn netem_loss_models_drop_what_they_describe() -> Result<()> {
    require_root!();
    nlink::require_modules!("sch_netem", "dummy");
    use nlink::Percent;

    let cases = [
        ("ge-never-bad", NetemLossModel::gilbert_elliot(Percent::ZERO), false),
        (
            "ge-lose-in-good",
            NetemLossModel::gilbert_elliot(Percent::ZERO).loss_in_good(Percent::HUNDRED),
            true,
        ),
        ("gi-always-burst", NetemLossModel::gilbert_intuitive(Percent::HUNDRED), true),
    ];
    for (name, model, drops_all) in cases {
        let ns = crate::common::TestNamespace::new(&format!("netem-drop-{name}"))?;
        let conn = ns.connection()?;
        conn.add_link(DummyLink::new("dummy0")).await?;
        conn.set_link_up("dummy0").await?;
        ns.add_addr("dummy0", "10.31.0.1/24")?;
        conn.add_qdisc("dummy0", NetemConfig::new().loss_model(model).build())
            .await?;

        // dummy is NOARP: every ping goes straight through the qdisc.
        ns.exec_ignore("ping", &["-c", "5", "-i", "0.2", "-W", "1", "10.31.0.2"]);

        let qdiscs = conn.get_qdiscs_by_name("dummy0").await?;
        let netem = qdiscs.iter().find(|q| q.kind() == Some("netem")).unwrap();
        let stats = netem.stats_queue().expect("netem reports queue stats");
        if drops_all {
            assert!(stats.drops >= 5, "{name}: dropped {} of 5 pings", stats.drops);
        } else {
            assert_eq!(stats.drops, 0, "{name}: must drop nothing, dropped {}", stats.drops);
        }
    }
    Ok(())
}

/// #370: replacing a netem with one that sets fewer attributes must clear
/// the rest. A replace is `netem_change()`, which keeps whatever it is not
/// sent; `rate`, `reorder` and `corrupt` used to survive this.
#[tokio::test]
async fn netem_replace_clears_what_the_new_config_does_not_set() -> Result<()> {
    require_root!();
    nlink::require_modules!("sch_netem");
    use nlink::Percent;

    let (_ns, conn) = setup_tc_ns("netem-replace-clears").await?;
    conn.add_qdisc(
        "dummy0",
        NetemConfig::new()
            .delay(Duration::from_millis(20))
            .jitter(Duration::from_millis(2))
            .delay_correlation(Percent::new(30.0))
            .rate(nlink::Rate::mbit(100))
            .loss(Percent::new(1.0))
            .loss_correlation(Percent::new(25.0))
            .duplicate(Percent::new(2.0))
            .duplicate_correlation(Percent::new(10.0))
            .corrupt(Percent::new(1.0))
            .corrupt_correlation(Percent::new(5.0))
            .reorder(Percent::new(3.0))
            .reorder_correlation(Percent::new(50.0))
            .gap(5)
            .build(),
    )
    .await?;
    let bare = NetemConfig::new().delay(Duration::from_millis(20)).build();
    conn.replace_qdisc("dummy0", bare).await?;

    let qdiscs = conn.get_qdiscs_by_name("dummy0").await?;
    let netem = qdiscs.iter().find(|q| q.kind() == Some("netem")).unwrap();
    let Some(QdiscOptions::Netem(o)) = netem.options() else {
        panic!("netem options did not parse");
    };
    let left: Vec<String> = [
        ("rate", o.rate_bps().unwrap_or(0) as f64),
        ("reorder", o.reorder().unwrap_or(0.0)),
        ("reorder correlation", o.reorder_correlation().unwrap_or(0.0)),
        ("corrupt", o.corrupt().unwrap_or(0.0)),
        ("corrupt correlation", o.corrupt_correlation().unwrap_or(0.0)),
        ("delay correlation", o.delay_correlation().unwrap_or(0.0)),
        ("loss correlation", o.loss_correlation().unwrap_or(0.0)),
        ("duplicate correlation", o.duplicate_correlation().unwrap_or(0.0)),
        ("loss", o.loss().unwrap_or(0.0)),
        ("duplicate", o.duplicate().unwrap_or(0.0)),
    ]
    .into_iter()
    .filter(|(_, v)| *v != 0.0)
    .map(|(k, v)| format!("{k}={v}"))
    .collect();
    assert!(left.is_empty(), "survived the replace: {left:?}");
    assert_eq!(o.jitter(), None);
    Ok(())
}

#[tokio::test]
async fn test_del_netem() -> Result<()> {
    require_root!();
    nlink::require_modules!("sch_netem");

    let (_ns, conn) = setup_tc_ns("netemrm").await?;

    // Add netem
    let netem = NetemConfig::new().delay(Duration::from_millis(50)).build();
    conn.add_qdisc("dummy0", netem).await?;

    // Remove it
    conn.del_netem("dummy0").await?;

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
    nlink::require_modules!("sch_htb");

    let (_ns, conn) = setup_tc_ns("htb").await?;

    // Add HTB qdisc
    let htb = HtbQdiscConfig::new().default_class(0x30).build();
    conn.add_qdisc_full("dummy0", TcHandle::ROOT, Some(TcHandle::major_only(1)), htb)
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
    nlink::require_modules!("sch_tbf");

    let (_ns, conn) = setup_tc_ns("tbf").await?;

    // Add TBF qdisc (token bucket filter)
    let tbf = TbfConfig::new()
        .rate(nlink::Rate::bytes_per_sec(1_000_000)) // 8 Mbps
        .burst(nlink::Bytes::new(10000))
        .limit(nlink::Bytes::new(100000))
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
    nlink::require_modules!("sch_fq_codel");

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
    nlink::require_modules!("sch_prio");

    let (_ns, conn) = setup_tc_ns("prio").await?;

    // Add prio qdisc
    let prio = PrioConfig::new().bands(3).build();
    conn.add_qdisc_full(
        "dummy0",
        TcHandle::ROOT,
        Some(TcHandle::major_only(1)),
        prio,
    )
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
    nlink::require_modules!("sch_sfq");

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
    nlink::require_modules!("sch_ingress");

    let (_ns, conn) = setup_tc_ns("ingress").await?;

    // Add ingress qdisc. The ingress qdisc is not a root qdisc — it must
    // attach to the special ingress parent (TC_H_INGRESS, ffff:fff1).
    // Adding it at the root parent makes the kernel return EOPNOTSUPP.
    conn.add_qdisc_full("dummy0", TcHandle::INGRESS, None, IngressConfig::new())
        .await?;

    // Verify
    let qdiscs = conn.get_qdiscs_by_name("dummy0").await?;
    let ingress = qdiscs.iter().find(|q| q.kind() == Some("ingress"));
    assert!(ingress.is_some(), "ingress qdisc should exist");

    Ok(())
}

#[tokio::test]
async fn test_delete_qdisc() -> Result<()> {
    require_root!();
    nlink::require_modules!("sch_htb");

    let (_ns, conn) = setup_tc_ns("qdiscdel").await?;

    // Add netem
    let netem = NetemConfig::new().delay(Duration::from_millis(10)).build();
    conn.add_qdisc("dummy0", netem).await?;

    // Delete it
    conn.del_qdisc("dummy0", TcHandle::ROOT).await?;

    // Verify
    let qdiscs = conn.get_qdiscs_by_name("dummy0").await?;
    assert!(!qdiscs.iter().any(|q| q.kind() == Some("netem")));

    Ok(())
}

#[tokio::test]
async fn test_replace_qdisc() -> Result<()> {
    require_root!();
    nlink::require_modules!("sch_htb", "sch_netem");

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
    nlink::require_modules!("sch_htb");

    let (_ns, conn) = setup_tc_ns("htbclass").await?;

    // Add HTB qdisc
    let htb = HtbQdiscConfig::new().default_class(0x30).build();
    conn.add_qdisc_full("dummy0", TcHandle::ROOT, Some(TcHandle::major_only(1)), htb)
        .await?;

    // Add class
    let class = HtbClassConfig::new(nlink::Rate::mbit(10))
        .ceil(nlink::Rate::mbit(800)) // 800 Mbps (was buggy 100_000_000 bytes/sec = 800 Mbps)
        .build();
    conn.add_class(
        "dummy0",
        TcHandle::major_only(1),
        TcHandle::new(1, 10),
        class,
    )
    .await?;

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
    nlink::require_modules!("sch_htb");

    let (_ns, conn) = setup_tc_ns("htbhier").await?;

    // Add HTB qdisc
    let htb = HtbQdiscConfig::new().default_class(0x30).build();
    conn.add_qdisc_full("dummy0", TcHandle::ROOT, Some(TcHandle::major_only(1)), htb)
        .await?;

    // Add root class
    let root_class = HtbClassConfig::new(nlink::Rate::mbit(100)).build();
    conn.add_class(
        "dummy0",
        TcHandle::major_only(1),
        TcHandle::new(1, 1),
        root_class,
    )
    .await?;

    // Add child classes
    let child1 = HtbClassConfig::new(nlink::Rate::mbit(50))
        .ceil(nlink::Rate::mbit(800))
        .build();
    conn.add_class("dummy0", TcHandle::new(1, 1), TcHandle::new(1, 10), child1)
        .await?;

    let child2 = HtbClassConfig::new(nlink::Rate::mbit(30))
        .ceil(nlink::Rate::mbit(800))
        .build();
    conn.add_class("dummy0", TcHandle::new(1, 1), TcHandle::new(1, 20), child2)
        .await?;

    // Verify
    let classes = conn.get_classes_by_name("dummy0").await?;
    assert!(classes.len() >= 3, "should have at least 3 classes");

    Ok(())
}

#[tokio::test]
async fn test_delete_class() -> Result<()> {
    require_root!();
    nlink::require_modules!("sch_htb");

    let (_ns, conn) = setup_tc_ns("classdel").await?;

    // Add HTB qdisc
    let htb = HtbQdiscConfig::new().default_class(0x30).build();
    conn.add_qdisc_full("dummy0", TcHandle::ROOT, Some(TcHandle::major_only(1)), htb)
        .await?;

    // Add class
    let class = HtbClassConfig::new(nlink::Rate::mbit(10)).build();
    conn.add_class(
        "dummy0",
        TcHandle::major_only(1),
        TcHandle::new(1, 10),
        class,
    )
    .await?;

    // Delete it
    conn.del_class("dummy0", TcHandle::major_only(1), TcHandle::new(1, 10))
        .await?;

    // Verify
    let classes = conn.get_classes_by_name("dummy0").await?;
    // Check that class 1:10 is gone
    assert!(!classes.iter().any(|c| c.handle() == TcHandle::new(1, 0x10)));

    Ok(())
}

// ============================================================================
// Filter Tests
// ============================================================================

#[tokio::test]
async fn test_add_matchall_filter() -> Result<()> {
    require_root!();
    nlink::require_modules!("sch_htb", "cls_matchall");

    let (_ns, conn) = setup_tc_ns("matchall").await?;

    // Add HTB qdisc first
    let htb = HtbQdiscConfig::new().default_class(0x30).build();
    conn.add_qdisc_full("dummy0", TcHandle::ROOT, Some(TcHandle::major_only(1)), htb)
        .await?;

    // Add class
    let class = HtbClassConfig::new(nlink::Rate::mbit(10)).build();
    conn.add_class(
        "dummy0",
        TcHandle::major_only(1),
        TcHandle::new(1, 10),
        class,
    )
    .await?;

    // Add matchall filter
    let filter = MatchallFilter::new()
        .classid(TcHandle::new(1, 0x10))
        .build();
    conn.add_filter("dummy0", TcHandle::major_only(1), filter)
        .await?;

    // Verify
    let filters = conn.get_filters_by_name("dummy0").await?;
    let matchall = filters.iter().find(|f| f.kind() == Some("matchall"));
    assert!(matchall.is_some(), "matchall filter should exist");

    Ok(())
}

#[tokio::test]
async fn test_add_u32_filter() -> Result<()> {
    require_root!();
    nlink::require_modules!("sch_htb", "cls_u32");

    let (_ns, conn) = setup_tc_ns("u32").await?;

    // Add HTB qdisc
    let htb = HtbQdiscConfig::new().default_class(0x30).build();
    conn.add_qdisc_full("dummy0", TcHandle::ROOT, Some(TcHandle::major_only(1)), htb)
        .await?;

    // Add class
    let class = HtbClassConfig::new(nlink::Rate::mbit(10)).build();
    conn.add_class(
        "dummy0",
        TcHandle::major_only(1),
        TcHandle::new(1, 10),
        class,
    )
    .await?;

    // Add u32 filter matching destination port 80
    let filter = U32Filter::new()
        .classid(TcHandle::new(1, 0x10))
        .match_dst_port(80)
        .build();
    conn.add_filter("dummy0", TcHandle::major_only(1), filter)
        .await?;

    // Verify
    let filters = conn.get_filters_by_name("dummy0").await?;
    let u32 = filters.iter().find(|f| f.kind() == Some("u32"));
    assert!(u32.is_some(), "u32 filter should exist");

    Ok(())
}

#[tokio::test]
async fn test_add_flower_filter() -> Result<()> {
    require_root!();
    nlink::require_modules!("sch_htb", "cls_flower");

    let (_ns, conn) = setup_tc_ns("flower").await?;

    // Add HTB qdisc
    let htb = HtbQdiscConfig::new().default_class(0x30).build();
    conn.add_qdisc_full("dummy0", TcHandle::ROOT, Some(TcHandle::major_only(1)), htb)
        .await?;

    // Add class
    let class = HtbClassConfig::new(nlink::Rate::mbit(10)).build();
    conn.add_class(
        "dummy0",
        TcHandle::major_only(1),
        TcHandle::new(1, 10),
        class,
    )
    .await?;

    // Add flower filter. `.ipv4()` is required, not decorative:
    // cls_flower silently drops ip_proto unless the request carries
    // TCA_FLOWER_KEY_ETH_TYPE, and would install this as a match-all
    // (#288).
    let filter = FlowerFilter::new()
        .classid(TcHandle::new(1, 0x10))
        .ipv4()
        .ip_proto_tcp()
        .build();
    conn.add_filter("dummy0", TcHandle::major_only(1), filter)
        .await?;

    // Verify
    let filters = conn.get_filters_by_name("dummy0").await?;
    let flower = filters.iter().find(|f| f.kind() == Some("flower"));
    assert!(flower.is_some(), "flower filter should exist");

    Ok(())
}

/// Regression test for the `tcm_info` protocol/priority packing bug
/// (see `TcMsg::with_filter_info`).
///
/// Adding a filter with an explicit ethernet protocol **and** a non-zero
/// priority must be accepted by the kernel. Before the fix, `tcm_info` packed
/// `(protocol << 16) | priority` (with no byte swap), so the kernel read the
/// two transposed and rejected the add with `EINVAL` — every filter add with
/// an explicit priority failed. A successful add is the regression guard:
/// verified to return `EINVAL` on the pre-fix code and `Ok` after.
///
/// The assertion is on the add, not a dump read-back: `get_filters` issues an
/// `RTM_GETTFILTER` dump with `tcm_ifindex = 0`, which returns nothing on
/// modern kernels (a separate nlink limitation), so a read-back here would be
/// flaky for reasons unrelated to this fix.
#[tokio::test]
async fn test_filter_add_explicit_protocol_priority() -> Result<()> {
    require_root!();
    nlink::require_modules!("sch_htb", "cls_matchall");

    let (_ns, conn) = setup_tc_ns("filterpp").await?;

    let htb = HtbQdiscConfig::new().default_class(0x30).build();
    conn.add_qdisc_full("dummy0", TcHandle::ROOT, Some(TcHandle::major_only(1)), htb)
        .await?;
    let class = HtbClassConfig::new(nlink::Rate::mbit(10)).build();
    conn.add_class("dummy0", TcHandle::major_only(1), TcHandle::new(1, 10), class)
        .await?;

    // Explicit IPv4 protocol + non-zero priority: the exact combination that
    // returned EINVAL before the tcm_info packing fix.
    const ETH_P_IP: u16 = 0x0800;
    let filter = MatchallFilter::new().classid(TcHandle::new(1, 0x10)).build();
    conn.add_filter_full("dummy0", TcHandle::major_only(1), None, ETH_P_IP, 200, filter)
        .await
        .expect("filter add with explicit protocol + priority must be accepted (pre-fix: EINVAL)");

    Ok(())
}

#[tokio::test]
async fn test_matchall_on_ingress() -> Result<()> {
    require_root!();
    nlink::require_modules!("sch_ingress", "cls_matchall");

    let (_ns, conn) = setup_tc_ns("matchinq").await?;

    // Add ingress qdisc at the special ingress parent (see
    // test_add_ingress_qdisc) — root-parent ingress is EOPNOTSUPP.
    conn.add_qdisc_full("dummy0", TcHandle::INGRESS, None, IngressConfig::new())
        .await?;

    // Add matchall filter on ingress (without actions - just classifying)
    let filter = MatchallFilter::new().build();
    conn.add_filter("dummy0", TcHandle::INGRESS, filter).await?;

    // Verify
    let filters = conn.get_filters_by_name("dummy0").await?;
    assert!(!filters.is_empty(), "filter should exist");

    Ok(())
}

#[tokio::test]
async fn test_matchall_goto_chain() -> Result<()> {
    require_root!();
    nlink::require_modules!("sch_htb", "cls_matchall");

    let (_ns, conn) = setup_tc_ns("gotoch").await?;

    // Add HTB qdisc
    let htb = HtbQdiscConfig::new().default_class(0x30).build();
    conn.add_qdisc_full("dummy0", TcHandle::ROOT, Some(TcHandle::major_only(1)), htb)
        .await?;

    // Add chain 10
    conn.add_tc_chain("dummy0", TcHandle::major_only(1), 10)
        .await?;

    // Add matchall filter with goto_chain
    let filter = MatchallFilter::new().goto_chain(10).build();
    conn.add_filter("dummy0", TcHandle::major_only(1), filter)
        .await?;

    // Verify
    let filters = conn.get_filters_by_name("dummy0").await?;
    assert!(!filters.is_empty(), "filter should exist");

    Ok(())
}

#[tokio::test]
async fn test_filter_on_ifb() -> Result<()> {
    require_root!();
    nlink::require_modules!("ifb", "sch_htb", "cls_matchall");

    let (_ns, conn) = setup_tc_ns("ifbfilt").await?;

    // Create IFB interface
    conn.add_link(IfbLink::new("ifb0")).await?;
    conn.set_link_up("ifb0").await?;

    // Add HTB qdisc on IFB
    let htb = HtbQdiscConfig::new().default_class(0x30).build();
    conn.add_qdisc_full("ifb0", TcHandle::ROOT, Some(TcHandle::major_only(1)), htb)
        .await?;

    // Add class
    let class = HtbClassConfig::new(nlink::Rate::mbit(10)).build();
    conn.add_class("ifb0", TcHandle::major_only(1), TcHandle::new(1, 10), class)
        .await?;

    // Add matchall filter
    let filter = MatchallFilter::new()
        .classid(TcHandle::new(1, 0x10))
        .build();
    conn.add_filter("ifb0", TcHandle::major_only(1), filter)
        .await?;

    // Verify
    let filters = conn.get_filters_by_name("ifb0").await?;
    assert!(!filters.is_empty(), "filter should exist");

    Ok(())
}

#[tokio::test]
async fn test_delete_filter() -> Result<()> {
    require_root!();
    nlink::require_modules!("sch_htb", "cls_matchall");

    let (_ns, conn) = setup_tc_ns("filterdel").await?;

    // Add HTB qdisc
    let htb = HtbQdiscConfig::new().default_class(0x30).build();
    conn.add_qdisc_full("dummy0", TcHandle::ROOT, Some(TcHandle::major_only(1)), htb)
        .await?;

    // Add class
    let class = HtbClassConfig::new(nlink::Rate::mbit(10)).build();
    conn.add_class(
        "dummy0",
        TcHandle::major_only(1),
        TcHandle::new(1, 10),
        class,
    )
    .await?;

    // Add filter
    let filter = MatchallFilter::new()
        .classid(TcHandle::new(1, 0x10))
        .build();
    conn.add_filter("dummy0", TcHandle::major_only(1), filter)
        .await?;

    // Flush filters
    conn.flush_filters("dummy0", TcHandle::major_only(1))
        .await?;

    // Verify
    let filters = conn.get_filters_by_name("dummy0").await?;
    assert!(filters.is_empty(), "filters should be deleted");

    Ok(())
}

#[tokio::test]
async fn test_replace_filter() -> Result<()> {
    require_root!();
    nlink::require_modules!("sch_htb", "cls_flower");

    let (_ns, conn) = setup_tc_ns("filterrep").await?;
    let ifindex = conn
        .get_link_by_name("dummy0")
        .await?
        .expect("dummy0 exists")
        .ifindex();

    // Add HTB qdisc
    let htb = HtbQdiscConfig::new().default_class(0x30).build();
    conn.add_qdisc_full("dummy0", TcHandle::ROOT, Some(TcHandle::major_only(1)), htb)
        .await?;

    // Add classes
    let class1 = HtbClassConfig::new(nlink::Rate::mbit(10)).build();
    conn.add_class(
        "dummy0",
        TcHandle::major_only(1),
        TcHandle::new(1, 10),
        class1,
    )
    .await?;

    let class2 = HtbClassConfig::new(nlink::Rate::mbit(20)).build();
    conn.add_class(
        "dummy0",
        TcHandle::major_only(1),
        TcHandle::new(1, 20),
        class2,
    )
    .await?;

    // Replace needs a filter kind that supports it, and a pinned
    // priority. Both matter, and neither was true before:
    //
    // 1. `cls_matchall` holds exactly one filter per `tcf_proto` and
    //    `mall_change` returns **EEXIST** when one already exists — it
    //    has no replace path at all. `tc(8)` fails the same way:
    //
    //      # tc filter replace dev d0 parent 1: protocol all pref 100 \
    //            matchall classid 1:20
    //      RTNETLINK answers: File exists
    //
    // 2. Replace identifies its target by (parent, protocol, priority,
    //    handle). Leave the priority unset and the kernel auto-assigns
    //    a different one, so you get a *second* filter — again matching
    //    `tc(8)`.
    //
    // This test used a matchall with no priority, so it was asserting
    // something the kernel cannot do. It could only ever have passed
    // while filter dumps returned nothing at all (#286) — and it had
    // never run anyway, being gated on `require_module!` (#273, #300).
    let prio = 200;
    conn.add_filter_full(
        "dummy0",
        TcHandle::major_only(1),
        Some(TcHandle::from_raw(1)),
        0x0800, // ETH_P_IP
        prio,
        FlowerFilter::new()
            .classid(TcHandle::new(1, 0x10))
            .dst_ipv4(std::net::Ipv4Addr::new(10, 0, 0, 1), 32)
            .build(),
    )
    .await?;

    conn.replace_filter_full(
        "dummy0",
        TcHandle::major_only(1),
        Some(TcHandle::from_raw(1)),
        0x0800,
        prio,
        FlowerFilter::new()
            .classid(TcHandle::new(1, 0x20))
            .dst_ipv4(std::net::Ipv4Addr::new(10, 0, 0, 2), 32)
            .build(),
    )
    .await?;

    // Replaced, not appended: still exactly one flower filter.
    let filters = conn
        .get_filters_by_parent_index(ifindex, TcHandle::major_only(1))
        .await?;
    let flower: Vec<_> = filters
        .iter()
        .filter(|f| f.kind() == Some("flower") && f.priority() == prio)
        .collect();
    assert_eq!(flower.len(), 1, "replace must not append a second filter");

    Ok(())
}

// ============================================================================
// Statistics Tests
// ============================================================================

#[tokio::test]
async fn test_qdisc_statistics() -> Result<()> {
    require_root!();
    nlink::require_modules!("sch_htb");

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
    nlink::require_modules!("sch_htb");

    let (_ns, conn) = setup_tc_ns("classstats").await?;

    // Add HTB qdisc and class
    let htb = HtbQdiscConfig::new().default_class(0x30).build();
    conn.add_qdisc_full("dummy0", TcHandle::ROOT, Some(TcHandle::major_only(1)), htb)
        .await?;

    let class = HtbClassConfig::new(nlink::Rate::mbit(10)).build();
    conn.add_class(
        "dummy0",
        TcHandle::major_only(1),
        TcHandle::new(1, 10),
        class,
    )
    .await?;

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
    nlink::require_modules!("sch_htb", "cls_matchall");

    let (_ns, conn) = setup_tc_ns("chain").await?;

    // Add HTB qdisc
    let htb = HtbQdiscConfig::new().default_class(0x30).build();
    conn.add_qdisc_full("dummy0", TcHandle::ROOT, Some(TcHandle::major_only(1)), htb)
        .await?;

    // Add a chain
    conn.add_tc_chain("dummy0", TcHandle::major_only(1), 10)
        .await?;

    // Get chains
    let chains = conn
        .get_tc_chains("dummy0", TcHandle::major_only(1))
        .await?;
    assert!(chains.contains(&10), "chain 10 should exist");

    Ok(())
}

#[tokio::test]
async fn test_delete_tc_chain() -> Result<()> {
    require_root!();
    nlink::require_modules!("sch_htb", "cls_matchall");

    let (_ns, conn) = setup_tc_ns("chaindel").await?;

    // Add HTB qdisc
    let htb = HtbQdiscConfig::new().default_class(0x30).build();
    conn.add_qdisc_full("dummy0", TcHandle::ROOT, Some(TcHandle::major_only(1)), htb)
        .await?;

    // Add and delete chain
    conn.add_tc_chain("dummy0", TcHandle::major_only(1), 20)
        .await?;
    conn.del_tc_chain("dummy0", TcHandle::major_only(1), 20)
        .await?;

    // Verify it's gone
    let chains = conn
        .get_tc_chains("dummy0", TcHandle::major_only(1))
        .await?;
    assert!(!chains.contains(&20), "chain 20 should be deleted");

    Ok(())
}

#[tokio::test]
async fn test_filter_with_chain() -> Result<()> {
    require_root!();
    nlink::require_modules!("sch_htb", "cls_matchall");

    let (_ns, conn) = setup_tc_ns("fchain").await?;

    // Add HTB qdisc
    let htb = HtbQdiscConfig::new().default_class(0x30).build();
    conn.add_qdisc_full("dummy0", TcHandle::ROOT, Some(TcHandle::major_only(1)), htb)
        .await?;

    // Add class
    let class = HtbClassConfig::new(nlink::Rate::mbit(10)).build();
    conn.add_class(
        "dummy0",
        TcHandle::major_only(1),
        TcHandle::new(1, 10),
        class,
    )
    .await?;

    // Add chain
    conn.add_tc_chain("dummy0", TcHandle::major_only(1), 5)
        .await?;

    // Add filter in chain 5
    let filter = MatchallFilter::new()
        .classid(TcHandle::new(1, 0x10))
        .chain(5)
        .build();
    conn.add_filter("dummy0", TcHandle::major_only(1), filter)
        .await?;

    // Verify filter is in chain
    let filters = conn.get_filters_by_name("dummy0").await?;
    // At least one filter should exist
    assert!(!filters.is_empty());

    Ok(())
}

// ============================================================================
// #424 — an exact SCTP port is a match, not a match-all
// ============================================================================

/// Send `count` SCTP packets from inside `ns` to `dst` on each of `ports`.
///
/// Through a raw IPv4 socket, so no `sctp` module is needed: the kernel
/// writes the IP header (protocol 132) and this writes the 12-byte SCTP
/// common header — source port, destination port, verification tag,
/// checksum. The flow dissector reads an SCTP packet's ports from its first
/// four bytes, as it does TCP's and UDP's, and nothing on the egress path
/// looks at the rest.
fn send_sctp(ns: &TestNamespace, dst: std::net::Ipv4Addr, ports: &[u16], count: usize) {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

    let name = ns.name().to_string();
    let ports = ports.to_vec();
    std::thread::spawn(move || {
        let _ns = nlink::netlink::namespace::enter(&name).expect("enter test netns");
        // SAFETY: socket(2) with constant arguments.
        let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_SCTP) };
        assert!(
            fd >= 0,
            "raw SCTP socket: {}",
            std::io::Error::last_os_error()
        );
        // SAFETY: `fd` was just returned by socket(2) and nothing else owns it.
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        let to = libc::sockaddr_in {
            sin_family: libc::AF_INET as libc::sa_family_t,
            sin_port: 0,
            sin_addr: libc::in_addr {
                s_addr: u32::from(dst).to_be(),
            },
            sin_zero: [0; 8],
        };
        for port in &ports {
            let mut header = [0u8; 12];
            header[..2].copy_from_slice(&40000u16.to_be_bytes());
            header[2..4].copy_from_slice(&port.to_be_bytes());
            for _ in 0..count {
                // SAFETY: `header` and `to` are live for the call and their
                // lengths are the ones passed.
                let sent = unsafe {
                    libc::sendto(
                        fd.as_raw_fd(),
                        header.as_ptr().cast(),
                        header.len(),
                        0,
                        (&to as *const libc::sockaddr_in).cast(),
                        std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
                    )
                };
                assert_eq!(
                    sent,
                    header.len() as isize,
                    "sendto: {}",
                    std::io::Error::last_os_error()
                );
            }
        }
    })
    .join()
    .expect("SCTP thread panicked");
}

/// A flower filter for one SCTP destination port classifies that port and
/// nothing else. `FlowerFilter` wrote an exact port only for TCP and UDP, so
/// an SCTP port filter installed as `ip_proto sctp` alone and claimed every
/// SCTP packet (#424).
///
/// The traffic leaves through a dummy device, so every packet is classified
/// by the HTB root and counted on the class it lands in.
#[tokio::test]
async fn flower_sctp_port_classifies_only_its_port() -> Result<()> {
    require_root!();
    nlink::require_modules!("dummy", "sch_htb", "cls_flower");
    use nlink::netlink::types::tc::filter::flower::TCA_FLOWER_KEY_SCTP_DST;

    let (ns, conn) = setup_tc_ns("flower-sctp").await?;
    ns.add_addr("dummy0", "10.42.0.1/24")?;

    let htb = HtbQdiscConfig::new().default_class(0x30).build();
    conn.add_qdisc_full("dummy0", TcHandle::ROOT, Some(TcHandle::major_only(1)), htb)
        .await?;
    for minor in [0x10, 0x30] {
        let class = HtbClassConfig::new(nlink::Rate::mbit(100)).build();
        conn.add_class(
            "dummy0",
            TcHandle::major_only(1),
            TcHandle::new(1, minor),
            class,
        )
        .await?;
    }
    let filter = FlowerFilter::new()
        .classid(TcHandle::new(1, 0x10))
        .ipv4()
        .ip_proto(132)
        .dst_port(5001)
        .build();
    conn.add_filter_full("dummy0", TcHandle::major_only(1), None, 0x0800, 1, filter)
        .await?;

    // The kernel holds the SCTP port key…
    let mut failures = Vec::new();
    let filters = conn.get_filters_by_name("dummy0").await?;
    let flower = filters
        .iter()
        .find(|f| f.kind() == Some("flower"))
        .expect("flower filter installed");
    let sctp_dst = nlink::netlink::AttrIter::new(flower.raw_options().unwrap_or_default())
        .find(|(ty, _)| *ty == TCA_FLOWER_KEY_SCTP_DST)
        .map(|(_, payload)| payload.to_vec());
    if sctp_dst != Some(5001u16.to_be_bytes().to_vec()) {
        failures.push(format!(
            "the installed filter's TCA_FLOWER_KEY_SCTP_DST is {sctp_dst:?}, want port 5001"
        ));
    }

    // …and classifies by it: port 5001 into 1:10, other SCTP ports and
    // UDP to the same port into the default class.
    const PER_PORT: usize = 5;
    let peer = std::net::Ipv4Addr::new(10, 42, 0, 2);
    send_sctp(&ns, peer, &[5001], PER_PORT);
    send_sctp(&ns, peer, &[5002, 80], PER_PORT);
    {
        let name = ns.name().to_string();
        std::thread::spawn(move || {
            let _ns = nlink::netlink::namespace::enter(&name).expect("enter test netns");
            let socket = std::net::UdpSocket::bind("0.0.0.0:0").expect("bind");
            for _ in 0..PER_PORT {
                socket.send_to(b"nlink", (peer, 5001)).expect("send");
            }
        })
        .join()
        .expect("UDP thread panicked");
    }

    let classes = conn.get_classes_by_name("dummy0").await?;
    let count = |minor: u16| {
        classes
            .iter()
            .find(|c| c.handle() == TcHandle::new(1, minor))
            .map(|c| c.packets())
    };
    let (port, default) = (count(0x10), count(0x30));
    let (want_port, want_default) = (PER_PORT as u64, 3 * PER_PORT as u64);
    if port != Some(want_port) || default != Some(want_default) {
        failures.push(format!(
            "port class 1:10 counted {port:?} packets (want {want_port}), default class 1:30 \
             counted {default:?} (want {want_default})"
        ));
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
    Ok(())
}

/// A flower filter for one VLAN id classifies that VLAN and nothing else.
/// `FlowerFilter` had no way to set a VLAN ethertype, and `cls_flower` reads
/// `vlan_id` only under one, so `.vlan_id(10)` installed a match-all (#431).
///
/// VLANs 10 and 20 sit on a dummy device with an HTB root; the filter is
/// installed for every protocol, so a match-all would claim VLAN 20 and the
/// untagged traffic too.
#[tokio::test]
async fn flower_vlan_id_classifies_only_its_vlan() -> Result<()> {
    require_root!();
    nlink::require_modules!("dummy", "8021q", "sch_htb", "cls_flower");
    use nlink::netlink::link::VlanLink;

    let (ns, conn) = setup_tc_ns("flower-vlan").await?;
    ns.add_addr("dummy0", "10.42.0.1/24")?;
    for (id, net) in [(10u16, "10.10.0.1/24"), (20, "10.20.0.1/24")] {
        let name = format!("dummy0.{id}");
        conn.add_link(VlanLink::new(&name, "dummy0", id)).await?;
        conn.set_link_up(name.as_str()).await?;
        ns.add_addr(&name, net)?;
    }

    let htb = HtbQdiscConfig::new().default_class(0x30).build();
    conn.add_qdisc_full("dummy0", TcHandle::ROOT, Some(TcHandle::major_only(1)), htb)
        .await?;
    for minor in [0x10, 0x30] {
        let class = HtbClassConfig::new(nlink::Rate::mbit(100)).build();
        conn.add_class(
            "dummy0",
            TcHandle::major_only(1),
            TcHandle::new(1, minor),
            class,
        )
        .await?;
    }
    let filter = FlowerFilter::new()
        .classid(TcHandle::new(1, 0x10))
        .vlan_id(10)
        .build();
    conn.add_filter_full("dummy0", TcHandle::major_only(1), None, 0x0003, 1, filter)
        .await?;

    const PER_TARGET: usize = 5;
    {
        let name = ns.name().to_string();
        std::thread::spawn(move || {
            let _ns = nlink::netlink::namespace::enter(&name).expect("enter test netns");
            let socket = std::net::UdpSocket::bind("0.0.0.0:0").expect("bind");
            for peer in ["10.10.0.2:9", "10.20.0.2:9", "10.42.0.2:9"] {
                for _ in 0..PER_TARGET {
                    socket.send_to(b"nlink", peer).expect("send");
                }
            }
        })
        .join()
        .expect("UDP thread panicked");
    }

    let classes = conn.get_classes_by_name("dummy0").await?;
    let count = |minor: u16| {
        classes
            .iter()
            .find(|c| c.handle() == TcHandle::new(1, minor))
            .map(|c| c.packets())
    };
    let (vlan, default) = (count(0x10), count(0x30));
    let (want_vlan, want_default) = (PER_TARGET as u64, 2 * PER_TARGET as u64);
    assert!(
        vlan == Some(want_vlan) && default == Some(want_default),
        "VLAN class 1:10 counted {vlan:?} packets (want {want_vlan}), default class 1:30 \
         counted {default:?} (want {want_default})"
    );
    Ok(())
}

// ============================================================================
// #433 — the flower ethertype comes from the filter's protocol
// ============================================================================

/// A flower filter installed under `protocol ip` with no ethertype of its own
/// takes the protocol as its TCA_FLOWER_KEY_ETH_TYPE, as tc(8) does. nlink
/// refused it ("needs an ethertype"), so `protocol ip flower ip_proto udp
/// dst_port 5001` — a standard tc(8) filter — could not be installed (#433).
///
/// All three explicit-protocol entry points are exercised: `add_filter_full`
/// puts UDP 5001 into 1:10, `replace_filter_full` puts UDP 5002 into 1:20,
/// and `change_filter_full` moves that filter to UDP 5003, which leaves 5002
/// to the default class.
#[tokio::test]
async fn flower_takes_its_ethertype_from_the_filter_protocol() -> Result<()> {
    require_root!();
    nlink::require_modules!("dummy", "sch_htb", "cls_flower");
    use nlink::netlink::types::tc::filter::flower::TCA_FLOWER_KEY_ETH_TYPE;

    let (ns, conn) = setup_tc_ns("flower-proto").await?;
    ns.add_addr("dummy0", "10.42.0.1/24")?;

    let htb = HtbQdiscConfig::new().default_class(0x30).build();
    conn.add_qdisc_full("dummy0", TcHandle::ROOT, Some(TcHandle::major_only(1)), htb)
        .await?;
    for minor in [0x10, 0x20, 0x30] {
        let class = HtbClassConfig::new(nlink::Rate::mbit(100)).build();
        conn.add_class(
            "dummy0",
            TcHandle::major_only(1),
            TcHandle::new(1, minor),
            class,
        )
        .await?;
    }
    let udp_port = |minor: u16, port: &str| {
        FlowerFilter::parse_params(&["classid", &format!("1:{minor:x}"), "ip_proto", "udp", "dst_port", port])
            .expect("parses")
    };
    conn.add_filter_full("dummy0", TcHandle::major_only(1), None, 0x0800, 1, udp_port(0x10, "5001"))
        .await?;
    conn.replace_filter_full("dummy0", TcHandle::major_only(1), None, 0x0800, 2, udp_port(0x20, "5002"))
        .await?;
    let handle = conn
        .get_filters_by_name("dummy0")
        .await?
        .iter()
        .find(|f| f.kind() == Some("flower") && f.priority() == 2 && f.handle_raw() != 0)
        .map(|f| f.handle())
        .expect("the replaced filter is installed");
    conn.change_filter_full("dummy0", TcHandle::major_only(1), Some(handle), 0x0800, 2, udp_port(0x20, "5003"))
        .await?;

    let mut failures = Vec::new();
    for f in conn.get_filters_by_name("dummy0").await? {
        if f.kind() != Some("flower") {
            continue;
        }
        let eth_type = nlink::netlink::AttrIter::new(f.raw_options().unwrap_or_default())
            .find(|(ty, _)| *ty == TCA_FLOWER_KEY_ETH_TYPE)
            .map(|(_, payload)| payload.to_vec());
        if eth_type != Some(0x0800u16.to_be_bytes().to_vec()) {
            failures.push(format!(
                "the flower filter at prio {} carries TCA_FLOWER_KEY_ETH_TYPE {eth_type:?}, want IPv4",
                f.priority()
            ));
        }
    }

    const PER_PORT: usize = 5;
    {
        let name = ns.name().to_string();
        std::thread::spawn(move || {
            let _ns = nlink::netlink::namespace::enter(&name).expect("enter test netns");
            let socket = std::net::UdpSocket::bind("0.0.0.0:0").expect("bind");
            for port in [5001, 5002, 5003] {
                for _ in 0..PER_PORT {
                    socket.send_to(b"nlink", ("10.42.0.2", port)).expect("send");
                }
            }
        })
        .join()
        .expect("UDP thread panicked");
    }

    let classes = conn.get_classes_by_name("dummy0").await?;
    let count = |minor: u16| {
        classes
            .iter()
            .find(|c| c.handle() == TcHandle::new(1, minor))
            .map(|c| c.packets())
    };
    let want = Some(PER_PORT as u64);
    for (minor, what) in [(0x10, "UDP 5001"), (0x20, "UDP 5003"), (0x30, "the default (UDP 5002)")] {
        if count(minor) != want {
            failures.push(format!(
                "class 1:{minor:x} for {what} counted {:?} packets, want {want:?}",
                count(minor)
            ));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
    Ok(())
}

/// A flower `vlan_id` filter under `protocol 802.1ad` classifies its 802.1AD
/// VLAN. `.vlan_id()` implied an 802.1Q ethertype even when the filter's
/// protocol named 802.1AD, so the filter asked for a TPID of 0x8100 on frames
/// the protocol had already restricted to 0x88a8, and matched nothing. tc(8)
/// takes the TPID from the protocol (#433). The kernel does not echo the
/// TPID, so only traffic shows the difference.
#[tokio::test]
async fn flower_vlan_id_under_802_1ad_classifies_its_vlan() -> Result<()> {
    require_root!();
    nlink::require_modules!("dummy", "8021q", "sch_htb", "cls_flower");
    use nlink::netlink::link::VlanLink;

    let (ns, conn) = setup_tc_ns("flower-qinq").await?;
    ns.add_addr("dummy0", "10.42.0.1/24")?;
    for (name, link, net) in [
        ("dummy0.10", VlanLink::new("dummy0.10", "dummy0", 10), "10.10.0.1/24"),
        ("dummy0.20", VlanLink::new("dummy0.20", "dummy0", 20).qinq(), "10.20.0.1/24"),
    ] {
        conn.add_link(link).await?;
        conn.set_link_up(name).await?;
        ns.add_addr(name, net)?;
    }

    let htb = HtbQdiscConfig::new().default_class(0x30).build();
    conn.add_qdisc_full("dummy0", TcHandle::ROOT, Some(TcHandle::major_only(1)), htb)
        .await?;
    for minor in [0x10, 0x30] {
        let class = HtbClassConfig::new(nlink::Rate::mbit(100)).build();
        conn.add_class(
            "dummy0",
            TcHandle::major_only(1),
            TcHandle::new(1, minor),
            class,
        )
        .await?;
    }
    // tc(8): `protocol 802.1ad flower vlan_id 20 classid 1:10`.
    let filter = FlowerFilter::parse_params(&["vlan_id", "20", "classid", "1:10"]).expect("parses");
    conn.add_filter_full("dummy0", TcHandle::major_only(1), None, 0x88A8, 1, filter)
        .await?;

    const PER_TARGET: usize = 5;
    {
        let name = ns.name().to_string();
        std::thread::spawn(move || {
            let _ns = nlink::netlink::namespace::enter(&name).expect("enter test netns");
            let socket = std::net::UdpSocket::bind("0.0.0.0:0").expect("bind");
            for peer in ["10.20.0.2:9", "10.10.0.2:9", "10.42.0.2:9"] {
                for _ in 0..PER_TARGET {
                    socket.send_to(b"nlink", peer).expect("send");
                }
            }
        })
        .join()
        .expect("UDP thread panicked");
    }

    let classes = conn.get_classes_by_name("dummy0").await?;
    let count = |minor: u16| {
        classes
            .iter()
            .find(|c| c.handle() == TcHandle::new(1, minor))
            .map(|c| c.packets())
    };
    let (vlan, default) = (count(0x10), count(0x30));
    let (want_vlan, want_default) = (PER_TARGET as u64, 2 * PER_TARGET as u64);
    assert!(
        vlan == Some(want_vlan) && default == Some(want_default),
        "802.1AD VLAN class 1:10 counted {vlan:?} packets (want {want_vlan}), default class 1:30 \
         counted {default:?} (want {want_default})"
    );
    Ok(())
}

// ============================================================================
// #450 — flower carries actions
// ============================================================================

/// A flower filter's actions run on its match, and only there: a
/// `dst_port 5001` filter with a drop drops UDP 5001, and UDP 5002 reaches
/// the default class. `FlowerFilter` could not carry actions (only
/// `goto_chain`), so tc(8)'s `flower … action drop` had no equivalent
/// (#450).
#[tokio::test]
async fn flower_actions_run_on_its_match() -> Result<()> {
    require_root!();
    nlink::require_modules!("dummy", "sch_htb", "cls_flower", "act_gact");
    use nlink::netlink::action::{ActionList, GactAction};

    let (ns, conn) = setup_tc_ns("flower-act").await?;
    ns.add_addr("dummy0", "10.42.0.1/24")?;

    let htb = HtbQdiscConfig::new().default_class(0x30).build();
    conn.add_qdisc_full("dummy0", TcHandle::ROOT, Some(TcHandle::major_only(1)), htb)
        .await?;
    let class = HtbClassConfig::new(nlink::Rate::mbit(100)).build();
    conn.add_class("dummy0", TcHandle::major_only(1), TcHandle::new(1, 0x30), class)
        .await?;
    let filter = FlowerFilter::new()
        .ipv4()
        .ip_proto_udp()
        .dst_port(5001)
        .actions(ActionList::new().with(GactAction::drop()))
        .build();
    conn.add_filter_full("dummy0", TcHandle::major_only(1), None, 0x0800, 1, filter)
        .await?;

    const PER_PORT: usize = 5;
    {
        let name = ns.name().to_string();
        std::thread::spawn(move || {
            let _ns = nlink::netlink::namespace::enter(&name).expect("enter test netns");
            let socket = std::net::UdpSocket::bind("0.0.0.0:0").expect("bind");
            for port in [5001, 5002] {
                for _ in 0..PER_PORT {
                    // A drop at the qdisc is not an error for UDP without
                    // IP_RECVERR, so every send succeeds.
                    socket.send_to(b"nlink", ("10.42.0.2", port)).expect("send");
                }
            }
        })
        .join()
        .expect("UDP thread panicked");
    }

    let qdiscs = conn.get_qdiscs_by_name("dummy0").await?;
    let drops = qdiscs
        .iter()
        .find(|q| q.kind() == Some("htb"))
        .map(|q| q.drops());
    let classes = conn.get_classes_by_name("dummy0").await?;
    let passed = classes
        .iter()
        .find(|c| c.handle() == TcHandle::new(1, 0x30))
        .map(|c| c.packets());
    let want = Some(PER_PORT as u64);
    assert!(
        drops.map(u64::from) == want && passed == want,
        "the HTB root dropped {drops:?} packets (want {want:?}: UDP 5001, by the flower drop) and \
         its default class passed {passed:?} (want {want:?}: UDP 5002)"
    );
    Ok(())
}
