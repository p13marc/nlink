//! Live-kernel verification of the nftables write statements: `meta mark
//! set` (plain and masked), `meta priority set`, `ct mark set` and the
//! connmark save/restore pair, `tcp option maxseg size set` (a constant or
//! the path MTU), and the set size.
//!
//! The unit tests pin the bytes nlink emits. These pin that the kernel
//! accepts them, echoes back the same expressions, and — sending real
//! packets through a netns and reading rule counters and TC class stats —
//! that the statements do to a packet what they claim to.

use std::net::Ipv4Addr;
use std::time::Duration;

use nlink::netlink::nftables::config::NftablesConfig;
use nlink::netlink::nftables::types::{
    Chain, ChainType, ExthdrOp, Family, Hook, MetaKey, Priority, Rule, Set, SetElement, SetKeyType,
    TCPOPT_MAXSEG, TcpFlags,
};
use nlink::netlink::nftables::{CmpOp, Expr, Register, RuleExpr};
use nlink::netlink::addr::Ipv4Address;
use nlink::netlink::filter::FwFilter;
use nlink::netlink::link::DummyLink;
use nlink::netlink::route::{Ipv4Route, RouteMetrics};
use nlink::netlink::tc::{HtbClassConfig, HtbQdiscConfig};
use nlink::netlink::{Connection, Nftables, Route, namespace};
use nlink::{Rate, TcHandle};

use crate::common::TestNamespace;

async fn with_timeout<F>(body: F) -> nlink::Result<()>
where
    F: std::future::Future<Output = nlink::Result<()>>,
{
    match tokio::time::timeout(Duration::from_secs(30), body).await {
        Ok(result) => result,
        Err(_elapsed) => Err(nlink::Error::Timeout),
    }
}

fn nft_in_ns(ns: &TestNamespace) -> nlink::Result<Connection<Nftables>> {
    namespace::connection_for(ns.name())
}

async fn add_mangle_chain(conn: &Connection<Nftables>, hook: Hook) -> nlink::Result<()> {
    conn.add_table("t", Family::Ip).await?;
    conn.add_chain(
        Chain::new("t", "c")?
            .family(Family::Ip)
            .hook(hook)
            .priority(Priority::Mangle)
            .chain_type(ChainType::Filter),
    )
    .await
}

/// Bring `lo` up inside `ns`, so locally generated traffic can flow.
async fn lo_up(ns: &TestNamespace) -> nlink::Result<()> {
    let route: Connection<Route> = namespace::connection_for(ns.name())?;
    let lo = route
        .get_link_by_name("lo")
        .await?
        .expect("every netns has a loopback device");
    route.set_link_up_by_index(lo.ifindex()).await
}

/// Send one TCP SYN from inside `ns` to 127.0.0.1:9. Nothing listens, so
/// the answer is a RST — by then the SYN has crossed `output` and
/// `postrouting`, which is all these tests need.
///
/// Entering a netns affects the whole thread, so this runs on a thread of
/// its own that exits afterwards instead of restoring.
fn send_syn(ns: &TestNamespace) {
    send_syn_to(ns, "127.0.0.1:9", Duration::from_secs(1));
}

/// Send one TCP SYN from inside `ns` to `target`, giving up after
/// `timeout` (an off-link target never answers; the SYN is out by then).
fn send_syn_to(ns: &TestNamespace, target: &str, timeout: Duration) {
    let name = ns.name().to_string();
    let target = target.parse().unwrap();
    std::thread::spawn(move || {
        let _ns = namespace::enter(&name).expect("enter test netns");
        let _ = std::net::TcpStream::connect_timeout(&target, timeout);
    })
    .join()
    .expect("SYN thread panicked");
}

/// Send `count` UDP datagrams from inside `ns` to `target`.
fn send_udp(ns: &TestNamespace, target: &str, count: usize) {
    let name = ns.name().to_string();
    let target: std::net::SocketAddr = target.parse().unwrap();
    std::thread::spawn(move || {
        let _ns = namespace::enter(&name).expect("enter test netns");
        let socket = std::net::UdpSocket::bind("0.0.0.0:0").expect("bind");
        for _ in 0..count {
            socket.send_to(b"nlink", target).expect("send");
        }
    })
    .join()
    .expect("UDP thread panicked");
}

/// A `dummy0` inside `ns`, up, with 10.98.0.1/24 — an egress device with
/// no peer: what leaves through it is counted and dropped.
async fn add_dummy(ns: &TestNamespace) -> nlink::Result<Connection<Route>> {
    let route = ns.connection()?;
    route.add_link(DummyLink::new("dummy0")).await?;
    route.set_link_up("dummy0").await?;
    route
        .add_address(Ipv4Address::new("dummy0", Ipv4Addr::new(10, 98, 0, 1), 24))
        .await?;
    Ok(route)
}

/// Packets counted by the `index`-th rule of `chain` (declaration order).
async fn rule_packets(
    conn: &Connection<Nftables>,
    chain: &str,
    index: usize,
) -> nlink::Result<u64> {
    let rules = conn.list_rules("t", Family::Ip).await?;
    let rule = rules
        .iter()
        .filter(|r| r.chain == chain)
        .nth(index)
        .unwrap_or_else(|| panic!("no rule #{index} in chain {chain}"));
    Ok(rule.counter().expect("rule has a counter").0)
}

/// An `output` and a `postrouting` mangle chain in table `ip t`.
async fn add_output_and_postrouting(conn: &Connection<Nftables>) -> nlink::Result<()> {
    conn.add_table("t", Family::Ip).await?;
    for (name, hook) in [("out", Hook::Output), ("post", Hook::Postrouting)] {
        conn.add_chain(
            Chain::new("t", name)?
                .family(Family::Ip)
                .hook(hook)
                .priority(Priority::Mangle)
                .chain_type(ChainType::Filter),
        )
        .await?;
    }
    Ok(())
}

/// [`add_dummy`] plus an HTB tree on `dummy0`: root `1:`, parent class
/// `1:1`, leaves `1:10` and `1:20`, default `1:20`.
async fn add_dummy_with_htb(ns: &TestNamespace) -> nlink::Result<Connection<Route>> {
    let route = add_dummy(ns).await?;
    route
        .add_qdisc_full(
            "dummy0",
            TcHandle::ROOT,
            Some(TcHandle::major_only(1)),
            HtbQdiscConfig::new().default_class(0x20).build(),
        )
        .await?;
    route
        .add_class(
            "dummy0",
            TcHandle::major_only(1),
            TcHandle::new(1, 1),
            HtbClassConfig::new(Rate::mbit(100)).build(),
        )
        .await?;
    for minor in [0x10, 0x20] {
        route
            .add_class(
                "dummy0",
                TcHandle::new(1, 1),
                TcHandle::new(1, minor),
                HtbClassConfig::new(Rate::mbit(10))
                    .ceil(Rate::mbit(100))
                    .build(),
            )
            .await?;
    }
    Ok(route)
}

/// Packets HTB class `class` on `dummy0` has sent.
async fn class_packets(route: &Connection<Route>, class: TcHandle) -> nlink::Result<u64> {
    let classes = route.get_classes_by_name("dummy0").await?;
    Ok(classes
        .iter()
        .find(|c| c.handle() == class)
        .unwrap_or_else(|| panic!("class {class} exists"))
        .packets())
}

/// `tcp option maxseg size == <mss> counter` in `chain`, as raw
/// expressions — the load form of `exthdr`, which no `Rule` helper emits.
fn count_mss(chain: &str, mss: u16) -> Rule {
    Rule::new("t", chain)
        .family(Family::Ip)
        .expressions(vec![
            Expr::Meta {
                dreg: Register::R0,
                key: MetaKey::L4Proto,
            },
            Expr::Cmp {
                sreg: Register::R0,
                op: CmpOp::Eq,
                data: vec![6],
            },
            Expr::Exthdr {
                dreg: Register::R0,
                op: ExthdrOp::TcpOpt,
                exthdr_type: TCPOPT_MAXSEG,
                offset: 2,
                len: 2,
            },
            Expr::Cmp {
                sreg: Register::R0,
                op: CmpOp::Eq,
                data: mss.to_be_bytes().to_vec(),
            },
        ])
        .counter()
}

/// `ip daddr @s meta mark set 1` installs, and dumps back as a meta *set*
/// (source register), not a meta load.
#[tokio::test]
async fn meta_mark_set_round_trips_through_the_kernel() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("nf_tables");

    let ns = TestNamespace::new("nft-markset")?;
    let conn = nft_in_ns(&ns)?;

    with_timeout(async {
        add_mangle_chain(&conn, Hook::Postrouting).await?;
        conn.add_set(
            Set::new("t", "s")
                .family(Family::Ip)
                .key_type(SetKeyType::Ipv4Addr),
        )
        .await?;
        conn.add_rule(
            Rule::new("t", "c")
                .family(Family::Ip)
                .match_daddr_in_set("s")
                .set_mark(1),
        )
        .await?;

        let rules = conn.list_rules("t", Family::Ip).await?;
        let exprs = rules[0].expressions();
        assert!(
            exprs.contains(&RuleExpr::MetaSet {
                key: MetaKey::Mark,
                sreg: Register::R0,
            }),
            "kernel did not echo `meta mark set`: {exprs:?}",
        );
        Ok(())
    })
    .await
}

/// `tcp flags syn / syn,rst tcp option maxseg size set 1360` installs and
/// dumps back as exactly what was sent: immediate + exthdr write.
#[tokio::test]
async fn tcp_mss_clamp_round_trips_through_the_kernel() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("nf_tables");

    let ns = TestNamespace::new("nft-mss")?;
    let conn = nft_in_ns(&ns)?;

    with_timeout(async {
        add_mangle_chain(&conn, Hook::Forward).await?;
        conn.add_rule(
            Rule::new("t", "c")
                .family(Family::Ip)
                .match_tcp_flags(TcpFlags::SYN, TcpFlags::SYN | TcpFlags::RST)
                .clamp_tcp_mss(1360),
        )
        .await?;

        let rules = conn.list_rules("t", Family::Ip).await?;
        let exprs = rules[0].expressions();
        assert_eq!(
            exprs[exprs.len() - 2..],
            [
                RuleExpr::Immediate {
                    dreg: Register::R0,
                    data: 1360u16.to_be_bytes().to_vec(),
                },
                RuleExpr::ExthdrSet {
                    sreg: Register::R0,
                    op: ExthdrOp::TcpOpt,
                    exthdr_type: TCPOPT_MAXSEG,
                    offset: 2,
                    len: 2,
                },
            ],
            "kernel did not echo the maxseg write: {exprs:?}",
        );
        Ok(())
    })
    .await
}

/// What the clamp does to a real SYN. The loopback SYN carries MSS 65495.
///
/// Clamping to 1360 lowers it; a second clamp to 65535 must not raise it
/// back (the kernel never increases an MSS), and must not end the rule
/// either — its trailing counter still sees the packet. A clamp built as
/// load + `cmp >` + write would skip that counter.
#[tokio::test]
async fn tcp_mss_clamp_lowers_a_syn_and_never_raises_it() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("nf_tables");

    let ns = TestNamespace::new("nft-mss-live")?;
    let conn = nft_in_ns(&ns)?;

    with_timeout(async {
        lo_up(&ns).await?;
        add_output_and_postrouting(&conn).await?;
        let syn = || {
            Rule::new("t", "out")
                .family(Family::Ip)
                .match_tcp_flags(TcpFlags::SYN, TcpFlags::SYN | TcpFlags::RST)
        };
        conn.add_rule(syn().clamp_tcp_mss(1360).counter()).await?;
        conn.add_rule(syn().clamp_tcp_mss(u16::MAX).counter())
            .await?;
        conn.add_rule(count_mss("post", 1360)).await?;

        send_syn(&ns);

        assert!(
            rule_packets(&conn, "out", 0).await? >= 1,
            "clamp to 1360 never saw the SYN"
        );
        assert!(
            rule_packets(&conn, "out", 1).await? >= 1,
            "a clamp that does not lower the MSS ended rule evaluation",
        );
        assert!(
            rule_packets(&conn, "post", 0).await? >= 1,
            "the SYN left with an MSS other than 1360",
        );
        Ok(())
    })
    .await
}

/// `meta mark set` marks the packet: a postrouting `meta mark` match sees it.
#[tokio::test]
async fn meta_mark_set_marks_the_packet() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("nf_tables");

    let ns = TestNamespace::new("nft-mark-live")?;
    let conn = nft_in_ns(&ns)?;

    with_timeout(async {
        lo_up(&ns).await?;
        add_output_and_postrouting(&conn).await?;
        conn.add_rule(
            Rule::new("t", "out")
                .family(Family::Ip)
                .match_tcp_dport(9)
                .set_mark(0x10),
        )
        .await?;
        conn.add_rule(
            Rule::new("t", "post")
                .family(Family::Ip)
                .match_mark(0x10)
                .counter(),
        )
        .await?;

        send_syn(&ns);

        assert!(
            rule_packets(&conn, "post", 0).await? >= 1,
            "no packet left with mark 0x10",
        );
        Ok(())
    })
    .await
}

/// A set created with `size(1)` refuses its second element.
#[tokio::test]
async fn set_size_is_enforced_by_the_kernel() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("nf_tables");

    let ns = TestNamespace::new("nft-setsize")?;
    let conn = nft_in_ns(&ns)?;

    with_timeout(async {
        conn.add_table("t", Family::Ip).await?;
        conn.add_set(
            Set::new("t", "s")
                .family(Family::Ip)
                .key_type(SetKeyType::Ipv4Addr)
                .size(1),
        )
        .await?;
        conn.add_set_elements(
            "t",
            "s",
            Family::Ip,
            &[SetElement::ipv4(Ipv4Addr::new(10, 0, 0, 1))],
        )
        .await?;
        let full = conn
            .add_set_elements(
                "t",
                "s",
                Family::Ip,
                &[SetElement::ipv4(Ipv4Addr::new(10, 0, 0, 2))],
            )
            .await;
        let err = full.expect_err("a size(1) set accepted a second element");
        assert_eq!(
            err.errno(),
            Some(libc::ENFILE),
            "a full set is ENFILE, got {err}"
        );
        Ok(())
    })
    .await
}

/// A declared MSS clamp + mark rule must not show up as changed on every
/// reconcile: the kernel dumps `NFTA_EXTHDR_FLAGS` for the exthdr set form
/// although it rejects it in the request.
#[tokio::test]
async fn reconcile_statements_are_idempotent() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("nf_tables");

    let ns = TestNamespace::new("nft-stmt-rec")?;
    let conn = nft_in_ns(&ns)?;

    with_timeout(async {
        let cfg = NftablesConfig::new().table("mangle", Family::Ip, |t| {
            t.chain("forward", |c| {
                c.hook(Hook::Forward)
                    .priority(Priority::Mangle)
                    .chain_type(ChainType::Filter)
            })
            .rule_keyed("forward", "mss", |r| {
                r.match_tcp_flags(TcpFlags::SYN, TcpFlags::SYN | TcpFlags::RST)
                    .clamp_tcp_mss(1360)
            })
            .rule_keyed("forward", "mark", |r| r.match_tcp_dport(80).set_mark(1))
        });

        cfg.diff(&conn).await?.apply(&conn).await?;
        let again = cfg.diff(&conn).await?;
        assert!(again.is_empty(), "second diff must be empty: {again}");
        Ok(())
    })
    .await
}

/// `set_mark_masked` sets the bits under the mask and keeps the others;
/// `match_mark_masked` sees only the bits under the mask.
#[tokio::test]
async fn masked_mark_set_keeps_the_foreign_bits() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("nf_tables");

    let ns = TestNamespace::new("nft-xmark-live")?;
    let conn = nft_in_ns(&ns)?;

    with_timeout(async {
        lo_up(&ns).await?;
        add_output_and_postrouting(&conn).await?;
        let out = || Rule::new("t", "out").family(Family::Ip).match_tcp_dport(9);
        // Someone else's bits first, then ours under 0xff.
        conn.add_rule(out().set_mark(0xff00_0000)).await?;
        conn.add_rule(out().set_mark_masked(0x1234, 0xff)).await?;
        let post = || Rule::new("t", "post").family(Family::Ip);
        conn.add_rule(post().match_mark(0xff00_0034).counter()).await?;
        conn.add_rule(post().match_mark_masked(0x34, 0xff).counter())
            .await?;

        send_syn(&ns);

        assert!(
            rule_packets(&conn, "post", 0).await? >= 1,
            "the mark is not 0xff000034: the foreign bits were lost or ours not set",
        );
        assert!(
            rule_packets(&conn, "post", 1).await? >= 1,
            "match_mark_masked(0x34, 0xff) missed mark 0xff000034",
        );
        Ok(())
    })
    .await
}

/// `ct mark set mark` saves the packet mark on the connection, and
/// `meta mark set ct mark` restores a connection mark onto the packet.
#[tokio::test]
async fn connmark_save_and_restore_carry_the_mark() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("nf_tables", "nft_ct");

    with_timeout(async {
        // Save: packet mark -> conntrack mark.
        let ns = TestNamespace::new("nft-ctsave")?;
        let conn = nft_in_ns(&ns)?;
        lo_up(&ns).await?;
        add_output_and_postrouting(&conn).await?;
        conn.add_rule(
            Rule::new("t", "out")
                .family(Family::Ip)
                .match_tcp_dport(9)
                .set_mark(0x20)
                .save_mark_to_ct(),
        )
        .await?;
        conn.add_rule(
            Rule::new("t", "post")
                .family(Family::Ip)
                .match_ct_mark(0x20)
                .counter(),
        )
        .await?;
        send_syn(&ns);
        assert!(
            rule_packets(&conn, "post", 0).await? >= 1,
            "the connection did not carry the saved mark 0x20",
        );

        // Restore: conntrack mark -> packet mark.
        let ns = TestNamespace::new("nft-ctrestore")?;
        let conn = nft_in_ns(&ns)?;
        lo_up(&ns).await?;
        add_output_and_postrouting(&conn).await?;
        let out = || Rule::new("t", "out").family(Family::Ip).match_tcp_dport(9);
        conn.add_rule(out().set_ct_mark(0x30)).await?;
        conn.add_rule(out().restore_mark_from_ct()).await?;
        conn.add_rule(
            Rule::new("t", "post")
                .family(Family::Ip)
                .match_mark(0x30)
                .counter(),
        )
        .await?;
        send_syn(&ns);
        assert!(
            rule_packets(&conn, "post", 0).await? >= 1,
            "the packet did not get the connection's mark 0x30",
        );
        Ok(())
    })
    .await
}

/// `meta priority set 1:10` puts packets in HTB leaf class 1:10 with no
/// `tc` filter: without it they would go to the default class 1:20.
#[tokio::test]
async fn meta_priority_set_classifies_into_an_htb_class() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("nf_tables", "sch_htb");

    let ns = TestNamespace::new("nft-prio-htb")?;
    let conn = nft_in_ns(&ns)?;

    with_timeout(async {
        let route = add_dummy_with_htb(&ns).await?;
        add_output_and_postrouting(&conn).await?;
        conn.add_rule(
            Rule::new("t", "out")
                .family(Family::Ip)
                .match_daddr_v4(Ipv4Addr::new(10, 98, 0, 3), 32)
                .set_priority(TcHandle::new(1, 0x10)),
        )
        .await?;

        send_udp(&ns, "10.98.0.3:9", 5);

        let sent = class_packets(&route, TcHandle::new(1, 0x10)).await?;
        assert!(
            sent >= 5,
            "class 1:10 saw {sent} packets, not the 5 priority-1:10 datagrams",
        );
        Ok(())
    })
    .await
}

/// A masked mark set by nftables, matched by a `tc` `fw` filter with the
/// same mask, lands in the filter's class — the recipe's Option 2.
#[tokio::test]
async fn masked_mark_classifies_through_a_fw_filter() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("nf_tables", "sch_htb", "cls_fw");

    let ns = TestNamespace::new("nft-fw-htb")?;
    let conn = nft_in_ns(&ns)?;

    with_timeout(async {
        let route = add_dummy_with_htb(&ns).await?;
        // tc filter add dev dummy0 parent 1: handle 0x10/0xff fw classid 1:10
        route
            .add_filter_full(
                "dummy0",
                TcHandle::major_only(1),
                Some(TcHandle::from(0x10u32)),
                0x0003, // ETH_P_ALL
                100,
                FwFilter::new()
                    .mask(0xff)
                    .classid(TcHandle::new(1, 0x10))
                    .build(),
            )
            .await?;

        add_output_and_postrouting(&conn).await?;
        let to_target = || {
            Rule::new("t", "post")
                .family(Family::Ip)
                .match_daddr_v4(Ipv4Addr::new(10, 98, 0, 3), 32)
        };
        // Foreign bits above ours: only the masked byte decides the class.
        conn.add_rule(to_target().set_mark(0xab00_0000)).await?;
        conn.add_rule(to_target().set_mark_masked(0x10, 0xff)).await?;

        send_udp(&ns, "10.98.0.3:9", 5);

        let sent = class_packets(&route, TcHandle::new(1, 0x10)).await?;
        assert!(
            sent >= 5,
            "class 1:10 saw {sent} packets: mark 0xab000010 did not reach it through fw 0x10/0xff",
        );
        Ok(())
    })
    .await
}

/// `tcp option maxseg size set rt mtu`. The route to 10.98.0.2 has MTU
/// 1400 but advertises MSS 1460, so the SYN leaves `output` claiming more
/// than the path carries; the clamp brings it to 1400 - 40 = 1360.
#[tokio::test]
async fn tcp_mss_clamp_to_pmtu_uses_the_route_mtu() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("nf_tables");

    let ns = TestNamespace::new("nft-pmtu-live")?;
    let conn = nft_in_ns(&ns)?;

    with_timeout(async {
        let route = add_dummy(&ns).await?;
        route
            .add_route(
                Ipv4Route::new("10.98.0.2", 32)
                    .dev("dummy0")
                    .metrics(RouteMetrics::new().mtu(1400).advmss(1460)),
            )
            .await?;

        add_output_and_postrouting(&conn).await?;
        // Before the clamp: the SYN really does claim 1460.
        conn.add_rule(count_mss("out", 1460)).await?;
        conn.add_rule(
            Rule::new("t", "out")
                .family(Family::Ip)
                .match_tcp_flags(TcpFlags::SYN, TcpFlags::SYN | TcpFlags::RST)
                .clamp_tcp_mss_to_pmtu(),
        )
        .await?;
        conn.add_rule(count_mss("post", 1360)).await?;

        send_syn_to(&ns, "10.98.0.2:9", Duration::from_millis(300));

        assert!(
            rule_packets(&conn, "out", 0).await? >= 1,
            "the SYN did not advertise 1460 — the test setup is not what it claims",
        );
        assert!(
            rule_packets(&conn, "post", 0).await? >= 1,
            "the SYN was not clamped to the path MSS 1360",
        );
        Ok(())
    })
    .await
}

/// A throttle config the way a UPF would declare it: a bounded set of
/// addresses and a rule marking traffic to them.
fn throttle_cfg(size: u32, addrs: &[Ipv4Addr]) -> NftablesConfig {
    let addrs = addrs.to_vec();
    NftablesConfig::new().table("t", Family::Ip, move |t| {
        t.set("throttled", move |mut s| {
            s = s.key_type(SetKeyType::Ipv4Addr).size(size);
            for a in addrs {
                s = s.ipv4(a);
            }
            s
        })
        .chain("post", |c| {
            c.hook(Hook::Postrouting)
                .priority(Priority::Mangle)
                .chain_type(ChainType::Filter)
        })
        .rule_keyed("post", "throttle", |r| {
            r.match_daddr_in_set("throttled")
                .set_mark_masked(0x10, 0xff)
                .counter()
        })
    })
}

fn addrs(n: u8) -> Vec<Ipv4Addr> {
    (1..=n).map(|i| Ipv4Addr::new(10, 45, 0, i)).collect()
}

/// A declared set size reaches the kernel, reads back, and reconciles to
/// an empty diff.
#[tokio::test]
async fn declared_set_size_applies_and_reconciles() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("nf_tables");

    let ns = TestNamespace::new("nft-dsize")?;
    let conn = nft_in_ns(&ns)?;

    with_timeout(async {
        let cfg = throttle_cfg(2, &addrs(2));
        cfg.diff(&conn).await?.apply(&conn).await?;

        let sets = conn.list_sets_in("t", Family::Ip).await?;
        assert_eq!(sets[0].size, Some(2), "SetInfo::size reads the kernel's size");

        let again = cfg.diff(&conn).await?;
        assert!(again.is_empty(), "second diff must be empty: {again}");
        Ok(())
    })
    .await
}

/// Growing a declared set's size is applied in place — the set keeps its
/// elements and the rule bound to it keeps its handle — and the elements
/// the larger size admits go in during the same apply.
///
/// The kernel checks element adds against the size a set has *before*
/// the commit, so this only works because the resize is committed first;
/// in one batch the two new elements would be ENFILE.
#[tokio::test]
async fn declared_set_resize_is_in_place_and_admits_new_elements() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("nf_tables");

    let ns = TestNamespace::new("nft-dresize")?;
    let conn = nft_in_ns(&ns)?;

    with_timeout(async {
        throttle_cfg(2, &addrs(2))
            .diff(&conn)
            .await?
            .apply(&conn)
            .await?;
        let handle_before = conn.list_rules("t", Family::Ip).await?[0].handle;

        let grown = throttle_cfg(4, &addrs(4));
        let diff = grown.diff(&conn).await?;
        assert_eq!(diff.sets_to_resize.len(), 1, "{diff}");
        assert!(
            diff.sets_to_delete.is_empty() && diff.sets_to_add.is_empty(),
            "a size change must not recreate the set: {diff}"
        );
        diff.apply(&conn).await?;

        let sets = conn.list_sets_in("t", Family::Ip).await?;
        assert_eq!(sets[0].size, Some(4));
        assert_eq!(
            conn.list_set_elements("t", "throttled", Family::Ip)
                .await?
                .len(),
            4
        );
        assert_eq!(
            conn.list_rules("t", Family::Ip).await?[0].handle,
            handle_before,
            "the rule bound to the set was replaced",
        );

        let again = grown.diff(&conn).await?;
        assert!(again.is_empty(), "the resize must converge: {again}");
        Ok(())
    })
    .await
}
