//! Live-kernel verification of the nftables write statements: `meta mark
//! set`, `tcp option maxseg size set` (exthdr) and the set size.
//!
//! The unit tests pin the bytes nlink emits; these pin that the kernel
//! accepts them and echoes back the same expressions.

use std::net::Ipv4Addr;
use std::time::Duration;

use nlink::netlink::nftables::config::NftablesConfig;
use nlink::netlink::nftables::types::{
    Chain, ChainType, ExthdrOp, Family, Hook, MetaKey, Priority, Rule, Set, SetElement, SetKeyType,
    TCPOPT_MAXSEG, TcpFlags,
};
use nlink::netlink::nftables::{CmpOp, Expr, Register, RuleExpr};
use nlink::netlink::{Connection, Nftables, Route, namespace};

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
    let name = ns.name().to_string();
    std::thread::spawn(move || {
        let _ns = namespace::enter(&name).expect("enter test netns");
        let target = "127.0.0.1:9".parse().unwrap();
        let _ = std::net::TcpStream::connect_timeout(&target, Duration::from_secs(1));
    })
    .join()
    .expect("SYN thread panicked");
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

/// `tcp option maxseg size == <mss> counter`, as raw expressions — the
/// load form of `exthdr`, which no `Rule` helper emits.
fn count_mss(mss: u16) -> Rule {
    Rule::new("t", "post")
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
        conn.add_rule(count_mss(1360)).await?;

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
