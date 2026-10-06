//! Live-kernel verification of the nftables write statements: `meta mark
//! set`, `tcp option maxseg size set` (exthdr) and the set size.
//!
//! The unit tests pin the bytes nlink emits; these pin that the kernel
//! accepts them and echoes back the same expressions.

use std::net::Ipv4Addr;
use std::time::Duration;

use nlink::netlink::nftables::RuleExpr;
use nlink::netlink::nftables::config::NftablesConfig;
use nlink::netlink::nftables::types::{
    Chain, ChainType, ExthdrOp, Family, Hook, MetaKey, Priority, Rule, Set, SetElement, SetKeyType,
    TCP_FLAG_RST, TCP_FLAG_SYN, TCPOPT_MAXSEG,
};
use nlink::netlink::{Connection, Nftables, namespace};

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
                sreg: nlink::netlink::nftables::types::Register::R0,
            }),
            "kernel did not echo `meta mark set`: {exprs:?}",
        );
        Ok(())
    })
    .await
}

/// `tcp flags syn / syn,rst tcp option maxseg size > 1360 tcp option
/// maxseg size set 1360` installs and dumps back as exthdr load + set.
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
                .match_tcp_flags(TCP_FLAG_SYN, TCP_FLAG_SYN | TCP_FLAG_RST)
                .clamp_tcp_mss(1360),
        )
        .await?;

        let rules = conn.list_rules("t", Family::Ip).await?;
        let exprs = rules[0].expressions();
        let maxseg = |e: &RuleExpr| match e {
            RuleExpr::Exthdr {
                op,
                exthdr_type,
                offset,
                len,
                ..
            }
            | RuleExpr::ExthdrSet {
                op,
                exthdr_type,
                offset,
                len,
                ..
            } => {
                *op == ExthdrOp::TcpOpt
                    && *exthdr_type == TCPOPT_MAXSEG
                    && *offset == 2
                    && *len == 2
            }
            _ => false,
        };
        assert!(
            exprs
                .iter()
                .any(|e| matches!(e, RuleExpr::Exthdr { .. }) && maxseg(e)),
            "kernel did not echo the maxseg load: {exprs:?}",
        );
        assert!(
            exprs
                .iter()
                .any(|e| matches!(e, RuleExpr::ExthdrSet { .. }) && maxseg(e)),
            "kernel did not echo the maxseg set: {exprs:?}",
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
        assert!(full.is_err(), "a size(1) set accepted a second element");
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
                r.match_tcp_flags(TCP_FLAG_SYN, TCP_FLAG_SYN | TCP_FLAG_RST)
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
