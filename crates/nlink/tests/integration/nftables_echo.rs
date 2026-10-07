//! Every rule shape nlink can write must reconcile to an empty diff.
//!
//! The declarative diff byte-compares a declared rule against the kernel's
//! echo of it (after `normalize_tlv`, which reorders but cannot add). So
//! every attribute the kernel always dumps has to be in what nlink writes,
//! and nothing the kernel drops may be. A writer that gets this wrong
//! installs fine and then has its rule replaced on every apply, forever —
//! visible only to a second `diff()`.
//!
//! `reconcile_idempotent_reapply_yields_empty_diff` only ever declared
//! `match_tcp_dport` rules, so the masquerade nest (#362) and the lookup /
//! limit / log / reject writers were never in an `is_empty()` assertion.
//! This file declares one keyed rule per `Rule` helper and `Expr` writer
//! arm instead.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use nlink::netlink::nftables::config::NftablesConfig;
use nlink::netlink::nftables::types::{
    ChainName, ChainType, CtState, Family, Hook, LimitUnit, Priority, SetKeyType, TcpFlags,
};
use nlink::netlink::nftables::{Expr, NFT_REJECT_TCP_RST, Verdict};
use nlink::netlink::{Connection, Nftables, namespace};
use nlink::TcHandle;

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

/// Apply `cfg`, then assert the next two diffs are empty.
async fn assert_reconciles(conn: &Connection<Nftables>, cfg: &NftablesConfig) -> nlink::Result<()> {
    cfg.diff(conn).await?.apply(conn).await?;
    let again = cfg.diff(conn).await?;
    assert!(
        again.is_empty(),
        "every rule below was written by nlink and echoed by the kernel \
         unchanged, so the second diff must be empty. Rules it lists are \
         ones whose writer disagrees with the kernel's dump: {again}"
    );
    // A third diff after the (no-op) apply of the second, in case apply
    // itself perturbs a rule.
    again.apply(conn).await?;
    let third = cfg.diff(conn).await?;
    assert!(third.is_empty(), "third diff must be empty too: {third}");
    Ok(())
}

/// Matchers, verdicts and statements in a filter chain.
#[tokio::test]
async fn every_filter_rule_shape_reconciles() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("nf_tables", "nft_limit", "nft_log", "nft_reject_inet", "nft_ct");

    let ns = TestNamespace::new("nft-echo-filter")?;
    let conn = nft_in_ns(&ns)?;

    let v4: Ipv4Addr = "192.0.2.0".parse().unwrap();
    let v6: Ipv6Addr = "2001:db8::".parse().unwrap();

    with_timeout(async {
        let cfg = NftablesConfig::new().table("shapes", Family::Inet, |t| {
            t.chain("input", |c| {
                c.hook(Hook::Input)
                    .priority(Priority::Filter)
                    .chain_type(ChainType::Filter)
            })
            .chain("sub", |c| c)
            .chain("forward", |c| {
                c.hook(Hook::Forward)
                    .priority(Priority::Mangle)
                    .chain_type(ChainType::Filter)
            })
            .set("allow4", |s| s.key_type(SetKeyType::Ipv4Addr).ipv4(v4))
            // Transport matchers.
            .rule_keyed("input", "tcp-dport", |r| r.match_tcp_dport(22).accept())
            .rule_keyed("input", "udp-dport", |r| r.match_udp_dport(53).accept())
            .rule_keyed("input", "tcp-sport", |r| r.match_tcp_sport(1024).accept())
            .rule_keyed("input", "udp-sport", |r| r.match_udp_sport(1024).accept())
            .rule_keyed("input", "tcp-dport-not", |r| r.match_tcp_dport_not(22).drop())
            .rule_keyed("input", "udp-dport-not", |r| r.match_udp_dport_not(53).drop())
            .rule_keyed("input", "l4proto", |r| r.match_l4proto(17).accept())
            .rule_keyed("input", "icmp", |r| r.match_icmp_type(8).accept())
            .rule_keyed("input", "icmpv6", |r| r.match_icmpv6_type(128).accept())
            .rule_keyed("input", "tcp-flags", |r| {
                r.match_tcp_flags(TcpFlags::SYN, TcpFlags::SYN | TcpFlags::RST)
                    .accept()
            })
            // Address matchers, exact and prefix, plain and negated.
            .rule_keyed("input", "saddr4", |r| r.match_saddr_v4(v4, 24).accept())
            .rule_keyed("input", "daddr4", |r| r.match_daddr_v4(v4, 32).accept())
            .rule_keyed("input", "saddr6", |r| r.match_saddr_v6(v6, 64).accept())
            .rule_keyed("input", "daddr6", |r| r.match_daddr_v6(v6, 128).accept())
            .rule_keyed("input", "saddr4-not", |r| r.match_saddr_v4_not(v4, 24).drop())
            .rule_keyed("input", "daddr4-not", |r| r.match_daddr_v4_not(v4, 32).drop())
            .rule_keyed("input", "saddr6-not", |r| r.match_saddr_v6_not(v6, 64).drop())
            .rule_keyed("input", "daddr6-not", |r| r.match_daddr_v6_not(v6, 128).drop())
            // Set lookups.
            .rule_keyed("input", "saddr-in-set", |r| {
                r.match_saddr_in_set("allow4").accept()
            })
            .rule_keyed("input", "daddr-in-set", |r| {
                r.match_daddr_in_set("allow4").accept()
            })
            // Meta / conntrack.
            .rule_keyed("input", "iif", |r| r.match_iif("lo").accept())
            .rule_keyed("input", "oif", |r| r.match_oif("lo").accept())
            .rule_keyed("input", "mark", |r| r.match_mark(0x10).accept())
            .rule_keyed("input", "ct-state", |r| {
                r.match_ct_state(CtState::ESTABLISHED | CtState::RELATED)
                    .accept()
            })
            // Statements.
            .rule_keyed("input", "counter", |r| r.match_tcp_dport(80).counter())
            .rule_keyed("input", "limit", |r| {
                r.match_tcp_dport(81).limit(10, LimitUnit::Second).accept()
            })
            .rule_keyed("input", "log-prefix", |r| {
                r.match_tcp_dport(82).log(Some("nlink: "))
            })
            .rule_keyed("input", "log-bare", |r| r.match_tcp_dport(83).log(None))
            .rule_keyed("input", "log-group", |r| {
                r.expressions(vec![Expr::Log {
                    prefix: Some("nlink-group: ".into()),
                    group: Some(5),
                }])
            })
            .rule_keyed("input", "set-mark", |r| r.match_tcp_dport(84).set_mark(1))
            .rule_keyed("input", "set-mark-masked", |r| {
                r.match_tcp_dport(89).set_mark_masked(0x10, 0xff)
            })
            .rule_keyed("input", "mark-masked", |r| {
                r.match_mark_masked(0x10, 0xff).accept()
            })
            .rule_keyed("input", "set-priority", |r| {
                r.match_tcp_dport(90).set_priority(TcHandle::new(1, 0x10))
            })
            .rule_keyed("input", "set-ct-mark", |r| r.match_tcp_dport(91).set_ct_mark(7))
            .rule_keyed("input", "ct-mark", |r| r.match_ct_mark(7).accept())
            .rule_keyed("input", "save-mark", |r| r.match_tcp_dport(92).save_mark_to_ct())
            .rule_keyed("input", "restore-mark", |r| {
                r.match_tcp_dport(93).restore_mark_from_ct()
            })
            // `rt tcpmss` is only valid in forward/output/postrouting.
            .rule_keyed("forward", "mss-pmtu", |r| {
                r.match_tcp_flags(TcpFlags::SYN, TcpFlags::SYN | TcpFlags::RST)
                    .clamp_tcp_mss_to_pmtu()
            })
            .rule_keyed("input", "mss", |r| {
                r.match_tcp_flags(TcpFlags::SYN, TcpFlags::SYN | TcpFlags::RST)
                    .clamp_tcp_mss(1360)
            })
            // Verdicts.
            .rule_keyed("input", "reject", |r| r.match_tcp_dport(85).reject())
            .rule_keyed("input", "reject-rst", |r| {
                r.match_tcp_dport(86).reject_with(NFT_REJECT_TCP_RST, 0)
            })
            .rule_keyed("input", "jump", |r| {
                r.match_tcp_dport(87).jump(ChainName::new("sub").unwrap())
            })
            .rule_keyed("input", "goto", |r| {
                r.match_tcp_dport(88).goto(ChainName::new("sub").unwrap())
            })
            .rule_keyed("sub", "return", |r| {
                r.expressions(vec![Expr::Verdict(Verdict::Return)])
            })
        });

        assert_reconciles(&conn, &cfg).await
    })
    .await
}

/// NAT statements, which need `nat`-type chains.
#[tokio::test]
async fn every_nat_rule_shape_reconciles() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("nf_tables", "nft_nat", "nft_masq", "nft_redir");

    let ns = TestNamespace::new("nft-echo-nat")?;
    let conn = nft_in_ns(&ns)?;

    with_timeout(async {
        let cfg = NftablesConfig::new().table("nat_shapes", Family::Inet, |t| {
            t.chain("postrouting", |c| {
                c.hook(Hook::Postrouting)
                    .priority(Priority::SrcNat)
                    .chain_type(ChainType::Nat)
            })
            .chain("prerouting", |c| {
                c.hook(Hook::Prerouting)
                    .priority(Priority::DstNat)
                    .chain_type(ChainType::Nat)
            })
            .rule_keyed("postrouting", "masq", |r| {
                r.match_saddr_v4("10.0.0.0".parse().unwrap(), 8).masquerade()
            })
            .rule_keyed("postrouting", "snat", |r| {
                r.match_saddr_v4("10.1.0.0".parse().unwrap(), 16)
                    .snat("192.0.2.1".parse().unwrap(), None)
            })
            .rule_keyed("postrouting", "snat-port", |r| {
                r.match_saddr_v4("10.2.0.0".parse().unwrap(), 16)
                    .snat("192.0.2.1".parse().unwrap(), Some(4000))
            })
            .rule_keyed("postrouting", "snat6", |r| {
                r.match_saddr_v6("fd00::".parse().unwrap(), 64)
                    .snat_v6("2001:db8::1".parse().unwrap(), None)
            })
            .rule_keyed("prerouting", "dnat", |r| {
                r.match_tcp_dport(8080)
                    .dnat("192.0.2.2".parse().unwrap(), Some(80))
            })
            .rule_keyed("prerouting", "dnat6", |r| {
                r.match_tcp_dport(8081)
                    .dnat_v6("2001:db8::2".parse().unwrap(), Some(80))
            })
            .rule_keyed("prerouting", "redir", |r| {
                r.match_tcp_dport(8082).redirect(None)
            })
            .rule_keyed("prerouting", "redir-port", |r| {
                r.match_tcp_dport(8083).redirect(Some(3128))
            })
        });

        assert_reconciles(&conn, &cfg).await
    })
    .await
}

/// `flow add @ft` against a declared flowtable.
#[tokio::test]
async fn flow_offload_rule_installs_and_reconciles() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("nf_tables", "nf_flow_table", "nft_flow_offload");

    let ns = TestNamespace::new("nft-echo-flow")?;
    let conn = nft_in_ns(&ns)?;

    with_timeout(async {
        let cfg = NftablesConfig::new().table("flow", Family::Inet, |t| {
            t.flowtable("ft", |f| f)
                .chain("forward", |c| {
                    c.hook(Hook::Forward)
                        .priority(Priority::Filter)
                        .chain_type(ChainType::Filter)
                })
                .rule_keyed("forward", "offload", |r| {
                    r.match_ct_state(CtState::ESTABLISHED).flow_offload("ft")
                })
        });

        assert_reconciles(&conn, &cfg).await
    })
    .await
}
