//! Set lookups by packet field — IPv6 addresses, ports, `!= @set` — the raw
//! escape hatch, and set-element / generation events, each checked against
//! real traffic or real notifications.

use std::net::{Ipv4Addr, Ipv6Addr};

use nlink::netlink::nftables::config::NftablesConfig;
use nlink::netlink::nftables::types::{
    Chain, ChainType, CtState, Family, Hook, PacketField, Priority, Rule, Set, SetElement,
    SetKeyType,
};
use nlink::netlink::nftables::{NftablesEvent, RawExpr};
use nlink::netlink::{Connection, Nftables};
use tokio_stream::StreamExt;

use crate::common::traffic::{lo_up, send_udp};
use crate::common::{TestNamespace, with_timeout};

/// An `inet t` table with an `output` filter chain `out`.
async fn add_output_chain(conn: &Connection<Nftables>) -> nlink::Result<()> {
    conn.add_table("t", Family::Inet).await?;
    conn.add_chain(
        Chain::new("t", "out")?
            .family(Family::Inet)
            .hook(Hook::Output)
            .priority(Priority::Filter)
            .chain_type(ChainType::Filter),
    )
    .await
}

async fn counted(conn: &Connection<Nftables>, index: usize) -> nlink::Result<u64> {
    let rules = conn.list_rules("t", Family::Inet).await?;
    Ok(rules[index].counter().expect("rule has a counter").0)
}

/// `ip6 daddr @s6` matches IPv6 traffic to a member — and the `meta nfproto
/// ipv6` guard keeps IPv4 traffic out of the lookup.
#[tokio::test]
async fn ip6_set_lookup_matches_ipv6_traffic() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("nf_tables");

    let ns = TestNamespace::new("nft-lk-ip6")?;
    let conn = ns.connection_for::<Nftables>()?;

    with_timeout(async {
        lo_up(&ns).await?;
        add_output_chain(&conn).await?;
        let set = Set::new("t", "s6").key_type(SetKeyType::Ipv6Addr);
        conn.add_set(set.clone()).await?;
        conn.add_set_elements(&set, &[SetElement::ipv6(Ipv6Addr::LOCALHOST)])
            .await?;
        // UDP only: nothing listens on [::1]:9, so each datagram draws an
        // ICMPv6 port-unreachable to ::1 that would match too.
        conn.add_rule(
            Rule::new("t", "out")
                .match_l4proto(17)
                .match_in_set(PacketField::Ip6Daddr, "s6")
                .counter(),
        )
        .await?;

        send_udp(&ns, &["[::1]:9"], 3);
        send_udp(&ns, &["127.0.0.1:9"], 2);
        assert_eq!(counted(&conn, 0).await?, 3, "only the IPv6 datagrams match");
        Ok(())
    })
    .await
}

/// `udp dport @ports` counts traffic to member ports only.
#[tokio::test]
async fn port_set_lookup_matches_member_ports() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("nf_tables");

    let ns = TestNamespace::new("nft-lk-port")?;
    let conn = ns.connection_for::<Nftables>()?;

    with_timeout(async {
        lo_up(&ns).await?;
        add_output_chain(&conn).await?;
        let set = Set::new("t", "ports").key_type(SetKeyType::InetService);
        conn.add_set(set.clone()).await?;
        conn.add_set_elements(&set, &[SetElement::port(9)]).await?;
        conn.add_rule(
            Rule::new("t", "out")
                .match_in_set(PacketField::UdpDport, "ports")
                .counter(),
        )
        .await?;

        send_udp(&ns, &["127.0.0.1:9"], 2);
        send_udp(&ns, &["127.0.0.1:10"], 4);
        assert_eq!(counted(&conn, 0).await?, 2);
        Ok(())
    })
    .await
}

/// `ip daddr != @s` counts only traffic to non-members.
#[tokio::test]
async fn inverted_lookup_counts_only_non_members() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("nf_tables");

    let ns = TestNamespace::new("nft-lk-inv")?;
    let conn = ns.connection_for::<Nftables>()?;

    with_timeout(async {
        lo_up(&ns).await?;
        add_output_chain(&conn).await?;
        let set = Set::new("t", "s4").key_type(SetKeyType::Ipv4Addr);
        conn.add_set(set.clone()).await?;
        conn.add_set_elements(&set, &[SetElement::ipv4(Ipv4Addr::new(127, 0, 0, 2))])
            .await?;
        conn.add_rule(
            Rule::new("t", "out")
                .match_l4proto(17)
                .match_not_in_set(PacketField::Ip4Daddr, "s4")
                .counter(),
        )
        .await?;

        send_udp(&ns, &["127.0.0.1:9"], 3);
        send_udp(&ns, &["127.0.0.2:9"], 2);
        assert_eq!(counted(&conn, 0).await?, 3, "the member's datagrams must not count");
        Ok(())
    })
    .await
}

/// Adding elements is notified as `NewSetElements`, and every commit as
/// `NewGen` with a growing generation.
#[tokio::test]
async fn set_element_and_generation_events_arrive() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("nf_tables");

    let ns = TestNamespace::new("nft-lk-events")?;
    let conn = ns.connection_for::<Nftables>()?;
    let watcher = ns.connection_for::<Nftables>()?;

    with_timeout(async {
        watcher.subscribe_all()?;
        let mut events = watcher.events().await;

        conn.add_table("t", Family::Inet).await?;
        let set = Set::new("t", "s").key_type(SetKeyType::Ipv4Addr);
        conn.add_set(set.clone()).await?;
        conn.add_set_elements(&set, &[SetElement::ipv4(Ipv4Addr::new(10, 0, 0, 7))])
            .await?;

        let mut gens = Vec::new();
        let mut added = None;
        while added.is_none() || gens.len() < 2 {
            match events.next().await {
                Some(Ok(NftablesEvent::NewGen(g))) => gens.push(g.id),
                Some(Ok(NftablesEvent::NewSetElements(e))) => added = Some(e),
                Some(Ok(_)) => {}
                Some(Err(e)) => return Err(e),
                None => break,
            }
        }
        let added = added.expect("no NewSetElements event");
        assert_eq!((added.table.as_str(), added.set.as_str()), ("t", "s"));
        assert_eq!(added.elements[0].key(), [10, 0, 0, 7]);
        assert!(gens.windows(2).all(|w| w[1] > w[0]), "generations grow: {gens:?}");
        Ok(())
    })
    .await
}

/// The raw escape hatch installs an expression nlink does not model —
/// `notrack`, which has no data nest at all — and a declared rule built
/// with it converges. Traffic proves it took effect: the packets leave
/// untracked.
#[tokio::test]
async fn a_raw_notrack_untracks_and_converges() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("nf_tables", "nft_ct");

    let ns = TestNamespace::new("nft-lk-raw")?;
    let conn = ns.connection_for::<Nftables>()?;

    with_timeout(async {
        lo_up(&ns).await?;
        let cfg = NftablesConfig::new().table("t", Family::Inet, |t| {
            t.chain("raw", |c| {
                c.hook(Hook::Output)
                    .priority(Priority::Raw)
                    .chain_type(ChainType::Filter)
            })
            .chain("out", |c| {
                c.hook(Hook::Output)
                    .priority(Priority::Filter)
                    .chain_type(ChainType::Filter)
            })
            .rule_keyed("raw", "notrack", |r| {
                r.match_udp_dport(9).expr(RawExpr::without_data("notrack"))
            })
            .rule_keyed("out", "untracked", |r| {
                r.match_udp_dport(9)
                    .match_ct_state(CtState::UNTRACKED)
                    .counter()
            })
        });
        cfg.diff(&conn).await?.apply(&conn).await?;
        let again = cfg.diff(&conn).await?;
        assert!(again.is_empty(), "second diff must be empty: {again}");

        send_udp(&ns, &["127.0.0.1:9"], 3);
        let rules = conn.list_rules("t", Family::Inet).await?;
        let untracked = rules
            .iter()
            .find(|r| r.key.as_deref() == Some("untracked"))
            .unwrap();
        assert!(untracked.counter().unwrap().0 >= 3, "packets were tracked");
        Ok(())
    })
    .await
}
