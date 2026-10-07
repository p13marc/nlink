//! Maps and verdict maps — `ip daddr vmap @vm`, `meta mark set ip daddr map
//! @m` — checked on traffic, and declared maps that converge and replace an
//! element whose data changed.

use std::net::Ipv4Addr;
use std::time::Duration;

use nlink::netlink::nftables::config::NftablesConfig;
use nlink::netlink::nftables::types::{
    Chain, ChainName, ChainType, Family, Hook, PacketField, Priority, Rule, Set, SetDataType,
    SetElement, SetKeyType, Verdict,
};
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

async fn lo_up(ns: &TestNamespace) -> nlink::Result<()> {
    let route: Connection<Route> = namespace::connection_for(ns.name())?;
    let lo = route
        .get_link_by_name("lo")
        .await?
        .expect("every netns has a loopback device");
    route.set_link_up_by_index(lo.ifindex()).await
}

/// Send `count` UDP datagrams from inside `ns` to each target.
fn send_udp(ns: &TestNamespace, targets: &[(&str, usize)]) {
    let name = ns.name().to_string();
    let targets: Vec<(std::net::SocketAddr, usize)> =
        targets.iter().map(|(t, n)| (t.parse().unwrap(), *n)).collect();
    std::thread::spawn(move || {
        let _ns = namespace::enter(&name).expect("enter test netns");
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind");
        for (target, count) in targets {
            for _ in 0..count {
                let _ = socket.send_to(b"nlink", target);
            }
        }
    })
    .join()
    .expect("UDP thread panicked");
}

fn ip(last: u8) -> Ipv4Addr {
    Ipv4Addr::new(127, 0, 0, last)
}

fn jump(chain: &str) -> Verdict {
    Verdict::JumpTo(ChainName::new(chain).unwrap())
}

/// The counter of the first rule in `chain`.
async fn counted(conn: &Connection<Nftables>, family: Family, chain: &str) -> nlink::Result<u64> {
    let rules = conn.list_rules("t", family).await?;
    let rule = rules.iter().find(|r| r.chain == chain).expect("chain has a rule");
    Ok(rule.counter().expect("rule has a counter").0)
}

async fn ip_table_with_output(conn: &Connection<Nftables>) -> nlink::Result<()> {
    conn.add_table("t", Family::Ip).await?;
    conn.add_chain(
        Chain::new("t", "out")?
            .family(Family::Ip)
            .hook(Hook::Output)
            .priority(Priority::Filter)
            .chain_type(ChainType::Filter),
    )
    .await
}

/// `ip daddr vmap @vm` jumps each destination to its own chain; one not in
/// the map goes on to the next rule.
#[tokio::test]
async fn a_verdict_map_jumps_each_destination_to_its_chain() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("nf_tables");

    let ns = TestNamespace::new("nft-map-vmap")?;
    let conn = nft_in_ns(&ns)?;

    with_timeout(async {
        lo_up(&ns).await?;
        ip_table_with_output(&conn).await?;
        for chain in ["c2", "c3"] {
            conn.add_chain(Chain::new("t", chain)?.family(Family::Ip)).await?;
            conn.add_rule(Rule::new("t", chain).family(Family::Ip).counter())
                .await?;
        }
        let vm = Set::new("t", "vm").family(Family::Ip).vmap();
        conn.add_set(vm.clone()).await?;
        conn.add_set_elements(
            &vm,
            &[
                SetElement::ipv4(ip(2)).verdict(jump("c2")),
                SetElement::ipv4(ip(3)).verdict(jump("c3")),
            ],
        )
        .await?;
        conn.add_rule(
            Rule::new("t", "out")
                .family(Family::Ip)
                .match_l4proto(17)
                .vmap(PacketField::Ip4Daddr, "vm"),
        )
        .await?;

        send_udp(&ns, &[("127.0.0.2:9", 3), ("127.0.0.3:9", 5), ("127.0.0.4:9", 2)]);
        assert_eq!(counted(&conn, Family::Ip, "c2").await?, 3);
        assert_eq!(counted(&conn, Family::Ip, "c3").await?, 5);

        // The elements read back with their verdicts.
        let mut back = conn.list_set_elements("t", "vm", Family::Ip).await?;
        back.sort_by(|a, b| a.key().cmp(b.key()));
        assert_eq!(back[0], SetElement::ipv4(ip(2)).verdict(jump("c2")));
        Ok(())
    })
    .await
}

/// `meta mark set ip daddr map @marks` marks each destination with its
/// value; the rules after it count by mark.
#[tokio::test]
async fn a_value_map_sets_each_destinations_mark() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("nf_tables");

    let ns = TestNamespace::new("nft-map-mark")?;
    let conn = nft_in_ns(&ns)?;

    with_timeout(async {
        lo_up(&ns).await?;
        ip_table_with_output(&conn).await?;
        let marks = Set::new("t", "marks")
            .family(Family::Ip)
            .map(SetDataType::Value(SetKeyType::Mark));
        conn.add_set(marks.clone()).await?;
        conn.add_set_elements(
            &marks,
            &[
                SetElement::ipv4(ip(2)).value(SetElement::mark(0x10)),
                SetElement::ipv4(ip(3)).value(SetElement::mark(0x20)),
            ],
        )
        .await?;
        for rule in [
            Rule::new("t", "out")
                .match_l4proto(17)
                .set_mark_from_map(PacketField::Ip4Daddr, "marks"),
            Rule::new("t", "out").match_mark(0x10).counter(),
            Rule::new("t", "out").match_mark(0x20).counter(),
        ] {
            conn.add_rule(rule.family(Family::Ip)).await?;
        }

        send_udp(&ns, &[("127.0.0.2:9", 2), ("127.0.0.3:9", 1), ("127.0.0.4:9", 4)]);
        let rules = conn.list_rules("t", Family::Ip).await?;
        let counts: Vec<u64> = rules[1..].iter().map(|r| r.counter().unwrap().0).collect();
        assert_eq!(counts, [2, 1]);
        Ok(())
    })
    .await
}

fn declared(to_c2: Ipv4Addr, ports_verdict: Verdict) -> NftablesConfig {
    NftablesConfig::new().table("t", Family::Ip, move |t| {
        t.chain("out", |c| {
            c.hook(Hook::Output)
                .priority(Priority::Filter)
                .chain_type(ChainType::Filter)
        })
        .chain("c2", |c| c)
        .chain("c3", |c| c)
        .rule_keyed("c2", "count", |r| r.counter())
        .rule_keyed("c3", "count", |r| r.counter())
        .set("vm", move |s| {
            s.vmap()
                .element(SetElement::ipv4(to_c2).verdict(jump("c2")))
                .element(SetElement::ipv4(ip(3)).verdict(jump("c3")))
        })
        .set("marks", |s| {
            s.map(SetDataType::Value(SetKeyType::Mark))
                .element(SetElement::ipv4(ip(2)).value(SetElement::mark(0x10)))
        })
        .set("ports", move |s| {
            s.key_type(SetKeyType::InetService)
                .interval()
                .vmap()
                .element(SetElement::port_range(1000, 1999).verdict(ports_verdict))
                .element(SetElement::port_range(2000, 2999).verdict(Verdict::Accept))
        })
        .rule_keyed("out", "vm", |r| {
            r.match_l4proto(17).vmap(PacketField::Ip4Daddr, "vm")
        })
        .rule_keyed("out", "marks", |r| {
            r.match_l4proto(17)
                .set_mark_from_map(PacketField::Ip4Daddr, "marks")
        })
        .rule_keyed("out", "ports", |r| r.vmap(PacketField::UdpDport, "ports"))
    })
}

/// Declared maps converge — verdicts with jumps, values, an interval map
/// whose touching ranges map to different verdicts and so stay two — and an
/// element whose data changed is replaced, by itself.
#[tokio::test]
async fn declared_maps_converge_and_replace_an_element_whose_data_changed() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("nf_tables");

    let ns = TestNamespace::new("nft-map-decl")?;
    let conn = nft_in_ns(&ns)?;

    with_timeout(async {
        lo_up(&ns).await?;
        let first = declared(ip(2), jump("c3"));
        first.diff(&conn).await?.apply(&conn).await?;
        let again = first.diff(&conn).await?;
        assert!(again.is_empty(), "second diff must be empty: {again}");
        assert_eq!(conn.list_set_elements("t", "ports", Family::Ip).await?.len(), 2);

        // .4 now jumps to c2 instead of .2; port 1000-1999 accepts.
        let second = declared(ip(4), Verdict::Accept);
        let diff = second.diff(&conn).await?;
        let changed = |c: &[nlink::netlink::nftables::config::SetElementsChange]| {
            let mut n: Vec<(String, usize)> = c
                .iter()
                .map(|c| (c.set.name().to_string(), c.elements.len()))
                .collect();
            n.sort();
            n
        };
        assert_eq!(
            changed(&diff.set_elements_to_remove),
            [("ports".to_string(), 1), ("vm".to_string(), 1)],
            "{diff}"
        );
        assert_eq!(
            changed(&diff.set_elements_to_add),
            [("ports".to_string(), 1), ("vm".to_string(), 1)],
            "{diff}"
        );
        assert!(diff.rules_to_replace.is_empty() && diff.sets_to_delete.is_empty(), "{diff}");
        diff.apply(&conn).await?;
        let again = second.diff(&conn).await?;
        assert!(again.is_empty(), "second diff must be empty: {again}");

        send_udp(&ns, &[("127.0.0.4:9", 2), ("127.0.0.2:9", 1), ("127.0.0.3:9", 1)]);
        assert_eq!(counted(&conn, Family::Ip, "c2").await?, 2);
        assert_eq!(counted(&conn, Family::Ip, "c3").await?, 1);
        Ok(())
    })
    .await
}
