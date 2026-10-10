//! Interval sets — ranges and prefixes (ipset `hash:net`) — checked on
//! traffic: a range matches its ends and nothing past them.

use std::net::Ipv4Addr;

use nlink::netlink::nftables::config::NftablesConfig;
use nlink::netlink::nftables::types::{
    Chain, ChainType, Family, Hook, PacketField, Priority, Rule, Set, SetElement, SetKeyType,
};
use nlink::netlink::{Connection, Nftables};

use crate::common::traffic::{lo_up, send_udp};
use crate::common::{TestNamespace, with_timeout};

/// `ip t` with an output chain counting UDP whose `field` is in `set`.
async fn counting_chain(
    conn: &Connection<Nftables>,
    set: &Set,
    elements: &[SetElement],
    field: PacketField,
) -> nlink::Result<()> {
    conn.add_table("t", Family::Ip).await?;
    conn.add_chain(
        Chain::new("t", "out")?
            .family(Family::Ip)
            .hook(Hook::Output)
            .priority(Priority::Filter)
            .chain_type(ChainType::Filter),
    )
    .await?;
    conn.add_set(set.clone()).await?;
    conn.add_set_elements(set, elements).await?;
    conn.add_rule(
        Rule::new("t", "out")
            .family(Family::Ip)
            .match_l4proto(17)
            .match_in_set(field, set.name())
            .counter(),
    )
    .await
}

async fn counted(conn: &Connection<Nftables>) -> nlink::Result<u64> {
    let rules = conn.list_rules("t", Family::Ip).await?;
    Ok(rules[0].counter().expect("rule has a counter").0)
}

fn interval_set(name: &str, key_type: SetKeyType) -> Set {
    Set::new("t", name)
        .family(Family::Ip)
        .key_type(key_type)
        .interval()
}

/// `udp dport @r` with r = 1000-2000: 1000 and 2000 match, 999 and 2001
/// do not — the end element is `2000 + 1`, not 2000 and not missing.
#[tokio::test]
async fn a_port_range_matches_its_ends_and_nothing_past_them() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("nf_tables");

    let ns = TestNamespace::new("nft-iv-port")?;
    let conn = ns.connection_for::<Nftables>()?;

    with_timeout(async {
        lo_up(&ns).await?;
        let set = interval_set("r", SetKeyType::InetService);
        counting_chain(&conn, &set, &[SetElement::port_range(1000, 2000)], PacketField::UdpDport)
            .await?;
        send_udp(
            &ns,
            &["127.0.0.1:999", "127.0.0.1:1000", "127.0.0.1:2000", "127.0.0.1:2001"],
            1,
        );
        assert_eq!(counted(&conn).await?, 2);
        Ok(())
    })
    .await
}

/// A /30 matches its four addresses and not its neighbours.
#[tokio::test]
async fn a_prefix_matches_its_addresses_only() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("nf_tables");

    let ns = TestNamespace::new("nft-iv-prefix")?;
    let conn = ns.connection_for::<Nftables>()?;

    with_timeout(async {
        lo_up(&ns).await?;
        let set = interval_set("n", SetKeyType::Ipv4Addr);
        let net = SetElement::ipv4_prefix(Ipv4Addr::new(127, 0, 0, 4), 30)?;
        counting_chain(&conn, &set, &[net], PacketField::Ip4Daddr).await?;
        send_udp(
            &ns,
            &["127.0.0.3:9", "127.0.0.4:9", "127.0.0.7:9", "127.0.0.8:9"],
            1,
        );
        assert_eq!(counted(&conn).await?, 2, "only .4 and .7 are in the /30");
        Ok(())
    })
    .await
}

/// A single address in an interval set is that address. Written as a bare
/// interval start — as nlink would have before it modelled intervals — it
/// would have matched every address above it.
#[tokio::test]
async fn a_single_address_in_an_interval_set_is_just_that_address() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("nf_tables");

    let ns = TestNamespace::new("nft-iv-single")?;
    let conn = ns.connection_for::<Nftables>()?;

    with_timeout(async {
        lo_up(&ns).await?;
        let set = interval_set("n", SetKeyType::Ipv4Addr);
        let one = SetElement::ipv4(Ipv4Addr::new(127, 0, 0, 10));
        counting_chain(&conn, &set, &[one], PacketField::Ip4Daddr).await?;
        send_udp(&ns, &["127.0.0.10:9", "127.0.0.11:9", "127.0.0.200:9"], 1);
        assert_eq!(counted(&conn).await?, 1);
        Ok(())
    })
    .await
}

fn declared(ranges: Vec<SetElement>) -> NftablesConfig {
    NftablesConfig::new().table("t", Family::Ip, move |t| {
        t.set("nets", move |s| {
            s.key_type(SetKeyType::Ipv4Addr)
                .interval()
                .elements(ranges)
        })
    })
}

fn prefix(a: u8, b: u8, c: u8, len: u8) -> SetElement {
    SetElement::ipv4_prefix(Ipv4Addr::new(a, b, c, 0), len).unwrap()
}

/// Declared ranges converge; changing one range removes and adds only that
/// range; ranges that touch are merged into one.
#[tokio::test]
async fn declared_ranges_converge_and_change_one_at_a_time() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("nf_tables");

    let ns = TestNamespace::new("nft-iv-decl")?;
    let conn = ns.connection_for::<Nftables>()?;

    with_timeout(async {
        let single = SetElement::ipv4(Ipv4Addr::new(192, 0, 2, 7));
        let first = declared(vec![prefix(10, 0, 0, 24), prefix(10, 0, 2, 24), single.clone()]);
        first.diff(&conn).await?.apply(&conn).await?;
        let again = first.diff(&conn).await?;
        assert!(again.is_empty(), "second diff must be empty: {again}");
        assert_eq!(conn.list_set_elements("t", "nets", Family::Ip).await?.len(), 3);

        let second = declared(vec![prefix(10, 0, 0, 24), prefix(10, 0, 3, 24), single]);
        let diff = second.diff(&conn).await?;
        assert_eq!(diff.set_elements_to_remove.len(), 1, "{diff}");
        assert_eq!(diff.set_elements_to_remove[0].elements.len(), 1, "{diff}");
        assert_eq!(diff.set_elements_to_add[0].elements.len(), 1, "{diff}");
        diff.apply(&conn).await?;
        let again = second.diff(&conn).await?;
        assert!(again.is_empty(), "second diff must be empty: {again}");

        // Two /25s that touch are one /24 to the kernel's lookups.
        let halves = declared(vec![
            SetElement::ipv4_prefix(Ipv4Addr::new(10, 9, 0, 0), 25)?,
            SetElement::ipv4_prefix(Ipv4Addr::new(10, 9, 0, 128), 25)?,
        ]);
        halves.diff(&conn).await?.apply(&conn).await?;
        let elements = conn.list_set_elements("t", "nets", Family::Ip).await?;
        assert_eq!(elements.len(), 1, "{elements:?}");
        assert_eq!(elements[0].key(), [10, 9, 0, 0]);
        assert_eq!(elements[0].key_end(), Some(&[10, 9, 0, 255][..]));
        let again = halves.diff(&conn).await?;
        assert!(again.is_empty(), "second diff must be empty: {again}");
        Ok(())
    })
    .await
}
