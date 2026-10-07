//! Set timeouts and `dynset` (`add|update|delete @set` from a rule) —
//! ipset `timeout` and `SET --add-set` — checked on traffic, and declared
//! dynamic sets that keep what the packet path put in them.

use std::net::Ipv4Addr;
use std::time::Duration;

use nlink::netlink::nftables::config::NftablesConfig;
use nlink::netlink::nftables::types::{
    Chain, ChainType, Family, Hook, PacketField, Priority, Rule, Set, SetElement, SetKeyType,
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

/// Send one UDP datagram from inside `ns` to each of `targets`.
fn send_udp(ns: &TestNamespace, targets: &[&str]) {
    let name = ns.name().to_string();
    let targets: Vec<std::net::SocketAddr> = targets.iter().map(|t| t.parse().unwrap()).collect();
    std::thread::spawn(move || {
        let _ns = namespace::enter(&name).expect("enter test netns");
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind");
        for target in targets {
            let _ = socket.send_to(b"nlink", target);
        }
    })
    .join()
    .expect("UDP thread panicked");
}

/// `ip t` with an output chain, `set`, and `rule` in the chain.
async fn chain_with(conn: &Connection<Nftables>, set: &Set, rule: Rule) -> nlink::Result<()> {
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
    conn.add_rule(rule.family(Family::Ip)).await
}

fn keys(elements: &[SetElement]) -> Vec<Vec<u8>> {
    let mut keys: Vec<Vec<u8>> = elements.iter().map(|e| e.key().to_vec()).collect();
    keys.sort();
    keys
}

fn ip(last: u8) -> Vec<u8> {
    vec![127, 0, 0, last]
}

/// `update @seen { ip daddr timeout 60s }` puts every destination the
/// chain sees in the set, with that timeout running.
#[tokio::test]
async fn update_in_set_records_each_destination_with_its_timeout() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("nf_tables");

    let ns = TestNamespace::new("nft-to-update")?;
    let conn = nft_in_ns(&ns)?;

    with_timeout(async {
        lo_up(&ns).await?;
        let set = Set::new("t", "seen")
            .family(Family::Ip)
            .dynamic()
            .per_element_timeouts();
        let rule = Rule::new("t", "out").match_l4proto(17).update_in_set(
            PacketField::Ip4Daddr,
            "seen",
            Some(Duration::from_secs(60)),
        );
        chain_with(&conn, &set, rule).await?;
        send_udp(&ns, &["127.0.0.5:9", "127.0.0.6:9", "127.0.0.5:10"]);

        let seen = conn.list_set_elements("t", "seen", Family::Ip).await?;
        assert_eq!(keys(&seen), [ip(5), ip(6)]);
        for e in &seen {
            assert_eq!(e.timeout(), Some(Duration::from_secs(60)));
            let left = e.expiration().expect("a timed element reports its time left");
            assert!(left <= Duration::from_secs(60) && left > Duration::from_secs(50), "{left:?}");
        }
        Ok(())
    })
    .await
}

/// `delete @s { ip daddr }` removes the destination from the set.
#[tokio::test]
async fn delete_from_set_removes_the_destination() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("nf_tables");

    let ns = TestNamespace::new("nft-to-delete")?;
    let conn = nft_in_ns(&ns)?;

    with_timeout(async {
        lo_up(&ns).await?;
        let set = Set::new("t", "s").family(Family::Ip).dynamic();
        let rule = Rule::new("t", "out")
            .match_l4proto(17)
            .delete_from_set(PacketField::Ip4Daddr, "s");
        chain_with(&conn, &set, rule).await?;
        let members = [5, 6].map(|n| SetElement::ipv4(Ipv4Addr::new(127, 0, 0, n)));
        conn.add_set_elements(&set, &members).await?;

        send_udp(&ns, &["127.0.0.5:9"]);
        let left = conn.list_set_elements("t", "s", Family::Ip).await?;
        assert_eq!(keys(&left), [ip(6)]);
        Ok(())
    })
    .await
}

/// Elements take the set's default timeout unless they carry their own,
/// and are gone — not listed — once it has run out.
#[tokio::test]
async fn elements_expire_after_the_set_default_or_their_own_timeout() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("nf_tables");

    let ns = TestNamespace::new("nft-to-expire")?;
    let conn = nft_in_ns(&ns)?;

    with_timeout(async {
        conn.add_table("t", Family::Ip).await?;
        let set = Set::new("t", "s")
            .family(Family::Ip)
            .timeout(Duration::from_secs(1))
            .gc_interval(Duration::from_secs(1));
        conn.add_set(set.clone()).await?;
        let info = conn.list_sets_in("t", Family::Ip).await?.remove(0);
        assert_eq!(info.timeout, Some(Duration::from_secs(1)));
        assert_eq!(info.gc_interval, Some(Duration::from_secs(1)));

        let short = SetElement::ipv4(Ipv4Addr::new(10, 0, 0, 1));
        let long = SetElement::ipv4(Ipv4Addr::new(10, 0, 0, 2)).with_timeout(Duration::from_secs(30));
        conn.add_set_elements(&set, &[short, long]).await?;
        let now = conn.list_set_elements("t", "s", Family::Ip).await?;
        assert_eq!(now.len(), 2);
        // Only a timeout that differs from the set's default is reported.
        let own: Vec<_> = now.iter().map(SetElement::timeout).collect();
        assert!(own.contains(&None) && own.contains(&Some(Duration::from_secs(30))), "{own:?}");

        tokio::time::sleep(Duration::from_millis(1500)).await;
        let later = conn.list_set_elements("t", "s", Family::Ip).await?;
        assert_eq!(keys(&later), [vec![10, 0, 0, 2]]);
        Ok(())
    })
    .await
}

fn declared(set_timeout: Duration, rule_timeout: Duration) -> NftablesConfig {
    NftablesConfig::new().table("t", Family::Ip, move |t| {
        t.chain("out", |c| {
            c.hook(Hook::Output)
                .priority(Priority::Filter)
                .chain_type(ChainType::Filter)
        })
        .set("seen", move |s| {
            s.key_type(SetKeyType::Ipv4Addr)
                .dynamic()
                .timeout(set_timeout)
                .gc_interval(Duration::from_millis(1500))
        })
        .rule_keyed("out", "track", move |r| {
            r.match_l4proto(17)
                .update_in_set(PacketField::Ip4Daddr, "seen", Some(rule_timeout))
        })
        // No timeout of its own: the kernel echoes a zero one.
        .rule_keyed("out", "first", |r| {
            r.match_l4proto(6).add_to_set(PacketField::Ip4Saddr, "seen", None)
        })
    })
}

/// A declared dynamic set keeps what its rule put there (#395: a set
/// declared without elements had them wiped on every apply), and its
/// timeouts converge — including ones the kernel rounds to a jiffy.
#[tokio::test]
async fn a_declared_dynamic_set_keeps_what_the_packet_path_put_there() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("nf_tables");

    let ns = TestNamespace::new("nft-to-decl")?;
    let conn = nft_in_ns(&ns)?;

    with_timeout(async {
        lo_up(&ns).await?;
        // 1001 ms reads back as 1000 at HZ=250 or 1003 at HZ=300.
        let cfg = declared(Duration::from_secs(3600), Duration::from_millis(1001));
        cfg.diff(&conn).await?.apply(&conn).await?;
        let again = cfg.diff(&conn).await?;
        assert!(again.is_empty(), "second diff must be empty: {again}");

        send_udp(&ns, &["127.0.0.5:9", "127.0.0.6:9"]);
        let again = cfg.diff(&conn).await?;
        assert!(again.is_empty(), "traffic must not make a diff: {again}");
        assert_eq!(again.apply(&conn).await?, 0);
        let seen = conn.list_set_elements("t", "seen", Family::Ip).await?;
        assert_eq!(keys(&seen), [ip(5), ip(6)]);

        // A changed default timeout is an in-place update: the set, its
        // elements and the rule's handle stay.
        let handle = conn.list_rules("t", Family::Ip).await?[0].handle;
        let longer = declared(Duration::from_secs(7200), Duration::from_millis(1001));
        let diff = longer.diff(&conn).await?;
        assert_eq!(diff.sets_to_update.len(), 1, "{diff}");
        assert!(diff.sets_to_delete.is_empty(), "{diff}");
        diff.apply(&conn).await?;
        let info = conn.list_sets_in("t", Family::Ip).await?.remove(0);
        assert_eq!(info.timeout, Some(Duration::from_secs(7200)));
        assert_eq!(keys(&conn.list_set_elements("t", "seen", Family::Ip).await?).len(), 2);
        assert_eq!(conn.list_rules("t", Family::Ip).await?[0].handle, handle);
        let again = longer.diff(&conn).await?;
        assert!(again.is_empty(), "second diff must be empty: {again}");
        Ok(())
    })
    .await
}

/// Resizing a set whose timeout and GC interval the declaration does not
/// state keeps them: the update overwrites both with what it carries, so it
/// carries the kernel's (#396).
#[tokio::test]
async fn a_resize_keeps_the_timers_it_does_not_declare() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("nf_tables");

    let ns = TestNamespace::new("nft-to-resize")?;
    let conn = nft_in_ns(&ns)?;

    with_timeout(async {
        conn.add_table("t", Family::Ip).await?;
        conn.add_set(
            Set::new("t", "s")
                .family(Family::Ip)
                .timeout(Duration::from_secs(30))
                .gc_interval(Duration::from_secs(5))
                .size(100),
        )
        .await?;

        let cfg = NftablesConfig::new().table("t", Family::Ip, |t| {
            t.set("s", |s| {
                s.key_type(SetKeyType::Ipv4Addr)
                    .per_element_timeouts()
                    .size(200)
            })
        });
        let diff = cfg.diff(&conn).await?;
        assert_eq!(diff.sets_to_update.len(), 1, "{diff}");
        diff.apply(&conn).await?;

        let info = conn.list_sets_in("t", Family::Ip).await?.remove(0);
        assert_eq!(info.size, Some(200));
        assert_eq!(info.timeout, Some(Duration::from_secs(30)));
        assert_eq!(info.gc_interval, Some(Duration::from_secs(5)));
        let again = cfg.diff(&conn).await?;
        assert!(again.is_empty(), "second diff must be empty: {again}");
        Ok(())
    })
    .await
}
