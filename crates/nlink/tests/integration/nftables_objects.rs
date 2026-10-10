//! Named stateful objects — counters, quotas, limits — and object maps,
//! checked on traffic; declared objects keep their live state across
//! applies, a quota is updated in place and a changed limit is recreated
//! without moving the rules that use it.

use std::net::Ipv4Addr;

use nlink::netlink::nftables::config::{MoveReason, NftablesConfig};
use nlink::netlink::nftables::types::{
    Chain, ChainType, Family, Hook, LimitUnit, PacketField, Priority, Rule, Set, SetDataType,
    SetElement,
};
use nlink::netlink::nftables::{
    LimitExpr, NftablesEvent, Object, ObjectConfig, ObjectState, ObjectType, QuotaExpr,
};
use nlink::netlink::{Connection, Nftables};
use tokio_stream::StreamExt;

use crate::common::traffic::{lo_up, send_udp};
use crate::common::{TestNamespace, with_timeout};

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

async fn object(conn: &Connection<Nftables>, name: &str) -> nlink::Result<ObjectState> {
    let objects = conn.list_objects_in("t", Family::Ip).await?;
    Ok(objects
        .into_iter()
        .find(|o| o.name == name)
        .expect("object exists")
        .state)
}

fn packets(state: &ObjectState) -> u64 {
    match state {
        ObjectState::Counter { packets, .. } => *packets,
        other => panic!("not a counter: {other:?}"),
    }
}

/// `counter name "c"` counts into the shared counter; `reset_object`
/// returns the count and zeroes it in one step. The object is notified.
#[tokio::test]
async fn a_named_counter_counts_and_resets() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("nf_tables");

    let ns = TestNamespace::new("nft-obj-counter")?;
    let conn = ns.connection_for::<Nftables>()?;
    let watcher = ns.connection_for::<Nftables>()?;

    with_timeout(async {
        lo_up(&ns).await?;
        watcher.subscribe_all()?;
        let mut events = watcher.events().await;
        ip_table_with_output(&conn).await?;
        conn.add_object(&Object::counter("t", "c").family(Family::Ip))
            .await?;
        conn.add_rule(
            Rule::new("t", "out")
                .family(Family::Ip)
                .match_l4proto(17)
                .counter_named("c"),
        )
        .await?;
        loop {
            match events.next().await {
                Some(Ok(NftablesEvent::NewObject(o))) => {
                    assert_eq!((o.name.as_str(), o.object_type()), ("c", Some(ObjectType::Counter)));
                    break;
                }
                Some(Ok(_)) => {}
                Some(Err(e)) => return Err(e),
                None => panic!("event stream ended"),
            }
        }
        send_udp(&ns, &["127.0.0.1:9"], 4);
        assert_eq!(packets(&object(&conn, "c").await?), 4);
        let before = conn
            .reset_object("t", "c", ObjectType::Counter, Family::Ip)
            .await?
            .expect("the counter exists");
        assert_eq!(packets(&before.state), 4);
        assert_eq!(packets(&object(&conn, "c").await?), 0);
        assert!(
            conn.reset_object("t", "nope", ObjectType::Counter, Family::Ip)
                .await?
                .is_none()
        );
        Ok(())
    })
    .await
}

/// `counter name ip daddr map @per_ip`: one counter per destination,
/// picked by an object map — ipset's per-element `counters`.
#[tokio::test]
async fn an_object_map_counts_each_destination_in_its_own_counter() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("nf_tables");

    let ns = TestNamespace::new("nft-obj-map")?;
    let conn = ns.connection_for::<Nftables>()?;

    with_timeout(async {
        lo_up(&ns).await?;
        ip_table_with_output(&conn).await?;
        for name in ["c2", "c3"] {
            conn.add_object(&Object::counter("t", name).family(Family::Ip))
                .await?;
        }
        let map = Set::new("t", "per_ip")
            .family(Family::Ip)
            .map(SetDataType::Object(ObjectType::Counter));
        conn.add_set(map.clone()).await?;
        conn.add_set_elements(
            &map,
            &[
                SetElement::ipv4(Ipv4Addr::new(127, 0, 0, 2)).object("c2"),
                SetElement::ipv4(Ipv4Addr::new(127, 0, 0, 3)).object("c3"),
            ],
        )
        .await?;
        conn.add_rule(
            Rule::new("t", "out")
                .family(Family::Ip)
                .match_l4proto(17)
                .objref_from_map(PacketField::Ip4Daddr, "per_ip"),
        )
        .await?;
        for (target, count) in [("127.0.0.2:9", 2), ("127.0.0.3:9", 3), ("127.0.0.4:9", 5)] {
            send_udp(&ns, &[target], count);
        }
        assert_eq!(packets(&object(&conn, "c2").await?), 2);
        assert_eq!(packets(&object(&conn, "c3").await?), 3);
        let elements = conn.list_set_elements("t", "per_ip", Family::Ip).await?;
        assert!(elements.iter().any(|e| e == &SetElement::ipv4(Ipv4Addr::new(127, 0, 0, 2)).object("c2")));
        Ok(())
    })
    .await
}

/// `quota until 100 bytes` matches 33-byte datagrams until the third has
/// used 99 of them; `quota over` matches the rest. A named quota reports
/// itself used up.
#[tokio::test]
async fn quotas_match_until_used_up_and_over_after() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("nf_tables", "nft_quota");

    let ns = TestNamespace::new("nft-obj-quota")?;
    let conn = ns.connection_for::<Nftables>()?;

    with_timeout(async {
        lo_up(&ns).await?;
        ip_table_with_output(&conn).await?;
        conn.add_object(&Object::quota("t", "q", QuotaExpr::new(100)).family(Family::Ip))
            .await?;
        for rule in [
            Rule::new("t", "out").match_l4proto(17).quota_until(100).counter(),
            Rule::new("t", "out").match_l4proto(17).quota_over(100).counter(),
            Rule::new("t", "out").match_l4proto(17).quota_named("q").counter(),
        ] {
            conn.add_rule(rule.family(Family::Ip)).await?;
        }
        send_udp(&ns, &["127.0.0.1:9"], 10);
        let rules = conn.list_rules("t", Family::Ip).await?;
        let counts: Vec<u64> = rules.iter().map(|r| r.counter().unwrap().0).collect();
        assert_eq!(counts, [3, 7, 3]);
        match object(&conn, "q").await? {
            ObjectState::Quota {
                bytes, consumed, depleted, ..
            } => assert_eq!((bytes, consumed, depleted), (100, 100, true)),
            other => panic!("not a quota: {other:?}"),
        }
        Ok(())
    })
    .await
}

fn declared(quota: u64, rate: u64) -> NftablesConfig {
    NftablesConfig::new().table("t", Family::Ip, move |t| {
        t.chain("out", |c| {
            c.hook(Hook::Output)
                .priority(Priority::Filter)
                .chain_type(ChainType::Filter)
        })
        .object("web", ObjectConfig::Counter)
        .object("budget", ObjectConfig::Quota(QuotaExpr::new(quota)))
        // Burst 0 is the kernel's default, which it stores (and dumps) as 5.
        .object(
            "rate",
            ObjectConfig::Limit(LimitExpr::packets(rate, LimitUnit::Second).burst(0)),
        )
        .rule_keyed("out", "first", |r| r.match_l4proto(6).counter())
        .rule_keyed("out", "web", |r| r.match_l4proto(17).counter_named("web"))
        .rule_keyed("out", "budget", |r| r.match_l4proto(17).quota_named("budget"))
        .rule_keyed("out", "rate", |r| r.match_l4proto(17).limit_named("rate"))
        // The rule's own quota: the kernel echoes its consumption.
        .rule_keyed("out", "cap", |r| r.match_l4proto(17).quota_over(1 << 40))
        // An object map naming a declared counter.
        .set("per_ip", |s| {
            s.map(SetDataType::Object(ObjectType::Counter))
                .element(SetElement::ipv4(Ipv4Addr::LOCALHOST).object("web"))
        })
        .rule_keyed("out", "per_ip", |r| {
            r.match_l4proto(17).objref_from_map(PacketField::Ip4Daddr, "per_ip")
        })
        .rule_keyed("out", "last", |r| r.match_l4proto(1).counter())
    })
}

/// Declared objects converge and keep their live state: re-applying after
/// traffic leaves the counter counting, a changed quota keeps what it has
/// used, and a changed limit is recreated with the rule that uses it moved
/// back to its place.
#[tokio::test]
async fn declared_objects_converge_and_keep_their_state() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("nf_tables", "nft_quota", "nft_limit");

    let ns = TestNamespace::new("nft-obj-decl")?;
    let conn = ns.connection_for::<Nftables>()?;

    with_timeout(async {
        lo_up(&ns).await?;
        let first = declared(1_000_000, 1000);
        first.diff(&conn).await?.apply(&conn).await?;
        let again = first.diff(&conn).await?;
        assert!(again.is_empty(), "second diff must be empty: {again}");
        send_udp(&ns, &["127.0.0.1:9"], 3);
        let again = first.diff(&conn).await?;
        assert!(again.is_empty(), "traffic must not make a diff: {again}");
        // Counted by name and again through the map.
        assert_eq!(packets(&object(&conn, "web").await?), 6);

        // A bigger quota: updated in place, its consumption kept.
        let bigger = declared(2_000_000, 1000);
        let diff = bigger.diff(&conn).await?;
        assert_eq!(diff.objects_to_update.len(), 1, "{diff}");
        assert!(diff.objects_to_delete.is_empty(), "{diff}");
        diff.apply(&conn).await?;
        match object(&conn, "budget").await? {
            ObjectState::Quota { bytes, consumed, .. } => {
                assert_eq!((bytes, consumed), (2_000_000, 99));
            }
            other => panic!("not a quota: {other:?}"),
        }
        assert_eq!(packets(&object(&conn, "web").await?), 6);

        // A new rate: the limit is recreated, and the rule using it moves
        // out of the way and back to the same place.
        let order = |rules: &[nlink::netlink::nftables::types::RuleInfo]| -> Vec<String> {
            rules.iter().filter_map(|r| r.key.clone()).collect()
        };
        let before = order(&conn.list_rules("t", Family::Ip).await?);
        let faster = declared(2_000_000, 2000);
        let diff = faster.diff(&conn).await?;
        assert_eq!(diff.objects_to_delete.len(), 1, "{diff}");
        assert_eq!(diff.rules_to_move.len(), 1, "{diff}");
        assert_eq!(diff.rules_to_move[0].reason, MoveReason::BoundToRecreatedObject);
        diff.apply(&conn).await?;
        assert_eq!(order(&conn.list_rules("t", Family::Ip).await?), before);
        match object(&conn, "rate").await? {
            ObjectState::Limit(limit) => assert_eq!(limit.rate, 2000),
            other => panic!("not a limit: {other:?}"),
        }
        let again = faster.diff(&conn).await?;
        assert!(again.is_empty(), "second diff must be empty: {again}");
        Ok(())
    })
    .await
}
