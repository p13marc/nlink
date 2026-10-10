//! The test helpers in `common/` checked against themselves.
//!
//! A helper that cannot fail turns every test built on it into a pass, so
//! each one here is also run where it must say no: traffic across a wire
//! that is down, an event on a stream that stays quiet, a forbidden event
//! that arrives first.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use nlink::netlink::config::NetworkConfig;
use nlink::netlink::link::DummyLink;
use nlink::netlink::{NetworkEvent, RtnetlinkGroup};

use crate::common::converge::{assert_converges, assert_transition, case, ip_json};
use crate::common::events::{expect_event, expect_event_without};
use crate::common::topo::NsPair;
use crate::common::traffic::{deliver_udp, ping};
use crate::common::{TestNamespace, with_timeout};

/// `deliver_udp` counts what arrives, and `ping` answers, in both
/// families — and both report nothing once the wire is down.
#[tokio::test]
async fn traffic_helpers_count_deliveries_and_see_a_dead_wire() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("veth");

    let pair = NsPair::new("hns-wire", 61).await?;
    with_timeout(async {
        let v4 = SocketAddr::new(pair.b_addr.into(), 9000);
        let v6 = SocketAddr::new(pair.b_addr6.into(), 9000);
        assert_eq!(deliver_udp(&pair.a, &pair.b, v4, 5), 5);
        assert_eq!(deliver_udp(&pair.a, &pair.b, v6, 5), 5);
        assert!(ping(&pair.b, IpAddr::V4(pair.a_addr), 1));
        assert!(ping(&pair.b, IpAddr::V6(pair.a_addr6), 1));

        let b = pair.b.connection()?;
        let b_link = b
            .get_link_by_name(pair.b_if)
            .await?
            .expect("the pair's b end exists");
        assert_eq!(b_link.ifindex(), pair.b_ifindex);
        b.set_link_down_by_index(pair.b_ifindex).await?;

        assert_eq!(deliver_udp(&pair.a, &pair.b, v4, 5), 0, "the wire is down");
        assert!(!ping(&pair.a, IpAddr::V4(pair.b_addr), 1), "the wire is down");
        Ok(())
    })
    .await
}

/// `expect_event` returns the event it waits for, fails on a stream that
/// stays quiet, and `expect_event_without` fails when the forbidden event
/// comes first.
#[tokio::test]
async fn event_helpers_fail_when_the_event_does_not_come() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("dummy");

    let ns = TestNamespace::new("hns-events")?;
    let conn = ns.connection()?;
    conn.subscribe(&[RtnetlinkGroup::Link])?;
    let mut events = conn.events().await;
    let other = ns.connection()?;

    let quiet = expect_event(&mut events, Duration::from_millis(300), "a link event", |_| true).await;
    assert!(quiet.is_err(), "nothing changed, yet an event arrived: {quiet:?}");

    other.add_link(DummyLink::new("d0")).await?;
    let is_d0 = |e: &NetworkEvent| matches!(e, NetworkEvent::NewLink(l) if l.name() == Some("d0"));
    expect_event(&mut events, Duration::from_secs(5), "NewLink d0", is_d0).await?;

    other.add_link(DummyLink::new("d1")).await?;
    other.add_link(DummyLink::new("d2")).await?;
    let is_d2 = |e: &NetworkEvent| matches!(e, NetworkEvent::NewLink(l) if l.name() == Some("d2"));
    let is_d1 = |e: &NetworkEvent| matches!(e, NetworkEvent::NewLink(l) if l.name() == Some("d1"));
    let forbidden = expect_event_without(
        &mut events,
        Duration::from_secs(5),
        "NewLink d2 with no d1 before it",
        is_d2,
        is_d1,
    )
    .await;
    assert!(forbidden.is_err(), "d1 came first and is forbidden: {forbidden:?}");
    Ok(())
}

/// A gateway change under purge converges in one apply and leaves one
/// route behind — checked through `ip`, both as a transition and as a
/// case with a check.
#[tokio::test]
async fn a_purged_gateway_change_converges_to_one_route() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("dummy");

    let via = |gw: &str| -> nlink::Result<NetworkConfig> {
        let gw = gw.to_string();
        Ok(NetworkConfig::new()
            .link("d0", |l| l.dummy().up())
            .address("d0", "10.62.0.1/24")?
            .route("10.5.0.0/16", move |r| r.via(&gw))?)
    };
    let only_via = |ns: &TestNamespace, gw: &str| -> Result<(), String> {
        let routes = ip_json(ns, &["route", "show", "10.5.0.0/16"])?;
        let routes = routes.as_array().cloned().unwrap_or_default();
        match routes.as_slice() {
            [route] if route["gateway"] == gw => Ok(()),
            _ => Err(format!("want one route via {gw}, the kernel has {routes:?}")),
        }
    };

    let ns = TestNamespace::new("hns-gw")?;
    let steps = [via("10.62.0.2")?, via("10.62.0.3")?];
    assert_transition(&ns, &steps, true, async |i, _conn| {
        only_via(&ns, ["10.62.0.2", "10.62.0.3"][i])
    })
    .await?;

    let cases = vec![
        case("gateway-change", vec![via("10.62.0.2")?, via("10.62.0.3")?])
            .purging()
            .check(move |ns| only_via(ns, "10.62.0.3")),
    ];
    assert_converges("hns-gw-case", cases).await
}
