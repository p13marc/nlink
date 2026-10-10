//! Event monitoring integration tests.
//!
//! Every test subscribes first and makes its change on a second
//! connection. rtnetlink queues the notification on the subscribed socket
//! before it acknowledges the change, so by the time that call returns the
//! event is waiting — and one that never arrives is a bug, not timing.
//! The tests wait for it with `expect_event`, which fails instead of
//! shrugging. (They used to accept a missed event "due to timing", which
//! meant no event bug could ever fail them.)

use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    time::Duration,
};

use nlink::{
    Result,
    netlink::{
        NetworkEvent, RtnetlinkGroup,
        addr::{Ipv4Address, Ipv6Address},
        link::DummyLink,
        tc::NetemConfig,
    },
};

use crate::common::TestNamespace;
use crate::common::events::{expect_event, expect_event_without};

/// Long enough for a loaded CI box; the event is already queued.
const WITHIN: Duration = Duration::from_secs(5);

fn new_link(name: &'static str) -> impl FnMut(&NetworkEvent) -> bool {
    move |e| matches!(e, NetworkEvent::NewLink(l) if l.name() == Some(name))
}

fn new_address(ip: IpAddr) -> impl FnMut(&NetworkEvent) -> bool {
    move |e| matches!(e, NetworkEvent::NewAddress(a) if a.address() == Some(&ip))
}

#[tokio::test]
async fn test_link_events() -> Result<()> {
    require_root!();
    nlink::require_module!("dummy");

    let ns = TestNamespace::new("linkev")?;
    let conn = ns.connection()?;
    conn.subscribe(&[RtnetlinkGroup::Link])?;
    let mut events = conn.events().await;

    ns.connection()?.add_link(DummyLink::new("dummy0")).await?;

    expect_event(&mut events, WITHIN, "NewLink dummy0", new_link("dummy0")).await?;
    Ok(())
}

/// An address event arrives, and nothing from a group the socket did not
/// join arrives before it: the link was flipped up first, and its NewLink
/// must not leak onto an `Ipv4Addr`-only subscription.
#[tokio::test]
async fn test_address_events() -> Result<()> {
    require_root!();
    nlink::require_module!("dummy");

    let ns = TestNamespace::new("addrev")?;
    let conn = ns.connection()?;
    conn.add_link(DummyLink::new("dummy0")).await?;
    conn.subscribe(&[RtnetlinkGroup::Ipv4Addr])?;
    let mut events = conn.events().await;

    let conn2 = ns.connection()?;
    conn2.set_link_up("dummy0").await?;
    let ip = Ipv4Addr::new(192, 168, 1, 1);
    conn2
        .add_address(Ipv4Address::new("dummy0", ip, 24))
        .await?;

    expect_event_without(
        &mut events,
        WITHIN,
        "NewAddress 192.168.1.1",
        new_address(ip.into()),
        |e| matches!(e, NetworkEvent::NewLink(_)),
    )
    .await?;
    Ok(())
}

#[tokio::test]
async fn test_tc_events() -> Result<()> {
    require_root!();
    nlink::require_modules!("dummy", "sch_netem");

    let ns = TestNamespace::new("tcev")?;
    let conn = ns.connection()?;
    conn.add_link(DummyLink::new("dummy0")).await?;
    conn.set_link_up("dummy0").await?;
    conn.subscribe(&[RtnetlinkGroup::Tc])?;
    let mut events = conn.events().await;

    let netem = NetemConfig::new().delay(Duration::from_millis(10)).build();
    ns.connection()?.add_qdisc("dummy0", netem).await?;

    expect_event(&mut events, WITHIN, "NewQdisc netem", |e| {
        matches!(e, NetworkEvent::NewQdisc(tc) if tc.kind() == Some("netem"))
    })
    .await?;
    Ok(())
}

#[tokio::test]
async fn test_subscribe_all() -> Result<()> {
    require_root!();
    nlink::require_module!("dummy");

    let ns = TestNamespace::new("suball")?;
    let conn = ns.connection()?;
    conn.subscribe_all()?;
    let mut events = conn.events().await;

    ns.connection()?.add_link(DummyLink::new("dummy0")).await?;

    expect_event(&mut events, WITHIN, "NewLink dummy0", new_link("dummy0")).await?;
    Ok(())
}

/// One socket, three groups: each delivers its own event.
#[tokio::test]
async fn test_multiple_subscriptions() -> Result<()> {
    require_root!();
    nlink::require_module!("dummy");

    let ns = TestNamespace::new("multisub")?;
    let conn = ns.connection()?;
    conn.subscribe(&[
        RtnetlinkGroup::Link,
        RtnetlinkGroup::Ipv4Addr,
        RtnetlinkGroup::Ipv4Route,
    ])?;
    let mut events = conn.events().await;

    let conn2 = ns.connection()?;
    conn2.add_link(DummyLink::new("dummy0")).await?;
    conn2.set_link_up("dummy0").await?;
    let ip = Ipv4Addr::new(10, 0, 0, 1);
    conn2
        .add_address(Ipv4Address::new("dummy0", ip, 24))
        .await?;

    expect_event(&mut events, WITHIN, "NewLink dummy0", new_link("dummy0")).await?;
    expect_event(&mut events, WITHIN, "NewAddress 10.0.0.1", new_address(ip.into())).await?;
    expect_event(&mut events, WITHIN, "a NewRoute for the address", |e| {
        matches!(e, NetworkEvent::NewRoute(_))
    })
    .await?;
    Ok(())
}

/// Bringing a link down announces it down. A NewLink that still says up
/// (linkwatch can report late) is skipped, not taken as the answer.
#[tokio::test]
async fn test_link_down_event() -> Result<()> {
    require_root!();
    nlink::require_module!("dummy");

    let ns = TestNamespace::new("linkdown")?;
    let conn = ns.connection()?;
    conn.add_link(DummyLink::new("dummy0")).await?;
    conn.set_link_up("dummy0").await?;
    conn.subscribe(&[RtnetlinkGroup::Link])?;
    let mut events = conn.events().await;

    ns.connection()?.set_link_down("dummy0").await?;

    expect_event(&mut events, WITHIN, "NewLink dummy0, down", |e| {
        matches!(e, NetworkEvent::NewLink(l) if l.name() == Some("dummy0") && !l.is_up())
    })
    .await?;
    Ok(())
}

#[tokio::test]
async fn test_del_link_event() -> Result<()> {
    require_root!();
    nlink::require_module!("dummy");

    let ns = TestNamespace::new("dellinkev")?;
    let conn = ns.connection()?;
    conn.add_link(DummyLink::new("dummy0")).await?;
    conn.subscribe(&[RtnetlinkGroup::Link])?;
    let mut events = conn.events().await;

    ns.connection()?.del_link("dummy0").await?;

    expect_event(&mut events, WITHIN, "DelLink dummy0", |e| {
        matches!(e, NetworkEvent::DelLink(l) if l.name() == Some("dummy0"))
    })
    .await?;
    Ok(())
}

#[tokio::test]
async fn test_del_address_event() -> Result<()> {
    require_root!();
    nlink::require_module!("dummy");

    let ns = TestNamespace::new("deladdrev")?;
    let conn = ns.connection()?;
    conn.add_link(DummyLink::new("dummy0")).await?;
    conn.set_link_up("dummy0").await?;
    let ip = Ipv4Addr::new(10, 0, 0, 1);
    conn.add_address(Ipv4Address::new("dummy0", ip, 24)).await?;
    conn.subscribe(&[RtnetlinkGroup::Ipv4Addr])?;
    let mut events = conn.events().await;

    ns.connection()?.del_address("dummy0", ip.into(), 24).await?;

    let expected: IpAddr = ip.into();
    expect_event(&mut events, WITHIN, "DelAddress 10.0.0.1", |e| {
        matches!(e, NetworkEvent::DelAddress(a) if a.address() == Some(&expected))
    })
    .await?;
    Ok(())
}

#[tokio::test]
async fn test_owned_event_stream() -> Result<()> {
    require_root!();
    nlink::require_module!("dummy");

    let ns = TestNamespace::new("ownedstream")?;
    let conn = ns.connection()?;
    conn.subscribe(&[RtnetlinkGroup::Link])?;
    let mut stream = conn.into_events().await;

    ns.connection()?.add_link(DummyLink::new("dummy0")).await?;

    expect_event(&mut stream, WITHIN, "NewLink dummy0", new_link("dummy0")).await?;

    // The connection comes back out of the stream.
    let _conn = stream.into_connection();
    Ok(())
}

/// The stream keeps delivering: three links, three events, in order.
#[tokio::test]
async fn test_event_stream_continues() -> Result<()> {
    require_root!();
    nlink::require_module!("dummy");

    let ns = TestNamespace::new("streamcont")?;
    let conn = ns.connection()?;
    conn.subscribe(&[RtnetlinkGroup::Link])?;
    let mut events = conn.events().await;

    let conn2 = ns.connection()?;
    for name in ["dummy0", "dummy1", "dummy2"] {
        conn2.add_link(DummyLink::new(name)).await?;
    }

    expect_event(&mut events, WITHIN, "NewLink dummy0", new_link("dummy0")).await?;
    expect_event(&mut events, WITHIN, "NewLink dummy1", new_link("dummy1")).await?;
    expect_event(&mut events, WITHIN, "NewLink dummy2", new_link("dummy2")).await?;
    Ok(())
}

/// The event for the address added, not the link-local one or a DAD
/// update for something else.
#[tokio::test]
async fn test_ipv6_address_events() -> Result<()> {
    require_root!();
    nlink::require_module!("dummy");

    let ns = TestNamespace::new("addr6ev")?;
    let conn = ns.connection()?;
    conn.add_link(DummyLink::new("dummy0")).await?;
    conn.set_link_up("dummy0").await?;
    conn.subscribe(&[RtnetlinkGroup::Ipv6Addr])?;
    let mut events = conn.events().await;

    let ip: Ipv6Addr = "fd00::1".parse().unwrap();
    ns.connection()?
        .add_address(Ipv6Address::new("dummy0", ip, 64))
        .await?;

    expect_event(&mut events, WITHIN, "NewAddress fd00::1", new_address(ip.into())).await?;
    Ok(())
}

/// After an overflow the watch-cache equals a fresh dump. The resync took
/// its snapshot without draining the socket, then delivered the frames
/// queued before the overflow on top of it — the `NewLink` of a link whose
/// `DelLink` the overflow had dropped, kept forever (#464).
#[tokio::test]
async fn a_resynced_mirror_equals_a_fresh_dump() -> Result<()> {
    use nlink::netlink::resync::ResyncMarker;
    use nlink::netlink::resync::{ConnectionFactory, ResyncedEvent};
    use nlink::netlink::{Route, namespace};
    use std::collections::BTreeSet;
    use std::sync::Arc;
    use tokio_stream::StreamExt;
    require_root!();
    nlink::require_module!("dummy");

    let ns = TestNamespace::new("resync-drain")?;
    let name = ns.name().to_string();
    let factory: ConnectionFactory<Route> = Arc::new(move || {
        let name = name.clone();
        Box::pin(async move { namespace::connection_for::<Route>(&name) })
    });
    let conn = ns.connection()?;
    conn.socket().set_rcvbuf(1024)?;
    let mut stream = conn.into_events_with_resync(factory).await?;

    // A burst the tiny buffer cannot hold, read nothing meanwhile: links
    // that come and go, and some that stay.
    let other = ns.connection()?;
    // It starts with a link that goes again: what the full buffer holds is
    // that link's NewLink, and the DelLink is what the overflow drops.
    for i in 1..=300 {
        let name = format!("t{i}");
        other.add_link(DummyLink::new(name.as_str())).await?;
        if i % 10 != 0 {
            other.del_link(name.as_str()).await?;
        }
    }

    let mut mirror: BTreeSet<String> = BTreeSet::new();
    let mut resyncs = 0;
    loop {
        let next = tokio::time::timeout(Duration::from_secs(1), stream.next()).await;
        let Ok(Some(item)) = next else { break };
        match item? {
            ResyncedEvent::Marker(ResyncMarker::ResyncStart) => {
                resyncs += 1;
                mirror.clear();
            }
            ResyncedEvent::Event(NetworkEvent::NewLink(l))
            | ResyncedEvent::Resynced(NetworkEvent::NewLink(l)) => {
                mirror.extend(l.name().map(str::to_string));
            }
            ResyncedEvent::Event(NetworkEvent::DelLink(l)) => {
                if let Some(n) = l.name() {
                    mirror.remove(n);
                }
            }
            _ => {}
        }
    }
    assert!(
        resyncs > 0,
        "the burst should have overflowed the 1 KiB buffer"
    );
    let fresh: BTreeSet<String> = ns
        .connection()?
        .get_links()
        .await?
        .iter()
        .filter_map(|l| l.name().map(str::to_string))
        .collect();
    assert_eq!(mirror, fresh);
    Ok(())
}
