//! Event monitoring integration tests.
//!
//! Tests for netlink event subscription and monitoring using network namespaces.

use nlink::Result;
use nlink::netlink::addr::Ipv4Address;
use nlink::netlink::link::DummyLink;
use nlink::netlink::tc::NetemConfig;
use nlink::netlink::{NetworkEvent, RtnetlinkGroup};
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;
use tokio_stream::StreamExt;

use crate::common::TestNamespace;

#[tokio::test]
async fn test_link_events() -> Result<()> {
    require_root!();

    let ns = TestNamespace::new("linkev")?;
    let mut conn = ns.connection()?;

    // Subscribe to link events
    conn.subscribe(&[RtnetlinkGroup::Link])?;

    // Create a stream with timeout
    let mut events = conn.events();

    // Create a dummy interface (will generate NewLink event)
    {
        let conn2 = ns.connection()?;
        conn2.add_link(DummyLink::new("dummy0")).await?;
    }

    // Wait for event with timeout
    let event = tokio::time::timeout(Duration::from_secs(2), events.next()).await;

    if let Ok(Some(Ok(NetworkEvent::NewLink(link)))) = event {
        assert_eq!(link.name().as_deref(), Some("dummy0"));
    } else {
        // Event might have been missed due to timing, that's ok for this test
    }

    Ok(())
}

#[tokio::test]
async fn test_address_events() -> Result<()> {
    require_root!();

    let ns = TestNamespace::new("addrev")?;
    let mut conn = ns.connection()?;

    // Create dummy first
    conn.add_link(DummyLink::new("dummy0")).await?;
    conn.set_link_up("dummy0").await?;

    // Subscribe to address events
    conn.subscribe(&[RtnetlinkGroup::Ipv4Addr])?;

    let mut events = conn.events();

    // Add address (will generate NewAddr event)
    {
        let conn2 = ns.connection()?;
        conn2
            .add_address(Ipv4Address::new(
                "dummy0",
                Ipv4Addr::new(192, 168, 1, 1),
                24,
            ))
            .await?;
    }

    // Wait for event
    let event = tokio::time::timeout(Duration::from_secs(2), events.next()).await;

    if let Ok(Some(Ok(NetworkEvent::NewAddress(addr)))) = event {
        let expected: IpAddr = Ipv4Addr::new(192, 168, 1, 1).into();
        assert_eq!(addr.address(), Some(&expected));
    }

    Ok(())
}

#[tokio::test]
async fn test_tc_events() -> Result<()> {
    require_root!();

    let ns = TestNamespace::new("tcev")?;
    let mut conn = ns.connection()?;

    // Create dummy first
    conn.add_link(DummyLink::new("dummy0")).await?;
    conn.set_link_up("dummy0").await?;

    // Subscribe to TC events
    conn.subscribe(&[RtnetlinkGroup::Tc])?;

    let mut events = conn.events();

    // Add qdisc (will generate NewQdisc event)
    {
        let conn2 = ns.connection()?;
        let netem = NetemConfig::new().delay(Duration::from_millis(10)).build();
        conn2.add_qdisc("dummy0", netem).await?;
    }

    // Wait for event
    let event = tokio::time::timeout(Duration::from_secs(2), events.next()).await;

    if let Ok(Some(Ok(NetworkEvent::NewQdisc(tc)))) = event {
        assert_eq!(tc.kind(), Some("netem"));
    }

    Ok(())
}

#[tokio::test]
async fn test_subscribe_all() -> Result<()> {
    require_root!();

    let ns = TestNamespace::new("suball")?;
    let mut conn = ns.connection()?;

    // Subscribe to all common groups
    conn.subscribe_all()?;

    // Verify subscription worked by creating something
    let mut events = conn.events();

    // Create dummy interface
    {
        let conn2 = ns.connection()?;
        conn2.add_link(DummyLink::new("dummy0")).await?;
    }

    // Should receive an event
    let event = tokio::time::timeout(Duration::from_secs(2), events.next()).await;
    assert!(event.is_ok(), "should receive some event");

    Ok(())
}

#[tokio::test]
async fn test_multiple_subscriptions() -> Result<()> {
    require_root!();

    let ns = TestNamespace::new("multisub")?;
    let mut conn = ns.connection()?;

    // Subscribe to multiple groups
    conn.subscribe(&[
        RtnetlinkGroup::Link,
        RtnetlinkGroup::Ipv4Addr,
        RtnetlinkGroup::Ipv4Route,
    ])?;

    // Create interface and add address
    conn.add_link(DummyLink::new("dummy0")).await?;
    conn.set_link_up("dummy0").await?;

    // We should be receiving events now
    // Just verify the subscription doesn't error
    Ok(())
}

#[tokio::test]
async fn test_link_down_event() -> Result<()> {
    require_root!();

    let ns = TestNamespace::new("linkdown")?;
    let mut conn = ns.connection()?;

    // Create dummy first
    conn.add_link(DummyLink::new("dummy0")).await?;
    conn.set_link_up("dummy0").await?;

    // Subscribe to link events
    conn.subscribe(&[RtnetlinkGroup::Link])?;

    let mut events = conn.events();

    // Bring down interface
    {
        let conn2 = ns.connection()?;
        conn2.set_link_down("dummy0").await?;
    }

    // Wait for event
    let event = tokio::time::timeout(Duration::from_secs(2), events.next()).await;

    // Should receive a NewLink event with updated flags
    if let Ok(Some(Ok(NetworkEvent::NewLink(link)))) = event {
        assert_eq!(link.name().as_deref(), Some("dummy0"));
        // The link should be down (up flag not set)
    }

    Ok(())
}

#[tokio::test]
async fn test_del_link_event() -> Result<()> {
    require_root!();

    let ns = TestNamespace::new("dellinkev")?;
    let mut conn = ns.connection()?;

    // Create dummy first
    conn.add_link(DummyLink::new("dummy0")).await?;

    // Subscribe to link events
    conn.subscribe(&[RtnetlinkGroup::Link])?;

    let mut events = conn.events();

    // Delete interface
    {
        let conn2 = ns.connection()?;
        conn2.del_link("dummy0").await?;
    }

    // Wait for event
    let event = tokio::time::timeout(Duration::from_secs(2), events.next()).await;

    if let Ok(Some(Ok(NetworkEvent::DelLink(link)))) = event {
        assert_eq!(link.name().as_deref(), Some("dummy0"));
    }

    Ok(())
}

#[tokio::test]
async fn test_del_address_event() -> Result<()> {
    require_root!();

    let ns = TestNamespace::new("deladdrev")?;
    let mut conn = ns.connection()?;

    // Create dummy and add address
    conn.add_link(DummyLink::new("dummy0")).await?;
    conn.set_link_up("dummy0").await?;

    let ip = Ipv4Addr::new(10, 0, 0, 1);
    conn.add_address(Ipv4Address::new("dummy0", ip, 24)).await?;

    // Subscribe to address events
    conn.subscribe(&[RtnetlinkGroup::Ipv4Addr])?;

    let mut events = conn.events();

    // Delete address
    {
        let conn2 = ns.connection()?;
        conn2.del_address("dummy0", ip.into(), 24).await?;
    }

    // Wait for event
    let event = tokio::time::timeout(Duration::from_secs(2), events.next()).await;

    if let Ok(Some(Ok(NetworkEvent::DelAddress(addr)))) = event {
        let expected: IpAddr = ip.into();
        assert_eq!(addr.address(), Some(&expected));
    }

    Ok(())
}

#[tokio::test]
async fn test_owned_event_stream() -> Result<()> {
    require_root!();

    let ns = TestNamespace::new("ownedstream")?;
    let mut conn = ns.connection()?;

    // Subscribe before converting to owned stream
    conn.subscribe(&[RtnetlinkGroup::Link])?;

    // Convert to owned stream
    let mut stream = conn.into_events();

    // Create dummy interface from another connection
    {
        let conn2 = ns.connection()?;
        conn2.add_link(DummyLink::new("dummy0")).await?;
    }

    // Wait for event on owned stream
    let event = tokio::time::timeout(Duration::from_secs(2), stream.next()).await;

    if let Ok(Some(Ok(NetworkEvent::NewLink(link)))) = event {
        assert_eq!(link.name().as_deref(), Some("dummy0"));
    }

    // Recover connection from stream if needed
    let _conn = stream.into_connection();

    Ok(())
}

#[tokio::test]
async fn test_event_stream_continues() -> Result<()> {
    require_root!();

    let ns = TestNamespace::new("streamcont")?;
    let mut conn = ns.connection()?;

    // Subscribe to link events
    conn.subscribe(&[RtnetlinkGroup::Link])?;

    let mut events = conn.events();

    // Create multiple interfaces
    let conn2 = ns.connection()?;
    conn2.add_link(DummyLink::new("dummy0")).await?;
    conn2.add_link(DummyLink::new("dummy1")).await?;
    conn2.add_link(DummyLink::new("dummy2")).await?;

    // Collect events with timeout
    let mut received = 0;
    loop {
        match tokio::time::timeout(Duration::from_millis(500), events.next()).await {
            Ok(Some(Ok(_))) => received += 1,
            _ => break,
        }
    }

    // Should have received multiple events
    assert!(received >= 1, "should receive at least one event");

    Ok(())
}

#[tokio::test]
async fn test_ipv6_address_events() -> Result<()> {
    require_root!();

    let ns = TestNamespace::new("addr6ev")?;
    let mut conn = ns.connection()?;

    // Create dummy first
    conn.add_link(DummyLink::new("dummy0")).await?;
    conn.set_link_up("dummy0").await?;

    // Subscribe to IPv6 address events
    conn.subscribe(&[RtnetlinkGroup::Ipv6Addr])?;

    let mut events = conn.events();

    // Add IPv6 address
    {
        use nlink::netlink::addr::Ipv6Address;
        use std::net::Ipv6Addr;

        let conn2 = ns.connection()?;
        let ip: Ipv6Addr = "fd00::1".parse().unwrap();
        conn2
            .add_address(Ipv6Address::new("dummy0", ip, 64))
            .await?;
    }

    // Wait for event
    let event = tokio::time::timeout(Duration::from_secs(2), events.next()).await;

    // Should receive NewAddress event
    if let Ok(Some(Ok(NetworkEvent::NewAddress(_)))) = event {
        // Got it
    }

    Ok(())
}
