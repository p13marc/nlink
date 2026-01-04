//! Route integration tests.
//!
//! Tests for route management using network namespaces.

use nlink::netlink::addr::Ipv4Address;
use nlink::netlink::link::DummyLink;
use nlink::netlink::route::{Ipv4Route, Ipv6Route, NextHop, RouteMetrics};
use nlink::netlink::types::route::RouteType;
use nlink::{Connection, Result, Route};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::common::TestNamespace;

/// Set up a namespace with a dummy interface and address.
async fn setup_routed_ns(name: &str) -> Result<(TestNamespace, Connection<Route>)> {
    let ns = TestNamespace::new(name)?;
    let conn = ns.connection()?;

    // Create dummy interface
    conn.add_link(DummyLink::new("dummy0")).await?;
    conn.set_link_up("dummy0").await?;

    // Add IP address
    conn.add_address(Ipv4Address::new(
        "dummy0",
        Ipv4Addr::new(192, 168, 1, 1),
        24,
    ))
    .await?;

    Ok((ns, conn))
}

#[tokio::test]
async fn test_add_route_via_interface() -> Result<()> {
    require_root!();

    let (_ns, conn) = setup_routed_ns("rtdev").await?;

    // Add route via interface
    conn.add_route(Ipv4Route::new("10.0.0.0", 8).dev("dummy0"))
        .await?;

    // Verify route exists
    let routes = conn.get_routes().await?;
    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0));
    let route = routes
        .iter()
        .find(|r| r.destination() == Some(&target) && r.dst_len() == 8);
    assert!(route.is_some(), "route should exist");

    Ok(())
}

#[tokio::test]
async fn test_add_route_via_gateway() -> Result<()> {
    require_root!();

    let (_ns, conn) = setup_routed_ns("rtgw").await?;

    // Add route via gateway
    conn.add_route(
        Ipv4Route::new("10.0.0.0", 8)
            .gateway(Ipv4Addr::new(192, 168, 1, 254))
            .dev("dummy0"),
    )
    .await?;

    // Verify route exists with gateway
    let routes = conn.get_routes().await?;
    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0));
    let gw = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 254));
    let route = routes
        .iter()
        .find(|r| r.destination() == Some(&target) && r.dst_len() == 8);
    assert!(route.is_some());
    assert_eq!(route.unwrap().gateway(), Some(&gw));

    Ok(())
}

#[tokio::test]
async fn test_delete_route() -> Result<()> {
    require_root!();

    let (_ns, conn) = setup_routed_ns("rtdel").await?;

    // Add route
    conn.add_route(Ipv4Route::new("10.0.0.0", 8).dev("dummy0"))
        .await?;

    // Verify it exists
    let routes = conn.get_routes().await?;
    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0));
    assert!(routes.iter().any(|r| r.destination() == Some(&target)));

    // Delete it
    conn.del_route_v4("10.0.0.0", 8).await?;

    // Verify it's gone
    let routes = conn.get_routes().await?;
    assert!(!routes.iter().any(|r| r.destination() == Some(&target)));

    Ok(())
}

#[tokio::test]
async fn test_blackhole_route() -> Result<()> {
    require_root!();

    let ns = TestNamespace::new("rtblack")?;
    let conn = ns.connection()?;

    // Add blackhole route
    conn.add_route(Ipv4Route::new("10.255.0.0", 16).route_type(RouteType::Blackhole))
        .await?;

    // Verify route exists and is blackhole
    let routes = conn.get_routes().await?;
    let target = IpAddr::V4(Ipv4Addr::new(10, 255, 0, 0));
    let route = routes
        .iter()
        .find(|r| r.destination() == Some(&target) && r.dst_len() == 16);
    assert!(route.is_some());
    assert_eq!(route.unwrap().route_type(), RouteType::Blackhole);

    Ok(())
}

#[tokio::test]
async fn test_unreachable_route() -> Result<()> {
    require_root!();

    let ns = TestNamespace::new("rtunreach")?;
    let conn = ns.connection()?;

    // Add unreachable route
    conn.add_route(Ipv4Route::new("10.254.0.0", 16).route_type(RouteType::Unreachable))
        .await?;

    // Verify
    let routes = conn.get_routes().await?;
    let target = IpAddr::V4(Ipv4Addr::new(10, 254, 0, 0));
    let route = routes
        .iter()
        .find(|r| r.destination() == Some(&target) && r.dst_len() == 16);
    assert!(route.is_some());
    assert_eq!(route.unwrap().route_type(), RouteType::Unreachable);

    Ok(())
}

#[tokio::test]
async fn test_prohibit_route() -> Result<()> {
    require_root!();

    let ns = TestNamespace::new("rtprohib")?;
    let conn = ns.connection()?;

    // Add prohibit route
    conn.add_route(Ipv4Route::new("10.253.0.0", 16).route_type(RouteType::Prohibit))
        .await?;

    // Verify
    let routes = conn.get_routes().await?;
    let target = IpAddr::V4(Ipv4Addr::new(10, 253, 0, 0));
    let route = routes
        .iter()
        .find(|r| r.destination() == Some(&target) && r.dst_len() == 16);
    assert!(route.is_some());
    assert_eq!(route.unwrap().route_type(), RouteType::Prohibit);

    Ok(())
}

#[tokio::test]
async fn test_default_route() -> Result<()> {
    require_root!();

    let (_ns, conn) = setup_routed_ns("rtdefault").await?;

    // Add default route
    conn.add_route(
        Ipv4Route::new("0.0.0.0", 0)
            .gateway(Ipv4Addr::new(192, 168, 1, 254))
            .dev("dummy0"),
    )
    .await?;

    // Verify
    let routes = conn.get_routes().await?;
    let default = routes.iter().find(|r| r.dst_len() == 0);
    assert!(default.is_some());
    let gw = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 254));
    assert_eq!(default.unwrap().gateway(), Some(&gw));

    Ok(())
}

#[tokio::test]
async fn test_ipv6_route() -> Result<()> {
    require_root!();

    let ns = TestNamespace::new("rtv6")?;
    let conn = ns.connection()?;

    // Create dummy interface
    conn.add_link(DummyLink::new("dummy0")).await?;
    conn.set_link_up("dummy0").await?;

    // Add IPv6 route
    conn.add_route(Ipv6Route::new("2001:db8:2::", 48).dev("dummy0"))
        .await?;

    // Verify
    let routes = conn.get_routes().await?;
    let target = IpAddr::V6("2001:db8:2::".parse::<Ipv6Addr>().unwrap());
    let route = routes
        .iter()
        .find(|r| r.destination() == Some(&target) && r.dst_len() == 48);
    assert!(route.is_some());

    Ok(())
}

#[tokio::test]
async fn test_route_with_source() -> Result<()> {
    require_root!();

    let (_ns, conn) = setup_routed_ns("rtsrc").await?;

    // Add route with preferred source
    conn.add_route(
        Ipv4Route::new("10.0.0.0", 8)
            .dev("dummy0")
            .prefsrc(Ipv4Addr::new(192, 168, 1, 1)),
    )
    .await?;

    // Verify source is set
    let routes = conn.get_routes().await?;
    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0));
    let route = routes
        .iter()
        .find(|r| r.destination() == Some(&target) && r.dst_len() == 8);
    assert!(route.is_some());
    let src = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
    assert_eq!(route.unwrap().prefsrc(), Some(&src));

    Ok(())
}

#[tokio::test]
async fn test_route_with_table() -> Result<()> {
    require_root!();

    let (_ns, conn) = setup_routed_ns("rttable").await?;

    // Add route to custom table
    conn.add_route(Ipv4Route::new("10.0.0.0", 8).dev("dummy0").table(100))
        .await?;

    // Get all routes including non-main tables
    // Note: get_routes() only returns main table by default
    // We verify by deleting from the specific table
    conn.del_route(Ipv4Route::new("10.0.0.0", 8).table(100))
        .await?;

    // If we got here without error, the route existed in table 100
    Ok(())
}

#[tokio::test]
async fn test_route_with_metrics() -> Result<()> {
    require_root!();

    let (_ns, conn) = setup_routed_ns("rtmetric").await?;

    // Add route with MTU metric
    conn.add_route(
        Ipv4Route::new("10.0.0.0", 8)
            .dev("dummy0")
            .metrics(RouteMetrics::new().mtu(1400)),
    )
    .await?;

    // Verify
    let routes = conn.get_routes().await?;
    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0));
    let route = routes
        .iter()
        .find(|r| r.destination() == Some(&target) && r.dst_len() == 8);
    assert!(route.is_some());

    Ok(())
}

#[tokio::test]
async fn test_multipath_route() -> Result<()> {
    require_root!();

    let ns = TestNamespace::new("rtecmp")?;
    let conn = ns.connection()?;

    // Create two dummy interfaces
    conn.add_link(DummyLink::new("dummy0")).await?;
    conn.add_link(DummyLink::new("dummy1")).await?;
    conn.set_link_up("dummy0").await?;
    conn.set_link_up("dummy1").await?;

    // Add addresses
    conn.add_address(Ipv4Address::new(
        "dummy0",
        Ipv4Addr::new(192, 168, 1, 1),
        24,
    ))
    .await?;
    conn.add_address(Ipv4Address::new(
        "dummy1",
        Ipv4Addr::new(192, 168, 2, 1),
        24,
    ))
    .await?;

    // Add multipath route
    conn.add_route(Ipv4Route::new("10.0.0.0", 8).multipath(vec![
            NextHop::new()
                .gateway_v4(Ipv4Addr::new(192, 168, 1, 254))
                .dev("dummy0")
                .weight(1),
            NextHop::new()
                .gateway_v4(Ipv4Addr::new(192, 168, 2, 254))
                .dev("dummy1")
                .weight(1),
        ]))
    .await?;

    // Verify route exists
    let routes = conn.get_routes().await?;
    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0));
    let route = routes
        .iter()
        .find(|r| r.destination() == Some(&target) && r.dst_len() == 8);
    assert!(route.is_some());

    Ok(())
}

#[tokio::test]
async fn test_replace_route() -> Result<()> {
    require_root!();

    let (_ns, conn) = setup_routed_ns("rtreplace").await?;

    // Add initial route
    conn.add_route(
        Ipv4Route::new("10.0.0.0", 8)
            .gateway(Ipv4Addr::new(192, 168, 1, 100))
            .dev("dummy0"),
    )
    .await?;

    // Replace with different gateway
    conn.replace_route(
        Ipv4Route::new("10.0.0.0", 8)
            .gateway(Ipv4Addr::new(192, 168, 1, 200))
            .dev("dummy0"),
    )
    .await?;

    // Verify only one route with new gateway
    let routes = conn.get_routes().await?;
    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0));
    let matching: Vec<_> = routes
        .iter()
        .filter(|r| r.destination() == Some(&target) && r.dst_len() == 8)
        .collect();

    assert_eq!(matching.len(), 1);
    let gw = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 200));
    assert_eq!(matching[0].gateway(), Some(&gw));

    Ok(())
}

#[tokio::test]
async fn test_connected_route_auto_created() -> Result<()> {
    require_root!();

    let ns = TestNamespace::new("rtconn")?;
    let conn = ns.connection()?;

    // Create dummy interface
    conn.add_link(DummyLink::new("dummy0")).await?;
    conn.set_link_up("dummy0").await?;

    // Add address - this should auto-create a connected route
    conn.add_address(Ipv4Address::new(
        "dummy0",
        Ipv4Addr::new(192, 168, 100, 1),
        24,
    ))
    .await?;

    // Verify connected route was created
    let routes = conn.get_routes().await?;
    let target = IpAddr::V4(Ipv4Addr::new(192, 168, 100, 0));
    let route = routes
        .iter()
        .find(|r| r.destination() == Some(&target) && r.dst_len() == 24);
    assert!(route.is_some(), "connected route should be auto-created");

    Ok(())
}

#[tokio::test]
async fn test_host_route() -> Result<()> {
    require_root!();

    let (_ns, conn) = setup_routed_ns("rthost").await?;

    // Add /32 host route
    conn.add_route(
        Ipv4Route::new("10.0.0.100", 32)
            .gateway(Ipv4Addr::new(192, 168, 1, 254))
            .dev("dummy0"),
    )
    .await?;

    // Verify
    let routes = conn.get_routes().await?;
    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 100));
    let route = routes
        .iter()
        .find(|r| r.destination() == Some(&target) && r.dst_len() == 32);
    assert!(route.is_some());

    Ok(())
}
