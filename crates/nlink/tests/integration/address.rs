//! Address integration tests.
//!
//! Tests for IP address management using network namespaces.

use nlink::Result;
use nlink::netlink::addr::{Ipv4Address, Ipv6Address};
use nlink::netlink::link::DummyLink;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::common::TestNamespace;

#[tokio::test]
async fn test_add_ipv4_address() -> Result<()> {
    require_root!();

    let ns = TestNamespace::new("addr4")?;
    let conn = ns.connection()?;

    // Create and bring up dummy interface
    conn.add_link(DummyLink::new("dummy0")).await?;
    conn.set_link_up("dummy0").await?;

    // Add IPv4 address
    let target_ip = Ipv4Addr::new(192, 168, 1, 100);
    conn.add_address(Ipv4Address::new("dummy0", target_ip, 24))
        .await?;

    // Verify address exists
    let addrs = conn.get_addresses().await?;
    let addr = addrs.iter().find(|a| {
        a.address()
            .map(|ip| *ip == IpAddr::V4(target_ip))
            .unwrap_or(false)
    });
    assert!(addr.is_some(), "address should exist");
    assert_eq!(addr.unwrap().prefix_len(), 24);

    Ok(())
}

#[tokio::test]
async fn test_add_ipv6_address() -> Result<()> {
    require_root!();

    let ns = TestNamespace::new("addr6")?;
    let conn = ns.connection()?;

    // Create and bring up dummy interface
    conn.add_link(DummyLink::new("dummy0")).await?;
    conn.set_link_up("dummy0").await?;

    // Add IPv6 address
    let ipv6: Ipv6Addr = "2001:db8::1".parse().unwrap();
    conn.add_address(Ipv6Address::new("dummy0", ipv6, 64))
        .await?;

    // Verify address exists
    let addrs = conn.get_addresses().await?;
    let addr = addrs.iter().find(|a| {
        a.address()
            .map(|ip| *ip == IpAddr::V6(ipv6))
            .unwrap_or(false)
    });
    assert!(addr.is_some(), "IPv6 address should exist");
    assert_eq!(addr.unwrap().prefix_len(), 64);

    Ok(())
}

#[tokio::test]
async fn test_delete_ipv4_address() -> Result<()> {
    require_root!();

    let ns = TestNamespace::new("deladdr4")?;
    let conn = ns.connection()?;

    // Create and bring up dummy interface
    conn.add_link(DummyLink::new("dummy0")).await?;
    conn.set_link_up("dummy0").await?;

    let ip = Ipv4Addr::new(10, 0, 0, 1);

    // Add IPv4 address
    conn.add_address(Ipv4Address::new("dummy0", ip, 24)).await?;

    // Verify it exists
    let addrs = conn.get_addresses().await?;
    assert!(addrs.iter().any(|a| a.address() == Some(&IpAddr::V4(ip))));

    // Delete it
    conn.del_address("dummy0", ip.into(), 24).await?;

    // Verify it's gone
    let addrs = conn.get_addresses().await?;
    assert!(!addrs.iter().any(|a| a.address() == Some(&IpAddr::V4(ip))));

    Ok(())
}

#[tokio::test]
async fn test_delete_ipv6_address() -> Result<()> {
    require_root!();

    let ns = TestNamespace::new("deladdr6")?;
    let conn = ns.connection()?;

    // Create and bring up dummy interface
    conn.add_link(DummyLink::new("dummy0")).await?;
    conn.set_link_up("dummy0").await?;

    let ip: Ipv6Addr = "fd00::1".parse().unwrap();

    // Add IPv6 address
    conn.add_address(Ipv6Address::new("dummy0", ip, 64)).await?;

    // Verify it exists
    let addrs = conn.get_addresses().await?;
    assert!(addrs.iter().any(|a| a.address() == Some(&IpAddr::V6(ip))));

    // Delete it
    conn.del_address("dummy0", ip.into(), 64).await?;

    // Verify it's gone
    let addrs = conn.get_addresses().await?;
    assert!(!addrs.iter().any(|a| a.address() == Some(&IpAddr::V6(ip))));

    Ok(())
}

#[tokio::test]
async fn test_multiple_addresses() -> Result<()> {
    require_root!();

    let ns = TestNamespace::new("multiaddr")?;
    let conn = ns.connection()?;

    // Create and bring up dummy interface
    conn.add_link(DummyLink::new("dummy0")).await?;
    conn.set_link_up("dummy0").await?;

    // Add multiple addresses
    let ip1 = Ipv4Addr::new(192, 168, 1, 1);
    let ip2 = Ipv4Addr::new(192, 168, 1, 2);
    let ip3 = Ipv4Addr::new(10, 0, 0, 1);

    conn.add_address(Ipv4Address::new("dummy0", ip1, 24))
        .await?;
    conn.add_address(Ipv4Address::new("dummy0", ip2, 24))
        .await?;
    conn.add_address(Ipv4Address::new("dummy0", ip3, 8)).await?;

    // Verify all exist
    let addrs = conn.get_addresses().await?;
    let dummy_addrs: Vec<_> = addrs
        .iter()
        .filter(|a| {
            a.address()
                .map(|ip| {
                    *ip == IpAddr::V4(ip1) || *ip == IpAddr::V4(ip2) || *ip == IpAddr::V4(ip3)
                })
                .unwrap_or(false)
        })
        .collect();

    assert_eq!(dummy_addrs.len(), 3);

    Ok(())
}

#[tokio::test]
async fn test_get_addresses_for_interface() -> Result<()> {
    require_root!();

    let ns = TestNamespace::new("getaddr")?;
    let conn = ns.connection()?;

    // Create two interfaces
    conn.add_link(DummyLink::new("dummy0")).await?;
    conn.add_link(DummyLink::new("dummy1")).await?;
    conn.set_link_up("dummy0").await?;
    conn.set_link_up("dummy1").await?;

    let target_ip = Ipv4Addr::new(192, 168, 1, 1);

    // Add addresses to each
    conn.add_address(Ipv4Address::new("dummy0", target_ip, 24))
        .await?;
    conn.add_address(Ipv4Address::new(
        "dummy1",
        Ipv4Addr::new(192, 168, 2, 1),
        24,
    ))
    .await?;

    // Get addresses for dummy0 only
    let addrs = conn.get_addresses_for("dummy0").await?;

    // Should only have dummy0's address (plus any link-local)
    let ipv4_addrs: Vec<_> = addrs
        .iter()
        .filter(|a| matches!(a.address(), Some(IpAddr::V4(_))))
        .collect();

    assert_eq!(ipv4_addrs.len(), 1);
    assert_eq!(ipv4_addrs[0].address(), Some(&IpAddr::V4(target_ip)));

    Ok(())
}

#[tokio::test]
async fn test_address_with_broadcast() -> Result<()> {
    require_root!();

    let ns = TestNamespace::new("bcast")?;
    let conn = ns.connection()?;

    // Create and bring up dummy interface
    conn.add_link(DummyLink::new("dummy0")).await?;
    conn.set_link_up("dummy0").await?;

    let target_ip = Ipv4Addr::new(192, 168, 1, 100);
    let bcast_ip = Ipv4Addr::new(192, 168, 1, 255);

    // Add address with explicit broadcast
    conn.add_address(Ipv4Address::new("dummy0", target_ip, 24).broadcast(bcast_ip))
        .await?;

    // Verify
    let addrs = conn.get_addresses().await?;
    let addr = addrs.iter().find(|a| {
        a.address()
            .map(|ip| *ip == IpAddr::V4(target_ip))
            .unwrap_or(false)
    });
    assert!(addr.is_some());

    // Broadcast should be set
    let addr = addr.unwrap();
    assert_eq!(addr.broadcast(), Some(&IpAddr::V4(bcast_ip)));

    Ok(())
}

#[tokio::test]
async fn test_address_with_label() -> Result<()> {
    require_root!();

    let ns = TestNamespace::new("label")?;
    let conn = ns.connection()?;

    // Create and bring up dummy interface
    conn.add_link(DummyLink::new("dummy0")).await?;
    conn.set_link_up("dummy0").await?;

    let target_ip = Ipv4Addr::new(192, 168, 1, 100);

    // Add address with label
    conn.add_address(Ipv4Address::new("dummy0", target_ip, 24).label("dummy0:web"))
        .await?;

    // Verify label is set
    let addrs = conn.get_addresses().await?;
    let addr = addrs.iter().find(|a| {
        a.address()
            .map(|ip| *ip == IpAddr::V4(target_ip))
            .unwrap_or(false)
    });
    assert!(addr.is_some());
    assert_eq!(addr.unwrap().label(), Some("dummy0:web"));

    Ok(())
}

#[tokio::test]
async fn test_replace_address() -> Result<()> {
    require_root!();

    let ns = TestNamespace::new("replace")?;
    let conn = ns.connection()?;

    // Create and bring up dummy interface
    conn.add_link(DummyLink::new("dummy0")).await?;
    conn.set_link_up("dummy0").await?;

    let ip = Ipv4Addr::new(192, 168, 1, 100);

    // Add address with one label
    conn.add_address(Ipv4Address::new("dummy0", ip, 24).label("dummy0:first"))
        .await?;

    // Replace with different label
    conn.replace_address(Ipv4Address::new("dummy0", ip, 24).label("dummy0:second"))
        .await?;

    // Verify only one address exists with new label
    let addrs = conn.get_addresses().await?;
    let matching: Vec<_> = addrs
        .iter()
        .filter(|a| a.address() == Some(&IpAddr::V4(ip)))
        .collect();

    assert_eq!(matching.len(), 1);
    assert_eq!(matching[0].label(), Some("dummy0:second"));

    Ok(())
}

#[tokio::test]
async fn test_loopback_address() -> Result<()> {
    require_root!();

    let ns = TestNamespace::new("loaddr")?;
    let conn = ns.connection()?;

    // Bring up loopback
    conn.set_link_up("lo").await?;

    let target_ip = Ipv4Addr::new(127, 0, 0, 2);

    // Add address to loopback
    conn.add_address(Ipv4Address::new("lo", target_ip, 8))
        .await?;

    // Verify
    let addrs = conn.get_addresses_for("lo").await?;
    let addr = addrs.iter().find(|a| {
        a.address()
            .map(|ip| *ip == IpAddr::V4(target_ip))
            .unwrap_or(false)
    });
    assert!(addr.is_some());

    Ok(())
}

#[tokio::test]
async fn test_address_scope() -> Result<()> {
    require_root!();

    let ns = TestNamespace::new("scope")?;
    let conn = ns.connection()?;

    // Create and bring up dummy interface
    conn.add_link(DummyLink::new("dummy0")).await?;
    conn.set_link_up("dummy0").await?;

    let global_ip = Ipv4Addr::new(192, 168, 1, 1);
    let link_ip = Ipv4Addr::new(169, 254, 1, 1);

    // Add global scope address
    conn.add_address(Ipv4Address::new("dummy0", global_ip, 24))
        .await?;

    // Add link-local address
    conn.add_address(Ipv4Address::new("dummy0", link_ip, 16))
        .await?;

    // Verify both exist
    let addrs = conn.get_addresses_for("dummy0").await?;
    let global = addrs.iter().find(|a| {
        a.address()
            .map(|ip| *ip == IpAddr::V4(global_ip))
            .unwrap_or(false)
    });
    let link = addrs.iter().find(|a| {
        a.address()
            .map(|ip| *ip == IpAddr::V4(link_ip))
            .unwrap_or(false)
    });

    assert!(global.is_some());
    assert!(link.is_some());

    Ok(())
}
