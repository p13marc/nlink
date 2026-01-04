//! Link integration tests.
//!
//! Tests for link creation, modification, and deletion using network namespaces.

use nlink::Result;
use nlink::netlink::link::{
    BridgeLink, DummyLink, IfbLink, IpvlanLink, MacvlanLink, MacvlanMode, VethLink, VlanLink,
    VrfLink,
};

use crate::common::TestNamespace;

#[tokio::test]
async fn test_create_dummy_interface() -> Result<()> {
    require_root!();

    let ns = TestNamespace::new("dummy")?;
    let conn = ns.connection()?;

    // Create dummy interface
    conn.add_link(DummyLink::new("dummy0")).await?;

    // Verify it exists
    let links = conn.get_links().await?;
    let dummy = links.iter().find(|l| l.name() == Some("dummy0"));
    assert!(dummy.is_some(), "dummy0 should exist");

    // Verify type
    let dummy = dummy.unwrap();
    assert_eq!(dummy.kind(), Some("dummy"));

    // Bring it up
    conn.set_link_up("dummy0").await?;

    // Verify it's up
    let links = conn.get_links().await?;
    let dummy = links.iter().find(|l| l.name() == Some("dummy0")).unwrap();
    assert!(dummy.is_up(), "dummy0 should be up");

    // Delete it
    conn.del_link("dummy0").await?;

    // Verify it's gone
    let links = conn.get_links().await?;
    assert!(
        !links.iter().any(|l| l.name() == Some("dummy0")),
        "dummy0 should be deleted"
    );

    Ok(())
}

#[tokio::test]
async fn test_create_veth_pair() -> Result<()> {
    require_root!();

    let ns = TestNamespace::new("veth")?;
    let conn = ns.connection()?;

    // Create veth pair
    conn.add_link(VethLink::new("veth0", "veth1")).await?;

    // Verify both ends exist
    let links = conn.get_links().await?;
    assert!(
        links.iter().any(|l| l.name() == Some("veth0")),
        "veth0 should exist"
    );
    assert!(
        links.iter().any(|l| l.name() == Some("veth1")),
        "veth1 should exist"
    );

    // Verify they're linked
    let veth0 = links.iter().find(|l| l.name() == Some("veth0")).unwrap();
    let veth1 = links.iter().find(|l| l.name() == Some("veth1")).unwrap();
    assert_eq!(veth0.link(), Some(veth1.ifindex()));
    assert_eq!(veth1.link(), Some(veth0.ifindex()));

    // Delete one (should delete the pair)
    conn.del_link("veth0").await?;

    // Verify both are gone
    let links = conn.get_links().await?;
    assert!(
        !links.iter().any(|l| l.name() == Some("veth0")),
        "veth0 should be deleted"
    );
    assert!(
        !links.iter().any(|l| l.name() == Some("veth1")),
        "veth1 should be deleted"
    );

    Ok(())
}

#[tokio::test]
async fn test_create_bridge() -> Result<()> {
    require_root!();

    let ns = TestNamespace::new("bridge")?;
    let conn = ns.connection()?;

    // Create a bridge
    conn.add_link(BridgeLink::new("br0").stp(false)).await?;

    // Verify it exists
    let links = conn.get_links().await?;
    let br = links.iter().find(|l| l.name() == Some("br0"));
    assert!(br.is_some(), "br0 should exist");
    assert_eq!(br.unwrap().kind(), Some("bridge"));

    // Create dummy interfaces to add to bridge
    conn.add_link(DummyLink::new("dummy0")).await?;
    conn.add_link(DummyLink::new("dummy1")).await?;

    // Add interfaces to bridge
    conn.set_link_master("dummy0", "br0").await?;
    conn.set_link_master("dummy1", "br0").await?;

    // Verify they're attached
    let links = conn.get_links().await?;
    let br = links.iter().find(|l| l.name() == Some("br0")).unwrap();
    let dummy0 = links.iter().find(|l| l.name() == Some("dummy0")).unwrap();
    let dummy1 = links.iter().find(|l| l.name() == Some("dummy1")).unwrap();

    assert_eq!(dummy0.master(), Some(br.ifindex()));
    assert_eq!(dummy1.master(), Some(br.ifindex()));

    // Remove from bridge
    conn.set_link_nomaster("dummy0").await?;

    let links = conn.get_links().await?;
    let dummy0 = links.iter().find(|l| l.name() == Some("dummy0")).unwrap();
    assert_eq!(dummy0.master(), None);

    Ok(())
}

#[tokio::test]
async fn test_create_vlan() -> Result<()> {
    require_root!();

    let ns = TestNamespace::new("vlan")?;
    let conn = ns.connection()?;

    // Create parent interface
    conn.add_link(DummyLink::new("eth0")).await?;
    conn.set_link_up("eth0").await?;

    // Create VLAN
    conn.add_link(VlanLink::new("eth0.100", "eth0", 100))
        .await?;

    // Verify it exists
    let links = conn.get_links().await?;
    let vlan = links.iter().find(|l| l.name() == Some("eth0.100"));
    assert!(vlan.is_some(), "eth0.100 should exist");
    assert_eq!(vlan.unwrap().kind(), Some("vlan"));

    // Bring it up
    conn.set_link_up("eth0.100").await?;

    // Delete
    conn.del_link("eth0.100").await?;

    let links = conn.get_links().await?;
    assert!(!links.iter().any(|l| l.name() == Some("eth0.100")));

    Ok(())
}

#[tokio::test]
async fn test_create_macvlan() -> Result<()> {
    require_root!();

    let ns = TestNamespace::new("macvlan")?;
    let conn = ns.connection()?;

    // Create parent interface
    conn.add_link(DummyLink::new("eth0")).await?;
    conn.set_link_up("eth0").await?;

    // Create macvlan in bridge mode
    conn.add_link(MacvlanLink::new("macvlan0", "eth0").mode(MacvlanMode::Bridge))
        .await?;

    // Verify it exists
    let links = conn.get_links().await?;
    let macvlan = links.iter().find(|l| l.name() == Some("macvlan0"));
    assert!(macvlan.is_some(), "macvlan0 should exist");
    assert_eq!(macvlan.unwrap().kind(), Some("macvlan"));

    Ok(())
}

#[tokio::test]
async fn test_create_ipvlan() -> Result<()> {
    require_root!();

    let ns = TestNamespace::new("ipvlan")?;
    let conn = ns.connection()?;

    // Create parent interface
    conn.add_link(DummyLink::new("eth0")).await?;
    conn.set_link_up("eth0").await?;

    // Create ipvlan
    conn.add_link(IpvlanLink::new("ipvlan0", "eth0")).await?;

    // Verify it exists
    let links = conn.get_links().await?;
    let ipvlan = links.iter().find(|l| l.name() == Some("ipvlan0"));
    assert!(ipvlan.is_some(), "ipvlan0 should exist");
    assert_eq!(ipvlan.unwrap().kind(), Some("ipvlan"));

    Ok(())
}

#[tokio::test]
async fn test_create_ifb() -> Result<()> {
    require_root!();

    let ns = TestNamespace::new("ifb")?;
    let conn = ns.connection()?;

    // Create IFB interface
    conn.add_link(IfbLink::new("ifb0")).await?;

    // Verify it exists
    let links = conn.get_links().await?;
    let ifb = links.iter().find(|l| l.name() == Some("ifb0"));
    assert!(ifb.is_some(), "ifb0 should exist");
    assert_eq!(ifb.unwrap().kind(), Some("ifb"));

    Ok(())
}

#[tokio::test]
async fn test_create_vrf() -> Result<()> {
    require_root!();

    let ns = TestNamespace::new("vrf")?;
    let conn = ns.connection()?;

    // Create VRF with routing table 100
    conn.add_link(VrfLink::new("vrf0", 100)).await?;

    // Verify it exists
    let links = conn.get_links().await?;
    let vrf = links.iter().find(|l| l.name() == Some("vrf0"));
    assert!(vrf.is_some(), "vrf0 should exist");
    assert_eq!(vrf.unwrap().kind(), Some("vrf"));

    // Create dummy and add to VRF
    conn.add_link(DummyLink::new("dummy0")).await?;
    conn.set_link_master("dummy0", "vrf0").await?;

    let links = conn.get_links().await?;
    let dummy = links.iter().find(|l| l.name() == Some("dummy0")).unwrap();
    let vrf = links.iter().find(|l| l.name() == Some("vrf0")).unwrap();
    assert_eq!(dummy.master(), Some(vrf.ifindex()));

    Ok(())
}

#[tokio::test]
async fn test_set_mtu() -> Result<()> {
    require_root!();

    let ns = TestNamespace::new("mtu")?;
    let conn = ns.connection()?;

    // Create dummy interface
    conn.add_link(DummyLink::new("dummy0")).await?;

    // Set MTU
    conn.set_link_mtu("dummy0", 9000).await?;

    // Verify
    let links = conn.get_links().await?;
    let dummy = links.iter().find(|l| l.name() == Some("dummy0")).unwrap();
    assert_eq!(dummy.mtu(), Some(9000));

    Ok(())
}

#[tokio::test]
async fn test_rename_interface() -> Result<()> {
    require_root!();

    let ns = TestNamespace::new("rename")?;
    let conn = ns.connection()?;

    // Create dummy interface
    conn.add_link(DummyLink::new("oldname")).await?;

    // Rename (interface must be down)
    conn.set_link_down("oldname").await?;
    conn.set_link_name("oldname", "newname").await?;

    // Verify
    let links = conn.get_links().await?;
    assert!(!links.iter().any(|l| l.name() == Some("oldname")));
    assert!(links.iter().any(|l| l.name() == Some("newname")));

    Ok(())
}

#[tokio::test]
async fn test_set_mac_address() -> Result<()> {
    require_root!();

    let ns = TestNamespace::new("mac")?;
    let conn = ns.connection()?;

    // Create dummy interface
    conn.add_link(DummyLink::new("dummy0")).await?;
    conn.set_link_down("dummy0").await?;

    // Set MAC address
    let new_mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
    conn.set_link_address("dummy0", new_mac).await?;

    // Verify
    let links = conn.get_links().await?;
    let dummy = links.iter().find(|l| l.name() == Some("dummy0")).unwrap();
    assert_eq!(dummy.address(), Some(new_mac.as_slice()));

    Ok(())
}

#[tokio::test]
async fn test_get_link_by_name() -> Result<()> {
    require_root!();

    let ns = TestNamespace::new("getlink")?;
    let conn = ns.connection()?;

    // Create dummy interface
    conn.add_link(DummyLink::new("dummy0")).await?;

    // Get by name
    let link = conn.get_link_by_name("dummy0").await?;
    assert!(link.is_some(), "dummy0 should exist");
    assert_eq!(link.unwrap().name(), Some("dummy0"));

    // Get non-existent should return None
    let result = conn.get_link_by_name("nonexistent").await?;
    assert!(result.is_none());

    Ok(())
}

#[tokio::test]
async fn test_get_link_by_index() -> Result<()> {
    require_root!();

    let ns = TestNamespace::new("getidx")?;
    let conn = ns.connection()?;

    // Create dummy interface
    conn.add_link(DummyLink::new("dummy0")).await?;

    // Get by name first to get index
    let link = conn
        .get_link_by_name("dummy0")
        .await?
        .expect("dummy0 should exist");
    let ifindex = link.ifindex();

    // Get by index
    let link2 = conn
        .get_link_by_index(ifindex)
        .await?
        .expect("link should exist");
    assert_eq!(link2.name(), Some("dummy0"));
    assert_eq!(link2.ifindex(), ifindex);

    Ok(())
}

#[tokio::test]
async fn test_veth_between_namespaces() -> Result<()> {
    require_root!();

    let ns1 = TestNamespace::new("veth-ns1")?;
    let ns2 = TestNamespace::new("veth-ns2")?;

    // Create veth pair between namespaces
    ns1.connect_to(&ns2, "veth0", "veth1")?;

    // Verify in ns1
    let conn1 = ns1.connection()?;
    let links1 = conn1.get_links().await?;
    assert!(links1.iter().any(|l| l.name() == Some("veth0")));
    assert!(!links1.iter().any(|l| l.name() == Some("veth1")));

    // Verify in ns2
    let conn2 = ns2.connection()?;
    let links2 = conn2.get_links().await?;
    assert!(links2.iter().any(|l| l.name() == Some("veth1")));
    assert!(!links2.iter().any(|l| l.name() == Some("veth0")));

    Ok(())
}

#[tokio::test]
async fn test_interface_flags() -> Result<()> {
    require_root!();

    let ns = TestNamespace::new("flags")?;
    let conn = ns.connection()?;

    // Create dummy interface
    conn.add_link(DummyLink::new("dummy0")).await?;

    // Initially should be down
    let links = conn.get_links().await?;
    let dummy = links.iter().find(|l| l.name() == Some("dummy0")).unwrap();
    assert!(!dummy.is_up());

    // Bring up
    conn.set_link_up("dummy0").await?;

    let links = conn.get_links().await?;
    let dummy = links.iter().find(|l| l.name() == Some("dummy0")).unwrap();
    assert!(dummy.is_up());

    // Bring down
    conn.set_link_down("dummy0").await?;

    let links = conn.get_links().await?;
    let dummy = links.iter().find(|l| l.name() == Some("dummy0")).unwrap();
    assert!(!dummy.is_up());

    Ok(())
}

#[tokio::test]
async fn test_loopback_exists() -> Result<()> {
    require_root!();

    let ns = TestNamespace::new("lo")?;
    let conn = ns.connection()?;

    // Loopback should exist in every namespace
    let links = conn.get_links().await?;
    let lo = links.iter().find(|l| l.name() == Some("lo"));
    assert!(lo.is_some(), "loopback should exist");

    let lo = lo.unwrap();
    assert!(lo.is_loopback());

    Ok(())
}
