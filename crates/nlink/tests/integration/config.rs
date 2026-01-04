//! Integration tests for declarative network configuration.

use nlink::Result;
use nlink::netlink::config::{ApplyOptions, DeclaredLinkType, LinkState, NetworkConfig};
use nlink::netlink::link::DummyLink;

use crate::common::TestNamespace;

// ============================================================================
// Unit Tests (no namespace required)
// ============================================================================

#[test]
fn test_network_config_builder() {
    let config = NetworkConfig::new()
        .link("dummy0", |l| l.dummy().up())
        .link("br0", |l| l.bridge().up().mtu(9000));

    assert_eq!(config.links().len(), 2);
    assert_eq!(config.links()[0].name(), "dummy0");
    assert_eq!(config.links()[0].link_type(), &DeclaredLinkType::Dummy);
    assert_eq!(config.links()[0].state(), LinkState::Up);

    assert_eq!(config.links()[1].name(), "br0");
    assert_eq!(config.links()[1].link_type(), &DeclaredLinkType::Bridge);
    assert_eq!(config.links()[1].mtu(), Some(9000));
}

#[test]
fn test_address_parsing() {
    let config = NetworkConfig::new()
        .address("eth0", "192.168.1.1/24")
        .unwrap()
        .address("eth0", "2001:db8::1/64")
        .unwrap();

    assert_eq!(config.addresses().len(), 2);

    let addr1 = &config.addresses()[0];
    assert_eq!(addr1.dev(), "eth0");
    assert!(addr1.is_ipv4());
    assert_eq!(addr1.prefix_len(), 24);

    let addr2 = &config.addresses()[1];
    assert!(addr2.is_ipv6());
    assert_eq!(addr2.prefix_len(), 64);
}

#[test]
fn test_address_parsing_errors() {
    // Missing prefix
    let result = NetworkConfig::new().address("eth0", "192.168.1.1");
    assert!(result.is_err());

    // Invalid address
    let result = NetworkConfig::new().address("eth0", "invalid/24");
    assert!(result.is_err());

    // Invalid prefix
    let result = NetworkConfig::new().address("eth0", "192.168.1.1/abc");
    assert!(result.is_err());

    // Prefix too large for IPv4
    let result = NetworkConfig::new().address("eth0", "192.168.1.1/33");
    assert!(result.is_err());
}

#[test]
fn test_route_parsing() {
    let config = NetworkConfig::new()
        .route("10.0.0.0/8", |r| r.via("192.168.1.1").dev("eth0"))
        .unwrap()
        .route("0.0.0.0/0", |r| r.via("192.168.1.254"))
        .unwrap();

    assert_eq!(config.routes().len(), 2);

    let route1 = &config.routes()[0];
    assert!(route1.is_ipv4());
    assert_eq!(route1.prefix_len(), 8);
    assert!(route1.gateway().is_some());
    assert_eq!(route1.dev(), Some("eth0"));

    let route2 = &config.routes()[1];
    assert_eq!(route2.prefix_len(), 0); // default route
}

#[test]
fn test_route_parsing_errors() {
    // Missing prefix
    let result = NetworkConfig::new().route("10.0.0.0", |r| r);
    assert!(result.is_err());

    // Invalid destination
    let result = NetworkConfig::new().route("invalid/8", |r| r);
    assert!(result.is_err());
}

#[test]
fn test_qdisc_builder() {
    let config = NetworkConfig::new()
        .qdisc("eth0", |q| q.netem().delay_ms(100).loss(1.0))
        .qdisc("eth1", |q| q.htb().default_class(0x30));

    assert_eq!(config.qdiscs().len(), 2);
    assert_eq!(config.qdiscs()[0].dev(), "eth0");
    assert_eq!(config.qdiscs()[0].qdisc_type().kind(), "netem");
    assert_eq!(config.qdiscs()[1].qdisc_type().kind(), "htb");
}

#[test]
fn test_veth_link_builder() {
    let config = NetworkConfig::new().link("veth0", |l| l.veth("veth1").master("br0").up());

    let link = &config.links()[0];
    assert_eq!(link.name(), "veth0");
    assert!(matches!(
        link.link_type(),
        DeclaredLinkType::Veth { peer } if peer == "veth1"
    ));
    assert_eq!(link.master(), Some("br0"));
    assert_eq!(link.state(), LinkState::Up);
}

#[test]
fn test_vlan_link_builder() {
    let config = NetworkConfig::new().link("eth0.100", |l| l.vlan("eth0", 100).up());

    let link = &config.links()[0];
    assert!(matches!(
        link.link_type(),
        DeclaredLinkType::Vlan { parent, vlan_id } if parent == "eth0" && *vlan_id == 100
    ));
}

// ============================================================================
// Integration Tests (require namespace)
// ============================================================================

#[tokio::test]
async fn test_config_diff_empty_namespace() -> Result<()> {
    require_root!();

    let ns = TestNamespace::new("config-diff")?;
    let conn = ns.connection()?;

    // Empty config against empty namespace should have no changes
    let config = NetworkConfig::new();
    let diff = config.diff(&conn).await?;

    assert!(diff.is_empty());
    assert_eq!(diff.change_count(), 0);
    Ok(())
}

#[tokio::test]
async fn test_config_diff_detects_missing_link() -> Result<()> {
    require_root!();

    let ns = TestNamespace::new("config-diff-link")?;
    let conn = ns.connection()?;

    // Config wants a dummy interface that doesn't exist
    let config = NetworkConfig::new().link("dummy0", |l| l.dummy().up());

    let diff = config.diff(&conn).await?;

    assert!(!diff.is_empty());
    assert_eq!(diff.links_to_add.len(), 1);
    assert_eq!(diff.links_to_add[0].name(), "dummy0");
    Ok(())
}

#[tokio::test]
async fn test_config_diff_detects_existing_link() -> Result<()> {
    require_root!();

    let ns = TestNamespace::new("config-diff-existing")?;
    let conn = ns.connection()?;

    // Create the interface first
    conn.add_link(DummyLink::new("dummy0")).await?;

    // Config wants the same interface
    let config = NetworkConfig::new().link("dummy0", |l| l.dummy());

    let diff = config.diff(&conn).await?;

    // Interface already exists, no creation needed
    assert!(diff.links_to_add.is_empty());
    Ok(())
}

#[tokio::test]
async fn test_config_diff_detects_state_change() -> Result<()> {
    require_root!();

    let ns = TestNamespace::new("config-diff-state")?;
    let conn = ns.connection()?;

    // Create interface in down state
    conn.add_link(DummyLink::new("dummy0")).await?;

    // Config wants it up
    let config = NetworkConfig::new().link("dummy0", |l| l.dummy().up());

    let diff = config.diff(&conn).await?;

    // Should detect need to bring interface up
    assert_eq!(diff.links_to_modify.len(), 1);
    assert_eq!(diff.links_to_modify[0].0, "dummy0");
    assert!(diff.links_to_modify[0].1.set_up);
    Ok(())
}

#[tokio::test]
async fn test_config_apply_creates_link() -> Result<()> {
    require_root!();

    let ns = TestNamespace::new("config-apply-link")?;
    let conn = ns.connection()?;

    let config = NetworkConfig::new().link("dummy0", |l| l.dummy().up());

    let result = config.apply(&conn).await?;

    assert!(result.is_success());
    assert!(result.changes_made > 0);

    // Verify the interface was created
    let link = conn.get_link_by_name("dummy0").await?;
    assert!(link.is_some());
    Ok(())
}

#[tokio::test]
async fn test_config_apply_creates_address() -> Result<()> {
    require_root!();

    let ns = TestNamespace::new("config-apply-addr")?;
    let conn = ns.connection()?;

    // Create interface first
    conn.add_link(DummyLink::new("dummy0")).await?;
    conn.set_link_up("dummy0").await?;

    let config = NetworkConfig::new()
        .address("dummy0", "192.168.100.1/24")
        .unwrap();

    let result = config.apply(&conn).await?;

    assert!(result.is_success());

    // Verify address was added
    let addrs = conn.get_addresses_for("dummy0").await?;
    assert!(!addrs.is_empty());
    Ok(())
}

#[tokio::test]
async fn test_config_apply_idempotent() -> Result<()> {
    require_root!();

    let ns = TestNamespace::new("config-idempotent")?;
    let conn = ns.connection()?;

    let config = NetworkConfig::new()
        .link("dummy0", |l| l.dummy().up())
        .address("dummy0", "10.0.0.1/24")
        .unwrap();

    // First apply
    let result1 = config.apply(&conn).await?;
    assert!(result1.changes_made > 0);

    // Second apply should be a no-op
    let result2 = config.apply(&conn).await?;
    assert_eq!(result2.changes_made, 0);
    Ok(())
}

#[tokio::test]
async fn test_config_dry_run() -> Result<()> {
    require_root!();

    let ns = TestNamespace::new("config-dryrun")?;
    let conn = ns.connection()?;

    let config = NetworkConfig::new().link("dummy0", |l| l.dummy());

    let result = config
        .apply_with_options(
            &conn,
            ApplyOptions {
                dry_run: true,
                ..Default::default()
            },
        )
        .await?;

    // Should report changes but not apply them
    assert!(result.changes_made > 0);

    // Interface should NOT exist
    let link = conn.get_link_by_name("dummy0").await?;
    assert!(link.is_none());
    Ok(())
}

#[tokio::test]
async fn test_config_apply_bridge_with_port() -> Result<()> {
    require_root!();

    let ns = TestNamespace::new("config-bridge")?;
    let conn = ns.connection()?;

    let config = NetworkConfig::new()
        .link("br0", |l| l.bridge().up())
        .link("dummy0", |l| l.dummy().master("br0").up());

    let result = config.apply(&conn).await?;
    assert!(result.is_success());

    // Verify bridge was created
    let br = conn.get_link_by_name("br0").await?;
    assert!(br.is_some());

    // Verify dummy was created and attached to bridge
    let dummy = conn.get_link_by_name("dummy0").await?;
    assert!(dummy.is_some());
    assert!(dummy.unwrap().master().is_some());
    Ok(())
}

#[tokio::test]
async fn test_config_diff_summary() -> Result<()> {
    require_root!();

    let ns = TestNamespace::new("config-summary")?;
    let conn = ns.connection()?;

    let config = NetworkConfig::new()
        .link("dummy0", |l| l.dummy().up())
        .address("dummy0", "10.0.0.1/24")
        .unwrap();

    let diff = config.diff(&conn).await?;
    let summary = diff.summary();

    assert!(summary.contains("dummy0"));
    assert!(summary.contains("10.0.0.1/24"));
    Ok(())
}

#[tokio::test]
async fn test_config_apply_qdisc() -> Result<()> {
    require_root!();

    let ns = TestNamespace::new("config-qdisc")?;
    let conn = ns.connection()?;

    // Create interface
    conn.add_link(DummyLink::new("dummy0")).await?;
    conn.set_link_up("dummy0").await?;

    let config = NetworkConfig::new().qdisc("dummy0", |q| q.netem().delay_ms(50));

    let result = config.apply(&conn).await?;
    assert!(result.is_success());

    // Verify qdisc was added
    let qdiscs = conn.get_qdiscs_for("dummy0").await?;
    let netem = qdiscs.iter().find(|q| q.kind() == Some("netem"));
    assert!(netem.is_some());
    Ok(())
}
