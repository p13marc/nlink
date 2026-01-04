//! Declarative Network Configuration Example
//!
//! Demonstrates how to define desired network state declaratively
//! and have nlink compute and apply the necessary changes.
//!
//! Run: cargo run -p nlink --example config_declarative

use nlink::netlink::config::{
    AddressConfig, ApplyOptions, LinkConfig, LinkType, NetworkConfig, QdiscConfig, RouteConfig,
};
use nlink::netlink::{Connection, Route};
use std::net::Ipv4Addr;

#[tokio::main]
async fn main() -> nlink::Result<()> {
    println!("=== Declarative Network Configuration ===\n");

    // Build a desired network configuration
    let config = NetworkConfig::new()
        // Define links (interfaces)
        .link(
            LinkConfig::new("dummy0")
                .link_type(LinkType::Dummy)
                .mtu(9000)
                .up(),
        )
        .link(LinkConfig::new("br0").link_type(LinkType::Bridge).up())
        // Define addresses
        .address(AddressConfig::new("dummy0", "10.0.0.1/24"))
        .address(AddressConfig::new("dummy0", "10.0.0.2/24"))
        .address(AddressConfig::new("br0", "192.168.100.1/24"))
        // Define routes
        .route(
            RouteConfig::new("10.1.0.0/16")
                .dev("dummy0")
                .gateway(Ipv4Addr::new(10, 0, 0, 254)),
        )
        // Define qdiscs
        .qdisc(QdiscConfig::fq_codel("dummy0"));

    println!("Desired Configuration:");
    println!("  Links: {}", config.links().len());
    for link in config.links() {
        println!("    - {} ({:?})", link.name(), link.link_type());
    }
    println!("  Addresses: {}", config.addresses().len());
    for addr in config.addresses() {
        println!("    - {} on {}", addr.address(), addr.dev());
    }
    println!("  Routes: {}", config.routes().len());
    for route in config.routes() {
        println!("    - {} via {:?}", route.destination(), route.gateway());
    }
    println!("  Qdiscs: {}", config.qdiscs().len());
    println!();

    // Connect and compute diff (dry-run)
    let conn = Connection::<Route>::new()?;

    println!("Computing diff against current state...\n");

    match config.diff(&conn).await {
        Ok(diff) => {
            println!("Changes needed:");
            println!("  Links to add: {}", diff.links_to_add.len());
            println!("  Links to modify: {}", diff.links_to_modify.len());
            println!("  Addresses to add: {}", diff.addresses_to_add.len());
            println!("  Addresses to remove: {}", diff.addresses_to_remove.len());
            println!("  Routes to add: {}", diff.routes_to_add.len());
            println!("  Routes to remove: {}", diff.routes_to_remove.len());
            println!("  Qdiscs to add: {}", diff.qdiscs_to_add.len());
            println!("  Qdiscs to remove: {}", diff.qdiscs_to_remove.len());

            if diff.is_empty() {
                println!("\nSystem is already in desired state.");
            }
        }
        Err(e) => println!("Error computing diff: {}", e),
    }

    println!("\n=== Configuration Examples ===\n");

    println!("--- Define network configuration ---");
    println!(
        r#"
    use nlink::netlink::config::{{
        NetworkConfig, LinkConfig, LinkType,
        AddressConfig, RouteConfig, QdiscConfig
    }};

    let config = NetworkConfig::new()
        // Dummy interface with MTU 9000
        .link(LinkConfig::new("dummy0")
            .link_type(LinkType::Dummy)
            .mtu(9000)
            .up())

        // Veth pair
        .link(LinkConfig::new("veth0")
            .link_type(LinkType::Veth { peer: "veth1".into() })
            .up())

        // Bridge with slave
        .link(LinkConfig::new("br0")
            .link_type(LinkType::Bridge)
            .up())
        .link(LinkConfig::new("veth1")
            .master("br0")
            .up())

        // VLAN interface
        .link(LinkConfig::new("eth0.100")
            .link_type(LinkType::Vlan { parent: "eth0".into(), id: 100 })
            .up())

        // IP addresses
        .address(AddressConfig::new("dummy0", "10.0.0.1/24"))
        .address(AddressConfig::new("br0", "192.168.1.1/24"))

        // Routes
        .route(RouteConfig::new("10.0.0.0/8")
            .gateway(Ipv4Addr::new(192, 168, 1, 254)))

        // Traffic control
        .qdisc(QdiscConfig::fq_codel("eth0"))
        .qdisc(QdiscConfig::netem("dummy0")
            .delay_ms(100)
            .loss_percent(1.0));
"#
    );

    println!("--- Compute diff ---");
    println!(
        r#"
    let conn = Connection::<Route>::new()?;

    // Compute what changes are needed
    let diff = config.diff(&conn).await?;

    println!("Links to add: {:?}", diff.links_to_add);
    println!("Links to modify: {:?}", diff.links_to_modify);
    println!("Links to remove: {:?}", diff.links_to_remove);
    println!("Addresses to add: {:?}", diff.addresses_to_add);
    println!("Routes to add: {:?}", diff.routes_to_add);
"#
    );

    println!("--- Apply configuration ---");
    println!(
        r#"
    // Apply with default options (fail on first error)
    config.apply(&conn).await?;

    // Apply with options
    config.apply_with_options(&conn, ApplyOptions {
        dry_run: false,      // Actually apply changes
        continue_on_error: true,  // Don't stop on first error
        delete_extra: false, // Don't remove unconfigured items
    }).await?;

    // Dry run - compute changes without applying
    let result = config.apply_with_options(&conn, ApplyOptions {
        dry_run: true,
        ..Default::default()
    }).await?;

    for change in &result.applied {
        println!("Would apply: {:?}", change);
    }
"#
    );

    println!("--- Idempotent operations ---");
    println!(
        r#"
    // Apply is idempotent - running twice has no effect
    config.apply(&conn).await?;  // First apply
    config.apply(&conn).await?;  // Second apply does nothing

    // Check if already in desired state
    let diff = config.diff(&conn).await?;
    if diff.is_empty() {
        println!("Already configured");
    }
"#
    );

    println!("=== Use Cases ===\n");
    println!("1. Infrastructure as Code - Define network in version control");
    println!("2. Container networking - Configure network namespaces");
    println!("3. Network testing - Set up test topologies");
    println!("4. Configuration management - Ensure consistent state");
    println!();

    Ok(())
}
