//! MPTCP (Multipath TCP) Configuration Example
//!
//! Demonstrates MPTCP endpoint configuration via Generic Netlink.
//! MPTCP enables using multiple paths for a single TCP connection.
//!
//! Run: cargo run -p nlink --example genl_mptcp

use nlink::netlink::{Connection, Mptcp};

#[tokio::main]
async fn main() -> nlink::Result<()> {
    println!("=== MPTCP Endpoint Configuration ===\n");

    // Create MPTCP connection
    match Connection::<Mptcp>::new_async().await {
        Ok(conn) => {
            println!("MPTCP PM GENL family ID: {}\n", conn.family_id());

            // Get current limits
            match conn.get_limits().await {
                Ok(limits) => {
                    println!("Current MPTCP Limits:");
                    println!("  Max subflows: {}", limits.subflows.unwrap_or(0));
                    println!(
                        "  Max addresses accepted: {}",
                        limits.add_addr_accepted.unwrap_or(0)
                    );
                    println!();
                }
                Err(e) => println!("Could not get limits: {}\n", e),
            }

            // List configured endpoints
            match conn.get_endpoints().await {
                Ok(endpoints) => {
                    if endpoints.is_empty() {
                        println!("No MPTCP endpoints configured.\n");
                    } else {
                        println!("Configured Endpoints:");
                        for ep in &endpoints {
                            print!("  ID {}: {}", ep.id, ep.address);
                            if let Some(port) = ep.port {
                                print!(":{}", port);
                            }
                            if let Some(ifindex) = ep.ifindex {
                                print!(" (ifindex {})", ifindex);
                            }
                            print!(" flags=[");
                            let mut flags = Vec::new();
                            if ep.flags.signal {
                                flags.push("signal");
                            }
                            if ep.flags.subflow {
                                flags.push("subflow");
                            }
                            if ep.flags.backup {
                                flags.push("backup");
                            }
                            if ep.flags.fullmesh {
                                flags.push("fullmesh");
                            }
                            print!("{}]", flags.join(","));
                            println!();
                        }
                        println!();
                    }
                }
                Err(e) => println!("Could not list endpoints: {}\n", e),
            }
        }
        Err(e) => {
            println!("MPTCP GENL not available: {}\n", e);
            println!("MPTCP requires Linux 5.6+ with CONFIG_MPTCP enabled.");
            println!();
            println!("Check MPTCP availability:");
            println!("  cat /proc/sys/net/mptcp/enabled");
            println!();
            println!("Enable MPTCP:");
            println!("  sudo sysctl net.mptcp.enabled=1");
            println!();
        }
    }

    // Example MPTCP configurations
    println!("=== MPTCP Configuration Examples ===\n");

    println!("--- Enable MPTCP ---");
    println!(
        r#"
    # Enable MPTCP globally
    sudo sysctl net.mptcp.enabled=1

    # Check if enabled
    cat /proc/sys/net/mptcp/enabled
"#
    );

    println!("--- Add MPTCP endpoint ---");
    println!(
        r#"
    use nlink::netlink::{{Connection, Mptcp}};
    use nlink::netlink::genl::mptcp::MptcpEndpointBuilder;

    let conn = Connection::<Mptcp>::new_async().await?;

    // Add endpoint for second interface (signal + subflow)
    // This advertises the address AND creates subflows
    conn.add_endpoint(
        MptcpEndpointBuilder::new("192.168.2.1".parse()?)
            .id(1)          // Endpoint ID (1-255)
            .dev("eth1")    // Bind to interface
            .subflow()      // Create subflows through this address
            .signal()       // Advertise to peer
    ).await?;

    // Add backup endpoint (used when primary fails)
    conn.add_endpoint(
        MptcpEndpointBuilder::new("10.0.0.1".parse()?)
            .id(2)
            .dev("wlan0")
            .backup()       // Use as backup only
            .signal()
    ).await?;

    // Add fullmesh endpoint (connect to all peer addresses)
    conn.add_endpoint(
        MptcpEndpointBuilder::new("192.168.3.1".parse()?)
            .id(3)
            .dev("eth2")
            .fullmesh()
    ).await?;
"#
    );

    println!("--- Set MPTCP limits ---");
    println!(
        r#"
    use nlink::netlink::genl::mptcp::MptcpLimits;

    // Configure maximum subflows and accepted addresses
    conn.set_limits(
        MptcpLimits::new()
            .subflows(4)           // Max subflows per connection
            .add_addr_accepted(4)  // Max addresses to accept from peers
    ).await?;

    // Get current limits
    let limits = conn.get_limits().await?;
    println!("Max subflows: {:?}", limits.subflows);
"#
    );

    println!("--- Update endpoint flags ---");
    println!(
        r#"
    use nlink::netlink::genl::mptcp::MptcpFlags;

    // Change endpoint to backup mode
    conn.set_endpoint_flags(1, MptcpFlags {
        backup: true,
        ..Default::default()
    }).await?;
"#
    );

    println!("--- Delete endpoints ---");
    println!(
        r#"
    // Delete specific endpoint by ID
    conn.del_endpoint(1).await?;

    // Flush all endpoints
    conn.flush_endpoints().await?;
"#
    );

    println!("--- List endpoints ---");
    println!(
        r#"
    let endpoints = conn.get_endpoints().await?;
    for ep in &endpoints {
        println!("ID {}: {} {:?}", ep.id, ep.address, ep.flags);
    }
"#
    );

    println!("=== MPTCP Use Cases ===\n");
    println!("1. Mobile devices - Seamless handover between WiFi and cellular");
    println!("2. Data centers - Bandwidth aggregation across multiple NICs");
    println!("3. High availability - Automatic failover to backup paths");
    println!("4. Load balancing - Distribute traffic across multiple paths");
    println!();

    println!("=== MPTCP Flags Explained ===\n");
    println!("signal   - Advertise this address to the peer");
    println!("subflow  - Create subflows using this address");
    println!("backup   - Use only when primary paths fail");
    println!("fullmesh - Connect to all peer-announced addresses");
    println!();

    println!("=== Verifying MPTCP ===\n");
    println!(
        r#"
    # Check if connection is using MPTCP
    ss -tMin | grep mptcp

    # Monitor MPTCP subflows
    ip mptcp monitor

    # Show endpoint configuration
    ip mptcp endpoint show
"#
    );

    Ok(())
}
