//! TC Filter Chains Example
//!
//! Demonstrates how to use TC filter chains for organizing filters.
//! Chains allow jumping between filter groups for complex classification.
//!
//! Run: cargo run -p nlink --example route_tc_chains

use nlink::netlink::{Connection, Route};

#[tokio::main]
async fn main() -> nlink::Result<()> {
    let conn = Connection::<Route>::new()?;

    // List existing chains on all interfaces
    println!("=== Existing TC Chains ===\n");
    let links = conn.get_links().await?;

    for link in &links {
        let name = link.name_or("?");

        // Check ingress chains
        if let Ok(chains) = conn.get_tc_chains(name, "ingress").await {
            if !chains.is_empty() {
                println!("Interface: {} (ingress)", name);
                for chain in &chains {
                    println!("  Chain {}", chain);
                }
                println!();
            }
        }

        // Check root chains
        if let Ok(chains) = conn.get_tc_chains(name, "root").await {
            if !chains.is_empty() {
                println!("Interface: {} (egress/root)", name);
                for chain in &chains {
                    println!("  Chain {}", chain);
                }
                println!();
            }
        }
    }

    // Example chain configuration
    println!("=== TC Chain Configuration Example ===\n");

    println!("Filter chains allow organizing filters into numbered groups.");
    println!("Filters can jump between chains using goto_chain action.\n");

    println!(
        r#"
    use nlink::netlink::tc::IngressConfig;
    use nlink::netlink::filter::FlowerFilter;
    use nlink::netlink::action::GactAction;

    // Add ingress qdisc
    conn.add_qdisc("eth0", IngressConfig::new()).await?;

    // Create filter chains
    conn.add_tc_chain("eth0", "ingress", 0).await?;    // Default chain
    conn.add_tc_chain("eth0", "ingress", 100).await?;  // TCP processing
    conn.add_tc_chain("eth0", "ingress", 200).await?;  // UDP processing

    // Chain 0: Initial classification
    // Jump to chain 100 for TCP traffic
    let filter = FlowerFilter::new()
        .chain(0)
        .ip_proto_tcp()
        .goto_chain(100)
        .build();
    conn.add_filter("eth0", "ingress", filter).await?;

    // Jump to chain 200 for UDP traffic
    let filter = FlowerFilter::new()
        .chain(0)
        .ip_proto_udp()
        .goto_chain(200)
        .build();
    conn.add_filter("eth0", "ingress", filter).await?;

    // Chain 100: TCP processing
    // Drop traffic to port 80 (HTTP blocked)
    let filter = FlowerFilter::new()
        .chain(100)
        .dst_port(80)
        .build()
        .with_action(GactAction::drop());
    conn.add_filter("eth0", "ingress", filter).await?;

    // Chain 200: UDP processing
    // Rate limit DNS traffic
    let filter = FlowerFilter::new()
        .chain(200)
        .dst_port(53)
        .build()
        .with_action(PoliceAction::new()
            .rate(1_000_000)  // 1 Mbps
            .burst(10000)
            .exceed_drop()
            .build());
    conn.add_filter("eth0", "ingress", filter).await?;

    // List chains
    let chains = conn.get_tc_chains("eth0", "ingress").await?;
    for chain in chains {
        println!("Chain: {}", chain);
    }

    // Delete a chain (filters must be removed first)
    conn.flush_filters("eth0", "ingress").await?;
    conn.del_tc_chain("eth0", "ingress", 200).await?;
"#
    );

    println!("\n=== GactAction goto_chain ===\n");
    println!(
        r#"
    use nlink::netlink::action::GactAction;

    // Create goto_chain action
    let goto = GactAction::goto_chain(100);

    // Use with a filter
    let filter = MatchallFilter::new()
        .actions(ActionList::new().with(goto))
        .build();
"#
    );

    Ok(())
}
