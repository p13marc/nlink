//! nftables firewall management example.
//!
//! Demonstrates creating tables, chains, rules, and sets using
//! the Connection<Nftables> API.
//!
//! Run with: cargo run -p nlink --example nftables_firewall
//!
//! Requires root privileges.

use nlink::netlink::nftables::{
    Chain, ChainType, CtState, Family, Hook, Policy, Priority, Rule, Set, SetElement, SetKeyType,
};
use nlink::netlink::{Connection, Nftables};
use std::net::Ipv4Addr;

#[tokio::main]
async fn main() -> nlink::netlink::Result<()> {
    let conn = Connection::<Nftables>::new()?;

    // List existing tables
    println!("=== Existing Tables ===");
    let tables = conn.list_tables().await?;
    for table in &tables {
        println!("  {} ({:?})", table.name, table.family);
    }

    // Create a filter table with input chain
    println!("\n=== Creating Firewall ===");

    conn.add_table("example", Family::Inet).await?;
    println!("Created table: example");

    conn.add_chain(
        Chain::new("example", "input")
            .family(Family::Inet)
            .hook(Hook::Input)
            .chain_type(ChainType::Filter)
            .priority(Priority::Filter)
            .policy(Policy::Drop),
    )
    .await?;
    println!("Created chain: input (policy drop)");

    // Allow established/related connections
    conn.add_rule(
        Rule::new("example", "input")
            .family(Family::Inet)
            .match_ct_state(CtState::ESTABLISHED | CtState::RELATED)
            .accept(),
    )
    .await?;
    println!("Added rule: allow established/related");

    // Allow SSH
    conn.add_rule(
        Rule::new("example", "input")
            .family(Family::Inet)
            .match_tcp_dport(22)
            .counter()
            .accept(),
    )
    .await?;
    println!("Added rule: allow SSH (port 22)");

    // Create a set of allowed IPs
    conn.add_set(
        Set::new("example", "allowed_ips")
            .family(Family::Inet)
            .key_type(SetKeyType::Ipv4Addr),
    )
    .await?;

    conn.add_set_elements(
        "example",
        "allowed_ips",
        Family::Inet,
        &[
            SetElement::ipv4(Ipv4Addr::new(10, 0, 0, 1)),
            SetElement::ipv4(Ipv4Addr::new(192, 168, 1, 0)),
        ],
    )
    .await?;
    println!("Created set: allowed_ips with 2 entries");

    // List rules
    println!("\n=== Rules ===");
    let rules = conn.list_rules("example", Family::Inet).await?;
    for rule in &rules {
        println!("  chain={} handle={}", rule.chain, rule.handle);
    }

    // Cleanup
    conn.flush_table("example", Family::Inet).await?;
    conn.del_table("example", Family::Inet).await?;
    println!("\nCleaned up example table.");

    Ok(())
}
