//! nftables firewall management example.
//!
//! Demonstrates creating tables, chains, rules, and sets using
//! the Connection<Nftables> API.
//!
//! Run with: cargo run -p nlink --example nftables_firewall
//!
//! Requires root privileges.

use std::net::Ipv4Addr;

use nlink::netlink::{
    Connection, Nftables,
    nftables::{
        Chain, ChainType, CtState, Family, Hook, LimitUnit, Policy, Priority, Rule, Set,
        SetElement, SetKeyType,
    },
};

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

    // Allow ICMP echo requests (ping)
    conn.add_rule(
        Rule::new("example", "input")
            .family(Family::Inet)
            .match_icmp_type(8) // echo-request
            .accept(),
    )
    .await?;
    println!("Added rule: allow ICMP echo-request");

    // Allow ICMPv6 neighbor discovery
    conn.add_rule(
        Rule::new("example", "input")
            .family(Family::Inet)
            .match_icmpv6_type(135) // neighbor solicitation
            .accept(),
    )
    .await?;
    println!("Added rule: allow ICMPv6 neighbor solicitation");

    // Rate-limit HTTP traffic
    conn.add_rule(
        Rule::new("example", "input")
            .family(Family::Inet)
            .match_tcp_dport(80)
            .limit(100, LimitUnit::Second)
            .accept(),
    )
    .await?;
    println!("Added rule: rate-limit HTTP (100/sec)");

    // Block traffic NOT from 10.0.0.0/8 on port 443
    conn.add_rule(
        Rule::new("example", "input")
            .family(Family::Inet)
            .match_saddr_v4_not(Ipv4Addr::new(10, 0, 0, 0), 8)
            .match_tcp_dport(443)
            .log(Some("blocked-https: "))
            .drop(),
    )
    .await?;
    println!("Added rule: block non-10.0.0.0/8 on HTTPS");

    // Match by packet mark
    conn.add_rule(
        Rule::new("example", "input")
            .family(Family::Inet)
            .match_mark(0x42)
            .accept(),
    )
    .await?;
    println!("Added rule: accept marked packets (0x42)");

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
