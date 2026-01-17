//! TC Filter Management Example
//!
//! Demonstrates how to create TC filters for traffic classification.
//! Shows U32, Flower, Matchall, and other filter types.
//!
//! Run: cargo run -p nlink --example route_tc_filters

use nlink::netlink::{Connection, Route};

#[tokio::main]
async fn main() -> nlink::Result<()> {
    let conn = Connection::<Route>::new()?;

    // List existing filters on all interfaces
    println!("=== Existing TC Filters ===\n");
    let links = conn.get_links().await?;

    for link in &links {
        let name = link.name_or("?");

        // Get qdiscs to find filter attach points
        let qdiscs = conn.get_qdiscs_by_name(name).await?;

        for qdisc in &qdiscs {
            let parent = qdisc.parent_str();
            let filters = conn.get_filters_by_name(name, &parent).await?;

            if !filters.is_empty() {
                println!("Interface: {} (parent {})", name, parent);
                for filter in &filters {
                    println!(
                        "  Filter prio {} proto 0x{:04x} ({})",
                        filter.priority(),
                        filter.protocol(),
                        filter.kind().unwrap_or("?")
                    );
                    if filter.chain() != 0 {
                        println!("    Chain: {}", filter.chain());
                    }
                }
                println!();
            }
        }
    }

    // Example filter configurations
    println!("=== Filter Configuration Examples ===\n");

    println!("--- U32 Filter (match specific fields) ---");
    println!(
        r#"
    use nlink::netlink::filter::U32Filter;

    // Match destination port 80 (HTTP)
    let filter = U32Filter::new()
        .classid("1:10")
        .match_dst_port(80)
        .build();
    conn.add_filter("eth0", "1:", filter).await?;

    // Match source IP 10.0.0.0/8
    let filter = U32Filter::new()
        .classid("1:20")
        .match_src_ip("10.0.0.0".parse()?, 8)
        .build();
    conn.add_filter("eth0", "1:", filter).await?;
"#
    );

    println!("--- Flower Filter (modern, flexible) ---");
    println!(
        r#"
    use nlink::netlink::filter::FlowerFilter;
    use std::net::Ipv4Addr;

    // Match TCP traffic to 192.168.1.0/24
    let filter = FlowerFilter::new()
        .classid("1:10")
        .ip_proto_tcp()
        .dst_ipv4(Ipv4Addr::new(192, 168, 1, 0), 24)
        .build();
    conn.add_filter("eth0", "1:", filter).await?;

    // Match UDP port 53 (DNS)
    let filter = FlowerFilter::new()
        .classid("1:20")
        .ip_proto_udp()
        .dst_port(53)
        .build();
    conn.add_filter("eth0", "1:", filter).await?;

    // Match VLAN tagged traffic
    let filter = FlowerFilter::new()
        .classid("1:30")
        .vlan_id(100)
        .build();
    conn.add_filter("eth0", "1:", filter).await?;
"#
    );

    println!("--- Matchall Filter (catch-all) ---");
    println!(
        r#"
    use nlink::netlink::filter::MatchallFilter;

    // Send all traffic to a specific class
    let filter = MatchallFilter::new()
        .classid("1:30")
        .build();
    conn.add_filter("eth0", "1:", filter).await?;
"#
    );

    println!("--- FW Filter (firewall mark based) ---");
    println!(
        r#"
    use nlink::netlink::filter::FwFilter;

    // Match packets with fwmark 0x10
    let filter = FwFilter::new()
        .handle(0x10)
        .classid("1:10")
        .build();
    conn.add_filter("eth0", "1:", filter).await?;
"#
    );

    println!("--- Cgroup Filter ---");
    println!(
        r#"
    use nlink::netlink::filter::CgroupFilter;
    use nlink::netlink::action::GactAction;

    // Match based on cgroup membership
    let filter = CgroupFilter::new()
        .with_action(GactAction::pass());
    conn.add_filter("eth0", "1:", filter).await?;
"#
    );

    println!("--- Flow Filter (multi-key hashing) ---");
    println!(
        r#"
    use nlink::netlink::filter::{FlowFilter, FlowKey};

    // Hash by source+destination for load balancing
    let filter = FlowFilter::new()
        .key(FlowKey::Src)
        .key(FlowKey::Dst)
        .key(FlowKey::Proto)
        .divisor(256)
        .baseclass(0x10001);  // 1:1
    conn.add_filter("eth0", "1:", filter).await?;
"#
    );

    Ok(())
}
