//! TC Actions Example
//!
//! Demonstrates various TC actions that can be attached to filters.
//! Actions control what happens to matched packets.
//!
//! Run: cargo run -p nlink --example route_tc_actions

fn main() {
    println!("=== TC Actions Examples ===\n");

    println!("TC actions are attached to filters to control packet handling.\n");

    println!("--- GactAction (generic action) ---");
    println!(
        r#"
    use nlink::netlink::action::GactAction;

    // Pass the packet (continue processing)
    let pass = GactAction::pass();

    // Drop the packet
    let drop = GactAction::drop();

    // Continue to next filter
    let cont = GactAction::continue_();

    // Pipe to next action
    let pipe = GactAction::pipe();

    // Jump to another chain
    let goto = GactAction::goto_chain(100);

    // Steal the packet (for redirecting)
    let steal = GactAction::stolen();
"#
    );

    println!("--- MirredAction (mirror/redirect) ---");
    println!(
        r#"
    use nlink::netlink::action::MirredAction;

    // Mirror egress traffic to another interface
    let mirror = MirredAction::mirror_egress("eth1");

    // Redirect to another interface
    let redirect = MirredAction::redirect_egress("eth1");

    // Mirror ingress (for monitoring)
    let mirror_in = MirredAction::mirror_ingress("mon0");
"#
    );

    println!("--- PoliceAction (rate limiting) ---");
    println!(
        r#"
    use nlink::netlink::action::PoliceAction;

    // Rate limit to 1 Mbps, drop excess
    let police = PoliceAction::new()
        .rate(1_000_000)     // 1 Mbps
        .burst(10000)        // 10KB burst
        .exceed_drop()       // Drop excess
        .build();

    // Rate limit with conform/exceed actions
    let police = PoliceAction::new()
        .rate(10_000_000)    // 10 Mbps
        .burst(64000)        // 64KB burst
        .exceed_drop()
        .conform_pass()
        .build();
"#
    );

    println!("--- NatAction (network address translation) ---");
    println!(
        r#"
    use nlink::netlink::action::NatAction;
    use std::net::Ipv4Addr;

    // Source NAT: 10.0.0.0/8 -> 192.168.1.1
    let snat = NatAction::snat(
        Ipv4Addr::new(10, 0, 0, 0),
        Ipv4Addr::new(192, 168, 1, 1),
    ).prefix(8);

    // Destination NAT
    let dnat = NatAction::dnat(
        Ipv4Addr::new(192, 168, 1, 1),
        Ipv4Addr::new(10, 0, 0, 1),
    );
"#
    );

    println!("--- VlanAction (VLAN tag manipulation) ---");
    println!(
        r#"
    use nlink::netlink::action::VlanAction;

    // Push VLAN tag
    let push = VlanAction::push(100);  // VLAN ID 100

    // Pop VLAN tag
    let pop = VlanAction::pop();

    // Modify VLAN tag
    let modify = VlanAction::modify(200);
"#
    );

    println!("--- TunnelKeyAction (tunnel encapsulation) ---");
    println!(
        r#"
    use nlink::netlink::action::TunnelKeyAction;
    use std::net::Ipv4Addr;

    // Set tunnel key (for VXLAN/Geneve hardware offload)
    let tunnel_set = TunnelKeyAction::set()
        .src(Ipv4Addr::new(192, 168, 1, 1))
        .dst(Ipv4Addr::new(192, 168, 1, 2))
        .key_id(100)      // VNI
        .dst_port(4789)   // VXLAN port
        .ttl(64)
        .no_csum()
        .build();

    // Release tunnel key (after decapsulation)
    let tunnel_release = TunnelKeyAction::release();
"#
    );

    println!("--- SkbeditAction (socket buffer editing) ---");
    println!(
        r#"
    use nlink::netlink::action::SkbeditAction;

    // Set packet priority
    let prio = SkbeditAction::new()
        .priority(7)
        .build();

    // Set queue mapping
    let queue = SkbeditAction::new()
        .queue_mapping(2)
        .build();

    // Set mark
    let mark = SkbeditAction::new()
        .mark(0x100)
        .build();
"#
    );

    println!("--- ConnmarkAction (connection tracking marks) ---");
    println!(
        r#"
    use nlink::netlink::action::ConnmarkAction;

    // Save packet mark to connection
    let save = ConnmarkAction::save().zone(1);

    // Restore connection mark to packet
    let restore = ConnmarkAction::restore().zone(1);
"#
    );

    println!("--- CsumAction (checksum recalculation) ---");
    println!(
        r#"
    use nlink::netlink::action::CsumAction;

    // Recalculate checksums after packet modification
    let csum = CsumAction::new()
        .iph()    // IP header checksum
        .tcp()    // TCP checksum
        .udp();   // UDP checksum
"#
    );

    println!("--- SampleAction (packet sampling) ---");
    println!(
        r#"
    use nlink::netlink::action::SampleAction;

    // Sample 1 in 100 packets for monitoring (sFlow)
    let sample = SampleAction::new()
        .rate(100)       // Sample 1 in 100
        .group(5)        // PSAMPLE group ID
        .trunc(128);     // Truncate to 128 bytes
"#
    );

    println!("--- CtAction (connection tracking) ---");
    println!(
        r#"
    use nlink::netlink::action::CtAction;
    use std::net::Ipv4Addr;

    // Commit connection with SNAT
    let ct = CtAction::commit()
        .zone(1)
        .mark(0x100)
        .nat_src(Ipv4Addr::new(192, 168, 1, 1))
        .nat_src_port_range(1024, 65535);

    // Commit with DNAT
    let dnat_ct = CtAction::commit()
        .zone(1)
        .nat_dst(Ipv4Addr::new(10, 0, 0, 1))
        .nat_dst_port(8080);
"#
    );

    println!("--- PeditAction (packet header editing) ---");
    println!(
        r#"
    use nlink::netlink::action::PeditAction;
    use std::net::Ipv4Addr;

    // Rewrite packet headers
    let pedit = PeditAction::new()
        .set_ipv4_src(Ipv4Addr::new(10, 0, 0, 1))
        .set_ipv4_dst(Ipv4Addr::new(10, 0, 0, 2))
        .set_tcp_sport(8080)
        .set_tcp_dport(80)
        .set_eth_src([0x00, 0x11, 0x22, 0x33, 0x44, 0x55])
        .set_eth_dst([0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb]);
"#
    );

    println!("--- ActionList (combining actions) ---");
    println!(
        r#"
    use nlink::netlink::action::{ActionList, GactAction, PoliceAction, MirredAction};
    use nlink::netlink::filter::MatchallFilter;

    // Chain multiple actions
    let actions = ActionList::new()
        .with(PoliceAction::new()
            .rate(1_000_000)
            .burst(10000)
            .exceed_drop()
            .build())
        .with(MirredAction::mirror_egress("mon0"))
        .with(GactAction::pass());

    // Attach to a filter
    let filter = MatchallFilter::new()
        .actions(actions)
        .build();
    conn.add_filter("eth0", "ingress", filter).await?;
"#
    );
}
