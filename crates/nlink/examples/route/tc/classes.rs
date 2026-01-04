//! TC Class Management Example
//!
//! Demonstrates how to create and manage TC classes for traffic shaping.
//! Shows both string-based and typed builder APIs.
//!
//! Run: sudo cargo run -p nlink --example route_tc_classes

use nlink::netlink::tc::{HtbClassConfig, HtbQdiscConfig};
use nlink::netlink::{Connection, Route};

#[tokio::main]
async fn main() -> nlink::Result<()> {
    let conn = Connection::<Route>::new()?;

    // List existing classes on all interfaces
    println!("=== Existing TC Classes ===\n");
    let links = conn.get_links().await?;

    for link in &links {
        let name = link.name_or("?");
        let classes = conn.get_classes_for(name).await?;

        if !classes.is_empty() {
            println!("Interface: {}", name);
            for class in &classes {
                println!(
                    "  Class {:x}:{:x} ({})",
                    class.handle() >> 16,
                    class.handle() & 0xFFFF,
                    class.kind().unwrap_or("?")
                );
                println!(
                    "    Stats: {} bytes, {} packets",
                    class.bytes(),
                    class.packets()
                );
                println!("    Rate: {} bps, {} pps", class.bps(), class.pps());
                if class.drops() > 0 {
                    println!("    Drops: {}", class.drops());
                }
            }
            println!();
        }
    }

    // Example: Create HTB hierarchy (requires root)
    println!("=== HTB Class Hierarchy Example ===\n");
    println!("To create an HTB class hierarchy, run with sudo:\n");

    println!(
        r#"
    // Add HTB qdisc with default class
    let htb = HtbQdiscConfig::new().default_class(0x30).build();
    conn.add_qdisc_full("eth0", "root", Some("1:"), htb).await?;

    // Add root class (total bandwidth)
    conn.add_class_config("eth0", "1:0", "1:1",
        HtbClassConfig::new("1gbit")?
            .ceil("1gbit")?
            .build()
    ).await?;

    // Add high priority class
    conn.add_class_config("eth0", "1:1", "1:10",
        HtbClassConfig::new("100mbit")?
            .ceil("500mbit")?
            .prio(1)
            .build()
    ).await?;

    // Add normal priority class
    conn.add_class_config("eth0", "1:1", "1:20",
        HtbClassConfig::new("200mbit")?
            .ceil("800mbit")?
            .prio(2)
            .build()
    ).await?;

    // Add best effort class (default)
    conn.add_class_config("eth0", "1:1", "1:30",
        HtbClassConfig::new("50mbit")?
            .prio(3)
            .build()
    ).await?;
"#
    );

    // Also show the string-based API
    println!("=== Alternative String-based API ===\n");
    println!(
        r#"
    // Using string parameters (like tc command)
    conn.add_class("eth0", "1:0", "1:1", "htb",
        &["rate", "1gbit", "ceil", "1gbit"]).await?;

    conn.add_class("eth0", "1:1", "1:10", "htb",
        &["rate", "100mbit", "ceil", "500mbit", "prio", "1"]).await?;
"#
    );

    Ok(())
}
