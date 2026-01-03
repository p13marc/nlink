//! Hierarchical Token Bucket (HTB) traffic shaping.
//!
//! This example demonstrates how to query HTB qdisc with classes
//! for bandwidth management.
//!
//! Run with: cargo run -p nlink --features tc --example tc_htb
//!
//! Examples:
//!   cargo run -p nlink --features tc --example tc_htb -- show eth0
//!   cargo run -p nlink --features tc --example tc_htb -- classes eth0

use std::env;

use nlink::netlink::tc_options::QdiscOptions;
use nlink::netlink::{Connection, Route};

#[tokio::main]
async fn main() -> nlink::netlink::Result<()> {
    let conn = Connection::<Route>::new()?;
    let args: Vec<String> = env::args().collect();

    match args.get(1).map(|s| s.as_str()) {
        Some("show") => {
            let dev = args.get(2).map(|s| s.as_str()).unwrap_or("eth0");
            show_htb(&conn, dev).await?;
        }
        Some("classes") => {
            let dev = args.get(2).map(|s| s.as_str()).unwrap_or("eth0");
            show_classes(&conn, dev).await?;
        }
        _ => {
            println!("Usage:");
            println!("  show <dev>     - Show HTB qdisc configuration");
            println!("  classes <dev>  - Show HTB classes and stats");
            println!();
            println!("Note: Use the tc binary to add HTB qdiscs and classes:");
            println!("  tc qdisc add dev eth0 --parent root htb default 10");
            println!("  tc class add dev eth0 --parent 1: --classid 1:10 htb rate 10mbit");
        }
    }

    Ok(())
}

async fn show_htb(conn: &Connection<Route>, dev: &str) -> nlink::netlink::Result<()> {
    let qdiscs = conn.get_qdiscs_for(dev).await?;

    println!("TC qdiscs on {}:", dev);
    println!("{}", "-".repeat(60));

    let mut found_htb = false;

    for qdisc in &qdiscs {
        let kind = qdisc.kind().unwrap_or("?");

        if kind == "htb" {
            found_htb = true;
            println!("qdisc htb handle {:x}:", qdisc.handle() >> 16);

            if let Some(QdiscOptions::Htb(htb)) = qdisc.options() {
                println!("  default class: {:x}", htb.default_class);
                println!("  r2q: {}", htb.rate2quantum);
                if let Some(qlen) = htb.direct_qlen {
                    println!("  direct_qlen: {}", qlen);
                }
            }

            // Show stats
            println!("  stats:");
            println!("    bytes: {}", qdisc.bytes());
            println!("    packets: {}", qdisc.packets());
            println!("    drops: {}", qdisc.drops());
            println!("    overlimits: {}", qdisc.overlimits());
            println!("    rate: {} bps, {} pps", qdisc.bps(), qdisc.pps());
        } else {
            let parent = if qdisc.is_root() {
                "root".to_string()
            } else {
                format!("{:x}:{:x}", qdisc.parent() >> 16, qdisc.parent() & 0xffff)
            };
            println!("qdisc {} parent {}", kind, parent);
        }
    }

    if !found_htb {
        println!("No HTB qdisc found on {}", dev);
        println!();
        println!("To create one:");
        println!("  tc qdisc add dev {} --parent root htb default 10", dev);
    }

    Ok(())
}

async fn show_classes(conn: &Connection<Route>, dev: &str) -> nlink::netlink::Result<()> {
    let classes = conn.get_classes_for(dev).await?;

    println!("TC classes on {}:", dev);
    println!("{}", "-".repeat(80));
    println!(
        "{:<12} {:<12} {:<12} {:>12} {:>12} {:>10}",
        "CLASSID", "PARENT", "TYPE", "BYTES", "PACKETS", "RATE"
    );

    for class in &classes {
        let kind = class.kind().unwrap_or("?");

        let classid = format!("{:x}:{:x}", class.handle() >> 16, class.handle() & 0xffff);

        let parent = if class.parent() == 0xffffffff {
            "root".to_string()
        } else {
            format!("{:x}:{:x}", class.parent() >> 16, class.parent() & 0xffff)
        };

        let rate = if class.bps() > 0 {
            format_rate(class.bps() as u64)
        } else {
            "-".to_string()
        };

        println!(
            "{:<12} {:<12} {:<12} {:>12} {:>12} {:>10}",
            classid,
            parent,
            kind,
            class.bytes(),
            class.packets(),
            rate
        );
    }

    if classes.is_empty() {
        println!("No classes found on {}", dev);
    }

    Ok(())
}

fn format_rate(bps: u64) -> String {
    if bps >= 1_000_000_000 {
        format!("{:.1}Gbps", bps as f64 / 1_000_000_000.0)
    } else if bps >= 1_000_000 {
        format!("{:.1}Mbps", bps as f64 / 1_000_000.0)
    } else if bps >= 1_000 {
        format!("{:.1}Kbps", bps as f64 / 1_000.0)
    } else {
        format!("{}bps", bps)
    }
}
