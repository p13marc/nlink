//! Network emulation with netem.
//!
//! This example demonstrates how to configure network emulation
//! (delay, loss, corruption, etc.) using the TC netem qdisc.
//!
//! Run with: cargo run -p nlink --features tc --example tc_netem
//!
//! Requires root privileges. Uses a dummy interface for safety.
//!
//! Examples:
//!   cargo run -p nlink --features tc --example tc_netem -- show eth0
//!   sudo cargo run -p nlink --features tc --example tc_netem -- add eth0 delay 100ms
//!   sudo cargo run -p nlink --features tc --example tc_netem -- add eth0 loss 1%
//!   sudo cargo run -p nlink --features tc --example tc_netem -- del eth0

use std::env;
use std::time::Duration;

use nlink::netlink::tc::NetemConfig;
use nlink::netlink::tc_options::QdiscOptions;
use nlink::netlink::{Connection, Route};

#[tokio::main]
async fn main() -> nlink::netlink::Result<()> {
    let conn = Connection::<Route>::new()?;
    let args: Vec<String> = env::args().collect();

    match args.get(1).map(|s| s.as_str()) {
        Some("show") => {
            let dev = args.get(2).map(|s| s.as_str()).unwrap_or("eth0");
            show_netem(&conn, dev).await?;
        }
        Some("add") => {
            let dev = args.get(2).expect("usage: add <dev> <type> <value>");
            let effect = args.get(3).expect("usage: add <dev> <type> <value>");
            let value = args.get(4).expect("usage: add <dev> <type> <value>");
            add_netem(&conn, dev, effect, value).await?;
        }
        Some("del") => {
            let dev = args.get(2).expect("usage: del <dev>");
            del_netem(&conn, dev).await?;
        }
        _ => {
            println!("Usage:");
            println!("  show <dev>              - Show netem configuration");
            println!("  add <dev> delay <time>  - Add delay (e.g., 100ms)");
            println!("  add <dev> loss <pct>    - Add packet loss (e.g., 1%)");
            println!("  add <dev> corrupt <pct> - Add corruption (e.g., 0.1%)");
            println!("  add <dev> duplicate <p> - Add duplication (e.g., 0.5%)");
            println!("  del <dev>               - Remove netem qdisc");
        }
    }

    Ok(())
}

async fn show_netem(conn: &Connection<Route>, dev: &str) -> nlink::netlink::Result<()> {
    let qdiscs = conn.get_qdiscs_for(dev).await?;

    println!("TC qdiscs on {}:", dev);
    println!("{}", "-".repeat(60));

    for qdisc in &qdiscs {
        let kind = qdisc.kind().unwrap_or("?");
        let parent = if qdisc.is_root() {
            "root".to_string()
        } else if qdisc.is_ingress() {
            "ingress".to_string()
        } else {
            format!("{:x}:{:x}", qdisc.parent() >> 16, qdisc.parent() & 0xffff)
        };

        println!("qdisc {} parent {}", kind, parent);

        // Show netem-specific options
        if let Some(netem) = qdisc.netem_options() {
            let delay = netem.delay();
            if !delay.is_zero() {
                print!("  delay {:?}", delay);
                let jitter = netem.jitter();
                if !jitter.is_zero() {
                    print!(" +/- {:?}", jitter);
                }
                if netem.delay_corr > 0.0 {
                    print!(" ({}% correlation)", netem.delay_corr);
                }
                println!();
            }

            if netem.loss_percent > 0.0 {
                print!("  loss {:.2}%", netem.loss_percent);
                if netem.loss_corr > 0.0 {
                    print!(" ({}% correlation)", netem.loss_corr);
                }
                println!();
            }

            if netem.duplicate_percent > 0.0 {
                println!("  duplicate {:.2}%", netem.duplicate_percent);
            }

            if netem.corrupt_percent > 0.0 {
                println!("  corrupt {:.2}%", netem.corrupt_percent);
            }

            if netem.reorder_percent > 0.0 {
                println!("  reorder {:.2}% gap {}", netem.reorder_percent, netem.gap);
            }

            if netem.rate > 0 {
                println!("  rate {} bytes/sec", netem.rate);
            }

            if netem.ecn {
                println!("  ecn enabled");
            }

            // Show loss model if present
            if let Some(loss_model) = &netem.loss_model {
                use nlink::netlink::tc_options::NetemLossModel;
                match loss_model {
                    NetemLossModel::GilbertIntuitive {
                        p13,
                        p31,
                        p32,
                        p14,
                        p23,
                    } => {
                        println!("  loss model: Gilbert-Intuitive (4-state)");
                        println!(
                            "    p13={:.2}% p31={:.2}% p32={:.2}% p14={:.2}% p23={:.2}%",
                            p13, p31, p32, p14, p23
                        );
                    }
                    NetemLossModel::GilbertElliot { p, r, h, k1 } => {
                        println!("  loss model: Gilbert-Elliot (2-state)");
                        println!("    p={:.2}% r={:.2}% h={:.2}% k1={:.2}%", p, r, h, k1);
                    }
                }
            }
        } else if let Some(opts) = qdisc.parsed_options() {
            // Show other qdisc types briefly
            match opts {
                QdiscOptions::FqCodel(fq) => {
                    println!("  target {}us interval {}us", fq.target_us, fq.interval_us);
                }
                QdiscOptions::Htb(htb) => {
                    println!("  default {:x}", htb.default_class);
                }
                QdiscOptions::Tbf(tbf) => {
                    println!("  rate {} burst {}", tbf.rate, tbf.burst);
                }
                _ => {}
            }
        }
    }

    Ok(())
}

async fn add_netem(
    conn: &Connection<Route>,
    dev: &str,
    effect: &str,
    value: &str,
) -> nlink::netlink::Result<()> {
    use nlink::netlink::Error;

    let config = match effect {
        "delay" => {
            let ms = parse_duration(value)?;
            NetemConfig::new().delay(ms).build()
        }
        "loss" => {
            let pct = parse_percent(value)?;
            NetemConfig::new().loss(pct as f64).build()
        }
        "corrupt" => {
            let pct = parse_percent(value)?;
            NetemConfig::new().corrupt(pct as f64).build()
        }
        "duplicate" => {
            let pct = parse_percent(value)?;
            NetemConfig::new().duplicate(pct as f64).build()
        }
        _ => {
            return Err(Error::not_supported(format!("unknown effect: {}", effect)));
        }
    };

    // Use apply_netem convenience method - replaces existing or creates new
    conn.apply_netem(dev, config).await?;
    println!("Applied netem on {} with {} {}", dev, effect, value);

    Ok(())
}

async fn del_netem(conn: &Connection<Route>, dev: &str) -> nlink::netlink::Result<()> {
    // Use remove_netem convenience method
    match conn.remove_netem(dev).await {
        Ok(()) => println!("Removed netem from {}", dev),
        Err(e) if e.is_not_found() => println!("No netem qdisc on {}", dev),
        Err(e) => return Err(e),
    }
    Ok(())
}

fn parse_duration(s: &str) -> nlink::netlink::Result<Duration> {
    use nlink::netlink::Error;

    let s = s.trim();
    if let Some(ms) = s.strip_suffix("ms") {
        let val: u64 = ms
            .parse()
            .map_err(|e| Error::invalid_message(format!("invalid duration: {}", e)))?;
        Ok(Duration::from_millis(val))
    } else if let Some(us) = s.strip_suffix("us") {
        let val: u64 = us
            .parse()
            .map_err(|e| Error::invalid_message(format!("invalid duration: {}", e)))?;
        Ok(Duration::from_micros(val))
    } else if let Some(s_val) = s.strip_suffix('s') {
        let val: u64 = s_val
            .parse()
            .map_err(|e| Error::invalid_message(format!("invalid duration: {}", e)))?;
        Ok(Duration::from_secs(val))
    } else {
        // Assume milliseconds
        let val: u64 = s
            .parse()
            .map_err(|e| Error::invalid_message(format!("invalid duration: {}", e)))?;
        Ok(Duration::from_millis(val))
    }
}

fn parse_percent(s: &str) -> nlink::netlink::Result<f32> {
    use nlink::netlink::Error;

    let s = s.trim().trim_end_matches('%');
    s.parse()
        .map_err(|e| Error::invalid_message(format!("invalid percentage: {}", e)))
}
