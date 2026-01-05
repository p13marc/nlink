//! Query and display ring buffer sizes for a network interface.
//!
//! This example demonstrates how to use the ethtool netlink interface
//! to query the RX/TX ring buffer sizes of a network interface.
//!
//! # Usage
//!
//! ```bash
//! cargo run --example ethtool_rings -- eth0
//! ```
//!
//! # Requirements
//!
//! - Linux kernel 5.6+ with ethtool netlink support
//! - No special privileges required for read operations

use nlink::netlink::{Connection, Ethtool};

#[tokio::main]
async fn main() -> nlink::Result<()> {
    let ifname = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "eth0".to_string());

    println!("Querying ring buffer sizes for {}...\n", ifname);

    let conn = Connection::<Ethtool>::new_async().await?;

    // Get ring sizes
    let rings = conn.get_rings(&ifname).await?;

    println!("Ring parameters for {}:", ifname);
    println!();
    println!("Pre-set maximums:");
    if let Some(rx_max) = rings.rx_max {
        println!("  RX:         {}", rx_max);
    }
    if let Some(rx_mini_max) = rings.rx_mini_max
        && rx_mini_max > 0
    {
        println!("  RX Mini:    {}", rx_mini_max);
    }
    if let Some(rx_jumbo_max) = rings.rx_jumbo_max
        && rx_jumbo_max > 0
    {
        println!("  RX Jumbo:   {}", rx_jumbo_max);
    }
    if let Some(tx_max) = rings.tx_max {
        println!("  TX:         {}", tx_max);
    }

    println!();
    println!("Current hardware settings:");
    if let Some(rx) = rings.rx {
        println!("  RX:         {}", rx);
    }
    if let Some(rx_mini) = rings.rx_mini
        && rx_mini > 0
    {
        println!("  RX Mini:    {}", rx_mini);
    }
    if let Some(rx_jumbo) = rings.rx_jumbo
        && rx_jumbo > 0
    {
        println!("  RX Jumbo:   {}", rx_jumbo);
    }
    if let Some(tx) = rings.tx {
        println!("  TX:         {}", tx);
    }

    if let Some(rx_buf_len) = rings.rx_buf_len {
        println!();
        println!("  RX Buf Len: {}", rx_buf_len);
    }

    if let Some(cqe_size) = rings.cqe_size {
        println!("  CQE Size:   {}", cqe_size);
    }

    if let Some(tx_push) = rings.tx_push {
        println!("  TX Push:    {}", if tx_push { "on" } else { "off" });
    }

    if let Some(rx_push) = rings.rx_push {
        println!("  RX Push:    {}", if rx_push { "on" } else { "off" });
    }

    // Get channel counts
    println!();
    println!("Channel parameters for {}:", ifname);

    let channels = conn.get_channels(&ifname).await?;

    println!();
    println!("Pre-set maximums:");
    if let Some(rx_max) = channels.rx_max {
        println!("  RX:       {}", rx_max);
    }
    if let Some(tx_max) = channels.tx_max {
        println!("  TX:       {}", tx_max);
    }
    if let Some(other_max) = channels.other_max {
        println!("  Other:    {}", other_max);
    }
    if let Some(combined_max) = channels.combined_max {
        println!("  Combined: {}", combined_max);
    }

    println!();
    println!("Current hardware settings:");
    if let Some(rx) = channels.rx_count {
        println!("  RX:       {}", rx);
    }
    if let Some(tx) = channels.tx_count {
        println!("  TX:       {}", tx);
    }
    if let Some(other) = channels.other_count {
        println!("  Other:    {}", other);
    }
    if let Some(combined) = channels.combined_count {
        println!("  Combined: {}", combined);
    }

    Ok(())
}
