//! WiFi interface management via nl80211 Generic Netlink.
//!
//! Demonstrates listing wireless interfaces, scanning, and
//! querying station info.
//!
//! Run with: cargo run -p nlink --example genl_nl80211
//!
//! Note: Requires a WiFi adapter. Some operations require root.

use nlink::netlink::{Connection, Nl80211};

#[tokio::main]
async fn main() -> nlink::netlink::Result<()> {
    let conn = match Connection::<Nl80211>::new_async().await {
        Ok(conn) => conn,
        Err(e) => {
            eprintln!("Failed to connect to nl80211: {}", e);
            eprintln!("Make sure the cfg80211 module is loaded.");
            return Ok(());
        }
    };

    // List wireless interfaces
    println!("=== Wireless Interfaces ===\n");
    let interfaces = conn.get_interfaces().await?;

    if interfaces.is_empty() {
        println!("No wireless interfaces found.");
        return Ok(());
    }

    for iface in &interfaces {
        let name = iface.name.as_deref().unwrap_or("?");
        println!("  {}: type={:?}", name, iface.iftype);
        if let Some(mac) = iface.mac_str() {
            println!("    mac: {}", mac);
        }
        if let Some(freq) = iface.frequency {
            println!("    frequency: {} MHz", freq);
        }
    }

    // Get physical device info
    println!("\n=== Physical Devices ===\n");
    let phys = conn.get_phys().await?;
    for phy in &phys {
        println!("  phy#{}: {} ({} bands)", phy.index, phy.name, phy.bands.len());
    }

    // Get station info (connected AP) for first interface
    if let Some(iface) = interfaces.first() {
        let name = iface.name.as_deref().unwrap_or("wlan0");
        println!("\n=== Station Info ({}) ===\n", name);

        match conn.get_stations(name).await {
            Ok(stations) if stations.is_empty() => {
                println!("  Not connected to any AP.");
            }
            Ok(stations) => {
                for sta in &stations {
                    if let Some(signal) = sta.signal_dbm {
                        println!("  Signal: {} dBm", signal);
                    }
                    if let Some(rx) = &sta.rx_bitrate {
                        println!("  RX bitrate: {:?}", rx.mbps());
                    }
                    if let Some(tx) = &sta.tx_bitrate {
                        println!("  TX bitrate: {:?}", tx.mbps());
                    }
                }
            }
            Err(e) => println!("  Could not query stations: {}", e),
        }
    }

    // Get regulatory domain
    println!("\n=== Regulatory Domain ===\n");
    match conn.get_regulatory().await {
        Ok(reg) => println!("  Country: {}", reg.country),
        Err(e) => println!("  Could not query regulatory: {}", e),
    }

    Ok(())
}
