//! wifi - WiFi management utility via nl80211.
//!
//! Lists wireless interfaces, scan results, station info,
//! and manages connections via Generic Netlink.

use clap::{Parser, Subcommand};
use nlink::netlink::genl::nl80211::{ConnectRequest, ScanRequest};
use nlink::netlink::{Connection, Nl80211, Result};

#[derive(Parser)]
#[command(name = "wifi", version, about = "WiFi management utility")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// List wireless interfaces.
    List,

    /// Show detailed info for an interface.
    Show {
        /// Interface name (e.g., "wlan0").
        interface: String,
    },

    /// Trigger a scan and show results.
    Scan {
        /// Interface name.
        interface: String,
        /// Scan specific SSID.
        #[arg(long)]
        ssid: Option<String>,
    },

    /// Show cached scan results without triggering a new scan.
    Results {
        /// Interface name.
        interface: String,
    },

    /// Show station (connection) info.
    Station {
        /// Interface name.
        interface: String,
    },

    /// List physical devices and their capabilities.
    Phy,

    /// Show regulatory domain.
    Reg,

    /// Connect to a network.
    Connect {
        /// Interface name.
        interface: String,
        /// SSID to connect to.
        ssid: String,
    },

    /// Disconnect from the current network.
    Disconnect {
        /// Interface name.
        interface: String,
    },

    /// Get or set power save mode.
    Powersave {
        /// Interface name.
        interface: String,
        /// Set mode: "on" or "off". Omit to show current state.
        mode: Option<String>,
    },
}

fn format_mac(mac: &[u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let conn = Connection::<Nl80211>::new_async().await?;

    match cli.command {
        Command::List => {
            let interfaces = conn.get_interfaces().await?;
            for iface in &interfaces {
                let name = iface.name.as_deref().unwrap_or("?");
                print!("{name}: type={:?}", iface.iftype);
                if let Some(freq) = iface.frequency {
                    print!(" freq={freq} MHz");
                    if let Some(ch) = iface.channel() {
                        print!(" (ch {ch})");
                    }
                }
                if let Some(mac) = iface.mac_str() {
                    print!(" mac={mac}");
                }
                println!();
            }
        }

        Command::Show { interface } => {
            let iface = conn.get_interface(&interface).await?;
            match iface {
                Some(iface) => {
                    let name = iface.name.as_deref().unwrap_or("?");
                    println!("Interface: {name}");
                    println!("  Type: {:?}", iface.iftype);
                    if let Some(mac) = iface.mac_str() {
                        println!("  MAC: {mac}");
                    }
                    println!("  PHY: {}", iface.wiphy);
                    println!("  ifindex: {}", iface.ifindex);
                    if let Some(freq) = iface.frequency {
                        println!("  Frequency: {freq} MHz");
                        if let Some(ch) = iface.channel() {
                            println!("  Channel: {ch}");
                        }
                    }
                    if let Some(ssid) = &iface.ssid {
                        println!("  SSID: {ssid}");
                    }
                }
                None => {
                    eprintln!("Interface {interface} not found");
                    std::process::exit(1);
                }
            }
        }

        Command::Scan { interface, ssid } => {
            let mut request = ScanRequest::default();
            if let Some(ref ssid) = ssid {
                request = request.ssid(ssid.as_bytes().to_vec());
            }
            eprintln!("Triggering scan on {interface}...");
            conn.trigger_scan(&interface, &request).await?;

            // Brief delay to allow scan to complete
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;

            let results = conn.get_scan_results(&interface).await?;
            print_scan_results(&results);
        }

        Command::Results { interface } => {
            let results = conn.get_scan_results(&interface).await?;
            print_scan_results(&results);
        }

        Command::Station { interface } => {
            let stations = conn.get_stations(&interface).await?;
            if stations.is_empty() {
                println!("No stations connected");
            }
            for sta in &stations {
                println!("Station: {}", format_mac(&sta.mac));
                if let Some(signal) = sta.signal_dbm {
                    println!("  Signal: {signal} dBm");
                }
                if let Some(ref rx) = sta.rx_bitrate {
                    if let Some(mbps) = rx.mbps() {
                        print!("  RX bitrate: {mbps} Mbps");
                        if let Some(mcs) = rx.mcs {
                            print!(" MCS {mcs}");
                        }
                        println!();
                    }
                }
                if let Some(ref tx) = sta.tx_bitrate {
                    if let Some(mbps) = tx.mbps() {
                        print!("  TX bitrate: {mbps} Mbps");
                        if let Some(mcs) = tx.mcs {
                            print!(" MCS {mcs}");
                        }
                        println!();
                    }
                }
                if let Some(rx_bytes) = sta.rx_bytes {
                    println!("  RX bytes: {rx_bytes}");
                }
                if let Some(tx_bytes) = sta.tx_bytes {
                    println!("  TX bytes: {tx_bytes}");
                }
            }
        }

        Command::Phy => {
            let phys = conn.get_phys().await?;
            for phy in &phys {
                println!("phy#{}: {}", phy.index, phy.name);
                for (i, band) in phy.bands.iter().enumerate() {
                    println!("  Band {i}:");
                    let freq_count = band.frequencies.len();
                    if freq_count > 0 {
                        println!("    Frequencies: {freq_count}");
                    }
                }
                if !phy.supported_iftypes.is_empty() {
                    println!("  Supported types: {:?}", phy.supported_iftypes);
                }
            }
        }

        Command::Reg => {
            let reg = conn.get_regulatory().await?;
            println!("Country: {}", reg.country);
            for rule in &reg.rules {
                println!(
                    "  {}-{} MHz: max_bw={} MHz, max_eirp={} dBm flags=0x{:x}",
                    rule.start_freq_khz / 1000,
                    rule.end_freq_khz / 1000,
                    rule.max_bandwidth_khz / 1000,
                    rule.max_eirp_mbm / 100,
                    rule.flags,
                );
            }
        }

        Command::Connect { interface, ssid } => {
            let request = ConnectRequest::new(ssid.as_bytes());
            conn.connect(&interface, request).await?;
            eprintln!("Connect request sent for SSID: {ssid}");
        }

        Command::Disconnect { interface } => {
            conn.disconnect(&interface).await?;
            eprintln!("Disconnected from {interface}");
        }

        Command::Powersave { interface, mode } => {
            if let Some(mode) = mode {
                let enabled = match mode.as_str() {
                    "on" | "true" | "1" => true,
                    "off" | "false" | "0" => false,
                    _ => {
                        eprintln!("Unknown mode: {mode}. Use 'on' or 'off'.");
                        std::process::exit(1);
                    }
                };
                conn.set_power_save(&interface, enabled).await?;
                eprintln!("Power save set to {mode}");
            } else {
                let state = conn.get_power_save(&interface).await?;
                println!("Power save: {state:?}");
            }
        }
    }

    Ok(())
}

fn print_scan_results(results: &[nlink::netlink::genl::nl80211::ScanResult]) {
    if results.is_empty() {
        println!("No scan results");
        return;
    }
    for r in results {
        print!("{}", r.bssid_str());
        if let Some(ref ssid) = r.ssid {
            print!("  {ssid}");
        }
        print!("  {} MHz", r.frequency);
        print!("  {} dBm", r.signal_dbm());
        if r.is_privacy() {
            print!("  [secured]");
        }
        println!();
    }
}
