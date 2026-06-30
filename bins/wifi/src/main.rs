//! wifi - WiFi management utility via nl80211.
//!
//! Lists wireless interfaces, scan results, station info,
//! and manages connections via Generic Netlink.

use std::time::Duration;

use clap::{Parser, Subcommand};
use nlink::netlink::{
    Connection, Error, Nl80211, Result,
    genl::nl80211::{AuthType, ConnectRequest, Nl80211Event, ScanRequest},
};
use tokio_stream::StreamExt;

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

    /// Show channel survey (per-frequency occupation / noise).
    Survey {
        /// Interface name.
        interface: String,
    },

    /// Remove (kick) an associated station from an AP-mode interface.
    DelStation {
        /// Interface name.
        interface: String,
        /// Station MAC to remove (aa:bb:cc:dd:ee:ff).
        mac: String,
    },

    /// List physical devices and their capabilities.
    Phy,

    /// Show the regulatory domain, or set it by country code.
    Reg {
        /// ISO 3166-1 alpha-2 country code to set (e.g. US, DE, or 00
        /// for the world domain). Omit to show the current domain.
        country: Option<String>,
    },

    /// Connect to a network.
    Connect {
        /// Interface name.
        interface: String,
        /// SSID to connect to.
        ssid: String,
        /// Restrict to a specific BSSID (aa:bb:cc:dd:ee:ff).
        #[arg(long)]
        bssid: Option<String>,
        /// Restrict to a specific frequency in MHz.
        #[arg(long)]
        freq: Option<u32>,
        /// Authentication type: open, shared, sae, ft, eap.
        #[arg(long)]
        auth: Option<String>,
    },

    /// Disconnect from the current network.
    Disconnect {
        /// Interface name.
        interface: String,
    },

    /// Monitor WiFi events (scan, connect, disconnect, regulatory).
    Monitor,

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

/// Parse a `aa:bb:cc:dd:ee:ff` MAC string into 6 bytes.
fn parse_mac(s: &str) -> Result<[u8; 6]> {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 6 {
        return Err(Error::InvalidMessage(format!(
            "wifi: invalid BSSID `{s}` (expected aa:bb:cc:dd:ee:ff)"
        )));
    }
    let mut mac = [0u8; 6];
    for (i, p) in parts.iter().enumerate() {
        mac[i] = u8::from_str_radix(p, 16).map_err(|_| {
            Error::InvalidMessage(format!("wifi: invalid BSSID byte `{p}` in `{s}`"))
        })?;
    }
    Ok(mac)
}

/// Parse an authentication-type token. Strict — an unknown value is
/// an error, not a silent fall-through to open-system.
fn parse_auth_type(s: &str) -> Result<AuthType> {
    match s.to_lowercase().as_str() {
        "open" | "open-system" => Ok(AuthType::OpenSystem),
        "shared" | "shared-key" => Ok(AuthType::SharedKey),
        "sae" => Ok(AuthType::Sae),
        "ft" => Ok(AuthType::Ft),
        "eap" | "network-eap" => Ok(AuthType::NetworkEap),
        other => Err(Error::InvalidMessage(format!(
            "wifi: unknown auth type `{other}` (expected open/shared/sae/ft/eap)"
        ))),
    }
}

/// Render a monitored nl80211 event as a readable line instead of the
/// raw `{:?}` Debug form.
fn format_event(event: &Nl80211Event) -> String {
    match event {
        Nl80211Event::ScanComplete { ifindex } => format!("scan complete (ifindex {ifindex})"),
        Nl80211Event::ScanAborted { ifindex } => format!("scan aborted (ifindex {ifindex})"),
        Nl80211Event::Connect {
            ifindex,
            bssid,
            status_code,
        } => format!(
            "connect (ifindex {ifindex}, bssid {}, status {status_code})",
            format_mac(bssid)
        ),
        Nl80211Event::Disconnect {
            ifindex,
            reason_code,
            ..
        } => format!("disconnect (ifindex {ifindex}, reason {reason_code})"),
        Nl80211Event::NewInterface { ifindex, name, .. } => format!(
            "new interface {} (ifindex {ifindex})",
            name.as_deref().unwrap_or("?")
        ),
        Nl80211Event::DelInterface { ifindex, .. } => {
            format!("del interface (ifindex {ifindex})")
        }
        other => format!("{other:?}"),
    }
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
                    // Link quality — previously parsed into
                    // WirelessInterface but never printed.
                    if let Some(signal) = iface.signal_dbm {
                        println!("  Signal: {signal} dBm");
                    }
                    if let Some(bitrate) = iface.tx_bitrate {
                        // Stored in 100kbps units.
                        println!("  TX bitrate: {:.1} Mbps", f64::from(bitrate) / 10.0);
                    }
                }
                None => {
                    return Err(Error::InvalidMessage(format!(
                        "interface {interface} not found"
                    )));
                }
            }
        }

        Command::Scan { interface, ssid } => {
            let mut request = ScanRequest::default();
            if let Some(ref ssid) = ssid {
                request = request.ssid(ssid.as_bytes().to_vec());
            }

            // Resolve the target ifindex so we can match the
            // ScanComplete event to this interface.
            let target_ifindex = conn
                .get_interface(&interface)
                .await?
                .ok_or_else(|| Error::InvalidMessage(format!("interface {interface} not found")))?
                .ifindex;

            // Subscribe on a second connection so the event stream
            // doesn't serialize against trigger_scan/get_scan_results
            // on the main connection.
            let sub = Connection::<Nl80211>::new_async().await?;
            sub.subscribe()?;
            let mut events = sub.events().await;

            eprintln!("Triggering scan on {interface}...");
            conn.trigger_scan(&interface, &request).await?;

            // Wait for the kernel's scan-complete signal instead of a
            // fixed sleep (which both missed slow scans and wasted time
            // on fast ones). Fall back after a timeout.
            let _ = tokio::time::timeout(Duration::from_secs(10), async {
                while let Some(result) = events.next().await {
                    if let Ok(
                        Nl80211Event::ScanComplete { ifindex }
                        | Nl80211Event::ScanAborted { ifindex },
                    ) = result
                        && ifindex == target_ifindex
                    {
                        break;
                    }
                }
            })
            .await;
            drop(events);

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
                if let Some(avg) = sta.signal_avg_dbm {
                    println!("  Signal avg: {avg} dBm");
                }
                if let Some(secs) = sta.connected_time_secs {
                    println!("  Connected time: {secs} s");
                }
                if let Some(ms) = sta.inactive_time_ms {
                    println!("  Inactive time: {ms} ms");
                }
                if let Some(ref rx) = sta.rx_bitrate
                    && let Some(mbps) = rx.mbps()
                {
                    print!("  RX bitrate: {mbps} Mbps");
                    if let Some(mcs) = rx.mcs {
                        print!(" MCS {mcs}");
                    }
                    println!();
                }
                if let Some(ref tx) = sta.tx_bitrate
                    && let Some(mbps) = tx.mbps()
                {
                    print!("  TX bitrate: {mbps} Mbps");
                    if let Some(mcs) = tx.mcs {
                        print!(" MCS {mcs}");
                    }
                    println!();
                }
                if let Some(rx_bytes) = sta.rx_bytes {
                    println!("  RX bytes: {rx_bytes}");
                }
                if let Some(tx_bytes) = sta.tx_bytes {
                    println!("  TX bytes: {tx_bytes}");
                }
                if let Some(rx) = sta.rx_packets {
                    println!("  RX packets: {rx}");
                }
                if let Some(tx) = sta.tx_packets {
                    println!("  TX packets: {tx}");
                }
                if let (Some(retries), Some(failed)) = (sta.tx_retries, sta.tx_failed) {
                    println!("  TX retries: {retries}, failed: {failed}");
                }
                if let Some(ack) = sta.ack_signal_dbm {
                    println!("  ACK signal: {ack} dBm");
                }
            }
        }

        Command::Survey { interface } => {
            let surveys = conn.get_survey(&interface).await?;
            if surveys.is_empty() {
                println!("No survey data");
            }
            for s in &surveys {
                print!("Frequency: {} MHz", s.frequency_mhz);
                if s.in_use {
                    print!(" [in use]");
                }
                println!();
                if let Some(noise) = s.noise_dbm {
                    println!("  Noise: {noise} dBm");
                }
                if let Some(active) = s.time_ms {
                    print!("  Channel active time: {active} ms");
                    if let Some(busy) = s.time_busy_ms {
                        // Utilisation is the headline number for channel selection.
                        if active > 0 {
                            let pct = (busy as f64 / active as f64) * 100.0;
                            print!(" (busy {busy} ms, {pct:.1}% utilisation)");
                        } else {
                            print!(" (busy {busy} ms)");
                        }
                    }
                    println!();
                }
                if let Some(rx) = s.time_rx_ms {
                    println!("  RX time: {rx} ms");
                }
                if let Some(tx) = s.time_tx_ms {
                    println!("  TX time: {tx} ms");
                }
                if let Some(scan) = s.time_scan_ms {
                    println!("  Scan time: {scan} ms");
                }
            }
        }

        Command::DelStation { interface, mac } => {
            let mac = parse_mac(&mac)?;
            conn.del_station(&interface, mac).await?;
            println!("Removed station {} from {interface}", format_mac(&mac));
        }

        Command::Phy => {
            let phys = conn.get_phys().await?;
            for phy in &phys {
                println!("phy#{}: {}", phy.index, phy.name);
                for (i, band) in phy.bands.iter().enumerate() {
                    println!("  Band {i}:");

                    // Capabilities line: HT/VHT/HE/EHT presence.
                    let mut caps = Vec::new();
                    if band.ht_capa.is_some() {
                        caps.push("HT".to_string());
                    }
                    if band.vht_capa.is_some() {
                        caps.push("VHT".to_string());
                    }
                    if band.he_supported() {
                        caps.push("HE".to_string());
                    }
                    if band.eht_supported() {
                        caps.push("EHT".to_string());
                    }
                    if !caps.is_empty() {
                        println!("    Capabilities: {}", caps.join(" "));
                    }

                    if !band.rates.is_empty() {
                        let rates: Vec<String> = band
                            .rates
                            .iter()
                            .map(|r| format!("{:.1}", *r as f64 / 10.0))
                            .collect();
                        println!("    Bitrates (Mbps): {}", rates.join(" "));
                    }

                    for f in &band.frequencies {
                        let mut flags = Vec::new();
                        if f.disabled {
                            flags.push("disabled".to_string());
                        }
                        if f.no_ir {
                            flags.push("no-IR".to_string());
                        }
                        if f.radar {
                            match f.dfs_state {
                                Some(s) => flags.push(format!("radar/DFS({s:?})")),
                                None => flags.push("radar/DFS".to_string()),
                            }
                        }
                        if f.no_80mhz {
                            flags.push("no-80MHz".to_string());
                        }
                        if f.no_160mhz {
                            flags.push("no-160MHz".to_string());
                        }
                        let flag_str = if flags.is_empty() {
                            String::new()
                        } else {
                            format!(" [{}]", flags.join(", "))
                        };
                        println!(
                            "    * {} MHz (ch {}, {:.1} dBm){}",
                            f.freq,
                            f.channel(),
                            f.max_power_dbm(),
                            flag_str,
                        );
                    }
                }
                if !phy.supported_iftypes.is_empty() {
                    println!("  Supported types: {:?}", phy.supported_iftypes);
                }
                if !phy.cipher_suites.is_empty() {
                    let ciphers: Vec<String> = phy
                        .cipher_suites
                        .iter()
                        .map(|c| format!("0x{c:08x}"))
                        .collect();
                    println!("  Cipher suites: {}", ciphers.join(" "));
                }
            }
        }

        Command::Reg { country } => {
            if let Some(country) = country {
                conn.set_regulatory(&country).await?;
                eprintln!("Regulatory domain change requested: {country}");
            } else {
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
        }

        Command::Connect {
            interface,
            ssid,
            bssid,
            freq,
            auth,
        } => {
            let mut request = ConnectRequest::new(ssid.as_bytes());
            if let Some(b) = &bssid {
                request = request.bssid(parse_mac(b)?);
            }
            if let Some(f) = freq {
                request = request.frequency(f);
            }
            if let Some(a) = &auth {
                request = request.auth_type(parse_auth_type(a)?);
            }
            conn.connect(&interface, request).await?;
            eprintln!("Connect request sent for SSID: {ssid}");
        }

        Command::Disconnect { interface } => {
            conn.disconnect(&interface).await?;
            eprintln!("Disconnected from {interface}");
        }

        Command::Monitor => {
            conn.subscribe()?;
            eprintln!("Monitoring WiFi events (Ctrl+C to stop)...");
            let mut events = conn.events().await;
            while let Some(result) = events.next().await {
                match result {
                    Ok(event) => println!("{}", format_event(&event)),
                    Err(e) => eprintln!("Error: {e}"),
                }
            }
        }

        Command::Powersave { interface, mode } => {
            if let Some(mode) = mode {
                let enabled = match mode.as_str() {
                    "on" | "true" | "1" => true,
                    "off" | "false" | "0" => false,
                    _ => {
                        return Err(Error::InvalidMessage(format!(
                            "unknown power-save mode `{mode}` (expected on/off)"
                        )));
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mac_parse_strict() {
        assert_eq!(parse_mac("00:11:22:33:44:55").unwrap(), [0, 17, 34, 51, 68, 85]);
        assert!(parse_mac("00:11:22:33:44").is_err()); // too short
        assert!(parse_mac("zz:11:22:33:44:55").is_err()); // bad byte
    }

    #[test]
    fn auth_type_parse_strict() {
        assert!(matches!(parse_auth_type("open"), Ok(AuthType::OpenSystem)));
        assert!(matches!(parse_auth_type("SAE"), Ok(AuthType::Sae)));
        // The point: an unknown value errors, never silently opens.
        assert!(parse_auth_type("wpa9").is_err());
    }
}
