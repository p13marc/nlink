//! ip macsec command implementation.
//!
//! This module implements MACsec device information display.

use clap::{Args, Subcommand};
use nlink::netlink::genl::macsec::{
    MacsecCipherSuite, MacsecDevice, MacsecOffload, MacsecValidate,
};
use nlink::netlink::{Connection, Macsec, Result, Route};
use nlink::output::{OutputFormat, OutputOptions};

#[derive(Args)]
pub struct MacsecCmd {
    #[command(subcommand)]
    action: Option<MacsecAction>,
}

#[derive(Subcommand)]
enum MacsecAction {
    /// Show MACsec devices.
    Show {
        /// Device name.
        device: Option<String>,
    },
}

impl MacsecCmd {
    pub async fn run(
        self,
        conn: &Connection<Route>,
        format: OutputFormat,
        opts: &OutputOptions,
    ) -> Result<()> {
        match self.action.unwrap_or(MacsecAction::Show { device: None }) {
            MacsecAction::Show { device } => {
                Self::show(conn, device.as_deref(), format, opts).await
            }
        }
    }

    async fn show(
        conn: &Connection<Route>,
        device: Option<&str>,
        format: OutputFormat,
        opts: &OutputOptions,
    ) -> Result<()> {
        // Find MACsec interfaces
        let links = conn.get_links().await?;
        let macsec_links: Vec<_> = links
            .iter()
            .filter(|l| {
                l.link_info()
                    .and_then(|i| i.kind())
                    .map(|k| k == "macsec")
                    .unwrap_or(false)
            })
            .collect();

        if macsec_links.is_empty() && device.is_none() {
            return Ok(());
        }

        // Create MACsec connection for detailed info (may not be available)
        let macsec_conn = Connection::<Macsec>::new_async().await.ok();

        let mut devices_info = Vec::new();

        if let Some(dev_name) = device {
            // Show specific device - resolve name to index via Route connection
            let link = conn.get_link_by_name(dev_name).await?.ok_or_else(|| {
                nlink::netlink::Error::InterfaceNotFound {
                    name: dev_name.to_string(),
                }
            })?;

            if let Some(macsec) = &macsec_conn {
                match macsec.get_device_by_index(link.ifindex()).await {
                    Ok(dev) => devices_info.push((dev_name.to_string(), dev)),
                    Err(e) => {
                        return Err(e);
                    }
                }
            } else {
                return Err(nlink::netlink::Error::InvalidMessage(
                    "MACsec GENL family not available".into(),
                ));
            }
        } else {
            // Show all MACsec devices
            for link in &macsec_links {
                let name = link.name_or("?");
                if let Some(macsec) = &macsec_conn
                    && let Ok(dev) = macsec.get_device_by_index(link.ifindex()).await
                {
                    devices_info.push((name.to_string(), dev));
                }
            }
        }

        match format {
            OutputFormat::Json => {
                print_devices_json(&devices_info, opts);
            }
            OutputFormat::Text => {
                for (name, dev) in &devices_info {
                    print_device_text(name, dev, opts);
                }
            }
        }

        Ok(())
    }
}

/// Print devices in JSON format.
fn print_devices_json(devices: &[(String, MacsecDevice)], opts: &OutputOptions) {
    let json_devices: Vec<serde_json::Value> = devices
        .iter()
        .map(|(name, dev)| device_to_json(name, dev))
        .collect();

    let output = if opts.pretty {
        serde_json::to_string_pretty(&json_devices).unwrap_or_default()
    } else {
        serde_json::to_string(&json_devices).unwrap_or_default()
    };
    println!("{}", output);
}

/// Convert device to JSON.
fn device_to_json(name: &str, dev: &MacsecDevice) -> serde_json::Value {
    let mut obj = serde_json::json!({
        "name": name,
        "sci": format_sci(dev.sci),
        "protect": dev.protect,
        "validate": validate_str(dev.validate),
        "encrypt": dev.encrypt,
        "cipher_suite": cipher_str(dev.cipher),
        "icv_len": dev.icv_len,
        "encoding_sa": dev.encoding_sa,
        "send_sci": dev.include_sci,
        "end_station": dev.end_station,
        "scb": dev.scb,
        "replay": dev.replay_protect,
        "replay_window": dev.replay_window,
        "offload": offload_str(dev.offload),
    });

    if let Some(tx_sc) = &dev.tx_sc {
        let tx_sas: Vec<serde_json::Value> = tx_sc
            .sas
            .iter()
            .map(|sa| {
                let mut sa_obj = serde_json::json!({
                    "an": sa.an,
                    "pn": sa.pn,
                    "active": sa.active,
                });
                if let Some(key_id) = &sa.key_id {
                    sa_obj["key_id"] = serde_json::json!(format_key_id(key_id));
                }
                sa_obj
            })
            .collect();

        obj["tx_sc"] = serde_json::json!({
            "sci": format_sci(tx_sc.sci),
            "sas": tx_sas,
            "stats": {
                "protected_pkts": tx_sc.stats_protected_pkts,
                "encrypted_pkts": tx_sc.stats_encrypted_pkts,
                "protected_octets": tx_sc.stats_protected_octets,
                "encrypted_octets": tx_sc.stats_encrypted_octets,
            }
        });
    }

    let rx_scs: Vec<serde_json::Value> = dev
        .rx_scs
        .iter()
        .map(|rx| {
            let rx_sas: Vec<serde_json::Value> = rx
                .sas
                .iter()
                .map(|sa| {
                    let mut sa_obj = serde_json::json!({
                        "an": sa.an,
                        "pn": sa.pn,
                        "active": sa.active,
                    });
                    if let Some(key_id) = &sa.key_id {
                        sa_obj["key_id"] = serde_json::json!(format_key_id(key_id));
                    }
                    sa_obj
                })
                .collect();

            serde_json::json!({
                "sci": format_sci(rx.sci),
                "active": rx.active,
                "sas": rx_sas,
                "stats": {
                    "ok_pkts": rx.stats_ok_pkts,
                    "invalid_pkts": rx.stats_invalid_pkts,
                    "not_valid_pkts": rx.stats_not_valid_pkts,
                    "validated_octets": rx.stats_validated_octets,
                    "decrypted_octets": rx.stats_decrypted_octets,
                }
            })
        })
        .collect();

    obj["rx_scs"] = serde_json::json!(rx_scs);

    obj
}

/// Print device information in text format.
fn print_device_text(name: &str, dev: &MacsecDevice, opts: &OutputOptions) {
    // First line: device name and flags
    print!(
        "{}: protect {} validate {} sc {} sa {} encrypt {} send_sci {} end_station {} scb {} replay {}",
        name,
        if dev.protect { "on" } else { "off" },
        validate_str(dev.validate),
        if dev.include_sci { "on" } else { "off" },
        dev.encoding_sa,
        if dev.encrypt { "on" } else { "off" },
        if dev.include_sci { "on" } else { "off" },
        if dev.end_station { "on" } else { "off" },
        if dev.scb { "on" } else { "off" },
        if dev.replay_protect { "on" } else { "off" },
    );

    if dev.replay_protect && dev.replay_window > 0 {
        print!(" window {}", dev.replay_window);
    }

    println!();

    // Cipher suite line
    println!(
        "    cipher suite: {}, using ICV length {}",
        cipher_str(dev.cipher),
        dev.icv_len
    );

    // Offload info
    if dev.offload != MacsecOffload::Off {
        println!("    offload: {}", offload_str(dev.offload));
    }

    // TX SC
    if let Some(tx_sc) = &dev.tx_sc {
        println!(
            "    TXSC: {} on SA {}",
            format_sci(tx_sc.sci),
            dev.encoding_sa
        );

        for sa in &tx_sc.sas {
            print!(
                "        {}: PN {}, state {}",
                sa.an,
                sa.pn,
                if sa.active { "on" } else { "off" }
            );
            if let Some(key_id) = &sa.key_id {
                print!(", key {}", format_key_id(key_id));
            }
            println!();
        }

        if opts.stats {
            println!(
                "        stats: protected {} encrypted {} octets {} {}",
                tx_sc.stats_protected_pkts,
                tx_sc.stats_encrypted_pkts,
                tx_sc.stats_protected_octets,
                tx_sc.stats_encrypted_octets
            );
        }
    }

    // RX SCs
    for rx_sc in &dev.rx_scs {
        println!(
            "    RXSC: {}, state {}",
            format_sci(rx_sc.sci),
            if rx_sc.active { "on" } else { "off" }
        );

        for sa in &rx_sc.sas {
            print!(
                "        {}: PN {}, state {}",
                sa.an,
                sa.pn,
                if sa.active { "on" } else { "off" }
            );
            if let Some(key_id) = &sa.key_id {
                print!(", key {}", format_key_id(key_id));
            }
            println!();
        }

        if opts.stats {
            println!(
                "        stats: ok {} invalid {} notValid {} validated {} decrypted {}",
                rx_sc.stats_ok_pkts,
                rx_sc.stats_invalid_pkts,
                rx_sc.stats_not_valid_pkts,
                rx_sc.stats_validated_octets,
                rx_sc.stats_decrypted_octets
            );
        }
    }
}

/// Format SCI as MAC:port.
fn format_sci(sci: u64) -> String {
    let mac = (sci >> 16) & 0xFFFFFFFFFFFF;
    let port = sci & 0xFFFF;
    format!(
        "{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}:{:04x}",
        (mac >> 40) & 0xFF,
        (mac >> 32) & 0xFF,
        (mac >> 24) & 0xFF,
        (mac >> 16) & 0xFF,
        (mac >> 8) & 0xFF,
        mac & 0xFF,
        port
    )
}

/// Format key ID as hex string.
fn format_key_id(key_id: &[u8; 16]) -> String {
    key_id.iter().map(|b| format!("{:02x}", b)).collect()
}

fn cipher_str(cipher: MacsecCipherSuite) -> &'static str {
    match cipher {
        MacsecCipherSuite::GcmAes128 => "GCM-AES-128",
        MacsecCipherSuite::GcmAes256 => "GCM-AES-256",
        MacsecCipherSuite::GcmAesXpn128 => "GCM-AES-XPN-128",
        MacsecCipherSuite::GcmAesXpn256 => "GCM-AES-XPN-256",
    }
}

fn validate_str(validate: MacsecValidate) -> &'static str {
    match validate {
        MacsecValidate::Disabled => "disabled",
        MacsecValidate::Check => "check",
        MacsecValidate::Strict => "strict",
    }
}

fn offload_str(offload: MacsecOffload) -> &'static str {
    match offload {
        MacsecOffload::Off => "off",
        MacsecOffload::Phy => "phy",
        MacsecOffload::Mac => "mac",
    }
}
