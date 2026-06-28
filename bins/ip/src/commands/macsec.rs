//! ip macsec command implementation.
//!
//! This module implements MACsec device information display.

use clap::{Args, Subcommand, ValueEnum};
use nlink::{
    netlink::{
        Connection, Error, Macsec, Result, Route,
        genl::macsec::{
            MacsecCipherSuite, MacsecDevice, MacsecOffload, MacsecSaBuilder, MacsecValidate,
        },
    },
    output::{OutputFormat, OutputOptions},
};

#[derive(Args)]
pub struct MacsecCmd {
    #[command(subcommand)]
    action: Option<MacsecAction>,
}

/// TX vs RX secure-channel direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum Direction {
    Tx,
    Rx,
}

/// Arguments shared by the SA/SC mutation subcommands. Which fields are
/// required depends on the verb + direction (validated in `mutate`):
/// `tx` operates on the device's single TX SC; `rx` needs `--sci` to pick
/// the per-peer RX SC, and an `--an` selects an SA within it (omit `--an`
/// on `rx` to operate on the RX SC itself).
#[derive(Args)]
struct MacsecSaArgs {
    /// MACsec device name.
    device: String,

    /// Secure-channel direction.
    direction: Direction,

    /// RX secure-channel identifier (required for `rx`; hex `0x…` or decimal).
    #[arg(long)]
    sci: Option<String>,

    /// Association Number (0-3) selecting an SA.
    #[arg(long)]
    an: Option<u8>,

    /// SA key (hex; 16 bytes for GCM-AES-128, 32 for -256). Required on add.
    #[arg(long)]
    key: Option<String>,

    /// 128-bit key identifier (32 hex chars).
    #[arg(long = "key-id")]
    key_id: Option<String>,

    /// Initial/next packet number.
    #[arg(long)]
    pn: Option<u64>,

    /// Whether the SA is active (the encoding SA for TX).
    #[arg(long, default_value = "on")]
    active: OnOff,
}

/// on/off toggle that maps to a bool.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum OnOff {
    On,
    Off,
}

impl From<OnOff> for bool {
    fn from(v: OnOff) -> bool {
        matches!(v, OnOff::On)
    }
}

#[derive(Subcommand)]
enum MacsecAction {
    /// Show MACsec devices.
    Show {
        /// Device name.
        device: Option<String>,
    },

    /// Add a TX SA, RX secure-channel, or RX SA.
    Add(MacsecSaArgs),

    /// Update an existing TX/RX SA (packet number / active flag).
    Set(MacsecSaArgs),

    /// Delete a TX SA, RX secure-channel, or RX SA.
    Del(MacsecSaArgs),
}

/// Verb for the shared `mutate` dispatcher.
#[derive(Clone, Copy)]
enum Verb {
    Add,
    Set,
    Del,
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
            MacsecAction::Add(args) => mutate(conn, Verb::Add, &args).await,
            MacsecAction::Set(args) => mutate(conn, Verb::Set, &args).await,
            MacsecAction::Del(args) => mutate(conn, Verb::Del, &args).await,
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
            // Show specific device
            if let Some(macsec) = &macsec_conn {
                match macsec.get_device(dev_name).await {
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
                    && let Ok(dev) = macsec.get_device(name).await
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

/// Resolve the device to an ifindex (namespace-safe) and dispatch the
/// add/set/del to the matching `Connection<Macsec>` `*_by_index` method.
async fn mutate(conn: &Connection<Route>, verb: Verb, args: &MacsecSaArgs) -> Result<()> {
    let ifindex = conn
        .get_link_by_name(args.device.as_str())
        .await?
        .ok_or_else(|| Error::InvalidMessage(format!("device `{}` not found", args.device)))?
        .ifindex();

    let macsec = Connection::<Macsec>::new_async().await?;

    // Validate the AN up front — MacsecSaBuilder::new panics on an > 3.
    if let Some(an) = args.an
        && an > 3
    {
        return Err(Error::InvalidMessage(format!(
            "macsec: association number must be 0-3 (got {an})"
        )));
    }

    match (verb, args.direction) {
        // ---- TX SA ----
        (Verb::Add, Direction::Tx) => {
            macsec.add_tx_sa_by_index(ifindex, build_sa(args)?).await?;
        }
        (Verb::Set, Direction::Tx) => {
            macsec
                .update_tx_sa_by_index(ifindex, build_sa(args)?)
                .await?;
        }
        (Verb::Del, Direction::Tx) => {
            let an = require_an(args)?;
            macsec.del_tx_sa_by_index(ifindex, an).await?;
        }

        // ---- RX SC / RX SA ----
        (verb, Direction::Rx) => {
            let sci = parse_sci(require(&args.sci, "--sci")?)?;
            match (verb, args.an) {
                // No AN: operate on the RX secure-channel itself.
                (Verb::Add, None) => macsec.add_rx_sc_by_index(ifindex, sci).await?,
                (Verb::Del, None) => macsec.del_rx_sc_by_index(ifindex, sci).await?,
                (Verb::Set, None) => {
                    return Err(Error::InvalidMessage(
                        "macsec set rx requires --an (RX secure-channels have no mutable state)"
                            .into(),
                    ));
                }
                // With AN: operate on an RX SA within that SC.
                (Verb::Add, Some(_)) => {
                    macsec
                        .add_rx_sa_by_index(ifindex, sci, build_sa(args)?)
                        .await?
                }
                (Verb::Set, Some(_)) => {
                    macsec
                        .update_rx_sa_by_index(ifindex, sci, build_sa(args)?)
                        .await?
                }
                (Verb::Del, Some(an)) => macsec.del_rx_sa_by_index(ifindex, sci, an).await?,
            }
        }
    }

    Ok(())
}

/// Build a `MacsecSaBuilder` from the CLI args (for add/update). Requires
/// `--an`; `--key` is required for `add` (the kernel needs it to create the
/// SA) but the same builder serves `update`, where the key is re-sent.
fn build_sa(args: &MacsecSaArgs) -> Result<MacsecSaBuilder> {
    let an = require_an(args)?;
    let key = parse_hex(require(&args.key, "--key")?, "--key")?;

    let mut sa = MacsecSaBuilder::new(an, &key).active(args.active.into());
    if let Some(pn) = args.pn {
        sa = sa.packet_number(pn);
    }
    if let Some(ref id) = args.key_id {
        let bytes = parse_hex(id, "--key-id")?;
        let arr: [u8; 16] = bytes.as_slice().try_into().map_err(|_| {
            Error::InvalidMessage(format!(
                "macsec: --key-id must be 16 bytes (32 hex chars), got {}",
                bytes.len()
            ))
        })?;
        sa = sa.key_id(arr);
    }
    Ok(sa)
}

fn require_an(args: &MacsecSaArgs) -> Result<u8> {
    let an = require(&args.an, "--an")?;
    if *an > 3 {
        return Err(Error::InvalidMessage(format!(
            "macsec: association number must be 0-3 (got {an})"
        )));
    }
    Ok(*an)
}

/// Require an optional CLI value, erroring with the flag name if absent.
fn require<'a, T>(opt: &'a Option<T>, what: &str) -> Result<&'a T> {
    opt.as_ref()
        .ok_or_else(|| Error::InvalidMessage(format!("macsec: {what} is required here")))
}

/// Parse an SCI: hex (`0x…`) or decimal `u64`.
fn parse_sci(s: &str) -> Result<u64> {
    let parsed = if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16)
    } else {
        s.parse::<u64>()
    };
    parsed.map_err(|_| Error::InvalidMessage(format!("macsec: invalid SCI `{s}`")))
}

/// Parse an even-length hex string into bytes.
fn parse_hex(s: &str, what: &str) -> Result<Vec<u8>> {
    let s = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s);
    if !s.len().is_multiple_of(2) {
        return Err(Error::InvalidMessage(format!(
            "macsec: {what} must have an even number of hex digits"
        )));
    }
    (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&s[i..i + 2], 16)
                .map_err(|_| Error::InvalidMessage(format!("macsec: invalid hex in {what}")))
        })
        .collect()
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
        _ => "unknown",
    }
}

fn validate_str(validate: MacsecValidate) -> &'static str {
    match validate {
        MacsecValidate::Disabled => "disabled",
        MacsecValidate::Check => "check",
        MacsecValidate::Strict => "strict",
        _ => "unknown",
    }
}

fn offload_str(offload: MacsecOffload) -> &'static str {
    match offload {
        MacsecOffload::Off => "off",
        MacsecOffload::Phy => "phy",
        MacsecOffload::Mac => "mac",
        _ => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_sci_hex_and_dec() {
        assert_eq!(
            parse_sci("0x11223344550001").unwrap(),
            0x0011_2233_4455_0001
        );
        assert_eq!(parse_sci("42").unwrap(), 42);
        assert!(parse_sci("nope").is_err());
    }

    #[test]
    fn parse_hex_keys() {
        assert_eq!(parse_hex("0a0b", "--key").unwrap(), vec![0x0a, 0x0b]);
        assert_eq!(parse_hex("0x0a0b", "--key").unwrap(), vec![0x0a, 0x0b]);
        assert!(parse_hex("abc", "--key").is_err()); // odd length
        assert!(parse_hex("zz", "--key").is_err()); // not hex
    }

    #[test]
    fn on_off_to_bool() {
        assert!(bool::from(OnOff::On));
        assert!(!bool::from(OnOff::Off));
    }
}
