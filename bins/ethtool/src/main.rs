//! nlink-ethtool: Proof-of-concept ethtool utility using nlink
//!
//! This binary demonstrates the nlink ethtool API. It is not intended
//! to be a full replacement for the standard ethtool command.

use clap::{Parser, Subcommand};
use nlink::netlink::{
    Connection, Ethtool,
    genl::ethtool::{Duplex, EthtoolEvent},
};

#[derive(Parser)]
#[command(name = "nlink-ethtool")]
#[command(about = "Query and control network device settings")]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    /// Device name (when no subcommand is given)
    #[arg(global = true)]
    device: Option<String>,

    /// Emit machine-readable JSON instead of the default text output
    #[arg(long, short, global = true)]
    json: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Show device settings (default action)
    Show {
        /// Device name
        device: String,
    },
    /// Show device features (offloads)
    #[command(short_flag = 'k')]
    Features {
        /// Device name
        device: String,
    },
    /// Show ring buffer sizes
    #[command(short_flag = 'g')]
    Rings {
        /// Device name
        device: String,
    },
    /// Show channel counts
    #[command(short_flag = 'l')]
    Channels {
        /// Device name
        device: String,
    },
    /// Show coalesce parameters
    #[command(short_flag = 'c')]
    Coalesce {
        /// Device name
        device: String,
    },
    /// Show pause parameters
    #[command(short_flag = 'a')]
    Pause {
        /// Device name
        device: String,
    },
    /// Show standardized NIC statistics (IEEE 802.3 / RMON groups)
    #[command(short_flag = 'S')]
    Stats {
        /// Device name
        device: String,
    },
    /// Show Wake-on-LAN settings
    #[command(short_flag = 'w')]
    Wol {
        /// Device name
        device: String,
    },
    /// Set Wake-on-LAN modes
    #[command(short_flag = 'W')]
    SetWol {
        /// Device name
        device: String,
        /// WoL modes to enable: any of phy, ucast, mcast, bcast, arp,
        /// magic, magicsecure, filter (space-separated). Pass `none`
        /// to disable all.
        #[arg(trailing_var_arg = true)]
        modes: Vec<String>,
    },
    /// Show Energy-Efficient Ethernet settings
    Eee {
        /// Device name
        device: String,
    },
    /// Show Forward Error Correction settings
    Fec {
        /// Device name
        device: String,
    },
    /// Set Forward Error Correction settings
    SetFec {
        /// Device name
        device: String,
        /// FEC encodings to enable: any of off, none, rs, baser, llrs
        /// (space-separated; use the names `fec` reports for the device).
        #[arg(trailing_var_arg = true)]
        modes: Vec<String>,
        /// Enable/disable FEC auto-negotiation (on/off)
        #[arg(long)]
        auto: Option<bool>,
    },
    /// Dump SFP/QSFP module EEPROM bytes
    #[command(short_flag = 'm')]
    Module {
        /// Device name
        device: String,
        /// Byte offset within the page
        #[arg(long, default_value_t = 0)]
        offset: u32,
        /// Number of bytes to read (1..=128)
        #[arg(long, default_value_t = 128)]
        length: u32,
        /// Page number
        #[arg(long, default_value_t = 0)]
        page: u8,
        /// Bank number
        #[arg(long, default_value_t = 0)]
        bank: u8,
        /// I2C address (0x50 lower / 0x51 upper)
        #[arg(long, default_value_t = 0x50)]
        i2c_address: u8,
    },
    /// Set Energy-Efficient Ethernet settings
    SetEee {
        /// Device name
        device: String,
        /// Administratively enable/disable EEE (on/off)
        #[arg(long)]
        enabled: Option<bool>,
        /// Enable/disable TX low-power idle (on/off)
        #[arg(long)]
        tx_lpi: Option<bool>,
        /// TX low-power-idle timer in microseconds
        #[arg(long)]
        tx_lpi_timer: Option<u32>,
    },
    /// Set ring buffer sizes
    #[command(short_flag = 'G')]
    SetRings {
        /// Device name
        device: String,
        /// RX ring size
        #[arg(long)]
        rx: Option<u32>,
        /// TX ring size
        #[arg(long)]
        tx: Option<u32>,
    },
    /// Set channel counts
    #[command(short_flag = 'L')]
    SetChannels {
        /// Device name
        device: String,
        /// RX channels
        #[arg(long)]
        rx: Option<u32>,
        /// TX channels
        #[arg(long)]
        tx: Option<u32>,
        /// Combined channels
        #[arg(long)]
        combined: Option<u32>,
        /// Other channels
        #[arg(long)]
        other: Option<u32>,
    },
    /// Set coalesce parameters
    #[command(short_flag = 'C')]
    SetCoalesce {
        /// Device name
        device: String,
        /// RX microseconds
        #[arg(long)]
        rx_usecs: Option<u32>,
        /// TX microseconds
        #[arg(long)]
        tx_usecs: Option<u32>,
        /// RX max frames
        #[arg(long)]
        rx_frames: Option<u32>,
        /// TX max frames
        #[arg(long)]
        tx_frames: Option<u32>,
        /// Adaptive RX (on/off)
        #[arg(long)]
        adaptive_rx: Option<bool>,
        /// Adaptive TX (on/off)
        #[arg(long)]
        adaptive_tx: Option<bool>,
    },
    /// Set pause parameters
    #[command(short_flag = 'A')]
    SetPause {
        /// Device name
        device: String,
        /// Autonegotiate (on/off)
        #[arg(long)]
        autoneg: Option<bool>,
        /// RX pause (on/off)
        #[arg(long)]
        rx: Option<bool>,
        /// TX pause (on/off)
        #[arg(long)]
        tx: Option<bool>,
    },
    /// Set link speed/duplex/autoneg
    #[command(short_flag = 's')]
    SetSpeed {
        /// Device name
        device: String,
        /// Speed in Mb/s
        #[arg(long)]
        speed: Option<u32>,
        /// Duplex: full or half
        #[arg(long)]
        duplex: Option<String>,
        /// Autonegotiation (on/off)
        #[arg(long)]
        autoneg: Option<bool>,
    },
    /// Set device features (offloads): `<feature> on|off` pairs
    #[command(short_flag = 'K')]
    SetFeatures {
        /// Device name
        device: String,
        /// `<feature> on|off` pairs, e.g. `tx-checksumming on rx-checksumming off`
        #[arg(trailing_var_arg = true)]
        features: Vec<String>,
    },
    /// Monitor ethtool events
    Monitor,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    let command = match cli.command {
        Some(cmd) => cmd,
        None => {
            if let Some(device) = cli.device {
                Commands::Show { device }
            } else {
                eprintln!("Usage: nlink-ethtool <device> or nlink-ethtool <subcommand>");
                std::process::exit(1);
            }
        }
    };

    let json = cli.json;
    match command {
        Commands::Show { device } => show_device(&device, json).await?,
        Commands::Features { device } => show_features(&device, json).await?,
        Commands::SetFeatures { device, features } => set_features_cmd(&device, &features).await?,
        Commands::Rings { device } => show_rings(&device, json).await?,
        Commands::Channels { device } => show_channels(&device, json).await?,
        Commands::Coalesce { device } => show_coalesce(&device, json).await?,
        Commands::Pause { device } => show_pause(&device, json).await?,
        Commands::Stats { device } => show_stats(&device, json).await?,
        Commands::Wol { device } => show_wol(&device, json).await?,
        Commands::SetWol { device, modes } => set_wol(&device, &modes).await?,
        Commands::Eee { device } => show_eee(&device, json).await?,
        Commands::Fec { device } => show_fec(&device, json).await?,
        Commands::SetFec {
            device,
            modes,
            auto,
        } => set_fec(&device, &modes, auto).await?,
        Commands::Module {
            device,
            offset,
            length,
            page,
            bank,
            i2c_address,
        } => show_module_eeprom(&device, offset, length, page, bank, i2c_address, json).await?,
        Commands::SetEee {
            device,
            enabled,
            tx_lpi,
            tx_lpi_timer,
        } => set_eee(&device, enabled, tx_lpi, tx_lpi_timer).await?,
        Commands::SetRings { device, rx, tx } => set_rings(&device, rx, tx).await?,
        Commands::SetChannels {
            device,
            rx,
            tx,
            combined,
            other,
        } => set_channels(&device, rx, tx, combined, other).await?,
        Commands::SetCoalesce {
            device,
            rx_usecs,
            tx_usecs,
            rx_frames,
            tx_frames,
            adaptive_rx,
            adaptive_tx,
        } => {
            set_coalesce(
                &device,
                rx_usecs,
                tx_usecs,
                rx_frames,
                tx_frames,
                adaptive_rx,
                adaptive_tx,
            )
            .await?
        }
        Commands::SetPause {
            device,
            autoneg,
            rx,
            tx,
        } => set_pause(&device, autoneg, rx, tx).await?,
        Commands::SetSpeed {
            device,
            speed,
            duplex,
            autoneg,
        } => set_speed(&device, speed, duplex, autoneg).await?,
        Commands::Monitor => monitor_events().await?,
    }

    Ok(())
}

/// Print a value as pretty JSON on stdout.
fn print_json(value: &serde_json::Value) {
    println!(
        "{}",
        serde_json::to_string_pretty(value).expect("JSON serialization")
    );
}

fn duplex_str(d: Duplex) -> &'static str {
    match d {
        Duplex::Full => "Full",
        Duplex::Half => "Half",
        Duplex::Unknown => "Unknown",
        _ => "?",
    }
}

fn mdix_str(m: nlink::netlink::genl::ethtool::MdiX) -> &'static str {
    use nlink::netlink::genl::ethtool::MdiX;
    match m {
        MdiX::Mdi => "MDI",
        MdiX::MdiX => "MDI-X",
        MdiX::Auto => "Auto",
        _ => "Unknown",
    }
}

fn ext_state_str(s: nlink::netlink::genl::ethtool::LinkExtState) -> &'static str {
    use nlink::netlink::genl::ethtool::LinkExtState;
    match s {
        LinkExtState::Ok => "ok",
        LinkExtState::Autoneg => "autoneg",
        LinkExtState::LinkTrainingFailure => "link-training-failure",
        LinkExtState::LinkLogicalMismatch => "link-logical-mismatch",
        LinkExtState::BadSignalIntegrity => "bad-signal-integrity",
        LinkExtState::NoCable => "no-cable",
        LinkExtState::CableIssue => "cable-issue",
        LinkExtState::EepromIssue => "eeprom-issue",
        LinkExtState::CalibrationFailure => "calibration-failure",
        LinkExtState::PowerBudgetExceeded => "power-budget-exceeded",
        LinkExtState::Overheat => "overheat",
        LinkExtState::ModuleNotPresent => "module-not-present",
        _ => "unknown",
    }
}

async fn show_device(device: &str, json: bool) -> nlink::Result<()> {
    let conn = Connection::<Ethtool>::new_async().await?;

    let state = conn.get_link_state(device).await?;
    let modes = conn.get_link_modes(device).await?;
    let info = conn.get_link_info(device).await?;
    let supported = modes.supported_modes();
    let advertised = modes.advertised_modes();

    if json {
        print_json(&serde_json::json!({
            "device": device,
            "link_detected": state.link,
            "link_ext_state": state.ext_state.map(ext_state_str),
            "link_ext_substate": state.ext_substate,
            "sqi": state.sqi,
            "sqi_max": state.sqi_max,
            "speed_mbps": modes.speed,
            "duplex": modes.duplex.map(duplex_str),
            "autoneg": modes.autoneg,
            "port": info.port.map(|p| format!("{p:?}")),
            "phyad": info.phyaddr,
            "mdix": info.tp_mdix.map(mdix_str),
            "mdix_ctrl": info.tp_mdix_ctrl.map(mdix_str),
            "transceiver": info.transceiver.map(|t| format!("{t:?}")),
            "supported_modes": supported,
            "advertised_modes": advertised,
        }));
        return Ok(());
    }

    println!("Settings for {}:", device);
    if let Some(phyad) = info.phyaddr {
        println!("\tPHYAD: {}", phyad);
    }
    if let Some(mdix) = info.tp_mdix {
        let ctrl = info
            .tp_mdix_ctrl
            .map(|c| format!(" (configured: {})", mdix_str(c)))
            .unwrap_or_default();
        println!("\tMDI-X: {}{}", mdix_str(mdix), ctrl);
    }
    if let Some(sqi) = state.sqi {
        match state.sqi_max {
            Some(max) => println!("\tSQI: {}/{}", sqi, max),
            None => println!("\tSQI: {}", sqi),
        }
    }
    println!("\tLink detected: {}", if state.link { "yes" } else { "no" });
    // Only meaningful when the link is down: why.
    if let Some(ext) = state.ext_state
        && ext != nlink::netlink::genl::ethtool::LinkExtState::Ok
    {
        print!("\tLink extended state: {}", ext_state_str(ext));
        if let Some(sub) = state.ext_substate {
            print!(" (substate {})", sub);
        }
        println!();
    }
    if let Some(speed) = modes.speed {
        println!("\tSpeed: {}Mb/s", speed);
    } else {
        println!("\tSpeed: Unknown");
    }
    if let Some(duplex) = modes.duplex {
        println!("\tDuplex: {}", duplex_str(duplex));
    }
    println!(
        "\tAuto-negotiation: {}",
        if modes.autoneg { "on" } else { "off" }
    );
    if let Some(port) = info.port {
        println!("\tPort: {:?}", port);
    }
    if let Some(transceiver) = info.transceiver {
        println!("\tTransceiver: {:?}", transceiver);
    }
    if !supported.is_empty() {
        println!("\tSupported link modes:");
        for mode in &supported {
            println!("\t\t{}", mode);
        }
    }
    if !advertised.is_empty() {
        println!("\tAdvertised link modes:");
        for mode in &advertised {
            println!("\t\t{}", mode);
        }
    }

    Ok(())
}

async fn show_features(device: &str, json: bool) -> nlink::Result<()> {
    let conn = Connection::<Ethtool>::new_async().await?;
    let features = conn.get_features(device).await?;

    let mut items: Vec<_> = features.iter().collect();
    items.sort_by(|a, b| a.0.cmp(b.0));

    if json {
        let arr: Vec<_> = items
            .iter()
            .map(|(name, enabled)| {
                serde_json::json!({
                    "name": name,
                    "enabled": enabled,
                    "hw_supported": features.is_hw_supported(name),
                    "changeable": features.is_changeable(name),
                })
            })
            .collect();
        print_json(&serde_json::json!({ "device": device, "features": arr }));
        return Ok(());
    }

    println!("Features for {}:", device);
    for (name, enabled) in items {
        let hw_supported = features.is_hw_supported(name);
        let changeable = features.is_changeable(name);

        let status = if enabled { "on" } else { "off" };
        let mut notes = Vec::new();
        if !hw_supported {
            notes.push("not hw");
        }
        if !changeable {
            notes.push("fixed");
        }

        if notes.is_empty() {
            println!("{}: {}", name, status);
        } else {
            println!("{}: {} [{}]", name, status, notes.join(", "));
        }
    }

    Ok(())
}

async fn show_rings(device: &str, json: bool) -> nlink::Result<()> {
    let conn = Connection::<Ethtool>::new_async().await?;
    let rings = conn.get_rings(device).await?;

    if json {
        print_json(&serde_json::json!({
            "device": device,
            "max": {
                "rx": rings.rx_max, "rx_mini": rings.rx_mini_max,
                "rx_jumbo": rings.rx_jumbo_max, "tx": rings.tx_max,
            },
            "current": {
                "rx": rings.rx, "rx_mini": rings.rx_mini,
                "rx_jumbo": rings.rx_jumbo, "tx": rings.tx,
            },
        }));
        return Ok(());
    }

    println!("Ring parameters for {}:", device);

    println!("Pre-set maximums:");
    if let Some(v) = rings.rx_max {
        println!("\tRX:\t\t{}", v);
    }
    if let Some(v) = rings.rx_mini_max {
        println!("\tRX Mini:\t{}", v);
    }
    if let Some(v) = rings.rx_jumbo_max {
        println!("\tRX Jumbo:\t{}", v);
    }
    if let Some(v) = rings.tx_max {
        println!("\tTX:\t\t{}", v);
    }

    println!("Current hardware settings:");
    if let Some(v) = rings.rx {
        println!("\tRX:\t\t{}", v);
    }
    if let Some(v) = rings.rx_mini {
        println!("\tRX Mini:\t{}", v);
    }
    if let Some(v) = rings.rx_jumbo {
        println!("\tRX Jumbo:\t{}", v);
    }
    if let Some(v) = rings.tx {
        println!("\tTX:\t\t{}", v);
    }

    Ok(())
}

async fn show_channels(device: &str, json: bool) -> nlink::Result<()> {
    let conn = Connection::<Ethtool>::new_async().await?;
    let channels = conn.get_channels(device).await?;

    if json {
        print_json(&serde_json::json!({
            "device": device,
            "max": {
                "rx": channels.rx_max, "tx": channels.tx_max,
                "other": channels.other_max, "combined": channels.combined_max,
            },
            "current": {
                "rx": channels.rx_count, "tx": channels.tx_count,
                "other": channels.other_count, "combined": channels.combined_count,
            },
        }));
        return Ok(());
    }

    println!("Channel parameters for {}:", device);

    println!("Pre-set maximums:");
    if let Some(v) = channels.rx_max {
        println!("\tRX:\t\t{}", v);
    }
    if let Some(v) = channels.tx_max {
        println!("\tTX:\t\t{}", v);
    }
    if let Some(v) = channels.other_max {
        println!("\tOther:\t\t{}", v);
    }
    if let Some(v) = channels.combined_max {
        println!("\tCombined:\t{}", v);
    }

    println!("Current hardware settings:");
    if let Some(v) = channels.rx_count {
        println!("\tRX:\t\t{}", v);
    }
    if let Some(v) = channels.tx_count {
        println!("\tTX:\t\t{}", v);
    }
    if let Some(v) = channels.other_count {
        println!("\tOther:\t\t{}", v);
    }
    if let Some(v) = channels.combined_count {
        println!("\tCombined:\t{}", v);
    }

    Ok(())
}

async fn show_coalesce(device: &str, json: bool) -> nlink::Result<()> {
    let conn = Connection::<Ethtool>::new_async().await?;
    let coalesce = conn.get_coalesce(device).await?;

    if json {
        print_json(&serde_json::json!({
            "device": device,
            "rx_usecs": coalesce.rx_usecs,
            "rx_frames": coalesce.rx_max_frames,
            "rx_usecs_irq": coalesce.rx_usecs_irq,
            "rx_frames_irq": coalesce.rx_max_frames_irq,
            "tx_usecs": coalesce.tx_usecs,
            "tx_frames": coalesce.tx_max_frames,
            "tx_usecs_irq": coalesce.tx_usecs_irq,
            "tx_frames_irq": coalesce.tx_max_frames_irq,
            "adaptive_rx": coalesce.use_adaptive_rx,
            "adaptive_tx": coalesce.use_adaptive_tx,
        }));
        return Ok(());
    }

    println!("Coalesce parameters for {}:", device);

    if let Some(v) = coalesce.rx_usecs {
        println!("\trx-usecs:\t{}", v);
    }
    if let Some(v) = coalesce.rx_max_frames {
        println!("\trx-frames:\t{}", v);
    }
    if let Some(v) = coalesce.rx_usecs_irq {
        println!("\trx-usecs-irq:\t{}", v);
    }
    if let Some(v) = coalesce.rx_max_frames_irq {
        println!("\trx-frames-irq:\t{}", v);
    }
    if let Some(v) = coalesce.tx_usecs {
        println!("\ttx-usecs:\t{}", v);
    }
    if let Some(v) = coalesce.tx_max_frames {
        println!("\ttx-frames:\t{}", v);
    }
    if let Some(v) = coalesce.tx_usecs_irq {
        println!("\ttx-usecs-irq:\t{}", v);
    }
    if let Some(v) = coalesce.tx_max_frames_irq {
        println!("\ttx-frames-irq:\t{}", v);
    }
    if let Some(v) = coalesce.use_adaptive_rx {
        println!("\tadaptive-rx:\t{}", if v { "on" } else { "off" });
    }
    if let Some(v) = coalesce.use_adaptive_tx {
        println!("\tadaptive-tx:\t{}", if v { "on" } else { "off" });
    }

    Ok(())
}

async fn show_pause(device: &str, json: bool) -> nlink::Result<()> {
    let conn = Connection::<Ethtool>::new_async().await?;
    let pause = conn.get_pause(device).await?;

    if json {
        print_json(&serde_json::json!({
            "device": device,
            "autoneg": pause.autoneg,
            "rx": pause.rx,
            "tx": pause.tx,
            "stats": pause.stats.as_ref().map(|s| serde_json::json!({
                "tx_pause_frames": s.tx_frames,
                "rx_pause_frames": s.rx_frames,
            })),
        }));
        return Ok(());
    }

    println!("Pause parameters for {}:", device);

    if let Some(v) = pause.autoneg {
        println!("\tAutonegotiate:\t{}", if v { "on" } else { "off" });
    }
    if let Some(v) = pause.rx {
        println!("\tRX:\t\t{}", if v { "on" } else { "off" });
    }
    if let Some(v) = pause.tx {
        println!("\tTX:\t\t{}", if v { "on" } else { "off" });
    }
    if let Some(ref s) = pause.stats {
        println!("\tStatistics:");
        if let Some(n) = s.tx_frames {
            println!("\t\ttx_pause_frames: {}", n);
        }
        if let Some(n) = s.rx_frames {
            println!("\t\trx_pause_frames: {}", n);
        }
    }

    Ok(())
}

async fn show_wol(device: &str, json: bool) -> nlink::Result<()> {
    let conn = Connection::<Ethtool>::new_async().await?;
    let wol = conn.get_wol(device).await?;

    let sopass = wol
        .sopass
        .map(|p| nlink::util::addr::format_mac(&p));

    if json {
        print_json(&serde_json::json!({
            "device": device,
            "supported": wol.supported,
            "active": wol.active,
            "sopass": sopass,
        }));
        return Ok(());
    }

    println!("Wake-on-LAN settings for {}:", device);
    println!("\tSupports Wake-on:\t{}", wol_flags(&wol.supported));
    println!("\tWake-on:\t\t{}", wol_flags(&wol.active));
    if let Some(p) = sopass {
        println!("\tSecureOn password:\t{}", p);
    }
    Ok(())
}

/// Render WoL mode names as the single-letter flag string ethtool(8)
/// uses (`p u m b a g s f`), or `d` when nothing is set.
fn wol_flags(modes: &[String]) -> String {
    let mut s = String::new();
    for (name, ch) in [
        ("phy", 'p'),
        ("ucast", 'u'),
        ("mcast", 'm'),
        ("bcast", 'b'),
        ("arp", 'a'),
        ("magic", 'g'),
        ("magicsecure", 's'),
        ("filter", 'f'),
    ] {
        if modes.iter().any(|m| m == name) {
            s.push(ch);
        }
    }
    if s.is_empty() { "d".to_string() } else { s }
}

async fn set_wol(device: &str, modes: &[String]) -> nlink::Result<()> {
    let conn = Connection::<Ethtool>::new_async().await?;

    // `none`/`d` (ethtool's "disable" sentinels) clear all modes.
    let enable: Vec<String> = if modes.iter().any(|m| m == "none" || m == "d") {
        Vec::new()
    } else {
        modes.to_vec()
    };

    conn.set_wol(device, |w| w.modes(enable)).await?;
    eprintln!("Wake-on-LAN modes set for {}", device);
    Ok(())
}

async fn show_eee(device: &str, json: bool) -> nlink::Result<()> {
    let conn = Connection::<Ethtool>::new_async().await?;
    let eee = conn.get_eee(device).await?;

    if json {
        print_json(&serde_json::json!({
            "device": device,
            "active": eee.active,
            "enabled": eee.enabled,
            "tx_lpi_enabled": eee.tx_lpi_enabled,
            "tx_lpi_timer": eee.tx_lpi_timer,
            "advertised": eee.advertised,
            "peer": eee.peer,
        }));
        return Ok(());
    }

    let on = |v: Option<bool>| match v {
        Some(true) => "enabled",
        Some(false) => "disabled",
        None => "not reported",
    };

    println!("EEE settings for {}:", device);
    println!("\tEEE active:\t\t{}", on(eee.active));
    println!("\tEEE enabled:\t\t{}", on(eee.enabled));
    println!("\tTX LPI enabled:\t\t{}", on(eee.tx_lpi_enabled));
    if let Some(t) = eee.tx_lpi_timer {
        println!("\tTX LPI timer:\t\t{} us", t);
    }
    if !eee.advertised.is_empty() {
        println!("\tAdvertised EEE link modes: {}", eee.advertised.join(" "));
    }
    if !eee.peer.is_empty() {
        println!("\tLink partner EEE link modes: {}", eee.peer.join(" "));
    }
    Ok(())
}

async fn set_eee(
    device: &str,
    enabled: Option<bool>,
    tx_lpi: Option<bool>,
    tx_lpi_timer: Option<u32>,
) -> nlink::Result<()> {
    let conn = Connection::<Ethtool>::new_async().await?;
    conn.set_eee(device, |mut e| {
        if let Some(v) = enabled {
            e = e.enabled(v);
        }
        if let Some(v) = tx_lpi {
            e = e.tx_lpi_enabled(v);
        }
        if let Some(v) = tx_lpi_timer {
            e = e.tx_lpi_timer(v);
        }
        e
    })
    .await?;
    eprintln!("EEE settings updated for {}", device);
    Ok(())
}

async fn show_fec(device: &str, json: bool) -> nlink::Result<()> {
    let conn = Connection::<Ethtool>::new_async().await?;
    let fec = conn.get_fec(device).await?;

    if json {
        print_json(&serde_json::json!({
            "device": device,
            "modes": fec.modes,
            "auto": fec.auto,
            "active": fec.active,
        }));
        return Ok(());
    }

    println!("FEC settings for {}:", device);
    if !fec.modes.is_empty() {
        println!("\tConfigured FEC encodings: {}", fec.modes.join(" "));
    }
    if let Some(a) = fec.auto {
        println!("\tAuto-negotiation:\t{}", if a { "on" } else { "off" });
    }
    if let Some(active) = fec.active {
        println!("\tActive FEC mode (raw bit):\t{}", active);
    }
    Ok(())
}

async fn set_fec(device: &str, modes: &[String], auto: Option<bool>) -> nlink::Result<()> {
    if modes.is_empty() && auto.is_none() {
        return Err(nlink::Error::InvalidMessage(
            "set-fec: specify at least one encoding (off/none/rs/baser/llrs) or --auto".into(),
        ));
    }
    let conn = Connection::<Ethtool>::new_async().await?;
    conn.set_fec(device, |mut f| {
        for m in modes {
            f = f.mode(m);
        }
        if let Some(a) = auto {
            f = f.auto(a);
        }
        f
    })
    .await?;
    eprintln!("FEC settings updated for {}", device);
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn show_module_eeprom(
    device: &str,
    offset: u32,
    length: u32,
    page: u8,
    bank: u8,
    i2c_address: u8,
    json: bool,
) -> nlink::Result<()> {
    use nlink::netlink::genl::ethtool::ModuleEepromRequest;
    let conn = Connection::<Ethtool>::new_async().await?;
    let req = ModuleEepromRequest::new(offset, length)
        .page(page)
        .bank(bank)
        .i2c_address(i2c_address);
    let eeprom = conn.get_module_eeprom(device, req).await?;

    if json {
        print_json(&serde_json::json!({
            "device": device,
            "offset": offset,
            "length": eeprom.data.len(),
            "data": eeprom.data,
        }));
        return Ok(());
    }

    println!("Module EEPROM for {} (offset {}, {} bytes):", device, offset, eeprom.data.len());
    for (i, chunk) in eeprom.data.chunks(16).enumerate() {
        let hex: Vec<String> = chunk.iter().map(|b| format!("{b:02x}")).collect();
        println!("\t{:#06x}: {}", offset as usize + i * 16, hex.join(" "));
    }
    Ok(())
}

async fn show_stats(device: &str, json: bool) -> nlink::Result<()> {
    use nlink::netlink::genl::ethtool::{StatGroup, standard_stat_name, stats_group};

    let conn = Connection::<Ethtool>::new_async().await?;
    let stats = conn.get_eth_stats(device).await?;

    // (group label, kernel group id, the group's values).
    let groups: [(&str, u32, &Option<StatGroup>); 4] = [
        ("eth-phy", stats_group::ETH_PHY, &stats.eth_phy),
        ("eth-mac", stats_group::ETH_MAC, &stats.eth_mac),
        ("eth-ctrl", stats_group::ETH_CTRL, &stats.eth_ctrl),
        ("rmon", stats_group::RMON, &stats.rmon),
    ];

    if json {
        let mut obj = serde_json::Map::new();
        for (label, gid, group) in groups {
            if let Some(g) = group {
                let mut gobj = serde_json::Map::new();
                for (&index, &value) in &g.values {
                    let key = standard_stat_name(gid, index)
                        .map(|s| s.to_string())
                        .unwrap_or_else(|| index.to_string());
                    gobj.insert(key, serde_json::json!(value));
                }
                obj.insert(label.to_string(), serde_json::Value::Object(gobj));
            }
        }
        print_json(&serde_json::json!({ "device": device, "groups": obj }));
        return Ok(());
    }

    println!("Standardized statistics for {device}:");
    let mut any = false;
    for (label, gid, group) in groups {
        if let Some(g) = group {
            any = true;
            println!("  {label}:");
            for (&index, &value) in &g.values {
                match standard_stat_name(gid, index) {
                    Some(name) => println!("\t{name}: {value}"),
                    None => println!("\t[{index}]: {value}"),
                }
            }
        }
    }
    if !any {
        println!("  (no standardized stat groups reported by this device)");
    }

    Ok(())
}

async fn set_rings(device: &str, rx: Option<u32>, tx: Option<u32>) -> nlink::Result<()> {
    let conn = Connection::<Ethtool>::new_async().await?;
    conn.set_rings(device, |mut r| {
        if let Some(v) = rx {
            r = r.rx(v);
        }
        if let Some(v) = tx {
            r = r.tx(v);
        }
        r
    })
    .await?;
    eprintln!("Ring parameters set for {}", device);
    Ok(())
}

async fn set_channels(
    device: &str,
    rx: Option<u32>,
    tx: Option<u32>,
    combined: Option<u32>,
    other: Option<u32>,
) -> nlink::Result<()> {
    let conn = Connection::<Ethtool>::new_async().await?;
    conn.set_channels(device, |mut c| {
        if let Some(v) = rx {
            c = c.rx(v);
        }
        if let Some(v) = tx {
            c = c.tx(v);
        }
        if let Some(v) = combined {
            c = c.combined(v);
        }
        if let Some(v) = other {
            c = c.other(v);
        }
        c
    })
    .await?;
    eprintln!("Channel parameters set for {}", device);
    Ok(())
}

async fn set_coalesce(
    device: &str,
    rx_usecs: Option<u32>,
    tx_usecs: Option<u32>,
    rx_frames: Option<u32>,
    tx_frames: Option<u32>,
    adaptive_rx: Option<bool>,
    adaptive_tx: Option<bool>,
) -> nlink::Result<()> {
    let conn = Connection::<Ethtool>::new_async().await?;
    conn.set_coalesce(device, |mut c| {
        if let Some(v) = rx_usecs {
            c = c.rx_usecs(v);
        }
        if let Some(v) = tx_usecs {
            c = c.tx_usecs(v);
        }
        if let Some(v) = rx_frames {
            c = c.rx_max_frames(v);
        }
        if let Some(v) = tx_frames {
            c = c.tx_max_frames(v);
        }
        if let Some(v) = adaptive_rx {
            c = c.use_adaptive_rx(v);
        }
        if let Some(v) = adaptive_tx {
            c = c.use_adaptive_tx(v);
        }
        c
    })
    .await?;
    eprintln!("Coalesce parameters set for {}", device);
    Ok(())
}

async fn set_pause(
    device: &str,
    autoneg: Option<bool>,
    rx: Option<bool>,
    tx: Option<bool>,
) -> nlink::Result<()> {
    let conn = Connection::<Ethtool>::new_async().await?;
    conn.set_pause(device, |mut p| {
        if let Some(v) = autoneg {
            p = p.autoneg(v);
        }
        if let Some(v) = rx {
            p = p.rx(v);
        }
        if let Some(v) = tx {
            p = p.tx(v);
        }
        p
    })
    .await?;
    eprintln!("Pause parameters set for {}", device);
    Ok(())
}

async fn set_speed(
    device: &str,
    speed: Option<u32>,
    duplex: Option<String>,
    autoneg: Option<bool>,
) -> nlink::Result<()> {
    // Validate duplex up front — previously any non-`half` value
    // (incl. typos like `ful`) silently became Full.
    let duplex = duplex.as_deref().map(parse_duplex).transpose()?;

    let conn = Connection::<Ethtool>::new_async().await?;
    conn.set_link_modes(device, |mut m| {
        if let Some(v) = speed {
            m = m.speed(v);
        }
        if let Some(d) = duplex {
            m = m.duplex(d);
        }
        if let Some(v) = autoneg {
            m = m.autoneg(v);
        }
        m
    })
    .await?;
    eprintln!("Link modes set for {}", device);
    Ok(())
}

/// Parse a duplex token, rejecting anything but `full`/`half`.
fn parse_duplex(s: &str) -> nlink::Result<Duplex> {
    match s {
        "full" => Ok(Duplex::Full),
        "half" => Ok(Duplex::Half),
        other => Err(nlink::netlink::Error::InvalidMessage(format!(
            "ethtool: invalid duplex `{other}` (expected `full` or `half`)"
        ))),
    }
}

/// Parse `<feature> on|off` pairs from the trailing args of
/// `set-features`. Strict: an odd token count or a value that isn't
/// `on`/`off` is an error rather than a silently-dropped change.
fn parse_feature_pairs(tokens: &[String]) -> nlink::Result<Vec<(String, bool)>> {
    if tokens.is_empty() {
        return Err(nlink::netlink::Error::InvalidMessage(
            "ethtool set-features: expected at least one `<feature> on|off` pair".into(),
        ));
    }
    if !tokens.len().is_multiple_of(2) {
        return Err(nlink::netlink::Error::InvalidMessage(format!(
            "ethtool set-features: expected `<feature> on|off` pairs, got an odd number of \
             tokens ({})",
            tokens.len()
        )));
    }
    tokens
        .chunks(2)
        .map(|pair| {
            let on = match pair[1].as_str() {
                "on" | "true" => true,
                "off" | "false" => false,
                other => {
                    return Err(nlink::netlink::Error::InvalidMessage(format!(
                        "ethtool set-features: invalid value `{other}` for `{}` \
                         (expected on/off)",
                        pair[0]
                    )));
                }
            };
            Ok((pair[0].clone(), on))
        })
        .collect()
}

async fn set_features_cmd(device: &str, tokens: &[String]) -> nlink::Result<()> {
    let changes = parse_feature_pairs(tokens)?;
    let conn = Connection::<Ethtool>::new_async().await?;
    conn.set_features(device, |mut f| {
        for (name, on) in &changes {
            f = if *on { f.enable(name) } else { f.disable(name) };
        }
        f
    })
    .await?;
    eprintln!("Features set for {}", device);
    Ok(())
}

async fn monitor_events() -> nlink::Result<()> {
    use tokio_stream::StreamExt;

    println!("Monitoring ethtool events (Ctrl+C to stop)...\n");

    let conn = Connection::<Ethtool>::new_async().await?;
    conn.subscribe()?;

    let mut events = conn.events().await;
    while let Some(result) = events.next().await {
        match result {
            Ok(event) => {
                print_event(&event);
            }
            Err(e) => {
                eprintln!("Error: {}", e);
            }
        }
    }

    Ok(())
}

fn print_event(event: &EthtoolEvent) {
    match event {
        EthtoolEvent::LinkStateChanged { ifname, state } => {
            let name = ifname.as_deref().unwrap_or("?");
            println!(
                "[{}] link state: {}",
                name,
                if state.link { "up" } else { "down" }
            );
        }
        EthtoolEvent::LinkModesChanged { ifname, modes } => {
            let name = ifname.as_deref().unwrap_or("?");
            let speed = modes
                .speed
                .map(|s| format!("{}Mb/s", s))
                .unwrap_or_else(|| "?".into());
            let duplex = modes
                .duplex
                .map(|d| format!("{:?}", d))
                .unwrap_or_else(|| "?".into());
            println!("[{}] link modes: {} {}", name, speed, duplex);
        }
        EthtoolEvent::LinkInfoChanged { ifname, .. } => {
            let name = ifname.as_deref().unwrap_or("?");
            println!("[{}] link info changed", name);
        }
        EthtoolEvent::FeaturesChanged { ifname, .. } => {
            let name = ifname.as_deref().unwrap_or("?");
            println!("[{}] features changed", name);
        }
        EthtoolEvent::RingsChanged { ifname, .. } => {
            let name = ifname.as_deref().unwrap_or("?");
            println!("[{}] rings changed", name);
        }
        EthtoolEvent::ChannelsChanged { ifname, .. } => {
            let name = ifname.as_deref().unwrap_or("?");
            println!("[{}] channels changed", name);
        }
        EthtoolEvent::CoalesceChanged { ifname, .. } => {
            let name = ifname.as_deref().unwrap_or("?");
            println!("[{}] coalesce changed", name);
        }
        EthtoolEvent::PauseChanged { ifname, .. } => {
            let name = ifname.as_deref().unwrap_or("?");
            println!("[{}] pause changed", name);
        }
        EthtoolEvent::Unknown { cmd } => {
            println!("[?] unknown event (cmd={})", cmd);
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duplex_parse_strict() {
        assert!(matches!(parse_duplex("full"), Ok(Duplex::Full)));
        assert!(matches!(parse_duplex("half"), Ok(Duplex::Half)));
        // The whole point: typos must error, not default to Full.
        assert!(parse_duplex("ful").is_err());
        assert!(parse_duplex("").is_err());
    }

    #[test]
    fn mdix_and_ext_state_render() {
        use nlink::netlink::genl::ethtool::{LinkExtState, MdiX};
        assert_eq!(mdix_str(MdiX::MdiX), "MDI-X");
        assert_eq!(mdix_str(MdiX::Auto), "Auto");
        assert_eq!(ext_state_str(LinkExtState::NoCable), "no-cable");
        assert_eq!(ext_state_str(LinkExtState::Ok), "ok");
    }

    #[test]
    fn feature_pairs_parse() {
        let v = parse_feature_pairs(&[
            "tx-checksumming".into(),
            "on".into(),
            "rx-checksumming".into(),
            "off".into(),
        ])
        .unwrap();
        assert_eq!(
            v,
            vec![
                ("tx-checksumming".to_string(), true),
                ("rx-checksumming".to_string(), false),
            ]
        );
    }

    #[test]
    fn feature_pairs_strict() {
        assert!(parse_feature_pairs(&[]).is_err()); // nothing to do
        assert!(parse_feature_pairs(&["tx".into()]).is_err()); // odd count
        assert!(parse_feature_pairs(&["tx".into(), "maybe".into()]).is_err()); // bad value
    }
}
