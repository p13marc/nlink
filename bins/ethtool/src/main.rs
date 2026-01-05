//! nlink-ethtool: Proof-of-concept ethtool utility using nlink
//!
//! This binary demonstrates the nlink ethtool API. It is not intended
//! to be a full replacement for the standard ethtool command.

use clap::{Parser, Subcommand};
use nlink::netlink::genl::ethtool::{Duplex, EthtoolEvent};
use nlink::netlink::{Connection, Ethtool};

#[derive(Parser)]
#[command(name = "nlink-ethtool")]
#[command(about = "Query and control network device settings")]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    /// Device name (when no subcommand is given)
    #[arg(global = true)]
    device: Option<String>,
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

    match command {
        Commands::Show { device } => show_device(&device).await?,
        Commands::Features { device } => show_features(&device).await?,
        Commands::Rings { device } => show_rings(&device).await?,
        Commands::Channels { device } => show_channels(&device).await?,
        Commands::Coalesce { device } => show_coalesce(&device).await?,
        Commands::Pause { device } => show_pause(&device).await?,
        Commands::Monitor => monitor_events().await?,
    }

    Ok(())
}

async fn show_device(device: &str) -> nlink::Result<()> {
    let conn = Connection::<Ethtool>::new_async().await?;

    println!("Settings for {}:", device);

    // Link state
    let state = conn.get_link_state(device).await?;
    println!("\tLink detected: {}", if state.link { "yes" } else { "no" });

    // Link modes
    let modes = conn.get_link_modes(device).await?;
    if let Some(speed) = modes.speed {
        println!("\tSpeed: {}Mb/s", speed);
    } else {
        println!("\tSpeed: Unknown");
    }
    if let Some(duplex) = modes.duplex {
        let duplex_str = match duplex {
            Duplex::Full => "Full",
            Duplex::Half => "Half",
            Duplex::Unknown => "Unknown",
        };
        println!("\tDuplex: {}", duplex_str);
    }
    println!(
        "\tAuto-negotiation: {}",
        if modes.autoneg { "on" } else { "off" }
    );

    // Link info
    let info = conn.get_link_info(device).await?;
    if let Some(port) = info.port {
        println!("\tPort: {:?}", port);
    }
    if let Some(transceiver) = info.transceiver {
        println!("\tTransceiver: {:?}", transceiver);
    }

    // Supported modes
    let supported = modes.supported_modes();
    if !supported.is_empty() {
        println!("\tSupported link modes:");
        for mode in supported {
            println!("\t\t{}", mode);
        }
    }

    // Advertised modes
    let advertised = modes.advertised_modes();
    if !advertised.is_empty() {
        println!("\tAdvertised link modes:");
        for mode in advertised {
            println!("\t\t{}", mode);
        }
    }

    Ok(())
}

async fn show_features(device: &str) -> nlink::Result<()> {
    let conn = Connection::<Ethtool>::new_async().await?;
    let features = conn.get_features(device).await?;

    println!("Features for {}:", device);

    let mut items: Vec<_> = features.iter().collect();
    items.sort_by(|a, b| a.0.cmp(b.0));

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

async fn show_rings(device: &str) -> nlink::Result<()> {
    let conn = Connection::<Ethtool>::new_async().await?;
    let rings = conn.get_rings(device).await?;

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

async fn show_channels(device: &str) -> nlink::Result<()> {
    let conn = Connection::<Ethtool>::new_async().await?;
    let channels = conn.get_channels(device).await?;

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

async fn show_coalesce(device: &str) -> nlink::Result<()> {
    let conn = Connection::<Ethtool>::new_async().await?;
    let coalesce = conn.get_coalesce(device).await?;

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

async fn show_pause(device: &str) -> nlink::Result<()> {
    let conn = Connection::<Ethtool>::new_async().await?;
    let pause = conn.get_pause(device).await?;

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

    Ok(())
}

async fn monitor_events() -> nlink::Result<()> {
    use tokio_stream::StreamExt;

    println!("Monitoring ethtool events (Ctrl+C to stop)...\n");

    let mut conn = Connection::<Ethtool>::new_async().await?;
    conn.subscribe()?;

    let mut events = conn.events();
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
    }
}
