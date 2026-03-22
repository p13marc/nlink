//! devlink - Hardware device management utility.
//!
//! Manages devlink devices, ports, health reporters, and parameters
//! via Generic Netlink.

use clap::{Parser, Subcommand};
use nlink::netlink::genl::devlink::{ConfigMode, FlashRequest, ParamData, ReloadAction};
use nlink::netlink::{Connection, Devlink, Result};
use tokio_stream::StreamExt;

#[derive(Parser)]
#[command(name = "devlink", version, about = "Devlink device management utility")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// List devlink devices.
    Dev {
        #[command(subcommand)]
        action: Option<DevAction>,
    },

    /// Manage devlink ports.
    Port {
        #[command(subcommand)]
        action: Option<PortAction>,
    },

    /// Show device firmware and driver info.
    Info {
        /// Bus name (e.g., "pci").
        bus: String,
        /// Device name (e.g., "0000:03:00.0").
        device: String,
    },

    /// Manage health reporters.
    Health {
        #[command(subcommand)]
        action: HealthAction,
    },

    /// Manage device parameters.
    Param {
        #[command(subcommand)]
        action: ParamAction,
    },

    /// Flash firmware to a device.
    Flash {
        /// Bus name.
        bus: String,
        /// Device name.
        device: String,
        /// Firmware file path.
        file: String,
        /// Component to flash.
        #[arg(long)]
        component: Option<String>,
    },

    /// Monitor devlink events.
    Monitor,

    /// Reload a device.
    Reload {
        /// Bus name.
        bus: String,
        /// Device name.
        device: String,
        /// Reload action: "driver_reinit" or "fw_activate".
        #[arg(long, default_value = "driver_reinit")]
        action: String,
    },
}

#[derive(Subcommand)]
enum DevAction {
    /// Show all devices.
    Show,
}

#[derive(Subcommand)]
enum PortAction {
    /// Show all ports.
    Show {
        /// Filter by bus name.
        #[arg(long)]
        bus: Option<String>,
        /// Filter by device name.
        #[arg(long)]
        device: Option<String>,
    },
}

#[derive(Subcommand)]
enum HealthAction {
    /// Show health reporters.
    Show {
        /// Bus name.
        bus: String,
        /// Device name.
        device: String,
    },

    /// Trigger recovery on a reporter.
    Recover {
        /// Bus name.
        bus: String,
        /// Device name.
        device: String,
        /// Reporter name.
        reporter: String,
    },
}

#[derive(Subcommand)]
enum ParamAction {
    /// Show device parameters.
    Show {
        /// Bus name.
        bus: String,
        /// Device name.
        device: String,
    },

    /// Set a device parameter.
    Set {
        /// Bus name.
        bus: String,
        /// Device name.
        device: String,
        /// Parameter name.
        name: String,
        /// Parameter value.
        value: String,
        /// Configuration mode: "runtime", "driverinit", or "permanent".
        #[arg(long, default_value = "runtime")]
        cmode: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    // Monitor needs a mutable connection for subscribe()
    if matches!(cli.command, Command::Monitor) {
        let mut conn = Connection::<Devlink>::new_async().await?;
        conn.subscribe()?;
        eprintln!("Monitoring devlink events (Ctrl+C to stop)...");
        let mut events = conn.events();
        while let Some(result) = events.next().await {
            match result {
                Ok(event) => println!("{event:?}"),
                Err(e) => eprintln!("Error: {e}"),
            }
        }
        return Ok(());
    }

    let conn = Connection::<Devlink>::new_async().await?;

    match cli.command {
        Command::Dev { action } => {
            let _ = action; // show is default
            let devices = conn.get_devices().await?;
            for dev in &devices {
                println!("{}", dev.path());
            }
        }

        Command::Port { action } => {
            let ports = conn.get_ports().await?;
            let (filter_bus, filter_dev) = match action {
                Some(PortAction::Show { bus, device }) => (bus, device),
                None => (None, None),
            };
            for port in &ports {
                if let Some(ref b) = filter_bus
                    && &port.bus != b
                {
                    continue;
                }
                if let Some(ref d) = filter_dev
                    && &port.device != d
                {
                    continue;
                }
                print!("{}", port.path());
                if let Some(ref name) = port.netdev_name {
                    print!(" netdev {name}");
                }
                if let Some(flavour) = port.flavour {
                    print!(" flavour {flavour:?}");
                }
                println!();
            }
        }

        Command::Info { bus, device } => {
            let info = conn.get_device_info(&bus, &device).await?;
            println!("{}/{}", info.bus, info.device);
            println!("  driver: {}", info.driver);
            if let Some(ref serial) = info.serial {
                println!("  serial: {serial}");
            }
            if !info.versions_fixed.is_empty() {
                println!("  versions (fixed):");
                for v in &info.versions_fixed {
                    println!("    {}: {}", v.name, v.value);
                }
            }
            if !info.versions_running.is_empty() {
                println!("  versions (running):");
                for v in &info.versions_running {
                    println!("    {}: {}", v.name, v.value);
                }
            }
            if !info.versions_stored.is_empty() {
                println!("  versions (stored):");
                for v in &info.versions_stored {
                    println!("    {}: {}", v.name, v.value);
                }
            }
            if info.has_pending_update() {
                println!("  ** pending firmware update **");
            }
        }

        Command::Health { action } => match action {
            HealthAction::Show { bus, device } => {
                let reporters = conn.get_health_reporters(&bus, &device).await?;
                for r in &reporters {
                    print!("{}: state={:?}", r.name, r.state);
                    if r.error_count > 0 {
                        print!(" errors={}", r.error_count);
                    }
                    if r.recover_count > 0 {
                        print!(" recoveries={}", r.recover_count);
                    }
                    print!(" auto_recover={} auto_dump={}", r.auto_recover, r.auto_dump);
                    println!();
                }
            }
            HealthAction::Recover {
                bus,
                device,
                reporter,
            } => {
                conn.health_reporter_recover(&bus, &device, &reporter)
                    .await?;
                eprintln!("Recovery triggered for {reporter}");
            }
        },

        Command::Param { action } => match action {
            ParamAction::Show { bus, device } => {
                let params = conn.get_params(&bus, &device).await?;
                for p in &params {
                    print!("{}:", p.name);
                    if p.generic {
                        print!(" [generic]");
                    }
                    for v in &p.values {
                        print!(" {:?}={}", v.cmode, v.data);
                    }
                    println!();
                }
            }
            ParamAction::Set {
                bus,
                device,
                name,
                value,
                cmode,
            } => {
                let cmode = match cmode.as_str() {
                    "runtime" => ConfigMode::Runtime,
                    "driverinit" => ConfigMode::Driverinit,
                    "permanent" => ConfigMode::Permanent,
                    _ => {
                        eprintln!("Unknown cmode: {cmode}. Use runtime, driverinit, or permanent.");
                        std::process::exit(1);
                    }
                };
                // Try as bool, then u32, then string
                let data = if value == "true" || value == "false" {
                    ParamData::Bool(value == "true")
                } else if let Ok(n) = value.parse::<u32>() {
                    ParamData::U32(n)
                } else {
                    ParamData::String(value)
                };
                conn.set_param(&bus, &device, &name, cmode, data).await?;
                eprintln!("Parameter {name} set");
            }
        },

        Command::Flash {
            bus,
            device,
            file,
            component,
        } => {
            let mut request = FlashRequest::new(file);
            if let Some(c) = component {
                request = request.component(c);
            }
            conn.flash_update(&bus, &device, request).await?;
            eprintln!("Flash update initiated");
        }

        Command::Monitor => unreachable!(),

        Command::Reload {
            bus,
            device,
            action,
        } => {
            let action = match action.as_str() {
                "driver_reinit" => ReloadAction::DriverReinit,
                "fw_activate" => ReloadAction::FwActivate,
                _ => {
                    eprintln!("Unknown action: {action}. Use driver_reinit or fw_activate.");
                    std::process::exit(1);
                }
            };
            conn.reload(&bus, &device, action).await?;
            eprintln!("Reload complete");
        }
    }

    Ok(())
}
