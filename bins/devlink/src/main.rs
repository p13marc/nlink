//! devlink - Hardware device management utility.
//!
//! Manages devlink devices, ports, health reporters, and parameters
//! via Generic Netlink.

use clap::{Parser, Subcommand};
use nlink::{
    Rate,
    netlink::{
        Connection, Devlink, Result,
        genl::devlink::{
            ConfigMode, DevlinkPortFunctionState, DevlinkRate, DevlinkRateType, FlashRequest,
            ParamData, ReloadAction,
        },
    },
};
use tokio_stream::StreamExt;

#[derive(Parser)]
#[command(name = "devlink", version, about = "Devlink device management utility")]
struct Cli {
    /// Emit machine-readable JSON instead of the default text output.
    #[arg(long, short, global = true)]
    json: bool,

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

    /// Manage rate objects (port-function / scheduler-node shaping).
    Rate {
        #[command(subcommand)]
        action: RateAction,
    },

    /// Show shared-buffer instances.
    Sb,

    /// Show packet traps.
    Trap,

    /// Show address regions.
    Region,

    /// Show hardware resources for a device.
    Resource {
        /// Bus name (e.g., "pci").
        bus: String,
        /// Device name (e.g., "0000:03:00.0").
        device: String,
    },
}

#[derive(Subcommand)]
enum RateAction {
    /// Add a rate object (leaf by default; --node for a scheduler node).
    Add {
        /// Bus name.
        bus: String,
        /// Device name.
        device: String,
        /// Rate-object node name.
        node: String,
        /// Create a scheduler node instead of a leaf.
        #[arg(long)]
        node_type: bool,
        /// Guaranteed share (tc-style rate, e.g. `100mbit`).
        #[arg(long)]
        tx_share: Option<String>,
        /// Maximum cap (tc-style rate, e.g. `1gbit`).
        #[arg(long)]
        tx_max: Option<String>,
        /// Parent scheduler node name.
        #[arg(long)]
        parent: Option<String>,
    },
    /// Set parameters on an existing rate object.
    Set {
        /// Bus name.
        bus: String,
        /// Device name.
        device: String,
        /// Rate-object node name.
        node: String,
        /// Create/treat as a scheduler node instead of a leaf.
        #[arg(long)]
        node_type: bool,
        /// Guaranteed share (tc-style rate).
        #[arg(long)]
        tx_share: Option<String>,
        /// Maximum cap (tc-style rate).
        #[arg(long)]
        tx_max: Option<String>,
        /// Parent scheduler node name.
        #[arg(long)]
        parent: Option<String>,
    },
    /// Delete a rate object.
    Del {
        /// Bus name.
        bus: String,
        /// Device name.
        device: String,
        /// Rate-object node name.
        node: String,
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

    /// Split a port into sub-ports.
    Split {
        /// Bus name.
        bus: String,
        /// Device name.
        device: String,
        /// Port index.
        port: u32,
        /// Number of sub-ports to split into.
        count: u32,
    },

    /// Unsplit a previously split port.
    Unsplit {
        /// Bus name.
        bus: String,
        /// Device name.
        device: String,
        /// Port index.
        port: u32,
    },

    /// Set a port-function state (activate/deactivate an SR-IOV VF).
    Function {
        /// Bus name.
        bus: String,
        /// Device name.
        device: String,
        /// Port index.
        port: u32,
        /// State: "active" or "inactive".
        state: String,
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
        let conn = Connection::<Devlink>::new_async().await?;
        conn.subscribe()?;
        eprintln!("Monitoring devlink events (Ctrl+C to stop)...");
        let mut events = conn.events().await;
        while let Some(result) = events.next().await {
            match result {
                Ok(event) => println!("{}", format_event(&event)),
                Err(e) => eprintln!("Error: {e}"),
            }
        }
        return Ok(());
    }

    let json = cli.json;
    let conn = Connection::<Devlink>::new_async().await?;

    match cli.command {
        Command::Dev { action } => {
            let _ = action; // show is default
            let devices = conn.get_devices().await?;
            if json {
                let arr: Vec<_> = devices
                    .iter()
                    .map(|dev| {
                        serde_json::json!({
                            "bus": dev.bus,
                            "device": dev.device,
                            "path": dev.path(),
                        })
                    })
                    .collect();
                print_json(&serde_json::Value::Array(arr));
            } else {
                for dev in &devices {
                    println!("{}", dev.path());
                }
            }
        }

        Command::Port { action } => match action {
            None | Some(PortAction::Show { .. }) => {
                let (filter_bus, filter_dev) = match action {
                    Some(PortAction::Show { bus, device }) => (bus, device),
                    _ => (None, None),
                };
                let ports = conn.get_ports().await?;
                let filtered: Vec<_> = ports
                    .iter()
                    .filter(|port| {
                        filter_bus.as_ref().is_none_or(|b| &port.bus == b)
                            && filter_dev.as_ref().is_none_or(|d| &port.device == d)
                    })
                    .collect();
                if json {
                    let arr: Vec<_> = filtered
                        .iter()
                        .map(|port| {
                            serde_json::json!({
                                "bus": port.bus,
                                "device": port.device,
                                "index": port.index,
                                "path": port.path(),
                                "type": format!("{:?}", port.port_type),
                                "netdev": port.netdev_name,
                                "flavour": port.flavour.map(|f| format!("{f:?}")),
                            })
                        })
                        .collect();
                    print_json(&serde_json::Value::Array(arr));
                } else {
                    for port in filtered {
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
            }

            Some(PortAction::Split {
                bus,
                device,
                port,
                count,
            }) => {
                conn.port_split(&bus, &device, port, count).await?;
                eprintln!("Port {port} split into {count}");
            }

            Some(PortAction::Unsplit { bus, device, port }) => {
                conn.port_unsplit(&bus, &device, port).await?;
                eprintln!("Port {port} unsplit");
            }

            Some(PortAction::Function {
                bus,
                device,
                port,
                state,
            }) => {
                let state = match state.as_str() {
                    "active" => DevlinkPortFunctionState::Active,
                    "inactive" => DevlinkPortFunctionState::Inactive,
                    other => {
                        return Err(nlink::netlink::Error::InvalidMessage(format!(
                            "devlink port function: invalid state `{other}` (expected active/inactive)"
                        )));
                    }
                };
                conn.set_port_function_state(&bus, &device, port, state)
                    .await?;
                eprintln!("Port {port} function set to {state:?}");
            }
        },

        Command::Info { bus, device } => {
            let info = conn.get_device_info(&bus, &device).await?;
            if json {
                let versions = |vs: &[nlink::netlink::genl::devlink::VersionInfo]| {
                    vs.iter()
                        .map(|v| serde_json::json!({"name": v.name, "value": v.value}))
                        .collect::<Vec<_>>()
                };
                print_json(&serde_json::json!({
                    "bus": info.bus,
                    "device": info.device,
                    "driver": info.driver,
                    "serial": info.serial,
                    "board_serial": info.board_serial,
                    "versions_fixed": versions(&info.versions_fixed),
                    "versions_running": versions(&info.versions_running),
                    "versions_stored": versions(&info.versions_stored),
                    "pending_update": info.has_pending_update(),
                }));
            } else {
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
        }

        Command::Health { action } => match action {
            HealthAction::Show { bus, device } => {
                let reporters = conn.get_health_reporters(&bus, &device).await?;
                if json {
                    let arr: Vec<_> = reporters
                        .iter()
                        .map(|r| {
                            serde_json::json!({
                                "name": r.name,
                                "state": format!("{:?}", r.state),
                                "error_count": r.error_count,
                                "recover_count": r.recover_count,
                                "auto_recover": r.auto_recover,
                                "auto_dump": r.auto_dump,
                            })
                        })
                        .collect();
                    print_json(&serde_json::Value::Array(arr));
                } else {
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
                if json {
                    let arr: Vec<_> = params
                        .iter()
                        .map(|p| {
                            let values: Vec<_> = p
                                .values
                                .iter()
                                .map(|v| {
                                    serde_json::json!({
                                        "cmode": format!("{:?}", v.cmode),
                                        "value": v.data.to_string(),
                                    })
                                })
                                .collect();
                            serde_json::json!({
                                "name": p.name,
                                "generic": p.generic,
                                "values": values,
                            })
                        })
                        .collect();
                    print_json(&serde_json::Value::Array(arr));
                } else {
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
                // Read the parameter's declared type first so the value is
                // parsed into it (instead of lossily inferring bool→u32→str).
                let existing = conn.get_param(&bus, &device, &name).await?;
                let declared = existing
                    .as_ref()
                    .and_then(|p| p.values.first())
                    .map(|v| &v.data);
                let data = coerce_param_value(&name, value, declared)?;
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

        // Mutating commands report status on stderr regardless of --json.
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

        Command::Rate { action } => match action {
            RateAction::Add {
                bus,
                device,
                node,
                node_type,
                tx_share,
                tx_max,
                parent,
            } => {
                let rate =
                    build_rate(&bus, &device, &node, node_type, &tx_share, &tx_max, &parent)?;
                conn.add_rate(&rate).await?;
                eprintln!("Rate object {node} added");
            }
            RateAction::Set {
                bus,
                device,
                node,
                node_type,
                tx_share,
                tx_max,
                parent,
            } => {
                let rate =
                    build_rate(&bus, &device, &node, node_type, &tx_share, &tx_max, &parent)?;
                conn.set_rate(&rate).await?;
                eprintln!("Rate object {node} updated");
            }
            RateAction::Del { bus, device, node } => {
                conn.del_rate(&bus, &device, &node).await?;
                eprintln!("Rate object {node} deleted");
            }
        },

        Command::Sb => {
            let buffers = conn.get_shared_buffers().await?;
            if json {
                let arr: Vec<_> = buffers
                    .iter()
                    .map(|sb| {
                        serde_json::json!({
                            "bus": sb.bus,
                            "device": sb.device,
                            "index": sb.index,
                            "size": sb.size,
                            "ingress_pools": sb.ingress_pools,
                            "egress_pools": sb.egress_pools,
                            "ingress_tcs": sb.ingress_tcs,
                            "egress_tcs": sb.egress_tcs,
                        })
                    })
                    .collect();
                print_json(&serde_json::Value::Array(arr));
            } else {
                for sb in &buffers {
                    println!(
                        "{}/{} sb {} size {} ingress_pools {} egress_pools {}",
                        sb.bus, sb.device, sb.index, sb.size, sb.ingress_pools, sb.egress_pools
                    );
                }
            }
        }

        Command::Trap => {
            let traps = conn.get_traps().await?;
            if json {
                let arr: Vec<_> = traps
                    .iter()
                    .map(|t| {
                        serde_json::json!({
                            "bus": t.bus,
                            "device": t.device,
                            "name": t.name,
                            "action": t.action.as_str(),
                            "type": t.trap_type.as_str(),
                            "generic": t.generic,
                            "group": t.group,
                        })
                    })
                    .collect();
                print_json(&serde_json::Value::Array(arr));
            } else {
                for t in &traps {
                    print!(
                        "{}/{} trap {} type {} action {}",
                        t.bus,
                        t.device,
                        t.name,
                        t.trap_type.as_str(),
                        t.action.as_str()
                    );
                    if let Some(ref g) = t.group {
                        print!(" group {g}");
                    }
                    println!();
                }
            }
        }

        Command::Region => {
            let regions = conn.get_regions().await?;
            if json {
                let arr: Vec<_> = regions
                    .iter()
                    .map(|r| {
                        serde_json::json!({
                            "bus": r.bus,
                            "device": r.device,
                            "name": r.name,
                            "size": r.size,
                            "snapshots": r.snapshot_count,
                        })
                    })
                    .collect();
                print_json(&serde_json::Value::Array(arr));
            } else {
                for r in &regions {
                    print!("{}/{} region {}", r.bus, r.device, r.name);
                    if let Some(size) = r.size {
                        print!(" size {size}");
                    }
                    println!(" snapshots {}", r.snapshot_count);
                }
            }
        }

        Command::Resource { bus, device } => {
            let resources = conn.get_resources(&bus, &device).await?;
            if json {
                let arr: Vec<_> = resources
                    .iter()
                    .map(|r| {
                        serde_json::json!({
                            "bus": r.bus,
                            "device": r.device,
                            "name": r.name,
                            "id": r.id,
                            "size": r.size,
                            "occ": r.occ,
                            "size_valid": r.size_valid,
                        })
                    })
                    .collect();
                print_json(&serde_json::Value::Array(arr));
            } else {
                for r in &resources {
                    print!("{} size {}", r.name, r.size);
                    if let Some(occ) = r.occ {
                        print!(" occ {occ}");
                    }
                    println!();
                }
            }
        }
    }

    Ok(())
}

/// Parse a tc-style rate string (`100mbit`, `1gbit`, ...).
fn parse_rate(s: &str) -> Result<Rate> {
    s.parse::<Rate>().map_err(|_| {
        nlink::netlink::Error::InvalidMessage(format!(
            "devlink rate: invalid rate `{s}` (expected tc-style rate like `100mbit`)"
        ))
    })
}

/// Build a `DevlinkRate` from CLI args, parsing the rate strings.
fn build_rate(
    bus: &str,
    device: &str,
    node: &str,
    node_type: bool,
    tx_share: &Option<String>,
    tx_max: &Option<String>,
    parent: &Option<String>,
) -> Result<DevlinkRate> {
    let mut rate = DevlinkRate::new(bus, device, node);
    if node_type {
        rate = rate.rate_type(DevlinkRateType::Node);
    }
    if let Some(s) = tx_share {
        rate = rate.tx_share(parse_rate(s)?);
    }
    if let Some(s) = tx_max {
        rate = rate.tx_max(parse_rate(s)?);
    }
    if let Some(p) = parent {
        rate = rate.parent_node(p);
    }
    Ok(rate)
}

/// Coerce a CLI `param set` value string into the parameter's declared type.
///
/// `existing` is the parameter's current value (from `get_param`), whose
/// `ParamData` variant tells us the real type. Parsing into that type avoids
/// the lossy "bool → u32 → string" inference that silently mis-typed `u8`/
/// `u16` params and all-digit string labels. When the param can't be read
/// (`None`), fall back to best-effort inference so the command still works.
fn coerce_param_value(name: &str, value: String, existing: Option<&ParamData>) -> Result<ParamData> {
    let int = |bits: &str, max: u64| -> Result<u64> {
        value.parse::<u64>().ok().filter(|n| *n <= max).ok_or_else(|| {
            nlink::netlink::Error::InvalidMessage(format!(
                "devlink param `{name}` expects a {bits} value, got `{value}`"
            ))
        })
    };
    let data = match existing {
        Some(ParamData::U8(_)) => ParamData::U8(int("u8", u8::MAX as u64)? as u8),
        Some(ParamData::U16(_)) => ParamData::U16(int("u16", u16::MAX as u64)? as u16),
        Some(ParamData::U32(_)) => ParamData::U32(int("u32", u32::MAX as u64)? as u32),
        Some(ParamData::Bool(_)) => ParamData::Bool(match value.as_str() {
            "true" | "1" | "on" => true,
            "false" | "0" | "off" => false,
            _ => {
                return Err(nlink::netlink::Error::InvalidMessage(format!(
                    "devlink param `{name}` expects a boolean (true/false), got `{value}`"
                )));
            }
        }),
        Some(ParamData::String(_)) => ParamData::String(value),
        // Param not found, or a future ParamData variant: best-effort infer.
        _ => infer_param_value(value),
    };
    Ok(data)
}

/// Best-effort type inference from a value string (used only when the
/// parameter's declared type is unavailable).
fn infer_param_value(value: String) -> ParamData {
    if value == "true" || value == "false" {
        ParamData::Bool(value == "true")
    } else if let Ok(n) = value.parse::<u32>() {
        ParamData::U32(n)
    } else {
        ParamData::String(value)
    }
}

/// Render a monitored devlink event as a readable line instead of the raw
/// `{:?}` Debug form.
fn format_event(event: &nlink::netlink::genl::devlink::DevlinkEvent) -> String {
    use nlink::netlink::genl::devlink::DevlinkEvent;
    match event {
        DevlinkEvent::NewDevice { bus, device } => format!("new device {bus}/{device}"),
        DevlinkEvent::DelDevice { bus, device } => format!("del device {bus}/{device}"),
        DevlinkEvent::NewPort {
            bus,
            device,
            port_index,
            netdev_name,
        } => {
            let nd = netdev_name
                .as_deref()
                .map(|n| format!(" ({n})"))
                .unwrap_or_default();
            format!("new port {bus}/{device} port {port_index}{nd}")
        }
        DevlinkEvent::DelPort {
            bus,
            device,
            port_index,
        } => format!("del port {bus}/{device} port {port_index}"),
        DevlinkEvent::HealthEvent {
            bus,
            device,
            reporter,
        } => {
            let r = reporter.as_deref().unwrap_or("?");
            format!("health event {bus}/{device} reporter {r}")
        }
        DevlinkEvent::FlashUpdate(p) => {
            let comp = p
                .component
                .as_deref()
                .map(|c| format!(" [{c}]"))
                .unwrap_or_default();
            let msg = p.message.as_deref().unwrap_or("");
            format!("flash update{comp} {}/{} {msg}", p.done, p.total)
                .trim_end()
                .to_string()
        }
        // DevlinkEvent is #[non_exhaustive]; future variants fall back.
        other => format!("{other:?}"),
    }
}

/// Print a JSON value as pretty-printed JSON on stdout.
fn print_json(value: &serde_json::Value) {
    println!(
        "{}",
        serde_json::to_string_pretty(value).expect("JSON serialization")
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rate_parse_strict() {
        assert!(parse_rate("100mbit").is_ok());
        assert!(parse_rate("1gbit").is_ok());
        assert!(parse_rate("notarate").is_err());
    }

    #[test]
    fn format_event_renders_readable() {
        use nlink::netlink::genl::devlink::DevlinkEvent;
        assert_eq!(
            format_event(&DevlinkEvent::NewDevice {
                bus: "pci".into(),
                device: "0000:01:00.0".into()
            }),
            "new device pci/0000:01:00.0"
        );
        assert_eq!(
            format_event(&DevlinkEvent::NewPort {
                bus: "pci".into(),
                device: "d".into(),
                port_index: 3,
                netdev_name: Some("eth3".into()),
            }),
            "new port pci/d port 3 (eth3)"
        );
    }

    #[test]
    fn coerce_respects_declared_type() {
        // A u8 param keeps its width and rejects out-of-range values.
        let got = coerce_param_value("p", "200".into(), Some(&ParamData::U8(0))).unwrap();
        assert!(matches!(got, ParamData::U8(200)));
        assert!(coerce_param_value("p", "300".into(), Some(&ParamData::U8(0))).is_err());

        // A u16 param doesn't collapse to u32.
        assert!(matches!(
            coerce_param_value("p", "5000".into(), Some(&ParamData::U16(0))).unwrap(),
            ParamData::U16(5000)
        ));

        // A string param keeps an all-digits label as a String, not U32.
        assert!(matches!(
            coerce_param_value("p", "12345".into(), Some(&ParamData::String(String::new()))).unwrap(),
            ParamData::String(s) if s == "12345"
        ));
    }

    #[test]
    fn coerce_bool_param_is_strict() {
        assert!(matches!(
            coerce_param_value("p", "on".into(), Some(&ParamData::Bool(false))).unwrap(),
            ParamData::Bool(true)
        ));
        assert!(coerce_param_value("p", "maybe".into(), Some(&ParamData::Bool(false))).is_err());
    }

    #[test]
    fn coerce_falls_back_to_inference_when_type_unknown() {
        // No declared type (param not found): infer.
        assert!(matches!(
            coerce_param_value("p", "true".into(), None).unwrap(),
            ParamData::Bool(true)
        ));
        assert!(matches!(
            coerce_param_value("p", "42".into(), None).unwrap(),
            ParamData::U32(42)
        ));
        assert!(matches!(
            coerce_param_value("p", "label".into(), None).unwrap(),
            ParamData::String(s) if s == "label"
        ));
    }

    #[test]
    fn build_rate_sets_type_and_fields() {
        let leaf = build_rate("pci", "0000:01:00.0", "vf0", false, &None, &None, &None).unwrap();
        assert_eq!(leaf.rate_type, DevlinkRateType::Leaf);
        assert_eq!(leaf.node_name, "vf0");

        let node = build_rate(
            "pci",
            "0000:01:00.0",
            "group0",
            true,
            &Some("100mbit".to_string()),
            &Some("1gbit".to_string()),
            &Some("root".to_string()),
        )
        .unwrap();
        assert_eq!(node.rate_type, DevlinkRateType::Node);
        assert_eq!(node.parent_node.as_deref(), Some("root"));
        assert!(node.tx_share.is_some());
        assert!(node.tx_max.is_some());

        // bad rate string propagates
        assert!(
            build_rate("pci", "d", "n", false, &Some("bad".into()), &None, &None).is_err()
        );
    }
}
