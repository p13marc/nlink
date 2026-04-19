//! `bridge vlan` command implementation.

use clap::{Args, Subcommand};
use nlink::{
    netlink::{
        Connection, Error, Result, Route,
        bridge_vlan::{BridgeVlanBuilder, BridgeVlanEntry, BridgeVlanTunnelBuilder},
    },
    output::{OutputFormat, OutputOptions},
};

#[derive(Args)]
pub struct VlanCmd {
    #[command(subcommand)]
    command: Option<VlanCommand>,
}

#[derive(Subcommand)]
enum VlanCommand {
    /// Show VLAN configuration
    #[command(visible_alias = "list", visible_alias = "ls")]
    Show {
        /// Port device (optional, shows all if omitted)
        #[arg(long)]
        dev: Option<String>,
    },
    /// Add VLAN to a port
    Add(VlanAddArgs),
    /// Delete VLAN from a port
    #[command(visible_alias = "delete")]
    Del(VlanDelArgs),
    /// Set PVID for a port
    Set(VlanSetArgs),
    /// Manage VLAN-to-tunnel (VNI) mappings
    Tunnel {
        #[command(subcommand)]
        command: TunnelCommand,
    },
}

#[derive(Args)]
struct VlanAddArgs {
    /// VLAN ID (1-4094) or range (e.g., 100-110)
    #[arg(long)]
    vid: String,

    /// Port device
    #[arg(long)]
    dev: String,

    /// Set as PVID (native VLAN)
    #[arg(long)]
    pvid: bool,

    /// Egress untagged
    #[arg(long)]
    untagged: bool,
}

#[derive(Args)]
struct VlanDelArgs {
    /// VLAN ID or range (e.g., 100 or 100-110)
    #[arg(long)]
    vid: String,

    /// Port device
    #[arg(long)]
    dev: String,
}

#[derive(Args)]
struct VlanSetArgs {
    /// PVID to set
    #[arg(long)]
    pvid: u16,

    /// Port device
    #[arg(long)]
    dev: String,
}

#[derive(Subcommand)]
enum TunnelCommand {
    /// Show VLAN tunnel mappings
    #[command(visible_alias = "list", visible_alias = "ls")]
    Show {
        /// Port device
        #[arg(long)]
        dev: String,
    },
    /// Add VLAN-to-VNI tunnel mapping
    Add(TunnelAddArgs),
    /// Delete VLAN-to-VNI tunnel mapping
    #[command(visible_alias = "delete")]
    Del(TunnelDelArgs),
}

#[derive(Args)]
struct TunnelAddArgs {
    /// VLAN ID
    #[arg(long)]
    vid: u16,

    /// Tunnel ID (VNI)
    #[arg(long)]
    tunnel_id: u32,

    /// Port device
    #[arg(long)]
    dev: String,

    /// End of VLAN range (maps VID..range_end to VNI..VNI+(range_end-vid))
    #[arg(long)]
    range: Option<u16>,
}

#[derive(Args)]
struct TunnelDelArgs {
    /// VLAN ID
    #[arg(long)]
    vid: u16,

    /// Port device
    #[arg(long)]
    dev: String,

    /// End of VLAN range
    #[arg(long)]
    range: Option<u16>,
}

impl VlanCmd {
    pub async fn run(
        self,
        conn: &Connection<Route>,
        format: OutputFormat,
        opts: &OutputOptions,
    ) -> Result<()> {
        match self.command {
            None => {
                // Default to show all
                show_vlans(conn, None, format, opts).await
            }
            Some(VlanCommand::Show { dev }) => show_vlans(conn, dev, format, opts).await,
            Some(VlanCommand::Add(args)) => add_vlan(conn, args).await,
            Some(VlanCommand::Del(args)) => del_vlan(conn, args).await,
            Some(VlanCommand::Set(args)) => set_pvid(conn, args).await,
            Some(VlanCommand::Tunnel { command }) => match command {
                TunnelCommand::Show { dev } => show_tunnels(conn, &dev, format, opts).await,
                TunnelCommand::Add(args) => add_tunnel(conn, args).await,
                TunnelCommand::Del(args) => del_tunnel(conn, args).await,
            },
        }
    }
}

/// Parse a VLAN ID or range string (e.g., "100" or "100-110").
fn parse_vid_range(s: &str) -> Result<(u16, Option<u16>)> {
    if let Some((start, end)) = s.split_once('-') {
        let start_vid: u16 = start
            .trim()
            .parse()
            .map_err(|_| Error::InvalidMessage(format!("invalid VLAN ID: {}", start)))?;
        let end_vid: u16 = end
            .trim()
            .parse()
            .map_err(|_| Error::InvalidMessage(format!("invalid VLAN ID: {}", end)))?;

        if start_vid > end_vid {
            return Err(Error::InvalidMessage(
                "VLAN range start must be <= end".into(),
            ));
        }
        if start_vid == 0 || start_vid > 4094 || end_vid > 4094 {
            return Err(Error::InvalidMessage("VLAN ID must be 1-4094".into()));
        }

        Ok((start_vid, Some(end_vid)))
    } else {
        let vid: u16 = s
            .trim()
            .parse()
            .map_err(|_| Error::InvalidMessage(format!("invalid VLAN ID: {}", s)))?;

        if vid == 0 || vid > 4094 {
            return Err(Error::InvalidMessage("VLAN ID must be 1-4094".into()));
        }

        Ok((vid, None))
    }
}

async fn show_vlans(
    conn: &Connection<Route>,
    dev: Option<String>,
    format: OutputFormat,
    opts: &OutputOptions,
) -> Result<()> {
    let entries = if let Some(ref name) = dev {
        conn.get_bridge_vlans(name).await?
    } else {
        // Get all bridge VLANs - we need to dump all links with VLAN filter
        // For now, return an error suggesting to specify a device
        return Err(Error::InvalidMessage(
            "please specify a device with --dev".into(),
        ));
    };

    // Build ifindex -> name map
    let names = conn.get_interface_names().await?;

    match format {
        OutputFormat::Json => print_vlans_json(&entries, &names, opts),
        OutputFormat::Text => print_vlans_text(&entries, &names),
    }

    Ok(())
}

fn print_vlans_text(entries: &[BridgeVlanEntry], names: &std::collections::HashMap<u32, String>) {
    // Group by interface
    let mut by_dev: std::collections::HashMap<u32, Vec<&BridgeVlanEntry>> =
        std::collections::HashMap::new();
    for entry in entries {
        by_dev.entry(entry.ifindex).or_default().push(entry);
    }

    println!("{:<12} vlan-id", "port");

    for (ifindex, vlans) in by_dev {
        let dev = names.get(&ifindex).map(|s| s.as_str()).unwrap_or("?");

        for (i, vlan) in vlans.iter().enumerate() {
            let port_col = if i == 0 { dev } else { "" };

            let mut flags = Vec::new();
            if vlan.is_pvid() {
                flags.push("PVID");
            }
            if vlan.is_untagged() {
                flags.push("Egress Untagged");
            }

            let flags_str = if flags.is_empty() {
                String::new()
            } else {
                format!(" {}", flags.join(" "))
            };

            println!("{:<12} {}{}", port_col, vlan.vid, flags_str);
        }
    }
}

fn print_vlans_json(
    entries: &[BridgeVlanEntry],
    names: &std::collections::HashMap<u32, String>,
    opts: &OutputOptions,
) {
    // Group by interface
    let mut by_dev: std::collections::HashMap<u32, Vec<&BridgeVlanEntry>> =
        std::collections::HashMap::new();
    for entry in entries {
        by_dev.entry(entry.ifindex).or_default().push(entry);
    }

    let json_output: Vec<serde_json::Value> = by_dev
        .into_iter()
        .map(|(ifindex, vlans)| {
            let dev = names
                .get(&ifindex)
                .cloned()
                .unwrap_or_else(|| "?".to_string());

            let vlan_list: Vec<serde_json::Value> = vlans
                .iter()
                .map(|v| {
                    serde_json::json!({
                        "vid": v.vid,
                        "pvid": v.is_pvid(),
                        "untagged": v.is_untagged(),
                    })
                })
                .collect();

            serde_json::json!({
                "ifindex": ifindex,
                "dev": dev,
                "vlans": vlan_list,
            })
        })
        .collect();

    let output = if opts.pretty {
        serde_json::to_string_pretty(&json_output).expect("JSON serialization")
    } else {
        serde_json::to_string(&json_output).expect("JSON serialization")
    };
    println!("{}", output);
}

async fn add_vlan(conn: &Connection<Route>, args: VlanAddArgs) -> Result<()> {
    let (vid_start, vid_end) = parse_vid_range(&args.vid)?;

    let mut builder = BridgeVlanBuilder::new(vid_start).dev(&args.dev);

    if let Some(end) = vid_end {
        builder = builder.range(end);
    }

    if args.pvid {
        builder = builder.pvid();
    }

    if args.untagged {
        builder = builder.untagged();
    }

    conn.add_bridge_vlan(builder).await
}

async fn del_vlan(conn: &Connection<Route>, args: VlanDelArgs) -> Result<()> {
    let (vid_start, vid_end) = parse_vid_range(&args.vid)?;

    if let Some(end) = vid_end {
        conn.del_bridge_vlan_range(&args.dev, vid_start, end).await
    } else {
        conn.del_bridge_vlan(&args.dev, vid_start).await
    }
}

async fn set_pvid(conn: &Connection<Route>, args: VlanSetArgs) -> Result<()> {
    conn.set_bridge_pvid(&args.dev, args.pvid).await
}

async fn show_tunnels(
    conn: &Connection<Route>,
    dev: &str,
    format: OutputFormat,
    opts: &OutputOptions,
) -> Result<()> {
    let tunnels = conn.get_vlan_tunnels(dev).await?;

    match format {
        OutputFormat::Json => {
            let json_output: Vec<serde_json::Value> = tunnels
                .iter()
                .map(|t| {
                    serde_json::json!({
                        "vid": t.vid,
                        "tunnel_id": t.tunnel_id,
                    })
                })
                .collect();

            let output = if opts.pretty {
                serde_json::to_string_pretty(&json_output).expect("JSON serialization")
            } else {
                serde_json::to_string(&json_output).expect("JSON serialization")
            };
            println!("{}", output);
        }
        OutputFormat::Text => {
            let header = format!("{:<8} {:<12} {}", "port", "vlan-id", "tunnel-id");
            println!("{header}");
            for (i, t) in tunnels.iter().enumerate() {
                let port_col = if i == 0 { dev } else { "" };
                println!("{:<8} {:<12} {}", port_col, t.vid, t.tunnel_id);
            }
        }
    }

    Ok(())
}

async fn add_tunnel(conn: &Connection<Route>, args: TunnelAddArgs) -> Result<()> {
    let mut builder = BridgeVlanTunnelBuilder::new(args.vid, args.tunnel_id).dev(&args.dev);

    if let Some(end) = args.range {
        builder = builder.range(end);
    }

    conn.add_vlan_tunnel(builder).await
}

async fn del_tunnel(conn: &Connection<Route>, args: TunnelDelArgs) -> Result<()> {
    if let Some(end) = args.range {
        conn.del_vlan_tunnel_range(&args.dev, args.vid, end).await
    } else {
        conn.del_vlan_tunnel(&args.dev, args.vid).await
    }
}
