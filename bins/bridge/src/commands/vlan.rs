//! `bridge vlan` command implementation.

use clap::{Args, Subcommand};
use nlink::{
    netlink::{
        Connection, Error, Result, Route,
        bridge_vlan::{
            BridgeVlanBuilder, BridgeVlanEntry, BridgeVlanEntryOptionsBuilder,
            BridgeVlanGlobalOptionsBuilder, BridgeVlanState, BridgeVlanTunnelBuilder,
        },
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
    /// Manage bridge-global per-VLAN options (multicast snooping)
    #[command(visible_alias = "gopts")]
    Global {
        #[command(subcommand)]
        command: GlobalCommand,
    },
    /// Manage per-VLAN entry options on a port (STP state, mcast router)
    #[command(visible_alias = "opts")]
    Options {
        #[command(subcommand)]
        command: OptionsCommand,
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

#[derive(Subcommand)]
enum GlobalCommand {
    /// Show bridge-global per-VLAN options
    #[command(visible_alias = "list", visible_alias = "ls")]
    Show {
        /// Bridge device
        #[arg(long)]
        dev: String,
    },
    /// Set bridge-global per-VLAN options
    Set(GlobalSetArgs),
}

#[derive(Subcommand)]
enum OptionsCommand {
    /// Show per-VLAN entry options on a port
    #[command(visible_alias = "list", visible_alias = "ls")]
    Show {
        /// Bridge port device
        #[arg(long)]
        dev: String,
    },
    /// Set per-VLAN entry options on a port
    Set(OptionsSetArgs),
}

#[derive(Args)]
struct OptionsSetArgs {
    /// VLAN ID or range (e.g., 100 or 100-110)
    #[arg(long)]
    vid: String,

    /// Bridge port device
    #[arg(long)]
    dev: String,

    /// Per-VLAN STP state (disabled|listening|learning|forwarding|blocking)
    #[arg(long)]
    state: Option<BridgeVlanStateArg>,

    /// Per-VLAN multicast router mode (0 disabled, 1 temp, 2 perm)
    #[arg(long)]
    mcast_router: Option<u8>,

    /// Per-VLAN multicast group limit
    #[arg(long)]
    mcast_max_groups: Option<u32>,

    /// Neighbour suppression (on/off)
    #[arg(long, value_parser = clap::builder::BoolishValueParser::new())]
    neigh_suppress: Option<bool>,
}

#[derive(Clone, Copy, clap::ValueEnum)]
enum BridgeVlanStateArg {
    Disabled,
    Listening,
    Learning,
    Forwarding,
    Blocking,
}

impl From<BridgeVlanStateArg> for BridgeVlanState {
    fn from(v: BridgeVlanStateArg) -> Self {
        match v {
            BridgeVlanStateArg::Disabled => BridgeVlanState::Disabled,
            BridgeVlanStateArg::Listening => BridgeVlanState::Listening,
            BridgeVlanStateArg::Learning => BridgeVlanState::Learning,
            BridgeVlanStateArg::Forwarding => BridgeVlanState::Forwarding,
            BridgeVlanStateArg::Blocking => BridgeVlanState::Blocking,
        }
    }
}

#[derive(Args)]
struct GlobalSetArgs {
    /// VLAN ID or range (e.g., 100 or 100-110)
    #[arg(long)]
    vid: String,

    /// Bridge device
    #[arg(long)]
    dev: String,

    /// Per-VLAN multicast snooping (on/off)
    #[arg(long, value_parser = clap::builder::BoolishValueParser::new())]
    mcast_snooping: Option<bool>,

    /// Per-VLAN multicast querier (on/off)
    #[arg(long, value_parser = clap::builder::BoolishValueParser::new())]
    mcast_querier: Option<bool>,

    /// IGMP query version (2 or 3)
    #[arg(long)]
    mcast_igmp_version: Option<u8>,

    /// MLD query version (1 or 2)
    #[arg(long)]
    mcast_mld_version: Option<u8>,

    /// MST instance id this VLAN maps to
    #[arg(long)]
    msti: Option<u16>,
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
            Some(VlanCommand::Global { command }) => match command {
                GlobalCommand::Show { dev } => show_global(conn, &dev, format, opts).await,
                GlobalCommand::Set(args) => set_global(conn, args).await,
            },
            Some(VlanCommand::Options { command }) => match command {
                OptionsCommand::Show { dev } => show_options(conn, &dev, format, opts).await,
                OptionsCommand::Set(args) => set_options(conn, args).await,
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
        // No --dev: aggregate VLAN entries across every bridge in the
        // namespace, matching `bridge vlan show` with no device.
        let mut all = Vec::new();
        for link in conn.get_links().await? {
            if link.link_info().and_then(|i| i.kind()) == Some("bridge") {
                all.extend(conn.get_bridge_vlans_all_by_index(link.ifindex()).await?);
            }
        }
        all
    };

    // Build ifindex -> name map
    let names = conn.get_interface_names().await?;

    match format {
        OutputFormat::Json => print_vlans_json(&entries, &names, opts)?,
        OutputFormat::Text => print_vlans_text(&entries, &names),
    }

    Ok(())
}

fn print_vlans_text(entries: &[BridgeVlanEntry], names: &std::collections::HashMap<u32, String>) {
    // Group by interface
    let mut by_dev: std::collections::HashMap<u32, Vec<&BridgeVlanEntry>> =
        std::collections::HashMap::new();
    for entry in entries {
        by_dev.entry(entry.ifindex()).or_default().push(entry);
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

            println!("{:<12} {}{}", port_col, vlan.vid(), flags_str);
        }
    }
}

fn print_vlans_json(
    entries: &[BridgeVlanEntry],
    names: &std::collections::HashMap<u32, String>,
    opts: &OutputOptions,
) -> Result<()> {
    // Group by interface, then sort by ifindex so the output is
    // deterministic regardless of HashMap iteration order.
    let mut by_dev: std::collections::HashMap<u32, Vec<&BridgeVlanEntry>> =
        std::collections::HashMap::new();
    for entry in entries {
        by_dev.entry(entry.ifindex()).or_default().push(entry);
    }
    let mut by_dev: Vec<(u32, Vec<&BridgeVlanEntry>)> = by_dev.into_iter().collect();
    by_dev.sort_by_key(|(ifindex, _)| *ifindex);

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
                        "vid": v.vid(),
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

    println!("{}", super::to_json_string(&json_output, opts.pretty)?);
    Ok(())
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

            println!("{}", super::to_json_string(&json_output, opts.pretty)?);
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

async fn show_global(
    conn: &Connection<Route>,
    dev: &str,
    format: OutputFormat,
    opts: &OutputOptions,
) -> Result<()> {
    let mut opts_list = conn.get_bridge_vlan_global_options(dev).await?;
    opts_list.sort_by_key(|o| o.vid());

    match format {
        OutputFormat::Json => {
            let json_output: Vec<serde_json::Value> = opts_list
                .iter()
                .map(|o| {
                    serde_json::json!({
                        "vid": o.vid(),
                        "vid_end": o.vid_end(),
                        "mcast_snooping": o.mcast_snooping(),
                        "mcast_querier": o.mcast_querier(),
                        "mcast_igmp_version": o.mcast_igmp_version(),
                        "mcast_mld_version": o.mcast_mld_version(),
                        "msti": o.msti(),
                    })
                })
                .collect();
            println!("{}", super::to_json_string(&json_output, opts.pretty)?);
        }
        OutputFormat::Text => {
            println!("{:<8} {:<12} options", "bridge", "vlan-id");
            for (i, o) in opts_list.iter().enumerate() {
                let vid = match o.vid_end() {
                    Some(end) => format!("{}-{}", o.vid(), end),
                    None => o.vid().to_string(),
                };
                let mut flags = Vec::new();
                if let Some(v) = o.mcast_snooping() {
                    flags.push(format!("mcast_snooping {}", on_off(v)));
                }
                if let Some(v) = o.mcast_querier() {
                    flags.push(format!("mcast_querier {}", on_off(v)));
                }
                if let Some(v) = o.mcast_igmp_version() {
                    flags.push(format!("mcast_igmp_version {v}"));
                }
                if let Some(v) = o.mcast_mld_version() {
                    flags.push(format!("mcast_mld_version {v}"));
                }
                if let Some(v) = o.msti() {
                    flags.push(format!("msti {v}"));
                }
                let bridge_col = if i == 0 { dev } else { "" };
                println!("{:<8} {:<12} {}", bridge_col, vid, flags.join(" "));
            }
        }
    }

    Ok(())
}

fn on_off(v: bool) -> &'static str {
    if v { "on" } else { "off" }
}

async fn show_options(
    conn: &Connection<Route>,
    dev: &str,
    format: OutputFormat,
    opts: &OutputOptions,
) -> Result<()> {
    let mut list = conn.get_bridge_vlan_entry_options(dev).await?;
    list.sort_by_key(|o| o.vid());

    match format {
        OutputFormat::Json => {
            let json_output: Vec<serde_json::Value> = list
                .iter()
                .map(|o| {
                    serde_json::json!({
                        "vid": o.vid(),
                        "vid_end": o.vid_end(),
                        "state": o.state().map(|s| format!("{s:?}")),
                        "mcast_router": o.mcast_router(),
                        "mcast_max_groups": o.mcast_max_groups(),
                        "neigh_suppress": o.neigh_suppress(),
                    })
                })
                .collect();
            println!("{}", super::to_json_string(&json_output, opts.pretty)?);
        }
        OutputFormat::Text => {
            println!("{:<8} {:<12} options", "port", "vlan-id");
            for (i, o) in list.iter().enumerate() {
                let vid = match o.vid_end() {
                    Some(end) => format!("{}-{}", o.vid(), end),
                    None => o.vid().to_string(),
                };
                let mut flags = Vec::new();
                if let Some(s) = o.state() {
                    flags.push(format!("state {s:?}"));
                }
                if let Some(v) = o.mcast_router() {
                    flags.push(format!("mcast_router {v}"));
                }
                if let Some(v) = o.neigh_suppress() {
                    flags.push(format!("neigh_suppress {}", on_off(v)));
                }
                let port_col = if i == 0 { dev } else { "" };
                println!("{:<8} {:<12} {}", port_col, vid, flags.join(" "));
            }
        }
    }

    Ok(())
}

async fn set_options(conn: &Connection<Route>, args: OptionsSetArgs) -> Result<()> {
    let (vid_start, vid_end) = parse_vid_range(&args.vid)?;

    let mut builder = BridgeVlanEntryOptionsBuilder::new(vid_start).dev(&args.dev);
    if let Some(end) = vid_end {
        builder = builder.range(end);
    }
    if let Some(state) = args.state {
        builder = builder.state(state.into());
    }
    if let Some(v) = args.mcast_router {
        builder = builder.mcast_router(v);
    }
    if let Some(v) = args.mcast_max_groups {
        builder = builder.mcast_max_groups(v);
    }
    if let Some(v) = args.neigh_suppress {
        builder = builder.neigh_suppress(v);
    }

    conn.set_bridge_vlan_entry_options(builder).await
}

async fn set_global(conn: &Connection<Route>, args: GlobalSetArgs) -> Result<()> {
    let (vid_start, vid_end) = parse_vid_range(&args.vid)?;

    let mut builder = BridgeVlanGlobalOptionsBuilder::new(vid_start).dev(&args.dev);
    if let Some(end) = vid_end {
        builder = builder.range(end);
    }
    if let Some(v) = args.mcast_snooping {
        builder = builder.mcast_snooping(v);
    }
    if let Some(v) = args.mcast_querier {
        builder = builder.mcast_querier(v);
    }
    if let Some(v) = args.mcast_igmp_version {
        builder = builder.mcast_igmp_version(v);
    }
    if let Some(v) = args.mcast_mld_version {
        builder = builder.mcast_mld_version(v);
    }
    if let Some(v) = args.msti {
        builder = builder.msti(v);
    }

    conn.set_bridge_vlan_global_options(builder).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_single_vid() {
        assert_eq!(parse_vid_range("100").unwrap(), (100, None));
    }

    #[test]
    fn parses_vid_range() {
        assert_eq!(parse_vid_range("100-110").unwrap(), (100, Some(110)));
    }

    #[test]
    fn rejects_reversed_range() {
        let e = parse_vid_range("110-100").unwrap_err().to_string();
        assert!(e.contains("start must be <= end"), "{e}");
    }

    #[test]
    fn rejects_zero_and_out_of_band() {
        assert!(parse_vid_range("0").is_err());
        assert!(parse_vid_range("4095").is_err());
        assert!(parse_vid_range("1-4095").is_err());
    }

    #[test]
    fn rejects_non_numeric() {
        assert!(parse_vid_range("abc").is_err());
    }
}
