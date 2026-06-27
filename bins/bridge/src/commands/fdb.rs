//! `bridge fdb` command implementation.

use std::net::IpAddr;

use clap::{Args, Subcommand};
use nlink::{
    netlink::{
        Connection, Error, Result, Route,
        fdb::{FdbEntry, FdbEntryBuilder},
    },
    output::{OutputFormat, OutputOptions},
};

#[derive(Args)]
pub struct FdbCmd {
    #[command(subcommand)]
    command: Option<FdbCommand>,
}

#[derive(Subcommand)]
enum FdbCommand {
    /// Show FDB entries
    #[command(visible_alias = "list", visible_alias = "ls")]
    Show {
        /// Bridge or port device
        dev: Option<String>,
    },
    /// Add FDB entry
    Add(FdbAddArgs),
    /// Replace FDB entry (add or update)
    Replace(FdbAddArgs),
    /// Delete FDB entry
    #[command(visible_alias = "delete")]
    Del(FdbDelArgs),
    /// Flush dynamic FDB entries
    Flush {
        /// Bridge device
        dev: String,
    },
}

#[derive(Args)]
struct FdbAddArgs {
    /// MAC address
    mac: String,

    /// Port device
    #[arg(long)]
    dev: String,

    /// Bridge device (master)
    #[arg(long)]
    master: Option<String>,

    /// VLAN ID
    #[arg(long)]
    vlan: Option<u16>,

    /// Remote VTEP destination (for VXLAN)
    #[arg(long)]
    dst: Option<IpAddr>,

    /// VXLAN VNI for the remote destination
    #[arg(long)]
    vni: Option<u32>,

    /// Permanent (static) entry
    #[arg(long)]
    permanent: bool,

    /// Dynamic (ageable) entry — the kernel default, explicit for clarity
    #[arg(long)]
    dynamic: bool,

    /// Self entry (entry on the device itself)
    #[arg(long, name = "self")]
    self_entry: bool,
}

#[derive(Args)]
struct FdbDelArgs {
    /// MAC address
    mac: String,

    /// Port device
    #[arg(long)]
    dev: String,

    /// VLAN ID
    #[arg(long)]
    vlan: Option<u16>,
}

impl FdbCmd {
    pub async fn run(
        self,
        conn: &Connection<Route>,
        format: OutputFormat,
        opts: &OutputOptions,
    ) -> Result<()> {
        match self.command {
            None => {
                // Default to show all
                show_fdb(conn, None, format, opts).await
            }
            Some(FdbCommand::Show { dev }) => show_fdb(conn, dev, format, opts).await,
            Some(FdbCommand::Add(args)) => add_fdb(conn, args, false).await,
            Some(FdbCommand::Replace(args)) => add_fdb(conn, args, true).await,
            Some(FdbCommand::Del(args)) => del_fdb(conn, args).await,
            Some(FdbCommand::Flush { dev }) => flush_fdb(conn, &dev).await,
        }
    }
}

async fn show_fdb(
    conn: &Connection<Route>,
    dev: Option<String>,
    format: OutputFormat,
    opts: &OutputOptions,
) -> Result<()> {
    let entries = if let Some(ref name) = dev {
        conn.get_fdb(name).await?
    } else {
        // No device: aggregate FDB entries across every bridge in the
        // namespace, matching `bridge fdb show` with no device.
        let mut all = Vec::new();
        for link in conn.get_links().await? {
            if link.link_info().and_then(|i| i.kind()) == Some("bridge") {
                all.extend(conn.get_fdb_by_index(link.ifindex()).await?);
            }
        }
        all
    };

    // Build ifindex -> name map
    let names = conn.get_interface_names().await?;

    match format {
        OutputFormat::Json => print_fdb_json(&entries, &names, opts),
        OutputFormat::Text => print_fdb_text(&entries, &names, opts),
    }

    Ok(())
}

fn print_fdb_text(
    entries: &[FdbEntry],
    names: &std::collections::HashMap<u32, String>,
    opts: &OutputOptions,
) {
    for entry in entries {
        let dev = names.get(&entry.ifindex()).map(|s| s.as_str()).unwrap_or("?");

        let mut line = format!("{} dev {}", entry.mac_str(), dev);

        if let Some(master_idx) = entry.master()
            && let Some(master) = names.get(&master_idx)
        {
            line.push_str(&format!(" master {}", master));
        }

        if let Some(vlan) = entry.vlan() {
            line.push_str(&format!(" vlan {}", vlan));
        }

        if let Some(dst) = entry.dst() {
            line.push_str(&format!(" dst {}", dst));
        }

        if let Some(vni) = entry.vni() {
            line.push_str(&format!(" vni {}", vni));
        }

        // State
        if entry.is_permanent() {
            line.push_str(" permanent");
        }

        // Flags
        if entry.is_self() {
            line.push_str(" self");
        }
        if entry.is_extern_learn() {
            line.push_str(" extern_learn");
        }

        // -d/--details: surface the raw NUD state (REACHABLE, STALE, …)
        // that the summary "permanent/dynamic" line hides.
        if opts.details {
            line.push_str(&format!(" state {}", entry.state().name()));
        }

        println!("{}", line);
    }
}

fn print_fdb_json(
    entries: &[FdbEntry],
    names: &std::collections::HashMap<u32, String>,
    opts: &OutputOptions,
) {
    let json_entries: Vec<serde_json::Value> = entries
        .iter()
        .map(|entry| {
            let mut obj = serde_json::json!({
                "mac": entry.mac_str(),
                "ifindex": entry.ifindex(),
            });

            if let Some(dev) = names.get(&entry.ifindex()) {
                obj["dev"] = serde_json::json!(dev);
            }

            if let Some(master_idx) = entry.master() {
                obj["master_ifindex"] = serde_json::json!(master_idx);
                if let Some(master) = names.get(&master_idx) {
                    obj["master"] = serde_json::json!(master);
                }
            }

            if let Some(vlan) = entry.vlan() {
                obj["vlan"] = serde_json::json!(vlan);
            }

            if let Some(dst) = &entry.dst() {
                obj["dst"] = serde_json::json!(dst.to_string());
            }

            if let Some(vni) = entry.vni() {
                obj["vni"] = serde_json::json!(vni);
            }

            obj["state"] = serde_json::json!(if entry.is_permanent() {
                "permanent"
            } else {
                "dynamic"
            });

            let mut flags = Vec::new();
            if entry.is_self() {
                flags.push("self");
            }
            if entry.is_master() {
                flags.push("master");
            }
            if entry.is_extern_learn() {
                flags.push("extern_learn");
            }
            if !flags.is_empty() {
                obj["flags"] = serde_json::json!(flags);
            }

            obj
        })
        .collect();

    let output = if opts.pretty {
        serde_json::to_string_pretty(&json_entries).expect("JSON serialization")
    } else {
        serde_json::to_string(&json_entries).expect("JSON serialization")
    };
    println!("{}", output);
}

async fn add_fdb(conn: &Connection<Route>, args: FdbAddArgs, replace: bool) -> Result<()> {
    let mac = FdbEntryBuilder::parse_mac(&args.mac)
        .map_err(|e| Error::InvalidMessage(format!("invalid MAC address: {}", e)))?;

    let mut builder = FdbEntryBuilder::new(mac).dev(&args.dev);

    if let Some(ref master) = args.master {
        builder = builder.master(master);
    }

    if let Some(vlan) = args.vlan {
        builder = builder.vlan(vlan);
    }

    if let Some(dst) = args.dst {
        builder = builder.dst(dst);
    }

    if let Some(vni) = args.vni {
        builder = builder.vni(vni);
    }

    if args.permanent && args.dynamic {
        return Err(Error::InvalidMessage(
            "bridge fdb: --permanent and --dynamic are mutually exclusive".into(),
        ));
    }
    if args.permanent {
        builder = builder.permanent();
    }
    if args.dynamic {
        builder = builder.dynamic();
    }

    if args.self_entry {
        builder = builder.self_();
    }

    if replace {
        conn.replace_fdb(builder).await
    } else {
        conn.add_fdb(builder).await
    }
}

async fn del_fdb(conn: &Connection<Route>, args: FdbDelArgs) -> Result<()> {
    let mac = FdbEntryBuilder::parse_mac(&args.mac)
        .map_err(|e| Error::InvalidMessage(format!("invalid MAC address: {}", e)))?;

    conn.del_fdb(&args.dev, mac, args.vlan).await
}

async fn flush_fdb(conn: &Connection<Route>, bridge: &str) -> Result<()> {
    conn.flush_fdb(bridge).await
}
