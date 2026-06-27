//! `bridge mdb` command implementation.

use clap::{Args, Subcommand};
use nlink::{
    netlink::{
        Connection, Result, Route,
        mdb::{MdbEntry, MdbEntryBuilder, MdbGroup},
    },
    output::{OutputFormat, OutputOptions},
};

#[derive(Args)]
pub struct MdbCmd {
    #[command(subcommand)]
    command: Option<MdbCommand>,
}

#[derive(Subcommand)]
enum MdbCommand {
    /// Show MDB entries
    #[command(visible_alias = "list", visible_alias = "ls")]
    Show {
        /// Bridge device (shows all bridges if omitted)
        dev: Option<String>,
    },
    /// Add a static MDB group on a port
    Add(MdbAddArgs),
    /// Delete an MDB group from a port
    #[command(visible_alias = "delete")]
    Del(MdbAddArgs),
}

#[derive(Args)]
struct MdbAddArgs {
    /// Bridge device
    #[arg(long)]
    dev: String,

    /// Member port device
    #[arg(long)]
    port: String,

    /// Multicast group (IPv4/IPv6 address or MAC)
    #[arg(long)]
    grp: MdbGroup,

    /// VLAN ID
    #[arg(long)]
    vid: Option<u16>,

    /// Permanent (static) entry
    #[arg(long)]
    permanent: bool,
}

impl MdbCmd {
    pub async fn run(
        self,
        conn: &Connection<Route>,
        format: OutputFormat,
        opts: &OutputOptions,
    ) -> Result<()> {
        match self.command {
            None => show_mdb(conn, None, format, opts).await,
            Some(MdbCommand::Show { dev }) => show_mdb(conn, dev, format, opts).await,
            Some(MdbCommand::Add(args)) => modify_mdb(conn, args, false).await,
            Some(MdbCommand::Del(args)) => modify_mdb(conn, args, true).await,
        }
    }
}

async fn show_mdb(
    conn: &Connection<Route>,
    dev: Option<String>,
    format: OutputFormat,
    opts: &OutputOptions,
) -> Result<()> {
    let entries = if let Some(ref name) = dev {
        conn.get_mdb(name.as_str()).await?
    } else {
        // No device: aggregate across every bridge in the namespace.
        let mut all = Vec::new();
        for link in conn.get_links().await? {
            if link.link_info().and_then(|i| i.kind()) == Some("bridge") {
                all.extend(conn.get_mdb_by_index(link.ifindex()).await?);
            }
        }
        all
    };

    let names = conn.get_interface_names().await?;

    match format {
        OutputFormat::Json => print_mdb_json(&entries, &names, opts),
        OutputFormat::Text => print_mdb_text(&entries, &names),
    }

    Ok(())
}

fn print_mdb_text(entries: &[MdbEntry], names: &std::collections::HashMap<u32, String>) {
    for e in entries {
        let dev = names.get(&e.bridge_ifindex).map(|s| s.as_str()).unwrap_or("?");
        let port = names.get(&e.port_ifindex).map(|s| s.as_str()).unwrap_or("?");
        let mut line = format!("dev {dev} port {port} grp {}", e.group);
        if e.vid != 0 {
            line.push_str(&format!(" vid {}", e.vid));
        }
        line.push_str(if e.permanent { " permanent" } else { " temp" });
        if e.is_offloaded() {
            line.push_str(" offload");
        }
        println!("{line}");
    }
}

fn print_mdb_json(
    entries: &[MdbEntry],
    names: &std::collections::HashMap<u32, String>,
    opts: &OutputOptions,
) {
    let json: Vec<serde_json::Value> = entries
        .iter()
        .map(|e| {
            let mut obj = serde_json::json!({
                "bridge_ifindex": e.bridge_ifindex,
                "port_ifindex": e.port_ifindex,
                "grp": e.group.to_string(),
                "state": if e.permanent { "permanent" } else { "temp" },
            });
            if let Some(dev) = names.get(&e.bridge_ifindex) {
                obj["dev"] = serde_json::json!(dev);
            }
            if let Some(port) = names.get(&e.port_ifindex) {
                obj["port"] = serde_json::json!(port);
            }
            if e.vid != 0 {
                obj["vid"] = serde_json::json!(e.vid);
            }
            let mut flags = Vec::new();
            if e.is_offloaded() {
                flags.push("offload");
            }
            if e.is_fast_leave() {
                flags.push("fast_leave");
            }
            if e.is_blocked() {
                flags.push("blocked");
            }
            if !flags.is_empty() {
                obj["flags"] = serde_json::json!(flags);
            }
            obj
        })
        .collect();

    let out = if opts.pretty {
        serde_json::to_string_pretty(&json).expect("JSON serialization")
    } else {
        serde_json::to_string(&json).expect("JSON serialization")
    };
    println!("{out}");
}

async fn modify_mdb(conn: &Connection<Route>, args: MdbAddArgs, delete: bool) -> Result<()> {
    let mut builder = MdbEntryBuilder::new(args.dev.as_str(), args.port.as_str(), args.grp);
    if let Some(vid) = args.vid {
        builder = builder.vid(vid);
    }
    if args.permanent {
        builder = builder.permanent();
    }
    if delete {
        conn.del_mdb(builder).await
    } else {
        conn.add_mdb(builder).await
    }
}
