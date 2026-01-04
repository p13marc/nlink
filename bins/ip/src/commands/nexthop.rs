//! `ip nexthop` command implementation.

use std::net::IpAddr;

use clap::{Args, Subcommand};
use nlink::netlink::nexthop::{Nexthop, NexthopBuilder, NexthopGroupBuilder};
use nlink::netlink::{Connection, Error, Result, Route};
use nlink::output::OutputFormat;

#[derive(Args)]
pub struct NexthopCmd {
    #[command(subcommand)]
    command: Option<NexthopCommand>,
}

#[derive(Subcommand)]
enum NexthopCommand {
    /// Show nexthops
    #[command(visible_alias = "list", visible_alias = "ls")]
    Show {
        /// Show specific nexthop ID
        #[arg(long)]
        id: Option<u32>,
        /// Show only groups
        #[arg(long)]
        group: bool,
    },
    /// Add a nexthop
    Add(NexthopAddArgs),
    /// Replace a nexthop (add or update)
    Replace(NexthopAddArgs),
    /// Delete a nexthop
    Del {
        /// Nexthop ID
        #[arg(long)]
        id: u32,
    },
    /// Flush all nexthops
    Flush,
}

#[derive(Args)]
struct NexthopAddArgs {
    /// Nexthop ID
    #[arg(long)]
    id: u32,
    /// Gateway address
    #[arg(long)]
    via: Option<IpAddr>,
    /// Output device
    #[arg(long)]
    dev: Option<String>,
    /// Create blackhole
    #[arg(long)]
    blackhole: bool,
    /// On-link flag (gateway is directly reachable)
    #[arg(long)]
    onlink: bool,
    /// Group members (id,weight/id,weight/... or id/id/...)
    #[arg(long)]
    group: Option<String>,
    /// Group type (mpath, resilient)
    #[arg(long, name = "type")]
    group_type: Option<String>,
    /// Resilient group buckets
    #[arg(long)]
    buckets: Option<u16>,
    /// Resilient group idle timer (seconds)
    #[arg(long)]
    idle_timer: Option<u32>,
}

impl NexthopCmd {
    pub async fn run(
        self,
        conn: &Connection<Route>,
        format: OutputFormat,
        opts: &nlink::output::OutputOptions,
    ) -> Result<()> {
        match self.command {
            None
            | Some(NexthopCommand::Show {
                id: None,
                group: false,
            }) => show_nexthops(conn, format, opts, None, false).await,
            Some(NexthopCommand::Show { id, group }) => {
                show_nexthops(conn, format, opts, id, group).await
            }
            Some(NexthopCommand::Add(args)) => add_nexthop(conn, args, false).await,
            Some(NexthopCommand::Replace(args)) => add_nexthop(conn, args, true).await,
            Some(NexthopCommand::Del { id }) => del_nexthop(conn, id).await,
            Some(NexthopCommand::Flush) => flush_nexthops(conn).await,
        }
    }
}

async fn show_nexthops(
    conn: &Connection<Route>,
    format: OutputFormat,
    _opts: &nlink::output::OutputOptions,
    id: Option<u32>,
    groups_only: bool,
) -> Result<()> {
    let nexthops = if let Some(id) = id {
        match conn.get_nexthop(id).await? {
            Some(nh) => vec![nh],
            None => {
                eprintln!("Nexthop {} not found", id);
                return Ok(());
            }
        }
    } else if groups_only {
        conn.get_nexthop_groups().await?
    } else {
        conn.get_nexthops().await?
    };

    match format {
        OutputFormat::Json => {
            let json = serde_json::to_string_pretty(&nexthops_to_json(&nexthops))
                .map_err(|e| Error::InvalidMessage(e.to_string()))?;
            println!("{}", json);
        }
        OutputFormat::Text => {
            for nh in &nexthops {
                print_nexthop(nh);
            }
        }
    }

    Ok(())
}

fn print_nexthop(nh: &Nexthop) {
    print!("id {} ", nh.id);

    if let Some(ref group) = nh.group {
        // This is a group
        print!("group ");
        let members: Vec<String> = group
            .iter()
            .map(|m| {
                if m.weight > 1 {
                    format!("{},{}", m.id, m.weight)
                } else {
                    format!("{}", m.id)
                }
            })
            .collect();
        print!("{} ", members.join("/"));

        if let Some(group_type) = nh.group_type {
            match group_type {
                nlink::netlink::nexthop::NexthopGroupType::Multipath => {
                    print!("type mpath ");
                }
                nlink::netlink::nexthop::NexthopGroupType::Resilient => {
                    print!("type resilient ");
                    if let Some(ref res) = nh.resilient {
                        if res.buckets > 0 {
                            print!("buckets {} ", res.buckets);
                        }
                        if res.idle_timer > 0 {
                            print!("idle_timer {} ", res.idle_timer);
                        }
                        if res.unbalanced_timer > 0 {
                            print!("unbalanced_timer {} ", res.unbalanced_timer);
                        }
                    }
                }
            }
        }
    } else {
        // Individual nexthop
        if nh.blackhole {
            print!("blackhole ");
        } else {
            if let Some(gw) = nh.gateway {
                print!("via {} ", gw);
            }
            if let Some(ifindex) = nh.ifindex {
                // Try to resolve interface name
                if let Some(name) = get_ifname(ifindex) {
                    print!("dev {} ", name);
                } else {
                    print!("dev {} ", ifindex);
                }
            }
        }

        // Scope
        let scope = match nh.scope {
            0 => "global",
            200 => "site",
            253 => "link",
            254 => "host",
            255 => "nowhere",
            _ => "",
        };
        if !scope.is_empty() && scope != "global" {
            print!("scope {} ", scope);
        }
    }

    // Flags
    if nh.is_onlink() {
        print!("onlink ");
    }
    if nh.is_dead() {
        print!("dead ");
    }
    if nh.is_linkdown() {
        print!("linkdown ");
    }
    if nh.fdb {
        print!("fdb ");
    }

    // Protocol
    let proto = match nh.protocol {
        0 => "",
        2 => "proto kernel ",
        4 => "proto static ",
        _ => "",
    };
    print!("{}", proto);

    println!();
}

fn nexthops_to_json(nexthops: &[Nexthop]) -> Vec<serde_json::Value> {
    nexthops
        .iter()
        .map(|nh| {
            let mut obj = serde_json::json!({
                "id": nh.id,
            });

            if let Some(ref group) = nh.group {
                let members: Vec<serde_json::Value> = group
                    .iter()
                    .map(|m| {
                        serde_json::json!({
                            "id": m.id,
                            "weight": m.weight,
                        })
                    })
                    .collect();
                obj["group"] = serde_json::json!(members);
                if let Some(gt) = nh.group_type {
                    obj["type"] = match gt {
                        nlink::netlink::nexthop::NexthopGroupType::Multipath => "mpath".into(),
                        nlink::netlink::nexthop::NexthopGroupType::Resilient => "resilient".into(),
                    };
                }
                if let Some(ref res) = nh.resilient {
                    obj["buckets"] = res.buckets.into();
                    obj["idle_timer"] = res.idle_timer.into();
                    obj["unbalanced_timer"] = res.unbalanced_timer.into();
                }
            } else {
                if nh.blackhole {
                    obj["blackhole"] = true.into();
                }
                if let Some(gw) = nh.gateway {
                    obj["gateway"] = gw.to_string().into();
                }
                if let Some(ifindex) = nh.ifindex {
                    obj["dev"] = get_ifname(ifindex)
                        .unwrap_or_else(|| ifindex.to_string())
                        .into();
                }
                obj["scope"] = match nh.scope {
                    0 => "global",
                    200 => "site",
                    253 => "link",
                    254 => "host",
                    255 => "nowhere",
                    _ => "unknown",
                }
                .into();
            }

            let mut flags = Vec::new();
            if nh.is_onlink() {
                flags.push("onlink");
            }
            if nh.is_dead() {
                flags.push("dead");
            }
            if nh.is_linkdown() {
                flags.push("linkdown");
            }
            if nh.fdb {
                flags.push("fdb");
            }
            if !flags.is_empty() {
                obj["flags"] = flags.into();
            }

            obj["protocol"] = match nh.protocol {
                2 => "kernel",
                4 => "static",
                _ => "unspec",
            }
            .into();

            obj
        })
        .collect()
}

async fn add_nexthop(conn: &Connection<Route>, args: NexthopAddArgs, replace: bool) -> Result<()> {
    if let Some(ref group_str) = args.group {
        // Create a nexthop group
        let mut builder = NexthopGroupBuilder::new(args.id);

        // Parse group members: "1/2" or "1,2/2,1"
        for member_str in group_str.split('/') {
            let parts: Vec<&str> = member_str.split(',').collect();
            let nh_id: u32 = parts[0]
                .parse()
                .map_err(|_| Error::InvalidMessage(format!("invalid nexthop id: {}", parts[0])))?;
            let weight: u8 = if parts.len() > 1 {
                parts[1]
                    .parse()
                    .map_err(|_| Error::InvalidMessage(format!("invalid weight: {}", parts[1])))?
            } else {
                1
            };
            builder = builder.member(nh_id, weight);
        }

        // Set group type
        if let Some(ref gt) = args.group_type {
            match gt.as_str() {
                "resilient" | "res" => {
                    builder = builder.resilient();
                }
                "mpath" | "multipath" => {
                    builder = builder.multipath();
                }
                _ => {
                    return Err(Error::InvalidMessage(format!("unknown group type: {}", gt)));
                }
            }
        }

        // Set resilient parameters
        if let Some(buckets) = args.buckets {
            builder = builder.buckets(buckets);
        }
        if let Some(idle) = args.idle_timer {
            builder = builder.idle_timer(idle);
        }

        if replace {
            conn.replace_nexthop_group(builder).await?;
        } else {
            conn.add_nexthop_group(builder).await?;
        }
    } else {
        // Create an individual nexthop
        let mut builder = NexthopBuilder::new(args.id);

        if args.blackhole {
            builder = builder.blackhole();
        } else {
            if let Some(gw) = args.via {
                builder = builder.gateway(gw);
            }
            if let Some(ref dev) = args.dev {
                builder = builder.dev(dev);
            }
            if args.onlink {
                builder = builder.onlink();
            }
        }

        if replace {
            conn.replace_nexthop(builder).await?;
        } else {
            conn.add_nexthop(builder).await?;
        }
    }

    Ok(())
}

async fn del_nexthop(conn: &Connection<Route>, id: u32) -> Result<()> {
    conn.del_nexthop(id).await?;
    Ok(())
}

async fn flush_nexthops(conn: &Connection<Route>) -> Result<()> {
    // Get all nexthops and delete them
    // We need to delete groups first, then individual nexthops
    let nexthops = conn.get_nexthops().await?;

    // Separate groups from individual nexthops
    let (groups, individuals): (Vec<_>, Vec<_>) = nexthops.iter().partition(|nh| nh.is_group());

    // Delete groups first (they depend on individual nexthops)
    for nh in &groups {
        if let Err(e) = conn.del_nexthop(nh.id).await {
            eprintln!("Warning: failed to delete group {}: {}", nh.id, e);
        }
    }

    // Then delete individual nexthops
    for nh in &individuals {
        if let Err(e) = conn.del_nexthop(nh.id).await {
            eprintln!("Warning: failed to delete nexthop {}: {}", nh.id, e);
        }
    }

    Ok(())
}

/// Get interface name from index
fn get_ifname(ifindex: u32) -> Option<String> {
    let path = "/sys/class/net/";
    let entries = std::fs::read_dir(path).ok()?;
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        let idx_path = entry.path().join("ifindex");
        if let Ok(content) = std::fs::read_to_string(&idx_path) {
            if let Ok(idx) = content.trim().parse::<u32>() {
                if idx == ifindex {
                    return Some(name);
                }
            }
        }
    }
    None
}
