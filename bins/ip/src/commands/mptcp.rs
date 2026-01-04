//! `ip mptcp` command implementation.

use std::net::IpAddr;

use clap::{Args, Subcommand};
use nlink::netlink::genl::mptcp::{MptcpEndpoint, MptcpEndpointBuilder, MptcpLimits};
use nlink::netlink::{Connection, Error, Mptcp, Result};
use nlink::output::OutputFormat;

#[derive(Args)]
pub struct MptcpCmd {
    #[command(subcommand)]
    command: Option<MptcpCommand>,
}

#[derive(Subcommand)]
enum MptcpCommand {
    /// Manage MPTCP endpoints
    Endpoint {
        #[command(subcommand)]
        command: Option<EndpointCommand>,
    },
    /// Manage MPTCP limits
    Limits {
        #[command(subcommand)]
        command: Option<LimitsCommand>,
    },
}

#[derive(Subcommand)]
enum EndpointCommand {
    /// Show endpoints
    #[command(visible_alias = "list", visible_alias = "ls")]
    Show,
    /// Add an endpoint
    Add(EndpointAddArgs),
    /// Delete an endpoint
    #[command(visible_alias = "delete")]
    Del {
        /// Endpoint ID
        #[arg(long)]
        id: u8,
    },
    /// Flush all endpoints
    Flush,
}

#[derive(Args)]
struct EndpointAddArgs {
    /// IP address
    address: IpAddr,

    /// Endpoint ID (0-255, optional - kernel assigns if not set)
    #[arg(long)]
    id: Option<u8>,

    /// Network device
    #[arg(long)]
    dev: Option<String>,

    /// Port (optional)
    #[arg(long)]
    port: Option<u16>,

    /// Signal this address to peer
    #[arg(long)]
    signal: bool,

    /// Create subflows to this address
    #[arg(long)]
    subflow: bool,

    /// Use as backup path
    #[arg(long)]
    backup: bool,

    /// Enable fullmesh mode
    #[arg(long)]
    fullmesh: bool,
}

#[derive(Subcommand)]
enum LimitsCommand {
    /// Show current limits
    Show,
    /// Set limits
    Set {
        /// Maximum subflows per connection
        #[arg(long)]
        subflows: Option<u32>,

        /// Maximum ADD_ADDR accepted from peers
        #[arg(long)]
        add_addr_accepted: Option<u32>,
    },
}

impl MptcpCmd {
    pub async fn run(
        self,
        format: OutputFormat,
        opts: &nlink::output::OutputOptions,
    ) -> Result<()> {
        let conn = Connection::<Mptcp>::new_async().await?;

        match self.command {
            None | Some(MptcpCommand::Endpoint { command: None }) => {
                show_endpoints(&conn, format, opts).await
            }
            Some(MptcpCommand::Endpoint { command: Some(cmd) }) => match cmd {
                EndpointCommand::Show => show_endpoints(&conn, format, opts).await,
                EndpointCommand::Add(args) => add_endpoint(&conn, args).await,
                EndpointCommand::Del { id } => del_endpoint(&conn, id).await,
                EndpointCommand::Flush => flush_endpoints(&conn).await,
            },
            Some(MptcpCommand::Limits { command }) => match command {
                None | Some(LimitsCommand::Show) => show_limits(&conn, format, opts).await,
                Some(LimitsCommand::Set {
                    subflows,
                    add_addr_accepted,
                }) => set_limits(&conn, subflows, add_addr_accepted).await,
            },
        }
    }
}

async fn show_endpoints(
    conn: &Connection<Mptcp>,
    format: OutputFormat,
    opts: &nlink::output::OutputOptions,
) -> Result<()> {
    let endpoints = conn.get_endpoints().await?;

    match format {
        OutputFormat::Json => print_endpoints_json(&endpoints, opts),
        OutputFormat::Text => print_endpoints_text(&endpoints),
    }

    Ok(())
}

fn print_endpoints_text(endpoints: &[MptcpEndpoint]) {
    for ep in endpoints {
        let mut line = format!("{}: {}", ep.id, ep.address);

        if let Some(port) = ep.port {
            line.push_str(&format!(" port {}", port));
        }

        if let Some(ifindex) = ep.ifindex {
            if let Some(name) = get_ifname(ifindex) {
                line.push_str(&format!(" dev {}", name));
            } else {
                line.push_str(&format!(" ifindex {}", ifindex));
            }
        }

        let mut flags = Vec::new();
        if ep.flags.signal {
            flags.push("signal");
        }
        if ep.flags.subflow {
            flags.push("subflow");
        }
        if ep.flags.backup {
            flags.push("backup");
        }
        if ep.flags.fullmesh {
            flags.push("fullmesh");
        }

        if !flags.is_empty() {
            line.push_str(&format!(" flags {}", flags.join(",")));
        }

        println!("{}", line);
    }
}

fn print_endpoints_json(endpoints: &[MptcpEndpoint], opts: &nlink::output::OutputOptions) {
    let json_endpoints: Vec<serde_json::Value> = endpoints
        .iter()
        .map(|ep| {
            let mut obj = serde_json::json!({
                "id": ep.id,
                "address": ep.address.to_string(),
            });

            if let Some(port) = ep.port {
                obj["port"] = serde_json::json!(port);
            }

            if let Some(ifindex) = ep.ifindex {
                if let Some(name) = get_ifname(ifindex) {
                    obj["dev"] = serde_json::json!(name);
                }
                obj["ifindex"] = serde_json::json!(ifindex);
            }

            let mut flags = Vec::new();
            if ep.flags.signal {
                flags.push("signal");
            }
            if ep.flags.subflow {
                flags.push("subflow");
            }
            if ep.flags.backup {
                flags.push("backup");
            }
            if ep.flags.fullmesh {
                flags.push("fullmesh");
            }

            if !flags.is_empty() {
                obj["flags"] = serde_json::json!(flags);
            }

            obj
        })
        .collect();

    let output = if opts.pretty {
        serde_json::to_string_pretty(&json_endpoints).unwrap()
    } else {
        serde_json::to_string(&json_endpoints).unwrap()
    };
    println!("{}", output);
}

async fn add_endpoint(conn: &Connection<Mptcp>, args: EndpointAddArgs) -> Result<()> {
    let mut builder = MptcpEndpointBuilder::new(args.address);

    if let Some(id) = args.id {
        builder = builder.id(id);
    }
    if let Some(ref dev) = args.dev {
        builder = builder.dev(dev);
    }
    if let Some(port) = args.port {
        builder = builder.port(port);
    }
    if args.signal {
        builder = builder.signal();
    }
    if args.subflow {
        builder = builder.subflow();
    }
    if args.backup {
        builder = builder.backup();
    }
    if args.fullmesh {
        builder = builder.fullmesh();
    }

    conn.add_endpoint(builder).await
}

async fn del_endpoint(conn: &Connection<Mptcp>, id: u8) -> Result<()> {
    conn.del_endpoint(id).await
}

async fn flush_endpoints(conn: &Connection<Mptcp>) -> Result<()> {
    conn.flush_endpoints().await
}

async fn show_limits(
    conn: &Connection<Mptcp>,
    format: OutputFormat,
    opts: &nlink::output::OutputOptions,
) -> Result<()> {
    let limits = conn.get_limits().await?;

    match format {
        OutputFormat::Json => print_limits_json(&limits, opts),
        OutputFormat::Text => print_limits_text(&limits),
    }

    Ok(())
}

fn print_limits_text(limits: &MptcpLimits) {
    let subflows = limits.subflows.unwrap_or(0);
    let add_addr = limits.add_addr_accepted.unwrap_or(0);
    println!("subflows {} add_addr_accepted {}", subflows, add_addr);
}

fn print_limits_json(limits: &MptcpLimits, opts: &nlink::output::OutputOptions) {
    let obj = serde_json::json!({
        "subflows": limits.subflows.unwrap_or(0),
        "add_addr_accepted": limits.add_addr_accepted.unwrap_or(0),
    });

    let output = if opts.pretty {
        serde_json::to_string_pretty(&obj).unwrap()
    } else {
        serde_json::to_string(&obj).unwrap()
    };
    println!("{}", output);
}

async fn set_limits(
    conn: &Connection<Mptcp>,
    subflows: Option<u32>,
    add_addr_accepted: Option<u32>,
) -> Result<()> {
    if subflows.is_none() && add_addr_accepted.is_none() {
        return Err(Error::InvalidMessage(
            "at least one limit must be specified".into(),
        ));
    }

    let mut limits = MptcpLimits::new();
    if let Some(s) = subflows {
        limits = limits.subflows(s);
    }
    if let Some(a) = add_addr_accepted {
        limits = limits.add_addr_accepted(a);
    }

    conn.set_limits(limits).await
}

fn get_ifname(ifindex: u32) -> Option<String> {
    nlink::util::device::get_ifname(ifindex).ok()
}
