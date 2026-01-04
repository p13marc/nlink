//! ip command - network interface and routing configuration.

mod commands;

use clap::{Parser, Subcommand};
use nlink::netlink::{Connection, Route};
use nlink::output::OutputFormat;

#[derive(Parser)]
#[command(name = "ip", version, about = "Network configuration tool")]
struct Cli {
    /// Use IPv4 only.
    #[arg(short = '4')]
    ipv4: bool,

    /// Use IPv6 only.
    #[arg(short = '6')]
    ipv6: bool,

    /// Output JSON.
    #[arg(short = 'j', long)]
    json: bool,

    /// Pretty print JSON.
    #[arg(short = 'p', long)]
    pretty: bool,

    /// Show statistics.
    #[arg(short = 's', long)]
    stats: bool,

    /// Show details.
    #[arg(short = 'd', long)]
    details: bool,

    /// Don't resolve names.
    #[arg(short = 'n', long)]
    numeric: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Manage network interfaces.
    #[command(visible_alias = "l")]
    Link(commands::link::LinkCmd),

    /// Manage IP addresses.
    #[command(visible_alias = "a", visible_alias = "addr")]
    Address(commands::address::AddressCmd),

    /// Manage routing table.
    #[command(visible_alias = "r")]
    Route(commands::route::RouteCmd),

    /// Manage ARP/NDP cache.
    #[command(visible_alias = "n", visible_alias = "neigh")]
    Neighbor(commands::neighbor::NeighborCmd),

    /// Manage routing policy rules.
    #[command(visible_alias = "ru")]
    Rule(commands::rule::RuleCmd),

    /// Manage nexthop objects.
    #[command(visible_alias = "nh")]
    Nexthop(commands::nexthop::NexthopCmd),

    /// Manage network namespaces.
    #[command(visible_alias = "ns")]
    Netns(commands::netns::NetnsCmd),

    /// Monitor netlink events.
    #[command(visible_alias = "m", visible_alias = "mon")]
    Monitor(commands::monitor::MonitorCmd),

    /// Manage IP tunnels (GRE, IPIP, SIT, VTI).
    #[command(visible_alias = "t", visible_alias = "tun")]
    Tunnel(commands::tunnel::TunnelCmd),

    /// Show multicast addresses.
    #[command(visible_alias = "maddr")]
    Maddress(commands::maddress::MaddressCmd),

    /// Manage VRF (Virtual Routing and Forwarding) devices.
    Vrf(commands::vrf::VrfCmd),

    /// Manage XFRM (IPSec) state and policy.
    Xfrm(commands::xfrm::XfrmCmd),

    /// Manage MPTCP (Multipath TCP) endpoints and limits.
    Mptcp(commands::mptcp::MptcpCmd),

    /// Manage Segment Routing (SRv6).
    Sr(commands::sr::SrCmd),

    /// Show MACsec device information.
    Macsec(commands::macsec::MacsecCmd),
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::WARN.into()),
        )
        .init();

    let cli = Cli::parse();

    // Determine output format
    let format = if cli.json {
        OutputFormat::Json
    } else {
        OutputFormat::Text
    };

    let opts = nlink::output::OutputOptions {
        stats: cli.stats,
        details: cli.details,
        color: atty::is(atty::Stream::Stdout),
        numeric: cli.numeric,
        pretty: cli.pretty,
    };

    // Determine address family filter
    let family = match (cli.ipv4, cli.ipv6) {
        (true, false) => Some(2),  // AF_INET
        (false, true) => Some(10), // AF_INET6
        _ => None,
    };

    // Create netlink connection
    let conn = Connection::<Route>::new()?;

    // Execute command
    let result = match cli.command {
        Command::Link(cmd) => cmd.run(&conn, format, &opts).await,
        Command::Address(cmd) => cmd.run(&conn, format, &opts, family).await,
        Command::Route(cmd) => cmd.run(&conn, format, &opts, family).await,
        Command::Neighbor(cmd) => cmd.run(&conn, format, &opts, family).await,
        Command::Rule(cmd) => cmd.run(&conn, format, &opts, family).await,
        Command::Nexthop(cmd) => cmd.run(&conn, format, &opts).await,
        Command::Netns(cmd) => cmd.run(format, &opts).await,
        Command::Monitor(cmd) => cmd.run(format, &opts).await,
        Command::Tunnel(cmd) => cmd.run(&conn, format, &opts).await,
        Command::Maddress(cmd) => cmd.run(format, &opts, family).await,
        Command::Vrf(cmd) => cmd.run(&conn, format, &opts).await,
        Command::Xfrm(cmd) => cmd.run(format, &opts).await,
        Command::Mptcp(cmd) => cmd.run(format, &opts).await,
        Command::Sr(cmd) => cmd.run(&conn, format, &opts).await,
        Command::Macsec(cmd) => cmd.run(&conn, format, &opts).await,
    };

    if let Err(e) = result {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }

    Ok(())
}
