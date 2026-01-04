//! bridge - Bridge management utility
//!
//! Manages bridge forwarding database (FDB), VLANs, and ports.

mod commands;

use clap::{Parser, Subcommand};
use nlink::netlink::{Connection, Result, Route};
use nlink::output::{OutputFormat, OutputOptions};

use commands::fdb::FdbCmd;
use commands::vlan::VlanCmd;

#[derive(Parser)]
#[command(name = "bridge")]
#[command(about = "Bridge management utility", long_about = None)]
#[command(version)]
struct Cli {
    /// Output JSON
    #[arg(short = 'j', long, global = true)]
    json: bool,

    /// Pretty print JSON
    #[arg(short = 'p', long, global = true)]
    pretty: bool,

    /// Show statistics
    #[arg(short = 's', long, global = true)]
    stats: bool,

    /// Show details
    #[arg(short = 'd', long, global = true)]
    details: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Manage forwarding database entries
    Fdb(FdbCmd),

    /// Manage VLAN filtering
    Vlan(VlanCmd),
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    let format = if cli.json {
        OutputFormat::Json
    } else {
        OutputFormat::Text
    };

    let opts = OutputOptions {
        stats: cli.stats,
        details: cli.details,
        pretty: cli.pretty,
        numeric: false,
        color: atty::is(atty::Stream::Stdout),
    };

    // Create netlink connection
    let conn = Connection::<Route>::new()?;

    match cli.command {
        Command::Fdb(cmd) => cmd.run(&conn, format, &opts).await,
        Command::Vlan(cmd) => cmd.run(&conn, format, &opts).await,
    }
}
