//! tc - Traffic control tool
//!
//! Manages queuing disciplines (qdiscs), classes, and filters.

use clap::{Parser, Subcommand};
use rip_netlink::{Connection, Protocol, Result};
use rip_output::{OutputFormat, OutputOptions};

mod commands;

use commands::class::ClassCmd;
use commands::filter::FilterCmd;
use commands::monitor::MonitorCmd;
use commands::qdisc::QdiscCmd;

#[derive(Parser)]
#[command(name = "tc")]
#[command(about = "Traffic control tool", long_about = None)]
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

    /// Batch mode (not yet implemented)
    #[arg(short = 'b', long, global = true)]
    batch: Option<String>,

    /// Use names instead of numeric handles
    #[arg(short = 'n', long = "names", global = true)]
    use_names: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Manage queuing disciplines
    #[command(visible_alias = "q")]
    Qdisc(QdiscCmd),

    /// Manage traffic classes
    #[command(visible_alias = "c")]
    Class(ClassCmd),

    /// Manage traffic filters
    #[command(visible_alias = "f")]
    Filter(FilterCmd),

    /// Monitor TC events in real-time
    #[command(visible_alias = "m")]
    Monitor(MonitorCmd),
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
        numeric: !cli.use_names,
        color: false,
    };

    // Create netlink connection
    let conn = Connection::new(Protocol::Route)?;

    match cli.command {
        Command::Qdisc(cmd) => cmd.run(&conn, format, &opts).await,
        Command::Class(cmd) => cmd.run(&conn, format, &opts).await,
        Command::Filter(cmd) => cmd.run(&conn, format, &opts).await,
        Command::Monitor(cmd) => cmd.run(format, &opts).await,
    }
}
