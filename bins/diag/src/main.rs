//! nlink-diag - Network diagnostics utility
//!
//! Provides network diagnostics and issue detection.

mod check;
mod interface;
mod scan;
mod watch;

use clap::{Parser, Subcommand};
use nlink::netlink::Result;

#[derive(Parser)]
#[command(name = "nlink-diag")]
#[command(about = "Network diagnostics utility", long_about = None)]
#[command(version)]
struct Cli {
    /// Output JSON
    #[arg(short, long, global = true)]
    json: bool,

    /// Verbose output
    #[arg(short, long, global = true)]
    verbose: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Scan all interfaces for issues
    Scan(scan::ScanArgs),

    /// Diagnose a specific interface
    Interface(interface::InterfaceArgs),

    /// Check connectivity to a destination
    Check(check::CheckArgs),

    /// Watch for network issues in real-time
    Watch(watch::WatchArgs),
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Scan(args) => scan::run(args, cli.json, cli.verbose).await,
        Command::Interface(args) => interface::run(args, cli.json).await,
        Command::Check(args) => check::run(args, cli.json).await,
        Command::Watch(args) => watch::run(args, cli.json).await,
    }
}
