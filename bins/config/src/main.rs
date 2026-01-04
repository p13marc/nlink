//! nlink-config - Declarative network configuration utility
//!
//! Captures and manages network configuration in YAML/JSON format.

mod capture;
mod example;

use clap::{Parser, Subcommand};
use nlink::netlink::Result;

#[derive(Parser)]
#[command(name = "nlink-config")]
#[command(about = "Declarative network configuration utility", long_about = None)]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Capture current network state
    Capture(capture::CaptureArgs),

    /// Generate example configuration
    Example(example::ExampleArgs),
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Capture(args) => capture::run(args).await,
        Command::Example(args) => example::run(args),
    }
}
