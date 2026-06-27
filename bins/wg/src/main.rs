//! wg - WireGuard management utility
//!
//! Manages WireGuard interfaces and peers via Generic Netlink.

mod keys;
mod output;
mod set;
mod show;
mod watch;

use clap::{Parser, Subcommand};
use nlink::netlink::Result;

#[derive(Parser)]
#[command(name = "wg")]
#[command(about = "WireGuard management utility", long_about = None)]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Show WireGuard interfaces and peers
    Show(show::ShowArgs),

    /// Show interface configuration in wg-quick format
    Showconf {
        /// Interface name
        interface: String,
    },

    /// Set interface configuration
    Set(set::SetArgs),

    /// Generate a new private key
    Genkey,

    /// Derive public key from private key (reads from stdin)
    Pubkey,

    /// Generate a preshared key
    Genpsk,

    /// Watch interfaces for peer/handshake/endpoint changes
    Watch {
        /// Interface(s) to watch.
        interfaces: Vec<String>,
        /// Poll interval in seconds.
        #[arg(long, default_value_t = 1)]
        interval: u64,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        None => show::run_all().await,
        Some(Command::Show(args)) => show::run(args).await,
        Some(Command::Showconf { interface }) => show::run_conf(&interface).await,
        Some(Command::Set(args)) => set::run(args).await,
        Some(Command::Genkey) => keys::genkey(),
        Some(Command::Pubkey) => keys::pubkey(),
        Some(Command::Genpsk) => keys::genpsk(),
        Some(Command::Watch {
            interfaces,
            interval,
        }) => watch::run(interfaces, interval).await,
    }
}
