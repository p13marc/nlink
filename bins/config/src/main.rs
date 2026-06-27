//! nlink-config - Declarative network configuration utility
//!
//! Captures and manages network configuration in YAML/JSON format.

mod capture;
mod example;
mod schema;

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};
use nlink::netlink::{Connection, Result, Route, config::ApplyOptions};

use crate::schema::ConfigFile;

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

    /// Show what `apply` would change, without touching the kernel
    Diff(FileArgs),

    /// Reconcile the kernel to match a configuration file
    Apply(ApplyArgs),
}

#[derive(Args)]
struct FileArgs {
    /// Path to a YAML or JSON configuration file
    file: PathBuf,
}

#[derive(Args)]
struct ApplyArgs {
    /// Path to a YAML or JSON configuration file
    file: PathBuf,

    /// Compute and print the changes without applying them
    #[arg(long)]
    dry_run: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Capture(args) => capture::run(args).await,
        Command::Example(args) => example::run(args),
        Command::Diff(args) => diff_cmd(args).await,
        Command::Apply(args) => apply_cmd(args).await,
    }
}

/// Load the file, translate it to a library `NetworkConfig`, and emit
/// any translation warnings on stderr (never silently dropped).
fn load_config(file: &std::path::Path) -> Result<nlink::netlink::config::NetworkConfig> {
    let file = ConfigFile::load(file)?;
    let (cfg, warnings) = file.to_network_config()?;
    for w in &warnings {
        eprintln!("warning: {w}");
    }
    Ok(cfg)
}

async fn diff_cmd(args: FileArgs) -> Result<()> {
    let cfg = load_config(&args.file)?;
    let conn = Connection::<Route>::new()?;
    let diff = cfg.diff(&conn).await?;
    if diff.is_empty() {
        println!("No changes needed; the system already matches the configuration.");
    } else {
        print!("{diff}");
    }
    Ok(())
}

async fn apply_cmd(args: ApplyArgs) -> Result<()> {
    let cfg = load_config(&args.file)?;
    let conn = Connection::<Route>::new()?;

    let result = cfg
        .apply_with_options(&conn, ApplyOptions::default().with_dry_run(args.dry_run))
        .await?;

    if args.dry_run {
        println!("Dry run — would make {} change(s):", result.changes_made);
    } else {
        println!("Applied {} change(s):", result.changes_made);
    }
    println!("{}", result.summary_text());

    if !result.is_success() {
        for e in &result.errors {
            eprintln!("error: {e}");
        }
    }
    Ok(())
}
