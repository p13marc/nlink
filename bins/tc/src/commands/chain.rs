//! `tc chain` command implementation.

use clap::{Args, Subcommand};
use nlink::netlink::{Connection, Result, Route};
use nlink::output::{OutputFormat, OutputOptions};

#[derive(Args)]
pub struct ChainCmd {
    #[command(subcommand)]
    command: Option<ChainCommand>,
}

#[derive(Subcommand)]
enum ChainCommand {
    /// Show filter chains
    #[command(visible_alias = "list", visible_alias = "ls")]
    Show(ChainShowArgs),
    /// Add a filter chain
    Add(ChainAddArgs),
    /// Delete a filter chain
    #[command(visible_alias = "delete")]
    Del(ChainDelArgs),
}

#[derive(Args)]
struct ChainShowArgs {
    /// Network device
    dev: String,

    /// Parent qdisc (root, ingress, or handle like 1:)
    #[arg(long, default_value = "root")]
    parent: String,
}

#[derive(Args)]
struct ChainAddArgs {
    /// Network device
    dev: String,

    /// Parent qdisc (root, ingress, or handle like 1:)
    #[arg(long, default_value = "root")]
    parent: String,

    /// Chain index
    #[arg(long)]
    chain: u32,
}

#[derive(Args)]
struct ChainDelArgs {
    /// Network device
    dev: String,

    /// Parent qdisc (root, ingress, or handle like 1:)
    #[arg(long, default_value = "root")]
    parent: String,

    /// Chain index
    #[arg(long)]
    chain: u32,
}

impl ChainCmd {
    pub async fn run(
        self,
        conn: &Connection<Route>,
        format: OutputFormat,
        opts: &OutputOptions,
    ) -> Result<()> {
        match self.command {
            None => {
                eprintln!("Usage: tc chain <show|add|del> ...");
                Ok(())
            }
            Some(ChainCommand::Show(args)) => show_chains(conn, args, format, opts).await,
            Some(ChainCommand::Add(args)) => add_chain(conn, args).await,
            Some(ChainCommand::Del(args)) => del_chain(conn, args).await,
        }
    }
}

async fn show_chains(
    conn: &Connection<Route>,
    args: ChainShowArgs,
    format: OutputFormat,
    opts: &OutputOptions,
) -> Result<()> {
    let chains = conn.get_tc_chains(&args.dev, &args.parent).await?;

    match format {
        OutputFormat::Json => print_chains_json(&args.dev, &args.parent, &chains, opts),
        OutputFormat::Text => print_chains_text(&chains),
    }

    Ok(())
}

fn print_chains_text(chains: &[u32]) {
    for chain in chains {
        println!("chain {}", chain);
    }
}

fn print_chains_json(dev: &str, parent: &str, chains: &[u32], opts: &OutputOptions) {
    let obj = serde_json::json!({
        "dev": dev,
        "parent": parent,
        "chains": chains,
    });

    let output = if opts.pretty {
        serde_json::to_string_pretty(&obj).unwrap()
    } else {
        serde_json::to_string(&obj).unwrap()
    };
    println!("{}", output);
}

async fn add_chain(conn: &Connection<Route>, args: ChainAddArgs) -> Result<()> {
    conn.add_tc_chain(&args.dev, &args.parent, args.chain).await
}

async fn del_chain(conn: &Connection<Route>, args: ChainDelArgs) -> Result<()> {
    conn.del_tc_chain(&args.dev, &args.parent, args.chain).await
}
