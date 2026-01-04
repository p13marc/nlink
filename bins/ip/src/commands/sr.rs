//! ip sr command implementation.
//!
//! This module implements Segment Routing (SRv6) management commands.

use clap::{Args, Subcommand};
use nlink::netlink::{Connection, Result, Route};
use nlink::output::{OutputFormat, OutputOptions};
use std::net::Ipv6Addr;

#[derive(Args)]
pub struct SrCmd {
    #[command(subcommand)]
    action: SrAction,
}

#[derive(Subcommand)]
enum SrAction {
    /// Manage tunnel source address.
    Tunsrc {
        #[command(subcommand)]
        command: TunsrcCommand,
    },
}

#[derive(Subcommand)]
enum TunsrcCommand {
    /// Show tunnel source address.
    Show,
    /// Set tunnel source address.
    Set {
        /// Source IPv6 address.
        address: Ipv6Addr,
    },
}

impl SrCmd {
    pub async fn run(
        self,
        _conn: &Connection<Route>,
        format: OutputFormat,
        _opts: &OutputOptions,
    ) -> Result<()> {
        match self.action {
            SrAction::Tunsrc { command } => match command {
                TunsrcCommand::Show => Self::tunsrc_show(format).await,
                TunsrcCommand::Set { address } => Self::tunsrc_set(address).await,
            },
        }
    }

    async fn tunsrc_show(format: OutputFormat) -> Result<()> {
        // Read /proc/sys/net/ipv6/conf/all/seg6_src
        // This is the global SRv6 tunnel source address
        let path = "/proc/sys/net/ipv6/conf/all/seg6_src";
        match std::fs::read_to_string(path) {
            Ok(content) => {
                let addr = content.trim();
                if addr.is_empty() || addr == "::" {
                    match format {
                        OutputFormat::Json => println!("{{\"tunsrc\": null}}"),
                        OutputFormat::Text => println!("tunsrc addr (not set)"),
                    }
                } else {
                    match format {
                        OutputFormat::Json => {
                            println!("{{\"tunsrc\": \"{}\"}}", addr);
                        }
                        OutputFormat::Text => {
                            println!("tunsrc addr {}", addr);
                        }
                    }
                }
            }
            Err(_) => {
                // SRv6 not supported or not available
                match format {
                    OutputFormat::Json => println!("{{\"tunsrc\": null}}"),
                    OutputFormat::Text => println!("tunsrc addr (not available)"),
                }
            }
        }
        Ok(())
    }

    async fn tunsrc_set(address: Ipv6Addr) -> Result<()> {
        // Write to /proc/sys/net/ipv6/conf/all/seg6_src
        // This requires root privileges
        let path = "/proc/sys/net/ipv6/conf/all/seg6_src";
        std::fs::write(path, format!("{}\n", address)).map_err(|e| {
            nlink::netlink::Error::InvalidMessage(format!(
                "failed to set tunsrc: {} (requires root)",
                e
            ))
        })?;
        Ok(())
    }
}
