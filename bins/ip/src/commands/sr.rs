//! ip sr command implementation.
//!
//! This module implements Segment Routing (SRv6) management commands.

use std::net::Ipv6Addr;

use clap::{Args, Subcommand};
use nlink::{
    netlink::{Connection, Result, Route},
    output::{OutputFormat, OutputOptions},
};

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
        opts: &OutputOptions,
    ) -> Result<()> {
        match self.action {
            SrAction::Tunsrc { command } => match command {
                TunsrcCommand::Show => Self::tunsrc_show(format, opts.pretty),
                TunsrcCommand::Set { address } => Self::tunsrc_set(address).await,
            },
        }
    }

    fn tunsrc_show(format: OutputFormat, pretty: bool) -> Result<()> {
        // Read /proc/sys/net/ipv6/conf/all/seg6_src
        // This is the global SRv6 tunnel source address. A read error
        // (SRv6 unsupported) and an empty/`::` value both mean "not set".
        let path = "/proc/sys/net/ipv6/conf/all/seg6_src";
        let tunsrc: Option<String> = match std::fs::read_to_string(path) {
            Ok(content) => {
                let addr = content.trim();
                if addr.is_empty() || addr == "::" {
                    None
                } else {
                    Some(addr.to_string())
                }
            }
            Err(_) => None,
        };

        match format {
            OutputFormat::Json => {
                // Build via serde_json so `--pretty` is honored and the
                // address is correctly escaped (no hand-rolled JSON).
                let value = serde_json::json!({ "tunsrc": tunsrc });
                let rendered = if pretty {
                    serde_json::to_string_pretty(&value)
                } else {
                    serde_json::to_string(&value)
                }
                .map_err(|e| {
                    nlink::netlink::Error::InvalidMessage(format!(
                        "JSON serialization failed: {e}"
                    ))
                })?;
                println!("{rendered}");
            }
            OutputFormat::Text => match tunsrc {
                Some(addr) => println!("tunsrc addr {addr}"),
                None => println!("tunsrc addr (not set)"),
            },
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
