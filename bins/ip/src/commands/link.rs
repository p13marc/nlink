//! ip link command implementation.
//!
//! This module uses the strongly-typed LinkMessage API from rip-netlink.

use clap::{Args, Subcommand};
use nlink::{
    netlink::{Connection, Result, Route, message::NlMsgType, messages::LinkMessage},
    output::{OutputFormat, OutputOptions, print_all},
};

use super::link_add::{LinkAddType, add_link};

#[derive(Args)]
pub struct LinkCmd {
    #[command(subcommand)]
    action: Option<LinkAction>,
}

#[derive(Subcommand)]
enum LinkAction {
    /// Show link information.
    Show {
        /// Interface name or index.
        dev: Option<String>,
    },

    /// Add a virtual link.
    Add {
        #[command(subcommand)]
        link_type: LinkAddType,
    },

    /// Delete a link.
    Del {
        /// Interface name.
        dev: String,
    },

    /// Set link attributes.
    Set {
        /// Interface name.
        dev: String,

        /// Bring interface up.
        #[arg(long)]
        up: bool,

        /// Bring interface down.
        #[arg(long)]
        down: bool,

        /// Set MTU.
        #[arg(long)]
        mtu: Option<u32>,

        /// Set interface name.
        #[arg(long)]
        name: Option<String>,

        /// Set TX queue length.
        #[arg(long)]
        txqlen: Option<u32>,

        /// Set MAC address.
        #[arg(long)]
        address: Option<String>,

        /// Set master device.
        #[arg(long)]
        master: Option<String>,

        /// Remove from master device.
        #[arg(long)]
        nomaster: bool,

        /// Move the device into a network namespace (a netns name under
        /// /var/run/netns, or a numeric PID whose netns to join).
        #[arg(long)]
        netns: Option<String>,
    },
}

impl LinkCmd {
    pub async fn run(
        self,
        conn: &Connection<Route>,
        format: OutputFormat,
        opts: &OutputOptions,
    ) -> Result<()> {
        match self.action.unwrap_or(LinkAction::Show { dev: None }) {
            LinkAction::Show { dev } => Self::show(conn, dev.as_deref(), format, opts).await,
            LinkAction::Add { link_type } => add_link(conn, link_type).await,
            LinkAction::Del { dev } => conn.del_link(&dev).await,
            LinkAction::Set {
                dev,
                up,
                down,
                mtu,
                name,
                txqlen,
                address,
                master,
                nomaster,
                netns,
            } => {
                Self::set(
                    conn, &dev, up, down, mtu, name, txqlen, address, master, nomaster, netns,
                )
                .await
            }
        }
    }

    async fn show(
        conn: &Connection<Route>,
        dev: Option<&str>,
        format: OutputFormat,
        opts: &OutputOptions,
    ) -> Result<()> {
        // Use the strongly-typed API to get all links
        let all_links: Vec<LinkMessage> = conn.dump_typed(NlMsgType::RTM_GETLINK).await?;

        // Filter by device name if specified
        let links: Vec<_> = all_links
            .into_iter()
            .filter(|link| {
                if let Some(filter_dev) = dev {
                    link.name() == Some(filter_dev)
                } else {
                    true
                }
            })
            .collect();

        print_all(&links, format, opts)?;

        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    async fn set(
        conn: &Connection<Route>,
        dev: &str,
        up: bool,
        down: bool,
        mtu: Option<u32>,
        name: Option<String>,
        txqlen: Option<u32>,
        address: Option<String>,
        master: Option<String>,
        nomaster: bool,
        netns: Option<String>,
    ) -> Result<()> {
        // Set up/down state
        if up {
            conn.set_link_up(dev).await?;
        } else if down {
            conn.set_link_down(dev).await?;
        }

        // Set MTU if specified
        if let Some(mtu_val) = mtu {
            conn.set_link_mtu(dev, mtu_val).await?;
        }

        // Set new name if specified
        if let Some(new_name) = name {
            conn.set_link_name(dev, &new_name).await?;
        }

        // Set TX queue length if specified
        if let Some(qlen) = txqlen {
            conn.set_link_txqlen(dev, qlen).await?;
        }

        // Set MAC address if specified
        if let Some(addr_str) = address {
            let mac = nlink::util::addr::parse_mac(&addr_str).map_err(|e| {
                nlink::netlink::Error::InvalidMessage(format!("invalid MAC address: {}", e))
            })?;
            conn.set_link_address(dev, mac).await?;
        }

        // Set or clear master
        if let Some(master_name) = master {
            conn.set_link_master(dev, &master_name).await?;
        } else if nomaster {
            conn.set_link_nomaster(dev).await?;
        }

        // Move the device into a network namespace. Resolve the ifindex once
        // (namespace-safe, per CLAUDE.md "prefer _by_index") then use the
        // by-index setters. A purely-numeric argument is treated as a target
        // PID; anything else as a named netns under /var/run/netns — mirroring
        // iproute2's `ip link set DEV netns { PID | NAME }`.
        if let Some(ns) = netns {
            let ifindex = conn
                .get_link_by_name(dev)
                .await?
                .ok_or_else(|| {
                    nlink::netlink::Error::InvalidMessage(format!("device `{dev}` not found"))
                })?
                .ifindex();
            if let Ok(pid) = ns.parse::<u32>() {
                conn.set_link_netns_pid_by_index(ifindex, pid).await?;
            } else {
                conn.set_link_netns_by_index(ifindex, &ns).await?;
            }
        }

        Ok(())
    }
}
