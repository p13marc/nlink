//! ip link command implementation.
//!
//! This module uses the strongly-typed LinkMessage API from rip-netlink.

use clap::{Args, Subcommand};
use rip_netlink::message::NlMsgType;
use rip_netlink::messages::LinkMessage;
use rip_netlink::types::link::{IfInfoMsg, IflaAttr, iff};
use rip_netlink::{Connection, Result, connection::ack_request};
use rip_output::{OutputFormat, OutputOptions, print_all};

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
    },
}

impl LinkCmd {
    pub async fn run(
        self,
        conn: &Connection,
        format: OutputFormat,
        opts: &OutputOptions,
    ) -> Result<()> {
        match self.action.unwrap_or(LinkAction::Show { dev: None }) {
            LinkAction::Show { dev } => Self::show(conn, dev.as_deref(), format, opts).await,
            LinkAction::Add { link_type } => add_link(conn, link_type).await,
            LinkAction::Del { dev } => Self::del(conn, &dev).await,
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
            } => {
                Self::set(
                    conn, &dev, up, down, mtu, name, txqlen, address, master, nomaster,
                )
                .await
            }
        }
    }

    async fn show(
        conn: &Connection,
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
                    link.name.as_deref() == Some(filter_dev)
                } else {
                    true
                }
            })
            .collect();

        print_all(&links, format, opts)?;

        Ok(())
    }

    async fn del(conn: &Connection, dev: &str) -> Result<()> {
        let ifindex = rip_lib::get_ifindex(dev).map_err(rip_netlink::Error::InvalidMessage)? as u32;

        let ifinfo = IfInfoMsg::new().with_index(ifindex as i32);

        let mut builder = ack_request(NlMsgType::RTM_DELLINK);
        builder.append(&ifinfo);

        conn.request_ack(builder).await?;

        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    async fn set(
        conn: &Connection,
        dev: &str,
        up: bool,
        down: bool,
        mtu: Option<u32>,
        name: Option<String>,
        txqlen: Option<u32>,
        address: Option<String>,
        master: Option<String>,
        nomaster: bool,
    ) -> Result<()> {
        let ifindex = rip_lib::get_ifindex(dev).map_err(rip_netlink::Error::InvalidMessage)? as u32;

        let mut ifinfo = IfInfoMsg::new().with_index(ifindex as i32);

        // Set flags
        if up {
            ifinfo.ifi_flags = iff::UP;
            ifinfo.ifi_change = iff::UP;
        } else if down {
            ifinfo.ifi_flags = 0;
            ifinfo.ifi_change = iff::UP;
        }

        let mut builder = ack_request(NlMsgType::RTM_SETLINK);
        builder.append(&ifinfo);

        // Add MTU if specified
        if let Some(mtu_val) = mtu {
            builder.append_attr_u32(IflaAttr::Mtu as u16, mtu_val);
        }

        // Add new name if specified
        if let Some(new_name) = name {
            builder.append_attr_str(IflaAttr::Ifname as u16, &new_name);
        }

        // Add TX queue length if specified
        if let Some(qlen) = txqlen {
            builder.append_attr_u32(IflaAttr::TxqLen as u16, qlen);
        }

        // Add MAC address if specified
        if let Some(addr_str) = address {
            let mac = rip_lib::addr::parse_mac(&addr_str).map_err(|e| {
                rip_netlink::Error::InvalidMessage(format!("invalid MAC address: {}", e))
            })?;
            builder.append_attr(IflaAttr::Address as u16, &mac);
        }

        // Set or clear master
        if let Some(master_name) = master {
            let master_idx = rip_lib::get_ifindex(&master_name)
                .map_err(rip_netlink::Error::InvalidMessage)? as u32;
            builder.append_attr_u32(IflaAttr::Master as u16, master_idx);
        } else if nomaster {
            builder.append_attr_u32(IflaAttr::Master as u16, 0);
        }

        conn.request_ack(builder).await?;

        Ok(())
    }
}
