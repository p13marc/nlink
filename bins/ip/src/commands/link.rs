//! ip link command implementation.
//!
//! This module uses the strongly-typed LinkMessage API from rip-netlink.

use clap::{Args, Subcommand};
use rip_netlink::message::NlMsgType;
use rip_netlink::messages::LinkMessage;
use rip_netlink::types::link::{IfInfoMsg, IflaAttr, iff};
use rip_netlink::{Connection, Result, connection::ack_request};
use rip_output::{OutputFormat, OutputOptions};
use std::io::{self, Write};

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

        let mut stdout = io::stdout().lock();

        match format {
            OutputFormat::Text => {
                for link in &links {
                    print_link_text(&mut stdout, link, opts)?;
                }
            }
            OutputFormat::Json => {
                let json: Vec<_> = links.iter().map(link_to_json).collect();
                if opts.pretty {
                    serde_json::to_writer_pretty(&mut stdout, &json)?;
                } else {
                    serde_json::to_writer(&mut stdout, &json)?;
                }
                writeln!(stdout)?;
            }
        }

        Ok(())
    }

    async fn del(conn: &Connection, dev: &str) -> Result<()> {
        use rip_lib::ifname::name_to_index;

        let ifindex = name_to_index(dev).map_err(|e| {
            rip_netlink::Error::InvalidMessage(format!("interface not found: {}", e))
        })?;

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
        use rip_lib::ifname::name_to_index;

        let ifindex = name_to_index(dev).map_err(|e| {
            rip_netlink::Error::InvalidMessage(format!("interface not found: {}", e))
        })?;

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
            let master_idx = name_to_index(&master_name).map_err(|e| {
                rip_netlink::Error::InvalidMessage(format!("master device not found: {}", e))
            })?;
            builder.append_attr_u32(IflaAttr::Master as u16, master_idx);
        } else if nomaster {
            builder.append_attr_u32(IflaAttr::Master as u16, 0);
        }

        conn.request_ack(builder).await?;

        Ok(())
    }
}

/// Convert LinkMessage to JSON.
fn link_to_json(link: &LinkMessage) -> serde_json::Value {
    let mut obj = serde_json::json!({
        "ifindex": link.ifindex(),
        "ifname": link.name.as_deref().unwrap_or(""),
        "flags": rip_lib::names::format_link_flags(link.flags()),
        "mtu": link.mtu.unwrap_or(0),
        "qdisc": link.qdisc.as_deref().unwrap_or(""),
        "operstate": link.operstate.map(|s| s.name()).unwrap_or("UNKNOWN"),
        "link_type": link_type_name(link.header.ifi_type),
    });

    if let Some(ref addr) = link.mac_address() {
        obj["address"] = serde_json::json!(addr);
    }
    if let Some(master) = link.master {
        obj["master"] = serde_json::json!(master);
    }
    if let Some(ref info) = link.link_info
        && let Some(ref kind) = info.kind {
            obj["link_kind"] = serde_json::json!(kind);
        }
    if let Some(txqlen) = link.txqlen {
        obj["txqlen"] = serde_json::json!(txqlen);
    }
    if let Some(group) = link.group {
        obj["group"] = serde_json::json!(group_name(group));
    }

    obj
}

fn group_name(group: u32) -> String {
    if group == 0 {
        "default".to_string()
    } else {
        format!("{}", group)
    }
}

fn link_type_name(ifi_type: u16) -> &'static str {
    match ifi_type {
        1 => "ether",      // ARPHRD_ETHER
        772 => "loopback", // ARPHRD_LOOPBACK
        776 => "sit",      // ARPHRD_SIT
        778 => "gre",      // ARPHRD_IPGRE
        823 => "ip6gre",   // ARPHRD_IP6GRE
        65534 => "none",   // ARPHRD_NONE
        _ => "unknown",
    }
}

/// Print link in text format.
fn print_link_text<W: Write>(
    w: &mut W,
    link: &LinkMessage,
    _opts: &OutputOptions,
) -> io::Result<()> {
    let name = link.name.as_deref().unwrap_or("?");

    // Build flags string, adding NO-CARRIER if carrier is false
    let mut flags = rip_lib::names::format_link_flags(link.flags());
    if let Some(false) = link.carrier
        && !link.is_loopback() {
            flags = format!("NO-CARRIER,{}", flags);
        }

    let mtu = link.mtu.unwrap_or(0);
    let qdisc = link.qdisc.as_deref().unwrap_or("noqueue");
    let operstate = link.operstate.map(|s| s.name()).unwrap_or("UNKNOWN");

    // Line 1: index, name, flags, mtu, qdisc, state, group, qlen
    write!(
        w,
        "{}: {}: <{}> mtu {} qdisc {} state {}",
        link.ifindex(),
        name,
        flags,
        mtu,
        qdisc,
        operstate
    )?;

    if let Some(group) = link.group {
        write!(w, " group {}", group_name(group))?;
    }

    if let Some(qlen) = link.txqlen {
        write!(w, " qlen {}", qlen)?;
    }

    if let Some(master) = link.master
        && let Ok(master_name) = rip_lib::ifname::index_to_name(master) {
            write!(w, " master {}", master_name)?;
        }

    writeln!(w)?;

    // Line 2: link type, address
    write!(w, "    link/{}", link_type_name(link.header.ifi_type))?;
    if let Some(ref addr) = link.mac_address() {
        write!(w, " {}", addr)?;
    }
    if let Some(ref brd) = link.broadcast
        && brd.len() == 6 {
            write!(
                w,
                " brd {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                brd[0], brd[1], brd[2], brd[3], brd[4], brd[5]
            )?;
        }
    // Show permanent address if different from current
    if let Some(ref perm) = link.perm_address {
        let perm_mac = if perm.len() == 6 {
            Some(format!(
                "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                perm[0], perm[1], perm[2], perm[3], perm[4], perm[5]
            ))
        } else {
            None
        };
        if perm_mac.as_ref() != link.mac_address().as_ref()
            && let Some(ref perm_str) = perm_mac {
                write!(w, " permaddr {}", perm_str)?;
            }
    }
    writeln!(w)?;

    // Show link kind if present
    if let Some(ref info) = link.link_info
        && let Some(ref kind) = info.kind
            && !kind.is_empty() {
                // This would be shown in more detailed output
            }

    Ok(())
}
