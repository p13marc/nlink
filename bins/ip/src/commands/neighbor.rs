//! ip neighbor command implementation.
//!
//! This module uses the strongly-typed NeighborMessage API from rip-netlink.

use clap::{Args, Subcommand};
use rip_netlink::message::{NLMSG_HDRLEN, NlMsgType};
use rip_netlink::messages::NeighborMessage;
use rip_netlink::parse::FromNetlink;
use rip_netlink::types::neigh::{NdMsg, NdaAttr, nud, nud_state_name};
use rip_netlink::{Connection, Result, connection::dump_request};
use rip_output::{OutputFormat, OutputOptions, print_items};
use std::io::{self, Write};
use std::net::IpAddr;

#[derive(Args)]
pub struct NeighborCmd {
    #[command(subcommand)]
    action: Option<NeighborAction>,
}

#[derive(Subcommand)]
enum NeighborAction {
    /// Show neighbor entries.
    Show {
        /// Interface name.
        dev: Option<String>,
    },

    /// Add a neighbor entry.
    Add {
        /// IP address.
        address: String,

        /// Link-layer address (MAC).
        #[arg(long)]
        lladdr: String,

        /// Device name.
        #[arg(long, short)]
        dev: String,

        /// Create permanent entry.
        #[arg(long)]
        permanent: bool,

        /// NUD state (reachable, stale, delay, probe, failed, noarp).
        #[arg(long)]
        state: Option<String>,
    },

    /// Replace or add a neighbor entry.
    Replace {
        /// IP address.
        address: String,

        /// Link-layer address (MAC).
        #[arg(long)]
        lladdr: String,

        /// Device name.
        #[arg(long, short)]
        dev: String,

        /// Create permanent entry.
        #[arg(long)]
        permanent: bool,
    },

    /// Delete a neighbor entry.
    Del {
        /// IP address.
        address: String,

        /// Device name.
        #[arg(long, short)]
        dev: String,
    },

    /// Flush neighbor entries.
    Flush {
        /// Device name.
        dev: Option<String>,
    },
}

impl NeighborCmd {
    pub async fn run(
        self,
        conn: &Connection,
        format: OutputFormat,
        opts: &OutputOptions,
        family: Option<u8>,
    ) -> Result<()> {
        match self.action.unwrap_or(NeighborAction::Show { dev: None }) {
            NeighborAction::Show { dev } => {
                Self::show(conn, dev.as_deref(), format, opts, family).await
            }
            NeighborAction::Add {
                address,
                lladdr,
                dev,
                permanent,
                state,
            } => {
                Self::add(
                    conn,
                    &address,
                    &lladdr,
                    &dev,
                    permanent,
                    state.as_deref(),
                    false,
                )
                .await
            }
            NeighborAction::Replace {
                address,
                lladdr,
                dev,
                permanent,
            } => Self::add(conn, &address, &lladdr, &dev, permanent, None, true).await,
            NeighborAction::Del { address, dev } => Self::del(conn, &address, &dev).await,
            NeighborAction::Flush { dev } => Self::flush(conn, dev.as_deref(), family).await,
        }
    }

    async fn show(
        conn: &Connection,
        dev: Option<&str>,
        format: OutputFormat,
        opts: &OutputOptions,
        family: Option<u8>,
    ) -> Result<()> {
        // Build request with family filter
        let mut builder = dump_request(NlMsgType::RTM_GETNEIGH);
        let ndmsg = NdMsg::new().with_family(family.unwrap_or(0));
        builder.append(&ndmsg);

        // Send and receive
        let responses = conn.dump(builder).await?;

        // Get device index if filtering by name
        let filter_index = if let Some(dev_name) = dev {
            Some(rip_lib::get_ifindex(dev_name).map_err(rip_netlink::Error::InvalidMessage)? as u32)
        } else {
            None
        };

        // Parse responses into typed NeighborMessage
        let mut neighbors = Vec::new();
        for response in &responses {
            if response.len() < NLMSG_HDRLEN + NdMsg::SIZE {
                continue;
            }

            let payload = &response[NLMSG_HDRLEN..];
            if let Ok(neigh) = NeighborMessage::from_bytes(payload) {
                // Filter by device if specified
                if let Some(idx) = filter_index
                    && neigh.ifindex() != idx
                {
                    continue;
                }
                // Filter by family if specified
                if let Some(fam) = family
                    && neigh.family() != fam
                {
                    continue;
                }
                neighbors.push(neigh);
            }
        }

        print_items(&neighbors, format, opts, neigh_to_json, print_neigh_text)?;

        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    async fn add(
        conn: &Connection,
        address: &str,
        lladdr: &str,
        dev: &str,
        permanent: bool,
        state_name: Option<&str>,
        replace: bool,
    ) -> Result<()> {
        use rip_lib::addr::{parse_addr, parse_mac};
        use rip_netlink::connection::{ack_request, replace_request};

        let addr = parse_addr(address)
            .map_err(|e| rip_netlink::Error::InvalidMessage(format!("invalid address: {}", e)))?;

        let mac = parse_mac(lladdr)
            .map_err(|e| rip_netlink::Error::InvalidMessage(format!("invalid MAC: {}", e)))?;

        let ifindex = rip_lib::get_ifindex(dev).map_err(rip_netlink::Error::InvalidMessage)? as u32;

        let family = if addr.is_ipv4() { 2u8 } else { 10u8 };

        // Parse NUD state
        let state = if permanent {
            nud::PERMANENT
        } else if let Some(s) = state_name {
            match s.to_lowercase().as_str() {
                "reachable" => nud::REACHABLE,
                "stale" => nud::STALE,
                "delay" => nud::DELAY,
                "probe" => nud::PROBE,
                "failed" => nud::FAILED,
                "noarp" => nud::NOARP,
                "permanent" => nud::PERMANENT,
                _ => nud::REACHABLE,
            }
        } else {
            nud::REACHABLE
        };

        let ndmsg = NdMsg {
            ndm_family: family,
            ndm_ifindex: ifindex as i32,
            ndm_state: state,
            ndm_flags: 0,
            ndm_type: 0,
            ..Default::default()
        };

        let mut builder = if replace {
            replace_request(NlMsgType::RTM_NEWNEIGH)
        } else {
            ack_request(NlMsgType::RTM_NEWNEIGH)
        };
        builder.append(&ndmsg);

        // Add destination address
        match addr {
            IpAddr::V4(v4) => {
                builder.append_attr(NdaAttr::Dst as u16, &v4.octets());
            }
            IpAddr::V6(v6) => {
                builder.append_attr(NdaAttr::Dst as u16, &v6.octets());
            }
        }

        // Add link-layer address
        builder.append_attr(NdaAttr::Lladdr as u16, &mac);

        conn.request_ack(builder).await?;

        Ok(())
    }

    async fn del(conn: &Connection, address: &str, dev: &str) -> Result<()> {
        use rip_lib::addr::parse_addr;
        use rip_netlink::connection::ack_request;

        let addr = parse_addr(address)
            .map_err(|e| rip_netlink::Error::InvalidMessage(format!("invalid address: {}", e)))?;

        let ifindex = rip_lib::get_ifindex(dev).map_err(rip_netlink::Error::InvalidMessage)? as u32;

        let family = if addr.is_ipv4() { 2u8 } else { 10u8 };

        let ndmsg = NdMsg {
            ndm_family: family,
            ndm_ifindex: ifindex as i32,
            ..Default::default()
        };

        let mut builder = ack_request(NlMsgType::RTM_DELNEIGH);
        builder.append(&ndmsg);

        // Add destination address
        match addr {
            IpAddr::V4(v4) => {
                builder.append_attr(NdaAttr::Dst as u16, &v4.octets());
            }
            IpAddr::V6(v6) => {
                builder.append_attr(NdaAttr::Dst as u16, &v6.octets());
            }
        }

        conn.request_ack(builder).await?;

        Ok(())
    }

    async fn flush(_conn: &Connection, _dev: Option<&str>, _family: Option<u8>) -> Result<()> {
        // TODO: Implement flush
        Err(rip_netlink::Error::NotSupported(
            "neighbor flush not yet implemented".into(),
        ))
    }
}

/// Convert NeighborMessage to JSON.
fn neigh_to_json(neigh: &NeighborMessage) -> serde_json::Value {
    let dev = rip_lib::ifname::index_to_name(neigh.ifindex())
        .unwrap_or_else(|_| format!("if{}", neigh.ifindex()));

    let mut obj = serde_json::json!({
        "ifindex": neigh.ifindex(),
        "dev": dev,
        "state": nud_state_name(neigh.header.ndm_state),
    });

    if let Some(ref dst) = neigh.destination {
        obj["dst"] = serde_json::json!(dst.to_string());
    }

    if let Some(ref mac) = neigh.mac_address() {
        obj["lladdr"] = serde_json::json!(mac);
    }

    if neigh.is_router() {
        obj["router"] = serde_json::json!(true);
    }

    if neigh.is_proxy() {
        obj["proxy"] = serde_json::json!(true);
    }

    obj
}

/// Print neighbor in text format.
fn print_neigh_text(
    w: &mut io::StdoutLock<'_>,
    neigh: &NeighborMessage,
    _opts: &OutputOptions,
) -> io::Result<()> {
    // Destination
    if let Some(ref dst) = neigh.destination {
        write!(w, "{}", dst)?;
    } else {
        write!(w, "?")?;
    }

    // Device
    let dev = rip_lib::ifname::index_to_name(neigh.ifindex())
        .unwrap_or_else(|_| format!("if{}", neigh.ifindex()));
    write!(w, " dev {}", dev)?;

    // Link-layer address
    if let Some(ref lladdr) = neigh.mac_address() {
        write!(w, " lladdr {}", lladdr)?;
    }

    // Router flag for IPv6
    if neigh.is_router() {
        write!(w, " router")?;
    }

    // State
    write!(w, " {}", nud_state_name(neigh.header.ndm_state))?;

    writeln!(w)?;

    Ok(())
}
