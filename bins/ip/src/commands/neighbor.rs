//! ip neighbor command implementation.

use clap::{Args, Subcommand};
use rip_netlink::attr::{AttrIter, get};
use rip_netlink::message::{NLMSG_HDRLEN, NlMsgHdr, NlMsgType};
use rip_netlink::types::neigh::{NdMsg, NdaAttr, nud, nud_state_name};
use rip_netlink::{Connection, MessageBuilder, Result, connection::dump_request};
use rip_output::{OutputFormat, OutputOptions};
use std::io::{self, Write};

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
        // Build request
        let mut builder = dump_request(NlMsgType::RTM_GETNEIGH);
        let ndmsg = NdMsg::new().with_family(family.unwrap_or(0));
        builder.append(&ndmsg);

        // Send and receive
        let responses = conn.dump(builder).await?;

        let mut stdout = io::stdout().lock();
        let mut neighbors = Vec::new();

        // Get device index if filtering by name
        let filter_index = if let Some(dev_name) = dev {
            Some(rip_lib::ifname::name_to_index(dev_name).map_err(|e| {
                rip_netlink::Error::InvalidMessage(format!("interface not found: {}", e))
            })?)
        } else {
            None
        };

        for response in &responses {
            if let Some(neigh) = parse_neigh_message(response)? {
                // Filter by device if specified
                if let Some(idx) = filter_index {
                    if neigh.ifindex != idx as i32 {
                        continue;
                    }
                }
                // Filter by family if specified
                if let Some(fam) = family {
                    if neigh.family != fam {
                        continue;
                    }
                }
                neighbors.push(neigh);
            }
        }

        match format {
            OutputFormat::Text => {
                for neigh in &neighbors {
                    print_neigh_text(&mut stdout, neigh, opts)?;
                }
            }
            OutputFormat::Json => {
                let json: Vec<_> = neighbors.iter().map(|n| n.to_json()).collect();
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

        let ifindex = rip_lib::ifname::name_to_index(dev).map_err(|e| {
            rip_netlink::Error::InvalidMessage(format!("interface not found: {}", e))
        })?;

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
            std::net::IpAddr::V4(v4) => {
                builder.append_attr(NdaAttr::Dst as u16, &v4.octets());
            }
            std::net::IpAddr::V6(v6) => {
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

        let ifindex = rip_lib::ifname::name_to_index(dev).map_err(|e| {
            rip_netlink::Error::InvalidMessage(format!("interface not found: {}", e))
        })?;

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
            std::net::IpAddr::V4(v4) => {
                builder.append_attr(NdaAttr::Dst as u16, &v4.octets());
            }
            std::net::IpAddr::V6(v6) => {
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

/// Parsed neighbor information.
#[derive(Debug)]
struct NeighInfo {
    ifindex: i32,
    family: u8,
    state: u16,
    flags: u8,
    dst: Option<String>,
    lladdr: Option<String>,
}

impl NeighInfo {
    fn to_json(&self) -> serde_json::Value {
        let dev = rip_lib::ifname::index_to_name(self.ifindex as u32)
            .unwrap_or_else(|_| format!("if{}", self.ifindex));

        let mut obj = serde_json::json!({
            "ifindex": self.ifindex,
            "dev": dev,
            "state": nud_state_name(self.state),
        });

        if let Some(ref dst) = self.dst {
            obj["dst"] = serde_json::json!(dst);
        }

        if let Some(ref lladdr) = self.lladdr {
            obj["lladdr"] = serde_json::json!(lladdr);
        }

        obj
    }
}

fn parse_neigh_message(data: &[u8]) -> Result<Option<NeighInfo>> {
    if data.len() < NLMSG_HDRLEN + NdMsg::SIZE {
        return Ok(None);
    }

    let header = NlMsgHdr::from_bytes(data)?;

    // Skip non-neighbor messages
    if header.nlmsg_type != NlMsgType::RTM_NEWNEIGH {
        return Ok(None);
    }

    let payload = &data[NLMSG_HDRLEN..];
    let ndmsg = NdMsg::from_bytes(payload)?;
    let attrs_data = &payload[NdMsg::SIZE..];

    let mut dst = None;
    let mut lladdr = None;

    for (attr_type, attr_data) in AttrIter::new(attrs_data) {
        match NdaAttr::from(attr_type) {
            NdaAttr::Dst => {
                dst = rip_lib::addr::format_addr_bytes(attr_data, ndmsg.ndm_family);
            }
            NdaAttr::Lladdr => {
                lladdr = Some(rip_lib::addr::format_mac(attr_data));
            }
            _ => {}
        }
    }

    Ok(Some(NeighInfo {
        ifindex: ndmsg.ndm_ifindex,
        family: ndmsg.ndm_family,
        state: ndmsg.ndm_state,
        flags: ndmsg.ndm_flags,
        dst,
        lladdr,
    }))
}

fn print_neigh_text<W: Write>(
    w: &mut W,
    neigh: &NeighInfo,
    _opts: &OutputOptions,
) -> io::Result<()> {
    // Destination
    if let Some(ref dst) = neigh.dst {
        write!(w, "{}", dst)?;
    } else {
        write!(w, "?")?;
    }

    // Device
    let dev = rip_lib::ifname::index_to_name(neigh.ifindex as u32)
        .unwrap_or_else(|_| format!("if{}", neigh.ifindex));
    write!(w, " dev {}", dev)?;

    // Link-layer address
    if let Some(ref lladdr) = neigh.lladdr {
        write!(w, " lladdr {}", lladdr)?;
    }

    // State
    write!(w, " {}", nud_state_name(neigh.state))?;

    writeln!(w)?;

    Ok(())
}
