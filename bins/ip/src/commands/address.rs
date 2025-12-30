//! ip address command implementation.

use clap::{Args, Subcommand};
use rip_netlink::attr::{AttrIter, get};
use rip_netlink::message::{NLMSG_HDRLEN, NlMsgHdr, NlMsgType};
use rip_netlink::types::addr::{IfAddrMsg, IfaAttr, Scope};
use rip_netlink::{Connection, MessageBuilder, Result, connection::dump_request};
use rip_output::{OutputFormat, OutputOptions};
use std::io::{self, Write};

#[derive(Args)]
pub struct AddressCmd {
    #[command(subcommand)]
    action: Option<AddressAction>,
}

#[derive(Subcommand)]
enum AddressAction {
    /// Show addresses.
    Show {
        /// Interface name.
        dev: Option<String>,
    },

    /// Add an address.
    Add {
        /// Address with prefix (e.g., 192.168.1.1/24).
        address: String,

        /// Device name.
        #[arg(long, short)]
        dev: String,

        /// Address label.
        #[arg(long)]
        label: Option<String>,

        /// Broadcast address.
        #[arg(long)]
        broadcast: Option<String>,

        /// Scope (global, site, link, host).
        #[arg(long)]
        scope: Option<String>,

        /// Peer address (for point-to-point).
        #[arg(long)]
        peer: Option<String>,
    },

    /// Delete an address.
    Del {
        /// Address with prefix.
        address: String,

        /// Device name.
        #[arg(long, short)]
        dev: String,
    },

    /// Flush addresses.
    Flush {
        /// Interface name.
        dev: Option<String>,
    },
}

impl AddressCmd {
    pub async fn run(
        self,
        conn: &Connection,
        format: OutputFormat,
        opts: &OutputOptions,
        family: Option<u8>,
    ) -> Result<()> {
        match self.action.unwrap_or(AddressAction::Show { dev: None }) {
            AddressAction::Show { dev } => {
                Self::show(conn, dev.as_deref(), format, opts, family).await
            }
            AddressAction::Add {
                address,
                dev,
                label,
                broadcast,
                scope,
                peer,
            } => {
                Self::add(
                    conn,
                    &address,
                    &dev,
                    label.as_deref(),
                    broadcast.as_deref(),
                    scope.as_deref(),
                    peer.as_deref(),
                )
                .await
            }
            AddressAction::Del { address, dev } => Self::del(conn, &address, &dev).await,
            AddressAction::Flush { dev } => Self::flush(conn, dev.as_deref(), family).await,
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
        let mut builder = dump_request(NlMsgType::RTM_GETADDR);
        let ifaddr = IfAddrMsg::new().with_family(family.unwrap_or(0));
        builder.append(&ifaddr);

        // Send and receive
        let responses = conn.dump(builder).await?;

        let mut stdout = io::stdout().lock();
        let mut addrs = Vec::new();

        // Get device index if filtering by name
        let filter_index = if let Some(dev_name) = dev {
            Some(rip_lib::ifname::name_to_index(dev_name).map_err(|e| {
                rip_netlink::Error::InvalidMessage(format!("interface not found: {}", e))
            })?)
        } else {
            None
        };

        for response in &responses {
            if let Some(addr) = parse_addr_message(response)? {
                // Filter by device if specified
                if let Some(idx) = filter_index {
                    if addr.index != idx {
                        continue;
                    }
                }
                // Filter by family if specified
                if let Some(fam) = family {
                    if addr.family != fam {
                        continue;
                    }
                }
                addrs.push(addr);
            }
        }

        match format {
            OutputFormat::Text => {
                // Group by interface
                let mut current_index = 0u32;
                for addr in &addrs {
                    if addr.index != current_index {
                        current_index = addr.index;
                        // Print interface header
                        let ifname = rip_lib::ifname::index_to_name(addr.index)
                            .unwrap_or_else(|_| format!("if{}", addr.index));
                        writeln!(stdout, "{}: {}:", addr.index, ifname)?;
                    }
                    print_addr_text(&mut stdout, addr, opts)?;
                }
            }
            OutputFormat::Json => {
                let json: Vec<_> = addrs.iter().map(|a| a.to_json()).collect();
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
        dev: &str,
        label: Option<&str>,
        broadcast: Option<&str>,
        scope: Option<&str>,
        peer: Option<&str>,
    ) -> Result<()> {
        use rip_lib::addr::parse_prefix;
        use rip_netlink::connection::ack_request;

        let (addr, prefix) = parse_prefix(address)
            .map_err(|e| rip_netlink::Error::InvalidMessage(format!("invalid address: {}", e)))?;

        let ifindex = rip_lib::ifname::name_to_index(dev).map_err(|e| {
            rip_netlink::Error::InvalidMessage(format!("interface not found: {}", e))
        })?;

        let family = if addr.is_ipv4() { 2u8 } else { 10u8 };

        // Parse scope
        let scope_val = if let Some(s) = scope {
            Scope::from_name(s)
                .map(|sc| sc as u8)
                .unwrap_or_else(|| s.parse().unwrap_or(0))
        } else {
            0 // RT_SCOPE_UNIVERSE
        };

        let ifaddr = IfAddrMsg::new()
            .with_family(family)
            .with_prefixlen(prefix)
            .with_index(ifindex)
            .with_scope(scope_val);

        let mut builder = ack_request(NlMsgType::RTM_NEWADDR);
        builder.append(&ifaddr);

        // Add local address (the address we're adding)
        match addr {
            std::net::IpAddr::V4(v4) => {
                builder.append_attr(IfaAttr::Local as u16, &v4.octets());
            }
            std::net::IpAddr::V6(v6) => {
                builder.append_attr(IfaAttr::Local as u16, &v6.octets());
            }
        }

        // Add peer address (for point-to-point) or same as local for broadcast
        if let Some(peer_str) = peer {
            let peer_addr: std::net::IpAddr = peer_str.parse().map_err(|_| {
                rip_netlink::Error::InvalidMessage(format!("invalid peer address: {}", peer_str))
            })?;
            match peer_addr {
                std::net::IpAddr::V4(v4) => {
                    builder.append_attr(IfaAttr::Address as u16, &v4.octets());
                }
                std::net::IpAddr::V6(v6) => {
                    builder.append_attr(IfaAttr::Address as u16, &v6.octets());
                }
            }
        } else {
            // For non-point-to-point, IFA_ADDRESS is the same as IFA_LOCAL
            match addr {
                std::net::IpAddr::V4(v4) => {
                    builder.append_attr(IfaAttr::Address as u16, &v4.octets());
                }
                std::net::IpAddr::V6(v6) => {
                    builder.append_attr(IfaAttr::Address as u16, &v6.octets());
                }
            }
        }

        // Add broadcast if specified (IPv4 only)
        if let Some(brd_str) = broadcast {
            if let Ok(brd_addr) = brd_str.parse::<std::net::Ipv4Addr>() {
                builder.append_attr(IfaAttr::Broadcast as u16, &brd_addr.octets());
            }
        }

        // Add label if specified
        if let Some(lbl) = label {
            builder.append_attr_str(IfaAttr::Label as u16, lbl);
        }

        conn.request_ack(builder).await?;

        Ok(())
    }

    async fn del(conn: &Connection, address: &str, dev: &str) -> Result<()> {
        use rip_lib::addr::parse_prefix;
        use rip_netlink::connection::ack_request;

        let (addr, prefix) = parse_prefix(address)
            .map_err(|e| rip_netlink::Error::InvalidMessage(format!("invalid address: {}", e)))?;

        let ifindex = rip_lib::ifname::name_to_index(dev).map_err(|e| {
            rip_netlink::Error::InvalidMessage(format!("interface not found: {}", e))
        })?;

        let family = if addr.is_ipv4() { 2u8 } else { 10u8 };

        let ifaddr = IfAddrMsg::new()
            .with_family(family)
            .with_prefixlen(prefix)
            .with_index(ifindex);

        let mut builder = ack_request(NlMsgType::RTM_DELADDR);
        builder.append(&ifaddr);

        // Add address attribute
        match addr {
            std::net::IpAddr::V4(v4) => {
                builder.append_attr(IfaAttr::Local as u16, &v4.octets());
            }
            std::net::IpAddr::V6(v6) => {
                builder.append_attr(IfaAttr::Local as u16, &v6.octets());
            }
        }

        conn.request_ack(builder).await?;

        Ok(())
    }

    async fn flush(_conn: &Connection, _dev: Option<&str>, _family: Option<u8>) -> Result<()> {
        // TODO: Implement flush by iterating and deleting
        Err(rip_netlink::Error::NotSupported(
            "flush not yet implemented".into(),
        ))
    }
}

/// Parsed address information.
#[derive(Debug)]
struct AddrInfo {
    index: u32,
    family: u8,
    prefix_len: u8,
    scope: Scope,
    address: String,
    local: Option<String>,
    label: Option<String>,
    flags: u32,
}

impl AddrInfo {
    fn to_json(&self) -> serde_json::Value {
        let ifname = rip_lib::ifname::index_to_name(self.index)
            .unwrap_or_else(|_| format!("if{}", self.index));

        let mut obj = serde_json::json!({
            "ifindex": self.index,
            "ifname": ifname,
            "family": rip_lib::names::family_name(self.family),
            "prefixlen": self.prefix_len,
            "scope": self.scope.name(),
            "address": self.address,
        });

        if let Some(ref local) = self.local {
            obj["local"] = serde_json::json!(local);
        }
        if let Some(ref label) = self.label {
            obj["label"] = serde_json::json!(label);
        }

        obj
    }
}

fn parse_addr_message(data: &[u8]) -> Result<Option<AddrInfo>> {
    if data.len() < NLMSG_HDRLEN + IfAddrMsg::SIZE {
        return Ok(None);
    }

    let header = NlMsgHdr::from_bytes(data)?;

    // Skip non-address messages
    if header.nlmsg_type != NlMsgType::RTM_NEWADDR {
        return Ok(None);
    }

    let payload = &data[NLMSG_HDRLEN..];
    let ifaddr = IfAddrMsg::from_bytes(payload)?;
    let attrs_data = &payload[IfAddrMsg::SIZE..];

    let mut address = String::new();
    let mut local = None;
    let mut label = None;
    let mut flags = ifaddr.ifa_flags as u32;

    for (attr_type, attr_data) in AttrIter::new(attrs_data) {
        match IfaAttr::from(attr_type) {
            IfaAttr::Address => {
                address = rip_lib::addr::format_addr_bytes(attr_data, ifaddr.ifa_family)
                    .unwrap_or_default();
            }
            IfaAttr::Local => {
                local = rip_lib::addr::format_addr_bytes(attr_data, ifaddr.ifa_family);
            }
            IfaAttr::Label => {
                label = Some(get::string(attr_data).unwrap_or("").to_string());
            }
            IfaAttr::Flags => {
                flags = get::u32_ne(attr_data).unwrap_or(0);
            }
            _ => {}
        }
    }

    Ok(Some(AddrInfo {
        index: ifaddr.ifa_index,
        family: ifaddr.ifa_family,
        prefix_len: ifaddr.ifa_prefixlen,
        scope: Scope::from(ifaddr.ifa_scope),
        address,
        local,
        label,
        flags,
    }))
}

fn print_addr_text<W: Write>(w: &mut W, addr: &AddrInfo, _opts: &OutputOptions) -> io::Result<()> {
    let family = rip_lib::names::family_name(addr.family);

    write!(w, "    {} {}/{}", family, addr.address, addr.prefix_len)?;

    if let Some(ref local) = addr.local {
        if local != &addr.address {
            write!(w, " peer {}", local)?;
        }
    }

    write!(w, " scope {}", addr.scope.name())?;

    if let Some(ref label) = addr.label {
        write!(w, " {}", label)?;
    }

    writeln!(w)?;

    Ok(())
}
