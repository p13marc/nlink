//! ip address command implementation.
//!
//! This module uses the strongly-typed AddressMessage API from rip-netlink.

use clap::{Args, Subcommand};
use rip::netlink::message::NlMsgType;
use rip::netlink::messages::{AddressMessage, AddressMessageBuilder};
use rip::netlink::types::addr::{IfAddrMsg, IfaAttr, Scope};
use rip::netlink::{Connection, Result, connection::ack_request};
use rip::output::{OutputFormat, OutputOptions};
use std::io::{self, Write};
use std::net::IpAddr;

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
        // Use the strongly-typed API to get all addresses
        let all_addresses: Vec<AddressMessage> = conn.dump_typed(NlMsgType::RTM_GETADDR).await?;

        // Get device index if filtering by name
        let filter_index = rip::util::get_ifindex_opt(dev)
            .map(|opt| opt.map(|i| i as u32))
            .map_err(rip::netlink::Error::InvalidMessage)?;

        // Filter addresses
        let addresses: Vec<_> = all_addresses
            .into_iter()
            .filter(|addr| {
                // Filter by device if specified
                if let Some(idx) = filter_index
                    && addr.ifindex() != idx
                {
                    return false;
                }
                // Filter by family if specified
                if let Some(fam) = family
                    && addr.family() != fam
                {
                    return false;
                }
                true
            })
            .collect();

        let mut stdout = io::stdout().lock();

        match format {
            OutputFormat::Text => {
                // Group by interface
                let mut current_index = 0u32;
                for addr in &addresses {
                    if addr.ifindex() != current_index {
                        current_index = addr.ifindex();
                        // Print interface header
                        let ifname = rip::util::get_ifname_or_index(addr.ifindex() as i32);
                        writeln!(stdout, "{}: {}:", addr.ifindex(), ifname)?;
                    }
                    print_addr_text(&mut stdout, addr, opts)?;
                }
            }
            OutputFormat::Json => {
                let json: Vec<_> = addresses.iter().map(addr_to_json).collect();
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
        use rip::util::addr::parse_prefix;

        let (addr, prefix) = parse_prefix(address)
            .map_err(|e| rip::netlink::Error::InvalidMessage(format!("invalid address: {}", e)))?;

        let ifindex = rip::util::get_ifindex(dev).map_err(rip::netlink::Error::InvalidMessage)? as u32;

        // Parse scope
        let scope_val = if let Some(s) = scope {
            Scope::from_name(s).unwrap_or(Scope::Universe)
        } else {
            Scope::Universe
        };

        // Build the message using the typed builder
        let mut builder = AddressMessageBuilder::new()
            .ifindex(ifindex)
            .prefix_len(prefix)
            .scope(scope_val)
            .address(addr)
            .local(addr);

        // Add peer address (for point-to-point)
        if let Some(peer_str) = peer {
            let peer_addr: IpAddr = peer_str.parse().map_err(|_| {
                rip::netlink::Error::InvalidMessage(format!("invalid peer address: {}", peer_str))
            })?;
            builder = builder.address(peer_addr);
        }

        // Add broadcast if specified (IPv4 only)
        if let Some(brd_str) = broadcast
            && let Ok(brd_addr) = brd_str.parse::<std::net::Ipv4Addr>()
        {
            builder = builder.broadcast(IpAddr::V4(brd_addr));
        }

        // Add label if specified
        if let Some(lbl) = label {
            builder = builder.label(lbl);
        }

        let msg = builder.build();

        // For now, we still need to use the low-level builder for sending
        // because we need to set the message type and flags
        let family = if addr.is_ipv4() { 2u8 } else { 10u8 };
        let ifaddr = IfAddrMsg::new()
            .with_family(family)
            .with_prefixlen(prefix)
            .with_index(ifindex)
            .with_scope(scope_val as u8);

        let mut nl_builder = ack_request(NlMsgType::RTM_NEWADDR);
        nl_builder.append(&ifaddr);

        // Add local address
        match addr {
            IpAddr::V4(v4) => {
                nl_builder.append_attr(IfaAttr::Local as u16, &v4.octets());
            }
            IpAddr::V6(v6) => {
                nl_builder.append_attr(IfaAttr::Local as u16, &v6.octets());
            }
        }

        // Add address attribute (peer or same as local)
        if let Some(peer_str) = peer {
            let peer_addr: IpAddr = peer_str.parse().unwrap();
            match peer_addr {
                IpAddr::V4(v4) => {
                    nl_builder.append_attr(IfaAttr::Address as u16, &v4.octets());
                }
                IpAddr::V6(v6) => {
                    nl_builder.append_attr(IfaAttr::Address as u16, &v6.octets());
                }
            }
        } else {
            match addr {
                IpAddr::V4(v4) => {
                    nl_builder.append_attr(IfaAttr::Address as u16, &v4.octets());
                }
                IpAddr::V6(v6) => {
                    nl_builder.append_attr(IfaAttr::Address as u16, &v6.octets());
                }
            }
        }

        // Add broadcast if specified
        if let Some(ref brd) = msg.broadcast
            && let IpAddr::V4(v4) = brd
        {
            nl_builder.append_attr(IfaAttr::Broadcast as u16, &v4.octets());
        }

        // Add label if specified
        if let Some(ref lbl) = msg.label {
            nl_builder.append_attr_str(IfaAttr::Label as u16, lbl);
        }

        conn.request_ack(nl_builder).await?;

        Ok(())
    }

    async fn del(conn: &Connection, address: &str, dev: &str) -> Result<()> {
        use rip::util::addr::parse_prefix;

        let (addr, prefix) = parse_prefix(address)
            .map_err(|e| rip::netlink::Error::InvalidMessage(format!("invalid address: {}", e)))?;

        let ifindex = rip::util::get_ifindex(dev).map_err(rip::netlink::Error::InvalidMessage)? as u32;

        let family = if addr.is_ipv4() { 2u8 } else { 10u8 };

        let ifaddr = IfAddrMsg::new()
            .with_family(family)
            .with_prefixlen(prefix)
            .with_index(ifindex);

        let mut builder = ack_request(NlMsgType::RTM_DELADDR);
        builder.append(&ifaddr);

        // Add address attribute
        match addr {
            IpAddr::V4(v4) => {
                builder.append_attr(IfaAttr::Local as u16, &v4.octets());
            }
            IpAddr::V6(v6) => {
                builder.append_attr(IfaAttr::Local as u16, &v6.octets());
            }
        }

        conn.request_ack(builder).await?;

        Ok(())
    }

    async fn flush(conn: &Connection, dev: Option<&str>, family: Option<u8>) -> Result<()> {
        // Get all addresses using the typed API
        let all_addresses: Vec<AddressMessage> = conn.dump_typed(NlMsgType::RTM_GETADDR).await?;

        // Get device index if filtering by name
        let filter_index = rip::util::get_ifindex_opt(dev)
            .map(|opt| opt.map(|i| i as u32))
            .map_err(rip::netlink::Error::InvalidMessage)?;

        // Filter and delete addresses
        for addr in all_addresses {
            // Skip if device filter doesn't match
            if let Some(idx) = filter_index
                && addr.ifindex() != idx
            {
                continue;
            }
            // Skip if family filter doesn't match
            if let Some(fam) = family
                && addr.family() != fam
            {
                continue;
            }

            // Delete this address
            let ifaddr = IfAddrMsg::new()
                .with_family(addr.family())
                .with_prefixlen(addr.prefix_len())
                .with_index(addr.ifindex());

            let mut builder = ack_request(NlMsgType::RTM_DELADDR);
            builder.append(&ifaddr);

            // Add address attribute
            if let Some(local) = &addr.local {
                match local {
                    IpAddr::V4(v4) => {
                        builder.append_attr(IfaAttr::Local as u16, &v4.octets());
                    }
                    IpAddr::V6(v6) => {
                        builder.append_attr(IfaAttr::Local as u16, &v6.octets());
                    }
                }
            } else if let Some(address) = &addr.address {
                match address {
                    IpAddr::V4(v4) => {
                        builder.append_attr(IfaAttr::Local as u16, &v4.octets());
                    }
                    IpAddr::V6(v6) => {
                        builder.append_attr(IfaAttr::Local as u16, &v6.octets());
                    }
                }
            }

            // Ignore errors for individual deletions
            let _ = conn.request_ack(builder).await;
        }

        Ok(())
    }
}

/// Convert AddressMessage to JSON.
fn addr_to_json(addr: &AddressMessage) -> serde_json::Value {
    let ifname = rip::util::get_ifname_or_index(addr.ifindex() as i32);

    let mut obj = serde_json::json!({
        "ifindex": addr.ifindex(),
        "ifname": ifname,
        "family": rip::util::names::family_name(addr.family()),
        "prefixlen": addr.prefix_len(),
        "scope": addr.scope().name(),
    });

    if let Some(ref address) = addr.address {
        obj["address"] = serde_json::json!(address.to_string());
    }
    if let Some(ref local) = addr.local {
        obj["local"] = serde_json::json!(local.to_string());
    }
    if let Some(ref label) = addr.label {
        obj["label"] = serde_json::json!(label);
    }
    if let Some(ref broadcast) = addr.broadcast {
        obj["broadcast"] = serde_json::json!(broadcast.to_string());
    }

    // Add flags
    let mut flags = Vec::new();
    if addr.is_secondary() {
        flags.push("secondary");
    }
    if addr.is_permanent() {
        flags.push("permanent");
    }
    if addr.is_deprecated() {
        flags.push("deprecated");
    }
    if addr.is_tentative() {
        flags.push("tentative");
    }
    if !flags.is_empty() {
        obj["flags"] = serde_json::json!(flags);
    }

    obj
}

/// Print address in text format.
fn print_addr_text<W: Write>(
    w: &mut W,
    addr: &AddressMessage,
    _opts: &OutputOptions,
) -> io::Result<()> {
    let family = rip::util::names::family_name(addr.family());

    // Get the primary address to display
    let display_addr = addr
        .primary_address()
        .map(|a| a.to_string())
        .unwrap_or_else(|| "unknown".to_string());

    write!(w, "    {} {}/{}", family, display_addr, addr.prefix_len())?;

    // Show peer if different from local
    if let (Some(local), Some(address)) = (&addr.local, &addr.address)
        && local != address
    {
        write!(w, " peer {}", address)?;
    }

    // Show broadcast for IPv4
    if let Some(ref brd) = addr.broadcast {
        write!(w, " brd {}", brd)?;
    }

    write!(w, " scope {}", addr.scope().name())?;

    // Show flags
    if addr.is_secondary() {
        write!(w, " secondary")?;
    }
    if addr.is_deprecated() {
        write!(w, " deprecated")?;
    }
    if addr.is_tentative() {
        write!(w, " tentative")?;
    }

    if let Some(ref label) = addr.label {
        write!(w, " {}", label)?;
    }

    writeln!(w)?;

    Ok(())
}
