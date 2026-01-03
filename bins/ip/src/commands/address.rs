//! ip address command implementation.
//!
//! This module uses the strongly-typed AddressMessage API from rip-netlink.

use clap::{Args, Subcommand};
use nlink::netlink::addr::{Ipv4Address, Ipv6Address};
use nlink::netlink::messages::AddressMessage;
use nlink::netlink::types::addr::Scope;
use nlink::netlink::{Connection, Result, Route};
use nlink::output::{OutputFormat, OutputOptions};
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
        conn: &Connection<Route>,
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
        conn: &Connection<Route>,
        dev: Option<&str>,
        format: OutputFormat,
        opts: &OutputOptions,
        family: Option<u8>,
    ) -> Result<()> {
        // Use the strongly-typed API to get all addresses
        let all_addresses = conn.get_addresses().await?;

        // Get device index if filtering by name
        let filter_index =
            nlink::util::get_ifindex_opt(dev).map_err(nlink::netlink::Error::InvalidMessage)?;

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
                        let ifname = nlink::util::get_ifname_or_index(addr.ifindex());
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
        conn: &Connection<Route>,
        address: &str,
        dev: &str,
        label: Option<&str>,
        broadcast: Option<&str>,
        scope: Option<&str>,
        _peer: Option<&str>,
    ) -> Result<()> {
        use nlink::util::addr::parse_prefix;

        let (addr, prefix) = parse_prefix(address).map_err(|e| {
            nlink::netlink::Error::InvalidMessage(format!("invalid address: {}", e))
        })?;

        // Parse scope
        let scope_val = if let Some(s) = scope {
            Scope::from_name(s).unwrap_or(Scope::Universe)
        } else {
            Scope::Universe
        };

        match addr {
            IpAddr::V4(v4) => {
                let mut config = Ipv4Address::new(dev, v4, prefix).scope(scope_val);

                if let Some(lbl) = label {
                    config = config.label(lbl);
                }

                if let Some(brd_str) = broadcast
                    && let Ok(brd_addr) = brd_str.parse::<std::net::Ipv4Addr>()
                {
                    config = config.broadcast(brd_addr);
                }

                conn.add_address(config).await
            }
            IpAddr::V6(v6) => {
                let config = Ipv6Address::new(dev, v6, prefix).scope(scope_val);
                conn.add_address(config).await
            }
        }
    }

    async fn del(conn: &Connection<Route>, address: &str, dev: &str) -> Result<()> {
        use nlink::util::addr::parse_prefix;

        let (addr, prefix) = parse_prefix(address).map_err(|e| {
            nlink::netlink::Error::InvalidMessage(format!("invalid address: {}", e))
        })?;

        conn.del_address(dev, addr, prefix).await
    }

    async fn flush(conn: &Connection<Route>, dev: Option<&str>, family: Option<u8>) -> Result<()> {
        // Get all addresses using the typed API
        let all_addresses = conn.get_addresses().await?;

        // Get device index if filtering by name
        let filter_index =
            nlink::util::get_ifindex_opt(dev).map_err(nlink::netlink::Error::InvalidMessage)?;

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

            // Get the address to delete
            let address_to_del = addr.local().or(addr.address());
            if let Some(ip_addr) = address_to_del {
                // Get interface name for del_address
                let ifname = nlink::util::get_ifname(addr.ifindex());
                if let Ok(name) = ifname {
                    // Ignore errors for individual deletions
                    let _ = conn.del_address(&name, *ip_addr, addr.prefix_len()).await;
                }
            }
        }

        Ok(())
    }
}

/// Convert AddressMessage to JSON.
fn addr_to_json(addr: &AddressMessage) -> serde_json::Value {
    let ifname = nlink::util::get_ifname_or_index(addr.ifindex());

    let mut obj = serde_json::json!({
        "ifindex": addr.ifindex(),
        "ifname": ifname,
        "family": nlink::util::names::family_name(addr.family()),
        "prefixlen": addr.prefix_len(),
        "scope": addr.scope().name(),
    });

    if let Some(address) = addr.address() {
        obj["address"] = serde_json::json!(address.to_string());
    }
    if let Some(local) = addr.local() {
        obj["local"] = serde_json::json!(local.to_string());
    }
    if let Some(label) = addr.label() {
        obj["label"] = serde_json::json!(label);
    }
    if let Some(broadcast) = addr.broadcast() {
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
    let family = nlink::util::names::family_name(addr.family());

    // Get the primary address to display
    let display_addr = addr
        .primary_address()
        .map(|a| a.to_string())
        .unwrap_or_else(|| "unknown".to_string());

    write!(w, "    {} {}/{}", family, display_addr, addr.prefix_len())?;

    // Show peer if different from local
    if let (Some(local), Some(address)) = (addr.local(), addr.address())
        && local != address
    {
        write!(w, " peer {}", address)?;
    }

    // Show broadcast for IPv4
    if let Some(brd) = addr.broadcast() {
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

    if let Some(label) = addr.label() {
        write!(w, " {}", label)?;
    }

    writeln!(w)?;

    Ok(())
}
