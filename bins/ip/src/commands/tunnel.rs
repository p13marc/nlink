//! ip tunnel command implementation.
//!
//! Tunnel management for GRE, IPIP, SIT, and VTI tunnels.
//! This provides a traditional iproute2-style interface for tunnel operations.
//!
//! Modern tunnels are created via `ip link add type <type>`, but this command
//! provides compatibility with the classic `ip tunnel` syntax.

use clap::{Args, Subcommand};
use nlink::netlink::attr::AttrIter;
use nlink::netlink::link::{GreLink, GretapLink, IpipLink, SitLink, VtiLink};
use nlink::netlink::{Connection, Result, Route};
use nlink::output::{OutputFormat, OutputOptions, Printable, print_all};
use std::io::Write;
use std::net::Ipv4Addr;

/// IFLA_GRE_* attribute constants
mod gre_attrs {
    pub const IFLA_GRE_IKEY: u16 = 4;
    pub const IFLA_GRE_LOCAL: u16 = 6;
    pub const IFLA_GRE_REMOTE: u16 = 7;
    pub const IFLA_GRE_TTL: u16 = 8;
}

/// IFLA_IPTUN_* attribute constants (for ipip/sit)
mod iptun_attrs {
    pub const IFLA_IPTUN_LOCAL: u16 = 2;
    pub const IFLA_IPTUN_REMOTE: u16 = 3;
    pub const IFLA_IPTUN_TTL: u16 = 4;
}

#[derive(Args)]
pub struct TunnelCmd {
    #[command(subcommand)]
    action: Option<TunnelAction>,
}

#[derive(Subcommand)]
enum TunnelAction {
    /// Show tunnels.
    Show {
        /// Filter by tunnel name.
        name: Option<String>,

        /// Filter by mode.
        #[arg(long)]
        mode: Option<String>,
    },

    /// List tunnels (alias for show).
    #[command(visible_alias = "ls")]
    List,

    /// Add a tunnel.
    Add {
        /// Tunnel name.
        name: String,

        /// Tunnel mode (gre, ipip, sit, vti).
        #[arg(long)]
        mode: String,

        /// Remote endpoint address.
        #[arg(long)]
        remote: String,

        /// Local endpoint address.
        #[arg(long)]
        local: Option<String>,

        /// TTL value.
        #[arg(long)]
        ttl: Option<u8>,

        /// TOS value.
        #[arg(long)]
        tos: Option<u8>,

        /// Tunnel key (for GRE).
        #[arg(long)]
        key: Option<u32>,

        /// Input key (for GRE).
        #[arg(long)]
        ikey: Option<u32>,

        /// Output key (for GRE).
        #[arg(long)]
        okey: Option<u32>,

        /// Enable path MTU discovery.
        #[arg(long)]
        pmtudisc: bool,

        /// Disable path MTU discovery.
        #[arg(long)]
        nopmtudisc: bool,

        /// Physical device for the tunnel.
        #[arg(long)]
        dev: Option<String>,
    },

    /// Delete a tunnel.
    #[command(visible_alias = "del")]
    Delete {
        /// Tunnel name.
        name: String,
    },

    /// Change tunnel parameters.
    Change {
        /// Tunnel name.
        name: String,

        /// Remote endpoint address.
        #[arg(long)]
        remote: Option<String>,

        /// Local endpoint address.
        #[arg(long)]
        local: Option<String>,

        /// TTL value.
        #[arg(long)]
        ttl: Option<u8>,

        /// Tunnel key (for GRE).
        #[arg(long)]
        key: Option<u32>,
    },
}

impl TunnelCmd {
    pub async fn run(
        &self,
        conn: &Connection<Route>,
        format: OutputFormat,
        opts: &OutputOptions,
    ) -> Result<()> {
        match &self.action {
            Some(TunnelAction::Show { name, mode }) => {
                self.show_tunnels(conn, name.as_deref(), mode.as_deref(), format, opts)
                    .await
            }
            None => self.show_tunnels(conn, None, None, format, opts).await,
            Some(TunnelAction::List) => self.show_tunnels(conn, None, None, format, opts).await,
            Some(TunnelAction::Add {
                name,
                mode,
                remote,
                local,
                ttl,
                tos,
                key,
                ikey,
                okey,
                pmtudisc,
                nopmtudisc,
                dev,
            }) => {
                self.add_tunnel(
                    conn,
                    name,
                    mode,
                    remote,
                    local.as_deref(),
                    *ttl,
                    *tos,
                    *key,
                    *ikey,
                    *okey,
                    *pmtudisc,
                    *nopmtudisc,
                    dev.as_deref(),
                )
                .await
            }
            Some(TunnelAction::Delete { name }) => self.delete_tunnel(conn, name).await,
            Some(TunnelAction::Change {
                name,
                remote,
                local,
                ttl,
                key,
            }) => {
                self.change_tunnel(conn, name, remote.as_deref(), local.as_deref(), *ttl, *key)
                    .await
            }
        }
    }

    async fn show_tunnels(
        &self,
        conn: &Connection<Route>,
        name_filter: Option<&str>,
        mode_filter: Option<&str>,
        format: OutputFormat,
        _opts: &OutputOptions,
    ) -> Result<()> {
        // Get all links and filter for tunnel types
        let links = conn.get_links().await?;

        let tunnel_modes = [
            "gre",
            "gretap",
            "ipip",
            "sit",
            "vti",
            "ip6gre",
            "ip6tnl",
            "ip6gretap",
        ];

        let mut tunnels = Vec::new();

        for link in &links {
            // Check if this is a tunnel type
            let link_info = match &link.link_info {
                Some(info) => info,
                None => continue,
            };

            let kind = match &link_info.kind {
                Some(k) => k.as_str(),
                None => continue,
            };

            if !tunnel_modes.contains(&kind) {
                continue;
            }

            // Apply name filter
            if let Some(name) = name_filter
                && link.name.as_deref() != Some(name) {
                    continue;
                }

            // Apply mode filter
            if let Some(mode) = mode_filter
                && kind != mode {
                    continue;
                }

            // Extract tunnel-specific info from link_info.data
            let (remote, local, ttl, key) =
                extract_tunnel_info(kind, link_info.data.as_deref().unwrap_or(&[]));

            tunnels.push(TunnelInfo {
                name: link.name.clone().unwrap_or_default(),
                mode: kind.to_string(),
                remote,
                local,
                ttl,
                key,
                ifindex: link.ifindex(),
            });
        }

        print_all(&tunnels, format, &OutputOptions::default())?;

        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    async fn add_tunnel(
        &self,
        conn: &Connection<Route>,
        name: &str,
        mode: &str,
        remote: &str,
        local: Option<&str>,
        ttl: Option<u8>,
        _tos: Option<u8>,
        key: Option<u32>,
        ikey: Option<u32>,
        okey: Option<u32>,
        _pmtudisc: bool,
        _nopmtudisc: bool,
        _dev: Option<&str>,
    ) -> Result<()> {
        // Parse addresses
        let remote_addr: Ipv4Addr = remote.parse().map_err(|_| {
            nlink::netlink::Error::InvalidMessage(format!("invalid remote address: {}", remote))
        })?;

        let local_addr: Option<Ipv4Addr> = if let Some(l) = local {
            Some(l.parse().map_err(|_| {
                nlink::netlink::Error::InvalidMessage(format!("invalid local address: {}", l))
            })?)
        } else {
            None
        };

        // Use the first key specified (key > ikey > okey)
        let effective_key = key.or(ikey).or(okey);

        match mode.to_lowercase().as_str() {
            "gre" => {
                let mut link = GreLink::new(name).remote(remote_addr);
                if let Some(local) = local_addr {
                    link = link.local(local);
                }
                if let Some(t) = ttl {
                    link = link.ttl(t);
                }
                if let Some(k) = effective_key {
                    link = link.key(k);
                }
                conn.add_link(link).await?;
            }
            "gretap" => {
                let mut link = GretapLink::new(name).remote(remote_addr);
                if let Some(local) = local_addr {
                    link = link.local(local);
                }
                if let Some(t) = ttl {
                    link = link.ttl(t);
                }
                if let Some(k) = effective_key {
                    link = link.key(k);
                }
                conn.add_link(link).await?;
            }
            "ipip" | "ip/ip" => {
                let mut link = IpipLink::new(name).remote(remote_addr);
                if let Some(local) = local_addr {
                    link = link.local(local);
                }
                if let Some(t) = ttl {
                    link = link.ttl(t);
                }
                conn.add_link(link).await?;
            }
            "sit" | "ipv6/ip" => {
                let mut link = SitLink::new(name).remote(remote_addr);
                if let Some(local) = local_addr {
                    link = link.local(local);
                }
                if let Some(t) = ttl {
                    link = link.ttl(t);
                }
                conn.add_link(link).await?;
            }
            "vti" => {
                let mut link = VtiLink::new(name).remote(remote_addr);
                if let Some(local) = local_addr {
                    link = link.local(local);
                }
                if let Some(k) = effective_key {
                    link = link.ikey(k).okey(k);
                }
                conn.add_link(link).await?;
            }
            _ => {
                return Err(nlink::netlink::Error::InvalidMessage(format!(
                    "unknown tunnel mode '{}', supported: gre, gretap, ipip, sit, vti",
                    mode
                )));
            }
        }

        println!("Tunnel '{}' created", name);
        Ok(())
    }

    async fn delete_tunnel(&self, conn: &Connection<Route>, name: &str) -> Result<()> {
        conn.del_link(name).await?;
        println!("Tunnel '{}' deleted", name);
        Ok(())
    }

    async fn change_tunnel(
        &self,
        _conn: &Connection<Route>,
        name: &str,
        _remote: Option<&str>,
        _local: Option<&str>,
        _ttl: Option<u8>,
        _key: Option<u32>,
    ) -> Result<()> {
        // Changing tunnel parameters in-place is not well supported by the kernel
        // for most tunnel types. The recommended approach is to delete and recreate.
        Err(nlink::netlink::Error::InvalidMessage(format!(
            "changing tunnel '{}' parameters is not supported; use 'ip tunnel del' followed by 'ip tunnel add'",
            name
        )))
    }
}

/// Parsed tunnel information.
#[derive(Debug)]
struct TunnelInfo {
    name: String,
    mode: String,
    remote: Option<Ipv4Addr>,
    local: Option<Ipv4Addr>,
    ttl: Option<u8>,
    key: Option<u32>,
    ifindex: u32,
}

impl Printable for TunnelInfo {
    fn print_text<W: Write>(&self, w: &mut W, _opts: &OutputOptions) -> std::io::Result<()> {
        write!(w, "{}: {}/ip", self.name, self.mode)?;

        write!(
            w,
            " remote {}",
            self.remote
                .map(|a| a.to_string())
                .unwrap_or_else(|| "any".to_string())
        )?;

        write!(
            w,
            " local {}",
            self.local
                .map(|a| a.to_string())
                .unwrap_or_else(|| "any".to_string())
        )?;

        if let Some(ttl) = self.ttl {
            if ttl > 0 {
                write!(w, " ttl {}", ttl)?;
            } else {
                write!(w, " ttl inherit")?;
            }
        }

        if let Some(key) = self.key {
            write!(w, " key {}", key)?;
        }

        writeln!(w)?;

        Ok(())
    }

    fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "name": self.name,
            "mode": self.mode,
            "remote": self.remote.map(|a| a.to_string()),
            "local": self.local.map(|a| a.to_string()),
            "ttl": self.ttl,
            "key": self.key,
            "ifindex": self.ifindex,
        })
    }
}

/// Extract tunnel info from link_data bytes.
fn extract_tunnel_info(
    kind: &str,
    data: &[u8],
) -> (Option<Ipv4Addr>, Option<Ipv4Addr>, Option<u8>, Option<u32>) {
    let mut remote = None;
    let mut local = None;
    let mut ttl = None;
    let mut key = None;

    for (attr_type, attr_data) in AttrIter::new(data) {
        if kind == "gre" || kind == "gretap" {
            match attr_type {
                t if t == gre_attrs::IFLA_GRE_REMOTE => {
                    if attr_data.len() >= 4 {
                        let bytes: [u8; 4] = attr_data[..4].try_into().unwrap();
                        remote = Some(Ipv4Addr::from(bytes));
                    }
                }
                t if t == gre_attrs::IFLA_GRE_LOCAL => {
                    if attr_data.len() >= 4 {
                        let bytes: [u8; 4] = attr_data[..4].try_into().unwrap();
                        local = Some(Ipv4Addr::from(bytes));
                    }
                }
                t if t == gre_attrs::IFLA_GRE_TTL => {
                    if !attr_data.is_empty() {
                        ttl = Some(attr_data[0]);
                    }
                }
                t if t == gre_attrs::IFLA_GRE_IKEY => {
                    if attr_data.len() >= 4 {
                        let bytes: [u8; 4] = attr_data[..4].try_into().unwrap();
                        key = Some(u32::from_be_bytes(bytes));
                    }
                }
                _ => {}
            }
        } else {
            // IPIP/SIT/VTI
            match attr_type {
                t if t == iptun_attrs::IFLA_IPTUN_REMOTE => {
                    if attr_data.len() >= 4 {
                        let bytes: [u8; 4] = attr_data[..4].try_into().unwrap();
                        remote = Some(Ipv4Addr::from(bytes));
                    }
                }
                t if t == iptun_attrs::IFLA_IPTUN_LOCAL => {
                    if attr_data.len() >= 4 {
                        let bytes: [u8; 4] = attr_data[..4].try_into().unwrap();
                        local = Some(Ipv4Addr::from(bytes));
                    }
                }
                t if t == iptun_attrs::IFLA_IPTUN_TTL => {
                    if !attr_data.is_empty() {
                        ttl = Some(attr_data[0]);
                    }
                }
                _ => {}
            }
        }
    }

    (remote, local, ttl, key)
}
