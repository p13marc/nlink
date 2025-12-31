//! ip tunnel command implementation.
//!
//! Tunnel management for GRE, IPIP, SIT, and VTI tunnels.
//! This provides a traditional iproute2-style interface for tunnel operations.
//!
//! Modern tunnels are created via `ip link add type <type>`, but this command
//! provides compatibility with the classic `ip tunnel` syntax.

use clap::{Args, Subcommand};
use rip_netlink::attr::AttrIter;
use rip_netlink::connection::dump_request;
use rip_netlink::message::{NLMSG_HDRLEN, NlMsgType};
use rip_netlink::types::link::{IfInfoMsg, IflaAttr, IflaInfo};
use rip_netlink::{Connection, MessageBuilder, Result};
use rip_output::{OutputFormat, OutputOptions};
use std::io::{self, Write};
use std::net::Ipv4Addr;

/// IFLA_GRE_* attribute constants
mod gre_attrs {
    pub const IFLA_GRE_IFLAGS: u16 = 2;
    pub const IFLA_GRE_OFLAGS: u16 = 3;
    pub const IFLA_GRE_IKEY: u16 = 4;
    pub const IFLA_GRE_OKEY: u16 = 5;
    pub const IFLA_GRE_LOCAL: u16 = 6;
    pub const IFLA_GRE_REMOTE: u16 = 7;
    pub const IFLA_GRE_TTL: u16 = 8;
    pub const IFLA_GRE_TOS: u16 = 9;
    pub const IFLA_GRE_PMTUDISC: u16 = 10;
}

/// IFLA_IPTUN_* attribute constants (for ipip/sit)
mod iptun_attrs {
    pub const IFLA_IPTUN_LOCAL: u16 = 2;
    pub const IFLA_IPTUN_REMOTE: u16 = 3;
    pub const IFLA_IPTUN_TTL: u16 = 4;
    pub const IFLA_IPTUN_TOS: u16 = 5;
    pub const IFLA_IPTUN_PMTUDISC: u16 = 8;
}

/// GRE flag constants
const GRE_KEY: u16 = 0x2000;

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
        conn: &Connection,
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
        conn: &Connection,
        name_filter: Option<&str>,
        mode_filter: Option<&str>,
        format: OutputFormat,
        _opts: &OutputOptions,
    ) -> Result<()> {
        // Get all links and filter for tunnel types
        let mut builder = dump_request(NlMsgType::RTM_GETLINK);
        let ifinfo = IfInfoMsg::new();
        builder.append(&ifinfo);

        let responses = conn.dump(builder).await?;

        let mut tunnels = Vec::new();

        for response in &responses {
            if response.len() < NLMSG_HDRLEN + std::mem::size_of::<IfInfoMsg>() {
                continue;
            }

            let payload = &response[NLMSG_HDRLEN..];
            if let Some(tunnel) = parse_tunnel_link(payload) {
                // Apply filters
                if let Some(name) = name_filter
                    && tunnel.name != name
                {
                    continue;
                }
                if let Some(mode) = mode_filter
                    && tunnel.mode != mode
                {
                    continue;
                }
                tunnels.push(tunnel);
            }
        }

        let mut stdout = io::stdout().lock();

        match format {
            OutputFormat::Json => {
                let json: Vec<_> = tunnels.iter().map(|t| t.to_json()).collect();
                serde_json::to_writer(&mut stdout, &json)?;
                writeln!(stdout)?;
            }
            OutputFormat::Text => {
                for tunnel in &tunnels {
                    print_tunnel_text(&mut stdout, tunnel)?;
                }
            }
        }

        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    async fn add_tunnel(
        &self,
        conn: &Connection,
        name: &str,
        mode: &str,
        remote: &str,
        local: Option<&str>,
        ttl: Option<u8>,
        tos: Option<u8>,
        key: Option<u32>,
        ikey: Option<u32>,
        okey: Option<u32>,
        _pmtudisc: bool,
        nopmtudisc: bool,
        _dev: Option<&str>,
    ) -> Result<()> {
        // Validate mode
        let kind = match mode.to_lowercase().as_str() {
            "gre" => "gre",
            "gretap" => "gretap",
            "ipip" | "ip/ip" => "ipip",
            "sit" | "ipv6/ip" => "sit",
            "vti" => "vti",
            "ip6gre" => "ip6gre",
            "ip6tnl" => "ip6tnl",
            _ => {
                return Err(rip_netlink::Error::InvalidMessage(format!(
                    "unknown tunnel mode '{}', supported: gre, gretap, ipip, sit, vti",
                    mode
                )));
            }
        };

        // Parse addresses
        let remote_addr: Ipv4Addr = remote.parse().map_err(|_| {
            rip_netlink::Error::InvalidMessage(format!("invalid remote address: {}", remote))
        })?;

        let local_addr: Option<Ipv4Addr> = if let Some(l) = local {
            Some(l.parse().map_err(|_| {
                rip_netlink::Error::InvalidMessage(format!("invalid local address: {}", l))
            })?)
        } else {
            None
        };

        // Build netlink message
        let mut builder = MessageBuilder::new(
            NlMsgType::RTM_NEWLINK,
            rip_netlink::message::NLM_F_REQUEST
                | rip_netlink::message::NLM_F_ACK
                | rip_netlink::message::NLM_F_CREATE
                | rip_netlink::message::NLM_F_EXCL,
        );

        let ifinfo = IfInfoMsg::new();
        builder.append(&ifinfo);

        // Interface name
        let name_bytes: Vec<u8> = name.bytes().chain(std::iter::once(0)).collect();
        builder.append_attr(IflaAttr::Ifname as u16, &name_bytes);

        // IFLA_LINKINFO nested attribute
        let linkinfo = builder.nest_start(IflaAttr::Linkinfo as u16);

        // IFLA_INFO_KIND
        let kind_bytes: Vec<u8> = kind.bytes().chain(std::iter::once(0)).collect();
        builder.append_attr(IflaInfo::Kind as u16, &kind_bytes);

        // IFLA_INFO_DATA with tunnel-specific attributes
        let info_data = builder.nest_start(IflaInfo::Data as u16);

        if kind == "gre" || kind == "gretap" {
            // GRE attributes
            builder.append_attr(gre_attrs::IFLA_GRE_REMOTE, &remote_addr.octets());

            if let Some(local) = local_addr {
                builder.append_attr(gre_attrs::IFLA_GRE_LOCAL, &local.octets());
            }

            if let Some(t) = ttl {
                builder.append_attr(gre_attrs::IFLA_GRE_TTL, &[t]);
            }

            if let Some(t) = tos {
                builder.append_attr(gre_attrs::IFLA_GRE_TOS, &[t]);
            }

            // Handle keys
            let effective_ikey = ikey.or(key);
            let effective_okey = okey.or(key);

            if let Some(k) = effective_ikey {
                builder.append_attr(gre_attrs::IFLA_GRE_IKEY, &k.to_be_bytes());
                builder.append_attr(gre_attrs::IFLA_GRE_IFLAGS, &GRE_KEY.to_be_bytes());
            }

            if let Some(k) = effective_okey {
                builder.append_attr(gre_attrs::IFLA_GRE_OKEY, &k.to_be_bytes());
                builder.append_attr(gre_attrs::IFLA_GRE_OFLAGS, &GRE_KEY.to_be_bytes());
            }

            // PMTU discovery (1 = enabled by default, 0 = disabled)
            let pmtu: u8 = if nopmtudisc { 0 } else { 1 };
            builder.append_attr(gre_attrs::IFLA_GRE_PMTUDISC, &[pmtu]);
        } else {
            // IPIP/SIT attributes
            builder.append_attr(iptun_attrs::IFLA_IPTUN_REMOTE, &remote_addr.octets());

            if let Some(local) = local_addr {
                builder.append_attr(iptun_attrs::IFLA_IPTUN_LOCAL, &local.octets());
            }

            if let Some(t) = ttl {
                builder.append_attr(iptun_attrs::IFLA_IPTUN_TTL, &[t]);
            }

            if let Some(t) = tos {
                builder.append_attr(iptun_attrs::IFLA_IPTUN_TOS, &[t]);
            }

            let pmtu: u8 = if nopmtudisc { 0 } else { 1 };
            builder.append_attr(iptun_attrs::IFLA_IPTUN_PMTUDISC, &[pmtu]);
        }

        builder.nest_end(info_data);
        builder.nest_end(linkinfo);

        conn.request(builder).await?;

        println!("Tunnel '{}' created", name);
        Ok(())
    }

    async fn delete_tunnel(&self, conn: &Connection, name: &str) -> Result<()> {
        // Get interface index
        let ifindex = rip_lib::get_ifindex(name).map_err(|_| {
            rip_netlink::Error::InvalidMessage(format!("tunnel '{}' not found", name))
        })? as u32;

        // Build delete message
        let mut builder = MessageBuilder::new(
            NlMsgType::RTM_DELLINK,
            rip_netlink::message::NLM_F_REQUEST | rip_netlink::message::NLM_F_ACK,
        );

        let mut ifinfo = IfInfoMsg::new();
        ifinfo.ifi_index = ifindex as i32;
        builder.append(&ifinfo);

        conn.request(builder).await?;

        println!("Tunnel '{}' deleted", name);
        Ok(())
    }

    async fn change_tunnel(
        &self,
        conn: &Connection,
        name: &str,
        remote: Option<&str>,
        local: Option<&str>,
        ttl: Option<u8>,
        key: Option<u32>,
    ) -> Result<()> {
        // Get interface index
        let ifindex = rip_lib::get_ifindex(name).map_err(|_| {
            rip_netlink::Error::InvalidMessage(format!("tunnel '{}' not found", name))
        })? as u32;

        // Build change message
        let mut builder = MessageBuilder::new(
            NlMsgType::RTM_NEWLINK,
            rip_netlink::message::NLM_F_REQUEST | rip_netlink::message::NLM_F_ACK,
        );

        let mut ifinfo = IfInfoMsg::new();
        ifinfo.ifi_index = ifindex as i32;
        builder.append(&ifinfo);

        // We need to know the tunnel type to set the right attributes
        // For now, assume GRE-style attributes
        let linkinfo = builder.nest_start(IflaAttr::Linkinfo as u16);
        let info_data = builder.nest_start(IflaInfo::Data as u16);

        if let Some(r) = remote {
            let addr: Ipv4Addr = r.parse().map_err(|_| {
                rip_netlink::Error::InvalidMessage(format!("invalid remote address: {}", r))
            })?;
            builder.append_attr(gre_attrs::IFLA_GRE_REMOTE, &addr.octets());
        }

        if let Some(l) = local {
            let addr: Ipv4Addr = l.parse().map_err(|_| {
                rip_netlink::Error::InvalidMessage(format!("invalid local address: {}", l))
            })?;
            builder.append_attr(gre_attrs::IFLA_GRE_LOCAL, &addr.octets());
        }

        if let Some(t) = ttl {
            builder.append_attr(gre_attrs::IFLA_GRE_TTL, &[t]);
        }

        if let Some(k) = key {
            builder.append_attr(gre_attrs::IFLA_GRE_IKEY, &k.to_be_bytes());
            builder.append_attr(gre_attrs::IFLA_GRE_OKEY, &k.to_be_bytes());
            builder.append_attr(gre_attrs::IFLA_GRE_IFLAGS, &GRE_KEY.to_be_bytes());
            builder.append_attr(gre_attrs::IFLA_GRE_OFLAGS, &GRE_KEY.to_be_bytes());
        }

        builder.nest_end(info_data);
        builder.nest_end(linkinfo);

        conn.request(builder).await?;

        println!("Tunnel '{}' changed", name);
        Ok(())
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
    ifindex: i32,
}

impl TunnelInfo {
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

/// Parse a link message and extract tunnel info if it's a tunnel.
fn parse_tunnel_link(payload: &[u8]) -> Option<TunnelInfo> {
    if payload.len() < std::mem::size_of::<IfInfoMsg>() {
        return None;
    }

    let ifinfo = unsafe { &*(payload.as_ptr() as *const IfInfoMsg) };
    let attrs_data = &payload[std::mem::size_of::<IfInfoMsg>()..];

    let mut name = None;
    let mut kind = None;
    let mut remote = None;
    let mut local = None;
    let mut ttl = None;
    let mut key = None;

    for (attr_type, attr_data) in AttrIter::new(attrs_data) {
        match attr_type {
            a if a == IflaAttr::Ifname as u16 => {
                if let Ok(s) = std::str::from_utf8(attr_data) {
                    name = Some(s.trim_end_matches('\0').to_string());
                }
            }
            a if a == IflaAttr::Linkinfo as u16 => {
                // Parse nested IFLA_LINKINFO
                for (info_type, info_data) in AttrIter::new(attr_data) {
                    match info_type {
                        t if t == IflaInfo::Kind as u16 => {
                            if let Ok(s) = std::str::from_utf8(info_data) {
                                kind = Some(s.trim_end_matches('\0').to_string());
                            }
                        }
                        t if t == IflaInfo::Data as u16 => {
                            // Parse tunnel-specific data based on kind
                            if let Some(ref k) = kind {
                                parse_tunnel_data(
                                    k,
                                    info_data,
                                    &mut remote,
                                    &mut local,
                                    &mut ttl,
                                    &mut key,
                                );
                            }
                        }
                        _ => {}
                    }
                }
            }
            _ => {}
        }
    }

    // Only return if this is a known tunnel type
    let kind = kind?;
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
    if !tunnel_modes.contains(&kind.as_str()) {
        return None;
    }

    Some(TunnelInfo {
        name: name.unwrap_or_default(),
        mode: kind,
        remote,
        local,
        ttl,
        key,
        ifindex: ifinfo.ifi_index,
    })
}

/// Parse tunnel-specific data attributes.
fn parse_tunnel_data(
    kind: &str,
    data: &[u8],
    remote: &mut Option<Ipv4Addr>,
    local: &mut Option<Ipv4Addr>,
    ttl: &mut Option<u8>,
    key: &mut Option<u32>,
) {
    for (attr_type, attr_data) in AttrIter::new(data) {
        if kind == "gre" || kind == "gretap" {
            match attr_type {
                t if t == gre_attrs::IFLA_GRE_REMOTE => {
                    if attr_data.len() >= 4 {
                        let bytes: [u8; 4] = attr_data[..4].try_into().unwrap();
                        *remote = Some(Ipv4Addr::from(bytes));
                    }
                }
                t if t == gre_attrs::IFLA_GRE_LOCAL => {
                    if attr_data.len() >= 4 {
                        let bytes: [u8; 4] = attr_data[..4].try_into().unwrap();
                        *local = Some(Ipv4Addr::from(bytes));
                    }
                }
                t if t == gre_attrs::IFLA_GRE_TTL => {
                    if !attr_data.is_empty() {
                        *ttl = Some(attr_data[0]);
                    }
                }
                t if t == gre_attrs::IFLA_GRE_IKEY => {
                    if attr_data.len() >= 4 {
                        let bytes: [u8; 4] = attr_data[..4].try_into().unwrap();
                        *key = Some(u32::from_be_bytes(bytes));
                    }
                }
                _ => {}
            }
        } else {
            // IPIP/SIT
            match attr_type {
                t if t == iptun_attrs::IFLA_IPTUN_REMOTE => {
                    if attr_data.len() >= 4 {
                        let bytes: [u8; 4] = attr_data[..4].try_into().unwrap();
                        *remote = Some(Ipv4Addr::from(bytes));
                    }
                }
                t if t == iptun_attrs::IFLA_IPTUN_LOCAL => {
                    if attr_data.len() >= 4 {
                        let bytes: [u8; 4] = attr_data[..4].try_into().unwrap();
                        *local = Some(Ipv4Addr::from(bytes));
                    }
                }
                t if t == iptun_attrs::IFLA_IPTUN_TTL => {
                    if !attr_data.is_empty() {
                        *ttl = Some(attr_data[0]);
                    }
                }
                _ => {}
            }
        }
    }
}

/// Print tunnel info in text format.
fn print_tunnel_text(w: &mut impl Write, tunnel: &TunnelInfo) -> Result<()> {
    write!(w, "{}: {}/ip", tunnel.name, tunnel.mode)?;

    write!(
        w,
        " remote {}",
        tunnel
            .remote
            .map(|a| a.to_string())
            .unwrap_or_else(|| "any".to_string())
    )?;

    write!(
        w,
        " local {}",
        tunnel
            .local
            .map(|a| a.to_string())
            .unwrap_or_else(|| "any".to_string())
    )?;

    if let Some(ttl) = tunnel.ttl {
        if ttl > 0 {
            write!(w, " ttl {}", ttl)?;
        } else {
            write!(w, " ttl inherit")?;
        }
    }

    if let Some(key) = tunnel.key {
        write!(w, " key {}", key)?;
    }

    writeln!(w)?;

    Ok(())
}
