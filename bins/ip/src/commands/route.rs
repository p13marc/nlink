//! ip route command implementation.

use clap::{Args, Subcommand};
use rip_netlink::attr::{AttrIter, get};
use rip_netlink::message::{NLMSG_HDRLEN, NlMsgHdr, NlMsgType};
use rip_netlink::types::route::{RouteProtocol, RouteScope, RouteType, RtMsg, RtaAttr};
use rip_netlink::{Connection, MessageBuilder, Result, connection::dump_request};
use rip_output::{OutputFormat, OutputOptions};
use std::io::{self, Write};

#[derive(Args)]
pub struct RouteCmd {
    #[command(subcommand)]
    action: Option<RouteAction>,
}

#[derive(Subcommand)]
enum RouteAction {
    /// Show routes.
    Show {
        /// Routing table (main, local, etc.).
        #[arg(long, default_value = "main")]
        table: String,
    },

    /// Add a route.
    Add {
        /// Destination prefix (e.g., 10.0.0.0/8 or default).
        destination: String,

        /// Gateway address.
        #[arg(long, short)]
        via: Option<String>,

        /// Output device.
        #[arg(long, short)]
        dev: Option<String>,

        /// Routing table.
        #[arg(long, default_value = "main")]
        table: String,

        /// Route metric/priority.
        #[arg(long)]
        metric: Option<u32>,
    },

    /// Delete a route.
    Del {
        /// Destination prefix.
        destination: String,

        /// Routing table.
        #[arg(long, default_value = "main")]
        table: String,
    },

    /// Get route for a destination.
    Get {
        /// Destination address.
        destination: String,
    },
}

impl RouteCmd {
    pub async fn run(
        self,
        conn: &Connection,
        format: OutputFormat,
        opts: &OutputOptions,
        family: Option<u8>,
    ) -> Result<()> {
        match self.action.unwrap_or(RouteAction::Show {
            table: "main".into(),
        }) {
            RouteAction::Show { table } => Self::show(conn, &table, format, opts, family).await,
            RouteAction::Add {
                destination,
                via,
                dev,
                table,
                metric,
            } => {
                Self::add(
                    conn,
                    &destination,
                    via.as_deref(),
                    dev.as_deref(),
                    &table,
                    metric,
                )
                .await
            }
            RouteAction::Del { destination, table } => Self::del(conn, &destination, &table).await,
            RouteAction::Get { destination } => Self::get(conn, &destination, format, opts).await,
        }
    }

    async fn show(
        conn: &Connection,
        table: &str,
        format: OutputFormat,
        opts: &OutputOptions,
        family: Option<u8>,
    ) -> Result<()> {
        let table_id = rip_lib::names::table_id(table).unwrap_or(254); // main

        // Build request
        let mut builder = dump_request(NlMsgType::RTM_GETROUTE);
        let rtmsg = RtMsg::new()
            .with_family(family.unwrap_or(0))
            .with_table(if table_id <= 255 { table_id as u8 } else { 0 });
        builder.append(&rtmsg);

        // For table IDs > 255, add RTA_TABLE attribute
        if table_id > 255 {
            builder.append_attr_u32(RtaAttr::Table as u16, table_id);
        }

        // Send and receive
        let responses = conn.dump(builder).await?;

        let mut stdout = io::stdout().lock();
        let mut routes = Vec::new();

        for response in &responses {
            if let Some(route) = parse_route_message(response)? {
                // Filter by table
                if route.table != table_id {
                    continue;
                }
                // Filter by family
                if let Some(fam) = family {
                    if route.family != fam {
                        continue;
                    }
                }
                routes.push(route);
            }
        }

        match format {
            OutputFormat::Text => {
                for route in &routes {
                    print_route_text(&mut stdout, route, opts)?;
                }
            }
            OutputFormat::Json => {
                let json: Vec<_> = routes.iter().map(|r| r.to_json()).collect();
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

    async fn add(
        conn: &Connection,
        destination: &str,
        via: Option<&str>,
        dev: Option<&str>,
        table: &str,
        metric: Option<u32>,
    ) -> Result<()> {
        use rip_lib::addr::parse_prefix;
        use rip_netlink::connection::ack_request;

        let table_id = rip_lib::names::table_id(table).unwrap_or(254);

        // Parse destination
        let (dst_addr, dst_len, family) = if destination == "default" {
            (
                None,
                0u8,
                via.map(|v| if v.contains(':') { 10u8 } else { 2u8 })
                    .unwrap_or(2),
            )
        } else {
            let (addr, prefix) = parse_prefix(destination).map_err(|e| {
                rip_netlink::Error::InvalidMessage(format!("invalid destination: {}", e))
            })?;
            let family = if addr.is_ipv4() { 2u8 } else { 10u8 };
            (Some(addr), prefix, family)
        };

        let rtmsg = RtMsg::new()
            .with_family(family)
            .with_dst_len(dst_len)
            .with_table(if table_id <= 255 { table_id as u8 } else { 0 })
            .with_protocol(4) // RTPROT_STATIC
            .with_scope(if via.is_some() { 0 } else { 253 }) // universe or link
            .with_type(1); // RTN_UNICAST

        let mut builder = ack_request(NlMsgType::RTM_NEWROUTE);
        builder.append(&rtmsg);

        // Add destination
        if let Some(addr) = dst_addr {
            match addr {
                std::net::IpAddr::V4(v4) => {
                    builder.append_attr(RtaAttr::Dst as u16, &v4.octets());
                }
                std::net::IpAddr::V6(v6) => {
                    builder.append_attr(RtaAttr::Dst as u16, &v6.octets());
                }
            }
        }

        // Add gateway
        if let Some(gw) = via {
            let gw_addr: std::net::IpAddr = gw.parse().map_err(|_| {
                rip_netlink::Error::InvalidMessage(format!("invalid gateway: {}", gw))
            })?;
            match gw_addr {
                std::net::IpAddr::V4(v4) => {
                    builder.append_attr(RtaAttr::Gateway as u16, &v4.octets());
                }
                std::net::IpAddr::V6(v6) => {
                    builder.append_attr(RtaAttr::Gateway as u16, &v6.octets());
                }
            }
        }

        // Add output interface
        if let Some(dev_name) = dev {
            let ifindex = rip_lib::ifname::name_to_index(dev_name).map_err(|e| {
                rip_netlink::Error::InvalidMessage(format!("interface not found: {}", e))
            })?;
            builder.append_attr_u32(RtaAttr::Oif as u16, ifindex);
        }

        // Add table if > 255
        if table_id > 255 {
            builder.append_attr_u32(RtaAttr::Table as u16, table_id);
        }

        // Add metric
        if let Some(m) = metric {
            builder.append_attr_u32(RtaAttr::Priority as u16, m);
        }

        conn.request_ack(builder).await?;

        Ok(())
    }

    async fn del(conn: &Connection, destination: &str, table: &str) -> Result<()> {
        use rip_lib::addr::parse_prefix;
        use rip_netlink::connection::ack_request;

        let table_id = rip_lib::names::table_id(table).unwrap_or(254);

        // Parse destination
        let (dst_addr, dst_len, family) = if destination == "default" {
            (None, 0u8, 2u8) // Assume IPv4 for default
        } else {
            let (addr, prefix) = parse_prefix(destination).map_err(|e| {
                rip_netlink::Error::InvalidMessage(format!("invalid destination: {}", e))
            })?;
            let family = if addr.is_ipv4() { 2u8 } else { 10u8 };
            (Some(addr), prefix, family)
        };

        let rtmsg = RtMsg::new()
            .with_family(family)
            .with_dst_len(dst_len)
            .with_table(if table_id <= 255 { table_id as u8 } else { 0 });

        let mut builder = ack_request(NlMsgType::RTM_DELROUTE);
        builder.append(&rtmsg);

        // Add destination
        if let Some(addr) = dst_addr {
            match addr {
                std::net::IpAddr::V4(v4) => {
                    builder.append_attr(RtaAttr::Dst as u16, &v4.octets());
                }
                std::net::IpAddr::V6(v6) => {
                    builder.append_attr(RtaAttr::Dst as u16, &v6.octets());
                }
            }
        }

        // Add table if > 255
        if table_id > 255 {
            builder.append_attr_u32(RtaAttr::Table as u16, table_id);
        }

        conn.request_ack(builder).await?;

        Ok(())
    }

    async fn get(
        _conn: &Connection,
        _destination: &str,
        _format: OutputFormat,
        _opts: &OutputOptions,
    ) -> Result<()> {
        // TODO: Implement route get
        Err(rip_netlink::Error::NotSupported(
            "route get not yet implemented".into(),
        ))
    }
}

/// Parsed route information.
#[derive(Debug)]
struct RouteInfo {
    family: u8,
    dst_len: u8,
    route_type: RouteType,
    protocol: RouteProtocol,
    scope: RouteScope,
    table: u32,
    destination: Option<String>,
    gateway: Option<String>,
    oif: Option<u32>,
    prefsrc: Option<String>,
    priority: Option<u32>,
}

impl RouteInfo {
    fn to_json(&self) -> serde_json::Value {
        let mut obj = serde_json::json!({
            "type": self.route_type.name(),
            "protocol": self.protocol.name(),
            "scope": self.scope.name(),
            "table": rip_lib::names::table_name(self.table),
        });

        if let Some(ref dst) = self.destination {
            obj["dst"] = serde_json::json!(format!("{}/{}", dst, self.dst_len));
        } else {
            obj["dst"] = serde_json::json!("default");
        }

        if let Some(ref gw) = self.gateway {
            obj["gateway"] = serde_json::json!(gw);
        }

        if let Some(oif) = self.oif {
            let dev = rip_lib::ifname::index_to_name(oif).unwrap_or_else(|_| format!("if{}", oif));
            obj["dev"] = serde_json::json!(dev);
        }

        if let Some(ref src) = self.prefsrc {
            obj["prefsrc"] = serde_json::json!(src);
        }

        if let Some(prio) = self.priority {
            obj["metric"] = serde_json::json!(prio);
        }

        obj
    }
}

fn parse_route_message(data: &[u8]) -> Result<Option<RouteInfo>> {
    if data.len() < NLMSG_HDRLEN + RtMsg::SIZE {
        return Ok(None);
    }

    let header = NlMsgHdr::from_bytes(data)?;

    // Skip non-route messages
    if header.nlmsg_type != NlMsgType::RTM_NEWROUTE {
        return Ok(None);
    }

    let payload = &data[NLMSG_HDRLEN..];
    let rtmsg = RtMsg::from_bytes(payload)?;
    let attrs_data = &payload[RtMsg::SIZE..];

    let mut destination = None;
    let mut gateway = None;
    let mut oif = None;
    let mut prefsrc = None;
    let mut priority = None;
    let mut table = rtmsg.rtm_table as u32;

    for (attr_type, attr_data) in AttrIter::new(attrs_data) {
        match RtaAttr::from(attr_type) {
            RtaAttr::Dst => {
                destination = rip_lib::addr::format_addr_bytes(attr_data, rtmsg.rtm_family);
            }
            RtaAttr::Gateway => {
                gateway = rip_lib::addr::format_addr_bytes(attr_data, rtmsg.rtm_family);
            }
            RtaAttr::Oif => {
                oif = Some(get::u32_ne(attr_data).unwrap_or(0));
            }
            RtaAttr::Prefsrc => {
                prefsrc = rip_lib::addr::format_addr_bytes(attr_data, rtmsg.rtm_family);
            }
            RtaAttr::Priority => {
                priority = Some(get::u32_ne(attr_data).unwrap_or(0));
            }
            RtaAttr::Table => {
                table = get::u32_ne(attr_data).unwrap_or(table);
            }
            _ => {}
        }
    }

    Ok(Some(RouteInfo {
        family: rtmsg.rtm_family,
        dst_len: rtmsg.rtm_dst_len,
        route_type: RouteType::from(rtmsg.rtm_type),
        protocol: RouteProtocol::from(rtmsg.rtm_protocol),
        scope: RouteScope::from(rtmsg.rtm_scope),
        table,
        destination,
        gateway,
        oif,
        prefsrc,
        priority,
    }))
}

fn print_route_text<W: Write>(
    w: &mut W,
    route: &RouteInfo,
    _opts: &OutputOptions,
) -> io::Result<()> {
    // Destination
    if let Some(ref dst) = route.destination {
        write!(w, "{}/{}", dst, route.dst_len)?;
    } else {
        write!(w, "default")?;
    }

    // Gateway
    if let Some(ref gw) = route.gateway {
        write!(w, " via {}", gw)?;
    }

    // Device
    if let Some(oif) = route.oif {
        let dev = rip_lib::ifname::index_to_name(oif).unwrap_or_else(|_| format!("if{}", oif));
        write!(w, " dev {}", dev)?;
    }

    // Protocol
    if route.protocol != RouteProtocol::Unspec {
        write!(w, " proto {}", route.protocol.name())?;
    }

    // Scope
    if route.scope != RouteScope::Universe {
        write!(w, " scope {}", route.scope.name())?;
    }

    // Preferred source
    if let Some(ref src) = route.prefsrc {
        write!(w, " src {}", src)?;
    }

    // Metric
    if let Some(prio) = route.priority {
        write!(w, " metric {}", prio)?;
    }

    writeln!(w)?;

    Ok(())
}
