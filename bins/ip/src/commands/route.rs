//! ip route command implementation.
//!
//! This module uses the strongly-typed RouteMessage API from rip-netlink.

use clap::{Args, Subcommand};
use rip::netlink::message::NlMsgType;
use rip::netlink::messages::RouteMessage;
use rip::netlink::types::route::{RouteScope, RtMsg, RtaAttr};
use rip::netlink::{Connection, Result, connection::dump_request};
use rip::output::{OutputFormat, OutputOptions, print_all};
use std::net::IpAddr;

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

        /// Preferred source address.
        #[arg(long)]
        src: Option<String>,

        /// Route scope (global, link, host).
        #[arg(long)]
        scope: Option<String>,

        /// MTU for route.
        #[arg(long)]
        mtu: Option<u32>,
    },

    /// Replace a route (add or update).
    Replace {
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

        /// Preferred source address.
        #[arg(long)]
        src: Option<String>,
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
                src,
                scope,
                mtu,
            } => {
                Self::add(
                    conn,
                    &destination,
                    via.as_deref(),
                    dev.as_deref(),
                    &table,
                    metric,
                    src.as_deref(),
                    scope.as_deref(),
                    mtu,
                    false,
                )
                .await
            }
            RouteAction::Replace {
                destination,
                via,
                dev,
                table,
                metric,
                src,
            } => {
                Self::add(
                    conn,
                    &destination,
                    via.as_deref(),
                    dev.as_deref(),
                    &table,
                    metric,
                    src.as_deref(),
                    None,
                    None,
                    true,
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
        let table_id = rip::util::names::table_id(table).unwrap_or(254); // main

        // Use the strongly-typed API to get all routes
        // Note: We need to build a custom request with family/table filter
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

        // Parse responses into typed RouteMessage
        let mut routes = Vec::new();
        for response in &responses {
            use rip::netlink::message::NLMSG_HDRLEN;
            use rip::netlink::parse::FromNetlink;

            if response.len() < NLMSG_HDRLEN + RtMsg::SIZE {
                continue;
            }

            let payload = &response[NLMSG_HDRLEN..];
            if let Ok(route) = RouteMessage::from_bytes(payload) {
                // Filter by table
                if route.table_id() != table_id {
                    continue;
                }
                // Filter by family
                if let Some(fam) = family
                    && route.family() != fam
                {
                    continue;
                }
                routes.push(route);
            }
        }

        print_all(&routes, format, opts)?;

        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    async fn add(
        conn: &Connection,
        destination: &str,
        via: Option<&str>,
        dev: Option<&str>,
        table: &str,
        metric: Option<u32>,
        src: Option<&str>,
        scope: Option<&str>,
        mtu: Option<u32>,
        replace: bool,
    ) -> Result<()> {
        use rip::util::addr::parse_prefix;
        use rip::netlink::connection::{ack_request, replace_request};

        let table_id = rip::util::names::table_id(table).unwrap_or(254);

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
                rip::netlink::Error::InvalidMessage(format!("invalid destination: {}", e))
            })?;
            let family = if addr.is_ipv4() { 2u8 } else { 10u8 };
            (Some(addr), prefix, family)
        };

        // Parse scope
        let scope_val = if let Some(s) = scope {
            RouteScope::from_name(s).map(|sc| sc as u8).unwrap_or(0)
        } else if via.is_some() {
            0 // RT_SCOPE_UNIVERSE
        } else {
            253 // RT_SCOPE_LINK
        };

        let rtmsg = RtMsg::new()
            .with_family(family)
            .with_dst_len(dst_len)
            .with_table(if table_id <= 255 { table_id as u8 } else { 0 })
            .with_protocol(4) // RTPROT_STATIC
            .with_scope(scope_val)
            .with_type(1); // RTN_UNICAST

        let mut builder = if replace {
            replace_request(NlMsgType::RTM_NEWROUTE)
        } else {
            ack_request(NlMsgType::RTM_NEWROUTE)
        };
        builder.append(&rtmsg);

        // Add destination
        if let Some(addr) = dst_addr {
            match addr {
                IpAddr::V4(v4) => {
                    builder.append_attr(RtaAttr::Dst as u16, &v4.octets());
                }
                IpAddr::V6(v6) => {
                    builder.append_attr(RtaAttr::Dst as u16, &v6.octets());
                }
            }
        }

        // Add gateway
        if let Some(gw) = via {
            let gw_addr: IpAddr = gw.parse().map_err(|_| {
                rip::netlink::Error::InvalidMessage(format!("invalid gateway: {}", gw))
            })?;
            match gw_addr {
                IpAddr::V4(v4) => {
                    builder.append_attr(RtaAttr::Gateway as u16, &v4.octets());
                }
                IpAddr::V6(v6) => {
                    builder.append_attr(RtaAttr::Gateway as u16, &v6.octets());
                }
            }
        }

        // Add output interface
        if let Some(dev_name) = dev {
            let ifindex =
                rip::util::get_ifindex(dev_name).map_err(rip::netlink::Error::InvalidMessage)? as u32;
            builder.append_attr_u32(RtaAttr::Oif as u16, ifindex);
        }

        // Add preferred source
        if let Some(src_str) = src {
            let src_addr: IpAddr = src_str.parse().map_err(|_| {
                rip::netlink::Error::InvalidMessage(format!("invalid source: {}", src_str))
            })?;
            match src_addr {
                IpAddr::V4(v4) => {
                    builder.append_attr(RtaAttr::Prefsrc as u16, &v4.octets());
                }
                IpAddr::V6(v6) => {
                    builder.append_attr(RtaAttr::Prefsrc as u16, &v6.octets());
                }
            }
        }

        // Add table if > 255
        if table_id > 255 {
            builder.append_attr_u32(RtaAttr::Table as u16, table_id);
        }

        // Add metric
        if let Some(m) = metric {
            builder.append_attr_u32(RtaAttr::Priority as u16, m);
        }

        // Add MTU via RTA_METRICS
        if let Some(mtu_val) = mtu {
            let metrics = builder.nest_start(RtaAttr::Metrics as u16);
            // RTAX_MTU = 2
            builder.append_attr_u32(2, mtu_val);
            builder.nest_end(metrics);
        }

        conn.request_ack(builder).await?;

        Ok(())
    }

    async fn del(conn: &Connection, destination: &str, table: &str) -> Result<()> {
        use rip::util::addr::parse_prefix;
        use rip::netlink::connection::ack_request;

        let table_id = rip::util::names::table_id(table).unwrap_or(254);

        // Parse destination
        let (dst_addr, dst_len, family) = if destination == "default" {
            (None, 0u8, 2u8) // Assume IPv4 for default
        } else {
            let (addr, prefix) = parse_prefix(destination).map_err(|e| {
                rip::netlink::Error::InvalidMessage(format!("invalid destination: {}", e))
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
                IpAddr::V4(v4) => {
                    builder.append_attr(RtaAttr::Dst as u16, &v4.octets());
                }
                IpAddr::V6(v6) => {
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
        conn: &Connection,
        destination: &str,
        format: OutputFormat,
        opts: &OutputOptions,
    ) -> Result<()> {
        use rip::netlink::connection::ack_request;
        use rip::netlink::message::NLMSG_HDRLEN;
        use rip::netlink::parse::FromNetlink;

        // Parse destination address
        let dst_addr: IpAddr = destination.parse().map_err(|_| {
            rip::netlink::Error::InvalidMessage(format!("invalid destination: {}", destination))
        })?;

        let family = if dst_addr.is_ipv4() { 2u8 } else { 10u8 };
        let dst_len = if dst_addr.is_ipv4() { 32u8 } else { 128u8 };

        let rtmsg = RtMsg::new().with_family(family).with_dst_len(dst_len);

        let mut builder = ack_request(NlMsgType::RTM_GETROUTE);
        builder.append(&rtmsg);

        // Add destination address
        match dst_addr {
            IpAddr::V4(v4) => {
                builder.append_attr(RtaAttr::Dst as u16, &v4.octets());
            }
            IpAddr::V6(v6) => {
                builder.append_attr(RtaAttr::Dst as u16, &v6.octets());
            }
        }

        // Send request and get response
        let response = conn.request(builder).await?;

        // Parse response
        if response.len() < NLMSG_HDRLEN + RtMsg::SIZE {
            return Err(rip::netlink::Error::InvalidMessage(
                "invalid response from kernel".into(),
            ));
        }

        let payload = &response[NLMSG_HDRLEN..];
        let route = RouteMessage::from_bytes(payload).map_err(|e| {
            rip::netlink::Error::InvalidMessage(format!("failed to parse route: {}", e))
        })?;

        print_all(&[route], format, opts)?;

        Ok(())
    }
}
