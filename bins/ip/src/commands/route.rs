//! ip route command implementation.
//!
//! This module uses the strongly-typed RouteMessage API from rip-netlink.

use clap::{Args, Subcommand};
use nlink::netlink::route::{Ipv4Route, Ipv6Route, RouteMetrics};
use nlink::netlink::types::route::{RouteProtocol, RouteScope};
use nlink::netlink::{Connection, Result, Route};
use nlink::output::{OutputFormat, OutputOptions, print_all};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

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
        conn: &Connection<Route>,
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
        conn: &Connection<Route>,
        table: &str,
        format: OutputFormat,
        opts: &OutputOptions,
        family: Option<u8>,
    ) -> Result<()> {
        let table_id = nlink::util::names::table_id(table).unwrap_or(254); // main

        // Get routes and filter
        let routes = conn.get_routes_for_table(table_id).await?;

        // Filter by family if specified
        let routes: Vec<_> = if let Some(fam) = family {
            routes.into_iter().filter(|r| r.family() == fam).collect()
        } else {
            routes
        };

        print_all(&routes, format, opts)?;

        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    async fn add(
        conn: &Connection<Route>,
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
        use nlink::util::addr::parse_prefix;

        let table_id = nlink::util::names::table_id(table).unwrap_or(254);

        // Parse destination to determine family
        let (dst_addr, dst_len, is_ipv6) = if destination == "default" {
            // Determine family from gateway or default to IPv4
            let is_v6 = via.is_some_and(|v| v.contains(':'));
            (None, 0u8, is_v6)
        } else {
            let (addr, prefix) = parse_prefix(destination).map_err(|e| {
                nlink::netlink::Error::InvalidMessage(format!("invalid destination: {}", e))
            })?;
            let is_v6 = addr.is_ipv6();
            (Some(addr), prefix, is_v6)
        };

        // Parse scope
        let scope_val = scope.and_then(RouteScope::from_name);

        // Build metrics if MTU specified
        let metrics = mtu.map(|m| RouteMetrics::new().mtu(m));

        if is_ipv6 {
            // Build IPv6 route
            let dst_v6 = dst_addr
                .and_then(|a| match a {
                    IpAddr::V6(v6) => Some(v6),
                    _ => None,
                })
                .unwrap_or(Ipv6Addr::UNSPECIFIED);

            let mut route = Ipv6Route::from_addr(dst_v6, dst_len)
                .table(table_id)
                .protocol(RouteProtocol::Static);

            if let Some(gw) = via {
                let gw_addr: Ipv6Addr = gw.parse().map_err(|_| {
                    nlink::netlink::Error::InvalidMessage(format!("invalid gateway: {}", gw))
                })?;
                route = route.gateway(gw_addr);
            }

            if let Some(dev_name) = dev {
                route = route.dev(dev_name);
            }

            if let Some(src_str) = src {
                let src_addr: Ipv6Addr = src_str.parse().map_err(|_| {
                    nlink::netlink::Error::InvalidMessage(format!("invalid source: {}", src_str))
                })?;
                route = route.prefsrc(src_addr);
            }

            if let Some(sc) = scope_val {
                route = route.scope(sc);
            }

            if let Some(m) = metric {
                route = route.priority(m);
            }

            if let Some(met) = metrics {
                route = route.metrics(met);
            }

            if replace {
                conn.replace_route(route).await
            } else {
                conn.add_route(route).await
            }
        } else {
            // Build IPv4 route
            let dst_v4 = dst_addr
                .and_then(|a| match a {
                    IpAddr::V4(v4) => Some(v4),
                    _ => None,
                })
                .unwrap_or(Ipv4Addr::UNSPECIFIED);

            let mut route = Ipv4Route::from_addr(dst_v4, dst_len)
                .table(table_id)
                .protocol(RouteProtocol::Static);

            if let Some(gw) = via {
                let gw_addr: Ipv4Addr = gw.parse().map_err(|_| {
                    nlink::netlink::Error::InvalidMessage(format!("invalid gateway: {}", gw))
                })?;
                route = route.gateway(gw_addr);
            }

            if let Some(dev_name) = dev {
                route = route.dev(dev_name);
            }

            if let Some(src_str) = src {
                let src_addr: Ipv4Addr = src_str.parse().map_err(|_| {
                    nlink::netlink::Error::InvalidMessage(format!("invalid source: {}", src_str))
                })?;
                route = route.prefsrc(src_addr);
            }

            if let Some(sc) = scope_val {
                route = route.scope(sc);
            }

            if let Some(m) = metric {
                route = route.priority(m);
            }

            if let Some(met) = metrics {
                route = route.metrics(met);
            }

            if replace {
                conn.replace_route(route).await
            } else {
                conn.add_route(route).await
            }
        }
    }

    async fn del(conn: &Connection<Route>, destination: &str, table: &str) -> Result<()> {
        use nlink::util::addr::parse_prefix;

        let table_id = nlink::util::names::table_id(table).unwrap_or(254);

        // Parse destination
        if destination == "default" {
            // Delete default route - try IPv4 first
            let route = Ipv4Route::from_addr(Ipv4Addr::UNSPECIFIED, 0).table(table_id);
            conn.del_route(route).await
        } else {
            let (addr, prefix) = parse_prefix(destination).map_err(|e| {
                nlink::netlink::Error::InvalidMessage(format!("invalid destination: {}", e))
            })?;

            match addr {
                IpAddr::V4(v4) => {
                    let route = Ipv4Route::from_addr(v4, prefix).table(table_id);
                    conn.del_route(route).await
                }
                IpAddr::V6(v6) => {
                    let route = Ipv6Route::from_addr(v6, prefix).table(table_id);
                    conn.del_route(route).await
                }
            }
        }
    }

    async fn get(
        conn: &Connection<Route>,
        destination: &str,
        format: OutputFormat,
        opts: &OutputOptions,
    ) -> Result<()> {
        // Parse destination prefix
        use nlink::util::addr::parse_prefix;

        let (dst_addr, prefix_len) = parse_prefix(destination).map_err(|e| {
            nlink::netlink::Error::InvalidMessage(format!("invalid destination: {}", e))
        })?;

        // Get all routes and filter for the matching destination
        let routes = conn.get_routes().await?;
        let matching: Vec<_> = routes
            .into_iter()
            .filter(|r| r.destination == Some(dst_addr) && r.dst_len() == prefix_len)
            .collect();

        if matching.is_empty() {
            return Err(nlink::netlink::Error::InvalidMessage(format!(
                "route to {} not found",
                destination
            )));
        }

        print_all(&matching, format, opts)?;

        Ok(())
    }
}
