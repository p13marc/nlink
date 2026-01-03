//! ip neighbor command implementation.
//!
//! This module uses the strongly-typed NeighborMessage API from rip-netlink.

use clap::{Args, Subcommand};
use nlink::netlink::neigh::Neighbor;
use nlink::netlink::types::neigh::NeighborState;
use nlink::netlink::{Connection, Result, Route};
use nlink::output::{OutputFormat, OutputOptions, print_all};
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
        conn: &Connection<Route>,
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
        conn: &Connection<Route>,
        dev: Option<&str>,
        format: OutputFormat,
        opts: &OutputOptions,
        family: Option<u8>,
    ) -> Result<()> {
        // Get neighbors (optionally filtered by device)
        let neighbors = if let Some(dev_name) = dev {
            conn.get_neighbors_for(dev_name).await?
        } else {
            conn.get_neighbors().await?
        };

        // Filter by family if specified
        let neighbors: Vec<_> = if let Some(fam) = family {
            neighbors
                .into_iter()
                .filter(|n| n.family() == fam)
                .collect()
        } else {
            neighbors
        };

        print_all(&neighbors, format, opts)?;

        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    async fn add(
        conn: &Connection<Route>,
        address: &str,
        lladdr: &str,
        dev: &str,
        permanent: bool,
        state_name: Option<&str>,
        replace: bool,
    ) -> Result<()> {
        use nlink::util::addr::{parse_addr, parse_mac};

        let addr: IpAddr = parse_addr(address).map_err(|e| {
            nlink::netlink::Error::InvalidMessage(format!("invalid address: {}", e))
        })?;

        let mac = parse_mac(lladdr)
            .map_err(|e| nlink::netlink::Error::InvalidMessage(format!("invalid MAC: {}", e)))?;

        // Parse NUD state
        let state = if permanent {
            NeighborState::Permanent
        } else if let Some(s) = state_name {
            match s.to_lowercase().as_str() {
                "reachable" => NeighborState::Reachable,
                "stale" => NeighborState::Stale,
                "delay" => NeighborState::Delay,
                "probe" => NeighborState::Probe,
                "failed" => NeighborState::Failed,
                "noarp" => NeighborState::Noarp,
                "permanent" => NeighborState::Permanent,
                _ => NeighborState::Reachable,
            }
        } else {
            NeighborState::Reachable
        };

        let neigh = Neighbor::new(dev, addr).lladdr(mac).state(state);

        if replace {
            conn.replace_neighbor(neigh).await
        } else {
            conn.add_neighbor(neigh).await
        }
    }

    async fn del(conn: &Connection<Route>, address: &str, dev: &str) -> Result<()> {
        use nlink::util::addr::parse_addr;

        let addr: IpAddr = parse_addr(address).map_err(|e| {
            nlink::netlink::Error::InvalidMessage(format!("invalid address: {}", e))
        })?;

        let neigh = Neighbor::new(dev, addr);
        conn.del_neighbor(neigh).await
    }

    async fn flush(conn: &Connection<Route>, dev: Option<&str>, family: Option<u8>) -> Result<()> {
        // Get all neighbor entries
        let neighbors = if let Some(dev_name) = dev {
            conn.get_neighbors_for(dev_name).await?
        } else {
            conn.get_neighbors().await?
        };

        // Filter by family if specified, and skip permanent/noarp entries
        let neighbors_to_delete: Vec<_> = neighbors
            .into_iter()
            .filter(|n| {
                if let Some(fam) = family
                    && n.family() != fam
                {
                    return false;
                }
                // Skip permanent/noarp entries (like iproute2 does)
                !n.is_permanent()
            })
            .collect();

        let count = neighbors_to_delete.len();

        // Delete each neighbor - need interface name for Neighbor builder
        let names = conn.get_interface_names().await?;

        for neigh in neighbors_to_delete {
            if let Some(addr) = neigh.destination()
                && let Some(ifname) = names.get(&neigh.ifindex())
            {
                // Ignore errors for individual deletes (entry may have been removed)
                let _ = conn.del_neighbor(Neighbor::new(ifname, *addr)).await;
            }
        }

        if count > 0 {
            eprintln!("Flushed {} neighbor entries", count);
        }

        Ok(())
    }
}
