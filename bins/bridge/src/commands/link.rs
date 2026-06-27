//! `bridge link` command implementation.
//!
//! Currently exposes `bridge link set`, which configures per-port
//! bridge options (`IFLA_BRPORT_*`) via
//! [`Connection::set_bridge_port`](nlink::netlink::Connection::set_bridge_port).

use std::str::FromStr;

use clap::{Args, Subcommand};
use nlink::{
    netlink::{Connection, Error, Result, Route, link::BridgePortConfig},
    output::{OutputFormat, OutputOptions},
};

#[derive(Args)]
pub struct LinkCmd {
    #[command(subcommand)]
    command: LinkCommand,
}

#[derive(Subcommand)]
enum LinkCommand {
    /// Set per-port bridge options on an enslaved interface.
    Set(LinkSetArgs),
}

/// A tri-state `on`/`off` flag value (mirrors `bridge link set`).
#[derive(Clone, Copy)]
struct OnOff(bool);

impl FromStr for OnOff {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        match s {
            "on" | "1" | "yes" | "true" => Ok(OnOff(true)),
            "off" | "0" | "no" | "false" => Ok(OnOff(false)),
            other => Err(Error::InvalidMessage(format!(
                "bridge link set: invalid on/off value `{other}` (expected `on` or `off`)"
            ))),
        }
    }
}

#[derive(Args)]
struct LinkSetArgs {
    /// Port device
    #[arg(long)]
    dev: String,

    /// STP port state (0 disabled, 1 listening, 2 learning, 3 forwarding, 4 blocking)
    #[arg(long)]
    state: Option<u8>,

    /// STP port priority
    #[arg(long)]
    priority: Option<u16>,

    /// STP path cost
    #[arg(long)]
    cost: Option<u32>,

    /// Hairpin mode (on/off)
    #[arg(long)]
    hairpin: Option<OnOff>,

    /// BPDU guard (on/off)
    #[arg(long = "bpdu-guard")]
    bpdu_guard: Option<OnOff>,

    /// Root block — reject superior BPDUs (on/off)
    #[arg(long = "root-block")]
    root_block: Option<OnOff>,

    /// IGMP fast leave (on/off)
    #[arg(long = "fast-leave")]
    fast_leave: Option<OnOff>,

    /// MAC learning (on/off)
    #[arg(long)]
    learning: Option<OnOff>,

    /// Unknown-unicast flooding (on/off)
    #[arg(long)]
    flood: Option<OnOff>,

    /// Proxy ARP (on/off)
    #[arg(long = "proxy-arp")]
    proxy_arp: Option<OnOff>,

    /// Multicast flooding (on/off)
    #[arg(long = "mcast-flood")]
    mcast_flood: Option<OnOff>,

    /// Multicast-to-unicast (on/off)
    #[arg(long = "mcast-to-unicast")]
    mcast_to_unicast: Option<OnOff>,

    /// Broadcast flooding (on/off)
    #[arg(long = "bcast-flood")]
    bcast_flood: Option<OnOff>,

    /// Neighbour suppression (on/off)
    #[arg(long = "neigh-suppress")]
    neigh_suppress: Option<OnOff>,

    /// Port isolation (on/off)
    #[arg(long)]
    isolated: Option<OnOff>,
}

impl LinkCmd {
    pub async fn run(
        &self,
        conn: &Connection<Route>,
        _format: OutputFormat,
        _opts: &OutputOptions,
    ) -> Result<()> {
        match &self.command {
            LinkCommand::Set(args) => {
                let mut cfg = BridgePortConfig::new();
                if let Some(v) = args.state {
                    cfg.state = Some(v);
                }
                if let Some(v) = args.priority {
                    cfg.priority = Some(v);
                }
                if let Some(v) = args.cost {
                    cfg.cost = Some(v);
                }
                if let Some(v) = args.hairpin {
                    cfg.hairpin = Some(v.0);
                }
                if let Some(v) = args.bpdu_guard {
                    cfg.bpdu_guard = Some(v.0);
                }
                if let Some(v) = args.root_block {
                    cfg.root_block = Some(v.0);
                }
                if let Some(v) = args.fast_leave {
                    cfg.fast_leave = Some(v.0);
                }
                if let Some(v) = args.learning {
                    cfg.learning = Some(v.0);
                }
                if let Some(v) = args.flood {
                    cfg.unicast_flood = Some(v.0);
                }
                if let Some(v) = args.proxy_arp {
                    cfg.proxy_arp = Some(v.0);
                }
                if let Some(v) = args.mcast_flood {
                    cfg.mcast_flood = Some(v.0);
                }
                if let Some(v) = args.mcast_to_unicast {
                    cfg.mcast_to_unicast = Some(v.0);
                }
                if let Some(v) = args.bcast_flood {
                    cfg.bcast_flood = Some(v.0);
                }
                if let Some(v) = args.neigh_suppress {
                    cfg.neigh_suppress = Some(v.0);
                }
                if let Some(v) = args.isolated {
                    cfg.isolated = Some(v.0);
                }

                conn.set_bridge_port(args.dev.as_str(), cfg).await?;
                println!("bridge port `{}` updated", args.dev);
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::OnOff;

    #[test]
    fn parses_on_aliases() {
        for s in ["on", "1", "yes", "true"] {
            let Ok(v) = OnOff::from_str(s) else {
                panic!("{s} should parse");
            };
            assert!(v.0, "{s} should be true");
        }
    }

    #[test]
    fn parses_off_aliases() {
        for s in ["off", "0", "no", "false"] {
            let Ok(v) = OnOff::from_str(s) else {
                panic!("{s} should parse");
            };
            assert!(!v.0, "{s} should be false");
        }
    }

    #[test]
    fn rejects_unknown() {
        match OnOff::from_str("maybe") {
            Ok(_) => panic!("`maybe` should be rejected"),
            Err(e) => assert!(
                e.to_string().contains("invalid on/off value `maybe`"),
                "{e}"
            ),
        }
    }
}
