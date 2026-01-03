//! Link type subcommands for `ip link add`.

use clap::{Args, Subcommand};
use nlink::netlink::link::{
    BondLink, BridgeLink, DummyLink, GreLink, GretapLink, IpipLink, IpvlanLink, MacvlanLink,
    MacvtapLink, SitLink, VethLink, VlanLink, VrfLink, VxlanLink, WireguardLink, bond_mode,
};
use nlink::netlink::{Connection, Result, Route};

/// Common options for all link types.
#[derive(Args, Debug)]
pub struct CommonLinkArgs {
    /// MTU (Maximum Transmission Unit).
    #[arg(long)]
    pub mtu: Option<u32>,

    /// TX queue length.
    #[arg(long)]
    pub txqlen: Option<u32>,

    /// MAC address.
    #[arg(long)]
    pub address: Option<String>,

    /// Number of TX queues.
    #[arg(long)]
    pub numtxqueues: Option<u32>,

    /// Number of RX queues.
    #[arg(long)]
    pub numrxqueues: Option<u32>,
}

/// Link type subcommands.
#[derive(Subcommand, Debug)]
pub enum LinkAddType {
    /// Create a dummy interface.
    Dummy {
        /// Interface name.
        name: String,
        #[command(flatten)]
        common: CommonLinkArgs,
    },

    /// Create a virtual ethernet pair.
    Veth {
        /// Interface name.
        name: String,
        /// Peer interface name.
        #[arg(long)]
        peer: String,
        #[command(flatten)]
        common: CommonLinkArgs,
    },

    /// Create a bridge device.
    Bridge {
        /// Interface name.
        name: String,
        /// Enable Spanning Tree Protocol.
        #[arg(long)]
        stp: bool,
        /// Forward delay in seconds.
        #[arg(long)]
        forward_delay: Option<u32>,
        /// Hello time in seconds.
        #[arg(long)]
        hello_time: Option<u32>,
        /// Max age in seconds.
        #[arg(long)]
        max_age: Option<u32>,
        /// Ageing time in seconds.
        #[arg(long)]
        ageing_time: Option<u32>,
        /// Bridge priority (0-65535).
        #[arg(long)]
        priority: Option<u16>,
        /// Enable VLAN filtering.
        #[arg(long)]
        vlan_filtering: bool,
        #[command(flatten)]
        common: CommonLinkArgs,
    },

    /// Create a bonding (link aggregation) device.
    Bond {
        /// Interface name.
        name: String,
        /// Bonding mode: balance-rr, active-backup, balance-xor, broadcast, 802.3ad, balance-tlb, balance-alb.
        #[arg(long, default_value = "balance-rr")]
        mode: String,
        /// Link monitoring interval in milliseconds.
        #[arg(long)]
        miimon: Option<u32>,
        /// Delay before enabling slave after link up (ms).
        #[arg(long)]
        updelay: Option<u32>,
        /// Delay before disabling slave after link down (ms).
        #[arg(long)]
        downdelay: Option<u32>,
        /// Minimum number of links for bond to be up.
        #[arg(long)]
        min_links: Option<u32>,
        /// Hash policy: layer2, layer3+4, layer2+3, encap2+3, encap3+4.
        #[arg(long)]
        xmit_hash_policy: Option<String>,
        #[command(flatten)]
        common: CommonLinkArgs,
    },

    /// Create a VLAN interface.
    Vlan {
        /// Interface name.
        name: String,
        /// Parent interface.
        #[arg(long)]
        link: String,
        /// VLAN ID (1-4094).
        #[arg(long)]
        id: u16,
        /// VLAN protocol: 802.1q or 802.1ad.
        #[arg(long, default_value = "802.1q")]
        protocol: String,
        #[command(flatten)]
        common: CommonLinkArgs,
    },

    /// Create a VXLAN interface.
    Vxlan {
        /// Interface name.
        name: String,
        /// VXLAN Network Identifier (VNI).
        #[arg(long)]
        vni: u32,
        /// Remote IP address (multicast or unicast).
        #[arg(long)]
        remote: Option<String>,
        /// Local IP address.
        #[arg(long)]
        local: Option<String>,
        /// Destination port (default: 4789).
        #[arg(long, default_value = "4789")]
        dstport: u16,
        /// Parent device for VXLAN.
        #[arg(long)]
        dev: Option<String>,
        /// TTL value.
        #[arg(long)]
        ttl: Option<u8>,
        /// Enable learning.
        #[arg(long)]
        learning: bool,
        /// Disable learning.
        #[arg(long)]
        nolearning: bool,
        #[command(flatten)]
        common: CommonLinkArgs,
    },

    /// Create a MACVLAN interface.
    Macvlan {
        /// Interface name.
        name: String,
        /// Parent interface.
        #[arg(long)]
        link: String,
        /// MACVLAN mode: private, vepa, bridge, passthru, source.
        #[arg(long, default_value = "bridge")]
        mode: String,
        #[command(flatten)]
        common: CommonLinkArgs,
    },

    /// Create a MACVTAP interface.
    Macvtap {
        /// Interface name.
        name: String,
        /// Parent interface.
        #[arg(long)]
        link: String,
        /// MACVTAP mode: private, vepa, bridge, passthru, source.
        #[arg(long, default_value = "bridge")]
        mode: String,
        #[command(flatten)]
        common: CommonLinkArgs,
    },

    /// Create an IPVLAN interface.
    Ipvlan {
        /// Interface name.
        name: String,
        /// Parent interface.
        #[arg(long)]
        link: String,
        /// IPVLAN mode: l2, l3, l3s.
        #[arg(long, default_value = "l3")]
        mode: String,
        #[command(flatten)]
        common: CommonLinkArgs,
    },

    /// Create a VRF (Virtual Routing and Forwarding) device.
    Vrf {
        /// Interface name.
        name: String,
        /// Routing table ID.
        #[arg(long)]
        table: u32,
        #[command(flatten)]
        common: CommonLinkArgs,
    },

    /// Create a GRE tunnel.
    Gre {
        /// Interface name.
        name: String,
        /// Remote endpoint address.
        #[arg(long)]
        remote: String,
        /// Local endpoint address.
        #[arg(long)]
        local: Option<String>,
        /// TTL value.
        #[arg(long)]
        ttl: Option<u8>,
        /// Tunnel key.
        #[arg(long)]
        key: Option<u32>,
        #[command(flatten)]
        common: CommonLinkArgs,
    },

    /// Create a GRE TAP tunnel (Ethernet over GRE).
    Gretap {
        /// Interface name.
        name: String,
        /// Remote endpoint address.
        #[arg(long)]
        remote: String,
        /// Local endpoint address.
        #[arg(long)]
        local: Option<String>,
        /// TTL value.
        #[arg(long)]
        ttl: Option<u8>,
        /// Tunnel key.
        #[arg(long)]
        key: Option<u32>,
        #[command(flatten)]
        common: CommonLinkArgs,
    },

    /// Create an IPIP tunnel.
    Ipip {
        /// Interface name.
        name: String,
        /// Remote endpoint address.
        #[arg(long)]
        remote: String,
        /// Local endpoint address.
        #[arg(long)]
        local: Option<String>,
        /// TTL value.
        #[arg(long)]
        ttl: Option<u8>,
        #[command(flatten)]
        common: CommonLinkArgs,
    },

    /// Create a SIT tunnel (IPv6-in-IPv4).
    Sit {
        /// Interface name.
        name: String,
        /// Remote endpoint address.
        #[arg(long)]
        remote: String,
        /// Local endpoint address.
        #[arg(long)]
        local: Option<String>,
        /// TTL value.
        #[arg(long)]
        ttl: Option<u8>,
        #[command(flatten)]
        common: CommonLinkArgs,
    },

    /// Create a WireGuard interface.
    Wireguard {
        /// Interface name.
        name: String,
        #[command(flatten)]
        common: CommonLinkArgs,
    },
}

/// Add a link with the specified type.
pub async fn add_link(conn: &Connection<Route>, link_type: LinkAddType) -> Result<()> {
    match link_type {
        LinkAddType::Dummy { name, common } => {
            let mut link = DummyLink::new(&name);
            if let Some(mtu) = common.mtu {
                link = link.mtu(mtu);
            }
            if let Some(ref addr) = common.address {
                let mac = parse_mac(addr)?;
                link = link.address(mac);
            }
            conn.add_link(link).await
        }

        LinkAddType::Veth { name, peer, common } => {
            let mut link = VethLink::new(&name, &peer);
            if let Some(mtu) = common.mtu {
                link = link.mtu(mtu);
            }
            if let Some(ref addr) = common.address {
                let mac = parse_mac(addr)?;
                link = link.address(mac);
            }
            conn.add_link(link).await
        }

        LinkAddType::Bridge {
            name,
            stp,
            forward_delay,
            hello_time,
            max_age,
            ageing_time,
            priority,
            vlan_filtering,
            common,
        } => {
            let mut link = BridgeLink::new(&name);
            if stp {
                link = link.stp(true);
            }
            if let Some(v) = forward_delay {
                // CLI takes seconds, API takes milliseconds
                link = link.forward_delay_ms(v * 1000);
            }
            if let Some(v) = hello_time {
                link = link.hello_time_ms(v * 1000);
            }
            if let Some(v) = max_age {
                link = link.max_age_ms(v * 1000);
            }
            if let Some(v) = ageing_time {
                link = link.ageing_time(v);
            }
            if let Some(v) = priority {
                link = link.priority(v);
            }
            if vlan_filtering {
                link = link.vlan_filtering(true);
            }
            if let Some(mtu) = common.mtu {
                link = link.mtu(mtu);
            }
            if let Some(ref addr) = common.address {
                let mac = parse_mac(addr)?;
                link = link.address(mac);
            }
            conn.add_link(link).await
        }

        LinkAddType::Bond {
            name,
            mode,
            miimon,
            updelay,
            downdelay,
            min_links,
            xmit_hash_policy,
            common,
        } => {
            let mode_val = parse_bond_mode(&mode);
            let mut link = BondLink::new(&name).mode(mode_val);
            if let Some(v) = miimon {
                link = link.miimon(v);
            }
            if let Some(v) = updelay {
                link = link.updelay(v);
            }
            if let Some(v) = downdelay {
                link = link.downdelay(v);
            }
            if let Some(v) = min_links {
                link = link.min_links(v);
            }
            if let Some(ref policy) = xmit_hash_policy {
                let p = parse_xmit_hash_policy(policy);
                link = link.xmit_hash_policy(p);
            }
            if let Some(mtu) = common.mtu {
                link = link.mtu(mtu);
            }
            if let Some(ref addr) = common.address {
                let mac = parse_mac(addr)?;
                link = link.address(mac);
            }
            conn.add_link(link).await
        }

        LinkAddType::Vlan {
            name,
            link: parent,
            id,
            protocol,
            common,
        } => {
            let mut link = VlanLink::new(&name, &parent, id);
            if protocol == "802.1ad" {
                link = link.qinq();
            }
            if let Some(mtu) = common.mtu {
                link = link.mtu(mtu);
            }
            if let Some(ref addr) = common.address {
                let mac = parse_mac(addr)?;
                link = link.address(mac);
            }
            conn.add_link(link).await
        }

        LinkAddType::Vxlan {
            name,
            vni,
            remote,
            local,
            dstport,
            dev,
            ttl,
            learning,
            nolearning,
            common,
        } => {
            let mut link = VxlanLink::new(&name, vni).port(dstport);
            if let Some(ref addr) = remote
                && let Ok(ip) = addr.parse::<std::net::Ipv4Addr>() {
                    link = link.remote(ip);
                }
            if let Some(ref addr) = local
                && let Ok(ip) = addr.parse::<std::net::Ipv4Addr>() {
                    link = link.local(ip);
                }
            if let Some(ref dev_name) = dev {
                link = link.dev(dev_name);
            }
            if let Some(t) = ttl {
                link = link.ttl(t);
            }
            if learning {
                link = link.learning(true);
            } else if nolearning {
                link = link.learning(false);
            }
            if let Some(mtu) = common.mtu {
                link = link.mtu(mtu);
            }
            if let Some(ref addr) = common.address {
                let mac = parse_mac(addr)?;
                link = link.address(mac);
            }
            conn.add_link(link).await
        }

        LinkAddType::Macvlan {
            name,
            link: parent,
            mode,
            common,
        } => {
            let mode_val = parse_macvlan_mode(&mode);
            let mut link = MacvlanLink::new(&name, &parent).mode(mode_val);
            if let Some(mtu) = common.mtu {
                link = link.mtu(mtu);
            }
            if let Some(ref addr) = common.address {
                let mac = parse_mac(addr)?;
                link = link.address(mac);
            }
            conn.add_link(link).await
        }

        LinkAddType::Macvtap {
            name,
            link: parent,
            mode,
            common,
        } => {
            let mode_val = parse_macvlan_mode(&mode);
            let mut link = MacvtapLink::new(&name, &parent).mode(mode_val);
            if let Some(mtu) = common.mtu {
                link = link.mtu(mtu);
            }
            if let Some(ref addr) = common.address {
                let mac = parse_mac(addr)?;
                link = link.address(mac);
            }
            conn.add_link(link).await
        }

        LinkAddType::Ipvlan {
            name,
            link: parent,
            mode,
            common,
        } => {
            let mode_val = parse_ipvlan_mode(&mode);
            let mut link = IpvlanLink::new(&name, &parent).mode(mode_val);
            if let Some(mtu) = common.mtu {
                link = link.mtu(mtu);
            }
            // Note: ipvlan inherits MAC from parent, cannot set address
            conn.add_link(link).await
        }

        LinkAddType::Vrf {
            name,
            table,
            common,
        } => {
            let mut link = VrfLink::new(&name, table);
            if let Some(mtu) = common.mtu {
                link = link.mtu(mtu);
            }
            conn.add_link(link).await
        }

        LinkAddType::Gre {
            name,
            remote,
            local,
            ttl,
            key,
            common,
        } => {
            let remote_ip: std::net::Ipv4Addr = remote.parse().map_err(|_| {
                nlink::netlink::Error::InvalidMessage("invalid remote IP address".into())
            })?;
            let mut link = GreLink::new(&name).remote(remote_ip);
            if let Some(ref addr) = local
                && let Ok(ip) = addr.parse::<std::net::Ipv4Addr>() {
                    link = link.local(ip);
                }
            if let Some(t) = ttl {
                link = link.ttl(t);
            }
            if let Some(k) = key {
                link = link.key(k);
            }
            if let Some(mtu) = common.mtu {
                link = link.mtu(mtu);
            }
            conn.add_link(link).await
        }

        LinkAddType::Gretap {
            name,
            remote,
            local,
            ttl,
            key,
            common,
        } => {
            let remote_ip: std::net::Ipv4Addr = remote.parse().map_err(|_| {
                nlink::netlink::Error::InvalidMessage("invalid remote IP address".into())
            })?;
            let mut link = GretapLink::new(&name).remote(remote_ip);
            if let Some(ref addr) = local
                && let Ok(ip) = addr.parse::<std::net::Ipv4Addr>() {
                    link = link.local(ip);
                }
            if let Some(t) = ttl {
                link = link.ttl(t);
            }
            if let Some(k) = key {
                link = link.key(k);
            }
            if let Some(mtu) = common.mtu {
                link = link.mtu(mtu);
            }
            conn.add_link(link).await
        }

        LinkAddType::Ipip {
            name,
            remote,
            local,
            ttl,
            common,
        } => {
            let remote_ip: std::net::Ipv4Addr = remote.parse().map_err(|_| {
                nlink::netlink::Error::InvalidMessage("invalid remote IP address".into())
            })?;
            let mut link = IpipLink::new(&name).remote(remote_ip);
            if let Some(ref addr) = local
                && let Ok(ip) = addr.parse::<std::net::Ipv4Addr>() {
                    link = link.local(ip);
                }
            if let Some(t) = ttl {
                link = link.ttl(t);
            }
            if let Some(mtu) = common.mtu {
                link = link.mtu(mtu);
            }
            conn.add_link(link).await
        }

        LinkAddType::Sit {
            name,
            remote,
            local,
            ttl,
            common,
        } => {
            let remote_ip: std::net::Ipv4Addr = remote.parse().map_err(|_| {
                nlink::netlink::Error::InvalidMessage("invalid remote IP address".into())
            })?;
            let mut link = SitLink::new(&name).remote(remote_ip);
            if let Some(ref addr) = local
                && let Ok(ip) = addr.parse::<std::net::Ipv4Addr>() {
                    link = link.local(ip);
                }
            if let Some(t) = ttl {
                link = link.ttl(t);
            }
            if let Some(mtu) = common.mtu {
                link = link.mtu(mtu);
            }
            conn.add_link(link).await
        }

        LinkAddType::Wireguard { name, common } => {
            let mut link = WireguardLink::new(&name);
            if let Some(mtu) = common.mtu {
                link = link.mtu(mtu);
            }
            conn.add_link(link).await
        }
    }
}

fn parse_mac(addr: &str) -> Result<[u8; 6]> {
    nlink::util::addr::parse_mac(addr)
        .map_err(|e| nlink::netlink::Error::InvalidMessage(format!("invalid MAC address: {}", e)))
}

fn parse_bond_mode(mode: &str) -> u8 {
    match mode.to_lowercase().as_str() {
        "balance-rr" | "0" => bond_mode::BALANCE_RR,
        "active-backup" | "1" => bond_mode::ACTIVE_BACKUP,
        "balance-xor" | "2" => bond_mode::BALANCE_XOR,
        "broadcast" | "3" => bond_mode::BROADCAST,
        "802.3ad" | "4" => bond_mode::LACP,
        "balance-tlb" | "5" => bond_mode::BALANCE_TLB,
        "balance-alb" | "6" => bond_mode::BALANCE_ALB,
        _ => bond_mode::BALANCE_RR,
    }
}

fn parse_xmit_hash_policy(policy: &str) -> u8 {
    match policy.to_lowercase().as_str() {
        "layer2" | "0" => 0,
        "layer3+4" | "1" => 1,
        "layer2+3" | "2" => 2,
        "encap2+3" | "3" => 3,
        "encap3+4" | "4" => 4,
        _ => 0,
    }
}

fn parse_macvlan_mode(mode: &str) -> nlink::netlink::link::MacvlanMode {
    use nlink::netlink::link::MacvlanMode;
    match mode.to_lowercase().as_str() {
        "private" => MacvlanMode::Private,
        "vepa" => MacvlanMode::Vepa,
        "bridge" => MacvlanMode::Bridge,
        "passthru" => MacvlanMode::Passthru,
        "source" => MacvlanMode::Source,
        _ => MacvlanMode::Bridge,
    }
}

fn parse_ipvlan_mode(mode: &str) -> nlink::netlink::link::IpvlanMode {
    use nlink::netlink::link::IpvlanMode;
    match mode.to_lowercase().as_str() {
        "l2" => IpvlanMode::L2,
        "l3" => IpvlanMode::L3,
        "l3s" => IpvlanMode::L3S,
        _ => IpvlanMode::L3,
    }
}
