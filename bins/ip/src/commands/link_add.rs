//! Link type subcommands for `ip link add`.

use clap::{Args, Subcommand};
use rip_netlink::connection::create_request;
use rip_netlink::message::NlMsgType;
use rip_netlink::types::link::{IfInfoMsg, IflaAttr, IflaInfo};
use rip_netlink::{Connection, MessageBuilder, Result};

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
pub async fn add_link(conn: &Connection, link_type: LinkAddType) -> Result<()> {
    let (name, kind, common) = match &link_type {
        LinkAddType::Dummy { name, common } => (name.as_str(), "dummy", common),
        LinkAddType::Veth { name, common, .. } => (name.as_str(), "veth", common),
        LinkAddType::Bridge { name, common, .. } => (name.as_str(), "bridge", common),
        LinkAddType::Bond { name, common, .. } => (name.as_str(), "bond", common),
        LinkAddType::Vlan { name, common, .. } => (name.as_str(), "vlan", common),
        LinkAddType::Vxlan { name, common, .. } => (name.as_str(), "vxlan", common),
        LinkAddType::Macvlan { name, common, .. } => (name.as_str(), "macvlan", common),
        LinkAddType::Macvtap { name, common, .. } => (name.as_str(), "macvtap", common),
        LinkAddType::Ipvlan { name, common, .. } => (name.as_str(), "ipvlan", common),
        LinkAddType::Vrf { name, common, .. } => (name.as_str(), "vrf", common),
        LinkAddType::Gre { name, common, .. } => (name.as_str(), "gre", common),
        LinkAddType::Gretap { name, common, .. } => (name.as_str(), "gretap", common),
        LinkAddType::Ipip { name, common, .. } => (name.as_str(), "ipip", common),
        LinkAddType::Sit { name, common, .. } => (name.as_str(), "sit", common),
        LinkAddType::Wireguard { name, common } => (name.as_str(), "wireguard", common),
    };

    let ifinfo = IfInfoMsg::new();
    let mut builder = create_request(NlMsgType::RTM_NEWLINK);
    builder.append(&ifinfo);

    // Interface name
    builder.append_attr_str(IflaAttr::Ifname as u16, name);

    // Common attributes
    build_common_attrs(&mut builder, common)?;

    // Parent link for types that need it
    build_parent_link(&mut builder, &link_type)?;

    // IFLA_LINKINFO nested attribute
    let linkinfo = builder.nest_start(IflaAttr::Linkinfo as u16);
    builder.append_attr_str(IflaInfo::Kind as u16, kind);

    // Type-specific IFLA_INFO_DATA
    let has_data = build_type_specific_data(&mut builder, &link_type)?;
    if has_data {
        // Data was added inside the function
    }

    builder.nest_end(linkinfo);

    conn.request_ack(builder).await?;

    Ok(())
}

fn build_common_attrs(builder: &mut MessageBuilder, common: &CommonLinkArgs) -> Result<()> {
    if let Some(mtu) = common.mtu {
        builder.append_attr_u32(IflaAttr::Mtu as u16, mtu);
    }
    if let Some(txqlen) = common.txqlen {
        builder.append_attr_u32(IflaAttr::TxqLen as u16, txqlen);
    }
    if let Some(ref addr) = common.address {
        let mac = rip_lib::addr::parse_mac(addr).map_err(|e| {
            rip_netlink::Error::InvalidMessage(format!("invalid MAC address: {}", e))
        })?;
        builder.append_attr(IflaAttr::Address as u16, &mac);
    }
    if let Some(n) = common.numtxqueues {
        builder.append_attr_u32(IflaAttr::NumTxQueues as u16, n);
    }
    if let Some(n) = common.numrxqueues {
        builder.append_attr_u32(IflaAttr::NumRxQueues as u16, n);
    }
    Ok(())
}

fn build_parent_link(builder: &mut MessageBuilder, link_type: &LinkAddType) -> Result<()> {
    let link_name = match link_type {
        LinkAddType::Vlan { link, .. } => Some(link.as_str()),
        LinkAddType::Macvlan { link, .. } => Some(link.as_str()),
        LinkAddType::Macvtap { link, .. } => Some(link.as_str()),
        LinkAddType::Ipvlan { link, .. } => Some(link.as_str()),
        LinkAddType::Vxlan { dev, .. } => dev.as_deref(),
        _ => None,
    };

    if let Some(name) = link_name {
        let idx = rip_lib::ifname::name_to_index(name).map_err(|e| {
            rip_netlink::Error::InvalidMessage(format!("parent device not found: {}", e))
        })?;
        builder.append_attr_u32(IflaAttr::Link as u16, idx);
    }

    Ok(())
}

fn build_type_specific_data(builder: &mut MessageBuilder, link_type: &LinkAddType) -> Result<bool> {
    match link_type {
        LinkAddType::Dummy { .. } => Ok(false),

        LinkAddType::Veth { peer, .. } => {
            let data = builder.nest_start(IflaInfo::Data as u16);
            // VETH_INFO_PEER = 1
            let peer_nest = builder.nest_start(1);
            let peer_ifinfo = IfInfoMsg::new();
            builder.append(&peer_ifinfo);
            builder.append_attr_str(IflaAttr::Ifname as u16, peer);
            builder.nest_end(peer_nest);
            builder.nest_end(data);
            Ok(true)
        }

        LinkAddType::Bridge {
            stp,
            forward_delay,
            hello_time,
            max_age,
            ageing_time,
            priority,
            vlan_filtering,
            ..
        } => {
            let data = builder.nest_start(IflaInfo::Data as u16);
            // IFLA_BR_STP_STATE = 5
            if *stp {
                builder.append_attr_u32(5, 1);
            }
            // IFLA_BR_FORWARD_DELAY = 1 (in centiseconds)
            if let Some(v) = forward_delay {
                builder.append_attr_u32(1, v * 100);
            }
            // IFLA_BR_HELLO_TIME = 2
            if let Some(v) = hello_time {
                builder.append_attr_u32(2, v * 100);
            }
            // IFLA_BR_MAX_AGE = 3
            if let Some(v) = max_age {
                builder.append_attr_u32(3, v * 100);
            }
            // IFLA_BR_AGEING_TIME = 4
            if let Some(v) = ageing_time {
                builder.append_attr_u32(4, v * 100);
            }
            // IFLA_BR_PRIORITY = 6
            if let Some(v) = priority {
                builder.append_attr_u16(6, *v);
            }
            // IFLA_BR_VLAN_FILTERING = 7
            if *vlan_filtering {
                builder.append_attr_u8(7, 1);
            }
            builder.nest_end(data);
            Ok(true)
        }

        LinkAddType::Bond {
            mode,
            miimon,
            updelay,
            downdelay,
            min_links,
            xmit_hash_policy,
            ..
        } => {
            let data = builder.nest_start(IflaInfo::Data as u16);
            // IFLA_BOND_MODE = 1
            let mode_val = parse_bond_mode(mode);
            builder.append_attr_u8(1, mode_val);
            // IFLA_BOND_MIIMON = 3
            if let Some(v) = miimon {
                builder.append_attr_u32(3, *v);
            }
            // IFLA_BOND_UPDELAY = 4
            if let Some(v) = updelay {
                builder.append_attr_u32(4, *v);
            }
            // IFLA_BOND_DOWNDELAY = 5
            if let Some(v) = downdelay {
                builder.append_attr_u32(5, *v);
            }
            // IFLA_BOND_MIN_LINKS = 18
            if let Some(v) = min_links {
                builder.append_attr_u32(18, *v);
            }
            // IFLA_BOND_XMIT_HASH_POLICY = 14
            if let Some(policy) = xmit_hash_policy {
                let p = parse_xmit_hash_policy(policy);
                builder.append_attr_u8(14, p);
            }
            builder.nest_end(data);
            Ok(true)
        }

        LinkAddType::Vlan { id, protocol, .. } => {
            let data = builder.nest_start(IflaInfo::Data as u16);
            // IFLA_VLAN_ID = 1
            builder.append_attr_u16(1, *id);
            // IFLA_VLAN_PROTOCOL = 5
            let proto = match protocol.as_str() {
                "802.1ad" => 0x88a8u16.to_be(),
                _ => 0x8100u16.to_be(), // 802.1q
            };
            builder.append_attr_u16(5, proto);
            builder.nest_end(data);
            Ok(true)
        }

        LinkAddType::Vxlan {
            vni,
            remote,
            local,
            dstport,
            ttl,
            learning,
            nolearning,
            ..
        } => {
            let data = builder.nest_start(IflaInfo::Data as u16);
            // IFLA_VXLAN_ID = 1
            builder.append_attr_u32(1, *vni);
            // IFLA_VXLAN_GROUP = 2 (remote for multicast) or IFLA_VXLAN_GROUP6 = 16
            if let Some(addr) = remote {
                if let Ok(ip) = addr.parse::<std::net::Ipv4Addr>() {
                    builder.append_attr(2, &ip.octets());
                } else if let Ok(ip) = addr.parse::<std::net::Ipv6Addr>() {
                    builder.append_attr(16, &ip.octets());
                }
            }
            // IFLA_VXLAN_LOCAL = 4 or IFLA_VXLAN_LOCAL6 = 17
            if let Some(addr) = local {
                if let Ok(ip) = addr.parse::<std::net::Ipv4Addr>() {
                    builder.append_attr(4, &ip.octets());
                } else if let Ok(ip) = addr.parse::<std::net::Ipv6Addr>() {
                    builder.append_attr(17, &ip.octets());
                }
            }
            // IFLA_VXLAN_PORT = 15 (big endian)
            builder.append_attr_u16_be(15, *dstport);
            // IFLA_VXLAN_TTL = 7
            if let Some(t) = ttl {
                builder.append_attr_u8(7, *t);
            }
            // IFLA_VXLAN_LEARNING = 9
            if *learning {
                builder.append_attr_u8(9, 1);
            } else if *nolearning {
                builder.append_attr_u8(9, 0);
            }
            builder.nest_end(data);
            Ok(true)
        }

        LinkAddType::Macvlan { mode, .. } | LinkAddType::Macvtap { mode, .. } => {
            let data = builder.nest_start(IflaInfo::Data as u16);
            // IFLA_MACVLAN_MODE = 1
            let mode_val = parse_macvlan_mode(mode);
            builder.append_attr_u32(1, mode_val);
            builder.nest_end(data);
            Ok(true)
        }

        LinkAddType::Ipvlan { mode, .. } => {
            let data = builder.nest_start(IflaInfo::Data as u16);
            // IFLA_IPVLAN_MODE = 1
            let mode_val = match mode.as_str() {
                "l2" => 0u16,
                "l3" => 1,
                "l3s" => 2,
                _ => 1, // default l3
            };
            builder.append_attr_u16(1, mode_val);
            builder.nest_end(data);
            Ok(true)
        }

        LinkAddType::Vrf { table, .. } => {
            let data = builder.nest_start(IflaInfo::Data as u16);
            // IFLA_VRF_TABLE = 1
            builder.append_attr_u32(1, *table);
            builder.nest_end(data);
            Ok(true)
        }

        LinkAddType::Gre {
            remote,
            local,
            ttl,
            key,
            ..
        }
        | LinkAddType::Gretap {
            remote,
            local,
            ttl,
            key,
            ..
        } => {
            let data = builder.nest_start(IflaInfo::Data as u16);
            // IFLA_GRE_REMOTE = 2
            if let Ok(ip) = remote.parse::<std::net::Ipv4Addr>() {
                builder.append_attr(2, &ip.octets());
            }
            // IFLA_GRE_LOCAL = 1
            if let Some(addr) = local
                && let Ok(ip) = addr.parse::<std::net::Ipv4Addr>() {
                    builder.append_attr(1, &ip.octets());
                }
            // IFLA_GRE_TTL = 4
            if let Some(t) = ttl {
                builder.append_attr_u8(4, *t);
            }
            // IFLA_GRE_IKEY/OKEY = 5/6
            if let Some(k) = key {
                builder.append_attr_u32(5, *k);
                builder.append_attr_u32(6, *k);
                // IFLA_GRE_IFLAGS/OFLAGS = 7/8 (set GRE_KEY flag = 0x2000)
                builder.append_attr_u16(7, 0x2000);
                builder.append_attr_u16(8, 0x2000);
            }
            builder.nest_end(data);
            Ok(true)
        }

        LinkAddType::Ipip {
            remote, local, ttl, ..
        }
        | LinkAddType::Sit {
            remote, local, ttl, ..
        } => {
            let data = builder.nest_start(IflaInfo::Data as u16);
            // IFLA_IPTUN_REMOTE = 2
            if let Ok(ip) = remote.parse::<std::net::Ipv4Addr>() {
                builder.append_attr(2, &ip.octets());
            }
            // IFLA_IPTUN_LOCAL = 1
            if let Some(addr) = local
                && let Ok(ip) = addr.parse::<std::net::Ipv4Addr>() {
                    builder.append_attr(1, &ip.octets());
                }
            // IFLA_IPTUN_TTL = 4
            if let Some(t) = ttl {
                builder.append_attr_u8(4, *t);
            }
            builder.nest_end(data);
            Ok(true)
        }

        LinkAddType::Wireguard { .. } => {
            // WireGuard has no IFLA_INFO_DATA for creation
            // Configuration is done via the WireGuard netlink interface
            Ok(false)
        }
    }
}

fn parse_bond_mode(mode: &str) -> u8 {
    match mode.to_lowercase().as_str() {
        "balance-rr" | "0" => 0,
        "active-backup" | "1" => 1,
        "balance-xor" | "2" => 2,
        "broadcast" | "3" => 3,
        "802.3ad" | "4" => 4,
        "balance-tlb" | "5" => 5,
        "balance-alb" | "6" => 6,
        _ => 0,
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

fn parse_macvlan_mode(mode: &str) -> u32 {
    match mode.to_lowercase().as_str() {
        "private" => 1,
        "vepa" => 2,
        "bridge" => 4,
        "passthru" => 8,
        "source" => 16,
        _ => 4, // default bridge
    }
}
