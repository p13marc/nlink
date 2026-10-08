//! Link type subcommands for `ip link add`.

use clap::{Args, Subcommand};
use nlink::netlink::{
    Connection, Result, Route,
    link::{
        BondLink, BondMode, BridgeLink, DummyLink, GreLink, GretapLink, Ip6GreLink, Ip6GretapLink,
        IpipLink, IpvlanLink, LacpRate, MacvlanLink, MacvtapLink, SitLink, VethLink, VlanLink,
        VrfLink, Vti6Link, VtiLink, VxlanLink, WireguardLink, XmitHashPolicy,
    },
};

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
        /// ARP monitoring interval in milliseconds.
        #[arg(long)]
        arp_interval: Option<u32>,
        /// ARP monitoring IP target.
        #[arg(long)]
        arp_ip_target: Option<String>,
        /// LACP rate: slow or fast (802.3ad mode only).
        #[arg(long)]
        lacp_rate: Option<String>,
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

    /// Create a VTI (Virtual Tunnel Interface) for route-based IPsec.
    Vti {
        /// Interface name.
        name: String,
        /// Local endpoint address.
        #[arg(long)]
        local: Option<String>,
        /// Remote endpoint address.
        #[arg(long)]
        remote: Option<String>,
        /// Input key (SPI).
        #[arg(long)]
        ikey: Option<u32>,
        /// Output key (SPI).
        #[arg(long)]
        okey: Option<u32>,
        #[command(flatten)]
        common: CommonLinkArgs,
    },

    /// Create a VTI6 (IPv6 Virtual Tunnel Interface).
    Vti6 {
        /// Interface name.
        name: String,
        /// Local IPv6 endpoint address.
        #[arg(long)]
        local: Option<String>,
        /// Remote IPv6 endpoint address.
        #[arg(long)]
        remote: Option<String>,
        /// Input key (SPI).
        #[arg(long)]
        ikey: Option<u32>,
        /// Output key (SPI).
        #[arg(long)]
        okey: Option<u32>,
        #[command(flatten)]
        common: CommonLinkArgs,
    },

    /// Create an IPv6 GRE tunnel.
    Ip6gre {
        /// Interface name.
        name: String,
        /// Local IPv6 endpoint address.
        #[arg(long)]
        local: Option<String>,
        /// Remote IPv6 endpoint address.
        #[arg(long)]
        remote: Option<String>,
        /// TTL value.
        #[arg(long)]
        ttl: Option<u8>,
        #[command(flatten)]
        common: CommonLinkArgs,
    },

    /// Create an IPv6 GRE TAP tunnel (Ethernet over IPv6 GRE).
    Ip6gretap {
        /// Interface name.
        name: String,
        /// Local IPv6 endpoint address.
        #[arg(long)]
        local: Option<String>,
        /// Remote IPv6 endpoint address.
        #[arg(long)]
        remote: Option<String>,
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
impl LinkAddType {
    fn parts(&self) -> (&str, &'static str, &CommonLinkArgs) {
        match self {
            Self::Dummy { name, common, .. } => (name, "dummy", common),
            Self::Veth { name, common, .. } => (name, "veth", common),
            Self::Bridge { name, common, .. } => (name, "bridge", common),
            Self::Bond { name, common, .. } => (name, "bond", common),
            Self::Vlan { name, common, .. } => (name, "vlan", common),
            Self::Vxlan { name, common, .. } => (name, "vxlan", common),
            Self::Macvlan { name, common, .. } => (name, "macvlan", common),
            Self::Macvtap { name, common, .. } => (name, "macvtap", common),
            Self::Ipvlan { name, common, .. } => (name, "ipvlan", common),
            Self::Vrf { name, common, .. } => (name, "vrf", common),
            Self::Gre { name, common, .. } => (name, "gre", common),
            Self::Gretap { name, common, .. } => (name, "gretap", common),
            Self::Ipip { name, common, .. } => (name, "ipip", common),
            Self::Sit { name, common, .. } => (name, "sit", common),
            Self::Vti { name, common, .. } => (name, "vti", common),
            Self::Vti6 { name, common, .. } => (name, "vti6", common),
            Self::Ip6gre { name, common, .. } => (name, "ip6gre", common),
            Self::Ip6gretap { name, common, .. } => (name, "ip6gretap", common),
            Self::Wireguard { name, common, .. } => (name, "wireguard", common),
        }
    }

    fn name(&self) -> &str {
        self.parts().0
    }

    fn kind_and_common(&self) -> (&'static str, &CommonLinkArgs) {
        let (_, kind, common) = self.parts();
        (kind, common)
    }

    /// Why this kind cannot take `--address`, if it cannot.
    fn no_mac(&self) -> Option<&'static str> {
        match self {
            Self::Ipvlan { .. } => Some("an ipvlan shares its parent's MAC"),
            Self::Gre { .. }
            | Self::Ipip { .. }
            | Self::Sit { .. }
            | Self::Vti { .. }
            | Self::Vti6 { .. }
            | Self::Ip6gre { .. }
            | Self::Wireguard { .. } => Some("it is a layer-3 device with no MAC"),
            _ => None,
        }
    }
}

/// The common options, checked before anything is created. Each kind puts
/// what its create message can carry into it ([`create`] `take`s those);
/// whatever is left is set on the new link right after.
struct Pending {
    mtu: Option<u32>,
    txqlen: Option<u32>,
    address: Option<[u8; 6]>,
}

impl Pending {
    fn parse(link_type: &LinkAddType) -> Result<Self> {
        let (kind, common) = link_type.kind_and_common();
        let address = match &common.address {
            None => None,
            Some(addr) => {
                if let Some(why) = link_type.no_mac() {
                    return Err(invalid(format!("{kind}: --address is not supported: {why}")));
                }
                Some(parse_mac(addr)?)
            }
        };
        Ok(Self {
            mtu: common.mtu,
            txqlen: common.txqlen,
            address,
        })
    }

    async fn apply(&self, conn: &Connection<Route>, name: &str) -> Result<()> {
        if let Some(mtu) = self.mtu {
            conn.set_link_mtu(name, mtu).await?;
        }
        if let Some(txqlen) = self.txqlen {
            conn.set_link_txqlen(name, txqlen).await?;
        }
        if let Some(mac) = self.address {
            conn.set_link_address(name, mac).await?;
        }
        Ok(())
    }
}

/// Create a link. Every option is checked before anything is sent, so a bad
/// one leaves nothing behind; what the kind's create message cannot carry
/// (`--txqlen` always, `--mtu` on some tunnels) is set right after, and if
/// that fails the new link is deleted again — as one `ip link add` would
/// leave nothing. These options used to be dropped without a word (#428).
pub async fn add_link(conn: &Connection<Route>, link_type: LinkAddType) -> Result<()> {
    let name = link_type.name().to_string();
    let mut pending = Pending::parse(&link_type)?;
    create(conn, link_type, &mut pending).await?;
    if let Err(e) = pending.apply(conn, &name).await {
        let _ = conn.del_link(name.as_str()).await;
        return Err(e);
    }
    Ok(())
}

async fn create(
    conn: &Connection<Route>,
    link_type: LinkAddType,
    pending: &mut Pending,
) -> Result<()> {
    match link_type {
        LinkAddType::Dummy { name, .. } => {
            let mut link = DummyLink::new(&name);
            if let Some(mtu) = pending.mtu.take() {
                link = link.mtu(mtu);
            }
            if let Some(mac) = pending.address.take() {
                link = link.address(mac);
            }
            conn.add_link(link).await
        }

        LinkAddType::Veth { name, peer, .. } => {
            let mut link = VethLink::new(&name, &peer);
            if let Some(mtu) = pending.mtu.take() {
                link = link.mtu(mtu);
            }
            if let Some(mac) = pending.address.take() {
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
            ..
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
            if let Some(mtu) = pending.mtu.take() {
                link = link.mtu(mtu);
            }
            if let Some(mac) = pending.address.take() {
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
            arp_interval,
            arp_ip_target,
            lacp_rate,
            ..
        } => {
            let mode_val = parse_bond_mode(&mode)?;
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
                let p = parse_xmit_hash_policy(policy)?;
                link = link.xmit_hash_policy(p);
            }
            if let Some(v) = arp_interval {
                link = link.arp_interval(v);
            }
            if let Some(ref target) = arp_ip_target {
                link = link.arp_ip_target(parse_v4("bond", "arp_ip_target", target)?);
            }
            if let Some(ref rate) = lacp_rate {
                link = link.lacp_rate(parse_lacp_rate(rate)?);
            }
            if let Some(mtu) = pending.mtu.take() {
                link = link.mtu(mtu);
            }
            if let Some(mac) = pending.address.take() {
                link = link.address(mac);
            }
            conn.add_link(link).await
        }

        LinkAddType::Vlan {
            name,
            link: parent,
            id,
            protocol,
            ..
        } => {
            let mut link = VlanLink::new(&name, &parent, id);
            match protocol.to_lowercase().as_str() {
                "802.1q" => {}
                "802.1ad" => link = link.qinq(),
                other => {
                    return Err(invalid(format!(
                        "vlan: unknown protocol `{other}` (expected 802.1q or 802.1ad)"
                    )));
                }
            }
            if let Some(mtu) = pending.mtu.take() {
                link = link.mtu(mtu);
            }
            if let Some(mac) = pending.address.take() {
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
            ..
        } => {
            let mut link = VxlanLink::new(&name, vni).port(dstport);
            // Either family; an IPv6 or unparseable address used to be
            // dropped without a word (#418).
            let parse_ip = |what: &str, addr: &str| {
                addr.parse::<std::net::IpAddr>()
                    .map_err(|_| invalid(format!("vxlan: invalid {what} address `{addr}`")))
            };
            if let Some(ref addr) = remote {
                link = match parse_ip("remote", addr)? {
                    std::net::IpAddr::V4(ip) => link.remote(ip),
                    std::net::IpAddr::V6(ip) => link.remote6(ip),
                };
            }
            if let Some(ref addr) = local {
                link = match parse_ip("local", addr)? {
                    std::net::IpAddr::V4(ip) => link.local(ip),
                    std::net::IpAddr::V6(ip) => link.local6(ip),
                };
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
            if let Some(mtu) = pending.mtu.take() {
                link = link.mtu(mtu);
            }
            if let Some(mac) = pending.address.take() {
                link = link.address(mac);
            }
            conn.add_link(link).await
        }

        LinkAddType::Macvlan {
            name,
            link: parent,
            mode,
            ..
        } => {
            let mode_val = parse_macvlan_mode(&mode)?;
            let mut link = MacvlanLink::new(&name, &parent).mode(mode_val);
            if let Some(mtu) = pending.mtu.take() {
                link = link.mtu(mtu);
            }
            if let Some(mac) = pending.address.take() {
                link = link.address(mac);
            }
            conn.add_link(link).await
        }

        LinkAddType::Macvtap {
            name,
            link: parent,
            mode,
            ..
        } => {
            let mode_val = parse_macvlan_mode(&mode)?;
            let mut link = MacvtapLink::new(&name, &parent).mode(mode_val);
            if let Some(mtu) = pending.mtu.take() {
                link = link.mtu(mtu);
            }
            if let Some(mac) = pending.address.take() {
                link = link.address(mac);
            }
            conn.add_link(link).await
        }

        LinkAddType::Ipvlan {
            name,
            link: parent,
            mode,
            ..
        } => {
            let mode_val = parse_ipvlan_mode(&mode)?;
            let mut link = IpvlanLink::new(&name, &parent).mode(mode_val);
            if let Some(mtu) = pending.mtu.take() {
                link = link.mtu(mtu);
            }
            conn.add_link(link).await
        }

        LinkAddType::Vrf {
            name,
            table,
            ..
        } => {
            let mut link = VrfLink::new(&name, table);
            if let Some(mtu) = pending.mtu.take() {
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
            ..
        } => {
            let remote_ip = parse_v4("gre", "remote", &remote)?;
            let mut link = GreLink::new(&name).remote(remote_ip);
            if let Some(ref addr) = local {
                link = link.local(parse_v4("gre", "local", addr)?);
            }
            if let Some(t) = ttl {
                link = link.ttl(t);
            }
            if let Some(k) = key {
                link = link.key(k);
            }
            if let Some(mtu) = pending.mtu.take() {
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
            ..
        } => {
            let remote_ip = parse_v4("gretap", "remote", &remote)?;
            let mut link = GretapLink::new(&name).remote(remote_ip);
            if let Some(ref addr) = local {
                link = link.local(parse_v4("gretap", "local", addr)?);
            }
            if let Some(t) = ttl {
                link = link.ttl(t);
            }
            if let Some(k) = key {
                link = link.key(k);
            }
            if let Some(mtu) = pending.mtu.take() {
                link = link.mtu(mtu);
            }
            conn.add_link(link).await
        }

        LinkAddType::Ipip {
            name,
            remote,
            local,
            ttl,
            ..
        } => {
            let remote_ip = parse_v4("ipip", "remote", &remote)?;
            let mut link = IpipLink::new(&name).remote(remote_ip);
            if let Some(ref addr) = local {
                link = link.local(parse_v4("ipip", "local", addr)?);
            }
            if let Some(t) = ttl {
                link = link.ttl(t);
            }
            if let Some(mtu) = pending.mtu.take() {
                link = link.mtu(mtu);
            }
            conn.add_link(link).await
        }

        LinkAddType::Sit {
            name,
            remote,
            local,
            ttl,
            ..
        } => {
            let remote_ip = parse_v4("sit", "remote", &remote)?;
            let mut link = SitLink::new(&name).remote(remote_ip);
            if let Some(ref addr) = local {
                link = link.local(parse_v4("sit", "local", addr)?);
            }
            if let Some(t) = ttl {
                link = link.ttl(t);
            }
            if let Some(mtu) = pending.mtu.take() {
                link = link.mtu(mtu);
            }
            conn.add_link(link).await
        }

        LinkAddType::Vti {
            name,
            local,
            remote,
            ikey,
            okey,
            ..
        } => {
            let mut link = VtiLink::new(&name);
            if let Some(ref addr) = local {
                link = link.local(parse_v4("vti", "local", addr)?);
            }
            if let Some(ref addr) = remote {
                link = link.remote(parse_v4("vti", "remote", addr)?);
            }
            if let Some(k) = ikey {
                link = link.ikey(k);
            }
            if let Some(k) = okey {
                link = link.okey(k);
            }
            conn.add_link(link).await
        }

        LinkAddType::Vti6 {
            name,
            local,
            remote,
            ikey,
            okey,
            ..
        } => {
            let mut link = Vti6Link::new(&name);
            if let Some(ref addr) = local {
                link = link.local(parse_v6("vti6", "local", addr)?);
            }
            if let Some(ref addr) = remote {
                link = link.remote(parse_v6("vti6", "remote", addr)?);
            }
            if let Some(k) = ikey {
                link = link.ikey(k);
            }
            if let Some(k) = okey {
                link = link.okey(k);
            }
            conn.add_link(link).await
        }

        LinkAddType::Ip6gre {
            name,
            local,
            remote,
            ttl,
            ..
        } => {
            let mut link = Ip6GreLink::new(&name);
            if let Some(ref addr) = local {
                link = link.local(parse_v6("ip6gre", "local", addr)?);
            }
            if let Some(ref addr) = remote {
                link = link.remote(parse_v6("ip6gre", "remote", addr)?);
            }
            if let Some(t) = ttl {
                link = link.ttl(t);
            }
            conn.add_link(link).await
        }

        LinkAddType::Ip6gretap {
            name,
            local,
            remote,
            ttl,
            ..
        } => {
            let mut link = Ip6GretapLink::new(&name);
            if let Some(ref addr) = local {
                link = link.local(parse_v6("ip6gretap", "local", addr)?);
            }
            if let Some(ref addr) = remote {
                link = link.remote(parse_v6("ip6gretap", "remote", addr)?);
            }
            if let Some(t) = ttl {
                link = link.ttl(t);
            }
            conn.add_link(link).await
        }

        LinkAddType::Wireguard { name, .. } => {
            let mut link = WireguardLink::new(&name);
            if let Some(mtu) = pending.mtu.take() {
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

fn invalid(msg: String) -> nlink::netlink::Error {
    nlink::netlink::Error::InvalidMessage(msg)
}

/// An IPv4 address option of an IPv4-only kind: an IPv6 address names the
/// kind that takes one instead of being dropped.
fn parse_v4(kind: &str, what: &str, addr: &str) -> Result<std::net::Ipv4Addr> {
    match addr.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(ip)) => Ok(ip),
        Ok(std::net::IpAddr::V6(_)) => {
            let instead = match kind {
                "gre" => " (use ip6gre)",
                "gretap" => " (use ip6gretap)",
                "vti" => " (use vti6)",
                _ => "",
            };
            Err(invalid(format!(
                "{kind}: {what} address `{addr}` is IPv6, but {kind} takes IPv4{instead}"
            )))
        }
        Err(_) => Err(invalid(format!("{kind}: invalid {what} address `{addr}`"))),
    }
}

/// An IPv6 address option of an IPv6 tunnel.
fn parse_v6(kind: &str, what: &str, addr: &str) -> Result<std::net::Ipv6Addr> {
    match addr.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V6(ip)) => Ok(ip),
        Ok(std::net::IpAddr::V4(_)) => Err(invalid(format!(
            "{kind}: {what} address `{addr}` is IPv4, but {kind} takes IPv6"
        ))),
        Err(_) => Err(invalid(format!("{kind}: invalid {what} address `{addr}`"))),
    }
}

fn parse_bond_mode(mode: &str) -> Result<BondMode> {
    Ok(match mode.to_lowercase().as_str() {
        "balance-rr" | "0" => BondMode::BalanceRr,
        "active-backup" | "1" => BondMode::ActiveBackup,
        "balance-xor" | "2" => BondMode::BalanceXor,
        "broadcast" | "3" => BondMode::Broadcast,
        "802.3ad" | "4" => BondMode::Lacp,
        "balance-tlb" | "5" => BondMode::BalanceTlb,
        "balance-alb" | "6" => BondMode::BalanceAlb,
        other => {
            return Err(invalid(format!(
                "bond: unknown mode `{other}` (expected balance-rr, active-backup, \
                 balance-xor, broadcast, 802.3ad, balance-tlb, balance-alb, or 0-6)"
            )));
        }
    })
}

fn parse_xmit_hash_policy(policy: &str) -> Result<XmitHashPolicy> {
    Ok(match policy.to_lowercase().as_str() {
        "layer2" | "0" => XmitHashPolicy::Layer2,
        "layer3+4" | "1" => XmitHashPolicy::Layer34,
        "layer2+3" | "2" => XmitHashPolicy::Layer23,
        "encap2+3" | "3" => XmitHashPolicy::Encap23,
        "encap3+4" | "4" => XmitHashPolicy::Encap34,
        "vlan+srcmac" | "5" => XmitHashPolicy::VlanSrcMac,
        other => {
            return Err(invalid(format!(
                "bond: unknown xmit_hash_policy `{other}` (expected layer2, layer3+4, \
                 layer2+3, encap2+3, encap3+4, vlan+srcmac, or 0-5)"
            )));
        }
    })
}

fn parse_lacp_rate(rate: &str) -> Result<LacpRate> {
    Ok(match rate.to_lowercase().as_str() {
        "fast" | "1" => LacpRate::Fast,
        "slow" | "0" => LacpRate::Slow,
        other => {
            return Err(invalid(format!(
                "bond: unknown lacp_rate `{other}` (expected fast, slow, 0, or 1)"
            )));
        }
    })
}

fn parse_macvlan_mode(mode: &str) -> Result<nlink::netlink::link::MacvlanMode> {
    use nlink::netlink::link::MacvlanMode;
    Ok(match mode.to_lowercase().as_str() {
        "private" => MacvlanMode::Private,
        "vepa" => MacvlanMode::Vepa,
        "bridge" => MacvlanMode::Bridge,
        "passthru" => MacvlanMode::Passthru,
        "source" => MacvlanMode::Source,
        other => {
            return Err(invalid(format!(
                "macvlan: unknown mode `{other}` (expected private, vepa, bridge, \
                 passthru, or source)"
            )));
        }
    })
}

fn parse_ipvlan_mode(mode: &str) -> Result<nlink::netlink::link::IpvlanMode> {
    use nlink::netlink::link::IpvlanMode;
    Ok(match mode.to_lowercase().as_str() {
        "l2" => IpvlanMode::L2,
        "l3" => IpvlanMode::L3,
        "l3s" => IpvlanMode::L3S,
        other => {
            return Err(invalid(format!(
                "ipvlan: unknown mode `{other}` (expected l2, l3, or l3s)"
            )));
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bond_mode_accepts_known() {
        assert!(matches!(parse_bond_mode("active-backup"), Ok(BondMode::ActiveBackup)));
        assert!(matches!(parse_bond_mode("4"), Ok(BondMode::Lacp)));
        assert!(matches!(parse_bond_mode("802.3AD"), Ok(BondMode::Lacp)));
    }

    #[test]
    fn bond_mode_rejects_unknown() {
        let err = parse_bond_mode("bogus").unwrap_err().to_string();
        assert!(err.contains("bond: unknown mode `bogus`"), "{err}");
    }

    #[test]
    fn xmit_hash_policy_rejects_unknown() {
        assert!(parse_xmit_hash_policy("layer2").is_ok());
        let err = parse_xmit_hash_policy("layer9").unwrap_err().to_string();
        assert!(err.contains("unknown xmit_hash_policy `layer9`"), "{err}");
    }

    #[test]
    fn lacp_rate_rejects_unknown() {
        assert!(parse_lacp_rate("fast").is_ok());
        let err = parse_lacp_rate("turbo").unwrap_err().to_string();
        assert!(err.contains("unknown lacp_rate `turbo`"), "{err}");
    }

    #[test]
    fn macvlan_mode_rejects_unknown() {
        assert!(parse_macvlan_mode("bridge").is_ok());
        let err = parse_macvlan_mode("brigde").unwrap_err().to_string();
        assert!(err.contains("macvlan: unknown mode `brigde`"), "{err}");
    }

    #[test]
    fn ipvlan_mode_rejects_unknown() {
        assert!(parse_ipvlan_mode("l3s").is_ok());
        let err = parse_ipvlan_mode("l4").unwrap_err().to_string();
        assert!(err.contains("ipvlan: unknown mode `l4`"), "{err}");
    }
}
