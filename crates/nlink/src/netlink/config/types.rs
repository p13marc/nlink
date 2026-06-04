//! Core types for declarative network configuration.

use std::net::IpAddr;

pub use crate::netlink::link::{
    AdSelect as BondAdSelect, LacpRate as BondLacpRate, NetkitMode, NetkitPolicy, NetkitScrub,
    VlanProtocol,
};

/// Declarative network configuration.
///
/// Represents the desired state of network resources. Use the builder methods
/// to add links, addresses, routes, and qdiscs, then call [`diff()`](NetworkConfig::diff)
/// or [`apply()`](NetworkConfig::apply) to reconcile with the current state.
#[derive(Debug, Clone, Default)]
pub struct NetworkConfig {
    pub(crate) links: Vec<DeclaredLink>,
    pub(crate) addresses: Vec<DeclaredAddress>,
    pub(crate) routes: Vec<DeclaredRoute>,
    pub(crate) qdiscs: Vec<DeclaredQdisc>,
}

impl NetworkConfig {
    /// Create an empty network configuration.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a link (interface) configuration.
    ///
    /// **Ordering note (Plan 186 §3c)**: declared order of
    /// `.link()` calls is preserved at the surface, but the
    /// internal apply step topologically sorts parent → child
    /// (e.g., a `vlan` whose parent is also being created in
    /// this apply). You can declare the VLAN before its parent
    /// dummy and the apply still works:
    ///
    /// ```ignore
    /// // Either order works — the apply sorts before sending.
    /// let cfg = NetworkConfig::new()
    ///     .link("eth0.42", |l| l.vlan("eth0", 42))
    ///     .link("eth0",    |l| l.dummy());
    /// ```
    ///
    /// # Example
    ///
    /// ```ignore
    /// let config = NetworkConfig::new()
    ///     .link("br0", |l| l.bridge().up())
    ///     .link("dummy0", |l| l.dummy())
    ///     .link("veth0", |l| l.veth("veth1").master("br0"));
    /// ```
    pub fn link(mut self, name: &str, f: impl FnOnce(LinkBuilder) -> LinkBuilder) -> Self {
        let builder = f(LinkBuilder::new(name));
        self.links.push(builder.build());
        self
    }

    /// Add an IP address to an interface.
    ///
    /// The address should be in CIDR notation (e.g., "192.168.1.1/24").
    ///
    /// # Example
    ///
    /// ```ignore
    /// let config = NetworkConfig::new()
    ///     .address("eth0", "192.168.1.1/24")?
    ///     .address("eth0", "2001:db8::1/64")?;
    /// ```
    pub fn address(mut self, dev: &str, addr: &str) -> Result<Self, AddressParseError> {
        let declared = DeclaredAddress::parse(dev, addr)?;
        self.addresses.push(declared);
        Ok(self)
    }

    /// Add a route.
    ///
    /// The destination should be in CIDR notation (e.g., "10.0.0.0/8" or "0.0.0.0/0").
    ///
    /// # Example
    ///
    /// ```ignore
    /// let config = NetworkConfig::new()
    ///     .route("10.0.0.0/8", |r| r.via("192.168.1.1"))?
    ///     .route("0.0.0.0/0", |r| r.via("192.168.1.254").dev("eth0"))?;
    /// ```
    pub fn route(
        mut self,
        dst: &str,
        f: impl FnOnce(RouteBuilder) -> RouteBuilder,
    ) -> Result<Self, RouteParseError> {
        let builder = f(RouteBuilder::new(dst)?);
        self.routes.push(builder.build());
        Ok(self)
    }

    /// Add a qdisc configuration.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let config = NetworkConfig::new()
    ///     .qdisc("eth0", |q| q.netem().delay_ms(100).loss(1.0))
    ///     .qdisc("eth1", |q| q.htb().default_class(0x30));
    /// ```
    pub fn qdisc(mut self, dev: &str, f: impl FnOnce(QdiscBuilder) -> QdiscBuilder) -> Self {
        let builder = f(QdiscBuilder::new(dev));
        self.qdiscs.push(builder.build());
        self
    }

    /// Get the configured links.
    pub fn links(&self) -> &[DeclaredLink] {
        &self.links
    }

    /// Get the configured addresses.
    pub fn addresses(&self) -> &[DeclaredAddress] {
        &self.addresses
    }

    /// Get the configured routes.
    pub fn routes(&self) -> &[DeclaredRoute] {
        &self.routes
    }

    /// Get the configured qdiscs.
    pub fn qdiscs(&self) -> &[DeclaredQdisc] {
        &self.qdiscs
    }
}

// ============================================================================
// Link Types
// ============================================================================

/// Declared link configuration.
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case"))]
#[derive(Debug, Clone)]
pub struct DeclaredLink {
    pub(crate) name: String,
    pub(crate) link_type: DeclaredLinkType,
    pub(crate) state: LinkState,
    pub(crate) mtu: Option<u32>,
    pub(crate) master: Option<String>,
    pub(crate) address: Option<[u8; 6]>,
}

impl DeclaredLink {
    /// Get the interface name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Get the link type.
    pub fn link_type(&self) -> &DeclaredLinkType {
        &self.link_type
    }

    /// Get the desired state.
    pub fn state(&self) -> LinkState {
        self.state
    }

    /// Get the desired MTU.
    pub fn mtu(&self) -> Option<u32> {
        self.mtu
    }

    /// Get the master interface name.
    pub fn master(&self) -> Option<&str> {
        self.master.as_deref()
    }
}

/// Link type for declared configuration.
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum DeclaredLinkType {
    /// Dummy interface.
    Dummy,
    /// Veth pair with peer name.
    Veth { peer: String },
    /// Bridge interface.
    Bridge,
    /// VLAN interface. Plan 190 §2.2 added `protocol`.
    Vlan {
        parent: String,
        vlan_id: u16,
        /// VLAN tagging protocol; `None` == kernel default
        /// (802.1Q). Use [`VlanProtocol::Dot1ad`] for Q-in-Q.
        protocol: Option<VlanProtocol>,
    },
    /// VXLAN interface. Plan 190 §2.1 added `local`/`port`/`underlay_dev`.
    Vxlan {
        vni: u32,
        remote: Option<IpAddr>,
        /// Tunnel source IP (`IFLA_VXLAN_LOCAL` /
        /// `IFLA_VXLAN_LOCAL6`). IPv4 only at the imperative
        /// layer today — IPv6 source addresses ignored.
        local: Option<IpAddr>,
        /// UDP encap port (`IFLA_VXLAN_PORT`, default 4789).
        port: Option<u16>,
        /// Underlay parent device by name
        /// (`IFLA_VXLAN_LINK`).
        underlay_dev: Option<String>,
    },
    /// Macvlan interface.
    Macvlan { parent: String, mode: MacvlanMode },
    /// Bond interface. Plan 190 §8 added 5 new option knobs.
    Bond {
        mode: BondMode,
        miimon: Option<u32>,
        xmit_hash_policy: Option<u8>,
        min_links: Option<u32>,
        /// 802.3ad aggregator selection logic. Plan 190 §8.
        ad_select: Option<BondAdSelect>,
        /// LACPDU transmit rate. Plan 190 §8.
        lacp_rate: Option<BondLacpRate>,
        /// Time (ms) to wait before disabling a slave on
        /// link-down. Plan 190 §8.
        downdelay: Option<u32>,
        /// Time (ms) to wait before enabling a slave on
        /// link-up. Plan 190 §8.
        updelay: Option<u32>,
        /// Number of IGMP membership reports to resend on
        /// failover. Plan 190 §8.
        resend_igmp: Option<u32>,
    },
    /// IFB (Intermediate Functional Block).
    Ifb,
    /// VRF (Virtual Routing & Forwarding) — table-scoped
    /// forwarding domain. Members enslave via
    /// [`LinkBuilder::master`]. Plan 190 §2.3.
    Vrf { table: u32 },
    /// OpenVPN data-channel-offload link (kernel 6.16+).
    /// Link-half only — peer / cipher config goes through
    /// the GENL `ovpn` family (Plan 197 / 0.20). Plan 190 §2.3b.
    Ovpn,
    /// Netkit BPF-programmable veth pair (kernel 6.7+).
    /// Plan 190 §2.3a.
    Netkit {
        /// Name of the peer interface.
        peer: String,
        /// L2 vs L3 operating mode.
        mode: Option<NetkitMode>,
        /// Default policy on the primary peer.
        primary_policy: Option<NetkitPolicy>,
        /// Default policy on the peer interface.
        peer_policy: Option<NetkitPolicy>,
        /// Scrub mode on the primary peer (kernel 6.10+).
        scrub: Option<NetkitScrub>,
        /// Scrub mode on the peer interface (kernel 6.10+).
        peer_scrub: Option<NetkitScrub>,
    },
    /// Existing physical interface (not created, only configured).
    Physical,
}

impl DeclaredLinkType {
    /// Get the kind string for this link type.
    pub fn kind(&self) -> Option<&str> {
        match self {
            Self::Dummy => Some("dummy"),
            Self::Veth { .. } => Some("veth"),
            Self::Bridge => Some("bridge"),
            Self::Vlan { .. } => Some("vlan"),
            Self::Vxlan { .. } => Some("vxlan"),
            Self::Macvlan { .. } => Some("macvlan"),
            Self::Bond { .. } => Some("bond"),
            Self::Ifb => Some("ifb"),
            Self::Vrf { .. } => Some("vrf"),
            Self::Netkit { .. } => Some("netkit"),
            Self::Ovpn => Some("ovpn"),
            Self::Physical => None,
        }
    }
}

/// Link state (up or down).
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum LinkState {
    /// Interface should be up.
    Up,
    /// Interface should be down.
    #[default]
    Down,
    /// Don't change the state.
    Unchanged,
}

/// Macvlan mode.
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum MacvlanMode {
    /// Private mode (no communication between macvlans).
    Private,
    /// VEPA mode (Virtual Ethernet Port Aggregator).
    Vepa,
    /// Bridge mode (macvlans can communicate).
    #[default]
    Bridge,
    /// Passthru mode (single macvlan, exclusive access).
    Passthru,
    /// Source mode (filter by source MAC).
    Source,
}

/// Bond mode.
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum BondMode {
    /// Round-robin (balance-rr).
    #[default]
    BalanceRr,
    /// Active-backup.
    ActiveBackup,
    /// XOR (balance-xor).
    BalanceXor,
    /// Broadcast.
    Broadcast,
    /// 802.3ad (LACP).
    Ieee802_3ad,
    /// Transmit load balancing.
    BalanceTlb,
    /// Adaptive load balancing.
    BalanceAlb,
}

/// Builder for link configuration.
#[derive(Debug)]
#[must_use = "builders do nothing unless used"]
pub struct LinkBuilder {
    name: String,
    link_type: DeclaredLinkType,
    state: LinkState,
    mtu: Option<u32>,
    master: Option<String>,
    address: Option<[u8; 6]>,
}

impl LinkBuilder {
    fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            link_type: DeclaredLinkType::Physical,
            state: LinkState::Unchanged,
            mtu: None,
            master: None,
            address: None,
        }
    }

    /// Create a dummy interface.
    pub fn dummy(mut self) -> Self {
        self.link_type = DeclaredLinkType::Dummy;
        self
    }

    /// Create a veth pair with the given peer name.
    pub fn veth(mut self, peer: &str) -> Self {
        self.link_type = DeclaredLinkType::Veth {
            peer: peer.to_string(),
        };
        self
    }

    /// Create a bridge interface.
    pub fn bridge(mut self) -> Self {
        self.link_type = DeclaredLinkType::Bridge;
        self
    }

    /// Create a VLAN interface on the given parent with the specified VLAN ID.
    pub fn vlan(mut self, parent: &str, vlan_id: u16) -> Self {
        self.link_type = DeclaredLinkType::Vlan {
            parent: parent.to_string(),
            vlan_id,
            protocol: None,
        };
        self
    }

    /// Set the VLAN tagging protocol. Defaults to 802.1Q
    /// (kernel default) when unset. Use
    /// [`VlanProtocol::Dot1ad`] for Q-in-Q stacked VLAN
    /// encap. Plan 190 §2.2. No-op if the link isn't a VLAN.
    pub fn vlan_protocol(mut self, p: VlanProtocol) -> Self {
        if let DeclaredLinkType::Vlan { protocol, .. } = &mut self.link_type {
            *protocol = Some(p);
        }
        self
    }

    /// Create a VXLAN interface with the given VNI.
    pub fn vxlan(mut self, vni: u32) -> Self {
        self.link_type = DeclaredLinkType::Vxlan {
            vni,
            remote: None,
            local: None,
            port: None,
            underlay_dev: None,
        };
        self
    }

    /// Set the VXLAN remote endpoint. No-op if the builder
    /// isn't a VXLAN.
    pub fn vxlan_remote(mut self, remote_addr: IpAddr) -> Self {
        if let DeclaredLinkType::Vxlan { remote, .. } = &mut self.link_type {
            *remote = Some(remote_addr);
        }
        self
    }

    /// Set the VXLAN tunnel source IP (`IFLA_VXLAN_LOCAL`).
    /// The local address must be configured on the underlay
    /// interface — the kernel rejects mismatches.
    /// Plan 190 §2.1.
    pub fn vxlan_local(mut self, local_addr: IpAddr) -> Self {
        if let DeclaredLinkType::Vxlan { local, .. } = &mut self.link_type {
            *local = Some(local_addr);
        }
        self
    }

    /// Set the VXLAN UDP encap port (`IFLA_VXLAN_PORT`,
    /// default 4789). Plan 190 §2.1.
    pub fn vxlan_port(mut self, udp_port: u16) -> Self {
        if let DeclaredLinkType::Vxlan { port, .. } = &mut self.link_type {
            *port = Some(udp_port);
        }
        self
    }

    /// Set the VXLAN underlay parent device name
    /// (`IFLA_VXLAN_LINK`). Plan 190 §2.1.
    pub fn vxlan_underlay_dev(mut self, dev: impl Into<String>) -> Self {
        if let DeclaredLinkType::Vxlan {
            underlay_dev, ..
        } = &mut self.link_type
        {
            *underlay_dev = Some(dev.into());
        }
        self
    }

    /// Create a macvlan interface on the given parent.
    pub fn macvlan(mut self, parent: &str) -> Self {
        self.link_type = DeclaredLinkType::Macvlan {
            parent: parent.to_string(),
            mode: MacvlanMode::default(),
        };
        self
    }

    /// Set the macvlan mode.
    pub fn macvlan_mode(mut self, mode: MacvlanMode) -> Self {
        if let DeclaredLinkType::Macvlan { parent, .. } = &self.link_type {
            self.link_type = DeclaredLinkType::Macvlan {
                parent: parent.clone(),
                mode,
            };
        }
        self
    }

    /// Create a bond interface.
    pub fn bond(mut self) -> Self {
        self.link_type = DeclaredLinkType::Bond {
            mode: BondMode::default(),
            miimon: None,
            xmit_hash_policy: None,
            min_links: None,
            ad_select: None,
            lacp_rate: None,
            downdelay: None,
            updelay: None,
            resend_igmp: None,
        };
        self
    }

    /// Set the bond mode.
    pub fn bond_mode(mut self, mode: BondMode) -> Self {
        if let DeclaredLinkType::Bond {
            mode: ref mut m, ..
        } = self.link_type
        {
            *m = mode;
        }
        self
    }

    /// Set the MII monitoring interval in milliseconds.
    pub fn miimon(mut self, ms: u32) -> Self {
        if let DeclaredLinkType::Bond { miimon, .. } = &mut self.link_type {
            *miimon = Some(ms);
        }
        self
    }

    /// Set the transmit hash policy (0=Layer2, 1=Layer34, 2=Layer23).
    pub fn xmit_hash_policy(mut self, policy: u8) -> Self {
        if let DeclaredLinkType::Bond {
            xmit_hash_policy, ..
        } = &mut self.link_type
        {
            *xmit_hash_policy = Some(policy);
        }
        self
    }

    /// Set the minimum number of active links.
    pub fn min_links(mut self, count: u32) -> Self {
        if let DeclaredLinkType::Bond { min_links, .. } = &mut self.link_type {
            *min_links = Some(count);
        }
        self
    }

    /// Set the 802.3ad aggregator selection logic.
    /// No-op on non-Bond builders. Plan 190 §8.
    pub fn bond_ad_select(mut self, sel: BondAdSelect) -> Self {
        if let DeclaredLinkType::Bond { ad_select, .. } = &mut self.link_type {
            *ad_select = Some(sel);
        }
        self
    }

    /// Set the LACPDU transmit rate (Slow=30s, Fast=1s).
    /// No-op on non-Bond builders. Plan 190 §8.
    pub fn bond_lacp_rate(mut self, rate: BondLacpRate) -> Self {
        if let DeclaredLinkType::Bond { lacp_rate, .. } = &mut self.link_type {
            *lacp_rate = Some(rate);
        }
        self
    }

    /// Set the time (ms) to wait before disabling a slave on
    /// link-down. No-op on non-Bond builders. Plan 190 §8.
    pub fn bond_downdelay(mut self, ms: u32) -> Self {
        if let DeclaredLinkType::Bond { downdelay, .. } = &mut self.link_type {
            *downdelay = Some(ms);
        }
        self
    }

    /// Set the time (ms) to wait before enabling a slave on
    /// link-up. No-op on non-Bond builders. Plan 190 §8.
    pub fn bond_updelay(mut self, ms: u32) -> Self {
        if let DeclaredLinkType::Bond { updelay, .. } = &mut self.link_type {
            *updelay = Some(ms);
        }
        self
    }

    /// Set the number of IGMP membership reports to resend
    /// on failover. No-op on non-Bond builders. Plan 190 §8.
    pub fn bond_resend_igmp(mut self, count: u32) -> Self {
        if let DeclaredLinkType::Bond { resend_igmp, .. } = &mut self.link_type {
            *resend_igmp = Some(count);
        }
        self
    }

    /// Create an IFB interface.
    pub fn ifb(mut self) -> Self {
        self.link_type = DeclaredLinkType::Ifb;
        self
    }

    /// Build an OpenVPN data-channel-offload link (kernel
    /// 6.16+). Link half only — peer / cipher config goes
    /// through the GENL `ovpn` family (deferred to Plan
    /// 197). Plan 190 §2.3b.
    pub fn ovpn(mut self) -> Self {
        self.link_type = DeclaredLinkType::Ovpn;
        self
    }

    /// Build a netkit BPF-programmable veth pair (kernel
    /// 6.7+). The `peer` argument names the peer interface;
    /// both ends are created atomically. Use
    /// [`LinkBuilder::netkit_mode`] / `netkit_primary_policy` /
    /// `netkit_peer_policy` / `netkit_scrub` /
    /// `netkit_peer_scrub` to refine. Plan 190 §2.3a.
    pub fn netkit(mut self, peer: impl Into<String>) -> Self {
        self.link_type = DeclaredLinkType::Netkit {
            peer: peer.into(),
            mode: None,
            primary_policy: None,
            peer_policy: None,
            scrub: None,
            peer_scrub: None,
        };
        self
    }

    /// Set netkit L2 vs L3 mode. No-op on non-netkit builders.
    pub fn netkit_mode(mut self, m: NetkitMode) -> Self {
        if let DeclaredLinkType::Netkit { mode, .. } = &mut self.link_type {
            *mode = Some(m);
        }
        self
    }

    /// Set the netkit primary-peer default policy. No-op on
    /// non-netkit builders.
    pub fn netkit_primary_policy(mut self, p: NetkitPolicy) -> Self {
        if let DeclaredLinkType::Netkit { primary_policy, .. } = &mut self.link_type {
            *primary_policy = Some(p);
        }
        self
    }

    /// Set the netkit peer default policy. No-op on
    /// non-netkit builders.
    pub fn netkit_peer_policy(mut self, p: NetkitPolicy) -> Self {
        if let DeclaredLinkType::Netkit { peer_policy, .. } = &mut self.link_type {
            *peer_policy = Some(p);
        }
        self
    }

    /// Set the netkit primary-peer scrub mode (kernel 6.10+).
    /// No-op on non-netkit builders.
    pub fn netkit_scrub(mut self, s: NetkitScrub) -> Self {
        if let DeclaredLinkType::Netkit { scrub, .. } = &mut self.link_type {
            *scrub = Some(s);
        }
        self
    }

    /// Set the netkit peer scrub mode (kernel 6.10+). No-op
    /// on non-netkit builders.
    pub fn netkit_peer_scrub(mut self, s: NetkitScrub) -> Self {
        if let DeclaredLinkType::Netkit { peer_scrub, .. } = &mut self.link_type {
            *peer_scrub = Some(s);
        }
        self
    }

    /// Build a VRF link bound to routing-table `table`.
    ///
    /// VRF (Virtual Routing & Forwarding) groups interfaces
    /// under a per-table forwarding domain; common in
    /// multi-tenant networks. Members enslave via
    /// [`LinkBuilder::master`].
    ///
    /// Requires the kernel `vrf` module. Plan 190 §2.3.
    pub fn vrf(mut self, table: u32) -> Self {
        self.link_type = DeclaredLinkType::Vrf { table };
        self
    }

    /// Set the interface state to up.
    pub fn up(mut self) -> Self {
        self.state = LinkState::Up;
        self
    }

    /// Set the interface state to down.
    pub fn down(mut self) -> Self {
        self.state = LinkState::Down;
        self
    }

    /// Set the MTU.
    pub fn mtu(mut self, mtu: u32) -> Self {
        self.mtu = Some(mtu);
        self
    }

    /// Set the master interface (for bridging/bonding).
    pub fn master(mut self, master: &str) -> Self {
        self.master = Some(master.to_string());
        self
    }

    /// Set the MAC address.
    pub fn address(mut self, addr: [u8; 6]) -> Self {
        self.address = Some(addr);
        self
    }

    fn build(self) -> DeclaredLink {
        DeclaredLink {
            name: self.name,
            link_type: self.link_type,
            state: self.state,
            mtu: self.mtu,
            master: self.master,
            address: self.address,
        }
    }
}

// ============================================================================
// Address Types
// ============================================================================

/// Declared address configuration.
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case"))]
#[derive(Debug, Clone)]
pub struct DeclaredAddress {
    pub(crate) dev: String,
    pub(crate) address: IpAddr,
    pub(crate) prefix_len: u8,
}

impl DeclaredAddress {
    /// Parse an address from CIDR notation.
    pub fn parse(dev: &str, addr: &str) -> Result<Self, AddressParseError> {
        let (ip_str, prefix_str) = addr
            .split_once('/')
            .ok_or_else(|| AddressParseError::MissingPrefix(addr.to_string()))?;

        let address: IpAddr = ip_str
            .parse()
            .map_err(|_| AddressParseError::InvalidAddress(ip_str.to_string()))?;

        let prefix_len: u8 = prefix_str
            .parse()
            .map_err(|_| AddressParseError::InvalidPrefix(prefix_str.to_string()))?;

        // Validate prefix length
        let max_prefix = if address.is_ipv4() { 32 } else { 128 };
        if prefix_len > max_prefix {
            return Err(AddressParseError::PrefixTooLarge {
                prefix: prefix_len,
                max: max_prefix,
            });
        }

        Ok(Self {
            dev: dev.to_string(),
            address,
            prefix_len,
        })
    }

    /// Get the device name.
    pub fn dev(&self) -> &str {
        &self.dev
    }

    /// Get the IP address.
    pub fn address(&self) -> IpAddr {
        self.address
    }

    /// Get the prefix length.
    pub fn prefix_len(&self) -> u8 {
        self.prefix_len
    }

    /// Check if this is an IPv4 address.
    pub fn is_ipv4(&self) -> bool {
        self.address.is_ipv4()
    }

    /// Check if this is an IPv6 address.
    pub fn is_ipv6(&self) -> bool {
        self.address.is_ipv6()
    }
}

/// Error parsing an address.
#[derive(Debug, Clone, thiserror::Error)]
#[non_exhaustive]
pub enum AddressParseError {
    /// Address is missing prefix (no "/").
    #[error("address missing prefix: {0} (expected format: 192.168.1.1/24)")]
    MissingPrefix(String),
    /// Invalid IP address.
    #[error("invalid IP address: {0}")]
    InvalidAddress(String),
    /// Invalid prefix length.
    #[error("invalid prefix length: {0}")]
    InvalidPrefix(String),
    /// Prefix length too large.
    #[error("prefix length {prefix} exceeds maximum {max}")]
    PrefixTooLarge { prefix: u8, max: u8 },
}

// ============================================================================
// Route Types
// ============================================================================

/// Declared route configuration.
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case"))]
#[derive(Debug, Clone)]
pub struct DeclaredRoute {
    pub(crate) destination: IpAddr,
    pub(crate) prefix_len: u8,
    pub(crate) gateway: Option<IpAddr>,
    pub(crate) dev: Option<String>,
    pub(crate) metric: Option<u32>,
    pub(crate) table: Option<u32>,
    pub(crate) route_type: DeclaredRouteType,
}

impl DeclaredRoute {
    /// Get the destination address.
    pub fn destination(&self) -> IpAddr {
        self.destination
    }

    /// Get the prefix length.
    pub fn prefix_len(&self) -> u8 {
        self.prefix_len
    }

    /// Get the gateway address.
    pub fn gateway(&self) -> Option<IpAddr> {
        self.gateway
    }

    /// Get the output device.
    pub fn dev(&self) -> Option<&str> {
        self.dev.as_deref()
    }

    /// Get the route metric.
    pub fn metric(&self) -> Option<u32> {
        self.metric
    }

    /// Get the routing table.
    pub fn table(&self) -> Option<u32> {
        self.table
    }

    /// Get the route type.
    pub fn route_type(&self) -> DeclaredRouteType {
        self.route_type
    }

    /// Check if this is an IPv4 route.
    pub fn is_ipv4(&self) -> bool {
        self.destination.is_ipv4()
    }

    /// Check if this is an IPv6 route.
    pub fn is_ipv6(&self) -> bool {
        self.destination.is_ipv6()
    }
}

/// Route type for declared configuration.
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum DeclaredRouteType {
    /// Normal unicast route.
    #[default]
    Unicast,
    /// Blackhole (silently drop).
    Blackhole,
    /// Unreachable (ICMP unreachable).
    Unreachable,
    /// Prohibit (ICMP prohibited).
    Prohibit,
}

/// Error parsing a route.
#[derive(Debug, Clone, thiserror::Error)]
#[non_exhaustive]
pub enum RouteParseError {
    /// Destination is missing prefix.
    #[error("destination missing prefix: {0} (expected format: 10.0.0.0/8)")]
    MissingPrefix(String),
    /// Invalid destination address.
    #[error("invalid destination address: {0}")]
    InvalidDestination(String),
    /// Invalid prefix length.
    #[error("invalid prefix length: {0}")]
    InvalidPrefix(String),
    /// Prefix length too large.
    #[error("prefix length {prefix} exceeds maximum {max}")]
    PrefixTooLarge { prefix: u8, max: u8 },
    /// Invalid gateway address.
    #[error("invalid gateway address: {0}")]
    InvalidGateway(String),
}

/// Builder for route configuration.
#[derive(Debug)]
#[must_use = "builders do nothing unless used"]
pub struct RouteBuilder {
    destination: IpAddr,
    prefix_len: u8,
    gateway: Option<IpAddr>,
    dev: Option<String>,
    metric: Option<u32>,
    table: Option<u32>,
    route_type: DeclaredRouteType,
}

impl RouteBuilder {
    /// `RouteBuilder` whose destination is `0.0.0.0/0` — the
    /// IPv4 default route. Mirrors [`crate::Ipv4Route::default_route`]
    /// (Plan 184) on the declarative side. Pairs with `.via()` to
    /// set the gateway:
    ///
    /// ```ignore
    /// use nlink::netlink::config::RouteBuilder;
    /// let r = RouteBuilder::default_v4().via("192.0.2.1");
    /// ```
    ///
    /// Plan 188 §2.3.
    pub fn default_v4() -> Self {
        // 0.0.0.0/0 is always a valid IPv4 CIDR; expect is safe.
        Self::new("0.0.0.0/0").expect("0.0.0.0/0 is a valid IPv4 CIDR")
    }

    /// `RouteBuilder` whose destination is `::/0` — the IPv6
    /// default route. Mirrors [`crate::Ipv6Route::default_route`].
    ///
    /// Plan 188 §2.3.
    pub fn default_v6() -> Self {
        Self::new("::/0").expect("::/0 is a valid IPv6 CIDR")
    }

    fn new(dst: &str) -> Result<Self, RouteParseError> {
        let (ip_str, prefix_str) = dst
            .split_once('/')
            .ok_or_else(|| RouteParseError::MissingPrefix(dst.to_string()))?;

        let destination: IpAddr = ip_str
            .parse()
            .map_err(|_| RouteParseError::InvalidDestination(ip_str.to_string()))?;

        let prefix_len: u8 = prefix_str
            .parse()
            .map_err(|_| RouteParseError::InvalidPrefix(prefix_str.to_string()))?;

        let max_prefix = if destination.is_ipv4() { 32 } else { 128 };
        if prefix_len > max_prefix {
            return Err(RouteParseError::PrefixTooLarge {
                prefix: prefix_len,
                max: max_prefix,
            });
        }

        Ok(Self {
            destination,
            prefix_len,
            gateway: None,
            dev: None,
            metric: None,
            table: None,
            route_type: DeclaredRouteType::default(),
        })
    }

    /// Set the gateway address.
    pub fn via(mut self, gateway: &str) -> Self {
        if let Ok(addr) = gateway.parse() {
            self.gateway = Some(addr);
        }
        self
    }

    /// Set the output device.
    pub fn dev(mut self, dev: &str) -> Self {
        self.dev = Some(dev.to_string());
        self
    }

    /// Set the route metric (priority).
    pub fn metric(mut self, metric: u32) -> Self {
        self.metric = Some(metric);
        self
    }

    /// Set the routing table.
    pub fn table(mut self, table: u32) -> Self {
        self.table = Some(table);
        self
    }

    /// Make this a blackhole route.
    pub fn blackhole(mut self) -> Self {
        self.route_type = DeclaredRouteType::Blackhole;
        self
    }

    /// Make this an unreachable route.
    pub fn unreachable(mut self) -> Self {
        self.route_type = DeclaredRouteType::Unreachable;
        self
    }

    /// Make this a prohibit route.
    pub fn prohibit(mut self) -> Self {
        self.route_type = DeclaredRouteType::Prohibit;
        self
    }

    fn build(self) -> DeclaredRoute {
        DeclaredRoute {
            destination: self.destination,
            prefix_len: self.prefix_len,
            gateway: self.gateway,
            dev: self.dev,
            metric: self.metric,
            table: self.table,
            route_type: self.route_type,
        }
    }
}

// ============================================================================
// Qdisc Types
// ============================================================================

/// Declared qdisc configuration.
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case"))]
#[derive(Debug, Clone)]
pub struct DeclaredQdisc {
    pub(crate) dev: String,
    pub(crate) parent: QdiscParent,
    pub(crate) qdisc_type: DeclaredQdiscType,
}

impl DeclaredQdisc {
    /// Get the device name.
    pub fn dev(&self) -> &str {
        &self.dev
    }

    /// Get the parent.
    pub fn parent(&self) -> QdiscParent {
        self.parent
    }

    /// Get the qdisc type.
    pub fn qdisc_type(&self) -> &DeclaredQdiscType {
        &self.qdisc_type
    }
}

/// Qdisc parent location.
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum QdiscParent {
    /// Root qdisc.
    #[default]
    Root,
    /// Ingress qdisc.
    Ingress,
}

/// Qdisc type for declared configuration.
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum DeclaredQdiscType {
    /// Network emulator.
    Netem {
        delay_us: Option<u32>,
        jitter_us: Option<u32>,
        loss_percent: Option<f64>,
        limit: Option<u32>,
    },
    /// Hierarchical Token Bucket.
    Htb { default_class: u32 },
    /// Fair Queueing Controlled Delay.
    FqCodel {
        limit: Option<u32>,
        target_us: Option<u32>,
        interval_us: Option<u32>,
    },
    /// Token Bucket Filter.
    Tbf {
        rate_bps: u64,
        burst_bytes: u32,
        limit_bytes: Option<u32>,
    },
    /// Stochastic Fair Queueing.
    Sfq { perturb_secs: Option<u32> },
    /// Priority qdisc.
    Prio { bands: Option<u8> },
    /// Ingress qdisc.
    Ingress,
    /// Clsact qdisc (for BPF).
    Clsact,
}

impl DeclaredQdiscType {
    /// Get the kind string.
    pub fn kind(&self) -> &str {
        match self {
            Self::Netem { .. } => "netem",
            Self::Htb { .. } => "htb",
            Self::FqCodel { .. } => "fq_codel",
            Self::Tbf { .. } => "tbf",
            Self::Sfq { .. } => "sfq",
            Self::Prio { .. } => "prio",
            Self::Ingress => "ingress",
            Self::Clsact => "clsact",
        }
    }
}

/// Builder for qdisc configuration.
#[derive(Debug)]
#[must_use = "builders do nothing unless used"]
pub struct QdiscBuilder {
    dev: String,
    parent: QdiscParent,
    qdisc_type: Option<DeclaredQdiscType>,
}

impl QdiscBuilder {
    fn new(dev: &str) -> Self {
        Self {
            dev: dev.to_string(),
            parent: QdiscParent::Root,
            qdisc_type: None,
        }
    }

    /// Configure as netem qdisc.
    pub fn netem(mut self) -> Self {
        self.qdisc_type = Some(DeclaredQdiscType::Netem {
            delay_us: None,
            jitter_us: None,
            loss_percent: None,
            limit: None,
        });
        self
    }

    /// Set netem delay in milliseconds.
    pub fn delay_ms(mut self, ms: u32) -> Self {
        if let Some(DeclaredQdiscType::Netem { delay_us, .. }) = &mut self.qdisc_type {
            *delay_us = Some(ms * 1000);
        }
        self
    }

    /// Set netem delay in microseconds.
    pub fn delay_us(mut self, us: u32) -> Self {
        if let Some(DeclaredQdiscType::Netem { delay_us, .. }) = &mut self.qdisc_type {
            *delay_us = Some(us);
        }
        self
    }

    /// Set netem jitter in milliseconds.
    pub fn jitter_ms(mut self, ms: u32) -> Self {
        if let Some(DeclaredQdiscType::Netem { jitter_us, .. }) = &mut self.qdisc_type {
            *jitter_us = Some(ms * 1000);
        }
        self
    }

    /// Set netem packet loss percentage.
    ///
    /// **Deprecated** in 0.20.1: use [`Self::loss_pct`] with the typed
    /// [`crate::util::Percent`] newtype. The raw-`f64` form silently
    /// accepts out-of-range and NaN values; the typed sibling clamps
    /// to `[0, 100]` and rejects non-finite inputs through `Percent::new`.
    ///
    /// The unit-confusion footgun (fraction vs percent) is the bug class
    /// `Percent::from_fraction` was added to kill.
    #[deprecated(
        since = "0.20.1",
        note = "use loss_pct(Percent::new(x)) instead — closes the units-confusion bug class"
    )]
    pub fn loss(mut self, percent: f64) -> Self {
        if let Some(DeclaredQdiscType::Netem { loss_percent, .. }) = &mut self.qdisc_type {
            *loss_percent = Some(percent);
        }
        self
    }

    /// Set netem packet loss as a typed [`crate::util::Percent`].
    ///
    /// This is the typed sibling of the deprecated [`Self::loss`].
    /// Internally stores the clamped `f64` so the wire-format diff
    /// machinery (which compares with `PartialEq` on `Option<f64>`)
    /// stays stable. The boundary type at the setter is what kills
    /// the wrong-units footgun.
    pub fn loss_pct(mut self, percent: crate::util::Percent) -> Self {
        if let Some(DeclaredQdiscType::Netem { loss_percent, .. }) = &mut self.qdisc_type {
            *loss_percent = Some(percent.as_percent());
        }
        self
    }

    /// Set netem queue limit.
    pub fn limit(mut self, packets: u32) -> Self {
        if let Some(DeclaredQdiscType::Netem { limit, .. }) = &mut self.qdisc_type {
            *limit = Some(packets);
        }
        self
    }

    /// Configure as HTB qdisc.
    pub fn htb(mut self) -> Self {
        self.qdisc_type = Some(DeclaredQdiscType::Htb { default_class: 0 });
        self
    }

    /// Set HTB default class.
    pub fn default_class(mut self, class: u32) -> Self {
        if let Some(DeclaredQdiscType::Htb { default_class }) = &mut self.qdisc_type {
            *default_class = class;
        }
        self
    }

    /// Configure as fq_codel qdisc.
    pub fn fq_codel(mut self) -> Self {
        self.qdisc_type = Some(DeclaredQdiscType::FqCodel {
            limit: None,
            target_us: None,
            interval_us: None,
        });
        self
    }

    /// Configure as TBF qdisc.
    pub fn tbf(mut self, rate_bps: u64, burst_bytes: u32) -> Self {
        self.qdisc_type = Some(DeclaredQdiscType::Tbf {
            rate_bps,
            burst_bytes,
            limit_bytes: None,
        });
        self
    }

    /// Configure as SFQ qdisc.
    pub fn sfq(mut self) -> Self {
        self.qdisc_type = Some(DeclaredQdiscType::Sfq { perturb_secs: None });
        self
    }

    /// Configure as prio qdisc.
    pub fn prio(mut self) -> Self {
        self.qdisc_type = Some(DeclaredQdiscType::Prio { bands: None });
        self
    }

    /// Configure as ingress qdisc.
    pub fn ingress(mut self) -> Self {
        self.parent = QdiscParent::Ingress;
        self.qdisc_type = Some(DeclaredQdiscType::Ingress);
        self
    }

    /// Configure as clsact qdisc.
    pub fn clsact(mut self) -> Self {
        self.qdisc_type = Some(DeclaredQdiscType::Clsact);
        self
    }

    fn build(self) -> DeclaredQdisc {
        DeclaredQdisc {
            dev: self.dev,
            parent: self.parent,
            qdisc_type: self.qdisc_type.unwrap_or(DeclaredQdiscType::FqCodel {
                limit: None,
                target_us: None,
                interval_us: None,
            }),
        }
    }
}

#[cfg(test)]
mod plan_190_tests {
    //! Plan 190 — LinkBuilder gaps.
    //! Unit-level coverage for new DeclaredLinkType variants
    //! + LinkBuilder setters.

    use super::*;

    #[test]
    fn vrf_builder_sets_table() {
        let link = LinkBuilder::new("vrf-red").vrf(100).build();
        match link.link_type {
            DeclaredLinkType::Vrf { table } => assert_eq!(table, 100),
            other => panic!("expected DeclaredLinkType::Vrf, got {other:?}"),
        }
    }

    #[test]
    fn vrf_kind_string_is_vrf() {
        let lt = DeclaredLinkType::Vrf { table: 7 };
        assert_eq!(lt.kind(), Some("vrf"));
    }

    // -------- Plan 190 §2.3b — ovpn link half --------

    #[test]
    fn ovpn_builder_creates_ovpn_variant() {
        let link = LinkBuilder::new("ovpn0").ovpn().build();
        assert!(matches!(link.link_type, DeclaredLinkType::Ovpn));
    }

    #[test]
    fn ovpn_kind_string_is_ovpn() {
        assert_eq!(DeclaredLinkType::Ovpn.kind(), Some("ovpn"));
    }

    // -------- end Plan 190 §2.3b --------

    // -------- Plan 190 §2.3a — netkit --------

    #[test]
    fn netkit_builder_peer_carried_others_default_none() {
        let link = LinkBuilder::new("nk0").netkit("nk1").build();
        match link.link_type {
            DeclaredLinkType::Netkit {
                peer,
                mode,
                primary_policy,
                peer_policy,
                scrub,
                peer_scrub,
            } => {
                assert_eq!(peer, "nk1");
                assert!(mode.is_none());
                assert!(primary_policy.is_none());
                assert!(peer_policy.is_none());
                assert!(scrub.is_none());
                assert!(peer_scrub.is_none());
            }
            other => panic!("expected Netkit, got {other:?}"),
        }
    }

    #[test]
    fn netkit_builder_full_setter_chain() {
        let link = LinkBuilder::new("nk0")
            .netkit("nk1")
            .netkit_mode(NetkitMode::L2)
            .netkit_primary_policy(NetkitPolicy::Forward)
            .netkit_peer_policy(NetkitPolicy::Blackhole)
            .netkit_scrub(NetkitScrub::Default)
            .netkit_peer_scrub(NetkitScrub::None)
            .build();
        match link.link_type {
            DeclaredLinkType::Netkit {
                peer,
                mode,
                primary_policy,
                peer_policy,
                scrub,
                peer_scrub,
            } => {
                assert_eq!(peer, "nk1");
                assert_eq!(mode, Some(NetkitMode::L2));
                assert_eq!(primary_policy, Some(NetkitPolicy::Forward));
                assert_eq!(peer_policy, Some(NetkitPolicy::Blackhole));
                assert_eq!(scrub, Some(NetkitScrub::Default));
                assert_eq!(peer_scrub, Some(NetkitScrub::None));
            }
            other => panic!("expected Netkit, got {other:?}"),
        }
    }

    #[test]
    fn netkit_kind_string_is_netkit() {
        let lt = DeclaredLinkType::Netkit {
            peer: "x".into(),
            mode: None,
            primary_policy: None,
            peer_policy: None,
            scrub: None,
            peer_scrub: None,
        };
        assert_eq!(lt.kind(), Some("netkit"));
    }

    // -------- end Plan 190 §2.3a --------

    // -------- Plan 190 §8 — Bond options gap-fill --------

    #[test]
    fn bond_builder_defaults_all_new_knobs_to_none() {
        let link = LinkBuilder::new("bond0").bond().build();
        match link.link_type {
            DeclaredLinkType::Bond {
                ad_select,
                lacp_rate,
                downdelay,
                updelay,
                resend_igmp,
                ..
            } => {
                assert!(ad_select.is_none());
                assert!(lacp_rate.is_none());
                assert!(downdelay.is_none());
                assert!(updelay.is_none());
                assert!(resend_igmp.is_none());
            }
            other => panic!("expected Bond, got {other:?}"),
        }
    }

    #[test]
    fn bond_builder_all_5_setters_round_trip() {
        let link = LinkBuilder::new("bond0")
            .bond()
            .bond_ad_select(BondAdSelect::Bandwidth)
            .bond_lacp_rate(BondLacpRate::Fast)
            .bond_downdelay(200)
            .bond_updelay(500)
            .bond_resend_igmp(3)
            .build();
        match link.link_type {
            DeclaredLinkType::Bond {
                ad_select,
                lacp_rate,
                downdelay,
                updelay,
                resend_igmp,
                ..
            } => {
                assert_eq!(ad_select, Some(BondAdSelect::Bandwidth));
                assert_eq!(lacp_rate, Some(BondLacpRate::Fast));
                assert_eq!(downdelay, Some(200));
                assert_eq!(updelay, Some(500));
                assert_eq!(resend_igmp, Some(3));
            }
            other => panic!("expected Bond, got {other:?}"),
        }
    }

    #[test]
    fn bond_setters_no_op_on_non_bond() {
        let link = LinkBuilder::new("eth0")
            .dummy()
            .bond_ad_select(BondAdSelect::Stable)
            .bond_lacp_rate(BondLacpRate::Slow)
            .bond_downdelay(100)
            .bond_updelay(100)
            .bond_resend_igmp(1)
            .build();
        assert!(matches!(link.link_type, DeclaredLinkType::Dummy));
    }

    // -------- end Plan 190 §8 --------

    // -------- Plan 190 §2.1 — VXLAN extras --------

    #[test]
    fn vxlan_builder_defaults_to_none_for_new_knobs() {
        let link = LinkBuilder::new("vx0").vxlan(42).build();
        match link.link_type {
            DeclaredLinkType::Vxlan {
                vni,
                remote,
                local,
                port,
                underlay_dev,
            } => {
                assert_eq!(vni, 42);
                assert!(remote.is_none());
                assert!(local.is_none());
                assert!(port.is_none());
                assert!(underlay_dev.is_none());
            }
            other => panic!("expected Vxlan, got {other:?}"),
        }
    }

    #[test]
    fn vxlan_builder_local_port_underlay_round_trip() {
        use std::net::Ipv4Addr;
        let link = LinkBuilder::new("vx0")
            .vxlan(100)
            .vxlan_remote(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)))
            .vxlan_local(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)))
            .vxlan_port(4790)
            .vxlan_underlay_dev("eth0")
            .build();
        match link.link_type {
            DeclaredLinkType::Vxlan {
                vni,
                remote,
                local,
                port,
                underlay_dev,
            } => {
                assert_eq!(vni, 100);
                assert_eq!(remote, Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
                assert_eq!(local, Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))));
                assert_eq!(port, Some(4790));
                assert_eq!(underlay_dev.as_deref(), Some("eth0"));
            }
            other => panic!("expected Vxlan, got {other:?}"),
        }
    }

    #[test]
    fn vxlan_setters_no_op_on_non_vxlan() {
        // Each new setter must early-return if the builder
        // isn't a VXLAN — same shape as vlan_protocol.
        use std::net::Ipv4Addr;
        let link = LinkBuilder::new("eth0")
            .dummy()
            .vxlan_local(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)))
            .vxlan_port(4790)
            .vxlan_underlay_dev("ignored")
            .build();
        assert!(matches!(link.link_type, DeclaredLinkType::Dummy));
    }

    // -------- end Plan 190 §2.1 --------

    // -------- Plan 190 §2.2 — VLAN protocol --------

    #[test]
    fn vlan_builder_protocol_defaults_to_none() {
        let link = LinkBuilder::new("eth0.100").vlan("eth0", 100).build();
        match link.link_type {
            DeclaredLinkType::Vlan { protocol, .. } => assert!(protocol.is_none()),
            other => panic!("expected Vlan, got {other:?}"),
        }
    }

    #[test]
    fn vlan_builder_protocol_setter_records_dot1ad() {
        let link = LinkBuilder::new("eth0.100")
            .vlan("eth0", 100)
            .vlan_protocol(VlanProtocol::Dot1ad)
            .build();
        match link.link_type {
            DeclaredLinkType::Vlan { protocol, .. } => {
                assert_eq!(protocol, Some(VlanProtocol::Dot1ad));
            }
            other => panic!("expected Vlan, got {other:?}"),
        }
    }

    #[test]
    fn vlan_protocol_setter_no_op_on_non_vlan() {
        // Calling vlan_protocol() on a builder that isn't a
        // VLAN should leave the link_type unchanged.
        let link = LinkBuilder::new("eth0")
            .dummy()
            .vlan_protocol(VlanProtocol::Dot1ad)
            .build();
        assert!(matches!(link.link_type, DeclaredLinkType::Dummy));
    }

    #[test]
    fn vlan_protocol_wire_values() {
        // 802.1Q == 0x8100, 802.1ad == 0x88a8. Pins the wire
        // contract for IFLA_VLAN_PROTOCOL emission.
        assert_eq!(VlanProtocol::Dot1q.as_u16(), 0x8100);
        assert_eq!(VlanProtocol::Dot1ad.as_u16(), 0x88a8);
    }

    // -------- end Plan 190 §2.2 --------

    #[test]
    fn vrf_in_network_config_carries_master_chain() {
        // The master() chain works alongside vrf(); confirms
        // recipes that enslave a dummy into a VRF via the
        // declarative path compose correctly.
        let cfg = NetworkConfig::new()
            .link("vrf-red", |b| b.vrf(100))
            .link("eth0", |b| b.dummy().master("vrf-red"));
        assert_eq!(cfg.links.len(), 2);
        assert!(matches!(
            cfg.links[0].link_type,
            DeclaredLinkType::Vrf { table: 100 }
        ));
        assert_eq!(cfg.links[1].master.as_deref(), Some("vrf-red"));
    }
}

#[cfg(test)]
mod plan_228_tests {
    //! Plan 228 — typed Percent on declarative QdiscBuilder.
    //!
    //! Adversarial coverage that the new `loss_pct(Percent)` and the
    //! deprecated `loss(f64)` produce identical stored state for sane
    //! inputs, and that the typed sibling clamps adversarial floats
    //! while the raw f64 path lets them through.

    use super::*;
    use crate::util::Percent;

    fn netem_loss(q: &DeclaredQdisc) -> Option<f64> {
        match &q.qdisc_type {
            DeclaredQdiscType::Netem { loss_percent, .. } => *loss_percent,
            _ => None,
        }
    }

    #[test]
    fn loss_pct_parity_with_loss_for_sane_input() {
        let typed = QdiscBuilder::new("eth0").netem().loss_pct(Percent::new(1.5));
        let typed_q = typed.build();
        #[allow(deprecated)]
        let raw = QdiscBuilder::new("eth0").netem().loss(1.5);
        let raw_q = raw.build();
        assert_eq!(netem_loss(&typed_q), netem_loss(&raw_q));
    }

    #[test]
    fn loss_pct_clamps_supra_100() {
        let q = QdiscBuilder::new("eth0")
            .netem()
            .loss_pct(Percent::new(150.0))
            .build();
        assert_eq!(netem_loss(&q), Some(100.0));
    }

    #[test]
    fn loss_pct_clamps_negative() {
        let q = QdiscBuilder::new("eth0")
            .netem()
            .loss_pct(Percent::new(-1.5))
            .build();
        assert_eq!(netem_loss(&q), Some(0.0));
    }

    #[test]
    fn loss_pct_handles_nan() {
        // Percent::new uses clamp which for f64 NaN returns NaN.
        // Document the behaviour at the typed boundary — adversarial
        // callers learn the failure mode here rather than discovering
        // a kernel rejection at apply time.
        let q = QdiscBuilder::new("eth0")
            .netem()
            .loss_pct(Percent::new(f64::NAN))
            .build();
        // NaN propagates through clamp; verify the stored value is NaN.
        let v = netem_loss(&q).expect("loss_percent set");
        assert!(v.is_nan(), "Percent::new(NaN) → stored NaN (documented)");
    }

    #[test]
    fn loss_pct_handles_infinity() {
        let q = QdiscBuilder::new("eth0")
            .netem()
            .loss_pct(Percent::new(f64::INFINITY))
            .build();
        // Infinity clamps to 100.
        assert_eq!(netem_loss(&q), Some(100.0));
    }

    #[test]
    fn loss_pct_from_fraction_distinguishes_units() {
        // The headline footgun the typed boundary kills: f64 mixed
        // fraction-vs-percent. Percent::from_fraction(0.015) = 1.5%.
        let q = QdiscBuilder::new("eth0")
            .netem()
            .loss_pct(Percent::from_fraction(0.015))
            .build();
        assert_eq!(netem_loss(&q), Some(1.5));
    }
}
