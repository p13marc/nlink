//! Core types for declarative network configuration.

use std::net::IpAddr;

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
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeclaredLinkType {
    /// Dummy interface.
    Dummy,
    /// Veth pair with peer name.
    Veth { peer: String },
    /// Bridge interface.
    Bridge,
    /// VLAN interface.
    Vlan { parent: String, vlan_id: u16 },
    /// VXLAN interface.
    Vxlan { vni: u32, remote: Option<IpAddr> },
    /// Macvlan interface.
    Macvlan { parent: String, mode: MacvlanMode },
    /// Bond interface.
    Bond { mode: BondMode },
    /// IFB (Intermediate Functional Block).
    Ifb,
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
            Self::Physical => None,
        }
    }
}

/// Link state (up or down).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
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
        };
        self
    }

    /// Create a VXLAN interface with the given VNI.
    pub fn vxlan(mut self, vni: u32) -> Self {
        self.link_type = DeclaredLinkType::Vxlan { vni, remote: None };
        self
    }

    /// Set the VXLAN remote endpoint.
    pub fn vxlan_remote(mut self, remote: IpAddr) -> Self {
        if let DeclaredLinkType::Vxlan { vni, .. } = self.link_type {
            self.link_type = DeclaredLinkType::Vxlan {
                vni,
                remote: Some(remote),
            };
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
        };
        self
    }

    /// Set the bond mode.
    pub fn bond_mode(mut self, mode: BondMode) -> Self {
        if let DeclaredLinkType::Bond { .. } = self.link_type {
            self.link_type = DeclaredLinkType::Bond { mode };
        }
        self
    }

    /// Create an IFB interface.
    pub fn ifb(mut self) -> Self {
        self.link_type = DeclaredLinkType::Ifb;
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum QdiscParent {
    /// Root qdisc.
    #[default]
    Root,
    /// Ingress qdisc.
    Ingress,
}

/// Qdisc type for declared configuration.
#[derive(Debug, Clone)]
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
    pub fn loss(mut self, percent: f64) -> Self {
        if let Some(DeclaredQdiscType::Netem { loss_percent, .. }) = &mut self.qdisc_type {
            *loss_percent = Some(percent);
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
