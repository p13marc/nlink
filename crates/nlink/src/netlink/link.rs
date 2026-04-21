//! Link creation and management builders.
//!
//! This module provides typed builders for creating virtual network interfaces.
//!
//! # Supported Link Types
//!
//! - [`DummyLink`] - Dummy interface (loopback-like, no actual network)
//! - [`VethLink`] - Virtual ethernet pair
//! - [`BridgeLink`] - Bridge interface
//! - [`BondLink`] - Bonding (link aggregation) interface
//! - [`VlanLink`] - VLAN interface
//! - [`VxlanLink`] - VXLAN overlay interface
//! - [`MacvlanLink`] - MAC-based VLAN interface
//! - [`MacvtapLink`] - MAC-based tap interface (for VMs)
//! - [`IpvlanLink`] - IP-based VLAN interface
//! - [`VrfLink`] - Virtual Routing and Forwarding interface
//! - [`IfbLink`] - Intermediate Functional Block (for ingress shaping)
//! - [`GeneveLink`] - Generic Network Virtualization Encapsulation
//! - [`BareudpLink`] - Bare UDP tunneling
//! - [`NetkitLink`] - BPF-optimized virtual ethernet
//! - [`NlmonLink`] - Netlink monitor for debugging
//! - [`VirtWifiLink`] - Virtual WiFi for testing
//! - [`GreLink`] - GRE tunnel (IPv4)
//! - [`GretapLink`] - GRE TAP tunnel (Layer 2 over IPv4)
//! - [`IpipLink`] - IP-in-IP tunnel
//! - [`SitLink`] - SIT tunnel (IPv6-in-IPv4)
//! - [`VtiLink`] - Virtual Tunnel Interface (IPv4 IPsec)
//! - [`Vti6Link`] - Virtual Tunnel Interface (IPv6 IPsec)
//! - [`Ip6GreLink`] - IPv6 GRE tunnel
//! - [`Ip6GretapLink`] - IPv6 GRE TAP tunnel (Layer 2)
//! - [`WireguardLink`] - WireGuard interface
//! - [`MacsecLink`] - MACsec (IEEE 802.1AE) L2 encryption interface
//!
//! # Tunnel Modification Limitations
//!
//! Tunnel parameters (local/remote IP, keys, TTL, encapsulation options) are
//! **immutable after creation**. This is a Linux kernel limitation, not a library bug:
//!
//! - `RTM_NEWLINK` with `NLM_F_CREATE` sets tunnel parameters at creation time
//! - `RTM_SETLINK` can only modify link-level attributes (MTU, name, up/down state)
//! - No kernel API exists to modify `IFLA_LINKINFO_DATA` after creation
//!
//! ## What Can Be Changed After Creation
//!
//! These operations work on all link types, including tunnels:
//!
//! - Interface up/down state ([`set_link_up()`](Connection::set_link_up), [`set_link_down()`](Connection::set_link_down))
//! - MTU ([`set_link_mtu()`](Connection::set_link_mtu))
//! - Interface name ([`set_link_name()`](Connection::set_link_name))
//! - MAC address ([`set_link_address()`](Connection::set_link_address))
//! - Master device ([`set_link_master()`](Connection::set_link_master))
//! - Network namespace ([`set_link_netns()`](Connection::set_link_netns), [`set_link_netns_pid()`](Connection::set_link_netns_pid))
//!
//! ## What Cannot Be Changed (requires delete + recreate)
//!
//! These parameters are set at creation and cannot be modified:
//!
//! - Tunnel endpoints (local/remote IP addresses)
//! - Tunnel keys (GRE, VTI)
//! - TTL, TOS, encapsulation flags
//! - VXLAN VNI, port, learning settings
//! - Geneve VNI and options
//! - Any parameter stored in `IFLA_LINKINFO_DATA`
//!
//! ## Safe Replacement Pattern
//!
//! To change tunnel parameters, delete and recreate the tunnel:
//!
//! ```ignore
//! // To change tunnel parameters:
//! conn.del_link("gre1").await?;
//! conn.add_link(GreLink::new("gre1")
//!     .remote(new_remote_ip)
//!     .local(new_local_ip)
//!     .ttl(64)
//! ).await?;
//! ```
//!
//! Note: This causes a brief network interruption. For zero-downtime changes,
//! consider creating the new tunnel with a temporary name, migrating traffic,
//! then renaming.
//!
//! # Example
//!
//! ```ignore
//! use nlink::netlink::{Connection, Route};
//! use nlink::netlink::link::{DummyLink, VethLink, BridgeLink, VlanLink};
//!
//! let conn = Connection::<Route>::new()?;
//!
//! // Create a dummy interface
//! conn.add_link(DummyLink::new("dummy0")).await?;
//!
//! // Create a veth pair
//! conn.add_link(VethLink::new("veth0", "veth1")).await?;
//!
//! // Create a bridge
//! conn.add_link(BridgeLink::new("br0")).await?;
//!
//! // Create a VLAN on eth0
//! conn.add_link(VlanLink::new("eth0.100", "eth0", 100)).await?;
//! ```

use std::net::Ipv4Addr;

use super::{
    builder::MessageBuilder,
    connection::Connection,
    error::Result,
    interface_ref::InterfaceRef,
    message::NlMsgType,
    protocol::Route,
    types::link::{IfInfoMsg, IflaAttr, IflaInfo},
};

/// NLM_F_CREATE flag
const NLM_F_CREATE: u16 = 0x400;
/// NLM_F_EXCL flag (fail if exists)
const NLM_F_EXCL: u16 = 0x200;

/// Trait for link configurations that can be added to the system.
pub trait LinkConfig: Send + Sync {
    /// Get the name of this interface.
    fn name(&self) -> &str;

    /// Get the kind string for this link type (e.g., "dummy", "veth", "bridge").
    fn kind(&self) -> &str;

    /// Get the peer interface name, if this is a paired link type (veth, netkit).
    fn peer_name(&self) -> Option<&str> {
        None
    }

    /// Get the parent/link interface reference, if any.
    ///
    /// Returns `Some(&InterfaceRef)` for link types that require a parent interface
    /// (VLAN, MACVLAN, VXLAN, etc.), `None` for standalone types (dummy, bridge, etc.).
    fn parent_ref(&self) -> Option<&InterfaceRef> {
        None
    }

    /// Write the link configuration to the message builder.
    ///
    /// The `parent_index` parameter contains the resolved interface index
    /// for link types that have a parent reference.
    fn write_to(&self, builder: &mut MessageBuilder, parent_index: Option<u32>);
}

// ============================================================================
// Dummy Link
// ============================================================================

/// Configuration for a dummy interface.
///
/// Dummy interfaces are virtual interfaces that simply drop all traffic.
/// They're useful for testing or as anchors for IP addresses.
///
/// # Example
///
/// ```ignore
/// use nlink::netlink::link::DummyLink;
///
/// let dummy = DummyLink::new("dummy0")
///     .mtu(9000);
///
/// conn.add_link(dummy).await?;
/// ```
#[derive(Debug, Clone)]
#[must_use = "builders do nothing unless used"]
pub struct DummyLink {
    name: String,
    mtu: Option<u32>,
    address: Option<[u8; 6]>,
}

impl DummyLink {
    /// Create a new dummy interface configuration.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            mtu: None,
            address: None,
        }
    }

    /// Set the MTU for this interface.
    pub fn mtu(mut self, mtu: u32) -> Self {
        self.mtu = Some(mtu);
        self
    }

    /// Set the MAC address for this interface.
    pub fn address(mut self, addr: [u8; 6]) -> Self {
        self.address = Some(addr);
        self
    }
}

impl LinkConfig for DummyLink {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> &str {
        "dummy"
    }

    fn write_to(&self, builder: &mut MessageBuilder, _parent_index: Option<u32>) {
        write_simple_link(
            builder,
            &self.name,
            "dummy",
            self.mtu,
            self.address.as_ref(),
        );
    }
}

// ============================================================================
// Veth Link
// ============================================================================

/// Configuration for a veth (virtual ethernet) pair.
///
/// Veth devices are created in pairs. Whatever enters one end comes out the other.
/// They're commonly used to connect network namespaces.
///
/// # Example
///
/// ```ignore
/// use nlink::netlink::link::VethLink;
///
/// // Create a veth pair
/// let veth = VethLink::new("veth0", "veth1");
/// conn.add_link(veth).await?;
///
/// // Now veth0 and veth1 are connected
/// ```
#[derive(Debug)]
#[must_use = "builders do nothing unless used"]
pub struct VethLink {
    name: String,
    peer_name: String,
    mtu: Option<u32>,
    address: Option<[u8; 6]>,
    peer_address: Option<[u8; 6]>,
    peer_netns_fd: Option<i32>,
    peer_netns_pid: Option<u32>,
    /// Owned namespace FD kept alive for the duration of the builder.
    _peer_netns_owned: Option<super::namespace::NamespaceFd>,
}

impl VethLink {
    /// Create a new veth pair configuration.
    ///
    /// # Arguments
    ///
    /// * `name` - Name for the first interface
    /// * `peer_name` - Name for the peer interface
    pub fn new(name: impl Into<String>, peer_name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            peer_name: peer_name.into(),
            mtu: None,
            address: None,
            peer_address: None,
            peer_netns_fd: None,
            peer_netns_pid: None,
            _peer_netns_owned: None,
        }
    }

    /// Set the MTU for both interfaces.
    pub fn mtu(mut self, mtu: u32) -> Self {
        self.mtu = Some(mtu);
        self
    }

    /// Set the MAC address for the first interface.
    pub fn address(mut self, addr: [u8; 6]) -> Self {
        self.address = Some(addr);
        self
    }

    /// Set the MAC address for the peer interface.
    pub fn peer_address(mut self, addr: [u8; 6]) -> Self {
        self.peer_address = Some(addr);
        self
    }

    /// Move the peer interface to a different network namespace by fd.
    pub fn peer_netns_fd(mut self, fd: i32) -> Self {
        self.peer_netns_fd = Some(fd);
        self.peer_netns_pid = None;
        self
    }

    /// Move the peer interface to a different network namespace by PID.
    pub fn peer_netns_pid(mut self, pid: u32) -> Self {
        self.peer_netns_pid = Some(pid);
        self.peer_netns_fd = None;
        self
    }

    /// Move the peer interface to a named network namespace.
    ///
    /// Opens the namespace by name (from `/var/run/netns/<name>`) and stores
    /// the file descriptor for use during link creation.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let veth = VethLink::new("veth0", "veth1").peer_netns("my-ns")?;
    /// conn.add_link(veth).await?;
    /// ```
    pub fn peer_netns(mut self, ns_name: &str) -> Result<Self> {
        let ns_fd = super::namespace::open(ns_name)?;
        self.peer_netns_fd = Some(ns_fd.as_raw_fd());
        self.peer_netns_pid = None;
        self._peer_netns_owned = Some(ns_fd);
        Ok(self)
    }
}

/// VETH-specific nested attributes
mod veth {
    pub const VETH_INFO_PEER: u16 = 1;
}

impl LinkConfig for VethLink {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> &str {
        "veth"
    }

    fn peer_name(&self) -> Option<&str> {
        Some(&self.peer_name)
    }

    fn write_to(&self, builder: &mut MessageBuilder, _parent_index: Option<u32>) {
        // Add interface name
        write_ifname(builder, &self.name);

        // Add optional attributes
        if let Some(mtu) = self.mtu {
            builder.append_attr_u32(IflaAttr::Mtu as u16, mtu);
        }
        if let Some(ref addr) = self.address {
            builder.append_attr(IflaAttr::Address as u16, addr);
        }

        // IFLA_LINKINFO
        let linkinfo = builder.nest_start(IflaAttr::Linkinfo as u16);
        builder.append_attr_str(IflaInfo::Kind as u16, "veth");

        // IFLA_INFO_DATA -> VETH_INFO_PEER -> nested ifinfomsg + attrs
        let data = builder.nest_start(IflaInfo::Data as u16);
        let peer = builder.nest_start(veth::VETH_INFO_PEER);

        // Peer ifinfomsg
        let peer_ifinfo = IfInfoMsg::new();
        builder.append(&peer_ifinfo);

        // Peer name
        builder.append_attr_str(IflaAttr::Ifname as u16, &self.peer_name);

        // Peer MTU
        if let Some(mtu) = self.mtu {
            builder.append_attr_u32(IflaAttr::Mtu as u16, mtu);
        }

        // Peer address
        if let Some(ref addr) = self.peer_address {
            builder.append_attr(IflaAttr::Address as u16, addr);
        }

        // Peer namespace
        if let Some(fd) = self.peer_netns_fd {
            builder.append_attr_u32(IflaAttr::NetNsFd as u16, fd as u32);
        } else if let Some(pid) = self.peer_netns_pid {
            builder.append_attr_u32(IflaAttr::NetNsPid as u16, pid);
        }

        builder.nest_end(peer);
        builder.nest_end(data);
        builder.nest_end(linkinfo);
    }
}

// ============================================================================
// Bridge Link
// ============================================================================

/// Configuration for a bridge interface.
///
/// A bridge is a virtual switch that forwards packets between attached interfaces.
///
/// # Example
///
/// ```ignore
/// use nlink::netlink::link::BridgeLink;
///
/// let bridge = BridgeLink::new("br0")
///     .stp(true)
///     .vlan_filtering(true);
///
/// conn.add_link(bridge).await?;
/// ```
#[derive(Debug, Clone)]
#[must_use = "builders do nothing unless used"]
pub struct BridgeLink {
    name: String,
    mtu: Option<u32>,
    address: Option<[u8; 6]>,
    /// Forward delay in centiseconds
    forward_delay: Option<u32>,
    /// Hello time in centiseconds
    hello_time: Option<u32>,
    /// Max age in centiseconds
    max_age: Option<u32>,
    /// Ageing time in centiseconds
    ageing_time: Option<u32>,
    /// STP state (0 = off, 1 = on)
    stp_state: Option<u32>,
    /// Priority (0-65535)
    priority: Option<u16>,
    /// VLAN filtering enabled
    vlan_filtering: Option<bool>,
    /// Default PVID
    vlan_default_pvid: Option<u16>,
}

/// Bridge-specific attributes (IFLA_BR_*)
mod bridge {
    pub const IFLA_BR_FORWARD_DELAY: u16 = 1;
    pub const IFLA_BR_HELLO_TIME: u16 = 2;
    pub const IFLA_BR_MAX_AGE: u16 = 3;
    pub const IFLA_BR_AGEING_TIME: u16 = 4;
    pub const IFLA_BR_STP_STATE: u16 = 5;
    pub const IFLA_BR_PRIORITY: u16 = 6;
    pub const IFLA_BR_VLAN_FILTERING: u16 = 7;
    pub const IFLA_BR_VLAN_DEFAULT_PVID: u16 = 39;
}

impl BridgeLink {
    /// Create a new bridge interface configuration.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            mtu: None,
            address: None,
            forward_delay: None,
            hello_time: None,
            max_age: None,
            ageing_time: None,
            stp_state: None,
            priority: None,
            vlan_filtering: None,
            vlan_default_pvid: None,
        }
    }

    /// Set the MTU.
    pub fn mtu(mut self, mtu: u32) -> Self {
        self.mtu = Some(mtu);
        self
    }

    /// Set the MAC address.
    pub fn address(mut self, addr: [u8; 6]) -> Self {
        self.address = Some(addr);
        self
    }

    /// Enable or disable STP.
    pub fn stp(mut self, enabled: bool) -> Self {
        self.stp_state = Some(if enabled { 1 } else { 0 });
        self
    }

    /// Set the forward delay in milliseconds.
    pub fn forward_delay_ms(mut self, ms: u32) -> Self {
        // Kernel expects centiseconds (USER_HZ typically 100)
        self.forward_delay = Some(ms / 10);
        self
    }

    /// Set the hello time in milliseconds.
    pub fn hello_time_ms(mut self, ms: u32) -> Self {
        self.hello_time = Some(ms / 10);
        self
    }

    /// Set the max age in milliseconds.
    pub fn max_age_ms(mut self, ms: u32) -> Self {
        self.max_age = Some(ms / 10);
        self
    }

    /// Set the ageing time in seconds.
    pub fn ageing_time(mut self, seconds: u32) -> Self {
        // Kernel expects centiseconds
        self.ageing_time = Some(seconds * 100);
        self
    }

    /// Set the bridge priority.
    pub fn priority(mut self, priority: u16) -> Self {
        self.priority = Some(priority);
        self
    }

    /// Enable or disable VLAN filtering.
    pub fn vlan_filtering(mut self, enabled: bool) -> Self {
        self.vlan_filtering = Some(enabled);
        self
    }

    /// Set the default PVID (port VLAN ID).
    pub fn vlan_default_pvid(mut self, pvid: u16) -> Self {
        self.vlan_default_pvid = Some(pvid);
        self
    }
}

impl LinkConfig for BridgeLink {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> &str {
        "bridge"
    }

    fn write_to(&self, builder: &mut MessageBuilder, _parent_index: Option<u32>) {
        // Add interface name
        write_ifname(builder, &self.name);

        // Add optional attributes
        if let Some(mtu) = self.mtu {
            builder.append_attr_u32(IflaAttr::Mtu as u16, mtu);
        }
        if let Some(ref addr) = self.address {
            builder.append_attr(IflaAttr::Address as u16, addr);
        }

        // IFLA_LINKINFO
        let linkinfo = builder.nest_start(IflaAttr::Linkinfo as u16);
        builder.append_attr_str(IflaInfo::Kind as u16, "bridge");

        // Check if we have any bridge-specific options
        let has_options = self.forward_delay.is_some()
            || self.hello_time.is_some()
            || self.max_age.is_some()
            || self.ageing_time.is_some()
            || self.stp_state.is_some()
            || self.priority.is_some()
            || self.vlan_filtering.is_some()
            || self.vlan_default_pvid.is_some();

        if has_options {
            let data = builder.nest_start(IflaInfo::Data as u16);

            if let Some(val) = self.forward_delay {
                builder.append_attr_u32(bridge::IFLA_BR_FORWARD_DELAY, val);
            }
            if let Some(val) = self.hello_time {
                builder.append_attr_u32(bridge::IFLA_BR_HELLO_TIME, val);
            }
            if let Some(val) = self.max_age {
                builder.append_attr_u32(bridge::IFLA_BR_MAX_AGE, val);
            }
            if let Some(val) = self.ageing_time {
                builder.append_attr_u32(bridge::IFLA_BR_AGEING_TIME, val);
            }
            if let Some(val) = self.stp_state {
                builder.append_attr_u32(bridge::IFLA_BR_STP_STATE, val);
            }
            if let Some(val) = self.priority {
                builder.append_attr_u16(bridge::IFLA_BR_PRIORITY, val);
            }
            if let Some(enabled) = self.vlan_filtering {
                builder.append_attr_u8(bridge::IFLA_BR_VLAN_FILTERING, if enabled { 1 } else { 0 });
            }
            if let Some(pvid) = self.vlan_default_pvid {
                builder.append_attr_u16(bridge::IFLA_BR_VLAN_DEFAULT_PVID, pvid);
            }

            builder.nest_end(data);
        }

        builder.nest_end(linkinfo);
    }
}

// ============================================================================
// VLAN Link
// ============================================================================

/// Configuration for a VLAN interface.
///
/// A VLAN interface tags/untags packets with an 802.1Q VLAN ID.
///
/// # Example
///
/// ```ignore
/// use nlink::netlink::link::VlanLink;
///
/// // Create VLAN 100 on eth0
/// let vlan = VlanLink::new("eth0.100", "eth0", 100);
/// conn.add_link(vlan).await?;
/// ```
#[derive(Debug, Clone)]
#[must_use = "builders do nothing unless used"]
pub struct VlanLink {
    name: String,
    parent: InterfaceRef,
    vlan_id: u16,
    mtu: Option<u32>,
    address: Option<[u8; 6]>,
    /// Protocol: 0x8100 for 802.1Q, 0x88a8 for 802.1ad
    protocol: Option<u16>,
    flags: VlanFlags,
}

/// VLAN-specific attributes (IFLA_VLAN_*)
mod vlan {
    pub const IFLA_VLAN_ID: u16 = 1;
    pub const IFLA_VLAN_FLAGS: u16 = 2;
    pub const IFLA_VLAN_PROTOCOL: u16 = 5;

    /// VLAN flags
    pub const VLAN_FLAG_REORDER_HDR: u32 = 0x1;
    pub const VLAN_FLAG_GVRP: u32 = 0x2;
    pub const VLAN_FLAG_LOOSE_BINDING: u32 = 0x4;
    pub const VLAN_FLAG_MVRP: u32 = 0x8;
}

/// VLAN flags structure
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct VlanFlags {
    pub flags: u32,
    pub mask: u32,
}

impl VlanLink {
    /// Create a new VLAN interface configuration.
    ///
    /// # Arguments
    ///
    /// * `name` - Name for the VLAN interface (e.g., "eth0.100")
    /// * `parent` - Parent interface name (e.g., "eth0")
    /// * `vlan_id` - VLAN ID (1-4094)
    pub fn new(name: impl Into<String>, parent: impl Into<String>, vlan_id: u16) -> Self {
        Self {
            name: name.into(),
            parent: InterfaceRef::Name(parent.into()),
            vlan_id,
            mtu: None,
            address: None,
            protocol: None,
            flags: VlanFlags::default(),
        }
    }

    /// Create a new VLAN interface with parent specified by index.
    ///
    /// This is the namespace-safe variant that avoids reading from /sys/class/net/.
    ///
    /// # Arguments
    ///
    /// * `name` - Name for the VLAN interface
    /// * `parent_index` - Parent interface index
    /// * `vlan_id` - VLAN ID (1-4094)
    pub fn with_parent_index(name: impl Into<String>, parent_index: u32, vlan_id: u16) -> Self {
        Self {
            name: name.into(),
            parent: InterfaceRef::Index(parent_index),
            vlan_id,
            mtu: None,
            address: None,
            protocol: None,
            flags: VlanFlags::default(),
        }
    }

    /// Set the MTU.
    pub fn mtu(mut self, mtu: u32) -> Self {
        self.mtu = Some(mtu);
        self
    }

    /// Set the MAC address.
    pub fn address(mut self, addr: [u8; 6]) -> Self {
        self.address = Some(addr);
        self
    }

    /// Set to 802.1ad (QinQ) protocol instead of 802.1Q.
    pub fn qinq(mut self) -> Self {
        self.protocol = Some(0x88a8);
        self
    }

    /// Enable GVRP (GARP VLAN Registration Protocol).
    pub fn gvrp(mut self, enabled: bool) -> Self {
        self.flags.mask |= vlan::VLAN_FLAG_GVRP;
        if enabled {
            self.flags.flags |= vlan::VLAN_FLAG_GVRP;
        } else {
            self.flags.flags &= !vlan::VLAN_FLAG_GVRP;
        }
        self
    }

    /// Enable MVRP (Multiple VLAN Registration Protocol).
    pub fn mvrp(mut self, enabled: bool) -> Self {
        self.flags.mask |= vlan::VLAN_FLAG_MVRP;
        if enabled {
            self.flags.flags |= vlan::VLAN_FLAG_MVRP;
        } else {
            self.flags.flags &= !vlan::VLAN_FLAG_MVRP;
        }
        self
    }

    /// Enable loose binding (don't follow parent state).
    pub fn loose_binding(mut self, enabled: bool) -> Self {
        self.flags.mask |= vlan::VLAN_FLAG_LOOSE_BINDING;
        if enabled {
            self.flags.flags |= vlan::VLAN_FLAG_LOOSE_BINDING;
        } else {
            self.flags.flags &= !vlan::VLAN_FLAG_LOOSE_BINDING;
        }
        self
    }

    /// Enable reorder header.
    pub fn reorder_hdr(mut self, enabled: bool) -> Self {
        self.flags.mask |= vlan::VLAN_FLAG_REORDER_HDR;
        if enabled {
            self.flags.flags |= vlan::VLAN_FLAG_REORDER_HDR;
        } else {
            self.flags.flags &= !vlan::VLAN_FLAG_REORDER_HDR;
        }
        self
    }
}

impl LinkConfig for VlanLink {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> &str {
        "vlan"
    }

    fn parent_ref(&self) -> Option<&InterfaceRef> {
        Some(&self.parent)
    }

    fn write_to(&self, builder: &mut MessageBuilder, parent_index: Option<u32>) {
        // Add interface name
        write_ifname(builder, &self.name);

        // Link to parent (parent_index is guaranteed to be Some for types with parent_ref)
        let idx = parent_index.expect("VlanLink requires parent_index");
        builder.append_attr_u32(IflaAttr::Link as u16, idx);

        // Add optional attributes
        if let Some(mtu) = self.mtu {
            builder.append_attr_u32(IflaAttr::Mtu as u16, mtu);
        }
        if let Some(ref addr) = self.address {
            builder.append_attr(IflaAttr::Address as u16, addr);
        }

        // IFLA_LINKINFO
        let linkinfo = builder.nest_start(IflaAttr::Linkinfo as u16);
        builder.append_attr_str(IflaInfo::Kind as u16, "vlan");

        // IFLA_INFO_DATA
        let data = builder.nest_start(IflaInfo::Data as u16);

        // VLAN ID
        builder.append_attr_u16(vlan::IFLA_VLAN_ID, self.vlan_id);

        // Protocol (if set)
        if let Some(proto) = self.protocol {
            builder.append_attr_u16_be(vlan::IFLA_VLAN_PROTOCOL, proto);
        }

        // Flags (if any set)
        if self.flags.mask != 0 {
            // SAFETY: VlanFlags is a #[repr(C)] struct of two u32 fields with no padding.
            // The pointer and size are valid for the lifetime of `self.flags`.
            let flags_bytes = unsafe {
                std::slice::from_raw_parts(
                    &self.flags as *const VlanFlags as *const u8,
                    std::mem::size_of::<VlanFlags>(),
                )
            };
            builder.append_attr(vlan::IFLA_VLAN_FLAGS, flags_bytes);
        }

        builder.nest_end(data);
        builder.nest_end(linkinfo);
    }
}

// ============================================================================
// VXLAN Link
// ============================================================================

/// Configuration for a VXLAN interface.
///
/// VXLAN provides Layer 2 overlay networks over Layer 3 infrastructure.
///
/// # Example
///
/// ```ignore
/// use nlink::netlink::link::VxlanLink;
/// use std::net::Ipv4Addr;
///
/// let vxlan = VxlanLink::new("vxlan0", 100)
///     .local(Ipv4Addr::new(192, 168, 1, 1))
///     .group(Ipv4Addr::new(239, 1, 1, 1))
///     .dev("eth0")
///     .port(4789);
///
/// conn.add_link(vxlan).await?;
/// ```
#[derive(Debug, Clone)]
#[must_use = "builders do nothing unless used"]
pub struct VxlanLink {
    name: String,
    vni: u32,
    mtu: Option<u32>,
    address: Option<[u8; 6]>,
    /// Local IP address
    local: Option<Ipv4Addr>,
    /// Remote IP address (for point-to-point)
    remote: Option<Ipv4Addr>,
    /// Multicast group
    group: Option<Ipv4Addr>,
    /// Underlying device
    dev: Option<InterfaceRef>,
    /// UDP port (default 4789)
    port: Option<u16>,
    /// Port range
    port_range: Option<(u16, u16)>,
    /// TTL
    ttl: Option<u8>,
    /// TOS
    tos: Option<u8>,
    /// Learning enabled
    learning: Option<bool>,
    /// Proxy ARP enabled
    proxy: Option<bool>,
    /// RSC (route short circuit)
    rsc: Option<bool>,
    /// L2miss notifications
    l2miss: Option<bool>,
    /// L3miss notifications
    l3miss: Option<bool>,
    /// UDP checksum
    udp_csum: Option<bool>,
}

/// VXLAN-specific attributes (IFLA_VXLAN_*)
mod vxlan {
    pub const IFLA_VXLAN_ID: u16 = 1;
    pub const IFLA_VXLAN_GROUP: u16 = 2;
    pub const IFLA_VXLAN_LINK: u16 = 3;
    pub const IFLA_VXLAN_LOCAL: u16 = 4;
    pub const IFLA_VXLAN_TTL: u16 = 5;
    pub const IFLA_VXLAN_TOS: u16 = 6;
    pub const IFLA_VXLAN_LEARNING: u16 = 7;
    pub const IFLA_VXLAN_PORT_RANGE: u16 = 10;
    pub const IFLA_VXLAN_PROXY: u16 = 11;
    pub const IFLA_VXLAN_RSC: u16 = 12;
    pub const IFLA_VXLAN_L2MISS: u16 = 13;
    pub const IFLA_VXLAN_L3MISS: u16 = 14;
    pub const IFLA_VXLAN_PORT: u16 = 15;
    pub const IFLA_VXLAN_UDP_CSUM: u16 = 18;
}

impl VxlanLink {
    /// Create a new VXLAN interface configuration.
    ///
    /// # Arguments
    ///
    /// * `name` - Name for the VXLAN interface
    /// * `vni` - VXLAN Network Identifier (1-16777215)
    pub fn new(name: impl Into<String>, vni: u32) -> Self {
        Self {
            name: name.into(),
            vni,
            mtu: None,
            address: None,
            local: None,
            remote: None,
            group: None,
            dev: None,
            port: None,
            port_range: None,
            ttl: None,
            tos: None,
            learning: None,
            proxy: None,
            rsc: None,
            l2miss: None,
            l3miss: None,
            udp_csum: None,
        }
    }

    /// Set the MTU.
    pub fn mtu(mut self, mtu: u32) -> Self {
        self.mtu = Some(mtu);
        self
    }

    /// Set the MAC address.
    pub fn address(mut self, addr: [u8; 6]) -> Self {
        self.address = Some(addr);
        self
    }

    /// Set the local IP address.
    pub fn local(mut self, addr: Ipv4Addr) -> Self {
        self.local = Some(addr);
        self
    }

    /// Set the remote IP address (for point-to-point).
    pub fn remote(mut self, addr: Ipv4Addr) -> Self {
        self.remote = Some(addr);
        self
    }

    /// Set the multicast group.
    pub fn group(mut self, addr: Ipv4Addr) -> Self {
        self.group = Some(addr);
        self
    }

    /// Set the underlying device by name.
    pub fn dev(mut self, dev: impl Into<String>) -> Self {
        self.dev = Some(InterfaceRef::Name(dev.into()));
        self
    }

    /// Set the underlying device by interface index.
    ///
    /// This is the namespace-safe variant that avoids reading from /sys/class/net/.
    pub fn dev_index(mut self, index: u32) -> Self {
        self.dev = Some(InterfaceRef::Index(index));
        self
    }

    /// Set the UDP port (default 4789).
    pub fn port(mut self, port: u16) -> Self {
        self.port = Some(port);
        self
    }

    /// Set the UDP port range.
    pub fn port_range(mut self, low: u16, high: u16) -> Self {
        self.port_range = Some((low, high));
        self
    }

    /// Set the TTL.
    pub fn ttl(mut self, ttl: u8) -> Self {
        self.ttl = Some(ttl);
        self
    }

    /// Set the TOS.
    pub fn tos(mut self, tos: u8) -> Self {
        self.tos = Some(tos);
        self
    }

    /// Enable or disable learning.
    pub fn learning(mut self, enabled: bool) -> Self {
        self.learning = Some(enabled);
        self
    }

    /// Enable or disable proxy ARP.
    pub fn proxy(mut self, enabled: bool) -> Self {
        self.proxy = Some(enabled);
        self
    }

    /// Enable or disable RSC (route short circuit).
    pub fn rsc(mut self, enabled: bool) -> Self {
        self.rsc = Some(enabled);
        self
    }

    /// Enable or disable L2miss notifications.
    pub fn l2miss(mut self, enabled: bool) -> Self {
        self.l2miss = Some(enabled);
        self
    }

    /// Enable or disable L3miss notifications.
    pub fn l3miss(mut self, enabled: bool) -> Self {
        self.l3miss = Some(enabled);
        self
    }

    /// Enable or disable UDP checksum.
    pub fn udp_csum(mut self, enabled: bool) -> Self {
        self.udp_csum = Some(enabled);
        self
    }
}

impl LinkConfig for VxlanLink {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> &str {
        "vxlan"
    }

    fn parent_ref(&self) -> Option<&InterfaceRef> {
        self.dev.as_ref()
    }

    fn write_to(&self, builder: &mut MessageBuilder, parent_index: Option<u32>) {
        // Add interface name
        write_ifname(builder, &self.name);

        // Add optional attributes
        if let Some(mtu) = self.mtu {
            builder.append_attr_u32(IflaAttr::Mtu as u16, mtu);
        }
        if let Some(ref addr) = self.address {
            builder.append_attr(IflaAttr::Address as u16, addr);
        }

        // IFLA_LINKINFO
        let linkinfo = builder.nest_start(IflaAttr::Linkinfo as u16);
        builder.append_attr_str(IflaInfo::Kind as u16, "vxlan");

        // IFLA_INFO_DATA
        let data = builder.nest_start(IflaInfo::Data as u16);

        // VNI (required)
        builder.append_attr_u32(vxlan::IFLA_VXLAN_ID, self.vni);

        // Local address
        if let Some(addr) = self.local {
            builder.append_attr(vxlan::IFLA_VXLAN_LOCAL, &addr.octets());
        }

        // Remote/Group
        if let Some(addr) = self.remote {
            builder.append_attr(vxlan::IFLA_VXLAN_GROUP, &addr.octets());
        } else if let Some(addr) = self.group {
            builder.append_attr(vxlan::IFLA_VXLAN_GROUP, &addr.octets());
        }

        // Underlying device (use resolved parent_index if dev was set)
        if let Some(idx) = parent_index {
            builder.append_attr_u32(vxlan::IFLA_VXLAN_LINK, idx);
        }

        // Port
        if let Some(port) = self.port {
            builder.append_attr_u16_be(vxlan::IFLA_VXLAN_PORT, port);
        }

        // Port range
        if let Some((low, high)) = self.port_range {
            let range = [low.to_be(), high.to_be()];
            // SAFETY: [u16; 2] is 4 bytes with no padding; pointer is valid for the array lifetime.
            let range_bytes = unsafe { std::slice::from_raw_parts(range.as_ptr() as *const u8, 4) };
            builder.append_attr(vxlan::IFLA_VXLAN_PORT_RANGE, range_bytes);
        }

        // TTL
        if let Some(ttl) = self.ttl {
            builder.append_attr_u8(vxlan::IFLA_VXLAN_TTL, ttl);
        }

        // TOS
        if let Some(tos) = self.tos {
            builder.append_attr_u8(vxlan::IFLA_VXLAN_TOS, tos);
        }

        // Boolean options
        if let Some(enabled) = self.learning {
            builder.append_attr_u8(vxlan::IFLA_VXLAN_LEARNING, if enabled { 1 } else { 0 });
        }
        if let Some(enabled) = self.proxy {
            builder.append_attr_u8(vxlan::IFLA_VXLAN_PROXY, if enabled { 1 } else { 0 });
        }
        if let Some(enabled) = self.rsc {
            builder.append_attr_u8(vxlan::IFLA_VXLAN_RSC, if enabled { 1 } else { 0 });
        }
        if let Some(enabled) = self.l2miss {
            builder.append_attr_u8(vxlan::IFLA_VXLAN_L2MISS, if enabled { 1 } else { 0 });
        }
        if let Some(enabled) = self.l3miss {
            builder.append_attr_u8(vxlan::IFLA_VXLAN_L3MISS, if enabled { 1 } else { 0 });
        }
        if let Some(enabled) = self.udp_csum {
            builder.append_attr_u8(vxlan::IFLA_VXLAN_UDP_CSUM, if enabled { 1 } else { 0 });
        }

        builder.nest_end(data);
        builder.nest_end(linkinfo);
    }
}

// ============================================================================
// Macvlan Link
// ============================================================================

/// Macvlan mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum MacvlanMode {
    /// Private mode - no communication with other macvlans
    Private = 1,
    /// VEPA mode - traffic goes through external switch
    Vepa = 2,
    /// Bridge mode - communication between macvlans
    Bridge = 4,
    /// Passthrough mode - single macvlan on parent
    Passthru = 8,
    /// Source mode - filter by source MAC
    Source = 16,
}

/// Configuration for a macvlan interface.
///
/// Macvlan creates virtual interfaces with their own MAC addresses on a parent device.
///
/// # Example
///
/// ```ignore
/// use nlink::netlink::link::{MacvlanLink, MacvlanMode};
///
/// let macvlan = MacvlanLink::new("macvlan0", "eth0")
///     .mode(MacvlanMode::Bridge);
///
/// conn.add_link(macvlan).await?;
/// ```
#[derive(Debug, Clone)]
#[must_use = "builders do nothing unless used"]
pub struct MacvlanLink {
    name: String,
    parent: InterfaceRef,
    mode: MacvlanMode,
    mtu: Option<u32>,
    address: Option<[u8; 6]>,
}

/// Macvlan-specific attributes
mod macvlan {
    pub const IFLA_MACVLAN_MODE: u16 = 1;
}

impl MacvlanLink {
    /// Create a new macvlan interface configuration.
    pub fn new(name: impl Into<String>, parent: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            parent: InterfaceRef::Name(parent.into()),
            mode: MacvlanMode::Bridge,
            mtu: None,
            address: None,
        }
    }

    /// Create a new macvlan interface with parent specified by index.
    ///
    /// This is the namespace-safe variant that avoids reading from /sys/class/net/.
    pub fn with_parent_index(name: impl Into<String>, parent_index: u32) -> Self {
        Self {
            name: name.into(),
            parent: InterfaceRef::Index(parent_index),
            mode: MacvlanMode::Bridge,
            mtu: None,
            address: None,
        }
    }

    /// Set the macvlan mode.
    pub fn mode(mut self, mode: MacvlanMode) -> Self {
        self.mode = mode;
        self
    }

    /// Set the MTU.
    pub fn mtu(mut self, mtu: u32) -> Self {
        self.mtu = Some(mtu);
        self
    }

    /// Set the MAC address.
    pub fn address(mut self, addr: [u8; 6]) -> Self {
        self.address = Some(addr);
        self
    }
}

impl LinkConfig for MacvlanLink {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> &str {
        "macvlan"
    }

    fn parent_ref(&self) -> Option<&InterfaceRef> {
        Some(&self.parent)
    }

    fn write_to(&self, builder: &mut MessageBuilder, parent_index: Option<u32>) {
        // Add interface name
        write_ifname(builder, &self.name);

        // Link to parent
        let idx = parent_index.expect("MacvlanLink requires parent_index");
        builder.append_attr_u32(IflaAttr::Link as u16, idx);

        // Add optional attributes
        if let Some(mtu) = self.mtu {
            builder.append_attr_u32(IflaAttr::Mtu as u16, mtu);
        }
        if let Some(ref addr) = self.address {
            builder.append_attr(IflaAttr::Address as u16, addr);
        }

        // IFLA_LINKINFO
        let linkinfo = builder.nest_start(IflaAttr::Linkinfo as u16);
        builder.append_attr_str(IflaInfo::Kind as u16, "macvlan");

        // IFLA_INFO_DATA
        let data = builder.nest_start(IflaInfo::Data as u16);
        builder.append_attr_u32(macvlan::IFLA_MACVLAN_MODE, self.mode as u32);
        builder.nest_end(data);

        builder.nest_end(linkinfo);
    }
}

// ============================================================================
// Ipvlan Link
// ============================================================================

/// Ipvlan mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum IpvlanMode {
    /// L2 mode
    L2 = 0,
    /// L3 mode
    L3 = 1,
    /// L3S mode (L3 with source check)
    L3S = 2,
}

/// Ipvlan flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum IpvlanFlags {
    /// Bridge mode
    Bridge = 0,
    /// Private mode
    Private = 1,
    /// VEPA mode
    Vepa = 2,
}

/// Configuration for an ipvlan interface.
///
/// Ipvlan is similar to macvlan but shares the parent's MAC address.
///
/// # Example
///
/// ```ignore
/// use nlink::netlink::link::{IpvlanLink, IpvlanMode};
///
/// let ipvlan = IpvlanLink::new("ipvlan0", "eth0")
///     .mode(IpvlanMode::L3);
///
/// conn.add_link(ipvlan).await?;
/// ```
#[derive(Debug, Clone)]
#[must_use = "builders do nothing unless used"]
pub struct IpvlanLink {
    name: String,
    parent: InterfaceRef,
    mode: IpvlanMode,
    flags: IpvlanFlags,
    mtu: Option<u32>,
}

/// Ipvlan-specific attributes
mod ipvlan {
    pub const IFLA_IPVLAN_MODE: u16 = 1;
    pub const IFLA_IPVLAN_FLAGS: u16 = 2;
}

impl IpvlanLink {
    /// Create a new ipvlan interface configuration.
    pub fn new(name: impl Into<String>, parent: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            parent: InterfaceRef::Name(parent.into()),
            mode: IpvlanMode::L3,
            flags: IpvlanFlags::Bridge,
            mtu: None,
        }
    }

    /// Create a new ipvlan interface with parent specified by index.
    ///
    /// This is the namespace-safe variant that avoids reading from /sys/class/net/.
    pub fn with_parent_index(name: impl Into<String>, parent_index: u32) -> Self {
        Self {
            name: name.into(),
            parent: InterfaceRef::Index(parent_index),
            mode: IpvlanMode::L3,
            flags: IpvlanFlags::Bridge,
            mtu: None,
        }
    }

    /// Set the ipvlan mode.
    pub fn mode(mut self, mode: IpvlanMode) -> Self {
        self.mode = mode;
        self
    }

    /// Set the ipvlan flags.
    pub fn flags(mut self, flags: IpvlanFlags) -> Self {
        self.flags = flags;
        self
    }

    /// Set the MTU.
    pub fn mtu(mut self, mtu: u32) -> Self {
        self.mtu = Some(mtu);
        self
    }
}

impl LinkConfig for IpvlanLink {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> &str {
        "ipvlan"
    }

    fn parent_ref(&self) -> Option<&InterfaceRef> {
        Some(&self.parent)
    }

    fn write_to(&self, builder: &mut MessageBuilder, parent_index: Option<u32>) {
        // Add interface name
        write_ifname(builder, &self.name);

        // Link to parent
        let idx = parent_index.expect("IpvlanLink requires parent_index");
        builder.append_attr_u32(IflaAttr::Link as u16, idx);

        // Add optional attributes
        if let Some(mtu) = self.mtu {
            builder.append_attr_u32(IflaAttr::Mtu as u16, mtu);
        }

        // IFLA_LINKINFO
        let linkinfo = builder.nest_start(IflaAttr::Linkinfo as u16);
        builder.append_attr_str(IflaInfo::Kind as u16, "ipvlan");

        // IFLA_INFO_DATA
        let data = builder.nest_start(IflaInfo::Data as u16);
        builder.append_attr_u16(ipvlan::IFLA_IPVLAN_MODE, self.mode as u16);
        builder.append_attr_u16(ipvlan::IFLA_IPVLAN_FLAGS, self.flags as u16);
        builder.nest_end(data);

        builder.nest_end(linkinfo);
    }
}

// ============================================================================
// IFB Link
// ============================================================================

/// Configuration for an IFB (Intermediate Functional Block) interface.
///
/// IFB devices are used in conjunction with TC to redirect traffic for
/// ingress shaping. They act as a pseudo-interface where you can attach
/// qdiscs to shape incoming traffic.
///
/// # Example
///
/// ```ignore
/// use nlink::netlink::link::IfbLink;
///
/// let ifb = IfbLink::new("ifb0");
/// conn.add_link(ifb).await?;
///
/// // Then redirect ingress traffic to ifb0 for shaping
/// ```
#[derive(Debug, Clone)]
#[must_use = "builders do nothing unless used"]
pub struct IfbLink {
    name: String,
    mtu: Option<u32>,
}

impl IfbLink {
    /// Create a new IFB interface configuration.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            mtu: None,
        }
    }

    /// Set the MTU for this interface.
    pub fn mtu(mut self, mtu: u32) -> Self {
        self.mtu = Some(mtu);
        self
    }
}

impl LinkConfig for IfbLink {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> &str {
        "ifb"
    }

    fn write_to(&self, builder: &mut MessageBuilder, _parent_index: Option<u32>) {
        write_simple_link(builder, &self.name, "ifb", self.mtu, None);
    }
}

// ============================================================================
// Macvtap Link
// ============================================================================

/// Configuration for a macvtap interface.
///
/// Macvtap is similar to macvlan but provides a tap-like interface
/// that can be used by userspace programs (like QEMU/KVM for VM networking).
///
/// # Example
///
/// ```ignore
/// use nlink::netlink::link::{MacvtapLink, MacvlanMode};
///
/// let macvtap = MacvtapLink::new("macvtap0", "eth0")
///     .mode(MacvlanMode::Bridge);
///
/// conn.add_link(macvtap).await?;
/// ```
#[derive(Debug, Clone)]
#[must_use = "builders do nothing unless used"]
pub struct MacvtapLink {
    name: String,
    parent: InterfaceRef,
    mode: MacvlanMode,
    mtu: Option<u32>,
    address: Option<[u8; 6]>,
}

impl MacvtapLink {
    /// Create a new macvtap interface configuration.
    pub fn new(name: impl Into<String>, parent: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            parent: InterfaceRef::Name(parent.into()),
            mode: MacvlanMode::Bridge,
            mtu: None,
            address: None,
        }
    }

    /// Create a new macvtap interface with parent specified by index.
    ///
    /// This is the namespace-safe variant that avoids reading from /sys/class/net/.
    pub fn with_parent_index(name: impl Into<String>, parent_index: u32) -> Self {
        Self {
            name: name.into(),
            parent: InterfaceRef::Index(parent_index),
            mode: MacvlanMode::Bridge,
            mtu: None,
            address: None,
        }
    }

    /// Set the macvtap mode.
    pub fn mode(mut self, mode: MacvlanMode) -> Self {
        self.mode = mode;
        self
    }

    /// Set the MTU.
    pub fn mtu(mut self, mtu: u32) -> Self {
        self.mtu = Some(mtu);
        self
    }

    /// Set the MAC address.
    pub fn address(mut self, addr: [u8; 6]) -> Self {
        self.address = Some(addr);
        self
    }
}

impl LinkConfig for MacvtapLink {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> &str {
        "macvtap"
    }

    fn parent_ref(&self) -> Option<&InterfaceRef> {
        Some(&self.parent)
    }

    fn write_to(&self, builder: &mut MessageBuilder, parent_index: Option<u32>) {
        // Add interface name
        write_ifname(builder, &self.name);

        // Link to parent
        let idx = parent_index.expect("MacvtapLink requires parent_index");
        builder.append_attr_u32(IflaAttr::Link as u16, idx);

        // Add optional attributes
        if let Some(mtu) = self.mtu {
            builder.append_attr_u32(IflaAttr::Mtu as u16, mtu);
        }
        if let Some(ref addr) = self.address {
            builder.append_attr(IflaAttr::Address as u16, addr);
        }

        // IFLA_LINKINFO
        let linkinfo = builder.nest_start(IflaAttr::Linkinfo as u16);
        builder.append_attr_str(IflaInfo::Kind as u16, "macvtap");

        // IFLA_INFO_DATA - uses same attributes as macvlan
        let data = builder.nest_start(IflaInfo::Data as u16);
        builder.append_attr_u32(macvlan::IFLA_MACVLAN_MODE, self.mode as u32);
        builder.nest_end(data);

        builder.nest_end(linkinfo);
    }
}

// ============================================================================
// Geneve Link
// ============================================================================

/// Configuration for a Geneve (Generic Network Virtualization Encapsulation) interface.
///
/// Geneve is an overlay network encapsulation protocol similar to VXLAN but
/// with a more flexible TLV-based option mechanism.
///
/// # Example
///
/// ```ignore
/// use nlink::netlink::link::GeneveLink;
/// use std::net::Ipv4Addr;
///
/// let geneve = GeneveLink::new("geneve0", 100)
///     .remote(Ipv4Addr::new(192, 168, 1, 100))
///     .port(6081);
///
/// conn.add_link(geneve).await?;
/// ```
#[derive(Debug, Clone)]
#[must_use = "builders do nothing unless used"]
pub struct GeneveLink {
    name: String,
    vni: u32,
    mtu: Option<u32>,
    /// Remote IPv4 address
    remote: Option<Ipv4Addr>,
    /// Remote IPv6 address
    remote6: Option<std::net::Ipv6Addr>,
    /// TTL
    ttl: Option<u8>,
    /// TTL inherit from inner packet
    ttl_inherit: bool,
    /// TOS
    tos: Option<u8>,
    /// Don't Fragment setting
    df: Option<GeneveDf>,
    /// Flow label for IPv6
    label: Option<u32>,
    /// UDP destination port (default 6081)
    port: Option<u16>,
    /// Collect metadata mode (for BPF)
    collect_metadata: bool,
    /// UDP checksum
    udp_csum: Option<bool>,
    /// Zero UDP checksum for IPv6 TX
    udp6_zero_csum_tx: Option<bool>,
    /// Zero UDP checksum for IPv6 RX
    udp6_zero_csum_rx: Option<bool>,
    /// Inherit inner protocol
    inner_proto_inherit: bool,
}

/// Geneve DF (Don't Fragment) setting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum GeneveDf {
    /// Don't set DF
    Unset = 0,
    /// Set DF
    Set = 1,
    /// Inherit from inner packet
    Inherit = 2,
}

/// Geneve-specific attributes (IFLA_GENEVE_*)
mod geneve {
    pub const IFLA_GENEVE_ID: u16 = 1;
    pub const IFLA_GENEVE_REMOTE: u16 = 2;
    pub const IFLA_GENEVE_TTL: u16 = 3;
    pub const IFLA_GENEVE_TOS: u16 = 4;
    pub const IFLA_GENEVE_PORT: u16 = 5;
    pub const IFLA_GENEVE_COLLECT_METADATA: u16 = 6;
    pub const IFLA_GENEVE_REMOTE6: u16 = 7;
    pub const IFLA_GENEVE_UDP_CSUM: u16 = 8;
    pub const IFLA_GENEVE_UDP_ZERO_CSUM6_TX: u16 = 9;
    pub const IFLA_GENEVE_UDP_ZERO_CSUM6_RX: u16 = 10;
    pub const IFLA_GENEVE_LABEL: u16 = 11;
    pub const IFLA_GENEVE_TTL_INHERIT: u16 = 12;
    pub const IFLA_GENEVE_DF: u16 = 13;
    pub const IFLA_GENEVE_INNER_PROTO_INHERIT: u16 = 14;
}

impl GeneveLink {
    /// Create a new Geneve interface configuration.
    ///
    /// # Arguments
    ///
    /// * `name` - Name for the Geneve interface
    /// * `vni` - Virtual Network Identifier (0-16777215)
    pub fn new(name: impl Into<String>, vni: u32) -> Self {
        Self {
            name: name.into(),
            vni,
            mtu: None,
            remote: None,
            remote6: None,
            ttl: None,
            ttl_inherit: false,
            tos: None,
            df: None,
            label: None,
            port: None,
            collect_metadata: false,
            udp_csum: None,
            udp6_zero_csum_tx: None,
            udp6_zero_csum_rx: None,
            inner_proto_inherit: false,
        }
    }

    /// Set the MTU.
    pub fn mtu(mut self, mtu: u32) -> Self {
        self.mtu = Some(mtu);
        self
    }

    /// Set the remote IPv4 address.
    pub fn remote(mut self, addr: Ipv4Addr) -> Self {
        self.remote = Some(addr);
        self.remote6 = None;
        self
    }

    /// Set the remote IPv6 address.
    pub fn remote6(mut self, addr: std::net::Ipv6Addr) -> Self {
        self.remote6 = Some(addr);
        self.remote = None;
        self
    }

    /// Set the TTL.
    pub fn ttl(mut self, ttl: u8) -> Self {
        self.ttl = Some(ttl);
        self.ttl_inherit = false;
        self
    }

    /// Inherit TTL from inner packet.
    pub fn ttl_inherit(mut self) -> Self {
        self.ttl_inherit = true;
        self.ttl = None;
        self
    }

    /// Set the TOS.
    pub fn tos(mut self, tos: u8) -> Self {
        self.tos = Some(tos);
        self
    }

    /// Set the Don't Fragment behavior.
    pub fn df(mut self, df: GeneveDf) -> Self {
        self.df = Some(df);
        self
    }

    /// Set the flow label for IPv6.
    pub fn label(mut self, label: u32) -> Self {
        self.label = Some(label);
        self
    }

    /// Set the UDP destination port.
    pub fn port(mut self, port: u16) -> Self {
        self.port = Some(port);
        self
    }

    /// Enable collect metadata mode (for BPF programs).
    pub fn collect_metadata(mut self) -> Self {
        self.collect_metadata = true;
        self
    }

    /// Set UDP checksum.
    pub fn udp_csum(mut self, enabled: bool) -> Self {
        self.udp_csum = Some(enabled);
        self
    }

    /// Set zero UDP checksum for IPv6 TX.
    pub fn udp6_zero_csum_tx(mut self, enabled: bool) -> Self {
        self.udp6_zero_csum_tx = Some(enabled);
        self
    }

    /// Set zero UDP checksum for IPv6 RX.
    pub fn udp6_zero_csum_rx(mut self, enabled: bool) -> Self {
        self.udp6_zero_csum_rx = Some(enabled);
        self
    }

    /// Enable inner protocol inheritance.
    pub fn inner_proto_inherit(mut self) -> Self {
        self.inner_proto_inherit = true;
        self
    }
}

impl LinkConfig for GeneveLink {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> &str {
        "geneve"
    }

    fn write_to(&self, builder: &mut MessageBuilder, _parent_index: Option<u32>) {
        // Add interface name
        write_ifname(builder, &self.name);

        if let Some(mtu) = self.mtu {
            builder.append_attr_u32(IflaAttr::Mtu as u16, mtu);
        }

        // IFLA_LINKINFO
        let linkinfo = builder.nest_start(IflaAttr::Linkinfo as u16);
        builder.append_attr_str(IflaInfo::Kind as u16, "geneve");

        // IFLA_INFO_DATA
        let data = builder.nest_start(IflaInfo::Data as u16);

        // VNI (required)
        builder.append_attr_u32(geneve::IFLA_GENEVE_ID, self.vni);

        // Remote address
        if let Some(addr) = self.remote {
            builder.append_attr(geneve::IFLA_GENEVE_REMOTE, &addr.octets());
        } else if let Some(addr) = self.remote6 {
            builder.append_attr(geneve::IFLA_GENEVE_REMOTE6, &addr.octets());
        }

        // TTL
        if self.ttl_inherit {
            builder.append_attr_u8(geneve::IFLA_GENEVE_TTL_INHERIT, 1);
        } else if let Some(ttl) = self.ttl {
            builder.append_attr_u8(geneve::IFLA_GENEVE_TTL, ttl);
        }

        // TOS
        if let Some(tos) = self.tos {
            builder.append_attr_u8(geneve::IFLA_GENEVE_TOS, tos);
        }

        // DF
        if let Some(df) = self.df {
            builder.append_attr_u8(geneve::IFLA_GENEVE_DF, df as u8);
        }

        // Flow label
        if let Some(label) = self.label {
            builder.append_attr_u32(geneve::IFLA_GENEVE_LABEL, label);
        }

        // Port
        if let Some(port) = self.port {
            builder.append_attr_u16_be(geneve::IFLA_GENEVE_PORT, port);
        }

        // Collect metadata
        if self.collect_metadata {
            builder.append_attr_empty(geneve::IFLA_GENEVE_COLLECT_METADATA);
        }

        // UDP checksum options
        if let Some(enabled) = self.udp_csum {
            builder.append_attr_u8(geneve::IFLA_GENEVE_UDP_CSUM, if enabled { 1 } else { 0 });
        }
        if let Some(enabled) = self.udp6_zero_csum_tx {
            builder.append_attr_u8(
                geneve::IFLA_GENEVE_UDP_ZERO_CSUM6_TX,
                if enabled { 1 } else { 0 },
            );
        }
        if let Some(enabled) = self.udp6_zero_csum_rx {
            builder.append_attr_u8(
                geneve::IFLA_GENEVE_UDP_ZERO_CSUM6_RX,
                if enabled { 1 } else { 0 },
            );
        }

        // Inner protocol inherit
        if self.inner_proto_inherit {
            builder.append_attr_empty(geneve::IFLA_GENEVE_INNER_PROTO_INHERIT);
        }

        builder.nest_end(data);
        builder.nest_end(linkinfo);
    }
}

// ============================================================================
// Bareudp Link
// ============================================================================

/// Configuration for a Bareudp interface.
///
/// Bareudp is a minimal UDP tunneling driver that provides UDP encapsulation
/// for various L3 protocols like MPLS and IP.
///
/// # Example
///
/// ```ignore
/// use nlink::netlink::link::BareudpLink;
///
/// // Create a bareudp tunnel for MPLS
/// let bareudp = BareudpLink::new("bareudp0", 6635, 0x8847);
/// conn.add_link(bareudp).await?;
/// ```
#[derive(Debug, Clone)]
#[must_use = "builders do nothing unless used"]
pub struct BareudpLink {
    name: String,
    /// UDP destination port
    port: u16,
    /// EtherType of the tunneled protocol
    ethertype: u16,
    /// Minimum source port
    srcport_min: Option<u16>,
    /// Multiprotocol mode
    multiproto_mode: bool,
    mtu: Option<u32>,
}

/// Bareudp-specific attributes (IFLA_BAREUDP_*)
mod bareudp {
    pub const IFLA_BAREUDP_PORT: u16 = 1;
    pub const IFLA_BAREUDP_ETHERTYPE: u16 = 2;
    pub const IFLA_BAREUDP_SRCPORT_MIN: u16 = 3;
    pub const IFLA_BAREUDP_MULTIPROTO_MODE: u16 = 4;
}

impl BareudpLink {
    /// Create a new Bareudp interface configuration.
    ///
    /// # Arguments
    ///
    /// * `name` - Name for the interface
    /// * `port` - UDP destination port
    /// * `ethertype` - EtherType of tunneled protocol (e.g., 0x8847 for MPLS unicast)
    pub fn new(name: impl Into<String>, port: u16, ethertype: u16) -> Self {
        Self {
            name: name.into(),
            port,
            ethertype,
            srcport_min: None,
            multiproto_mode: false,
            mtu: None,
        }
    }

    /// Set the minimum source port.
    pub fn srcport_min(mut self, port: u16) -> Self {
        self.srcport_min = Some(port);
        self
    }

    /// Enable multiprotocol mode.
    pub fn multiproto_mode(mut self) -> Self {
        self.multiproto_mode = true;
        self
    }

    /// Set the MTU.
    pub fn mtu(mut self, mtu: u32) -> Self {
        self.mtu = Some(mtu);
        self
    }
}

impl LinkConfig for BareudpLink {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> &str {
        "bareudp"
    }

    fn write_to(&self, builder: &mut MessageBuilder, _parent_index: Option<u32>) {
        // Add interface name
        write_ifname(builder, &self.name);

        if let Some(mtu) = self.mtu {
            builder.append_attr_u32(IflaAttr::Mtu as u16, mtu);
        }

        // IFLA_LINKINFO
        let linkinfo = builder.nest_start(IflaAttr::Linkinfo as u16);
        builder.append_attr_str(IflaInfo::Kind as u16, "bareudp");

        // IFLA_INFO_DATA
        let data = builder.nest_start(IflaInfo::Data as u16);

        // Port (required) - network byte order
        builder.append_attr_u16_be(bareudp::IFLA_BAREUDP_PORT, self.port);

        // Ethertype (required) - network byte order
        builder.append_attr_u16_be(bareudp::IFLA_BAREUDP_ETHERTYPE, self.ethertype);

        // Source port min
        if let Some(srcport) = self.srcport_min {
            builder.append_attr_u16(bareudp::IFLA_BAREUDP_SRCPORT_MIN, srcport);
        }

        // Multiproto mode
        if self.multiproto_mode {
            builder.append_attr_empty(bareudp::IFLA_BAREUDP_MULTIPROTO_MODE);
        }

        builder.nest_end(data);
        builder.nest_end(linkinfo);
    }
}

// ============================================================================
// Netkit Link
// ============================================================================

/// Configuration for a Netkit interface.
///
/// Netkit devices are similar to veth but designed for BPF program attachment.
/// They provide a more efficient path for BPF-based packet processing.
///
/// # Example
///
/// ```ignore
/// use nlink::netlink::link::{NetkitLink, NetkitMode, NetkitPolicy};
///
/// let netkit = NetkitLink::new("nk0", "nk1")
///     .mode(NetkitMode::L3)
///     .policy(NetkitPolicy::Forward);
///
/// conn.add_link(netkit).await?;
/// ```
#[derive(Debug, Clone)]
#[must_use = "builders do nothing unless used"]
pub struct NetkitLink {
    name: String,
    peer_name: String,
    mode: Option<NetkitMode>,
    policy: Option<NetkitPolicy>,
    peer_policy: Option<NetkitPolicy>,
    scrub: Option<NetkitScrub>,
    peer_scrub: Option<NetkitScrub>,
    mtu: Option<u32>,
}

/// Netkit operating mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum NetkitMode {
    /// L2 mode (Ethernet frames)
    L2 = 0,
    /// L3 mode (IP packets)
    L3 = 1,
}

/// Netkit default policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum NetkitPolicy {
    /// Forward packets (default)
    Forward = 0,
    /// Blackhole (drop)
    Blackhole = 2,
}

/// Netkit scrub mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum NetkitScrub {
    /// No scrubbing
    None = 0,
    /// Default scrubbing
    Default = 1,
}

/// Netkit-specific attributes (IFLA_NETKIT_*)
mod netkit {
    pub const IFLA_NETKIT_PEER_INFO: u16 = 1;
    pub const IFLA_NETKIT_MODE: u16 = 4;
    pub const IFLA_NETKIT_POLICY: u16 = 2;
    pub const IFLA_NETKIT_PEER_POLICY: u16 = 3;
    pub const IFLA_NETKIT_SCRUB: u16 = 5;
    pub const IFLA_NETKIT_PEER_SCRUB: u16 = 6;
}

impl NetkitLink {
    /// Create a new Netkit pair configuration.
    ///
    /// # Arguments
    ///
    /// * `name` - Name for the primary interface
    /// * `peer_name` - Name for the peer interface
    pub fn new(name: impl Into<String>, peer_name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            peer_name: peer_name.into(),
            mode: None,
            policy: None,
            peer_policy: None,
            scrub: None,
            peer_scrub: None,
            mtu: None,
        }
    }

    /// Set the operating mode.
    pub fn mode(mut self, mode: NetkitMode) -> Self {
        self.mode = Some(mode);
        self
    }

    /// Set the default policy for the primary interface.
    pub fn policy(mut self, policy: NetkitPolicy) -> Self {
        self.policy = Some(policy);
        self
    }

    /// Set the default policy for the peer interface.
    pub fn peer_policy(mut self, policy: NetkitPolicy) -> Self {
        self.peer_policy = Some(policy);
        self
    }

    /// Set the scrub mode for the primary interface.
    pub fn scrub(mut self, scrub: NetkitScrub) -> Self {
        self.scrub = Some(scrub);
        self
    }

    /// Set the scrub mode for the peer interface.
    pub fn peer_scrub(mut self, scrub: NetkitScrub) -> Self {
        self.peer_scrub = Some(scrub);
        self
    }

    /// Set the MTU.
    pub fn mtu(mut self, mtu: u32) -> Self {
        self.mtu = Some(mtu);
        self
    }
}

impl LinkConfig for NetkitLink {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> &str {
        "netkit"
    }

    fn peer_name(&self) -> Option<&str> {
        Some(&self.peer_name)
    }

    fn write_to(&self, builder: &mut MessageBuilder, _parent_index: Option<u32>) {
        // Add interface name
        write_ifname(builder, &self.name);

        if let Some(mtu) = self.mtu {
            builder.append_attr_u32(IflaAttr::Mtu as u16, mtu);
        }

        // IFLA_LINKINFO
        let linkinfo = builder.nest_start(IflaAttr::Linkinfo as u16);
        builder.append_attr_str(IflaInfo::Kind as u16, "netkit");

        // IFLA_INFO_DATA
        let data = builder.nest_start(IflaInfo::Data as u16);

        // Mode
        if let Some(mode) = self.mode {
            builder.append_attr_u32(netkit::IFLA_NETKIT_MODE, mode as u32);
        }

        // Policy
        if let Some(policy) = self.policy {
            builder.append_attr_u32(netkit::IFLA_NETKIT_POLICY, policy as u32);
        }

        // Peer policy
        if let Some(policy) = self.peer_policy {
            builder.append_attr_u32(netkit::IFLA_NETKIT_PEER_POLICY, policy as u32);
        }

        // Scrub
        if let Some(scrub) = self.scrub {
            builder.append_attr_u32(netkit::IFLA_NETKIT_SCRUB, scrub as u32);
        }

        // Peer scrub
        if let Some(scrub) = self.peer_scrub {
            builder.append_attr_u32(netkit::IFLA_NETKIT_PEER_SCRUB, scrub as u32);
        }

        // Peer info (nested ifinfomsg for peer)
        let peer_info = builder.nest_start(netkit::IFLA_NETKIT_PEER_INFO);
        let peer_ifinfo = IfInfoMsg::new();
        builder.append(&peer_ifinfo);
        builder.append_attr_str(IflaAttr::Ifname as u16, &self.peer_name);
        builder.nest_end(peer_info);

        builder.nest_end(data);
        builder.nest_end(linkinfo);
    }
}

// ============================================================================
// Nlmon Link (Netlink Monitor)
// ============================================================================

/// Configuration for a netlink monitor interface.
///
/// Nlmon interfaces capture netlink traffic for debugging and analysis.
/// All netlink messages passing through the system can be captured.
///
/// # Example
///
/// ```ignore
/// use nlink::netlink::link::NlmonLink;
///
/// let nlmon = NlmonLink::new("nlmon0");
/// conn.add_link(nlmon).await?;
///
/// // Now use tcpdump or similar to capture netlink traffic:
/// // tcpdump -i nlmon0 -w netlink.pcap
/// ```
#[derive(Debug, Clone)]
#[must_use = "builders do nothing unless used"]
pub struct NlmonLink {
    name: String,
}

impl NlmonLink {
    /// Create a new netlink monitor interface configuration.
    pub fn new(name: impl Into<String>) -> Self {
        Self { name: name.into() }
    }
}

impl LinkConfig for NlmonLink {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> &str {
        "nlmon"
    }

    fn write_to(&self, builder: &mut MessageBuilder, _parent_index: Option<u32>) {
        write_simple_link(builder, &self.name, "nlmon", None, None);
    }
}

// ============================================================================
// VirtWifi Link
// ============================================================================

/// Configuration for a virtual WiFi interface.
///
/// VirtWifi creates a virtual wireless interface on top of an existing
/// Ethernet interface. This is useful for testing WiFi-dependent applications
/// without actual WiFi hardware.
///
/// # Example
///
/// ```ignore
/// use nlink::netlink::link::VirtWifiLink;
///
/// let vwifi = VirtWifiLink::new("vwifi0", "eth0");
/// conn.add_link(vwifi).await?;
/// ```
#[derive(Debug, Clone)]
#[must_use = "builders do nothing unless used"]
pub struct VirtWifiLink {
    name: String,
    link: InterfaceRef,
}

impl VirtWifiLink {
    /// Create a new virtual WiFi interface configuration.
    ///
    /// # Arguments
    ///
    /// * `name` - Name for the virtual WiFi interface
    /// * `link` - Name of the underlying Ethernet interface
    pub fn new(name: impl Into<String>, link: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            link: InterfaceRef::Name(link.into()),
        }
    }

    /// Create a new virtual WiFi interface with underlying link specified by index.
    ///
    /// This is the namespace-safe variant that avoids reading from /sys/class/net/.
    pub fn with_link_index(name: impl Into<String>, link_index: u32) -> Self {
        Self {
            name: name.into(),
            link: InterfaceRef::Index(link_index),
        }
    }
}

impl LinkConfig for VirtWifiLink {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> &str {
        "virt_wifi"
    }

    fn parent_ref(&self) -> Option<&InterfaceRef> {
        Some(&self.link)
    }

    fn write_to(&self, builder: &mut MessageBuilder, parent_index: Option<u32>) {
        // Add interface name
        write_ifname(builder, &self.name);

        // Set the underlying link
        let idx = parent_index.expect("VirtWifiLink requires link index");
        builder.append_attr_u32(IflaAttr::Link as u16, idx);

        // IFLA_LINKINFO
        let linkinfo = builder.nest_start(IflaAttr::Linkinfo as u16);
        builder.append_attr_str(IflaInfo::Kind as u16, "virt_wifi");
        builder.nest_end(linkinfo);
    }
}

// ============================================================================
// VTI Link (Virtual Tunnel Interface)
// ============================================================================

/// Configuration for a VTI (Virtual Tunnel Interface) for IPv4.
///
/// VTI interfaces are used with IPsec to create route-based VPNs.
/// Traffic routed through the VTI is automatically encrypted/decrypted.
///
/// # Example
///
/// ```ignore
/// use nlink::netlink::link::VtiLink;
/// use std::net::Ipv4Addr;
///
/// let vti = VtiLink::new("vti0")
///     .local(Ipv4Addr::new(10, 0, 0, 1))
///     .remote(Ipv4Addr::new(10, 0, 0, 2))
///     .ikey(100)
///     .okey(100);
///
/// conn.add_link(vti).await?;
/// ```
#[derive(Debug, Clone)]
#[must_use = "builders do nothing unless used"]
pub struct VtiLink {
    name: String,
    local: Option<Ipv4Addr>,
    remote: Option<Ipv4Addr>,
    ikey: Option<u32>,
    okey: Option<u32>,
    link: Option<InterfaceRef>,
}

/// VTI-specific attributes (IFLA_VTI_*)
#[allow(dead_code)]
mod vti {
    pub const IFLA_VTI_LINK: u16 = 1;
    pub const IFLA_VTI_IKEY: u16 = 2;
    pub const IFLA_VTI_OKEY: u16 = 3;
    pub const IFLA_VTI_LOCAL: u16 = 4;
    pub const IFLA_VTI_REMOTE: u16 = 5;
    pub const IFLA_VTI_FWMARK: u16 = 6;
}

impl VtiLink {
    /// Create a new VTI interface configuration.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            local: None,
            remote: None,
            ikey: None,
            okey: None,
            link: None,
        }
    }

    /// Set the local (source) address.
    pub fn local(mut self, addr: Ipv4Addr) -> Self {
        self.local = Some(addr);
        self
    }

    /// Set the remote (destination) address.
    pub fn remote(mut self, addr: Ipv4Addr) -> Self {
        self.remote = Some(addr);
        self
    }

    /// Set the input key (for identifying incoming traffic).
    pub fn ikey(mut self, key: u32) -> Self {
        self.ikey = Some(key);
        self
    }

    /// Set the output key (for marking outgoing traffic).
    pub fn okey(mut self, key: u32) -> Self {
        self.okey = Some(key);
        self
    }

    /// Set the underlying link device by name.
    pub fn link(mut self, link: impl Into<String>) -> Self {
        self.link = Some(InterfaceRef::Name(link.into()));
        self
    }

    /// Set the underlying link device by index.
    ///
    /// This is the namespace-safe variant that avoids reading from /sys/class/net/.
    pub fn link_index(mut self, index: u32) -> Self {
        self.link = Some(InterfaceRef::Index(index));
        self
    }
}

impl LinkConfig for VtiLink {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> &str {
        "vti"
    }

    fn parent_ref(&self) -> Option<&InterfaceRef> {
        self.link.as_ref()
    }

    fn write_to(&self, builder: &mut MessageBuilder, parent_index: Option<u32>) {
        // Add interface name
        write_ifname(builder, &self.name);

        // Set underlying link if specified
        if let Some(idx) = parent_index {
            builder.append_attr_u32(IflaAttr::Link as u16, idx);
        }

        // IFLA_LINKINFO
        let linkinfo = builder.nest_start(IflaAttr::Linkinfo as u16);
        builder.append_attr_str(IflaInfo::Kind as u16, "vti");

        // IFLA_INFO_DATA
        let data = builder.nest_start(IflaInfo::Data as u16);

        if let Some(local) = self.local {
            builder.append_attr(vti::IFLA_VTI_LOCAL, &local.octets());
        }
        if let Some(remote) = self.remote {
            builder.append_attr(vti::IFLA_VTI_REMOTE, &remote.octets());
        }
        if let Some(ikey) = self.ikey {
            builder.append_attr_u32_be(vti::IFLA_VTI_IKEY, ikey);
        }
        if let Some(okey) = self.okey {
            builder.append_attr_u32_be(vti::IFLA_VTI_OKEY, okey);
        }

        builder.nest_end(data);
        builder.nest_end(linkinfo);
    }
}

// ============================================================================
// VTI6 Link (Virtual Tunnel Interface for IPv6)
// ============================================================================

/// Configuration for a VTI6 (Virtual Tunnel Interface) for IPv6.
///
/// Similar to VTI but for IPv6 tunnels.
///
/// # Example
///
/// ```ignore
/// use nlink::netlink::link::Vti6Link;
/// use std::net::Ipv6Addr;
///
/// let vti6 = Vti6Link::new("vti6_0")
///     .local(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1))
///     .remote(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2));
///
/// conn.add_link(vti6).await?;
/// ```
#[derive(Debug, Clone)]
#[must_use = "builders do nothing unless used"]
pub struct Vti6Link {
    name: String,
    local: Option<std::net::Ipv6Addr>,
    remote: Option<std::net::Ipv6Addr>,
    ikey: Option<u32>,
    okey: Option<u32>,
    link: Option<InterfaceRef>,
}

impl Vti6Link {
    /// Create a new VTI6 interface configuration.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            local: None,
            remote: None,
            ikey: None,
            okey: None,
            link: None,
        }
    }

    /// Set the local (source) address.
    pub fn local(mut self, addr: std::net::Ipv6Addr) -> Self {
        self.local = Some(addr);
        self
    }

    /// Set the remote (destination) address.
    pub fn remote(mut self, addr: std::net::Ipv6Addr) -> Self {
        self.remote = Some(addr);
        self
    }

    /// Set the input key (for identifying incoming traffic).
    pub fn ikey(mut self, key: u32) -> Self {
        self.ikey = Some(key);
        self
    }

    /// Set the output key (for marking outgoing traffic).
    pub fn okey(mut self, key: u32) -> Self {
        self.okey = Some(key);
        self
    }

    /// Set the underlying link device by name.
    pub fn link(mut self, link: impl Into<String>) -> Self {
        self.link = Some(InterfaceRef::Name(link.into()));
        self
    }

    /// Set the underlying link device by index.
    ///
    /// This is the namespace-safe variant that avoids reading from /sys/class/net/.
    pub fn link_index(mut self, index: u32) -> Self {
        self.link = Some(InterfaceRef::Index(index));
        self
    }
}

impl LinkConfig for Vti6Link {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> &str {
        "vti6"
    }

    fn parent_ref(&self) -> Option<&InterfaceRef> {
        self.link.as_ref()
    }

    fn write_to(&self, builder: &mut MessageBuilder, parent_index: Option<u32>) {
        // Add interface name
        write_ifname(builder, &self.name);

        // Set underlying link if specified
        if let Some(idx) = parent_index {
            builder.append_attr_u32(IflaAttr::Link as u16, idx);
        }

        // IFLA_LINKINFO
        let linkinfo = builder.nest_start(IflaAttr::Linkinfo as u16);
        builder.append_attr_str(IflaInfo::Kind as u16, "vti6");

        // IFLA_INFO_DATA - VTI6 uses same attributes as VTI
        let data = builder.nest_start(IflaInfo::Data as u16);

        if let Some(local) = self.local {
            builder.append_attr(vti::IFLA_VTI_LOCAL, &local.octets());
        }
        if let Some(remote) = self.remote {
            builder.append_attr(vti::IFLA_VTI_REMOTE, &remote.octets());
        }
        if let Some(ikey) = self.ikey {
            builder.append_attr_u32_be(vti::IFLA_VTI_IKEY, ikey);
        }
        if let Some(okey) = self.okey {
            builder.append_attr_u32_be(vti::IFLA_VTI_OKEY, okey);
        }

        builder.nest_end(data);
        builder.nest_end(linkinfo);
    }
}

// ============================================================================
// IP6GRE Link
// ============================================================================

/// Configuration for an IP6GRE (IPv6 GRE tunnel) interface.
///
/// IP6GRE creates a GRE tunnel over IPv6. This is useful for
/// encapsulating IPv4 or IPv6 traffic over an IPv6 network.
///
/// # Example
///
/// ```ignore
/// use nlink::netlink::link::Ip6GreLink;
/// use std::net::Ipv6Addr;
///
/// let gre = Ip6GreLink::new("ip6gre0")
///     .local(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1))
///     .remote(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2))
///     .ttl(64);
///
/// conn.add_link(gre).await?;
/// ```
#[derive(Debug, Clone)]
#[must_use = "builders do nothing unless used"]
pub struct Ip6GreLink {
    name: String,
    local: Option<std::net::Ipv6Addr>,
    remote: Option<std::net::Ipv6Addr>,
    ttl: Option<u8>,
    encap_limit: Option<u8>,
    flowinfo: Option<u32>,
    flags: Option<u32>,
    link: Option<InterfaceRef>,
}

/// IFLA_GRE_* attributes (shared by gre, gretap, ip6gre, ip6gretap, erspan).
/// Verified against linux/if_tunnel.h (kernel 6.19.6).
#[allow(dead_code)]
mod gre_attr {
    pub const IFLA_GRE_LINK: u16 = 1;
    pub const IFLA_GRE_IFLAGS: u16 = 2;
    pub const IFLA_GRE_OFLAGS: u16 = 3;
    pub const IFLA_GRE_IKEY: u16 = 4;
    pub const IFLA_GRE_OKEY: u16 = 5;
    pub const IFLA_GRE_LOCAL: u16 = 6;
    pub const IFLA_GRE_REMOTE: u16 = 7;
    pub const IFLA_GRE_TTL: u16 = 8;
    pub const IFLA_GRE_TOS: u16 = 9;
    pub const IFLA_GRE_PMTUDISC: u16 = 10;
    pub const IFLA_GRE_ENCAP_LIMIT: u16 = 11;
    pub const IFLA_GRE_FLOWINFO: u16 = 12;
    pub const IFLA_GRE_FLAGS: u16 = 13;
    pub const IFLA_GRE_ENCAP_TYPE: u16 = 14;
    pub const IFLA_GRE_ENCAP_FLAGS: u16 = 15;
    pub const IFLA_GRE_ENCAP_SPORT: u16 = 16;
    pub const IFLA_GRE_ENCAP_DPORT: u16 = 17;
    pub const IFLA_GRE_COLLECT_METADATA: u16 = 18;
    pub const IFLA_GRE_IGNORE_DF: u16 = 19;
    pub const IFLA_GRE_FWMARK: u16 = 20;

    /// GRE_KEY flag for IFLA_GRE_IFLAGS/OFLAGS.
    pub const GRE_KEY: u16 = 0x2000;
}

/// IFLA_IPTUN_* attributes (for ipip and sit tunnels).
/// Separate enum from IFLA_GRE_* — different numeric values.
/// Verified against linux/if_tunnel.h (kernel 6.19.6).
#[allow(dead_code)]
mod iptun_attr {
    pub const IFLA_IPTUN_LINK: u16 = 1;
    pub const IFLA_IPTUN_LOCAL: u16 = 2;
    pub const IFLA_IPTUN_REMOTE: u16 = 3;
    pub const IFLA_IPTUN_TTL: u16 = 4;
    pub const IFLA_IPTUN_TOS: u16 = 5;
    pub const IFLA_IPTUN_ENCAP_LIMIT: u16 = 6;
    pub const IFLA_IPTUN_FLOWINFO: u16 = 7;
    pub const IFLA_IPTUN_FLAGS: u16 = 8;
    pub const IFLA_IPTUN_PROTO: u16 = 9;
    pub const IFLA_IPTUN_PMTUDISC: u16 = 10;
    pub const IFLA_IPTUN_ENCAP_TYPE: u16 = 15;
    pub const IFLA_IPTUN_ENCAP_FLAGS: u16 = 16;
    pub const IFLA_IPTUN_ENCAP_SPORT: u16 = 17;
    pub const IFLA_IPTUN_ENCAP_DPORT: u16 = 18;
    pub const IFLA_IPTUN_COLLECT_METADATA: u16 = 19;
    pub const IFLA_IPTUN_FWMARK: u16 = 20;

    /// ISATAP flag for SIT tunnels (IFLA_IPTUN_FLAGS).
    pub const SIT_ISATAP: u16 = 0x0001;
}

impl Ip6GreLink {
    /// Create a new IP6GRE interface configuration.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            local: None,
            remote: None,
            ttl: None,
            encap_limit: None,
            flowinfo: None,
            flags: None,
            link: None,
        }
    }

    /// Set the local (source) address.
    pub fn local(mut self, addr: std::net::Ipv6Addr) -> Self {
        self.local = Some(addr);
        self
    }

    /// Set the remote (destination) address.
    pub fn remote(mut self, addr: std::net::Ipv6Addr) -> Self {
        self.remote = Some(addr);
        self
    }

    /// Set the TTL (hop limit).
    pub fn ttl(mut self, ttl: u8) -> Self {
        self.ttl = Some(ttl);
        self
    }

    /// Set the encapsulation limit.
    pub fn encap_limit(mut self, limit: u8) -> Self {
        self.encap_limit = Some(limit);
        self
    }

    /// Set the flow label.
    pub fn flowinfo(mut self, flowinfo: u32) -> Self {
        self.flowinfo = Some(flowinfo);
        self
    }

    /// Set the underlying link device by name.
    pub fn link(mut self, link: impl Into<String>) -> Self {
        self.link = Some(InterfaceRef::Name(link.into()));
        self
    }

    /// Set the underlying link device by index.
    ///
    /// This is the namespace-safe variant that avoids reading from /sys/class/net/.
    pub fn link_index(mut self, index: u32) -> Self {
        self.link = Some(InterfaceRef::Index(index));
        self
    }
}

impl LinkConfig for Ip6GreLink {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> &str {
        "ip6gre"
    }

    fn parent_ref(&self) -> Option<&InterfaceRef> {
        self.link.as_ref()
    }

    fn write_to(&self, builder: &mut MessageBuilder, parent_index: Option<u32>) {
        // Add interface name
        write_ifname(builder, &self.name);

        // IFLA_LINKINFO
        let linkinfo = builder.nest_start(IflaAttr::Linkinfo as u16);
        builder.append_attr_str(IflaInfo::Kind as u16, "ip6gre");

        // IFLA_INFO_DATA
        let data = builder.nest_start(IflaInfo::Data as u16);

        if let Some(idx) = parent_index {
            builder.append_attr_u32(gre_attr::IFLA_GRE_LINK, idx);
        }
        if let Some(local) = self.local {
            builder.append_attr(gre_attr::IFLA_GRE_LOCAL, &local.octets());
        }
        if let Some(remote) = self.remote {
            builder.append_attr(gre_attr::IFLA_GRE_REMOTE, &remote.octets());
        }
        if let Some(ttl) = self.ttl {
            builder.append_attr_u8(gre_attr::IFLA_GRE_TTL, ttl);
        }
        if let Some(limit) = self.encap_limit {
            builder.append_attr_u8(gre_attr::IFLA_GRE_ENCAP_LIMIT, limit);
        }
        if let Some(flowinfo) = self.flowinfo {
            builder.append_attr_u32_be(gre_attr::IFLA_GRE_FLOWINFO, flowinfo);
        }
        if let Some(flags) = self.flags {
            builder.append_attr_u32(gre_attr::IFLA_GRE_FLAGS, flags);
        }

        builder.nest_end(data);
        builder.nest_end(linkinfo);
    }
}

// ============================================================================
// IP6GRETAP Link
// ============================================================================

/// Configuration for an IP6GRETAP (IPv6 GRE TAP tunnel) interface.
///
/// Similar to IP6GRE but operates at Layer 2, encapsulating Ethernet frames.
/// This is useful for bridging networks over an IPv6 tunnel.
///
/// # Example
///
/// ```ignore
/// use nlink::netlink::link::Ip6GretapLink;
/// use std::net::Ipv6Addr;
///
/// let gretap = Ip6GretapLink::new("ip6gretap0")
///     .local(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1))
///     .remote(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2))
///     .ttl(64);
///
/// conn.add_link(gretap).await?;
/// ```
#[derive(Debug, Clone)]
#[must_use = "builders do nothing unless used"]
pub struct Ip6GretapLink {
    name: String,
    local: Option<std::net::Ipv6Addr>,
    remote: Option<std::net::Ipv6Addr>,
    ttl: Option<u8>,
    encap_limit: Option<u8>,
    flowinfo: Option<u32>,
    link: Option<InterfaceRef>,
}

impl Ip6GretapLink {
    /// Create a new IP6GRETAP interface configuration.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            local: None,
            remote: None,
            ttl: None,
            encap_limit: None,
            flowinfo: None,
            link: None,
        }
    }

    /// Set the local (source) address.
    pub fn local(mut self, addr: std::net::Ipv6Addr) -> Self {
        self.local = Some(addr);
        self
    }

    /// Set the remote (destination) address.
    pub fn remote(mut self, addr: std::net::Ipv6Addr) -> Self {
        self.remote = Some(addr);
        self
    }

    /// Set the TTL (hop limit).
    pub fn ttl(mut self, ttl: u8) -> Self {
        self.ttl = Some(ttl);
        self
    }

    /// Set the encapsulation limit.
    pub fn encap_limit(mut self, limit: u8) -> Self {
        self.encap_limit = Some(limit);
        self
    }

    /// Set the flow label.
    pub fn flowinfo(mut self, flowinfo: u32) -> Self {
        self.flowinfo = Some(flowinfo);
        self
    }

    /// Set the underlying link device by name.
    pub fn link(mut self, link: impl Into<String>) -> Self {
        self.link = Some(InterfaceRef::Name(link.into()));
        self
    }

    /// Set the underlying link device by index.
    ///
    /// This is the namespace-safe variant that avoids reading from /sys/class/net/.
    pub fn link_index(mut self, index: u32) -> Self {
        self.link = Some(InterfaceRef::Index(index));
        self
    }
}

impl LinkConfig for Ip6GretapLink {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> &str {
        "ip6gretap"
    }

    fn parent_ref(&self) -> Option<&InterfaceRef> {
        self.link.as_ref()
    }

    fn write_to(&self, builder: &mut MessageBuilder, parent_index: Option<u32>) {
        // Add interface name
        write_ifname(builder, &self.name);

        // IFLA_LINKINFO
        let linkinfo = builder.nest_start(IflaAttr::Linkinfo as u16);
        builder.append_attr_str(IflaInfo::Kind as u16, "ip6gretap");

        // IFLA_INFO_DATA - uses same attributes as ip6gre
        let data = builder.nest_start(IflaInfo::Data as u16);

        if let Some(idx) = parent_index {
            builder.append_attr_u32(gre_attr::IFLA_GRE_LINK, idx);
        }
        if let Some(local) = self.local {
            builder.append_attr(gre_attr::IFLA_GRE_LOCAL, &local.octets());
        }
        if let Some(remote) = self.remote {
            builder.append_attr(gre_attr::IFLA_GRE_REMOTE, &remote.octets());
        }
        if let Some(ttl) = self.ttl {
            builder.append_attr_u8(gre_attr::IFLA_GRE_TTL, ttl);
        }
        if let Some(limit) = self.encap_limit {
            builder.append_attr_u8(gre_attr::IFLA_GRE_ENCAP_LIMIT, limit);
        }
        if let Some(flowinfo) = self.flowinfo {
            builder.append_attr_u32_be(gre_attr::IFLA_GRE_FLOWINFO, flowinfo);
        }

        builder.nest_end(data);
        builder.nest_end(linkinfo);
    }
}

// ============================================================================
// Bond Link
// ============================================================================

/// Bond mode constants (deprecated, use `BondMode` enum instead).
#[deprecated(note = "use `BondMode` enum instead")]
pub mod bond_mode {
    pub const BALANCE_RR: u8 = 0;
    pub const ACTIVE_BACKUP: u8 = 1;
    pub const BALANCE_XOR: u8 = 2;
    pub const BROADCAST: u8 = 3;
    pub const LACP: u8 = 4; // 802.3ad
    pub const BALANCE_TLB: u8 = 5;
    pub const BALANCE_ALB: u8 = 6;
}

/// Bonding mode.
///
/// Determines how traffic is distributed across slave interfaces.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
#[non_exhaustive]
pub enum BondMode {
    /// Round-robin: packets transmitted in sequential order.
    BalanceRr = 0,
    /// Active-backup: only one slave active, failover on link failure.
    ActiveBackup = 1,
    /// XOR: transmit based on hash of source/destination.
    BalanceXor = 2,
    /// Broadcast: all packets on all slaves.
    Broadcast = 3,
    /// IEEE 802.3ad (LACP): dynamic link aggregation.
    Lacp = 4,
    /// Adaptive transmit load balancing.
    BalanceTlb = 5,
    /// Adaptive load balancing (RX + TX).
    BalanceAlb = 6,
}

impl TryFrom<u8> for BondMode {
    type Error = super::Error;
    fn try_from(value: u8) -> std::result::Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::BalanceRr),
            1 => Ok(Self::ActiveBackup),
            2 => Ok(Self::BalanceXor),
            3 => Ok(Self::Broadcast),
            4 => Ok(Self::Lacp),
            5 => Ok(Self::BalanceTlb),
            6 => Ok(Self::BalanceAlb),
            _ => Err(super::Error::InvalidAttribute(format!(
                "unknown bond mode: {value}"
            ))),
        }
    }
}

/// Transmit hash policy for XOR/LACP modes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
#[non_exhaustive]
pub enum XmitHashPolicy {
    /// Hash by L2 (MAC) addresses.
    Layer2 = 0,
    /// Hash by L3+L4 (IP + port).
    Layer34 = 1,
    /// Hash by L2+L3 (MAC + IP).
    Layer23 = 2,
    /// Hash by encapsulated L2+L3.
    Encap23 = 3,
    /// Hash by encapsulated L3+L4.
    Encap34 = 4,
    /// Hash by VLAN + source MAC.
    VlanSrcMac = 5,
}

impl TryFrom<u8> for XmitHashPolicy {
    type Error = super::Error;
    fn try_from(value: u8) -> std::result::Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Layer2),
            1 => Ok(Self::Layer34),
            2 => Ok(Self::Layer23),
            3 => Ok(Self::Encap23),
            4 => Ok(Self::Encap34),
            5 => Ok(Self::VlanSrcMac),
            _ => Err(super::Error::InvalidAttribute(format!(
                "unknown xmit hash policy: {value}"
            ))),
        }
    }
}

/// LACP rate for 802.3ad mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
#[non_exhaustive]
pub enum LacpRate {
    /// Send LACPDUs every 30 seconds.
    Slow = 0,
    /// Send LACPDUs every 1 second.
    Fast = 1,
}

/// Primary slave reselection policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
#[non_exhaustive]
pub enum PrimaryReselect {
    /// Always reselect when a better slave comes up.
    Always = 0,
    /// Reselect only if the new slave is better.
    Better = 1,
    /// Reselect only on active slave failure.
    Failure = 2,
}

/// Fail-over MAC address policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
#[non_exhaustive]
pub enum FailOverMac {
    /// Don't change MAC on failover.
    None = 0,
    /// Set bond MAC to active slave's MAC.
    Active = 1,
    /// Follow the current active slave's MAC.
    Follow = 2,
}

/// ARP validation mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
#[non_exhaustive]
pub enum ArpValidate {
    /// No ARP validation.
    None = 0,
    /// Validate only on the active slave.
    Active = 1,
    /// Validate only on backup slaves.
    Backup = 2,
    /// Validate on all slaves.
    All = 3,
    /// Filter and validate on active.
    FilterActive = 4,
    /// Filter and validate on backup.
    FilterBackup = 5,
}

/// Ad (802.3ad) selection logic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
#[non_exhaustive]
pub enum AdSelect {
    /// Select by highest aggregator bandwidth.
    Stable = 0,
    /// Select by aggregator bandwidth.
    Bandwidth = 1,
    /// Select by number of ports.
    Count = 2,
}

/// IFLA_BOND_* attribute constants (verified against linux/if_link.h, kernel 6.19.6).
#[allow(dead_code)]
mod bond_attr {
    pub const IFLA_BOND_MODE: u16 = 1;
    pub const IFLA_BOND_ACTIVE_SLAVE: u16 = 2;
    pub const IFLA_BOND_MIIMON: u16 = 3;
    pub const IFLA_BOND_UPDELAY: u16 = 4;
    pub const IFLA_BOND_DOWNDELAY: u16 = 5;
    pub const IFLA_BOND_USE_CARRIER: u16 = 6;
    pub const IFLA_BOND_ARP_INTERVAL: u16 = 7;
    pub const IFLA_BOND_ARP_IP_TARGET: u16 = 8;
    pub const IFLA_BOND_ARP_VALIDATE: u16 = 9;
    pub const IFLA_BOND_ARP_ALL_TARGETS: u16 = 10;
    pub const IFLA_BOND_PRIMARY: u16 = 11;
    pub const IFLA_BOND_PRIMARY_RESELECT: u16 = 12;
    pub const IFLA_BOND_FAIL_OVER_MAC: u16 = 13;
    pub const IFLA_BOND_XMIT_HASH_POLICY: u16 = 14;
    pub const IFLA_BOND_RESEND_IGMP: u16 = 15;
    pub const IFLA_BOND_NUM_PEER_NOTIF: u16 = 16;
    pub const IFLA_BOND_ALL_SLAVES_ACTIVE: u16 = 17;
    pub const IFLA_BOND_MIN_LINKS: u16 = 18;
    pub const IFLA_BOND_LP_INTERVAL: u16 = 19;
    pub const IFLA_BOND_PACKETS_PER_SLAVE: u16 = 20;
    pub const IFLA_BOND_AD_LACP_RATE: u16 = 21;
    pub const IFLA_BOND_AD_SELECT: u16 = 22;
    pub const IFLA_BOND_AD_INFO: u16 = 23;
    pub const IFLA_BOND_AD_ACTOR_SYS_PRIO: u16 = 24;
    pub const IFLA_BOND_AD_USER_PORT_KEY: u16 = 25;
    pub const IFLA_BOND_AD_ACTOR_SYSTEM: u16 = 26;
    pub const IFLA_BOND_TLB_DYNAMIC_LB: u16 = 27;
    pub const IFLA_BOND_PEER_NOTIF_DELAY: u16 = 28;
    pub const IFLA_BOND_AD_LACP_ACTIVE: u16 = 29;
    pub const IFLA_BOND_MISSED_MAX: u16 = 30;
    pub const IFLA_BOND_NS_IP6_TARGET: u16 = 31;
    pub const IFLA_BOND_COUPLED_CONTROL: u16 = 32;
}

/// Configuration for a bonding (link aggregation) interface.
///
/// Supports all 33 kernel IFLA_BOND_* attributes with typed enums.
///
/// # Example
///
/// ```ignore
/// use nlink::netlink::link::{BondLink, BondMode, XmitHashPolicy, LacpRate};
///
/// // LACP bond with fast rate and layer3+4 hashing
/// let bond = BondLink::new("bond0")
///     .mode(BondMode::Lacp)
///     .miimon(100)
///     .lacp_rate(LacpRate::Fast)
///     .xmit_hash_policy(XmitHashPolicy::Layer34)
///     .min_links(1);
/// conn.add_link(bond).await?;
///
/// // Active-backup with ARP monitoring
/// let bond = BondLink::new("bond1")
///     .mode(BondMode::ActiveBackup)
///     .arp_interval(200)
///     .arp_ip_target(Ipv4Addr::new(192, 168, 1, 1))
///     .arp_validate(ArpValidate::All);
/// conn.add_link(bond).await?;
/// ```
#[derive(Debug, Clone)]
#[must_use = "builders do nothing unless used"]
pub struct BondLink {
    name: String,
    mode: BondMode,
    mtu: Option<u32>,
    address: Option<[u8; 6]>,

    // MII monitoring
    miimon: Option<u32>,
    updelay: Option<u32>,
    downdelay: Option<u32>,
    use_carrier: Option<bool>,

    // ARP monitoring
    arp_interval: Option<u32>,
    arp_ip_targets: Vec<Ipv4Addr>,
    arp_validate: Option<ArpValidate>,
    arp_all_targets: Option<u32>,

    // Slave selection
    primary_reselect: Option<PrimaryReselect>,
    fail_over_mac: Option<FailOverMac>,

    // Hashing / distribution
    xmit_hash_policy: Option<XmitHashPolicy>,
    min_links: Option<u32>,
    packets_per_slave: Option<u32>,

    // 802.3ad (LACP) specific
    lacp_rate: Option<LacpRate>,
    ad_select: Option<AdSelect>,
    ad_actor_sys_prio: Option<u16>,
    ad_user_port_key: Option<u16>,
    ad_actor_system: Option<[u8; 6]>,
    lacp_active: Option<bool>,

    // Misc
    all_slaves_active: Option<bool>,
    resend_igmp: Option<u32>,
    num_peer_notif: Option<u8>,
    lp_interval: Option<u32>,
    tlb_dynamic_lb: Option<bool>,
    peer_notif_delay: Option<u32>,
    missed_max: Option<u8>,
    coupled_control: Option<bool>,
}

impl BondLink {
    /// Create a new bond interface with default mode (balance-rr).
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            mode: BondMode::BalanceRr,
            mtu: None,
            address: None,
            miimon: None,
            updelay: None,
            downdelay: None,
            use_carrier: None,
            arp_interval: None,
            arp_ip_targets: Vec::new(),
            arp_validate: None,
            arp_all_targets: None,
            primary_reselect: None,
            fail_over_mac: None,
            xmit_hash_policy: None,
            min_links: None,
            packets_per_slave: None,
            lacp_rate: None,
            ad_select: None,
            ad_actor_sys_prio: None,
            ad_user_port_key: None,
            ad_actor_system: None,
            lacp_active: None,
            all_slaves_active: None,
            resend_igmp: None,
            num_peer_notif: None,
            lp_interval: None,
            tlb_dynamic_lb: None,
            peer_notif_delay: None,
            missed_max: None,
            coupled_control: None,
        }
    }

    /// Set the bonding mode.
    pub fn mode(mut self, mode: BondMode) -> Self {
        self.mode = mode;
        self
    }

    /// Set the MII link monitoring interval in milliseconds.
    pub fn miimon(mut self, ms: u32) -> Self {
        self.miimon = Some(ms);
        self
    }

    /// Set the delay before enabling a slave after link up (ms).
    pub fn updelay(mut self, ms: u32) -> Self {
        self.updelay = Some(ms);
        self
    }

    /// Set the delay before disabling a slave after link down (ms).
    pub fn downdelay(mut self, ms: u32) -> Self {
        self.downdelay = Some(ms);
        self
    }

    /// Use carrier state for link monitoring instead of MII/ethtool.
    pub fn use_carrier(mut self, enabled: bool) -> Self {
        self.use_carrier = Some(enabled);
        self
    }

    /// Set the minimum number of links for the bond to be up.
    pub fn min_links(mut self, n: u32) -> Self {
        self.min_links = Some(n);
        self
    }

    /// Set the transmit hash policy.
    pub fn xmit_hash_policy(mut self, policy: XmitHashPolicy) -> Self {
        self.xmit_hash_policy = Some(policy);
        self
    }

    /// Set the LACP rate (for 802.3ad mode).
    pub fn lacp_rate(mut self, rate: LacpRate) -> Self {
        self.lacp_rate = Some(rate);
        self
    }

    /// Set the ad selection logic (for 802.3ad mode).
    pub fn ad_select(mut self, select: AdSelect) -> Self {
        self.ad_select = Some(select);
        self
    }

    /// Set the ARP monitoring interval in milliseconds.
    pub fn arp_interval(mut self, ms: u32) -> Self {
        self.arp_interval = Some(ms);
        self
    }

    /// Add an ARP monitoring target IP (up to 16).
    pub fn arp_ip_target(mut self, addr: Ipv4Addr) -> Self {
        self.arp_ip_targets.push(addr);
        self
    }

    /// Set the ARP validation mode.
    pub fn arp_validate(mut self, validate: ArpValidate) -> Self {
        self.arp_validate = Some(validate);
        self
    }

    /// Set the primary slave reselection policy.
    pub fn primary_reselect(mut self, policy: PrimaryReselect) -> Self {
        self.primary_reselect = Some(policy);
        self
    }

    /// Set the fail-over MAC address policy.
    pub fn fail_over_mac(mut self, policy: FailOverMac) -> Self {
        self.fail_over_mac = Some(policy);
        self
    }

    /// Enable/disable all slaves active (for multicast/broadcast).
    pub fn all_slaves_active(mut self, enabled: bool) -> Self {
        self.all_slaves_active = Some(enabled);
        self
    }

    /// Enable/disable TLB dynamic load balancing.
    pub fn tlb_dynamic_lb(mut self, enabled: bool) -> Self {
        self.tlb_dynamic_lb = Some(enabled);
        self
    }

    /// Set the MTU.
    pub fn mtu(mut self, mtu: u32) -> Self {
        self.mtu = Some(mtu);
        self
    }

    /// Set the MAC address.
    pub fn address(mut self, address: [u8; 6]) -> Self {
        self.address = Some(address);
        self
    }

    /// Set 802.3ad actor system priority.
    pub fn ad_actor_sys_prio(mut self, prio: u16) -> Self {
        self.ad_actor_sys_prio = Some(prio);
        self
    }

    /// Set 802.3ad user port key.
    pub fn ad_user_port_key(mut self, key: u16) -> Self {
        self.ad_user_port_key = Some(key);
        self
    }

    /// Set 802.3ad actor system MAC address.
    pub fn ad_actor_system(mut self, mac: [u8; 6]) -> Self {
        self.ad_actor_system = Some(mac);
        self
    }

    /// Enable/disable LACP active mode (for 802.3ad).
    pub fn lacp_active(mut self, enabled: bool) -> Self {
        self.lacp_active = Some(enabled);
        self
    }

    /// Set the number of peer notifications after failover.
    pub fn num_peer_notif(mut self, n: u8) -> Self {
        self.num_peer_notif = Some(n);
        self
    }

    /// Set the IGMP resend count after failover.
    pub fn resend_igmp(mut self, count: u32) -> Self {
        self.resend_igmp = Some(count);
        self
    }

    /// Set the learning packets interval (ms).
    pub fn lp_interval(mut self, ms: u32) -> Self {
        self.lp_interval = Some(ms);
        self
    }

    /// Set packets per slave for balance-rr mode.
    pub fn packets_per_slave(mut self, n: u32) -> Self {
        self.packets_per_slave = Some(n);
        self
    }

    /// Set the peer notification delay (ms).
    pub fn peer_notif_delay(mut self, ms: u32) -> Self {
        self.peer_notif_delay = Some(ms);
        self
    }

    /// Set the maximum number of missed MII monitoring intervals.
    pub fn missed_max(mut self, n: u8) -> Self {
        self.missed_max = Some(n);
        self
    }

    /// Enable/disable coupled control (kernel 6.0+).
    pub fn coupled_control(mut self, enabled: bool) -> Self {
        self.coupled_control = Some(enabled);
        self
    }
}

impl LinkConfig for BondLink {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> &str {
        "bond"
    }

    fn write_to(&self, builder: &mut MessageBuilder, _parent_index: Option<u32>) {
        write_ifname(builder, &self.name);

        if let Some(mtu) = self.mtu {
            builder.append_attr_u32(IflaAttr::Mtu as u16, mtu);
        }
        if let Some(ref addr) = self.address {
            builder.append_attr(IflaAttr::Address as u16, addr);
        }

        let linkinfo = builder.nest_start(IflaAttr::Linkinfo as u16);
        builder.append_attr_str(IflaInfo::Kind as u16, "bond");

        let data = builder.nest_start(IflaInfo::Data as u16);
        builder.append_attr_u8(bond_attr::IFLA_BOND_MODE, self.mode as u8);

        if let Some(v) = self.miimon {
            builder.append_attr_u32(bond_attr::IFLA_BOND_MIIMON, v);
        }
        if let Some(v) = self.updelay {
            builder.append_attr_u32(bond_attr::IFLA_BOND_UPDELAY, v);
        }
        if let Some(v) = self.downdelay {
            builder.append_attr_u32(bond_attr::IFLA_BOND_DOWNDELAY, v);
        }
        if let Some(v) = self.use_carrier {
            builder.append_attr_u8(bond_attr::IFLA_BOND_USE_CARRIER, v as u8);
        }
        if let Some(v) = self.arp_interval {
            builder.append_attr_u32(bond_attr::IFLA_BOND_ARP_INTERVAL, v);
        }
        if let Some(v) = self.arp_validate {
            builder.append_attr_u32(bond_attr::IFLA_BOND_ARP_VALIDATE, v as u32);
        }
        if let Some(v) = self.arp_all_targets {
            builder.append_attr_u32(bond_attr::IFLA_BOND_ARP_ALL_TARGETS, v);
        }
        if let Some(v) = self.primary_reselect {
            builder.append_attr_u8(bond_attr::IFLA_BOND_PRIMARY_RESELECT, v as u8);
        }
        if let Some(v) = self.fail_over_mac {
            builder.append_attr_u8(bond_attr::IFLA_BOND_FAIL_OVER_MAC, v as u8);
        }
        if let Some(v) = self.xmit_hash_policy {
            builder.append_attr_u8(bond_attr::IFLA_BOND_XMIT_HASH_POLICY, v as u8);
        }
        if let Some(v) = self.resend_igmp {
            builder.append_attr_u32(bond_attr::IFLA_BOND_RESEND_IGMP, v);
        }
        if let Some(v) = self.num_peer_notif {
            builder.append_attr_u8(bond_attr::IFLA_BOND_NUM_PEER_NOTIF, v);
        }
        if let Some(v) = self.all_slaves_active {
            builder.append_attr_u8(bond_attr::IFLA_BOND_ALL_SLAVES_ACTIVE, v as u8);
        }
        if let Some(v) = self.min_links {
            builder.append_attr_u32(bond_attr::IFLA_BOND_MIN_LINKS, v);
        }
        if let Some(v) = self.lp_interval {
            builder.append_attr_u32(bond_attr::IFLA_BOND_LP_INTERVAL, v);
        }
        if let Some(v) = self.packets_per_slave {
            builder.append_attr_u32(bond_attr::IFLA_BOND_PACKETS_PER_SLAVE, v);
        }
        if let Some(v) = self.lacp_rate {
            builder.append_attr_u8(bond_attr::IFLA_BOND_AD_LACP_RATE, v as u8);
        }
        if let Some(v) = self.ad_select {
            builder.append_attr_u8(bond_attr::IFLA_BOND_AD_SELECT, v as u8);
        }
        if let Some(v) = self.ad_actor_sys_prio {
            builder.append_attr_u16(bond_attr::IFLA_BOND_AD_ACTOR_SYS_PRIO, v);
        }
        if let Some(v) = self.ad_user_port_key {
            builder.append_attr_u16(bond_attr::IFLA_BOND_AD_USER_PORT_KEY, v);
        }
        if let Some(ref mac) = self.ad_actor_system {
            builder.append_attr(bond_attr::IFLA_BOND_AD_ACTOR_SYSTEM, mac);
        }
        if let Some(v) = self.tlb_dynamic_lb {
            builder.append_attr_u8(bond_attr::IFLA_BOND_TLB_DYNAMIC_LB, v as u8);
        }
        if let Some(v) = self.peer_notif_delay {
            builder.append_attr_u32(bond_attr::IFLA_BOND_PEER_NOTIF_DELAY, v);
        }
        if let Some(v) = self.lacp_active {
            builder.append_attr_u8(bond_attr::IFLA_BOND_AD_LACP_ACTIVE, v as u8);
        }
        if let Some(v) = self.missed_max {
            builder.append_attr_u8(bond_attr::IFLA_BOND_MISSED_MAX, v);
        }
        if let Some(v) = self.coupled_control {
            builder.append_attr_u8(bond_attr::IFLA_BOND_COUPLED_CONTROL, v as u8);
        }

        // ARP IP targets (nested)
        if !self.arp_ip_targets.is_empty() {
            let targets = builder.nest_start(bond_attr::IFLA_BOND_ARP_IP_TARGET);
            for (i, addr) in self.arp_ip_targets.iter().enumerate() {
                builder.append_attr(i as u16, &addr.octets());
            }
            builder.nest_end(targets);
        }

        builder.nest_end(data);
        builder.nest_end(linkinfo);
    }
}

// ============================================================================
// VRF Link
// ============================================================================

/// VRF attribute constants.
mod vrf_attr {
    pub const IFLA_VRF_TABLE: u16 = 1;
}

/// Configuration for a VRF (Virtual Routing and Forwarding) interface.
///
/// # Example
///
/// ```ignore
/// use nlink::netlink::link::VrfLink;
///
/// let vrf = VrfLink::new("vrf-red", 100);
///
/// conn.add_link(vrf).await?;
/// ```
#[derive(Debug, Clone)]
#[must_use = "builders do nothing unless used"]
pub struct VrfLink {
    name: String,
    table: u32,
    mtu: Option<u32>,
}

impl VrfLink {
    /// Create a new VRF interface configuration.
    pub fn new(name: &str, table: u32) -> Self {
        Self {
            name: name.to_string(),
            table,
            mtu: None,
        }
    }

    /// Set the MTU.
    pub fn mtu(mut self, mtu: u32) -> Self {
        self.mtu = Some(mtu);
        self
    }
}

impl LinkConfig for VrfLink {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> &str {
        "vrf"
    }

    fn write_to(&self, builder: &mut MessageBuilder, _parent_index: Option<u32>) {
        write_ifname(builder, &self.name);

        if let Some(mtu) = self.mtu {
            builder.append_attr_u32(IflaAttr::Mtu as u16, mtu);
        }

        let linkinfo = builder.nest_start(IflaAttr::Linkinfo as u16);
        builder.append_attr_str(IflaInfo::Kind as u16, "vrf");

        let data = builder.nest_start(IflaInfo::Data as u16);
        builder.append_attr_u32(vrf_attr::IFLA_VRF_TABLE, self.table);
        builder.nest_end(data);

        builder.nest_end(linkinfo);
    }
}

// ============================================================================
// GRE Link (IPv4)
// ============================================================================

/// Configuration for a GRE tunnel interface.
///
/// # Example
///
/// ```ignore
/// use nlink::netlink::link::GreLink;
/// use std::net::Ipv4Addr;
///
/// let gre = GreLink::new("gre1")
///     .remote(Ipv4Addr::new(192, 168, 1, 1))
///     .local(Ipv4Addr::new(192, 168, 1, 2))
///     .ttl(64);
///
/// conn.add_link(gre).await?;
/// ```
#[derive(Debug, Clone)]
#[must_use = "builders do nothing unless used"]
pub struct GreLink {
    name: String,
    local: Option<Ipv4Addr>,
    remote: Option<Ipv4Addr>,
    ttl: Option<u8>,
    tos: Option<u8>,
    ikey: Option<u32>,
    okey: Option<u32>,
    pmtudisc: Option<bool>,
    ignore_df: Option<bool>,
    fwmark: Option<u32>,
    mtu: Option<u32>,
    link: Option<InterfaceRef>,
}

impl GreLink {
    /// Create a new GRE tunnel configuration.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            local: None,
            remote: None,
            ttl: None,
            tos: None,
            ikey: None,
            okey: None,
            pmtudisc: None,
            ignore_df: None,
            fwmark: None,
            mtu: None,
            link: None,
        }
    }

    /// Set the local endpoint address.
    pub fn local(mut self, addr: Ipv4Addr) -> Self {
        self.local = Some(addr);
        self
    }

    /// Set the remote endpoint address.
    pub fn remote(mut self, addr: Ipv4Addr) -> Self {
        self.remote = Some(addr);
        self
    }

    /// Set the TTL.
    pub fn ttl(mut self, ttl: u8) -> Self {
        self.ttl = Some(ttl);
        self
    }

    /// Set the TOS.
    pub fn tos(mut self, tos: u8) -> Self {
        self.tos = Some(tos);
        self
    }

    /// Set the input GRE key. Automatically enables GRE_KEY flag.
    pub fn ikey(mut self, key: u32) -> Self {
        self.ikey = Some(key);
        self
    }

    /// Set the output GRE key. Automatically enables GRE_KEY flag.
    pub fn okey(mut self, key: u32) -> Self {
        self.okey = Some(key);
        self
    }

    /// Set both input and output GRE key.
    pub fn key(self, key: u32) -> Self {
        self.ikey(key).okey(key)
    }

    /// Enable/disable Path MTU Discovery.
    pub fn pmtudisc(mut self, enabled: bool) -> Self {
        self.pmtudisc = Some(enabled);
        self
    }

    /// Ignore the Don't Fragment flag on inner packets.
    pub fn ignore_df(mut self, enabled: bool) -> Self {
        self.ignore_df = Some(enabled);
        self
    }

    /// Set firewall mark.
    pub fn fwmark(mut self, mark: u32) -> Self {
        self.fwmark = Some(mark);
        self
    }

    /// Set the MTU.
    pub fn mtu(mut self, mtu: u32) -> Self {
        self.mtu = Some(mtu);
        self
    }

    /// Set the underlay interface by name.
    pub fn link(mut self, iface: impl Into<String>) -> Self {
        self.link = Some(InterfaceRef::Name(iface.into()));
        self
    }

    /// Set the underlay interface by index.
    pub fn link_index(mut self, index: u32) -> Self {
        self.link = Some(InterfaceRef::Index(index));
        self
    }
}

impl LinkConfig for GreLink {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> &str {
        "gre"
    }

    fn parent_ref(&self) -> Option<&InterfaceRef> {
        self.link.as_ref()
    }

    fn write_to(&self, builder: &mut MessageBuilder, parent_index: Option<u32>) {
        write_ifname(builder, &self.name);

        if let Some(mtu) = self.mtu {
            builder.append_attr_u32(IflaAttr::Mtu as u16, mtu);
        }
        if let Some(idx) = parent_index {
            builder.append_attr_u32(IflaAttr::Link as u16, idx);
        }

        let linkinfo = builder.nest_start(IflaAttr::Linkinfo as u16);
        builder.append_attr_str(IflaInfo::Kind as u16, "gre");

        let data = builder.nest_start(IflaInfo::Data as u16);
        if let Some(addr) = self.local {
            builder.append_attr(gre_attr::IFLA_GRE_LOCAL, &addr.octets());
        }
        if let Some(addr) = self.remote {
            builder.append_attr(gre_attr::IFLA_GRE_REMOTE, &addr.octets());
        }
        if let Some(ttl) = self.ttl {
            builder.append_attr_u8(gre_attr::IFLA_GRE_TTL, ttl);
        }
        if let Some(tos) = self.tos {
            builder.append_attr_u8(gre_attr::IFLA_GRE_TOS, tos);
        }
        if let Some(key) = self.ikey {
            builder.append_attr_u16(gre_attr::IFLA_GRE_IFLAGS, gre_attr::GRE_KEY);
            builder.append_attr_u32(gre_attr::IFLA_GRE_IKEY, key);
        }
        if let Some(key) = self.okey {
            builder.append_attr_u16(gre_attr::IFLA_GRE_OFLAGS, gre_attr::GRE_KEY);
            builder.append_attr_u32(gre_attr::IFLA_GRE_OKEY, key);
        }
        if let Some(pmtu) = self.pmtudisc {
            builder.append_attr_u8(gre_attr::IFLA_GRE_PMTUDISC, pmtu as u8);
        }
        if let Some(ignore) = self.ignore_df {
            builder.append_attr_u8(gre_attr::IFLA_GRE_IGNORE_DF, ignore as u8);
        }
        if let Some(mark) = self.fwmark {
            builder.append_attr_u32(gre_attr::IFLA_GRE_FWMARK, mark);
        }
        builder.nest_end(data);

        builder.nest_end(linkinfo);
    }
}

// ============================================================================
// GRETAP Link (Layer 2 GRE)
// ============================================================================

/// Configuration for a GRETAP (Ethernet over GRE) tunnel interface.
///
/// # Example
///
/// ```ignore
/// use nlink::netlink::link::GretapLink;
/// use std::net::Ipv4Addr;
///
/// let gretap = GretapLink::new("gretap1")
///     .remote(Ipv4Addr::new(192, 168, 1, 1))
///     .local(Ipv4Addr::new(192, 168, 1, 2));
///
/// conn.add_link(gretap).await?;
/// ```
#[derive(Debug, Clone)]
#[must_use = "builders do nothing unless used"]
pub struct GretapLink {
    name: String,
    local: Option<Ipv4Addr>,
    remote: Option<Ipv4Addr>,
    ttl: Option<u8>,
    tos: Option<u8>,
    ikey: Option<u32>,
    okey: Option<u32>,
    pmtudisc: Option<bool>,
    fwmark: Option<u32>,
    mtu: Option<u32>,
    link: Option<InterfaceRef>,
}

impl GretapLink {
    /// Create a new GRETAP tunnel configuration.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            local: None,
            remote: None,
            ttl: None,
            tos: None,
            ikey: None,
            okey: None,
            pmtudisc: None,
            fwmark: None,
            mtu: None,
            link: None,
        }
    }

    /// Set the local endpoint address.
    pub fn local(mut self, addr: Ipv4Addr) -> Self {
        self.local = Some(addr);
        self
    }

    /// Set the remote endpoint address.
    pub fn remote(mut self, addr: Ipv4Addr) -> Self {
        self.remote = Some(addr);
        self
    }

    /// Set the TTL.
    pub fn ttl(mut self, ttl: u8) -> Self {
        self.ttl = Some(ttl);
        self
    }

    /// Set the TOS.
    pub fn tos(mut self, tos: u8) -> Self {
        self.tos = Some(tos);
        self
    }

    /// Set the input GRE key.
    pub fn ikey(mut self, key: u32) -> Self {
        self.ikey = Some(key);
        self
    }

    /// Set the output GRE key.
    pub fn okey(mut self, key: u32) -> Self {
        self.okey = Some(key);
        self
    }

    /// Set both input and output GRE key.
    pub fn key(self, key: u32) -> Self {
        self.ikey(key).okey(key)
    }

    /// Enable/disable Path MTU Discovery.
    pub fn pmtudisc(mut self, enabled: bool) -> Self {
        self.pmtudisc = Some(enabled);
        self
    }

    /// Set firewall mark.
    pub fn fwmark(mut self, mark: u32) -> Self {
        self.fwmark = Some(mark);
        self
    }

    /// Set the MTU.
    pub fn mtu(mut self, mtu: u32) -> Self {
        self.mtu = Some(mtu);
        self
    }

    /// Set the underlay interface by name.
    pub fn link(mut self, iface: impl Into<String>) -> Self {
        self.link = Some(InterfaceRef::Name(iface.into()));
        self
    }

    /// Set the underlay interface by index.
    pub fn link_index(mut self, index: u32) -> Self {
        self.link = Some(InterfaceRef::Index(index));
        self
    }
}

impl LinkConfig for GretapLink {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> &str {
        "gretap"
    }

    fn parent_ref(&self) -> Option<&InterfaceRef> {
        self.link.as_ref()
    }

    fn write_to(&self, builder: &mut MessageBuilder, parent_index: Option<u32>) {
        write_ifname(builder, &self.name);

        if let Some(mtu) = self.mtu {
            builder.append_attr_u32(IflaAttr::Mtu as u16, mtu);
        }
        if let Some(idx) = parent_index {
            builder.append_attr_u32(IflaAttr::Link as u16, idx);
        }

        let linkinfo = builder.nest_start(IflaAttr::Linkinfo as u16);
        builder.append_attr_str(IflaInfo::Kind as u16, "gretap");

        let data = builder.nest_start(IflaInfo::Data as u16);
        if let Some(addr) = self.local {
            builder.append_attr(gre_attr::IFLA_GRE_LOCAL, &addr.octets());
        }
        if let Some(addr) = self.remote {
            builder.append_attr(gre_attr::IFLA_GRE_REMOTE, &addr.octets());
        }
        if let Some(ttl) = self.ttl {
            builder.append_attr_u8(gre_attr::IFLA_GRE_TTL, ttl);
        }
        if let Some(tos) = self.tos {
            builder.append_attr_u8(gre_attr::IFLA_GRE_TOS, tos);
        }
        if let Some(key) = self.ikey {
            builder.append_attr_u16(gre_attr::IFLA_GRE_IFLAGS, gre_attr::GRE_KEY);
            builder.append_attr_u32(gre_attr::IFLA_GRE_IKEY, key);
        }
        if let Some(key) = self.okey {
            builder.append_attr_u16(gre_attr::IFLA_GRE_OFLAGS, gre_attr::GRE_KEY);
            builder.append_attr_u32(gre_attr::IFLA_GRE_OKEY, key);
        }
        if let Some(pmtu) = self.pmtudisc {
            builder.append_attr_u8(gre_attr::IFLA_GRE_PMTUDISC, pmtu as u8);
        }
        if let Some(mark) = self.fwmark {
            builder.append_attr_u32(gre_attr::IFLA_GRE_FWMARK, mark);
        }
        builder.nest_end(data);

        builder.nest_end(linkinfo);
    }
}

// ============================================================================
// IPIP Link
// ============================================================================

/// Configuration for an IPIP (IP-in-IP) tunnel interface.
///
/// # Example
///
/// ```ignore
/// use nlink::netlink::link::IpipLink;
/// use std::net::Ipv4Addr;
///
/// let ipip = IpipLink::new("ipip1")
///     .remote(Ipv4Addr::new(192, 168, 1, 1))
///     .local(Ipv4Addr::new(192, 168, 1, 2));
///
/// conn.add_link(ipip).await?;
/// ```
#[derive(Debug, Clone)]
#[must_use = "builders do nothing unless used"]
pub struct IpipLink {
    name: String,
    local: Option<Ipv4Addr>,
    remote: Option<Ipv4Addr>,
    ttl: Option<u8>,
    tos: Option<u8>,
    pmtudisc: Option<bool>,
    fwmark: Option<u32>,
    mtu: Option<u32>,
    link: Option<InterfaceRef>,
}

impl IpipLink {
    /// Create a new IPIP tunnel configuration.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            local: None,
            remote: None,
            ttl: None,
            tos: None,
            pmtudisc: None,
            fwmark: None,
            mtu: None,
            link: None,
        }
    }

    /// Set the local endpoint address.
    pub fn local(mut self, addr: Ipv4Addr) -> Self {
        self.local = Some(addr);
        self
    }

    /// Set the remote endpoint address.
    pub fn remote(mut self, addr: Ipv4Addr) -> Self {
        self.remote = Some(addr);
        self
    }

    /// Set the TTL.
    pub fn ttl(mut self, ttl: u8) -> Self {
        self.ttl = Some(ttl);
        self
    }

    /// Set the TOS.
    pub fn tos(mut self, tos: u8) -> Self {
        self.tos = Some(tos);
        self
    }

    /// Enable/disable Path MTU Discovery.
    pub fn pmtudisc(mut self, enabled: bool) -> Self {
        self.pmtudisc = Some(enabled);
        self
    }

    /// Set firewall mark.
    pub fn fwmark(mut self, mark: u32) -> Self {
        self.fwmark = Some(mark);
        self
    }

    /// Set the MTU.
    pub fn mtu(mut self, mtu: u32) -> Self {
        self.mtu = Some(mtu);
        self
    }

    /// Set the underlay interface by name.
    pub fn link(mut self, iface: impl Into<String>) -> Self {
        self.link = Some(InterfaceRef::Name(iface.into()));
        self
    }

    /// Set the underlay interface by index.
    pub fn link_index(mut self, index: u32) -> Self {
        self.link = Some(InterfaceRef::Index(index));
        self
    }
}

impl LinkConfig for IpipLink {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> &str {
        "ipip"
    }

    fn parent_ref(&self) -> Option<&InterfaceRef> {
        self.link.as_ref()
    }

    fn write_to(&self, builder: &mut MessageBuilder, parent_index: Option<u32>) {
        write_ifname(builder, &self.name);

        if let Some(mtu) = self.mtu {
            builder.append_attr_u32(IflaAttr::Mtu as u16, mtu);
        }
        if let Some(idx) = parent_index {
            builder.append_attr_u32(IflaAttr::Link as u16, idx);
        }

        let linkinfo = builder.nest_start(IflaAttr::Linkinfo as u16);
        builder.append_attr_str(IflaInfo::Kind as u16, "ipip");

        let data = builder.nest_start(IflaInfo::Data as u16);
        if let Some(addr) = self.local {
            builder.append_attr(iptun_attr::IFLA_IPTUN_LOCAL, &addr.octets());
        }
        if let Some(addr) = self.remote {
            builder.append_attr(iptun_attr::IFLA_IPTUN_REMOTE, &addr.octets());
        }
        if let Some(ttl) = self.ttl {
            builder.append_attr_u8(iptun_attr::IFLA_IPTUN_TTL, ttl);
        }
        if let Some(tos) = self.tos {
            builder.append_attr_u8(iptun_attr::IFLA_IPTUN_TOS, tos);
        }
        if let Some(pmtu) = self.pmtudisc {
            builder.append_attr_u8(iptun_attr::IFLA_IPTUN_PMTUDISC, pmtu as u8);
        }
        if let Some(mark) = self.fwmark {
            builder.append_attr_u32(iptun_attr::IFLA_IPTUN_FWMARK, mark);
        }
        builder.nest_end(data);

        builder.nest_end(linkinfo);
    }
}

// ============================================================================
// SIT Link (IPv6-in-IPv4)
// ============================================================================

/// Configuration for a SIT (Simple Internet Transition) tunnel interface.
///
/// SIT tunnels encapsulate IPv6 packets in IPv4 for transition mechanisms.
///
/// # Example
///
/// ```ignore
/// use nlink::netlink::link::SitLink;
/// use std::net::Ipv4Addr;
///
/// let sit = SitLink::new("sit1")
///     .remote(Ipv4Addr::new(192, 168, 1, 1))
///     .local(Ipv4Addr::new(192, 168, 1, 2));
///
/// conn.add_link(sit).await?;
/// ```
#[derive(Debug, Clone)]
#[must_use = "builders do nothing unless used"]
pub struct SitLink {
    name: String,
    local: Option<Ipv4Addr>,
    remote: Option<Ipv4Addr>,
    ttl: Option<u8>,
    tos: Option<u8>,
    pmtudisc: Option<bool>,
    fwmark: Option<u32>,
    isatap: bool,
    mtu: Option<u32>,
    link: Option<InterfaceRef>,
}

impl SitLink {
    /// Create a new SIT tunnel configuration.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            local: None,
            remote: None,
            ttl: None,
            tos: None,
            pmtudisc: None,
            fwmark: None,
            isatap: false,
            mtu: None,
            link: None,
        }
    }

    /// Set the local endpoint address.
    pub fn local(mut self, addr: Ipv4Addr) -> Self {
        self.local = Some(addr);
        self
    }

    /// Set the remote endpoint address.
    pub fn remote(mut self, addr: Ipv4Addr) -> Self {
        self.remote = Some(addr);
        self
    }

    /// Set the TTL.
    pub fn ttl(mut self, ttl: u8) -> Self {
        self.ttl = Some(ttl);
        self
    }

    /// Set the TOS.
    pub fn tos(mut self, tos: u8) -> Self {
        self.tos = Some(tos);
        self
    }

    /// Enable/disable Path MTU Discovery.
    pub fn pmtudisc(mut self, enabled: bool) -> Self {
        self.pmtudisc = Some(enabled);
        self
    }

    /// Set firewall mark.
    pub fn fwmark(mut self, mark: u32) -> Self {
        self.fwmark = Some(mark);
        self
    }

    /// Enable ISATAP (Intra-Site Automatic Tunnel Addressing Protocol) mode.
    pub fn isatap(mut self) -> Self {
        self.isatap = true;
        self
    }

    /// Set the MTU.
    pub fn mtu(mut self, mtu: u32) -> Self {
        self.mtu = Some(mtu);
        self
    }

    /// Set the underlay interface by name.
    pub fn link(mut self, iface: impl Into<String>) -> Self {
        self.link = Some(InterfaceRef::Name(iface.into()));
        self
    }

    /// Set the underlay interface by index.
    pub fn link_index(mut self, index: u32) -> Self {
        self.link = Some(InterfaceRef::Index(index));
        self
    }
}

impl LinkConfig for SitLink {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> &str {
        "sit"
    }

    fn parent_ref(&self) -> Option<&InterfaceRef> {
        self.link.as_ref()
    }

    fn write_to(&self, builder: &mut MessageBuilder, parent_index: Option<u32>) {
        write_ifname(builder, &self.name);

        if let Some(mtu) = self.mtu {
            builder.append_attr_u32(IflaAttr::Mtu as u16, mtu);
        }
        if let Some(idx) = parent_index {
            builder.append_attr_u32(IflaAttr::Link as u16, idx);
        }

        let linkinfo = builder.nest_start(IflaAttr::Linkinfo as u16);
        builder.append_attr_str(IflaInfo::Kind as u16, "sit");

        let data = builder.nest_start(IflaInfo::Data as u16);
        if let Some(addr) = self.local {
            builder.append_attr(iptun_attr::IFLA_IPTUN_LOCAL, &addr.octets());
        }
        if let Some(addr) = self.remote {
            builder.append_attr(iptun_attr::IFLA_IPTUN_REMOTE, &addr.octets());
        }
        if let Some(ttl) = self.ttl {
            builder.append_attr_u8(iptun_attr::IFLA_IPTUN_TTL, ttl);
        }
        if let Some(tos) = self.tos {
            builder.append_attr_u8(iptun_attr::IFLA_IPTUN_TOS, tos);
        }
        if let Some(pmtu) = self.pmtudisc {
            builder.append_attr_u8(iptun_attr::IFLA_IPTUN_PMTUDISC, pmtu as u8);
        }
        if let Some(mark) = self.fwmark {
            builder.append_attr_u32(iptun_attr::IFLA_IPTUN_FWMARK, mark);
        }
        if self.isatap {
            builder.append_attr_u16(iptun_attr::IFLA_IPTUN_FLAGS, iptun_attr::SIT_ISATAP);
        }
        builder.nest_end(data);

        builder.nest_end(linkinfo);
    }
}

// ============================================================================
// WireGuard Link
// ============================================================================

/// Configuration for a WireGuard interface.
///
/// Note: WireGuard interfaces are created with just the interface name.
/// Configuration (keys, peers, etc.) is done via the WireGuard netlink API.
///
/// # Example
///
/// ```ignore
/// use nlink::netlink::{Connection, Wireguard};
/// use nlink::netlink::link::WireguardLink;
///
/// let wg = WireguardLink::new("wg0");
/// conn.add_link(wg).await?;
///
/// // Then configure via Connection<Wireguard>
/// let wg_conn = Connection::<Wireguard>::new_async().await?;
/// wg_conn.set_device("wg0", |dev| dev.private_key(key)).await?;
/// ```
#[derive(Debug, Clone)]
#[must_use = "builders do nothing unless used"]
pub struct WireguardLink {
    name: String,
    mtu: Option<u32>,
}

impl WireguardLink {
    /// Create a new WireGuard interface configuration.
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            mtu: None,
        }
    }

    /// Set the MTU.
    pub fn mtu(mut self, mtu: u32) -> Self {
        self.mtu = Some(mtu);
        self
    }
}

impl LinkConfig for WireguardLink {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> &str {
        "wireguard"
    }

    fn write_to(&self, builder: &mut MessageBuilder, _parent_index: Option<u32>) {
        write_simple_link(builder, &self.name, "wireguard", self.mtu, None);
    }
}

// ============================================================================
// MACsec Link
// ============================================================================

/// IFLA_MACSEC_* attribute IDs (kernel `include/uapi/linux/if_link.h`).
/// We only emit the subset the builder exposes; `ICV_LEN`,
/// `CIPHER_SUITE`, and `VALIDATION` are managed via the GENL
/// `Connection::<Macsec>` API after creation.
mod macsec {
    pub const IFLA_MACSEC_SCI: u16 = 1;
    pub const IFLA_MACSEC_PORT: u16 = 2;
    pub const IFLA_MACSEC_WINDOW: u16 = 5;
    pub const IFLA_MACSEC_ENCODING_SA: u16 = 6;
    pub const IFLA_MACSEC_ENCRYPT: u16 = 7;
    pub const IFLA_MACSEC_PROTECT: u16 = 8;
    pub const IFLA_MACSEC_INC_SCI: u16 = 9;
    pub const IFLA_MACSEC_ES: u16 = 10;
    pub const IFLA_MACSEC_SCB: u16 = 11;
    pub const IFLA_MACSEC_REPLAY_PROTECT: u16 = 12;
}

/// Configuration for a MACsec (IEEE 802.1AE) interface.
///
/// MACsec provides Layer-2 authenticated encryption for point-to-point
/// links. The interface sits on top of a parent (typically a physical
/// NIC or a veth in a lab). Key and SA management happens via the
/// separate `Connection::<Macsec>` Generic-Netlink API — creating the
/// interface is an rtnetlink operation, configuring its TX/RX SAs is
/// GENL.
///
/// # Example
///
/// ```no_run
/// # async fn example() -> nlink::Result<()> {
/// use nlink::netlink::{Connection, Route};
/// use nlink::netlink::link::{DummyLink, MacsecLink};
///
/// let conn = Connection::<Route>::new()?;
/// conn.add_link(DummyLink::new("dummy0")).await?;
/// conn.set_link_up("dummy0").await?;
///
/// // Plain macsec interface — encrypt + protect enabled by default.
/// conn.add_link(MacsecLink::new("macsec0", "dummy0")).await?;
///
/// // With an explicit SCI + replay protection disabled (e.g. during
/// // key rollover when you temporarily accept duplicates).
/// conn.add_link(
///     MacsecLink::new("macsec1", "dummy0")
///         .sci(0x0011_2233_4455_0001)
///         .replay_protect(false)
/// ).await?;
/// # Ok(())
/// # }
/// ```
pub struct MacsecLink {
    name: String,
    parent: InterfaceRef,
    mtu: Option<u32>,
    sci: Option<u64>,
    port: Option<u16>,
    encrypt: Option<bool>,
    protect: Option<bool>,
    inc_sci: Option<bool>,
    end_station: Option<bool>,
    scb: Option<bool>,
    replay_protect: Option<bool>,
    replay_window: Option<u32>,
    encoding_sa: Option<u8>,
}

impl MacsecLink {
    /// Create a new MACsec interface configuration sitting on top of
    /// `parent` (a physical NIC or other Ethernet-kind interface).
    pub fn new(name: impl Into<String>, parent: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            parent: InterfaceRef::Name(parent.into()),
            mtu: None,
            sci: None,
            port: None,
            encrypt: None,
            protect: None,
            inc_sci: None,
            end_station: None,
            scb: None,
            replay_protect: None,
            replay_window: None,
            encoding_sa: None,
        }
    }

    /// Create a new MACsec interface with parent specified by index.
    /// Use this when working across namespaces to avoid a `/sys` lookup.
    pub fn with_parent_index(name: impl Into<String>, parent_index: u32) -> Self {
        Self {
            name: name.into(),
            parent: InterfaceRef::Index(parent_index),
            mtu: None,
            sci: None,
            port: None,
            encrypt: None,
            protect: None,
            inc_sci: None,
            end_station: None,
            scb: None,
            replay_protect: None,
            replay_window: None,
            encoding_sa: None,
        }
    }

    /// Set the MTU.
    pub fn mtu(mut self, mtu: u32) -> Self {
        self.mtu = Some(mtu);
        self
    }

    /// Explicit Secure Channel Identifier. If omitted, the kernel
    /// derives the SCI from the parent's MAC address + [`Self::port`]
    /// (default port = 1).
    pub fn sci(mut self, sci: u64) -> Self {
        self.sci = Some(sci);
        self
    }

    /// Port component used when the kernel auto-derives the SCI
    /// (default 1).
    pub fn port(mut self, port: u16) -> Self {
        self.port = Some(port);
        self
    }

    /// Enable / disable frame encryption. Default: enabled.
    pub fn encrypt(mut self, enabled: bool) -> Self {
        self.encrypt = Some(enabled);
        self
    }

    /// Enable / disable frame protection (integrity). Default: enabled.
    pub fn protect(mut self, enabled: bool) -> Self {
        self.protect = Some(enabled);
        self
    }

    /// Whether to always include the SCI in frames. Default: off
    /// (kernel omits it when the SCI matches the derived one).
    pub fn include_sci(mut self, enabled: bool) -> Self {
        self.inc_sci = Some(enabled);
        self
    }

    /// End-station mode (ES bit).
    pub fn end_station(mut self, enabled: bool) -> Self {
        self.end_station = Some(enabled);
        self
    }

    /// Single-copy-broadcast mode (SCB bit).
    pub fn scb(mut self, enabled: bool) -> Self {
        self.scb = Some(enabled);
        self
    }

    /// Enable / disable replay protection. Default: enabled.
    pub fn replay_protect(mut self, enabled: bool) -> Self {
        self.replay_protect = Some(enabled);
        self
    }

    /// Replay-window size in frames.
    pub fn replay_window(mut self, window: u32) -> Self {
        self.replay_window = Some(window);
        self
    }

    /// Active TX association number (0-3). Typically managed via the
    /// GENL `Connection::<Macsec>::update_tx_sa` API after the
    /// interface is created.
    pub fn encoding_sa(mut self, an: u8) -> Self {
        self.encoding_sa = Some(an);
        self
    }
}

impl LinkConfig for MacsecLink {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> &str {
        "macsec"
    }

    fn parent_ref(&self) -> Option<&InterfaceRef> {
        Some(&self.parent)
    }

    fn write_to(&self, builder: &mut MessageBuilder, parent_index: Option<u32>) {
        write_ifname(builder, &self.name);

        let idx = parent_index.expect("MacsecLink requires parent_index");
        builder.append_attr_u32(IflaAttr::Link as u16, idx);

        if let Some(mtu) = self.mtu {
            builder.append_attr_u32(IflaAttr::Mtu as u16, mtu);
        }

        let linkinfo = builder.nest_start(IflaAttr::Linkinfo as u16);
        builder.append_attr_str(IflaInfo::Kind as u16, "macsec");

        let data = builder.nest_start(IflaInfo::Data as u16);
        if let Some(sci) = self.sci {
            builder.append_attr_u64(macsec::IFLA_MACSEC_SCI, sci);
        }
        if let Some(port) = self.port {
            builder.append_attr_u16(macsec::IFLA_MACSEC_PORT, port);
        }
        if let Some(window) = self.replay_window {
            builder.append_attr_u32(macsec::IFLA_MACSEC_WINDOW, window);
        }
        if let Some(encoding_sa) = self.encoding_sa {
            builder.append_attr_u8(macsec::IFLA_MACSEC_ENCODING_SA, encoding_sa);
        }
        if let Some(v) = self.encrypt {
            builder.append_attr_u8(macsec::IFLA_MACSEC_ENCRYPT, v as u8);
        }
        if let Some(v) = self.protect {
            builder.append_attr_u8(macsec::IFLA_MACSEC_PROTECT, v as u8);
        }
        if let Some(v) = self.inc_sci {
            builder.append_attr_u8(macsec::IFLA_MACSEC_INC_SCI, v as u8);
        }
        if let Some(v) = self.end_station {
            builder.append_attr_u8(macsec::IFLA_MACSEC_ES, v as u8);
        }
        if let Some(v) = self.scb {
            builder.append_attr_u8(macsec::IFLA_MACSEC_SCB, v as u8);
        }
        if let Some(v) = self.replay_protect {
            builder.append_attr_u8(macsec::IFLA_MACSEC_REPLAY_PROTECT, v as u8);
        }
        builder.nest_end(data);
        builder.nest_end(linkinfo);
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Write the interface name attribute.
fn write_ifname(builder: &mut MessageBuilder, name: &str) {
    builder.append_attr_str(IflaAttr::Ifname as u16, name);
}

/// Write a simple link (like dummy) with just name and optional MTU/address.
fn write_simple_link(
    builder: &mut MessageBuilder,
    name: &str,
    kind: &str,
    mtu: Option<u32>,
    address: Option<&[u8; 6]>,
) {
    // Add interface name
    write_ifname(builder, name);

    // Add optional attributes
    if let Some(mtu) = mtu {
        builder.append_attr_u32(IflaAttr::Mtu as u16, mtu);
    }
    if let Some(addr) = address {
        builder.append_attr(IflaAttr::Address as u16, addr);
    }

    // IFLA_LINKINFO -> IFLA_INFO_KIND
    let linkinfo = builder.nest_start(IflaAttr::Linkinfo as u16);
    builder.append_attr_str(IflaInfo::Kind as u16, kind);
    builder.nest_end(linkinfo);
}

// ============================================================================
// Connection Methods
// ============================================================================

impl Connection<Route> {
    /// Add a new network interface.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use nlink::netlink::link::{DummyLink, VethLink, BridgeLink};
    ///
    /// // Create a dummy interface
    /// conn.add_link(DummyLink::new("dummy0")).await?;
    ///
    /// // Create a veth pair
    /// conn.add_link(VethLink::new("veth0", "veth1")).await?;
    ///
    /// // Create a bridge
    /// conn.add_link(BridgeLink::new("br0").stp(true)).await?;
    ///
    /// // Create a VLAN with parent by index (namespace-safe)
    /// conn.add_link(VlanLink::with_parent_index("vlan100", 5, 100)).await?;
    /// ```
    pub async fn add_link<L: LinkConfig>(&self, config: L) -> Result<()> {
        use super::message::{NLM_F_ACK, NLM_F_REQUEST};

        // Validate interface name(s) before sending to kernel
        crate::util::ifname::validate(config.name()).map_err(super::error::Error::Interface)?;
        if let Some(peer) = config.peer_name() {
            crate::util::ifname::validate(peer).map_err(super::error::Error::Interface)?;
        }

        // Resolve parent interface if needed
        let parent_index = match config.parent_ref() {
            Some(iface) => Some(self.resolve_interface(iface).await?),
            None => None,
        };

        // Build the message
        let mut builder = MessageBuilder::new(
            NlMsgType::RTM_NEWLINK,
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
        );

        // Append ifinfomsg header
        let ifinfo = IfInfoMsg::new();
        builder.append(&ifinfo);

        // Write the link configuration
        let link_name = config.name().to_string();
        let link_kind = config.kind().to_string();
        config.write_to(&mut builder, parent_index);

        self.send_ack(builder)
            .await
            .map_err(|e| e.with_context(format!("add_link({link_name}, kind={link_kind})")))
    }

    /// Set the master (controller) device for an interface.
    ///
    /// This is used to add an interface to a bridge or bond.
    ///
    /// # Example
    ///
    /// ```ignore
    /// // Add eth0 to bridge br0
    /// conn.set_link_master("eth0", "br0").await?;
    ///
    /// // Or by index
    /// conn.set_link_master(InterfaceRef::Index(5), InterfaceRef::Index(10)).await?;
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "set_link_master"))]
    pub async fn set_link_master(
        &self,
        iface: impl Into<InterfaceRef>,
        master: impl Into<InterfaceRef>,
    ) -> Result<()> {
        let ifindex = self.resolve_interface(&iface.into()).await?;
        let master_index = self.resolve_interface(&master.into()).await?;
        self.set_link_master_by_index(ifindex, master_index).await
    }

    /// Set the master device by interface indices.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "set_link_master_by_index"))]
    pub async fn set_link_master_by_index(&self, ifindex: u32, master_index: u32) -> Result<()> {
        use super::connection::ack_request;

        let ifinfo = IfInfoMsg::new().with_index(ifindex as i32);

        let mut builder = ack_request(NlMsgType::RTM_SETLINK);
        builder.append(&ifinfo);
        builder.append_attr_u32(IflaAttr::Master as u16, master_index);

        self.send_ack(builder)
            .await
            .map_err(|e| e.with_context("set_link_master"))
    }

    /// Enslave an interface to a bond or bridge.
    ///
    /// This convenience method handles the required down/master/up sequence:
    /// the member interface must be brought down before enslaving, then brought
    /// back up afterward.
    ///
    /// # Example
    ///
    /// ```ignore
    /// // Enslave eth0 to bond0 (handles down/master/up automatically)
    /// conn.enslave("eth0", "bond0").await?;
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "enslave"))]
    pub async fn enslave(
        &self,
        member: impl Into<InterfaceRef>,
        master: impl Into<InterfaceRef>,
    ) -> Result<()> {
        let member = member.into();
        let master = master.into();
        let member_idx = self.resolve_interface(&member).await?;
        let master_idx = self.resolve_interface(&master).await?;
        self.set_link_down_by_index(member_idx).await?;
        self.set_link_master_by_index(member_idx, master_idx)
            .await?;
        self.set_link_up_by_index(member_idx).await
    }

    /// Enslave an interface to a bond or bridge by index.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "enslave_by_index"))]
    pub async fn enslave_by_index(&self, member_index: u32, master_index: u32) -> Result<()> {
        self.set_link_down_by_index(member_index).await?;
        self.set_link_master_by_index(member_index, master_index)
            .await?;
        self.set_link_up_by_index(member_index).await
    }

    /// Remove an interface from its master device.
    ///
    /// Accepts either an interface name or index via [`InterfaceRef`].
    ///
    /// # Example
    ///
    /// ```ignore
    /// // Remove eth0 from its bridge/bond
    /// conn.set_link_nomaster("eth0").await?;
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "set_link_nomaster"))]
    pub async fn set_link_nomaster(&self, iface: impl Into<InterfaceRef>) -> Result<()> {
        let ifindex = self.resolve_interface(&iface.into()).await?;
        self.set_link_nomaster_by_index(ifindex).await
    }

    /// Remove an interface from its master by index.
    #[tracing::instrument(
        level = "debug",
        skip_all,
        fields(method = "set_link_nomaster_by_index")
    )]
    pub async fn set_link_nomaster_by_index(&self, ifindex: u32) -> Result<()> {
        use super::connection::ack_request;

        let ifinfo = IfInfoMsg::new().with_index(ifindex as i32);

        let mut builder = ack_request(NlMsgType::RTM_SETLINK);
        builder.append(&ifinfo);
        builder.append_attr_u32(IflaAttr::Master as u16, 0);

        self.send_ack(builder)
            .await
            .map_err(|e| e.with_context("set_link_nomaster"))
    }

    /// Rename a network interface.
    ///
    /// Accepts either an interface name or index via [`InterfaceRef`].
    /// Note: The interface must be down to be renamed.
    ///
    /// # Example
    ///
    /// ```ignore
    /// conn.set_link_name("eth0", "lan0").await?;
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "set_link_name"))]
    pub async fn set_link_name(
        &self,
        iface: impl Into<InterfaceRef>,
        new_name: &str,
    ) -> Result<()> {
        let ifindex = self.resolve_interface(&iface.into()).await?;
        self.set_link_name_by_index(ifindex, new_name).await
    }

    /// Rename a network interface by index.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "set_link_name_by_index"))]
    pub async fn set_link_name_by_index(&self, ifindex: u32, new_name: &str) -> Result<()> {
        use super::connection::ack_request;

        // Validate the new name before sending to kernel
        crate::util::ifname::validate(new_name).map_err(super::error::Error::Interface)?;

        let ifinfo = IfInfoMsg::new().with_index(ifindex as i32);

        let mut builder = ack_request(NlMsgType::RTM_SETLINK);
        builder.append(&ifinfo);
        builder.append_attr_str(IflaAttr::Ifname as u16, new_name);

        self.send_ack(builder)
            .await
            .map_err(|e| e.with_context("set_link_name"))
    }

    /// Set the MAC address of a network interface.
    ///
    /// Accepts either an interface name or index via [`InterfaceRef`].
    ///
    /// # Example
    ///
    /// ```ignore
    /// conn.set_link_address("eth0", [0x00, 0x11, 0x22, 0x33, 0x44, 0x55]).await?;
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "set_link_address"))]
    pub async fn set_link_address(
        &self,
        iface: impl Into<InterfaceRef>,
        address: [u8; 6],
    ) -> Result<()> {
        let ifindex = self.resolve_interface(&iface.into()).await?;
        self.set_link_address_by_index(ifindex, address).await
    }

    /// Set the MAC address by interface index.
    #[tracing::instrument(
        level = "debug",
        skip_all,
        fields(method = "set_link_address_by_index")
    )]
    pub async fn set_link_address_by_index(&self, ifindex: u32, address: [u8; 6]) -> Result<()> {
        use super::connection::ack_request;

        let ifinfo = IfInfoMsg::new().with_index(ifindex as i32);

        let mut builder = ack_request(NlMsgType::RTM_SETLINK);
        builder.append(&ifinfo);
        builder.append_attr(IflaAttr::Address as u16, &address);

        self.send_ack(builder)
            .await
            .map_err(|e| e.with_context("set_link_address"))
    }

    /// Move a network interface to a different network namespace.
    ///
    /// Accepts either an interface name or index via [`InterfaceRef`].
    ///
    /// # Example
    ///
    /// ```ignore
    /// // Move veth1 to namespace by PID
    /// conn.set_link_netns_pid("veth1", container_pid).await?;
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "set_link_netns_pid"))]
    pub async fn set_link_netns_pid(&self, iface: impl Into<InterfaceRef>, pid: u32) -> Result<()> {
        let ifindex = self.resolve_interface(&iface.into()).await?;
        self.set_link_netns_pid_by_index(ifindex, pid).await
    }

    /// Move a network interface to a namespace by PID (by index).
    #[tracing::instrument(
        level = "debug",
        skip_all,
        fields(method = "set_link_netns_pid_by_index")
    )]
    pub async fn set_link_netns_pid_by_index(&self, ifindex: u32, pid: u32) -> Result<()> {
        use super::connection::ack_request;

        let ifinfo = IfInfoMsg::new().with_index(ifindex as i32);

        let mut builder = ack_request(NlMsgType::RTM_SETLINK);
        builder.append(&ifinfo);
        builder.append_attr_u32(IflaAttr::NetNsPid as u16, pid);

        self.send_ack(builder)
            .await
            .map_err(|e| e.with_context("set_link_netns"))
    }

    /// Move a network interface to a namespace by file descriptor.
    ///
    /// Accepts either an interface name or index via [`InterfaceRef`].
    #[tracing::instrument(level = "debug", skip_all, fields(method = "set_link_netns_fd"))]
    pub async fn set_link_netns_fd(&self, iface: impl Into<InterfaceRef>, fd: i32) -> Result<()> {
        let ifindex = self.resolve_interface(&iface.into()).await?;
        self.set_link_netns_fd_by_index(ifindex, fd).await
    }

    /// Move a network interface to a namespace by fd (by index).
    #[tracing::instrument(
        level = "debug",
        skip_all,
        fields(method = "set_link_netns_fd_by_index")
    )]
    pub async fn set_link_netns_fd_by_index(&self, ifindex: u32, fd: i32) -> Result<()> {
        use super::connection::ack_request;

        let ifinfo = IfInfoMsg::new().with_index(ifindex as i32);

        let mut builder = ack_request(NlMsgType::RTM_SETLINK);
        builder.append(&ifinfo);
        builder.append_attr_u32(IflaAttr::NetNsFd as u16, fd as u32);

        self.send_ack(builder)
            .await
            .map_err(|e| e.with_context("set_link_netns"))
    }

    /// Move a network interface to a named network namespace.
    ///
    /// This is a convenience wrapper that opens the namespace by name
    /// (from `/var/run/netns/<name>`) and calls [`set_link_netns_fd()`](Self::set_link_netns_fd).
    ///
    /// # Example
    ///
    /// ```ignore
    /// conn.set_link_netns("eth0", "my-ns").await?;
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "set_link_netns"))]
    pub async fn set_link_netns(
        &self,
        iface: impl Into<InterfaceRef>,
        ns_name: &str,
    ) -> Result<()> {
        let ns_fd = super::namespace::open(ns_name)?;
        let ifindex = self.resolve_interface(&iface.into()).await?;
        self.set_link_netns_fd_by_index(ifindex, ns_fd.as_raw_fd())
            .await
    }

    /// Move a network interface to a named network namespace (by index).
    ///
    /// See [`set_link_netns()`](Self::set_link_netns) for details.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "set_link_netns_by_index"))]
    pub async fn set_link_netns_by_index(&self, ifindex: u32, ns_name: &str) -> Result<()> {
        let ns_fd = super::namespace::open(ns_name)?;
        self.set_link_netns_fd_by_index(ifindex, ns_fd.as_raw_fd())
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bond_mode_try_from() {
        assert!(matches!(BondMode::try_from(0u8), Ok(BondMode::BalanceRr)));
        assert!(matches!(
            BondMode::try_from(1u8),
            Ok(BondMode::ActiveBackup)
        ));
        assert!(matches!(BondMode::try_from(2u8), Ok(BondMode::BalanceXor)));
        assert!(matches!(BondMode::try_from(3u8), Ok(BondMode::Broadcast)));
        assert!(matches!(BondMode::try_from(4u8), Ok(BondMode::Lacp)));
        assert!(matches!(BondMode::try_from(5u8), Ok(BondMode::BalanceTlb)));
        assert!(matches!(BondMode::try_from(6u8), Ok(BondMode::BalanceAlb)));
        assert!(BondMode::try_from(7u8).is_err());
        assert!(BondMode::try_from(255u8).is_err());
    }

    #[test]
    fn test_xmit_hash_policy_try_from() {
        assert!(matches!(
            XmitHashPolicy::try_from(0u8),
            Ok(XmitHashPolicy::Layer2)
        ));
        assert!(matches!(
            XmitHashPolicy::try_from(1u8),
            Ok(XmitHashPolicy::Layer34)
        ));
        assert!(matches!(
            XmitHashPolicy::try_from(2u8),
            Ok(XmitHashPolicy::Layer23)
        ));
        assert!(matches!(
            XmitHashPolicy::try_from(3u8),
            Ok(XmitHashPolicy::Encap23)
        ));
        assert!(matches!(
            XmitHashPolicy::try_from(4u8),
            Ok(XmitHashPolicy::Encap34)
        ));
        assert!(matches!(
            XmitHashPolicy::try_from(5u8),
            Ok(XmitHashPolicy::VlanSrcMac)
        ));
        assert!(XmitHashPolicy::try_from(6u8).is_err());
        assert!(XmitHashPolicy::try_from(255u8).is_err());
    }

    #[test]
    fn test_bond_mode_debug_format() {
        assert_eq!(format!("{:?}", BondMode::BalanceRr), "BalanceRr");
        assert_eq!(format!("{:?}", BondMode::Lacp), "Lacp");
        assert_eq!(format!("{:?}", BondMode::BalanceAlb), "BalanceAlb");
    }

    #[test]
    fn test_xmit_hash_policy_debug_format() {
        assert_eq!(format!("{:?}", XmitHashPolicy::Layer2), "Layer2");
        assert_eq!(format!("{:?}", XmitHashPolicy::Layer34), "Layer34");
        assert_eq!(format!("{:?}", XmitHashPolicy::VlanSrcMac), "VlanSrcMac");
    }
}
