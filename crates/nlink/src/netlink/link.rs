//! Link creation and management builders.
//!
//! This module provides typed builders for creating virtual network interfaces.
//!
//! # Supported Link Types
//!
//! - [`DummyLink`] - Dummy interface (loopback-like, no actual network)
//! - [`VethLink`] - Virtual ethernet pair
//! - [`BridgeLink`] - Bridge interface
//! - [`VlanLink`] - VLAN interface
//! - [`VxlanLink`] - VXLAN overlay interface
//! - [`MacvlanLink`] - MAC-based VLAN interface
//! - [`MacvtapLink`] - MAC-based tap interface (for VMs)
//! - [`IpvlanLink`] - IP-based VLAN interface
//! - [`IfbLink`] - Intermediate Functional Block (for ingress shaping)
//! - [`GeneveLink`] - Generic Network Virtualization Encapsulation
//! - [`BareudpLink`] - Bare UDP tunneling
//! - [`NetkitLink`] - BPF-optimized virtual ethernet
//! - [`NlmonLink`] - Netlink monitor for debugging
//! - [`VirtWifiLink`] - Virtual WiFi for testing
//! - [`VtiLink`] - Virtual Tunnel Interface (IPv4 IPsec)
//! - [`Vti6Link`] - Virtual Tunnel Interface (IPv6 IPsec)
//! - [`Ip6GreLink`] - IPv6 GRE tunnel
//! - [`Ip6GretapLink`] - IPv6 GRE TAP tunnel (Layer 2)
//!
//! # Example
//!
//! ```ignore
//! use nlink::netlink::{Connection, Protocol};
//! use nlink::netlink::link::{DummyLink, VethLink, BridgeLink, VlanLink};
//!
//! let conn = Connection::new(Protocol::Route)?;
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

use super::builder::MessageBuilder;
use super::connection::Connection;
use super::error::{Error, Result};
use super::message::NlMsgType;
use super::types::link::{IfInfoMsg, IflaAttr, IflaInfo};

/// NLM_F_CREATE flag
const NLM_F_CREATE: u16 = 0x400;
/// NLM_F_EXCL flag (fail if exists)
const NLM_F_EXCL: u16 = 0x200;

/// Trait for link configurations that can be added to the system.
pub trait LinkConfig {
    /// Get the name of this interface.
    fn name(&self) -> &str;

    /// Get the kind string for this link type (e.g., "dummy", "veth", "bridge").
    fn kind(&self) -> &str;

    /// Build the netlink message for creating this link.
    fn build(&self) -> Result<MessageBuilder>;
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

    fn build(&self) -> Result<MessageBuilder> {
        build_simple_link(&self.name, "dummy", self.mtu, self.address.as_ref())
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
#[derive(Debug, Clone)]
pub struct VethLink {
    name: String,
    peer_name: String,
    mtu: Option<u32>,
    address: Option<[u8; 6]>,
    peer_address: Option<[u8; 6]>,
    peer_netns_fd: Option<i32>,
    peer_netns_pid: Option<u32>,
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

    fn build(&self) -> Result<MessageBuilder> {
        let mut builder = create_link_message(&self.name);

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

        Ok(builder)
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

    fn build(&self) -> Result<MessageBuilder> {
        let mut builder = create_link_message(&self.name);

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

        Ok(builder)
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
pub struct VlanLink {
    name: String,
    parent: String,
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
            parent: parent.into(),
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

    fn build(&self) -> Result<MessageBuilder> {
        // Get parent interface index
        let parent_index = ifname_to_index(&self.parent)?;

        let mut builder = create_link_message(&self.name);

        // Link to parent
        builder.append_attr_u32(IflaAttr::Link as u16, parent_index as u32);

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

        Ok(builder)
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
    dev: Option<String>,
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

    /// Set the underlying device.
    pub fn dev(mut self, dev: impl Into<String>) -> Self {
        self.dev = Some(dev.into());
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

    fn build(&self) -> Result<MessageBuilder> {
        let mut builder = create_link_message(&self.name);

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

        // Underlying device
        if let Some(ref dev) = self.dev {
            let index = ifname_to_index(dev)?;
            builder.append_attr_u32(vxlan::IFLA_VXLAN_LINK, index as u32);
        }

        // Port
        if let Some(port) = self.port {
            builder.append_attr_u16_be(vxlan::IFLA_VXLAN_PORT, port);
        }

        // Port range
        if let Some((low, high)) = self.port_range {
            let range = [low.to_be(), high.to_be()];
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

        Ok(builder)
    }
}

// ============================================================================
// Macvlan Link
// ============================================================================

/// Macvlan mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
pub struct MacvlanLink {
    name: String,
    parent: String,
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
            parent: parent.into(),
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

    fn build(&self) -> Result<MessageBuilder> {
        let parent_index = ifname_to_index(&self.parent)?;

        let mut builder = create_link_message(&self.name);

        // Link to parent
        builder.append_attr_u32(IflaAttr::Link as u16, parent_index as u32);

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

        Ok(builder)
    }
}

// ============================================================================
// Ipvlan Link
// ============================================================================

/// Ipvlan mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
pub struct IpvlanLink {
    name: String,
    parent: String,
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
            parent: parent.into(),
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

    fn build(&self) -> Result<MessageBuilder> {
        let parent_index = ifname_to_index(&self.parent)?;

        let mut builder = create_link_message(&self.name);

        // Link to parent
        builder.append_attr_u32(IflaAttr::Link as u16, parent_index as u32);

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

        Ok(builder)
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

    fn build(&self) -> Result<MessageBuilder> {
        build_simple_link(&self.name, "ifb", self.mtu, None)
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
pub struct MacvtapLink {
    name: String,
    parent: String,
    mode: MacvlanMode,
    mtu: Option<u32>,
    address: Option<[u8; 6]>,
}

impl MacvtapLink {
    /// Create a new macvtap interface configuration.
    pub fn new(name: impl Into<String>, parent: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            parent: parent.into(),
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

    fn build(&self) -> Result<MessageBuilder> {
        let parent_index = ifname_to_index(&self.parent)?;

        let mut builder = create_link_message(&self.name);

        // Link to parent
        builder.append_attr_u32(IflaAttr::Link as u16, parent_index as u32);

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

        Ok(builder)
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

    fn build(&self) -> Result<MessageBuilder> {
        let mut builder = create_link_message(&self.name);

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

        Ok(builder)
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

    fn build(&self) -> Result<MessageBuilder> {
        let mut builder = create_link_message(&self.name);

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

        Ok(builder)
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
pub enum NetkitMode {
    /// L2 mode (Ethernet frames)
    L2 = 0,
    /// L3 mode (IP packets)
    L3 = 1,
}

/// Netkit default policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetkitPolicy {
    /// Forward packets (default)
    Forward = 0,
    /// Blackhole (drop)
    Blackhole = 2,
}

/// Netkit scrub mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

    fn build(&self) -> Result<MessageBuilder> {
        let mut builder = create_link_message(&self.name);

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

        Ok(builder)
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

    fn build(&self) -> Result<MessageBuilder> {
        build_simple_link(&self.name, "nlmon", None, None)
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
pub struct VirtWifiLink {
    name: String,
    link: String,
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
            link: link.into(),
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

    fn build(&self) -> Result<MessageBuilder> {
        let link_index = ifname_to_index(&self.link)?;

        let mut builder = create_link_message(&self.name);

        // Set the underlying link
        builder.append_attr_u32(IflaAttr::Link as u16, link_index as u32);

        // IFLA_LINKINFO
        let linkinfo = builder.nest_start(IflaAttr::Linkinfo as u16);
        builder.append_attr_str(IflaInfo::Kind as u16, "virt_wifi");
        builder.nest_end(linkinfo);

        Ok(builder)
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
pub struct VtiLink {
    name: String,
    local: Option<Ipv4Addr>,
    remote: Option<Ipv4Addr>,
    ikey: Option<u32>,
    okey: Option<u32>,
    link: Option<String>,
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

    /// Set the underlying link device.
    pub fn link(mut self, link: impl Into<String>) -> Self {
        self.link = Some(link.into());
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

    fn build(&self) -> Result<MessageBuilder> {
        let mut builder = create_link_message(&self.name);

        // Set underlying link if specified
        if let Some(ref link) = self.link {
            let link_index = ifname_to_index(link)?;
            builder.append_attr_u32(IflaAttr::Link as u16, link_index as u32);
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

        Ok(builder)
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
pub struct Vti6Link {
    name: String,
    local: Option<std::net::Ipv6Addr>,
    remote: Option<std::net::Ipv6Addr>,
    ikey: Option<u32>,
    okey: Option<u32>,
    link: Option<String>,
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

    /// Set the underlying link device.
    pub fn link(mut self, link: impl Into<String>) -> Self {
        self.link = Some(link.into());
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

    fn build(&self) -> Result<MessageBuilder> {
        let mut builder = create_link_message(&self.name);

        // Set underlying link if specified
        if let Some(ref link) = self.link {
            let link_index = ifname_to_index(link)?;
            builder.append_attr_u32(IflaAttr::Link as u16, link_index as u32);
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

        Ok(builder)
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
pub struct Ip6GreLink {
    name: String,
    local: Option<std::net::Ipv6Addr>,
    remote: Option<std::net::Ipv6Addr>,
    ttl: Option<u8>,
    encap_limit: Option<u8>,
    flowinfo: Option<u32>,
    flags: Option<u32>,
    link: Option<String>,
}

/// IP6GRE-specific attributes (IFLA_GRE_*)
#[allow(dead_code)]
mod ip6gre {
    pub const IFLA_GRE_LINK: u16 = 1;
    pub const IFLA_GRE_IFLAGS: u16 = 2;
    pub const IFLA_GRE_OFLAGS: u16 = 3;
    pub const IFLA_GRE_IKEY: u16 = 4;
    pub const IFLA_GRE_OKEY: u16 = 5;
    pub const IFLA_GRE_LOCAL: u16 = 6;
    pub const IFLA_GRE_REMOTE: u16 = 7;
    pub const IFLA_GRE_TTL: u16 = 8;
    pub const IFLA_GRE_TOS: u16 = 9;
    pub const IFLA_GRE_ENCAP_LIMIT: u16 = 12;
    pub const IFLA_GRE_FLOWINFO: u16 = 13;
    pub const IFLA_GRE_FLAGS: u16 = 14;
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

    /// Set the underlying link device.
    pub fn link(mut self, link: impl Into<String>) -> Self {
        self.link = Some(link.into());
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

    fn build(&self) -> Result<MessageBuilder> {
        let mut builder = create_link_message(&self.name);

        // IFLA_LINKINFO
        let linkinfo = builder.nest_start(IflaAttr::Linkinfo as u16);
        builder.append_attr_str(IflaInfo::Kind as u16, "ip6gre");

        // IFLA_INFO_DATA
        let data = builder.nest_start(IflaInfo::Data as u16);

        if let Some(ref link) = self.link {
            let link_index = ifname_to_index(link)?;
            builder.append_attr_u32(ip6gre::IFLA_GRE_LINK, link_index as u32);
        }
        if let Some(local) = self.local {
            builder.append_attr(ip6gre::IFLA_GRE_LOCAL, &local.octets());
        }
        if let Some(remote) = self.remote {
            builder.append_attr(ip6gre::IFLA_GRE_REMOTE, &remote.octets());
        }
        if let Some(ttl) = self.ttl {
            builder.append_attr_u8(ip6gre::IFLA_GRE_TTL, ttl);
        }
        if let Some(limit) = self.encap_limit {
            builder.append_attr_u8(ip6gre::IFLA_GRE_ENCAP_LIMIT, limit);
        }
        if let Some(flowinfo) = self.flowinfo {
            builder.append_attr_u32_be(ip6gre::IFLA_GRE_FLOWINFO, flowinfo);
        }
        if let Some(flags) = self.flags {
            builder.append_attr_u32(ip6gre::IFLA_GRE_FLAGS, flags);
        }

        builder.nest_end(data);
        builder.nest_end(linkinfo);

        Ok(builder)
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
pub struct Ip6GretapLink {
    name: String,
    local: Option<std::net::Ipv6Addr>,
    remote: Option<std::net::Ipv6Addr>,
    ttl: Option<u8>,
    encap_limit: Option<u8>,
    flowinfo: Option<u32>,
    link: Option<String>,
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

    /// Set the underlying link device.
    pub fn link(mut self, link: impl Into<String>) -> Self {
        self.link = Some(link.into());
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

    fn build(&self) -> Result<MessageBuilder> {
        let mut builder = create_link_message(&self.name);

        // IFLA_LINKINFO
        let linkinfo = builder.nest_start(IflaAttr::Linkinfo as u16);
        builder.append_attr_str(IflaInfo::Kind as u16, "ip6gretap");

        // IFLA_INFO_DATA - uses same attributes as ip6gre
        let data = builder.nest_start(IflaInfo::Data as u16);

        if let Some(ref link) = self.link {
            let link_index = ifname_to_index(link)?;
            builder.append_attr_u32(ip6gre::IFLA_GRE_LINK, link_index as u32);
        }
        if let Some(local) = self.local {
            builder.append_attr(ip6gre::IFLA_GRE_LOCAL, &local.octets());
        }
        if let Some(remote) = self.remote {
            builder.append_attr(ip6gre::IFLA_GRE_REMOTE, &remote.octets());
        }
        if let Some(ttl) = self.ttl {
            builder.append_attr_u8(ip6gre::IFLA_GRE_TTL, ttl);
        }
        if let Some(limit) = self.encap_limit {
            builder.append_attr_u8(ip6gre::IFLA_GRE_ENCAP_LIMIT, limit);
        }
        if let Some(flowinfo) = self.flowinfo {
            builder.append_attr_u32_be(ip6gre::IFLA_GRE_FLOWINFO, flowinfo);
        }

        builder.nest_end(data);
        builder.nest_end(linkinfo);

        Ok(builder)
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Helper function to convert interface name to index.
fn ifname_to_index(name: &str) -> Result<i32> {
    let path = format!("/sys/class/net/{}/ifindex", name);
    let content = std::fs::read_to_string(&path)
        .map_err(|_| Error::InvalidMessage(format!("interface not found: {}", name)))?;
    content
        .trim()
        .parse()
        .map_err(|_| Error::InvalidMessage(format!("invalid ifindex for: {}", name)))
}

/// Create the base RTM_NEWLINK message with ifinfomsg header.
fn create_link_message(name: &str) -> MessageBuilder {
    use super::message::{NLM_F_ACK, NLM_F_REQUEST};

    let mut builder = MessageBuilder::new(
        NlMsgType::RTM_NEWLINK,
        NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
    );

    // Append ifinfomsg header
    let ifinfo = IfInfoMsg::new();
    builder.append(&ifinfo);

    // Add interface name
    builder.append_attr_str(IflaAttr::Ifname as u16, name);

    builder
}

/// Build a simple link (like dummy) with just name and optional MTU/address.
fn build_simple_link(
    name: &str,
    kind: &str,
    mtu: Option<u32>,
    address: Option<&[u8; 6]>,
) -> Result<MessageBuilder> {
    let mut builder = create_link_message(name);

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

    Ok(builder)
}

// ============================================================================
// Connection Methods
// ============================================================================

impl Connection {
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
    /// ```
    pub async fn add_link<L: LinkConfig>(&self, config: L) -> Result<()> {
        let builder = config.build()?;
        self.request_ack(builder).await
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
    /// ```
    pub async fn set_link_master(&self, ifname: &str, master: &str) -> Result<()> {
        let ifindex = ifname_to_index(ifname)?;
        let master_index = ifname_to_index(master)?;
        self.set_link_master_by_index(ifindex, master_index).await
    }

    /// Set the master device by interface indices.
    pub async fn set_link_master_by_index(&self, ifindex: i32, master_index: i32) -> Result<()> {
        use super::connection::ack_request;

        let ifinfo = IfInfoMsg::new().with_index(ifindex);

        let mut builder = ack_request(NlMsgType::RTM_SETLINK);
        builder.append(&ifinfo);
        builder.append_attr_u32(IflaAttr::Master as u16, master_index as u32);

        self.request_ack(builder).await
    }

    /// Remove an interface from its master device.
    ///
    /// # Example
    ///
    /// ```ignore
    /// // Remove eth0 from its bridge/bond
    /// conn.set_link_nomaster("eth0").await?;
    /// ```
    pub async fn set_link_nomaster(&self, ifname: &str) -> Result<()> {
        let ifindex = ifname_to_index(ifname)?;
        self.set_link_nomaster_by_index(ifindex).await
    }

    /// Remove an interface from its master by index.
    pub async fn set_link_nomaster_by_index(&self, ifindex: i32) -> Result<()> {
        use super::connection::ack_request;

        let ifinfo = IfInfoMsg::new().with_index(ifindex);

        let mut builder = ack_request(NlMsgType::RTM_SETLINK);
        builder.append(&ifinfo);
        builder.append_attr_u32(IflaAttr::Master as u16, 0);

        self.request_ack(builder).await
    }

    /// Rename a network interface.
    ///
    /// Note: The interface must be down to be renamed.
    ///
    /// # Example
    ///
    /// ```ignore
    /// conn.set_link_name("eth0", "lan0").await?;
    /// ```
    pub async fn set_link_name(&self, ifname: &str, new_name: &str) -> Result<()> {
        let ifindex = ifname_to_index(ifname)?;
        self.set_link_name_by_index(ifindex, new_name).await
    }

    /// Rename a network interface by index.
    pub async fn set_link_name_by_index(&self, ifindex: i32, new_name: &str) -> Result<()> {
        use super::connection::ack_request;

        let ifinfo = IfInfoMsg::new().with_index(ifindex);

        let mut builder = ack_request(NlMsgType::RTM_SETLINK);
        builder.append(&ifinfo);
        builder.append_attr_str(IflaAttr::Ifname as u16, new_name);

        self.request_ack(builder).await
    }

    /// Set the MAC address of a network interface.
    ///
    /// # Example
    ///
    /// ```ignore
    /// conn.set_link_address("eth0", [0x00, 0x11, 0x22, 0x33, 0x44, 0x55]).await?;
    /// ```
    pub async fn set_link_address(&self, ifname: &str, address: [u8; 6]) -> Result<()> {
        let ifindex = ifname_to_index(ifname)?;
        self.set_link_address_by_index(ifindex, address).await
    }

    /// Set the MAC address by interface index.
    pub async fn set_link_address_by_index(&self, ifindex: i32, address: [u8; 6]) -> Result<()> {
        use super::connection::ack_request;

        let ifinfo = IfInfoMsg::new().with_index(ifindex);

        let mut builder = ack_request(NlMsgType::RTM_SETLINK);
        builder.append(&ifinfo);
        builder.append_attr(IflaAttr::Address as u16, &address);

        self.request_ack(builder).await
    }

    /// Move a network interface to a different network namespace.
    ///
    /// # Example
    ///
    /// ```ignore
    /// // Move veth1 to namespace by PID
    /// conn.set_link_netns_pid("veth1", container_pid).await?;
    /// ```
    pub async fn set_link_netns_pid(&self, ifname: &str, pid: u32) -> Result<()> {
        let ifindex = ifname_to_index(ifname)?;
        self.set_link_netns_pid_by_index(ifindex, pid).await
    }

    /// Move a network interface to a namespace by PID (by index).
    pub async fn set_link_netns_pid_by_index(&self, ifindex: i32, pid: u32) -> Result<()> {
        use super::connection::ack_request;

        let ifinfo = IfInfoMsg::new().with_index(ifindex);

        let mut builder = ack_request(NlMsgType::RTM_SETLINK);
        builder.append(&ifinfo);
        builder.append_attr_u32(IflaAttr::NetNsPid as u16, pid);

        self.request_ack(builder).await
    }

    /// Move a network interface to a namespace by file descriptor.
    pub async fn set_link_netns_fd(&self, ifname: &str, fd: i32) -> Result<()> {
        let ifindex = ifname_to_index(ifname)?;
        self.set_link_netns_fd_by_index(ifindex, fd).await
    }

    /// Move a network interface to a namespace by fd (by index).
    pub async fn set_link_netns_fd_by_index(&self, ifindex: i32, fd: i32) -> Result<()> {
        use super::connection::ack_request;

        let ifinfo = IfInfoMsg::new().with_index(ifindex);

        let mut builder = ack_request(NlMsgType::RTM_SETLINK);
        builder.append(&ifinfo);
        builder.append_attr_u32(IflaAttr::NetNsFd as u16, fd as u32);

        self.request_ack(builder).await
    }
}
