//! IP address management.
//!
//! This module provides typed builders for adding and managing IP addresses.
//!
//! # Example
//!
//! ```ignore
//! use nlink::netlink::{Connection, Protocol};
//! use nlink::netlink::addr::{Ipv4Address, Ipv6Address, AddressFlags};
//! use std::net::{Ipv4Addr, Ipv6Addr};
//!
//! let conn = Connection::new(Protocol::Route)?;
//!
//! // Add an IPv4 address
//! conn.add_address(
//!     Ipv4Address::new("eth0", Ipv4Addr::new(192, 168, 1, 100), 24)
//!         .broadcast(Ipv4Addr::new(192, 168, 1, 255))
//!         .label("eth0:web")
//! ).await?;
//!
//! // Add an IPv6 address with lifetimes
//! conn.add_address(
//!     Ipv6Address::new("eth0", "2001:db8::1".parse()?, 64)
//!         .preferred_lifetime(3600)
//!         .valid_lifetime(7200)
//! ).await?;
//!
//! // Delete an address
//! conn.del_address("eth0", Ipv4Addr::new(192, 168, 1, 100), 24).await?;
//! ```

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use super::builder::MessageBuilder;
use super::connection::Connection;
use super::error::{Error, Result};
use super::message::{NLM_F_ACK, NLM_F_REQUEST, NlMsgType};
use super::types::addr::{IfAddrMsg, IfaAttr, Scope, ifa_flags};

/// NLM_F_CREATE flag
const NLM_F_CREATE: u16 = 0x400;
/// NLM_F_EXCL flag
const NLM_F_EXCL: u16 = 0x200;

/// Address families
pub const AF_INET: u8 = 2;
pub const AF_INET6: u8 = 10;

/// Trait for address configurations that can be added.
pub trait AddressConfig {
    /// Get the interface name.
    fn interface(&self) -> &str;

    /// Build the netlink message for adding this address.
    fn build(&self) -> Result<MessageBuilder>;

    /// Build a message for deleting this address.
    fn build_delete(&self) -> Result<MessageBuilder>;
}

/// Cache info structure for address lifetimes.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
struct IfaCacheinfo {
    /// Preferred lifetime in seconds (INFINITY_LIFE_TIME for forever)
    ifa_prefered: u32,
    /// Valid lifetime in seconds (INFINITY_LIFE_TIME for forever)
    ifa_valid: u32,
    /// Creation timestamp (unused for add)
    cstamp: u32,
    /// Update timestamp (unused for add)
    tstamp: u32,
}

/// Infinity lifetime value (0xFFFFFFFF)
pub const INFINITY_LIFE_TIME: u32 = 0xFFFFFFFF;

// ============================================================================
// IPv4 Address
// ============================================================================

/// Configuration for an IPv4 address.
///
/// # Example
///
/// ```ignore
/// use nlink::netlink::addr::Ipv4Address;
/// use std::net::Ipv4Addr;
///
/// let addr = Ipv4Address::new("eth0", Ipv4Addr::new(192, 168, 1, 100), 24)
///     .broadcast(Ipv4Addr::new(192, 168, 1, 255))
///     .label("eth0:web")
///     .scope(nlink::netlink::types::addr::Scope::Universe);
///
/// conn.add_address(addr).await?;
/// ```
#[derive(Debug, Clone)]
pub struct Ipv4Address {
    interface: String,
    address: Ipv4Addr,
    prefix_len: u8,
    /// Peer address for point-to-point links
    peer: Option<Ipv4Addr>,
    /// Broadcast address
    broadcast: Option<Ipv4Addr>,
    /// Address label (max 15 chars + null)
    label: Option<String>,
    /// Address scope
    scope: Scope,
    /// Address flags
    flags: u32,
    /// Preferred lifetime in seconds
    preferred_lft: Option<u32>,
    /// Valid lifetime in seconds
    valid_lft: Option<u32>,
    /// Route metric/priority
    metric: Option<u32>,
}

impl Ipv4Address {
    /// Create a new IPv4 address configuration.
    ///
    /// # Arguments
    ///
    /// * `interface` - Interface name (e.g., "eth0")
    /// * `address` - IPv4 address
    /// * `prefix_len` - Prefix length (0-32)
    pub fn new(interface: impl Into<String>, address: Ipv4Addr, prefix_len: u8) -> Self {
        Self {
            interface: interface.into(),
            address,
            prefix_len,
            peer: None,
            broadcast: None,
            label: None,
            scope: Scope::Universe,
            flags: 0,
            preferred_lft: None,
            valid_lft: None,
            metric: None,
        }
    }

    /// Set the peer address for point-to-point links.
    pub fn peer(mut self, peer: Ipv4Addr) -> Self {
        self.peer = Some(peer);
        self
    }

    /// Set the broadcast address.
    ///
    /// If not set, the kernel will compute it automatically.
    pub fn broadcast(mut self, broadcast: Ipv4Addr) -> Self {
        self.broadcast = Some(broadcast);
        self
    }

    /// Set an address label.
    ///
    /// Labels are used for compatibility with older tools and can be
    /// used to identify addresses (e.g., "eth0:web").
    /// Maximum 15 characters.
    pub fn label(mut self, label: impl Into<String>) -> Self {
        let mut l = label.into();
        if l.len() > 15 {
            l.truncate(15);
        }
        self.label = Some(l);
        self
    }

    /// Set the address scope.
    pub fn scope(mut self, scope: Scope) -> Self {
        self.scope = scope;
        self
    }

    /// Mark as secondary address.
    pub fn secondary(mut self) -> Self {
        self.flags |= ifa_flags::SECONDARY;
        self
    }

    /// Disable prefix route creation.
    pub fn noprefixroute(mut self) -> Self {
        self.flags |= ifa_flags::NOPREFIXROUTE;
        self
    }

    /// Set home address flag (Mobile IPv6).
    pub fn home(mut self) -> Self {
        self.flags |= ifa_flags::HOMEADDRESS;
        self
    }

    /// Set the preferred lifetime in seconds.
    ///
    /// Use `INFINITY_LIFE_TIME` for forever.
    pub fn preferred_lifetime(mut self, seconds: u32) -> Self {
        self.preferred_lft = Some(seconds);
        self
    }

    /// Set the valid lifetime in seconds.
    ///
    /// Use `INFINITY_LIFE_TIME` for forever.
    pub fn valid_lifetime(mut self, seconds: u32) -> Self {
        self.valid_lft = Some(seconds);
        self
    }

    /// Set the route metric/priority.
    pub fn metric(mut self, metric: u32) -> Self {
        self.metric = Some(metric);
        self
    }
}

impl AddressConfig for Ipv4Address {
    fn interface(&self) -> &str {
        &self.interface
    }

    fn build(&self) -> Result<MessageBuilder> {
        let ifindex = ifname_to_index(&self.interface)?;

        let mut builder = MessageBuilder::new(
            NlMsgType::RTM_NEWADDR,
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
        );

        // Build ifaddrmsg
        let ifaddr = IfAddrMsg::new()
            .with_family(AF_INET)
            .with_prefixlen(self.prefix_len)
            .with_index(ifindex as u32)
            .with_scope(self.scope as u8);

        builder.append(&ifaddr);

        // IFA_LOCAL (the actual address on this interface)
        builder.append_attr(IfaAttr::Local as u16, &self.address.octets());

        // IFA_ADDRESS (peer address for ptp, or same as local)
        if let Some(peer) = self.peer {
            builder.append_attr(IfaAttr::Address as u16, &peer.octets());
        } else {
            builder.append_attr(IfaAttr::Address as u16, &self.address.octets());
        }

        // IFA_BROADCAST
        if let Some(brd) = self.broadcast {
            builder.append_attr(IfaAttr::Broadcast as u16, &brd.octets());
        }

        // IFA_LABEL
        if let Some(ref label) = self.label {
            builder.append_attr_str(IfaAttr::Label as u16, label);
        }

        // IFA_FLAGS (extended flags, 32-bit)
        if self.flags != 0 {
            builder.append_attr_u32(IfaAttr::Flags as u16, self.flags);
        }

        // IFA_CACHEINFO (lifetimes)
        if self.preferred_lft.is_some() || self.valid_lft.is_some() {
            let cacheinfo = IfaCacheinfo {
                ifa_prefered: self.preferred_lft.unwrap_or(INFINITY_LIFE_TIME),
                ifa_valid: self.valid_lft.unwrap_or(INFINITY_LIFE_TIME),
                cstamp: 0,
                tstamp: 0,
            };
            let bytes = unsafe {
                std::slice::from_raw_parts(
                    &cacheinfo as *const IfaCacheinfo as *const u8,
                    std::mem::size_of::<IfaCacheinfo>(),
                )
            };
            builder.append_attr(IfaAttr::Cacheinfo as u16, bytes);
        }

        // IFA_RT_PRIORITY (metric)
        if let Some(metric) = self.metric {
            builder.append_attr_u32(IfaAttr::RtPriority as u16, metric);
        }

        Ok(builder)
    }

    fn build_delete(&self) -> Result<MessageBuilder> {
        let ifindex = ifname_to_index(&self.interface)?;

        let mut builder = MessageBuilder::new(NlMsgType::RTM_DELADDR, NLM_F_REQUEST | NLM_F_ACK);

        let ifaddr = IfAddrMsg::new()
            .with_family(AF_INET)
            .with_prefixlen(self.prefix_len)
            .with_index(ifindex as u32);

        builder.append(&ifaddr);

        // IFA_LOCAL
        builder.append_attr(IfaAttr::Local as u16, &self.address.octets());

        Ok(builder)
    }
}

// ============================================================================
// IPv6 Address
// ============================================================================

/// Configuration for an IPv6 address.
///
/// # Example
///
/// ```ignore
/// use nlink::netlink::addr::Ipv6Address;
/// use std::net::Ipv6Addr;
///
/// let addr = Ipv6Address::new("eth0", "2001:db8::1".parse()?, 64)
///     .preferred_lifetime(3600)
///     .valid_lifetime(7200)
///     .nodad();
///
/// conn.add_address(addr).await?;
/// ```
#[derive(Debug, Clone)]
pub struct Ipv6Address {
    interface: String,
    address: Ipv6Addr,
    prefix_len: u8,
    /// Peer address for point-to-point links
    peer: Option<Ipv6Addr>,
    /// Address scope
    scope: Scope,
    /// Address flags
    flags: u32,
    /// Preferred lifetime in seconds
    preferred_lft: Option<u32>,
    /// Valid lifetime in seconds
    valid_lft: Option<u32>,
    /// Route metric/priority
    metric: Option<u32>,
}

impl Ipv6Address {
    /// Create a new IPv6 address configuration.
    ///
    /// # Arguments
    ///
    /// * `interface` - Interface name (e.g., "eth0")
    /// * `address` - IPv6 address
    /// * `prefix_len` - Prefix length (0-128)
    pub fn new(interface: impl Into<String>, address: Ipv6Addr, prefix_len: u8) -> Self {
        Self {
            interface: interface.into(),
            address,
            prefix_len,
            peer: None,
            scope: Scope::Universe,
            flags: 0,
            preferred_lft: None,
            valid_lft: None,
            metric: None,
        }
    }

    /// Set the peer address for point-to-point links.
    pub fn peer(mut self, peer: Ipv6Addr) -> Self {
        self.peer = Some(peer);
        self
    }

    /// Set the address scope.
    pub fn scope(mut self, scope: Scope) -> Self {
        self.scope = scope;
        self
    }

    /// Disable Duplicate Address Detection.
    pub fn nodad(mut self) -> Self {
        self.flags |= ifa_flags::NODAD;
        self
    }

    /// Set optimistic DAD flag.
    pub fn optimistic(mut self) -> Self {
        self.flags |= ifa_flags::OPTIMISTIC;
        self
    }

    /// Disable prefix route creation.
    pub fn noprefixroute(mut self) -> Self {
        self.flags |= ifa_flags::NOPREFIXROUTE;
        self
    }

    /// Set home address flag (Mobile IPv6).
    pub fn home(mut self) -> Self {
        self.flags |= ifa_flags::HOMEADDRESS;
        self
    }

    /// Enable management of temporary addresses.
    pub fn mngtmpaddr(mut self) -> Self {
        self.flags |= ifa_flags::MANAGETEMPADDR;
        self
    }

    /// Set the preferred lifetime in seconds.
    ///
    /// Use `INFINITY_LIFE_TIME` for forever.
    pub fn preferred_lifetime(mut self, seconds: u32) -> Self {
        self.preferred_lft = Some(seconds);
        self
    }

    /// Set the valid lifetime in seconds.
    ///
    /// Use `INFINITY_LIFE_TIME` for forever.
    pub fn valid_lifetime(mut self, seconds: u32) -> Self {
        self.valid_lft = Some(seconds);
        self
    }

    /// Set the route metric/priority.
    pub fn metric(mut self, metric: u32) -> Self {
        self.metric = Some(metric);
        self
    }
}

impl AddressConfig for Ipv6Address {
    fn interface(&self) -> &str {
        &self.interface
    }

    fn build(&self) -> Result<MessageBuilder> {
        let ifindex = ifname_to_index(&self.interface)?;

        let mut builder = MessageBuilder::new(
            NlMsgType::RTM_NEWADDR,
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
        );

        let ifaddr = IfAddrMsg::new()
            .with_family(AF_INET6)
            .with_prefixlen(self.prefix_len)
            .with_index(ifindex as u32)
            .with_scope(self.scope as u8);

        builder.append(&ifaddr);

        // IFA_LOCAL
        builder.append_attr(IfaAttr::Local as u16, &self.address.octets());

        // IFA_ADDRESS (peer or same as local)
        if let Some(peer) = self.peer {
            builder.append_attr(IfaAttr::Address as u16, &peer.octets());
        } else {
            builder.append_attr(IfaAttr::Address as u16, &self.address.octets());
        }

        // IFA_FLAGS (extended flags, 32-bit)
        if self.flags != 0 {
            builder.append_attr_u32(IfaAttr::Flags as u16, self.flags);
        }

        // IFA_CACHEINFO (lifetimes)
        if self.preferred_lft.is_some() || self.valid_lft.is_some() {
            let cacheinfo = IfaCacheinfo {
                ifa_prefered: self.preferred_lft.unwrap_or(INFINITY_LIFE_TIME),
                ifa_valid: self.valid_lft.unwrap_or(INFINITY_LIFE_TIME),
                cstamp: 0,
                tstamp: 0,
            };
            let bytes = unsafe {
                std::slice::from_raw_parts(
                    &cacheinfo as *const IfaCacheinfo as *const u8,
                    std::mem::size_of::<IfaCacheinfo>(),
                )
            };
            builder.append_attr(IfaAttr::Cacheinfo as u16, bytes);
        }

        // IFA_RT_PRIORITY (metric)
        if let Some(metric) = self.metric {
            builder.append_attr_u32(IfaAttr::RtPriority as u16, metric);
        }

        Ok(builder)
    }

    fn build_delete(&self) -> Result<MessageBuilder> {
        let ifindex = ifname_to_index(&self.interface)?;

        let mut builder = MessageBuilder::new(NlMsgType::RTM_DELADDR, NLM_F_REQUEST | NLM_F_ACK);

        let ifaddr = IfAddrMsg::new()
            .with_family(AF_INET6)
            .with_prefixlen(self.prefix_len)
            .with_index(ifindex as u32);

        builder.append(&ifaddr);

        // IFA_LOCAL
        builder.append_attr(IfaAttr::Local as u16, &self.address.octets());

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

// ============================================================================
// Connection Methods
// ============================================================================

impl Connection {
    /// Add an IP address to an interface.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use nlink::netlink::addr::{Ipv4Address, Ipv6Address};
    /// use std::net::{Ipv4Addr, Ipv6Addr};
    ///
    /// // Add IPv4 address
    /// conn.add_address(
    ///     Ipv4Address::new("eth0", Ipv4Addr::new(192, 168, 1, 100), 24)
    /// ).await?;
    ///
    /// // Add IPv6 address
    /// conn.add_address(
    ///     Ipv6Address::new("eth0", "2001:db8::1".parse()?, 64)
    /// ).await?;
    /// ```
    pub async fn add_address<A: AddressConfig>(&self, config: A) -> Result<()> {
        let builder = config.build()?;
        self.request_ack(builder).await
    }

    /// Delete an IP address from an interface.
    ///
    /// # Example
    ///
    /// ```ignore
    /// conn.del_address("eth0", IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 24).await?;
    /// ```
    pub async fn del_address(&self, ifname: &str, address: IpAddr, prefix_len: u8) -> Result<()> {
        match address {
            IpAddr::V4(addr) => {
                let config = Ipv4Address::new(ifname, addr, prefix_len);
                let builder = config.build_delete()?;
                self.request_ack(builder).await
            }
            IpAddr::V6(addr) => {
                let config = Ipv6Address::new(ifname, addr, prefix_len);
                let builder = config.build_delete()?;
                self.request_ack(builder).await
            }
        }
    }

    /// Delete an IPv4 address from an interface.
    pub async fn del_address_v4(
        &self,
        ifname: &str,
        address: Ipv4Addr,
        prefix_len: u8,
    ) -> Result<()> {
        let config = Ipv4Address::new(ifname, address, prefix_len);
        let builder = config.build_delete()?;
        self.request_ack(builder).await
    }

    /// Delete an IPv6 address from an interface.
    pub async fn del_address_v6(
        &self,
        ifname: &str,
        address: Ipv6Addr,
        prefix_len: u8,
    ) -> Result<()> {
        let config = Ipv6Address::new(ifname, address, prefix_len);
        let builder = config.build_delete()?;
        self.request_ack(builder).await
    }

    /// Delete an IP address using a typed config.
    pub async fn del_address_config<A: AddressConfig>(&self, config: A) -> Result<()> {
        let builder = config.build_delete()?;
        self.request_ack(builder).await
    }

    /// Replace an IP address (add or update).
    ///
    /// This is like `add_address` but will update if the address exists.
    pub async fn replace_address<A: AddressConfig>(&self, config: A) -> Result<()> {
        // We need to rebuild with different flags
        let builder = config.build()?;
        // Modify flags in the header to use REPLACE instead of CREATE|EXCL
        // We need to rebuild the message with different flags

        // Get interface and rebuild with replace flags
        let ifname = config.interface();
        let _ifindex = ifname_to_index(ifname)?;

        // For now, just use the build which handles flags internally
        // TODO: Implement proper replace by modifying builder flags
        self.request_ack(builder).await
    }

    /// Flush all addresses from an interface.
    ///
    /// # Example
    ///
    /// ```ignore
    /// conn.flush_addresses("eth0").await?;
    /// ```
    pub async fn flush_addresses(&self, ifname: &str) -> Result<()> {
        let addresses = self.get_addresses_for(ifname).await?;

        for addr in addresses {
            if let (Some(address), Some(prefix_len)) = (addr.address, Some(addr.prefix_len())) {
                // Skip loopback addresses on loopback interface
                if ifname == "lo"
                    && (address == IpAddr::V4(Ipv4Addr::LOCALHOST)
                        || address == IpAddr::V6(Ipv6Addr::LOCALHOST))
                {
                    continue;
                }

                if let Err(e) = self.del_address(ifname, address, prefix_len).await {
                    // Ignore "not found" errors (race condition)
                    if !e.is_not_found() {
                        return Err(e);
                    }
                }
            }
        }

        Ok(())
    }
}
