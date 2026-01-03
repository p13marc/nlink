//! Protocol state types for strongly-typed connections.
//!
//! This module provides the type-level protocol distinction that enables
//! compile-time safety for protocol-specific operations on [`Connection`].
//!
//! # Design
//!
//! Each netlink protocol (Route, Generic, etc.) has an associated state type
//! that may carry protocol-specific data:
//!
//! - [`Route`]: Zero-sized, no additional state needed
//! - [`Generic`]: Contains a family ID cache for efficient lookups
//!
//! The [`ProtocolState`] trait is sealed to prevent external implementations.
//!
//! # Example
//!
//! ```ignore
//! use nlink::netlink::{Connection, Route, Generic};
//!
//! // Route connection for interface/address/route/TC operations
//! let route = Connection::<Route>::new()?;
//! route.get_links().await?;
//!
//! // Generic connection for WireGuard/MACsec configuration
//! let genl = Connection::<Generic>::new()?;
//! genl.get_family("wireguard").await?;
//! ```

use std::collections::HashMap;
use std::sync::RwLock;

use super::genl::FamilyInfo;
use super::socket::Protocol;

/// Sealed trait module to prevent external implementations.
mod private {
    pub trait Sealed {}
}

/// Protocol state trait for typed connections.
///
/// This trait is sealed and cannot be implemented outside this crate.
/// Each implementation provides:
/// - The underlying netlink protocol constant
/// - Protocol-specific state (if any)
///
/// Types that implement `Default` can use the generic `Connection::new()`.
/// Types that require special initialization should provide their own constructor.
pub trait ProtocolState: private::Sealed {
    /// The netlink protocol for this state type.
    const PROTOCOL: Protocol;
}

/// Route protocol state (RTNetlink).
///
/// Used for interface, address, route, neighbor, and traffic control operations.
/// This is a zero-sized type with no additional state.
#[derive(Debug, Default, Clone, Copy)]
pub struct Route;

impl private::Sealed for Route {}

impl ProtocolState for Route {
    const PROTOCOL: Protocol = Protocol::Route;
}

/// Socket diagnostics protocol state.
///
/// Used for querying socket information (TCP, UDP, Unix, etc.).
/// This is a zero-sized type with no additional state.
#[derive(Debug, Default, Clone, Copy)]
pub struct SockDiag;

impl private::Sealed for SockDiag {}

impl ProtocolState for SockDiag {
    const PROTOCOL: Protocol = Protocol::SockDiag;
}

/// Generic netlink protocol state.
///
/// Used for family-based protocols like WireGuard and MACsec.
/// Contains a cache of resolved family IDs for efficient lookups.
pub struct Generic {
    /// Cache of family name -> family info mappings.
    pub(crate) cache: RwLock<HashMap<String, FamilyInfo>>,
}

impl Default for Generic {
    fn default() -> Self {
        Self {
            cache: RwLock::new(HashMap::new()),
        }
    }
}

impl std::fmt::Debug for Generic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Generic")
            .field(
                "cache_size",
                &self.cache.read().map(|c| c.len()).unwrap_or(0),
            )
            .finish()
    }
}

impl private::Sealed for Generic {}

impl ProtocolState for Generic {
    const PROTOCOL: Protocol = Protocol::Generic;
}

/// WireGuard protocol state.
///
/// Used for WireGuard device configuration via Generic Netlink.
/// Contains the resolved WireGuard family ID.
#[derive(Debug, Default)]
pub struct Wireguard {
    /// Resolved WireGuard GENL family ID.
    pub(crate) family_id: u16,
}

impl private::Sealed for Wireguard {}

impl ProtocolState for Wireguard {
    const PROTOCOL: Protocol = Protocol::Generic;
}

/// Kobject uevent protocol state.
///
/// Used for receiving kernel object events (device hotplug, like udev).
/// This is a zero-sized type with no additional state.
///
/// Note: Does not implement `Default` because connections require
/// multicast group subscription. Use `Connection::<KobjectUevent>::new()`.
#[derive(Debug, Clone, Copy)]
pub struct KobjectUevent;

impl private::Sealed for KobjectUevent {}

impl ProtocolState for KobjectUevent {
    const PROTOCOL: Protocol = Protocol::KobjectUevent;
}

/// Connector protocol state.
///
/// Used for kernel connector events, primarily process events (fork/exec/exit).
/// This is a zero-sized type with no additional state.
///
/// Note: Does not implement `Default` because connections require
/// registration with the kernel. Use `Connection::<Connector>::new()`.
#[derive(Debug, Clone, Copy)]
pub struct Connector;

impl private::Sealed for Connector {}

impl ProtocolState for Connector {
    const PROTOCOL: Protocol = Protocol::Connector;
}

/// Netfilter protocol state.
///
/// Used for netfilter operations, primarily connection tracking (conntrack).
/// This is a zero-sized type with no additional state.
#[derive(Debug, Clone, Copy)]
pub struct Netfilter;

impl private::Sealed for Netfilter {}

impl ProtocolState for Netfilter {
    const PROTOCOL: Protocol = Protocol::Netfilter;
}

/// XFRM protocol state.
///
/// Used for IPsec Security Association (SA) and Security Policy (SP) management.
/// This is a zero-sized type with no additional state.
#[derive(Debug, Clone, Copy)]
pub struct Xfrm;

impl private::Sealed for Xfrm {}

impl ProtocolState for Xfrm {
    const PROTOCOL: Protocol = Protocol::Xfrm;
}

/// FIB lookup protocol state.
///
/// Used for performing FIB (Forwarding Information Base) route lookups.
/// This is a zero-sized type with no additional state.
#[derive(Debug, Clone, Copy)]
pub struct FibLookup;

impl private::Sealed for FibLookup {}

impl ProtocolState for FibLookup {
    const PROTOCOL: Protocol = Protocol::FibLookup;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn route_is_zero_sized() {
        assert_eq!(std::mem::size_of::<Route>(), 0);
    }

    #[test]
    fn sockdiag_is_zero_sized() {
        assert_eq!(std::mem::size_of::<SockDiag>(), 0);
    }

    #[test]
    fn generic_has_cache() {
        let g = Generic::default();
        assert!(g.cache.read().unwrap().is_empty());
    }

    #[test]
    fn protocol_constants() {
        assert_eq!(Route::PROTOCOL, Protocol::Route);
        assert_eq!(SockDiag::PROTOCOL, Protocol::SockDiag);
        assert_eq!(Generic::PROTOCOL, Protocol::Generic);
        assert_eq!(Wireguard::PROTOCOL, Protocol::Generic);
        assert_eq!(KobjectUevent::PROTOCOL, Protocol::KobjectUevent);
        assert_eq!(Connector::PROTOCOL, Protocol::Connector);
        assert_eq!(Netfilter::PROTOCOL, Protocol::Netfilter);
        assert_eq!(Xfrm::PROTOCOL, Protocol::Xfrm);
        assert_eq!(FibLookup::PROTOCOL, Protocol::FibLookup);
    }

    #[test]
    fn new_types_are_zero_sized() {
        assert_eq!(std::mem::size_of::<KobjectUevent>(), 0);
        assert_eq!(std::mem::size_of::<Connector>(), 0);
        assert_eq!(std::mem::size_of::<Netfilter>(), 0);
        assert_eq!(std::mem::size_of::<Xfrm>(), 0);
        assert_eq!(std::mem::size_of::<FibLookup>(), 0);
    }
}
