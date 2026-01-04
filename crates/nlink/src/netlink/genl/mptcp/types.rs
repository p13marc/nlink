//! MPTCP types and builders.

use std::net::{IpAddr, Ipv4Addr};

use crate::netlink::types::mptcp::mptcp_pm_flags;

/// MPTCP endpoint flags.
///
/// These flags control how an endpoint is used for MPTCP connections.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MptcpFlags {
    /// Announce this endpoint to peers via ADD_ADDR.
    pub signal: bool,
    /// Use this endpoint for creating new subflows.
    pub subflow: bool,
    /// Mark as backup path (lower priority).
    pub backup: bool,
    /// Create subflows to all peer addresses (fullmesh).
    pub fullmesh: bool,
}

impl MptcpFlags {
    /// Create flags from a raw u32 value.
    pub fn from_raw(flags: u32) -> Self {
        Self {
            signal: flags & mptcp_pm_flags::SIGNAL != 0,
            subflow: flags & mptcp_pm_flags::SUBFLOW != 0,
            backup: flags & mptcp_pm_flags::BACKUP != 0,
            fullmesh: flags & mptcp_pm_flags::FULLMESH != 0,
        }
    }

    /// Convert flags to raw u32 value.
    pub fn to_raw(self) -> u32 {
        let mut flags = 0u32;
        if self.signal {
            flags |= mptcp_pm_flags::SIGNAL;
        }
        if self.subflow {
            flags |= mptcp_pm_flags::SUBFLOW;
        }
        if self.backup {
            flags |= mptcp_pm_flags::BACKUP;
        }
        if self.fullmesh {
            flags |= mptcp_pm_flags::FULLMESH;
        }
        flags
    }

    /// Check if any flags are set.
    pub fn is_empty(&self) -> bool {
        !self.signal && !self.subflow && !self.backup && !self.fullmesh
    }
}

/// Parsed MPTCP endpoint information.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MptcpEndpoint {
    /// Endpoint ID (0-255).
    pub id: u8,
    /// IP address of the endpoint.
    pub address: IpAddr,
    /// Optional port number.
    pub port: Option<u16>,
    /// Optional interface index.
    pub ifindex: Option<u32>,
    /// Endpoint flags.
    pub flags: MptcpFlags,
}

impl Default for MptcpEndpoint {
    fn default() -> Self {
        Self {
            id: 0,
            address: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            port: None,
            ifindex: None,
            flags: MptcpFlags::default(),
        }
    }
}

impl MptcpEndpoint {
    /// Check if this is a signal endpoint.
    pub fn is_signal(&self) -> bool {
        self.flags.signal
    }

    /// Check if this is a subflow endpoint.
    pub fn is_subflow(&self) -> bool {
        self.flags.subflow
    }

    /// Check if this is a backup endpoint.
    pub fn is_backup(&self) -> bool {
        self.flags.backup
    }

    /// Check if this is a fullmesh endpoint.
    pub fn is_fullmesh(&self) -> bool {
        self.flags.fullmesh
    }
}

/// Builder for MPTCP endpoint configuration.
#[derive(Debug, Clone)]
pub struct MptcpEndpointBuilder {
    /// Endpoint ID (optional, kernel assigns if not set).
    pub(crate) id: Option<u8>,
    /// IP address of the endpoint.
    pub(crate) address: IpAddr,
    /// Optional port number.
    pub(crate) port: Option<u16>,
    /// Device name (resolved to ifindex).
    pub(crate) dev: Option<String>,
    /// Interface index (direct).
    pub(crate) ifindex: Option<u32>,
    /// Endpoint flags.
    pub(crate) flags: MptcpFlags,
}

impl MptcpEndpointBuilder {
    /// Create a new endpoint builder with the given address.
    ///
    /// # Example
    ///
    /// ```
    /// use nlink::netlink::genl::mptcp::MptcpEndpointBuilder;
    /// use std::net::Ipv4Addr;
    ///
    /// let builder = MptcpEndpointBuilder::new(Ipv4Addr::new(192, 168, 1, 1).into())
    ///     .id(1)
    ///     .subflow()
    ///     .signal();
    /// ```
    pub fn new(address: IpAddr) -> Self {
        Self {
            id: None,
            address,
            port: None,
            dev: None,
            ifindex: None,
            flags: MptcpFlags::default(),
        }
    }

    /// Set the endpoint ID (0-255).
    ///
    /// If not set, the kernel will assign an ID automatically.
    pub fn id(mut self, id: u8) -> Self {
        self.id = Some(id);
        self
    }

    /// Set the port number.
    pub fn port(mut self, port: u16) -> Self {
        self.port = Some(port);
        self
    }

    /// Set the device by name.
    ///
    /// The device name will be resolved to an interface index.
    pub fn dev(mut self, dev: impl Into<String>) -> Self {
        self.dev = Some(dev.into());
        self
    }

    /// Set the interface index directly.
    pub fn ifindex(mut self, ifindex: u32) -> Self {
        self.ifindex = Some(ifindex);
        self
    }

    /// Set the signal flag (announce to peers).
    pub fn signal(mut self) -> Self {
        self.flags.signal = true;
        self
    }

    /// Set the subflow flag (use for new subflows).
    pub fn subflow(mut self) -> Self {
        self.flags.subflow = true;
        self
    }

    /// Set the backup flag (lower priority path).
    pub fn backup(mut self) -> Self {
        self.flags.backup = true;
        self
    }

    /// Set the fullmesh flag (connect to all peer addresses).
    pub fn fullmesh(mut self) -> Self {
        self.flags.fullmesh = true;
        self
    }

    /// Set all flags at once.
    pub fn flags(mut self, flags: MptcpFlags) -> Self {
        self.flags = flags;
        self
    }
}

/// MPTCP limits configuration.
///
/// These limits control the maximum number of subflows and addresses
/// that can be used per MPTCP connection.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MptcpLimits {
    /// Maximum subflows per connection.
    pub subflows: Option<u32>,
    /// Maximum additional addresses to accept from peers.
    pub add_addr_accepted: Option<u32>,
}

impl MptcpLimits {
    /// Create a new limits builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set maximum subflows per connection.
    pub fn subflows(mut self, max: u32) -> Self {
        self.subflows = Some(max);
        self
    }

    /// Set maximum additional addresses to accept from peers.
    pub fn add_addr_accepted(mut self, max: u32) -> Self {
        self.add_addr_accepted = Some(max);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_flags_from_raw() {
        let flags = MptcpFlags::from_raw(mptcp_pm_flags::SIGNAL | mptcp_pm_flags::BACKUP);
        assert!(flags.signal);
        assert!(!flags.subflow);
        assert!(flags.backup);
        assert!(!flags.fullmesh);
    }

    #[test]
    fn test_flags_to_raw() {
        let flags = MptcpFlags {
            signal: true,
            subflow: true,
            backup: false,
            fullmesh: false,
        };
        assert_eq!(
            flags.to_raw(),
            mptcp_pm_flags::SIGNAL | mptcp_pm_flags::SUBFLOW
        );
    }

    #[test]
    fn test_flags_roundtrip() {
        let original = MptcpFlags {
            signal: true,
            subflow: false,
            backup: true,
            fullmesh: true,
        };
        let raw = original.to_raw();
        let restored = MptcpFlags::from_raw(raw);
        assert_eq!(original, restored);
    }

    #[test]
    fn test_endpoint_builder() {
        let builder = MptcpEndpointBuilder::new(Ipv4Addr::new(192, 168, 1, 1).into())
            .id(1)
            .port(8080)
            .subflow()
            .signal();

        assert_eq!(builder.id, Some(1));
        assert_eq!(builder.address, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
        assert_eq!(builder.port, Some(8080));
        assert!(builder.flags.signal);
        assert!(builder.flags.subflow);
        assert!(!builder.flags.backup);
    }

    #[test]
    fn test_endpoint_builder_ipv6() {
        let addr: std::net::Ipv6Addr = "2001:db8::1".parse().unwrap();
        let builder = MptcpEndpointBuilder::new(addr.into())
            .id(2)
            .backup()
            .fullmesh();

        assert_eq!(builder.id, Some(2));
        assert!(matches!(builder.address, IpAddr::V6(_)));
        assert!(!builder.flags.signal);
        assert!(builder.flags.backup);
        assert!(builder.flags.fullmesh);
    }

    #[test]
    fn test_limits_builder() {
        let limits = MptcpLimits::new().subflows(4).add_addr_accepted(8);

        assert_eq!(limits.subflows, Some(4));
        assert_eq!(limits.add_addr_accepted, Some(8));
    }

    #[test]
    fn test_endpoint_helpers() {
        let ep = MptcpEndpoint {
            id: 1,
            address: Ipv4Addr::new(10, 0, 0, 1).into(),
            port: None,
            ifindex: Some(2),
            flags: MptcpFlags {
                signal: true,
                subflow: false,
                backup: true,
                fullmesh: false,
            },
        };

        assert!(ep.is_signal());
        assert!(!ep.is_subflow());
        assert!(ep.is_backup());
        assert!(!ep.is_fullmesh());
    }
}
