//! Async netlink library for Linux network configuration.
//!
//! This crate provides a complete netlink implementation for programmatic
//! network management on Linux. It supports RTNetlink (routing), traffic
//! control, socket diagnostics, and TUN/TAP device management.
//!
//! # Features
//!
//! - `sockdiag` - Socket diagnostics via NETLINK_SOCK_DIAG
//! - `tuntap` - TUN/TAP device management
//! - `tuntap-async` - Async TUN/TAP support (implies `tuntap`)
//! - `tc` - Traffic control utilities
//! - `output` - JSON/text output formatting
//! - `full` - All features enabled
//!
//! # Example
//!
//! ```ignore
//! use nlink::netlink::{Connection, Route};
//!
//! #[tokio::main]
//! async fn main() -> nlink::netlink::Result<()> {
//!     let conn = Connection::<Route>::new()?;
//!
//!     // Query interfaces
//!     let links = conn.get_links().await?;
//!     for link in &links {
//!         // Use name_or() helper for cleaner code
//!         println!("{}: {}", link.ifindex(), link.name_or("?"));
//!     }
//!
//!     // Build ifindex -> name map for resolving routes/addresses
//!     let names = conn.get_interface_names().await?;
//!
//!     Ok(())
//! }
//! ```
//!
//! # Link State Management
//!
//! ```ignore
//! use nlink::netlink::{Connection, Route};
//!
//! let conn = Connection::<Route>::new()?;
//!
//! // Bring an interface up
//! conn.set_link_up("eth0").await?;
//!
//! // Bring it down
//! conn.set_link_down("eth0").await?;
//!
//! // Set MTU
//! conn.set_link_mtu("eth0", 9000).await?;
//! ```
//!
//! # Network Namespace Support
//!
//! Operations can be performed in specific network namespaces:
//!
//! ```ignore
//! use nlink::netlink::{Connection, Route, Generic};
//! use nlink::netlink::namespace;
//!
//! // Connect to a named namespace (created via `ip netns add myns`)
//! // Functions are generic over protocol type
//! let conn: Connection<Route> = namespace::connection_for("myns")?;
//! let links = conn.get_links().await?;
//!
//! // Or connect to a container's namespace
//! let conn: Connection<Route> = namespace::connection_for_pid(container_pid)?;
//! let links = conn.get_links().await?;
//!
//! // Or use a path directly
//! let conn: Connection<Route> = namespace::connection_for_path("/proc/1234/ns/net")?;
//!
//! // Generic connections work too (e.g., for WireGuard in a namespace)
//! let genl: Connection<Generic> = namespace::connection_for("myns")?;
//! ```
//!
//! # Event Monitoring
//!
//! Use `Connection::subscribe()` to select event types, then `events()` to get a stream:
//!
//! ```ignore
//! use nlink::netlink::{Connection, Route, RtnetlinkGroup, NetworkEvent};
//! use tokio_stream::StreamExt;
//!
//! let mut conn = Connection::<Route>::new()?;
//! conn.subscribe(&[RtnetlinkGroup::Link, RtnetlinkGroup::Ipv4Addr])?;
//!
//! let mut events = conn.events();
//! while let Some(event) = events.next().await {
//!     match event? {
//!         NetworkEvent::NewLink(link) => println!("New link: {:?}", link.name),
//!         NetworkEvent::NewAddress(addr) => println!("New address: {:?}", addr.address),
//!         _ => {}
//!     }
//! }
//! ```
//!
//! # Multi-Namespace Event Monitoring
//!
//! Use `tokio_stream::StreamMap` to monitor multiple namespaces:
//!
//! ```ignore
//! use nlink::netlink::{Connection, Route, RtnetlinkGroup};
//! use tokio_stream::{StreamExt, StreamMap};
//!
//! let mut streams = StreamMap::new();
//!
//! let mut conn1 = Connection::<Route>::new()?;
//! conn1.subscribe_all()?;
//! streams.insert("default", conn1.into_events());
//!
//! let mut conn2 = Connection::<Route>::new_in_namespace("ns1")?;
//! conn2.subscribe_all()?;
//! streams.insert("ns1", conn2.into_events());
//!
//! while let Some((ns, event)) = streams.next().await {
//!     println!("[{}] {:?}", ns, event?);
//! }
//! ```

// Core modules (always available)
pub mod netlink;
pub mod util;

// Feature-gated modules
#[cfg(feature = "sockdiag")]
pub mod sockdiag;

#[cfg(feature = "tuntap")]
pub mod tuntap;

#[cfg(feature = "tc")]
pub mod tc;

#[cfg(feature = "output")]
pub mod output;

// Re-export common types at crate root for convenience
pub use netlink::{Connection, Error, Protocol, Result};

// Protocol state types
pub use netlink::{Generic, Route};

// Event types
pub use netlink::NetworkEvent;

// Stream-based event API
pub use netlink::{EventSource, EventSubscription, OwnedEventStream};

// Route protocol multicast groups
pub use netlink::RtnetlinkGroup;

// Namespace types
pub use netlink::NamespaceSpec;

// Message types (commonly used)
pub use netlink::messages::{
    AddressMessage,
    // Type aliases for TcMessage
    ClassMessage,
    FilterMessage,
    LinkMessage,
    NeighborMessage,
    QdiscMessage,
    RouteMessage,
    RuleMessage,
    TcMessage,
};

// FDB types
pub use netlink::fdb::{FdbEntry, FdbEntryBuilder};

// Bridge VLAN types
pub use netlink::bridge_vlan::{BridgeVlanBuilder, BridgeVlanEntry, BridgeVlanFlags};
