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
//! use nlink::netlink::{Connection, Protocol};
//!
//! #[tokio::main]
//! async fn main() -> nlink::netlink::Result<()> {
//!     let conn = Connection::new(Protocol::Route)?;
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
//! use nlink::netlink::{Connection, Protocol};
//!
//! let conn = Connection::new(Protocol::Route)?;
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
//! use nlink::netlink::{Connection, Protocol};
//! use nlink::netlink::namespace;
//!
//! // Connect to a named namespace (created via `ip netns add myns`)
//! let conn = namespace::connection_for("myns")?;
//! let links = conn.get_links().await?;
//!
//! // Or connect to a container's namespace
//! let conn = namespace::connection_for_pid(container_pid)?;
//! let links = conn.get_links().await?;
//!
//! // Or use a path directly
//! let conn = Connection::new_in_namespace_path(
//!     Protocol::Route,
//!     "/proc/1234/ns/net"
//! )?;
//! ```
//!
//! # Event Monitoring
//!
//! `EventStream` implements the `Stream` trait from `tokio-stream`:
//!
//! ```ignore
//! use nlink::netlink::events::{EventStream, NetworkEvent};
//! use tokio_stream::StreamExt;
//!
//! let mut stream = EventStream::builder()
//!     .links(true)
//!     .addresses(true)
//!     .build()?;
//!
//! // Use try_next() for familiar ? operator ergonomics
//! while let Some(event) = stream.try_next().await? {
//!     match event {
//!         NetworkEvent::NewLink(link) => println!("New link: {:?}", link.name),
//!         NetworkEvent::NewAddress(addr) => println!("New address: {:?}", addr.address),
//!         _ => {}
//!     }
//! }
//! ```
//!
//! # Multi-Namespace Event Monitoring
//!
//! Monitor events across multiple namespaces simultaneously:
//!
//! ```ignore
//! use nlink::netlink::events::{EventStream, MultiNamespaceEventStream};
//! use tokio_stream::StreamExt;
//!
//! let mut multi = MultiNamespaceEventStream::new();
//! multi.add("", EventStream::builder().all().build()?);
//! multi.add("ns1", EventStream::builder().namespace("ns1").all().build()?);
//!
//! while let Some(result) = multi.next().await {
//!     let ev = result?;
//!     println!("[{}] {:?}", ev.namespace, ev.event);
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
pub use netlink::{
    EventStream, EventStreamBuilder, MultiNamespaceEventStream, NamespacedEvent, NetworkEvent,
};

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
