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
//!     for link in links {
//!         println!("{}: {}", link.index, link.name.unwrap_or_default());
//!     }
//!
//!     Ok(())
//! }
//! ```
//!
//! # Event Monitoring
//!
//! ```ignore
//! use nlink::netlink::events::{EventStream, NetworkEvent};
//!
//! let mut stream = EventStream::builder()
//!     .links(true)
//!     .addresses(true)
//!     .build()?;
//!
//! while let Some(event) = stream.next().await? {
//!     match event {
//!         NetworkEvent::NewLink(link) => println!("New link: {:?}", link.name),
//!         NetworkEvent::NewAddress(addr) => println!("New address: {:?}", addr.address),
//!         _ => {}
//!     }
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
