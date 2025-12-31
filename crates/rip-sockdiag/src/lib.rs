//! Socket diagnostics library for Linux.
//!
//! This crate provides a strongly-typed, async API for querying socket information
//! via the NETLINK_SOCK_DIAG protocol. It is the foundation for implementing
//! tools like `ss` (socket statistics).
//!
//! # Features
//!
//! - Query TCP, UDP, Unix, and other socket types
//! - Filter by state, port, address, and other criteria
//! - Retrieve detailed socket information (memory, TCP info, etc.)
//! - Async/await support with Tokio
//!
//! # Example
//!
//! ```ignore
//! use rip_sockdiag::{SockDiag, SocketFilter, TcpState};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let diag = SockDiag::new().await?;
//!
//!     // Query all TCP sockets in LISTEN state
//!     let filter = SocketFilter::tcp()
//!         .states(&[TcpState::Listen])
//!         .build();
//!
//!     let sockets = diag.query(&filter).await?;
//!     for sock in sockets {
//!         println!("{:?}", sock);
//!     }
//!
//!     Ok(())
//! }
//! ```
//!
//! # Socket Types
//!
//! The library supports querying multiple socket families:
//!
//! - [`InetSocket`] - TCP/UDP over IPv4 and IPv6
//! - [`UnixSocket`] - Unix domain sockets
//! - [`NetlinkSocket`] - Netlink protocol sockets
//! - [`PacketSocket`] - Raw packet sockets
//!
//! Each socket type has its own query method and response structure.

pub mod connection;
pub mod error;
pub mod filter;
pub mod socket;
pub mod types;

pub use connection::SockDiag;
pub use error::{Error, Result};
pub use filter::{InetFilter, SocketFilter, UnixFilter};
pub use socket::{InetSocket, NetlinkSocket, PacketSocket, SocketInfo, UnixSocket};
pub use types::{AddressFamily, InetExtension, Protocol, SocketState, TcpInfo, TcpState, UnixShow};
