//! Socket diagnostics library for Linux.
//!
//! This module provides a strongly-typed, async API for querying socket information
//! via the NETLINK_SOCK_DIAG protocol. It is the foundation for implementing
//! tools like `ss` (socket statistics).
//!
//! # Features
//!
//! - Query TCP, UDP, Unix, and other socket types
//! - Filter by state, port, address, and other criteria
//! - Retrieve detailed socket information (memory, TCP info, etc.)
//! - Async/await support with Tokio
//! - Namespace support via `Connection::new_in_namespace_path()`
//!
//! # Example
//!
//! ```ignore
//! use nlink::netlink::{Connection, SockDiag};
//! use nlink::sockdiag::{SocketFilter, TcpState};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let conn = Connection::<SockDiag>::new()?;
//!
//!     // Query all TCP sockets in LISTEN state
//!     let filter = SocketFilter::tcp()
//!         .states(&[TcpState::Listen])
//!         .build();
//!
//!     let sockets = conn.query(&filter).await?;
//!     for sock in sockets {
//!         println!("{:?}", sock);
//!     }
//!
//!     Ok(())
//! }
//! ```
//!
//! # Namespace Support
//!
//! Query sockets in other namespaces:
//!
//! ```ignore
//! use nlink::netlink::{Connection, SockDiag, namespace};
//!
//! // Query sockets in a named namespace
//! let conn: Connection<SockDiag> = namespace::connection_for("myns")?;
//! let sockets = conn.query_tcp().await?;
//!
//! // Or by PID
//! let conn: Connection<SockDiag> = namespace::connection_for_pid(1234)?;
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

pub mod error;
pub mod filter;
pub mod socket;
pub mod types;

pub use error::{Error, Result};
pub use filter::{InetFilter, SocketFilter, UnixFilter};
pub use socket::{InetSocket, NetlinkSocket, PacketSocket, SocketInfo, UnixSocket};
pub use types::{AddressFamily, InetExtension, Protocol, SocketState, TcpInfo, TcpState, UnixShow};
