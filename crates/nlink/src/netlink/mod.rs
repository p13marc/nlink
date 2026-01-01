//! Async netlink protocol implementation for Linux.
//!
//! This crate provides a complete netlink implementation from scratch,
//! supporting RTNetlink (routing), traffic control, and other subsystems.
//!
//! # Strongly-Typed API
//!
//! The `parse` module provides traits for zero-copy parsing and serialization:
//!
//! ```ignore
//! use rip_netlink::parse::{FromNetlink, ToNetlink};
//! use rip_netlink::messages::AddressMessage;
//!
//! // Parse a netlink message
//! let msg = AddressMessage::from_bytes(&data)?;
//!
//! // Serialize back to bytes
//! let bytes = msg.to_bytes()?;
//! ```
//!
//! # Event Monitoring
//!
//! The `events` module provides a high-level API for monitoring network changes:
//!
//! ```ignore
//! use rip_netlink::events::{EventStream, NetworkEvent};
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
//!
//! # Traffic Control (TC)
//!
//! The `tc` module provides typed configuration for qdiscs:
//!
//! ```ignore
//! use rip_netlink::tc::NetemConfig;
//! use std::time::Duration;
//!
//! // Add network emulation with delay and packet loss
//! let netem = NetemConfig::new()
//!     .delay(Duration::from_millis(100))
//!     .jitter(Duration::from_millis(10))
//!     .loss(1.0)  // 1% packet loss
//!     .build();
//!
//! conn.add_qdisc("eth0", netem).await?;
//!
//! // Update the configuration
//! let updated = NetemConfig::new()
//!     .delay(Duration::from_millis(50))
//!     .build();
//! conn.change_qdisc("eth0", "root", updated).await?;
//!
//! // Delete the qdisc
//! conn.del_qdisc("eth0", "root").await?;
//! ```

pub mod attr;
mod builder;
pub mod connection;
mod error;
pub mod events;
#[cfg(test)]
mod fixtures;
pub mod message;
pub mod messages;
pub mod namespace;
pub mod namespace_events;
#[cfg(feature = "namespace_watcher")]
pub mod namespace_watcher;
pub mod parse;
mod socket;
pub mod stats;
pub mod tc;
pub mod tc_options;
pub mod types;

pub use attr::{AttrIter, NlAttr};
pub use builder::{MessageBuilder, NestToken};
pub use connection::Connection;
pub use error::{Error, Result};
pub use message::{MessageIter, NLMSG_HDRLEN, NlMsgHdr, NlMsgType};
pub use namespace_events::{NamespaceEventSubscriber, NamespaceNetlinkEvent};
#[cfg(feature = "namespace_watcher")]
pub use namespace_watcher::{
    NamespaceEvent, NamespaceEventStream, NamespaceWatcher, NamespaceWatcherConfig,
};
pub use parse::{FromNetlink, ToNetlink};
pub use socket::{NetlinkSocket, Protocol, rtnetlink_groups};
