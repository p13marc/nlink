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

pub mod attr;
mod builder;
pub mod connection;
mod error;
pub mod message;
pub mod messages;
pub mod parse;
mod socket;
pub mod types;

pub use attr::{AttrIter, NlAttr};
pub use builder::{MessageBuilder, NestToken};
pub use connection::Connection;
pub use error::{Error, Result};
pub use message::{MessageIter, NLMSG_HDRLEN, NlMsgHdr, NlMsgType};
pub use parse::{FromNetlink, ToNetlink};
pub use socket::{NetlinkSocket, Protocol, rtnetlink_groups};
