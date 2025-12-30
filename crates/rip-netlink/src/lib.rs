//! Async netlink protocol implementation for Linux.
//!
//! This crate provides a complete netlink implementation from scratch,
//! supporting RTNetlink (routing), traffic control, and other subsystems.

pub mod attr;
mod builder;
pub mod connection;
mod error;
pub mod message;
mod socket;
pub mod types;

pub use attr::{AttrIter, NlAttr};
pub use builder::{MessageBuilder, NestToken};
pub use connection::Connection;
pub use error::{Error, Result};
pub use message::{MessageIter, NLMSG_HDRLEN, NlMsgHdr, NlMsgType};
pub use socket::{NetlinkSocket, Protocol, rtnetlink_groups};
