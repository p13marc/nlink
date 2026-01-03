//! Strongly-typed netlink message structures.
//!
//! This module provides high-level message types that automatically
//! parse and serialize netlink attributes.
//!
//! # Example
//!
//! ```ignore
//! use nlink::netlink::messages::AddressMessage;
//! use nlink::netlink::parse::FromNetlink;
//!
//! // Parse from raw netlink data
//! let msg = AddressMessage::from_bytes(&data)?;
//! println!("Address: {:?}", msg.address);
//! println!("Interface: {}", msg.header.ifa_index);
//! ```

mod address;
mod link;
mod neighbor;
mod nsid;
mod route;
mod rule;
mod tc;

pub use address::*;
pub use link::*;
pub use neighbor::*;
pub use nsid::*;
pub use route::*;
pub use rule::*;
pub use tc::*;
