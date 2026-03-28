//! Convenience re-exports for common types.
//!
//! # Usage
//!
//! ```ignore
//! use nlink::prelude::*;
//! ```

pub use crate::netlink::messages::LinkMessage;
pub use crate::netlink::{Connection, Error, Result, Route};
pub use crate::{Generic, NetworkEvent, RtnetlinkGroup};
