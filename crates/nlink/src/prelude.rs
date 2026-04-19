//! Convenience re-exports for common types.
//!
//! # Usage
//!
//! ```ignore
//! use nlink::prelude::*;
//! ```

pub use crate::{
    FilterPriority, Generic, NetworkEvent, RtnetlinkGroup, TcHandle,
    netlink::{
        Connection, Error, Result, Route,
        messages::LinkMessage,
        route::{Ipv4Route, Ipv6Route},
    },
    util::{Bytes, Percent, Rate},
};
