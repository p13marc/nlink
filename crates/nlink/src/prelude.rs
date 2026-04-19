//! Convenience re-exports for common types.
//!
//! # Usage
//!
//! ```ignore
//! use nlink::prelude::*;
//! ```

pub use crate::{
    Generic, NetworkEvent, RtnetlinkGroup,
    netlink::{
        Connection, Error, Result, Route,
        messages::LinkMessage,
        route::{Ipv4Route, Ipv6Route},
    },
    util::{Bytes, Percent, Rate},
};
