//! Network event types for Route protocol monitoring.
//!
//! This module provides the [`NetworkEvent`] enum representing events
//! received from the kernel via RTNetlink multicast groups.
//!
//! # Example
//!
//! ```ignore
//! use nlink::netlink::{Connection, Route, RtnetlinkGroup, NetworkEvent};
//! use tokio_stream::StreamExt;
//!
//! let mut conn = Connection::<Route>::new()?;
//! conn.subscribe(&[RtnetlinkGroup::Link, RtnetlinkGroup::Tc])?;
//!
//! let mut events = conn.events();
//! while let Some(event) = events.next().await {
//!     match event? {
//!         NetworkEvent::NewLink(link) => {
//!             println!("New link: {}", link.name_or("?"));
//!         }
//!         NetworkEvent::DelLink(link) => {
//!             println!("Deleted link: {}", link.name_or("?"));
//!         }
//!         _ => {}
//!     }
//! }
//! ```

use super::messages::{AddressMessage, LinkMessage, NeighborMessage, RouteMessage, TcMessage};

/// Network events that can be received from the kernel.
///
/// These events are generated when network configuration changes occur.
/// Use [`Connection<Route>::subscribe`](super::Connection::subscribe) to select
/// which event types to receive, then use [`Connection::events`](super::Connection::events)
/// to get a stream of events.
#[derive(Debug, Clone)]
pub enum NetworkEvent {
    // Link events
    /// A new link was created or an existing link changed.
    NewLink(LinkMessage),
    /// A link was deleted.
    DelLink(LinkMessage),

    // Address events
    /// A new address was added.
    NewAddress(AddressMessage),
    /// An address was removed.
    DelAddress(AddressMessage),

    // Route events
    /// A new route was added.
    NewRoute(RouteMessage),
    /// A route was removed.
    DelRoute(RouteMessage),

    // Neighbor events
    /// A new neighbor entry was added.
    NewNeighbor(NeighborMessage),
    /// A neighbor entry was removed.
    DelNeighbor(NeighborMessage),

    // Traffic control events
    /// A new qdisc was added or changed.
    NewQdisc(TcMessage),
    /// A qdisc was deleted.
    DelQdisc(TcMessage),
    /// A new class was added or changed.
    NewClass(TcMessage),
    /// A class was deleted.
    DelClass(TcMessage),
    /// A new filter was added or changed.
    NewFilter(TcMessage),
    /// A filter was deleted.
    DelFilter(TcMessage),
    /// A new action was added or changed.
    NewAction(TcMessage),
    /// An action was deleted.
    DelAction(TcMessage),
}

impl NetworkEvent {
    /// Returns true if this is a "new" event (add or change).
    pub fn is_new(&self) -> bool {
        matches!(
            self,
            NetworkEvent::NewLink(_)
                | NetworkEvent::NewAddress(_)
                | NetworkEvent::NewRoute(_)
                | NetworkEvent::NewNeighbor(_)
                | NetworkEvent::NewQdisc(_)
                | NetworkEvent::NewClass(_)
                | NetworkEvent::NewFilter(_)
                | NetworkEvent::NewAction(_)
        )
    }

    /// Returns true if this is a "delete" event.
    pub fn is_del(&self) -> bool {
        !self.is_new()
    }

    /// Returns the interface index associated with this event, if any.
    pub fn ifindex(&self) -> Option<u32> {
        match self {
            NetworkEvent::NewLink(m) | NetworkEvent::DelLink(m) => Some(m.ifindex()),
            NetworkEvent::NewAddress(m) | NetworkEvent::DelAddress(m) => Some(m.ifindex()),
            NetworkEvent::NewNeighbor(m) | NetworkEvent::DelNeighbor(m) => Some(m.ifindex()),
            NetworkEvent::NewQdisc(m)
            | NetworkEvent::DelQdisc(m)
            | NetworkEvent::NewClass(m)
            | NetworkEvent::DelClass(m)
            | NetworkEvent::NewFilter(m)
            | NetworkEvent::DelFilter(m)
            | NetworkEvent::NewAction(m)
            | NetworkEvent::DelAction(m) => Some(m.ifindex()),
            NetworkEvent::NewRoute(_) | NetworkEvent::DelRoute(_) => None,
        }
    }

    /// Returns "new" or "del" based on the event type.
    ///
    /// Useful for display/logging purposes.
    pub fn action(&self) -> &'static str {
        if self.is_new() { "new" } else { "del" }
    }

    /// Returns the inner LinkMessage if this is a link event.
    pub fn as_link(&self) -> Option<&LinkMessage> {
        match self {
            NetworkEvent::NewLink(m) | NetworkEvent::DelLink(m) => Some(m),
            _ => None,
        }
    }

    /// Consumes self and returns the inner LinkMessage if this is a link event.
    pub fn into_link(self) -> Option<LinkMessage> {
        match self {
            NetworkEvent::NewLink(m) | NetworkEvent::DelLink(m) => Some(m),
            _ => None,
        }
    }

    /// Returns the inner AddressMessage if this is an address event.
    pub fn as_address(&self) -> Option<&AddressMessage> {
        match self {
            NetworkEvent::NewAddress(m) | NetworkEvent::DelAddress(m) => Some(m),
            _ => None,
        }
    }

    /// Consumes self and returns the inner AddressMessage if this is an address event.
    pub fn into_address(self) -> Option<AddressMessage> {
        match self {
            NetworkEvent::NewAddress(m) | NetworkEvent::DelAddress(m) => Some(m),
            _ => None,
        }
    }

    /// Returns the inner RouteMessage if this is a route event.
    pub fn as_route(&self) -> Option<&RouteMessage> {
        match self {
            NetworkEvent::NewRoute(m) | NetworkEvent::DelRoute(m) => Some(m),
            _ => None,
        }
    }

    /// Consumes self and returns the inner RouteMessage if this is a route event.
    pub fn into_route(self) -> Option<RouteMessage> {
        match self {
            NetworkEvent::NewRoute(m) | NetworkEvent::DelRoute(m) => Some(m),
            _ => None,
        }
    }

    /// Returns the inner NeighborMessage if this is a neighbor event.
    pub fn as_neighbor(&self) -> Option<&NeighborMessage> {
        match self {
            NetworkEvent::NewNeighbor(m) | NetworkEvent::DelNeighbor(m) => Some(m),
            _ => None,
        }
    }

    /// Consumes self and returns the inner NeighborMessage if this is a neighbor event.
    pub fn into_neighbor(self) -> Option<NeighborMessage> {
        match self {
            NetworkEvent::NewNeighbor(m) | NetworkEvent::DelNeighbor(m) => Some(m),
            _ => None,
        }
    }

    /// Returns the inner TcMessage if this is a TC event (qdisc, class, filter, or action).
    pub fn as_tc(&self) -> Option<&TcMessage> {
        match self {
            NetworkEvent::NewQdisc(m)
            | NetworkEvent::DelQdisc(m)
            | NetworkEvent::NewClass(m)
            | NetworkEvent::DelClass(m)
            | NetworkEvent::NewFilter(m)
            | NetworkEvent::DelFilter(m)
            | NetworkEvent::NewAction(m)
            | NetworkEvent::DelAction(m) => Some(m),
            _ => None,
        }
    }

    /// Consumes self and returns the inner TcMessage if this is a TC event.
    pub fn into_tc(self) -> Option<TcMessage> {
        match self {
            NetworkEvent::NewQdisc(m)
            | NetworkEvent::DelQdisc(m)
            | NetworkEvent::NewClass(m)
            | NetworkEvent::DelClass(m)
            | NetworkEvent::NewFilter(m)
            | NetworkEvent::DelFilter(m)
            | NetworkEvent::NewAction(m)
            | NetworkEvent::DelAction(m) => Some(m),
            _ => None,
        }
    }
}
