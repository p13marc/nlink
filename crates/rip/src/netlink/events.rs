//! High-level event stream API for network monitoring.
//!
//! This module provides an ergonomic, strongly-typed interface for monitoring
//! network changes including interface, address, route, neighbor, and TC events.
//!
//! # Example
//!
//! ```ignore
//! use rip_netlink::events::{EventStream, NetworkEvent};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let mut stream = EventStream::builder()
//!         .links(true)
//!         .addresses(true)
//!         .routes(true)
//!         .build()?;
//!
//!     while let Some(event) = stream.next().await? {
//!         match event {
//!             NetworkEvent::NewLink(link) => {
//!                 println!("New link: {}", link.name.as_deref().unwrap_or("?"));
//!             }
//!             NetworkEvent::DelLink(link) => {
//!                 println!("Deleted link: {}", link.name.as_deref().unwrap_or("?"));
//!             }
//!             NetworkEvent::NewAddress(addr) => {
//!                 println!("New address: {:?}", addr.address);
//!             }
//!             _ => {}
//!         }
//!     }
//!     Ok(())
//! }
//! ```

use super::connection::Connection;
use super::message::{MessageIter, NlMsgType};
use super::messages::{AddressMessage, LinkMessage, NeighborMessage, RouteMessage, TcMessage};
use super::parse::FromNetlink;
use super::socket::rtnetlink_groups::*;
use super::{Protocol, Result};

/// Network events that can be received from the kernel.
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
    pub fn ifindex(&self) -> Option<i32> {
        match self {
            NetworkEvent::NewLink(m) | NetworkEvent::DelLink(m) => Some(m.ifindex()),
            NetworkEvent::NewAddress(m) | NetworkEvent::DelAddress(m) => Some(m.ifindex() as i32),
            NetworkEvent::NewNeighbor(m) | NetworkEvent::DelNeighbor(m) => Some(m.ifindex() as i32),
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
}

/// Builder for configuring an event stream.
#[derive(Debug, Default)]
pub struct EventStreamBuilder {
    links: bool,
    addresses_v4: bool,
    addresses_v6: bool,
    routes_v4: bool,
    routes_v6: bool,
    neighbors: bool,
    tc: bool,
}

impl EventStreamBuilder {
    /// Create a new builder with no subscriptions.
    pub fn new() -> Self {
        Self::default()
    }

    /// Subscribe to link (interface) events.
    pub fn links(mut self, enabled: bool) -> Self {
        self.links = enabled;
        self
    }

    /// Subscribe to IPv4 address events.
    pub fn addresses_v4(mut self, enabled: bool) -> Self {
        self.addresses_v4 = enabled;
        self
    }

    /// Subscribe to IPv6 address events.
    pub fn addresses_v6(mut self, enabled: bool) -> Self {
        self.addresses_v6 = enabled;
        self
    }

    /// Subscribe to both IPv4 and IPv6 address events.
    pub fn addresses(mut self, enabled: bool) -> Self {
        self.addresses_v4 = enabled;
        self.addresses_v6 = enabled;
        self
    }

    /// Subscribe to IPv4 route events.
    pub fn routes_v4(mut self, enabled: bool) -> Self {
        self.routes_v4 = enabled;
        self
    }

    /// Subscribe to IPv6 route events.
    pub fn routes_v6(mut self, enabled: bool) -> Self {
        self.routes_v6 = enabled;
        self
    }

    /// Subscribe to both IPv4 and IPv6 route events.
    pub fn routes(mut self, enabled: bool) -> Self {
        self.routes_v4 = enabled;
        self.routes_v6 = enabled;
        self
    }

    /// Subscribe to neighbor (ARP/NDP) events.
    pub fn neighbors(mut self, enabled: bool) -> Self {
        self.neighbors = enabled;
        self
    }

    /// Subscribe to traffic control events (qdiscs, classes, filters).
    pub fn tc(mut self, enabled: bool) -> Self {
        self.tc = enabled;
        self
    }

    /// Subscribe to all event types.
    pub fn all(self) -> Self {
        self.links(true)
            .addresses(true)
            .routes(true)
            .neighbors(true)
            .tc(true)
    }

    /// Build the event stream.
    pub fn build(self) -> Result<EventStream> {
        let mut conn = Connection::new(Protocol::Route)?;

        if self.links {
            conn.subscribe(RTNLGRP_LINK)?;
        }
        if self.addresses_v4 {
            conn.subscribe(RTNLGRP_IPV4_IFADDR)?;
        }
        if self.addresses_v6 {
            conn.subscribe(RTNLGRP_IPV6_IFADDR)?;
        }
        if self.routes_v4 {
            conn.subscribe(RTNLGRP_IPV4_ROUTE)?;
        }
        if self.routes_v6 {
            conn.subscribe(RTNLGRP_IPV6_ROUTE)?;
        }
        if self.neighbors {
            conn.subscribe(RTNLGRP_NEIGH)?;
        }
        if self.tc {
            conn.subscribe(RTNLGRP_TC)?;
        }

        Ok(EventStream {
            conn,
            buffer: Vec::new(),
            pending_events: Vec::new(),
        })
    }
}

/// A stream of network events.
///
/// Use [`EventStream::builder()`] to configure which events to receive.
pub struct EventStream {
    conn: Connection,
    buffer: Vec<u8>,
    pending_events: Vec<NetworkEvent>,
}

impl EventStream {
    /// Create a builder for configuring the event stream.
    pub fn builder() -> EventStreamBuilder {
        EventStreamBuilder::new()
    }

    /// Receive the next event.
    ///
    /// This method blocks until an event is received. Returns `None` if
    /// the connection is closed.
    pub async fn next(&mut self) -> Result<Option<NetworkEvent>> {
        // Return any pending events first
        if let Some(event) = self.pending_events.pop() {
            return Ok(Some(event));
        }

        // Receive new data
        self.buffer = self.conn.recv_event().await?;

        // Parse all messages in the buffer
        for result in MessageIter::new(&self.buffer) {
            let (header, payload) = result?;

            if let Some(event) = parse_event(header.nlmsg_type, payload) {
                self.pending_events.push(event);
            }
        }

        // Return the first event (events are collected in reverse order)
        self.pending_events.reverse();
        Ok(self.pending_events.pop())
    }

    /// Get a reference to the underlying connection.
    pub fn connection(&self) -> &Connection {
        &self.conn
    }

    /// Get a mutable reference to the underlying connection.
    pub fn connection_mut(&mut self) -> &mut Connection {
        &mut self.conn
    }
}

/// Parse a netlink message into a network event.
fn parse_event(msg_type: u16, payload: &[u8]) -> Option<NetworkEvent> {
    match msg_type {
        // Link events
        t if t == NlMsgType::RTM_NEWLINK => LinkMessage::from_bytes(payload)
            .ok()
            .map(NetworkEvent::NewLink),
        t if t == NlMsgType::RTM_DELLINK => LinkMessage::from_bytes(payload)
            .ok()
            .map(NetworkEvent::DelLink),

        // Address events
        t if t == NlMsgType::RTM_NEWADDR => AddressMessage::from_bytes(payload)
            .ok()
            .map(NetworkEvent::NewAddress),
        t if t == NlMsgType::RTM_DELADDR => AddressMessage::from_bytes(payload)
            .ok()
            .map(NetworkEvent::DelAddress),

        // Route events
        t if t == NlMsgType::RTM_NEWROUTE => RouteMessage::from_bytes(payload)
            .ok()
            .map(NetworkEvent::NewRoute),
        t if t == NlMsgType::RTM_DELROUTE => RouteMessage::from_bytes(payload)
            .ok()
            .map(NetworkEvent::DelRoute),

        // Neighbor events
        t if t == NlMsgType::RTM_NEWNEIGH => NeighborMessage::from_bytes(payload)
            .ok()
            .map(NetworkEvent::NewNeighbor),
        t if t == NlMsgType::RTM_DELNEIGH => NeighborMessage::from_bytes(payload)
            .ok()
            .map(NetworkEvent::DelNeighbor),

        // TC events - qdiscs
        t if t == NlMsgType::RTM_NEWQDISC => TcMessage::from_bytes(payload)
            .ok()
            .map(NetworkEvent::NewQdisc),
        t if t == NlMsgType::RTM_DELQDISC => TcMessage::from_bytes(payload)
            .ok()
            .map(NetworkEvent::DelQdisc),

        // TC events - classes
        t if t == NlMsgType::RTM_NEWTCLASS => TcMessage::from_bytes(payload)
            .ok()
            .map(NetworkEvent::NewClass),
        t if t == NlMsgType::RTM_DELTCLASS => TcMessage::from_bytes(payload)
            .ok()
            .map(NetworkEvent::DelClass),

        // TC events - filters
        t if t == NlMsgType::RTM_NEWTFILTER => TcMessage::from_bytes(payload)
            .ok()
            .map(NetworkEvent::NewFilter),
        t if t == NlMsgType::RTM_DELTFILTER => TcMessage::from_bytes(payload)
            .ok()
            .map(NetworkEvent::DelFilter),

        // TC events - actions
        t if t == NlMsgType::RTM_NEWACTION => TcMessage::from_bytes(payload)
            .ok()
            .map(NetworkEvent::NewAction),
        t if t == NlMsgType::RTM_DELACTION => TcMessage::from_bytes(payload)
            .ok()
            .map(NetworkEvent::DelAction),

        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_builder_default() {
        let builder = EventStreamBuilder::new();
        assert!(!builder.links);
        assert!(!builder.addresses_v4);
        assert!(!builder.addresses_v6);
    }

    #[test]
    fn test_builder_chaining() {
        let builder = EventStreamBuilder::new()
            .links(true)
            .addresses(true)
            .tc(true);

        assert!(builder.links);
        assert!(builder.addresses_v4);
        assert!(builder.addresses_v6);
        assert!(builder.tc);
        assert!(!builder.routes_v4);
        assert!(!builder.neighbors);
    }
}
