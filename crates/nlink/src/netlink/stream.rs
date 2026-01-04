//! Stream-based event monitoring for netlink protocols.
//!
//! This module provides the [`EventSource`] trait and stream types for
//! protocols that support event monitoring via multicast groups.
//!
//! # Overview
//!
//! Protocols that implement [`EventSource`] can produce events via:
//! - [`Connection::events()`] - returns a borrowed stream, connection remains usable
//! - [`Connection::into_events()`] - consumes connection, returns owned stream
//!
//! # Example
//!
//! ```ignore
//! use nlink::netlink::{Connection, KobjectUevent};
//! use tokio_stream::StreamExt;
//!
//! let conn = Connection::<KobjectUevent>::new()?;
//!
//! // Get event stream (borrows connection)
//! let mut events = conn.events();
//! while let Some(event) = events.try_next().await? {
//!     println!("[{}] {}", event.action, event.devpath);
//! }
//!
//! // Connection still usable after dropping stream
//! drop(events);
//! ```
//!
//! # Combining Multiple Event Sources
//!
//! ```ignore
//! use nlink::netlink::{Connection, KobjectUevent, SELinux};
//! use tokio_stream::StreamExt;
//! use std::pin::pin;
//!
//! let uevent_conn = Connection::<KobjectUevent>::new()?;
//! let selinux_conn = Connection::<SELinux>::new()?;
//!
//! let mut uevent_events = pin!(uevent_conn.events());
//! let mut selinux_events = pin!(selinux_conn.events());
//!
//! loop {
//!     tokio::select! {
//!         Some(event) = uevent_events.next() => {
//!             println!("[device] {:?}", event?);
//!         }
//!         Some(event) = selinux_events.next() => {
//!             println!("[selinux] {:?}", event?);
//!         }
//!     }
//! }
//! ```

use std::pin::Pin;
use std::task::{Context, Poll};

use tokio_stream::Stream;

use super::connection::Connection;
use super::error::Result;
use super::message::MessageIter;
use super::protocol::ProtocolState;

/// Sealed trait module to prevent external implementations.
mod private {
    pub trait Sealed {}
}

/// Trait for protocols that can produce events via multicast subscription.
///
/// This trait is sealed and cannot be implemented outside this crate.
/// Protocols implementing this trait can use [`Connection::events()`]
/// and [`Connection::into_events()`] to receive events as a [`Stream`].
///
/// # Implementors
///
/// - [`Route`](super::Route) - Network configuration events (link, address, route, neighbor, TC)
/// - [`KobjectUevent`](super::KobjectUevent) - Device hotplug events
/// - [`Connector`](super::Connector) - Process lifecycle events (fork, exec, exit)
/// - [`SELinux`](super::SELinux) - SELinux policy/enforcement events
pub trait EventSource: ProtocolState + private::Sealed {
    /// The event type produced by this protocol.
    type Event: Send + 'static;

    /// Parse events from raw netlink message data.
    ///
    /// Returns a vector of parsed events. Multiple events may be present
    /// in a single netlink message batch.
    fn parse_events(data: &[u8]) -> Vec<Self::Event>;
}

// ============================================================================
// EventSubscription - Borrowed stream
// ============================================================================

/// A stream of events that borrows the underlying connection.
///
/// Created by [`Connection::events()`]. The connection remains
/// usable for queries while this stream is active.
///
/// # Example
///
/// ```ignore
/// use nlink::netlink::{Connection, KobjectUevent};
/// use tokio_stream::StreamExt;
///
/// let conn = Connection::<KobjectUevent>::new()?;
/// let mut events = conn.events();
///
/// while let Some(event) = events.try_next().await? {
///     println!("{:?}", event);
/// }
/// ```
pub struct EventSubscription<'a, P: EventSource> {
    conn: &'a Connection<P>,
    buffer: Vec<u8>,
    pending: Vec<P::Event>,
}

impl<'a, P: EventSource> EventSubscription<'a, P> {
    pub(crate) fn new(conn: &'a Connection<P>) -> Self {
        Self {
            conn,
            buffer: Vec::new(),
            pending: Vec::new(),
        }
    }
}

impl<P: EventSource> Stream for EventSubscription<'_, P> {
    type Item = Result<P::Event>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();

        // Return pending events first
        if let Some(event) = this.pending.pop() {
            return Poll::Ready(Some(Ok(event)));
        }

        // Poll for new data
        loop {
            match this.conn.socket().poll_recv(cx) {
                Poll::Ready(Ok(data)) => {
                    this.buffer = data;

                    // Parse all events from the buffer
                    this.pending = P::parse_events(&this.buffer);

                    // Reverse so we pop in the correct order
                    this.pending.reverse();

                    // Return first event if available
                    if let Some(event) = this.pending.pop() {
                        return Poll::Ready(Some(Ok(event)));
                    }

                    // No events in this batch, continue polling
                    continue;
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Some(Err(e))),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl<P: EventSource> Unpin for EventSubscription<'_, P> {}

// ============================================================================
// OwnedEventStream - Owned stream
// ============================================================================

/// A stream of events that owns the underlying connection.
///
/// Created by [`Connection::into_events()`]. Use [`EventSubscription`]
/// via [`Connection::subscribe()`] if you need to retain access to the connection.
///
/// # Example
///
/// ```ignore
/// use nlink::netlink::{Connection, SELinux};
/// use tokio_stream::StreamExt;
///
/// let conn = Connection::<SELinux>::new()?;
/// let mut stream = conn.into_events();
///
/// while let Some(event) = stream.try_next().await? {
///     println!("{:?}", event);
/// }
///
/// // Recover the connection if needed
/// let conn = stream.into_connection();
/// ```
pub struct OwnedEventStream<P: EventSource> {
    conn: Connection<P>,
    buffer: Vec<u8>,
    pending: Vec<P::Event>,
}

impl<P: EventSource> OwnedEventStream<P> {
    pub(crate) fn new(conn: Connection<P>) -> Self {
        Self {
            conn,
            buffer: Vec::new(),
            pending: Vec::new(),
        }
    }

    /// Get a reference to the underlying connection.
    pub fn connection(&self) -> &Connection<P> {
        &self.conn
    }

    /// Consume this stream and return the underlying connection.
    pub fn into_connection(self) -> Connection<P> {
        self.conn
    }
}

impl<P: EventSource> Stream for OwnedEventStream<P> {
    type Item = Result<P::Event>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();

        // Return pending events first
        if let Some(event) = this.pending.pop() {
            return Poll::Ready(Some(Ok(event)));
        }

        // Poll for new data
        loop {
            match this.conn.socket().poll_recv(cx) {
                Poll::Ready(Ok(data)) => {
                    this.buffer = data;

                    // Parse all events from the buffer
                    this.pending = P::parse_events(&this.buffer);

                    // Reverse so we pop in the correct order
                    this.pending.reverse();

                    // Return first event if available
                    if let Some(event) = this.pending.pop() {
                        return Poll::Ready(Some(Ok(event)));
                    }

                    // No events in this batch, continue polling
                    continue;
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Some(Err(e))),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl<P: EventSource> Unpin for OwnedEventStream<P> {}

// ============================================================================
// Connection methods for EventSource protocols
// ============================================================================

impl<P: EventSource> Connection<P> {
    /// Create an event stream that borrows this connection.
    ///
    /// Returns a [`Stream`] that borrows the connection. The connection
    /// remains usable for queries while the stream is active.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use nlink::netlink::{Connection, KobjectUevent};
    /// use tokio_stream::StreamExt;
    ///
    /// let conn = Connection::<KobjectUevent>::new()?;
    ///
    /// // Borrow connection for streaming
    /// let mut events = conn.events();
    /// while let Some(event) = events.try_next().await? {
    ///     if event.is_add() {
    ///         println!("Device added: {}", event.devpath);
    ///     }
    /// }
    ///
    /// // Connection still usable
    /// drop(events);
    /// ```
    pub fn events(&self) -> EventSubscription<'_, P> {
        EventSubscription::new(self)
    }

    /// Convert this connection into an owned event stream.
    ///
    /// This consumes the connection. Use [`events()`](Self::events)
    /// if you need to keep using the connection for queries.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use nlink::netlink::{Connection, SELinux};
    /// use tokio_stream::StreamExt;
    ///
    /// let conn = Connection::<SELinux>::new()?;
    /// let mut stream = conn.into_events();
    ///
    /// while let Some(event) = stream.try_next().await? {
    ///     println!("{:?}", event);
    /// }
    ///
    /// // Recover connection if needed
    /// let conn = stream.into_connection();
    /// ```
    pub fn into_events(self) -> OwnedEventStream<P> {
        OwnedEventStream::new(self)
    }
}

// ============================================================================
// EventSource implementations
// ============================================================================

use super::connector::ProcEvent;
use super::events::NetworkEvent;
use super::message::NlMsgType;
use super::messages::{AddressMessage, LinkMessage, NeighborMessage, RouteMessage, TcMessage};
use super::parse::FromNetlink;
use super::protocol::{Connector, KobjectUevent, Route, SELinux};
use super::selinux::SELinuxEvent;
use super::uevent::Uevent;

// Route protocol events
impl private::Sealed for Route {}

impl EventSource for Route {
    type Event = NetworkEvent;

    fn parse_events(data: &[u8]) -> Vec<NetworkEvent> {
        let mut events = Vec::new();

        for (header, payload) in MessageIter::new(data).flatten() {
            if let Some(event) = parse_route_event(header.nlmsg_type, payload) {
                events.push(event);
            }
        }

        events
    }
}

fn parse_route_event(msg_type: u16, payload: &[u8]) -> Option<NetworkEvent> {
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

        // Neighbor events (including FDB for AF_BRIDGE family)
        t if t == NlMsgType::RTM_NEWNEIGH => NeighborMessage::from_bytes(payload).ok().map(|msg| {
            // AF_BRIDGE (7) neighbor messages are FDB entries
            if msg.family() == 7 {
                super::fdb::FdbEntry::from_neighbor(&msg)
                    .map(NetworkEvent::NewFdb)
                    .unwrap_or(NetworkEvent::NewNeighbor(msg))
            } else {
                NetworkEvent::NewNeighbor(msg)
            }
        }),
        t if t == NlMsgType::RTM_DELNEIGH => NeighborMessage::from_bytes(payload).ok().map(|msg| {
            // AF_BRIDGE (7) neighbor messages are FDB entries
            if msg.family() == 7 {
                super::fdb::FdbEntry::from_neighbor(&msg)
                    .map(NetworkEvent::DelFdb)
                    .unwrap_or(NetworkEvent::DelNeighbor(msg))
            } else {
                NetworkEvent::DelNeighbor(msg)
            }
        }),

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

// KobjectUevent protocol events
impl private::Sealed for KobjectUevent {}

impl EventSource for KobjectUevent {
    type Event = Uevent;

    fn parse_events(data: &[u8]) -> Vec<Uevent> {
        // Uevent messages don't have netlink headers, parse directly
        Uevent::parse(data).into_iter().collect()
    }
}

// Connector protocol events
impl private::Sealed for Connector {}

impl EventSource for Connector {
    type Event = ProcEvent;

    fn parse_events(data: &[u8]) -> Vec<ProcEvent> {
        // Connector messages need special parsing
        parse_connector_event(data).into_iter().collect()
    }
}

fn parse_connector_event(data: &[u8]) -> Option<ProcEvent> {
    // Skip netlink header (16 bytes) and connector header
    const NLMSG_HDRLEN: usize = 16;
    const CN_MSG_HDRLEN: usize = 20;

    if data.len() < NLMSG_HDRLEN + CN_MSG_HDRLEN {
        return None;
    }

    let payload = &data[NLMSG_HDRLEN + CN_MSG_HDRLEN..];
    ProcEvent::parse_from_bytes(payload)
}

// SELinux protocol events
impl private::Sealed for SELinux {}

impl EventSource for SELinux {
    type Event = SELinuxEvent;

    fn parse_events(data: &[u8]) -> Vec<SELinuxEvent> {
        parse_selinux_event(data).into_iter().collect()
    }
}

fn parse_selinux_event(data: &[u8]) -> Option<SELinuxEvent> {
    use super::selinux::{SelnlMsgPolicyload, SelnlMsgSetenforce};
    use zerocopy::FromBytes;

    const NLMSG_HDRLEN: usize = 16;
    const SELNL_MSG_SETENFORCE: u16 = 0x10;
    const SELNL_MSG_POLICYLOAD: u16 = 0x11;

    if data.len() < NLMSG_HDRLEN {
        return None;
    }

    let nlmsg_type = u16::from_ne_bytes([data[4], data[5]]);
    let payload = &data[NLMSG_HDRLEN..];

    match nlmsg_type {
        SELNL_MSG_SETENFORCE => {
            let (msg, _) = SelnlMsgSetenforce::ref_from_prefix(payload).ok()?;
            Some(SELinuxEvent::SetEnforce {
                enforcing: msg.val != 0,
            })
        }
        SELNL_MSG_POLICYLOAD => {
            let (msg, _) = SelnlMsgPolicyload::ref_from_prefix(payload).ok()?;
            Some(SELinuxEvent::PolicyLoad { seqno: msg.seqno })
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_subscription_is_unpin() {
        fn assert_unpin<T: Unpin>() {}
        assert_unpin::<EventSubscription<'_, KobjectUevent>>();
        assert_unpin::<EventSubscription<'_, SELinux>>();
    }

    #[test]
    fn owned_event_stream_is_unpin() {
        fn assert_unpin<T: Unpin>() {}
        assert_unpin::<OwnedEventStream<KobjectUevent>>();
        assert_unpin::<OwnedEventStream<SELinux>>();
    }
}
