//! High-level event stream API for network monitoring.
//!
//! This module provides an ergonomic, strongly-typed interface for monitoring
//! network changes including interface, address, route, neighbor, and TC events.
//!
//! # Single Namespace Example
//!
//! ```ignore
//! use nlink::netlink::events::{EventStream, NetworkEvent};
//! use tokio_stream::StreamExt;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let mut stream = EventStream::builder()
//!         .links(true)
//!         .addresses(true)
//!         .routes(true)
//!         .build()?;
//!
//!     // Using try_next() for familiar ? operator ergonomics
//!     while let Some(event) = stream.try_next().await? {
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
//!
//! # Multi-Namespace Example
//!
//! ```ignore
//! use nlink::netlink::events::{EventStream, MultiNamespaceEventStream};
//! use tokio_stream::StreamExt;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let mut multi = MultiNamespaceEventStream::new();
//!
//!     // Monitor default namespace
//!     multi.add("", EventStream::builder().all().build()?);
//!
//!     // Monitor named namespaces
//!     multi.add("ns1", EventStream::builder().namespace("ns1").all().build()?);
//!     multi.add("ns2", EventStream::builder().namespace("ns2").all().build()?);
//!
//!     while let Some(result) = multi.next().await {
//!         let ev = result?;
//!         println!("[{}] {:?}", ev.namespace, ev.event);
//!     }
//!     Ok(())
//! }
//! ```

use std::pin::Pin;
use std::task::{Context, Poll};

use tokio_stream::{Stream, StreamMap};

use super::connection::Connection;
use super::message::{MessageIter, NlMsgType};
use super::messages::{AddressMessage, LinkMessage, NeighborMessage, RouteMessage, TcMessage};
use super::parse::FromNetlink;
use super::socket::rtnetlink_groups::*;
use super::{Protocol, Result};
use std::path::PathBuf;

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

/// Event types that can be subscribed to.
///
/// Used with [`EventStreamBuilder::event_types`] for convenient subscription
/// based on CLI arguments or configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EventType {
    /// Link (interface) events.
    Link,
    /// IPv4 and IPv6 address events.
    Address,
    /// IPv4 address events only.
    AddressV4,
    /// IPv6 address events only.
    AddressV6,
    /// IPv4 and IPv6 route events.
    Route,
    /// IPv4 route events only.
    RouteV4,
    /// IPv6 route events only.
    RouteV6,
    /// Neighbor (ARP/NDP) events.
    Neighbor,
    /// Traffic control events (qdiscs, classes, filters).
    Tc,
    /// All event types.
    All,
}

/// Namespace configuration for EventStreamBuilder.
#[derive(Debug, Clone, Default)]
enum NamespaceConfig {
    /// Use the current/default namespace.
    #[default]
    Default,
    /// Use a named namespace (from /var/run/netns/).
    Named(String),
    /// Use a namespace by path.
    Path(PathBuf),
    /// Use a namespace by PID.
    Pid(u32),
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
    namespace: NamespaceConfig,
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

    /// Subscribe to event types from a slice.
    ///
    /// This is convenient when event types come from CLI arguments or configuration.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use nlink::netlink::events::{EventStream, EventType};
    ///
    /// let types = [EventType::Link, EventType::Address];
    /// let stream = EventStream::builder()
    ///     .event_types(&types)
    ///     .build()?;
    /// ```
    pub fn event_types(mut self, types: &[EventType]) -> Self {
        for t in types {
            match t {
                EventType::Link => self.links = true,
                EventType::Address => {
                    self.addresses_v4 = true;
                    self.addresses_v6 = true;
                }
                EventType::AddressV4 => self.addresses_v4 = true,
                EventType::AddressV6 => self.addresses_v6 = true,
                EventType::Route => {
                    self.routes_v4 = true;
                    self.routes_v6 = true;
                }
                EventType::RouteV4 => self.routes_v4 = true,
                EventType::RouteV6 => self.routes_v6 = true,
                EventType::Neighbor => self.neighbors = true,
                EventType::Tc => self.tc = true,
                EventType::All => {
                    self.links = true;
                    self.addresses_v4 = true;
                    self.addresses_v6 = true;
                    self.routes_v4 = true;
                    self.routes_v6 = true;
                    self.neighbors = true;
                    self.tc = true;
                }
            }
        }
        self
    }

    /// Subscribe to a single event type.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let stream = EventStream::builder()
    ///     .event_type(EventType::Link)
    ///     .event_type(EventType::Tc)
    ///     .build()?;
    /// ```
    pub fn event_type(self, t: EventType) -> Self {
        self.event_types(&[t])
    }

    /// Monitor events in a named network namespace.
    ///
    /// The namespace must exist in `/var/run/netns/` (created via `ip netns add`).
    ///
    /// # Example
    ///
    /// ```ignore
    /// let mut stream = EventStream::builder()
    ///     .namespace("myns")
    ///     .links(true)
    ///     .tc(true)
    ///     .build()?;
    /// ```
    pub fn namespace(mut self, name: impl Into<String>) -> Self {
        self.namespace = NamespaceConfig::Named(name.into());
        self
    }

    /// Monitor events in a network namespace by path.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let mut stream = EventStream::builder()
    ///     .namespace_path("/proc/1234/ns/net")
    ///     .links(true)
    ///     .build()?;
    /// ```
    pub fn namespace_path(mut self, path: impl AsRef<std::path::Path>) -> Self {
        self.namespace = NamespaceConfig::Path(path.as_ref().to_path_buf());
        self
    }

    /// Monitor events in a process's network namespace.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let mut stream = EventStream::builder()
    ///     .namespace_pid(container_pid)
    ///     .links(true)
    ///     .build()?;
    /// ```
    pub fn namespace_pid(mut self, pid: u32) -> Self {
        self.namespace = NamespaceConfig::Pid(pid);
        self
    }

    /// Build the event stream.
    pub fn build(self) -> Result<EventStream> {
        let mut conn = match self.namespace {
            NamespaceConfig::Default => Connection::new(Protocol::Route)?,
            NamespaceConfig::Named(ref name) => {
                let path = PathBuf::from("/var/run/netns").join(name);
                Connection::new_in_namespace_path(Protocol::Route, path)?
            }
            NamespaceConfig::Path(ref path) => {
                Connection::new_in_namespace_path(Protocol::Route, path)?
            }
            NamespaceConfig::Pid(pid) => {
                let path = PathBuf::from(format!("/proc/{}/ns/net", pid));
                Connection::new_in_namespace_path(Protocol::Route, path)?
            }
        };

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
/// Implements the [`Stream`] trait from `tokio-stream`, allowing use with
/// stream combinators and [`StreamMap`] for multi-namespace monitoring.
///
/// Use [`EventStream::builder()`] to configure which events to receive.
///
/// # Example
///
/// ```ignore
/// use nlink::netlink::events::EventStream;
/// use tokio_stream::StreamExt;
///
/// let mut stream = EventStream::builder()
///     .links(true)
///     .tc(true)
///     .build()?;
///
/// // Using try_next() for ? operator ergonomics
/// while let Some(event) = stream.try_next().await? {
///     println!("{:?}", event);
/// }
/// ```
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

    /// Get a reference to the underlying connection.
    pub fn connection(&self) -> &Connection {
        &self.conn
    }

    /// Get a mutable reference to the underlying connection.
    pub fn connection_mut(&mut self) -> &mut Connection {
        &mut self.conn
    }
}

impl Stream for EventStream {
    type Item = Result<NetworkEvent>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();

        // Return pending events first
        if let Some(event) = this.pending_events.pop() {
            return Poll::Ready(Some(Ok(event)));
        }

        // Poll for new data
        loop {
            match this.conn.poll_recv_event(cx) {
                Poll::Ready(Ok(data)) => {
                    this.buffer = data;

                    // Parse all messages in the buffer
                    for result in MessageIter::new(&this.buffer) {
                        match result {
                            Ok((header, payload)) => {
                                if let Some(event) = parse_event(header.nlmsg_type, payload) {
                                    this.pending_events.push(event);
                                }
                            }
                            Err(e) => return Poll::Ready(Some(Err(e))),
                        }
                    }

                    // Reverse so we pop in the correct order
                    this.pending_events.reverse();

                    // Return first event if available
                    if let Some(event) = this.pending_events.pop() {
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

// EventStream is Unpin because all its fields are Unpin (Vec, Connection)
impl Unpin for EventStream {}

// ============================================================================
// Multi-Namespace Event Stream
// ============================================================================

/// An event paired with its source namespace.
#[derive(Debug, Clone)]
pub struct NamespacedEvent {
    /// Namespace name ("" for default namespace).
    pub namespace: String,
    /// The network event.
    pub event: NetworkEvent,
}

impl NamespacedEvent {
    /// Returns true if this event is from the default namespace.
    pub fn is_default_namespace(&self) -> bool {
        self.namespace.is_empty()
    }

    /// Returns the interface index associated with this event, if any.
    pub fn ifindex(&self) -> Option<u32> {
        self.event.ifindex()
    }
}

/// Monitor network events across multiple namespaces.
///
/// Uses [`StreamMap`] internally to multiplex events from multiple
/// [`EventStream`] instances. Streams that end are automatically
/// removed from the map.
///
/// # Example
///
/// ```ignore
/// use nlink::netlink::events::{EventStream, MultiNamespaceEventStream};
/// use tokio_stream::StreamExt;
///
/// let mut multi = MultiNamespaceEventStream::new();
///
/// // Add default namespace (use empty string)
/// multi.add("", EventStream::builder().all().build()?);
///
/// // Add named namespaces
/// multi.add("ns1", EventStream::builder().namespace("ns1").all().build()?);
/// multi.add("ns2", EventStream::builder().namespace("ns2").all().build()?);
///
/// // Monitor all namespaces
/// while let Some(result) = multi.next().await {
///     match result {
///         Ok(ev) => println!("[{}] {:?}", ev.namespace, ev.event),
///         Err(e) => eprintln!("Error: {}", e),
///     }
/// }
/// ```
pub struct MultiNamespaceEventStream {
    streams: StreamMap<String, EventStream>,
}

impl MultiNamespaceEventStream {
    /// Create a new empty multi-namespace event stream.
    pub fn new() -> Self {
        Self {
            streams: StreamMap::new(),
        }
    }

    /// Create with pre-allocated capacity.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            streams: StreamMap::with_capacity(capacity),
        }
    }

    /// Add a namespace to monitor.
    ///
    /// If a stream with this name already exists, it is replaced
    /// and the old stream is returned.
    ///
    /// Use `""` (empty string) for the default namespace.
    pub fn add(&mut self, name: impl Into<String>, stream: EventStream) -> Option<EventStream> {
        self.streams.insert(name.into(), stream)
    }

    /// Remove a namespace from monitoring.
    pub fn remove(&mut self, name: &str) -> Option<EventStream> {
        self.streams.remove(name)
    }

    /// Check if a namespace is being monitored.
    pub fn contains(&self, name: &str) -> bool {
        self.streams.contains_key(name)
    }

    /// Number of namespaces being monitored.
    pub fn len(&self) -> usize {
        self.streams.len()
    }

    /// Returns true if no namespaces are being monitored.
    pub fn is_empty(&self) -> bool {
        self.streams.is_empty()
    }

    /// Get the next event from any monitored namespace.
    ///
    /// Returns `None` when all streams have ended.
    pub async fn next(&mut self) -> Option<Result<NamespacedEvent>> {
        use tokio_stream::StreamExt;

        self.streams
            .next()
            .await
            .map(|(namespace, result)| result.map(|event| NamespacedEvent { namespace, event }))
    }

    /// Iterator over namespace names being monitored.
    pub fn namespaces(&self) -> impl Iterator<Item = &String> {
        self.streams.keys()
    }

    /// Clear all streams.
    pub fn clear(&mut self) {
        self.streams.clear()
    }
}

impl Default for MultiNamespaceEventStream {
    fn default() -> Self {
        Self::new()
    }
}

impl Stream for MultiNamespaceEventStream {
    type Item = Result<NamespacedEvent>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match Pin::new(&mut self.streams).poll_next(cx) {
            Poll::Ready(Some((namespace, result))) => Poll::Ready(Some(
                result.map(|event| NamespacedEvent { namespace, event }),
            )),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl Unpin for MultiNamespaceEventStream {}

// ============================================================================
// Helper Functions
// ============================================================================

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

    #[test]
    fn test_multi_namespace_new() {
        let multi = MultiNamespaceEventStream::new();
        assert!(multi.is_empty());
        assert_eq!(multi.len(), 0);
    }

    #[test]
    fn test_namespaced_event() {
        let link = LinkMessage::default();
        let event = NamespacedEvent {
            namespace: "ns1".to_string(),
            event: NetworkEvent::NewLink(link),
        };
        assert!(!event.is_default_namespace());

        let event = NamespacedEvent {
            namespace: "".to_string(),
            event: NetworkEvent::NewLink(LinkMessage::default()),
        };
        assert!(event.is_default_namespace());
    }

    #[test]
    fn test_event_stream_is_unpin() {
        fn assert_unpin<T: Unpin>() {}
        assert_unpin::<EventStream>();
        assert_unpin::<MultiNamespaceEventStream>();
    }
}
