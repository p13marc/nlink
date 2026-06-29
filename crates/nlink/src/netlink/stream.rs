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
//! let mut events = conn.events().await;
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
//! let mut uevent_events = pin!(uevent_conn.events().await);
//! let mut selinux_events = pin!(selinux_conn.events().await);
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

use std::{
    pin::Pin,
    task::{Context, Poll},
};

use tokio_stream::Stream;

use super::{
    connection::Connection,
    error::{Error, Result},
    message::MessageIter,
    protocol::ProtocolState,
};

/// Error surfaced when an event stream is created on a dispatcher-mode
/// connection. The background driver task owns `recv` on the socket, so a
/// `poll_recv`-based stream would be a two-reader race. Multicast subscribers
/// must use a default-mode `Connection` (or a separate connection from a
/// `ConnectionPool`). See #134.
pub(crate) fn dispatcher_mode_stream_error() -> Error {
    Error::not_supported(
        "event/dump streams are not supported on a dispatcher-mode connection; \
         use a default-mode Connection (or a separate ConnectionPool connection) \
         for long-lived subscriptions",
    )
}

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
/// - [`Route`] - Network configuration events (link, address, route, neighbor, TC)
/// - [`KobjectUevent`] - Device hotplug events
/// - [`Connector`] - Process lifecycle events (fork, exec, exit)
/// - [`SELinux`] - SELinux policy/enforcement events
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
/// let mut events = conn.events().await;
///
/// while let Some(event) = events.try_next().await? {
///     println!("{:?}", event);
/// }
/// ```
pub struct EventSubscription<'a, P: EventSource> {
    conn: &'a Connection<P>,
    buffer: Vec<u8>,
    pending: Vec<P::Event>,
    /// 0.19 Finding B — hold the Connection's request lock for the
    /// subscription's lifetime so concurrent dumps / other streams
    /// on a shared `Arc<Connection>` don't race on `poll_recv`. The
    /// lock is acquired in [`Connection::events`] (now async) and
    /// released when the stream is dropped.
    _guard: tokio::sync::OwnedMutexGuard<()>,
    /// #134 — set when the connection is in dispatcher mode, where the
    /// driver owns recv and a second reader (this stream) would race
    /// it. The stream yields one error then ends.
    unsupported: bool,
    terminated: bool,
}

impl<'a, P: EventSource> EventSubscription<'a, P> {
    pub(crate) fn new(conn: &'a Connection<P>, guard: tokio::sync::OwnedMutexGuard<()>) -> Self {
        Self {
            unsupported: conn.is_dispatcher_mode(),
            conn,
            buffer: Vec::new(),
            pending: Vec::new(),
            _guard: guard,
            terminated: false,
        }
    }
}

impl<P: EventSource> Stream for EventSubscription<'_, P> {
    type Item = Result<P::Event>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();

        // #134 — dispatcher mode: surface the limitation once, then end.
        if this.unsupported {
            if this.terminated {
                return Poll::Ready(None);
            }
            this.terminated = true;
            return Poll::Ready(Some(Err(dispatcher_mode_stream_error())));
        }

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
                    tracing::trace!(
                        protocol = std::any::type_name::<P>(),
                        events = this.pending.len(),
                        "delivered multicast batch"
                    );

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
/// let mut stream = conn.into_events().await;
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
    /// 0.19 Finding B — same role as `EventSubscription::_guard`.
    /// Because the lock is held by the OwnedMutexGuard wrapping
    /// the Connection's own request_lock Arc, and the Connection
    /// is owned by this struct, dropping the stream releases the
    /// guard which drops the Arc reference (alongside the
    /// Connection itself).
    _guard: tokio::sync::OwnedMutexGuard<()>,
    /// #134 — see [`EventSubscription::unsupported`].
    unsupported: bool,
    terminated: bool,
}

impl<P: EventSource> OwnedEventStream<P> {
    pub(crate) fn new(conn: Connection<P>, guard: tokio::sync::OwnedMutexGuard<()>) -> Self {
        Self {
            unsupported: conn.is_dispatcher_mode(),
            conn,
            buffer: Vec::new(),
            pending: Vec::new(),
            _guard: guard,
            terminated: false,
        }
    }

    /// Get a reference to the underlying connection.
    pub fn connection(&self) -> &Connection<P> {
        &self.conn
    }

    /// Consume this stream and return the underlying connection.
    /// 0.19 Finding B — the guard is dropped here, releasing the
    /// Connection's request lock so subsequent requests can proceed.
    pub fn into_connection(self) -> Connection<P> {
        // Drop the guard explicitly via struct destructure so the
        // released lock is observable before we return.
        let Self { conn, .. } = self;
        conn
    }
}

impl<P: EventSource> Stream for OwnedEventStream<P> {
    type Item = Result<P::Event>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();

        // #134 — dispatcher mode: surface the limitation once, then end.
        if this.unsupported {
            if this.terminated {
                return Poll::Ready(None);
            }
            this.terminated = true;
            return Poll::Ready(Some(Err(dispatcher_mode_stream_error())));
        }

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
                    tracing::trace!(
                        protocol = std::any::type_name::<P>(),
                        events = this.pending.len(),
                        "delivered multicast batch (owned stream)"
                    );

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
    /// remains usable for **non-recv** operations (`set_strict_checking`,
    /// `subscribe` to add more groups, etc.) while the stream is active.
    ///
    /// **0.19 Finding B — now `async`.** Acquires the connection's
    /// request lock for the subscription's lifetime so concurrent
    /// streams (multiple `events()`, `events()` + `dump_stream()`)
    /// no longer race on `poll_recv` and steal each other's frames.
    /// Concurrent dumps on a connection with an active events stream
    /// will block until the events stream is dropped — use a second
    /// Connection (or `ConnectionPool`) for query-in-parallel
    /// patterns.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use nlink::netlink::{Connection, KobjectUevent};
    /// use tokio_stream::StreamExt;
    ///
    /// let conn = Connection::<KobjectUevent>::new()?;
    ///
    /// // Borrow connection for streaming (0.19: now async).
    /// let mut events = conn.events().await;
    /// while let Some(event) = events.try_next().await? {
    ///     if event.is_add() {
    ///         println!("Device added: {}", event.devpath);
    ///     }
    /// }
    ///
    /// // Connection still usable
    /// drop(events);
    /// ```
    pub async fn events(&self) -> EventSubscription<'_, P> {
        let guard = self.lock_request_owned().await;
        EventSubscription::new(self, guard)
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
    /// let mut stream = conn.into_events().await;
    ///
    /// while let Some(event) = stream.try_next().await? {
    ///     println!("{:?}", event);
    /// }
    ///
    /// // Recover connection if needed
    /// let conn = stream.into_connection();
    /// ```
    ///
    /// **0.19 Finding B — now `async`.** Same locking semantics as
    /// [`Self::events`]; see that method's docstring for the trade-off.
    pub async fn into_events(self) -> OwnedEventStream<P> {
        let guard = self.lock_request_owned().await;
        OwnedEventStream::new(self, guard)
    }
}

// ============================================================================
// EventSource implementations
// ============================================================================

use super::{
    connector::ProcEvent,
    events::NetworkEvent,
    message::NlMsgType,
    messages::{AddressMessage, LinkMessage, NeighborMessage, RouteMessage, TcMessage},
    netfilter::{ConntrackEvent, parse_conntrack_event},
    parse::FromNetlink,
    protocol::{Connector, Devlink, Ethtool, KobjectUevent, Netfilter, Nl80211, Route, SELinux},
    selinux::SELinuxEvent,
    uevent::Uevent,
};

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

// Netfilter protocol events (ctnetlink multicast)
impl private::Sealed for Netfilter {}

impl EventSource for Netfilter {
    type Event = ConntrackEvent;

    fn parse_events(data: &[u8]) -> Vec<ConntrackEvent> {
        let mut events = Vec::new();
        for (header, payload) in MessageIter::new(data).flatten() {
            if let Some(evt) = parse_conntrack_event(header.nlmsg_type, payload) {
                events.push(evt);
            }
        }
        events
    }
}

// Nftables protocol events (NFNLGRP_NFTABLES multicast — table /
// chain / rule / flowtable mutations).
impl private::Sealed for super::protocol::Nftables {}

impl EventSource for super::protocol::Nftables {
    type Event = super::nftables::NftablesEvent;

    fn parse_events(data: &[u8]) -> Vec<super::nftables::NftablesEvent> {
        let mut events = Vec::new();
        for (header, payload) in MessageIter::new(data).flatten() {
            if let Some(evt) =
                super::nftables::events::parse_nftables_event(header.nlmsg_type, payload)
            {
                events.push(evt);
            }
        }
        events
    }
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
    use zerocopy::FromBytes;

    use super::selinux::{SelnlMsgPolicyload, SelnlMsgSetenforce};

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

// Devlink protocol events
impl private::Sealed for Devlink {}

impl EventSource for Devlink {
    type Event = super::genl::devlink::DevlinkEvent;

    fn parse_events(data: &[u8]) -> Vec<Self::Event> {
        parse_devlink_events(data)
    }
}

fn parse_devlink_events(data: &[u8]) -> Vec<super::genl::devlink::DevlinkEvent> {
    use super::genl::{
        GENL_HDRLEN, GenlMsgHdr,
        devlink::{
            DEVLINK_ATTR_BUS_NAME, DEVLINK_ATTR_DEV_NAME, DEVLINK_ATTR_FLASH_UPDATE_COMPONENT,
            DEVLINK_ATTR_FLASH_UPDATE_STATUS_DONE, DEVLINK_ATTR_FLASH_UPDATE_STATUS_MSG,
            DEVLINK_ATTR_FLASH_UPDATE_STATUS_TOTAL, DEVLINK_ATTR_HEALTH_REPORTER,
            DEVLINK_ATTR_HEALTH_REPORTER_NAME, DEVLINK_ATTR_PORT_INDEX,
            DEVLINK_ATTR_PORT_NETDEV_NAME, DEVLINK_CMD_FLASH_UPDATE_STATUS, DEVLINK_CMD_GET,
            DEVLINK_CMD_HEALTH_REPORTER_RECOVER, DEVLINK_CMD_PORT_DEL, DEVLINK_CMD_PORT_NEW,
            DevlinkEvent, FlashProgress,
        },
    };

    let mut events = Vec::new();

    for msg_result in MessageIter::new(data) {
        let Ok((header, payload)) = msg_result else {
            continue;
        };

        if header.is_error() || header.is_done() {
            continue;
        }

        if payload.len() < GENL_HDRLEN {
            continue;
        }

        let Some(genl_hdr) = GenlMsgHdr::from_bytes(payload) else {
            continue;
        };

        let cmd = genl_hdr.cmd;
        let attrs_data = &payload[GENL_HDRLEN..];

        let mut bus = String::new();
        let mut device = String::new();
        let mut port_index = 0u32;
        let mut netdev_name: Option<String> = None;
        let mut reporter_name: Option<String> = None;
        let mut flash_msg: Option<String> = None;
        let mut flash_component: Option<String> = None;
        let mut flash_done: u64 = 0;
        let mut flash_total: u64 = 0;

        for (attr_type, attr_payload) in super::attr::AttrIter::new(attrs_data) {
            match attr_type {
                DEVLINK_ATTR_BUS_NAME => {
                    bus = std::str::from_utf8(attr_payload)
                        .unwrap_or("")
                        .trim_end_matches('\0')
                        .to_string();
                }
                DEVLINK_ATTR_DEV_NAME => {
                    device = std::str::from_utf8(attr_payload)
                        .unwrap_or("")
                        .trim_end_matches('\0')
                        .to_string();
                }
                DEVLINK_ATTR_PORT_INDEX if attr_payload.len() >= 4 => {
                    port_index = u32::from_ne_bytes(attr_payload[..4].try_into().unwrap());
                }
                DEVLINK_ATTR_PORT_NETDEV_NAME => {
                    netdev_name = Some(
                        std::str::from_utf8(attr_payload)
                            .unwrap_or("")
                            .trim_end_matches('\0')
                            .to_string(),
                    );
                }
                DEVLINK_ATTR_HEALTH_REPORTER => {
                    // Parse nested reporter to get name
                    for (inner_type, inner_payload) in super::attr::AttrIter::new(attr_payload) {
                        if inner_type == DEVLINK_ATTR_HEALTH_REPORTER_NAME {
                            reporter_name = Some(
                                std::str::from_utf8(inner_payload)
                                    .unwrap_or("")
                                    .trim_end_matches('\0')
                                    .to_string(),
                            );
                        }
                    }
                }
                DEVLINK_ATTR_FLASH_UPDATE_STATUS_MSG => {
                    flash_msg = Some(
                        std::str::from_utf8(attr_payload)
                            .unwrap_or("")
                            .trim_end_matches('\0')
                            .to_string(),
                    );
                }
                DEVLINK_ATTR_FLASH_UPDATE_COMPONENT => {
                    flash_component = Some(
                        std::str::from_utf8(attr_payload)
                            .unwrap_or("")
                            .trim_end_matches('\0')
                            .to_string(),
                    );
                }
                DEVLINK_ATTR_FLASH_UPDATE_STATUS_DONE if attr_payload.len() >= 8 => {
                    flash_done = u64::from_ne_bytes(attr_payload[..8].try_into().unwrap());
                }
                DEVLINK_ATTR_FLASH_UPDATE_STATUS_TOTAL if attr_payload.len() >= 8 => {
                    flash_total = u64::from_ne_bytes(attr_payload[..8].try_into().unwrap());
                }
                _ => {}
            }
        }

        // Devlink uses CMD_GET (1) for both new/del device notifications
        // Port notifications use CMD_PORT_NEW (6) and CMD_PORT_DEL (7)
        let event = match cmd {
            DEVLINK_CMD_GET => {
                // Device new notification
                DevlinkEvent::NewDevice { bus, device }
            }
            DEVLINK_CMD_PORT_NEW => DevlinkEvent::NewPort {
                bus,
                device,
                port_index,
                netdev_name,
            },
            DEVLINK_CMD_PORT_DEL => DevlinkEvent::DelPort {
                bus,
                device,
                port_index,
            },
            DEVLINK_CMD_HEALTH_REPORTER_RECOVER => DevlinkEvent::HealthEvent {
                bus,
                device,
                reporter: reporter_name,
            },
            DEVLINK_CMD_FLASH_UPDATE_STATUS => DevlinkEvent::FlashUpdate(FlashProgress {
                message: flash_msg,
                component: flash_component,
                done: flash_done,
                total: flash_total,
            }),
            _ => continue,
        };

        events.push(event);
    }

    events
}

// Nl80211 protocol events
impl private::Sealed for Nl80211 {}

impl EventSource for Nl80211 {
    type Event = super::genl::nl80211::Nl80211Event;

    fn parse_events(data: &[u8]) -> Vec<Self::Event> {
        parse_nl80211_events(data)
    }
}

fn parse_nl80211_events(data: &[u8]) -> Vec<super::genl::nl80211::Nl80211Event> {
    use super::genl::{
        GENL_HDRLEN, GenlMsgHdr,
        nl80211::{
            InterfaceType, NL80211_ATTR_IFINDEX, NL80211_ATTR_IFNAME, NL80211_ATTR_IFTYPE,
            NL80211_ATTR_MAC, NL80211_ATTR_REASON_CODE, NL80211_ATTR_REG_ALPHA2,
            NL80211_ATTR_STATUS_CODE, NL80211_CMD_CONNECT, NL80211_CMD_DEL_INTERFACE,
            NL80211_CMD_DISCONNECT, NL80211_CMD_NEW_INTERFACE, NL80211_CMD_NEW_SCAN_RESULTS,
            NL80211_CMD_REG_CHANGE, NL80211_CMD_SCAN_ABORTED, Nl80211Event,
        },
    };

    let mut events = Vec::new();

    for msg_result in MessageIter::new(data) {
        let Ok((header, payload)) = msg_result else {
            continue;
        };

        if header.is_error() || header.is_done() {
            continue;
        }

        if payload.len() < GENL_HDRLEN {
            continue;
        }

        let Some(genl_hdr) = GenlMsgHdr::from_bytes(payload) else {
            continue;
        };

        let cmd = genl_hdr.cmd;
        let attrs_data = &payload[GENL_HDRLEN..];

        // Parse common attributes
        let mut ifindex = 0u32;
        let mut ifname: Option<String> = None;
        let mut iftype = InterfaceType::Unspecified;
        let mut mac: Option<[u8; 6]> = None;
        let mut reason_code = 0u16;
        let mut status_code = 0u16;
        let mut country: Option<String> = None;

        for (attr_type, attr_payload) in super::attr::AttrIter::new(attrs_data) {
            match attr_type {
                NL80211_ATTR_IFINDEX if attr_payload.len() >= 4 => {
                    ifindex = u32::from_ne_bytes(attr_payload[..4].try_into().unwrap());
                }
                NL80211_ATTR_IFNAME => {
                    ifname = std::str::from_utf8(attr_payload)
                        .ok()
                        .map(|s| s.trim_end_matches('\0').to_string())
                        .filter(|s| !s.is_empty());
                }
                NL80211_ATTR_IFTYPE if attr_payload.len() >= 4 => {
                    let val = u32::from_ne_bytes(attr_payload[..4].try_into().unwrap());
                    iftype = InterfaceType::try_from(val).unwrap_or(InterfaceType::Unspecified);
                }
                NL80211_ATTR_MAC if attr_payload.len() >= 6 => {
                    let mut m = [0u8; 6];
                    m.copy_from_slice(&attr_payload[..6]);
                    mac = Some(m);
                }
                NL80211_ATTR_REASON_CODE if attr_payload.len() >= 2 => {
                    reason_code = u16::from_ne_bytes(attr_payload[..2].try_into().unwrap());
                }
                NL80211_ATTR_STATUS_CODE if attr_payload.len() >= 2 => {
                    status_code = u16::from_ne_bytes(attr_payload[..2].try_into().unwrap());
                }
                NL80211_ATTR_REG_ALPHA2 => {
                    country = std::str::from_utf8(attr_payload)
                        .ok()
                        .map(|s| s.trim_end_matches('\0').to_string())
                        .filter(|s| !s.is_empty());
                }
                _ => {}
            }
        }

        let event = match cmd {
            NL80211_CMD_NEW_SCAN_RESULTS => Nl80211Event::ScanComplete { ifindex },
            NL80211_CMD_SCAN_ABORTED => Nl80211Event::ScanAborted { ifindex },
            NL80211_CMD_CONNECT => Nl80211Event::Connect {
                ifindex,
                bssid: mac.unwrap_or([0; 6]),
                status_code,
            },
            NL80211_CMD_DISCONNECT => Nl80211Event::Disconnect {
                ifindex,
                bssid: mac,
                reason_code,
            },
            NL80211_CMD_NEW_INTERFACE => Nl80211Event::NewInterface {
                ifindex,
                name: ifname,
                iftype,
            },
            NL80211_CMD_DEL_INTERFACE => Nl80211Event::DelInterface { ifindex },
            NL80211_CMD_REG_CHANGE => Nl80211Event::RegChange { country },
            _ => continue,
        };

        events.push(event);
    }

    events
}

// Ethtool protocol events
impl private::Sealed for Ethtool {}

impl EventSource for Ethtool {
    type Event = super::genl::ethtool::EthtoolEvent;

    fn parse_events(data: &[u8]) -> Vec<Self::Event> {
        parse_ethtool_events(data)
    }
}

// DPLL multicast monitor events (Plan 156 Phase 5). Uses the
// generic GENL-family group-resolution infra in the macro
// stack — see `Connection::<Dpll>::subscribe_monitor()` and
// `crates/nlink/src/netlink/genl/dpll/events.rs`.
impl private::Sealed for super::genl::dpll::Dpll {}

impl EventSource for super::genl::dpll::Dpll {
    type Event = super::genl::dpll::DpllEvent;

    fn parse_events(data: &[u8]) -> Vec<Self::Event> {
        let mut events = Vec::new();
        for msg_result in MessageIter::new(data) {
            let Ok((_header, payload)) = msg_result else {
                continue;
            };
            if let Some(evt) = super::genl::dpll::events::parse_dpll_event(payload) {
                events.push(evt);
            }
        }
        events
    }
}

// OVPN multicast `peers` group events (Plan 197). Mirrors the
// DPLL pattern: forward-compat skip on parse errors, dispatch
// via the GENL header's cmd byte. See
// `Connection::<Ovpn>::subscribe_peers()` and
// `crates/nlink/src/netlink/genl/ovpn/events.rs`.
impl private::Sealed for super::genl::ovpn::Ovpn {}

impl EventSource for super::genl::ovpn::Ovpn {
    type Event = super::genl::ovpn::OvpnEvent;

    fn parse_events(data: &[u8]) -> Vec<Self::Event> {
        let mut events = Vec::new();
        for msg_result in MessageIter::new(data) {
            let Ok((_header, payload)) = msg_result else {
                continue;
            };
            if let Some(evt) = super::genl::ovpn::events::parse_ovpn_event(payload) {
                events.push(evt);
            }
        }
        events
    }
}

fn parse_ethtool_events(data: &[u8]) -> Vec<super::genl::ethtool::EthtoolEvent> {
    use super::genl::{GENL_HDRLEN, GenlMsgHdr};

    let mut events = Vec::new();

    for msg_result in MessageIter::new(data) {
        let Ok((header, payload)) = msg_result else {
            continue;
        };

        if header.is_error() || header.is_done() {
            continue;
        }

        // Parse GENL header
        if payload.len() < GENL_HDRLEN {
            continue;
        }

        let Some(genl_hdr) = GenlMsgHdr::from_bytes(payload) else {
            continue;
        };

        let cmd = genl_hdr.cmd;
        let attrs_data = &payload[GENL_HDRLEN..];

        if let Some(event) = parse_ethtool_event(cmd, attrs_data) {
            events.push(event);
        }
    }

    events
}

fn parse_ethtool_event(cmd: u8, data: &[u8]) -> Option<super::genl::ethtool::EthtoolEvent> {
    use super::{
        attr::AttrIter,
        genl::ethtool::{
            Channels, Coalesce, Duplex, EthtoolChannelsAttr, EthtoolCmd, EthtoolCoalesceAttr,
            EthtoolEvent, EthtoolFeaturesAttr, EthtoolHeaderAttr, EthtoolLinkinfoAttr,
            EthtoolLinkmodesAttr, EthtoolLinkstateAttr, EthtoolPauseAttr, EthtoolRingsAttr,
            Features, LinkExtState, LinkInfo, LinkModes, LinkState, MdiX, Pause, Port, Rings,
            Transceiver,
        },
    };

    // Helper to parse header
    fn parse_header(data: &[u8]) -> (Option<String>, Option<u32>) {
        let mut ifname = None;
        let mut ifindex = None;
        for (attr_type, payload) in AttrIter::new(data) {
            if attr_type == EthtoolHeaderAttr::DevName as u16 {
                ifname = Some(
                    std::str::from_utf8(payload)
                        .unwrap_or("")
                        .trim_end_matches('\0')
                        .to_string(),
                );
            } else if attr_type == EthtoolHeaderAttr::DevIndex as u16 && payload.len() >= 4 {
                ifindex = Some(u32::from_ne_bytes(payload[..4].try_into().unwrap()));
            }
        }
        (ifname, ifindex)
    }

    // Ethtool notifications use the same command IDs as their GET counterparts
    match cmd {
        c if c == EthtoolCmd::LinkinfoGet as u8 => {
            let mut info = LinkInfo::default();
            for (attr_type, payload) in AttrIter::new(data) {
                match attr_type {
                    t if t == EthtoolLinkinfoAttr::Header as u16 => {
                        let (name, idx) = parse_header(payload);
                        info.ifname = name;
                        info.ifindex = idx;
                    }
                    t if t == EthtoolLinkinfoAttr::Port as u16 && !payload.is_empty() => {
                        info.port = Some(Port::from_u8(payload[0]));
                    }
                    t if t == EthtoolLinkinfoAttr::Phyaddr as u16 && !payload.is_empty() => {
                        info.phyaddr = Some(payload[0]);
                    }
                    t if t == EthtoolLinkinfoAttr::TpMdiCtrl as u16 && !payload.is_empty() => {
                        info.tp_mdix_ctrl = Some(MdiX::from_u8(payload[0]));
                    }
                    t if t == EthtoolLinkinfoAttr::TpMdix as u16 && !payload.is_empty() => {
                        info.tp_mdix = Some(MdiX::from_u8(payload[0]));
                    }
                    t if t == EthtoolLinkinfoAttr::Transceiver as u16 && !payload.is_empty() => {
                        info.transceiver = Some(Transceiver::from_u8(payload[0]));
                    }
                    _ => {}
                }
            }
            Some(EthtoolEvent::LinkInfoChanged {
                ifname: info.ifname.clone(),
                info,
            })
        }
        c if c == EthtoolCmd::LinkmodesGet as u8 => {
            let mut modes = LinkModes::default();
            for (attr_type, payload) in AttrIter::new(data) {
                match attr_type {
                    t if t == EthtoolLinkmodesAttr::Header as u16 => {
                        let (name, idx) = parse_header(payload);
                        modes.ifname = name;
                        modes.ifindex = idx;
                    }
                    t if t == EthtoolLinkmodesAttr::Autoneg as u16 && !payload.is_empty() => {
                        modes.autoneg = payload[0] != 0;
                    }
                    t if t == EthtoolLinkmodesAttr::Speed as u16 && payload.len() >= 4 => {
                        let speed = u32::from_ne_bytes(payload[..4].try_into().unwrap());
                        if speed != 0xFFFFFFFF {
                            modes.speed = Some(speed);
                        }
                    }
                    t if t == EthtoolLinkmodesAttr::Duplex as u16 && !payload.is_empty() => {
                        modes.duplex = Some(Duplex::from_u8(payload[0]));
                    }
                    _ => {}
                }
            }
            Some(EthtoolEvent::LinkModesChanged {
                ifname: modes.ifname.clone(),
                modes,
            })
        }
        c if c == EthtoolCmd::LinkstateGet as u8 => {
            // LinkState doesn't have a dedicated NTF, but we handle it anyway
            let mut state = LinkState::default();
            for (attr_type, payload) in AttrIter::new(data) {
                match attr_type {
                    t if t == EthtoolLinkstateAttr::Header as u16 => {
                        let (name, idx) = parse_header(payload);
                        state.ifname = name;
                        state.ifindex = idx;
                    }
                    t if t == EthtoolLinkstateAttr::Link as u16 && !payload.is_empty() => {
                        state.link = payload[0] != 0;
                    }
                    t if t == EthtoolLinkstateAttr::Sqi as u16 && payload.len() >= 4 => {
                        state.sqi = Some(u32::from_ne_bytes(payload[..4].try_into().unwrap()));
                    }
                    t if t == EthtoolLinkstateAttr::SqiMax as u16 && payload.len() >= 4 => {
                        state.sqi_max = Some(u32::from_ne_bytes(payload[..4].try_into().unwrap()));
                    }
                    t if t == EthtoolLinkstateAttr::ExtState as u16 && !payload.is_empty() => {
                        state.ext_state = Some(LinkExtState::from_u8(payload[0]));
                    }
                    _ => {}
                }
            }
            Some(EthtoolEvent::LinkStateChanged {
                ifname: state.ifname.clone(),
                state,
            })
        }
        c if c == EthtoolCmd::FeaturesGet as u8 => {
            let mut features = Features::default();
            for (attr_type, payload) in AttrIter::new(data) {
                if attr_type == EthtoolFeaturesAttr::Header as u16 {
                    let (name, idx) = parse_header(payload);
                    features.ifname = name;
                    features.ifindex = idx;
                }
                // Note: full bitset parsing would require more complex handling
            }
            Some(EthtoolEvent::FeaturesChanged {
                ifname: features.ifname.clone(),
                features,
            })
        }
        c if c == EthtoolCmd::RingsGet as u8 => {
            let mut rings = Rings::default();
            for (attr_type, payload) in AttrIter::new(data) {
                match attr_type {
                    t if t == EthtoolRingsAttr::Header as u16 => {
                        let (name, idx) = parse_header(payload);
                        rings.ifname = name;
                        rings.ifindex = idx;
                    }
                    t if t == EthtoolRingsAttr::Rx as u16 && payload.len() >= 4 => {
                        rings.rx = Some(u32::from_ne_bytes(payload[..4].try_into().unwrap()));
                    }
                    t if t == EthtoolRingsAttr::Tx as u16 && payload.len() >= 4 => {
                        rings.tx = Some(u32::from_ne_bytes(payload[..4].try_into().unwrap()));
                    }
                    _ => {}
                }
            }
            Some(EthtoolEvent::RingsChanged {
                ifname: rings.ifname.clone(),
                rings,
            })
        }
        c if c == EthtoolCmd::ChannelsGet as u8 => {
            let mut channels = Channels::default();
            for (attr_type, payload) in AttrIter::new(data) {
                match attr_type {
                    t if t == EthtoolChannelsAttr::Header as u16 => {
                        let (name, idx) = parse_header(payload);
                        channels.ifname = name;
                        channels.ifindex = idx;
                    }
                    t if t == EthtoolChannelsAttr::CombinedCount as u16 && payload.len() >= 4 => {
                        channels.combined_count =
                            Some(u32::from_ne_bytes(payload[..4].try_into().unwrap()));
                    }
                    _ => {}
                }
            }
            Some(EthtoolEvent::ChannelsChanged {
                ifname: channels.ifname.clone(),
                channels,
            })
        }
        c if c == EthtoolCmd::CoalesceGet as u8 => {
            let mut coalesce = Coalesce::default();
            for (attr_type, payload) in AttrIter::new(data) {
                match attr_type {
                    t if t == EthtoolCoalesceAttr::Header as u16 => {
                        let (name, idx) = parse_header(payload);
                        coalesce.ifname = name;
                        coalesce.ifindex = idx;
                    }
                    t if t == EthtoolCoalesceAttr::RxUsecs as u16 && payload.len() >= 4 => {
                        coalesce.rx_usecs =
                            Some(u32::from_ne_bytes(payload[..4].try_into().unwrap()));
                    }
                    t if t == EthtoolCoalesceAttr::TxUsecs as u16 && payload.len() >= 4 => {
                        coalesce.tx_usecs =
                            Some(u32::from_ne_bytes(payload[..4].try_into().unwrap()));
                    }
                    _ => {}
                }
            }
            Some(EthtoolEvent::CoalesceChanged {
                ifname: coalesce.ifname.clone(),
                coalesce,
            })
        }
        c if c == EthtoolCmd::PauseGet as u8 => {
            let mut pause = Pause::default();
            for (attr_type, payload) in AttrIter::new(data) {
                match attr_type {
                    t if t == EthtoolPauseAttr::Header as u16 => {
                        let (name, idx) = parse_header(payload);
                        pause.ifname = name;
                        pause.ifindex = idx;
                    }
                    t if t == EthtoolPauseAttr::Autoneg as u16 && !payload.is_empty() => {
                        pause.autoneg = Some(payload[0] != 0);
                    }
                    t if t == EthtoolPauseAttr::Rx as u16 && !payload.is_empty() => {
                        pause.rx = Some(payload[0] != 0);
                    }
                    t if t == EthtoolPauseAttr::Tx as u16 && !payload.is_empty() => {
                        pause.tx = Some(payload[0] != 0);
                    }
                    _ => {}
                }
            }
            Some(EthtoolEvent::PauseChanged {
                ifname: pause.ifname.clone(),
                pause,
            })
        }
        _ => Some(EthtoolEvent::Unknown { cmd }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -------------------------------------------------------------
    // Plan 193 §2.3 — parse-error skip regression coverage.
    //
    // Per CLAUDE.md §"Parser robustness" rule 3, event parsers
    // walking `MessageIter::new(data)` must skip malformed
    // frames rather than propagate via `?`. One bad frame from
    // a future kernel must NOT kill a long-lived multicast
    // subscriber. These tests pin the contract.
    //
    // The audit script `scripts/audit-recv-loop-error-handling.sh`
    // is the CI-side defense (Plan 193 phase 1); these tests
    // are the runtime-side defense.
    // -------------------------------------------------------------

    /// Build a length-tagged netlink frame: nlmsg_len (u32) +
    /// nlmsg_type (u16) + flags (u16) + seq (u32) + pid (u32)
    /// + payload. Used for the parse_events skip tests.
    fn build_nl_frame(msg_type: u16, payload: &[u8]) -> Vec<u8> {
        // Netlink header is 16 bytes.
        let mut frame = Vec::with_capacity(16 + payload.len());
        let total_len = 16 + payload.len() as u32;
        frame.extend_from_slice(&total_len.to_ne_bytes());
        frame.extend_from_slice(&msg_type.to_ne_bytes());
        frame.extend_from_slice(&0u16.to_ne_bytes()); // flags
        frame.extend_from_slice(&0u32.to_ne_bytes()); // seq
        frame.extend_from_slice(&0u32.to_ne_bytes()); // pid
        frame.extend_from_slice(payload);
        // Align to 4 bytes.
        while frame.len() % 4 != 0 {
            frame.push(0);
        }
        frame
    }

    /// Build a frame with a header that claims more bytes than
    /// the actual buffer carries — `MessageIter` should report
    /// the truncation as an Err the event parser silently skips.
    fn build_truncated_frame(msg_type: u16, claimed_payload_size: usize) -> Vec<u8> {
        let mut frame = Vec::with_capacity(16);
        // Claim a payload size that goes beyond what we'll write.
        let total_len = (16 + claimed_payload_size) as u32;
        frame.extend_from_slice(&total_len.to_ne_bytes());
        frame.extend_from_slice(&msg_type.to_ne_bytes());
        frame.extend_from_slice(&0u16.to_ne_bytes());
        frame.extend_from_slice(&0u32.to_ne_bytes());
        frame.extend_from_slice(&0u32.to_ne_bytes());
        // ... but write NO payload bytes. Iter advances past
        // the header, then sees the buffer is too short.
        frame
    }

    #[test]
    fn route_parse_events_skips_unknown_msg_type() {
        // Build a frame with an unknown msg type. Per Plan 193
        // §2.3, the iterator surfaces it; parse_route_event
        // returns None; parse_events yields an empty vec rather
        // than panicking. Pins the kernel-version-forward
        // compatibility contract.
        let payload = vec![0u8; 16];
        let frame = build_nl_frame(0xFFFF, &payload);
        let events = Route::parse_events(&frame);
        assert!(events.is_empty(), "unknown msg-type must skip silently");
    }

    #[test]
    fn route_parse_events_skips_truncated_frame_without_panic() {
        // A frame that claims 100 bytes of payload but carries
        // 0. MessageIter should report the truncation; the
        // event parser ignores it and yields an empty vec.
        let frame = build_truncated_frame(NlMsgType::RTM_NEWLINK, 100);
        let events = Route::parse_events(&frame);
        // No panic, no infinite loop.
        let _: Vec<NetworkEvent> = events;
    }

    #[test]
    fn route_parse_events_skips_garbage_payload_on_known_msg_type() {
        // Known msg_type (RTM_NEWLINK) but a 4-byte payload
        // that won't satisfy IfInfoMsg::SIZE (16 bytes). The
        // typed parser returns Err; the event parser drops
        // the result via `.ok()` per the lib's parse contract.
        let bogus_payload = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let frame = build_nl_frame(NlMsgType::RTM_NEWLINK, &bogus_payload);
        let events = Route::parse_events(&frame);
        // The parser silently dropped the malformed frame —
        // exactly the "one malformed frame must NOT kill the
        // subscriber" contract.
        assert!(
            events.is_empty(),
            "malformed payload on known msg-type must skip"
        );
    }

    #[test]
    fn route_parse_events_handles_empty_buffer_without_loop() {
        // Empty data — must terminate immediately, not spin.
        let events = Route::parse_events(&[]);
        assert!(events.is_empty());
    }

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
