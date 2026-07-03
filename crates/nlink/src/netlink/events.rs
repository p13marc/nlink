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
//! let conn = Connection::<Route>::new()?;
//! conn.subscribe(&[RtnetlinkGroup::Link, RtnetlinkGroup::Tc])?;
//!
//! let mut events = conn.events().await;
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

use super::{
    fdb::FdbEntry,
    mdb::MdbEntry,
    messages::{
        AddressMessage, LinkMessage, NeighborMessage, NsIdMessage, RouteMessage, RuleMessage,
        TcMessage,
    },
    nexthop::Nexthop,
};

/// Network events that can be received from the kernel.
///
/// These events are generated when network configuration changes occur.
/// Use [`Connection<Route>::subscribe`](super::Connection::subscribe) to select
/// which event types to receive, then use [`Connection::events`](super::Connection::events)
/// to get a stream of events.
#[derive(Debug, Clone)]
#[non_exhaustive]
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

    // FDB (bridge forwarding database) events
    /// A new FDB entry was added or learned.
    NewFdb(FdbEntry),
    /// An FDB entry was removed.
    DelFdb(FdbEntry),

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

    // Policy-routing rule events (RTM_NEWRULE / RTM_DELRULE).
    // Subscribe via `RtnetlinkGroup::{Ipv4Rule, Ipv6Rule}`.
    /// A new policy-routing rule was added.
    NewRule(RuleMessage),
    /// A policy-routing rule was removed.
    DelRule(RuleMessage),

    // Nexthop-object events (RTM_NEWNEXTHOP / RTM_DELNEXTHOP).
    // Subscribe via `RtnetlinkGroup::Nexthop`.
    /// A new nexthop object was added or changed.
    NewNexthop(Nexthop),
    /// A nexthop object was removed.
    DelNexthop(Nexthop),

    // Network-namespace ID events (RTM_NEWNSID / RTM_DELNSID).
    // Subscribe via `RtnetlinkGroup::NsId`.
    /// A network-namespace ID was assigned.
    NewNsId(NsIdMessage),
    /// A network-namespace ID was released.
    DelNsId(NsIdMessage),

    // Bridge multicast-database events (RTM_NEWMDB / RTM_DELMDB).
    // Subscribe via `RtnetlinkGroup::Mdb`.
    /// A bridge MDB entry was added or learned.
    NewMdb(MdbEntry),
    /// A bridge MDB entry was removed.
    DelMdb(MdbEntry),
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
                | NetworkEvent::NewFdb(_)
                | NetworkEvent::NewQdisc(_)
                | NetworkEvent::NewClass(_)
                | NetworkEvent::NewFilter(_)
                | NetworkEvent::NewAction(_)
                | NetworkEvent::NewRule(_)
                | NetworkEvent::NewNexthop(_)
                | NetworkEvent::NewNsId(_)
                | NetworkEvent::NewMdb(_)
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
            NetworkEvent::NewFdb(m) | NetworkEvent::DelFdb(m) => Some(m.ifindex),
            NetworkEvent::NewQdisc(m)
            | NetworkEvent::DelQdisc(m)
            | NetworkEvent::NewClass(m)
            | NetworkEvent::DelClass(m)
            | NetworkEvent::NewFilter(m)
            | NetworkEvent::DelFilter(m)
            | NetworkEvent::NewAction(m)
            | NetworkEvent::DelAction(m) => Some(m.ifindex()),
            NetworkEvent::NewNexthop(m) | NetworkEvent::DelNexthop(m) => m.ifindex(),
            NetworkEvent::NewMdb(m) | NetworkEvent::DelMdb(m) => Some(m.port_ifindex),
            NetworkEvent::NewRoute(_)
            | NetworkEvent::DelRoute(_)
            | NetworkEvent::NewRule(_)
            | NetworkEvent::DelRule(_)
            | NetworkEvent::NewNsId(_)
            | NetworkEvent::DelNsId(_) => None,
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

    /// Returns the inner FdbEntry if this is an FDB event.
    pub fn as_fdb(&self) -> Option<&FdbEntry> {
        match self {
            NetworkEvent::NewFdb(m) | NetworkEvent::DelFdb(m) => Some(m),
            _ => None,
        }
    }

    /// Consumes self and returns the inner FdbEntry if this is an FDB event.
    pub fn into_fdb(self) -> Option<FdbEntry> {
        match self {
            NetworkEvent::NewFdb(m) | NetworkEvent::DelFdb(m) => Some(m),
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

    /// Returns the inner RuleMessage if this is a policy-routing rule event.
    pub fn as_rule(&self) -> Option<&RuleMessage> {
        match self {
            NetworkEvent::NewRule(m) | NetworkEvent::DelRule(m) => Some(m),
            _ => None,
        }
    }

    /// Consumes self and returns the inner RuleMessage if this is a rule event.
    pub fn into_rule(self) -> Option<RuleMessage> {
        match self {
            NetworkEvent::NewRule(m) | NetworkEvent::DelRule(m) => Some(m),
            _ => None,
        }
    }

    /// Returns the inner Nexthop if this is a nexthop-object event.
    pub fn as_nexthop(&self) -> Option<&Nexthop> {
        match self {
            NetworkEvent::NewNexthop(m) | NetworkEvent::DelNexthop(m) => Some(m),
            _ => None,
        }
    }

    /// Consumes self and returns the inner Nexthop if this is a nexthop event.
    pub fn into_nexthop(self) -> Option<Nexthop> {
        match self {
            NetworkEvent::NewNexthop(m) | NetworkEvent::DelNexthop(m) => Some(m),
            _ => None,
        }
    }

    /// Returns the inner NsIdMessage if this is a namespace-ID event.
    pub fn as_nsid(&self) -> Option<&NsIdMessage> {
        match self {
            NetworkEvent::NewNsId(m) | NetworkEvent::DelNsId(m) => Some(m),
            _ => None,
        }
    }

    /// Consumes self and returns the inner NsIdMessage if this is a namespace-ID event.
    pub fn into_nsid(self) -> Option<NsIdMessage> {
        match self {
            NetworkEvent::NewNsId(m) | NetworkEvent::DelNsId(m) => Some(m),
            _ => None,
        }
    }

    /// Returns the inner MdbEntry if this is a bridge MDB event.
    pub fn as_mdb(&self) -> Option<&MdbEntry> {
        match self {
            NetworkEvent::NewMdb(m) | NetworkEvent::DelMdb(m) => Some(m),
            _ => None,
        }
    }

    /// Consumes self and returns the inner MdbEntry if this is a bridge MDB event.
    pub fn into_mdb(self) -> Option<MdbEntry> {
        match self {
            NetworkEvent::NewMdb(m) | NetworkEvent::DelMdb(m) => Some(m),
            _ => None,
        }
    }
}
