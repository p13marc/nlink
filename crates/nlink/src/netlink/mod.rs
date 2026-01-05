//! Async netlink protocol implementation for Linux.
//!
//! This module provides a complete netlink implementation from scratch,
//! supporting RTNetlink (routing), traffic control, and other subsystems.
//!
//! # Quick Start
//!
//! ```ignore
//! use nlink::netlink::{Connection, Route};
//!
//! let conn = Connection::<Route>::new()?;
//!
//! // Query interfaces
//! let links = conn.get_links().await?;
//! for link in &links {
//!     println!("{}: {}", link.ifindex(), link.name_or("?"));
//! }
//!
//! // Build ifindex -> name map for resolving routes/addresses
//! let names = conn.get_interface_names().await?;
//! ```
//!
//! # Event Monitoring
//!
//! Subscribe to multicast groups and use the stream API to monitor events:
//!
//! ```ignore
//! use nlink::netlink::{Connection, Route, RtnetlinkGroup, NetworkEvent};
//! use tokio_stream::StreamExt;
//!
//! let mut conn = Connection::<Route>::new()?;
//! conn.subscribe(&[RtnetlinkGroup::Link, RtnetlinkGroup::Ipv4Addr])?;
//!
//! let mut events = conn.events();
//! while let Some(event) = events.next().await {
//!     match event? {
//!         NetworkEvent::NewLink(link) => println!("New link: {:?}", link.name),
//!         NetworkEvent::NewAddress(addr) => println!("New address: {:?}", addr.address),
//!         _ => {}
//!     }
//! }
//! ```
//!
//! # Traffic Control (TC)
//!
//! The `tc` module provides typed configuration for qdiscs:
//!
//! ```ignore
//! use nlink::netlink::tc::NetemConfig;
//! use std::time::Duration;
//!
//! // Add network emulation with delay and packet loss
//! let netem = NetemConfig::new()
//!     .delay(Duration::from_millis(100))
//!     .jitter(Duration::from_millis(10))
//!     .loss(1.0)  // 1% packet loss
//!     .build();
//!
//! conn.add_qdisc("eth0", netem).await?;
//!
//! // Update the configuration
//! let updated = NetemConfig::new()
//!     .delay(Duration::from_millis(50))
//!     .build();
//! conn.change_qdisc("eth0", "root", updated).await?;
//!
//! // Delete the qdisc
//! conn.del_qdisc("eth0", "root").await?;
//! ```

pub mod action;
pub mod addr;
pub mod attr;
pub mod audit;
pub mod bridge_vlan;
mod builder;
pub mod config;
pub mod connection;
pub mod connector;
pub mod diagnostics;
mod error;
pub mod events;
pub mod fdb;
pub mod fib_lookup;
pub mod filter;
#[cfg(test)]
mod fixtures;
pub mod genl;
pub mod link;
pub mod message;
pub mod messages;
pub mod mpls;
pub mod namespace;
pub mod namespace_events;
#[cfg(feature = "namespace_watcher")]
pub mod namespace_watcher;
pub mod neigh;
pub mod netfilter;
pub mod nexthop;
pub mod parse;
mod protocol;
pub mod ratelimit;
pub mod route;
pub mod rule;
pub mod selinux;
#[cfg(feature = "sockdiag")]
mod sockdiag;
mod socket;
pub mod srv6;
pub mod stats;
mod stream;
pub mod tc;
pub mod tc_options;
pub mod types;
pub mod uevent;
pub mod xfrm;

pub use attr::{AttrIter, NlAttr};
pub use builder::{MessageBuilder, NestToken};
pub use connection::{Connection, RtnetlinkGroup};
pub use error::{Error, Result};
pub use events::NetworkEvent;
pub use message::{MessageIter, NLMSG_HDRLEN, NlMsgHdr, NlMsgType};
pub use namespace::NamespaceSpec;
pub use namespace_events::{NamespaceEventSubscriber, NamespaceNetlinkEvent};
#[cfg(feature = "namespace_watcher")]
pub use namespace_watcher::{
    NamespaceEvent, NamespaceEventStream, NamespaceWatcher, NamespaceWatcherConfig,
};
pub use parse::{FromNetlink, ToNetlink};
pub use protocol::{
    Audit, Connector, Ethtool, FibLookup, Generic, KobjectUevent, Macsec, Mptcp, Netfilter,
    ProtocolState, Route, SELinux, SockDiag, Wireguard, Xfrm,
};
pub use socket::{NetlinkSocket, Protocol, rtnetlink_groups};
pub use stream::{EventSource, EventSubscription, OwnedEventStream};
pub use tc_options::NetemParameter;
