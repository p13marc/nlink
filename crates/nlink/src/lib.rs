//! Async netlink library for Linux network configuration.
//!
//! This crate provides a complete netlink implementation for programmatic
//! network management on Linux. It supports RTNetlink (routing), traffic
//! control, socket diagnostics, and TUN/TAP device management.
//!
//! # Features
//!
//! - `sockdiag` - Socket diagnostics via NETLINK_SOCK_DIAG
//! - `tuntap` - TUN/TAP device management
//! - `tuntap-async` - Async TUN/TAP support (implies `tuntap`)
//! - `tc` - Traffic control utilities
//! - `output` - JSON/text output formatting
//! - `full` - All features enabled
//!
//! # Example
//!
//! ```ignore
//! use nlink::netlink::{Connection, Route};
//!
//! #[tokio::main]
//! async fn main() -> nlink::netlink::Result<()> {
//!     let conn = Connection::<Route>::new()?;
//!
//!     // Query interfaces
//!     let links = conn.get_links().await?;
//!     for link in &links {
//!         // Use name_or() helper for cleaner code
//!         println!("{}: {}", link.ifindex(), link.name_or("?"));
//!     }
//!
//!     // Build ifindex -> name map for resolving routes/addresses
//!     let names = conn.get_interface_names().await?;
//!
//!     Ok(())
//! }
//! ```
//!
//! # Link State Management
//!
//! ```ignore
//! use nlink::netlink::{Connection, Route};
//!
//! let conn = Connection::<Route>::new()?;
//!
//! // Bring an interface up
//! conn.set_link_up("eth0").await?;
//!
//! // Bring it down
//! conn.set_link_down("eth0").await?;
//!
//! // Set MTU
//! conn.set_link_mtu("eth0", 9000).await?;
//! ```
//!
//! # Network Namespace Support
//!
//! Operations can be performed in specific network namespaces:
//!
//! ```ignore
//! use nlink::netlink::{Connection, Route, Generic};
//! use nlink::netlink::namespace;
//!
//! // Connect to a named namespace (created via `ip netns add myns`)
//! // Functions are generic over protocol type
//! let conn: Connection<Route> = namespace::connection_for("myns")?;
//! let links = conn.get_links().await?;
//!
//! // Or connect to a container's namespace
//! let conn: Connection<Route> = namespace::connection_for_pid(container_pid)?;
//! let links = conn.get_links().await?;
//!
//! // Or use a path directly
//! let conn: Connection<Route> = namespace::connection_for_path("/proc/1234/ns/net")?;
//!
//! // Generic connections work too (e.g., for WireGuard in a namespace)
//! let genl: Connection<Generic> = namespace::connection_for("myns")?;
//! ```
//!
//! ## Namespace safety — `_by_index` vs `_by_name`
//!
//! Every resource lookup that takes an interface comes in two
//! flavors: `*_by_index(ifindex: u32)` and `*_by_name(name: &str)`.
//! The `_by_index` form is **always** safe to call from any process
//! mount namespace — the kernel ifindex is relative to the
//! connection's netns, no userspace resolution needed. The
//! `_by_name` form reads `/sys/class/net/` from the **calling
//! process's mount namespace**, which is convenient for simple
//! cases but surprises inside foreign netns (CNI plugins,
//! multi-tenant managers, integration-test harnesses).
//!
//! For namespace-aware code, the canonical pattern is:
//!
//! ```ignore
//! use nlink::{Connection, Route};
//! let conn = Connection::<Route>::new()?;
//! // One name resolution at startup, then ifindex everywhere:
//! let eth0_idx = conn.get_link_by_name("eth0").await?
//!     .ok_or(nlink::Error::InterfaceNotFound { name: "eth0".into() })?
//!     .ifindex();
//! conn.set_link_mtu_by_index(eth0_idx, 9000).await?;
//! ```
//!
//! This is a deliberate design choice. `neli` and
//! `vishvananda/netlink` both leave namespace handling to the
//! caller — a documented footgun in
//! [Cilium issue #40280](https://github.com/cilium/cilium/issues/40280).
//! nlink's typed `InterfaceRef::Index(u32)` plus the per-method
//! `_by_index` variants make namespace-correct code natural to
//! write, while `_by_name` stays available as the deliberate
//! convenience choice.
//!
//! # Event Monitoring
//!
//! Use `Connection::subscribe()` to select event types, then `events()` to get a stream:
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
//! # Multi-Namespace Event Monitoring
//!
//! Use `tokio_stream::StreamMap` to monitor multiple namespaces:
//!
//! ```ignore
//! use nlink::netlink::{Connection, Route, RtnetlinkGroup};
//! use tokio_stream::{StreamExt, StreamMap};
//!
//! let mut streams = StreamMap::new();
//!
//! let mut conn1 = Connection::<Route>::new()?;
//! conn1.subscribe_all()?;
//! streams.insert("default", conn1.into_events());
//!
//! let mut conn2 = Connection::<Route>::new_in_namespace("ns1")?;
//! conn2.subscribe_all()?;
//! streams.insert("ns1", conn2.into_events());
//!
//! while let Some((ns, event)) = streams.next().await {
//!     println!("[{}] {:?}", ns, event?);
//! }
//! ```

// The Plan 154 derive macros generate code referencing
// `::nlink::macros::__rt::*` so the same expansion works
// uniformly from any downstream crate. Inside `nlink` itself
// that path would fail to resolve (no external crate named
// `nlink` from our own perspective); this `extern crate self as
// nlink` aliases the crate to its own external name so generated
// paths work here too. Required for the in-tree derive tests in
// `crate::macros::tests`.
extern crate self as nlink;

// Core modules (always available)
pub mod macros;
pub mod netlink;
pub mod prelude;
pub mod util;

// Feature-gated modules
#[cfg(feature = "sockdiag")]
pub mod sockdiag;

#[cfg(feature = "tuntap")]
pub mod tuntap;

#[cfg(feature = "output")]
pub mod output;

#[cfg(feature = "lab")]
pub mod lab;

// Re-export common types at crate root for convenience
// Namespace types
// Event types
// Route protocol multicast groups
// Bridge VLAN types
pub use netlink::bridge_vlan::{BridgeVlanBuilder, BridgeVlanEntry, BridgeVlanFlags};
// Diagnostics types
pub use netlink::diagnostics::{
    Bottleneck, BottleneckType, ConnectivityReport, DiagnosticReport, Diagnostics,
    DiagnosticsConfig, InterfaceDiag, Issue, IssueCategory, IssueStream, LinkRates, RouteDiag,
    RouteInfo, Severity, TcDiag,
};
// FDB types
pub use netlink::fdb::{FdbEntry, FdbEntryBuilder};
// Per-peer impairment helper
pub use netlink::impair::{PeerImpairment, PeerMatch, PerPeerImpairer};
// Message types (commonly used)
pub use netlink::messages::{
    AddressMessage,
    // Type aliases for TcMessage
    ClassMessage,
    FilterMessage,
    LinkMessage,
    NeighborMessage,
    QdiscMessage,
    RouteMessage,
    RuleMessage,
    TcMessage,
};
// Sealed trait formalizing the `parse_params` contract on every typed TC
// config. Inherent methods stay; the trait is for generic dispatch.
pub use netlink::parse_params::ParseParams;
// Strongly-typed TC handle and filter priority — use these in new code at
// public boundaries instead of raw &str / u16.
pub use netlink::tc_handle::{FilterPriority, TcHandle, TcHandleParseError};
// Reconcile-pattern types shared by recipe helpers.
pub use netlink::tc_recipe::{ReconcileOptions, ReconcileReport, StaleObject, UnmanagedObject};
pub use netlink::{
    Connection, Error, NamespaceSpec, NetworkEvent, Protocol, Result, RtnetlinkGroup,
};
// Stream-based event API
pub use netlink::{EventSource, EventSubscription, OwnedEventStream};
// Protocol state types
pub use netlink::{Generic, Nftables, Route, Wireguard};
// Strongly-typed unit types (rate, byte, percent values used at TC API
// boundaries). Use these in new code; the kernel's unit confusion (bits/sec
// vs bytes/sec, decimal vs binary) is handled at type construction.
pub use util::{Bytes, Percent, Rate};

// ---- Plan 148 §4.3 re-export hygiene ----------------------------------
// The route / address / rule builders and the extension traits users
// implement to add custom link/addr/route/neighbor types. Previously
// reachable only via deep `nlink::netlink::route::Ipv4Route`-style
// paths; surface them at the crate root for shorter imports.

// Route builders + nested types.
pub use netlink::route::{Ipv4Route, Ipv6Route, NextHop, RouteConfig, RouteMetrics};
// Address builders + extension trait.
pub use netlink::addr::{AddressConfig, Ipv4Address, Ipv6Address};
// Rule builder.
pub use netlink::rule::RuleBuilder;
// Link + neighbor extension traits for custom impl.
pub use netlink::link::LinkConfig;
pub use netlink::neigh::NeighborConfig;

// Connection pool (Plan 159) — bounded mpsc-channel-backed pool
// for high-fanout consumers.
pub use netlink::pool::{ConnectionPool, ConnectionPoolBuilder, PooledConnection};

// ENOBUFS resync helper types (Plan 151) — sum type yielded by a
// resync-aware event consumer, plus boundary markers, plus the
// pre-baked Stream wrapper (Plan 151 closeout). Plan 185 added
// the generic `ConnectionFactory<P>` / `ConnectionFuture<P>` —
// the boxed closure shape protocol-specific resync wrappers
// (e.g. `Connection<Nftables>::into_events_with_resync`) consume
// to materialise a fresh unicast connection on every ENOBUFS.
pub use netlink::resync::{
    ConnectionFactory, ConnectionFuture, ResyncMarker, ResyncStream, ResyncedEvent,
    events_with_resync,
};

// Streaming dump API (Plan 149) — yield typed netlink dump
// messages one at a time.
pub use netlink::dump_stream::DumpStream;

// nftables flowtable (Plan 150) — flow-table fast path for the
// netfilter conntrack-cached forwarding bypass.
pub use netlink::nftables::Flowtable;

// Declarative nftables config (Plan 157) — diff + apply for
// tables/chains/rules/flowtables, mirroring NetworkConfig's shape.
pub use netlink::nftables::config::{
    DeclaredChain, DeclaredFlowtable, DeclaredRule, DeclaredTable, NftablesConfig,
    NftablesDiff,
};

// XFRM IPsec hardware offload (Plan 153.1) — request kernel push
// SA crypto/packet path onto NIC hardware.
pub use netlink::xfrm::{XfrmOffloadFlag, XfrmUserOffload};
