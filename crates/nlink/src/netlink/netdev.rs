//! Joining rtnetlink and uevents into one typed netdev lifecycle
//! (#253).
//!
//! nlink has two independent views of a network device coming into
//! existence, and neither is complete:
//!
//! * **rtnetlink** (`RTM_NEWLINK` / `RTM_DELLINK`) knows the ifindex,
//!   the flags, the MTU, the master, the kind — everything in the
//!   `IFLA_*` namespace. It knows nothing about the driver bind, the
//!   PCI or USB parent, or the sysfs path.
//! * **uevents** know the driver, the devpath, the bus parent, and the
//!   `add`/`bind`/`unbind`/`remove` lifecycle. They carry no link
//!   attributes at all.
//!
//! What makes the join tractable is that net-subsystem uevents carry
//! `IFINDEX=` and `INTERFACE=`: the two sources share a primary key.
//! [`NetdevLifecycle`] merges them into one [`NetdevEvent`] stream, and
//! optionally mirrors the result into a [`Store<u32, NetdevInfo>`] for
//! a watch-cache of fully attributed devices.
//!
//! # The four decisions this design rests on
//!
//! ## 1. rtnetlink is authoritative for existence; uevents annotate
//!
//! The kernel gives no ordering guarantee between the `RTM_NEWLINK` on
//! one socket and the matching `add@` uevent on another — either can
//! land first. Three ways out were on the table: emit on whichever
//! arrives first and follow up; buffer with a join window; or make one
//! side authoritative.
//!
//! This takes the third, with the first as its follow-up rule. A
//! device exists when rtnetlink says so, and [`NetdevEvent::Added`]
//! carries whatever annotation had already arrived — possibly none.
//! When the uevent half lands afterwards, it surfaces as a
//! [`NetdevEvent::Changed`] with the enriched
//! [`NetdevInfo`]. Buffering was rejected because it needs a latency
//! knob *and* a "the partner never arrived" timeout — and the partner
//! genuinely may never arrive: a device whose uevent predates the
//! subscription has no second announcement coming.
//!
//! The crack in the model is `bind`/`unbind`, which have no rtnetlink
//! counterpart at all. Those are emitted as
//! [`NetdevEvent::DriverBound`] / [`NetdevEvent::DriverUnbound`]
//! without requiring an rtnetlink partner. Read them as annotations of
//! a device's driver state, never as statements about whether the
//! device exists.
//!
//! ## 2. ifindex reuse is handled by name cross-check, not by trust
//!
//! Kernel ifindexes are recycled. A stale uevent for a dead ifindex
//! can arrive after a new device has claimed the same number, and a
//! join keyed on ifindex alone would silently attribute it to the
//! wrong device.
//!
//! Two things prevent that. An annotation is dropped when the device
//! is removed, so a recycled index starts clean. And because net
//! uevents carry `INTERFACE=`, an annotation held for an ifindex that
//! then turns up as a *new* device under a different name is discarded
//! as stale rather than attached.
//!
//! The name check is deliberately applied only on the
//! [`Added`](NetdevEvent::Added) transition. A rename emits both an
//! `RTM_NEWLINK` and a `move` uevent, and their order is not fixed —
//! enforcing the check on every event would throw away good
//! annotations during a rename. [`NetdevInfo::is_fully_attributed`]
//! reports whether the annotation's name currently agrees with
//! rtnetlink's, so a caller that wants to be strict can be.
//!
//! ## 3. The devpath is carried, never resolved
//!
//! `DEVPATH=` names a path in sysfs, and sysfs resolves in the calling
//! process's **mount** namespace — while the ifindex resolves in the
//! connection's **network** namespace. They are not the same
//! namespace, and nothing in this module may pretend otherwise. So
//! [`NetdevAnnotation::devpath`] is the string the kernel sent and
//! nothing more; this module never opens it. Resolving it is the
//! caller's business, in `util` (see
//! [`crate::util::uevent_trigger`]), under the caller's namespace
//! assumptions. The `scripts/audit-sysfs-in-lib.sh` CI gate enforces
//! the same rule mechanically.
//!
//! ## 4. Inside a namespace you see net uevents and nothing else
//!
//! Net-device uevents are delivered to the network namespace of the
//! listening socket. Uevents for every other subsystem go only to the
//! initial namespace. So a `NetdevLifecycle` running inside a netns
//! sees exactly what it needs and nothing more — but do not expect the
//! PCI-parent uevent of a device passed into that namespace to turn
//! up. It won't.
//!
//! # Frame loss
//!
//! The uevent side can drop frames under burst, and has no dump to
//! resync from (#252) — an annotation lost that way stays lost until
//! the device is re-announced. Size the receive buffer (which
//! [`Connection::<KobjectUevent>::new`] now does) and prefilter the
//! stream ([`crate::netlink::uevent_filter`]) so it doesn't come to
//! that. A cache built from this stream can be missing *annotations*;
//! it cannot be missing *devices*, since those come from rtnetlink.
//!
//! [`Connection::<KobjectUevent>::new`]: crate::netlink::Connection::new

use std::{
    collections::{HashMap, VecDeque},
    pin::Pin,
    task::{Context, Poll},
};

use tokio_stream::Stream;

use super::{events::NetworkEvent, reflector::Store, uevent::Uevent};
use crate::{LinkMessage, Result};

/// Subsystem value on the uevents this join consumes.
const NET_SUBSYSTEM: &str = "net";

/// What a uevent adds to rtnetlink's picture of a device.
///
/// Every field is exactly what the kernel put in the event's
/// environment. Nothing here has been resolved against sysfs — see
/// decision 3 in the module docs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetdevAnnotation {
    /// `DEVPATH=` — the device's path within sysfs, as a string. Not
    /// opened, not validated, not namespace-resolved.
    pub devpath: String,
    /// `INTERFACE=` — the interface name as of the uevent. Used to
    /// detect an annotation left over from a recycled ifindex.
    pub interface: Option<String>,
    /// `DRIVER=` — the bound driver, when the kernel names one.
    pub driver: Option<String>,
    /// `DEVTYPE=` — e.g. `bridge`, `vlan`, `veth`.
    pub devtype: Option<String>,
    /// `SEQNUM=` — monotonic within the uevent stream, which makes it
    /// useful for ordering annotations against each other. It says
    /// nothing about ordering against rtnetlink.
    pub seqnum: Option<u64>,
}

impl NetdevAnnotation {
    /// Build from a net-subsystem uevent. `None` when the event
    /// carries no `IFINDEX=`, which is the only key that makes the
    /// join possible.
    fn from_uevent(event: &Uevent) -> Option<(u32, Self)> {
        let ifindex = event.env.get("IFINDEX")?.parse().ok()?;
        Some((
            ifindex,
            Self {
                devpath: event.devpath.clone(),
                interface: event.env.get("INTERFACE").cloned(),
                driver: event.driver().map(str::to_string),
                devtype: event.devtype().map(str::to_string),
                seqnum: event.seqnum(),
            },
        ))
    }
}

/// A network device as both sources see it.
#[derive(Debug, Clone)]
pub struct NetdevInfo {
    link: LinkMessage,
    annotation: Option<NetdevAnnotation>,
}

impl NetdevInfo {
    /// Kernel ifindex — the join key, and the only identifier that is
    /// meaningful in a foreign namespace.
    pub fn ifindex(&self) -> u32 {
        self.link.ifindex()
    }

    /// Interface name according to rtnetlink.
    pub fn name(&self) -> Option<&str> {
        self.link.name()
    }

    /// The full rtnetlink view.
    pub fn link(&self) -> &LinkMessage {
        &self.link
    }

    /// The uevent view, when one has arrived.
    pub fn annotation(&self) -> Option<&NetdevAnnotation> {
        self.annotation.as_ref()
    }

    /// Bound driver, from the uevent side.
    pub fn driver(&self) -> Option<&str> {
        self.annotation.as_ref()?.driver.as_deref()
    }

    /// Sysfs devpath, from the uevent side. A string; see decision 3.
    pub fn devpath(&self) -> Option<&str> {
        Some(self.annotation.as_ref()?.devpath.as_str())
    }

    /// Whether both halves are present *and* agree on the interface
    /// name.
    ///
    /// False while an annotation is still missing, and false during
    /// the window between a rename's two announcements — which is the
    /// honest answer in both cases, and the reason this is a
    /// predicate rather than something enforced silently.
    pub fn is_fully_attributed(&self) -> bool {
        let Some(annotation) = &self.annotation else {
            return false;
        };
        match (annotation.interface.as_deref(), self.link.name()) {
            (Some(a), Some(b)) => a == b,
            // No name on one side to compare: having the annotation at
            // all is as attributed as this device gets.
            _ => true,
        }
    }
}

/// A device lifecycle transition, from either source.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum NetdevEvent {
    /// A device appeared, per rtnetlink. Carries the annotation if one
    /// had already arrived; expect a [`Changed`](Self::Changed) later
    /// if not.
    Added(NetdevInfo),
    /// An existing device changed — either rtnetlink reported new
    /// attributes, or the uevent half of an already-announced device
    /// arrived or was updated.
    Changed(NetdevInfo),
    /// A driver bound to the device. Uevent-only: rtnetlink has no
    /// equivalent, so this can arrive for an ifindex no `Added` has
    /// been emitted for.
    DriverBound {
        /// Kernel ifindex from `IFINDEX=`.
        ifindex: u32,
        /// The uevent's view of the device.
        annotation: NetdevAnnotation,
    },
    /// A driver unbound from the device. Uevent-only, as above.
    DriverUnbound {
        /// Kernel ifindex from `IFINDEX=`.
        ifindex: u32,
        /// The uevent's view of the device.
        annotation: NetdevAnnotation,
    },
    /// The device is gone, per rtnetlink. Any annotation held for this
    /// ifindex is dropped at the same time, so a recycled index starts
    /// clean.
    Removed {
        /// Kernel ifindex, now free to be reused.
        ifindex: u32,
        /// Last known interface name.
        name: Option<String>,
    },
}

impl NetdevEvent {
    /// The device this event describes, for the variants that carry
    /// one.
    pub fn info(&self) -> Option<&NetdevInfo> {
        match self {
            Self::Added(info) | Self::Changed(info) => Some(info),
            _ => None,
        }
    }

    /// Ifindex this event is about — present on every variant, since
    /// it is the join key.
    pub fn ifindex(&self) -> u32 {
        match self {
            Self::Added(info) | Self::Changed(info) => info.ifindex(),
            Self::DriverBound { ifindex, .. }
            | Self::DriverUnbound { ifindex, .. }
            | Self::Removed { ifindex, .. } => *ifindex,
        }
    }
}

/// Merged rtnetlink + uevent device lifecycle.
///
/// Build it from a link-event stream and a uevent stream, both already
/// subscribed. The two must come from **separate connections**: they
/// are different netlink protocols.
///
/// ```no_run
/// use nlink::netlink::{Connection, KobjectUevent, Route, RtnetlinkGroup};
/// use nlink::netlink::netdev::{NetdevEvent, NetdevLifecycle};
/// use nlink::netlink::uevent_filter::UeventFilter;
/// use tokio_stream::StreamExt;
///
/// # async fn demo() -> nlink::Result<()> {
/// let links = Connection::<Route>::new()?;
/// links.subscribe(&[RtnetlinkGroup::Link])?;
///
/// let uevents = Connection::<KobjectUevent>::new()?;
/// // Shed every non-net uevent in the kernel.
/// uevents.attach_filter(&UeventFilter::new().subsystem("net").build())?;
///
/// let mut lifecycle = NetdevLifecycle::new(links.events().await, uevents.events().await);
///
/// while let Some(event) = lifecycle.next().await {
///     match event? {
///         NetdevEvent::Added(info) => {
///             println!("{} ({:?}) driver={:?}", info.ifindex(), info.name(), info.driver());
///         }
///         other => println!("{other:?}"),
///     }
/// }
/// # Ok(())
/// # }
/// ```
pub struct NetdevLifecycle<L, U> {
    links: Option<L>,
    uevents: Option<U>,
    /// rtnetlink's authoritative view, keyed by ifindex.
    known: HashMap<u32, LinkMessage>,
    /// Uevent annotations, including ones that arrived before their
    /// rtnetlink partner.
    annotations: HashMap<u32, NetdevAnnotation>,
    /// Emitted events not yet handed to the caller.
    pending: VecDeque<NetdevEvent>,
    /// Optional watch-cache mirror.
    store: Option<Store<u32, NetdevInfo>>,
    /// Which source to poll first, flipped each wake-up so neither
    /// side can starve the other under sustained load.
    prefer_uevents: bool,
}

impl<L, U> NetdevLifecycle<L, U>
where
    L: Stream<Item = Result<NetworkEvent>> + Unpin,
    U: Stream<Item = Result<Uevent>> + Unpin,
{
    /// Merge a link-event stream and a uevent stream.
    pub fn new(links: L, uevents: U) -> Self {
        Self {
            links: Some(links),
            uevents: Some(uevents),
            known: HashMap::new(),
            annotations: HashMap::new(),
            pending: VecDeque::new(),
            store: None,
            prefer_uevents: false,
        }
    }

    /// Mirror the joined state into `store`, keyed by ifindex.
    ///
    /// The store is updated as each event is yielded, so a reader sees
    /// an entry no earlier than the consumer of this stream does.
    /// [`Store`] is cheap to clone and shares its backing map, so hand
    /// clones to readers and drive this stream from one task.
    ///
    /// Note what the cache can and cannot miss: devices come from
    /// rtnetlink, which has a dump to resync from, so the *set* of
    /// devices is sound. Annotations come from uevents, which have no
    /// dump — a device may sit in the store un-annotated indefinitely.
    /// [`NetdevInfo::is_fully_attributed`] tells them apart.
    pub fn with_store(mut self, store: Store<u32, NetdevInfo>) -> Self {
        self.store = Some(store);
        self
    }

    /// Devices seen so far, per rtnetlink.
    pub fn len(&self) -> usize {
        self.known.len()
    }

    /// Whether no device has been seen yet.
    pub fn is_empty(&self) -> bool {
        self.known.is_empty()
    }

    /// Build the joined view for an ifindex whose link is known.
    fn info(&self, ifindex: u32) -> Option<NetdevInfo> {
        Some(NetdevInfo {
            link: self.known.get(&ifindex)?.clone(),
            annotation: self.annotations.get(&ifindex).cloned(),
        })
    }

    fn on_link_event(&mut self, event: NetworkEvent) {
        match event {
            NetworkEvent::NewLink(link) => {
                let ifindex = link.ifindex();
                let first_sighting = !self.known.contains_key(&ifindex);

                if first_sighting {
                    // Decision 2: an annotation held for an ifindex
                    // that turns up as a *new* device under a
                    // different name is left over from the previous
                    // occupant of that index.
                    if let Some(stale) = self.annotations.get(&ifindex)
                        && let (Some(annotated), Some(actual)) =
                            (stale.interface.as_deref(), link.name())
                        && annotated != actual
                    {
                        tracing::debug!(
                            ifindex,
                            annotated,
                            actual,
                            "discarding uevent annotation from a recycled ifindex"
                        );
                        self.annotations.remove(&ifindex);
                    }
                }

                self.known.insert(ifindex, link);
                let Some(info) = self.info(ifindex) else {
                    return;
                };
                self.emit(if first_sighting {
                    NetdevEvent::Added(info)
                } else {
                    NetdevEvent::Changed(info)
                });
            }
            NetworkEvent::DelLink(link) => {
                let ifindex = link.ifindex();
                let name = self
                    .known
                    .remove(&ifindex)
                    .and_then(|l| l.name().map(str::to_string))
                    .or_else(|| link.name().map(str::to_string));
                // The index is free to be reused now; anything we know
                // about the old occupant must go with it.
                self.annotations.remove(&ifindex);
                self.emit(NetdevEvent::Removed { ifindex, name });
            }
            // Everything else on the link group is not this join's
            // business.
            _ => {}
        }
    }

    fn on_uevent(&mut self, event: Uevent) {
        if event.subsystem != NET_SUBSYSTEM {
            return;
        }
        let Some((ifindex, annotation)) = NetdevAnnotation::from_uevent(&event) else {
            // No IFINDEX= — nothing to join on. Net uevents carry it;
            // one that doesn't cannot be attributed to a device.
            tracing::debug!(devpath = %event.devpath, action = %event.action,
                            "net uevent without IFINDEX=; cannot join");
            return;
        };

        match event.action.as_str() {
            "remove" => {
                // rtnetlink's DelLink is authoritative for existence,
                // so this only retires the annotation.
                self.annotations.remove(&ifindex);
            }
            "bind" | "unbind" => {
                let bound = event.action == "bind";
                self.annotations.insert(ifindex, annotation.clone());
                self.emit(if bound {
                    NetdevEvent::DriverBound {
                        ifindex,
                        annotation,
                    }
                } else {
                    NetdevEvent::DriverUnbound {
                        ifindex,
                        annotation,
                    }
                });
            }
            _ => {
                let changed = self.annotations.get(&ifindex) != Some(&annotation);
                self.annotations.insert(ifindex, annotation);
                // Only surface an event once rtnetlink has announced
                // the device; otherwise this is the half that arrived
                // early and it will ride along on the `Added`.
                if changed && let Some(info) = self.info(ifindex) {
                    self.emit(NetdevEvent::Changed(info));
                }
            }
        }
    }

    fn emit(&mut self, event: NetdevEvent) {
        if let Some(store) = &self.store {
            match &event {
                NetdevEvent::Added(info) | NetdevEvent::Changed(info) => {
                    store.upsert(info.ifindex(), info.clone());
                }
                NetdevEvent::Removed { ifindex, .. } => {
                    store.remove(ifindex);
                }
                // Driver bind/unbind says nothing about whether the
                // device exists, so it must not create a cache entry.
                // The annotation reaches the store on the next
                // rtnetlink event for this device.
                _ => {}
            }
        }
        self.pending.push_back(event);
    }

    /// Poll one source, folding whatever it produced into state.
    /// Returns `Poll::Ready(Some(Err(_)))` to short-circuit on a
    /// stream error, `Poll::Ready(None)` when that source is done.
    fn poll_links(&mut self, cx: &mut Context<'_>) -> Poll<Option<Result<()>>> {
        let Some(links) = self.links.as_mut() else {
            return Poll::Ready(None);
        };
        match Pin::new(links).poll_next(cx) {
            Poll::Ready(Some(Ok(event))) => {
                self.on_link_event(event);
                Poll::Ready(Some(Ok(())))
            }
            Poll::Ready(Some(Err(e))) => Poll::Ready(Some(Err(e))),
            Poll::Ready(None) => {
                self.links = None;
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_uevents(&mut self, cx: &mut Context<'_>) -> Poll<Option<Result<()>>> {
        let Some(uevents) = self.uevents.as_mut() else {
            return Poll::Ready(None);
        };
        match Pin::new(uevents).poll_next(cx) {
            Poll::Ready(Some(Ok(event))) => {
                self.on_uevent(event);
                Poll::Ready(Some(Ok(())))
            }
            Poll::Ready(Some(Err(e))) => Poll::Ready(Some(Err(e))),
            Poll::Ready(None) => {
                self.uevents = None;
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<L, U> Unpin for NetdevLifecycle<L, U> {}

impl<L, U> Stream for NetdevLifecycle<L, U>
where
    L: Stream<Item = Result<NetworkEvent>> + Unpin,
    U: Stream<Item = Result<Uevent>> + Unpin,
{
    type Item = Result<NetdevEvent>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();

        loop {
            if let Some(event) = this.pending.pop_front() {
                return Poll::Ready(Some(Ok(event)));
            }
            if this.links.is_none() && this.uevents.is_none() {
                return Poll::Ready(None);
            }

            // Alternate which source goes first. Uevents can arrive in
            // long bursts (a coldplug storm), and always polling them
            // first would let one starve the link stream that decides
            // whether those events are even attributable.
            this.prefer_uevents = !this.prefer_uevents;
            let (first, second) = if this.prefer_uevents {
                (
                    Self::poll_uevents as fn(&mut Self, &mut Context<'_>) -> _,
                    Self::poll_links as fn(&mut Self, &mut Context<'_>) -> _,
                )
            } else {
                (
                    Self::poll_links as fn(&mut Self, &mut Context<'_>) -> _,
                    Self::poll_uevents as fn(&mut Self, &mut Context<'_>) -> _,
                )
            };

            let a = first(this, cx);
            if let Poll::Ready(Some(Err(e))) = a {
                return Poll::Ready(Some(Err(e)));
            }
            let b = second(this, cx);
            if let Poll::Ready(Some(Err(e))) = b {
                return Poll::Ready(Some(Err(e)));
            }

            // Only an actual item counts as progress. A source that
            // just *ended* must not, or the loop would spin: an ended
            // source keeps answering `Ready(None)` forever while the
            // other one sits pending.
            let produced = matches!(a, Poll::Ready(Some(Ok(()))))
                || matches!(b, Poll::Ready(Some(Ok(()))));
            if !produced {
                if this.links.is_none() && this.uevents.is_none() {
                    return Poll::Ready(None);
                }
                return Poll::Pending;
            }
            // A source produced something. Loop round: it may have
            // queued an event, and there may be more to drain.
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{cell::RefCell, rc::Rc, task::Waker};

    fn link(ifindex: u32, name: &str) -> LinkMessage {
        crate::netlink::messages::LinkMessageBuilder::new()
            .ifindex(ifindex as i32)
            .name(name)
            .build()
    }

    fn uevent(action: &str, ifindex: u32, interface: &str, driver: Option<&str>) -> Uevent {
        let mut env = HashMap::new();
        env.insert("ACTION".to_string(), action.to_string());
        env.insert("SUBSYSTEM".to_string(), "net".to_string());
        env.insert("IFINDEX".to_string(), ifindex.to_string());
        env.insert("INTERFACE".to_string(), interface.to_string());
        if let Some(driver) = driver {
            env.insert("DRIVER".to_string(), driver.to_string());
        }
        Uevent {
            action: action.to_string(),
            devpath: format!("/devices/virtual/net/{interface}"),
            subsystem: "net".to_string(),
            env,
        }
    }

    /// A hand-fed stream. The join's whole subject is the *order* in
    /// which two sockets deliver, so the tests need to place each
    /// item precisely — which `tokio_stream::iter` cannot do, since
    /// every one of its items is ready at once.
    #[derive(Clone)]
    struct Feed<T> {
        items: Rc<RefCell<VecDeque<Result<T>>>>,
        closed: Rc<RefCell<bool>>,
    }

    impl<T> Feed<T> {
        fn new() -> Self {
            Self {
                items: Rc::new(RefCell::new(VecDeque::new())),
                closed: Rc::new(RefCell::new(false)),
            }
        }

        fn push(&self, item: Result<T>) {
            self.items.borrow_mut().push_back(item);
        }

        fn close(&self) {
            *self.closed.borrow_mut() = true;
        }
    }

    impl<T: Unpin> Stream for Feed<T> {
        type Item = Result<T>;

        fn poll_next(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            if let Some(item) = self.items.borrow_mut().pop_front() {
                Poll::Ready(Some(item))
            } else if *self.closed.borrow() {
                Poll::Ready(None)
            } else {
                Poll::Pending
            }
        }
    }

    /// Drives the join by hand so each input's position is exact.
    struct Harness {
        lifecycle: NetdevLifecycle<Feed<NetworkEvent>, Feed<Uevent>>,
        links: Feed<NetworkEvent>,
        uevents: Feed<Uevent>,
    }

    impl Harness {
        fn new() -> Self {
            Self::with_store(None)
        }

        fn with_store(store: Option<Store<u32, NetdevInfo>>) -> Self {
            let links = Feed::new();
            let uevents = Feed::new();
            let mut lifecycle = NetdevLifecycle::new(links.clone(), uevents.clone());
            if let Some(store) = store {
                lifecycle = lifecycle.with_store(store);
            }
            Self {
                lifecycle,
                links,
                uevents,
            }
        }

        /// Poll to quiescence, returning everything emitted.
        fn drain(&mut self) -> Vec<NetdevEvent> {
            let waker = Waker::noop();
            let mut cx = Context::from_waker(waker);
            let mut out = Vec::new();
            loop {
                match Pin::new(&mut self.lifecycle).poll_next(&mut cx) {
                    Poll::Ready(Some(Ok(event))) => out.push(event),
                    Poll::Ready(Some(Err(e))) => panic!("unexpected stream error: {e}"),
                    Poll::Ready(None) | Poll::Pending => return out,
                }
            }
        }

        fn feed_link(&mut self, event: NetworkEvent) -> Vec<NetdevEvent> {
            self.links.push(Ok(event));
            self.drain()
        }

        fn feed_uevent(&mut self, event: Uevent) -> Vec<NetdevEvent> {
            self.uevents.push(Ok(event));
            self.drain()
        }
    }

    #[test]
    fn rtnetlink_alone_produces_added_without_an_annotation() {
        let mut h = Harness::new();
        let events = h.feed_link(NetworkEvent::NewLink(link(3, "veth0")));

        assert_eq!(events.len(), 1, "{events:?}");
        let NetdevEvent::Added(info) = &events[0] else {
            panic!("expected Added, got {:?}", events[0]);
        };
        assert_eq!(info.ifindex(), 3);
        assert_eq!(info.name(), Some("veth0"));
        assert!(info.annotation().is_none());
        assert!(!info.is_fully_attributed());
    }

    /// Decision 1's follow-up rule: the uevent half arriving second
    /// must surface as `Changed`, not be silently absorbed.
    #[test]
    fn late_uevent_surfaces_as_changed() {
        let mut h = Harness::new();
        assert!(matches!(
            h.feed_link(NetworkEvent::NewLink(link(3, "veth0")))[..],
            [NetdevEvent::Added(_)]
        ));

        let events = h.feed_uevent(uevent("add", 3, "veth0", Some("veth")));
        assert_eq!(events.len(), 1, "{events:?}");
        let NetdevEvent::Changed(info) = &events[0] else {
            panic!("expected Changed, got {:?}", events[0]);
        };
        assert_eq!(info.driver(), Some("veth"));
        assert_eq!(info.devpath(), Some("/devices/virtual/net/veth0"));
        assert!(info.is_fully_attributed());
    }

    /// The other order: a uevent that lands first is stashed, emits
    /// nothing on its own, and rides along on the `Added`.
    #[test]
    fn early_uevent_rides_along_on_added() {
        let mut h = Harness::new();
        let events = h.feed_uevent(uevent("add", 3, "veth0", Some("veth")));
        assert!(events.is_empty(), "{events:?}");

        let events = h.feed_link(NetworkEvent::NewLink(link(3, "veth0")));
        assert_eq!(events.len(), 1, "{events:?}");
        let NetdevEvent::Added(info) = &events[0] else {
            panic!("expected Added, got {:?}", events[0]);
        };
        assert_eq!(info.driver(), Some("veth"));
        assert!(info.is_fully_attributed());
    }

    /// A repeated uevent carrying nothing new must not manufacture a
    /// `Changed` — a coldplug re-announcement would otherwise churn
    /// every consumer.
    #[test]
    fn a_redundant_uevent_emits_nothing() {
        let mut h = Harness::new();
        h.feed_link(NetworkEvent::NewLink(link(3, "veth0")));
        assert_eq!(h.feed_uevent(uevent("add", 3, "veth0", Some("veth"))).len(), 1);

        let events = h.feed_uevent(uevent("add", 3, "veth0", Some("veth")));
        assert!(events.is_empty(), "{events:?}");
    }

    #[test]
    fn removal_reports_the_last_known_name() {
        let mut h = Harness::new();
        h.feed_link(NetworkEvent::NewLink(link(3, "veth0")));
        h.feed_uevent(uevent("add", 3, "veth0", Some("veth")));

        let events = h.feed_link(NetworkEvent::DelLink(link(3, "veth0")));
        assert_eq!(events.len(), 1, "{events:?}");
        let NetdevEvent::Removed { ifindex, name } = &events[0] else {
            panic!("expected Removed, got {:?}", events[0]);
        };
        assert_eq!(*ifindex, 3);
        assert_eq!(name.as_deref(), Some("veth0"));
    }

    /// Decision 2. The annotation from the index's previous occupant
    /// must not be inherited by the device that takes the index over.
    #[test]
    fn recycled_ifindex_does_not_inherit_a_stale_annotation() {
        let mut h = Harness::new();
        h.feed_link(NetworkEvent::NewLink(link(3, "veth0")));
        h.feed_uevent(uevent("add", 3, "veth0", Some("veth")));
        h.feed_link(NetworkEvent::DelLink(link(3, "veth0")));

        // A late uevent for the dead device, then a new device
        // claiming index 3.
        h.feed_uevent(uevent("change", 3, "veth0", Some("veth")));
        let events = h.feed_link(NetworkEvent::NewLink(link(3, "eth9")));

        assert_eq!(events.len(), 1, "{events:?}");
        let NetdevEvent::Added(info) = &events[0] else {
            panic!("expected Added, got {:?}", events[0]);
        };
        assert_eq!(info.name(), Some("eth9"));
        assert!(
            info.annotation().is_none(),
            "stale annotation attached: {:?}",
            info.annotation()
        );
    }

    /// ...and the check must not fire during a rename, where the two
    /// sources legitimately disagree for a moment.
    #[test]
    fn rename_keeps_the_annotation_but_reports_it_unverified() {
        let mut h = Harness::new();
        h.feed_link(NetworkEvent::NewLink(link(3, "veth0")));
        h.feed_uevent(uevent("add", 3, "veth0", Some("veth")));

        // Renamed; the matching `move` uevent has not arrived yet.
        let events = h.feed_link(NetworkEvent::NewLink(link(3, "veth1")));
        let NetdevEvent::Changed(info) = &events[0] else {
            panic!("expected Changed, got {:?}", events[0]);
        };
        assert_eq!(info.name(), Some("veth1"));
        // Annotation kept...
        assert_eq!(info.driver(), Some("veth"));
        // ...but flagged as not yet agreeing.
        assert!(!info.is_fully_attributed());

        // The `move` uevent settles it.
        let events = h.feed_uevent(uevent("move", 3, "veth1", Some("veth")));
        assert!(events[0].info().unwrap().is_fully_attributed());
    }

    /// Driver bind/unbind has no rtnetlink counterpart, so it must be
    /// emitted for an ifindex that was never `Added`.
    #[test]
    fn bind_and_unbind_are_emitted_without_an_rtnetlink_partner() {
        let mut h = Harness::new();
        let events = h.feed_uevent(uevent("bind", 7, "enp4s0", Some("igb")));
        assert!(
            matches!(events[..], [NetdevEvent::DriverBound { ifindex: 7, .. }]),
            "{events:?}"
        );

        let events = h.feed_uevent(uevent("unbind", 7, "enp4s0", Some("igb")));
        assert!(
            matches!(events[..], [NetdevEvent::DriverUnbound { ifindex: 7, .. }]),
            "{events:?}"
        );
    }

    /// A uevent `remove` retires the annotation but must not claim
    /// the device is gone — rtnetlink's `DelLink` is what says that.
    #[test]
    fn a_uevent_remove_retires_the_annotation_without_removing_the_device() {
        let mut h = Harness::new();
        h.feed_link(NetworkEvent::NewLink(link(3, "veth0")));
        assert_eq!(h.feed_uevent(uevent("add", 3, "veth0", Some("veth"))).len(), 1);

        // No event: existence is not this source's call.
        let events = h.feed_uevent(uevent("remove", 3, "veth0", Some("veth")));
        assert!(events.is_empty(), "{events:?}");

        // ...but the annotation is gone, so the next rtnetlink event
        // reports the device without it.
        let events = h.feed_link(NetworkEvent::NewLink(link(3, "veth0")));
        let info = events[0].info().unwrap();
        assert!(info.annotation().is_none());
        assert!(!info.is_fully_attributed());
    }

    /// A uevent with no `INTERFACE=` cannot be cross-checked, so
    /// having the annotation at all is as attributed as that device
    /// gets — reporting `false` would strand it forever.
    #[test]
    fn an_annotation_without_a_name_still_counts_as_attributed() {
        let mut h = Harness::new();
        h.feed_link(NetworkEvent::NewLink(link(3, "veth0")));

        let mut ev = uevent("add", 3, "veth0", Some("veth"));
        ev.env.remove("INTERFACE");
        let events = h.feed_uevent(ev);

        let info = events[0].info().unwrap();
        assert!(info.annotation().is_some());
        assert_eq!(info.annotation().unwrap().interface, None);
        assert!(info.is_fully_attributed());
    }

    /// The annotation is carried verbatim off the wire — in
    /// particular the devpath, which this module must never resolve.
    #[test]
    fn the_annotation_is_the_uevent_environment_verbatim() {
        let mut h = Harness::new();
        h.feed_link(NetworkEvent::NewLink(link(3, "veth0")));

        let mut ev = uevent("add", 3, "veth0", Some("veth"));
        ev.env.insert("DEVTYPE".to_string(), "veth".to_string());
        ev.env.insert("SEQNUM".to_string(), "4242".to_string());
        let events = h.feed_uevent(ev);

        let annotation = events[0].info().unwrap().annotation().unwrap();
        assert_eq!(annotation.devpath, "/devices/virtual/net/veth0");
        assert_eq!(annotation.interface.as_deref(), Some("veth0"));
        assert_eq!(annotation.driver.as_deref(), Some("veth"));
        assert_eq!(annotation.devtype.as_deref(), Some("veth"));
        assert_eq!(annotation.seqnum, Some(4242));
    }

    #[test]
    fn device_count_tracks_rtnetlink_only() {
        let mut h = Harness::new();
        assert!(h.lifecycle.is_empty());

        // A uevent alone must not count as a device.
        h.feed_uevent(uevent("add", 3, "veth0", Some("veth")));
        assert!(h.lifecycle.is_empty());

        h.feed_link(NetworkEvent::NewLink(link(3, "veth0")));
        h.feed_link(NetworkEvent::NewLink(link(4, "veth1")));
        assert_eq!(h.lifecycle.len(), 2);

        h.feed_link(NetworkEvent::DelLink(link(3, "veth0")));
        assert_eq!(h.lifecycle.len(), 1);
    }

    /// A `DelLink` for an ifindex the join never saw must still be
    /// reported — a consumer that subscribed mid-life has state for
    /// devices this stream never announced.
    #[test]
    fn removal_of_an_unknown_device_is_still_reported() {
        let mut h = Harness::new();
        let events = h.feed_link(NetworkEvent::DelLink(link(9, "ghost0")));
        let NetdevEvent::Removed { ifindex, name } = &events[0] else {
            panic!("expected Removed, got {:?}", events[0]);
        };
        assert_eq!(*ifindex, 9);
        assert_eq!(name.as_deref(), Some("ghost0"));
    }

    #[test]
    fn non_net_uevents_and_ifindexless_uevents_are_ignored() {
        let mut h = Harness::new();

        let mut usb = uevent("add", 1, "irrelevant", None);
        usb.subsystem = "usb".to_string();
        assert!(h.feed_uevent(usb).is_empty());

        let mut no_ifindex = uevent("add", 3, "veth0", None);
        no_ifindex.env.remove("IFINDEX");
        assert!(h.feed_uevent(no_ifindex).is_empty());
    }

    #[test]
    fn ifindex_is_available_on_every_variant() {
        let mut h = Harness::new();
        h.feed_link(NetworkEvent::NewLink(link(3, "veth0")));
        let events = h.feed_uevent(uevent("bind", 3, "veth0", Some("veth")));
        assert_eq!(events[0].ifindex(), 3);

        let events = h.feed_link(NetworkEvent::DelLink(link(3, "veth0")));
        assert_eq!(events[0].ifindex(), 3);
    }

    #[test]
    fn store_mirrors_the_joined_state() {
        let store: Store<u32, NetdevInfo> = Store::new();
        let mut h = Harness::with_store(Some(store.clone()));

        h.feed_link(NetworkEvent::NewLink(link(3, "veth0")));
        h.feed_link(NetworkEvent::NewLink(link(4, "veth1")));
        h.feed_uevent(uevent("add", 3, "veth0", Some("veth")));

        assert_eq!(store.len(), 2);
        assert_eq!(store.get(&3).unwrap().driver(), Some("veth"));
        assert!(store.get(&4).unwrap().annotation().is_none());

        h.feed_link(NetworkEvent::DelLink(link(3, "veth0")));
        assert_eq!(store.len(), 1);
        assert!(!store.contains_key(&3));
    }

    /// A bind for an unknown ifindex must not conjure a cache entry —
    /// it says nothing about whether the device exists.
    #[test]
    fn store_ignores_driver_events_for_unknown_devices() {
        let store: Store<u32, NetdevInfo> = Store::new();
        let mut h = Harness::with_store(Some(store.clone()));

        h.feed_uevent(uevent("bind", 7, "enp4s0", Some("igb")));
        assert!(store.is_empty());
    }

    #[test]
    fn errors_from_either_source_propagate() {
        let waker = Waker::noop();
        let mut cx = Context::from_waker(waker);

        let mut h = Harness::new();
        h.links
            .push(Err(crate::Error::InvalidMessage("boom".into())));
        assert!(matches!(
            Pin::new(&mut h.lifecycle).poll_next(&mut cx),
            Poll::Ready(Some(Err(_)))
        ));

        let mut h = Harness::new();
        h.uevents
            .push(Err(crate::Error::InvalidMessage("boom".into())));
        assert!(matches!(
            Pin::new(&mut h.lifecycle).poll_next(&mut cx),
            Poll::Ready(Some(Err(_)))
        ));
    }

    /// One source ending must leave the other running — and must not
    /// spin: an ended stream answers `Ready(None)` forever, so
    /// counting that as progress would busy-loop the poll.
    #[test]
    fn one_source_ending_does_not_end_or_spin_the_join() {
        let mut h = Harness::new();
        h.uevents.close();

        let events = h.feed_link(NetworkEvent::NewLink(link(3, "veth0")));
        assert!(matches!(events[..], [NetdevEvent::Added(_)]), "{events:?}");

        // Still pending, not terminated.
        assert!(h.drain().is_empty());

        // Both closed: now the stream ends.
        h.links.close();
        let waker = Waker::noop();
        let mut cx = Context::from_waker(waker);
        assert!(matches!(
            Pin::new(&mut h.lifecycle).poll_next(&mut cx),
            Poll::Ready(None)
        ));
    }

    #[test]
    fn link_events_other_than_new_and_del_are_ignored() {
        let mut h = Harness::new();
        let events = h.feed_link(NetworkEvent::NewRoute(Default::default()));
        assert!(events.is_empty(), "{events:?}");
        assert!(h.lifecycle.is_empty());
    }
}
