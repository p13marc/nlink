//! Link-kind parameters: what the kernel holds for a declared link's kind
//! (a VLAN's id, a VXLAN's VNI, a bond's mode, …), compared with the
//! declaration, and what an apply has to do when they differ.
//!
//! Until #417 the diff compared a link's MTU, MAC, master and state and
//! nothing about its kind, so a changed VNI, VLAN id or bond mode on an
//! existing link was an empty diff and the kernel kept the old value.
//!
//! A parameter that differs is either changed in place — an
//! `RTM_NEWLINK` carrying only `IFLA_LINKINFO`, which `rtnl_newlink` hands
//! to the kind's `changelink` — or, where that `changelink` refuses or
//! silently ignores it, by deleting the link and creating it again. Which
//! is which was read from the kernel source (v6.12) per parameter:
//!
//! | Parameter | Kernel | Here |
//! |---|---|---|
//! | VLAN id, protocol | `vlan_changelink` applies only `IFLA_VLAN_FLAGS` and the QoS maps; it ignores `IFLA_VLAN_ID`/`IFLA_VLAN_PROTOCOL` and returns 0 | recreate |
//! | VLAN / macvlan lower device | nothing changes `IFLA_LINK` on a live link | recreate |
//! | VXLAN VNI, port | `vxlan_nl2conf`: "Cannot change VNI", "Cannot change port" (EOPNOTSUPP) | recreate |
//! | VXLAN remote, local, same family | `vxlan_nl2conf` takes them | in place |
//! | VXLAN address family | `vxlan_nl2conf`: "New group address family does not match old group" (EOPNOTSUPP) | recreate |
//! | VXLAN lower device, set or moved | `vxlan_changelink` moves it (`netdev_adjacent_change_*`) | in place |
//! | VXLAN lower device, removed | `vxlan_config_apply` only assigns `remote_ifindex` when there is a new lower device, so the old one stays | recreate |
//! | bond mode | `BOND_OPT_MODE` is `BOND_OPTFLAG_NOSLAVES \| BOND_OPTFLAG_IFDOWN` | recreate |
//! | bond `lacp_rate`, `ad_select` | `BOND_OPTFLAG_IFDOWN`: EBUSY on a bond that is up | recreate |
//! | bond `miimon`, `updelay`, `downdelay`, `xmit_hash_policy`, `min_links`, `resend_igmp` | no flags | in place |
//! | macvlan mode | `macvlan_changelink` takes it, except into or out of passthru (EINVAL) | in place / recreate |
//! | VRF table | `vrf_link_ops` has no `changelink`, so `rtnl_newlink` answers EOPNOTSUPP | recreate |
//! | netkit policies | `netkit_change_link` takes them on the primary | in place |
//! | netkit mode, scrub | `netkit_change_link`: "cannot be changed after device creation" (EACCES) | refused |
//! | the kind itself | — | recreate |
//!
//! A recreate deletes the link, and the kernel takes with it everything
//! that hangs off it: its addresses, the routes through it, its qdiscs,
//! the links stacked on it (a VLAN or macvlan on its lower device, a
//! VXLAN on its underlay — `vlan_device_event`, `macvlan_device_event`,
//! `vxlan_handle_lowerdev_unregister`), and its ports, which are released
//! (`bond_uninit` → `__bond_release_one`, which closes each one). The
//! diff therefore treats a recreated link as absent, so that what the
//! config declares on it — addresses, routes, qdiscs, stacked links,
//! ports — is put back by the same apply. What the config does *not*
//! declare cannot be put back, so a recreate that would destroy any of it
//! is refused, naming what it would destroy, the way an in-place HTB
//! `default_class` edit is (#402). A netkit pair is never recreated: its
//! peer usually lives in another namespace, which no declaration here
//! describes.
//!
//! Some of what a deleted link takes with it cannot be declared at all,
//! so wherever it exists it blocks the recreate (#426): FDB entries a user
//! or a controller added (a VXLAN's head-end replication list, a bridge's
//! static entries), permanent and proxy neighbours (`neigh_ifdown`),
//! nexthop objects (`nexthop_flush_dev`), and multipath and nexthop-object
//! routes through the link, whose dump carries no `RTA_OIF` for it (an
//! IPv4 multipath route goes whole: `fib_sync_down_dev` counts every
//! nexthop dead on NETDEV_UNREGISTER). The kernel's own FDB entries are
//! told apart by what makes them: a device's unicast and multicast address
//! lists (`ndo_dflt_fdb_dump` — the stack's multicast joins, and the MACs
//! of links stacked on it), a bridge port's or bridge's own MAC, and a
//! VXLAN's default remote (`__vxlan_dev_create`).
//!
//! The ports of a deleted bond or VRF stay, but leaving it flushes them as
//! a link going down does — `__bond_release_one` closes the port, and an
//! L3-master change makes `fib_netdev_event` and `addrconf_notify` flush
//! its routes, IPv6 addresses and neighbours — so what of that the config
//! does not declare blocks too; except routes in the deleted VRF's own
//! table, which nothing reaches once the VRF is gone.
//!
//! An optional parameter left undeclared is compared against the
//! kernel's default where that default is fixed in the kernel (a VLAN's
//! 802.1Q, no VXLAN remote/local/underlay, netkit's L3 mode and forward
//! policies), so a knob dropped from a declaration is reset rather than
//! left as it was. Where the default comes from a module parameter (the
//! VXLAN port — `vxlan`'s `udp_port`, 8472 unless set — and every bond
//! option), an undeclared parameter is not compared.

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use super::types::{DeclaredLink, DeclaredLinkType, NetworkConfig, QdiscParent};
use crate::netlink::{
    attr::AttrIter,
    connection::Connection,
    error::Result,
    link::{
        BondMode as KernelBondMode, MacvlanMode as KernelMacvlanMode, NetkitMode, NetkitPolicy,
        NetkitScrub, VlanProtocol, bond_attr, macvlan, netkit, vlan, vrf_attr, vxlan,
    },
    messages::{AddressMessage, LinkMessage, NeighborMessage, RouteMessage, TcMessage},
    nexthop::Nexthop,
    protocol::Route,
    types::{
        addr::Scope,
        neigh::{ntf, nud},
        route::RouteProtocol,
    },
};

/// A link the apply deletes and creates again, because a declared
/// parameter cannot be changed on a live link.
///
/// The recreated link itself is also in
/// [`ConfigDiff::links_to_add`](super::ConfigDiff::links_to_add), and what
/// the config declares on it — addresses, routes, qdiscs, ports, links
/// stacked on it — in the other `*_to_add` / `links_to_modify` lists, since
/// deleting the link deletes them.
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case"))]
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct LinkRecreate {
    /// The link.
    pub name: String,
    /// Why: the parameters that differ (`vxlan vni 100 -> 200`), or the
    /// link it is stacked on.
    pub reason: String,
    /// What deleting the link would destroy that the config does not
    /// declare, and so cannot restore. Non-empty means the apply refuses,
    /// with [`Error::NotSupported`](crate::Error::NotSupported), rather than
    /// recreate the link; nothing else in the diff depends on it then.
    pub blocked_by: Vec<String>,
}

impl LinkRecreate {
    /// True when the apply will refuse this recreate (see
    /// [`blocked_by`](Self::blocked_by)).
    pub fn is_refused(&self) -> bool {
        !self.blocked_by.is_empty()
    }
}

impl std::fmt::Display for LinkRecreate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.blocked_by.is_empty() {
            write!(f, "-/+ link {} (recreate: {})", self.name, self.reason)
        } else {
            write!(
                f,
                "-/+ link {} (recreate refused: {}; it would destroy what the config does not \
                 declare: {})",
                self.name,
                self.reason,
                self.blocked_by.join(", ")
            )
        }
    }
}

/// An in-place change of a live link's kind parameters.
#[derive(Debug, Clone)]
pub(crate) struct KindUpdate {
    /// `IFLA_INFO_KIND` — the kernel matches it against the live link.
    pub(crate) kind: &'static str,
    /// The `IFLA_INFO_DATA` attributes to send: only the ones that change.
    pub(crate) attrs: Vec<KindAttr>,
    /// One `name old -> new` line per changed parameter.
    pub(crate) changes: Vec<String>,
}

/// One `IFLA_INFO_DATA` attribute of a [`KindUpdate`].
#[derive(Debug, Clone)]
pub(crate) enum KindAttr {
    U8(u16, u8),
    U32(u16, u32),
    Bytes(u16, Vec<u8>),
    /// A link's ifindex, resolved by name when the change is applied — the
    /// link may be created by the same apply.
    Ifindex(u16, String),
}

/// How a declared link's kind parameters differ from the live link's.
#[derive(Debug, Default)]
struct KindDiff {
    /// Parameters the kernel cannot change on a live link.
    recreate: Vec<String>,
    /// Parameters that cannot change, where a recreate is refused too.
    refuse: Vec<String>,
    /// Parameters changed in place.
    update: Option<KindUpdate>,
}

impl KindDiff {
    fn update(&mut self, kind: &'static str, attr: KindAttr, change: String) {
        let u = self.update.get_or_insert_with(|| KindUpdate {
            kind,
            attrs: Vec::new(),
            changes: Vec::new(),
        });
        u.attrs.push(attr);
        u.changes.push(change);
    }
}

/// A live link's `IFLA_INFO_DATA`, by attribute type.
struct InfoData<'a>(HashMap<u16, &'a [u8]>);

impl<'a> InfoData<'a> {
    fn of(link: &'a LinkMessage) -> Self {
        let data = link.link_info().and_then(|i| i.data()).unwrap_or(&[]);
        Self(AttrIter::new(data).collect())
    }

    fn u8(&self, t: u16) -> Option<u8> {
        self.0.get(&t).and_then(|p| p.first().copied())
    }

    fn u16_ne(&self, t: u16) -> Option<u16> {
        let p = self.0.get(&t)?;
        Some(u16::from_ne_bytes(p.get(..2)?.try_into().ok()?))
    }

    fn u16_be(&self, t: u16) -> Option<u16> {
        let p = self.0.get(&t)?;
        Some(u16::from_be_bytes(p.get(..2)?.try_into().ok()?))
    }

    fn u32(&self, t: u16) -> Option<u32> {
        let p = self.0.get(&t)?;
        Some(u32::from_ne_bytes(p.get(..4)?.try_into().ok()?))
    }

    fn ipv4(&self, t: u16) -> Option<Ipv4Addr> {
        let p = self.0.get(&t)?;
        let octets: [u8; 4] = p.get(..4)?.try_into().ok()?;
        Some(Ipv4Addr::from(octets))
    }

    fn ipv6(&self, t: u16) -> Option<Ipv6Addr> {
        let p = self.0.get(&t)?;
        let octets: [u8; 16] = p.get(..16)?.try_into().ok()?;
        Some(Ipv6Addr::from(octets))
    }
}

/// The attribute a VXLAN endpoint goes in, by family.
fn vxlan_attr(what: &str, v6: bool) -> u16 {
    match (what, v6) {
        ("local", false) => vxlan::IFLA_VXLAN_LOCAL,
        ("local", true) => vxlan::IFLA_VXLAN_LOCAL6,
        (_, false) => vxlan::IFLA_VXLAN_GROUP,
        (_, true) => vxlan::IFLA_VXLAN_GROUP6,
    }
}

fn vlan_protocol_name(p: u16) -> String {
    match p {
        0x8100 => "802.1Q".to_string(),
        0x88a8 => "802.1ad".to_string(),
        other => format!("{other:#06x}"),
    }
}

fn bond_mode_name(m: u8) -> String {
    match KernelBondMode::try_from(m) {
        Ok(mode) => format!("{mode:?}"),
        Err(_) => m.to_string(),
    }
}

fn or_none(v: Option<impl std::fmt::Display>) -> String {
    v.map_or_else(|| "none".to_string(), |v| v.to_string())
}

pub(super) fn kernel_macvlan_mode(mode: super::types::MacvlanMode) -> KernelMacvlanMode {
    use super::types::MacvlanMode as M;
    match mode {
        M::Private => KernelMacvlanMode::Private,
        M::Vepa => KernelMacvlanMode::Vepa,
        M::Bridge => KernelMacvlanMode::Bridge,
        M::Passthru => KernelMacvlanMode::Passthru,
        M::Source => KernelMacvlanMode::Source,
    }
}

pub(super) fn kernel_bond_mode(mode: super::types::BondMode) -> KernelBondMode {
    use super::types::BondMode as M;
    match mode {
        M::BalanceRr => KernelBondMode::BalanceRr,
        M::ActiveBackup => KernelBondMode::ActiveBackup,
        M::BalanceXor => KernelBondMode::BalanceXor,
        M::Broadcast => KernelBondMode::Broadcast,
        M::Ieee802_3ad => KernelBondMode::Lacp,
        M::BalanceTlb => KernelBondMode::BalanceTlb,
        M::BalanceAlb => KernelBondMode::BalanceAlb,
    }
}

/// The name of the link `live`'s `IFLA_LINK` names, when that is a link in
/// this namespace. `None` for a lower device in another namespace — a
/// declaration made here cannot name it.
fn lower_name<'n>(live: &LinkMessage, names: &HashMap<u32, &'n str>) -> Option<&'n str> {
    if live.link_netnsid.is_some() {
        return None;
    }
    live.link().and_then(|i| names.get(&i).copied())
}

/// Compare a declared link's kind parameters with the live link's.
fn compare(declared: &DeclaredLink, live: &LinkMessage, names: &HashMap<u32, &str>) -> KindDiff {
    let mut d = KindDiff::default();
    let Some(want_kind) = declared.link_type.kind() else {
        // `Physical`: an existing device, configured but never created, so
        // nothing about its kind is declared.
        return d;
    };
    match live.kind() {
        Some(have) if have == want_kind => {}
        Some(have) => {
            d.recreate.push(format!("kind {have} -> {want_kind}"));
            return d;
        }
        None => {
            d.refuse.push(format!(
                "it is a device with no link kind (a physical NIC?), declared as {want_kind}"
            ));
            return d;
        }
    }
    let data = InfoData::of(live);

    match &declared.link_type {
        DeclaredLinkType::Vlan {
            parent,
            vlan_id,
            protocol,
        } => {
            if let Some(have) = data.u16_ne(vlan::IFLA_VLAN_ID)
                && have != *vlan_id
            {
                d.recreate.push(format!("vlan id {have} -> {vlan_id}"));
            }
            // `vlan_newlink` defaults an absent protocol to 802.1Q.
            let want = protocol.unwrap_or(VlanProtocol::Dot1q).as_u16();
            if let Some(have) = data.u16_be(vlan::IFLA_VLAN_PROTOCOL)
                && have != want
            {
                d.recreate.push(format!(
                    "vlan protocol {} -> {}",
                    vlan_protocol_name(have),
                    vlan_protocol_name(want)
                ));
            }
            if let Some(have) = lower_name(live, names)
                && have != parent.as_str()
            {
                d.recreate.push(format!("vlan parent {have} -> {parent}"));
            }
        }
        DeclaredLinkType::Vxlan {
            vni,
            remote,
            local,
            port,
            underlay_dev,
        } => {
            if let Some(have) = data.u32(vxlan::IFLA_VXLAN_ID)
                && have != *vni
            {
                d.recreate.push(format!("vxlan vni {have} -> {vni}"));
            }
            if let (Some(want), Some(have)) = (port, data.u16_be(vxlan::IFLA_VXLAN_PORT))
                && have != *want
            {
                d.recreate.push(format!("vxlan port {have} -> {want}"));
            }
            let have_underlay = data
                .u32(vxlan::IFLA_VXLAN_LINK)
                .map(|i| names.get(&i).map_or_else(|| format!("ifindex {i}"), |n| n.to_string()));
            match (underlay_dev.as_deref(), have_underlay.as_deref()) {
                (Some(want), Some(have)) if want == have => {}
                (Some(want), have) => d.update(
                    "vxlan",
                    KindAttr::Ifindex(vxlan::IFLA_VXLAN_LINK, want.to_string()),
                    format!("vxlan underlay {} -> {want}", or_none(have)),
                ),
                (None, Some(have)) => d.recreate.push(format!("vxlan underlay {have} -> none")),
                (None, None) => {}
            }
            // The endpoints, either family (#418). `vxlan_nl2conf` takes a
            // new remote or local on a live link only in the family it has
            // ("New group address family does not match old group",
            // EOPNOTSUPP), and the kernel keeps both in one family
            // (`vxlan_config_validate`), so a declared family that differs
            // from the live one recreates the link.
            let have_remote = data
                .ipv4(vxlan::IFLA_VXLAN_GROUP)
                .map(IpAddr::V4)
                .or_else(|| data.ipv6(vxlan::IFLA_VXLAN_GROUP6).map(IpAddr::V6));
            let have_local = data
                .ipv4(vxlan::IFLA_VXLAN_LOCAL)
                .map(IpAddr::V4)
                .or_else(|| data.ipv6(vxlan::IFLA_VXLAN_LOCAL6).map(IpAddr::V6));
            // Neither dumped: the kernel assumed IPv4 at creation ("Unless
            // IPv6 is explicitly requested, assume IPv4").
            let have_v6 = have_local.or(have_remote).is_some_and(|a| a.is_ipv6());
            let want_v6 = local.or(*remote).map(|a| a.is_ipv6());
            if let Some(want_v6) = want_v6
                && want_v6 != have_v6
            {
                let family = |v6: bool| if v6 { "IPv6" } else { "IPv4" };
                d.recreate.push(format!(
                    "vxlan address family {} -> {}",
                    family(have_v6),
                    family(want_v6)
                ));
            } else {
                let endpoints = [
                    (*remote, have_remote, "remote"),
                    (*local, have_local, "local"),
                ];
                for (want, have, what) in endpoints {
                    if want == have {
                        continue;
                    }
                    // The unspecified address of the link's family clears
                    // it, as `ip link set ... type vxlan remote 0.0.0.0`
                    // does.
                    let (attr, bytes) = match want {
                        Some(IpAddr::V4(a)) => (vxlan_attr(what, false), a.octets().to_vec()),
                        Some(IpAddr::V6(a)) => (vxlan_attr(what, true), a.octets().to_vec()),
                        None if have_v6 => {
                            (vxlan_attr(what, true), Ipv6Addr::UNSPECIFIED.octets().to_vec())
                        }
                        None => (vxlan_attr(what, false), Ipv4Addr::UNSPECIFIED.octets().to_vec()),
                    };
                    d.update(
                        "vxlan",
                        KindAttr::Bytes(attr, bytes),
                        format!("vxlan {what} {} -> {}", or_none(have), or_none(want)),
                    );
                }
            }
        }
        DeclaredLinkType::Macvlan { parent, mode } => {
            if let Some(have) = lower_name(live, names)
                && have != parent.as_str()
            {
                d.recreate.push(format!("macvlan parent {have} -> {parent}"));
            }
            let want = kernel_macvlan_mode(*mode) as u32;
            if let Some(have) = data.u32(macvlan::IFLA_MACVLAN_MODE)
                && have != want
            {
                let passthru = KernelMacvlanMode::Passthru as u32;
                let change = format!("macvlan mode {have} -> {want} ({mode:?})");
                if (have == passthru) != (want == passthru) {
                    d.recreate.push(change);
                } else {
                    d.update("macvlan", KindAttr::U32(macvlan::IFLA_MACVLAN_MODE, want), change);
                }
            }
        }
        DeclaredLinkType::Bond {
            mode,
            miimon,
            xmit_hash_policy,
            min_links,
            ad_select,
            lacp_rate,
            downdelay,
            updelay,
            resend_igmp,
        } => {
            let want_mode = kernel_bond_mode(*mode) as u8;
            if let Some(have) = data.u8(bond_attr::IFLA_BOND_MODE)
                && have != want_mode
            {
                d.recreate.push(format!(
                    "bond mode {} -> {}",
                    bond_mode_name(have),
                    bond_mode_name(want_mode)
                ));
            }
            let down_only = [
                (lacp_rate.map(|v| v as u8), bond_attr::IFLA_BOND_AD_LACP_RATE, "lacp_rate"),
                (ad_select.map(|v| v as u8), bond_attr::IFLA_BOND_AD_SELECT, "ad_select"),
            ];
            for (want, attr, what) in down_only {
                if let (Some(want), Some(have)) = (want, data.u8(attr))
                    && have != want
                {
                    d.recreate.push(format!("bond {what} {have} -> {want}"));
                }
            }

            let live_miimon = data.u32(bond_attr::IFLA_BOND_MIIMON);
            if let (Some(want), Some(have)) = (miimon, live_miimon)
                && have != *want
            {
                d.update(
                    "bond",
                    KindAttr::U32(bond_attr::IFLA_BOND_MIIMON, *want),
                    format!("bond miimon {have} -> {want}"),
                );
            }
            // The kernel keeps a delay as a count of miimon intervals
            // (`_bond_option_delay_set`: `value / miimon`) and dumps it
            // multiplied back, so a delay that is not a multiple of miimon
            // comes back rounded down — and one that is comes back changed
            // when miimon changes.
            let miimon_ms = miimon.or(live_miimon).unwrap_or(0);
            let delays = [
                (updelay, bond_attr::IFLA_BOND_UPDELAY, "updelay"),
                (downdelay, bond_attr::IFLA_BOND_DOWNDELAY, "downdelay"),
            ];
            for (want, attr, what) in delays {
                let Some(want) = want else { continue };
                let stored = want
                    .checked_div(miimon_ms)
                    .map_or(*want, |intervals| intervals * miimon_ms);
                let have = data.u32(attr);
                if have != Some(stored) {
                    d.update(
                        "bond",
                        KindAttr::U32(attr, *want),
                        format!("bond {what} {} -> {want}", or_none(have)),
                    );
                }
            }
            if let (Some(want), Some(have)) =
                (xmit_hash_policy, data.u8(bond_attr::IFLA_BOND_XMIT_HASH_POLICY))
                && have != *want
            {
                d.update(
                    "bond",
                    KindAttr::U8(bond_attr::IFLA_BOND_XMIT_HASH_POLICY, *want),
                    format!("bond xmit_hash_policy {have} -> {want}"),
                );
            }
            let counts = [
                (min_links, bond_attr::IFLA_BOND_MIN_LINKS, "min_links"),
                (resend_igmp, bond_attr::IFLA_BOND_RESEND_IGMP, "resend_igmp"),
            ];
            for (want, attr, what) in counts {
                if let (Some(want), Some(have)) = (want, data.u32(attr))
                    && have != *want
                {
                    d.update(
                        "bond",
                        KindAttr::U32(attr, *want),
                        format!("bond {what} {have} -> {want}"),
                    );
                }
            }
        }
        DeclaredLinkType::Vrf { table } => {
            if let Some(have) = data.u32(vrf_attr::IFLA_VRF_TABLE)
                && have != *table
            {
                d.recreate.push(format!("vrf table {have} -> {table}"));
            }
        }
        DeclaredLinkType::Netkit {
            peer,
            mode,
            primary_policy,
            peer_policy,
            scrub,
            peer_scrub,
        } => {
            // `netkit_new_link` defaults: L3, forward both ways, default
            // scrubbing both ways.
            let fixed = [
                (
                    mode.unwrap_or(NetkitMode::L3) as u32,
                    netkit::IFLA_NETKIT_MODE,
                    "netkit mode",
                ),
                (
                    scrub.unwrap_or(NetkitScrub::Default) as u32,
                    netkit::IFLA_NETKIT_SCRUB,
                    "netkit scrub",
                ),
                (
                    peer_scrub.unwrap_or(NetkitScrub::Default) as u32,
                    netkit::IFLA_NETKIT_PEER_SCRUB,
                    "netkit peer scrub",
                ),
            ];
            for (want, attr, what) in fixed {
                if let Some(have) = data.u32(attr)
                    && have != want
                {
                    d.refuse.push(format!(
                        "{what} {have} -> {want} cannot be changed on a live pair \
                         (netkit_change_link), and recreating it would delete its peer {peer}"
                    ));
                }
            }
            // Settings change only through the primary.
            if data.u8(netkit::IFLA_NETKIT_PRIMARY) != Some(0) {
                let policies = [
                    (primary_policy, netkit::IFLA_NETKIT_POLICY, "netkit policy"),
                    (peer_policy, netkit::IFLA_NETKIT_PEER_POLICY, "netkit peer policy"),
                ];
                for (want, attr, what) in policies {
                    let want = want.unwrap_or(NetkitPolicy::Forward) as u32;
                    if let Some(have) = data.u32(attr)
                        && have != want
                    {
                        d.update(
                            "netkit",
                            KindAttr::U32(attr, want),
                            format!("{what} {have} -> {want}"),
                        );
                    }
                }
            }
        }
        DeclaredLinkType::Dummy
        | DeclaredLinkType::Veth { .. }
        | DeclaredLinkType::Bridge
        | DeclaredLinkType::Ifb
        | DeclaredLinkType::Ovpn
        | DeclaredLinkType::Physical => {}
    }
    d
}

/// What the kind parameters of a config ask of the live links.
#[derive(Debug, Default)]
pub(crate) struct KindPlan {
    /// Links to delete and create again, in deletion order, and the ones
    /// refused.
    pub(crate) recreate: Vec<LinkRecreate>,
    /// The ifindexes the apply deletes: the recreated links and the links
    /// the kernel deletes with them.
    pub(crate) gone: HashSet<u32>,
    /// Ports of a deleted master, which the kernel releases: ifindex, and
    /// whether it closes them on the way out (a bond does).
    pub(crate) released: HashMap<u32, bool>,
    /// Ports whose routes the kernel flushes as they leave the deleted
    /// master and join the new one: a bond closes them, a VRF cycles them.
    pub(crate) cycled: HashSet<u32>,
    /// Deleted links that were up, so an undeclared state comes back up.
    pub(crate) was_up: HashSet<String>,
    /// In-place changes, by link name.
    pub(crate) updates: HashMap<String, KindUpdate>,
}

/// What hangs off the links beyond the four dumps every diff takes (links,
/// addresses, routes, qdiscs), and a recreate destroys with them. Read
/// only when the plan recreates a link ([`recreates_any`]).
#[derive(Debug, Default)]
pub(crate) struct LinkExtras {
    /// The `AF_BRIDGE` neighbour dump: every device's FDB entries.
    pub(crate) fdb: Vec<NeighborMessage>,
    /// ARP and ND entries.
    pub(crate) neighbours: Vec<NeighborMessage>,
    /// Proxy entries, which the neighbour dump leaves out.
    pub(crate) proxies: Vec<NeighborMessage>,
    /// Nexthop objects.
    pub(crate) nexthops: Vec<Nexthop>,
}

impl LinkExtras {
    pub(crate) async fn read(conn: &Connection<Route>) -> Result<Self> {
        let nexthops = match conn.get_nexthops().await {
            Ok(nexthops) => nexthops,
            // A kernel without nexthop objects (before 5.3) has no
            // RTM_GETNEXTHOP handler, and no nexthop objects either.
            Err(e) if e.is_not_supported() => Vec::new(),
            Err(e) => return Err(e),
        };
        Ok(Self {
            fdb: conn.get_bridge_neighbors().await?,
            neighbours: conn.get_neighbors().await?,
            proxies: conn.get_proxy_neighbors().await?,
            nexthops,
        })
    }
}

/// True when some declared link has a parameter the kernel cannot change
/// on it, so the plan recreates (or refuses to recreate) it.
pub(crate) fn recreates_any(config: &NetworkConfig, links: &[LinkMessage]) -> bool {
    let names: HashMap<u32, &str> = links
        .iter()
        .filter_map(|l| l.name.as_deref().map(|n| (l.ifindex(), n)))
        .collect();
    config.links.iter().any(|link| {
        links
            .iter()
            .find(|l| l.name.as_deref() == Some(link.name.as_str()))
            .is_some_and(|live| {
                let d = compare(link, live, &names);
                !d.recreate.is_empty() || !d.refuse.is_empty()
            })
    })
}

/// `downed`, and the VLANs the kernel takes down with them, transitively:
/// `vlan_device_event` closes every up VLAN on a lower device that goes
/// down, unless it was created with `loose_binding`, and opens them all
/// again when the lower device comes back up.
pub(crate) fn with_vlans_on(links: &[LinkMessage], downed: &HashSet<u32>) -> HashSet<u32> {
    let mut out = downed.clone();
    let mut queue: VecDeque<u32> = downed.iter().copied().collect();
    while let Some(lower) = queue.pop_front() {
        for l in links {
            let follows = l.kind() == Some("vlan")
                && l.link() == Some(lower)
                && l.link_netnsid.is_none()
                && l.is_up()
                && !loose_binding(l);
            if follows && out.insert(l.ifindex()) {
                queue.push_back(l.ifindex());
            }
        }
    }
    out
}

/// `IFLA_VLAN_FLAGS` is a `struct ifla_vlan_flags { flags, mask }`.
fn loose_binding(vlan_link: &LinkMessage) -> bool {
    InfoData::of(vlan_link)
        .u32(vlan::IFLA_VLAN_FLAGS)
        .is_some_and(|flags| flags & vlan::VLAN_FLAG_LOOSE_BINDING != 0)
}

/// The devices each nexthop object sends through: its own, or for a group
/// its members' (the kernel does not nest groups).
fn nexthop_devices(nexthops: &[Nexthop]) -> HashMap<u32, Vec<u32>> {
    let own: HashMap<u32, u32> = nexthops
        .iter()
        .filter_map(|nh| nh.ifindex().map(|dev| (nh.id(), dev)))
        .collect();
    nexthops
        .iter()
        .map(|nh| {
            let devs = match nh.group() {
                Some(members) => members.iter().filter_map(|m| own.get(&m.id()).copied()).collect(),
                None => nh.ifindex().into_iter().collect(),
            };
            (nh.id(), devs)
        })
        .collect()
}

/// How a route goes through `dev`, if it does: its own output interface,
/// one of its multipath nexthops, or the nexthop object it uses. The last
/// two dump no `RTA_OIF` (a nexthop object's only while
/// `nexthop_compat_mode` is on), so checking `oif` alone missed them.
fn route_through(
    r: &RouteMessage,
    dev: u32,
    nh_devs: &HashMap<u32, Vec<u32>>,
) -> Option<&'static str> {
    if r.nh_id()
        .and_then(|id| nh_devs.get(&id))
        .is_some_and(|devs| devs.contains(&dev))
    {
        return Some("through a nexthop object on");
    }
    if r.oif() == Some(dev) {
        return Some("");
    }
    r.multipath()
        .is_some_and(|hops| hops.iter().any(|h| h.ifindex == dev))
        .then_some("with a multipath nexthop on")
}

fn route_label(r: &RouteMessage, name: &str, how: &str) -> String {
    let dst = r.destination.unwrap_or(if r.is_ipv4() {
        IpAddr::V4(Ipv4Addr::UNSPECIFIED)
    } else {
        IpAddr::V6(Ipv6Addr::UNSPECIFIED)
    });
    let nhid = r.nh_id().map(|id| format!(" nhid {id}")).unwrap_or_default();
    if how.is_empty() {
        format!("route {dst}/{}{nhid} dev {name} table {}", r.dst_len(), r.table_id())
    } else {
        format!("route {dst}/{}{nhid} table {}, {how} {name}", r.dst_len(), r.table_id())
    }
}

fn mac_str(mac: &[u8]) -> String {
    mac.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(":")
}

/// True for an FDB entry the kernel did not make itself — one a user or a
/// controller added, which nothing puts back once its link is deleted.
///
/// Only entries that stay count: `permanent`, `static` (NUD_NOARP) and
/// externally learned ones. A learned entry ages out and is learned again.
/// Of the rest, the kernel's own are:
/// - on a VXLAN, its default remote: the all-zeros entry
///   `__vxlan_dev_create` adds for the remote it was created with, which
///   `vxlan_fdb_info` dumps without `NDA_PORT` or `NDA_VNI`;
/// - any other `self` entry is the device's unicast or multicast address
///   list (`ndo_dflt_fdb_dump`): the stack's multicast joins, and the MACs
///   of links stacked on it (`dev_uc_add` by a macvlan, a VLAN or a bond's
///   upper with its own address). A user can add a unicast one
///   (`bridge fdb add MAC dev X self permanent`), and that is told apart by
///   being no link's MAC; a multicast one cannot be told apart;
/// - in a bridge's database, a port's or the bridge's own MAC, which the
///   bridge adds as a `local` entry, dumped as permanent (`fdb_to_nud`).
fn fdb_entry_is_users(
    e: &NeighborMessage,
    by_index: &HashMap<u32, &LinkMessage>,
    link_macs: &HashSet<&[u8]>,
) -> bool {
    let Some(mac) = e.lladdr().filter(|m| m.len() == 6) else {
        return false;
    };
    let state = e.header.ndm_state;
    let flags = e.header.ndm_flags;
    let ext_learned = flags & ntf::EXT_LEARNED != 0;
    if state & (nud::PERMANENT | nud::NOARP) == 0 && !ext_learned {
        return false;
    }
    let dev = by_index.get(&e.ifindex());
    if flags & ntf::SELF != 0 {
        if let Some(vx) = dev.filter(|d| d.kind() == Some("vxlan")) {
            let data = InfoData::of(vx);
            let default_remote = data
                .ipv4(vxlan::IFLA_VXLAN_GROUP)
                .map(IpAddr::V4)
                .or_else(|| data.ipv6(vxlan::IFLA_VXLAN_GROUP6).map(IpAddr::V6));
            let is_default = mac.iter().all(|b| *b == 0)
                && e.port().is_none()
                && e.vni().is_none()
                && default_remote.is_some()
                && e.destination().copied() == default_remote;
            return !is_default;
        }
        let multicast = mac[0] & 1 != 0;
        return !multicast && !link_macs.contains(mac);
    }
    let own_mac = dev.and_then(|d| d.address()) == Some(mac);
    !(state & nud::PERMANENT != 0 && !ext_learned && own_mac)
}

fn fdb_label(e: &NeighborMessage, names: &HashMap<u32, &str>) -> String {
    let mac = e.lladdr().map(mac_str).unwrap_or_default();
    let dev = names.get(&e.ifindex()).copied().unwrap_or("?");
    let mut s = format!("fdb entry {mac} dev {dev}");
    if let Some(dst) = e.destination() {
        s.push_str(&format!(" dst {dst}"));
    }
    // Not the VLAN: one `bridge fdb add` without one makes an entry per
    // VLAN of the port as well as the untagged one, and it is one thing to
    // remove.
    if let Some(master) = e.master() {
        s.push_str(&format!(" master {}", names.get(&master).copied().unwrap_or("?")));
    }
    s
}

/// What deleting or flushing one link destroys that cannot be declared:
/// its user-made neighbours and proxy entries, and its nexthop objects.
fn undeclarable_on(
    ifindex: u32,
    name: &str,
    extras: &LinkExtras,
    blocked_by: &mut Vec<String>,
) {
    for n in extras.neighbours.iter().filter(|n| n.ifindex() == ifindex) {
        let permanent = n.header.ndm_state & nud::PERMANENT != 0;
        let ext_learned = n.header.ndm_flags & ntf::EXT_LEARNED != 0;
        if !(permanent || ext_learned) {
            continue;
        }
        let Some(dst) = n.destination() else { continue };
        let what = if permanent { "permanent" } else { "externally learned" };
        blocked_by.push(format!("neighbour {dst} dev {name} ({what})"));
    }
    for p in extras.proxies.iter().filter(|p| p.ifindex() == ifindex) {
        if let Some(dst) = p.destination() {
            blocked_by.push(format!("proxy neighbour {dst} dev {name}"));
        }
    }
    for nh in extras.nexthops.iter().filter(|nh| nh.ifindex() == Some(ifindex)) {
        let via = nh.gateway().map(|g| format!(" via {g}")).unwrap_or_default();
        blocked_by.push(format!("nexthop id {}{via} dev {name}", nh.id()));
    }
}

/// Compare every declared link's kind parameters with the live links, and
/// work out what a recreate takes with it.
pub(crate) fn plan(
    config: &NetworkConfig,
    links: &[LinkMessage],
    addresses: &[AddressMessage],
    routes: &[RouteMessage],
    qdiscs: &[TcMessage],
    extras: &LinkExtras,
) -> KindPlan {
    let mut plan = KindPlan::default();
    let names: HashMap<u32, &str> = links
        .iter()
        .filter_map(|l| l.name.as_deref().map(|n| (l.ifindex(), n)))
        .collect();
    let by_name: HashMap<&str, &LinkMessage> = links
        .iter()
        .filter_map(|l| l.name.as_deref().map(|n| (n, l)))
        .collect();
    let by_index: HashMap<u32, &LinkMessage> = links.iter().map(|l| (l.ifindex(), l)).collect();
    // Tunnels and loopback have an all-zeros address, which is no MAC.
    let link_macs: HashSet<&[u8]> = links
        .iter()
        .filter_map(|l| l.address())
        .filter(|a| a.iter().any(|b| *b != 0))
        .collect();
    let nh_devs = nexthop_devices(&extras.nexthops);
    let declared: HashMap<&str, &DeclaredLink> =
        config.links.iter().map(|l| (l.name.as_str(), l)).collect();

    let mut seeds = Vec::new();
    for link in &config.links {
        let Some(live) = by_name.get(link.name.as_str()) else {
            continue;
        };
        let d = compare(link, live, &names);
        if !d.recreate.is_empty() || !d.refuse.is_empty() {
            let mut reasons = d.refuse.clone();
            reasons.extend(d.recreate.iter().cloned());
            seeds.push((*live, reasons.join(", "), d.refuse));
        } else if let Some(update) = d.update {
            plan.updates.insert(link.name.clone(), update);
        }
    }

    // What the kernel deletes along with a link: the links whose IFLA_LINK
    // is it (VLANs, macvlans, a veth's peer, …) and the VXLANs whose
    // underlay it is.
    let stacked_on = |lower: u32| -> Vec<&LinkMessage> {
        links
            .iter()
            .filter(|l| l.ifindex() != lower)
            .filter(|l| {
                (l.link() == Some(lower) && l.link_netnsid.is_none())
                    || (l.kind() == Some("vxlan")
                        && InfoData::of(l).u32(vxlan::IFLA_VXLAN_LINK) == Some(lower))
            })
            .collect()
    };
    let declared_routes: HashSet<(IpAddr, u8, u32)> = config
        .routes
        .iter()
        .map(|r| {
            (
                super::diff::kernel_destination(r.destination, r.prefix_len),
                r.prefix_len,
                r.table.unwrap_or(254),
            )
        })
        .collect();
    let name_of = |ifindex: u32| names.get(&ifindex).copied().unwrap_or("?");
    let route_key = |r: &RouteMessage| {
        let dst = r.destination.unwrap_or(if r.is_ipv4() {
            IpAddr::V4(Ipv4Addr::UNSPECIFIED)
        } else {
            IpAddr::V6(Ipv6Addr::UNSPECIFIED)
        });
        (dst, r.dst_len(), r.table_id())
    };

    for (seed, reason, refuse) in seeds {
        if plan.gone.contains(&seed.ifindex()) {
            continue;
        }
        // The seed and everything stacked on it, transitively, parents
        // first.
        let mut closure: Vec<(&LinkMessage, Option<u32>)> = vec![(seed, None)];
        let mut seen: HashSet<u32> = HashSet::from([seed.ifindex()]);
        let mut queue: VecDeque<u32> = VecDeque::from([seed.ifindex()]);
        while let Some(lower) = queue.pop_front() {
            for l in stacked_on(lower) {
                if seen.insert(l.ifindex()) {
                    closure.push((l, Some(lower)));
                    queue.push_back(l.ifindex());
                }
            }
        }
        let members: HashSet<u32> = seen;

        let mut blocked_by = refuse;
        for (l, lower) in &closure {
            let name = name_of(l.ifindex());
            if let Some(lower) = lower {
                let kind = l.kind().unwrap_or("link");
                match declared.get(name) {
                    None => blocked_by.push(format!(
                        "link {name} ({kind} on {}), which the kernel deletes with it",
                        name_of(*lower)
                    )),
                    Some(d) if d.link_type.kind().is_none() => blocked_by.push(format!(
                        "link {name} ({kind} on {}), which the kernel deletes with it and \
                         the config declares as an existing device, not one to create",
                        name_of(*lower)
                    )),
                    Some(_) => {}
                }
            }
            for a in addresses.iter().filter(|a| a.ifindex() == l.ifindex()) {
                let Some(addr) = a.address else { continue };
                if a.scope() != Scope::Universe {
                    continue;
                }
                let is_declared = config.addresses.iter().any(|d| {
                    d.dev == name && d.address == addr && d.prefix_len == a.prefix_len()
                });
                if !is_declared {
                    blocked_by.push(format!("address {addr}/{} on {name}", a.prefix_len()));
                }
            }
            for r in routes {
                if r.protocol() == RouteProtocol::Kernel || declared_routes.contains(&route_key(r))
                {
                    continue;
                }
                if let Some(how) = route_through(r, l.ifindex(), &nh_devs) {
                    blocked_by.push(route_label(r, name, how));
                }
            }
            for q in qdiscs.iter().filter(|q| q.ifindex() == l.ifindex()) {
                // A qdisc with handle 0: is the kernel's default for the
                // device, recreated with it.
                if q.handle().major() == 0 {
                    continue;
                }
                let parent = if q.is_root() {
                    QdiscParent::Root
                } else if q.parent().is_ingress() {
                    QdiscParent::Ingress
                } else {
                    continue;
                };
                let is_declared = config
                    .qdiscs
                    .iter()
                    .any(|d| d.dev == name && d.effective_parent() == parent);
                if !is_declared {
                    blocked_by.push(format!(
                        "qdisc {} on {name}",
                        q.kind().unwrap_or("?")
                    ));
                }
            }
            // The link's FDB entries, and — for a bridge — every entry in
            // its database, whichever port it is on.
            for e in extras.fdb.iter().filter(|e| {
                e.ifindex() == l.ifindex() || e.master() == Some(l.ifindex())
            }) {
                if fdb_entry_is_users(e, &by_index, &link_macs) {
                    blocked_by.push(fdb_label(e, &names));
                }
            }
            // Entries on another device that send *through* this one — a
            // VXLAN remote with `via` (`NDA_IFINDEX`, the rdst's
            // remote_ifindex). Deleting the link leaves them naming its old
            // ifindex: `bridge fdb` shows `via if10`, and the new link is
            // never used (#438). Entries on a device recreated with it go
            // anyway.
            for e in extras.fdb.iter().filter(|e| {
                e.ifindex_attr == Some(l.ifindex()) && !members.contains(&e.ifindex())
            }) {
                if fdb_entry_is_users(e, &by_index, &link_macs) {
                    blocked_by.push(format!(
                        "{} via {name}, which would point at the deleted {name}",
                        fdb_label(e, &names)
                    ));
                }
            }
            undeclarable_on(l.ifindex(), name, extras, &mut blocked_by);
        }

        // The ports of every deleted master, which the kernel releases.
        let ports: Vec<(&LinkMessage, &LinkMessage)> = closure
            .iter()
            .flat_map(|(l, _)| {
                links
                    .iter()
                    .filter(|p| p.master() == Some(l.ifindex()) && !members.contains(&p.ifindex()))
                    .map(move |p| (*l, p))
            })
            .collect();
        for (master, port) in &ports {
            let port_name = name_of(port.ifindex());
            if !declared.contains_key(port_name) {
                blocked_by.push(format!(
                    "link {port_name}, a port of {}, which the kernel releases",
                    name_of(master.ifindex())
                ));
            }
        }
        // The ports a bond closes or a VRF unlinks on the way out, and the
        // VLANs on them, lose their routes, IPv6 addresses, neighbours and
        // nexthop objects, as a link going down does. What the config
        // declares there is put back; what it does not is gone — except the
        // routes in a deleted VRF's own table, which nothing reaches once
        // the VRF is gone.
        let flushing: HashSet<u32> = ports
            .iter()
            .filter(|(m, _)| matches!(m.kind(), Some("bond" | "vrf")))
            .map(|(_, p)| p.ifindex())
            .collect();
        let old_tables: HashSet<u32> = closure
            .iter()
            .filter(|(l, _)| l.kind() == Some("vrf"))
            .filter_map(|(l, _)| InfoData::of(l).u32(vrf_attr::IFLA_VRF_TABLE))
            .collect();
        let mut flushed: Vec<u32> = with_vlans_on(links, &flushing).into_iter().collect();
        flushed.sort_unstable();
        for ifindex in flushed {
            let name = name_of(ifindex);
            for a in addresses.iter().filter(|a| a.ifindex() == ifindex) {
                let Some(addr) = a.address.filter(|a| a.is_ipv6()) else { continue };
                if a.scope() != Scope::Universe {
                    continue;
                }
                let is_declared = config.addresses.iter().any(|d| {
                    d.dev == name && d.address == addr && d.prefix_len == a.prefix_len()
                });
                if !is_declared {
                    blocked_by.push(format!("address {addr}/{} on {name}", a.prefix_len()));
                }
            }
            for r in routes {
                if r.protocol() == RouteProtocol::Kernel
                    || declared_routes.contains(&route_key(r))
                    || old_tables.contains(&r.table_id())
                {
                    continue;
                }
                if let Some(how) = route_through(r, ifindex, &nh_devs) {
                    blocked_by.push(route_label(r, name, how));
                }
            }
            undeclarable_on(ifindex, name, extras, &mut blocked_by);
        }

        // A bridge entry is dumped once per VLAN as well as once without.
        let mut seen_reasons = HashSet::new();
        blocked_by.retain(|b| seen_reasons.insert(b.clone()));

        if !blocked_by.is_empty() {
            plan.recreate.push(LinkRecreate {
                name: name_of(seed.ifindex()).to_string(),
                reason,
                blocked_by,
            });
            continue;
        }

        for (l, lower) in &closure {
            let name = name_of(l.ifindex());
            plan.gone.insert(l.ifindex());
            if l.is_up() {
                plan.was_up.insert(name.to_string());
            }
            let reason = match lower {
                None => reason.clone(),
                Some(lower) => {
                    format!("it is stacked on {}, which is recreated", name_of(*lower))
                }
            };
            plan.recreate.push(LinkRecreate {
                name: name.to_string(),
                reason,
                blocked_by: Vec::new(),
            });
        }
        for (master, port) in &ports {
            let closes = master.kind() == Some("bond");
            plan.released.insert(port.ifindex(), closes);
            if flushing.contains(&port.ifindex()) {
                plan.cycled.insert(port.ifindex());
            }
        }
    }

    // A recreated link needs no in-place change.
    plan.updates.retain(|name, _| {
        by_name
            .get(name.as_str())
            .is_none_or(|l| !plan.gone.contains(&l.ifindex()))
    });
    plan
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::netlink::messages::LinkInfo;

    /// One netlink attribute: header, payload, padding.
    fn attr(t: u16, payload: &[u8]) -> Vec<u8> {
        let len = 4 + payload.len();
        let mut out = Vec::with_capacity((len + 3) & !3);
        out.extend_from_slice(&(len as u16).to_ne_bytes());
        out.extend_from_slice(&t.to_ne_bytes());
        out.extend_from_slice(payload);
        out.resize((len + 3) & !3, 0);
        out
    }

    fn live(kind: &str, data: Vec<u8>) -> LinkMessage {
        LinkMessage {
            name: Some("l0".into()),
            link_info: Some(LinkInfo {
                kind: Some(kind.into()),
                data: Some(data),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    fn declared(cfg: NetworkConfig) -> DeclaredLink {
        cfg.links.into_iter().next().expect("one link")
    }

    #[test]
    fn a_truncated_attribute_reads_as_absent() {
        let link = live("bond", attr(bond_attr::IFLA_BOND_MIIMON, &[1, 0]));
        let data = InfoData::of(&link);
        assert_eq!(data.u32(bond_attr::IFLA_BOND_MIIMON), None);
        assert_eq!(data.u8(bond_attr::IFLA_BOND_MODE), None);
    }

    #[test]
    fn a_vni_change_recreates_and_a_remote_change_does_not() {
        let mut data = attr(vxlan::IFLA_VXLAN_ID, &100u32.to_ne_bytes());
        data.extend(attr(vxlan::IFLA_VXLAN_GROUP, &[10, 0, 0, 2]));
        let link = live("vxlan", data);
        let names = HashMap::new();

        let vni = declared(NetworkConfig::new().link("l0", |l| {
            l.vxlan(200).vxlan_remote(Ipv4Addr::new(10, 0, 0, 2).into())
        }));
        let d = compare(&vni, &link, &names);
        assert_eq!(d.recreate, vec!["vxlan vni 100 -> 200".to_string()]);
        assert!(d.update.is_none());

        let remote = declared(NetworkConfig::new().link("l0", |l| {
            l.vxlan(100).vxlan_remote(Ipv4Addr::new(10, 0, 0, 3).into())
        }));
        let d = compare(&remote, &link, &names);
        assert!(d.recreate.is_empty(), "{:?}", d.recreate);
        let update = d.update.expect("an in-place change");
        assert_eq!(update.kind, "vxlan");
        assert!(matches!(
            update.attrs.as_slice(),
            [KindAttr::Bytes(t, b)] if *t == vxlan::IFLA_VXLAN_GROUP && b == &[10, 0, 0, 3]
        ));
    }

    /// IPv6 endpoints are read back and compared (#418); a change within
    /// the family is made in place, a change of family recreates.
    #[test]
    fn vxlan_ipv6_endpoints_are_compared() {
        let local: Ipv6Addr = "fd00::1".parse().unwrap();
        let mut data = attr(vxlan::IFLA_VXLAN_ID, &7u32.to_ne_bytes());
        data.extend(attr(vxlan::IFLA_VXLAN_LOCAL6, &local.octets()));
        let link = live("vxlan", data);
        let names = HashMap::new();
        let vx = |local: &str| {
            declared(NetworkConfig::new().link("l0", |l| {
                l.vxlan(7).vxlan_local(local.parse().unwrap())
            }))
        };

        let d = compare(&vx("fd00::1"), &link, &names);
        assert!(d.recreate.is_empty() && d.update.is_none(), "{d:?}");

        let d = compare(&vx("fd00::5"), &link, &names);
        assert!(d.recreate.is_empty(), "{d:?}");
        let update = d.update.expect("an in-place change");
        assert!(matches!(
            update.attrs.as_slice(),
            [KindAttr::Bytes(t, b)] if *t == vxlan::IFLA_VXLAN_LOCAL6 && b.len() == 16
        ));

        let d = compare(&vx("10.0.0.1"), &link, &names);
        assert_eq!(d.recreate, vec!["vxlan address family IPv6 -> IPv4".to_string()]);
    }

    /// The kernel stores a bond delay as a count of miimon intervals.
    #[test]
    fn bond_delays_compare_as_the_kernel_rounds_them() {
        let mut data = attr(bond_attr::IFLA_BOND_MODE, &[1]);
        data.extend(attr(bond_attr::IFLA_BOND_MIIMON, &100u32.to_ne_bytes()));
        data.extend(attr(bond_attr::IFLA_BOND_UPDELAY, &100u32.to_ne_bytes()));
        let link = live("bond", data);
        let names = HashMap::new();
        let bond = |miimon: u32, updelay: u32| {
            declared(NetworkConfig::new().link("l0", |l| {
                l.bond()
                    .bond_mode(super::super::types::BondMode::ActiveBackup)
                    .miimon(miimon)
                    .bond_updelay(updelay)
            }))
        };

        let d = compare(&bond(100, 150), &link, &names);
        assert!(d.recreate.is_empty() && d.update.is_none(), "{d:?}");

        let d = compare(&bond(250, 500), &link, &names);
        assert!(d.recreate.is_empty(), "{d:?}");
        let update = d.update.expect("miimon and updelay change in place");
        assert_eq!(
            update.changes,
            vec![
                "bond miimon 100 -> 250".to_string(),
                "bond updelay 100 -> 500".to_string()
            ]
        );
    }

    fn link_at(ifindex: i32, name: &str, kind: &str, data: Vec<u8>, mac: [u8; 6]) -> LinkMessage {
        let mut l = live(kind, data);
        l.header.ifi_index = ifindex;
        l.header.ifi_flags = libc::IFF_UP as u32;
        l.name = Some(name.into());
        l.address = Some(mac.to_vec());
        l
    }

    fn fdb(ifindex: u32, mac: [u8; 6], state: u16, flags: u8) -> NeighborMessage {
        let mut e = crate::netlink::messages::NeighborMessageBuilder::new()
            .ifindex(ifindex)
            .lladdr(mac.to_vec())
            .build();
        e.header.ndm_family = libc::AF_BRIDGE as u8;
        e.header.ndm_state = state;
        e.header.ndm_flags = flags;
        e
    }

    /// The kernel's own FDB entries do not block a recreate; one a user
    /// added does (#426).
    #[test]
    fn fdb_entries_the_kernel_makes_are_told_from_the_ones_a_user_adds() {
        const OWN: [u8; 6] = [0x02, 0, 0, 0, 0, 1];
        const UPPER: [u8; 6] = [0x02, 0, 0, 0, 0, 2];
        const OTHER: [u8; 6] = [0x02, 0, 0, 0, 0, 9];
        const ZEROS: [u8; 6] = [0; 6];
        let remote = Ipv4Addr::new(10, 1, 0, 2);
        let mut vx_data = attr(vxlan::IFLA_VXLAN_ID, &100u32.to_ne_bytes());
        vx_data.extend(attr(vxlan::IFLA_VXLAN_GROUP, &remote.octets()));
        let links = [
            link_at(2, "d0", "dummy", Vec::new(), OWN),
            link_at(3, "vx0", "vxlan", vx_data, OWN),
            link_at(4, "mv0", "macvlan", Vec::new(), UPPER),
        ];
        let by_index: HashMap<u32, &LinkMessage> = links.iter().map(|l| (l.ifindex(), l)).collect();
        let macs: HashSet<&[u8]> = links.iter().filter_map(|l| l.address()).collect();
        let users = |e: NeighborMessage| fdb_entry_is_users(&e, &by_index, &macs);
        let perm = nud::PERMANENT | nud::NOARP;
        let with_dst = |mut e: NeighborMessage, dst: Ipv4Addr| {
            e.destination = Some(IpAddr::V4(dst));
            e
        };

        // A device's address lists: multicast joins, a stacked link's MAC.
        assert!(!users(fdb(2, [0x33, 0x33, 0, 0, 0, 1], nud::PERMANENT, ntf::SELF)));
        assert!(!users(fdb(2, UPPER, nud::PERMANENT, ntf::SELF)));
        // `bridge fdb add MAC dev d0 self permanent`.
        assert!(users(fdb(2, OTHER, nud::PERMANENT, ntf::SELF)));
        // A VXLAN's default remote, and a second remote appended to it.
        let default = fdb(3, ZEROS, nud::PERMANENT | nud::REACHABLE, ntf::SELF);
        assert!(!users(with_dst(default, remote)));
        let appended = fdb(3, ZEROS, perm, ntf::SELF);
        assert!(users(with_dst(appended, Ipv4Addr::new(192, 0, 2, 1))));
        // The same remote on another port is not the default either.
        let mut other_port = with_dst(fdb(3, ZEROS, perm, ntf::SELF), remote);
        other_port.port = Some(4791);
        assert!(users(other_port));
        // Learned entries age out; externally learned ones stay.
        assert!(!users(with_dst(fdb(3, OTHER, nud::REACHABLE, ntf::SELF), remote)));
        assert!(users(with_dst(
            fdb(3, OTHER, nud::REACHABLE, ntf::SELF | ntf::EXT_LEARNED),
            remote
        )));
        // A bridge's database: the port's own MAC is the kernel's local
        // entry; a static or another permanent one is a user's.
        let in_bridge = |mac, state| {
            let mut e = fdb(2, mac, state, 0);
            e.master = Some(9);
            e
        };
        assert!(!users(in_bridge(OWN, nud::PERMANENT)));
        assert!(users(in_bridge(OTHER, nud::PERMANENT)));
        assert!(users(in_bridge(OTHER, nud::NOARP)));
        assert!(!users(in_bridge(OTHER, nud::REACHABLE)));
    }

    /// A multipath route and a nexthop-object route dump no `RTA_OIF` for
    /// the link they go through (#426).
    #[test]
    fn a_route_goes_through_a_link_by_oif_multipath_or_nexthop_object() {
        use crate::netlink::messages::{ParsedNextHop, RouteMessageBuilder};
        let nh = |id, ifindex, group: Option<Vec<u32>>| Nexthop {
            id,
            gateway: None,
            ifindex,
            family: libc::AF_INET as u8,
            flags: 0,
            protocol: 0,
            scope: 0,
            blackhole: false,
            fdb: false,
            group: group.map(|ids| {
                ids.into_iter()
                    .map(|id| crate::netlink::nexthop::NexthopGroupMember { id, weight: 1 })
                    .collect()
            }),
            group_type: None,
            resilient: None,
        };
        let nh_devs = nexthop_devices(&[nh(5, Some(2), None), nh(6, Some(3), None), nh(7, None, Some(vec![5, 6]))]);
        let hop = |ifindex| ParsedNextHop {
            ifindex,
            weight: 1,
            flags: 0,
            gateway: None,
        };

        let single = RouteMessageBuilder::new().oif(2).build();
        assert_eq!(route_through(&single, 2, &nh_devs), Some(""));
        assert_eq!(route_through(&single, 3, &nh_devs), None);
        let multipath = RouteMessageBuilder::new().multipath(vec![hop(3), hop(2)]).build();
        assert!(route_through(&multipath, 2, &nh_devs).is_some());
        assert!(route_through(&multipath, 4, &nh_devs).is_none());
        // `nexthop_compat_mode` off: the id is all the route carries.
        let object = RouteMessageBuilder::new().nh_id(5).build();
        assert!(route_through(&object, 2, &nh_devs).is_some());
        assert!(route_through(&object, 3, &nh_devs).is_none());
        let group = RouteMessageBuilder::new().nh_id(7).build();
        assert!(route_through(&group, 3, &nh_devs).is_some());
    }

    /// A VLAN goes down with its lower device unless it was created with
    /// `loose_binding`, and a VLAN that is down already has nothing to
    /// lose.
    #[test]
    fn vlans_follow_their_lower_device_down() {
        let flags = |f: u32| {
            let mut payload = f.to_ne_bytes().to_vec();
            payload.extend(u32::MAX.to_ne_bytes());
            attr(vlan::IFLA_VLAN_FLAGS, &payload)
        };
        let vlan_on = |ifindex, lower, f| {
            let mut l = link_at(ifindex, "v", "vlan", flags(f), [0x02, 0, 0, 0, 0, ifindex as u8]);
            l.link = Some(lower);
            l
        };
        let mut down = vlan_on(6, 2, 1);
        down.header.ifi_flags = 0;
        let links = [
            link_at(2, "d0", "dummy", Vec::new(), [0x02, 0, 0, 0, 0, 2]),
            vlan_on(3, 2, vlan::VLAN_FLAG_REORDER_HDR),
            vlan_on(4, 3, vlan::VLAN_FLAG_REORDER_HDR),
            vlan_on(5, 2, vlan::VLAN_FLAG_LOOSE_BINDING),
            down,
        ];
        let got = with_vlans_on(&links, &HashSet::from([2]));
        assert_eq!(got, HashSet::from([2, 3, 4]));
    }

    #[test]
    fn a_refused_recreate_says_what_it_would_destroy() {
        let r = LinkRecreate {
            name: "vx0".into(),
            reason: "vxlan vni 100 -> 200".into(),
            blocked_by: vec!["address 10.0.0.9/24 on vx0".into()],
        };
        assert!(r.is_refused());
        let shown = r.to_string();
        assert!(
            shown.contains("vni 100 -> 200") && shown.contains("10.0.0.9/24"),
            "{shown}"
        );
        let ok = LinkRecreate {
            blocked_by: Vec::new(),
            ..r
        };
        assert!(!ok.is_refused());
        assert_eq!(ok.to_string(), "-/+ link vx0 (recreate: vxlan vni 100 -> 200)");
    }
}
