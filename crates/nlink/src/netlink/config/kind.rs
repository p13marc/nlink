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
//! | VXLAN remote, local | `vxlan_nl2conf` takes them when the address family stays | in place |
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
//! An optional parameter left undeclared is compared against the
//! kernel's default where that default is fixed in the kernel (a VLAN's
//! 802.1Q, no VXLAN remote/local/underlay, netkit's L3 mode and forward
//! policies), so a knob dropped from a declaration is reset rather than
//! left as it was. Where the default comes from a module parameter (the
//! VXLAN port — `vxlan`'s `udp_port`, 8472 unless set — and every bond
//! option), an undeclared parameter is not compared.

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{IpAddr, Ipv4Addr};

use super::types::{DeclaredLink, DeclaredLinkType, NetworkConfig, QdiscParent};
use crate::netlink::{
    attr::AttrIter,
    link::{
        BondMode as KernelBondMode, MacvlanMode as KernelMacvlanMode, NetkitMode, NetkitPolicy,
        NetkitScrub, VlanProtocol, bond_attr, macvlan, netkit, vlan, vrf_attr, vxlan,
    },
    messages::{AddressMessage, LinkMessage, RouteMessage, TcMessage},
    types::{addr::Scope, route::RouteProtocol},
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
            // IPv4 endpoints only: an IPv6 one is not written at creation
            // either, and so is not compared (#418).
            let endpoints = [
                (remote, vxlan::IFLA_VXLAN_GROUP, "remote"),
                (local, vxlan::IFLA_VXLAN_LOCAL, "local"),
            ];
            for (want, attr, what) in endpoints {
                let want = match want {
                    Some(IpAddr::V6(_)) => continue,
                    Some(IpAddr::V4(a)) => Some(*a),
                    None => None,
                };
                let have = data.ipv4(attr);
                if have != want {
                    // The unspecified address clears it, as `ip link set
                    // ... type vxlan remote 0.0.0.0` does.
                    let bytes = want.unwrap_or(Ipv4Addr::UNSPECIFIED).octets().to_vec();
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

/// Compare every declared link's kind parameters with the live links, and
/// work out what a recreate takes with it.
pub(crate) fn plan(
    config: &NetworkConfig,
    links: &[LinkMessage],
    addresses: &[AddressMessage],
    routes: &[RouteMessage],
    qdiscs: &[TcMessage],
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
            for r in routes.iter().filter(|r| r.oif() == Some(l.ifindex())) {
                if r.protocol() == RouteProtocol::Kernel {
                    continue;
                }
                let dst = r.destination.unwrap_or(if r.is_ipv4() {
                    IpAddr::V4(Ipv4Addr::UNSPECIFIED)
                } else {
                    IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED)
                });
                if !declared_routes.contains(&(dst, r.dst_len(), r.table_id())) {
                    blocked_by.push(format!(
                        "route {dst}/{} dev {name} table {}",
                        r.dst_len(),
                        r.table_id()
                    ));
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
                } else if q.is_ingress() || q.is_clsact() {
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
            for port in links
                .iter()
                .filter(|p| p.master() == Some(l.ifindex()) && !members.contains(&p.ifindex()))
            {
                let port_name = name_of(port.ifindex());
                if !declared.contains_key(port_name) {
                    blocked_by.push(format!(
                        "link {port_name}, a port of {name}, which the kernel releases"
                    ));
                }
            }
        }

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
            let master_kind = l.kind();
            for port in links
                .iter()
                .filter(|p| p.master() == Some(l.ifindex()) && !members.contains(&p.ifindex()))
            {
                let closes = master_kind == Some("bond");
                plan.released.insert(port.ifindex(), closes);
                if closes || master_kind == Some("vrf") {
                    plan.cycled.insert(port.ifindex());
                }
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
