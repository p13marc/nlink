//! Every shape `NetworkConfig` can declare must converge.
//!
//! The declarative diff compares a declaration against the kernel's
//! dump of what the last apply installed. Wherever the kernel stores
//! something other than what it was sent — a masked prefix, a default it
//! substitutes, a value it clamps or quantises, an attribute it does not
//! echo — or wherever an apply step undoes an earlier one, the next diff
//! is not empty, and every apply after it rewrites the same thing
//! forever. None of that is visible applying once to an empty namespace.
//!
//! So each case here goes through `common::converge`: every step is
//! applied, diffed, applied again and diffed again, and all four must say
//! "nothing to do". A case with several steps applies them in order to the
//! same namespace, which is how a replace (a knob removed, a link moved)
//! gets exercised at all: every case that only ever installs onto a fresh
//! device misses what a replace keeps.
//!
//! The cases are tables rather than one test each so a run reports every
//! red shape at once instead of stopping at the first.

use std::net::Ipv4Addr;
use std::time::Duration;

use nlink::netlink::config::{
    BondMode, MacvlanMode, NetkitMode, NetworkConfig, QdiscBuilder, RouteBuilder, VlanProtocol,
};
use nlink::netlink::tc::{NetemLossModel, TbfConfig};
use nlink::netlink::{Connection, Route};
use nlink::{Bytes, Percent, Rate, TcMessage};

use crate::common::converge::{assert_converges, case, converges, ip_json};
use crate::common::{STEP_TIMEOUT, TestNamespace};

const MAC_A: [u8; 6] = [0x02, 0x00, 0x5e, 0x10, 0x00, 0x01];
const MAC_B: [u8; 6] = [0x02, 0x00, 0x5e, 0x10, 0x00, 0x02];

fn dummy_up(name: &str) -> NetworkConfig {
    NetworkConfig::new().link(name, |l| l.dummy().up())
}

// ============================================================================
// Links
// ============================================================================

/// A VLAN declared down stays down when the apply brings its lower device
/// up. `vlan_device_event()` brings up every VLAN on a device that comes up,
/// so it ended the apply up and converged only on the next one (#436).
#[tokio::test]
async fn a_vlan_declared_down_stays_down_when_its_lower_device_comes_up() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("dummy", "8021q");

    let lower = |up: bool| {
        NetworkConfig::new().link("d0", |l| if up { l.dummy().up() } else { l.dummy().down() })
    };
    let with_vlan = |cfg: NetworkConfig| cfg.link("d0.10", |l| l.vlan("d0", 10).down());
    let cases = vec![
        // The lower device is set up while the VLAN on it is declared down.
        case(
            "lower-set-up",
            vec![with_vlan(lower(false)), with_vlan(lower(true))],
        ),
        // Both created by one apply: the VLAN is made down, then the lower
        // device comes up under it.
        case("both-created", vec![with_vlan(lower(true))]),
    ];
    assert_converges("nce-vlan-down", cases).await
}

/// A VLAN declared up on a lower device declared down is refused before
/// anything changes. The kernel cannot hold it (`vlan_dev_open()` is ENETDOWN
/// while the lower device is down), and the first apply used to end with the
/// VLAN down and the second fail (#437).
#[tokio::test]
async fn a_vlan_declared_up_on_a_lower_device_declared_down_is_refused() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("dummy", "8021q");

    let ns = TestNamespace::new("nce-vlan-up")?;
    let conn = ns.connection()?;
    let cfg = NetworkConfig::new()
        .link("d0", |l| l.dummy().down())
        .link("d0.10", |l| l.vlan("d0", 10).up());
    for (what, outcome) in [
        ("diff", cfg.diff(&conn).await.map(drop)),
        ("apply", cfg.apply(&conn).await.map(drop)),
    ] {
        let err = outcome.expect_err(what).to_string();
        assert!(err.contains("d0.10") && err.contains("declared down"), "{what}: {err}");
    }
    assert!(
        conn.get_link_by_name("d0").await?.is_none(),
        "the refused apply must not have created anything"
    );
    Ok(())
}

/// Every link kind, created by the apply.
#[tokio::test]
async fn every_link_kind_converges() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!(
        "dummy", "veth", "bridge", "8021q", "vxlan", "macvlan", "bonding", "vrf", "ifb"
    );

    let cases = vec![
        case("dummy", vec![dummy_up("d0")]),
        case(
            "dummy-mtu-mac",
            vec![NetworkConfig::new().link("d0", |l| l.dummy().mtu(9000).address(MAC_A).up())],
        ),
        case(
            "veth-mtu-mac",
            vec![NetworkConfig::new().link("v0", |l| l.veth("v1").mtu(1400).address(MAC_A).up())],
        ),
        case(
            "bridge+port",
            vec![
                NetworkConfig::new()
                    .link("br0", |l| l.bridge().up())
                    .link("d0", |l| l.dummy().master("br0").up()),
            ],
        ),
        case(
            "vlan",
            vec![dummy_up("d0").link("d0.10", |l| l.vlan("d0", 10).up())],
        ),
        case(
            "vlan-802.1ad-mac",
            vec![dummy_up("d0").link("d0.20", |l| {
                l.vlan("d0", 20)
                    .vlan_protocol(VlanProtocol::Dot1ad)
                    .address(MAC_A)
                    .up()
            })],
        ),
        case(
            "vxlan",
            vec![
                dummy_up("d0")
                    .link("vx0", |l| {
                        l.vxlan(100)
                            .vxlan_remote(Ipv4Addr::new(10, 1, 0, 2).into())
                            .vxlan_local(Ipv4Addr::new(10, 1, 0, 1).into())
                            .vxlan_port(4790)
                            .vxlan_underlay_dev("d0")
                            .mtu(1400)
                            .address(MAC_A)
                            .up()
                    })
                    .address("d0", "10.1.0.1/24")
                    .unwrap(),
            ],
        ),
        case(
            "macvlan-mac",
            vec![dummy_up("d0").link("mv0", |l| {
                l.macvlan("d0")
                    .macvlan_mode(MacvlanMode::Bridge)
                    .address(MAC_A)
                    .up()
            })],
        ),
        case(
            "bond+slaves-declared-up",
            vec![
                NetworkConfig::new()
                    .link("bond0", |l| {
                        l.bond().bond_mode(BondMode::ActiveBackup).miimon(100).up()
                    })
                    .link("d0", |l| l.dummy().master("bond0").up())
                    .link("d1", |l| l.dummy().master("bond0").up()),
            ],
        ),
        case(
            "bond+slaves-state-unchanged",
            vec![
                NetworkConfig::new()
                    .link("bond0", |l| l.bond().bond_mode(BondMode::BalanceXor).up())
                    .link("d0", |l| l.dummy().master("bond0"))
                    .link("d1", |l| l.dummy().master("bond0")),
            ],
        ),
        case(
            "vrf+member",
            vec![
                NetworkConfig::new()
                    .link("vrf0", |l| l.vrf(10).up())
                    .link("d0", |l| l.dummy().master("vrf0").up()),
            ],
        ),
        case(
            "vrf-mac",
            vec![NetworkConfig::new().link("vrf0", |l| l.vrf(10).address(MAC_A).up())],
        ),
        case(
            "ifb-mac",
            vec![NetworkConfig::new().link("ifb0", |l| l.ifb().address(MAC_A).up())],
        ),
    ];
    assert_converges("nce-links", cases).await
}

/// netkit is 6.7+, so it gets its own gate.
#[tokio::test]
async fn netkit_converges() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("netkit");

    let cases = vec![
        case(
            "netkit-l3",
            vec![NetworkConfig::new().link("nk0", |l| {
                l.netkit("nk1").netkit_mode(NetkitMode::L3).up()
            })],
        ),
        case(
            "netkit-l2-mac",
            vec![NetworkConfig::new().link("nk0", |l| {
                l.netkit("nk1").netkit_mode(NetkitMode::L2).address(MAC_A).up()
            })],
        ),
    ];
    assert_converges("nce-netkit", cases).await
}

/// An L3 netkit has no hardware address. The kernel refuses one with a
/// bare EOPNOTSUPP; apply says which knob is wrong.
#[tokio::test]
async fn netkit_l3_mac_is_refused() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("netkit");

    let ns = TestNamespace::new("nce-netkit-l3mac")?;
    let conn = ns.connection()?;
    let err = NetworkConfig::new()
        .link("nk0", |l| l.netkit("nk1").address(MAC_A).up())
        .apply(&conn)
        .await
        .expect_err("an L3 netkit cannot take a MAC");
    assert!(err.to_string().contains("L2"), "the error must name the mode: {err}");
    Ok(())
}

/// Modifiers on links that already exist: each case's first step builds
/// the starting point, the next one changes it.
#[tokio::test]
async fn link_modifiers_converge() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("dummy", "bridge", "bonding", "vrf");

    let cases = vec![
        // A bridge's MTU follows its ports unless it was set by the
        // user, so a declared bridge MTU above a port's has to survive
        // the port joining.
        case(
            "bridge-mtu-above-port",
            vec![
                NetworkConfig::new()
                    .link("br0", |l| l.bridge().mtu(9000).up())
                    .link("d0", |l| l.dummy().mtu(1500).master("br0").up()),
            ],
        ),
        case(
            "bridge-mtu-below-port",
            vec![
                NetworkConfig::new()
                    .link("br0", |l| l.bridge().mtu(1400).up())
                    .link("d0", |l| l.dummy().master("br0").up()),
            ],
        ),
        // The bridge's own default, so setting it at creation changes
        // nothing and cannot mark it user-set.
        case(
            "bridge-mtu-1500-jumbo-port",
            vec![
                NetworkConfig::new()
                    .link("br0", |l| l.bridge().mtu(1500).up())
                    .link("d0", |l| l.dummy().mtu(9000).master("br0").up()),
            ],
        ),
        // A bridge that already exists with an MTU set at creation (as
        // `ip link add br0 mtu 9000 type bridge` leaves it) gains a port.
        case(
            "existing-bridge-mtu-gains-port",
            vec![
                NetworkConfig::new().link("br0", |l| l.bridge().mtu(9000).up()),
                NetworkConfig::new()
                    .link("br0", |l| l.bridge().mtu(9000).up())
                    .link("d0", |l| l.dummy().master("br0").up()),
            ],
        ),
        case(
            "existing-link-into-bridge",
            vec![
                dummy_up("d0"),
                NetworkConfig::new()
                    .link("br0", |l| l.bridge().up())
                    .link("d0", |l| l.dummy().master("br0").up()),
            ],
        ),
        case(
            "existing-link-out-of-bridge",
            vec![
                NetworkConfig::new()
                    .link("br0", |l| l.bridge().up())
                    .link("d0", |l| l.dummy().master("br0").up()),
                NetworkConfig::new()
                    .link("br0", |l| l.bridge().up())
                    .link("d0", |l| l.dummy().up()),
            ],
        ),
        case(
            "existing-up-link-into-bond",
            vec![
                dummy_up("d0"),
                NetworkConfig::new()
                    .link("bond0", |l| l.bond().up())
                    .link("d0", |l| l.dummy().master("bond0").up()),
            ],
        ),
        // A bond closes the port it releases, so a port declared up has
        // to be brought up after it leaves.
        case(
            "bond-port-released",
            vec![
                NetworkConfig::new()
                    .link("bond0", |l| l.bond().up())
                    .link("d0", |l| l.dummy().master("bond0").up()),
                NetworkConfig::new()
                    .link("bond0", |l| l.bond().up())
                    .link("d0", |l| l.dummy().up()),
            ],
        ),
        // …and opens the one it enslaves, so a port declared down has to
        // be taken down after it joins.
        case(
            "bond-port-declared-down",
            vec![
                // Created into the bond.
                NetworkConfig::new()
                    .link("bond0", |l| l.bond().up())
                    .link("d0", |l| l.dummy().master("bond0").down())
                    .link("d1", |l| l.dummy().down()),
                // An existing link, already down, moved into it.
                NetworkConfig::new()
                    .link("bond0", |l| l.bond().up())
                    .link("d0", |l| l.dummy().master("bond0").down())
                    .link("d1", |l| l.dummy().master("bond0").down()),
            ],
        ),
        case(
            "existing-link-into-vrf",
            vec![
                dummy_up("d0"),
                NetworkConfig::new()
                    .link("vrf0", |l| l.vrf(10).up())
                    .link("d0", |l| l.dummy().master("vrf0").up()),
            ],
        ),
        case(
            "mtu-change",
            vec![
                NetworkConfig::new().link("d0", |l| l.dummy().mtu(1500).up()),
                NetworkConfig::new().link("d0", |l| l.dummy().mtu(9000).up()),
            ],
        ),
        case(
            "mac-change",
            vec![
                NetworkConfig::new().link("d0", |l| l.dummy().address(MAC_A)),
                NetworkConfig::new().link("d0", |l| l.dummy().address(MAC_B)),
            ],
        ),
        case(
            "set-down",
            vec![
                dummy_up("d0"),
                NetworkConfig::new().link("d0", |l| l.dummy().down()),
            ],
        ),
        case(
            "bridge-mtu-change-with-port",
            vec![
                NetworkConfig::new()
                    .link("br0", |l| l.bridge().up())
                    .link("d0", |l| l.dummy().master("br0").up()),
                NetworkConfig::new()
                    .link("br0", |l| l.bridge().mtu(1400).up())
                    .link("d0", |l| l.dummy().master("br0").up()),
            ],
        ),
    ];
    assert_converges("nce-mods", cases).await
}

// ============================================================================
// Link-kind parameters (#417)
// ============================================================================

/// The kernel's view of a link, from `ip -d -j link show dev <dev>`.
///
/// An independent reader: the diff converging only shows that the diff
/// and the kernel agree, and a diff that does not compare a parameter
/// agrees with anything.
fn ip_link_json(ns: &TestNamespace, dev: &str) -> Result<serde_json::Value, String> {
    let links = ip_json(ns, &["-d", "link", "show", "dev", dev])?;
    links
        .as_array()
        .and_then(|links| links.last())
        .cloned()
        .ok_or_else(|| format!("ip link show {dev}: no link"))
}

/// The value at a dotted path, `Null` where any step is missing.
fn at_path<'a>(v: &'a serde_json::Value, path: &str) -> &'a serde_json::Value {
    path.split('.').fold(v, |v, key| &v[key])
}

/// A sequence of declarations applied to one namespace, and what the
/// kernel must hold after the last one.
struct KindCase {
    name: &'static str,
    steps: Vec<NetworkConfig>,
    /// `(device, JSON path in its `ip -d -j link` object, value)`. `Null`
    /// means the key must be absent.
    expect: Vec<(&'static str, &'static str, serde_json::Value)>,
    /// A device the last step must change in place: same ifindex after.
    in_place: Option<&'static str>,
}

fn kind_case(
    name: &'static str,
    steps: Vec<NetworkConfig>,
    expect: Vec<(&'static str, &'static str, serde_json::Value)>,
) -> KindCase {
    KindCase {
        name,
        steps,
        expect,
        in_place: None,
    }
}

fn in_place(mut c: KindCase, dev: &'static str) -> KindCase {
    c.in_place = Some(dev);
    c
}

async fn run_kind_case(case: &KindCase) -> Result<(), String> {
    let ns = TestNamespace::new("nce-kind").map_err(|e| e.to_string())?;
    let conn = ns.connection().map_err(|e| e.to_string())?;
    let last = case.steps.len() - 1;
    let mut ifindex_before = None;
    for (i, step) in case.steps.iter().enumerate() {
        if i == last
            && let Some(dev) = case.in_place
        {
            ifindex_before = Some(ip_link_json(&ns, dev)?["ifindex"].clone());
        }
        let outcome = match tokio::time::timeout(STEP_TIMEOUT, converges(&conn, step, false)).await
        {
            Ok(outcome) => outcome,
            Err(_elapsed) => Err("timed out".to_string()),
        };
        outcome.map_err(|why| format!("step {}: {why}", i + 1))?;
    }
    let mut wrong = Vec::new();
    for (dev, path, want) in &case.expect {
        let link = ip_link_json(&ns, dev)?;
        // An `ip` older than the link kind prints no `info_data` for it at
        // all — bookworm's iproute2 6.1 and netkit (6.7), on the CI lane.
        // That is this cross-check's blind spot, not the kernel's state: the
        // apply-twice check above already read the link back through nlink.
        // Say so, rather than fail on a value nobody could print.
        if path.starts_with("linkinfo.info_data.") && link["linkinfo"]["info_data"].is_null() {
            eprintln!(
                "[{}] {dev}: this `ip` does not decode {} link data; {path} not cross-checked",
                case.name, link["linkinfo"]["info_kind"],
            );
            continue;
        }
        let have = at_path(&link, path);
        if have != want {
            wrong.push(format!("{dev} {path}: kernel has {have}, declared {want}"));
        }
    }
    if let (Some(dev), Some(before)) = (case.in_place, ifindex_before) {
        let after = ip_link_json(&ns, dev)?["ifindex"].clone();
        if after != before {
            wrong.push(format!(
                "{dev} was recreated (ifindex {before} -> {after}); the change can be made in place"
            ));
        }
    }
    if wrong.is_empty() {
        Ok(())
    } else {
        Err(wrong.join("\n"))
    }
}

async fn assert_kind_cases(cases: Vec<KindCase>) -> nlink::Result<()> {
    let mut failures = Vec::new();
    for case in &cases {
        if let Err(why) = run_kind_case(case).await {
            failures.push(format!("[{}] {why}", case.name));
        }
    }
    assert!(
        failures.is_empty(),
        "{} case(s) did not reach the kernel:\n\n{}",
        failures.len(),
        failures.join("\n\n")
    );
    Ok(())
}

/// Changing a declared link's kind parameters reaches the kernel, and
/// converges. The diff compared MTU, MAC, master and state only, so a
/// changed VNI, VLAN id or bond mode came back as an empty diff and the
/// kernel kept the old value (#417).
///
/// What can be changed on a live link is changed in place (`in_place`
/// pins the ifindex); what cannot is recreated, and everything the
/// config declares on it — addresses, routes through it, its master, its
/// ports, links stacked on it — comes back with it, which the apply-twice
/// check in each step shows.
#[tokio::test]
async fn link_kind_parameter_changes_reach_the_kernel() -> nlink::Result<()> {
    use serde_json::json;
    require_root!();
    nlink::require_modules!("dummy", "8021q", "vxlan", "macvlan", "bonding", "vrf", "bridge");

    let v4 = |a, b, c, d| -> std::net::IpAddr { Ipv4Addr::new(a, b, c, d).into() };

    // A VLAN with addresses and a route through it, in a bridge.
    let vlan = |id: u16, proto: Option<VlanProtocol>| {
        NetworkConfig::new()
            .link("d0", |l| l.dummy().up())
            .link("br0", |l| l.bridge().up())
            .link("d0.10", |l| {
                let l = l.vlan("d0", id).master("br0").up();
                match proto {
                    Some(p) => l.vlan_protocol(p),
                    None => l,
                }
            })
            .link("v1", |l| l.vlan("d0", 50).up())
            .address("v1", "10.4.0.1/24")
            .unwrap()
            .address("v1", "fd00:4::1/64")
            .unwrap()
            .route("10.40.0.0/16", |r| r.via("10.4.0.254"))
            .unwrap()
            .route("2001:db8:40::/48", |r| r.dev("v1"))
            .unwrap()
    };
    let vlan_on = |parent: &str, id: u16| {
        NetworkConfig::new()
            .link("d0", |l| l.dummy().up())
            .link("d1", |l| l.dummy().up())
            .link("v1", |l| l.vlan(parent, id).up())
            .address("v1", "10.4.0.1/24")
            .unwrap()
    };

    // A VXLAN with an address, a route through it, and a bridge master.
    struct Vx {
        vni: u32,
        port: Option<u16>,
        remote: Option<std::net::IpAddr>,
        local: Option<std::net::IpAddr>,
        underlay: Option<&'static str>,
    }
    let vx = |p: Vx| {
        NetworkConfig::new()
            .link("d0", |l| l.dummy().up())
            .link("d1", |l| l.dummy().up())
            .address("d0", "10.1.0.1/24")
            .unwrap()
            .address("d0", "10.1.0.5/24")
            .unwrap()
            .address("d1", "10.2.0.1/24")
            .unwrap()
            .link("br0", |l| l.bridge().up())
            .link("vx0", |l| {
                let mut l = l.vxlan(p.vni).master("br0").up();
                if let Some(port) = p.port {
                    l = l.vxlan_port(port);
                }
                if let Some(r) = p.remote {
                    l = l.vxlan_remote(r);
                }
                if let Some(a) = p.local {
                    l = l.vxlan_local(a);
                }
                if let Some(d) = p.underlay {
                    l = l.vxlan_underlay_dev(d);
                }
                l
            })
            .address("vx0", "10.5.0.1/24")
            .unwrap()
            .route("10.50.0.0/16", |r| r.via("10.5.0.254"))
            .unwrap()
    };
    let base_vx = || Vx {
        vni: 100,
        port: Some(4790),
        remote: Some(v4(10, 1, 0, 2)),
        local: Some(v4(10, 1, 0, 1)),
        underlay: Some("d0"),
    };

    // A bond with two declared ports and an address, and a route through
    // a port: a bond closes the ports it releases, which flushes it.
    let bond = |f: fn(nlink::netlink::config::LinkBuilder) -> nlink::netlink::config::LinkBuilder| {
        NetworkConfig::new()
            .link("bond0", |l| f(l.bond()).up())
            .link("d0", |l| l.dummy().master("bond0").up())
            .link("d1", |l| l.dummy().master("bond0").up())
            .address("bond0", "10.6.0.1/24")
            .unwrap()
            .address("bond0", "fd00:6::1/64")
            .unwrap()
            .route("10.60.0.0/16", |r| r.via("10.6.0.254"))
            .unwrap()
            .route("10.61.0.0/16", |r| r.dev("d0"))
            .unwrap()
    };

    let macvlan = |parent: &str, mode: MacvlanMode| {
        NetworkConfig::new()
            .link("d0", |l| l.dummy().up())
            .link("d1", |l| l.dummy().up())
            .link("mv0", |l| l.macvlan(parent).macvlan_mode(mode).up())
            .address("mv0", "10.7.0.1/24")
            .unwrap()
    };

    let vrf = |table: u32| {
        NetworkConfig::new()
            .link("vrf0", |l| l.vrf(table).up())
            .link("d0", |l| l.dummy().master("vrf0").up())
            .address("d0", "10.8.0.1/24")
            .unwrap()
            .address("d0", "fd00:8::1/64")
            .unwrap()
            .route("10.80.0.0/16", |r| r.via("10.8.0.254").table(table))
            .unwrap()
    };

    // Q-in-Q: an 802.1ad outer tag with an 802.1Q VLAN stacked on it.
    let qinq = |outer: u16| {
        NetworkConfig::new()
            .link("d0", |l| l.dummy().up())
            .link("s0", |l| l.vlan("d0", outer).vlan_protocol(VlanProtocol::Dot1ad).up())
            .link("c0", |l| l.vlan("s0", 30).up())
            .address("c0", "10.9.0.1/24")
            .unwrap()
    };

    let cases = vec![
        kind_case(
            "vlan-id",
            vec![vlan(10, None), vlan(20, None)],
            vec![("d0.10", "linkinfo.info_data.id", json!(20))],
        ),
        kind_case(
            "vlan-protocol",
            vec![vlan(10, None), vlan(10, Some(VlanProtocol::Dot1ad))],
            vec![("d0.10", "linkinfo.info_data.protocol", json!("802.1ad"))],
        ),
        // An undeclared protocol is the kernel's default, 802.1Q.
        kind_case(
            "vlan-protocol-back-to-default",
            vec![vlan(10, Some(VlanProtocol::Dot1ad)), vlan(10, None)],
            vec![("d0.10", "linkinfo.info_data.protocol", json!("802.1Q"))],
        ),
        kind_case(
            "vlan-parent",
            vec![vlan_on("d0", 10), vlan_on("d1", 10)],
            vec![("v1", "link", json!("d1"))],
        ),
        kind_case(
            "vlan-with-a-vlan-stacked-on-it",
            vec![qinq(20), qinq(21)],
            vec![
                ("s0", "linkinfo.info_data.id", json!(21)),
                ("c0", "link", json!("s0")),
                ("c0", "linkinfo.info_data.id", json!(30)),
            ],
        ),
        // The macvlan's own MAC is in the VLAN's unicast address list, so
        // `bridge fdb` shows it on v1 as `self permanent`: the kernel's
        // entry, put back when the macvlan is, not undeclared state (#426).
        kind_case(
            "vlan-with-a-macvlan-stacked-on-it",
            vec![
                vlan_on("d0", 10).link("mv0", |l| l.macvlan("v1").up()),
                vlan_on("d0", 20).link("mv0", |l| l.macvlan("v1").up()),
            ],
            vec![
                ("v1", "linkinfo.info_data.id", json!(20)),
                ("mv0", "link", json!("v1")),
            ],
        ),
        kind_case(
            "vxlan-vni",
            vec![vx(base_vx()), vx(Vx { vni: 200, ..base_vx() })],
            vec![
                ("vx0", "linkinfo.info_data.id", json!(200)),
                ("vx0", "linkinfo.info_data.port", json!(4790)),
                ("vx0", "linkinfo.info_data.remote", json!("10.1.0.2")),
            ],
        ),
        kind_case(
            "vxlan-port",
            vec![vx(base_vx()), vx(Vx { port: Some(4791), ..base_vx() })],
            vec![("vx0", "linkinfo.info_data.port", json!(4791))],
        ),
        in_place(
            kind_case(
                "vxlan-remote",
                vec![vx(base_vx()), vx(Vx { remote: Some(v4(10, 1, 0, 3)), ..base_vx() })],
                vec![("vx0", "linkinfo.info_data.remote", json!("10.1.0.3"))],
            ),
            "vx0",
        ),
        in_place(
            kind_case(
                "vxlan-remote-removed",
                vec![vx(base_vx()), vx(Vx { remote: None, ..base_vx() })],
                vec![("vx0", "linkinfo.info_data.remote", serde_json::Value::Null)],
            ),
            "vx0",
        ),
        in_place(
            kind_case(
                "vxlan-local",
                vec![vx(base_vx()), vx(Vx { local: Some(v4(10, 1, 0, 5)), ..base_vx() })],
                vec![("vx0", "linkinfo.info_data.local", json!("10.1.0.5"))],
            ),
            "vx0",
        ),
        in_place(
            kind_case(
                "vxlan-underlay-moved",
                vec![vx(base_vx()), vx(Vx { underlay: Some("d1"), ..base_vx() })],
                vec![("vx0", "linkinfo.info_data.link", json!("d1"))],
            ),
            "vx0",
        ),
        // The kernel keeps a VXLAN's lower device when a change names
        // none, so dropping the underlay recreates the link.
        kind_case(
            "vxlan-underlay-removed",
            vec![vx(base_vx()), vx(Vx { underlay: None, ..base_vx() })],
            vec![("vx0", "linkinfo.info_data.link", serde_json::Value::Null)],
        ),
        kind_case(
            "bond-mode",
            vec![
                bond(|b| b.bond_mode(BondMode::ActiveBackup).miimon(100)),
                bond(|b| b.bond_mode(BondMode::BalanceXor).miimon(100)),
            ],
            vec![
                ("bond0", "linkinfo.info_data.mode", json!("balance-xor")),
                ("d0", "master", json!("bond0")),
                ("d1", "master", json!("bond0")),
            ],
        ),
        in_place(
            kind_case(
                "bond-miimon-and-delays",
                vec![
                    bond(|b| b.bond_mode(BondMode::ActiveBackup).miimon(100).bond_updelay(200)),
                    bond(|b| {
                        b.bond_mode(BondMode::ActiveBackup)
                            .miimon(250)
                            .bond_updelay(500)
                            .bond_downdelay(750)
                    }),
                ],
                vec![
                    ("bond0", "linkinfo.info_data.miimon", json!(250)),
                    ("bond0", "linkinfo.info_data.updelay", json!(500)),
                    ("bond0", "linkinfo.info_data.downdelay", json!(750)),
                ],
            ),
            "bond0",
        ),
        // The kernel keeps a delay as a count of miimon intervals, so a
        // delay that is not a multiple of miimon is rounded down.
        kind_case(
            "bond-updelay-rounded",
            vec![bond(|b| b.bond_mode(BondMode::ActiveBackup).miimon(100).bond_updelay(150))],
            vec![("bond0", "linkinfo.info_data.updelay", json!(100))],
        ),
        in_place(
            kind_case(
                "bond-xmit-min-links-resend-igmp",
                vec![
                    bond(|b| b.bond_mode(BondMode::BalanceXor)),
                    bond(|b| {
                        b.bond_mode(BondMode::BalanceXor)
                            .xmit_hash_policy(1)
                            .min_links(1)
                            .bond_resend_igmp(3)
                    }),
                ],
                vec![
                    ("bond0", "linkinfo.info_data.xmit_hash_policy", json!("layer3+4")),
                    ("bond0", "linkinfo.info_data.min_links", json!(1)),
                    ("bond0", "linkinfo.info_data.resend_igmp", json!(3)),
                ],
            ),
            "bond0",
        ),
        // lacp_rate and ad_select are only taken by a bond that is down.
        kind_case(
            "bond-lacp-rate-ad-select",
            vec![
                bond(|b| b.bond_mode(BondMode::Ieee802_3ad).miimon(100)),
                bond(|b| {
                    b.bond_mode(BondMode::Ieee802_3ad)
                        .miimon(100)
                        .bond_lacp_rate(nlink::netlink::config::BondLacpRate::Fast)
                        .bond_ad_select(nlink::netlink::config::BondAdSelect::Bandwidth)
                }),
            ],
            vec![
                ("bond0", "linkinfo.info_data.ad_lacp_rate", json!("fast")),
                ("bond0", "linkinfo.info_data.ad_select", json!("bandwidth")),
            ],
        ),
        in_place(
            kind_case(
                "macvlan-mode",
                vec![macvlan("d0", MacvlanMode::Bridge), macvlan("d0", MacvlanMode::Vepa)],
                vec![("mv0", "linkinfo.info_data.mode", json!("vepa"))],
            ),
            "mv0",
        ),
        // Passthru cannot be set or cleared on a live macvlan.
        kind_case(
            "macvlan-to-passthru",
            vec![macvlan("d0", MacvlanMode::Bridge), macvlan("d0", MacvlanMode::Passthru)],
            vec![("mv0", "linkinfo.info_data.mode", json!("passthru"))],
        ),
        kind_case(
            "macvlan-parent",
            vec![macvlan("d0", MacvlanMode::Bridge), macvlan("d1", MacvlanMode::Bridge)],
            vec![("mv0", "link", json!("d1"))],
        ),
        kind_case(
            "vrf-table",
            vec![vrf(10), vrf(20)],
            vec![
                ("vrf0", "linkinfo.info_data.table", json!(20)),
                ("d0", "master", json!("vrf0")),
            ],
        ),
        kind_case(
            "kind",
            vec![
                NetworkConfig::new().link("x0", |l| l.dummy().up()),
                NetworkConfig::new().link("x0", |l| l.bridge().up()),
            ],
            vec![("x0", "linkinfo.info_kind", json!("bridge"))],
        ),
        // A bridge's database goes with it, but the entries the kernel
        // made — the port's local MAC, per VLAN too, and the bridge's own
        // multicast list — are not undeclared state (#426).
        kind_case(
            "kind-of-a-bridge-with-a-port",
            vec![
                NetworkConfig::new()
                    .link("x0", |l| l.bridge().up())
                    .link("d0", |l| l.dummy().master("x0").up()),
                NetworkConfig::new()
                    .link("x0", |l| l.bond().up())
                    .link("d0", |l| l.dummy().master("x0").up()),
            ],
            vec![
                ("x0", "linkinfo.info_kind", json!("bond")),
                ("d0", "master", json!("x0")),
            ],
        ),
    ];
    assert_kind_cases(cases).await
}

/// A VXLAN with IPv6 endpoints. The builder wrote `IFLA_VXLAN_LOCAL` and
/// `IFLA_VXLAN_GROUP` for IPv4 addresses and dropped IPv6 ones without a
/// word, so a declared IPv6 `local` (or `remote`) never reached the kernel
/// and the diff, which did not compare them, said nothing either (#418).
#[tokio::test]
async fn vxlan_ipv6_endpoints_reach_the_kernel() -> nlink::Result<()> {
    use serde_json::json;
    require_root!();
    nlink::require_modules!("dummy", "vxlan");

    let ip = |s: &str| -> std::net::IpAddr { s.parse().unwrap() };
    let vx = |local: Option<&str>, remote: Option<&str>| {
        let (local, remote) = (local.map(ip), remote.map(ip));
        NetworkConfig::new()
            .link("d0", |l| l.dummy().up())
            .address("d0", "fd00:1::1/64")
            .unwrap()
            .address("d0", "fd00:1::5/64")
            .unwrap()
            .address("d0", "10.1.0.1/24")
            .unwrap()
            .link("vx0", |l| {
                let mut l = l.vxlan(100).vxlan_underlay_dev("d0").vxlan_port(4789).up();
                if let Some(a) = local {
                    l = l.vxlan_local(a);
                }
                if let Some(a) = remote {
                    l = l.vxlan_remote(a);
                }
                l
            })
            .address("vx0", "fd00:2::1/64")
            .unwrap()
    };
    let null = serde_json::Value::Null;
    let cases = vec![
        kind_case(
            "local-and-remote",
            vec![vx(Some("fd00:1::1"), Some("fd00:1::2"))],
            vec![
                ("vx0", "linkinfo.info_data.local6", json!("fd00:1::1")),
                ("vx0", "linkinfo.info_data.remote6", json!("fd00:1::2")),
            ],
        ),
        kind_case(
            "local-only",
            vec![vx(Some("fd00:1::1"), None)],
            vec![("vx0", "linkinfo.info_data.local6", json!("fd00:1::1"))],
        ),
        kind_case(
            "remote-only",
            vec![vx(None, Some("fd00:1::2"))],
            vec![("vx0", "linkinfo.info_data.remote6", json!("fd00:1::2"))],
        ),
        in_place(
            kind_case(
                "local-changed",
                vec![
                    vx(Some("fd00:1::1"), Some("fd00:1::2")),
                    vx(Some("fd00:1::5"), Some("fd00:1::2")),
                ],
                vec![("vx0", "linkinfo.info_data.local6", json!("fd00:1::5"))],
            ),
            "vx0",
        ),
        in_place(
            kind_case(
                "remote-changed-then-removed",
                vec![
                    vx(Some("fd00:1::1"), Some("fd00:1::2")),
                    vx(Some("fd00:1::1"), Some("fd00:1::3")),
                    vx(Some("fd00:1::1"), None),
                ],
                vec![
                    ("vx0", "linkinfo.info_data.remote6", null.clone()),
                    ("vx0", "linkinfo.info_data.local6", json!("fd00:1::1")),
                ],
            ),
            "vx0",
        ),
        // `vxlan_nl2conf` refuses a change of address family on a live
        // VXLAN, so this one is recreated.
        kind_case(
            "ipv4-to-ipv6",
            vec![
                vx(Some("10.1.0.1"), Some("10.1.0.2")),
                vx(Some("fd00:1::1"), Some("fd00:1::2")),
            ],
            vec![
                ("vx0", "linkinfo.info_data.local6", json!("fd00:1::1")),
                ("vx0", "linkinfo.info_data.local", null.clone()),
                ("vx0", "linkinfo.info_data.remote", null.clone()),
            ],
        ),
        kind_case(
            "ipv6-to-ipv4",
            vec![
                vx(Some("fd00:1::1"), Some("fd00:1::2")),
                vx(Some("10.1.0.1"), Some("10.1.0.2")),
            ],
            vec![
                ("vx0", "linkinfo.info_data.local", json!("10.1.0.1")),
                ("vx0", "linkinfo.info_data.local6", null.clone()),
                ("vx0", "linkinfo.info_data.remote6", null),
            ],
        ),
    ];
    assert_kind_cases(cases).await
}

/// A recreate that would destroy something the config does not declare
/// is refused, says what, and leaves the kernel alone.
///
/// `NetworkConfig` cannot declare FDB entries, neighbours, multipath
/// routes or nexthop objects, so every one of those on a link the apply
/// would delete is undeclared state — and so is what the kernel flushes
/// from the ports of a deleted VRF or bond as they leave it (#426).
#[tokio::test]
async fn a_recreate_that_would_destroy_undeclared_state_is_refused() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("dummy", "8021q", "vxlan", "bonding", "bridge", "vrf");

    struct Refusal {
        name: &'static str,
        /// Applied by nlink; then `extra` runs commands outside it.
        first: NetworkConfig,
        extra: Vec<(&'static str, Vec<&'static str>)>,
        second: NetworkConfig,
        /// The error must name this.
        names: &'static str,
        /// `(device, JSON path, value)` the kernel must still hold.
        unchanged: (&'static str, &'static str, serde_json::Value),
    }
    let vx = |vni: u32| {
        NetworkConfig::new()
            .link("d0", |l| l.dummy().up())
            .link("vx0", |l| l.vxlan(vni).vxlan_underlay_dev("d0").vxlan_port(4790).up())
    };
    let bond = |mode: BondMode| {
        NetworkConfig::new()
            .link("bond0", |l| l.bond().bond_mode(mode).up())
            .link("d0", |l| l.dummy().master("bond0").up())
    };
    let vlan = |id: u16| {
        NetworkConfig::new()
            .link("d0", |l| l.dummy().up())
            .link("v1", |l| l.vlan("d0", id).up())
    };
    // A VXLAN that is a bridge port, with a remote: the kernel's own FDB
    // entries (the default remote, the port's local MAC) do not block it.
    let bridged_vx = |vni: u32| {
        NetworkConfig::new()
            .link("d0", |l| l.dummy().up())
            .link("br0", |l| l.bridge().up())
            .link("vx0", |l| {
                l.vxlan(vni)
                    .vxlan_underlay_dev("d0")
                    .vxlan_port(4790)
                    .vxlan_remote(Ipv4Addr::new(10, 1, 0, 2).into())
                    .master("br0")
                    .up()
            })
    };
    // A VLAN with addresses, next to a second link a multipath route or a
    // nexthop group can also use.
    let addressed_vlan = |id: u16| {
        vlan(id)
            .link("d1", |l| l.dummy().up())
            .address("v1", "10.5.0.1/24")
            .unwrap()
            .address("v1", "fd00:5::1/64")
            .unwrap()
            .address("d1", "10.6.0.1/24")
            .unwrap()
            .address("d1", "fd00:6::1/64")
            .unwrap()
    };
    let vrf = |table: u32| {
        NetworkConfig::new()
            .link("vrf0", |l| l.vrf(table).up())
            .link("d0", |l| l.dummy().master("vrf0").up())
            .address("d0", "10.8.0.1/24")
            .unwrap()
    };
    let cases = vec![
        Refusal {
            name: "undeclared-address",
            first: vx(100),
            extra: vec![("ip", vec!["addr", "add", "10.5.0.9/24", "dev", "vx0"])],
            second: vx(200),
            names: "10.5.0.9/24",
            unchanged: ("vx0", "linkinfo.info_data.id", serde_json::json!(100)),
        },
        Refusal {
            name: "undeclared-route",
            first: vx(100).address("vx0", "10.5.0.1/24").unwrap(),
            extra: vec![("ip", vec!["route", "add", "10.55.0.0/16", "via", "10.5.0.254"])],
            second: vx(200).address("vx0", "10.5.0.1/24").unwrap(),
            names: "10.55.0.0/16",
            unchanged: ("vx0", "linkinfo.info_data.id", serde_json::json!(100)),
        },
        Refusal {
            name: "undeclared-port",
            first: bond(BondMode::ActiveBackup),
            extra: vec![
                ("ip", vec!["link", "add", "d9", "type", "dummy"]),
                ("ip", vec!["link", "set", "d9", "master", "bond0"]),
            ],
            second: bond(BondMode::BalanceXor),
            names: "d9",
            unchanged: ("bond0", "linkinfo.info_data.mode", serde_json::json!("active-backup")),
        },
        Refusal {
            name: "undeclared-stacked-link",
            first: vlan(10),
            extra: vec![(
                "ip",
                vec!["link", "add", "link", "v1", "name", "v1.30", "type", "vlan", "id", "30"],
            )],
            second: vlan(20),
            names: "v1.30",
            unchanged: ("v1", "linkinfo.info_data.id", serde_json::json!(10)),
        },
        Refusal {
            name: "undeclared-qdisc",
            first: vlan(10),
            extra: vec![("tc", vec!["qdisc", "add", "dev", "v1", "root", "handle", "1:", "prio"])],
            second: vlan(20),
            names: "prio",
            unchanged: ("v1", "linkinfo.info_data.id", serde_json::json!(10)),
        },
        // Head-end replication: one all-zeros FDB entry per remote VTEP.
        Refusal {
            name: "undeclared-fdb-flood-entry",
            first: vx(100),
            extra: vec![(
                "bridge",
                vec![
                    "fdb", "append", "00:00:00:00:00:00", "dev", "vx0", "dst", "192.0.2.1",
                    "permanent",
                ],
            )],
            second: vx(200),
            names: "192.0.2.1",
            unchanged: ("vx0", "linkinfo.info_data.id", serde_json::json!(100)),
        },
        // A remote on another VXLAN that sends through the recreated link:
        // the entry would keep naming its old ifindex (#438).
        Refusal {
            name: "undeclared-fdb-entry-via-the-link",
            first: vlan(10),
            extra: vec![
                ("ip", vec!["link", "add", "vx9", "type", "vxlan", "id", "9", "dstport", "4791"]),
                (
                    "bridge",
                    vec![
                        "fdb", "append", "00:00:00:00:00:00", "dev", "vx9", "dst", "192.0.2.9",
                        "via", "v1",
                    ],
                ),
            ],
            second: vlan(20),
            names: "via v1",
            unchanged: ("v1", "linkinfo.info_data.id", serde_json::json!(10)),
        },
        Refusal {
            name: "undeclared-fdb-unicast-entry",
            first: vx(100),
            extra: vec![(
                "bridge",
                vec![
                    "fdb", "add", "02:00:5e:10:00:41", "dev", "vx0", "dst", "192.0.2.5",
                    "permanent",
                ],
            )],
            second: vx(200),
            names: "02:00:5e:10:00:41",
            unchanged: ("vx0", "linkinfo.info_data.id", serde_json::json!(100)),
        },
        // A static entry in a bridge's FDB, for the port being recreated.
        Refusal {
            name: "undeclared-fdb-entry-in-the-bridge",
            first: bridged_vx(100),
            extra: vec![(
                "bridge",
                vec!["fdb", "add", "02:00:5e:10:00:42", "dev", "vx0", "master", "static"],
            )],
            second: bridged_vx(200),
            names: "02:00:5e:10:00:42",
            unchanged: ("vx0", "linkinfo.info_data.id", serde_json::json!(100)),
        },
        Refusal {
            name: "undeclared-permanent-neighbour",
            first: addressed_vlan(10),
            extra: vec![(
                "ip",
                vec![
                    "neigh", "add", "10.5.0.7", "lladdr", "02:00:5e:10:00:07", "nud", "permanent",
                    "dev", "v1",
                ],
            )],
            second: addressed_vlan(20),
            names: "10.5.0.7",
            unchanged: ("v1", "linkinfo.info_data.id", serde_json::json!(10)),
        },
        Refusal {
            name: "undeclared-permanent-v6-neighbour",
            first: addressed_vlan(10),
            extra: vec![(
                "ip",
                vec![
                    "-6", "neigh", "add", "fd00:5::7", "lladdr", "02:00:5e:10:00:08", "nud",
                    "permanent", "dev", "v1",
                ],
            )],
            second: addressed_vlan(20),
            names: "fd00:5::7",
            unchanged: ("v1", "linkinfo.info_data.id", serde_json::json!(10)),
        },
        Refusal {
            name: "undeclared-proxy-neighbour",
            first: addressed_vlan(10),
            extra: vec![("ip", vec!["neigh", "add", "proxy", "10.5.0.8", "dev", "v1"])],
            second: addressed_vlan(20),
            names: "10.5.0.8",
            unchanged: ("v1", "linkinfo.info_data.id", serde_json::json!(10)),
        },
        // A multipath route's nexthops are in RTA_MULTIPATH; it has no oif.
        Refusal {
            name: "undeclared-multipath-route",
            first: addressed_vlan(10),
            extra: vec![(
                "ip",
                vec![
                    "route", "add", "10.56.0.0/16", "nexthop", "via", "10.5.0.254", "dev", "v1",
                    "nexthop", "via", "10.6.0.254", "dev", "d1",
                ],
            )],
            second: addressed_vlan(20),
            names: "10.56.0.0/16",
            unchanged: ("v1", "linkinfo.info_data.id", serde_json::json!(10)),
        },
        Refusal {
            name: "undeclared-multipath-v6-route",
            first: addressed_vlan(10),
            extra: vec![(
                "ip",
                vec![
                    "-6", "route", "add", "2001:db8:56::/48", "nexthop", "via", "fd00:5::fe", "dev",
                    "v1", "nexthop", "via", "fd00:6::fe", "dev", "d1",
                ],
            )],
            second: addressed_vlan(20),
            names: "2001:db8:56::/48",
            unchanged: ("v1", "linkinfo.info_data.id", serde_json::json!(10)),
        },
        // A nexthop object on the link: deleted with it, and so is every
        // route that uses it.
        Refusal {
            name: "undeclared-nexthop-object",
            first: addressed_vlan(10),
            extra: vec![(
                "ip",
                vec!["nexthop", "add", "id", "5", "via", "10.5.0.253", "dev", "v1"],
            )],
            second: addressed_vlan(20),
            names: "nexthop id 5",
            unchanged: ("v1", "linkinfo.info_data.id", serde_json::json!(10)),
        },
        // A route through a nexthop group: no oif, and its nexthops are
        // objects, not RTA_MULTIPATH entries of its own.
        Refusal {
            name: "undeclared-route-through-a-nexthop-group",
            first: addressed_vlan(10),
            extra: vec![
                ("ip", vec!["nexthop", "add", "id", "6", "via", "10.5.0.253", "dev", "v1"]),
                ("ip", vec!["nexthop", "add", "id", "7", "via", "10.6.0.253", "dev", "d1"]),
                ("ip", vec!["nexthop", "add", "id", "8", "group", "6/7"]),
                ("ip", vec!["route", "add", "10.57.0.0/16", "nhid", "8"]),
            ],
            second: addressed_vlan(20),
            names: "10.57.0.0/16",
            unchanged: ("v1", "linkinfo.info_data.id", serde_json::json!(10)),
        },
        // A VRF releases its ports when it is deleted, and the kernel
        // flushes what hangs off a port that leaves an L3 master: its
        // routes (`fib_disable_ip`, forced, for NETDEV_CHANGEUPPER) and its
        // neighbours (`arp_ifdown`).
        Refusal {
            name: "undeclared-neighbour-on-a-port",
            first: vrf(10),
            extra: vec![(
                "ip",
                vec![
                    "neigh", "add", "10.8.0.7", "lladdr", "02:00:5e:10:00:09", "nud", "permanent",
                    "dev", "d0",
                ],
            )],
            second: vrf(20),
            names: "10.8.0.7",
            unchanged: ("vrf0", "linkinfo.info_data.table", serde_json::json!(10)),
        },
        Refusal {
            name: "undeclared-route-through-a-port",
            first: vrf(10),
            extra: vec![("ip", vec!["route", "add", "10.88.0.0/16", "dev", "d0"])],
            second: vrf(20),
            names: "10.88.0.0/16",
            unchanged: ("vrf0", "linkinfo.info_data.table", serde_json::json!(10)),
        },
    ];

    let mut failures = Vec::new();
    for case in cases {
        let ns = TestNamespace::new("nce-refuse")?;
        let conn = ns.connection()?;
        let first = case.first.apply(&conn).await?;
        assert!(first.is_success(), "[{}] {first:?}", case.name);
        for (cmd, args) in &case.extra {
            ns.exec(cmd, args)?;
        }
        let diff = case.second.diff(&conn).await?;
        let shown = diff.to_string();
        match case.second.apply(&conn).await {
            Ok(r) => failures.push(format!(
                "[{}] apply succeeded ({:?}); diff was:\n{shown}",
                case.name, r.summary
            )),
            Err(e) if !e.is_not_supported() => failures.push(format!(
                "[{}] wrong error kind: {e}",
                case.name
            )),
            Err(e) if !e.to_string().contains(case.names) => failures.push(format!(
                "[{}] the error does not name {}: {e}",
                case.name, case.names
            )),
            Err(_) => {}
        }
        if !shown.contains(case.names) {
            failures.push(format!(
                "[{}] the diff does not name {}:\n{shown}",
                case.name, case.names
            ));
        }
        let (dev, path, want) = &case.unchanged;
        let link = ip_link_json(&ns, dev).map_err(nlink::Error::InvalidMessage)?;
        if at_path(&link, path) != want {
            failures.push(format!(
                "[{}] the kernel changed: {dev} {path} is {}",
                case.name,
                at_path(&link, path)
            ));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n\n"));
    Ok(())
}

/// netkit: the policies change in place; the mode cannot change on a live
/// pair, and recreating it would delete the peer, which may live in
/// another namespace — so that is refused.
#[tokio::test]
async fn netkit_kind_parameters() -> nlink::Result<()> {
    use nlink::netlink::config::NetkitPolicy;
    use serde_json::json;
    require_root!();
    nlink::require_modules!("netkit");

    let nk = |mode: NetkitMode, policy: NetkitPolicy, peer: NetkitPolicy| {
        NetworkConfig::new().link("nk0", |l| {
            l.netkit("nk1")
                .netkit_mode(mode)
                .netkit_primary_policy(policy)
                .netkit_peer_policy(peer)
                .up()
        })
    };
    let cases = vec![in_place(
        kind_case(
            "netkit-policies",
            vec![
                nk(NetkitMode::L2, NetkitPolicy::Forward, NetkitPolicy::Forward),
                nk(NetkitMode::L2, NetkitPolicy::Blackhole, NetkitPolicy::Blackhole),
            ],
            vec![
                ("nk0", "linkinfo.info_data.policy", json!("blackhole")),
                ("nk0", "linkinfo.info_data.peer_policy", json!("blackhole")),
            ],
        ),
        "nk0",
    )];
    assert_kind_cases(cases).await?;

    let ns = TestNamespace::new("nce-nk-mode")?;
    let conn = ns.connection()?;
    let l2 = nk(NetkitMode::L2, NetkitPolicy::Forward, NetkitPolicy::Forward);
    let applied = l2.apply(&conn).await?;
    assert!(applied.is_success(), "{applied:?}");
    let before = ip_link_json(&ns, "nk0").map_err(nlink::Error::InvalidMessage)?;
    let err = nk(NetkitMode::L3, NetkitPolicy::Forward, NetkitPolicy::Forward)
        .apply(&conn)
        .await
        .expect_err("a netkit mode change cannot be applied");
    assert!(err.is_not_supported(), "{err}");
    assert!(err.to_string().contains("mode"), "the error must name the mode: {err}");
    // Refused before anything changed: the same link, still L2.
    let link = ip_link_json(&ns, "nk0").map_err(nlink::Error::InvalidMessage)?;
    assert_eq!(link["ifindex"], before["ifindex"], "the refused apply recreated nk0");
    if link["linkinfo"]["info_data"].is_null() {
        eprintln!("this `ip` does not decode netkit link data; the mode is not cross-checked");
    } else {
        assert_eq!(at_path(&link, "linkinfo.info_data.mode"), &json!("l2"));
    }
    Ok(())
}

// ============================================================================
// Addresses
// ============================================================================

#[tokio::test]
async fn addresses_converge() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("dummy", "vrf", "bonding");

    let addressed = |cfg: NetworkConfig| {
        cfg.address("d0", "10.2.0.1/24")
            .unwrap()
            .address("d0", "fd00:2::1/64")
            .unwrap()
    };

    let cases = vec![
        case("v4+v6-on-up-link", vec![addressed(dummy_up("d0"))]),
        case(
            "v4+v6-on-down-link",
            vec![addressed(NetworkConfig::new().link("d0", |l| l.dummy().down()))],
        ),
        case(
            "host-routes",
            vec![
                dummy_up("d0")
                    .address("d0", "10.2.0.9/32")
                    .unwrap()
                    .address("d0", "fd00:2::9/128")
                    .unwrap(),
            ],
        ),
        // Setting a link down makes the kernel drop its IPv6 addresses
        // (unless `keep_addr_on_down`); the diff saw them present before
        // the link change ran.
        case(
            "existing-link-set-down",
            vec![
                addressed(dummy_up("d0")),
                addressed(NetworkConfig::new().link("d0", |l| l.dummy().down())),
            ],
        ),
        // Enslaving to an L3 master flushes the port's IPv6 addresses
        // (addrconf's NETDEV_CHANGEUPPER handler).
        case(
            "existing-link-moved-into-vrf",
            vec![
                addressed(dummy_up("d0")),
                addressed(
                    NetworkConfig::new()
                        .link("vrf0", |l| l.vrf(10).up())
                        .link("d0", |l| l.dummy().master("vrf0").up()),
                ),
            ],
        ),
        // …and so does leaving one.
        case(
            "existing-link-moved-out-of-vrf",
            vec![
                addressed(
                    NetworkConfig::new()
                        .link("vrf0", |l| l.vrf(10).up())
                        .link("d0", |l| l.dummy().master("vrf0").up()),
                ),
                addressed(
                    NetworkConfig::new()
                        .link("vrf0", |l| l.vrf(10).up())
                        .link("d0", |l| l.dummy().up()),
                ),
            ],
        ),
        // A bond takes its port down on the way in and out.
        case(
            "existing-link-moved-into-bond",
            vec![
                addressed(dummy_up("d0")),
                addressed(
                    NetworkConfig::new()
                        .link("bond0", |l| l.bond().up())
                        .link("d0", |l| l.dummy().master("bond0").up()),
                ),
            ],
        ),
        case(
            "new-link-in-vrf",
            vec![addressed(
                NetworkConfig::new()
                    .link("vrf0", |l| l.vrf(10).up())
                    .link("d0", |l| l.dummy().master("vrf0").up()),
            )],
        ),
    ];
    assert_converges("nce-addrs", cases).await
}

/// A purging apply that takes a link down: the kernel flushes the link's
/// IPv6 addresses during the link step, including the undeclared one the
/// purge is about to remove. That removal finds it gone, which is the
/// state wanted, not an error.
#[tokio::test]
async fn purge_tolerates_an_address_the_link_change_flushed() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("dummy");

    let cases = vec![
        case(
            "link-down-flushes-undeclared",
            vec![
                dummy_up("d0")
                    .address("d0", "fd00:2::1/64")?
                    .address("d0", "fd00:2::2/64")?,
                NetworkConfig::new()
                    .link("d0", |l| l.dummy().down())
                    .address("d0", "fd00:2::1/64")?,
            ],
        )
        .purging(),
    ];
    assert_converges("nce-addr-purge", cases).await
}

// ============================================================================
// Routes
// ============================================================================

#[tokio::test]
async fn routes_converge() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("dummy");

    let base = || {
        dummy_up("d0")
            .address("d0", "10.3.0.1/24")
            .unwrap()
            .address("d0", "fd00:3::1/64")
            .unwrap()
    };
    let with_route = |dst: &str, f: fn(RouteBuilder) -> RouteBuilder| base().route(dst, f).unwrap();

    let cases = vec![
        case("v4-via", vec![with_route("10.30.0.0/16", |r| r.via("10.3.0.254"))]),
        case("v4-dev", vec![with_route("10.31.0.0/16", |r| r.dev("d0"))]),
        case("v4-default", vec![with_route("0.0.0.0/0", |r| r.via("10.3.0.254"))]),
        case("v4-metric-0", vec![with_route("10.32.0.0/16", |r| r.dev("d0").metric(0))]),
        case("v4-metric-50", vec![with_route("10.32.0.0/16", |r| r.dev("d0").metric(50))]),
        case("v6-via", vec![with_route("2001:db8:30::/48", |r| r.via("fd00:3::fe"))]),
        case("v6-dev", vec![with_route("2001:db8:31::/48", |r| r.dev("d0"))]),
        case("v6-default", vec![with_route("::/0", |r| r.via("fd00:3::fe"))]),
        // The kernel masks an IPv6 destination to its prefix; IPv4
        // rejects one with host bits instead.
        case(
            "v6-destination-host-bits",
            vec![with_route("2001:db8:32::1/48", |r| r.dev("d0"))],
        ),
        // ip6_route_add turns metric 0 into IP6_RT_PRIO_USER.
        case("v6-metric-0", vec![with_route("2001:db8:33::/48", |r| r.dev("d0").metric(0))]),
        case(
            "v6-metric-1024",
            vec![with_route("2001:db8:34::/48", |r| r.dev("d0").metric(1024))],
        ),
        case("v4-blackhole", vec![with_route("10.33.0.0/16", |r| r.blackhole())]),
        case("v6-blackhole", vec![with_route("2001:db8:35::/48", |r| r.blackhole())]),
        case("v4-unreachable", vec![with_route("10.34.0.0/16", |r| r.unreachable())]),
        case("v6-unreachable", vec![with_route("2001:db8:36::/48", |r| r.unreachable())]),
        case("v4-prohibit", vec![with_route("10.35.0.0/16", |r| r.prohibit())]),
        case("v6-prohibit", vec![with_route("2001:db8:37::/48", |r| r.prohibit())]),
        case("v4-table", vec![with_route("10.36.0.0/16", |r| r.dev("d0").table(100))]),
        case("v6-table", vec![with_route("2001:db8:38::/48", |r| r.dev("d0").table(100))]),
        case(
            "v6-table-host-bits-metric-0",
            vec![with_route("2001:db8:39::5/48", |r| r.dev("d0").table(100).metric(0))],
        ),
        case(
            "v4-gateway-change",
            vec![
                with_route("10.37.0.0/16", |r| r.via("10.3.0.254")),
                with_route("10.37.0.0/16", |r| r.via("10.3.0.253")),
            ],
        ),
        case(
            "v6-gateway-change",
            vec![
                with_route("2001:db8:3a::/48", |r| r.via("fd00:3::fe")),
                with_route("2001:db8:3a::/48", |r| r.via("fd00:3::fd")),
            ],
        ),
    ];
    assert_converges("nce-routes", cases).await
}

/// Addresses on `dev`, and routes through it in both families — by `dev`,
/// in `table` if given, and by gateway alone, where the kernel picks `dev`
/// (`gateways`; not in a VRF, where the gateway resolves in its table).
fn routed(cfg: NetworkConfig, dev: &str, table: Option<u32>, gateways: bool) -> NetworkConfig {
    let in_table = move |r: RouteBuilder| match table {
        Some(t) => r.table(t),
        None => r,
    };
    let cfg = cfg
        .address(dev, "10.3.0.1/24")
        .unwrap()
        .address(dev, "fd00:3::1/64")
        .unwrap()
        .route("10.31.0.0/16", |r| in_table(r.dev(dev)))
        .unwrap()
        .route("2001:db8:31::/48", |r| in_table(r.dev(dev)))
        .unwrap();
    if !gateways {
        return cfg;
    }
    cfg.route("10.30.0.0/16", |r| r.via("10.3.0.254"))
        .unwrap()
        .route("2001:db8:30::/48", |r| r.via("fd00:3::fe"))
        .unwrap()
}

/// The kernel flushes the routes through a link that goes down or changes
/// L3 master, in both families: `fib_netdev_event` (NETDEV_DOWN, and
/// NETDEV_CHANGEUPPER to or from a VRF, forced) and `addrconf_notify`
/// (`addrconf_ifdown` -> `rt6_disable_ip`). A bond takes its port down on
/// the way in and closes it on the way out; a VRF cycles it. The diff read
/// the routes before the link step ran, saw them present and left them
/// out, so they stayed gone until the next apply (#427). The same goes for
/// a VLAN on such a link, which the kernel takes down with it.
#[tokio::test]
async fn routes_a_link_change_flushes_are_put_back() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("dummy", "vrf", "bonding", "8021q");

    let vrf = |cfg: NetworkConfig| cfg.link("vrf0", |l| l.vrf(10).up());
    let bond = |cfg: NetworkConfig| cfg.link("bond0", |l| l.bond().up());
    let d0 = |master: Option<&'static str>| {
        NetworkConfig::new().link("d0", |l| match master {
            Some(m) => l.dummy().master(m).up(),
            None => l.dummy().up(),
        })
    };
    let vlan_on_d0 = |cfg: NetworkConfig| cfg.link("v10", |l| l.vlan("d0", 10).up());

    let cases = vec![
        case(
            "set-down-then-up",
            vec![
                routed(dummy_up("d0"), "d0", None, true),
                NetworkConfig::new()
                    .link("d0", |l| l.dummy().down())
                    .address("d0", "10.3.0.1/24")?
                    .address("d0", "fd00:3::1/64")?,
                routed(dummy_up("d0"), "d0", None, true),
            ],
        ),
        case(
            "moved-into-vrf",
            vec![
                routed(vrf(d0(None)), "d0", None, false),
                routed(vrf(d0(Some("vrf0"))), "d0", None, false),
            ],
        ),
        case(
            "moved-out-of-vrf",
            vec![
                routed(vrf(d0(Some("vrf0"))), "d0", Some(10), false),
                routed(vrf(d0(None)), "d0", Some(10), false),
            ],
        ),
        case(
            "moved-between-vrfs",
            vec![
                routed(
                    vrf(d0(Some("vrf0"))).link("vrf1", |l| l.vrf(20).up()),
                    "d0",
                    Some(100),
                    false,
                ),
                routed(
                    vrf(d0(Some("vrf1"))).link("vrf1", |l| l.vrf(20).up()),
                    "d0",
                    Some(100),
                    false,
                ),
            ],
        ),
        case(
            "moved-into-bond",
            vec![
                routed(bond(d0(None)), "d0", None, true),
                routed(bond(d0(Some("bond0"))), "d0", None, true),
            ],
        ),
        case(
            "moved-out-of-bond",
            vec![
                routed(bond(d0(Some("bond0"))), "d0", None, true),
                routed(bond(d0(None)), "d0", None, true),
            ],
        ),
        case(
            "vlan-on-a-link-moved-into-vrf",
            vec![
                routed(vlan_on_d0(vrf(d0(None))), "v10", None, true),
                routed(vlan_on_d0(vrf(d0(Some("vrf0")))), "v10", None, true),
            ],
        ),
        case(
            "vlan-on-a-link-moved-into-bond",
            vec![
                routed(vlan_on_d0(bond(d0(None))), "v10", None, true),
                routed(vlan_on_d0(bond(d0(Some("bond0")))), "v10", None, true),
            ],
        ),
    ];
    assert_converges("nce-route-flush", cases).await
}

/// A route through a link declared down cannot exist — the kernel refuses
/// one (`fib_check_nh_nongw`: "Device for nexthop is not up", ENETDOWN;
/// IPv6 the same) and flushes the ones there when the link goes down. The
/// apply that takes the link down says so, as the next one would, instead
/// of reporting success with the route gone (#427).
#[tokio::test]
async fn a_route_through_a_link_declared_down_fails_in_the_same_apply() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("dummy");

    let ns = TestNamespace::new("nce-route-down")?;
    let conn = ns.connection()?;
    let up = routed(dummy_up("d0"), "d0", None, false);
    let applied = up.apply(&conn).await?;
    assert!(applied.is_success(), "{applied:?}");
    let down = routed(NetworkConfig::new().link("d0", |l| l.dummy().down()), "d0", None, false);
    match down.apply(&conn).await {
        Ok(r) => panic!("the apply succeeded with its routes gone: {:?}", r.summary),
        Err(e) => assert_eq!(e.errno(), Some(libc::ENETDOWN), "{e}"),
    }
    Ok(())
}

/// A purge keys "is it declared" on the same destination the add path
/// does, so an IPv6 route declared with host bits must not be purged as
/// undeclared — and re-added — on every purging apply.
#[tokio::test]
async fn v6_route_with_host_bits_survives_a_purge() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("dummy");

    let cfg = dummy_up("d0")
        .address("d0", "fd00:3::1/64")?
        .route("2001:db8:3c::7/48", |r| r.dev("d0"))?;
    assert_converges("nce-v6-purge", vec![case("host-bits", vec![cfg]).purging()]).await
}

// ============================================================================
// Qdiscs
// ============================================================================

/// TBF across a rate sweep, with and without peakrate and mtu, and with
/// the limit edited in place. The kernel keeps `buffer` and `mtu` as
/// psched ticks and does not echo the byte-valued `TCA_TBF_BURST`/
/// `PBURST`, so the burst that comes back is a tick round-trip of the
/// declared one.
#[tokio::test]
async fn tbf_rate_sweep_converges() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("dummy", "sch_tbf");

    let rates = [
        Rate::kbit(512),
        Rate::mbit(1),
        Rate::mbit(3),
        Rate::mbit(100),
        Rate::gbit(1),
        Rate::gbit(10),
    ];
    let mut cases = Vec::new();
    for rate in rates {
        let peak = Rate::bytes_per_sec(rate.as_bytes_per_sec() * 2);
        for burst in [Bytes::kib(32), Bytes::new(10_000)] {
            let tag = format!("{rate}-burst{}", burst.as_u32_saturating());
            cases.push(case(
                format!("tbf-{tag}-limit"),
                vec![dummy_up("d0").qdisc("d0", |q| {
                    q.tbf(rate, burst).limit_bytes(Bytes::kib(64))
                })],
            ));
            cases.push(case(
                format!("tbf-{tag}-limit-edited"),
                vec![
                    dummy_up("d0").qdisc("d0", |q| q.tbf(rate, burst).limit_bytes(Bytes::kib(64))),
                    dummy_up("d0").qdisc("d0", |q| q.tbf(rate, burst).limit_bytes(Bytes::mib(1))),
                ],
            ));
            cases.push(case(
                format!("tbf-{tag}-limit-peakrate"),
                vec![dummy_up("d0").qdisc("d0", |q| {
                    q.tbf(rate, burst).limit_bytes(Bytes::kib(64)).peakrate(peak)
                })],
            ));
            cases.push(case(
                format!("tbf-{tag}-limit-peakrate-mtu"),
                vec![dummy_up("d0").qdisc("d0", |q| {
                    q.tbf(rate, burst)
                        .limit_bytes(Bytes::kib(64))
                        .peakrate(peak)
                        .mtu(1600)
                })],
            ));
        }
    }
    assert_converges("nce-tbf", cases).await
}

/// Each netem knob added to a plain delay, then removed again. A replace
/// is `netem_change()`, which keeps whatever it is not sent (#370).
#[tokio::test]
async fn netem_knobs_added_and_removed_converge() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("dummy", "sch_netem");

    type Knob = fn(QdiscBuilder) -> QdiscBuilder;
    let knobs: Vec<(&str, Knob)> = vec![
        ("jitter", |q| q.jitter(Duration::from_millis(2))),
        ("loss", |q| q.loss_pct(Percent::new(1.0))),
        ("duplicate", |q| q.duplicate_pct(Percent::new(1.0))),
        ("corrupt", |q| q.corrupt_pct(Percent::new(1.0))),
        ("limit", |q| q.limit(500)),
        ("rate", |q| q.rate(Rate::mbit(10))),
        ("loss-correlation", |q| {
            q.loss_pct(Percent::new(1.0))
                .loss_correlation_pct(Percent::new(25.0))
        }),
        ("delay-correlation", |q| {
            q.jitter(Duration::from_millis(2))
                .delay_correlation_pct(Percent::new(25.0))
        }),
        ("duplicate-correlation", |q| {
            q.duplicate_pct(Percent::new(1.0))
                .duplicate_correlation_pct(Percent::new(25.0))
        }),
        ("corrupt-correlation", |q| {
            q.corrupt_pct(Percent::new(1.0))
                .corrupt_correlation_pct(Percent::new(25.0))
        }),
        ("reorder-gap-correlation", |q| {
            q.reorder_pct(Percent::new(5.0))
                .reorder_correlation_pct(Percent::new(25.0))
                .gap(3)
        }),
        ("loss-model", |q| {
            q.loss_model(
                NetemLossModel::gilbert_elliot(Percent::new(1.0)).r(Percent::new(30.0)),
            )
        }),
    ];

    let base = || dummy_up("d0");
    let mut cases = Vec::new();
    for (name, knob) in knobs {
        cases.push(case(
            format!("netem-{name}"),
            vec![
                base().qdisc("d0", |q| q.netem().delay(Duration::from_millis(10))),
                base().qdisc("d0", |q| knob(q.netem().delay(Duration::from_millis(10)))),
                base().qdisc("d0", |q| q.netem().delay(Duration::from_millis(10))),
            ],
        ));
    }
    assert_converges("nce-netem", cases).await
}

/// fq_codel / sfq / prio / htb / hook kinds, including values the kernel
/// clamps on the way in.
#[tokio::test]
async fn other_qdisc_kinds_converge() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!(
        "dummy", "sch_fq_codel", "sch_sfq", "sch_prio", "sch_htb", "sch_ingress", "sch_tbf",
        "sch_netem"
    );

    let base = || dummy_up("d0");
    let cases = vec![
        case("fq_codel", vec![base().qdisc("d0", |q| q.fq_codel())]),
        // fq_codel_change: `q->quantum = max(256U, quantum)`.
        case("fq_codel-quantum-128", vec![base().qdisc("d0", |q| q.fq_codel().quantum(128))]),
        case("fq_codel-quantum-256", vec![base().qdisc("d0", |q| q.fq_codel().quantum(256))]),
        // fq_codel_init turns ECN on; off has to be written, and a replace
        // that does not send it keeps it on (#488).
        case(
            "fq_codel-ecn-off",
            vec![base().qdisc("d0", |q| q.fq_codel().ecn(false))],
        )
        .check(|ns| fq_codel_ecn_is(ns, false)),
        case(
            "fq_codel-ecn-on-then-off",
            vec![
                base().qdisc("d0", |q| q.fq_codel().ecn(true)),
                base().qdisc("d0", |q| q.fq_codel().ecn(false)),
            ],
        )
        .check(|ns| fq_codel_ecn_is(ns, false)),
        case("sfq", vec![base().qdisc("d0", |q| q.sfq())]),
        // sfq_change caps limit at maxdepth * maxflows (127 * 128).
        case("sfq-limit-20000", vec![base().qdisc("d0", |q| q.sfq().limit(20000))]),
        case("sfq-limit-200", vec![base().qdisc("d0", |q| q.sfq().limit(200))]),
        case(
            "sfq-perturb-quantum",
            vec![base().qdisc("d0", |q| {
                q.sfq().perturb(Duration::from_secs(10)).quantum(1514)
            })],
        ),
        case("prio", vec![base().qdisc("d0", |q| q.prio())]),
        case("prio-bands-4", vec![base().qdisc("d0", |q| q.prio().bands(4))]),
        case("htb", vec![base().qdisc("d0", |q| q.htb().default_class(0x10))]),
        case("ingress", vec![base().qdisc("d0", |q| q.ingress())]),
        case("clsact", vec![base().qdisc("d0", |q| q.clsact())]),
        case(
            "ingress-then-clsact",
            vec![
                base().qdisc("d0", |q| q.ingress()),
                base().qdisc("d0", |q| q.clsact()),
            ],
        ),
        case(
            "kind-switches",
            vec![
                base().qdisc("d0", |q| {
                    q.tbf(Rate::mbit(10), Bytes::kib(32))
                        .limit_bytes(Bytes::kib(64))
                }),
                base().qdisc("d0", |q| q.netem().delay(Duration::from_millis(5))),
                base().qdisc("d0", |q| q.fq_codel()),
                base().qdisc("d0", |q| q.prio()),
                base().qdisc("d0", |q| q.sfq()),
                base().qdisc("d0", |q| q.htb().default_class(0x10)),
            ],
        ),
    ];
    assert_converges("nce-qdiscs", cases).await
}

/// Whether `tc` says d0's root fq_codel marks ECN. `tc` prints the flag
/// only when it is on.
fn fq_codel_ecn_is(ns: &TestNamespace, want: bool) -> Result<(), String> {
    let out = ns
        .exec("tc", &["-j", "qdisc", "show", "dev", "d0", "root"])
        .map_err(|e| format!("tc qdisc show: {e}"))?;
    let qdiscs: serde_json::Value =
        serde_json::from_str(&out).map_err(|e| format!("tc qdisc show: {e}: {out}"))?;
    let ecn = qdiscs[0]["options"]["ecn"].as_bool().unwrap_or(false);
    if ecn == want {
        Ok(())
    } else {
        Err(format!("fq_codel ecn is {ecn}, want {want}: {out}"))
    }
}

// ============================================================================
// Things a second diff cannot show
// ============================================================================

async fn tbf_on(conn: &Connection<Route>, dev: &str) -> nlink::Result<Option<TcMessage>> {
    let qdiscs = conn.get_qdiscs_by_name(dev).await?;
    Ok(qdiscs.into_iter().find(|q| q.kind() == Some("tbf")))
}

/// A TBF needs a queue limit; without one it is refused, not installed.
///
/// `tbf_change` only creates the child bfifo when `qopt->limit > 0`; with
/// a zero limit the child stays `noop_qdisc` and every packet is dropped.
/// tc(8) refuses such a qdisc ("either \"limit\" or \"latency\" are
/// required"). `TbfConfig::new()` defaults the limit to 0, so a TBF
/// declared with only a rate and a burst used to install as a black hole —
/// and the diff converged on it perfectly, so only traffic could show it.
/// The half with a limit pins that a TBF does pass traffic.
#[tokio::test]
async fn tbf_without_a_limit_is_refused() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("veth", "sch_tbf");

    let left = TestNamespace::new("nce-tbf-traf-l")?;
    let right = TestNamespace::new("nce-tbf-traf-r")?;
    left.connect_to(&right, "veth0", "veth1")?;
    left.add_addr("veth0", "10.9.7.1/24")?;
    left.link_up("veth0")?;
    right.add_addr("veth1", "10.9.7.2/24")?;
    right.link_up("veth1")?;
    let conn = left.connection()?;

    // Declared without a limit: refused, and nothing installed.
    let unlimited = NetworkConfig::new().qdisc("veth0", |q| q.tbf(Rate::mbit(10), Bytes::kib(32)));
    let err = unlimited
        .apply(&conn)
        .await
        .expect_err("a TBF without a limit has no queue and drops every packet");
    assert!(err.to_string().contains("limit"), "the error must say what is missing: {err}");
    assert!(tbf_on(&conn, "veth0").await?.is_none(), "nothing may be installed");

    // The imperative config refuses it the same way.
    let imperative = TbfConfig::new().rate(Rate::mbit(10)).burst(Bytes::kib(32));
    let err = conn
        .add_qdisc("veth0", imperative)
        .await
        .expect_err("TbfConfig without a limit is refused too");
    assert!(err.to_string().contains("limit"), "{err}");

    // With a limit it installs, and passes traffic.
    let limited = NetworkConfig::new().qdisc("veth0", |q| {
        q.tbf(Rate::mbit(10), Bytes::kib(32)).limit_bytes(Bytes::kib(64))
    });
    let applied = limited.apply(&conn).await?;
    assert!(applied.is_success(), "{applied:?}");
    left.exec("ping", &["-c", "10", "-i", "0.05", "-W", "1", "10.9.7.2"])?;
    let tbf = tbf_on(&conn, "veth0").await?.expect("the declared tbf is installed");
    assert!(
        tbf.packets() >= 10 && tbf.drops() == 0,
        "a TBF with a limit must pass traffic: sent {}, dropped {}",
        tbf.packets(),
        tbf.drops()
    );
    Ok(())
}

/// Changing a route's type at the same destination has to reach the
/// kernel. The diff's match ignores the type, so `unicast → blackhole`
/// diffs clean while the unicast route stays.
#[tokio::test]
async fn route_type_change_reaches_the_kernel() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("dummy");

    for (v6, dst) in [(false, "10.38.0.0/16"), (true, "2001:db8:3b::/48")] {
        let ns = TestNamespace::new("nce-rtype")?;
        let conn = ns.connection()?;
        let base = || {
            dummy_up("d0")
                .address("d0", "10.3.0.1/24")
                .unwrap()
                .address("d0", "fd00:3::1/64")
                .unwrap()
        };
        let unicast = base().route(dst, |r| r.dev("d0"))?.apply(&conn).await?;
        assert!(unicast.is_success(), "{unicast:?}");
        let blackholed = base().route(dst, |r| r.blackhole())?;
        let applied = blackholed.apply(&conn).await?;
        assert!(applied.is_success(), "{applied:?}");

        let routes = conn.get_routes().await?;
        let prefix: u8 = if v6 { 48 } else { 16 };
        let at_dst: Vec<_> = routes
            .iter()
            .filter(|r| r.dst_len() == prefix && r.is_ipv6() == v6 && r.table_id() == 254)
            .filter(|r| r.destination().is_some_and(|d| dst.starts_with(&d.to_string())))
            .collect();
        assert!(
            at_dst
                .iter()
                .any(|r| r.route_type() == nlink::netlink::types::route::RouteType::Blackhole),
            "{dst}: declared blackhole, kernel has {:?}",
            at_dst.iter().map(|r| r.route_type()).collect::<Vec<_>>()
        );
        let again = blackholed.diff(&conn).await?;
        assert!(again.is_empty(), "{dst}: {again}");
    }
    Ok(())
}

/// Editing an HTB root's `default_class` cannot be done in place: `htb`
/// has no change operation, so a same-kind replace is refused. The only
/// way through is delete + add, which takes every class and filter under
/// the qdisc with it — including ones nlink does not manage. So the apply
/// must fail, say so, and leave the tree alone.
#[tokio::test]
async fn htb_default_class_edit_is_a_clear_error() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("dummy", "sch_htb");

    let ns = TestNamespace::new("nce-htb-defcls")?;
    let conn = ns.connection()?;
    let installed = dummy_up("d0")
        .qdisc("d0", |q| q.htb().default_class(0x10))
        .apply(&conn)
        .await?;
    assert!(installed.is_success(), "{installed:?}");
    // A class nlink did not declare.
    conn.add_class(
        "d0",
        nlink::TcHandle::major_only(1),
        nlink::TcHandle::new(1, 0x10),
        nlink::netlink::tc::HtbClassConfig::new(Rate::mbit(10)).build(),
    )
    .await?;

    let edited = dummy_up("d0").qdisc("d0", |q| q.htb().default_class(0x20));
    let err = edited
        .apply(&conn)
        .await
        .expect_err("an HTB default_class edit cannot be applied in place");
    let msg = err.to_string();
    assert!(
        msg.contains("default_class") || msg.contains("default class"),
        "the error must name what cannot change: {msg}"
    );

    let classes = conn.get_classes_by_name("d0").await?;
    assert!(
        classes.iter().any(|c| c.handle() == nlink::TcHandle::new(1, 0x10)),
        "the undeclared class 1:10 must survive the refused edit"
    );
    Ok(())
}
