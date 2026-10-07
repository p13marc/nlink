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
//! So each case here is applied, then diffed, then applied again, then
//! diffed again, and all four must say "nothing to do". A case with
//! several steps applies them in order to the same namespace, which is
//! how a replace (a knob removed, a link moved) gets exercised at all:
//! every case that only ever installs onto a fresh device misses what a
//! replace keeps.
//!
//! The cases are tables rather than one test each so a run reports every
//! red shape at once instead of stopping at the first.

use std::net::Ipv4Addr;
use std::time::Duration;

use nlink::netlink::config::{
    ApplyOptions, BondMode, DiffOptions, MacvlanMode, NetkitMode, NetworkConfig, QdiscBuilder,
    RouteBuilder, VlanProtocol,
};
use nlink::netlink::tc::{NetemLossModel, TbfConfig};
use nlink::netlink::{Connection, Route};
use nlink::{Bytes, Percent, Rate, TcMessage};

use crate::common::TestNamespace;

const MAC_A: [u8; 6] = [0x02, 0x00, 0x5e, 0x10, 0x00, 0x01];
const MAC_B: [u8; 6] = [0x02, 0x00, 0x5e, 0x10, 0x00, 0x02];

/// One declaration, or a sequence applied in order to one namespace.
struct Case {
    name: String,
    steps: Vec<NetworkConfig>,
}

fn case(name: impl Into<String>, steps: Vec<NetworkConfig>) -> Case {
    Case {
        name: name.into(),
        steps,
    }
}

/// Apply `cfg` and check that it converged: the diff after the apply is
/// empty, a second apply changes nothing, and the diff after that is
/// empty too.
async fn converges(conn: &Connection<Route>, cfg: &NetworkConfig) -> Result<(), String> {
    let first = cfg
        .apply(conn)
        .await
        .map_err(|e| format!("first apply failed: {e}"))?;
    if !first.is_success() {
        return Err(format!("first apply reported errors: {:?}", first.errors));
    }
    let diff = cfg
        .diff(conn)
        .await
        .map_err(|e| format!("diff after apply failed: {e}"))?;
    if !diff.is_empty() {
        return Err(format!("diff after apply is not empty:\n{diff}"));
    }
    let second = cfg
        .apply(conn)
        .await
        .map_err(|e| format!("second apply failed: {e}"))?;
    if second.changes_made != 0 {
        return Err(format!(
            "second apply made {} change(s): {:?}",
            second.changes_made, second.summary
        ));
    }
    let third = cfg
        .diff(conn)
        .await
        .map_err(|e| format!("diff after second apply failed: {e}"))?;
    if !third.is_empty() {
        return Err(format!("diff after second apply is not empty:\n{third}"));
    }
    Ok(())
}

/// Run every case in its own namespace, then fail once, listing every
/// case that did not converge.
async fn assert_converges(prefix: &str, cases: Vec<Case>) -> nlink::Result<()> {
    let mut failures = Vec::new();
    for case in cases {
        let ns = TestNamespace::new(prefix)?;
        let conn = ns.connection()?;
        for (i, step) in case.steps.iter().enumerate() {
            let outcome =
                match tokio::time::timeout(Duration::from_secs(30), converges(&conn, step)).await {
                    Ok(outcome) => outcome,
                    Err(_elapsed) => Err("timed out".to_string()),
                };
            if let Err(why) = outcome {
                failures.push(format!("[{}] step {}: {why}", case.name, i + 1));
                break;
            }
        }
    }
    assert!(
        failures.is_empty(),
        "{} case(s) did not converge:\n\n{}",
        failures.len(),
        failures.join("\n\n")
    );
    Ok(())
}

fn dummy_up(name: &str) -> NetworkConfig {
    NetworkConfig::new().link(name, |l| l.dummy().up())
}

// ============================================================================
// Links
// ============================================================================

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
    ];
    assert_converges("nce-netkit", cases).await
}

/// Modifiers on links that already exist: each case's first step builds
/// the starting point, the next one changes it.
#[tokio::test]
async fn link_modifiers_converge() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("dummy", "bridge", "bonding", "vrf");

    let cases = vec![
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
// Addresses
// ============================================================================

#[tokio::test]
async fn addresses_converge() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("dummy", "vrf");

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

/// A purge keys "is it declared" on the same destination the add path
/// does, so an IPv6 route declared with host bits must not be purged as
/// undeclared — and re-added — on every purging apply.
#[tokio::test]
async fn v6_route_with_host_bits_survives_a_purge() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("dummy");

    let ns = TestNamespace::new("nce-v6-purge")?;
    let conn = ns.connection()?;
    let cfg = dummy_up("d0")
        .address("d0", "fd00:3::1/64")?
        .route("2001:db8:3c::7/48", |r| r.dev("d0"))?;
    let purging = ApplyOptions::default().with_purge(true);
    let first = cfg.apply_with_options(&conn, purging.clone()).await?;
    assert!(first.is_success(), "{first:?}");
    let diff = cfg
        .diff_with_options(&conn, DiffOptions::default().purge(true))
        .await?;
    assert!(diff.is_empty(), "a purging diff after a purging apply: {diff}");
    let second = cfg.apply_with_options(&conn, purging).await?;
    assert_eq!(second.changes_made, 0, "{second:?}");
    Ok(())
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
