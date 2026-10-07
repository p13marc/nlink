//! Every shape the TC recipes can declare must reconcile to a no-op.
//!
//! `RateLimiter`, `PerHostLimiter` and `PerPeerImpairer` compare the live
//! HTB tree against what they would build, object by object. Anything the
//! kernel stores differently from how it was sent — a rate past 32 bits,
//! a netem field it rounds, a flower key it masks — makes every
//! `reconcile()` rewrite the same object forever. The existing
//! idempotence tests each declare one IPv4 host with defaults; these
//! declare every matcher and knob.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use nlink::netlink::impair::{PeerImpairment, PerPeerImpairer};
use nlink::netlink::ratelimit::{PerHostLimiter, RateLimiter};
use nlink::netlink::tc::{NetemConfig, NetemLossModel};
use nlink::netlink::{Connection, Route};
use nlink::{Bytes, Percent, Rate, ReconcileReport};

use crate::common::TestNamespace;

#[derive(Clone)]
enum Recipe {
    Rate(RateLimiter),
    Host(PerHostLimiter),
    Peer(PerPeerImpairer),
}

impl Recipe {
    async fn reconcile(&self, conn: &Connection<Route>) -> nlink::Result<ReconcileReport> {
        match self {
            Recipe::Rate(r) => r.reconcile(conn).await,
            Recipe::Host(r) => r.reconcile(conn).await,
            Recipe::Peer(r) => r.reconcile(conn).await,
        }
    }
}

struct Case {
    name: String,
    steps: Vec<Recipe>,
}

fn case(name: impl Into<String>, steps: Vec<Recipe>) -> Case {
    Case {
        name: name.into(),
        steps,
    }
}

/// Reconcile, then check that the next two reconciles change nothing.
async fn converges(conn: &Connection<Route>, recipe: &Recipe) -> Result<(), String> {
    let _first = recipe
        .reconcile(conn)
        .await
        .map_err(|e| format!("first reconcile failed: {e}"))?;
    for which in ["second", "third"] {
        let report = recipe
            .reconcile(conn)
            .await
            .map_err(|e| format!("{which} reconcile failed: {e}"))?;
        if !report.is_noop() {
            return Err(format!("{which} reconcile was not a no-op: {report:?}"));
        }
    }
    Ok(())
}

async fn assert_converges(prefix: &str, cases: Vec<Case>) -> nlink::Result<()> {
    let mut failures = Vec::new();
    for case in cases {
        let ns = TestNamespace::new(prefix)?;
        let conn = ns.connection()?;
        conn.add_link(nlink::netlink::link::DummyLink::new("d0"))
            .await?;
        conn.set_link_up("d0").await?;
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

fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(a, b, c, d))
}

fn v6(s: &str) -> IpAddr {
    IpAddr::V6(s.parse::<Ipv6Addr>().unwrap())
}

// ============================================================================
// RateLimiter
// ============================================================================

#[tokio::test]
async fn rate_limiter_shapes_converge() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!(
        "dummy", "sch_htb", "sch_fq_codel", "ifb", "sch_ingress", "cls_u32", "act_mirred"
    );

    let rl = || RateLimiter::new("d0");
    let cases = vec![
        case("egress", vec![Recipe::Rate(rl().egress(Rate::mbit(10)))]),
        case(
            "egress-ceil",
            vec![Recipe::Rate(rl().egress(Rate::mbit(10)).burst_to(Rate::mbit(20)))],
        ),
        case(
            "egress-burst-size",
            vec![Recipe::Rate(rl().egress(Rate::mbit(10)).burst_size(Bytes::kib(64)))],
        ),
        case(
            "egress-latency",
            vec![Recipe::Rate(
                rl().egress(Rate::mbit(10)).latency(Duration::from_millis(5)),
            )],
        ),
        case("egress-10gbit", vec![Recipe::Rate(rl().egress(Rate::gbit(10)))]),
        case(
            "egress-and-ingress",
            vec![Recipe::Rate(
                rl().egress(Rate::mbit(10)).ingress(Rate::mbit(20)),
            )],
        ),
        case(
            "rate-change",
            vec![
                Recipe::Rate(rl().egress(Rate::mbit(10))),
                Recipe::Rate(rl().egress(Rate::mbit(30))),
            ],
        ),
    ];
    assert_converges("rce-rl", cases).await
}

// ============================================================================
// PerHostLimiter
// ============================================================================

#[tokio::test]
async fn per_host_limiter_shapes_converge() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("dummy", "sch_htb", "sch_fq_codel", "cls_flower");

    let ph = || PerHostLimiter::new("d0", Rate::mbit(10));
    let cases = vec![
        case(
            "ip-v4",
            vec![Recipe::Host(ph().limit_ip(v4(10, 0, 0, 1), Rate::mbit(100)))],
        ),
        case(
            "ip-v6",
            vec![Recipe::Host(ph().limit_ip(v6("fd00::5"), Rate::mbit(100)))],
        ),
        case(
            "subnet-v4",
            vec![Recipe::Host(ph().limit_subnet("10.5.0.0/16", Rate::mbit(50))?)],
        ),
        case(
            "subnet-v4-host-bits",
            vec![Recipe::Host(ph().limit_subnet("10.5.1.7/16", Rate::mbit(50))?)],
        ),
        case(
            "subnet-v6",
            vec![Recipe::Host(ph().limit_subnet("fd00:5::/64", Rate::mbit(50))?)],
        ),
        case(
            "subnet-v6-host-bits",
            vec![Recipe::Host(ph().limit_subnet("fd00:5::7/64", Rate::mbit(50))?)],
        ),
        case(
            "port",
            vec![Recipe::Host(ph().limit_port(80, Rate::mbit(5)))],
        ),
        case(
            "port-range",
            vec![Recipe::Host(ph().limit_port_range(8000, 8100, Rate::mbit(5)))],
        ),
        case(
            "src-ip-v4",
            vec![Recipe::Host(ph().limit_src_ip(v4(10, 0, 0, 2), Rate::mbit(5)))],
        ),
        case(
            "src-ip-v6",
            vec![Recipe::Host(ph().limit_src_ip(v6("fd00::6"), Rate::mbit(5)))],
        ),
        case(
            "src-subnet",
            vec![Recipe::Host(ph().limit_src_subnet("10.6.0.0/16", Rate::mbit(5))?)],
        ),
        case(
            "ip-with-ceil",
            vec![Recipe::Host(ph().limit_ip_with_ceil(
                v4(10, 0, 0, 3),
                Rate::mbit(10),
                Rate::mbit(40),
            ))],
        ),
        case(
            "latency",
            vec![Recipe::Host(
                ph().limit_ip(v4(10, 0, 0, 4), Rate::mbit(10))
                    .latency(Duration::from_millis(5)),
            )],
        ),
        case(
            "default-10gbit",
            vec![Recipe::Host(
                PerHostLimiter::new("d0", Rate::gbit(10)).limit_ip(v4(10, 0, 0, 5), Rate::gbit(5)),
            )],
        ),
        case(
            "every-matcher",
            vec![Recipe::Host(
                ph().limit_ip(v4(10, 0, 0, 1), Rate::mbit(100))
                    .limit_ip(v6("fd00::5"), Rate::mbit(100))
                    .limit_subnet("10.5.1.7/16", Rate::mbit(50))?
                    .limit_subnet("fd00:5::7/64", Rate::mbit(50))?
                    .limit_port(80, Rate::mbit(5))
                    .limit_port_range(8000, 8100, Rate::mbit(5))
                    .limit_src_ip(v4(10, 0, 0, 2), Rate::mbit(5))
                    .limit_src_subnet("10.6.0.0/16", Rate::mbit(5))?
                    .limit_ip_with_ceil(v4(10, 0, 0, 3), Rate::mbit(10), Rate::mbit(40))
                    .latency(Duration::from_millis(5)),
            )],
        ),
        case(
            "host-rule-removed",
            vec![
                Recipe::Host(
                    ph().limit_ip(v4(10, 0, 0, 1), Rate::mbit(100))
                        .limit_ip(v6("fd00::5"), Rate::mbit(100)),
                ),
                Recipe::Host(ph().limit_ip(v4(10, 0, 0, 1), Rate::mbit(100))),
            ],
        ),
    ];
    assert_converges("rce-ph", cases).await
}

// ============================================================================
// PerPeerImpairer
// ============================================================================

#[tokio::test]
async fn per_peer_impairer_shapes_converge() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("dummy", "sch_htb", "sch_netem", "cls_flower");

    let delay = || NetemConfig::new().delay(Duration::from_millis(20)).build();
    let pp = || PerPeerImpairer::new("d0");
    let mac = [0x02, 0x00, 0x5e, 0x10, 0x00, 0x09];

    let mut cases = vec![
        case("dst-ip-v4", vec![Recipe::Peer(pp().impair_dst_ip(v4(10, 0, 0, 1), delay()))]),
        case("dst-ip-v6", vec![Recipe::Peer(pp().impair_dst_ip(v6("fd00::1"), delay()))]),
        case(
            "dst-subnet-v4",
            vec![Recipe::Peer(pp().impair_dst_subnet("10.7.0.0/16", delay())?)],
        ),
        case(
            "dst-subnet-v4-host-bits",
            vec![Recipe::Peer(pp().impair_dst_subnet("10.7.1.9/16", delay())?)],
        ),
        case(
            "dst-subnet-v6",
            vec![Recipe::Peer(pp().impair_dst_subnet("fd00:7::/64", delay())?)],
        ),
        case(
            "dst-subnet-v6-host-bits",
            vec![Recipe::Peer(pp().impair_dst_subnet("fd00:7::9/64", delay())?)],
        ),
        case("dst-mac", vec![Recipe::Peer(pp().impair_dst_mac(mac, delay()))]),
        case("src-ip-v4", vec![Recipe::Peer(pp().impair_src_ip(v4(10, 0, 0, 2), delay()))]),
        case("src-ip-v6", vec![Recipe::Peer(pp().impair_src_ip(v6("fd00::2"), delay()))]),
        case(
            "src-subnet",
            vec![Recipe::Peer(pp().impair_src_subnet("10.8.0.0/16", delay())?)],
        ),
        case("src-mac", vec![Recipe::Peer(pp().impair_src_mac(mac, delay()))]),
        case(
            "rate-cap",
            vec![Recipe::Peer(pp().impair_dst_ip(
                v4(10, 0, 0, 3),
                PeerImpairment::new(delay()).rate_cap(Rate::mbit(10)),
            ))],
        ),
        case(
            "default-impairment-added-then-removed",
            vec![
                Recipe::Peer(pp().impair_dst_ip(v4(10, 0, 0, 4), delay())),
                Recipe::Peer(
                    pp().impair_dst_ip(v4(10, 0, 0, 4), delay())
                        .default_impairment(
                            PeerImpairment::new(delay()).rate_cap(Rate::mbit(50)),
                        ),
                ),
                Recipe::Peer(pp().impair_dst_ip(v4(10, 0, 0, 4), delay())),
            ],
        ),
        case(
            "peer-rule-removed",
            vec![
                Recipe::Peer(
                    pp().impair_dst_ip(v4(10, 0, 0, 5), delay())
                        .impair_dst_ip(v6("fd00::5"), delay()),
                ),
                Recipe::Peer(pp().impair_dst_ip(v4(10, 0, 0, 5), delay())),
            ],
        ),
    ];

    // Each netem knob on a rule leaf, added and then removed again.
    type Knob = fn(NetemConfig) -> NetemConfig;
    let knobs: Vec<(&str, Knob)> = vec![
        ("jitter-correlation", |n| {
            n.jitter(Duration::from_millis(2))
                .delay_correlation(Percent::new(25.0))
        }),
        ("loss", |n| n.loss(Percent::new(1.0))),
        ("loss-correlation", |n| {
            n.loss(Percent::new(1.0)).loss_correlation(Percent::new(25.0))
        }),
        ("duplicate", |n| n.duplicate(Percent::new(1.0))),
        ("corrupt", |n| n.corrupt(Percent::new(1.0))),
        ("reorder", |n| n.reorder(Percent::new(5.0))),
        ("rate", |n| n.rate(Rate::mbit(10))),
        ("limit", |n| n.limit(500)),
        ("loss-model", |n| {
            n.loss_model(NetemLossModel::gilbert_elliot(Percent::new(1.0)).r(Percent::new(30.0)))
        }),
    ];
    for (name, knob) in knobs {
        let with = knob(NetemConfig::new().delay(Duration::from_millis(20))).build();
        cases.push(case(
            format!("netem-{name}"),
            vec![
                Recipe::Peer(pp().impair_dst_ip(v4(10, 0, 0, 6), delay())),
                Recipe::Peer(pp().impair_dst_ip(v4(10, 0, 0, 6), with.clone())),
                Recipe::Peer(pp().impair_dst_ip(v4(10, 0, 0, 6), delay())),
            ],
        ));
    }
    assert_converges("rce-pp", cases).await
}
