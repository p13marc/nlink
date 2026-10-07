//! Every shape `WireguardConfig` can declare must converge.
//!
//! The WireGuard diff compares a declaration against `GET_DEVICE`. The
//! kernel does not store everything as it was sent: a private key is
//! X25519-clamped before it is kept, an allowed IP is masked to its
//! prefix, a duplicate allowed IP is one trie node. Each of those makes
//! the next diff non-empty and every later apply rewrite the device or
//! the peer — invisible applying once.
//!
//! Creating a WireGuard device needs root in the initial user namespace,
//! so this file gates on `require_host_root!()` (#357).

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use nlink::netlink::genl::wireguard::{AllowedIp, WireguardConfig};
use nlink::netlink::{Connection, Route, Wireguard};

use crate::common::TestNamespace;

const UNCLAMPED: [u8; 32] = [0xaa; 32];

/// `UNCLAMPED` the way the kernel stores it (curve25519_clamp_secret).
fn clamped(mut key: [u8; 32]) -> [u8; 32] {
    key[0] &= 248;
    key[31] &= 127;
    key[31] |= 64;
    key
}

fn peer_key(byte: u8) -> [u8; 32] {
    [byte; 32]
}

struct Case {
    name: &'static str,
    steps: Vec<WireguardConfig>,
}

fn case(name: &'static str, steps: Vec<WireguardConfig>) -> Case {
    Case { name, steps }
}

/// Bootstrap the links, apply, and check convergence: the diff after the
/// apply is empty, a second apply writes nothing, the diff after that is
/// empty.
async fn converges(
    route: &Connection<Route>,
    wg: &Connection<Wireguard>,
    cfg: &WireguardConfig,
) -> Result<(), String> {
    cfg.ensure_devices(route)
        .await
        .map_err(|e| format!("ensure_devices failed: {e}"))?;
    let _first = cfg
        .apply(wg)
        .await
        .map_err(|e| format!("first apply failed: {e}"))?;
    let diff = cfg
        .diff(wg)
        .await
        .map_err(|e| format!("diff after apply failed: {e}"))?;
    if !diff.is_empty() {
        return Err(format!("diff after apply is not empty:\n{diff}"));
    }
    let second = cfg
        .apply(wg)
        .await
        .map_err(|e| format!("second apply failed: {e}"))?;
    if second.total_writes() != 0 {
        return Err(format!("second apply wrote {second:?}"));
    }
    let third = cfg
        .diff(wg)
        .await
        .map_err(|e| format!("diff after second apply failed: {e}"))?;
    if !third.is_empty() {
        return Err(format!("diff after second apply is not empty:\n{third}"));
    }
    Ok(())
}

async fn assert_converges(cases: Vec<Case>) -> nlink::Result<()> {
    let mut failures = Vec::new();
    for case in cases {
        let ns = TestNamespace::new("wge")?;
        let route = ns.connection()?;
        let wg = ns.connection_for_async::<Wireguard>().await?;
        for (i, step) in case.steps.iter().enumerate() {
            let outcome =
                match tokio::time::timeout(Duration::from_secs(30), converges(&route, &wg, step))
                    .await
                {
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

fn v4_endpoint() -> SocketAddr {
    "203.0.113.1:51820".parse().unwrap()
}

#[tokio::test]
async fn every_wireguard_shape_converges() -> nlink::Result<()> {
    require_root!();
    nlink::require_host_root!();
    nlink::require_modules!("wireguard");

    let cases = vec![
        // The kernel clamps the private key before storing it, and dumps
        // the clamped one.
        case(
            "private-key-unclamped",
            vec![WireguardConfig::new().device("wg0", |d| d.private_key(UNCLAMPED))],
        ),
        case(
            "private-key-clamped",
            vec![WireguardConfig::new().device("wg0", |d| d.private_key(clamped(UNCLAMPED)))],
        ),
        case(
            "listen-port",
            vec![WireguardConfig::new().device("wg0", |d| d.listen_port(51820))],
        ),
        case(
            "fwmark",
            vec![WireguardConfig::new().device("wg0", |d| d.fwmark(0x42))],
        ),
        case(
            "fwmark-0",
            vec![WireguardConfig::new().device("wg0", |d| d.fwmark(0))],
        ),
        case(
            "device-fields-together",
            vec![WireguardConfig::new().device("wg0", |d| {
                d.private_key(UNCLAMPED).listen_port(51821).fwmark(7)
            })],
        ),
        case(
            "peer-v4",
            vec![WireguardConfig::new().device("wg0", |d| {
                d.private_key(UNCLAMPED).peer(peer_key(0xb1), |p| {
                    p.endpoint(v4_endpoint())
                        .persistent_keepalive(Duration::from_secs(25))
                        .allowed_ip(AllowedIp::v4(Ipv4Addr::new(10, 0, 0, 0), 24))
                })
            })],
        ),
        case(
            "peer-v6-endpoint-and-allowed-ips",
            vec![WireguardConfig::new().device("wg0", |d| {
                d.peer(peer_key(0xb3), |p| {
                    p.endpoint("[2001:db8::1]:51820".parse().unwrap())
                        .allowed_ip(AllowedIp::v6("fd00:1::".parse().unwrap(), 64))
                        .allowed_ip(AllowedIp::v6(Ipv6Addr::UNSPECIFIED, 0))
                })
            })],
        ),
        case(
            "multiple-peers",
            vec![WireguardConfig::new().device("wg0", |d| {
                d.private_key(UNCLAMPED)
                    .listen_port(51822)
                    .peer(peer_key(0xc1), |p| {
                        p.endpoint(v4_endpoint())
                            .allowed_ip(AllowedIp::v4(Ipv4Addr::new(10, 1, 1, 0), 24))
                    })
                    .peer(peer_key(0xc2), |p| {
                        p.endpoint("203.0.113.2:51820".parse().unwrap())
                            .allowed_ip(AllowedIp::v4(Ipv4Addr::new(10, 1, 2, 0), 24))
                    })
                    .peer(peer_key(0xc3), |p| {
                        p.allowed_ip(AllowedIp::v6("fd00:3::".parse().unwrap(), 64))
                    })
            })],
        ),
        case(
            "peer-removed",
            vec![
                WireguardConfig::new().device("wg0", |d| {
                    d.peer(peer_key(0xd1), |p| {
                        p.endpoint(v4_endpoint())
                            .allowed_ip(AllowedIp::v4(Ipv4Addr::new(10, 2, 1, 0), 24))
                    })
                    .peer(peer_key(0xd2), |p| {
                        p.allowed_ip(AllowedIp::v4(Ipv4Addr::new(10, 2, 2, 0), 24))
                    })
                }),
                WireguardConfig::new().device("wg0", |d| {
                    d.peer(peer_key(0xd1), |p| {
                        p.allowed_ip(AllowedIp::v4(Ipv4Addr::new(10, 2, 1, 0), 24))
                    })
                }),
            ],
        ),
    ];
    assert_converges(cases).await
}

