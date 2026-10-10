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

use crate::common::TestNamespace;
use crate::common::converge::{assert_converges, case};

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
        // 0 means "kernel, pick one"; the port it picked is never 0.
        case(
            "listen-port-0",
            vec![WireguardConfig::new().device("wg0", |d| {
                d.private_key(UNCLAMPED).listen_port(0)
            })],
        ),
        case(
            "keepalive-0",
            vec![WireguardConfig::new().device("wg0", |d| {
                d.peer(peer_key(0xe1), |p| p.persistent_keepalive(Duration::ZERO))
            })],
        ),
        case(
            "endpoint-v4-to-v6",
            vec![
                WireguardConfig::new().device("wg0", |d| {
                    d.peer(peer_key(0xe2), |p| p.endpoint(v4_endpoint()))
                }),
                WireguardConfig::new().device("wg0", |d| {
                    d.peer(peer_key(0xe2), |p| p.endpoint("[2001:db8::9]:5".parse().unwrap()))
                }),
            ],
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
        // The kernel returns a preshared key to a CAP_NET_ADMIN GET, so it
        // can be compared like the private key.
        case(
            "peer-preshared-key",
            vec![WireguardConfig::new().device("wg0", |d| {
                d.peer(peer_key(0xb2), |p| {
                    p.preshared_key([0x11; 32])
                        .allowed_ip(AllowedIp::v4(Ipv4Addr::new(10, 0, 1, 0), 24))
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
        // The allowed-IPs trie keeps the prefix, not the host bits.
        case(
            "allowed-ips-with-host-bits",
            vec![WireguardConfig::new().device("wg0", |d| {
                d.peer(peer_key(0xb4), |p| {
                    p.allowed_ip(AllowedIp::v4(Ipv4Addr::new(10, 0, 2, 5), 24))
                        .allowed_ip(AllowedIp::v6("fd00:2::5".parse().unwrap(), 64))
                })
            })],
        ),
        // One trie node, however many times it is declared.
        case(
            "allowed-ips-duplicated",
            vec![WireguardConfig::new().device("wg0", |d| {
                d.peer(peer_key(0xb5), |p| {
                    p.allowed_ip(AllowedIp::v4(Ipv4Addr::new(10, 0, 3, 0), 24))
                        .allowed_ip(AllowedIp::v4(Ipv4Addr::new(10, 0, 3, 0), 24))
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
    assert_converges("wge", cases).await
}

/// A `wg-quick` profile as people write them: an unclamped private key
/// (whatever `wg genkey` printed is already clamped, but a hand-made or
/// derived one need not be), a preshared key, host bits in AllowedIPs.
#[tokio::test]
async fn wg_quick_profile_converges() -> nlink::Result<()> {
    require_root!();
    nlink::require_host_root!();
    nlink::require_modules!("wireguard");

    // 0xaa * 32, 0xbb * 32 and 0x11 * 32 in base64.
    let profile = "\
[Interface]
PrivateKey = qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqo=
ListenPort = 51823
FwMark = 0x10
Address = 10.200.0.1/24

[Peer]
PublicKey = u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7s=
PresharedKey = ERERERERERERERERERERERERERERERERERERERERERE=
Endpoint = 198.51.100.7:51820
AllowedIPs = 10.200.0.2/32, 10.201.0.9/16, fd00:200::1/64
PersistentKeepalive = 15
";
    let cfg = WireguardConfig::from_wg_quick("wg0", profile)?;
    assert_converges("wge", vec![case("wg-quick", vec![cfg])]).await
}

/// One allowed-IP prefix on two peers of a device is refused before
/// anything is written. The kernel gives a prefix to one peer, so writing
/// it on the second took it from the first, and every apply rewrote every
/// peer — a hub declaring each spoke with the tunnel /24 (#498).
#[tokio::test]
async fn a_prefix_on_two_peers_is_refused() -> nlink::Result<()> {
    require_root!();
    nlink::require_host_root!();
    nlink::require_modules!("wireguard");

    let ns = TestNamespace::new("wge-shared")?;
    let tunnel = AllowedIp::v4(Ipv4Addr::new(10, 99, 0, 0), 24);
    let cfg = WireguardConfig::new().device("wg0", |d| {
        d.private_key(UNCLAMPED)
            .peer(peer_key(0xb1), |p| p.allowed_ip(tunnel))
            .peer(peer_key(0xb2), |p| p.allowed_ip(tunnel))
    });
    cfg.ensure_devices(&ns.connection()?).await?;
    let wg = ns
        .connection_for_async::<nlink::netlink::Wireguard>()
        .await?;
    let err = cfg.apply(&wg).await.unwrap_err();
    assert!(err.to_string().contains("allowed IP of two peers"), "{err}");
    let device = wg.get_device_by_name("wg0").await?;
    assert!(device.peers.is_empty(), "nothing was written: {device:?}");
    Ok(())
}
