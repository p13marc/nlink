//! JSON serialization views for WireGuard devices (bin-local).
//!
//! A stable, machine-readable shape for `wg show --json` / `wg showconf
//! --json`. `reveal_secrets` controls whether the private key and preshared
//! keys are emitted (true for `showconf`, which is a config dump; false for
//! `show`, which mirrors the text output's `(hidden)`).

use nlink::netlink::genl::wireguard::{WgDevice, WgPeer};
use serde::Serialize;

use crate::output::base64_encode;

#[derive(Serialize)]
pub struct DeviceJson {
    interface: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    public_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    private_key: Option<String>,
    listen_port: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    fwmark: Option<u32>,
    peers: Vec<PeerJson>,
}

#[derive(Serialize)]
pub struct PeerJson {
    public_key: String,
    has_preshared_key: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    preshared_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    endpoint: Option<String>,
    allowed_ips: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    latest_handshake: Option<u64>,
    transfer_rx: u64,
    transfer_tx: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    persistent_keepalive: Option<u16>,
}

impl DeviceJson {
    pub fn from_device(device: &WgDevice, reveal_secrets: bool) -> Self {
        Self {
            interface: device.ifname.clone(),
            public_key: device.public_key.as_ref().map(|k| base64_encode(k)),
            private_key: if reveal_secrets {
                device.private_key.as_ref().map(|k| base64_encode(k))
            } else {
                None
            },
            listen_port: device.listen_port.unwrap_or(0),
            fwmark: device.fwmark.filter(|&f| f != 0),
            peers: device
                .peers
                .iter()
                .map(|p| PeerJson::from_peer(p, reveal_secrets))
                .collect(),
        }
    }
}

impl PeerJson {
    fn from_peer(peer: &WgPeer, reveal_secrets: bool) -> Self {
        Self {
            public_key: base64_encode(&peer.public_key),
            has_preshared_key: peer.preshared_key.is_some(),
            preshared_key: if reveal_secrets {
                peer.preshared_key.as_ref().map(|k| base64_encode(k))
            } else {
                None
            },
            endpoint: peer.endpoint.as_ref().map(|e| e.to_string()),
            allowed_ips: peer.allowed_ips.iter().map(|ip| ip.to_string()).collect(),
            latest_handshake: peer.last_handshake.and_then(|t| {
                t.duration_since(std::time::UNIX_EPOCH)
                    .ok()
                    .map(|d| d.as_secs())
            }),
            transfer_rx: peer.rx_bytes,
            transfer_tx: peer.tx_bytes,
            persistent_keepalive: peer.persistent_keepalive.filter(|&k| k > 0),
        }
    }
}

/// Print a device as JSON to stdout.
pub fn print_device(device: &WgDevice, reveal_secrets: bool, pretty: bool) {
    let view = DeviceJson::from_device(device, reveal_secrets);
    let out = if pretty {
        serde_json::to_string_pretty(&view)
    } else {
        serde_json::to_string(&view)
    };
    // Serialization of this fixed shape cannot fail; fall back defensively.
    println!("{}", out.unwrap_or_else(|_| "{}".to_string()));
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use nlink::netlink::genl::wireguard::{AllowedIp, WgDevice, WgPeer};

    use super::*;

    fn device() -> WgDevice {
        let peer = WgPeer {
            public_key: [3u8; 32],
            preshared_key: Some([4u8; 32]),
            endpoint: Some("203.0.113.1:51820".parse::<SocketAddr>().unwrap()),
            allowed_ips: vec![AllowedIp {
                addr: "10.0.0.0".parse().unwrap(),
                cidr: 24,
            }],
            ..Default::default()
        };
        WgDevice {
            ifname: Some("wg0".into()),
            private_key: Some([1u8; 32]),
            public_key: Some([2u8; 32]),
            listen_port: Some(51820),
            fwmark: Some(0x42),
            peers: vec![peer],
            ..Default::default()
        }
    }

    #[test]
    fn show_view_hides_secrets() {
        let v = serde_json::to_value(DeviceJson::from_device(&device(), false)).unwrap();
        assert!(v.get("private_key").is_none(), "private key must be hidden");
        let peer = &v["peers"][0];
        assert!(peer.get("preshared_key").is_none(), "psk must be hidden");
        assert_eq!(peer["has_preshared_key"], true);
        assert_eq!(v["listen_port"], 51820);
        assert_eq!(peer["allowed_ips"][0], "10.0.0.0/24");
    }

    #[test]
    fn showconf_view_reveals_secrets() {
        let v = serde_json::to_value(DeviceJson::from_device(&device(), true)).unwrap();
        assert!(v["private_key"].is_string(), "showconf must reveal key");
        assert!(v["peers"][0]["preshared_key"].is_string());
    }
}
