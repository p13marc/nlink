//! WireGuard type definitions.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Size of a WireGuard key in bytes.
pub const WG_KEY_LEN: usize = 32;

/// WireGuard device information.
#[derive(Debug, Clone, Default)]
pub struct WgDevice {
    /// Interface index.
    pub ifindex: Option<u32>,
    /// Interface name.
    pub ifname: Option<String>,
    /// Private key (only set, never returned by kernel for security).
    pub private_key: Option<[u8; WG_KEY_LEN]>,
    /// Public key (derived from private key).
    pub public_key: Option<[u8; WG_KEY_LEN]>,
    /// UDP listen port (0 = kernel chooses).
    pub listen_port: Option<u16>,
    /// Firewall mark for outgoing packets.
    pub fwmark: Option<u32>,
    /// Configured peers.
    pub peers: Vec<WgPeer>,
}

impl WgDevice {
    /// Create a new empty device.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a builder for setting device configuration.
    pub fn builder() -> WgDeviceBuilder {
        WgDeviceBuilder::new()
    }
}

/// Builder for WgDevice configuration.
#[derive(Debug, Clone, Default)]
pub struct WgDeviceBuilder {
    private_key: Option<[u8; WG_KEY_LEN]>,
    listen_port: Option<u16>,
    fwmark: Option<u32>,
    replace_peers: bool,
    peers: Vec<WgPeerBuilder>,
}

impl WgDeviceBuilder {
    /// Create a new device builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the private key.
    pub fn private_key(mut self, key: [u8; WG_KEY_LEN]) -> Self {
        self.private_key = Some(key);
        self
    }

    /// Set the listen port.
    pub fn listen_port(mut self, port: u16) -> Self {
        self.listen_port = Some(port);
        self
    }

    /// Set the firewall mark.
    pub fn fwmark(mut self, mark: u32) -> Self {
        self.fwmark = Some(mark);
        self
    }

    /// Replace all existing peers (instead of merging).
    pub fn replace_peers(mut self) -> Self {
        self.replace_peers = true;
        self
    }

    /// Add a peer to configure.
    pub fn peer(mut self, peer: WgPeerBuilder) -> Self {
        self.peers.push(peer);
        self
    }

    /// Check if replace_peers flag is set.
    pub fn has_replace_peers(&self) -> bool {
        self.replace_peers
    }

    /// Get the private key if set.
    pub fn get_private_key(&self) -> Option<&[u8; WG_KEY_LEN]> {
        self.private_key.as_ref()
    }

    /// Get the listen port if set.
    pub fn get_listen_port(&self) -> Option<u16> {
        self.listen_port
    }

    /// Get the fwmark if set.
    pub fn get_fwmark(&self) -> Option<u32> {
        self.fwmark
    }

    /// Get the peers to configure.
    pub fn get_peers(&self) -> &[WgPeerBuilder] {
        &self.peers
    }
}

/// WireGuard peer information.
#[derive(Debug, Clone, Default)]
pub struct WgPeer {
    /// Peer's public key (identifies the peer).
    pub public_key: [u8; WG_KEY_LEN],
    /// Optional preshared key for post-quantum resistance.
    pub preshared_key: Option<[u8; WG_KEY_LEN]>,
    /// Peer's endpoint (IP:port).
    pub endpoint: Option<SocketAddr>,
    /// Persistent keepalive interval in seconds (0 = disabled).
    pub persistent_keepalive: Option<u16>,
    /// Last successful handshake time.
    pub last_handshake: Option<SystemTime>,
    /// Bytes received from this peer.
    pub rx_bytes: u64,
    /// Bytes sent to this peer.
    pub tx_bytes: u64,
    /// Allowed IP ranges for this peer.
    pub allowed_ips: Vec<AllowedIp>,
    /// Protocol version (typically 1).
    pub protocol_version: Option<u32>,
}

impl WgPeer {
    /// Create a new peer with the given public key.
    pub fn new(public_key: [u8; WG_KEY_LEN]) -> Self {
        Self {
            public_key,
            ..Default::default()
        }
    }

    /// Create a builder for this peer.
    pub fn builder(public_key: [u8; WG_KEY_LEN]) -> WgPeerBuilder {
        WgPeerBuilder::new(public_key)
    }

    /// Get the duration since last handshake.
    pub fn time_since_handshake(&self) -> Option<Duration> {
        self.last_handshake
            .and_then(|t| SystemTime::now().duration_since(t).ok())
    }
}

/// Peer flags for SET_DEVICE operations.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WgPeerFlags {
    /// Remove this peer.
    RemoveMe = 1 << 0,
    /// Replace all allowed IPs (instead of adding).
    ReplaceAllowedIps = 1 << 1,
    /// Update the endpoint only if it was previously empty.
    UpdateOnly = 1 << 2,
}

/// Builder for configuring a WireGuard peer.
#[derive(Debug, Clone)]
pub struct WgPeerBuilder {
    public_key: [u8; WG_KEY_LEN],
    preshared_key: Option<[u8; WG_KEY_LEN]>,
    endpoint: Option<SocketAddr>,
    persistent_keepalive: Option<u16>,
    allowed_ips: Vec<AllowedIp>,
    flags: u32,
}

impl WgPeerBuilder {
    /// Create a new peer builder with the given public key.
    pub fn new(public_key: [u8; WG_KEY_LEN]) -> Self {
        Self {
            public_key,
            preshared_key: None,
            endpoint: None,
            persistent_keepalive: None,
            allowed_ips: Vec::new(),
            flags: 0,
        }
    }

    /// Set the preshared key.
    pub fn preshared_key(mut self, key: [u8; WG_KEY_LEN]) -> Self {
        self.preshared_key = Some(key);
        self
    }

    /// Set the endpoint address.
    pub fn endpoint(mut self, addr: SocketAddr) -> Self {
        self.endpoint = Some(addr);
        self
    }

    /// Set the persistent keepalive interval in seconds.
    pub fn persistent_keepalive(mut self, interval: u16) -> Self {
        self.persistent_keepalive = Some(interval);
        self
    }

    /// Add an allowed IP range.
    pub fn allowed_ip(mut self, ip: AllowedIp) -> Self {
        self.allowed_ips.push(ip);
        self
    }

    /// Add multiple allowed IP ranges.
    pub fn allowed_ips(mut self, ips: impl IntoIterator<Item = AllowedIp>) -> Self {
        self.allowed_ips.extend(ips);
        self
    }

    /// Replace all existing allowed IPs instead of adding.
    pub fn replace_allowed_ips(mut self) -> Self {
        self.flags |= WgPeerFlags::ReplaceAllowedIps as u32;
        self
    }

    /// Mark this peer for removal.
    pub fn remove(mut self) -> Self {
        self.flags |= WgPeerFlags::RemoveMe as u32;
        self
    }

    /// Get the public key.
    pub fn get_public_key(&self) -> &[u8; WG_KEY_LEN] {
        &self.public_key
    }

    /// Get the preshared key if set.
    pub fn get_preshared_key(&self) -> Option<&[u8; WG_KEY_LEN]> {
        self.preshared_key.as_ref()
    }

    /// Get the endpoint if set.
    pub fn get_endpoint(&self) -> Option<&SocketAddr> {
        self.endpoint.as_ref()
    }

    /// Get the persistent keepalive interval if set.
    pub fn get_persistent_keepalive(&self) -> Option<u16> {
        self.persistent_keepalive
    }

    /// Get the allowed IPs.
    pub fn get_allowed_ips(&self) -> &[AllowedIp] {
        &self.allowed_ips
    }

    /// Get the flags.
    pub fn get_flags(&self) -> u32 {
        self.flags
    }
}

/// An allowed IP range for a WireGuard peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AllowedIp {
    /// IP address (network portion).
    pub addr: IpAddr,
    /// CIDR prefix length.
    pub cidr: u8,
}

impl AllowedIp {
    /// Create an IPv4 allowed IP range.
    pub fn v4(addr: Ipv4Addr, cidr: u8) -> Self {
        Self {
            addr: IpAddr::V4(addr),
            cidr: cidr.min(32),
        }
    }

    /// Create an IPv6 allowed IP range.
    pub fn v6(addr: Ipv6Addr, cidr: u8) -> Self {
        Self {
            addr: IpAddr::V6(addr),
            cidr: cidr.min(128),
        }
    }

    /// Get the address family (AF_INET or AF_INET6).
    pub fn family(&self) -> u16 {
        match self.addr {
            IpAddr::V4(_) => libc::AF_INET as u16,
            IpAddr::V6(_) => libc::AF_INET6 as u16,
        }
    }

    /// Get the address bytes.
    pub fn addr_bytes(&self) -> Vec<u8> {
        match self.addr {
            IpAddr::V4(v4) => v4.octets().to_vec(),
            IpAddr::V6(v6) => v6.octets().to_vec(),
        }
    }
}

impl std::fmt::Display for AllowedIp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.addr, self.cidr)
    }
}

/// Parse a timespec from WireGuard's last_handshake attribute.
///
/// The kernel sends this as two i64 values: seconds and nanoseconds.
pub fn parse_timespec(data: &[u8]) -> Option<SystemTime> {
    if data.len() < 16 {
        return None;
    }

    let secs = i64::from_ne_bytes([
        data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
    ]);
    let nsecs = i64::from_ne_bytes([
        data[8], data[9], data[10], data[11], data[12], data[13], data[14], data[15],
    ]);

    if secs == 0 && nsecs == 0 {
        return None; // No handshake yet
    }

    let duration = Duration::new(secs as u64, nsecs as u32);
    Some(UNIX_EPOCH + duration)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_allowed_ip_v4() {
        let ip = AllowedIp::v4(Ipv4Addr::new(10, 0, 0, 0), 8);
        assert_eq!(ip.family(), libc::AF_INET as u16);
        assert_eq!(ip.cidr, 8);
        assert_eq!(ip.addr_bytes(), vec![10, 0, 0, 0]);
        assert_eq!(ip.to_string(), "10.0.0.0/8");
    }

    #[test]
    fn test_allowed_ip_v6() {
        let ip = AllowedIp::v6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0), 64);
        assert_eq!(ip.family(), libc::AF_INET6 as u16);
        assert_eq!(ip.cidr, 64);
        assert_eq!(ip.to_string(), "fd00::/64");
    }

    #[test]
    fn test_wg_device_builder() {
        let key = [1u8; 32];
        let builder = WgDeviceBuilder::new()
            .private_key(key)
            .listen_port(51820)
            .fwmark(100);

        assert_eq!(builder.get_private_key(), Some(&key));
        assert_eq!(builder.get_listen_port(), Some(51820));
        assert_eq!(builder.get_fwmark(), Some(100));
    }

    #[test]
    fn test_wg_peer_builder() {
        let pubkey = [2u8; 32];
        let builder = WgPeerBuilder::new(pubkey)
            .persistent_keepalive(25)
            .allowed_ip(AllowedIp::v4(Ipv4Addr::new(10, 0, 0, 0), 24))
            .replace_allowed_ips();

        assert_eq!(builder.get_public_key(), &pubkey);
        assert_eq!(builder.get_persistent_keepalive(), Some(25));
        assert_eq!(builder.get_allowed_ips().len(), 1);
        assert!(builder.get_flags() & (WgPeerFlags::ReplaceAllowedIps as u32) != 0);
    }

    #[test]
    fn test_parse_timespec() {
        // Zero timespec (no handshake)
        let data = [0u8; 16];
        assert!(parse_timespec(&data).is_none());

        // Valid timespec: 1609459200 seconds (2021-01-01 00:00:00 UTC)
        let mut data = [0u8; 16];
        data[0..8].copy_from_slice(&1609459200i64.to_ne_bytes());
        let time = parse_timespec(&data).unwrap();
        let expected = UNIX_EPOCH + Duration::from_secs(1609459200);
        assert_eq!(time, expected);
    }
}
