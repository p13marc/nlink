//! WireGuard configuration via Generic Netlink.
//!
//! This module provides an API for configuring WireGuard interfaces using
//! the kernel's Generic Netlink interface. WireGuard link creation uses
//! standard RTNetlink, but all configuration (keys, peers, allowed IPs)
//! is done via GENL.
//!
//! # Example
//!
//! ```rust,no_run
//! use nlink::netlink::{Connection, Wireguard};
//! use std::net::SocketAddr;
//!
//! # async fn example() -> nlink::Result<()> {
//! // Create a WireGuard connection
//! let conn = Connection::<Wireguard>::new_async().await?;
//!
//! // Get device information
//! let device = conn.get_device("wg0").await?;
//! println!("Public key: {:?}", device.public_key);
//! println!("Listen port: {:?}", device.listen_port);
//!
//! // List peers
//! for peer in &device.peers {
//!     println!("Peer: {:?}", peer.public_key);
//!     println!("  Endpoint: {:?}", peer.endpoint);
//!     println!("  Allowed IPs: {:?}", peer.allowed_ips);
//! }
//! # Ok(())
//! # }
//! ```
//!
//! # Setting Configuration
//!
//! ```rust,no_run
//! use nlink::netlink::{Connection, Wireguard};
//! use nlink::netlink::genl::wireguard::AllowedIp;
//! use std::net::{Ipv4Addr, SocketAddrV4};
//!
//! # async fn example() -> nlink::Result<()> {
//! let conn = Connection::<Wireguard>::new_async().await?;
//!
//! // Set device private key and listen port
//! let private_key = [0u8; 32]; // Your private key
//! conn.set_device("wg0", |dev| {
//!     dev.private_key(private_key)
//!        .listen_port(51820)
//! }).await?;
//!
//! // Add a peer
//! let peer_pubkey = [0u8; 32]; // Peer's public key
//! conn.set_peer("wg0", peer_pubkey, |peer| {
//!     peer.endpoint(SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 1), 51820).into())
//!         .persistent_keepalive(25)
//!         .allowed_ip(AllowedIp::v4(Ipv4Addr::new(10, 0, 0, 0), 24))
//! }).await?;
//! # Ok(())
//! # }
//! ```

mod connection;
mod types;

pub use types::{
    AllowedIp, WG_KEY_LEN, WgDevice, WgDeviceBuilder, WgPeer, WgPeerBuilder, WgPeerFlags,
};

// Re-export deprecated type for backwards compatibility
#[allow(deprecated)]
pub use connection::WireguardConnection;

/// WireGuard Generic Netlink family name.
pub const WG_GENL_NAME: &str = "wireguard";

/// WireGuard Generic Netlink version.
pub const WG_GENL_VERSION: u8 = 1;

/// WireGuard GENL commands.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WgCmd {
    GetDevice = 0,
    SetDevice = 1,
}

/// WireGuard device attributes.
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WgDeviceAttr {
    Unspec = 0,
    Ifindex = 1,
    Ifname = 2,
    PrivateKey = 3,
    PublicKey = 4,
    Flags = 5,
    ListenPort = 6,
    Fwmark = 7,
    Peers = 8,
}

/// WireGuard peer attributes.
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WgPeerAttr {
    Unspec = 0,
    PublicKey = 1,
    PresharedKey = 2,
    Flags = 3,
    Endpoint = 4,
    PersistentKeepalive = 5,
    LastHandshake = 6,
    RxBytes = 7,
    TxBytes = 8,
    AllowedIps = 9,
    ProtocolVersion = 10,
}

/// WireGuard allowed IP attributes.
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WgAllowedIpAttr {
    Unspec = 0,
    Family = 1,
    IpAddr = 2,
    CidrMask = 3,
}

/// WireGuard device flags.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WgDeviceFlag {
    /// Replace all peers instead of adding
    ReplacePeers = 1 << 0,
}
