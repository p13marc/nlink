//! Set command implementation for WireGuard.

use clap::Args;
use nlink::netlink::genl::wireguard::AllowedIp;
use nlink::netlink::{Connection, Error, Result, Wireguard};
use std::fs;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;

use crate::output::base64_decode;

#[derive(Args)]
pub struct SetArgs {
    /// Interface name
    pub interface: String,

    /// Listen port
    #[arg(long = "listen-port")]
    pub listen_port: Option<u16>,

    /// Private key file path
    #[arg(long = "private-key")]
    pub private_key: Option<PathBuf>,

    /// Firewall mark
    #[arg(long)]
    pub fwmark: Option<u32>,

    /// Peer public key (base64)
    #[arg(long)]
    pub peer: Option<String>,

    /// Remove the peer
    #[arg(long)]
    pub remove: bool,

    /// Peer endpoint (IP:port)
    #[arg(long)]
    pub endpoint: Option<SocketAddr>,

    /// Peer allowed IPs (comma-separated CIDR notation)
    #[arg(long = "allowed-ips")]
    pub allowed_ips: Option<String>,

    /// Persistent keepalive interval in seconds
    #[arg(long = "persistent-keepalive")]
    pub persistent_keepalive: Option<u16>,

    /// Preshared key file path
    #[arg(long = "preshared-key")]
    pub preshared_key: Option<PathBuf>,
}

/// Run the set command.
pub async fn run(args: SetArgs) -> Result<()> {
    let conn = Connection::<Wireguard>::new_async().await?;

    // Set device parameters if any device-level options are specified
    if args.listen_port.is_some() || args.private_key.is_some() || args.fwmark.is_some() {
        conn.set_device(&args.interface, |mut dev| {
            if let Some(port) = args.listen_port {
                dev = dev.listen_port(port);
            }
            if let Some(ref path) = args.private_key {
                if let Ok(key) = read_key_file(path) {
                    dev = dev.private_key(key);
                }
            }
            if let Some(mark) = args.fwmark {
                dev = dev.fwmark(mark);
            }
            dev
        })
        .await?;
    }

    // Set peer parameters if a peer is specified
    if let Some(ref peer_key_str) = args.peer {
        let peer_key = parse_public_key(peer_key_str)?;

        if args.remove {
            conn.remove_peer(&args.interface, peer_key).await?;
        } else {
            // Parse preshared key if provided
            let psk = if let Some(ref path) = args.preshared_key {
                Some(read_key_file(path)?)
            } else {
                None
            };

            // Parse allowed IPs
            let allowed_ips = if let Some(ref ips_str) = args.allowed_ips {
                parse_allowed_ips(ips_str)?
            } else {
                Vec::new()
            };

            conn.set_peer(&args.interface, peer_key, |mut peer| {
                if let Some(ref endpoint) = args.endpoint {
                    peer = peer.endpoint(*endpoint);
                }
                if let Some(keepalive) = args.persistent_keepalive {
                    peer = peer.persistent_keepalive(keepalive);
                }
                if let Some(ref key) = psk {
                    peer = peer.preshared_key(*key);
                }
                if !allowed_ips.is_empty() {
                    peer = peer.allowed_ips(allowed_ips.clone()).replace_allowed_ips();
                }
                peer
            })
            .await?;
        }
    }

    Ok(())
}

/// Read a key from a file.
fn read_key_file(path: &PathBuf) -> Result<[u8; 32]> {
    let content = fs::read_to_string(path).map_err(|e| Error::Io(e))?;

    let bytes = base64_decode(&content)
        .map_err(|e| Error::InvalidMessage(format!("Invalid base64 in key file: {}", e)))?;

    if bytes.len() != 32 {
        return Err(Error::InvalidMessage(format!(
            "Invalid key length: expected 32, got {}",
            bytes.len()
        )));
    }

    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes);
    Ok(key)
}

/// Parse a base64 public key string.
fn parse_public_key(s: &str) -> Result<[u8; 32]> {
    let bytes = base64_decode(s)
        .map_err(|e| Error::InvalidMessage(format!("Invalid base64 public key: {}", e)))?;

    if bytes.len() != 32 {
        return Err(Error::InvalidMessage(format!(
            "Invalid public key length: expected 32, got {}",
            bytes.len()
        )));
    }

    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes);
    Ok(key)
}

/// Parse a comma-separated list of allowed IPs in CIDR notation.
fn parse_allowed_ips(s: &str) -> Result<Vec<AllowedIp>> {
    let mut result = Vec::new();

    for cidr in s.split(',') {
        let cidr = cidr.trim();
        if cidr.is_empty() {
            continue;
        }

        let (addr_str, prefix_str) = cidr.split_once('/').ok_or_else(|| {
            Error::InvalidMessage(format!("Invalid CIDR notation: {}", cidr))
        })?;

        let addr: IpAddr = addr_str.trim().parse().map_err(|e| {
            Error::InvalidMessage(format!("Invalid IP address '{}': {}", addr_str, e))
        })?;

        let prefix: u8 = prefix_str.trim().parse().map_err(|e| {
            Error::InvalidMessage(format!("Invalid prefix length '{}': {}", prefix_str, e))
        })?;

        let max_prefix = match addr {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };

        if prefix > max_prefix {
            return Err(Error::InvalidMessage(format!(
                "Prefix length {} exceeds maximum {} for {}",
                prefix, max_prefix, addr
            )));
        }

        result.push(AllowedIp { addr, cidr: prefix });
    }

    Ok(result)
}
