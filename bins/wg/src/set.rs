//! Set command implementation for WireGuard.

use std::{
    fs,
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
};

use clap::Args;
use nlink::netlink::{Connection, Error, Result, Wireguard, genl::wireguard::AllowedIp};

use crate::output::base64_decode;

#[derive(Args)]
pub struct SetArgs {
    /// Interface name
    pub interface: String,

    /// Listen port
    #[arg(long = "listen-port")]
    pub listen_port: Option<u16>,

    /// Private key file path (use /dev/null or an empty file to unset)
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

    /// Peer allowed IPs (comma-separated CIDR; prefix all with `+` to add
    /// incrementally instead of replacing the existing set)
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
    let has_device_opts =
        args.listen_port.is_some() || args.private_key.is_some() || args.fwmark.is_some();
    let has_peer_config = args.endpoint.is_some()
        || args.allowed_ips.is_some()
        || args.persistent_keepalive.is_some()
        || args.preshared_key.is_some();

    // `--remove` removes the peer wholesale; combining it with
    // per-peer config flags previously silently dropped those flags.
    // Reject the contradiction instead.
    if args.remove && has_peer_config {
        return Err(Error::InvalidMessage(
            "wg set: `--remove` cannot be combined with peer configuration flags \
             (--endpoint/--allowed-ips/--persistent-keepalive/--preshared-key)"
                .into(),
        ));
    }

    // A `set` with nothing to do was previously a silent no-op exiting 0.
    if !has_device_opts && args.peer.is_none() {
        return Err(Error::InvalidMessage(
            "wg set: nothing to do — specify a device option \
             (--listen-port/--private-key/--fwmark) or `--peer <key> ...`"
                .into(),
        ));
    }

    let conn = Connection::<Wireguard>::new_async().await?;

    // Set device parameters if any device-level options are specified
    if has_device_opts {
        // Plan 209 H6 — security UX. Pre-0.19 a missing private-key
        // file or a base64-decode failure silently dropped the key
        // set; `wg set wg0 --private-key /path/typo` exited 0 and
        // the user believed the new key was installed. Now propagate
        // the read error so the user sees the typo immediately.
        let private_key = if let Some(ref path) = args.private_key {
            Some(read_private_key(path)?)
        } else {
            None
        };

        conn.set_device(&args.interface, |mut dev| {
            if let Some(port) = args.listen_port {
                dev = dev.listen_port(port);
            }
            if let Some(key) = private_key {
                dev = dev.private_key(key);
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
            conn.del_peer(&args.interface, peer_key).await?;
        } else {
            // Parse preshared key if provided
            let psk = if let Some(ref path) = args.preshared_key {
                Some(read_key_file(path)?)
            } else {
                None
            };

            // Parse allowed IPs. A plain list replaces the peer's set;
            // a `+`-prefixed list adds incrementally (matches real `wg set`).
            let allowed = if let Some(ref ips_str) = args.allowed_ips {
                Some(parse_allowed_ips_spec(ips_str)?)
            } else {
                None
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
                if let Some((ref ips, replace)) = allowed
                    && !ips.is_empty()
                {
                    peer = peer.allowed_ips(ips.clone());
                    if replace {
                        peer = peer.replace_allowed_ips();
                    }
                }
                peer
            })
            .await?;
        }
    }

    Ok(())
}

/// Read a device private key, supporting the "unset" idiom.
///
/// `wg set wg0 private-key /dev/null` (or an empty file) clears the device's
/// private key — WireGuard treats an all-zero key as "remove". Otherwise this
/// behaves like [`read_key_file`].
fn read_private_key(path: &Path) -> Result<[u8; 32]> {
    if path == Path::new("/dev/null") {
        return Ok([0u8; 32]);
    }
    let content = fs::read_to_string(path).map_err(Error::Io)?;
    if content.trim().is_empty() {
        return Ok([0u8; 32]);
    }
    decode_key(&content)
}

/// Read a key from a file.
fn read_key_file(path: &PathBuf) -> Result<[u8; 32]> {
    let content = fs::read_to_string(path).map_err(Error::Io)?;
    decode_key(&content)
}

/// Decode a base64 32-byte WireGuard key.
fn decode_key(s: &str) -> Result<[u8; 32]> {
    let bytes = base64_decode(s)
        .map_err(|e| Error::InvalidMessage(format!("Invalid base64 in key: {}", e)))?;
    bytes.as_slice().try_into().map_err(|_| {
        Error::InvalidMessage(format!("Invalid key length: expected 32, got {}", bytes.len()))
    })
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

/// Parse one CIDR token (e.g. `10.0.0.0/24`) into an [`AllowedIp`].
fn parse_one_cidr(cidr: &str) -> Result<AllowedIp> {
    let (addr_str, prefix_str) = cidr
        .split_once('/')
        .ok_or_else(|| Error::InvalidMessage(format!("Invalid CIDR notation: {}", cidr)))?;

    let addr: IpAddr = addr_str
        .trim()
        .parse()
        .map_err(|e| Error::InvalidMessage(format!("Invalid IP address '{}': {}", addr_str, e)))?;

    let prefix: u8 = prefix_str
        .trim()
        .parse()
        .map_err(|e| Error::InvalidMessage(format!("Invalid prefix length '{}': {}", prefix_str, e)))?;

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

    Ok(AllowedIp { addr, cidr: prefix })
}

/// Parse a comma-separated allowed-IPs spec, returning the parsed ranges and
/// whether they should **replace** the peer's existing set.
///
/// Matches `wg set` incremental semantics:
/// - a plain list (`10.0.0.0/24, ...`) **replaces**;
/// - a `+`-prefixed list (`+10.0.0.0/24`) **adds** without replacing;
/// - a `-`-prefixed entry (single-range removal) is **not modelled** — the
///   library lacks the WGALLOWEDIP remove flag — and is a hard error rather
///   than a silent drop;
/// - mixing plain and `+` entries is rejected as ambiguous.
fn parse_allowed_ips_spec(s: &str) -> Result<(Vec<AllowedIp>, bool)> {
    let mut ips = Vec::new();
    let mut saw_incremental = false;
    let mut saw_plain = false;

    for raw in s.split(',') {
        let entry = raw.trim();
        if entry.is_empty() {
            continue;
        }
        let cidr = if let Some(rest) = entry.strip_prefix('+') {
            saw_incremental = true;
            rest.trim()
        } else if entry.starts_with('-') {
            return Err(Error::InvalidMessage(
                "removing individual allowed-ips (`-`) is not modelled — the library \
                 lacks the WGALLOWEDIP remove flag; re-list the full set to replace it"
                    .into(),
            ));
        } else {
            saw_plain = true;
            entry
        };
        ips.push(parse_one_cidr(cidr)?);
    }

    if saw_incremental && saw_plain {
        return Err(Error::InvalidMessage(
            "mixing plain and `+`-prefixed allowed-ips is not supported; prefix all with \
             `+` for incremental add, or none for replace"
                .into(),
        ));
    }

    // Plain (or empty) → replace; all-`+` → incremental add.
    Ok((ips, !saw_incremental))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_list_replaces() {
        let (ips, replace) = parse_allowed_ips_spec("10.0.0.0/24, 192.168.0.0/16").unwrap();
        assert!(replace);
        assert_eq!(ips.len(), 2);
        assert_eq!(ips[0].cidr, 24);
    }

    #[test]
    fn plus_prefixed_list_is_incremental() {
        let (ips, replace) = parse_allowed_ips_spec("+10.0.0.0/24, +10.1.0.0/24").unwrap();
        assert!(!replace, "`+` list must not replace");
        assert_eq!(ips.len(), 2);
    }

    #[test]
    fn minus_prefix_is_rejected() {
        let e = parse_allowed_ips_spec("-10.0.0.0/24").unwrap_err().to_string();
        assert!(e.contains("not modelled"), "{e}");
    }

    #[test]
    fn mixed_plain_and_plus_is_rejected() {
        let e = parse_allowed_ips_spec("10.0.0.0/24, +10.1.0.0/24")
            .unwrap_err()
            .to_string();
        assert!(e.contains("mixing plain and `+`"), "{e}");
    }

    #[test]
    fn rejects_bad_cidr() {
        assert!(parse_allowed_ips_spec("10.0.0.0/99").is_err());
        assert!(parse_allowed_ips_spec("not-an-ip/24").is_err());
        assert!(parse_allowed_ips_spec("10.0.0.0").is_err());
    }

    #[test]
    fn dev_null_unsets_private_key() {
        // /dev/null path is checked before any base64 decode → all-zeros.
        assert_eq!(read_private_key(Path::new("/dev/null")).unwrap(), [0u8; 32]);
    }

    #[test]
    fn decode_key_validates_length() {
        assert!(decode_key("AAAA").is_err());
        // 32 zero bytes base64-encodes to 44 chars ending in '='.
        let z = crate::output::base64_encode(&[0u8; 32]);
        assert_eq!(decode_key(&z).unwrap(), [0u8; 32]);
    }
}
