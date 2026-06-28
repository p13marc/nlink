//! wg-quick / `wg setconf` configuration-file parser (bin-local).
//!
//! Parses the kernel-level subset of the WireGuard config-file format into a
//! library [`WireguardConfig`]:
//!
//! ```text
//! [Interface]
//! PrivateKey = <base64>
//! ListenPort = 51820
//! FwMark = 0x42            # optional; "off" clears
//!
//! [Peer]
//! PublicKey = <base64>
//! PresharedKey = <base64>  # optional
//! Endpoint = host:port     # optional
//! AllowedIPs = 10.0.0.0/24, 192.168.0.0/16
//! PersistentKeepalive = 25 # optional; "off" disables
//! ```
//!
//! This is the inverse of [`crate::show::run_conf`] (the `showconf` writer).
//!
//! **Strict by design** (CLAUDE.md parse contract): unknown keys, malformed
//! values, a key outside any section, and a `[Peer]` without a `PublicKey`
//! are all hard errors. This matches real `wg setconf`, which rejects
//! wg-quick-only keys (`Address`/`DNS`/`MTU`/`Table`/`PreUp`/…) — use
//! `wg-quick` for those.

use std::{fs, net::SocketAddr, path::Path, time::Duration};

use nlink::netlink::{
    Connection, Error, Result, Wireguard,
    genl::wireguard::{AllowedIp, WireguardConfig},
    nftables::config::ReconcileOptions,
};

use crate::output::base64_decode;

/// `wg setconf <if> <file>` — apply the config-file's declared device + peers
/// to the kernel (declarative apply; only differing fields are written).
///
/// Note: like the library's `WireguardConfig::apply`, this is additive — it
/// does not remove peers that exist in the kernel but are absent from the
/// file. (Real `wg setconf` prunes unlisted peers; that pruning is not
/// modelled here.)
pub async fn run_setconf(interface: &str, file: &Path) -> Result<()> {
    let cfg = load(interface, file)?;
    let conn = Connection::<Wireguard>::new_async().await?;
    let result = cfg.apply(&conn).await?;
    println!(
        "wg: applied {} change(s) to {interface}",
        result.total_writes()
    );
    Ok(())
}

/// `wg syncconf <if> <file>` — the reconcile shape: apply with bounded retry
/// on transient kernel contention (EBUSY/EAGAIN).
pub async fn run_syncconf(interface: &str, file: &Path) -> Result<()> {
    let cfg = load(interface, file)?;
    let conn = Connection::<Wireguard>::new_async().await?;
    let report = cfg
        .apply_reconcile(&conn, ReconcileOptions::default())
        .await?;
    println!(
        "wg: synced {} change(s) to {interface} in {} attempt(s)",
        report.change_count, report.attempts
    );
    Ok(())
}

/// `wg addconf <if> <file>` — append the config-file's peers/settings to
/// the interface without removing peers that already exist in the kernel.
///
/// This is the additive form. Because the library's `WireguardConfig::apply`
/// never prunes unlisted peers, `addconf` and [`run_setconf`] currently
/// behave identically here — the distinction matters only once `setconf`
/// gains real `wg setconf` pruning of unlisted peers (not modelled yet).
pub async fn run_addconf(interface: &str, file: &Path) -> Result<()> {
    let cfg = load(interface, file)?;
    let conn = Connection::<Wireguard>::new_async().await?;
    let result = cfg.apply(&conn).await?;
    println!(
        "wg: added {} change(s) to {interface}",
        result.total_writes()
    );
    Ok(())
}

/// Read and parse a config file into a [`WireguardConfig`]. The parse runs
/// before any kernel connection, so a malformed file fails fast.
fn load(interface: &str, file: &Path) -> Result<WireguardConfig> {
    let contents = fs::read_to_string(file).map_err(Error::Io)?;
    parse(&contents, interface)
}

#[derive(Default)]
struct Iface {
    private_key: Option<[u8; 32]>,
    listen_port: Option<u16>,
    fwmark: Option<u32>,
}

struct Peer {
    public_key: Option<[u8; 32]>,
    preshared_key: Option<[u8; 32]>,
    endpoint: Option<SocketAddr>,
    keepalive: Option<u16>,
    allowed_ips: Vec<AllowedIp>,
}

impl Peer {
    fn new() -> Self {
        Self {
            public_key: None,
            preshared_key: None,
            endpoint: None,
            keepalive: None,
            allowed_ips: Vec::new(),
        }
    }
}

enum Section {
    None,
    Interface,
    Peer,
}

/// Parse a WireGuard config file into a single-device [`WireguardConfig`]
/// bound to `ifname`.
pub fn parse(contents: &str, ifname: &str) -> Result<WireguardConfig> {
    let mut iface = Iface::default();
    let mut peers: Vec<Peer> = Vec::new();
    let mut section = Section::None;

    for (lineno, raw) in contents.lines().enumerate() {
        let lineno = lineno + 1;
        // Strip inline comments and surrounding whitespace.
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }

        // Section header?
        if let Some(stripped) = line.strip_prefix('[') {
            let name = stripped
                .strip_suffix(']')
                .ok_or_else(|| err(lineno, format!("malformed section header `{line}`")))?
                .trim()
                .to_ascii_lowercase();
            section = match name.as_str() {
                "interface" => Section::Interface,
                "peer" => {
                    peers.push(Peer::new());
                    Section::Peer
                }
                other => return Err(err(lineno, format!("unknown section `[{other}]`"))),
            };
            continue;
        }

        // Key = Value line.
        let (key, value) = line
            .split_once('=')
            .ok_or_else(|| err(lineno, format!("expected `Key = Value`, got `{line}`")))?;
        let key = key.trim().to_ascii_lowercase();
        let value = value.trim();

        match section {
            Section::None => {
                return Err(err(
                    lineno,
                    format!("`{key}` appears before any [Interface]/[Peer] section"),
                ));
            }
            Section::Interface => match key.as_str() {
                "privatekey" => iface.private_key = Some(decode_key(lineno, "PrivateKey", value)?),
                "listenport" => {
                    iface.listen_port = Some(value.parse().map_err(|_| {
                        err(lineno, format!("invalid ListenPort `{value}`"))
                    })?)
                }
                "fwmark" => iface.fwmark = Some(parse_fwmark(lineno, value)?),
                other => {
                    return Err(err(
                        lineno,
                        format!(
                            "unknown [Interface] key `{other}` (supported: PrivateKey, \
                             ListenPort, FwMark — wg-quick keys like Address/DNS/MTU are \
                             not handled by setconf; use wg-quick)"
                        ),
                    ));
                }
            },
            Section::Peer => {
                let peer = peers
                    .last_mut()
                    .expect("a [Peer] section was opened before any peer key");
                match key.as_str() {
                    "publickey" => peer.public_key = Some(decode_key(lineno, "PublicKey", value)?),
                    "presharedkey" => {
                        peer.preshared_key = Some(decode_key(lineno, "PresharedKey", value)?)
                    }
                    "endpoint" => {
                        peer.endpoint = Some(value.parse().map_err(|_| {
                            err(lineno, format!("invalid Endpoint `{value}` (expected host:port)"))
                        })?)
                    }
                    "allowedips" => peer.allowed_ips = parse_allowed_ips(lineno, value)?,
                    "persistentkeepalive" => peer.keepalive = parse_keepalive(lineno, value)?,
                    other => {
                        return Err(err(
                            lineno,
                            format!(
                                "unknown [Peer] key `{other}` (supported: PublicKey, \
                                 PresharedKey, Endpoint, AllowedIPs, PersistentKeepalive)"
                            ),
                        ));
                    }
                }
            }
        }
    }

    // Validate peers and build the config.
    let mut finalized: Vec<Peer> = Vec::with_capacity(peers.len());
    for (idx, peer) in peers.into_iter().enumerate() {
        if peer.public_key.is_none() {
            return Err(Error::InvalidMessage(format!(
                "wg conf: [Peer] #{} is missing a PublicKey",
                idx + 1
            )));
        }
        finalized.push(peer);
    }

    let cfg = WireguardConfig::new().device(ifname.to_string(), |mut d| {
        if let Some(k) = iface.private_key {
            d = d.private_key(k);
        }
        if let Some(p) = iface.listen_port {
            d = d.listen_port(p);
        }
        if let Some(fw) = iface.fwmark {
            d = d.fwmark(fw);
        }
        for peer in finalized {
            let pk = peer.public_key.expect("validated above");
            d = d.peer(pk, move |mut pb| {
                if let Some(psk) = peer.preshared_key {
                    pb = pb.preshared_key(psk);
                }
                if let Some(ep) = peer.endpoint {
                    pb = pb.endpoint(ep);
                }
                if let Some(ka) = peer.keepalive {
                    pb = pb.persistent_keepalive(Duration::from_secs(ka as u64));
                }
                for ip in &peer.allowed_ips {
                    pb = pb.allowed_ip(*ip);
                }
                pb
            });
        }
        d
    });

    Ok(cfg)
}

fn err(lineno: usize, msg: String) -> Error {
    Error::InvalidMessage(format!("wg conf: line {lineno}: {msg}"))
}

/// Decode a base64 WireGuard key into a 32-byte array.
fn decode_key(lineno: usize, field: &str, value: &str) -> Result<[u8; 32]> {
    let bytes = base64_decode(value)
        .map_err(|e| err(lineno, format!("invalid base64 for {field}: {e}")))?;
    let arr: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
        err(
            lineno,
            format!("{field} must be 32 bytes, got {}", bytes.len()),
        )
    })?;
    Ok(arr)
}

/// Parse a firewall mark: decimal, `0x`-prefixed hex, or `off` (== 0).
fn parse_fwmark(lineno: usize, value: &str) -> Result<u32> {
    if value.eq_ignore_ascii_case("off") {
        return Ok(0);
    }
    let parsed = if let Some(hex) = value.strip_prefix("0x").or_else(|| value.strip_prefix("0X")) {
        u32::from_str_radix(hex, 16)
    } else {
        value.parse::<u32>()
    };
    parsed.map_err(|_| err(lineno, format!("invalid FwMark `{value}`")))
}

/// Parse `PersistentKeepalive`: `off` disables, otherwise seconds (1..=65535).
fn parse_keepalive(lineno: usize, value: &str) -> Result<Option<u16>> {
    if value.eq_ignore_ascii_case("off") || value == "0" {
        return Ok(None);
    }
    let secs: u16 = value
        .parse()
        .map_err(|_| err(lineno, format!("invalid PersistentKeepalive `{value}`")))?;
    Ok(Some(secs))
}

/// Parse a comma-separated `AllowedIPs` list in CIDR notation.
fn parse_allowed_ips(lineno: usize, value: &str) -> Result<Vec<AllowedIp>> {
    use std::net::IpAddr;

    let mut out = Vec::new();
    for cidr in value.split(',') {
        let cidr = cidr.trim();
        if cidr.is_empty() {
            continue;
        }
        let (addr_str, prefix_str) = cidr
            .split_once('/')
            .ok_or_else(|| err(lineno, format!("invalid CIDR `{cidr}` (expected addr/prefix)")))?;
        let addr: IpAddr = addr_str
            .trim()
            .parse()
            .map_err(|e| err(lineno, format!("invalid IP `{addr_str}`: {e}")))?;
        let prefix: u8 = prefix_str
            .trim()
            .parse()
            .map_err(|e| err(lineno, format!("invalid prefix `{prefix_str}`: {e}")))?;
        let max = if addr.is_ipv4() { 32 } else { 128 };
        if prefix > max {
            return Err(err(
                lineno,
                format!("prefix {prefix} exceeds maximum {max} for {addr}"),
            ));
        }
        out.push(AllowedIp { addr, cidr: prefix });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SK: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEE=";
    const PK: &str = "ABEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEE=";

    fn sample() -> String {
        format!(
            "# a comment\n\
             [Interface]\n\
             PrivateKey = {SK}\n\
             ListenPort = 51820\n\
             FwMark = 0x42\n\
             \n\
             [Peer]\n\
             PublicKey = {PK}\n\
             Endpoint = 203.0.113.1:51820\n\
             AllowedIPs = 10.0.0.0/24, 192.168.0.0/16\n\
             PersistentKeepalive = 25\n"
        )
    }

    #[test]
    fn parses_a_full_config() {
        let cfg = parse(&sample(), "wg0").unwrap();
        let devs = cfg.devices();
        assert_eq!(devs.len(), 1);
        let d = &devs[0];
        assert_eq!(d.ifname, "wg0");
        assert_eq!(d.listen_port, Some(51820));
        assert_eq!(d.fwmark, Some(0x42));
        assert!(d.private_key.is_some());
        assert_eq!(d.peers.len(), 1);
        let p = &d.peers[0];
        assert_eq!(p.endpoint.unwrap().to_string(), "203.0.113.1:51820");
        assert_eq!(p.persistent_keepalive, Some(Duration::from_secs(25)));
        assert_eq!(p.allowed_ips.len(), 2);
    }

    #[test]
    fn rejects_unknown_interface_key() {
        // `Address` is a wg-quick-only key — real `wg setconf` rejects it too.
        let conf = format!("[Interface]\nPrivateKey = {SK}\nAddress = 10.0.0.1/24\n");
        let e = parse(&conf, "wg0").unwrap_err().to_string();
        assert!(e.contains("unknown [Interface] key `address`"), "{e}");
    }

    #[test]
    fn rejects_unknown_peer_key() {
        let conf = format!("[Peer]\nPublicKey = {PK}\nFancyKey = x\n");
        let e = parse(&conf, "wg0").unwrap_err().to_string();
        assert!(e.contains("unknown [Peer] key `fancykey`"), "{e}");
    }

    #[test]
    fn rejects_peer_without_public_key() {
        let conf = "[Peer]\nAllowedIPs = 10.0.0.0/24\n";
        let e = parse(conf, "wg0").unwrap_err().to_string();
        assert!(e.contains("missing a PublicKey"), "{e}");
    }

    #[test]
    fn rejects_key_before_section() {
        let conf = format!("PrivateKey = {SK}\n");
        let e = parse(&conf, "wg0").unwrap_err().to_string();
        assert!(e.contains("before any [Interface]/[Peer] section"), "{e}");
    }

    #[test]
    fn rejects_bad_base64_key() {
        let conf = "[Interface]\nPrivateKey = not-valid-base64!!\n";
        let e = parse(conf, "wg0").unwrap_err().to_string();
        assert!(e.contains("invalid base64 for PrivateKey"), "{e}");
    }

    #[test]
    fn rejects_short_key() {
        let conf = "[Interface]\nPrivateKey = AAAA\n";
        let e = parse(conf, "wg0").unwrap_err().to_string();
        assert!(e.contains("must be 32 bytes"), "{e}");
    }

    #[test]
    fn fwmark_off_is_zero_and_keepalive_off_is_none() {
        let conf = format!(
            "[Interface]\nPrivateKey = {SK}\nFwMark = off\n\
             [Peer]\nPublicKey = {PK}\nPersistentKeepalive = off\n"
        );
        let cfg = parse(&conf, "wg0").unwrap();
        let d = &cfg.devices()[0];
        assert_eq!(d.fwmark, Some(0));
        assert_eq!(d.peers[0].persistent_keepalive, None);
    }
}
