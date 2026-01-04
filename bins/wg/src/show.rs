//! Show command implementation for WireGuard.

use clap::{Args, ValueEnum};
use nlink::netlink::genl::wireguard::{WgDevice, WgPeer};
use nlink::netlink::{Connection, Result, Route, Wireguard};

use crate::output::{base64_encode, format_bytes, format_time_ago};

#[derive(Args)]
pub struct ShowArgs {
    /// Interface name (shows all if omitted)
    pub interface: Option<String>,

    /// Show only specific field
    #[arg(value_enum)]
    pub field: Option<ShowField>,
}

#[derive(Clone, ValueEnum)]
pub enum ShowField {
    /// Show public key
    PublicKey,
    /// Show private key
    PrivateKey,
    /// Show listen port
    ListenPort,
    /// Show firewall mark
    Fwmark,
    /// Show peer public keys
    Peers,
    /// Show preshared keys
    PresharedKeys,
    /// Show peer endpoints
    Endpoints,
    /// Show allowed IPs
    AllowedIps,
    /// Show latest handshake times
    LatestHandshakes,
    /// Show transfer statistics
    Transfer,
    /// Show persistent keepalive intervals
    PersistentKeepalive,
    /// Machine-readable dump format
    Dump,
}

/// Run show for all WireGuard interfaces.
pub async fn run_all() -> Result<()> {
    let wg_interfaces = get_wireguard_interfaces().await?;

    if wg_interfaces.is_empty() {
        return Ok(());
    }

    let conn = Connection::<Wireguard>::new_async().await?;

    let mut first = true;
    for ifname in &wg_interfaces {
        if !first {
            println!();
        }
        first = false;

        match conn.get_device(ifname).await {
            Ok(device) => print_device(&device),
            Err(e) => eprintln!("Error reading {}: {}", ifname, e),
        }
    }

    Ok(())
}

/// Run show command with arguments.
pub async fn run(args: ShowArgs) -> Result<()> {
    if let Some(interface) = args.interface {
        let conn = Connection::<Wireguard>::new_async().await?;
        let device = conn.get_device(&interface).await?;

        match args.field {
            None => print_device(&device),
            Some(ShowField::PublicKey) => {
                if let Some(ref pk) = device.public_key {
                    println!("{}", base64_encode(pk));
                }
            }
            Some(ShowField::PrivateKey) => {
                // Private key is never returned by kernel
                println!("(none)");
            }
            Some(ShowField::ListenPort) => {
                println!("{}", device.listen_port.unwrap_or(0));
            }
            Some(ShowField::Fwmark) => {
                if let Some(fwmark) = device.fwmark {
                    if fwmark != 0 {
                        println!("0x{:x}", fwmark);
                    } else {
                        println!("off");
                    }
                } else {
                    println!("off");
                }
            }
            Some(ShowField::Peers) => {
                for peer in &device.peers {
                    println!("{}", base64_encode(&peer.public_key));
                }
            }
            Some(ShowField::PresharedKeys) => {
                for peer in &device.peers {
                    if let Some(ref psk) = peer.preshared_key {
                        println!("{}\t{}", base64_encode(&peer.public_key), base64_encode(psk));
                    } else {
                        println!("{}\t(none)", base64_encode(&peer.public_key));
                    }
                }
            }
            Some(ShowField::Endpoints) => {
                for peer in &device.peers {
                    let endpoint = peer
                        .endpoint
                        .as_ref()
                        .map(|e| e.to_string())
                        .unwrap_or_else(|| "(none)".to_string());
                    println!("{}\t{}", base64_encode(&peer.public_key), endpoint);
                }
            }
            Some(ShowField::AllowedIps) => {
                for peer in &device.peers {
                    let ips: Vec<String> = peer.allowed_ips.iter().map(|ip| ip.to_string()).collect();
                    println!(
                        "{}\t{}",
                        base64_encode(&peer.public_key),
                        if ips.is_empty() {
                            "(none)".to_string()
                        } else {
                            ips.join(" ")
                        }
                    );
                }
            }
            Some(ShowField::LatestHandshakes) => {
                for peer in &device.peers {
                    let handshake = peer
                        .last_handshake
                        .map(|t| {
                            t.duration_since(std::time::UNIX_EPOCH)
                                .map(|d| d.as_secs().to_string())
                                .unwrap_or_else(|_| "0".to_string())
                        })
                        .unwrap_or_else(|| "0".to_string());
                    println!("{}\t{}", base64_encode(&peer.public_key), handshake);
                }
            }
            Some(ShowField::Transfer) => {
                for peer in &device.peers {
                    println!(
                        "{}\t{}\t{}",
                        base64_encode(&peer.public_key),
                        peer.rx_bytes,
                        peer.tx_bytes
                    );
                }
            }
            Some(ShowField::PersistentKeepalive) => {
                for peer in &device.peers {
                    let keepalive = peer
                        .persistent_keepalive
                        .filter(|&k| k > 0)
                        .map(|k| k.to_string())
                        .unwrap_or_else(|| "off".to_string());
                    println!("{}\t{}", base64_encode(&peer.public_key), keepalive);
                }
            }
            Some(ShowField::Dump) => {
                print_dump(&device);
            }
        }
    } else {
        run_all().await?;
    }

    Ok(())
}

/// Run showconf command - output in wg-quick format.
pub async fn run_conf(interface: &str) -> Result<()> {
    let conn = Connection::<Wireguard>::new_async().await?;
    let device = conn.get_device(interface).await?;

    println!("[Interface]");
    if let Some(port) = device.listen_port
        && port != 0 {
            println!("ListenPort = {}", port);
        }
    if let Some(fwmark) = device.fwmark
        && fwmark != 0 {
            println!("FwMark = 0x{:x}", fwmark);
        }
    // Private key is not returned by kernel, so we can't output it
    // In the real wg tool, it requires PrivateKey to be set

    for peer in &device.peers {
        println!();
        println!("[Peer]");
        println!("PublicKey = {}", base64_encode(&peer.public_key));
        if let Some(ref psk) = peer.preshared_key {
            println!("PresharedKey = {}", base64_encode(psk));
        }
        if !peer.allowed_ips.is_empty() {
            let ips: Vec<String> = peer.allowed_ips.iter().map(|ip| ip.to_string()).collect();
            println!("AllowedIPs = {}", ips.join(", "));
        }
        if let Some(ref endpoint) = peer.endpoint {
            println!("Endpoint = {}", endpoint);
        }
        if let Some(keepalive) = peer.persistent_keepalive
            && keepalive > 0 {
                println!("PersistentKeepalive = {}", keepalive);
            }
    }

    Ok(())
}

/// Print device information in human-readable format.
fn print_device(device: &WgDevice) {
    let ifname = device.ifname.as_deref().unwrap_or("?");
    println!("interface: {}", ifname);

    if let Some(ref pk) = device.public_key {
        println!("  public key: {}", base64_encode(pk));
    }
    println!("  private key: (hidden)");

    if let Some(port) = device.listen_port
        && port != 0 {
            println!("  listening port: {}", port);
        }

    if let Some(fwmark) = device.fwmark
        && fwmark != 0 {
            println!("  fwmark: 0x{:x}", fwmark);
        }

    for peer in &device.peers {
        println!();
        print_peer(peer);
    }
}

/// Print peer information.
fn print_peer(peer: &WgPeer) {
    println!("peer: {}", base64_encode(&peer.public_key));

    if peer.preshared_key.is_some() {
        println!("  preshared key: (hidden)");
    }

    if let Some(ref endpoint) = peer.endpoint {
        println!("  endpoint: {}", endpoint);
    }

    if !peer.allowed_ips.is_empty() {
        let ips: Vec<String> = peer.allowed_ips.iter().map(|ip| ip.to_string()).collect();
        println!("  allowed ips: {}", ips.join(", "));
    }

    if let Some(time) = peer.last_handshake {
        println!("  latest handshake: {}", format_time_ago(time));
    }

    if peer.rx_bytes > 0 || peer.tx_bytes > 0 {
        println!(
            "  transfer: {} received, {} sent",
            format_bytes(peer.rx_bytes),
            format_bytes(peer.tx_bytes)
        );
    }

    if let Some(keepalive) = peer.persistent_keepalive
        && keepalive > 0 {
            println!("  persistent keepalive: every {} seconds", keepalive);
        }
}

/// Print device in machine-readable dump format.
fn print_dump(device: &WgDevice) {
    let ifname = device.ifname.as_deref().unwrap_or("?");
    let private_key = "(none)"; // Never returned by kernel
    let public_key = device
        .public_key
        .as_ref()
        .map(|k| base64_encode(k))
        .unwrap_or_else(|| "(none)".to_string());
    let listen_port = device.listen_port.unwrap_or(0);
    let fwmark = device
        .fwmark
        .filter(|&f| f != 0)
        .map(|f| format!("0x{:x}", f))
        .unwrap_or_else(|| "off".to_string());

    // Interface line
    println!(
        "{}\t{}\t{}\t{}\t{}",
        ifname, private_key, public_key, listen_port, fwmark
    );

    // Peer lines
    for peer in &device.peers {
        let psk = peer
            .preshared_key
            .as_ref()
            .map(|k| base64_encode(k))
            .unwrap_or_else(|| "(none)".to_string());
        let endpoint = peer
            .endpoint
            .as_ref()
            .map(|e| e.to_string())
            .unwrap_or_else(|| "(none)".to_string());
        let allowed_ips: Vec<String> = peer.allowed_ips.iter().map(|ip| ip.to_string()).collect();
        let allowed_ips_str = if allowed_ips.is_empty() {
            "(none)".to_string()
        } else {
            allowed_ips.join(",")
        };
        let handshake = peer
            .last_handshake
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let keepalive = peer
            .persistent_keepalive
            .filter(|&k| k > 0)
            .map(|k| k.to_string())
            .unwrap_or_else(|| "off".to_string());

        println!(
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            base64_encode(&peer.public_key),
            psk,
            endpoint,
            allowed_ips_str,
            handshake,
            peer.rx_bytes,
            peer.tx_bytes,
            keepalive
        );
    }
}

/// Get list of WireGuard interface names.
async fn get_wireguard_interfaces() -> Result<Vec<String>> {
    let conn = Connection::<Route>::new()?;
    let links = conn.get_links().await?;

    let mut wg_interfaces = Vec::new();
    for link in links {
        if let Some(info) = link.link_info()
            && info.kind() == Some("wireguard")
                && let Some(name) = link.name() {
                    wg_interfaces.push(name.to_string());
                }
    }

    Ok(wg_interfaces)
}
