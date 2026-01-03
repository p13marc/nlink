//! Query WireGuard interfaces via Generic Netlink.
//!
//! This example demonstrates how to use the Generic Netlink protocol
//! to query WireGuard device configuration and peer information.
//!
//! Run with: cargo run -p nlink --example genl_wireguard
//!
//! Note: Requires a WireGuard interface to exist. Create one with:
//!   sudo ip link add wg0 type wireguard
//!   sudo wg genkey | sudo tee /etc/wireguard/private.key
//!   sudo wg set wg0 private-key /etc/wireguard/private.key listen-port 51820

use nlink::netlink::genl::wireguard::WireguardConnection;

#[tokio::main]
async fn main() -> nlink::netlink::Result<()> {
    // Try to connect to WireGuard GENL family
    let wg = match WireguardConnection::new().await {
        Ok(wg) => wg,
        Err(e) => {
            eprintln!("Failed to connect to WireGuard: {}", e);
            eprintln!("Make sure the wireguard kernel module is loaded.");
            eprintln!("Try: sudo modprobe wireguard");
            return Ok(());
        }
    };

    // List all WireGuard interfaces by checking common names
    println!("=== WireGuard Interfaces ===\n");

    let interface_names = ["wg0", "wg1", "wg2", "wg-vpn", "wireguard0"];
    let mut found_any = false;

    for ifname in &interface_names {
        match wg.get_device(ifname).await {
            Ok(device) => {
                found_any = true;
                print_device(&device);
            }
            Err(e) if e.is_not_found() || e.is_no_device() => {
                // Interface doesn't exist, skip
            }
            Err(e) => {
                eprintln!("Error querying {}: {}", ifname, e);
            }
        }
    }

    if !found_any {
        println!("No WireGuard interfaces found.");
        println!("\nTo create a WireGuard interface:");
        println!("  sudo ip link add wg0 type wireguard");
        println!("  wg genkey > privatekey");
        println!("  sudo wg set wg0 private-key ./privatekey listen-port 51820");
        println!("  sudo ip link set wg0 up");
    }

    Ok(())
}

fn print_device(device: &nlink::netlink::genl::wireguard::WgDevice) {
    let ifname = device.ifname.as_deref().unwrap_or("?");
    let ifindex = device.ifindex.unwrap_or(0);

    println!("interface: {} (index {})", ifname, ifindex);

    if let Some(key) = &device.public_key {
        println!("  public key: {}", format_key(key));
    }

    if let Some(port) = device.listen_port {
        println!("  listening port: {}", port);
    }

    if let Some(fwmark) = device.fwmark
        && fwmark != 0
    {
        println!("  fwmark: 0x{:x}", fwmark);
    }

    if device.peers.is_empty() {
        println!("  peers: (none)");
    } else {
        println!("  peers: {}", device.peers.len());
        for peer in &device.peers {
            println!();
            print_peer(peer);
        }
    }
    println!();
}

fn print_peer(peer: &nlink::netlink::genl::wireguard::WgPeer) {
    println!("  peer: {}", format_key(&peer.public_key));

    if let Some(endpoint) = &peer.endpoint {
        println!("    endpoint: {}", endpoint);
    }

    if !peer.allowed_ips.is_empty() {
        let ips: Vec<String> = peer
            .allowed_ips
            .iter()
            .map(|ip| format!("{}/{}", ip.addr, ip.cidr))
            .collect();
        println!("    allowed ips: {}", ips.join(", "));
    }

    if let Some(keepalive) = peer.persistent_keepalive
        && keepalive > 0
    {
        println!("    persistent keepalive: every {} seconds", keepalive);
    }

    if let Some(handshake) = peer.last_handshake {
        let now = std::time::SystemTime::now();
        if let Ok(duration) = now.duration_since(handshake) {
            let secs = duration.as_secs();
            if secs < 60 {
                println!("    latest handshake: {} seconds ago", secs);
            } else if secs < 3600 {
                println!("    latest handshake: {} minutes ago", secs / 60);
            } else if secs < 86400 {
                println!("    latest handshake: {} hours ago", secs / 3600);
            } else {
                println!("    latest handshake: {} days ago", secs / 86400);
            }
        }
    }

    if peer.rx_bytes > 0 || peer.tx_bytes > 0 {
        println!(
            "    transfer: {} received, {} sent",
            format_bytes(peer.rx_bytes),
            format_bytes(peer.tx_bytes)
        );
    }
}

fn format_key(key: &[u8; 32]) -> String {
    use std::io::Write;
    let mut buf = Vec::with_capacity(44);
    {
        let mut encoder = base64::Encoder::new(&mut buf);
        encoder.write_all(key).unwrap();
    }
    String::from_utf8(buf).unwrap_or_else(|_| "(invalid)".to_string())
}

fn format_bytes(bytes: u64) -> String {
    const KIB: u64 = 1024;
    const MIB: u64 = 1024 * KIB;
    const GIB: u64 = 1024 * MIB;

    if bytes >= GIB {
        format!("{:.2} GiB", bytes as f64 / GIB as f64)
    } else if bytes >= MIB {
        format!("{:.2} MiB", bytes as f64 / MIB as f64)
    } else if bytes >= KIB {
        format!("{:.2} KiB", bytes as f64 / KIB as f64)
    } else {
        format!("{} B", bytes)
    }
}

// Simple base64 encoder for WireGuard keys
mod base64 {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    pub struct Encoder<'a> {
        output: &'a mut Vec<u8>,
        buffer: u32,
        bits: u8,
    }

    impl<'a> Encoder<'a> {
        pub fn new(output: &'a mut Vec<u8>) -> Self {
            Self {
                output,
                buffer: 0,
                bits: 0,
            }
        }

        fn flush(&mut self) {
            while self.bits >= 6 {
                self.bits -= 6;
                let idx = ((self.buffer >> self.bits) & 0x3F) as usize;
                self.output.push(ALPHABET[idx]);
            }
        }
    }

    impl std::io::Write for Encoder<'_> {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            for &byte in buf {
                self.buffer = (self.buffer << 8) | byte as u32;
                self.bits += 8;
                self.flush();
            }
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            if self.bits > 0 {
                self.buffer <<= 6 - self.bits;
                self.bits = 6;
                Encoder::flush(self);
                // Add padding
                let padding = (3 - (self.output.len() % 3)) % 3;
                for _ in 0..padding {
                    self.output.push(b'=');
                }
            }
            Ok(())
        }
    }

    impl Drop for Encoder<'_> {
        fn drop(&mut self) {
            let _ = std::io::Write::flush(self);
        }
    }
}
