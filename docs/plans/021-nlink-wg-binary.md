# Plan 021: Create `nlink-wg` Binary

## Overview

Create a new binary for WireGuard management, exposing the WireGuard Generic Netlink API.

## Current State

- Library: Full WireGuard support in `netlink/genl/wireguard/`
- Binary: None exists
- Reference: `wg` tool from wireguard-tools

## Target Commands

```bash
# Show all WireGuard interfaces
wg show
wg

# Show specific interface
wg show wg0
wg show wg0 public-key
wg show wg0 private-key
wg show wg0 listen-port
wg show wg0 peers
wg show wg0 endpoints
wg show wg0 allowed-ips
wg show wg0 latest-handshakes
wg show wg0 transfer
wg show wg0 persistent-keepalive
wg show wg0 dump  # machine-readable

# Show configuration format
wg showconf wg0

# Set interface parameters
wg set wg0 listen-port 51820
wg set wg0 private-key /path/to/key
wg set wg0 peer <base64-pubkey> endpoint 192.168.1.1:51820
wg set wg0 peer <base64-pubkey> allowed-ips 10.0.0.0/24,192.168.0.0/16
wg set wg0 peer <base64-pubkey> persistent-keepalive 25
wg set wg0 peer <base64-pubkey> remove

# Generate keys
wg genkey
wg pubkey < privatekey
wg genpsk
```

## Project Structure

```
bins/wg/
├── Cargo.toml
└── src/
    ├── main.rs
    ├── show.rs
    ├── set.rs
    ├── keys.rs
    └── output.rs
```

### Cargo.toml

```toml
[package]
name = "nlink-wg"
version.workspace = true
edition.workspace = true

[[bin]]
name = "wg"
path = "src/main.rs"

[dependencies]
nlink = { path = "../../crates/nlink" }
clap = { workspace = true }
tokio = { workspace = true }
base64 = "0.21"
rand = "0.8"
x25519-dalek = "2.0"
```

## Implementation Details

### main.rs

```rust
use clap::{Parser, Subcommand};

mod show;
mod set;
mod keys;
mod output;

#[derive(Parser)]
#[command(name = "wg", about = "WireGuard management utility")]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Show WireGuard interfaces and peers
    Show(show::ShowArgs),
    /// Show interface configuration
    Showconf {
        /// Interface name
        interface: String,
    },
    /// Set interface configuration
    Set(set::SetArgs),
    /// Generate a private key
    Genkey,
    /// Derive public key from private key (stdin)
    Pubkey,
    /// Generate a preshared key
    Genpsk,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    
    match cli.command {
        None => show::run_all().await,
        Some(Command::Show(args)) => show::run(args).await,
        Some(Command::Showconf { interface }) => show::run_conf(&interface).await,
        Some(Command::Set(args)) => set::run(args).await,
        Some(Command::Genkey) => keys::genkey(),
        Some(Command::Pubkey) => keys::pubkey(),
        Some(Command::Genpsk) => keys::genpsk(),
    }
}
```

### show.rs

```rust
use clap::Args;
use nlink::netlink::{Connection, Wireguard};

#[derive(Args)]
pub struct ShowArgs {
    /// Interface name (optional, shows all if omitted)
    interface: Option<String>,
    
    /// Show only specific field
    #[arg(value_enum)]
    field: Option<ShowField>,
}

#[derive(Clone, ValueEnum)]
pub enum ShowField {
    PublicKey,
    PrivateKey,
    ListenPort,
    Fwmark,
    Peers,
    PresharedKeys,
    Endpoints,
    AllowedIps,
    LatestHandshakes,
    Transfer,
    PersistentKeepalive,
    Dump,
}

pub async fn run_all() -> anyhow::Result<()> {
    let conn = Connection::<Wireguard>::new_async().await?;
    
    // List all WireGuard interfaces
    let links = {
        let route_conn = Connection::<Route>::new()?;
        route_conn.get_links().await?
    };
    
    for link in links {
        if link.link_info().map(|i| i.kind()) == Some(Some("wireguard")) {
            let name = link.name_or("?");
            let device = conn.get_device(name).await?;
            print_device(&device);
        }
    }
    
    Ok(())
}

pub async fn run(args: ShowArgs) -> anyhow::Result<()> {
    let conn = Connection::<Wireguard>::new_async().await?;
    
    if let Some(interface) = args.interface {
        let device = conn.get_device(&interface).await?;
        
        match args.field {
            None => print_device(&device),
            Some(ShowField::PublicKey) => println!("{}", base64_encode(&device.public_key)),
            Some(ShowField::ListenPort) => println!("{}", device.listen_port.unwrap_or(0)),
            Some(ShowField::Peers) => {
                for peer in &device.peers {
                    println!("{}", base64_encode(&peer.public_key));
                }
            }
            Some(ShowField::Dump) => print_dump(&device),
            // ... other fields
        }
    } else {
        run_all().await?;
    }
    
    Ok(())
}

fn print_device(device: &WgDevice) {
    println!("interface: {}", device.name);
    if let Some(ref pk) = device.public_key {
        println!("  public key: {}", base64_encode(pk));
    }
    if let Some(port) = device.listen_port {
        println!("  listening port: {}", port);
    }
    
    for peer in &device.peers {
        println!();
        println!("peer: {}", base64_encode(&peer.public_key));
        if let Some(ref endpoint) = peer.endpoint {
            println!("  endpoint: {}", endpoint);
        }
        if !peer.allowed_ips.is_empty() {
            let ips: Vec<String> = peer.allowed_ips.iter()
                .map(|ip| format!("{}/{}", ip.addr, ip.cidr))
                .collect();
            println!("  allowed ips: {}", ips.join(", "));
        }
        if let Some(handshake) = peer.last_handshake_time {
            println!("  latest handshake: {}", format_time(handshake));
        }
        println!("  transfer: {} received, {} sent", 
            format_bytes(peer.rx_bytes),
            format_bytes(peer.tx_bytes));
        if peer.persistent_keepalive_interval > 0 {
            println!("  persistent keepalive: every {} seconds", 
                peer.persistent_keepalive_interval);
        }
    }
}
```

### set.rs

```rust
use clap::Args;
use nlink::netlink::{Connection, Wireguard};
use nlink::netlink::genl::wireguard::AllowedIp;
use std::net::SocketAddr;

#[derive(Args)]
pub struct SetArgs {
    /// Interface name
    interface: String,
    
    /// Listen port
    #[arg(long = "listen-port")]
    listen_port: Option<u16>,
    
    /// Private key file
    #[arg(long = "private-key")]
    private_key: Option<PathBuf>,
    
    /// Firewall mark
    #[arg(long)]
    fwmark: Option<u32>,
    
    /// Peer public key (base64)
    #[arg(long)]
    peer: Option<String>,
    
    /// Remove peer
    #[arg(long)]
    remove: bool,
    
    /// Peer endpoint
    #[arg(long)]
    endpoint: Option<SocketAddr>,
    
    /// Peer allowed IPs (comma-separated)
    #[arg(long = "allowed-ips")]
    allowed_ips: Option<String>,
    
    /// Persistent keepalive interval
    #[arg(long = "persistent-keepalive")]
    persistent_keepalive: Option<u16>,
    
    /// Preshared key file
    #[arg(long = "preshared-key")]
    preshared_key: Option<PathBuf>,
}

pub async fn run(args: SetArgs) -> anyhow::Result<()> {
    let conn = Connection::<Wireguard>::new_async().await?;
    
    // Set device parameters
    if args.listen_port.is_some() || args.private_key.is_some() || args.fwmark.is_some() {
        conn.set_device(&args.interface, |dev| {
            if let Some(port) = args.listen_port {
                dev.listen_port(port);
            }
            if let Some(ref path) = args.private_key {
                let key = read_key_file(path)?;
                dev.private_key(key);
            }
            if let Some(mark) = args.fwmark {
                dev.fwmark(mark);
            }
            dev
        }).await?;
    }
    
    // Set peer parameters
    if let Some(ref peer_key) = args.peer {
        let pubkey = base64_decode(peer_key)?;
        
        if args.remove {
            conn.remove_peer(&args.interface, pubkey).await?;
        } else {
            conn.set_peer(&args.interface, pubkey, |peer| {
                if let Some(ref endpoint) = args.endpoint {
                    peer.endpoint(*endpoint);
                }
                if let Some(ref allowed_ips) = args.allowed_ips {
                    for cidr in allowed_ips.split(',') {
                        let ip = parse_allowed_ip(cidr.trim())?;
                        peer.allowed_ip(ip);
                    }
                    peer.replace_allowed_ips();
                }
                if let Some(keepalive) = args.persistent_keepalive {
                    peer.persistent_keepalive(keepalive);
                }
                if let Some(ref path) = args.preshared_key {
                    let psk = read_key_file(path)?;
                    peer.preshared_key(psk);
                }
                peer
            }).await?;
        }
    }
    
    Ok(())
}
```

### keys.rs

```rust
use rand::RngCore;
use x25519_dalek::{StaticSecret, PublicKey};
use base64::{Engine, engine::general_purpose::STANDARD};
use std::io::{self, Read, Write};

pub fn genkey() -> anyhow::Result<()> {
    let mut key = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut key);
    
    // Clamp for Curve25519
    key[0] &= 248;
    key[31] &= 127;
    key[31] |= 64;
    
    println!("{}", STANDARD.encode(key));
    Ok(())
}

pub fn pubkey() -> anyhow::Result<()> {
    let mut input = String::new();
    io::stdin().read_to_string(&mut input)?;
    
    let private_bytes = STANDARD.decode(input.trim())?;
    if private_bytes.len() != 32 {
        anyhow::bail!("Invalid private key length");
    }
    
    let mut key = [0u8; 32];
    key.copy_from_slice(&private_bytes);
    
    let secret = StaticSecret::from(key);
    let public = PublicKey::from(&secret);
    
    println!("{}", STANDARD.encode(public.as_bytes()));
    Ok(())
}

pub fn genpsk() -> anyhow::Result<()> {
    let mut key = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut key);
    println!("{}", STANDARD.encode(key));
    Ok(())
}
```

## Output Formats

### Default Output (wg show)

```
interface: wg0
  public key: HIgo9xNzJMWLKASShiTqIybxZ0U3wGLiUeJ1PKf8ykw=
  private key: (hidden)
  listening port: 51820

peer: xTIBA5rboUvnH4htodjb60Y7YAf21J7YQMlNGC8HQ14=
  endpoint: 192.168.1.1:51820
  allowed ips: 10.0.0.0/24, 192.168.0.0/16
  latest handshake: 1 minute, 34 seconds ago
  transfer: 1.48 MiB received, 824.14 KiB sent
  persistent keepalive: every 25 seconds
```

### Dump Output (wg show wg0 dump)

Tab-separated, machine-readable:
```
wg0	HIgo9xNzJMWL...	(none)	51820	off
xTIBA5rboUvn...	(none)	192.168.1.1:51820	10.0.0.0/24,192.168.0.0/16	1234567890	1551024	843021	25
```

### Conf Output (wg showconf)

```ini
[Interface]
ListenPort = 51820
PrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=

[Peer]
PublicKey = xTIBA5rboUvnH4htodjb60Y7YAf21J7YQMlNGC8HQ14=
AllowedIPs = 10.0.0.0/24, 192.168.0.0/16
Endpoint = 192.168.1.1:51820
PersistentKeepalive = 25
```

## Testing

```bash
# Create WireGuard interface first
sudo ip link add wg0 type wireguard

# Generate keys
./target/release/wg genkey > privatekey
./target/release/wg pubkey < privatekey > publickey

# Configure interface
sudo ./target/release/wg set wg0 listen-port 51820 private-key ./privatekey

# Show interface
./target/release/wg show wg0
./target/release/wg showconf wg0

# Add peer
sudo ./target/release/wg set wg0 peer $(cat peer_pubkey) \
    endpoint 192.168.1.1:51820 \
    allowed-ips 10.0.0.0/24

# Cleanup
sudo ip link del wg0
```

## Estimated Effort

- Project setup: 1 hour
- show commands: 3-4 hours
- set commands: 3-4 hours
- Key generation: 1-2 hours
- showconf output: 1-2 hours
- Testing: 2 hours
- Total: 2-3 days

## Dependencies

- `nlink::netlink::Connection::<Wireguard>::new_async()`
- `nlink::netlink::genl::wireguard::{WgDevice, WgPeer, AllowedIp}`
- External: `base64`, `rand`, `x25519-dalek`

## Notes

- Key generation requires cryptographic crates (x25519-dalek)
- The `wg` tool from wireguard-tools is the reference implementation
- Private keys should never be shown by default (use "(hidden)")
- Consider adding `wg syncconf` for atomic configuration updates
