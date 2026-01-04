# Plan 023: Create `nlink-config` Binary

## Overview

Create a new binary for declarative network configuration, exposing the config module from Plan 012.

## Current State

- Library: Full config support in `netlink/config/` (2,219 lines)
- Binary: None exists
- Unique to nlink (similar to Netplan, but direct netlink)

## Target Commands

```bash
# Capture current network state
nlink-config capture
nlink-config capture --yaml > network.yaml
nlink-config capture --json > network.json
nlink-config capture --interface eth0  # single interface

# Validate a configuration file
nlink-config validate network.yaml
nlink-config validate network.json

# Show diff between current state and config file
nlink-config diff network.yaml
nlink-config diff network.yaml --color

# Apply configuration
nlink-config apply network.yaml
nlink-config apply network.yaml --dry-run
nlink-config apply network.yaml --force  # skip confirmation

# Generate example configuration
nlink-config example
nlink-config example --full
```

## Project Structure

```
bins/config/
├── Cargo.toml
└── src/
    ├── main.rs
    ├── capture.rs
    ├── validate.rs
    ├── diff.rs
    ├── apply.rs
    └── example.rs
```

### Cargo.toml

```toml
[package]
name = "nlink-config"
version.workspace = true
edition.workspace = true

[[bin]]
name = "nlink-config"
path = "src/main.rs"

[dependencies]
nlink = { path = "../../crates/nlink", features = ["output"] }
clap = { workspace = true }
tokio = { workspace = true }
serde = { workspace = true }
serde_json = { workspace = true }
serde_yaml = "0.9"
anyhow = "1.0"
```

## Implementation Details

### main.rs

```rust
use clap::{Parser, Subcommand};

mod capture;
mod validate;
mod diff;
mod apply;
mod example;

#[derive(Parser)]
#[command(name = "nlink-config", about = "Declarative network configuration")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Capture current network state
    Capture(capture::CaptureArgs),
    /// Validate a configuration file
    Validate(validate::ValidateArgs),
    /// Show differences between current state and config
    Diff(diff::DiffArgs),
    /// Apply a configuration file
    Apply(apply::ApplyArgs),
    /// Generate example configuration
    Example(example::ExampleArgs),
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    
    match cli.command {
        Command::Capture(args) => capture::run(args).await,
        Command::Validate(args) => validate::run(args),
        Command::Diff(args) => diff::run(args).await,
        Command::Apply(args) => apply::run(args).await,
        Command::Example(args) => example::run(args),
    }
}
```

### capture.rs

```rust
use clap::{Args, ValueEnum};
use nlink::netlink::{Connection, Route};
use nlink::netlink::config::NetworkConfig;

#[derive(Args)]
pub struct CaptureArgs {
    /// Output format
    #[arg(short, long, value_enum, default_value = "yaml")]
    format: OutputFormat,
    
    /// Capture only specific interface
    #[arg(short, long)]
    interface: Option<String>,
    
    /// Include TC configuration
    #[arg(long)]
    tc: bool,
    
    /// Include routing rules
    #[arg(long)]
    rules: bool,
    
    /// Include all details
    #[arg(long)]
    full: bool,
}

#[derive(Clone, ValueEnum)]
pub enum OutputFormat {
    Yaml,
    Json,
}

pub async fn run(args: CaptureArgs) -> anyhow::Result<()> {
    let conn = Connection::<Route>::new()?;
    
    let config = if let Some(ref iface) = args.interface {
        NetworkConfig::capture_interface(&conn, iface).await?
    } else {
        let mut opts = CaptureOptions::default();
        opts.include_tc = args.tc || args.full;
        opts.include_rules = args.rules || args.full;
        NetworkConfig::capture_with_options(&conn, opts).await?
    };
    
    match args.format {
        OutputFormat::Yaml => {
            println!("{}", serde_yaml::to_string(&config)?);
        }
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&config)?);
        }
    }
    
    Ok(())
}
```

### validate.rs

```rust
use clap::Args;
use nlink::netlink::config::NetworkConfig;
use std::path::PathBuf;

#[derive(Args)]
pub struct ValidateArgs {
    /// Configuration file to validate
    file: PathBuf,
}

pub fn run(args: ValidateArgs) -> anyhow::Result<()> {
    let content = std::fs::read_to_string(&args.file)?;
    
    let config: NetworkConfig = if args.file.extension().map(|e| e == "json").unwrap_or(false) {
        serde_json::from_str(&content)?
    } else {
        serde_yaml::from_str(&content)?
    };
    
    // Validate the configuration
    let errors = config.validate();
    
    if errors.is_empty() {
        println!("✓ Configuration is valid");
        println!();
        println!("Summary:");
        println!("  Links: {}", config.links.len());
        println!("  Addresses: {}", config.addresses.len());
        println!("  Routes: {}", config.routes.len());
        if !config.qdiscs.is_empty() {
            println!("  Qdiscs: {}", config.qdiscs.len());
        }
        Ok(())
    } else {
        println!("✗ Configuration has {} errors:", errors.len());
        println!();
        for error in &errors {
            println!("  - {}", error);
        }
        std::process::exit(1);
    }
}
```

### diff.rs

```rust
use clap::Args;
use nlink::netlink::{Connection, Route};
use nlink::netlink::config::{NetworkConfig, ConfigDiff, DiffOperation};
use std::path::PathBuf;

#[derive(Args)]
pub struct DiffArgs {
    /// Configuration file to compare
    file: PathBuf,
    
    /// Use color output
    #[arg(short, long)]
    color: bool,
    
    /// Show only summary
    #[arg(short, long)]
    summary: bool,
}

pub async fn run(args: DiffArgs) -> anyhow::Result<()> {
    let conn = Connection::<Route>::new()?;
    
    // Load desired configuration
    let content = std::fs::read_to_string(&args.file)?;
    let desired: NetworkConfig = if args.file.extension().map(|e| e == "json").unwrap_or(false) {
        serde_json::from_str(&content)?
    } else {
        serde_yaml::from_str(&content)?
    };
    
    // Capture current state
    let current = NetworkConfig::capture(&conn).await?;
    
    // Compute diff
    let diff = current.diff(&desired);
    
    if diff.is_empty() {
        println!("No changes needed - configuration matches current state");
        return Ok(());
    }
    
    if args.summary {
        println!("Changes: {} additions, {} removals, {} modifications",
            diff.additions().len(),
            diff.removals().len(),
            diff.modifications().len());
    } else {
        print_diff(&diff, args.color);
    }
    
    Ok(())
}

fn print_diff(diff: &ConfigDiff, color: bool) {
    let green = if color { "\x1b[32m" } else { "" };
    let red = if color { "\x1b[31m" } else { "" };
    let yellow = if color { "\x1b[33m" } else { "" };
    let reset = if color { "\x1b[0m" } else { "" };
    
    for op in diff.operations() {
        match op {
            DiffOperation::AddLink(link) => {
                println!("{}+ link: {}{}", green, link.name, reset);
            }
            DiffOperation::RemoveLink(name) => {
                println!("{}- link: {}{}", red, name, reset);
            }
            DiffOperation::ModifyLink(name, changes) => {
                println!("{}~ link: {} ({}){}", yellow, name, changes, reset);
            }
            DiffOperation::AddAddress(addr) => {
                println!("{}+ address: {} dev {}{}", green, addr.address, addr.dev, reset);
            }
            DiffOperation::RemoveAddress(addr) => {
                println!("{}- address: {} dev {}{}", red, addr.address, addr.dev, reset);
            }
            DiffOperation::AddRoute(route) => {
                println!("{}+ route: {}{}", green, route.destination, reset);
            }
            DiffOperation::RemoveRoute(route) => {
                println!("{}- route: {}{}", red, route.destination, reset);
            }
            // ... other operations
        }
    }
}
```

### apply.rs

```rust
use clap::Args;
use nlink::netlink::{Connection, Route};
use nlink::netlink::config::NetworkConfig;
use std::path::PathBuf;
use std::io::{self, Write};

#[derive(Args)]
pub struct ApplyArgs {
    /// Configuration file to apply
    file: PathBuf,
    
    /// Dry run (show what would be done)
    #[arg(long)]
    dry_run: bool,
    
    /// Skip confirmation prompt
    #[arg(short, long)]
    force: bool,
    
    /// Continue on errors
    #[arg(long)]
    continue_on_error: bool,
}

pub async fn run(args: ApplyArgs) -> anyhow::Result<()> {
    let conn = Connection::<Route>::new()?;
    
    // Load configuration
    let content = std::fs::read_to_string(&args.file)?;
    let desired: NetworkConfig = if args.file.extension().map(|e| e == "json").unwrap_or(false) {
        serde_json::from_str(&content)?
    } else {
        serde_yaml::from_str(&content)?
    };
    
    // Validate
    let errors = desired.validate();
    if !errors.is_empty() {
        eprintln!("Configuration validation failed:");
        for error in &errors {
            eprintln!("  - {}", error);
        }
        std::process::exit(1);
    }
    
    // Capture current and compute diff
    let current = NetworkConfig::capture(&conn).await?;
    let diff = current.diff(&desired);
    
    if diff.is_empty() {
        println!("No changes needed");
        return Ok(());
    }
    
    // Show what will be done
    println!("The following changes will be applied:");
    println!();
    print_diff_summary(&diff);
    println!();
    
    if args.dry_run {
        println!("Dry run - no changes made");
        return Ok(());
    }
    
    // Confirm
    if !args.force {
        print!("Apply these changes? [y/N] ");
        io::stdout().flush()?;
        
        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        
        if !input.trim().eq_ignore_ascii_case("y") {
            println!("Aborted");
            return Ok(());
        }
    }
    
    // Apply changes
    println!("Applying configuration...");
    
    let result = if args.continue_on_error {
        diff.apply_continue_on_error(&conn).await
    } else {
        diff.apply(&conn).await.map(|_| vec![])
    };
    
    match result {
        Ok(errors) if errors.is_empty() => {
            println!("✓ Configuration applied successfully");
        }
        Ok(errors) => {
            println!("Configuration applied with {} errors:", errors.len());
            for error in &errors {
                eprintln!("  - {}", error);
            }
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("✗ Failed to apply configuration: {}", e);
            std::process::exit(1);
        }
    }
    
    Ok(())
}
```

### example.rs

```rust
use clap::Args;

#[derive(Args)]
pub struct ExampleArgs {
    /// Show full example with all features
    #[arg(long)]
    full: bool,
    
    /// Output format
    #[arg(short, long, value_enum, default_value = "yaml")]
    format: OutputFormat,
}

pub fn run(args: ExampleArgs) -> anyhow::Result<()> {
    let example = if args.full {
        FULL_EXAMPLE
    } else {
        BASIC_EXAMPLE
    };
    
    println!("{}", example);
    Ok(())
}

const BASIC_EXAMPLE: &str = r#"# Basic network configuration
links:
  - name: br0
    kind: bridge
    state: up
  
  - name: veth0
    kind: veth
    peer: veth1
    master: br0
    state: up

addresses:
  - dev: br0
    address: 10.0.0.1/24

routes:
  - destination: 10.1.0.0/16
    gateway: 10.0.0.254
    dev: br0
"#;

const FULL_EXAMPLE: &str = r#"# Full network configuration example
links:
  # Bridge with VLAN filtering
  - name: br0
    kind: bridge
    state: up
    mtu: 9000
    options:
      vlan_filtering: true
      stp_state: 1
  
  # Veth pair
  - name: veth0
    kind: veth
    peer: veth1
    master: br0
    state: up
  
  # VXLAN tunnel
  - name: vxlan100
    kind: vxlan
    state: up
    options:
      vni: 100
      local: 192.168.1.1
      remote: 192.168.1.2
      port: 4789
  
  # Dummy for routing
  - name: dummy0
    kind: dummy
    state: up

addresses:
  - dev: br0
    address: 10.0.0.1/24
    label: br0:mgmt
  
  - dev: dummy0
    address: 192.168.100.1/32

routes:
  # Default route
  - destination: default
    gateway: 10.0.0.254
    dev: br0
    metric: 100
  
  # Static route
  - destination: 10.1.0.0/16
    gateway: 10.0.0.1
    dev: br0
  
  # Blackhole
  - destination: 10.99.0.0/16
    type: blackhole

rules:
  - priority: 100
    from: 10.0.0.0/8
    table: 100
  
  - priority: 200
    fwmark: 0x100
    table: 200

qdiscs:
  - dev: veth0
    parent: root
    kind: htb
    handle: "1:"
    options:
      default: 0x30

classes:
  - dev: veth0
    parent: "1:0"
    classid: "1:1"
    kind: htb
    options:
      rate: 1gbit
      ceil: 1gbit

filters:
  - dev: veth0
    parent: "1:"
    kind: flower
    options:
      ip_proto: tcp
      dst_port: 80
      classid: "1:10"
"#;
```

## Configuration File Format

### YAML Format

```yaml
# Network configuration
links:
  - name: br0
    kind: bridge
    state: up
    mtu: 1500
    options:
      vlan_filtering: true

  - name: veth0
    kind: veth
    peer: veth1
    master: br0

addresses:
  - dev: br0
    address: 10.0.0.1/24
    broadcast: 10.0.0.255
    label: br0:primary

routes:
  - destination: 10.1.0.0/16
    gateway: 10.0.0.254
    dev: br0
    metric: 100
    table: main

rules:
  - priority: 100
    from: 10.0.0.0/8
    table: 100

qdiscs:
  - dev: eth0
    parent: root
    kind: htb
    handle: "1:"
```

### JSON Format

```json
{
  "links": [
    {
      "name": "br0",
      "kind": "bridge",
      "state": "up"
    }
  ],
  "addresses": [
    {
      "dev": "br0",
      "address": "10.0.0.1/24"
    }
  ],
  "routes": [
    {
      "destination": "10.1.0.0/16",
      "gateway": "10.0.0.254"
    }
  ]
}
```

## Testing

```bash
# Capture current state
./target/release/nlink-config capture > current.yaml

# Validate a config
./target/release/nlink-config validate network.yaml

# Show diff
./target/release/nlink-config diff network.yaml --color

# Dry run
sudo ./target/release/nlink-config apply network.yaml --dry-run

# Apply
sudo ./target/release/nlink-config apply network.yaml

# Generate example
./target/release/nlink-config example --full
```

## Estimated Effort

- Project setup: 1 hour
- capture command: 2 hours
- validate command: 1-2 hours
- diff command: 2-3 hours
- apply command: 3-4 hours
- example command: 1 hour
- Testing: 2 hours
- Total: 2 days

## Dependencies

- `nlink::netlink::config::{NetworkConfig, ConfigDiff, CaptureOptions}`
- `serde`, `serde_yaml`, `serde_json`

## Notes

- Configuration format is similar to Netplan but uses netlink directly
- Apply operations are ordered: links first, then addresses, then routes
- Rollback on failure is not implemented (future enhancement)
- Consider adding `nlink-config watch` for config file monitoring
