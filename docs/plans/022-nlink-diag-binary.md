# Plan 022: Create `nlink-diag` Binary

## Overview

Create a new binary for network diagnostics, exposing the diagnostics module from Plan 014.

## Current State

- Library: Full diagnostics support in `netlink/diagnostics.rs` (1,294 lines)
- Binary: None exists
- Unique to nlink (no iproute2 equivalent)

## Target Commands

```bash
# Scan a subnet for active hosts
nlink-diag scan 192.168.1.0/24
nlink-diag scan 192.168.1.0/24 --ports 22,80,443
nlink-diag scan 192.168.1.0/24 --resolve
nlink-diag scan 192.168.1.0/24 --timeout 2000 --concurrent 100

# Scan a range
nlink-diag scan 192.168.1.1-192.168.1.50

# Check connectivity to a destination
nlink-diag check 8.8.8.8
nlink-diag check 8.8.8.8 --method icmp
nlink-diag check google.com --method tcp --port 443
nlink-diag check https://google.com --method http

# Detect bottlenecks on a path
nlink-diag bottleneck 10.0.0.1
nlink-diag bottleneck 10.0.0.1 --samples 10

# Trace path with diagnostics
nlink-diag path 8.8.8.8
nlink-diag path 8.8.8.8 --mtu-discovery

# Interface diagnostics
nlink-diag interface eth0
nlink-diag interface eth0 --watch
```

## Project Structure

```
bins/diag/
├── Cargo.toml
└── src/
    ├── main.rs
    ├── scan.rs
    ├── check.rs
    ├── bottleneck.rs
    ├── path.rs
    ├── interface.rs
    └── output.rs
```

### Cargo.toml

```toml
[package]
name = "nlink-diag"
version.workspace = true
edition.workspace = true

[[bin]]
name = "nlink-diag"
path = "src/main.rs"

[dependencies]
nlink = { path = "../../crates/nlink", features = ["output"] }
clap = { workspace = true }
tokio = { workspace = true }
serde_json = { workspace = true }
```

## Implementation Details

### main.rs

```rust
use clap::{Parser, Subcommand};

mod scan;
mod check;
mod bottleneck;
mod path;
mod interface;
mod output;

#[derive(Parser)]
#[command(name = "nlink-diag", about = "Network diagnostics utility")]
struct Cli {
    /// Output JSON
    #[arg(short, long, global = true)]
    json: bool,
    
    /// Verbose output
    #[arg(short, long, global = true)]
    verbose: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Scan a subnet for active hosts
    Scan(scan::ScanArgs),
    /// Check connectivity to a destination
    Check(check::CheckArgs),
    /// Detect bottlenecks on a network path
    Bottleneck(bottleneck::BottleneckArgs),
    /// Trace path with diagnostics
    Path(path::PathArgs),
    /// Interface diagnostics
    Interface(interface::InterfaceArgs),
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    
    match cli.command {
        Command::Scan(args) => scan::run(args, cli.json, cli.verbose).await,
        Command::Check(args) => check::run(args, cli.json).await,
        Command::Bottleneck(args) => bottleneck::run(args, cli.json).await,
        Command::Path(args) => path::run(args, cli.json).await,
        Command::Interface(args) => interface::run(args, cli.json).await,
    }
}
```

### scan.rs

```rust
use clap::Args;
use nlink::netlink::diagnostics::{NetworkScanner, ScanOptions, ScanResult};
use std::net::IpAddr;

#[derive(Args)]
pub struct ScanArgs {
    /// Target subnet (CIDR) or range (start-end)
    target: String,
    
    /// Ports to check (comma-separated)
    #[arg(short, long, value_delimiter = ',')]
    ports: Vec<u16>,
    
    /// Resolve hostnames
    #[arg(short, long)]
    resolve: bool,
    
    /// Timeout in milliseconds
    #[arg(short, long, default_value = "1000")]
    timeout: u64,
    
    /// Concurrent scans
    #[arg(short, long, default_value = "50")]
    concurrent: usize,
    
    /// Show only active hosts
    #[arg(long)]
    active_only: bool,
}

pub async fn run(args: ScanArgs, json: bool, verbose: bool) -> anyhow::Result<()> {
    let scanner = NetworkScanner::new();
    
    let options = ScanOptions {
        timeout_ms: args.timeout,
        concurrent: args.concurrent,
        resolve_hostnames: args.resolve,
        check_ports: args.ports.clone(),
    };
    
    if verbose {
        eprintln!("Scanning {} with timeout {}ms, {} concurrent...", 
            args.target, args.timeout, args.concurrent);
    }
    
    let results = if args.target.contains('-') {
        // Range scan
        let parts: Vec<&str> = args.target.split('-').collect();
        let start: IpAddr = parts[0].parse()?;
        let end: IpAddr = parts[1].parse()?;
        scanner.scan_range(start, end, options).await?
    } else {
        // Subnet scan
        scanner.scan(&args.target, options).await?
    };
    
    if json {
        println!("{}", serde_json::to_string_pretty(&results)?);
    } else {
        print_scan_results(&results, args.active_only);
    }
    
    Ok(())
}

fn print_scan_results(results: &[ScanResult], active_only: bool) {
    let active: Vec<_> = results.iter().filter(|r| r.is_active).collect();
    
    println!("Discovered {} active hosts:", active.len());
    println!();
    
    for result in results {
        if active_only && !result.is_active {
            continue;
        }
        
        print!("{}", result.ip);
        
        if let Some(ref hostname) = result.hostname {
            print!(" ({})", hostname);
        }
        
        if let Some(latency) = result.latency {
            print!(" - {:?}", latency);
        }
        
        if !result.open_ports.is_empty() {
            print!(" - ports: {:?}", result.open_ports);
        }
        
        println!();
    }
}
```

### check.rs

```rust
use clap::{Args, ValueEnum};
use nlink::netlink::diagnostics::{ConnectivityChecker, ConnectivityMethod, ConnectivityResult};

#[derive(Args)]
pub struct CheckArgs {
    /// Destination (IP, hostname, or URL)
    destination: String,
    
    /// Check method
    #[arg(short, long, value_enum, default_value = "icmp")]
    method: CheckMethod,
    
    /// Port for TCP/HTTP checks
    #[arg(short, long)]
    port: Option<u16>,
    
    /// Timeout in milliseconds
    #[arg(short, long, default_value = "5000")]
    timeout: u64,
    
    /// Number of attempts
    #[arg(short = 'c', long, default_value = "3")]
    count: usize,
}

#[derive(Clone, ValueEnum)]
pub enum CheckMethod {
    Icmp,
    Tcp,
    Http,
    Https,
}

pub async fn run(args: CheckArgs, json: bool) -> anyhow::Result<()> {
    let checker = ConnectivityChecker::new();
    
    let method = match args.method {
        CheckMethod::Icmp => ConnectivityMethod::Icmp,
        CheckMethod::Tcp => ConnectivityMethod::Tcp(args.port.unwrap_or(80)),
        CheckMethod::Http => ConnectivityMethod::Http,
        CheckMethod::Https => ConnectivityMethod::Https,
    };
    
    let result = checker.check(&args.destination, method).await?;
    
    if json {
        println!("{}", serde_json::to_string_pretty(&result)?);
    } else {
        print_check_result(&result);
    }
    
    Ok(())
}

fn print_check_result(result: &ConnectivityResult) {
    if result.reachable {
        println!("✓ {} is reachable", result.destination);
        if let Some(latency) = result.latency {
            println!("  Latency: {:?}", latency);
        }
        if let Some(hops) = result.hops {
            println!("  Hops: {}", hops);
        }
    } else {
        println!("✗ {} is not reachable", result.destination);
        if let Some(ref error) = result.error {
            println!("  Error: {}", error);
        }
    }
}
```

### bottleneck.rs

```rust
use clap::Args;
use nlink::netlink::diagnostics::{BottleneckDetector, BottleneckReport, Issue, Severity};

#[derive(Args)]
pub struct BottleneckArgs {
    /// Destination to analyze
    destination: String,
    
    /// Number of samples
    #[arg(short, long, default_value = "5")]
    samples: usize,
    
    /// Include recommendations
    #[arg(short, long)]
    recommendations: bool,
}

pub async fn run(args: BottleneckArgs, json: bool) -> anyhow::Result<()> {
    let detector = BottleneckDetector::new();
    
    eprintln!("Analyzing path to {}...", args.destination);
    
    let report = detector.detect(&args.destination).await?;
    
    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        print_bottleneck_report(&report, args.recommendations);
    }
    
    Ok(())
}

fn print_bottleneck_report(report: &BottleneckReport, show_recommendations: bool) {
    println!("Bottleneck Analysis Report");
    println!("==========================");
    println!();
    
    if report.issues.is_empty() {
        println!("✓ No significant bottlenecks detected");
    } else {
        println!("Found {} issues:", report.issues.len());
        println!();
        
        for issue in &report.issues {
            let icon = match issue.severity {
                Severity::Critical => "🔴",
                Severity::Warning => "🟡", 
                Severity::Info => "🔵",
            };
            
            println!("{} [{}] {}", icon, issue.location, issue.description);
            
            if show_recommendations {
                for rec in &issue.recommendations {
                    println!("   → {}", rec);
                }
            }
            println!();
        }
    }
    
    if let Some(ref summary) = report.summary {
        println!("Summary: {}", summary);
    }
}
```

### interface.rs

```rust
use clap::Args;
use nlink::netlink::{Connection, Route};
use std::time::Duration;

#[derive(Args)]
pub struct InterfaceArgs {
    /// Interface name
    interface: String,
    
    /// Watch mode (continuous)
    #[arg(short, long)]
    watch: bool,
    
    /// Watch interval in seconds
    #[arg(short, long, default_value = "1")]
    interval: u64,
    
    /// Include TC statistics
    #[arg(long)]
    tc: bool,
}

pub async fn run(args: InterfaceArgs, json: bool) -> anyhow::Result<()> {
    let conn = Connection::<Route>::new()?;
    
    loop {
        let link = conn.get_link_by_name(&args.interface).await?
            .ok_or_else(|| anyhow::anyhow!("Interface not found: {}", args.interface))?;
        
        if json {
            println!("{}", serde_json::to_string_pretty(&link)?);
        } else {
            print_interface_stats(&link);
            
            if args.tc {
                let qdiscs = conn.get_qdiscs_for(&args.interface).await?;
                print_tc_stats(&qdiscs);
            }
        }
        
        if !args.watch {
            break;
        }
        
        tokio::time::sleep(Duration::from_secs(args.interval)).await;
        print!("\x1B[2J\x1B[1;1H"); // Clear screen
    }
    
    Ok(())
}

fn print_interface_stats(link: &LinkMessage) {
    println!("Interface: {} (index {})", link.name_or("?"), link.ifindex());
    println!("State: {}", if link.is_up() { "UP" } else { "DOWN" });
    println!("MTU: {}", link.mtu().unwrap_or(0));
    println!();
    
    if let Some(stats) = link.stats() {
        println!("Statistics:");
        println!("  RX: {} packets, {} bytes", stats.rx_packets(), stats.rx_bytes());
        println!("  TX: {} packets, {} bytes", stats.tx_packets(), stats.tx_bytes());
        println!("  Errors: {} RX, {} TX", stats.rx_errors(), stats.tx_errors());
        println!("  Dropped: {} RX, {} TX", stats.rx_dropped(), stats.tx_dropped());
    }
}
```

## Output Formats

### Scan Text Output

```
Scanning 192.168.1.0/24 with timeout 1000ms, 50 concurrent...

Discovered 5 active hosts:

192.168.1.1 (router.local) - 1.2ms - ports: [22, 80]
192.168.1.10 (desktop.local) - 0.5ms
192.168.1.20 (server.local) - 0.8ms - ports: [22, 80, 443]
192.168.1.100 - 2.1ms
192.168.1.254 (gateway.local) - 1.0ms
```

### Scan JSON Output

```json
[
  {
    "ip": "192.168.1.1",
    "hostname": "router.local",
    "is_active": true,
    "latency_ms": 1.2,
    "open_ports": [22, 80]
  }
]
```

### Check Text Output

```
✓ 8.8.8.8 is reachable
  Latency: 15.3ms
  Hops: 12
```

### Bottleneck Text Output

```
Bottleneck Analysis Report
==========================

Found 2 issues:

🟡 [hop 5] High latency detected (45ms)
   → Consider checking link quality
   → Verify no congestion on this segment

🔴 [hop 8] Packet loss detected (5%)
   → Check for hardware issues
   → Verify QoS configuration

Summary: Path has moderate issues affecting performance
```

## Testing

```bash
# Scan local network
sudo ./target/release/nlink-diag scan 192.168.1.0/24 --ports 22,80,443

# Check connectivity
./target/release/nlink-diag check 8.8.8.8
./target/release/nlink-diag check google.com --method tcp --port 443

# Bottleneck detection
./target/release/nlink-diag bottleneck 8.8.8.8 --recommendations

# Interface diagnostics
./target/release/nlink-diag interface eth0 --tc
./target/release/nlink-diag interface eth0 --watch
```

## Estimated Effort

- Project setup: 1 hour
- scan command: 2-3 hours
- check command: 2 hours
- bottleneck command: 2-3 hours
- interface command: 2 hours
- Testing: 2 hours
- Total: 2 days

## Dependencies

- `nlink::netlink::diagnostics::{NetworkScanner, ConnectivityChecker, BottleneckDetector}`
- `nlink::netlink::Connection::<Route>`

## Notes

- Some operations (ICMP ping, raw sockets) may require elevated privileges
- The scan command should be used responsibly (rate limiting, permission)
- Consider adding progress indicators for long-running scans
