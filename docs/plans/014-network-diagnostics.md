# Plan 014: Network Diagnostics

## Overview

Add a diagnostic API that combines data from multiple sources (links, TC, routes, sockets) to provide actionable insights about network issues.

## Motivation

Troubleshooting network issues requires correlating data from:
- Link statistics (errors, drops)
- TC statistics (qdisc drops, overlimits)
- Route lookups
- Socket states
- Event history

A unified diagnostic API would simplify troubleshooting.

## Design

### API Design

```rust
/// Network diagnostic report.
#[derive(Debug)]
pub struct DiagnosticReport {
    pub timestamp: Instant,
    pub interfaces: Vec<InterfaceDiag>,
    pub routes: RouteDiag,
    pub issues: Vec<Issue>,
}

#[derive(Debug)]
pub struct InterfaceDiag {
    pub name: String,
    pub state: OperState,
    pub stats: LinkStats,
    pub rates: LinkRates,
    pub tc: Option<TcDiag>,
    pub issues: Vec<Issue>,
}

#[derive(Debug)]
pub struct TcDiag {
    pub qdisc: String,
    pub drops: u64,
    pub overlimits: u64,
    pub backlog: u32,
    pub rate_bps: u64,
}

#[derive(Debug)]
pub struct Issue {
    pub severity: Severity,
    pub category: IssueCategory,
    pub message: String,
    pub details: Option<String>,
}

#[derive(Debug)]
pub enum Severity {
    Info,
    Warning,
    Error,
    Critical,
}

#[derive(Debug)]
pub enum IssueCategory {
    LinkDown,
    HighPacketLoss,
    QdiscDrops,
    BufferOverflow,
    NoRoute,
    Unreachable,
    HighLatency,
}

/// Network diagnostics runner.
pub struct Diagnostics {
    conn: Connection<Route>,
}

impl Diagnostics {
    pub fn new(conn: Connection<Route>) -> Self;
    
    /// Run full diagnostic scan.
    pub async fn scan(&self) -> Result<DiagnosticReport>;
    
    /// Diagnose specific interface.
    pub async fn scan_interface(&self, dev: &str) -> Result<InterfaceDiag>;
    
    /// Check connectivity to destination.
    pub async fn check_connectivity(&self, dest: IpAddr) -> Result<ConnectivityReport>;
    
    /// Watch for issues in real-time.
    pub async fn watch(&self) -> impl Stream<Item = Issue>;
    
    /// Get bottleneck analysis.
    pub async fn find_bottleneck(&self) -> Result<Option<Bottleneck>>;
}

#[derive(Debug)]
pub struct ConnectivityReport {
    pub destination: IpAddr,
    pub route: Option<RouteInfo>,
    pub gateway_reachable: bool,
    pub issues: Vec<Issue>,
}

#[derive(Debug)]
pub struct Bottleneck {
    pub location: String,  // e.g., "eth0 egress qdisc"
    pub bottleneck_type: BottleneckType,
    pub current_rate: u64,
    pub drop_rate: f64,
    pub recommendation: String,
}
```

### Usage Example

```rust
use nlink::netlink::{Connection, Route};
use nlink::diagnostics::Diagnostics;

let conn = Connection::<Route>::new()?;
let diag = Diagnostics::new(conn);

// Full scan
let report = diag.scan().await?;
for issue in &report.issues {
    println!("[{:?}] {}: {}", issue.severity, issue.category, issue.message);
}

// Interface diagnostics
let eth0 = diag.scan_interface("eth0").await?;
println!("eth0: {} bps, {} drops", eth0.rates.tx_bps, eth0.stats.tx_dropped);
if let Some(tc) = &eth0.tc {
    println!("  TC: {} ({} drops)", tc.qdisc, tc.drops);
}

// Connectivity check
let report = diag.check_connectivity("8.8.8.8".parse()?).await?;
if !report.issues.is_empty() {
    println!("Connectivity issues:");
    for issue in &report.issues {
        println!("  - {}", issue.message);
    }
}

// Find bottleneck
if let Some(bottleneck) = diag.find_bottleneck().await? {
    println!("Bottleneck: {}", bottleneck.location);
    println!("  Drop rate: {:.2}%", bottleneck.drop_rate * 100.0);
    println!("  Recommendation: {}", bottleneck.recommendation);
}

// Real-time monitoring
let mut issues = diag.watch().await;
while let Some(issue) = issues.next().await {
    println!("[{:?}] {}", issue.severity, issue.message);
}
```

### Issue Detection Rules

```rust
fn detect_issues(stats: &LinkStats, prev_stats: &LinkStats) -> Vec<Issue> {
    let mut issues = Vec::new();
    
    // High packet loss
    let total = stats.rx_packets + stats.tx_packets;
    let dropped = stats.rx_dropped + stats.tx_dropped;
    if total > 0 && dropped as f64 / total as f64 > 0.01 {
        issues.push(Issue {
            severity: Severity::Warning,
            category: IssueCategory::HighPacketLoss,
            message: format!("{:.2}% packet loss", dropped as f64 / total as f64 * 100.0),
            details: None,
        });
    }
    
    // RX errors
    if stats.rx_errors > prev_stats.rx_errors {
        issues.push(Issue {
            severity: Severity::Warning,
            category: IssueCategory::LinkDown,
            message: format!("{} new RX errors", stats.rx_errors - prev_stats.rx_errors),
            details: Some("Check cable/PHY".into()),
        });
    }
    
    issues
}
```

## Implementation Steps

1. Create `diagnostics` module with core types
2. Implement interface scanning
3. Implement issue detection rules
4. Add TC diagnostic collection
5. Add connectivity checking
6. Add bottleneck detection
7. Add real-time monitoring

## Effort Estimate

- Core types: ~2 hours
- Interface scanning: ~3 hours
- Issue detection: ~4 hours
- TC diagnostics: ~2 hours
- Connectivity check: ~2 hours
- Bottleneck detection: ~3 hours
- Real-time monitoring: ~2 hours
- **Total: ~18 hours**
