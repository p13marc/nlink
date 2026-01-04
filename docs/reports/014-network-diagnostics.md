# Plan 014: Network Diagnostics - Completion Report

## Overview

Implemented a comprehensive network diagnostics module that combines data from multiple sources (links, TC, routes, addresses) to provide actionable insights about network issues.

## Implementation Summary

### Core Types

Created `crates/nlink/src/netlink/diagnostics.rs` (~1250 lines) with:

**Main Types:**
- `Diagnostics` - Main diagnostics runner with scan, connectivity check, and bottleneck detection
- `DiagnosticReport` - Complete scan result containing all interfaces, routes, and issues
- `InterfaceDiag` - Per-interface diagnostics with stats, rates, TC info, and issues
- `TcDiag` - Traffic control diagnostics (qdisc type, drops, overlimits, backlog, rates)
- `RouteDiag` - Route summary (IPv4/IPv6 counts, default routes, gateways)
- `ConnectivityReport` - Connectivity check result with route info and reachability
- `Bottleneck` - Bottleneck analysis result with location, type, and recommendations

**Issue Types:**
- `Issue` - Detected problem with severity, category, message, and details
- `Severity` - Info, Warning, Error, Critical (with ordering)
- `IssueCategory` - LinkDown, NoCarrier, HighPacketLoss, LinkErrors, QdiscDrops, BufferOverflow, NoRoute, Unreachable, HighLatency, NoAddress, NoDefaultRoute, MtuIssue, DuplexMismatch
- `BottleneckType` - QdiscDrops, InterfaceDrops, BufferFull, RateLimited, HardwareErrors

**Configuration:**
- `DiagnosticsConfig` - Configurable thresholds for issue detection:
  - `packet_loss_threshold` - Default 1%
  - `error_rate_threshold` - Default 0.1%
  - `qdisc_drop_threshold` - Default 1%
  - `backlog_threshold` - Default 100KB
  - `qlen_threshold` - Default 1000 packets
  - `skip_loopback` - Default true
  - `skip_down` - Default false

**Streaming:**
- `IssueStream` - Real-time issue monitoring via Stream API

### API Methods

```rust
impl Diagnostics {
    // Create with default or custom configuration
    pub fn new(conn: Connection<Route>) -> Self;
    pub fn with_config(conn: Connection<Route>, config: DiagnosticsConfig) -> Self;
    
    // Full diagnostic scan
    pub async fn scan(&self) -> Result<DiagnosticReport>;
    
    // Scan specific interface
    pub async fn scan_interface(&self, dev: &str) -> Result<InterfaceDiag>;
    
    // Check connectivity to destination
    pub async fn check_connectivity(&self, dest: IpAddr) -> Result<ConnectivityReport>;
    
    // Find worst bottleneck
    pub async fn find_bottleneck(&self) -> Result<Option<Bottleneck>>;
    
    // Real-time issue monitoring
    pub async fn watch(&self) -> Result<IssueStream>;
}
```

### Issue Detection Rules

The module detects:

1. **Link Issues:**
   - Interface down (LinkDown)
   - No carrier detected (NoCarrier)
   - High packet loss rate > threshold (HighPacketLoss)
   - RX/TX errors > threshold (LinkErrors)
   - No IP addresses configured (NoAddress)

2. **TC Issues:**
   - Qdisc dropping packets > threshold (QdiscDrops)
   - High backlog > threshold (BufferOverflow)

3. **Route Issues:**
   - No route to destination (NoRoute)
   - No default route configured (NoDefaultRoute)
   - Gateway unreachable based on neighbor cache (Unreachable)

4. **Bottleneck Detection:**
   - Analyzes all interfaces and qdiscs
   - Calculates drop rates and error rates
   - Returns worst bottleneck with recommendations

### Rate Calculation

The module tracks previous statistics for rate calculation:
- `LinkRates` - rx_bps, tx_bps, rx_pps, tx_pps, sample_duration_ms
- Uses `prev_stats` HashMap to store previous samples per interface
- Calculates deltas on subsequent scans

## Testing

Created `crates/nlink/tests/integration/diagnostics.rs` (~320 lines) with:

**Unit Tests:**
- `test_severity_ordering` - Verify severity comparison
- `test_severity_display` - Verify display formatting
- `test_issue_category_display` - Verify category formatting
- `test_link_rates` - Verify rate calculations
- `test_config_defaults` - Verify default configuration
- `test_bottleneck_type_display` - Verify bottleneck type formatting

**Integration Tests (require root):**
- `test_diagnostics_scan` - Full scan with dummy interface
- `test_diagnostics_scan_interface` - Single interface scan
- `test_diagnostics_scan_interface_not_found` - Error on missing interface
- `test_diagnostics_check_connectivity_no_route` - NoRoute detection
- `test_diagnostics_check_connectivity_with_route` - Route lookup
- `test_diagnostics_find_bottleneck` - Bottleneck analysis
- `test_diagnostics_with_tc` - TC info collection
- `test_diagnostics_link_down_detection` - LinkDown issue detection
- `test_diagnostics_no_address_detection` - NoAddress issue detection
- `test_diagnostics_route_summary` - Route statistics
- `test_diagnostics_custom_config` - Custom thresholds
- `test_diagnostics_skip_loopback` - Loopback filtering

## Files Changed

### New Files
- `crates/nlink/src/netlink/diagnostics.rs` - Main diagnostics module (~1250 lines)
- `crates/nlink/tests/integration/diagnostics.rs` - Integration tests (~320 lines)

### Modified Files
- `crates/nlink/src/netlink/mod.rs` - Added `pub mod diagnostics`
- `crates/nlink/tests/integration.rs` - Added diagnostics test module
- `CLAUDE.md` - Added diagnostics documentation and usage examples

## Usage Example

```rust
use nlink::netlink::{Connection, Route};
use nlink::netlink::diagnostics::{Diagnostics, DiagnosticsConfig};

let conn = Connection::<Route>::new()?;
let diag = Diagnostics::new(conn);

// Full scan
let report = diag.scan().await?;
for issue in &report.issues {
    println!("[{:?}] {}: {}", issue.severity, issue.category, issue.message);
}

// Connectivity check
let report = diag.check_connectivity("8.8.8.8".parse()?).await?;
if !report.issues.is_empty() {
    for issue in &report.issues {
        println!("  - {}", issue.message);
    }
}

// Find bottleneck
if let Some(b) = diag.find_bottleneck().await? {
    println!("Bottleneck: {} - {}", b.location, b.recommendation);
}

// Real-time monitoring
use tokio_stream::StreamExt;
let mut issues = diag.watch().await?;
while let Some(issue) = issues.next().await {
    println!("[{:?}] {}", issue?.severity, issue?.message);
}
```

## Verification

```bash
# Build passes
cargo build -p nlink

# Clippy passes
cargo clippy -p nlink

# Tests compile
cargo test --test integration --no-run
```

## Summary

- Implemented full diagnostic API as specified in Plan 014
- All core types: DiagnosticReport, InterfaceDiag, TcDiag, Issue, Severity, etc.
- Interface scanning with stats and rate calculation
- TC diagnostic collection
- Connectivity checking with route lookup and gateway reachability
- Bottleneck detection with recommendations
- Real-time monitoring via Stream API
- Configurable thresholds for issue detection
- Comprehensive test coverage
- Documentation updated in CLAUDE.md

Total lines of code: ~1570 (diagnostics.rs + tests)
