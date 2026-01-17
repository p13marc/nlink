//! Network diagnostics module.
//!
//! Provides a unified diagnostic API that combines data from multiple sources
//! (links, TC, routes, addresses) to provide actionable insights about network issues.
//!
//! # Quick Start
//!
//! ```ignore
//! use nlink::netlink::{Connection, Route};
//! use nlink::netlink::diagnostics::Diagnostics;
//!
//! let conn = Connection::<Route>::new()?;
//! let diag = Diagnostics::new(conn);
//!
//! // Full scan
//! let report = diag.scan().await?;
//! for issue in &report.issues {
//!     println!("[{:?}] {}: {}", issue.severity, issue.category, issue.message);
//! }
//!
//! // Interface diagnostics
//! let eth0 = diag.scan_interface("eth0").await?;
//! println!("eth0: {} bps, {} drops", eth0.rates.tx_bps, eth0.stats.tx_dropped());
//!
//! // Connectivity check
//! let report = diag.check_connectivity("8.8.8.8".parse()?).await?;
//! if !report.issues.is_empty() {
//!     for issue in &report.issues {
//!         println!("  - {}", issue.message);
//!     }
//! }
//!
//! // Find bottleneck
//! if let Some(bottleneck) = diag.find_bottleneck().await? {
//!     println!("Bottleneck: {}", bottleneck.location);
//!     println!("  Drop rate: {:.2}%", bottleneck.drop_rate * 100.0);
//!     println!("  Recommendation: {}", bottleneck.recommendation);
//! }
//! ```
//!
//! # Real-time Monitoring
//!
//! ```ignore
//! use tokio_stream::StreamExt;
//!
//! let mut issues = diag.watch().await?;
//! while let Some(issue) = issues.next().await {
//!     let issue = issue?;
//!     println!("[{:?}] {}", issue.severity, issue.message);
//! }
//! ```

use std::collections::HashMap;
use std::fmt;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Instant;

use tokio::sync::Mutex;
use tokio_stream::Stream;

use crate::netlink::connection::Connection;
use crate::netlink::error::Result;
use crate::netlink::events::NetworkEvent;
use crate::netlink::messages::{AddressMessage, LinkMessage, LinkStats, RouteMessage, TcMessage};
use crate::netlink::protocol::Route;
use crate::netlink::stream::OwnedEventStream;
use crate::netlink::types::link::OperState;
use crate::netlink::types::neigh::NeighborState;

// ============================================================================
// Core Types
// ============================================================================

/// Network diagnostic report containing all collected information.
#[derive(Debug, Clone)]
pub struct DiagnosticReport {
    /// When the report was generated.
    pub timestamp: Instant,
    /// Interface diagnostics.
    pub interfaces: Vec<InterfaceDiag>,
    /// Route diagnostics.
    pub routes: RouteDiag,
    /// All detected issues across the system.
    pub issues: Vec<Issue>,
}

/// Diagnostics for a single network interface.
#[derive(Debug, Clone)]
pub struct InterfaceDiag {
    /// Interface name.
    pub name: String,
    /// Interface index.
    pub ifindex: u32,
    /// Operational state.
    pub state: OperState,
    /// Interface flags (IFF_UP, IFF_RUNNING, etc.).
    pub flags: u32,
    /// MTU.
    pub mtu: Option<u32>,
    /// Link statistics.
    pub stats: LinkStats,
    /// Calculated rates (requires previous sample).
    pub rates: LinkRates,
    /// Traffic control diagnostics.
    pub tc: Option<TcDiag>,
    /// Issues detected for this interface.
    pub issues: Vec<Issue>,
}

/// Link transfer rates calculated from statistics deltas.
#[derive(Debug, Clone, Copy, Default)]
pub struct LinkRates {
    /// Receive bytes per second.
    pub rx_bps: u64,
    /// Transmit bytes per second.
    pub tx_bps: u64,
    /// Receive packets per second.
    pub rx_pps: u64,
    /// Transmit packets per second.
    pub tx_pps: u64,
    /// Sample duration in milliseconds.
    pub sample_duration_ms: u64,
}

impl LinkRates {
    /// Total bits per second (rx + tx).
    pub fn total_bps(&self) -> u64 {
        self.rx_bps + self.tx_bps
    }

    /// Total packets per second (rx + tx).
    pub fn total_pps(&self) -> u64 {
        self.rx_pps + self.tx_pps
    }
}

/// Traffic control diagnostics for an interface.
#[derive(Debug, Clone)]
pub struct TcDiag {
    /// Qdisc type (e.g., "fq_codel", "htb", "netem").
    pub qdisc: String,
    /// Qdisc handle as string (e.g., "1:0").
    pub handle: String,
    /// Total drops from this qdisc.
    pub drops: u64,
    /// Overlimit count.
    pub overlimits: u64,
    /// Current backlog in bytes.
    pub backlog: u32,
    /// Current queue length in packets.
    pub qlen: u32,
    /// Current rate in bytes per second (from rate estimator).
    pub rate_bps: u64,
    /// Current packet rate (from rate estimator).
    pub rate_pps: u64,
    /// Total bytes processed.
    pub bytes: u64,
    /// Total packets processed.
    pub packets: u64,
}

impl TcDiag {
    /// Create TC diagnostics from a TcMessage.
    pub fn from_tc_message(tc: &TcMessage) -> Self {
        Self {
            qdisc: tc.kind().unwrap_or("unknown").to_string(),
            handle: tc.handle_str(),
            drops: tc.drops() as u64,
            overlimits: tc.overlimits() as u64,
            backlog: tc.backlog(),
            qlen: tc.qlen(),
            rate_bps: tc.bps() as u64,
            rate_pps: tc.pps() as u64,
            bytes: tc.bytes(),
            packets: tc.packets(),
        }
    }
}

/// Route diagnostics summary.
#[derive(Debug, Clone, Default)]
pub struct RouteDiag {
    /// Total number of IPv4 routes.
    pub ipv4_route_count: usize,
    /// Total number of IPv6 routes.
    pub ipv6_route_count: usize,
    /// Whether a default IPv4 route exists.
    pub has_default_ipv4: bool,
    /// Whether a default IPv6 route exists.
    pub has_default_ipv6: bool,
    /// Default gateway for IPv4 (if any).
    pub default_gateway_v4: Option<IpAddr>,
    /// Default gateway for IPv6 (if any).
    pub default_gateway_v6: Option<IpAddr>,
}

/// A detected issue.
#[derive(Debug, Clone)]
pub struct Issue {
    /// Severity level.
    pub severity: Severity,
    /// Category of the issue.
    pub category: IssueCategory,
    /// Human-readable message.
    pub message: String,
    /// Additional details or recommendations.
    pub details: Option<String>,
    /// Interface name if issue is interface-specific.
    pub interface: Option<String>,
    /// When the issue was detected.
    pub timestamp: Instant,
}

impl fmt::Display for Issue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(ref iface) = self.interface {
            write!(f, "[{}] ", iface)?;
        }
        write!(f, "{}", self.message)?;
        if let Some(ref details) = self.details {
            write!(f, " ({})", details)?;
        }
        Ok(())
    }
}

/// Issue severity level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Severity {
    /// Informational message.
    Info,
    /// Warning that may indicate a problem.
    Warning,
    /// Error that affects functionality.
    Error,
    /// Critical issue requiring immediate attention.
    Critical,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Severity::Info => write!(f, "INFO"),
            Severity::Warning => write!(f, "WARN"),
            Severity::Error => write!(f, "ERROR"),
            Severity::Critical => write!(f, "CRITICAL"),
        }
    }
}

/// Category of detected issue.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IssueCategory {
    /// Interface is down.
    LinkDown,
    /// No carrier detected.
    NoCarrier,
    /// High packet loss rate.
    HighPacketLoss,
    /// RX/TX errors detected.
    LinkErrors,
    /// Qdisc dropping packets.
    QdiscDrops,
    /// Buffer overflow / backlog.
    BufferOverflow,
    /// No route to destination.
    NoRoute,
    /// Destination unreachable.
    Unreachable,
    /// High latency detected.
    HighLatency,
    /// Interface has no addresses.
    NoAddress,
    /// No default route configured.
    NoDefaultRoute,
    /// MTU mismatch or issue.
    MtuIssue,
    /// Duplex/speed mismatch.
    DuplexMismatch,
}

impl fmt::Display for IssueCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IssueCategory::LinkDown => write!(f, "LinkDown"),
            IssueCategory::NoCarrier => write!(f, "NoCarrier"),
            IssueCategory::HighPacketLoss => write!(f, "HighPacketLoss"),
            IssueCategory::LinkErrors => write!(f, "LinkErrors"),
            IssueCategory::QdiscDrops => write!(f, "QdiscDrops"),
            IssueCategory::BufferOverflow => write!(f, "BufferOverflow"),
            IssueCategory::NoRoute => write!(f, "NoRoute"),
            IssueCategory::Unreachable => write!(f, "Unreachable"),
            IssueCategory::HighLatency => write!(f, "HighLatency"),
            IssueCategory::NoAddress => write!(f, "NoAddress"),
            IssueCategory::NoDefaultRoute => write!(f, "NoDefaultRoute"),
            IssueCategory::MtuIssue => write!(f, "MtuIssue"),
            IssueCategory::DuplexMismatch => write!(f, "DuplexMismatch"),
        }
    }
}

/// Connectivity check result.
#[derive(Debug, Clone)]
pub struct ConnectivityReport {
    /// Destination that was checked.
    pub destination: IpAddr,
    /// Route information if found.
    pub route: Option<RouteInfo>,
    /// Output interface for the route.
    pub output_interface: Option<String>,
    /// Gateway address if any.
    pub gateway: Option<IpAddr>,
    /// Whether the gateway is reachable (based on neighbor state).
    pub gateway_reachable: bool,
    /// Issues detected during connectivity check.
    pub issues: Vec<Issue>,
}

/// Basic route information.
#[derive(Debug, Clone)]
pub struct RouteInfo {
    /// Destination prefix.
    pub destination: String,
    /// Prefix length.
    pub prefix_len: u8,
    /// Gateway address.
    pub gateway: Option<IpAddr>,
    /// Output interface index.
    pub oif: Option<u32>,
    /// Route metric.
    pub metric: Option<u32>,
}

/// Bottleneck analysis result.
#[derive(Debug, Clone)]
pub struct Bottleneck {
    /// Location description (e.g., "eth0 egress qdisc").
    pub location: String,
    /// Type of bottleneck.
    pub bottleneck_type: BottleneckType,
    /// Current rate in bytes per second.
    pub current_rate: u64,
    /// Drop rate as fraction (0.0 to 1.0).
    pub drop_rate: f64,
    /// Total drops observed.
    pub total_drops: u64,
    /// Recommendation for fixing the bottleneck.
    pub recommendation: String,
}

/// Type of bottleneck detected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BottleneckType {
    /// Qdisc is dropping packets.
    QdiscDrops,
    /// Interface is dropping packets.
    InterfaceDrops,
    /// Buffer overflow.
    BufferFull,
    /// Rate limiting in effect.
    RateLimited,
    /// Hardware errors.
    HardwareErrors,
}

impl fmt::Display for BottleneckType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BottleneckType::QdiscDrops => write!(f, "Qdisc Drops"),
            BottleneckType::InterfaceDrops => write!(f, "Interface Drops"),
            BottleneckType::BufferFull => write!(f, "Buffer Full"),
            BottleneckType::RateLimited => write!(f, "Rate Limited"),
            BottleneckType::HardwareErrors => write!(f, "Hardware Errors"),
        }
    }
}

// ============================================================================
// Configuration
// ============================================================================

/// Configuration for issue detection thresholds.
#[derive(Debug, Clone)]
pub struct DiagnosticsConfig {
    /// Packet loss threshold as fraction (default: 0.01 = 1%).
    pub packet_loss_threshold: f64,
    /// Error rate threshold as fraction (default: 0.001 = 0.1%).
    pub error_rate_threshold: f64,
    /// Qdisc drop threshold as fraction of packets (default: 0.01 = 1%).
    pub qdisc_drop_threshold: f64,
    /// Backlog threshold in bytes (default: 100KB).
    pub backlog_threshold: u32,
    /// Queue length threshold in packets (default: 1000).
    pub qlen_threshold: u32,
    /// Whether to skip loopback interfaces.
    pub skip_loopback: bool,
    /// Whether to skip down interfaces.
    pub skip_down: bool,
    /// Minimum bytes transferred before calculating loss rate.
    pub min_bytes_for_rate: u64,
}

impl Default for DiagnosticsConfig {
    fn default() -> Self {
        Self {
            packet_loss_threshold: 0.01,
            error_rate_threshold: 0.001,
            qdisc_drop_threshold: 0.01,
            backlog_threshold: 100_000,
            qlen_threshold: 1000,
            skip_loopback: true,
            skip_down: false,
            min_bytes_for_rate: 1000,
        }
    }
}

// ============================================================================
// Diagnostics Runner
// ============================================================================

/// Network diagnostics runner.
///
/// Provides methods to scan and analyze network configuration.
pub struct Diagnostics {
    conn: Connection<Route>,
    config: DiagnosticsConfig,
    /// Previous statistics for rate calculation.
    prev_stats: Arc<Mutex<HashMap<u32, (Instant, LinkStats)>>>,
    /// Previous TC stats for rate calculation (reserved for future use).
    #[allow(dead_code, clippy::type_complexity)]
    prev_tc_stats: Arc<Mutex<HashMap<(u32, u32), (Instant, u64, u64)>>>,
}

impl Diagnostics {
    /// Create a new diagnostics runner with default configuration.
    pub fn new(conn: Connection<Route>) -> Self {
        Self {
            conn,
            config: DiagnosticsConfig::default(),
            prev_stats: Arc::new(Mutex::new(HashMap::new())),
            prev_tc_stats: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Create a new diagnostics runner with custom configuration.
    pub fn with_config(conn: Connection<Route>, config: DiagnosticsConfig) -> Self {
        Self {
            conn,
            config,
            prev_stats: Arc::new(Mutex::new(HashMap::new())),
            prev_tc_stats: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Get a reference to the configuration.
    pub fn config(&self) -> &DiagnosticsConfig {
        &self.config
    }

    /// Get a mutable reference to the configuration.
    pub fn config_mut(&mut self) -> &mut DiagnosticsConfig {
        &mut self.config
    }

    /// Run a full diagnostic scan of all interfaces and routes.
    pub async fn scan(&self) -> Result<DiagnosticReport> {
        let timestamp = Instant::now();
        let mut all_issues = Vec::new();

        // Get all links
        let links = self.conn.get_links().await?;

        // Get all addresses for checking
        let addresses = self.conn.get_addresses().await?;
        let addr_by_ifindex: HashMap<u32, Vec<_>> = {
            let mut map: HashMap<u32, Vec<_>> = HashMap::new();
            for addr in addresses {
                map.entry(addr.ifindex()).or_default().push(addr);
            }
            map
        };

        // Get all qdiscs
        let qdiscs = self.conn.get_qdiscs().await?;
        let qdiscs_by_ifindex: HashMap<u32, Vec<_>> = {
            let mut map: HashMap<u32, Vec<_>> = HashMap::new();
            for qdisc in qdiscs {
                map.entry(qdisc.ifindex()).or_default().push(qdisc);
            }
            map
        };

        // Get routes and split by family
        let all_routes = self.conn.get_routes().await.unwrap_or_default();
        let ipv4_routes: Vec<_> = all_routes.iter().filter(|r| r.is_ipv4()).collect();
        let ipv6_routes: Vec<_> = all_routes.iter().filter(|r| r.is_ipv6()).collect();

        // Build route diagnostics
        let routes = self.build_route_diag(&ipv4_routes, &ipv6_routes);

        // Check for missing default route
        if !routes.has_default_ipv4 && !routes.has_default_ipv6 {
            all_issues.push(Issue {
                severity: Severity::Warning,
                category: IssueCategory::NoDefaultRoute,
                message: "No default route configured".to_string(),
                details: Some("System may not have internet connectivity".to_string()),
                interface: None,
                timestamp,
            });
        }

        // Scan each interface
        let mut interfaces = Vec::new();
        let mut prev_stats = self.prev_stats.lock().await;

        for link in links {
            // Skip loopback if configured
            if self.config.skip_loopback && link.is_loopback() {
                continue;
            }

            // Skip down interfaces if configured
            if self.config.skip_down && !link.is_up() {
                continue;
            }

            let ifindex = link.ifindex();
            let name = link.name().unwrap_or("?").to_string();
            let state = link.operstate().unwrap_or(OperState::Unknown);
            let stats = link.stats().cloned().unwrap_or_default();

            // Calculate rates
            let rates = if let Some((prev_time, prev)) = prev_stats.get(&ifindex) {
                let elapsed = prev_time.elapsed();
                if elapsed.as_millis() > 0 {
                    let ms = elapsed.as_millis() as u64;
                    LinkRates {
                        rx_bps: (stats.rx_bytes().saturating_sub(prev.rx_bytes())) * 1000 / ms,
                        tx_bps: (stats.tx_bytes().saturating_sub(prev.tx_bytes())) * 1000 / ms,
                        rx_pps: (stats.rx_packets().saturating_sub(prev.rx_packets())) * 1000 / ms,
                        tx_pps: (stats.tx_packets().saturating_sub(prev.tx_packets())) * 1000 / ms,
                        sample_duration_ms: ms,
                    }
                } else {
                    LinkRates::default()
                }
            } else {
                LinkRates::default()
            };

            // Store current stats for next calculation
            prev_stats.insert(ifindex, (Instant::now(), stats));

            // Detect issues for this interface
            let mut issues = self.detect_link_issues(&link, &stats, &addr_by_ifindex, timestamp);

            // Get TC diagnostics
            let tc = qdiscs_by_ifindex.get(&ifindex).and_then(|qs| {
                // Find the root qdisc
                qs.iter()
                    .find(|q| q.is_root())
                    .or_else(|| qs.first())
                    .map(|q| {
                        let tc_diag = TcDiag::from_tc_message(q);
                        // Check for TC issues
                        issues.extend(self.detect_tc_issues(q, &name, timestamp));
                        tc_diag
                    })
            });

            // Add interface issues to global list
            all_issues.extend(issues.iter().cloned());

            interfaces.push(InterfaceDiag {
                name,
                ifindex,
                state,
                flags: link.flags(),
                mtu: link.mtu(),
                stats,
                rates,
                tc,
                issues,
            });
        }

        Ok(DiagnosticReport {
            timestamp,
            interfaces,
            routes,
            issues: all_issues,
        })
    }

    /// Diagnose a specific interface.
    pub async fn scan_interface(&self, dev: &str) -> Result<InterfaceDiag> {
        let timestamp = Instant::now();

        // Get the link
        let link = self.conn.get_link_by_name(dev).await?;
        let link = link.ok_or_else(|| crate::netlink::error::Error::interface_not_found(dev))?;

        let ifindex = link.ifindex();
        let name = dev.to_string();
        let state = link.operstate().unwrap_or(OperState::Unknown);
        let stats = link.stats().cloned().unwrap_or_default();

        // Get addresses
        let addresses = self.conn.get_addresses_by_name(dev).await?;
        let addr_by_ifindex: HashMap<u32, Vec<_>> = {
            let mut map: HashMap<u32, Vec<_>> = HashMap::new();
            for addr in addresses {
                map.entry(addr.ifindex()).or_default().push(addr);
            }
            map
        };

        // Calculate rates
        let mut prev_stats = self.prev_stats.lock().await;
        let rates = if let Some((prev_time, prev)) = prev_stats.get(&ifindex) {
            let elapsed = prev_time.elapsed();
            if elapsed.as_millis() > 0 {
                let ms = elapsed.as_millis() as u64;
                LinkRates {
                    rx_bps: (stats.rx_bytes().saturating_sub(prev.rx_bytes())) * 1000 / ms,
                    tx_bps: (stats.tx_bytes().saturating_sub(prev.tx_bytes())) * 1000 / ms,
                    rx_pps: (stats.rx_packets().saturating_sub(prev.rx_packets())) * 1000 / ms,
                    tx_pps: (stats.tx_packets().saturating_sub(prev.tx_packets())) * 1000 / ms,
                    sample_duration_ms: ms,
                }
            } else {
                LinkRates::default()
            }
        } else {
            LinkRates::default()
        };

        prev_stats.insert(ifindex, (Instant::now(), stats));

        // Detect issues
        let mut issues = self.detect_link_issues(&link, &stats, &addr_by_ifindex, timestamp);

        // Get TC diagnostics
        let qdiscs = self.conn.get_qdiscs_by_name(dev).await?;
        let tc = qdiscs
            .iter()
            .find(|q| q.is_root())
            .or(qdiscs.first())
            .map(|q| {
                let tc_diag = TcDiag::from_tc_message(q);
                issues.extend(self.detect_tc_issues(q, &name, timestamp));
                tc_diag
            });

        Ok(InterfaceDiag {
            name,
            ifindex,
            state,
            flags: link.flags(),
            mtu: link.mtu(),
            stats,
            rates,
            tc,
            issues,
        })
    }

    /// Check connectivity to a destination IP address.
    pub async fn check_connectivity(&self, dest: IpAddr) -> Result<ConnectivityReport> {
        let timestamp = Instant::now();
        let mut issues = Vec::new();

        // Get routes and filter by address family
        let all_routes = self.conn.get_routes().await?;
        let routes: Vec<_> = match dest {
            IpAddr::V4(_) => all_routes.iter().filter(|r| r.is_ipv4()).collect(),
            IpAddr::V6(_) => all_routes.iter().filter(|r| r.is_ipv6()).collect(),
        };

        // Find matching route (simple longest prefix match)
        let matching_route = routes.iter().find(|r| {
            if let Some(dst) = &r.destination {
                // For default route (0.0.0.0/0 or ::/0)
                if r.dst_len() == 0 {
                    return true;
                }
                // Check if destination matches (simplified)
                match (dest, dst) {
                    (IpAddr::V4(d), IpAddr::V4(p)) => {
                        let prefix_len = r.dst_len();
                        let mask = if prefix_len >= 32 {
                            u32::MAX
                        } else {
                            u32::MAX << (32 - prefix_len)
                        };
                        (u32::from(d) & mask) == (u32::from(*p) & mask)
                    }
                    (IpAddr::V6(d), IpAddr::V6(p)) => {
                        let d_bytes = d.octets();
                        let p_bytes = p.octets();
                        let prefix_len = r.dst_len();
                        let full_bytes = (prefix_len / 8) as usize;
                        let remaining_bits = prefix_len % 8;

                        if d_bytes[..full_bytes] != p_bytes[..full_bytes] {
                            return false;
                        }

                        if remaining_bits > 0 && full_bytes < 16 {
                            let mask = 0xFF << (8 - remaining_bits);
                            (d_bytes[full_bytes] & mask) == (p_bytes[full_bytes] & mask)
                        } else {
                            true
                        }
                    }
                    _ => false,
                }
            } else {
                // Default route
                r.dst_len() == 0
            }
        });

        let (route, gateway, output_interface, oif) = if let Some(r) = matching_route {
            let gateway = r.gateway;
            let oif = r.oif;
            let output_interface = if let Some(idx) = oif {
                self.conn
                    .get_link_by_index(idx)
                    .await?
                    .and_then(|l| l.name().map(|s| s.to_string()))
            } else {
                None
            };

            let route_info = RouteInfo {
                destination: r
                    .destination
                    .map(|d| d.to_string())
                    .unwrap_or_else(|| "default".to_string()),
                prefix_len: r.dst_len(),
                gateway,
                oif,
                metric: r.priority(),
            };

            (Some(route_info), gateway, output_interface, oif)
        } else {
            issues.push(Issue {
                severity: Severity::Error,
                category: IssueCategory::NoRoute,
                message: format!("No route to {}", dest),
                details: None,
                interface: None,
                timestamp,
            });
            (None, None, None, None)
        };

        // Check if gateway is reachable via neighbor cache
        let gateway_reachable = if let Some(gw) = gateway {
            // Check neighbor cache
            let neighbors = self.conn.get_neighbors().await.unwrap_or_default();
            neighbors.iter().any(|n| {
                n.destination == Some(gw)
                    && n.state() != NeighborState::Incomplete
                    && n.state() != NeighborState::Failed
            })
        } else {
            true // No gateway means direct route
        };

        if gateway.is_some() && !gateway_reachable {
            issues.push(Issue {
                severity: Severity::Warning,
                category: IssueCategory::Unreachable,
                message: format!("Gateway {:?} may be unreachable", gateway),
                details: Some("Not found in neighbor cache or in failed state".to_string()),
                interface: output_interface.clone(),
                timestamp,
            });
        }

        // Check if output interface is up
        if let Some(idx) = oif
            && let Some(link) = self.conn.get_link_by_index(idx).await?
            && !link.is_up()
        {
            issues.push(Issue {
                severity: Severity::Error,
                category: IssueCategory::LinkDown,
                message: format!("Output interface {} is down", link.name().unwrap_or("?")),
                details: None,
                interface: link.name().map(|s| s.to_string()),
                timestamp,
            });
        }

        Ok(ConnectivityReport {
            destination: dest,
            route,
            output_interface,
            gateway,
            gateway_reachable,
            issues,
        })
    }

    /// Find the most significant bottleneck in the system.
    pub async fn find_bottleneck(&self) -> Result<Option<Bottleneck>> {
        let mut bottlenecks = Vec::new();

        // Check all interfaces
        let links = self.conn.get_links().await?;

        for link in &links {
            if link.is_loopback() {
                continue;
            }

            let name = link.name().unwrap_or("?");

            if let Some(stats) = link.stats() {
                let total_packets = stats.total_packets();
                let total_dropped = stats.total_dropped();
                let total_errors = stats.total_errors();

                if total_packets > 0 {
                    let drop_rate = total_dropped as f64 / total_packets as f64;

                    if drop_rate > self.config.packet_loss_threshold {
                        bottlenecks.push(Bottleneck {
                            location: format!("{} interface", name),
                            bottleneck_type: BottleneckType::InterfaceDrops,
                            current_rate: 0,
                            drop_rate,
                            total_drops: total_dropped,
                            recommendation: format!(
                                "Check {} for hardware issues or increase buffer sizes",
                                name
                            ),
                        });
                    }

                    if total_errors > 0 {
                        let error_rate = total_errors as f64 / total_packets as f64;
                        if error_rate > self.config.error_rate_threshold {
                            bottlenecks.push(Bottleneck {
                                location: format!("{} interface", name),
                                bottleneck_type: BottleneckType::HardwareErrors,
                                current_rate: 0,
                                drop_rate: error_rate,
                                total_drops: total_errors,
                                recommendation: format!(
                                    "Check cable, PHY settings, or NIC on {}",
                                    name
                                ),
                            });
                        }
                    }
                }
            }
        }

        // Check all qdiscs
        let qdiscs = self.conn.get_qdiscs().await?;
        let names = self.conn.get_interface_names().await?;

        for qdisc in &qdiscs {
            if !qdisc.is_root() {
                continue;
            }

            let name = names
                .get(&qdisc.ifindex())
                .map(|s| s.as_str())
                .unwrap_or("?");

            let drops = qdisc.drops() as u64;
            let packets = qdisc.packets();

            if packets > 0 {
                let drop_rate = drops as f64 / packets as f64;

                if drop_rate > self.config.qdisc_drop_threshold {
                    bottlenecks.push(Bottleneck {
                        location: format!(
                            "{} egress qdisc ({})",
                            name,
                            qdisc.kind().unwrap_or("?")
                        ),
                        bottleneck_type: BottleneckType::QdiscDrops,
                        current_rate: qdisc.bps() as u64,
                        drop_rate,
                        total_drops: drops,
                        recommendation: format!(
                            "Increase qdisc limit or rate on {}, or switch to a different qdisc",
                            name
                        ),
                    });
                }
            }

            // Check for buffer issues
            let backlog = qdisc.backlog();
            let qlen = qdisc.qlen();

            if backlog > self.config.backlog_threshold || qlen > self.config.qlen_threshold {
                bottlenecks.push(Bottleneck {
                    location: format!("{} egress qdisc ({})", name, qdisc.kind().unwrap_or("?")),
                    bottleneck_type: BottleneckType::BufferFull,
                    current_rate: qdisc.bps() as u64,
                    drop_rate: 0.0,
                    total_drops: drops,
                    recommendation: format!(
                        "High queue depth on {} - consider reducing buffering or increasing rate",
                        name
                    ),
                });
            }
        }

        // Return the worst bottleneck (highest drop rate)
        bottlenecks.sort_by(|a, b| {
            b.drop_rate
                .partial_cmp(&a.drop_rate)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        Ok(bottlenecks.into_iter().next())
    }

    /// Watch for issues in real-time.
    ///
    /// Returns a stream of issues detected from network events.
    pub async fn watch(&self) -> Result<IssueStream> {
        let mut conn = Connection::<Route>::new()?;
        conn.subscribe_all()?;
        Ok(IssueStream {
            events: conn.into_events(),
            config: self.config.clone(),
        })
    }

    // ========================================================================
    // Private helpers
    // ========================================================================

    fn build_route_diag(
        &self,
        ipv4_routes: &[&RouteMessage],
        ipv6_routes: &[&RouteMessage],
    ) -> RouteDiag {
        let mut diag = RouteDiag {
            ipv4_route_count: ipv4_routes.len(),
            ipv6_route_count: ipv6_routes.len(),
            ..Default::default()
        };

        // Find default IPv4 route
        for route in ipv4_routes {
            if route.dst_len() == 0 {
                diag.has_default_ipv4 = true;
                diag.default_gateway_v4 = route.gateway;
                break;
            }
        }

        // Find default IPv6 route
        for route in ipv6_routes {
            if route.dst_len() == 0 {
                diag.has_default_ipv6 = true;
                diag.default_gateway_v6 = route.gateway;
                break;
            }
        }

        diag
    }

    fn detect_link_issues(
        &self,
        link: &LinkMessage,
        stats: &LinkStats,
        addr_by_ifindex: &HashMap<u32, Vec<AddressMessage>>,
        timestamp: Instant,
    ) -> Vec<Issue> {
        let mut issues = Vec::new();
        let name = link.name().unwrap_or("?").to_string();
        let ifindex = link.ifindex();

        // Check if interface is down
        if !link.is_up() {
            issues.push(Issue {
                severity: Severity::Warning,
                category: IssueCategory::LinkDown,
                message: format!("Interface {} is down", name),
                details: None,
                interface: Some(name.clone()),
                timestamp,
            });
        }

        // Check carrier
        if link.is_up() && !link.has_carrier() {
            issues.push(Issue {
                severity: Severity::Error,
                category: IssueCategory::NoCarrier,
                message: format!("No carrier on {}", name),
                details: Some("Check cable connection".to_string()),
                interface: Some(name.clone()),
                timestamp,
            });
        }

        // Check for packet loss
        let total_packets = stats.total_packets();
        let total_dropped = stats.total_dropped();

        if total_packets > self.config.min_bytes_for_rate && total_dropped > 0 {
            let drop_rate = total_dropped as f64 / total_packets as f64;
            if drop_rate > self.config.packet_loss_threshold {
                issues.push(Issue {
                    severity: Severity::Warning,
                    category: IssueCategory::HighPacketLoss,
                    message: format!("{:.2}% packet loss on {}", drop_rate * 100.0, name),
                    details: Some(format!(
                        "{} dropped out of {} packets",
                        total_dropped, total_packets
                    )),
                    interface: Some(name.clone()),
                    timestamp,
                });
            }
        }

        // Check for errors
        let total_errors = stats.total_errors();
        if total_packets > self.config.min_bytes_for_rate && total_errors > 0 {
            let error_rate = total_errors as f64 / total_packets as f64;
            if error_rate > self.config.error_rate_threshold {
                issues.push(Issue {
                    severity: Severity::Warning,
                    category: IssueCategory::LinkErrors,
                    message: format!(
                        "{} errors on {} ({:.3}%)",
                        total_errors,
                        name,
                        error_rate * 100.0
                    ),
                    details: Some(format!(
                        "RX errors: {}, TX errors: {}",
                        stats.rx_errors(),
                        stats.tx_errors()
                    )),
                    interface: Some(name.clone()),
                    timestamp,
                });
            }
        }

        // Check for missing addresses (skip loopback)
        if link.is_up() && !link.is_loopback() {
            let has_addrs = addr_by_ifindex
                .get(&ifindex)
                .map(|addrs| !addrs.is_empty())
                .unwrap_or(false);
            if !has_addrs {
                issues.push(Issue {
                    severity: Severity::Info,
                    category: IssueCategory::NoAddress,
                    message: format!("No IP addresses configured on {}", name),
                    details: None,
                    interface: Some(name.clone()),
                    timestamp,
                });
            }
        }

        issues
    }

    fn detect_tc_issues(&self, tc: &TcMessage, iface: &str, timestamp: Instant) -> Vec<Issue> {
        let mut issues = Vec::new();

        let drops = tc.drops() as u64;
        let packets = tc.packets();

        if packets > 0 {
            let drop_rate = drops as f64 / packets as f64;
            if drop_rate > self.config.qdisc_drop_threshold {
                issues.push(Issue {
                    severity: Severity::Warning,
                    category: IssueCategory::QdiscDrops,
                    message: format!(
                        "Qdisc {} dropping {:.2}% of packets on {}",
                        tc.kind().unwrap_or("?"),
                        drop_rate * 100.0,
                        iface
                    ),
                    details: Some(format!("{} drops out of {} packets", drops, packets)),
                    interface: Some(iface.to_string()),
                    timestamp,
                });
            }
        }

        // Check backlog
        if tc.backlog() > self.config.backlog_threshold {
            issues.push(Issue {
                severity: Severity::Warning,
                category: IssueCategory::BufferOverflow,
                message: format!("High backlog ({} bytes) on {} qdisc", tc.backlog(), iface),
                details: Some(format!("Queue length: {} packets", tc.qlen())),
                interface: Some(iface.to_string()),
                timestamp,
            });
        }

        issues
    }
}

// ============================================================================
// Issue Stream
// ============================================================================

/// Stream of issues from real-time monitoring.
pub struct IssueStream {
    events: OwnedEventStream<Route>,
    /// Configuration for issue thresholds (reserved for future filtering).
    #[allow(dead_code)]
    config: DiagnosticsConfig,
}

impl Stream for IssueStream {
    type Item = Result<Issue>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        loop {
            let events = Pin::new(&mut self.events);

            match events.poll_next(cx) {
                Poll::Ready(Some(Ok(event))) => {
                    if let Some(issue) = self.event_to_issue(&event) {
                        return Poll::Ready(Some(Ok(issue)));
                    }
                    // Continue polling for next event
                }
                Poll::Ready(Some(Err(e))) => {
                    return Poll::Ready(Some(Err(e)));
                }
                Poll::Ready(None) => {
                    return Poll::Ready(None);
                }
                Poll::Pending => {
                    return Poll::Pending;
                }
            }
        }
    }
}

impl IssueStream {
    fn event_to_issue(&self, event: &NetworkEvent) -> Option<Issue> {
        let timestamp = Instant::now();

        match event {
            NetworkEvent::DelLink(link) => {
                let name = link.name().unwrap_or("?").to_string();
                Some(Issue {
                    severity: Severity::Warning,
                    category: IssueCategory::LinkDown,
                    message: format!("Interface {} removed", name),
                    details: None,
                    interface: Some(name),
                    timestamp,
                })
            }
            NetworkEvent::NewLink(link) => {
                let name = link.name().unwrap_or("?").to_string();

                // Check for carrier issues on new/changed links
                if link.is_up() && !link.has_carrier() {
                    return Some(Issue {
                        severity: Severity::Error,
                        category: IssueCategory::NoCarrier,
                        message: format!("No carrier on {}", name),
                        details: Some("Check cable connection".to_string()),
                        interface: Some(name),
                        timestamp,
                    });
                }

                // Check for operstate changes
                if let Some(state) = link.operstate()
                    && (state == OperState::Down || state == OperState::LowerLayerDown)
                {
                    return Some(Issue {
                        severity: Severity::Warning,
                        category: IssueCategory::LinkDown,
                        message: format!("Interface {} is {:?}", name, state),
                        details: None,
                        interface: Some(name),
                        timestamp,
                    });
                }

                None
            }
            NetworkEvent::DelAddress(addr) => {
                let name = crate::util::ifname::index_to_name(addr.ifindex())
                    .unwrap_or_else(|_| format!("if{}", addr.ifindex()));
                Some(Issue {
                    severity: Severity::Info,
                    category: IssueCategory::NoAddress,
                    message: format!("Address {:?} removed from {}", addr.address(), name),
                    details: None,
                    interface: Some(name),
                    timestamp,
                })
            }
            NetworkEvent::DelRoute(route) => {
                // Check if it's the default route
                if route.dst_len() == 0 {
                    return Some(Issue {
                        severity: Severity::Warning,
                        category: IssueCategory::NoDefaultRoute,
                        message: "Default route removed".to_string(),
                        details: None,
                        interface: None,
                        timestamp,
                    });
                }
                None
            }
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_severity_ordering() {
        assert!(Severity::Info < Severity::Warning);
        assert!(Severity::Warning < Severity::Error);
        assert!(Severity::Error < Severity::Critical);
    }

    #[test]
    fn test_issue_display() {
        let issue = Issue {
            severity: Severity::Warning,
            category: IssueCategory::HighPacketLoss,
            message: "5% packet loss".to_string(),
            details: Some("Check cable".to_string()),
            interface: Some("eth0".to_string()),
            timestamp: Instant::now(),
        };

        let s = format!("{}", issue);
        assert!(s.contains("eth0"));
        assert!(s.contains("5% packet loss"));
        assert!(s.contains("Check cable"));
    }

    #[test]
    fn test_link_rates() {
        let rates = LinkRates {
            rx_bps: 1000,
            tx_bps: 2000,
            rx_pps: 10,
            tx_pps: 20,
            sample_duration_ms: 1000,
        };

        assert_eq!(rates.total_bps(), 3000);
        assert_eq!(rates.total_pps(), 30);
    }

    #[test]
    fn test_config_defaults() {
        let config = DiagnosticsConfig::default();
        assert_eq!(config.packet_loss_threshold, 0.01);
        assert!(config.skip_loopback);
    }
}
