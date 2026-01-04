//! Integration tests for the diagnostics module.

use crate::common::TestNamespace;
use nlink::netlink::diagnostics::{
    BottleneckType, Diagnostics, DiagnosticsConfig, IssueCategory, LinkRates, Severity,
};

// ============================================================================
// Unit Tests (no network namespace required)
// ============================================================================

#[test]
fn test_severity_ordering() {
    assert!(Severity::Info < Severity::Warning);
    assert!(Severity::Warning < Severity::Error);
    assert!(Severity::Error < Severity::Critical);
}

#[test]
fn test_severity_display() {
    assert_eq!(format!("{}", Severity::Info), "INFO");
    assert_eq!(format!("{}", Severity::Warning), "WARN");
    assert_eq!(format!("{}", Severity::Error), "ERROR");
    assert_eq!(format!("{}", Severity::Critical), "CRITICAL");
}

#[test]
fn test_issue_category_display() {
    assert_eq!(format!("{}", IssueCategory::LinkDown), "LinkDown");
    assert_eq!(format!("{}", IssueCategory::NoCarrier), "NoCarrier");
    assert_eq!(
        format!("{}", IssueCategory::HighPacketLoss),
        "HighPacketLoss"
    );
    assert_eq!(format!("{}", IssueCategory::QdiscDrops), "QdiscDrops");
    assert_eq!(format!("{}", IssueCategory::NoRoute), "NoRoute");
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
fn test_link_rates_default() {
    let rates = LinkRates::default();
    assert_eq!(rates.rx_bps, 0);
    assert_eq!(rates.tx_bps, 0);
    assert_eq!(rates.total_bps(), 0);
}

#[test]
fn test_config_defaults() {
    let config = DiagnosticsConfig::default();
    assert_eq!(config.packet_loss_threshold, 0.01);
    assert_eq!(config.error_rate_threshold, 0.001);
    assert_eq!(config.qdisc_drop_threshold, 0.01);
    assert_eq!(config.backlog_threshold, 100_000);
    assert_eq!(config.qlen_threshold, 1000);
    assert!(config.skip_loopback);
    assert!(!config.skip_down);
    assert_eq!(config.min_bytes_for_rate, 1000);
}

#[test]
fn test_bottleneck_type_display() {
    assert_eq!(format!("{}", BottleneckType::QdiscDrops), "Qdisc Drops");
    assert_eq!(
        format!("{}", BottleneckType::InterfaceDrops),
        "Interface Drops"
    );
    assert_eq!(format!("{}", BottleneckType::BufferFull), "Buffer Full");
    assert_eq!(format!("{}", BottleneckType::RateLimited), "Rate Limited");
    assert_eq!(
        format!("{}", BottleneckType::HardwareErrors),
        "Hardware Errors"
    );
}

// ============================================================================
// Integration Tests (require network namespace)
// ============================================================================

#[tokio::test]
#[ignore] // Requires root privileges for network namespaces
async fn test_diagnostics_scan() {
    let ns = TestNamespace::new("diag_scan").unwrap();

    // Create a dummy interface
    ns.add_dummy("dummy0").unwrap();
    ns.link_up("dummy0").unwrap();
    ns.add_addr("dummy0", "10.0.0.1/24").unwrap();

    // Create diagnostics runner
    let conn = ns.connection().unwrap();
    let diag = Diagnostics::new(conn);

    // Run scan
    let report = diag.scan().await.unwrap();

    // Verify we got results
    assert!(!report.interfaces.is_empty());

    // Find our dummy interface
    let dummy = report
        .interfaces
        .iter()
        .find(|i| i.name == "dummy0")
        .expect("dummy0 not found in report");

    assert_eq!(dummy.name, "dummy0");
    assert!(dummy.mtu.is_some());
}

#[tokio::test]
#[ignore] // Requires root privileges for network namespaces
async fn test_diagnostics_scan_interface() {
    let ns = TestNamespace::new("diag_scan_if").unwrap();

    // Create a dummy interface
    ns.add_dummy("eth0").unwrap();
    ns.link_up("eth0").unwrap();
    ns.add_addr("eth0", "192.168.1.1/24").unwrap();

    let conn = ns.connection().unwrap();
    let diag = Diagnostics::new(conn);

    // Scan specific interface
    let iface = diag.scan_interface("eth0").await.unwrap();

    assert_eq!(iface.name, "eth0");
    assert!(iface.mtu.is_some());
}

#[tokio::test]
#[ignore] // Requires root privileges for network namespaces
async fn test_diagnostics_scan_interface_not_found() {
    let ns = TestNamespace::new("diag_notfound").unwrap();

    let conn = ns.connection().unwrap();
    let diag = Diagnostics::new(conn);

    // Try to scan non-existent interface
    let result = diag.scan_interface("nonexistent0").await;
    assert!(result.is_err());

    let err = result.unwrap_err();
    assert!(err.is_not_found());
}

#[tokio::test]
#[ignore] // Requires root privileges for network namespaces
async fn test_diagnostics_check_connectivity_no_route() {
    let ns = TestNamespace::new("diag_conn").unwrap();

    // Create a dummy interface without any routes
    ns.add_dummy("eth0").unwrap();
    ns.link_up("eth0").unwrap();

    let conn = ns.connection().unwrap();
    let diag = Diagnostics::new(conn);

    // Check connectivity to external IP - should fail (no route)
    let report = diag
        .check_connectivity("8.8.8.8".parse().unwrap())
        .await
        .unwrap();

    // Should have a NoRoute issue
    assert!(!report.issues.is_empty());
    assert!(
        report
            .issues
            .iter()
            .any(|i| i.category == IssueCategory::NoRoute)
    );
}

#[tokio::test]
#[ignore] // Requires root privileges for network namespaces
async fn test_diagnostics_check_connectivity_with_route() {
    let ns = TestNamespace::new("diag_route").unwrap();

    // Create interface with address and default route
    ns.add_dummy("eth0").unwrap();
    ns.link_up("eth0").unwrap();
    ns.add_addr("eth0", "192.168.1.1/24").unwrap();
    // Add a default route (may fail if kernel requires a real gateway)
    let _ = ns.exec("ip", &["route", "add", "default", "via", "192.168.1.254"]);

    let conn = ns.connection().unwrap();
    let diag = Diagnostics::new(conn);

    // Check connectivity to local subnet - should have a route
    let report = diag
        .check_connectivity("192.168.1.100".parse().unwrap())
        .await
        .unwrap();

    // Should find a route (even if not the default)
    assert!(
        report.route.is_some() || report.issues.is_empty(),
        "Expected route or no issues"
    );
}

#[tokio::test]
#[ignore] // Requires root privileges for network namespaces
async fn test_diagnostics_find_bottleneck() {
    let ns = TestNamespace::new("diag_bottle").unwrap();

    // Create a dummy interface
    ns.add_dummy("eth0").unwrap();
    ns.link_up("eth0").unwrap();

    let conn = ns.connection().unwrap();
    let diag = Diagnostics::new(conn);

    // Find bottleneck - likely none on a fresh interface
    let bottleneck = diag.find_bottleneck().await.unwrap();

    // Fresh interface shouldn't have a bottleneck
    // (unless there's a pre-existing issue)
    if let Some(b) = bottleneck {
        println!("Found bottleneck: {} ({:?})", b.location, b.bottleneck_type);
    }
}

#[tokio::test]
#[ignore] // Requires root privileges for network namespaces
async fn test_diagnostics_with_tc() {
    let ns = TestNamespace::new("diag_tc").unwrap();

    // Create a dummy interface with TC
    ns.add_dummy("eth0").unwrap();
    ns.link_up("eth0").unwrap();

    // Add a qdisc
    ns.exec_ignore(
        "tc",
        &[
            "qdisc", "add", "dev", "eth0", "root", "handle", "1:", "htb", "default", "10",
        ],
    );

    let conn = ns.connection().unwrap();
    let diag = Diagnostics::new(conn);

    let report = diag.scan().await.unwrap();

    // Find eth0 and check TC info
    let eth0 = report.interfaces.iter().find(|i| i.name == "eth0");
    assert!(eth0.is_some());

    let eth0 = eth0.unwrap();
    if let Some(tc) = &eth0.tc {
        assert_eq!(tc.qdisc, "htb");
    }
}

#[tokio::test]
#[ignore] // Requires root privileges for network namespaces
async fn test_diagnostics_link_down_detection() {
    let ns = TestNamespace::new("diag_down").unwrap();

    // Create a dummy interface but leave it down
    ns.add_dummy("eth0").unwrap();
    // Don't bring it up

    let conn = ns.connection().unwrap();

    // Use config that doesn't skip down interfaces
    let mut config = DiagnosticsConfig::default();
    config.skip_down = false;

    let diag = Diagnostics::with_config(conn, config);

    let report = diag.scan().await.unwrap();

    // Find eth0
    let eth0 = report.interfaces.iter().find(|i| i.name == "eth0");
    assert!(eth0.is_some());

    let eth0 = eth0.unwrap();

    // Should have LinkDown issue
    assert!(
        eth0.issues
            .iter()
            .any(|i| i.category == IssueCategory::LinkDown)
    );
}

#[tokio::test]
#[ignore] // Requires root privileges for network namespaces
async fn test_diagnostics_no_address_detection() {
    let ns = TestNamespace::new("diag_noaddr").unwrap();

    // Create interface without address
    ns.add_dummy("eth0").unwrap();
    ns.link_up("eth0").unwrap();
    // Don't add any addresses

    let conn = ns.connection().unwrap();
    let diag = Diagnostics::new(conn);

    let report = diag.scan().await.unwrap();

    // Find eth0
    let eth0 = report.interfaces.iter().find(|i| i.name == "eth0");
    assert!(eth0.is_some());

    let eth0 = eth0.unwrap();

    // Should have NoAddress issue (info level)
    assert!(
        eth0.issues
            .iter()
            .any(|i| i.category == IssueCategory::NoAddress)
    );
}

#[tokio::test]
#[ignore] // Requires root privileges for network namespaces
async fn test_diagnostics_route_summary() {
    let ns = TestNamespace::new("diag_routes").unwrap();

    // Create interface and add routes
    ns.add_dummy("eth0").unwrap();
    ns.link_up("eth0").unwrap();
    ns.add_addr("eth0", "10.0.0.1/24").unwrap();
    ns.exec("ip", &["route", "add", "192.168.0.0/16", "dev", "eth0"])
        .unwrap();

    let conn = ns.connection().unwrap();
    let diag = Diagnostics::new(conn);

    let report = diag.scan().await.unwrap();

    // Check route diagnostics
    assert!(report.routes.ipv4_route_count >= 1);
}

#[tokio::test]
#[ignore] // Requires root privileges for network namespaces
async fn test_diagnostics_custom_config() {
    let ns = TestNamespace::new("diag_config").unwrap();

    ns.add_dummy("eth0").unwrap();
    ns.link_up("eth0").unwrap();

    let conn = ns.connection().unwrap();

    // Custom config with stricter thresholds
    let config = DiagnosticsConfig {
        packet_loss_threshold: 0.001, // 0.1%
        error_rate_threshold: 0.0001, // 0.01%
        skip_loopback: true,
        skip_down: true,
        ..Default::default()
    };

    let diag = Diagnostics::with_config(conn, config);

    assert_eq!(diag.config().packet_loss_threshold, 0.001);
    assert_eq!(diag.config().error_rate_threshold, 0.0001);

    let report = diag.scan().await.unwrap();
    assert!(!report.interfaces.is_empty());
}

#[tokio::test]
#[ignore] // Requires root privileges for network namespaces
async fn test_diagnostics_skip_loopback() {
    let ns = TestNamespace::new("diag_lo").unwrap();

    let conn = ns.connection().unwrap();

    // Default config skips loopback
    let diag = Diagnostics::new(conn);
    let report = diag.scan().await.unwrap();

    // lo should not be in the results
    assert!(!report.interfaces.iter().any(|i| i.name == "lo"));
}
