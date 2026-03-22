//! Sysctl integration tests.
//!
//! Tests for sysctl read/write operations inside network namespaces.

use nlink::Result;
use nlink::netlink::namespace;
use nlink::netlink::sysctl;

use crate::common::TestNamespace;

#[tokio::test]
async fn test_sysctl_get_in_namespace() -> Result<()> {
    require_root!();

    let ns = TestNamespace::new("sysctl-get")?;

    // ip_forward defaults to "0" in a new namespace
    let val = namespace::get_sysctl(ns.name(), "net.ipv4.ip_forward")?;
    assert_eq!(val, "0");

    Ok(())
}

#[tokio::test]
async fn test_sysctl_set_roundtrip() -> Result<()> {
    require_root!();

    let ns = TestNamespace::new("sysctl-set")?;

    // Set ip_forward to 1
    namespace::set_sysctl(ns.name(), "net.ipv4.ip_forward", "1")?;

    // Read it back
    let val = namespace::get_sysctl(ns.name(), "net.ipv4.ip_forward")?;
    assert_eq!(val, "1");

    // Set it back to 0
    namespace::set_sysctl(ns.name(), "net.ipv4.ip_forward", "0")?;
    let val = namespace::get_sysctl(ns.name(), "net.ipv4.ip_forward")?;
    assert_eq!(val, "0");

    Ok(())
}

#[tokio::test]
async fn test_sysctl_set_many() -> Result<()> {
    require_root!();

    let ns = TestNamespace::new("sysctl-many")?;

    namespace::set_sysctls(
        ns.name(),
        &[
            ("net.ipv4.ip_forward", "1"),
            ("net.ipv6.conf.all.forwarding", "1"),
        ],
    )?;

    assert_eq!(
        namespace::get_sysctl(ns.name(), "net.ipv4.ip_forward")?,
        "1"
    );
    assert_eq!(
        namespace::get_sysctl(ns.name(), "net.ipv6.conf.all.forwarding")?,
        "1"
    );

    Ok(())
}

#[tokio::test]
async fn test_sysctl_invalid_key() -> Result<()> {
    require_root!();

    let ns = TestNamespace::new("sysctl-inv")?;

    // Non-existent key should error
    let result = namespace::get_sysctl(ns.name(), "net.ipv4.nonexistent_key_12345");
    assert!(result.is_err());

    Ok(())
}

#[test]
fn test_sysctl_validate_key_rejects_traversal() {
    assert!(sysctl::get("net..ipv4").is_err());
    assert!(sysctl::get("/etc/passwd").is_err());
    assert!(sysctl::get("").is_err());
}
