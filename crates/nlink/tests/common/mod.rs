//! Common test utilities for integration tests.
//!
//! Provides `TestNamespace` for isolated network namespace testing
//! and helper macros for conditional test execution.

use nlink::Result;
use nlink::Route;
use nlink::netlink::Connection;
use nlink::netlink::namespace;
use std::io;
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};

/// Global counter for unique namespace names.
static NAMESPACE_COUNTER: AtomicU32 = AtomicU32::new(0);

/// Generate a unique namespace name for this test.
fn unique_ns_name(prefix: &str) -> String {
    let id = NAMESPACE_COUNTER.fetch_add(1, Ordering::SeqCst);
    let pid = std::process::id();
    format!("nlink-test-{}-{}-{}", prefix, pid, id)
}

/// A test network namespace with automatic cleanup.
///
/// Creates an isolated network namespace for testing netlink operations.
/// The namespace is automatically deleted when the struct is dropped.
///
/// # Example
///
/// ```ignore
/// let ns = TestNamespace::new("mytest")?;
/// let conn = ns.connection()?;
///
/// // Perform netlink operations in isolation
/// conn.add_link(DummyLink::new("dummy0")).await?;
/// ```
pub struct TestNamespace {
    name: String,
}

impl TestNamespace {
    /// Create a new test namespace with a unique name.
    ///
    /// The `prefix` is used to generate a unique namespace name
    /// that includes the process ID and a counter.
    pub fn new(prefix: &str) -> Result<Self> {
        let name = unique_ns_name(prefix);

        let status = Command::new("ip")
            .args(["netns", "add", &name])
            .status()
            .map_err(|e| nlink::Error::Io(io::Error::from(e.kind())))?;

        if !status.success() {
            return Err(nlink::Error::InvalidMessage(format!(
                "failed to create namespace: {}",
                name
            )));
        }

        Ok(Self { name })
    }

    /// Get the namespace name.
    #[allow(dead_code)]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Get a connection to this namespace.
    pub fn connection(&self) -> Result<Connection<Route>> {
        namespace::connection_for(&self.name)
    }

    /// Run a command in the namespace and return its output.
    pub fn exec(&self, cmd: &str, args: &[&str]) -> Result<String> {
        let output = Command::new("ip")
            .args(["netns", "exec", &self.name, cmd])
            .args(args)
            .output()
            .map_err(|e| nlink::Error::Io(io::Error::from(e.kind())))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(nlink::Error::InvalidMessage(format!(
                "command failed: {} {:?}: {}",
                cmd, args, stderr
            )));
        }

        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    }

    /// Run a command in the namespace, ignoring errors.
    pub fn exec_ignore(&self, cmd: &str, args: &[&str]) {
        let _ = Command::new("ip")
            .args(["netns", "exec", &self.name, cmd])
            .args(args)
            .output();
    }

    /// Add a veth pair with one end in this namespace and the other in another.
    ///
    /// Creates `local_name` in this namespace and `remote_name` in `other`.
    pub fn connect_to(
        &self,
        other: &TestNamespace,
        local_name: &str,
        remote_name: &str,
    ) -> Result<()> {
        // Create veth pair in this namespace
        let status = Command::new("ip")
            .args([
                "netns",
                "exec",
                &self.name,
                "ip",
                "link",
                "add",
                local_name,
                "type",
                "veth",
                "peer",
                "name",
                remote_name,
            ])
            .status()
            .map_err(|e| nlink::Error::Io(io::Error::from(e.kind())))?;

        if !status.success() {
            return Err(nlink::Error::InvalidMessage(
                "failed to create veth pair".into(),
            ));
        }

        // Move the peer to the other namespace
        let status = Command::new("ip")
            .args([
                "netns",
                "exec",
                &self.name,
                "ip",
                "link",
                "set",
                remote_name,
                "netns",
                &other.name,
            ])
            .status()
            .map_err(|e| nlink::Error::Io(io::Error::from(e.kind())))?;

        if !status.success() {
            return Err(nlink::Error::InvalidMessage(
                "failed to move veth peer".into(),
            ));
        }

        Ok(())
    }

    /// Add a dummy interface in this namespace using ip command.
    pub fn add_dummy(&self, name: &str) -> Result<()> {
        self.exec("ip", &["link", "add", name, "type", "dummy"])?;
        Ok(())
    }

    /// Bring an interface up using ip command.
    pub fn link_up(&self, name: &str) -> Result<()> {
        self.exec("ip", &["link", "set", name, "up"])?;
        Ok(())
    }

    /// Add an IP address using ip command.
    pub fn add_addr(&self, dev: &str, addr: &str) -> Result<()> {
        self.exec("ip", &["addr", "add", addr, "dev", dev])?;
        Ok(())
    }
}

impl Drop for TestNamespace {
    fn drop(&mut self) {
        // Clean up the namespace
        let _ = Command::new("ip")
            .args(["netns", "del", &self.name])
            .status();
    }
}

/// Check if running as root.
pub fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

/// Skip the test if not running as root.
///
/// Use this at the beginning of integration tests that require root privileges.
#[macro_export]
macro_rules! require_root {
    () => {
        if !crate::common::is_root() {
            eprintln!("Skipping test: requires root");
            return Ok(());
        }
    };
}

/// Skip the test if not running as root (for non-Result functions).
#[macro_export]
macro_rules! require_root_void {
    () => {
        if !crate::common::is_root() {
            eprintln!("Skipping test: requires root");
            return;
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unique_ns_name() {
        let name1 = unique_ns_name("test");
        let name2 = unique_ns_name("test");
        assert_ne!(name1, name2);
        assert!(name1.starts_with("nlink-test-test-"));
    }
}
