//! Common test utilities for integration tests.
//!
//! Thin shim over `nlink::lab` so existing integration tests keep
//! working without import changes while the shared helpers live in
//! the public `lab` module.

pub use nlink::lab::LabNamespace as TestNamespace;

/// Check if running as root.
pub fn is_root() -> bool {
    nlink::lab::is_root()
}

/// Skip the test if not running as root.
///
/// Use this at the beginning of integration tests that require root privileges.
#[macro_export]
macro_rules! require_root {
    () => {
        if !$crate::common::is_root() {
            eprintln!("Skipping test: requires root");
            return Ok(());
        }
    };
}

/// Skip the test if not running as root (for non-Result functions).
#[macro_export]
macro_rules! require_root_void {
    () => {
        if !$crate::common::is_root() {
            eprintln!("Skipping test: requires root");
            return;
        }
    };
}
