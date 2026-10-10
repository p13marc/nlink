//! Common test utilities for integration tests.
//!
//! Thin shim over `nlink::lab` so existing integration tests keep
//! working without import changes while the shared helpers live in
//! the public `lab` module.

pub mod converge;
pub mod counters;
pub mod events;
pub mod topo;
pub mod traffic;

use std::time::Duration;

pub use nlink::lab::LabNamespace as TestNamespace;

/// How long one test body, or one step of a convergence case, may take.
pub const STEP_TIMEOUT: Duration = Duration::from_secs(30);

/// Run `body`, failing with `Error::Timeout` after [`STEP_TIMEOUT`]
/// instead of hanging the suite.
pub async fn with_timeout<T>(body: impl Future<Output = nlink::Result<T>>) -> nlink::Result<T> {
    match tokio::time::timeout(STEP_TIMEOUT, body).await {
        Ok(result) => result,
        Err(_elapsed) => Err(nlink::Error::Timeout),
    }
}

/// Check if running as root.
pub fn is_root() -> bool {
    nlink::lab::is_root()
}

/// Skip the test if not running as root.
///
/// Use this at the beginning of integration tests that require root privileges.
///
/// Per Plan 174 — also initializes a `tracing-subscriber` (via
/// [`nlink::lab::init_test_tracing`]) so the lib's
/// `#[tracing::instrument]` spans surface in CI logs. Equivalent to
/// `nlink::require_root!()`; both paths feed through the same
/// subscriber-init helper.
#[macro_export]
macro_rules! require_root {
    () => {
        ::nlink::lab::init_test_tracing();
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
        ::nlink::lab::init_test_tracing();
        if !$crate::common::is_root() {
            eprintln!("Skipping test: requires root");
            return;
        }
    };
}
