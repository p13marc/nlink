//! Lab / integration-test helpers for building ephemeral network
//! environments.
//!
//! This module promotes the `TestNamespace` helper that previously
//! lived in `crates/nlink/tests/common/mod.rs` to a public, reusable
//! building block. Use it to spin up an isolated network namespace
//! with a dummy interface or a veth pair in a few lines, run your
//! code, and let `Drop` clean up afterward.
//!
//! Gated behind the `lab` feature flag so production consumers don't
//! pay for the command-spawning + tracing surface.
//!
//! # Typical shape
//!
//! ```no_run
//! # async fn example() -> nlink::Result<()> {
//! use nlink::lab::{LabNamespace, with_namespace};
//! use nlink::netlink::link::DummyLink;
//!
//! // Manual lifecycle — the namespace is deleted on Drop.
//! let ns = LabNamespace::new("mytest")?;
//! let conn = ns.connection()?;
//! conn.add_link(DummyLink::new("dummy0")).await?;
//!
//! // Scope-guarded lifecycle — the namespace is always deleted,
//! // even if the closure errors or panics inside a catch_unwind.
//! with_namespace("mytest2", |ns| async move {
//!     let conn = ns.connection()?;
//!     conn.add_link(DummyLink::new("dummy0")).await?;
//!     Ok(())
//! }).await?;
//! # Ok(())
//! # }
//! ```
//!
//! # Requirements
//!
//! - Linux with network-namespace support.
//! - `CAP_SYS_ADMIN` (typically root) — the same requirement as
//!   `ip netns add`.
//! - The `ip` command in `PATH`, used by the `connect_to` / `add_dummy`
//!   / `link_up` / `add_addr` convenience helpers. The low-level
//!   `spawn` / `spawn_output` / `connection` methods don't need it.
//!
//! # Naming
//!
//! `LabNamespace::new(prefix)` generates a name of the form
//! `nlink-lab-<prefix>-<pid>-<counter>` so concurrent tests don't
//! collide.

use std::{
    future::Future,
    process::{Child, Command, Output},
    sync::atomic::{AtomicU32, Ordering},
};

mod bridge;
mod veth;

pub use bridge::LabBridge;
pub use veth::LabVeth;

use tracing::warn;

use crate::{
    Result, Route,
    netlink::{AsyncProtocolInit, Connection, ProtocolState, namespace},
};

static NAMESPACE_COUNTER: AtomicU32 = AtomicU32::new(0);

fn unique_ns_name(prefix: &str) -> String {
    let id = NAMESPACE_COUNTER.fetch_add(1, Ordering::SeqCst);
    let pid = std::process::id();
    format!("nlink-lab-{prefix}-{pid}-{id}")
}

/// An ephemeral, isolated network namespace for local experimentation,
/// tests, or CLI demos.
///
/// The namespace is created in [`LabNamespace::new`] and deleted on
/// `Drop`. Concurrent construction produces non-colliding names via a
/// PID + per-process counter suffix.
///
/// See the [module-level docs](self) for usage.
pub struct LabNamespace {
    name: String,
}

impl LabNamespace {
    /// Create a uniquely-named namespace.
    ///
    /// The full name is `nlink-lab-<prefix>-<pid>-<counter>`.
    pub fn new(prefix: &str) -> Result<Self> {
        let name = unique_ns_name(prefix);
        namespace::create(&name)?;
        Ok(Self { name })
    }

    /// Create a namespace with a specific name.
    ///
    /// Errors if a namespace with that name already exists.
    pub fn named(name: &str) -> Result<Self> {
        namespace::create(name)?;
        Ok(Self {
            name: name.to_string(),
        })
    }

    /// Get the full namespace name (suitable for `ip netns exec`).
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Open a rtnetlink `Connection<Route>` scoped to this namespace.
    pub fn connection(&self) -> Result<Connection<Route>> {
        namespace::connection_for(&self.name)
    }

    /// Open a protocol-generic connection scoped to this namespace.
    ///
    /// Works for protocols whose construction is synchronous
    /// (rtnetlink, netfilter, uevent, sockdiag, etc.). For GENL
    /// families that need async family-ID resolution, use
    /// [`Self::connection_for_async`].
    pub fn connection_for<P>(&self) -> Result<Connection<P>>
    where
        P: ProtocolState + Default,
    {
        namespace::connection_for(&self.name)
    }

    /// Open a GENL-style connection that resolves its family ID
    /// asynchronously (WireGuard, MACsec, MPTCP, Ethtool, nl80211,
    /// Devlink).
    pub async fn connection_for_async<P>(&self) -> Result<Connection<P>>
    where
        P: AsyncProtocolInit,
    {
        namespace::connection_for_async(&self.name).await
    }

    /// Spawn a child process inside this namespace.
    ///
    /// The child's network namespace is set via the same `setns()`
    /// mechanism used by `ip netns exec` — no shelling to `ip netns
    /// exec` on the caller's side.
    pub fn spawn(&self, cmd: Command) -> Result<Child> {
        namespace::spawn(&self.name, cmd)
    }

    /// Spawn and collect stdout/stderr.
    pub fn spawn_output(&self, cmd: Command) -> Result<Output> {
        namespace::spawn_output(&self.name, cmd)
    }

    /// Run `cmd args...` in this namespace, returning stdout as a
    /// string. Errors if the command exits non-zero.
    ///
    /// Convenience for the common "run `ip` and check status" pattern.
    pub fn exec(&self, cmd: &str, args: &[&str]) -> Result<String> {
        let mut command = Command::new(cmd);
        command.args(args);
        let output = namespace::spawn_output(&self.name, command)?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(crate::Error::InvalidMessage(format!(
                "command failed: {cmd} {args:?}: {stderr}"
            )));
        }

        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    }

    /// Run a command, discarding the output and any error. Useful for
    /// best-effort teardown operations where the next step will fail
    /// loudly anyway if something is wrong.
    pub fn exec_ignore(&self, cmd: &str, args: &[&str]) {
        let mut command = Command::new(cmd);
        command.args(args);
        let _ = namespace::spawn_output(&self.name, command);
    }

    /// Create a veth pair with one end in this namespace and the other
    /// in `peer_ns`.
    ///
    /// Uses `ip link add ... type veth peer name ...` followed by
    /// `ip link set <remote> netns <peer_ns>`, both run inside this
    /// namespace.
    pub fn connect_to(
        &self,
        peer_ns: &LabNamespace,
        local_name: &str,
        remote_name: &str,
    ) -> Result<()> {
        let mut cmd = Command::new("ip");
        cmd.args([
            "link",
            "add",
            local_name,
            "type",
            "veth",
            "peer",
            "name",
            remote_name,
        ]);
        let output = namespace::spawn_output(&self.name, cmd)?;
        if !output.status.success() {
            return Err(crate::Error::InvalidMessage(
                "failed to create veth pair".into(),
            ));
        }

        let mut cmd = Command::new("ip");
        cmd.args(["link", "set", remote_name, "netns", &peer_ns.name]);
        let output = namespace::spawn_output(&self.name, cmd)?;
        if !output.status.success() {
            return Err(crate::Error::InvalidMessage(
                "failed to move veth peer".into(),
            ));
        }

        Ok(())
    }

    /// Create a dummy interface inside this namespace. Convenience
    /// wrapper around `ip link add <name> type dummy`.
    pub fn add_dummy(&self, name: &str) -> Result<()> {
        self.exec("ip", &["link", "add", name, "type", "dummy"])?;
        Ok(())
    }

    /// Bring an interface up. Convenience wrapper around `ip link set
    /// <name> up`.
    pub fn link_up(&self, name: &str) -> Result<()> {
        self.exec("ip", &["link", "set", name, "up"])?;
        Ok(())
    }

    /// Add an IPv4/IPv6 address to an interface. Convenience wrapper
    /// around `ip addr add <addr> dev <dev>`.
    pub fn add_addr(&self, dev: &str, addr: &str) -> Result<()> {
        self.exec("ip", &["addr", "add", addr, "dev", dev])?;
        Ok(())
    }
}

impl Drop for LabNamespace {
    fn drop(&mut self) {
        if let Err(e) = namespace::delete(&self.name) {
            warn!(
                namespace = %self.name,
                error = %e,
                "LabNamespace::drop failed to delete namespace — may need manual cleanup via `ip netns del {}`",
                self.name,
            );
        }
    }
}

/// Run an async closure inside a freshly-created namespace, deleting
/// the namespace when the closure resolves.
///
/// Equivalent to `LabNamespace::new(prefix)` + invoking the closure,
/// but makes the "create, use, destroy" idiom a single expression.
/// Cleanup runs via `LabNamespace::Drop`, so it still happens even
/// if the closure returns an error.
///
/// # Example
///
/// ```no_run
/// # async fn example() -> nlink::Result<()> {
/// use nlink::lab::with_namespace;
/// use nlink::netlink::link::DummyLink;
///
/// with_namespace("probe", |ns| async move {
///     let conn = ns.connection()?;
///     conn.add_link(DummyLink::new("dummy0")).await?;
///     Ok(())
/// })
/// .await?;
/// # Ok(())
/// # }
/// ```
pub async fn with_namespace<F, Fut, T>(prefix: &str, f: F) -> Result<T>
where
    F: FnOnce(LabNamespace) -> Fut,
    Fut: Future<Output = Result<T>>,
{
    let ns = LabNamespace::new(prefix)?;
    f(ns).await
}

/// `true` if the current process has effective UID 0.
pub fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

/// `true` if the named kernel feature is loaded as a module or
/// compiled into the kernel.
///
/// Checks for `/sys/module/<name>`, which sysfs exposes for both
/// loaded loadable modules (after `modprobe`) and built-in features
/// — many distros build common bits like `nf_conntrack` directly
/// into the kernel image, so a `/proc/modules` grep would falsely
/// report them as missing.
///
/// Returns `false` (not an error) when the module is missing, so
/// the caller can decide whether to skip or fail. Also returns
/// `false` for any name containing `/` or `\0` (kernel module names
/// can't legally contain those, and `Path::join` would otherwise
/// silently resolve outside `/sys/module` for an absolute name).
pub fn has_module(name: &str) -> bool {
    if name.is_empty() || name.contains('/') || name.contains('\0') {
        return false;
    }
    std::path::Path::new("/sys/module").join(name).exists()
}

/// Macro that returns early with `Ok(())` if the current process is
/// not running as root, useful for integration tests that need
/// `CAP_SYS_ADMIN`.
///
/// ```ignore
/// #[tokio::test]
/// async fn needs_root() -> nlink::Result<()> {
///     nlink::require_root!();
///     // ... real test body ...
///     Ok(())
/// }
/// ```
#[macro_export]
macro_rules! require_root {
    () => {
        if !$crate::lab::is_root() {
            eprintln!("Skipping test: requires root");
            return Ok(());
        }
    };
}

/// Like [`require_root`] but for test functions whose return type is
/// `()` rather than `Result<()>`.
#[macro_export]
macro_rules! require_root_void {
    () => {
        if !$crate::lab::is_root() {
            eprintln!("Skipping test: requires root");
            return;
        }
    };
}

/// Macro that returns early with `Ok(())` if the named kernel
/// module isn't loaded or built-in. Use this in integration tests
/// that depend on a specific kernel feature (`nf_conntrack`,
/// `cls_flower`, `xfrm_user`, etc.) so a missing module produces a
/// clean skip rather than a cryptic `is_not_supported()` error
/// deep in the test body.
///
/// Wraps [`has_module`]. Pair with [`require_root`] — the module
/// can only be checked once the test is actually trying to run.
///
/// ```ignore
/// #[tokio::test]
/// async fn needs_conntrack() -> nlink::Result<()> {
///     nlink::require_root!();
///     nlink::require_module!("nf_conntrack");
///     nlink::require_module!("nf_conntrack_netlink");
///     // ... real test body ...
///     Ok(())
/// }
/// ```
#[macro_export]
macro_rules! require_module {
    ($name:expr) => {
        if !$crate::lab::has_module($name) {
            eprintln!(
                "Skipping test: kernel module '{}' not loaded or built-in",
                $name
            );
            return Ok(());
        }
    };
}

/// Like [`require_module`] but for test functions whose return type
/// is `()` rather than `Result<()>`.
#[macro_export]
macro_rules! require_module_void {
    ($name:expr) => {
        if !$crate::lab::has_module($name) {
            eprintln!(
                "Skipping test: kernel module '{}' not loaded or built-in",
                $name
            );
            return;
        }
    };
}

/// Require multiple kernel modules in one call. Skips the test
/// (returning `Ok(())`) if any of the named modules is not
/// loaded or built-in. Convenience for tests that touch several
/// independent kernel features.
///
/// ```ignore
/// #[tokio::test]
/// async fn needs_htb_and_flower() -> nlink::Result<()> {
///     nlink::require_root!();
///     nlink::require_modules!("sch_htb", "cls_flower");
///     // ...
/// }
/// ```
#[macro_export]
macro_rules! require_modules {
    ($($name:expr),+ $(,)?) => {
        $( $crate::require_module!($name); )+
    };
}

/// Require that a sysctl path exists and is writable. Used by
/// sysctl write tests that need `/proc/sys/...` to be RW (some
/// container configurations mount it read-only). Skips the
/// test (returning `Ok(())`) if the path is not writable.
///
/// ```ignore
/// nlink::require_writable_sysctl!("/proc/sys/net/ipv4/ip_forward");
/// ```
#[macro_export]
macro_rules! require_writable_sysctl {
    ($path:expr) => {
        match std::fs::OpenOptions::new().write(true).open($path) {
            Ok(_) => {}
            Err(e) => {
                eprintln!(
                    "Skipping test: sysctl '{}' not writable ({}); \
                     /proc/sys may be read-only in this environment",
                    $path, e
                );
                return Ok(());
            }
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unique_ns_name() {
        let n1 = unique_ns_name("probe");
        let n2 = unique_ns_name("probe");
        assert_ne!(n1, n2);
        assert!(n1.starts_with("nlink-lab-probe-"));
    }

    #[test]
    fn has_module_returns_false_for_unknown_name() {
        assert!(!has_module("nlink_definitely_not_a_real_module_xyzzy"));
    }

    #[test]
    fn has_module_rejects_path_traversal() {
        // Names containing '/' or NUL aren't valid kernel module names
        // and would let `Path::join` resolve outside /sys/module on an
        // absolute component.
        assert!(!has_module(""));
        assert!(!has_module("/etc/passwd"));
        assert!(!has_module("../../etc/passwd"));
        assert!(!has_module("nf_conntrack/foo"));
        assert!(!has_module("nf\0conntrack"));
    }
}
