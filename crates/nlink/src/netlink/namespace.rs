//! Network namespace utilities.
//!
//! This module provides utilities for working with Linux network namespaces,
//! including executing operations in specific namespaces and managing namespace
//! file descriptors.
//!
//! # Example
//!
//! ```ignore
//! use nlink::netlink::namespace;
//! use nlink::netlink::{Connection, Route, Generic};
//!
//! // Get a Route connection for a named namespace
//! let conn: Connection<Route> = namespace::connection_for("myns")?;
//! let links = conn.get_links().await?;
//!
//! // Or a Generic connection for WireGuard in a namespace
//! let conn: Connection<Generic> = namespace::connection_for("myns")?;
//!
//! // Or use a path directly
//! let conn: Connection<Route> = namespace::connection_for_path("/proc/1234/ns/net")?;
//!
//! // Or use NamespaceSpec for a unified API
//! use nlink::netlink::namespace::NamespaceSpec;
//!
//! let spec = NamespaceSpec::Named("myns");
//! let conn: Connection<Route> = spec.connection()?;
//! ```

use std::fs::File;
use std::os::unix::io::{AsRawFd, RawFd};
use std::path::{Path, PathBuf};

use super::connection::Connection;
use super::error::{Error, Result};
use super::protocol::{AsyncProtocolInit, ProtocolState};
use super::socket::NetlinkSocket;

/// Specification for which network namespace to use.
///
/// This enum provides a unified way to specify a network namespace,
/// whether it's the default namespace, a named namespace, a path,
/// or a process's namespace.
///
/// # Example
///
/// ```ignore
/// use nlink::netlink::{Connection, Route};
/// use nlink::netlink::namespace::NamespaceSpec;
///
/// // Different ways to specify a namespace
/// let default = NamespaceSpec::Default;
/// let named = NamespaceSpec::Named("myns");
/// let by_path = NamespaceSpec::Path(Path::new("/proc/1234/ns/net"));
/// let by_pid = NamespaceSpec::Pid(1234);
///
/// // Create connections (generic over protocol type)
/// let conn: Connection<Route> = named.connection()?;
/// ```
#[derive(Debug, Clone)]
pub enum NamespaceSpec<'a> {
    /// Use the current/default namespace.
    Default,
    /// Use a named namespace (from /var/run/netns/).
    Named(&'a str),
    /// Use a namespace specified by path.
    Path(&'a Path),
    /// Use a process's namespace by PID.
    Pid(u32),
}

impl<'a> NamespaceSpec<'a> {
    /// Create a connection for this namespace specification.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use nlink::netlink::namespace::NamespaceSpec;
    /// use nlink::netlink::protocol::Route;
    ///
    /// let spec = NamespaceSpec::Named("myns");
    /// let conn: Connection<Route> = spec.connection()?;
    /// let links = conn.get_links().await?;
    /// ```
    pub fn connection<P: ProtocolState + Default>(&self) -> Result<Connection<P>> {
        match self {
            NamespaceSpec::Default => Connection::<P>::new(),
            NamespaceSpec::Named(name) => connection_for(name),
            NamespaceSpec::Path(path) => connection_for_path(path),
            NamespaceSpec::Pid(pid) => connection_for_pid(*pid),
        }
    }

    /// Check if this refers to the default namespace.
    #[inline]
    pub fn is_default(&self) -> bool {
        matches!(self, NamespaceSpec::Default)
    }

    /// Spawn a process in this namespace.
    ///
    /// For [`NamespaceSpec::Default`], the command is spawned normally without
    /// any namespace switching.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use nlink::netlink::namespace::NamespaceSpec;
    /// use std::process::Command;
    ///
    /// let spec = NamespaceSpec::Named("myns");
    /// let mut child = spec.spawn(Command::new("ip").arg("link"))?;
    /// child.wait()?;
    /// ```
    pub fn spawn(&self, cmd: std::process::Command) -> Result<std::process::Child> {
        match self {
            NamespaceSpec::Default => {
                let mut cmd = cmd;
                cmd.spawn().map_err(Error::Io)
            }
            NamespaceSpec::Named(name) => spawn(name, cmd),
            NamespaceSpec::Path(path) => spawn_path(path, cmd),
            NamespaceSpec::Pid(pid) => {
                let path = format!("/proc/{}/ns/net", pid);
                spawn_path(&path, cmd)
            }
        }
    }

    /// Spawn a process and collect its output in this namespace.
    ///
    /// See [`spawn_output`] for details.
    pub fn spawn_output(&self, cmd: std::process::Command) -> Result<std::process::Output> {
        match self {
            NamespaceSpec::Default => {
                let mut cmd = cmd;
                cmd.stdout(std::process::Stdio::piped());
                cmd.stderr(std::process::Stdio::piped());
                let child = cmd.spawn().map_err(Error::Io)?;
                child.wait_with_output().map_err(Error::Io)
            }
            NamespaceSpec::Named(name) => spawn_output(name, cmd),
            NamespaceSpec::Path(path) => spawn_output_path(path, cmd),
            NamespaceSpec::Pid(pid) => {
                let path = format!("/proc/{}/ns/net", pid);
                spawn_output_path(&path, cmd)
            }
        }
    }
}

/// The runtime directory where named network namespaces are stored.
pub const NETNS_RUN_DIR: &str = "/var/run/netns";

/// Get a connection for a named network namespace.
///
/// Named namespaces are those created via `ip netns add <name>` and stored
/// in `/var/run/netns/`.
///
/// # Example
///
/// ```ignore
/// use nlink::netlink::namespace;
/// use nlink::netlink::protocol::Route;
///
/// // Create a connection to work in the "production" namespace
/// let conn: Connection<Route> = namespace::connection_for("production")?;
/// let links = conn.get_links().await?;
/// ```
pub fn connection_for<P: ProtocolState + Default>(name: &str) -> Result<Connection<P>> {
    let path = PathBuf::from(NETNS_RUN_DIR).join(name);
    connection_for_path(&path)
}

/// Get a connection for a network namespace specified by path.
///
/// This works with any namespace file path, including:
/// - Named namespaces: `/var/run/netns/<name>`
/// - Process namespaces: `/proc/<pid>/ns/net`
/// - Container namespaces: `/proc/<container_init_pid>/ns/net`
///
/// # Example
///
/// ```ignore
/// use nlink::netlink::namespace;
/// use nlink::netlink::protocol::Route;
///
/// // For a container's namespace
/// let conn: Connection<Route> = namespace::connection_for_path("/proc/1234/ns/net")?;
/// let links = conn.get_links().await?;
/// ```
pub fn connection_for_path<P: ProtocolState + Default, T: AsRef<Path>>(
    path: T,
) -> Result<Connection<P>> {
    Connection::<P>::new_in_namespace_path(path)
}

/// Get a connection for a process's network namespace.
///
/// # Example
///
/// ```ignore
/// use nlink::netlink::namespace;
/// use nlink::netlink::protocol::Route;
///
/// // Get interfaces visible to process 1234
/// let conn: Connection<Route> = namespace::connection_for_pid(1234)?;
/// let links = conn.get_links().await?;
/// ```
pub fn connection_for_pid<P: ProtocolState + Default>(pid: u32) -> Result<Connection<P>> {
    let path = format!("/proc/{}/ns/net", pid);
    connection_for_path(&path)
}

/// Get an async-initialized connection for a named network namespace.
///
/// This is for GENL protocols (WireGuard, MACsec, MPTCP, Ethtool, nl80211, Devlink)
/// that need async family ID resolution after socket creation. The socket is created
/// in the target namespace, then the GENL family is resolved through that socket.
///
/// # Example
///
/// ```ignore
/// use nlink::netlink::{Connection, Wireguard, namespace};
///
/// let conn: Connection<Wireguard> = namespace::connection_for_async("myns").await?;
/// let device = conn.get_device("wg0").await?;
/// ```
pub async fn connection_for_async<P: AsyncProtocolInit>(name: &str) -> Result<Connection<P>> {
    let path = PathBuf::from(NETNS_RUN_DIR).join(name);
    connection_for_path_async(&path).await
}

/// Get an async-initialized connection for a namespace specified by path.
///
/// See [`connection_for_async`] for details.
pub async fn connection_for_path_async<P: AsyncProtocolInit, T: AsRef<Path>>(
    path: T,
) -> Result<Connection<P>> {
    let socket = NetlinkSocket::new_in_namespace_path(P::PROTOCOL, path)?;
    let state = P::resolve_async(&socket).await?;
    Ok(Connection::from_parts(socket, state))
}

/// Get an async-initialized connection for a process's network namespace.
///
/// See [`connection_for_async`] for details.
pub async fn connection_for_pid_async<P: AsyncProtocolInit>(pid: u32) -> Result<Connection<P>> {
    let path = format!("/proc/{}/ns/net", pid);
    connection_for_path_async(&path).await
}

/// Open a namespace file and return its file descriptor.
///
/// The returned `NamespaceFd` keeps the file open and can be used with
/// [`Connection::new_in_namespace`] or [`enter`].
///
/// # Example
///
/// ```ignore
/// use nlink::netlink::namespace;
/// use nlink::netlink::{Connection, Protocol};
///
/// let ns = namespace::open("myns")?;
/// let conn = Connection::new_in_namespace(Protocol::Route, ns.as_raw_fd())?;
/// ```
pub fn open(name: &str) -> Result<NamespaceFd> {
    let path = PathBuf::from(NETNS_RUN_DIR).join(name);
    open_path(&path)
}

/// Open a namespace file by path and return its file descriptor.
pub fn open_path<P: AsRef<Path>>(path: P) -> Result<NamespaceFd> {
    let file = File::open(path.as_ref()).map_err(|e| {
        Error::InvalidMessage(format!(
            "cannot open namespace '{}': {}",
            path.as_ref().display(),
            e
        ))
    })?;
    Ok(NamespaceFd { file })
}

/// Open a process's namespace and return its file descriptor.
pub fn open_pid(pid: u32) -> Result<NamespaceFd> {
    let path = format!("/proc/{}/ns/net", pid);
    open_path(&path)
}

/// A handle to an open namespace file.
///
/// This keeps the namespace file open so it can be used multiple times
/// with [`Connection::new_in_namespace`].
#[derive(Debug)]
pub struct NamespaceFd {
    file: File,
}

impl NamespaceFd {
    /// Get the raw file descriptor.
    pub fn as_raw_fd(&self) -> RawFd {
        self.file.as_raw_fd()
    }
}

impl AsRawFd for NamespaceFd {
    fn as_raw_fd(&self) -> RawFd {
        self.file.as_raw_fd()
    }
}

/// Enter a network namespace temporarily.
///
/// This function switches the current thread to the specified network namespace.
/// Use [`NamespaceGuard::restore`] or drop the guard to return to the original namespace.
///
/// # Warning
///
/// This affects the entire thread. In async contexts, prefer using
/// [`connection_for`] or [`Connection::new_in_namespace_path`] instead,
/// which create a socket in the namespace without affecting the thread.
///
/// # Example
///
/// ```ignore
/// use nlink::netlink::namespace;
///
/// let guard = namespace::enter("myns")?;
/// // Now in "myns" namespace
/// // ... do something ...
/// guard.restore()?;  // Or just drop it
/// ```
pub fn enter(name: &str) -> Result<NamespaceGuard> {
    let path = PathBuf::from(NETNS_RUN_DIR).join(name);
    enter_path(&path)
}

/// Enter a network namespace by path.
pub fn enter_path<P: AsRef<Path>>(path: P) -> Result<NamespaceGuard> {
    // Save the current namespace
    let original = File::open("/proc/thread-self/ns/net")
        .map_err(|e| Error::InvalidMessage(format!("cannot open current namespace: {}", e)))?;

    // Open and enter the target namespace
    let target = File::open(path.as_ref()).map_err(|e| {
        Error::InvalidMessage(format!(
            "cannot open namespace '{}': {}",
            path.as_ref().display(),
            e
        ))
    })?;

    // SAFETY: libc::setns is a standard Linux syscall for switching namespaces.
    // target.as_raw_fd() is a valid fd to a namespace file, CLONE_NEWNET
    // specifies we're switching the network namespace.
    let ret = unsafe { libc::setns(target.as_raw_fd(), libc::CLONE_NEWNET) };
    if ret < 0 {
        return Err(Error::Io(std::io::Error::last_os_error()));
    }

    Ok(NamespaceGuard { original })
}

/// A guard that restores the original namespace when dropped.
#[derive(Debug)]
pub struct NamespaceGuard {
    original: File,
}

impl NamespaceGuard {
    /// Restore the original namespace explicitly.
    ///
    /// This is called automatically on drop, but calling it explicitly
    /// allows you to handle errors.
    pub fn restore(self) -> Result<()> {
        self.do_restore()
    }

    fn do_restore(&self) -> Result<()> {
        // SAFETY: libc::setns restores the original namespace. The fd is valid
        // (opened from /proc/thread-self/ns/net when the guard was created).
        let ret = unsafe { libc::setns(self.original.as_raw_fd(), libc::CLONE_NEWNET) };
        if ret < 0 {
            return Err(Error::Io(std::io::Error::last_os_error()));
        }
        Ok(())
    }
}

impl Drop for NamespaceGuard {
    fn drop(&mut self) {
        if let Err(e) = self.do_restore() {
            eprintln!("warning: failed to restore namespace: {}", e);
        }
    }
}

/// Check if a named namespace exists.
///
/// # Example
///
/// ```ignore
/// use nlink::netlink::{Connection, Route, namespace};
///
/// if namespace::exists("myns") {
///     let conn: Connection<Route> = namespace::connection_for("myns")?;
///     // ...
/// }
/// ```
pub fn exists(name: &str) -> bool {
    let path = PathBuf::from(NETNS_RUN_DIR).join(name);
    path.exists()
}

/// Create a named network namespace.
///
/// This is equivalent to `ip netns add <name>`. It creates the namespace
/// directory if needed, creates a new network namespace, and bind-mounts
/// it to `/var/run/netns/<name>`.
///
/// # Errors
///
/// Returns an error if:
/// - The namespace already exists
/// - Permission is denied (requires root or CAP_SYS_ADMIN)
/// - The namespace directory cannot be created
///
/// # Example
///
/// ```ignore
/// use nlink::netlink::namespace;
///
/// namespace::create("myns")?;
/// // Now "myns" exists and can be used
/// let conn = namespace::connection_for("myns")?;
/// ```
pub fn create(name: &str) -> Result<()> {
    let ns_path = PathBuf::from(NETNS_RUN_DIR).join(name);

    // Check if namespace already exists
    if ns_path.exists() {
        return Err(Error::InvalidMessage(format!(
            "namespace '{}' already exists",
            name
        )));
    }

    // Create the netns directory if it doesn't exist
    if !Path::new(NETNS_RUN_DIR).exists() {
        std::fs::create_dir_all(NETNS_RUN_DIR).map_err(|e| {
            Error::InvalidMessage(format!("cannot create {}: {}", NETNS_RUN_DIR, e))
        })?;
    }

    // Create an empty file for the bind mount
    File::create(&ns_path).map_err(|e| {
        Error::InvalidMessage(format!("cannot create namespace file '{}': {}", name, e))
    })?;

    // Save the current namespace so we can restore after unshare.
    // Without this, unshare(CLONE_NEWNET) permanently changes the calling
    // thread's namespace, breaking subsequent namespace operations.
    let original_ns = File::open("/proc/thread-self/ns/net").map_err(|e| {
        let _ = std::fs::remove_file(&ns_path);
        Error::InvalidMessage(format!("cannot save current namespace: {}", e))
    })?;

    // Create a new network namespace
    // SAFETY: unshare is a standard Linux syscall. CLONE_NEWNET creates a new
    // network namespace for the current process.
    let ret = unsafe { libc::unshare(libc::CLONE_NEWNET) };
    if ret < 0 {
        // Clean up the file we created
        let _ = std::fs::remove_file(&ns_path);
        return Err(Error::Io(std::io::Error::last_os_error()));
    }

    // Bind mount the namespace to the file
    let ns_path_cstr =
        std::ffi::CString::new(ns_path.to_string_lossy().as_bytes()).map_err(|_| {
            let _ = std::fs::remove_file(&ns_path);
            Error::InvalidMessage("invalid namespace path".to_string())
        })?;

    let self_ns = std::ffi::CString::new("/proc/thread-self/ns/net").unwrap();

    // SAFETY: mount is a standard Linux syscall. We're bind-mounting the current
    // process's network namespace (which we just created) to the namespace file.
    let ret = unsafe {
        libc::mount(
            self_ns.as_ptr(),
            ns_path_cstr.as_ptr(),
            std::ptr::null(),
            libc::MS_BIND,
            std::ptr::null(),
        )
    };

    if ret < 0 {
        let err = std::io::Error::last_os_error();
        // Try to restore original namespace before returning
        unsafe { libc::setns(original_ns.as_raw_fd(), libc::CLONE_NEWNET) };
        let _ = std::fs::remove_file(&ns_path);
        return Err(Error::Io(err));
    }

    // Restore the calling thread to its original namespace.
    // SAFETY: setns is a standard Linux syscall. original_ns is a valid FD
    // to the namespace we opened before unshare().
    let ret = unsafe { libc::setns(original_ns.as_raw_fd(), libc::CLONE_NEWNET) };
    if ret < 0 {
        // The namespace was created and persisted via bind mount, but we
        // failed to restore. Log a warning — this is a serious issue.
        return Err(Error::InvalidMessage(format!(
            "namespace '{}' created but failed to restore original namespace: {}",
            name,
            std::io::Error::last_os_error()
        )));
    }

    Ok(())
}

/// Delete a named network namespace.
///
/// This is equivalent to `ip netns del <name>`. It unmounts and removes
/// the namespace file from `/var/run/netns/<name>`.
///
/// # Errors
///
/// Returns an error if:
/// - The namespace doesn't exist
/// - Permission is denied
/// - The unmount fails (e.g., namespace is in use)
///
/// # Example
///
/// ```ignore
/// use nlink::netlink::namespace;
///
/// namespace::delete("myns")?;
/// ```
pub fn delete(name: &str) -> Result<()> {
    let ns_path = PathBuf::from(NETNS_RUN_DIR).join(name);

    if !ns_path.exists() {
        return Err(Error::NamespaceNotFound {
            name: name.to_string(),
        });
    }

    let ns_path_cstr = std::ffi::CString::new(ns_path.to_string_lossy().as_bytes())
        .map_err(|_| Error::InvalidMessage("invalid namespace path".to_string()))?;

    // Unmount the namespace
    // SAFETY: umount2 is a standard Linux syscall. MNT_DETACH allows lazy
    // unmounting which succeeds even if the mount is busy.
    let ret = unsafe { libc::umount2(ns_path_cstr.as_ptr(), libc::MNT_DETACH) };
    if ret < 0 {
        let err = std::io::Error::last_os_error();
        // EINVAL means it's not a mount point (maybe already unmounted)
        if err.raw_os_error() != Some(libc::EINVAL) {
            return Err(Error::Io(err));
        }
    }

    // Remove the file
    std::fs::remove_file(&ns_path)
        .map_err(|e| Error::InvalidMessage(format!("cannot remove namespace file: {}", e)))?;

    Ok(())
}

/// Execute a function in a network namespace and return to the original.
///
/// This is a convenience wrapper around [`enter`] that ensures the original
/// namespace is restored even if the function panics.
///
/// # Warning
///
/// This affects the entire thread. In async contexts, prefer using
/// [`connection_for`] which creates a socket in the namespace without
/// affecting the thread state.
///
/// # Example
///
/// ```ignore
/// use nlink::netlink::namespace;
///
/// let result = namespace::execute_in("myns", || {
///     // Code here runs in "myns" namespace
///     std::fs::read_to_string("/proc/net/dev")
/// })??;
/// // Back in original namespace
/// ```
pub fn execute_in<F, T>(name: &str, f: F) -> Result<T>
where
    F: FnOnce() -> T,
{
    let guard = enter(name)?;
    let result = f();
    guard.restore()?;
    Ok(result)
}

/// Execute a function in a network namespace specified by path.
///
/// See [`execute_in`] for details.
pub fn execute_in_path<F, T, P: AsRef<Path>>(path: P, f: F) -> Result<T>
where
    F: FnOnce() -> T,
{
    let guard = enter_path(path)?;
    let result = f();
    guard.restore()?;
    Ok(result)
}

/// List all named network namespaces.
///
/// Returns the names of namespaces in `/var/run/netns/`.
///
/// # Example
///
/// ```ignore
/// use nlink::netlink::namespace;
///
/// for ns in namespace::list()? {
///     println!("Namespace: {}", ns);
/// }
/// ```
pub fn list() -> Result<Vec<String>> {
    let dir = match std::fs::read_dir(NETNS_RUN_DIR) {
        Ok(d) => d,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // No namespaces directory means no namespaces
            return Ok(Vec::new());
        }
        Err(e) => {
            return Err(Error::Io(e));
        }
    };

    let mut names = Vec::new();
    for entry in dir {
        let entry = entry.map_err(Error::Io)?;
        let name = entry.file_name().to_string_lossy().to_string();
        if name != "." && name != ".." {
            names.push(name);
        }
    }

    names.sort();
    Ok(names)
}

// ─────────────────────────────────────────────────
// Sysctl operations (namespace-aware)
// ─────────────────────────────────────────────────

/// Read a sysctl value inside a named namespace.
///
/// Temporarily enters the namespace, reads the value from `/proc/sys/`,
/// and restores the original namespace.
///
/// # Example
///
/// ```ignore
/// use nlink::netlink::namespace;
///
/// let val = namespace::get_sysctl("myns", "net.ipv4.ip_forward")?;
/// assert!(val == "0" || val == "1");
/// ```
pub fn get_sysctl(ns_name: &str, key: &str) -> Result<String> {
    execute_in(ns_name, || super::sysctl::get(key))?
}

/// Set a sysctl value inside a named namespace.
///
/// Temporarily enters the namespace, writes the value to `/proc/sys/`,
/// and restores the original namespace. Requires root or `CAP_SYS_ADMIN`.
///
/// # Example
///
/// ```ignore
/// use nlink::netlink::namespace;
///
/// namespace::set_sysctl("myns", "net.ipv4.ip_forward", "1")?;
/// ```
pub fn set_sysctl(ns_name: &str, key: &str, value: &str) -> Result<()> {
    execute_in(ns_name, || super::sysctl::set(key, value))?
}

/// Set multiple sysctl values inside a named namespace.
///
/// Enters the namespace once and applies all entries. If any entry fails,
/// returns the error immediately without applying remaining entries.
///
/// # Example
///
/// ```ignore
/// use nlink::netlink::namespace;
///
/// namespace::set_sysctls("myns", &[
///     ("net.ipv4.ip_forward", "1"),
///     ("net.ipv6.conf.all.forwarding", "1"),
/// ])?;
/// ```
pub fn set_sysctls(ns_name: &str, entries: &[(&str, &str)]) -> Result<()> {
    execute_in(ns_name, || super::sysctl::set_many(entries))?
}

/// Read a sysctl value inside a namespace specified by path.
///
/// See [`get_sysctl`] for details.
pub fn get_sysctl_path<P: AsRef<Path>>(path: P, key: &str) -> Result<String> {
    execute_in_path(path, || super::sysctl::get(key))?
}

/// Set a sysctl value inside a namespace specified by path.
///
/// See [`set_sysctl`] for details.
pub fn set_sysctl_path<P: AsRef<Path>>(path: P, key: &str, value: &str) -> Result<()> {
    execute_in_path(path, || super::sysctl::set(key, value))?
}

/// Set multiple sysctl values inside a namespace specified by path.
///
/// See [`set_sysctls`] for details.
pub fn set_sysctls_path<P: AsRef<Path>>(path: P, entries: &[(&str, &str)]) -> Result<()> {
    execute_in_path(path, || super::sysctl::set_many(entries))?
}

// ─────────────────────────────────────────────────
// Process spawning (namespace-aware)
// ─────────────────────────────────────────────────

/// Spawn a process inside a named network namespace.
///
/// Uses `pre_exec` + `setns()` to switch the child process into the target
/// namespace between `fork()` and `exec()`. The parent process is unaffected.
///
/// # Example
///
/// ```ignore
/// use nlink::netlink::namespace;
/// use std::process::Command;
///
/// let mut child = namespace::spawn("myns", Command::new("ip").arg("link"))?;
/// child.wait()?;
/// ```
pub fn spawn(ns_name: &str, cmd: std::process::Command) -> Result<std::process::Child> {
    let path = PathBuf::from(NETNS_RUN_DIR).join(ns_name);
    if !path.exists() {
        return Err(Error::NamespaceNotFound {
            name: ns_name.to_string(),
        });
    }
    spawn_path(&path, cmd)
}

/// Spawn a process and collect its output inside a named namespace.
///
/// This is a convenience wrapper that spawns the process with stdout and
/// stderr captured, waits for it to complete, and returns the output.
///
/// # Example
///
/// ```ignore
/// use nlink::netlink::namespace;
/// use std::process::Command;
///
/// let output = namespace::spawn_output("myns", Command::new("ip").arg("addr"))?;
/// println!("{}", String::from_utf8_lossy(&output.stdout));
/// ```
pub fn spawn_output(ns_name: &str, mut cmd: std::process::Command) -> Result<std::process::Output> {
    cmd.stdout(std::process::Stdio::piped());
    cmd.stderr(std::process::Stdio::piped());
    let child = spawn(ns_name, cmd)?;
    child.wait_with_output().map_err(Error::Io)
}

/// Spawn a process inside a namespace specified by path.
///
/// See [`spawn`] for details.
///
/// # Example
///
/// ```ignore
/// use nlink::netlink::namespace;
/// use std::process::Command;
///
/// let child = namespace::spawn_path(
///     "/proc/1234/ns/net",
///     Command::new("ip").arg("link"),
/// )?;
/// ```
pub fn spawn_path<P: AsRef<Path>>(
    path: P,
    mut cmd: std::process::Command,
) -> Result<std::process::Child> {
    use std::os::unix::process::CommandExt;

    let ns_fd = open_path(path)?;
    let raw_fd = ns_fd.as_raw_fd();

    // SAFETY: setns is async-signal-safe (it's a syscall). pre_exec runs in
    // the child process after fork() but before exec(). The fd is valid
    // because ns_fd is kept alive until after spawn() returns — the closure
    // captures raw_fd by value, and ns_fd is dropped only after spawn().
    unsafe {
        cmd.pre_exec(move || {
            if libc::setns(raw_fd, libc::CLONE_NEWNET) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }

    let child = cmd.spawn().map_err(Error::Io)?;
    drop(ns_fd);
    Ok(child)
}

/// Spawn a process and collect its output inside a namespace specified by path.
///
/// See [`spawn_output`] for details.
pub fn spawn_output_path<P: AsRef<Path>>(
    path: P,
    mut cmd: std::process::Command,
) -> Result<std::process::Output> {
    cmd.stdout(std::process::Stdio::piped());
    cmd.stderr(std::process::Stdio::piped());
    let child = spawn_path(path, cmd)?;
    child.wait_with_output().map_err(Error::Io)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_netns_run_dir() {
        assert_eq!(NETNS_RUN_DIR, "/var/run/netns");
    }

    #[test]
    fn test_list_namespaces() {
        // This should not fail even if the directory doesn't exist
        let result = list();
        assert!(result.is_ok());
    }

    #[test]
    fn test_exists_nonexistent() {
        assert!(!exists("definitely_does_not_exist_12345"));
    }
}
