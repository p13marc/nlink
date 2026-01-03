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
use super::protocol::ProtocolState;

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
    pub fn connection<P: ProtocolState>(&self) -> Result<Connection<P>> {
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
pub fn connection_for<P: ProtocolState>(name: &str) -> Result<Connection<P>> {
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
pub fn connection_for_path<P: ProtocolState, T: AsRef<Path>>(path: T) -> Result<Connection<P>> {
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
pub fn connection_for_pid<P: ProtocolState>(pid: u32) -> Result<Connection<P>> {
    let path = format!("/proc/{}/ns/net", pid);
    connection_for_path(&path)
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
    let original = File::open("/proc/self/ns/net")
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
        // (opened from /proc/self/ns/net when the guard was created).
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
