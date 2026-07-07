//! Network namespace utilities.
//!
//! This module provides utilities for working with Linux network namespaces,
//! including executing operations in specific namespaces and managing namespace
//! file descriptors.
//!
//! [`create`]/[`delete`] persist a netns at the `ip netns` convention
//! `/var/run/netns/<name>`. [`create_path`]/[`delete_path`] persist it at any
//! caller-chosen path, so an application can own its netns directory (clearer
//! ownership, no collisions with operator `ip netns add`).
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

use std::{
    fs::File,
    os::unix::{ffi::OsStrExt, io::{AsRawFd, RawFd}},
    path::{Path, PathBuf},
};

use super::{
    connection::Connection,
    error::{Error, Result},
    protocol::{
        construction::{AsyncConstructible, SyncConstructible},
        AsyncProtocolInit, ProtocolState,
    },
    socket::NetlinkSocket,
};

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
#[non_exhaustive]
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
    pub fn connection<P: ProtocolState + Default + SyncConstructible>(&self) -> Result<Connection<P>> {
        match self {
            NamespaceSpec::Default => Connection::<P>::new(),
            NamespaceSpec::Named(name) => connection_for(name),
            NamespaceSpec::Path(path) => connection_for_path(path),
            NamespaceSpec::Pid(pid) => connection_for_pid(*pid),
        }
    }

    /// Create an async-initialized connection (GENL families that
    /// need family-ID resolution — WireGuard, MACsec, …) for this
    /// namespace specification. Async counterpart of
    /// [`connection`](Self::connection) (#169).
    pub async fn connection_async<P: AsyncProtocolInit + AsyncConstructible>(
        &self,
    ) -> Result<Connection<P>> {
        match self {
            NamespaceSpec::Default => Connection::<P>::new_async().await,
            NamespaceSpec::Named(name) => connection_for_async(name).await,
            NamespaceSpec::Path(path) => connection_for_path_async(path).await,
            NamespaceSpec::Pid(pid) => connection_for_pid_async(*pid).await,
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

    /// Spawn a process with `/etc/netns/` file overlays.
    ///
    /// See [`spawn_with_etc`] for details. For [`NamespaceSpec::Path`] and
    /// [`NamespaceSpec::Pid`], falls back to regular [`spawn_path`] (no overlay).
    pub fn spawn_with_etc(&self, cmd: std::process::Command) -> Result<std::process::Child> {
        match self {
            NamespaceSpec::Default => {
                let mut cmd = cmd;
                cmd.spawn().map_err(Error::Io)
            }
            NamespaceSpec::Named(name) => spawn_with_etc(name, cmd),
            NamespaceSpec::Path(path) => spawn_path(path, cmd),
            NamespaceSpec::Pid(pid) => {
                let path = format!("/proc/{}/ns/net", pid);
                spawn_path(&path, cmd)
            }
        }
    }

    /// Spawn a process and collect its output with `/etc/netns/` file overlays.
    ///
    /// See [`spawn_with_etc`] for details. For [`NamespaceSpec::Path`] and
    /// [`NamespaceSpec::Pid`], falls back to regular [`spawn_output_path`] (no overlay).
    pub fn spawn_output_with_etc(
        &self,
        cmd: std::process::Command,
    ) -> Result<std::process::Output> {
        match self {
            NamespaceSpec::Default => {
                let mut cmd = cmd;
                cmd.stdout(std::process::Stdio::piped());
                cmd.stderr(std::process::Stdio::piped());
                let child = cmd.spawn().map_err(Error::Io)?;
                child.wait_with_output().map_err(Error::Io)
            }
            NamespaceSpec::Named(name) => spawn_output_with_etc(name, cmd),
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
pub fn connection_for<P: ProtocolState + Default + SyncConstructible>(name: &str) -> Result<Connection<P>> {
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
pub fn connection_for_path<P: ProtocolState + Default + SyncConstructible, T: AsRef<Path>>(
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
pub fn connection_for_pid<P: ProtocolState + Default + SyncConstructible>(pid: u32) -> Result<Connection<P>> {
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
pub async fn connection_for_async<P: AsyncProtocolInit + AsyncConstructible>(name: &str) -> Result<Connection<P>> {
    let path = PathBuf::from(NETNS_RUN_DIR).join(name);
    connection_for_path_async(&path).await
}

/// Get an async-initialized connection for a namespace specified by path.
///
/// See [`connection_for_async`] for details.
pub async fn connection_for_path_async<P: AsyncProtocolInit + AsyncConstructible, T: AsRef<Path>>(
    path: T,
) -> Result<Connection<P>> {
    let socket = NetlinkSocket::new_in_namespace_path(P::PROTOCOL, path)?;
    let state = P::resolve_async(&socket).await?;
    Ok(Connection::from_parts(socket, state))
}

/// Get an async-initialized connection for a process's network namespace.
///
/// See [`connection_for_async`] for details.
pub async fn connection_for_pid_async<P: AsyncProtocolInit + AsyncConstructible>(pid: u32) -> Result<Connection<P>> {
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
            // We cannot return an error from Drop. Emit a structured
            // tracing event so observers see the failure (replaces the
            // pre-0.16.0 `eprintln!` — consistent with the broader
            // eprintln→tracing audit in Plan 147 §9.2). Callers that
            // need explicit detection should restore the namespace via
            // an explicit call before dropping the guard.
            tracing::error!(
                error = %e,
                "NamespaceGuard::drop: failed to restore original namespace; thread may be stuck"
            );
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

/// Convert a filesystem path to a `CString`, preserving its exact bytes.
/// Linux paths aren't necessarily UTF-8, so this goes through `OsStr` bytes
/// rather than `to_string_lossy` (which would mangle non-UTF-8 paths into a
/// different path than the one on disk). Errors only on an interior NUL.
fn path_to_cstring(path: &Path) -> Result<std::ffi::CString> {
    std::ffi::CString::new(path.as_os_str().as_bytes())
        .map_err(|_| Error::InvalidMessage(format!("invalid namespace path '{}'", path.display())))
}

/// `nsfs` superblock magic (`NSFS_MAGIC` from `<linux/magic.h>` — ASCII
/// "nsfs"). Backs `/proc/<pid>/ns/*` and bind-mounts of them. Not exported by
/// the `libc` crate, so defined here. Compared as `u64`: `statfs.f_type`
/// varies in type across libc/arch (`__fsword_t` on glibc x86_64, `c_ulong`
/// on musl, `c_uint` on s390x), so we widen at the comparison rather than pin
/// a type the field doesn't always have.
const NSFS_MAGIC: u64 = 0x6e_73_66_73;

/// Return `true` if `path` is a *live* network-namespace bind-mount.
///
/// A persistent netns (see [`create_path`]) is a bind-mount of an `nsfs` inode
/// onto a marker file. After an unclean shutdown the marker can linger as an
/// ordinary file with the bind-mount gone — present on disk but no longer a
/// namespace. This distinguishes the two via `statfs(2)`: a live netns
/// bind-mount sits on the `nsfs` pseudo-filesystem; a stale marker sits on
/// whatever backs its parent directory (typically `tmpfs`).
///
/// Returns `false` (never errors) when the path is absent, unreadable, or
/// backed by any non-`nsfs` filesystem, mirroring [`exists`].
///
/// `/proc/mounts` is deliberately **not** consulted: mount-namespace
/// propagation can hide a working bind-mount from it. `statfs` reflects the
/// actual backing filesystem regardless of propagation.
pub fn is_namespace_path<P: AsRef<Path>>(path: P) -> bool {
    let Ok(c_path) = path_to_cstring(path.as_ref()) else {
        return false; // interior NUL — cannot be a real path
    };
    // SAFETY: `c_path` outlives the call, so the path pointer stays valid;
    // `f_type` is read only when `rc == 0`.
    let mut buf: libc::statfs = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::statfs(c_path.as_ptr(), &mut buf) };
    rc == 0 && buf.f_type as u64 == NSFS_MAGIC
}

/// Named-namespace counterpart to [`is_namespace_path`], resolving against the
/// `ip netns` convention `/var/run/netns/<name>`.
///
/// Pairs with [`exists`]: `exists` only checks the marker is present; this
/// checks it is a live netns.
pub fn is_namespace(name: &str) -> bool {
    is_namespace_path(PathBuf::from(NETNS_RUN_DIR).join(name))
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
///
/// See also [`create_path`] to persist a netns at an arbitrary path.
pub fn create(name: &str) -> Result<()> {
    create_path(PathBuf::from(NETNS_RUN_DIR).join(name))
}

/// Highest ancestor of `dir` that does not yet exist — the directory that
/// `create_dir_all(dir)` will materialize first. Removing it on rollback
/// undoes exactly what we created and nothing pre-existing.
fn topmost_missing_ancestor(dir: &Path) -> PathBuf {
    let mut topmost = dir.to_path_buf();
    let mut cursor = dir;
    while let Some(parent) = cursor.parent() {
        if parent.exists() {
            break;
        }
        topmost = parent.to_path_buf();
        cursor = parent;
    }
    topmost
}

/// Create a persistent network namespace bind-mounted at an arbitrary `path`.
///
/// Like [`create`], but the namespace lives at the caller's path instead of
/// the `ip netns` convention `/var/run/netns/<name>`. The parent directory is
/// created if needed.
///
/// `path` should be absolute. A relative path resolves against the current
/// working directory, which a multi-threaded program can change mid-call —
/// surprising for both the bind mount and the parent-rollback target.
///
/// # Errors
///
/// Returns an error if the path already exists, the parent cannot be created,
/// or the unshare/mount sequence fails (requires root or CAP_SYS_ADMIN).
pub fn create_path<P: AsRef<Path>>(path: P) -> Result<()> {
    let ns_path = path.as_ref().to_path_buf();

    // Check if namespace already exists
    if ns_path.exists() {
        return Err(Error::InvalidMessage(format!(
            "namespace '{}' already exists",
            ns_path.display()
        )));
    }

    // Remember the topmost created ancestor so a later failure can roll
    // back the directory tree instead of leaking it.
    let created_dir = match ns_path.parent() {
        Some(parent) if !parent.exists() => {
            let topmost = topmost_missing_ancestor(parent);
            std::fs::create_dir_all(parent).map_err(|e| {
                Error::InvalidMessage(format!("cannot create {}: {}", parent.display(), e))
            })?;
            Some(topmost)
        }
        _ => None,
    };

    let rollback_dir = |dir: &Option<PathBuf>| {
        if let Some(dir) = dir {
            let _ = std::fs::remove_dir_all(dir);
        }
    };

    // Create an empty file for the bind mount
    File::create(&ns_path).map_err(|e| {
        rollback_dir(&created_dir);
        Error::InvalidMessage(format!(
            "cannot create namespace file '{}': {}",
            ns_path.display(),
            e
        ))
    })?;

    // 0.19 N1 fix — isolate the unshare+mount+setns sequence on
    // a dedicated OS thread.
    //
    // The kernel scopes `unshare(CLONE_NEWNET)` to the *calling
    // thread*, not the process. When this function is called from
    // an async context (tokio `LabNamespace::new`, integration
    // test setup), the calling thread is a tokio worker. Until
    // the matching `setns()` restores the original netns, every
    // other tokio task scheduled on that worker temporarily
    // observes the new (empty) namespace — including any
    // `Connection<P>` they construct in that window, which
    // silently binds to the wrong netns. The same mechanism
    // affects sync callers from a multi-threaded program because
    // `mount(2)` can block on disk I/O long enough for any other
    // thread to be scheduled.
    //
    // The fix: do the unshare+mount+setns on a freshly-spawned
    // `std::thread`, then `join()`. The dedicated thread has no
    // co-scheduled work, and its destructor is the only observer
    // of the transient netns membership; we wait for setns to
    // complete before returning.
    let ns_path_owned = ns_path.clone();
    let label = ns_path.display().to_string();
    let thread_result = std::thread::spawn(move || -> Result<()> {
        create_namespace_in_current_thread(&label, &ns_path_owned)
    })
    .join();

    match thread_result {
        Ok(Ok(())) => Ok(()),
        Ok(Err(e)) => {
            // Worker already tore down its marker (and any live mount) on every
            // error path; retry here in case it raced, then roll back parent dirs.
            let _ = std::fs::remove_file(&ns_path);
            rollback_dir(&created_dir);
            Err(e)
        }
        Err(_panic) => {
            // Worker panicked — leaves the bind mount in an
            // undefined state. Remove the file so we don't leak
            // an empty netns marker.
            let _ = std::fs::remove_file(&ns_path);
            rollback_dir(&created_dir);
            Err(Error::InvalidMessage(format!(
                "namespace '{}' worker thread panicked during create",
                ns_path.display()
            )))
        }
    }
}

/// Inner half of [`create`] — runs on a dedicated `std::thread`
/// so the `unshare(CLONE_NEWNET)` + `mount(MS_BIND)` + `setns()`
/// sequence is isolated from tokio worker threads. See [`create`]
/// for the rationale.
fn create_namespace_in_current_thread(name: &str, ns_path: &Path) -> Result<()> {
    // Save the current namespace so we can restore after unshare.
    // Without this, unshare(CLONE_NEWNET) permanently changes the calling
    // thread's namespace, breaking subsequent namespace operations.
    let original_ns = File::open("/proc/thread-self/ns/net").map_err(|e| {
        let _ = std::fs::remove_file(ns_path);
        Error::InvalidMessage(format!("cannot save current namespace: {}", e))
    })?;

    // Create a new network namespace
    // SAFETY: unshare is a standard Linux syscall. CLONE_NEWNET creates a new
    // network namespace for the current process.
    let ret = unsafe { libc::unshare(libc::CLONE_NEWNET) };
    if ret < 0 {
        // Clean up the file we created
        let _ = std::fs::remove_file(ns_path);
        return Err(Error::Io(std::io::Error::last_os_error()));
    }

    // Bind mount the namespace to the file
    let ns_path_cstr = path_to_cstring(ns_path).inspect_err(|_| {
        let _ = std::fs::remove_file(ns_path);
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
        let _ = std::fs::remove_file(ns_path);
        return Err(Error::Io(err));
    }

    // Restore the calling thread to its original namespace.
    // SAFETY: setns is a standard Linux syscall. original_ns is a valid FD
    // to the namespace we opened before unshare().
    let ret = unsafe { libc::setns(original_ns.as_raw_fd(), libc::CLONE_NEWNET) };
    if ret < 0 {
        let restore_err = std::io::Error::last_os_error();
        // Bind mount is live but we couldn't restore the caller's netns, so the
        // create has failed as a whole. Tear down the mount + marker here so the
        // caller's rollback isn't racing a pinned mount.
        if let Ok(c) = path_to_cstring(ns_path) {
            unsafe { libc::umount2(c.as_ptr(), libc::MNT_DETACH) };
        }
        let _ = std::fs::remove_file(ns_path);
        return Err(Error::InvalidMessage(format!(
            "namespace '{}' failed to restore original namespace: {}",
            name, restore_err
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
///
/// See also [`delete_path`] to delete a netns at an arbitrary path.
pub fn delete(name: &str) -> Result<()> {
    delete_path(PathBuf::from(NETNS_RUN_DIR).join(name))
}

/// Delete a persistent network namespace at an arbitrary `path`.
///
/// The path-based counterpart to [`delete`], for namespaces created via
/// [`create_path`]. Lazily unmounts the bind mount (`MNT_DETACH`) and removes
/// the marker file.
///
/// Removes only the marker file and bind mount; parent directories that
/// [`create_path`] created are left in place — delete cannot know which
/// ancestors were pre-existing. The caller owns teardown of its directory
/// tree.
///
/// # Errors
///
/// Returns an error if:
/// - The path doesn't exist — `Error::NamespaceNotFound`, whose `name` field
///   carries the path string for path-based deletes.
/// - The unmount fails with anything other than `EINVAL` (which covers the
///   "not a mount point" case — a stale marker with no live bind mount).
/// - The marker file cannot be removed.
pub fn delete_path<P: AsRef<Path>>(path: P) -> Result<()> {
    let ns_path = path.as_ref();

    if !ns_path.exists() {
        return Err(Error::NamespaceNotFound {
            name: ns_path.display().to_string(),
        });
    }

    let ns_path_cstr = path_to_cstring(ns_path)?;

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
    std::fs::remove_file(ns_path)
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

// ============================================================================
// Process spawning with /etc/netns/ overlay (mirrors `ip netns exec`)
// ============================================================================

/// Pre-compute bind mount pairs from `/etc/netns/<name>/`.
///
/// This runs in the parent process where memory allocation is safe.
/// The returned `CString` pairs are captured by the `pre_exec` closure
/// so that only raw syscalls (no allocations) happen after fork.
fn prepare_etc_binds(ns_name: &str) -> Result<Vec<(std::ffi::CString, std::ffi::CString)>> {
    let etc_netns = PathBuf::from("/etc/netns").join(ns_name);

    let entries = match std::fs::read_dir(&etc_netns) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(Error::Io(e)),
    };

    let mut binds = Vec::new();
    for entry in entries {
        let entry = entry.map_err(Error::Io)?;
        let file_name = entry.file_name();
        let src = entry.path();
        let dst = Path::new("/etc").join(&file_name);

        // Only overlay if the target exists (can't bind-mount over nothing)
        if !dst.exists() {
            continue;
        }

        let src_c = std::ffi::CString::new(src.as_os_str().as_encoded_bytes())
            .map_err(|_| Error::InvalidMessage("null byte in path".into()))?;
        let dst_c = std::ffi::CString::new(dst.as_os_str().as_encoded_bytes())
            .map_err(|_| Error::InvalidMessage("null byte in path".into()))?;

        binds.push((src_c, dst_c));
    }

    Ok(binds)
}

/// Spawn a process in a network namespace with `/etc/netns/` file overlays.
///
/// Like [`spawn`], but also creates a private mount namespace in the child and:
/// 1. Bind-mounts files from `/etc/netns/<ns_name>/` over `/etc/`
/// 2. Remounts `/sys` (sysfs) to reflect the new network namespace
///
/// This mirrors the behavior of `ip netns exec <name> <cmd>`.
///
/// If `/etc/netns/<ns_name>/` does not exist, the mount overlay step is skipped
/// and behavior is identical to [`spawn`].
///
/// Requires `CAP_SYS_ADMIN` (for `unshare(CLONE_NEWNS)`).
///
/// # Example
///
/// ```ignore
/// use nlink::netlink::namespace;
/// use std::process::Command;
///
/// // Create /etc/netns/myns/hosts with custom DNS entries, then:
/// let output = namespace::spawn_output_with_etc("myns", Command::new("cat").arg("/etc/hosts"))?;
/// // The process sees the custom /etc/hosts, not the host's
/// ```
pub fn spawn_with_etc(ns_name: &str, cmd: std::process::Command) -> Result<std::process::Child> {
    let path = PathBuf::from(NETNS_RUN_DIR).join(ns_name);
    if !path.exists() {
        return Err(Error::NamespaceNotFound {
            name: ns_name.to_string(),
        });
    }
    spawn_path_with_etc(&path, ns_name, cmd)
}

/// Spawn a process and collect its output with `/etc/netns/` file overlays.
///
/// See [`spawn_with_etc`] for details.
pub fn spawn_output_with_etc(
    ns_name: &str,
    mut cmd: std::process::Command,
) -> Result<std::process::Output> {
    cmd.stdout(std::process::Stdio::piped());
    cmd.stderr(std::process::Stdio::piped());
    let child = spawn_with_etc(ns_name, cmd)?;
    child.wait_with_output().map_err(Error::Io)
}

/// Spawn a process in a namespace specified by path with `/etc/netns/` file overlays.
///
/// The `ns_name` parameter is needed to locate the `/etc/netns/<name>/` directory.
///
/// See [`spawn_with_etc`] for details.
pub fn spawn_path_with_etc<P: AsRef<Path>>(
    path: P,
    ns_name: &str,
    mut cmd: std::process::Command,
) -> Result<std::process::Child> {
    use std::os::unix::process::CommandExt;

    let ns_fd = open_path(path)?;
    let raw_fd = ns_fd.as_raw_fd();

    // Pre-compute ALL data before fork — no allocations in pre_exec.
    let bind_mounts = prepare_etc_binds(ns_name)?;
    let ns_name_c = std::ffi::CString::new(ns_name)
        .map_err(|_| Error::InvalidMessage("null byte in namespace name".into()))?;

    // Pre-computed string literals for syscalls (avoid allocation after fork).
    let c_root = std::ffi::CString::new("/").unwrap();
    let c_none = std::ffi::CString::new("none").unwrap();
    let c_sys = std::ffi::CString::new("/sys").unwrap();
    let c_sysfs = std::ffi::CString::new("sysfs").unwrap();

    // SAFETY: All operations in pre_exec use only raw syscalls (setns, unshare,
    // mount, umount2). No memory allocation occurs — all CStrings are pre-computed
    // above and captured by the closure. This is async-signal-safe.
    unsafe {
        cmd.pre_exec(move || {
            // 1. Enter network namespace
            if libc::setns(raw_fd, libc::CLONE_NEWNET) != 0 {
                return Err(std::io::Error::last_os_error());
            }

            // 2. If no /etc overlay files, skip mount namespace setup entirely
            if bind_mounts.is_empty() {
                return Ok(());
            }

            // 3. Create private mount namespace for the child
            if libc::unshare(libc::CLONE_NEWNS) != 0 {
                return Err(std::io::Error::last_os_error());
            }

            // 4. Make mount tree slave to prevent propagation back to host.
            //    MS_SLAVE (not MS_PRIVATE) so parent->child propagation still works.
            if libc::mount(
                c_none.as_ptr(),
                c_root.as_ptr(),
                std::ptr::null(),
                libc::MS_SLAVE | libc::MS_REC,
                std::ptr::null(),
            ) != 0
            {
                return Err(std::io::Error::last_os_error());
            }

            // 5. Remount /sys so sysfs reflects the new network namespace.
            //    Without this, /sys/class/net/ shows the host's interfaces.
            libc::umount2(c_sys.as_ptr(), libc::MNT_DETACH);
            if libc::mount(
                ns_name_c.as_ptr(),
                c_sys.as_ptr(),
                c_sysfs.as_ptr(),
                0,
                std::ptr::null(),
            ) != 0
            {
                // Non-fatal: sysfs remount may fail in nested namespaces
                // or restricted environments. Continue with /etc overlays.
            }

            // 6. Apply pre-computed /etc bind mounts
            for (src, dst) in &bind_mounts {
                if libc::mount(
                    src.as_ptr(),
                    dst.as_ptr(),
                    std::ptr::null(),
                    libc::MS_BIND,
                    std::ptr::null(),
                ) != 0
                {
                    return Err(std::io::Error::last_os_error());
                }
            }

            Ok(())
        });
    }

    let child = cmd.spawn().map_err(Error::Io)?;
    drop(ns_fd);
    Ok(child)
}

/// Spawn a process and collect output in a namespace by path with `/etc/netns/` overlays.
///
/// See [`spawn_path_with_etc`] for details.
pub fn spawn_output_path_with_etc<P: AsRef<Path>>(
    path: P,
    ns_name: &str,
    mut cmd: std::process::Command,
) -> Result<std::process::Output> {
    cmd.stdout(std::process::Stdio::piped());
    cmd.stderr(std::process::Stdio::piped());
    let child = spawn_path_with_etc(path, ns_name, cmd)?;
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

    #[test]
    fn test_topmost_missing_ancestor() {
        let base = std::env::temp_dir().join(format!("nlink-tma-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        // base does not exist; the topmost missing ancestor of base/a/b is base.
        assert_eq!(topmost_missing_ancestor(&base.join("a/b")), base);

        std::fs::create_dir_all(&base).unwrap();
        // base exists now; the topmost missing ancestor of base/a/b is base/a.
        assert_eq!(topmost_missing_ancestor(&base.join("a/b")), base.join("a"));
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn test_create_path_rejects_existing_marker() {
        // The already-exists check runs before any privileged syscall, so this
        // exercises the error path without root.
        let path = std::env::temp_dir().join(format!("nlink-exists-{}", std::process::id()));
        std::fs::File::create(&path).unwrap();
        let err = create_path(&path).expect_err("existing path must be rejected");
        assert!(err.to_string().contains("already exists"));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_delete_path_missing_is_not_found() {
        let path =
            std::env::temp_dir().join(format!("nlink-missing-del-{}", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let err = delete_path(&path).expect_err("missing path must be rejected");
        assert!(err.is_not_found());
    }

    #[test]
    fn is_namespace_path_false_for_missing() {
        let path =
            std::env::temp_dir().join(format!("nlink-isns-missing-{}", std::process::id()));
        let _ = std::fs::remove_file(&path);
        assert!(!is_namespace_path(&path));
    }

    #[test]
    fn is_namespace_path_false_for_plain_file() {
        // A regular file (the shape of a *stale* marker) is not a live netns.
        let path = std::env::temp_dir().join(format!("nlink-isns-plain-{}", std::process::id()));
        std::fs::File::create(&path).unwrap();
        assert!(!is_namespace_path(&path));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn is_namespace_false_for_nonexistent_name() {
        assert!(!is_namespace("definitely_does_not_exist_12345"));
    }

    #[test]
    fn is_namespace_path_true_for_own_net_ns() {
        // /proc/self/ns/net is a live nsfs inode in any process, so this pins
        // NSFS_MAGIC against the kernel's real value without needing root.
        assert!(is_namespace_path("/proc/self/ns/net"));
    }
}
