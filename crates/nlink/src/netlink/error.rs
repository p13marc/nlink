//! Error types for netlink operations.

use std::io;

use crate::util::{addr::AddrError, ifname::IfError, parse::ParseError};

/// Result type for netlink operations.
pub type Result<T> = std::result::Result<T, Error>;

/// Errors that can occur during netlink operations.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// I/O error from socket operations.
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    /// JSON serialization error.
    #[cfg(feature = "output")]
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// Kernel returned an error code.
    ///
    /// Carries optional extended-ack TLVs ([`ext_ack`](Self::Kernel::ext_ack),
    /// [`ext_ack_offset`](Self::Kernel::ext_ack_offset)) populated by
    /// the kernel when `NETLINK_EXT_ACK` is enabled (on by default in
    /// nlink — see [`Self::is_namespace_restore_failed`] note).
    #[error("{}", format_kernel(message, *errno, ext_ack.as_deref(), *ext_ack_offset))]
    #[non_exhaustive]
    Kernel {
        /// The errno value from the kernel.
        errno: i32,
        /// Human-readable error message (from `strerror(errno)`).
        message: String,
        /// Kernel-supplied human-readable detail string from the
        /// `NLMSGERR_ATTR_MSG` TLV, when present. Often dramatically
        /// more actionable than the raw errno — for example,
        /// `errno = 22 (EINVAL)` + `ext_ack = "attribute IFLA_MTU
        /// rejected: value 0 out of range"`.
        ext_ack: Option<String>,
        /// Byte offset into the original request where the kernel
        /// detected the problem, from `NLMSGERR_ATTR_OFFS`.
        ext_ack_offset: Option<u32>,
    },

    /// Kernel error with operation context.
    ///
    /// Like [`Self::Kernel`] but carries the calling-site operation
    /// label (`"add_link(veth0, kind=veth)"` etc.) for readable
    /// `tracing` events.
    #[error("{}", format_kernel_ctx(operation, message, *errno, ext_ack.as_deref(), *ext_ack_offset))]
    #[non_exhaustive]
    KernelWithContext {
        /// The operation that failed.
        operation: String,
        /// The errno value from the kernel.
        errno: i32,
        /// Human-readable error message (from `strerror(errno)`).
        message: String,
        /// See [`Self::Kernel::ext_ack`].
        ext_ack: Option<String>,
        /// See [`Self::Kernel::ext_ack_offset`].
        ext_ack_offset: Option<u32>,
    },

    /// Message was truncated.
    #[error("message truncated: expected {expected} bytes, got {actual}")]
    Truncated {
        /// Expected message length.
        expected: usize,
        /// Actual bytes received.
        actual: usize,
    },

    /// Invalid message format.
    #[error("invalid message: {0}")]
    InvalidMessage(String),

    /// Invalid attribute format.
    #[error("invalid attribute: {0}")]
    InvalidAttribute(String),

    /// Sequence number mismatch.
    #[error("sequence mismatch: expected {expected}, got {actual}")]
    SequenceMismatch {
        /// Expected sequence number.
        expected: u32,
        /// Actual sequence number received.
        actual: u32,
    },

    /// Operation not supported.
    #[error("operation not supported: {0}")]
    NotSupported(String),

    /// Parse error from util parsing functions.
    #[error("parse error: {0}")]
    Parse(#[from] ParseError),

    /// Address parsing error.
    #[error("address error: {0}")]
    Address(#[from] AddrError),

    /// Interface error (not found, invalid name).
    #[error("interface error: {0}")]
    Interface(#[from] IfError),

    /// Validation errors from configuration builders.
    #[error("validation failed: {}", format_validation_errors(.0))]
    Validation(Vec<ValidationErrorInfo>),

    /// Interface not found.
    #[error("interface not found: {name}")]
    InterfaceNotFound {
        /// The interface name that was not found.
        name: String,
    },

    /// Namespace not found.
    #[error("namespace not found: {name}")]
    NamespaceNotFound {
        /// The namespace name that was not found.
        name: String,
    },

    /// Qdisc not found.
    #[error("qdisc not found: {kind} on {interface}")]
    QdiscNotFound {
        /// The qdisc kind (e.g., "netem", "htb").
        kind: String,
        /// The interface name.
        interface: String,
    },

    /// Generic Netlink family not found.
    #[error("GENL family not found: {name}")]
    FamilyNotFound {
        /// The family name that was not found.
        name: String,
    },

    /// Operation timed out.
    ///
    /// The configured timeout expired before the kernel responded.
    /// This typically indicates a kernel bug or an extremely loaded system.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use nlink::{Connection, Route};
    /// use std::time::Duration;
    ///
    /// let conn = Connection::<Route>::new()?
    ///     .timeout(Duration::from_secs(5));
    ///
    /// match conn.get_links().await {
    ///     Err(e) if e.is_timeout() => eprintln!("kernel not responding"),
    ///     Err(e) => return Err(e),
    ///     Ok(links) => { /* ... */ }
    /// }
    /// ```
    #[error("operation timed out")]
    Timeout,

    /// Connection pool was unable to hand out a connection within
    /// the configured `acquire_timeout`.
    ///
    /// Recover via [`Self::is_pool_exhausted`]. Typical responses:
    /// retry with a longer timeout, scale the pool size up, or
    /// shed load.
    #[error("connection pool exhausted: {size} connections all busy, waited {timeout:?}")]
    PoolExhausted {
        /// Configured pool size (total connections, busy + idle).
        size: usize,
        /// The acquire timeout that just expired.
        timeout: std::time::Duration,
    },

    /// The connection pool was dropped while an `acquire()` was
    /// pending, or while waiting to send a connection back to it.
    ///
    /// Recover via [`Self::is_pool_closed`]. Indicates a teardown
    /// race; the surviving task should fail through.
    #[error("connection pool is closed (all handles dropped)")]
    PoolClosed,

    /// `setns()` failed to restore the calling thread to its original
    /// network namespace after a `new_in_namespace`-style socket
    /// creation.
    ///
    /// The socket itself was created successfully and lives in the
    /// target namespace as intended. But the **calling thread** is
    /// now stuck in the target namespace — every subsequent
    /// `/sys/class/net/`-reading call from this thread (or any
    /// other tokio task scheduled on it) will read from the wrong
    /// namespace. There is no automatic recovery; the calling code
    /// must decide whether to abort, retry the restore manually, or
    /// pin work to a different thread.
    ///
    /// Previously (≤ 0.15.1) this condition logged to stderr and
    /// returned the socket anyway. Promoted to an error variant in
    /// 0.16.0 because silent thread-state corruption was producing
    /// surprises that took hours to debug.
    ///
    /// Recover via [`Error::is_namespace_restore_failed`] for the
    /// predicate form.
    #[error("netns restore failed after socket creation; thread \
             stuck in target netns: {source}")]
    NamespaceRestoreFailed {
        /// The underlying `setns()` failure.
        #[source]
        source: io::Error,
    },
}

/// Structured validation error information.
#[derive(Debug, Clone)]
pub struct ValidationErrorInfo {
    /// Field that failed validation.
    pub field: String,
    /// Description of the error.
    pub message: String,
}

impl ValidationErrorInfo {
    /// Create a new validation error.
    pub fn new(field: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            field: field.into(),
            message: message.into(),
        }
    }
}

impl std::fmt::Display for ValidationErrorInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.field, self.message)
    }
}

/// Format validation errors for display.
fn format_validation_errors(errors: &[ValidationErrorInfo]) -> String {
    errors
        .iter()
        .map(|e| e.to_string())
        .collect::<Vec<_>>()
        .join("; ")
}

/// Format the Display output for [`Error::Kernel`], stitching the
/// ext-ack message in when present. Pulled into a free fn so the
/// `#[error(...)]` attribute stays readable.
fn format_kernel(
    message: &str,
    errno: i32,
    ext_ack: Option<&str>,
    ext_ack_offset: Option<u32>,
) -> String {
    let mut out = format!("kernel error: {message} (errno {errno})");
    if let Some(msg) = ext_ack {
        out.push_str(": ");
        out.push_str(msg);
    }
    if let Some(off) = ext_ack_offset {
        out.push_str(&format!(" (at request offset {off})"));
    }
    out
}

/// Format the Display output for [`Error::KernelWithContext`].
fn format_kernel_ctx(
    operation: &str,
    message: &str,
    errno: i32,
    ext_ack: Option<&str>,
    ext_ack_offset: Option<u32>,
) -> String {
    let mut out = format!("{operation}: {message} (errno {errno})");
    if let Some(msg) = ext_ack {
        out.push_str(": ");
        out.push_str(msg);
    }
    if let Some(off) = ext_ack_offset {
        out.push_str(&format!(" (at request offset {off})"));
    }
    out
}

impl Error {
    /// Create a kernel error from an errno value (no ext-ack info).
    ///
    /// Prefer [`Self::from_errno_ext_ack`] when the kernel response
    /// carries `NLMSGERR_ATTR_MSG` / `NLMSGERR_ATTR_OFFS` TLVs —
    /// those become user-visible diagnostics far more actionable than
    /// the raw errno.
    pub fn from_errno(errno: i32) -> Self {
        Self::from_errno_ext_ack(errno, None, None)
    }

    /// Create a kernel error from an errno value plus the parsed
    /// extended-ack TLVs from the same error response.
    ///
    /// Typical use: after `NlMsgError::from_bytes`, call
    /// `err.parsed_ext_ack(payload)` to get a [`crate::netlink::message::ParsedExtAck`],
    /// then forward the fields here.
    pub fn from_errno_ext_ack(
        errno: i32,
        ext_ack: Option<String>,
        ext_ack_offset: Option<u32>,
    ) -> Self {
        let message = io::Error::from_raw_os_error(-errno).to_string();
        Self::Kernel {
            errno: -errno,
            message,
            ext_ack,
            ext_ack_offset,
        }
    }

    /// Create a kernel error with operation context (no ext-ack info).
    pub fn from_errno_with_context(errno: i32, operation: impl Into<String>) -> Self {
        Self::from_errno_with_context_ext_ack(errno, operation, None, None)
    }

    /// Create a kernel error with operation context plus the parsed
    /// extended-ack TLVs.
    pub fn from_errno_with_context_ext_ack(
        errno: i32,
        operation: impl Into<String>,
        ext_ack: Option<String>,
        ext_ack_offset: Option<u32>,
    ) -> Self {
        let message = io::Error::from_raw_os_error(-errno).to_string();
        Self::KernelWithContext {
            operation: operation.into(),
            errno: -errno,
            message,
            ext_ack,
            ext_ack_offset,
        }
    }

    /// Add context to this error.
    ///
    /// Wraps kernel errors with operation context. Other errors are returned unchanged.
    pub fn with_context(self, operation: impl Into<String>) -> Self {
        match self {
            Self::Kernel {
                errno,
                message,
                ext_ack,
                ext_ack_offset,
            } => Self::KernelWithContext {
                operation: operation.into(),
                errno,
                message,
                ext_ack,
                ext_ack_offset,
            },
            other => other,
        }
    }

    /// Create a validation error from a list of field errors.
    pub fn validation(errors: impl IntoIterator<Item = ValidationErrorInfo>) -> Self {
        Self::Validation(errors.into_iter().collect())
    }

    /// Create a single validation error.
    pub fn validation_error(field: impl Into<String>, message: impl Into<String>) -> Self {
        Self::Validation(vec![ValidationErrorInfo::new(field, message)])
    }

    /// Create an invalid message error.
    ///
    /// This is a convenience constructor for the common case of creating
    /// an `InvalidMessage` error with a formatted message.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use nlink::netlink::Error;
    ///
    /// let err = Error::invalid_message("invalid MAC address format");
    /// ```
    pub fn invalid_message(message: impl Into<String>) -> Self {
        Self::InvalidMessage(message.into())
    }

    /// Create an invalid attribute error.
    pub fn invalid_attribute(message: impl Into<String>) -> Self {
        Self::InvalidAttribute(message.into())
    }

    /// Create a not supported error.
    pub fn not_supported(message: impl Into<String>) -> Self {
        Self::NotSupported(message.into())
    }

    /// Create an interface not found error.
    pub fn interface_not_found(name: impl Into<String>) -> Self {
        Self::InterfaceNotFound { name: name.into() }
    }

    /// Create a namespace not found error.
    pub fn namespace_not_found(name: impl Into<String>) -> Self {
        Self::NamespaceNotFound { name: name.into() }
    }

    /// Create a qdisc not found error.
    pub fn qdisc_not_found(kind: impl Into<String>, interface: impl Into<String>) -> Self {
        Self::QdiscNotFound {
            kind: kind.into(),
            interface: interface.into(),
        }
    }

    /// Create a GENL family not found error.
    pub fn family_not_found(name: impl Into<String>) -> Self {
        Self::FamilyNotFound { name: name.into() }
    }

    /// Check if this is a "not found" error (ENOENT, ENODEV, etc.).
    pub fn is_not_found(&self) -> bool {
        match self {
            Self::Kernel { errno, .. } | Self::KernelWithContext { errno, .. } => {
                matches!(*errno, 2 | 19) // ENOENT=2, ENODEV=19
            }
            Self::Interface(IfError::NotFound(_)) => true,
            Self::InterfaceNotFound { .. }
            | Self::NamespaceNotFound { .. }
            | Self::QdiscNotFound { .. }
            | Self::FamilyNotFound { .. } => true,
            _ => false,
        }
    }

    /// Check if this is a permission error (EPERM, EACCES).
    pub fn is_permission_denied(&self) -> bool {
        match self {
            Self::Kernel { errno, .. } | Self::KernelWithContext { errno, .. } => {
                matches!(*errno, 1 | 13) // EPERM=1, EACCES=13
            }
            _ => false,
        }
    }

    /// Check if this is a "already exists" error (EEXIST).
    pub fn is_already_exists(&self) -> bool {
        match self {
            Self::Kernel { errno, .. } | Self::KernelWithContext { errno, .. } => {
                *errno == 17 // EEXIST=17
            }
            _ => false,
        }
    }

    /// Check if this is a "device busy" error (EBUSY).
    pub fn is_busy(&self) -> bool {
        match self {
            Self::Kernel { errno, .. } | Self::KernelWithContext { errno, .. } => {
                *errno == 16 // EBUSY=16
            }
            _ => false,
        }
    }

    /// Get the errno value if this is a kernel error.
    pub fn errno(&self) -> Option<i32> {
        match self {
            Self::Kernel { errno, .. } | Self::KernelWithContext { errno, .. } => Some(*errno),
            _ => None,
        }
    }

    /// Check if this is an "invalid argument" error (EINVAL).
    ///
    /// This typically indicates that the kernel rejected the request
    /// due to invalid parameters (e.g., invalid handle, unsupported option).
    pub fn is_invalid_argument(&self) -> bool {
        self.errno() == Some(libc::EINVAL)
    }

    /// Check if this is a "no such device" error (ENODEV).
    ///
    /// This indicates the specified network device does not exist.
    pub fn is_no_device(&self) -> bool {
        self.errno() == Some(libc::ENODEV)
    }

    /// Check if this is a "not supported" error (EOPNOTSUPP).
    ///
    /// This indicates the requested operation is not supported by the kernel
    /// or the specific device/driver.
    pub fn is_not_supported(&self) -> bool {
        self.errno() == Some(libc::EOPNOTSUPP)
    }

    /// Check if this is a "network unreachable" error (ENETUNREACH).
    pub fn is_network_unreachable(&self) -> bool {
        self.errno() == Some(libc::ENETUNREACH)
    }

    /// Check if this is a timeout error.
    ///
    /// Returns `true` for both the [`Error::Timeout`] variant and
    /// kernel ETIMEDOUT errors.
    pub fn is_timeout(&self) -> bool {
        matches!(self, Self::Timeout) || self.errno() == Some(libc::ETIMEDOUT)
    }

    /// Check if this is a [`Error::PoolExhausted`].
    ///
    /// All pool slots were busy when `ConnectionPool::acquire` was
    /// called, and the `acquire_timeout` elapsed before any returned.
    /// Typical recovery: retry with a longer timeout, scale the
    /// pool size up, or shed load.
    pub fn is_pool_exhausted(&self) -> bool {
        matches!(self, Self::PoolExhausted { .. })
    }

    /// Check if this is a [`Error::PoolClosed`].
    ///
    /// The pool was dropped while an acquire / return was pending.
    /// Indicates teardown race; the surviving task should fail
    /// through.
    pub fn is_pool_closed(&self) -> bool {
        matches!(self, Self::PoolClosed)
    }

    /// Check if this is a namespace-restore failure
    /// ([`Error::NamespaceRestoreFailed`]).
    ///
    /// Indicates that a socket was created successfully in a target
    /// netns, but the calling thread could not be restored to its
    /// original netns. The thread is now stuck in the target netns;
    /// callers typically respond by aborting the affected task or
    /// pinning subsequent work to a different thread.
    pub fn is_namespace_restore_failed(&self) -> bool {
        matches!(self, Self::NamespaceRestoreFailed { .. })
    }

    /// Check if this is an "address already in use" error (EADDRINUSE).
    ///
    /// This typically occurs when trying to add an IP address that is
    /// already assigned to an interface.
    pub fn is_address_in_use(&self) -> bool {
        self.errno() == Some(libc::EADDRINUSE)
    }

    /// Check if this is a "name too long" error (ENAMETOOLONG).
    ///
    /// Interface names in Linux are limited to 15 characters (IFNAMSIZ - 1).
    pub fn is_name_too_long(&self) -> bool {
        self.errno() == Some(libc::ENAMETOOLONG)
    }

    /// Check if this is a "resource temporarily unavailable" error (EAGAIN).
    ///
    /// This may occur during transient resource contention.
    pub fn is_try_again(&self) -> bool {
        self.errno() == Some(libc::EAGAIN)
    }

    /// Check if this is a "no buffer space available" error (ENOBUFS).
    ///
    /// This typically occurs when the kernel cannot allocate memory
    /// for network operations.
    pub fn is_no_buffer_space(&self) -> bool {
        self.errno() == Some(libc::ENOBUFS)
    }

    /// Check if this is a "connection refused" error (ECONNREFUSED).
    pub fn is_connection_refused(&self) -> bool {
        self.errno() == Some(libc::ECONNREFUSED)
    }

    /// Check if this is a "host unreachable" error (EHOSTUNREACH).
    pub fn is_host_unreachable(&self) -> bool {
        self.errno() == Some(libc::EHOSTUNREACH)
    }

    /// Check if this is a "message too long" error (EMSGSIZE).
    ///
    /// This occurs when a netlink message exceeds the maximum size.
    pub fn is_message_too_long(&self) -> bool {
        self.errno() == Some(libc::EMSGSIZE)
    }

    /// Check if this is a "too many open files" error (EMFILE).
    pub fn is_too_many_open_files(&self) -> bool {
        self.errno() == Some(libc::EMFILE)
    }

    /// Check if this is a "read-only file system" error (EROFS).
    ///
    /// This can occur when trying to modify network configuration
    /// in a read-only namespace or container.
    pub fn is_read_only(&self) -> bool {
        self.errno() == Some(libc::EROFS)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_errno() {
        let err = Error::from_errno(-1); // EPERM
        assert!(err.is_permission_denied());
        assert_eq!(err.errno(), Some(1));
    }

    #[test]
    fn test_from_errno_with_context() {
        let err = Error::from_errno_with_context(-2, "deleting interface eth0"); // ENOENT
        assert!(err.is_not_found());
        let msg = err.to_string();
        assert!(msg.contains("deleting interface eth0"));
        assert!(msg.contains("No such file or directory"));
    }

    #[test]
    fn test_with_context() {
        let err = Error::from_errno(-13); // EACCES
        let err = err.with_context("setting link up on eth0");
        assert!(err.is_permission_denied());
        let msg = err.to_string();
        assert!(msg.contains("setting link up on eth0"));
    }

    #[test]
    fn test_is_not_found() {
        assert!(Error::from_errno(-2).is_not_found()); // ENOENT
        assert!(Error::from_errno(-19).is_not_found()); // ENODEV
        assert!(
            Error::InterfaceNotFound {
                name: "eth0".into()
            }
            .is_not_found()
        );
        assert!(
            Error::NamespaceNotFound {
                name: "test".into()
            }
            .is_not_found()
        );
        assert!(
            Error::QdiscNotFound {
                kind: "netem".into(),
                interface: "eth0".into()
            }
            .is_not_found()
        );
    }

    #[test]
    fn test_is_busy() {
        assert!(Error::from_errno(-16).is_busy()); // EBUSY
        assert!(!Error::from_errno(-1).is_busy()); // EPERM is not busy
    }

    #[test]
    fn test_timeout() {
        let err = Error::Timeout;
        assert!(err.is_timeout());
        assert_eq!(err.to_string(), "operation timed out");

        // Kernel ETIMEDOUT should also match
        let err = Error::from_errno(-(libc::ETIMEDOUT));
        assert!(err.is_timeout());
    }

    #[test]
    fn test_namespace_restore_failed_predicate() {
        let err = Error::NamespaceRestoreFailed {
            source: io::Error::from_raw_os_error(libc::EPERM),
        };
        assert!(err.is_namespace_restore_failed());
        assert!(!err.is_timeout());
        assert!(!err.is_permission_denied()); // not an errno predicate
        assert!(err.to_string().contains("netns restore failed"));
        assert!(err.to_string().contains("thread stuck"));

        // Unrelated errors don't claim to be netns-restore failures.
        let other = Error::Timeout;
        assert!(!other.is_namespace_restore_failed());
    }

    #[test]
    fn test_error_messages() {
        let err = Error::InterfaceNotFound {
            name: "eth0".into(),
        };
        assert_eq!(err.to_string(), "interface not found: eth0");

        let err = Error::NamespaceNotFound {
            name: "myns".into(),
        };
        assert_eq!(err.to_string(), "namespace not found: myns");

        let err = Error::QdiscNotFound {
            kind: "netem".into(),
            interface: "docker0".into(),
        };
        assert_eq!(err.to_string(), "qdisc not found: netem on docker0");
    }
}
