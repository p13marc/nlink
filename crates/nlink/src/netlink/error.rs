//! Error types for netlink operations.

use std::io;

/// Result type for netlink operations.
pub type Result<T> = std::result::Result<T, Error>;

/// Errors that can occur during netlink operations.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// I/O error from socket operations.
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    /// JSON serialization error.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// Kernel returned an error code.
    #[error("kernel error: {message} (errno {errno})")]
    Kernel {
        /// The errno value from the kernel.
        errno: i32,
        /// Human-readable error message.
        message: String,
    },

    /// Kernel error with operation context.
    #[error("{operation}: {message} (errno {errno})")]
    KernelWithContext {
        /// The operation that failed.
        operation: String,
        /// The errno value from the kernel.
        errno: i32,
        /// Human-readable error message.
        message: String,
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

    /// Parse error.
    #[error("parse error: {0}")]
    Parse(String),

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
}

impl Error {
    /// Create a kernel error from an errno value.
    pub fn from_errno(errno: i32) -> Self {
        let message = io::Error::from_raw_os_error(-errno).to_string();
        Self::Kernel {
            errno: -errno,
            message,
        }
    }

    /// Create a kernel error with operation context.
    pub fn from_errno_with_context(errno: i32, operation: impl Into<String>) -> Self {
        let message = io::Error::from_raw_os_error(-errno).to_string();
        Self::KernelWithContext {
            operation: operation.into(),
            errno: -errno,
            message,
        }
    }

    /// Add context to this error.
    ///
    /// Wraps kernel errors with operation context. Other errors are returned unchanged.
    pub fn with_context(self, operation: impl Into<String>) -> Self {
        match self {
            Self::Kernel { errno, message } => Self::KernelWithContext {
                operation: operation.into(),
                errno,
                message,
            },
            other => other,
        }
    }

    /// Check if this is a "not found" error (ENOENT, ENODEV, etc.).
    pub fn is_not_found(&self) -> bool {
        match self {
            Self::Kernel { errno, .. } | Self::KernelWithContext { errno, .. } => {
                matches!(*errno, 2 | 19) // ENOENT=2, ENODEV=19
            }
            Self::InterfaceNotFound { .. }
            | Self::NamespaceNotFound { .. }
            | Self::QdiscNotFound { .. } => true,
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
