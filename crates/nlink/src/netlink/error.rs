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
}
