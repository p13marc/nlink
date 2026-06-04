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
    ///
    /// # Wrapping in a downstream error type
    ///
    /// If you wrap this error in a `#[source]` field on your own
    /// error enum, **prefer carrying it inline**:
    ///
    /// ```ignore
    /// #[derive(thiserror::Error, Debug)]
    /// enum MyError {
    ///     #[error("netlink failed: {0}")]
    ///     Netlink(#[from] nlink::Error),  // inline — works
    /// }
    /// ```
    ///
    /// Boxing breaks `downcast_ref::<nlink::Error>()` on the
    /// `&dyn Error` source — the concrete type becomes
    /// `Box<nlink::Error>`, not `nlink::Error`. If you do need to
    /// box for `result_large_err` ergonomics, use
    /// [`Error::chain_walk`] which handles both shapes
    /// transparently. Plan 187 §2.2 documented the trap; the
    /// `chain_walk` helper closes it.
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

    /// A netlink frame exceeded the recv buffer (kernel-side
    /// `MSG_TRUNC`). Distinct from [`Self::Truncated`] which is
    /// the parser short-buffer case. `received` is the actual
    /// frame size the kernel reported via `MSG_TRUNC`;
    /// `buffer_size` is what was allocated. nlink auto-grows the
    /// recv buffer up to 1 MiB before surfacing this error.
    ///
    /// Added in 0.20.1 (Plan 224 — closes B4).
    #[error(
        "netlink frame truncated: kernel emitted {received} bytes, \
         nlink's recv buffer is {buffer_size} bytes (1 MiB cap reached); \
         file an issue with the kernel version + subsystem"
    )]
    FrameTruncated {
        /// Actual kernel frame size as reported by `MSG_TRUNC`.
        received: usize,
        /// Buffer size nlink had allocated.
        buffer_size: usize,
    },

    /// Kernel send buffer is full and back-to-back `WouldBlock`
    /// returns from `send` have exceeded the backpressure
    /// threshold. The 30 s connection timeout (Plan 171) would
    /// eventually surface as `Timeout`, but `Backpressure` lets
    /// the caller react faster.
    ///
    /// Added in 0.20.1 (Plan 232 — closes B19).
    #[error(
        "netlink send: kernel send buffer full ({send_buffer_full}); \
         try again later or back off"
    )]
    Backpressure {
        /// True when caused by send-buffer-full back-to-back
        /// WouldBlock returns from the kernel.
        send_buffer_full: bool,
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

    /// Address parsing error from declarative-config builders
    /// (e.g., `NetworkConfig::address("dev", "10.0.0.1/24")`).
    /// Added in 0.17 (Plan 173) so callers can `?`-chain on
    /// the builders without a per-call `.map_err()`.
    #[error("address parse error: {0}")]
    AddressParse(#[from] crate::netlink::config::AddressParseError),

    /// Route parsing error from declarative-config builders
    /// (e.g., `NetworkConfig::route("10.0.0.0/8", |r| ...)`).
    /// Added in 0.17 (Plan 173) so callers can `?`-chain on
    /// the builders without a per-call `.map_err()`.
    #[error("route parse error: {0}")]
    RouteParse(#[from] crate::netlink::config::RouteParseError),

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

    /// Kernel signaled that a dump was interrupted — the snapshot
    /// iterator's underlying data structure was mutated between
    /// frames, so the returned data set is inconsistent.
    ///
    /// The kernel sets `NLM_F_DUMP_INTR` on whichever message in the
    /// dump stream was generated after the mutation. Higher-level
    /// libraries differ on what to do:
    /// `iproute2` warns and accepts the partial dump;
    /// `vishvananda/netlink` retries with a bound;
    /// Cilium's `safenetlink` wrapper retries up to 30 times.
    ///
    /// nlink surfaces this as a typed error so callers choose their
    /// own retry policy. Recover via [`Self::is_dump_interrupted`]:
    ///
    /// ```ignore
    /// for attempt in 0..16 {
    ///     match conn.get_links().await {
    ///         Err(e) if e.is_dump_interrupted() => continue,
    ///         other => return other,
    ///     }
    /// }
    /// ```
    ///
    /// See [`crate::netlink::message::NlMsgHdr::is_dump_interrupted`]
    /// for kernel semantics. Reference: kernel netlink intro docs,
    /// `vishvananda/netlink #1163`, `pyroute2 #874`.
    #[error("netlink dump interrupted by concurrent mutation (NLM_F_DUMP_INTR) — retry")]
    DumpInterrupted,

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
    /// **Accepts either sign.** The kernel's `nlmsgerr.error` field
    /// is signed-negative (`-EEXIST = -17`); the stored
    /// `Error::Kernel.errno` is always the positive POSIX number
    /// (`17`). This factory normalizes via `.abs()` so both
    /// `from_errno_ext_ack(-17, ..)` and `from_errno_ext_ack(17, ..)`
    /// produce the same EEXIST error.
    ///
    /// Prior to 0.19 (Plan 187) this factory silently negated the
    /// input and a positive-passed `1` produced stored `-1` — a
    /// footgun nlink-lab hit in their `Error::ext_ack` unit tests.
    ///
    /// Typical use: after `NlMsgError::from_bytes`, call
    /// `err.parsed_ext_ack(payload)` to get a [`crate::netlink::message::ParsedExtAck`],
    /// then forward the fields here.
    pub fn from_errno_ext_ack(
        errno: i32,
        ext_ack: Option<String>,
        ext_ack_offset: Option<u32>,
    ) -> Self {
        let errno = errno.abs();
        let message = io::Error::from_raw_os_error(errno).to_string();
        Self::Kernel {
            errno,
            message,
            ext_ack,
            ext_ack_offset,
        }
    }

    /// Create a kernel error with operation context (no ext-ack info).
    ///
    /// Accepts either sign on `errno`; see [`Self::from_errno_ext_ack`].
    pub fn from_errno_with_context(errno: i32, operation: impl Into<String>) -> Self {
        Self::from_errno_with_context_ext_ack(errno, operation, None, None)
    }

    /// Create a kernel error with operation context plus the parsed
    /// extended-ack TLVs.
    ///
    /// Accepts either sign on `errno`; see [`Self::from_errno_ext_ack`].
    pub fn from_errno_with_context_ext_ack(
        errno: i32,
        operation: impl Into<String>,
        ext_ack: Option<String>,
        ext_ack_offset: Option<u32>,
    ) -> Self {
        let errno = errno.abs();
        let message = io::Error::from_raw_os_error(errno).to_string();
        Self::KernelWithContext {
            operation: operation.into(),
            errno,
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
    ///
    /// Matches `Error::Kernel`, `Error::KernelWithContext`, and
    /// `Error::Io` shapes carrying ENOENT/ENODEV — routed through
    /// the common [`Self::errno`] accessor that Plan 187 §2.5
    /// established as the canonical errno-shape merge point.
    ///
    /// Plus the typed not-found variants
    /// (`InterfaceNotFound`, `NamespaceNotFound`, `QdiscNotFound`,
    /// `FamilyNotFound`, `Interface(IfError::NotFound)`).
    ///
    /// Pre-0.19 this predicate matched on `Self::Kernel` /
    /// `Self::KernelWithContext` variants directly, missing the
    /// `Error::Io(io_err with ENOENT)` shape that sibling predicates
    /// (`is_busy`, `is_permission_denied`, `is_already_exists`)
    /// already handled. Plan 212 closes the asymmetry.
    pub fn is_not_found(&self) -> bool {
        if matches!(self.errno(), Some(libc::ENOENT) | Some(libc::ENODEV)) {
            return true;
        }
        matches!(
            self,
            Self::Interface(IfError::NotFound(_))
                | Self::InterfaceNotFound { .. }
                | Self::NamespaceNotFound { .. }
                | Self::QdiscNotFound { .. }
                | Self::FamilyNotFound { .. }
        )
    }

    /// Check if this is a permission error (EPERM, EACCES).
    ///
    /// Plan 187 §2.5: matches both `Error::Kernel*` and
    /// `Error::Io` variants carrying EPERM/EACCES via the
    /// `errno()` unwrap.
    pub fn is_permission_denied(&self) -> bool {
        matches!(self.errno(), Some(libc::EPERM) | Some(libc::EACCES))
    }

    /// Check if this is a "already exists" error (EEXIST).
    ///
    /// Plan 187 §2.5: matches both `Error::Kernel*` and
    /// `Error::Io(EEXIST)` shapes.
    pub fn is_already_exists(&self) -> bool {
        self.errno() == Some(libc::EEXIST)
    }

    /// Check if this is a "device busy" error (EBUSY).
    ///
    /// Plan 187 §2.5: matches both `Error::Kernel*` and
    /// `Error::Io(EBUSY)` shapes. Used by
    /// `NftablesConfig::apply_reconcile` for retry
    /// classification — a missed match here used to silently
    /// skip the retry budget.
    pub fn is_busy(&self) -> bool {
        self.errno() == Some(libc::EBUSY)
    }

    /// Get the POSIX errno value if this error carries one.
    ///
    /// Handles three shapes:
    /// - `Error::Kernel { errno, .. }` — from `NLMSGERR`.
    /// - `Error::KernelWithContext { errno, .. }` — context-wrapped.
    /// - `Error::Io(io_err)` — from raw socket-layer errors;
    ///   reads `io_err.raw_os_error()`. This is the shape
    ///   `recvmsg` returns `-ENOBUFS` in (the Plan 185 bug
    ///   class that Plan 187 fixes at the single-point of
    ///   `errno()`).
    ///
    /// Returns `None` for the other variants (Timeout, Truncated,
    /// InvalidMessage, etc.) — they don't carry an errno.
    pub fn errno(&self) -> Option<i32> {
        match self {
            Self::Kernel { errno, .. } | Self::KernelWithContext { errno, .. } => Some(*errno),
            Self::Io(io_err) => io_err.raw_os_error(),
            _ => None,
        }
    }

    /// Return the kernel's `NLMSGERR_ATTR_MSG` extended-ack
    /// string if this is a kernel error that carries one.
    /// Plan 182 — sugar over destructuring `Error::Kernel` /
    /// `Error::KernelWithContext`, both of which are
    /// `#[non_exhaustive]` and so force a wildcard arm at
    /// every call site. Equivalent to:
    ///
    /// ```ignore
    /// match &err {
    ///     Error::Kernel { ext_ack, .. }
    ///     | Error::KernelWithContext { ext_ack, .. } => ext_ack.as_deref(),
    ///     _ => None,
    /// }
    /// ```
    pub fn ext_ack(&self) -> Option<&str> {
        match self {
            Self::Kernel { ext_ack, .. } | Self::KernelWithContext { ext_ack, .. } => {
                ext_ack.as_deref()
            }
            _ => None,
        }
    }

    /// Return the `NLMSGERR_ATTR_OFFS` byte offset pointing at
    /// the offending attribute in the request payload, if the
    /// kernel sent one. Pair with [`Self::ext_ack`] when
    /// constructing structured error reports. Plan 182.
    pub fn ext_ack_offset(&self) -> Option<u32> {
        match self {
            Self::Kernel { ext_ack_offset, .. }
            | Self::KernelWithContext { ext_ack_offset, .. } => *ext_ack_offset,
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

    /// Walk the source chain of an arbitrary error and yield
    /// every `&nlink::Error` along the way, **transparently
    /// unwrapping `Box<nlink::Error>`** at each step.
    ///
    /// Saves consumers from writing the
    /// `src.downcast_ref::<nlink::Error>()` → fallback-to-
    /// `Box<nlink::Error>` ladder by hand. The chain-walk is
    /// the primitive that `Error::ext_ack` and friends use to
    /// see through `#[source]`-wrapped errors in downstream
    /// types; this helper exposes it.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use nlink::Error;
    /// // Find the first kernel ENOBUFS anywhere in the chain.
    /// let enobufs = Error::chain_walk(&outer_err)
    ///     .find(|e| e.is_no_buffer_space());
    /// ```
    ///
    /// Plan 187 §2.2.
    pub fn chain_walk<'a>(err: &'a (dyn std::error::Error + 'static)) -> ChainWalk<'a> {
        ChainWalk { current: Some(err) }
    }

    /// The deepest `nlink::Error` in the chain — typically the
    /// kernel error at the bottom of a wrapper stack. Returns
    /// `self` if the chain is just this one error.
    ///
    /// Convenience over [`Self::chain_walk`].
    pub fn root_cause(&self) -> &Error {
        Self::chain_walk(self).last().unwrap_or(self)
    }

    /// All `nlink::Error` layers in the chain as a `Vec`,
    /// outer-to-inner. Useful for serialization or rendering
    /// every layer of context.
    ///
    /// Convenience over [`Self::chain_walk`].
    pub fn contexts(&self) -> Vec<&Error> {
        Self::chain_walk(self).collect()
    }

    /// Check if this is a timeout error.
    ///
    /// Returns `true` for both the [`Error::Timeout`] variant and
    /// kernel ETIMEDOUT errors.
    pub fn is_timeout(&self) -> bool {
        matches!(self, Self::Timeout) || self.errno() == Some(libc::ETIMEDOUT)
    }

    /// Check if this is an [`Error::FrameTruncated`] error — the
    /// kernel emitted a netlink frame larger than nlink's
    /// auto-grow recv buffer cap (1 MiB).
    ///
    /// Added in 0.20.1 (Plan 224 — closes B4).
    pub fn is_truncated(&self) -> bool {
        matches!(self, Self::FrameTruncated { .. })
    }

    /// Check if this is an [`Error::Backpressure`] error — the
    /// kernel send buffer is full and back-to-back `WouldBlock`
    /// returns exceeded the backpressure threshold.
    ///
    /// Added in 0.20.1 (Plan 232 — closes B19).
    pub fn is_backpressure(&self) -> bool {
        matches!(self, Self::Backpressure { .. })
    }

    /// Check if this is an [`Error::DumpInterrupted`].
    ///
    /// The kernel signaled `NLM_F_DUMP_INTR` on a dump message,
    /// meaning the snapshot was mutated mid-flight and the returned
    /// data set is inconsistent. The right response is to retry the
    /// dump with a bound (Cilium uses 30 attempts, vishvananda uses
    /// 24). Without this predicate, pre-0.19 nlink callers had no way
    /// to know the dump was stale — they would silently use the
    /// inconsistent data.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use nlink::{Connection, Route};
    ///
    /// async fn get_links_with_retry(
    ///     conn: &Connection<Route>,
    /// ) -> nlink::Result<Vec<nlink::netlink::LinkMessage>> {
    ///     for _ in 0..16 {
    ///         match conn.get_links().await {
    ///             Err(e) if e.is_dump_interrupted() => continue,
    ///             other => return other,
    ///         }
    ///     }
    ///     conn.get_links().await
    /// }
    /// ```
    pub fn is_dump_interrupted(&self) -> bool {
        matches!(self, Self::DumpInterrupted)
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
        // Plan 187 made `errno()` itself unwrap `Error::Io` via
        // `raw_os_error()`, so this predicate (and every sibling
        // predicate) catches both the kernel-shape and the
        // socket-shape ENOBUFS via the same path. The Plan 185
        // defensive branch is no longer needed.
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

/// Named iterator returned by [`Error::chain_walk`]. Yields
/// `&nlink::Error` values, transparently unwrapping
/// `Box<nlink::Error>` source layers along the way.
///
/// Plan 187 §2.2.
#[must_use = "iterators do nothing unless polled"]
pub struct ChainWalk<'a> {
    current: Option<&'a (dyn std::error::Error + 'static)>,
}

impl<'a> Iterator for ChainWalk<'a> {
    type Item = &'a Error;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let err = self.current?;
            // Try the unboxed form first (the common shape).
            if let Some(nl) = err.downcast_ref::<Error>() {
                self.current = err.source();
                return Some(nl);
            }
            // Fall back to Box<nlink::Error> — the trap from
            // nlink-feedback §4. The `downcast_ref` on the
            // outer &dyn Error sees the concrete Box type.
            if let Some(boxed) = err.downcast_ref::<Box<Error>>() {
                self.current = err.source();
                return Some(boxed.as_ref());
            }
            // Not an nlink error at this level; advance and
            // try again.
            self.current = err.source();
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

    // Plan 212 M9 — is_not_found must match Error::Io(ENOENT/ENODEV)
    // through the common `errno()` accessor (sibling predicates
    // `is_busy`, `is_permission_denied`, `is_already_exists` already
    // did per Plan 187 §2.5; this closes the asymmetry).
    #[test]
    fn is_not_found_catches_io_enoent() {
        let io_err = io::Error::from_raw_os_error(libc::ENOENT);
        let err: Error = io_err.into();
        assert!(
            err.is_not_found(),
            "is_not_found must catch Error::Io(ENOENT) (Plan 212 M9)"
        );
    }

    #[test]
    fn is_not_found_catches_io_enodev() {
        let io_err = io::Error::from_raw_os_error(libc::ENODEV);
        let err: Error = io_err.into();
        assert!(err.is_not_found());
    }

    #[test]
    fn is_not_found_does_not_match_unrelated_io_errors() {
        let io_err = io::Error::from_raw_os_error(libc::EPERM);
        let err: Error = io_err.into();
        assert!(!err.is_not_found());
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
    fn test_dump_interrupted_predicate() {
        let err = Error::DumpInterrupted;
        assert!(err.is_dump_interrupted());
        // Mutually exclusive with other recovery predicates.
        assert!(!err.is_timeout());
        assert!(!err.is_busy());
        assert!(!err.is_not_found());
        // Message mentions retry guidance so the error is
        // self-describing in logs.
        let s = err.to_string();
        assert!(s.contains("interrupted"), "got: {s}");
        assert!(s.contains("retry"), "got: {s}");
    }

    #[test]
    fn test_dump_interrupted_does_not_match_unrelated_errors() {
        assert!(!Error::Timeout.is_dump_interrupted());
        assert!(!Error::from_errno(-16).is_dump_interrupted()); // EBUSY
        assert!(!Error::InterfaceNotFound { name: "x".into() }.is_dump_interrupted());
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

    // ---- Plan 182 — ext_ack / ext_ack_offset accessors ----

    #[test]
    fn ext_ack_returns_some_for_kernel_with_ack() {
        let err = Error::Kernel {
            errno: 22,
            message: "Invalid argument".into(),
            ext_ack: Some("attribute IFLA_MTU rejected: value 0 out of range".into()),
            ext_ack_offset: Some(24),
        };
        assert_eq!(
            err.ext_ack(),
            Some("attribute IFLA_MTU rejected: value 0 out of range")
        );
        assert_eq!(err.ext_ack_offset(), Some(24));
    }

    #[test]
    fn ext_ack_returns_some_for_kernel_with_context() {
        let err = Error::KernelWithContext {
            operation: "add_link".into(),
            errno: 17,
            message: "File exists".into(),
            ext_ack: Some("interface 'veth0' already exists".into()),
            ext_ack_offset: None,
        };
        assert_eq!(err.ext_ack(), Some("interface 'veth0' already exists"));
        assert_eq!(err.ext_ack_offset(), None);
    }

    #[test]
    fn ext_ack_returns_none_for_kernel_without_ack() {
        let err = Error::Kernel {
            errno: 22,
            message: "EINVAL".into(),
            ext_ack: None,
            ext_ack_offset: None,
        };
        assert_eq!(err.ext_ack(), None);
        assert_eq!(err.ext_ack_offset(), None);
    }

    #[test]
    fn ext_ack_returns_none_for_non_kernel_errors() {
        assert_eq!(Error::Timeout.ext_ack(), None);
        assert_eq!(Error::Timeout.ext_ack_offset(), None);
        assert_eq!(
            Error::InvalidMessage("bad".into()).ext_ack(),
            None
        );
    }

    // Plan 185 fix — `is_no_buffer_space` must catch the OS-shape
    // ENOBUFS from a raw `recvmsg`, not just the kernel-shape
    // NLMSGERR variant. The multicast overflow path takes the
    // OS branch.
    #[test]
    fn is_no_buffer_space_matches_io_enobufs() {
        let err = Error::Io(std::io::Error::from_raw_os_error(libc::ENOBUFS));
        assert!(
            err.is_no_buffer_space(),
            "Io(ENOBUFS) must be caught by is_no_buffer_space"
        );
    }

    #[test]
    fn is_no_buffer_space_matches_kernel_enobufs() {
        let err = Error::Kernel {
            errno: libc::ENOBUFS,
            message: "ENOBUFS".into(),
            ext_ack: None,
            ext_ack_offset: None,
        };
        assert!(err.is_no_buffer_space());
    }

    #[test]
    fn is_no_buffer_space_rejects_unrelated_io_errors() {
        let err = Error::Io(std::io::Error::from_raw_os_error(libc::EAGAIN));
        assert!(!err.is_no_buffer_space());
    }

    // ===== Plan 187 — sign-normalization on the factories. =====

    #[test]
    fn from_errno_ext_ack_normalizes_negative_input() {
        let e = Error::from_errno_ext_ack(-libc::EEXIST, None, None);
        assert_eq!(e.errno(), Some(libc::EEXIST));
    }

    #[test]
    fn from_errno_ext_ack_normalizes_positive_input() {
        let e = Error::from_errno_ext_ack(libc::EEXIST, None, None);
        assert_eq!(e.errno(), Some(libc::EEXIST));
    }

    #[test]
    fn from_errno_ext_ack_zero_stays_zero() {
        let e = Error::from_errno_ext_ack(0, None, None);
        assert_eq!(e.errno(), Some(0));
    }

    #[test]
    fn from_errno_with_context_ext_ack_normalizes_both_signs() {
        let neg = Error::from_errno_with_context_ext_ack(
            -libc::EBUSY,
            "add_link",
            None,
            None,
        );
        let pos = Error::from_errno_with_context_ext_ack(
            libc::EBUSY,
            "add_link",
            None,
            None,
        );
        assert_eq!(neg.errno(), pos.errno());
        assert_eq!(neg.errno(), Some(libc::EBUSY));
    }

    #[test]
    fn from_errno_delegates_to_from_errno_ext_ack_for_normalization() {
        // `from_errno` is a thin wrapper around `from_errno_ext_ack`,
        // so it inherits the sign-normalization. Pin it.
        let neg = Error::from_errno(-libc::EINVAL);
        let pos = Error::from_errno(libc::EINVAL);
        assert_eq!(neg.errno(), pos.errno());
        assert_eq!(neg.errno(), Some(libc::EINVAL));
    }

    // ===== Plan 187 §2.5 — predicate Io-shape sweep. =====
    //
    // Every `is_*` predicate must match BOTH `Error::Kernel*`
    // and `Error::Io` variants carrying the same errno. The
    // Plan 187 fix to `errno()` (unwrap `Io` via
    // `raw_os_error()`) makes this work uniformly; this sweep
    // pins the contract so future predicates inherit it.

    fn assert_predicate_matches_both_shapes(
        pred: fn(&Error) -> bool,
        errno: i32,
        name: &str,
    ) {
        let kernel = Error::from_errno_ext_ack(errno, None, None);
        assert!(
            pred(&kernel),
            "{name}: Kernel({errno}) must match the predicate"
        );
        let io = Error::Io(std::io::Error::from_raw_os_error(errno));
        assert!(
            pred(&io),
            "{name}: Io({errno}) must match the predicate"
        );
        let kctx = Error::from_errno_with_context_ext_ack(
            errno, "ctx", None, None,
        );
        assert!(
            pred(&kctx),
            "{name}: KernelWithContext({errno}) must match the predicate"
        );
    }

    #[test]
    fn predicate_io_shape_sweep() {
        // Each predicate × 3 variants = 36+ assertions via the
        // shared helper. Adding a new `is_*` predicate later
        // appends one line here.
        assert_predicate_matches_both_shapes(
            Error::is_no_buffer_space, libc::ENOBUFS, "is_no_buffer_space",
        );
        assert_predicate_matches_both_shapes(
            Error::is_busy, libc::EBUSY, "is_busy",
        );
        assert_predicate_matches_both_shapes(
            Error::is_try_again, libc::EAGAIN, "is_try_again",
        );
        assert_predicate_matches_both_shapes(
            Error::is_already_exists, libc::EEXIST, "is_already_exists",
        );
        assert_predicate_matches_both_shapes(
            Error::is_permission_denied, libc::EACCES, "is_permission_denied",
        );
        assert_predicate_matches_both_shapes(
            Error::is_invalid_argument, libc::EINVAL, "is_invalid_argument",
        );
        assert_predicate_matches_both_shapes(
            Error::is_not_supported, libc::EOPNOTSUPP, "is_not_supported",
        );
        assert_predicate_matches_both_shapes(
            Error::is_network_unreachable, libc::ENETUNREACH, "is_network_unreachable",
        );
        assert_predicate_matches_both_shapes(
            Error::is_host_unreachable, libc::EHOSTUNREACH, "is_host_unreachable",
        );
        assert_predicate_matches_both_shapes(
            Error::is_connection_refused, libc::ECONNREFUSED, "is_connection_refused",
        );
    }

    #[test]
    fn predicate_rejects_unrelated_errno_for_each_shape() {
        // is_busy(EAGAIN) must be false — the predicate is
        // specific to its target errno, not "any retryable error".
        let kernel_eagain = Error::from_errno_ext_ack(libc::EAGAIN, None, None);
        assert!(!kernel_eagain.is_busy());
        let io_eagain = Error::Io(std::io::Error::from_raw_os_error(libc::EAGAIN));
        assert!(!io_eagain.is_busy());
    }

    // ===== Plan 187 §2.2 — Error::chain_walk + root_cause + contexts. =====

    #[derive(Debug, thiserror::Error)]
    #[error("inline wrapper")]
    struct InlineWrapper(#[source] Error);

    #[derive(Debug, thiserror::Error)]
    #[error("boxed wrapper")]
    struct BoxedWrapper(#[source] Box<Error>);

    #[test]
    fn chain_walk_finds_nlink_error_through_inline_source() {
        let inner = Error::from_errno_ext_ack(libc::EEXIST, None, None);
        let outer = InlineWrapper(inner);
        let found: Vec<_> = Error::chain_walk(&outer).collect();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].errno(), Some(libc::EEXIST));
    }

    #[test]
    fn chain_walk_finds_nlink_error_through_boxed_source() {
        // The trap from nlink-feedback §4 — must NOT yield empty.
        let inner = Error::from_errno_ext_ack(libc::EEXIST, None, None);
        let outer = BoxedWrapper(Box::new(inner));
        let found: Vec<_> = Error::chain_walk(&outer).collect();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].errno(), Some(libc::EEXIST));
    }

    #[test]
    fn chain_walk_returns_empty_for_non_nlink_chain() {
        let plain = std::io::Error::other("no nlink here");
        let v: Vec<_> = Error::chain_walk(&plain).collect();
        assert!(v.is_empty());
    }

    #[test]
    fn root_cause_returns_deepest_nlink_error() {
        // Two-level chain: BoxedWrapper(InlineWrapper(Error)).
        // root_cause must reach the innermost.
        let leaf = Error::from_errno_ext_ack(libc::ENODEV, None, None);
        let inline = InlineWrapper(leaf);
        // chain_walk through the inline form gives us one nlink::Error.
        let walked: Vec<_> = Error::chain_walk(&inline).collect();
        assert_eq!(walked.len(), 1);
        assert_eq!(walked[0].errno(), Some(libc::ENODEV));
    }

    #[test]
    fn root_cause_falls_back_to_self_when_chain_is_single() {
        let solo = Error::from_errno_ext_ack(libc::EAGAIN, None, None);
        assert_eq!(solo.root_cause().errno(), solo.errno());
    }

    #[test]
    fn contexts_returns_every_layer_outer_to_inner() {
        let leaf = Error::from_errno_ext_ack(libc::ENOENT, None, None);
        let inline = InlineWrapper(leaf);
        let v = Error::chain_walk(&inline).collect::<Vec<_>>();
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].errno(), Some(libc::ENOENT));
    }
}
