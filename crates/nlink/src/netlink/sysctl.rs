//! Sysctl management via `/proc/sys/`.
//!
//! This module provides functions for reading and writing kernel parameters
//! (sysctls) through the `/proc/sys/` filesystem. For namespace-aware
//! operations, use the wrappers in [`super::namespace`].
//!
//! # Example
//!
//! ```ignore
//! use nlink::netlink::sysctl;
//!
//! // Read a sysctl value
//! let val = sysctl::get("net.ipv4.ip_forward")?;
//! println!("ip_forward = {}", val);
//!
//! // Set a sysctl value (requires root)
//! sysctl::set("net.ipv4.ip_forward", "1")?;
//!
//! // Set multiple values at once
//! sysctl::set_many(&[
//!     ("net.ipv4.ip_forward", "1"),
//!     ("net.ipv6.conf.all.forwarding", "1"),
//! ])?;
//! ```

use std::path::PathBuf;

use super::error::{Error, Result};

/// Convert a dotted sysctl key to a `/proc/sys/` path.
///
/// # Example
///
/// ```ignore
/// assert_eq!(
///     sysctl_path("net.ipv4.ip_forward")?,
///     PathBuf::from("/proc/sys/net/ipv4/ip_forward"),
/// );
/// ```
fn sysctl_path(key: &str) -> Result<PathBuf> {
    validate_key(key)?;
    let relative = key.replace('.', "/");
    Ok(PathBuf::from("/proc/sys").join(relative))
}

/// Validate a sysctl key to prevent path traversal.
fn validate_key(key: &str) -> Result<()> {
    if key.is_empty() {
        return Err(Error::InvalidMessage("sysctl key cannot be empty".into()));
    }
    if key.contains("..") || key.starts_with('/') || key.contains('\0') {
        return Err(Error::InvalidMessage(format!(
            "invalid sysctl key: {}",
            key
        )));
    }
    Ok(())
}

/// Read a sysctl value.
///
/// Reads from `/proc/sys/` in the current namespace. For namespace-aware
/// operations, use [`super::namespace::get_sysctl`].
///
/// # Example
///
/// ```ignore
/// use nlink::netlink::sysctl;
///
/// let val = sysctl::get("net.ipv4.ip_forward")?;
/// assert!(val == "0" || val == "1");
/// ```
pub fn get(key: &str) -> Result<String> {
    let path = sysctl_path(key)?;
    let contents = std::fs::read_to_string(&path).map_err(|e| match e.kind() {
        std::io::ErrorKind::NotFound => {
            Error::InvalidMessage(format!("sysctl key not found: {}", key))
        }
        std::io::ErrorKind::PermissionDenied => Error::Io(e),
        _ => Error::Io(e),
    })?;
    Ok(contents.trim_end().to_string())
}

/// Set a sysctl value.
///
/// Writes to `/proc/sys/` in the current namespace. Requires root or
/// `CAP_SYS_ADMIN`. For namespace-aware operations, use
/// [`super::namespace::set_sysctl`].
///
/// # Example
///
/// ```ignore
/// use nlink::netlink::sysctl;
///
/// sysctl::set("net.ipv4.ip_forward", "1")?;
/// ```
pub fn set(key: &str, value: &str) -> Result<()> {
    let path = sysctl_path(key)?;
    std::fs::write(&path, value).map_err(|e| match e.kind() {
        std::io::ErrorKind::NotFound => {
            Error::InvalidMessage(format!("sysctl key not found: {}", key))
        }
        std::io::ErrorKind::PermissionDenied => Error::Io(e),
        _ => Error::Io(e),
    })?;
    Ok(())
}

/// Set multiple sysctl values.
///
/// Applies all entries in order. If any entry fails, returns the error
/// immediately without applying remaining entries.
///
/// # Example
///
/// ```ignore
/// use nlink::netlink::sysctl;
///
/// sysctl::set_many(&[
///     ("net.ipv4.ip_forward", "1"),
///     ("net.ipv6.conf.all.forwarding", "1"),
/// ])?;
/// ```
pub fn set_many(entries: &[(&str, &str)]) -> Result<()> {
    for &(key, value) in entries {
        set(key, value)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sysctl_path_conversion() {
        assert_eq!(
            sysctl_path("net.ipv4.ip_forward").unwrap(),
            PathBuf::from("/proc/sys/net/ipv4/ip_forward")
        );
        assert_eq!(
            sysctl_path("net.ipv6.conf.all.forwarding").unwrap(),
            PathBuf::from("/proc/sys/net/ipv6/conf/all/forwarding")
        );
    }

    #[test]
    fn test_validate_key_rejects_traversal() {
        assert!(validate_key("net..ipv4").is_err());
        assert!(validate_key("/etc/passwd").is_err());
        assert!(validate_key("").is_err());
        assert!(validate_key("net.ipv4\0.ip_forward").is_err());
    }

    #[test]
    fn test_validate_key_accepts_valid() {
        assert!(validate_key("net.ipv4.ip_forward").is_ok());
        assert!(validate_key("net.ipv6.conf.all.forwarding").is_ok());
        assert!(validate_key("kernel.hostname").is_ok());
    }
}
