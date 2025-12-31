//! TC handle parsing and formatting utilities.
//!
//! TC handles are 32-bit values split into major:minor parts (16 bits each).
//! They identify qdiscs, classes, and filters in the traffic control hierarchy.

use rip_netlink::Error;

/// Special handle values.
pub mod constants {
    /// Root qdisc handle.
    pub const ROOT: u32 = 0xFFFFFFFF;
    /// Ingress qdisc handle.
    pub const INGRESS: u32 = 0xFFFFFFF1;
    /// Clsact qdisc handle.
    pub const CLSACT: u32 = 0xFFFFFFF2;
    /// Unspecified handle.
    pub const UNSPEC: u32 = 0;
}

pub use constants::*;

/// A parsed TC handle with major:minor components.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Handle {
    /// Major number (upper 16 bits).
    pub major: u16,
    /// Minor number (lower 16 bits).
    pub minor: u16,
}

impl Handle {
    /// Create a new handle from major:minor components.
    pub const fn new(major: u16, minor: u16) -> Self {
        Self { major, minor }
    }

    /// Create a handle from a raw 32-bit value.
    pub const fn from_raw(raw: u32) -> Self {
        Self {
            major: (raw >> 16) as u16,
            minor: (raw & 0xFFFF) as u16,
        }
    }

    /// Convert to a raw 32-bit value.
    pub const fn to_raw(self) -> u32 {
        ((self.major as u32) << 16) | (self.minor as u32)
    }

    /// Check if this is the root handle.
    pub const fn is_root(self) -> bool {
        self.to_raw() == ROOT
    }

    /// Check if this is the ingress handle.
    pub const fn is_ingress(self) -> bool {
        self.to_raw() == INGRESS
    }

    /// Check if this is the clsact handle.
    pub const fn is_clsact(self) -> bool {
        self.to_raw() == CLSACT
    }

    /// Check if this handle is unspecified.
    pub const fn is_unspec(self) -> bool {
        self.to_raw() == UNSPEC
    }
}

impl From<u32> for Handle {
    fn from(raw: u32) -> Self {
        Self::from_raw(raw)
    }
}

impl From<Handle> for u32 {
    fn from(handle: Handle) -> Self {
        handle.to_raw()
    }
}

/// Make a handle from major:minor components.
pub const fn make(major: u16, minor: u16) -> u32 {
    ((major as u32) << 16) | (minor as u32)
}

/// Get the major number from a handle.
pub const fn major(handle: u32) -> u16 {
    (handle >> 16) as u16
}

/// Get the minor number from a handle.
pub const fn minor(handle: u32) -> u16 {
    (handle & 0xFFFF) as u16
}

/// Format a handle as a string (e.g., "1:0", "root", "ingress").
pub fn format_handle(handle: u32) -> String {
    match handle {
        ROOT => "root".to_string(),
        INGRESS => "ingress".to_string(),
        CLSACT => "clsact".to_string(),
        UNSPEC => "none".to_string(),
        _ => {
            let maj = major(handle);
            let min = minor(handle);
            if min == 0 {
                format!("{:x}:", maj)
            } else {
                format!("{:x}:{:x}", maj, min)
            }
        }
    }
}

/// Parse a handle from a string (e.g., "1:0", "root", "ingress").
///
/// Returns `None` if the string cannot be parsed as a valid handle.
pub fn parse_handle(s: &str) -> Option<u32> {
    match s {
        "root" => Some(ROOT),
        "ingress" => Some(INGRESS),
        "clsact" => Some(CLSACT),
        "none" => Some(UNSPEC),
        _ => {
            let parts: Vec<&str> = s.split(':').collect();
            if parts.len() == 2 {
                let major = u16::from_str_radix(parts[0], 16).ok()?;
                let minor = if parts[1].is_empty() {
                    0
                } else {
                    u16::from_str_radix(parts[1], 16).ok()?
                };
                Some(make(major, minor))
            } else {
                None
            }
        }
    }
}

/// Parse a handle from a string, returning an error with context if parsing fails.
pub fn parse_handle_or_err(s: &str, context: &str) -> Result<u32, Error> {
    parse_handle(s)
        .ok_or_else(|| Error::InvalidMessage(format!("invalid {} handle: {}", context, s)))
}

/// Parse an optional parent handle, defaulting to ROOT if not specified.
pub fn parse_parent(parent: Option<&str>) -> Result<u32, Error> {
    match parent {
        Some(s) => parse_handle_or_err(s, "parent"),
        None => Ok(ROOT),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_make_and_split() {
        let handle = make(1, 0);
        assert_eq!(major(handle), 1);
        assert_eq!(minor(handle), 0);
        assert_eq!(handle, 0x00010000);

        let handle = make(0x10, 0x20);
        assert_eq!(major(handle), 0x10);
        assert_eq!(minor(handle), 0x20);
    }

    #[test]
    fn test_parse_handle() {
        assert_eq!(parse_handle("root"), Some(ROOT));
        assert_eq!(parse_handle("ingress"), Some(INGRESS));
        assert_eq!(parse_handle("clsact"), Some(CLSACT));
        assert_eq!(parse_handle("none"), Some(UNSPEC));
        assert_eq!(parse_handle("1:"), Some(make(1, 0)));
        assert_eq!(parse_handle("1:0"), Some(make(1, 0)));
        assert_eq!(parse_handle("10:20"), Some(make(0x10, 0x20)));
        assert_eq!(parse_handle("ffff:ffff"), Some(make(0xffff, 0xffff)));
        assert_eq!(parse_handle("invalid"), None);
        assert_eq!(parse_handle("1"), None);
    }

    #[test]
    fn test_format_handle() {
        assert_eq!(format_handle(ROOT), "root");
        assert_eq!(format_handle(INGRESS), "ingress");
        assert_eq!(format_handle(CLSACT), "clsact");
        assert_eq!(format_handle(UNSPEC), "none");
        assert_eq!(format_handle(make(1, 0)), "1:");
        assert_eq!(format_handle(make(0x10, 0x20)), "10:20");
    }

    #[test]
    fn test_handle_struct() {
        let h = Handle::new(1, 0);
        assert_eq!(h.to_raw(), 0x00010000);
        assert!(!h.is_root());

        let h = Handle::from_raw(ROOT);
        assert!(h.is_root());

        let h: Handle = 0x00010000u32.into();
        assert_eq!(h.major, 1);
        assert_eq!(h.minor, 0);

        let raw: u32 = h.into();
        assert_eq!(raw, 0x00010000);
    }
}
