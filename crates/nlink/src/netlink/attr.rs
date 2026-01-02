//! Netlink attribute (rtattr/nlattr) handling.

use super::error::{Error, Result};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

/// Netlink attribute alignment.
pub const NLA_ALIGNTO: usize = 4;

/// Align a length to NLA_ALIGNTO boundary.
#[inline]
pub const fn nla_align(len: usize) -> usize {
    (len + NLA_ALIGNTO - 1) & !(NLA_ALIGNTO - 1)
}

/// Size of the attribute header.
pub const NLA_HDRLEN: usize = 4; // nla_align(size_of::<NlAttr>())

/// Netlink attribute header (mirrors struct nlattr / struct rtattr).
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct NlAttr {
    /// Length including header.
    pub nla_len: u16,
    /// Attribute type.
    pub nla_type: u16,
}

/// Attribute type flags.
pub const NLA_F_NESTED: u16 = 1 << 15;
pub const NLA_F_NET_BYTEORDER: u16 = 1 << 14;
pub const NLA_TYPE_MASK: u16 = !(NLA_F_NESTED | NLA_F_NET_BYTEORDER);

impl NlAttr {
    /// Create a new attribute header.
    pub fn new(attr_type: u16, data_len: usize) -> Self {
        Self {
            nla_len: (NLA_HDRLEN + data_len) as u16,
            nla_type: attr_type,
        }
    }

    /// Get the attribute type without flags.
    pub fn kind(&self) -> u16 {
        self.nla_type & NLA_TYPE_MASK
    }

    /// Check if this is a nested attribute.
    pub fn is_nested(&self) -> bool {
        self.nla_type & NLA_F_NESTED != 0
    }

    /// Get the payload length (total length minus header).
    pub fn payload_len(&self) -> usize {
        (self.nla_len as usize).saturating_sub(NLA_HDRLEN)
    }

    /// Convert to bytes.
    pub fn as_bytes(&self) -> &[u8] {
        <Self as IntoBytes>::as_bytes(self)
    }

    /// Parse from bytes.
    pub fn from_bytes(data: &[u8]) -> Result<&Self> {
        Self::ref_from_prefix(data)
            .map(|(r, _)| r)
            .map_err(|_| Error::Truncated {
                expected: std::mem::size_of::<Self>(),
                actual: data.len(),
            })
    }
}

/// Iterator over netlink attributes in a buffer.
pub struct AttrIter<'a> {
    data: &'a [u8],
}

impl<'a> AttrIter<'a> {
    /// Create a new attribute iterator.
    pub fn new(data: &'a [u8]) -> Self {
        Self { data }
    }

    /// Check if there are no more attributes.
    pub fn is_empty(&self) -> bool {
        self.data.len() < NLA_HDRLEN
    }
}

impl<'a> Iterator for AttrIter<'a> {
    /// Returns (attribute type, payload data).
    type Item = (u16, &'a [u8]);

    fn next(&mut self) -> Option<Self::Item> {
        if self.data.len() < NLA_HDRLEN {
            return None;
        }

        let attr = match NlAttr::from_bytes(self.data) {
            Ok(a) => a,
            Err(_) => return None,
        };

        let len = attr.nla_len as usize;
        if len < NLA_HDRLEN || len > self.data.len() {
            return None;
        }

        let payload = &self.data[NLA_HDRLEN..len];
        let aligned_len = nla_align(len);

        // Move to next attribute
        if aligned_len >= self.data.len() {
            self.data = &[];
        } else {
            self.data = &self.data[aligned_len..];
        }

        Some((attr.kind(), payload))
    }
}

/// Helper functions for extracting typed values from attribute payloads.
pub mod get {
    use super::*;

    /// Extract a u8 value.
    pub fn u8(data: &[u8]) -> Result<u8> {
        if data.is_empty() {
            return Err(Error::InvalidAttribute("empty u8 attribute".into()));
        }
        Ok(data[0])
    }

    /// Extract a u16 value (native endian).
    pub fn u16_ne(data: &[u8]) -> Result<u16> {
        if data.len() < 2 {
            return Err(Error::InvalidAttribute("truncated u16 attribute".into()));
        }
        Ok(u16::from_ne_bytes([data[0], data[1]]))
    }

    /// Extract a u32 value (native endian).
    pub fn u32_ne(data: &[u8]) -> Result<u32> {
        if data.len() < 4 {
            return Err(Error::InvalidAttribute("truncated u32 attribute".into()));
        }
        Ok(u32::from_ne_bytes([data[0], data[1], data[2], data[3]]))
    }

    /// Extract a u64 value (native endian).
    pub fn u64_ne(data: &[u8]) -> Result<u64> {
        if data.len() < 8 {
            return Err(Error::InvalidAttribute("truncated u64 attribute".into()));
        }
        Ok(u64::from_ne_bytes([
            data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
        ]))
    }

    /// Extract a u16 value (big endian / network order).
    pub fn u16_be(data: &[u8]) -> Result<u16> {
        if data.len() < 2 {
            return Err(Error::InvalidAttribute("truncated u16 attribute".into()));
        }
        Ok(u16::from_be_bytes([data[0], data[1]]))
    }

    /// Extract a u32 value (big endian / network order).
    pub fn u32_be(data: &[u8]) -> Result<u32> {
        if data.len() < 4 {
            return Err(Error::InvalidAttribute("truncated u32 attribute".into()));
        }
        Ok(u32::from_be_bytes([data[0], data[1], data[2], data[3]]))
    }

    /// Extract a null-terminated string.
    pub fn string(data: &[u8]) -> Result<&str> {
        // Find null terminator or use whole buffer
        let len = data.iter().position(|&b| b == 0).unwrap_or(data.len());
        std::str::from_utf8(&data[..len])
            .map_err(|e| Error::InvalidAttribute(format!("invalid UTF-8: {}", e)))
    }

    /// Extract bytes (no interpretation).
    pub fn bytes(data: &[u8]) -> &[u8] {
        data
    }

    /// Extract an i32 value (native endian).
    pub fn i32_ne(data: &[u8]) -> Result<i32> {
        if data.len() < 4 {
            return Err(Error::InvalidAttribute("truncated i32 attribute".into()));
        }
        Ok(i32::from_ne_bytes([data[0], data[1], data[2], data[3]]))
    }
}
