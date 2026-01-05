//! Ethtool bitset parsing and building.
//!
//! Ethtool uses a special bitset format for feature flags and link modes.
//! There are two formats:
//!
//! 1. **Compact format**: Two bitmaps (values + mask)
//! 2. **Bit-by-bit format**: Nested list of (index, name, value) tuples
//!
//! This module handles both formats transparently.

use std::collections::HashMap;

use crate::netlink::attr::AttrIter;
use crate::netlink::error::Result;

use super::{EthtoolBitsetAttr, EthtoolBitsetBitAttr};

/// An ethtool bitset.
///
/// Represents a set of named bits, each with an index, name, and value.
#[derive(Debug, Clone, Default)]
pub struct EthtoolBitset {
    /// Number of bits in the set.
    size: u32,
    /// Bit values by index.
    values: HashMap<u32, bool>,
    /// Bit names by index.
    names: HashMap<u32, String>,
    /// Index lookup by name.
    name_to_index: HashMap<String, u32>,
}

impl EthtoolBitset {
    /// Create an empty bitset.
    pub fn new() -> Self {
        Self::default()
    }

    /// Parse a bitset from netlink attributes.
    ///
    /// Handles both compact and bit-by-bit formats.
    pub fn parse(data: &[u8]) -> Result<Self> {
        let mut bitset = Self::new();
        let mut compact_value: Option<&[u8]> = None;
        let mut compact_mask: Option<&[u8]> = None;
        let mut is_nomask = false;

        for (attr_type, payload) in AttrIter::new(data) {
            match attr_type {
                t if t == EthtoolBitsetAttr::Nomask as u16 => {
                    is_nomask = true;
                }
                t if t == EthtoolBitsetAttr::Size as u16 => {
                    if payload.len() >= 4 {
                        bitset.size = u32::from_ne_bytes(payload[..4].try_into().unwrap());
                    }
                }
                t if t == EthtoolBitsetAttr::Value as u16 => {
                    compact_value = Some(payload);
                }
                t if t == EthtoolBitsetAttr::Mask as u16 => {
                    compact_mask = Some(payload);
                }
                t if t == EthtoolBitsetAttr::Bits as u16 => {
                    // Bit-by-bit format
                    bitset.parse_bits(payload)?;
                }
                _ => {}
            }
        }

        // Handle compact format
        if let Some(value) = compact_value {
            bitset.parse_compact(value, compact_mask, is_nomask)?;
        }

        Ok(bitset)
    }

    /// Parse bit-by-bit format.
    fn parse_bits(&mut self, data: &[u8]) -> Result<()> {
        for (_idx, bit_data) in AttrIter::new(data) {
            let mut index: Option<u32> = None;
            let mut name: Option<String> = None;
            let mut value = false;

            for (attr_type, payload) in AttrIter::new(bit_data) {
                match attr_type {
                    t if t == EthtoolBitsetBitAttr::Index as u16 => {
                        if payload.len() >= 4 {
                            index = Some(u32::from_ne_bytes(payload[..4].try_into().unwrap()));
                        }
                    }
                    t if t == EthtoolBitsetBitAttr::Name as u16 => {
                        name = Some(
                            std::str::from_utf8(payload)
                                .unwrap_or("")
                                .trim_end_matches('\0')
                                .to_string(),
                        );
                    }
                    t if t == EthtoolBitsetBitAttr::Value as u16 => {
                        // Flag attribute - presence means true
                        value = true;
                    }
                    _ => {}
                }
            }

            if let Some(idx) = index {
                self.values.insert(idx, value);
                if let Some(n) = name {
                    self.name_to_index.insert(n.clone(), idx);
                    self.names.insert(idx, n);
                }
            }
        }

        Ok(())
    }

    /// Parse compact bitmap format.
    fn parse_compact(&mut self, value: &[u8], mask: Option<&[u8]>, is_nomask: bool) -> Result<()> {
        let bits_count = self.size.min((value.len() * 8) as u32);

        for bit_idx in 0..bits_count {
            let byte_idx = (bit_idx / 8) as usize;
            let bit_pos = bit_idx % 8;

            if byte_idx >= value.len() {
                break;
            }

            let bit_value = (value[byte_idx] >> bit_pos) & 1 != 0;

            // Check if this bit is in the mask (relevant)
            let in_mask = if is_nomask {
                true
            } else if let Some(m) = mask {
                if byte_idx < m.len() {
                    (m[byte_idx] >> bit_pos) & 1 != 0
                } else {
                    false
                }
            } else {
                true
            };

            if in_mask {
                self.values.insert(bit_idx, bit_value);
            }
        }

        Ok(())
    }

    /// Check if a bit is set by name.
    pub fn is_set(&self, name: &str) -> bool {
        if let Some(&idx) = self.name_to_index.get(name) {
            self.values.get(&idx).copied().unwrap_or(false)
        } else {
            false
        }
    }

    /// Check if a bit is set by index.
    pub fn is_set_by_index(&self, index: u32) -> bool {
        self.values.get(&index).copied().unwrap_or(false)
    }

    /// Get the name of a bit by index.
    pub fn name(&self, index: u32) -> Option<&str> {
        self.names.get(&index).map(|s| s.as_str())
    }

    /// Get the index of a bit by name.
    pub fn index(&self, name: &str) -> Option<u32> {
        self.name_to_index.get(name).copied()
    }

    /// Get all active (set) bit names.
    pub fn active_names(&self) -> Vec<&str> {
        self.values
            .iter()
            .filter(|&(_, v)| *v)
            .filter_map(|(idx, _)| self.names.get(idx).map(|s| s.as_str()))
            .collect()
    }

    /// Get all bit names (set or not).
    pub fn all_names(&self) -> Vec<&str> {
        self.names.values().map(|s| s.as_str()).collect()
    }

    /// Iterate over all bits with their values.
    pub fn iter(&self) -> impl Iterator<Item = (&str, bool)> {
        self.names.iter().map(|(idx, name)| {
            let value = self.values.get(idx).copied().unwrap_or(false);
            (name.as_str(), value)
        })
    }

    /// Get the number of bits.
    pub fn len(&self) -> usize {
        self.names.len()
    }

    /// Check if the bitset is empty.
    pub fn is_empty(&self) -> bool {
        self.names.is_empty()
    }

    /// Set a bit by name.
    pub fn set(&mut self, name: &str, value: bool) {
        if let Some(&idx) = self.name_to_index.get(name) {
            self.values.insert(idx, value);
        } else {
            // Add new bit with auto-assigned index
            let idx = self.names.len() as u32;
            self.names.insert(idx, name.to_string());
            self.name_to_index.insert(name.to_string(), idx);
            self.values.insert(idx, value);
        }
    }

    /// Add a named bit.
    pub fn add(&mut self, index: u32, name: &str, value: bool) {
        self.names.insert(index, name.to_string());
        self.name_to_index.insert(name.to_string(), index);
        self.values.insert(index, value);
        if index >= self.size {
            self.size = index + 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bitset_set_get() {
        let mut bs = EthtoolBitset::new();
        bs.add(0, "tx-checksum", true);
        bs.add(1, "rx-checksum", false);
        bs.add(2, "tso", true);

        assert!(bs.is_set("tx-checksum"));
        assert!(!bs.is_set("rx-checksum"));
        assert!(bs.is_set("tso"));
        assert!(!bs.is_set("nonexistent"));

        assert_eq!(bs.index("tx-checksum"), Some(0));
        assert_eq!(bs.name(0), Some("tx-checksum"));
    }

    #[test]
    fn test_active_names() {
        let mut bs = EthtoolBitset::new();
        bs.add(0, "a", true);
        bs.add(1, "b", false);
        bs.add(2, "c", true);

        let active: Vec<_> = bs.active_names();
        assert_eq!(active.len(), 2);
        assert!(active.contains(&"a"));
        assert!(active.contains(&"c"));
    }
}
