//! Re-exports + runtime substrate for the proc-macro derives
//! from `nlink-macros`.
//!
//! Downstream code typically writes `use nlink::macros::*;` to
//! pull in both the derives and the supporting traits in one
//! shot — no need to depend on `nlink-macros` directly.
//!
//! # What's here
//!
//! - The proc-macro derives [`GenlCommand`], [`GenlAttribute`],
//!   [`GenlEnum`] re-exported from [`nlink-macros`][nlink-macros].
//!   `GenlMessage` and `NetlinkAttrs` derives + the
//!   `#[genl_family]` attribute macro ship in Plan 154 Phase 3b
//!   / Phase 4.
//! - Public traits [`GenlMessage`] and [`NetlinkAttrs`] defining
//!   the wire-protocol contract that the derives implement.
//!   Authors writing a GENL family by hand can implement these
//!   traits directly until the derives ship.
//! - The [`__rt`] runtime module — small helpers the macros
//!   emit calls into. Documented `#[doc(hidden)]` as internal
//!   API; reach for the public surface above instead.
//!
//! [nlink-macros]: https://docs.rs/nlink-macros
//!
//! # Plan 154 progress (the long view)
//!
//! | Phase | Ships | Status |
//! |---|---|---|
//! | 1 | Crate scaffold + `#[derive(GenlCommand)]` | ✓ |
//! | 2 | `#[derive(GenlAttribute)]` + `#[derive(GenlEnum)]` | ✓ |
//! | 3a | `nlink::macros` substrate (this module) | ✓ |
//! | 3b | `#[derive(GenlMessage)]` + `#[derive(NetlinkAttrs)]` | — |
//! | 4 | `#[genl_family(...)]` attribute macro | — |
//! | 5 | `Connection::<F>::send_typed<M, R>` + `dump_typed_stream` | — |
//! | 6 | Worked example + recipe | — |
//! | 7 | Final re-export polish + CHANGELOG framing | — |

pub use nlink_macros::{GenlAttribute, GenlCommand, GenlEnum};

use crate::netlink::MessageBuilder;
use crate::Result;

/// A GENL message that knows how to serialize itself onto the
/// wire and deserialize from an attribute-iterator payload.
///
/// Implemented automatically by `#[derive(GenlMessage)]` (Plan
/// 154 Phase 3b). Can also be implemented by hand against the
/// runtime helpers in [`__rt`] for cases the derive doesn't yet
/// cover.
///
/// # Wire contract
///
/// - `CMD` is the kernel-side command byte (used to populate the
///   GENL header's `cmd` field).
/// - `to_bytes` writes the message body — `MessageBuilder` is
///   positioned after the netlink header + GENL header; the impl
///   appends the message's `nlattr`s.
/// - `from_bytes` parses the attribute payload (already past the
///   netlink + GENL headers).
pub trait GenlMessage: Sized {
    /// Kernel command code for this message (e.g.
    /// `DPLL_CMD_DEVICE_GET = 2`).
    const CMD: u8;

    /// Serialize the message body into the builder. The builder
    /// is already positioned after the netlink + GENL headers;
    /// this impl appends the message's `nlattr`s.
    fn to_bytes(&self, builder: &mut MessageBuilder) -> Result<()>;

    /// Parse the message body from an attribute payload (i.e. the
    /// bytes after the GENL header).
    fn from_bytes(payload: &[u8]) -> Result<Self>;
}

/// A nested-attribute group — a payload struct that doesn't carry
/// a command code but is encoded as the contents of a single
/// `NLA_F_NESTED` attribute.
///
/// Used as the building block for nested fields inside a
/// [`GenlMessage`]; e.g. the DPLL `pin-parent-device` block that
/// lives inside `DPLL_A_PIN_PARENT_DEVICE`.
///
/// Implemented automatically by `#[derive(NetlinkAttrs)]` (Plan
/// 154 Phase 3b).
pub trait NetlinkAttrs: Sized {
    /// Serialize this group's attributes into the builder.
    /// The builder is positioned inside the enclosing nested
    /// attribute; this impl appends the inner `nlattr`s.
    fn write_attrs(&self, builder: &mut MessageBuilder) -> Result<()>;

    /// Parse the inner attribute payload (bytes inside the
    /// enclosing nested attribute, after its header).
    fn read_attrs(payload: &[u8]) -> Result<Self>;
}

/// Runtime helpers that the proc-macro derives emit calls into.
///
/// **Documented as internal API.** Treat as part of the
/// `#[derive(GenlMessage)]` machinery; downstream code that
/// wants to manipulate attributes directly should use
/// [`MessageBuilder`] + [`AttrIter`][crate::netlink::attr::AttrIter]
/// instead.
///
/// The helpers are stable across patch releases but new
/// helpers may be added in minor releases as the derive's
/// type-mapping table grows.
#[doc(hidden)]
pub mod __rt {
    use crate::netlink::{attr::AttrIter, MessageBuilder};
    use crate::{Error, Result};

    // -- emit_* helpers (called by the derived to_bytes) --
    //
    // All emit the attribute in native byte order. For
    // big-endian attributes (rare — mostly netfilter / nftables)
    // the user explicitly opts in via `#[genl_attr_be(...)]`
    // (Phase 3b syntax), which routes through `_be` variants.

    pub fn emit_u8_attr(b: &mut MessageBuilder, attr_type: u16, v: u8) {
        b.append_attr_u8(attr_type, v);
    }
    pub fn emit_u16_attr(b: &mut MessageBuilder, attr_type: u16, v: u16) {
        b.append_attr_u16(attr_type, v);
    }
    pub fn emit_u32_attr(b: &mut MessageBuilder, attr_type: u16, v: u32) {
        b.append_attr_u32(attr_type, v);
    }
    pub fn emit_u64_attr(b: &mut MessageBuilder, attr_type: u16, v: u64) {
        b.append_attr_u64(attr_type, v);
    }
    pub fn emit_str_attr(b: &mut MessageBuilder, attr_type: u16, v: &str) {
        b.append_attr_str(attr_type, v);
    }
    pub fn emit_bytes_attr(b: &mut MessageBuilder, attr_type: u16, v: &[u8]) {
        b.append_attr(attr_type, v);
    }
    pub fn emit_flag_attr(b: &mut MessageBuilder, attr_type: u16) {
        b.append_attr_empty(attr_type);
    }

    // Big-endian variants for nftables-style attributes.
    pub fn emit_u16_be_attr(b: &mut MessageBuilder, attr_type: u16, v: u16) {
        b.append_attr_u16_be(attr_type, v);
    }
    pub fn emit_u32_be_attr(b: &mut MessageBuilder, attr_type: u16, v: u32) {
        b.append_attr_u32_be(attr_type, v);
    }
    pub fn emit_u64_be_attr(b: &mut MessageBuilder, attr_type: u16, v: u64) {
        b.append_attr_u64_be(attr_type, v);
    }

    // -- parse_* helpers (called by the derived from_bytes) --
    //
    // All take the attribute *payload* bytes (already past the
    // nlattr header) and return the typed value.

    pub fn parse_u8_attr(payload: &[u8]) -> Result<u8> {
        if payload.is_empty() {
            return Err(Error::Truncated {
                expected: 1,
                actual: 0,
            });
        }
        Ok(payload[0])
    }
    pub fn parse_u16_attr(payload: &[u8]) -> Result<u16> {
        if payload.len() < 2 {
            return Err(Error::Truncated {
                expected: 2,
                actual: payload.len(),
            });
        }
        Ok(u16::from_ne_bytes([payload[0], payload[1]]))
    }
    pub fn parse_u32_attr(payload: &[u8]) -> Result<u32> {
        if payload.len() < 4 {
            return Err(Error::Truncated {
                expected: 4,
                actual: payload.len(),
            });
        }
        Ok(u32::from_ne_bytes([
            payload[0], payload[1], payload[2], payload[3],
        ]))
    }
    pub fn parse_u64_attr(payload: &[u8]) -> Result<u64> {
        if payload.len() < 8 {
            return Err(Error::Truncated {
                expected: 8,
                actual: payload.len(),
            });
        }
        let mut a = [0u8; 8];
        a.copy_from_slice(&payload[..8]);
        Ok(u64::from_ne_bytes(a))
    }
    pub fn parse_str_attr(payload: &[u8]) -> Result<String> {
        // Kernel strings are NUL-terminated; strip and decode
        // lossily so non-UTF8 doesn't poison the whole parse.
        let trimmed = payload
            .iter()
            .position(|&b| b == 0)
            .map(|n| &payload[..n])
            .unwrap_or(payload);
        Ok(String::from_utf8_lossy(trimmed).into_owned())
    }
    pub fn parse_bytes_attr(payload: &[u8]) -> Result<Vec<u8>> {
        Ok(payload.to_vec())
    }

    // Big-endian parse variants.
    pub fn parse_u16_be_attr(payload: &[u8]) -> Result<u16> {
        if payload.len() < 2 {
            return Err(Error::Truncated {
                expected: 2,
                actual: payload.len(),
            });
        }
        Ok(u16::from_be_bytes([payload[0], payload[1]]))
    }
    pub fn parse_u32_be_attr(payload: &[u8]) -> Result<u32> {
        if payload.len() < 4 {
            return Err(Error::Truncated {
                expected: 4,
                actual: payload.len(),
            });
        }
        Ok(u32::from_be_bytes([
            payload[0], payload[1], payload[2], payload[3],
        ]))
    }
    pub fn parse_u64_be_attr(payload: &[u8]) -> Result<u64> {
        if payload.len() < 8 {
            return Err(Error::Truncated {
                expected: 8,
                actual: payload.len(),
            });
        }
        let mut a = [0u8; 8];
        a.copy_from_slice(&payload[..8]);
        Ok(u64::from_be_bytes(a))
    }

    /// Walk the attribute payload bytes via the existing
    /// [`AttrIter`][crate::netlink::attr::AttrIter]. Re-exported
    /// here so derived code doesn't have to know the full path.
    pub fn attr_iter(payload: &[u8]) -> AttrIter<'_> {
        AttrIter::new(payload)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Error;

    /// Hand-rolled GenlMessage impl exercising the trait shape +
    /// the runtime helpers. Stand-in for what the derive will
    /// generate in Phase 3b.
    #[derive(Debug, Clone, PartialEq, Eq)]
    struct TinyMsg {
        id: u32,
        label: String,
    }

    const ATTR_ID: u16 = 1;
    const ATTR_LABEL: u16 = 2;

    impl GenlMessage for TinyMsg {
        const CMD: u8 = 7;

        fn to_bytes(&self, builder: &mut MessageBuilder) -> Result<()> {
            __rt::emit_u32_attr(builder, ATTR_ID, self.id);
            __rt::emit_str_attr(builder, ATTR_LABEL, &self.label);
            Ok(())
        }

        fn from_bytes(payload: &[u8]) -> Result<Self> {
            let mut id: u32 = 0;
            let mut label = String::new();
            for (ty, p) in __rt::attr_iter(payload) {
                match ty {
                    ATTR_ID => id = __rt::parse_u32_attr(p)?,
                    ATTR_LABEL => label = __rt::parse_str_attr(p)?,
                    _ => {}
                }
            }
            Ok(TinyMsg { id, label })
        }
    }

    #[test]
    fn hand_rolled_message_round_trips_via_runtime_helpers() {
        let original = TinyMsg {
            id: 0xDEADBEEF,
            label: "hello".to_string(),
        };

        let mut builder = MessageBuilder::new(0, 0);
        let body_start = builder.len();
        original.to_bytes(&mut builder).expect("emit");
        let bytes = builder.as_bytes();

        let parsed = TinyMsg::from_bytes(&bytes[body_start..]).expect("parse");
        assert_eq!(parsed, original);
    }

    #[test]
    fn parse_helpers_reject_truncated_payloads() {
        let short_u32: &[u8] = &[0, 1, 2];
        let err = __rt::parse_u32_attr(short_u32).unwrap_err();
        assert!(matches!(err, Error::Truncated { expected: 4, actual: 3 }));

        let short_u64: &[u8] = &[0, 0, 0, 0];
        let err = __rt::parse_u64_attr(short_u64).unwrap_err();
        assert!(matches!(err, Error::Truncated { expected: 8, actual: 4 }));

        let empty: &[u8] = &[];
        let err = __rt::parse_u8_attr(empty).unwrap_err();
        assert!(matches!(err, Error::Truncated { expected: 1, actual: 0 }));
    }

    #[test]
    fn parse_str_handles_nul_termination_and_invalid_utf8() {
        let s = __rt::parse_str_attr(b"hello\0").unwrap();
        assert_eq!(s, "hello");

        let s = __rt::parse_str_attr(b"abc").unwrap();
        assert_eq!(s, "abc");

        let s = __rt::parse_str_attr(b"\xFF\xFE\0").unwrap();
        assert!(!s.is_empty());
    }

    #[test]
    fn big_endian_helpers_round_trip_against_native_endian_layout() {
        let mut b = MessageBuilder::new(0, 0);
        let start = b.len();
        __rt::emit_u32_be_attr(&mut b, 99, 0x1234_5678);
        let bytes = &b.as_bytes()[start..];

        let mut found = None;
        for (ty, payload) in __rt::attr_iter(bytes) {
            if ty == 99 {
                found = Some(__rt::parse_u32_be_attr(payload).unwrap());
            }
        }
        assert_eq!(found, Some(0x1234_5678));
    }
}
