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
//! | 3b | `#[derive(GenlMessage)]` (NetlinkAttrs deferred) | ✓ |
//! | 4 | `#[genl_family(...)]` attribute macro | ✓ |
//! | 5 | `Connection::<F>::send_typed<M, R>` + `dump_typed_stream` | ✓ |
//! | 6 | Worked example + recipe | ✓ |
//! | 7 | Final re-export polish + CHANGELOG framing | ✓ |
//! | 8 | Extended field types (`GenlEnum` / `Vec<T: GenlEnum>` / bitflags / `i32` / `NetlinkAttrs`) — unblocks Plan 156/153.3/152 | — |

pub use nlink_macros::{genl_family, GenlAttribute, GenlCommand, GenlEnum, GenlMessage};

mod genl_dispatch;

pub use genl_dispatch::GenlTypedDumpStream;

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

/// Connection-facing trait for a Generic Netlink family marker.
///
/// Implemented automatically by [`macro@genl_family`]. Carries
/// the runtime-resolved kernel family ID + the compile-time
/// version constant the GENL header needs on every outbound
/// message. This is what
/// [`Connection::<F>::send_typed`](crate::netlink::Connection) +
/// [`dump_typed_stream`](crate::netlink::Connection)
/// (Plan 154 Phase 5) bound their generic dispatch on.
///
/// # Hand-implementation
///
/// Hand-implementing this trait is supported for the rare case
/// where the macro doesn't fit (e.g. a family marker that needs
/// extra fields beyond `family_id`). Match the shape:
///
/// ```ignore
/// pub struct MyFamily { family_id: u16, extra: SomeCache }
/// impl GenlFamily for MyFamily {
///     const VERSION: u8 = 1;
///     const NAME: &'static str = "my_family";
///     fn family_id(&self) -> u16 { self.family_id }
/// }
/// ```
///
/// Family ID resolution still goes through
/// [`AsyncProtocolInit`](crate::netlink::AsyncProtocolInit); the
/// `GenlFamily` trait is the *send-time* contract, not the
/// construction-time one.
pub trait GenlFamily {
    /// Family version (the GENL header's `version` field).
    /// Compile-time constant per Generic Netlink convention.
    const VERSION: u8;

    /// Family name (the kernel-side string registered via
    /// `CTRL_CMD_NEWFAMILY`). Compile-time constant; mirrors
    /// the `NAME` const that `#[genl_family]` already emits as an
    /// inherent associated constant on the marker struct.
    const NAME: &'static str;

    /// Kernel-assigned family ID, resolved at connection
    /// construction time and stored on the marker.
    fn family_id(&self) -> u16;
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

    // ============================================================
    // GENL family resolution helper (Plan 154 Phase 4)
    // ============================================================
    //
    // `#[genl_family(name = "...", version = N)]` emits an
    // AsyncProtocolInit impl whose body calls
    // `resolve_genl_family(socket, "...")` to look up the
    // kernel-assigned family ID at connection construction.
    //
    // Body matches the per-family `resolve_wireguard_family` /
    // `resolve_macsec_family` / etc. helpers in each in-tree
    // family's connection.rs — just parametrized on name. A
    // future cleanup pass can rewire those copies to call this
    // resolver and eliminate the duplication.

    use crate::netlink::{
        genl::{CtrlAttr, CtrlCmd, GenlMsgHdr, GENL_HDRLEN, GENL_ID_CTRL},
        message::{MessageIter, NlMsgError, NLM_F_ACK, NLM_F_REQUEST},
        NetlinkSocket,
    };

    /// Resolve the kernel-assigned family ID for a Generic
    /// Netlink family by name.
    ///
    /// Emits `CTRL_CMD_GETFAMILY` with the family name and parses
    /// the response's `CTRL_ATTR_FAMILY_ID`. Returns
    /// `Error::FamilyNotFound` if the kernel reports the family
    /// doesn't exist (typically: required kernel module isn't
    /// loaded, or kernel is too old for the feature).
    ///
    /// Emitted by `#[genl_family]`-expanded `AsyncProtocolInit::resolve_async`
    /// impls. Downstream code shouldn't call this directly — let
    /// the macro handle it.
    pub async fn resolve_genl_family(
        socket: &NetlinkSocket,
        name: &str,
    ) -> Result<u16> {
        let mut builder = MessageBuilder::new(GENL_ID_CTRL, NLM_F_REQUEST | NLM_F_ACK);
        let genl_hdr = GenlMsgHdr::new(CtrlCmd::GetFamily as u8, 1);
        builder.append(&genl_hdr);
        builder.append_attr_str(CtrlAttr::FamilyName as u16, name);

        let seq = socket.next_seq();
        builder.set_seq(seq);
        builder.set_pid(socket.pid());

        let msg = builder.finish();
        socket.send(&msg).await?;

        let response: Vec<u8> = socket.recv_msg().await?;

        for result in MessageIter::new(&response) {
            let (header, payload) = result?;

            if header.nlmsg_seq != seq {
                continue;
            }

            if header.is_error() {
                let err = NlMsgError::from_bytes(payload)?;
                if !err.is_ack() {
                    if err.error == -libc::ENOENT {
                        return Err(Error::FamilyNotFound {
                            name: name.to_string(),
                        });
                    }
                    return Err(err.into_error(payload));
                }
                continue;
            }

            if header.is_done() {
                continue;
            }

            if payload.len() < GENL_HDRLEN {
                return Err(Error::InvalidMessage(
                    "GENL header too short in CTRL_CMD_GETFAMILY response".into(),
                ));
            }

            let attrs_data = &payload[GENL_HDRLEN..];
            for (attr_type, attr_payload) in AttrIter::new(attrs_data) {
                if attr_type == CtrlAttr::FamilyId as u16 {
                    return parse_u16_attr(attr_payload);
                }
            }
        }

        Err(Error::FamilyNotFound {
            name: name.to_string(),
        })
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

    // -- Phase 3b derive tests ---------------------------------
    //
    // The crate-root re-export `nlink_macros::GenlMessage` lives
    // in the macro namespace; the trait `GenlMessage` lives in
    // the type namespace. Both share the name without colliding.
    //
    // These tests use the derive (`#[derive(GenlMessage)]`)
    // against the trait + runtime helpers defined in this same
    // module — the proof that the macro expansion's
    // `::nlink::macros::__rt::*` path resolves correctly.

    use crate::macros::GenlMessage as GenlMessageDerive;
    // ^ Cargo doc-test's macro/trait dual-namespace works fine
    //   in normal test compilation; this alias is only here to
    //   make the derive macro's identity unambiguous if a future
    //   rustc warning forces one or the other.

    #[derive(GenlMessageDerive, Debug, Clone, PartialEq, Eq)]
    #[genl_message(cmd = 7u8)]
    struct DerivedSimple {
        #[genl_attr(1u16)]
        id: u32,
        #[genl_attr(2u16)]
        label: String,
    }

    #[test]
    fn derived_simple_round_trips() {
        let original = DerivedSimple {
            id: 0xCAFEBABE,
            label: "world".to_string(),
        };
        assert_eq!(DerivedSimple::CMD, 7);

        let mut builder = MessageBuilder::new(0, 0);
        let body_start = builder.len();
        original.to_bytes(&mut builder).expect("emit");
        let bytes = builder.as_bytes();

        let parsed = DerivedSimple::from_bytes(&bytes[body_start..]).expect("parse");
        assert_eq!(parsed, original);
    }

    #[derive(GenlMessageDerive, Debug, Clone, PartialEq, Eq)]
    #[genl_message(cmd = 9u8)]
    struct DerivedOptional {
        #[genl_attr(1u16)]
        id: u32,
        #[genl_attr(2u16)]
        description: Option<String>,
        #[genl_attr(3u16)]
        priority: Option<u16>,
    }

    #[test]
    fn derived_optional_omits_none_on_emit() {
        let with_none = DerivedOptional {
            id: 1,
            description: None,
            priority: None,
        };
        let mut builder = MessageBuilder::new(0, 0);
        let body_start = builder.len();
        with_none.to_bytes(&mut builder).expect("emit");
        let bytes = &builder.as_bytes()[body_start..];

        // Only the id attribute should be present.
        let mut attrs_seen: Vec<u16> = Vec::new();
        for (ty, _) in __rt::attr_iter(bytes) {
            attrs_seen.push(ty);
        }
        assert_eq!(attrs_seen, vec![1u16]);

        let parsed = DerivedOptional::from_bytes(bytes).expect("parse");
        assert_eq!(parsed, with_none);
    }

    #[test]
    fn derived_optional_round_trips_some() {
        let original = DerivedOptional {
            id: 42,
            description: Some("hello".to_string()),
            priority: Some(99),
        };
        let mut builder = MessageBuilder::new(0, 0);
        let body_start = builder.len();
        original.to_bytes(&mut builder).expect("emit");
        let parsed = DerivedOptional::from_bytes(&builder.as_bytes()[body_start..])
            .expect("parse");
        assert_eq!(parsed, original);
    }

    // Verify the derive interoperates with the typed-enum
    // codec derives — the realistic shape downstream code uses.

    use crate::macros::{GenlAttribute, GenlCommand};

    #[derive(GenlCommand, Debug, Clone, Copy, PartialEq, Eq)]
    #[genl_command(repr = "u8")]
    enum TestCmd {
        Unspec = 0,
        Get = 2,
    }

    #[derive(GenlAttribute, Debug, Clone, Copy, PartialEq, Eq)]
    #[genl_attribute(repr = "u16")]
    enum TestAttr {
        Id = 1,
        Name = 2,
    }

    #[derive(GenlMessageDerive, Debug, Clone, PartialEq, Eq)]
    #[genl_message(cmd = TestCmd::Get)]
    struct TypedGetReq {
        #[genl_attr(TestAttr::Id)]
        id: u32,
        #[genl_attr(TestAttr::Name)]
        name: String,
    }

    #[test]
    fn typed_enums_compose_with_message_derive() {
        // CMD comes from TestCmd::Get (= 2) via `as u8`.
        assert_eq!(TypedGetReq::CMD, 2);

        let original = TypedGetReq {
            id: 7,
            name: "device-0".to_string(),
        };
        let mut builder = MessageBuilder::new(0, 0);
        let body_start = builder.len();
        original.to_bytes(&mut builder).expect("emit");
        let parsed = TypedGetReq::from_bytes(&builder.as_bytes()[body_start..])
            .expect("parse");
        assert_eq!(parsed, original);
    }

    #[derive(GenlMessageDerive, Debug, Clone, PartialEq, Eq)]
    #[genl_message(cmd = 5u8)]
    struct DerivedBytes {
        #[genl_attr(1u16)]
        payload: Vec<u8>,
    }

    #[test]
    fn derived_vec_u8_round_trips() {
        let original = DerivedBytes {
            payload: vec![0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01, 0x02],
        };
        let mut builder = MessageBuilder::new(0, 0);
        let body_start = builder.len();
        original.to_bytes(&mut builder).expect("emit");
        let parsed = DerivedBytes::from_bytes(&builder.as_bytes()[body_start..])
            .expect("parse");
        assert_eq!(parsed, original);
    }

    #[test]
    fn derived_from_bytes_fills_defaults_for_missing_attrs() {
        // Empty payload — every field comes back as its default.
        let parsed = DerivedSimple::from_bytes(&[]).expect("parse");
        assert_eq!(parsed.id, 0);
        assert_eq!(parsed.label, "");
    }

    #[test]
    fn derived_from_bytes_skips_unknown_attrs() {
        // Emit a known attr (id=1) + an unknown attr (id=99).
        let mut builder = MessageBuilder::new(0, 0);
        let body_start = builder.len();
        __rt::emit_u32_attr(&mut builder, 1, 42);
        __rt::emit_u32_attr(&mut builder, 99, 0xDEAD_BEEF);
        let parsed =
            DerivedSimple::from_bytes(&builder.as_bytes()[body_start..]).expect("parse");
        // Only id is consumed; label stays default.
        assert_eq!(parsed.id, 42);
        assert_eq!(parsed.label, "");
    }

    // -- Phase 4: #[genl_family] attribute macro ---------------

    use crate::macros::genl_family;
    use crate::netlink::construction::AsyncConstructible;
    use crate::netlink::{AsyncProtocolInit, Protocol, ProtocolState};

    #[genl_family(name = "my_family", version = 1)]
    pub struct MyFamily;

    #[test]
    fn genl_family_macro_generates_constants() {
        assert_eq!(MyFamily::NAME, "my_family");
        assert_eq!(MyFamily::VERSION, 1);
    }

    #[test]
    fn genl_family_macro_default_constructs_with_zero_family_id() {
        let f = MyFamily::default();
        assert_eq!(f.family_id(), 0);
    }

    #[test]
    fn genl_family_macro_implements_protocol_state() {
        // Compile-time check: PROTOCOL is the Generic variant.
        const _: () = {
            assert!(matches!(MyFamily::PROTOCOL, Protocol::Generic));
        };
    }

    /// Helper that's only valid for types implementing
    /// AsyncConstructible — proves the macro adds the right
    /// sealed-trait impl. If `MyFamily` didn't get the impl,
    /// this generic function would fail to compile.
    fn assert_async_constructible<P: AsyncConstructible>() {}

    /// Same for the AsyncProtocolInit trait (the kernel-resolved
    /// family-ID setup that runs at Connection::new_async time).
    fn assert_async_protocol_init<P: AsyncProtocolInit>() {}

    #[test]
    fn genl_family_macro_satisfies_trait_bounds_required_by_connection() {
        // These calls only compile if MyFamily impls both
        // traits. They're the substantive contract of the macro:
        // any family defined via #[genl_family] plugs into
        // Connection::<F>::new_async() the same way the in-tree
        // hand-written families do.
        assert_async_constructible::<MyFamily>();
        assert_async_protocol_init::<MyFamily>();
    }

    #[test]
    fn genl_family_macro_provides_debug() {
        let f = MyFamily::default();
        let s = format!("{f:?}");
        assert!(s.contains("MyFamily"));
        assert!(s.contains("my_family"));
        assert!(s.contains("version"));
        assert!(s.contains("family_id"));
    }

    // Second family declaration to verify the macro is reusable
    // (a hand-written family + a macro-defined one can coexist).
    #[genl_family(name = "second_family", version = 2)]
    pub struct SecondFamily;

    #[test]
    fn two_macro_defined_families_coexist() {
        assert_eq!(SecondFamily::NAME, "second_family");
        assert_eq!(SecondFamily::VERSION, 2);
        assert_async_constructible::<SecondFamily>();
    }
}
