//! Property-based parser-robustness harnesses (Plan 193 phase 2-3,
//! #137).
//!
//! These feed **arbitrary bytes** to the protocol-stack parsers and
//! assert the invariants from CLAUDE.md `## Parser robustness` hold —
//! no panics, bounded termination (no infinite loop), and the Plan 193
//! rule-2 exhaustion contract. They complement the hand-written
//! adversarial unit tests: a property test explores the input space the
//! audit scripts and example-driven tests can't enumerate.
//!
//! Dev-only (`proptest` is a dev-dependency); runs under
//! `cargo test -p nlink --lib`, no root required.
//!
//! Invariants pinned here:
//! 1. `MessageIter` / `AttrIter` never panic on any byte slice.
//! 2. They always terminate, yielding at most one item per minimum
//!    header's worth of input (catches the infinite-loop bug class —
//!    netlink-packet-route #152, the real 0.19 MessageIter bug).
//! 3. Rule 2: once `MessageIter` yields an `Err`, it is exhausted (the
//!    next `next()` returns `None`) so a malformed frame can't re-emit
//!    forever and stall a long-lived subscriber.
//! 4. The fixed-size struct parsers and the `get::*` typed extractors
//!    return `Result`/`Option` on arbitrary bytes — never panic
//!    (no out-of-bounds slice, no unwrap).

use proptest::prelude::*;

use super::{
    attr::{AttrIter, NlAttr, get},
    message::{MessageIter, NLMSG_HDRLEN, NlMsgHdr},
    messages::{
        AddressMessage, LinkMessage, NeighborMessage, RouteMessage, RuleMessage, TcMessage,
    },
    parse::FromNetlink,
};

/// Upper bound on items a correct iterator can yield for `len` bytes:
/// every yielded item consumes at least one aligned minimum-header
/// (>= 4 bytes) or exhausts the iterator, so `len + 2` is a generous
/// cap that a correct impl always finishes strictly under. If the
/// iterator looped forever, `.take(cap)` would still terminate the test
/// at exactly `cap`, and the assertion `count < cap` would fail.
fn loop_cap(len: usize) -> usize {
    len + 2
}

proptest! {
    /// `MessageIter` never panics and always terminates on arbitrary
    /// bytes (invariants 1 + 2).
    #[test]
    fn message_iter_terminates_without_panic(data in proptest::collection::vec(any::<u8>(), 0..1024)) {
        let cap = loop_cap(data.len());
        let count = MessageIter::new(&data).take(cap).count();
        prop_assert!(count < cap, "MessageIter did not terminate within bound (possible infinite loop)");
    }

    /// Plan 193 rule 2: once `MessageIter` yields an `Err`, it must be
    /// exhausted — the next poll returns `None` (invariant 3).
    #[test]
    fn message_iter_exhausts_after_error(data in proptest::collection::vec(any::<u8>(), 0..1024)) {
        let cap = loop_cap(data.len());
        let mut it = MessageIter::new(&data);
        let mut polled = 0;
        let mut saw_err = false;
        // `while let` (not `for`) on purpose: we keep `it` by-ref to poll
        // it again *after* the loop and assert it stays exhausted.
        #[allow(clippy::while_let_on_iterator)]
        while let Some(item) = it.next() {
            polled += 1;
            prop_assert!(polled <= cap, "iterator exceeded the termination bound");
            if item.is_err() {
                saw_err = true;
                break;
            }
        }
        if saw_err {
            prop_assert!(
                it.next().is_none(),
                "MessageIter must be exhausted after yielding an error (Plan 193 rule 2)"
            );
        }
    }

    /// `AttrIter` never panics and always terminates on arbitrary bytes.
    #[test]
    fn attr_iter_terminates_without_panic(data in proptest::collection::vec(any::<u8>(), 0..1024)) {
        let cap = loop_cap(data.len());
        let count = AttrIter::new(&data).take(cap).count();
        prop_assert!(count < cap, "AttrIter did not terminate within bound (possible infinite loop)");
    }

    /// Walk arbitrary bytes as a full netlink message stream, then walk
    /// each message payload as an attribute chain, then run every typed
    /// extractor over each attribute payload. The whole nested walk must
    /// complete without panicking (invariants 1 + 4 combined — the real
    /// kernel-response parse path).
    #[test]
    fn nested_message_attr_walk_never_panics(data in proptest::collection::vec(any::<u8>(), 0..2048)) {
        let mut messages = 0;
        for item in MessageIter::new(&data).take(loop_cap(data.len())) {
            messages += 1;
            prop_assert!(messages <= loop_cap(data.len()));
            let Ok((_hdr, payload)) = item else { break };
            let mut attrs = 0;
            for (_kind, attr_payload) in AttrIter::new(payload).take(loop_cap(payload.len())) {
                attrs += 1;
                prop_assert!(attrs <= loop_cap(payload.len()));
                // Every typed extractor must tolerate arbitrary payloads.
                let _ = get::u8(attr_payload);
                let _ = get::u16_ne(attr_payload);
                let _ = get::u32_ne(attr_payload);
                let _ = get::u64_ne(attr_payload);
                let _ = get::i32_ne(attr_payload);
                let _ = get::string(attr_payload);
                let _ = get::bytes(attr_payload);
            }
        }
    }

    /// The fixed-size struct parsers return `Result` on any input —
    /// never panic, never slice out of bounds (invariant 4).
    #[test]
    fn struct_from_bytes_never_panics(data in proptest::collection::vec(any::<u8>(), 0..128)) {
        let _ = NlMsgHdr::from_bytes(&data);
        let _ = NlAttr::from_bytes(&data);
    }

    /// Plan 193 rule 1 (accept-larger-than-expected): a byte slice at
    /// least header-sized parses; trailing bytes are ignored, never
    /// rejected. `NlMsgHdr::from_bytes` reads the fixed prefix.
    #[test]
    fn nlmsghdr_accepts_oversized_input(extra in proptest::collection::vec(any::<u8>(), 0..64)) {
        let mut buf = vec![0u8; NLMSG_HDRLEN];
        // A well-formed minimal header: nlmsg_len = NLMSG_HDRLEN.
        buf[0..4].copy_from_slice(&(NLMSG_HDRLEN as u32).to_ne_bytes());
        buf.extend_from_slice(&extra);
        prop_assert!(
            NlMsgHdr::from_bytes(&buf).is_ok(),
            "header-sized-or-larger input must parse (Plan 193 rule 1: accept trailing bytes)"
        );
    }

    /// The typed RTNetlink message parsers (`FromNetlink::from_bytes`) —
    /// the real kernel-response attack surface — must return `Result` on
    /// arbitrary bytes, never panic. Each walks a fixed-size struct
    /// prefix plus an attribute chain, so this exercises rules 1 + 2 at
    /// the typed layer over the same input.
    #[test]
    fn typed_message_parsers_never_panic(data in proptest::collection::vec(any::<u8>(), 0..1024)) {
        let _ = LinkMessage::from_bytes(&data);
        let _ = RouteMessage::from_bytes(&data);
        let _ = AddressMessage::from_bytes(&data);
        let _ = NeighborMessage::from_bytes(&data);
        let _ = RuleMessage::from_bytes(&data);
        let _ = TcMessage::from_bytes(&data);
    }
}
