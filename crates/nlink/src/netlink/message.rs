//! Netlink message header and parsing.

use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

use super::{
    attr::AttrIter,
    error::{Error, Result},
};

/// Netlink message header alignment.
pub const NLMSG_ALIGNTO: usize = 4;

/// Align a length to NLMSG_ALIGNTO boundary.
///
/// Plan 232 B18 — `len + 3` debug-panicked on `usize::MAX`-ish
/// inputs. The kernel can't emit a >`u32::MAX` netlink frame so
/// the panic is unreachable in production, but a misbehaving
/// builder appending to a 2 GiB+ `Vec` could trip it. Switched to
/// `saturating_add` so overflow returns `usize::MAX` (which then
/// trips downstream `<= data.len()` guards naturally) instead
/// of debug-panicking.
#[inline]
pub const fn nlmsg_align(len: usize) -> usize {
    let bumped = len.saturating_add(NLMSG_ALIGNTO - 1);
    bumped & !(NLMSG_ALIGNTO - 1)
}

/// Checked variant of [`nlmsg_align`]. Returns `None` if the
/// alignment would overflow.
///
/// Plan 232 B18 — additive helper for callers that want to
/// surface the overflow as an error rather than relying on the
/// saturating fallback.
#[inline]
pub const fn nlmsg_align_checked(len: usize) -> Option<usize> {
    match len.checked_add(NLMSG_ALIGNTO - 1) {
        Some(bumped) => Some(bumped & !(NLMSG_ALIGNTO - 1)),
        None => None,
    }
}

/// Size of the netlink message header.
pub const NLMSG_HDRLEN: usize = nlmsg_align(std::mem::size_of::<NlMsgHdr>());

/// Netlink message header (mirrors struct nlmsghdr).
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct NlMsgHdr {
    /// Length of message including header.
    pub nlmsg_len: u32,
    /// Message type.
    pub nlmsg_type: u16,
    /// Additional flags.
    pub nlmsg_flags: u16,
    /// Sequence number.
    pub nlmsg_seq: u32,
    /// Sending process port ID.
    pub nlmsg_pid: u32,
}

impl NlMsgHdr {
    /// Create a new message header.
    pub fn new(msg_type: u16, flags: u16) -> Self {
        Self {
            nlmsg_len: NLMSG_HDRLEN as u32,
            nlmsg_type: msg_type,
            nlmsg_flags: flags,
            nlmsg_seq: 0,
            nlmsg_pid: 0,
        }
    }

    /// Get the payload length (total length minus header).
    pub fn payload_len(&self) -> usize {
        self.nlmsg_len as usize - NLMSG_HDRLEN
    }

    /// Check if this is an error message.
    pub fn is_error(&self) -> bool {
        self.nlmsg_type == NlMsgType::ERROR
    }

    /// Check if this is a done message.
    pub fn is_done(&self) -> bool {
        self.nlmsg_type == NlMsgType::DONE
    }

    /// Check if this message has the multi flag.
    pub fn is_multi(&self) -> bool {
        self.nlmsg_flags & NLM_F_MULTI != 0
    }

    /// Check if the kernel signaled that the dump was interrupted —
    /// the snapshot iterator's underlying data structure was mutated
    /// between dump frames, so the returned data is inconsistent.
    ///
    /// The kernel sets `NLM_F_DUMP_INTR` on whichever message in the
    /// dump stream was generated after the mutation; `iproute2` warns,
    /// `vishvananda/netlink` retries up to N times, Cilium's
    /// `safenetlink` wrapper retries up to 30. nlink surfaces this as
    /// [`Error::DumpInterrupted`] from `Connection::send_dump` so
    /// callers can choose their own retry policy via the
    /// [`Error::is_dump_interrupted`] predicate.
    ///
    /// Reference: [kernel netlink intro docs][1], `vishvananda #1163`,
    /// `pyroute2 #874`. Tracks the bug class Cilium issue #40280
    /// classified as "the dump never told us its data is stale."
    ///
    /// [1]: https://docs.kernel.org/userspace-api/netlink/intro.html
    pub fn is_dump_interrupted(&self) -> bool {
        self.nlmsg_flags & NLM_F_DUMP_INTR != 0
    }

    /// Convert header to bytes.
    pub fn as_bytes(&self) -> &[u8] {
        <Self as IntoBytes>::as_bytes(self)
    }

    /// Parse header from bytes.
    pub fn from_bytes(data: &[u8]) -> Result<&Self> {
        Self::ref_from_prefix(data)
            .map(|(r, _)| r)
            .map_err(|_| Error::Truncated {
                expected: std::mem::size_of::<Self>(),
                actual: data.len(),
            })
    }
}

/// Standard netlink message types.
pub struct NlMsgType;

impl NlMsgType {
    /// No operation, message must be discarded.
    pub const NOOP: u16 = 1;
    /// Error message or ACK.
    pub const ERROR: u16 = 2;
    /// End of multipart message.
    pub const DONE: u16 = 3;
    /// Data lost, request resend.
    pub const OVERRUN: u16 = 4;

    /// RTNetlink base (for link/addr/route/etc).
    pub const RTM_BASE: u16 = 16;

    // Link messages
    pub const RTM_NEWLINK: u16 = 16;
    pub const RTM_DELLINK: u16 = 17;
    pub const RTM_GETLINK: u16 = 18;
    pub const RTM_SETLINK: u16 = 19;

    // Address messages
    pub const RTM_NEWADDR: u16 = 20;
    pub const RTM_DELADDR: u16 = 21;
    pub const RTM_GETADDR: u16 = 22;

    // Route messages
    pub const RTM_NEWROUTE: u16 = 24;
    pub const RTM_DELROUTE: u16 = 25;
    pub const RTM_GETROUTE: u16 = 26;

    // Neighbor messages
    pub const RTM_NEWNEIGH: u16 = 28;
    pub const RTM_DELNEIGH: u16 = 29;
    pub const RTM_GETNEIGH: u16 = 30;

    // Rule messages
    pub const RTM_NEWRULE: u16 = 32;
    pub const RTM_DELRULE: u16 = 33;
    pub const RTM_GETRULE: u16 = 34;

    // Qdisc messages
    pub const RTM_NEWQDISC: u16 = 36;
    pub const RTM_DELQDISC: u16 = 37;
    pub const RTM_GETQDISC: u16 = 38;

    // Traffic class messages
    pub const RTM_NEWTCLASS: u16 = 40;
    pub const RTM_DELTCLASS: u16 = 41;
    pub const RTM_GETTCLASS: u16 = 42;

    // Traffic filter messages
    pub const RTM_NEWTFILTER: u16 = 44;
    pub const RTM_DELTFILTER: u16 = 45;
    pub const RTM_GETTFILTER: u16 = 46;

    // Traffic action messages
    pub const RTM_NEWACTION: u16 = 48;
    pub const RTM_DELACTION: u16 = 49;
    pub const RTM_GETACTION: u16 = 50;

    // Netns messages
    pub const RTM_NEWNSID: u16 = 88;
    pub const RTM_DELNSID: u16 = 89;
    pub const RTM_GETNSID: u16 = 90;

    // Chain messages (Linux 4.1+)
    pub const RTM_NEWCHAIN: u16 = 100;
    pub const RTM_DELCHAIN: u16 = 101;
    pub const RTM_GETCHAIN: u16 = 102;

    // Nexthop messages (Linux 5.3+)
    pub const RTM_NEWNEXTHOP: u16 = 104;
    pub const RTM_DELNEXTHOP: u16 = 105;
    pub const RTM_GETNEXTHOP: u16 = 106;
}

/// Netlink message flags.
pub const NLM_F_REQUEST: u16 = 0x01;
pub const NLM_F_MULTI: u16 = 0x02;
pub const NLM_F_ACK: u16 = 0x04;
pub const NLM_F_ECHO: u16 = 0x08;
pub const NLM_F_DUMP_INTR: u16 = 0x10;
pub const NLM_F_DUMP_FILTERED: u16 = 0x20;

// Modifiers to GET request
pub const NLM_F_ROOT: u16 = 0x100;
pub const NLM_F_MATCH: u16 = 0x200;
pub const NLM_F_ATOMIC: u16 = 0x400;
pub const NLM_F_DUMP: u16 = NLM_F_ROOT | NLM_F_MATCH;

// Modifiers to NEW request
pub const NLM_F_REPLACE: u16 = 0x100;
pub const NLM_F_EXCL: u16 = 0x200;
pub const NLM_F_CREATE: u16 = 0x400;
pub const NLM_F_APPEND: u16 = 0x800;

/// Iterator over netlink messages in a buffer.
pub struct MessageIter<'a> {
    data: &'a [u8],
}

impl<'a> MessageIter<'a> {
    /// Create a new message iterator.
    pub fn new(data: &'a [u8]) -> Self {
        Self { data }
    }
}

impl<'a> Iterator for MessageIter<'a> {
    type Item = Result<(&'a NlMsgHdr, &'a [u8])>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.data.len() < NLMSG_HDRLEN {
            return None;
        }

        let header = match NlMsgHdr::from_bytes(self.data) {
            Ok(h) => h,
            Err(e) => {
                // Plan 193 §2.3 / rule 2 — exhaust the iterator
                // on parse error so a subsequent `next()` call
                // returns None instead of looping forever on the
                // same malformed prefix.
                self.data = &[];
                return Some(Err(e));
            }
        };

        let msg_len = header.nlmsg_len as usize;
        if msg_len < NLMSG_HDRLEN || msg_len > self.data.len() {
            // Same exhaustion contract as above — without this
            // sentinel, a truncated frame from the kernel (or
            // any malformed header advertising more bytes than
            // present) would re-emit the Err on every poll,
            // hanging long-lived multicast subscribers (Plan
            // 193 §2.3, CLAUDE.md §"Parser robustness" rule 2).
            self.data = &[];
            return Some(Err(Error::InvalidMessage(format!(
                "invalid message length: {}",
                msg_len
            ))));
        }

        let payload = &self.data[NLMSG_HDRLEN..msg_len];
        let aligned_len = nlmsg_align(msg_len);

        // Move to next message. Edge case: `aligned_len == 0`
        // would mean the header advertises zero bytes (rejected
        // above by the `msg_len < NLMSG_HDRLEN` guard) — so this
        // branch always advances at least NLMSG_HDRLEN bytes.
        if aligned_len >= self.data.len() {
            self.data = &[];
        } else {
            self.data = &self.data[aligned_len..];
        }

        Some(Ok((header, payload)))
    }
}

/// Netlink error message payload.
#[repr(C)]
#[derive(Debug, Clone, Copy, FromBytes, Immutable, KnownLayout)]
pub struct NlMsgError {
    /// Error code (negative errno or 0 for ACK).
    pub error: i32,
    /// Original message header that caused the error.
    pub msg: NlMsgHdr,
}

/// `NLMSGERR_ATTR_*` enum from `include/uapi/linux/netlink.h`. Kernel
/// populates these as nlattr TLVs after the embedded `nlmsghdr` in an
/// error response, when `NETLINK_EXT_ACK` is enabled on the listening
/// socket (on by default in nlink — see `socket.rs`).
pub mod nlmsgerr_attr {
    /// Human-readable error message string (NUL-terminated).
    pub const MSG: u16 = 1;
    /// Offset of the offending attribute inside the original request,
    /// in bytes from the start of the netlink message.
    pub const OFFS: u16 = 2;
    /// Opaque cookie for matching error to request (rarely useful).
    pub const COOKIE: u16 = 3;
    /// Nested policy info (rarely useful at the lib level).
    pub const POLICY: u16 = 4;
    /// Type of a missing required attribute.
    pub const MISS_TYPE: u16 = 5;
    /// Type of a missing required nested attribute.
    pub const MISS_NEST: u16 = 6;
}

/// Parsed extended-ack TLVs from a netlink error response.
///
/// The kernel attaches these after the embedded `nlmsghdr` when
/// `NETLINK_EXT_ACK` is enabled. They turn `errno = 22 (EINVAL)`
/// into actionable diagnostics like
/// `"attribute IFLA_MTU rejected: value 0 out of range"`.
///
/// Most fields are `Option` because not every kernel error path
/// populates them — older kernels and some subsystems still return
/// bare errno. Absence is normal, not error.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ParsedExtAck {
    /// Human-readable kernel error string. `None` if the kernel did
    /// not include `NLMSGERR_ATTR_MSG` or it was empty / malformed.
    pub message: Option<String>,
    /// Byte offset into the original request where the kernel
    /// detected the problem. `None` if the kernel did not include
    /// `NLMSGERR_ATTR_OFFS`.
    pub offset: Option<u32>,
}

impl NlMsgError {
    /// Parse error message from payload.
    pub fn from_bytes(data: &[u8]) -> Result<&Self> {
        Self::ref_from_prefix(data)
            .map(|(r, _)| r)
            .map_err(|_| Error::Truncated {
                expected: std::mem::size_of::<Self>(),
                actual: data.len(),
            })
    }

    /// Check if this is an ACK (no error).
    pub fn is_ack(&self) -> bool {
        self.error == 0
    }

    /// Get attributes after the error message (extended ACK).
    pub fn attrs<'a>(&self, payload: &'a [u8]) -> AttrIter<'a> {
        let offset = std::mem::size_of::<Self>();
        if payload.len() > offset {
            AttrIter::new(&payload[offset..])
        } else {
            AttrIter::new(&[])
        }
    }

    /// Construct an [`Error`] from this error message plus the
    /// extended-ack TLVs in `payload`. Caller is responsible for
    /// checking `!is_ack()` before calling (this method assumes the
    /// response represents a real error, not an ACK).
    ///
    /// Centralizes the "parse ext-ack + build Error" pattern that's
    /// repeated across every protocol's response-handling loop.
    pub fn into_error(&self, payload: &[u8]) -> Error {
        let ext = self.parsed_ext_ack(payload);
        Error::from_errno_ext_ack(self.error, ext.message, ext.offset)
    }

    /// Parse the extended-ack TLVs (`NLMSGERR_ATTR_MSG` +
    /// `NLMSGERR_ATTR_OFFS`) from an error-response payload.
    ///
    /// Returns an all-`None` [`ParsedExtAck`] if no recognized TLVs
    /// are present. Other recognized TLVs (`COOKIE`, `POLICY`,
    /// `MISS_TYPE`, `MISS_NEST`) are deliberately ignored at this
    /// level — they're niche, and surfacing them would inflate the
    /// `Error` variants without a clear user-value story. They can
    /// be re-extracted via [`Self::attrs`] if a caller needs them.
    pub fn parsed_ext_ack(&self, payload: &[u8]) -> ParsedExtAck {
        let mut out = ParsedExtAck::default();
        for (attr_type, attr_payload) in self.attrs(payload) {
            match attr_type {
                nlmsgerr_attr::MSG => {
                    // Kernel strings are typically NUL-terminated;
                    // strip the NUL + tolerate non-UTF8 by lossy
                    // decode (we'd rather show "?" than swallow the
                    // whole message).
                    let trimmed = attr_payload
                        .iter()
                        .position(|&b| b == 0)
                        .map(|n| &attr_payload[..n])
                        .unwrap_or(attr_payload);
                    if !trimmed.is_empty() {
                        out.message = Some(String::from_utf8_lossy(trimmed).into_owned());
                    }
                }
                nlmsgerr_attr::OFFS if attr_payload.len() >= 4 => {
                    // SAFETY of the unwrap: the guard above ensures
                    // ≥ 4 bytes; `try_into` on `&[u8; 4]` is infallible
                    // when the slice is exactly 4 bytes.
                    let bytes: [u8; 4] = attr_payload[..4].try_into().expect("len ≥ 4");
                    out.offset = Some(u32::from_ne_bytes(bytes));
                }
                _ => {} // ignore COOKIE/POLICY/MISS_TYPE/MISS_NEST + unknown
            }
        }
        out
    }
}

#[cfg(test)]
mod nlmsgerr_tests {
    use super::*;
    use crate::netlink::attr::nla_align;

    fn synth_payload_with_ext_ack(error: i32, msg: Option<&str>, offset: Option<u32>) -> Vec<u8> {
        // NlMsgError: error(i32) + NlMsgHdr (fixed 16 bytes)
        let mut buf = Vec::new();
        buf.extend_from_slice(&error.to_ne_bytes());
        // Zero NlMsgHdr — the test doesn't care about the embedded
        // original-request header.
        buf.extend_from_slice(&[0u8; 16]);

        // NLMSGERR_ATTR_MSG TLV
        if let Some(s) = msg {
            let mut payload = s.as_bytes().to_vec();
            payload.push(0); // NUL-terminate
            let attr_len = 4 + payload.len();
            buf.extend_from_slice(&(attr_len as u16).to_ne_bytes());
            buf.extend_from_slice(&nlmsgerr_attr::MSG.to_ne_bytes());
            buf.extend_from_slice(&payload);
            // Pad to 4-byte alignment.
            while buf.len() < nla_align(buf.len()) {
                buf.push(0);
            }
        }

        // NLMSGERR_ATTR_OFFS TLV
        if let Some(off) = offset {
            let attr_len: u16 = 4 + 4;
            buf.extend_from_slice(&attr_len.to_ne_bytes());
            buf.extend_from_slice(&nlmsgerr_attr::OFFS.to_ne_bytes());
            buf.extend_from_slice(&off.to_ne_bytes());
        }

        buf
    }

    #[test]
    fn parses_msg_and_offs() {
        let payload = synth_payload_with_ext_ack(
            -22,
            Some("attribute IFLA_MTU rejected: value 0 out of range"),
            Some(42),
        );
        let err = NlMsgError::from_bytes(&payload).expect("parse");
        assert_eq!(err.error, -22);
        let parsed = err.parsed_ext_ack(&payload);
        assert_eq!(
            parsed.message.as_deref(),
            Some("attribute IFLA_MTU rejected: value 0 out of range")
        );
        assert_eq!(parsed.offset, Some(42));
    }

    #[test]
    fn parses_msg_only_when_offs_missing() {
        let payload = synth_payload_with_ext_ack(-22, Some("policy violation"), None);
        let err = NlMsgError::from_bytes(&payload).expect("parse");
        let parsed = err.parsed_ext_ack(&payload);
        assert_eq!(parsed.message.as_deref(), Some("policy violation"));
        assert_eq!(parsed.offset, None);
    }

    #[test]
    fn empty_payload_yields_all_none() {
        let payload = synth_payload_with_ext_ack(-22, None, None);
        let err = NlMsgError::from_bytes(&payload).expect("parse");
        let parsed = err.parsed_ext_ack(&payload);
        assert_eq!(parsed.message, None);
        assert_eq!(parsed.offset, None);
    }

    #[test]
    fn malformed_utf8_decodes_lossily_rather_than_failing() {
        let mut payload = synth_payload_with_ext_ack(-22, None, None);
        // Inject a NLMSGERR_ATTR_MSG with invalid UTF-8.
        let bad_bytes = b"\xFF\xFE\xFD\x00"; // NUL-terminated invalid utf-8
        let attr_len: u16 = 4 + bad_bytes.len() as u16;
        payload.extend_from_slice(&attr_len.to_ne_bytes());
        payload.extend_from_slice(&nlmsgerr_attr::MSG.to_ne_bytes());
        payload.extend_from_slice(bad_bytes);
        let err = NlMsgError::from_bytes(&payload).expect("parse");
        let parsed = err.parsed_ext_ack(&payload);
        // Lossy decode produces replacement characters; what we
        // actually care about is "we didn't crash / return None".
        assert!(parsed.message.is_some());
    }
}

#[cfg(test)]
mod dump_intr_tests {
    use super::*;

    #[test]
    fn nlmsghdr_reports_dump_interrupted_when_flag_set() {
        let h = NlMsgHdr {
            nlmsg_len: NLMSG_HDRLEN as u32,
            nlmsg_type: NlMsgType::DONE,
            nlmsg_flags: NLM_F_MULTI | NLM_F_DUMP_INTR,
            nlmsg_seq: 42,
            nlmsg_pid: 0,
        };
        assert!(h.is_dump_interrupted());
        assert!(h.is_done());
    }

    #[test]
    fn nlmsghdr_does_not_report_dump_interrupted_for_clean_done() {
        let h = NlMsgHdr {
            nlmsg_len: NLMSG_HDRLEN as u32,
            nlmsg_type: NlMsgType::DONE,
            nlmsg_flags: NLM_F_MULTI,
            nlmsg_seq: 42,
            nlmsg_pid: 0,
        };
        assert!(!h.is_dump_interrupted());
    }

    #[test]
    fn nlmsghdr_reports_dump_interrupted_on_data_frame_too() {
        // The kernel may set NLM_F_DUMP_INTR on any frame in the
        // dump stream, not just NLMSG_DONE. Pin that we detect it
        // on a mid-dump RTM_NEWLINK frame.
        let h = NlMsgHdr {
            nlmsg_len: NLMSG_HDRLEN as u32,
            nlmsg_type: NlMsgType::RTM_NEWLINK,
            nlmsg_flags: NLM_F_MULTI | NLM_F_DUMP_INTR,
            nlmsg_seq: 42,
            nlmsg_pid: 0,
        };
        assert!(h.is_dump_interrupted());
        assert!(!h.is_done());
        assert!(h.is_multi());
    }
}

#[cfg(test)]
mod nlmsg_align_overflow_tests {
    use super::*;

    /// Plan 232 B18 — pre-fix `nlmsg_align(usize::MAX)`
    /// debug-panicked on the `len + 3` overflow. Post-fix it
    /// saturates and `nlmsg_align_checked` returns None.
    #[test]
    fn b18_nlmsg_align_saturates_on_overflow() {
        // Pre-fix this would panic in debug; post-fix it
        // saturates to usize::MAX (which downstream
        // `<= data.len()` checks will reject naturally).
        let aligned = nlmsg_align(usize::MAX);
        // The exact value is `usize::MAX & !3`; verify no
        // panic and the value is at least `usize::MAX - 3`.
        assert!(aligned >= usize::MAX - 3);
    }

    #[test]
    fn b18_nlmsg_align_checked_returns_none_on_overflow() {
        assert_eq!(nlmsg_align_checked(usize::MAX), None);
        assert_eq!(nlmsg_align_checked(usize::MAX - 2), None);
        // A "valid" small length still aligns correctly.
        assert_eq!(nlmsg_align_checked(0), Some(0));
        assert_eq!(nlmsg_align_checked(1), Some(4));
        assert_eq!(nlmsg_align_checked(5), Some(8));
        assert_eq!(nlmsg_align_checked(8), Some(8));
    }
}
