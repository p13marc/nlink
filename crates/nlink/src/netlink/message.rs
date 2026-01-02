//! Netlink message header and parsing.

use super::attr::AttrIter;
use super::error::{Error, Result};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

/// Netlink message header alignment.
pub const NLMSG_ALIGNTO: usize = 4;

/// Align a length to NLMSG_ALIGNTO boundary.
#[inline]
pub const fn nlmsg_align(len: usize) -> usize {
    (len + NLMSG_ALIGNTO - 1) & !(NLMSG_ALIGNTO - 1)
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
            Err(e) => return Some(Err(e)),
        };

        let msg_len = header.nlmsg_len as usize;
        if msg_len < NLMSG_HDRLEN || msg_len > self.data.len() {
            return Some(Err(Error::InvalidMessage(format!(
                "invalid message length: {}",
                msg_len
            ))));
        }

        let payload = &self.data[NLMSG_HDRLEN..msg_len];
        let aligned_len = nlmsg_align(msg_len);

        // Move to next message
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
}
