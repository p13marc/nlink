//! Message builder for constructing netlink messages.

use super::attr::{NLA_F_NESTED, NlAttr, nla_align};
use super::message::{NLMSG_HDRLEN, NlMsgHdr, nlmsg_align};

/// Token returned when starting a nested attribute.
/// Used to finalize the nested attribute length.
#[derive(Debug, Clone, Copy)]
pub struct NestToken {
    /// Offset of the nested attribute header in the buffer.
    offset: usize,
}

/// Builder for constructing netlink messages.
#[derive(Debug, Clone)]
pub struct MessageBuilder {
    buf: Vec<u8>,
}

impl MessageBuilder {
    /// Create a new message builder with the given type and flags.
    pub fn new(msg_type: u16, flags: u16) -> Self {
        let header = NlMsgHdr::new(msg_type, flags);
        let mut buf = vec![0u8; NLMSG_HDRLEN];
        buf[..std::mem::size_of::<NlMsgHdr>()].copy_from_slice(header.as_bytes());
        Self { buf }
    }

    /// Create a builder from an existing header.
    pub fn with_header(header: NlMsgHdr) -> Self {
        let mut buf = vec![0u8; NLMSG_HDRLEN];
        buf[..std::mem::size_of::<NlMsgHdr>()].copy_from_slice(header.as_bytes());
        Self { buf }
    }

    /// Get the current message length.
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    /// Check if the message is empty (header only).
    pub fn is_empty(&self) -> bool {
        self.buf.len() == NLMSG_HDRLEN
    }

    /// Append raw bytes to the message (with alignment padding).
    pub fn append_bytes(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
        // Pad to alignment
        let aligned = nlmsg_align(self.buf.len());
        self.buf.resize(aligned, 0);
    }

    /// Append a fixed-size struct to the message.
    ///
    /// # Safety
    /// The type T must be repr(C) and have no padding bytes that could leak data.
    pub fn append<T: Copy>(&mut self, data: &T) {
        let bytes = unsafe {
            std::slice::from_raw_parts(data as *const T as *const u8, std::mem::size_of::<T>())
        };
        self.append_bytes(bytes);
    }

    /// Append an attribute with the given type and data.
    pub fn append_attr(&mut self, attr_type: u16, data: &[u8]) {
        let attr = NlAttr::new(attr_type, data.len());
        self.buf.extend_from_slice(attr.as_bytes());
        self.buf.extend_from_slice(data);
        // Pad to alignment
        let aligned = nla_align(self.buf.len());
        self.buf.resize(aligned, 0);
    }

    /// Append a u8 attribute.
    pub fn append_attr_u8(&mut self, attr_type: u16, value: u8) {
        self.append_attr(attr_type, &[value]);
    }

    /// Append an empty (flag) attribute with no payload.
    pub fn append_attr_empty(&mut self, attr_type: u16) {
        self.append_attr(attr_type, &[]);
    }

    /// Append a u16 attribute (native endian).
    pub fn append_attr_u16(&mut self, attr_type: u16, value: u16) {
        self.append_attr(attr_type, &value.to_ne_bytes());
    }

    /// Append a u32 attribute (native endian).
    pub fn append_attr_u32(&mut self, attr_type: u16, value: u32) {
        self.append_attr(attr_type, &value.to_ne_bytes());
    }

    /// Append a u64 attribute (native endian).
    pub fn append_attr_u64(&mut self, attr_type: u16, value: u64) {
        self.append_attr(attr_type, &value.to_ne_bytes());
    }

    /// Append a u16 attribute (big endian / network order).
    pub fn append_attr_u16_be(&mut self, attr_type: u16, value: u16) {
        self.append_attr(attr_type, &value.to_be_bytes());
    }

    /// Append a u32 attribute (big endian / network order).
    pub fn append_attr_u32_be(&mut self, attr_type: u16, value: u32) {
        self.append_attr(attr_type, &value.to_be_bytes());
    }

    /// Append a null-terminated string attribute.
    pub fn append_attr_str(&mut self, attr_type: u16, value: &str) {
        let mut data = value.as_bytes().to_vec();
        data.push(0); // null terminator
        self.append_attr(attr_type, &data);
    }

    /// Append a string attribute without null terminator.
    pub fn append_attr_string(&mut self, attr_type: u16, value: &str) {
        self.append_attr(attr_type, value.as_bytes());
    }

    /// Start a nested attribute. Returns a token to finalize it.
    pub fn nest_start(&mut self, attr_type: u16) -> NestToken {
        let offset = self.buf.len();
        // Write placeholder header with nested flag
        let attr = NlAttr::new(attr_type | NLA_F_NESTED, 0);
        self.buf.extend_from_slice(attr.as_bytes());
        NestToken { offset }
    }

    /// End a nested attribute started with `nest_start`.
    pub fn nest_end(&mut self, token: NestToken) {
        let len = self.buf.len() - token.offset;
        // Update the length in the nested attribute header
        let len_bytes = (len as u16).to_ne_bytes();
        self.buf[token.offset] = len_bytes[0];
        self.buf[token.offset + 1] = len_bytes[1];
        // Ensure alignment
        let aligned = nla_align(self.buf.len());
        self.buf.resize(aligned, 0);
    }

    /// Set the sequence number.
    pub fn set_seq(&mut self, seq: u32) {
        let bytes = seq.to_ne_bytes();
        self.buf[8..12].copy_from_slice(&bytes);
    }

    /// Set the port ID.
    pub fn set_pid(&mut self, pid: u32) {
        let bytes = pid.to_ne_bytes();
        self.buf[12..16].copy_from_slice(&bytes);
    }

    /// Finalize and return the message bytes.
    pub fn finish(mut self) -> Vec<u8> {
        // Update message length in header
        let len = self.buf.len() as u32;
        let len_bytes = len.to_ne_bytes();
        self.buf[0..4].copy_from_slice(&len_bytes);
        self.buf
    }

    /// Get the current buffer for inspection.
    pub fn as_bytes(&self) -> &[u8] {
        &self.buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::netlink::attr::NLA_HDRLEN;
    use crate::netlink::message::NLM_F_REQUEST;

    #[test]
    fn test_simple_message() {
        let msg = MessageBuilder::new(16, NLM_F_REQUEST).finish();
        assert_eq!(msg.len(), NLMSG_HDRLEN);

        let header = NlMsgHdr::from_bytes(&msg).unwrap();
        assert_eq!(header.nlmsg_len as usize, NLMSG_HDRLEN);
        assert_eq!(header.nlmsg_type, 16);
        assert_eq!(header.nlmsg_flags, NLM_F_REQUEST);
    }

    #[test]
    fn test_attribute() {
        let mut builder = MessageBuilder::new(16, NLM_F_REQUEST);
        builder.append_attr_u32(1, 0x12345678);
        let msg = builder.finish();

        // Header + attr header + u32 value
        assert!(msg.len() >= NLMSG_HDRLEN + NLA_HDRLEN + 4);
    }

    #[test]
    fn test_nested_attribute() {
        let mut builder = MessageBuilder::new(16, NLM_F_REQUEST);
        let nest = builder.nest_start(1);
        builder.append_attr_u32(2, 100);
        builder.nest_end(nest);
        let msg = builder.finish();

        assert!(msg.len() > NLMSG_HDRLEN);
    }
}
