//! Namespace ID message parsing.
//!
//! Parses RTM_NEWNSID and RTM_DELNSID netlink messages.

use crate::netlink::attr::AttrIter;
use crate::netlink::types::nsid::netnsa;

/// Parsed namespace ID message from RTM_NEWNSID/RTM_DELNSID.
#[derive(Debug, Clone, Default)]
pub struct NsIdMessage {
    /// Address family (usually AF_UNSPEC = 0)
    pub family: u8,
    /// Namespace ID
    pub nsid: Option<u32>,
    /// Process ID that owns/triggered the namespace
    pub pid: Option<u32>,
    /// File descriptor (for fd-based references)
    pub fd: Option<i32>,
    /// Target namespace ID (for queries)
    pub target_nsid: Option<u32>,
    /// Current namespace ID
    pub current_nsid: Option<u32>,
}

impl NsIdMessage {
    /// Parse a namespace ID message from raw bytes.
    ///
    /// The input should be the payload after the netlink header (16 bytes).
    /// Format: rtgenmsg (1 byte family + 3 padding) + attributes
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.is_empty() {
            return None;
        }

        // Parse rtgenmsg header (1 byte family, 3 bytes padding)
        let family = data[0];

        // Attributes start at offset 4 (after rtgenmsg + padding)
        let attr_data = data.get(4..)?;

        let mut msg = NsIdMessage {
            family,
            ..Default::default()
        };

        // Parse attributes using existing AttrIter
        for (attr_type, payload) in AttrIter::new(attr_data) {
            match attr_type {
                x if x == netnsa::NSID => {
                    if payload.len() >= 4 {
                        msg.nsid = Some(u32::from_ne_bytes(payload[..4].try_into().ok()?));
                    }
                }
                x if x == netnsa::PID => {
                    if payload.len() >= 4 {
                        msg.pid = Some(u32::from_ne_bytes(payload[..4].try_into().ok()?));
                    }
                }
                x if x == netnsa::FD => {
                    if payload.len() >= 4 {
                        msg.fd = Some(i32::from_ne_bytes(payload[..4].try_into().ok()?));
                    }
                }
                x if x == netnsa::TARGET_NSID => {
                    if payload.len() >= 4 {
                        msg.target_nsid = Some(u32::from_ne_bytes(payload[..4].try_into().ok()?));
                    }
                }
                x if x == netnsa::CURRENT_NSID => {
                    if payload.len() >= 4 {
                        msg.current_nsid = Some(u32::from_ne_bytes(payload[..4].try_into().ok()?));
                    }
                }
                _ => {}
            }
        }

        Some(msg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nsid_message_parsing() {
        // rtgenmsg (1 byte family + 3 padding) + NETNSA_NSID attribute
        let data = [
            0x00, 0x00, 0x00, 0x00, // rtgenmsg: family=0, padding
            0x08, 0x00, // attr len=8
            0x01, 0x00, // attr type=NETNSA_NSID
            0x42, 0x00, 0x00, 0x00, // nsid=66
        ];

        let msg = NsIdMessage::parse(&data).unwrap();
        assert_eq!(msg.family, 0);
        assert_eq!(msg.nsid, Some(66));
        assert_eq!(msg.pid, None);
    }

    #[test]
    fn test_nsid_message_with_pid() {
        let data = [
            0x00, 0x00, 0x00, 0x00, // rtgenmsg
            0x08, 0x00, 0x01, 0x00, // NETNSA_NSID
            0x01, 0x00, 0x00, 0x00, // nsid=1
            0x08, 0x00, 0x02, 0x00, // NETNSA_PID
            0xe8, 0x03, 0x00, 0x00, // pid=1000
        ];

        let msg = NsIdMessage::parse(&data).unwrap();
        assert_eq!(msg.nsid, Some(1));
        assert_eq!(msg.pid, Some(1000));
    }

    #[test]
    fn test_empty_message() {
        assert!(NsIdMessage::parse(&[]).is_none());
    }

    #[test]
    fn test_minimal_message() {
        // Just the rtgenmsg header, no attributes
        let data = [0x00, 0x00, 0x00, 0x00];
        let msg = NsIdMessage::parse(&data).unwrap();
        assert_eq!(msg.family, 0);
        assert_eq!(msg.nsid, None);
    }
}
