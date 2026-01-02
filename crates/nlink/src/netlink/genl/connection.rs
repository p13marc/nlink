//! Generic Netlink connection with family resolution.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use super::header::{GENL_HDRLEN, GenlMsgHdr};
use super::{CtrlAttr, CtrlAttrMcastGrp, CtrlCmd, GENL_ID_CTRL};
use crate::netlink::attr::{AttrIter, get};
use crate::netlink::builder::MessageBuilder;
use crate::netlink::error::{Error, Result};
use crate::netlink::message::{MessageIter, NLM_F_ACK, NLM_F_DUMP, NLM_F_REQUEST, NlMsgError};
use crate::netlink::socket::{NetlinkSocket, Protocol};

/// Information about a Generic Netlink family.
#[derive(Debug, Clone)]
pub struct FamilyInfo {
    /// Dynamically assigned family ID (used as nlmsg_type).
    pub id: u16,
    /// Family version.
    pub version: u8,
    /// Header size (additional bytes after genlmsghdr).
    pub hdr_size: u32,
    /// Maximum attribute number.
    pub max_attr: u32,
    /// Multicast groups: name -> group ID.
    pub mcast_groups: HashMap<String, u32>,
}

/// Cache for resolved family information.
#[derive(Debug, Default)]
struct FamilyCache {
    families: HashMap<String, FamilyInfo>,
}

/// Generic Netlink connection.
///
/// Provides family ID resolution and high-level GENL operations.
/// Family IDs are cached to avoid repeated kernel queries.
///
/// # Example
///
/// ```rust,no_run
/// use nlink::netlink::genl::GenlConnection;
///
/// # async fn example() -> nlink::Result<()> {
/// let conn = GenlConnection::new()?;
///
/// // Get family info (cached after first call)
/// let wg_family = conn.get_family("wireguard").await?;
/// println!("WireGuard family ID: {}", wg_family.id);
///
/// // Check if a family exists
/// if conn.get_family("macsec").await.is_ok() {
///     println!("MACsec is available");
/// }
/// # Ok(())
/// # }
/// ```
pub struct GenlConnection {
    socket: NetlinkSocket,
    cache: Arc<RwLock<FamilyCache>>,
}

impl GenlConnection {
    /// Create a new Generic Netlink connection.
    pub fn new() -> Result<Self> {
        Ok(Self {
            socket: NetlinkSocket::new(Protocol::Generic)?,
            cache: Arc::new(RwLock::new(FamilyCache::default())),
        })
    }

    /// Create a GENL connection from an existing socket.
    ///
    /// The socket must be a `Protocol::Generic` socket.
    pub fn from_socket(socket: NetlinkSocket) -> Self {
        Self {
            socket,
            cache: Arc::new(RwLock::new(FamilyCache::default())),
        }
    }

    /// Get the underlying socket.
    pub fn socket(&self) -> &NetlinkSocket {
        &self.socket
    }

    /// Get information about a Generic Netlink family.
    ///
    /// The result is cached, so subsequent calls for the same family
    /// do not require kernel communication.
    pub async fn get_family(&self, name: &str) -> Result<FamilyInfo> {
        // Check cache first
        {
            let cache = self.cache.read().unwrap();
            if let Some(info) = cache.families.get(name) {
                return Ok(info.clone());
            }
        }

        // Query kernel for family info
        let info = self.query_family(name).await?;

        // Cache the result
        {
            let mut cache = self.cache.write().unwrap();
            cache.families.insert(name.to_string(), info.clone());
        }

        Ok(info)
    }

    /// Get the family ID for a given family name.
    ///
    /// This is a convenience method that returns just the ID.
    pub async fn get_family_id(&self, name: &str) -> Result<u16> {
        Ok(self.get_family(name).await?.id)
    }

    /// Clear the family cache.
    ///
    /// This is rarely needed, but may be useful if families are
    /// dynamically loaded/unloaded.
    pub fn clear_cache(&self) {
        let mut cache = self.cache.write().unwrap();
        cache.families.clear();
    }

    /// Query the kernel for family information.
    async fn query_family(&self, name: &str) -> Result<FamilyInfo> {
        // Build CTRL_CMD_GETFAMILY request
        let mut builder = MessageBuilder::new(GENL_ID_CTRL, NLM_F_REQUEST | NLM_F_ACK);

        // Append GENL header
        let genl_hdr = GenlMsgHdr::new(CtrlCmd::GetFamily as u8, 1);
        builder.append(&genl_hdr);

        // Append family name attribute
        builder.append_attr_str(CtrlAttr::FamilyName as u16, name);

        // Send request
        let seq = self.socket.next_seq();
        builder.set_seq(seq);
        builder.set_pid(self.socket.pid());

        let msg = builder.finish();
        self.socket.send(&msg).await?;

        // Receive response
        let response = self.socket.recv_msg().await?;

        // Parse response
        self.parse_family_response(&response, seq, name)
    }

    /// Parse a CTRL_CMD_GETFAMILY response.
    fn parse_family_response(&self, data: &[u8], seq: u32, name: &str) -> Result<FamilyInfo> {
        for result in MessageIter::new(data) {
            let (header, payload) = result?;

            // Check sequence number
            if header.nlmsg_seq != seq {
                continue;
            }

            // Check for error
            if header.is_error() {
                let err = NlMsgError::from_bytes(payload)?;
                if !err.is_ack() {
                    // ENOENT means family not found
                    if err.error == -libc::ENOENT {
                        return Err(Error::FamilyNotFound {
                            name: name.to_string(),
                        });
                    }
                    return Err(Error::from_errno(err.error));
                }
                continue;
            }

            // Skip DONE message
            if header.is_done() {
                continue;
            }

            // Parse GENL header
            if payload.len() < GENL_HDRLEN {
                return Err(Error::InvalidMessage("GENL header too short".into()));
            }

            // Parse attributes after GENL header
            let attrs_data = &payload[GENL_HDRLEN..];
            return self.parse_family_attrs(attrs_data);
        }

        Err(Error::FamilyNotFound {
            name: name.to_string(),
        })
    }

    /// Parse family attributes from a CTRL_CMD_GETFAMILY response.
    fn parse_family_attrs(&self, data: &[u8]) -> Result<FamilyInfo> {
        let mut id: Option<u16> = None;
        let mut version: u8 = 0;
        let mut hdr_size: u32 = 0;
        let mut max_attr: u32 = 0;
        let mut mcast_groups = HashMap::new();

        for (attr_type, payload) in AttrIter::new(data) {
            match attr_type {
                t if t == CtrlAttr::FamilyId as u16 => {
                    id = Some(get::u16_ne(payload)?);
                }
                t if t == CtrlAttr::Version as u16 => {
                    version = get::u32_ne(payload)? as u8;
                }
                t if t == CtrlAttr::HdrSize as u16 => {
                    hdr_size = get::u32_ne(payload)?;
                }
                t if t == CtrlAttr::MaxAttr as u16 => {
                    max_attr = get::u32_ne(payload)?;
                }
                t if t == CtrlAttr::McastGroups as u16 => {
                    mcast_groups = self.parse_mcast_groups(payload)?;
                }
                _ => {}
            }
        }

        let id = id.ok_or_else(|| Error::InvalidMessage("missing family ID".into()))?;

        Ok(FamilyInfo {
            id,
            version,
            hdr_size,
            max_attr,
            mcast_groups,
        })
    }

    /// Parse multicast groups from CTRL_ATTR_MCAST_GROUPS.
    fn parse_mcast_groups(&self, data: &[u8]) -> Result<HashMap<String, u32>> {
        let mut groups = HashMap::new();

        // The mcast_groups attribute contains nested arrays
        for (_group_idx, group_payload) in AttrIter::new(data) {
            let mut name: Option<String> = None;
            let mut grp_id: Option<u32> = None;

            // Parse the nested group attributes
            for (attr_type, payload) in AttrIter::new(group_payload) {
                match attr_type {
                    t if t == CtrlAttrMcastGrp::Name as u16 => {
                        name = Some(get::string(payload)?.to_string());
                    }
                    t if t == CtrlAttrMcastGrp::Id as u16 => {
                        grp_id = Some(get::u32_ne(payload)?);
                    }
                    _ => {}
                }
            }

            if let (Some(name), Some(id)) = (name, grp_id) {
                groups.insert(name, id);
            }
        }

        Ok(groups)
    }

    /// Send a GENL command and wait for a response.
    ///
    /// This is a low-level method for sending arbitrary GENL commands.
    /// Family-specific wrappers (like WireguardConnection) should use this.
    pub async fn command(
        &self,
        family_id: u16,
        cmd: u8,
        version: u8,
        build_attrs: impl FnOnce(&mut MessageBuilder),
    ) -> Result<Vec<u8>> {
        let mut builder = MessageBuilder::new(family_id, NLM_F_REQUEST | NLM_F_ACK);

        // Append GENL header
        let genl_hdr = GenlMsgHdr::new(cmd, version);
        builder.append(&genl_hdr);

        // Let caller append attributes
        build_attrs(&mut builder);

        // Send request
        let seq = self.socket.next_seq();
        builder.set_seq(seq);
        builder.set_pid(self.socket.pid());

        let msg = builder.finish();
        self.socket.send(&msg).await?;

        // Receive response
        let response = self.socket.recv_msg().await?;
        self.process_response(&response, seq)?;

        Ok(response)
    }

    /// Send a GENL dump command and collect all responses.
    pub async fn dump_command(
        &self,
        family_id: u16,
        cmd: u8,
        version: u8,
        build_attrs: impl FnOnce(&mut MessageBuilder),
    ) -> Result<Vec<Vec<u8>>> {
        let mut builder = MessageBuilder::new(family_id, NLM_F_REQUEST | NLM_F_DUMP);

        // Append GENL header
        let genl_hdr = GenlMsgHdr::new(cmd, version);
        builder.append(&genl_hdr);

        // Let caller append attributes
        build_attrs(&mut builder);

        // Send request
        let seq = self.socket.next_seq();
        builder.set_seq(seq);
        builder.set_pid(self.socket.pid());

        let msg = builder.finish();
        self.socket.send(&msg).await?;

        let mut responses = Vec::new();

        loop {
            let data = self.socket.recv_msg().await?;
            let mut done = false;

            for result in MessageIter::new(&data) {
                let (header, payload) = result?;

                if header.nlmsg_seq != seq {
                    continue;
                }

                if header.is_error() {
                    let err = NlMsgError::from_bytes(payload)?;
                    if !err.is_ack() {
                        return Err(Error::from_errno(err.error));
                    }
                    continue;
                }

                if header.is_done() {
                    done = true;
                    break;
                }

                // Include the payload (with GENL header)
                responses.push(payload.to_vec());
            }

            if done {
                break;
            }
        }

        Ok(responses)
    }

    /// Process a response, checking for errors.
    fn process_response(&self, data: &[u8], seq: u32) -> Result<()> {
        for result in MessageIter::new(data) {
            let (header, payload) = result?;

            if header.nlmsg_seq != seq {
                continue;
            }

            if header.is_error() {
                let err = NlMsgError::from_bytes(payload)?;
                if !err.is_ack() {
                    return Err(Error::from_errno(err.error));
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_family_info_default() {
        let info = FamilyInfo {
            id: 21,
            version: 1,
            hdr_size: 0,
            max_attr: 10,
            mcast_groups: HashMap::new(),
        };
        assert_eq!(info.id, 21);
        assert_eq!(info.version, 1);
    }

    // Integration tests require root and network access
    // They are feature-gated or run separately
}
