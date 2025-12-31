//! High-level netlink connection with request/response handling.

use crate::builder::MessageBuilder;
use crate::error::{Error, Result};
use crate::message::{
    MessageIter, NLM_F_ACK, NLM_F_DUMP, NLM_F_REQUEST, NLMSG_HDRLEN, NlMsgError, NlMsgHdr,
    NlMsgType,
};
use crate::parse::FromNetlink;
use crate::socket::{NetlinkSocket, Protocol};

/// High-level netlink connection.
pub struct Connection {
    socket: NetlinkSocket,
}

impl Connection {
    /// Create a new connection for the given protocol.
    pub fn new(protocol: Protocol) -> Result<Self> {
        Ok(Self {
            socket: NetlinkSocket::new(protocol)?,
        })
    }

    /// Get the underlying socket.
    pub fn socket(&self) -> &NetlinkSocket {
        &self.socket
    }

    /// Send a request and wait for a single response or ACK.
    pub async fn request(&self, mut builder: MessageBuilder) -> Result<Vec<u8>> {
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

    /// Send a request that expects an ACK only (no data response).
    pub async fn request_ack(&self, mut builder: MessageBuilder) -> Result<()> {
        let seq = self.socket.next_seq();
        builder.set_seq(seq);
        builder.set_pid(self.socket.pid());

        let msg = builder.finish();
        self.socket.send(&msg).await?;

        // Receive ACK
        let response = self.socket.recv_msg().await?;
        self.process_ack(&response, seq)?;

        Ok(())
    }

    /// Send a dump request and collect all responses.
    pub async fn dump(&self, mut builder: MessageBuilder) -> Result<Vec<Vec<u8>>> {
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

                // Check sequence number
                if header.nlmsg_seq != seq {
                    continue;
                }

                if header.is_error() {
                    let err = NlMsgError::from_bytes(payload)?;
                    if !err.is_ack() {
                        return Err(Error::from_errno(err.error));
                    }
                }

                if header.is_done() {
                    done = true;
                    break;
                }

                // Collect the full message (header + payload)
                let msg_len = header.nlmsg_len as usize;
                let msg_start = payload.as_ptr() as usize
                    - data.as_ptr() as usize
                    - std::mem::size_of::<NlMsgHdr>();
                if msg_start + msg_len <= data.len() {
                    responses.push(data[msg_start..msg_start + msg_len].to_vec());
                }
            }

            if done {
                break;
            }
        }

        Ok(responses)
    }

    /// Process a response and check for errors.
    fn process_response(&self, data: &[u8], expected_seq: u32) -> Result<()> {
        for result in MessageIter::new(data) {
            let (header, payload) = result?;

            if header.nlmsg_seq != expected_seq {
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

    /// Process an ACK response.
    fn process_ack(&self, data: &[u8], expected_seq: u32) -> Result<()> {
        for result in MessageIter::new(data) {
            let (header, payload) = result?;

            if header.nlmsg_seq != expected_seq {
                continue;
            }

            if header.is_error() {
                let err = NlMsgError::from_bytes(payload)?;
                if !err.is_ack() {
                    return Err(Error::from_errno(err.error));
                }
                return Ok(());
            }
        }

        Err(Error::InvalidMessage("expected ACK message".into()))
    }

    /// Subscribe to multicast groups for monitoring.
    pub fn subscribe(&mut self, group: u32) -> Result<()> {
        self.socket.add_membership(group)
    }

    /// Receive the next event message (for monitoring).
    pub async fn recv_event(&self) -> Result<Vec<u8>> {
        self.socket.recv_msg().await
    }

    // ========================================================================
    // Strongly-typed API
    // ========================================================================

    /// Send a dump request and parse all responses into typed messages.
    ///
    /// This is a convenience method that combines `dump()` with parsing.
    /// The type T must implement `FromNetlink::write_dump_header` to provide
    /// the required message header (e.g., IfInfoMsg for links, IfAddrMsg for addresses).
    ///
    /// # Example
    ///
    /// ```ignore
    /// use rip_netlink::messages::AddressMessage;
    /// use rip_netlink::message::NlMsgType;
    ///
    /// let addresses: Vec<AddressMessage> = conn.dump_typed(NlMsgType::RTM_GETADDR).await?;
    /// for addr in addresses {
    ///     println!("{}: {:?}", addr.ifindex(), addr.address);
    /// }
    /// ```
    pub async fn dump_typed<T: FromNetlink>(&self, msg_type: u16) -> Result<Vec<T>> {
        let mut builder = dump_request(msg_type);

        // Get the header from the type and append it to the request
        let mut header_buf = Vec::new();
        T::write_dump_header(&mut header_buf);
        builder.append_bytes(&header_buf);

        let responses = self.dump(builder).await?;

        let mut parsed = Vec::with_capacity(responses.len());
        for response in responses {
            if response.len() < NLMSG_HDRLEN {
                continue;
            }
            let payload = &response[NLMSG_HDRLEN..];
            if let Ok(msg) = T::from_bytes(payload) {
                parsed.push(msg);
            }
        }

        Ok(parsed)
    }

    /// Parse a single response into a typed message.
    pub fn parse_response<T: FromNetlink>(&self, response: &[u8]) -> Result<T> {
        if response.len() < NLMSG_HDRLEN {
            return Err(Error::Truncated {
                expected: NLMSG_HDRLEN,
                actual: response.len(),
            });
        }
        let payload = &response[NLMSG_HDRLEN..];
        T::from_bytes(payload)
    }
}

/// Helper to build a dump request.
pub fn dump_request(msg_type: u16) -> MessageBuilder {
    MessageBuilder::new(msg_type, NLM_F_REQUEST | NLM_F_DUMP)
}

/// Helper to build a request expecting ACK.
pub fn ack_request(msg_type: u16) -> MessageBuilder {
    MessageBuilder::new(msg_type, NLM_F_REQUEST | NLM_F_ACK)
}

/// Helper to build a create request.
pub fn create_request(msg_type: u16) -> MessageBuilder {
    MessageBuilder::new(msg_type, NLM_F_REQUEST | NLM_F_ACK | 0x400) // NLM_F_CREATE
}

/// Helper to build a create-or-replace request.
pub fn replace_request(msg_type: u16) -> MessageBuilder {
    MessageBuilder::new(msg_type, NLM_F_REQUEST | NLM_F_ACK | 0x400 | 0x100) // NLM_F_CREATE | NLM_F_REPLACE
}

// ============================================================================
// Convenience Query Methods
// ============================================================================

use crate::messages::{AddressMessage, LinkMessage, NeighborMessage, RouteMessage, TcMessage};

/// Helper function to convert interface name to index.
/// This is a standalone implementation to avoid dependency on rip-lib.
fn ifname_to_index(name: &str) -> Result<i32> {
    let path = format!("/sys/class/net/{}/ifindex", name);
    let content = std::fs::read_to_string(&path)
        .map_err(|_| Error::InvalidMessage(format!("interface not found: {}", name)))?;
    content
        .trim()
        .parse()
        .map_err(|_| Error::InvalidMessage(format!("invalid ifindex for: {}", name)))
}

impl Connection {
    /// Get all network interfaces.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let links = conn.get_links().await?;
    /// for link in links {
    ///     println!("{}: {}", link.ifindex(), link.name.as_deref().unwrap_or("?"));
    /// }
    /// ```
    pub async fn get_links(&self) -> Result<Vec<LinkMessage>> {
        self.dump_typed(NlMsgType::RTM_GETLINK).await
    }

    /// Get a network interface by name.
    ///
    /// Returns `None` if the interface doesn't exist.
    pub async fn get_link_by_name(&self, name: &str) -> Result<Option<LinkMessage>> {
        let links = self.get_links().await?;
        Ok(links.into_iter().find(|l| l.name.as_deref() == Some(name)))
    }

    /// Get a network interface by index.
    ///
    /// Returns `None` if the interface doesn't exist.
    pub async fn get_link_by_index(&self, index: i32) -> Result<Option<LinkMessage>> {
        let links = self.get_links().await?;
        Ok(links.into_iter().find(|l| l.ifindex() == index))
    }

    /// Get all IP addresses.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let addresses = conn.get_addresses().await?;
    /// for addr in addresses {
    ///     println!("{:?}/{} on idx {}", addr.address, addr.prefix_len(), addr.ifindex());
    /// }
    /// ```
    pub async fn get_addresses(&self) -> Result<Vec<AddressMessage>> {
        self.dump_typed(NlMsgType::RTM_GETADDR).await
    }

    /// Get IP addresses for a specific interface by name.
    pub async fn get_addresses_for(&self, ifname: &str) -> Result<Vec<AddressMessage>> {
        let ifindex = ifname_to_index(ifname)?;
        let addresses = self.get_addresses().await?;
        Ok(addresses
            .into_iter()
            .filter(|a| a.ifindex() as i32 == ifindex)
            .collect())
    }

    /// Get IP addresses for a specific interface by index.
    pub async fn get_addresses_for_index(&self, ifindex: u32) -> Result<Vec<AddressMessage>> {
        let addresses = self.get_addresses().await?;
        Ok(addresses
            .into_iter()
            .filter(|a| a.ifindex() == ifindex)
            .collect())
    }

    /// Get all routes.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let routes = conn.get_routes().await?;
    /// for route in routes {
    ///     println!("{:?}/{}", route.destination(), route.dst_len());
    /// }
    /// ```
    pub async fn get_routes(&self) -> Result<Vec<RouteMessage>> {
        self.dump_typed(NlMsgType::RTM_GETROUTE).await
    }

    /// Get routes for a specific table.
    pub async fn get_routes_for_table(&self, table_id: u32) -> Result<Vec<RouteMessage>> {
        let routes = self.get_routes().await?;
        Ok(routes
            .into_iter()
            .filter(|r| r.table_id() == table_id)
            .collect())
    }

    /// Get all neighbor entries.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let neighbors = conn.get_neighbors().await?;
    /// for neigh in neighbors {
    ///     println!("{:?} -> {:?}", neigh.destination, neigh.lladdr);
    /// }
    /// ```
    pub async fn get_neighbors(&self) -> Result<Vec<NeighborMessage>> {
        self.dump_typed(NlMsgType::RTM_GETNEIGH).await
    }

    /// Get neighbor entries for a specific interface.
    pub async fn get_neighbors_for(&self, ifname: &str) -> Result<Vec<NeighborMessage>> {
        let ifindex = ifname_to_index(ifname)?;
        let neighbors = self.get_neighbors().await?;
        Ok(neighbors
            .into_iter()
            .filter(|n| n.ifindex() as i32 == ifindex)
            .collect())
    }

    /// Get all qdiscs.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let qdiscs = conn.get_qdiscs().await?;
    /// for qdisc in qdiscs {
    ///     println!("{}: {}", qdisc.ifindex(), qdisc.kind().unwrap_or("?"));
    /// }
    /// ```
    pub async fn get_qdiscs(&self) -> Result<Vec<TcMessage>> {
        self.dump_typed(NlMsgType::RTM_GETQDISC).await
    }

    /// Get qdiscs for a specific interface.
    pub async fn get_qdiscs_for(&self, ifname: &str) -> Result<Vec<TcMessage>> {
        let ifindex = ifname_to_index(ifname)?;
        let qdiscs = self.get_qdiscs().await?;
        Ok(qdiscs
            .into_iter()
            .filter(|q| q.ifindex() == ifindex)
            .collect())
    }

    /// Get all TC classes.
    pub async fn get_classes(&self) -> Result<Vec<TcMessage>> {
        self.dump_typed(NlMsgType::RTM_GETTCLASS).await
    }

    /// Get TC classes for a specific interface.
    pub async fn get_classes_for(&self, ifname: &str) -> Result<Vec<TcMessage>> {
        let ifindex = ifname_to_index(ifname)?;
        let classes = self.get_classes().await?;
        Ok(classes
            .into_iter()
            .filter(|c| c.ifindex() == ifindex)
            .collect())
    }

    /// Get all TC filters.
    pub async fn get_filters(&self) -> Result<Vec<TcMessage>> {
        self.dump_typed(NlMsgType::RTM_GETTFILTER).await
    }

    /// Get TC filters for a specific interface.
    pub async fn get_filters_for(&self, ifname: &str) -> Result<Vec<TcMessage>> {
        let ifindex = ifname_to_index(ifname)?;
        let filters = self.get_filters().await?;
        Ok(filters
            .into_iter()
            .filter(|f| f.ifindex() == ifindex)
            .collect())
    }
}
