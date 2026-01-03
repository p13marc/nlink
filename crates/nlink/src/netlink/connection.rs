//! High-level netlink connection with request/response handling.

use std::os::unix::io::RawFd;
use std::path::Path;
use std::task::{Context, Poll};

use super::builder::MessageBuilder;
use super::error::{Error, Result};
use super::message::{
    MessageIter, NLM_F_ACK, NLM_F_DUMP, NLM_F_REQUEST, NLMSG_HDRLEN, NlMsgError, NlMsgHdr,
    NlMsgType,
};
use super::parse::FromNetlink;
use super::protocol::{ProtocolState, Route};
use super::socket::NetlinkSocket;

/// High-level netlink connection parameterized by protocol state.
///
/// The type parameter `P` determines which protocol this connection uses
/// and which methods are available:
///
/// - [`Connection<Route>`]: RTNetlink for interfaces, addresses, routes, TC
/// - [`Connection<Generic>`]: Generic netlink for WireGuard, MACsec, etc.
///
/// # Example
///
/// ```ignore
/// use nlink::netlink::{Connection, Route, Generic};
///
/// // Route protocol connection
/// let route = Connection::<Route>::new()?;
/// route.get_links().await?;
///
/// // Generic netlink connection
/// let genl = Connection::<Generic>::new()?;
/// genl.get_family("wireguard").await?;
/// ```
pub struct Connection<P: ProtocolState> {
    socket: NetlinkSocket,
    state: P,
}

// ============================================================================
// Shared methods for all protocol types
// ============================================================================

impl<P: ProtocolState> Connection<P> {
    /// Create a new connection for this protocol type.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use nlink::netlink::{Connection, Route, Generic};
    ///
    /// let route = Connection::<Route>::new()?;
    /// let genl = Connection::<Generic>::new()?;
    /// ```
    pub fn new() -> Result<Self> {
        Ok(Self {
            socket: NetlinkSocket::new(P::PROTOCOL)?,
            state: P::default(),
        })
    }

    /// Create a connection that operates in a specific network namespace.
    ///
    /// The namespace is specified by an open file descriptor to a namespace file
    /// (e.g., `/proc/<pid>/ns/net` or `/var/run/netns/<name>`).
    ///
    /// # Example
    ///
    /// ```ignore
    /// use std::fs::File;
    /// use std::os::unix::io::AsRawFd;
    /// use nlink::netlink::{Connection, Route};
    ///
    /// let ns_file = File::open("/var/run/netns/myns")?;
    /// let conn = Connection::<Route>::new_in_namespace(ns_file.as_raw_fd())?;
    ///
    /// // All operations now occur in the "myns" namespace
    /// let links = conn.get_links().await?;
    /// ```
    pub fn new_in_namespace(ns_fd: RawFd) -> Result<Self> {
        Ok(Self {
            socket: NetlinkSocket::new_in_namespace(P::PROTOCOL, ns_fd)?,
            state: P::default(),
        })
    }

    /// Create a connection that operates in a network namespace specified by path.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use nlink::netlink::{Connection, Route};
    ///
    /// // For a named namespace (created via `ip netns add myns`)
    /// let conn = Connection::<Route>::new_in_namespace_path("/var/run/netns/myns")?;
    ///
    /// // For a container's namespace
    /// let conn = Connection::<Route>::new_in_namespace_path("/proc/1234/ns/net")?;
    ///
    /// // Query interfaces in that namespace
    /// let links = conn.get_links().await?;
    /// ```
    pub fn new_in_namespace_path<T: AsRef<Path>>(ns_path: T) -> Result<Self> {
        Ok(Self {
            socket: NetlinkSocket::new_in_namespace_path(P::PROTOCOL, ns_path)?,
            state: P::default(),
        })
    }

    /// Get the underlying socket.
    pub fn socket(&self) -> &NetlinkSocket {
        &self.socket
    }

    /// Get the protocol state.
    pub fn state(&self) -> &P {
        &self.state
    }

    // ========================================================================
    // Internal request methods (pub(crate) - not part of public API)
    // ========================================================================

    /// Send a request and wait for a single response or ACK.
    /// Send a request and wait for a response.
    ///
    /// This is a low-level method. Prefer using typed methods like `get_links()`,
    /// `add_route()`, etc. when available.
    pub(crate) async fn send_request(&self, mut builder: MessageBuilder) -> Result<Vec<u8>> {
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
    ///
    /// This is a low-level method. Prefer using typed methods like `add_link()`,
    /// `del_route()`, etc. when available.
    pub(crate) async fn send_ack(&self, mut builder: MessageBuilder) -> Result<()> {
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
    ///
    /// This is a low-level method. Prefer using typed methods like `get_links()`,
    /// `get_routes()`, etc. when available.
    pub(crate) async fn send_dump(&self, mut builder: MessageBuilder) -> Result<Vec<Vec<u8>>> {
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
}

// ============================================================================
// Route protocol specific methods
// ============================================================================

impl Connection<Route> {
    /// Create a connection for the specified namespace.
    ///
    /// This is a convenience method that creates a Route protocol connection
    /// for any namespace specification.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use nlink::netlink::{Connection, Route};
    /// use nlink::netlink::namespace::NamespaceSpec;
    ///
    /// // For a named namespace
    /// let conn = Connection::<Route>::for_namespace(NamespaceSpec::Named("myns"))?;
    ///
    /// // For a container by PID
    /// let conn = Connection::<Route>::for_namespace(NamespaceSpec::Pid(1234))?;
    ///
    /// // For the default namespace
    /// let conn = Connection::<Route>::for_namespace(NamespaceSpec::Default)?;
    /// ```
    pub fn for_namespace(spec: super::namespace::NamespaceSpec<'_>) -> Result<Self> {
        spec.connection()
    }

    /// Subscribe to multicast groups for monitoring.
    pub fn subscribe(&mut self, group: u32) -> Result<()> {
        self.socket.add_membership(group)
    }

    /// Receive the next event message (for monitoring).
    pub async fn recv_event(&self) -> Result<Vec<u8>> {
        self.socket.recv_msg().await
    }

    /// Poll for incoming event data.
    ///
    /// This is the poll-based version of `recv_event()` for use with `Stream` implementations.
    pub(crate) fn poll_recv_event(&self, cx: &mut Context<'_>) -> Poll<Result<Vec<u8>>> {
        self.socket.poll_recv(cx)
    }

    // ========================================================================
    // Strongly-typed API for Route protocol
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
    /// use nlink::netlink::messages::AddressMessage;
    /// use nlink::netlink::message::NlMsgType;
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

        let responses = self.send_dump(builder).await?;

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
pub(crate) fn dump_request(msg_type: u16) -> MessageBuilder {
    MessageBuilder::new(msg_type, NLM_F_REQUEST | NLM_F_DUMP)
}

/// Helper to build a request expecting ACK.
pub(crate) fn ack_request(msg_type: u16) -> MessageBuilder {
    MessageBuilder::new(msg_type, NLM_F_REQUEST | NLM_F_ACK)
}

/// Helper to build a create request.
pub(crate) fn create_request(msg_type: u16) -> MessageBuilder {
    MessageBuilder::new(msg_type, NLM_F_REQUEST | NLM_F_ACK | 0x400) // NLM_F_CREATE
}

/// Helper to build a create-or-replace request.
pub(crate) fn replace_request(msg_type: u16) -> MessageBuilder {
    MessageBuilder::new(msg_type, NLM_F_REQUEST | NLM_F_ACK | 0x400 | 0x100) // NLM_F_CREATE | NLM_F_REPLACE
}

// ============================================================================
// Convenience Query Methods
// ============================================================================

use super::messages::{
    AddressMessage, LinkMessage, NeighborMessage, RouteMessage, RuleMessage, TcMessage,
};

/// Helper function to convert interface name to index.
/// This is a standalone implementation to avoid dependency on rip-lib.
pub(crate) fn ifname_to_index(name: &str) -> Result<u32> {
    let path = format!("/sys/class/net/{}/ifindex", name);
    let content = std::fs::read_to_string(&path)
        .map_err(|_| Error::InvalidMessage(format!("interface not found: {}", name)))?;
    content
        .trim()
        .parse()
        .map_err(|_| Error::InvalidMessage(format!("invalid ifindex for: {}", name)))
}

impl Connection<Route> {
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
    pub async fn get_link_by_index(&self, index: u32) -> Result<Option<LinkMessage>> {
        let links = self.get_links().await?;
        Ok(links.into_iter().find(|l| l.ifindex() == index))
    }

    /// Build a map of interface index to name.
    ///
    /// This is a convenience method for code that needs to look up interface
    /// names by index (e.g., when displaying addresses, routes, or TC objects).
    ///
    /// # Example
    ///
    /// ```ignore
    /// let names = conn.get_interface_names().await?;
    /// let addresses = conn.get_addresses().await?;
    /// for addr in addresses {
    ///     let name = names.get(&addr.ifindex()).map(|s| s.as_str()).unwrap_or("?");
    ///     println!("{}: {:?}", name, addr.address);
    /// }
    /// ```
    pub async fn get_interface_names(&self) -> Result<std::collections::HashMap<u32, String>> {
        let links = self.get_links().await?;
        Ok(links
            .into_iter()
            .filter_map(|l| l.name.clone().map(|n| (l.ifindex(), n)))
            .collect())
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
            .filter(|a| a.ifindex() == ifindex)
            .collect())
    }

    /// Get IP addresses for a specific interface by index.
    pub async fn get_addresses_by_index(&self, ifindex: u32) -> Result<Vec<AddressMessage>> {
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
            .filter(|n| n.ifindex() == ifindex)
            .collect())
    }

    /// Get all routing rules.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let rules = conn.get_rules().await?;
    /// for rule in rules {
    ///     println!("{}: {:?} -> table {}", rule.priority, rule.source, rule.table);
    /// }
    /// ```
    pub async fn get_rules(&self) -> Result<Vec<RuleMessage>> {
        self.dump_typed(NlMsgType::RTM_GETRULE).await
    }

    /// Get routing rules for a specific address family.
    ///
    /// # Arguments
    ///
    /// * `family` - Address family: `libc::AF_INET` for IPv4, `libc::AF_INET6` for IPv6
    pub async fn get_rules_for_family(&self, family: u8) -> Result<Vec<RuleMessage>> {
        let rules = self.get_rules().await?;
        Ok(rules.into_iter().filter(|r| r.family() == family).collect())
    }

    /// Get IPv4 routing rules.
    pub async fn get_rules_v4(&self) -> Result<Vec<RuleMessage>> {
        self.get_rules_for_family(libc::AF_INET as u8).await
    }

    /// Get IPv6 routing rules.
    pub async fn get_rules_v6(&self) -> Result<Vec<RuleMessage>> {
        self.get_rules_for_family(libc::AF_INET6 as u8).await
    }

    /// Add a routing rule.
    ///
    /// Use the [`RuleBuilder`] to construct the rule.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use nlink::netlink::rule::RuleBuilder;
    ///
    /// // Add a rule to lookup table 100 for traffic from 10.0.0.0/8
    /// conn.add_rule(
    ///     RuleBuilder::v4()
    ///         .priority(100)
    ///         .from("10.0.0.0", 8)
    ///         .table(100)
    /// ).await?;
    /// ```
    pub async fn add_rule(&self, rule: super::rule::RuleBuilder) -> Result<()> {
        let builder = rule.build()?;
        self.send_ack(builder).await
    }

    /// Delete a routing rule.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use nlink::netlink::rule::RuleBuilder;
    ///
    /// conn.del_rule(
    ///     RuleBuilder::v4()
    ///         .priority(100)
    /// ).await?;
    /// ```
    pub async fn del_rule(&self, rule: super::rule::RuleBuilder) -> Result<()> {
        let builder = rule.build_delete()?;
        self.send_ack(builder).await
    }

    /// Delete a rule by priority.
    pub async fn del_rule_by_priority(&self, family: u8, priority: u32) -> Result<()> {
        let rule = super::rule::RuleBuilder::new(family).priority(priority);
        self.del_rule(rule).await
    }

    /// Flush all non-default routing rules for a family.
    ///
    /// This deletes all rules except the default ones (priority 0, 32766, 32767).
    pub async fn flush_rules(&self, family: u8) -> Result<()> {
        let rules = self.get_rules_for_family(family).await?;

        for rule in rules {
            // Skip default rules
            if rule.priority == 0 || rule.priority == 32766 || rule.priority == 32767 {
                continue;
            }

            // Delete by priority
            let _ = self.del_rule_by_priority(family, rule.priority).await;
        }

        Ok(())
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

    /// Get the root qdisc for an interface (parent == ROOT).
    ///
    /// Returns `None` if no root qdisc is configured.
    ///
    /// # Example
    ///
    /// ```ignore
    /// if let Some(root) = conn.get_root_qdisc_for("eth0").await? {
    ///     println!("Root qdisc: {}", root.kind().unwrap_or("?"));
    /// }
    /// ```
    pub async fn get_root_qdisc_for(&self, ifname: &str) -> Result<Option<TcMessage>> {
        let qdiscs = self.get_qdiscs_for(ifname).await?;
        Ok(qdiscs.into_iter().find(|q| q.is_root()))
    }

    /// Get the root qdisc for an interface by index.
    ///
    /// Returns `None` if no root qdisc is configured.
    pub async fn get_root_qdisc_by_index(&self, ifindex: u32) -> Result<Option<TcMessage>> {
        let qdiscs = self.get_qdiscs().await?;
        Ok(qdiscs
            .into_iter()
            .find(|q| q.ifindex() == ifindex && q.is_root()))
    }

    /// Get a qdisc by interface name and handle.
    ///
    /// # Example
    ///
    /// ```ignore
    /// // Get the qdisc with handle 1:0 on eth0
    /// if let Some(qdisc) = conn.get_qdisc_by_handle("eth0", "1:").await? {
    ///     println!("Found qdisc: {}", qdisc.kind().unwrap_or("?"));
    /// }
    /// ```
    pub async fn get_qdisc_by_handle(
        &self,
        ifname: &str,
        handle: &str,
    ) -> Result<Option<TcMessage>> {
        let ifindex = ifname_to_index(ifname)?;
        self.get_qdisc_by_handle_index(ifindex, handle).await
    }

    /// Get a qdisc by interface index and handle.
    ///
    /// # Example
    ///
    /// ```ignore
    /// // Get the qdisc with handle 1:0 on interface index 2
    /// if let Some(qdisc) = conn.get_qdisc_by_handle_index(2, "1:").await? {
    ///     println!("Found qdisc: {}", qdisc.kind().unwrap_or("?"));
    /// }
    /// ```
    pub async fn get_qdisc_by_handle_index(
        &self,
        ifindex: u32,
        handle: &str,
    ) -> Result<Option<TcMessage>> {
        use super::types::tc::tc_handle;
        let target_handle = tc_handle::parse(handle)
            .ok_or_else(|| Error::InvalidMessage(format!("invalid handle: {}", handle)))?;
        let qdiscs = self.get_qdiscs().await?;
        Ok(qdiscs
            .into_iter()
            .find(|q| q.ifindex() == ifindex && q.handle() == target_handle))
    }

    /// Get netem options for an interface, if a netem qdisc is configured at root.
    ///
    /// This is a convenience method that returns `Some` only if a netem qdisc
    /// is the root qdisc and its options can be parsed.
    ///
    /// # Example
    ///
    /// ```ignore
    /// if let Some(netem) = conn.get_netem_for("eth0").await? {
    ///     println!("Delay: {:?}, Loss: {}%", netem.delay(), netem.loss_percent);
    ///     if netem.has_rate() {
    ///         println!("Rate limit: {} bytes/sec", netem.rate);
    ///     }
    /// }
    /// ```
    pub async fn get_netem_for(
        &self,
        ifname: &str,
    ) -> Result<Option<super::tc_options::NetemOptions>> {
        let root = self.get_root_qdisc_for(ifname).await?;
        Ok(root.and_then(|q| q.netem_options()))
    }

    /// Get netem options for an interface by index.
    ///
    /// Returns `None` if no netem qdisc is configured at root.
    pub async fn get_netem_by_index(
        &self,
        ifindex: u32,
    ) -> Result<Option<super::tc_options::NetemOptions>> {
        let root = self.get_root_qdisc_by_index(ifindex).await?;
        Ok(root.and_then(|q| q.netem_options()))
    }
}

// ============================================================================
// Link State Management
// ============================================================================

use super::types::link::{IfInfoMsg, iff};

impl Connection<Route> {
    /// Bring a network interface up.
    ///
    /// # Example
    ///
    /// ```ignore
    /// conn.set_link_up("eth0").await?;
    /// ```
    pub async fn set_link_up(&self, ifname: &str) -> Result<()> {
        self.set_link_state(ifname, true).await
    }

    /// Bring a network interface up by index.
    pub async fn set_link_up_by_index(&self, ifindex: u32) -> Result<()> {
        self.set_link_state_by_index(ifindex, true).await
    }

    /// Bring a network interface down.
    ///
    /// # Example
    ///
    /// ```ignore
    /// conn.set_link_down("eth0").await?;
    /// ```
    pub async fn set_link_down(&self, ifname: &str) -> Result<()> {
        self.set_link_state(ifname, false).await
    }

    /// Bring a network interface down by index.
    pub async fn set_link_down_by_index(&self, ifindex: u32) -> Result<()> {
        self.set_link_state_by_index(ifindex, false).await
    }

    /// Set the state of a network interface (up or down).
    ///
    /// # Arguments
    ///
    /// * `ifname` - The interface name (e.g., "eth0")
    /// * `up` - `true` to bring the interface up, `false` to bring it down
    ///
    /// # Example
    ///
    /// ```ignore
    /// // Bring interface up
    /// conn.set_link_state("eth0", true).await?;
    ///
    /// // Bring interface down
    /// conn.set_link_state("eth0", false).await?;
    /// ```
    pub async fn set_link_state(&self, ifname: &str, up: bool) -> Result<()> {
        let ifindex = ifname_to_index(ifname)?;
        self.set_link_state_by_index(ifindex, up).await
    }

    /// Set the state of a network interface by index.
    pub async fn set_link_state_by_index(&self, ifindex: u32, up: bool) -> Result<()> {
        let mut ifinfo = IfInfoMsg::new().with_index(ifindex as i32);

        if up {
            ifinfo.ifi_flags = iff::UP;
            ifinfo.ifi_change = iff::UP;
        } else {
            ifinfo.ifi_flags = 0;
            ifinfo.ifi_change = iff::UP;
        }

        let mut builder = ack_request(NlMsgType::RTM_SETLINK);
        builder.append(&ifinfo);

        self.send_ack(builder).await
    }

    /// Set the MTU of a network interface.
    ///
    /// # Example
    ///
    /// ```ignore
    /// conn.set_link_mtu("eth0", 9000).await?;
    /// ```
    pub async fn set_link_mtu(&self, ifname: &str, mtu: u32) -> Result<()> {
        let ifindex = ifname_to_index(ifname)?;
        self.set_link_mtu_by_index(ifindex, mtu).await
    }

    /// Set the MTU of a network interface by index.
    pub async fn set_link_mtu_by_index(&self, ifindex: u32, mtu: u32) -> Result<()> {
        use super::types::link::IflaAttr;

        let ifinfo = IfInfoMsg::new().with_index(ifindex as i32);

        let mut builder = ack_request(NlMsgType::RTM_SETLINK);
        builder.append(&ifinfo);
        builder.append_attr_u32(IflaAttr::Mtu as u16, mtu);

        self.send_ack(builder).await
    }

    /// Delete a network interface.
    ///
    /// # Example
    ///
    /// ```ignore
    /// conn.del_link("veth0").await?;
    /// ```
    pub async fn del_link(&self, ifname: &str) -> Result<()> {
        let ifindex = ifname_to_index(ifname)?;
        self.del_link_by_index(ifindex).await
    }

    /// Delete a network interface by index.
    pub async fn del_link_by_index(&self, ifindex: u32) -> Result<()> {
        let ifinfo = IfInfoMsg::new().with_index(ifindex as i32);

        let mut builder = ack_request(NlMsgType::RTM_DELLINK);
        builder.append(&ifinfo);

        self.send_ack(builder).await
    }

    /// Set the TX queue length of a network interface.
    ///
    /// # Example
    ///
    /// ```ignore
    /// conn.set_link_txqlen("eth0", 1000).await?;
    /// ```
    pub async fn set_link_txqlen(&self, ifname: &str, txqlen: u32) -> Result<()> {
        let ifindex = ifname_to_index(ifname)?;
        self.set_link_txqlen_by_index(ifindex, txqlen).await
    }

    /// Set the TX queue length of a network interface by index.
    pub async fn set_link_txqlen_by_index(&self, ifindex: u32, txqlen: u32) -> Result<()> {
        use super::types::link::IflaAttr;

        let ifinfo = IfInfoMsg::new().with_index(ifindex as i32);

        let mut builder = ack_request(NlMsgType::RTM_SETLINK);
        builder.append(&ifinfo);
        builder.append_attr_u32(IflaAttr::TxqLen as u16, txqlen);

        self.send_ack(builder).await
    }
}

// ============================================================================
// Namespace ID Queries
// ============================================================================

use super::messages::NsIdMessage;
use super::types::nsid::{RTM_GETNSID, RtGenMsg, netnsa};

impl Connection<Route> {
    /// Get the namespace ID for a given file descriptor.
    ///
    /// The file descriptor should be an open reference to a network namespace
    /// (e.g., from opening `/proc/<pid>/ns/net`).
    ///
    /// # Errors
    ///
    /// Returns an error if the namespace ID cannot be determined.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use std::fs::File;
    /// use std::os::unix::io::AsRawFd;
    ///
    /// let ns_file = File::open("/var/run/netns/myns")?;
    /// let nsid = conn.get_nsid(ns_file.as_raw_fd()).await?;
    /// println!("Namespace ID: {}", nsid);
    /// ```
    pub async fn get_nsid(&self, ns_fd: RawFd) -> Result<u32> {
        let mut builder = ack_request(RTM_GETNSID);

        // Append rtgenmsg header (1 byte + 3 padding)
        builder.append(&RtGenMsg::new());
        builder.append_bytes(&[0u8; 3]); // Padding to 4 bytes

        // Add NETNSA_FD attribute
        builder.append_attr_u32(netnsa::FD, ns_fd as u32);

        let response = self.send_request(builder).await?;

        // Parse the response
        if response.len() >= super::message::NLMSG_HDRLEN {
            let payload = &response[super::message::NLMSG_HDRLEN..];
            if let Some(nsid_msg) = NsIdMessage::parse(payload)
                && let Some(nsid) = nsid_msg.nsid
            {
                return Ok(nsid);
            }
        }

        Err(Error::InvalidMessage(
            "namespace ID not found in response".into(),
        ))
    }

    /// Get the namespace ID for a given process's network namespace.
    ///
    /// # Errors
    ///
    /// Returns an error if the namespace ID cannot be determined.
    ///
    /// # Example
    ///
    /// ```ignore
    /// // Get the namespace ID for process 1234
    /// let nsid = conn.get_nsid_for_pid(1234).await?;
    /// println!("Namespace ID for PID 1234: {}", nsid);
    /// ```
    pub async fn get_nsid_for_pid(&self, pid: u32) -> Result<u32> {
        let mut builder = ack_request(RTM_GETNSID);

        // Append rtgenmsg header (1 byte + 3 padding)
        builder.append(&RtGenMsg::new());
        builder.append_bytes(&[0u8; 3]); // Padding to 4 bytes

        // Add NETNSA_PID attribute
        builder.append_attr_u32(netnsa::PID, pid);

        let response = self.send_request(builder).await?;

        // Parse the response
        if response.len() >= super::message::NLMSG_HDRLEN {
            let payload = &response[super::message::NLMSG_HDRLEN..];
            if let Some(nsid_msg) = NsIdMessage::parse(payload)
                && let Some(nsid) = nsid_msg.nsid
            {
                return Ok(nsid);
            }
        }

        Err(Error::InvalidMessage(
            "namespace ID not found in response".into(),
        ))
    }
}

// ============================================================================
// Generic Netlink protocol methods
// ============================================================================

use super::genl::{
    CtrlAttr, CtrlAttrMcastGrp, CtrlCmd, FamilyInfo, GENL_HDRLEN, GENL_ID_CTRL, GenlMsgHdr,
};
use super::protocol::Generic;
use std::collections::HashMap;

impl Connection<Generic> {
    /// Get information about a Generic Netlink family.
    ///
    /// The result is cached, so subsequent calls for the same family
    /// do not require kernel communication.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use nlink::netlink::{Connection, Generic};
    ///
    /// let conn = Connection::<Generic>::new()?;
    /// let wg = conn.get_family("wireguard").await?;
    /// println!("WireGuard family ID: {}", wg.id);
    /// ```
    pub async fn get_family(&self, name: &str) -> Result<FamilyInfo> {
        // Check cache first
        {
            let cache = self.state.cache.read().unwrap();
            if let Some(info) = cache.get(name) {
                return Ok(info.clone());
            }
        }

        // Query kernel for family info
        let info = self.query_family(name).await?;

        // Cache the result
        {
            let mut cache = self.state.cache.write().unwrap();
            cache.insert(name.to_string(), info.clone());
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
        let mut cache = self.state.cache.write().unwrap();
        cache.clear();
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
        use super::attr::{AttrIter, get};

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
        use super::attr::{AttrIter, get};

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
        self.process_genl_response(&response, seq)?;

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

    /// Process a GENL response, checking for errors.
    fn process_genl_response(&self, data: &[u8], seq: u32) -> Result<()> {
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
mod send_sync_tests {
    use super::*;

    fn assert_send<T: Send>() {}
    fn assert_sync<T: Sync>() {}

    #[test]
    fn connection_is_send_sync() {
        assert_send::<Connection<Route>>();
        assert_sync::<Connection<Route>>();
    }
}
