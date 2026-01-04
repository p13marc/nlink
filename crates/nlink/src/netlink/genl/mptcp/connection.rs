//! Connection<Mptcp> implementation.

use std::net::IpAddr;

use super::types::{MptcpEndpoint, MptcpEndpointBuilder, MptcpFlags, MptcpLimits};
use super::{MPTCP_PM_GENL_NAME, MPTCP_PM_GENL_VERSION};
use crate::netlink::attr::{AttrIter, NLA_F_NESTED, get};
use crate::netlink::builder::MessageBuilder;
use crate::netlink::connection::Connection;
use crate::netlink::error::{Error, Result};
use crate::netlink::genl::{CtrlAttr, CtrlCmd, GENL_HDRLEN, GENL_ID_CTRL, GenlMsgHdr};
use crate::netlink::message::{MessageIter, NLM_F_ACK, NLM_F_DUMP, NLM_F_REQUEST, NlMsgError};
use crate::netlink::protocol::{Mptcp, ProtocolState};
use crate::netlink::socket::NetlinkSocket;
use crate::netlink::types::mptcp::{mptcp_pm_addr_attr, mptcp_pm_attr, mptcp_pm_cmd};

impl Connection<Mptcp> {
    /// Create a new MPTCP connection.
    ///
    /// This resolves the MPTCP PM GENL family ID during initialization.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use nlink::netlink::{Connection, Mptcp};
    ///
    /// let conn = Connection::<Mptcp>::new_async().await?;
    /// let endpoints = conn.get_endpoints().await?;
    /// ```
    pub async fn new_async() -> Result<Self> {
        let socket = NetlinkSocket::new(Mptcp::PROTOCOL)?;
        let family_id = resolve_mptcp_family(&socket).await?;

        let state = Mptcp { family_id };
        Ok(Self::from_parts(socket, state))
    }

    /// Get the MPTCP PM family ID.
    pub fn family_id(&self) -> u16 {
        self.state().family_id
    }

    /// Get all configured MPTCP endpoints.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let conn = Connection::<Mptcp>::new_async().await?;
    /// for ep in conn.get_endpoints().await? {
    ///     println!("Endpoint {}: {} flags={:?}", ep.id, ep.address, ep.flags);
    /// }
    /// ```
    pub async fn get_endpoints(&self) -> Result<Vec<MptcpEndpoint>> {
        let responses = self
            .dump_mptcp_command(mptcp_pm_cmd::GET_ADDR, |_builder| {})
            .await?;

        let mut endpoints = Vec::new();
        for response in &responses {
            if let Some(ep) = parse_endpoint_response(response)? {
                endpoints.push(ep);
            }
        }

        Ok(endpoints)
    }

    /// Add an MPTCP endpoint.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use nlink::netlink::genl::mptcp::MptcpEndpointBuilder;
    ///
    /// conn.add_endpoint(
    ///     MptcpEndpointBuilder::new("192.168.2.1".parse()?)
    ///         .id(1)
    ///         .dev("eth1")
    ///         .subflow()
    ///         .signal()
    /// ).await?;
    /// ```
    pub async fn add_endpoint(&self, endpoint: MptcpEndpointBuilder) -> Result<()> {
        self.mptcp_command(mptcp_pm_cmd::ADD_ADDR, |builder| {
            let addr_token = builder.nest_start(mptcp_pm_attr::ADDR | NLA_F_NESTED);
            append_endpoint_attrs(builder, &endpoint);
            builder.nest_end(addr_token);
        })
        .await?;

        Ok(())
    }

    /// Delete an MPTCP endpoint by ID.
    ///
    /// # Example
    ///
    /// ```ignore
    /// conn.del_endpoint(1).await?;
    /// ```
    pub async fn del_endpoint(&self, id: u8) -> Result<()> {
        self.mptcp_command(mptcp_pm_cmd::DEL_ADDR, |builder| {
            let addr_token = builder.nest_start(mptcp_pm_attr::ADDR | NLA_F_NESTED);
            builder.append_attr_u8(mptcp_pm_addr_attr::ID, id);
            builder.nest_end(addr_token);
        })
        .await?;

        Ok(())
    }

    /// Flush all MPTCP endpoints.
    ///
    /// # Example
    ///
    /// ```ignore
    /// conn.flush_endpoints().await?;
    /// ```
    pub async fn flush_endpoints(&self) -> Result<()> {
        self.mptcp_command(mptcp_pm_cmd::FLUSH_ADDRS, |_builder| {})
            .await?;

        Ok(())
    }

    /// Get MPTCP limits.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let limits = conn.get_limits().await?;
    /// println!("Max subflows: {:?}", limits.subflows);
    /// println!("Max add_addr_accepted: {:?}", limits.add_addr_accepted);
    /// ```
    pub async fn get_limits(&self) -> Result<MptcpLimits> {
        let responses = self
            .dump_mptcp_command(mptcp_pm_cmd::GET_LIMITS, |_builder| {})
            .await?;

        for response in &responses {
            if let Some(limits) = parse_limits_response(response)? {
                return Ok(limits);
            }
        }

        Ok(MptcpLimits::default())
    }

    /// Set MPTCP limits.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use nlink::netlink::genl::mptcp::MptcpLimits;
    ///
    /// conn.set_limits(
    ///     MptcpLimits::new()
    ///         .subflows(4)
    ///         .add_addr_accepted(4)
    /// ).await?;
    /// ```
    pub async fn set_limits(&self, limits: MptcpLimits) -> Result<()> {
        self.mptcp_command(mptcp_pm_cmd::SET_LIMITS, |builder| {
            if let Some(subflows) = limits.subflows {
                builder.append_attr_u32(mptcp_pm_attr::SUBFLOWS, subflows);
            }
            if let Some(add_addr) = limits.add_addr_accepted {
                builder.append_attr_u32(mptcp_pm_attr::RCV_ADD_ADDRS, add_addr);
            }
        })
        .await?;

        Ok(())
    }

    /// Set endpoint flags by ID.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use nlink::netlink::genl::mptcp::MptcpFlags;
    ///
    /// // Mark endpoint 1 as backup
    /// conn.set_endpoint_flags(1, MptcpFlags { backup: true, ..Default::default() }).await?;
    /// ```
    pub async fn set_endpoint_flags(&self, id: u8, flags: MptcpFlags) -> Result<()> {
        self.mptcp_command(mptcp_pm_cmd::SET_FLAGS, |builder| {
            let addr_token = builder.nest_start(mptcp_pm_attr::ADDR | NLA_F_NESTED);
            builder.append_attr_u8(mptcp_pm_addr_attr::ID, id);
            builder.append_attr_u32(mptcp_pm_addr_attr::FLAGS, flags.to_raw());
            builder.nest_end(addr_token);
        })
        .await?;

        Ok(())
    }

    /// Send an MPTCP PM GENL command and wait for ACK.
    async fn mptcp_command(
        &self,
        cmd: u8,
        build_attrs: impl FnOnce(&mut MessageBuilder),
    ) -> Result<Vec<u8>> {
        let family_id = self.state().family_id;

        let mut builder = MessageBuilder::new(family_id, NLM_F_REQUEST | NLM_F_ACK);

        let genl_hdr = GenlMsgHdr::new(cmd, MPTCP_PM_GENL_VERSION);
        builder.append(&genl_hdr);

        build_attrs(&mut builder);

        let seq = self.socket().next_seq();
        builder.set_seq(seq);
        builder.set_pid(self.socket().pid());

        let msg = builder.finish();
        self.socket().send(&msg).await?;

        let response: Vec<u8> = self.socket().recv_msg().await?;
        self.process_genl_response(&response, seq)?;

        Ok(response)
    }

    /// Send an MPTCP PM GENL dump command and collect all responses.
    async fn dump_mptcp_command(
        &self,
        cmd: u8,
        build_attrs: impl FnOnce(&mut MessageBuilder),
    ) -> Result<Vec<Vec<u8>>> {
        let family_id = self.state().family_id;

        let mut builder = MessageBuilder::new(family_id, NLM_F_REQUEST | NLM_F_DUMP);

        let genl_hdr = GenlMsgHdr::new(cmd, MPTCP_PM_GENL_VERSION);
        builder.append(&genl_hdr);

        build_attrs(&mut builder);

        let seq = self.socket().next_seq();
        builder.set_seq(seq);
        builder.set_pid(self.socket().pid());

        let msg = builder.finish();
        self.socket().send(&msg).await?;

        let mut responses = Vec::new();

        loop {
            let data: Vec<u8> = self.socket().recv_msg().await?;
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

/// Resolve the MPTCP PM GENL family ID.
async fn resolve_mptcp_family(socket: &NetlinkSocket) -> Result<u16> {
    let mut builder = MessageBuilder::new(GENL_ID_CTRL, NLM_F_REQUEST | NLM_F_ACK);

    let genl_hdr = GenlMsgHdr::new(CtrlCmd::GetFamily as u8, 1);
    builder.append(&genl_hdr);

    builder.append_attr_str(CtrlAttr::FamilyName as u16, MPTCP_PM_GENL_NAME);

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
                        name: MPTCP_PM_GENL_NAME.to_string(),
                    });
                }
                return Err(Error::from_errno(err.error));
            }
            continue;
        }

        if header.is_done() {
            continue;
        }

        if payload.len() < GENL_HDRLEN {
            return Err(Error::InvalidMessage("GENL header too short".into()));
        }

        let attrs_data = &payload[GENL_HDRLEN..];
        for (attr_type, attr_payload) in AttrIter::new(attrs_data) {
            if attr_type == CtrlAttr::FamilyId as u16 {
                return get::u16_ne(attr_payload);
            }
        }
    }

    Err(Error::FamilyNotFound {
        name: MPTCP_PM_GENL_NAME.to_string(),
    })
}

/// Append endpoint attributes to a message builder.
fn append_endpoint_attrs(builder: &mut MessageBuilder, endpoint: &MptcpEndpointBuilder) {
    // Address family
    let family = match endpoint.address {
        IpAddr::V4(_) => libc::AF_INET as u16,
        IpAddr::V6(_) => libc::AF_INET6 as u16,
    };
    builder.append_attr(mptcp_pm_addr_attr::FAMILY, &family.to_ne_bytes());

    // Address
    match endpoint.address {
        IpAddr::V4(addr) => {
            builder.append_attr(mptcp_pm_addr_attr::ADDR4, &addr.octets());
        }
        IpAddr::V6(addr) => {
            builder.append_attr(mptcp_pm_addr_attr::ADDR6, &addr.octets());
        }
    }

    // Optional ID
    if let Some(id) = endpoint.id {
        builder.append_attr_u8(mptcp_pm_addr_attr::ID, id);
    }

    // Optional port (network byte order)
    if let Some(port) = endpoint.port {
        builder.append_attr(mptcp_pm_addr_attr::PORT, &port.to_be_bytes());
    }

    // Optional interface index
    if let Some(ifindex) = endpoint.ifindex {
        builder.append_attr_u32(mptcp_pm_addr_attr::IF_IDX, ifindex);
    } else if let Some(ref dev) = endpoint.dev
        && let Ok(ifindex) = crate::util::device::get_ifindex(dev)
    {
        builder.append_attr_u32(mptcp_pm_addr_attr::IF_IDX, ifindex);
    }

    // Flags
    let flags = endpoint.flags.to_raw();
    if flags != 0 {
        builder.append_attr_u32(mptcp_pm_addr_attr::FLAGS, flags);
    }
}

/// Parse an endpoint from a GENL response.
fn parse_endpoint_response(payload: &[u8]) -> Result<Option<MptcpEndpoint>> {
    // Skip GENL header
    if payload.len() < GENL_HDRLEN {
        return Ok(None);
    }
    let data = &payload[GENL_HDRLEN..];

    // Look for MPTCP_PM_ATTR_ADDR
    for (attr_type, attr_payload) in AttrIter::new(data) {
        if attr_type == mptcp_pm_attr::ADDR {
            return Ok(Some(parse_endpoint_attrs(attr_payload)?));
        }
    }

    Ok(None)
}

/// Parse endpoint attributes from nested data.
fn parse_endpoint_attrs(data: &[u8]) -> Result<MptcpEndpoint> {
    let mut endpoint = MptcpEndpoint::default();

    for (attr_type, payload) in AttrIter::new(data) {
        match attr_type {
            t if t == mptcp_pm_addr_attr::ID => {
                if !payload.is_empty() {
                    endpoint.id = payload[0];
                }
            }
            t if t == mptcp_pm_addr_attr::ADDR4 => {
                if payload.len() >= 4 {
                    let octets: [u8; 4] = payload[..4].try_into().unwrap();
                    endpoint.address = IpAddr::V4(octets.into());
                }
            }
            t if t == mptcp_pm_addr_attr::ADDR6 => {
                if payload.len() >= 16 {
                    let octets: [u8; 16] = payload[..16].try_into().unwrap();
                    endpoint.address = IpAddr::V6(octets.into());
                }
            }
            t if t == mptcp_pm_addr_attr::PORT => {
                if payload.len() >= 2 {
                    let port = u16::from_be_bytes(payload[..2].try_into().unwrap());
                    if port != 0 {
                        endpoint.port = Some(port);
                    }
                }
            }
            t if t == mptcp_pm_addr_attr::FLAGS => {
                if payload.len() >= 4 {
                    let flags = u32::from_ne_bytes(payload[..4].try_into().unwrap());
                    endpoint.flags = MptcpFlags::from_raw(flags);
                }
            }
            t if t == mptcp_pm_addr_attr::IF_IDX => {
                if payload.len() >= 4 {
                    let ifindex = u32::from_ne_bytes(payload[..4].try_into().unwrap());
                    if ifindex != 0 {
                        endpoint.ifindex = Some(ifindex);
                    }
                }
            }
            _ => {}
        }
    }

    Ok(endpoint)
}

/// Parse limits from a GENL response.
fn parse_limits_response(payload: &[u8]) -> Result<Option<MptcpLimits>> {
    // Skip GENL header
    if payload.len() < GENL_HDRLEN {
        return Ok(None);
    }
    let data = &payload[GENL_HDRLEN..];

    let mut limits = MptcpLimits::default();
    let mut found = false;

    for (attr_type, attr_payload) in AttrIter::new(data) {
        match attr_type {
            t if t == mptcp_pm_attr::SUBFLOWS => {
                if attr_payload.len() >= 4 {
                    limits.subflows =
                        Some(u32::from_ne_bytes(attr_payload[..4].try_into().unwrap()));
                    found = true;
                }
            }
            t if t == mptcp_pm_attr::RCV_ADD_ADDRS => {
                if attr_payload.len() >= 4 {
                    limits.add_addr_accepted =
                        Some(u32::from_ne_bytes(attr_payload[..4].try_into().unwrap()));
                    found = true;
                }
            }
            _ => {}
        }
    }

    if found { Ok(Some(limits)) } else { Ok(None) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_empty_payload() {
        let result = parse_endpoint_response(&[]).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_parse_limits_empty() {
        let result = parse_limits_response(&[]).unwrap();
        assert!(result.is_none());
    }
}
