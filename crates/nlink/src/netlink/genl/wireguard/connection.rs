//! WireGuard connection implementation for `Connection<Wireguard>`.
//!
//! This module provides methods for WireGuard device configuration
//! integrated into the Connection pattern.

use std::net::{IpAddr, SocketAddr, SocketAddrV4, SocketAddrV6};

use super::types::{AllowedIp, WG_KEY_LEN, WgDevice, WgDeviceBuilder, WgPeer, parse_timespec};
use super::{
    WG_GENL_NAME, WG_GENL_VERSION, WgAllowedIpAttr, WgCmd, WgDeviceAttr, WgDeviceFlag, WgPeerAttr,
};
use crate::netlink::attr::{AttrIter, NLA_F_NESTED, get};
use crate::netlink::builder::MessageBuilder;
use crate::netlink::connection::Connection;
use crate::netlink::error::{Error, Result};
use crate::netlink::genl::{CtrlAttr, CtrlCmd, GENL_HDRLEN, GENL_ID_CTRL, GenlMsgHdr};
use crate::netlink::interface_ref::InterfaceRef;
use crate::netlink::message::{MessageIter, NLM_F_ACK, NLM_F_DUMP, NLM_F_REQUEST, NlMsgError};
use crate::netlink::protocol::{ProtocolState, Route, Wireguard};
use crate::netlink::socket::NetlinkSocket;

impl Connection<Wireguard> {
    /// Create a new WireGuard connection.
    ///
    /// This resolves the WireGuard GENL family ID during initialization.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use nlink::netlink::{Connection, Wireguard};
    ///
    /// let conn = Connection::<Wireguard>::new().await?;
    /// let device = conn.get_device("wg0").await?;
    /// ```
    pub async fn new_async() -> Result<Self> {
        let socket = NetlinkSocket::new(Wireguard::PROTOCOL)?;
        let family_id = resolve_wireguard_family(&socket).await?;

        let state = Wireguard { family_id };
        Ok(Self::from_parts(socket, state))
    }

    /// Get the WireGuard family ID.
    pub fn family_id(&self) -> u16 {
        self.state().family_id
    }

    /// Resolve an interface reference to a name.
    ///
    /// WireGuard uses interface names in its protocol, so we resolve
    /// indices back to names when needed.
    async fn resolve_interface_name(&self, iface: &InterfaceRef) -> Result<String> {
        match iface {
            InterfaceRef::Name(name) => Ok(name.clone()),
            InterfaceRef::Index(idx) => {
                let route_conn = Connection::<Route>::new()?;
                route_conn
                    .get_link_by_index(*idx)
                    .await?
                    .and_then(|l| l.name().map(|s| s.to_string()))
                    .ok_or_else(|| Error::InterfaceNotFound {
                        name: format!("ifindex {}", idx),
                    })
            }
        }
    }

    // ========================================================================
    // Convenience methods that accept InterfaceRef
    // ========================================================================

    /// Get device information.
    ///
    /// Accepts either an interface name or index via [`InterfaceRef`].
    ///
    /// # Example
    ///
    /// ```ignore
    /// use nlink::netlink::{Connection, Wireguard};
    ///
    /// let conn = Connection::<Wireguard>::new_async().await?;
    ///
    /// // By name
    /// let device = conn.get_device("wg0").await?;
    ///
    /// // By index
    /// let device = conn.get_device(5u32).await?;
    /// ```
    pub async fn get_device(&self, iface: impl Into<InterfaceRef>) -> Result<WgDevice> {
        let ifname = self.resolve_interface_name(&iface.into()).await?;
        self.get_device_by_name(&ifname).await
    }

    /// Set device configuration.
    ///
    /// Accepts either an interface name or index via [`InterfaceRef`].
    ///
    /// # Example
    ///
    /// ```ignore
    /// conn.set_device("wg0", |dev| {
    ///     dev.private_key(my_key)
    ///        .listen_port(51820)
    /// }).await?;
    /// ```
    pub async fn set_device(
        &self,
        iface: impl Into<InterfaceRef>,
        configure: impl FnOnce(WgDeviceBuilder) -> WgDeviceBuilder,
    ) -> Result<()> {
        let ifname = self.resolve_interface_name(&iface.into()).await?;
        self.set_device_by_name(&ifname, configure).await
    }

    /// Add or update a peer.
    ///
    /// Accepts either an interface name or index via [`InterfaceRef`].
    pub async fn set_peer(
        &self,
        iface: impl Into<InterfaceRef>,
        public_key: [u8; WG_KEY_LEN],
        configure: impl FnOnce(super::types::WgPeerBuilder) -> super::types::WgPeerBuilder,
    ) -> Result<()> {
        let ifname = self.resolve_interface_name(&iface.into()).await?;
        self.set_peer_by_name(&ifname, public_key, configure).await
    }

    /// Remove a peer by public key.
    ///
    /// Accepts either an interface name or index via [`InterfaceRef`].
    pub async fn remove_peer(
        &self,
        iface: impl Into<InterfaceRef>,
        public_key: [u8; WG_KEY_LEN],
    ) -> Result<()> {
        let ifname = self.resolve_interface_name(&iface.into()).await?;
        self.remove_peer_by_name(&ifname, public_key).await
    }

    // ========================================================================
    // Name-based methods (used internally and for efficiency)
    // ========================================================================

    /// Get device information by interface name.
    ///
    /// Returns the current configuration and status of the WireGuard interface.
    pub async fn get_device_by_name(&self, ifname: &str) -> Result<WgDevice> {
        let responses = self
            .dump_wg_command(WgCmd::GetDevice as u8, |builder| {
                builder.append_attr_str(WgDeviceAttr::Ifname as u16, ifname);
            })
            .await?;

        if responses.is_empty() {
            return Err(Error::InterfaceNotFound {
                name: ifname.to_string(),
            });
        }

        // Parse the response(s) - may be split across multiple messages for large peer lists
        let mut device = WgDevice::new();

        for response in &responses {
            if response.len() < GENL_HDRLEN {
                continue;
            }

            let attrs_data = &response[GENL_HDRLEN..];
            self.parse_device_attrs(attrs_data, &mut device)?;
        }

        Ok(device)
    }

    /// Set device configuration by interface name.
    pub async fn set_device_by_name(
        &self,
        ifname: &str,
        configure: impl FnOnce(WgDeviceBuilder) -> WgDeviceBuilder,
    ) -> Result<()> {
        let builder = configure(WgDeviceBuilder::new());
        self.apply_device_config(ifname, &builder).await
    }

    /// Add or update a peer by interface name.
    pub async fn set_peer_by_name(
        &self,
        ifname: &str,
        public_key: [u8; WG_KEY_LEN],
        configure: impl FnOnce(super::types::WgPeerBuilder) -> super::types::WgPeerBuilder,
    ) -> Result<()> {
        let peer_builder = configure(super::types::WgPeerBuilder::new(public_key));
        let device_builder = WgDeviceBuilder::new().peer(peer_builder);
        self.apply_device_config(ifname, &device_builder).await
    }

    /// Remove a peer by public key using interface name.
    pub async fn remove_peer_by_name(
        &self,
        ifname: &str,
        public_key: [u8; WG_KEY_LEN],
    ) -> Result<()> {
        let peer_builder = super::types::WgPeerBuilder::new(public_key).remove();
        let device_builder = WgDeviceBuilder::new().peer(peer_builder);
        self.apply_device_config(ifname, &device_builder).await
    }

    /// Apply device configuration to the kernel.
    async fn apply_device_config(&self, ifname: &str, config: &WgDeviceBuilder) -> Result<()> {
        self.wg_command(WgCmd::SetDevice as u8, |builder| {
            // Device name
            builder.append_attr_str(WgDeviceAttr::Ifname as u16, ifname);

            // Device flags
            if config.has_replace_peers() {
                builder.append_attr_u32(
                    WgDeviceAttr::Flags as u16,
                    WgDeviceFlag::ReplacePeers as u32,
                );
            }

            // Private key
            if let Some(key) = config.get_private_key() {
                builder.append_attr(WgDeviceAttr::PrivateKey as u16, key);
            }

            // Listen port
            if let Some(port) = config.get_listen_port() {
                builder.append_attr_u16(WgDeviceAttr::ListenPort as u16, port);
            }

            // Fwmark
            if let Some(mark) = config.get_fwmark() {
                builder.append_attr_u32(WgDeviceAttr::Fwmark as u16, mark);
            }

            // Peers
            if !config.get_peers().is_empty() {
                let peers_token = builder.nest_start(WgDeviceAttr::Peers as u16 | NLA_F_NESTED);
                for (idx, peer) in config.get_peers().iter().enumerate() {
                    append_peer_attrs(builder, idx as u16, peer);
                }
                builder.nest_end(peers_token);
            }
        })
        .await?;

        Ok(())
    }

    /// Send a WireGuard GENL command and wait for ACK.
    async fn wg_command(
        &self,
        cmd: u8,
        build_attrs: impl FnOnce(&mut MessageBuilder),
    ) -> Result<Vec<u8>> {
        let family_id = self.state().family_id;

        let mut builder = MessageBuilder::new(family_id, NLM_F_REQUEST | NLM_F_ACK);

        // Append GENL header
        let genl_hdr = GenlMsgHdr::new(cmd, WG_GENL_VERSION);
        builder.append(&genl_hdr);

        // Let caller append attributes
        build_attrs(&mut builder);

        // Send request
        let seq = self.socket().next_seq();
        builder.set_seq(seq);
        builder.set_pid(self.socket().pid());

        let msg = builder.finish();
        self.socket().send(&msg).await?;

        // Receive response
        let response: Vec<u8> = self.socket().recv_msg().await?;
        self.process_genl_response(&response, seq)?;

        Ok(response)
    }

    /// Send a WireGuard GENL dump command and collect all responses.
    async fn dump_wg_command(
        &self,
        cmd: u8,
        build_attrs: impl FnOnce(&mut MessageBuilder),
    ) -> Result<Vec<Vec<u8>>> {
        let family_id = self.state().family_id;

        let mut builder = MessageBuilder::new(family_id, NLM_F_REQUEST | NLM_F_DUMP);

        // Append GENL header
        let genl_hdr = GenlMsgHdr::new(cmd, WG_GENL_VERSION);
        builder.append(&genl_hdr);

        // Let caller append attributes
        build_attrs(&mut builder);

        // Send request
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

    /// Parse device attributes from a GENL response.
    fn parse_device_attrs(&self, data: &[u8], device: &mut WgDevice) -> Result<()> {
        for (attr_type, payload) in AttrIter::new(data) {
            match attr_type {
                t if t == WgDeviceAttr::Ifindex as u16 => {
                    device.ifindex = Some(get::u32_ne(payload)?);
                }
                t if t == WgDeviceAttr::Ifname as u16 => {
                    device.ifname = Some(get::string(payload)?.to_string());
                }
                t if t == WgDeviceAttr::PublicKey as u16 => {
                    if payload.len() >= WG_KEY_LEN {
                        let mut key = [0u8; WG_KEY_LEN];
                        key.copy_from_slice(&payload[..WG_KEY_LEN]);
                        device.public_key = Some(key);
                    }
                }
                t if t == WgDeviceAttr::ListenPort as u16 => {
                    device.listen_port = Some(get::u16_ne(payload)?);
                }
                t if t == WgDeviceAttr::Fwmark as u16 => {
                    device.fwmark = Some(get::u32_ne(payload)?);
                }
                t if t == WgDeviceAttr::Peers as u16 => {
                    self.parse_peers_attr(payload, &mut device.peers)?;
                }
                _ => {}
            }
        }
        Ok(())
    }

    /// Parse the peers nested attribute.
    fn parse_peers_attr(&self, data: &[u8], peers: &mut Vec<WgPeer>) -> Result<()> {
        for (_idx, peer_data) in AttrIter::new(data) {
            let peer = self.parse_peer_attrs(peer_data)?;
            peers.push(peer);
        }
        Ok(())
    }

    /// Parse a single peer's attributes.
    fn parse_peer_attrs(&self, data: &[u8]) -> Result<WgPeer> {
        let mut peer = WgPeer::default();

        for (attr_type, payload) in AttrIter::new(data) {
            match attr_type {
                t if t == WgPeerAttr::PublicKey as u16 => {
                    if payload.len() >= WG_KEY_LEN {
                        peer.public_key.copy_from_slice(&payload[..WG_KEY_LEN]);
                    }
                }
                t if t == WgPeerAttr::PresharedKey as u16 => {
                    if payload.len() >= WG_KEY_LEN {
                        let mut key = [0u8; WG_KEY_LEN];
                        key.copy_from_slice(&payload[..WG_KEY_LEN]);
                        // Only set if not all zeros (kernel returns zeros if not set)
                        if key.iter().any(|&b| b != 0) {
                            peer.preshared_key = Some(key);
                        }
                    }
                }
                t if t == WgPeerAttr::Endpoint as u16 => {
                    peer.endpoint = parse_sockaddr(payload);
                }
                t if t == WgPeerAttr::PersistentKeepalive as u16 => {
                    peer.persistent_keepalive = Some(get::u16_ne(payload)?);
                }
                t if t == WgPeerAttr::LastHandshake as u16 => {
                    peer.last_handshake = parse_timespec(payload);
                }
                t if t == WgPeerAttr::RxBytes as u16 => {
                    peer.rx_bytes = get::u64_ne(payload)?;
                }
                t if t == WgPeerAttr::TxBytes as u16 => {
                    peer.tx_bytes = get::u64_ne(payload)?;
                }
                t if t == WgPeerAttr::AllowedIps as u16 => {
                    self.parse_allowed_ips_attr(payload, &mut peer.allowed_ips)?;
                }
                t if t == WgPeerAttr::ProtocolVersion as u16 => {
                    peer.protocol_version = Some(get::u32_ne(payload)?);
                }
                _ => {}
            }
        }

        Ok(peer)
    }

    /// Parse allowed IPs nested attribute.
    fn parse_allowed_ips_attr(&self, data: &[u8], allowed_ips: &mut Vec<AllowedIp>) -> Result<()> {
        for (_idx, ip_data) in AttrIter::new(data) {
            if let Some(ip) = parse_allowed_ip_attrs(ip_data)? {
                allowed_ips.push(ip);
            }
        }
        Ok(())
    }
}

/// Resolve the WireGuard GENL family ID.
async fn resolve_wireguard_family(socket: &NetlinkSocket) -> Result<u16> {
    // Build CTRL_CMD_GETFAMILY request
    let mut builder = MessageBuilder::new(GENL_ID_CTRL, NLM_F_REQUEST | NLM_F_ACK);

    // Append GENL header
    let genl_hdr = GenlMsgHdr::new(CtrlCmd::GetFamily as u8, 1);
    builder.append(&genl_hdr);

    // Append family name attribute
    builder.append_attr_str(CtrlAttr::FamilyName as u16, WG_GENL_NAME);

    // Send request
    let seq = socket.next_seq();
    builder.set_seq(seq);
    builder.set_pid(socket.pid());

    let msg = builder.finish();
    socket.send(&msg).await?;

    // Receive response
    let response: Vec<u8> = socket.recv_msg().await?;

    // Parse response
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
                        name: WG_GENL_NAME.to_string(),
                    });
                }
                return Err(Error::from_errno(err.error));
            }
            continue;
        }

        if header.is_done() {
            continue;
        }

        // Parse GENL header
        if payload.len() < GENL_HDRLEN {
            return Err(Error::InvalidMessage("GENL header too short".into()));
        }

        // Parse attributes after GENL header
        let attrs_data = &payload[GENL_HDRLEN..];
        for (attr_type, attr_payload) in AttrIter::new(attrs_data) {
            if attr_type == CtrlAttr::FamilyId as u16 {
                return get::u16_ne(attr_payload);
            }
        }
    }

    Err(Error::FamilyNotFound {
        name: WG_GENL_NAME.to_string(),
    })
}

/// Append peer attributes to a message builder.
fn append_peer_attrs(builder: &mut MessageBuilder, idx: u16, peer: &super::types::WgPeerBuilder) {
    let peer_token = builder.nest_start(idx | NLA_F_NESTED);

    // Public key (required)
    builder.append_attr(WgPeerAttr::PublicKey as u16, peer.get_public_key());

    // Flags
    let flags = peer.get_flags();
    if flags != 0 {
        builder.append_attr_u32(WgPeerAttr::Flags as u16, flags);
    }

    // Preshared key
    if let Some(psk) = peer.get_preshared_key() {
        builder.append_attr(WgPeerAttr::PresharedKey as u16, psk);
    }

    // Endpoint
    if let Some(endpoint) = peer.get_endpoint() {
        let sockaddr_bytes = sockaddr_to_bytes(endpoint);
        builder.append_attr(WgPeerAttr::Endpoint as u16, &sockaddr_bytes);
    }

    // Persistent keepalive
    if let Some(interval) = peer.get_persistent_keepalive() {
        builder.append_attr_u16(WgPeerAttr::PersistentKeepalive as u16, interval);
    }

    // Allowed IPs
    let allowed_ips = peer.get_allowed_ips();
    if !allowed_ips.is_empty() {
        let ips_token = builder.nest_start(WgPeerAttr::AllowedIps as u16 | NLA_F_NESTED);
        for (ip_idx, allowed_ip) in allowed_ips.iter().enumerate() {
            let ip_token = builder.nest_start(ip_idx as u16 | NLA_F_NESTED);
            builder.append_attr_u16(WgAllowedIpAttr::Family as u16, allowed_ip.family());
            builder.append_attr(WgAllowedIpAttr::IpAddr as u16, &allowed_ip.addr_bytes());
            builder.append_attr_u8(WgAllowedIpAttr::CidrMask as u16, allowed_ip.cidr);
            builder.nest_end(ip_token);
        }
        builder.nest_end(ips_token);
    }

    builder.nest_end(peer_token);
}

/// Parse a single allowed IP's attributes.
fn parse_allowed_ip_attrs(data: &[u8]) -> Result<Option<AllowedIp>> {
    let mut family: Option<u16> = None;
    let mut addr_bytes: Option<&[u8]> = None;
    let mut cidr: Option<u8> = None;

    for (attr_type, payload) in AttrIter::new(data) {
        match attr_type {
            t if t == WgAllowedIpAttr::Family as u16 => {
                family = Some(get::u16_ne(payload)?);
            }
            t if t == WgAllowedIpAttr::IpAddr as u16 => {
                addr_bytes = Some(payload);
            }
            t if t == WgAllowedIpAttr::CidrMask as u16 => {
                cidr = Some(get::u8(payload)?);
            }
            _ => {}
        }
    }

    let (family, addr_bytes, cidr) = match (family, addr_bytes, cidr) {
        (Some(f), Some(a), Some(c)) => (f, a, c),
        _ => return Ok(None),
    };

    let addr = match family as i32 {
        libc::AF_INET if addr_bytes.len() >= 4 => IpAddr::V4(std::net::Ipv4Addr::new(
            addr_bytes[0],
            addr_bytes[1],
            addr_bytes[2],
            addr_bytes[3],
        )),
        libc::AF_INET6 if addr_bytes.len() >= 16 => {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&addr_bytes[..16]);
            IpAddr::V6(std::net::Ipv6Addr::from(octets))
        }
        _ => return Ok(None),
    };

    Ok(Some(AllowedIp { addr, cidr }))
}

/// Convert a SocketAddr to kernel sockaddr bytes.
fn sockaddr_to_bytes(addr: &SocketAddr) -> Vec<u8> {
    match addr {
        SocketAddr::V4(v4) => {
            // struct sockaddr_in: family (2), port (2), addr (4), zero (8)
            let mut buf = vec![0u8; 16];
            buf[0..2].copy_from_slice(&(libc::AF_INET as u16).to_ne_bytes());
            buf[2..4].copy_from_slice(&v4.port().to_be_bytes());
            buf[4..8].copy_from_slice(&v4.ip().octets());
            buf
        }
        SocketAddr::V6(v6) => {
            // struct sockaddr_in6: family (2), port (2), flowinfo (4), addr (16), scope_id (4)
            let mut buf = vec![0u8; 28];
            buf[0..2].copy_from_slice(&(libc::AF_INET6 as u16).to_ne_bytes());
            buf[2..4].copy_from_slice(&v6.port().to_be_bytes());
            buf[4..8].copy_from_slice(&v6.flowinfo().to_ne_bytes());
            buf[8..24].copy_from_slice(&v6.ip().octets());
            buf[24..28].copy_from_slice(&v6.scope_id().to_ne_bytes());
            buf
        }
    }
}

/// Parse kernel sockaddr bytes to a SocketAddr.
fn parse_sockaddr(data: &[u8]) -> Option<SocketAddr> {
    if data.len() < 4 {
        return None;
    }

    let family = u16::from_ne_bytes([data[0], data[1]]);
    let port = u16::from_be_bytes([data[2], data[3]]);

    match family as i32 {
        libc::AF_INET if data.len() >= 8 => {
            let ip = std::net::Ipv4Addr::new(data[4], data[5], data[6], data[7]);
            Some(SocketAddr::V4(SocketAddrV4::new(ip, port)))
        }
        libc::AF_INET6 if data.len() >= 24 => {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&data[8..24]);
            let ip = std::net::Ipv6Addr::from(octets);
            let scope_id = if data.len() >= 28 {
                u32::from_ne_bytes([data[24], data[25], data[26], data[27]])
            } else {
                0
            };
            Some(SocketAddr::V6(SocketAddrV6::new(ip, port, 0, scope_id)))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_sockaddr_v4_roundtrip() {
        let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 1), 51820));
        let bytes = sockaddr_to_bytes(&addr);
        let parsed = parse_sockaddr(&bytes).unwrap();
        assert_eq!(addr, parsed);
    }

    #[test]
    fn test_sockaddr_v6_roundtrip() {
        let addr = SocketAddr::V6(SocketAddrV6::new(
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
            51820,
            0,
            0,
        ));
        let bytes = sockaddr_to_bytes(&addr);
        let parsed = parse_sockaddr(&bytes).unwrap();
        assert_eq!(addr, parsed);
    }
}
