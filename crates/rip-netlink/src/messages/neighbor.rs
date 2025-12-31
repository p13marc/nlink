//! Strongly-typed neighbor message.

use std::net::IpAddr;

use winnow::binary::le_u16;
use winnow::prelude::*;
use winnow::token::take;

use crate::error::Result;
use crate::parse::{FromNetlink, PResult, ToNetlink, parse_ip_addr};
use crate::types::neigh::{NdMsg, NdaAttr, NeighborState};

/// Attribute IDs for NDA_* constants.
mod attr_ids {
    pub const NDA_DST: u16 = 1;
    pub const NDA_LLADDR: u16 = 2;
    pub const NDA_CACHEINFO: u16 = 3;
    pub const NDA_PROBES: u16 = 4;
    pub const NDA_VLAN: u16 = 5;
    pub const NDA_PORT: u16 = 6;
    pub const NDA_VNI: u16 = 7;
    pub const NDA_IFINDEX: u16 = 8;
    pub const NDA_MASTER: u16 = 9;
}

/// Strongly-typed neighbor message with all attributes parsed.
#[derive(Debug, Clone, Default)]
pub struct NeighborMessage {
    /// Fixed-size header.
    pub header: NdMsg,
    /// Destination address (NDA_DST).
    pub destination: Option<IpAddr>,
    /// Link-layer address (NDA_LLADDR).
    pub lladdr: Option<Vec<u8>>,
    /// Number of probes (NDA_PROBES).
    pub probes: Option<u32>,
    /// VLAN ID (NDA_VLAN).
    pub vlan: Option<u16>,
    /// Port (NDA_PORT).
    pub port: Option<u16>,
    /// VNI (NDA_VNI).
    pub vni: Option<u32>,
    /// Interface index (NDA_IFINDEX).
    pub ifindex_attr: Option<u32>,
    /// Master device index (NDA_MASTER).
    pub master: Option<u32>,
    /// Cache info.
    pub cache_info: Option<NeighborCacheInfo>,
}

/// Neighbor cache information.
#[derive(Debug, Clone, Copy, Default)]
pub struct NeighborCacheInfo {
    /// Time since confirmed.
    pub confirmed: u32,
    /// Time since used.
    pub used: u32,
    /// Time since updated.
    pub updated: u32,
    /// Reference count.
    pub refcnt: u32,
}

impl NeighborMessage {
    /// Create a new empty neighbor message.
    pub fn new() -> Self {
        Self::default()
    }

    /// Get the address family.
    pub fn family(&self) -> u8 {
        self.header.ndm_family
    }

    /// Check if this is an IPv4 neighbor.
    pub fn is_ipv4(&self) -> bool {
        self.header.ndm_family == libc::AF_INET as u8
    }

    /// Check if this is an IPv6 neighbor.
    pub fn is_ipv6(&self) -> bool {
        self.header.ndm_family == libc::AF_INET6 as u8
    }

    /// Get the interface index.
    pub fn ifindex(&self) -> u32 {
        self.header.ndm_ifindex as u32
    }

    /// Get the neighbor state.
    pub fn state(&self) -> NeighborState {
        NeighborState::from(self.header.ndm_state)
    }

    /// Check if the neighbor is reachable.
    pub fn is_reachable(&self) -> bool {
        self.header.ndm_state & 0x02 != 0 // NUD_REACHABLE
    }

    /// Check if the neighbor is permanent.
    pub fn is_permanent(&self) -> bool {
        self.header.ndm_state & 0x80 != 0 // NUD_PERMANENT
    }

    /// Check if the neighbor is stale.
    pub fn is_stale(&self) -> bool {
        self.header.ndm_state & 0x04 != 0 // NUD_STALE
    }

    /// Check if the neighbor is incomplete.
    pub fn is_incomplete(&self) -> bool {
        self.header.ndm_state & 0x01 != 0 // NUD_INCOMPLETE
    }

    /// Check if the neighbor failed.
    pub fn is_failed(&self) -> bool {
        self.header.ndm_state & 0x20 != 0 // NUD_FAILED
    }

    /// Check if this is a router (for IPv6).
    pub fn is_router(&self) -> bool {
        self.header.ndm_flags & 0x80 != 0 // NTF_ROUTER
    }

    /// Check if this is a proxy entry.
    pub fn is_proxy(&self) -> bool {
        self.header.ndm_flags & 0x08 != 0 // NTF_PROXY
    }

    /// Format the link-layer address as a MAC string.
    pub fn mac_address(&self) -> Option<String> {
        let lladdr = self.lladdr.as_ref()?;
        if lladdr.len() == 6 {
            Some(format!(
                "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                lladdr[0], lladdr[1], lladdr[2], lladdr[3], lladdr[4], lladdr[5]
            ))
        } else {
            None
        }
    }
}

impl FromNetlink for NeighborMessage {
    fn parse(input: &mut &[u8]) -> PResult<Self> {
        // Parse fixed header (12 bytes)
        if input.len() < NdMsg::SIZE {
            return Err(winnow::error::ErrMode::Cut(
                winnow::error::ContextError::new(),
            ));
        }

        let header_bytes: &[u8] = take(NdMsg::SIZE).parse_next(input)?;
        let header = *NdMsg::from_bytes(header_bytes)
            .map_err(|_| winnow::error::ErrMode::Cut(winnow::error::ContextError::new()))?;

        let mut msg = NeighborMessage {
            header,
            ..Default::default()
        };

        // Parse attributes
        while !input.is_empty() && input.len() >= 4 {
            let len = le_u16.parse_next(input)? as usize;
            let attr_type = le_u16.parse_next(input)?;

            if len < 4 {
                break;
            }

            let payload_len = len.saturating_sub(4);
            if input.len() < payload_len {
                break;
            }

            let attr_data: &[u8] = take(payload_len).parse_next(input)?;

            // Align to 4 bytes
            let aligned = (len + 3) & !3;
            let padding = aligned.saturating_sub(len);
            if input.len() >= padding {
                let _: &[u8] = take(padding).parse_next(input)?;
            }

            // Match attribute type
            match attr_type & 0x3FFF {
                attr_ids::NDA_DST => {
                    if let Ok(addr) = parse_ip_addr(attr_data, header.ndm_family) {
                        msg.destination = Some(addr);
                    }
                }
                attr_ids::NDA_LLADDR => {
                    msg.lladdr = Some(attr_data.to_vec());
                }
                attr_ids::NDA_PROBES => {
                    if attr_data.len() >= 4 {
                        msg.probes = Some(u32::from_ne_bytes(attr_data[..4].try_into().unwrap()));
                    }
                }
                attr_ids::NDA_VLAN => {
                    if attr_data.len() >= 2 {
                        msg.vlan = Some(u16::from_ne_bytes(attr_data[..2].try_into().unwrap()));
                    }
                }
                attr_ids::NDA_PORT => {
                    if attr_data.len() >= 2 {
                        msg.port = Some(u16::from_be_bytes(attr_data[..2].try_into().unwrap()));
                    }
                }
                attr_ids::NDA_VNI => {
                    if attr_data.len() >= 4 {
                        msg.vni = Some(u32::from_ne_bytes(attr_data[..4].try_into().unwrap()));
                    }
                }
                attr_ids::NDA_IFINDEX => {
                    if attr_data.len() >= 4 {
                        msg.ifindex_attr =
                            Some(u32::from_ne_bytes(attr_data[..4].try_into().unwrap()));
                    }
                }
                attr_ids::NDA_MASTER => {
                    if attr_data.len() >= 4 {
                        msg.master = Some(u32::from_ne_bytes(attr_data[..4].try_into().unwrap()));
                    }
                }
                attr_ids::NDA_CACHEINFO => {
                    if attr_data.len() >= 16 {
                        msg.cache_info = Some(NeighborCacheInfo {
                            confirmed: u32::from_ne_bytes(attr_data[0..4].try_into().unwrap()),
                            used: u32::from_ne_bytes(attr_data[4..8].try_into().unwrap()),
                            updated: u32::from_ne_bytes(attr_data[8..12].try_into().unwrap()),
                            refcnt: u32::from_ne_bytes(attr_data[12..16].try_into().unwrap()),
                        });
                    }
                }
                _ => {} // Ignore unknown attributes
            }
        }

        Ok(msg)
    }
}

impl ToNetlink for NeighborMessage {
    fn netlink_len(&self) -> usize {
        let mut len = NdMsg::SIZE;

        if self.destination.is_some() {
            len += nla_size(if self.is_ipv4() { 4 } else { 16 });
        }
        if let Some(ref lladdr) = self.lladdr {
            len += nla_size(lladdr.len());
        }
        if self.vlan.is_some() {
            len += nla_size(2);
        }

        len
    }

    fn write_to(&self, buf: &mut Vec<u8>) -> Result<usize> {
        let start = buf.len();

        // Write header
        buf.extend_from_slice(self.header.as_bytes());

        // Write attributes
        if let Some(ref dst) = self.destination {
            write_attr_ip(buf, attr_ids::NDA_DST, dst);
        }
        if let Some(ref lladdr) = self.lladdr {
            write_attr_bytes(buf, attr_ids::NDA_LLADDR, lladdr);
        }
        if let Some(vlan) = self.vlan {
            write_attr_u16(buf, attr_ids::NDA_VLAN, vlan);
        }

        Ok(buf.len() - start)
    }
}

/// Calculate aligned attribute size.
fn nla_size(payload_len: usize) -> usize {
    (4 + payload_len + 3) & !3
}

fn write_attr_u16(buf: &mut Vec<u8>, attr_type: u16, value: u16) {
    let len: u16 = 6;
    buf.extend_from_slice(&len.to_ne_bytes());
    buf.extend_from_slice(&attr_type.to_ne_bytes());
    buf.extend_from_slice(&value.to_ne_bytes());
    buf.push(0); // padding
    buf.push(0);
}

fn write_attr_bytes(buf: &mut Vec<u8>, attr_type: u16, value: &[u8]) {
    let len = 4 + value.len();
    buf.extend_from_slice(&(len as u16).to_ne_bytes());
    buf.extend_from_slice(&attr_type.to_ne_bytes());
    buf.extend_from_slice(value);
    // Padding
    let aligned = (len + 3) & !3;
    for _ in 0..(aligned - len) {
        buf.push(0);
    }
}

fn write_attr_ip(buf: &mut Vec<u8>, attr_type: u16, addr: &IpAddr) {
    let octets = match addr {
        IpAddr::V4(v4) => v4.octets().to_vec(),
        IpAddr::V6(v6) => v6.octets().to_vec(),
    };
    let len = 4 + octets.len();
    buf.extend_from_slice(&(len as u16).to_ne_bytes());
    buf.extend_from_slice(&attr_type.to_ne_bytes());
    buf.extend_from_slice(&octets);
    // Padding
    let aligned = (len + 3) & !3;
    for _ in 0..(aligned - len) {
        buf.push(0);
    }
}

/// Builder for constructing NeighborMessage.
#[derive(Debug, Clone, Default)]
pub struct NeighborMessageBuilder {
    msg: NeighborMessage,
}

impl NeighborMessageBuilder {
    /// Create a new builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the interface index.
    pub fn ifindex(mut self, index: u32) -> Self {
        self.msg.header.ndm_ifindex = index as i32;
        self
    }

    /// Set the destination address.
    pub fn destination(mut self, addr: IpAddr) -> Self {
        match addr {
            IpAddr::V4(_) => self.msg.header.ndm_family = libc::AF_INET as u8,
            IpAddr::V6(_) => self.msg.header.ndm_family = libc::AF_INET6 as u8,
        }
        self.msg.destination = Some(addr);
        self
    }

    /// Set the link-layer address.
    pub fn lladdr(mut self, addr: Vec<u8>) -> Self {
        self.msg.lladdr = Some(addr);
        self
    }

    /// Set the neighbor state.
    pub fn state(mut self, state: NeighborState) -> Self {
        self.msg.header.ndm_state = state as u16;
        self
    }

    /// Set the neighbor flags.
    pub fn flags(mut self, flags: u8) -> Self {
        self.msg.header.ndm_flags = flags;
        self
    }

    /// Mark as permanent.
    pub fn permanent(mut self) -> Self {
        self.msg.header.ndm_state |= 0x80; // NUD_PERMANENT
        self
    }

    /// Set VLAN ID.
    pub fn vlan(mut self, vlan: u16) -> Self {
        self.msg.vlan = Some(vlan);
        self
    }

    /// Build the message.
    pub fn build(self) -> NeighborMessage {
        self.msg
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_builder() {
        let msg = NeighborMessageBuilder::new()
            .ifindex(2)
            .destination(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)))
            .lladdr(vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x55])
            .permanent()
            .build();

        assert_eq!(msg.ifindex(), 2);
        assert!(msg.is_ipv4());
        assert!(msg.is_permanent());
        assert_eq!(msg.mac_address(), Some("00:11:22:33:44:55".to_string()));
    }
}
