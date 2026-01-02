//! Strongly-typed link message.

use winnow::binary::le_u16;
use winnow::prelude::*;
use winnow::token::take;

use crate::netlink::error::Result;
use crate::netlink::parse::{FromNetlink, PResult, ToNetlink, parse_string_from_bytes};
use crate::netlink::types::link::{IfInfoMsg, LinkStats64, OperState};

/// Attribute IDs for IFLA_* constants.
mod attr_ids {
    pub const IFLA_ADDRESS: u16 = 1;
    pub const IFLA_BROADCAST: u16 = 2;
    pub const IFLA_IFNAME: u16 = 3;
    pub const IFLA_MTU: u16 = 4;
    pub const IFLA_LINK: u16 = 5;
    pub const IFLA_QDISC: u16 = 6;
    pub const IFLA_MASTER: u16 = 10;
    pub const IFLA_TXQLEN: u16 = 13;
    pub const IFLA_OPERSTATE: u16 = 16;
    pub const IFLA_LINKINFO: u16 = 18;
    pub const IFLA_STATS64: u16 = 23;
    pub const IFLA_GROUP: u16 = 27;
    pub const IFLA_PROMISCUITY: u16 = 30;
    pub const IFLA_NUM_TX_QUEUES: u16 = 31;
    pub const IFLA_NUM_RX_QUEUES: u16 = 32;
    pub const IFLA_CARRIER: u16 = 33;
    pub const IFLA_MIN_MTU: u16 = 50;
    pub const IFLA_MAX_MTU: u16 = 51;
    pub const IFLA_PERM_ADDRESS: u16 = 54;
}

/// Nested IFLA_INFO_* attribute IDs.
mod info_ids {
    pub const IFLA_INFO_KIND: u16 = 1;
    pub const IFLA_INFO_DATA: u16 = 2;
    pub const IFLA_INFO_SLAVE_KIND: u16 = 4;
    pub const IFLA_INFO_SLAVE_DATA: u16 = 5;
}

/// Strongly-typed link message with all attributes parsed.
#[derive(Debug, Clone, Default)]
pub struct LinkMessage {
    /// Fixed-size header.
    pub header: IfInfoMsg,
    /// Interface name (IFLA_IFNAME).
    pub name: Option<String>,
    /// Hardware address (IFLA_ADDRESS).
    pub address: Option<Vec<u8>>,
    /// Broadcast address (IFLA_BROADCAST).
    pub broadcast: Option<Vec<u8>>,
    /// Permanent hardware address (IFLA_PERM_ADDRESS).
    pub perm_address: Option<Vec<u8>>,
    /// MTU (IFLA_MTU).
    pub mtu: Option<u32>,
    /// Minimum MTU (IFLA_MIN_MTU).
    pub min_mtu: Option<u32>,
    /// Maximum MTU (IFLA_MAX_MTU).
    pub max_mtu: Option<u32>,
    /// Link index for stacked devices (IFLA_LINK).
    pub link: Option<u32>,
    /// Qdisc name (IFLA_QDISC).
    pub qdisc: Option<String>,
    /// Master device index (IFLA_MASTER).
    pub master: Option<u32>,
    /// Transmit queue length (IFLA_TXQLEN).
    pub txqlen: Option<u32>,
    /// Operational state (IFLA_OPERSTATE).
    pub operstate: Option<OperState>,
    /// Group (IFLA_GROUP).
    pub group: Option<u32>,
    /// Promiscuity count (IFLA_PROMISCUITY).
    pub promiscuity: Option<u32>,
    /// Number of TX queues (IFLA_NUM_TX_QUEUES).
    pub num_tx_queues: Option<u32>,
    /// Number of RX queues (IFLA_NUM_RX_QUEUES).
    pub num_rx_queues: Option<u32>,
    /// Carrier state (IFLA_CARRIER).
    pub carrier: Option<bool>,
    /// Link info (IFLA_LINKINFO).
    pub link_info: Option<LinkInfo>,
    /// Statistics (IFLA_STATS64).
    pub stats: Option<LinkStats>,
}

/// Link type information from IFLA_LINKINFO.
#[derive(Debug, Clone, Default)]
pub struct LinkInfo {
    /// Link type kind (e.g., "vlan", "bridge", "bond").
    pub kind: Option<String>,
    /// Slave kind for bonded interfaces.
    pub slave_kind: Option<String>,
    /// Raw type-specific data.
    pub data: Option<Vec<u8>>,
    /// Raw slave-specific data.
    pub slave_data: Option<Vec<u8>>,
}

/// Link statistics.
#[derive(Debug, Clone, Copy, Default)]
pub struct LinkStats {
    pub rx_packets: u64,
    pub tx_packets: u64,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_errors: u64,
    pub tx_errors: u64,
    pub rx_dropped: u64,
    pub tx_dropped: u64,
    pub multicast: u64,
    pub collisions: u64,
}

impl LinkMessage {
    /// Create a new empty link message.
    pub fn new() -> Self {
        Self::default()
    }

    /// Get the interface index.
    ///
    /// Returns the index as `u32` since interface indices are always non-negative.
    pub fn ifindex(&self) -> u32 {
        self.header.ifi_index as u32
    }

    /// Get the interface name, or a default placeholder.
    ///
    /// Returns the interface name if available, otherwise returns the provided default.
    /// This is a convenience method to avoid repeated `.name.as_deref().unwrap_or("?")`.
    ///
    /// # Example
    ///
    /// ```ignore
    /// for link in conn.get_links().await? {
    ///     println!("{}: {}", link.ifindex(), link.name_or("?"));
    /// }
    /// ```
    pub fn name_or<'a>(&'a self, default: &'a str) -> &'a str {
        self.name.as_deref().unwrap_or(default)
    }

    /// Get the interface flags.
    pub fn flags(&self) -> u32 {
        self.header.ifi_flags
    }

    /// Check if the interface is up.
    pub fn is_up(&self) -> bool {
        self.header.ifi_flags & 0x1 != 0 // IFF_UP
    }

    /// Check if the interface is running (lower layer up).
    pub fn is_running(&self) -> bool {
        self.header.ifi_flags & 0x40 != 0 // IFF_RUNNING
    }

    /// Check if the interface is a loopback.
    pub fn is_loopback(&self) -> bool {
        self.header.ifi_flags & 0x8 != 0 // IFF_LOOPBACK
    }

    /// Check if the interface supports broadcast.
    pub fn is_broadcast(&self) -> bool {
        self.header.ifi_flags & 0x2 != 0 // IFF_BROADCAST
    }

    /// Check if the interface is point-to-point.
    pub fn is_pointopoint(&self) -> bool {
        self.header.ifi_flags & 0x10 != 0 // IFF_POINTOPOINT
    }

    /// Check if the carrier is present.
    pub fn has_carrier(&self) -> bool {
        self.carrier.unwrap_or(false)
    }

    /// Get the link type kind.
    pub fn kind(&self) -> Option<&str> {
        self.link_info.as_ref()?.kind.as_deref()
    }

    /// Format the hardware address as a MAC string.
    pub fn mac_address(&self) -> Option<String> {
        let addr = self.address.as_ref()?;
        if addr.len() == 6 {
            Some(format!(
                "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]
            ))
        } else {
            None
        }
    }
}

impl FromNetlink for LinkMessage {
    fn write_dump_header(buf: &mut Vec<u8>) {
        // RTM_GETLINK requires an IfInfoMsg header
        let header = IfInfoMsg::new();
        buf.extend_from_slice(header.as_bytes());
    }

    fn parse(input: &mut &[u8]) -> PResult<Self> {
        // Parse fixed header (16 bytes)
        if input.len() < IfInfoMsg::SIZE {
            return Err(winnow::error::ErrMode::Cut(
                winnow::error::ContextError::new(),
            ));
        }

        let header_bytes: &[u8] = take(IfInfoMsg::SIZE).parse_next(input)?;
        let header = *IfInfoMsg::from_bytes(header_bytes)
            .map_err(|_| winnow::error::ErrMode::Cut(winnow::error::ContextError::new()))?;

        let mut msg = LinkMessage {
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

            // Match attribute type (mask out flags)
            match attr_type & 0x3FFF {
                attr_ids::IFLA_IFNAME => {
                    msg.name = Some(parse_string_from_bytes(attr_data));
                }
                attr_ids::IFLA_ADDRESS => {
                    msg.address = Some(attr_data.to_vec());
                }
                attr_ids::IFLA_BROADCAST => {
                    msg.broadcast = Some(attr_data.to_vec());
                }
                attr_ids::IFLA_PERM_ADDRESS => {
                    msg.perm_address = Some(attr_data.to_vec());
                }
                attr_ids::IFLA_MTU => {
                    if attr_data.len() >= 4 {
                        msg.mtu = Some(u32::from_ne_bytes(attr_data[..4].try_into().unwrap()));
                    }
                }
                attr_ids::IFLA_MIN_MTU => {
                    if attr_data.len() >= 4 {
                        msg.min_mtu = Some(u32::from_ne_bytes(attr_data[..4].try_into().unwrap()));
                    }
                }
                attr_ids::IFLA_MAX_MTU => {
                    if attr_data.len() >= 4 {
                        msg.max_mtu = Some(u32::from_ne_bytes(attr_data[..4].try_into().unwrap()));
                    }
                }
                attr_ids::IFLA_LINK => {
                    if attr_data.len() >= 4 {
                        msg.link = Some(u32::from_ne_bytes(attr_data[..4].try_into().unwrap()));
                    }
                }
                attr_ids::IFLA_QDISC => {
                    msg.qdisc = Some(parse_string_from_bytes(attr_data));
                }
                attr_ids::IFLA_MASTER => {
                    if attr_data.len() >= 4 {
                        msg.master = Some(u32::from_ne_bytes(attr_data[..4].try_into().unwrap()));
                    }
                }
                attr_ids::IFLA_TXQLEN => {
                    if attr_data.len() >= 4 {
                        msg.txqlen = Some(u32::from_ne_bytes(attr_data[..4].try_into().unwrap()));
                    }
                }
                attr_ids::IFLA_OPERSTATE => {
                    if !attr_data.is_empty() {
                        msg.operstate = Some(OperState::from(attr_data[0]));
                    }
                }
                attr_ids::IFLA_GROUP => {
                    if attr_data.len() >= 4 {
                        msg.group = Some(u32::from_ne_bytes(attr_data[..4].try_into().unwrap()));
                    }
                }
                attr_ids::IFLA_PROMISCUITY => {
                    if attr_data.len() >= 4 {
                        msg.promiscuity =
                            Some(u32::from_ne_bytes(attr_data[..4].try_into().unwrap()));
                    }
                }
                attr_ids::IFLA_NUM_TX_QUEUES => {
                    if attr_data.len() >= 4 {
                        msg.num_tx_queues =
                            Some(u32::from_ne_bytes(attr_data[..4].try_into().unwrap()));
                    }
                }
                attr_ids::IFLA_NUM_RX_QUEUES => {
                    if attr_data.len() >= 4 {
                        msg.num_rx_queues =
                            Some(u32::from_ne_bytes(attr_data[..4].try_into().unwrap()));
                    }
                }
                attr_ids::IFLA_CARRIER => {
                    if !attr_data.is_empty() {
                        msg.carrier = Some(attr_data[0] != 0);
                    }
                }
                attr_ids::IFLA_LINKINFO => {
                    msg.link_info = Some(parse_link_info(attr_data));
                }
                attr_ids::IFLA_STATS64 => {
                    if let Some(stats) = LinkStats64::from_bytes(attr_data) {
                        msg.stats = Some(LinkStats {
                            rx_packets: stats.rx_packets,
                            tx_packets: stats.tx_packets,
                            rx_bytes: stats.rx_bytes,
                            tx_bytes: stats.tx_bytes,
                            rx_errors: stats.rx_errors,
                            tx_errors: stats.tx_errors,
                            rx_dropped: stats.rx_dropped,
                            tx_dropped: stats.tx_dropped,
                            multicast: stats.multicast,
                            collisions: stats.collisions,
                        });
                    }
                }
                _ => {} // Ignore unknown attributes
            }
        }

        Ok(msg)
    }
}

/// Parse IFLA_LINKINFO nested attributes.
fn parse_link_info(data: &[u8]) -> LinkInfo {
    let mut info = LinkInfo::default();
    let mut input = data;

    while !input.is_empty() && input.len() >= 4 {
        let len = u16::from_ne_bytes(input[..2].try_into().unwrap()) as usize;
        let attr_type = u16::from_ne_bytes(input[2..4].try_into().unwrap());

        if len < 4 || input.len() < len {
            break;
        }

        let payload = &input[4..len];

        match attr_type & 0x3FFF {
            info_ids::IFLA_INFO_KIND => {
                info.kind = Some(parse_string_from_bytes(payload));
            }
            info_ids::IFLA_INFO_DATA => {
                info.data = Some(payload.to_vec());
            }
            info_ids::IFLA_INFO_SLAVE_KIND => {
                info.slave_kind = Some(parse_string_from_bytes(payload));
            }
            info_ids::IFLA_INFO_SLAVE_DATA => {
                info.slave_data = Some(payload.to_vec());
            }
            _ => {}
        }

        let aligned = (len + 3) & !3;
        if input.len() <= aligned {
            break;
        }
        input = &input[aligned..];
    }

    info
}

impl ToNetlink for LinkMessage {
    fn netlink_len(&self) -> usize {
        let mut len = IfInfoMsg::SIZE;

        if let Some(ref name) = self.name {
            len += nla_size(name.len() + 1);
        }
        if let Some(ref addr) = self.address {
            len += nla_size(addr.len());
        }
        if self.mtu.is_some() {
            len += nla_size(4);
        }
        if self.master.is_some() {
            len += nla_size(4);
        }
        if self.txqlen.is_some() {
            len += nla_size(4);
        }

        len
    }

    fn write_to(&self, buf: &mut Vec<u8>) -> Result<usize> {
        let start = buf.len();

        // Write header
        buf.extend_from_slice(self.header.as_bytes());

        // Write attributes
        if let Some(ref name) = self.name {
            write_attr_str(buf, attr_ids::IFLA_IFNAME, name);
        }
        if let Some(ref addr) = self.address {
            write_attr_bytes(buf, attr_ids::IFLA_ADDRESS, addr);
        }
        if let Some(mtu) = self.mtu {
            write_attr_u32(buf, attr_ids::IFLA_MTU, mtu);
        }
        if let Some(master) = self.master {
            write_attr_u32(buf, attr_ids::IFLA_MASTER, master);
        }
        if let Some(txqlen) = self.txqlen {
            write_attr_u32(buf, attr_ids::IFLA_TXQLEN, txqlen);
        }

        Ok(buf.len() - start)
    }
}

/// Calculate aligned attribute size.
fn nla_size(payload_len: usize) -> usize {
    (4 + payload_len + 3) & !3
}

fn write_attr_u32(buf: &mut Vec<u8>, attr_type: u16, value: u32) {
    let len: u16 = 8;
    buf.extend_from_slice(&len.to_ne_bytes());
    buf.extend_from_slice(&attr_type.to_ne_bytes());
    buf.extend_from_slice(&value.to_ne_bytes());
}

fn write_attr_str(buf: &mut Vec<u8>, attr_type: u16, value: &str) {
    let payload_len = value.len() + 1;
    let len = 4 + payload_len;
    buf.extend_from_slice(&(len as u16).to_ne_bytes());
    buf.extend_from_slice(&attr_type.to_ne_bytes());
    buf.extend_from_slice(value.as_bytes());
    buf.push(0);
    // Padding
    let aligned = (len + 3) & !3;
    for _ in 0..(aligned - len) {
        buf.push(0);
    }
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

/// Builder for constructing LinkMessage.
#[derive(Debug, Clone, Default)]
pub struct LinkMessageBuilder {
    msg: LinkMessage,
}

impl LinkMessageBuilder {
    /// Create a new builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the interface index.
    pub fn ifindex(mut self, index: i32) -> Self {
        self.msg.header.ifi_index = index;
        self
    }

    /// Set the interface flags.
    pub fn flags(mut self, flags: u32) -> Self {
        self.msg.header.ifi_flags = flags;
        self
    }

    /// Set the change mask.
    pub fn change(mut self, change: u32) -> Self {
        self.msg.header.ifi_change = change;
        self
    }

    /// Set the interface name.
    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.msg.name = Some(name.into());
        self
    }

    /// Set the MTU.
    pub fn mtu(mut self, mtu: u32) -> Self {
        self.msg.mtu = Some(mtu);
        self
    }

    /// Set the hardware address.
    pub fn address(mut self, addr: Vec<u8>) -> Self {
        self.msg.address = Some(addr);
        self
    }

    /// Set the master device index.
    pub fn master(mut self, master: u32) -> Self {
        self.msg.master = Some(master);
        self
    }

    /// Set the TX queue length.
    pub fn txqlen(mut self, txqlen: u32) -> Self {
        self.msg.txqlen = Some(txqlen);
        self
    }

    /// Build the message.
    pub fn build(self) -> LinkMessage {
        self.msg
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_builder() {
        let msg = LinkMessageBuilder::new()
            .ifindex(1)
            .name("eth0")
            .mtu(1500)
            .build();

        assert_eq!(msg.ifindex(), 1);
        assert_eq!(msg.name, Some("eth0".to_string()));
        assert_eq!(msg.mtu, Some(1500));
    }
}
