//! Strongly-typed traffic control messages.

use winnow::binary::le_u16;
use winnow::prelude::*;
use winnow::token::take;

use crate::netlink::parse::{FromNetlink, PResult, parse_string_from_bytes};
use crate::netlink::types::tc::TcMsg;

/// Attribute IDs for TCA_* constants.
mod attr_ids {
    pub const TCA_KIND: u16 = 1;
    pub const TCA_OPTIONS: u16 = 2;
    pub const TCA_STATS: u16 = 3;
    pub const TCA_XSTATS: u16 = 4;
    pub const TCA_STATS2: u16 = 7;
    pub const TCA_CHAIN: u16 = 11;
    pub const TCA_HW_OFFLOAD: u16 = 12;
    pub const TCA_INGRESS_BLOCK: u16 = 13;
    pub const TCA_EGRESS_BLOCK: u16 = 14;
}

/// Nested TCA_STATS2 attribute IDs.
mod stats2_ids {
    pub const TCA_STATS_BASIC: u16 = 1;
    pub const TCA_STATS_RATE_EST: u16 = 2;
    pub const TCA_STATS_QUEUE: u16 = 3;
    pub const TCA_STATS_APP: u16 = 4;
    pub const TCA_STATS_BASIC_HW: u16 = 7;
    pub const TCA_STATS_PKT64: u16 = 8;
}

/// Strongly-typed traffic control message.
///
/// This struct represents a qdisc, class, or filter message from the kernel.
/// The specific type is determined by the netlink message type (RTM_NEWQDISC,
/// RTM_NEWTCLASS, RTM_NEWTFILTER).
#[derive(Debug, Clone, Default)]
pub struct TcMessage {
    /// Fixed-size header (struct tcmsg).
    pub header: TcMsg,
    /// Qdisc/class/filter type (e.g., "htb", "fq_codel", "u32").
    pub kind: Option<String>,
    /// Raw options data (type-specific, nested attributes).
    pub options: Option<Vec<u8>>,
    /// Chain index for filters.
    pub chain: Option<u32>,
    /// Hardware offload flag.
    pub hw_offload: Option<u8>,
    /// Ingress block index.
    pub ingress_block: Option<u32>,
    /// Egress block index.
    pub egress_block: Option<u32>,
    /// Basic statistics.
    pub stats_basic: Option<TcStatsBasic>,
    /// Queue statistics.
    pub stats_queue: Option<TcStatsQueue>,
    /// Rate estimator.
    pub stats_rate_est: Option<TcStatsRateEst>,
    /// Extended statistics (type-specific).
    pub xstats: Option<Vec<u8>>,
}

/// Basic traffic control statistics (from TCA_STATS2/TCA_STATS_BASIC).
#[derive(Debug, Clone, Copy, Default)]
pub struct TcStatsBasic {
    /// Bytes transmitted.
    pub bytes: u64,
    /// Packets transmitted.
    pub packets: u64,
}

impl TcStatsBasic {
    /// Calculate the delta (difference) from a previous sample.
    ///
    /// Uses saturating subtraction to handle counter wraps gracefully.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let prev = qdisc.stats_basic.unwrap();
    /// // ... wait some time ...
    /// let curr = qdisc.stats_basic.unwrap();
    /// let delta = curr.delta(&prev);
    /// println!("Transferred {} bytes, {} packets", delta.bytes, delta.packets);
    /// ```
    pub fn delta(&self, previous: &Self) -> TcStatsBasic {
        TcStatsBasic {
            bytes: self.bytes.saturating_sub(previous.bytes),
            packets: self.packets.saturating_sub(previous.packets),
        }
    }
}

/// Queue statistics (from TCA_STATS2/TCA_STATS_QUEUE).
#[derive(Debug, Clone, Copy, Default)]
pub struct TcStatsQueue {
    /// Current queue length in packets.
    pub qlen: u32,
    /// Backlog in bytes.
    pub backlog: u32,
    /// Total drops.
    pub drops: u32,
    /// Requeue count.
    pub requeues: u32,
    /// Overlimit count.
    pub overlimits: u32,
}

impl TcStatsQueue {
    /// Calculate the delta (difference) from a previous sample.
    ///
    /// Note: `qlen` and `backlog` are instantaneous values, not counters,
    /// so they are taken from the current sample directly.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let prev = qdisc.stats_queue.unwrap();
    /// // ... wait some time ...
    /// let curr = qdisc.stats_queue.unwrap();
    /// let delta = curr.delta(&prev);
    /// println!("New drops: {}, new overlimits: {}", delta.drops, delta.overlimits);
    /// ```
    pub fn delta(&self, previous: &Self) -> TcStatsQueue {
        TcStatsQueue {
            qlen: self.qlen,       // Instantaneous, not a counter
            backlog: self.backlog, // Instantaneous, not a counter
            drops: self.drops.saturating_sub(previous.drops),
            requeues: self.requeues.saturating_sub(previous.requeues),
            overlimits: self.overlimits.saturating_sub(previous.overlimits),
        }
    }
}

/// Rate estimator statistics (from TCA_STATS2/TCA_STATS_RATE_EST).
#[derive(Debug, Clone, Copy, Default)]
pub struct TcStatsRateEst {
    /// Bytes per second.
    pub bps: u32,
    /// Packets per second.
    pub pps: u32,
}

impl TcMessage {
    /// Create a new empty TC message.
    pub fn new() -> Self {
        Self::default()
    }

    /// Get the interface index.
    pub fn ifindex(&self) -> i32 {
        self.header.tcm_ifindex
    }

    /// Get the handle (qdisc/class ID).
    pub fn handle(&self) -> u32 {
        self.header.tcm_handle
    }

    /// Get the parent handle.
    pub fn parent(&self) -> u32 {
        self.header.tcm_parent
    }

    /// Get the info field.
    ///
    /// For filters, this contains protocol (upper 16 bits) and priority (lower 16 bits).
    pub fn info(&self) -> u32 {
        self.header.tcm_info
    }

    /// For filters: get the protocol from tcm_info.
    pub fn protocol(&self) -> u16 {
        (self.header.tcm_info >> 16) as u16
    }

    /// For filters: get the priority from tcm_info.
    pub fn priority(&self) -> u16 {
        (self.header.tcm_info & 0xFFFF) as u16
    }

    /// Get the kind (type name) if present.
    pub fn kind(&self) -> Option<&str> {
        self.kind.as_deref()
    }

    /// Get total bytes from basic stats.
    pub fn bytes(&self) -> u64 {
        self.stats_basic.map(|s| s.bytes).unwrap_or(0)
    }

    /// Get total packets from basic stats.
    pub fn packets(&self) -> u64 {
        self.stats_basic.map(|s| s.packets).unwrap_or(0)
    }

    /// Get drops from queue stats.
    pub fn drops(&self) -> u32 {
        self.stats_queue.map(|s| s.drops).unwrap_or(0)
    }

    /// Get overlimits from queue stats.
    pub fn overlimits(&self) -> u32 {
        self.stats_queue.map(|s| s.overlimits).unwrap_or(0)
    }

    /// Get requeues from queue stats.
    pub fn requeues(&self) -> u32 {
        self.stats_queue.map(|s| s.requeues).unwrap_or(0)
    }

    /// Get queue length from queue stats.
    pub fn qlen(&self) -> u32 {
        self.stats_queue.map(|s| s.qlen).unwrap_or(0)
    }

    /// Get backlog from queue stats.
    pub fn backlog(&self) -> u32 {
        self.stats_queue.map(|s| s.backlog).unwrap_or(0)
    }

    /// Get bytes per second from rate estimator.
    ///
    /// Returns 0 if rate estimator statistics are not available.
    pub fn bps(&self) -> u32 {
        self.stats_rate_est.map(|s| s.bps).unwrap_or(0)
    }

    /// Get packets per second from rate estimator.
    ///
    /// Returns 0 if rate estimator statistics are not available.
    pub fn pps(&self) -> u32 {
        self.stats_rate_est.map(|s| s.pps).unwrap_or(0)
    }

    /// Get parsed qdisc options if available.
    ///
    /// This parses the raw options data into a strongly-typed enum
    /// based on the qdisc kind.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use nlink::netlink::tc_options::QdiscOptions;
    ///
    /// let qdiscs = conn.get_qdiscs().await?;
    /// for qdisc in &qdiscs {
    ///     if let Some(QdiscOptions::Netem(netem)) = qdisc.parsed_options() {
    ///         println!("delay={}us, loss={}%", netem.delay_us, netem.loss_percent);
    ///     }
    /// }
    /// ```
    pub fn parsed_options(&self) -> Option<crate::netlink::tc_options::QdiscOptions> {
        crate::netlink::tc_options::parse_qdisc_options(self)
    }

    /// Get netem options if this is a netem qdisc.
    ///
    /// This is a convenience method that returns `Some` only if the qdisc
    /// kind is "netem" and the options can be parsed.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let qdiscs = conn.get_qdiscs().await?;
    /// for qdisc in &qdiscs {
    ///     if let Some(netem) = qdisc.netem_options() {
    ///         println!("delay={}ms, loss={}%", netem.delay_ms(), netem.loss_percent);
    ///     }
    /// }
    /// ```
    pub fn netem_options(&self) -> Option<crate::netlink::tc_options::NetemOptions> {
        match self.parsed_options()? {
            crate::netlink::tc_options::QdiscOptions::Netem(opts) => Some(opts),
            _ => None,
        }
    }

    /// Check if this is a netem qdisc.
    #[inline]
    pub fn is_netem(&self) -> bool {
        self.kind() == Some("netem")
    }

    /// Check if this qdisc is attached to the root.
    #[inline]
    pub fn is_root(&self) -> bool {
        self.header.tcm_parent == crate::netlink::types::tc::tc_handle::ROOT
    }

    /// Check if this is an ingress qdisc.
    #[inline]
    pub fn is_ingress(&self) -> bool {
        self.header.tcm_parent == crate::netlink::types::tc::tc_handle::INGRESS
            || self.kind() == Some("ingress")
    }

    /// Check if this is a clsact qdisc.
    #[inline]
    pub fn is_clsact(&self) -> bool {
        self.header.tcm_parent == crate::netlink::types::tc::tc_handle::CLSACT
            || self.kind() == Some("clsact")
    }
}

impl FromNetlink for TcMessage {
    fn write_dump_header(buf: &mut Vec<u8>) {
        // TC dump requests require a TcMsg header
        let header = TcMsg::new();
        buf.extend_from_slice(header.as_bytes());
    }

    fn parse(input: &mut &[u8]) -> PResult<Self> {
        // Parse fixed header (20 bytes)
        if input.len() < TcMsg::SIZE {
            return Err(winnow::error::ErrMode::Cut(
                winnow::error::ContextError::new(),
            ));
        }

        let header_bytes: &[u8] = take(TcMsg::SIZE).parse_next(input)?;
        let header = *TcMsg::from_bytes(header_bytes)
            .map_err(|_| winnow::error::ErrMode::Cut(winnow::error::ContextError::new()))?;

        let mut msg = TcMessage {
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

            // Match attribute type (mask out NLA_F_NESTED and other flags)
            match attr_type & 0x3FFF {
                attr_ids::TCA_KIND => {
                    msg.kind = Some(parse_string_from_bytes(attr_data));
                }
                attr_ids::TCA_OPTIONS => {
                    msg.options = Some(attr_data.to_vec());
                }
                attr_ids::TCA_XSTATS => {
                    msg.xstats = Some(attr_data.to_vec());
                }
                attr_ids::TCA_CHAIN => {
                    if attr_data.len() >= 4 {
                        msg.chain = Some(u32::from_ne_bytes(attr_data[..4].try_into().unwrap()));
                    }
                }
                attr_ids::TCA_HW_OFFLOAD => {
                    if !attr_data.is_empty() {
                        msg.hw_offload = Some(attr_data[0]);
                    }
                }
                attr_ids::TCA_INGRESS_BLOCK => {
                    if attr_data.len() >= 4 {
                        msg.ingress_block =
                            Some(u32::from_ne_bytes(attr_data[..4].try_into().unwrap()));
                    }
                }
                attr_ids::TCA_EGRESS_BLOCK => {
                    if attr_data.len() >= 4 {
                        msg.egress_block =
                            Some(u32::from_ne_bytes(attr_data[..4].try_into().unwrap()));
                    }
                }
                attr_ids::TCA_STATS2 => {
                    parse_stats2(&mut msg, attr_data);
                }
                attr_ids::TCA_STATS => {
                    // Legacy stats format (struct tc_stats)
                    parse_legacy_stats(&mut msg, attr_data);
                }
                _ => {} // Ignore unknown attributes
            }
        }

        Ok(msg)
    }
}

/// Parse TCA_STATS2 nested attributes.
fn parse_stats2(msg: &mut TcMessage, data: &[u8]) {
    let mut input = data;

    while !input.is_empty() && input.len() >= 4 {
        let len = u16::from_ne_bytes(input[..2].try_into().unwrap()) as usize;
        let attr_type = u16::from_ne_bytes(input[2..4].try_into().unwrap());

        if len < 4 || input.len() < len {
            break;
        }

        let payload = &input[4..len];

        match attr_type & 0x3FFF {
            stats2_ids::TCA_STATS_BASIC | stats2_ids::TCA_STATS_BASIC_HW => {
                // struct gnet_stats_basic: u64 bytes, u32 packets (+ padding)
                if payload.len() >= 12 {
                    let bytes = u64::from_ne_bytes(payload[..8].try_into().unwrap());
                    let packets = u32::from_ne_bytes(payload[8..12].try_into().unwrap());
                    msg.stats_basic = Some(TcStatsBasic {
                        bytes,
                        packets: packets as u64,
                    });
                }
            }
            stats2_ids::TCA_STATS_PKT64 => {
                // 64-bit packet count
                if payload.len() >= 8 {
                    let packets = u64::from_ne_bytes(payload[..8].try_into().unwrap());
                    if let Some(ref mut stats) = msg.stats_basic {
                        stats.packets = packets;
                    } else {
                        msg.stats_basic = Some(TcStatsBasic { bytes: 0, packets });
                    }
                }
            }
            stats2_ids::TCA_STATS_QUEUE => {
                // struct gnet_stats_queue: u32 qlen, backlog, drops, requeues, overlimits
                if payload.len() >= 20 {
                    msg.stats_queue = Some(TcStatsQueue {
                        qlen: u32::from_ne_bytes(payload[0..4].try_into().unwrap()),
                        backlog: u32::from_ne_bytes(payload[4..8].try_into().unwrap()),
                        drops: u32::from_ne_bytes(payload[8..12].try_into().unwrap()),
                        requeues: u32::from_ne_bytes(payload[12..16].try_into().unwrap()),
                        overlimits: u32::from_ne_bytes(payload[16..20].try_into().unwrap()),
                    });
                }
            }
            stats2_ids::TCA_STATS_RATE_EST => {
                // struct gnet_stats_rate_est: u32 bps, pps
                if payload.len() >= 8 {
                    msg.stats_rate_est = Some(TcStatsRateEst {
                        bps: u32::from_ne_bytes(payload[0..4].try_into().unwrap()),
                        pps: u32::from_ne_bytes(payload[4..8].try_into().unwrap()),
                    });
                }
            }
            stats2_ids::TCA_STATS_APP => {
                // Application-specific stats, store in xstats if not already set
                if msg.xstats.is_none() {
                    msg.xstats = Some(payload.to_vec());
                }
            }
            _ => {}
        }

        let aligned = (len + 3) & !3;
        if input.len() <= aligned {
            break;
        }
        input = &input[aligned..];
    }
}

/// Parse legacy TCA_STATS (struct tc_stats).
fn parse_legacy_stats(msg: &mut TcMessage, data: &[u8]) {
    // struct tc_stats {
    //     __u64 bytes;
    //     __u32 packets;
    //     __u32 drops;
    //     __u32 overlimits;
    //     __u32 bps;
    //     __u32 pps;
    //     __u32 qlen;
    //     __u32 backlog;
    // }
    if data.len() >= 36 {
        let bytes = u64::from_ne_bytes(data[0..8].try_into().unwrap());
        let packets = u32::from_ne_bytes(data[8..12].try_into().unwrap());
        let drops = u32::from_ne_bytes(data[12..16].try_into().unwrap());
        let overlimits = u32::from_ne_bytes(data[16..20].try_into().unwrap());
        let bps = u32::from_ne_bytes(data[20..24].try_into().unwrap());
        let pps = u32::from_ne_bytes(data[24..28].try_into().unwrap());
        let qlen = u32::from_ne_bytes(data[28..32].try_into().unwrap());
        let backlog = u32::from_ne_bytes(data[32..36].try_into().unwrap());

        msg.stats_basic = Some(TcStatsBasic {
            bytes,
            packets: packets as u64,
        });
        msg.stats_queue = Some(TcStatsQueue {
            qlen,
            backlog,
            drops,
            requeues: 0,
            overlimits,
        });
        msg.stats_rate_est = Some(TcStatsRateEst { bps, pps });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tc_message_default() {
        let msg = TcMessage::new();
        assert_eq!(msg.ifindex(), 0);
        assert_eq!(msg.handle(), 0);
        assert_eq!(msg.parent(), 0);
        assert!(msg.kind().is_none());
    }

    #[test]
    fn test_filter_protocol_priority() {
        let mut msg = TcMessage::new();
        // tcm_info = (protocol << 16) | priority
        // protocol = 0x0800 (ETH_P_IP), priority = 100
        msg.header.tcm_info = (0x0800 << 16) | 100;

        assert_eq!(msg.protocol(), 0x0800);
        assert_eq!(msg.priority(), 100);
    }
}
