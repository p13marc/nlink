//! Traffic control message types.

use crate::error::{Error, Result};

/// Traffic control message (struct tcmsg).
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct TcMsg {
    /// Address family.
    pub tcm_family: u8,
    /// Padding.
    pub tcm__pad1: u8,
    /// Padding.
    pub tcm__pad2: u16,
    /// Interface index.
    pub tcm_ifindex: i32,
    /// Qdisc handle.
    pub tcm_handle: u32,
    /// Parent qdisc.
    pub tcm_parent: u32,
    /// Info (depends on message type).
    pub tcm_info: u32,
}

impl TcMsg {
    /// Size of this structure.
    pub const SIZE: usize = std::mem::size_of::<Self>();

    /// Create a new TC message.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the interface index.
    pub fn with_ifindex(mut self, ifindex: i32) -> Self {
        self.tcm_ifindex = ifindex;
        self
    }

    /// Set the handle.
    pub fn with_handle(mut self, handle: u32) -> Self {
        self.tcm_handle = handle;
        self
    }

    /// Set the parent.
    pub fn with_parent(mut self, parent: u32) -> Self {
        self.tcm_parent = parent;
        self
    }

    /// Convert to bytes.
    pub fn as_bytes(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self as *const Self as *const u8, Self::SIZE) }
    }

    /// Parse from bytes.
    pub fn from_bytes(data: &[u8]) -> Result<&Self> {
        if data.len() < Self::SIZE {
            return Err(Error::Truncated {
                expected: Self::SIZE,
                actual: data.len(),
            });
        }
        Ok(unsafe { &*(data.as_ptr() as *const Self) })
    }
}

/// Traffic control attributes (TCA_*).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum TcaAttr {
    Unspec = 0,
    Kind = 1,
    Options = 2,
    Stats = 3,
    Xstats = 4,
    Rate = 5,
    Fcnt = 6,
    Stats2 = 7,
    Stab = 8,
    Pad = 9,
    DumpInvisible = 10,
    Chain = 11,
    HwOffload = 12,
    IngressBlock = 13,
    EgressBlock = 14,
    DumpFlags = 15,
    ExtWarnMsg = 16,
}

impl From<u16> for TcaAttr {
    fn from(val: u16) -> Self {
        match val {
            0 => Self::Unspec,
            1 => Self::Kind,
            2 => Self::Options,
            3 => Self::Stats,
            4 => Self::Xstats,
            5 => Self::Rate,
            6 => Self::Fcnt,
            7 => Self::Stats2,
            8 => Self::Stab,
            9 => Self::Pad,
            10 => Self::DumpInvisible,
            11 => Self::Chain,
            12 => Self::HwOffload,
            13 => Self::IngressBlock,
            14 => Self::EgressBlock,
            15 => Self::DumpFlags,
            16 => Self::ExtWarnMsg,
            _ => Self::Unspec,
        }
    }
}

/// Special handle values.
pub mod tc_handle {
    /// Root qdisc.
    pub const ROOT: u32 = 0xFFFFFFFF;
    /// Ingress qdisc.
    pub const INGRESS: u32 = 0xFFFFFFF1;
    /// Clsact qdisc.
    pub const CLSACT: u32 = 0xFFFFFFF2;
    /// Unspecified.
    pub const UNSPEC: u32 = 0;

    /// Make a handle from major:minor.
    pub const fn make(major: u16, minor: u16) -> u32 {
        ((major as u32) << 16) | (minor as u32)
    }

    /// Get the major number from a handle.
    pub const fn major(handle: u32) -> u16 {
        (handle >> 16) as u16
    }

    /// Get the minor number from a handle.
    pub const fn minor(handle: u32) -> u16 {
        (handle & 0xFFFF) as u16
    }

    /// Format a handle as major:minor string.
    pub fn format(handle: u32) -> String {
        if handle == ROOT {
            "root".to_string()
        } else if handle == INGRESS {
            "ingress".to_string()
        } else if handle == CLSACT {
            "clsact".to_string()
        } else if handle == UNSPEC {
            "none".to_string()
        } else {
            let maj = major(handle);
            let min = minor(handle);
            if min == 0 {
                format!("{:x}:", maj)
            } else {
                format!("{:x}:{:x}", maj, min)
            }
        }
    }

    /// Parse a handle from major:minor string.
    pub fn parse(s: &str) -> Option<u32> {
        match s {
            "root" => Some(ROOT),
            "ingress" => Some(INGRESS),
            "clsact" => Some(CLSACT),
            "none" => Some(UNSPEC),
            _ => {
                let parts: Vec<&str> = s.split(':').collect();
                if parts.len() == 2 {
                    let major = u16::from_str_radix(parts[0], 16).ok()?;
                    let minor = if parts[1].is_empty() {
                        0
                    } else {
                        u16::from_str_radix(parts[1], 16).ok()?
                    };
                    Some(make(major, minor))
                } else {
                    None
                }
            }
        }
    }
}

/// TC statistics (struct tc_stats).
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct TcStats {
    /// Bytes seen.
    pub bytes: u64,
    /// Packets seen.
    pub packets: u32,
    /// Packets dropped.
    pub drops: u32,
    /// Packets overlimits.
    pub overlimits: u32,
    /// Current queue length.
    pub bps: u32,
    /// Current packet rate.
    pub pps: u32,
    /// Queue length.
    pub qlen: u32,
    /// Backlog bytes.
    pub backlog: u32,
}

impl TcStats {
    /// Parse from bytes.
    pub fn from_bytes(data: &[u8]) -> Option<&Self> {
        if data.len() >= std::mem::size_of::<Self>() {
            Some(unsafe { &*(data.as_ptr() as *const Self) })
        } else {
            None
        }
    }
}

/// TC statistics 2 (struct gnet_stats_basic).
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct GnetStatsBasic {
    pub bytes: u64,
    pub packets: u32,
}

/// TC queue stats (struct gnet_stats_queue).
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct GnetStatsQueue {
    pub qlen: u32,
    pub backlog: u32,
    pub drops: u32,
    pub requeues: u32,
    pub overlimits: u32,
}

/// TCA_STATS2 nested attributes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum TcaStats {
    Unspec = 0,
    Basic = 1,
    RateEst = 2,
    Queue = 3,
    App = 4,
    RateEst64 = 5,
    Pad = 6,
    BasicHw = 7,
    Pkt64 = 8,
}

impl From<u16> for TcaStats {
    fn from(val: u16) -> Self {
        match val {
            1 => Self::Basic,
            2 => Self::RateEst,
            3 => Self::Queue,
            4 => Self::App,
            5 => Self::RateEst64,
            6 => Self::Pad,
            7 => Self::BasicHw,
            8 => Self::Pkt64,
            _ => Self::Unspec,
        }
    }
}

/// TC rate estimator parameters.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct TcEstimator {
    pub interval: i8,
    pub ewma_log: u8,
}

/// Common qdisc options.
pub mod qdisc {
    /// HTB qdisc-specific attributes.
    pub mod htb {
        pub const TCA_HTB_UNSPEC: u16 = 0;
        pub const TCA_HTB_PARMS: u16 = 1;
        pub const TCA_HTB_INIT: u16 = 2;
        pub const TCA_HTB_CTAB: u16 = 3;
        pub const TCA_HTB_RTAB: u16 = 4;
        pub const TCA_HTB_DIRECT_QLEN: u16 = 5;
        pub const TCA_HTB_RATE64: u16 = 6;
        pub const TCA_HTB_CEIL64: u16 = 7;
        pub const TCA_HTB_OFFLOAD: u16 = 8;
    }

    /// FQ_CODEL qdisc-specific attributes.
    pub mod fq_codel {
        pub const TCA_FQ_CODEL_UNSPEC: u16 = 0;
        pub const TCA_FQ_CODEL_TARGET: u16 = 1;
        pub const TCA_FQ_CODEL_LIMIT: u16 = 2;
        pub const TCA_FQ_CODEL_INTERVAL: u16 = 3;
        pub const TCA_FQ_CODEL_ECN: u16 = 4;
        pub const TCA_FQ_CODEL_FLOWS: u16 = 5;
        pub const TCA_FQ_CODEL_QUANTUM: u16 = 6;
        pub const TCA_FQ_CODEL_CE_THRESHOLD: u16 = 7;
        pub const TCA_FQ_CODEL_DROP_BATCH_SIZE: u16 = 8;
        pub const TCA_FQ_CODEL_MEMORY_LIMIT: u16 = 9;
    }

    /// TBF qdisc-specific attributes.
    pub mod tbf {
        pub const TCA_TBF_UNSPEC: u16 = 0;
        pub const TCA_TBF_PARMS: u16 = 1;
        pub const TCA_TBF_RTAB: u16 = 2;
        pub const TCA_TBF_PTAB: u16 = 3;
        pub const TCA_TBF_RATE64: u16 = 4;
        pub const TCA_TBF_PRATE64: u16 = 5;
        pub const TCA_TBF_BURST: u16 = 6;
        pub const TCA_TBF_PBURST: u16 = 7;
    }

    /// PRIO qdisc-specific attributes.
    pub mod prio {
        pub const TCA_PRIO_UNSPEC: u16 = 0;
        pub const TCA_PRIO_MQ: u16 = 1;
    }
}

/// Common filter attributes.
pub mod filter {
    /// U32 filter attributes.
    pub mod u32 {
        pub const TCA_U32_UNSPEC: u16 = 0;
        pub const TCA_U32_CLASSID: u16 = 1;
        pub const TCA_U32_HASH: u16 = 2;
        pub const TCA_U32_LINK: u16 = 3;
        pub const TCA_U32_DIVISOR: u16 = 4;
        pub const TCA_U32_SEL: u16 = 5;
        pub const TCA_U32_POLICE: u16 = 6;
        pub const TCA_U32_ACT: u16 = 7;
        pub const TCA_U32_INDEV: u16 = 8;
        pub const TCA_U32_PCNT: u16 = 9;
        pub const TCA_U32_MARK: u16 = 10;
        pub const TCA_U32_FLAGS: u16 = 11;
    }

    /// Flower filter attributes.
    pub mod flower {
        pub const TCA_FLOWER_UNSPEC: u16 = 0;
        pub const TCA_FLOWER_CLASSID: u16 = 1;
        pub const TCA_FLOWER_INDEV: u16 = 2;
        pub const TCA_FLOWER_ACT: u16 = 3;
        pub const TCA_FLOWER_KEY_ETH_DST: u16 = 4;
        pub const TCA_FLOWER_KEY_ETH_DST_MASK: u16 = 5;
        pub const TCA_FLOWER_KEY_ETH_SRC: u16 = 6;
        pub const TCA_FLOWER_KEY_ETH_SRC_MASK: u16 = 7;
        pub const TCA_FLOWER_KEY_ETH_TYPE: u16 = 8;
        pub const TCA_FLOWER_KEY_IP_PROTO: u16 = 9;
        pub const TCA_FLOWER_KEY_IPV4_SRC: u16 = 10;
        pub const TCA_FLOWER_KEY_IPV4_SRC_MASK: u16 = 11;
        pub const TCA_FLOWER_KEY_IPV4_DST: u16 = 12;
        pub const TCA_FLOWER_KEY_IPV4_DST_MASK: u16 = 13;
        pub const TCA_FLOWER_KEY_IPV6_SRC: u16 = 14;
        pub const TCA_FLOWER_KEY_IPV6_SRC_MASK: u16 = 15;
        pub const TCA_FLOWER_KEY_IPV6_DST: u16 = 16;
        pub const TCA_FLOWER_KEY_IPV6_DST_MASK: u16 = 17;
        pub const TCA_FLOWER_KEY_TCP_SRC: u16 = 18;
        pub const TCA_FLOWER_KEY_TCP_DST: u16 = 19;
        pub const TCA_FLOWER_KEY_UDP_SRC: u16 = 20;
        pub const TCA_FLOWER_KEY_UDP_DST: u16 = 21;
        pub const TCA_FLOWER_FLAGS: u16 = 22;
    }
}

/// Common action attributes.
pub mod action {
    /// Generic action attributes.
    pub const TCA_ACT_UNSPEC: u16 = 0;
    pub const TCA_ACT_KIND: u16 = 1;
    pub const TCA_ACT_OPTIONS: u16 = 2;
    pub const TCA_ACT_INDEX: u16 = 3;
    pub const TCA_ACT_STATS: u16 = 4;
    pub const TCA_ACT_PAD: u16 = 5;
    pub const TCA_ACT_COOKIE: u16 = 6;
    pub const TCA_ACT_FLAGS: u16 = 7;
    pub const TCA_ACT_HW_STATS: u16 = 8;
    pub const TCA_ACT_USED_HW_STATS: u16 = 9;
    pub const TCA_ACT_IN_HW_COUNT: u16 = 10;

    /// Mirred action attributes.
    pub mod mirred {
        pub const TCA_MIRRED_UNSPEC: u16 = 0;
        pub const TCA_MIRRED_TM: u16 = 1;
        pub const TCA_MIRRED_PARMS: u16 = 2;
    }

    /// Gact action attributes.
    pub mod gact {
        pub const TCA_GACT_UNSPEC: u16 = 0;
        pub const TCA_GACT_TM: u16 = 1;
        pub const TCA_GACT_PARMS: u16 = 2;
        pub const TCA_GACT_PROB: u16 = 3;
    }

    /// Police action attributes.
    pub mod police {
        pub const TCA_POLICE_UNSPEC: u16 = 0;
        pub const TCA_POLICE_TBF: u16 = 1;
        pub const TCA_POLICE_RATE: u16 = 2;
        pub const TCA_POLICE_PEAKRATE: u16 = 3;
        pub const TCA_POLICE_AVRATE: u16 = 4;
        pub const TCA_POLICE_RESULT: u16 = 5;
        pub const TCA_POLICE_TM: u16 = 6;
        pub const TCA_POLICE_PAD: u16 = 7;
        pub const TCA_POLICE_RATE64: u16 = 8;
        pub const TCA_POLICE_PEAKRATE64: u16 = 9;
        pub const TCA_POLICE_PKTRATE64: u16 = 10;
        pub const TCA_POLICE_PKTBURST64: u16 = 11;
    }
}
