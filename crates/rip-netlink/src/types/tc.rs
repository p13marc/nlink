//! Traffic control message types.

use crate::error::{Error, Result};

/// Traffic control message (struct tcmsg).
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct TcMsg {
    /// Address family.
    pub tcm_family: u8,
    /// Padding.
    pub tcm_pad1: u8,
    /// Padding.
    pub tcm_pad2: u16,
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

/// Action table attribute (for RTM_*ACTION messages).
pub const TCA_ACT_TAB: u16 = 1;

/// Root action attributes (for action dump).
pub const TCA_ROOT_UNSPEC: u16 = 0;
pub const TCA_ROOT_TAB: u16 = 1;
pub const TCA_ROOT_FLAGS: u16 = 2;
pub const TCA_ROOT_COUNT: u16 = 3;
pub const TCA_ROOT_TIME_DELTA: u16 = 4;

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

        /// HTB global parameters (struct tc_htb_glob).
        #[repr(C)]
        #[derive(Debug, Clone, Copy, Default)]
        pub struct TcHtbGlob {
            pub version: u32,
            pub rate2quantum: u32,
            pub defcls: u32,
            pub debug: u32,
            pub direct_pkts: u32,
        }

        impl TcHtbGlob {
            pub const SIZE: usize = std::mem::size_of::<Self>();

            pub fn new() -> Self {
                Self {
                    version: 3,
                    rate2quantum: 10,
                    defcls: 0,
                    debug: 0,
                    direct_pkts: 0,
                }
            }

            pub fn with_default(mut self, defcls: u32) -> Self {
                self.defcls = defcls;
                self
            }

            pub fn as_bytes(&self) -> &[u8] {
                unsafe { std::slice::from_raw_parts(self as *const Self as *const u8, Self::SIZE) }
            }
        }

        /// HTB class parameters (struct tc_htb_opt).
        #[repr(C)]
        #[derive(Debug, Clone, Copy, Default)]
        pub struct TcHtbOpt {
            pub rate: super::TcRateSpec,
            pub ceil: super::TcRateSpec,
            pub buffer: u32,
            pub cbuffer: u32,
            pub quantum: u32,
            pub level: u32,
            pub prio: u32,
        }

        impl TcHtbOpt {
            pub const SIZE: usize = std::mem::size_of::<Self>();

            pub fn as_bytes(&self) -> &[u8] {
                unsafe { std::slice::from_raw_parts(self as *const Self as *const u8, Self::SIZE) }
            }
        }
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

        /// TBF parameters (struct tc_tbf_qopt).
        #[repr(C)]
        #[derive(Debug, Clone, Copy, Default)]
        pub struct TcTbfQopt {
            pub rate: super::TcRateSpec,
            pub peakrate: super::TcRateSpec,
            pub limit: u32,
            pub buffer: u32,
            pub mtu: u32,
        }

        impl TcTbfQopt {
            pub const SIZE: usize = std::mem::size_of::<Self>();

            pub fn as_bytes(&self) -> &[u8] {
                unsafe { std::slice::from_raw_parts(self as *const Self as *const u8, Self::SIZE) }
            }
        }
    }

    /// PRIO qdisc-specific attributes.
    pub mod prio {
        pub const TCA_PRIO_UNSPEC: u16 = 0;
        pub const TCA_PRIO_MQ: u16 = 1;

        /// PRIO parameters (struct tc_prio_qopt).
        #[repr(C)]
        #[derive(Debug, Clone, Copy)]
        pub struct TcPrioQopt {
            pub bands: i32,
            pub priomap: [u8; 16],
        }

        impl Default for TcPrioQopt {
            fn default() -> Self {
                Self {
                    bands: 3,
                    // Default priomap: { 1, 2, 2, 2, 1, 2, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1 }
                    priomap: [1, 2, 2, 2, 1, 2, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1],
                }
            }
        }

        impl TcPrioQopt {
            pub const SIZE: usize = std::mem::size_of::<Self>();

            pub fn as_bytes(&self) -> &[u8] {
                unsafe { std::slice::from_raw_parts(self as *const Self as *const u8, Self::SIZE) }
            }
        }
    }

    /// SFQ qdisc-specific attributes.
    pub mod sfq {
        /// SFQ parameters (struct tc_sfq_qopt_v1).
        #[repr(C)]
        #[derive(Debug, Clone, Copy, Default)]
        pub struct TcSfqQoptV1 {
            pub v0: TcSfqQopt,
            pub depth: u32,
            pub headdrop: u32,
            pub limit: u32,
            pub qth_min: u32,
            pub qth_max: u32,
            pub wlog: u8,
            pub plog: u8,
            pub scell_log: u8,
            pub flags: u8,
            pub max_p: u32,
            // ... additional fields omitted for simplicity
        }

        /// SFQ basic parameters (struct tc_sfq_qopt).
        #[repr(C)]
        #[derive(Debug, Clone, Copy, Default)]
        pub struct TcSfqQopt {
            pub quantum: u32,
            pub perturb_period: i32,
            pub limit: u32,
            pub divisor: u32,
            pub flows: u32,
        }

        impl TcSfqQopt {
            pub const SIZE: usize = std::mem::size_of::<Self>();

            pub fn as_bytes(&self) -> &[u8] {
                unsafe { std::slice::from_raw_parts(self as *const Self as *const u8, Self::SIZE) }
            }
        }
    }

    /// Netem qdisc-specific attributes.
    pub mod netem {
        pub const TCA_NETEM_UNSPEC: u16 = 0;
        pub const TCA_NETEM_CORR: u16 = 1;
        pub const TCA_NETEM_DELAY_DIST: u16 = 2;
        pub const TCA_NETEM_REORDER: u16 = 3;
        pub const TCA_NETEM_CORRUPT: u16 = 4;
        pub const TCA_NETEM_LOSS: u16 = 5;
        pub const TCA_NETEM_RATE: u16 = 6;
        pub const TCA_NETEM_ECN: u16 = 7;
        pub const TCA_NETEM_RATE64: u16 = 8;
        pub const TCA_NETEM_PAD: u16 = 9;
        pub const TCA_NETEM_LATENCY64: u16 = 10;
        pub const TCA_NETEM_JITTER64: u16 = 11;
        pub const TCA_NETEM_SLOT: u16 = 12;
        pub const TCA_NETEM_SLOT_DIST: u16 = 13;
        pub const TCA_NETEM_PRNG_SEED: u16 = 14;

        /// Netem loss model types.
        pub const NETEM_LOSS_UNSPEC: u16 = 0;
        pub const NETEM_LOSS_GI: u16 = 1; // General Intuitive - 4 state model
        pub const NETEM_LOSS_GE: u16 = 2; // Gilbert Elliot model

        /// Netem basic options (struct tc_netem_qopt).
        #[repr(C)]
        #[derive(Debug, Clone, Copy, Default)]
        pub struct TcNetemQopt {
            /// Added delay in microseconds.
            pub latency: u32,
            /// FIFO limit (packets).
            pub limit: u32,
            /// Random packet loss (0=none, ~0=100%).
            pub loss: u32,
            /// Re-ordering gap (0 for none).
            pub gap: u32,
            /// Random packet duplication (0=none, ~0=100%).
            pub duplicate: u32,
            /// Random jitter in latency (microseconds).
            pub jitter: u32,
        }

        impl TcNetemQopt {
            pub const SIZE: usize = std::mem::size_of::<Self>();

            pub fn new() -> Self {
                Self {
                    limit: 1000,
                    ..Default::default()
                }
            }

            pub fn as_bytes(&self) -> &[u8] {
                unsafe { std::slice::from_raw_parts(self as *const Self as *const u8, Self::SIZE) }
            }
        }

        /// Netem correlation structure (struct tc_netem_corr).
        #[repr(C)]
        #[derive(Debug, Clone, Copy, Default)]
        pub struct TcNetemCorr {
            /// Delay correlation.
            pub delay_corr: u32,
            /// Packet loss correlation.
            pub loss_corr: u32,
            /// Duplicate correlation.
            pub dup_corr: u32,
        }

        impl TcNetemCorr {
            pub const SIZE: usize = std::mem::size_of::<Self>();

            pub fn as_bytes(&self) -> &[u8] {
                unsafe { std::slice::from_raw_parts(self as *const Self as *const u8, Self::SIZE) }
            }
        }

        /// Netem reorder structure (struct tc_netem_reorder).
        #[repr(C)]
        #[derive(Debug, Clone, Copy, Default)]
        pub struct TcNetemReorder {
            pub probability: u32,
            pub correlation: u32,
        }

        impl TcNetemReorder {
            pub const SIZE: usize = std::mem::size_of::<Self>();

            pub fn as_bytes(&self) -> &[u8] {
                unsafe { std::slice::from_raw_parts(self as *const Self as *const u8, Self::SIZE) }
            }
        }

        /// Netem corrupt structure (struct tc_netem_corrupt).
        #[repr(C)]
        #[derive(Debug, Clone, Copy, Default)]
        pub struct TcNetemCorrupt {
            pub probability: u32,
            pub correlation: u32,
        }

        impl TcNetemCorrupt {
            pub const SIZE: usize = std::mem::size_of::<Self>();

            pub fn as_bytes(&self) -> &[u8] {
                unsafe { std::slice::from_raw_parts(self as *const Self as *const u8, Self::SIZE) }
            }
        }

        /// Netem rate structure (struct tc_netem_rate).
        #[repr(C)]
        #[derive(Debug, Clone, Copy, Default)]
        pub struct TcNetemRate {
            /// Rate in bytes/s.
            pub rate: u32,
            /// Packet overhead.
            pub packet_overhead: i32,
            /// Cell size.
            pub cell_size: u32,
            /// Cell overhead.
            pub cell_overhead: i32,
        }

        impl TcNetemRate {
            pub const SIZE: usize = std::mem::size_of::<Self>();

            pub fn as_bytes(&self) -> &[u8] {
                unsafe { std::slice::from_raw_parts(self as *const Self as *const u8, Self::SIZE) }
            }
        }

        /// Netem slot structure (struct tc_netem_slot).
        #[repr(C)]
        #[derive(Debug, Clone, Copy, Default)]
        pub struct TcNetemSlot {
            /// Minimum delay in nanoseconds.
            pub min_delay: i64,
            /// Maximum delay in nanoseconds.
            pub max_delay: i64,
            /// Maximum packets per slot.
            pub max_packets: i32,
            /// Maximum bytes per slot.
            pub max_bytes: i32,
            /// Distribution delay in nanoseconds.
            pub dist_delay: i64,
            /// Distribution jitter in nanoseconds.
            pub dist_jitter: i64,
        }

        impl TcNetemSlot {
            pub const SIZE: usize = std::mem::size_of::<Self>();

            pub fn as_bytes(&self) -> &[u8] {
                unsafe { std::slice::from_raw_parts(self as *const Self as *const u8, Self::SIZE) }
            }
        }

        /// Gilbert-Intuitive loss model (4 state) (struct tc_netem_gimodel).
        #[repr(C)]
        #[derive(Debug, Clone, Copy, Default)]
        pub struct TcNetemGiModel {
            pub p13: u32,
            pub p31: u32,
            pub p32: u32,
            pub p14: u32,
            pub p23: u32,
        }

        impl TcNetemGiModel {
            pub const SIZE: usize = std::mem::size_of::<Self>();

            pub fn as_bytes(&self) -> &[u8] {
                unsafe { std::slice::from_raw_parts(self as *const Self as *const u8, Self::SIZE) }
            }
        }

        /// Gilbert-Elliot loss model (struct tc_netem_gemodel).
        #[repr(C)]
        #[derive(Debug, Clone, Copy, Default)]
        pub struct TcNetemGeModel {
            pub p: u32,
            pub r: u32,
            pub h: u32,
            pub k1: u32,
        }

        impl TcNetemGeModel {
            pub const SIZE: usize = std::mem::size_of::<Self>();

            pub fn as_bytes(&self) -> &[u8] {
                unsafe { std::slice::from_raw_parts(self as *const Self as *const u8, Self::SIZE) }
            }
        }

        /// Convert percentage (0.0-100.0) to netem probability (0 to u32::MAX).
        pub fn percent_to_prob(percent: f64) -> u32 {
            ((percent / 100.0) * (u32::MAX as f64)) as u32
        }

        /// Convert netem probability to percentage.
        pub fn prob_to_percent(prob: u32) -> f64 {
            (prob as f64 / u32::MAX as f64) * 100.0
        }
    }

    /// Rate specification (struct tc_ratespec).
    #[repr(C)]
    #[derive(Debug, Clone, Copy, Default)]
    pub struct TcRateSpec {
        pub cell_log: u8,
        pub linklayer: u8,
        pub overhead: u16,
        pub cell_align: i16,
        pub mpu: u16,
        pub rate: u32,
    }

    impl TcRateSpec {
        pub const SIZE: usize = std::mem::size_of::<Self>();

        pub fn new(rate: u32) -> Self {
            Self {
                rate,
                ..Default::default()
            }
        }

        pub fn as_bytes(&self) -> &[u8] {
            unsafe { std::slice::from_raw_parts(self as *const Self as *const u8, Self::SIZE) }
        }
    }
}

/// Common filter attributes.
pub mod filter {
    /// U32 filter attributes and structures.
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

        /// U32 selector flags.
        pub const TC_U32_TERMINAL: u8 = 1;
        pub const TC_U32_OFFSET: u8 = 2;
        pub const TC_U32_VAROFFSET: u8 = 4;
        pub const TC_U32_EAT: u8 = 8;

        /// U32 key (struct tc_u32_key).
        /// Matches a 32-bit value at a specific offset.
        #[repr(C)]
        #[derive(Debug, Clone, Copy, Default)]
        pub struct TcU32Key {
            /// Mask to apply (big-endian).
            pub mask: u32,
            /// Value to match (big-endian).
            pub val: u32,
            /// Byte offset from header start.
            pub off: i32,
            /// Offset mask for variable offset (-1 for nexthdr+).
            pub offmask: i32,
        }

        impl TcU32Key {
            pub const SIZE: usize = std::mem::size_of::<Self>();

            /// Create a new key with value, mask, and offset.
            pub fn new(val: u32, mask: u32, off: i32) -> Self {
                Self {
                    mask,
                    val: val & mask,
                    off,
                    offmask: 0,
                }
            }

            /// Create a key for matching at nexthdr+ offset.
            pub fn with_nexthdr(val: u32, mask: u32, off: i32) -> Self {
                Self {
                    mask,
                    val: val & mask,
                    off,
                    offmask: -1,
                }
            }
        }

        /// U32 selector header (struct tc_u32_sel without keys).
        #[repr(C)]
        #[derive(Debug, Clone, Copy, Default)]
        pub struct TcU32SelHdr {
            /// Flags (TC_U32_TERMINAL, etc.).
            pub flags: u8,
            /// Shift for variable offset.
            pub offshift: u8,
            /// Number of keys.
            pub nkeys: u8,
            /// Padding.
            pub _pad: u8,
            /// Mask for variable offset (big-endian).
            pub offmask: u16,
            /// Fixed offset to add.
            pub off: u16,
            /// Offset to variable offset field.
            pub offoff: i16,
            /// Hash key offset.
            pub hoff: i16,
            /// Hash mask (big-endian).
            pub hmask: u32,
        }

        impl TcU32SelHdr {
            pub const SIZE: usize = std::mem::size_of::<Self>();

            pub fn as_bytes(&self) -> &[u8] {
                unsafe { std::slice::from_raw_parts(self as *const Self as *const u8, Self::SIZE) }
            }
        }

        /// U32 selector builder - builds the full selector with keys.
        #[derive(Debug, Clone, Default)]
        pub struct TcU32Sel {
            pub hdr: TcU32SelHdr,
            pub keys: Vec<TcU32Key>,
        }

        impl TcU32Sel {
            pub fn new() -> Self {
                Self::default()
            }

            /// Add a key to the selector.
            pub fn add_key(&mut self, key: TcU32Key) {
                self.keys.push(key);
                self.hdr.nkeys = self.keys.len() as u8;
            }

            /// Set terminal flag (packet will be classified).
            pub fn set_terminal(&mut self) {
                self.hdr.flags |= TC_U32_TERMINAL;
            }

            /// Convert to bytes for netlink message.
            pub fn to_bytes(&self) -> Vec<u8> {
                let mut buf =
                    Vec::with_capacity(TcU32SelHdr::SIZE + self.keys.len() * TcU32Key::SIZE);
                buf.extend_from_slice(self.hdr.as_bytes());
                for key in &self.keys {
                    let key_bytes = unsafe {
                        std::slice::from_raw_parts(
                            key as *const TcU32Key as *const u8,
                            TcU32Key::SIZE,
                        )
                    };
                    buf.extend_from_slice(key_bytes);
                }
                buf
            }
        }

        /// U32 mark structure (struct tc_u32_mark).
        #[repr(C)]
        #[derive(Debug, Clone, Copy, Default)]
        pub struct TcU32Mark {
            pub val: u32,
            pub mask: u32,
            pub success: u32,
        }

        impl TcU32Mark {
            pub const SIZE: usize = std::mem::size_of::<Self>();

            pub fn new(val: u32, mask: u32) -> Self {
                Self {
                    val,
                    mask,
                    success: 0,
                }
            }

            pub fn as_bytes(&self) -> &[u8] {
                unsafe { std::slice::from_raw_parts(self as *const Self as *const u8, Self::SIZE) }
            }
        }

        /// Helper to pack a 32-bit key at an offset.
        pub fn pack_key32(val: u32, mask: u32, off: i32) -> TcU32Key {
            TcU32Key::new(val.to_be(), mask.to_be(), off)
        }

        /// Helper to pack a 16-bit key at an offset.
        pub fn pack_key16(val: u16, mask: u16, off: i32) -> TcU32Key {
            // 16-bit values are positioned within a 32-bit word
            let (val32, mask32) = if (off & 3) == 0 {
                // Upper 16 bits
                ((val as u32) << 16, (mask as u32) << 16)
            } else {
                // Lower 16 bits
                (val as u32, mask as u32)
            };
            TcU32Key::new(val32.to_be(), mask32.to_be(), off & !3)
        }

        /// Helper to pack an 8-bit key at an offset.
        pub fn pack_key8(val: u8, mask: u8, off: i32) -> TcU32Key {
            let shift = match off & 3 {
                0 => 24,
                1 => 16,
                2 => 8,
                _ => 0,
            };
            let val32 = (val as u32) << shift;
            let mask32 = (mask as u32) << shift;
            TcU32Key::new(val32.to_be(), mask32.to_be(), off & !3)
        }
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
        pub const TCA_FLOWER_KEY_VLAN_ID: u16 = 23;
        pub const TCA_FLOWER_KEY_VLAN_PRIO: u16 = 24;
        pub const TCA_FLOWER_KEY_VLAN_ETH_TYPE: u16 = 25;
        pub const TCA_FLOWER_KEY_ENC_KEY_ID: u16 = 26;
        pub const TCA_FLOWER_KEY_ENC_IPV4_SRC: u16 = 27;
        pub const TCA_FLOWER_KEY_ENC_IPV4_SRC_MASK: u16 = 28;
        pub const TCA_FLOWER_KEY_ENC_IPV4_DST: u16 = 29;
        pub const TCA_FLOWER_KEY_ENC_IPV4_DST_MASK: u16 = 30;
        pub const TCA_FLOWER_KEY_ENC_IPV6_SRC: u16 = 31;
        pub const TCA_FLOWER_KEY_ENC_IPV6_SRC_MASK: u16 = 32;
        pub const TCA_FLOWER_KEY_ENC_IPV6_DST: u16 = 33;
        pub const TCA_FLOWER_KEY_ENC_IPV6_DST_MASK: u16 = 34;
        pub const TCA_FLOWER_KEY_TCP_SRC_MASK: u16 = 35;
        pub const TCA_FLOWER_KEY_TCP_DST_MASK: u16 = 36;
        pub const TCA_FLOWER_KEY_UDP_SRC_MASK: u16 = 37;
        pub const TCA_FLOWER_KEY_UDP_DST_MASK: u16 = 38;
        pub const TCA_FLOWER_KEY_SCTP_SRC_MASK: u16 = 39;
        pub const TCA_FLOWER_KEY_SCTP_DST_MASK: u16 = 40;
        pub const TCA_FLOWER_KEY_SCTP_SRC: u16 = 41;
        pub const TCA_FLOWER_KEY_SCTP_DST: u16 = 42;
        pub const TCA_FLOWER_KEY_ENC_UDP_SRC_PORT: u16 = 43;
        pub const TCA_FLOWER_KEY_ENC_UDP_SRC_PORT_MASK: u16 = 44;
        pub const TCA_FLOWER_KEY_ENC_UDP_DST_PORT: u16 = 45;
        pub const TCA_FLOWER_KEY_ENC_UDP_DST_PORT_MASK: u16 = 46;
        pub const TCA_FLOWER_KEY_FLAGS: u16 = 47;
        pub const TCA_FLOWER_KEY_FLAGS_MASK: u16 = 48;
        pub const TCA_FLOWER_KEY_ICMPV4_CODE: u16 = 49;
        pub const TCA_FLOWER_KEY_ICMPV4_CODE_MASK: u16 = 50;
        pub const TCA_FLOWER_KEY_ICMPV4_TYPE: u16 = 51;
        pub const TCA_FLOWER_KEY_ICMPV4_TYPE_MASK: u16 = 52;
        pub const TCA_FLOWER_KEY_ICMPV6_CODE: u16 = 53;
        pub const TCA_FLOWER_KEY_ICMPV6_CODE_MASK: u16 = 54;
        pub const TCA_FLOWER_KEY_ICMPV6_TYPE: u16 = 55;
        pub const TCA_FLOWER_KEY_ICMPV6_TYPE_MASK: u16 = 56;
        pub const TCA_FLOWER_KEY_ARP_SIP: u16 = 57;
        pub const TCA_FLOWER_KEY_ARP_SIP_MASK: u16 = 58;
        pub const TCA_FLOWER_KEY_ARP_TIP: u16 = 59;
        pub const TCA_FLOWER_KEY_ARP_TIP_MASK: u16 = 60;
        pub const TCA_FLOWER_KEY_ARP_OP: u16 = 61;
        pub const TCA_FLOWER_KEY_ARP_OP_MASK: u16 = 62;
        pub const TCA_FLOWER_KEY_ARP_SHA: u16 = 63;
        pub const TCA_FLOWER_KEY_ARP_SHA_MASK: u16 = 64;
        pub const TCA_FLOWER_KEY_ARP_THA: u16 = 65;
        pub const TCA_FLOWER_KEY_ARP_THA_MASK: u16 = 66;
        pub const TCA_FLOWER_KEY_MPLS_TTL: u16 = 67;
        pub const TCA_FLOWER_KEY_MPLS_BOS: u16 = 68;
        pub const TCA_FLOWER_KEY_MPLS_TC: u16 = 69;
        pub const TCA_FLOWER_KEY_MPLS_LABEL: u16 = 70;
        pub const TCA_FLOWER_KEY_TCP_FLAGS: u16 = 71;
        pub const TCA_FLOWER_KEY_TCP_FLAGS_MASK: u16 = 72;
        pub const TCA_FLOWER_KEY_IP_TOS: u16 = 73;
        pub const TCA_FLOWER_KEY_IP_TOS_MASK: u16 = 74;
        pub const TCA_FLOWER_KEY_IP_TTL: u16 = 75;
        pub const TCA_FLOWER_KEY_IP_TTL_MASK: u16 = 76;
        pub const TCA_FLOWER_KEY_CVLAN_ID: u16 = 77;
        pub const TCA_FLOWER_KEY_CVLAN_PRIO: u16 = 78;
        pub const TCA_FLOWER_KEY_CVLAN_ETH_TYPE: u16 = 79;
        pub const TCA_FLOWER_KEY_ENC_IP_TOS: u16 = 80;
        pub const TCA_FLOWER_KEY_ENC_IP_TOS_MASK: u16 = 81;
        pub const TCA_FLOWER_KEY_ENC_IP_TTL: u16 = 82;
        pub const TCA_FLOWER_KEY_ENC_IP_TTL_MASK: u16 = 83;
        pub const TCA_FLOWER_KEY_CT_STATE: u16 = 84;
        pub const TCA_FLOWER_KEY_CT_STATE_MASK: u16 = 85;
        pub const TCA_FLOWER_KEY_CT_ZONE: u16 = 86;
        pub const TCA_FLOWER_KEY_CT_ZONE_MASK: u16 = 87;
        pub const TCA_FLOWER_KEY_CT_MARK: u16 = 88;
        pub const TCA_FLOWER_KEY_CT_MARK_MASK: u16 = 89;
        pub const TCA_FLOWER_KEY_CT_LABELS: u16 = 90;
        pub const TCA_FLOWER_KEY_CT_LABELS_MASK: u16 = 91;

        /// Flower filter flags.
        pub const TCA_CLS_FLAGS_SKIP_HW: u32 = 1 << 0;
        pub const TCA_CLS_FLAGS_SKIP_SW: u32 = 1 << 1;
        pub const TCA_CLS_FLAGS_IN_HW: u32 = 1 << 2;
        pub const TCA_CLS_FLAGS_NOT_IN_HW: u32 = 1 << 3;
        pub const TCA_CLS_FLAGS_VERBOSE: u32 = 1 << 4;

        /// Connection tracking state flags.
        pub const TCA_FLOWER_KEY_CT_FLAGS_NEW: u16 = 1 << 0;
        pub const TCA_FLOWER_KEY_CT_FLAGS_ESTABLISHED: u16 = 1 << 1;
        pub const TCA_FLOWER_KEY_CT_FLAGS_RELATED: u16 = 1 << 2;
        pub const TCA_FLOWER_KEY_CT_FLAGS_TRACKED: u16 = 1 << 3;
        pub const TCA_FLOWER_KEY_CT_FLAGS_INVALID: u16 = 1 << 4;
        pub const TCA_FLOWER_KEY_CT_FLAGS_REPLY: u16 = 1 << 5;

        /// IP protocol constants.
        pub const IPPROTO_TCP: u8 = 6;
        pub const IPPROTO_UDP: u8 = 17;
        pub const IPPROTO_ICMP: u8 = 1;
        pub const IPPROTO_ICMPV6: u8 = 58;
        pub const IPPROTO_SCTP: u8 = 132;
        pub const IPPROTO_GRE: u8 = 47;

        /// Parse IP protocol from string.
        pub fn parse_ip_proto(s: &str) -> Option<u8> {
            match s.to_lowercase().as_str() {
                "tcp" => Some(IPPROTO_TCP),
                "udp" => Some(IPPROTO_UDP),
                "icmp" => Some(IPPROTO_ICMP),
                "icmpv6" => Some(IPPROTO_ICMPV6),
                "sctp" => Some(IPPROTO_SCTP),
                "gre" => Some(IPPROTO_GRE),
                _ => s.parse().ok(),
            }
        }
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

    /// Action binding constants.
    pub const TCA_ACT_BIND: i32 = 1;
    pub const TCA_ACT_NOBIND: i32 = 0;

    /// Action results (TC_ACT_*).
    pub const TC_ACT_UNSPEC: i32 = -1;
    pub const TC_ACT_OK: i32 = 0;
    pub const TC_ACT_RECLASSIFY: i32 = 1;
    pub const TC_ACT_SHOT: i32 = 2;
    pub const TC_ACT_PIPE: i32 = 3;
    pub const TC_ACT_STOLEN: i32 = 4;
    pub const TC_ACT_QUEUED: i32 = 5;
    pub const TC_ACT_REPEAT: i32 = 6;
    pub const TC_ACT_REDIRECT: i32 = 7;
    pub const TC_ACT_TRAP: i32 = 8;

    /// Parse action result from string.
    pub fn parse_action_result(s: &str) -> Option<i32> {
        match s.to_lowercase().as_str() {
            "ok" | "pass" => Some(TC_ACT_OK),
            "shot" | "drop" => Some(TC_ACT_SHOT),
            "reclassify" => Some(TC_ACT_RECLASSIFY),
            "pipe" => Some(TC_ACT_PIPE),
            "stolen" => Some(TC_ACT_STOLEN),
            "queued" => Some(TC_ACT_QUEUED),
            "repeat" => Some(TC_ACT_REPEAT),
            "redirect" => Some(TC_ACT_REDIRECT),
            "trap" => Some(TC_ACT_TRAP),
            "continue" => Some(TC_ACT_PIPE), // alias
            _ => None,
        }
    }

    /// Format action result to string.
    pub fn format_action_result(action: i32) -> &'static str {
        match action {
            TC_ACT_UNSPEC => "unspec",
            TC_ACT_OK => "pass",
            TC_ACT_SHOT => "drop",
            TC_ACT_RECLASSIFY => "reclassify",
            TC_ACT_PIPE => "pipe",
            TC_ACT_STOLEN => "stolen",
            TC_ACT_QUEUED => "queued",
            TC_ACT_REPEAT => "repeat",
            TC_ACT_REDIRECT => "redirect",
            TC_ACT_TRAP => "trap",
            _ => "unknown",
        }
    }

    /// Common action header (tc_gen macro in kernel).
    /// This is the base structure for all action parameters.
    #[repr(C)]
    #[derive(Debug, Clone, Copy, Default)]
    pub struct TcGen {
        pub index: u32,
        pub capab: u32,
        pub action: i32,
        pub refcnt: i32,
        pub bindcnt: i32,
    }

    impl TcGen {
        pub fn new(action: i32) -> Self {
            Self {
                index: 0,
                capab: 0,
                action,
                refcnt: 0,
                bindcnt: 0,
            }
        }

        pub fn as_bytes(&self) -> &[u8] {
            unsafe {
                std::slice::from_raw_parts(
                    self as *const Self as *const u8,
                    std::mem::size_of::<Self>(),
                )
            }
        }
    }

    /// Mirred action attributes.
    pub mod mirred {
        pub const TCA_MIRRED_UNSPEC: u16 = 0;
        pub const TCA_MIRRED_TM: u16 = 1;
        pub const TCA_MIRRED_PARMS: u16 = 2;
        pub const TCA_MIRRED_PAD: u16 = 3;
        pub const TCA_MIRRED_BLOCKID: u16 = 4;

        /// Mirred action types.
        pub const TCA_EGRESS_REDIR: i32 = 1;
        pub const TCA_EGRESS_MIRROR: i32 = 2;
        pub const TCA_INGRESS_REDIR: i32 = 3;
        pub const TCA_INGRESS_MIRROR: i32 = 4;

        /// Parse mirred action type from string.
        pub fn parse_mirred_action(s: &str) -> Option<i32> {
            match s.to_lowercase().as_str() {
                "egress_redir" | "redirect" => Some(TCA_EGRESS_REDIR),
                "egress_mirror" | "mirror" => Some(TCA_EGRESS_MIRROR),
                "ingress_redir" => Some(TCA_INGRESS_REDIR),
                "ingress_mirror" => Some(TCA_INGRESS_MIRROR),
                _ => None,
            }
        }

        /// Format mirred action type to string.
        pub fn format_mirred_action(eaction: i32) -> &'static str {
            match eaction {
                TCA_EGRESS_REDIR => "egress redirect",
                TCA_EGRESS_MIRROR => "egress mirror",
                TCA_INGRESS_REDIR => "ingress redirect",
                TCA_INGRESS_MIRROR => "ingress mirror",
                _ => "unknown",
            }
        }

        /// Mirred action parameters (struct tc_mirred).
        #[repr(C)]
        #[derive(Debug, Clone, Copy, Default)]
        pub struct TcMirred {
            /// Common action fields (tc_gen).
            pub index: u32,
            pub capab: u32,
            pub action: i32,
            pub refcnt: i32,
            pub bindcnt: i32,
            /// Mirred-specific: egress/ingress mirror/redirect.
            pub eaction: i32,
            /// Target interface index.
            pub ifindex: u32,
        }

        impl TcMirred {
            pub fn new(eaction: i32, ifindex: u32, action: i32) -> Self {
                Self {
                    index: 0,
                    capab: 0,
                    action,
                    refcnt: 0,
                    bindcnt: 0,
                    eaction,
                    ifindex,
                }
            }

            pub fn as_bytes(&self) -> &[u8] {
                unsafe {
                    std::slice::from_raw_parts(
                        self as *const Self as *const u8,
                        std::mem::size_of::<Self>(),
                    )
                }
            }
        }
    }

    /// Gact (generic action) attributes.
    pub mod gact {
        pub const TCA_GACT_UNSPEC: u16 = 0;
        pub const TCA_GACT_TM: u16 = 1;
        pub const TCA_GACT_PARMS: u16 = 2;
        pub const TCA_GACT_PROB: u16 = 3;
        pub const TCA_GACT_PAD: u16 = 4;

        /// Probability distribution types.
        pub const PGACT_NONE: u16 = 0;
        pub const PGACT_NETRAND: u16 = 1;
        pub const PGACT_DETERM: u16 = 2;

        /// Gact action parameters (struct tc_gact).
        #[repr(C)]
        #[derive(Debug, Clone, Copy, Default)]
        pub struct TcGact {
            /// Common action fields (tc_gen).
            pub index: u32,
            pub capab: u32,
            pub action: i32,
            pub refcnt: i32,
            pub bindcnt: i32,
        }

        impl TcGact {
            pub fn new(action: i32) -> Self {
                Self {
                    index: 0,
                    capab: 0,
                    action,
                    refcnt: 0,
                    bindcnt: 0,
                }
            }

            pub fn as_bytes(&self) -> &[u8] {
                unsafe {
                    std::slice::from_raw_parts(
                        self as *const Self as *const u8,
                        std::mem::size_of::<Self>(),
                    )
                }
            }
        }

        /// Gact probability parameters (struct tc_gact_p).
        #[repr(C)]
        #[derive(Debug, Clone, Copy, Default)]
        pub struct TcGactP {
            pub ptype: u16,
            pub pval: u16,
            pub paction: i32,
        }

        impl TcGactP {
            pub fn new(ptype: u16, pval: u16, paction: i32) -> Self {
                Self {
                    ptype,
                    pval,
                    paction,
                }
            }

            pub fn as_bytes(&self) -> &[u8] {
                unsafe {
                    std::slice::from_raw_parts(
                        self as *const Self as *const u8,
                        std::mem::size_of::<Self>(),
                    )
                }
            }
        }
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

        use crate::types::tc::qdisc::TcRateSpec;

        /// Police action parameters (struct tc_police).
        #[repr(C)]
        #[derive(Debug, Clone, Copy)]
        pub struct TcPolice {
            pub index: u32,
            pub action: i32,
            pub limit: u32,
            pub burst: u32,
            pub mtu: u32,
            pub rate: TcRateSpec,
            pub peakrate: TcRateSpec,
            pub refcnt: i32,
            pub bindcnt: i32,
            pub capab: u32,
        }

        impl Default for TcPolice {
            fn default() -> Self {
                Self {
                    index: 0,
                    action: super::TC_ACT_OK,
                    limit: 0,
                    burst: 0,
                    mtu: 0,
                    rate: TcRateSpec::default(),
                    peakrate: TcRateSpec::default(),
                    refcnt: 0,
                    bindcnt: 0,
                    capab: 0,
                }
            }
        }

        impl TcPolice {
            pub fn as_bytes(&self) -> &[u8] {
                unsafe {
                    std::slice::from_raw_parts(
                        self as *const Self as *const u8,
                        std::mem::size_of::<Self>(),
                    )
                }
            }
        }
    }

    /// Vlan action attributes.
    pub mod vlan {
        pub const TCA_VLAN_UNSPEC: u16 = 0;
        pub const TCA_VLAN_TM: u16 = 1;
        pub const TCA_VLAN_PARMS: u16 = 2;
        pub const TCA_VLAN_PUSH_VLAN_ID: u16 = 3;
        pub const TCA_VLAN_PUSH_VLAN_PROTOCOL: u16 = 4;
        pub const TCA_VLAN_PAD: u16 = 5;
        pub const TCA_VLAN_PUSH_VLAN_PRIORITY: u16 = 6;
        pub const TCA_VLAN_PUSH_ETH_DST: u16 = 7;
        pub const TCA_VLAN_PUSH_ETH_SRC: u16 = 8;

        /// Vlan action types.
        pub const TCA_VLAN_ACT_POP: i32 = 1;
        pub const TCA_VLAN_ACT_PUSH: i32 = 2;
        pub const TCA_VLAN_ACT_MODIFY: i32 = 3;
        pub const TCA_VLAN_ACT_POP_ETH: i32 = 4;
        pub const TCA_VLAN_ACT_PUSH_ETH: i32 = 5;

        /// Ethernet protocol for VLAN.
        pub const ETH_P_8021Q: u16 = 0x8100;
        pub const ETH_P_8021AD: u16 = 0x88A8;

        /// Format vlan action type to string.
        pub fn format_vlan_action(v_action: i32) -> &'static str {
            match v_action {
                TCA_VLAN_ACT_POP => "pop",
                TCA_VLAN_ACT_PUSH => "push",
                TCA_VLAN_ACT_MODIFY => "modify",
                TCA_VLAN_ACT_POP_ETH => "pop_eth",
                TCA_VLAN_ACT_PUSH_ETH => "push_eth",
                _ => "unknown",
            }
        }

        /// Vlan action parameters (struct tc_vlan).
        #[repr(C)]
        #[derive(Debug, Clone, Copy, Default)]
        pub struct TcVlan {
            /// Common action fields (tc_gen).
            pub index: u32,
            pub capab: u32,
            pub action: i32,
            pub refcnt: i32,
            pub bindcnt: i32,
            /// Vlan-specific action type.
            pub v_action: i32,
        }

        impl TcVlan {
            pub fn new(v_action: i32, action: i32) -> Self {
                Self {
                    index: 0,
                    capab: 0,
                    action,
                    refcnt: 0,
                    bindcnt: 0,
                    v_action,
                }
            }

            pub fn as_bytes(&self) -> &[u8] {
                unsafe {
                    std::slice::from_raw_parts(
                        self as *const Self as *const u8,
                        std::mem::size_of::<Self>(),
                    )
                }
            }
        }
    }

    /// Skbedit action attributes.
    pub mod skbedit {
        pub const TCA_SKBEDIT_UNSPEC: u16 = 0;
        pub const TCA_SKBEDIT_TM: u16 = 1;
        pub const TCA_SKBEDIT_PARMS: u16 = 2;
        pub const TCA_SKBEDIT_PRIORITY: u16 = 3;
        pub const TCA_SKBEDIT_QUEUE_MAPPING: u16 = 4;
        pub const TCA_SKBEDIT_MARK: u16 = 5;
        pub const TCA_SKBEDIT_PAD: u16 = 6;
        pub const TCA_SKBEDIT_PTYPE: u16 = 7;
        pub const TCA_SKBEDIT_MASK: u16 = 8;
        pub const TCA_SKBEDIT_FLAGS: u16 = 9;
        pub const TCA_SKBEDIT_QUEUE_MAPPING_MAX: u16 = 10;

        /// Skbedit flags.
        pub const SKBEDIT_F_PRIORITY: u64 = 0x1;
        pub const SKBEDIT_F_QUEUE_MAPPING: u64 = 0x2;
        pub const SKBEDIT_F_MARK: u64 = 0x4;
        pub const SKBEDIT_F_PTYPE: u64 = 0x8;
        pub const SKBEDIT_F_MASK: u64 = 0x10;
        pub const SKBEDIT_F_INHERITDSFIELD: u64 = 0x20;

        /// Packet types for ptype.
        pub const PACKET_HOST: u16 = 0;
        pub const PACKET_BROADCAST: u16 = 1;
        pub const PACKET_MULTICAST: u16 = 2;
        pub const PACKET_OTHERHOST: u16 = 3;
        pub const PACKET_OUTGOING: u16 = 4;
        pub const PACKET_LOOPBACK: u16 = 5;

        /// Skbedit action parameters (struct tc_skbedit).
        #[repr(C)]
        #[derive(Debug, Clone, Copy, Default)]
        pub struct TcSkbedit {
            /// Common action fields (tc_gen).
            pub index: u32,
            pub capab: u32,
            pub action: i32,
            pub refcnt: i32,
            pub bindcnt: i32,
        }

        impl TcSkbedit {
            pub fn new(action: i32) -> Self {
                Self {
                    index: 0,
                    capab: 0,
                    action,
                    refcnt: 0,
                    bindcnt: 0,
                }
            }

            pub fn as_bytes(&self) -> &[u8] {
                unsafe {
                    std::slice::from_raw_parts(
                        self as *const Self as *const u8,
                        std::mem::size_of::<Self>(),
                    )
                }
            }
        }
    }

    /// Tunnel key action attributes.
    pub mod tunnel_key {
        pub const TCA_TUNNEL_KEY_UNSPEC: u16 = 0;
        pub const TCA_TUNNEL_KEY_TM: u16 = 1;
        pub const TCA_TUNNEL_KEY_PARMS: u16 = 2;
        pub const TCA_TUNNEL_KEY_ENC_IPV4_SRC: u16 = 3;
        pub const TCA_TUNNEL_KEY_ENC_IPV4_DST: u16 = 4;
        pub const TCA_TUNNEL_KEY_ENC_IPV6_SRC: u16 = 5;
        pub const TCA_TUNNEL_KEY_ENC_IPV6_DST: u16 = 6;
        pub const TCA_TUNNEL_KEY_ENC_KEY_ID: u16 = 7;
        pub const TCA_TUNNEL_KEY_PAD: u16 = 8;
        pub const TCA_TUNNEL_KEY_ENC_DST_PORT: u16 = 9;
        pub const TCA_TUNNEL_KEY_NO_CSUM: u16 = 10;
        pub const TCA_TUNNEL_KEY_ENC_OPTS: u16 = 11;
        pub const TCA_TUNNEL_KEY_ENC_TOS: u16 = 12;
        pub const TCA_TUNNEL_KEY_ENC_TTL: u16 = 13;
        pub const TCA_TUNNEL_KEY_NO_FRAG: u16 = 14;

        /// Tunnel key action types.
        pub const TCA_TUNNEL_KEY_ACT_SET: i32 = 1;
        pub const TCA_TUNNEL_KEY_ACT_RELEASE: i32 = 2;

        /// Tunnel key action parameters (struct tc_tunnel_key).
        #[repr(C)]
        #[derive(Debug, Clone, Copy, Default)]
        pub struct TcTunnelKey {
            /// Common action fields (tc_gen).
            pub index: u32,
            pub capab: u32,
            pub action: i32,
            pub refcnt: i32,
            pub bindcnt: i32,
            /// Tunnel key action type.
            pub t_action: i32,
        }

        impl TcTunnelKey {
            pub fn new(t_action: i32, action: i32) -> Self {
                Self {
                    index: 0,
                    capab: 0,
                    action,
                    refcnt: 0,
                    bindcnt: 0,
                    t_action,
                }
            }

            pub fn as_bytes(&self) -> &[u8] {
                unsafe {
                    std::slice::from_raw_parts(
                        self as *const Self as *const u8,
                        std::mem::size_of::<Self>(),
                    )
                }
            }
        }
    }
}
