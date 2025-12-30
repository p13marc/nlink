//! Link (network interface) message types.

use crate::error::{Error, Result};

/// Interface info message (struct ifinfomsg).
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct IfInfoMsg {
    /// Address family (usually AF_UNSPEC).
    pub ifi_family: u8,
    /// Padding.
    pub __ifi_pad: u8,
    /// Device type (ARPHRD_*).
    pub ifi_type: u16,
    /// Interface index.
    pub ifi_index: i32,
    /// Device flags (IFF_*).
    pub ifi_flags: u32,
    /// Change mask.
    pub ifi_change: u32,
}

impl IfInfoMsg {
    /// Size of this structure.
    pub const SIZE: usize = std::mem::size_of::<Self>();

    /// Create a new interface info message.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the interface index.
    pub fn with_index(mut self, index: i32) -> Self {
        self.ifi_index = index;
        self
    }

    /// Set the address family.
    pub fn with_family(mut self, family: u8) -> Self {
        self.ifi_family = family;
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

/// Interface link attributes (IFLA_*).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum IflaAttr {
    Unspec = 0,
    Address = 1,
    Broadcast = 2,
    Ifname = 3,
    Mtu = 4,
    Link = 5,
    Qdisc = 6,
    Stats = 7,
    Cost = 8,
    Priority = 9,
    Master = 10,
    /// Wireless extensions
    Wireless = 11,
    /// Protocol specific information
    Protinfo = 12,
    TxqLen = 13,
    Map = 14,
    Weight = 15,
    Operstate = 16,
    Linkmode = 17,
    Linkinfo = 18,
    NetNsPid = 19,
    Ifalias = 20,
    NumVf = 21,
    VfinfoList = 22,
    Stats64 = 23,
    VfPorts = 24,
    PortSelf = 25,
    AfSpec = 26,
    Group = 27,
    NetNsFd = 28,
    ExtMask = 29,
    Promiscuity = 30,
    NumTxQueues = 31,
    NumRxQueues = 32,
    Carrier = 33,
    PhysPortId = 34,
    CarrierChanges = 35,
    PhysSwitchId = 36,
    LinkNetnsid = 37,
    PhysPortName = 38,
    ProtoDown = 39,
    GsoMaxSegs = 40,
    GsoMaxSize = 41,
    Pad = 42,
    Xdp = 43,
    Event = 44,
    NewNetnsid = 45,
    IfNetnsid = 46,
    // TargetNetnsid is an alias for IfNetnsid (same value 46)
    CarrierUpCount = 47,
    CarrierDownCount = 48,
    NewIfindex = 49,
    MinMtu = 50,
    MaxMtu = 51,
    PropList = 52,
    AltIfname = 53,
    PermAddress = 54,
    ProtoDownReason = 55,
    ParentDevName = 56,
    ParentDevBusName = 57,
    GroMaxSize = 58,
    TsoMaxSize = 59,
    TsoMaxSegs = 60,
    Allmulti = 61,
}

impl From<u16> for IflaAttr {
    fn from(val: u16) -> Self {
        match val {
            0 => Self::Unspec,
            1 => Self::Address,
            2 => Self::Broadcast,
            3 => Self::Ifname,
            4 => Self::Mtu,
            5 => Self::Link,
            6 => Self::Qdisc,
            7 => Self::Stats,
            8 => Self::Cost,
            9 => Self::Priority,
            10 => Self::Master,
            11 => Self::Wireless,
            12 => Self::Protinfo,
            13 => Self::TxqLen,
            14 => Self::Map,
            15 => Self::Weight,
            16 => Self::Operstate,
            17 => Self::Linkmode,
            18 => Self::Linkinfo,
            19 => Self::NetNsPid,
            20 => Self::Ifalias,
            21 => Self::NumVf,
            22 => Self::VfinfoList,
            23 => Self::Stats64,
            24 => Self::VfPorts,
            25 => Self::PortSelf,
            26 => Self::AfSpec,
            27 => Self::Group,
            28 => Self::NetNsFd,
            29 => Self::ExtMask,
            30 => Self::Promiscuity,
            31 => Self::NumTxQueues,
            32 => Self::NumRxQueues,
            33 => Self::Carrier,
            34 => Self::PhysPortId,
            35 => Self::CarrierChanges,
            36 => Self::PhysSwitchId,
            37 => Self::LinkNetnsid,
            38 => Self::PhysPortName,
            39 => Self::ProtoDown,
            40 => Self::GsoMaxSegs,
            41 => Self::GsoMaxSize,
            42 => Self::Pad,
            43 => Self::Xdp,
            44 => Self::Event,
            45 => Self::NewNetnsid,
            46 => Self::IfNetnsid,
            47 => Self::CarrierUpCount,
            48 => Self::CarrierDownCount,
            49 => Self::NewIfindex,
            50 => Self::MinMtu,
            51 => Self::MaxMtu,
            52 => Self::PropList,
            53 => Self::AltIfname,
            54 => Self::PermAddress,
            55 => Self::ProtoDownReason,
            56 => Self::ParentDevName,
            57 => Self::ParentDevBusName,
            58 => Self::GroMaxSize,
            59 => Self::TsoMaxSize,
            60 => Self::TsoMaxSegs,
            61 => Self::Allmulti,
            _ => Self::Unspec,
        }
    }
}

/// IFLA_LINKINFO nested attributes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum IflaInfo {
    Unspec = 0,
    Kind = 1,
    Data = 2,
    Xstats = 3,
    SlaveKind = 4,
    SlaveData = 5,
}

impl From<u16> for IflaInfo {
    fn from(val: u16) -> Self {
        match val {
            1 => Self::Kind,
            2 => Self::Data,
            3 => Self::Xstats,
            4 => Self::SlaveKind,
            5 => Self::SlaveData,
            _ => Self::Unspec,
        }
    }
}

/// Interface flags (IFF_*).
pub mod iff {
    pub const UP: u32 = 1 << 0;
    pub const BROADCAST: u32 = 1 << 1;
    pub const DEBUG: u32 = 1 << 2;
    pub const LOOPBACK: u32 = 1 << 3;
    pub const POINTOPOINT: u32 = 1 << 4;
    pub const NOTRAILERS: u32 = 1 << 5;
    pub const RUNNING: u32 = 1 << 6;
    pub const NOARP: u32 = 1 << 7;
    pub const PROMISC: u32 = 1 << 8;
    pub const ALLMULTI: u32 = 1 << 9;
    pub const MASTER: u32 = 1 << 10;
    pub const SLAVE: u32 = 1 << 11;
    pub const MULTICAST: u32 = 1 << 12;
    pub const PORTSEL: u32 = 1 << 13;
    pub const AUTOMEDIA: u32 = 1 << 14;
    pub const DYNAMIC: u32 = 1 << 15;
    pub const LOWER_UP: u32 = 1 << 16;
    pub const DORMANT: u32 = 1 << 17;
    pub const ECHO: u32 = 1 << 18;
}

/// Operational state (IF_OPER_*).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum OperState {
    Unknown = 0,
    NotPresent = 1,
    Down = 2,
    LowerLayerDown = 3,
    Testing = 4,
    Dormant = 5,
    Up = 6,
}

impl From<u8> for OperState {
    fn from(val: u8) -> Self {
        match val {
            0 => Self::Unknown,
            1 => Self::NotPresent,
            2 => Self::Down,
            3 => Self::LowerLayerDown,
            4 => Self::Testing,
            5 => Self::Dormant,
            6 => Self::Up,
            _ => Self::Unknown,
        }
    }
}

impl OperState {
    /// Get the name of this state.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Unknown => "UNKNOWN",
            Self::NotPresent => "NOT_PRESENT",
            Self::Down => "DOWN",
            Self::LowerLayerDown => "LOWERLAYERDOWN",
            Self::Testing => "TESTING",
            Self::Dormant => "DORMANT",
            Self::Up => "UP",
        }
    }
}

/// Link statistics (struct rtnl_link_stats64).
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct LinkStats64 {
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
    // Detailed rx errors
    pub rx_length_errors: u64,
    pub rx_over_errors: u64,
    pub rx_crc_errors: u64,
    pub rx_frame_errors: u64,
    pub rx_fifo_errors: u64,
    pub rx_missed_errors: u64,
    // Detailed tx errors
    pub tx_aborted_errors: u64,
    pub tx_carrier_errors: u64,
    pub tx_fifo_errors: u64,
    pub tx_heartbeat_errors: u64,
    pub tx_window_errors: u64,
    // For cslip etc
    pub rx_compressed: u64,
    pub tx_compressed: u64,
    pub rx_nohandler: u64,
}

impl LinkStats64 {
    /// Parse from bytes.
    pub fn from_bytes(data: &[u8]) -> Option<&Self> {
        if data.len() >= std::mem::size_of::<Self>() {
            Some(unsafe { &*(data.as_ptr() as *const Self) })
        } else {
            None
        }
    }
}
