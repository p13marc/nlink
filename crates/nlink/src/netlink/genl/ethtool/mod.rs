//! Ethtool configuration via Generic Netlink.
//!
//! This module provides an API for querying and configuring network device
//! settings using the kernel's ethtool netlink interface (available since
//! Linux 5.6).
//!
//! # Overview
//!
//! Ethtool provides access to:
//! - Link state (up/down, speed, duplex)
//! - Link modes (autonegotiation, advertised speeds)
//! - Device features (offloads, checksumming)
//! - Ring buffer sizes
//! - Channel counts (RX/TX queues)
//! - Interrupt coalescing
//! - Pause/flow control
//! - Statistics
//! - SFP/QSFP module information
//!
//! # Example
//!
//! ```rust,no_run
//! use nlink::netlink::{Connection, Ethtool};
//!
//! # async fn example() -> nlink::Result<()> {
//! let conn = Connection::<Ethtool>::new_async().await?;
//!
//! // Query link state
//! let state = conn.get_link_state("eth0").await?;
//! println!("Link: {}", if state.link { "up" } else { "down" });
//!
//! // Query link modes
//! let modes = conn.get_link_modes("eth0").await?;
//! println!("Speed: {:?} Mb/s", modes.speed);
//! println!("Duplex: {:?}", modes.duplex);
//! # Ok(())
//! # }
//! ```
//!
//! # Setting Configuration
//!
//! ```rust,no_run
//! use nlink::netlink::{Connection, Ethtool};
//!
//! # async fn example() -> nlink::Result<()> {
//! let conn = Connection::<Ethtool>::new_async().await?;
//!
//! // Set link modes
//! conn.set_link_modes("eth0", |m| {
//!     m.autoneg(true)
//!      .speed(1000)
//!      .duplex(nlink::netlink::genl::ethtool::Duplex::Full)
//! }).await?;
//!
//! // Query and modify features
//! let features = conn.get_features("eth0").await?;
//! println!("TSO: {}", features.is_active("tx-tcp-segmentation"));
//! # Ok(())
//! # }
//! ```

mod bitset;
mod connection;
mod types;

pub use bitset::EthtoolBitset;
pub use types::*;

/// Ethtool Generic Netlink family name.
pub const ETHTOOL_GENL_NAME: &str = "ethtool";

/// Ethtool Generic Netlink version.
pub const ETHTOOL_GENL_VERSION: u8 = 1;

/// Ethtool multicast group for monitoring.
pub const ETHTOOL_MCGRP_MONITOR: &str = "monitor";

// =============================================================================
// Commands
// =============================================================================

/// Ethtool netlink commands.
///
/// Commands ending in `Get` retrieve information, `Set` modify parameters,
/// and `Act` perform actions.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EthtoolCmd {
    /// Get string set (enumerate available options).
    StrsetGet = 1,
    /// Get link info (port type, MDI-X, transceiver).
    LinkinfoGet = 2,
    /// Set link info.
    LinkinfoSet = 3,
    /// Get link modes (speed, duplex, autoneg).
    LinkmodesGet = 4,
    /// Set link modes.
    LinkmodesSet = 5,
    /// Get link state (carrier, SQI).
    LinkstateGet = 6,
    /// Get debug settings.
    DebugGet = 7,
    /// Set debug settings.
    DebugSet = 8,
    /// Get Wake-on-LAN settings.
    WolGet = 9,
    /// Set Wake-on-LAN settings.
    WolSet = 10,
    /// Get device features (offloads).
    FeaturesGet = 11,
    /// Set device features.
    FeaturesSet = 12,
    /// Get private flags.
    PrivflagsGet = 13,
    /// Set private flags.
    PrivflagsSet = 14,
    /// Get ring buffer sizes.
    RingsGet = 15,
    /// Set ring buffer sizes.
    RingsSet = 16,
    /// Get channel counts.
    ChannelsGet = 17,
    /// Set channel counts.
    ChannelsSet = 18,
    /// Get interrupt coalescing parameters.
    CoalesceGet = 19,
    /// Set interrupt coalescing parameters.
    CoalesceSet = 20,
    /// Get pause/flow control settings.
    PauseGet = 21,
    /// Set pause/flow control settings.
    PauseSet = 22,
    /// Get Energy Efficient Ethernet settings.
    EeeGet = 23,
    /// Set Energy Efficient Ethernet settings.
    EeeSet = 24,
    /// Get timestamping info.
    TsinfoGet = 25,
    /// Start cable test.
    CableTestAct = 26,
    /// Start TDR cable test.
    CableTestTdrAct = 27,
    /// Get tunnel offload info.
    TunnelInfoGet = 28,
    /// Get Forward Error Correction settings.
    FecGet = 29,
    /// Set Forward Error Correction settings.
    FecSet = 30,
    /// Get SFP module EEPROM.
    ModuleEepromGet = 31,
    /// Get standard statistics.
    StatsGet = 32,
    /// Get PHC virtual clocks.
    PhcVclocksGet = 33,
    /// Get transceiver module parameters.
    ModuleGet = 34,
    /// Set transceiver module parameters.
    ModuleSet = 35,
    /// Get Power Sourcing Equipment status.
    PseGet = 36,
    /// Set Power Sourcing Equipment parameters.
    PseSet = 37,
    /// Get Receive Side Scaling settings.
    RssGet = 38,
    /// Get PLCA RS configuration.
    PlcaGetCfg = 39,
    /// Set PLCA RS configuration.
    PlcaSetCfg = 40,
    /// Get PLCA RS status.
    PlcaGetStatus = 41,
    /// Get MAC Merge layer state.
    MmGet = 42,
    /// Set MAC Merge layer configuration.
    MmSet = 43,
    /// Get PHY information.
    PhyGet = 44,
}

// =============================================================================
// Header Attributes
// =============================================================================

/// Attributes for the request header (nested under ETHTOOL_A_HEADER).
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EthtoolHeaderAttr {
    Unspec = 0,
    /// Device interface index (u32).
    DevIndex = 1,
    /// Device name (string).
    DevName = 2,
    /// Request flags (u32).
    Flags = 3,
    /// PHY device index (u32, optional).
    PhyIndex = 4,
}

/// Request flags for ethtool commands.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EthtoolFlag {
    /// Use compact bitset format in reply.
    CompactBitsets = 1 << 0,
    /// Don't send reply for SET commands.
    OmitReply = 1 << 1,
    /// Include statistics in reply.
    Stats = 1 << 2,
}

// =============================================================================
// Bitset Attributes
// =============================================================================

/// Attributes for bitset encoding.
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EthtoolBitsetAttr {
    Unspec = 0,
    /// Bitset is a list of bit names (flag).
    Nomask = 1,
    /// Number of significant bits (u32).
    Size = 2,
    /// Nested list of bits.
    Bits = 3,
    /// Compact bitmap of values.
    Value = 4,
    /// Compact bitmap of mask.
    Mask = 5,
}

/// Attributes for individual bits in a bitset.
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EthtoolBitsetBitAttr {
    Unspec = 0,
    /// Bit index (u32).
    Index = 1,
    /// Bit name (string).
    Name = 2,
    /// Bit is set (flag).
    Value = 3,
}

// =============================================================================
// String Set Attributes
// =============================================================================

/// Attributes for string set queries.
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EthtoolStrsetAttr {
    Unspec = 0,
    /// Request header (nested).
    Header = 1,
    /// Nested list of string sets.
    Stringsets = 2,
    /// Include counts only (flag).
    CountsOnly = 3,
}

/// Attributes for individual string sets.
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EthtoolStringsetAttr {
    Unspec = 0,
    /// String set ID (u32).
    Id = 1,
    /// Number of strings (u32).
    Count = 2,
    /// Nested list of strings.
    Strings = 3,
}

/// Attributes for individual strings.
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EthtoolStringAttr {
    Unspec = 0,
    /// String index (u32).
    Index = 1,
    /// String value.
    Value = 2,
}

/// String set IDs.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EthtoolStringSet {
    /// Test strings.
    Test = 0,
    /// Statistic names.
    Stats = 1,
    /// Private flags.
    PrivFlags = 2,
    /// N-tuple filter strings.
    NtupleFltrs = 3,
    /// RSS hash function names.
    RssHashFuncs = 4,
    /// Tunables.
    Tunables = 5,
    /// PHY statistics.
    PhyStats = 6,
    /// PHY tunables.
    PhyTunables = 7,
    /// Link modes (speeds).
    LinkModes = 8,
    /// Message levels.
    MsgClasses = 9,
    /// WoL modes.
    WolModes = 10,
    /// SOF timestamping.
    SofTimestamping = 11,
    /// TX timestamping types.
    TsTypes = 12,
    /// RX filters.
    RxFilters = 13,
    /// RSS contexts.
    RssContexts = 14,
    /// Stats standard groups.
    StatsStd = 15,
    /// Stats ethernet.
    StatsEth = 16,
    /// Stats ethernet PHY.
    StatsEthPhy = 17,
    /// Stats ethernet MAC.
    StatsEthMac = 18,
    /// Stats ethernet control.
    StatsEthCtrl = 19,
    /// Stats RMON.
    StatsRmon = 20,
}

// =============================================================================
// Link Info Attributes
// =============================================================================

/// Attributes for link info.
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EthtoolLinkinfoAttr {
    Unspec = 0,
    /// Request header (nested).
    Header = 1,
    /// Physical port type (u8).
    Port = 2,
    /// Physical medium type (u8).
    Phyaddr = 3,
    /// Transceiver type (u8).
    TpMdiCtrl = 4,
    /// Link TP MDI status (u8).
    TpMdix = 5,
    /// Transceiver type (u8).
    Transceiver = 6,
}

// =============================================================================
// Link Modes Attributes
// =============================================================================

/// Attributes for link modes.
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EthtoolLinkmodesAttr {
    Unspec = 0,
    /// Request header (nested).
    Header = 1,
    /// Autonegotiation enabled (u8).
    Autoneg = 2,
    /// Supported link modes (bitset).
    Supported = 3,
    /// Advertised link modes (bitset).
    Advertised = 4,
    /// Peer advertised link modes (bitset).
    Peer = 5,
    /// Current speed in Mb/s (u32).
    Speed = 6,
    /// Current duplex (u8).
    Duplex = 7,
    /// Wake-on-LAN modes (u32).
    MasterSlaveCfg = 8,
    /// Master/slave state (u8).
    MasterSlaveState = 9,
    /// Number of lanes (u32).
    Lanes = 10,
    /// Rate matching (u8).
    RateMatching = 11,
}

// =============================================================================
// Link State Attributes
// =============================================================================

/// Attributes for link state.
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EthtoolLinkstateAttr {
    Unspec = 0,
    /// Request header (nested).
    Header = 1,
    /// Link detected (u8, boolean).
    Link = 2,
    /// Signal Quality Index (u32).
    Sqi = 3,
    /// Maximum SQI value (u32).
    SqiMax = 4,
    /// Extended link state (u8).
    ExtState = 5,
    /// Extended link substate (u8).
    ExtSubstate = 6,
    /// Extended link down reason (u32).
    ExtDownCnt = 7,
}

// =============================================================================
// Features Attributes
// =============================================================================

/// Attributes for device features.
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EthtoolFeaturesAttr {
    Unspec = 0,
    /// Request header (nested).
    Header = 1,
    /// Hardware features (bitset).
    Hw = 2,
    /// Features that can be changed (bitset).
    Wanted = 3,
    /// Currently active features (bitset).
    Active = 4,
    /// Features that cannot be changed (bitset).
    NoChange = 5,
}

// =============================================================================
// Rings Attributes
// =============================================================================

/// Attributes for ring buffer sizes.
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EthtoolRingsAttr {
    Unspec = 0,
    /// Request header (nested).
    Header = 1,
    /// Maximum RX ring size (u32).
    RxMax = 2,
    /// Maximum RX mini ring size (u32).
    RxMiniMax = 3,
    /// Maximum RX jumbo ring size (u32).
    RxJumboMax = 4,
    /// Maximum TX ring size (u32).
    TxMax = 5,
    /// Current RX ring size (u32).
    Rx = 6,
    /// Current RX mini ring size (u32).
    RxMini = 7,
    /// Current RX jumbo ring size (u32).
    RxJumbo = 8,
    /// Current TX ring size (u32).
    Tx = 9,
    /// RX buffer length (u32).
    RxBufLen = 10,
    /// TCP data split (u8).
    TcpDataSplit = 11,
    /// CQE size (u32).
    CqeSize = 12,
    /// TX push enabled (u8).
    TxPush = 13,
    /// RX push enabled (u8).
    RxPush = 14,
    /// TX push buffer length (u32).
    TxPushBufLen = 15,
    /// Maximum TX push buffer length (u32).
    TxPushBufLenMax = 16,
}

// =============================================================================
// Channels Attributes
// =============================================================================

/// Attributes for channel counts.
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EthtoolChannelsAttr {
    Unspec = 0,
    /// Request header (nested).
    Header = 1,
    /// Maximum RX channels (u32).
    RxMax = 2,
    /// Maximum TX channels (u32).
    TxMax = 3,
    /// Maximum other channels (u32).
    OtherMax = 4,
    /// Maximum combined channels (u32).
    CombinedMax = 5,
    /// Current RX channels (u32).
    RxCount = 6,
    /// Current TX channels (u32).
    TxCount = 7,
    /// Current other channels (u32).
    OtherCount = 8,
    /// Current combined channels (u32).
    CombinedCount = 9,
}

// =============================================================================
// Coalesce Attributes
// =============================================================================

/// Attributes for interrupt coalescing.
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EthtoolCoalesceAttr {
    Unspec = 0,
    /// Request header (nested).
    Header = 1,
    /// RX coalesce usecs (u32).
    RxUsecs = 2,
    /// RX max frames (u32).
    RxMaxFrames = 3,
    /// RX coalesce usecs irq (u32).
    RxUsecsIrq = 4,
    /// RX max frames irq (u32).
    RxMaxFramesIrq = 5,
    /// TX coalesce usecs (u32).
    TxUsecs = 6,
    /// TX max frames (u32).
    TxMaxFrames = 7,
    /// TX coalesce usecs irq (u32).
    TxUsecsIrq = 8,
    /// TX max frames irq (u32).
    TxMaxFramesIrq = 9,
    /// Stats block usecs (u32).
    StatsBlockUsecs = 10,
    /// Use adaptive RX coalescing (u8).
    UseAdaptiveRx = 11,
    /// Use adaptive TX coalescing (u8).
    UseAdaptiveTx = 12,
    /// Packet rate low (u32).
    PktRateLow = 13,
    /// RX usecs low (u32).
    RxUsecsLow = 14,
    /// RX max frames low (u32).
    RxMaxFramesLow = 15,
    /// TX usecs low (u32).
    TxUsecsLow = 16,
    /// TX max frames low (u32).
    TxMaxFramesLow = 17,
    /// Packet rate high (u32).
    PktRateHigh = 18,
    /// RX usecs high (u32).
    RxUsecsHigh = 19,
    /// RX max frames high (u32).
    RxMaxFramesHigh = 20,
    /// TX usecs high (u32).
    TxUsecsHigh = 21,
    /// TX max frames high (u32).
    TxMaxFramesHigh = 22,
    /// Sample interval (u32).
    RateSampleInterval = 23,
    /// Use CQE mode RX (u8).
    UseCqeRx = 24,
    /// Use CQE mode TX (u8).
    UseCqeTx = 25,
    /// TX aggregate max bytes (u32).
    TxAggrMaxBytes = 26,
    /// TX aggregate max frames (u32).
    TxAggrMaxFrames = 27,
    /// TX aggregate time usecs (u32).
    TxAggrTimeUsecs = 28,
}

// =============================================================================
// Pause Attributes
// =============================================================================

/// Attributes for pause/flow control.
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EthtoolPauseAttr {
    Unspec = 0,
    /// Request header (nested).
    Header = 1,
    /// Autonegotiation enabled (u8).
    Autoneg = 2,
    /// RX pause enabled (u8).
    Rx = 3,
    /// TX pause enabled (u8).
    Tx = 4,
    /// Pause statistics (nested).
    Stats = 5,
    /// RX source select (u32).
    StatsRxSrc = 6,
}

// =============================================================================
// Statistics Attributes
// =============================================================================

/// Attributes for statistics.
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EthtoolStatsAttr {
    Unspec = 0,
    /// Request header (nested).
    Header = 1,
    /// Stat groups to query (bitset).
    Groups = 2,
    /// GRP nested stats.
    Grp = 3,
    /// Source for stats (u32).
    Src = 4,
}
