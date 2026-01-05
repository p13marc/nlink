//! Ethtool response types.
//!
//! This module contains strongly-typed structures for ethtool query responses.

use std::collections::HashMap;

use super::EthtoolBitset;

// =============================================================================
// Common Types
// =============================================================================

/// Duplex mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Duplex {
    /// Half duplex.
    Half,
    /// Full duplex.
    Full,
    /// Unknown duplex.
    #[default]
    Unknown,
}

impl Duplex {
    /// Parse from kernel value.
    pub fn from_u8(v: u8) -> Self {
        match v {
            0x00 => Duplex::Half,
            0x01 => Duplex::Full,
            _ => Duplex::Unknown,
        }
    }

    /// Convert to kernel value.
    pub fn to_u8(self) -> u8 {
        match self {
            Duplex::Half => 0x00,
            Duplex::Full => 0x01,
            Duplex::Unknown => 0xff,
        }
    }
}

/// Port type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Port {
    /// Twisted pair (RJ45).
    Tp,
    /// Attachment Unit Interface.
    Aui,
    /// Media Independent Interface.
    Mii,
    /// Fiber optic.
    Fibre,
    /// BNC connector.
    Bnc,
    /// Direct attach (copper SFP+).
    Da,
    /// No port.
    None,
    /// Other port type.
    #[default]
    Other,
}

impl Port {
    /// Parse from kernel value.
    pub fn from_u8(v: u8) -> Self {
        match v {
            0x00 => Port::Tp,
            0x01 => Port::Aui,
            0x02 => Port::Mii,
            0x03 => Port::Fibre,
            0x04 => Port::Bnc,
            0x05 => Port::Da,
            0xef => Port::None,
            _ => Port::Other,
        }
    }
}

/// Transceiver type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Transceiver {
    /// Internal transceiver.
    Internal,
    /// External transceiver.
    External,
    /// Unknown transceiver.
    #[default]
    Unknown,
}

impl Transceiver {
    /// Parse from kernel value.
    pub fn from_u8(v: u8) -> Self {
        match v {
            0x00 => Transceiver::Internal,
            0x01 => Transceiver::External,
            _ => Transceiver::Unknown,
        }
    }
}

/// MDI-X status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MdiX {
    /// MDI (straight-through).
    Mdi,
    /// MDI-X (crossover).
    MdiX,
    /// Auto MDI-X.
    Auto,
    /// Unknown.
    #[default]
    Unknown,
}

impl MdiX {
    /// Parse from kernel value.
    pub fn from_u8(v: u8) -> Self {
        match v {
            0x00 => MdiX::Mdi,
            0x01 => MdiX::MdiX,
            0x02 => MdiX::Auto,
            _ => MdiX::Unknown,
        }
    }
}

/// Extended link state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LinkExtState {
    /// Link is up.
    #[default]
    Ok,
    /// Autonegotiation in progress.
    Autoneg,
    /// Link training failure.
    LinkTrainingFailure,
    /// Link logical mismatch.
    LinkLogicalMismatch,
    /// Bad signal integrity.
    BadSignalIntegrity,
    /// No cable.
    NoCable,
    /// Cable issue.
    CableIssue,
    /// EEPROM issue.
    EepromIssue,
    /// Calibration failure.
    CalibrationFailure,
    /// Power budget exceeded.
    PowerBudgetExceeded,
    /// Overheat.
    Overheat,
    /// Module not present.
    ModuleNotPresent,
}

impl LinkExtState {
    /// Parse from kernel value.
    pub fn from_u8(v: u8) -> Self {
        match v {
            1 => LinkExtState::Autoneg,
            2 => LinkExtState::LinkTrainingFailure,
            3 => LinkExtState::LinkLogicalMismatch,
            4 => LinkExtState::BadSignalIntegrity,
            5 => LinkExtState::NoCable,
            6 => LinkExtState::CableIssue,
            7 => LinkExtState::EepromIssue,
            8 => LinkExtState::CalibrationFailure,
            9 => LinkExtState::PowerBudgetExceeded,
            10 => LinkExtState::Overheat,
            11 => LinkExtState::ModuleNotPresent,
            _ => LinkExtState::Ok,
        }
    }
}

// =============================================================================
// Link State
// =============================================================================

/// Link state information.
///
/// Contains the current link status including carrier detection,
/// signal quality, and extended state information.
#[derive(Debug, Clone, Default)]
pub struct LinkState {
    /// Interface name.
    pub ifname: Option<String>,
    /// Interface index.
    pub ifindex: Option<u32>,
    /// Link is detected (carrier present).
    pub link: bool,
    /// Signal Quality Index (0-100, if supported).
    pub sqi: Option<u32>,
    /// Maximum SQI value supported by the device.
    pub sqi_max: Option<u32>,
    /// Extended link state (reason for link down).
    pub ext_state: Option<LinkExtState>,
    /// Extended link substate (additional detail).
    pub ext_substate: Option<u8>,
}

// =============================================================================
// Link Info
// =============================================================================

/// Link information.
///
/// Contains physical layer information about the link.
#[derive(Debug, Clone, Default)]
pub struct LinkInfo {
    /// Interface name.
    pub ifname: Option<String>,
    /// Interface index.
    pub ifindex: Option<u32>,
    /// Physical port type.
    pub port: Option<Port>,
    /// PHY address.
    pub phyaddr: Option<u8>,
    /// MDI-X control setting.
    pub tp_mdix_ctrl: Option<MdiX>,
    /// Current MDI-X status.
    pub tp_mdix: Option<MdiX>,
    /// Transceiver type.
    pub transceiver: Option<Transceiver>,
}

// =============================================================================
// Link Modes
// =============================================================================

/// Link modes configuration.
///
/// Contains speed, duplex, and autonegotiation settings.
#[derive(Debug, Clone, Default)]
pub struct LinkModes {
    /// Interface name.
    pub ifname: Option<String>,
    /// Interface index.
    pub ifindex: Option<u32>,
    /// Autonegotiation enabled.
    pub autoneg: bool,
    /// Current speed in Mb/s.
    pub speed: Option<u32>,
    /// Current duplex mode.
    pub duplex: Option<Duplex>,
    /// Number of lanes (for multi-lane links).
    pub lanes: Option<u32>,
    /// Master/slave configuration.
    pub master_slave_cfg: Option<u8>,
    /// Master/slave state.
    pub master_slave_state: Option<u8>,
    /// Supported link modes.
    pub supported: EthtoolBitset,
    /// Advertised link modes.
    pub advertised: EthtoolBitset,
    /// Peer's advertised link modes.
    pub peer: EthtoolBitset,
}

impl LinkModes {
    /// Check if a specific mode is supported.
    pub fn supports(&self, mode: &str) -> bool {
        self.supported.is_set(mode)
    }

    /// Check if a specific mode is advertised.
    pub fn advertises(&self, mode: &str) -> bool {
        self.advertised.is_set(mode)
    }

    /// Get list of supported mode names.
    pub fn supported_modes(&self) -> Vec<&str> {
        self.supported.active_names()
    }

    /// Get list of advertised mode names.
    pub fn advertised_modes(&self) -> Vec<&str> {
        self.advertised.active_names()
    }
}

/// Builder for setting link modes.
#[derive(Debug, Clone, Default)]
pub struct LinkModesBuilder {
    pub(crate) autoneg: Option<bool>,
    pub(crate) speed: Option<u32>,
    pub(crate) duplex: Option<Duplex>,
    pub(crate) lanes: Option<u32>,
    pub(crate) advertised: Vec<String>,
}

impl LinkModesBuilder {
    /// Create a new builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set autonegotiation on or off.
    pub fn autoneg(mut self, enabled: bool) -> Self {
        self.autoneg = Some(enabled);
        self
    }

    /// Set speed in Mb/s.
    pub fn speed(mut self, speed: u32) -> Self {
        self.speed = Some(speed);
        self
    }

    /// Set duplex mode.
    pub fn duplex(mut self, duplex: Duplex) -> Self {
        self.duplex = Some(duplex);
        self
    }

    /// Set number of lanes.
    pub fn lanes(mut self, lanes: u32) -> Self {
        self.lanes = Some(lanes);
        self
    }

    /// Advertise a specific link mode.
    pub fn advertise(mut self, mode: &str) -> Self {
        self.advertised.push(mode.to_string());
        self
    }

    /// Advertise multiple link modes.
    pub fn advertise_modes(mut self, modes: &[&str]) -> Self {
        for mode in modes {
            self.advertised.push((*mode).to_string());
        }
        self
    }
}

// =============================================================================
// Features
// =============================================================================

/// Device features (offloads).
///
/// Contains information about hardware and software features.
#[derive(Debug, Clone, Default)]
pub struct Features {
    /// Interface name.
    pub ifname: Option<String>,
    /// Interface index.
    pub ifindex: Option<u32>,
    /// Hardware-supported features.
    pub hw: EthtoolBitset,
    /// Requested features.
    pub wanted: EthtoolBitset,
    /// Currently active features.
    pub active: EthtoolBitset,
    /// Features that cannot be changed.
    pub nochange: EthtoolBitset,
}

impl Features {
    /// Check if a feature is currently active.
    pub fn is_active(&self, feature: &str) -> bool {
        self.active.is_set(feature)
    }

    /// Check if a feature is supported by hardware.
    pub fn is_hw_supported(&self, feature: &str) -> bool {
        self.hw.is_set(feature)
    }

    /// Check if a feature can be changed.
    pub fn is_changeable(&self, feature: &str) -> bool {
        !self.nochange.is_set(feature)
    }

    /// Get all active feature names.
    pub fn active_features(&self) -> Vec<&str> {
        self.active.active_names()
    }

    /// Iterate over all features with their status.
    pub fn iter(&self) -> impl Iterator<Item = (&str, bool)> {
        self.active.iter()
    }
}

/// Builder for setting features.
#[derive(Debug, Clone, Default)]
pub struct FeaturesBuilder {
    pub(crate) enable: Vec<String>,
    pub(crate) disable: Vec<String>,
}

impl FeaturesBuilder {
    /// Create a new builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Enable a feature.
    pub fn enable(mut self, feature: &str) -> Self {
        self.enable.push(feature.to_string());
        self
    }

    /// Disable a feature.
    pub fn disable(mut self, feature: &str) -> Self {
        self.disable.push(feature.to_string());
        self
    }
}

// =============================================================================
// Rings
// =============================================================================

/// Ring buffer sizes.
///
/// Contains current and maximum ring buffer sizes for RX and TX.
#[derive(Debug, Clone, Default)]
pub struct Rings {
    /// Interface name.
    pub ifname: Option<String>,
    /// Interface index.
    pub ifindex: Option<u32>,
    /// Maximum RX ring size.
    pub rx_max: Option<u32>,
    /// Maximum RX mini ring size.
    pub rx_mini_max: Option<u32>,
    /// Maximum RX jumbo ring size.
    pub rx_jumbo_max: Option<u32>,
    /// Maximum TX ring size.
    pub tx_max: Option<u32>,
    /// Current RX ring size.
    pub rx: Option<u32>,
    /// Current RX mini ring size.
    pub rx_mini: Option<u32>,
    /// Current RX jumbo ring size.
    pub rx_jumbo: Option<u32>,
    /// Current TX ring size.
    pub tx: Option<u32>,
    /// RX buffer length.
    pub rx_buf_len: Option<u32>,
    /// CQE size.
    pub cqe_size: Option<u32>,
    /// TX push enabled.
    pub tx_push: Option<bool>,
    /// RX push enabled.
    pub rx_push: Option<bool>,
}

/// Builder for setting ring sizes.
#[derive(Debug, Clone, Default)]
pub struct RingsBuilder {
    pub(crate) rx: Option<u32>,
    pub(crate) rx_mini: Option<u32>,
    pub(crate) rx_jumbo: Option<u32>,
    pub(crate) tx: Option<u32>,
}

impl RingsBuilder {
    /// Create a new builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set RX ring size.
    pub fn rx(mut self, size: u32) -> Self {
        self.rx = Some(size);
        self
    }

    /// Set RX mini ring size.
    pub fn rx_mini(mut self, size: u32) -> Self {
        self.rx_mini = Some(size);
        self
    }

    /// Set RX jumbo ring size.
    pub fn rx_jumbo(mut self, size: u32) -> Self {
        self.rx_jumbo = Some(size);
        self
    }

    /// Set TX ring size.
    pub fn tx(mut self, size: u32) -> Self {
        self.tx = Some(size);
        self
    }
}

// =============================================================================
// Channels
// =============================================================================

/// Channel counts.
///
/// Contains current and maximum channel (queue) counts.
#[derive(Debug, Clone, Default)]
pub struct Channels {
    /// Interface name.
    pub ifname: Option<String>,
    /// Interface index.
    pub ifindex: Option<u32>,
    /// Maximum RX channels.
    pub rx_max: Option<u32>,
    /// Maximum TX channels.
    pub tx_max: Option<u32>,
    /// Maximum other channels.
    pub other_max: Option<u32>,
    /// Maximum combined channels.
    pub combined_max: Option<u32>,
    /// Current RX channels.
    pub rx_count: Option<u32>,
    /// Current TX channels.
    pub tx_count: Option<u32>,
    /// Current other channels.
    pub other_count: Option<u32>,
    /// Current combined channels.
    pub combined_count: Option<u32>,
}

/// Builder for setting channel counts.
#[derive(Debug, Clone, Default)]
pub struct ChannelsBuilder {
    pub(crate) rx: Option<u32>,
    pub(crate) tx: Option<u32>,
    pub(crate) other: Option<u32>,
    pub(crate) combined: Option<u32>,
}

impl ChannelsBuilder {
    /// Create a new builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set RX channel count.
    pub fn rx(mut self, count: u32) -> Self {
        self.rx = Some(count);
        self
    }

    /// Set TX channel count.
    pub fn tx(mut self, count: u32) -> Self {
        self.tx = Some(count);
        self
    }

    /// Set other channel count.
    pub fn other(mut self, count: u32) -> Self {
        self.other = Some(count);
        self
    }

    /// Set combined channel count.
    pub fn combined(mut self, count: u32) -> Self {
        self.combined = Some(count);
        self
    }
}

// =============================================================================
// Coalesce
// =============================================================================

/// Interrupt coalescing parameters.
#[derive(Debug, Clone, Default)]
pub struct Coalesce {
    /// Interface name.
    pub ifname: Option<String>,
    /// Interface index.
    pub ifindex: Option<u32>,
    /// RX coalesce microseconds.
    pub rx_usecs: Option<u32>,
    /// RX max frames before interrupt.
    pub rx_max_frames: Option<u32>,
    /// RX coalesce microseconds (irq context).
    pub rx_usecs_irq: Option<u32>,
    /// RX max frames (irq context).
    pub rx_max_frames_irq: Option<u32>,
    /// TX coalesce microseconds.
    pub tx_usecs: Option<u32>,
    /// TX max frames before interrupt.
    pub tx_max_frames: Option<u32>,
    /// TX coalesce microseconds (irq context).
    pub tx_usecs_irq: Option<u32>,
    /// TX max frames (irq context).
    pub tx_max_frames_irq: Option<u32>,
    /// Stats block update microseconds.
    pub stats_block_usecs: Option<u32>,
    /// Use adaptive RX coalescing.
    pub use_adaptive_rx: Option<bool>,
    /// Use adaptive TX coalescing.
    pub use_adaptive_tx: Option<bool>,
    /// Packet rate low threshold.
    pub pkt_rate_low: Option<u32>,
    /// Packet rate high threshold.
    pub pkt_rate_high: Option<u32>,
    /// Rate sample interval.
    pub rate_sample_interval: Option<u32>,
}

/// Builder for setting coalescing parameters.
#[derive(Debug, Clone, Default)]
pub struct CoalesceBuilder {
    pub(crate) rx_usecs: Option<u32>,
    pub(crate) rx_max_frames: Option<u32>,
    pub(crate) tx_usecs: Option<u32>,
    pub(crate) tx_max_frames: Option<u32>,
    pub(crate) use_adaptive_rx: Option<bool>,
    pub(crate) use_adaptive_tx: Option<bool>,
}

impl CoalesceBuilder {
    /// Create a new builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set RX coalesce microseconds.
    pub fn rx_usecs(mut self, usecs: u32) -> Self {
        self.rx_usecs = Some(usecs);
        self
    }

    /// Set RX max frames before interrupt.
    pub fn rx_max_frames(mut self, frames: u32) -> Self {
        self.rx_max_frames = Some(frames);
        self
    }

    /// Set TX coalesce microseconds.
    pub fn tx_usecs(mut self, usecs: u32) -> Self {
        self.tx_usecs = Some(usecs);
        self
    }

    /// Set TX max frames before interrupt.
    pub fn tx_max_frames(mut self, frames: u32) -> Self {
        self.tx_max_frames = Some(frames);
        self
    }

    /// Enable or disable adaptive RX coalescing.
    pub fn use_adaptive_rx(mut self, enabled: bool) -> Self {
        self.use_adaptive_rx = Some(enabled);
        self
    }

    /// Enable or disable adaptive TX coalescing.
    pub fn use_adaptive_tx(mut self, enabled: bool) -> Self {
        self.use_adaptive_tx = Some(enabled);
        self
    }
}

// =============================================================================
// Pause
// =============================================================================

/// Pause/flow control settings.
#[derive(Debug, Clone, Default)]
pub struct Pause {
    /// Interface name.
    pub ifname: Option<String>,
    /// Interface index.
    pub ifindex: Option<u32>,
    /// Autonegotiation of pause enabled.
    pub autoneg: Option<bool>,
    /// RX pause enabled.
    pub rx: Option<bool>,
    /// TX pause enabled.
    pub tx: Option<bool>,
    /// Pause statistics.
    pub stats: Option<PauseStats>,
}

/// Pause statistics.
#[derive(Debug, Clone, Default)]
pub struct PauseStats {
    /// TX pause frames sent.
    pub tx_frames: Option<u64>,
    /// RX pause frames received.
    pub rx_frames: Option<u64>,
}

/// Builder for setting pause parameters.
#[derive(Debug, Clone, Default)]
pub struct PauseBuilder {
    pub(crate) autoneg: Option<bool>,
    pub(crate) rx: Option<bool>,
    pub(crate) tx: Option<bool>,
}

impl PauseBuilder {
    /// Create a new builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set autonegotiation of pause.
    pub fn autoneg(mut self, enabled: bool) -> Self {
        self.autoneg = Some(enabled);
        self
    }

    /// Set RX pause.
    pub fn rx(mut self, enabled: bool) -> Self {
        self.rx = Some(enabled);
        self
    }

    /// Set TX pause.
    pub fn tx(mut self, enabled: bool) -> Self {
        self.tx = Some(enabled);
        self
    }
}

// =============================================================================
// String Sets
// =============================================================================

/// A string set from the device.
#[derive(Debug, Clone, Default)]
pub struct StringSet {
    /// String set ID.
    pub id: u32,
    /// Strings in the set, indexed by position.
    pub strings: HashMap<u32, String>,
}

impl StringSet {
    /// Get a string by index.
    pub fn get(&self, index: u32) -> Option<&str> {
        self.strings.get(&index).map(|s| s.as_str())
    }

    /// Get all strings as a vector.
    pub fn to_vec(&self) -> Vec<&str> {
        let mut result: Vec<_> = self.strings.iter().collect();
        result.sort_by_key(|(idx, _)| *idx);
        result.into_iter().map(|(_, s)| s.as_str()).collect()
    }
}

// =============================================================================
// Events
// =============================================================================

/// Ethtool event received from the monitor multicast group.
#[derive(Debug, Clone)]
pub enum EthtoolEvent {
    /// Link info changed.
    LinkInfoChanged {
        /// Interface name.
        ifname: Option<String>,
        /// New link info.
        info: LinkInfo,
    },
    /// Link modes changed.
    LinkModesChanged {
        /// Interface name.
        ifname: Option<String>,
        /// New link modes.
        modes: LinkModes,
    },
    /// Link state changed.
    LinkStateChanged {
        /// Interface name.
        ifname: Option<String>,
        /// New link state.
        state: LinkState,
    },
    /// Features changed.
    FeaturesChanged {
        /// Interface name.
        ifname: Option<String>,
        /// New features.
        features: Features,
    },
    /// Ring sizes changed.
    RingsChanged {
        /// Interface name.
        ifname: Option<String>,
        /// New ring sizes.
        rings: Rings,
    },
    /// Channel counts changed.
    ChannelsChanged {
        /// Interface name.
        ifname: Option<String>,
        /// New channel counts.
        channels: Channels,
    },
    /// Coalesce parameters changed.
    CoalesceChanged {
        /// Interface name.
        ifname: Option<String>,
        /// New coalesce parameters.
        coalesce: Coalesce,
    },
    /// Pause settings changed.
    PauseChanged {
        /// Interface name.
        ifname: Option<String>,
        /// New pause settings.
        pause: Pause,
    },
    /// Unknown or unhandled event.
    Unknown {
        /// Command that generated this event.
        cmd: u8,
    },
}
