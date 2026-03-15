//! nl80211 data types.

use crate::netlink::error::{Error, Result};

/// Wireless interface operating mode.
///
/// Maps to `NL80211_IFTYPE_*` kernel constants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum InterfaceType {
    /// Not specified.
    Unspecified = 0,
    /// Independent BSS (ad-hoc) member.
    Adhoc = 1,
    /// Managed BSS (station) member.
    Station = 2,
    /// Access point.
    Ap = 3,
    /// VLAN interface for access point.
    ApVlan = 4,
    /// Monitor interface (raw 802.11 frames).
    Monitor = 6,
    /// Mesh point (802.11s).
    MeshPoint = 7,
    /// P2P client.
    P2pClient = 8,
    /// P2P group owner.
    P2pGo = 9,
    /// P2P device (not a netdev).
    P2pDevice = 10,
    /// Outside Context of BSS.
    Ocb = 11,
    /// Neighbor Awareness Networking.
    Nan = 12,
}

impl TryFrom<u32> for InterfaceType {
    type Error = Error;

    fn try_from(value: u32) -> Result<Self> {
        match value {
            0 => Ok(Self::Unspecified),
            1 => Ok(Self::Adhoc),
            2 => Ok(Self::Station),
            3 => Ok(Self::Ap),
            4 => Ok(Self::ApVlan),
            6 => Ok(Self::Monitor),
            7 => Ok(Self::MeshPoint),
            8 => Ok(Self::P2pClient),
            9 => Ok(Self::P2pGo),
            10 => Ok(Self::P2pDevice),
            11 => Ok(Self::Ocb),
            12 => Ok(Self::Nan),
            _ => Err(Error::InvalidAttribute(format!(
                "unknown nl80211 interface type: {value}"
            ))),
        }
    }
}

/// BSS connection status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum BssStatus {
    /// Not authenticated.
    NotAuthenticated = 0,
    /// Authenticated but not associated.
    Authenticated = 1,
    /// Associated to this BSS.
    Associated = 2,
    /// Joined IBSS (ad-hoc).
    IbssJoined = 3,
}

impl TryFrom<u32> for BssStatus {
    type Error = Error;
    fn try_from(value: u32) -> Result<Self> {
        match value {
            0 => Ok(Self::NotAuthenticated),
            1 => Ok(Self::Authenticated),
            2 => Ok(Self::Associated),
            3 => Ok(Self::IbssJoined),
            _ => Err(Error::InvalidAttribute(format!(
                "unknown BSS status: {value}"
            ))),
        }
    }
}

/// Power save state for a wireless interface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum PowerSaveState {
    Disabled = 0,
    Enabled = 1,
}

impl TryFrom<u32> for PowerSaveState {
    type Error = Error;
    fn try_from(value: u32) -> Result<Self> {
        match value {
            0 => Ok(Self::Disabled),
            1 => Ok(Self::Enabled),
            _ => Err(Error::InvalidAttribute(format!(
                "unknown power save state: {value}"
            ))),
        }
    }
}

/// Authentication type for connect/associate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum AuthType {
    OpenSystem = 0,
    SharedKey = 1,
    Ft = 2,
    NetworkEap = 3,
    Sae = 4,
    FilsSk = 5,
    FilsSkPfs = 6,
    FilsPk = 7,
}

/// Channel width.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum ChannelWidth {
    Width20NoHt = 0,
    Width20 = 1,
    Width40 = 2,
    Width80 = 3,
    Width80P80 = 4,
    Width160 = 5,
    Width5 = 6,
    Width10 = 7,
    Width320 = 8,
}

impl TryFrom<u32> for ChannelWidth {
    type Error = Error;
    fn try_from(value: u32) -> Result<Self> {
        match value {
            0 => Ok(Self::Width20NoHt),
            1 => Ok(Self::Width20),
            2 => Ok(Self::Width40),
            3 => Ok(Self::Width80),
            4 => Ok(Self::Width80P80),
            5 => Ok(Self::Width160),
            6 => Ok(Self::Width5),
            7 => Ok(Self::Width10),
            8 => Ok(Self::Width320),
            _ => Err(Error::InvalidAttribute(format!(
                "unknown channel width: {value}"
            ))),
        }
    }
}

/// Information about a wireless interface.
#[derive(Debug, Clone)]
pub struct WirelessInterface {
    /// Kernel interface index.
    pub ifindex: u32,
    /// Interface name.
    pub name: Option<String>,
    /// Operating mode.
    pub iftype: InterfaceType,
    /// Physical device index.
    pub wiphy: u32,
    /// MAC address.
    pub mac: Option<[u8; 6]>,
    /// Current frequency in MHz.
    pub frequency: Option<u32>,
    /// Current SSID (if connected).
    pub ssid: Option<String>,
    /// Signal strength in dBm (from station info).
    pub signal_dbm: Option<i32>,
    /// TX bitrate in 100kbps units.
    pub tx_bitrate: Option<u32>,
    /// Generation counter (for cache invalidation).
    pub generation: Option<u32>,
}

impl WirelessInterface {
    /// Format MAC address as colon-separated hex.
    pub fn mac_str(&self) -> Option<String> {
        self.mac.map(|m| {
            format!(
                "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                m[0], m[1], m[2], m[3], m[4], m[5]
            )
        })
    }

    /// Get frequency as a channel number (approximate).
    pub fn channel(&self) -> Option<u32> {
        self.frequency.map(|f| match f {
            2412..=2484 => (f - 2407) / 5,
            5180..=5825 => (f - 5000) / 5,
            5955..=7115 => (f - 5950) / 5,
            _ => 0,
        })
    }
}

/// BSS (Basic Service Set) from scan results.
#[derive(Debug, Clone)]
pub struct ScanResult {
    /// BSSID (AP MAC address).
    pub bssid: [u8; 6],
    /// Frequency in MHz.
    pub frequency: u32,
    /// Network name. `None` for hidden networks.
    pub ssid: Option<String>,
    /// Signal strength in mBm (millidecibel-milliwatts).
    /// Divide by 100 for dBm.
    pub signal_mbm: i32,
    /// BSS capability field (IEEE 802.11).
    pub capability: u16,
    /// Beacon interval in TU (1024 us).
    pub beacon_interval: u16,
    /// Milliseconds since this BSS was last seen.
    pub seen_ms_ago: u32,
    /// TSF (Timing Synchronization Function) timestamp.
    pub tsf: Option<u64>,
    /// Connection status (if this is the associated BSS).
    pub status: Option<BssStatus>,
    /// Raw information elements (vendor-specific, WPA, RSN, etc.).
    pub information_elements: Vec<u8>,
}

impl ScanResult {
    /// Signal strength in dBm (rounded from mBm).
    pub fn signal_dbm(&self) -> i32 {
        self.signal_mbm / 100
    }

    /// Format BSSID as colon-separated hex.
    pub fn bssid_str(&self) -> String {
        format!(
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.bssid[0], self.bssid[1], self.bssid[2], self.bssid[3], self.bssid[4],
            self.bssid[5]
        )
    }

    /// Whether this BSS advertises privacy (WEP/WPA).
    pub fn is_privacy(&self) -> bool {
        self.capability & 0x0010 != 0
    }

    /// Whether this BSS is an ESS (infrastructure mode).
    pub fn is_ess(&self) -> bool {
        self.capability & 0x0001 != 0
    }
}

/// Station (connected peer) information.
#[derive(Debug, Clone)]
pub struct StationInfo {
    /// Station MAC address.
    pub mac: [u8; 6],
    /// Interface index.
    pub ifindex: u32,
    /// Time since last activity in milliseconds.
    pub inactive_time_ms: Option<u32>,
    /// Total bytes received from this station.
    pub rx_bytes: Option<u64>,
    /// Total bytes transmitted to this station.
    pub tx_bytes: Option<u64>,
    /// Signal strength in dBm.
    pub signal_dbm: Option<i8>,
    /// Average signal strength in dBm.
    pub signal_avg_dbm: Option<i8>,
    /// TX bitrate info.
    pub tx_bitrate: Option<BitrateInfo>,
    /// RX bitrate info.
    pub rx_bitrate: Option<BitrateInfo>,
    /// Time connected in seconds.
    pub connected_time_secs: Option<u32>,
}

/// Bitrate information (from NL80211_RATE_INFO_*).
#[derive(Debug, Clone)]
pub struct BitrateInfo {
    /// Bitrate in 100 kbps units.
    pub bitrate_100kbps: Option<u32>,
    /// MCS index (for HT/VHT).
    pub mcs: Option<u8>,
    /// Channel width.
    pub width: Option<ChannelWidth>,
    /// Short guard interval.
    pub short_gi: bool,
}

impl BitrateInfo {
    /// Bitrate in Mbps.
    pub fn mbps(&self) -> Option<f64> {
        self.bitrate_100kbps.map(|r| r as f64 / 10.0)
    }
}

/// Physical wireless device capabilities.
#[derive(Debug, Clone)]
pub struct PhyInfo {
    /// Physical device index.
    pub index: u32,
    /// Physical device name.
    pub name: String,
    /// Supported frequency bands.
    pub bands: Vec<Band>,
    /// Supported interface types.
    pub supported_iftypes: Vec<InterfaceType>,
    /// Maximum number of SSIDs in a scan request.
    pub max_scan_ssids: Option<u8>,
}

/// Frequency band (2.4 GHz, 5 GHz, 6 GHz).
#[derive(Debug, Clone)]
pub struct Band {
    /// Available frequencies.
    pub frequencies: Vec<Frequency>,
    /// Supported bitrates in 100kbps units.
    pub rates: Vec<u32>,
    /// HT (802.11n) capabilities.
    pub ht_capa: Option<u16>,
    /// VHT (802.11ac) capabilities.
    pub vht_capa: Option<u32>,
}

/// Individual frequency/channel info.
#[derive(Debug, Clone)]
pub struct Frequency {
    /// Frequency in MHz.
    pub freq: u32,
    /// Maximum TX power in mBm.
    pub max_power_mbm: u32,
    /// Whether this frequency is disabled by regulation.
    pub disabled: bool,
    /// Whether radar detection is required (DFS).
    pub radar: bool,
    /// Whether initiating radiation is not allowed (NO-IR).
    pub no_ir: bool,
}

impl Frequency {
    /// Maximum TX power in dBm.
    pub fn max_power_dbm(&self) -> f32 {
        self.max_power_mbm as f32 / 100.0
    }

    /// Approximate channel number.
    pub fn channel(&self) -> u32 {
        match self.freq {
            2412..=2484 => (self.freq - 2407) / 5,
            5180..=5825 => (self.freq - 5000) / 5,
            5955..=7115 => (self.freq - 5950) / 5,
            _ => 0,
        }
    }
}

/// Regulatory domain information.
#[derive(Debug, Clone)]
pub struct RegulatoryDomain {
    /// Two-letter country code (e.g., "US", "DE").
    pub country: String,
    /// Regulatory rules.
    pub rules: Vec<RegulatoryRule>,
}

/// Single regulatory rule defining allowed frequency range and power.
#[derive(Debug, Clone)]
pub struct RegulatoryRule {
    /// Start frequency in kHz.
    pub start_freq_khz: u32,
    /// End frequency in kHz.
    pub end_freq_khz: u32,
    /// Maximum bandwidth in kHz.
    pub max_bandwidth_khz: u32,
    /// Maximum antenna gain in mBi (milli-dBi).
    pub max_antenna_gain_mbi: u32,
    /// Maximum EIRP in mBm.
    pub max_eirp_mbm: u32,
    /// Regulatory flags (DFS, NO-IR, etc.).
    pub flags: u32,
}

/// Scan request configuration.
#[derive(Debug, Clone, Default)]
pub struct ScanRequest {
    /// Specific frequencies to scan (empty = all).
    pub frequencies: Vec<u32>,
    /// Specific SSIDs to probe for (empty = broadcast probe).
    pub ssids: Vec<Vec<u8>>,
}

impl ScanRequest {
    /// Scan a specific frequency.
    pub fn frequency(mut self, freq: u32) -> Self {
        self.frequencies.push(freq);
        self
    }

    /// Probe for a specific SSID.
    pub fn ssid(mut self, ssid: impl Into<Vec<u8>>) -> Self {
        self.ssids.push(ssid.into());
        self
    }
}

/// nl80211 multicast events.
#[derive(Debug, Clone)]
pub enum Nl80211Event {
    /// Scan completed successfully on an interface.
    ScanComplete {
        /// Interface index.
        ifindex: u32,
    },
    /// Scan was aborted.
    ScanAborted {
        /// Interface index.
        ifindex: u32,
    },
    /// Connected to a BSS.
    Connect {
        /// Interface index.
        ifindex: u32,
        /// AP BSSID.
        bssid: [u8; 6],
        /// IEEE 802.11 status code.
        status_code: u16,
    },
    /// Disconnected from BSS.
    Disconnect {
        /// Interface index.
        ifindex: u32,
        /// AP BSSID (if available).
        bssid: Option<[u8; 6]>,
        /// IEEE 802.11 reason code.
        reason_code: u16,
    },
    /// New wireless interface appeared.
    NewInterface {
        /// Interface index.
        ifindex: u32,
        /// Interface name.
        name: Option<String>,
        /// Interface type.
        iftype: InterfaceType,
    },
    /// Wireless interface removed.
    DelInterface {
        /// Interface index.
        ifindex: u32,
    },
    /// Regulatory domain changed.
    RegChange {
        /// Country code (if available).
        country: Option<String>,
    },
}

/// Connect request builder.
pub struct ConnectRequest {
    /// SSID to connect to.
    pub(crate) ssid: Vec<u8>,
    /// Target BSSID (optional).
    pub(crate) bssid: Option<[u8; 6]>,
    /// Target frequency (optional).
    pub(crate) frequency: Option<u32>,
    /// Authentication type.
    pub(crate) auth_type: AuthType,
}

impl ConnectRequest {
    /// Connect to a network by SSID.
    pub fn new(ssid: impl Into<Vec<u8>>) -> Self {
        Self {
            ssid: ssid.into(),
            bssid: None,
            frequency: None,
            auth_type: AuthType::OpenSystem,
        }
    }

    /// Target a specific BSSID (AP).
    pub fn bssid(mut self, bssid: [u8; 6]) -> Self {
        self.bssid = Some(bssid);
        self
    }

    /// Restrict to a specific frequency.
    pub fn frequency(mut self, freq: u32) -> Self {
        self.frequency = Some(freq);
        self
    }

    /// Set authentication type.
    pub fn auth_type(mut self, auth: AuthType) -> Self {
        self.auth_type = auth;
        self
    }
}
