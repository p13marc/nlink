//! nl80211 Generic Netlink support for WiFi configuration.
//!
//! This module provides a typed API for querying wireless interfaces,
//! scan results, station info, physical device capabilities, and
//! regulatory domains via the nl80211 Generic Netlink family.
//!
//! # Example
//!
//! ```ignore
//! use nlink::netlink::{Connection, Nl80211};
//!
//! let conn = Connection::<Nl80211>::new_async().await?;
//!
//! // List wireless interfaces
//! let ifaces = conn.get_interfaces().await?;
//! for iface in &ifaces {
//!     println!("{}: {:?} freq={:?}",
//!         iface.name.as_deref().unwrap_or("?"),
//!         iface.iftype,
//!         iface.frequency);
//! }
//!
//! // Get scan results
//! let results = conn.get_scan_results("wlan0").await?;
//! for bss in &results {
//!     println!("{} {} {}dBm",
//!         bss.bssid_str(),
//!         bss.ssid.as_deref().unwrap_or("<hidden>"),
//!         bss.signal_dbm());
//! }
//! ```

pub mod connection;
pub mod types;

pub use types::*;

/// nl80211 GENL family name.
pub const NL80211_GENL_NAME: &str = "nl80211";

/// nl80211 GENL version.
pub const NL80211_GENL_VERSION: u8 = 1;

// =============================================================================
// Commands
// =============================================================================

pub const NL80211_CMD_GET_WIPHY: u8 = 1;
pub const NL80211_CMD_SET_WIPHY: u8 = 2;
pub const NL80211_CMD_GET_INTERFACE: u8 = 5;
pub const NL80211_CMD_GET_KEY: u8 = 9;
pub const NL80211_CMD_GET_STATION: u8 = 17;
pub const NL80211_CMD_DEL_STATION: u8 = 20;
pub const NL80211_CMD_SET_REG: u8 = 26;
pub const NL80211_CMD_GET_REG: u8 = 31;
pub const NL80211_CMD_GET_SCAN: u8 = 32;
pub const NL80211_CMD_TRIGGER_SCAN: u8 = 33;
pub const NL80211_CMD_NEW_SCAN_RESULTS: u8 = 34;
pub const NL80211_CMD_SCAN_ABORTED: u8 = 35;
pub const NL80211_CMD_CONNECT: u8 = 46;
pub const NL80211_CMD_DISCONNECT: u8 = 48;
pub const NL80211_CMD_SET_POWER_SAVE: u8 = 61;
pub const NL80211_CMD_GET_POWER_SAVE: u8 = 62;

// =============================================================================
// Top-level Attributes
// =============================================================================

pub const NL80211_ATTR_WIPHY: u16 = 1;
pub const NL80211_ATTR_WIPHY_NAME: u16 = 2;
pub const NL80211_ATTR_IFINDEX: u16 = 3;
pub const NL80211_ATTR_IFNAME: u16 = 4;
pub const NL80211_ATTR_IFTYPE: u16 = 5;
pub const NL80211_ATTR_MAC: u16 = 6;
pub const NL80211_ATTR_KEY: u16 = 8;
pub const NL80211_ATTR_MAX_SCAN_SSIDS: u16 = 11;
pub const NL80211_ATTR_REG_ALPHA2: u16 = 16;
pub const NL80211_ATTR_REG_RULES: u16 = 17;
pub const NL80211_ATTR_SCAN_FREQUENCIES: u16 = 18;
pub const NL80211_ATTR_SCAN_SSIDS: u16 = 19;
pub const NL80211_ATTR_STA_INFO: u16 = 21;
pub const NL80211_ATTR_WIPHY_BANDS: u16 = 22;
pub const NL80211_ATTR_SUPPORTED_IFTYPES: u16 = 32;
pub const NL80211_ATTR_WIPHY_FREQ: u16 = 38;
pub const NL80211_ATTR_WIPHY_CHANNEL_TYPE: u16 = 39;
pub const NL80211_ATTR_GENERATION: u16 = 46;
pub const NL80211_ATTR_BSS: u16 = 47;
pub const NL80211_ATTR_SSID: u16 = 52;
pub const NL80211_ATTR_AUTH_TYPE: u16 = 53;
pub const NL80211_ATTR_REASON_CODE: u16 = 54;
pub const NL80211_ATTR_STATUS_CODE: u16 = 72;
pub const NL80211_ATTR_PS_STATE: u16 = 91;

// =============================================================================
// BSS Nested Attributes
// =============================================================================

pub const NL80211_BSS_BSSID: u16 = 1;
pub const NL80211_BSS_FREQUENCY: u16 = 2;
pub const NL80211_BSS_TSF: u16 = 3;
pub const NL80211_BSS_BEACON_INTERVAL: u16 = 4;
pub const NL80211_BSS_CAPABILITY: u16 = 5;
pub const NL80211_BSS_INFORMATION_ELEMENTS: u16 = 6;
pub const NL80211_BSS_SIGNAL_MBM: u16 = 7;
pub const NL80211_BSS_SIGNAL_UNSPEC: u16 = 8;
pub const NL80211_BSS_STATUS: u16 = 9;
pub const NL80211_BSS_SEEN_MS_AGO: u16 = 10;

// =============================================================================
// Station Info Nested Attributes
// =============================================================================

pub const NL80211_STA_INFO_INACTIVE_TIME: u16 = 1;
pub const NL80211_STA_INFO_RX_BYTES: u16 = 2;
pub const NL80211_STA_INFO_TX_BYTES: u16 = 3;
pub const NL80211_STA_INFO_SIGNAL: u16 = 7;
pub const NL80211_STA_INFO_TX_BITRATE: u16 = 8;
pub const NL80211_STA_INFO_RX_BITRATE: u16 = 12;
pub const NL80211_STA_INFO_SIGNAL_AVG: u16 = 13;
pub const NL80211_STA_INFO_CONNECTED_TIME: u16 = 16;
pub const NL80211_STA_INFO_RX_BYTES64: u16 = 23;
pub const NL80211_STA_INFO_TX_BYTES64: u16 = 24;

// =============================================================================
// Bitrate Info Nested Attributes
// =============================================================================

pub const NL80211_RATE_INFO_BITRATE: u16 = 1;
pub const NL80211_RATE_INFO_MCS: u16 = 2;
pub const NL80211_RATE_INFO_40_MHZ_WIDTH: u16 = 3;
pub const NL80211_RATE_INFO_SHORT_GI: u16 = 4;
pub const NL80211_RATE_INFO_BITRATE32: u16 = 5;
pub const NL80211_RATE_INFO_VHT_MCS: u16 = 6;
pub const NL80211_RATE_INFO_VHT_NSS: u16 = 7;
pub const NL80211_RATE_INFO_80_MHZ_WIDTH: u16 = 8;
pub const NL80211_RATE_INFO_80P80_MHZ_WIDTH: u16 = 9;
pub const NL80211_RATE_INFO_160_MHZ_WIDTH: u16 = 10;

// =============================================================================
// Band Nested Attributes
// =============================================================================

pub const NL80211_BAND_ATTR_FREQS: u16 = 1;
pub const NL80211_BAND_ATTR_RATES: u16 = 2;
pub const NL80211_BAND_ATTR_HT_CAPA: u16 = 4;
pub const NL80211_BAND_ATTR_VHT_CAPA: u16 = 9;

// =============================================================================
// Frequency Nested Attributes
// =============================================================================

pub const NL80211_FREQUENCY_ATTR_FREQ: u16 = 1;
pub const NL80211_FREQUENCY_ATTR_DISABLED: u16 = 2;
pub const NL80211_FREQUENCY_ATTR_NO_IR: u16 = 3;
pub const NL80211_FREQUENCY_ATTR_RADAR: u16 = 5;
pub const NL80211_FREQUENCY_ATTR_MAX_TX_POWER: u16 = 6;

// =============================================================================
// Bitrate Nested Attributes (within Band)
// =============================================================================

pub const NL80211_BITRATE_ATTR_RATE: u16 = 1;

// =============================================================================
// Regulatory Rule Attributes
// =============================================================================

pub const NL80211_ATTR_REG_RULE_FLAGS: u16 = 1;
pub const NL80211_ATTR_FREQ_RANGE_START: u16 = 2;
pub const NL80211_ATTR_FREQ_RANGE_END: u16 = 3;
pub const NL80211_ATTR_FREQ_RANGE_MAX_BW: u16 = 4;
pub const NL80211_ATTR_POWER_RULE_MAX_ANT_GAIN: u16 = 5;
pub const NL80211_ATTR_POWER_RULE_MAX_EIRP: u16 = 6;
