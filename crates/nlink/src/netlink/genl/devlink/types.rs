//! Devlink data types.

use crate::netlink::error::{Error, Result};

/// Devlink port type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum PortType {
    NotSet = 0,
    Auto = 1,
    Eth = 2,
    Ib = 3,
}

impl TryFrom<u16> for PortType {
    type Error = Error;
    fn try_from(value: u16) -> Result<Self> {
        match value {
            0 => Ok(Self::NotSet),
            1 => Ok(Self::Auto),
            2 => Ok(Self::Eth),
            3 => Ok(Self::Ib),
            _ => Err(Error::InvalidAttribute(format!(
                "unknown devlink port type: {value}"
            ))),
        }
    }
}

/// Devlink port flavour.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum PortFlavour {
    Physical = 0,
    Cpu = 1,
    Dsa = 2,
    PciPf = 3,
    PciVf = 4,
    Virtual = 5,
    PciSf = 6,
}

impl TryFrom<u16> for PortFlavour {
    type Error = Error;
    fn try_from(value: u16) -> Result<Self> {
        match value {
            0 => Ok(Self::Physical),
            1 => Ok(Self::Cpu),
            2 => Ok(Self::Dsa),
            3 => Ok(Self::PciPf),
            4 => Ok(Self::PciVf),
            5 => Ok(Self::Virtual),
            6 => Ok(Self::PciSf),
            _ => Err(Error::InvalidAttribute(format!(
                "unknown devlink port flavour: {value}"
            ))),
        }
    }
}

/// Health reporter state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum HealthState {
    Healthy = 0,
    Error = 1,
}

impl TryFrom<u8> for HealthState {
    type Error = Error;
    fn try_from(value: u8) -> Result<Self> {
        match value {
            0 => Ok(Self::Healthy),
            1 => Ok(Self::Error),
            _ => Err(Error::InvalidAttribute(format!(
                "unknown health state: {value}"
            ))),
        }
    }
}

/// Configuration mode for device parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ConfigMode {
    Runtime = 0,
    Driverinit = 1,
    Permanent = 2,
}

impl TryFrom<u8> for ConfigMode {
    type Error = Error;
    fn try_from(value: u8) -> Result<Self> {
        match value {
            0 => Ok(Self::Runtime),
            1 => Ok(Self::Driverinit),
            2 => Ok(Self::Permanent),
            _ => Err(Error::InvalidAttribute(format!(
                "unknown config mode: {value}"
            ))),
        }
    }
}

/// A devlink device (typically a NIC or switch ASIC).
#[derive(Debug, Clone)]
pub struct DevlinkDevice {
    /// Bus name (e.g., "pci", "auxiliary").
    pub bus: String,
    /// Device name (e.g., "0000:03:00.0").
    pub device: String,
}

impl DevlinkDevice {
    /// Format as "bus/device" (e.g., "pci/0000:03:00.0").
    pub fn path(&self) -> String {
        format!("{}/{}", self.bus, self.device)
    }
}

/// Device information including driver and firmware versions.
#[derive(Debug, Clone)]
pub struct DevlinkInfo {
    /// Bus name.
    pub bus: String,
    /// Device name.
    pub device: String,
    /// Driver name (e.g., "mlx5_core", "ice").
    pub driver: String,
    /// Device serial number.
    pub serial: Option<String>,
    /// Board serial number.
    pub board_serial: Option<String>,
    /// Fixed (hardware) version information.
    pub versions_fixed: Vec<VersionInfo>,
    /// Running (loaded) firmware versions.
    pub versions_running: Vec<VersionInfo>,
    /// Stored (on-flash) firmware versions.
    pub versions_stored: Vec<VersionInfo>,
}

impl DevlinkInfo {
    /// Get a specific running firmware version by name.
    pub fn running_version(&self, name: &str) -> Option<&str> {
        self.versions_running
            .iter()
            .find(|v| v.name == name)
            .map(|v| v.value.as_str())
    }

    /// Get a specific fixed (hardware) version by name.
    pub fn fixed_version(&self, name: &str) -> Option<&str> {
        self.versions_fixed
            .iter()
            .find(|v| v.name == name)
            .map(|v| v.value.as_str())
    }

    /// Check if there's a pending firmware update (stored != running).
    pub fn has_pending_update(&self) -> bool {
        for stored in &self.versions_stored {
            if let Some(running) = self.running_version(&stored.name) {
                if running != stored.value {
                    return true;
                }
            }
        }
        false
    }
}

/// Firmware or hardware version information.
#[derive(Debug, Clone)]
pub struct VersionInfo {
    /// Version component name (e.g., "fw.mgmt", "fw.undi", "board.id").
    pub name: String,
    /// Version value (e.g., "22.31.1014", "1.2881.0").
    pub value: String,
}

/// A devlink port representing a physical or virtual port.
#[derive(Debug, Clone)]
pub struct DevlinkPort {
    /// Bus name.
    pub bus: String,
    /// Device name.
    pub device: String,
    /// Port index (unique per device).
    pub index: u32,
    /// Port type.
    pub port_type: PortType,
    /// Network device interface index (if mapped).
    pub netdev_ifindex: Option<u32>,
    /// Network device name (if mapped).
    pub netdev_name: Option<String>,
    /// InfiniBand device name (if IB port).
    pub ibdev_name: Option<String>,
    /// Port flavour.
    pub flavour: Option<PortFlavour>,
    /// Physical port number.
    pub number: Option<u32>,
    /// Split sub-port number.
    pub split_subport: Option<u32>,
    /// Split group.
    pub split_group: Option<u32>,
    /// PCI PF number (for PF/VF/SF flavours).
    pub pci_pf: Option<u16>,
    /// PCI VF number (for VF flavour).
    pub pci_vf: Option<u16>,
    /// PCI SF number (for SF flavour).
    pub pci_sf: Option<u32>,
    /// Controller number (for multi-host).
    pub controller: Option<u32>,
}

impl DevlinkPort {
    /// Format the port path as "bus/device/port_index".
    pub fn path(&self) -> String {
        format!("{}/{}/{}", self.bus, self.device, self.index)
    }

    /// Whether this port is mapped to a netdev.
    pub fn has_netdev(&self) -> bool {
        self.netdev_ifindex.is_some()
    }

    /// Whether this is a physical port.
    pub fn is_physical(&self) -> bool {
        self.flavour == Some(PortFlavour::Physical)
    }

    /// Whether this is a PCI VF representor.
    pub fn is_vf_representor(&self) -> bool {
        self.flavour == Some(PortFlavour::PciVf)
    }

    /// Whether this is a PCI SF representor.
    pub fn is_sf_representor(&self) -> bool {
        self.flavour == Some(PortFlavour::PciSf)
    }
}

/// Health reporter status.
#[derive(Debug, Clone)]
pub struct HealthReporter {
    /// Bus name.
    pub bus: String,
    /// Device name.
    pub device: String,
    /// Reporter name (e.g., "fw", "fw_fatal", "tx").
    pub name: String,
    /// Current state.
    pub state: HealthState,
    /// Total number of errors detected.
    pub error_count: u64,
    /// Total number of recovery attempts.
    pub recover_count: u64,
    /// Whether automatic recovery is enabled.
    pub auto_recover: bool,
    /// Whether automatic dump on error is enabled.
    pub auto_dump: bool,
    /// Graceful period between recoveries in milliseconds.
    pub graceful_period_ms: Option<u64>,
    /// Timestamp of last dump (jiffies).
    pub dump_ts_jiffies: Option<u64>,
}

impl HealthReporter {
    /// Whether this reporter is in error state.
    pub fn is_error(&self) -> bool {
        self.state == HealthState::Error
    }

    /// Whether this reporter has had any errors.
    pub fn has_errors(&self) -> bool {
        self.error_count > 0
    }
}

/// Device parameter with its current values across configuration modes.
#[derive(Debug, Clone)]
pub struct DevlinkParam {
    /// Bus name.
    pub bus: String,
    /// Device name.
    pub device: String,
    /// Parameter name (e.g., "enable_sriov", "fw_load_policy").
    pub name: String,
    /// Whether this is a generic (driver-independent) parameter.
    pub generic: bool,
    /// Current values for each configuration mode.
    pub values: Vec<ParamValue>,
}

/// A parameter value in a specific configuration mode.
#[derive(Debug, Clone)]
pub struct ParamValue {
    /// Configuration mode (runtime, driverinit, permanent).
    pub cmode: ConfigMode,
    /// The value (type depends on param_type).
    pub data: ParamData,
}

/// Parameter data variants.
#[derive(Debug, Clone)]
pub enum ParamData {
    U8(u8),
    U16(u16),
    U32(u32),
    String(String),
    Bool(bool),
}

impl std::fmt::Display for ParamData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ParamData::U8(v) => write!(f, "{v}"),
            ParamData::U16(v) => write!(f, "{v}"),
            ParamData::U32(v) => write!(f, "{v}"),
            ParamData::String(v) => write!(f, "{v}"),
            ParamData::Bool(v) => write!(f, "{v}"),
        }
    }
}
