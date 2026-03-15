# Plan 037: Devlink Support

## Overview

Add devlink Generic Netlink support for hardware device management. Used by modern NIC drivers (mlx5, ice, bnxt, nfp) for firmware info, health monitoring, port configuration, and resource management.

## Scope

### Phase 1: Read-Only (MVP)

- List devices and get driver/firmware info
- List ports with netdev mapping
- Get health reporters and their state
- Get device parameters

### Phase 2: Management

- Firmware flash
- Reload device
- Port function configuration
- Health reporter recovery/dump
- Parameter configuration

## Progress

### Phase 1: Read-Only MVP
- [x] Create `genl/devlink/mod.rs` with command and attribute constants
- [x] Implement `PortType`, `PortFlavour`, `HealthState`, `ConfigMode` enums with `TryFrom`
- [x] Implement `Connection<Devlink>` with `new_async()` (resolves family ID)
- [x] Implement `DevlinkDevice` type with `path()` helper
- [x] Implement `get_devices()`
- [x] Implement `DevlinkInfo` type with `running_version()`, `fixed_version()`, `has_pending_update()`
- [x] Implement `get_device_info()`
- [x] Implement `VersionInfo` type
- [x] Implement attribute parsing (`parse_info`, `parse_version_nested`)
- [x] Implement `DevlinkPort` type with `path()`, `has_netdev()`, `is_physical()` helpers
- [x] Implement `get_ports()`, `get_device_ports()`, `get_port()`, `get_port_by_netdev()`
- [x] Implement `HealthReporter` type with `is_error()`, `has_errors()` helpers
- [x] Implement `get_health_reporters()`, `get_health_reporter()`, `get_health_errors()`
- [x] Implement health reporter attribute parsing (`parse_health_reporter`)
- [x] Implement `DevlinkParam`, `ParamValue`, `ParamData` types
- [x] Implement `get_params()`, `get_param()`
- [ ] Add integration tests for device listing (requires supported NIC)
- [ ] Add integration tests for info/port/health parsing
- [x] Add doc comments with examples on all public types and methods
- [x] Create `bins/devlink` binary or add devlink commands to existing binary
- [x] Update CLAUDE.md with devlink usage examples

### Phase 2: Management Operations
- [x] Implement `ReloadAction` enum
- [x] Implement `health_reporter_recover()`
- [x] Implement `set_health_reporter()` (auto_recover, auto_dump, graceful_period)
- [x] Implement `FlashRequest` builder and `flash_update()`
- [x] Implement `FlashProgress` type with `percent()` helper
- [x] Implement `reload()` with `ReloadAction`
- [x] Implement `port_split()` and `port_unsplit()`
- [x] Implement `set_param()` with `ParamData` and `ConfigMode`
- [ ] Add integration tests for management operations
- [x] Add management commands to binary
- [ ] Add doc comments with examples

### Phase 3: Event Monitoring
- [x] Implement `DevlinkEvent` enum
- [x] Implement `subscribe()` for multicast group
- [x] Implement `events()` and `into_events()` stream methods
- [ ] Add integration test for event monitoring
- [x] Add monitor mode to binary
- [ ] Add doc comments with examples

## Kernel Constants (verified against linux/devlink.h, kernel 6.19.6)

### Commands

| Constant | Value | Purpose |
|----------|-------|---------|
| `DEVLINK_CMD_GET` | 1 | Dump/get devices |
| `DEVLINK_CMD_SET` | 2 | Set device attributes |
| `DEVLINK_CMD_NEW` | 3 | New device notification |
| `DEVLINK_CMD_DEL` | 4 | Device removed notification |
| `DEVLINK_CMD_PORT_GET` | 5 | Dump/get ports |
| `DEVLINK_CMD_PORT_SET` | 6 | Set port attributes |
| `DEVLINK_CMD_PORT_NEW` | 7 | New port notification |
| `DEVLINK_CMD_PORT_DEL` | 8 | Port removed notification |
| `DEVLINK_CMD_PORT_SPLIT` | 9 | Split port into sub-ports |
| `DEVLINK_CMD_PORT_UNSPLIT` | 10 | Unsplit port |
| `DEVLINK_CMD_RELOAD` | 37 | Reload device/driver |
| `DEVLINK_CMD_PARAM_GET` | 38 | Get device parameter |
| `DEVLINK_CMD_PARAM_SET` | 39 | Set device parameter |
| `DEVLINK_CMD_PARAM_NEW` | 40 | New parameter notification |
| `DEVLINK_CMD_PARAM_DEL` | 41 | Parameter removed notification |
| `DEVLINK_CMD_REGION_GET` | 42 | Get device region |
| `DEVLINK_CMD_REGION_SET` | 43 | Set device region |
| `DEVLINK_CMD_REGION_NEW` | 44 | New region snapshot notification |
| `DEVLINK_CMD_REGION_DEL` | 45 | Delete region snapshot |
| `DEVLINK_CMD_REGION_READ` | 46 | Read region snapshot data |
| `DEVLINK_CMD_INFO_GET` | 51 | Get device info (driver, firmware) |
| `DEVLINK_CMD_HEALTH_REPORTER_GET` | 52 | Dump/get health reporters |
| `DEVLINK_CMD_HEALTH_REPORTER_SET` | 53 | Configure health reporter |
| `DEVLINK_CMD_HEALTH_REPORTER_RECOVER` | 54 | Trigger recovery |
| `DEVLINK_CMD_HEALTH_REPORTER_DIAGNOSE` | 55 | Get diagnostic info |
| `DEVLINK_CMD_HEALTH_REPORTER_DUMP_GET` | 56 | Get reporter dump |
| `DEVLINK_CMD_HEALTH_REPORTER_DUMP_CLEAR` | 57 | Clear reporter dump |
| `DEVLINK_CMD_FLASH_UPDATE` | 58 | Flash firmware |
| `DEVLINK_CMD_FLASH_UPDATE_END` | 59 | Flash complete notification |
| `DEVLINK_CMD_FLASH_UPDATE_STATUS` | 60 | Flash progress notification |
| `DEVLINK_CMD_TRAP_GET` | 61 | Get packet trap |
| `DEVLINK_CMD_TRAP_SET` | 62 | Set packet trap |
| `DEVLINK_CMD_TRAP_GROUP_GET` | 65 | Get trap group |
| `DEVLINK_CMD_TRAP_GROUP_SET` | 66 | Set trap group |
| `DEVLINK_CMD_TRAP_POLICER_GET` | 69 | Get trap policer |
| `DEVLINK_CMD_TRAP_POLICER_SET` | 70 | Set trap policer |
| `DEVLINK_CMD_RATE_GET` | 76 | Get rate limiting |
| `DEVLINK_CMD_RATE_SET` | 77 | Set rate limiting |
| `DEVLINK_CMD_SELFTESTS_GET` | 82 | Get available self tests |
| `DEVLINK_CMD_SELFTESTS_RUN` | 83 | Run self tests |

### Device/Port Attributes

| Constant | Value | Type |
|----------|-------|------|
| `DEVLINK_ATTR_BUS_NAME` | 1 | string |
| `DEVLINK_ATTR_DEV_NAME` | 2 | string |
| `DEVLINK_ATTR_PORT_INDEX` | 3 | u32 |
| `DEVLINK_ATTR_PORT_TYPE` | 4 | u16 (PortType) |
| `DEVLINK_ATTR_PORT_DESIRED_TYPE` | 5 | u16 |
| `DEVLINK_ATTR_PORT_NETDEV_IFINDEX` | 6 | u32 |
| `DEVLINK_ATTR_PORT_NETDEV_NAME` | 7 | string |
| `DEVLINK_ATTR_PORT_IBDEV_NAME` | 8 | string |
| `DEVLINK_ATTR_PORT_SPLIT_COUNT` | 9 | u32 |
| `DEVLINK_ATTR_PORT_SPLIT_GROUP` | 10 | u32 |
| `DEVLINK_ATTR_PORT_FLAVOUR` | 77 | u16 (PortFlavour) |
| `DEVLINK_ATTR_PORT_NUMBER` | 78 | u32 |
| `DEVLINK_ATTR_PORT_SPLIT_SUBPORT_NUMBER` | 79 | u32 |
| `DEVLINK_ATTR_PORT_PCI_PF_NUMBER` | 127 | u16 |
| `DEVLINK_ATTR_PORT_PCI_SF_NUMBER` | 164 | u32 |
| `DEVLINK_ATTR_PORT_PCI_VF_NUMBER` | 170 | u16 |
| `DEVLINK_ATTR_PORT_FUNCTION` | 145 | nested |
| `DEVLINK_ATTR_PORT_CONTROLLER_NUMBER` | 150 | u32 |

### Info Attributes

| Constant | Value | Type |
|----------|-------|------|
| `DEVLINK_ATTR_INFO_DRIVER_NAME` | 98 | string |
| `DEVLINK_ATTR_INFO_SERIAL_NUMBER` | 99 | string |
| `DEVLINK_ATTR_INFO_VERSION_FIXED` | 100 | nested |
| `DEVLINK_ATTR_INFO_VERSION_RUNNING` | 101 | nested |
| `DEVLINK_ATTR_INFO_VERSION_STORED` | 102 | nested |
| `DEVLINK_ATTR_INFO_VERSION_NAME` | 103 | string |
| `DEVLINK_ATTR_INFO_VERSION_VALUE` | 104 | string |
| `DEVLINK_ATTR_INFO_BOARD_SERIAL_NUMBER` | 141 | string |

### Health Reporter Attributes

| Constant | Value | Type |
|----------|-------|------|
| `DEVLINK_ATTR_HEALTH_REPORTER` | 114 | nested |
| `DEVLINK_ATTR_HEALTH_REPORTER_NAME` | 115 | string |
| `DEVLINK_ATTR_HEALTH_REPORTER_STATE` | 116 | u8 (HealthState) |
| `DEVLINK_ATTR_HEALTH_REPORTER_ERR_COUNT` | 117 | u64 |
| `DEVLINK_ATTR_HEALTH_REPORTER_RECOVER_COUNT` | 118 | u64 |
| `DEVLINK_ATTR_HEALTH_REPORTER_GRACEFUL_PERIOD` | 120 | u64 (ms) |
| `DEVLINK_ATTR_HEALTH_REPORTER_AUTO_RECOVER` | 121 | u8 (bool) |
| `DEVLINK_ATTR_HEALTH_REPORTER_DUMP_TS` | 119 | u64 (jiffies) |
| `DEVLINK_ATTR_HEALTH_REPORTER_AUTO_DUMP` | 136 | u8 (bool) |

### Parameter Attributes

| Constant | Value | Type |
|----------|-------|------|
| `DEVLINK_ATTR_PARAM` | 80 | nested |
| `DEVLINK_ATTR_PARAM_NAME` | 81 | string |
| `DEVLINK_ATTR_PARAM_GENERIC` | 82 | flag |
| `DEVLINK_ATTR_PARAM_TYPE` | 83 | u8 |
| `DEVLINK_ATTR_PARAM_VALUES_LIST` | 84 | nested |
| `DEVLINK_ATTR_PARAM_VALUE` | 85 | nested |
| `DEVLINK_ATTR_PARAM_VALUE_DATA` | 86 | varies |
| `DEVLINK_ATTR_PARAM_VALUE_CMODE` | 87 | u8 (ConfigMode) |

### Flash Update Attributes

| Constant | Value | Type |
|----------|-------|------|
| `DEVLINK_ATTR_FLASH_UPDATE_FILE_NAME` | 122 | string |
| `DEVLINK_ATTR_FLASH_UPDATE_COMPONENT` | 123 | string |
| `DEVLINK_ATTR_FLASH_UPDATE_STATUS_MSG` | 128 | string |
| `DEVLINK_ATTR_FLASH_UPDATE_STATUS_DONE` | 129 | u64 |
| `DEVLINK_ATTR_FLASH_UPDATE_STATUS_TOTAL` | 130 | u64 |
| `DEVLINK_ATTR_FLASH_UPDATE_OVERWRITE_MASK` | 160 | bitfield32 |

### Reload Attributes

| Constant | Value | Type |
|----------|-------|------|
| `DEVLINK_ATTR_RELOAD_ACTION` | 153 | u8 (ReloadAction) |
| `DEVLINK_ATTR_RELOAD_ACTIONS_PERFORMED` | 154 | bitfield32 |
| `DEVLINK_ATTR_RELOAD_LIMITS` | 155 | bitfield32 |

### Rate Attributes

| Constant | Value | Type |
|----------|-------|------|
| `DEVLINK_ATTR_RATE_NODE_NAME` | 168 | string |
| `DEVLINK_ATTR_RATE_TX_SHARE` | 166 | u64 (bps) |
| `DEVLINK_ATTR_RATE_TX_MAX` | 167 | u64 (bps) |
| `DEVLINK_ATTR_RATE_PARENT_NODE_NAME` | 173 | string |

## Types

### Strongly Typed Enums

```rust
/// Devlink port type.
///
/// Maps to `DEVLINK_PORT_TYPE_*` kernel constants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum PortType {
    /// Port type not set.
    NotSet = 0,
    /// Auto-detect port type.
    Auto = 1,
    /// Ethernet port.
    Eth = 2,
    /// InfiniBand port.
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
            _ => Err(Error::InvalidAttribute(
                format!("unknown devlink port type: {value}")
            )),
        }
    }
}

/// Devlink port flavour (physical, virtual, PCIe function, etc.).
///
/// Maps to `DEVLINK_PORT_FLAVOUR_*` kernel constants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum PortFlavour {
    /// Physical port on the device.
    Physical = 0,
    /// CPU port (internal to switch ASIC).
    Cpu = 1,
    /// DSA local port (for DSA switches).
    Dsa = 2,
    /// PCI Physical Function representor.
    PciPf = 3,
    /// PCI Virtual Function representor.
    PciVf = 4,
    /// Virtual port.
    Virtual = 5,
    /// PCI Sub-Function representor.
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
            _ => Err(Error::InvalidAttribute(
                format!("unknown devlink port flavour: {value}")
            )),
        }
    }
}

/// Health reporter state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum HealthState {
    /// Reporter is healthy, no errors detected.
    Healthy = 0,
    /// Reporter has detected an error condition.
    Error = 1,
}

impl TryFrom<u8> for HealthState {
    type Error = Error;
    fn try_from(value: u8) -> Result<Self> {
        match value {
            0 => Ok(Self::Healthy),
            1 => Ok(Self::Error),
            _ => Err(Error::InvalidAttribute(
                format!("unknown health state: {value}")
            )),
        }
    }
}

/// Configuration mode for device parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ConfigMode {
    /// Runtime configuration (volatile, immediate effect).
    Runtime = 0,
    /// Driverinit configuration (takes effect on driver reload).
    Driverinit = 1,
    /// Permanent configuration (survives reboot).
    Permanent = 2,
}

impl TryFrom<u8> for ConfigMode {
    type Error = Error;
    fn try_from(value: u8) -> Result<Self> {
        match value {
            0 => Ok(Self::Runtime),
            1 => Ok(Self::Driverinit),
            2 => Ok(Self::Permanent),
            _ => Err(Error::InvalidAttribute(
                format!("unknown config mode: {value}")
            )),
        }
    }
}

/// Device reload action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ReloadAction {
    /// Reload driver only.
    DriverReinit = 1,
    /// Reload firmware only.
    FwActivate = 2,
}

impl TryFrom<u8> for ReloadAction {
    type Error = Error;
    fn try_from(value: u8) -> Result<Self> {
        match value {
            1 => Ok(Self::DriverReinit),
            2 => Ok(Self::FwActivate),
            _ => Err(Error::InvalidAttribute(
                format!("unknown reload action: {value}")
            )),
        }
    }
}

/// Parameter data type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ParamType {
    U8 = 1,
    U16 = 2,
    U32 = 3,
    String = 5,
    Bool = 6,
}

/// Reload limit (what restrictions apply to reload).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ReloadLimit {
    /// No limits — full reset possible.
    Unspecified = 0,
    /// No reset allowed.
    NoReset = 1,
}
```

### Data Types

```rust
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
        self.versions_running.iter()
            .find(|v| v.name == name)
            .map(|v| v.value.as_str())
    }

    /// Get a specific fixed (hardware) version by name.
    pub fn fixed_version(&self, name: &str) -> Option<&str> {
        self.versions_fixed.iter()
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
    /// Parameter data type.
    pub param_type: Option<ParamType>,
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

/// Flash update progress.
#[derive(Debug, Clone)]
pub struct FlashProgress {
    /// Status message from the driver.
    pub message: Option<String>,
    /// Component being flashed.
    pub component: Option<String>,
    /// Bytes/units completed.
    pub done: u64,
    /// Total bytes/units.
    pub total: u64,
}

impl FlashProgress {
    /// Progress as a percentage (0.0 to 100.0).
    pub fn percent(&self) -> f64 {
        if self.total == 0 {
            0.0
        } else {
            (self.done as f64 / self.total as f64) * 100.0
        }
    }
}

/// Flash update request builder.
pub struct FlashRequest {
    file_name: String,
    component: Option<String>,
    overwrite_mask: Option<u32>,
}

impl FlashRequest {
    /// Flash a firmware file.
    pub fn new(file_name: impl Into<String>) -> Self {
        Self {
            file_name: file_name.into(),
            component: None,
            overwrite_mask: None,
        }
    }

    /// Flash a specific component (e.g., "fw.mgmt").
    pub fn component(mut self, component: impl Into<String>) -> Self {
        self.component = Some(component.into());
        self
    }

    /// Set overwrite mask (allow downgrade, settings reset, etc.).
    pub fn overwrite_mask(mut self, mask: u32) -> Self {
        self.overwrite_mask = Some(mask);
        self
    }
}
```

### Events

```rust
/// Devlink events from multicast notifications.
#[derive(Debug, Clone)]
pub enum DevlinkEvent {
    /// New device registered.
    DeviceNew {
        bus: String,
        device: String,
    },
    /// Device removed.
    DeviceDel {
        bus: String,
        device: String,
    },
    /// New port appeared.
    PortNew(DevlinkPort),
    /// Port removed.
    PortDel {
        bus: String,
        device: String,
        index: u32,
    },
    /// Health reporter state changed.
    HealthReporterChanged(HealthReporter),
    /// Flash update progress.
    FlashProgress(FlashProgress),
    /// Parameter value changed.
    ParamChanged(DevlinkParam),
}
```

## Connection API

```rust
impl Connection<Devlink> {
    /// Create a new devlink connection.
    ///
    /// Resolves the "devlink" GENL family ID asynchronously.
    pub async fn new_async() -> Result<Self>;

    // --- Device Queries ---

    /// List all devlink devices.
    pub async fn get_devices(&self) -> Result<Vec<DevlinkDevice>>;

    /// Get information for a specific device (driver, firmware versions).
    ///
    /// # Example
    ///
    /// ```ignore
    /// let info = conn.get_device_info("pci", "0000:03:00.0").await?;
    /// println!("Driver: {}", info.driver);
    /// for v in &info.versions_running {
    ///     println!("  {}: {}", v.name, v.value);
    /// }
    /// ```
    pub async fn get_device_info(
        &self,
        bus: &str,
        device: &str,
    ) -> Result<DevlinkInfo>;

    // --- Port Queries ---

    /// List all ports across all devices.
    pub async fn get_ports(&self) -> Result<Vec<DevlinkPort>>;

    /// List ports for a specific device.
    pub async fn get_device_ports(
        &self,
        bus: &str,
        device: &str,
    ) -> Result<Vec<DevlinkPort>>;

    /// Get a specific port by device and index.
    pub async fn get_port(
        &self,
        bus: &str,
        device: &str,
        index: u32,
    ) -> Result<Option<DevlinkPort>>;

    /// Find the port associated with a network interface name.
    ///
    /// Searches all ports for one with matching `netdev_name`.
    pub async fn get_port_by_netdev(
        &self,
        netdev: &str,
    ) -> Result<Option<DevlinkPort>>;

    // --- Health Reporters ---

    /// List all health reporters for a device.
    pub async fn get_health_reporters(
        &self,
        bus: &str,
        device: &str,
    ) -> Result<Vec<HealthReporter>>;

    /// Get a specific health reporter by name.
    pub async fn get_health_reporter(
        &self,
        bus: &str,
        device: &str,
        name: &str,
    ) -> Result<Option<HealthReporter>>;

    /// List health reporters that are in error state.
    ///
    /// Convenience method that filters `get_health_reporters()`.
    pub async fn get_health_errors(
        &self,
        bus: &str,
        device: &str,
    ) -> Result<Vec<HealthReporter>> {
        let reporters = self.get_health_reporters(bus, device).await?;
        Ok(reporters.into_iter().filter(|r| r.is_error()).collect())
    }

    // --- Parameters ---

    /// List all parameters for a device.
    pub async fn get_params(
        &self,
        bus: &str,
        device: &str,
    ) -> Result<Vec<DevlinkParam>>;

    /// Get a specific parameter by name.
    pub async fn get_param(
        &self,
        bus: &str,
        device: &str,
        name: &str,
    ) -> Result<Option<DevlinkParam>>;

    // --- Phase 2: Management Operations ---

    /// Trigger recovery on a health reporter.
    ///
    /// # Errors
    ///
    /// Returns `Error::Kernel` if the reporter doesn't support recovery.
    pub async fn health_reporter_recover(
        &self,
        bus: &str,
        device: &str,
        reporter: &str,
    ) -> Result<()>;

    /// Configure a health reporter.
    pub async fn set_health_reporter(
        &self,
        bus: &str,
        device: &str,
        reporter: &str,
        auto_recover: Option<bool>,
        auto_dump: Option<bool>,
        graceful_period_ms: Option<u64>,
    ) -> Result<()>;

    /// Flash firmware to a device.
    ///
    /// Returns immediately. Monitor progress via `DevlinkEvent::FlashProgress`
    /// events or by subscribing to the devlink multicast group.
    ///
    /// # Errors
    ///
    /// Returns `Error::Kernel` with `EBUSY` if a flash is already in progress.
    /// Returns `Error::Kernel` with `ENOENT` if the firmware file doesn't exist.
    pub async fn flash_update(
        &self,
        bus: &str,
        device: &str,
        request: FlashRequest,
    ) -> Result<()>;

    /// Reload a device (re-initialize driver or activate firmware).
    ///
    /// # Errors
    ///
    /// Returns `Error::Kernel` with `EOPNOTSUPP` if the reload action
    /// is not supported by the driver.
    pub async fn reload(
        &self,
        bus: &str,
        device: &str,
        action: ReloadAction,
    ) -> Result<()>;

    /// Split a port into sub-ports (e.g., 1x100G → 4x25G).
    ///
    /// # Errors
    ///
    /// Returns `Error::Kernel` with `ENOTSUP` if the port doesn't support splitting.
    pub async fn port_split(
        &self,
        bus: &str,
        device: &str,
        port_index: u32,
        count: u32,
    ) -> Result<()>;

    /// Unsplit a port (reverse of `port_split()`).
    pub async fn port_unsplit(
        &self,
        bus: &str,
        device: &str,
        port_index: u32,
    ) -> Result<()>;

    /// Set a device parameter value.
    pub async fn set_param(
        &self,
        bus: &str,
        device: &str,
        name: &str,
        cmode: ConfigMode,
        value: ParamData,
    ) -> Result<()>;

    // --- Event Monitoring ---

    /// Subscribe to devlink multicast events.
    pub fn subscribe(&mut self) -> Result<()>;

    /// Get event stream (borrowed).
    pub fn events(&self) -> impl Stream<Item = Result<DevlinkEvent>> + '_;

    /// Get owned event stream (consumes connection).
    pub fn into_events(self) -> impl Stream<Item = Result<DevlinkEvent>>;
}
```

## Internal: Attribute Parsing

```rust
/// Parse DevlinkInfo from DEVLINK_CMD_INFO_GET response.
fn parse_info(attrs: &AttrIter) -> Result<DevlinkInfo> {
    let mut info = DevlinkInfo {
        bus: String::new(),
        device: String::new(),
        driver: String::new(),
        serial: None,
        board_serial: None,
        versions_fixed: Vec::new(),
        versions_running: Vec::new(),
        versions_stored: Vec::new(),
    };

    for attr in attrs {
        match attr.attr_type() {
            DEVLINK_ATTR_BUS_NAME => {
                info.bus = attr.payload_str()
                    .ok_or_else(|| Error::InvalidAttribute("missing bus name".into()))?
                    .to_string();
            }
            DEVLINK_ATTR_DEV_NAME => {
                info.device = attr.payload_str()
                    .ok_or_else(|| Error::InvalidAttribute("missing device name".into()))?
                    .to_string();
            }
            DEVLINK_ATTR_INFO_DRIVER_NAME => {
                info.driver = attr.payload_str().unwrap_or("").to_string();
            }
            DEVLINK_ATTR_INFO_SERIAL_NUMBER => {
                info.serial = attr.payload_str().map(String::from);
            }
            DEVLINK_ATTR_INFO_BOARD_SERIAL_NUMBER => {
                info.board_serial = attr.payload_str().map(String::from);
            }
            DEVLINK_ATTR_INFO_VERSION_FIXED => {
                if let Some(version) = parse_version_nested(attr.nested())? {
                    info.versions_fixed.push(version);
                }
            }
            DEVLINK_ATTR_INFO_VERSION_RUNNING => {
                if let Some(version) = parse_version_nested(attr.nested())? {
                    info.versions_running.push(version);
                }
            }
            DEVLINK_ATTR_INFO_VERSION_STORED => {
                if let Some(version) = parse_version_nested(attr.nested())? {
                    info.versions_stored.push(version);
                }
            }
            _ => {}
        }
    }

    Ok(info)
}

/// Parse a version nested attribute (contains NAME + VALUE).
fn parse_version_nested(attrs: AttrIter) -> Result<Option<VersionInfo>> {
    let mut name = None;
    let mut value = None;

    for attr in attrs {
        match attr.attr_type() {
            DEVLINK_ATTR_INFO_VERSION_NAME => {
                name = attr.payload_str().map(String::from);
            }
            DEVLINK_ATTR_INFO_VERSION_VALUE => {
                value = attr.payload_str().map(String::from);
            }
            _ => {}
        }
    }

    match (name, value) {
        (Some(name), Some(value)) => Ok(Some(VersionInfo { name, value })),
        _ => Ok(None),
    }
}

/// Parse HealthReporter from nested DEVLINK_ATTR_HEALTH_REPORTER.
fn parse_health_reporter(
    bus: &str,
    device: &str,
    attrs: AttrIter,
) -> Result<HealthReporter> {
    let mut reporter = HealthReporter {
        bus: bus.to_string(),
        device: device.to_string(),
        name: String::new(),
        state: HealthState::Healthy,
        error_count: 0,
        recover_count: 0,
        auto_recover: false,
        auto_dump: false,
        graceful_period_ms: None,
        dump_ts_jiffies: None,
    };

    for attr in attrs {
        match attr.attr_type() {
            DEVLINK_ATTR_HEALTH_REPORTER_NAME => {
                reporter.name = attr.payload_str().unwrap_or("").to_string();
            }
            DEVLINK_ATTR_HEALTH_REPORTER_STATE => {
                reporter.state = attr.payload_u8()
                    .map(HealthState::try_from)
                    .transpose()?
                    .unwrap_or(HealthState::Healthy);
            }
            DEVLINK_ATTR_HEALTH_REPORTER_ERR_COUNT => {
                reporter.error_count = attr.payload_u64().unwrap_or(0);
            }
            DEVLINK_ATTR_HEALTH_REPORTER_RECOVER_COUNT => {
                reporter.recover_count = attr.payload_u64().unwrap_or(0);
            }
            DEVLINK_ATTR_HEALTH_REPORTER_AUTO_RECOVER => {
                reporter.auto_recover = attr.payload_u8().unwrap_or(0) != 0;
            }
            DEVLINK_ATTR_HEALTH_REPORTER_AUTO_DUMP => {
                reporter.auto_dump = attr.payload_u8().unwrap_or(0) != 0;
            }
            DEVLINK_ATTR_HEALTH_REPORTER_GRACEFUL_PERIOD => {
                reporter.graceful_period_ms = attr.payload_u64();
            }
            DEVLINK_ATTR_HEALTH_REPORTER_DUMP_TS => {
                reporter.dump_ts_jiffies = attr.payload_u64();
            }
            _ => {}
        }
    }

    Ok(reporter)
}
```

## Files to Create

```
crates/nlink/src/netlink/genl/devlink/
  mod.rs           - Constants (commands, attributes), typed enums
  types.rs         - DevlinkDevice, DevlinkInfo, DevlinkPort, HealthReporter, DevlinkParam
  connection.rs    - Connection<Devlink> API
```

## Estimated Effort

| Phase | Effort |
|-------|--------|
| Phase 1 (read-only: devices, info, ports, health, params) | 1 week |
| Phase 2 (flash, reload, port split, health recovery, param set) | 1-2 weeks |

## Notes

- Requires specific NIC hardware for testing (mlx5, ice recommended; `devlink dev` shows available)
- Follow the existing GENL pattern (see `genl/ethtool/`)
- Version nested attributes contain pairs: `DEVLINK_ATTR_INFO_VERSION_NAME` + `DEVLINK_ATTR_INFO_VERSION_VALUE` inside `DEVLINK_ATTR_INFO_VERSION_FIXED/RUNNING/STORED`
- Health reporter attributes are nested inside `DEVLINK_ATTR_HEALTH_REPORTER`
- Flash update is async — progress comes via multicast notifications
- Go's vishvananda/netlink and iproute2 have devlink implementations as reference
- Generic parameters are documented in `Documentation/networking/devlink/devlink-params.rst`
