# Plan 037: Devlink Support

## Overview

Add devlink Generic Netlink support for hardware device management. Used by modern NIC drivers (mlx5, ice, bnxt, nfp) for firmware info, health monitoring, and port configuration.

## Scope

### Phase 1: Read-Only (MVP)

- List devices and get driver/firmware info
- List ports with netdev mapping
- Get health reporters and their state

### Phase 2: Management (future)

- Firmware flash
- Reload device
- Port function configuration
- Health reporter recovery

## API Design

```rust
use nlink::netlink::{Connection, Devlink};

let conn = Connection::<Devlink>::new_async().await?;

// List devices
let devices = conn.get_devices().await?;
for dev in &devices {
    println!("{}/{}", dev.bus, dev.device);
}

// Get device info (driver, firmware versions)
let info = conn.get_device_info("pci", "0000:03:00.0").await?;
println!("Driver: {}", info.driver);
if let Some(serial) = &info.serial {
    println!("Serial: {serial}");
}
for version in &info.versions_running {
    println!("  {}: {}", version.name, version.value);
}

// List ports
let ports = conn.get_ports().await?;
for port in &ports {
    println!("  port {}: type={:?} netdev={:?}",
        port.index, port.port_type,
        port.netdev_name.as_deref().unwrap_or("-"));
}

// Get health reporters
let reporters = conn.get_health_reporters("pci", "0000:03:00.0").await?;
for r in &reporters {
    println!("  {}: state={:?} errors={} recoveries={}",
        r.name, r.state, r.error_count, r.recover_count);
}
```

### Types

```rust
#[derive(Debug, Clone)]
pub struct DevlinkDevice {
    pub bus: String,        // e.g., "pci"
    pub device: String,     // e.g., "0000:03:00.0"
}

#[derive(Debug, Clone)]
pub struct DevlinkInfo {
    pub driver: String,
    pub serial: Option<String>,
    pub versions_fixed: Vec<VersionInfo>,
    pub versions_running: Vec<VersionInfo>,
    pub versions_stored: Vec<VersionInfo>,
}

#[derive(Debug, Clone)]
pub struct VersionInfo {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone)]
pub struct DevlinkPort {
    pub bus: String,
    pub device: String,
    pub index: u32,
    pub port_type: PortType,
    pub netdev_ifindex: Option<u32>,
    pub netdev_name: Option<String>,
    pub flavour: Option<PortFlavour>,
    pub number: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortType {
    NotSet,   // 0
    Eth,      // 1
    Ib,       // 2
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortFlavour {
    Physical,       // 0
    CpuPort,        // 1
    DsaLocal,       // 2
    PciPf,          // 3
    PciVf,          // 4
    Virtual,        // 5
    PciSf,          // 6
}

#[derive(Debug, Clone)]
pub struct HealthReporter {
    pub name: String,
    pub state: HealthState,
    pub error_count: u64,
    pub recover_count: u64,
    pub auto_recover: bool,
    pub auto_dump: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HealthState {
    Healthy,  // 0
    Error,    // 1
}
```

## Key Kernel Constants

Commands:

| Command | Value | Purpose |
|---------|-------|---------|
| `DEVLINK_CMD_GET` | 1 | Dump devices |
| `DEVLINK_CMD_PORT_GET` | 5 | Dump ports |
| `DEVLINK_CMD_INFO_GET` | 51 | Get device info |
| `DEVLINK_CMD_HEALTH_REPORTER_GET` | 52 | Dump health reporters |

Attributes:

| Attribute | Value | Type |
|-----------|-------|------|
| `DEVLINK_ATTR_BUS_NAME` | 1 | string |
| `DEVLINK_ATTR_DEV_NAME` | 2 | string |
| `DEVLINK_ATTR_PORT_INDEX` | 3 | u32 |
| `DEVLINK_ATTR_PORT_TYPE` | 4 | u16 |
| `DEVLINK_ATTR_PORT_NETDEV_IFINDEX` | 6 | u32 |
| `DEVLINK_ATTR_PORT_NETDEV_NAME` | 7 | string |
| `DEVLINK_ATTR_INFO_DRIVER_NAME` | ~98 | string |
| `DEVLINK_ATTR_INFO_SERIAL_NUMBER` | ~99 | string |
| `DEVLINK_ATTR_INFO_VERSION_NAME` | ~103 | string |
| `DEVLINK_ATTR_INFO_VERSION_VALUE` | ~104 | string |
| `DEVLINK_ATTR_HEALTH_REPORTER_NAME` | ~114 | string |
| `DEVLINK_ATTR_HEALTH_REPORTER_STATE` | ~115 | u8 |
| `DEVLINK_ATTR_HEALTH_REPORTER_ERR_COUNT` | ~116 | u64 |
| `DEVLINK_ATTR_HEALTH_REPORTER_RECOVER_COUNT` | ~117 | u64 |
| `DEVLINK_ATTR_HEALTH_REPORTER_AUTO_RECOVER` | ~120 | u8 |

## Files to Create

```
crates/nlink/src/netlink/genl/devlink/
  mod.rs           - Constants, command/attribute enums
  types.rs         - DevlinkDevice, DevlinkInfo, DevlinkPort, HealthReporter
  connection.rs    - Connection<Devlink> API
```

## Estimated Effort

| Phase | Effort |
|-------|--------|
| Phase 1 (read-only MVP) | 1 week |
| Phase 2 (management) | 1-2 weeks (future) |

## Notes

- Requires specific NIC hardware for testing (mlx5, ice recommended)
- Follow existing GENL pattern (see `genl/ethtool/`)
- Go's vishvananda/netlink has devlink support as reference
- Attribute values above ~50 should be verified against the actual kernel header at build time
