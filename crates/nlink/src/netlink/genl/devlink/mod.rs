//! Devlink Generic Netlink support for hardware device management.
//!
//! This module provides a typed API for querying devlink devices, ports,
//! firmware info, health reporters, and device parameters via Generic Netlink.
//!
//! # Example
//!
//! ```ignore
//! use nlink::netlink::{Connection, Devlink};
//!
//! let conn = Connection::<Devlink>::new_async().await?;
//!
//! // List all devlink devices
//! let devices = conn.get_devices().await?;
//! for dev in &devices {
//!     println!("{}", dev.path());
//! }
//!
//! // Get firmware info
//! let info = conn.get_device_info("pci", "0000:03:00.0").await?;
//! println!("Driver: {}", info.driver);
//! for v in &info.versions_running {
//!     println!("  {}: {}", v.name, v.value);
//! }
//! ```

pub mod connection;
pub mod types;

pub use types::*;

/// Devlink GENL family name.
pub const DEVLINK_GENL_NAME: &str = "devlink";

/// Devlink GENL version.
pub const DEVLINK_GENL_VERSION: u8 = 1;

// Commands
pub const DEVLINK_CMD_GET: u8 = 1;
pub const DEVLINK_CMD_PORT_GET: u8 = 5;
pub const DEVLINK_CMD_PORT_SPLIT: u8 = 9;
pub const DEVLINK_CMD_PORT_UNSPLIT: u8 = 10;
pub const DEVLINK_CMD_RELOAD: u8 = 37;
pub const DEVLINK_CMD_PARAM_GET: u8 = 38;
pub const DEVLINK_CMD_PARAM_SET: u8 = 39;
pub const DEVLINK_CMD_INFO_GET: u8 = 51;
pub const DEVLINK_CMD_HEALTH_REPORTER_GET: u8 = 52;
pub const DEVLINK_CMD_HEALTH_REPORTER_SET: u8 = 53;
pub const DEVLINK_CMD_HEALTH_REPORTER_RECOVER: u8 = 54;
pub const DEVLINK_CMD_FLASH_UPDATE: u8 = 58;

// Device/Port attributes
pub const DEVLINK_ATTR_BUS_NAME: u16 = 1;
pub const DEVLINK_ATTR_DEV_NAME: u16 = 2;
pub const DEVLINK_ATTR_PORT_INDEX: u16 = 3;
pub const DEVLINK_ATTR_PORT_TYPE: u16 = 4;
pub const DEVLINK_ATTR_PORT_NETDEV_IFINDEX: u16 = 6;
pub const DEVLINK_ATTR_PORT_NETDEV_NAME: u16 = 7;
pub const DEVLINK_ATTR_PORT_IBDEV_NAME: u16 = 8;
pub const DEVLINK_ATTR_PORT_SPLIT_COUNT: u16 = 9;
pub const DEVLINK_ATTR_PORT_SPLIT_GROUP: u16 = 10;
pub const DEVLINK_ATTR_PORT_FLAVOUR: u16 = 77;
pub const DEVLINK_ATTR_PORT_NUMBER: u16 = 78;
pub const DEVLINK_ATTR_PORT_SPLIT_SUBPORT_NUMBER: u16 = 79;
pub const DEVLINK_ATTR_PORT_PCI_PF_NUMBER: u16 = 127;
pub const DEVLINK_ATTR_PORT_CONTROLLER_NUMBER: u16 = 150;
pub const DEVLINK_ATTR_PORT_PCI_SF_NUMBER: u16 = 164;
pub const DEVLINK_ATTR_PORT_PCI_VF_NUMBER: u16 = 170;

// Info attributes
pub const DEVLINK_ATTR_INFO_DRIVER_NAME: u16 = 98;
pub const DEVLINK_ATTR_INFO_SERIAL_NUMBER: u16 = 99;
pub const DEVLINK_ATTR_INFO_VERSION_FIXED: u16 = 100;
pub const DEVLINK_ATTR_INFO_VERSION_RUNNING: u16 = 101;
pub const DEVLINK_ATTR_INFO_VERSION_STORED: u16 = 102;
pub const DEVLINK_ATTR_INFO_VERSION_NAME: u16 = 103;
pub const DEVLINK_ATTR_INFO_VERSION_VALUE: u16 = 104;
pub const DEVLINK_ATTR_INFO_BOARD_SERIAL_NUMBER: u16 = 141;

// Health reporter attributes
pub const DEVLINK_ATTR_HEALTH_REPORTER: u16 = 114;
pub const DEVLINK_ATTR_HEALTH_REPORTER_NAME: u16 = 115;
pub const DEVLINK_ATTR_HEALTH_REPORTER_STATE: u16 = 116;
pub const DEVLINK_ATTR_HEALTH_REPORTER_ERR_COUNT: u16 = 117;
pub const DEVLINK_ATTR_HEALTH_REPORTER_RECOVER_COUNT: u16 = 118;
pub const DEVLINK_ATTR_HEALTH_REPORTER_DUMP_TS: u16 = 119;
pub const DEVLINK_ATTR_HEALTH_REPORTER_GRACEFUL_PERIOD: u16 = 120;
pub const DEVLINK_ATTR_HEALTH_REPORTER_AUTO_RECOVER: u16 = 121;
pub const DEVLINK_ATTR_HEALTH_REPORTER_AUTO_DUMP: u16 = 136;

// Flash update attributes
pub const DEVLINK_ATTR_FLASH_UPDATE_FILE_NAME: u16 = 122;
pub const DEVLINK_ATTR_FLASH_UPDATE_COMPONENT: u16 = 123;
pub const DEVLINK_ATTR_FLASH_UPDATE_STATUS_MSG: u16 = 128;
pub const DEVLINK_ATTR_FLASH_UPDATE_STATUS_DONE: u16 = 129;
pub const DEVLINK_ATTR_FLASH_UPDATE_STATUS_TOTAL: u16 = 130;

// Reload attributes
pub const DEVLINK_ATTR_RELOAD_ACTION: u16 = 153;

// Parameter attributes
pub const DEVLINK_ATTR_PARAM: u16 = 80;
pub const DEVLINK_ATTR_PARAM_NAME: u16 = 81;
pub const DEVLINK_ATTR_PARAM_GENERIC: u16 = 82;
pub const DEVLINK_ATTR_PARAM_TYPE: u16 = 83;
pub const DEVLINK_ATTR_PARAM_VALUES_LIST: u16 = 84;
pub const DEVLINK_ATTR_PARAM_VALUE: u16 = 85;
pub const DEVLINK_ATTR_PARAM_VALUE_DATA: u16 = 86;
pub const DEVLINK_ATTR_PARAM_VALUE_CMODE: u16 = 87;

// Notification commands (received via multicast)
pub const DEVLINK_CMD_PORT_NEW: u8 = 6;
pub const DEVLINK_CMD_PORT_DEL: u8 = 7;
pub const DEVLINK_CMD_FLASH_UPDATE_STATUS: u8 = 60;

/// Devlink multicast group name.
pub const DEVLINK_MCGRP_NAME: &str = "devlink";
