//! Kobject uevent implementation for `Connection<KobjectUevent>`.
//!
//! This module provides methods for receiving kernel object events via the
//! NETLINK_KOBJECT_UEVENT protocol. These are the same events that udev uses
//! for device hotplugging.
//!
//! # Example
//!
//! ```ignore
//! use nlink::netlink::{Connection, KobjectUevent};
//!
//! let conn = Connection::<KobjectUevent>::new()?;
//!
//! loop {
//!     let event = conn.recv().await?;
//!     println!("[{}] {} ({})", event.action, event.devpath, event.subsystem);
//! }
//! ```

use std::collections::HashMap;

use super::connection::Connection;
use super::error::{Error, Result};
use super::protocol::{KobjectUevent, ProtocolState};
use super::socket::NetlinkSocket;

/// Multicast group for kernel uevents.
const UEVENT_GROUP: u32 = 1;

/// A kernel object event.
///
/// Uevents are text-based messages containing KEY=VALUE pairs that describe
/// device state changes. The kernel broadcasts these when devices are added,
/// removed, or their state changes.
#[derive(Debug, Clone)]
pub struct Uevent {
    /// Action type: "add", "remove", "change", "move", "online", "offline", "bind", "unbind".
    pub action: String,
    /// Device path in sysfs (e.g., "/devices/pci0000:00/0000:00:14.0/usb1/1-1").
    pub devpath: String,
    /// Subsystem name (e.g., "usb", "block", "net", "input").
    pub subsystem: String,
    /// All environment variables as key-value pairs.
    ///
    /// Common keys include:
    /// - `DEVNAME`: Device node name (e.g., "sda", "ttyUSB0")
    /// - `DEVTYPE`: Device type (e.g., "disk", "partition", "usb_device")
    /// - `DRIVER`: Driver name
    /// - `MAJOR`/`MINOR`: Device numbers
    /// - `SEQNUM`: Event sequence number
    pub env: HashMap<String, String>,
}

impl Uevent {
    /// Parse a uevent from raw message data.
    ///
    /// Uevent format: header@devpath\0KEY=VALUE\0KEY=VALUE\0...
    pub fn parse(data: &[u8]) -> Option<Self> {
        // Find the header (action@devpath)
        let first_null = data.iter().position(|&b| b == 0)?;
        let header = std::str::from_utf8(&data[..first_null]).ok()?;

        // Parse action@devpath
        let at_pos = header.find('@')?;
        let action = header[..at_pos].to_string();
        let devpath = header[at_pos + 1..].to_string();

        // Parse KEY=VALUE pairs
        let mut env = HashMap::new();
        let mut subsystem = String::new();

        let mut offset = first_null + 1;
        while offset < data.len() {
            // Find next null terminator
            let end = data[offset..]
                .iter()
                .position(|&b| b == 0)
                .map(|p| offset + p)
                .unwrap_or(data.len());

            if end > offset
                && let Ok(kv) = std::str::from_utf8(&data[offset..end])
                && let Some(eq_pos) = kv.find('=')
            {
                let key = &kv[..eq_pos];
                let value = &kv[eq_pos + 1..];
                if key == "SUBSYSTEM" {
                    subsystem = value.to_string();
                }
                env.insert(key.to_string(), value.to_string());
            }

            offset = end + 1;
        }

        Some(Self {
            action,
            devpath,
            subsystem,
            env,
        })
    }

    /// Get the device name if available (e.g., "sda1", "eth0").
    pub fn devname(&self) -> Option<&str> {
        self.env.get("DEVNAME").map(|s| s.as_str())
    }

    /// Get the device type if available (e.g., "disk", "partition").
    pub fn devtype(&self) -> Option<&str> {
        self.env.get("DEVTYPE").map(|s| s.as_str())
    }

    /// Get the driver name if available.
    pub fn driver(&self) -> Option<&str> {
        self.env.get("DRIVER").map(|s| s.as_str())
    }

    /// Get the major device number if available.
    pub fn major(&self) -> Option<u32> {
        self.env.get("MAJOR").and_then(|s| s.parse().ok())
    }

    /// Get the minor device number if available.
    pub fn minor(&self) -> Option<u32> {
        self.env.get("MINOR").and_then(|s| s.parse().ok())
    }

    /// Get the event sequence number.
    pub fn seqnum(&self) -> Option<u64> {
        self.env.get("SEQNUM").and_then(|s| s.parse().ok())
    }

    /// Check if this is an "add" event.
    pub fn is_add(&self) -> bool {
        self.action == "add"
    }

    /// Check if this is a "remove" event.
    pub fn is_remove(&self) -> bool {
        self.action == "remove"
    }

    /// Check if this is a "change" event.
    pub fn is_change(&self) -> bool {
        self.action == "change"
    }

    /// Check if this is a "bind" event (driver bound to device).
    pub fn is_bind(&self) -> bool {
        self.action == "bind"
    }

    /// Check if this is an "unbind" event (driver unbound from device).
    pub fn is_unbind(&self) -> bool {
        self.action == "unbind"
    }
}

impl Connection<KobjectUevent> {
    /// Create a new uevent connection subscribed to kernel events.
    ///
    /// The connection is automatically subscribed to the kernel uevent
    /// multicast group.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use nlink::netlink::{Connection, KobjectUevent};
    ///
    /// let conn = Connection::<KobjectUevent>::new()?;
    /// ```
    pub fn new() -> Result<Self> {
        let mut socket = NetlinkSocket::new(KobjectUevent::PROTOCOL)?;
        socket.add_membership(UEVENT_GROUP)?;
        Ok(Self::from_parts(socket, KobjectUevent))
    }

    /// Receive the next uevent from the kernel.
    ///
    /// This method blocks until a uevent is available.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use nlink::netlink::{Connection, KobjectUevent};
    ///
    /// let conn = Connection::<KobjectUevent>::new()?;
    ///
    /// loop {
    ///     let event = conn.recv().await?;
    ///     if event.is_add() && event.subsystem == "usb" {
    ///         println!("USB device added: {:?}", event.devname());
    ///     }
    /// }
    /// ```
    pub async fn recv(&self) -> Result<Uevent> {
        loop {
            let data = self.socket().recv_msg().await?;

            if let Some(event) = Uevent::parse(&data) {
                return Ok(event);
            }
            // Invalid message, try again
        }
    }

    /// Try to receive a uevent without blocking.
    ///
    /// Returns `Ok(None)` if no event is immediately available.
    pub fn try_recv(&self) -> Result<Option<Uevent>> {
        // For now, this is not implemented as it would require non-blocking recv
        // The async recv() is the primary API
        Err(Error::not_supported("try_recv not implemented"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_uevent() {
        // Simulated uevent message
        let msg = b"add@/devices/pci0000:00/0000:00:14.0/usb1/1-1\0ACTION=add\0DEVPATH=/devices/pci0000:00/0000:00:14.0/usb1/1-1\0SUBSYSTEM=usb\0DEVTYPE=usb_device\0SEQNUM=12345\0";

        let event = Uevent::parse(msg).unwrap();
        assert_eq!(event.action, "add");
        assert_eq!(event.devpath, "/devices/pci0000:00/0000:00:14.0/usb1/1-1");
        assert_eq!(event.subsystem, "usb");
        assert_eq!(event.devtype(), Some("usb_device"));
        assert_eq!(event.seqnum(), Some(12345));
        assert!(event.is_add());
        assert!(!event.is_remove());
    }

    #[test]
    fn parse_uevent_with_devname() {
        let msg = b"add@/devices/virtual/block/loop0\0ACTION=add\0DEVPATH=/devices/virtual/block/loop0\0SUBSYSTEM=block\0DEVNAME=loop0\0DEVTYPE=disk\0MAJOR=7\0MINOR=0\0";

        let event = Uevent::parse(msg).unwrap();
        assert_eq!(event.subsystem, "block");
        assert_eq!(event.devname(), Some("loop0"));
        assert_eq!(event.major(), Some(7));
        assert_eq!(event.minor(), Some(0));
    }
}
