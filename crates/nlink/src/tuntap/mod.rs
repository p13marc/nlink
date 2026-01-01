//! TUN/TAP device management library.
//!
//! This crate provides a safe, strongly-typed API for creating and managing
//! TUN (network tunnel) and TAP (ethernet tunnel) devices on Linux.
//!
//! # Overview
//!
//! TUN devices operate at Layer 3 (IP) and TAP devices operate at Layer 2
//! (Ethernet). Both are virtual network interfaces that can be used for:
//!
//! - VPN implementations
//! - Network simulation
//! - Container networking
//! - Traffic capture and injection
//!
//! # Example
//!
//! ```ignore
//! use rip_tuntap::{TunTap, Mode};
//!
//! // Create a persistent TUN device
//! let tun = TunTap::builder()
//!     .name("mytun0")
//!     .mode(Mode::Tun)
//!     .persistent(true)
//!     .create()?;
//!
//! println!("Created device: {}", tun.name());
//!
//! // Create a TAP device owned by a specific user
//! let tap = TunTap::builder()
//!     .name("mytap0")
//!     .mode(Mode::Tap)
//!     .owner(1000)  // uid
//!     .group(1000)  // gid
//!     .persistent(true)
//!     .create()?;
//! ```
//!
//! # Async Support
//!
//! Enable the `async` feature for async read/write operations:
//!
//! ```ignore
//! use rip_tuntap::{TunTap, Mode};
//!
//! let mut tun = TunTap::builder()
//!     .name("mytun0")
//!     .mode(Mode::Tun)
//!     .create_async()
//!     .await?;
//!
//! // Read packets
//! let mut buf = [0u8; 1500];
//! let n = tun.read(&mut buf).await?;
//!
//! // Write packets
//! tun.write(&packet).await?;
//! ```

mod device;
mod error;

pub use device::{Mode, TunTap, TunTapBuilder, TunTapFlags};
pub use error::{Error, Result};

/// The path to the TUN device.
pub const TUN_DEVICE_PATH: &str = "/dev/net/tun";
