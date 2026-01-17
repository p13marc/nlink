//! MACsec (IEEE 802.1AE) configuration via Generic Netlink.
//!
//! This module provides an API for configuring MACsec interfaces using
//! the kernel's Generic Netlink interface.
//!
//! MACsec provides Layer 2 encryption for:
//! - Datacenter interconnects
//! - Campus networks with security requirements
//! - Point-to-point secure links
//! - Compliance requirements (PCI-DSS, HIPAA)
//!
//! # Example
//!
//! ```rust,no_run
//! use nlink::netlink::{Connection, Macsec, Route};
//! use nlink::netlink::genl::macsec::{MacsecCipherSuite, MacsecSaBuilder};
//!
//! # async fn example() -> nlink::Result<()> {
//! // First get the interface index via a Route connection
//! let route_conn = Connection::<Route>::new()?;
//! let link = route_conn.get_link_by_name("macsec0").await?
//!     .ok_or_else(|| nlink::netlink::Error::InterfaceNotFound { name: "macsec0".into() })?;
//! let ifindex = link.ifindex();
//!
//! // Create a MACsec connection
//! let conn = Connection::<Macsec>::new_async().await?;
//!
//! // Get device information
//! let device = conn.get_device_by_index(ifindex).await?;
//! println!("SCI: {:016x}", device.sci);
//! println!("Cipher: {:?}", device.cipher);
//! println!("Encrypt: {}", device.encrypt);
//!
//! // Add a TX SA
//! let key = [0u8; 16]; // 128-bit key for GCM-AES-128
//! conn.add_tx_sa_by_index(ifindex,
//!     MacsecSaBuilder::new(0, &key)
//!         .active(true)
//! ).await?;
//!
//! // Add an RX SC and SA
//! let peer_sci: u64 = 0x001122334455_0001;
//! conn.add_rx_sc_by_index(ifindex, peer_sci).await?;
//! conn.add_rx_sa_by_index(ifindex, peer_sci,
//!     MacsecSaBuilder::new(0, &key)
//! ).await?;
//! # Ok(())
//! # }
//! ```

mod connection;
mod types;

pub use types::{
    MacsecCipherSuite, MacsecDevice, MacsecOffload, MacsecRxSa, MacsecRxSc, MacsecSaBuilder,
    MacsecTxSa, MacsecTxSc, MacsecValidate,
};

/// MACsec Generic Netlink family name.
pub const MACSEC_GENL_NAME: &str = "macsec";

/// MACsec Generic Netlink version.
pub const MACSEC_GENL_VERSION: u8 = 1;
