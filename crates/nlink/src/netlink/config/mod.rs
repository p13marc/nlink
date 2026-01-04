//! Declarative network configuration.
//!
//! This module provides a declarative API for specifying desired network state
//! and computing/applying the necessary changes to achieve it.
//!
//! # Overview
//!
//! Instead of imperatively calling `add_link`, `add_address`, etc., you describe
//! the desired state and let the library figure out what changes are needed:
//!
//! ```ignore
//! use nlink::netlink::{Connection, Route};
//! use nlink::netlink::config::NetworkConfig;
//!
//! let conn = Connection::<Route>::new()?;
//!
//! // Define desired state
//! let config = NetworkConfig::new()
//!     .link("br0", |l| l.bridge().up())
//!     .link("veth0", |l| l.veth("veth1").master("br0").up())
//!     .address("br0", "192.168.100.1/24")?
//!     .route("10.0.0.0/8", |r| r.via("192.168.100.254"))?;
//!
//! // Preview changes
//! let diff = config.diff(&conn).await?;
//! println!("{}", diff.summary());
//!
//! // Apply changes
//! config.apply(&conn).await?;
//! ```
//!
//! # Benefits
//!
//! - **Idempotent**: Running the same config multiple times produces the same result
//! - **Diff-based**: Only makes necessary changes
//! - **Ordered**: Applies changes in the correct order (links before addresses, etc.)
//! - **Dry-run**: Preview changes before applying
//!
//! # Supported Resources
//!
//! - Links (interfaces): dummy, veth, bridge, vlan, vxlan, macvlan, bond
//! - Addresses: IPv4 and IPv6
//! - Routes: IPv4 and IPv6, with gateway, device, or multipath
//! - Qdiscs: netem, htb, fq_codel, tbf, etc.

mod apply;
mod diff;
mod types;

pub use apply::{ApplyOptions, ApplyResult};
pub use diff::ConfigDiff;
pub use types::*;

use super::connection::Connection;
use super::error::Result;
use super::protocol::Route;

impl NetworkConfig {
    /// Compute the difference between desired and current state.
    ///
    /// This fetches the current network state and compares it against
    /// the desired configuration, returning a diff of what needs to change.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let diff = config.diff(&conn).await?;
    /// if !diff.is_empty() {
    ///     println!("Changes needed:\n{}", diff.summary());
    /// }
    /// ```
    pub async fn diff(&self, conn: &Connection<Route>) -> Result<ConfigDiff> {
        diff::compute_diff(self, conn).await
    }

    /// Apply the configuration to achieve the desired state.
    ///
    /// This computes the diff and applies all necessary changes.
    /// Changes are applied in the correct order:
    /// 1. Create new links
    /// 2. Modify existing links
    /// 3. Add addresses
    /// 4. Add routes
    /// 5. Configure qdiscs
    /// 6. Remove old resources (if purge is enabled)
    ///
    /// # Example
    ///
    /// ```ignore
    /// let result = config.apply(&conn).await?;
    /// println!("Made {} changes", result.changes_made);
    /// ```
    pub async fn apply(&self, conn: &Connection<Route>) -> Result<ApplyResult> {
        self.apply_with_options(conn, ApplyOptions::default()).await
    }

    /// Apply the configuration with custom options.
    ///
    /// # Options
    ///
    /// - `dry_run`: Compute diff but don't make any changes
    /// - `continue_on_error`: Keep going if some operations fail
    /// - `purge`: Remove resources not in the config
    ///
    /// # Example
    ///
    /// ```ignore
    /// // Dry run first
    /// let result = config.apply_with_options(&conn, ApplyOptions {
    ///     dry_run: true,
    ///     ..Default::default()
    /// }).await?;
    /// println!("Would make {} changes", result.changes_made);
    ///
    /// // Then apply for real
    /// config.apply(&conn).await?;
    /// ```
    pub async fn apply_with_options(
        &self,
        conn: &Connection<Route>,
        options: ApplyOptions,
    ) -> Result<ApplyResult> {
        apply::apply_config(self, conn, options).await
    }
}
