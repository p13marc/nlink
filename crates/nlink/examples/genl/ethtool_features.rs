//! List device features (offloads) for a network interface.
//!
//! This example demonstrates how to use the ethtool netlink interface
//! to query the hardware offload features of a network interface.
//!
//! # Usage
//!
//! ```bash
//! cargo run --example ethtool_features -- eth0
//! ```
//!
//! # Requirements
//!
//! - Linux kernel 5.6+ with ethtool netlink support
//! - No special privileges required for read operations

use nlink::netlink::{Connection, Ethtool};

#[tokio::main]
async fn main() -> nlink::Result<()> {
    let ifname = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "eth0".to_string());

    println!("Querying features for {}...\n", ifname);

    let conn = Connection::<Ethtool>::new_async().await?;
    let features = conn.get_features(&ifname).await?;

    println!("Features for {}:", ifname);
    println!();

    // Collect and sort features
    let mut feature_list: Vec<_> = features.iter().collect();
    feature_list.sort_by_key(|(name, _)| *name);

    for (name, enabled) in feature_list {
        let status = if enabled { "on" } else { "off" };
        let changeable = if features.is_changeable(name) {
            ""
        } else {
            " [fixed]"
        };
        let hw = if features.is_hw_supported(name) {
            ""
        } else {
            " [not hw]"
        };
        println!("  {}: {}{}{}", name, status, changeable, hw);
    }

    // Summary
    let active_count = features.active_features().len();
    let total = features.active.len();
    println!();
    println!("Summary: {} of {} features enabled", active_count, total);

    Ok(())
}
