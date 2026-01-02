//! Statistics helpers for computing deltas and rates.
//!
//! This module provides utilities for tracking network statistics over time,
//! computing deltas between snapshots, and calculating rates.
//!
//! # Example
//!
//! ```ignore
//! use nlink::netlink::stats::{StatsSnapshot, StatsTracker};
//! use std::time::Duration;
//!
//! // Option 1: Manual rate calculation between snapshots
//! let links = conn.get_links().await?;
//! let snapshot1 = StatsSnapshot::from_links(&links);
//!
//! tokio::time::sleep(Duration::from_secs(1)).await;
//!
//! let links = conn.get_links().await?;
//! let snapshot2 = StatsSnapshot::from_links(&links);
//!
//! let rates = snapshot2.rates(&snapshot1, Duration::from_secs(1));
//! for (ifindex, link_rates) in &rates.links {
//!     println!("Interface {}: {:.2} Mbps RX, {:.2} Mbps TX",
//!         ifindex,
//!         link_rates.rx_bps() / 1_000_000.0,
//!         link_rates.tx_bps() / 1_000_000.0);
//! }
//!
//! // Option 2: Use StatsTracker for continuous monitoring
//! let mut tracker = StatsTracker::new();
//! loop {
//!     let links = conn.get_links().await?;
//!     let snapshot = StatsSnapshot::from_links(&links);
//!     if let Some(rates) = tracker.update(snapshot) {
//!         println!("Total: {:.2} Mbps", rates.total_bytes_per_sec() * 8.0 / 1_000_000.0);
//!     }
//!     tokio::time::sleep(Duration::from_secs(1)).await;
//! }
//! ```

use std::collections::HashMap;
use std::time::Duration;

use super::messages::{LinkMessage, TcMessage};

/// Statistics for a network interface.
#[derive(Debug, Clone, Default)]
pub struct LinkStats {
    /// Interface name.
    pub name: Option<String>,
    /// Bytes received.
    pub rx_bytes: u64,
    /// Bytes transmitted.
    pub tx_bytes: u64,
    /// Packets received.
    pub rx_packets: u64,
    /// Packets transmitted.
    pub tx_packets: u64,
    /// Receive errors.
    pub rx_errors: u64,
    /// Transmit errors.
    pub tx_errors: u64,
    /// Receive drops.
    pub rx_dropped: u64,
    /// Transmit drops.
    pub tx_dropped: u64,
    /// Multicast packets received.
    pub multicast: u64,
    /// Collisions.
    pub collisions: u64,
}

impl LinkStats {
    /// Create from a LinkMessage.
    pub fn from_link_message(msg: &LinkMessage) -> Self {
        if let Some(ref stats) = msg.stats {
            Self {
                name: msg.name.clone(),
                rx_bytes: stats.rx_bytes,
                tx_bytes: stats.tx_bytes,
                rx_packets: stats.rx_packets,
                tx_packets: stats.tx_packets,
                rx_errors: stats.rx_errors,
                tx_errors: stats.tx_errors,
                rx_dropped: stats.rx_dropped,
                tx_dropped: stats.tx_dropped,
                multicast: stats.multicast,
                collisions: stats.collisions,
            }
        } else {
            Self {
                name: msg.name.clone(),
                ..Default::default()
            }
        }
    }

    /// Total bytes (RX + TX).
    pub fn total_bytes(&self) -> u64 {
        self.rx_bytes + self.tx_bytes
    }

    /// Total packets (RX + TX).
    pub fn total_packets(&self) -> u64 {
        self.rx_packets + self.tx_packets
    }

    /// Total errors (RX + TX).
    pub fn total_errors(&self) -> u64 {
        self.rx_errors + self.tx_errors
    }

    /// Total drops (RX + TX).
    pub fn total_dropped(&self) -> u64 {
        self.rx_dropped + self.tx_dropped
    }
}

/// Rate statistics for a network interface (per second).
#[derive(Debug, Clone, Default)]
pub struct LinkRates {
    /// Interface name.
    pub name: Option<String>,
    /// Bytes per second received.
    pub rx_bytes_per_sec: f64,
    /// Bytes per second transmitted.
    pub tx_bytes_per_sec: f64,
    /// Packets per second received.
    pub rx_packets_per_sec: f64,
    /// Packets per second transmitted.
    pub tx_packets_per_sec: f64,
    /// Receive errors per second.
    pub rx_errors_per_sec: f64,
    /// Transmit errors per second.
    pub tx_errors_per_sec: f64,
    /// Receive drops per second.
    pub rx_dropped_per_sec: f64,
    /// Transmit drops per second.
    pub tx_dropped_per_sec: f64,
}

impl LinkRates {
    /// Total bytes per second (RX + TX).
    pub fn total_bytes_per_sec(&self) -> f64 {
        self.rx_bytes_per_sec + self.tx_bytes_per_sec
    }

    /// Total packets per second (RX + TX).
    pub fn total_packets_per_sec(&self) -> f64 {
        self.rx_packets_per_sec + self.tx_packets_per_sec
    }

    /// RX bandwidth in bits per second.
    pub fn rx_bps(&self) -> f64 {
        self.rx_bytes_per_sec * 8.0
    }

    /// TX bandwidth in bits per second.
    pub fn tx_bps(&self) -> f64 {
        self.tx_bytes_per_sec * 8.0
    }

    /// Total bandwidth in bits per second.
    pub fn total_bps(&self) -> f64 {
        self.total_bytes_per_sec() * 8.0
    }
}

/// Statistics for a TC qdisc/class.
#[derive(Debug, Clone, Default)]
pub struct TcStats {
    /// Qdisc/class kind.
    pub kind: Option<String>,
    /// Bytes transmitted.
    pub bytes: u64,
    /// Packets transmitted.
    pub packets: u64,
    /// Packets dropped.
    pub drops: u32,
    /// Packets overlimit.
    pub overlimits: u32,
    /// Packets requeued.
    pub requeues: u32,
    /// Current queue length.
    pub qlen: u32,
    /// Current backlog in bytes.
    pub backlog: u32,
}

impl TcStats {
    /// Create from a TcMessage.
    pub fn from_tc_message(msg: &TcMessage) -> Self {
        Self {
            kind: msg.kind.clone(),
            bytes: msg.bytes(),
            packets: msg.packets(),
            drops: msg.drops(),
            overlimits: msg.overlimits(),
            requeues: msg.requeues(),
            qlen: msg.qlen(),
            backlog: msg.backlog(),
        }
    }
}

/// Rate statistics for a TC qdisc/class (per second).
#[derive(Debug, Clone, Default)]
pub struct TcRates {
    /// Qdisc/class kind.
    pub kind: Option<String>,
    /// Bytes per second.
    pub bytes_per_sec: f64,
    /// Packets per second.
    pub packets_per_sec: f64,
    /// Drops per second.
    pub drops_per_sec: f64,
    /// Overlimits per second.
    pub overlimits_per_sec: f64,
    /// Requeues per second.
    pub requeues_per_sec: f64,
}

impl TcRates {
    /// Bandwidth in bits per second.
    pub fn bps(&self) -> f64 {
        self.bytes_per_sec * 8.0
    }
}

/// A snapshot of network statistics at a point in time.
#[derive(Debug, Clone, Default)]
pub struct StatsSnapshot {
    /// Link statistics by interface index.
    pub links: HashMap<u32, LinkStats>,
    /// Qdisc statistics by (ifindex, handle).
    pub qdiscs: HashMap<(u32, u32), TcStats>,
    /// Class statistics by (ifindex, handle).
    pub classes: HashMap<(u32, u32), TcStats>,
}

impl StatsSnapshot {
    /// Create a new empty snapshot.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a snapshot from link messages.
    pub fn from_links(links: &[LinkMessage]) -> Self {
        let mut snapshot = Self::new();
        for link in links {
            let stats = LinkStats::from_link_message(link);
            snapshot.links.insert(link.ifindex(), stats);
        }
        snapshot
    }

    /// Create a snapshot from TC messages.
    pub fn from_tc(qdiscs: &[TcMessage], classes: &[TcMessage]) -> Self {
        let mut snapshot = Self::new();

        for qdisc in qdiscs {
            let stats = TcStats::from_tc_message(qdisc);
            snapshot
                .qdiscs
                .insert((qdisc.ifindex(), qdisc.handle()), stats);
        }

        for class in classes {
            let stats = TcStats::from_tc_message(class);
            snapshot
                .classes
                .insert((class.ifindex(), class.handle()), stats);
        }

        snapshot
    }

    /// Add link statistics to the snapshot.
    pub fn add_links(&mut self, links: &[LinkMessage]) {
        for link in links {
            let stats = LinkStats::from_link_message(link);
            self.links.insert(link.ifindex(), stats);
        }
    }

    /// Add qdisc statistics to the snapshot.
    pub fn add_qdiscs(&mut self, qdiscs: &[TcMessage]) {
        for qdisc in qdiscs {
            let stats = TcStats::from_tc_message(qdisc);
            self.qdiscs.insert((qdisc.ifindex(), qdisc.handle()), stats);
        }
    }

    /// Add class statistics to the snapshot.
    pub fn add_classes(&mut self, classes: &[TcMessage]) {
        for class in classes {
            let stats = TcStats::from_tc_message(class);
            self.classes
                .insert((class.ifindex(), class.handle()), stats);
        }
    }

    /// Compute rates between this snapshot and a previous one.
    ///
    /// Returns rate statistics for all interfaces and TC objects that exist
    /// in both snapshots.
    pub fn rates(&self, previous: &StatsSnapshot, duration: Duration) -> RatesSnapshot {
        let secs = duration.as_secs_f64();
        if secs <= 0.0 {
            return RatesSnapshot::default();
        }

        let mut rates = RatesSnapshot::new();

        // Compute link rates
        for (ifindex, current) in &self.links {
            if let Some(prev) = previous.links.get(ifindex) {
                rates.links.insert(
                    *ifindex,
                    LinkRates {
                        name: current.name.clone(),
                        rx_bytes_per_sec: delta_u64(current.rx_bytes, prev.rx_bytes) / secs,
                        tx_bytes_per_sec: delta_u64(current.tx_bytes, prev.tx_bytes) / secs,
                        rx_packets_per_sec: delta_u64(current.rx_packets, prev.rx_packets) / secs,
                        tx_packets_per_sec: delta_u64(current.tx_packets, prev.tx_packets) / secs,
                        rx_errors_per_sec: delta_u64(current.rx_errors, prev.rx_errors) / secs,
                        tx_errors_per_sec: delta_u64(current.tx_errors, prev.tx_errors) / secs,
                        rx_dropped_per_sec: delta_u64(current.rx_dropped, prev.rx_dropped) / secs,
                        tx_dropped_per_sec: delta_u64(current.tx_dropped, prev.tx_dropped) / secs,
                    },
                );
            }
        }

        // Compute qdisc rates
        for (key, current) in &self.qdiscs {
            if let Some(prev) = previous.qdiscs.get(key) {
                rates.qdiscs.insert(
                    *key,
                    TcRates {
                        kind: current.kind.clone(),
                        bytes_per_sec: delta_u64(current.bytes, prev.bytes) / secs,
                        packets_per_sec: delta_u64(current.packets, prev.packets) / secs,
                        drops_per_sec: delta_u32(current.drops, prev.drops) / secs,
                        overlimits_per_sec: delta_u32(current.overlimits, prev.overlimits) / secs,
                        requeues_per_sec: delta_u32(current.requeues, prev.requeues) / secs,
                    },
                );
            }
        }

        // Compute class rates
        for (key, current) in &self.classes {
            if let Some(prev) = previous.classes.get(key) {
                rates.classes.insert(
                    *key,
                    TcRates {
                        kind: current.kind.clone(),
                        bytes_per_sec: delta_u64(current.bytes, prev.bytes) / secs,
                        packets_per_sec: delta_u64(current.packets, prev.packets) / secs,
                        drops_per_sec: delta_u32(current.drops, prev.drops) / secs,
                        overlimits_per_sec: delta_u32(current.overlimits, prev.overlimits) / secs,
                        requeues_per_sec: delta_u32(current.requeues, prev.requeues) / secs,
                    },
                );
            }
        }

        rates
    }
}

/// A snapshot of rate statistics.
#[derive(Debug, Clone, Default)]
pub struct RatesSnapshot {
    /// Link rates by interface index.
    pub links: HashMap<u32, LinkRates>,
    /// Qdisc rates by (ifindex, handle).
    pub qdiscs: HashMap<(u32, u32), TcRates>,
    /// Class rates by (ifindex, handle).
    pub classes: HashMap<(u32, u32), TcRates>,
}

impl RatesSnapshot {
    /// Create a new empty rates snapshot.
    pub fn new() -> Self {
        Self::default()
    }

    /// Get total RX bytes per second across all interfaces.
    pub fn total_rx_bytes_per_sec(&self) -> f64 {
        self.links.values().map(|r| r.rx_bytes_per_sec).sum()
    }

    /// Get total TX bytes per second across all interfaces.
    pub fn total_tx_bytes_per_sec(&self) -> f64 {
        self.links.values().map(|r| r.tx_bytes_per_sec).sum()
    }

    /// Get total bytes per second across all interfaces.
    pub fn total_bytes_per_sec(&self) -> f64 {
        self.total_rx_bytes_per_sec() + self.total_tx_bytes_per_sec()
    }
}

/// Compute delta between two u64 values, handling counter wrap.
#[inline]
fn delta_u64(current: u64, previous: u64) -> f64 {
    if current >= previous {
        (current - previous) as f64
    } else {
        // Counter wrapped - assume 64-bit wrap
        (u64::MAX - previous + current + 1) as f64
    }
}

/// Compute delta between two u32 values, handling counter wrap.
#[inline]
fn delta_u32(current: u32, previous: u32) -> f64 {
    if current >= previous {
        (current - previous) as f64
    } else {
        // Counter wrapped - assume 32-bit wrap
        (u32::MAX - previous + current + 1) as f64
    }
}

/// Helper struct for tracking statistics over time.
///
/// This maintains the previous snapshot and computes rates automatically.
#[derive(Debug, Clone)]
pub struct StatsTracker {
    previous: Option<StatsSnapshot>,
    previous_time: Option<std::time::Instant>,
}

impl Default for StatsTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl StatsTracker {
    /// Create a new stats tracker.
    pub fn new() -> Self {
        Self {
            previous: None,
            previous_time: None,
        }
    }

    /// Update with a new snapshot and return the rates since the last update.
    ///
    /// On the first call, returns `None` since there's no previous snapshot.
    pub fn update(&mut self, snapshot: StatsSnapshot) -> Option<RatesSnapshot> {
        let now = std::time::Instant::now();

        let rates = if let (Some(prev), Some(prev_time)) = (&self.previous, self.previous_time) {
            let duration = now.duration_since(prev_time);
            Some(snapshot.rates(prev, duration))
        } else {
            None
        };

        self.previous = Some(snapshot);
        self.previous_time = Some(now);

        rates
    }

    /// Reset the tracker, clearing the previous snapshot.
    pub fn reset(&mut self) {
        self.previous = None;
        self.previous_time = None;
    }

    /// Get the previous snapshot, if any.
    pub fn previous(&self) -> Option<&StatsSnapshot> {
        self.previous.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_delta_u64() {
        assert_eq!(delta_u64(100, 50), 50.0);
        assert_eq!(delta_u64(50, 50), 0.0);
        // Counter wrap
        assert_eq!(delta_u64(10, u64::MAX - 10), 21.0);
    }

    #[test]
    fn test_delta_u32() {
        assert_eq!(delta_u32(100, 50), 50.0);
        assert_eq!(delta_u32(50, 50), 0.0);
        // Counter wrap
        assert_eq!(delta_u32(10, u32::MAX - 10), 21.0);
    }

    #[test]
    fn test_link_stats_totals() {
        let stats = LinkStats {
            rx_bytes: 1000,
            tx_bytes: 2000,
            rx_packets: 10,
            tx_packets: 20,
            rx_errors: 1,
            tx_errors: 2,
            rx_dropped: 3,
            tx_dropped: 4,
            ..Default::default()
        };

        assert_eq!(stats.total_bytes(), 3000);
        assert_eq!(stats.total_packets(), 30);
        assert_eq!(stats.total_errors(), 3);
        assert_eq!(stats.total_dropped(), 7);
    }

    #[test]
    fn test_link_rates_bps() {
        let rates = LinkRates {
            rx_bytes_per_sec: 1000.0,
            tx_bytes_per_sec: 2000.0,
            ..Default::default()
        };

        assert_eq!(rates.rx_bps(), 8000.0);
        assert_eq!(rates.tx_bps(), 16000.0);
        assert_eq!(rates.total_bps(), 24000.0);
    }

    #[test]
    fn test_stats_snapshot_rates() {
        let mut prev = StatsSnapshot::new();
        prev.links.insert(
            1,
            LinkStats {
                name: Some("eth0".to_string()),
                rx_bytes: 1000,
                tx_bytes: 2000,
                ..Default::default()
            },
        );

        let mut curr = StatsSnapshot::new();
        curr.links.insert(
            1,
            LinkStats {
                name: Some("eth0".to_string()),
                rx_bytes: 2000,
                tx_bytes: 4000,
                ..Default::default()
            },
        );

        let rates = curr.rates(&prev, Duration::from_secs(1));

        let link_rates = rates.links.get(&1).unwrap();
        assert_eq!(link_rates.rx_bytes_per_sec, 1000.0);
        assert_eq!(link_rates.tx_bytes_per_sec, 2000.0);
    }
}
