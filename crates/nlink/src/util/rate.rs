//! Rate conversion utilities.
//!
//! This module provides helpers for converting between different rate units
//! commonly used in network configuration.
//!
//! # Example
//!
//! ```
//! use nlink::util::rate;
//!
//! // Convert 1 Mbps to bytes per second
//! let bps = rate::mbps_to_bytes(1);
//! assert_eq!(bps, 125_000);
//!
//! // Convert bytes per second back to Mbps
//! let mbps = rate::bytes_to_mbps(125_000);
//! assert_eq!(mbps, 1);
//! ```

/// Convert kilobits per second to bytes per second.
///
/// # Example
///
/// ```
/// use nlink::util::rate::kbps_to_bytes;
///
/// assert_eq!(kbps_to_bytes(1000), 125_000); // 1 Mbps
/// assert_eq!(kbps_to_bytes(100), 12_500);   // 100 Kbps
/// ```
#[inline]
pub const fn kbps_to_bytes(kbps: u64) -> u64 {
    kbps * 1000 / 8
}

/// Convert megabits per second to bytes per second.
///
/// # Example
///
/// ```
/// use nlink::util::rate::mbps_to_bytes;
///
/// assert_eq!(mbps_to_bytes(1), 125_000);       // 1 Mbps
/// assert_eq!(mbps_to_bytes(100), 12_500_000);  // 100 Mbps
/// assert_eq!(mbps_to_bytes(1000), 125_000_000); // 1 Gbps
/// ```
#[inline]
pub const fn mbps_to_bytes(mbps: u64) -> u64 {
    mbps * 1_000_000 / 8
}

/// Convert gigabits per second to bytes per second.
///
/// # Example
///
/// ```
/// use nlink::util::rate::gbps_to_bytes;
///
/// assert_eq!(gbps_to_bytes(1), 125_000_000);      // 1 Gbps
/// assert_eq!(gbps_to_bytes(10), 1_250_000_000);   // 10 Gbps
/// assert_eq!(gbps_to_bytes(100), 12_500_000_000); // 100 Gbps
/// ```
#[inline]
pub const fn gbps_to_bytes(gbps: u64) -> u64 {
    gbps * 1_000_000_000 / 8
}

/// Convert bytes per second to kilobits per second.
///
/// # Example
///
/// ```
/// use nlink::util::rate::bytes_to_kbps;
///
/// assert_eq!(bytes_to_kbps(125_000), 1000); // 1 Mbps = 1000 Kbps
/// assert_eq!(bytes_to_kbps(12_500), 100);   // 100 Kbps
/// ```
#[inline]
pub const fn bytes_to_kbps(bps: u64) -> u64 {
    bps * 8 / 1000
}

/// Convert bytes per second to megabits per second.
///
/// # Example
///
/// ```
/// use nlink::util::rate::bytes_to_mbps;
///
/// assert_eq!(bytes_to_mbps(125_000), 1);        // 1 Mbps
/// assert_eq!(bytes_to_mbps(12_500_000), 100);   // 100 Mbps
/// assert_eq!(bytes_to_mbps(125_000_000), 1000); // 1 Gbps
/// ```
#[inline]
pub const fn bytes_to_mbps(bps: u64) -> u64 {
    bps * 8 / 1_000_000
}

/// Convert bytes per second to gigabits per second.
///
/// # Example
///
/// ```
/// use nlink::util::rate::bytes_to_gbps;
///
/// assert_eq!(bytes_to_gbps(125_000_000), 1);       // 1 Gbps
/// assert_eq!(bytes_to_gbps(1_250_000_000), 10);    // 10 Gbps
/// assert_eq!(bytes_to_gbps(12_500_000_000), 100);  // 100 Gbps
/// ```
#[inline]
pub const fn bytes_to_gbps(bps: u64) -> u64 {
    bps * 8 / 1_000_000_000
}

/// Convert bits per second to bytes per second.
///
/// # Example
///
/// ```
/// use nlink::util::rate::bits_to_bytes;
///
/// assert_eq!(bits_to_bytes(1_000_000), 125_000); // 1 Mbps
/// assert_eq!(bits_to_bytes(8), 1);               // 8 bps = 1 Bps
/// ```
#[inline]
pub const fn bits_to_bytes(bps: u64) -> u64 {
    bps / 8
}

/// Convert bytes per second to bits per second.
///
/// # Example
///
/// ```
/// use nlink::util::rate::bytes_to_bits;
///
/// assert_eq!(bytes_to_bits(125_000), 1_000_000); // 1 Mbps
/// assert_eq!(bytes_to_bits(1), 8);               // 1 Bps = 8 bps
/// ```
#[inline]
pub const fn bytes_to_bits(bps: u64) -> u64 {
    bps * 8
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kbps_to_bytes() {
        assert_eq!(kbps_to_bytes(0), 0);
        assert_eq!(kbps_to_bytes(8), 1000);
        assert_eq!(kbps_to_bytes(1000), 125_000);
        assert_eq!(kbps_to_bytes(10_000), 1_250_000);
    }

    #[test]
    fn test_mbps_to_bytes() {
        assert_eq!(mbps_to_bytes(0), 0);
        assert_eq!(mbps_to_bytes(1), 125_000);
        assert_eq!(mbps_to_bytes(100), 12_500_000);
        assert_eq!(mbps_to_bytes(1000), 125_000_000);
    }

    #[test]
    fn test_gbps_to_bytes() {
        assert_eq!(gbps_to_bytes(0), 0);
        assert_eq!(gbps_to_bytes(1), 125_000_000);
        assert_eq!(gbps_to_bytes(10), 1_250_000_000);
        assert_eq!(gbps_to_bytes(100), 12_500_000_000);
    }

    #[test]
    fn test_bytes_to_kbps() {
        assert_eq!(bytes_to_kbps(0), 0);
        assert_eq!(bytes_to_kbps(125), 1);
        assert_eq!(bytes_to_kbps(125_000), 1000);
        assert_eq!(bytes_to_kbps(1_250_000), 10_000);
    }

    #[test]
    fn test_bytes_to_mbps() {
        assert_eq!(bytes_to_mbps(0), 0);
        assert_eq!(bytes_to_mbps(125_000), 1);
        assert_eq!(bytes_to_mbps(12_500_000), 100);
        assert_eq!(bytes_to_mbps(125_000_000), 1000);
    }

    #[test]
    fn test_bytes_to_gbps() {
        assert_eq!(bytes_to_gbps(0), 0);
        assert_eq!(bytes_to_gbps(125_000_000), 1);
        assert_eq!(bytes_to_gbps(1_250_000_000), 10);
        assert_eq!(bytes_to_gbps(12_500_000_000), 100);
    }

    #[test]
    fn test_roundtrip() {
        // Test that conversions roundtrip correctly for aligned values
        assert_eq!(bytes_to_mbps(mbps_to_bytes(100)), 100);
        assert_eq!(bytes_to_gbps(gbps_to_bytes(10)), 10);
        assert_eq!(bytes_to_kbps(kbps_to_bytes(1000)), 1000);
    }

    #[test]
    fn test_bits_bytes() {
        assert_eq!(bits_to_bytes(8), 1);
        assert_eq!(bits_to_bytes(1_000_000), 125_000);
        assert_eq!(bytes_to_bits(1), 8);
        assert_eq!(bytes_to_bits(125_000), 1_000_000);
    }
}
