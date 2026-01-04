//! Output formatting utilities for WireGuard.

use base64::prelude::*;
use std::time::{Duration, SystemTime};

/// Encode bytes as base64.
pub fn base64_encode(data: &[u8]) -> String {
    BASE64_STANDARD.encode(data)
}

/// Decode base64 string to bytes.
pub fn base64_decode(s: &str) -> Result<Vec<u8>, base64::DecodeError> {
    BASE64_STANDARD.decode(s.trim())
}

/// Format bytes in a human-readable way.
pub fn format_bytes(bytes: u64) -> String {
    const KIB: u64 = 1024;
    const MIB: u64 = KIB * 1024;
    const GIB: u64 = MIB * 1024;
    const TIB: u64 = GIB * 1024;

    if bytes >= TIB {
        format!("{:.2} TiB", bytes as f64 / TIB as f64)
    } else if bytes >= GIB {
        format!("{:.2} GiB", bytes as f64 / GIB as f64)
    } else if bytes >= MIB {
        format!("{:.2} MiB", bytes as f64 / MIB as f64)
    } else if bytes >= KIB {
        format!("{:.2} KiB", bytes as f64 / KIB as f64)
    } else {
        format!("{} B", bytes)
    }
}

/// Format a duration as a human-readable string.
pub fn format_duration(d: Duration) -> String {
    let secs = d.as_secs();

    if secs == 0 {
        return "now".to_string();
    }

    let days = secs / 86400;
    let hours = (secs % 86400) / 3600;
    let minutes = (secs % 3600) / 60;
    let seconds = secs % 60;

    let mut parts = Vec::new();

    if days > 0 {
        parts.push(format!(
            "{} {}",
            days,
            if days == 1 { "day" } else { "days" }
        ));
    }
    if hours > 0 {
        parts.push(format!(
            "{} {}",
            hours,
            if hours == 1 { "hour" } else { "hours" }
        ));
    }
    if minutes > 0 {
        parts.push(format!(
            "{} {}",
            minutes,
            if minutes == 1 { "minute" } else { "minutes" }
        ));
    }
    if seconds > 0 && days == 0 {
        parts.push(format!(
            "{} {}",
            seconds,
            if seconds == 1 { "second" } else { "seconds" }
        ));
    }

    if parts.is_empty() {
        "now".to_string()
    } else if parts.len() <= 2 {
        parts.join(", ")
    } else {
        // Only show first two components for longer durations
        parts[..2].join(", ")
    }
}

/// Format a SystemTime as "X ago" string.
pub fn format_time_ago(time: SystemTime) -> String {
    match SystemTime::now().duration_since(time) {
        Ok(duration) => format!("{} ago", format_duration(duration)),
        Err(_) => "in the future".to_string(),
    }
}
