//! Argument parsing utilities.

use std::time::Duration;

/// Error type for parsing.
#[derive(Debug, thiserror::Error)]
pub enum ParseError {
    #[error("invalid number: {0}")]
    InvalidNumber(String),

    #[error("number out of range: {0}")]
    OutOfRange(String),

    #[error("invalid format: {0}")]
    InvalidFormat(String),

    #[error("unknown unit: {0}")]
    UnknownUnit(String),
}

pub type Result<T> = std::result::Result<T, ParseError>;

/// Parse a u8 from string.
pub fn get_u8(s: &str) -> Result<u8> {
    parse_int(s)
}

/// Parse a u16 from string.
pub fn get_u16(s: &str) -> Result<u16> {
    parse_int(s)
}

/// Parse a u32 from string.
pub fn get_u32(s: &str) -> Result<u32> {
    parse_int(s)
}

/// Parse a u64 from string.
pub fn get_u64(s: &str) -> Result<u64> {
    parse_int(s)
}

/// Parse an i32 from string.
pub fn get_i32(s: &str) -> Result<i32> {
    parse_int(s)
}

/// Generic integer parsing with hex support.
fn parse_int<T: std::str::FromStr + TryFrom<u64>>(s: &str) -> Result<T>
where
    <T as std::str::FromStr>::Err: std::fmt::Display,
    <T as TryFrom<u64>>::Error: std::fmt::Display,
{
    let s = s.trim();

    // Handle hex
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        let val =
            u64::from_str_radix(hex, 16).map_err(|e| ParseError::InvalidNumber(e.to_string()))?;
        return T::try_from(val).map_err(|e| ParseError::OutOfRange(e.to_string()));
    }

    // Handle octal
    if s.starts_with('0') && s.len() > 1 && s.chars().nth(1).unwrap().is_ascii_digit() {
        let val = u64::from_str_radix(&s[1..], 8)
            .map_err(|e| ParseError::InvalidNumber(e.to_string()))?;
        return T::try_from(val).map_err(|e| ParseError::OutOfRange(e.to_string()));
    }

    s.parse()
        .map_err(|e| ParseError::InvalidNumber(format!("{}", e)))
}

/// Parse a rate (bits per second).
/// Supports suffixes: bit, kbit, mbit, gbit, tbit, bps, kbps, mbps, gbps, tbps
pub fn get_rate(s: &str) -> Result<u64> {
    let s = s.trim().to_lowercase();

    // Try to find where the number ends
    let (num_str, unit) = split_number_unit(&s);

    let num: f64 = num_str
        .parse()
        .map_err(|_| ParseError::InvalidNumber(num_str.to_string()))?;

    let multiplier: u64 = match unit {
        "" | "bit" | "bps" => 1,
        "kbit" | "kbps" | "k" => 1000,
        "mbit" | "mbps" | "m" => 1_000_000,
        "gbit" | "gbps" | "g" => 1_000_000_000,
        "tbit" | "tbps" | "t" => 1_000_000_000_000,
        "kibit" | "kibps" => 1024,
        "mibit" | "mibps" => 1024 * 1024,
        "gibit" | "gibps" => 1024 * 1024 * 1024,
        "tibit" | "tibps" => 1024u64 * 1024 * 1024 * 1024,
        _ => return Err(ParseError::UnknownUnit(unit.to_string())),
    };

    Ok((num * multiplier as f64) as u64)
}

/// Parse a size (bytes).
/// Supports suffixes: b, k, kb, m, mb, g, gb, t, tb
pub fn get_size(s: &str) -> Result<u64> {
    let s = s.trim().to_lowercase();

    let (num_str, unit) = split_number_unit(&s);

    let num: f64 = num_str
        .parse()
        .map_err(|_| ParseError::InvalidNumber(num_str.to_string()))?;

    let multiplier: u64 = match unit {
        "" | "b" => 1,
        "k" | "kb" => 1024,
        "m" | "mb" => 1024 * 1024,
        "g" | "gb" => 1024 * 1024 * 1024,
        "t" | "tb" => 1024u64 * 1024 * 1024 * 1024,
        "kbit" => 1000 / 8,
        "mbit" => 1_000_000 / 8,
        "gbit" => 1_000_000_000 / 8,
        _ => return Err(ParseError::UnknownUnit(unit.to_string())),
    };

    Ok((num * multiplier as f64) as u64)
}

/// Parse a time duration.
/// Supports suffixes: s, ms, us, ns
pub fn get_time(s: &str) -> Result<Duration> {
    let s = s.trim().to_lowercase();

    let (num_str, unit) = split_number_unit(&s);

    let num: f64 = num_str
        .parse()
        .map_err(|_| ParseError::InvalidNumber(num_str.to_string()))?;

    let duration = match unit {
        "" | "s" | "sec" | "secs" => Duration::from_secs_f64(num),
        "ms" | "msec" | "msecs" => Duration::from_secs_f64(num / 1000.0),
        "us" | "usec" | "usecs" => Duration::from_secs_f64(num / 1_000_000.0),
        "ns" | "nsec" | "nsecs" => Duration::from_nanos(num as u64),
        "m" | "min" | "mins" => Duration::from_secs_f64(num * 60.0),
        "h" | "hour" | "hours" => Duration::from_secs_f64(num * 3600.0),
        _ => return Err(ParseError::UnknownUnit(unit.to_string())),
    };

    Ok(duration)
}

/// Parse a percentage (0-100) to a fraction (0.0-1.0).
pub fn get_percent(s: &str) -> Result<f64> {
    let s = s.trim();
    let s = s.strip_suffix('%').unwrap_or(s);
    let val: f64 = s
        .parse()
        .map_err(|_| ParseError::InvalidNumber(s.to_string()))?;
    if !(0.0..=100.0).contains(&val) {
        return Err(ParseError::OutOfRange(format!(
            "{} not in range 0-100",
            val
        )));
    }
    Ok(val / 100.0)
}

/// Split a string into number and unit parts.
fn split_number_unit(s: &str) -> (&str, &str) {
    let idx = s
        .find(|c: char| !c.is_ascii_digit() && c != '.' && c != '-')
        .unwrap_or(s.len());
    (&s[..idx], &s[idx..])
}

/// Parse a boolean value.
pub fn get_bool(s: &str) -> Result<bool> {
    match s.to_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        _ => Err(ParseError::InvalidFormat(format!(
            "expected boolean, got '{}'",
            s
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_u32() {
        assert_eq!(get_u32("123").unwrap(), 123);
        assert_eq!(get_u32("0x1a").unwrap(), 26);
        assert_eq!(get_u32("0777").unwrap(), 511);
    }

    #[test]
    fn test_get_rate() {
        assert_eq!(get_rate("1000").unwrap(), 1000);
        assert_eq!(get_rate("1kbit").unwrap(), 1000);
        assert_eq!(get_rate("1mbit").unwrap(), 1_000_000);
        assert_eq!(get_rate("1.5mbit").unwrap(), 1_500_000);
    }

    #[test]
    fn test_get_size() {
        assert_eq!(get_size("1024").unwrap(), 1024);
        assert_eq!(get_size("1k").unwrap(), 1024);
        assert_eq!(get_size("1kb").unwrap(), 1024);
        assert_eq!(get_size("1m").unwrap(), 1024 * 1024);
    }

    #[test]
    fn test_get_time() {
        assert_eq!(get_time("1s").unwrap(), Duration::from_secs(1));
        assert_eq!(get_time("100ms").unwrap(), Duration::from_millis(100));
        assert_eq!(get_time("1000us").unwrap(), Duration::from_micros(1000));
    }
}
