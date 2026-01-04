//! Output formatting utilities for WireGuard.

use base64::prelude::*;

// Re-export formatting utilities from nlink library
pub use nlink::output::formatting::{format_bytes, format_time_ago};

/// Encode bytes as base64.
pub fn base64_encode(data: &[u8]) -> String {
    BASE64_STANDARD.encode(data)
}

/// Decode base64 string to bytes.
pub fn base64_decode(s: &str) -> Result<Vec<u8>, base64::DecodeError> {
    BASE64_STANDARD.decode(s.trim())
}
