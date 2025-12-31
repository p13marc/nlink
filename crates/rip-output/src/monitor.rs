//! Monitor helper utilities for event-based output.
//!
//! This module provides common functionality for monitoring netlink events
//! and formatting the output in both text and JSON formats.

use crate::{OutputFormat, OutputOptions};
use std::io::Write;
use std::time::SystemTime;

/// Configuration for monitor output.
#[derive(Debug, Clone, Default)]
pub struct MonitorConfig {
    /// Whether to prefix output with timestamps.
    pub timestamp: bool,
    /// Output format (text or JSON).
    pub format: OutputFormat,
    /// Output options.
    pub opts: OutputOptions,
}

impl MonitorConfig {
    /// Create a new monitor config with default settings.
    pub fn new() -> Self {
        Self::default()
    }

    /// Enable timestamp prefixes.
    pub fn with_timestamp(mut self, enabled: bool) -> Self {
        self.timestamp = enabled;
        self
    }

    /// Set the output format.
    pub fn with_format(mut self, format: OutputFormat) -> Self {
        self.format = format;
        self
    }

    /// Set the output options.
    pub fn with_opts(mut self, opts: OutputOptions) -> Self {
        self.opts = opts;
        self
    }
}

/// Write a timestamp prefix to the output if enabled.
///
/// Format: `[seconds.milliseconds] `
pub fn write_timestamp<W: Write>(w: &mut W, config: &MonitorConfig) -> std::io::Result<()> {
    if config.timestamp {
        let now = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        write!(w, "[{}.{:03}] ", now.as_secs(), now.subsec_millis())?;
    }
    Ok(())
}

/// Helper trait for event types that can be printed in monitor mode.
pub trait MonitorEvent {
    /// Get the event type name (e.g., "link", "route", "qdisc").
    fn event_type(&self) -> &'static str;

    /// Get the action name (e.g., "new", "del", "add").
    fn action(&self) -> &'static str;

    /// Print the event in text format.
    fn print_text<W: Write>(&self, w: &mut W, opts: &OutputOptions) -> std::io::Result<()>;

    /// Convert the event to a JSON value.
    fn to_json(&self) -> serde_json::Value;
}

/// Print a monitor event using the configured format.
pub fn print_event<W, E>(w: &mut W, event: &E, config: &MonitorConfig) -> std::io::Result<()>
where
    W: Write,
    E: MonitorEvent,
{
    write_timestamp(w, config)?;

    match config.format {
        OutputFormat::Text => {
            event.print_text(w, &config.opts)?;
        }
        OutputFormat::Json => {
            let json = event.to_json();
            writeln!(w, "{}", serde_json::to_string(&json).unwrap_or_default())?;
        }
    }

    w.flush()?;
    Ok(())
}

/// Print a startup message for monitor mode (text format only).
pub fn print_monitor_start<W: Write>(
    w: &mut W,
    config: &MonitorConfig,
    message: &str,
) -> std::io::Result<()> {
    if config.format == OutputFormat::Text {
        writeln!(w, "{}", message)?;
    }
    Ok(())
}
