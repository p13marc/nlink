//! Traffic control utilities for nlink.
//!
//! This crate provides TC-specific utilities including:
//! - Handle parsing and formatting
//! - Qdisc option parsers
//! - Message builders for qdisc/class/filter/action

pub mod builders;
pub mod handle;
pub mod options;

pub use handle::{format_handle, parse_handle, Handle};
