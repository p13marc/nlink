//! Shared utilities for nlink.

pub mod addr;
pub mod device;
pub mod ifname;
pub mod names;
pub mod parse;

pub use addr::{format_addr, format_prefix, parse_addr, parse_prefix};
pub use device::{get_ifindex, get_ifindex_opt, get_ifname, get_ifname_or_index};
pub use parse::{get_rate, get_size, get_time, get_u8, get_u16, get_u32, get_u64};
