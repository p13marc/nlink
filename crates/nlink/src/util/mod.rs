//! Shared utilities for nlink.

pub mod addr;
pub mod bytes;
pub mod device;
pub mod ifname;
pub mod names;
pub mod parse;
pub mod percent;
pub mod rate;

pub use addr::{format_addr, format_prefix, parse_addr, parse_prefix};
pub use bytes::{Bytes, BytesParseError};
pub use device::{get_ifindex, get_ifindex_opt, get_ifname, get_ifname_or_index};
pub use parse::{get_rate, get_size, get_time, get_u8, get_u16, get_u32, get_u64};
pub use percent::{Percent, PercentParseError};
pub use rate::{Rate, RateParseError};
