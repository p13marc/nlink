//! Qdisc option parsers.
//!
//! Each qdisc type has its own module that knows how to parse
//! command-line parameters and build netlink attributes.

pub mod cake;
pub mod codel;
pub mod fq;
pub mod fq_codel;
pub mod htb;
pub mod netem;
pub mod prio;
pub mod sfq;
pub mod tbf;

use rip_netlink::{MessageBuilder, Result};

/// Trait for qdisc option parsers.
pub trait QdiscOptions {
    /// Parse parameters and add attributes to the message builder.
    fn build(builder: &mut MessageBuilder, params: &[String]) -> Result<()>;
}
