//! RTNetlink message type definitions.

pub mod addr;
pub mod link;
pub mod neigh;
pub mod route;
pub mod rule;
pub mod tc;

// Re-export commonly used types
pub use addr::{IfAddrMsg, IfaAttr};
pub use link::{IfInfoMsg, IflaAttr};
pub use neigh::{NdMsg, NdaAttr};
pub use route::{RtMsg, RtaAttr};
pub use tc::{TcMsg, TcaAttr};

/// Address families.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AddressFamily {
    Unspec = 0,
    Unix = 1,
    Inet = 2,
    Inet6 = 10,
    Netlink = 16,
    Packet = 17,
    Mpls = 28,
    Bridge = 7,
}

impl From<u8> for AddressFamily {
    fn from(val: u8) -> Self {
        match val {
            0 => Self::Unspec,
            1 => Self::Unix,
            2 => Self::Inet,
            10 => Self::Inet6,
            16 => Self::Netlink,
            17 => Self::Packet,
            28 => Self::Mpls,
            7 => Self::Bridge,
            _ => Self::Unspec,
        }
    }
}

impl From<AddressFamily> for u8 {
    fn from(val: AddressFamily) -> Self {
        val as u8
    }
}
