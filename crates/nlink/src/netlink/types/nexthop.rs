//! Nexthop message types (Linux 5.3+).

use crate::netlink::error::{Error, Result};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

/// Nexthop message header (struct nhmsg).
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct NhMsg {
    /// Address family (AF_INET, AF_INET6, AF_UNSPEC).
    pub nh_family: u8,
    /// Nexthop scope.
    pub nh_scope: u8,
    /// Routing protocol that installed the nexthop.
    pub nh_protocol: u8,
    /// Reserved, must be zero.
    pub resvd: u8,
    /// Nexthop flags (NHF_*).
    pub nh_flags: u32,
}

impl NhMsg {
    /// Size of this structure.
    pub const SIZE: usize = std::mem::size_of::<Self>();

    /// Create a new nexthop message.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the address family.
    pub fn with_family(mut self, family: u8) -> Self {
        self.nh_family = family;
        self
    }

    /// Set the scope.
    pub fn with_scope(mut self, scope: u8) -> Self {
        self.nh_scope = scope;
        self
    }

    /// Set the protocol.
    pub fn with_protocol(mut self, protocol: u8) -> Self {
        self.nh_protocol = protocol;
        self
    }

    /// Set the flags.
    pub fn with_flags(mut self, flags: u32) -> Self {
        self.nh_flags = flags;
        self
    }

    /// Convert to bytes.
    pub fn as_bytes(&self) -> &[u8] {
        <Self as IntoBytes>::as_bytes(self)
    }

    /// Parse from bytes.
    pub fn from_bytes(data: &[u8]) -> Result<&Self> {
        Self::ref_from_prefix(data)
            .map(|(r, _)| r)
            .map_err(|_| Error::Truncated {
                expected: Self::SIZE,
                actual: data.len(),
            })
    }
}

/// Nexthop group entry (struct nexthop_grp).
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct NexthopGrp {
    /// Nexthop ID.
    pub id: u32,
    /// Weight (1-256, 0 means 1).
    pub weight: u8,
    /// Reserved.
    pub resvd1: u8,
    /// Reserved.
    pub resvd2: u16,
}

impl NexthopGrp {
    /// Size of this structure.
    pub const SIZE: usize = std::mem::size_of::<Self>();

    /// Create a new nexthop group entry.
    pub fn new(id: u32, weight: u8) -> Self {
        Self {
            id,
            weight,
            resvd1: 0,
            resvd2: 0,
        }
    }

    /// Convert to bytes.
    pub fn as_bytes(&self) -> &[u8] {
        <Self as IntoBytes>::as_bytes(self)
    }

    /// Parse from bytes.
    pub fn from_bytes(data: &[u8]) -> Option<&Self> {
        Self::ref_from_prefix(data).map(|(r, _)| r).ok()
    }
}

/// Nexthop attributes (NHA_*).
pub mod nha {
    pub const UNSPEC: u16 = 0;
    /// Nexthop ID (u32).
    pub const ID: u16 = 1;
    /// Nexthop group members (array of NexthopGrp).
    pub const GROUP: u16 = 2;
    /// Group type (u16, NEXTHOP_GRP_TYPE_*).
    pub const GROUP_TYPE: u16 = 3;
    /// Blackhole nexthop (flag, no value).
    pub const BLACKHOLE: u16 = 4;
    /// Output interface index (u32).
    pub const OIF: u16 = 5;
    /// Gateway address (IPv4 or IPv6).
    pub const GATEWAY: u16 = 6;
    /// Encapsulation type (u16).
    pub const ENCAP_TYPE: u16 = 7;
    /// Encapsulation data (nested).
    pub const ENCAP: u16 = 8;
    /// Return only groups (flag for dump).
    pub const GROUPS: u16 = 9;
    /// Master device for VRF (u32).
    pub const MASTER: u16 = 10;
    /// FDB nexthop (flag).
    pub const FDB: u16 = 11;
    /// Resilient group parameters (nested).
    pub const RES_GROUP: u16 = 12;
    /// Resilient bucket info (nested).
    pub const RES_BUCKET: u16 = 13;
}

/// Nexthop group types.
pub mod nhg_type {
    /// Multipath group with hash-threshold algorithm.
    pub const MPATH: u16 = 0;
    /// Resilient group that maintains flow affinity.
    pub const RES: u16 = 1;
}

/// Nexthop flags (nh_flags).
pub mod nhf {
    /// Gateway is on-link (no ARP needed).
    pub const ONLINK: u32 = 1;
    /// Nexthop is dead/invalid.
    pub const DEAD: u32 = 2;
    /// Link is down.
    pub const LINKDOWN: u32 = 4;
}

/// Resilient group attributes (nested under NHA_RES_GROUP).
pub mod nha_res_group {
    pub const UNSPEC: u16 = 0;
    /// Number of hash buckets (u16).
    pub const BUCKETS: u16 = 1;
    /// Idle timer in seconds (u32).
    pub const IDLE_TIMER: u16 = 2;
    /// Unbalanced timer in seconds (u32).
    pub const UNBALANCED_TIMER: u16 = 3;
    /// Unbalanced time remaining in seconds (u32, read-only).
    pub const UNBALANCED_TIME: u16 = 4;
}

/// Resilient bucket attributes (nested under NHA_RES_BUCKET).
pub mod nha_res_bucket {
    pub const UNSPEC: u16 = 0;
    /// Padding.
    pub const PAD: u16 = 1;
    /// Bucket index (u16).
    pub const INDEX: u16 = 2;
    /// Idle time in seconds (u32).
    pub const IDLE_TIME: u16 = 3;
    /// Nexthop ID for this bucket (u32).
    pub const NH_ID: u16 = 4;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nhmsg_size() {
        assert_eq!(NhMsg::SIZE, 8);
    }

    #[test]
    fn test_nexthop_grp_size() {
        assert_eq!(NexthopGrp::SIZE, 8);
    }

    #[test]
    fn test_nhmsg_builder() {
        let msg = NhMsg::new()
            .with_family(libc::AF_INET as u8)
            .with_protocol(4) // RTPROT_STATIC
            .with_flags(nhf::ONLINK);

        assert_eq!(msg.nh_family, libc::AF_INET as u8);
        assert_eq!(msg.nh_protocol, 4);
        assert_eq!(msg.nh_flags, nhf::ONLINK);
    }

    #[test]
    fn test_nexthop_grp() {
        let grp = NexthopGrp::new(42, 10);
        assert_eq!(grp.id, 42);
        assert_eq!(grp.weight, 10);
        assert_eq!(grp.resvd1, 0);
        assert_eq!(grp.resvd2, 0);
    }
}
