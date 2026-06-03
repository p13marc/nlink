//! nftables support via NETLINK_NETFILTER.
//!
//! This module provides a typed API for managing nftables tables, chains,
//! and rules using the nf_tables netlink subsystem.
//!
//! # Example
//!
//! ```ignore
//! use nlink::netlink::{Connection, Nftables};
//! use nlink::netlink::nftables::*;
//!
//! let conn = Connection::<Nftables>::new()?;
//!
//! // Create table and chain
//! conn.add_table("filter", Family::Inet).await?;
//! conn.add_chain(
//!     Chain::new("filter", "input")
//!         .family(Family::Inet)
//!         .hook(Hook::Input)
//!         .priority(Priority::Filter)
//!         .policy(Policy::Accept)
//!         .chain_type(ChainType::Filter)
//! ).await?;
//!
//! // Add a rule: accept TCP port 22
//! conn.add_rule(
//!     Rule::new("filter", "input")
//!         .family(Family::Inet)
//!         .match_tcp_dport(22)
//!         .accept()
//! ).await?;
//! ```

pub mod config;
pub mod connection;
pub mod events;
pub mod expr;
pub mod resync;
pub mod types;
pub(crate) mod userdata;

pub use events::{NftablesEvent, NftablesGroup, NFNLGRP_NFTABLES};
pub use resync::{nftables_snapshot, BorrowedResyncStream, OwnedResyncStream};
pub use expr::*;
pub use types::*;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

// =============================================================================
// Netfilter subsystem constants
// =============================================================================

/// nftables subsystem ID within NETLINK_NETFILTER.
pub const NFNL_SUBSYS_NFTABLES: u16 = 10;

/// Batch begin message type (NLMSG_MIN_TYPE = 0x10).
///
/// This is a raw nlmsg_type, NOT shifted by subsystem. The kernel defines
/// `NFNL_MSG_BATCH_BEGIN` as `NLMSG_MIN_TYPE` (16) in nfnetlink.h.
pub const NFNL_MSG_BATCH_BEGIN: u16 = 0x10;
/// Batch end message type (NLMSG_MIN_TYPE + 1 = 0x11).
pub const NFNL_MSG_BATCH_END: u16 = 0x11;

// =============================================================================
// NFT_MSG_* Message Types (shifted by subsystem)
// =============================================================================

pub const NFT_MSG_NEWTABLE: u8 = 0;
pub const NFT_MSG_GETTABLE: u8 = 1;
pub const NFT_MSG_DELTABLE: u8 = 2;
pub const NFT_MSG_NEWCHAIN: u8 = 3;
pub const NFT_MSG_GETCHAIN: u8 = 4;
pub const NFT_MSG_DELCHAIN: u8 = 5;
pub const NFT_MSG_NEWRULE: u8 = 6;
pub const NFT_MSG_GETRULE: u8 = 7;
pub const NFT_MSG_DELRULE: u8 = 8;
pub const NFT_MSG_NEWSET: u8 = 9;
pub const NFT_MSG_GETSET: u8 = 10;
pub const NFT_MSG_DELSET: u8 = 11;
pub const NFT_MSG_NEWSETELEM: u8 = 12;
pub const NFT_MSG_GETSETELEM: u8 = 13;
pub const NFT_MSG_DELSETELEM: u8 = 14;
pub const NFT_MSG_NEWGEN: u8 = 15;
pub const NFT_MSG_GETGEN: u8 = 16;
/// Create a flowtable (`NFT_MSG_NEWFLOWTABLE`). Kernel 5.x+.
pub const NFT_MSG_NEWFLOWTABLE: u8 = 22;
/// Dump flowtables (`NFT_MSG_GETFLOWTABLE`).
pub const NFT_MSG_GETFLOWTABLE: u8 = 23;
/// Delete a flowtable (`NFT_MSG_DELFLOWTABLE`).
pub const NFT_MSG_DELFLOWTABLE: u8 = 24;

// =============================================================================
// Flowtable Attributes (NFTA_FLOWTABLE_*) — kernel UAPI
// `include/uapi/linux/netfilter/nf_tables.h`
// =============================================================================

pub const NFTA_FLOWTABLE_TABLE: u16 = 1;
pub const NFTA_FLOWTABLE_NAME: u16 = 2;
pub const NFTA_FLOWTABLE_HOOK: u16 = 3;
pub const NFTA_FLOWTABLE_USE: u16 = 4;
pub const NFTA_FLOWTABLE_HANDLE: u16 = 5;
pub const NFTA_FLOWTABLE_PAD: u16 = 6;
pub const NFTA_FLOWTABLE_FLAGS: u16 = 7;

// Nested hook attributes.
pub const NFTA_FLOWTABLE_HOOK_NUM: u16 = 1;
pub const NFTA_FLOWTABLE_HOOK_PRIORITY: u16 = 2;
pub const NFTA_FLOWTABLE_HOOK_DEVS: u16 = 3;

// Device attribute (used inside FLOWTABLE_HOOK_DEVS list).
pub const NFTA_DEVICE_NAME: u16 = 1;

// NF_NETDEV_INGRESS hook id — flowtables always attach here.
pub const NF_NETDEV_INGRESS: u32 = 0;

/// `NFT_FLOWTABLE_HW_OFFLOAD` — request kernel push the flow path
/// onto NIC hardware where supported (mlx5, hns3, etc.).
pub const NFT_FLOWTABLE_HW_OFFLOAD: u32 = 0x1;
/// `NFT_FLOWTABLE_COUNTER` — track per-flow packet + byte counters.
/// Pair with `Connection::<Nftables>::get_flowtables` to read.
pub const NFT_FLOWTABLE_COUNTER: u32 = 0x2;

/// Compute the full netlink message type for an nftables message.
pub fn nft_msg_type(msg: u8) -> u16 {
    (NFNL_SUBSYS_NFTABLES << 8) | msg as u16
}

// =============================================================================
// Table Attributes
// =============================================================================

pub const NFTA_TABLE_NAME: u16 = 1;
pub const NFTA_TABLE_FLAGS: u16 = 2;
pub const NFTA_TABLE_USE: u16 = 3;
pub const NFTA_TABLE_HANDLE: u16 = 4;

/// `NFT_TABLE_F_DORMANT` — table is dormant (chains don't fire).
pub const NFT_TABLE_F_DORMANT: u32 = 0x1;
/// `NFT_TABLE_F_OWNER` — table is owned by the creating socket
/// (auto-deleted on socket close). Kernel 5.13+.
pub const NFT_TABLE_F_OWNER: u32 = 0x2;
/// `NFT_TABLE_F_PERSIST` — table survives `nft flush ruleset` issued
/// against the same family. Kernel 6.9+. Pair with
/// [`Connection<Nftables>::add_table_with_flags`](super::Connection) to
/// create a table that the operator can't accidentally flush away.
pub const NFT_TABLE_F_PERSIST: u32 = 0x4;

// =============================================================================
// Chain Attributes
// =============================================================================

pub const NFTA_CHAIN_TABLE: u16 = 1;
pub const NFTA_CHAIN_HANDLE: u16 = 2;
pub const NFTA_CHAIN_NAME: u16 = 3;
pub const NFTA_CHAIN_HOOK: u16 = 4;
pub const NFTA_CHAIN_POLICY: u16 = 5;
pub const NFTA_CHAIN_TYPE: u16 = 7;
pub const NFTA_CHAIN_FLAGS: u16 = 10;

// Chain hook nested attributes
pub const NFTA_HOOK_HOOKNUM: u16 = 1;
pub const NFTA_HOOK_PRIORITY: u16 = 2;
/// Single-device binding for netdev base chains
/// (`type filter hook ingress device eth0 priority -150`).
/// Required when `family == Netdev`; ignored on other families.
pub const NFTA_HOOK_DEV: u16 = 3;

// =============================================================================
// Rule Attributes
// =============================================================================

pub const NFTA_RULE_TABLE: u16 = 1;
pub const NFTA_RULE_CHAIN: u16 = 2;
pub const NFTA_RULE_HANDLE: u16 = 3;
pub const NFTA_RULE_EXPRESSIONS: u16 = 4;
pub const NFTA_RULE_POSITION: u16 = 6;
/// `NFTA_RULE_USERDATA = 7` — opaque-bytes payload the kernel
/// preserves verbatim across reads / writes (max
/// `NFT_USERDATA_MAXLEN = 256` bytes). Used for libnftnl-compatible
/// TLV-encoded rule comments — see the internal `userdata` module.
pub const NFTA_RULE_USERDATA: u16 = 7;

// =============================================================================
// Expression Attributes
// =============================================================================

pub const NFTA_LIST_ELEM: u16 = 1;
pub const NFTA_EXPR_NAME: u16 = 1;
pub const NFTA_EXPR_DATA: u16 = 2;

// Meta
pub const NFTA_META_DREG: u16 = 1;
pub const NFTA_META_KEY: u16 = 2;

// Cmp
pub const NFTA_CMP_SREG: u16 = 1;
pub const NFTA_CMP_OP: u16 = 2;
pub const NFTA_CMP_DATA: u16 = 3;

// Payload
pub const NFTA_PAYLOAD_DREG: u16 = 1;
pub const NFTA_PAYLOAD_BASE: u16 = 2;
pub const NFTA_PAYLOAD_OFFSET: u16 = 3;
pub const NFTA_PAYLOAD_LEN: u16 = 4;

// Immediate
pub const NFTA_IMMEDIATE_DREG: u16 = 1;
pub const NFTA_IMMEDIATE_DATA: u16 = 2;

// Data
pub const NFTA_DATA_VALUE: u16 = 1;
pub const NFTA_DATA_VERDICT: u16 = 2;

// Verdict
pub const NFTA_VERDICT_CODE: u16 = 1;
pub const NFTA_VERDICT_CHAIN: u16 = 2;

// Counter
pub const NFTA_COUNTER_BYTES: u16 = 1;
pub const NFTA_COUNTER_PACKETS: u16 = 2;

// Bitwise
pub const NFTA_BITWISE_SREG: u16 = 1;
pub const NFTA_BITWISE_DREG: u16 = 2;
pub const NFTA_BITWISE_LEN: u16 = 3;
pub const NFTA_BITWISE_MASK: u16 = 4;
pub const NFTA_BITWISE_XOR: u16 = 5;
pub const NFTA_BITWISE_OP: u16 = 6;
/// `NFT_BITWISE_BOOL` — the mask/xor boolean op (`NFTA_BITWISE_OP`).
pub const NFT_BITWISE_BOOL: u32 = 0;

// Conntrack
pub const NFTA_CT_DREG: u16 = 1;
pub const NFTA_CT_KEY: u16 = 2;

// Limit
pub const NFTA_LIMIT_RATE: u16 = 1;
pub const NFTA_LIMIT_UNIT: u16 = 2;
pub const NFTA_LIMIT_BURST: u16 = 3;
pub const NFTA_LIMIT_TYPE: u16 = 4;

// NAT
pub const NFTA_NAT_TYPE: u16 = 1;
pub const NFTA_NAT_FAMILY: u16 = 2;
pub const NFTA_NAT_REG_ADDR_MIN: u16 = 3;
pub const NFTA_NAT_REG_ADDR_MAX: u16 = 4;
pub const NFTA_NAT_REG_PROTO_MIN: u16 = 5;
pub const NFTA_NAT_REG_PROTO_MAX: u16 = 6;
pub const NFTA_NAT_FLAGS: u16 = 7;
/// `NF_NAT_RANGE_MAP_IPS` — `NFTA_NAT_FLAGS` bit: NAT rewrites the address.
pub const NF_NAT_RANGE_MAP_IPS: u32 = 1;
/// `NF_NAT_RANGE_PROTO_SPECIFIED` — `NFTA_NAT_FLAGS` bit: NAT rewrites the port.
pub const NF_NAT_RANGE_PROTO_SPECIFIED: u32 = 2;

// Log
pub const NFTA_LOG_PREFIX: u16 = 1;
pub const NFTA_LOG_GROUP: u16 = 2;

// =============================================================================
// Set Attributes
// =============================================================================

pub const NFTA_SET_TABLE: u16 = 1;
pub const NFTA_SET_NAME: u16 = 2;
pub const NFTA_SET_FLAGS: u16 = 3;
pub const NFTA_SET_KEY_TYPE: u16 = 4;
pub const NFTA_SET_KEY_LEN: u16 = 5;
pub const NFTA_SET_DATA_TYPE: u16 = 6;
pub const NFTA_SET_DATA_LEN: u16 = 7;
pub const NFTA_SET_ID: u16 = 16;
pub const NFTA_SET_HANDLE: u16 = 17;

// Set element attributes
pub const NFTA_SET_ELEM_LIST_TABLE: u16 = 1;
pub const NFTA_SET_ELEM_LIST_SET: u16 = 2;
pub const NFTA_SET_ELEM_LIST_ELEMENTS: u16 = 3;

pub const NFTA_SET_ELEM_KEY: u16 = 1;
pub const NFTA_SET_ELEM_DATA: u16 = 2;
pub const NFTA_SET_ELEM_FLAGS: u16 = 3;

// Lookup expression
pub const NFTA_LOOKUP_SET: u16 = 1;
pub const NFTA_LOOKUP_SREG: u16 = 2;
pub const NFTA_LOOKUP_DREG: u16 = 3;
pub const NFTA_LOOKUP_SET_ID: u16 = 4;
pub const NFTA_LOOKUP_FLAGS: u16 = 5;

// Set flags
pub const NFT_SET_ANONYMOUS: u32 = 0x1;
pub const NFT_SET_CONSTANT: u32 = 0x2;
pub const NFT_SET_INTERVAL: u32 = 0x4;
pub const NFT_SET_MAP: u32 = 0x8;

// Verdict codes — verified against `include/uapi/linux/netfilter/nf_tables.h`
// enum `nft_verdicts`. Plan 204 (0.19) corrected `NFT_JUMP` and `NFT_GOTO`,
// which previously emitted `-2` and `-3` respectively. Pre-0.19 a
// `Verdict::Jump(chain)` wrote `-2` on the wire which the kernel
// interpreted as `NFT_BREAK` (terminate rule eval) — every subroutine
// rule was silently broken. The new `NFT_BREAK = -2` constant is added
// for completeness.
pub const NF_DROP: i32 = 0;
pub const NF_ACCEPT: i32 = 1;
pub const NFT_CONTINUE: i32 = -1;
pub const NFT_BREAK: i32 = -2;
pub const NFT_JUMP: i32 = -3;
pub const NFT_GOTO: i32 = -4;
pub const NFT_RETURN: i32 = -5;

// =============================================================================
// NfGenMsg Header (zerocopy)
// =============================================================================

/// Netfilter generic message header (4 bytes).
///
/// Present at the start of every nftables message, after the nlmsghdr.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct NfGenMsg {
    pub nfgen_family: u8,
    pub version: u8,
    pub res_id: u16, // big-endian
}

impl NfGenMsg {
    pub fn new(family: Family) -> Self {
        Self {
            nfgen_family: family as u8,
            version: 0, // NFNETLINK_V0
            res_id: 0,
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        <Self as IntoBytes>::as_bytes(self)
    }

    pub fn from_bytes(data: &[u8]) -> Option<&Self> {
        Self::ref_from_prefix(data).map(|(r, _)| r).ok()
    }
}

/// Size of NfGenMsg header.
pub const NFGENMSG_HDRLEN: usize = 4;

#[cfg(test)]
mod table_flag_tests {
    use super::*;

    #[test]
    fn nft_table_flags_match_kernel_uapi() {
        // Values from include/uapi/linux/netfilter/nf_tables.h.
        // These are part of the public ABI and must not drift.
        assert_eq!(NFT_TABLE_F_DORMANT, 0x1);
        assert_eq!(NFT_TABLE_F_OWNER, 0x2);
        assert_eq!(NFT_TABLE_F_PERSIST, 0x4);
    }

    #[test]
    fn nft_flowtable_constants_match_kernel_uapi() {
        // From include/uapi/linux/netfilter/nf_tables.h. Stable
        // ABI; must not drift.
        assert_eq!(NFT_MSG_NEWFLOWTABLE, 22);
        assert_eq!(NFT_MSG_GETFLOWTABLE, 23);
        assert_eq!(NFT_MSG_DELFLOWTABLE, 24);
        assert_eq!(NFT_FLOWTABLE_HW_OFFLOAD, 0x1);
        assert_eq!(NFT_FLOWTABLE_COUNTER, 0x2);
        assert_eq!(NF_NETDEV_INGRESS, 0);
    }

    #[test]
    fn flowtable_builder_compose() {
        use super::Family;
        let ft = super::Flowtable::new(Family::Inet, "filter", "ft")
            .device("eth0")
            .device("eth1")
            .priority(-300)
            .hw_offload(true)
            .counter(true);
        assert_eq!(ft.devs, vec!["eth0", "eth1"]);
        assert_eq!(ft.priority, -300);
        assert!(ft.flags & NFT_FLOWTABLE_HW_OFFLOAD != 0);
        assert!(ft.flags & NFT_FLOWTABLE_COUNTER != 0);
        // Toggle off:
        let ft = ft.hw_offload(false);
        assert!(ft.flags & NFT_FLOWTABLE_HW_OFFLOAD == 0);
        assert!(ft.flags & NFT_FLOWTABLE_COUNTER != 0);
    }

    #[test]
    fn table_flags_compose_via_bitor() {
        // Verify users can combine flags the natural way.
        let combined = NFT_TABLE_F_DORMANT | NFT_TABLE_F_PERSIST;
        assert_eq!(combined & NFT_TABLE_F_DORMANT, NFT_TABLE_F_DORMANT);
        assert_eq!(combined & NFT_TABLE_F_PERSIST, NFT_TABLE_F_PERSIST);
        assert_eq!(combined & NFT_TABLE_F_OWNER, 0);
    }
}
