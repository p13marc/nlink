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

pub mod connection;
pub mod expr;
pub mod types;

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

// =============================================================================
// Rule Attributes
// =============================================================================

pub const NFTA_RULE_TABLE: u16 = 1;
pub const NFTA_RULE_CHAIN: u16 = 2;
pub const NFTA_RULE_HANDLE: u16 = 3;
pub const NFTA_RULE_EXPRESSIONS: u16 = 4;
pub const NFTA_RULE_POSITION: u16 = 6;

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

// Verdict codes
pub const NF_DROP: i32 = 0;
pub const NF_ACCEPT: i32 = 1;
pub const NFT_CONTINUE: i32 = -1;
pub const NFT_RETURN: i32 = -5;
pub const NFT_JUMP: i32 = -2;
pub const NFT_GOTO: i32 = -3;

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
