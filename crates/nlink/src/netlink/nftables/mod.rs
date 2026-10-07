//! nftables support via NETLINK_NETFILTER.
//!
//! This module provides a typed API for managing nftables tables, chains,
//! and rules using the nf_tables netlink subsystem.
//!
//! # Example
//!
//! ```no_run
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! use nlink::netlink::{Connection, Nftables};
//! use nlink::netlink::nftables::*;
//!
//! let conn = Connection::<Nftables>::new()?;
//!
//! // Create table and chain
//! conn.add_table("filter", Family::Inet).await?;
//! conn.add_chain(
//!     Chain::new("filter", "input")?
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
//! # Ok(())
//! # }
//! ```

pub mod config;
pub mod connection;
pub mod events;
pub mod expr;
pub(crate) mod interval;
pub mod object;
pub mod resync;
pub mod types;
pub(crate) mod userdata;

pub use connection::{RawMessage, Transaction};
pub use events::{GenInfo, NftablesEvent, NftablesGroup, SetElementsEvent, NFNLGRP_NFTABLES};
pub use resync::{nftables_snapshot, BorrowedResyncStream, OwnedResyncStream};
pub use expr::*;
pub use object::{Object, ObjectConfig, ObjectInfo, ObjectState, ObjectType};
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
pub const NFT_MSG_NEWOBJ: u8 = 18;
pub const NFT_MSG_GETOBJ: u8 = 19;
pub const NFT_MSG_DELOBJ: u8 = 20;
/// `NFT_MSG_GETOBJ_RESET` — read an object's state and reset it, atomically.
pub const NFT_MSG_GETOBJ_RESET: u8 = 21;

// Generation (`NFT_MSG_NEWGEN`, sent after every committed batch)
pub const NFTA_GEN_ID: u16 = 1;
pub const NFTA_GEN_PROC_PID: u16 = 2;
pub const NFTA_GEN_PROC_NAME: u16 = 3;
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

/// `NFTA_FLOW_TABLE_NAME` — the flowtable name inside a `flow_offload`
/// *expression* (`enum nft_offload_attributes`). Not
/// [`NFTA_FLOWTABLE_NAME`], which names the flowtable *object* and is 2:
/// the expression's policy stops at 1, so a 2 there is ignored and
/// `nft_flow_offload_init` fails the rule with `EINVAL`.
pub const NFTA_FLOW_TABLE_NAME: u16 = 1;
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
/// Source register of the set form (`meta <key> set ...`).
pub const NFTA_META_SREG: u16 = 3;

// Exthdr (IPv6 extension headers, TCP/IPv4/SCTP/DCCP options)
pub const NFTA_EXTHDR_DREG: u16 = 1;
pub const NFTA_EXTHDR_TYPE: u16 = 2;
pub const NFTA_EXTHDR_OFFSET: u16 = 3;
pub const NFTA_EXTHDR_LEN: u16 = 4;
pub const NFTA_EXTHDR_FLAGS: u16 = 5;
pub const NFTA_EXTHDR_OP: u16 = 6;
/// Source register of the set form (`tcp option ... set ...`).
pub const NFTA_EXTHDR_SREG: u16 = 7;

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

// Quota
pub const NFTA_QUOTA_BYTES: u16 = 1;
pub const NFTA_QUOTA_FLAGS: u16 = 2;
pub const NFTA_QUOTA_CONSUMED: u16 = 4;
/// `NFT_QUOTA_F_INV` — `quota over`: match once the quota is used up.
pub const NFT_QUOTA_F_INV: u32 = 1;

// Stateful object attributes (NFT_MSG_*OBJ).
pub const NFTA_OBJ_TABLE: u16 = 1;
pub const NFTA_OBJ_NAME: u16 = 2;
pub const NFTA_OBJ_TYPE: u16 = 3;
pub const NFTA_OBJ_DATA: u16 = 4;
pub const NFTA_OBJ_USE: u16 = 5;
pub const NFTA_OBJ_HANDLE: u16 = 6;

// objref expression attributes.
pub const NFTA_OBJREF_IMM_TYPE: u16 = 1;
pub const NFTA_OBJREF_IMM_NAME: u16 = 2;
pub const NFTA_OBJREF_SET_SREG: u16 = 3;
pub const NFTA_OBJREF_SET_NAME: u16 = 4;
/// `NFT_QUOTA_F_DEPLETED` — set by the kernel once the quota is used up;
/// live state, never part of a declaration.
pub const NFT_QUOTA_F_DEPLETED: u32 = 2;

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
/// `NFTA_CT_DIRECTION` — original/reply, for the directional keys. The
/// decoder demotes a `ct` carrying it to `RuleExpr::Unknown`: `Expr::Ct`
/// does not model a direction.
pub const NFTA_CT_DIRECTION: u16 = 3;
/// Source register of the set form (`ct mark set ...`).
pub const NFTA_CT_SREG: u16 = 4;

// Route (`rt`)
pub const NFTA_RT_DREG: u16 = 1;
pub const NFTA_RT_KEY: u16 = 2;

// Byteorder
pub const NFTA_BYTEORDER_SREG: u16 = 1;
pub const NFTA_BYTEORDER_DREG: u16 = 2;
pub const NFTA_BYTEORDER_OP: u16 = 3;
pub const NFTA_BYTEORDER_LEN: u16 = 4;
pub const NFTA_BYTEORDER_SIZE: u16 = 5;

// Limit
pub const NFTA_LIMIT_RATE: u16 = 1;
pub const NFTA_LIMIT_UNIT: u16 = 2;
pub const NFTA_LIMIT_BURST: u16 = 3;
pub const NFTA_LIMIT_TYPE: u16 = 4;
/// `NFTA_LIMIT_FLAGS` — `NFT_LIMIT_F_INV`. `nft_limit_dump` emits it on
/// every dump, 0 included, so the writer always sends it.
pub const NFTA_LIMIT_FLAGS: u16 = 5;
/// `NFT_LIMIT_F_INV` — `limit rate over`: match once the rate is exceeded.
pub const NFT_LIMIT_F_INV: u32 = 1;

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

// Redir — `enum nft_redir_attributes`.
//
// The `redir` expression has its OWN attribute namespace, distinct from
// `nft_nat_attributes` above. nlink used to emit `NFTA_NAT_REG_PROTO_MIN` (= 5)
// inside a `redir` nest; the kernel parses that nest with
// `nla_parse_nested_deprecated(tb, NFTA_REDIR_MAX, ...)`, and 5 is above
// `maxtype`, so the attribute was **silently skipped** (#206).
pub const NFTA_REDIR_REG_PROTO_MIN: u16 = 1;
pub const NFTA_REDIR_REG_PROTO_MAX: u16 = 2;
pub const NFTA_REDIR_FLAGS: u16 = 3;

// Reject — `enum nft_reject_attributes`.
//
// `reject` is a real expression that emits an ICMP unreachable or a TCP RST
// and then drops. `Rule::reject()` used to push a bare `NF_DROP` verdict, so
// the packet was black-holed with no ICMP and no RST and clients hung until
// TCP timeout instead of failing fast (#205).
pub const NFTA_REJECT_TYPE: u16 = 1;
pub const NFTA_REJECT_ICMP_CODE: u16 = 2;

/// `NFT_REJECT_ICMP_UNREACH` — send an ICMP unreachable of the family the rule
/// is in.
pub const NFT_REJECT_ICMP_UNREACH: u32 = 0;
/// `NFT_REJECT_TCP_RST` — send a TCP reset. Only valid for TCP traffic.
pub const NFT_REJECT_TCP_RST: u32 = 1;
/// `NFT_REJECT_ICMPX_UNREACH` — family-independent ICMP unreachable, usable in
/// an `inet` / `bridge` chain where the family isn't known at rule-load time.
pub const NFT_REJECT_ICMPX_UNREACH: u32 = 2;

// Log
pub const NFTA_LOG_PREFIX: u16 = 2;
pub const NFTA_LOG_GROUP: u16 = 1;
/// `NFTA_LOG_LEVEL` — syslog level of a `log` without a group.
/// `nft_log_dump` emits it for every such expression.
pub const NFTA_LOG_LEVEL: u16 = 5;
/// `NFT_LOGLEVEL_WARNING` — the level `nft_log_init` picks when the
/// request names none.
pub const NFT_LOGLEVEL_WARNING: u32 = 4;

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
/// `NFT_DATA_VERDICT` — a verdict map's `NFTA_SET_DATA_TYPE`. The kernel
/// reserves every type with these top bits and accepts only this one.
pub const NFT_DATA_VERDICT: u32 = 0xffff_ff00;
// Values below are the kernel `enum nft_set_attributes` positions.
// `NFTA_SET_ID` was previously (wrongly) 16 and `NFTA_SET_HANDLE` 17,
// which collided: a `NEWSET` carried its set id under attribute 16
// (the *real* `NFTA_SET_HANDLE`), so the kernel saw a bogus handle on
// a create and rejected it with ERANGE. No integration test exercised
// sets against a live kernel until the declarative-set work, so the
// drift went unnoticed.
pub const NFTA_SET_POLICY: u16 = 8;
pub const NFTA_SET_DESC: u16 = 9;
/// `NFTA_SET_DESC_SIZE` — inside the `NFTA_SET_DESC` nest: maximum
/// number of elements (`nft add set ... { size N; }`).
pub const NFTA_SET_DESC_SIZE: u16 = 1;
/// `NFTA_SET_DESC_CONCAT` — inside `NFTA_SET_DESC`: one `NFTA_LIST_ELEM`
/// per field of a concatenated key, each carrying `NFTA_SET_FIELD_LEN`.
pub const NFTA_SET_DESC_CONCAT: u16 = 2;
/// `NFTA_SET_FIELD_LEN` — a concatenation field's length **in bytes**. The
/// UAPI header documents it as bits; `nft_set_desc_concat_parse` reads it
/// as bytes (`DIV_ROUND_UP(len, sizeof(u32))` registers, at most `U8_MAX`).
pub const NFTA_SET_FIELD_LEN: u16 = 1;
pub const NFTA_SET_ID: u16 = 10;
/// `NFTA_SET_TIMEOUT` — the default element timeout in milliseconds (u64),
/// kept by the kernel in jiffies, so it reads back rounded down to one.
pub const NFTA_SET_TIMEOUT: u16 = 11;
/// `NFTA_SET_GC_INTERVAL` — the garbage-collection interval in
/// milliseconds (u32), kept as given.
pub const NFTA_SET_GC_INTERVAL: u16 = 12;
/// `NFTA_SET_OBJ_TYPE` — an object map's object type (`NFT_OBJECT_*`).
pub const NFTA_SET_OBJ_TYPE: u16 = 15;
pub const NFTA_SET_HANDLE: u16 = 16;

// Set element attributes
pub const NFTA_SET_ELEM_LIST_TABLE: u16 = 1;
pub const NFTA_SET_ELEM_LIST_SET: u16 = 2;
pub const NFTA_SET_ELEM_LIST_ELEMENTS: u16 = 3;

pub const NFTA_SET_ELEM_KEY: u16 = 1;
pub const NFTA_SET_ELEM_DATA: u16 = 2;
pub const NFTA_SET_ELEM_FLAGS: u16 = 3;
/// `NFTA_SET_ELEM_TIMEOUT` — the element's own timeout in milliseconds
/// (u64). Dumped only when it differs from the set's default.
pub const NFTA_SET_ELEM_TIMEOUT: u16 = 4;
/// `NFTA_SET_ELEM_EXPIRATION` — milliseconds the element has left (u64).
pub const NFTA_SET_ELEM_EXPIRATION: u16 = 5;
/// `NFTA_SET_ELEM_OBJREF` — the stateful object an object-map element
/// maps to, by name.
pub const NFTA_SET_ELEM_OBJREF: u16 = 9;
/// `NFTA_SET_ELEM_KEY_END` — the inclusive end of a range, in the same
/// element: how an interval set of concatenated keys stores one.
pub const NFTA_SET_ELEM_KEY_END: u16 = 10;
/// `NFT_SET_ELEM_INTERVAL_END` — an interval set's range-end element.
pub const NFT_SET_ELEM_INTERVAL_END: u32 = 1;
/// `NFT_SET_ELEM_CATCHALL` — the catch-all (`*`) element.
pub const NFT_SET_ELEM_CATCHALL: u32 = 2;

// Lookup expression
pub const NFTA_LOOKUP_SET: u16 = 1;
pub const NFTA_LOOKUP_SREG: u16 = 2;
pub const NFTA_LOOKUP_DREG: u16 = 3;
pub const NFTA_LOOKUP_SET_ID: u16 = 4;
pub const NFTA_LOOKUP_FLAGS: u16 = 5;
/// `NFT_LOOKUP_F_INV` — match keys *not* in the set (`!= @set`).
pub const NFT_LOOKUP_F_INV: u32 = 1;

// Dynset expression attributes (`add|update|delete @set { ... }`).
pub const NFTA_DYNSET_SET_NAME: u16 = 1;
pub const NFTA_DYNSET_OP: u16 = 3;
pub const NFTA_DYNSET_SREG_KEY: u16 = 4;
pub const NFTA_DYNSET_SREG_DATA: u16 = 5;
/// `NFTA_DYNSET_TIMEOUT` — milliseconds (u64), kept in jiffies. Always
/// dumped, 0 when the expression has none; refused (`EOPNOTSUPP`) in a
/// request for a set without `NFT_SET_TIMEOUT`.
pub const NFTA_DYNSET_TIMEOUT: u16 = 6;
/// `NFTA_DYNSET_EXPR` — one per-element expression (not modelled).
pub const NFTA_DYNSET_EXPR: u16 = 7;
/// `NFTA_DYNSET_FLAGS` — always dumped.
pub const NFTA_DYNSET_FLAGS: u16 = 9;
/// `NFTA_DYNSET_EXPRESSIONS` — several per-element expressions (not
/// modelled).
pub const NFTA_DYNSET_EXPRESSIONS: u16 = 10;
/// `NFT_DYNSET_F_INV` — the rule matches when the update *fails* (a full
/// set), instead of when it succeeds.
pub const NFT_DYNSET_F_INV: u32 = 1;

// Set flags
pub const NFT_SET_ANONYMOUS: u32 = 0x1;
pub const NFT_SET_CONSTANT: u32 = 0x2;
pub const NFT_SET_INTERVAL: u32 = 0x4;
pub const NFT_SET_MAP: u32 = 0x8;
pub const NFT_SET_TIMEOUT: u32 = 0x10;
pub const NFT_SET_EVAL: u32 = 0x20;
pub const NFT_SET_OBJECT: u32 = 0x40;
pub const NFT_SET_CONCAT: u32 = 0x80;
pub const NFT_SET_EXPR: u32 = 0x100;

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
