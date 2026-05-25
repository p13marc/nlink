//! Nftables multicast event types + parser.
//!
//! The kernel emits `NFT_MSG_NEW*` / `NFT_MSG_DEL*` notifications
//! on `NFNLGRP_NFTABLES` (group 7) whenever a table, chain, rule,
//! or flowtable is created or destroyed — by **any** writer on the
//! host, not just the current process. Subscribers see the full
//! ruleset mutation history in real time. Use cases include
//! reconcile-on-drift in declarative managers (Plan 157), audit
//! pipelines, and live introspection in `nft monitor`-style tools.
//!
//! Subscribe via [`Connection::<Nftables>::subscribe`] + consume the
//! [`Stream`](tokio_stream::Stream) returned by
//! [`Connection::events`](crate::netlink::Connection::events).
//!
//! See the parent module's `add_table` / `add_chain` etc. for the
//! mutating side that produces these events.
//!
//! [`Connection::<Nftables>::subscribe`]: crate::netlink::Connection

use super::connection::{parse_chain, parse_flowtable, parse_rule, parse_table};
use super::types::{ChainInfo, Family, Flowtable, RuleInfo, Table};
use super::{
    NFGENMSG_HDRLEN, NFNL_SUBSYS_NFTABLES, NFT_MSG_DELCHAIN, NFT_MSG_DELFLOWTABLE,
    NFT_MSG_DELRULE, NFT_MSG_DELTABLE, NFT_MSG_NEWCHAIN, NFT_MSG_NEWFLOWTABLE, NFT_MSG_NEWRULE,
    NFT_MSG_NEWTABLE,
};

/// `NFNLGRP_NFTABLES` (7) — the single multicast group on which
/// the kernel announces table/chain/rule/flowtable mutations.
///
/// All nftables events flow through this one group; the per-event
/// "kind" (new vs del, table vs chain vs rule vs flowtable) is
/// encoded in the `nlmsg_type` byte. Compare with conntrack which
/// uses one group per event kind.
pub const NFNLGRP_NFTABLES: u32 = 7;

/// Multicast group to subscribe to via
/// [`Connection::<Nftables>::subscribe`][subscribe].
///
/// At present nftables only ships a single multicast group
/// (`NFNLGRP_NFTABLES = 7`); this enum exists for forward symmetry
/// with [`ConntrackGroup`](crate::netlink::netfilter::ConntrackGroup)
/// and to leave room for the kernel adding finer-grained groups
/// later.
///
/// [subscribe]: crate::netlink::Connection
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum NftablesGroup {
    /// `NFNLGRP_NFTABLES` — table/chain/rule/flowtable mutations.
    All,
}

impl NftablesGroup {
    /// Map to the kernel multicast group ID.
    pub fn to_kernel_group(self) -> u32 {
        match self {
            Self::All => NFNLGRP_NFTABLES,
        }
    }
}

/// An event delivered on the nftables multicast stream.
///
/// One variant per ruleset-mutating wire message the kernel emits.
/// Sets (`NFT_MSG_NEWSET` / `DELSET` / `*SETELEM` / `NEWGEN`) are
/// not currently parsed into typed event variants — they're
/// silently dropped from the stream. Wire when a consumer asks.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum NftablesEvent {
    /// `NFT_MSG_NEWTABLE` — a table was created or updated. The
    /// kernel uses the same wire shape for both, so a stream
    /// subscribed to `All` sees both as `NewTable`.
    NewTable(Table),
    /// `NFT_MSG_DELTABLE` — a table was destroyed.
    DelTable(Table),
    /// `NFT_MSG_NEWCHAIN` — a chain was created or updated.
    NewChain(ChainInfo),
    /// `NFT_MSG_DELCHAIN` — a chain was destroyed.
    DelChain(ChainInfo),
    /// `NFT_MSG_NEWRULE` — a rule was added to a chain.
    NewRule(RuleInfo),
    /// `NFT_MSG_DELRULE` — a rule was removed from a chain.
    DelRule(RuleInfo),
    /// `NFT_MSG_NEWFLOWTABLE` — a flowtable was created or updated.
    NewFlowtable(Flowtable),
    /// `NFT_MSG_DELFLOWTABLE` — a flowtable was destroyed.
    DelFlowtable(Flowtable),
}

/// Build an [`NftablesEvent`] from the netlink message type byte +
/// the body (post-nlmsghdr). Returns `None` for messages we don't
/// recognise (e.g. set/setelem/gen messages, error frames, other
/// subsystems).
///
/// The body is `nfgenmsg (4 bytes) || attribute payload`. The
/// nfgenmsg's first byte is the address family, which we feed into
/// the per-type parser so the resulting typed value carries the
/// family the kernel reported.
pub(crate) fn parse_nftables_event(msg_type: u16, body: &[u8]) -> Option<NftablesEvent> {
    if (msg_type >> 8) != NFNL_SUBSYS_NFTABLES {
        return None;
    }
    if body.len() < NFGENMSG_HDRLEN {
        return None;
    }
    let family = Family::from_u8(body[0]).unwrap_or(Family::Inet);
    let attrs = &body[NFGENMSG_HDRLEN..];

    match (msg_type & 0xFF) as u8 {
        NFT_MSG_NEWTABLE => parse_table(attrs, family).map(NftablesEvent::NewTable),
        NFT_MSG_DELTABLE => parse_table(attrs, family).map(NftablesEvent::DelTable),
        NFT_MSG_NEWCHAIN => parse_chain(attrs, family).map(NftablesEvent::NewChain),
        NFT_MSG_DELCHAIN => parse_chain(attrs, family).map(NftablesEvent::DelChain),
        NFT_MSG_NEWRULE => parse_rule(attrs, family).map(NftablesEvent::NewRule),
        NFT_MSG_DELRULE => parse_rule(attrs, family).map(NftablesEvent::DelRule),
        NFT_MSG_NEWFLOWTABLE => parse_flowtable(attrs, family).map(NftablesEvent::NewFlowtable),
        NFT_MSG_DELFLOWTABLE => parse_flowtable(attrs, family).map(NftablesEvent::DelFlowtable),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn group_maps_to_kernel_id() {
        assert_eq!(NftablesGroup::All.to_kernel_group(), 7);
    }

    #[test]
    fn parse_rejects_wrong_subsystem() {
        // Subsystem byte != NFNL_SUBSYS_NFTABLES (10) — e.g. conntrack (1).
        let msg_type = (1u16 << 8) | NFT_MSG_NEWTABLE as u16;
        let body = vec![0u8; NFGENMSG_HDRLEN];
        assert!(parse_nftables_event(msg_type, &body).is_none());
    }

    #[test]
    fn parse_rejects_truncated_body() {
        let msg_type = (NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_NEWTABLE as u16;
        let body: Vec<u8> = vec![0; 2]; // shorter than NFGENMSG_HDRLEN (4)
        assert!(parse_nftables_event(msg_type, &body).is_none());
    }

    #[test]
    fn parse_unknown_msg_type_returns_none() {
        // Valid nftables subsystem byte, but msg=NFT_MSG_NEWSET which we
        // don't parse into a typed variant.
        let msg_type = (NFNL_SUBSYS_NFTABLES << 8) | 9u16;
        let body = vec![0u8; NFGENMSG_HDRLEN];
        assert!(parse_nftables_event(msg_type, &body).is_none());
    }
}
