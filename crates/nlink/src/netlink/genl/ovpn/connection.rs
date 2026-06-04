//! `Connection<Ovpn>` helper methods.
//!
//! Thin wrappers over the generic
//! [`Connection::send_typed`][crate::netlink::Connection::send_typed]
//! / [`dump_typed_stream`][crate::netlink::Connection::dump_typed_stream]
//! dispatch the `#[derive(GenlMessage)]` + `#[genl_family]` machinery
//! provides.
//!
//! # SCM_RIGHTS fd passing
//!
//! The kernel's `peer-new` GENL command takes an
//! `OVPN_A_PEER_SOCKET` u32 attribute that's a kernel-side
//! reference to a UDP/TCP socket. When the caller owns the socket
//! in the same process + netns, passing the bare fd value works
//! (the kernel resolves it via `sockfd_lookup`). Cross-namespace
//! fd passing requires SCM_RIGHTS in the sendmsg auxiliary control
//! message; that path is deferred to a follow-up — see
//! [`attach_socket`][Self::attach_socket] for the call shape so
//! consumers can plan ahead.

use std::os::fd::RawFd;

use crate::macros::GenlTypedDumpStream;
use crate::netlink::{
    Connection,
    error::{Error, Result},
    genl::ovpn::messages::{
        OvpnKeyDelRequest, OvpnKeyGetRequest, OvpnKeyNewRequest, OvpnKeyReply,
        OvpnKeySwapRequest, OvpnKeyconf, OvpnPeer, OvpnPeerDelRequest, OvpnPeerGetRequest,
        OvpnPeerNewRequest, OvpnPeerReply, OvpnPeerSetRequest,
    },
    genl::ovpn::types::OvpnKeySlot,
};

use super::Ovpn;

impl Connection<Ovpn> {
    // ============================================================
    // Peer operations
    // ============================================================

    /// Install a new peer on the ovpn interface.
    ///
    /// `peer.id` must be set and unique among the interface's
    /// peers. The peer's UDP/TCP socket can be specified via
    /// `peer.socket` (a fd value in the caller's process — same
    /// netns). Cross-netns fd passing isn't yet supported; use
    /// [`attach_socket`][Self::attach_socket] in a future release.
    pub async fn peer_new(&self, ifindex: u32, peer: OvpnPeer) -> Result<()> {
        let _: OvpnPeerReply = self
            .send_typed(OvpnPeerNewRequest::new(ifindex, peer))
            .await?;
        Ok(())
    }

    /// Modify an existing peer. Only set fields are applied; the
    /// kernel preserves prior values for omitted attributes.
    pub async fn peer_set(&self, ifindex: u32, peer: OvpnPeer) -> Result<()> {
        let _: OvpnPeerReply = self
            .send_typed(OvpnPeerSetRequest::new(ifindex, peer))
            .await?;
        Ok(())
    }

    /// Query a single peer by ID. Returns
    /// `Error::is_not_found()` if no peer with that ID exists on
    /// the interface.
    pub async fn peer_get(&self, ifindex: u32, peer_id: u32) -> Result<OvpnPeer> {
        let reply: OvpnPeerReply = self
            .send_typed(OvpnPeerGetRequest::by_id(ifindex, peer_id))
            .await?;
        reply.peer.ok_or_else(|| {
            Error::InvalidMessage(format!(
                "peer_get(ifindex={ifindex}, peer_id={peer_id}): kernel reply missing OVPN_A_PEER"
            ))
        })
    }

    /// Dump every peer on the ovpn interface. On an interface
    /// with no peers, returns an empty vector.
    pub async fn peer_dump(&self, ifindex: u32) -> Result<Vec<OvpnPeer>> {
        use tokio_stream::StreamExt;
        let mut stream: GenlTypedDumpStream<'_, Ovpn, OvpnPeerReply> = self
            .dump_typed_stream(OvpnPeerGetRequest::dump(ifindex))
            .await?;
        let mut out = Vec::new();
        while let Some(reply) = stream.next().await {
            let reply = reply?;
            if let Some(peer) = reply.peer {
                out.push(peer);
            }
        }
        Ok(out)
    }

    /// Delete a peer. The kernel emits a `peer-del-ntf` on the
    /// `peers` multicast group after the delete completes.
    pub async fn peer_del(&self, ifindex: u32, peer_id: u32) -> Result<()> {
        let _: OvpnPeerReply = self
            .send_typed(OvpnPeerDelRequest::new(ifindex, peer_id))
            .await?;
        Ok(())
    }

    // ============================================================
    // Key operations
    // ============================================================

    /// Install a cipher key for `(peer_id, slot)`. The key bytes
    /// in `keyconf.encrypt_dir` / `.decrypt_dir` are write-only
    /// — `key_get` never returns them.
    ///
    /// The `cipher_alg` and `key_id` fields must be set; the
    /// kernel rejects requests missing either.
    pub async fn key_new(&self, ifindex: u32, keyconf: OvpnKeyconf) -> Result<()> {
        let _: OvpnKeyReply = self
            .send_typed(OvpnKeyNewRequest::new(ifindex, keyconf))
            .await?;
        Ok(())
    }

    /// Read non-sensitive metadata about an installed key
    /// (cipher_alg, key_id, slot). Returns `Error::is_not_found()`
    /// if no key is installed at that slot.
    pub async fn key_get(
        &self,
        ifindex: u32,
        peer_id: u32,
        slot: OvpnKeySlot,
    ) -> Result<OvpnKeyconf> {
        let reply: OvpnKeyReply = self
            .send_typed(OvpnKeyGetRequest::new(ifindex, peer_id, slot))
            .await?;
        reply.keyconf.ok_or_else(|| {
            Error::InvalidMessage(format!(
                "key_get(ifindex={ifindex}, peer_id={peer_id}, slot={slot:?}): \
                 kernel reply missing OVPN_A_KEYCONF"
            ))
        })
    }

    /// Atomically swap the primary and secondary key slots for
    /// `peer_id`. This is the rekey cutover point — OpenVPN 2.7
    /// installs the new key into the secondary slot then calls
    /// `key_swap` to activate it without dropping a single packet.
    pub async fn key_swap(&self, ifindex: u32, peer_id: u32) -> Result<()> {
        let _: OvpnKeyReply = self
            .send_typed(OvpnKeySwapRequest::new(ifindex, peer_id))
            .await?;
        Ok(())
    }

    /// Delete the cipher key at `(peer_id, slot)`. Returns
    /// `Error::is_not_found()` if no key is installed there.
    pub async fn key_del(
        &self,
        ifindex: u32,
        peer_id: u32,
        slot: OvpnKeySlot,
    ) -> Result<()> {
        let _: OvpnKeyReply = self
            .send_typed(OvpnKeyDelRequest::new(ifindex, peer_id, slot))
            .await?;
        Ok(())
    }

    // ============================================================
    // Socket attachment
    // ============================================================

    /// Cross-namespace socket attachment via SCM_RIGHTS auxiliary
    /// control message.
    ///
    /// **Currently returns `Error::is_not_supported()`.** Same-netns
    /// callers should pass the socket fd via `OvpnPeer::socket`
    /// on `peer_new` — the kernel resolves it via `sockfd_lookup`
    /// without needing SCM_RIGHTS.
    ///
    /// Cross-netns fd passing requires extending the `NetlinkSocket`
    /// sendmsg path with a `cmsghdr` carrying `SCM_RIGHTS` + the fd
    /// number. That refactor is queued for a follow-up release; the
    /// method signature is shipped now so consumers can plan
    /// against it. When implemented, this will issue a `peer-new`
    /// (or `peer-set`) for `peer_id` with the fd passed in the
    /// auxiliary data.
    ///
    /// See `plans/197-declarative-ovpn-plan.md` §7 for the
    /// deferral rationale.
    pub async fn attach_socket(
        &self,
        _ifindex: u32,
        _peer_id: u32,
        _fd: RawFd,
    ) -> Result<()> {
        Err(Error::NotSupported(
            "Connection::<Ovpn>::attach_socket — cross-netns fd passing via SCM_RIGHTS \
             not yet implemented. Same-netns callers should set OvpnPeer::socket = Some(fd) \
             and call peer_new() directly; the kernel resolves the fd via sockfd_lookup. \
             See plans/197-declarative-ovpn-plan.md §7."
                .into(),
        ))
    }
}
