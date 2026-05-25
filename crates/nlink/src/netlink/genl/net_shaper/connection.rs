//! `Connection<NetShaper>` helper methods.
//!
//! Typed wrappers over the generic
//! [`Connection::send_typed`][crate::netlink::Connection::send_typed]
//! / [`dump_typed_stream`][crate::netlink::Connection::dump_typed_stream]
//! dispatch. Same shape as the DPLL helpers — one inherent
//! method per "do" operation, one per dump shape.

use crate::macros::GenlTypedDumpStream;
use crate::netlink::{connection::Connection, error::Result};

use super::messages::{
    NetShaperCapsGetRequest, NetShaperCapsReply, NetShaperDeleteRequest, NetShaperGetRequest,
    NetShaperHandle, NetShaperReply, NetShaperSetRequest,
};
use super::types::NetShaperScope;
use super::NetShaper;

impl Connection<NetShaper> {
    /// Read one shaper's state.
    ///
    /// Returns `Error::is_not_found()` if no shaper is installed
    /// at `(ifindex, handle)`. Requires `CAP_NET_ADMIN`.
    pub async fn get_shaper(
        &self,
        ifindex: u32,
        handle: NetShaperHandle,
    ) -> Result<NetShaperReply> {
        self.send_typed(NetShaperGetRequest::by_handle(ifindex, handle))
            .await
    }

    /// Stream every shaper installed on `ifindex` — one
    /// [`NetShaperReply`] per kernel frame. Empty stream on
    /// interfaces with no shapers; per-element error otherwise.
    ///
    /// ```ignore
    /// use tokio_stream::StreamExt;
    /// let conn = Connection::<NetShaper>::new_async().await?;
    /// let mut stream = conn.dump_shapers(eth0_ifindex).await?;
    /// while let Some(s) = stream.next().await {
    ///     let s = s?;
    ///     println!("{:?} bw_max={:?}", s.handle, s.bw_max);
    /// }
    /// ```
    pub async fn dump_shapers(
        &self,
        ifindex: u32,
    ) -> Result<GenlTypedDumpStream<'_, NetShaper, NetShaperReply>> {
        self.dump_typed_stream(NetShaperGetRequest::dump(ifindex))
            .await
    }

    /// Create or modify a shaper. Build the request with
    /// [`NetShaperSetRequest::new`] + chained setters.
    ///
    /// Returns `Error::is_not_supported()` if the driver lacks
    /// the requested feature — check
    /// [`get_caps`](Self::get_caps) first to avoid the round-trip.
    pub async fn set_shaper(&self, req: NetShaperSetRequest) -> Result<()> {
        // The kernel returns an empty reply (just an ACK); the
        // typed dispatch needs a Reply type that can parse the
        // empty body — `NetShaperReply` does (all Option<>) so we
        // discard.
        let _: NetShaperReply = self.send_typed(req).await?;
        Ok(())
    }

    /// Remove a shaper.
    ///
    /// `Error::is_not_found()` if no shaper is installed at
    /// `(ifindex, handle)`.
    pub async fn del_shaper(&self, ifindex: u32, handle: NetShaperHandle) -> Result<()> {
        let _: NetShaperReply = self
            .send_typed(NetShaperDeleteRequest::new(ifindex, handle))
            .await?;
        Ok(())
    }

    /// Query driver-supported shaper features for one specific
    /// scope.
    pub async fn get_caps(
        &self,
        ifindex: u32,
        scope: NetShaperScope,
    ) -> Result<NetShaperCapsReply> {
        self.send_typed(NetShaperCapsGetRequest::for_scope(ifindex, scope))
            .await
    }

    /// Stream caps across every scope the driver exposes — one
    /// reply per scope.
    pub async fn dump_caps(
        &self,
        ifindex: u32,
    ) -> Result<GenlTypedDumpStream<'_, NetShaper, NetShaperCapsReply>> {
        self.dump_typed_stream(NetShaperCapsGetRequest::dump(ifindex))
            .await
    }
}
