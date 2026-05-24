//! `Connection<Dpll>` helper methods.
//!
//! Thin wrappers over the generic
//! [`Connection::send_typed`][crate::netlink::Connection::send_typed]
//! / [`dump_typed_stream`][crate::netlink::Connection::dump_typed_stream]
//! dispatch that the `#[derive(GenlMessage)]` + `#[genl_family]`
//! machinery (Plan 154) provides. The helpers exist so downstream
//! code can write `conn.get_device(id).await?` instead of
//! `conn.send_typed(DpllDeviceGetRequest::by_id(id)).await?` —
//! same semantics, more discoverable.

use crate::macros::GenlTypedDumpStream;
use crate::netlink::{
    connection::Connection,
    error::Result,
    genl::dpll::messages::{DpllDeviceGetRequest, DpllDeviceReply, DpllDeviceSetRequest},
    genl::dpll::types::{DpllFeatureState, DpllMode},
};

use super::Dpll;

impl Connection<Dpll> {
    /// Query a single device by ID.
    ///
    /// Returns the kernel's [`DpllDeviceReply`] — every attribute
    /// the device exposes, with version-gated fields surfacing as
    /// `None` on kernels that don't ship them.
    ///
    /// `Error::is_not_found()` if the kernel doesn't have a
    /// device with `id`.
    pub async fn get_device(&self, id: u32) -> Result<DpllDeviceReply> {
        self.send_typed(DpllDeviceGetRequest::by_id(id)).await
    }

    /// Stream every DPLL device the kernel reports.
    ///
    /// Returns a [`GenlTypedDumpStream`] that yields one
    /// [`DpllDeviceReply`] per kernel frame. On hosts without
    /// DPLL hardware the stream completes immediately with zero
    /// elements; no per-element error.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use tokio_stream::StreamExt;
    /// let conn = Connection::<Dpll>::new_async().await?;
    /// let mut stream = conn.dump_devices().await?;
    /// while let Some(dev) = stream.next().await {
    ///     let dev = dev?;
    ///     println!("{}: {:?}", dev.id, dev.lock_status);
    /// }
    /// ```
    pub async fn dump_devices(
        &self,
    ) -> Result<GenlTypedDumpStream<'_, Dpll, DpllDeviceReply>> {
        self.dump_typed_stream(DpllDeviceGetRequest::dump()).await
    }

    /// Switch a device into the given mode (Manual ↔ Automatic).
    ///
    /// Most drivers reject `Manual` while in lock state
    /// `Unlocked` — surfaces as
    /// `Error::is_invalid_argument()`.
    pub async fn set_device_mode(&self, id: u32, mode: DpllMode) -> Result<()> {
        let _: DpllDeviceReply = self
            .send_typed(DpllDeviceSetRequest::new(id).mode(mode))
            .await?;
        Ok(())
    }

    /// Enable or disable the device's phase-offset monitor
    /// (kernel 6.12+). Returns
    /// `Error::is_invalid_argument()` on older kernels (kernel
    /// refuses the unknown attribute under
    /// `enable_strict_checking`).
    pub async fn set_device_phase_offset_monitor(
        &self,
        id: u32,
        state: DpllFeatureState,
    ) -> Result<()> {
        let _: DpllDeviceReply = self
            .send_typed(DpllDeviceSetRequest::new(id).phase_offset_monitor(state))
            .await?;
        Ok(())
    }

    /// Enable or disable the device's frequency monitor (kernel
    /// 6.12+).
    pub async fn set_device_frequency_monitor(
        &self,
        id: u32,
        state: DpllFeatureState,
    ) -> Result<()> {
        let _: DpllDeviceReply = self
            .send_typed(DpllDeviceSetRequest::new(id).frequency_monitor(state))
            .await?;
        Ok(())
    }
}

