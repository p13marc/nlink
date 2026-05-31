//! nl80211 connection implementation for `Connection<Nl80211>`.

use super::{types::*, *};
use crate::macros::{GenlFamily, __rt::resolve_genl_family_with_groups};
use crate::netlink::{
    attr::AttrIter,
    builder::MessageBuilder,
    connection::Connection,
    error::{Error, Result},
    genl::{GENL_HDRLEN, GenlMsgHdr},
    message::{MessageIter, NLM_F_ACK, NLM_F_DUMP, NLM_F_REQUEST, NlMsgError},
    protocol::{AsyncProtocolInit, Nl80211},
    socket::NetlinkSocket,
};

impl AsyncProtocolInit for Nl80211 {
    async fn resolve_async(socket: &NetlinkSocket) -> Result<Self> {
        let (family_id, mcast_groups) =
            resolve_genl_family_with_groups(socket, NL80211_GENL_NAME).await?;
        Ok(Self {
            family_id,
            mcast_groups,
        })
    }
}

impl GenlFamily for Nl80211 {
    const VERSION: u8 = NL80211_GENL_VERSION;
    const NAME: &'static str = NL80211_GENL_NAME;

    fn family_id(&self) -> u16 {
        self.family_id
    }

    fn mcast_group(&self, name: &str) -> Option<u32> {
        self.mcast_groups.get(name).copied()
    }
}

impl Connection<Nl80211> {

    /// Get the nl80211 family ID.
    pub fn family_id(&self) -> u16 {
        self.state().family_id
    }

    /// Subscribe to all nl80211 multicast event groups exposed by
    /// the kernel — typically `scan`, `mlme`, `regulatory`, and
    /// `config`. For fine-grained subscription, use the generic
    /// [`subscribe_group`](Connection::subscribe_group) directly.
    ///
    /// After subscribing, use `events()` or `into_events()` to
    /// receive events.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use nlink::netlink::{Connection, Nl80211};
    /// use tokio_stream::StreamExt;
    ///
    /// let mut conn = Connection::<Nl80211>::new_async().await?;
    /// conn.subscribe()?;
    ///
    /// let mut events = conn.events();
    /// while let Some(event) = events.next().await {
    ///     println!("{:?}", event?);
    /// }
    /// ```
    pub fn subscribe(&self) -> Result<()> {
        let mut subscribed = false;
        for name in [
            NL80211_MCGRP_SCAN,
            NL80211_MCGRP_MLME,
            NL80211_MCGRP_REGULATORY,
            NL80211_MCGRP_CONFIG,
        ] {
            if let Some(id) = self.state().mcast_groups.get(name).copied() {
                self.socket().add_membership(id)?;
                subscribed = true;
            }
        }

        if !subscribed {
            return Err(Error::InvalidMessage(
                "no nl80211 multicast groups available".into(),
            ));
        }

        Ok(())
    }

    // =========================================================================
    // Interface Queries
    // =========================================================================

    /// List all wireless interfaces.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let ifaces = conn.get_interfaces().await?;
    /// for iface in &ifaces {
    ///     println!("{}: {:?}", iface.name.as_deref().unwrap_or("?"), iface.iftype);
    /// }
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_interfaces"))]
    pub async fn get_interfaces(&self) -> Result<Vec<WirelessInterface>> {
        let responses = self.nl80211_dump(NL80211_CMD_GET_INTERFACE).await?;
        let mut interfaces = Vec::new();

        for payload in &responses {
            if payload.len() < GENL_HDRLEN {
                continue;
            }
            interfaces.push(parse_interface(&payload[GENL_HDRLEN..]));
        }

        Ok(interfaces)
    }

    /// Get a specific wireless interface by name.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_interface"))]
    pub async fn get_interface(&self, name: &str) -> Result<Option<WirelessInterface>> {
        let ifaces = self.get_interfaces().await?;
        Ok(ifaces.into_iter().find(|i| i.name.as_deref() == Some(name)))
    }

    /// Get a specific wireless interface by index.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_interface_by_index"))]
    pub async fn get_interface_by_index(&self, ifindex: u32) -> Result<Option<WirelessInterface>> {
        let ifaces = self.get_interfaces().await?;
        Ok(ifaces.into_iter().find(|i| i.ifindex == ifindex))
    }

    // =========================================================================
    // Scanning
    // =========================================================================

    /// Trigger a scan on an interface.
    ///
    /// This is asynchronous: the kernel starts the scan and returns
    /// immediately. Poll `get_scan_results()` to get results.
    ///
    /// # Errors
    ///
    /// Returns `Error::Kernel` with `EBUSY` if a scan is already in progress.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "trigger_scan"))]
    pub async fn trigger_scan(&self, iface: &str, request: &ScanRequest) -> Result<()> {
        let ifindex = self.resolve_ifindex(iface).await?;
        self.trigger_scan_by_index(ifindex, request).await
    }

    /// Trigger a scan by interface index (namespace-safe).
    #[tracing::instrument(level = "debug", skip_all, fields(method = "trigger_scan_by_index"))]
    pub async fn trigger_scan_by_index(&self, ifindex: u32, request: &ScanRequest) -> Result<()> {
        // F1 fix — serialize the send + recv-loop pair so concurrent
        // tasks on a shared `Arc<Connection>` don't race on the recv
        // side. See connection.rs `Concurrency` docstring.
        let _guard = self.lock_request().await;
        let family_id = self.state().family_id;

        let mut builder = MessageBuilder::new(family_id, NLM_F_REQUEST | NLM_F_ACK);
        let genl_hdr = GenlMsgHdr::new(NL80211_CMD_TRIGGER_SCAN, NL80211_GENL_VERSION);
        builder.append(&genl_hdr);
        builder.append_attr_u32(NL80211_ATTR_IFINDEX, ifindex);

        if !request.frequencies.is_empty() {
            let nest = builder.nest_start(NL80211_ATTR_SCAN_FREQUENCIES);
            for (i, freq) in request.frequencies.iter().enumerate() {
                builder.append_attr_u32((i + 1) as u16, *freq);
            }
            builder.nest_end(nest);
        }

        if !request.ssids.is_empty() {
            let nest = builder.nest_start(NL80211_ATTR_SCAN_SSIDS);
            for (i, ssid) in request.ssids.iter().enumerate() {
                builder.append_attr((i + 1) as u16, ssid);
            }
            builder.nest_end(nest);
        }

        let seq = self.socket().next_seq();
        builder.set_seq(seq);
        builder.set_pid(self.socket().pid());

        let msg = builder.finish();
        self.socket().send(&msg).await?;

        // Wait for ACK
        self.wait_ack(seq).await
    }

    /// Get cached scan results for an interface.
    ///
    /// Returns the most recent scan results. Call `trigger_scan()` first
    /// to ensure fresh results.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_scan_results"))]
    pub async fn get_scan_results(&self, iface: &str) -> Result<Vec<ScanResult>> {
        let ifindex = self.resolve_ifindex(iface).await?;
        self.get_scan_results_by_index(ifindex).await
    }

    /// Get scan results by interface index (namespace-safe).
    #[tracing::instrument(
        level = "debug",
        skip_all,
        fields(method = "get_scan_results_by_index")
    )]
    pub async fn get_scan_results_by_index(&self, ifindex: u32) -> Result<Vec<ScanResult>> {
        // F1 fix — serialize the send + recv-loop pair so concurrent
        // tasks on a shared `Arc<Connection>` don't race on the recv
        // side. See connection.rs `Concurrency` docstring.
        let _guard = self.lock_request().await;
        let family_id = self.state().family_id;

        let mut builder = MessageBuilder::new(family_id, NLM_F_REQUEST | NLM_F_DUMP);
        let genl_hdr = GenlMsgHdr::new(NL80211_CMD_GET_SCAN, NL80211_GENL_VERSION);
        builder.append(&genl_hdr);
        builder.append_attr_u32(NL80211_ATTR_IFINDEX, ifindex);

        let seq = self.socket().next_seq();
        builder.set_seq(seq);
        builder.set_pid(self.socket().pid());

        let msg = builder.finish();
        self.socket().send(&msg).await?;

        let responses = self.collect_dump_responses(seq).await?;
        let mut results = Vec::new();

        for payload in &responses {
            if payload.len() < GENL_HDRLEN {
                continue;
            }
            // Scan results have NL80211_ATTR_BSS as a nested attribute
            for (attr_type, attr_payload) in AttrIter::new(&payload[GENL_HDRLEN..]) {
                if attr_type == NL80211_ATTR_BSS {
                    results.push(parse_bss(attr_payload));
                }
            }
        }

        Ok(results)
    }

    // =========================================================================
    // Station Info
    // =========================================================================

    /// Get station info for the currently associated AP.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_station"))]
    pub async fn get_station(&self, iface: &str) -> Result<Option<StationInfo>> {
        let stations = self.get_stations(iface).await?;
        Ok(stations.into_iter().next())
    }

    /// Get station info by interface index (namespace-safe).
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_station_by_index"))]
    pub async fn get_station_by_index(&self, ifindex: u32) -> Result<Option<StationInfo>> {
        let stations = self.get_stations_by_index(ifindex).await?;
        Ok(stations.into_iter().next())
    }

    /// List all stations (useful in AP mode).
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_stations"))]
    pub async fn get_stations(&self, iface: &str) -> Result<Vec<StationInfo>> {
        let ifindex = self.resolve_ifindex(iface).await?;
        self.get_stations_by_index(ifindex).await
    }

    /// List all stations by interface index.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_stations_by_index"))]
    pub async fn get_stations_by_index(&self, ifindex: u32) -> Result<Vec<StationInfo>> {
        // F1 fix — serialize the send + recv-loop pair so concurrent
        // tasks on a shared `Arc<Connection>` don't race on the recv
        // side. See connection.rs `Concurrency` docstring.
        let _guard = self.lock_request().await;
        let family_id = self.state().family_id;

        let mut builder = MessageBuilder::new(family_id, NLM_F_REQUEST | NLM_F_DUMP);
        let genl_hdr = GenlMsgHdr::new(NL80211_CMD_GET_STATION, NL80211_GENL_VERSION);
        builder.append(&genl_hdr);
        builder.append_attr_u32(NL80211_ATTR_IFINDEX, ifindex);

        let seq = self.socket().next_seq();
        builder.set_seq(seq);
        builder.set_pid(self.socket().pid());

        let msg = builder.finish();
        self.socket().send(&msg).await?;

        let responses = self.collect_dump_responses(seq).await?;
        let mut stations = Vec::new();

        for payload in &responses {
            if payload.len() < GENL_HDRLEN {
                continue;
            }
            stations.push(parse_station(&payload[GENL_HDRLEN..]));
        }

        Ok(stations)
    }

    // =========================================================================
    // Physical Device
    // =========================================================================

    /// List all physical wireless devices.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_phys"))]
    pub async fn get_phys(&self) -> Result<Vec<PhyInfo>> {
        let responses = self.nl80211_dump(NL80211_CMD_GET_WIPHY).await?;
        let mut phys = Vec::new();

        for payload in &responses {
            if payload.len() < GENL_HDRLEN {
                continue;
            }
            phys.push(parse_phy(&payload[GENL_HDRLEN..]));
        }

        Ok(phys)
    }

    /// Get capabilities of a specific physical device.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_phy"))]
    pub async fn get_phy(&self, wiphy: u32) -> Result<Option<PhyInfo>> {
        let phys = self.get_phys().await?;
        Ok(phys.into_iter().find(|p| p.index == wiphy))
    }

    // =========================================================================
    // Regulatory
    // =========================================================================

    /// Get the current regulatory domain.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_regulatory"))]
    pub async fn get_regulatory(&self) -> Result<RegulatoryDomain> {
        // F1 fix — serialize the send + recv-loop pair so concurrent
        // tasks on a shared `Arc<Connection>` don't race on the recv
        // side. See connection.rs `Concurrency` docstring.
        let _guard = self.lock_request().await;
        let family_id = self.state().family_id;

        let mut builder = MessageBuilder::new(family_id, NLM_F_REQUEST);
        let genl_hdr = GenlMsgHdr::new(NL80211_CMD_GET_REG, NL80211_GENL_VERSION);
        builder.append(&genl_hdr);

        let seq = self.socket().next_seq();
        builder.set_seq(seq);
        builder.set_pid(self.socket().pid());

        let msg = builder.finish();
        self.socket().send(&msg).await?;

        let responses = self.collect_dump_responses(seq).await?;

        let mut domain = RegulatoryDomain {
            country: String::new(),
            rules: Vec::new(),
        };

        for payload in &responses {
            if payload.len() < GENL_HDRLEN {
                continue;
            }
            parse_regulatory(&payload[GENL_HDRLEN..], &mut domain);
        }

        Ok(domain)
    }

    // =========================================================================
    // Station Mode (Phase 2)
    // =========================================================================

    /// Connect to a wireless network.
    ///
    /// # Errors
    ///
    /// Returns `Error::Kernel` with `EALREADY` if already connected.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "connect"))]
    pub async fn connect(&self, iface: &str, request: ConnectRequest) -> Result<()> {
        let ifindex = self.resolve_ifindex(iface).await?;
        self.connect_by_index(ifindex, request).await
    }

    /// Connect by interface index (namespace-safe).
    #[tracing::instrument(level = "debug", skip_all, fields(method = "connect_by_index"))]
    pub async fn connect_by_index(&self, ifindex: u32, request: ConnectRequest) -> Result<()> {
        // F1 fix — serialize the send + recv-loop pair so concurrent
        // tasks on a shared `Arc<Connection>` don't race on the recv
        // side. See connection.rs `Concurrency` docstring.
        let _guard = self.lock_request().await;
        let family_id = self.state().family_id;

        let mut builder = MessageBuilder::new(family_id, NLM_F_REQUEST | NLM_F_ACK);
        let genl_hdr = GenlMsgHdr::new(NL80211_CMD_CONNECT, NL80211_GENL_VERSION);
        builder.append(&genl_hdr);
        builder.append_attr_u32(NL80211_ATTR_IFINDEX, ifindex);
        builder.append_attr(NL80211_ATTR_SSID, &request.ssid);
        builder.append_attr_u32(NL80211_ATTR_AUTH_TYPE, request.auth_type as u32);

        if let Some(bssid) = request.bssid {
            builder.append_attr(NL80211_ATTR_MAC, &bssid);
        }
        if let Some(freq) = request.frequency {
            builder.append_attr_u32(NL80211_ATTR_WIPHY_FREQ, freq);
        }

        let seq = self.socket().next_seq();
        builder.set_seq(seq);
        builder.set_pid(self.socket().pid());

        let msg = builder.finish();
        self.socket().send(&msg).await?;

        self.wait_ack(seq).await
    }

    /// Disconnect from the current network.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "disconnect"))]
    pub async fn disconnect(&self, iface: &str) -> Result<()> {
        let ifindex = self.resolve_ifindex(iface).await?;
        self.disconnect_by_index(ifindex).await
    }

    /// Disconnect by interface index (namespace-safe).
    #[tracing::instrument(level = "debug", skip_all, fields(method = "disconnect_by_index"))]
    pub async fn disconnect_by_index(&self, ifindex: u32) -> Result<()> {
        // F1 fix — serialize the send + recv-loop pair so concurrent
        // tasks on a shared `Arc<Connection>` don't race on the recv
        // side. See connection.rs `Concurrency` docstring.
        let _guard = self.lock_request().await;
        let family_id = self.state().family_id;

        let mut builder = MessageBuilder::new(family_id, NLM_F_REQUEST | NLM_F_ACK);
        let genl_hdr = GenlMsgHdr::new(NL80211_CMD_DISCONNECT, NL80211_GENL_VERSION);
        builder.append(&genl_hdr);
        builder.append_attr_u32(NL80211_ATTR_IFINDEX, ifindex);
        builder.append_attr_u16(NL80211_ATTR_REASON_CODE, 3); // REASON_DEAUTH_LEAVING

        let seq = self.socket().next_seq();
        builder.set_seq(seq);
        builder.set_pid(self.socket().pid());

        let msg = builder.finish();
        self.socket().send(&msg).await?;

        self.wait_ack(seq).await
    }

    /// Set power save mode.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "set_power_save"))]
    pub async fn set_power_save(&self, iface: &str, enabled: bool) -> Result<()> {
        let ifindex = self.resolve_ifindex(iface).await?;
        // F1 fix — serialize the send + recv-loop pair so concurrent
        // tasks on a shared `Arc<Connection>` don't race on the recv
        // side. See connection.rs `Concurrency` docstring. Note: the
        // `resolve_ifindex` above runs its own send+recv flow under
        // the lock; we re-acquire here for the actual SET request.
        let _guard = self.lock_request().await;
        let family_id = self.state().family_id;

        let mut builder = MessageBuilder::new(family_id, NLM_F_REQUEST | NLM_F_ACK);
        let genl_hdr = GenlMsgHdr::new(NL80211_CMD_SET_POWER_SAVE, NL80211_GENL_VERSION);
        builder.append(&genl_hdr);
        builder.append_attr_u32(NL80211_ATTR_IFINDEX, ifindex);
        builder.append_attr_u32(
            NL80211_ATTR_PS_STATE,
            if enabled {
                PowerSaveState::Enabled as u32
            } else {
                PowerSaveState::Disabled as u32
            },
        );

        let seq = self.socket().next_seq();
        builder.set_seq(seq);
        builder.set_pid(self.socket().pid());

        let msg = builder.finish();
        self.socket().send(&msg).await?;

        self.wait_ack(seq).await
    }

    /// Get power save mode.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_power_save"))]
    pub async fn get_power_save(&self, iface: &str) -> Result<PowerSaveState> {
        let ifindex = self.resolve_ifindex(iface).await?;
        // F1 fix — serialize the send + recv-loop pair so concurrent
        // tasks on a shared `Arc<Connection>` don't race on the recv
        // side. See connection.rs `Concurrency` docstring. Note: the
        // `resolve_ifindex` above runs its own send+recv flow under
        // the lock; we re-acquire here for the actual GET request.
        let _guard = self.lock_request().await;
        let family_id = self.state().family_id;

        let mut builder = MessageBuilder::new(family_id, NLM_F_REQUEST);
        let genl_hdr = GenlMsgHdr::new(NL80211_CMD_GET_POWER_SAVE, NL80211_GENL_VERSION);
        builder.append(&genl_hdr);
        builder.append_attr_u32(NL80211_ATTR_IFINDEX, ifindex);

        let seq = self.socket().next_seq();
        builder.set_seq(seq);
        builder.set_pid(self.socket().pid());

        let msg = builder.finish();
        self.socket().send(&msg).await?;

        let responses = self.collect_dump_responses(seq).await?;

        for payload in &responses {
            if payload.len() < GENL_HDRLEN {
                continue;
            }
            for (attr_type, attr_payload) in AttrIter::new(&payload[GENL_HDRLEN..]) {
                if attr_type == NL80211_ATTR_PS_STATE && attr_payload.len() >= 4 {
                    let val = u32::from_ne_bytes(attr_payload[..4].try_into().unwrap());
                    return PowerSaveState::try_from(val);
                }
            }
        }

        Ok(PowerSaveState::Disabled)
    }

    // =========================================================================
    // PHY namespace movement
    // =========================================================================

    /// Move a wireless PHY to a different network namespace.
    ///
    /// The PHY is identified by its wiphy index (from `get_phys()`).
    /// The target namespace is specified by file descriptor (from
    /// [`namespace::open()`](crate::netlink::namespace::open) or
    /// [`NamespaceFd`](crate::netlink::namespace::NamespaceFd)).
    ///
    /// After the move, all interfaces on this PHY appear inside the
    /// target namespace. The PHY can only be in one namespace at a time.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use nlink::netlink::{Connection, Nl80211, namespace};
    ///
    /// let nl = Connection::<Nl80211>::new_async().await?;
    /// let phys = nl.get_phys().await?;
    /// let ns_fd = namespace::open("my-namespace")?;
    ///
    /// // Move phy0 to the namespace
    /// nl.set_wiphy_netns(phys[0].index, ns_fd.as_raw_fd()).await?;
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "set_wiphy_netns"))]
    pub async fn set_wiphy_netns(&self, wiphy: u32, netns_fd: i32) -> Result<()> {
        // F1 fix — serialize the send + recv-loop pair so concurrent
        // tasks on a shared `Arc<Connection>` don't race on the recv
        // side. See connection.rs `Concurrency` docstring.
        let _guard = self.lock_request().await;
        let family_id = self.state().family_id;

        let mut builder = MessageBuilder::new(family_id, NLM_F_REQUEST | NLM_F_ACK);
        let genl_hdr = GenlMsgHdr::new(NL80211_CMD_SET_WIPHY, NL80211_GENL_VERSION);
        builder.append(&genl_hdr);
        builder.append_attr_u32(NL80211_ATTR_WIPHY, wiphy);
        builder.append_attr_u32(NL80211_ATTR_NETNS_FD, netns_fd as u32);

        let seq = self.socket().next_seq();
        builder.set_seq(seq);
        builder.set_pid(self.socket().pid());

        let msg = builder.finish();
        self.socket().send(&msg).await?;

        self.wait_ack(seq)
            .await
            .map_err(|e| e.with_context("set_wiphy_netns"))
    }

    /// Move a wireless PHY to the network namespace of a given process.
    ///
    /// This is a convenience variant that uses the process PID instead of
    /// a namespace file descriptor.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "set_wiphy_netns_pid"))]
    pub async fn set_wiphy_netns_pid(&self, wiphy: u32, pid: u32) -> Result<()> {
        // F1 fix — serialize the send + recv-loop pair so concurrent
        // tasks on a shared `Arc<Connection>` don't race on the recv
        // side. See connection.rs `Concurrency` docstring.
        let _guard = self.lock_request().await;
        let family_id = self.state().family_id;

        let mut builder = MessageBuilder::new(family_id, NLM_F_REQUEST | NLM_F_ACK);
        let genl_hdr = GenlMsgHdr::new(NL80211_CMD_SET_WIPHY, NL80211_GENL_VERSION);
        builder.append(&genl_hdr);
        builder.append_attr_u32(NL80211_ATTR_WIPHY, wiphy);
        builder.append_attr_u32(NL80211_ATTR_PID, pid);

        let seq = self.socket().next_seq();
        builder.set_seq(seq);
        builder.set_pid(self.socket().pid());

        let msg = builder.finish();
        self.socket().send(&msg).await?;

        self.wait_ack(seq)
            .await
            .map_err(|e| e.with_context("set_wiphy_netns_pid"))
    }

    // =========================================================================
    // Internal helpers
    // =========================================================================

    /// Send a GENL dump request (no filter).
    async fn nl80211_dump(&self, cmd: u8) -> Result<Vec<Vec<u8>>> {
        // F1 fix — serialize the send + recv-loop pair so concurrent
        // tasks on a shared `Arc<Connection>` don't race on the recv
        // side. See connection.rs `Concurrency` docstring.
        let _guard = self.lock_request().await;
        let family_id = self.state().family_id;

        let mut builder = MessageBuilder::new(family_id, NLM_F_REQUEST | NLM_F_DUMP);
        let genl_hdr = GenlMsgHdr::new(cmd, NL80211_GENL_VERSION);
        builder.append(&genl_hdr);

        let seq = self.socket().next_seq();
        builder.set_seq(seq);
        builder.set_pid(self.socket().pid());

        let msg = builder.finish();
        self.socket().send(&msg).await?;

        self.collect_dump_responses(seq).await
    }

    /// Collect all responses from a dump request.
    async fn collect_dump_responses(&self, seq: u32) -> Result<Vec<Vec<u8>>> {
        // Plan 172 — wrap the recv loop in the Connection-level
        // operation timeout (Plan 171 default: 30s).
        self.with_timeout(async {
            let mut results = Vec::new();

            loop {
                let data: Vec<u8> = self.socket().recv_msg().await?;
                let mut done = false;

                for msg_result in MessageIter::new(&data) {
                    let (header, payload) = msg_result?;

                    if header.nlmsg_seq != seq {
                        continue;
                    }

                    if header.is_error() {
                        let err = NlMsgError::from_bytes(payload)?;
                        if !err.is_ack() {
                            return Err(err.into_error(payload));
                        }
                        continue;
                    }

                    if header.is_done() {
                        done = true;
                        break;
                    }

                    results.push(payload.to_vec());
                }

                if done {
                    break;
                }
            }

            Ok(results)
        })
        .await
    }

    /// Wait for an ACK response.
    async fn wait_ack(&self, seq: u32) -> Result<()> {
        // Plan 172 — wrap the recv loop in the Connection-level
        // operation timeout (Plan 171 default: 30s).
        self.with_timeout(async {
            loop {
                let data: Vec<u8> = self.socket().recv_msg().await?;

                for msg_result in MessageIter::new(&data) {
                    let (header, payload) = msg_result?;

                    if header.nlmsg_seq != seq {
                        continue;
                    }

                    if header.is_error() {
                        let err = NlMsgError::from_bytes(payload)?;
                        if err.is_ack() {
                            return Ok(());
                        }
                        return Err(err.into_error(payload));
                    }

                    if header.is_done() {
                        return Ok(());
                    }
                }
            }
        })
        .await
    }

    /// Resolve interface name to ifindex via dump.
    async fn resolve_ifindex(&self, name: &str) -> Result<u32> {
        let ifaces = self.get_interfaces().await?;
        ifaces
            .iter()
            .find(|i| i.name.as_deref() == Some(name))
            .map(|i| i.ifindex)
            .ok_or_else(|| Error::InvalidAttribute(format!("interface not found: {name}")))
    }
}

// =============================================================================
// Attribute Parsing
// =============================================================================

fn parse_interface(data: &[u8]) -> WirelessInterface {
    let mut iface = WirelessInterface {
        ifindex: 0,
        name: None,
        iftype: InterfaceType::Unspecified,
        wiphy: 0,
        mac: None,
        frequency: None,
        ssid: None,
        signal_dbm: None,
        tx_bitrate: None,
        generation: None,
    };

    for (attr_type, payload) in AttrIter::new(data) {
        match attr_type {
            NL80211_ATTR_IFINDEX if payload.len() >= 4 => {
                iface.ifindex = u32::from_ne_bytes(payload[..4].try_into().unwrap());
            }
            NL80211_ATTR_IFNAME => {
                iface.name = attr_str(payload);
            }
            NL80211_ATTR_IFTYPE if payload.len() >= 4 => {
                let val = u32::from_ne_bytes(payload[..4].try_into().unwrap());
                iface.iftype = InterfaceType::try_from(val).unwrap_or(InterfaceType::Unspecified);
            }
            NL80211_ATTR_WIPHY if payload.len() >= 4 => {
                iface.wiphy = u32::from_ne_bytes(payload[..4].try_into().unwrap());
            }
            NL80211_ATTR_MAC if payload.len() >= 6 => {
                let mut mac = [0u8; 6];
                mac.copy_from_slice(&payload[..6]);
                iface.mac = Some(mac);
            }
            NL80211_ATTR_WIPHY_FREQ if payload.len() >= 4 => {
                iface.frequency = Some(u32::from_ne_bytes(payload[..4].try_into().unwrap()));
            }
            NL80211_ATTR_SSID => {
                iface.ssid = std::str::from_utf8(payload).ok().map(String::from);
            }
            NL80211_ATTR_GENERATION if payload.len() >= 4 => {
                iface.generation = Some(u32::from_ne_bytes(payload[..4].try_into().unwrap()));
            }
            _ => {}
        }
    }

    iface
}

fn parse_bss(data: &[u8]) -> ScanResult {
    let mut result = ScanResult {
        bssid: [0; 6],
        frequency: 0,
        ssid: None,
        signal_mbm: 0,
        capability: 0,
        beacon_interval: 0,
        seen_ms_ago: 0,
        tsf: None,
        status: None,
        information_elements: Vec::new(),
    };

    for (attr_type, payload) in AttrIter::new(data) {
        match attr_type {
            NL80211_BSS_BSSID if payload.len() >= 6 => {
                result.bssid.copy_from_slice(&payload[..6]);
            }
            NL80211_BSS_FREQUENCY if payload.len() >= 4 => {
                result.frequency = u32::from_ne_bytes(payload[..4].try_into().unwrap());
            }
            NL80211_BSS_TSF if payload.len() >= 8 => {
                result.tsf = Some(u64::from_ne_bytes(payload[..8].try_into().unwrap()));
            }
            NL80211_BSS_BEACON_INTERVAL if payload.len() >= 2 => {
                result.beacon_interval = u16::from_ne_bytes(payload[..2].try_into().unwrap());
            }
            NL80211_BSS_CAPABILITY if payload.len() >= 2 => {
                result.capability = u16::from_ne_bytes(payload[..2].try_into().unwrap());
            }
            NL80211_BSS_INFORMATION_ELEMENTS => {
                result.information_elements = payload.to_vec();
                // Walk the IE chain to find the SSID (element-id 0).
                // Plan 215 M13 — pre-fix assumed SSID is the FIRST IE
                // and returned None for any BSS whose beacon
                // prepended a vendor-specific IE (id=221) before the
                // SSID. Now walks the chain per 802.11 spec.
                result.ssid = parse_ssid_from_ies(payload);
            }
            NL80211_BSS_SIGNAL_MBM if payload.len() >= 4 => {
                result.signal_mbm = i32::from_ne_bytes(payload[..4].try_into().unwrap());
            }
            NL80211_BSS_STATUS if payload.len() >= 4 => {
                let val = u32::from_ne_bytes(payload[..4].try_into().unwrap());
                result.status = BssStatus::try_from(val).ok();
            }
            NL80211_BSS_SEEN_MS_AGO if payload.len() >= 4 => {
                result.seen_ms_ago = u32::from_ne_bytes(payload[..4].try_into().unwrap());
            }
            _ => {}
        }
    }

    result
}

/// Walk the 802.11 information elements (TLV chain) and extract the
/// SSID (element-id 0). The SSID IE may not be the first element —
/// vendor-specific IEs (id=221) are sometimes prepended.
///
/// Plan 215 M13 (0.19). Returns `None` if no SSID IE is found or
/// the chain is malformed. UTF-8 decoding is lossy to match how
/// `wpa_supplicant` and other tools handle non-printable SSIDs.
fn parse_ssid_from_ies(ies: &[u8]) -> Option<String> {
    let mut offset = 0;
    while offset + 2 <= ies.len() {
        let id = ies[offset];
        let len = ies[offset + 1] as usize;
        if offset + 2 + len > ies.len() {
            // Truncated IE — bail rather than slice-panic.
            return None;
        }
        if id == 0 {
            return Some(String::from_utf8_lossy(&ies[offset + 2..offset + 2 + len]).into_owned());
        }
        offset += 2 + len;
    }
    None
}

fn parse_station(data: &[u8]) -> StationInfo {
    let mut station = StationInfo {
        mac: [0; 6],
        ifindex: 0,
        inactive_time_ms: None,
        rx_bytes: None,
        tx_bytes: None,
        signal_dbm: None,
        signal_avg_dbm: None,
        tx_bitrate: None,
        rx_bitrate: None,
        connected_time_secs: None,
    };

    for (attr_type, payload) in AttrIter::new(data) {
        match attr_type {
            NL80211_ATTR_MAC if payload.len() >= 6 => {
                station.mac.copy_from_slice(&payload[..6]);
            }
            NL80211_ATTR_IFINDEX if payload.len() >= 4 => {
                station.ifindex = u32::from_ne_bytes(payload[..4].try_into().unwrap());
            }
            NL80211_ATTR_STA_INFO => {
                parse_station_info_nested(payload, &mut station);
            }
            _ => {}
        }
    }

    station
}

fn parse_station_info_nested(data: &[u8], station: &mut StationInfo) {
    for (attr_type, payload) in AttrIter::new(data) {
        match attr_type {
            NL80211_STA_INFO_INACTIVE_TIME if payload.len() >= 4 => {
                station.inactive_time_ms =
                    Some(u32::from_ne_bytes(payload[..4].try_into().unwrap()));
            }
            NL80211_STA_INFO_RX_BYTES if payload.len() >= 4 && station.rx_bytes.is_none() => {
                station.rx_bytes =
                    Some(u32::from_ne_bytes(payload[..4].try_into().unwrap()) as u64);
            }
            NL80211_STA_INFO_TX_BYTES if payload.len() >= 4 && station.tx_bytes.is_none() => {
                station.tx_bytes =
                    Some(u32::from_ne_bytes(payload[..4].try_into().unwrap()) as u64);
            }
            NL80211_STA_INFO_RX_BYTES64 if payload.len() >= 8 => {
                station.rx_bytes = Some(u64::from_ne_bytes(payload[..8].try_into().unwrap()));
            }
            NL80211_STA_INFO_TX_BYTES64 if payload.len() >= 8 => {
                station.tx_bytes = Some(u64::from_ne_bytes(payload[..8].try_into().unwrap()));
            }
            NL80211_STA_INFO_SIGNAL if !payload.is_empty() => {
                station.signal_dbm = Some(payload[0] as i8);
            }
            NL80211_STA_INFO_SIGNAL_AVG if !payload.is_empty() => {
                station.signal_avg_dbm = Some(payload[0] as i8);
            }
            NL80211_STA_INFO_TX_BITRATE => {
                station.tx_bitrate = Some(parse_bitrate_info(payload));
            }
            NL80211_STA_INFO_RX_BITRATE => {
                station.rx_bitrate = Some(parse_bitrate_info(payload));
            }
            NL80211_STA_INFO_CONNECTED_TIME if payload.len() >= 4 => {
                station.connected_time_secs =
                    Some(u32::from_ne_bytes(payload[..4].try_into().unwrap()));
            }
            _ => {}
        }
    }
}

fn parse_bitrate_info(data: &[u8]) -> BitrateInfo {
    let mut info = BitrateInfo {
        bitrate_100kbps: None,
        mcs: None,
        width: None,
        short_gi: false,
    };

    for (attr_type, payload) in AttrIter::new(data) {
        match attr_type {
            NL80211_RATE_INFO_BITRATE if payload.len() >= 2 && info.bitrate_100kbps.is_none() => {
                info.bitrate_100kbps =
                    Some(u16::from_ne_bytes(payload[..2].try_into().unwrap()) as u32);
            }
            NL80211_RATE_INFO_BITRATE32 if payload.len() >= 4 => {
                info.bitrate_100kbps = Some(u32::from_ne_bytes(payload[..4].try_into().unwrap()));
            }
            NL80211_RATE_INFO_MCS | NL80211_RATE_INFO_VHT_MCS if !payload.is_empty() => {
                info.mcs = Some(payload[0]);
            }
            NL80211_RATE_INFO_SHORT_GI => {
                info.short_gi = true; // Flag attribute
            }
            NL80211_RATE_INFO_40_MHZ_WIDTH => {
                info.width = Some(ChannelWidth::Width40);
            }
            NL80211_RATE_INFO_80_MHZ_WIDTH => {
                info.width = Some(ChannelWidth::Width80);
            }
            NL80211_RATE_INFO_80P80_MHZ_WIDTH => {
                info.width = Some(ChannelWidth::Width80P80);
            }
            NL80211_RATE_INFO_160_MHZ_WIDTH => {
                info.width = Some(ChannelWidth::Width160);
            }
            _ => {}
        }
    }

    info
}

fn parse_phy(data: &[u8]) -> PhyInfo {
    let mut phy = PhyInfo {
        index: 0,
        name: String::new(),
        bands: Vec::new(),
        supported_iftypes: Vec::new(),
        max_scan_ssids: None,
    };

    for (attr_type, payload) in AttrIter::new(data) {
        match attr_type {
            NL80211_ATTR_WIPHY if payload.len() >= 4 => {
                phy.index = u32::from_ne_bytes(payload[..4].try_into().unwrap());
            }
            NL80211_ATTR_WIPHY_NAME => {
                phy.name = attr_str(payload).unwrap_or_default();
            }
            NL80211_ATTR_WIPHY_BANDS => {
                for (_idx, band_data) in AttrIter::new(payload) {
                    phy.bands.push(parse_band(band_data));
                }
            }
            NL80211_ATTR_SUPPORTED_IFTYPES => {
                for (_idx, _iftype_data) in AttrIter::new(payload) {
                    // The attr index itself is the iftype value
                    if let Ok(iftype) = InterfaceType::try_from(_idx as u32) {
                        phy.supported_iftypes.push(iftype);
                    }
                }
            }
            NL80211_ATTR_MAX_SCAN_SSIDS if !payload.is_empty() => {
                phy.max_scan_ssids = Some(payload[0]);
            }
            _ => {}
        }
    }

    phy
}

fn parse_band(data: &[u8]) -> Band {
    let mut band = Band {
        frequencies: Vec::new(),
        rates: Vec::new(),
        ht_capa: None,
        vht_capa: None,
    };

    for (attr_type, payload) in AttrIter::new(data) {
        match attr_type {
            NL80211_BAND_ATTR_FREQS => {
                for (_idx, freq_data) in AttrIter::new(payload) {
                    band.frequencies.push(parse_frequency(freq_data));
                }
            }
            NL80211_BAND_ATTR_RATES => {
                for (_idx, rate_data) in AttrIter::new(payload) {
                    for (rate_attr, rate_payload) in AttrIter::new(rate_data) {
                        if rate_attr == NL80211_BITRATE_ATTR_RATE && rate_payload.len() >= 4 {
                            band.rates
                                .push(u32::from_ne_bytes(rate_payload[..4].try_into().unwrap()));
                        }
                    }
                }
            }
            NL80211_BAND_ATTR_HT_CAPA if payload.len() >= 2 => {
                band.ht_capa = Some(u16::from_ne_bytes(payload[..2].try_into().unwrap()));
            }
            NL80211_BAND_ATTR_VHT_CAPA if payload.len() >= 4 => {
                band.vht_capa = Some(u32::from_ne_bytes(payload[..4].try_into().unwrap()));
            }
            _ => {}
        }
    }

    band
}

fn parse_frequency(data: &[u8]) -> Frequency {
    let mut freq = Frequency {
        freq: 0,
        max_power_mbm: 0,
        disabled: false,
        radar: false,
        no_ir: false,
    };

    for (attr_type, payload) in AttrIter::new(data) {
        match attr_type {
            NL80211_FREQUENCY_ATTR_FREQ if payload.len() >= 4 => {
                freq.freq = u32::from_ne_bytes(payload[..4].try_into().unwrap());
            }
            NL80211_FREQUENCY_ATTR_DISABLED => {
                freq.disabled = true; // Flag attribute
            }
            NL80211_FREQUENCY_ATTR_NO_IR => {
                freq.no_ir = true;
            }
            NL80211_FREQUENCY_ATTR_RADAR => {
                freq.radar = true;
            }
            NL80211_FREQUENCY_ATTR_MAX_TX_POWER if payload.len() >= 4 => {
                freq.max_power_mbm = u32::from_ne_bytes(payload[..4].try_into().unwrap());
            }
            _ => {}
        }
    }

    freq
}

fn parse_regulatory(data: &[u8], domain: &mut RegulatoryDomain) {
    for (attr_type, payload) in AttrIter::new(data) {
        match attr_type {
            NL80211_ATTR_REG_ALPHA2 => {
                domain.country = attr_str(payload).unwrap_or_default();
            }
            NL80211_ATTR_REG_RULES => {
                for (_idx, rule_data) in AttrIter::new(payload) {
                    domain.rules.push(parse_reg_rule(rule_data));
                }
            }
            _ => {}
        }
    }
}

fn parse_reg_rule(data: &[u8]) -> RegulatoryRule {
    let mut rule = RegulatoryRule {
        start_freq_khz: 0,
        end_freq_khz: 0,
        max_bandwidth_khz: 0,
        max_antenna_gain_mbi: 0,
        max_eirp_mbm: 0,
        flags: 0,
    };

    for (attr_type, payload) in AttrIter::new(data) {
        if payload.len() < 4 {
            continue;
        }
        let val = u32::from_ne_bytes(payload[..4].try_into().unwrap());
        match attr_type {
            NL80211_ATTR_REG_RULE_FLAGS => rule.flags = val,
            NL80211_ATTR_FREQ_RANGE_START => rule.start_freq_khz = val,
            NL80211_ATTR_FREQ_RANGE_END => rule.end_freq_khz = val,
            NL80211_ATTR_FREQ_RANGE_MAX_BW => rule.max_bandwidth_khz = val,
            NL80211_ATTR_POWER_RULE_MAX_ANT_GAIN => rule.max_antenna_gain_mbi = val,
            NL80211_ATTR_POWER_RULE_MAX_EIRP => rule.max_eirp_mbm = val,
            _ => {}
        }
    }

    rule
}

/// Extract a null-terminated string from attribute payload.
fn attr_str(payload: &[u8]) -> Option<String> {
    if payload.is_empty() {
        return None;
    }
    let s = std::str::from_utf8(payload)
        .unwrap_or("")
        .trim_end_matches('\0');
    if s.is_empty() {
        None
    } else {
        Some(s.to_string())
    }
}

#[cfg(test)]
mod ssid_walker_tests {
    use super::parse_ssid_from_ies;

    #[test]
    fn ssid_extracted_from_first_ie() {
        // IE 0: id=0, len=4, "home"
        let ies = [0u8, 4, b'h', b'o', b'm', b'e'];
        assert_eq!(parse_ssid_from_ies(&ies).as_deref(), Some("home"));
    }

    #[test]
    fn ssid_extracted_after_vendor_specific_ie() {
        // Plan 215 M13 regression — vendor IE (id=221) prepended.
        let ies = [
            221, 3, 0xAA, 0xBB, 0xCC, // vendor IE
            0, 4, b'h', b'o', b'm', b'e', // SSID IE
        ];
        assert_eq!(parse_ssid_from_ies(&ies).as_deref(), Some("home"));
    }

    #[test]
    fn ssid_missing_returns_none_not_garbage() {
        let ies = [221u8, 3, 0xAA, 0xBB, 0xCC];
        assert_eq!(parse_ssid_from_ies(&ies), None);
    }

    #[test]
    fn truncated_ie_terminates_without_panic() {
        // IE claims 100 bytes of payload but only 3 follow.
        let ies = [0u8, 100, 1, 2, 3];
        assert_eq!(parse_ssid_from_ies(&ies), None);
    }

    #[test]
    fn ssid_with_non_utf8_decoded_lossily() {
        let ies = [0u8, 3, 0xFF, b'a', 0xFE];
        // Lossy decode produces replacement characters; assert
        // we get Some(_) (not None) and the SSID byte count is
        // preserved.
        let ssid = parse_ssid_from_ies(&ies).expect("lossy ssid");
        assert!(ssid.contains('a'));
    }

    #[test]
    fn empty_ies_returns_none() {
        assert_eq!(parse_ssid_from_ies(&[]), None);
    }
}

