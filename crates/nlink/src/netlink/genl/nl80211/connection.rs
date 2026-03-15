//! nl80211 connection implementation for `Connection<Nl80211>`.

use super::types::*;
use super::*;
use crate::netlink::attr::AttrIter;
use crate::netlink::builder::MessageBuilder;
use crate::netlink::connection::Connection;
use crate::netlink::error::{Error, Result};
use crate::netlink::genl::{
    CtrlAttr, CtrlCmd, GENL_HDRLEN, GENL_ID_CTRL, GenlMsgHdr,
};
use crate::netlink::message::{MessageIter, NLM_F_ACK, NLM_F_DUMP, NLM_F_REQUEST, NlMsgError};
use crate::netlink::protocol::{Nl80211, ProtocolState};
use crate::netlink::socket::NetlinkSocket;

impl Connection<Nl80211> {
    /// Create a new nl80211 connection.
    ///
    /// Resolves the "nl80211" GENL family ID during initialization.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use nlink::netlink::{Connection, Nl80211};
    ///
    /// let conn = Connection::<Nl80211>::new_async().await?;
    /// let ifaces = conn.get_interfaces().await?;
    /// ```
    pub async fn new_async() -> Result<Self> {
        let socket = NetlinkSocket::new(Nl80211::PROTOCOL)?;
        let family_id = resolve_nl80211_family(&socket).await?;
        let state = Nl80211 { family_id };
        Ok(Self::from_parts(socket, state))
    }

    /// Get the nl80211 family ID.
    pub fn family_id(&self) -> u16 {
        self.state().family_id
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
    pub async fn get_interface(&self, name: &str) -> Result<Option<WirelessInterface>> {
        let ifaces = self.get_interfaces().await?;
        Ok(ifaces.into_iter().find(|i| i.name.as_deref() == Some(name)))
    }

    /// Get a specific wireless interface by index.
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
    pub async fn trigger_scan(&self, iface: &str, request: &ScanRequest) -> Result<()> {
        let ifindex = self.resolve_ifindex(iface).await?;
        self.trigger_scan_by_index(ifindex, request).await
    }

    /// Trigger a scan by interface index (namespace-safe).
    pub async fn trigger_scan_by_index(
        &self,
        ifindex: u32,
        request: &ScanRequest,
    ) -> Result<()> {
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
    pub async fn get_scan_results(&self, iface: &str) -> Result<Vec<ScanResult>> {
        let ifindex = self.resolve_ifindex(iface).await?;
        self.get_scan_results_by_index(ifindex).await
    }

    /// Get scan results by interface index (namespace-safe).
    pub async fn get_scan_results_by_index(&self, ifindex: u32) -> Result<Vec<ScanResult>> {
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
    pub async fn get_station(&self, iface: &str) -> Result<Option<StationInfo>> {
        let stations = self.get_stations(iface).await?;
        Ok(stations.into_iter().next())
    }

    /// Get station info by interface index (namespace-safe).
    pub async fn get_station_by_index(&self, ifindex: u32) -> Result<Option<StationInfo>> {
        let stations = self.get_stations_by_index(ifindex).await?;
        Ok(stations.into_iter().next())
    }

    /// List all stations (useful in AP mode).
    pub async fn get_stations(&self, iface: &str) -> Result<Vec<StationInfo>> {
        let ifindex = self.resolve_ifindex(iface).await?;
        self.get_stations_by_index(ifindex).await
    }

    /// List all stations by interface index.
    pub async fn get_stations_by_index(&self, ifindex: u32) -> Result<Vec<StationInfo>> {
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
    pub async fn get_phy(&self, wiphy: u32) -> Result<Option<PhyInfo>> {
        let phys = self.get_phys().await?;
        Ok(phys.into_iter().find(|p| p.index == wiphy))
    }

    // =========================================================================
    // Regulatory
    // =========================================================================

    /// Get the current regulatory domain.
    pub async fn get_regulatory(&self) -> Result<RegulatoryDomain> {
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
    pub async fn connect(&self, iface: &str, request: ConnectRequest) -> Result<()> {
        let ifindex = self.resolve_ifindex(iface).await?;
        self.connect_by_index(ifindex, request).await
    }

    /// Connect by interface index (namespace-safe).
    pub async fn connect_by_index(
        &self,
        ifindex: u32,
        request: ConnectRequest,
    ) -> Result<()> {
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
    pub async fn disconnect(&self, iface: &str) -> Result<()> {
        let ifindex = self.resolve_ifindex(iface).await?;
        self.disconnect_by_index(ifindex).await
    }

    /// Disconnect by interface index (namespace-safe).
    pub async fn disconnect_by_index(&self, ifindex: u32) -> Result<()> {
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
    pub async fn set_power_save(&self, iface: &str, enabled: bool) -> Result<()> {
        let ifindex = self.resolve_ifindex(iface).await?;
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
    pub async fn get_power_save(&self, iface: &str) -> Result<PowerSaveState> {
        let ifindex = self.resolve_ifindex(iface).await?;
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
                if attr_type == NL80211_ATTR_PS_STATE {
                    if attr_payload.len() >= 4 {
                        let val = u32::from_ne_bytes(attr_payload[..4].try_into().unwrap());
                        return PowerSaveState::try_from(val);
                    }
                }
            }
        }

        Ok(PowerSaveState::Disabled)
    }

    // =========================================================================
    // Internal helpers
    // =========================================================================

    /// Send a GENL dump request (no filter).
    async fn nl80211_dump(&self, cmd: u8) -> Result<Vec<Vec<u8>>> {
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
                        return Err(Error::from_errno(err.error));
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
    }

    /// Wait for an ACK response.
    async fn wait_ack(&self, seq: u32) -> Result<()> {
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
                    return Err(Error::from_errno(err.error));
                }

                if header.is_done() {
                    return Ok(());
                }
            }
        }
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
            NL80211_ATTR_IFINDEX => {
                if payload.len() >= 4 {
                    iface.ifindex = u32::from_ne_bytes(payload[..4].try_into().unwrap());
                }
            }
            NL80211_ATTR_IFNAME => {
                iface.name = attr_str(payload);
            }
            NL80211_ATTR_IFTYPE => {
                if payload.len() >= 4 {
                    let val = u32::from_ne_bytes(payload[..4].try_into().unwrap());
                    iface.iftype = InterfaceType::try_from(val).unwrap_or(InterfaceType::Unspecified);
                }
            }
            NL80211_ATTR_WIPHY => {
                if payload.len() >= 4 {
                    iface.wiphy = u32::from_ne_bytes(payload[..4].try_into().unwrap());
                }
            }
            NL80211_ATTR_MAC => {
                if payload.len() >= 6 {
                    let mut mac = [0u8; 6];
                    mac.copy_from_slice(&payload[..6]);
                    iface.mac = Some(mac);
                }
            }
            NL80211_ATTR_WIPHY_FREQ => {
                if payload.len() >= 4 {
                    iface.frequency =
                        Some(u32::from_ne_bytes(payload[..4].try_into().unwrap()));
                }
            }
            NL80211_ATTR_SSID => {
                iface.ssid = std::str::from_utf8(payload).ok().map(String::from);
            }
            NL80211_ATTR_GENERATION => {
                if payload.len() >= 4 {
                    iface.generation =
                        Some(u32::from_ne_bytes(payload[..4].try_into().unwrap()));
                }
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
            NL80211_BSS_BSSID => {
                if payload.len() >= 6 {
                    result.bssid.copy_from_slice(&payload[..6]);
                }
            }
            NL80211_BSS_FREQUENCY => {
                if payload.len() >= 4 {
                    result.frequency = u32::from_ne_bytes(payload[..4].try_into().unwrap());
                }
            }
            NL80211_BSS_TSF => {
                if payload.len() >= 8 {
                    result.tsf =
                        Some(u64::from_ne_bytes(payload[..8].try_into().unwrap()));
                }
            }
            NL80211_BSS_BEACON_INTERVAL => {
                if payload.len() >= 2 {
                    result.beacon_interval =
                        u16::from_ne_bytes(payload[..2].try_into().unwrap());
                }
            }
            NL80211_BSS_CAPABILITY => {
                if payload.len() >= 2 {
                    result.capability = u16::from_ne_bytes(payload[..2].try_into().unwrap());
                }
            }
            NL80211_BSS_INFORMATION_ELEMENTS => {
                result.information_elements = payload.to_vec();
                // Parse SSID from IE (type 0, first element)
                if payload.len() >= 2 && payload[0] == 0 {
                    let len = payload[1] as usize;
                    if payload.len() >= 2 + len && len > 0 {
                        result.ssid = std::str::from_utf8(&payload[2..2 + len])
                            .ok()
                            .map(String::from);
                    }
                }
            }
            NL80211_BSS_SIGNAL_MBM => {
                if payload.len() >= 4 {
                    result.signal_mbm = i32::from_ne_bytes(payload[..4].try_into().unwrap());
                }
            }
            NL80211_BSS_STATUS => {
                if payload.len() >= 4 {
                    let val = u32::from_ne_bytes(payload[..4].try_into().unwrap());
                    result.status = BssStatus::try_from(val).ok();
                }
            }
            NL80211_BSS_SEEN_MS_AGO => {
                if payload.len() >= 4 {
                    result.seen_ms_ago =
                        u32::from_ne_bytes(payload[..4].try_into().unwrap());
                }
            }
            _ => {}
        }
    }

    result
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
            NL80211_ATTR_MAC => {
                if payload.len() >= 6 {
                    station.mac.copy_from_slice(&payload[..6]);
                }
            }
            NL80211_ATTR_IFINDEX => {
                if payload.len() >= 4 {
                    station.ifindex = u32::from_ne_bytes(payload[..4].try_into().unwrap());
                }
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
            NL80211_STA_INFO_INACTIVE_TIME => {
                if payload.len() >= 4 {
                    station.inactive_time_ms =
                        Some(u32::from_ne_bytes(payload[..4].try_into().unwrap()));
                }
            }
            NL80211_STA_INFO_RX_BYTES => {
                if payload.len() >= 4 && station.rx_bytes.is_none() {
                    station.rx_bytes = Some(
                        u32::from_ne_bytes(payload[..4].try_into().unwrap()) as u64,
                    );
                }
            }
            NL80211_STA_INFO_TX_BYTES => {
                if payload.len() >= 4 && station.tx_bytes.is_none() {
                    station.tx_bytes = Some(
                        u32::from_ne_bytes(payload[..4].try_into().unwrap()) as u64,
                    );
                }
            }
            NL80211_STA_INFO_RX_BYTES64 => {
                if payload.len() >= 8 {
                    station.rx_bytes =
                        Some(u64::from_ne_bytes(payload[..8].try_into().unwrap()));
                }
            }
            NL80211_STA_INFO_TX_BYTES64 => {
                if payload.len() >= 8 {
                    station.tx_bytes =
                        Some(u64::from_ne_bytes(payload[..8].try_into().unwrap()));
                }
            }
            NL80211_STA_INFO_SIGNAL => {
                if !payload.is_empty() {
                    station.signal_dbm = Some(payload[0] as i8);
                }
            }
            NL80211_STA_INFO_SIGNAL_AVG => {
                if !payload.is_empty() {
                    station.signal_avg_dbm = Some(payload[0] as i8);
                }
            }
            NL80211_STA_INFO_TX_BITRATE => {
                station.tx_bitrate = Some(parse_bitrate_info(payload));
            }
            NL80211_STA_INFO_RX_BITRATE => {
                station.rx_bitrate = Some(parse_bitrate_info(payload));
            }
            NL80211_STA_INFO_CONNECTED_TIME => {
                if payload.len() >= 4 {
                    station.connected_time_secs =
                        Some(u32::from_ne_bytes(payload[..4].try_into().unwrap()));
                }
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
            NL80211_RATE_INFO_BITRATE => {
                if payload.len() >= 2 && info.bitrate_100kbps.is_none() {
                    info.bitrate_100kbps =
                        Some(u16::from_ne_bytes(payload[..2].try_into().unwrap()) as u32);
                }
            }
            NL80211_RATE_INFO_BITRATE32 => {
                if payload.len() >= 4 {
                    info.bitrate_100kbps =
                        Some(u32::from_ne_bytes(payload[..4].try_into().unwrap()));
                }
            }
            NL80211_RATE_INFO_MCS | NL80211_RATE_INFO_VHT_MCS => {
                if !payload.is_empty() {
                    info.mcs = Some(payload[0]);
                }
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
            NL80211_ATTR_WIPHY => {
                if payload.len() >= 4 {
                    phy.index = u32::from_ne_bytes(payload[..4].try_into().unwrap());
                }
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
            NL80211_ATTR_MAX_SCAN_SSIDS => {
                if !payload.is_empty() {
                    phy.max_scan_ssids = Some(payload[0]);
                }
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
                            band.rates.push(u32::from_ne_bytes(
                                rate_payload[..4].try_into().unwrap(),
                            ));
                        }
                    }
                }
            }
            NL80211_BAND_ATTR_HT_CAPA => {
                if payload.len() >= 2 {
                    band.ht_capa =
                        Some(u16::from_ne_bytes(payload[..2].try_into().unwrap()));
                }
            }
            NL80211_BAND_ATTR_VHT_CAPA => {
                if payload.len() >= 4 {
                    band.vht_capa =
                        Some(u32::from_ne_bytes(payload[..4].try_into().unwrap()));
                }
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
            NL80211_FREQUENCY_ATTR_FREQ => {
                if payload.len() >= 4 {
                    freq.freq = u32::from_ne_bytes(payload[..4].try_into().unwrap());
                }
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
            NL80211_FREQUENCY_ATTR_MAX_TX_POWER => {
                if payload.len() >= 4 {
                    freq.max_power_mbm =
                        u32::from_ne_bytes(payload[..4].try_into().unwrap());
                }
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

/// Resolve the nl80211 GENL family ID.
async fn resolve_nl80211_family(socket: &NetlinkSocket) -> Result<u16> {
    let mut builder = MessageBuilder::new(GENL_ID_CTRL, NLM_F_REQUEST | NLM_F_ACK);
    let genl_hdr = GenlMsgHdr::new(CtrlCmd::GetFamily as u8, 1);
    builder.append(&genl_hdr);
    builder.append_attr_str(CtrlAttr::FamilyName as u16, NL80211_GENL_NAME);

    let seq = socket.next_seq();
    builder.set_seq(seq);
    builder.set_pid(socket.pid());

    let msg = builder.finish();
    socket.send(&msg).await?;

    let response: Vec<u8> = socket.recv_msg().await?;
    let mut family_id: Option<u16> = None;

    for result in MessageIter::new(&response) {
        let (header, payload) = result?;

        if header.nlmsg_seq != seq {
            continue;
        }

        if header.is_error() {
            let err = NlMsgError::from_bytes(payload)?;
            if !err.is_ack() {
                if err.error == -libc::ENOENT {
                    return Err(Error::FamilyNotFound {
                        name: NL80211_GENL_NAME.to_string(),
                    });
                }
                return Err(Error::from_errno(err.error));
            }
            continue;
        }

        if header.is_done() {
            continue;
        }

        if payload.len() < GENL_HDRLEN {
            return Err(Error::InvalidMessage("GENL header too short".into()));
        }

        let attrs_data = &payload[GENL_HDRLEN..];
        for (attr_type, attr_payload) in AttrIter::new(attrs_data) {
            if attr_type == CtrlAttr::FamilyId as u16 && attr_payload.len() >= 2 {
                family_id = Some(u16::from_ne_bytes(attr_payload[..2].try_into().unwrap()));
            }
        }
    }

    family_id.ok_or_else(|| Error::FamilyNotFound {
        name: NL80211_GENL_NAME.to_string(),
    })
}
