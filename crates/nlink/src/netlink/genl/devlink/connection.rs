//! Devlink connection implementation for `Connection<Devlink>`.

use super::types::*;
use super::*;
use crate::netlink::attr::AttrIter;
use crate::netlink::builder::MessageBuilder;
use crate::netlink::connection::Connection;
use crate::netlink::error::{Error, Result};
use crate::netlink::genl::{
    CtrlAttr, CtrlAttrMcastGrp, CtrlCmd, GENL_HDRLEN, GENL_ID_CTRL, GenlMsgHdr,
};
use crate::netlink::message::{MessageIter, NLM_F_ACK, NLM_F_DUMP, NLM_F_REQUEST, NlMsgError};
use crate::netlink::protocol::{Devlink, ProtocolState};
use crate::netlink::socket::NetlinkSocket;

impl Connection<Devlink> {
    /// Create a new devlink connection.
    ///
    /// Resolves the "devlink" GENL family ID during initialization.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use nlink::netlink::{Connection, Devlink};
    ///
    /// let conn = Connection::<Devlink>::new_async().await?;
    /// let devices = conn.get_devices().await?;
    /// ```
    pub async fn new_async() -> Result<Self> {
        let socket = NetlinkSocket::new(Devlink::PROTOCOL)?;
        let (family_id, monitor_group_id) = resolve_devlink_family(&socket).await?;
        let state = Devlink {
            family_id,
            monitor_group_id,
        };
        Ok(Self::from_parts(socket, state))
    }

    /// Get the devlink family ID.
    pub fn family_id(&self) -> u16 {
        self.state().family_id
    }

    /// Subscribe to devlink multicast events.
    ///
    /// After subscribing, use `events()` or `into_events()` to receive events.
    pub fn subscribe(&mut self) -> Result<()> {
        let group_id = self
            .state()
            .monitor_group_id
            .ok_or_else(|| Error::InvalidMessage("devlink monitor group not available".into()))?;
        self.socket_mut().add_membership(group_id)?;
        Ok(())
    }

    // =========================================================================
    // Device Queries
    // =========================================================================

    /// List all devlink devices.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let devices = conn.get_devices().await?;
    /// for dev in &devices {
    ///     println!("{}", dev.path());
    /// }
    /// ```
    pub async fn get_devices(&self) -> Result<Vec<DevlinkDevice>> {
        let responses = self.devlink_dump(DEVLINK_CMD_GET).await?;
        let mut devices = Vec::new();

        for payload in &responses {
            if payload.len() < GENL_HDRLEN {
                continue;
            }
            if let Some(dev) = parse_device(&payload[GENL_HDRLEN..]) {
                devices.push(dev);
            }
        }

        Ok(devices)
    }

    /// Get information for a specific device (driver, firmware versions).
    ///
    /// # Example
    ///
    /// ```ignore
    /// let info = conn.get_device_info("pci", "0000:03:00.0").await?;
    /// println!("Driver: {}", info.driver);
    /// for v in &info.versions_running {
    ///     println!("  {}: {}", v.name, v.value);
    /// }
    /// ```
    pub async fn get_device_info(&self, bus: &str, device: &str) -> Result<DevlinkInfo> {
        let response = self.devlink_get(DEVLINK_CMD_INFO_GET, bus, device).await?;

        if response.len() < GENL_HDRLEN {
            return Err(Error::InvalidMessage("empty info response".into()));
        }

        parse_info(&response[GENL_HDRLEN..])
    }

    // =========================================================================
    // Port Queries
    // =========================================================================

    /// List all ports across all devices.
    pub async fn get_ports(&self) -> Result<Vec<DevlinkPort>> {
        let responses = self.devlink_dump(DEVLINK_CMD_PORT_GET).await?;
        let mut ports = Vec::new();

        for payload in &responses {
            if payload.len() < GENL_HDRLEN {
                continue;
            }
            if let Some(port) = parse_port(&payload[GENL_HDRLEN..]) {
                ports.push(port);
            }
        }

        Ok(ports)
    }

    /// List ports for a specific device.
    pub async fn get_device_ports(
        &self,
        bus: &str,
        device: &str,
    ) -> Result<Vec<DevlinkPort>> {
        let ports = self.get_ports().await?;
        Ok(ports
            .into_iter()
            .filter(|p| p.bus == bus && p.device == device)
            .collect())
    }

    /// Get a specific port by device and index.
    pub async fn get_port(
        &self,
        bus: &str,
        device: &str,
        index: u32,
    ) -> Result<Option<DevlinkPort>> {
        let ports = self.get_device_ports(bus, device).await?;
        Ok(ports.into_iter().find(|p| p.index == index))
    }

    /// Find the port associated with a network interface name.
    pub async fn get_port_by_netdev(&self, netdev: &str) -> Result<Option<DevlinkPort>> {
        let ports = self.get_ports().await?;
        Ok(ports
            .into_iter()
            .find(|p| p.netdev_name.as_deref() == Some(netdev)))
    }

    // =========================================================================
    // Health Reporters
    // =========================================================================

    /// List all health reporters for a device.
    pub async fn get_health_reporters(
        &self,
        bus: &str,
        device: &str,
    ) -> Result<Vec<HealthReporter>> {
        let responses = self
            .devlink_dump_with_device(DEVLINK_CMD_HEALTH_REPORTER_GET, bus, device)
            .await?;
        let mut reporters = Vec::new();

        for payload in &responses {
            if payload.len() < GENL_HDRLEN {
                continue;
            }
            if let Some(reporter) = parse_health_response(bus, device, &payload[GENL_HDRLEN..]) {
                reporters.push(reporter);
            }
        }

        Ok(reporters)
    }

    /// Get a specific health reporter by name.
    pub async fn get_health_reporter(
        &self,
        bus: &str,
        device: &str,
        name: &str,
    ) -> Result<Option<HealthReporter>> {
        let reporters = self.get_health_reporters(bus, device).await?;
        Ok(reporters.into_iter().find(|r| r.name == name))
    }

    /// List health reporters that are in error state.
    pub async fn get_health_errors(
        &self,
        bus: &str,
        device: &str,
    ) -> Result<Vec<HealthReporter>> {
        let reporters = self.get_health_reporters(bus, device).await?;
        Ok(reporters.into_iter().filter(|r| r.is_error()).collect())
    }

    // =========================================================================
    // Parameters
    // =========================================================================

    /// List all parameters for a device.
    pub async fn get_params(
        &self,
        bus: &str,
        device: &str,
    ) -> Result<Vec<DevlinkParam>> {
        let responses = self
            .devlink_dump_with_device(DEVLINK_CMD_PARAM_GET, bus, device)
            .await?;
        let mut params = Vec::new();

        for payload in &responses {
            if payload.len() < GENL_HDRLEN {
                continue;
            }
            if let Some(param) = parse_param_response(bus, device, &payload[GENL_HDRLEN..]) {
                params.push(param);
            }
        }

        Ok(params)
    }

    /// Get a specific parameter by name.
    pub async fn get_param(
        &self,
        bus: &str,
        device: &str,
        name: &str,
    ) -> Result<Option<DevlinkParam>> {
        let params = self.get_params(bus, device).await?;
        Ok(params.into_iter().find(|p| p.name == name))
    }

    // =========================================================================
    // Health Reporter Management
    // =========================================================================

    /// Trigger recovery on a health reporter.
    pub async fn health_reporter_recover(
        &self,
        bus: &str,
        device: &str,
        reporter: &str,
    ) -> Result<()> {
        let mut builder = self.devlink_cmd_builder(DEVLINK_CMD_HEALTH_REPORTER_RECOVER, bus, device);
        let nested = builder.nest_start(DEVLINK_ATTR_HEALTH_REPORTER | 0x8000);
        builder.append_attr_str(DEVLINK_ATTR_HEALTH_REPORTER_NAME, reporter);
        builder.nest_end(nested);
        self.devlink_send_ack(builder).await
    }

    /// Configure a health reporter's settings.
    pub async fn set_health_reporter(
        &self,
        bus: &str,
        device: &str,
        reporter: &str,
        auto_recover: Option<bool>,
        auto_dump: Option<bool>,
        graceful_period_ms: Option<u64>,
    ) -> Result<()> {
        let mut builder = self.devlink_cmd_builder(DEVLINK_CMD_HEALTH_REPORTER_SET, bus, device);
        let nested = builder.nest_start(DEVLINK_ATTR_HEALTH_REPORTER | 0x8000);
        builder.append_attr_str(DEVLINK_ATTR_HEALTH_REPORTER_NAME, reporter);
        if let Some(v) = auto_recover {
            builder.append_attr(DEVLINK_ATTR_HEALTH_REPORTER_AUTO_RECOVER, &[u8::from(v)]);
        }
        if let Some(v) = auto_dump {
            builder.append_attr(DEVLINK_ATTR_HEALTH_REPORTER_AUTO_DUMP, &[u8::from(v)]);
        }
        if let Some(ms) = graceful_period_ms {
            builder.append_attr(DEVLINK_ATTR_HEALTH_REPORTER_GRACEFUL_PERIOD, &ms.to_ne_bytes());
        }
        builder.nest_end(nested);
        self.devlink_send_ack(builder).await
    }

    // =========================================================================
    // Flash Update
    // =========================================================================

    /// Flash firmware to a device.
    ///
    /// This is a long-running operation. The kernel will send progress
    /// notifications asynchronously.
    pub async fn flash_update(
        &self,
        bus: &str,
        device: &str,
        request: FlashRequest,
    ) -> Result<()> {
        let mut builder = self.devlink_cmd_builder(DEVLINK_CMD_FLASH_UPDATE, bus, device);
        builder.append_attr_str(DEVLINK_ATTR_FLASH_UPDATE_FILE_NAME, &request.file_name);
        if let Some(component) = &request.component {
            builder.append_attr_str(DEVLINK_ATTR_FLASH_UPDATE_COMPONENT, component);
        }
        self.devlink_send_ack(builder).await
    }

    // =========================================================================
    // Reload
    // =========================================================================

    /// Reload the device with the specified action.
    pub async fn reload(
        &self,
        bus: &str,
        device: &str,
        action: ReloadAction,
    ) -> Result<()> {
        let mut builder = self.devlink_cmd_builder(DEVLINK_CMD_RELOAD, bus, device);
        builder.append_attr(DEVLINK_ATTR_RELOAD_ACTION, &[action as u8]);
        self.devlink_send_ack(builder).await
    }

    // =========================================================================
    // Port Split/Unsplit
    // =========================================================================

    /// Split a port into sub-ports.
    pub async fn port_split(
        &self,
        bus: &str,
        device: &str,
        port_index: u32,
        count: u32,
    ) -> Result<()> {
        let mut builder = self.devlink_cmd_builder(DEVLINK_CMD_PORT_SPLIT, bus, device);
        builder.append_attr_u32(DEVLINK_ATTR_PORT_INDEX, port_index);
        builder.append_attr_u32(DEVLINK_ATTR_PORT_SPLIT_COUNT, count);
        self.devlink_send_ack(builder).await
    }

    /// Unsplit a previously split port.
    pub async fn port_unsplit(
        &self,
        bus: &str,
        device: &str,
        port_index: u32,
    ) -> Result<()> {
        let mut builder = self.devlink_cmd_builder(DEVLINK_CMD_PORT_UNSPLIT, bus, device);
        builder.append_attr_u32(DEVLINK_ATTR_PORT_INDEX, port_index);
        self.devlink_send_ack(builder).await
    }

    // =========================================================================
    // Parameter Configuration
    // =========================================================================

    /// Set a device parameter.
    pub async fn set_param(
        &self,
        bus: &str,
        device: &str,
        name: &str,
        cmode: ConfigMode,
        data: ParamData,
    ) -> Result<()> {
        let mut builder = self.devlink_cmd_builder(DEVLINK_CMD_PARAM_SET, bus, device);
        builder.append_attr_str(DEVLINK_ATTR_PARAM_NAME, name);
        builder.append_attr(DEVLINK_ATTR_PARAM_TYPE, &[data.type_id()]);

        // Nested: PARAM_VALUE_CMODE + PARAM_VALUE_DATA
        let value_list = builder.nest_start(DEVLINK_ATTR_PARAM_VALUES_LIST | 0x8000);
        let value_entry = builder.nest_start(DEVLINK_ATTR_PARAM_VALUE | 0x8000);
        builder.append_attr(DEVLINK_ATTR_PARAM_VALUE_CMODE, &[cmode as u8]);
        builder.append_attr(DEVLINK_ATTR_PARAM_VALUE_DATA, &data.to_bytes());
        builder.nest_end(value_entry);
        builder.nest_end(value_list);

        self.devlink_send_ack(builder).await
    }

    // =========================================================================
    // Internal helpers
    // =========================================================================

    /// Send a GENL dump request (no device filter).
    async fn devlink_dump(&self, cmd: u8) -> Result<Vec<Vec<u8>>> {
        let family_id = self.state().family_id;

        let mut builder = MessageBuilder::new(family_id, NLM_F_REQUEST | NLM_F_DUMP);
        let genl_hdr = GenlMsgHdr::new(cmd, DEVLINK_GENL_VERSION);
        builder.append(&genl_hdr);

        let seq = self.socket().next_seq();
        builder.set_seq(seq);
        builder.set_pid(self.socket().pid());

        let msg = builder.finish();
        self.socket().send(&msg).await?;

        self.collect_dump_responses(seq).await
    }

    /// Send a GENL dump request with device filter.
    async fn devlink_dump_with_device(
        &self,
        cmd: u8,
        bus: &str,
        device: &str,
    ) -> Result<Vec<Vec<u8>>> {
        let family_id = self.state().family_id;

        let mut builder = MessageBuilder::new(family_id, NLM_F_REQUEST | NLM_F_DUMP);
        let genl_hdr = GenlMsgHdr::new(cmd, DEVLINK_GENL_VERSION);
        builder.append(&genl_hdr);
        builder.append_attr_str(DEVLINK_ATTR_BUS_NAME, bus);
        builder.append_attr_str(DEVLINK_ATTR_DEV_NAME, device);

        let seq = self.socket().next_seq();
        builder.set_seq(seq);
        builder.set_pid(self.socket().pid());

        let msg = builder.finish();
        self.socket().send(&msg).await?;

        self.collect_dump_responses(seq).await
    }

    /// Send a GENL GET request for a specific device.
    async fn devlink_get(&self, cmd: u8, bus: &str, device: &str) -> Result<Vec<u8>> {
        let family_id = self.state().family_id;

        let mut builder = MessageBuilder::new(family_id, NLM_F_REQUEST | NLM_F_ACK);
        let genl_hdr = GenlMsgHdr::new(cmd, DEVLINK_GENL_VERSION);
        builder.append(&genl_hdr);
        builder.append_attr_str(DEVLINK_ATTR_BUS_NAME, bus);
        builder.append_attr_str(DEVLINK_ATTR_DEV_NAME, device);

        let seq = self.socket().next_seq();
        builder.set_seq(seq);
        builder.set_pid(self.socket().pid());

        let msg = builder.finish();
        self.socket().send(&msg).await?;

        // Collect response
        let mut result_payload: Option<Vec<u8>> = None;

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
                    done = true;
                    continue;
                }

                if header.is_done() {
                    done = true;
                    break;
                }

                if result_payload.is_none() {
                    result_payload = Some(payload.to_vec());
                }
            }

            if done {
                break;
            }
        }

        result_payload.ok_or_else(|| Error::InvalidMessage("no response received".into()))
    }

    /// Build a GENL command message for a device.
    fn devlink_cmd_builder(&self, cmd: u8, bus: &str, device: &str) -> MessageBuilder {
        let family_id = self.state().family_id;
        let mut builder = MessageBuilder::new(family_id, NLM_F_REQUEST | NLM_F_ACK);
        let genl_hdr = GenlMsgHdr::new(cmd, DEVLINK_GENL_VERSION);
        builder.append(&genl_hdr);
        builder.append_attr_str(DEVLINK_ATTR_BUS_NAME, bus);
        builder.append_attr_str(DEVLINK_ATTR_DEV_NAME, device);
        builder
    }

    /// Send a command and wait for ACK.
    async fn devlink_send_ack(&self, mut builder: MessageBuilder) -> Result<()> {
        let seq = self.socket().next_seq();
        builder.set_seq(seq);
        builder.set_pid(self.socket().pid());

        let msg = builder.finish();
        self.socket().send(&msg).await?;

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
}

// =============================================================================
// Attribute Parsing
// =============================================================================

fn parse_device(data: &[u8]) -> Option<DevlinkDevice> {
    let mut bus = None;
    let mut device = None;

    for (attr_type, payload) in AttrIter::new(data) {
        match attr_type {
            DEVLINK_ATTR_BUS_NAME => {
                bus = attr_str(payload);
            }
            DEVLINK_ATTR_DEV_NAME => {
                device = attr_str(payload);
            }
            _ => {}
        }
    }

    Some(DevlinkDevice {
        bus: bus?,
        device: device?,
    })
}

fn parse_info(data: &[u8]) -> Result<DevlinkInfo> {
    let mut info = DevlinkInfo {
        bus: String::new(),
        device: String::new(),
        driver: String::new(),
        serial: None,
        board_serial: None,
        versions_fixed: Vec::new(),
        versions_running: Vec::new(),
        versions_stored: Vec::new(),
    };

    for (attr_type, payload) in AttrIter::new(data) {
        match attr_type {
            DEVLINK_ATTR_BUS_NAME => {
                info.bus = attr_str(payload).unwrap_or_default();
            }
            DEVLINK_ATTR_DEV_NAME => {
                info.device = attr_str(payload).unwrap_or_default();
            }
            DEVLINK_ATTR_INFO_DRIVER_NAME => {
                info.driver = attr_str(payload).unwrap_or_default();
            }
            DEVLINK_ATTR_INFO_SERIAL_NUMBER => {
                info.serial = attr_str(payload);
            }
            DEVLINK_ATTR_INFO_BOARD_SERIAL_NUMBER => {
                info.board_serial = attr_str(payload);
            }
            DEVLINK_ATTR_INFO_VERSION_FIXED => {
                if let Some(v) = parse_version_nested(payload) {
                    info.versions_fixed.push(v);
                }
            }
            DEVLINK_ATTR_INFO_VERSION_RUNNING => {
                if let Some(v) = parse_version_nested(payload) {
                    info.versions_running.push(v);
                }
            }
            DEVLINK_ATTR_INFO_VERSION_STORED => {
                if let Some(v) = parse_version_nested(payload) {
                    info.versions_stored.push(v);
                }
            }
            _ => {}
        }
    }

    Ok(info)
}

fn parse_version_nested(data: &[u8]) -> Option<VersionInfo> {
    let mut name = None;
    let mut value = None;

    for (attr_type, payload) in AttrIter::new(data) {
        match attr_type {
            DEVLINK_ATTR_INFO_VERSION_NAME => {
                name = attr_str(payload);
            }
            DEVLINK_ATTR_INFO_VERSION_VALUE => {
                value = attr_str(payload);
            }
            _ => {}
        }
    }

    Some(VersionInfo {
        name: name?,
        value: value?,
    })
}

fn parse_port(data: &[u8]) -> Option<DevlinkPort> {
    let mut port = DevlinkPort {
        bus: String::new(),
        device: String::new(),
        index: 0,
        port_type: PortType::NotSet,
        netdev_ifindex: None,
        netdev_name: None,
        ibdev_name: None,
        flavour: None,
        number: None,
        split_subport: None,
        split_group: None,
        pci_pf: None,
        pci_vf: None,
        pci_sf: None,
        controller: None,
    };

    let mut has_index = false;

    for (attr_type, payload) in AttrIter::new(data) {
        match attr_type {
            DEVLINK_ATTR_BUS_NAME => {
                port.bus = attr_str(payload).unwrap_or_default();
            }
            DEVLINK_ATTR_DEV_NAME => {
                port.device = attr_str(payload).unwrap_or_default();
            }
            DEVLINK_ATTR_PORT_INDEX => {
                if payload.len() >= 4 {
                    port.index = u32::from_ne_bytes(payload[..4].try_into().unwrap());
                    has_index = true;
                }
            }
            DEVLINK_ATTR_PORT_TYPE => {
                if payload.len() >= 2 {
                    let v = u16::from_ne_bytes(payload[..2].try_into().unwrap());
                    port.port_type = PortType::try_from(v).unwrap_or(PortType::NotSet);
                }
            }
            DEVLINK_ATTR_PORT_NETDEV_IFINDEX => {
                if payload.len() >= 4 {
                    port.netdev_ifindex =
                        Some(u32::from_ne_bytes(payload[..4].try_into().unwrap()));
                }
            }
            DEVLINK_ATTR_PORT_NETDEV_NAME => {
                port.netdev_name = attr_str(payload);
            }
            DEVLINK_ATTR_PORT_IBDEV_NAME => {
                port.ibdev_name = attr_str(payload);
            }
            DEVLINK_ATTR_PORT_FLAVOUR => {
                if payload.len() >= 2 {
                    let v = u16::from_ne_bytes(payload[..2].try_into().unwrap());
                    port.flavour = PortFlavour::try_from(v).ok();
                }
            }
            DEVLINK_ATTR_PORT_NUMBER => {
                if payload.len() >= 4 {
                    port.number = Some(u32::from_ne_bytes(payload[..4].try_into().unwrap()));
                }
            }
            DEVLINK_ATTR_PORT_SPLIT_SUBPORT_NUMBER => {
                if payload.len() >= 4 {
                    port.split_subport =
                        Some(u32::from_ne_bytes(payload[..4].try_into().unwrap()));
                }
            }
            DEVLINK_ATTR_PORT_SPLIT_GROUP => {
                if payload.len() >= 4 {
                    port.split_group =
                        Some(u32::from_ne_bytes(payload[..4].try_into().unwrap()));
                }
            }
            DEVLINK_ATTR_PORT_PCI_PF_NUMBER => {
                if payload.len() >= 2 {
                    port.pci_pf = Some(u16::from_ne_bytes(payload[..2].try_into().unwrap()));
                }
            }
            DEVLINK_ATTR_PORT_PCI_VF_NUMBER => {
                if payload.len() >= 2 {
                    port.pci_vf = Some(u16::from_ne_bytes(payload[..2].try_into().unwrap()));
                }
            }
            DEVLINK_ATTR_PORT_PCI_SF_NUMBER => {
                if payload.len() >= 4 {
                    port.pci_sf = Some(u32::from_ne_bytes(payload[..4].try_into().unwrap()));
                }
            }
            DEVLINK_ATTR_PORT_CONTROLLER_NUMBER => {
                if payload.len() >= 4 {
                    port.controller =
                        Some(u32::from_ne_bytes(payload[..4].try_into().unwrap()));
                }
            }
            _ => {}
        }
    }

    if has_index {
        Some(port)
    } else {
        None
    }
}

fn parse_health_response(
    bus: &str,
    device: &str,
    data: &[u8],
) -> Option<HealthReporter> {
    for (attr_type, payload) in AttrIter::new(data) {
        if attr_type == DEVLINK_ATTR_HEALTH_REPORTER {
            return parse_health_reporter(bus, device, payload);
        }
    }
    None
}

fn parse_health_reporter(
    bus: &str,
    device: &str,
    data: &[u8],
) -> Option<HealthReporter> {
    let mut reporter = HealthReporter {
        bus: bus.to_string(),
        device: device.to_string(),
        name: String::new(),
        state: HealthState::Healthy,
        error_count: 0,
        recover_count: 0,
        auto_recover: false,
        auto_dump: false,
        graceful_period_ms: None,
        dump_ts_jiffies: None,
    };

    for (attr_type, payload) in AttrIter::new(data) {
        match attr_type {
            DEVLINK_ATTR_HEALTH_REPORTER_NAME => {
                reporter.name = attr_str(payload).unwrap_or_default();
            }
            DEVLINK_ATTR_HEALTH_REPORTER_STATE => {
                if !payload.is_empty() {
                    reporter.state =
                        HealthState::try_from(payload[0]).unwrap_or(HealthState::Healthy);
                }
            }
            DEVLINK_ATTR_HEALTH_REPORTER_ERR_COUNT => {
                if payload.len() >= 8 {
                    reporter.error_count =
                        u64::from_ne_bytes(payload[..8].try_into().unwrap());
                }
            }
            DEVLINK_ATTR_HEALTH_REPORTER_RECOVER_COUNT => {
                if payload.len() >= 8 {
                    reporter.recover_count =
                        u64::from_ne_bytes(payload[..8].try_into().unwrap());
                }
            }
            DEVLINK_ATTR_HEALTH_REPORTER_AUTO_RECOVER => {
                if !payload.is_empty() {
                    reporter.auto_recover = payload[0] != 0;
                }
            }
            DEVLINK_ATTR_HEALTH_REPORTER_AUTO_DUMP => {
                if !payload.is_empty() {
                    reporter.auto_dump = payload[0] != 0;
                }
            }
            DEVLINK_ATTR_HEALTH_REPORTER_GRACEFUL_PERIOD => {
                if payload.len() >= 8 {
                    reporter.graceful_period_ms =
                        Some(u64::from_ne_bytes(payload[..8].try_into().unwrap()));
                }
            }
            DEVLINK_ATTR_HEALTH_REPORTER_DUMP_TS => {
                if payload.len() >= 8 {
                    reporter.dump_ts_jiffies =
                        Some(u64::from_ne_bytes(payload[..8].try_into().unwrap()));
                }
            }
            _ => {}
        }
    }

    if reporter.name.is_empty() {
        None
    } else {
        Some(reporter)
    }
}

fn parse_param_response(
    bus: &str,
    device: &str,
    data: &[u8],
) -> Option<DevlinkParam> {
    for (attr_type, payload) in AttrIter::new(data) {
        if attr_type == DEVLINK_ATTR_PARAM {
            return parse_param(bus, device, payload);
        }
    }
    None
}

fn parse_param(bus: &str, device: &str, data: &[u8]) -> Option<DevlinkParam> {
    let mut param = DevlinkParam {
        bus: bus.to_string(),
        device: device.to_string(),
        name: String::new(),
        generic: false,
        values: Vec::new(),
    };

    let mut param_type: Option<u8> = None;

    for (attr_type, payload) in AttrIter::new(data) {
        match attr_type {
            DEVLINK_ATTR_PARAM_NAME => {
                param.name = attr_str(payload).unwrap_or_default();
            }
            DEVLINK_ATTR_PARAM_GENERIC => {
                param.generic = true; // Flag attribute — presence means true
            }
            DEVLINK_ATTR_PARAM_TYPE => {
                if !payload.is_empty() {
                    param_type = Some(payload[0]);
                }
            }
            DEVLINK_ATTR_PARAM_VALUES_LIST => {
                // Parse nested value entries
                for (_idx, value_data) in AttrIter::new(payload) {
                    if let Some(pv) = parse_param_value(value_data, param_type) {
                        param.values.push(pv);
                    }
                }
            }
            _ => {}
        }
    }

    if param.name.is_empty() {
        None
    } else {
        Some(param)
    }
}

fn parse_param_value(data: &[u8], param_type: Option<u8>) -> Option<ParamValue> {
    let mut cmode = None;
    let mut value_data: Option<&[u8]> = None;

    for (attr_type, payload) in AttrIter::new(data) {
        match attr_type {
            DEVLINK_ATTR_PARAM_VALUE_CMODE => {
                if !payload.is_empty() {
                    cmode = ConfigMode::try_from(payload[0]).ok();
                }
            }
            DEVLINK_ATTR_PARAM_VALUE_DATA => {
                value_data = Some(payload);
            }
            _ => {}
        }
    }

    let cmode = cmode?;
    let raw = value_data?;

    let data = match param_type {
        Some(1) if !raw.is_empty() => ParamData::U8(raw[0]),
        Some(2) if raw.len() >= 2 => {
            ParamData::U16(u16::from_ne_bytes(raw[..2].try_into().unwrap()))
        }
        Some(3) if raw.len() >= 4 => {
            ParamData::U32(u32::from_ne_bytes(raw[..4].try_into().unwrap()))
        }
        Some(5) => ParamData::String(attr_str(raw).unwrap_or_default()),
        Some(6) if !raw.is_empty() => ParamData::Bool(raw[0] != 0),
        _ => ParamData::U32(if raw.len() >= 4 {
            u32::from_ne_bytes(raw[..4].try_into().unwrap())
        } else {
            0
        }),
    };

    Some(ParamValue { cmode, data })
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

/// Resolve the devlink GENL family ID and multicast group ID.
async fn resolve_devlink_family(socket: &NetlinkSocket) -> Result<(u16, Option<u32>)> {
    let mut builder = MessageBuilder::new(GENL_ID_CTRL, NLM_F_REQUEST | NLM_F_ACK);
    let genl_hdr = GenlMsgHdr::new(CtrlCmd::GetFamily as u8, 1);
    builder.append(&genl_hdr);
    builder.append_attr_str(CtrlAttr::FamilyName as u16, DEVLINK_GENL_NAME);

    let seq = socket.next_seq();
    builder.set_seq(seq);
    builder.set_pid(socket.pid());

    let msg = builder.finish();
    socket.send(&msg).await?;

    let response: Vec<u8> = socket.recv_msg().await?;
    let mut family_id: Option<u16> = None;
    let mut monitor_group_id: Option<u32> = None;

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
                        name: DEVLINK_GENL_NAME.to_string(),
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
            } else if attr_type == CtrlAttr::McastGroups as u16 {
                for (_idx, grp_data) in AttrIter::new(attr_payload) {
                    let mut grp_name: Option<String> = None;
                    let mut grp_id: Option<u32> = None;

                    for (grp_attr_type, grp_attr_payload) in AttrIter::new(grp_data) {
                        if grp_attr_type == CtrlAttrMcastGrp::Name as u16 {
                            grp_name = Some(
                                std::str::from_utf8(grp_attr_payload)
                                    .unwrap_or("")
                                    .trim_end_matches('\0')
                                    .to_string(),
                            );
                        } else if grp_attr_type == CtrlAttrMcastGrp::Id as u16
                            && grp_attr_payload.len() >= 4
                        {
                            grp_id = Some(u32::from_ne_bytes(
                                grp_attr_payload[..4].try_into().unwrap(),
                            ));
                        }
                    }

                    if grp_name.as_deref() == Some(DEVLINK_MCGRP_NAME) {
                        monitor_group_id = grp_id;
                    }
                }
            }
        }
    }

    match family_id {
        Some(id) => Ok((id, monitor_group_id)),
        None => Err(Error::FamilyNotFound {
            name: DEVLINK_GENL_NAME.to_string(),
        }),
    }
}
