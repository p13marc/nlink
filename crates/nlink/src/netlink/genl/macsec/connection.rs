//! MACsec connection implementation for `Connection<Macsec>`.

use super::types::{
    MacsecCipherSuite, MacsecDevice, MacsecOffload, MacsecRxSa, MacsecRxSc, MacsecSaBuilder,
    MacsecTxSa, MacsecTxSc, MacsecValidate,
};
use super::{MACSEC_GENL_NAME, MACSEC_GENL_VERSION};
use crate::netlink::attr::{AttrIter, NLA_F_NESTED, get};
use crate::netlink::builder::MessageBuilder;
use crate::netlink::connection::Connection;
use crate::netlink::error::{Error, Result};
use crate::netlink::genl::{CtrlAttr, CtrlCmd, GENL_HDRLEN, GENL_ID_CTRL, GenlMsgHdr};
use crate::netlink::message::{MessageIter, NLM_F_ACK, NLM_F_DUMP, NLM_F_REQUEST, NlMsgError};
use crate::netlink::protocol::{Macsec, ProtocolState};
use crate::netlink::socket::NetlinkSocket;
use crate::netlink::types::macsec::{
    macsec_attr, macsec_cmd, macsec_offload_attr, macsec_rxsc_attr, macsec_rxsc_stats_attr,
    macsec_sa_attr, macsec_secy_attr, macsec_txsc_stats_attr,
};

impl Connection<Macsec> {
    /// Create a new MACsec connection.
    ///
    /// This resolves the MACsec GENL family ID during initialization.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use nlink::netlink::{Connection, Macsec};
    ///
    /// let conn = Connection::<Macsec>::new_async().await?;
    /// let device = conn.get_device("macsec0").await?;
    /// ```
    pub async fn new_async() -> Result<Self> {
        let socket = NetlinkSocket::new(Macsec::PROTOCOL)?;
        let family_id = resolve_macsec_family(&socket).await?;

        let state = Macsec { family_id };
        Ok(Self::from_parts(socket, state))
    }

    /// Get the MACsec family ID.
    pub fn family_id(&self) -> u16 {
        self.state().family_id
    }

    /// Get device information by interface index.
    ///
    /// Returns the current configuration and status of the MACsec interface.
    /// This is the preferred method for namespace operations.
    ///
    /// # Example
    ///
    /// ```ignore
    /// // Get ifindex via Route connection first
    /// let route_conn = Connection::<Route>::new()?;
    /// let link = route_conn.get_link_by_name("macsec0").await?.unwrap();
    ///
    /// let macsec_conn = Connection::<Macsec>::new_async().await?;
    /// let device = macsec_conn.get_device_by_index(link.ifindex()).await?;
    /// println!("SCI: {:016x}", device.sci);
    /// ```
    pub async fn get_device_by_index(&self, ifindex: u32) -> Result<MacsecDevice> {
        let responses = self
            .dump_macsec_command(macsec_cmd::GET_TXSC, |builder| {
                builder.append_attr_u32(macsec_attr::IFINDEX, ifindex);
            })
            .await?;

        if responses.is_empty() {
            return Err(Error::InterfaceNotFound {
                name: format!("ifindex {}", ifindex),
            });
        }

        let mut device = MacsecDevice::new();
        device.ifindex = ifindex;

        for response in &responses {
            if response.len() < GENL_HDRLEN {
                continue;
            }
            let attrs_data = &response[GENL_HDRLEN..];
            parse_device_attrs(attrs_data, &mut device)?;
        }

        Ok(device)
    }

    /// Add a TX Security Association by interface index.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let key = [0u8; 16]; // 128-bit key
    /// conn.add_tx_sa_by_index(ifindex,
    ///     MacsecSaBuilder::new(0, &key)
    ///         .packet_number(1)
    ///         .active(true)
    /// ).await?;
    /// ```
    pub async fn add_tx_sa_by_index(&self, ifindex: u32, sa: MacsecSaBuilder) -> Result<()> {
        self.macsec_command(macsec_cmd::ADD_TXSA, |builder| {
            builder.append_attr_u32(macsec_attr::IFINDEX, ifindex);

            let sa_config = builder.nest_start(macsec_attr::SA_CONFIG | NLA_F_NESTED);
            builder.append_attr_u8(macsec_sa_attr::AN, sa.get_an());
            builder.append_attr(macsec_sa_attr::KEY, sa.get_key());
            if let Some(pn) = sa.get_pn() {
                // Use u32 for standard PN, u64 for XPN
                if pn <= u32::MAX as u64 {
                    builder.append_attr_u32(macsec_sa_attr::PN, pn as u32);
                } else {
                    builder.append_attr_u64(macsec_sa_attr::PN, pn);
                }
            }
            builder.append_attr_u8(macsec_sa_attr::ACTIVE, sa.is_active() as u8);
            if let Some(key_id) = sa.get_key_id() {
                builder.append_attr(macsec_sa_attr::KEYID, key_id);
            }
            builder.nest_end(sa_config);
        })
        .await?;

        Ok(())
    }

    /// Delete a TX Security Association by interface index.
    ///
    /// # Arguments
    ///
    /// * `ifindex` - Interface index
    /// * `an` - Association Number (0-3)
    pub async fn del_tx_sa_by_index(&self, ifindex: u32, an: u8) -> Result<()> {
        self.macsec_command(macsec_cmd::DEL_TXSA, |builder| {
            builder.append_attr_u32(macsec_attr::IFINDEX, ifindex);

            let sa_config = builder.nest_start(macsec_attr::SA_CONFIG | NLA_F_NESTED);
            builder.append_attr_u8(macsec_sa_attr::AN, an);
            builder.nest_end(sa_config);
        })
        .await?;

        Ok(())
    }

    /// Update a TX Security Association by interface index.
    ///
    /// This can be used to activate/deactivate an SA or update the packet number.
    pub async fn update_tx_sa_by_index(&self, ifindex: u32, sa: MacsecSaBuilder) -> Result<()> {
        self.macsec_command(macsec_cmd::UPD_TXSA, |builder| {
            builder.append_attr_u32(macsec_attr::IFINDEX, ifindex);

            let sa_config = builder.nest_start(macsec_attr::SA_CONFIG | NLA_F_NESTED);
            builder.append_attr_u8(macsec_sa_attr::AN, sa.get_an());
            if let Some(pn) = sa.get_pn() {
                if pn <= u32::MAX as u64 {
                    builder.append_attr_u32(macsec_sa_attr::PN, pn as u32);
                } else {
                    builder.append_attr_u64(macsec_sa_attr::PN, pn);
                }
            }
            builder.append_attr_u8(macsec_sa_attr::ACTIVE, sa.is_active() as u8);
            builder.nest_end(sa_config);
        })
        .await?;

        Ok(())
    }

    /// Add an RX Secure Channel by interface index.
    ///
    /// # Arguments
    ///
    /// * `ifindex` - Interface index
    /// * `sci` - Secure Channel Identifier (typically peer's MAC + port)
    pub async fn add_rx_sc_by_index(&self, ifindex: u32, sci: u64) -> Result<()> {
        self.macsec_command(macsec_cmd::ADD_RXSC, |builder| {
            builder.append_attr_u32(macsec_attr::IFINDEX, ifindex);

            let rxsc_config = builder.nest_start(macsec_attr::RXSC_CONFIG | NLA_F_NESTED);
            builder.append_attr_u64(macsec_rxsc_attr::SCI, sci);
            builder.append_attr_u8(macsec_rxsc_attr::ACTIVE, 1);
            builder.nest_end(rxsc_config);
        })
        .await?;

        Ok(())
    }

    /// Delete an RX Secure Channel by interface index.
    ///
    /// This also deletes all associated RX SAs.
    pub async fn del_rx_sc_by_index(&self, ifindex: u32, sci: u64) -> Result<()> {
        self.macsec_command(macsec_cmd::DEL_RXSC, |builder| {
            builder.append_attr_u32(macsec_attr::IFINDEX, ifindex);

            let rxsc_config = builder.nest_start(macsec_attr::RXSC_CONFIG | NLA_F_NESTED);
            builder.append_attr_u64(macsec_rxsc_attr::SCI, sci);
            builder.nest_end(rxsc_config);
        })
        .await?;

        Ok(())
    }

    /// Add an RX Security Association by interface index.
    ///
    /// # Arguments
    ///
    /// * `ifindex` - Interface index
    /// * `sci` - Secure Channel Identifier
    /// * `sa` - SA configuration
    pub async fn add_rx_sa_by_index(
        &self,
        ifindex: u32,
        sci: u64,
        sa: MacsecSaBuilder,
    ) -> Result<()> {
        self.macsec_command(macsec_cmd::ADD_RXSA, |builder| {
            builder.append_attr_u32(macsec_attr::IFINDEX, ifindex);

            // RX SC config with SCI
            let rxsc_config = builder.nest_start(macsec_attr::RXSC_CONFIG | NLA_F_NESTED);
            builder.append_attr_u64(macsec_rxsc_attr::SCI, sci);
            builder.nest_end(rxsc_config);

            // SA config
            let sa_config = builder.nest_start(macsec_attr::SA_CONFIG | NLA_F_NESTED);
            builder.append_attr_u8(macsec_sa_attr::AN, sa.get_an());
            builder.append_attr(macsec_sa_attr::KEY, sa.get_key());
            if let Some(pn) = sa.get_pn() {
                if pn <= u32::MAX as u64 {
                    builder.append_attr_u32(macsec_sa_attr::PN, pn as u32);
                } else {
                    builder.append_attr_u64(macsec_sa_attr::PN, pn);
                }
            }
            builder.append_attr_u8(macsec_sa_attr::ACTIVE, sa.is_active() as u8);
            if let Some(key_id) = sa.get_key_id() {
                builder.append_attr(macsec_sa_attr::KEYID, key_id);
            }
            builder.nest_end(sa_config);
        })
        .await?;

        Ok(())
    }

    /// Delete an RX Security Association by interface index.
    pub async fn del_rx_sa_by_index(&self, ifindex: u32, sci: u64, an: u8) -> Result<()> {
        self.macsec_command(macsec_cmd::DEL_RXSA, |builder| {
            builder.append_attr_u32(macsec_attr::IFINDEX, ifindex);

            let rxsc_config = builder.nest_start(macsec_attr::RXSC_CONFIG | NLA_F_NESTED);
            builder.append_attr_u64(macsec_rxsc_attr::SCI, sci);
            builder.nest_end(rxsc_config);

            let sa_config = builder.nest_start(macsec_attr::SA_CONFIG | NLA_F_NESTED);
            builder.append_attr_u8(macsec_sa_attr::AN, an);
            builder.nest_end(sa_config);
        })
        .await?;

        Ok(())
    }

    /// Update an RX Security Association by interface index.
    pub async fn update_rx_sa_by_index(
        &self,
        ifindex: u32,
        sci: u64,
        sa: MacsecSaBuilder,
    ) -> Result<()> {
        self.macsec_command(macsec_cmd::UPD_RXSA, |builder| {
            builder.append_attr_u32(macsec_attr::IFINDEX, ifindex);

            let rxsc_config = builder.nest_start(macsec_attr::RXSC_CONFIG | NLA_F_NESTED);
            builder.append_attr_u64(macsec_rxsc_attr::SCI, sci);
            builder.nest_end(rxsc_config);

            let sa_config = builder.nest_start(macsec_attr::SA_CONFIG | NLA_F_NESTED);
            builder.append_attr_u8(macsec_sa_attr::AN, sa.get_an());
            if let Some(pn) = sa.get_pn() {
                if pn <= u32::MAX as u64 {
                    builder.append_attr_u32(macsec_sa_attr::PN, pn as u32);
                } else {
                    builder.append_attr_u64(macsec_sa_attr::PN, pn);
                }
            }
            builder.append_attr_u8(macsec_sa_attr::ACTIVE, sa.is_active() as u8);
            builder.nest_end(sa_config);
        })
        .await?;

        Ok(())
    }

    /// Send a MACsec GENL command and wait for ACK.
    async fn macsec_command(
        &self,
        cmd: u8,
        build_attrs: impl FnOnce(&mut MessageBuilder),
    ) -> Result<Vec<u8>> {
        let family_id = self.state().family_id;

        let mut builder = MessageBuilder::new(family_id, NLM_F_REQUEST | NLM_F_ACK);

        let genl_hdr = GenlMsgHdr::new(cmd, MACSEC_GENL_VERSION);
        builder.append(&genl_hdr);

        build_attrs(&mut builder);

        let seq = self.socket().next_seq();
        builder.set_seq(seq);
        builder.set_pid(self.socket().pid());

        let msg = builder.finish();
        self.socket().send(&msg).await?;

        let response: Vec<u8> = self.socket().recv_msg().await?;
        self.process_genl_response(&response, seq)?;

        Ok(response)
    }

    /// Send a MACsec GENL dump command and collect all responses.
    async fn dump_macsec_command(
        &self,
        cmd: u8,
        build_attrs: impl FnOnce(&mut MessageBuilder),
    ) -> Result<Vec<Vec<u8>>> {
        let family_id = self.state().family_id;

        let mut builder = MessageBuilder::new(family_id, NLM_F_REQUEST | NLM_F_DUMP);

        let genl_hdr = GenlMsgHdr::new(cmd, MACSEC_GENL_VERSION);
        builder.append(&genl_hdr);

        build_attrs(&mut builder);

        let seq = self.socket().next_seq();
        builder.set_seq(seq);
        builder.set_pid(self.socket().pid());

        let msg = builder.finish();
        self.socket().send(&msg).await?;

        let mut responses = Vec::new();

        loop {
            let data: Vec<u8> = self.socket().recv_msg().await?;
            let mut done = false;

            for result in MessageIter::new(&data) {
                let (header, payload) = result?;

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

                responses.push(payload.to_vec());
            }

            if done {
                break;
            }
        }

        Ok(responses)
    }

    /// Process a GENL response, checking for errors.
    fn process_genl_response(&self, data: &[u8], seq: u32) -> Result<()> {
        for result in MessageIter::new(data) {
            let (header, payload) = result?;

            if header.nlmsg_seq != seq {
                continue;
            }

            if header.is_error() {
                let err = NlMsgError::from_bytes(payload)?;
                if !err.is_ack() {
                    return Err(Error::from_errno(err.error));
                }
            }
        }

        Ok(())
    }
}

/// Resolve the MACsec GENL family ID.
async fn resolve_macsec_family(socket: &NetlinkSocket) -> Result<u16> {
    let mut builder = MessageBuilder::new(GENL_ID_CTRL, NLM_F_REQUEST | NLM_F_ACK);

    let genl_hdr = GenlMsgHdr::new(CtrlCmd::GetFamily as u8, 1);
    builder.append(&genl_hdr);

    builder.append_attr_str(CtrlAttr::FamilyName as u16, MACSEC_GENL_NAME);

    let seq = socket.next_seq();
    builder.set_seq(seq);
    builder.set_pid(socket.pid());

    let msg = builder.finish();
    socket.send(&msg).await?;

    let response: Vec<u8> = socket.recv_msg().await?;

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
                        name: MACSEC_GENL_NAME.to_string(),
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
            if attr_type == CtrlAttr::FamilyId as u16 {
                return get::u16_ne(attr_payload);
            }
        }
    }

    Err(Error::FamilyNotFound {
        name: MACSEC_GENL_NAME.to_string(),
    })
}

/// Parse device attributes from a GENL response.
fn parse_device_attrs(data: &[u8], device: &mut MacsecDevice) -> Result<()> {
    for (attr_type, payload) in AttrIter::new(data) {
        match attr_type {
            t if t == macsec_attr::IFINDEX => {
                device.ifindex = get::u32_ne(payload)?;
            }
            t if t == macsec_attr::SECY_CONFIG => {
                parse_secy_config(payload, device)?;
            }
            t if t == macsec_attr::TXSC_STATS => {
                parse_txsc_stats(payload, device)?;
            }
            t if t == macsec_attr::TXSA_LIST => {
                parse_txsa_list(payload, device)?;
            }
            t if t == macsec_attr::RXSC_LIST => {
                parse_rxsc_list(payload, device)?;
            }
            t if t == macsec_attr::OFFLOAD => {
                parse_offload(payload, device)?;
            }
            _ => {}
        }
    }
    Ok(())
}

/// Parse SecY configuration.
fn parse_secy_config(data: &[u8], device: &mut MacsecDevice) -> Result<()> {
    for (attr_type, payload) in AttrIter::new(data) {
        match attr_type {
            t if t == macsec_secy_attr::SCI => {
                device.sci = get::u64_ne(payload)?;
            }
            t if t == macsec_secy_attr::ENCODING_SA => {
                device.encoding_sa = get::u8(payload)?;
            }
            t if t == macsec_secy_attr::WINDOW => {
                device.replay_window = get::u32_ne(payload)?;
            }
            t if t == macsec_secy_attr::CIPHER_SUITE => {
                let cipher_id = get::u64_ne(payload)?;
                device.cipher = MacsecCipherSuite::from_u64(cipher_id).unwrap_or_default();
            }
            t if t == macsec_secy_attr::ICV_LEN => {
                device.icv_len = get::u8(payload)?;
            }
            t if t == macsec_secy_attr::ENCRYPT => {
                device.encrypt = get::u8(payload)? != 0;
            }
            t if t == macsec_secy_attr::PROTECT => {
                device.protect = get::u8(payload)? != 0;
            }
            t if t == macsec_secy_attr::REPLAY => {
                device.replay_protect = get::u8(payload)? != 0;
            }
            t if t == macsec_secy_attr::VALIDATE => {
                device.validate = MacsecValidate::from_u8(get::u8(payload)?);
            }
            t if t == macsec_secy_attr::INC_SCI => {
                device.include_sci = get::u8(payload)? != 0;
            }
            t if t == macsec_secy_attr::ES => {
                device.end_station = get::u8(payload)? != 0;
            }
            t if t == macsec_secy_attr::SCB => {
                device.scb = get::u8(payload)? != 0;
            }
            _ => {}
        }
    }
    Ok(())
}

/// Parse TX SC statistics.
fn parse_txsc_stats(data: &[u8], device: &mut MacsecDevice) -> Result<()> {
    let tx_sc = device.tx_sc.get_or_insert_with(MacsecTxSc::default);

    for (attr_type, payload) in AttrIter::new(data) {
        match attr_type {
            t if t == macsec_txsc_stats_attr::OUT_PKTS_PROTECTED => {
                tx_sc.stats_protected_pkts = get::u64_ne(payload)?;
            }
            t if t == macsec_txsc_stats_attr::OUT_PKTS_ENCRYPTED => {
                tx_sc.stats_encrypted_pkts = get::u64_ne(payload)?;
            }
            t if t == macsec_txsc_stats_attr::OUT_OCTETS_PROTECTED => {
                tx_sc.stats_protected_octets = get::u64_ne(payload)?;
            }
            t if t == macsec_txsc_stats_attr::OUT_OCTETS_ENCRYPTED => {
                tx_sc.stats_encrypted_octets = get::u64_ne(payload)?;
            }
            _ => {}
        }
    }
    Ok(())
}

/// Parse TX SA list.
fn parse_txsa_list(data: &[u8], device: &mut MacsecDevice) -> Result<()> {
    let tx_sc = device.tx_sc.get_or_insert_with(MacsecTxSc::default);
    tx_sc.sci = device.sci;

    for (_idx, sa_data) in AttrIter::new(data) {
        let sa = parse_sa_attrs(sa_data)?;
        tx_sc.sas.push(MacsecTxSa {
            an: sa.0,
            active: sa.1,
            pn: sa.2,
            key_id: sa.3,
        });
    }
    Ok(())
}

/// Parse RX SC list.
fn parse_rxsc_list(data: &[u8], device: &mut MacsecDevice) -> Result<()> {
    for (_idx, rxsc_data) in AttrIter::new(data) {
        let rxsc = parse_rxsc_attrs(rxsc_data)?;
        device.rx_scs.push(rxsc);
    }
    Ok(())
}

/// Parse a single RX SC.
fn parse_rxsc_attrs(data: &[u8]) -> Result<MacsecRxSc> {
    let mut rxsc = MacsecRxSc::default();

    for (attr_type, payload) in AttrIter::new(data) {
        match attr_type {
            t if t == macsec_rxsc_attr::SCI => {
                rxsc.sci = get::u64_ne(payload)?;
            }
            t if t == macsec_rxsc_attr::ACTIVE => {
                rxsc.active = get::u8(payload)? != 0;
            }
            t if t == macsec_rxsc_attr::SA_LIST => {
                for (_idx, sa_data) in AttrIter::new(payload) {
                    let sa = parse_sa_attrs(sa_data)?;
                    rxsc.sas.push(MacsecRxSa {
                        an: sa.0,
                        active: sa.1,
                        pn: sa.2,
                        key_id: sa.3,
                    });
                }
            }
            _ => {}
        }
    }

    // Parse stats if present (nested within same attributes)
    for (attr_type, payload) in AttrIter::new(data) {
        if attr_type == macsec_attr::RXSC_STATS {
            parse_rxsc_stats_attrs(payload, &mut rxsc)?;
        }
    }

    Ok(rxsc)
}

/// Parse RX SC statistics.
fn parse_rxsc_stats_attrs(data: &[u8], rxsc: &mut MacsecRxSc) -> Result<()> {
    for (attr_type, payload) in AttrIter::new(data) {
        match attr_type {
            t if t == macsec_rxsc_stats_attr::IN_PKTS_OK => {
                rxsc.stats_ok_pkts = get::u64_ne(payload)?;
            }
            t if t == macsec_rxsc_stats_attr::IN_PKTS_INVALID => {
                rxsc.stats_invalid_pkts = get::u64_ne(payload)?;
            }
            t if t == macsec_rxsc_stats_attr::IN_PKTS_NOT_VALID => {
                rxsc.stats_not_valid_pkts = get::u64_ne(payload)?;
            }
            t if t == macsec_rxsc_stats_attr::IN_OCTETS_VALIDATED => {
                rxsc.stats_validated_octets = get::u64_ne(payload)?;
            }
            t if t == macsec_rxsc_stats_attr::IN_OCTETS_DECRYPTED => {
                rxsc.stats_decrypted_octets = get::u64_ne(payload)?;
            }
            _ => {}
        }
    }
    Ok(())
}

/// Parse SA attributes, returns (an, active, pn, key_id).
fn parse_sa_attrs(data: &[u8]) -> Result<(u8, bool, u64, Option<[u8; 16]>)> {
    let mut an = 0u8;
    let mut active = false;
    let mut pn = 0u64;
    let mut key_id: Option<[u8; 16]> = None;

    for (attr_type, payload) in AttrIter::new(data) {
        match attr_type {
            t if t == macsec_sa_attr::AN => {
                an = get::u8(payload)?;
            }
            t if t == macsec_sa_attr::ACTIVE => {
                active = get::u8(payload)? != 0;
            }
            t if t == macsec_sa_attr::PN => {
                // PN can be u32 or u64 depending on XPN mode
                if payload.len() >= 8 {
                    pn = get::u64_ne(payload)?;
                } else if payload.len() >= 4 {
                    pn = get::u32_ne(payload)? as u64;
                }
            }
            t if t == macsec_sa_attr::KEYID => {
                if payload.len() >= 16 {
                    let mut id = [0u8; 16];
                    id.copy_from_slice(&payload[..16]);
                    key_id = Some(id);
                }
            }
            _ => {}
        }
    }

    Ok((an, active, pn, key_id))
}

/// Parse offload configuration.
fn parse_offload(data: &[u8], device: &mut MacsecDevice) -> Result<()> {
    for (attr_type, payload) in AttrIter::new(data) {
        if attr_type == macsec_offload_attr::TYPE {
            device.offload = MacsecOffload::from_u8(get::u8(payload)?);
        }
    }
    Ok(())
}
