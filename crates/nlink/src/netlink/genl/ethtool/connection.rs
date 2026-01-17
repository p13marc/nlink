//! Ethtool connection implementation for `Connection<Ethtool>`.
//!
//! This module provides methods for querying and configuring network device
//! settings using the ethtool netlink interface.

use super::bitset::EthtoolBitset;
use super::types::*;
use super::{
    ETHTOOL_GENL_NAME, ETHTOOL_GENL_VERSION, ETHTOOL_MCGRP_MONITOR, EthtoolChannelsAttr,
    EthtoolCmd, EthtoolCoalesceAttr, EthtoolFeaturesAttr, EthtoolHeaderAttr, EthtoolLinkinfoAttr,
    EthtoolLinkmodesAttr, EthtoolLinkstateAttr, EthtoolPauseAttr, EthtoolRingsAttr,
};
use crate::netlink::attr::{AttrIter, NLA_F_NESTED};
use crate::netlink::builder::MessageBuilder;
use crate::netlink::connection::Connection;
use crate::netlink::error::{Error, Result};
use crate::netlink::genl::{
    CtrlAttr, CtrlAttrMcastGrp, CtrlCmd, GENL_HDRLEN, GENL_ID_CTRL, GenlMsgHdr,
};
use crate::netlink::interface_ref::InterfaceRef;
use crate::netlink::message::{MessageIter, NLM_F_ACK, NLM_F_DUMP, NLM_F_REQUEST, NlMsgError};
use crate::netlink::protocol::{Ethtool, ProtocolState, Route};
use crate::netlink::socket::NetlinkSocket;

impl Connection<Ethtool> {
    /// Create a new ethtool connection.
    ///
    /// This resolves the ethtool GENL family ID during initialization.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use nlink::netlink::{Connection, Ethtool};
    ///
    /// let conn = Connection::<Ethtool>::new_async().await?;
    /// let state = conn.get_link_state("eth0").await?;
    /// println!("Link: {}", if state.link { "up" } else { "down" });
    /// ```
    pub async fn new_async() -> Result<Self> {
        let socket = NetlinkSocket::new(Ethtool::PROTOCOL)?;
        let (family_id, monitor_group_id) = resolve_ethtool_family(&socket).await?;

        let state = Ethtool {
            family_id,
            monitor_group_id,
        };
        Ok(Self::from_parts(socket, state))
    }

    /// Get the ethtool family ID.
    pub fn family_id(&self) -> u16 {
        self.state().family_id
    }

    /// Get the monitor multicast group ID (if available).
    pub fn monitor_group_id(&self) -> Option<u32> {
        self.state().monitor_group_id
    }

    /// Resolve an interface reference to a name.
    ///
    /// Ethtool uses interface names in its protocol, so we resolve
    /// indices back to names when needed.
    async fn resolve_interface_name(&self, iface: &InterfaceRef) -> Result<String> {
        match iface {
            InterfaceRef::Name(name) => Ok(name.clone()),
            InterfaceRef::Index(idx) => {
                let route_conn = Connection::<Route>::new()?;
                route_conn
                    .get_link_by_index(*idx)
                    .await?
                    .and_then(|l| l.name().map(|s| s.to_string()))
                    .ok_or_else(|| Error::InterfaceNotFound {
                        name: format!("ifindex {}", idx),
                    })
            }
        }
    }

    // =========================================================================
    // Link State
    // =========================================================================

    /// Get link state (carrier detection, signal quality).
    ///
    /// Accepts either an interface name or index via [`InterfaceRef`].
    ///
    /// # Example
    ///
    /// ```ignore
    /// use nlink::netlink::{Connection, Ethtool};
    ///
    /// let conn = Connection::<Ethtool>::new_async().await?;
    ///
    /// // By name
    /// let state = conn.get_link_state("eth0").await?;
    ///
    /// // By index
    /// let state = conn.get_link_state(5u32).await?;
    ///
    /// println!("Link detected: {}", state.link);
    /// ```
    pub async fn get_link_state(&self, iface: impl Into<InterfaceRef>) -> Result<LinkState> {
        let ifname = self.resolve_interface_name(&iface.into()).await?;
        self.get_link_state_by_name(&ifname).await
    }

    /// Get link state by interface name.
    pub async fn get_link_state_by_name(&self, ifname: &str) -> Result<LinkState> {
        let response = self.ethtool_get(EthtoolCmd::LinkstateGet, ifname).await?;

        let mut state = LinkState::default();

        if response.len() < GENL_HDRLEN {
            return Ok(state);
        }

        self.parse_link_state(&response[GENL_HDRLEN..], &mut state)?;
        Ok(state)
    }

    fn parse_link_state(&self, data: &[u8], state: &mut LinkState) -> Result<()> {
        for (attr_type, payload) in AttrIter::new(data) {
            match attr_type {
                t if t == EthtoolLinkstateAttr::Header as u16 => {
                    self.parse_header(payload, &mut state.ifname, &mut state.ifindex)?;
                }
                t if t == EthtoolLinkstateAttr::Link as u16 => {
                    if !payload.is_empty() {
                        state.link = payload[0] != 0;
                    }
                }
                t if t == EthtoolLinkstateAttr::Sqi as u16 => {
                    if payload.len() >= 4 {
                        state.sqi = Some(u32::from_ne_bytes(payload[..4].try_into().unwrap()));
                    }
                }
                t if t == EthtoolLinkstateAttr::SqiMax as u16 => {
                    if payload.len() >= 4 {
                        state.sqi_max = Some(u32::from_ne_bytes(payload[..4].try_into().unwrap()));
                    }
                }
                t if t == EthtoolLinkstateAttr::ExtState as u16 => {
                    if !payload.is_empty() {
                        state.ext_state = Some(LinkExtState::from_u8(payload[0]));
                    }
                }
                t if t == EthtoolLinkstateAttr::ExtSubstate as u16 => {
                    if !payload.is_empty() {
                        state.ext_substate = Some(payload[0]);
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }

    // =========================================================================
    // Link Info
    // =========================================================================

    /// Get link info (port type, transceiver, MDI-X).
    ///
    /// Accepts either an interface name or index via [`InterfaceRef`].
    ///
    /// # Example
    ///
    /// ```ignore
    /// use nlink::netlink::{Connection, Ethtool};
    ///
    /// let conn = Connection::<Ethtool>::new_async().await?;
    ///
    /// // By name
    /// let info = conn.get_link_info("eth0").await?;
    ///
    /// // By index
    /// let info = conn.get_link_info(5u32).await?;
    ///
    /// println!("Port: {:?}", info.port);
    /// println!("Transceiver: {:?}", info.transceiver);
    /// ```
    pub async fn get_link_info(&self, iface: impl Into<InterfaceRef>) -> Result<LinkInfo> {
        let ifname = self.resolve_interface_name(&iface.into()).await?;
        self.get_link_info_by_name(&ifname).await
    }

    /// Get link info by interface name.
    pub async fn get_link_info_by_name(&self, ifname: &str) -> Result<LinkInfo> {
        let response = self.ethtool_get(EthtoolCmd::LinkinfoGet, ifname).await?;

        let mut info = LinkInfo::default();

        if response.len() < GENL_HDRLEN {
            return Ok(info);
        }

        self.parse_link_info(&response[GENL_HDRLEN..], &mut info)?;
        Ok(info)
    }

    fn parse_link_info(&self, data: &[u8], info: &mut LinkInfo) -> Result<()> {
        for (attr_type, payload) in AttrIter::new(data) {
            match attr_type {
                t if t == EthtoolLinkinfoAttr::Header as u16 => {
                    self.parse_header(payload, &mut info.ifname, &mut info.ifindex)?;
                }
                t if t == EthtoolLinkinfoAttr::Port as u16 => {
                    if !payload.is_empty() {
                        info.port = Some(Port::from_u8(payload[0]));
                    }
                }
                t if t == EthtoolLinkinfoAttr::Phyaddr as u16 => {
                    if !payload.is_empty() {
                        info.phyaddr = Some(payload[0]);
                    }
                }
                t if t == EthtoolLinkinfoAttr::TpMdiCtrl as u16 => {
                    if !payload.is_empty() {
                        info.tp_mdix_ctrl = Some(MdiX::from_u8(payload[0]));
                    }
                }
                t if t == EthtoolLinkinfoAttr::TpMdix as u16 => {
                    if !payload.is_empty() {
                        info.tp_mdix = Some(MdiX::from_u8(payload[0]));
                    }
                }
                t if t == EthtoolLinkinfoAttr::Transceiver as u16 => {
                    if !payload.is_empty() {
                        info.transceiver = Some(Transceiver::from_u8(payload[0]));
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }

    // =========================================================================
    // Link Modes
    // =========================================================================

    /// Get link modes (speed, duplex, autonegotiation).
    ///
    /// Accepts either an interface name or index via [`InterfaceRef`].
    ///
    /// # Example
    ///
    /// ```ignore
    /// use nlink::netlink::{Connection, Ethtool};
    ///
    /// let conn = Connection::<Ethtool>::new_async().await?;
    ///
    /// // By name
    /// let modes = conn.get_link_modes("eth0").await?;
    ///
    /// // By index
    /// let modes = conn.get_link_modes(5u32).await?;
    ///
    /// println!("Speed: {:?} Mb/s", modes.speed);
    /// println!("Duplex: {:?}", modes.duplex);
    /// println!("Autoneg: {}", modes.autoneg);
    /// println!("Supported modes: {:?}", modes.supported_modes());
    /// ```
    pub async fn get_link_modes(&self, iface: impl Into<InterfaceRef>) -> Result<LinkModes> {
        let ifname = self.resolve_interface_name(&iface.into()).await?;
        self.get_link_modes_by_name(&ifname).await
    }

    /// Get link modes by interface name.
    pub async fn get_link_modes_by_name(&self, ifname: &str) -> Result<LinkModes> {
        let response = self.ethtool_get(EthtoolCmd::LinkmodesGet, ifname).await?;

        let mut modes = LinkModes::default();

        if response.len() < GENL_HDRLEN {
            return Ok(modes);
        }

        self.parse_link_modes(&response[GENL_HDRLEN..], &mut modes)?;
        Ok(modes)
    }

    /// Set link modes (speed, duplex, autonegotiation).
    ///
    /// Accepts either an interface name or index via [`InterfaceRef`].
    ///
    /// # Example
    ///
    /// ```ignore
    /// use nlink::netlink::{Connection, Ethtool};
    /// use nlink::netlink::genl::ethtool::Duplex;
    ///
    /// let conn = Connection::<Ethtool>::new_async().await?;
    ///
    /// // Force 1000Mbps full duplex (by name)
    /// conn.set_link_modes("eth0", |m| {
    ///     m.autoneg(false)
    ///      .speed(1000)
    ///      .duplex(Duplex::Full)
    /// }).await?;
    ///
    /// // By index
    /// conn.set_link_modes(5u32, |m| {
    ///     m.autoneg(true)
    ///      .advertise("1000baseT/Full")
    ///      .advertise("100baseT/Full")
    /// }).await?;
    /// ```
    pub async fn set_link_modes(
        &self,
        iface: impl Into<InterfaceRef>,
        configure: impl FnOnce(LinkModesBuilder) -> LinkModesBuilder,
    ) -> Result<()> {
        let ifname = self.resolve_interface_name(&iface.into()).await?;
        self.set_link_modes_by_name(&ifname, configure).await
    }

    /// Set link modes by interface name.
    pub async fn set_link_modes_by_name(
        &self,
        ifname: &str,
        configure: impl FnOnce(LinkModesBuilder) -> LinkModesBuilder,
    ) -> Result<()> {
        let builder = configure(LinkModesBuilder::new());
        self.apply_link_modes(ifname, &builder).await
    }

    fn parse_link_modes(&self, data: &[u8], modes: &mut LinkModes) -> Result<()> {
        for (attr_type, payload) in AttrIter::new(data) {
            match attr_type {
                t if t == EthtoolLinkmodesAttr::Header as u16 => {
                    self.parse_header(payload, &mut modes.ifname, &mut modes.ifindex)?;
                }
                t if t == EthtoolLinkmodesAttr::Autoneg as u16 => {
                    if !payload.is_empty() {
                        modes.autoneg = payload[0] != 0;
                    }
                }
                t if t == EthtoolLinkmodesAttr::Speed as u16 => {
                    if payload.len() >= 4 {
                        let speed = u32::from_ne_bytes(payload[..4].try_into().unwrap());
                        // 0xFFFFFFFF means unknown
                        if speed != 0xFFFFFFFF {
                            modes.speed = Some(speed);
                        }
                    }
                }
                t if t == EthtoolLinkmodesAttr::Duplex as u16 => {
                    if !payload.is_empty() {
                        modes.duplex = Some(Duplex::from_u8(payload[0]));
                    }
                }
                t if t == EthtoolLinkmodesAttr::Lanes as u16 => {
                    if payload.len() >= 4 {
                        modes.lanes = Some(u32::from_ne_bytes(payload[..4].try_into().unwrap()));
                    }
                }
                t if t == EthtoolLinkmodesAttr::MasterSlaveCfg as u16 => {
                    if !payload.is_empty() {
                        modes.master_slave_cfg = Some(payload[0]);
                    }
                }
                t if t == EthtoolLinkmodesAttr::MasterSlaveState as u16 => {
                    if !payload.is_empty() {
                        modes.master_slave_state = Some(payload[0]);
                    }
                }
                t if t == EthtoolLinkmodesAttr::Supported as u16 => {
                    modes.supported = EthtoolBitset::parse(payload)?;
                }
                t if t == EthtoolLinkmodesAttr::Advertised as u16 => {
                    modes.advertised = EthtoolBitset::parse(payload)?;
                }
                t if t == EthtoolLinkmodesAttr::Peer as u16 => {
                    modes.peer = EthtoolBitset::parse(payload)?;
                }
                _ => {}
            }
        }
        Ok(())
    }

    async fn apply_link_modes(&self, ifname: &str, config: &LinkModesBuilder) -> Result<()> {
        self.ethtool_set(EthtoolCmd::LinkmodesSet, ifname, |builder| {
            if let Some(autoneg) = config.autoneg {
                builder.append_attr_u8(EthtoolLinkmodesAttr::Autoneg as u16, autoneg as u8);
            }
            if let Some(speed) = config.speed {
                builder.append_attr_u32(EthtoolLinkmodesAttr::Speed as u16, speed);
            }
            if let Some(duplex) = config.duplex {
                builder.append_attr_u8(EthtoolLinkmodesAttr::Duplex as u16, duplex.to_u8());
            }
            if let Some(lanes) = config.lanes {
                builder.append_attr_u32(EthtoolLinkmodesAttr::Lanes as u16, lanes);
            }
            // TODO: Handle advertised modes bitset
        })
        .await
    }

    // =========================================================================
    // Features
    // =========================================================================

    /// Get device features (offloads).
    ///
    /// Accepts either an interface name or index via [`InterfaceRef`].
    ///
    /// # Example
    ///
    /// ```ignore
    /// use nlink::netlink::{Connection, Ethtool};
    ///
    /// let conn = Connection::<Ethtool>::new_async().await?;
    ///
    /// // By name
    /// let features = conn.get_features("eth0").await?;
    ///
    /// // By index
    /// let features = conn.get_features(5u32).await?;
    ///
    /// println!("TSO: {}", features.is_active("tx-tcp-segmentation"));
    /// println!("GRO: {}", features.is_active("rx-gro"));
    ///
    /// for (name, enabled) in features.iter() {
    ///     println!("{}: {}", name, if enabled { "on" } else { "off" });
    /// }
    /// ```
    pub async fn get_features(&self, iface: impl Into<InterfaceRef>) -> Result<Features> {
        let ifname = self.resolve_interface_name(&iface.into()).await?;
        self.get_features_by_name(&ifname).await
    }

    /// Get device features by interface name.
    pub async fn get_features_by_name(&self, ifname: &str) -> Result<Features> {
        let response = self.ethtool_get(EthtoolCmd::FeaturesGet, ifname).await?;

        let mut features = Features::default();

        if response.len() < GENL_HDRLEN {
            return Ok(features);
        }

        self.parse_features(&response[GENL_HDRLEN..], &mut features)?;
        Ok(features)
    }

    /// Set device features (offloads).
    ///
    /// Accepts either an interface name or index via [`InterfaceRef`].
    ///
    /// # Example
    ///
    /// ```ignore
    /// use nlink::netlink::{Connection, Ethtool};
    ///
    /// let conn = Connection::<Ethtool>::new_async().await?;
    ///
    /// // By name
    /// conn.set_features("eth0", |f| {
    ///     f.enable("tx-checksumming")
    ///      .disable("rx-gro")
    /// }).await?;
    ///
    /// // By index
    /// conn.set_features(5u32, |f| {
    ///     f.enable("tx-checksumming")
    /// }).await?;
    /// ```
    pub async fn set_features(
        &self,
        iface: impl Into<InterfaceRef>,
        configure: impl FnOnce(FeaturesBuilder) -> FeaturesBuilder,
    ) -> Result<()> {
        let ifname = self.resolve_interface_name(&iface.into()).await?;
        self.set_features_by_name(&ifname, configure).await
    }

    /// Set device features by interface name.
    pub async fn set_features_by_name(
        &self,
        ifname: &str,
        configure: impl FnOnce(FeaturesBuilder) -> FeaturesBuilder,
    ) -> Result<()> {
        let builder = configure(FeaturesBuilder::new());
        self.apply_features(ifname, &builder).await
    }

    fn parse_features(&self, data: &[u8], features: &mut Features) -> Result<()> {
        for (attr_type, payload) in AttrIter::new(data) {
            match attr_type {
                t if t == EthtoolFeaturesAttr::Header as u16 => {
                    self.parse_header(payload, &mut features.ifname, &mut features.ifindex)?;
                }
                t if t == EthtoolFeaturesAttr::Hw as u16 => {
                    features.hw = EthtoolBitset::parse(payload)?;
                }
                t if t == EthtoolFeaturesAttr::Wanted as u16 => {
                    features.wanted = EthtoolBitset::parse(payload)?;
                }
                t if t == EthtoolFeaturesAttr::Active as u16 => {
                    features.active = EthtoolBitset::parse(payload)?;
                }
                t if t == EthtoolFeaturesAttr::NoChange as u16 => {
                    features.nochange = EthtoolBitset::parse(payload)?;
                }
                _ => {}
            }
        }
        Ok(())
    }

    async fn apply_features(&self, ifname: &str, config: &FeaturesBuilder) -> Result<()> {
        // Build a bitset with the changes
        let mut wanted = EthtoolBitset::new();
        for name in &config.enable {
            wanted.set(name, true);
        }
        for name in &config.disable {
            wanted.set(name, false);
        }

        self.ethtool_set(EthtoolCmd::FeaturesSet, ifname, |builder| {
            // TODO: Properly encode bitset as ETHTOOL_A_FEATURES_WANTED
            let _ = wanted;
            let _ = builder;
        })
        .await
    }

    // =========================================================================
    // Rings
    // =========================================================================

    /// Get ring buffer sizes.
    ///
    /// Accepts either an interface name or index via [`InterfaceRef`].
    ///
    /// # Example
    ///
    /// ```ignore
    /// use nlink::netlink::{Connection, Ethtool};
    ///
    /// let conn = Connection::<Ethtool>::new_async().await?;
    ///
    /// // By name
    /// let rings = conn.get_rings("eth0").await?;
    ///
    /// // By index
    /// let rings = conn.get_rings(5u32).await?;
    ///
    /// println!("RX: {:?} (max {:?})", rings.rx, rings.rx_max);
    /// println!("TX: {:?} (max {:?})", rings.tx, rings.tx_max);
    /// ```
    pub async fn get_rings(&self, iface: impl Into<InterfaceRef>) -> Result<Rings> {
        let ifname = self.resolve_interface_name(&iface.into()).await?;
        self.get_rings_by_name(&ifname).await
    }

    /// Get ring buffer sizes by interface name.
    pub async fn get_rings_by_name(&self, ifname: &str) -> Result<Rings> {
        let response = self.ethtool_get(EthtoolCmd::RingsGet, ifname).await?;

        let mut rings = Rings::default();

        if response.len() < GENL_HDRLEN {
            return Ok(rings);
        }

        self.parse_rings(&response[GENL_HDRLEN..], &mut rings)?;
        Ok(rings)
    }

    /// Set ring buffer sizes.
    ///
    /// Accepts either an interface name or index via [`InterfaceRef`].
    ///
    /// # Example
    ///
    /// ```ignore
    /// use nlink::netlink::{Connection, Ethtool};
    ///
    /// let conn = Connection::<Ethtool>::new_async().await?;
    ///
    /// // By name
    /// conn.set_rings("eth0", |r| {
    ///     r.rx(4096).tx(4096)
    /// }).await?;
    ///
    /// // By index
    /// conn.set_rings(5u32, |r| {
    ///     r.rx(4096).tx(4096)
    /// }).await?;
    /// ```
    pub async fn set_rings(
        &self,
        iface: impl Into<InterfaceRef>,
        configure: impl FnOnce(RingsBuilder) -> RingsBuilder,
    ) -> Result<()> {
        let ifname = self.resolve_interface_name(&iface.into()).await?;
        self.set_rings_by_name(&ifname, configure).await
    }

    /// Set ring buffer sizes by interface name.
    pub async fn set_rings_by_name(
        &self,
        ifname: &str,
        configure: impl FnOnce(RingsBuilder) -> RingsBuilder,
    ) -> Result<()> {
        let builder = configure(RingsBuilder::new());
        self.apply_rings(ifname, &builder).await
    }

    fn parse_rings(&self, data: &[u8], rings: &mut Rings) -> Result<()> {
        for (attr_type, payload) in AttrIter::new(data) {
            match attr_type {
                t if t == EthtoolRingsAttr::Header as u16 => {
                    self.parse_header(payload, &mut rings.ifname, &mut rings.ifindex)?;
                }
                t if t == EthtoolRingsAttr::RxMax as u16 => {
                    if payload.len() >= 4 {
                        rings.rx_max = Some(u32::from_ne_bytes(payload[..4].try_into().unwrap()));
                    }
                }
                t if t == EthtoolRingsAttr::RxMiniMax as u16 => {
                    if payload.len() >= 4 {
                        rings.rx_mini_max =
                            Some(u32::from_ne_bytes(payload[..4].try_into().unwrap()));
                    }
                }
                t if t == EthtoolRingsAttr::RxJumboMax as u16 => {
                    if payload.len() >= 4 {
                        rings.rx_jumbo_max =
                            Some(u32::from_ne_bytes(payload[..4].try_into().unwrap()));
                    }
                }
                t if t == EthtoolRingsAttr::TxMax as u16 => {
                    if payload.len() >= 4 {
                        rings.tx_max = Some(u32::from_ne_bytes(payload[..4].try_into().unwrap()));
                    }
                }
                t if t == EthtoolRingsAttr::Rx as u16 => {
                    if payload.len() >= 4 {
                        rings.rx = Some(u32::from_ne_bytes(payload[..4].try_into().unwrap()));
                    }
                }
                t if t == EthtoolRingsAttr::RxMini as u16 => {
                    if payload.len() >= 4 {
                        rings.rx_mini = Some(u32::from_ne_bytes(payload[..4].try_into().unwrap()));
                    }
                }
                t if t == EthtoolRingsAttr::RxJumbo as u16 => {
                    if payload.len() >= 4 {
                        rings.rx_jumbo = Some(u32::from_ne_bytes(payload[..4].try_into().unwrap()));
                    }
                }
                t if t == EthtoolRingsAttr::Tx as u16 => {
                    if payload.len() >= 4 {
                        rings.tx = Some(u32::from_ne_bytes(payload[..4].try_into().unwrap()));
                    }
                }
                t if t == EthtoolRingsAttr::RxBufLen as u16 => {
                    if payload.len() >= 4 {
                        rings.rx_buf_len =
                            Some(u32::from_ne_bytes(payload[..4].try_into().unwrap()));
                    }
                }
                t if t == EthtoolRingsAttr::CqeSize as u16 => {
                    if payload.len() >= 4 {
                        rings.cqe_size = Some(u32::from_ne_bytes(payload[..4].try_into().unwrap()));
                    }
                }
                t if t == EthtoolRingsAttr::TxPush as u16 => {
                    if !payload.is_empty() {
                        rings.tx_push = Some(payload[0] != 0);
                    }
                }
                t if t == EthtoolRingsAttr::RxPush as u16 => {
                    if !payload.is_empty() {
                        rings.rx_push = Some(payload[0] != 0);
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }

    async fn apply_rings(&self, ifname: &str, config: &RingsBuilder) -> Result<()> {
        self.ethtool_set(EthtoolCmd::RingsSet, ifname, |builder| {
            if let Some(rx) = config.rx {
                builder.append_attr_u32(EthtoolRingsAttr::Rx as u16, rx);
            }
            if let Some(rx_mini) = config.rx_mini {
                builder.append_attr_u32(EthtoolRingsAttr::RxMini as u16, rx_mini);
            }
            if let Some(rx_jumbo) = config.rx_jumbo {
                builder.append_attr_u32(EthtoolRingsAttr::RxJumbo as u16, rx_jumbo);
            }
            if let Some(tx) = config.tx {
                builder.append_attr_u32(EthtoolRingsAttr::Tx as u16, tx);
            }
        })
        .await
    }

    // =========================================================================
    // Channels
    // =========================================================================

    /// Get channel counts (RX/TX queues).
    ///
    /// Accepts either an interface name or index via [`InterfaceRef`].
    ///
    /// # Example
    ///
    /// ```ignore
    /// use nlink::netlink::{Connection, Ethtool};
    ///
    /// let conn = Connection::<Ethtool>::new_async().await?;
    ///
    /// // By name
    /// let channels = conn.get_channels("eth0").await?;
    ///
    /// // By index
    /// let channels = conn.get_channels(5u32).await?;
    ///
    /// println!("RX: {:?} (max {:?})", channels.rx_count, channels.rx_max);
    /// println!("TX: {:?} (max {:?})", channels.tx_count, channels.tx_max);
    /// println!("Combined: {:?} (max {:?})", channels.combined_count, channels.combined_max);
    /// ```
    pub async fn get_channels(&self, iface: impl Into<InterfaceRef>) -> Result<Channels> {
        let ifname = self.resolve_interface_name(&iface.into()).await?;
        self.get_channels_by_name(&ifname).await
    }

    /// Get channel counts by interface name.
    pub async fn get_channels_by_name(&self, ifname: &str) -> Result<Channels> {
        let response = self.ethtool_get(EthtoolCmd::ChannelsGet, ifname).await?;

        let mut channels = Channels::default();

        if response.len() < GENL_HDRLEN {
            return Ok(channels);
        }

        self.parse_channels(&response[GENL_HDRLEN..], &mut channels)?;
        Ok(channels)
    }

    /// Set channel counts.
    ///
    /// Accepts either an interface name or index via [`InterfaceRef`].
    ///
    /// # Example
    ///
    /// ```ignore
    /// use nlink::netlink::{Connection, Ethtool};
    ///
    /// let conn = Connection::<Ethtool>::new_async().await?;
    ///
    /// // By name
    /// conn.set_channels("eth0", |c| {
    ///     c.combined(4)
    /// }).await?;
    ///
    /// // By index
    /// conn.set_channels(5u32, |c| {
    ///     c.combined(4)
    /// }).await?;
    /// ```
    pub async fn set_channels(
        &self,
        iface: impl Into<InterfaceRef>,
        configure: impl FnOnce(ChannelsBuilder) -> ChannelsBuilder,
    ) -> Result<()> {
        let ifname = self.resolve_interface_name(&iface.into()).await?;
        self.set_channels_by_name(&ifname, configure).await
    }

    /// Set channel counts by interface name.
    pub async fn set_channels_by_name(
        &self,
        ifname: &str,
        configure: impl FnOnce(ChannelsBuilder) -> ChannelsBuilder,
    ) -> Result<()> {
        let builder = configure(ChannelsBuilder::new());
        self.apply_channels(ifname, &builder).await
    }

    fn parse_channels(&self, data: &[u8], channels: &mut Channels) -> Result<()> {
        for (attr_type, payload) in AttrIter::new(data) {
            match attr_type {
                t if t == EthtoolChannelsAttr::Header as u16 => {
                    self.parse_header(payload, &mut channels.ifname, &mut channels.ifindex)?;
                }
                t if t == EthtoolChannelsAttr::RxMax as u16 => {
                    if payload.len() >= 4 {
                        channels.rx_max =
                            Some(u32::from_ne_bytes(payload[..4].try_into().unwrap()));
                    }
                }
                t if t == EthtoolChannelsAttr::TxMax as u16 => {
                    if payload.len() >= 4 {
                        channels.tx_max =
                            Some(u32::from_ne_bytes(payload[..4].try_into().unwrap()));
                    }
                }
                t if t == EthtoolChannelsAttr::OtherMax as u16 => {
                    if payload.len() >= 4 {
                        channels.other_max =
                            Some(u32::from_ne_bytes(payload[..4].try_into().unwrap()));
                    }
                }
                t if t == EthtoolChannelsAttr::CombinedMax as u16 => {
                    if payload.len() >= 4 {
                        channels.combined_max =
                            Some(u32::from_ne_bytes(payload[..4].try_into().unwrap()));
                    }
                }
                t if t == EthtoolChannelsAttr::RxCount as u16 => {
                    if payload.len() >= 4 {
                        channels.rx_count =
                            Some(u32::from_ne_bytes(payload[..4].try_into().unwrap()));
                    }
                }
                t if t == EthtoolChannelsAttr::TxCount as u16 => {
                    if payload.len() >= 4 {
                        channels.tx_count =
                            Some(u32::from_ne_bytes(payload[..4].try_into().unwrap()));
                    }
                }
                t if t == EthtoolChannelsAttr::OtherCount as u16 => {
                    if payload.len() >= 4 {
                        channels.other_count =
                            Some(u32::from_ne_bytes(payload[..4].try_into().unwrap()));
                    }
                }
                t if t == EthtoolChannelsAttr::CombinedCount as u16 => {
                    if payload.len() >= 4 {
                        channels.combined_count =
                            Some(u32::from_ne_bytes(payload[..4].try_into().unwrap()));
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }

    async fn apply_channels(&self, ifname: &str, config: &ChannelsBuilder) -> Result<()> {
        self.ethtool_set(EthtoolCmd::ChannelsSet, ifname, |builder| {
            if let Some(rx) = config.rx {
                builder.append_attr_u32(EthtoolChannelsAttr::RxCount as u16, rx);
            }
            if let Some(tx) = config.tx {
                builder.append_attr_u32(EthtoolChannelsAttr::TxCount as u16, tx);
            }
            if let Some(other) = config.other {
                builder.append_attr_u32(EthtoolChannelsAttr::OtherCount as u16, other);
            }
            if let Some(combined) = config.combined {
                builder.append_attr_u32(EthtoolChannelsAttr::CombinedCount as u16, combined);
            }
        })
        .await
    }

    // =========================================================================
    // Coalesce
    // =========================================================================

    /// Get interrupt coalescing parameters.
    ///
    /// Accepts either an interface name or index via [`InterfaceRef`].
    ///
    /// # Example
    ///
    /// ```ignore
    /// use nlink::netlink::{Connection, Ethtool};
    ///
    /// let conn = Connection::<Ethtool>::new_async().await?;
    ///
    /// // By name
    /// let coalesce = conn.get_coalesce("eth0").await?;
    ///
    /// // By index
    /// let coalesce = conn.get_coalesce(5u32).await?;
    ///
    /// println!("RX usecs: {:?}", coalesce.rx_usecs);
    /// println!("TX usecs: {:?}", coalesce.tx_usecs);
    /// println!("Adaptive RX: {:?}", coalesce.use_adaptive_rx);
    /// ```
    pub async fn get_coalesce(&self, iface: impl Into<InterfaceRef>) -> Result<Coalesce> {
        let ifname = self.resolve_interface_name(&iface.into()).await?;
        self.get_coalesce_by_name(&ifname).await
    }

    /// Get interrupt coalescing parameters by interface name.
    pub async fn get_coalesce_by_name(&self, ifname: &str) -> Result<Coalesce> {
        let response = self.ethtool_get(EthtoolCmd::CoalesceGet, ifname).await?;

        let mut coalesce = Coalesce::default();

        if response.len() < GENL_HDRLEN {
            return Ok(coalesce);
        }

        self.parse_coalesce(&response[GENL_HDRLEN..], &mut coalesce)?;
        Ok(coalesce)
    }

    /// Set interrupt coalescing parameters.
    ///
    /// Accepts either an interface name or index via [`InterfaceRef`].
    ///
    /// # Example
    ///
    /// ```ignore
    /// use nlink::netlink::{Connection, Ethtool};
    ///
    /// let conn = Connection::<Ethtool>::new_async().await?;
    ///
    /// // By name
    /// conn.set_coalesce("eth0", |c| {
    ///     c.rx_usecs(100)
    ///      .tx_usecs(100)
    ///      .use_adaptive_rx(true)
    /// }).await?;
    ///
    /// // By index
    /// conn.set_coalesce(5u32, |c| {
    ///     c.rx_usecs(100)
    /// }).await?;
    /// ```
    pub async fn set_coalesce(
        &self,
        iface: impl Into<InterfaceRef>,
        configure: impl FnOnce(CoalesceBuilder) -> CoalesceBuilder,
    ) -> Result<()> {
        let ifname = self.resolve_interface_name(&iface.into()).await?;
        self.set_coalesce_by_name(&ifname, configure).await
    }

    /// Set interrupt coalescing parameters by interface name.
    pub async fn set_coalesce_by_name(
        &self,
        ifname: &str,
        configure: impl FnOnce(CoalesceBuilder) -> CoalesceBuilder,
    ) -> Result<()> {
        let builder = configure(CoalesceBuilder::new());
        self.apply_coalesce(ifname, &builder).await
    }

    fn parse_coalesce(&self, data: &[u8], coalesce: &mut Coalesce) -> Result<()> {
        for (attr_type, payload) in AttrIter::new(data) {
            match attr_type {
                t if t == EthtoolCoalesceAttr::Header as u16 => {
                    self.parse_header(payload, &mut coalesce.ifname, &mut coalesce.ifindex)?;
                }
                t if t == EthtoolCoalesceAttr::RxUsecs as u16 => {
                    if payload.len() >= 4 {
                        coalesce.rx_usecs =
                            Some(u32::from_ne_bytes(payload[..4].try_into().unwrap()));
                    }
                }
                t if t == EthtoolCoalesceAttr::RxMaxFrames as u16 => {
                    if payload.len() >= 4 {
                        coalesce.rx_max_frames =
                            Some(u32::from_ne_bytes(payload[..4].try_into().unwrap()));
                    }
                }
                t if t == EthtoolCoalesceAttr::RxUsecsIrq as u16 => {
                    if payload.len() >= 4 {
                        coalesce.rx_usecs_irq =
                            Some(u32::from_ne_bytes(payload[..4].try_into().unwrap()));
                    }
                }
                t if t == EthtoolCoalesceAttr::RxMaxFramesIrq as u16 => {
                    if payload.len() >= 4 {
                        coalesce.rx_max_frames_irq =
                            Some(u32::from_ne_bytes(payload[..4].try_into().unwrap()));
                    }
                }
                t if t == EthtoolCoalesceAttr::TxUsecs as u16 => {
                    if payload.len() >= 4 {
                        coalesce.tx_usecs =
                            Some(u32::from_ne_bytes(payload[..4].try_into().unwrap()));
                    }
                }
                t if t == EthtoolCoalesceAttr::TxMaxFrames as u16 => {
                    if payload.len() >= 4 {
                        coalesce.tx_max_frames =
                            Some(u32::from_ne_bytes(payload[..4].try_into().unwrap()));
                    }
                }
                t if t == EthtoolCoalesceAttr::TxUsecsIrq as u16 => {
                    if payload.len() >= 4 {
                        coalesce.tx_usecs_irq =
                            Some(u32::from_ne_bytes(payload[..4].try_into().unwrap()));
                    }
                }
                t if t == EthtoolCoalesceAttr::TxMaxFramesIrq as u16 => {
                    if payload.len() >= 4 {
                        coalesce.tx_max_frames_irq =
                            Some(u32::from_ne_bytes(payload[..4].try_into().unwrap()));
                    }
                }
                t if t == EthtoolCoalesceAttr::StatsBlockUsecs as u16 => {
                    if payload.len() >= 4 {
                        coalesce.stats_block_usecs =
                            Some(u32::from_ne_bytes(payload[..4].try_into().unwrap()));
                    }
                }
                t if t == EthtoolCoalesceAttr::UseAdaptiveRx as u16 => {
                    if !payload.is_empty() {
                        coalesce.use_adaptive_rx = Some(payload[0] != 0);
                    }
                }
                t if t == EthtoolCoalesceAttr::UseAdaptiveTx as u16 => {
                    if !payload.is_empty() {
                        coalesce.use_adaptive_tx = Some(payload[0] != 0);
                    }
                }
                t if t == EthtoolCoalesceAttr::PktRateLow as u16 => {
                    if payload.len() >= 4 {
                        coalesce.pkt_rate_low =
                            Some(u32::from_ne_bytes(payload[..4].try_into().unwrap()));
                    }
                }
                t if t == EthtoolCoalesceAttr::PktRateHigh as u16 => {
                    if payload.len() >= 4 {
                        coalesce.pkt_rate_high =
                            Some(u32::from_ne_bytes(payload[..4].try_into().unwrap()));
                    }
                }
                t if t == EthtoolCoalesceAttr::RateSampleInterval as u16 => {
                    if payload.len() >= 4 {
                        coalesce.rate_sample_interval =
                            Some(u32::from_ne_bytes(payload[..4].try_into().unwrap()));
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }

    async fn apply_coalesce(&self, ifname: &str, config: &CoalesceBuilder) -> Result<()> {
        self.ethtool_set(EthtoolCmd::CoalesceSet, ifname, |builder| {
            if let Some(v) = config.rx_usecs {
                builder.append_attr_u32(EthtoolCoalesceAttr::RxUsecs as u16, v);
            }
            if let Some(v) = config.rx_max_frames {
                builder.append_attr_u32(EthtoolCoalesceAttr::RxMaxFrames as u16, v);
            }
            if let Some(v) = config.tx_usecs {
                builder.append_attr_u32(EthtoolCoalesceAttr::TxUsecs as u16, v);
            }
            if let Some(v) = config.tx_max_frames {
                builder.append_attr_u32(EthtoolCoalesceAttr::TxMaxFrames as u16, v);
            }
            if let Some(v) = config.use_adaptive_rx {
                builder.append_attr_u8(EthtoolCoalesceAttr::UseAdaptiveRx as u16, v as u8);
            }
            if let Some(v) = config.use_adaptive_tx {
                builder.append_attr_u8(EthtoolCoalesceAttr::UseAdaptiveTx as u16, v as u8);
            }
        })
        .await
    }

    // =========================================================================
    // Pause
    // =========================================================================

    /// Get pause/flow control settings.
    ///
    /// Accepts either an interface name or index via [`InterfaceRef`].
    ///
    /// # Example
    ///
    /// ```ignore
    /// use nlink::netlink::{Connection, Ethtool};
    ///
    /// let conn = Connection::<Ethtool>::new_async().await?;
    ///
    /// // By name
    /// let pause = conn.get_pause("eth0").await?;
    ///
    /// // By index
    /// let pause = conn.get_pause(5u32).await?;
    ///
    /// println!("Autoneg: {:?}", pause.autoneg);
    /// println!("RX pause: {:?}", pause.rx);
    /// println!("TX pause: {:?}", pause.tx);
    /// ```
    pub async fn get_pause(&self, iface: impl Into<InterfaceRef>) -> Result<Pause> {
        let ifname = self.resolve_interface_name(&iface.into()).await?;
        self.get_pause_by_name(&ifname).await
    }

    /// Get pause/flow control settings by interface name.
    pub async fn get_pause_by_name(&self, ifname: &str) -> Result<Pause> {
        let response = self.ethtool_get(EthtoolCmd::PauseGet, ifname).await?;

        let mut pause = Pause::default();

        if response.len() < GENL_HDRLEN {
            return Ok(pause);
        }

        self.parse_pause(&response[GENL_HDRLEN..], &mut pause)?;
        Ok(pause)
    }

    /// Set pause/flow control settings.
    ///
    /// Accepts either an interface name or index via [`InterfaceRef`].
    ///
    /// # Example
    ///
    /// ```ignore
    /// use nlink::netlink::{Connection, Ethtool};
    ///
    /// let conn = Connection::<Ethtool>::new_async().await?;
    ///
    /// // By name
    /// conn.set_pause("eth0", |p| {
    ///     p.autoneg(true)
    ///      .rx(true)
    ///      .tx(true)
    /// }).await?;
    ///
    /// // By index
    /// conn.set_pause(5u32, |p| {
    ///     p.autoneg(true)
    /// }).await?;
    /// ```
    pub async fn set_pause(
        &self,
        iface: impl Into<InterfaceRef>,
        configure: impl FnOnce(PauseBuilder) -> PauseBuilder,
    ) -> Result<()> {
        let ifname = self.resolve_interface_name(&iface.into()).await?;
        self.set_pause_by_name(&ifname, configure).await
    }

    /// Set pause/flow control settings by interface name.
    pub async fn set_pause_by_name(
        &self,
        ifname: &str,
        configure: impl FnOnce(PauseBuilder) -> PauseBuilder,
    ) -> Result<()> {
        let builder = configure(PauseBuilder::new());
        self.apply_pause(ifname, &builder).await
    }

    fn parse_pause(&self, data: &[u8], pause: &mut Pause) -> Result<()> {
        for (attr_type, payload) in AttrIter::new(data) {
            match attr_type {
                t if t == EthtoolPauseAttr::Header as u16 => {
                    self.parse_header(payload, &mut pause.ifname, &mut pause.ifindex)?;
                }
                t if t == EthtoolPauseAttr::Autoneg as u16 => {
                    if !payload.is_empty() {
                        pause.autoneg = Some(payload[0] != 0);
                    }
                }
                t if t == EthtoolPauseAttr::Rx as u16 => {
                    if !payload.is_empty() {
                        pause.rx = Some(payload[0] != 0);
                    }
                }
                t if t == EthtoolPauseAttr::Tx as u16 => {
                    if !payload.is_empty() {
                        pause.tx = Some(payload[0] != 0);
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }

    async fn apply_pause(&self, ifname: &str, config: &PauseBuilder) -> Result<()> {
        self.ethtool_set(EthtoolCmd::PauseSet, ifname, |builder| {
            if let Some(v) = config.autoneg {
                builder.append_attr_u8(EthtoolPauseAttr::Autoneg as u16, v as u8);
            }
            if let Some(v) = config.rx {
                builder.append_attr_u8(EthtoolPauseAttr::Rx as u16, v as u8);
            }
            if let Some(v) = config.tx {
                builder.append_attr_u8(EthtoolPauseAttr::Tx as u16, v as u8);
            }
        })
        .await
    }

    // =========================================================================
    // Helper Methods
    // =========================================================================

    /// Parse the common header (interface name and index).
    fn parse_header(
        &self,
        data: &[u8],
        ifname: &mut Option<String>,
        ifindex: &mut Option<u32>,
    ) -> Result<()> {
        for (attr_type, payload) in AttrIter::new(data) {
            match attr_type {
                t if t == EthtoolHeaderAttr::DevIndex as u16 => {
                    if payload.len() >= 4 {
                        *ifindex = Some(u32::from_ne_bytes(payload[..4].try_into().unwrap()));
                    }
                }
                t if t == EthtoolHeaderAttr::DevName as u16 => {
                    *ifname = Some(
                        std::str::from_utf8(payload)
                            .unwrap_or("")
                            .trim_end_matches('\0')
                            .to_string(),
                    );
                }
                _ => {}
            }
        }
        Ok(())
    }

    /// Send an ethtool GET request (dump style).
    async fn ethtool_get(&self, cmd: EthtoolCmd, ifname: &str) -> Result<Vec<u8>> {
        let family_id = self.state().family_id;

        let mut builder = MessageBuilder::new(family_id, NLM_F_REQUEST | NLM_F_DUMP);

        // Append GENL header
        let genl_hdr = GenlMsgHdr::new(cmd as u8, ETHTOOL_GENL_VERSION);
        builder.append(&genl_hdr);

        // Append request header with device name
        let header_token = builder.nest_start(1 | NLA_F_NESTED); // ETHTOOL_A_*_HEADER = 1
        builder.append_attr_str(EthtoolHeaderAttr::DevName as u16, ifname);
        builder.nest_end(header_token);

        // Send request
        let seq = self.socket().next_seq();
        builder.set_seq(seq);
        builder.set_pid(self.socket().pid());

        let msg = builder.finish();
        self.socket().send(&msg).await?;

        // Receive responses until NLMSG_DONE
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
                    continue;
                }

                if header.is_done() {
                    done = true;
                    break;
                }

                // Store the first valid response payload
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

    /// Send an ethtool SET request.
    async fn ethtool_set(
        &self,
        cmd: EthtoolCmd,
        ifname: &str,
        build_attrs: impl FnOnce(&mut MessageBuilder),
    ) -> Result<()> {
        let family_id = self.state().family_id;

        let mut builder = MessageBuilder::new(family_id, NLM_F_REQUEST | NLM_F_ACK);

        // Append GENL header
        let genl_hdr = GenlMsgHdr::new(cmd as u8, ETHTOOL_GENL_VERSION);
        builder.append(&genl_hdr);

        // Append request header with device name
        let header_token = builder.nest_start(1 | NLA_F_NESTED); // ETHTOOL_A_*_HEADER = 1
        builder.append_attr_str(EthtoolHeaderAttr::DevName as u16, ifname);
        builder.nest_end(header_token);

        // Let caller append additional attributes
        build_attrs(&mut builder);

        // Send request
        let seq = self.socket().next_seq();
        builder.set_seq(seq);
        builder.set_pid(self.socket().pid());

        let msg = builder.finish();
        self.socket().send(&msg).await?;

        // Receive ACK
        let response: Vec<u8> = self.socket().recv_msg().await?;
        self.process_ethtool_ack(&response, seq)?;

        Ok(())
    }

    /// Process an ethtool ACK response.
    fn process_ethtool_ack(&self, data: &[u8], seq: u32) -> Result<()> {
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

    // =========================================================================
    // Event Monitoring
    // =========================================================================

    /// Subscribe to ethtool events.
    ///
    /// After subscribing, use `events()` or `into_events()` to receive
    /// notifications about ethtool configuration changes.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use nlink::netlink::{Connection, Ethtool};
    /// use tokio_stream::StreamExt;
    ///
    /// let mut conn = Connection::<Ethtool>::new_async().await?;
    /// conn.subscribe()?;
    ///
    /// let mut events = conn.events();
    /// while let Some(event) = events.next().await {
    ///     println!("{:?}", event?);
    /// }
    /// ```
    pub fn subscribe(&mut self) -> Result<()> {
        let group_id = self
            .state()
            .monitor_group_id
            .ok_or_else(|| Error::InvalidMessage("monitor group not available".into()))?;
        self.socket_mut().add_membership(group_id)?;
        Ok(())
    }
}

/// Resolve the ethtool GENL family ID and monitor group ID.
async fn resolve_ethtool_family(socket: &NetlinkSocket) -> Result<(u16, Option<u32>)> {
    // Build CTRL_CMD_GETFAMILY request
    let mut builder = MessageBuilder::new(GENL_ID_CTRL, NLM_F_REQUEST | NLM_F_ACK);

    // Append GENL header
    let genl_hdr = GenlMsgHdr::new(CtrlCmd::GetFamily as u8, 1);
    builder.append(&genl_hdr);

    // Append family name attribute
    builder.append_attr_str(CtrlAttr::FamilyName as u16, ETHTOOL_GENL_NAME);

    // Send request
    let seq = socket.next_seq();
    builder.set_seq(seq);
    builder.set_pid(socket.pid());

    let msg = builder.finish();
    socket.send(&msg).await?;

    // Receive response
    let response: Vec<u8> = socket.recv_msg().await?;

    let mut family_id: Option<u16> = None;
    let mut monitor_group_id: Option<u32> = None;

    // Parse response
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
                        name: ETHTOOL_GENL_NAME.to_string(),
                    });
                }
                return Err(Error::from_errno(err.error));
            }
            continue;
        }

        if header.is_done() {
            continue;
        }

        // Parse GENL header
        if payload.len() < GENL_HDRLEN {
            return Err(Error::InvalidMessage("GENL header too short".into()));
        }

        // Parse attributes after GENL header
        let attrs_data = &payload[GENL_HDRLEN..];
        for (attr_type, attr_payload) in AttrIter::new(attrs_data) {
            if attr_type == CtrlAttr::FamilyId as u16 {
                if attr_payload.len() >= 2 {
                    family_id = Some(u16::from_ne_bytes(attr_payload[..2].try_into().unwrap()));
                }
            } else if attr_type == CtrlAttr::McastGroups as u16 {
                // Parse multicast groups to find "monitor"
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

                    if grp_name.as_deref() == Some(ETHTOOL_MCGRP_MONITOR) {
                        monitor_group_id = grp_id;
                    }
                }
            }
        }
    }

    match family_id {
        Some(id) => Ok((id, monitor_group_id)),
        None => Err(Error::FamilyNotFound {
            name: ETHTOOL_GENL_NAME.to_string(),
        }),
    }
}
