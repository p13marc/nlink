//! Typed request + reply structs for the DPLL family.
//!
//! Every struct in this file is declared via
//! `#[derive(GenlMessage)]` from `nlink-macros` — the wire-format
//! plumbing (`to_bytes` / `from_bytes`) is generated, leaving the
//! Rust-side declaration to read like a schema document.
//!
//! Compare with the hand-written GENL families
//! (`crates/nlink/src/netlink/genl/wireguard/`, `macsec/`, etc.)
//! where the equivalent code spans 200+ lines of manual
//! `MessageBuilder` + `AttrIter` walks.

use crate::macros::GenlMessage;

use super::types::{
    DpllAttr, DpllClockQualityLevel, DpllCmd, DpllFeatureState, DpllLockStatus,
    DpllLockStatusError, DpllMode, DpllType,
};

// ============================================================
// Device-side messages
// ============================================================

/// `DPLL_CMD_DEVICE_GET` request — single-device get or dump.
///
/// Set `id` to `Some(id)` for a single-device query (sent with
/// `NLM_F_REQUEST | NLM_F_ACK` via `Connection::send_typed`).
/// Set `id` to `None` for a full dump via
/// `Connection::dump_typed_stream` — the dump emits no
/// `DPLL_A_ID` attribute (matches the kernel's "no filter ⇒ list
/// every device" shape).
#[derive(GenlMessage, Debug, Default, Clone)]
#[genl_message(cmd = DpllCmd::DeviceGet)]
pub struct DpllDeviceGetRequest {
    /// Device ID to query. `None` = "no filter; dump all".
    #[genl_attr(DpllAttr::Id)]
    pub id: Option<u32>,
}

impl DpllDeviceGetRequest {
    /// Construct a single-device get request by ID.
    pub fn by_id(id: u32) -> Self {
        Self { id: Some(id) }
    }

    /// Construct a dump request (no ID filter).
    pub fn dump() -> Self {
        Self { id: None }
    }
}

/// `DPLL_CMD_DEVICE_GET` / `_CHANGE_NTF` reply — a device's
/// complete state.
///
/// Every field reflects an attribute the kernel may emit:
/// values present in every reply are non-`Option`; values added
/// in later kernel versions or only emitted in some configurations
/// are `Option<T>`. The macro derive defaults missing fields to
/// their type-defaults, so consumers can match on `None` to detect
/// "the kernel didn't ship this attribute" without surfacing a
/// parse error.
///
/// **Scaling fields:**
/// - `temp_mdeg` is milli-degrees Celsius. Divide by
///   [`super::DPLL_TEMP_DIVIDER`] (= 1000) for °C.
#[derive(GenlMessage, Debug, Default, Clone)]
#[genl_message(cmd = DpllCmd::DeviceGet)]
pub struct DpllDeviceReply {
    /// Numeric device ID (stable across the kernel's lifetime).
    #[genl_attr(DpllAttr::Id)]
    pub id: u32,
    /// Driver module name (e.g., `"ice"`, `"mlx5"`).
    #[genl_attr(DpllAttr::ModuleName)]
    pub module_name: String,
    /// Hardware clock identifier (PCIe BDF-derived per UAPI).
    #[genl_attr(DpllAttr::ClockId)]
    pub clock_id: u64,
    /// Current mode. `None` if the kernel didn't ship the
    /// attribute (shouldn't happen on a normal `DEVICE_GET` —
    /// would indicate a kernel/binary mismatch).
    #[genl_attr(DpllAttr::Mode, repr = "u32")]
    pub mode: Option<DpllMode>,
    /// Modes the device supports. Each `DPLL_A_MODE_SUPPORTED`
    /// attr in the response is one element.
    #[genl_attr(DpllAttr::ModeSupported, repr = "u32")]
    pub mode_supported: Vec<DpllMode>,
    /// Current lock state. `None` if absent — see `mode` note.
    #[genl_attr(DpllAttr::LockStatus, repr = "u32")]
    pub lock_status: Option<DpllLockStatus>,
    /// Device temperature, milli-degrees Celsius. `None` if the
    /// driver doesn't expose temperature.
    #[genl_attr(DpllAttr::Temp)]
    pub temp_mdeg: Option<i32>,
    /// DPLL kind (PPS / EEC). `None` if absent.
    #[genl_attr(DpllAttr::Type, repr = "u32")]
    pub kind: Option<DpllType>,
    /// Reason for lock failure (kernel 6.10+). `None` on older
    /// kernels or when no error is active.
    #[genl_attr(DpllAttr::LockStatusError, repr = "u32")]
    pub lock_status_error: Option<DpllLockStatusError>,
    /// Currently-asserted ITU-T G.8264 quality levels (kernel
    /// 6.10+; may be multiple, hence Vec).
    #[genl_attr(DpllAttr::ClockQualityLevel, repr = "u32")]
    pub clock_quality_level: Vec<DpllClockQualityLevel>,
    /// Phase-offset monitor on/off (kernel 6.12+). `None` on
    /// older kernels.
    #[genl_attr(DpllAttr::PhaseOffsetMonitor, repr = "u32")]
    pub phase_offset_monitor: Option<DpllFeatureState>,
    /// Moving-average factor for phase-offset reporting
    /// (kernel 6.12+).
    #[genl_attr(DpllAttr::PhaseOffsetAvgFactor)]
    pub phase_offset_avg_factor: Option<u32>,
    /// Frequency monitor on/off (kernel 6.12+).
    #[genl_attr(DpllAttr::FrequencyMonitor, repr = "u32")]
    pub frequency_monitor: Option<DpllFeatureState>,
}

/// `DPLL_CMD_DEVICE_SET` request — mutate a device's state.
///
/// Construct with [`Self::new(id)`] then chain setter methods for
/// the fields you want to change. Unset fields stay `None` and
/// are omitted from the wire request (`Option`-typed attrs).
#[derive(GenlMessage, Debug, Default, Clone)]
#[genl_message(cmd = DpllCmd::DeviceSet)]
pub struct DpllDeviceSetRequest {
    /// Target device ID. Always present.
    #[genl_attr(DpllAttr::Id)]
    pub id: u32,
    /// New mode, if changing.
    #[genl_attr(DpllAttr::Mode, repr = "u32")]
    pub mode: Option<DpllMode>,
    /// Toggle the kernel 6.12+ phase-offset monitor.
    #[genl_attr(DpllAttr::PhaseOffsetMonitor, repr = "u32")]
    pub phase_offset_monitor: Option<DpllFeatureState>,
    /// Set the moving-average factor for phase-offset reporting
    /// (kernel 6.12+).
    #[genl_attr(DpllAttr::PhaseOffsetAvgFactor)]
    pub phase_offset_avg_factor: Option<u32>,
    /// Toggle the kernel 6.12+ frequency monitor.
    #[genl_attr(DpllAttr::FrequencyMonitor, repr = "u32")]
    pub frequency_monitor: Option<DpllFeatureState>,
}

impl DpllDeviceSetRequest {
    /// Start a set request targeting `id`. Chain `mode(...)`,
    /// `phase_offset_monitor(...)`, etc. before sending.
    pub fn new(id: u32) -> Self {
        Self {
            id,
            ..Self::default()
        }
    }

    /// Switch the device into the given mode.
    #[must_use]
    pub fn mode(mut self, mode: DpllMode) -> Self {
        self.mode = Some(mode);
        self
    }

    /// Enable or disable the kernel 6.12+ phase-offset monitor.
    #[must_use]
    pub fn phase_offset_monitor(mut self, state: DpllFeatureState) -> Self {
        self.phase_offset_monitor = Some(state);
        self
    }

    /// Set the moving-average factor for phase-offset reporting
    /// (kernel 6.12+).
    #[must_use]
    pub fn phase_offset_avg_factor(mut self, factor: u32) -> Self {
        self.phase_offset_avg_factor = Some(factor);
        self
    }

    /// Enable or disable the kernel 6.12+ frequency monitor.
    #[must_use]
    pub fn frequency_monitor(mut self, state: DpllFeatureState) -> Self {
        self.frequency_monitor = Some(state);
        self
    }
}

impl DpllDeviceReply {
    /// Device temperature in degrees Celsius, if reported.
    /// Convenience wrapper around the raw `temp_mdeg` field.
    pub fn temp_celsius(&self) -> Option<f32> {
        self.temp_mdeg.map(|m| m as f32 / super::DPLL_TEMP_DIVIDER as f32)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::macros::__rt;
    use crate::netlink::MessageBuilder;

    #[test]
    fn device_get_request_with_id_emits_one_attr() {
        let req = DpllDeviceGetRequest::by_id(7);
        let mut b = MessageBuilder::new(0, 0);
        let start = b.len();
        req.to_bytes(&mut b).expect("emit");
        let bytes = &b.as_bytes()[start..];

        let mut attrs: Vec<u16> = Vec::new();
        for (ty, _) in __rt::attr_iter(bytes) {
            attrs.push(ty);
        }
        assert_eq!(attrs, vec![DpllAttr::Id as u16]);
    }

    #[test]
    fn device_get_dump_emits_no_attrs() {
        let req = DpllDeviceGetRequest::dump();
        let mut b = MessageBuilder::new(0, 0);
        let start = b.len();
        req.to_bytes(&mut b).expect("emit");
        let bytes = &b.as_bytes()[start..];

        let count = __rt::attr_iter(bytes).count();
        assert_eq!(count, 0, "dump request should emit zero attrs");
    }

    #[test]
    fn device_reply_round_trips_a_full_attr_set() {
        let original = DpllDeviceReply {
            id: 42,
            module_name: "ice".to_string(),
            clock_id: 0x0011_2233_4455_6677,
            mode: Some(DpllMode::Automatic),
            mode_supported: vec![DpllMode::Manual, DpllMode::Automatic],
            lock_status: Some(DpllLockStatus::LockedHoAcq),
            temp_mdeg: Some(47_500),
            kind: Some(DpllType::Eec),
            lock_status_error: None,
            clock_quality_level: vec![DpllClockQualityLevel::ItuOpt1Prc],
            phase_offset_monitor: Some(DpllFeatureState::Enable),
            phase_offset_avg_factor: Some(8),
            frequency_monitor: Some(DpllFeatureState::Disable),
        };

        let mut b = MessageBuilder::new(0, 0);
        let start = b.len();
        original.to_bytes(&mut b).expect("emit");
        let parsed = DpllDeviceReply::from_bytes(&b.as_bytes()[start..]).expect("parse");
        // Vec fields preserve order; everything else compares directly.
        assert_eq!(parsed.id, original.id);
        assert_eq!(parsed.module_name, original.module_name);
        assert_eq!(parsed.clock_id, original.clock_id);
        assert_eq!(parsed.mode, original.mode);
        assert_eq!(parsed.mode_supported, original.mode_supported);
        assert_eq!(parsed.lock_status, original.lock_status);
        assert_eq!(parsed.temp_mdeg, original.temp_mdeg);
        assert_eq!(parsed.kind, original.kind);
        assert_eq!(parsed.lock_status_error, original.lock_status_error);
        assert_eq!(parsed.clock_quality_level, original.clock_quality_level);
        assert_eq!(parsed.phase_offset_monitor, original.phase_offset_monitor);
        assert_eq!(parsed.phase_offset_avg_factor, original.phase_offset_avg_factor);
        assert_eq!(parsed.frequency_monitor, original.frequency_monitor);
    }

    #[test]
    fn device_reply_missing_attrs_yield_defaults_and_nones() {
        let parsed = DpllDeviceReply::from_bytes(&[]).expect("parse");
        assert_eq!(parsed.id, 0);
        assert_eq!(parsed.module_name, "");
        assert_eq!(parsed.clock_id, 0);
        assert_eq!(parsed.mode, None);
        assert!(parsed.mode_supported.is_empty());
        assert_eq!(parsed.lock_status, None);
        assert_eq!(parsed.temp_mdeg, None);
        assert_eq!(parsed.kind, None);
        assert_eq!(parsed.lock_status_error, None);
        assert!(parsed.clock_quality_level.is_empty());
        assert_eq!(parsed.phase_offset_monitor, None);
        assert_eq!(parsed.frequency_monitor, None);
    }

    #[test]
    fn device_set_builder_emits_only_set_fields() {
        let req = DpllDeviceSetRequest::new(7)
            .mode(DpllMode::Manual)
            .frequency_monitor(DpllFeatureState::Enable);

        let mut b = MessageBuilder::new(0, 0);
        let start = b.len();
        req.to_bytes(&mut b).expect("emit");
        let bytes = &b.as_bytes()[start..];

        let mut attrs: Vec<u16> = Vec::new();
        for (ty, _) in __rt::attr_iter(bytes) {
            attrs.push(ty);
        }
        // id is always emitted; mode + frequency_monitor were set;
        // phase_offset_monitor + phase_offset_avg_factor were left None.
        assert_eq!(
            attrs,
            vec![
                DpllAttr::Id as u16,
                DpllAttr::Mode as u16,
                DpllAttr::FrequencyMonitor as u16,
            ]
        );
    }

    #[test]
    fn temp_celsius_helper_applies_divider() {
        let reply = DpllDeviceReply {
            temp_mdeg: Some(47_500),
            ..DpllDeviceReply::default()
        };
        let c = reply.temp_celsius().expect("temp present");
        assert!((c - 47.5).abs() < f32::EPSILON, "expected 47.5°C, got {c}");
        assert_eq!(
            DpllDeviceReply::default().temp_celsius(),
            None,
            "missing temp_mdeg → None"
        );
    }
}
