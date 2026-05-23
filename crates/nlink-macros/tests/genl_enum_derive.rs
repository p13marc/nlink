//! Runtime tests for `#[derive(GenlEnum)]`. Covers the u32
//! repr (most common for value enums) + the 0-based outlier
//! pattern (DPLL_FEATURE_STATE_*).

use nlink_macros::GenlEnum;

// 1-based, u32 — the dominant kernel UAPI shape.
#[derive(GenlEnum, Debug, Clone, Copy, PartialEq, Eq)]
#[genl_enum(repr = "u32")]
#[non_exhaustive]
pub enum DpllMode {
    Manual = 1,
    Automatic = 2,
}

#[test]
fn u32_value_enum_round_trips() {
    assert_eq!(u32::from(DpllMode::Manual), 1);
    assert_eq!(u32::from(DpllMode::Automatic), 2);
    assert_eq!(DpllMode::try_from(1u32).unwrap(), DpllMode::Manual);
    assert!(DpllMode::try_from(0u32).is_err());
    assert!(DpllMode::try_from(99u32).is_err());
}

// 0-based outlier — DPLL_FEATURE_STATE_* in the wild.
#[derive(GenlEnum, Debug, Clone, Copy, PartialEq, Eq)]
#[genl_enum(repr = "u32")]
#[non_exhaustive]
pub enum FeatureState {
    Disable = 0,
    Enable = 1,
}

#[test]
fn zero_based_enum_handles_disable_at_0() {
    assert_eq!(u32::from(FeatureState::Disable), 0);
    assert_eq!(FeatureState::try_from(0u32).unwrap(), FeatureState::Disable);
    assert_eq!(FeatureState::try_from(1u32).unwrap(), FeatureState::Enable);
    assert!(FeatureState::try_from(2u32).is_err());
}

// u8-wide value enum — sometimes the kernel uses an attribute
// of type NLA_U8 to carry a typed enum value (rather than u32).
#[derive(GenlEnum, Debug, Clone, Copy, PartialEq, Eq)]
#[genl_enum(repr = "u8")]
pub enum NarrowPolicy {
    Accept = 1,
    Drop = 0,
}

#[test]
fn u8_value_enum_works() {
    assert_eq!(u8::from(NarrowPolicy::Accept), 1);
    assert_eq!(u8::from(NarrowPolicy::Drop), 0);
}

// All three reprs share the same error newtype shape.
#[test]
fn unknown_value_error_naming() {
    let err = DpllMode::try_from(42u32).unwrap_err();
    let s = err.to_string();
    assert!(s.contains("DpllMode"));
    assert!(s.contains("42"));
}
