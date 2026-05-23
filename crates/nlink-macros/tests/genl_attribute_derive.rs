//! Runtime tests for `#[derive(GenlAttribute)]`. Mirrors the
//! `GenlCommand` test shape since they share the codec
//! expansion.

use nlink_macros::GenlAttribute;

#[derive(GenlAttribute, Debug, Clone, Copy, PartialEq, Eq)]
#[genl_attribute(repr = "u16")]
#[non_exhaustive]
pub enum DpllAttr {
    Id = 1,
    ModuleName = 2,
    Pad = 3,
    ClockId = 4,
    Mode = 5,
    ModeSupported = 6,
    LockStatus = 7,
}

#[test]
fn u16_attr_round_trips() {
    assert_eq!(u16::from(DpllAttr::Id), 1);
    assert_eq!(u16::from(DpllAttr::LockStatus), 7);
    assert_eq!(DpllAttr::try_from(1u16).unwrap(), DpllAttr::Id);
    assert_eq!(DpllAttr::try_from(7u16).unwrap(), DpllAttr::LockStatus);
    assert!(DpllAttr::try_from(99u16).is_err());
}

#[test]
fn unknown_attr_error_carries_value() {
    let err = DpllAttr::try_from(42u16).unwrap_err();
    assert_eq!(err.0, 42);
    assert!(err.to_string().contains("DpllAttr"));
}

// u8 attribute kinds are rare but legal (some old GENL families
// pre-date the u16 widening).
#[derive(GenlAttribute, Debug, Clone, Copy, PartialEq, Eq)]
#[genl_attribute(repr = "u8")]
pub enum NarrowAttr {
    A = 0,
    B = 1,
}

#[test]
fn u8_attr_repr_works() {
    assert_eq!(u8::from(NarrowAttr::A), 0);
    assert_eq!(NarrowAttr::try_from(1u8).unwrap(), NarrowAttr::B);
}
