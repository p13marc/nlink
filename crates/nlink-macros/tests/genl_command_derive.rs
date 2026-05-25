//! Runtime tests for `#[derive(GenlCommand)]`.
//!
//! The compile-fail tests live under `tests/ui/` driven by
//! [`trybuild`][trybuild] — see `tests/trybuild.rs`.

use nlink_macros::GenlCommand;

#[derive(GenlCommand, Debug, Clone, Copy, PartialEq, Eq)]
#[genl_command(repr = "u8")]
pub enum MyCmd {
    Unspec = 0,
    Get = 1,
    Set = 2,
    Notify = 8,
}

#[test]
fn from_enum_to_u8_is_infallible_round_trip() {
    assert_eq!(u8::from(MyCmd::Unspec), 0);
    assert_eq!(u8::from(MyCmd::Get), 1);
    assert_eq!(u8::from(MyCmd::Set), 2);
    assert_eq!(u8::from(MyCmd::Notify), 8);
}

#[test]
fn try_from_u8_round_trips_known_values() {
    assert_eq!(MyCmd::try_from(0u8).unwrap(), MyCmd::Unspec);
    assert_eq!(MyCmd::try_from(1u8).unwrap(), MyCmd::Get);
    assert_eq!(MyCmd::try_from(2u8).unwrap(), MyCmd::Set);
    assert_eq!(MyCmd::try_from(8u8).unwrap(), MyCmd::Notify);
}

#[test]
fn try_from_u8_errors_for_unknown_values() {
    let err = MyCmd::try_from(3u8).unwrap_err();
    assert_eq!(err.0, 3);
    let err = MyCmd::try_from(255u8).unwrap_err();
    assert_eq!(err.0, 255);
}

#[test]
fn unknown_value_error_display_is_actionable() {
    let err = MyCmd::try_from(99u8).unwrap_err();
    let s = err.to_string();
    assert!(
        s.contains("MyCmd"),
        "Display should name the enum: {s}"
    );
    assert!(s.contains("99"), "Display should name the bad value: {s}");
}

#[test]
fn unknown_value_error_impls_std_error() {
    fn assert_error<E: std::error::Error>(_: &E) {}
    let err = MyCmd::try_from(99u8).unwrap_err();
    assert_error(&err);
}

// u16 repr coverage — typical for attribute kinds rather than
// commands, but Plan 154's spec accepts u16 for both since
// some GENL families use wider command spaces.
#[derive(GenlCommand, Debug, Clone, Copy, PartialEq, Eq)]
#[genl_command(repr = "u16")]
pub enum WideCmd {
    Unspec = 0,
    Get = 1,
    HighValue = 1000,
}

#[test]
fn u16_repr_handles_wider_discriminants() {
    assert_eq!(u16::from(WideCmd::HighValue), 1000);
    assert_eq!(WideCmd::try_from(1000u16).unwrap(), WideCmd::HighValue);
    assert!(WideCmd::try_from(99u16).is_err());
}

// Sparse-discriminants — GENL commands often have gaps (e.g.,
// kernel reserves slots between subsystems).
#[derive(GenlCommand, Debug, Clone, Copy, PartialEq, Eq)]
#[genl_command(repr = "u8")]
pub enum SparseCmd {
    A = 1,
    B = 5,
    C = 42,
}

#[test]
fn sparse_discriminants_round_trip() {
    assert_eq!(u8::from(SparseCmd::A), 1);
    assert_eq!(u8::from(SparseCmd::B), 5);
    assert_eq!(u8::from(SparseCmd::C), 42);
    assert!(SparseCmd::try_from(2u8).is_err());
    assert!(SparseCmd::try_from(6u8).is_err());
    assert_eq!(SparseCmd::try_from(42u8).unwrap(), SparseCmd::C);
}
