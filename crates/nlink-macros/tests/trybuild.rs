//! Compile-pass / compile-fail tests for the proc-macro derives.
//!
//! Trybuild's compile-fail output is rustc-version-dependent —
//! the `.stderr` baselines may need re-blessing across stable
//! Rust releases. To regenerate after a stable bump:
//!
//! ```bash
//! TRYBUILD=overwrite cargo test -p nlink-macros --test trybuild
//! ```
//!
//! When the message text drift is *only* in column numbers or
//! grammatical phrasing (not in semantic correctness), prefer to
//! re-bless rather than over-engineer the assertions.

#[test]
fn ui_compile_tests() {
    let t = trybuild::TestCases::new();
    t.pass("tests/ui/pass/*.rs");
    t.compile_fail("tests/ui/fail/*.rs");
}
