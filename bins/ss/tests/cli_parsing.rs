//! CLI argument parsing tests for the `ss` command.
//!
//! These exercise clap's parse phase only (`--help`, `--version`,
//! invalid arguments), which runs before `main` opens any netlink
//! socket — so the suite is hermetic and needs neither root nor a
//! live kernel diag interface.

use assert_cmd::Command;
use predicates::prelude::*;

fn ss_cmd() -> Command {
    Command::new(env!("CARGO_BIN_EXE_ss"))
}

#[test]
fn help_succeeds_and_names_the_tool() {
    ss_cmd()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("Socket statistics utility"));
}

#[test]
fn version_succeeds() {
    ss_cmd()
        .arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::contains("ss"));
}

#[test]
fn invalid_flag_fails() {
    ss_cmd()
        .arg("--definitely-not-a-flag")
        .assert()
        .failure()
        .stderr(predicate::str::contains("error"));
}

/// Lock in the socket-family selector flags that the hardening
/// campaign added/repaired (`-0/--packet`, `-O/--oneline`) so they
/// can't silently regress out of the help surface.
#[test]
fn help_documents_family_and_layout_flags() {
    ss_cmd()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("--packet"))
        .stdout(predicate::str::contains("--oneline"))
        .stdout(predicate::str::contains("--processes"));
}

/// The ss-style filter selectors land as documented options rather
/// than being swallowed as positional noise.
#[test]
fn help_documents_filter_selectors() {
    ss_cmd()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("--sport"))
        .stdout(predicate::str::contains("--dport"))
        .stdout(predicate::str::contains("--src"))
        .stdout(predicate::str::contains("--dst"));
}

/// A non-numeric port for `--sport` is rejected at parse time (the
/// value is typed `u16`), not silently dropped.
#[test]
fn non_numeric_sport_is_rejected() {
    ss_cmd()
        .args(["--sport", "not-a-port"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("error"));
}
