//! CLI argument parsing tests for the `bridge` command.
//!
//! These drive clap's parse phase (`--help` on the root and each
//! subcommand, plus invalid input), which completes before `main`
//! opens a netlink connection. The suite is therefore hermetic and
//! runs as a non-root user without a live kernel.

use assert_cmd::Command;
use predicates::prelude::*;

fn bridge_cmd() -> Command {
    Command::new(env!("CARGO_BIN_EXE_nlink-bridge"))
}

#[test]
fn help_succeeds_and_names_the_tool() {
    bridge_cmd()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("Bridge management utility"));
}

#[test]
fn help_lists_all_subcommands() {
    bridge_cmd()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("fdb"))
        .stdout(predicate::str::contains("vlan"))
        .stdout(predicate::str::contains("link"))
        .stdout(predicate::str::contains("mdb"))
        .stdout(predicate::str::contains("monitor"));
}

#[test]
fn invalid_subcommand_fails() {
    bridge_cmd()
        .arg("not-a-subcommand")
        .assert()
        .failure()
        .stderr(predicate::str::contains("error"));
}

/// Building the help for each subcommand forces clap to construct that
/// subcommand's full argument model — a cheap guard against arg-tree
/// definition bugs (duplicate short flags, bad defaults) that would
/// otherwise only surface at runtime.
#[test]
fn every_subcommand_help_builds() {
    for sub in ["fdb", "vlan", "link", "mdb", "monitor"] {
        bridge_cmd()
            .args([sub, "--help"])
            .assert()
            .success();
    }
}

/// The `fdb add` path gained `--extern-learn` in the hardening
/// campaign; keep it visible in help so it can't silently regress.
#[test]
fn fdb_add_documents_extern_learn() {
    bridge_cmd()
        .args(["fdb", "add", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("extern-learn"));
}
