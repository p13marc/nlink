//! CLI argument parsing tests for the `nlink-config` command.
//!
//! Most cases drive clap's parse phase, which completes before any
//! netlink connection is opened. The `example` subcommand emits an
//! embedded sample config without touching the kernel, so it is also
//! exercised end-to-end. The suite is hermetic — no root, no live
//! kernel.

use assert_cmd::Command;
use predicates::prelude::*;

fn config_cmd() -> Command {
    Command::new(env!("CARGO_BIN_EXE_nlink-config"))
}

#[test]
fn help_succeeds_and_names_the_tool() {
    config_cmd()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "Declarative network configuration utility",
        ));
}

#[test]
fn help_lists_all_subcommands() {
    config_cmd()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("capture"))
        .stdout(predicate::str::contains("example"))
        .stdout(predicate::str::contains("diff"))
        .stdout(predicate::str::contains("apply"));
}

#[test]
fn invalid_subcommand_fails() {
    config_cmd()
        .arg("not-a-subcommand")
        .assert()
        .failure()
        .stderr(predicate::str::contains("error"));
}

#[test]
fn every_subcommand_help_builds() {
    for sub in ["capture", "example", "diff", "apply"] {
        config_cmd().args([sub, "--help"]).assert().success();
    }
}

/// `diff` takes a required config-file path; omitting it is a parse
/// error, not a silent no-op.
#[test]
fn diff_requires_a_file() {
    config_cmd()
        .arg("diff")
        .assert()
        .failure()
        .stderr(predicate::str::contains("error"));
}

/// `apply --dry-run` and `--reconcile` are mutually exclusive; clap
/// rejects the combination during parsing, before the file is even
/// read.
#[test]
fn apply_dry_run_conflicts_with_reconcile() {
    config_cmd()
        .args(["apply", "--dry-run", "--reconcile", "/nonexistent.yaml"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("cannot be used with"));
}

/// `example` is self-contained (no kernel access) — it should emit a
/// non-empty sample configuration.
#[test]
fn example_emits_a_config() {
    config_cmd()
        .arg("example")
        .assert()
        .success()
        .stdout(predicate::str::is_empty().not());
}

/// `example --format json` yields parseable JSON.
#[test]
fn example_json_is_valid() {
    let out = config_cmd()
        .args(["example", "--format", "json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let parsed: serde_json::Value =
        serde_json::from_slice(&out).expect("example --format json must emit valid JSON");
    assert!(parsed.is_object() || parsed.is_array());
}
