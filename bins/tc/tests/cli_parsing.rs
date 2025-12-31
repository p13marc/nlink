//! CLI argument parsing tests for the tc command.
//!
//! These tests verify that command-line arguments are correctly parsed
//! without requiring network access or root privileges.

use assert_cmd::Command;
use predicates::prelude::*;

fn tc_cmd() -> Command {
    Command::new(env!("CARGO_BIN_EXE_tc"))
}

mod global_flags {
    use super::*;

    #[test]
    fn test_help() {
        tc_cmd()
            .arg("--help")
            .assert()
            .success()
            .stdout(predicate::str::contains("Traffic control tool"));
    }

    #[test]
    fn test_version() {
        tc_cmd()
            .arg("--version")
            .assert()
            .success()
            .stdout(predicate::str::contains("tc"));
    }

    #[test]
    fn test_invalid_subcommand() {
        tc_cmd()
            .arg("invalid_command")
            .assert()
            .failure()
            .stderr(predicate::str::contains("error"));
    }

    #[test]
    fn test_json_flag_short() {
        tc_cmd().args(["-j", "--help"]).assert().success();
    }

    #[test]
    fn test_json_flag_long() {
        tc_cmd().args(["--json", "--help"]).assert().success();
    }

    #[test]
    fn test_pretty_flag() {
        tc_cmd().args(["-p", "--help"]).assert().success();
    }

    #[test]
    fn test_stats_flag_short() {
        tc_cmd().args(["-s", "--help"]).assert().success();
    }

    #[test]
    fn test_stats_flag_long() {
        tc_cmd().args(["--stats", "--help"]).assert().success();
    }

    #[test]
    fn test_details_flag_short() {
        tc_cmd().args(["-d", "--help"]).assert().success();
    }

    #[test]
    fn test_details_flag_long() {
        tc_cmd().args(["--details", "--help"]).assert().success();
    }

    #[test]
    fn test_names_flag() {
        tc_cmd().args(["--names", "--help"]).assert().success();
    }
}

mod qdisc_command {
    use super::*;

    #[test]
    fn test_qdisc_help() {
        tc_cmd()
            .args(["qdisc", "--help"])
            .assert()
            .success()
            .stdout(predicate::str::contains("queuing disciplines"));
    }

    #[test]
    fn test_qdisc_alias_q() {
        tc_cmd()
            .args(["q", "--help"])
            .assert()
            .success()
            .stdout(predicate::str::contains("queuing disciplines"));
    }

    #[test]
    fn test_qdisc_show_help() {
        tc_cmd()
            .args(["qdisc", "show", "--help"])
            .assert()
            .success()
            .stdout(predicate::str::contains("--invisible"));
    }

    #[test]
    fn test_qdisc_list_alias() {
        tc_cmd()
            .args(["qdisc", "list", "--help"])
            .assert()
            .success();
    }

    #[test]
    fn test_qdisc_ls_alias() {
        tc_cmd().args(["qdisc", "ls", "--help"]).assert().success();
    }

    #[test]
    fn test_qdisc_add_help() {
        tc_cmd()
            .args(["qdisc", "add", "--help"])
            .assert()
            .success()
            .stdout(predicate::str::contains("--parent"))
            .stdout(predicate::str::contains("--handle"));
    }

    #[test]
    fn test_qdisc_add_requires_dev() {
        tc_cmd()
            .args(["qdisc", "add", "fq_codel"])
            .assert()
            .failure();
    }

    #[test]
    fn test_qdisc_add_requires_type() {
        tc_cmd().args(["qdisc", "add", "eth0"]).assert().failure();
    }

    #[test]
    fn test_qdisc_del_help() {
        tc_cmd()
            .args(["qdisc", "del", "--help"])
            .assert()
            .success()
            .stdout(predicate::str::contains("--parent"));
    }

    #[test]
    fn test_qdisc_del_requires_dev() {
        tc_cmd().args(["qdisc", "del"]).assert().failure();
    }

    #[test]
    fn test_qdisc_replace_help() {
        tc_cmd()
            .args(["qdisc", "replace", "--help"])
            .assert()
            .success();
    }

    #[test]
    fn test_qdisc_change_help() {
        tc_cmd()
            .args(["qdisc", "change", "--help"])
            .assert()
            .success();
    }
}

mod class_command {
    use super::*;

    #[test]
    fn test_class_help() {
        tc_cmd()
            .args(["class", "--help"])
            .assert()
            .success()
            .stdout(predicate::str::contains("traffic classes"));
    }

    #[test]
    fn test_class_alias_c() {
        tc_cmd()
            .args(["c", "--help"])
            .assert()
            .success()
            .stdout(predicate::str::contains("traffic classes"));
    }

    #[test]
    fn test_class_show_help() {
        tc_cmd()
            .args(["class", "show", "--help"])
            .assert()
            .success();
    }

    #[test]
    fn test_class_add_help() {
        tc_cmd().args(["class", "add", "--help"]).assert().success();
    }
}

mod filter_command {
    use super::*;

    #[test]
    fn test_filter_help() {
        tc_cmd()
            .args(["filter", "--help"])
            .assert()
            .success()
            .stdout(predicate::str::contains("traffic filters"));
    }

    #[test]
    fn test_filter_alias_f() {
        tc_cmd()
            .args(["f", "--help"])
            .assert()
            .success()
            .stdout(predicate::str::contains("traffic filters"));
    }

    #[test]
    fn test_filter_show_help() {
        tc_cmd()
            .args(["filter", "show", "--help"])
            .assert()
            .success();
    }

    #[test]
    fn test_filter_add_help() {
        tc_cmd()
            .args(["filter", "add", "--help"])
            .assert()
            .success();
    }
}

mod action_command {
    use super::*;

    #[test]
    fn test_action_help() {
        tc_cmd()
            .args(["action", "--help"])
            .assert()
            .success()
            .stdout(predicate::str::contains("actions"));
    }

    #[test]
    fn test_action_alias_a() {
        tc_cmd().args(["a", "--help"]).assert().success();
    }
}

mod monitor_command {
    use super::*;

    #[test]
    fn test_monitor_help() {
        tc_cmd()
            .args(["monitor", "--help"])
            .assert()
            .success()
            .stdout(predicate::str::contains("Monitor"));
    }

    #[test]
    fn test_monitor_alias_m() {
        tc_cmd().args(["m", "--help"]).assert().success();
    }
}
