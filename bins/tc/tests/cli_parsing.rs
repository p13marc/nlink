//! CLI argument parsing tests for the tc command.
//!
//! These tests verify that command-line arguments are correctly parsed
//! without requiring network access or root privileges.

use assert_cmd::Command;
use predicates::prelude::*;

fn tc_cmd() -> Command {
    Command::new(env!("CARGO_BIN_EXE_nlink-tc"))
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

mod flower_matches_tc {
    /// The same flower filters installed by tc(8) and by nlink-tc end up the
    /// same in the kernel. They did not:
    /// - nlink read a numeric `ip_proto` as decimal, where tc(8) reads hex (#432);
    /// - nlink read an `ip_tos`/`ip_ttl` value as hex, where tc(8) reads decimal (#447);
    /// - nlink refused L3/L4 keys under `protocol ip`, where tc(8) takes the
    ///   ethertype from the protocol (#433).
    ///
    /// Each filter goes on `d0` through tc(8) and on `d1` through nlink-tc,
    /// and `tc filter show` must print the same thing for both. Where a
    /// network namespace can be created (as root, with sudo) and tc(8) is
    /// installed; it skips otherwise. (`euid == 0` is not the test: CI's
    /// unprivileged containers run as root without `ip` or the right to make
    /// a netns.)
    #[test]
    fn test_flower_filters_match_what_tc_installs_as_root() {
        const NS: &str = "nlink-tc-t433";
        struct Netns;
        impl Drop for Netns {
            fn drop(&mut self) {
                let _ = std::process::Command::new("ip").args(["netns", "del", NS]).status();
            }
        }
        let created = std::process::Command::new("ip")
            .args(["netns", "add", NS])
            .stderr(std::process::Stdio::null())
            .status()
            .is_ok_and(|s| s.success());
        if !created {
            eprintln!("skipping: cannot create a network namespace here (run as root)");
            return;
        }
        let _ns = Netns;
        let run = |prog: &str, args: &[&str]| {
            let out = std::process::Command::new("ip")
                .args(["netns", "exec", NS, prog])
                .args(args)
                .output()
                .unwrap();
            (out.status.success(), String::from_utf8_lossy(&out.stdout).to_string()
                + &String::from_utf8_lossy(&out.stderr))
        };
        if !run("tc", &["-V"]).0 {
            eprintln!("skipping: tc(8) is not installed");
            return;
        }
        for dev in ["d0", "d1"] {
            for args in [
                &["link", "add", dev, "type", "dummy"][..],
                &["link", "set", dev, "up"][..],
            ] {
                assert!(run("ip", args).0, "ip {args:?}");
            }
            assert!(run("tc", &["qdisc", "add", "dev", dev, "ingress"]).0);
        }

        let cases: &[(&str, &str)] = &[
            ("ip", "ip_proto 2f"),
            ("ip", "ip_proto 47"),
            ("ip", "ip_proto 0x11"),
            ("ip", "ip_proto tcp dst_port 80"),
            ("ipv6", "ip_proto udp src_port 53"),
            ("ip", "ip_proto udp dst_ip 10.0.0.0/8 src_port 1000-2000"),
            ("ip", "ip_ttl 64"),
            ("ip", "ip_tos 16/10"),
            ("ip", "ip_tos 1a"),
            ("ip", "ip_proto tcp tcp_flags 0x12/0x3f"),
            ("802.1q", "vlan_id 10 vlan_prio 3"),
            ("802.1ad", "vlan_id 20"),
            ("arp", "dst_mac 02:00:00:00:00:01"),
        ];
        let mut failures = Vec::new();
        for (i, (protocol, flower)) in cases.iter().enumerate() {
            let pref = (i + 1).to_string();
            let flower: Vec<&str> = flower.split_whitespace().collect();
            let mut tc = vec!["filter", "add", "dev", "d0", "parent", "ffff:"];
            tc.extend(["protocol", protocol, "pref", &pref, "flower"]);
            tc.extend(&flower);
            let (ok, out) = run("tc", &tc);
            assert!(ok, "tc(8) refused {tc:?}: {out}");

            let mut nlink = vec!["filter", "add", "d1", "--parent", "ffff:"];
            nlink.extend(["--protocol", protocol, "--prio", &pref, "flower"]);
            nlink.extend(&flower);
            let (ok, out) = run(env!("CARGO_BIN_EXE_nlink-tc"), &nlink);
            if !ok {
                failures.push(format!("nlink-tc refused `{protocol} {flower:?}`, which tc(8) takes: {out}"));
                continue;
            }
            let show = |dev: &str| {
                run("tc", &["filter", "show", "dev", dev, "parent", "ffff:", "pref", &pref]).1
            };
            let (want, got) = (show("d0"), show("d1"));
            if want != got {
                failures.push(format!(
                    "`protocol {protocol} flower {}`:\n tc(8) installed:\n{want}\n nlink-tc installed:\n{got}",
                    flower.join(" ")
                ));
            }
        }
        assert!(failures.is_empty(), "{}", failures.join("\n"));
    }
}
