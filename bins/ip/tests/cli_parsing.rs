//! CLI argument parsing tests for the ip command.
//!
//! These tests verify that command-line arguments are correctly parsed
//! without requiring network access or root privileges.

use assert_cmd::Command;
use predicates::prelude::*;

fn ip_cmd() -> Command {
    Command::new(env!("CARGO_BIN_EXE_nlink-ip"))
}

mod global_flags {
    use super::*;

    #[test]
    fn test_help() {
        ip_cmd()
            .arg("--help")
            .assert()
            .success()
            .stdout(predicate::str::contains("Network configuration tool"));
    }

    #[test]
    fn test_version() {
        ip_cmd()
            .arg("--version")
            .assert()
            .success()
            .stdout(predicate::str::contains("ip"));
    }

    #[test]
    fn test_invalid_subcommand() {
        ip_cmd()
            .arg("invalid_command")
            .assert()
            .failure()
            .stderr(predicate::str::contains("error"));
    }
}

mod link_command {
    use super::*;

    #[test]
    fn test_link_help() {
        ip_cmd()
            .args(["link", "--help"])
            .assert()
            .success()
            .stdout(predicate::str::contains("Manage network interfaces"));
    }

    #[test]
    fn test_link_show_help() {
        ip_cmd().args(["link", "show", "--help"]).assert().success();
    }

    #[test]
    fn test_link_set_help() {
        ip_cmd()
            .args(["link", "set", "--help"])
            .assert()
            .success()
            .stdout(predicate::str::contains("--up"))
            .stdout(predicate::str::contains("--down"))
            .stdout(predicate::str::contains("--mtu"))
            .stdout(predicate::str::contains("--netns"));
    }

    #[test]
    fn test_link_set_netns_accepts_value() {
        // `--netns` must parse (name or PID); failure here would mean the flag
        // wasn't wired. We only check arg parsing, not the privileged move.
        ip_cmd()
            .args(["link", "set", "eth0", "--netns", "myns", "--help"])
            .assert()
            .success();
    }

    #[test]
    fn test_link_add_help() {
        ip_cmd().args(["link", "add", "--help"]).assert().success();
    }

    #[test]
    fn test_link_del_requires_dev() {
        ip_cmd()
            .args(["link", "del"])
            .assert()
            .failure()
            .stderr(predicate::str::contains("required"));
    }

    #[test]
    fn test_link_set_requires_dev() {
        ip_cmd().args(["link", "set", "--up"]).assert().failure();
    }

    /// An endpoint that is not an IP address is an error, not dropped
    /// (#418) — rejected before any request reaches the kernel.
    #[test]
    fn test_link_add_vxlan_rejects_a_bad_local() {
        ip_cmd()
            .args(["link", "add", "vxlan", "vx0", "--vni", "5", "--local", "not-an-ip"])
            .assert()
            .failure()
            .stderr(predicate::str::contains("invalid local address"));
    }

    /// Each of these used to be dropped without a word, and the link created
    /// without it (#428). Every one fails before anything is sent.
    fn link_add_fails(args: &[&str], message: &str) {
        let mut full = vec!["link", "add"];
        full.extend_from_slice(args);
        ip_cmd()
            .args(&full)
            .assert()
            .failure()
            .stderr(predicate::str::contains(message));
    }

    #[test]
    fn test_link_add_tunnel_addresses_are_checked() {
        link_add_fails(
            &["gre", "gre9", "--remote", "192.0.2.1", "--local", "not-an-ip"],
            "gre: invalid local address `not-an-ip`",
        );
        link_add_fails(
            &["gre", "gre9", "--remote", "192.0.2.1", "--local", "2001:db8::1"],
            "gre: local address `2001:db8::1` is IPv6, but gre takes IPv4 (use ip6gre)",
        );
        link_add_fails(
            &["ipip", "ipip9", "--remote", "nope"],
            "ipip: invalid remote address `nope`",
        );
        link_add_fails(
            &["vti", "vti9", "--remote", "2001:db8::1"],
            "vti: remote address `2001:db8::1` is IPv6, but vti takes IPv4 (use vti6)",
        );
        link_add_fails(
            &["ip6gre", "ip6gre9", "--remote", "192.0.2.1"],
            "ip6gre: remote address `192.0.2.1` is IPv4, but ip6gre takes IPv6",
        );
        link_add_fails(
            &["vti6", "vti69", "--local", "fe80::1%x"],
            "vti6: invalid local address `fe80::1%x`",
        );
        link_add_fails(
            &["bond", "bond9", "--arp-ip-target", "10.0.0.256"],
            "bond: invalid arp_ip_target address `10.0.0.256`",
        );
    }

    #[test]
    fn test_link_add_address_on_a_kind_without_one_is_refused() {
        link_add_fails(
            &["gre", "gre9", "--remote", "192.0.2.1", "--address", "02:00:00:00:00:01"],
            "gre: --address is not supported: it is a layer-3 device with no MAC",
        );
        link_add_fails(
            &["ipvlan", "ipv9", "--link", "lo", "--address", "02:00:00:00:00:01"],
            "ipvlan: --address is not supported: an ipvlan shares its parent's MAC",
        );
        link_add_fails(
            &["dummy", "d9", "--address", "not-a-mac"],
            "invalid MAC address",
        );
    }

    /// Where a network namespace can be created — as root, with sudo; it
    /// skips otherwise: `--mtu` and `--txqlen` reach a kind whose create
    /// message cannot carry them, and a link whose post-create step fails is
    /// deleted again. (`euid == 0` is not the test: CI's unprivileged
    /// containers run as root without `ip` or the right to make a netns.)
    #[test]
    fn test_link_add_sets_what_the_create_cannot_carry_as_root() {
        struct Netns(&'static str);
        impl Drop for Netns {
            fn drop(&mut self) {
                let _ = std::process::Command::new("ip").args(["netns", "del", self.0]).status();
            }
        }
        let created = std::process::Command::new("ip")
            .args(["netns", "add", "nlink-ip-t428"])
            .stderr(std::process::Stdio::null())
            .status()
            .is_ok_and(|s| s.success());
        if !created {
            eprintln!("skipping: cannot create a network namespace here (run as root)");
            return;
        }
        let ns = Netns("nlink-ip-t428");
        let in_ns = |args: &[&str]| {
            let mut cmd = std::process::Command::new("ip");
            cmd.args(["netns", "exec", ns.0, env!("CARGO_BIN_EXE_nlink-ip")]).args(args);
            cmd.output().unwrap()
        };
        let link = |dev: &str| {
            let out = std::process::Command::new("ip")
                .args(["-n", ns.0, "-j", "link", "show", "dev", dev])
                .output()
                .unwrap();
            String::from_utf8_lossy(&out.stdout).to_string()
        };

        let out = in_ns(&["link", "add", "vti", "vti1", "--remote", "192.0.2.1", "--mtu", "1300", "--txqlen", "77"]);
        assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
        let shown = link("vti1");
        assert!(shown.contains("\"mtu\":1300") && shown.contains("\"txqlen\":77"), "{shown}");

        let out = in_ns(&["link", "add", "vti", "vti2", "--remote", "192.0.2.9", "--mtu", "70000"]);
        assert!(!out.status.success(), "an MTU of 70000 must fail");
        assert_eq!(link("vti2"), "", "the failed link must not be left behind");
    }

    #[test]
    fn test_link_add_queue_counts_are_not_offered() {
        // They were accepted by every kind and never applied.
        ip_cmd()
            .args(["link", "add", "dummy", "d9", "--numtxqueues", "4"])
            .assert()
            .failure()
            .stderr(predicate::str::contains("unexpected argument"));
    }

    #[test]
    fn test_link_alias_l() {
        ip_cmd()
            .args(["l", "--help"])
            .assert()
            .success()
            .stdout(predicate::str::contains("Manage network interfaces"));
    }
}

mod address_command {
    use super::*;

    #[test]
    fn test_address_help() {
        ip_cmd()
            .args(["address", "--help"])
            .assert()
            .success()
            .stdout(predicate::str::contains("Manage IP addresses"));
    }

    #[test]
    fn test_addr_alias() {
        ip_cmd()
            .args(["addr", "--help"])
            .assert()
            .success()
            .stdout(predicate::str::contains("Manage IP addresses"));
    }

    #[test]
    fn test_a_alias() {
        ip_cmd()
            .args(["a", "--help"])
            .assert()
            .success()
            .stdout(predicate::str::contains("Manage IP addresses"));
    }

    #[test]
    fn test_address_add_requires_address() {
        ip_cmd()
            .args(["address", "add", "-d", "eth0"])
            .assert()
            .failure()
            .stderr(predicate::str::contains("required"));
    }

    #[test]
    fn test_address_add_requires_dev() {
        ip_cmd()
            .args(["address", "add", "192.168.1.1/24"])
            .assert()
            .failure()
            .stderr(predicate::str::contains("required"));
    }

    #[test]
    fn test_address_del_requires_args() {
        ip_cmd().args(["address", "del"]).assert().failure();
    }
}

mod route_command {
    use super::*;

    #[test]
    fn test_route_help() {
        ip_cmd()
            .args(["route", "--help"])
            .assert()
            .success()
            .stdout(predicate::str::contains("Manage routing table"));
    }

    #[test]
    fn test_route_alias_r() {
        ip_cmd()
            .args(["r", "--help"])
            .assert()
            .success()
            .stdout(predicate::str::contains("Manage routing table"));
    }

    #[test]
    fn test_route_add_help() {
        ip_cmd()
            .args(["route", "add", "--help"])
            .assert()
            .success()
            .stdout(predicate::str::contains("--via"))
            .stdout(predicate::str::contains("--dev"))
            .stdout(predicate::str::contains("--metric"));
    }

    #[test]
    fn test_route_add_requires_destination() {
        ip_cmd()
            .args(["route", "add", "--via", "192.168.1.1"])
            .assert()
            .failure();
    }

    #[test]
    fn test_route_del_requires_destination() {
        ip_cmd().args(["route", "del"]).assert().failure();
    }

    #[test]
    fn test_route_get_requires_destination() {
        ip_cmd().args(["route", "get"]).assert().failure();
    }
}

mod neighbor_command {
    use super::*;

    #[test]
    fn test_neighbor_help() {
        ip_cmd()
            .args(["neighbor", "--help"])
            .assert()
            .success()
            .stdout(predicate::str::contains("ARP/NDP"));
    }

    #[test]
    fn test_neigh_alias() {
        ip_cmd().args(["neigh", "--help"]).assert().success();
    }

    #[test]
    fn test_n_alias() {
        ip_cmd().args(["n", "--help"]).assert().success();
    }
}

mod rule_command {
    use super::*;

    #[test]
    fn test_rule_help() {
        ip_cmd()
            .args(["rule", "--help"])
            .assert()
            .success()
            .stdout(predicate::str::contains("routing policy"));
    }

    #[test]
    fn test_rule_alias_ru() {
        ip_cmd().args(["ru", "--help"]).assert().success();
    }
}

mod netns_command {
    use super::*;

    #[test]
    fn test_netns_help() {
        ip_cmd()
            .args(["netns", "--help"])
            .assert()
            .success()
            .stdout(predicate::str::contains("network namespaces"));
    }

    #[test]
    fn test_netns_alias_ns() {
        ip_cmd().args(["ns", "--help"]).assert().success();
    }
}

mod monitor_command {
    use super::*;

    #[test]
    fn test_monitor_help() {
        ip_cmd()
            .args(["monitor", "--help"])
            .assert()
            .success()
            .stdout(predicate::str::contains("netlink events"));
    }

    #[test]
    fn test_monitor_alias_m() {
        ip_cmd().args(["m", "--help"]).assert().success();
    }

    #[test]
    fn test_monitor_alias_mon() {
        ip_cmd().args(["mon", "--help"]).assert().success();
    }
}

mod tunnel_command {
    use super::*;

    #[test]
    fn test_tunnel_help() {
        ip_cmd()
            .args(["tunnel", "--help"])
            .assert()
            .success()
            .stdout(predicate::str::contains("IP tunnels"));
    }

    #[test]
    fn test_tunnel_alias_t() {
        ip_cmd().args(["t", "--help"]).assert().success();
    }

    #[test]
    fn test_tunnel_alias_tun() {
        ip_cmd().args(["tun", "--help"]).assert().success();
    }
}

mod json_output {
    use super::*;

    #[test]
    fn test_json_flag_short() {
        // Just verify the flag is accepted (actual output requires network)
        ip_cmd().args(["-j", "--help"]).assert().success();
    }

    #[test]
    fn test_json_flag_long() {
        ip_cmd().args(["--json", "--help"]).assert().success();
    }

    #[test]
    fn test_pretty_flag() {
        ip_cmd().args(["-p", "--help"]).assert().success();
    }
}

mod family_filters {
    use super::*;

    #[test]
    fn test_ipv4_flag() {
        ip_cmd().args(["-4", "--help"]).assert().success();
    }

    #[test]
    fn test_ipv6_flag() {
        ip_cmd().args(["-6", "--help"]).assert().success();
    }
}

mod other_flags {
    use super::*;

    #[test]
    fn test_stats_flag_short() {
        ip_cmd().args(["-s", "--help"]).assert().success();
    }

    #[test]
    fn test_stats_flag_long() {
        ip_cmd().args(["--stats", "--help"]).assert().success();
    }

    #[test]
    fn test_details_flag_short() {
        ip_cmd().args(["-d", "--help"]).assert().success();
    }

    #[test]
    fn test_details_flag_long() {
        ip_cmd().args(["--details", "--help"]).assert().success();
    }

    #[test]
    fn test_numeric_flag_short() {
        ip_cmd().args(["-n", "--help"]).assert().success();
    }

    #[test]
    fn test_numeric_flag_long() {
        ip_cmd().args(["--numeric", "--help"]).assert().success();
    }
}
