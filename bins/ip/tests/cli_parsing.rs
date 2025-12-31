//! CLI argument parsing tests for the ip command.
//!
//! These tests verify that command-line arguments are correctly parsed
//! without requiring network access or root privileges.

use assert_cmd::Command;
use predicates::prelude::*;

fn ip_cmd() -> Command {
    Command::new(env!("CARGO_BIN_EXE_ip"))
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
            .stdout(predicate::str::contains("--mtu"));
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
