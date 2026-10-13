//! ip vrf command implementation.
//!
//! Virtual Routing and Forwarding (VRF) device management.
//! VRFs provide network isolation by creating separate routing domains.

use std::io::Write;

use clap::{Args, Subcommand};
use nlink::{
    netlink::{Connection, Result, Route, attr::AttrIter},
    output::{OutputFormat, OutputOptions, Printable, print_all},
};

/// IFLA_VRF_TABLE attribute constant.
const IFLA_VRF_TABLE: u16 = 1;

#[derive(Args)]
pub struct VrfCmd {
    #[command(subcommand)]
    action: Option<VrfAction>,
}

#[derive(Subcommand)]
enum VrfAction {
    /// Show VRF devices.
    Show {
        /// VRF name.
        name: Option<String>,
    },

    /// List VRF devices (alias for show).
    #[command(visible_alias = "ls")]
    List,

    /// Execute a command in a VRF context.
    Exec {
        /// VRF name.
        name: String,

        /// Command to execute.
        #[arg(trailing_var_arg = true, required = true)]
        command: Vec<String>,
    },

    /// Identify which VRF a process is associated with.
    Identify {
        /// Process ID (default: self).
        #[arg(default_value = "self")]
        pid: String,
    },

    /// List PIDs associated with a VRF.
    Pids {
        /// VRF name.
        name: String,
    },
}

/// VRF device information.
#[derive(Debug)]
struct VrfInfo {
    name: String,
    ifindex: u32,
    table: u32,
}

impl Printable for VrfInfo {
    fn print_text<W: Write>(&self, w: &mut W, _opts: &OutputOptions) -> std::io::Result<()> {
        writeln!(w, "{} table {}", self.name, self.table)
    }

    fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "name": self.name,
            "ifindex": self.ifindex,
            "table": self.table,
        })
    }
}

impl VrfCmd {
    pub async fn run(
        &self,
        conn: &Connection<Route>,
        format: OutputFormat,
        opts: &OutputOptions,
    ) -> Result<()> {
        match &self.action {
            Some(VrfAction::Show { name }) => self.show(conn, name.as_deref(), format, opts).await,
            Some(VrfAction::List) | None => self.show(conn, None, format, opts).await,
            Some(VrfAction::Exec { name, command }) => self.exec(name, command),
            Some(VrfAction::Identify { pid }) => self.identify(pid),
            Some(VrfAction::Pids { name }) => self.pids(name),
        }
    }

    async fn show(
        &self,
        conn: &Connection<Route>,
        name_filter: Option<&str>,
        format: OutputFormat,
        opts: &OutputOptions,
    ) -> Result<()> {
        // Get all links and filter for VRF type
        let links = conn.get_links().await?;

        let mut vrfs = Vec::new();

        for link in &links {
            // Check if this is a VRF device
            let link_info = match link.link_info() {
                Some(info) => info,
                None => continue,
            };

            if link_info.kind() != Some("vrf") {
                continue;
            }

            // Apply name filter
            if let Some(name) = name_filter
                && link.name() != Some(name)
            {
                continue;
            }

            // Extract VRF table from link_info.data
            let table = extract_vrf_table(link_info.data().unwrap_or(&[]));

            vrfs.push(VrfInfo {
                name: link.name().unwrap_or_default().to_string(),
                ifindex: link.ifindex(),
                table,
            });
        }

        print_all(&vrfs, format, opts)?;

        Ok(())
    }

    /// `ip vrf exec <name> <cmd>`: run the command with every socket it
    /// opens bound to the VRF (#257), and exit with its status.
    fn exec(&self, name: &str, command: &[String]) -> Result<()> {
        use nlink::netlink::namespace::NetnsCommand;
        use std::process::Command;

        let Some((program, args)) = command.split_first() else {
            return Err(nlink::netlink::Error::invalid_message(
                "no command specified".to_string(),
            ));
        };
        let mut cmd = Command::new(program);
        cmd.args(args);
        let status = NetnsCommand::path("/proc/self/ns/net", cmd)?
            .vrf(name)
            .spawn()?
            .wait()
            .map_err(|e| nlink::netlink::Error::from(e).with_context(format!("wait for {program}")))?;
        std::process::exit(status.code().unwrap_or(1));
    }

    /// `ip vrf identify [pid]`: the VRF a process was started in, from the
    /// last component of its cgroup v2 path under `vrf/` (nlink's and
    /// iproute2's layouts both end with the VRF's name).
    fn identify(&self, pid: &str) -> Result<()> {
        let cgroup_path = format!("/proc/{}/cgroup", pid);
        let content = std::fs::read_to_string(&cgroup_path).map_err(|e| {
            nlink::netlink::Error::from(e).with_context(format!("read the cgroup of process {pid}"))
        })?;
        let vrf = content
            .lines()
            .filter_map(|line| line.strip_prefix("0::"))
            .find_map(|path| path.split_once("/vrf/").map(|(_, rest)| rest))
            .and_then(|rest| rest.rsplit('/').next())
            .unwrap_or_default();
        println!("{vrf}");
        Ok(())
    }

    /// `ip vrf pids <name>`: the processes in the VRF's cgroup.
    fn pids(&self, name: &str) -> Result<()> {
        let Some(dir) = nlink::netlink::namespace::vrf_cgroup(name)? else {
            return Ok(());
        };
        let procs = dir.join("cgroup.procs");
        let content = std::fs::read_to_string(&procs).map_err(|e| {
            nlink::netlink::Error::from(e).with_context(format!("read {}", procs.display()))
        })?;
        for line in content.lines() {
            println!("{line}");
        }
        Ok(())
    }
}

/// Extract VRF table ID from link_info.data bytes.
fn extract_vrf_table(data: &[u8]) -> u32 {
    for (attr_type, attr_data) in AttrIter::new(data) {
        if attr_type == IFLA_VRF_TABLE && attr_data.len() >= 4 {
            return u32::from_ne_bytes(attr_data[..4].try_into().expect("4-byte attribute data"));
        }
    }
    0
}
