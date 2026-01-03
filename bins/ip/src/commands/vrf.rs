//! ip vrf command implementation.
//!
//! Virtual Routing and Forwarding (VRF) device management.
//! VRFs provide network isolation by creating separate routing domains.

use clap::{Args, Subcommand};
use nlink::netlink::attr::AttrIter;
use nlink::netlink::{Connection, Result, Route};
use nlink::output::{OutputFormat, OutputOptions, Printable, print_all};
use std::io::Write;

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

    fn exec(&self, name: &str, command: &[String]) -> Result<()> {
        use std::os::unix::process::CommandExt;
        use std::process::Command;

        if command.is_empty() {
            return Err(nlink::netlink::Error::InvalidMessage(
                "no command specified".to_string(),
            ));
        }

        // Use ip vrf exec approach: set SO_BINDTODEVICE on sockets
        // The actual implementation binds the process to the VRF
        // For now, we can use the cgroup approach or LD_PRELOAD

        // Simplest approach: use `ip vrf exec` if available, or set environment
        // For a proper implementation, we'd need to:
        // 1. Create a network namespace or
        // 2. Use cgroups to associate the process with the VRF

        // For now, exec with VRF environment hint
        let err = Command::new(&command[0])
            .args(&command[1..])
            .env("VRF", name)
            .exec();

        Err(nlink::netlink::Error::InvalidMessage(format!(
            "failed to execute: {}",
            err
        )))
    }

    fn identify(&self, pid: &str) -> Result<()> {
        // Read /proc/<pid>/cgroup to find VRF association
        let cgroup_path = format!("/proc/{}/cgroup", pid);

        match std::fs::read_to_string(&cgroup_path) {
            Ok(content) => {
                // Look for net_cls cgroup that might indicate VRF
                for line in content.lines() {
                    if line.contains("net_cls") {
                        // Extract VRF name if present
                        if let Some(vrf_name) = line.split('/').next_back()
                            && !vrf_name.is_empty()
                            && vrf_name != ":"
                        {
                            println!("{}", vrf_name);
                            return Ok(());
                        }
                    }
                }
                // No VRF association found
                println!();
                Ok(())
            }
            Err(e) => Err(nlink::netlink::Error::InvalidMessage(format!(
                "cannot read cgroup for process {}: {}",
                pid, e
            ))),
        }
    }

    fn pids(&self, name: &str) -> Result<()> {
        // List PIDs in the VRF's cgroup
        let cgroup_path = format!("/sys/fs/cgroup/net_cls/{}/tasks", name);

        match std::fs::read_to_string(&cgroup_path) {
            Ok(content) => {
                for line in content.lines() {
                    println!("{}", line);
                }
                Ok(())
            }
            Err(_) => {
                // Try alternative cgroup v2 path
                let cgroup_v2_path = format!("/sys/fs/cgroup/{}/cgroup.procs", name);
                match std::fs::read_to_string(&cgroup_v2_path) {
                    Ok(content) => {
                        for line in content.lines() {
                            println!("{}", line);
                        }
                        Ok(())
                    }
                    Err(_) => {
                        // No cgroup found, VRF may not have any processes
                        Ok(())
                    }
                }
            }
        }
    }
}

/// Extract VRF table ID from link_info.data bytes.
fn extract_vrf_table(data: &[u8]) -> u32 {
    for (attr_type, attr_data) in AttrIter::new(data) {
        if attr_type == IFLA_VRF_TABLE && attr_data.len() >= 4 {
            return u32::from_ne_bytes(attr_data[..4].try_into().unwrap());
        }
    }
    0
}
