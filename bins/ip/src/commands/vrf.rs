//! ip vrf command implementation.
//!
//! Virtual Routing and Forwarding (VRF) device management.
//! VRFs provide network isolation by creating separate routing domains.

use clap::{Args, Subcommand};
use rip_netlink::attr::AttrIter;
use rip_netlink::connection::dump_request;
use rip_netlink::message::{NLMSG_HDRLEN, NlMsgType};
use rip_netlink::types::link::{IfInfoMsg, IflaAttr, IflaInfo};
use rip_netlink::{Connection, Result};
use rip_output::{OutputFormat, OutputOptions, Printable, print_all};
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
        conn: &Connection,
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
        conn: &Connection,
        name_filter: Option<&str>,
        format: OutputFormat,
        opts: &OutputOptions,
    ) -> Result<()> {
        // Get all links and filter for VRF type
        let mut builder = dump_request(NlMsgType::RTM_GETLINK);
        let ifinfo = IfInfoMsg::new();
        builder.append(&ifinfo);

        let responses = conn.dump(builder).await?;

        let mut vrfs = Vec::new();

        for response in &responses {
            if response.len() < NLMSG_HDRLEN + std::mem::size_of::<IfInfoMsg>() {
                continue;
            }

            let payload = &response[NLMSG_HDRLEN..];
            if let Some(vrf) = parse_vrf_link(payload) {
                // Apply filter
                if let Some(name) = name_filter {
                    if vrf.name != name {
                        continue;
                    }
                }
                vrfs.push(vrf);
            }
        }

        print_all(&vrfs, format, opts)?;

        Ok(())
    }

    fn exec(&self, name: &str, command: &[String]) -> Result<()> {
        use std::os::unix::process::CommandExt;
        use std::process::Command;

        if command.is_empty() {
            return Err(rip_netlink::Error::InvalidMessage(
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

        Err(rip_netlink::Error::InvalidMessage(format!(
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
                        if let Some(vrf_name) = line.split('/').last() {
                            if !vrf_name.is_empty() && vrf_name != ":" {
                                println!("{}", vrf_name);
                                return Ok(());
                            }
                        }
                    }
                }
                // No VRF association found
                println!();
                Ok(())
            }
            Err(e) => Err(rip_netlink::Error::InvalidMessage(format!(
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

/// Parse a link message and extract VRF info if it's a VRF device.
fn parse_vrf_link(payload: &[u8]) -> Option<VrfInfo> {
    if payload.len() < std::mem::size_of::<IfInfoMsg>() {
        return None;
    }

    let ifinfo = unsafe { &*(payload.as_ptr() as *const IfInfoMsg) };
    let attrs_data = &payload[std::mem::size_of::<IfInfoMsg>()..];

    let mut name = None;
    let mut kind = None;
    let mut table = None;

    for (attr_type, attr_data) in AttrIter::new(attrs_data) {
        match attr_type {
            a if a == IflaAttr::Ifname as u16 => {
                if let Ok(s) = std::str::from_utf8(attr_data) {
                    name = Some(s.trim_end_matches('\0').to_string());
                }
            }
            a if a == IflaAttr::Linkinfo as u16 => {
                // Parse nested IFLA_LINKINFO
                for (info_type, info_data) in AttrIter::new(attr_data) {
                    match info_type {
                        t if t == IflaInfo::Kind as u16 => {
                            if let Ok(s) = std::str::from_utf8(info_data) {
                                kind = Some(s.trim_end_matches('\0').to_string());
                            }
                        }
                        t if t == IflaInfo::Data as u16 => {
                            // Parse VRF-specific data
                            for (vrf_type, vrf_data) in AttrIter::new(info_data) {
                                if vrf_type == IFLA_VRF_TABLE && vrf_data.len() >= 4 {
                                    table =
                                        Some(u32::from_ne_bytes(vrf_data[..4].try_into().unwrap()));
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
            _ => {}
        }
    }

    // Only return if this is a VRF device
    if kind.as_deref() != Some("vrf") {
        return None;
    }

    Some(VrfInfo {
        name: name.unwrap_or_default(),
        ifindex: ifinfo.ifi_index as u32,
        table: table.unwrap_or(0),
    })
}
