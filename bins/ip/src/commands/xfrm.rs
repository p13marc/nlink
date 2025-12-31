//! ip xfrm command implementation.
//!
//! IPSec/XFRM transformation management.
//! Manages Security Associations (SAs) and Security Policies (SPs).

use clap::{Args, Subcommand};
use rip_netlink::Result;
use rip_output::{OutputFormat, OutputOptions, Printable, print_all};
use std::fs;
use std::io::Write;
use std::net::IpAddr;

#[derive(Args)]
pub struct XfrmCmd {
    #[command(subcommand)]
    action: XfrmAction,
}

#[derive(Subcommand)]
enum XfrmAction {
    /// Manage XFRM state (Security Associations).
    State {
        #[command(subcommand)]
        action: Option<StateAction>,
    },

    /// Manage XFRM policy (Security Policies).
    Policy {
        #[command(subcommand)]
        action: Option<PolicyAction>,
    },

    /// Monitor XFRM events.
    Monitor,
}

#[derive(Subcommand)]
enum StateAction {
    /// Show XFRM states.
    Show,
    /// List XFRM states (alias for show).
    #[command(visible_alias = "ls")]
    List,
    /// Flush all XFRM states.
    Flush,
    /// Get state count.
    Count,
}

#[derive(Subcommand)]
enum PolicyAction {
    /// Show XFRM policies.
    Show,
    /// List XFRM policies (alias for show).
    #[command(visible_alias = "ls")]
    List,
    /// Flush all XFRM policies.
    Flush,
    /// Get policy count.
    Count,
}

/// XFRM state information parsed from /proc/net/xfrm_stat.
#[derive(Debug)]
struct XfrmState {
    src: IpAddr,
    dst: IpAddr,
    proto: String,
    spi: u32,
    mode: String,
    reqid: u32,
}

impl Printable for XfrmState {
    fn print_text<W: Write>(&self, w: &mut W, _opts: &OutputOptions) -> std::io::Result<()> {
        writeln!(w, "src {} dst {}", self.src, self.dst)?;
        writeln!(
            w,
            "\tproto {} spi 0x{:08x} reqid {} mode {}",
            self.proto, self.spi, self.reqid, self.mode
        )?;
        Ok(())
    }

    fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "src": self.src.to_string(),
            "dst": self.dst.to_string(),
            "proto": self.proto,
            "spi": format!("0x{:08x}", self.spi),
            "reqid": self.reqid,
            "mode": self.mode,
        })
    }
}

/// XFRM policy information.
#[derive(Debug)]
struct XfrmPolicy {
    src: String,
    dst: String,
    dir: String,
    priority: u32,
    action: String,
}

impl Printable for XfrmPolicy {
    fn print_text<W: Write>(&self, w: &mut W, _opts: &OutputOptions) -> std::io::Result<()> {
        writeln!(w, "src {} dst {}", self.src, self.dst)?;
        writeln!(
            w,
            "\tdir {} priority {} action {}",
            self.dir, self.priority, self.action
        )?;
        Ok(())
    }

    fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "src": self.src,
            "dst": self.dst,
            "dir": self.dir,
            "priority": self.priority,
            "action": self.action,
        })
    }
}

impl XfrmCmd {
    pub async fn run(&self, format: OutputFormat, opts: &OutputOptions) -> Result<()> {
        match &self.action {
            XfrmAction::State { action } => match action.as_ref().unwrap_or(&StateAction::Show) {
                StateAction::Show | StateAction::List => self.show_states(format, opts).await,
                StateAction::Flush => self.flush_states().await,
                StateAction::Count => self.count_states().await,
            },
            XfrmAction::Policy { action } => match action.as_ref().unwrap_or(&PolicyAction::Show) {
                PolicyAction::Show | PolicyAction::List => self.show_policies(format, opts).await,
                PolicyAction::Flush => self.flush_policies().await,
                PolicyAction::Count => self.count_policies().await,
            },
            XfrmAction::Monitor => self.monitor().await,
        }
    }

    async fn show_states(&self, format: OutputFormat, opts: &OutputOptions) -> Result<()> {
        // Read states from /proc/net/xfrm_state
        // Note: Full implementation would use XFRM netlink messages
        // For now, parse the proc file which gives basic info

        let states = parse_xfrm_states()?;
        print_all(&states, format, opts)?;
        Ok(())
    }

    async fn flush_states(&self) -> Result<()> {
        // Would require XFRM_MSG_FLUSHSA netlink message
        // For now, indicate this is not fully implemented
        eprintln!("Note: Full XFRM netlink support requires additional implementation");
        eprintln!("Use 'ip xfrm state flush' from iproute2 for now");
        Ok(())
    }

    async fn count_states(&self) -> Result<()> {
        let states = parse_xfrm_states()?;
        println!("{}", states.len());
        Ok(())
    }

    async fn show_policies(&self, format: OutputFormat, opts: &OutputOptions) -> Result<()> {
        let policies = parse_xfrm_policies()?;
        print_all(&policies, format, opts)?;
        Ok(())
    }

    async fn flush_policies(&self) -> Result<()> {
        // Would require XFRM_MSG_FLUSHPOLICY netlink message
        eprintln!("Note: Full XFRM netlink support requires additional implementation");
        eprintln!("Use 'ip xfrm policy flush' from iproute2 for now");
        Ok(())
    }

    async fn count_policies(&self) -> Result<()> {
        let policies = parse_xfrm_policies()?;
        println!("{}", policies.len());
        Ok(())
    }

    async fn monitor(&self) -> Result<()> {
        // Would require subscribing to XFRM netlink multicast group
        eprintln!("XFRM monitoring requires netlink XFRM support");
        eprintln!("Use 'ip xfrm monitor' from iproute2 for now");
        Ok(())
    }
}

/// Parse XFRM states from the kernel.
/// Note: This is a simplified implementation that reads from proc.
/// A full implementation would use XFRM netlink messages.
fn parse_xfrm_states() -> Result<Vec<XfrmState>> {
    let states = Vec::new();

    // Try to read from /proc/net/xfrm_stat first for statistics
    if let Ok(content) = fs::read_to_string("/proc/net/xfrm_stat") {
        // This file contains statistics, not state entries
        // State entries require netlink XFRM_MSG_GETSA
        let _ = content; // Statistics parsing could be added
    }

    // For actual state listing, we would need netlink
    // Return empty for now - this is a placeholder
    // In production, implement XFRM_MSG_GETSA

    Ok(states)
}

/// Parse XFRM policies from the kernel.
fn parse_xfrm_policies() -> Result<Vec<XfrmPolicy>> {
    let policies = Vec::new();

    // For actual policy listing, we would need netlink
    // This is a placeholder - implement XFRM_MSG_GETPOLICY

    Ok(policies)
}
