//! ip xfrm command implementation.
//!
//! IPSec/XFRM transformation management. Manages Security
//! Associations (SAs) and Security Policies (SPs) over the kernel's
//! NETLINK_XFRM interface via `Connection<Xfrm>`.

use std::{io::Write, net::IpAddr};

use clap::{Args, Subcommand};
use nlink::{
    netlink::{
        Connection, Result, Xfrm,
        xfrm::{SecurityAssociation, SecurityPolicy},
    },
    output::{OutputFormat, OutputOptions, Printable, print_all},
};

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

fn addr_or_any(a: Option<IpAddr>) -> String {
    a.map(|ip| ip.to_string()).unwrap_or_else(|| "any".into())
}

/// Wrapper so we can implement the local `Printable` trait for the
/// library's `SecurityAssociation` (orphan rule).
struct SaRow(SecurityAssociation);

impl Printable for SaRow {
    fn print_text<W: Write>(&self, w: &mut W, _opts: &OutputOptions) -> std::io::Result<()> {
        let sa = &self.0;
        writeln!(
            w,
            "src {} dst {}",
            addr_or_any(sa.src_addr),
            addr_or_any(sa.dst_addr)
        )?;
        writeln!(
            w,
            "\tproto {:?} spi 0x{:08x} reqid {} mode {:?}",
            sa.protocol, sa.spi, sa.reqid, sa.mode
        )?;
        if let Some(ref a) = sa.aead_alg {
            writeln!(w, "\taead {} ({} bits)", a.name, a.key_len)?;
        }
        if let Some(ref a) = sa.enc_alg {
            writeln!(w, "\tenc {} ({} bits)", a.name, a.key_len)?;
        }
        if let Some(ref a) = sa.auth_alg {
            writeln!(w, "\tauth {} ({} bits)", a.name, a.key_len)?;
        }
        Ok(())
    }

    fn to_json(&self) -> serde_json::Value {
        let sa = &self.0;
        serde_json::json!({
            "src": sa.src_addr.map(|a| a.to_string()),
            "dst": sa.dst_addr.map(|a| a.to_string()),
            "proto": format!("{:?}", sa.protocol),
            "spi": format!("0x{:08x}", sa.spi),
            "reqid": sa.reqid,
            "mode": format!("{:?}", sa.mode),
            "enc": sa.enc_alg.as_ref().map(|a| a.name.clone()),
            "auth": sa.auth_alg.as_ref().map(|a| a.name.clone()),
            "aead": sa.aead_alg.as_ref().map(|a| a.name.clone()),
        })
    }
}

/// Wrapper so we can implement `Printable` for `SecurityPolicy`.
struct SpRow(SecurityPolicy);

impl Printable for SpRow {
    fn print_text<W: Write>(&self, w: &mut W, _opts: &OutputOptions) -> std::io::Result<()> {
        let sp = &self.0;
        let sel = &sp.selector;
        writeln!(
            w,
            "src {}/{} dst {}/{}",
            addr_or_any(sel.src_addr),
            sel.src_prefix_len,
            addr_or_any(sel.dst_addr),
            sel.dst_prefix_len
        )?;
        writeln!(
            w,
            "\tdir {:?} priority {} action {:?} index {}",
            sp.direction, sp.priority, sp.action, sp.index
        )?;
        Ok(())
    }

    fn to_json(&self) -> serde_json::Value {
        let sp = &self.0;
        let sel = &sp.selector;
        serde_json::json!({
            "src": sel.src_addr.map(|a| a.to_string()),
            "src_prefix_len": sel.src_prefix_len,
            "dst": sel.dst_addr.map(|a| a.to_string()),
            "dst_prefix_len": sel.dst_prefix_len,
            "dir": format!("{:?}", sp.direction),
            "priority": sp.priority,
            "action": format!("{:?}", sp.action),
            "index": sp.index,
        })
    }
}

impl XfrmCmd {
    pub async fn run(&self, format: OutputFormat, opts: &OutputOptions) -> Result<()> {
        match &self.action {
            XfrmAction::State { action } => match action.as_ref().unwrap_or(&StateAction::Show) {
                StateAction::Show | StateAction::List => Self::show_states(format, opts).await,
                StateAction::Flush => Self::flush_states().await,
                StateAction::Count => Self::count_states().await,
            },
            XfrmAction::Policy { action } => match action.as_ref().unwrap_or(&PolicyAction::Show) {
                PolicyAction::Show | PolicyAction::List => Self::show_policies(format, opts).await,
                PolicyAction::Flush => Self::flush_policies().await,
                PolicyAction::Count => Self::count_policies().await,
            },
            XfrmAction::Monitor => Self::monitor().await,
        }
    }

    async fn show_states(format: OutputFormat, opts: &OutputOptions) -> Result<()> {
        let conn = Connection::<Xfrm>::new()?;
        let rows: Vec<SaRow> = conn
            .get_security_associations()
            .await?
            .into_iter()
            .map(SaRow)
            .collect();
        print_all(&rows, format, opts)?;
        Ok(())
    }

    async fn flush_states() -> Result<()> {
        let conn = Connection::<Xfrm>::new()?;
        conn.flush_sa().await?;
        eprintln!("Flushed all XFRM states");
        Ok(())
    }

    async fn count_states() -> Result<()> {
        let conn = Connection::<Xfrm>::new()?;
        println!("{}", conn.get_security_associations().await?.len());
        Ok(())
    }

    async fn show_policies(format: OutputFormat, opts: &OutputOptions) -> Result<()> {
        let conn = Connection::<Xfrm>::new()?;
        let rows: Vec<SpRow> = conn
            .get_security_policies()
            .await?
            .into_iter()
            .map(SpRow)
            .collect();
        print_all(&rows, format, opts)?;
        Ok(())
    }

    async fn flush_policies() -> Result<()> {
        let conn = Connection::<Xfrm>::new()?;
        conn.flush_sp().await?;
        eprintln!("Flushed all XFRM policies");
        Ok(())
    }

    async fn count_policies() -> Result<()> {
        let conn = Connection::<Xfrm>::new()?;
        println!("{}", conn.get_security_policies().await?.len());
        Ok(())
    }

    async fn monitor() -> Result<()> {
        // XFRM multicast event subscription isn't exposed by the
        // library yet (no subscribe/events on Connection<Xfrm>).
        eprintln!("ip xfrm monitor is not yet implemented (no XFRM event API)");
        Ok(())
    }
}
