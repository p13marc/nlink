//! tc action command implementation.
//!
//! Actions are operations attached to filters that control packet fate.
//! Common actions include:
//! - gact: Generic action (pass, drop, etc.)
//! - mirred: Mirror or redirect to another interface
//! - police: Rate limiting with token bucket

use clap::{Args, Subcommand};
use rip_netlink::attr::AttrIter;
use rip_netlink::connection::dump_request;
use rip_netlink::message::{NLMSG_HDRLEN, NlMsgType};
use rip_netlink::types::tc::action::{
    self, TCA_ACT_KIND, TCA_ACT_OPTIONS,
    gact::{TCA_GACT_PARMS, TcGact},
    mirred::{self, TCA_MIRRED_PARMS, TcMirred},
    police::{TCA_POLICE_TBF, TcPolice},
};
use rip_netlink::types::tc::{TCA_ACT_TAB, TcMsg};
use rip_netlink::{Connection, Result};
use rip_output::{OutputFormat, OutputOptions};
use rip_tclib::builders::action as action_builder;
use std::io::{self, Write};

#[derive(Args)]
pub struct ActionCmd {
    #[command(subcommand)]
    action: Option<ActionAction>,
}

#[derive(Subcommand)]
enum ActionAction {
    /// Show actions.
    Show {
        /// Action type (gact, mirred, police).
        kind: String,
    },

    /// List actions (alias for show).
    #[command(visible_alias = "ls")]
    List {
        /// Action type.
        kind: String,
    },

    /// Add an action.
    Add {
        /// Action type (gact, mirred, police).
        kind: String,

        /// Action-specific parameters.
        #[arg(trailing_var_arg = true)]
        params: Vec<String>,
    },

    /// Delete an action.
    Del {
        /// Action type.
        kind: String,

        /// Action index.
        #[arg(long)]
        index: Option<u32>,
    },

    /// Get a specific action.
    Get {
        /// Action type.
        kind: String,

        /// Action index.
        index: u32,
    },
}

impl ActionCmd {
    pub async fn run(
        &self,
        conn: &Connection,
        format: OutputFormat,
        opts: &OutputOptions,
    ) -> Result<()> {
        match &self.action {
            Some(ActionAction::Show { kind }) | Some(ActionAction::List { kind }) => {
                Self::show_actions(conn, kind, format, opts).await
            }
            Some(ActionAction::Add { kind, params }) => {
                action_builder::add(conn, kind, params).await?;
                println!("Action added");
                Ok(())
            }
            Some(ActionAction::Del { kind, index }) => {
                action_builder::del(conn, kind, *index).await?;
                println!("Action deleted");
                Ok(())
            }
            Some(ActionAction::Get { kind, index }) => {
                Self::get_action(conn, kind, *index, format, opts).await
            }
            None => {
                println!("Usage: tc action <show|add|del|get> <type> [options]");
                println!("Action types: gact, mirred, police");
                Ok(())
            }
        }
    }

    async fn show_actions(
        conn: &Connection,
        kind: &str,
        format: OutputFormat,
        _opts: &OutputOptions,
    ) -> Result<()> {
        let mut builder = dump_request(NlMsgType::RTM_GETACTION);

        // Add tcmsg header (zeroed for action dump)
        let tcmsg = TcMsg::default();
        builder.append(&tcmsg);

        // Add TCA_ACT_TAB with action kind
        let tab_token = builder.nest_start(TCA_ACT_TAB);
        let act_token = builder.nest_start(1); // First action slot
        builder.append_attr(TCA_ACT_KIND, kind.as_bytes());
        builder.nest_end(act_token);
        builder.nest_end(tab_token);

        let responses = conn.dump(builder).await?;

        let stdout = io::stdout();
        let mut handle = stdout.lock();

        for response in responses {
            if response.len() < NLMSG_HDRLEN + std::mem::size_of::<TcMsg>() {
                continue;
            }

            let payload = &response[NLMSG_HDRLEN..];
            if payload.len() < std::mem::size_of::<TcMsg>() {
                continue;
            }

            let attrs_data = &payload[std::mem::size_of::<TcMsg>()..];
            print_action_response(&mut handle, attrs_data, format)?;
        }

        Ok(())
    }

    async fn get_action(
        conn: &Connection,
        kind: &str,
        index: u32,
        format: OutputFormat,
        _opts: &OutputOptions,
    ) -> Result<()> {
        let response = action_builder::get(conn, kind, index).await?;

        let stdout = io::stdout();
        let mut handle = stdout.lock();

        if response.len() >= NLMSG_HDRLEN + std::mem::size_of::<TcMsg>() {
            let payload = &response[NLMSG_HDRLEN..];
            let attrs_data = &payload[std::mem::size_of::<TcMsg>()..];
            print_action_response(&mut handle, attrs_data, format)?;
        }

        Ok(())
    }
}

/// Print action response.
fn print_action_response(
    w: &mut impl Write,
    attrs_data: &[u8],
    format: OutputFormat,
) -> Result<()> {
    // Parse TCA_ACT_TAB
    for (attr_type, attr_data) in AttrIter::new(attrs_data) {
        if attr_type == TCA_ACT_TAB {
            // Iterate over actions in the tab
            for (act_idx, act_data) in AttrIter::new(attr_data) {
                if act_idx == 0 {
                    continue;
                }
                print_single_action(w, act_data, format)?;
            }
        }
    }

    Ok(())
}

/// Print a single action.
fn print_single_action(w: &mut impl Write, act_data: &[u8], format: OutputFormat) -> Result<()> {
    let mut kind: Option<&str> = None;
    let mut options_data: Option<&[u8]> = None;

    for (attr_type, attr_data) in AttrIter::new(act_data) {
        match attr_type {
            TCA_ACT_KIND => {
                if let Ok(k) = std::str::from_utf8(attr_data) {
                    kind = Some(k.trim_end_matches('\0'));
                }
            }
            TCA_ACT_OPTIONS => {
                options_data = Some(attr_data);
            }
            _ => {}
        }
    }

    let kind = kind.unwrap_or("unknown");

    match format {
        OutputFormat::Json => {
            write!(w, "{{\"kind\":\"{}\",", kind)?;
            if let Some(opts) = options_data {
                print_action_options_json(w, kind, opts)?;
            }
            writeln!(w, "}}")?;
        }
        OutputFormat::Text => {
            write!(w, "action {} ", kind)?;
            if let Some(opts) = options_data {
                print_action_options_text(w, kind, opts)?;
            }
            writeln!(w)?;
        }
    }

    Ok(())
}

/// Print action options in JSON format.
fn print_action_options_json(w: &mut impl Write, kind: &str, opts_data: &[u8]) -> Result<()> {
    match kind {
        "gact" => {
            for (attr_type, attr_data) in AttrIter::new(opts_data) {
                if attr_type == TCA_GACT_PARMS && attr_data.len() >= std::mem::size_of::<TcGact>() {
                    let gact = unsafe { &*(attr_data.as_ptr() as *const TcGact) };
                    write!(
                        w,
                        "\"action\":\"{}\",\"index\":{},\"ref\":{},\"bind\":{}",
                        action::format_action_result(gact.action),
                        gact.index,
                        gact.refcnt,
                        gact.bindcnt
                    )?;
                }
            }
        }
        "mirred" => {
            for (attr_type, attr_data) in AttrIter::new(opts_data) {
                if attr_type == TCA_MIRRED_PARMS
                    && attr_data.len() >= std::mem::size_of::<TcMirred>()
                {
                    let m = unsafe { &*(attr_data.as_ptr() as *const TcMirred) };
                    write!(
                        w,
                        "\"mirred_action\":\"{}\",\"ifindex\":{},\"action\":\"{}\",\"index\":{},\"ref\":{},\"bind\":{}",
                        mirred::format_mirred_action(m.eaction),
                        m.ifindex,
                        action::format_action_result(m.action),
                        m.index,
                        m.refcnt,
                        m.bindcnt
                    )?;
                }
            }
        }
        "police" => {
            for (attr_type, attr_data) in AttrIter::new(opts_data) {
                if attr_type == TCA_POLICE_TBF && attr_data.len() >= std::mem::size_of::<TcPolice>()
                {
                    let p = unsafe { &*(attr_data.as_ptr() as *const TcPolice) };
                    write!(
                        w,
                        "\"rate\":{},\"burst\":{},\"mtu\":{},\"action\":\"{}\",\"index\":{},\"ref\":{},\"bind\":{}",
                        p.rate.rate,
                        p.burst,
                        p.mtu,
                        action::format_action_result(p.action),
                        p.index,
                        p.refcnt,
                        p.bindcnt
                    )?;
                }
            }
        }
        _ => {}
    }

    Ok(())
}

/// Print action options in text format.
fn print_action_options_text(w: &mut impl Write, kind: &str, opts_data: &[u8]) -> Result<()> {
    match kind {
        "gact" => {
            for (attr_type, attr_data) in AttrIter::new(opts_data) {
                if attr_type == TCA_GACT_PARMS && attr_data.len() >= std::mem::size_of::<TcGact>() {
                    let gact = unsafe { &*(attr_data.as_ptr() as *const TcGact) };
                    write!(w, "{}", action::format_action_result(gact.action))?;
                    writeln!(w)?;
                    write!(
                        w,
                        "\tindex {} ref {} bind {}",
                        gact.index, gact.refcnt, gact.bindcnt
                    )?;
                }
            }
        }
        "mirred" => {
            for (attr_type, attr_data) in AttrIter::new(opts_data) {
                if attr_type == TCA_MIRRED_PARMS
                    && attr_data.len() >= std::mem::size_of::<TcMirred>()
                {
                    let m = unsafe { &*(attr_data.as_ptr() as *const TcMirred) };
                    write!(
                        w,
                        "({} to device ifindex {}) {}",
                        mirred::format_mirred_action(m.eaction),
                        m.ifindex,
                        action::format_action_result(m.action)
                    )?;
                    writeln!(w)?;
                    write!(w, "\tindex {} ref {} bind {}", m.index, m.refcnt, m.bindcnt)?;
                }
            }
        }
        "police" => {
            for (attr_type, attr_data) in AttrIter::new(opts_data) {
                if attr_type == TCA_POLICE_TBF && attr_data.len() >= std::mem::size_of::<TcPolice>()
                {
                    let p = unsafe { &*(attr_data.as_ptr() as *const TcPolice) };
                    write!(
                        w,
                        "rate {} burst {} mtu {} action {}",
                        format_rate(p.rate.rate as u64),
                        p.burst,
                        p.mtu,
                        action::format_action_result(p.action)
                    )?;
                    writeln!(w)?;
                    write!(w, "\tindex {} ref {} bind {}", p.index, p.refcnt, p.bindcnt)?;
                }
            }
        }
        _ => {}
    }

    Ok(())
}

/// Format rate for display.
fn format_rate(rate: u64) -> String {
    if rate >= 1_000_000_000 {
        format!("{}Gbit", rate / 1_000_000_000)
    } else if rate >= 1_000_000 {
        format!("{}Mbit", rate / 1_000_000)
    } else if rate >= 1000 {
        format!("{}Kbit", rate / 1000)
    } else {
        format!("{}bit", rate)
    }
}
