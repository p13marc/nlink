//! tc action command implementation.
//!
//! Actions are operations attached to filters that control packet fate.
//! Common kinds: gact (pass/drop/etc.), mirred (mirror/redirect),
//! police (rate limit), vlan, skbedit, connmark, csum, sample,
//! tunnel_key, nat, simple, bpf, ct.

use std::io::{self, Write};

use clap::{Args, Subcommand};
use nlink::{
    Error, ParseParams,
    netlink::{
        Connection, Result, Route,
        action::{
            ActionMessage, BpfAction, ConnmarkAction, CsumAction, CtAction, CtinfoAction,
            GactAction, IfeAction, MirredAction, MplsAction, NatAction, PeditAction, PoliceAction,
            SampleAction, SimpleAction, SkbeditAction, SkbmodAction, TunnelKeyAction, VlanAction,
        },
        attr::AttrIter,
        types::tc::action::{
            self,
            gact::{TCA_GACT_PARMS, TcGact},
            mirred::{self, TCA_MIRRED_PARMS, TcMirred},
            police::{TCA_POLICE_TBF, TcPolice},
        },
    },
    output::{OutputFormat, OutputOptions, formatting::format_rate_bps},
};

#[derive(Args)]
pub struct ActionCmd {
    #[command(subcommand)]
    action: Option<ActionAction>,
}

#[derive(Subcommand)]
enum ActionAction {
    /// Show actions of a kind.
    Show {
        /// Action kind (gact, mirred, police, vlan, skbedit, connmark,
        /// csum, sample, tunnel_key, nat, simple, bpf, ct, pedit).
        kind: String,
    },

    /// List actions (alias for show).
    #[command(visible_alias = "ls")]
    List {
        /// Action kind.
        kind: String,
    },

    /// Add an action.
    Add {
        /// Action kind.
        kind: String,

        /// Kind-specific parameters (consumed by the kind's
        /// `parse_params`).
        #[arg(trailing_var_arg = true)]
        params: Vec<String>,
    },

    /// Delete an action by kind + index.
    Del {
        /// Action kind.
        kind: String,

        /// Action index (required — the typed CRUD lookup key).
        #[arg(long)]
        index: u32,
    },

    /// Get a specific action by kind + index.
    Get {
        /// Action kind.
        kind: String,

        /// Action index.
        index: u32,
    },
}

impl ActionCmd {
    pub async fn run(
        &self,
        conn: &Connection<Route>,
        format: OutputFormat,
        opts: &OutputOptions,
    ) -> Result<()> {
        match &self.action {
            Some(ActionAction::Show { kind }) | Some(ActionAction::List { kind }) => {
                Self::show_actions(conn, kind, format, opts).await
            }
            Some(ActionAction::Add { kind, params }) => {
                add_typed_action(conn, kind, params).await?;
                println!("Action added");
                Ok(())
            }
            Some(ActionAction::Del { kind, index }) => {
                conn.del_action(kind, *index).await?;
                println!("Action deleted");
                Ok(())
            }
            Some(ActionAction::Get { kind, index }) => {
                Self::get_action(conn, kind, *index, format, opts).await
            }
            None => {
                println!(
                    "Usage: tc action <show|add|del|get> <kind> [options]\n\
                     Recognised kinds: gact, mirred, police, vlan, skbedit, connmark, \
                     csum, sample, tunnel_key, nat, simple, bpf, ct, pedit"
                );
                Ok(())
            }
        }
    }

    async fn show_actions(
        conn: &Connection<Route>,
        kind: &str,
        format: OutputFormat,
        opts: &OutputOptions,
    ) -> Result<()> {
        let actions = conn.dump_actions(kind).await?;
        let stdout = io::stdout();
        let mut handle = stdout.lock();
        for am in &actions {
            print_action_message(&mut handle, am, format, opts)?;
        }
        Ok(())
    }

    async fn get_action(
        conn: &Connection<Route>,
        kind: &str,
        index: u32,
        format: OutputFormat,
        opts: &OutputOptions,
    ) -> Result<()> {
        match conn.get_action(kind, index).await? {
            Some(am) => {
                let stdout = io::stdout();
                let mut handle = stdout.lock();
                print_action_message(&mut handle, &am, format, opts)?;
            }
            None => {
                eprintln!("action {} index {} not found", kind, index);
            }
        }
        Ok(())
    }
}

/// Per-kind dispatch — parses the params via each action's
/// `ParseParams` impl and submits via the typed CRUD method.
/// Mirrors `try_typed_qdisc` / `try_typed_filter` from the qdisc /
/// filter subcommands.
async fn add_typed_action(conn: &Connection<Route>, kind: &str, params: &[String]) -> Result<()> {
    let refs: Vec<&str> = params.iter().map(String::as_str).collect();

    macro_rules! dispatch {
        ($Cfg:ident) => {{
            let cfg = <$Cfg as ParseParams>::parse_params(&refs)?;
            conn.add_action(cfg).await
        }};
    }

    match kind {
        "gact" => dispatch!(GactAction),
        "mirred" => dispatch!(MirredAction),
        "police" => dispatch!(PoliceAction),
        "vlan" => dispatch!(VlanAction),
        "skbedit" => dispatch!(SkbeditAction),
        "connmark" => dispatch!(ConnmarkAction),
        "csum" => dispatch!(CsumAction),
        "sample" => dispatch!(SampleAction),
        "tunnel_key" => dispatch!(TunnelKeyAction),
        "nat" => dispatch!(NatAction),
        "simple" => dispatch!(SimpleAction),
        "bpf" => dispatch!(BpfAction),
        "ct" => dispatch!(CtAction),
        "ctinfo" => dispatch!(CtinfoAction),
        "ife" => dispatch!(IfeAction),
        "pedit" => dispatch!(PeditAction),
        "mpls" => dispatch!(MplsAction),
        "skbmod" => dispatch!(SkbmodAction),
        other => Err(Error::InvalidMessage(format!(
            "tc action: unknown kind `{other}` (recognised: gact, mirred, police, vlan, skbedit, connmark, csum, sample, tunnel_key, nat, simple, bpf, ct, ctinfo, ife, pedit, mpls, skbmod)"
        ))),
    }
}

fn print_action_message(
    w: &mut impl Write,
    am: &ActionMessage,
    format: OutputFormat,
    opts: &OutputOptions,
) -> Result<()> {
    match format {
        OutputFormat::Json => {
            // Build a real serde_json value rather than hand-splicing
            // strings — escaping is handled and `-p/--pretty` works.
            let mut obj = serde_json::Map::new();
            obj.insert("kind".into(), serde_json::Value::from(am.kind.clone()));
            obj.insert("index".into(), serde_json::Value::from(am.index));
            if !am.options_raw.is_empty() {
                for (k, v) in action_options_json(&am.kind, &am.options_raw) {
                    obj.insert(k, v);
                }
            }
            let value = serde_json::Value::Object(obj);
            let rendered = if opts.pretty {
                serde_json::to_string_pretty(&value)
            } else {
                serde_json::to_string(&value)
            }
            .expect("JSON serialization");
            writeln!(w, "{rendered}")?;
        }
        OutputFormat::Text => {
            write!(w, "action {} index {} ", am.kind, am.index)?;
            if !am.options_raw.is_empty() {
                print_action_options_text(w, &am.kind, &am.options_raw)?;
            }
            writeln!(w)?;
        }
    }
    Ok(())
}

/// Extract an action's kind-specific options as JSON fields.
fn action_options_json(kind: &str, opts_data: &[u8]) -> serde_json::Map<String, serde_json::Value> {
    use serde_json::Value;
    let mut obj = serde_json::Map::new();
    match kind {
        "gact" => {
            for (attr_type, attr_data) in AttrIter::new(opts_data) {
                // Plan 209 H11 — alignment-safe zerocopy parse.
                if attr_type == TCA_GACT_PARMS
                    && let Ok((gact, _rest)) = <TcGact as zerocopy::FromBytes>::ref_from_prefix(attr_data)
                {
                    obj.insert(
                        "action".into(),
                        Value::from(action::format_action_result(gact.action)),
                    );
                    obj.insert("ref".into(), Value::from(gact.refcnt));
                    obj.insert("bind".into(), Value::from(gact.bindcnt));
                }
            }
        }
        "mirred" => {
            for (attr_type, attr_data) in AttrIter::new(opts_data) {
                if attr_type == TCA_MIRRED_PARMS
                    && let Ok((m, _rest)) = <TcMirred as zerocopy::FromBytes>::ref_from_prefix(attr_data)
                {
                    obj.insert(
                        "mirred_action".into(),
                        Value::from(mirred::format_mirred_action(m.eaction)),
                    );
                    obj.insert("ifindex".into(), Value::from(m.ifindex));
                    obj.insert(
                        "action".into(),
                        Value::from(action::format_action_result(m.action)),
                    );
                    obj.insert("ref".into(), Value::from(m.refcnt));
                    obj.insert("bind".into(), Value::from(m.bindcnt));
                }
            }
        }
        "police" => {
            for (attr_type, attr_data) in AttrIter::new(opts_data) {
                if attr_type == TCA_POLICE_TBF
                    && let Ok((p, _rest)) = <TcPolice as zerocopy::FromBytes>::ref_from_prefix(attr_data)
                {
                    obj.insert("rate".into(), Value::from(p.rate.rate));
                    obj.insert("burst".into(), Value::from(p.burst));
                    obj.insert("mtu".into(), Value::from(p.mtu));
                    obj.insert(
                        "action".into(),
                        Value::from(action::format_action_result(p.action)),
                    );
                    obj.insert("ref".into(), Value::from(p.refcnt));
                    obj.insert("bind".into(), Value::from(p.bindcnt));
                }
            }
        }
        _ => {}
    }
    obj
}

/// Print action options in text format.
fn print_action_options_text(w: &mut impl Write, kind: &str, opts_data: &[u8]) -> Result<()> {
    match kind {
        "gact" => {
            for (attr_type, attr_data) in AttrIter::new(opts_data) {
                // Plan 209 H11 — use zerocopy alignment-checked
                // ref_from_prefix instead of raw-pointer cast. The
                // old `*const TcGact` cast was UB on strict-
                // alignment targets (ARM/MIPS) — Vec<u8>'s data
                // pointer has no alignment guarantee.
                if attr_type == TCA_GACT_PARMS
                    && let Ok((gact, _rest)) = <TcGact as zerocopy::FromBytes>::ref_from_prefix(attr_data)
                {
                    write!(w, "{}", action::format_action_result(gact.action))?;
                    writeln!(w)?;
                    write!(w, "\tref {} bind {}", gact.refcnt, gact.bindcnt)?;
                }
            }
        }
        "mirred" => {
            for (attr_type, attr_data) in AttrIter::new(opts_data) {
                // Plan 209 H11 — zerocopy alignment-safe parse.
                if attr_type == TCA_MIRRED_PARMS
                    && let Ok((m, _rest)) = <TcMirred as zerocopy::FromBytes>::ref_from_prefix(attr_data)
                {
                    write!(
                        w,
                        "({} to device ifindex {}) {}",
                        mirred::format_mirred_action(m.eaction),
                        m.ifindex,
                        action::format_action_result(m.action)
                    )?;
                    writeln!(w)?;
                    write!(w, "\tref {} bind {}", m.refcnt, m.bindcnt)?;
                }
            }
        }
        "police" => {
            for (attr_type, attr_data) in AttrIter::new(opts_data) {
                // Plan 209 H11 — zerocopy alignment-safe parse.
                if attr_type == TCA_POLICE_TBF
                    && let Ok((p, _rest)) = <TcPolice as zerocopy::FromBytes>::ref_from_prefix(attr_data)
                {
                    write!(
                        w,
                        "rate {} burst {} mtu {} action {}",
                        format_rate_bps(p.rate.rate as u64),
                        p.burst,
                        p.mtu,
                        action::format_action_result(p.action)
                    )?;
                    writeln!(w)?;
                    write!(w, "\tref {} bind {}", p.refcnt, p.bindcnt)?;
                }
            }
        }
        _ => {}
    }

    Ok(())
}
