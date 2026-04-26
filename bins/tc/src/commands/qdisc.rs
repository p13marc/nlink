//! tc qdisc command implementation.

use clap::{Args, Subcommand};
use nlink::{
    Error, TcHandle,
    netlink::{
        Connection, Result, Route,
        message::NlMsgType,
        messages::TcMessage,
        tc::{
            CakeConfig, ClsactConfig, DrrConfig, EtfConfig, FqCodelConfig, HfscConfig,
            HtbQdiscConfig, IngressConfig, MqprioConfig, NetemConfig, PieConfig, PlugConfig,
            PrioConfig, QdiscConfig, QfqConfig, RedConfig, SfqConfig, TaprioConfig, TbfConfig,
        },
    },
    output::{OutputFormat, OutputOptions, print_all},
};

#[derive(Args)]
pub struct QdiscCmd {
    #[command(subcommand)]
    action: Option<QdiscAction>,
}

#[derive(Subcommand)]
enum QdiscAction {
    /// Show qdiscs.
    Show {
        /// Device name (use "dev NAME" or just "NAME").
        #[arg(value_name = "DEV")]
        dev: Option<String>,

        /// Show invisible qdiscs.
        #[arg(long)]
        invisible: bool,
    },

    /// List qdiscs (alias for show).
    #[command(visible_alias = "ls")]
    List {
        /// Device name.
        #[arg(value_name = "DEV")]
        dev: Option<String>,
    },

    /// Add a qdisc.
    Add {
        /// Device name.
        #[arg(value_name = "DEV")]
        dev: String,

        /// Parent handle (root, ingress, or handle).
        #[arg(long, default_value = "root")]
        parent: String,

        /// Handle for this qdisc.
        #[arg(long)]
        handle: Option<String>,

        /// Qdisc type (htb, fq_codel, prio, tbf, etc.).
        #[arg(name = "TYPE")]
        kind: String,

        /// Type-specific parameters.
        #[arg(trailing_var_arg = true)]
        params: Vec<String>,
    },

    /// Delete a qdisc.
    Del {
        /// Device name.
        dev: String,

        /// Parent handle.
        #[arg(long, default_value = "root")]
        parent: String,

        /// Handle to delete.
        #[arg(long)]
        handle: Option<String>,
    },

    /// Replace a qdisc.
    Replace {
        /// Device name.
        dev: String,

        /// Parent handle.
        #[arg(long, default_value = "root")]
        parent: String,

        /// Handle for this qdisc.
        #[arg(long)]
        handle: Option<String>,

        /// Qdisc type.
        #[arg(name = "TYPE")]
        kind: String,

        /// Type-specific parameters.
        #[arg(trailing_var_arg = true)]
        params: Vec<String>,
    },

    /// Change a qdisc.
    Change {
        /// Device name.
        dev: String,

        /// Parent handle.
        #[arg(long, default_value = "root")]
        parent: String,

        /// Handle for this qdisc.
        #[arg(long)]
        handle: Option<String>,

        /// Qdisc type.
        #[arg(name = "TYPE")]
        kind: String,

        /// Type-specific parameters.
        #[arg(trailing_var_arg = true)]
        params: Vec<String>,
    },
}

impl QdiscCmd {
    pub async fn run(
        self,
        conn: &Connection<Route>,
        format: OutputFormat,
        opts: &OutputOptions,
    ) -> Result<()> {
        match self.action.unwrap_or(QdiscAction::Show {
            dev: None,
            invisible: false,
        }) {
            QdiscAction::Show { dev, invisible } => {
                Self::show(conn, dev.as_deref(), invisible, format, opts).await
            }
            QdiscAction::List { dev } => {
                Self::show(conn, dev.as_deref(), false, format, opts).await
            }
            QdiscAction::Add {
                dev,
                parent,
                handle,
                kind,
                params,
            } => Self::add(conn, &dev, &parent, handle.as_deref(), &kind, &params).await,
            QdiscAction::Del {
                dev,
                parent,
                handle,
            } => Self::del(conn, &dev, &parent, handle.as_deref()).await,
            QdiscAction::Replace {
                dev,
                parent,
                handle,
                kind,
                params,
            } => Self::replace(conn, &dev, &parent, handle.as_deref(), &kind, &params).await,
            QdiscAction::Change {
                dev,
                parent,
                handle,
                kind,
                params,
            } => Self::change(conn, &dev, &parent, handle.as_deref(), &kind, &params).await,
        }
    }

    async fn show(
        conn: &Connection<Route>,
        dev: Option<&str>,
        _invisible: bool,
        format: OutputFormat,
        opts: &OutputOptions,
    ) -> Result<()> {
        // Get interface index if filtering
        let filter_index =
            nlink::util::get_ifindex_opt(dev).map_err(nlink::netlink::Error::InvalidMessage)?;

        // Fetch all qdiscs using typed API
        let all_qdiscs: Vec<TcMessage> = conn.dump_typed(NlMsgType::RTM_GETQDISC).await?;

        // Filter by device if specified
        let qdiscs: Vec<_> = all_qdiscs
            .into_iter()
            .filter(|q| {
                if let Some(idx) = filter_index {
                    q.ifindex() == idx
                } else {
                    true
                }
            })
            .collect();

        print_all(&qdiscs, format, opts)?;

        Ok(())
    }

    async fn add(
        conn: &Connection<Route>,
        dev: &str,
        parent: &str,
        handle: Option<&str>,
        kind: &str,
        params: &[String],
    ) -> Result<()> {
        dispatch_qdisc(conn, dev, parent, handle, kind, params, QdiscVerb::Add).await
    }

    async fn del(
        conn: &Connection<Route>,
        dev: &str,
        parent: &str,
        handle: Option<&str>,
    ) -> Result<()> {
        let (p, h) = parse_qdisc_handles(parent, handle)?;
        conn.del_qdisc_full(dev, p, h).await
    }

    async fn replace(
        conn: &Connection<Route>,
        dev: &str,
        parent: &str,
        handle: Option<&str>,
        kind: &str,
        params: &[String],
    ) -> Result<()> {
        dispatch_qdisc(conn, dev, parent, handle, kind, params, QdiscVerb::Replace).await
    }

    async fn change(
        conn: &Connection<Route>,
        dev: &str,
        parent: &str,
        handle: Option<&str>,
        kind: &str,
        params: &[String],
    ) -> Result<()> {
        dispatch_qdisc(conn, dev, parent, handle, kind, params, QdiscVerb::Change).await
    }
}

/// Verb tag for `try_typed_qdisc` — picks add/replace/change at the
/// `Connection::*_qdisc_full` callsite without duplicating the
/// per-kind dispatch in three places.
#[derive(Clone, Copy)]
enum QdiscVerb {
    Add,
    Replace,
    Change,
}

/// Parse the CLI's `parent` (always present) and `handle` (optional)
/// strings into typed `TcHandle` values. Returns Err on parse
/// failure so callers can fall back to the legacy string-args path.
fn parse_qdisc_handles(parent: &str, handle: Option<&str>) -> Result<(TcHandle, Option<TcHandle>)> {
    let parent = parent
        .parse::<TcHandle>()
        .map_err(|e| Error::InvalidMessage(format!("invalid parent `{parent}`: {e}")))?;
    let handle = handle
        .map(|s| {
            s.parse::<TcHandle>()
                .map_err(|e| Error::InvalidMessage(format!("invalid handle `{s}`: {e}")))
        })
        .transpose()?;
    Ok((parent, handle))
}

/// Typed dispatch path for every qdisc kind nlink models. Unknown
/// kinds error cleanly with a recognised-kinds list — there's no
/// silent fallback to a looser legacy parser anymore.
async fn dispatch_qdisc(
    conn: &Connection<Route>,
    dev: &str,
    parent: &str,
    handle: Option<&str>,
    kind: &str,
    params: &[String],
    verb: QdiscVerb,
) -> Result<()> {
    let (parent, handle) = parse_qdisc_handles(parent, handle)?;
    let refs: Vec<&str> = params.iter().map(String::as_str).collect();

    macro_rules! dispatch {
        ($Cfg:ident) => {{
            // Bind through the ParseParams trait so the dispatcher's
            // contract is type-checked, not just convention.
            let cfg = <$Cfg as nlink::ParseParams>::parse_params(&refs)?;
            run_typed_qdisc(conn, dev, parent, handle, cfg, verb).await
        }};
    }
    match kind {
        "htb" => dispatch!(HtbQdiscConfig),
        "netem" => dispatch!(NetemConfig),
        "cake" => dispatch!(CakeConfig),
        "tbf" => dispatch!(TbfConfig),
        "sfq" => dispatch!(SfqConfig),
        "prio" => dispatch!(PrioConfig),
        "fq_codel" => dispatch!(FqCodelConfig),
        "red" => dispatch!(RedConfig),
        "pie" => dispatch!(PieConfig),
        "hfsc" => dispatch!(HfscConfig),
        "drr" => dispatch!(DrrConfig),
        "qfq" => dispatch!(QfqConfig),
        "ingress" => dispatch!(IngressConfig),
        "clsact" => dispatch!(ClsactConfig),
        "plug" => dispatch!(PlugConfig),
        "mqprio" => dispatch!(MqprioConfig),
        "etf" => dispatch!(EtfConfig),
        "taprio" => dispatch!(TaprioConfig),
        other => Err(Error::InvalidMessage(format!(
            "tc qdisc: unknown kind `{other}` (recognised: htb, netem, cake, tbf, sfq, prio, fq_codel, red, pie, hfsc, drr, qfq, ingress, clsact, plug, mqprio, etf, taprio)"
        ))),
    }
}

async fn run_typed_qdisc<C: QdiscConfig>(
    conn: &Connection<Route>,
    dev: &str,
    parent: TcHandle,
    handle: Option<TcHandle>,
    cfg: C,
    verb: QdiscVerb,
) -> Result<()> {
    match verb {
        QdiscVerb::Add => conn.add_qdisc_full(dev, parent, handle, cfg).await,
        QdiscVerb::Replace => conn.replace_qdisc_full(dev, parent, handle, cfg).await,
        QdiscVerb::Change => conn.change_qdisc_full(dev, parent, handle, cfg).await,
    }
}
