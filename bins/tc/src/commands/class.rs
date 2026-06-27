//! tc class command implementation.

use clap::{Args, Subcommand};
use nlink::{
    Error, TcHandle,
    netlink::{
        Connection, Result, Route,
        message::NlMsgType,
        messages::TcMessage,
        tc::{ClassConfig, DrrClassConfig, HfscClassConfig, HtbClassConfig, QfqClassConfig},
        types::tc::tc_handle,
    },
    output::{OutputFormat, OutputOptions, print_all},
};

#[derive(Args)]
pub struct ClassCmd {
    #[command(subcommand)]
    action: Option<ClassAction>,
}

#[derive(Subcommand)]
enum ClassAction {
    /// Show classes.
    Show {
        /// Device name.
        dev: String,

        /// Qdisc type to filter.
        #[arg(long)]
        kind: Option<String>,

        /// Parent handle.
        #[arg(long)]
        parent: Option<String>,

        /// Specific classid.
        #[arg(long)]
        classid: Option<String>,
    },

    /// List classes (alias for show).
    #[command(visible_alias = "ls")]
    List {
        /// Device name.
        dev: String,
    },

    /// Add a class.
    Add {
        /// Device name.
        dev: String,

        /// Parent handle.
        #[arg(long)]
        parent: String,

        /// Class ID.
        #[arg(long)]
        classid: String,

        /// Class type (htb, hfsc, drr, qfq).
        #[arg(name = "TYPE")]
        kind: String,

        /// Type-specific parameters.
        #[arg(trailing_var_arg = true)]
        params: Vec<String>,
    },

    /// Delete a class.
    Del {
        /// Device name.
        dev: String,

        /// Parent handle.
        #[arg(long)]
        parent: String,

        /// Class ID to delete.
        #[arg(long)]
        classid: String,
    },

    /// Change a class.
    Change {
        /// Device name.
        dev: String,

        /// Parent handle.
        #[arg(long)]
        parent: String,

        /// Class ID.
        #[arg(long)]
        classid: String,

        /// Class type.
        #[arg(name = "TYPE")]
        kind: String,

        /// Type-specific parameters.
        #[arg(trailing_var_arg = true)]
        params: Vec<String>,
    },

    /// Replace a class.
    Replace {
        /// Device name.
        dev: String,

        /// Parent handle.
        #[arg(long)]
        parent: String,

        /// Class ID.
        #[arg(long)]
        classid: String,

        /// Class type.
        #[arg(name = "TYPE")]
        kind: String,

        /// Type-specific parameters.
        #[arg(trailing_var_arg = true)]
        params: Vec<String>,
    },
}

#[derive(Clone, Copy)]
enum ClassVerb {
    Add,
    Change,
    Replace,
}

impl ClassCmd {
    pub async fn run(
        self,
        conn: &Connection<Route>,
        format: OutputFormat,
        opts: &OutputOptions,
    ) -> Result<()> {
        match self
            .action
            .unwrap_or(ClassAction::List { dev: String::new() })
        {
            ClassAction::Show {
                dev,
                kind,
                parent,
                classid,
            } => {
                Self::show(
                    conn,
                    &dev,
                    kind.as_deref(),
                    parent.as_deref(),
                    classid.as_deref(),
                    format,
                    opts,
                )
                .await
            }
            ClassAction::List { dev } => {
                Self::show(conn, &dev, None, None, None, format, opts).await
            }
            ClassAction::Add {
                dev,
                parent,
                classid,
                kind,
                params,
            } => {
                dispatch_class(
                    conn,
                    &dev,
                    &parent,
                    &classid,
                    &kind,
                    &params,
                    ClassVerb::Add,
                )
                .await
            }
            ClassAction::Del {
                dev,
                parent,
                classid,
            } => {
                let (parent, classid) = parse_handles(&parent, &classid)?;
                conn.del_class(dev.as_str(), parent, classid).await
            }
            ClassAction::Change {
                dev,
                parent,
                classid,
                kind,
                params,
            } => {
                dispatch_class(
                    conn,
                    &dev,
                    &parent,
                    &classid,
                    &kind,
                    &params,
                    ClassVerb::Change,
                )
                .await
            }
            ClassAction::Replace {
                dev,
                parent,
                classid,
                kind,
                params,
            } => {
                dispatch_class(
                    conn,
                    &dev,
                    &parent,
                    &classid,
                    &kind,
                    &params,
                    ClassVerb::Replace,
                )
                .await
            }
        }
    }

    async fn show(
        conn: &Connection<Route>,
        dev: &str,
        kind_filter: Option<&str>,
        parent: Option<&str>,
        classid: Option<&str>,
        format: OutputFormat,
        opts: &OutputOptions,
    ) -> Result<()> {
        if dev.is_empty() {
            return Err(nlink::netlink::Error::InvalidMessage(
                "device name required".into(),
            ));
        }

        let ifindex =
            nlink::util::get_ifindex(dev).map_err(nlink::netlink::Error::InvalidMessage)?;

        // Strict: a present-but-unparseable handle is an error, not a
        // silently-dropped filter (which would dump *all* classes and
        // mislead the user). See the CLAUDE.md strict-parse contract.
        let parent_filter = parse_handle_filter(parent, "parent")?;
        let classid_filter = parse_handle_filter(classid, "classid")?;

        // Fetch all classes using typed API
        let all_classes: Vec<TcMessage> = conn.dump_typed(NlMsgType::RTM_GETTCLASS).await?;

        // Filter classes
        let classes: Vec<_> = all_classes
            .into_iter()
            .filter(|c| {
                // Filter by interface
                if c.ifindex() != ifindex {
                    return false;
                }
                // Filter by kind if specified
                if let Some(k) = kind_filter
                    && c.kind() != Some(k)
                {
                    return false;
                }
                // Filter by parent if specified
                if let Some(p) = parent_filter
                    && c.parent() != p
                {
                    return false;
                }
                // Filter by classid if specified
                if let Some(cid) = classid_filter
                    && c.handle() != cid
                {
                    return false;
                }
                true
            })
            .collect();

        print_all(&classes, format, opts)?;

        Ok(())
    }
}

/// Parse tc-style parent / classid handles from the CLI, surfacing a
/// clear error when either is malformed.
fn parse_handles(parent: &str, classid: &str) -> Result<(TcHandle, TcHandle)> {
    let parent = parent
        .parse::<TcHandle>()
        .map_err(|e| Error::InvalidMessage(format!("invalid parent `{parent}`: {e}")))?;
    let classid = classid
        .parse::<TcHandle>()
        .map_err(|e| Error::InvalidMessage(format!("invalid classid `{classid}`: {e}")))?;
    Ok((parent, classid))
}

/// Typed dispatch path for every class kind nlink models. Unknown
/// kinds error cleanly with a recognised-kinds list — there is no
/// silent fallback to a looser legacy parser.
async fn dispatch_class(
    conn: &Connection<Route>,
    dev: &str,
    parent: &str,
    classid: &str,
    kind: &str,
    params: &[String],
    verb: ClassVerb,
) -> Result<()> {
    let (parent, classid) = parse_handles(parent, classid)?;
    let refs: Vec<&str> = params.iter().map(String::as_str).collect();

    macro_rules! dispatch {
        ($Cfg:ident) => {{
            let cfg = <$Cfg as nlink::ParseParams>::parse_params(&refs)?;
            run_typed_class(conn, dev, parent, classid, cfg, verb).await
        }};
    }
    match kind {
        "htb" => dispatch!(HtbClassConfig),
        "hfsc" => dispatch!(HfscClassConfig),
        "drr" => dispatch!(DrrClassConfig),
        "qfq" => dispatch!(QfqClassConfig),
        other => Err(Error::InvalidMessage(format!(
            "tc class: unknown kind `{other}` (recognised: htb, hfsc, drr, qfq)"
        ))),
    }
}

async fn run_typed_class<C: ClassConfig>(
    conn: &Connection<Route>,
    dev: &str,
    parent: TcHandle,
    classid: TcHandle,
    cfg: C,
    verb: ClassVerb,
) -> Result<()> {
    match verb {
        ClassVerb::Add => conn.add_class(dev, parent, classid, cfg).await,
        ClassVerb::Change => conn.change_class(dev, parent, classid, cfg).await,
        ClassVerb::Replace => conn.replace_class(dev, parent, classid, cfg).await,
    }
}

/// Strictly parse an optional tc handle used as a `show` filter.
/// A present-but-unparseable value is an error (it must not silently
/// degrade to "no filter", which would dump every class).
fn parse_handle_filter(s: Option<&str>, what: &str) -> Result<Option<TcHandle>> {
    match s {
        None => Ok(None),
        Some(v) => tc_handle::parse(v).map(TcHandle::from_raw).map(Some).ok_or_else(|| {
            Error::InvalidMessage(format!(
                "tc class show: invalid {what} `{v}` (expected a tc handle like `1:10`)"
            ))
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handle_filter_strict() {
        assert!(parse_handle_filter(None, "parent").unwrap().is_none());
        assert!(parse_handle_filter(Some("1:10"), "parent").unwrap().is_some());
        // present but garbage -> error (not a silent "no filter")
        assert!(parse_handle_filter(Some("not-a-handle"), "classid").is_err());
    }
}
