//! tc class command implementation.

use clap::{Args, Subcommand};
use nlink::{
    TcHandle,
    netlink::{
        Connection, Error, Result, Route, message::NlMsgType, messages::TcMessage,
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

        /// Class type (htb, etc.).
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
                let (parent, classid) = parse_handles(&parent, &classid)?;
                let refs: Vec<&str> = params.iter().map(String::as_str).collect();
                conn.add_class(dev.as_str(), parent, classid, &kind, &refs)
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
                let (parent, classid) = parse_handles(&parent, &classid)?;
                let refs: Vec<&str> = params.iter().map(String::as_str).collect();
                conn.change_class(dev.as_str(), parent, classid, &kind, &refs)
                    .await
            }
            ClassAction::Replace {
                dev,
                parent,
                classid,
                kind,
                params,
            } => {
                let (parent, classid) = parse_handles(&parent, &classid)?;
                let refs: Vec<&str> = params.iter().map(String::as_str).collect();
                conn.replace_class(dev.as_str(), parent, classid, &kind, &refs)
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

        let parent_filter = parent
            .and_then(tc_handle::parse)
            .map(nlink::TcHandle::from_raw);
        let classid_filter = classid
            .and_then(tc_handle::parse)
            .map(nlink::TcHandle::from_raw);

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
