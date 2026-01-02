//! tc class command implementation.

use clap::{Args, Subcommand};
use nlink::netlink::message::NlMsgType;
use nlink::netlink::messages::TcMessage;
use nlink::netlink::types::tc::tc_handle;
use nlink::netlink::{Connection, Result};
use nlink::output::{OutputFormat, OutputOptions, print_all};
use nlink::tc::builders::class as class_builder;

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
        conn: &Connection,
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
            } => class_builder::add(conn, &dev, &parent, &classid, &kind, &params).await,
            ClassAction::Del {
                dev,
                parent,
                classid,
            } => class_builder::del(conn, &dev, &parent, &classid).await,
            ClassAction::Change {
                dev,
                parent,
                classid,
                kind,
                params,
            } => class_builder::change(conn, &dev, &parent, &classid, &kind, &params).await,
            ClassAction::Replace {
                dev,
                parent,
                classid,
                kind,
                params,
            } => class_builder::replace(conn, &dev, &parent, &classid, &kind, &params).await,
        }
    }

    async fn show(
        conn: &Connection,
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

        let parent_filter = parent.and_then(tc_handle::parse);
        let classid_filter = classid.and_then(tc_handle::parse);

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
