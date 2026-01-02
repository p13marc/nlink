//! tc filter command implementation.

use clap::{Args, Subcommand};
use nlink::netlink::message::NlMsgType;
use nlink::netlink::messages::TcMessage;
use nlink::netlink::types::tc::tc_handle;
use nlink::netlink::{Connection, Result};
use nlink::output::{OutputFormat, OutputOptions, print_items};
use nlink::tc::builders::filter as filter_builder;
use std::io::{self, Write};

#[derive(Args)]
pub struct FilterCmd {
    #[command(subcommand)]
    action: Option<FilterAction>,
}

#[derive(Subcommand)]
enum FilterAction {
    /// Show filters.
    Show {
        /// Device name.
        dev: String,

        /// Parent qdisc/class.
        #[arg(long, default_value = "root")]
        parent: String,

        /// Protocol (ip, ipv6, all, etc.).
        #[arg(long)]
        protocol: Option<String>,

        /// Priority/preference.
        #[arg(long)]
        prio: Option<u16>,
    },

    /// List filters (alias for show).
    #[command(visible_alias = "ls")]
    List {
        /// Device name.
        dev: String,
    },

    /// Add a filter.
    Add {
        /// Device name.
        dev: String,

        /// Parent qdisc/class.
        #[arg(long, default_value = "root")]
        parent: String,

        /// Protocol.
        #[arg(long, default_value = "ip")]
        protocol: String,

        /// Priority.
        #[arg(long)]
        prio: Option<u16>,

        /// Filter type (u32, flower, basic, etc.).
        #[arg(name = "TYPE")]
        kind: String,

        /// Type-specific parameters.
        #[arg(trailing_var_arg = true)]
        params: Vec<String>,
    },

    /// Delete a filter.
    Del {
        /// Device name.
        dev: String,

        /// Parent qdisc/class.
        #[arg(long, default_value = "root")]
        parent: String,

        /// Protocol.
        #[arg(long)]
        protocol: Option<String>,

        /// Priority.
        #[arg(long)]
        prio: Option<u16>,

        /// Filter type.
        #[arg(name = "TYPE")]
        kind: Option<String>,
    },

    /// Replace a filter.
    Replace {
        /// Device name.
        dev: String,

        /// Parent qdisc/class.
        #[arg(long, default_value = "root")]
        parent: String,

        /// Protocol.
        #[arg(long, default_value = "ip")]
        protocol: String,

        /// Priority.
        #[arg(long)]
        prio: Option<u16>,

        /// Filter type.
        #[arg(name = "TYPE")]
        kind: String,

        /// Type-specific parameters.
        #[arg(trailing_var_arg = true)]
        params: Vec<String>,
    },

    /// Change a filter.
    Change {
        /// Device name.
        dev: String,

        /// Parent qdisc/class.
        #[arg(long, default_value = "root")]
        parent: String,

        /// Protocol.
        #[arg(long, default_value = "ip")]
        protocol: String,

        /// Priority.
        #[arg(long)]
        prio: Option<u16>,

        /// Filter type.
        #[arg(name = "TYPE")]
        kind: String,

        /// Type-specific parameters.
        #[arg(trailing_var_arg = true)]
        params: Vec<String>,
    },
}

impl FilterCmd {
    pub async fn run(
        self,
        conn: &Connection,
        format: OutputFormat,
        opts: &OutputOptions,
    ) -> Result<()> {
        match self
            .action
            .unwrap_or(FilterAction::List { dev: String::new() })
        {
            FilterAction::Show {
                dev,
                parent,
                protocol,
                prio,
            } => Self::show(conn, &dev, &parent, protocol.as_deref(), prio, format, opts).await,
            FilterAction::List { dev } => {
                Self::show(conn, &dev, "root", None, None, format, opts).await
            }
            FilterAction::Add {
                dev,
                parent,
                protocol,
                prio,
                kind,
                params,
            } => filter_builder::add(conn, &dev, &parent, &protocol, prio, &kind, &params).await,
            FilterAction::Del {
                dev,
                parent,
                protocol,
                prio,
                kind,
            } => {
                filter_builder::del(
                    conn,
                    &dev,
                    &parent,
                    protocol.as_deref(),
                    prio,
                    kind.as_deref(),
                )
                .await
            }
            FilterAction::Replace {
                dev,
                parent,
                protocol,
                prio,
                kind,
                params,
            } => {
                filter_builder::replace(conn, &dev, &parent, &protocol, prio, &kind, &params).await
            }
            FilterAction::Change {
                dev,
                parent,
                protocol,
                prio,
                kind,
                params,
            } => filter_builder::change(conn, &dev, &parent, &protocol, prio, &kind, &params).await,
        }
    }

    async fn show(
        conn: &Connection,
        dev: &str,
        parent: &str,
        protocol_filter: Option<&str>,
        prio_filter: Option<u16>,
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

        let parent_handle = tc_handle::parse(parent).ok_or_else(|| {
            nlink::netlink::Error::InvalidMessage(format!("invalid parent: {}", parent))
        })?;

        let proto_filter = protocol_filter
            .map(filter_builder::parse_protocol)
            .transpose()?;

        // Fetch all filters using typed API
        let all_filters: Vec<TcMessage> = conn.dump_typed(NlMsgType::RTM_GETTFILTER).await?;

        // Filter results
        let filters: Vec<_> = all_filters
            .into_iter()
            .filter(|f| {
                // Filter by interface
                if f.ifindex() != ifindex {
                    return false;
                }
                // Filter by parent
                if f.parent() != parent_handle {
                    return false;
                }
                // Filter by protocol if specified
                if let Some(proto) = proto_filter
                    && f.protocol() != proto
                {
                    return false;
                }
                // Filter by priority if specified
                if let Some(prio) = prio_filter
                    && f.priority() != prio
                {
                    return false;
                }
                true
            })
            .collect();

        print_items(&filters, format, opts, filter_to_json, print_filter_text)?;

        Ok(())
    }
}

/// Convert a TcMessage to JSON representation for filter.
fn filter_to_json(filter: &TcMessage) -> serde_json::Value {
    let dev = nlink::util::get_ifname_or_index(filter.ifindex());

    let mut obj = serde_json::json!({
        "dev": dev,
        "kind": filter.kind().unwrap_or(""),
        "parent": tc_handle::format(filter.parent()),
        "protocol": filter_builder::format_protocol(filter.protocol()),
        "pref": filter.priority(),
    });

    if filter.handle() != 0 {
        obj["handle"] = serde_json::json!(format!("{:x}", filter.handle()));
    }

    if let Some(chain) = filter.chain {
        obj["chain"] = serde_json::json!(chain);
    }

    obj
}

/// Print filter in text format.
fn print_filter_text(
    w: &mut io::StdoutLock<'_>,
    filter: &TcMessage,
    _opts: &OutputOptions,
) -> io::Result<()> {
    let dev = nlink::util::get_ifname_or_index(filter.ifindex());

    write!(
        w,
        "filter parent {} protocol {} pref {} {} ",
        tc_handle::format(filter.parent()),
        filter_builder::format_protocol(filter.protocol()),
        filter.priority(),
        filter.kind().unwrap_or("")
    )?;

    if let Some(chain) = filter.chain {
        write!(w, "chain {} ", chain)?;
    }

    if filter.handle() != 0 {
        write!(w, "handle {:x} ", filter.handle())?;
    }

    write!(w, "dev {}", dev)?;

    writeln!(w)?;

    Ok(())
}
