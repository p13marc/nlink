//! tc filter command implementation.

use std::io::{self, Write};

use clap::{Args, Subcommand};
use nlink::{
    Error, TcHandle,
    netlink::{
        Connection, Result, Route,
        filter::{BpfFilter, FilterConfig, FlowerFilter, FwFilter, MatchallFilter, RouteFilter},
        message::NlMsgType,
        messages::TcMessage,
        types::tc::tc_handle,
    },
    output::{OutputFormat, OutputOptions, print_items},
};

// Deprecated in 0.14.0; only used as the long-tail fallback when the
// CLI gives a kind that doesn't yet have a typed parse_params (u32,
// basic, bpf, cgroup, route, flow). Flower / matchall / fw go
// through the typed dispatch below.
#[allow(deprecated)]
use nlink::tc::builders::filter as filter_builder;

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

// TODO(0.15+): migrate to Connection::add_filter + typed filter
// builders (FlowerFilter / U32Filter / MatchallFilter / ...). The
// legacy `tc::builders::filter` API is deprecated in 0.14.0 — the
// impl-level #[allow] covers both `run` (which dispatches add/del/
// change/replace) and the `show` helper's parse_protocol /
// format_protocol calls.
#[allow(deprecated)]
impl FilterCmd {
    pub async fn run(
        self,
        conn: &Connection<Route>,
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
            } => {
                if let Some(result) = try_typed_filter(
                    conn,
                    &dev,
                    &parent,
                    &protocol,
                    prio,
                    &kind,
                    &params,
                    FilterVerb::Add,
                )
                .await
                {
                    return result;
                }
                filter_builder::add(conn, &dev, &parent, &protocol, prio, &kind, &params).await
            }
            FilterAction::Del {
                dev,
                parent,
                protocol,
                prio,
                kind,
            } => {
                // Typed del path needs both protocol and prio (and a parsable
                // parent). Anything missing -> fall through to the legacy
                // filter_builder which knows how to handle the holes.
                if let Some(proto_str) = protocol.as_deref()
                    && let Some(p) = prio
                    && let Ok(parent_t) = parent.parse::<TcHandle>()
                    && let Ok(proto_u) = parse_protocol_u16(proto_str)
                {
                    return conn.del_filter(dev.as_str(), parent_t, proto_u, p).await;
                }
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
                if let Some(result) = try_typed_filter(
                    conn,
                    &dev,
                    &parent,
                    &protocol,
                    prio,
                    &kind,
                    &params,
                    FilterVerb::Replace,
                )
                .await
                {
                    return result;
                }
                filter_builder::replace(conn, &dev, &parent, &protocol, prio, &kind, &params).await
            }
            FilterAction::Change {
                dev,
                parent,
                protocol,
                prio,
                kind,
                params,
            } => {
                if let Some(result) = try_typed_filter(
                    conn,
                    &dev,
                    &parent,
                    &protocol,
                    prio,
                    &kind,
                    &params,
                    FilterVerb::Change,
                )
                .await
                {
                    return result;
                }
                filter_builder::change(conn, &dev, &parent, &protocol, prio, &kind, &params).await
            }
        }
    }

    async fn show(
        conn: &Connection<Route>,
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

        let parent_handle = tc_handle::parse(parent)
            .map(nlink::TcHandle::from_raw)
            .ok_or_else(|| {
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

/// Verb tag for `try_typed_filter` — picks add/replace/change at the
/// `Connection::*_filter_full` callsite.
#[derive(Clone, Copy)]
enum FilterVerb {
    Add,
    Replace,
    Change,
}

/// Try the typed dispatch path for known filter kinds (flower,
/// matchall, fw). Returns `Some(Ok)` on success, `Some(Err)` if the
/// typed parser rejected the params (we surface the error rather
/// than fall through, so a typo on a known kind doesn't get
/// silently rerouted through the looser legacy parser). Returns
/// `None` for unknown kinds — caller falls back to
/// `filter_builder::*`.
#[allow(clippy::too_many_arguments)] // mirrors the legacy filter_builder shape; bundling into a struct would just add ceremony
async fn try_typed_filter(
    conn: &Connection<Route>,
    dev: &str,
    parent: &str,
    protocol: &str,
    prio: Option<u16>,
    kind: &str,
    params: &[String],
    verb: FilterVerb,
) -> Option<Result<()>> {
    if !matches!(kind, "flower" | "matchall" | "fw" | "route" | "bpf") {
        return None;
    }
    let parent = match parent.parse::<TcHandle>() {
        Ok(h) => h,
        Err(_) => return None,
    };
    let proto = match parse_protocol_u16(protocol) {
        Ok(p) => p,
        Err(_) => return None,
    };
    let priority = prio.unwrap_or(0);

    let refs: Vec<&str> = params.iter().map(String::as_str).collect();

    macro_rules! dispatch {
        ($Cfg:ident) => {{
            let cfg = match $Cfg::parse_params(&refs) {
                Ok(c) => c,
                Err(e) => return Some(Err(e)),
            };
            run_typed_filter(conn, dev, parent, proto, priority, cfg, verb).await
        }};
    }
    Some(match kind {
        "flower" => dispatch!(FlowerFilter),
        "matchall" => dispatch!(MatchallFilter),
        "fw" => dispatch!(FwFilter),
        "route" => dispatch!(RouteFilter),
        "bpf" => dispatch!(BpfFilter),
        _ => unreachable!("checked by `matches!` guard above"),
    })
}

async fn run_typed_filter<C: FilterConfig>(
    conn: &Connection<Route>,
    dev: &str,
    parent: TcHandle,
    proto: u16,
    priority: u16,
    cfg: C,
    verb: FilterVerb,
) -> Result<()> {
    match verb {
        FilterVerb::Add => {
            conn.add_filter_full(dev, parent, None, proto, priority, cfg)
                .await
        }
        FilterVerb::Replace => {
            conn.replace_filter_full(dev, parent, None, proto, priority, cfg)
                .await
        }
        FilterVerb::Change => {
            conn.change_filter_full(dev, parent, None, proto, priority, cfg)
                .await
        }
    }
}

/// Wrap the legacy `filter_builder::parse_protocol` to surface its
/// result via `nlink::Error` and keep the typed dispatch above
/// independent of the deprecated module's exact error shape.
#[allow(deprecated)]
fn parse_protocol_u16(s: &str) -> Result<u16> {
    filter_builder::parse_protocol(s)
        .map_err(|e| Error::InvalidMessage(format!("invalid protocol `{s}`: {e}")))
}

/// Convert a TcMessage to JSON representation for filter.
#[allow(deprecated)] // filter_builder::format_protocol — see module deprecation plan
fn filter_to_json(filter: &TcMessage) -> serde_json::Value {
    let dev = nlink::util::get_ifname_or_index(filter.ifindex());

    let mut obj = serde_json::json!({
        "dev": dev,
        "kind": filter.kind().unwrap_or(""),
        "parent": filter.parent().to_string(),
        "protocol": filter_builder::format_protocol(filter.protocol()),
        "pref": filter.priority(),
    });

    if !filter.handle().is_unspec() {
        obj["handle"] = serde_json::json!(format!("{:x}", filter.handle_raw()));
    }

    if let Some(chain) = filter.chain() {
        obj["chain"] = serde_json::json!(chain);
    }

    if let Some(bpf) = filter.bpf_info() {
        let mut bpf_obj = serde_json::Map::new();
        if let Some(id) = bpf.id {
            bpf_obj.insert("id".into(), serde_json::json!(id));
        }
        if let Some(ref name) = bpf.name {
            bpf_obj.insert("name".into(), serde_json::json!(name));
        }
        if let Some(tag) = bpf.tag_hex() {
            bpf_obj.insert("tag".into(), serde_json::json!(tag));
        }
        bpf_obj.insert("direct_action".into(), serde_json::json!(bpf.direct_action));
        obj["bpf"] = serde_json::Value::Object(bpf_obj);
    }

    obj
}

/// Print filter in text format.
#[allow(deprecated)] // filter_builder::format_protocol — see module deprecation plan
fn print_filter_text(
    w: &mut io::StdoutLock<'_>,
    filter: &TcMessage,
    _opts: &OutputOptions,
) -> io::Result<()> {
    let dev = nlink::util::get_ifname_or_index(filter.ifindex());

    write!(
        w,
        "filter parent {} protocol {} pref {} {} ",
        filter.parent(),
        filter_builder::format_protocol(filter.protocol()),
        filter.priority(),
        filter.kind().unwrap_or("")
    )?;

    if let Some(chain) = filter.chain() {
        write!(w, "chain {} ", chain)?;
    }

    if !filter.handle().is_unspec() {
        write!(w, "handle {:x} ", filter.handle_raw())?;
    }

    write!(w, "dev {}", dev)?;

    // Show BPF program info if present
    if let Some(bpf) = filter.bpf_info() {
        if let Some(ref name) = bpf.name {
            write!(w, " [{name}]")?;
        }
        if let Some(id) = bpf.id {
            write!(w, " id {id}")?;
        }
        if let Some(tag) = bpf.tag_hex() {
            write!(w, " tag {tag}")?;
        }
        if bpf.direct_action {
            write!(w, " direct-action")?;
        }
    }

    writeln!(w)?;

    Ok(())
}
