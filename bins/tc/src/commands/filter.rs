//! tc filter command implementation.

use std::io::{self, Write};

use clap::{Args, Subcommand};
use nlink::{
    Error, TcHandle,
    netlink::{
        Connection, Result, Route,
        filter::{
            BasicFilter, BpfFilter, CgroupFilter, FilterConfig, FlowFilter, FlowerFilter,
            FwFilter, MatchallFilter, RouteFilter, U32Filter,
        },
        message::NlMsgType,
        messages::TcMessage,
        types::tc::tc_handle,
    },
    output::{OutputFormat, OutputOptions, print_items},
};

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
                dispatch_filter(
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
            }
            FilterAction::Del {
                dev,
                parent,
                protocol,
                prio,
                kind: _,
            } => {
                // Typed del_filter requires (parent, protocol, prio) — partial
                // specs (e.g. delete-by-kind-only) are no longer supported by
                // the bin; users must supply all three.
                let proto_str = protocol.as_deref().ok_or_else(|| {
                    Error::InvalidMessage(
                        "tc filter del: --protocol is required (typed del needs the full lookup tuple)"
                            .to_string(),
                    )
                })?;
                let p = prio.ok_or_else(|| {
                    Error::InvalidMessage(
                        "tc filter del: --prio is required (typed del needs the full lookup tuple)"
                            .to_string(),
                    )
                })?;
                let parent_t = parent.parse::<TcHandle>().map_err(|e| {
                    Error::InvalidMessage(format!("tc filter del: invalid parent `{parent}`: {e}"))
                })?;
                let proto_u = parse_protocol_u16(proto_str)?;
                conn.del_filter(dev.as_str(), parent_t, proto_u, p).await
            }
            FilterAction::Replace {
                dev,
                parent,
                protocol,
                prio,
                kind,
                params,
            } => {
                dispatch_filter(
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
            }
            FilterAction::Change {
                dev,
                parent,
                protocol,
                prio,
                kind,
                params,
            } => {
                dispatch_filter(
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

        let proto_filter = protocol_filter.map(parse_protocol_u16).transpose()?;

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

/// Typed dispatch for every filter kind nlink models. Unknown
/// kinds error cleanly with a recognised-kinds list; there's no
/// silent fallback to a looser legacy parser anymore.
#[allow(clippy::too_many_arguments)] // 7 args mirror the tc(8) CLI surface; bundling into a struct would just add ceremony
async fn dispatch_filter(
    conn: &Connection<Route>,
    dev: &str,
    parent: &str,
    protocol: &str,
    prio: Option<u16>,
    kind: &str,
    params: &[String],
    verb: FilterVerb,
) -> Result<()> {
    let parent = parent.parse::<TcHandle>().map_err(|e| {
        Error::InvalidMessage(format!("tc filter: invalid parent `{parent}`: {e}"))
    })?;
    let proto = parse_protocol_u16(protocol)?;
    let priority = prio.unwrap_or(0);

    let refs: Vec<&str> = params.iter().map(String::as_str).collect();

    macro_rules! dispatch {
        ($Cfg:ident) => {{
            // Bind through the ParseParams trait so the dispatcher's
            // contract is type-checked, not just convention.
            let cfg = <$Cfg as nlink::ParseParams>::parse_params(&refs)?;
            run_typed_filter(conn, dev, parent, proto, priority, cfg, verb).await
        }};
    }
    match kind {
        "flower" => dispatch!(FlowerFilter),
        "matchall" => dispatch!(MatchallFilter),
        "fw" => dispatch!(FwFilter),
        "route" => dispatch!(RouteFilter),
        "bpf" => dispatch!(BpfFilter),
        "cgroup" => dispatch!(CgroupFilter),
        "flow" => dispatch!(FlowFilter),
        "u32" => dispatch!(U32Filter),
        "basic" => dispatch!(BasicFilter),
        other => Err(Error::InvalidMessage(format!(
            "tc filter: unknown kind `{other}` (recognised: flower, matchall, fw, route, bpf, cgroup, flow, u32, basic)"
        ))),
    }
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

/// Parse a protocol name (or hex `0x…`) into the kernel's `u16`.
/// Recognised names mirror what `tc(8)` accepts.
fn parse_protocol_u16(s: &str) -> Result<u16> {
    Ok(match s.to_lowercase().as_str() {
        "all" => 0x0003,             // ETH_P_ALL
        "ip" => 0x0800,              // ETH_P_IP
        "ipv6" => 0x86DD,            // ETH_P_IPV6
        "arp" => 0x0806,             // ETH_P_ARP
        "802.1q" | "vlan" => 0x8100, // ETH_P_8021Q
        "802.1ad" => 0x88A8,         // ETH_P_8021AD
        "mpls_uc" => 0x8847,         // ETH_P_MPLS_UC
        "mpls_mc" => 0x8848,         // ETH_P_MPLS_MC
        _ => {
            if let Some(hex) = s.strip_prefix("0x") {
                u16::from_str_radix(hex, 16).map_err(|_| {
                    Error::InvalidMessage(format!("invalid protocol: {s}"))
                })?
            } else {
                s.parse().map_err(|_| {
                    Error::InvalidMessage(format!("unknown protocol: {s}"))
                })?
            }
        }
    })
}

/// Inverse of [`parse_protocol_u16`]. Inlined for the same
/// reason — keeps the bin off the deprecated module.
fn format_protocol(proto: u16) -> String {
    match proto {
        0x0003 => "all".to_string(),
        0x0800 => "ip".to_string(),
        0x86DD => "ipv6".to_string(),
        0x0806 => "arp".to_string(),
        0x8100 => "802.1Q".to_string(),
        0x88A8 => "802.1ad".to_string(),
        0x8847 => "mpls_uc".to_string(),
        0x8848 => "mpls_mc".to_string(),
        _ => format!("0x{proto:04x}"),
    }
}

/// Convert a TcMessage to JSON representation for filter.
fn filter_to_json(filter: &TcMessage) -> serde_json::Value {
    let dev = nlink::util::get_ifname_or_index(filter.ifindex());

    let mut obj = serde_json::json!({
        "dev": dev,
        "kind": filter.kind().unwrap_or(""),
        "parent": filter.parent().to_string(),
        "protocol": format_protocol(filter.protocol()),
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
        format_protocol(filter.protocol()),
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
