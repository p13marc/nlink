//! Capture command - capture current network state as configuration.

use std::collections::BTreeMap;

use clap::Args;
use nlink::netlink::{
    Connection, Result, Route,
    types::{route::RouteType, rule::FibRuleAction},
};

use crate::schema::{
    AddressConfig, ConfigFile, LinkConfig, OutputFormat, QdiscConfig, RouteConfig, RuleConfig,
};

#[derive(Args)]
pub struct CaptureArgs {
    /// Output format
    #[arg(short, long, value_enum, default_value = "yaml")]
    pub format: OutputFormat,

    /// Capture only specific interface
    #[arg(short, long)]
    pub interface: Option<String>,

    /// Include TC configuration
    #[arg(long)]
    pub tc: bool,

    /// Include routing rules
    #[arg(long)]
    pub rules: bool,

    /// Include all details
    #[arg(long)]
    pub full: bool,

    /// Skip loopback interface
    #[arg(long, default_value = "true")]
    pub skip_loopback: bool,
}

pub async fn run(args: CaptureArgs) -> Result<()> {
    let conn = Connection::<Route>::new()?;

    let include_tc = args.tc || args.full;
    let include_rules = args.rules || args.full;

    // Build interface name map
    let names = conn.get_interface_names().await?;

    // Capture links
    let links = conn.get_links().await?;
    let mut link_configs = Vec::new();

    for link in &links {
        let name = link.name().unwrap_or("?");

        // Skip loopback if requested
        if args.skip_loopback && link.is_loopback() {
            continue;
        }

        // Filter by interface if specified
        if let Some(ref filter) = args.interface
            && name != filter
        {
            continue;
        }

        let kind = link
            .link_info()
            .and_then(|i| i.kind())
            .map(|s| s.to_string());
        let state = if link.is_up() { "up" } else { "down" }.to_string();
        let mtu = link.mtu();
        let master = link.master().and_then(|idx| names.get(&idx).cloned());
        let mac = link.address().map(|a| {
            a.iter()
                .map(|b| format!("{:02x}", b))
                .collect::<Vec<_>>()
                .join(":")
        });

        link_configs.push(LinkConfig {
            name: name.to_string(),
            kind,
            state: Some(state),
            mtu,
            master,
            mac,
            options: BTreeMap::new(),
        });
    }

    // Capture addresses
    let addresses = conn.get_addresses().await?;
    let mut addr_configs = Vec::new();

    for addr in &addresses {
        let dev = names
            .get(&addr.ifindex())
            .map(|s| s.as_str())
            .unwrap_or("?");

        // Filter by interface if specified
        if let Some(ref filter) = args.interface
            && dev != filter
        {
            continue;
        }

        // Skip loopback addresses if requested
        if args.skip_loopback
            && let Some(link) = links.iter().find(|l| l.ifindex() == addr.ifindex())
            && link.is_loopback()
        {
            continue;
        }

        let address = addr
            .address()
            .map(|a| format!("{}/{}", a, addr.prefix_len()))
            .unwrap_or_default();

        let broadcast = addr.broadcast().map(|a| a.to_string());
        let label = addr.label().map(|s| s.to_string());

        if !address.is_empty() {
            addr_configs.push(AddressConfig {
                dev: dev.to_string(),
                address,
                broadcast,
                label,
            });
        }
    }

    // Capture routes
    let routes = conn.get_routes().await?;
    let mut route_configs = Vec::new();

    for route in &routes {
        // Skip local/broadcast routes unless full mode
        if !args.full {
            let rt_type = route.route_type();
            if rt_type == RouteType::Local || rt_type == RouteType::Broadcast {
                continue;
            }
        }

        // Filter by interface if specified
        if let Some(ref filter) = args.interface {
            if let Some(oif) = route.oif() {
                let dev = names.get(&oif).map(|s| s.as_str()).unwrap_or("?");
                if dev != filter {
                    continue;
                }
            } else {
                continue;
            }
        }

        let destination = route
            .destination()
            .map(|d| {
                if route.dst_len() == 0 {
                    "default".to_string()
                } else {
                    format!("{}/{}", d, route.dst_len())
                }
            })
            .unwrap_or_else(|| "default".to_string());

        let gateway = route.gateway().map(|g| g.to_string());
        let dev = route.oif().and_then(|idx| names.get(&idx).cloned());
        let metric = route.priority();
        let table = {
            let t = route.table_id();
            match t {
                254 => None, // main table
                253 => Some("default".to_string()),
                0 => Some("unspec".to_string()),
                255 => Some("local".to_string()),
                n => Some(n.to_string()),
            }
        };
        let route_type = match route.route_type() {
            RouteType::Unicast => None,
            RouteType::Local => Some("local".to_string()),
            RouteType::Broadcast => Some("broadcast".to_string()),
            RouteType::Blackhole => Some("blackhole".to_string()),
            RouteType::Unreachable => Some("unreachable".to_string()),
            RouteType::Prohibit => Some("prohibit".to_string()),
            other => {
                // Don't let an unmodelled route type vanish silently from
                // the captured config — warn and preserve its raw name.
                eprintln!(
                    "warning: route to {destination} has unmodelled type {other:?}; captured as-is"
                );
                Some(format!("{other:?}").to_lowercase())
            }
        };

        route_configs.push(RouteConfig {
            destination,
            gateway,
            dev,
            metric,
            table,
            route_type,
        });
    }

    // Capture rules if requested
    let mut rule_configs = Vec::new();
    if include_rules {
        let rules = conn.get_rules().await?;
        for rule in &rules {
            // Skip default rules unless full mode
            if !args.full && rule.is_default() {
                continue;
            }

            let from = rule.source().map(|addr| {
                if rule.src_len() == 0 {
                    "all".to_string()
                } else {
                    format!("{}/{}", addr, rule.src_len())
                }
            });
            let to = rule.destination().map(|addr| {
                if rule.dst_len() == 0 {
                    "all".to_string()
                } else {
                    format!("{}/{}", addr, rule.dst_len())
                }
            });
            let fwmark = rule.fwmark().map(|m| format!("0x{:x}", m));
            let table = {
                let t = rule.table_id();
                match t {
                    254 => Some("main".to_string()),
                    253 => Some("default".to_string()),
                    255 => Some("local".to_string()),
                    0 => None,
                    n => Some(n.to_string()),
                }
            };
            let action = match rule.action() {
                FibRuleAction::ToTbl => None,
                FibRuleAction::Blackhole => Some("blackhole".to_string()),
                FibRuleAction::Unreachable => Some("unreachable".to_string()),
                FibRuleAction::Prohibit => Some("prohibit".to_string()),
                other => {
                    eprintln!(
                        "warning: rule prio {} has unmodelled action {other:?}; captured as-is",
                        rule.priority()
                    );
                    Some(format!("{other:?}").to_lowercase())
                }
            };

            rule_configs.push(RuleConfig {
                priority: rule.priority(),
                from,
                to,
                fwmark,
                table,
                action,
            });
        }
    }

    // Capture qdiscs if requested
    let mut qdisc_configs = Vec::new();
    if include_tc {
        let qdiscs = conn.get_qdiscs().await?;
        for qdisc in &qdiscs {
            let dev = names
                .get(&qdisc.ifindex())
                .map(|s| s.as_str())
                .unwrap_or("?");

            // Filter by interface if specified
            if let Some(ref filter) = args.interface
                && dev != filter
            {
                continue;
            }

            // Skip loopback qdiscs
            if args.skip_loopback
                && let Some(link) = links.iter().find(|l| l.ifindex() == qdisc.ifindex())
                && link.is_loopback()
            {
                continue;
            }

            let parent = if qdisc.is_root() {
                "root".to_string()
            } else if qdisc.is_ingress() {
                "ingress".to_string()
            } else {
                qdisc.parent_str()
            };

            let kind = qdisc.kind().unwrap_or("unknown").to_string();
            let handle = if !qdisc.handle().is_unspec() {
                Some(qdisc.handle_str())
            } else {
                None
            };

            let options = qdisc_options_map(qdisc);

            qdisc_configs.push(QdiscConfig {
                dev: dev.to_string(),
                parent,
                kind,
                handle,
                options,
            });
        }
    }

    let config = ConfigFile {
        links: link_configs,
        addresses: addr_configs,
        routes: route_configs,
        rules: rule_configs,
        qdiscs: qdisc_configs,
    };

    match args.format {
        OutputFormat::Yaml => {
            println!(
                "{}",
                serde_yaml::to_string(&config).map_err(|e| {
                    nlink::netlink::Error::InvalidMessage(format!(
                        "YAML serialization failed: {}",
                        e
                    ))
                })?
            );
        }
        OutputFormat::Json => {
            println!(
                "{}",
                serde_json::to_string_pretty(&config).map_err(|e| {
                    nlink::netlink::Error::InvalidMessage(format!(
                        "JSON serialization failed: {}",
                        e
                    ))
                })?
            );
        }
    }

    Ok(())
}

/// Decode a captured qdisc's parameters into a `key -> value` map for the
/// `QdiscConfig.options` field. Covers the common shaping/AQM kinds
/// (htb / tbf / netem / fq_codel); other kinds capture their `kind` +
/// `handle` but leave options empty (the library decodes their bytes only
/// behind typed accessors, not a generic map).
fn qdisc_options_map(
    qdisc: &nlink::netlink::messages::TcMessage,
) -> BTreeMap<String, serde_yaml::Value> {
    use nlink::netlink::tc_options::QdiscOptions;

    let mut map: BTreeMap<String, serde_yaml::Value> = BTreeMap::new();
    let Some(opts) = qdisc.options() else {
        return map;
    };

    let mut put = |k: &str, v: String| {
        map.insert(k.to_string(), serde_yaml::Value::String(v));
    };

    match opts {
        QdiscOptions::Htb(h) => {
            if let Some(d) = h.default_class() {
                put("default", format!("0x{d:x}"));
            }
            if let Some(r) = h.rate2quantum() {
                put("r2q", r.to_string());
            }
            if let Some(q) = h.direct_qlen() {
                put("direct_qlen", q.to_string());
            }
        }
        QdiscOptions::Tbf(t) => {
            if let Some(r) = t.rate() {
                put("rate", r.to_string());
            }
            if let Some(p) = t.peakrate() {
                put("peakrate", p.to_string());
            }
            if let Some(b) = t.burst() {
                put("burst", b.to_string());
            }
            if let Some(m) = t.mtu() {
                put("mtu", m.to_string());
            }
            if let Some(l) = t.limit() {
                put("limit", l.to_string());
            }
        }
        QdiscOptions::Netem(n) => {
            if let Some(d) = n.delay() {
                put("delay", format!("{}us", d.as_micros()));
            }
            if let Some(j) = n.jitter() {
                put("jitter", format!("{}us", j.as_micros()));
            }
            if let Some(l) = n.loss() {
                put("loss", format!("{l}%"));
            }
            if let Some(d) = n.duplicate() {
                put("duplicate", format!("{d}%"));
            }
            if let Some(r) = n.reorder() {
                put("reorder", format!("{r}%"));
            }
            if let Some(l) = n.limit() {
                put("limit", l.to_string());
            }
        }
        QdiscOptions::FqCodel(f) => {
            if let Some(l) = f.limit() {
                put("limit", l.to_string());
            }
            if let Some(fl) = f.flows() {
                put("flows", fl.to_string());
            }
            if let Some(t) = f.target() {
                put("target", format!("{}us", t.as_micros()));
            }
            if let Some(i) = f.interval() {
                put("interval", format!("{}us", i.as_micros()));
            }
            if f.ecn() {
                put("ecn", "on".to_string());
            }
        }
        _ => {}
    }

    map
}
