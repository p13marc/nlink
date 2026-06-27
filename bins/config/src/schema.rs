//! Shared on-disk schema for `nlink-config`.
//!
//! There is exactly **one** file format, used by every subcommand:
//! `capture` serializes it, `apply`/`diff` deserialize it, and
//! `example` emits it. That single-schema rule is the whole point —
//! before this module, `capture` had its own private structs while
//! the library's builder-oriented `NetworkConfig` was serialize-only,
//! so a capture → apply round-trip was impossible.
//!
//! [`ConfigFile::to_network_config`] translates the file into the
//! library's [`NetworkConfig`] (the actual diff/apply engine). The
//! translation is deliberately honest about its limits: structural
//! problems (unknown link kind, missing required option, malformed
//! value) are hard errors, while options the library can't yet model
//! and whole sections it doesn't support (`rules`, `qdiscs`) are
//! returned as **visible warnings** rather than silently dropped.

use std::{collections::BTreeMap, net::IpAddr, path::Path};

use nlink::netlink::{
    Error, Result,
    config::{BondMode, MacvlanMode, NetworkConfig, VlanProtocol},
};
use serde::{Deserialize, Serialize};

/// Free-form per-resource options, mirroring the kernel's
/// open-ended attribute model. Values are kept as YAML scalars so a
/// captured file round-trips byte-for-byte; the translator
/// interprets them per kind.
type Options = BTreeMap<String, serde_yaml::Value>;

/// The complete `nlink-config` file format.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct ConfigFile {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub links: Vec<LinkConfig>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub addresses: Vec<AddressConfig>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub routes: Vec<RouteConfig>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rules: Vec<RuleConfig>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub qdiscs: Vec<QdiscConfig>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct LinkConfig {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mtu: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub master: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mac: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub options: Options,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct AddressConfig {
    pub dev: String,
    pub address: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub broadcast: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct RouteConfig {
    pub destination: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gateway: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dev: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metric: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub table: Option<String>,
    #[serde(default, rename = "type", skip_serializing_if = "Option::is_none")]
    pub route_type: Option<String>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct RuleConfig {
    pub priority: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fwmark: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub table: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct QdiscConfig {
    pub dev: String,
    pub parent: String,
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handle: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub options: Options,
}

impl ConfigFile {
    /// Load a config file, picking YAML or JSON by extension (with a
    /// content-sniff fallback for `{`-leading documents).
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| Error::InvalidMessage(format!("config: read {}: {e}", path.display())))?;
        let is_json = path.extension().and_then(|e| e.to_str()) == Some("json")
            || text.trim_start().starts_with('{');
        if is_json {
            serde_json::from_str(&text).map_err(|e| {
                Error::InvalidMessage(format!("config: parse JSON {}: {e}", path.display()))
            })
        } else {
            serde_yaml::from_str(&text).map_err(|e| {
                Error::InvalidMessage(format!("config: parse YAML {}: {e}", path.display()))
            })
        }
    }

    /// Translate this file into the library [`NetworkConfig`].
    ///
    /// Returns the config plus a list of human-readable warnings for
    /// anything the apply/diff engine can't (yet) carry — present but
    /// unmodelled link options, and the `rules` / `qdiscs` sections.
    /// Hard errors are reserved for malformed input the user must fix.
    pub fn to_network_config(&self) -> Result<(NetworkConfig, Vec<String>)> {
        let mut cfg = NetworkConfig::new();
        let mut warn = Vec::new();

        for link in &self.links {
            let plan = LinkPlan::from_config(link, &mut warn)?;
            let name = link.name.clone();
            cfg = cfg.link(&name, move |b| plan.apply(b));
        }

        for addr in &self.addresses {
            if addr.broadcast.is_some() || addr.label.is_some() {
                warn.push(format!(
                    "address {} on {}: broadcast/label are not applied (not modelled by config apply)",
                    addr.address, addr.dev
                ));
            }
            cfg = cfg.address(&addr.dev, &addr.address).map_err(|e| {
                Error::InvalidMessage(format!(
                    "config: invalid address `{}` on {}: {e}",
                    addr.address, addr.dev
                ))
            })?;
        }

        for route in &self.routes {
            cfg = add_route(cfg, route)?;
        }

        if !self.rules.is_empty() {
            warn.push(format!(
                "{} routing rule(s) in the file are not applied: `config apply` has no rule support yet — use `ip rule`",
                self.rules.len()
            ));
        }
        if !self.qdiscs.is_empty() {
            warn.push(format!(
                "{} qdisc(s) in the file are not applied: `config apply` does not translate qdisc options yet — use `tc qdisc`",
                self.qdiscs.len()
            ));
        }

        Ok((cfg, warn))
    }
}

/// A validated link, ready to apply to a `LinkBuilder` infallibly.
struct LinkPlan {
    kind: LinkKind,
    up: Option<bool>,
    mtu: Option<u32>,
    master: Option<String>,
    mac: Option<[u8; 6]>,
}

enum LinkKind {
    Physical,
    Dummy,
    Ifb,
    Bridge,
    Veth {
        peer: String,
    },
    Vlan {
        link: String,
        id: u16,
        protocol: Option<VlanProtocol>,
    },
    Vxlan {
        vni: u32,
        local: Option<IpAddr>,
        remote: Option<IpAddr>,
        port: Option<u16>,
        underlay: Option<String>,
    },
    Macvlan {
        link: String,
        mode: Option<MacvlanMode>,
    },
    Bond(BondPlan),
}

#[derive(Default)]
struct BondPlan {
    mode: Option<BondMode>,
    miimon: Option<u32>,
    min_links: Option<u32>,
    xmit_hash_policy: Option<u8>,
    updelay: Option<u32>,
    downdelay: Option<u32>,
    resend_igmp: Option<u32>,
}

impl LinkPlan {
    fn from_config(link: &LinkConfig, warn: &mut Vec<String>) -> Result<Self> {
        let kind = LinkKind::from_config(link, warn)?;
        let up = match link.state.as_deref() {
            None | Some("unchanged") | Some("") => None,
            Some("up") => Some(true),
            Some("down") => Some(false),
            Some(other) => {
                return Err(err(
                    &link.name,
                    format!("invalid state `{other}` (expected up/down)"),
                ));
            }
        };
        let mac = match &link.mac {
            None => None,
            Some(s) => Some(parse_mac(s).ok_or_else(|| {
                err(&link.name, format!("invalid mac `{s}` (expected aa:bb:cc:dd:ee:ff)"))
            })?),
        };
        Ok(Self {
            kind,
            up,
            mtu: link.mtu,
            master: link.master.clone(),
            mac,
        })
    }

    fn apply(self, mut b: nlink::netlink::config::LinkBuilder) -> nlink::netlink::config::LinkBuilder {
        b = match self.kind {
            LinkKind::Physical => b,
            LinkKind::Dummy => b.dummy(),
            LinkKind::Ifb => b.ifb(),
            LinkKind::Bridge => b.bridge(),
            LinkKind::Veth { peer } => b.veth(&peer),
            LinkKind::Vlan { link, id, protocol } => {
                b = b.vlan(&link, id);
                if let Some(p) = protocol {
                    b = b.vlan_protocol(p);
                }
                b
            }
            LinkKind::Vxlan {
                vni,
                local,
                remote,
                port,
                underlay,
            } => {
                b = b.vxlan(vni);
                if let Some(l) = local {
                    b = b.vxlan_local(l);
                }
                if let Some(r) = remote {
                    b = b.vxlan_remote(r);
                }
                if let Some(p) = port {
                    b = b.vxlan_port(p);
                }
                if let Some(u) = underlay {
                    b = b.vxlan_underlay_dev(u);
                }
                b
            }
            LinkKind::Macvlan { link, mode } => {
                b = b.macvlan(&link);
                if let Some(m) = mode {
                    b = b.macvlan_mode(m);
                }
                b
            }
            LinkKind::Bond(p) => {
                b = b.bond();
                if let Some(m) = p.mode {
                    b = b.bond_mode(m);
                }
                if let Some(v) = p.miimon {
                    b = b.miimon(v);
                }
                if let Some(v) = p.min_links {
                    b = b.min_links(v);
                }
                if let Some(v) = p.xmit_hash_policy {
                    b = b.xmit_hash_policy(v);
                }
                if let Some(v) = p.updelay {
                    b = b.bond_updelay(v);
                }
                if let Some(v) = p.downdelay {
                    b = b.bond_downdelay(v);
                }
                if let Some(v) = p.resend_igmp {
                    b = b.bond_resend_igmp(v);
                }
                b
            }
        };
        if let Some(up) = self.up {
            b = if up { b.up() } else { b.down() };
        }
        if let Some(mtu) = self.mtu {
            b = b.mtu(mtu);
        }
        if let Some(master) = self.master {
            b = b.master(&master);
        }
        if let Some(mac) = self.mac {
            b = b.address(mac);
        }
        b
    }
}

impl LinkKind {
    fn from_config(link: &LinkConfig, warn: &mut Vec<String>) -> Result<Self> {
        let o = &link.options;
        let name = &link.name;
        let kind = match link.kind.as_deref() {
            None | Some("") | Some("physical") | Some("device") => {
                warn_unknown_opts(name, o, &[], warn);
                LinkKind::Physical
            }
            Some("dummy") => {
                warn_unknown_opts(name, o, &[], warn);
                LinkKind::Dummy
            }
            Some("ifb") => {
                warn_unknown_opts(name, o, &[], warn);
                LinkKind::Ifb
            }
            Some("bridge") => {
                // vlan_filtering / stp_state aren't modelled by the
                // declarative builder yet — surface, don't drop.
                warn_unknown_opts(name, o, &[], warn);
                LinkKind::Bridge
            }
            Some("veth") => {
                let peer = req_str(name, o, "peer")?;
                warn_unknown_opts(name, o, &["peer"], warn);
                LinkKind::Veth { peer }
            }
            Some("vlan") => {
                let link_dev = req_str(name, o, "link")?;
                let id = req_u16(name, o, "id")?;
                let protocol = match opt_str(o, "protocol") {
                    None => None,
                    Some(s) => Some(parse_vlan_protocol(name, &s)?),
                };
                warn_unknown_opts(name, o, &["link", "id", "protocol"], warn);
                LinkKind::Vlan {
                    link: link_dev,
                    id,
                    protocol,
                }
            }
            Some("vxlan") => {
                let vni = req_u32(name, o, "vni")?;
                let local = opt_addr(name, o, "local")?;
                let remote = opt_addr(name, o, "remote")?;
                let port = opt_u16(name, o, "port")?;
                let underlay = opt_str(o, "link");
                warn_unknown_opts(name, o, &["vni", "local", "remote", "port", "link"], warn);
                LinkKind::Vxlan {
                    vni,
                    local,
                    remote,
                    port,
                    underlay,
                }
            }
            Some("macvlan") => {
                let link_dev = req_str(name, o, "link")?;
                let mode = match opt_str(o, "mode") {
                    None => None,
                    Some(s) => Some(parse_macvlan_mode(name, &s)?),
                };
                warn_unknown_opts(name, o, &["link", "mode"], warn);
                LinkKind::Macvlan {
                    link: link_dev,
                    mode,
                }
            }
            Some("bond") => {
                let mut p = BondPlan::default();
                if let Some(s) = opt_str(o, "mode") {
                    p.mode = Some(parse_bond_mode(name, &s)?);
                }
                p.miimon = opt_u32(name, o, "miimon")?;
                p.min_links = opt_u32(name, o, "min_links")?;
                if let Some(s) = opt_str(o, "xmit_hash_policy") {
                    p.xmit_hash_policy = Some(parse_xmit_hash(name, &s)?);
                }
                p.updelay = opt_u32(name, o, "updelay")?;
                p.downdelay = opt_u32(name, o, "downdelay")?;
                p.resend_igmp = opt_u32(name, o, "resend_igmp")?;
                warn_unknown_opts(
                    name,
                    o,
                    &[
                        "mode",
                        "miimon",
                        "min_links",
                        "xmit_hash_policy",
                        "updelay",
                        "downdelay",
                        "resend_igmp",
                    ],
                    warn,
                );
                LinkKind::Bond(p)
            }
            Some(other) => {
                return Err(err(
                    name,
                    format!("unknown link kind `{other}` (not modelled by config apply)"),
                ));
            }
        };
        Ok(kind)
    }
}

fn add_route(cfg: NetworkConfig, route: &RouteConfig) -> Result<NetworkConfig> {
    // Normalize the iproute2 `default` keyword to an explicit CIDR;
    // the family is inferred from the gateway (defaulting to v4).
    let dst = if route.destination == "default" {
        if route.gateway.as_deref().is_some_and(|g| g.contains(':')) {
            "::/0".to_string()
        } else {
            "0.0.0.0/0".to_string()
        }
    } else {
        route.destination.clone()
    };

    // Validate the things the builder closure can't report on.
    let table = match &route.table {
        None => None,
        Some(t) => Some(parse_table(t).ok_or_else(|| {
            Error::InvalidMessage(format!("config: route {dst}: invalid table `{t}`"))
        })?),
    };
    let rtype = match route.route_type.as_deref() {
        None | Some("unicast") => RouteTypePlan::Unicast,
        Some("blackhole") => RouteTypePlan::Blackhole,
        Some("unreachable") => RouteTypePlan::Unreachable,
        Some("prohibit") => RouteTypePlan::Prohibit,
        Some(other) => {
            return Err(Error::InvalidMessage(format!(
                "config: route {dst}: unsupported type `{other}`"
            )));
        }
    };
    let gateway = route.gateway.clone();
    let dev = route.dev.clone();
    let metric = route.metric;

    cfg.route(&dst, move |mut r| {
        if let Some(g) = &gateway {
            r = r.via(g);
        }
        if let Some(d) = &dev {
            r = r.dev(d);
        }
        if let Some(m) = metric {
            r = r.metric(m);
        }
        if let Some(t) = table {
            r = r.table(t);
        }
        match rtype {
            RouteTypePlan::Unicast => r,
            RouteTypePlan::Blackhole => r.blackhole(),
            RouteTypePlan::Unreachable => r.unreachable(),
            RouteTypePlan::Prohibit => r.prohibit(),
        }
    })
    .map_err(|e| Error::InvalidMessage(format!("config: invalid route `{dst}`: {e}")))
}

enum RouteTypePlan {
    Unicast,
    Blackhole,
    Unreachable,
    Prohibit,
}

// --- option helpers --------------------------------------------------

fn err(link: &str, msg: String) -> Error {
    Error::InvalidMessage(format!("config: link {link}: {msg}"))
}

fn opt_str(o: &Options, key: &str) -> Option<String> {
    o.get(key).and_then(|v| match v {
        serde_yaml::Value::String(s) => Some(s.clone()),
        // Accept bare scalars (numbers/bools) as their textual form,
        // matching how YAML users write `mode: 802.3ad` unquoted.
        serde_yaml::Value::Number(n) => Some(n.to_string()),
        serde_yaml::Value::Bool(b) => Some(b.to_string()),
        _ => None,
    })
}

fn opt_u64(link: &str, o: &Options, key: &str) -> Result<Option<u64>> {
    match o.get(key) {
        None => Ok(None),
        Some(v) => v
            .as_u64()
            .map(Some)
            .ok_or_else(|| err(link, format!("option `{key}` must be a non-negative integer"))),
    }
}

fn opt_u32(link: &str, o: &Options, key: &str) -> Result<Option<u32>> {
    Ok(opt_u64(link, o, key)?
        .map(|v| u32::try_from(v).unwrap_or(u32::MAX)))
}

fn opt_u16(link: &str, o: &Options, key: &str) -> Result<Option<u16>> {
    Ok(opt_u64(link, o, key)?
        .map(|v| u16::try_from(v).unwrap_or(u16::MAX)))
}

fn opt_addr(link: &str, o: &Options, key: &str) -> Result<Option<IpAddr>> {
    match opt_str(o, key) {
        None => Ok(None),
        Some(s) => s
            .parse()
            .map(Some)
            .map_err(|_| err(link, format!("option `{key}` is not an IP address: `{s}`"))),
    }
}

fn req_str(link: &str, o: &Options, key: &str) -> Result<String> {
    opt_str(o, key).ok_or_else(|| err(link, format!("missing required option `{key}`")))
}

fn req_u32(link: &str, o: &Options, key: &str) -> Result<u32> {
    opt_u32(link, o, key)?.ok_or_else(|| err(link, format!("missing required option `{key}`")))
}

fn req_u16(link: &str, o: &Options, key: &str) -> Result<u16> {
    opt_u16(link, o, key)?.ok_or_else(|| err(link, format!("missing required option `{key}`")))
}

fn warn_unknown_opts(link: &str, o: &Options, known: &[&str], warn: &mut Vec<String>) {
    for key in o.keys() {
        if !known.contains(&key.as_str()) {
            warn.push(format!(
                "link {link}: option `{key}` is not modelled by config apply and was ignored"
            ));
        }
    }
}

fn parse_mac(s: &str) -> Option<[u8; 6]> {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 6 {
        return None;
    }
    let mut mac = [0u8; 6];
    for (i, p) in parts.iter().enumerate() {
        mac[i] = u8::from_str_radix(p, 16).ok()?;
    }
    Some(mac)
}

fn parse_vlan_protocol(link: &str, s: &str) -> Result<VlanProtocol> {
    match s.to_lowercase().as_str() {
        "802.1q" | "dot1q" | "8021q" => Ok(VlanProtocol::Dot1q),
        "802.1ad" | "dot1ad" | "8021ad" => Ok(VlanProtocol::Dot1ad),
        other => Err(err(link, format!("unknown vlan protocol `{other}`"))),
    }
}

fn parse_macvlan_mode(link: &str, s: &str) -> Result<MacvlanMode> {
    match s.to_lowercase().as_str() {
        "private" => Ok(MacvlanMode::Private),
        "vepa" => Ok(MacvlanMode::Vepa),
        "bridge" => Ok(MacvlanMode::Bridge),
        "passthru" => Ok(MacvlanMode::Passthru),
        "source" => Ok(MacvlanMode::Source),
        other => Err(err(link, format!("unknown macvlan mode `{other}`"))),
    }
}

fn parse_bond_mode(link: &str, s: &str) -> Result<BondMode> {
    match s.to_lowercase().as_str() {
        "balance-rr" | "balance_rr" | "0" => Ok(BondMode::BalanceRr),
        "active-backup" | "active_backup" | "1" => Ok(BondMode::ActiveBackup),
        "balance-xor" | "balance_xor" | "2" => Ok(BondMode::BalanceXor),
        "broadcast" | "3" => Ok(BondMode::Broadcast),
        "802.3ad" | "8023ad" | "lacp" | "4" => Ok(BondMode::Ieee802_3ad),
        "balance-tlb" | "balance_tlb" | "5" => Ok(BondMode::BalanceTlb),
        "balance-alb" | "balance_alb" | "6" => Ok(BondMode::BalanceAlb),
        other => Err(err(link, format!("unknown bond mode `{other}`"))),
    }
}

fn parse_xmit_hash(link: &str, s: &str) -> Result<u8> {
    // Kernel: layer2=0, layer3+4=1, layer2+3=2.
    match s.to_lowercase().as_str() {
        "layer2" | "0" => Ok(0),
        "layer3+4" | "1" => Ok(1),
        "layer2+3" | "2" => Ok(2),
        other => Err(err(link, format!("unknown xmit_hash_policy `{other}`"))),
    }
}

/// Map a routing-table name/number to its id. Mirrors the names
/// `capture` emits.
fn parse_table(s: &str) -> Option<u32> {
    match s {
        "main" => Some(254),
        "default" => Some(253),
        "local" => Some(255),
        "unspec" => Some(0),
        n => n.parse().ok(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_round_trips_through_yaml() {
        let yaml = r#"
links:
  - name: br0
    kind: bridge
    state: up
    mtu: 1500
  - name: veth0
    kind: veth
    state: up
    master: br0
    options:
      peer: veth1
addresses:
  - dev: br0
    address: 10.0.0.1/24
routes:
  - destination: 10.1.0.0/16
    gateway: 10.0.0.254
    dev: br0
"#;
        let cfg: ConfigFile = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(cfg.links.len(), 2);
        assert_eq!(cfg.addresses.len(), 1);
        assert_eq!(cfg.routes.len(), 1);

        // Re-serialize and re-parse: the round trip is stable.
        let out = serde_yaml::to_string(&cfg).unwrap();
        let cfg2: ConfigFile = serde_yaml::from_str(&out).unwrap();
        assert_eq!(cfg2.links.len(), 2);
        assert_eq!(cfg2.links[1].options.get("peer").unwrap().as_str(), Some("veth1"));
    }

    #[test]
    fn translates_basic_config() {
        let yaml = r#"
links:
  - name: br0
    kind: bridge
    state: up
  - name: veth0
    kind: veth
    state: up
    master: br0
    options:
      peer: veth1
addresses:
  - dev: br0
    address: 10.0.0.1/24
routes:
  - destination: default
    gateway: 10.0.0.254
"#;
        let cfg: ConfigFile = serde_yaml::from_str(yaml).unwrap();
        let (nc, warnings) = cfg.to_network_config().unwrap();
        assert_eq!(nc.links().len(), 2);
        assert_eq!(nc.addresses().len(), 1);
        assert_eq!(nc.routes().len(), 1);
        assert!(warnings.is_empty(), "unexpected warnings: {warnings:?}");
    }

    #[test]
    fn unknown_kind_is_an_error() {
        let yaml = r#"
links:
  - name: x0
    kind: wormhole
"#;
        let cfg: ConfigFile = serde_yaml::from_str(yaml).unwrap();
        let e = cfg.to_network_config().unwrap_err();
        assert!(e.to_string().contains("unknown link kind"), "got: {e}");
    }

    #[test]
    fn missing_required_option_is_an_error() {
        let yaml = r#"
links:
  - name: v0
    kind: veth
"#;
        let cfg: ConfigFile = serde_yaml::from_str(yaml).unwrap();
        let e = cfg.to_network_config().unwrap_err();
        assert!(e.to_string().contains("missing required option `peer`"), "got: {e}");
    }

    #[test]
    fn unmodelled_sections_warn_not_fail() {
        let yaml = r#"
links:
  - name: br0
    kind: bridge
    state: up
    options:
      vlan_filtering: true
rules:
  - priority: 100
    from: 10.0.0.0/8
    table: "100"
qdiscs:
  - dev: br0
    parent: root
    kind: htb
"#;
        let cfg: ConfigFile = serde_yaml::from_str(yaml).unwrap();
        let (_nc, warnings) = cfg.to_network_config().unwrap();
        // bridge vlan_filtering option + rules + qdiscs => 3 warnings.
        assert_eq!(warnings.len(), 3, "warnings: {warnings:?}");
    }

    #[test]
    fn translates_bond_options() {
        let yaml = r#"
links:
  - name: bond0
    kind: bond
    state: up
    options:
      mode: 802.3ad
      miimon: 100
      min_links: 1
      xmit_hash_policy: layer3+4
"#;
        let cfg: ConfigFile = serde_yaml::from_str(yaml).unwrap();
        let (nc, warnings) = cfg.to_network_config().unwrap();
        assert_eq!(nc.links().len(), 1);
        assert!(warnings.is_empty(), "unexpected warnings: {warnings:?}");
    }
}
