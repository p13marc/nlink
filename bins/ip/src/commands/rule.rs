//! ip rule command implementation.

use clap::{Args, Subcommand};
use nlink::netlink::rule::RuleBuilder;
use nlink::netlink::types::rule::{FibRuleAction, FibRulePortRange, FibRuleUidRange};
use nlink::netlink::{Connection, Result, Route};
use nlink::output::{OutputFormat, OutputOptions, Printable, print_all};
use std::io::Write;

#[derive(Args)]
pub struct RuleCmd {
    #[command(subcommand)]
    action: Option<RuleAction>,
}

#[derive(Subcommand)]
enum RuleAction {
    /// Show routing rules.
    Show,
    /// Alias for show.
    List,

    /// Add a routing rule.
    Add {
        /// Rule priority.
        #[arg(long, short)]
        priority: Option<u32>,

        /// Match source prefix.
        #[arg(long)]
        from: Option<String>,

        /// Match destination prefix.
        #[arg(long, short = 't')]
        to: Option<String>,

        /// Input interface name.
        #[arg(long)]
        iif: Option<String>,

        /// Output interface name.
        #[arg(long)]
        oif: Option<String>,

        /// Match fwmark.
        #[arg(long)]
        fwmark: Option<String>,

        /// Lookup table.
        #[arg(long)]
        table: Option<String>,

        /// Action type (lookup, blackhole, unreachable, prohibit).
        #[arg(long, default_value = "lookup")]
        action_type: String,

        /// IP protocol (for sport/dport matching).
        #[arg(long)]
        ipproto: Option<String>,

        /// Source port or range (e.g., 80 or 80-443).
        #[arg(long)]
        sport: Option<String>,

        /// Destination port or range (e.g., 80 or 80-443).
        #[arg(long)]
        dport: Option<String>,
    },

    /// Delete a routing rule.
    Del {
        /// Rule priority.
        #[arg(long, short)]
        priority: Option<u32>,

        /// Match source prefix.
        #[arg(long)]
        from: Option<String>,

        /// Match destination prefix.
        #[arg(long, short = 't')]
        to: Option<String>,

        /// Input interface name.
        #[arg(long)]
        iif: Option<String>,

        /// Output interface name.
        #[arg(long)]
        oif: Option<String>,

        /// Match fwmark.
        #[arg(long)]
        fwmark: Option<String>,

        /// Lookup table.
        #[arg(long)]
        table: Option<String>,
    },

    /// Flush all rules (except default).
    Flush,
}

impl RuleCmd {
    pub async fn run(
        self,
        conn: &Connection<Route>,
        format: OutputFormat,
        opts: &OutputOptions,
        family: Option<u8>,
    ) -> Result<()> {
        match self.action.unwrap_or(RuleAction::Show) {
            RuleAction::Show | RuleAction::List => Self::show(conn, format, opts, family).await,
            RuleAction::Add {
                priority,
                from,
                to,
                iif,
                oif,
                fwmark,
                table,
                action_type,
                ipproto,
                sport,
                dport,
            } => {
                Self::add(
                    conn,
                    family.unwrap_or(2),
                    priority,
                    from.as_deref(),
                    to.as_deref(),
                    iif.as_deref(),
                    oif.as_deref(),
                    fwmark.as_deref(),
                    table.as_deref(),
                    &action_type,
                    ipproto.as_deref(),
                    sport.as_deref(),
                    dport.as_deref(),
                )
                .await
            }
            RuleAction::Del {
                priority,
                from,
                to,
                iif,
                oif,
                fwmark,
                table,
            } => {
                Self::del(
                    conn,
                    family.unwrap_or(2),
                    priority,
                    from.as_deref(),
                    to.as_deref(),
                    iif.as_deref(),
                    oif.as_deref(),
                    fwmark.as_deref(),
                    table.as_deref(),
                )
                .await
            }
            RuleAction::Flush => Self::flush(conn, family).await,
        }
    }

    async fn show(
        conn: &Connection<Route>,
        format: OutputFormat,
        opts: &OutputOptions,
        family: Option<u8>,
    ) -> Result<()> {
        let raw_rules = if let Some(fam) = family {
            conn.get_rules_for_family(fam).await?
        } else {
            conn.get_rules().await?
        };

        // Convert to RuleInfo for display
        let mut rules: Vec<RuleInfo> = raw_rules
            .iter()
            .map(|r| RuleInfo {
                _family: r.family(),
                src_len: r.src_len(),
                dst_len: r.dst_len(),
                action: r.action(),
                priority: r.priority,
                table: r.table,
                source: r.source.map(|a| a.to_string()),
                destination: r.destination.map(|a| a.to_string()),
                iif: r.iifname.clone(),
                oif: r.oifname.clone(),
                fwmark: r.fwmark,
                fwmask: r.fwmask,
                ipproto: r.ip_proto,
                sport: r.sport_range,
                dport: r.dport_range,
                uid_range: r.uid_range,
            })
            .collect();

        // Sort by priority
        rules.sort_by_key(|r| r.priority);

        print_all(&rules, format, opts)?;

        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    async fn add(
        conn: &Connection<Route>,
        family: u8,
        priority: Option<u32>,
        from: Option<&str>,
        to: Option<&str>,
        iif: Option<&str>,
        oif: Option<&str>,
        fwmark: Option<&str>,
        table: Option<&str>,
        action_type: &str,
        ipproto: Option<&str>,
        sport: Option<&str>,
        dport: Option<&str>,
    ) -> Result<()> {
        use nlink::util::addr::parse_prefix;

        // Parse source/destination prefixes
        let (src_addr, src_len) = if let Some(s) = from {
            if s == "all" || s == "any" || s == "default" {
                (None, 0)
            } else {
                let (addr, len) = parse_prefix(s).map_err(|e| {
                    nlink::netlink::Error::InvalidMessage(format!("invalid source: {}", e))
                })?;
                (Some(addr), len)
            }
        } else {
            (None, 0)
        };

        let (dst_addr, dst_len) = if let Some(d) = to {
            if d == "all" || d == "any" || d == "default" {
                (None, 0)
            } else {
                let (addr, len) = parse_prefix(d).map_err(|e| {
                    nlink::netlink::Error::InvalidMessage(format!("invalid destination: {}", e))
                })?;
                (Some(addr), len)
            }
        } else {
            (None, 0)
        };

        // Determine actual family from addresses if not specified
        let actual_family = if family == 0 {
            src_addr
                .map(|a| if a.is_ipv4() { 2u8 } else { 10u8 })
                .or_else(|| dst_addr.map(|a| if a.is_ipv4() { 2u8 } else { 10u8 }))
                .unwrap_or(2)
        } else {
            family
        };

        // Parse table
        let table_id = table
            .map(|t| nlink::util::names::table_id(t).unwrap_or(254))
            .unwrap_or(254);

        // Build the rule
        let mut rule = RuleBuilder::new(actual_family).table(table_id);

        // Set priority
        if let Some(prio) = priority {
            rule = rule.priority(prio);
        }

        // Set source
        if let Some(addr) = src_addr {
            rule = rule.from_addr(addr, src_len);
        }

        // Set destination
        if let Some(addr) = dst_addr {
            rule = rule.to_addr(addr, dst_len);
        }

        // Set input interface
        if let Some(iif_name) = iif {
            rule = rule.iif(iif_name);
        }

        // Set output interface
        if let Some(oif_name) = oif {
            rule = rule.oif(oif_name);
        }

        // Set fwmark
        if let Some(mark_str) = fwmark {
            let (mark, mask) = parse_fwmark(mark_str)?;
            if mask != 0xffffffff {
                rule = rule.fwmark_mask(mark, mask);
            } else {
                rule = rule.fwmark(mark);
            }
        }

        // Set action
        rule = match action_type.to_lowercase().as_str() {
            "lookup" | "table" => rule, // default is table lookup
            "blackhole" => rule.blackhole(),
            "unreachable" => rule.unreachable(),
            "prohibit" => rule.prohibit(),
            "nop" => rule, // nop not directly supported, use default
            _ => {
                return Err(nlink::netlink::Error::InvalidMessage(format!(
                    "unknown action: {}",
                    action_type
                )));
            }
        };

        // Set IP protocol
        if let Some(proto) = ipproto {
            let proto_num = parse_ip_proto(proto)?;
            rule = rule.ipproto(proto_num);
        }

        // Set sport
        if let Some(port) = sport {
            let (start, end) = parse_port_range(port)?;
            rule = rule.sport(start, end);
        }

        // Set dport
        if let Some(port) = dport {
            let (start, end) = parse_port_range(port)?;
            rule = rule.dport(start, end);
        }

        conn.add_rule(rule).await?;

        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    async fn del(
        conn: &Connection<Route>,
        family: u8,
        priority: Option<u32>,
        from: Option<&str>,
        to: Option<&str>,
        iif: Option<&str>,
        oif: Option<&str>,
        fwmark: Option<&str>,
        table: Option<&str>,
    ) -> Result<()> {
        use nlink::util::addr::parse_prefix;

        // Parse source/destination prefixes
        let (src_addr, src_len) = if let Some(s) = from {
            if s == "all" || s == "any" || s == "default" {
                (None, 0)
            } else {
                let (addr, len) = parse_prefix(s).map_err(|e| {
                    nlink::netlink::Error::InvalidMessage(format!("invalid source: {}", e))
                })?;
                (Some(addr), len)
            }
        } else {
            (None, 0)
        };

        let (dst_addr, dst_len) = if let Some(d) = to {
            if d == "all" || d == "any" || d == "default" {
                (None, 0)
            } else {
                let (addr, len) = parse_prefix(d).map_err(|e| {
                    nlink::netlink::Error::InvalidMessage(format!("invalid destination: {}", e))
                })?;
                (Some(addr), len)
            }
        } else {
            (None, 0)
        };

        // Determine actual family
        let actual_family = if family == 0 {
            src_addr
                .map(|a| if a.is_ipv4() { 2u8 } else { 10u8 })
                .or_else(|| dst_addr.map(|a| if a.is_ipv4() { 2u8 } else { 10u8 }))
                .unwrap_or(2)
        } else {
            family
        };

        // Parse table
        let table_id = table
            .map(|t| nlink::util::names::table_id(t).unwrap_or(254))
            .unwrap_or(0);

        // Build the rule for deletion
        let mut rule = RuleBuilder::new(actual_family);

        if table_id > 0 {
            rule = rule.table(table_id);
        }

        // Set priority
        if let Some(prio) = priority {
            rule = rule.priority(prio);
        }

        // Set source
        if let Some(addr) = src_addr {
            rule = rule.from_addr(addr, src_len);
        }

        // Set destination
        if let Some(addr) = dst_addr {
            rule = rule.to_addr(addr, dst_len);
        }

        // Set input interface
        if let Some(iif_name) = iif {
            rule = rule.iif(iif_name);
        }

        // Set output interface
        if let Some(oif_name) = oif {
            rule = rule.oif(oif_name);
        }

        // Set fwmark
        if let Some(mark_str) = fwmark {
            let (mark, mask) = parse_fwmark(mark_str)?;
            if mask != 0xffffffff {
                rule = rule.fwmark_mask(mark, mask);
            } else {
                rule = rule.fwmark(mark);
            }
        }

        conn.del_rule(rule).await?;

        Ok(())
    }

    async fn flush(conn: &Connection<Route>, family: Option<u8>) -> Result<()> {
        // Flush IPv4 rules
        if family.is_none() || family == Some(libc::AF_INET as u8) {
            conn.flush_rules(libc::AF_INET as u8).await?;
        }

        // Flush IPv6 rules
        if family.is_none() || family == Some(libc::AF_INET6 as u8) {
            conn.flush_rules(libc::AF_INET6 as u8).await?;
        }

        Ok(())
    }
}

/// Parsed rule information.
#[derive(Debug)]
struct RuleInfo {
    _family: u8,
    src_len: u8,
    dst_len: u8,
    action: FibRuleAction,
    priority: u32,
    table: u32,
    source: Option<String>,
    destination: Option<String>,
    iif: Option<String>,
    oif: Option<String>,
    fwmark: Option<u32>,
    fwmask: Option<u32>,
    ipproto: Option<u8>,
    sport: Option<FibRulePortRange>,
    dport: Option<FibRulePortRange>,
    uid_range: Option<FibRuleUidRange>,
}

impl Printable for RuleInfo {
    fn print_text<W: Write>(&self, w: &mut W, _opts: &OutputOptions) -> std::io::Result<()> {
        // Priority
        write!(w, "{}:\t", self.priority)?;

        // Source
        if let Some(ref src) = self.source {
            write!(w, "from {}/{} ", src, self.src_len)?;
        } else {
            write!(w, "from all ")?;
        }

        // Destination
        if let Some(ref dst) = self.destination {
            write!(w, "to {}/{} ", dst, self.dst_len)?;
        }

        // Input interface
        if let Some(ref iif) = self.iif {
            write!(w, "iif {} ", iif)?;
        }

        // Output interface
        if let Some(ref oif) = self.oif {
            write!(w, "oif {} ", oif)?;
        }

        // Fwmark
        if let Some(mark) = self.fwmark {
            if let Some(mask) = self.fwmask {
                if mask != 0xffffffff {
                    write!(w, "fwmark {:#x}/{:#x} ", mark, mask)?;
                } else {
                    write!(w, "fwmark {:#x} ", mark)?;
                }
            } else {
                write!(w, "fwmark {:#x} ", mark)?;
            }
        }

        // IP protocol
        if let Some(proto) = self.ipproto {
            write!(w, "ipproto {} ", ip_proto_name(proto))?;
        }

        // Source port
        if let Some(ref range) = self.sport {
            if range.start == range.end {
                write!(w, "sport {} ", range.start)?;
            } else {
                write!(w, "sport {}-{} ", range.start, range.end)?;
            }
        }

        // Destination port
        if let Some(ref range) = self.dport {
            if range.start == range.end {
                write!(w, "dport {} ", range.start)?;
            } else {
                write!(w, "dport {}-{} ", range.start, range.end)?;
            }
        }

        // UID range
        if let Some(ref uid) = self.uid_range {
            if uid.start == uid.end {
                write!(w, "uidrange {} ", uid.start)?;
            } else {
                write!(w, "uidrange {}-{} ", uid.start, uid.end)?;
            }
        }

        // Action
        match self.action {
            FibRuleAction::ToTbl => {
                write!(w, "lookup {}", nlink::util::names::table_name(self.table))?;
            }
            FibRuleAction::Blackhole => {
                write!(w, "blackhole")?;
            }
            FibRuleAction::Unreachable => {
                write!(w, "unreachable")?;
            }
            FibRuleAction::Prohibit => {
                write!(w, "prohibit")?;
            }
            FibRuleAction::Goto => {
                write!(w, "goto")?;
            }
            FibRuleAction::Nop => {
                write!(w, "nop")?;
            }
            _ => {}
        }

        writeln!(w)?;
        Ok(())
    }

    fn to_json(&self) -> serde_json::Value {
        let mut obj = serde_json::json!({
            "priority": self.priority,
            "action": self.action.name(),
        });

        if let Some(ref src) = self.source {
            obj["src"] = serde_json::json!(format!("{}/{}", src, self.src_len));
        } else if self.src_len == 0 {
            obj["src"] = serde_json::json!("all");
        }

        if let Some(ref dst) = self.destination {
            obj["dst"] = serde_json::json!(format!("{}/{}", dst, self.dst_len));
        }

        if self.action == FibRuleAction::ToTbl {
            obj["table"] = serde_json::json!(nlink::util::names::table_name(self.table));
        }

        if let Some(ref iif) = self.iif {
            obj["iif"] = serde_json::json!(iif);
        }

        if let Some(ref oif) = self.oif {
            obj["oif"] = serde_json::json!(oif);
        }

        if let Some(mark) = self.fwmark {
            if let Some(mask) = self.fwmask {
                obj["fwmark"] = serde_json::json!(format!("{:#x}/{:#x}", mark, mask));
            } else {
                obj["fwmark"] = serde_json::json!(format!("{:#x}", mark));
            }
        }

        if let Some(proto) = self.ipproto {
            obj["ipproto"] = serde_json::json!(ip_proto_name(proto));
        }

        if let Some(ref range) = self.sport {
            if range.start == range.end {
                obj["sport"] = serde_json::json!(range.start);
            } else {
                obj["sport"] = serde_json::json!(format!("{}-{}", range.start, range.end));
            }
        }

        if let Some(ref range) = self.dport {
            if range.start == range.end {
                obj["dport"] = serde_json::json!(range.start);
            } else {
                obj["dport"] = serde_json::json!(format!("{}-{}", range.start, range.end));
            }
        }

        obj
    }
}

/// Parse fwmark/mask string like "0x100" or "0x100/0xff00".
fn parse_fwmark(s: &str) -> Result<(u32, u32)> {
    if let Some((mark_str, mask_str)) = s.split_once('/') {
        let mark = parse_u32(mark_str)?;
        let mask = parse_u32(mask_str)?;
        Ok((mark, mask))
    } else {
        let mark = parse_u32(s)?;
        Ok((mark, 0xffffffff))
    }
}

/// Parse a u32 from string (supports hex with 0x prefix).
fn parse_u32(s: &str) -> Result<u32> {
    let s = s.trim();
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u32::from_str_radix(hex, 16)
    } else {
        s.parse()
    }
    .map_err(|_| nlink::netlink::Error::InvalidMessage(format!("invalid number: {}", s)))
}

/// Parse port or port range like "80" or "80-443".
fn parse_port_range(s: &str) -> Result<(u16, u16)> {
    if let Some((start_str, end_str)) = s.split_once('-') {
        let start: u16 = start_str
            .trim()
            .parse()
            .map_err(|_| nlink::netlink::Error::InvalidMessage(format!("invalid port: {}", s)))?;
        let end: u16 = end_str
            .trim()
            .parse()
            .map_err(|_| nlink::netlink::Error::InvalidMessage(format!("invalid port: {}", s)))?;
        Ok((start, end))
    } else {
        let port: u16 = s
            .trim()
            .parse()
            .map_err(|_| nlink::netlink::Error::InvalidMessage(format!("invalid port: {}", s)))?;
        Ok((port, port))
    }
}

/// Parse IP protocol name or number.
fn parse_ip_proto(s: &str) -> Result<u8> {
    match s.to_lowercase().as_str() {
        "tcp" => Ok(6),
        "udp" => Ok(17),
        "icmp" => Ok(1),
        "icmpv6" => Ok(58),
        "gre" => Ok(47),
        "esp" => Ok(50),
        "ah" => Ok(51),
        "sctp" => Ok(132),
        _ => s
            .parse()
            .map_err(|_| nlink::netlink::Error::InvalidMessage(format!("unknown protocol: {}", s))),
    }
}

/// Get IP protocol name from number.
fn ip_proto_name(proto: u8) -> &'static str {
    match proto {
        1 => "icmp",
        6 => "tcp",
        17 => "udp",
        47 => "gre",
        50 => "esp",
        51 => "ah",
        58 => "icmpv6",
        132 => "sctp",
        _ => "unknown",
    }
}
