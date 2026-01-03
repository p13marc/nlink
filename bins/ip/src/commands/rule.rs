//! ip rule command implementation.

use clap::{Args, Subcommand};
use nlink::netlink::attr::{AttrIter, get};
use nlink::netlink::message::{NLMSG_HDRLEN, NlMsgHdr, NlMsgType};
use nlink::netlink::types::rule::{
    FibRuleAction, FibRuleHdr, FibRulePortRange, FibRuleUidRange, FraAttr,
};
use nlink::netlink::{Connection, Result, Route, connection::dump_request};
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
        // Build request
        let mut builder = dump_request(NlMsgType::RTM_GETRULE);
        let hdr = FibRuleHdr::new().with_family(family.unwrap_or(0));
        builder.append(&hdr);

        // Send and receive
        let responses = conn.send_dump(builder).await?;

        let mut rules = Vec::new();

        for response in &responses {
            if let Some(rule) = parse_rule_message(response)? {
                // Filter by family if specified
                if let Some(fam) = family
                    && rule.family != fam
                {
                    continue;
                }
                rules.push(rule);
            }
        }

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
        use nlink::netlink::connection::ack_request;
        use nlink::util::addr::parse_prefix;

        // Determine action
        let action = match action_type.to_lowercase().as_str() {
            "lookup" | "table" => FibRuleAction::ToTbl,
            "blackhole" => FibRuleAction::Blackhole,
            "unreachable" => FibRuleAction::Unreachable,
            "prohibit" => FibRuleAction::Prohibit,
            "nop" => FibRuleAction::Nop,
            _ => {
                return Err(nlink::netlink::Error::InvalidMessage(format!(
                    "unknown action: {}",
                    action_type
                )));
            }
        };

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

        let mut hdr = FibRuleHdr::new().with_family(actual_family);
        hdr.src_len = src_len;
        hdr.dst_len = dst_len;
        hdr.action = action as u8;
        hdr.table = if table_id <= 255 { table_id as u8 } else { 0 };

        let mut builder = ack_request(NlMsgType::RTM_NEWRULE);
        builder.append(&hdr);

        // Add priority
        if let Some(prio) = priority {
            builder.append_attr_u32(FraAttr::Priority as u16, prio);
        }

        // Add source
        if let Some(addr) = src_addr {
            match addr {
                std::net::IpAddr::V4(v4) => {
                    builder.append_attr(FraAttr::Src as u16, &v4.octets());
                }
                std::net::IpAddr::V6(v6) => {
                    builder.append_attr(FraAttr::Src as u16, &v6.octets());
                }
            }
        }

        // Add destination
        if let Some(addr) = dst_addr {
            match addr {
                std::net::IpAddr::V4(v4) => {
                    builder.append_attr(FraAttr::Dst as u16, &v4.octets());
                }
                std::net::IpAddr::V6(v6) => {
                    builder.append_attr(FraAttr::Dst as u16, &v6.octets());
                }
            }
        }

        // Add input interface
        if let Some(iif_name) = iif {
            builder.append_attr_str(FraAttr::Iifname as u16, iif_name);
        }

        // Add output interface
        if let Some(oif_name) = oif {
            builder.append_attr_str(FraAttr::Oifname as u16, oif_name);
        }

        // Add fwmark
        if let Some(mark_str) = fwmark {
            let (mark, mask) = parse_fwmark(mark_str)?;
            builder.append_attr_u32(FraAttr::Fwmark as u16, mark);
            if mask != 0xffffffff {
                builder.append_attr_u32(FraAttr::Fwmask as u16, mask);
            }
        }

        // Add table if > 255
        if table_id > 255 {
            builder.append_attr_u32(FraAttr::Table as u16, table_id);
        }

        // Add IP protocol
        if let Some(proto) = ipproto {
            let proto_num = parse_ip_proto(proto)?;
            builder.append_attr(FraAttr::IpProto as u16, &[proto_num]);
        }

        // Add sport
        if let Some(port) = sport {
            let range = parse_port_range(port)?;
            let range_bytes = [
                (range.0 & 0xff) as u8,
                ((range.0 >> 8) & 0xff) as u8,
                (range.1 & 0xff) as u8,
                ((range.1 >> 8) & 0xff) as u8,
            ];
            builder.append_attr(FraAttr::Sport as u16, &range_bytes);
        }

        // Add dport
        if let Some(port) = dport {
            let range = parse_port_range(port)?;
            let range_bytes = [
                (range.0 & 0xff) as u8,
                ((range.0 >> 8) & 0xff) as u8,
                (range.1 & 0xff) as u8,
                ((range.1 >> 8) & 0xff) as u8,
            ];
            builder.append_attr(FraAttr::Dport as u16, &range_bytes);
        }

        conn.send_ack(builder).await?;

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
        use nlink::netlink::connection::ack_request;
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

        let mut hdr = FibRuleHdr::new().with_family(actual_family);
        hdr.src_len = src_len;
        hdr.dst_len = dst_len;
        hdr.table = if table_id <= 255 { table_id as u8 } else { 0 };

        let mut builder = ack_request(NlMsgType::RTM_DELRULE);
        builder.append(&hdr);

        // Add priority
        if let Some(prio) = priority {
            builder.append_attr_u32(FraAttr::Priority as u16, prio);
        }

        // Add source
        if let Some(addr) = src_addr {
            match addr {
                std::net::IpAddr::V4(v4) => {
                    builder.append_attr(FraAttr::Src as u16, &v4.octets());
                }
                std::net::IpAddr::V6(v6) => {
                    builder.append_attr(FraAttr::Src as u16, &v6.octets());
                }
            }
        }

        // Add destination
        if let Some(addr) = dst_addr {
            match addr {
                std::net::IpAddr::V4(v4) => {
                    builder.append_attr(FraAttr::Dst as u16, &v4.octets());
                }
                std::net::IpAddr::V6(v6) => {
                    builder.append_attr(FraAttr::Dst as u16, &v6.octets());
                }
            }
        }

        // Add input interface
        if let Some(iif_name) = iif {
            builder.append_attr_str(FraAttr::Iifname as u16, iif_name);
        }

        // Add output interface
        if let Some(oif_name) = oif {
            builder.append_attr_str(FraAttr::Oifname as u16, oif_name);
        }

        // Add fwmark
        if let Some(mark_str) = fwmark {
            let (mark, mask) = parse_fwmark(mark_str)?;
            builder.append_attr_u32(FraAttr::Fwmark as u16, mark);
            if mask != 0xffffffff {
                builder.append_attr_u32(FraAttr::Fwmask as u16, mask);
            }
        }

        // Add table if > 255
        if table_id > 255 {
            builder.append_attr_u32(FraAttr::Table as u16, table_id);
        }

        conn.send_ack(builder).await?;

        Ok(())
    }

    async fn flush(conn: &Connection<Route>, family: Option<u8>) -> Result<()> {
        // Get all rules first
        let mut builder = dump_request(NlMsgType::RTM_GETRULE);
        let hdr = FibRuleHdr::new().with_family(family.unwrap_or(0));
        builder.append(&hdr);

        let responses = conn.send_dump(builder).await?;

        let mut rules = Vec::new();
        for response in &responses {
            if let Some(rule) = parse_rule_message(response)? {
                // Skip default rules (priority 0 or 32766/32767)
                if rule.priority == 0 || rule.priority == 32766 || rule.priority == 32767 {
                    continue;
                }
                rules.push(rule);
            }
        }

        // Delete each rule
        for rule in rules {
            use nlink::netlink::connection::ack_request;

            let mut hdr = FibRuleHdr::new().with_family(rule.family);
            hdr.src_len = rule.src_len;
            hdr.dst_len = rule.dst_len;

            let mut del_builder = ack_request(NlMsgType::RTM_DELRULE);
            del_builder.append(&hdr);
            del_builder.append_attr_u32(FraAttr::Priority as u16, rule.priority);

            // Ignore errors (rule may have been deleted already)
            let _ = conn.send_ack(del_builder).await;
        }

        Ok(())
    }
}

/// Parsed rule information.
#[derive(Debug)]
struct RuleInfo {
    family: u8,
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

fn parse_rule_message(data: &[u8]) -> Result<Option<RuleInfo>> {
    if data.len() < NLMSG_HDRLEN + FibRuleHdr::SIZE {
        return Ok(None);
    }

    let header = NlMsgHdr::from_bytes(data)?;

    // Skip non-rule messages
    if header.nlmsg_type != NlMsgType::RTM_NEWRULE {
        return Ok(None);
    }

    let payload = &data[NLMSG_HDRLEN..];
    let hdr = FibRuleHdr::from_bytes(payload)?;
    let attrs_data = &payload[FibRuleHdr::SIZE..];

    let mut priority = 0u32;
    let mut table = hdr.table as u32;
    let mut source = None;
    let mut destination = None;
    let mut iif = None;
    let mut oif = None;
    let mut fwmark = None;
    let mut fwmask = None;
    let mut ipproto = None;
    let mut sport = None;
    let mut dport = None;
    let mut uid_range = None;

    for (attr_type, attr_data) in AttrIter::new(attrs_data) {
        match FraAttr::from(attr_type) {
            FraAttr::Priority => {
                priority = get::u32_ne(attr_data).unwrap_or(0);
            }
            FraAttr::Table => {
                table = get::u32_ne(attr_data).unwrap_or(table);
            }
            FraAttr::Src => {
                source = nlink::util::addr::format_addr_bytes(attr_data, hdr.family);
            }
            FraAttr::Dst => {
                destination = nlink::util::addr::format_addr_bytes(attr_data, hdr.family);
            }
            FraAttr::Iifname => {
                iif = get::string(attr_data).ok().map(String::from);
            }
            FraAttr::Oifname => {
                oif = get::string(attr_data).ok().map(String::from);
            }
            FraAttr::Fwmark => {
                fwmark = Some(get::u32_ne(attr_data).unwrap_or(0));
            }
            FraAttr::Fwmask => {
                fwmask = Some(get::u32_ne(attr_data).unwrap_or(0xffffffff));
            }
            FraAttr::IpProto => {
                ipproto = get::u8(attr_data).ok();
            }
            FraAttr::Sport => {
                sport = FibRulePortRange::from_bytes(attr_data).copied();
            }
            FraAttr::Dport => {
                dport = FibRulePortRange::from_bytes(attr_data).copied();
            }
            FraAttr::UidRange => {
                uid_range = FibRuleUidRange::from_bytes(attr_data).copied();
            }
            _ => {}
        }
    }

    Ok(Some(RuleInfo {
        family: hdr.family,
        src_len: hdr.src_len,
        dst_len: hdr.dst_len,
        action: FibRuleAction::from(hdr.action),
        priority,
        table,
        source,
        destination,
        iif,
        oif,
        fwmark,
        fwmask,
        ipproto,
        sport,
        dport,
        uid_range,
    }))
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
