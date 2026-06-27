//! nft - nftables firewall management utility.
//!
//! Manages nftables tables, chains, rules, and sets via NETLINK_NETFILTER.

use std::net::Ipv4Addr;

use clap::{Parser, Subcommand};
use nlink::netlink::{
    Connection, Nftables, Result,
    nftables::{
        Chain, ChainType, Family, Hook, Policy, Priority, Rule, Set, SetElement, SetKeyType,
        Transaction,
    },
};

#[derive(Parser)]
#[command(name = "nft", version, about = "nftables firewall management utility")]
struct Cli {
    /// Emit machine-readable JSON for `list` commands.
    #[arg(long, short, global = true)]
    json: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// List tables, chains, rules, or sets.
    List {
        #[command(subcommand)]
        what: ListWhat,
    },

    /// Add a table, chain, or rule.
    Add {
        #[command(subcommand)]
        what: AddWhat,
    },

    /// Delete a table, chain, or rule.
    Delete {
        #[command(subcommand)]
        what: DeleteWhat,
    },

    /// Flush a table or the entire ruleset.
    Flush {
        #[command(subcommand)]
        what: FlushWhat,
    },

    /// Apply a batch of operations atomically from a file.
    ///
    /// The file holds one operation per line (blank lines and `#`
    /// comments ignored), e.g.:
    ///
    ///   add table inet filter
    ///   add chain inet filter input hook input priority 0 policy drop
    ///   add rule inet filter input ct state established,related accept
    ///   add rule inet filter input tcp dport 22 accept
    ///
    /// All operations commit in a single kernel transaction — either
    /// every line applies or none do.
    Apply {
        /// Path to the operations file.
        file: String,
        /// Parse and validate only; don't commit to the kernel.
        #[arg(long)]
        dry_run: bool,
    },
}

#[derive(Subcommand)]
enum ListWhat {
    /// List all tables.
    Tables,
    /// List all chains.
    Chains,
    /// List rules in a chain.
    Rules {
        /// Address family (inet, ip, ip6, bridge, arp, netdev).
        family: String,
        /// Table name.
        table: String,
        /// Chain name.
        chain: String,
    },
    /// List sets.
    Sets {
        /// Address family.
        family: String,
    },
}

#[derive(Subcommand)]
enum AddWhat {
    /// Add a table.
    Table {
        /// Address family.
        family: String,
        /// Table name.
        name: String,
    },
    /// Add a chain.
    Chain {
        /// Address family.
        family: String,
        /// Table name.
        table: String,
        /// Chain name.
        name: String,
        /// Hook point (prerouting, input, forward, output, postrouting).
        #[arg(long)]
        hook: Option<String>,
        /// Priority (raw, mangle, dstnat, filter, security, srcnat, or integer).
        #[arg(long)]
        priority: Option<String>,
        /// Chain type (filter, nat, route).
        #[arg(long, name = "type")]
        chain_type: Option<String>,
        /// Default policy (accept or drop).
        #[arg(long)]
        policy: Option<String>,
    },
    /// Add a rule.
    Rule {
        /// Address family.
        family: String,
        /// Table name.
        table: String,
        /// Chain name.
        chain: String,
        /// Rule specification (e.g., "tcp dport 22 accept").
        #[arg(trailing_var_arg = true)]
        spec: Vec<String>,
    },
    /// Add a named set.
    Set {
        /// Address family.
        family: String,
        /// Table name.
        table: String,
        /// Set name.
        name: String,
        /// Key type: ipv4_addr, ipv6_addr, ether_addr, inet_service, ifindex, mark.
        #[arg(long, default_value = "ipv4_addr")]
        key_type: String,
    },
    /// Add elements to a set.
    Element {
        /// Address family.
        family: String,
        /// Table name.
        table: String,
        /// Set name.
        set: String,
        /// Elements to add (comma-separated, e.g., "10.0.0.1,10.0.0.2" or "80,443").
        elements: String,
        /// Key type hint for parsing: ip, port.
        #[arg(long, default_value = "ip")]
        key_type: String,
    },
}

#[derive(Subcommand)]
enum DeleteWhat {
    /// Delete a table.
    Table {
        /// Address family.
        family: String,
        /// Table name.
        name: String,
    },
    /// Delete a chain.
    Chain {
        /// Address family.
        family: String,
        /// Table name.
        table: String,
        /// Chain name.
        name: String,
    },
    /// Delete a rule by handle.
    Rule {
        /// Address family.
        family: String,
        /// Table name.
        table: String,
        /// Chain name.
        chain: String,
        /// Rule handle.
        handle: u64,
    },
    /// Delete a set.
    Set {
        /// Address family.
        family: String,
        /// Table name.
        table: String,
        /// Set name.
        name: String,
    },
}

#[derive(Subcommand)]
enum FlushWhat {
    /// Flush a specific table.
    Table {
        /// Address family.
        family: String,
        /// Table name.
        name: String,
    },
    /// Flush the entire ruleset.
    Ruleset,
}

/// Print a list of JSON values as a pretty-printed JSON array.
fn print_json(items: &Vec<serde_json::Value>) {
    println!(
        "{}",
        serde_json::to_string_pretty(items).expect("JSON serialization")
    );
}

fn parse_family(s: &str) -> Result<Family> {
    match s {
        "inet" => Ok(Family::Inet),
        "ip" | "ip4" | "ipv4" => Ok(Family::Ip),
        "ip6" | "ipv6" => Ok(Family::Ip6),
        "arp" => Ok(Family::Arp),
        "bridge" => Ok(Family::Bridge),
        "netdev" => Ok(Family::Netdev),
        _ => Err(nlink::netlink::Error::InvalidAttribute(format!(
            "unknown family: {s}"
        ))),
    }
}

fn parse_hook(s: &str) -> Result<Hook> {
    // Plan 211 M1 — `Hook::Ingress` was split into `NetdevIngress`
    // (kernel `NF_NETDEV_INGRESS = 0`) and `InetIngress` (kernel
    // `NF_INET_INGRESS = 5`). This CLI uses a `netdev:`/`inet:`
    // prefix to disambiguate; bare `ingress` defaults to the
    // netdev variant for backwards-compat with pre-0.19 commands.
    match s {
        "prerouting" => Ok(Hook::Prerouting),
        "input" => Ok(Hook::Input),
        "forward" => Ok(Hook::Forward),
        "output" => Ok(Hook::Output),
        "postrouting" => Ok(Hook::Postrouting),
        "ingress" | "netdev:ingress" => Ok(Hook::NetdevIngress),
        "inet:ingress" => Ok(Hook::InetIngress),
        "netdev:egress" => Ok(Hook::NetdevEgress),
        _ => Err(nlink::netlink::Error::InvalidAttribute(format!(
            "unknown hook: {s}"
        ))),
    }
}

// Plan 209 H5 (extended) — reject unknown priority tokens. Pre-fix a
// typo on `--priority` silently fell through to `Filter`, installing a
// chain at a different priority than the user asked for (the same
// security footgun the chain_type/policy parsers were hardened against;
// priority was left out of that pass).
fn parse_priority(s: &str) -> Result<Priority> {
    Ok(match s {
        "raw" => Priority::Raw,
        "mangle" => Priority::Mangle,
        "dstnat" => Priority::DstNat,
        "filter" => Priority::Filter,
        "security" => Priority::Security,
        "srcnat" => Priority::SrcNat,
        _ => match s.parse::<i32>() {
            Ok(n) => Priority::Custom(n),
            Err(_) => {
                return Err(nlink::netlink::Error::InvalidAttribute(format!(
                    "unknown priority `{s}` — expected a name (raw, mangle, dstnat, \
                     filter, security, srcnat) or a signed integer"
                )));
            }
        },
    })
}

/// Build a typed [`Chain`] from CLI/file tokens (shared by `add chain`
/// and the atomic `apply` path). Strict on unknown hook / priority /
/// type / policy tokens.
fn build_chain(
    family: Family,
    table: &str,
    name: &str,
    hook: Option<&str>,
    priority: Option<&str>,
    chain_type: Option<&str>,
    policy: Option<&str>,
) -> Result<Chain> {
    let mut chain = Chain::new(table, name).family(family);
    if let Some(h) = hook {
        chain = chain.hook(parse_hook(h)?);
    }
    if let Some(p) = priority {
        chain = chain.priority(parse_priority(p)?);
    }
    if let Some(t) = chain_type {
        let ct = match t {
            "filter" => ChainType::Filter,
            "nat" => ChainType::Nat,
            "route" => ChainType::Route,
            other => {
                return Err(nlink::netlink::Error::InvalidAttribute(format!(
                    "unknown chain type `{other}` — expected one of `filter`, `nat`, `route`"
                )));
            }
        };
        chain = chain.chain_type(ct);
    }
    if let Some(p) = policy {
        let pol = match p {
            "drop" => Policy::Drop,
            "accept" => Policy::Accept,
            other => {
                return Err(nlink::netlink::Error::InvalidAttribute(format!(
                    "unknown policy `{other}` — expected `drop` or `accept`"
                )));
            }
        };
        chain = chain.policy(pol);
    }
    Ok(chain)
}

/// Parse a rule spec (token slice) into a typed [`Rule`] (shared by
/// `add rule` and the atomic `apply` path). STRICT: every token is
/// either consumed by a recognised arm or rejected — a mistyped token
/// is never silently dropped (a firewall failing open).
fn build_rule(family: Family, table: &str, chain: &str, tokens: &[&str]) -> Result<Rule> {
    let mut rule = Rule::new(table, chain).family(family);
    let mut i = 0;
    while i < tokens.len() {
        match tokens[i] {
            "tcp" if tokens.get(i + 1) == Some(&"dport") => {
                let port = parse_rule_port(tokens.get(i + 2), "tcp dport")?;
                rule = rule.match_tcp_dport(port);
                i += 3;
            }
            "udp" if tokens.get(i + 1) == Some(&"dport") => {
                let port = parse_rule_port(tokens.get(i + 2), "udp dport")?;
                rule = rule.match_udp_dport(port);
                i += 3;
            }
            "accept" => {
                rule = rule.accept();
                i += 1;
            }
            "drop" => {
                rule = rule.drop();
                i += 1;
            }
            "counter" => {
                rule = rule.counter();
                i += 1;
            }
            "masquerade" => {
                rule = rule.masquerade();
                i += 1;
            }
            "dnat" if tokens.get(i + 1) == Some(&"to") => {
                let (ip, port) = parse_rule_nat(tokens.get(i + 2), "dnat to")?;
                rule = rule.dnat(ip, port);
                i += 3;
            }
            "snat" if tokens.get(i + 1) == Some(&"to") => {
                let (ip, port) = parse_rule_nat(tokens.get(i + 2), "snat to")?;
                rule = rule.snat(ip, port);
                i += 3;
            }
            "redirect" if tokens.get(i + 1) == Some(&"to") => {
                let port = parse_rule_port(tokens.get(i + 2), "redirect to")?;
                rule = rule.redirect(Some(port));
                i += 3;
            }
            "redirect" => {
                rule = rule.redirect(None);
                i += 1;
            }
            "iif" | "iifname" => {
                let name = tokens.get(i + 1).ok_or_else(|| {
                    nlink::netlink::Error::InvalidAttribute(format!(
                        "nft: `{}` requires an interface name",
                        tokens[i]
                    ))
                })?;
                rule = rule.match_iif(name);
                i += 2;
            }
            "oif" | "oifname" => {
                let name = tokens.get(i + 1).ok_or_else(|| {
                    nlink::netlink::Error::InvalidAttribute(format!(
                        "nft: `{}` requires an interface name",
                        tokens[i]
                    ))
                })?;
                rule = rule.match_oif(name);
                i += 2;
            }
            "ct" if tokens.get(i + 1) == Some(&"state") => {
                use nlink::netlink::nftables::CtState;
                let state_str = tokens.get(i + 2).ok_or_else(|| {
                    nlink::netlink::Error::InvalidAttribute(
                        "nft: `ct state` requires a comma-separated state list".into(),
                    )
                })?;
                let mut state = CtState(0);
                for s in state_str.split(',') {
                    match s.trim() {
                        "established" => state |= CtState::ESTABLISHED,
                        "related" => state |= CtState::RELATED,
                        "new" => state |= CtState::NEW,
                        "invalid" => state |= CtState::INVALID,
                        other => {
                            return Err(nlink::netlink::Error::InvalidAttribute(format!(
                                "nft: unknown ct state `{other}` — expected \
                                 established/related/new/invalid"
                            )));
                        }
                    }
                }
                rule = rule.match_ct_state(state);
                i += 3;
            }
            "ip" if tokens.get(i + 1) == Some(&"saddr") => {
                let (ip, prefix) = parse_rule_cidr(tokens.get(i + 2), "ip saddr")?;
                rule = rule.match_saddr_v4(ip, prefix);
                i += 3;
            }
            "ip" if tokens.get(i + 1) == Some(&"daddr") => {
                let (ip, prefix) = parse_rule_cidr(tokens.get(i + 2), "ip daddr")?;
                rule = rule.match_daddr_v4(ip, prefix);
                i += 3;
            }
            other => {
                return Err(nlink::netlink::Error::InvalidAttribute(format!(
                    "nft: unrecognized rule token `{other}` (a mistyped or unmodelled token \
                     is rejected rather than silently dropped)"
                )));
            }
        }
    }
    Ok(rule)
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let json = cli.json;
    let conn = Connection::<Nftables>::new()?;

    match cli.command {
        Command::List { what } => match what {
            ListWhat::Tables => {
                let tables = conn.list_tables().await?;
                if json {
                    print_json(
                        &tables
                            .iter()
                            .map(|t| serde_json::json!({"family": format!("{:?}", t.family), "name": t.name}))
                            .collect(),
                    );
                } else {
                    for t in &tables {
                        println!("table {:?} {}", t.family, t.name);
                    }
                }
            }
            ListWhat::Chains => {
                let chains = conn.list_chains().await?;
                if json {
                    print_json(
                        &chains
                            .iter()
                            .map(|c| serde_json::json!({
                                "family": format!("{:?}", c.family),
                                "table": c.table,
                                "name": c.name,
                                "hook": c.hook,
                            }))
                            .collect(),
                    );
                } else {
                    for c in &chains {
                        print!("chain {:?} {} {}", c.family, c.table, c.name);
                        if let Some(ref hook) = c.hook {
                            print!(" {{ type filter hook {hook} }}");
                        }
                        println!();
                    }
                }
            }
            ListWhat::Rules {
                family,
                table,
                chain,
            } => {
                let family = parse_family(&family)?;
                let rules = conn.list_rules(&table, family).await?;
                if json {
                    print_json(
                        &rules
                            .iter()
                            .filter(|r| r.chain == chain)
                            .map(|r| serde_json::json!({"chain": r.chain, "handle": r.handle}))
                            .collect(),
                    );
                } else {
                    for r in &rules {
                        if r.chain == chain {
                            println!("  handle {}", r.handle);
                        }
                    }
                }
            }
            ListWhat::Sets { family } => {
                let family = parse_family(&family)?;
                let sets = conn.list_sets(family).await?;
                if json {
                    print_json(
                        &sets
                            .iter()
                            .map(|s| serde_json::json!({"table": s.table, "name": s.name, "flags": s.flags}))
                            .collect(),
                    );
                } else {
                    for s in &sets {
                        println!("set {} {} ({})", s.table, s.name, s.flags);
                    }
                }
            }
        },

        Command::Add { what } => match what {
            AddWhat::Table { family, name } => {
                let family = parse_family(&family)?;
                conn.add_table(&name, family).await?;
                eprintln!("Table {name} added");
            }
            AddWhat::Chain {
                family,
                table,
                name,
                hook,
                priority,
                chain_type,
                policy,
            } => {
                let family = parse_family(&family)?;
                let chain = build_chain(
                    family,
                    &table,
                    &name,
                    hook.as_deref(),
                    priority.as_deref(),
                    chain_type.as_deref(),
                    policy.as_deref(),
                )?;
                conn.add_chain(chain).await?;
                eprintln!("Chain {name} added");
            }
            AddWhat::Rule {
                family,
                table,
                chain,
                spec,
            } => {
                let family = parse_family(&family)?;
                let spec_str = spec.join(" ");
                let tokens: Vec<&str> = spec_str.split_whitespace().collect();
                let rule = build_rule(family, &table, &chain, &tokens)?;
                conn.add_rule(rule).await?;
                eprintln!("Rule added");
            }
            AddWhat::Set {
                family,
                table,
                name,
                key_type,
            } => {
                let family = parse_family(&family)?;
                let kt = parse_key_type(&key_type)?;
                conn.add_set(Set::new(&table, &name).family(family).key_type(kt))
                    .await?;
                eprintln!("Set {name} added");
            }
            AddWhat::Element {
                family,
                table,
                set,
                elements,
                key_type,
            } => {
                let family = parse_family(&family)?;
                let elems = parse_elements(&elements, &key_type)?;
                conn.add_set_elements(&table, &set, family, &elems).await?;
                eprintln!("Elements added to set {set}");
            }
        },

        Command::Delete { what } => match what {
            DeleteWhat::Table { family, name } => {
                let family = parse_family(&family)?;
                conn.del_table(&name, family).await?;
                eprintln!("Table {name} deleted");
            }
            DeleteWhat::Chain {
                family,
                table,
                name,
            } => {
                let family = parse_family(&family)?;
                conn.del_chain(&table, &name, family).await?;
                eprintln!("Chain {name} deleted");
            }
            DeleteWhat::Rule {
                family,
                table,
                chain,
                handle,
            } => {
                let family = parse_family(&family)?;
                conn.del_rule(&table, &chain, family, handle).await?;
                eprintln!("Rule deleted");
            }
            DeleteWhat::Set {
                family,
                table,
                name,
            } => {
                let family = parse_family(&family)?;
                conn.del_set(&table, &name, family).await?;
                eprintln!("Set {name} deleted");
            }
        },

        Command::Flush { what } => match what {
            FlushWhat::Table { family, name } => {
                let family = parse_family(&family)?;
                conn.flush_table(&name, family).await?;
                eprintln!("Table {name} flushed");
            }
            FlushWhat::Ruleset => {
                conn.flush_ruleset().await?;
                eprintln!("Ruleset flushed");
            }
        },

        Command::Apply { file, dry_run } => {
            apply_file(&conn, &file, dry_run).await?;
        }
    }

    Ok(())
}

/// Parse an operations file into a single [`Transaction`] and commit
/// it atomically (or, with `dry_run`, just report what would apply).
async fn apply_file(conn: &Connection<Nftables>, path: &str, dry_run: bool) -> Result<()> {
    let contents = std::fs::read_to_string(path).map_err(|e| {
        nlink::netlink::Error::InvalidMessage(format!("nft apply: cannot read `{path}`: {e}"))
    })?;

    let mut txn = conn.transaction();
    let mut count = 0usize;

    for (lineno, raw) in contents.lines().enumerate() {
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let tokens: Vec<&str> = line.split_whitespace().collect();
        txn = apply_line(txn, &tokens).map_err(|e| {
            nlink::netlink::Error::InvalidMessage(format!(
                "nft apply: {path}:{}: {e}",
                lineno + 1
            ))
        })?;
        count += 1;
    }

    if count == 0 {
        return Err(nlink::netlink::Error::InvalidMessage(
            "nft apply: file contains no operations".into(),
        ));
    }

    if dry_run {
        eprintln!("nft apply: {count} operation(s) parsed OK (dry-run, not committed)");
        return Ok(());
    }

    txn.commit(conn).await?;
    eprintln!("nft apply: {count} operation(s) committed atomically");
    Ok(())
}

/// Translate one tokenized operation line into a Transaction step.
fn apply_line(txn: Transaction, tokens: &[&str]) -> Result<Transaction> {
    let err = |m: String| nlink::netlink::Error::InvalidAttribute(m);
    match tokens {
        ["add", "table", family, name] => Ok(txn.add_table(name, parse_family(family)?)),
        ["delete", "table", family, name] => Ok(txn.del_table(name, parse_family(family)?)),
        ["add", "chain", family, table, name, rest @ ..] => {
            let fam = parse_family(family)?;
            let (mut hook, mut priority, mut ctype, mut policy) = (None, None, None, None);
            let mut i = 0;
            while i < rest.len() {
                let key = rest[i];
                let val = rest.get(i + 1).ok_or_else(|| {
                    err(format!("chain option `{key}` requires a value"))
                })?;
                match key {
                    "hook" => hook = Some(*val),
                    "priority" => priority = Some(*val),
                    "type" => ctype = Some(*val),
                    "policy" => policy = Some(*val),
                    other => return Err(err(format!("unknown chain option `{other}`"))),
                }
                i += 2;
            }
            Ok(txn.add_chain(build_chain(fam, table, name, hook, priority, ctype, policy)?))
        }
        ["delete", "chain", family, table, name] => {
            Ok(txn.del_chain(table, name, parse_family(family)?))
        }
        ["add", "rule", family, table, chain, spec @ ..] => {
            let fam = parse_family(family)?;
            Ok(txn.add_rule(build_rule(fam, table, chain, spec)?))
        }
        _ => Err(err(format!(
            "unrecognized operation `{}` (expected `add|delete table|chain|rule …`)",
            tokens.join(" ")
        ))),
    }
}

fn parse_key_type(s: &str) -> Result<SetKeyType> {
    match s {
        "ipv4_addr" | "ipv4" => Ok(SetKeyType::Ipv4Addr),
        "ipv6_addr" | "ipv6" => Ok(SetKeyType::Ipv6Addr),
        "ether_addr" | "mac" => Ok(SetKeyType::EtherAddr),
        "inet_service" | "port" => Ok(SetKeyType::InetService),
        "ifindex" => Ok(SetKeyType::IfIndex),
        "mark" => Ok(SetKeyType::Mark),
        _ => Err(nlink::netlink::Error::InvalidAttribute(format!(
            "unknown key type: {s}"
        ))),
    }
}

fn parse_elements(s: &str, key_type: &str) -> Result<Vec<SetElement>> {
    s.split(',')
        .map(|elem| {
            let elem = elem.trim();
            match key_type {
                "ip" | "ipv4" => {
                    let ip: Ipv4Addr = elem.parse().map_err(|_| {
                        nlink::netlink::Error::InvalidAttribute(format!("invalid IP: {elem}"))
                    })?;
                    Ok(SetElement::ipv4(ip))
                }
                "port" => {
                    let port: u16 = elem.parse().map_err(|_| {
                        nlink::netlink::Error::InvalidAttribute(format!("invalid port: {elem}"))
                    })?;
                    Ok(SetElement::port(port))
                }
                _ => {
                    let ip: Ipv4Addr = elem.parse().map_err(|_| {
                        nlink::netlink::Error::InvalidAttribute(format!("invalid element: {elem}"))
                    })?;
                    Ok(SetElement::ipv4(ip))
                }
            }
        })
        .collect()
}

fn parse_nat_target(s: &str) -> (Option<Ipv4Addr>, Option<u16>) {
    if let Some((addr, port)) = s.split_once(':') {
        (addr.parse().ok(), port.parse().ok())
    } else {
        (s.parse().ok(), None)
    }
}

fn parse_cidr(s: &str) -> Option<(Ipv4Addr, u8)> {
    if let Some((addr, prefix)) = s.split_once('/') {
        Some((addr.parse().ok()?, prefix.parse().ok()?))
    } else {
        Some((s.parse().ok()?, 32))
    }
}

/// Strict port parse for a rule-spec token: rejects a missing or
/// unparseable value instead of silently dropping the clause.
fn parse_rule_port(tok: Option<&&str>, what: &str) -> Result<u16> {
    let s = tok.ok_or_else(|| {
        nlink::netlink::Error::InvalidAttribute(format!("nft: `{what}` requires a port number"))
    })?;
    s.parse::<u16>().map_err(|_| {
        nlink::netlink::Error::InvalidAttribute(format!(
            "nft: invalid {what} `{s}` (expected port number 0-65535)"
        ))
    })
}

/// Strict NAT-target parse: rejects a missing target or one whose
/// address won't parse, rather than sending a NAT rule to the kernel
/// missing its target.
fn parse_rule_nat(tok: Option<&&str>, what: &str) -> Result<(Ipv4Addr, Option<u16>)> {
    let s = tok.ok_or_else(|| {
        nlink::netlink::Error::InvalidAttribute(format!(
            "nft: `{what}` requires an address (IP or IP:port)"
        ))
    })?;
    let (addr, port) = parse_nat_target(s);
    let ip = addr.ok_or_else(|| {
        nlink::netlink::Error::InvalidAttribute(format!(
            "nft: invalid {what} target `{s}` (expected IPv4 address or IPv4:port)"
        ))
    })?;
    Ok((ip, port))
}

/// Strict CIDR parse for a rule-spec token.
fn parse_rule_cidr(tok: Option<&&str>, what: &str) -> Result<(Ipv4Addr, u8)> {
    let s = tok.ok_or_else(|| {
        nlink::netlink::Error::InvalidAttribute(format!("nft: `{what}` requires an address"))
    })?;
    parse_cidr(s).ok_or_else(|| {
        nlink::netlink::Error::InvalidAttribute(format!(
            "nft: invalid {what} `{s}` (expected IPv4 address or CIDR like 10.0.0.0/8)"
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_priority_known_and_custom() {
        assert!(matches!(parse_priority("filter"), Ok(Priority::Filter)));
        assert!(matches!(parse_priority("-150"), Ok(Priority::Custom(-150))));
    }

    #[test]
    fn parse_priority_rejects_typo() {
        // The whole point: a typo must NOT silently become Filter.
        assert!(parse_priority("filtr").is_err());
        assert!(parse_priority("").is_err());
    }

    #[test]
    fn rule_port_strict() {
        assert_eq!(parse_rule_port(Some(&"22"), "tcp dport").unwrap(), 22);
        assert!(parse_rule_port(None, "tcp dport").is_err());
        assert!(parse_rule_port(Some(&"nope"), "tcp dport").is_err());
        assert!(parse_rule_port(Some(&"70000"), "tcp dport").is_err());
    }

    #[test]
    fn rule_nat_strict() {
        let (ip, port) = parse_rule_nat(Some(&"10.0.0.1:8080"), "dnat to").unwrap();
        assert_eq!(ip, Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(port, Some(8080));
        let (ip, port) = parse_rule_nat(Some(&"10.0.0.2"), "dnat to").unwrap();
        assert_eq!(ip, Ipv4Addr::new(10, 0, 0, 2));
        assert_eq!(port, None);
        assert!(parse_rule_nat(None, "dnat to").is_err());
        assert!(parse_rule_nat(Some(&"not-an-ip"), "dnat to").is_err());
    }

    #[test]
    fn rule_cidr_strict() {
        assert_eq!(
            parse_rule_cidr(Some(&"192.168.0.0/16"), "ip saddr").unwrap(),
            (Ipv4Addr::new(192, 168, 0, 0), 16)
        );
        assert_eq!(
            parse_rule_cidr(Some(&"10.0.0.1"), "ip saddr").unwrap(),
            (Ipv4Addr::new(10, 0, 0, 1), 32)
        );
        assert!(parse_rule_cidr(None, "ip saddr").is_err());
        assert!(parse_rule_cidr(Some(&"garbage"), "ip saddr").is_err());
    }

    #[test]
    fn build_chain_strict() {
        // Valid: hook + priority + type + policy all parse.
        assert!(
            build_chain(
                Family::Inet,
                "filter",
                "input",
                Some("input"),
                Some("0"),
                Some("filter"),
                Some("drop"),
            )
            .is_ok()
        );
        // A bare chain (no options) is fine.
        assert!(build_chain(Family::Inet, "t", "c", None, None, None, None).is_ok());
        // Strict: bad hook / priority / type / policy each error.
        assert!(build_chain(Family::Inet, "t", "c", Some("nope"), None, None, None).is_err());
        assert!(build_chain(Family::Inet, "t", "c", None, Some("filtr"), None, None).is_err());
        assert!(build_chain(Family::Inet, "t", "c", None, None, Some("bogus"), None).is_err());
        assert!(build_chain(Family::Inet, "t", "c", None, None, None, Some("drpo")).is_err());
    }

    #[test]
    fn build_rule_strict() {
        assert!(build_rule(Family::Inet, "t", "c", &["tcp", "dport", "22", "accept"]).is_ok());
        assert!(
            build_rule(
                Family::Inet,
                "t",
                "c",
                &["ct", "state", "established,related", "accept"]
            )
            .is_ok()
        );
        // Empty spec is a valid (empty) rule.
        assert!(build_rule(Family::Inet, "t", "c", &[]).is_ok());
        // Strict: a mistyped token is rejected, not dropped.
        assert!(build_rule(Family::Inet, "t", "c", &["tcp", "dpot", "22"]).is_err());
        assert!(build_rule(Family::Inet, "t", "c", &["bogus"]).is_err());
        assert!(build_rule(Family::Inet, "t", "c", &["ct", "state", "frobnicate"]).is_err());
    }

    #[test]
    fn family_known_and_aliases() {
        assert!(matches!(parse_family("inet"), Ok(Family::Inet)));
        assert!(matches!(parse_family("ipv4"), Ok(Family::Ip)));
        assert!(matches!(parse_family("ip6"), Ok(Family::Ip6)));
        assert!(matches!(parse_family("netdev"), Ok(Family::Netdev)));
        assert!(parse_family("ipx").is_err());
    }

    #[test]
    fn hook_known_and_ingress_variants() {
        assert!(matches!(parse_hook("prerouting"), Ok(Hook::Prerouting)));
        // bare `ingress` defaults to the netdev variant
        assert!(matches!(parse_hook("ingress"), Ok(Hook::NetdevIngress)));
        assert!(matches!(parse_hook("inet:ingress"), Ok(Hook::InetIngress)));
        assert!(parse_hook("sideways").is_err());
    }

    #[test]
    fn cidr_defaults_to_32() {
        assert_eq!(parse_cidr("10.0.0.1"), Some((Ipv4Addr::new(10, 0, 0, 1), 32)));
        assert_eq!(
            parse_cidr("172.16.0.0/12"),
            Some((Ipv4Addr::new(172, 16, 0, 0), 12))
        );
        assert_eq!(parse_cidr("not-an-ip"), None);
        assert_eq!(parse_cidr("10.0.0.0/bad"), None);
    }
}
