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
        config::{NftablesConfig, ReconcileOptions},
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

    /// Reconcile the kernel to a declarative desired-state ruleset.
    ///
    /// Unlike `apply` (which replays imperative `add`/`delete` ops in
    /// one transaction), `reconcile` reads a desired-state file —
    /// `add table`/`add chain`/`add rule` lines describing what
    /// *should* exist — diffs it against the live ruleset, and applies
    /// the minimal set of changes (the same `NftablesConfig` engine the
    /// `config` binary uses for interfaces). `delete`/`flush` lines are
    /// rejected: removal is inferred from the diff, not spelled out.
    Reconcile {
        /// Path to the desired-state ruleset file.
        file: String,
        /// Compute and print the diff without touching the kernel.
        #[arg(long)]
        dry_run: bool,
        /// Apply once without the bounded retry-on-contention loop.
        #[arg(long)]
        no_retry: bool,
    },

    /// Show what `reconcile` would change for a desired-state file,
    /// without touching the kernel (alias for `reconcile --dry-run`).
    Diff {
        /// Path to the desired-state ruleset file.
        file: String,
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

/// Map a kernel hook number to its name for display. Netdev base chains
/// use `ingress`/`egress`; every other family uses the standard L3 hooks.
/// (Bridge can technically host a netdev-ingress chain too, but the L3
/// names are the overwhelmingly common case; an unknown number prints raw.)
fn hook_name(family: Family, n: u32) -> String {
    let name = if matches!(family, Family::Netdev) {
        match n {
            0 => Some("ingress"),
            1 => Some("egress"),
            _ => None,
        }
    } else {
        match n {
            0 => Some("prerouting"),
            1 => Some("input"),
            2 => Some("forward"),
            3 => Some("output"),
            4 => Some("postrouting"),
            5 => Some("ingress"),
            _ => None,
        }
    };
    name.map(str::to_string).unwrap_or_else(|| n.to_string())
}

/// Map a base-chain default policy (`NF_DROP` / `NF_ACCEPT`) to its name.
fn policy_name(p: u32) -> &'static str {
    match p {
        0 => "drop",
        1 => "accept",
        _ => "unknown",
    }
}

/// Report the outcome of an idempotent delete.
fn report_delete(kind: &str, name: &str, existed: bool) {
    if existed {
        eprintln!("{kind} {name} deleted");
    } else {
        eprintln!("{kind} {name} did not exist (no-op)");
    }
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
    let mut chain = Chain::new(table, name)?.family(family);
    if let Some(h) = hook {
        chain = chain.hook(parse_hook(h)?);
    }
    if let Some(p) = priority {
        chain = chain.priority(parse_priority(p)?);
    }
    if let Some(t) = chain_type {
        chain = chain.chain_type(parse_chain_type(t)?);
    }
    if let Some(p) = policy {
        chain = chain.policy(parse_policy(p)?);
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
                                "type": c.chain_type.map(|t| t.as_str()),
                                "hook": c.hook.map(|h| hook_name(c.family, h)),
                                "priority": c.priority,
                                "policy": c.policy.map(policy_name),
                                "device": c.device,
                            }))
                            .collect(),
                    );
                } else {
                    for c in &chains {
                        print!("chain {:?} {} {}", c.family, c.table, c.name);
                        // A base chain carries a hook + type; print the real
                        // values from the kernel rather than a hardcoded
                        // `type filter hook ...`.
                        if let Some(hook) = c.hook {
                            let ty = c.chain_type.map(|t| t.as_str()).unwrap_or("filter");
                            print!(" {{ type {ty} hook {}", hook_name(c.family, hook));
                            if let Some(prio) = c.priority {
                                print!(" priority {prio};");
                            }
                            if let Some(policy) = c.policy {
                                print!(" policy {};", policy_name(policy));
                            }
                            print!(" }}");
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
                            .map(|r| {
                                serde_json::json!({
                                    "chain": r.chain,
                                    "handle": r.handle,
                                    "position": r.position,
                                    "comment": r.comment,
                                    // The library keeps rule expressions as
                                    // raw bytes (no disassembler); expose the
                                    // payload length so callers can tell
                                    // empty rules from non-trivial ones.
                                    "expr_bytes": r.expression_bytes.len(),
                                })
                            })
                            .collect(),
                    );
                } else {
                    for r in &rules {
                        if r.chain == chain {
                            let mut line = format!("  handle {}", r.handle);
                            if let Some(pos) = r.position {
                                line.push_str(&format!(" position {pos}"));
                            }
                            if let Some(ref c) = r.comment {
                                line.push_str(&format!(" comment \"{c}\""));
                            }
                            if !r.expression_bytes.is_empty() {
                                line.push_str(&format!(
                                    " ({} expr bytes)",
                                    r.expression_bytes.len()
                                ));
                            }
                            println!("{line}");
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
                conn.add_table(name.as_str(), family).await?;
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

        // Deletes are idempotent: a missing object is a clean no-op
        // (reported as such) rather than an error, via the `*_if_exists`
        // library variants.
        Command::Delete { what } => match what {
            DeleteWhat::Table { family, name } => {
                let family = parse_family(&family)?;
                let existed = conn.del_table_if_exists(name.as_str(), family).await?;
                report_delete("Table", &name, existed);
            }
            DeleteWhat::Chain {
                family,
                table,
                name,
            } => {
                let family = parse_family(&family)?;
                let existed = conn.del_chain_if_exists(table.as_str(), name.as_str(), family).await?;
                report_delete("Chain", &name, existed);
            }
            DeleteWhat::Rule {
                family,
                table,
                chain,
                handle,
            } => {
                let family = parse_family(&family)?;
                let existed = conn.del_rule_if_exists(&table, &chain, family, handle).await?;
                report_delete("Rule", &handle.to_string(), existed);
            }
            DeleteWhat::Set {
                family,
                table,
                name,
            } => {
                let family = parse_family(&family)?;
                let existed = conn.del_set_if_exists(&table, &name, family).await?;
                report_delete("Set", &name, existed);
            }
        },

        Command::Flush { what } => match what {
            FlushWhat::Table { family, name } => {
                let family = parse_family(&family)?;
                conn.flush_table(name.as_str(), family).await?;
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

        Command::Reconcile {
            file,
            dry_run,
            no_retry,
        } => {
            reconcile_file(&conn, &file, dry_run, no_retry).await?;
        }

        Command::Diff { file } => {
            reconcile_file(&conn, &file, true, false).await?;
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

/// Reconcile the kernel ruleset to a declarative desired-state file.
///
/// The file uses the same `add table`/`add chain`/`add rule` line
/// grammar as `apply`, but is interpreted as *desired state*: the
/// whole file is parsed into an [`NftablesConfig`], diffed against the
/// live ruleset, and the minimal change set is applied. With
/// `dry_run`, the diff is printed and nothing is committed.
async fn reconcile_file(
    conn: &Connection<Nftables>,
    path: &str,
    dry_run: bool,
    no_retry: bool,
) -> Result<()> {
    let contents = std::fs::read_to_string(path).map_err(|e| {
        nlink::netlink::Error::InvalidMessage(format!("nft reconcile: cannot read `{path}`: {e}"))
    })?;
    let cfg = parse_ruleset(&contents)
        .map_err(|e| nlink::netlink::Error::InvalidMessage(format!("nft reconcile: {path}: {e}")))?;

    let diff = cfg.diff(conn).await?;

    if dry_run {
        if diff.is_empty() {
            println!("No changes needed; the live ruleset already matches `{path}`.");
        } else {
            println!("Reconcile would make {} change(s):", diff.change_count());
            print!("{diff}");
        }
        return Ok(());
    }

    if diff.is_empty() {
        eprintln!("nft reconcile: no changes needed");
        return Ok(());
    }

    if no_retry {
        let n = diff.apply(conn).await?;
        eprintln!("nft reconcile: applied {n} change(s)");
    } else {
        let report = diff
            .apply_reconcile(conn, ReconcileOptions::default())
            .await?;
        eprintln!(
            "nft reconcile: applied {} change(s) in {} attempt(s)",
            report.change_count, report.attempts
        );
    }
    Ok(())
}

/// Parse a declarative desired-state ruleset into an [`NftablesConfig`].
///
/// Two passes: the first validates every line and folds the flat
/// `add table`/`add chain`/`add rule` grammar into per-table groups
/// (surfacing parse errors eagerly — STRICT, like the imperative
/// parser); the second assembles the nested `NftablesConfig` via its
/// builder closures. `delete`/`flush` lines are rejected, because
/// removal in a desired-state model is inferred from the diff.
fn parse_ruleset(contents: &str) -> Result<NftablesConfig> {
    let err = |m: String| nlink::netlink::Error::InvalidAttribute(m);

    /// A chain with its options pre-resolved to typed enums.
    struct PendingChain {
        name: String,
        hook: Option<Hook>,
        priority: Option<Priority>,
        chain_type: Option<ChainType>,
        policy: Option<Policy>,
    }
    /// One table and its declared chains + pre-built rules.
    struct PendingTable {
        name: String,
        family: Family,
        chains: Vec<PendingChain>,
        rules: Vec<(String, Rule)>,
    }

    let mut tables: Vec<PendingTable> = Vec::new();
    // Locate (or refuse to invent) the pending table for an op.
    fn find<'a>(
        tables: &'a mut [PendingTable],
        family: Family,
        name: &str,
    ) -> Option<&'a mut PendingTable> {
        tables
            .iter_mut()
            .find(|t| t.family == family && t.name == name)
    }

    for (lineno, raw) in contents.lines().enumerate() {
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let tokens: Vec<&str> = line.split_whitespace().collect();
        let loc = |m: String| err(format!("line {}: {m}", lineno + 1));

        match tokens.as_slice() {
            ["add", "table", family, name] => {
                let fam = parse_family(family)?;
                if find(&mut tables, fam, name).is_none() {
                    tables.push(PendingTable {
                        name: (*name).to_string(),
                        family: fam,
                        chains: Vec::new(),
                        rules: Vec::new(),
                    });
                }
            }
            ["add", "chain", family, table, name, rest @ ..] => {
                let fam = parse_family(family)?;
                let (mut hook, mut priority, mut chain_type, mut policy) = (None, None, None, None);
                let mut i = 0;
                while i < rest.len() {
                    let key = rest[i];
                    let val = rest
                        .get(i + 1)
                        .ok_or_else(|| loc(format!("chain option `{key}` requires a value")))?;
                    match key {
                        "hook" => hook = Some(parse_hook(val)?),
                        "priority" => priority = Some(parse_priority(val)?),
                        "type" => chain_type = Some(parse_chain_type(val)?),
                        "policy" => policy = Some(parse_policy(val)?),
                        other => return Err(loc(format!("unknown chain option `{other}`"))),
                    }
                    i += 2;
                }
                let t = find(&mut tables, fam, table).ok_or_else(|| {
                    loc(format!(
                        "chain `{name}` references table `{table}` (family {family}) not declared earlier in the file"
                    ))
                })?;
                t.chains.push(PendingChain {
                    name: (*name).to_string(),
                    hook,
                    priority,
                    chain_type,
                    policy,
                });
            }
            ["add", "rule", family, table, chain, spec @ ..] => {
                let fam = parse_family(family)?;
                // Pre-build the typed rule body so parse errors surface
                // here rather than inside the infallible builder closure.
                let rule = build_rule(fam, table, chain, spec)?;
                let t = find(&mut tables, fam, table).ok_or_else(|| {
                    loc(format!(
                        "rule references table `{table}` (family {family}) not declared earlier in the file"
                    ))
                })?;
                t.rules.push(((*chain).to_string(), rule));
            }
            ["delete", ..] | ["flush", ..] => {
                return Err(loc(format!(
                    "`{}` is not allowed in a desired-state ruleset — removal is inferred from the diff. Use `nft apply <file>` for imperative ops.",
                    tokens[0]
                )));
            }
            _ => {
                return Err(loc(format!(
                    "unrecognized line `{}` (expected `add table|chain|rule …`)",
                    tokens.join(" ")
                )));
            }
        }
    }

    if tables.is_empty() {
        return Err(err("file declares no tables".into()));
    }

    // Second pass: assemble the nested config via the builder closures.
    // All fallible parsing already happened above, so these are infallible.
    let mut cfg = NftablesConfig::new();
    for pt in tables {
        let PendingTable {
            name,
            family,
            chains,
            rules,
        } = pt;
        cfg = cfg.table(name, family, move |mut tb| {
            for pc in chains {
                let PendingChain {
                    name,
                    hook,
                    priority,
                    chain_type,
                    policy,
                } = pc;
                tb = tb.chain(name, move |mut cb| {
                    if let Some(h) = hook {
                        cb = cb.hook(h);
                    }
                    if let Some(p) = priority {
                        cb = cb.priority(p);
                    }
                    if let Some(ct) = chain_type {
                        cb = cb.chain_type(ct);
                    }
                    if let Some(pol) = policy {
                        cb = cb.policy(pol);
                    }
                    cb
                });
            }
            for (chain, rule) in rules {
                // The pre-built rule already carries this table/chain/
                // family; return it in place of the fresh builder rule.
                tb = tb.rule(chain, move |_fresh| rule);
            }
            tb
        });
    }
    Ok(cfg)
}

/// Parse a chain `type` token (`filter`/`nat`/`route`).
fn parse_chain_type(s: &str) -> Result<ChainType> {
    match s {
        "filter" => Ok(ChainType::Filter),
        "nat" => Ok(ChainType::Nat),
        "route" => Ok(ChainType::Route),
        other => Err(nlink::netlink::Error::InvalidAttribute(format!(
            "unknown chain type `{other}` — expected one of `filter`, `nat`, `route`"
        ))),
    }
}

/// Parse a chain `policy` token (`accept`/`drop`).
fn parse_policy(s: &str) -> Result<Policy> {
    match s {
        "drop" => Ok(Policy::Drop),
        "accept" => Ok(Policy::Accept),
        other => Err(nlink::netlink::Error::InvalidAttribute(format!(
            "unknown policy `{other}` — expected `drop` or `accept`"
        ))),
    }
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
    fn hook_name_maps_per_family() {
        assert_eq!(hook_name(Family::Inet, 1), "input");
        assert_eq!(hook_name(Family::Ip, 4), "postrouting");
        assert_eq!(hook_name(Family::Netdev, 0), "ingress");
        assert_eq!(hook_name(Family::Netdev, 1), "egress");
        // Unknown number prints raw.
        assert_eq!(hook_name(Family::Inet, 99), "99");
    }

    #[test]
    fn policy_name_maps() {
        assert_eq!(policy_name(0), "drop");
        assert_eq!(policy_name(1), "accept");
        assert_eq!(policy_name(7), "unknown");
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

    #[test]
    fn parse_ruleset_folds_flat_lines_into_tables() {
        let cfg = parse_ruleset(
            "
            # a desired-state ruleset
            add table inet filter
            add chain inet filter input hook input priority 0 policy drop
            add rule inet filter input tcp dport 22 accept
            add rule inet filter input tcp dport 443 accept
            add table ip nat
            add chain ip nat post hook postrouting priority 100 type nat
            ",
        )
        .expect("valid ruleset");

        assert_eq!(cfg.tables().len(), 2);
        let filter = &cfg.tables()[0];
        assert_eq!(filter.name(), "filter");
        assert_eq!(filter.chains().len(), 1);
        assert_eq!(filter.chains()[0].name(), "input");
        assert_eq!(filter.rules().len(), 2);
        let nat = &cfg.tables()[1];
        assert_eq!(nat.name(), "nat");
        assert_eq!(nat.chains().len(), 1);
    }

    #[test]
    fn parse_ruleset_rejects_delete_and_flush() {
        let e = parse_ruleset("add table inet filter\ndelete table inet filter\n").unwrap_err();
        assert!(e.to_string().contains("desired-state"), "{e}");
        let e = parse_ruleset("flush ruleset\n").unwrap_err();
        assert!(e.to_string().contains("desired-state"), "{e}");
    }

    #[test]
    fn parse_ruleset_rejects_chain_for_undeclared_table() {
        let e = parse_ruleset("add chain inet filter input\n").unwrap_err();
        assert!(e.to_string().contains("not declared"), "{e}");
    }

    #[test]
    fn parse_ruleset_rejects_empty_and_unknown() {
        assert!(parse_ruleset("# only comments\n").is_err());
        let e = parse_ruleset("frobnicate the widget\n").unwrap_err();
        assert!(e.to_string().contains("unrecognized"), "{e}");
    }

    #[test]
    fn parse_ruleset_propagates_strict_rule_errors() {
        // A malformed rule spec must fail the whole parse (strict),
        // never silently drop the offending token.
        let e = parse_ruleset(
            "add table inet filter\nadd rule inet filter input tcp dport notaport accept\n",
        )
        .unwrap_err();
        assert!(!e.to_string().is_empty());
    }
}
