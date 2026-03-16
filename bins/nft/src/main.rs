//! nft - nftables firewall management utility.
//!
//! Manages nftables tables, chains, rules, and sets via NETLINK_NETFILTER.

use clap::{Parser, Subcommand};
use nlink::netlink::nftables::{
    Chain, ChainType, Family, Hook, Policy, Priority, Rule, Set, SetElement, SetKeyType,
};
use nlink::netlink::{Connection, Nftables, Result};
use std::net::Ipv4Addr;

#[derive(Parser)]
#[command(name = "nft", version, about = "nftables firewall management utility")]
struct Cli {
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
    match s {
        "prerouting" => Ok(Hook::Prerouting),
        "input" => Ok(Hook::Input),
        "forward" => Ok(Hook::Forward),
        "output" => Ok(Hook::Output),
        "postrouting" => Ok(Hook::Postrouting),
        "ingress" => Ok(Hook::Ingress),
        _ => Err(nlink::netlink::Error::InvalidAttribute(format!(
            "unknown hook: {s}"
        ))),
    }
}

fn parse_priority(s: &str) -> Priority {
    match s {
        "raw" => Priority::Raw,
        "mangle" => Priority::Mangle,
        "dstnat" => Priority::DstNat,
        "filter" => Priority::Filter,
        "security" => Priority::Security,
        "srcnat" => Priority::SrcNat,
        _ => {
            if let Ok(n) = s.parse::<i32>() {
                Priority::Custom(n)
            } else {
                Priority::Filter
            }
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let conn = Connection::<Nftables>::new()?;

    match cli.command {
        Command::List { what } => match what {
            ListWhat::Tables => {
                let tables = conn.list_tables().await?;
                for t in &tables {
                    println!("table {:?} {}", t.family, t.name);
                }
            }
            ListWhat::Chains => {
                let chains = conn.list_chains().await?;
                for c in &chains {
                    print!("chain {:?} {} {}", c.family, c.table, c.name);
                    if let Some(ref hook) = c.hook {
                        print!(" {{ type filter hook {hook} }}");
                    }
                    println!();
                }
            }
            ListWhat::Rules {
                family,
                table,
                chain,
            } => {
                let family = parse_family(&family)?;
                let rules = conn.list_rules(&table, family).await?;
                for r in &rules {
                    if r.chain == chain {
                        println!("  handle {}", r.handle);
                    }
                }
            }
            ListWhat::Sets { family } => {
                let family = parse_family(&family)?;
                let sets = conn.list_sets(family).await?;
                for s in &sets {
                    println!("set {} {} ({})", s.table, s.name, s.flags);
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
                let mut chain = Chain::new(&table, &name).family(family);

                if let Some(ref h) = hook {
                    chain = chain.hook(parse_hook(h)?);
                }
                if let Some(ref p) = priority {
                    chain = chain.priority(parse_priority(p));
                }
                if let Some(ref t) = chain_type {
                    chain = chain.chain_type(match t.as_str() {
                        "filter" => ChainType::Filter,
                        "nat" => ChainType::Nat,
                        "route" => ChainType::Route,
                        _ => ChainType::Filter,
                    });
                }
                if let Some(ref p) = policy {
                    chain = chain.policy(match p.as_str() {
                        "drop" => Policy::Drop,
                        _ => Policy::Accept,
                    });
                }

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
                let mut rule = Rule::new(&table, &chain).family(family);

                // Simple rule spec parsing
                let spec_str = spec.join(" ");
                let tokens: Vec<&str> = spec_str.split_whitespace().collect();
                let mut i = 0;
                while i < tokens.len() {
                    match tokens[i] {
                        "tcp" if tokens.get(i + 1) == Some(&"dport") => {
                            if let Some(port) = tokens.get(i + 2).and_then(|s| s.parse().ok()) {
                                rule = rule.match_tcp_dport(port);
                                i += 3;
                                continue;
                            }
                        }
                        "udp" if tokens.get(i + 1) == Some(&"dport") => {
                            if let Some(port) = tokens.get(i + 2).and_then(|s| s.parse().ok()) {
                                rule = rule.match_udp_dport(port);
                                i += 3;
                                continue;
                            }
                        }
                        "accept" => {
                            rule = rule.accept();
                        }
                        "drop" => {
                            rule = rule.drop();
                        }
                        "counter" => {
                            rule = rule.counter();
                        }
                        "masquerade" => {
                            rule = rule.masquerade();
                        }
                        "dnat" if tokens.get(i + 1) == Some(&"to") => {
                            if let Some(target) = tokens.get(i + 2) {
                                let (addr, port) = parse_nat_target(target);
                                if let Some(ip) = addr {
                                    rule = rule.dnat(ip, port);
                                    i += 3;
                                    continue;
                                }
                            }
                        }
                        "snat" if tokens.get(i + 1) == Some(&"to") => {
                            if let Some(target) = tokens.get(i + 2) {
                                let (addr, port) = parse_nat_target(target);
                                if let Some(ip) = addr {
                                    rule = rule.snat(ip, port);
                                    i += 3;
                                    continue;
                                }
                            }
                        }
                        "redirect" if tokens.get(i + 1) == Some(&"to") => {
                            if let Some(port) = tokens.get(i + 2).and_then(|s| s.parse().ok()) {
                                rule = rule.redirect(Some(port));
                                i += 3;
                                continue;
                            }
                        }
                        "redirect" => {
                            rule = rule.redirect(None);
                        }
                        "iif" | "iifname" => {
                            if let Some(name) = tokens.get(i + 1) {
                                rule = rule.match_iif(name);
                                i += 2;
                                continue;
                            }
                        }
                        "oif" | "oifname" => {
                            if let Some(name) = tokens.get(i + 1) {
                                rule = rule.match_oif(name);
                                i += 2;
                                continue;
                            }
                        }
                        "ct" if tokens.get(i + 1) == Some(&"state") => {
                            if let Some(state_str) = tokens.get(i + 2) {
                                use nlink::netlink::nftables::CtState;
                                let mut state = CtState(0);
                                for s in state_str.split(',') {
                                    match s.trim() {
                                        "established" => state |= CtState::ESTABLISHED,
                                        "related" => state |= CtState::RELATED,
                                        "new" => state |= CtState::NEW,
                                        "invalid" => state |= CtState::INVALID,
                                        _ => {}
                                    }
                                }
                                rule = rule.match_ct_state(state);
                                i += 3;
                                continue;
                            }
                        }
                        "ip" if tokens.get(i + 1) == Some(&"saddr") => {
                            if let Some(addr_str) = tokens.get(i + 2)
                                && let Some((ip, prefix)) = parse_cidr(addr_str)
                            {
                                rule = rule.match_saddr_v4(ip, prefix);
                                i += 3;
                                continue;
                            }
                        }
                        "ip" if tokens.get(i + 1) == Some(&"daddr") => {
                            if let Some(addr_str) = tokens.get(i + 2)
                                && let Some((ip, prefix)) = parse_cidr(addr_str)
                            {
                                rule = rule.match_daddr_v4(ip, prefix);
                                i += 3;
                                continue;
                            }
                        }
                        _ => {}
                    }
                    i += 1;
                }

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
    }

    Ok(())
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
