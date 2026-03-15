//! nft - nftables firewall management utility.
//!
//! Manages nftables tables, chains, rules, and sets via NETLINK_NETFILTER.

use clap::{Parser, Subcommand};
use nlink::netlink::nftables::{Chain, ChainType, Family, Hook, Policy, Priority, Rule};
use nlink::netlink::{Connection, Nftables, Result};

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
                        _ => {}
                    }
                    i += 1;
                }

                conn.add_rule(rule).await?;
                eprintln!("Rule added");
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
