//! Declarative `NftablesConfig` — mirror of `NetworkConfig` for
//! the nftables subsystem.
//!
//! See [`NftablesConfig`] for the builder, [`NftablesDiff`] for
//! the result of `diff`, and `apply.rs` for the transactional
//! commit.
//!
//! # When to use
//!
//! - You manage a firewall declaratively (config file → kernel
//!   state) rather than imperatively (call `add_table` /
//!   `add_chain` / `add_rule` by hand).
//! - You need atomic apply (all-or-nothing) so the kernel never
//!   sees a partially-applied ruleset.
//! - You want a stable cycle: declare state → compute diff →
//!   apply → diff again is no-op.
//!
//! For one-off mutations, use the imperative
//! `Connection::<Nftables>::{add_table, add_chain, add_rule}`
//! methods directly.
//!
//! # Example
//!
//! ```no_run
//! use nlink::{Connection, Nftables, NftablesConfig};
//! use nlink::netlink::nftables::{Family, Hook, Priority, Policy};
//!
//! # async fn run() -> nlink::Result<()> {
//! let cfg = NftablesConfig::new()
//!     .table("filter", Family::Inet, |t| t
//!         .chain("input", |c| c
//!             .hook(Hook::Input).priority(Priority::Filter).policy(Policy::Drop)));
//!
//! let conn = Connection::<Nftables>::new()?;
//! let diff = cfg.diff(&conn).await?;
//! println!("{}", diff.summary());
//! diff.apply(&conn).await?;
//! # Ok(())
//! # }
//! ```
//!
//! # Scope
//!
//! Covers tables, chains, rules, flowtables, sets (intervals,
//! concatenations, timeouts, maps and verdict maps) and named
//! stateful objects (counters, quotas, limits). A `DeclaredRule`
//! matches a kernel rule by its key — caller-supplied with
//! `rule_keyed`, else derived from its content — and declared order is
//! enforced per chain. Bodies are compared after attribute
//! normalization, with the live state the kernel echoes (counter
//! values, quota consumption) left out; sets and objects are compared
//! by configuration, never by what the packet path has done to them.
//! See `docs/recipes/nftables-declarative-config.md` and
//! `docs/recipes/nftables-sets-maps.md`.

mod apply;
mod diff;
mod rules;
mod types;

pub use apply::{ReconcileOptions, ReconcileReport};
pub use diff::{
    MoveReason, NftDiffOptions, NftablesDiff, RuleAdd, RuleHandle, RuleMove, RulePlacement,
    SetElementsChange,
};
// DeclaredSet/DeclaredSetBuilder are the type of the *public* field
// `NftablesDiff::sets_to_add`, so leaving them unexported made that field
// unnameable — a caller could not destructure or construct it (#210).
// The *Builder types are the same story from the other direction: the
// declarative DSL hands one to every closure the caller writes
// (`cfg.table("t", Inet, |t| t.chain("c", |c| ...))`), so they are already
// de-facto public API — a caller just could not name them, which meant no
// helper function could take one as a parameter.
pub use types::{
    DeclaredChain, DeclaredChainBuilder, DeclaredFlowtable, DeclaredFlowtableBuilder,
    DeclaredObject, DeclaredRule, DeclaredSet, DeclaredSetBuilder, DeclaredTable,
    DeclaredTableBuilder, NftablesConfig, SetElementMode,
};
