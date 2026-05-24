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
//! ```ignore
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
//! # 0.16 scope
//!
//! Covers tables, chains, rules, and flowtables. Sets and maps
//! deferred — they're a separate dimension of nftables state that
//! warrants its own design pass. The shipped diff uses
//! **name-based identity** for rules: a `DeclaredRule` matches a
//! kernel rule by its `handle_key` (caller-supplied); rules
//! without a key are re-applied on every diff. The full
//! canonicalization-based diff designed in Plan 157 §4.3 is
//! deferred — it needs `Rule` type's typed match collection to be
//! refactored for sortability, which is a separate pass.

mod apply;
mod diff;
mod types;

pub use apply::{ReconcileOptions, ReconcileReport};
pub use diff::{NftablesDiff, RuleHandle};
pub use types::{
    DeclaredChain, DeclaredFlowtable, DeclaredRule, DeclaredTable, NftablesConfig,
};
