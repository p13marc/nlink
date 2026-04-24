//! TC message builders (legacy, deprecated).
//!
//! These are the original string-args message builders for TC
//! operations. They take `&str` parent / classid / handle plus
//! `&[String]` type-specific params, and dispatch to per-kind
//! parsers that re-split the strings at runtime.
//!
//! New code should use the typed API on `Connection<Route>` instead:
//!
//! | Legacy                                    | Typed replacement                                                                 |
//! |-------------------------------------------|-----------------------------------------------------------------------------------|
//! | `tc::builders::class::{add, change, ...}` | `Connection::add_class_config` + `HtbClassConfig` / `HfscClassConfig` / ...       |
//! | `tc::builders::qdisc::{add, change, ...}` | `Connection::add_qdisc(_full)` + `HtbQdiscConfig` / `CakeConfig` / `NetemConfig` / ... |
//! | `tc::builders::filter::{add, change, ...}`| `Connection::add_filter` + `FlowerFilter` / `U32Filter` / `MatchallFilter` / ...  |
//! | `tc::builders::action::*`                 | Attach via `FilterConfig::actions(...)` with `GactAction` / `MirredAction` / ... (standalone-action CRUD typed path is not yet wired — see Plan 137-family follow-ups). |
//!
//! The legacy modules are kept for `bins/tc/`'s CLI pass-through —
//! they'll be removed once the bin migrates to the typed API. The
//! `#[deprecated]` attribute here makes every remaining call site
//! visible at compile time, so the migration TODO list survives across
//! sessions.

#[deprecated(
    since = "0.14.0",
    note = "use Connection::add_class_config + HtbClassConfig / HfscClassConfig / DrrClassConfig / QfqClassConfig — see `tc::builders` module docs for the migration table"
)]
pub mod class;

#[deprecated(
    since = "0.14.0",
    note = "use Connection::add_qdisc(_full) + the typed qdisc configs (HtbQdiscConfig, NetemConfig, CakeConfig, FqPieConfig, TbfConfig, ...) — see `tc::builders` module docs"
)]
pub mod qdisc;

#[deprecated(
    since = "0.14.0",
    note = "use Connection::add_filter + typed filter builders (FlowerFilter, U32Filter, MatchallFilter, BasicFilter, ...) — see `tc::builders` module docs"
)]
pub mod filter;

#[deprecated(
    since = "0.14.0",
    note = "for filter-attached actions, compose via FilterConfig::actions(ActionList::new().with(GactAction::drop())); standalone shared-action CRUD on Connection is not yet typed — this module is kept until that API lands"
)]
pub mod action;
