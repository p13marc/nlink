//! Sealed trait that formalizes the `parse_params` contract used
//! across every typed TC config (qdiscs, classes, filters, actions).
//!
//! See [`ParseParams`] for the contract and the
//! ["TC API conventions"](https://github.com/.../CLAUDE.md#tc-api-conventions)
//! section of `CLAUDE.md` for the broader pattern.
//!
//! # Why a trait at all?
//!
//! Every typed config already has an inherent `pub fn parse_params`
//! method — the trait doesn't change behaviour. It exists so:
//!
//! 1. The contract (strict rejection, kind-prefixed error messages,
//!    return shape) is declared in one place rather than implied by
//!    convention across 25 inherent methods.
//! 2. Generic dispatch (`fn run<C: ParseParams>(p: &[&str]) -> Result<C>`)
//!    becomes possible — relevant for the bin's typed-dispatch macros
//!    and for any downstream consumer building their own DSL on top.
//! 3. The set of types that participate is closed (sealed trait), so
//!    third-party consumers can't accidentally diverge from the
//!    contract by impl'ing `ParseParams` for their own types with
//!    looser semantics.
//!
//! Inherent methods stay; the trait simply forwards to them. Existing
//! callers (every test, every recipe) keep working unchanged.

use crate::Result;

mod sealed {
    pub trait Sealed {}
}

/// Parse a `tc(8)`-style token slice into a typed config.
///
/// # Contract
///
/// Implementations **must**:
///
/// - Return `Err(`[`Error::InvalidMessage`]`)` for unknown tokens,
///   missing values, and unparseable inner values. Silent skipping
///   is a bug — the legacy `tc::options::*` parsers swallowed
///   unknown tokens, and the typed parsers exist to fix that.
/// - Begin every error message with the kind name
///   (`"htb: invalid r2q `foo` (expected unsigned integer)"`,
///   `"flower: `classid` requires a value"`,
///   `"netem: unknown token `nonsense`"`).
/// - Accept tokens in any order (keyword-style). Positional
///   optional args are consumed greedily up to the next keyword via
///   a per-config `is_keyword` helper.
/// - Honour `tc(8)` aliases (`classid`/`flowid`,
///   `burst`/`buffer`/`maxburst`) at the same arm.
/// - Reject "kernel-accepts-but-typed-config-doesn't-model"
///   tokens with a clear error pointing at the typed builder
///   method or the legacy fallback. **Never silently fall back.**
///
/// # Sealed
///
/// This trait is sealed via a private supertrait. Third-party crates
/// can use the trait but cannot implement it. The contract is
/// intentionally narrow; extending it across foreign types invites
/// drift.
///
/// # Example
///
/// ```no_run
/// # fn example() -> nlink::Result<()> {
/// use nlink::ParseParams;
/// use nlink::netlink::tc::HtbQdiscConfig;
///
/// let cfg: HtbQdiscConfig = ParseParams::parse_params(&["default", "10"])?;
/// # Ok(())
/// # }
/// ```
///
/// [`Error::InvalidMessage`]: crate::Error::InvalidMessage
pub trait ParseParams: Sized + sealed::Sealed {
    /// Parse `params` into `Self`. See the trait-level docs for the
    /// full error-shape and rejection contract.
    fn parse_params(params: &[&str]) -> Result<Self>;
}

/// Generates the sealing impl + the trait impl for each listed type.
/// Each trait impl forwards to the inherent `parse_params` method,
/// which every listed type already exposes.
macro_rules! impl_parse_params {
    ($($ty:path),+ $(,)?) => {
        $(
            impl sealed::Sealed for $ty {}
            impl ParseParams for $ty {
                fn parse_params(params: &[&str]) -> Result<Self> {
                    <$ty>::parse_params(params)
                }
            }
        )+
    };
}

impl_parse_params! {
    // Qdisc configs (18) — see crates/nlink/src/netlink/tc.rs.
    crate::netlink::tc::CakeConfig,
    crate::netlink::tc::ClsactConfig,
    crate::netlink::tc::DrrConfig,
    crate::netlink::tc::EtfConfig,
    crate::netlink::tc::FqCodelConfig,
    crate::netlink::tc::HfscConfig,
    crate::netlink::tc::HtbQdiscConfig,
    crate::netlink::tc::IngressConfig,
    crate::netlink::tc::MqprioConfig,
    crate::netlink::tc::NetemConfig,
    crate::netlink::tc::PieConfig,
    crate::netlink::tc::PlugConfig,
    crate::netlink::tc::PrioConfig,
    crate::netlink::tc::QfqConfig,
    crate::netlink::tc::RedConfig,
    crate::netlink::tc::SfqConfig,
    crate::netlink::tc::TaprioConfig,
    crate::netlink::tc::TbfConfig,
    // Filter configs (9 — full filter side typed-first as of Plan 138 + Plan 133 PR C).
    crate::netlink::filter::BasicFilter,
    crate::netlink::filter::BpfFilter,
    crate::netlink::filter::CgroupFilter,
    crate::netlink::filter::FlowFilter,
    crate::netlink::filter::FlowerFilter,
    crate::netlink::filter::FwFilter,
    crate::netlink::filter::MatchallFilter,
    crate::netlink::filter::RouteFilter,
    crate::netlink::filter::U32Filter,
    // Action configs — Plan 139 PR B closes (14 of 14 typed-first;
    // PeditAction is a stub that rejects all inputs per Plan §10).
    crate::netlink::action::BpfAction,
    crate::netlink::action::ConnmarkAction,
    crate::netlink::action::CsumAction,
    crate::netlink::action::CtAction,
    crate::netlink::action::GactAction,
    crate::netlink::action::MirredAction,
    crate::netlink::action::NatAction,
    crate::netlink::action::PeditAction,
    crate::netlink::action::PoliceAction,
    crate::netlink::action::SampleAction,
    crate::netlink::action::SimpleAction,
    crate::netlink::action::SkbeditAction,
    crate::netlink::action::TunnelKeyAction,
    crate::netlink::action::VlanAction,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::netlink::tc::HtbQdiscConfig;

    #[test]
    fn trait_dispatch_matches_inherent() {
        let via_trait = <HtbQdiscConfig as ParseParams>::parse_params(&["default", "10"])
            .expect("htb default 10 should parse via trait");
        let via_inherent =
            HtbQdiscConfig::parse_params(&["default", "10"]).expect("inherent parse");
        // No PartialEq on these configs, so compare a discriminating field.
        assert_eq!(via_trait.default_class, via_inherent.default_class);
    }

    #[test]
    fn trait_propagates_strict_errors() {
        let err = <HtbQdiscConfig as ParseParams>::parse_params(&["nonsense"])
            .expect_err("strict parser must reject unknown tokens");
        let msg = err.to_string();
        assert!(msg.contains("htb"), "error must be kind-prefixed: {msg}");
    }

    /// Generic dispatch to prove the trait is usable in a generic
    /// position — this is the whole point of the formalization.
    #[test]
    fn generic_dispatch_compiles() {
        fn parse<C: ParseParams>(params: &[&str]) -> Result<C> {
            C::parse_params(params)
        }
        let _: HtbQdiscConfig = parse(&["default", "10"]).expect("htb default 10");
    }
}
