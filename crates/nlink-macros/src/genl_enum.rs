//! `#[derive(GenlEnum)]` — typed value enum encoded *inside* an
//! attribute payload (not as the attribute kind itself).
//!
//! Used for things like `DPLL_LOCK_STATUS_*`,
//! `DEVLINK_RATE_TYPE_*`, etc. — the kernel UAPI declares them
//! as `enum` types whose values appear inside `nla_u32` (or
//! sometimes `nla_u8`) attribute payloads. The derive produces
//! the same `From + TryFrom + UnknownValue` codec as
//! `GenlCommand` / `GenlAttribute`, just with the wider u32 repr
//! also allowed.
//!
//! ## 1-based vs 0-based discriminants
//!
//! Kernel UAPI enums are predominantly 1-based (DPLL_MODE_MANUAL
//! = 1, DPLL_MODE_AUTOMATIC = 2). A small minority are 0-based
//! (DPLL_FEATURE_STATE_DISABLE = 0). The derive doesn't care
//! either way — variants carry their explicit discriminants
//! verbatim through `From`/`TryFrom`. The user declares whatever
//! the kernel UAPI says; the derive matches.

use proc_macro2::TokenStream as TokenStream2;
use syn::DeriveInput;

use crate::{
    codec::{expand_codec, CodecDeriveSpec},
    ReprWidth,
};

pub(crate) fn expand(input: DeriveInput) -> syn::Result<TokenStream2> {
    expand_codec(
        input,
        CodecDeriveSpec {
            derive_name: "GenlEnum",
            attr_name: "genl_enum",
            allowed: &[ReprWidth::U8, ReprWidth::U16, ReprWidth::U32],
            // GenlEnum accepts all widths; this hint never fires
            // because allowed covers every ReprWidth variant.
            // Keep a sensible message just in case a future
            // ReprWidth variant gets added without an `allowed`
            // update.
            rejected_repr_hint: "GenlEnum supports u8, u16, and u32 reprs",
        },
    )
}
